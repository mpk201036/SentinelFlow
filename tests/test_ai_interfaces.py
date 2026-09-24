"""Stage 12 - the AI path as the analyst meets it: REST API, console and CLI.

Also holds the regression tests for defects found while building it: event
text that restyled or crashed the terminal, alert collections that came back
in a different order on each read, and an incident title that named whichever
rule the database returned first.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.ai.providers import ProviderUnavailableError
from app.api.app import create_app
from app.api.dependencies import AIState
from app.cli import app as cli
from app.core.config import AIProvider, Settings, get_settings
from app.database import repository
from app.database.session import session_scope
from app.models.alert import Alert
from app.models.detection import DetectionResult
from app.models.enums import Severity
from app.services.correlation import CorrelationEngine
from tests.ai_support import HOSTILE_COMMAND, FakeProvider, make_reply, triaged_alert

pytestmark = pytest.mark.integration


@pytest.fixture
def settings(global_db: Settings) -> Settings:
    return global_db.model_copy(update={"api_rate_limit_per_minute": 0})


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _alert(settings: Settings, **overrides: Any) -> Alert:
    with session_scope(settings) as session:
        return triaged_alert(session, settings, **overrides)


def _audit_details(settings: Settings, alert: Alert) -> list[str]:
    with session_scope(settings) as session:
        return [e.detail or "" for e in repository.list_audit(session, object_id=alert.alert_id)]


def _use(client: TestClient, provider: Any) -> None:
    client.app.state.ai = AIState(provider=provider)  # type: ignore[attr-defined]


# ===========================================================================
# REST API
# ===========================================================================
class TestApi:
    def test_status_says_ai_is_off_and_why(self, client: TestClient) -> None:
        body = client.get("/api/v1/ai/status").json()
        assert body["enabled"] is False
        assert "disabled" in body["problem"]
        assert body["prompt_version"]

    def test_requesting_an_analysis_while_off_is_a_503(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        response = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
        assert response.status_code == 503
        assert "SENTINELFLOW_AI_ENABLED" in response.json()["detail"]

    def test_an_unknown_alert_is_a_404_either_way(self, client: TestClient) -> None:
        missing = "/api/v1/alerts/00000000-0000-4000-8000-000000000000/ai-analysis"
        assert client.post(missing).status_code == 404
        _use(client, FakeProvider())
        assert client.post(missing).status_code == 404

    def test_an_analysis_is_created_and_the_alert_is_unchanged(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        before = client.get(f"/api/v1/alerts/{alert.alert_id}").json()
        _use(client, FakeProvider(make_reply(suggested_severity="low")))

        response = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")

        assert response.status_code == 201
        body = response.json()
        assert body["is_advisory"] is True
        assert body["suggested_severity"] == "low"
        assert body["disclaimer"].startswith("AI SUGGESTION")
        assert {s["statement_type"] for s in body["statements"]} == {
            "observed",
            "inferred",
            "unknown",
        }
        after = client.get(f"/api/v1/alerts/{alert.alert_id}").json()
        for field in ("severity", "status", "classification", "mitre", "updated_at"):
            assert after[field] == before[field], field
        assert after["ai_analysis"][0]["analysis_id"] == body["analysis_id"]

    def test_system_checks_travel_with_the_analysis(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings, command_line=HOSTILE_COMMAND)
        reply = make_reply(
            statements=[{"label": "observed", "text": "It beaconed to 198.51.100.4."}],
            suggested_severity="low",
        )
        _use(client, FakeProvider(reply))
        body = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis").json()

        assert body["injection_suspected"] is True
        assert body["injection_signals"]
        assert body["statements"][0] == {
            "statement_type": "inferred",
            "text": "It beaconed to 198.51.100.4.",
            "downgraded": True,
        }
        assert any("198.51.100.4" in note for note in body["grounding_notes"])

    def test_a_second_request_while_one_runs_is_refused(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        _use(client, FakeProvider())
        lock = client.app.state.ai.lock  # type: ignore[attr-defined]
        lock.acquire()
        try:
            response = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
        finally:
            lock.release()
        assert response.status_code == 429
        assert client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis").status_code == 201

    def test_an_unusable_reply_is_a_502_and_the_attempt_is_kept(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        _use(client, FakeProvider("I'd say this one is fine."))
        response = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
        assert response.status_code == 502
        assert any("outcome=rejected" in d for d in _audit_details(settings, alert))

    def test_an_unreachable_model_is_a_503_and_the_attempt_is_kept(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        _use(client, FakeProvider(ProviderUnavailableError("no reply within 60s")))
        response = client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
        assert response.status_code == 503
        assert "no reply within 60s" in response.json()["detail"]
        assert any("outcome=unavailable" in d for d in _audit_details(settings, alert))

    def test_status_reports_a_working_provider(self, client: TestClient) -> None:
        _use(client, FakeProvider())
        body = client.get("/api/v1/ai/status").json()
        assert body["enabled"] and body["reachable"] and body["model_installed"]
        assert body["local"] is True and body["problem"] is None

    def test_a_remote_provider_is_refused_when_the_app_starts(self, settings: Settings) -> None:
        remote = settings.model_copy(
            update={
                "ai_enabled": True,
                "ai_provider": AIProvider.OLLAMA,
                "ollama_base_url": "http://192.0.2.50:11434",
            }
        )
        with TestClient(create_app(remote)) as test_client:
            assert test_client.app.state.ai.provider is None  # type: ignore[attr-defined]
            assert "not on this machine" in test_client.get("/api/v1/ai/status").json()["problem"]
            alert = _alert(settings)
            response = test_client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
            assert response.status_code == 503
            assert "not on this machine" in response.json()["detail"]

    def test_the_provider_is_closed_when_the_app_stops(self, settings: Settings) -> None:
        provider = FakeProvider()
        with TestClient(create_app(settings)) as test_client:
            _use(test_client, provider)
        assert provider.closed is True


# ===========================================================================
# Console
# ===========================================================================
class TestConsole:
    def _page(self, client: TestClient, alert: Alert) -> str:
        response = client.get(f"/alerts/{alert.alert_id}")
        assert response.status_code == 200
        return response.text

    def test_the_whole_analysis_is_shown_with_its_checks(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings, command_line=HOSTILE_COMMAND)
        reply = make_reply(
            statements=[{"label": "observed", "text": "It beaconed to 198.51.100.4."}],
            suggested_severity="low",
        )
        _use(client, FakeProvider(reply))
        client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")

        page = self._page(client, alert)
        assert "Possible prompt injection" in page
        assert "instruction override in observed_event.command_line" in page
        assert "relabelled from observed" in page
        assert "SentinelFlow checks" in page and "not the model" in page
        assert "may have been steered" in page
        assert "Suggested next steps" in page and "Decode the command" in page
        assert "prompt sf-triage" in page

    def test_model_text_is_escaped(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        _use(
            client,
            FakeProvider(make_reply(summary='<script>alert("x")</script><img src=x onerror=1>')),
        )
        client.post(f"/api/v1/alerts/{alert.alert_id}/ai-analysis")
        page = self._page(client, alert)
        assert "<script>alert" not in page and "<img src=x" not in page
        assert "&lt;script&gt;" in page

    def test_the_empty_state_says_how_to_ask(self, settings: Settings) -> None:
        enabled = settings.model_copy(update={"ai_enabled": True, "ai_provider": AIProvider.OLLAMA})
        alert = _alert(settings)
        with TestClient(create_app(enabled)) as test_client:
            page = self._page(test_client, alert)
        assert "No analysis has been requested" in page
        assert f"sentinelflow ai analyze {str(alert.alert_id)[:8]}" in page

    def test_a_misconfiguration_is_explained_not_hidden(self, settings: Settings) -> None:
        remote = settings.model_copy(
            update={
                "ai_enabled": True,
                "ai_provider": AIProvider.OLLAMA,
                "ollama_base_url": "http://192.0.2.50:11434",
            }
        )
        alert = _alert(settings)
        with TestClient(create_app(remote)) as test_client:
            page = self._page(test_client, alert)
        assert "AI is enabled but not in use" in page
        assert "not on this machine" in page


# ===========================================================================
# CLI
# ===========================================================================
@pytest.fixture
def cli_settings(settings: Settings, clean_env: pytest.MonkeyPatch) -> Iterator[Settings]:
    clean_env.setenv("SENTINELFLOW_DATABASE_URL", settings.database_url)
    get_settings.cache_clear()
    yield settings
    get_settings.cache_clear()


def _run(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args))


class TestCli:
    def test_event_text_cannot_restyle_or_crash_the_terminal(self, cli_settings: Settings) -> None:
        """Rich reads [..] as markup: '[/]' crashed this command before it was escaped."""
        hostile = "[/] [bold red]SAFE[/bold red] [link=https://evil.example]docs[/link]"
        alert = _alert(cli_settings, hostname="HOST[/]", event_message=hostile)

        result = _run("alert", str(alert.alert_id)[:8])

        assert result.exit_code == 0, result.output
        assert "HOST[/]" in result.output
        assert "[bold red]SAFE[/bold red]" in " ".join(result.output.split())

    def test_prefixes_are_resolved_in_the_database(self, cli_settings: Settings) -> None:
        alert = _alert(cli_settings)
        assert _run("alert", str(alert.alert_id)[:8].upper()).exit_code == 0
        for prefix in ("zzzz", "%", "_", ""):
            result = _run("alert", prefix)
            assert result.exit_code == 1
            assert "No alert starts with" in result.output

    def test_ai_status_while_off(self, cli_settings: Settings) -> None:
        result = _run("ai", "status")
        assert result.exit_code == 0
        assert "AI is off" in result.output

    def test_ai_status_refuses_a_remote_provider(
        self, cli_settings: Settings, clean_env: pytest.MonkeyPatch
    ) -> None:
        clean_env.setenv("SENTINELFLOW_AI_ENABLED", "true")
        clean_env.setenv("SENTINELFLOW_AI_PROVIDER", "ollama")
        clean_env.setenv("SENTINELFLOW_OLLAMA_BASE_URL", "http://192.0.2.50:11434")
        get_settings.cache_clear()
        result = _run("ai", "status")
        assert result.exit_code == 1
        assert "not on this machine" in " ".join(result.output.split())

    def test_ai_analyze_while_off(self, cli_settings: Settings) -> None:
        alert = _alert(cli_settings)
        result = _run("ai", "analyze", str(alert.alert_id)[:8])
        assert result.exit_code == 1
        assert "AI is off" in result.output

    def test_ai_analyze_prints_both_voices_and_keeps_the_verdict(
        self, cli_settings: Settings, clean_env: pytest.MonkeyPatch
    ) -> None:
        clean_env.setenv("SENTINELFLOW_AI_ENABLED", "true")
        clean_env.setenv("SENTINELFLOW_AI_PROVIDER", "ollama")
        get_settings.cache_clear()
        reply = make_reply(
            summary="Looks scripted [/] [red]benign[/red].",
            statements=[{"label": "observed", "text": "It beaconed to 198.51.100.4."}],
            suggested_severity="low",
        )
        clean_env.setattr("app.ai.build_provider", lambda _settings: FakeProvider(reply))
        alert = _alert(cli_settings)

        result = _run("ai", "analyze", str(alert.alert_id)[:8])

        output = " ".join(result.output.split())
        assert result.exit_code == 0, result.output
        assert "AI SUGGESTION - NOT AUTHORITATIVE" in output
        assert "(the verdict)" in output and "AI suggests low" in output
        assert "[/] [red]benign[/red]" in output
        assert "relabelled by SentinelFlow" in output
        assert "SentinelFlow checks (not written by the model)" in output
        with session_scope(cli_settings) as session:
            after = repository.get_alert(session, alert.alert_id)
        assert after is not None and after.severity == alert.severity


# ===========================================================================
# Regressions found during Stage 12
# ===========================================================================
class TestStableOrdering:
    def test_alert_collections_come_back_in_a_defined_order(self, settings: Settings) -> None:
        alert = _alert(settings)
        with session_scope(settings) as session:
            first = repository.get_alert(session, alert.alert_id)
        with session_scope(settings) as session:
            second = repository.get_alert(session, alert.alert_id)
        assert first is not None and second is not None
        assert first.model_dump() == second.model_dump()

        pairs = [(i.indicator_type.value, i.value) for i in first.indicators]
        assert pairs == sorted(pairs)
        techniques = [m.technique_id for m in first.mitre]
        assert techniques == sorted(techniques)

    def test_an_incident_title_leads_with_the_most_severe_rule(self) -> None:
        from tests.test_incident_correlation import alert as make_alert
        from tests.test_incident_correlation import event

        def detection(rule_id: str, name: str, severity: Severity) -> DetectionResult:
            return DetectionResult(
                rule_id=rule_id, rule_name=name, rule_severity=severity, description="test"
            )

        source = event()
        lead = make_alert(
            source,
            detections=[
                detection("SF-9001", "Quiet rule", Severity.LOW),
                detection("SF-9002", "Loud rule", Severity.HIGH),
            ],
        )
        (group,) = CorrelationEngine(30).group([(lead, source)])
        assert CorrelationEngine(30).build_incident(group).title.startswith("Loud rule")
