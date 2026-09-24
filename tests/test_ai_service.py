"""Stage 12 - the AI service, the Ollama client and the guards around them.

The service tests use a fake provider; the client tests use httpx's mock
transport. Neither reaches a network. The property checked most often is the
one the project exists to demonstrate: whatever the model says, the alert's
deterministic verdict does not move.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.ai.evidence import build_evidence
from app.ai.output import OUTPUT_SCHEMA
from app.ai.prompts import build_prompt
from app.ai.providers import (
    MAX_RESPONSE_BYTES,
    OllamaProvider,
    ProviderConfigurationError,
    ProviderError,
    ProviderUnavailableError,
    build_provider,
)
from app.ai.service import AIAnalysisService, AlertNotFoundError, OutcomeKind
from app.core.config import AIProvider, Settings
from app.database import repository
from app.database.init_db import MIGRATIONS, apply_pending_migrations, current_version
from app.database.tables import SCHEMA_VERSION
from app.models.alert import Alert
from app.models.enums import Actor, AuditAction, Severity, StatementType
from tests.ai_support import HOSTILE_COMMAND, FakeProvider, make_reply, triaged_alert

pytestmark = pytest.mark.integration


def _verdict(alert: Alert) -> dict[str, Any]:
    """Everything about an alert that only the pipeline or an analyst may change."""
    return alert.model_dump(
        include={
            "severity",
            "confidence",
            "status",
            "classification",
            "assigned_to",
            "tags",
            "mitre",
            "detections",
            "indicators",
            "incident_id",
            "updated_at",
            "closed_at",
        }
    )


def _audit(session: Session, alert: Alert) -> list[Any]:
    return list(reversed(repository.list_audit(session, object_id=alert.alert_id)))


# ===========================================================================
# Service
# ===========================================================================
class TestService:
    def test_an_analysis_is_stored_beside_the_alert(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        provider = FakeProvider()

        outcome = AIAnalysisService(db_session, provider).analyze_alert(alert.alert_id)

        assert outcome.kind is OutcomeKind.STORED and outcome.stored
        (stored,) = repository.get_ai_analyses(db_session, alert.alert_id)
        assert stored.analysis_id == outcome.analysis.analysis_id  # type: ignore[union-attr]
        assert stored.provider == "fake" and stored.model == "fake-model:1b"
        assert stored.prompt_version and stored.is_advisory is True
        assert stored.suggested_severity is Severity.HIGH

    @pytest.mark.parametrize("suggested", ["low", "critical"])
    def test_the_verdict_does_not_move_whatever_the_model_says(
        self, db_session: Session, db_settings: Settings, suggested: str
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        before = _verdict(alert)
        reply = make_reply(
            suggested_severity=suggested, severity="low", status="closed", classification="benign"
        )

        AIAnalysisService(db_session, FakeProvider(reply)).analyze_alert(alert.alert_id)
        db_session.flush()
        db_session.expire_all()

        after = repository.get_alert(db_session, alert.alert_id)
        assert after is not None
        assert _verdict(after) == before

    def test_the_request_and_the_result_are_both_audited(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        AIAnalysisService(db_session, FakeProvider(), requested_by="tester").analyze_alert(
            alert.alert_id
        )

        entries = [e for e in _audit(db_session, alert) if e.action.value.startswith("ai_")]
        requested, stored = entries
        assert requested.action is AuditAction.AI_ANALYSIS_REQUESTED
        assert requested.actor is Actor.ANALYST and requested.actor_name == "tester"
        assert "outcome=stored" in (requested.detail or "")
        assert stored.action is AuditAction.AI_ANALYSIS_STORED
        assert stored.actor is Actor.AI_ASSISTANT
        assert stored.actor_name == "fake/fake-model:1b"
        assert "(unchanged)" in (stored.detail or "")

    def test_the_prompt_never_carries_the_deterministic_score(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        provider = FakeProvider()
        AIAnalysisService(db_session, provider).analyze_alert(alert.alert_id)
        (prompt,) = provider.prompts
        assert '"score"' not in prompt.user and '"severity"' not in prompt.user
        assert f"{alert.severity.score}/100" not in prompt.user

    def test_hostile_evidence_is_flagged_warned_about_and_recorded(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings, command_line=HOSTILE_COMMAND)
        provider = FakeProvider(make_reply(suggested_severity="low"))

        outcome = AIAnalysisService(db_session, provider).analyze_alert(alert.alert_id)

        assert "WARNING FOR THIS ALERT" in provider.prompts[0].system
        analysis = outcome.analysis
        assert analysis is not None and analysis.injection_suspected is True
        assert any("instruction override" in s for s in analysis.injection_signals)
        assert any("may have been steered" in note for note in analysis.grounding_notes)
        (stored,) = repository.get_ai_analyses(db_session, alert.alert_id)
        assert stored.injection_signals == analysis.injection_signals

    def test_a_higher_suggestion_on_hostile_evidence_is_not_called_steered(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings, command_line=HOSTILE_COMMAND)
        outcome = AIAnalysisService(
            db_session, FakeProvider(make_reply(suggested_severity="critical"))
        ).analyze_alert(alert.alert_id)
        assert outcome.analysis is not None
        assert not any("steered" in note for note in outcome.analysis.grounding_notes)

    def test_unsupported_claims_are_relabelled_before_storage(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        reply = make_reply(
            statements=[
                {"label": "observed", "text": "Beaconing to 198.51.100.99 was seen."},
                {"label": "unknown", "text": "Whether lab-user opened the document."},
            ]
        )
        AIAnalysisService(db_session, FakeProvider(reply)).analyze_alert(alert.alert_id)

        (stored,) = repository.get_ai_analyses(db_session, alert.alert_id)
        first = stored.statements[0]
        assert first.statement_type is StatementType.INFERRED and first.downgraded is True
        assert any("198.51.100.99" in note for note in stored.grounding_notes)
        assert stored.downgraded == [first]

    @pytest.mark.parametrize(
        ("error", "kind"),
        [
            (ProviderUnavailableError("no reply within 60s"), OutcomeKind.UNAVAILABLE),
            (ProviderError("the provider returned HTTP 500"), OutcomeKind.UNAVAILABLE),
        ],
    )
    def test_a_provider_failure_stores_nothing_and_is_audited(
        self, db_session: Session, db_settings: Settings, error: Exception, kind: OutcomeKind
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        outcome = AIAnalysisService(db_session, FakeProvider(error)).analyze_alert(alert.alert_id)

        assert outcome.kind is kind and outcome.analysis is None
        assert str(error) in (outcome.problem or "")
        assert repository.get_ai_analyses(db_session, alert.alert_id) == []
        (entry,) = [e for e in _audit(db_session, alert) if e.action.value.startswith("ai_")]
        assert entry.action is AuditAction.AI_ANALYSIS_REQUESTED
        assert f"outcome={kind.value}" in (entry.detail or "")

    def test_an_unusable_reply_stores_nothing_and_is_audited(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        outcome = AIAnalysisService(
            db_session, FakeProvider("Sure! This alert looks benign to me.")
        ).analyze_alert(alert.alert_id)

        assert outcome.kind is OutcomeKind.REJECTED
        assert repository.get_ai_analyses(db_session, alert.alert_id) == []
        assert any("outcome=rejected" in (e.detail or "") for e in _audit(db_session, alert))

    def test_with_no_provider_nothing_is_contacted_or_stored(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        outcome = AIAnalysisService(db_session, None).analyze_alert(alert.alert_id)
        assert outcome.kind is OutcomeKind.DISABLED
        assert repository.get_ai_analyses(db_session, alert.alert_id) == []

    def test_an_unknown_alert_is_an_error(self, db_session: Session) -> None:
        from uuid import uuid4

        with pytest.raises(AlertNotFoundError):
            AIAnalysisService(db_session, FakeProvider()).analyze_alert(uuid4())

    def test_nothing_in_the_pipeline_depends_on_the_ai_package(self) -> None:
        """AI is optional in the import graph too, not just in configuration."""
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parents[1] / "app"
        for folder in ("services", "detection", "ingestion", "enrichment", "mitre", "models"):
            for path in (root / folder).rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        assert not node.module.startswith("app.ai"), path


# ===========================================================================
# Ollama client
# ===========================================================================
def _provider(handler: Any, **kwargs: Any) -> OllamaProvider:
    return OllamaProvider(
        base_url="http://127.0.0.1:11434",
        model=kwargs.pop("model", "qwen2.5:7b"),
        timeout_seconds=kwargs.pop("timeout_seconds", 30),
        transport=httpx.MockTransport(handler),
    )


def _chat_reply(content: str, **extra: Any) -> httpx.Response:
    body = {"model": "qwen2.5:7b", "message": {"role": "assistant", "content": content}}
    body.update(extra)
    return httpx.Response(200, json=body)


@pytest.fixture
def prompt(db_session: Session, db_settings: Settings) -> Any:
    alert = triaged_alert(db_session, db_settings)
    evidence = build_evidence(alert, repository.get_event(db_session, alert.primary_event_id))
    return build_prompt(evidence)


class TestOllamaClient:
    def test_the_request_is_deterministic_schema_constrained_and_complete(
        self, prompt: Any
    ) -> None:
        seen: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST" and request.url.path == "/api/chat"
            seen.append(json.loads(request.content))
            return _chat_reply(make_reply(), total_duration=2_500_000_000)

        reply = _provider(handler).complete(prompt)

        (body,) = seen
        assert body["model"] == "qwen2.5:7b"
        assert body["stream"] is False
        assert body["format"] == OUTPUT_SCHEMA
        assert body["options"]["temperature"] == 0
        assert [m["role"] for m in body["messages"]] == ["system", "user"]
        assert body["messages"][0]["content"] == prompt.system
        assert body["messages"][1]["content"] == prompt.user
        assert reply.duration_ms == 2_500
        assert json.loads(reply.content)["suggested_severity"] == "high"

    def test_the_client_ignores_proxy_settings_and_redirects(self) -> None:
        provider = _provider(lambda r: _chat_reply("{}"))
        assert provider._client.trust_env is False
        assert provider._client.follow_redirects is False

    def test_a_redirect_is_refused_not_followed(self, prompt: Any) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(307, headers={"location": "https://collector.example/steal"})

        with pytest.raises(ProviderError, match="redirect"):
            _provider(handler).complete(prompt)
        assert calls == ["http://127.0.0.1:11434/api/chat"]

    def test_a_missing_model_says_how_to_fix_it(self, prompt: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": 'model "qwen2.5:7b" not found'})

        with pytest.raises(ProviderUnavailableError, match=re.escape("ollama pull qwen2.5:7b")):
            _provider(handler).complete(prompt)

    @pytest.mark.parametrize(
        ("exception", "message"),
        [
            (httpx.ReadTimeout("slow"), "no reply from"),
            (httpx.ConnectError("refused"), "could not reach"),
        ],
    )
    def test_network_failures_become_unavailable(
        self, prompt: Any, exception: Exception, message: str
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise exception

        with pytest.raises(ProviderUnavailableError, match=message):
            _provider(handler).complete(prompt)

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            (httpx.Response(500, json={"error": "boom"}), "HTTP 500"),
            (httpx.Response(200, content=b"not json"), "JSON object"),
            (httpx.Response(200, json=[1, 2]), "JSON object"),
            (httpx.Response(200, json={"message": {"content": "  "}}), "empty reply"),
            (httpx.Response(200, json={"done": True}), "empty reply"),
        ],
    )
    def test_bad_responses_are_errors(
        self, prompt: Any, response: httpx.Response, message: str
    ) -> None:
        with pytest.raises(ProviderError, match=message):
            _provider(lambda r: response).complete(prompt)

    def test_an_oversized_response_is_abandoned(self, prompt: Any) -> None:
        huge = b"x" * (MAX_RESPONSE_BYTES + 10)
        with pytest.raises(ProviderError, match="larger than"):
            _provider(lambda r: httpx.Response(200, content=huge)).complete(prompt)

    def test_status_reports_version_and_installed_models(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/version":
                return httpx.Response(200, json={"version": "0.30.8"})
            return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}, {"name": "x:1b"}]})

        status = _provider(handler).status()
        assert status.ready and status.local and status.version == "0.30.8"
        assert status.installed_models == ("qwen2.5:7b", "x:1b")

    def test_status_names_a_missing_model(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/version":
                return httpx.Response(200, json={"version": "0.30.8"})
            return httpx.Response(200, json={"models": [{"name": "other:1b"}]})

        status = _provider(handler, model="llama3.1:8b").status()
        assert status.reachable and not status.model_installed and not status.ready
        assert "ollama pull llama3.1:8b" in (status.problem or "")

    def test_a_bare_model_name_means_latest(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/version":
                return httpx.Response(200, json={"version": "1"})
            return httpx.Response(200, json={"models": [{"name": "mistral:latest"}]})

        assert _provider(handler, model="mistral").status().model_installed is True

    def test_status_of_an_unreachable_server_is_not_an_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        status = _provider(handler).status()
        assert not status.reachable and "could not reach" in (status.problem or "")


# ===========================================================================
# Configuration guards
# ===========================================================================
def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


@pytest.mark.usefixtures("clean_env")
class TestProviderConfiguration:
    def test_no_provider_is_built_while_ai_is_off(self) -> None:
        assert build_provider(_settings()) is None
        assert build_provider(_settings(ai_enabled=True)) is None  # provider still "none"

    @pytest.mark.parametrize(
        "url", ["http://127.0.0.1:11434", "http://localhost:11434/", "http://[::1]:11434"]
    )
    def test_a_local_provider_is_built(self, url: str) -> None:
        provider = build_provider(
            _settings(ai_enabled=True, ai_provider=AIProvider.OLLAMA, ollama_base_url=url)
        )
        assert isinstance(provider, OllamaProvider)
        assert not provider.base_url.endswith("/")
        provider.close()

    @pytest.mark.parametrize("url", ["http://10.0.0.8:11434", "https://ollama.example.com"])
    def test_a_remote_provider_is_refused_by_default(self, url: str) -> None:
        settings = _settings(ai_enabled=True, ai_provider=AIProvider.OLLAMA, ollama_base_url=url)
        assert settings.ai_endpoint_problem is not None
        with pytest.raises(ProviderConfigurationError, match="not on this machine"):
            build_provider(settings)

    def test_a_remote_provider_can_be_allowed_deliberately(self) -> None:
        provider = build_provider(
            _settings(
                ai_enabled=True,
                ai_provider=AIProvider.OLLAMA,
                ollama_base_url="https://ollama.example.com",
                ai_allow_remote_provider=True,
            )
        )
        assert provider is not None
        provider.close()

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://127.0.0.1:11434",
            "http://user:secret@127.0.0.1:11434",
            "http://127.0.0.1:11434/?token=abc",
            "http://127.0.0.1:11434/#frag",
            "http://",
            "127.0.0.1:11434",
        ],
    )
    def test_malformed_provider_urls_are_rejected_at_load(self, url: str) -> None:
        with pytest.raises(ValidationError):
            _settings(ollama_base_url=url)


# ===========================================================================
# Schema version 5
# ===========================================================================
_V5_COLUMNS = {
    "ai_analysis": ("injection_signals", "grounding_notes"),
    "ai_statements": ("downgraded",),
}


def _columns(engine: Engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {row[1] for row in connection.execute(sa.text(f"PRAGMA table_info({table})"))}


class TestMigrationV5:
    def test_a_version_4_database_is_brought_forward(
        self, db_engine: Engine, db_settings: Settings
    ) -> None:
        # Recreate a version 4 database by removing what version 5 added.
        with db_engine.begin() as connection:
            for table, columns in _V5_COLUMNS.items():
                for column in columns:
                    connection.execute(sa.text(f"ALTER TABLE {table} DROP COLUMN {column}"))
            connection.execute(sa.text("DELETE FROM schema_version WHERE version >= 4"))
            connection.execute(
                sa.text(
                    "INSERT INTO schema_version (version, description, applied_at) "
                    "VALUES (4, 'add events.triaged_at', CURRENT_TIMESTAMP)"
                )
            )
        assert current_version(db_engine) == 4

        assert apply_pending_migrations(db_engine) == [5]
        assert current_version(db_engine) == SCHEMA_VERSION == 5
        for table, columns in _V5_COLUMNS.items():
            assert set(columns) <= _columns(db_engine, table)

        with Session(db_engine) as session:
            alert = triaged_alert(session, db_settings)
            AIAnalysisService(session, FakeProvider()).analyze_alert(alert.alert_id)
            session.commit()
            (stored,) = repository.get_ai_analyses(session, alert.alert_id)
            assert stored.grounding_notes == [] and stored.injection_signals == []

    def test_the_migration_is_safe_to_repeat(self, db_engine: Engine) -> None:
        (migration,) = [m for m in MIGRATIONS if m.version == 5]
        with db_engine.begin() as connection:
            migration.upgrade(connection)  # columns already exist: no error
        assert set(_V5_COLUMNS["ai_analysis"]) <= _columns(db_engine, "ai_analysis")
