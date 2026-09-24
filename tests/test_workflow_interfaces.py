"""Stage 13 - the workflow as the analyst meets it: API, console forms, CLI.

Also the two layers that stop another website from using the analyst's
browser to change anything: the cross-site write guard, and CSRF tokens on
the console's forms. Those tests send the headers a real browser sends,
because the test client sends none - which is how a real defect (our own
forms being refused under Referrer-Policy: no-referrer) got past the first
version of these tests and was caught in a browser instead.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.api.app import create_app
from app.api.dependencies import AIState
from app.cli import app as cli
from app.core.config import AIProvider, Settings, get_settings
from app.database import repository
from app.database.session import session_scope
from app.models.alert import Alert
from app.models.enums import Actor, AlertStatus, AuditAction, IncidentStatus
from app.services.correlation import CorrelationService
from app.web import csrf
from tests.ai_support import FakeProvider, triaged_alert

pytestmark = pytest.mark.integration

ANALYST = "tester"
TOKEN_RE = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')
VERSION_RE = re.compile(r'name="updated_at" value="([^"]+)"')


@pytest.fixture
def settings(global_db: Settings) -> Settings:
    return global_db.model_copy(update={"api_rate_limit_per_minute": 0, "analyst_name": ANALYST})


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), follow_redirects=False) as test_client:
        yield test_client


def _alert(settings: Settings, **overrides: Any) -> Alert:
    with session_scope(settings) as session:
        return triaged_alert(session, settings, **overrides)


def _incident(settings: Settings) -> Any:
    with session_scope(settings) as session:
        triaged_alert(session, settings, hostname="WIN-IF-01")
        triaged_alert(session, settings, hostname="WIN-IF-01", parent_process="excel.exe")
        (created,) = CorrelationService(session, settings).correlate_pending().created
        return created.incident_id


def _reload(settings: Settings, alert: Alert) -> Alert:
    with session_scope(settings) as session:
        found = repository.get_alert(session, alert.alert_id)
    assert found is not None
    return found


def _trail(settings: Settings, object_id: Any) -> list[Any]:
    with session_scope(settings) as session:
        return repository.list_audit(session, object_id=object_id, oldest_first=True)


def _form(client: TestClient, path: str) -> tuple[str, str]:
    """Load a console page as a browser would; return its CSRF token and version."""
    page = client.get(path)
    assert page.status_code == 200
    token = TOKEN_RE.search(page.text)
    version = VERSION_RE.search(page.text)
    assert token and version
    return token.group(1), version.group(1)


#: What a browser adds to a form post from our own page.
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}


# ===========================================================================
# REST API
# ===========================================================================
class TestApi:
    def test_a_decision_is_applied_and_audited_as_the_configured_analyst(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        response = client.patch(
            f"/api/v1/alerts/{alert.alert_id}",
            json={"status": "investigating", "assigned_to": "alice"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["changes"] == ["status new -> investigating", "assignee nobody -> alice"]
        assert body["alert"]["status"] == "investigating"
        assert body["alert"]["assigned_to"] == "alice"

        trail = client.get(f"/api/v1/alerts/{alert.alert_id}/audit").json()
        assert [e["action"] for e in trail] == [
            "alert_created",
            "alert_status_changed",
            "alert_assigned",
        ]
        assert trail[1]["actor"] == "analyst" and trail[1]["actor_name"] == ANALYST
        assert trail[1]["detail"] == "via api"

    def test_a_refused_decision_is_a_422_with_the_reason(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        response = client.patch(
            f"/api/v1/alerts/{alert.alert_id}", json={"status": "closed", "reason": "done"}
        )
        assert response.status_code == 422
        assert response.json()["error"] == "decision_refused"
        assert "Classify the alert before closing it" in response.json()["detail"]

    def test_a_stale_decision_is_a_409(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        seen = alert.updated_at.isoformat()
        client.patch(f"/api/v1/alerts/{alert.alert_id}", json={"status": "investigating"})
        response = client.patch(
            f"/api/v1/alerts/{alert.alert_id}",
            json={"assigned_to": "bob", "expected_updated_at": seen},
        )
        assert response.status_code == 409
        assert response.json()["error"] == "stale_decision"

    def test_null_unassigns_and_omission_leaves_alone(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        path = f"/api/v1/alerts/{alert.alert_id}"
        client.patch(path, json={"assigned_to": "alice"})
        body = client.patch(path, json={"classification": "true_positive"}).json()
        assert body["alert"]["assigned_to"] == "alice"
        body = client.patch(path, json={"assigned_to": None}).json()
        assert body["alert"]["assigned_to"] is None

    def test_an_identical_decision_reports_no_changes(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        body = client.patch(f"/api/v1/alerts/{alert.alert_id}", json={"status": "new"}).json()
        assert body["changes"] == []

    @pytest.mark.parametrize(
        "payload",
        [{"status": "resolved"}, {"severity": "low"}, {"reason": "x" * 1_001}],
        ids=["unknown-status", "severity-is-not-an-analyst-field", "reason-too-long"],
    )
    def test_invalid_decisions_are_validation_errors(
        self, client: TestClient, settings: Settings, payload: dict[str, Any]
    ) -> None:
        alert = _alert(settings)
        response = client.patch(f"/api/v1/alerts/{alert.alert_id}", json=payload)
        assert response.status_code == 422
        assert _reload(settings, alert).status is AlertStatus.NEW

    def test_unknown_records_are_404(self, client: TestClient) -> None:
        missing = "00000000-0000-4000-8000-000000000000"
        assert client.patch(f"/api/v1/alerts/{missing}", json={}).status_code == 404
        assert client.post(f"/api/v1/alerts/{missing}/notes", json={"body": "x"}).status_code == 404
        assert client.get(f"/api/v1/alerts/{missing}/audit").status_code == 404
        assert client.patch(f"/api/v1/incidents/{missing}", json={}).status_code == 404

    def test_notes(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        response = client.post(
            f"/api/v1/alerts/{alert.alert_id}/notes", json={"body": "Owner confirmed."}
        )
        assert response.status_code == 201
        assert response.json()["author"] == ANALYST
        detail = client.get(f"/api/v1/alerts/{alert.alert_id}").json()
        assert [n["body"] for n in detail["notes"]] == ["Owner confirmed."]
        assert (
            client.post(f"/api/v1/alerts/{alert.alert_id}/notes", json={"body": ""}).status_code
            == 422
        )
        assert (
            client.post(f"/api/v1/alerts/{alert.alert_id}/notes", json={"body": "  "}).status_code
            == 422
        )

    def test_incident_decisions_and_notes(self, client: TestClient, settings: Settings) -> None:
        incident_id = _incident(settings)
        path = f"/api/v1/incidents/{incident_id}"
        refused = client.patch(path, json={"status": "confirmed"})
        assert refused.status_code == 422 and "what confirms" in refused.json()["detail"]

        body = client.patch(
            path, json={"status": "confirmed", "reason": "Decoy used", "assigned_to": "alice"}
        ).json()
        assert body["incident"]["status"] == "confirmed"
        assert body["incident"]["display_label"] == "Confirmed"
        assert body["incident"]["assigned_to"] == "alice"

        client.post(f"{path}/notes", json={"body": "Escalated to IR."})
        assert [n["body"] for n in client.get(path).json()["notes"]] == ["Escalated to IR."]
        actions = [e["action"] for e in client.get(f"{path}/audit").json()]
        assert actions == [
            "incident_created",
            "incident_status_changed",
            "incident_assigned",
            "note_added",
        ]

    def test_the_global_trail_filters_and_counts(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        client.patch(f"/api/v1/alerts/{alert.alert_id}", json={"status": "investigating"})
        page = client.get("/api/v1/audit", params={"action": "alert_status_changed"}).json()
        assert page["total"] >= 1
        assert {e["action"] for e in page["items"]} == {"alert_status_changed"}
        assert client.get("/api/v1/audit", params={"object_type": "x;drop"}).status_code == 422


# ===========================================================================
# Cross-site writes
# ===========================================================================
class TestCrossSiteGuard:
    @pytest.mark.parametrize(
        "headers",
        [
            {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
            {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:3000"},
            {"Origin": "https://evil.example"},  # an older browser: no fetch metadata
            {"Origin": "null"},  # a sandboxed frame or data: URL
        ],
        ids=["cross-site", "another-local-port", "origin-only", "opaque-origin"],
    )
    def test_writes_from_other_sites_are_refused(
        self, client: TestClient, settings: Settings, headers: dict[str, str]
    ) -> None:
        alert = _alert(settings)
        response = client.patch(
            f"/api/v1/alerts/{alert.alert_id}", json={"status": "investigating"}, headers=headers
        )
        assert response.status_code == 403
        assert response.json()["error"] == "cross_site_request"
        assert _reload(settings, alert).status is AlertStatus.NEW

    def test_bodyless_writes_are_covered_too(self, client: TestClient, settings: Settings) -> None:
        """A plain HTML form on any site could trigger these; nothing needs a body."""
        hostile = {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
        for path in ("/api/v1/triage", "/api/v1/correlate"):
            assert client.post(path, headers=hostile).status_code == 403

    @pytest.mark.parametrize(
        "headers",
        [
            SAME_ORIGIN,
            # Under Referrer-Policy: no-referrer a browser sends Origin: null on
            # its own same-origin form posts. Fetch metadata must win.
            {"Sec-Fetch-Site": "same-origin", "Origin": "null"},
            {"Sec-Fetch-Site": "none"},  # typed into the address bar, bookmarks
            {"Origin": "http://testserver"},
            {},  # curl, scripts: not a browser
        ],
        ids=[
            "same-origin",
            "same-origin-null-origin",
            "user-initiated",
            "origin-only",
            "no-browser",
        ],
    )
    def test_legitimate_writes_are_allowed(
        self, client: TestClient, settings: Settings, headers: dict[str, str]
    ) -> None:
        alert = _alert(settings)
        response = client.patch(
            f"/api/v1/alerts/{alert.alert_id}", json={"status": "investigating"}, headers=headers
        )
        assert response.status_code == 200

    def test_reads_are_never_blocked(self, client: TestClient) -> None:
        response = client.get("/api/v1/health", headers={"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 200

    def test_the_referrer_policy_keeps_origin_on_our_own_posts(self, client: TestClient) -> None:
        assert client.get("/").headers["Referrer-Policy"] == "same-origin"
        assert 'content="same-origin"' in client.get("/").text


# ===========================================================================
# Console forms and CSRF
# ===========================================================================
class TestConsoleForms:
    def test_pages_issue_a_strict_http_only_token_cookie(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        page = client.get(f"/alerts/{alert.alert_id}")
        cookie = page.headers["set-cookie"]
        assert cookie.startswith(f"{csrf.COOKIE_NAME}=")
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert "Secure" not in cookie  # loopback over http; Secure would drop it

        token = TOKEN_RE.search(page.text)
        assert token is not None
        secret = client.app.state.csrf_secret  # type: ignore[attr-defined]
        assert token.group(1) == csrf.sign(secret, client.cookies[csrf.COOKIE_NAME])

    def test_the_cookie_is_secure_when_the_console_is_exposed(self, settings: Settings) -> None:
        exposed = settings.model_copy(update={"api_host": "0.0.0.0"})
        with TestClient(create_app(exposed)) as test_client:
            assert "Secure" in test_client.get("/").headers["set-cookie"]

    def test_a_decision_through_the_console(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        response = client.post(
            f"/alerts/{alert.alert_id}/decision",
            data={
                "csrf_token": token,
                "updated_at": version,
                "status": "closed",
                "classification": "false_positive",
                "assigned_to": "alice",
                "reason": "Scheduled admin script",
            },
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 303
        assert response.headers["location"] == f"/alerts/{alert.alert_id}?saved=decision#decided"

        after = _reload(settings, alert)
        assert (after.status, after.classification, after.assigned_to) == (
            AlertStatus.CLOSED,
            after.classification,
            "alice",
        )
        details = [e.detail for e in _trail(settings, alert.alert_id) if e.actor is Actor.ANALYST]
        assert "Scheduled admin script (via console)" in details

        page = client.get(response.headers["location"])
        assert "Decision recorded." in page.text

    @pytest.mark.parametrize(
        "tamper",
        ["missing", "wrong", "other-cookie", "non-ascii"],
    )
    def test_a_form_without_a_valid_token_changes_nothing(
        self, client: TestClient, settings: Settings, tamper: str
    ) -> None:
        alert = _alert(settings)
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        data = {"updated_at": version, "status": "investigating"}
        if tamper == "wrong":
            data["csrf_token"] = "0" * 64
        elif tamper == "other-cookie":
            data["csrf_token"] = token
            client.cookies.set(csrf.COOKIE_NAME, "A" * 43)
        elif tamper == "non-ascii":
            data["csrf_token"] = "é" * 64
        response = client.post(f"/alerts/{alert.alert_id}/decision", data=data, headers=SAME_ORIGIN)
        assert response.status_code == 403
        assert "could not be verified" in response.text
        assert f'href="/alerts/{alert.alert_id}"' in response.text
        assert _reload(settings, alert).status is AlertStatus.NEW

    def test_a_valid_token_from_another_site_is_still_refused(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        response = client.post(
            f"/alerts/{alert.alert_id}/decision",
            data={"csrf_token": token, "updated_at": version, "status": "investigating"},
            headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
        )
        assert response.status_code == 403
        assert _reload(settings, alert).status is AlertStatus.NEW

    def test_a_refused_decision_is_explained_and_the_input_kept(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        response = client.post(
            f"/alerts/{alert.alert_id}/decision",
            data={
                "csrf_token": token,
                "updated_at": version,
                "status": "closed",
                "reason": "<script>alert(1)</script> owner confirmed",
            },
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 422
        assert 'role="alert"' in response.text
        assert "Classify the alert before closing it" in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt; owner confirmed" in response.text
        assert "<script>alert(1)" not in response.text
        assert '<option value="closed" selected>' in response.text

    def test_a_stale_form_is_a_409_that_says_to_reload(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        client.patch(f"/api/v1/alerts/{alert.alert_id}", json={"assigned_to": "bob"})
        response = client.post(
            f"/alerts/{alert.alert_id}/decision",
            data={"csrf_token": token, "updated_at": version, "status": "investigating"},
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 409
        assert "changed after you opened it" in response.text
        assert _reload(settings, alert).status is AlertStatus.NEW

    def test_take_it(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        page = client.get(f"/alerts/{alert.alert_id}").text
        assert "Take it" in page and f'name="assigned_to" value="{ANALYST}"' in page
        token, version = _form(client, f"/alerts/{alert.alert_id}")
        client.post(
            f"/alerts/{alert.alert_id}/decision",
            data={
                "csrf_token": token,
                "updated_at": version,
                "status": "investigating",
                "assigned_to": ANALYST,
            },
            headers=SAME_ORIGIN,
        )
        after = _reload(settings, alert)
        assert (after.status, after.assigned_to) == (AlertStatus.INVESTIGATING, ANALYST)
        assert "Take it" not in client.get(f"/alerts/{alert.alert_id}").text

    def test_notes_through_the_console(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        token, _ = _form(client, f"/alerts/{alert.alert_id}")
        empty = client.post(
            f"/alerts/{alert.alert_id}/notes",
            data={"csrf_token": token, "body": "   "},
            headers=SAME_ORIGIN,
        )
        assert empty.status_code == 422 and "cannot be empty" in empty.text

        added = client.post(
            f"/alerts/{alert.alert_id}/notes",
            data={"csrf_token": token, "body": "Line one\n<b>bold?</b>"},
            headers=SAME_ORIGIN,
        )
        assert added.status_code == 303
        assert added.headers["location"].endswith("?saved=note#notes")
        page = client.get(added.headers["location"]).text
        assert "Note added." in page
        assert "Line one\n&lt;b&gt;bold?&lt;/b&gt;" in page

    def test_the_history_names_who_did_what(self, client: TestClient, settings: Settings) -> None:
        alert = _alert(settings)
        client.patch(
            f"/api/v1/alerts/{alert.alert_id}",
            json={"status": "escalated", "reason": "Needs IR"},
        )
        page = client.get(f"/alerts/{alert.alert_id}").text
        assert "SentinelFlow" in page and "Alert created" in page
        assert ANALYST in page and "Alert status changed" in page
        assert "New → Escalated" in page and "Needs IR (via api)" in page

    def test_unknown_notice_codes_print_nothing(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        page = client.get(f"/alerts/{alert.alert_id}?saved=<script>").text
        assert 'class="notice"' not in page and "&lt;script&gt;" not in page

    def test_new_is_only_offered_while_the_alert_is_new(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        assert '<option value="new"' in client.get(f"/alerts/{alert.alert_id}").text
        client.patch(f"/api/v1/alerts/{alert.alert_id}", json={"status": "investigating"})
        assert '<option value="new"' not in client.get(f"/alerts/{alert.alert_id}").text

    def test_an_incident_decision_through_the_console(
        self, client: TestClient, settings: Settings
    ) -> None:
        incident_id = _incident(settings)
        path = f"/incidents/{incident_id}"
        token, version = _form(client, path)
        response = client.post(
            f"{path}/decision",
            data={
                "csrf_token": token,
                "updated_at": version,
                "status": "dismissed",
                "reason": "Red-team exercise, scheduled",
            },
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 303
        page = client.get(response.headers["location"]).text
        assert "Decision recorded." in page
        assert "Potential incident." not in page  # the banner goes once a human rules
        assert '<option value="potential"' not in page
        actions = [e.action for e in _trail(settings, incident_id)]
        assert AuditAction.INCIDENT_STATUS_CHANGED in actions
        with session_scope(settings) as session:
            incident = repository.get_incident(session, incident_id)
        assert incident is not None and incident.status is IncidentStatus.DISMISSED


class TestConsoleAiRequest:
    def test_asking_the_model_from_the_console(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        assert "Ask the local model" not in client.get(f"/alerts/{alert.alert_id}").text
        client.app.state.ai = AIState(provider=FakeProvider())  # type: ignore[attr-defined]
        assert "Ask the local model" in client.get(f"/alerts/{alert.alert_id}").text

        token, _ = _form(client, f"/alerts/{alert.alert_id}")
        response = client.post(
            f"/alerts/{alert.alert_id}/ai-analysis",
            data={"csrf_token": token},
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("?saved=analysis#suggested")
        page = client.get(response.headers["location"]).text
        assert "The model&#39;s analysis was stored" in page
        assert _reload(settings, alert).severity == alert.severity

    def test_asking_while_ai_is_off_explains_why(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _alert(settings)
        token, _ = _form(client, f"/alerts/{alert.alert_id}")
        response = client.post(
            f"/alerts/{alert.alert_id}/ai-analysis",
            data={"csrf_token": token},
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 503
        assert "AI is disabled" in response.text

    def test_the_button_is_not_offered_when_misconfigured(self, settings: Settings) -> None:
        remote = settings.model_copy(
            update={
                "ai_enabled": True,
                "ai_provider": AIProvider.OLLAMA,
                "ollama_base_url": "http://192.0.2.9:11434",
            }
        )
        alert = _alert(settings)
        with TestClient(create_app(remote)) as test_client:
            page = test_client.get(f"/alerts/{alert.alert_id}").text
        assert "Ask the local model" not in page and "not on this machine" in page


# ===========================================================================
# CLI
# ===========================================================================
@pytest.fixture
def cli_settings(settings: Settings, clean_env: pytest.MonkeyPatch) -> Iterator[Settings]:
    clean_env.setenv("SENTINELFLOW_DATABASE_URL", settings.database_url)
    clean_env.setenv("SENTINELFLOW_ANALYST_NAME", ANALYST)
    # Wide enough that table cells do not wrap into each other.
    clean_env.setenv("COLUMNS", "220")
    get_settings.cache_clear()
    yield settings
    get_settings.cache_clear()


def _run(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args))


def _flat(text: str) -> str:
    return " ".join(text.split())


class TestCli:
    def test_decide_note_and_history(self, cli_settings: Settings) -> None:
        alert = _alert(cli_settings)
        prefix = str(alert.alert_id)[:8]

        taken = _run("decide", prefix, "--status", "investigating", "--assign", "me")
        assert taken.exit_code == 0, taken.output
        assert "assignee nobody -> tester" in taken.output

        refused = _run("decide", prefix, "--status", "closed")
        assert refused.exit_code == 1
        assert "Classify the alert before closing it" in _flat(refused.output)

        closed = _run(
            "decide", prefix, "-s", "closed", "-c", "false_positive", "-r", "Known script"
        )
        assert closed.exit_code == 0, closed.output
        again = _run("decide", prefix, "-s", "closed", "-c", "false_positive", "-r", "x")
        assert "Nothing changed" in again.output

        assert _run("note", prefix, "Checked with the owner.").exit_code == 0
        shown = _flat(_run("history", prefix).output)
        assert "Investigating -> Closed" in shown and "Known script (via cli)" in shown
        assert "Note added" in shown and "append-only" in shown

        after = _reload(cli_settings, alert)
        assert after.assigned_to == ANALYST and after.status is AlertStatus.CLOSED

    def test_bad_choices_are_explained(self, cli_settings: Settings) -> None:
        prefix = str(_alert(cli_settings).alert_id)[:8]
        result = _run("decide", prefix, "--status", "resolved")
        assert result.exit_code == 1 and "Choose from" in _flat(result.output)
        both = _run("decide", prefix, "--assign", "a", "--unassign")
        assert both.exit_code == 1

    def test_incident_decisions(self, cli_settings: Settings) -> None:
        incident_id = _incident(cli_settings)
        prefix = str(incident_id)[:8]
        refused = _run("decide", prefix, "--incident", "-s", "confirmed")
        assert refused.exit_code == 1 and "what confirms" in _flat(refused.output)
        confirmed = _run("decide", prefix, "-i", "-s", "confirmed", "-r", "Decoy used")
        assert confirmed.exit_code == 0, confirmed.output
        assert _run("note", prefix, "-i", "IR engaged.").exit_code == 0
        assert "Incident status changed" in _flat(_run("history", prefix, "-i").output)
