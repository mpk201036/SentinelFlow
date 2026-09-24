"""Stage 15 - console forms that arrive tampered, stale or pointing at nothing.

A form field is attacker-controlled the moment it leaves the browser: a status
can be edited to a value the select never offered, a version can be removed,
an id can point at nothing. Each such submission must be refused with a clear
page, with the right status code, and change nothing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.ai.providers import ProviderUnavailableError
from app.api.app import create_app
from app.api.dependencies import AIState
from app.core.config import Settings
from app.database import repository
from app.database.session import session_scope
from app.models.enums import AlertStatus
from app.services.correlation import CorrelationService
from tests.ai_support import FakeProvider, triaged_alert

pytestmark = pytest.mark.integration

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
TOKEN_RE = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')
VERSION_RE = re.compile(r'name="updated_at" value="([^"]+)"')
MISSING = "00000000-0000-4000-8000-000000000000"


@pytest.fixture
def settings(global_db: Settings) -> Settings:
    return global_db.model_copy(update={"api_rate_limit_per_minute": 0, "analyst_name": "t"})


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def records(settings: Settings) -> dict[str, str]:
    with session_scope(settings) as session:
        alert = triaged_alert(session, settings, hostname="WIN-FORM-01")
        triaged_alert(session, settings, hostname="WIN-FORM-01", parent_process="excel.exe")
        (incident,) = CorrelationService(session, settings).correlate_pending().created
    return {"alert": str(alert.alert_id), "incident": str(incident.incident_id)}


def _form(client: TestClient, path: str) -> tuple[str, str]:
    page = client.get(path).text
    token, version = TOKEN_RE.search(page), VERSION_RE.search(page)
    assert token and version
    return token.group(1), version.group(1)


def _post(client: TestClient, path: str, **fields: str) -> Any:
    return client.post(path, data=fields, headers=SAME_ORIGIN)


def _status(settings: Settings, alert_id: str) -> AlertStatus:
    from uuid import UUID

    with session_scope(settings) as session:
        alert = repository.get_alert(session, UUID(alert_id))
    assert alert is not None
    return alert.status


class TestTamperedDecisions:
    @pytest.mark.parametrize(
        ("fields", "code", "message"),
        [
            ({"status": "owned"}, 422, "not one SentinelFlow knows"),
            ({"classification": "totally_fine"}, 422, "not one SentinelFlow knows"),
            ({"updated_at": ""}, 400, "form was incomplete"),
            ({"updated_at": "yesterday"}, 400, "form was incomplete"),
        ],
    )
    def test_an_alert_decision_with_edited_fields(
        self,
        client: TestClient,
        settings: Settings,
        records: dict[str, str],
        fields: dict[str, str],
        code: int,
        message: str,
    ) -> None:
        path = f"/alerts/{records['alert']}"
        token, version = _form(client, path)
        data = {"csrf_token": token, "updated_at": version, "status": "investigating", **fields}
        response = _post(client, f"{path}/decision", **data)
        assert response.status_code == code
        assert message in response.text
        assert _status(settings, records["alert"]) is AlertStatus.NEW

    @pytest.mark.parametrize("target", [MISSING, "not-a-uuid"])
    def test_forms_for_records_that_do_not_exist(
        self, client: TestClient, records: dict[str, str], target: str
    ) -> None:
        token, version = _form(client, f"/alerts/{records['alert']}")
        for path, fields in (
            (f"/alerts/{target}/notes", {"body": "x"}),
            (f"/alerts/{target}/ai-analysis", {}),
            (f"/incidents/{target}/notes", {"body": "x"}),
        ):
            response = _post(client, path, csrf_token=token, **fields)
            assert response.status_code == 404, path
            assert "No such" in response.text
        decision = _post(
            client,
            f"/alerts/{target}/decision",
            csrf_token=token,
            updated_at=version,
            status="investigating",
        )
        # Malformed or unknown, no alert has that id: 404, as for GET /alerts/<id>.
        assert decision.status_code == 404
        assert "No such alert" in decision.text


class TestTamperedInvestigationDecisions:
    @pytest.mark.parametrize(
        ("fields", "code", "message"),
        [
            ({"status": "pwned"}, 422, "not one SentinelFlow knows"),
            ({"updated_at": "tuesday"}, 400, "form was incomplete"),
            ({"status": "confirmed"}, 422, "what confirms"),
            ({"status": "potential"}, 200, ""),  # already potential: nothing changes
        ],
    )
    def test_an_investigation_decision_with_edited_fields(
        self,
        client: TestClient,
        records: dict[str, str],
        fields: dict[str, str],
        code: int,
        message: str,
    ) -> None:
        path = f"/incidents/{records['incident']}"
        token, version = _form(client, path)
        data = {"csrf_token": token, "updated_at": version, "status": "investigating", **fields}
        response = _post(client, f"{path}/decision", **data)
        if code == 200:
            assert response.status_code == 303
            assert response.headers["location"].endswith("?saved=unchanged#decided")
            return
        assert response.status_code == code
        assert message in response.text

    def test_a_stale_investigation_form(self, client: TestClient, records: dict[str, str]) -> None:
        path = f"/incidents/{records['incident']}"
        token, version = _form(client, path)
        client.patch(f"/api/v1{path}", json={"assigned_to": "someone"})
        response = _post(
            client, f"{path}/decision", csrf_token=token, updated_at=version, status="investigating"
        )
        assert response.status_code == 409
        assert "changed after you opened it" in response.text

    def test_an_empty_investigation_note(self, client: TestClient, records: dict[str, str]) -> None:
        path = f"/incidents/{records['incident']}"
        token, _ = _form(client, path)
        response = _post(client, f"{path}/notes", csrf_token=token, body="   ")
        assert response.status_code == 422 and "cannot be empty" in response.text
        added = _post(client, f"{path}/notes", csrf_token=token, body="Timeline reviewed.")
        assert added.status_code == 303 and added.headers["location"].endswith("#notes")


class TestConsoleAiFailures:
    def _ask(self, client: TestClient, records: dict[str, str], provider: Any) -> Any:
        client.app.state.ai = AIState(provider=provider)  # type: ignore[attr-defined]
        token, _ = _form(client, f"/alerts/{records['alert']}")
        return _post(client, f"/alerts/{records['alert']}/ai-analysis", csrf_token=token)

    def test_an_unusable_reply(self, client: TestClient, records: dict[str, str]) -> None:
        response = self._ask(client, records, FakeProvider("no json here"))
        assert response.status_code == 502
        assert "reply was not usable" in response.text

    def test_an_unreachable_model(self, client: TestClient, records: dict[str, str]) -> None:
        response = self._ask(
            client, records, FakeProvider(ProviderUnavailableError("no reply within 60s"))
        )
        assert response.status_code == 503 and "no reply within 60s" in response.text

    def test_a_second_request_while_one_runs(
        self, client: TestClient, records: dict[str, str]
    ) -> None:
        busy = AIState(provider=FakeProvider())
        busy.lock.acquire()  # as if another analysis were under way
        client.app.state.ai = busy  # type: ignore[attr-defined]
        token, _ = _form(client, f"/alerts/{records['alert']}")
        try:
            response = _post(client, f"/alerts/{records['alert']}/ai-analysis", csrf_token=token)
        finally:
            busy.lock.release()
        assert response.status_code == 429 and "Another analysis is running" in response.text
