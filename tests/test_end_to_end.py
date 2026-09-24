"""Stage 15 - one analyst's day, through the public interface only.

Everything here goes over HTTP, as a client would: upload the shipped sample
exports, let SentinelFlow triage and correlate them, work the investigation,
close an alert, export a report and check it against the audit trail. No
internal function is called, so this is the test that breaks if the pieces
stop fitting together, even when each one still passes on its own.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.core.config import Settings

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"
EXPORTS = [
    "windows_security.json",
    "sysmon.json",
    "firewall.csv",
    "driftwatch.json",
    "ghostcredential.json",
]


@pytest.fixture
def client(global_db: Settings) -> Iterator[TestClient]:
    settings = global_db.model_copy(
        update={"api_rate_limit_per_minute": 0, "analyst_name": "e2e-analyst"}
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _ok(response: Any, *codes: int) -> Any:
    assert response.status_code in (codes or (200,)), (response.status_code, response.text)
    assert response.headers["x-request-id"]
    assert response.headers["x-content-type-options"] == "nosniff"
    return response.json() if "json" in response.headers.get("content-type", "") else response


def test_an_investigation_from_upload_to_verified_report(client: TestClient) -> None:
    # 1. Upload the exports, as a SOC would from each source.
    accepted = 0
    for name in EXPORTS:
        with (SAMPLES / name).open("rb") as handle:
            body = _ok(
                client.post("/api/v1/events/import", files={"file": (name, handle)}), 200, 201
            )
        accepted += body["accepted"]
    assert accepted > 0

    # 2. Triage ran on upload; correlation groups what belongs together.
    stats = _ok(client.get("/api/v1/stats"))
    assert stats["events"] == accepted and stats["alerts"] > 0
    correlation = _ok(client.post("/api/v1/correlate"))
    assert correlation["incidents_created"] >= 1

    # 3. The analyst opens the most severe investigation.
    incidents = _ok(client.get("/api/v1/incidents"))["items"]
    incident = max(
        incidents, key=lambda i: ("low", "medium", "high", "critical").index(i["severity"])
    )
    detail = _ok(client.get(f"/api/v1/incidents/{incident['incident_id']}"))
    assert detail["display_label"] == "Potential Incident"
    assert len(detail["alerts"]) >= 2

    # 4. ...takes it, works one alert to a conclusion, and leaves a note.
    _ok(
        client.patch(
            f"/api/v1/incidents/{incident['incident_id']}",
            json={"status": "investigating", "assigned_to": "e2e-analyst"},
        )
    )
    alert = detail["alerts"][0]
    before = _ok(client.get(f"/api/v1/alerts/{alert['alert_id']}"))
    refused = client.patch(f"/api/v1/alerts/{alert['alert_id']}", json={"status": "closed"})
    assert refused.status_code == 422
    closed = _ok(
        client.patch(
            f"/api/v1/alerts/{alert['alert_id']}",
            json={
                "status": "closed",
                "classification": "true_positive",
                "reason": "Part of the confirmed intrusion; host isolated.",
                "expected_updated_at": before["updated_at"],
            },
        )
    )
    assert closed["alert"]["status"] == "closed"
    assert closed["alert"]["severity"] == before["severity"]  # a decision never rescores
    _ok(
        client.post(
            f"/api/v1/incidents/{incident['incident_id']}/notes",
            json={"body": "Isolated WIN-LAB-01 at 14:05; credentials rotated."},
        ),
        201,
    )
    _ok(
        client.patch(
            f"/api/v1/incidents/{incident['incident_id']}",
            json={"status": "confirmed", "reason": "Decoy credential used after admin creation."},
        )
    )

    # 5. The report says what happened, and the audit trail vouches for it.
    report = _ok(client.get(f"/api/v1/incidents/{incident['incident_id']}/report"))
    text = report.text
    assert "Confirmed, by e2e-analyst" in text
    assert "Isolated WIN-LAB-01 at 14:05" in text
    assert "Part of the confirmed intrusion" in text
    digest = hashlib.sha256(report.content).hexdigest()
    assert report.headers["x-sentinelflow-report-sha256"] == digest

    trail = _ok(client.get(f"/api/v1/incidents/{incident['incident_id']}/audit"))
    actions = [entry["action"] for entry in trail]
    assert actions[0] == "incident_created"
    assert "incident_status_changed" in actions and "note_added" in actions
    (export,) = [entry for entry in trail if entry["action"] == "report_generated"]
    assert export["after"].endswith(f"sha256:{digest}")
    assert export["actor_name"] == "e2e-analyst"

    # 6. The console shows the same state.
    page = client.get(f"/incidents/{incident['incident_id']}")
    assert page.status_code == 200 and "Confirmed" in page.text
    assert client.get("/").status_code == 200
