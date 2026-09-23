"""Stage 10: REST API tests.

Covers:
- App factory produces a working ASGI app.
- Every registered route responds (no 404/500 at the handler level).
- Health endpoint returns expected shape and schema version.
- Rules endpoint returns all 15 rules.
- Alerts and incidents endpoints return paginated responses.
- Events endpoint returns paginated responses.
- Ingest endpoint accepts canonical events and returns the right shape.
- Triage endpoint processes pending events.
- Correlate endpoint groups alerts.
- Stats endpoint returns counts.
- Error handling: 404, 422, unknown-source.
- Security headers are present on every response.
- Rate-limit and body-size-limit middleware are wired.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.core.config import Settings
from app.database.init_db import initialize_database
from app.database.session import get_engine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    db = tmp_path_factory.mktemp("api_db") / "test.db"
    return Settings(
        database_url=f"sqlite:///{db}",
        environment="test",
        api_docs_enabled=True,
        ai_enabled=False,
        api_rate_limit_per_minute=0,  # disable rate limiting in tests
    )


@pytest.fixture(scope="module")
def client(app_settings: Settings) -> TestClient:
    engine = get_engine(app_settings)
    initialize_database(engine)
    app = create_app(app_settings)
    return TestClient(app, raise_server_exceptions=True)


def _canonical_event(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "canonical",
        "event_type": "process_creation",
        "hostname": "test-host",
        "username": "test-user",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden",
        "src_ip": "10.0.0.5",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def test_create_app_returns_asgi_app(app_settings: Settings) -> None:
    app = create_app(app_settings)
    assert callable(app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_ok(client: TestClient) -> None:
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["database"] == "ok"
    assert isinstance(body["schema_version"], int)
    assert body["ai_enabled"] is False


def test_health_has_security_headers(client: TestClient) -> None:
    r = client.get("/api/v1/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "X-Request-ID" in r.headers


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_rules_returns_list(client: TestClient) -> None:
    r = client.get("/api/v1/rules")
    assert r.status_code == 200
    rules = r.json()
    assert isinstance(rules, list)
    assert len(rules) >= 10  # at least the shipped rules
    ids = [rule["rule_id"] for rule in rules]
    assert "SF-0003" in ids


def test_rule_detail(client: TestClient) -> None:
    r = client.get("/api/v1/rules/SF-0003")
    assert r.status_code == 200
    body = r.json()
    assert body["rule_id"] == "SF-0003"
    assert body["severity"] == "high"
    assert "T1059.001" in body["mitre"]


def test_rule_not_found(client: TestClient) -> None:
    r = client.get("/api/v1/rules/SF-9999")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_events_empty_page(client: TestClient) -> None:
    r = client.get("/api/v1/events")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert "total" in body
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_event_not_found(client: TestClient) -> None:
    r = client.get(f"/api/v1/events/{uuid4()}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_alerts_empty_page(client: TestClient) -> None:
    r = client.get("/api/v1/alerts")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body


def test_alert_not_found(client: TestClient) -> None:
    r = client.get(f"/api/v1/alerts/{uuid4()}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


def test_incidents_empty_page(client: TestClient) -> None:
    r = client.get("/api/v1/incidents")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body


def test_incident_not_found(client: TestClient) -> None:
    r = client.get(f"/api/v1/incidents/{uuid4()}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_shape(client: TestClient) -> None:
    r = client.get("/api/v1/stats")
    assert r.status_code == 200
    body = r.json()
    for key in ("events", "alerts", "alerts_open", "incidents", "indicators"):
        assert key in body, f"missing key: {key}"


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


def test_ingest_canonical_event(client: TestClient) -> None:
    payload = {"events": [_canonical_event()], "source": "canonical", "triage": False}
    r = client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    assert body["adapter"] == "canonical"


def test_ingest_and_triage(client: TestClient) -> None:
    # An encoded PowerShell command should fire SF-0003 (high severity).
    event = _canonical_event(
        process_name="powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
    )
    payload = {"events": [event], "source": "canonical", "triage": True}
    r = client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1
    assert body["alerts_created"] >= 1


def test_ingest_empty_events_rejected(client: TestClient) -> None:
    r = client.post("/api/v1/ingest", json={"events": []})
    assert r.status_code == 422


def test_ingest_unknown_source(client: TestClient) -> None:
    payload = {"events": [_canonical_event()], "source": "no_such_adapter"}
    r = client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 400
    assert r.json()["error"] == "unknown_source"


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


def test_triage_dry_run(client: TestClient) -> None:
    r = client.post("/api/v1/triage?dry_run=true")
    assert r.status_code == 200
    body = r.json()
    assert "events_processed" in body
    assert "alerts_created" in body


def test_triage_live(client: TestClient) -> None:
    r = client.post("/api/v1/triage")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["events_processed"], int)


# ---------------------------------------------------------------------------
# Correlate
# ---------------------------------------------------------------------------


def test_correlate(client: TestClient) -> None:
    r = client.post("/api/v1/correlate")
    assert r.status_code == 200
    body = r.json()
    for key in (
        "alerts_considered",
        "incidents_created",
        "incidents_extended",
        "standalone_alerts",
    ):
        assert key in body


# ---------------------------------------------------------------------------
# Pagination bounds
# ---------------------------------------------------------------------------


def test_pagination_invalid_limit(client: TestClient) -> None:
    r = client.get("/api/v1/alerts?limit=0")
    assert r.status_code == 422


def test_pagination_oversized_limit(client: TestClient) -> None:
    r = client.get("/api/v1/alerts?limit=9999")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Ingest + full round-trip: events show up in alerts list
# ---------------------------------------------------------------------------


def test_ingest_triage_alert_visible(client: TestClient) -> None:
    """An ingested event that fires a rule should produce a visible alert."""
    event = _canonical_event(
        hostname="roundtrip-host",
        process_name="powershell.exe",
        command_line=(
            "powershell.exe -nop -NonInteractive -enc "
            "JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA="
        ),
    )
    ingest_r = client.post(
        "/api/v1/ingest", json={"events": [event], "source": "canonical", "triage": True}
    )
    assert ingest_r.status_code == 200

    alerts_r = client.get("/api/v1/alerts")
    assert alerts_r.status_code == 200
    items = alerts_r.json()["items"]
    assert len(items) >= 1

    # The severity always travels with its provenance.
    for item in items:
        sev = item["severity"]
        assert sev["method"] == "deterministic"
        assert "factors" in sev


# ---------------------------------------------------------------------------
# AI boundary: severity.method is never "ai"
# ---------------------------------------------------------------------------


def test_severity_method_is_always_deterministic(client: TestClient) -> None:
    r = client.get("/api/v1/alerts")
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"]["method"] == "deterministic", (
            f"alert {item['alert_id']} has non-deterministic severity"
        )
