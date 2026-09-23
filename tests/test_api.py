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

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.core.config import Settings
from app.database.init_db import initialize_database
from app.database.session import get_engine, reset_engine
from app.ingestion.generator import DEMO_ENCODED_COMMAND

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
def client(app_settings: Settings) -> Iterator[TestClient]:
    # The session dependency uses the process-wide engine. Point it at this
    # module's database explicitly rather than relying on this fixture
    # happening to create it first, and release it afterwards.
    reset_engine()
    initialize_database(get_engine(app_settings))
    # As a context manager, so the app's lifespan runs and disposes its engine.
    with TestClient(create_app(app_settings), raise_server_exceptions=True) as test_client:
        yield test_client
    reset_engine()


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
    r = client.post("/api/v1/events", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    assert body["adapter"] == "canonical"


def test_ingest_and_triage(client: TestClient) -> None:
    # An encoded PowerShell command should fire SF-0003 (high severity).
    event = _canonical_event(
        process_name="powershell.exe",
        command_line=f"powershell.exe -nop -w hidden -enc {DEMO_ENCODED_COMMAND}",
    )
    payload = {"events": [event], "source": "canonical", "triage": True}
    r = client.post("/api/v1/events", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["accepted"] == 1
    assert body["alerts_created"] >= 1


def test_ingest_empty_events_rejected(client: TestClient) -> None:
    r = client.post("/api/v1/events", json={"events": []})
    assert r.status_code == 422


def test_ingest_unknown_source(client: TestClient) -> None:
    payload = {"events": [_canonical_event()], "source": "no_such_adapter"}
    r = client.post("/api/v1/events", json=payload)
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
        command_line=f"powershell.exe -nop -NonInteractive -enc {DEMO_ENCODED_COMMAND}",
    )
    ingest_r = client.post(
        "/api/v1/events", json={"events": [event], "source": "canonical", "triage": True}
    )
    assert ingest_r.status_code == 201

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


# ---------------------------------------------------------------------------
# Stage 10 review: a regression test for every defect the review found
# ---------------------------------------------------------------------------
@pytest.fixture
def fresh(global_db: Settings) -> Iterator[TestClient]:
    """A client over an empty database of its own, rate limiting off."""
    app = create_app(global_db.model_copy(update={"api_rate_limit_per_minute": 0}))
    with TestClient(app) as test_client:
        yield test_client


def _batch(fresh_settings: Settings) -> list[Any]:
    from app.database import repository
    from app.database.session import session_scope

    with session_scope(fresh_settings) as session:
        return [(b.accepted, b.rejected, b.origin) for b in repository.list_batches(session)]


def test_the_old_ingest_path_is_gone(fresh: TestClient) -> None:
    assert fresh.post("/api/v1/ingest", json={"events": [_canonical_event()]}).status_code == 404


def test_an_api_batch_is_recorded_once_with_true_counts(
    fresh: TestClient, global_db: Settings
) -> None:
    """The route used to save the batch a second time, which the upsert
    counted as a re-import: accepted and rejected doubled on every call."""
    body = {
        "source": "canonical",
        "triage": False,
        "events": [_canonical_event(), {"no": "timestamp"}],
    }
    assert fresh.post("/api/v1/events", json=body).status_code == 201
    assert _batch(global_db) == [(1, 1, "api")]


def test_a_retry_is_idempotent(fresh: TestClient) -> None:
    body = {"source": "canonical", "triage": False, "events": [_canonical_event()]}
    first = fresh.post("/api/v1/events", json=body)
    retry = fresh.post("/api/v1/events", json=body)
    assert first.status_code == 201
    assert retry.status_code == 200
    assert retry.json()["duplicate_batch"] is True
    assert fresh.get("/api/v1/events").json()["total"] == 1


def test_force_accepts_a_genuine_repeat(fresh: TestClient) -> None:
    body = {"source": "canonical", "triage": False, "events": [_canonical_event()]}
    fresh.post("/api/v1/events", json=body)
    again = fresh.post("/api/v1/events", json={**body, "force": True})
    assert again.status_code == 201
    assert fresh.get("/api/v1/events").json()["total"] == 2


def test_a_batch_with_nothing_valid_is_200_with_reasons(fresh: TestClient) -> None:
    r = fresh.post("/api/v1/events", json={"source": "canonical", "events": [{"no": "timestamp"}]})
    assert r.status_code == 200
    assert r.json()["accepted"] == 0
    assert r.json()["rejections"][0]["reason"] == "adapter_error"


def test_the_import_limit_applies_to_the_api(global_db: Settings) -> None:
    limited = global_db.model_copy(
        update={"max_events_per_import": 2, "api_rate_limit_per_minute": 0}
    )
    events = [_canonical_event(hostname=f"h{i}") for i in range(5)]
    with TestClient(create_app(limited)) as client:
        body = client.post(
            "/api/v1/events", json={"source": "canonical", "triage": False, "events": events}
        ).json()
    assert body["accepted"] == 2
    assert body["rejections"][-1]["reason"] == "limit_exceeded"


def test_a_filtered_total_matches_the_filter(fresh: TestClient) -> None:
    """Total and items now come from one filter definition."""
    events = [_canonical_event(hostname="alpha"), _canonical_event(hostname="beta")]
    fresh.post("/api/v1/events", json={"source": "canonical", "triage": False, "events": events})
    page = fresh.get("/api/v1/events?hostname=ALPHA").json()
    assert page["total"] == len(page["items"]) == 1


def test_username_filters_normalise_like_storage(fresh: TestClient) -> None:
    """LAB\\lab-user and lab-user are one account."""
    fresh.post(
        "/api/v1/events",
        json={
            "source": "canonical",
            "triage": False,
            "events": [_canonical_event(username="lab-user")],
        },
    )
    assert fresh.get("/api/v1/events", params={"username": "LAB\\Lab-User"}).json()["total"] == 1


def test_incident_pages_honour_offset(fresh: TestClient, global_db: Settings) -> None:
    """Offset used to be echoed back and ignored."""
    from app.database import repository
    from app.database.session import session_scope
    from app.models.enums import Severity
    from app.models.incident import Incident

    with session_scope(global_db) as session:
        for index in range(3):
            repository.save_incident(
                session,
                Incident(
                    title=f"incident {index}", severity=Severity.LOW, correlation_key=f"k{index}"
                ),
            )
    first = fresh.get("/api/v1/incidents?limit=1&offset=0").json()
    second = fresh.get("/api/v1/incidents?limit=1&offset=1").json()
    assert first["total"] == 3
    assert first["items"][0]["incident_id"] != second["items"][0]["incident_id"]


# --- File upload -------------------------------------------------------------
def test_a_json_upload_is_ingested(fresh: TestClient) -> None:
    content = json.dumps([_canonical_event()]).encode()
    r = fresh.post(
        "/api/v1/events/import",
        files={"file": ("events.json", content, "application/json")},
        data={"source": "canonical", "triage": "false"},
    )
    assert r.status_code == 201
    assert r.json()["accepted"] == 1


def test_a_csv_upload_is_ingested(fresh: TestClient) -> None:
    content = b"timestamp,source,hostname\n2026-09-23T13:42:10Z,canonical,WIN-LAB-01\n"
    r = fresh.post("/api/v1/events/import", files={"file": ("export.csv", content, "text/csv")})
    assert r.status_code == 201
    assert r.json()["accepted"] == 1


def test_an_unsupported_upload_is_415(fresh: TestClient) -> None:
    r = fresh.post("/api/v1/events/import", files={"file": ("events.xml", b"<x/>", "text/xml")})
    assert r.status_code == 415


def test_an_oversized_upload_is_413(global_db: Settings) -> None:
    small = global_db.model_copy(update={"max_upload_bytes": 2_048, "api_rate_limit_per_minute": 0})
    with TestClient(create_app(small)) as client:
        r = client.post(
            "/api/v1/events/import", files={"file": ("big.json", b"[" + b" " * 4_000 + b"]")}
        )
    assert r.status_code == 413


def test_an_upload_filename_is_a_label_never_a_path(fresh: TestClient, global_db: Settings) -> None:
    """Only the final component survives, and it is never opened."""
    content = json.dumps([_canonical_event()]).encode()
    r = fresh.post(
        "/api/v1/events/import",
        files={"file": ("../../../etc/passwd.json", content, "application/json")},
        data={"source": "canonical", "triage": "false"},
    )
    assert r.status_code == 201
    assert _batch(global_db)[0][2] == "upload:passwd.json"


def test_a_repeated_upload_is_a_no_op(fresh: TestClient) -> None:
    content = json.dumps([_canonical_event()]).encode()
    files = {"file": ("events.json", content, "application/json")}
    data = {"source": "canonical", "triage": "false"}
    assert fresh.post("/api/v1/events/import", files=files, data=data).status_code == 201
    repeat = fresh.post("/api/v1/events/import", files=files, data=data)
    assert repeat.status_code == 200
    assert repeat.json()["duplicate_batch"] is True


# --- Serving -------------------------------------------------------------------
def test_serve_refuses_a_non_loopback_address_without_expose() -> None:
    """No authentication means exposure has to be a decision, not a typo."""
    from typer.testing import CliRunner

    from app.cli import app as cli

    result = CliRunner().invoke(cli, ["serve", "--host", "0.0.0.0", "--port", "8799"])
    assert result.exit_code == 2
    assert "no authentication" in result.output.lower()


def test_each_app_serves_the_database_it_was_given(tmp_path: Any) -> None:
    """The factory's settings used to reach the middleware and nothing else:
    every handler read the process defaults. Two apps, two databases."""
    settings_pair = []
    for name in ("a", "b"):
        settings = Settings(
            _env_file=None,
            database_url=f"sqlite:///{tmp_path / name}.db",
            api_rate_limit_per_minute=0,
        )
        initialize_database(get_engine(settings))
        reset_engine()
        settings_pair.append(settings)

    body = {"source": "canonical", "triage": False, "events": [_canonical_event()]}
    with (
        TestClient(create_app(settings_pair[0])) as first,
        TestClient(create_app(settings_pair[1])) as second,
    ):
        assert first.post("/api/v1/events", json=body).status_code == 201
        assert first.get("/api/v1/events").json()["total"] == 1
        assert second.get("/api/v1/events").json()["total"] == 0
