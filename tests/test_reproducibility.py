"""Stage 15 - the same events always give the same verdict.

Every alert page says the deterministic layer is "reproducible: the same event
always gives this result". This is the test behind that sentence. The full
demonstration dataset - background noise and the attack chain - is run
through two fresh databases, and everything deterministic must match: scores,
every factor and its wording, rules, ATT&CK mappings and their reasons,
indicators, and how alerts were grouped into investigations.

IDs are random by design, so records are compared by what they are about
(the event behind them), never by ID.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database import repository
from app.database.init_db import initialize_database
from app.database.session import create_db_engine
from app.ingestion import IngestionService, generate_dataset, get_adapter
from app.services import CorrelationService, TriagePipeline

pytestmark = pytest.mark.integration

BASE_TIME = datetime(2026, 9, 23, 22, 0, tzinfo=UTC)
SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


@contextmanager
def _fresh() -> Iterator[tuple[Session, Settings]]:
    with tempfile.TemporaryDirectory() as directory:
        settings = Settings(_env_file=None, database_url=f"sqlite:///{Path(directory) / 'r.db'}")
        engine = create_db_engine(settings)
        initialize_database(engine)
        session = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            yield session, settings
        finally:
            session.close()
            engine.dispose()


def _event_key(event: Any) -> tuple[str, ...]:
    """What an event is, independent of the random ID it was given."""
    return (
        event.timestamp.isoformat(),
        event.source,
        event.event_type.value,
        event.hostname or "",
        event.username or "",
        event.command_line or "",
        event.event_message or "",
    )


def _run(session: Session, settings: Settings) -> dict[str, Any]:
    """Ingest, triage and correlate the dataset; return every deterministic result."""
    records = generate_dataset(normal_count=60, seed=1337, base_time=BASE_TIME)
    events = [get_adapter(record.adapter).normalise(record.record) for record in records]
    repository.save_events(session, events)
    # Every shipped sample too, so each adapter and most rules take part.
    service = IngestionService(session, settings)
    for sample in sorted(SAMPLES.glob("*")):
        if sample.suffix in (".json", ".csv") and sample.name != "malformed.json":
            service.ingest_file(sample, allowed_roots=[SAMPLES])
    TriagePipeline(session, settings).process_stored()
    CorrelationService(session, settings).correlate_pending()
    session.commit()

    alerts: dict[tuple[str, ...], Any] = {}
    for alert in repository.list_alerts(session, limit=10_000):
        event = repository.get_event(session, alert.primary_event_id)
        assert event is not None
        alerts[_event_key(event)] = {
            "title": alert.title,
            "score": alert.severity.score,
            "level": alert.severity_level.value,
            "factors": [(f.name, f.points, f.detail) for f in alert.severity.factors],
            "confidence": alert.confidence.value,
            "rules": sorted(alert.rule_ids),
            "matched": sorted(
                (d.rule_id, m.field_name, m.condition, m.observed_value or "")
                for d in alert.detections
                for m in d.matched
            ),
            "mitre": sorted((m.technique_id, m.reason) for m in alert.mitre),
            "indicators": sorted((i.indicator_type.value, i.value) for i in alert.indicators),
            "incident": alert.incident_id is not None,
        }

    incidents = []
    for incident in repository.list_incidents(session, limit=1_000):
        members = repository.list_alerts(session, incident_id=incident.incident_id, limit=1_000)
        member_keys = sorted(
            _event_key(repository.get_event(session, a.primary_event_id)) for a in members
        )
        incidents.append(
            {
                "title": incident.title,
                "severity": incident.severity.value,
                "key": incident.correlation_key,
                "reasons": sorted(incident.correlation_reasons),
                "members": member_keys,
            }
        )
    incidents.sort(key=lambda item: (item["key"], item["members"]))
    return {"alerts": alerts, "incidents": incidents}


def test_the_same_events_give_the_same_verdicts() -> None:
    with _fresh() as (session, settings):
        first = _run(session, settings)
    with _fresh() as (session, settings):
        second = _run(session, settings)

    assert first["alerts"], "the dataset should raise alerts"
    assert first["incidents"], "the dataset should produce an investigation"
    assert first["alerts"].keys() == second["alerts"].keys()
    for key, result in first["alerts"].items():
        assert second["alerts"][key] == result, key
    assert first["incidents"] == second["incidents"]


def test_running_the_pipeline_again_changes_nothing() -> None:
    """Triage and correlation are safe to repeat: nothing is counted twice."""
    with _fresh() as (session, settings):
        before = _run(session, settings)
        TriagePipeline(session, settings).process_stored()
        CorrelationService(session, settings).correlate_pending()
        session.commit()
        assert repository.count_alerts(session) == len(before["alerts"])
        assert repository.count_incidents(session) == len(before["incidents"])
