"""Stage 3 — persistence.

Most of these are integration tests against a real SQLite file, because the
things most likely to be wrong in a persistence layer are the things a mocked
database cannot tell you: whether foreign keys are actually enforced, whether a
timezone survives a round trip, and whether the value stored matches the value
the API emits.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import mappers, repository
from app.database.init_db import (
    current_version,
    database_status,
    existing_tables,
    initialize_database,
    table_counts,
)
from app.database.session import (
    _sqlite_path,
    get_db_session,
    get_engine,
    get_session_factory,
    reset_engine,
    session_scope,
)
from app.database.tables import ALL_TABLES, SCHEMA_VERSION, AlertRow, DetectionRow, EventRow
from app.models import (
    Actor,
    AIAnalysis,
    AIStatement,
    Alert,
    AlertSeverity,
    AlertStatus,
    AnalystNote,
    AuditAction,
    AuditEntry,
    Classification,
    Confidence,
    DetectionMatch,
    DetectionResult,
    EventType,
    Incident,
    IncidentStatus,
    Indicator,
    IndicatorType,
    MitreMapping,
    MitreTechnique,
    SecurityEvent,
    Severity,
    SeverityFactor,
    StatementType,
    utcnow,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def build_event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
        "event_type": EventType.PROCESS_CREATION,
        "hostname": "WIN-LAB-01",
        "username": "LAB\\lab-user",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -enc AAA=",
        "src_ip": "10.0.0.5",
        "raw_event": {"EventID": 1, "nested": {"a": [1, 2, 3]}},
        "tags": ["lab"],
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


def build_alert(event: SecurityEvent, **overrides: object) -> Alert:
    technique = MitreTechnique(technique_id="T1059.001", name="PowerShell", tactics=["Execution"])
    payload: dict[str, object] = {
        "title": "Encoded PowerShell on WIN-LAB-01",
        "primary_event_id": event.event_id,
        "severity": AlertSeverity.from_factors(
            [SeverityFactor(name="rule_severity", points=65, detail="Rule SF-0003 is HIGH")]
        ),
        "confidence": Confidence.HIGH,
        "detections": [
            DetectionResult(
                rule_id="SF-0003",
                rule_name="Encoded PowerShell command",
                rule_severity=Severity.HIGH,
                description="PowerShell invoked with an encoded command block.",
                recommendation="Decode the command and confirm with the user.",
                event_id=event.event_id,
                matched=[
                    DetectionMatch(
                        field_name="command_line",
                        condition="contains '-enc'",
                        observed_value="-enc AAA=",
                    )
                ],
                mitre_technique_ids=["T1059.001"],
            )
        ],
        "indicators": [
            Indicator(
                indicator_type=IndicatorType.IPV4,
                value="10.0.0.5",
                source_event_id=event.event_id,
                source_field="src_ip",
            )
        ],
        "mitre": [
            MitreMapping(
                technique=technique,
                reason="powershell.exe ran with an encoded command on WIN-LAB-01",
                source_rule_id="SF-0003",
            )
        ],
        "tags": ["lab"],
    }
    payload.update(overrides)
    return Alert(**payload)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
class TestSchemaCreation:
    def test_every_expected_table_exists(self, db_engine: Engine) -> None:
        assert set(ALL_TABLES) == set(existing_tables(db_engine))

    def test_schema_is_stamped_with_a_version(self, db_engine: Engine) -> None:
        assert current_version(db_engine) == SCHEMA_VERSION

    def test_initialisation_is_idempotent(self, db_engine: Engine) -> None:
        report = initialize_database(db_engine)
        assert report.created is False
        assert report.version == SCHEMA_VERSION
        assert current_version(db_engine) == SCHEMA_VERSION

    def test_force_recreate_drops_and_rebuilds(
        self, db_engine: Engine, db_session: Session
    ) -> None:
        repository.save_event(db_session, build_event())
        db_session.commit()
        assert table_counts(db_engine)["events"] == 1

        report = initialize_database(db_engine, drop_existing=True)
        assert report.dropped is True
        assert table_counts(db_engine)["events"] == 0

    def test_status_summary_is_complete(self, db_engine: Engine) -> None:
        status = database_status(db_engine)
        assert status["initialised"] is True
        assert status["up_to_date"] is True
        assert status["table_count"] == len(ALL_TABLES)
        assert status["row_counts"]["events"] == 0


class TestIntegrityIsActuallyEnforced:
    def test_foreign_keys_are_on(self, db_engine: Engine) -> None:
        """SQLite disables foreign keys by default; without the pragma half the
        schema would be decorative."""
        assert database_status(db_engine)["foreign_keys_enforced"] is True

    def test_orphan_detection_is_rejected(self, db_session: Session) -> None:
        db_session.add(
            DetectionRow(
                detection_id=uuid4(),
                alert_id=uuid4(),  # no such alert
                rule_id="SF-0001",
                rule_name="x",
                rule_severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="x",
                detected_at=utcnow(),
            )
        )
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()

    def test_mapping_to_an_unknown_technique_is_rejected(self, db_session: Session) -> None:
        """A technique that is not in the catalogue cannot be attached to an alert."""
        event = build_event()
        repository.save_event(db_session, event)
        alert_row = repository.save_alert(db_session, build_alert(event))
        db_session.commit()

        statement = sa.text(
            "INSERT INTO mitre_mappings "
            "(mapping_id, alert_id, technique_id, reason, confidence) "
            "VALUES (:m, :a, :t, :r, :c)"
        ).bindparams(sa.bindparam("m", type_=sa.Uuid), sa.bindparam("a", type_=sa.Uuid))

        with pytest.raises(IntegrityError):
            db_session.execute(
                statement,
                {
                    "m": uuid4(),
                    "a": alert_row.alert_id,
                    "t": "T9999",
                    "r": "fabricated mapping to a technique that does not exist",
                    "c": "medium",
                },
            )
            db_session.flush()
        db_session.rollback()

    def test_enum_values_outside_the_vocabulary_are_rejected(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert_row = repository.save_alert(db_session, build_alert(event))
        db_session.commit()

        statement = sa.text("UPDATE alerts SET status = :status WHERE alert_id = :id").bindparams(
            sa.bindparam("id", type_=sa.Uuid)
        )
        with pytest.raises(IntegrityError):
            db_session.execute(statement, {"status": "resolved", "id": alert_row.alert_id})
            db_session.flush()
        db_session.rollback()

    def test_ai_output_cannot_be_stored_unlabelled(self, db_session: Session) -> None:
        """The advisory label is enforced by a CHECK constraint, not just by code."""
        event = build_event()
        repository.save_event(db_session, event)
        alert_row = repository.save_alert(db_session, build_alert(event))
        db_session.commit()

        analysis = AIAnalysis(
            alert_id=alert_row.alert_id,
            provider="ollama",
            model="llama3.1:8b",
            summary="PowerShell executed shortly after a successful logon.",
        )
        row = mappers.ai_analysis_to_row(analysis)
        row.is_advisory = False
        db_session.add(row)
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()

    def test_duplicate_indicators_are_refused_at_the_schema_level(
        self, db_session: Session
    ) -> None:
        indicator = Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.5")
        db_session.add(mappers.indicator_to_row(indicator))
        db_session.flush()
        duplicate = Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.5")
        db_session.add(mappers.indicator_to_row(duplicate))
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()


# ---------------------------------------------------------------------------
# Column behaviour
# ---------------------------------------------------------------------------
class TestColumnTypes:
    def test_timestamps_come_back_timezone_aware_and_utc(self, db_session: Session) -> None:
        """A naive read would silently shift every correlation window."""
        event = build_event(timestamp="2026-09-23T15:42:10+02:00")
        repository.save_event(db_session, event)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_event(db_session, event.event_id)
        assert stored is not None
        assert stored.timestamp.tzinfo is not None
        assert stored.timestamp == datetime(2026, 9, 23, 13, 42, 10, tzinfo=UTC)

    def test_enums_are_stored_as_their_api_values(self, db_session: Session) -> None:
        """The database and the JSON API must agree on 'high', not 'HIGH'."""
        event = build_event()
        repository.save_event(db_session, event)
        db_session.commit()

        # SQLAlchemy's Uuid type stores dashless hex on SQLite, so the bind
        # parameter must be typed rather than stringified.
        statement = sa.text("SELECT event_type FROM events WHERE event_id = :id").bindparams(
            sa.bindparam("id", type_=sa.Uuid)
        )
        raw = db_session.execute(statement, {"id": event.event_id}).scalar()
        assert raw == "process_creation"

    def test_json_columns_round_trip_nested_structures(self, db_session: Session) -> None:
        event = build_event(raw_event={"EventID": 1, "nested": {"a": [1, 2, 3]}})
        repository.save_event(db_session, event)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_event(db_session, event.event_id)
        assert stored is not None
        assert stored.raw_event == {"EventID": 1, "nested": {"a": [1, 2, 3]}}

    def test_correlation_keys_are_denormalised_on_write(self, db_session: Session) -> None:
        """Stored so correlation can use an index instead of scanning every row."""
        event = build_event(hostname="WIN-LAB-01", username="LAB\\Lab-User")
        row = repository.save_event(db_session, event)
        assert row.hostname_key == "win-lab-01"
        assert row.username_key == "lab-user"


class TestHostileContentIsData:
    @pytest.mark.parametrize(
        "payload",
        [
            "'; DROP TABLE events; --",
            "admin' OR '1'='1",
            "<script>alert('xss')</script>",
            "'); DELETE FROM alerts WHERE ''='",
        ],
    )
    def test_sql_metacharacters_are_stored_verbatim_and_harmlessly(
        self, db_session: Session, db_engine: Engine, payload: str
    ) -> None:
        """Every query is built from expressions with bound parameters, so an
        event field can never become part of a statement."""
        event = build_event(hostname=payload, command_line=payload)
        repository.save_event(db_session, event)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_event(db_session, event.event_id)
        assert stored is not None
        assert stored.hostname == payload
        assert stored.command_line == payload
        assert "events" in existing_tables(db_engine)
        assert table_counts(db_engine)["events"] == 1


# ---------------------------------------------------------------------------
# Round trips through the repository
# ---------------------------------------------------------------------------
class TestRoundTrips:
    def test_event(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        db_session.commit()
        db_session.expunge_all()
        assert repository.get_event(db_session, event.event_id) == event

    def test_alert_with_all_of_its_analysis(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_alert(db_session, alert.alert_id)
        assert stored is not None
        assert stored.title == alert.title
        assert stored.severity.score == alert.severity.score
        assert stored.severity.level is Severity.HIGH
        assert stored.severity.method == "deterministic"
        assert [f.name for f in stored.severity.factors] == ["rule_severity"]
        assert stored.rule_ids == ["SF-0003"]
        assert stored.technique_ids == ["T1059.001"]
        assert stored.detections[0].matched[0].observed_value == "-enc AAA="
        assert stored.mitre[0].reason == alert.mitre[0].reason
        assert [i.value for i in stored.indicators] == ["10.0.0.5"]

    def test_incident_membership(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        incident = Incident(
            title="Possible credential attack on WIN-LAB-01",
            severity=Severity.HIGH,
            correlation_key="hostname:win-lab-01",
            correlation_reasons=["same hostname within 30 minutes"],
            alert_ids=[alert.alert_id],
            hostnames=["WIN-LAB-01"],
        )
        repository.save_incident(db_session, incident)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_incident(db_session, incident.incident_id)
        assert stored is not None
        assert stored.status is IncidentStatus.POTENTIAL
        assert stored.alert_ids == [alert.alert_id]
        assert stored.display_label == "Potential Incident"

    def test_ai_analysis_keeps_its_labels(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        analysis = AIAnalysis(
            alert_id=alert.alert_id,
            provider="ollama",
            model="llama3.1:8b",
            summary="PowerShell executed on WIN-LAB-01 after a successful logon.",
            statements=[
                AIStatement(statement_type=StatementType.OBSERVED, text="powershell.exe ran."),
                AIStatement(
                    statement_type=StatementType.UNKNOWN, text="Whether it was authorised."
                ),
            ],
            suggested_severity=Severity.CRITICAL,
            injection_suspected=True,
        )
        repository.save_ai_analysis(db_session, analysis)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_ai_analyses(db_session, alert.alert_id)
        assert len(stored) == 1
        assert stored[0].is_advisory is True
        assert stored[0].injection_suspected is True
        assert stored[0].suggested_severity is Severity.CRITICAL
        assert [s.statement_type for s in stored[0].statements] == [
            StatementType.OBSERVED,
            StatementType.UNKNOWN,
        ]

    def test_the_ai_suggestion_never_becomes_the_stored_verdict(self, db_session: Session) -> None:
        """The whole design claim, checked against the database."""
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        repository.save_ai_analysis(
            db_session,
            AIAnalysis(
                alert_id=alert.alert_id,
                provider="ollama",
                model="llama3.1:8b",
                summary="This looks like a confirmed compromise.",
                suggested_severity=Severity.CRITICAL,
            ),
        )
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_alert(db_session, alert.alert_id)
        assert stored is not None
        assert stored.severity_level is Severity.HIGH
        assert stored.severity.method == "deterministic"

    def test_note_and_audit_entry(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        repository.add_note(
            db_session,
            AnalystNote(author="miaad", body="Confirmed with the user.", alert_id=alert.alert_id),
        )
        repository.record_audit(
            db_session,
            AuditEntry(
                actor=Actor.ANALYST,
                actor_name="miaad",
                action=AuditAction.ALERT_STATUS_CHANGED,
                object_type="alert",
                object_id=alert.alert_id,
                before="new",
                after="investigating",
            ),
        )
        db_session.commit()
        db_session.expunge_all()

        notes = repository.list_notes(db_session, alert_id=alert.alert_id)
        assert [n.body for n in notes] == ["Confirmed with the user."]
        trail = repository.list_audit(db_session, object_id=alert.alert_id)
        assert trail[0].action is AuditAction.ALERT_STATUS_CHANGED


# ---------------------------------------------------------------------------
# Repository behaviour
# ---------------------------------------------------------------------------
class TestRepository:
    def test_indicator_sightings_accumulate(self, db_session: Session) -> None:
        now = utcnow()
        first = Indicator(
            indicator_type=IndicatorType.IPV4,
            value="10.0.0.5",
            first_seen=now - timedelta(hours=2),
            last_seen=now - timedelta(hours=2),
        )
        repository.upsert_indicator(db_session, first)
        repository.upsert_indicator(
            db_session,
            Indicator(
                indicator_type=IndicatorType.IPV4, value="10.0.0.5", first_seen=now, last_seen=now
            ),
        )
        db_session.commit()

        stored = repository.list_indicators(db_session)
        assert len(stored) == 1
        assert stored[0].occurrences == 2
        assert stored[0].first_seen == first.first_seen

    def test_technique_catalogue_upsert_refreshes_metadata(self, db_session: Session) -> None:
        repository.upsert_technique(db_session, MitreTechnique(technique_id="T1110", name="Old"))
        repository.upsert_technique(
            db_session,
            MitreTechnique(technique_id="T1110", name="Brute Force", tactics=["Credential Access"]),
        )
        db_session.commit()
        row = db_session.execute(
            sa.text("SELECT name FROM mitre_techniques WHERE technique_id = :t"), {"t": "T1110"}
        ).scalar()
        assert row == "Brute Force"

    def test_alerts_can_be_filtered(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        high = build_alert(event)
        low = build_alert(
            event,
            title="Low severity alert",
            severity=AlertSeverity.from_factors(
                [SeverityFactor(name="rule_severity", points=20, detail="Rule is LOW")]
            ),
            status=AlertStatus.CLOSED,
            detections=[],
            indicators=[],
            mitre=[],
        )
        repository.save_alert(db_session, high)
        repository.save_alert(db_session, low)
        db_session.commit()

        assert len(repository.list_alerts(db_session)) == 2
        assert len(repository.list_alerts(db_session, severity=Severity.HIGH)) == 1
        assert len(repository.list_alerts(db_session, open_only=True)) == 1
        assert len(repository.list_alerts(db_session, status=AlertStatus.CLOSED)) == 1

    def test_closing_an_alert_records_when(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        db_session.commit()

        row = repository.update_alert_status(db_session, alert.alert_id, AlertStatus.BENIGN)
        db_session.commit()
        assert row is not None
        assert row.closed_at is not None

    def test_updating_an_unknown_alert_returns_none(self, db_session: Session) -> None:
        assert repository.update_alert_status(db_session, uuid4(), AlertStatus.CLOSED) is None

    def test_events_can_be_queried_by_correlation_key(self, db_session: Session) -> None:
        repository.save_events(
            db_session,
            [
                build_event(hostname="WIN-LAB-01"),
                build_event(hostname="WIN-LAB-02"),
                build_event(hostname="WIN-LAB-01", timestamp="2026-09-23T14:00:00Z"),
            ],
        )
        db_session.commit()
        assert len(repository.list_events(db_session, hostname_key="win-lab-01")) == 2
        assert len(repository.list_events(db_session, username_key="lab-user")) == 3

    def test_events_can_be_queried_by_time_window(self, db_session: Session) -> None:
        repository.save_events(
            db_session,
            [
                build_event(timestamp="2026-09-23T10:00:00Z"),
                build_event(timestamp="2026-09-23T14:00:00Z"),
            ],
        )
        db_session.commit()
        window = repository.list_events(db_session, since=datetime(2026, 9, 23, 12, tzinfo=UTC))
        assert len(window) == 1


class TestCascades:
    def test_deleting_an_alert_removes_its_analysis_but_keeps_the_evidence(
        self, db_session: Session, db_engine: Engine
    ) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        repository.save_ai_analysis(
            db_session,
            AIAnalysis(
                alert_id=alert.alert_id,
                provider="ollama",
                model="llama3.1:8b",
                summary="Advisory analysis of the alert.",
                statements=[AIStatement(statement_type=StatementType.OBSERVED, text="It ran.")],
            ),
        )
        db_session.commit()

        db_session.delete(db_session.get(AlertRow, alert.alert_id))
        db_session.commit()

        counts = table_counts(db_engine)
        assert counts["alerts"] == 0
        assert counts["detections"] == 0
        assert counts["ai_analysis"] == 0
        assert counts["ai_statements"] == 0
        # The observation itself, and the indicator seen in it, are not opinions
        # about the alert and survive it.
        assert counts["events"] == 1
        assert counts["indicators"] == 1

    def test_the_audit_trail_outlives_what_it_describes(
        self, db_session: Session, db_engine: Engine
    ) -> None:
        """object_id is deliberately not a foreign key."""
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        repository.record_audit(
            db_session,
            AuditEntry(
                action=AuditAction.ALERT_CREATED, object_type="alert", object_id=alert.alert_id
            ),
        )
        db_session.commit()

        db_session.delete(db_session.get(AlertRow, alert.alert_id))
        db_session.commit()

        assert table_counts(db_engine)["audit_log"] == 1


class TestClassificationWorkflow:
    def test_analyst_verdict_persists(self, db_session: Session) -> None:
        event = build_event()
        repository.save_event(db_session, event)
        alert = build_alert(event)
        repository.save_alert(db_session, alert)
        db_session.commit()

        row = db_session.get(AlertRow, alert.alert_id)
        assert row is not None
        row.classification = Classification.FALSE_POSITIVE
        row.status = AlertStatus.CLOSED
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_alert(db_session, alert.alert_id)
        assert stored is not None
        assert stored.classification is Classification.FALSE_POSITIVE
        assert stored.is_open is False


class TestEventImmutabilityInPractice:
    def test_events_are_only_ever_inserted(self, db_session: Session) -> None:
        """No repository function updates an event; evidence does not change."""
        event = build_event()
        repository.save_event(db_session, event)
        db_session.commit()
        assert not [name for name in dir(repository) if name.startswith("update_event")]
        row = db_session.get(EventRow, event.event_id)
        assert row is not None


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
class TestSessionLifecycle:
    def test_scope_commits_on_success(self, global_db: Settings) -> None:
        with session_scope(global_db) as session:
            repository.save_event(session, build_event())
        with session_scope(global_db) as session:
            assert repository.count_events(session) == 1

    def test_scope_rolls_back_on_failure(self, global_db: Settings) -> None:
        """A half-written import must leave nothing behind."""
        with pytest.raises(RuntimeError), session_scope(global_db) as session:
            repository.save_event(session, build_event())
            raise RuntimeError("ingestion failed halfway through")

        with session_scope(global_db) as session:
            assert repository.count_events(session) == 0

    def test_fastapi_dependency_yields_a_working_session(self, global_db: Settings) -> None:
        generator = get_db_session()
        session = next(generator)
        repository.save_event(session, build_event())
        with pytest.raises(StopIteration):
            next(generator)  # closes and commits the scope

        with session_scope(global_db) as verify:
            assert repository.count_events(verify) == 1

    def test_engine_and_factory_are_singletons(self, global_db: Settings) -> None:
        assert get_engine(global_db) is get_engine(global_db)
        assert get_session_factory(global_db) is get_session_factory(global_db)

    def test_reset_releases_the_engine(self, global_db: Settings) -> None:
        first = get_engine(global_db)
        reset_engine()
        assert get_engine(global_db) is not first

    @pytest.mark.parametrize(
        "url, expected_none",
        [
            ("sqlite:///:memory:", True),
            ("postgresql://user@host/db", True),
            ("sqlite:////tmp/sentinelflow.db", False),
        ],
    )
    def test_sqlite_path_extraction(self, url: str, expected_none: bool) -> None:
        assert (_sqlite_path(url) is None) is expected_none
