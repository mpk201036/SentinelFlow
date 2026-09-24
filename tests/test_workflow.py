"""Stage 13 - the analyst workflow: its rules, its audit trail, its history.

The console, the API and the CLI all go through ``AnalystWorkflow``, so the
rules are tested once, here, against a real database. The interfaces are
tested in ``test_workflow_interfaces.py``.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import repository
from app.database.init_db import apply_pending_migrations, current_version
from app.database.tables import SCHEMA_VERSION
from app.enrichment.extractor import IOCExtractor
from app.models.alert import Alert
from app.models.enums import (
    Actor,
    AlertStatus,
    AuditAction,
    Classification,
    IncidentStatus,
    IndicatorType,
)
from app.services.correlation import CorrelationService
from app.services.workflow import (
    UNCHANGED,
    AlertDecision,
    AnalystWorkflow,
    Channel,
    IncidentDecision,
    RecordNotFoundError,
    StaleDecisionError,
    WorkflowError,
)
from tests.ai_support import triaged_alert

pytestmark = pytest.mark.integration

S = AlertStatus
C = Classification


@pytest.fixture
def workflow(db_session: Session) -> AnalystWorkflow:
    return AnalystWorkflow(db_session, analyst="alice", channel=Channel.CLI)


@pytest.fixture
def alert(db_session: Session, db_settings: Settings) -> Alert:
    return triaged_alert(db_session, db_settings)


def _decide(workflow: AnalystWorkflow, alert: Alert, **fields: Any) -> Any:
    return workflow.decide_alert(alert.alert_id, AlertDecision(**fields))


def _trail(session: Session, object_id: Any) -> list[Any]:
    entries = repository.list_audit(session, object_id=object_id, oldest_first=True)
    return [e for e in entries if e.actor is Actor.ANALYST]


def _move(workflow: AnalystWorkflow, alert: Alert, *steps: dict[str, Any]) -> Alert:
    for step in steps:
        result = _decide(workflow, alert, **step)
        assert result.alert is not None
        alert = result.alert
    return alert


# ===========================================================================
# Alert rules
# ===========================================================================
class TestAlertRules:
    @pytest.mark.parametrize(
        ("fields", "message"),
        [
            ({"status": S.CLOSED, "reason": "done"}, "Classify the alert before closing it"),
            ({"status": S.BENIGN, "reason": "done"}, "Classify the alert before closing it"),
            (
                {"status": S.CLOSED, "classification": C.FALSE_POSITIVE},
                "Say why the alert is being closed",
            ),
            (
                {"status": S.CLOSED, "classification": C.NEEDS_MORE_INFORMATION, "reason": "x"},
                "needs more information cannot be closed",
            ),
            (
                {"status": S.BENIGN, "classification": C.TRUE_POSITIVE, "reason": "x"},
                "Only a benign positive or a false positive",
            ),
            ({"status": S.ESCALATED}, "Say why the alert is being escalated"),
            ({"status": S.ESCALATED, "reason": "   "}, "Say why the alert is being escalated"),
        ],
    )
    def test_decisions_that_are_refused(
        self, workflow: AnalystWorkflow, alert: Alert, fields: dict[str, Any], message: str
    ) -> None:
        with pytest.raises(WorkflowError, match=message):
            _decide(workflow, alert, **fields)

    def test_nothing_is_written_when_a_decision_is_refused(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        with pytest.raises(WorkflowError):
            _decide(workflow, alert, status=S.CLOSED, assigned_to="bob", reason="x")
        after = repository.get_alert(db_session, alert.alert_id)
        assert after is not None
        assert (after.status, after.assigned_to, after.updated_at) == (
            S.NEW,
            None,
            alert.updated_at,
        )
        assert _trail(db_session, alert.alert_id) == []

    def test_an_alert_cannot_go_back_to_new(self, workflow: AnalystWorkflow, alert: Alert) -> None:
        alert = _move(workflow, alert, {"status": S.INVESTIGATING})
        with pytest.raises(WorkflowError, match="cannot go back to New"):
            _decide(workflow, alert, status=S.NEW)

    def test_the_full_lifecycle(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        alert = _move(
            workflow,
            alert,
            {"status": S.INVESTIGATING, "assigned_to": "alice"},
            {"status": S.ESCALATED, "reason": "Needs IR: admin account created"},
            {"status": S.CLOSED, "classification": C.TRUE_POSITIVE, "reason": "Contained"},
        )
        assert (alert.status, alert.classification) == (S.CLOSED, C.TRUE_POSITIVE)
        assert alert.closed_at is not None

    def test_reopening_needs_a_reason_and_clears_the_closing_time(
        self, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        alert = _move(
            workflow,
            alert,
            {"status": S.BENIGN, "classification": C.FALSE_POSITIVE, "reason": "Test script"},
        )
        assert alert.closed_at is not None
        with pytest.raises(WorkflowError, match="being reopened"):
            _decide(workflow, alert, status=S.INVESTIGATING)
        alert = _move(workflow, alert, {"status": S.INVESTIGATING, "reason": "Seen again"})
        assert alert.status is S.INVESTIGATING and alert.closed_at is None

    def test_moving_between_closed_states_keeps_the_first_closing_time(
        self, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        alert = _move(
            workflow,
            alert,
            {"status": S.BENIGN, "classification": C.FALSE_POSITIVE, "reason": "r"},
        )
        closed_at = alert.closed_at
        alert = _move(workflow, alert, {"status": S.CLOSED})
        assert alert.closed_at == closed_at

    def test_reclassifying_a_closed_alert_needs_a_reason_and_must_fit(
        self, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        alert = _move(
            workflow,
            alert,
            {"status": S.BENIGN, "classification": C.FALSE_POSITIVE, "reason": "r"},
        )
        with pytest.raises(WorkflowError, match="classification of a closed alert"):
            _decide(workflow, alert, classification=C.BENIGN_POSITIVE)
        with pytest.raises(WorkflowError, match="Only a benign positive"):
            _decide(workflow, alert, classification=C.TRUE_POSITIVE, reason="r")
        alert = _move(
            workflow, alert, {"classification": C.BENIGN_POSITIVE, "reason": "IT confirmed"}
        )
        assert alert.classification is C.BENIGN_POSITIVE

    def test_an_open_alert_can_be_classified_without_a_reason(
        self, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        alert = _move(workflow, alert, {"classification": C.NEEDS_MORE_INFORMATION})
        assert alert.classification is C.NEEDS_MORE_INFORMATION and alert.status is S.NEW

    def test_assignment(self, workflow: AnalystWorkflow, alert: Alert) -> None:
        alert = _move(workflow, alert, {"assigned_to": "  alice  "})
        assert alert.assigned_to == "alice"
        alert = _move(workflow, alert, {"assigned_to": UNCHANGED, "status": S.INVESTIGATING})
        assert alert.assigned_to == "alice"
        alert = _move(workflow, alert, {"assigned_to": None})
        assert alert.assigned_to is None
        alert = _move(workflow, alert, {"assigned_to": "bob\x00\n"})
        assert alert.assigned_to == "bob"

    def test_a_decision_that_changes_nothing_writes_nothing(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        result = _decide(workflow, alert, status=S.NEW, assigned_to=None)
        assert not result.changed
        after = repository.get_alert(db_session, alert.alert_id)
        assert after is not None and after.updated_at == alert.updated_at
        assert _trail(db_session, alert.alert_id) == []

    def test_an_unknown_alert(self, workflow: AnalystWorkflow) -> None:
        from uuid import uuid4

        with pytest.raises(RecordNotFoundError):
            workflow.decide_alert(uuid4(), AlertDecision(status=S.INVESTIGATING))


# ===========================================================================
# Concurrency
# ===========================================================================
class TestStaleDecisions:
    def test_a_decision_against_an_old_version_is_refused(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        seen = alert.updated_at
        _move(workflow, alert, {"status": S.INVESTIGATING})
        with pytest.raises(StaleDecisionError, match="changed after you opened it"):
            _decide(workflow, alert, assigned_to="bob", expected_updated_at=seen)
        after = repository.get_alert(db_session, alert.alert_id)
        assert after is not None and after.assigned_to is None

    def test_the_write_itself_is_a_compare_and_swap(
        self, db_session: Session, alert: Alert
    ) -> None:
        """Even between the read and the write, a changed row is not overwritten."""
        stale = alert.updated_at - timedelta(seconds=1)
        assert (
            repository.update_alert_workflow(
                db_session,
                alert.alert_id,
                expected_updated_at=stale,
                status=S.INVESTIGATING,
                classification=None,
                assigned_to="mallory",
            )
            is None
        )
        written = repository.update_alert_workflow(
            db_session,
            alert.alert_id,
            expected_updated_at=alert.updated_at,
            status=S.INVESTIGATING,
            classification=None,
            assigned_to="alice",
        )
        assert written is not None

    def test_the_current_version_is_accepted(self, workflow: AnalystWorkflow, alert: Alert) -> None:
        result = _decide(
            workflow, alert, status=S.INVESTIGATING, expected_updated_at=alert.updated_at
        )
        assert result.changed


# ===========================================================================
# Audit trail
# ===========================================================================
class TestAuditTrail:
    def test_every_change_is_one_entry_naming_the_analyst_and_channel(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        _move(
            workflow,
            alert,
            {"status": S.INVESTIGATING, "assigned_to": "alice"},
            {"status": S.CLOSED, "classification": C.FALSE_POSITIVE, "reason": "Known script"},
        )
        entries = _trail(db_session, alert.alert_id)
        summary = [(e.action, e.before, e.after) for e in entries]
        assert summary == [
            (AuditAction.ALERT_STATUS_CHANGED, "new", "investigating"),
            (AuditAction.ALERT_ASSIGNED, None, "alice"),
            (AuditAction.ALERT_STATUS_CHANGED, "investigating", "closed"),
            (AuditAction.ALERT_CLASSIFIED, None, "false_positive"),
        ]
        assert {e.actor_name for e in entries} == {"alice"}
        assert all("via cli" in (e.detail or "") for e in entries)
        assert entries[2].detail == "Known script (via cli)"

    def test_a_note_is_recorded_and_audited(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        note = workflow.add_alert_note(alert.alert_id, "Owner confirmed.\nTicket 44.")
        assert note.author == "alice"
        (stored,) = repository.list_notes(db_session, alert_id=alert.alert_id)
        assert stored.body == "Owner confirmed.\nTicket 44."
        (entry,) = _trail(db_session, alert.alert_id)
        assert entry.action is AuditAction.NOTE_ADDED
        assert entry.after == f"note {note.note_id}"

    def test_an_empty_note_is_refused(self, workflow: AnalystWorkflow, alert: Alert) -> None:
        with pytest.raises(WorkflowError, match="cannot be empty"):
            workflow.add_alert_note(alert.alert_id, " \n\t ")

    def test_a_decision_must_name_an_analyst(self, db_session: Session) -> None:
        with pytest.raises(ValueError, match="which analyst"):
            AnalystWorkflow(db_session, analyst="  ", channel=Channel.API)

    def test_the_audit_log_cannot_be_edited_or_deleted(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        _move(workflow, alert, {"status": S.INVESTIGATING})
        db_session.commit()
        for statement in (
            "UPDATE audit_log SET actor_name = 'mallory'",
            "DELETE FROM audit_log",
        ):
            with pytest.raises(DatabaseError, match="append-only"):
                db_session.execute(sa.text(statement))
            db_session.rollback()
        assert _trail(db_session, alert.alert_id)[0].actor_name == "alice"

    def test_a_note_cannot_be_edited(
        self, db_session: Session, workflow: AnalystWorkflow, alert: Alert
    ) -> None:
        workflow.add_alert_note(alert.alert_id, "original")
        db_session.commit()
        with pytest.raises(DatabaseError, match="cannot be edited"):
            db_session.execute(sa.text("UPDATE analyst_notes SET body = 'rewritten'"))
        db_session.rollback()

    def test_correlation_records_what_it_did(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        first = triaged_alert(db_session, db_settings, hostname="WIN-CORR-01")
        second = triaged_alert(
            db_session, db_settings, hostname="WIN-CORR-01", parent_process="excel.exe"
        )
        result = CorrelationService(db_session, db_settings).correlate_pending()
        (incident,) = result.created
        (entry,) = repository.list_audit(db_session, object_id=incident.incident_id)
        assert entry.action is AuditAction.INCIDENT_CREATED
        assert entry.actor is Actor.SYSTEM
        assert "2 alerts" in (entry.after or "")
        assert {first.alert_id, second.alert_id} <= set(incident.alert_ids)

        triaged_alert(db_session, db_settings, hostname="WIN-CORR-01", parent_process="outlook.exe")
        extended = CorrelationService(db_session, db_settings).correlate_pending()
        assert [i.incident_id for i in extended.extended] == [incident.incident_id]
        actions = [
            e.action for e in repository.list_audit(db_session, object_id=incident.incident_id)
        ]
        assert AuditAction.INCIDENT_EXTENDED in actions


# ===========================================================================
# Incidents
# ===========================================================================
@pytest.fixture
def incident_id(db_session: Session, db_settings: Settings) -> Any:
    triaged_alert(db_session, db_settings, hostname="WIN-INC-01")
    triaged_alert(db_session, db_settings, hostname="WIN-INC-01", parent_process="excel.exe")
    (created,) = CorrelationService(db_session, db_settings).correlate_pending().created
    return created.incident_id


class TestIncidentRules:
    def _decide(self, workflow: AnalystWorkflow, incident_id: Any, **fields: Any) -> Any:
        return workflow.decide_incident(incident_id, IncidentDecision(**fields))

    def test_starting_an_investigation_needs_no_reason(
        self, workflow: AnalystWorkflow, incident_id: Any
    ) -> None:
        result = self._decide(
            workflow, incident_id, status=IncidentStatus.INVESTIGATING, assigned_to="alice"
        )
        assert result.incident.status is IncidentStatus.INVESTIGATING
        assert result.incident.assigned_to == "alice"

    @pytest.mark.parametrize(
        ("status", "message"),
        [
            (IncidentStatus.CONFIRMED, "what confirms"),
            (IncidentStatus.DISMISSED, "being dismissed"),
        ],
    )
    def test_ruling_needs_a_reason(
        self, workflow: AnalystWorkflow, incident_id: Any, status: IncidentStatus, message: str
    ) -> None:
        with pytest.raises(WorkflowError, match=message):
            self._decide(workflow, incident_id, status=status)
        result = self._decide(workflow, incident_id, status=status, reason="Evidence X")
        assert result.incident.status is status

    def test_only_correlation_makes_an_incident_potential(
        self, workflow: AnalystWorkflow, incident_id: Any
    ) -> None:
        self._decide(workflow, incident_id, status=IncidentStatus.INVESTIGATING)
        with pytest.raises(WorkflowError, match="Only correlation"):
            self._decide(workflow, incident_id, status=IncidentStatus.POTENTIAL)

    def test_reopening_a_ruled_incident_needs_a_reason(
        self, db_session: Session, workflow: AnalystWorkflow, incident_id: Any
    ) -> None:
        self._decide(workflow, incident_id, status=IncidentStatus.DISMISSED, reason="Lab test")
        with pytest.raises(WorkflowError, match="being reopened"):
            self._decide(workflow, incident_id, status=IncidentStatus.INVESTIGATING)
        self._decide(workflow, incident_id, status=IncidentStatus.INVESTIGATING, reason="New alert")
        entries = _trail(db_session, incident_id)
        assert [e.after for e in entries] == ["dismissed", "investigating"]
        assert entries[-1].detail == "New alert (via cli)"

    def test_a_stale_incident_decision_is_refused(
        self, workflow: AnalystWorkflow, incident_id: Any, db_session: Session
    ) -> None:
        seen = repository.get_incident(db_session, incident_id)
        assert seen is not None
        self._decide(workflow, incident_id, assigned_to="alice")
        with pytest.raises(StaleDecisionError):
            self._decide(
                workflow,
                incident_id,
                status=IncidentStatus.INVESTIGATING,
                expected_updated_at=seen.updated_at,
            )

    def test_incident_notes_are_kept_apart_from_alert_notes(
        self, db_session: Session, workflow: AnalystWorkflow, incident_id: Any
    ) -> None:
        workflow.add_incident_note(incident_id, "Timeline reviewed.")
        (note,) = repository.list_notes(db_session, incident_id=incident_id)
        assert note.body == "Timeline reviewed." and note.alert_id is None
        (entry,) = _trail(db_session, incident_id)
        assert entry.object_type == "incident"


# ===========================================================================
# Schema version 6
# ===========================================================================
_V5_AUDIT_LOG = """
CREATE TABLE audit_log (
    entry_id CHAR(32) NOT NULL, occurred_at DATETIME NOT NULL, actor VARCHAR(64) NOT NULL,
    actor_name VARCHAR(128), action VARCHAR(64) NOT NULL, object_type VARCHAR(64) NOT NULL,
    object_id CHAR(32), "before" VARCHAR(512), "after" VARCHAR(512), detail TEXT,
    CONSTRAINT pk_audit_log PRIMARY KEY (entry_id),
    CONSTRAINT ck_audit_log_audit_actor CHECK (actor IN ('system', 'analyst', 'ai_assistant')),
    CONSTRAINT ck_audit_log_audit_action CHECK (action IN ('event_ingested', 'alert_created',
        'alert_status_changed', 'alert_classified', 'note_added', 'incident_created',
        'incident_status_changed', 'ai_analysis_requested', 'ai_analysis_stored',
        'report_generated'))
)"""


class TestMigrationV6:
    def _as_version_5(self, engine: Engine) -> None:
        with engine.begin() as connection:
            for name in (
                "trg_audit_log_no_update",
                "trg_audit_log_no_delete",
                "trg_analyst_notes_no_update",
            ):
                connection.execute(sa.text(f"DROP TRIGGER {name}"))
            connection.execute(sa.text("DROP INDEX ix_audit_object"))
            connection.execute(sa.text("DROP INDEX ix_audit_log_occurred_at"))
            connection.execute(sa.text("DROP TABLE audit_log"))
            connection.execute(sa.text(_V5_AUDIT_LOG))
            connection.execute(
                sa.text("CREATE INDEX ix_audit_object ON audit_log (object_type, object_id)")
            )
            connection.execute(
                sa.text("CREATE INDEX ix_audit_log_occurred_at ON audit_log (occurred_at)")
            )
            for index in range(3):
                connection.execute(
                    sa.text(
                        "INSERT INTO audit_log (entry_id, occurred_at, actor, action, object_type) "
                        "VALUES (:id, '2026-09-01 10:00:00.000000', 'system', 'alert_created', 'alert')"
                    ),
                    {"id": f"{index:032x}"},
                )
            connection.execute(sa.text("DELETE FROM schema_version WHERE version >= 5"))
            connection.execute(
                sa.text(
                    "INSERT INTO schema_version (version, description, applied_at) "
                    "VALUES (5, 'v5', CURRENT_TIMESTAMP)"
                )
            )

    def test_a_version_5_audit_log_is_rebuilt_with_every_row_kept(self, db_engine: Engine) -> None:
        self._as_version_5(db_engine)
        with db_engine.begin() as connection, pytest.raises(DatabaseError):
            connection.execute(
                sa.text(
                    "INSERT INTO audit_log (entry_id, occurred_at, actor, action, object_type) "
                    "VALUES ('ff', '2026-09-01', 'analyst', 'alert_assigned', 'alert')"
                )
            )

        assert apply_pending_migrations(db_engine) == [6]
        assert current_version(db_engine) == SCHEMA_VERSION == 6
        with db_engine.begin() as connection:
            assert connection.execute(sa.text("SELECT count(*) FROM audit_log")).scalar() == 3
            connection.execute(
                sa.text(
                    "INSERT INTO audit_log (entry_id, occurred_at, actor, action, object_type) "
                    "VALUES ('ff', '2026-09-01', 'analyst', 'alert_assigned', 'alert')"
                )
            )
            triggers = {
                row[0]
                for row in connection.execute(
                    sa.text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
                )
            }
        assert {"trg_audit_log_no_update", "trg_audit_log_no_delete"} <= triggers
        with db_engine.begin() as connection, pytest.raises(DatabaseError, match="append-only"):
            connection.execute(sa.text("DELETE FROM audit_log"))

    def test_the_migration_is_safe_to_repeat(self, db_engine: Engine) -> None:
        from app.database.init_db import MIGRATIONS

        (migration,) = [m for m in MIGRATIONS if m.version == 6]
        with db_engine.begin() as connection:
            migration.upgrade(connection)
            migration.upgrade(connection)


# ===========================================================================
# Regressions found during Stage 13
# ===========================================================================
class TestRegressions:
    def test_reopening_through_the_low_level_helper_clears_closed_at(
        self, db_session: Session, alert: Alert
    ) -> None:
        closed = repository.update_alert_status(db_session, alert.alert_id, S.CLOSED)
        assert closed is not None and closed.closed_at is not None
        reopened = repository.update_alert_status(db_session, alert.alert_id, S.INVESTIGATING)
        assert reopened is not None and reopened.closed_at is None

    @pytest.mark.parametrize(
        "text",
        [
            "The file 'C:\\Users\\x\\Temp\\update.exe' was run",
            "ran `C:\\Tools\\a.exe` twice",
            "path: '/var/tmp/.cache/run.sh'.",
        ],
    )
    def test_a_quoted_path_is_extracted_without_its_quote(self, text: str) -> None:
        paths = [
            value
            for kind, value in IOCExtractor().scan_text(text)
            if kind is IndicatorType.FILE_PATH
        ]
        assert paths and all(not p.endswith(("'", "`")) for p in paths)

    def test_a_path_ending_in_a_bracket_keeps_it(self) -> None:
        (path,) = [
            value
            for kind, value in IOCExtractor().scan_text("see C:\\Program Files (x86)\\App\\a.exe")
            if kind is IndicatorType.FILE_PATH
        ]
        assert path == "C:\\Program Files (x86)\\App\\a.exe"

    def test_the_analyst_name_defaults_to_something_printable(self, settings: Settings) -> None:
        assert settings.analyst_name and settings.analyst_name.isprintable()

    def test_a_blank_analyst_name_is_refused(self, clean_env: pytest.MonkeyPatch) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Settings(_env_file=None, analyst_name=" \x07 ")  # type: ignore[call-arg]
