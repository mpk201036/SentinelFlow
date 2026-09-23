"""Persistence operations, expressed in domain terms.

The rest of the application asks for "the alert with this id" and receives a
Pydantic :class:`~app.models.alert.Alert`. It never sees a row, never builds a
query and never imports SQLAlchemy. That keeps the storage decisions here,
where they can be changed without touching the pipeline or the dashboard.

Every query is built with SQLAlchemy expressions and bound parameters. There is
no place in this module where a value becomes part of a SQL string, which is
what makes hostile field content — the whole point of the data SentinelFlow
ingests — structurally unable to alter a query.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import CursorResult, func, select
from sqlalchemy.orm import Session, selectinload

from app.database import mappers
from app.database.tables import (
    AIAnalysisRow,
    AlertRow,
    AnalystNoteRow,
    AuditLogRow,
    DetectionRuleRow,
    EventIndicatorRow,
    EventRow,
    ImportBatchRow,
    IncidentRow,
    IndicatorRow,
    MitreTechniqueRow,
    RejectedEventRow,
)
from app.models.ai import AIAnalysis
from app.models.alert import Alert
from app.models.analyst import AnalystNote, AuditEntry
from app.models.enums import AlertStatus, IndicatorType, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.ingestion import IngestionReport, RejectedRecord
from app.models.mitre import MitreTechnique

_ALERT_LOADERS = (
    selectinload(AlertRow.detections),
    selectinload(AlertRow.indicators),
    selectinload(AlertRow.mitre_mappings),
    selectinload(AlertRow.events),
)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
def save_event(session: Session, event: SecurityEvent) -> EventRow:
    """Store one event. Events are immutable, so this is always an insert."""
    row = mappers.event_to_row(event)
    session.add(row)
    session.flush()
    return row


def save_events(session: Session, events: Iterable[SecurityEvent]) -> int:
    """Store many events in one flush. Returns the number stored."""
    rows = [mappers.event_to_row(event) for event in events]
    session.add_all(rows)
    session.flush()
    return len(rows)


def get_event(session: Session, event_id: UUID) -> SecurityEvent | None:
    row = session.get(EventRow, event_id)
    return mappers.row_to_event(row) if row else None


def list_events(
    session: Session,
    *,
    source: str | None = None,
    hostname_key: str | None = None,
    username_key: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[SecurityEvent]:
    """Query events by the indexed correlation keys."""
    query = select(EventRow).order_by(EventRow.timestamp.desc())
    if source is not None:
        query = query.where(EventRow.source == source)
    if hostname_key is not None:
        query = query.where(EventRow.hostname_key == hostname_key)
    if username_key is not None:
        query = query.where(EventRow.username_key == username_key)
    if since is not None:
        query = query.where(EventRow.timestamp >= since)
    if until is not None:
        query = query.where(EventRow.timestamp <= until)
    rows: Sequence[EventRow] = session.scalars(query.limit(limit).offset(offset)).all()
    return [mappers.row_to_event(row) for row in rows]


def count_events(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(EventRow)) or 0)


# ---------------------------------------------------------------------------
# Indicators and ATT&CK catalogue
# ---------------------------------------------------------------------------
def upsert_indicator(session: Session, indicator: Indicator) -> IndicatorRow:
    """Record a sighting, merging into an existing indicator when one exists.

    Indicators are unique per (type, value): seeing ``10.0.0.5`` in fifty events
    is one indicator with fifty sightings, not fifty indicators.
    """
    existing = find_indicator(session, indicator.indicator_type, indicator.value)
    if existing is not None:
        existing.first_seen = min(existing.first_seen, indicator.first_seen)
        existing.last_seen = max(existing.last_seen, indicator.last_seen)
        existing.occurrences += indicator.occurrences
        session.flush()
        return existing

    row = mappers.indicator_to_row(indicator)
    session.add(row)
    session.flush()
    return row


def upsert_technique(session: Session, technique: MitreTechnique) -> MitreTechniqueRow:
    """Insert or refresh a technique in the ATT&CK catalogue."""
    existing = session.get(MitreTechniqueRow, technique.technique_id)
    if existing is not None:
        existing.name = technique.name
        existing.tactics = list(technique.tactics)
        existing.description = technique.description
        session.flush()
        return existing

    row = mappers.technique_to_row(technique)
    session.add(row)
    session.flush()
    return row


def list_indicators(
    session: Session,
    *,
    indicator_type: IndicatorType | None = None,
    limit: int = 100,
    order_by_frequency: bool = False,
) -> list[Indicator]:
    """Stored indicators, newest sighting first unless frequency is requested."""
    query = select(IndicatorRow).limit(limit)
    if indicator_type is not None:
        query = query.where(IndicatorRow.indicator_type == indicator_type)
    query = query.order_by(
        IndicatorRow.occurrences.desc() if order_by_frequency else IndicatorRow.last_seen.desc()
    )
    return [mappers.row_to_indicator(row) for row in session.scalars(query).all()]


def count_indicators(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(IndicatorRow)) or 0)


def find_indicator(
    session: Session, indicator_type: IndicatorType, value: str
) -> IndicatorRow | None:
    """Look up one indicator by its unique (type, value) pair."""
    return session.scalar(
        select(IndicatorRow).where(
            IndicatorRow.indicator_type == indicator_type, IndicatorRow.value == value
        )
    )


def link_event_indicator(
    session: Session,
    event_id: UUID,
    indicator_id: UUID,
    *,
    source_field: str | None = None,
    occurrences: int = 1,
) -> EventIndicatorRow:
    """Record that an indicator was seen in an event.

    Idempotent per (event, indicator): re-running extraction over the same
    event updates the sighting count rather than inserting a duplicate.
    """
    existing = session.get(EventIndicatorRow, (event_id, indicator_id))
    if existing is not None:
        existing.occurrences = occurrences
        existing.source_field = source_field or existing.source_field
        session.flush()
        return existing

    row = EventIndicatorRow(
        event_id=event_id,
        indicator_id=indicator_id,
        source_field=source_field,
        occurrences=occurrences,
    )
    session.add(row)
    session.flush()
    return row


def list_indicators_for_event(session: Session, event_id: UUID) -> list[Indicator]:
    """Every indicator extracted from one event."""
    rows = session.scalars(
        select(IndicatorRow)
        .join(EventIndicatorRow, EventIndicatorRow.indicator_id == IndicatorRow.indicator_id)
        .where(EventIndicatorRow.event_id == event_id)
        .order_by(IndicatorRow.indicator_type)
    ).all()
    return [mappers.row_to_indicator(row) for row in rows]


def find_events_for_indicator(
    session: Session, indicator_type: IndicatorType, value: str, *, limit: int = 100
) -> list[SecurityEvent]:
    """Every event an indicator was seen in.

    The question correlation asks, and the reason ``event_indicators`` exists:
    a value found inside a command line is not reachable by querying columns.
    """
    rows = session.scalars(
        select(EventRow)
        .join(EventIndicatorRow, EventIndicatorRow.event_id == EventRow.event_id)
        .join(IndicatorRow, IndicatorRow.indicator_id == EventIndicatorRow.indicator_id)
        .where(IndicatorRow.indicator_type == indicator_type, IndicatorRow.value == value)
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [mappers.row_to_event(row) for row in rows]


def events_without_indicators(session: Session, *, limit: int = 500) -> list[SecurityEvent]:
    """Stored events that extraction has not run over yet."""
    linked = select(EventIndicatorRow.event_id)
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.event_id.not_in(linked))
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [mappers.row_to_event(row) for row in rows]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
def save_alert(session: Session, alert: Alert) -> AlertRow:
    """Store an alert with its detections, indicators and ATT&CK mappings.

    Techniques are registered in the catalogue first, because
    ``mitre_mappings.technique_id`` is a foreign key into it — a mapping to a
    technique that does not exist is rejected by the database.
    """
    for mapping in alert.mitre:
        upsert_technique(session, mapping.technique)

    row = mappers.alert_to_row(alert)
    session.add(row)
    session.flush()

    if alert.event_ids:
        events = session.scalars(
            select(EventRow).where(EventRow.event_id.in_(alert.event_ids))
        ).all()
        row.events = list(events)

    row.indicators = [upsert_indicator(session, indicator) for indicator in alert.indicators]
    session.flush()
    return row


def get_alert(session: Session, alert_id: UUID) -> Alert | None:
    row = session.scalar(
        select(AlertRow).where(AlertRow.alert_id == alert_id).options(*_ALERT_LOADERS)
    )
    return mappers.row_to_alert(row) if row else None


def list_alerts(
    session: Session,
    *,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    incident_id: UUID | None = None,
    open_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> list[Alert]:
    query = select(AlertRow).options(*_ALERT_LOADERS).order_by(AlertRow.created_at.desc())
    if status is not None:
        query = query.where(AlertRow.status == status)
    if severity is not None:
        query = query.where(AlertRow.severity_level == severity)
    if incident_id is not None:
        query = query.where(AlertRow.incident_id == incident_id)
    if open_only:
        open_statuses = [s for s in AlertStatus if s.is_open]
        query = query.where(AlertRow.status.in_(open_statuses))
    rows = session.scalars(query.limit(limit).offset(offset)).all()
    return [mappers.row_to_alert(row) for row in rows]


def events_awaiting_triage(session: Session, *, limit: int = 1_000) -> list[SecurityEvent]:
    """Stored events the pipeline has not processed yet.

    Deliberately not "events with no alert". A threshold rule anchors its
    detection on the last event of a burst, so the rest of the burst has no
    alert of its own and would be re-evaluated forever, producing a duplicate
    brute-force alert on every run.
    """
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.triaged_at.is_(None))
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [mappers.row_to_event(row) for row in rows]


def mark_events_triaged(session: Session, event_ids: Iterable[UUID]) -> int:
    """Record that the pipeline has processed these events."""
    ids = list(event_ids)
    if not ids:
        return 0
    moment = _now()
    result = cast(
        "CursorResult[Any]",
        session.execute(
            sa.update(EventRow).where(EventRow.event_id.in_(ids)).values(triaged_at=moment)
        ),
    )
    session.flush()
    return int(result.rowcount or 0)


def count_recent_alerts_for_host(session: Session, hostname_key: str, *, since: datetime) -> int:
    """Alerts already raised for a host, by the time of the event behind them.

    Feeds the severity engine's repeat-activity factor. Counted on the event's
    timestamp rather than the alert's creation time, so importing a week-old
    export does not make everything in it look like a fresh burst.
    """
    return int(
        session.scalar(
            select(func.count())
            .select_from(AlertRow)
            .join(EventRow, EventRow.event_id == AlertRow.primary_event_id)
            .where(EventRow.hostname_key == hostname_key, EventRow.timestamp >= since)
        )
        or 0
    )


def count_alerts(session: Session, *, status: AlertStatus | None = None) -> int:
    query = select(func.count()).select_from(AlertRow)
    if status is not None:
        query = query.where(AlertRow.status == status)
    return int(session.scalar(query) or 0)


def severity_breakdown(session: Session) -> dict[str, int]:
    """Alert counts per severity band, for the dashboard and the CLI."""
    rows = session.execute(
        select(AlertRow.severity_level, func.count()).group_by(AlertRow.severity_level)
    ).all()
    return {str(level.value): int(count) for level, count in rows}


def update_alert_status(session: Session, alert_id: UUID, status: AlertStatus) -> AlertRow | None:
    """Change an alert's status. Callers are expected to write an audit entry."""
    row = session.get(AlertRow, alert_id)
    if row is None:
        return None
    row.status = status
    row.updated_at = _now()
    if not status.is_open and row.closed_at is None:
        row.closed_at = row.updated_at
    session.flush()
    return row


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
def save_incident(session: Session, incident: Incident) -> IncidentRow:
    row = mappers.incident_to_row(incident)
    session.add(row)
    session.flush()
    if incident.alert_ids:
        alerts = session.scalars(
            select(AlertRow).where(AlertRow.alert_id.in_(incident.alert_ids))
        ).all()
        for alert_row in alerts:
            alert_row.incident_id = row.incident_id
        session.flush()
    return row


def get_incident(session: Session, incident_id: UUID) -> Incident | None:
    row = session.scalar(
        select(IncidentRow)
        .where(IncidentRow.incident_id == incident_id)
        .options(selectinload(IncidentRow.alerts))
    )
    return mappers.row_to_incident(row) if row else None


def list_incidents(session: Session, *, limit: int = 50) -> list[Incident]:
    rows = session.scalars(
        select(IncidentRow)
        .options(selectinload(IncidentRow.alerts))
        .order_by(IncidentRow.created_at.desc())
        .limit(limit)
    ).all()
    return [mappers.row_to_incident(row) for row in rows]


# ---------------------------------------------------------------------------
# Optional AI analysis
# ---------------------------------------------------------------------------
def save_ai_analysis(session: Session, analysis: AIAnalysis) -> AIAnalysisRow:
    """Store advisory model output. Writes only to ``ai_analysis``."""
    row = mappers.ai_analysis_to_row(analysis)
    session.add(row)
    session.flush()
    return row


def get_ai_analyses(session: Session, alert_id: UUID) -> list[AIAnalysis]:
    rows = session.scalars(
        select(AIAnalysisRow)
        .where(AIAnalysisRow.alert_id == alert_id)
        .options(selectinload(AIAnalysisRow.statements))
        .order_by(AIAnalysisRow.generated_at.desc())
    ).all()
    return [mappers.row_to_ai_analysis(row) for row in rows]


# ---------------------------------------------------------------------------
# Analyst workflow
# ---------------------------------------------------------------------------
def add_note(session: Session, note: AnalystNote) -> AnalystNoteRow:
    row = mappers.note_to_row(note)
    session.add(row)
    session.flush()
    return row


def list_notes(session: Session, *, alert_id: UUID | None = None) -> list[AnalystNote]:
    query = select(AnalystNoteRow).order_by(AnalystNoteRow.created_at.asc())
    if alert_id is not None:
        query = query.where(AnalystNoteRow.alert_id == alert_id)
    return [mappers.row_to_note(row) for row in session.scalars(query).all()]


def record_audit(session: Session, entry: AuditEntry) -> AuditLogRow:
    """Append to the audit trail. Entries are never updated or deleted."""
    row = mappers.audit_to_row(entry)
    session.add(row)
    session.flush()
    return row


def list_audit(
    session: Session, *, object_id: UUID | None = None, limit: int = 100
) -> list[AuditEntry]:
    query = select(AuditLogRow).order_by(AuditLogRow.occurred_at.desc()).limit(limit)
    if object_id is not None:
        query = query.where(AuditLogRow.object_id == object_id)
    return [mappers.row_to_audit(row) for row in session.scalars(query).all()]


# ---------------------------------------------------------------------------
# Detection rule catalogue
# ---------------------------------------------------------------------------
def upsert_detection_rule(session: Session, rule: Any) -> DetectionRuleRow:
    """Mirror a loaded rule into the catalogue table.

    The YAML on disk stays the source of truth. This table exists so the
    dashboard and reports can name a rule without re-reading the filesystem,
    and so an alert raised last month can still be explained after the rule
    file has been edited.
    """
    definition = rule.model_dump(mode="json", by_alias=True)
    existing = session.get(DetectionRuleRow, rule.rule_id)
    target = existing or DetectionRuleRow(rule_id=rule.rule_id)

    target.name = rule.name
    target.description = rule.description
    target.severity = rule.severity
    target.confidence = rule.confidence
    target.enabled = rule.enabled
    target.recommendation = rule.recommendation
    target.mitre_technique_ids = list(rule.mitre)
    target.definition = definition
    target.source_path = rule.source_path
    target.loaded_at = _now()

    if existing is None:
        session.add(target)
    session.flush()
    return target


def list_detection_rules(session: Session) -> list[DetectionRuleRow]:
    return list(session.scalars(select(DetectionRuleRow).order_by(DetectionRuleRow.rule_id)).all())


def count_detection_rules(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(DetectionRuleRow)) or 0)


# ---------------------------------------------------------------------------
# Ingestion bookkeeping
# ---------------------------------------------------------------------------
def find_batch_by_hash(session: Session, content_hash: str) -> ImportBatchRow | None:
    """Look up a previous import of identical content."""
    return session.scalar(select(ImportBatchRow).where(ImportBatchRow.content_hash == content_hash))


def save_import_batch(session: Session, report: IngestionReport) -> ImportBatchRow:
    """Record an import and everything it rejected.

    A batch row describes *content*, keyed by its hash, so a deliberate
    re-import (``--force``) or a repeated API submission updates the existing
    row rather than inserting a second one with the same hash. The fact that
    the content was imported again is recorded in the audit log, which is the
    table designed for "what happened, and when".
    """
    content_hash = report.content_hash or str(report.batch_id)
    existing = find_batch_by_hash(session, content_hash)
    if existing is not None:
        existing.imported_at = report.started_at
        existing.origin = report.origin
        existing.adapter = report.adapter
        existing.accepted += report.accepted
        existing.rejected += report.rejected
        for rejection in report.rejections:
            existing.rejections.append(mappers.rejected_to_row(rejection, existing.batch_id))
        session.flush()
        return existing

    row = ImportBatchRow(
        batch_id=report.batch_id,
        imported_at=report.started_at,
        origin=report.origin,
        adapter=report.adapter,
        content_hash=content_hash,
        accepted=report.accepted,
        rejected=report.rejected,
    )
    row.rejections = [
        mappers.rejected_to_row(rejection, report.batch_id) for rejection in report.rejections
    ]
    session.add(row)
    session.flush()
    return row


def list_rejections(
    session: Session, *, batch_id: UUID | None = None, limit: int = 100
) -> list[RejectedRecord]:
    """Records that failed to normalise, newest first."""
    query = select(RejectedEventRow).order_by(RejectedEventRow.rejected_at.desc()).limit(limit)
    if batch_id is not None:
        query = query.where(RejectedEventRow.batch_id == batch_id)
    return [mappers.row_to_rejected(row) for row in session.scalars(query).all()]


def list_batches(session: Session, *, limit: int = 50) -> list[ImportBatchRow]:
    return list(
        session.scalars(
            select(ImportBatchRow).order_by(ImportBatchRow.imported_at.desc()).limit(limit)
        ).all()
    )


def _now() -> datetime:
    from app.models.base import utcnow

    return utcnow()
