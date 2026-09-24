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

import re
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
    DetectionRow,
    DetectionRuleRow,
    EventIndicatorRow,
    EventRow,
    ImportBatchRow,
    IncidentRow,
    IndicatorRow,
    MitreMappingRow,
    MitreTechniqueRow,
    RejectedEventRow,
)
from app.models.ai import AIAnalysis
from app.models.alert import Alert
from app.models.analyst import AnalystNote, AuditEntry
from app.models.enums import (
    AlertStatus,
    AuditAction,
    Classification,
    EventType,
    IncidentStatus,
    IndicatorType,
    Severity,
)
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


def get_events(session: Session, event_ids: Iterable[UUID]) -> dict[UUID, SecurityEvent]:
    """Several events in one query, keyed by id.

    Pages and reports that show many alerts need the event behind each one.
    Fetching them one at a time cost a query per alert: two hundred for a full
    alert queue.
    """
    ids = list(dict.fromkeys(event_ids))
    if not ids:
        return {}
    rows = session.scalars(select(EventRow).where(EventRow.event_id.in_(ids))).all()
    return {row.event_id: mappers.row_to_event(row) for row in rows}


def _event_filters(
    query: sa.Select[Any],
    *,
    source: str | None = None,
    event_type: EventType | None = None,
    hostname_key: str | None = None,
    username_key: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> sa.Select[Any]:
    """The one definition of an event filter, shared by listing and counting.

    A count computed from a separately written filter is a count that can
    quietly disagree with the page it describes.
    """
    if source is not None:
        query = query.where(EventRow.source == source)
    if event_type is not None:
        query = query.where(EventRow.event_type == event_type)
    if hostname_key is not None:
        query = query.where(EventRow.hostname_key == hostname_key)
    if username_key is not None:
        query = query.where(EventRow.username_key == username_key)
    if since is not None:
        query = query.where(EventRow.timestamp >= since)
    if until is not None:
        query = query.where(EventRow.timestamp <= until)
    return query


def list_events(
    session: Session,
    *,
    source: str | None = None,
    event_type: EventType | None = None,
    hostname_key: str | None = None,
    username_key: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[SecurityEvent]:
    """Query events by the indexed correlation keys, newest first."""
    query = _event_filters(
        select(EventRow),
        source=source,
        event_type=event_type,
        hostname_key=hostname_key,
        username_key=username_key,
        since=since,
        until=until,
    ).order_by(EventRow.timestamp.desc())
    rows: Sequence[EventRow] = session.scalars(query.limit(limit).offset(offset)).all()
    return [mappers.row_to_event(row) for row in rows]


def count_events_matching(
    session: Session,
    *,
    source: str | None = None,
    event_type: EventType | None = None,
    hostname_key: str | None = None,
    username_key: str | None = None,
) -> int:
    """Total for the same filter ``list_events`` applies."""
    query = _event_filters(
        select(func.count()).select_from(EventRow),
        source=source,
        event_type=event_type,
        hostname_key=hostname_key,
        username_key=username_key,
    )
    return int(session.scalar(query) or 0)


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


_HEX_PREFIX_RE = re.compile(r"^[0-9a-f]{1,32}$")


def _id_prefix_clause(column: Any, prefix: str) -> Any:
    """A LIKE clause for an id prefix, or None if the prefix is not plain hex.

    Ids are stored as 32 hex characters with no dashes. Restricting the prefix
    to hex characters also means ``%`` and ``_`` can never reach the LIKE
    pattern as wildcards.
    """
    key = prefix.strip().lower().replace("-", "")
    if not _HEX_PREFIX_RE.match(key):
        return None
    return sa.cast(column, sa.String).like(f"{key}%")


def find_alert_ids_by_prefix(session: Session, prefix: str, *, limit: int = 2) -> list[UUID]:
    """Alert ids starting with ``prefix``. Ask for 2 to tell unique from ambiguous."""
    clause = _id_prefix_clause(AlertRow.alert_id, prefix)
    if clause is None:
        return []
    return list(session.scalars(select(AlertRow.alert_id).where(clause).limit(limit)))


def _alert_filters(
    query: sa.Select[Any],
    *,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    incident_id: UUID | None = None,
    open_only: bool = False,
) -> sa.Select[Any]:
    """The one definition of an alert filter, shared by listing and counting."""
    if status is not None:
        query = query.where(AlertRow.status == status)
    if severity is not None:
        query = query.where(AlertRow.severity_level == severity)
    if incident_id is not None:
        query = query.where(AlertRow.incident_id == incident_id)
    if open_only:
        query = query.where(AlertRow.status.in_([s for s in AlertStatus if s.is_open]))
    return query


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
    query = _alert_filters(
        select(AlertRow).options(*_ALERT_LOADERS),
        status=status,
        severity=severity,
        incident_id=incident_id,
        open_only=open_only,
    ).order_by(AlertRow.created_at.desc())
    rows = session.scalars(query.limit(limit).offset(offset)).all()
    return [mappers.row_to_alert(row) for row in rows]


def count_alerts_matching(
    session: Session,
    *,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    incident_id: UUID | None = None,
    open_only: bool = False,
) -> int:
    """Total for the same filter ``list_alerts`` applies."""
    query = _alert_filters(
        select(func.count()).select_from(AlertRow),
        status=status,
        severity=severity,
        incident_id=incident_id,
        open_only=open_only,
    )
    return int(session.scalar(query) or 0)


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
    """Change an alert's status. Callers are expected to write an audit entry.

    Low-level: no workflow rules. Analyst decisions go through
    :class:`app.services.workflow.AnalystWorkflow`, which applies them and
    audits the change.
    """
    row = session.get(AlertRow, alert_id)
    if row is None:
        return None
    row.status = status
    row.updated_at = _now()
    row.closed_at = _closed_at(row.closed_at, status, row.updated_at)
    session.flush()
    return row


def _closed_at(current: datetime | None, status: AlertStatus, now: datetime) -> datetime | None:
    """Closing stamps the time once; reopening clears it."""
    if status.is_open:
        return None
    return current or now


def update_alert_workflow(
    session: Session,
    alert_id: UUID,
    *,
    expected_updated_at: datetime,
    status: AlertStatus,
    classification: Classification | None,
    assigned_to: str | None,
) -> datetime | None:
    """Apply an analyst decision, only if nobody changed the alert meanwhile.

    A compare-and-swap on ``updated_at``: the ``UPDATE`` matches only the
    version the decision was made against, so two browser tabs cannot
    silently overwrite each other. Returns the new ``updated_at``, or None if
    the alert had changed (or does not exist).
    """
    row = session.get(AlertRow, alert_id)
    if row is None:
        return None
    now = _now()
    result = session.execute(
        sa.update(AlertRow)
        .where(AlertRow.alert_id == alert_id, AlertRow.updated_at == expected_updated_at)
        .values(
            status=status,
            classification=classification,
            assigned_to=assigned_to,
            updated_at=now,
            closed_at=_closed_at(row.closed_at, status, now),
        )
        .execution_options(synchronize_session="fetch")
    )
    session.flush()
    return now if cast(CursorResult[Any], result).rowcount == 1 else None


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


def upsert_incident(session: Session, incident: Incident) -> IncidentRow:
    """Create an incident, or refresh an existing one in place.

    Refreshing rather than replacing matters: an analyst may already have moved
    the incident to investigating or written notes against it, and correlation
    finding another related alert must not undo that. Status and classification
    are therefore never touched here.
    """
    existing = session.get(IncidentRow, incident.incident_id)
    if existing is None:
        return save_incident(session, incident)

    existing.updated_at = incident.updated_at
    existing.title = incident.title
    existing.severity = incident.severity
    existing.correlation_key = incident.correlation_key
    existing.correlation_reasons = list(incident.correlation_reasons)
    existing.first_event_at = incident.first_event_at
    existing.last_event_at = incident.last_event_at
    existing.hostnames = list(incident.hostnames)
    existing.usernames = list(incident.usernames)
    existing.summary = incident.summary
    session.flush()

    if incident.alert_ids:
        attach_alerts_to_incident(session, incident.incident_id, incident.alert_ids)
    return existing


def attach_alerts_to_incident(
    session: Session, incident_id: UUID, alert_ids: Iterable[UUID]
) -> int:
    """Attach alerts to an incident, never moving one that already belongs elsewhere.

    Reassigning an alert would silently rewrite an investigation somebody may
    already be working on.
    """
    ids = list(alert_ids)
    if not ids:
        return 0
    rows = session.scalars(
        select(AlertRow).where(
            AlertRow.alert_id.in_(ids),
            (AlertRow.incident_id.is_(None)) | (AlertRow.incident_id == incident_id),
        )
    ).all()
    for row in rows:
        row.incident_id = incident_id
    session.flush()
    return len(rows)


def alerts_without_incident(
    session: Session, *, limit: int = 1_000
) -> list[tuple[Alert, SecurityEvent]]:
    """Alerts correlation has not considered yet, with the event behind each.

    Returned with their events because correlation reasons entirely in event
    time. An alert created today from a week-old export describes activity from
    a week ago, and grouping it by when the row was written would put it beside
    whatever else happened to be imported this afternoon.
    """
    rows = session.execute(
        select(AlertRow, EventRow)
        .join(EventRow, EventRow.event_id == AlertRow.primary_event_id)
        .options(*_ALERT_LOADERS)
        .where(AlertRow.incident_id.is_(None))
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [(mappers.row_to_alert(alert), mappers.row_to_event(event)) for alert, event in rows]


def alerts_with_events_since(
    session: Session, since: datetime, *, limit: int = 2_000
) -> list[tuple[Alert, SecurityEvent]]:
    """Alerts whose underlying event happened at or after ``since``.

    Joined on the event rather than the alert's creation time: importing a
    week-old export late must not make its alerts look simultaneous.
    """
    rows = session.execute(
        select(AlertRow, EventRow)
        .join(EventRow, EventRow.event_id == AlertRow.primary_event_id)
        .options(*_ALERT_LOADERS)
        .where(EventRow.timestamp >= since)
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [(mappers.row_to_alert(alert), mappers.row_to_event(event)) for alert, event in rows]


def count_incidents(session: Session, *, status: IncidentStatus | None = None) -> int:
    query = select(func.count()).select_from(IncidentRow)
    if status is not None:
        query = query.where(IncidentRow.status == status)
    return int(session.scalar(query) or 0)


def update_incident_workflow(
    session: Session,
    incident_id: UUID,
    *,
    expected_updated_at: datetime,
    status: IncidentStatus,
    assigned_to: str | None,
) -> datetime | None:
    """Apply an analyst decision to an incident. Compare-and-swap, as for alerts."""
    now = _now()
    result = session.execute(
        sa.update(IncidentRow)
        .where(
            IncidentRow.incident_id == incident_id,
            IncidentRow.updated_at == expected_updated_at,
        )
        .values(status=status, assigned_to=assigned_to, updated_at=now)
        .execution_options(synchronize_session="fetch")
    )
    session.flush()
    return now if cast(CursorResult[Any], result).rowcount == 1 else None


def update_incident_status(
    session: Session, incident_id: UUID, status: IncidentStatus
) -> IncidentRow | None:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        return None
    row.status = status
    row.updated_at = _now()
    session.flush()
    return row


def get_incident(session: Session, incident_id: UUID) -> Incident | None:
    row = session.scalar(
        select(IncidentRow)
        .where(IncidentRow.incident_id == incident_id)
        .options(selectinload(IncidentRow.alerts))
    )
    return mappers.row_to_incident(row) if row else None


def find_incident_ids_by_prefix(session: Session, prefix: str, *, limit: int = 2) -> list[UUID]:
    clause = _id_prefix_clause(IncidentRow.incident_id, prefix)
    if clause is None:
        return []
    return list(session.scalars(select(IncidentRow.incident_id).where(clause).limit(limit)))


def list_incidents(session: Session, *, limit: int = 50, offset: int = 0) -> list[Incident]:
    rows = session.scalars(
        select(IncidentRow)
        .options(selectinload(IncidentRow.alerts))
        .order_by(IncidentRow.created_at.desc())
        .limit(limit)
        .offset(offset)
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


def get_ai_analyses_for(
    session: Session, alert_ids: Iterable[UUID]
) -> dict[UUID, list[AIAnalysis]]:
    """Analyses for several alerts in one query, newest first per alert."""
    ids = list(dict.fromkeys(alert_ids))
    found: dict[UUID, list[AIAnalysis]] = {alert_id: [] for alert_id in ids}
    if not ids:
        return found
    rows = session.scalars(
        select(AIAnalysisRow)
        .where(AIAnalysisRow.alert_id.in_(ids))
        .options(selectinload(AIAnalysisRow.statements))
        .order_by(AIAnalysisRow.generated_at.desc())
    ).all()
    for row in rows:
        found[row.alert_id].append(mappers.row_to_ai_analysis(row))
    return found


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


def list_notes(
    session: Session, *, alert_id: UUID | None = None, incident_id: UUID | None = None
) -> list[AnalystNote]:
    query = select(AnalystNoteRow).order_by(AnalystNoteRow.created_at.asc())
    if alert_id is not None:
        query = query.where(AnalystNoteRow.alert_id == alert_id)
    if incident_id is not None:
        query = query.where(AnalystNoteRow.incident_id == incident_id)
    return [mappers.row_to_note(row) for row in session.scalars(query).all()]


def notes_for_alerts(session: Session, alert_ids: Iterable[UUID]) -> dict[UUID, list[AnalystNote]]:
    """Notes on several alerts in one query, oldest first per alert."""
    ids = list(dict.fromkeys(alert_ids))
    found: dict[UUID, list[AnalystNote]] = {alert_id: [] for alert_id in ids}
    if not ids:
        return found
    rows = session.scalars(
        select(AnalystNoteRow)
        .where(AnalystNoteRow.alert_id.in_(ids))
        .order_by(AnalystNoteRow.created_at.asc())
    ).all()
    for row in rows:
        if row.alert_id is not None:
            found[row.alert_id].append(mappers.row_to_note(row))
    return found


def record_audit(session: Session, entry: AuditEntry) -> AuditLogRow:
    """Append to the audit trail. Entries are never updated or deleted."""
    row = mappers.audit_to_row(entry)
    session.add(row)
    session.flush()
    return row


def _audit_filters(
    object_id: UUID | None,
    object_type: str | None,
    action: AuditAction | None,
    object_ids: Sequence[UUID] | None = None,
) -> list[Any]:
    clauses: list[Any] = []
    if object_id is not None:
        clauses.append(AuditLogRow.object_id == object_id)
    if object_ids is not None:
        clauses.append(AuditLogRow.object_id.in_(list(object_ids)))
    if object_type is not None:
        clauses.append(AuditLogRow.object_type == object_type)
    if action is not None:
        clauses.append(AuditLogRow.action == action)
    return clauses


def list_audit(
    session: Session,
    *,
    object_id: UUID | None = None,
    object_ids: Sequence[UUID] | None = None,
    object_type: str | None = None,
    action: AuditAction | None = None,
    limit: int = 100,
    offset: int = 0,
    oldest_first: bool = False,
) -> list[AuditEntry]:
    """The audit trail, newest first unless asked otherwise.

    Ties on ``occurred_at`` are broken by insertion order, so a status change
    and the classification recorded in the same decision always read in the
    order they were written.
    """
    order = (
        (AuditLogRow.occurred_at.asc(), sa.text("audit_log.rowid ASC"))
        if oldest_first
        else (AuditLogRow.occurred_at.desc(), sa.text("audit_log.rowid DESC"))
    )
    query = (
        select(AuditLogRow)
        .where(*_audit_filters(object_id, object_type, action, object_ids))
        .order_by(*order)
        .limit(limit)
        .offset(offset)
    )
    return [mappers.row_to_audit(row) for row in session.scalars(query).all()]


def count_audit(
    session: Session,
    *,
    object_id: UUID | None = None,
    object_type: str | None = None,
    action: AuditAction | None = None,
) -> int:
    query = (
        select(func.count())
        .select_from(AuditLogRow)
        .where(*_audit_filters(object_id, object_type, action))
    )
    return int(session.scalar(query) or 0)


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


# ---------------------------------------------------------------------------
# Dashboard aggregates
#
# Every aggregate here filters on the *event* time behind each alert, never on
# when the alert row was written. An export imported this afternoon describes
# activity from whenever it happened, and a "last 24 hours" view built on row
# time would show a week of old activity as a spike at 3pm.
# ---------------------------------------------------------------------------
def _alerts_in_window(since: datetime | None) -> sa.Select[Any]:
    """Alert ids whose underlying event happened at or after ``since``."""
    query = select(AlertRow.alert_id).join(EventRow, EventRow.event_id == AlertRow.primary_event_id)
    if since is not None:
        query = query.where(EventRow.timestamp >= since)
    return query


def alert_counts(session: Session, *, since: datetime | None = None) -> dict[str, dict[str, int]]:
    """Alert totals by severity and by status, within the window."""
    window = _alerts_in_window(since)
    by_severity = session.execute(
        select(AlertRow.severity_level, func.count())
        .where(AlertRow.alert_id.in_(window))
        .group_by(AlertRow.severity_level)
    ).all()
    by_status = session.execute(
        select(AlertRow.status, func.count())
        .where(AlertRow.alert_id.in_(window))
        .group_by(AlertRow.status)
    ).all()
    return {
        "severity": {str(level.value): int(count) for level, count in by_severity},
        "status": {str(state.value): int(count) for state, count in by_status},
    }


def top_alert_hosts(
    session: Session, *, since: datetime | None = None, limit: int = 8
) -> list[tuple[str, int]]:
    """Hosts with the most alerts, by the host named on the underlying event."""
    rows = session.execute(
        select(EventRow.hostname, func.count(AlertRow.alert_id))
        .join(AlertRow, AlertRow.primary_event_id == EventRow.event_id)
        .where(EventRow.hostname.is_not(None))
        .where(AlertRow.alert_id.in_(_alerts_in_window(since)))
        .group_by(EventRow.hostname_key, EventRow.hostname)
        .order_by(func.count(AlertRow.alert_id).desc(), EventRow.hostname)
        .limit(limit)
    ).all()
    return [(str(host), int(count)) for host, count in rows]


def top_alert_rules(
    session: Session, *, since: datetime | None = None, limit: int = 8
) -> list[tuple[str, str, int]]:
    """Rules that fired most often: (rule_id, rule_name, detections)."""
    rows = session.execute(
        select(DetectionRow.rule_id, DetectionRow.rule_name, func.count())
        .where(DetectionRow.alert_id.in_(_alerts_in_window(since)))
        .group_by(DetectionRow.rule_id, DetectionRow.rule_name)
        .order_by(func.count().desc(), DetectionRow.rule_id)
        .limit(limit)
    ).all()
    return [(str(rule_id), str(name), int(count)) for rule_id, name, count in rows]


def alert_event_times(
    session: Session, *, since: datetime | None = None, limit: int = 10_000
) -> list[tuple[datetime, Severity]]:
    """When each alert's activity happened, with its severity, for the trend."""
    rows = session.execute(
        select(EventRow.timestamp, AlertRow.severity_level)
        .join(AlertRow, AlertRow.primary_event_id == EventRow.event_id)
        .where(AlertRow.alert_id.in_(_alerts_in_window(since)))
        .order_by(EventRow.timestamp.asc())
        .limit(limit)
    ).all()
    return [(moment, level) for moment, level in rows]


def observed_techniques(
    session: Session, *, since: datetime | None = None
) -> list[tuple[str, int]]:
    """ATT&CK techniques attached to alerts in the window, with alert counts.

    Read from the mappings table, not from what rules declared, so a technique
    the catalogue could not name - and therefore refused to map - never appears.
    """
    rows = session.execute(
        select(MitreMappingRow.technique_id, func.count(sa.distinct(MitreMappingRow.alert_id)))
        .where(MitreMappingRow.alert_id.in_(_alerts_in_window(since)))
        .group_by(MitreMappingRow.technique_id)
        .order_by(func.count(sa.distinct(MitreMappingRow.alert_id)).desc())
    ).all()
    return [(str(technique), int(count)) for technique, count in rows]


def count_rejections(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(RejectedEventRow)) or 0)


def _now() -> datetime:
    from app.models.base import utcnow

    return utcnow()
