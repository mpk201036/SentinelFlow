"""Conversion between Pydantic domain models and ORM rows.

Pure functions, no session, no I/O. Keeping the translation explicit is the
price of separating the API contract from the storage schema, and it is worth
paying: every field that crosses the boundary is visible in one file, so it is
obvious when a new column is added and forgotten, and there is no mechanism by
which an internal column can appear in an API response.
"""

from __future__ import annotations

from typing import Any

from app.database.tables import (
    AIAnalysisRow,
    AIStatementRow,
    AlertRow,
    AnalystNoteRow,
    AuditLogRow,
    DetectionRow,
    EventRow,
    IncidentRow,
    IndicatorRow,
    MitreMappingRow,
    MitreTechniqueRow,
    RejectedEventRow,
)
from app.models.ai import AIAnalysis, AIStatement
from app.models.alert import Alert, AlertSeverity, SeverityFactor
from app.models.analyst import AnalystNote, AuditEntry
from app.models.detection import DetectionMatch, DetectionResult
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.ingestion import RejectedRecord
from app.models.mitre import MitreMapping, MitreTechnique


def _dump(models: Any) -> list[dict[str, Any]]:
    """Serialise a list of models to JSON-safe dicts for a JSON column."""
    return [model.model_dump(mode="json") for model in models]


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
def event_to_row(event: SecurityEvent) -> EventRow:
    return EventRow(
        event_id=event.event_id,
        timestamp=event.timestamp,
        received_at=event.received_at,
        source=event.source,
        event_type=event.event_type,
        event_type_raw=event.event_type_raw,
        hostname=event.hostname,
        username=event.username,
        # Derived once at write time so correlation queries can use an index.
        hostname_key=event.hostname_key,
        username_key=event.username_key,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        process_name=event.process_name,
        process_name_key=event.process_name_key,
        parent_process=event.parent_process,
        process_id=event.process_id,
        parent_process_id=event.parent_process_id,
        command_line=event.command_line,
        file_path=event.file_path,
        file_hash=event.file_hash,
        domain=event.domain,
        url=event.url,
        event_message=event.event_message,
        source_severity=event.source_severity,
        source_confidence=event.source_confidence,
        tags=list(event.tags),
        raw_event=dict(event.raw_event),
    )


def row_to_event(row: EventRow) -> SecurityEvent:
    return SecurityEvent(
        event_id=row.event_id,
        timestamp=row.timestamp,
        received_at=row.received_at,
        source=row.source,
        event_type=row.event_type,
        event_type_raw=row.event_type_raw,
        hostname=row.hostname,
        username=row.username,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        protocol=row.protocol,
        process_name=row.process_name,
        parent_process=row.parent_process,
        process_id=row.process_id,
        parent_process_id=row.parent_process_id,
        command_line=row.command_line,
        file_path=row.file_path,
        file_hash=row.file_hash,
        domain=row.domain,
        url=row.url,
        event_message=row.event_message,
        source_severity=row.source_severity,
        source_confidence=row.source_confidence,
        tags=list(row.tags),
        raw_event=dict(row.raw_event),
    )


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------
def indicator_to_row(indicator: Indicator) -> IndicatorRow:
    return IndicatorRow(
        indicator_id=indicator.indicator_id,
        indicator_type=indicator.indicator_type,
        value=indicator.value,
        source_event_id=indicator.source_event_id,
        source_field=indicator.source_field,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        occurrences=indicator.occurrences,
    )


def row_to_indicator(row: IndicatorRow) -> Indicator:
    return Indicator(
        indicator_id=row.indicator_id,
        indicator_type=row.indicator_type,
        value=row.value,
        source_event_id=row.source_event_id,
        source_field=row.source_field,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        occurrences=row.occurrences,
    )


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------
def detection_to_row(detection: DetectionResult, alert_id: Any) -> DetectionRow:
    return DetectionRow(
        detection_id=detection.detection_id,
        alert_id=alert_id,
        event_id=detection.event_id,
        rule_id=detection.rule_id,
        rule_name=detection.rule_name,
        rule_severity=detection.rule_severity,
        confidence=detection.confidence,
        description=detection.description,
        recommendation=detection.recommendation,
        detected_at=detection.detected_at,
        matched=_dump(detection.matched),
        mitre_technique_ids=list(detection.mitre_technique_ids),
    )


def row_to_detection(row: DetectionRow) -> DetectionResult:
    return DetectionResult(
        detection_id=row.detection_id,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        rule_severity=row.rule_severity,
        confidence=row.confidence,
        description=row.description,
        recommendation=row.recommendation,
        event_id=row.event_id,
        detected_at=row.detected_at,
        matched=[DetectionMatch(**item) for item in row.matched],
        mitre_technique_ids=list(row.mitre_technique_ids),
    )


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------
def technique_to_row(technique: MitreTechnique) -> MitreTechniqueRow:
    return MitreTechniqueRow(
        technique_id=technique.technique_id,
        name=technique.name,
        tactics=list(technique.tactics),
        description=technique.description,
    )


def row_to_technique(row: MitreTechniqueRow) -> MitreTechnique:
    return MitreTechnique(
        technique_id=row.technique_id,
        name=row.name,
        tactics=list(row.tactics),
        description=row.description,
    )


def mapping_to_row(mapping: MitreMapping, alert_id: Any) -> MitreMappingRow:
    from app.models.base import new_id

    return MitreMappingRow(
        mapping_id=new_id(),
        alert_id=alert_id,
        technique_id=mapping.technique.technique_id,
        reason=mapping.reason,
        source_rule_id=mapping.source_rule_id,
        confidence=mapping.confidence,
    )


def row_to_mapping(row: MitreMappingRow) -> MitreMapping:
    return MitreMapping(
        technique=row_to_technique(row.technique),
        reason=row.reason,
        source_rule_id=row.source_rule_id,
        confidence=row.confidence,
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
def alert_to_row(alert: Alert) -> AlertRow:
    """Build an alert row, including its detections and MITRE mappings.

    Indicators and events are association-table links and are attached by the
    repository, which is the layer that knows about existing rows.
    """
    row = AlertRow(
        alert_id=alert.alert_id,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        title=alert.title,
        primary_event_id=alert.primary_event_id,
        severity_score=alert.severity.score,
        severity_level=alert.severity.level,
        severity_factors=_dump(alert.severity.factors),
        severity_method=alert.severity.method,
        confidence=alert.confidence,
        status=alert.status,
        classification=alert.classification,
        assigned_to=alert.assigned_to,
        closed_at=alert.closed_at,
        incident_id=alert.incident_id,
        tags=list(alert.tags),
    )
    row.detections = [detection_to_row(d, alert.alert_id) for d in alert.detections]
    row.mitre_mappings = [mapping_to_row(m, alert.alert_id) for m in alert.mitre]
    return row


def row_to_alert(row: AlertRow) -> Alert:
    return Alert(
        alert_id=row.alert_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
        title=row.title,
        primary_event_id=row.primary_event_id,
        event_ids=[event.event_id for event in row.events] or [row.primary_event_id],
        severity=AlertSeverity(
            score=row.severity_score,
            level=row.severity_level,
            factors=[SeverityFactor(**item) for item in row.severity_factors],
        ),
        confidence=row.confidence,
        detections=[row_to_detection(d) for d in row.detections],
        indicators=[row_to_indicator(i) for i in row.indicators],
        mitre=[row_to_mapping(m) for m in row.mitre_mappings],
        status=row.status,
        classification=row.classification,
        assigned_to=row.assigned_to,
        closed_at=row.closed_at,
        incident_id=row.incident_id,
        tags=list(row.tags),
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
def incident_to_row(incident: Incident) -> IncidentRow:
    return IncidentRow(
        incident_id=incident.incident_id,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        title=incident.title,
        status=incident.status,
        severity=incident.severity,
        classification=incident.classification,
        correlation_key=incident.correlation_key,
        correlation_reasons=list(incident.correlation_reasons),
        first_event_at=incident.first_event_at,
        last_event_at=incident.last_event_at,
        hostnames=list(incident.hostnames),
        usernames=list(incident.usernames),
        summary=incident.summary,
        assigned_to=incident.assigned_to,
        tags=list(incident.tags),
    )


def row_to_incident(row: IncidentRow) -> Incident:
    return Incident(
        incident_id=row.incident_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
        title=row.title,
        status=row.status,
        severity=row.severity,
        classification=row.classification,
        alert_ids=[alert.alert_id for alert in row.alerts],
        correlation_key=row.correlation_key,
        correlation_reasons=list(row.correlation_reasons),
        first_event_at=row.first_event_at,
        last_event_at=row.last_event_at,
        hostnames=list(row.hostnames),
        usernames=list(row.usernames),
        summary=row.summary,
        assigned_to=row.assigned_to,
        tags=list(row.tags),
    )


# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------
def ai_analysis_to_row(analysis: AIAnalysis) -> AIAnalysisRow:
    from app.models.base import new_id

    row = AIAnalysisRow(
        analysis_id=analysis.analysis_id,
        alert_id=analysis.alert_id,
        generated_at=analysis.generated_at,
        provider=analysis.provider,
        model=analysis.model,
        duration_ms=analysis.duration_ms,
        prompt_version=analysis.prompt_version,
        summary=analysis.summary,
        suspicious_observations=list(analysis.suspicious_observations),
        possible_explanations=list(analysis.possible_explanations),
        analyst_questions=list(analysis.analyst_questions),
        recommended_next_steps=list(analysis.recommended_next_steps),
        suggested_severity=analysis.suggested_severity,
        suggested_severity_rationale=analysis.suggested_severity_rationale,
        is_advisory=True,
        injection_suspected=analysis.injection_suspected,
        truncated=analysis.truncated,
    )
    row.statements = [
        AIStatementRow(
            statement_id=new_id(),
            analysis_id=analysis.analysis_id,
            position=index,
            statement_type=statement.statement_type,
            text=statement.text,
        )
        for index, statement in enumerate(analysis.statements)
    ]
    return row


def row_to_ai_analysis(row: AIAnalysisRow) -> AIAnalysis:
    return AIAnalysis(
        analysis_id=row.analysis_id,
        alert_id=row.alert_id,
        generated_at=row.generated_at,
        provider=row.provider,
        model=row.model,
        duration_ms=row.duration_ms,
        prompt_version=row.prompt_version,
        summary=row.summary,
        statements=[
            AIStatement(statement_type=s.statement_type, text=s.text) for s in row.statements
        ],
        suspicious_observations=list(row.suspicious_observations),
        possible_explanations=list(row.possible_explanations),
        analyst_questions=list(row.analyst_questions),
        recommended_next_steps=list(row.recommended_next_steps),
        suggested_severity=row.suggested_severity,
        suggested_severity_rationale=row.suggested_severity_rationale,
        injection_suspected=row.injection_suspected,
        truncated=row.truncated,
    )


# ---------------------------------------------------------------------------
# Notes and audit
# ---------------------------------------------------------------------------
def note_to_row(note: AnalystNote) -> AnalystNoteRow:
    return AnalystNoteRow(
        note_id=note.note_id,
        created_at=note.created_at,
        author=note.author,
        body=note.body,
        alert_id=note.alert_id,
        incident_id=note.incident_id,
    )


def row_to_note(row: AnalystNoteRow) -> AnalystNote:
    return AnalystNote(
        note_id=row.note_id,
        created_at=row.created_at,
        author=row.author,
        body=row.body,
        alert_id=row.alert_id,
        incident_id=row.incident_id,
    )


def audit_to_row(entry: AuditEntry) -> AuditLogRow:
    return AuditLogRow(
        entry_id=entry.entry_id,
        occurred_at=entry.occurred_at,
        actor=entry.actor,
        actor_name=entry.actor_name,
        action=entry.action,
        object_type=entry.object_type,
        object_id=entry.object_id,
        before=entry.before,
        after=entry.after,
        detail=entry.detail,
    )


def row_to_audit(row: AuditLogRow) -> AuditEntry:
    return AuditEntry(
        entry_id=row.entry_id,
        occurred_at=row.occurred_at,
        actor=row.actor,
        actor_name=row.actor_name,
        action=row.action,
        object_type=row.object_type,
        object_id=row.object_id,
        before=row.before,
        after=row.after,
        detail=row.detail,
    )


# ---------------------------------------------------------------------------
# Rejected records
# ---------------------------------------------------------------------------
def rejected_to_row(record: RejectedRecord, batch_id: Any = None) -> RejectedEventRow:
    return RejectedEventRow(
        record_id=record.record_id,
        batch_id=batch_id,
        rejected_at=record.rejected_at,
        index_in_batch=record.index,
        reason=record.reason,
        detail=record.detail,
        payload=record.payload,
        origin=record.origin,
        adapter=record.adapter,
    )


def row_to_rejected(row: RejectedEventRow) -> RejectedRecord:
    return RejectedRecord(
        record_id=row.record_id,
        rejected_at=row.rejected_at,
        index=row.index_in_batch,
        reason=row.reason,
        detail=row.detail,
        payload=row.payload,
        origin=row.origin,
        adapter=row.adapter,
    )
