"""Domain models to API responses.

Every field that crosses into a response is written out here. It is more typing
than ``model_dump()`` and that is the point: adding a column to the database
cannot silently change what the API returns, and the attack surface is a list
somebody can read.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.api import schemas
from app.detection.schema import RuleDefinition
from app.models.ai import AIAnalysis
from app.models.alert import Alert, AlertSeverity
from app.models.analyst import AnalystNote, AuditEntry
from app.models.detection import DetectionResult
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.ingestion import IngestionReport
from app.models.mitre import MitreMapping, MitreTechnique


def event_summary(event: SecurityEvent) -> schemas.EventSummary:
    return schemas.EventSummary(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        hostname=event.hostname,
        username=event.username,
        process_name=event.process_name,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        event_message=event.event_message,
    )


def event_detail(event: SecurityEvent) -> schemas.EventDetail:
    return schemas.EventDetail(
        **event_summary(event).model_dump(),
        received_at=event.received_at,
        event_type_raw=event.event_type_raw,
        parent_process=event.parent_process,
        process_id=event.process_id,
        parent_process_id=event.parent_process_id,
        command_line=event.command_line,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        file_path=event.file_path,
        file_hash=event.file_hash,
        domain=event.domain,
        url=event.url,
        source_severity=event.source_severity,
        source_confidence=event.source_confidence,
        tags=list(event.tags),
        raw_event=dict(event.raw_event),
    )


def detection(result: DetectionResult) -> schemas.DetectionOut:
    return schemas.DetectionOut(
        detection_id=result.detection_id,
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        rule_severity=result.rule_severity,
        confidence=result.confidence,
        description=result.description,
        recommendation=result.recommendation,
        detected_at=result.detected_at,
        matched=[
            schemas.DetectionMatchOut(
                field_name=match.field_name,
                condition=match.condition,
                observed_value=match.observed_value,
            )
            for match in result.matched
        ],
        mitre_technique_ids=list(result.mitre_technique_ids),
    )


def indicator(item: Indicator) -> schemas.IndicatorOut:
    return schemas.IndicatorOut(
        indicator_id=item.indicator_id,
        indicator_type=item.indicator_type,
        value=item.value,
        source_field=item.source_field,
        first_seen=item.first_seen,
        last_seen=item.last_seen,
        occurrences=item.occurrences,
        is_internal=item.is_internal,
        is_documentation=item.is_documentation,
    )


def technique(item: MitreTechnique) -> schemas.TechniqueOut:
    return schemas.TechniqueOut(
        technique_id=item.technique_id,
        name=item.name,
        tactics=list(item.tactics),
        description=item.description,
        url=item.url,
    )


def mapping(item: MitreMapping) -> schemas.MitreMappingOut:
    return schemas.MitreMappingOut(
        technique=technique(item.technique),
        reason=item.reason,
        source_rule_id=item.source_rule_id,
        confidence=item.confidence,
    )


def severity(verdict: AlertSeverity) -> schemas.SeverityOut:
    """Always with its factors and its method. There is no bare-string form."""
    return schemas.SeverityOut(
        score=verdict.score,
        level=verdict.level,
        method=verdict.method,
        factors=[
            schemas.SeverityFactorOut(name=f.name, points=f.points, detail=f.detail)
            for f in verdict.factors
        ],
    )


def note(item: AnalystNote) -> schemas.AnalystNoteOut:
    return schemas.AnalystNoteOut(
        note_id=item.note_id,
        created_at=item.created_at,
        author=item.author,
        body=item.body,
    )


def ai_analysis(analysis: AIAnalysis) -> schemas.AIAnalysisOut:
    """Advisory output, carrying the disclaimer with it."""
    return schemas.AIAnalysisOut(
        analysis_id=analysis.analysis_id,
        generated_at=analysis.generated_at,
        provider=analysis.provider,
        model=analysis.model,
        duration_ms=analysis.duration_ms,
        prompt_version=analysis.prompt_version,
        summary=analysis.summary,
        statements=[
            schemas.AIStatementOut(
                statement_type=s.statement_type.value, text=s.text, downgraded=s.downgraded
            )
            for s in analysis.statements
        ],
        suspicious_observations=list(analysis.suspicious_observations),
        possible_explanations=list(analysis.possible_explanations),
        analyst_questions=list(analysis.analyst_questions),
        recommended_next_steps=list(analysis.recommended_next_steps),
        suggested_severity=analysis.suggested_severity,
        suggested_severity_rationale=analysis.suggested_severity_rationale,
        is_advisory=analysis.is_advisory,
        injection_suspected=analysis.injection_suspected,
        truncated=analysis.truncated,
        injection_signals=list(analysis.injection_signals),
        grounding_notes=list(analysis.grounding_notes),
        disclaimer=AIAnalysis.DISCLAIMER,
    )


def alert_summary(alert: Alert) -> schemas.AlertSummary:
    return schemas.AlertSummary(
        alert_id=alert.alert_id,
        created_at=alert.created_at,
        title=alert.title,
        severity=severity(alert.severity),
        confidence=alert.confidence,
        status=alert.status,
        classification=alert.classification,
        incident_id=alert.incident_id,
        rule_ids=sorted(set(alert.rule_ids)),
        technique_ids=alert.technique_ids,
    )


def alert_detail(
    alert: Alert,
    *,
    event: SecurityEvent | None = None,
    notes: Sequence[AnalystNote] = (),
    analyses: Sequence[AIAnalysis] = (),
) -> schemas.AlertDetail:
    return schemas.AlertDetail(
        **alert_summary(alert).model_dump(),
        updated_at=alert.updated_at,
        primary_event=event_detail(event) if event is not None else None,
        detections=[detection(d) for d in alert.detections],
        indicators=[indicator(i) for i in alert.indicators],
        mitre=[mapping(m) for m in alert.mitre],
        tags=list(alert.tags),
        assigned_to=alert.assigned_to,
        closed_at=alert.closed_at,
        notes=[note(n) for n in notes],
        ai_analysis=[ai_analysis(a) for a in analyses],
    )


def incident_summary(item: Incident) -> schemas.IncidentSummary:
    return schemas.IncidentSummary(
        incident_id=item.incident_id,
        created_at=item.created_at,
        title=item.title,
        status=item.status,
        display_label=item.display_label,
        severity=item.severity,
        alert_count=item.alert_count,
        hostnames=list(item.hostnames),
        usernames=list(item.usernames),
        first_event_at=item.first_event_at,
        last_event_at=item.last_event_at,
    )


def incident_detail(
    item: Incident, *, alerts: Sequence[Alert] = (), notes: Sequence[AnalystNote] = ()
) -> schemas.IncidentDetail:
    return schemas.IncidentDetail(
        **incident_summary(item).model_dump(),
        updated_at=item.updated_at,
        classification=item.classification,
        assigned_to=item.assigned_to,
        correlation_key=item.correlation_key,
        correlation_reasons=list(item.correlation_reasons),
        summary=item.summary,
        alerts=[alert_summary(a) for a in alerts],
        notes=[note(n) for n in notes],
    )


def audit_entry(entry: AuditEntry) -> schemas.AuditEntryOut:
    return schemas.AuditEntryOut(
        entry_id=entry.entry_id,
        occurred_at=entry.occurred_at,
        actor=entry.actor.value,
        actor_name=entry.actor_name,
        action=entry.action.value,
        object_type=entry.object_type,
        object_id=entry.object_id,
        before=entry.before,
        after=entry.after,
        detail=entry.detail,
    )


def rule(definition: RuleDefinition) -> schemas.RuleOut:
    return schemas.RuleOut(
        rule_id=definition.rule_id,
        name=definition.name,
        description=definition.description,
        severity=definition.severity,
        confidence=definition.confidence,
        enabled=definition.enabled,
        kind=definition.kind,
        mitre=list(definition.mitre),
        tags=list(definition.tags),
        recommendation=definition.recommendation,
        false_positives=list(definition.false_positives),
    )


def ingestion(report: IngestionReport, *, alerts_created: int = 0) -> schemas.IngestResponse:
    return schemas.IngestResponse(
        batch_id=report.batch_id,
        adapter=report.adapter,
        accepted=report.accepted,
        rejected=report.rejected,
        duplicate_batch=report.duplicate_batch,
        event_ids=list(report.event_ids),
        rejections=[
            schemas.RejectionOut(index=r.index, reason=r.reason.value, detail=r.detail)
            for r in report.rejections
        ],
        alerts_created=alerts_created,
        duration_ms=report.duration_ms,
    )
