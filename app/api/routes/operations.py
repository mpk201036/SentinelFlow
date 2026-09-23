"""Operational endpoints: health, stats, ingest, triage, correlate."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, status
from sqlalchemy import Engine

from app.api import converters, schemas
from app.api.dependencies import CatalogueDep, RulesDep, SessionDep, SettingsDep
from app.database import repository
from app.ingestion.adapters import UnknownAdapterError
from app.ingestion.service import IngestionService
from app.models.ingestion import RejectionReason
from app.services.correlation import CorrelationService
from app.services.pipeline import TriagePipeline

router = APIRouter(tags=["operations"])


@router.get("/health", response_model=schemas.HealthResponse)
def health(settings: SettingsDep, session: SessionDep) -> schemas.HealthResponse:
    from app import __version__
    from app.database.init_db import current_version

    try:
        # get_bind() may hand back a Connection rather than an Engine; either
        # way, the health check must read the database this session really uses.
        bind = session.get_bind()
        engine = bind if isinstance(bind, Engine) else bind.engine
        version = current_version(engine)
        db_status = "ok"
    except Exception:
        version = -1
        db_status = "error"

    return schemas.HealthResponse(
        status="ok",
        version=__version__,
        environment=settings.environment.value,
        database=db_status,
        schema_version=version,
        ai_enabled=settings.ai_enabled,
    )


@router.get("/stats", response_model=schemas.StatsResponse)
def stats(session: SessionDep) -> schemas.StatsResponse:
    from sqlalchemy import func, select

    from app.database.tables import AlertRow, DetectionRow, EventRow, RejectedEventRow
    from app.models.enums import AlertStatus

    events = repository.count_events(session)
    alerts_total = repository.count_alerts(session)
    open_statuses = [s for s in AlertStatus if s.is_open]
    alerts_open = int(
        session.scalar(
            select(func.count()).select_from(AlertRow).where(AlertRow.status.in_(open_statuses))
        )
        or 0
    )
    incidents = repository.count_incidents(session)
    indicators = repository.count_indicators(session)
    rejected = int(session.scalar(select(func.count()).select_from(RejectedEventRow)) or 0)

    severity_counts = repository.severity_breakdown(session)

    status_rows = session.execute(
        select(AlertRow.status, func.count()).group_by(AlertRow.status)
    ).all()
    status_counts = {str(s.value): int(c) for s, c in status_rows}

    top_hosts: dict[str, int] = {}
    host_rows = session.execute(
        select(EventRow.hostname_key, func.count())
        .join(AlertRow, AlertRow.primary_event_id == EventRow.event_id)
        .where(EventRow.hostname_key.isnot(None))
        .group_by(EventRow.hostname_key)
        .order_by(func.count().desc())
        .limit(10)
    ).all()
    for host, count in host_rows:
        if host:
            top_hosts[host] = int(count)

    techniques_rows = session.execute(
        select(DetectionRow.mitre_technique_ids)
        .where(DetectionRow.mitre_technique_ids.isnot(None))
        .limit(500)
    ).all()
    techniques_seen: set[str] = set()
    for (ids,) in techniques_rows:
        if isinstance(ids, list):
            techniques_seen.update(ids)

    return schemas.StatsResponse(
        events=events,
        alerts=alerts_total,
        alerts_open=alerts_open,
        incidents=incidents,
        indicators=indicators,
        rejected_events=rejected,
        severity_counts=severity_counts,
        status_counts=status_counts,
        top_rules={},
        top_hosts=top_hosts,
        techniques_observed=sorted(techniques_seen),
    )


@router.post("/ingest", response_model=schemas.IngestResponse, status_code=status.HTTP_200_OK)
def ingest(
    body: schemas.IngestRequest,
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
    catalogue: CatalogueDep,
) -> schemas.IngestResponse:
    """Ingest a batch of events. Runs triage immediately unless ``triage=false``."""
    svc = IngestionService(session, settings)
    outcome = svc.ingest_mappings(
        body.events,
        adapter_name=body.source,
        origin="api",
        force=False,
        persist=True,
    )

    if any(r.reason == RejectionReason.UNKNOWN_SOURCE for r in outcome.report.rejections):
        raise UnknownAdapterError(body.source or "auto")

    repository.save_import_batch(session, outcome.report)

    alerts_created = 0
    if body.triage and outcome.events:
        pipeline = TriagePipeline(session, settings, rules=rules, catalogue=catalogue)
        result = pipeline.process(outcome.events, persist=True)
        alerts_created = result.alerts_created

    outcome.report.finished_at = datetime.now(UTC)

    return converters.ingestion(outcome.report, alerts_created=alerts_created)


@router.post("/triage", response_model=schemas.TriageResponse, status_code=status.HTTP_200_OK)
def triage(
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
    catalogue: CatalogueDep,
    dry_run: bool = False,
) -> schemas.TriageResponse:
    """Score all stored untriaged events and create alerts."""
    pipeline = TriagePipeline(session, settings, rules=rules, catalogue=catalogue)
    result = pipeline.process_stored(persist=not dry_run)
    return schemas.TriageResponse(
        events_processed=result.events_processed,
        indicators_found=result.indicators_found,
        detections=result.detections,
        alerts_created=result.alerts_created,
        severity_counts=result.severity_counts(),
    )


@router.post("/correlate", response_model=schemas.CorrelateResponse, status_code=status.HTTP_200_OK)
def correlate(session: SessionDep, settings: SettingsDep) -> schemas.CorrelateResponse:
    """Group uncorrelated alerts into potential incidents."""
    svc = CorrelationService(session, settings)
    result = svc.correlate_pending()
    return schemas.CorrelateResponse(
        alerts_considered=result.alerts_considered,
        incidents_created=len(result.created),
        incidents_extended=len(result.extended),
        standalone_alerts=result.singletons,
    )
