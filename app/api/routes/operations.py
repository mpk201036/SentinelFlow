"""Operational endpoints: health, stats, triage, correlate.

Ingestion lives on the events collection: ``POST /api/v1/events``.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import Engine

from app.api import schemas
from app.api.dependencies import CatalogueDep, RulesDep, SessionDep, SettingsDep
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
def stats(session: SessionDep, catalogue: CatalogueDep) -> schemas.StatsResponse:
    """Headline counts. Shares its builder with the dashboard, so they agree."""
    from app.services.dashboard import collect_dashboard_stats

    data = collect_dashboard_stats(session, catalogue=catalogue)
    return schemas.StatsResponse(
        events=data.events,
        alerts=data.alerts_total,
        alerts_open=data.alerts_open,
        incidents=data.incidents,
        indicators=data.indicators,
        rejected_events=data.rejected_events,
        severity_counts=data.severity_counts,
        status_counts=data.status_counts,
        top_rules={rule_id: count for rule_id, _, count in data.top_rules},
        top_hosts=dict(data.top_hosts),
        techniques_observed=data.techniques_observed,
    )


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
