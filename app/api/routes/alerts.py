"""Alert endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.ai.service import AIAnalysisService, AlertNotFoundError, OutcomeKind
from app.api import converters, schemas
from app.api.dependencies import AIDep, PageDep, SessionDep
from app.database import repository
from app.models.enums import AlertStatus, Severity

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=schemas.Page[schemas.AlertSummary])
def list_alerts(
    session: SessionDep,
    page: PageDep,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    open_only: bool = False,
) -> schemas.Page[schemas.AlertSummary]:
    alerts = repository.list_alerts(
        session,
        status=status,
        severity=severity,
        open_only=open_only,
        limit=page.limit,
        offset=page.offset,
    )
    return schemas.Page(
        items=[converters.alert_summary(a) for a in alerts],
        # Counted with the same filter that produced the page, so the two
        # cannot disagree.
        total=repository.count_alerts_matching(
            session, status=status, severity=severity, open_only=open_only
        ),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{alert_id}", response_model=schemas.AlertDetail)
def get_alert(alert_id: UUID, session: SessionDep) -> schemas.AlertDetail:
    alert = repository.get_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    event = repository.get_event(session, alert.primary_event_id)

    notes = repository.list_notes(session, alert_id=alert_id)
    analyses = repository.get_ai_analyses(session, alert_id)
    return converters.alert_detail(alert, event=event, notes=notes, analyses=analyses)


@router.post(
    "/{alert_id}/ai-analysis",
    response_model=schemas.AIAnalysisOut,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"description": "No such alert."},
        429: {"description": "Another analysis is already running."},
        502: {"description": "The model's reply was unusable. Nothing was stored."},
        503: {"description": "AI is disabled, misconfigured or unreachable."},
    },
)
def request_ai_analysis(alert_id: UUID, session: SessionDep, ai: AIDep) -> schemas.AIAnalysisOut:
    """Ask the local model for an advisory analysis of one alert.

    The analysis is stored beside the alert and changes nothing on it: not its
    severity, status, classification or ATT&CK mappings. Every request is
    audited, including the ones that fail.
    """
    if ai.provider is not None and not ai.lock.acquire(blocking=False):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="an analysis is already running; try again when it finishes",
        )
    try:
        outcome = AIAnalysisService(session, ai.provider, requested_by="api").analyze_alert(
            alert_id
        )
    except AlertNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="alert not found"
        ) from None
    finally:
        if ai.provider is not None:
            ai.lock.release()

    if outcome.analysis is not None:
        return converters.ai_analysis(outcome.analysis)

    # The failure was audited. Commit that before the error response, which
    # would otherwise roll it back with the rest of the request.
    session.commit()
    if outcome.kind is OutcomeKind.REJECTED:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"the model's reply was not stored: {outcome.problem}",
        )
    detail = ai.problem if outcome.kind is OutcomeKind.DISABLED else outcome.problem
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)
