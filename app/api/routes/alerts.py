"""Alert endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.api import converters, schemas
from app.api.dependencies import PageDep, SessionDep
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
    from sqlalchemy import func, select

    from app.database.tables import AlertRow

    query = select(AlertRow).order_by(AlertRow.created_at.desc())
    if status is not None:
        query = query.where(AlertRow.status == status)
    if severity is not None:
        query = query.where(AlertRow.severity_level == severity)
    if open_only:
        open_statuses = [s for s in AlertStatus if s.is_open]
        query = query.where(AlertRow.status.in_(open_statuses))

    total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)

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
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{alert_id}", response_model=schemas.AlertDetail)
def get_alert(alert_id: UUID, session: SessionDep) -> schemas.AlertDetail:
    alert = repository.get_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    event = None
    if alert.event_ids:
        event = repository.get_event(session, next(iter(alert.event_ids)))

    notes = repository.list_notes(session, alert_id=alert_id)
    analyses = repository.get_ai_analyses(session, alert_id)
    return converters.alert_detail(alert, event=event, notes=notes, analyses=analyses)
