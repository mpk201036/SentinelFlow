"""Incident endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.api import converters, schemas
from app.api.dependencies import PageDep, SessionDep
from app.database import repository

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=schemas.Page[schemas.IncidentSummary])
def list_incidents(session: SessionDep, page: PageDep) -> schemas.Page[schemas.IncidentSummary]:
    from sqlalchemy import func, select

    from app.database.tables import IncidentRow

    total = int(session.scalar(select(func.count()).select_from(IncidentRow)) or 0)
    incidents = repository.list_incidents(session, limit=page.limit)
    return schemas.Page(
        items=[converters.incident_summary(i) for i in incidents],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: UUID, session: SessionDep) -> schemas.IncidentDetail:
    incident = repository.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    alerts = repository.list_alerts(session, incident_id=incident_id, limit=200)
    return converters.incident_detail(incident, alerts=alerts)
