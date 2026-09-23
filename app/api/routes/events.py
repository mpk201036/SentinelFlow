"""Event endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.api import converters, schemas
from app.api.dependencies import PageDep, SessionDep
from app.database import repository
from app.models.enums import EventType

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=schemas.Page[schemas.EventSummary])
def list_events(
    session: SessionDep,
    page: PageDep,
    source: Annotated[str | None, Query(max_length=64)] = None,
    event_type: EventType | None = None,
    hostname: Annotated[str | None, Query(max_length=256)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
) -> schemas.Page[schemas.EventSummary]:
    from app.database.tables import EventRow
    from sqlalchemy import func, select

    query = select(EventRow).order_by(EventRow.timestamp.desc())
    if source is not None:
        query = query.where(EventRow.source == source)
    if event_type is not None:
        query = query.where(EventRow.event_type == event_type)
    if hostname is not None:
        from app.enrichment.extractor import _normalise_key  # type: ignore[attr-defined]
        query = query.where(EventRow.hostname_key == hostname.lower().strip())
    if username is not None:
        query = query.where(EventRow.username_key == username.lower().strip())

    total = int(session.scalar(
        select(func.count()).select_from(query.subquery())
    ) or 0)
    from app.database import mappers
    rows = session.scalars(query.limit(page.limit).offset(page.offset)).all()
    events = [mappers.row_to_event(r) for r in rows]
    return schemas.Page(
        items=[converters.event_summary(e) for e in events],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{event_id}", response_model=schemas.EventDetail)
def get_event(event_id: UUID, session: SessionDep) -> schemas.EventDetail:
    event = repository.get_event(session, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="event not found")
    return converters.event_detail(event)
