"""The audit trail, read-only. Nothing in the API can write to it directly."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api import converters, schemas
from app.api.dependencies import PageDep, SessionDep
from app.database import repository
from app.models.enums import AuditAction

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=schemas.Page[schemas.AuditEntryOut])
def list_audit(
    session: SessionDep,
    page: PageDep,
    action: AuditAction | None = None,
    object_type: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_]+$")] = None,
) -> schemas.Page[schemas.AuditEntryOut]:
    """Newest first. Filter by action (e.g. `alert_status_changed`) or object type."""
    entries = repository.list_audit(
        session, action=action, object_type=object_type, limit=page.limit, offset=page.offset
    )
    return schemas.Page(
        items=[converters.audit_entry(e) for e in entries],
        total=repository.count_audit(session, action=action, object_type=object_type),
        limit=page.limit,
        offset=page.offset,
    )
