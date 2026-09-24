"""Incident endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api import converters, schemas
from app.api.dependencies import PageDep, SessionDep, SettingsDep
from app.api.reporting import report_response
from app.database import repository
from app.reports import ReportFormat
from app.services.workflow import UNCHANGED, AnalystWorkflow, Channel, IncidentDecision

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=schemas.Page[schemas.IncidentSummary])
def list_incidents(session: SessionDep, page: PageDep) -> schemas.Page[schemas.IncidentSummary]:
    # Offset was previously accepted, echoed back, and ignored: every page
    # returned the first page again.
    incidents = repository.list_incidents(session, limit=page.limit, offset=page.offset)
    return schemas.Page(
        items=[converters.incident_summary(i) for i in incidents],
        total=repository.count_incidents(session),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: UUID, session: SessionDep) -> schemas.IncidentDetail:
    return _detail(session, incident_id)


def _detail(session: Session, incident_id: UUID) -> schemas.IncidentDetail:
    incident = repository.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    alerts = repository.list_alerts(session, incident_id=incident_id, limit=200)
    notes = repository.list_notes(session, incident_id=incident_id)
    return converters.incident_detail(incident, alerts=alerts, notes=notes)


@router.patch(
    "/{incident_id}",
    response_model=schemas.IncidentDecisionOut,
    responses={
        404: {"description": "No such incident."},
        409: {"description": "The incident changed after `expected_updated_at`."},
        422: {"description": "The decision breaks a workflow rule; the detail says which."},
    },
)
def decide_incident(
    incident_id: UUID, body: schemas.IncidentDecisionIn, session: SessionDep, settings: SettingsDep
) -> schemas.IncidentDecisionOut:
    """Move an investigation on. Confirming, dismissing and reopening need a reason.

    SentinelFlow never confirms a compromise itself; this is the only way an
    incident becomes CONFIRMED.
    """
    decision = IncidentDecision(
        status=body.status,
        assigned_to=body.assigned_to if "assigned_to" in body.model_fields_set else UNCHANGED,
        reason=body.reason,
        expected_updated_at=body.expected_updated_at,
    )
    result = _workflow(session, settings.analyst_name).decide_incident(incident_id, decision)
    return schemas.IncidentDecisionOut(
        changes=result.changes, incident=_detail(session, incident_id)
    )


@router.post(
    "/{incident_id}/notes",
    response_model=schemas.AnalystNoteOut,
    status_code=status.HTTP_201_CREATED,
)
def add_incident_note(
    incident_id: UUID, body: schemas.NoteIn, session: SessionDep, settings: SettingsDep
) -> schemas.AnalystNoteOut:
    note = _workflow(session, settings.analyst_name).add_incident_note(incident_id, body.body)
    return converters.note(note)


@router.get("/{incident_id}/audit", response_model=list[schemas.AuditEntryOut])
def incident_audit(incident_id: UUID, session: SessionDep) -> list[schemas.AuditEntryOut]:
    """Everything that happened to this investigation, oldest first."""
    if repository.get_incident(session, incident_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    entries = repository.list_audit(session, object_id=incident_id, limit=500, oldest_first=True)
    return [converters.audit_entry(e) for e in entries]


@router.get(
    "/{incident_id}/report",
    response_class=Response,
    responses={
        200: {"description": "The report, as Markdown, HTML or JSON."},
        403: {"description": "The request came from another site."},
        404: {"description": "No such incident."},
    },
)
def incident_report(
    incident_id: UUID,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    report_format: Annotated[ReportFormat, Query(alias="format")] = ReportFormat.MARKDOWN,
    download: bool = False,
) -> Response:
    """Export an investigation report: timeline, detections, ATT&CK, indicators, AI, decisions."""
    return report_response(
        request,
        session,
        settings,
        "incident",
        incident_id,
        report_format,
        download=download,
        channel=Channel.API,
    )


def _workflow(session: Session, analyst: str) -> AnalystWorkflow:
    return AnalystWorkflow(session, analyst=analyst, channel=Channel.API)
