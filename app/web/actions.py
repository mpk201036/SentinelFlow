"""The console's forms: every change an analyst makes from the browser.

Each handler verifies the CSRF token before reading anything else, applies
the decision through :class:`~app.services.workflow.AnalystWorkflow` (the same
rules and audit trail as the API and the CLI), and then either:

* **redirects** back to the page with a fixed confirmation code
  (Post/Redirect/Get: reloading never submits twice), or
* **re-renders** the page with the refusal and the analyst's own input, so a
  rejected closing note is not lost.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from app.ai.service import AIAnalysisService, OutcomeKind
from app.api.dependencies import AIDep, SessionDep, SettingsDep
from app.models.enums import AlertStatus, Classification, IncidentStatus
from app.services.workflow import (
    AlertDecision,
    AnalystWorkflow,
    Channel,
    IncidentDecision,
    StaleDecisionError,
    WorkflowError,
)
from app.web.csrf import verify_csrf
from app.web.views import alert_page, incident_page

router = APIRouter(include_in_schema=False, dependencies=[Depends(verify_csrf)])

FormText = Annotated[str, Form()]


def _uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        return None


def _version(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _redirect(path: str, code: str, anchor: str) -> Response:
    return RedirectResponse(f"{path}?saved={code}#{anchor}", status_code=303)


def _workflow(session: SessionDep, settings: SettingsDep) -> AnalystWorkflow:
    return AnalystWorkflow(session, analyst=settings.analyst_name, channel=Channel.CONSOLE)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@router.post("/alerts/{alert_id}/decision")
def alert_decision(
    request: Request,
    alert_id: str,
    session: SessionDep,
    settings: SettingsDep,
    updated_at: FormText = "",
    status: FormText = "",
    classification: FormText = "",
    assigned_to: FormText = "",
    reason: FormText = "",
) -> Response:
    parsed = _uuid(alert_id)
    values = {
        "status": status,
        "classification": classification,
        "assigned_to": assigned_to,
        "reason": reason,
    }

    def refuse(message: str, code: int = 422) -> Response:
        return alert_page(
            request,
            session,
            settings,
            parsed,
            errors={"decision": message},
            values=values,
            status_code=code,
        )

    try:
        wanted_status = AlertStatus(status) if status else None
        wanted_class = Classification(classification) if classification else None
    except ValueError:
        return refuse("That status or classification is not one SentinelFlow knows.")
    version = _version(updated_at)
    if parsed is None or version is None:
        return refuse("The form was incomplete. Reload the page and try again.", 400)

    try:
        result = _workflow(session, settings).decide_alert(
            parsed,
            AlertDecision(
                status=wanted_status,
                classification=wanted_class,
                assigned_to=assigned_to or None,
                reason=reason or None,
                expected_updated_at=version,
            ),
        )
    except StaleDecisionError as exc:
        return refuse(str(exc), 409)
    except WorkflowError as exc:
        return refuse(str(exc))
    except LookupError:
        return alert_page(request, session, settings, None)

    code = "decision" if result.changed else "unchanged"
    return _redirect(f"/alerts/{parsed}", code, "decided")


@router.post("/alerts/{alert_id}/notes")
def alert_note(
    request: Request,
    alert_id: str,
    session: SessionDep,
    settings: SettingsDep,
    body: FormText = "",
) -> Response:
    parsed = _uuid(alert_id)
    if parsed is None:
        return alert_page(request, session, settings, None)
    try:
        _workflow(session, settings).add_alert_note(parsed, body)
    except WorkflowError as exc:
        return alert_page(
            request,
            session,
            settings,
            parsed,
            errors={"note": str(exc)},
            values={"body": body},
            status_code=422,
        )
    except LookupError:
        return alert_page(request, session, settings, None)
    return _redirect(f"/alerts/{parsed}", "note", "notes")


@router.post("/alerts/{alert_id}/ai-analysis")
def alert_ai_analysis(
    request: Request,
    alert_id: str,
    session: SessionDep,
    settings: SettingsDep,
    ai: AIDep,
) -> Response:
    """Ask the local model from the console. Same service, same audit, as the CLI and API."""
    parsed = _uuid(alert_id)
    if parsed is None:
        return alert_page(request, session, settings, None)

    def refuse(message: str, code: int) -> Response:
        return alert_page(
            request, session, settings, parsed, errors={"ai": message}, status_code=code
        )

    if ai.provider is None:
        return refuse(ai.problem or "AI is disabled.", 503)
    if not ai.lock.acquire(blocking=False):
        return refuse("Another analysis is running. Try again when it finishes.", 429)
    try:
        outcome = AIAnalysisService(
            session, ai.provider, requested_by=settings.analyst_name
        ).analyze_alert(parsed)
    except LookupError:
        return alert_page(request, session, settings, None)
    finally:
        ai.lock.release()

    if outcome.analysis is None:
        prefix = "The model's reply was not usable" if outcome.kind is OutcomeKind.REJECTED else ""
        message = f"{prefix}: {outcome.problem}" if prefix else (outcome.problem or "")
        return refuse(message, 502 if outcome.kind is OutcomeKind.REJECTED else 503)
    return _redirect(f"/alerts/{parsed}", "analysis", "suggested")


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------
@router.post("/incidents/{incident_id}/decision")
def incident_decision(
    request: Request,
    incident_id: str,
    session: SessionDep,
    settings: SettingsDep,
    updated_at: FormText = "",
    status: FormText = "",
    assigned_to: FormText = "",
    reason: FormText = "",
) -> Response:
    parsed = _uuid(incident_id)
    values = {"status": status, "assigned_to": assigned_to, "reason": reason}

    def refuse(message: str, code: int = 422) -> Response:
        return incident_page(
            request,
            session,
            settings,
            parsed,
            errors={"decision": message},
            values=values,
            status_code=code,
        )

    try:
        wanted_status = IncidentStatus(status) if status else None
    except ValueError:
        return refuse("That status is not one SentinelFlow knows.")
    version = _version(updated_at)
    if parsed is None or version is None:
        return refuse("The form was incomplete. Reload the page and try again.", 400)

    try:
        result = _workflow(session, settings).decide_incident(
            parsed,
            IncidentDecision(
                status=wanted_status,
                assigned_to=assigned_to or None,
                reason=reason or None,
                expected_updated_at=version,
            ),
        )
    except StaleDecisionError as exc:
        return refuse(str(exc), 409)
    except WorkflowError as exc:
        return refuse(str(exc))
    except LookupError:
        return incident_page(request, session, settings, None)

    code = "decision" if result.changed else "unchanged"
    return _redirect(f"/incidents/{parsed}", code, "decided")


@router.post("/incidents/{incident_id}/notes")
def incident_note(
    request: Request,
    incident_id: str,
    session: SessionDep,
    settings: SettingsDep,
    body: FormText = "",
) -> Response:
    parsed = _uuid(incident_id)
    if parsed is None:
        return incident_page(request, session, settings, None)
    try:
        _workflow(session, settings).add_incident_note(parsed, body)
    except WorkflowError as exc:
        return incident_page(
            request,
            session,
            settings,
            parsed,
            errors={"note": str(exc)},
            values={"body": body},
            status_code=422,
        )
    except LookupError:
        return incident_page(request, session, settings, None)
    return _redirect(f"/incidents/{parsed}", "note", "notes")
