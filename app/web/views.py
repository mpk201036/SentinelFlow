"""The analyst console: server-rendered HTML over the same pipeline as the API.

Every page is plain HTML plus one static stylesheet and one static script. No
page carries inline script or inline style, because the Content-Security-Policy
set in ``app/api/middleware.py`` forbids both - which means that if escaping
ever failed on an attacker-controlled field, the injected script would still
have nowhere to run. Autoescaping is the first line; the policy is the second.

The console shows each alert in the order its trust was established:
observed evidence, then deterministic analysis, then - only if enabled and
clearly set apart - the model's suggestion, then the analyst's own decision.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from app import __version__
from app.api.dependencies import CatalogueDep, RulesDep, SessionDep, SettingsDep
from app.api.reporting import report_response
from app.core.config import PROJECT_ROOT
from app.database import repository
from app.models.ai import AIAnalysis
from app.models.enums import AlertStatus, Classification, IncidentStatus, Severity
from app.reports import ReportFormat, ReportKind, ReportSubjectNotFoundError
from app.services.dashboard import RANGES, SEVERITY_ORDER, collect_dashboard_stats
from app.services.workflow import Channel
from app.web import charts, csrf
from app.web.formatting import FILTERS

TEMPLATE_DIR = PROJECT_ROOT / "dashboard" / "templates"
STATIC_DIR = PROJECT_ROOT / "dashboard" / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.filters.update(FILTERS)
# Belt and braces: Jinja2Templates enables autoescaping for .html already, but
# the console renders attacker-controlled strings on every page, so the setting
# is asserted rather than assumed. A test checks it too.
templates.env.autoescape = True

router = APIRouter(include_in_schema=False)

NAV = (
    ("overview", "/", "Overview"),
    ("alerts", "/alerts", "Alerts"),
    ("incidents", "/incidents", "Investigations"),
    ("rules", "/rules", "Rules"),
)


#: Confirmations shown after a successful form, keyed by a fixed code in the
#: redirect URL. The URL carries the code, never the message, so nothing a
#: link supplies is ever printed on the page.
NOTICES = {
    "decision": ("decided", "Decision recorded."),
    "unchanged": ("decided", "Nothing changed: the form matched what was already recorded."),
    "note": ("notes", "Note added."),
    "analysis": (
        "suggested",
        "The model's analysis was stored. It is advisory and changed nothing above.",
    ),
}


def _render(
    request: Request,
    template: str,
    *,
    active: str,
    settings: Any,
    status_code: int = 200,
    **context: Any,
) -> Response:
    token, issued = csrf.form_token(request)
    response = templates.TemplateResponse(
        request,
        template,
        {
            "nav": NAV,
            "active": active,
            "version": __version__,
            "ai_enabled": settings.ai_active,
            "analyst": settings.analyst_name,
            "csrf_field": csrf.FIELD_NAME,
            "csrf_token": token,
            "severity_order": [s.value for s in SEVERITY_ORDER],
            **context,
        },
        status_code=status_code,
    )
    if issued is not None:
        csrf.set_cookie(response, issued, secure=settings.api_is_exposed)
    return response


def _not_found(request: Request, settings: Any, what: str) -> Response:
    return _render(
        request,
        "not_found.html",
        active="",
        settings=settings,
        status_code=404,
        what=what,
    )


_FORM_PARENT_RE = re.compile(r"^(/(?:alerts|incidents)/[0-9a-f-]{36})/[a-z-]+$")


def form_rejected(request: Request) -> Response:
    """The page shown when a form's CSRF token does not check out. Nothing changed."""
    match = _FORM_PARENT_RE.match(request.url.path)
    return _render(
        request,
        "form_rejected.html",
        active="",
        settings=request.app.state.settings,
        status_code=403,
        back=match.group(1) if match else "/",
    )


def _parse_uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def overview(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    catalogue: CatalogueDep,
    range_key: str | None = Query(None, alias="range", max_length=8),
) -> Response:
    stats = collect_dashboard_stats(session, range_key=range_key, catalogue=catalogue)
    host_rows = charts.bar_list(stats.top_hosts)
    rule_rows = charts.bar_list(
        [(rule_id, count, name, None) for rule_id, name, count in stats.top_rules]
    )
    return _render(
        request,
        "overview.html",
        active="overview",
        settings=settings,
        stats=stats,
        ranges=RANGES,
        trend=charts.trend_chart(stats.trend),
        host_rows=host_rows,
        rule_rows=rule_rows,
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@router.get("/alerts", response_class=HTMLResponse)
def alert_queue(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    status: str | None = Query(None, max_length=16),
    severity: str | None = Query(None, max_length=16),
    open_only: bool = Query(False, alias="open"),
) -> Response:
    # Unknown filter values are ignored rather than erroring: a mistyped URL
    # should show the queue, not a validation page.
    wanted_status = AlertStatus(status) if status in {s.value for s in AlertStatus} else None
    wanted_severity = Severity(severity) if severity in {s.value for s in Severity} else None

    alerts = repository.list_alerts(
        session,
        status=wanted_status,
        severity=wanted_severity,
        open_only=open_only,
        limit=200,
    )
    alerts.sort(key=lambda a: (-a.severity.score, a.created_at))
    by_event = repository.get_events(session, (a.primary_event_id for a in alerts))
    events = {a.alert_id: by_event.get(a.primary_event_id) for a in alerts}
    return _render(
        request,
        "alerts.html",
        active="alerts",
        settings=settings,
        alerts=alerts,
        events=events,
        statuses=[s.value for s in AlertStatus],
        severities=[s.value for s in SEVERITY_ORDER],
        filter_status=wanted_status.value if wanted_status else "",
        filter_severity=wanted_severity.value if wanted_severity else "",
        filter_open=open_only,
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(
    request: Request,
    alert_id: str,
    session: SessionDep,
    settings: SettingsDep,
    saved: str | None = Query(None, max_length=16),
) -> Response:
    return alert_page(
        request, session, settings, _parse_uuid(alert_id), notice=NOTICES.get(saved or "")
    )


def alert_page(
    request: Request,
    session: Any,
    settings: Any,
    alert_id: UUID | None,
    *,
    notice: tuple[str, str] | None = None,
    errors: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """The alert page. Also re-rendered, with the analyst's input, when a form is refused."""
    alert = repository.get_alert(session, alert_id) if alert_id else None
    if alert is None:
        return _not_found(request, settings, "alert")

    event = repository.get_event(session, alert.primary_event_id)
    incident = repository.get_incident(session, alert.incident_id) if alert.incident_id else None

    recommendations: list[tuple[str, str]] = []
    for detection in alert.detections:
        if detection.recommendation:
            item = (detection.rule_id, detection.recommendation.strip())
            if item not in recommendations:
                recommendations.append(item)

    return _render(
        request,
        "alert_detail.html",
        active="alerts",
        settings=settings,
        alert=alert,
        event=event,
        incident=incident,
        track=charts.severity_track(alert.severity),
        notes=repository.list_notes(session, alert_id=alert.alert_id),
        analyses=repository.get_ai_analyses(session, alert.alert_id),
        ai_disclaimer=AIAnalysis.DISCLAIMER,
        ai_problem=request.app.state.ai.problem,
        ai_ready=request.app.state.ai.provider is not None,
        recommendations=recommendations,
        history=repository.list_audit(session, object_id=alert.alert_id, limit=200),
        alert_statuses=[
            s.value for s in AlertStatus if s is not AlertStatus.NEW or alert.status is s
        ],
        classifications=[c.value for c in Classification],
        form={
            "status": alert.status.value,
            "classification": alert.classification.value if alert.classification else "",
            "assigned_to": alert.assigned_to or "",
            "reason": "",
            "body": "",
            **(values or {}),
        },
        errors=errors or {},
        notice=notice,
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------
@router.get("/incidents", response_class=HTMLResponse)
def incident_list(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    incidents = repository.list_incidents(session, limit=200)
    incidents.sort(key=lambda i: (-i.severity.rank, -i.alert_count))
    return _render(
        request,
        "incidents.html",
        active="incidents",
        settings=settings,
        incidents=incidents,
    )


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(
    request: Request,
    incident_id: str,
    session: SessionDep,
    settings: SettingsDep,
    saved: str | None = Query(None, max_length=16),
) -> Response:
    return incident_page(
        request, session, settings, _parse_uuid(incident_id), notice=NOTICES.get(saved or "")
    )


def incident_page(
    request: Request,
    session: Any,
    settings: Any,
    incident_id: UUID | None,
    *,
    notice: tuple[str, str] | None = None,
    errors: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    incident = repository.get_incident(session, incident_id) if incident_id else None
    if incident is None:
        return _not_found(request, settings, "investigation")

    members = repository.list_alerts(session, incident_id=incident.incident_id, limit=500)
    events = repository.get_events(session, (a.primary_event_id for a in members))
    timeline = [
        (events[alert.primary_event_id], alert)
        for alert in members
        if alert.primary_event_id in events
    ]
    timeline.sort(key=lambda pair: pair[0].timestamp)

    techniques: dict[str, Any] = {}
    for alert in members:
        for mapping in alert.mitre:
            techniques.setdefault(mapping.technique_id, mapping.technique)

    return _render(
        request,
        "incident_detail.html",
        active="incidents",
        settings=settings,
        incident=incident,
        timeline=timeline,
        techniques=sorted(techniques.values(), key=lambda t: t.technique_id),
        potential=incident.status is IncidentStatus.POTENTIAL,
        notes=repository.list_notes(session, incident_id=incident.incident_id),
        history=repository.list_audit(session, object_id=incident.incident_id, limit=200),
        incident_statuses=[
            s.value
            for s in IncidentStatus
            if s is not IncidentStatus.POTENTIAL or incident.status is s
        ],
        form={
            "status": incident.status.value,
            "assigned_to": incident.assigned_to or "",
            "reason": "",
            "body": "",
            **(values or {}),
        },
        errors=errors or {},
        notice=notice,
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@router.get("/alerts/{alert_id}/report")
def alert_report(
    request: Request,
    alert_id: str,
    session: SessionDep,
    settings: SettingsDep,
    report_format: str = Query("html", alias="format", max_length=16),
    download: bool = False,
) -> Response:
    return _report(request, session, settings, "alert", alert_id, report_format, download)


@router.get("/incidents/{incident_id}/report")
def incident_report(
    request: Request,
    incident_id: str,
    session: SessionDep,
    settings: SettingsDep,
    report_format: str = Query("html", alias="format", max_length=16),
    download: bool = False,
) -> Response:
    return _report(request, session, settings, "incident", incident_id, report_format, download)


def _report(
    request: Request,
    session: Any,
    settings: Any,
    kind: ReportKind,
    subject: str,
    report_format: str,
    download: bool,
) -> Response:
    parsed = _parse_uuid(subject)
    wanted = ReportFormat(report_format) if report_format in set(ReportFormat) else None
    what = "investigation" if kind == "incident" else "alert"
    if parsed is None or wanted is None:
        return _not_found(request, settings, what)
    try:
        return report_response(
            request,
            session,
            settings,
            kind,
            parsed,
            wanted,
            download=download,
            channel=Channel.CONSOLE,
        )
    except ReportSubjectNotFoundError:
        return _not_found(request, settings, what)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
@router.get("/rules", response_class=HTMLResponse)
def rule_catalogue(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
) -> Response:
    fired = {rule_id: count for rule_id, _, count in repository.top_alert_rules(session, limit=500)}
    return _render(
        request,
        "rules.html",
        active="rules",
        settings=settings,
        rules=rules.rules,
        errors=rules.errors,
        fired=fired,
    )
