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

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from app import __version__
from app.api.dependencies import CatalogueDep, RulesDep, SessionDep, SettingsDep
from app.core.config import PROJECT_ROOT
from app.database import repository
from app.models.ai import AIAnalysis
from app.models.enums import AlertStatus, IncidentStatus, Severity
from app.services.dashboard import RANGES, SEVERITY_ORDER, collect_dashboard_stats
from app.web import charts
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


def _render(
    request: Request,
    template: str,
    *,
    active: str,
    settings: Any,
    status_code: int = 200,
    **context: Any,
) -> Response:
    return templates.TemplateResponse(
        request,
        template,
        {
            "nav": NAV,
            "active": active,
            "version": __version__,
            "ai_enabled": settings.ai_active,
            "severity_order": [s.value for s in SEVERITY_ORDER],
            **context,
        },
        status_code=status_code,
    )


def _not_found(request: Request, settings: Any, what: str) -> Response:
    return _render(
        request,
        "not_found.html",
        active="",
        settings=settings,
        status_code=404,
        what=what,
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
    events = {a.alert_id: repository.get_event(session, a.primary_event_id) for a in alerts}
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
) -> Response:
    parsed = _parse_uuid(alert_id)
    alert = repository.get_alert(session, parsed) if parsed else None
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
        recommendations=recommendations,
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
) -> Response:
    parsed = _parse_uuid(incident_id)
    incident = repository.get_incident(session, parsed) if parsed else None
    if incident is None:
        return _not_found(request, settings, "investigation")

    members = repository.list_alerts(session, incident_id=incident.incident_id, limit=500)
    timeline = []
    for alert in members:
        event = repository.get_event(session, alert.primary_event_id)
        if event is not None:
            timeline.append((event, alert))
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
    )


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
