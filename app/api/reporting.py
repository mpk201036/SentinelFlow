"""Serving a report over HTTP, for the API and the console alike.

An export is data leaving SentinelFlow, and generating one writes an audit
entry, so a request that a browser marks as coming from another site is
refused even though it is a GET. A page elsewhere could not read the report
anyway; refusing it keeps the audit trail free of exports nobody asked for.

The HTML report is served with its own Content-Security-Policy - the one it
also carries in a ``<meta>`` tag - instead of the console's, because its
single stylesheet is embedded and allowed by hash.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.reports import ReportFormat, ReportKind, ReportService
from app.reports.html import content_security_policy
from app.services.workflow import Channel


def export_refusal(request: Request) -> str | None:
    site = request.headers.get("sec-fetch-site")
    if site is not None and site.lower() in ("cross-site", "same-site"):
        return "Reports can only be exported from SentinelFlow itself or a non-browser client."
    return None


def report_response(
    request: Request,
    session: Session,
    settings: Settings,
    kind: ReportKind,
    subject_id: UUID,
    report_format: ReportFormat,
    *,
    download: bool,
    channel: Channel,
) -> Response:
    problem = export_refusal(request)
    if problem is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=problem)

    generated = ReportService(session, analyst=settings.analyst_name, channel=channel).generate(
        kind, subject_id, report_format
    )
    inline = report_format is ReportFormat.HTML and not download
    headers = {
        # Only [A-Za-z0-9.-] can appear in the name, so it needs no quoting rules.
        "Content-Disposition": (
            f'{"inline" if inline else "attachment"}; filename="{generated.filename}"'
        ),
        "Cache-Control": "no-store",
        "X-SentinelFlow-Report-Id": generated.report_id,
        "X-SentinelFlow-Report-SHA256": generated.sha256,
    }
    if report_format is ReportFormat.HTML:
        headers["Content-Security-Policy"] = f"{content_security_policy()}; frame-ancestors 'none'"
    return Response(generated.content, media_type=report_format.media_type, headers=headers)
