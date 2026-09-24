"""Investigation reports: Markdown, self-contained HTML, and JSON.

model     what a report says, built once from the database for every format
markdown  the Markdown report, and the escaping that makes it safe to share
html      a single-file HTML report that carries its own strict CSP
service   generating (fingerprinted and audited) and verifying copies later
"""

from app.reports.model import (
    Report,
    ReportKind,
    ReportSubjectNotFoundError,
    build_alert_report,
    build_incident_report,
)
from app.reports.service import (
    GeneratedReport,
    ReportFormat,
    ReportService,
    Verification,
    VerificationStatus,
    render,
    to_json,
    verify_report,
)

__all__ = [
    "GeneratedReport",
    "Report",
    "ReportFormat",
    "ReportKind",
    "ReportService",
    "ReportSubjectNotFoundError",
    "Verification",
    "VerificationStatus",
    "build_alert_report",
    "build_incident_report",
    "render",
    "to_json",
    "verify_report",
]
