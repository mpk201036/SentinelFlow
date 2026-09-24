"""The HTML report: one self-contained file, safe to open from anywhere.

An HTML report is opened from a download folder, an e-mail attachment or a
ticket, where no server sends security headers. So the file carries its own
Content-Security-Policy in a ``<meta>`` tag:

* ``default-src 'none'`` - nothing is fetched from anywhere: no images, no
  fonts, no scripts. A tracking pixel smuggled into the evidence would have
  nowhere to load from.
* ``style-src 'sha256-...'`` - exactly one stylesheet may apply: the one
  embedded here, identified by its hash. No inline ``style`` attributes.
* No ``script-src`` at all - the report has no script, and none can run.

Every value is escaped by Jinja2's autoescaping, and the same defanging as
the Markdown report is applied to prose. The only links are ATT&CK technique
pages from the local catalogue, and those are checked against the ATT&CK site
before they are written.
"""

from __future__ import annotations

import base64
import hashlib
import re
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from app import __version__
from app.core.display import audit_label, audit_summary, audit_who
from app.enrichment.defang import defang_text
from app.models.ai import AIAnalysis
from app.reports.markdown import indicator_display, indicator_scope_label
from app.reports.model import Report

TEMPLATE_DIR = Path(__file__).parent / "templates"
_ATTACK_URL_RE = re.compile(r"^https://attack\.mitre\.org/techniques/T\d{4}(?:/\d{3})?/?$")


def attack_url(url: str | None) -> str | None:
    """The URL if it is an ATT&CK technique page, else None. Nothing else is linked."""
    return url if url and _ATTACK_URL_RE.fullmatch(url) else None


@lru_cache(maxsize=1)
def _environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters.update(
        {
            "defang": lambda value: defang_text(str(value)),
            "indicator_display": indicator_display,
            "indicator_scope": indicator_scope_label,
            "audit_who": audit_who,
            "audit_label": audit_label,
            "audit_summary": audit_summary,
            "attack_url": attack_url,
        }
    )
    return environment


@lru_cache(maxsize=1)
def stylesheet() -> tuple[str, str]:
    """The embedded CSS and the CSP source that allows exactly it."""
    css = (TEMPLATE_DIR / "report.css").read_text(encoding="utf-8")
    # The stylesheet is written into <style> unescaped (see render_html), so
    # it must not be able to end that element. CSS never needs a "<".
    if "<" in css:
        raise ValueError("report.css must not contain '<'")
    digest = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    return css, f"'sha256-{digest}'"


def content_security_policy() -> str:
    """The policy for a report page, used in the file and in the HTTP header."""
    _, style_source = stylesheet()
    return (
        f"default-src 'none'; style-src {style_source}; img-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )


def render_html(report: Report) -> str:
    css, _ = stylesheet()
    template = _environment().get_template("report.html")
    return template.render(
        report=report,
        subject="Investigation" if report.kind == "incident" else "Alert",
        # Our own file, written verbatim: escaping it would break the CSS
        # (entities are not decoded inside <style>) and the hash with it.
        css=Markup(css),  # noqa: S704 - our packaged stylesheet, checked in stylesheet()
        csp=content_security_policy(),
        version=__version__,
        disclaimer=AIAnalysis.DISCLAIMER,
        limitations=report.limitations(),
    )
