"""Template filters.

These format values for display. None of them builds HTML: every filter
returns plain text, and Jinja2's autoescaping turns it into markup-safe output.
That is the property that keeps attacker-controlled event data - a hostname of
``<script>...`` is a perfectly valid thing for an adversary to send - inert on
the page. A filter returning ``Markup`` would be a hole in that, so none do.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.core.display import audit_change, audit_label, audit_subject, humanise
from app.models.base import utcnow


def timestamp(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """UTC timestamp, always labelled as UTC by the template, never localised."""
    if value is None:
        return "-"
    return value.strftime(fmt)


def ago(value: datetime | None, now: datetime | None = None) -> str:
    """Coarse relative time, for scanning a queue."""
    if value is None:
        return "-"
    seconds = int(((now or utcnow()) - value).total_seconds())
    if seconds < 0:
        return "just now"
    for size, unit in ((86_400, "d"), (3_600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def compact(value: int | float | None) -> str:
    """Auto-compact figures for stat tiles: 1,284 / 12.9K / 4.2M."""
    if value is None:
        return "-"
    number = float(value)
    for size, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (10_000, "K")):
        if abs(number) >= size:
            scaled = number / (size if suffix != "K" else 1_000)
            return f"{scaled:.1f}{suffix}".replace(".0", "")
    return f"{int(number):,}"


def pretty_json(value: Any) -> str:
    """Indented JSON for the raw-event panel. Escaped by the template, not here."""
    return json.dumps(value, indent=2, sort_keys=True, default=str, ensure_ascii=False)


FILTERS = {
    "ts": timestamp,
    "ago": ago,
    "compact": compact,
    "pretty_json": pretty_json,
    "humanise": humanise,
    "audit_label": audit_label,
    "audit_change": audit_change,
    "audit_subject": audit_subject,
}
