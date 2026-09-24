"""How things read, wherever they are shown.

The console, the CLI and the exported reports all show the audit trail, and
they must describe the same entry the same way. These helpers are that one
description. They return plain text; each caller escapes it for its medium.
"""

from __future__ import annotations

from app.models.analyst import AuditEntry

#: Actions whose before and after are workflow values, read as words.
_VALUE_CHANGES = frozenset({"alert_status_changed", "alert_classified", "incident_status_changed"})
#: Actions whose before and after are names, shown verbatim.
_NAME_CHANGES = frozenset({"alert_assigned", "incident_assigned"})
_LABELS = {
    "ai_analysis_requested": "AI analysis requested",
    "ai_analysis_stored": "AI analysis stored",
}


def counted(count: int, singular: str, plural: str | None = None) -> str:
    """``1 incident``, ``2 incidents``: a count with its noun agreeing."""
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def humanise(value: str | None) -> str:
    """``privileged_account`` -> ``Privileged account``."""
    if not value:
        return ""
    text = value.replace("_", " ").strip()
    return text[:1].upper() + text[1:]


def audit_label(action: str) -> str:
    """``alert_status_changed`` -> ``Alert status changed``, with "AI" kept upper case."""
    return _LABELS.get(action) or humanise(action)


def audit_who(entry: AuditEntry) -> str:
    if entry.actor.value == "system":
        return "SentinelFlow"
    if entry.actor.value == "ai_assistant":
        return "AI assistant"
    return entry.actor_name or "analyst"


def audit_change(entry: AuditEntry) -> tuple[str, str] | None:
    """The before and after worth showing, or None if the entry is not a change."""
    action = entry.action.value
    if action in _VALUE_CHANGES:
        return (humanise(entry.before) or "—", humanise(entry.after) or "—")
    if action in _NAME_CHANGES:
        return (entry.before or "nobody", entry.after or "nobody")
    return None


def audit_subject(entry: AuditEntry) -> str | None:
    """A single value worth showing for entries that are not changes."""
    action = entry.action.value
    if action == "alert_created":
        return entry.after
    if action == "report_generated" and entry.after:
        # "report SFR-... sha256:..." - the ID is what a reader looks for.
        return entry.after.split(" ")[1] if " " in entry.after else entry.after
    return None


def audit_summary(entry: AuditEntry) -> str:
    """The change or the subject as one line: "New -> Closed", "SFR-...", or ""."""
    change = audit_change(entry)
    if change is not None:
        return f"{change[0]} -> {change[1]}"
    return audit_subject(entry) or ""
