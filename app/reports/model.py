"""What a report says, assembled once for every format.

A report is built from the database into a :class:`Report`, and the Markdown
and HTML renderers only lay it out. That keeps the two formats from drifting
apart in what they claim - the wording of the summary, what counts as
"reviewed", which indicators are external - because those decisions are made
here, once.

The report follows the same order of trust as the console: what was observed,
what the rules determined, what a model suggested (clearly set apart), and
what an analyst decided. Nothing is re-derived: severities, mappings and
indicators are the stored deterministic results, and the AI section repeats
stored advisory output without letting it touch anything else.
"""

from __future__ import annotations

import re
import secrets
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session

from app.database import repository
from app.models.ai import AIAnalysis
from app.models.alert import Alert
from app.models.analyst import AnalystNote, AuditEntry
from app.models.base import utcnow
from app.models.enums import AuditAction, IncidentStatus, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.mitre import MitreTechnique

ReportKind = Literal["alert", "incident"]

#: The most audit entries a report includes. An investigation with more is
#: not normal, and the report says it was cut.
MAX_HISTORY = 500

#: Normalised event fields quoted in the evidence block, in reading order.
EVIDENCE_FIELDS: tuple[str, ...] = (
    "timestamp",
    "source",
    "event_type",
    "hostname",
    "username",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "process_name",
    "process_id",
    "parent_process",
    "command_line",
    "file_path",
    "file_hash",
    "domain",
    "url",
    "event_message",
)

_REASON_RE = re.compile(r"^(?P<reason>.*) \(via (?P<channel>\w+)\)$", re.DOTALL)


class ReportSubjectNotFoundError(LookupError):
    """No alert or incident has the requested id."""


def indicator_scope(indicator: Indicator) -> str | None:
    """Where a network indicator sits: internal, documentation or external.

    ``None`` for a hash, a path or a process name, which sit nowhere. Every
    format asks this one function, so they cannot disagree; they once called a
    file hash "external".
    """
    if indicator.is_internal:
        return "internal"
    if not indicator.is_external:
        return None
    return "documentation" if indicator.is_documentation else "external"


@dataclass(frozen=True)
class AlertSection:
    alert: Alert
    event: SecurityEvent | None
    analyses: list[AIAnalysis]
    notes: list[AnalystNote]

    @property
    def latest_analysis(self) -> AIAnalysis | None:
        return self.analyses[0] if self.analyses else None

    @property
    def event_time(self) -> datetime:
        return self.event.timestamp if self.event is not None else self.alert.created_at

    def evidence(self) -> list[tuple[str, str]]:
        """The normalised event as (field, value) pairs, verbatim."""
        if self.event is None:
            return []
        pairs: list[tuple[str, str]] = []
        for name in EVIDENCE_FIELDS:
            value = getattr(self.event, name, None)
            if value is None or value == "":
                continue
            if name == "timestamp":
                text = self.event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            elif hasattr(value, "value"):
                text = str(value.value)
            else:
                text = str(value)
            pairs.append((name, text))
        return pairs


@dataclass(frozen=True)
class TechniqueUse:
    technique: MitreTechnique
    reasons: list[str]
    alert_titles: list[str]


@dataclass(frozen=True)
class Decision:
    """The latest ruling on the report's subject, from the audit trail."""

    status: str
    analyst: str | None
    at: datetime
    reason: str | None


@dataclass
class Report:
    report_id: str
    kind: ReportKind
    subject_id: UUID
    title: str
    generated_at: datetime
    generated_by: str
    alerts: list[AlertSection]
    incident: Incident | None = None
    incident_notes: list[AnalystNote] = field(default_factory=list)
    techniques: list[TechniqueUse] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    recommendations: list[tuple[str, str]] = field(default_factory=list)
    history: list[AuditEntry] = field(default_factory=list)
    history_truncated: bool = False
    decision: Decision | None = None

    # ------------------------------------------------------------------
    # Facts every format states the same way
    # ------------------------------------------------------------------
    @property
    def severity(self) -> Severity:
        """The highest deterministic severity in scope."""
        levels = [section.alert.severity_level for section in self.alerts]
        return Severity.highest(levels) or Severity.LOW

    @property
    def top_score(self) -> int:
        return max((section.alert.severity.score for section in self.alerts), default=0)

    @property
    def window(self) -> tuple[datetime, datetime] | None:
        times = [section.event_time for section in self.alerts]
        return (min(times), max(times)) if times else None

    @property
    def hostnames(self) -> list[str]:
        return _distinct(s.event.hostname for s in self.alerts if s.event and s.event.hostname)

    @property
    def usernames(self) -> list[str]:
        return _distinct(s.event.username for s in self.alerts if s.event and s.event.username)

    @property
    def assigned_to(self) -> str | None:
        if self.incident is not None:
            return self.incident.assigned_to
        return self.alerts[0].alert.assigned_to if self.alerts else None

    @property
    def reviewed(self) -> bool:
        """Whether an analyst has moved the subject past its initial state."""
        if self.incident is not None:
            return self.incident.status is not IncidentStatus.POTENTIAL
        return any(section.alert.status.value != "new" for section in self.alerts)

    @property
    def state_label(self) -> str:
        if self.incident is not None:
            return self.incident.display_label
        alert = self.alerts[0].alert
        label = alert.status.value.replace("_", " ").capitalize()
        if alert.classification is not None:
            label += f" ({alert.classification.value.replace('_', ' ')})"
        return label

    @property
    def analysed_alerts(self) -> list[AlertSection]:
        return [section for section in self.alerts if section.analyses]

    @property
    def all_notes(self) -> list[tuple[str, AnalystNote]]:
        """Every note in scope with what it is attached to, oldest first."""
        attached: list[tuple[str, AnalystNote]] = [
            ("this investigation", note) for note in self.incident_notes
        ]
        for section in self.alerts:
            attached.extend((section.alert.title, note) for note in section.notes)
        return sorted(attached, key=lambda pair: pair[1].created_at)

    def summary_sentences(self) -> list[str]:
        """The opening paragraph, generated from facts only. No adjectives."""
        count = len(self.alerts)
        window = self.window
        where = ", ".join(self.hostnames) or "an unrecorded host"
        sentences: list[str] = []
        if self.kind == "incident":
            sentences.append(
                f"{count} related alert{'s' if count != 1 else ''} on {where}"
                + (
                    f" between {window[0]:%Y-%m-%d %H:%M} and {window[1]:%H:%M} UTC."
                    if window
                    else "."
                )
            )
        elif window:
            sentences.append(f"One alert on {where} at {window[0]:%Y-%m-%d %H:%M} UTC.")
        sentences.append(
            f"Highest deterministic severity: {self.severity.value} ({self.top_score}/100)."
        )
        if self.techniques:
            tactics = _distinct(t for use in self.techniques for t in use.technique.tactics)
            sentences.append(
                f"{len(self.techniques)} ATT&CK technique"
                f"{'s' if len(self.techniques) != 1 else ''} mapped by rule, across "
                f"{len(tactics)} tactic{'s' if len(tactics) != 1 else ''}."
            )
        external = [i for i in self.indicators if i.is_external]
        if self.indicators:
            sentences.append(
                f"{len(self.indicators)} indicator{'s' if len(self.indicators) != 1 else ''} "
                f"extracted, {len(external)} of them "
                f"{'an address or domain' if len(external) == 1 else 'addresses or domains'} "
                "outside the estate."
            )
        classified = Counter(
            s.alert.classification.value.replace("_", " ")
            for s in self.alerts
            if s.alert.classification is not None
        )
        if classified:
            parts = ", ".join(f"{n} {label}" for label, n in classified.most_common())
            sentences.append(f"Analyst classifications: {parts}.")
        return sentences

    def limitations(self) -> list[str]:
        """What the report cannot tell the reader. Plain text; the renderers escape it."""
        lines = [
            f"Generated from SentinelFlow's database at {self.generated_at:%Y-%m-%d %H:%M} UTC. "
            "Activity that was not ingested is not reflected, and later changes are not "
            "included.",
        ]
        if self.kind == "incident" and not self.reviewed:
            lines.append(
                "This is a potential incident: alerts grouped because they share evidence. "
                "SentinelFlow does not assert a compromise."
            )
        lines.append(
            "Severities, detections and ATT&CK mappings are deterministic and reproducible "
            "from the same events and rules."
        )
        if self.analysed_alerts:
            lines.append(
                "AI output is advisory. It was produced by a local model that was not shown the "
                "deterministic severity, and it changed nothing in this report's other sections."
            )
        lines.append(
            "Evidence quoted verbatim is shown as code. Elsewhere, links, domains and e-mail "
            "addresses are defanged: hxxps://example[.]com, user[at]example[.]com."
        )
        return lines

    def conclusion(self) -> str:
        """What an analyst concluded, or plainly that nobody has yet."""
        if self.kind == "incident" and not self.reviewed:
            return (
                "Not yet reviewed. SentinelFlow grouped these alerts because they share "
                "concrete evidence; it does not assert a compromise. That is an analyst's call."
            )
        if self.decision is None:
            return (
                "Not yet reviewed by an analyst."
                if not self.reviewed
                else f"{self.state_label}. No reason was recorded."
            )
        who = self.decision.analyst or "an analyst"
        text = f"{self.state_label}, by {who} on {self.decision.at:%Y-%m-%d %H:%M} UTC."
        if self.decision.reason:
            text += f" Reason given: {self.decision.reason}"
        return text


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------
def new_report_id(now: datetime) -> str:
    return f"SFR-{now:%Y%m%d}-{secrets.token_hex(4)}"


def build_alert_report(
    session: Session, alert_id: UUID, *, generated_by: str, now: datetime | None = None
) -> Report:
    alert = repository.get_alert(session, alert_id)
    if alert is None:
        raise ReportSubjectNotFoundError(f"no alert {alert_id}")
    moment = now or utcnow()
    (section,) = _sections(session, [alert])
    history, truncated = _history(session, [alert_id])
    report = Report(
        report_id=new_report_id(moment),
        kind="alert",
        subject_id=alert_id,
        title=alert.title,
        generated_at=moment,
        generated_by=generated_by,
        alerts=[section],
        history=history,
        history_truncated=truncated,
    )
    _aggregate(report)
    report.decision = _decision(history, alert_id, AuditAction.ALERT_STATUS_CHANGED)
    return report


def build_incident_report(
    session: Session, incident_id: UUID, *, generated_by: str, now: datetime | None = None
) -> Report:
    incident = repository.get_incident(session, incident_id)
    if incident is None:
        raise ReportSubjectNotFoundError(f"no incident {incident_id}")
    moment = now or utcnow()
    members = repository.list_alerts(session, incident_id=incident_id, limit=500)
    sections = sorted(_sections(session, members), key=_by_time)
    history, truncated = _history(session, [incident_id, *(a.alert_id for a in members)])
    report = Report(
        report_id=new_report_id(moment),
        kind="incident",
        subject_id=incident_id,
        title=incident.title,
        generated_at=moment,
        generated_by=generated_by,
        alerts=sections,
        incident=incident,
        incident_notes=repository.list_notes(session, incident_id=incident_id),
        history=history,
        history_truncated=truncated,
    )
    _aggregate(report)
    report.decision = _decision(history, incident_id, AuditAction.INCIDENT_STATUS_CHANGED)
    return report


def _sections(session: Session, alerts: list[Alert]) -> list[AlertSection]:
    """Everything a report shows about each alert, in three queries whatever the count."""
    events = repository.get_events(session, (a.primary_event_id for a in alerts))
    analyses = repository.get_ai_analyses_for(session, (a.alert_id for a in alerts))
    notes = repository.notes_for_alerts(session, (a.alert_id for a in alerts))
    return [
        AlertSection(
            alert=alert,
            event=events.get(alert.primary_event_id),
            analyses=analyses.get(alert.alert_id, []),
            notes=notes.get(alert.alert_id, []),
        )
        for alert in alerts
    ]


def _by_time(section: AlertSection) -> datetime:
    return section.event_time


def _history(session: Session, object_ids: list[UUID]) -> tuple[list[AuditEntry], bool]:
    entries = repository.list_audit(
        session, object_ids=object_ids, limit=MAX_HISTORY + 1, oldest_first=True
    )
    return entries[:MAX_HISTORY], len(entries) > MAX_HISTORY


def _aggregate(report: Report) -> None:
    """Techniques, indicators and next steps across every alert in scope, de-duplicated."""
    techniques: dict[str, tuple[MitreTechnique, list[str], list[str]]] = {}
    indicators: dict[tuple[str, str], Indicator] = {}
    recommendations: dict[tuple[str, str], None] = {}
    for section in report.alerts:
        alert = section.alert
        for mapping in alert.mitre:
            _, reasons, titles = techniques.setdefault(
                mapping.technique_id, (mapping.technique, [], [])
            )
            if mapping.reason not in reasons:
                reasons.append(mapping.reason)
            if alert.title not in titles:
                titles.append(alert.title)
        for indicator in alert.indicators:
            indicators.setdefault((indicator.indicator_type.value, indicator.value), indicator)
        for detection in alert.detections:
            if detection.recommendation:
                recommendations.setdefault(
                    (detection.rule_id, detection.recommendation.strip()), None
                )

    report.techniques = [
        TechniqueUse(technique=technique, reasons=reasons, alert_titles=titles)
        for technique, reasons, titles in sorted(
            techniques.values(), key=lambda item: item[0].technique_id
        )
    ]
    # External indicators first: they are the ones to search for elsewhere.
    report.indicators = sorted(
        indicators.values(),
        # Outside the estate first, then what sits nowhere, then internal.
        key=lambda i: (not i.is_external, i.is_internal, i.indicator_type.value, i.value),
    )
    report.recommendations = list(recommendations)


def _decision(history: list[AuditEntry], subject: UUID, action: AuditAction) -> Decision | None:
    for entry in reversed(history):
        if entry.object_id == subject and entry.action is action:
            match = _REASON_RE.match(entry.detail or "")
            return Decision(
                status=entry.after or "",
                analyst=entry.actor_name,
                at=entry.occurred_at,
                reason=match.group("reason") if match else None,
            )
    return None


def _distinct(values: Iterable[object]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(str(value), None)
    return list(seen)
