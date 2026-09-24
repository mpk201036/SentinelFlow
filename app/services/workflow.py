"""The analyst's decisions: status, classification, assignment and notes.

This is the only layer that can close an alert or confirm an incident, so it
is where the rules of the workflow live. They exist because each one protects
something a SOC depends on later:

* **Closing needs an answer.** An alert cannot be closed without a
  classification. True- and false-positive rates are how rules get tuned, and
  an alert closed without saying which it was teaches nobody anything.
* **The answer must fit the outcome.** "Benign" cannot be closed as a true
  positive, and "needs more information" is not an answer to close on.
* **Some moves need a reason.** Closing, reopening and escalating an alert, and
  confirming, dismissing or reopening an incident, each record why. The reason
  goes into the audit trail with the change, for whoever reads the history.
* **Nothing goes back to "new" or "potential".** Once a human has looked, the
  record says so. Only the pipeline creates new alerts, and only correlation
  creates potential incidents.
* **No silent overwrites.** Every decision is made against the version the
  analyst saw. If the record changed meanwhile - another tab, the API, an
  incident gaining alerts - the decision is refused, not merged.

Every change writes one audit entry naming the analyst, the channel and the
before and after values. A decision that changes nothing writes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.sanitize import clean_line, clean_text
from app.database import repository
from app.models.alert import Alert
from app.models.analyst import AnalystNote, AuditEntry
from app.models.enums import Actor, AlertStatus, AuditAction, Classification, IncidentStatus
from app.models.incident import Incident

logger = get_logger(__name__)

MAX_REASON_LENGTH = 1_000
MAX_ASSIGNEE_LENGTH = 128

#: Statuses that end the work on an alert.
CLOSED_STATUSES: Final = frozenset({AlertStatus.BENIGN, AlertStatus.CLOSED})
#: Classifications that mean the activity was not malicious.
NOT_MALICIOUS: Final = frozenset({Classification.BENIGN_POSITIVE, Classification.FALSE_POSITIVE})
#: Incident states an analyst has ruled on.
RULED: Final = frozenset({IncidentStatus.CONFIRMED, IncidentStatus.DISMISSED})


class Channel(StrEnum):
    """Where a decision was made. Recorded in the audit trail."""

    CONSOLE = "console"
    API = "api"
    CLI = "cli"


class WorkflowError(ValueError):
    """A decision SentinelFlow refuses. The message is written for the analyst."""


class StaleDecisionError(WorkflowError):
    """The record changed after the analyst loaded it."""


class RecordNotFoundError(LookupError):
    """No alert or incident has that id."""


class _Unchanged:
    """Marker for "leave the assignee as it is", distinct from "unassign" (None)."""

    def __repr__(self) -> str:
        return "UNCHANGED"


UNCHANGED: Final = _Unchanged()


@dataclass(frozen=True)
class AlertDecision:
    """What the analyst asked for. ``None`` status or classification means "as is"."""

    status: AlertStatus | None = None
    classification: Classification | None = None
    assigned_to: str | _Unchanged | None = UNCHANGED
    reason: str | None = None
    #: The ``updated_at`` the analyst was looking at. None skips the check,
    #: which only the CLI does, because it reads and writes in one step.
    expected_updated_at: datetime | None = None


@dataclass(frozen=True)
class IncidentDecision:
    status: IncidentStatus | None = None
    assigned_to: str | _Unchanged | None = UNCHANGED
    reason: str | None = None
    expected_updated_at: datetime | None = None


@dataclass
class DecisionResult:
    """What changed, in words, plus the record as it now stands."""

    changes: list[str] = field(default_factory=list)
    alert: Alert | None = None
    incident: Incident | None = None

    @property
    def changed(self) -> bool:
        return bool(self.changes)


class AnalystWorkflow:
    """Applies one analyst's decisions, with the rules above and a full audit trail."""

    def __init__(self, session: Session, *, analyst: str, channel: Channel) -> None:
        name = clean_line(analyst, max_length=64)
        if not name:
            raise ValueError("a decision must record which analyst made it")
        self.session = session
        self.analyst = name
        self.channel = channel

    # ==================================================================
    # Alerts
    # ==================================================================
    def decide_alert(self, alert_id: UUID, decision: AlertDecision) -> DecisionResult:
        alert = repository.get_alert(self.session, alert_id)
        if alert is None:
            raise RecordNotFoundError(f"no alert {alert_id}")
        self._check_version("alert", alert.updated_at, decision.expected_updated_at)

        status = decision.status or alert.status
        classification = decision.classification or alert.classification
        assignee = self._assignee(decision.assigned_to, alert.assigned_to)
        reason = _reason(decision.reason)

        status_changes = status is not alert.status
        class_changes = classification is not alert.classification
        assignee_changes = assignee != alert.assigned_to
        if not (status_changes or class_changes or assignee_changes):
            return DecisionResult(alert=alert)

        _check_alert_rules(alert, status, classification, reason, status_changes, class_changes)

        written = repository.update_alert_workflow(
            self.session,
            alert_id,
            expected_updated_at=alert.updated_at,
            status=status,
            classification=classification,
            assigned_to=assignee,
        )
        if written is None:
            raise StaleDecisionError(_STALE.format(kind="alert"))

        result = DecisionResult()
        if status_changes:
            result.changes.append(f"status {alert.status.value} -> {status.value}")
            self._audit(
                AuditAction.ALERT_STATUS_CHANGED,
                "alert",
                alert_id,
                alert.status.value,
                status.value,
                reason,
            )
        if class_changes:
            before = alert.classification.value if alert.classification else None
            after = classification.value if classification else "none"
            result.changes.append(f"classification {before or 'none'} -> {after}")
            self._audit(
                AuditAction.ALERT_CLASSIFIED,
                "alert",
                alert_id,
                before,
                classification.value if classification else None,
                reason if not status_changes else None,
            )
        if assignee_changes:
            result.changes.append(
                f"assignee {alert.assigned_to or 'nobody'} -> {assignee or 'nobody'}"
            )
            self._audit(
                AuditAction.ALERT_ASSIGNED, "alert", alert_id, alert.assigned_to, assignee, None
            )

        self.session.expire_all()
        result.alert = repository.get_alert(self.session, alert_id)
        logger.info(
            "%s changed alert %s via %s: %s",
            self.analyst,
            alert_id,
            self.channel.value,
            "; ".join(result.changes),
        )
        return result

    def add_alert_note(self, alert_id: UUID, body: str) -> AnalystNote:
        if repository.get_alert(self.session, alert_id) is None:
            raise RecordNotFoundError(f"no alert {alert_id}")
        return self._add_note(body, alert_id=alert_id)

    # ==================================================================
    # Incidents
    # ==================================================================
    def decide_incident(self, incident_id: UUID, decision: IncidentDecision) -> DecisionResult:
        incident = repository.get_incident(self.session, incident_id)
        if incident is None:
            raise RecordNotFoundError(f"no incident {incident_id}")
        self._check_version("investigation", incident.updated_at, decision.expected_updated_at)

        status = decision.status or incident.status
        assignee = self._assignee(decision.assigned_to, incident.assigned_to)
        reason = _reason(decision.reason)

        status_changes = status is not incident.status
        assignee_changes = assignee != incident.assigned_to
        if not (status_changes or assignee_changes):
            return DecisionResult(incident=incident)

        if status_changes:
            _check_incident_rules(incident, status, reason)

        written = repository.update_incident_workflow(
            self.session,
            incident_id,
            expected_updated_at=incident.updated_at,
            status=status,
            assigned_to=assignee,
        )
        if written is None:
            raise StaleDecisionError(_STALE.format(kind="investigation"))

        result = DecisionResult()
        if status_changes:
            result.changes.append(f"status {incident.status.value} -> {status.value}")
            self._audit(
                AuditAction.INCIDENT_STATUS_CHANGED,
                "incident",
                incident_id,
                incident.status.value,
                status.value,
                reason,
            )
        if assignee_changes:
            result.changes.append(
                f"assignee {incident.assigned_to or 'nobody'} -> {assignee or 'nobody'}"
            )
            self._audit(
                AuditAction.INCIDENT_ASSIGNED,
                "incident",
                incident_id,
                incident.assigned_to,
                assignee,
                None,
            )

        self.session.expire_all()
        result.incident = repository.get_incident(self.session, incident_id)
        return result

    def add_incident_note(self, incident_id: UUID, body: str) -> AnalystNote:
        if repository.get_incident(self.session, incident_id) is None:
            raise RecordNotFoundError(f"no incident {incident_id}")
        return self._add_note(body, incident_id=incident_id)

    # ==================================================================
    # Shared
    # ==================================================================
    def _add_note(
        self, body: str, *, alert_id: UUID | None = None, incident_id: UUID | None = None
    ) -> AnalystNote:
        if not clean_text(body):
            raise WorkflowError("A note cannot be empty.")
        note = AnalystNote(
            author=self.analyst, body=body, alert_id=alert_id, incident_id=incident_id
        )
        repository.add_note(self.session, note)
        excerpt = note.body if len(note.body) <= 200 else note.body[:197] + "..."
        self._audit(
            AuditAction.NOTE_ADDED,
            "alert" if alert_id else "incident",
            alert_id or incident_id,
            None,
            f"note {note.note_id}",
            excerpt,
        )
        return note

    def _assignee(self, requested: str | _Unchanged | None, current: str | None) -> str | None:
        if isinstance(requested, _Unchanged):
            return current
        if requested is None:
            return None
        return clean_line(requested, max_length=MAX_ASSIGNEE_LENGTH) or None

    @staticmethod
    def _check_version(kind: str, current: datetime, expected: datetime | None) -> None:
        if expected is not None and expected != current:
            raise StaleDecisionError(_STALE.format(kind=kind))

    def _audit(
        self,
        action: AuditAction,
        object_type: str,
        object_id: UUID | None,
        before: str | None,
        after: str | None,
        reason: str | None,
    ) -> None:
        detail = f"via {self.channel.value}"
        if reason:
            detail = f"{reason} ({detail})"
        repository.record_audit(
            self.session,
            AuditEntry(
                actor=Actor.ANALYST,
                actor_name=self.analyst,
                action=action,
                object_type=object_type,
                object_id=object_id,
                before=before,
                after=after,
                detail=detail[:1_024],
            ),
        )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
_STALE = (
    "This {kind} changed after you opened it, so your decision was not applied. "
    "Reload to see what changed, then decide again."
)


def _reason(text: str | None) -> str | None:
    return clean_text(text, max_length=MAX_REASON_LENGTH) if text else None


def _require(reason: str | None, message: str) -> None:
    if not reason:
        raise WorkflowError(message)


def _check_alert_rules(
    alert: Alert,
    status: AlertStatus,
    classification: Classification | None,
    reason: str | None,
    status_changes: bool,
    class_changes: bool,
) -> None:
    if status_changes and status is AlertStatus.NEW:
        raise WorkflowError(
            "An alert cannot go back to New once someone has looked at it. "
            "Use Investigating to reopen it."
        )

    closing = status in CLOSED_STATUSES
    if closing:
        if classification is None:
            raise WorkflowError(
                "Classify the alert before closing it. The classification is the answer the "
                "alert is closed with, and it is what tunes the rules."
            )
        if classification is Classification.NEEDS_MORE_INFORMATION:
            raise WorkflowError(
                "An alert that needs more information cannot be closed. Keep it open, or "
                "classify it once the information is in."
            )
        if status is AlertStatus.BENIGN and classification not in NOT_MALICIOUS:
            raise WorkflowError(
                "Only a benign positive or a false positive can be closed as Benign. "
                "Close a true positive as Closed, or escalate it."
            )

    if status_changes:
        if closing and alert.status not in CLOSED_STATUSES:
            _require(reason, "Say why the alert is being closed.")
        elif not closing and alert.status in CLOSED_STATUSES:
            _require(reason, "Say why the alert is being reopened.")
        elif status is AlertStatus.ESCALATED:
            _require(reason, "Say why the alert is being escalated, for whoever picks it up.")
    elif class_changes and alert.status in CLOSED_STATUSES:
        _require(reason, "Say why the classification of a closed alert is changing.")


def _check_incident_rules(incident: Incident, status: IncidentStatus, reason: str | None) -> None:
    if status is IncidentStatus.POTENTIAL:
        raise WorkflowError(
            "Only correlation marks an investigation as potential. Use Investigating to reopen it."
        )
    if status is IncidentStatus.CONFIRMED:
        _require(reason, "Say what confirms this incident.")
    elif status is IncidentStatus.DISMISSED:
        _require(reason, "Say why this investigation is being dismissed.")
    elif incident.status in RULED:
        _require(reason, "Say why this investigation is being reopened.")
