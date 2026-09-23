"""Controlled vocabularies shared across the whole system.

Every enum here is a closed set on purpose. If an incoming event uses a value
that is not in one of these sets, the value is preserved verbatim in a
``*_raw`` field or in ``raw_event`` and the canonical field falls back to a
safe default. Data is never silently discarded, and the canonical vocabulary is
never silently extended by whoever sent the event.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Self


class Severity(StrEnum):
    """Risk level of an alert.

    ``Severity`` is ordered, but **not** by its string value — ``"high"`` sorts
    before ``"low"`` alphabetically, which would be a silent and dangerous bug.
    The comparison operators below are defined explicitly against ``rank``.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in the ordering, 0 (lowest) to 3 (highest)."""
        return _SEVERITY_RANK[self]

    @property
    def base_score(self) -> int:
        """Numeric contribution used by the deterministic severity engine."""
        return _SEVERITY_SCORE[self]

    @classmethod
    def from_score(cls, score: int) -> Self:
        """Map a 0-100 risk score onto a severity band."""
        if score >= 85:
            return cls(cls.CRITICAL)
        if score >= 60:
            return cls(cls.HIGH)
        if score >= 30:
            return cls(cls.MEDIUM)
        return cls(cls.LOW)

    @classmethod
    def highest(cls, values: Iterable[Severity]) -> Severity | None:
        """Return the highest severity in an iterable, or ``None`` if empty."""
        items = list(values)
        return max(items, key=lambda severity: severity.rank) if items else None

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 65,
    Severity.CRITICAL: 85,
}


class Confidence(StrEnum):
    """How much weight the producer of a signal places on it."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def multiplier(self) -> float:
        """Weighting applied by the severity engine."""
        return {"low": 0.6, "medium": 0.85, "high": 1.0}[self.value]


class EventType(StrEnum):
    """Canonical categories of observed activity.

    Source-specific names (Sysmon's ``ProcessCreate``, Windows event ID 4625,
    and so on) are mapped onto these by the ingestion adapters. Anything
    unrecognised becomes :attr:`OTHER` with the original preserved.
    """

    PROCESS_CREATION = "process_creation"
    PROCESS_TERMINATION = "process_termination"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_CREATION = "file_creation"
    FILE_DOWNLOAD = "file_download"
    FILE_MODIFICATION = "file_modification"
    FILE_DELETION = "file_deletion"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_MODIFIED = "account_modified"
    GROUP_MEMBERSHIP_CHANGE = "group_membership_change"
    SERVICE_INSTALLED = "service_installed"
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    REGISTRY_MODIFICATION = "registry_modification"
    NETWORK_EXPOSURE_CHANGE = "network_exposure_change"
    DECOY_CREDENTIAL_ACCESS = "decoy_credential_access"
    LOG_CLEARED = "log_cleared"
    OTHER = "other"


class IndicatorType(StrEnum):
    """Categories of extracted indicator of compromise."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"


class AlertStatus(StrEnum):
    """Where an alert sits in the analyst workflow."""

    NEW = "new"
    INVESTIGATING = "investigating"
    BENIGN = "benign"
    ESCALATED = "escalated"
    CLOSED = "closed"

    @property
    def is_open(self) -> bool:
        return self in {AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.ESCALATED}


class Classification(StrEnum):
    """An analyst's verdict on an alert.

    This is deliberately separate from :class:`AlertStatus`: *where the work has
    got to* and *what the answer was* are different questions. Only a human
    ever sets this.
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    NEEDS_MORE_INFORMATION = "needs_more_information"


class IncidentStatus(StrEnum):
    """Lifecycle of a correlated group of alerts.

    Note the starting value. SentinelFlow never declares a compromise on its
    own: correlation produces a *potential* incident, and only an analyst can
    move it to :attr:`CONFIRMED`.
    """

    POTENTIAL = "potential"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class StatementType(StrEnum):
    """Epistemic status of a single statement in an AI analysis.

    The optional model is required to label every claim it makes. An analyst
    can then read the ``OBSERVED`` lines as evidence, the ``INFERRED`` lines as
    hypotheses, and the ``UNKNOWN`` lines as the investigation's to-do list.
    """

    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class AuditAction(StrEnum):
    """Actions recorded in the immutable audit log."""

    EVENT_INGESTED = "event_ingested"
    ALERT_CREATED = "alert_created"
    ALERT_STATUS_CHANGED = "alert_status_changed"
    ALERT_CLASSIFIED = "alert_classified"
    NOTE_ADDED = "note_added"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_STATUS_CHANGED = "incident_status_changed"
    AI_ANALYSIS_REQUESTED = "ai_analysis_requested"
    AI_ANALYSIS_STORED = "ai_analysis_stored"
    REPORT_GENERATED = "report_generated"


class Actor(StrEnum):
    """Who or what performed an audited action."""

    SYSTEM = "system"
    ANALYST = "analyst"
    AI_ASSISTANT = "ai_assistant"
