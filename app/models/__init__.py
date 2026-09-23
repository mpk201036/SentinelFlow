"""Domain models — the vocabulary the whole system shares.

Import from this package rather than from the individual modules::

    from app.models import SecurityEvent, Alert, Severity

The layering is deliberate and worth keeping in mind when adding to it:

    enums      controlled vocabularies, no behaviour beyond ordering
    base       frozen/mutable base classes, UTC handling, size limits
    event      SecurityEvent - observation only
    indicator  extracted IOCs - facts, not verdicts
    detection  deterministic rule outcomes, with their working shown
    mitre      techniques and evidence-backed mappings
    alert      the deterministic verdict plus analyst workflow state
    incident   correlated groups of alerts
    ai         optional advisory analysis, structurally isolated
    analyst    notes and the immutable audit trail
"""

from app.models.ai import AIAnalysis, AIStatement
from app.models.alert import Alert, AlertSeverity, SeverityFactor
from app.models.analyst import AnalystNote, AuditEntry
from app.models.base import (
    MAX_LIST_ITEMS,
    MAX_RAW_EVENT_BYTES,
    MAX_TAGS,
    EvidenceModel,
    ObservedDatetime,
    SentinelModel,
    UtcDatetime,
    WorkflowModel,
    new_id,
    utcnow,
)
from app.models.detection import DetectionMatch, DetectionResult
from app.models.enums import (
    Actor,
    AlertStatus,
    AuditAction,
    Classification,
    Confidence,
    EventType,
    IncidentStatus,
    IndicatorType,
    Severity,
    StatementType,
)
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.mitre import MitreMapping, MitreTechnique

__all__ = [
    "MAX_LIST_ITEMS",
    "MAX_RAW_EVENT_BYTES",
    "MAX_TAGS",
    "AIAnalysis",
    "AIStatement",
    "Actor",
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "AnalystNote",
    "AuditAction",
    "AuditEntry",
    "Classification",
    "Confidence",
    "DetectionMatch",
    "DetectionResult",
    "EventType",
    "EvidenceModel",
    "Incident",
    "IncidentStatus",
    "Indicator",
    "IndicatorType",
    "MitreMapping",
    "MitreTechnique",
    "ObservedDatetime",
    "SecurityEvent",
    "SentinelModel",
    "Severity",
    "SeverityFactor",
    "StatementType",
    "UtcDatetime",
    "WorkflowModel",
    "new_id",
    "utcnow",
]
