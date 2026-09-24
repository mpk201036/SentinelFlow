"""The HTTP contract.

These models are deliberately separate from the domain models in ``app/models``.
The domain models describe what SentinelFlow knows; these describe what it
promises to return. Keeping them apart means adding an internal field cannot
silently change an API response, and it makes the surface an attacker sees an
explicit, reviewable list.

Two properties of the responses matter more than convenience:

* **Severity always travels with its provenance.** An alert's severity is
  returned as an object carrying the score, the band, the contributing factors
  and ``method: "deterministic"``. There is no representation in which a
  severity appears as a bare string with no indication of where it came from.
* **AI output is never inlined into an alert.** It has its own field, its own
  shape, and an ``is_advisory`` flag that cannot be false.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    AlertStatus,
    Classification,
    Confidence,
    EventType,
    IncidentStatus,
    IndicatorType,
    Severity,
)

#: Pagination bounds. The default is small because a triage queue is read by a
#: human, and the maximum is bounded so one request cannot ask for everything.
DEFAULT_PAGE_SIZE = 50


class ApiModel(BaseModel):
    """Base for every response model."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class Page[T](ApiModel):
    """A bounded slice of a collection."""

    items: list[T]
    total: int = Field(description="Total matching records, ignoring pagination.")
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
class EventSummary(ApiModel):
    """An event as it appears in a list."""

    event_id: UUID
    timestamp: datetime
    source: str
    event_type: EventType
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_message: str | None = None


class EventDetail(EventSummary):
    """A single event, including the untouched original record."""

    received_at: datetime
    event_type_raw: str | None = None
    parent_process: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    command_line: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    source_severity: Severity | None = Field(
        default=None, description="Severity claimed by the source. Advisory, never the verdict."
    )
    source_confidence: Confidence | None = None
    tags: list[str] = Field(default_factory=list)
    raw_event: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detections, indicators, ATT&CK
# ---------------------------------------------------------------------------
class DetectionMatchOut(ApiModel):
    field_name: str
    condition: str
    observed_value: str | None = None


class DetectionOut(ApiModel):
    """A rule that matched, with the evidence that caused it."""

    detection_id: UUID
    rule_id: str
    rule_name: str
    rule_severity: Severity
    confidence: Confidence
    description: str
    recommendation: str | None = None
    detected_at: datetime
    matched: list[DetectionMatchOut] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)


class IndicatorOut(ApiModel):
    indicator_id: UUID
    indicator_type: IndicatorType
    value: str
    source_field: str | None = None
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    is_internal: bool = Field(description="On a private, loopback or link-local network.")
    is_documentation: bool = Field(description="In a reserved documentation range.")


class TechniqueOut(ApiModel):
    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    description: str | None = None
    url: str


class MitreMappingOut(ApiModel):
    """A technique attached to an alert, with the evidence for it."""

    technique: TechniqueOut
    reason: str = Field(description="Why this technique applies, drawn from what was observed.")
    source_rule_id: str | None = None
    confidence: Confidence


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
class SeverityFactorOut(ApiModel):
    name: str
    points: int
    detail: str


class SeverityOut(ApiModel):
    """A severity verdict that always carries its provenance."""

    score: int
    level: Severity
    method: str = Field(description='Always "deterministic". AI output cannot occupy this field.')
    factors: list[SeverityFactorOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class AlertSummary(ApiModel):
    alert_id: UUID
    created_at: datetime
    title: str
    severity: SeverityOut
    confidence: Confidence
    status: AlertStatus
    classification: Classification | None = None
    incident_id: UUID | None = None
    rule_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)


class AIStatementOut(ApiModel):
    statement_type: str
    text: str
    downgraded: bool = Field(
        default=False,
        description=(
            "Set by SentinelFlow: the model said observed, but the statement cites something "
            "the evidence does not contain."
        ),
    )


class AIAnalysisOut(ApiModel):
    """Advisory model output. Separate field, separate shape, always labelled."""

    analysis_id: UUID
    generated_at: datetime
    provider: str
    model: str
    duration_ms: int | None = None
    prompt_version: str | None = None
    summary: str
    statements: list[AIStatementOut] = Field(default_factory=list)
    suspicious_observations: list[str] = Field(default_factory=list)
    possible_explanations: list[str] = Field(default_factory=list)
    analyst_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    suggested_severity: Severity | None = Field(
        default=None,
        description="The model's opinion. Never copied into the alert's severity.",
    )
    suggested_severity_rationale: str | None = None
    is_advisory: bool = Field(description="Always true. AI output is never authoritative.")
    injection_suspected: bool
    truncated: bool
    injection_signals: list[str] = Field(
        default_factory=list,
        description="Written by SentinelFlow: text in the evidence that addressed the model.",
    )
    grounding_notes: list[str] = Field(
        default_factory=list,
        description="Written by SentinelFlow: claims it could not match to the evidence.",
    )
    disclaimer: str


class AIStatusOut(ApiModel):
    """Whether AI analysis is available, and if not, why not."""

    enabled: bool
    provider: str
    model: str | None = None
    endpoint: str | None = None
    local: bool | None = Field(default=None, description="True when the provider is loopback.")
    reachable: bool = False
    model_installed: bool = False
    version: str | None = None
    installed_models: list[str] = Field(default_factory=list)
    prompt_version: str
    problem: str | None = None


class AlertDetail(AlertSummary):
    """Everything an analyst needs to triage one alert."""

    updated_at: datetime
    primary_event: EventDetail | None = None
    detections: list[DetectionOut] = Field(default_factory=list)
    indicators: list[IndicatorOut] = Field(default_factory=list)
    mitre: list[MitreMappingOut] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    assigned_to: str | None = None
    closed_at: datetime | None = None
    notes: list[AnalystNoteOut] = Field(default_factory=list)
    ai_analysis: list[AIAnalysisOut] = Field(
        default_factory=list,
        description="Advisory only. Absent unless AI is explicitly enabled.",
    )


class AnalystNoteOut(ApiModel):
    note_id: UUID
    created_at: datetime
    author: str
    body: str


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class IncidentSummary(ApiModel):
    incident_id: UUID
    created_at: datetime
    title: str
    status: IncidentStatus
    display_label: str = Field(description='"Potential Incident" until an analyst confirms it.')
    severity: Severity = Field(description="Highest severity among the member alerts.")
    alert_count: int
    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None


class IncidentDetail(IncidentSummary):
    updated_at: datetime
    classification: Classification | None = None
    correlation_key: str
    correlation_reasons: list[str] = Field(default_factory=list)
    summary: str | None = None
    alerts: list[AlertSummary] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
class RuleOut(ApiModel):
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence
    enabled: bool
    kind: str = Field(description='"match" or "threshold".')
    mitre: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    recommendation: str | None = None
    false_positives: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
class IngestRequest(ApiModel):
    """A batch of events to ingest.

    ``source`` names the adapter. Leaving it out asks SentinelFlow to detect
    the format, which it will refuse to guess at rather than mislabel.
    """

    events: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=10_000,
        description="Records in the named source's own format.",
    )
    source: str | None = Field(
        default=None, max_length=64, description="Adapter name, e.g. sysmon. Detected if omitted."
    )
    triage: bool = Field(
        default=True, description="Run detection and scoring on the accepted events."
    )
    force: bool = Field(
        default=False,
        description=(
            "Accept this batch even if identical content was already ingested. Off by "
            "default: an identical batch is almost always a retry, and accepting it would "
            "double every event. Use it for sources whose timestamps are too coarse to "
            "tell a genuine repeat from a retry."
        ),
    )


class RejectionOut(ApiModel):
    index: int
    reason: str
    detail: str


class IngestResponse(ApiModel):
    """What an ingestion request produced. The counts always add up."""

    batch_id: UUID
    adapter: str
    accepted: int
    rejected: int
    duplicate_batch: bool = Field(description="True when this exact content was already imported.")
    event_ids: list[UUID] = Field(default_factory=list)
    rejections: list[RejectionOut] = Field(default_factory=list)
    alerts_created: int = 0
    duration_ms: int | None = None


# ---------------------------------------------------------------------------
# Operations and status
# ---------------------------------------------------------------------------
class TriageResponse(ApiModel):
    events_processed: int
    indicators_found: int
    detections: int
    alerts_created: int
    severity_counts: dict[str, int] = Field(default_factory=dict)


class CorrelateResponse(ApiModel):
    alerts_considered: int
    incidents_created: int
    incidents_extended: int
    standalone_alerts: int


class HealthResponse(ApiModel):
    status: str
    version: str
    environment: str
    database: str
    schema_version: int
    ai_enabled: bool = Field(description="False by default; the pipeline does not require it.")


class StatsResponse(ApiModel):
    """Counts for the dashboard."""

    events: int
    alerts: int
    alerts_open: int
    incidents: int
    indicators: int
    rejected_events: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)
    top_rules: dict[str, int] = Field(default_factory=dict)
    top_hosts: dict[str, int] = Field(default_factory=dict)
    techniques_observed: list[str] = Field(default_factory=list)


class ErrorResponse(ApiModel):
    """A failure, described without leaking internals."""

    error: str
    detail: str | None = None
    request_id: str | None = None


AlertDetail.model_rebuild()
