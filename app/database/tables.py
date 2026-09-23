"""ORM tables.

These are storage structures, kept deliberately separate from the Pydantic
domain models in ``app/models``. The separation costs a mapping layer and buys
two things: the API contract cannot drift into the database schema by accident,
and internal columns cannot leak into a response because someone added a field.

Three constraints in here are security controls rather than data hygiene:

* ``ai_analysis.is_advisory`` carries a ``CHECK`` constraint pinning it to
  true. The trust boundary is enforced by Pydantic, by the type system, and
  now by the database — an AI analysis that is not labelled advisory cannot be
  written, even by raw SQL.
* ``mitre_mappings.technique_id`` is a foreign key into the ATT&CK catalogue,
  so a technique that does not exist cannot be attached to an alert. Fabricated
  ATT&CK decoration is rejected by the schema.
* Every enum column is a ``VARCHAR`` with a ``CHECK`` constraint, so a status
  outside the controlled vocabulary is refused at the storage layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UtcDateTime, enum_column
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

# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------
SCHEMA_VERSION = 1


class SchemaVersion(Base):
    """One row per applied migration. The baseline schema is version 1."""

    __tablename__ = "schema_version"

    version: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    description: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


# ---------------------------------------------------------------------------
# Association tables
# ---------------------------------------------------------------------------
alert_events = sa.Table(
    "alert_events",
    Base.metadata,
    sa.Column(
        "alert_id", sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True
    ),
    sa.Column(
        "event_id", sa.Uuid, ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True
    ),
)

alert_indicators = sa.Table(
    "alert_indicators",
    Base.metadata,
    sa.Column(
        "alert_id", sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True
    ),
    sa.Column(
        "indicator_id",
        sa.Uuid,
        ForeignKey("indicators.indicator_id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

incident_alerts = sa.Table(
    "incident_alerts",
    Base.metadata,
    sa.Column(
        "incident_id",
        sa.Uuid,
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column(
        "alert_id", sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True
    ),
)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
class EventRow(Base):
    """A normalised observation. Never updated after insert."""

    __tablename__ = "events"
    __table_args__ = (
        sa.Index("ix_events_host_time", "hostname_key", "timestamp"),
        sa.Index("ix_events_user_time", "username_key", "timestamp"),
    )

    event_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)

    event_type: Mapped[EventType] = mapped_column(
        enum_column(EventType, "event_type"), nullable=False, index=True
    )
    event_type_raw: Mapped[str | None] = mapped_column(sa.String(256))

    hostname: Mapped[str | None] = mapped_column(sa.String(256))
    username: Mapped[str | None] = mapped_column(sa.String(256))
    # Lower-cased, domain-stripped keys are stored rather than computed at query
    # time so correlation can use an index instead of a full scan.
    hostname_key: Mapped[str | None] = mapped_column(sa.String(256), index=True)
    username_key: Mapped[str | None] = mapped_column(sa.String(256), index=True)

    src_ip: Mapped[str | None] = mapped_column(sa.String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(sa.String(64), index=True)
    src_port: Mapped[int | None] = mapped_column(sa.Integer)
    dst_port: Mapped[int | None] = mapped_column(sa.Integer)
    protocol: Mapped[str | None] = mapped_column(sa.String(32))

    process_name: Mapped[str | None] = mapped_column(sa.String(256))
    process_name_key: Mapped[str | None] = mapped_column(sa.String(256), index=True)
    parent_process: Mapped[str | None] = mapped_column(sa.String(256))
    process_id: Mapped[int | None] = mapped_column(sa.Integer)
    parent_process_id: Mapped[int | None] = mapped_column(sa.Integer)
    command_line: Mapped[str | None] = mapped_column(sa.Text)

    file_path: Mapped[str | None] = mapped_column(sa.String(2048))
    file_hash: Mapped[str | None] = mapped_column(sa.String(64), index=True)

    domain: Mapped[str | None] = mapped_column(sa.String(256), index=True)
    url: Mapped[str | None] = mapped_column(sa.String(2048))
    event_message: Mapped[str | None] = mapped_column(sa.Text)

    source_severity: Mapped[Severity | None] = mapped_column(
        enum_column(Severity, "source_severity")
    )
    source_confidence: Mapped[Confidence | None] = mapped_column(
        enum_column(Confidence, "source_confidence")
    )

    tags: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    raw_event: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)


# ---------------------------------------------------------------------------
# Detection rules (catalogue) and results
# ---------------------------------------------------------------------------
class DetectionRuleRow(Base):
    """The rule catalogue loaded from ``rules/*.yaml``. Populated in Stage 6."""

    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity, "rule_severity"), nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence, "rule_confidence"), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    recommendation: Mapped[str | None] = mapped_column(sa.Text)
    mitre_technique_ids: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    definition: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)
    source_path: Mapped[str | None] = mapped_column(sa.String(1024))
    loaded_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class DetectionRow(Base):
    """A rule matching an event. A snapshot: later rule edits never rewrite it."""

    __tablename__ = "detections"

    detection_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    alert_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("events.event_id", ondelete="SET NULL"), index=True
    )

    rule_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    rule_severity: Mapped[Severity] = mapped_column(
        enum_column(Severity, "detection_severity"), nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence, "detection_confidence"), nullable=False
    )
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    recommendation: Mapped[str | None] = mapped_column(sa.Text)
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    matched: Mapped[list[dict[str, Any]]] = mapped_column(sa.JSON, nullable=False, default=list)
    mitre_technique_ids: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)

    alert: Mapped[AlertRow] = relationship(back_populates="detections")


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------
class IndicatorRow(Base):
    """An extracted indicator. Unique per (type, value) so sightings accumulate."""

    __tablename__ = "indicators"
    __table_args__ = (sa.UniqueConstraint("indicator_type", "value"),)

    indicator_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    indicator_type: Mapped[IndicatorType] = mapped_column(
        enum_column(IndicatorType, "indicator_type"), nullable=False, index=True
    )
    value: Mapped[str] = mapped_column(sa.String(2048), nullable=False, index=True)
    source_event_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("events.event_id", ondelete="SET NULL")
    )
    source_field: Mapped[str | None] = mapped_column(sa.String(64))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    occurrences: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    alerts: Mapped[list[AlertRow]] = relationship(
        secondary=alert_indicators, back_populates="indicators"
    )


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
class MitreTechniqueRow(Base):
    """The ATT&CK catalogue. Loaded from ``data/mitre/`` in Stage 7."""

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    tactics: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    description: Mapped[str | None] = mapped_column(sa.Text)


class MitreMappingRow(Base):
    """A technique attached to an alert, with the evidence that justifies it."""

    __tablename__ = "mitre_mappings"
    __table_args__ = (sa.UniqueConstraint("alert_id", "technique_id", "source_rule_id"),)

    mapping_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    alert_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True
    )
    # A foreign key into the catalogue: a technique that does not exist cannot
    # be attached to an alert.
    technique_id: Mapped[str] = mapped_column(
        sa.String(16),
        ForeignKey("mitre_techniques.technique_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    reason: Mapped[str] = mapped_column(sa.Text, nullable=False)
    source_rule_id: Mapped[str | None] = mapped_column(sa.String(64))
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence, "mapping_confidence"), nullable=False
    )

    alert: Mapped[AlertRow] = relationship(back_populates="mitre_mappings")
    technique: Mapped[MitreTechniqueRow] = relationship(lazy="joined")


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class AlertRow(Base):
    """The deterministic verdict plus analyst workflow state."""

    __tablename__ = "alerts"
    __table_args__ = (sa.Index("ix_alerts_status_created", "status", "created_at"),)

    alert_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    title: Mapped[str] = mapped_column(sa.String(256), nullable=False)

    primary_event_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("events.event_id", ondelete="CASCADE"), nullable=False, index=True
    )

    # The verdict is stored decomposed rather than as an opaque blob, so the
    # score can be queried and the factors remain auditable.
    severity_score: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    severity_level: Mapped[Severity] = mapped_column(
        enum_column(Severity, "alert_severity"), nullable=False, index=True
    )
    severity_factors: Mapped[list[dict[str, Any]]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    severity_method: Mapped[str] = mapped_column(
        sa.String(32), nullable=False, default="deterministic"
    )
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence, "alert_confidence"), nullable=False
    )

    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"), nullable=False, index=True
    )
    classification: Mapped[Classification | None] = mapped_column(
        enum_column(Classification, "alert_classification")
    )
    assigned_to: Mapped[str | None] = mapped_column(sa.String(128))
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    incident_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("incidents.incident_id", ondelete="SET NULL"), index=True
    )
    tags: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)

    primary_event: Mapped[EventRow] = relationship(foreign_keys=[primary_event_id], lazy="joined")
    events: Mapped[list[EventRow]] = relationship(secondary=alert_events)
    detections: Mapped[list[DetectionRow]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    indicators: Mapped[list[IndicatorRow]] = relationship(
        secondary=alert_indicators, back_populates="alerts"
    )
    mitre_mappings: Mapped[list[MitreMappingRow]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    notes: Mapped[list[AnalystNoteRow]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[list[AIAnalysisRow]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    incident: Mapped[IncidentRow | None] = relationship(back_populates="alerts")


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class IncidentRow(Base):
    """A correlated group of alerts. Starts as POTENTIAL, never as confirmed."""

    __tablename__ = "incidents"

    incident_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    title: Mapped[str] = mapped_column(sa.String(256), nullable=False)

    status: Mapped[IncidentStatus] = mapped_column(
        enum_column(IncidentStatus, "incident_status"), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity, "incident_severity"), nullable=False, index=True
    )
    classification: Mapped[Classification | None] = mapped_column(
        enum_column(Classification, "incident_classification")
    )

    correlation_key: Mapped[str] = mapped_column(sa.String(256), nullable=False, index=True)
    correlation_reasons: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    first_event_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_event_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    hostnames: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    usernames: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)

    summary: Mapped[str | None] = mapped_column(sa.Text)
    assigned_to: Mapped[str | None] = mapped_column(sa.String(128))
    tags: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)

    alerts: Mapped[list[AlertRow]] = relationship(back_populates="incident")
    members: Mapped[list[AlertRow]] = relationship(secondary=incident_alerts, viewonly=True)
    notes: Mapped[list[AnalystNoteRow]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# Optional AI analysis - isolated by design
# ---------------------------------------------------------------------------
class AIAnalysisRow(Base):
    """Advisory model output. Separate table, separate lifecycle, always labelled.

    Nothing in the deterministic pipeline reads this table. Deleting every row
    in it changes no alert's severity, no detection and no MITRE mapping.
    """

    __tablename__ = "ai_analysis"
    __table_args__ = (
        # The label is not a convention the application must remember.
        sa.CheckConstraint("is_advisory = 1", name="ai_output_is_always_advisory"),
    )

    analysis_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    alert_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    model: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(sa.Integer)
    prompt_version: Mapped[str | None] = mapped_column(sa.String(32))

    summary: Mapped[str] = mapped_column(sa.Text, nullable=False)
    suspicious_observations: Mapped[list[str]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    possible_explanations: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    analyst_questions: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    recommended_next_steps: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)

    # Deliberately NOT named `severity`. This is an opinion, stored beside the
    # verdict, never in place of it.
    suggested_severity: Mapped[Severity | None] = mapped_column(
        enum_column(Severity, "ai_suggested_severity")
    )
    suggested_severity_rationale: Mapped[str | None] = mapped_column(sa.Text)

    is_advisory: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    injection_suspected: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    truncated: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    alert: Mapped[AlertRow] = relationship(back_populates="ai_analyses")
    statements: Mapped[list[AIStatementRow]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", order_by="AIStatementRow.position"
    )


class AIStatementRow(Base):
    """One labelled claim from a model. The label is not optional."""

    __tablename__ = "ai_statements"

    statement_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    analysis_id: Mapped[UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("ai_analysis.analysis_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    position: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    statement_type: Mapped[StatementType] = mapped_column(
        enum_column(StatementType, "statement_type"), nullable=False
    )
    text: Mapped[str] = mapped_column(sa.Text, nullable=False)

    analysis: Mapped[AIAnalysisRow] = relationship(back_populates="statements")


# ---------------------------------------------------------------------------
# Analyst workflow
# ---------------------------------------------------------------------------
class AnalystNoteRow(Base):
    """A human's note on an alert or an incident."""

    __tablename__ = "analyst_notes"

    note_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    author: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)
    alert_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("alerts.alert_id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )

    alert: Mapped[AlertRow | None] = relationship(back_populates="notes")
    incident: Mapped[IncidentRow | None] = relationship(back_populates="notes")


class AuditLogRow(Base):
    """Append-only record of everything that happened. Never updated or deleted."""

    __tablename__ = "audit_log"
    __table_args__ = (sa.Index("ix_audit_object", "object_type", "object_id"),)

    entry_id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    actor: Mapped[Actor] = mapped_column(enum_column(Actor, "audit_actor"), nullable=False)
    actor_name: Mapped[str | None] = mapped_column(sa.String(128))
    action: Mapped[AuditAction] = mapped_column(
        enum_column(AuditAction, "audit_action"), nullable=False
    )
    object_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    # Intentionally not a foreign key: the trail must survive the deletion of
    # whatever it describes.
    object_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    before: Mapped[str | None] = mapped_column(sa.String(512))
    after: Mapped[str | None] = mapped_column(sa.String(512))
    detail: Mapped[str | None] = mapped_column(sa.Text)


#: Every table, in dependency order. Used by init and by the integrity checks.
ALL_TABLES = [
    "schema_version",
    "events",
    "incidents",
    "alerts",
    "alert_events",
    "detection_rules",
    "detections",
    "indicators",
    "alert_indicators",
    "incident_alerts",
    "mitre_techniques",
    "mitre_mappings",
    "ai_analysis",
    "ai_statements",
    "analyst_notes",
    "audit_log",
]
