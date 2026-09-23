"""Alerts — the deterministic verdict, plus the analyst's workflow state.

The severity of an alert is not a bare enum on this model. It is an
:class:`AlertSeverity` object that carries the score, the band and the list of
factors that produced it. That is a deliberate structural choice:

* an analyst can always see *how* a severity was arrived at; and
* an AI suggestion (which is a bare :class:`~app.models.enums.Severity`) is the
  wrong type to assign here, so the trust boundary is enforced by the type
  system rather than by everyone remembering a convention.

``Alert`` is mutable, because status, classification and assignment genuinely
change as an analyst works. Every one of those changes is recorded in the audit
log (see :mod:`app.models.analyst`).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import clean_line, clean_text, normalize_slug
from app.models.base import (
    MAX_LIST_ITEMS,
    MAX_TAGS,
    EvidenceModel,
    UtcDatetime,
    WorkflowModel,
    new_id,
    utcnow,
)
from app.models.detection import DetectionResult
from app.models.enums import AlertStatus, Classification, Confidence, Severity
from app.models.indicator import Indicator
from app.models.mitre import MitreMapping


class SeverityFactor(EvidenceModel):
    """One contribution to an alert's risk score."""

    name: str = Field(max_length=64, description="Short identifier, e.g. 'privileged_user'.")
    points: int = Field(ge=-100, le=100)
    detail: str = Field(max_length=512, description="Why this factor applied.")

    @field_validator("name", mode="before")
    @classmethod
    def _slug(cls, value: Any) -> str:
        return normalize_slug(value)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: Any) -> str:
        text = clean_text(value, max_length=512)
        if not text:
            raise ValueError("a severity factor must explain itself")
        return text


class AlertSeverity(EvidenceModel):
    """A deterministic severity verdict with its working shown.

    ``method`` is a constant. It exists so that the provenance of a severity
    survives serialisation into the database, the API and the report — there is
    no way to store a severity here without it being labelled deterministic,
    and no AI-produced value can ever occupy this field.
    """

    score: int = Field(ge=0, le=100)
    level: Severity
    factors: list[SeverityFactor] = Field(default_factory=list, max_length=64)
    method: Literal["deterministic"] = "deterministic"

    @model_validator(mode="after")
    def _level_matches_score(self) -> Self:
        expected = Severity.from_score(self.score)
        if self.level is not expected:
            raise ValueError(
                f"severity level {self.level.value!r} does not match score {self.score} "
                f"(expected {expected.value!r})"
            )
        return self

    @classmethod
    def from_factors(cls, factors: Iterable[SeverityFactor]) -> AlertSeverity:
        """Build a verdict by summing factors and clamping to 0-100."""
        items = list(factors)
        score = max(0, min(100, sum(factor.points for factor in items)))
        return cls(score=score, level=Severity.from_score(score), factors=items)

    def explain(self) -> str:
        """Plain-English account of the score."""
        if not self.factors:
            return f"Score {self.score}/100 ({self.level.value}) with no recorded factors."
        lines = [f"{factor.detail} ({factor.points:+d})" for factor in self.factors]
        return f"Score {self.score}/100 ({self.level.value}): " + "; ".join(lines)


class Alert(WorkflowModel):
    """A detection outcome presented to an analyst for triage."""

    # --- Identity -------------------------------------------------------
    alert_id: UUID = Field(default_factory=new_id)
    created_at: UtcDatetime = Field(default_factory=utcnow)
    updated_at: UtcDatetime = Field(default_factory=utcnow)
    title: str = Field(max_length=256)

    # --- Evidence -------------------------------------------------------
    primary_event_id: UUID
    event_ids: list[UUID] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)

    # --- Deterministic analysis ----------------------------------------
    severity: AlertSeverity
    confidence: Confidence = Confidence.MEDIUM
    detections: list[DetectionResult] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    indicators: list[Indicator] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    mitre: list[MitreMapping] = Field(default_factory=list, max_length=32)

    # --- Analyst workflow ----------------------------------------------
    status: AlertStatus = AlertStatus.NEW
    classification: Classification | None = None
    assigned_to: str | None = Field(default=None, max_length=128)
    closed_at: UtcDatetime | None = None

    # --- Grouping -------------------------------------------------------
    incident_id: UUID | None = None
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)

    @field_validator("title", mode="before")
    @classmethod
    def _validate_title(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("an alert must have a title")
        return text

    @field_validator("assigned_to", mode="before")
    @classmethod
    def _clean_assignee(cls, value: Any) -> str | None:
        return clean_line(value, max_length=128)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalise_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        result: dict[str, None] = {}
        for item in value:
            try:
                result.setdefault(normalize_slug(item), None)
            except ValueError:
                continue
        return list(result)[:MAX_TAGS]

    @model_validator(mode="after")
    def _primary_event_is_included(self) -> Self:
        if self.primary_event_id not in self.event_ids:
            self.event_ids.insert(0, self.primary_event_id)
        return self

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------
    @property
    def severity_level(self) -> Severity:
        """The deterministic severity band. Never influenced by AI output."""
        return self.severity.level

    @property
    def is_open(self) -> bool:
        return self.status.is_open

    @property
    def rule_ids(self) -> list[str]:
        return [detection.rule_id for detection in self.detections]

    @property
    def technique_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for mapping in self.mitre:
            seen.setdefault(mapping.technique_id, None)
        return list(seen)

    def touch(self) -> None:
        """Record that the alert changed."""
        self.updated_at = utcnow()
