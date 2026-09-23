"""Correlated groups of alerts.

Naming is doing real work here. Correlation produces a **potential** incident:
several related alerts that a human should look at together. SentinelFlow does
not declare a compromise, and the vocabulary in :class:`IncidentStatus` makes
the claim it is entitled to make and no more. Only an analyst moves an incident
to ``CONFIRMED``.
"""

from __future__ import annotations

from typing import Any, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import clean_line, clean_text, normalize_slug
from app.models.base import (
    MAX_LIST_ITEMS,
    MAX_TAGS,
    UtcDatetime,
    WorkflowModel,
    new_id,
    utcnow,
)
from app.models.enums import Classification, IncidentStatus, Severity


class Incident(WorkflowModel):
    """A group of alerts that correlation suggests belong together."""

    incident_id: UUID = Field(default_factory=new_id)
    created_at: UtcDatetime = Field(default_factory=utcnow)
    updated_at: UtcDatetime = Field(default_factory=utcnow)
    title: str = Field(max_length=256)

    status: IncidentStatus = IncidentStatus.POTENTIAL
    severity: Severity = Field(description="Highest severity among the member alerts.")
    classification: Classification | None = None

    alert_ids: list[UUID] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    correlation_key: str = Field(
        max_length=256, description="What links these alerts, e.g. 'hostname:win-lab-01'."
    )
    correlation_reasons: list[str] = Field(default_factory=list, max_length=32)

    first_event_at: UtcDatetime | None = None
    last_event_at: UtcDatetime | None = None
    hostnames: list[str] = Field(default_factory=list, max_length=64)
    usernames: list[str] = Field(default_factory=list, max_length=64)

    summary: str | None = Field(default=None, max_length=4_096)
    assigned_to: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)

    @field_validator("title", "correlation_key", mode="before")
    @classmethod
    def _require_line(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("title and correlation_key are required")
        return text

    @field_validator("summary", mode="before")
    @classmethod
    def _clean_summary(cls, value: Any) -> str | None:
        return clean_text(value, max_length=4_096)

    @field_validator("assigned_to", mode="before")
    @classmethod
    def _clean_assignee(cls, value: Any) -> str | None:
        return clean_line(value, max_length=128)

    @field_validator("correlation_reasons", mode="before")
    @classmethod
    def _clean_reasons(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        cleaned = [clean_text(item, max_length=512) for item in value]
        return [item for item in cleaned if item]

    @field_validator("hostnames", "usernames", mode="before")
    @classmethod
    def _clean_names(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        result: dict[str, None] = {}
        for item in value:
            cleaned = clean_line(item, max_length=256)
            if cleaned:
                result.setdefault(cleaned.lower(), None)
        return list(result)

    @field_validator("tags", mode="before")
    @classmethod
    def _clean_tags(cls, value: Any) -> list[str]:
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
    def _timeline_is_ordered(self) -> Self:
        if self.first_event_at and self.last_event_at and self.last_event_at < self.first_event_at:
            raise ValueError("last_event_at cannot be earlier than first_event_at")
        return self

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)

    @property
    def is_confirmed(self) -> bool:
        """True only after an analyst confirmed it. Never set automatically."""
        return self.status is IncidentStatus.CONFIRMED

    @property
    def display_label(self) -> str:
        """How the incident is described in the UI before a human has ruled on it."""
        if self.status is IncidentStatus.POTENTIAL:
            return "Potential Incident"
        return self.status.value.replace("_", " ").title()

    def touch(self) -> None:
        self.updated_at = utcnow()
