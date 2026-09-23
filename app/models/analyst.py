"""Analyst notes and the audit trail.

Both models are frozen. A note records what someone thought at a point in time,
and an audit entry records that something happened; neither is a mutable
opinion that gets edited later. Corrections are new records.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import clean_line, clean_text
from app.models.base import EvidenceModel, UtcDatetime, new_id, utcnow
from app.models.enums import Actor, AuditAction

MAX_NOTE_LENGTH = 8_192


class AnalystNote(EvidenceModel):
    """A free-text note attached to an alert or an incident."""

    note_id: UUID = Field(default_factory=new_id)
    created_at: UtcDatetime = Field(default_factory=utcnow)
    author: str = Field(max_length=128)
    body: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)
    alert_id: UUID | None = None
    incident_id: UUID | None = None

    @field_validator("author", mode="before")
    @classmethod
    def _clean_author(cls, value: Any) -> str:
        text = clean_line(value, max_length=128)
        if not text:
            raise ValueError("a note must record who wrote it")
        return text

    @field_validator("body", mode="before")
    @classmethod
    def _clean_body(cls, value: Any) -> str:
        text = clean_text(value, max_length=MAX_NOTE_LENGTH)
        if not text:
            raise ValueError("a note cannot be empty")
        return text

    @model_validator(mode="after")
    def _must_attach_to_something(self) -> AnalystNote:
        if self.alert_id is None and self.incident_id is None:
            raise ValueError("a note must reference an alert or an incident")
        return self


class AuditEntry(EvidenceModel):
    """One immutable record of something that happened.

    ``before`` and ``after`` capture state changes as plain strings so the trail
    stays readable without needing the rest of the database to interpret it.
    """

    entry_id: UUID = Field(default_factory=new_id)
    occurred_at: UtcDatetime = Field(default_factory=utcnow)
    actor: Actor = Actor.SYSTEM
    actor_name: str | None = Field(default=None, max_length=128)
    action: AuditAction
    object_type: str = Field(max_length=64, description="e.g. 'alert', 'incident'.")
    object_id: UUID | None = None
    before: str | None = Field(default=None, max_length=512)
    after: str | None = Field(default=None, max_length=512)
    detail: str | None = Field(default=None, max_length=1_024)

    @field_validator("object_type", mode="before")
    @classmethod
    def _clean_object_type(cls, value: Any) -> str:
        text = clean_line(value, max_length=64)
        if not text:
            raise ValueError("object_type is required")
        return text.lower()

    @field_validator("actor_name", "before", "after", mode="before")
    @classmethod
    def _clean_short(cls, value: Any) -> str | None:
        return clean_line(value, max_length=512)

    @field_validator("detail", mode="before")
    @classmethod
    def _clean_detail(cls, value: Any) -> str | None:
        return clean_text(value, max_length=1_024)

    def describe(self) -> str:
        """One-line rendering for the audit view."""
        who = self.actor_name or self.actor.value
        change = f" ({self.before} -> {self.after})" if self.before or self.after else ""
        return (
            f"{self.occurred_at.isoformat()} {who} {self.action.value} {self.object_type}{change}"
        )
