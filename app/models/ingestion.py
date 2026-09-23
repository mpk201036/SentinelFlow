"""Results of an import.

Ingestion is the one place where SentinelFlow routinely handles data that is
wrong — truncated exports, fields a source stopped populating, hand-edited CSV,
and occasionally something deliberately malformed. The design decision recorded
in these models is that **a bad record is reported, not discarded and not
allowed to abort the batch**.

Importing 5,000 events and silently keeping 4,988 is how an analyst ends up
investigating a gap that does not exist. Every rejection is counted, given a
reason, and kept with enough of the original to diagnose.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.sanitize import clean_text
from app.models.base import EvidenceModel, SentinelModel, UtcDatetime, new_id, utcnow

#: How much of a rejected record is retained for diagnosis.
MAX_REJECTED_PAYLOAD = 2_048


class RejectionReason(StrEnum):
    """Why a record did not become an event."""

    MALFORMED_JSON = "malformed_json"
    MALFORMED_CSV = "malformed_csv"
    NOT_AN_OBJECT = "not_an_object"
    SCHEMA_VALIDATION = "schema_validation"
    ADAPTER_ERROR = "adapter_error"
    UNKNOWN_SOURCE = "unknown_source"
    NESTING_TOO_DEEP = "nesting_too_deep"
    LIMIT_EXCEEDED = "limit_exceeded"
    EMPTY_RECORD = "empty_record"


class RejectedRecord(EvidenceModel):
    """One record that could not be turned into a :class:`SecurityEvent`."""

    record_id: UUID = Field(default_factory=new_id)
    rejected_at: UtcDatetime = Field(default_factory=utcnow)
    index: int = Field(ge=0, description="Position within the import, 0-based.")
    reason: RejectionReason
    detail: str = Field(max_length=2_048, description="What specifically was wrong.")
    payload: str | None = Field(
        default=None, max_length=MAX_REJECTED_PAYLOAD + 64, description="The original record."
    )
    origin: str | None = Field(default=None, max_length=512)
    adapter: str | None = Field(default=None, max_length=64)

    @field_validator("detail", mode="before")
    @classmethod
    def _clean_detail(cls, value: Any) -> str:
        text = clean_text(value, max_length=2_048)
        return text or "no detail recorded"

    @field_validator("payload", mode="before")
    @classmethod
    def _clean_payload(cls, value: Any) -> str | None:
        return clean_text(value, max_length=MAX_REJECTED_PAYLOAD)


class IngestionReport(SentinelModel):
    """Summary of one import, returned by the API and printed by the CLI."""

    batch_id: UUID = Field(default_factory=new_id)
    origin: str = Field(max_length=512, description="File name, 'api' or 'generator'.")
    adapter: str = Field(max_length=64, description="Adapter that normalised the records.")
    started_at: UtcDatetime = Field(default_factory=utcnow)
    finished_at: UtcDatetime | None = None

    accepted: int = Field(default=0, ge=0)
    rejected: int = Field(default=0, ge=0)
    event_ids: list[UUID] = Field(default_factory=list)
    rejections: list[RejectedRecord] = Field(default_factory=list)

    duplicate_batch: bool = Field(
        default=False, description="True when this exact content was already imported."
    )
    content_hash: str | None = Field(default=None, max_length=64)

    @property
    def total(self) -> int:
        return self.accepted + self.rejected

    @property
    def success_rate(self) -> float:
        return self.accepted / self.total if self.total else 1.0

    @property
    def duration_ms(self) -> int | None:
        if self.finished_at is None:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)

    def summary(self) -> str:
        if self.duplicate_batch:
            return f"{self.origin}: already imported, skipped (content hash {self.content_hash})"
        parts = [f"{self.origin}: {self.accepted} accepted"]
        if self.rejected:
            parts.append(f"{self.rejected} rejected")
        if self.duration_ms is not None:
            parts.append(f"{self.duration_ms} ms")
        return ", ".join(parts)

    def rejection_counts(self) -> dict[str, int]:
        """Rejections grouped by reason, for the CLI and the dashboard."""
        counts: dict[str, int] = {}
        for rejection in self.rejections:
            counts[rejection.reason.value] = counts.get(rejection.reason.value, 0) + 1
        return counts
