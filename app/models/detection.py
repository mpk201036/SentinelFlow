"""Results produced by the deterministic detection engine.

A detection result is a *reproducible* statement: given the same event and the
same rule, the same result is produced every time. That is what separates this
layer from the AI layer, and it is why every result carries the matched fields
that caused it to fire. An analyst can check the working.

The rule *definition* schema (the YAML on disk) belongs with the engine that
interprets it (``app/detection/schema.py``). What is modelled here is the engine's
output: a snapshot of the rule as it was when it matched, so that later edits
to a rule never rewrite the history of alerts it already produced.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.sanitize import clean_line, clean_text
from app.models.base import MAX_LIST_ITEMS, EvidenceModel, UtcDatetime, new_id, utcnow
from app.models.enums import Confidence, Severity

RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


class DetectionMatch(EvidenceModel):
    """One field-level condition that contributed to a rule firing."""

    field_name: str = Field(max_length=64)
    condition: str = Field(max_length=256, description="Human-readable test, e.g. 'contains -enc'.")
    observed_value: str | None = Field(
        default=None, max_length=1_024, description="The value that satisfied the condition."
    )

    @field_validator("field_name", "condition", mode="before")
    @classmethod
    def _require_text(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("field_name and condition are required")
        return text

    @field_validator("observed_value", mode="before")
    @classmethod
    def _clean_observed(cls, value: Any) -> str | None:
        return clean_text(value, max_length=1_024)

    def __str__(self) -> str:
        suffix = f" -> {self.observed_value}" if self.observed_value else ""
        return f"{self.field_name} {self.condition}{suffix}"


class DetectionResult(EvidenceModel):
    """A rule matched an event."""

    detection_id: UUID = Field(default_factory=new_id)
    rule_id: str
    rule_name: str = Field(max_length=256)
    rule_severity: Severity = Field(description="Severity declared by the rule itself.")
    confidence: Confidence = Confidence.MEDIUM
    description: str = Field(max_length=2_048)
    recommendation: str | None = Field(default=None, max_length=2_048)
    event_id: UUID | None = None
    detected_at: UtcDatetime = Field(default_factory=utcnow)
    matched: list[DetectionMatch] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    mitre_technique_ids: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("rule_id", mode="before")
    @classmethod
    def _validate_rule_id(cls, value: Any) -> str:
        text = clean_line(value, max_length=64) or ""
        if not RULE_ID_RE.match(text):
            raise ValueError(f"not a valid rule id: {text!r}")
        return text

    @field_validator("rule_name", mode="before")
    @classmethod
    def _validate_rule_name(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("rule_name is required")
        return text

    @field_validator("description", mode="before")
    @classmethod
    def _validate_description(cls, value: Any) -> str:
        text = clean_text(value, max_length=2_048)
        if not text:
            raise ValueError("description is required")
        return text

    @field_validator("recommendation", mode="before")
    @classmethod
    def _clean_recommendation(cls, value: Any) -> str | None:
        return clean_text(value, max_length=2_048)

    @field_validator("mitre_technique_ids", mode="before")
    @classmethod
    def _normalise_technique_ids(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        from app.models.mitre import TECHNIQUE_ID_RE

        result: list[str] = []
        for item in value:
            text = (clean_line(item, max_length=16) or "").upper()
            if not TECHNIQUE_ID_RE.match(text):
                raise ValueError(f"not a valid ATT&CK technique ID: {text!r}")
            if text not in result:
                result.append(text)
        return result

    def explain(self) -> str:
        """Plain-English account of why this rule fired."""
        if not self.matched:
            return f"{self.rule_name} ({self.rule_id}) matched."
        conditions = "; ".join(str(match) for match in self.matched)
        return f"{self.rule_name} ({self.rule_id}) matched because {conditions}."
