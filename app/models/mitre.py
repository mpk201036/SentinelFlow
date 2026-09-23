"""MITRE ATT&CK techniques and evidence-backed mappings.

The rule this module enforces in code: **a mapping must carry a reason**.

It is trivially easy to decorate an alert with plausible-looking technique IDs
and it makes a tool look sophisticated. It is also how analysts learn to
distrust a tool. ``MitreMapping.reason`` is mandatory and non-trivial in
length, so every technique shown to an analyst can answer "why is this here?"
with something that was written when the mapping was made.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field, field_validator

from app.core.sanitize import clean_line, clean_text
from app.models.base import EvidenceModel
from app.models.enums import Confidence

#: e.g. T1059 (technique) or T1059.001 (sub-technique)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

ATTACK_BASE_URL = "https://attack.mitre.org/techniques"


class MitreTechnique(EvidenceModel):
    """A technique from the ATT&CK Enterprise matrix."""

    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list, max_length=16)
    description: str | None = None

    @field_validator("technique_id", mode="before")
    @classmethod
    def _validate_technique_id(cls, value: Any) -> str:
        text = (clean_line(value, max_length=16) or "").upper()
        if not TECHNIQUE_ID_RE.match(text):
            raise ValueError(f"not a valid ATT&CK technique ID: {text!r}")
        return text

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("technique name is required")
        return text

    @field_validator("tactics", mode="before")
    @classmethod
    def _clean_tactics(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        cleaned = [clean_line(item, max_length=64) for item in value]
        return [item for item in cleaned if item]

    @field_validator("description", mode="before")
    @classmethod
    def _clean_description(cls, value: Any) -> str | None:
        return clean_text(value, max_length=2_048)

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique_id

    @property
    def parent_id(self) -> str:
        """Parent technique ID; identical to ``technique_id`` for a base technique."""
        return self.technique_id.split(".", 1)[0]

    @property
    def url(self) -> str:
        """Canonical ATT&CK page for this technique."""
        path = self.technique_id.replace(".", "/")
        return f"{ATTACK_BASE_URL}/{path}/"


class MitreMapping(EvidenceModel):
    """A technique attached to an alert, together with the evidence for it."""

    technique: MitreTechnique
    reason: str = Field(
        min_length=10,
        max_length=1_024,
        description="Why this technique applies, referencing what was observed.",
    )
    source_rule_id: str | None = Field(
        default=None, description="Detection rule that produced this mapping."
    )
    confidence: Confidence = Confidence.MEDIUM

    @field_validator("reason", mode="before")
    @classmethod
    def _clean_reason(cls, value: Any) -> str:
        text = clean_text(value, max_length=1_024)
        if not text:
            raise ValueError("a MITRE mapping must state why it applies")
        return text

    @field_validator("source_rule_id", mode="before")
    @classmethod
    def _clean_rule_id(cls, value: Any) -> str | None:
        return clean_line(value, max_length=64)

    @property
    def technique_id(self) -> str:
        return self.technique.technique_id
