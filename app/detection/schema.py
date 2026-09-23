"""The rule definition language.

Rules live in ``rules/*.yaml`` as data. Adding a detection requires no Python
change, which is how detection engineering actually works: content and code
have different authors and different review cycles.

The language is deliberately small and explicit. It borrows Sigma's vocabulary
— ``contains``, ``startswith``, ``endswith``, ``re``, ``cidr`` — so the idiom is
familiar, but writes the operator out as a field rather than encoding it in the
key (``field|contains:``). Sigma's modifier syntax is more compact; an explicit
operator is easier to validate, easier to report on when it fails, and easier
for someone who has never seen Sigma to read. A Sigma importer that emits this
format is a natural extension rather than a rewrite.

Two validation choices are worth stating:

* **Field names are checked against the event schema at load time.** A typo in
  a field name would otherwise produce a rule that quietly never fires, which
  is the worst possible failure for a detection: it looks like coverage.
* **Regular expressions compile at load time.** A broken pattern fails at
  startup with the file name attached, not halfway through a triage.
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import clean_line, clean_text
from app.detection.operators import (
    NUMERIC_OPERATORS,
    OPERATORS,
    REGEX_OPERATORS,
    compile_pattern,
)
from app.models.base import SentinelModel
from app.models.detection import RULE_ID_RE
from app.models.enums import Confidence, EventType, Severity
from app.models.event import SecurityEvent
from app.models.mitre import TECHNIQUE_ID_RE

#: Derived properties a rule may reference alongside the stored fields.
DERIVED_FIELDS = frozenset(
    {"hostname_key", "username_key", "process_name_key", "file_hash_algorithm"}
)

#: Every field name a rule may use. Anything else is a typo.
KNOWN_FIELDS = frozenset(SecurityEvent.model_fields) | DERIVED_FIELDS

#: Prefix for reaching into the untouched original record.
RAW_PREFIX = "raw_event."


class Condition(SentinelModel):
    """One field test."""

    field_name: str = Field(alias="field", max_length=128)
    operator: str = Field(max_length=32)
    value: Any = None
    ignore_case: bool = True
    label: str | None = Field(default=None, max_length=256)

    @field_validator("field_name", mode="before")
    @classmethod
    def _validate_field(cls, value: Any) -> str:
        name = (clean_line(value, max_length=128) or "").strip()
        if not name:
            raise ValueError("a condition must name a field")
        if name.startswith(RAW_PREFIX):
            if len(name) <= len(RAW_PREFIX):
                raise ValueError("raw_event. must be followed by a key name")
            return name
        if name not in KNOWN_FIELDS:
            raise ValueError(
                f"unknown event field {name!r}. Known fields: "
                f"{', '.join(sorted(KNOWN_FIELDS))}, or raw_event.<key>"
            )
        return name

    @field_validator("operator", mode="before")
    @classmethod
    def _validate_operator(cls, value: Any) -> str:
        name = (clean_line(value, max_length=32) or "").strip().lower()
        if name not in OPERATORS:
            raise ValueError(
                f"unknown operator {name!r}. Available: {', '.join(sorted(OPERATORS))}"
            )
        return name

    @model_validator(mode="after")
    def _validate_argument(self) -> Self:
        """Fail at load time on an argument the operator cannot use."""
        if self.operator in REGEX_OPERATORS:
            patterns = self.value if isinstance(self.value, list) else [self.value]
            for pattern in patterns:
                compile_pattern(pattern, ignore_case=self.ignore_case)
        elif self.operator in NUMERIC_OPERATORS:
            try:
                float(self.value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"operator {self.operator!r} needs a number, got {self.value!r}"
                ) from exc
        elif self.operator not in ("exists", "is_private") and self.value is None:
            raise ValueError(f"operator {self.operator!r} needs a value")
        return self

    def describe(self) -> str:
        """Human-readable form, used in the evidence shown to an analyst."""
        if self.label:
            return self.label
        if self.operator == "exists":
            return "is present" if self.value in (None, True) else "is absent"
        rendered = (
            ", ".join(str(item) for item in self.value)
            if isinstance(self.value, list)
            else str(self.value)
        )
        return f"{self.operator.replace('_', ' ')} {rendered}"


class Logic(SentinelModel):
    """How a rule's conditions combine.

    ``all`` must match, at least one of ``any`` must match, and none of ``none``
    may match. ``none`` exists because most real rules are "this pattern, except
    when it is our own tooling", and an exclusion list is far more readable than
    a negated operator buried among the positives.
    """

    event_types: list[EventType] = Field(default_factory=list, max_length=32)
    all_of: list[Condition] = Field(default_factory=list, alias="all", max_length=32)
    any_of: list[Condition] = Field(default_factory=list, alias="any", max_length=32)
    none_of: list[Condition] = Field(default_factory=list, alias="none", max_length=32)

    @model_validator(mode="after")
    def _must_test_something(self) -> Self:
        if not (self.all_of or self.any_of or self.event_types):
            raise ValueError(
                "a rule must test something: give event_types, all, or any. "
                "A rule with only exclusions would match every event."
            )
        return self


class Threshold(SentinelModel):
    """Counting across events, for rules a single event cannot express.

    "Five failed logons for one account within ten minutes" is not a property of
    any single event, so these rules are evaluated over a sequence.
    """

    count: int = Field(ge=2, le=10_000)
    within_minutes: int = Field(ge=1, le=1_440)
    group_by: list[str] = Field(min_length=1, max_length=4)

    @field_validator("group_by")
    @classmethod
    def _validate_group_by(cls, value: list[str]) -> list[str]:
        for name in value:
            if name not in KNOWN_FIELDS:
                raise ValueError(f"cannot group by unknown field {name!r}")
        return value

    def describe(self) -> str:
        keys = " and ".join(name.removesuffix("_key") for name in self.group_by)
        return f"{self.count} or more within {self.within_minutes} minutes, grouped by {keys}"


class RuleDefinition(SentinelModel):
    """A complete detection rule, as loaded from YAML."""

    rule_id: str = Field(alias="id", max_length=64)
    name: str = Field(max_length=256)
    description: str = Field(max_length=4_096)
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    enabled: bool = True

    detection: Logic
    threshold: Threshold | None = None

    mitre: list[str] = Field(default_factory=list, max_length=16)
    tags: list[str] = Field(default_factory=list, max_length=16)
    recommendation: str | None = Field(default=None, max_length=4_096)
    false_positives: list[str] = Field(default_factory=list, max_length=16)
    references: list[str] = Field(default_factory=list, max_length=16)
    author: str | None = Field(default=None, max_length=128)

    #: Set by the loader, not by the file.
    source_path: str | None = Field(default=None, max_length=1_024)

    @field_validator("rule_id", mode="before")
    @classmethod
    def _validate_id(cls, value: Any) -> str:
        text = (clean_line(value, max_length=64) or "").strip()
        if not RULE_ID_RE.match(text):
            raise ValueError(f"not a valid rule id: {text!r}")
        return text

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: Any) -> str:
        text = clean_line(value, max_length=256)
        if not text:
            raise ValueError("a rule must have a name")
        return text

    @field_validator("description", mode="before")
    @classmethod
    def _validate_description(cls, value: Any) -> str:
        text = clean_text(value, max_length=4_096)
        if not text or len(text) < 20:
            raise ValueError(
                "a rule needs a description an analyst can act on (at least 20 characters)"
            )
        return text

    @field_validator("recommendation", mode="before")
    @classmethod
    def _clean_recommendation(cls, value: Any) -> str | None:
        return clean_text(value, max_length=4_096)

    @field_validator("mitre", mode="before")
    @classmethod
    def _validate_mitre(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        result: list[str] = []
        for item in value:
            text = (clean_line(item, max_length=16) or "").upper()
            if not TECHNIQUE_ID_RE.match(text):
                raise ValueError(f"not a valid ATT&CK technique ID: {text!r}")
            if text not in result:
                result.append(text)
        return result

    @field_validator("tags", "false_positives", "references", mode="before")
    @classmethod
    def _clean_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        cleaned = [clean_text(item, max_length=512) for item in value]
        return [item for item in cleaned if item]

    @model_validator(mode="after")
    def _threshold_consistency(self) -> Self:
        if self.threshold is not None and not (
            self.detection.all_of or self.detection.any_of or self.detection.event_types
        ):
            raise ValueError("a threshold rule still needs conditions to count")
        return self

    @property
    def is_threshold(self) -> bool:
        return self.threshold is not None

    @property
    def kind(self) -> str:
        return "threshold" if self.is_threshold else "match"

    def summary(self) -> str:
        state = "" if self.enabled else " (disabled)"
        return f"{self.rule_id} [{self.severity.value}] {self.name}{state}"
