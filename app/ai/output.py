"""The shape a model must answer in, and the parser that enforces it.

Model output is untrusted input, exactly like an imported log file. It is
bounded in size, parsed as JSON, validated against a fixed schema and cleaned
before any of it is stored. Output that fails is rejected whole and nothing is
stored: an analyst is better served by "the model's answer was unusable" than
by a half-parsed guess.

Two things are handled leniently, because rejecting the whole answer for them
would throw away the useful part:

* **A statement without a valid label** is dropped, and a note says so. An
  unlabelled claim is never shown.
* **Keys the model has no business setting** (``severity``, ``status``,
  ``is_advisory`` ...) are discarded, and a note names them. A model that tries
  to set the verdict is worth telling the analyst about; it may have been
  steered by the evidence.

The schema is also sent to Ollama as the ``format`` parameter, which constrains
decoding to it. That makes a valid reply likely. This parser is what makes an
invalid one harmless.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.sanitize import clean_text
from app.models.ai import (
    MAX_ENTRY_LENGTH,
    MAX_LIST_ENTRIES,
    MAX_STATEMENTS,
    MAX_SUMMARY_LENGTH,
    AIStatement,
)
from app.models.enums import Severity, StatementType

#: Anything longer is not an answer to this prompt.
MAX_OUTPUT_CHARS = 64_000

#: Schema limits sent to the model. Tighter than storage limits on purpose:
#: a short answer from a small model is faster and usually better.
SCHEMA_MAX_STATEMENTS = 12
SCHEMA_MAX_ITEMS = 6

#: Top-level keys that would claim authority the model does not have.
AUTHORITY_KEYS = frozenset(
    {
        "severity",
        "severity_score",
        "score",
        "risk_score",
        "status",
        "classification",
        "verdict",
        "disposition",
        "is_advisory",
        "injection_suspected",
        "assigned_to",
        "mitre",
        "mitre_mappings",
        "techniques",
    }
)

_LABELS = {label.value for label in StatementType}
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def _string_list(max_items: int) -> dict[str, Any]:
    return {"type": "array", "items": {"type": "string"}, "maxItems": max_items}


#: JSON Schema for the model's reply. Written by hand rather than generated,
#: so it has no ``$ref`` indirection for a grammar compiler to trip over.
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "statements": {
            "type": "array",
            "maxItems": SCHEMA_MAX_STATEMENTS,
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "enum": sorted(_LABELS)},
                    "text": {"type": "string"},
                },
                "required": ["label", "text"],
            },
        },
        "suspicious_observations": _string_list(SCHEMA_MAX_ITEMS),
        "possible_explanations": _string_list(SCHEMA_MAX_ITEMS),
        "analyst_questions": _string_list(SCHEMA_MAX_ITEMS),
        "recommended_next_steps": _string_list(SCHEMA_MAX_ITEMS),
        "suggested_severity": {"type": "string", "enum": [s.value for s in Severity]},
        "suggested_severity_rationale": {"type": "string"},
    },
    "required": [
        "summary",
        "statements",
        "suspicious_observations",
        "possible_explanations",
        "analyst_questions",
        "recommended_next_steps",
        "suggested_severity",
        "suggested_severity_rationale",
    ],
}


class AIOutputError(ValueError):
    """The model's reply could not be used. Nothing is stored."""


class _Statement(BaseModel):
    model_config = ConfigDict(extra="ignore")

    label: str = ""
    text: str = ""

    @field_validator("label", "text", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> str:
        return "" if value is None else str(value)


class _Reply(BaseModel):
    """Lenient reading of the reply. Strictness is applied afterwards, per field."""

    model_config = ConfigDict(extra="ignore")

    summary: str
    statements: list[_Statement] = Field(default_factory=list)
    suspicious_observations: list[str] = Field(default_factory=list)
    possible_explanations: list[str] = Field(default_factory=list)
    analyst_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    suggested_severity: str | None = None
    suggested_severity_rationale: str | None = None

    @field_validator(
        "suspicious_observations",
        "possible_explanations",
        "analyst_questions",
        "recommended_next_steps",
        mode="before",
    )
    @classmethod
    def _listify(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        raise ValueError("expected a list of strings")


@dataclass
class ParsedReply:
    """A validated reply, ready to become an :class:`~app.models.ai.AIAnalysis`."""

    summary: str
    statements: list[AIStatement]
    suspicious_observations: list[str]
    possible_explanations: list[str]
    analyst_questions: list[str]
    recommended_next_steps: list[str]
    suggested_severity: Severity | None
    suggested_severity_rationale: str | None
    notes: list[str] = field(default_factory=list)
    truncated: bool = False

    def all_text(self) -> list[str]:
        """Every piece of prose in the reply, for grounding checks."""
        return [
            self.summary,
            *(s.text for s in self.statements),
            *self.suspicious_observations,
            *self.possible_explanations,
            *self.analyst_questions,
            *self.recommended_next_steps,
            self.suggested_severity_rationale or "",
        ]


def parse_reply(raw: str) -> ParsedReply:
    """Turn a model's raw reply into a :class:`ParsedReply`, or raise AIOutputError."""
    if len(raw) > MAX_OUTPUT_CHARS:
        raise AIOutputError(f"the reply was longer than {MAX_OUTPUT_CHARS:,} characters")

    data = _extract_object(raw)
    notes: list[str] = []

    claimed = sorted(key for key in data if key.strip().lower() in AUTHORITY_KEYS)
    if claimed:
        notes.append(
            f"The model's reply tried to set {', '.join(claimed)}, which it has no authority "
            "to set. Discarded."
        )

    try:
        reply = _Reply.model_validate(data)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in error["loc"]) for error in exc.errors()})
        raise AIOutputError(
            f"the reply did not match the required schema ({', '.join(fields)[:200]})"
        ) from None

    summary = clean_text(reply.summary, max_length=MAX_SUMMARY_LENGTH)
    if not summary:
        raise AIOutputError("the reply had no summary")

    statements: list[AIStatement] = []
    unlabelled = 0
    for item in reply.statements:
        label = item.label.strip().lower()
        text = clean_text(item.text, max_length=MAX_ENTRY_LENGTH)
        if not text:
            continue
        if label not in _LABELS:
            unlabelled += 1
            continue
        statements.append(AIStatement(statement_type=StatementType(label), text=text))
    if unlabelled:
        notes.append(
            f"{unlabelled} statement(s) without an observed, inferred or unknown label "
            "were discarded."
        )

    severity: Severity | None = None
    if reply.suggested_severity:
        candidate = reply.suggested_severity.strip().lower()
        if candidate in {s.value for s in Severity}:
            severity = Severity(candidate)
        else:
            notes.append(
                f"The suggested severity {candidate[:40]!r} is not a SentinelFlow level. Ignored."
            )

    truncated = len(statements) > MAX_STATEMENTS or any(
        len(values) > MAX_LIST_ENTRIES
        for values in (
            reply.suspicious_observations,
            reply.possible_explanations,
            reply.analyst_questions,
            reply.recommended_next_steps,
        )
    )
    return ParsedReply(
        summary=summary,
        statements=statements[:MAX_STATEMENTS],
        suspicious_observations=_clean_list(reply.suspicious_observations),
        possible_explanations=_clean_list(reply.possible_explanations),
        analyst_questions=_clean_list(reply.analyst_questions),
        recommended_next_steps=_clean_list(reply.recommended_next_steps),
        suggested_severity=severity,
        suggested_severity_rationale=clean_text(
            reply.suggested_severity_rationale, max_length=MAX_ENTRY_LENGTH
        )
        if severity is not None
        else None,
        notes=notes,
        truncated=truncated,
    )


def _extract_object(raw: str) -> dict[str, Any]:
    """Find the single JSON object in a reply.

    Reasoning models may wrap their answer in ``<think>`` blocks, and some
    models add a Markdown fence despite being told not to. Both are removed;
    anything else outside the outermost braces is ignored.
    """
    text = _THINK_RE.sub("", raw).strip()
    text = _FENCE_RE.sub("", text).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise AIOutputError("the reply contained no JSON object")
    try:
        data = json.loads(text[start : end + 1])
    except (json.JSONDecodeError, RecursionError):
        raise AIOutputError("the reply was not valid JSON") from None
    if not isinstance(data, dict):
        raise AIOutputError("the reply was not a JSON object")
    return data


def _clean_list(values: list[str]) -> list[str]:
    cleaned = (clean_text(value, max_length=MAX_ENTRY_LENGTH) for value in values)
    return [value for value in cleaned if value][:MAX_LIST_ENTRIES]
