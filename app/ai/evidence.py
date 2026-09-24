"""The evidence document a model is shown, decided in one place.

Everything the model knows about an alert comes from :func:`build_evidence`.
Keeping that decision in one function makes three properties checkable:

* **Nothing is sent that an analyst could not already see.** The document is
  built from the stored alert and its primary event, and nothing else — no
  other alerts, no environment file, no configuration.
* **The deterministic severity is left out on purpose.** A model shown the
  score tends to agree with it, and a second opinion that only echoes the
  first is worth nothing. The model's suggestion is independent, and the
  console puts the two side by side.
* **The size is bounded.** Every string is clipped and the whole document has
  a ceiling, so a hostile 8 KB command line cannot crowd the instructions out
  of a small local model's context window.

The document is serialised as JSON. That is itself a defence: quotes,
newlines and backslashes inside attacker-controlled values are escaped, so a
value cannot close its own string, add a key, or start a new line that looks
like a fresh instruction.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.enrichment.defang import refang
from app.models.alert import Alert
from app.models.event import SecurityEvent

#: Longest any single string may be in the document.
MAX_FIELD_CHARS = 800
#: Clip applied to every string when the document is still too large.
TIGHT_FIELD_CHARS = 240
#: Ceiling on the serialised document. About 4,000 tokens for most models.
MAX_EVIDENCE_CHARS = 14_000
MAX_DETECTIONS = 8
MAX_MATCHES_PER_DETECTION = 8
MAX_INDICATORS = 25
TIGHT_INDICATORS = 10

#: Normalised event fields shown to the model, in reading order. ``raw_event``
#: is deliberately absent: it repeats these fields in the source's own shape
#: and would double the attacker-controlled text for no analytical gain.
EVENT_FIELDS: tuple[str, ...] = (
    "timestamp",
    "source",
    "event_type",
    "hostname",
    "username",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "process_name",
    "process_id",
    "parent_process",
    "parent_process_id",
    "command_line",
    "file_path",
    "file_hash",
    "domain",
    "url",
    "event_message",
)


@dataclass(frozen=True)
class Evidence:
    """What the model will see for one alert, plus what grounding needs."""

    alert_id: UUID
    document: dict[str, Any]
    #: The exact JSON placed between the evidence markers.
    text: str
    #: ATT&CK techniques SentinelFlow mapped to this alert.
    mapped_techniques: frozenset[str]
    #: Paths of values that were clipped, so the analyst can be told.
    clipped: tuple[str, ...]
    #: Every string value, lower-cased and refanged, for grounding lookups.
    haystack: str

    def strings(self) -> Iterator[tuple[str, str]]:
        """Every string in the document with its JSON path."""
        yield from _walk(self.document, "")

    def contains(self, value: str) -> bool:
        """Whether ``value`` appears in the evidence as a whole token.

        Token boundaries matter: ``10.0.0.5`` must not be "found" inside
        ``10.0.0.50``, nor ``evil.com`` inside ``notevil.com``.
        """
        needle = refang(value).strip().lower()
        if not needle:
            return False
        pattern = rf"(?<![\w.-]){re.escape(needle)}(?![\w-]|\.\w)"
        return re.search(pattern, self.haystack) is not None


def build_evidence(alert: Alert, event: SecurityEvent | None) -> Evidence:
    """Assemble the document for ``alert``, within the size ceiling."""
    document, clipped = _assemble(alert, event, MAX_FIELD_CHARS, MAX_INDICATORS)
    text = _serialise(document)
    if len(text) > MAX_EVIDENCE_CHARS:
        document, clipped = _assemble(alert, event, TIGHT_FIELD_CHARS, TIGHT_INDICATORS)
        text = _serialise(document)
    if len(text) > MAX_EVIDENCE_CHARS:  # pragma: no cover - bounded by the caps above
        raise ValueError("evidence document exceeds its ceiling even when clipped")

    haystack = "\n".join(refang(value).lower() for _, value in _walk(document, ""))
    return Evidence(
        alert_id=alert.alert_id,
        document=document,
        text=text,
        mapped_techniques=frozenset(m.technique_id.upper() for m in alert.mitre),
        clipped=tuple(clipped),
        haystack=haystack,
    )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def _assemble(
    alert: Alert, event: SecurityEvent | None, field_chars: int, indicator_cap: int
) -> tuple[dict[str, Any], list[str]]:
    clipped: list[str] = []

    def clip(path: str, value: Any) -> Any:
        if value is None or isinstance(value, bool | int):
            return value
        text = str(value)
        if len(text) <= field_chars:
            return text
        clipped.append(path)
        return f"{text[:field_chars]}...[clipped {len(text) - field_chars} chars]"

    observed = _observed_fields(event)

    def match_value(path: str, field_name: str, value: str | None) -> Any:
        # A rule usually matched on a field that is already in observed_event.
        # Repeating it would show the model the same attacker-controlled text
        # once per rule, so the match points at the field instead.
        source = observed.get(field_name)
        if value is not None and isinstance(source, str) and source.startswith(value[:200]):
            return f"(see observed_event.{field_name})"
        return clip(path, value)

    detections = []
    for d_index, detection in enumerate(alert.detections[:MAX_DETECTIONS]):
        base = f"sentinelflow_findings.detections[{d_index}]"
        detections.append(
            {
                "rule_id": detection.rule_id,
                "rule_name": clip(f"{base}.rule_name", detection.rule_name),
                "description": clip(f"{base}.description", detection.description),
                "matched": [
                    {
                        "field": match.field_name,
                        "condition": clip(f"{base}.matched[{m_index}].condition", match.condition),
                        "value": match_value(
                            f"{base}.matched[{m_index}].value",
                            match.field_name,
                            match.observed_value,
                        ),
                    }
                    for m_index, match in enumerate(detection.matched[:MAX_MATCHES_PER_DETECTION])
                ],
            }
        )

    findings: dict[str, Any] = {
        "detections": detections,
        "mitre_attack": [
            {
                "technique_id": mapping.technique_id,
                "name": mapping.technique.name,
                "tactics": list(mapping.technique.tactics),
            }
            for mapping in alert.mitre
        ],
        "indicators": [
            {
                "type": indicator.indicator_type.value,
                "value": clip(f"sentinelflow_findings.indicators[{i}].value", indicator.value),
                "internal": indicator.is_internal,
            }
            for i, indicator in enumerate(alert.indicators[:indicator_cap])
        ],
    }

    observed_clipped = {name: clip(f"observed_event.{name}", v) for name, v in observed.items()}

    document: dict[str, Any] = {
        "alert": {
            "title": clip("alert.title", alert.title),
            "raised_at": alert.created_at.isoformat(),
            "rule_confidence": alert.confidence.value,
            "related_event_count": len(alert.event_ids),
        },
        "sentinelflow_findings": findings,
        "observed_event": observed_clipped or None,
    }
    return document, clipped


def _observed_fields(event: SecurityEvent | None) -> dict[str, Any]:
    """The event's populated fields, in reading order, before clipping."""
    observed: dict[str, Any] = {}
    if event is None:
        return observed
    for name in EVENT_FIELDS:
        value = getattr(event, name, None)
        if value is None or value == "":
            continue
        if name == "timestamp":
            value = event.timestamp.isoformat()
        elif hasattr(value, "value"):  # enums
            value = value.value
        observed[name] = value
    return observed


def _serialise(document: dict[str, Any]) -> str:
    # ensure_ascii=False keeps non-English names readable. Invisible and
    # bidirectional control characters were already removed at ingestion.
    return json.dumps(document, ensure_ascii=False, indent=1)


def _walk(node: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node
