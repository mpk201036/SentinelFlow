"""Turning detections into evidence-backed ATT&CK mappings.

Two rules govern this module, and both exist because ATT&CK decoration is the
easiest thing in security tooling to fake:

1. **A mapping must state why it applies**, in terms of what was observed. The
   reason is built from the rule that fired and the field values that caused
   it, so "why is T1059.001 on this alert?" always has a real answer.
   ``MitreMapping`` refuses a reason shorter than ten characters, so a mapping
   without one cannot be constructed at all.

2. **A technique that is not in the catalogue is not mapped.** SentinelFlow
   will not render a bare ``T1234`` that looks authoritative and says nothing.
   Unknown identifiers are reported so the gap is visible and fixable.

The mapper invents nothing. It maps only the techniques a rule declared, and
only when the catalogue can name them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from app.core.display import counted
from app.core.logging import get_logger
from app.mitre.catalogue import Catalogue, get_catalogue
from app.models.detection import DetectionResult
from app.models.event import SecurityEvent
from app.models.mitre import MitreMapping

logger = get_logger(__name__)

#: MitreMapping caps the reason at 1024; leave room for the truncation marker.
MAX_REASON_LENGTH = 980


@dataclass
class MappingResult:
    """What a mapping pass produced, including what it refused to map."""

    mappings: list[MitreMapping] = field(default_factory=list)
    unknown_techniques: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.mappings)

    @property
    def technique_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for mapping in self.mappings:
            seen.setdefault(mapping.technique_id, None)
        return list(seen)

    def tactics(self) -> list[str]:
        seen: dict[str, None] = {}
        for mapping in self.mappings:
            for tactic in mapping.technique.tactics:
                seen.setdefault(tactic, None)
        return list(seen)

    def summary(self) -> str:
        parts = [
            f"{counted(len(self.mappings), 'mapping')} across "
            f"{counted(len(self.technique_ids), 'technique')}"
        ]
        if self.unknown_techniques:
            parts.append(f"{len(set(self.unknown_techniques))} not in the catalogue")
        return ", ".join(parts)


def build_reason(detection: DetectionResult, event: SecurityEvent | None = None) -> str:
    """Explain a mapping in terms of what was observed.

    The reason names the rule, the host and account where known, and the field
    values that satisfied the rule's conditions — so the mapping is auditable
    without opening the rule file.
    """
    context: list[str] = []
    if event is not None:
        if event.hostname:
            context.append(f"on {event.hostname}")
        if event.username:
            context.append(f"for {event.username}")
    where = " ".join(context)

    evidence = "; ".join(str(match) for match in detection.matched)
    head = f"Rule {detection.rule_id} ({detection.rule_name}) matched"
    if where:
        head = f"{head} {where}"

    reason = f"{head}: {evidence}" if evidence else f"{head}."
    if len(reason) > MAX_REASON_LENGTH:
        reason = reason[:MAX_REASON_LENGTH] + "...[truncated]"
    return reason


class MitreMapper:
    """Builds mappings from detections, refusing anything it cannot justify."""

    def __init__(self, catalogue: Catalogue | None = None) -> None:
        self.catalogue = catalogue if catalogue is not None else get_catalogue()

    def map_detection(
        self, detection: DetectionResult, event: SecurityEvent | None = None
    ) -> MappingResult:
        """Map one detection's declared techniques."""
        result = MappingResult()
        reason = build_reason(detection, event)

        for technique_id in detection.mitre_technique_ids:
            technique = self.catalogue.resolve(technique_id)
            if technique is None:
                # Refusing to render an identifier we cannot name is the whole
                # anti-fabrication control; record it so the gap is fixable.
                result.unknown_techniques.append(technique_id)
                logger.warning(
                    "rule %s references %s, which is not in the ATT&CK catalogue",
                    detection.rule_id,
                    technique_id,
                )
                continue

            note = reason
            if technique.technique_id != technique_id.upper():
                note = (
                    f"{reason} (rule referenced {technique_id.upper()}; "
                    f"mapped to parent technique {technique.technique_id})"
                )[:MAX_REASON_LENGTH]

            result.mappings.append(
                MitreMapping(
                    technique=technique,
                    reason=note,
                    source_rule_id=detection.rule_id,
                    confidence=detection.confidence,
                )
            )
        return result

    def map_detections(
        self,
        detections: Iterable[DetectionResult],
        events: Mapping[UUID, SecurityEvent] | None = None,
    ) -> MappingResult:
        """Map many detections, de-duplicating identical (technique, rule) pairs."""
        combined = MappingResult()
        seen: set[tuple[str, str | None]] = set()

        for detection in detections:
            event = None
            if events is not None and detection.event_id is not None:
                event = events.get(detection.event_id)
            outcome = self.map_detection(detection, event)
            combined.unknown_techniques.extend(outcome.unknown_techniques)
            for mapping in outcome.mappings:
                key = (mapping.technique_id, mapping.source_rule_id)
                if key in seen:
                    continue
                seen.add(key)
                combined.mappings.append(mapping)

        if combined.mappings or combined.unknown_techniques:
            logger.info("ATT&CK mapping: %s", combined.summary())
        return combined


def validate_rule_techniques(rules: Iterable[object], catalogue: Catalogue) -> list[str]:
    """Report rules referencing techniques the catalogue cannot name."""
    problems: list[str] = []
    for rule in rules:
        for technique_id in getattr(rule, "mitre", []) or []:
            if catalogue.get(technique_id) is None:
                parent = catalogue.resolve(technique_id)
                detail = (
                    f"would fall back to {parent.technique_id}"
                    if parent is not None
                    else "no parent technique either"
                )
                problems.append(
                    f"{getattr(rule, 'rule_id', '?')}: {technique_id} is not in the catalogue "
                    f"({detail})"
                )
    return problems


def tactic_coverage(rules: Sequence[object], catalogue: Catalogue) -> dict[str, list[str]]:
    """Which tactics the rule set covers, and through which rules.

    Coverage is a map of what the rules can see, not a score. Every real estate
    has gaps, and a tool that hides them is less useful than one that names them.
    """
    coverage: dict[str, list[str]] = {name: [] for name in catalogue.tactic_names()}
    for rule in rules:
        rule_id = str(getattr(rule, "rule_id", "?"))
        for technique_id in getattr(rule, "mitre", []) or []:
            technique = catalogue.resolve(technique_id)
            if technique is None:
                continue
            for tactic in technique.tactics:
                bucket = coverage.setdefault(tactic, [])
                if rule_id not in bucket:
                    bucket.append(rule_id)
    return coverage
