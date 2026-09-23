"""Rule evaluation.

The engine's contract is that a detection is **reproducible and explainable**.
Given the same event and the same rule it produces the same result every time,
and the result carries the field, the test and the observed value that caused
it. An analyst can always answer "why did this fire?" without reading the
source.

That is the whole reason the deterministic layer is kept separate from the
optional model. A language model can produce a more fluent explanation; it
cannot produce a reproducible one.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from app.core.logging import get_logger
from app.detection.operators import OPERATORS
from app.detection.schema import RAW_PREFIX, Condition, Logic, RuleDefinition
from app.models.detection import DetectionMatch, DetectionResult
from app.models.event import SecurityEvent

logger = get_logger(__name__)

#: Observed values are truncated in the evidence, which is read by a human.
MAX_OBSERVED_LENGTH = 512


@dataclass
class DetectionRun:
    """Everything one evaluation pass produced."""

    results: dict[UUID, list[DetectionResult]] = field(default_factory=dict)
    events_evaluated: int = 0
    rules_evaluated: int = 0

    def add(self, event_id: UUID, results: Sequence[DetectionResult]) -> None:
        if results:
            self.results.setdefault(event_id, []).extend(results)

    def all_results(self) -> list[DetectionResult]:
        return [result for results in self.results.values() for result in results]

    @property
    def detection_count(self) -> int:
        return sum(len(results) for results in self.results.values())

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.all_results():
            counts[result.rule_id] = counts.get(result.rule_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def summary(self) -> str:
        return (
            f"{self.detection_count} detections from {self.rules_evaluated} rules "
            f"over {self.events_evaluated} events"
        )


def resolve_field(event: SecurityEvent, name: str) -> Any:
    """Read a field from an event, including derived keys and the raw record.

    ``raw_event`` lookups are case-insensitive: the same Windows export can use
    ``EventID``, ``eventid`` or ``event_id`` depending on what produced it, and
    a rule should not have to know which.
    """
    if not name.startswith(RAW_PREFIX):
        return getattr(event, name, None)

    current: Any = event.raw_event
    for part in name[len(RAW_PREFIX) :].split("."):
        if not isinstance(current, dict):
            return None
        if part in current:
            current = current[part]
            continue
        lowered = {str(key).lower(): value for key, value in current.items()}
        if part.lower() not in lowered:
            return None
        current = lowered[part.lower()]
    return current


def evaluate_condition(
    condition: Condition, event: SecurityEvent
) -> tuple[bool, DetectionMatch | None]:
    """Test one condition, returning the evidence when it matches."""
    value = resolve_field(event, condition.field_name)
    operator = OPERATORS[condition.operator]
    try:
        matched = bool(operator(value, condition.value, ignore_case=condition.ignore_case))
    except Exception as exc:
        # A rule that errors must not stop the other rules from running, and
        # must not be silently treated as "did not match".
        logger.warning("condition %s %s failed: %s", condition.field_name, condition.operator, exc)
        return (False, None)

    if not matched:
        return (False, None)

    observed = None if value is None else str(value)[:MAX_OBSERVED_LENGTH]
    return (
        True,
        DetectionMatch(
            field_name=condition.field_name,
            condition=condition.describe(),
            observed_value=observed,
        ),
    )


def evaluate_logic(logic: Logic, event: SecurityEvent) -> list[DetectionMatch] | None:
    """Evaluate a logic block. Returns the evidence, or ``None`` if it did not match."""
    if logic.event_types and event.event_type not in logic.event_types:
        return None

    evidence: list[DetectionMatch] = []

    for condition in logic.all_of:
        matched, match = evaluate_condition(condition, event)
        if not matched:
            return None
        if match is not None:
            evidence.append(match)

    if logic.any_of:
        any_evidence = [
            match
            for matched, match in (evaluate_condition(c, event) for c in logic.any_of)
            if matched and match is not None
        ]
        if not any_evidence:
            return None
        evidence.extend(any_evidence)

    for condition in logic.none_of:
        matched, _ = evaluate_condition(condition, event)
        if matched:
            return None

    if not evidence and logic.event_types:
        evidence.append(
            DetectionMatch(
                field_name="event_type",
                condition=f"is one of {', '.join(t.value for t in logic.event_types)}",
                observed_value=event.event_type.value,
            )
        )
    return evidence


class DetectionEngine:
    """Evaluates a set of rules against events."""

    def __init__(self, rules: Iterable[RuleDefinition]) -> None:
        self.rules = [rule for rule in rules if rule.enabled]
        self.match_rules = [rule for rule in self.rules if not rule.is_threshold]
        self.threshold_rules = [rule for rule in self.rules if rule.is_threshold]

    # ------------------------------------------------------------------
    def evaluate_event(self, event: SecurityEvent) -> list[DetectionResult]:
        """Run every stateless rule against one event."""
        results: list[DetectionResult] = []
        for rule in self.match_rules:
            evidence = evaluate_logic(rule.detection, event)
            if evidence is None:
                continue
            results.append(_result(rule, event.event_id, evidence))
        return results

    def evaluate_events(self, events: Sequence[SecurityEvent]) -> DetectionRun:
        """Run every rule, including the ones that count across events."""
        run = DetectionRun(events_evaluated=len(events), rules_evaluated=len(self.rules))
        for event in events:
            run.add(event.event_id, self.evaluate_event(event))
        for rule in self.threshold_rules:
            for event_id, result in self._evaluate_threshold(rule, events):
                run.add(event_id, [result])
        if run.detection_count:
            logger.info("detection run: %s", run.summary())
        return run

    # ------------------------------------------------------------------
    def _evaluate_threshold(
        self, rule: RuleDefinition, events: Sequence[SecurityEvent]
    ) -> list[tuple[UUID, DetectionResult]]:
        """Count matching events per group within a sliding time window.

        A burst fires once. After the threshold is reached the window resets, so
        eleven failures with a threshold of five produce two detections, not
        seven — an analyst wants to know a burst happened, not receive one alert
        per event in it.
        """
        assert rule.threshold is not None
        spec = rule.threshold
        window = spec.within_minutes * 60

        grouped: dict[tuple[str, ...], list[SecurityEvent]] = {}
        for event in events:
            if evaluate_logic(rule.detection, event) is None:
                continue
            key = tuple(str(resolve_field(event, name) or "") for name in spec.group_by)
            if any(not part for part in key):
                continue  # cannot attribute the activity; counting it would be a guess
            grouped.setdefault(key, []).append(event)

        fired: list[tuple[UUID, DetectionResult]] = []
        for key, members in grouped.items():
            ordered = sorted(members, key=lambda item: item.timestamp)
            start = 0
            for index, event in enumerate(ordered):
                while (event.timestamp - ordered[start].timestamp).total_seconds() > window:
                    start += 1
                count = index - start + 1
                if count < spec.count:
                    continue
                first = ordered[start]
                evidence = [
                    DetectionMatch(
                        field_name=", ".join(spec.group_by),
                        condition=spec.describe(),
                        observed_value=f"{count} events for {' / '.join(key)}",
                    ),
                    DetectionMatch(
                        field_name="timestamp",
                        condition="window",
                        observed_value=(
                            f"{first.timestamp.isoformat()} to {event.timestamp.isoformat()}"
                        ),
                    ),
                ]
                fired.append((event.event_id, _result(rule, event.event_id, evidence)))
                start = index + 1  # reset, so one burst produces one detection
        return fired


def _result(
    rule: RuleDefinition, event_id: UUID, evidence: list[DetectionMatch]
) -> DetectionResult:
    """Snapshot the rule as it was when it matched."""
    return DetectionResult(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        rule_severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        recommendation=rule.recommendation,
        event_id=event_id,
        matched=evidence,
        mitre_technique_ids=list(rule.mitre),
    )
