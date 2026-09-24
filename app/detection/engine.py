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

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.display import counted
from app.core.logging import get_logger
from app.detection.operators import OPERATORS
from app.detection.schema import RAW_PREFIX, Condition, Logic, RuleDefinition
from app.models.detection import DetectionMatch, DetectionResult
from app.models.event import SecurityEvent

logger = get_logger(__name__)

#: Observed values are truncated in the evidence, which is read by a human.
MAX_OBSERVED_LENGTH = 512


@dataclass(frozen=True)
class ThresholdHistory:
    """What earlier triage runs saw, so a burst split across batches is one burst.

    A threshold rule counts events across a window. Evaluated over one batch
    only, it depends on where the batch boundaries fall: eight failed logons
    triaged together fired, and the same eight triaged as they arrived never
    did. With the history, a batch is judged as if everything before it had
    arrived with it.
    """

    #: Already-triaged events from the window before the batch.
    events: Sequence[SecurityEvent] = ()
    #: rule_id -> the events that rule has already fired on, which is where
    #: its count restarts.
    triggers: Mapping[str, Sequence[SecurityEvent]] = field(default_factory=dict)


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
            f"{counted(self.detection_count, 'detection')} from "
            f"{counted(self.rules_evaluated, 'rule')} over {counted(self.events_evaluated, 'event')}"
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

    def evaluate_events(
        self, events: Sequence[SecurityEvent], *, history: ThresholdHistory | None = None
    ) -> DetectionRun:
        """Run every rule, including the ones that count across events.

        Without ``history`` a threshold rule sees this batch alone. The triage
        pipeline always passes it; a dry run over stored events need not.
        """
        run = DetectionRun(events_evaluated=len(events), rules_evaluated=len(self.rules))
        for event in events:
            run.add(event.event_id, self.evaluate_event(event))
        history = history or ThresholdHistory()
        for rule in self.threshold_rules:
            for event_id, result in self._evaluate_threshold(
                rule, events, earlier=history.events, fired=history.triggers.get(rule.rule_id, ())
            ):
                run.add(event_id, [result])
        if run.detection_count:
            logger.info("detection run: %s", run.summary())
        return run

    # ------------------------------------------------------------------
    def threshold_key(self, rule: RuleDefinition, event: SecurityEvent) -> tuple[str, ...] | None:
        """The group an event counts towards, or ``None`` if it cannot be attributed."""
        if rule.threshold is None:
            return None
        key = tuple(str(resolve_field(event, name) or "") for name in rule.threshold.group_by)
        return None if any(not part for part in key) else key

    def _evaluate_threshold(
        self,
        rule: RuleDefinition,
        events: Sequence[SecurityEvent],
        *,
        earlier: Sequence[SecurityEvent] = (),
        fired: Sequence[SecurityEvent] = (),
    ) -> list[tuple[UUID, DetectionResult]]:
        """Count matching events per group within a sliding time window.

        A burst fires once. After the threshold is reached the window resets, so
        eleven failures with a threshold of five produce two detections, not
        seven — an analyst wants to know a burst happened, not receive one alert
        per event in it.

        ``earlier`` events count towards a burst but are never fired on: they
        were triaged already. Counting restarts after the last event in
        ``fired`` for the same group, exactly as it would have in one batch.
        """
        if rule.threshold is None:
            raise ValueError(f"rule {rule.rule_id} is not a threshold rule")
        spec = rule.threshold
        window = spec.within_minutes * 60

        restart: dict[tuple[str, ...], datetime] = {}
        for event in fired:
            fired_key = self.threshold_key(rule, event)
            if fired_key is not None and (
                fired_key not in restart or event.timestamp > restart[fired_key]
            ):
                restart[fired_key] = event.timestamp

        in_batch = {event.event_id for event in events}
        grouped: dict[tuple[str, ...], list[SecurityEvent]] = {}
        # Earlier events first, so at an equal timestamp they sort before the
        # batch, as they would have in the order they arrived.
        for event in [*earlier, *events]:
            if evaluate_logic(rule.detection, event) is None:
                continue
            key = self.threshold_key(rule, event)
            if key is None:
                continue  # cannot attribute the activity; counting it would be a guess
            if (
                event.event_id not in in_batch
                and key in restart
                and event.timestamp <= restart[key]
            ):
                continue  # already part of a burst that fired
            grouped.setdefault(key, []).append(event)

        fired_now: list[tuple[UUID, DetectionResult]] = []
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
                if event.event_id in in_batch:
                    fired_now.append((event.event_id, _result(rule, event.event_id, evidence)))
                start = index + 1  # reset, so one burst produces one detection
        return fired_now


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
