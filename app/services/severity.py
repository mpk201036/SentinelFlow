"""The deterministic severity engine.

Severity is the number an analyst uses to decide what to look at first, so two
properties matter more than sophistication:

* **It is reproducible.** The same inputs always produce the same score. No
  randomness, no clock, no model.
* **It shows its working.** Every point is attached to a named factor with a
  sentence explaining why it applied. An analyst who disagrees with a score can
  see exactly which factor to argue with, and a detection engineer can see
  which weight to change.

Scoring is purely additive and then clamped to 0-100. Multiplicative scoring
produces numbers nobody can reason about backwards: a 72 that came from
0.8 x 0.9 x 100 cannot be explained in a sentence, whereas "65 because the rule
is HIGH, +15 because the account is privileged, -10 because confidence is low"
can.

**Nothing in this module can be influenced by the optional AI.** The engine
takes detections, events, indicators and a count of prior alerts. There is no
parameter through which a model's opinion could arrive, and a test asserts that
every factor name comes from this module's own vocabulary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from app.core.logging import get_logger
from app.models.alert import AlertSeverity, SeverityFactor
from app.models.detection import DetectionResult
from app.models.enums import Confidence, EventType, IndicatorType, Severity
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services.context import EnvironmentContext, get_context

logger = get_logger(__name__)

#: Indicator types that describe something outside the estate.
NETWORK_INDICATORS = frozenset(
    {IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN, IndicatorType.URL}
)

#: Every factor this engine can produce. Used by the tests to assert that
#: nothing outside this vocabulary ever reaches an alert's severity.
FACTOR_NAMES = frozenset(
    {
        "rule_severity",
        "corroboration",
        "detection_confidence",
        "privileged_account",
        "critical_host",
        "deception_signal",
        "external_source",
        "external_indicators",
        "out_of_hours",
        "repeat_activity",
    }
)


@dataclass(frozen=True)
class SeverityWeights:
    """Tunable weights. Defaults are documented in docs/severity.md."""

    corroboration_per_rule: int = 8
    corroboration_cap: int = 24
    confidence_high: int = 5
    confidence_low: int = -10
    privileged_account: int = 15
    critical_host: int = 15
    deception_signal: int = 20
    external_source: int = 5
    external_indicator_each: int = 3
    external_indicator_cap: int = 9
    out_of_hours: int = 5
    repeat_activity_each: int = 10
    repeat_activity_cap: int = 20


class SeverityEngine:
    """Turns evidence into a scored, explained verdict."""

    def __init__(
        self,
        context: EnvironmentContext | None = None,
        weights: SeverityWeights | None = None,
    ) -> None:
        self.context = context if context is not None else get_context()
        self.weights = weights or SeverityWeights()

    # ------------------------------------------------------------------
    def score(
        self,
        *,
        detections: Sequence[DetectionResult],
        events: Sequence[SecurityEvent],
        indicators: Sequence[Indicator] = (),
        prior_alerts: int = 0,
    ) -> AlertSeverity:
        """Produce a severity verdict from deterministic inputs only."""
        factors: list[SeverityFactor] = []

        factors.extend(self._rule_severity(detections))
        factors.extend(self._corroboration(detections))
        factors.extend(self._confidence(detections))
        factors.extend(self._privileged_account(events))
        factors.extend(self._critical_host(events))
        factors.extend(self._deception(events))
        factors.extend(self._external_source(events))
        factors.extend(self._external_indicators(indicators))
        factors.extend(self._out_of_hours(events))
        factors.extend(self._repeat_activity(prior_alerts))

        verdict = AlertSeverity.from_factors(factors)
        logger.debug("severity %s from %s factors", verdict.score, len(factors))
        return verdict

    # ------------------------------------------------------------------
    # Factors
    # ------------------------------------------------------------------
    def _rule_severity(self, detections: Sequence[DetectionResult]) -> list[SeverityFactor]:
        """The base score: the most severe rule that fired.

        The *highest* rather than the sum, because five LOW rules firing is not
        a CRITICAL alert - it is five low-severity observations, and the
        corroboration factor is what reflects their number.
        """
        if not detections:
            return []
        worst = max(detections, key=lambda item: item.rule_severity.rank)
        return [
            SeverityFactor(
                name="rule_severity",
                points=worst.rule_severity.base_score,
                detail=(
                    f"Rule {worst.rule_id} ({worst.rule_name}) is "
                    f"{worst.rule_severity.value.upper()} severity"
                ),
            )
        ]

    def _corroboration(self, detections: Sequence[DetectionResult]) -> list[SeverityFactor]:
        """Independent rules agreeing is evidence; the same rule twice is not."""
        distinct = {detection.rule_id for detection in detections}
        if len(distinct) < 2:
            return []
        extra = len(distinct) - 1
        points = min(extra * self.weights.corroboration_per_rule, self.weights.corroboration_cap)
        return [
            SeverityFactor(
                name="corroboration",
                points=points,
                detail=(
                    f"{len(distinct)} independent rules matched this activity: "
                    f"{', '.join(sorted(distinct))}"
                ),
            )
        ]

    def _confidence(self, detections: Sequence[DetectionResult]) -> list[SeverityFactor]:
        """A rule that admits it is a heuristic should not carry full weight."""
        if not detections:
            return []
        best = max(
            detections, key=lambda item: ["low", "medium", "high"].index(item.confidence.value)
        )
        if best.confidence is Confidence.HIGH:
            return [
                SeverityFactor(
                    name="detection_confidence",
                    points=self.weights.confidence_high,
                    detail=f"Rule {best.rule_id} is high confidence",
                )
            ]
        if best.confidence is Confidence.LOW:
            return [
                SeverityFactor(
                    name="detection_confidence",
                    points=self.weights.confidence_low,
                    detail=(
                        f"No rule above low confidence matched (most confident was {best.rule_id})"
                    ),
                )
            ]
        return []

    def _privileged_account(self, events: Sequence[SecurityEvent]) -> list[SeverityFactor]:
        for event in events:
            reason = self.context.privileged_account_reason(event.username)
            if reason:
                return [
                    SeverityFactor(
                        name="privileged_account",
                        points=self.weights.privileged_account,
                        detail=reason,
                    )
                ]
        return []

    def _critical_host(self, events: Sequence[SecurityEvent]) -> list[SeverityFactor]:
        for event in events:
            reason = self.context.critical_host_reason(event.hostname)
            if reason:
                return [
                    SeverityFactor(
                        name="critical_host", points=self.weights.critical_host, detail=reason
                    )
                ]
        return []

    def _deception(self, events: Sequence[SecurityEvent]) -> list[SeverityFactor]:
        """Deception signals have almost no legitimate background rate.

        This is the one place a source's own confidence is allowed to move the
        score, and only because the source is a decoy: nothing legitimate has a
        reason to touch one. It raises the number, it does not set it, and a
        human still confirms.
        """
        for event in events:
            if event.event_type is EventType.DECOY_CREDENTIAL_ACCESS:
                return [
                    SeverityFactor(
                        name="deception_signal",
                        points=self.weights.deception_signal,
                        detail=(
                            "A decoy credential was accessed, which has no routine legitimate cause"
                        ),
                    )
                ]
        return []

    def _external_source(self, events: Sequence[SecurityEvent]) -> list[SeverityFactor]:
        """Something reached in from outside the estate."""
        for event in events:
            if not event.src_ip:
                continue
            indicator = _as_indicator(event.src_ip)
            if indicator is not None and not indicator.is_internal:
                return [
                    SeverityFactor(
                        name="external_source",
                        points=self.weights.external_source,
                        detail=f"Activity originated from {event.src_ip}, outside the estate",
                    )
                ]
        return []

    def _external_indicators(self, indicators: Sequence[Indicator]) -> list[SeverityFactor]:
        """Breadth of external infrastructure touched."""
        external = {
            indicator.value
            for indicator in indicators
            if indicator.indicator_type in NETWORK_INDICATORS and not indicator.is_internal
        }
        if not external:
            return []
        points = min(
            len(external) * self.weights.external_indicator_each,
            self.weights.external_indicator_cap,
        )
        listed = ", ".join(sorted(external)[:5])
        return [
            SeverityFactor(
                name="external_indicators",
                points=points,
                detail=f"{len(external)} external indicator(s) observed: {listed}",
            )
        ]

    def _out_of_hours(self, events: Sequence[SecurityEvent]) -> list[SeverityFactor]:
        moment: datetime | None = min((event.timestamp for event in events), default=None)
        if not self.context.is_out_of_hours(moment) or moment is None:
            return []
        return [
            SeverityFactor(
                name="out_of_hours",
                points=self.weights.out_of_hours,
                detail=f"Activity occurred at {moment.strftime('%H:%M UTC on %A')}, outside working hours",
            )
        ]

    def _repeat_activity(self, prior_alerts: int) -> list[SeverityFactor]:
        """Recent alerts on the same host or account raise the stakes."""
        if prior_alerts <= 0:
            return []
        points = min(
            prior_alerts * self.weights.repeat_activity_each, self.weights.repeat_activity_cap
        )
        return [
            SeverityFactor(
                name="repeat_activity",
                points=points,
                detail=(f"{prior_alerts} recent alert(s) already involve this host or account"),
            )
        ]


def _as_indicator(value: str) -> Indicator | None:
    """Wrap an address so the internal/external classification is shared."""
    import ipaddress

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    indicator_type = (
        IndicatorType.IPV6 if isinstance(address, ipaddress.IPv6Address) else IndicatorType.IPV4
    )
    try:
        return Indicator(indicator_type=indicator_type, value=value)
    except ValueError:  # pragma: no cover - value already parsed as an address
        return None


def describe_scale() -> list[tuple[str, str]]:
    """The score-to-band mapping, for documentation and the dashboard legend."""
    return [
        (f"{Severity.LOW.value}", "0-29"),
        (f"{Severity.MEDIUM.value}", "30-59"),
        (f"{Severity.HIGH.value}", "60-84"),
        (f"{Severity.CRITICAL.value}", "85-100"),
    ]
