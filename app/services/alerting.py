"""Turning detections into alerts an analyst can queue.

One alert per event, carrying every rule that fired on it. That is the natural
unit before correlation: an analyst opens an event and asks "what is wrong
here?", and the answer is all of it at once rather than one notification per
rule. Grouping *alerts* into incidents is correlation's job and a different
question — "is this related to anything else?".

The alert's severity is an :class:`~app.models.alert.AlertSeverity` produced by
the deterministic engine, carrying its factors. Nothing in this module can put
anything else there: the type will not accept a bare severity, and there is no
parameter through which a model's opinion could arrive.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from app.core.logging import get_logger
from app.detection.engine import DetectionRun
from app.mitre.mapper import MitreMapper
from app.models.alert import Alert
from app.models.detection import DetectionResult
from app.models.enums import Confidence, Severity
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services.severity import SeverityEngine

logger = get_logger(__name__)

MAX_TITLE_LENGTH = 200


@dataclass
class AlertBuildResult:
    """Alerts produced, and anything the mapper refused to claim."""

    alerts: list[Alert] = field(default_factory=list)
    unknown_techniques: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.alerts)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.severity_level.value] = counts.get(alert.severity_level.value, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def summary(self) -> str:
        if not self.alerts:
            return "no alerts"
        bands = ", ".join(f"{count} {name}" for name, count in self.severity_counts().items())
        return f"{len(self.alerts)} alerts ({bands})"


def build_title(detections: Sequence[DetectionResult], event: SecurityEvent) -> str:
    """A title an analyst can triage from the queue without opening it."""
    if not detections:
        return f"Activity on {event.hostname or event.source}"[:MAX_TITLE_LENGTH]

    worst = max(detections, key=lambda item: item.rule_severity.rank)
    title = worst.rule_name
    if len(detections) > 1:
        others = len({d.rule_id for d in detections}) - 1
        if others > 0:
            title = f"{title} (+{others} more rule{'s' if others > 1 else ''})"
    if event.hostname:
        title = f"{title} on {event.hostname}"
    if event.username:
        title = f"{title} [{event.username}]"
    return title[:MAX_TITLE_LENGTH]


class AlertFactory:
    """Assembles alerts from detections, evidence and context."""

    def __init__(
        self,
        severity_engine: SeverityEngine | None = None,
        mapper: MitreMapper | None = None,
    ) -> None:
        self.severity_engine = severity_engine or SeverityEngine()
        self.mapper = mapper or MitreMapper()

    def build_alert(
        self,
        *,
        event: SecurityEvent,
        detections: Sequence[DetectionResult],
        indicators: Sequence[Indicator] = (),
        prior_alerts: int = 0,
    ) -> tuple[Alert, list[str]]:
        """Build one alert. Returns it with any techniques that could not be named."""
        severity = self.severity_engine.score(
            detections=detections,
            events=[event],
            indicators=indicators,
            prior_alerts=prior_alerts,
        )
        mapping = self.mapper.map_detections(detections, {event.event_id: event})

        alert = Alert(
            title=build_title(detections, event),
            primary_event_id=event.event_id,
            event_ids=[event.event_id],
            severity=severity,
            confidence=_overall_confidence(detections),
            detections=list(detections),
            indicators=list(indicators),
            mitre=mapping.mappings,
            tags=list(event.tags),
        )
        return alert, mapping.unknown_techniques

    def build_alerts(
        self,
        run: DetectionRun,
        events: Sequence[SecurityEvent],
        *,
        indicators: Mapping[UUID, Sequence[Indicator]] | None = None,
        prior_alerts: Mapping[UUID, int] | None = None,
    ) -> AlertBuildResult:
        """Build one alert per event that something fired on.

        ``prior_alerts`` maps an event to the alerts already on its host in the
        window before it, for the repeat-activity factor.
        """
        by_id = {event.event_id: event for event in events}
        result = AlertBuildResult()

        for event_id, detections in run.results.items():
            event = by_id.get(event_id)
            if event is None or not detections:
                continue
            prior = (prior_alerts or {}).get(event_id, 0)
            alert, unknown = self.build_alert(
                event=event,
                detections=detections,
                indicators=(indicators or {}).get(event_id, ()),
                prior_alerts=prior,
            )
            result.alerts.append(alert)
            result.unknown_techniques.extend(unknown)

        result.alerts.sort(key=lambda alert: (-alert.severity.score, alert.created_at))
        if result.alerts:
            logger.info("built %s", result.summary())
        return result


def _overall_confidence(detections: Sequence[DetectionResult]) -> Confidence:
    """The most confident rule that fired sets the alert's confidence."""
    if not detections:
        return Confidence.LOW
    order = ["low", "medium", "high"]
    return max(detections, key=lambda item: order.index(item.confidence.value)).confidence


def worst_severity(alerts: Sequence[Alert]) -> Severity | None:
    """Highest severity across a set of alerts."""
    return Severity.highest(alert.severity_level for alert in alerts)
