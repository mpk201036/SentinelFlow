"""The triage pipeline: evidence in, alerts out.

Each stage is a separate, testable component, and this module is the only place
that knows the order they run in:

    enrich (indicators) -> detect (rules) -> map (ATT&CK) -> score -> alert

Every step is deterministic. Running the pipeline twice over the same events
produces the same alerts with the same scores, which is what makes an analyst's
"why is this a 70?" answerable.

The optional AI is deliberately absent. It is not a step here and never will
be: it reads finished alerts and writes to its own table. Deleting every row of
AI output would not change a single severity, detection or mapping produced by
this pipeline.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.display import counted
from app.core.logging import get_logger
from app.database import repository
from app.detection import DetectionEngine, DetectionRun, RuleSet, ThresholdHistory, load_rules
from app.enrichment import EnrichmentService
from app.mitre import Catalogue, MitreMapper, get_catalogue
from app.models.alert import Alert
from app.models.analyst import AuditEntry
from app.models.enums import Actor, AuditAction, EventType
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services.alerting import AlertFactory
from app.services.context import EnvironmentContext, get_context
from app.services.severity import REPEAT_WINDOW_HOURS, SeverityEngine

logger = get_logger(__name__)


@dataclass
class TriageResult:
    """What one pipeline run produced."""

    events_processed: int = 0
    indicators_found: int = 0
    detections: int = 0
    alerts: list[Alert] = field(default_factory=list)
    unknown_techniques: list[str] = field(default_factory=list)
    rule_counts: dict[str, int] = field(default_factory=dict)
    persisted: bool = True

    @property
    def alerts_created(self) -> int:
        return len(self.alerts)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.severity_level.value] = counts.get(alert.severity_level.value, 0) + 1
        return counts

    def summary(self) -> str:
        parts = [
            counted(self.events_processed, "event"),
            counted(self.indicators_found, "indicator"),
            counted(self.detections, "detection"),
            counted(self.alerts_created, "alert"),
        ]
        if not self.persisted:
            parts.append("(dry run)")
        return ", ".join(parts)


class TriagePipeline:
    """Runs the deterministic pipeline over a set of events."""

    def __init__(
        self,
        session: Session,
        settings: Settings | None = None,
        *,
        rules: RuleSet | None = None,
        catalogue: Catalogue | None = None,
        context: EnvironmentContext | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.rules = rules if rules is not None else load_rules(self.settings.rules_dir)
        self.catalogue = catalogue if catalogue is not None else get_catalogue()
        self.context = context if context is not None else get_context()

        self.enricher = EnrichmentService(session)
        self.engine = DetectionEngine(self.rules.enabled)
        self.factory = AlertFactory(
            severity_engine=SeverityEngine(self.context),
            mapper=MitreMapper(self.catalogue),
        )

    # ------------------------------------------------------------------
    def process(self, events: Sequence[SecurityEvent], *, persist: bool = True) -> TriageResult:
        """Run the full pipeline over a batch of events."""
        result = TriageResult(events_processed=len(events), persisted=persist)
        if not events:
            return result

        # 1. Enrichment - indicators are evidence, and feed the severity engine.
        indicators: dict[UUID, list[Indicator]] = {}
        for event in events:
            extraction, _ = self.enricher.enrich_event(event)
            indicators[event.event_id] = extraction.indicators
            result.indicators_found += len(extraction.indicators)

        # 2. Detection. Threshold rules also see what earlier runs saw, so a
        #    burst is one burst however the events happened to be batched.
        run = self.engine.evaluate_events(events, history=self._threshold_history(events))
        result.detections = run.detection_count
        result.rule_counts = run.by_rule()

        # 3. Earlier alerts on the same host, for the repeat factor. A dry run
        #    reads the same history, so it shows what triage would do.
        prior = self._prior_alert_counts(events, run)

        # 4. Mapping, scoring and assembly.
        built = self.factory.build_alerts(run, events, indicators=indicators, prior_alerts=prior)
        result.alerts = built.alerts
        result.unknown_techniques = built.unknown_techniques

        if persist:
            self._persist(built.alerts)
            # Mark every event the pipeline saw, not only the ones that became
            # an alert, so a burst is not re-counted on the next run.
            repository.mark_events_triaged(self.session, [e.event_id for e in events])

        logger.info("triage complete: %s", result.summary())
        return result

    def process_stored(self, *, limit: int = 1_000, persist: bool = True) -> TriageResult:
        """Run the pipeline over stored events that have no alert yet."""
        pending = repository.events_awaiting_triage(self.session, limit=limit)
        return self.process(pending, persist=persist)

    # ------------------------------------------------------------------
    def _threshold_history(self, events: Sequence[SecurityEvent]) -> ThresholdHistory:
        """The stored events and firings a threshold rule's window reaches back to."""
        rules = self.engine.threshold_rules
        windows = [rule.threshold.within_minutes for rule in rules if rule.threshold is not None]
        if not windows:
            return ThresholdHistory()
        since = min(event.timestamp for event in events) - timedelta(minutes=max(windows))
        until = max(event.timestamp for event in events)
        # Only the kinds of event some threshold rule counts, unless one of
        # them counts every kind.
        kinds: set[EventType] | None = {
            kind for rule in rules for kind in rule.detection.event_types
        }
        if any(not rule.detection.event_types for rule in rules):
            kinds = None
        batch = {event.event_id for event in events}
        earlier = [
            event
            for event in repository.triaged_events_between(
                self.session, since=since, until=until, event_types=kinds
            )
            if event.event_id not in batch
        ]
        triggers = repository.detection_triggers(
            self.session, [rule.rule_id for rule in rules], since=since, until=until
        )
        return ThresholdHistory(events=earlier, triggers=triggers)

    def _prior_alert_counts(
        self, events: Sequence[SecurityEvent], run: DetectionRun
    ) -> dict[UUID, int]:
        """event_id -> alerts on the same host in the window before that event.

        Counted per event, over stored alerts and the alerts this batch is about
        to create alike, and only those strictly earlier. So the count is the
        same whether the events arrived together or one at a time.
        """
        hosts = {event.hostname_key for event in events if event.hostname_key}
        if not hosts:
            return {}
        window = timedelta(hours=REPEAT_WINDOW_HOURS)
        times = repository.alert_times_by_host(
            self.session,
            hosts,
            since=min(event.timestamp for event in events) - window,
            until=max(event.timestamp for event in events),
        )
        for event in events:  # the alerts this batch will create
            if event.hostname_key and run.results.get(event.event_id):
                times.setdefault(event.hostname_key, []).append(event.timestamp)
        return {
            event.event_id: sum(
                1
                for moment in times.get(event.hostname_key, ())
                if event.timestamp - window <= moment < event.timestamp
            )
            for event in events
            if event.hostname_key
        }

    def _persist(self, alerts: Sequence[Alert]) -> None:
        """Store alerts and record their creation in the audit trail."""
        for alert in alerts:
            repository.save_alert(self.session, alert)
            repository.record_audit(
                self.session,
                AuditEntry(
                    actor=Actor.SYSTEM,
                    action=AuditAction.ALERT_CREATED,
                    object_type="alert",
                    object_id=alert.alert_id,
                    after=f"{alert.severity_level.value} ({alert.severity.score}/100)",
                    detail=alert.severity.explain(),
                ),
            )
