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
from app.core.logging import get_logger
from app.database import repository
from app.detection import DetectionEngine, RuleSet, load_rules
from app.enrichment import EnrichmentService
from app.mitre import Catalogue, MitreMapper, get_catalogue
from app.models.alert import Alert
from app.models.analyst import AuditEntry
from app.models.enums import Actor, AuditAction
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services.alerting import AlertFactory
from app.services.context import EnvironmentContext, get_context
from app.services.severity import SeverityEngine

logger = get_logger(__name__)

#: How far back "recent activity on this host" reaches for the repeat factor.
#: Longer than a correlation window on purpose: correlation asks whether two
#: things are the same incident, this asks whether a host has been noisy.
REPEAT_WINDOW_HOURS = 24


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
            f"{self.events_processed} events",
            f"{self.indicators_found} indicators",
            f"{self.detections} detections",
            f"{self.alerts_created} alerts",
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

        # 2. Detection - threshold rules need the whole batch, not one event.
        run = self.engine.evaluate_events(events)
        result.detections = run.detection_count
        result.rule_counts = run.by_rule()

        # 3. Prior activity, for the repeat factor.
        prior = self._prior_alert_counts(events) if persist else {}

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
    def _prior_alert_counts(self, events: Sequence[SecurityEvent]) -> dict[str, int]:
        """How many alerts each host already has in the recent window."""
        counts: dict[str, int] = {}
        for event in events:
            key = event.hostname_key
            if not key or key in counts:
                continue
            counts[key] = repository.count_recent_alerts_for_host(
                self.session, key, since=event.timestamp - timedelta(hours=REPEAT_WINDOW_HOURS)
            )
        return counts

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
