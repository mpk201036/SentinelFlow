"""Extraction wired to storage.

Indicators are stored once per ``(type, value)`` and linked to every event they
appeared in. That shape matters: seeing ``192.0.2.77`` in fifty events is one
indicator with fifty sightings, not fifty indicators, and the link table is what
lets an analyst ask "show me everything that mentioned this address" — including
the events where it only appeared inside a command line.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.core.display import counted
from app.core.logging import get_logger
from app.database import repository
from app.enrichment.extractor import ExtractionResult, IOCExtractor
from app.models.event import SecurityEvent

logger = get_logger(__name__)


@dataclass
class EnrichmentSummary:
    """What an enrichment pass did."""

    events_processed: int = 0
    indicators_found: int = 0
    indicators_new: int = 0
    events_truncated: int = 0
    by_type: dict[str, int] = field(default_factory=dict)

    def merge(self, result: ExtractionResult, *, new: int) -> None:
        self.events_processed += 1
        self.indicators_found += len(result)
        self.indicators_new += new
        if result.truncated:
            self.events_truncated += 1
        for name, count in result.counts().items():
            self.by_type[name] = self.by_type.get(name, 0) + count

    def summary(self) -> str:
        parts = [
            counted(self.events_processed, "event"),
            f"{counted(self.indicators_found, 'indicator')} ({self.indicators_new} new)",
        ]
        if self.events_truncated:
            parts.append(f"{counted(self.events_truncated, 'event')} hit the per-event limit")
        return ", ".join(parts)


class EnrichmentService:
    """Extracts indicators from events and records the sightings."""

    def __init__(self, session: Session, extractor: IOCExtractor | None = None) -> None:
        self.session = session
        self.extractor = extractor or IOCExtractor()

    def enrich_event(self, event: SecurityEvent) -> tuple[ExtractionResult, int]:
        """Extract from one event, storing indicators and their links.

        Returns the extraction result and how many indicators were new.
        """
        result = self.extractor.extract(event)
        new_count = 0

        for indicator in result.indicators:
            # One indexed lookup to tell "new" from "seen again"; counting rows
            # per indicator would make enrichment quadratic in the table size.
            was_known = (
                repository.find_indicator(self.session, indicator.indicator_type, indicator.value)
                is not None
            )
            row = repository.upsert_indicator(self.session, indicator)
            if not was_known:
                new_count += 1
            repository.link_event_indicator(
                self.session,
                event.event_id,
                row.indicator_id,
                source_field=indicator.source_field,
                occurrences=indicator.occurrences,
            )
        return result, new_count

    def enrich_events(self, events: Iterable[SecurityEvent]) -> EnrichmentSummary:
        """Extract from many events."""
        summary = EnrichmentSummary()
        for event in events:
            result, new_count = self.enrich_event(event)
            summary.merge(result, new=new_count)
        if summary.events_processed:
            logger.info("enriched %s", summary.summary())
        return summary

    def backfill(self, *, limit: int = 500) -> EnrichmentSummary:
        """Run extraction over stored events that have never been enriched."""
        pending = repository.events_without_indicators(self.session, limit=limit)
        return self.enrich_events(pending)
