"""Numbers for the analyst console, computed once and shared.

The HTML dashboard and ``GET /api/v1/stats`` read from this single builder, so
the page and the API can never disagree about how many alerts are open. Before
this module existed the stats endpoint computed its own figures inline and
returned an empty ``top_rules`` - a panel with nothing behind it.

Every figure is scoped to one time window, on event time. A filter row that
narrows one chart but not the tiles beside it produces numbers that do not add
up, so the window is applied to everything or nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.database import repository
from app.mitre import Catalogue, get_catalogue
from app.models.alert import Alert
from app.models.base import utcnow
from app.models.enums import AlertStatus, Severity
from app.models.event import SecurityEvent

#: The windows the filter row offers, and the label each one shows.
RANGES: dict[str, tuple[str, timedelta | None]] = {
    "24h": ("Last 24 hours", timedelta(hours=24)),
    "7d": ("Last 7 days", timedelta(days=7)),
    "30d": ("Last 30 days", timedelta(days=30)),
    "all": ("All time", None),
}
DEFAULT_RANGE = "all"

#: Lower bound for "all time"; earlier than any plausible event.
_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)

#: Severity bands in display order, most urgent first.
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass
class TechniqueCount:
    technique_id: str
    name: str
    alerts: int
    url: str


@dataclass
class DashboardStats:
    """Everything the overview page and the stats endpoint show."""

    range_key: str
    range_label: str
    since: datetime | None
    generated_at: datetime

    events: int = 0
    incidents: int = 0
    indicators: int = 0
    rejected_events: int = 0

    severity_counts: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)
    top_hosts: list[tuple[str, int]] = field(default_factory=list)
    top_rules: list[tuple[str, str, int]] = field(default_factory=list)
    trend: list[tuple[datetime, Severity]] = field(default_factory=list)
    techniques_by_tactic: dict[str, list[TechniqueCount]] = field(default_factory=dict)
    recent_alerts: list[tuple[Alert, SecurityEvent]] = field(default_factory=list)

    @property
    def alerts_total(self) -> int:
        return sum(self.severity_counts.values())

    @property
    def alerts_open(self) -> int:
        return sum(
            count for state, count in self.status_counts.items() if AlertStatus(state).is_open
        )

    @property
    def techniques_observed(self) -> list[str]:
        return sorted(
            {t.technique_id for items in self.techniques_by_tactic.values() for t in items}
        )

    @property
    def tactics_covered(self) -> int:
        return sum(1 for items in self.techniques_by_tactic.values() if items)

    @property
    def is_empty(self) -> bool:
        return self.alerts_total == 0


def resolve_range(key: str | None) -> str:
    """An unknown range falls back to the default rather than erroring."""
    return key if key in RANGES else DEFAULT_RANGE


def collect_dashboard_stats(
    session: Session,
    *,
    range_key: str | None = None,
    catalogue: Catalogue | None = None,
    now: datetime | None = None,
) -> DashboardStats:
    """Gather every dashboard figure for one window."""
    key = resolve_range(range_key)
    label, span = RANGES[key]
    moment = now or utcnow()
    since = moment - span if span is not None else None
    catalogue = catalogue if catalogue is not None else get_catalogue()

    counts = repository.alert_counts(session, since=since)
    stats = DashboardStats(
        range_key=key,
        range_label=label,
        since=since,
        generated_at=moment,
        events=repository.count_events(session),
        incidents=repository.count_incidents(session),
        indicators=repository.count_indicators(session),
        rejected_events=repository.count_rejections(session),
        severity_counts={s.value: counts["severity"].get(s.value, 0) for s in SEVERITY_ORDER},
        status_counts={s.value: counts["status"].get(s.value, 0) for s in AlertStatus},
        top_hosts=repository.top_alert_hosts(session, since=since),
        top_rules=repository.top_alert_rules(session, since=since),
        trend=repository.alert_event_times(session, since=since),
    )

    # Group observed techniques by tactic, in the matrix's own order, so the
    # page can show where along the kill chain the activity sits - and where
    # nothing was seen.
    grouped: dict[str, list[TechniqueCount]] = {name: [] for name in catalogue.tactic_names()}
    for technique_id, alerts in repository.observed_techniques(session, since=since):
        technique = catalogue.get(technique_id)
        if technique is None:
            continue
        entry = TechniqueCount(technique_id, technique.name, alerts, technique.url)
        for tactic in technique.tactics:
            grouped.setdefault(tactic, []).append(entry)
    stats.techniques_by_tactic = grouped

    # One join, newest activity first. Event time again: an alert raised today
    # from an old export is not "recent" activity.
    pairs = repository.alerts_with_events_since(session, since or _EPOCH, limit=2_000)
    stats.recent_alerts = sorted(pairs, key=lambda pair: pair[1].timestamp, reverse=True)[:8]
    return stats
