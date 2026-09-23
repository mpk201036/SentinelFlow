"""Grouping related alerts into potential incidents.

An analyst's second question, after "what is wrong here?", is "is this related
to anything else?". Correlation answers it by linking alerts that share
something concrete — a host, an account, an address, a process chain, an
indicator — within a bounded time window.

Three design decisions shape this module.

**Linking is transitive, via connected components.** If A shares a host with B,
and B shares an account with C, all three belong to one investigation even
though A and C have nothing directly in common. That is how an intrusion
actually looks: the chain is the story, and grouping by a single key would cut
it into unrelated fragments.

**"Same rule" is deliberately not a link.** SF-0003 firing on forty unrelated
workstations is forty investigations, not one incident, and merging them would
bury the one that matters. The cases people actually want from rule-based
linking — a password spray from one address, one hash across many hosts — are
already covered by the address and indicator signals. A campaign view across
hosts is a genuinely useful report, but it is a different question from "is
this alert part of that incident?".

**Correlation does not invent severity.** An incident takes the highest
severity among its members and records its breadth as stated reasons ("spans 5
ATT&CK tactics", "9 alerts over 47 minutes"). Inventing a new number at this
layer would be a third scoring system nobody asked for; the breadth facts let
an analyst judge, which is the job.

Nothing here declares a compromise. The result is a *potential* incident, and
only an analyst moves it to confirmed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.database import repository
from app.models.alert import Alert
from app.models.enums import IncidentStatus, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident

logger = get_logger(__name__)

#: A group larger than this is almost certainly over-linked - one very busy
#: host swallowing unrelated activity. It is still produced, but it is flagged.
OVERSIZED_GROUP = 200

#: Indicator types worth linking on. Process names and paths are far too common
#: to link across hosts: every workstation runs powershell.exe.
LINKABLE_INDICATORS = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"})


@dataclass(frozen=True)
class Signal:
    """One thing two alerts can have in common."""

    kind: str
    value: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def describe(self) -> str:
        labels = {
            "host": "the same host",
            "user": "the same account",
            "address": "the same network address",
            "process_chain": "the same process chain",
            "indicator": "the same indicator",
        }
        return f"{labels.get(self.kind, self.kind)} ({self.value})"


def signals_for(alert: Alert, event: SecurityEvent | None) -> set[Signal]:
    """Everything an alert can be linked on."""
    found: set[Signal] = set()

    if event is not None:
        if event.hostname_key:
            found.add(Signal("host", event.hostname_key))
        if event.username_key:
            found.add(Signal("user", event.username_key))
        for address in (event.src_ip, event.dst_ip):
            if address:
                found.add(Signal("address", address))
        if event.process_name_key and event.parent_process:
            found.add(
                Signal("process_chain", f"{event.parent_process.lower()}>{event.process_name_key}")
            )

    for indicator in alert.indicators:
        if indicator.indicator_type.value not in LINKABLE_INDICATORS:
            continue
        if indicator.is_internal:
            # An internal address is usually the estate's own infrastructure -
            # a DNS server or proxy that every host talks to. Linking on it
            # would merge everything.
            continue
        found.add(Signal("indicator", f"{indicator.indicator_type.value}:{indicator.value}"))

    return found


class _DisjointSet:
    """Union-find over alert indices."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, left: int, right: int) -> bool:
        root_left, root_right = self.find(left), self.find(right)
        if root_left == root_right:
            return False
        self._parent[root_right] = root_left
        return True


@dataclass
class CorrelationGroup:
    """A set of alerts that belong to one investigation."""

    alerts: list[Alert] = field(default_factory=list)
    events: dict[UUID, SecurityEvent] = field(default_factory=dict)
    linking_signals: set[Signal] = field(default_factory=set)
    oversized: bool = False

    def __len__(self) -> int:
        return len(self.alerts)

    @property
    def severity(self) -> Severity:
        return Severity.highest(a.severity_level for a in self.alerts) or Severity.LOW

    @property
    def worst_alert(self) -> Alert:
        return max(self.alerts, key=lambda a: a.severity.score)

    def timespan(self) -> tuple[datetime | None, datetime | None]:
        moments = [
            self.events[a.primary_event_id].timestamp
            for a in self.alerts
            if a.primary_event_id in self.events
        ]
        return (min(moments), max(moments)) if moments else (None, None)

    def hostnames(self) -> list[str]:
        return sorted({e.hostname for e in self.events.values() if e.hostname})

    def usernames(self) -> list[str]:
        return sorted({e.username for e in self.events.values() if e.username})

    def rule_ids(self) -> list[str]:
        return sorted({rule_id for alert in self.alerts for rule_id in alert.rule_ids})

    def tactics(self) -> list[str]:
        seen: set[str] = set()
        for alert in self.alerts:
            for mapping in alert.mitre:
                seen.update(mapping.technique.tactics)
        return sorted(seen)

    def technique_ids(self) -> list[str]:
        return sorted({t for alert in self.alerts for t in alert.technique_ids})


class CorrelationEngine:
    """Links alerts into groups, with the reason for every link recorded."""

    def __init__(self, window_minutes: int = 30) -> None:
        self.window = timedelta(minutes=window_minutes)

    # ------------------------------------------------------------------
    def group(self, pairs: Sequence[tuple[Alert, SecurityEvent | None]]) -> list[CorrelationGroup]:
        """Group alerts into connected components of shared signals."""
        if not pairs:
            return []

        ordered = sorted(pairs, key=lambda pair: _moment(pair[0], pair[1]))
        signals = [signals_for(alert, event) for alert, event in ordered]
        sets = _DisjointSet(len(ordered))
        links: dict[int, set[Signal]] = {}

        # Sliding window: only compare alerts that are close enough in time to
        # be part of the same activity.
        start = 0
        for index in range(len(ordered)):
            current = _moment(*ordered[index])
            while current - _moment(*ordered[start]) > self.window:
                start += 1
            for other in range(start, index):
                shared = signals[index] & signals[other]
                if not shared:
                    continue
                sets.union(other, index)
                links.setdefault(sets.find(index), set()).update(shared)

        # Assemble components.
        buckets: dict[int, CorrelationGroup] = {}
        for index, (alert, event) in enumerate(ordered):
            root = sets.find(index)
            bucket = buckets.setdefault(root, CorrelationGroup())
            bucket.alerts.append(alert)
            if event is not None:
                bucket.events[event.event_id] = event

        for root, bucket in buckets.items():
            bucket.linking_signals = links.get(root, set())
            if len(bucket) > OVERSIZED_GROUP:
                bucket.oversized = True
                logger.warning(
                    "correlation group of %s alerts exceeds the expected size; "
                    "a very busy host may be over-linking",
                    len(bucket),
                )

        groups = sorted(
            buckets.values(),
            key=lambda item: (-item.severity.rank, -len(item)),
        )
        logger.info(
            "correlated %s alerts into %s group(s)",
            len(ordered),
            sum(1 for g in groups if len(g) > 1),
        )
        return groups

    # ------------------------------------------------------------------
    def build_incident(self, group: CorrelationGroup) -> Incident:
        """Describe a group as a potential incident, in facts only."""
        first, last = group.timespan()
        hosts = group.hostnames()
        reasons = self._reasons(group, first, last)

        return Incident(
            title=self._title(group, hosts),
            status=IncidentStatus.POTENTIAL,
            severity=group.severity,
            alert_ids=[alert.alert_id for alert in group.alerts],
            correlation_key=self._correlation_key(group, hosts),
            correlation_reasons=reasons,
            first_event_at=first,
            last_event_at=last,
            hostnames=hosts,
            usernames=group.usernames(),
            summary=self._summary(group, first, last),
        )

    def _title(self, group: CorrelationGroup, hosts: list[str]) -> str:
        worst = group.worst_alert
        lead = worst.detections[0].rule_name if worst.detections else worst.title
        others = len(group) - 1
        where = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
        if others <= 0:
            return f"{lead} on {where}"[:256]
        return f"{lead} and {others} related alert{'s' if others > 1 else ''} on {where}"[:256]

    def _correlation_key(self, group: CorrelationGroup, hosts: list[str]) -> str:
        """The strongest shared signal, used as the group's identity."""
        for kind in ("host", "user", "indicator", "address", "process_chain"):
            matching = sorted(s.key for s in group.linking_signals if s.kind == kind)
            if matching:
                return matching[0][:256]
        if hosts:
            return f"host:{hosts[0].lower()}"
        return f"alert:{group.alerts[0].alert_id}"

    def _reasons(
        self, group: CorrelationGroup, first: datetime | None, last: datetime | None
    ) -> list[str]:
        """Why these alerts are together, and how broad the activity is."""
        reasons: list[str] = []
        by_kind: dict[str, list[str]] = {}
        for signal in sorted(group.linking_signals, key=lambda s: s.key):
            by_kind.setdefault(signal.kind, []).append(signal.value)
        for kind, values in by_kind.items():
            shown = ", ".join(values[:4])
            extra = f" and {len(values) - 4} more" if len(values) > 4 else ""
            reasons.append(f"Linked by {Signal(kind, shown).describe()}{extra}")

        if first and last:
            minutes = int((last - first).total_seconds() // 60)
            span = f"{minutes} minutes" if minutes else "under a minute"
            reasons.append(f"{len(group)} alerts spanning {span}")

        rules = group.rule_ids()
        if len(rules) > 1:
            reasons.append(f"{len(rules)} distinct rules matched: {', '.join(rules)}")

        tactics = group.tactics()
        if len(tactics) > 1:
            reasons.append(f"Spans {len(tactics)} ATT&CK tactics: {', '.join(tactics)}")

        if group.oversized:
            reasons.append("This group is unusually large and may be over-linked by a busy host")
        return reasons

    def _summary(
        self, group: CorrelationGroup, first: datetime | None, last: datetime | None
    ) -> str:
        """A factual description. No conclusion is drawn."""
        parts = [
            f"{len(group)} correlated alerts",
            f"highest severity {group.severity.value}",
        ]
        if first and last:
            parts.append(f"from {first.strftime('%Y-%m-%d %H:%M')} to {last.strftime('%H:%M')} UTC")
        hosts = group.hostnames()
        if hosts:
            parts.append(f"on {', '.join(hosts[:3])}")
        users = group.usernames()
        if users:
            parts.append(f"involving {', '.join(users[:3])}")
        techniques = group.technique_ids()
        if techniques:
            parts.append(f"mapped to {', '.join(techniques[:6])}")
        return (
            ". ".join([", ".join(parts)])
            + ". This is a potential incident awaiting analyst review; no compromise is asserted."
        )[:4096]


def _moment(alert: Alert, event: SecurityEvent | None) -> datetime:
    """The time an alert's activity happened, preferring the event's own."""
    return event.timestamp if event is not None else alert.created_at


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
@dataclass
class CorrelationResult:
    """What one correlation pass did."""

    created: list[Incident] = field(default_factory=list)
    extended: list[Incident] = field(default_factory=list)
    alerts_considered: int = 0
    alerts_grouped: int = 0
    singletons: int = 0

    @property
    def incident_count(self) -> int:
        return len(self.created) + len(self.extended)

    def summary(self) -> str:
        parts = [
            f"{self.alerts_considered} alerts considered",
            f"{len(self.created)} incidents created",
        ]
        if self.extended:
            parts.append(f"{len(self.extended)} extended")
        if self.singletons:
            parts.append(f"{self.singletons} alerts remain standalone")
        return ", ".join(parts)


class CorrelationService:
    """Runs correlation against stored alerts and records the result."""

    #: An incident needs at least this many alerts. A single alert is just an
    #: alert; wrapping it in an incident adds a layer and no information.
    MIN_GROUP_SIZE = 2

    def __init__(
        self,
        session: Session,
        settings: Settings | None = None,
        engine: CorrelationEngine | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.engine = engine or CorrelationEngine(
            window_minutes=self.settings.correlation_window_minutes
        )

    def correlate_pending(self, *, limit: int = 1_000) -> CorrelationResult:
        """Correlate alerts that have not been placed in an incident yet.

        Alerts already in an incident are loaded too, within the window, so a
        new alert can extend an existing investigation instead of starting a
        parallel one beside it.
        """
        result = CorrelationResult()
        pending = repository.alerts_without_incident(self.session, limit=limit)
        if not pending:
            return result

        # Anchored on event time, not on when the alert row was written: an
        # alert created today from a week-old export describes activity from a
        # week ago, and grouping by write time would put it beside whatever
        # else happened to be imported this afternoon.
        earliest = min(event.timestamp for _, event in pending)
        context = repository.alerts_with_events_since(self.session, earliest - self.engine.window)

        by_id: dict[UUID, tuple[Alert, SecurityEvent | None]] = {
            alert.alert_id: (alert, event) for alert, event in context
        }
        for alert, event in pending:
            by_id[alert.alert_id] = (alert, event)
        pairs = list(by_id.values())
        result.alerts_considered = len(pairs)

        for group in self.engine.group(pairs):
            if len(group) < self.MIN_GROUP_SIZE:
                result.singletons += len(group)
                continue
            result.alerts_grouped += len(group)
            self._record(group, result)

        logger.info("correlation: %s", result.summary())
        return result

    def _record(self, group: CorrelationGroup, result: CorrelationResult) -> None:
        """Create or extend the incident for one group."""
        existing_ids = sorted({a.incident_id for a in group.alerts if a.incident_id is not None})
        incident = self.engine.build_incident(group)

        if not existing_ids:
            repository.save_incident(self.session, incident)
            result.created.append(incident)
            return

        # Attach to the oldest existing incident. Alerts already belonging to a
        # different one are left alone - moving them would rewrite somebody's
        # investigation - and the overlap is recorded instead.
        target = existing_ids[0]
        if len(existing_ids) > 1:
            others = ", ".join(str(item)[:8] for item in existing_ids[1:])
            incident.correlation_reasons.append(
                f"Also related to incident(s) {others}, which were left intact"
            )
        merged = incident.model_copy(update={"incident_id": target})
        repository.upsert_incident(self.session, merged)
        result.extended.append(merged)
