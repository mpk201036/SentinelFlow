"""Stage 9 — correlating alerts into potential incidents.

Correlation is a balance between two failures: cutting one intrusion into
unrelated fragments, and merging unrelated investigations into one useless
blob. Most of these tests pin down where that line sits.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import repository
from app.ingestion import generate_demo_scenario, get_adapter
from app.models.alert import Alert, AlertSeverity, SeverityFactor
from app.models.enums import IncidentStatus, IndicatorType, Severity
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services import CorrelationEngine, CorrelationService, Signal, TriagePipeline, signals_for

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 9, 23, 13, 0, tzinfo=UTC)


def event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": BASE,
        "source": "sysmon",
        "event_type": "process_creation",
        "hostname": "WIN-LAB-01",
        "username": "lab-user",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)  # type: ignore[arg-type]


def alert(event_source: SecurityEvent, *, score: int = 65, **overrides: object) -> Alert:
    payload: dict[str, object] = {
        "title": "Test alert",
        "primary_event_id": event_source.event_id,
        "severity": AlertSeverity.from_factors(
            [SeverityFactor(name="rule_severity", points=score, detail="A rule matched the event")]
        ),
    }
    payload.update(overrides)
    return Alert(**payload)  # type: ignore[arg-type]


def pair(**overrides: object) -> tuple[Alert, SecurityEvent]:
    source = event(**overrides)
    return (alert(source), source)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------
class TestSignals:
    def test_host_user_and_addresses_are_signals(self) -> None:
        source = event(src_ip="192.0.2.77", dst_ip="10.0.0.5")
        found = {s.key for s in signals_for(alert(source), source)}
        assert "host:win-lab-01" in found
        assert "user:lab-user" in found
        assert "address:192.0.2.77" in found

    def test_a_process_chain_is_a_signal(self) -> None:
        source = event(process_name="powershell.exe", parent_process="cmd.exe")
        assert Signal("process_chain", "cmd.exe>powershell.exe") in signals_for(
            alert(source), source
        )

    def test_external_indicators_are_signals(self) -> None:
        source = event()
        with_indicators = alert(
            source,
            indicators=[Indicator(indicator_type=IndicatorType.SHA256, value="a" * 64)],
        )
        assert Signal("indicator", f"sha256:{'a' * 64}") in signals_for(with_indicators, source)

    def test_internal_addresses_are_not_indicator_signals(self) -> None:
        """A DNS server or proxy every host talks to would merge everything."""
        source = event()
        with_internal = alert(
            source, indicators=[Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.53")]
        )
        assert not any(s.kind == "indicator" for s in signals_for(with_internal, source))

    def test_process_names_are_not_linkable_indicators(self) -> None:
        """Every workstation runs powershell.exe."""
        source = event()
        with_process = alert(
            source,
            indicators=[
                Indicator(indicator_type=IndicatorType.PROCESS_NAME, value="powershell.exe")
            ],
        )
        assert not any(s.kind == "indicator" for s in signals_for(with_process, source))

    def test_an_alert_with_no_event_yields_only_indicator_signals(self) -> None:
        source = event()
        assert signals_for(alert(source), None) == set()


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------
class TestGrouping:
    def test_alerts_on_the_same_host_are_grouped(self) -> None:
        pairs = [pair(), pair(timestamp=BASE + timedelta(minutes=5))]
        groups = CorrelationEngine(30).group(pairs)
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_alerts_on_different_hosts_are_not(self) -> None:
        pairs = [
            pair(hostname="WIN-LAB-01", username="alice"),
            pair(hostname="WIN-LAB-02", username="bob", timestamp=BASE + timedelta(minutes=5)),
        ]
        assert len(CorrelationEngine(30).group(pairs)) == 2

    def test_linking_is_transitive(self) -> None:
        """A shares a host with B, B shares an account with C: one investigation."""
        pairs = [
            pair(hostname="WIN-LAB-01", username="alice"),
            pair(hostname="WIN-LAB-01", username="bob", timestamp=BASE + timedelta(minutes=2)),
            pair(hostname="WIN-LAB-09", username="bob", timestamp=BASE + timedelta(minutes=4)),
        ]
        groups = CorrelationEngine(30).group(pairs)
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_the_time_window_bounds_grouping(self) -> None:
        pairs = [pair(), pair(timestamp=BASE + timedelta(hours=5))]
        assert len(CorrelationEngine(30).group(pairs)) == 2

    def test_a_chain_of_close_alerts_spans_more_than_one_window(self) -> None:
        """Each link is within the window even though the ends are not."""
        pairs = [pair(timestamp=BASE + timedelta(minutes=20 * step)) for step in range(5)]
        groups = CorrelationEngine(30).group(pairs)
        assert len(groups) == 1
        assert len(groups[0]) == 5

    def test_the_same_rule_on_unrelated_hosts_does_not_link(self) -> None:
        """Forty workstations firing SF-0003 is forty investigations."""
        pairs = []
        for index in range(4):
            source = event(hostname=f"WIN-LAB-{index:02d}", username=f"user{index}")
            pairs.append((alert(source, tags=["sf-0003"]), source))
        assert len(CorrelationEngine(30).group(pairs)) == 4

    def test_a_shared_external_address_links_across_hosts(self) -> None:
        """A password spray from one address is one investigation."""
        pairs = [
            pair(hostname="WIN-LAB-01", username="alice", src_ip="192.0.2.77"),
            pair(
                hostname="WIN-LAB-02",
                username="bob",
                src_ip="192.0.2.77",
                timestamp=BASE + timedelta(minutes=3),
            ),
        ]
        groups = CorrelationEngine(30).group(pairs)
        assert len(groups) == 1

    def test_groups_are_ordered_by_severity(self) -> None:
        low_event = event(hostname="HOST-A", username="a")
        high_event = event(hostname="HOST-B", username="b")
        pairs = [(alert(low_event, score=20), low_event), (alert(high_event, score=90), high_event)]
        groups = CorrelationEngine(30).group(pairs)
        assert groups[0].severity is Severity.CRITICAL

    def test_an_oversized_group_is_flagged(self) -> None:
        pairs = [pair(timestamp=BASE + timedelta(seconds=index)) for index in range(205)]
        group = CorrelationEngine(60).group(pairs)[0]
        assert group.oversized is True

    def test_no_pairs_means_no_groups(self) -> None:
        assert CorrelationEngine(30).group([]) == []


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class TestIncidentDescription:
    def _group(self):
        pairs = [
            pair(src_ip="192.0.2.77"),
            pair(timestamp=BASE + timedelta(minutes=5), username="svc-helper"),
        ]
        return CorrelationEngine(30).group(pairs)[0]

    def test_an_incident_starts_as_potential(self) -> None:
        incident = CorrelationEngine(30).build_incident(self._group())
        assert incident.status is IncidentStatus.POTENTIAL
        assert incident.display_label == "Potential Incident"
        assert not incident.is_confirmed

    def test_no_compromise_is_asserted(self) -> None:
        """The wording is the claim, and the claim must stay modest."""
        incident = CorrelationEngine(30).build_incident(self._group())
        assert "no compromise is asserted" in (incident.summary or "")
        for word in ("compromised", "breach", "attacker"):
            assert word not in (incident.summary or "").lower()

    def test_severity_is_the_highest_member_not_a_new_number(self) -> None:
        """Correlation does not invent a third scoring system."""
        low_event = event()
        high_event = event(timestamp=BASE + timedelta(minutes=1))
        group = CorrelationEngine(30).group(
            [(alert(low_event, score=20), low_event), (alert(high_event, score=90), high_event)]
        )[0]
        incident = CorrelationEngine(30).build_incident(group)
        assert incident.severity is Severity.CRITICAL

    def test_every_link_is_explained(self) -> None:
        incident = CorrelationEngine(30).build_incident(self._group())
        assert any("Linked by" in reason for reason in incident.correlation_reasons)
        assert any("alerts spanning" in reason for reason in incident.correlation_reasons)

    def test_the_window_is_recorded(self) -> None:
        incident = CorrelationEngine(30).build_incident(self._group())
        assert incident.first_event_at == BASE
        assert incident.last_event_at == BASE + timedelta(minutes=5)

    def test_hosts_and_accounts_are_collected(self) -> None:
        incident = CorrelationEngine(30).build_incident(self._group())
        assert incident.hostnames == ["win-lab-01"]
        assert set(incident.usernames) == {"lab-user", "svc-helper"}

    def test_the_correlation_key_names_the_strongest_signal(self) -> None:
        incident = CorrelationEngine(30).build_incident(self._group())
        assert incident.correlation_key.startswith("host:")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestCorrelationService:
    def _triage(self, session: Session, settings: Settings, records=None):
        events = [
            get_adapter(r.adapter).normalise(r.record)
            for r in (records or generate_demo_scenario())
        ]
        repository.save_events(session, events)
        TriagePipeline(session, settings).process(events)
        session.commit()
        return events

    def test_the_demo_scenario_becomes_one_investigation(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        self._triage(db_session, db_settings)
        result = CorrelationService(db_session, db_settings).correlate_pending()
        db_session.commit()

        assert len(result.created) == 1
        incident = result.created[0]
        assert incident.alert_count >= 8
        assert incident.severity is Severity.CRITICAL
        assert incident.status is IncidentStatus.POTENTIAL

    def test_alerts_are_attached_to_the_incident(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        self._triage(db_session, db_settings)
        result = CorrelationService(db_session, db_settings).correlate_pending()
        db_session.commit()
        db_session.expunge_all()

        incident_id = result.created[0].incident_id
        members = repository.list_alerts(db_session, incident_id=incident_id, limit=100)
        assert len(members) == result.created[0].alert_count

    def test_correlation_is_idempotent(self, db_session: Session, db_settings: Settings) -> None:
        self._triage(db_session, db_settings)
        service = CorrelationService(db_session, db_settings)
        service.correlate_pending()
        db_session.commit()
        second = service.correlate_pending()
        db_session.commit()

        assert second.alerts_considered == 0
        assert repository.count_incidents(db_session) == 1

    def test_correlation_uses_event_time_not_row_time(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """Alerts written today from a week-old export describe week-old activity.

        The alert rows are all created within the same second, so grouping by
        creation time would merge everything regardless of the window.
        """
        events = [
            event(hostname="HOST-A", username="a"),
            event(hostname="HOST-A", username="a", timestamp=BASE - timedelta(days=7)),
        ]
        repository.save_events(db_session, events)
        for source in events:
            repository.save_alert(db_session, alert(source))
        db_session.commit()

        result = CorrelationService(db_session, db_settings).correlate_pending()
        db_session.commit()
        assert result.created == []
        assert result.singletons == 2

    def test_a_standalone_alert_does_not_become_an_incident(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """A single alert is just an alert; wrapping it adds a layer, not information."""
        source = event()
        repository.save_events(db_session, [source])
        repository.save_alert(db_session, alert(source))
        db_session.commit()

        result = CorrelationService(db_session, db_settings).correlate_pending()
        assert result.created == []
        assert result.singletons == 1

    def test_a_new_alert_extends_an_existing_incident(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        self._triage(db_session, db_settings)
        service = CorrelationService(db_session, db_settings)
        first = service.correlate_pending()
        db_session.commit()
        incident_id = first.created[0].incident_id
        before = first.created[0].alert_count

        later = event(timestamp=(first.created[0].last_event_at or BASE) + timedelta(minutes=5))
        repository.save_events(db_session, [later])
        repository.save_alert(db_session, alert(later, score=90))
        db_session.commit()

        second = service.correlate_pending()
        db_session.commit()

        assert second.extended
        assert second.extended[0].incident_id == incident_id
        assert repository.count_incidents(db_session) == 1
        stored = repository.get_incident(db_session, incident_id)
        assert stored is not None and stored.alert_count > before

    def test_extending_does_not_reset_analyst_state(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """Correlation finding another alert must not undo somebody's work."""
        self._triage(db_session, db_settings)
        service = CorrelationService(db_session, db_settings)
        incident_id = service.correlate_pending().created[0].incident_id
        db_session.commit()

        repository.update_incident_status(db_session, incident_id, IncidentStatus.INVESTIGATING)
        db_session.commit()

        later = event(timestamp=BASE + timedelta(minutes=3))
        repository.save_events(db_session, [later])
        repository.save_alert(db_session, alert(later))
        db_session.commit()
        service.correlate_pending()
        db_session.commit()

        stored = repository.get_incident(db_session, incident_id)
        assert stored is not None
        assert stored.status is IncidentStatus.INVESTIGATING

    def test_an_alert_already_in_an_incident_is_never_moved(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        first_event = event(hostname="HOST-A", username="a")
        second_event = event(hostname="HOST-A", username="a", timestamp=BASE + timedelta(minutes=1))
        repository.save_events(db_session, [first_event, second_event])
        kept = alert(first_event)
        repository.save_alert(db_session, kept)
        repository.save_alert(db_session, alert(second_event))
        db_session.commit()

        service = CorrelationService(db_session, db_settings)
        original = service.correlate_pending().created[0].incident_id
        db_session.commit()

        third = event(hostname="HOST-A", username="a", timestamp=BASE + timedelta(minutes=2))
        repository.save_events(db_session, [third])
        repository.save_alert(db_session, alert(third))
        db_session.commit()
        service.correlate_pending()
        db_session.commit()

        stored = repository.get_alert(db_session, kept.alert_id)
        assert stored is not None
        assert stored.incident_id == original

    def test_nothing_to_correlate_is_not_an_error(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        result = CorrelationService(db_session, db_settings).correlate_pending()
        assert result.alerts_considered == 0
        assert "0 alerts considered" in result.summary()
