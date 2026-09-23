"""Stage 8 — deterministic severity, alert assembly and the triage pipeline.

Two properties matter more than sophistication: the score is reproducible, and
it shows its working. Almost every test here checks one of those.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import repository
from app.detection import DetectionEngine, load_rules
from app.ingestion import generate_demo_scenario, generate_normal_activity, get_adapter
from app.models.alert import AlertSeverity
from app.models.base import new_id
from app.models.detection import DetectionMatch, DetectionResult
from app.models.enums import AlertStatus, AuditAction, Confidence, IndicatorType, Severity
from app.models.event import SecurityEvent
from app.models.indicator import Indicator
from app.services import (
    FACTOR_NAMES,
    AlertFactory,
    SeverityEngine,
    SeverityWeights,
    TriagePipeline,
    build_title,
    load_context,
)
from app.services.context import BusinessHours, EnvironmentContext

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: A context with nothing in it, so a test exercising one factor is not
#: quietly influenced by another.
EMPTY_CONTEXT = EnvironmentContext(business_hours=BusinessHours(enabled=False))


def event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "hostname": "WIN-LAB-01",
        "username": "lab-user",
        "process_name": "powershell.exe",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)  # type: ignore[arg-type]


def detection(**overrides: object) -> DetectionResult:
    payload: dict[str, object] = {
        "rule_id": "SF-0003",
        "rule_name": "Encoded PowerShell command",
        "rule_severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "description": "PowerShell invoked with an encoded command block.",
        "matched": [
            DetectionMatch(
                field_name="command_line", condition="contains -enc", observed_value="-enc AAA="
            )
        ],
    }
    payload.update(overrides)
    return DetectionResult(**payload)  # type: ignore[arg-type]


def engine(context: EnvironmentContext | None = None) -> SeverityEngine:
    return SeverityEngine(context or EMPTY_CONTEXT)


# ---------------------------------------------------------------------------
# Environment context
# ---------------------------------------------------------------------------
class TestEnvironmentContext:
    def test_the_shipped_context_loads(self) -> None:
        context = load_context(PROJECT_ROOT / "data" / "context" / "environment.yaml")
        assert context.errors == []
        assert context.critical_hosts

    def test_exact_and_pattern_matches_say_which_applied(self) -> None:
        """The factor quotes the specific entry, so an analyst can check it."""
        context = load_context(PROJECT_ROOT / "data" / "context" / "environment.yaml")
        assert "listed as a critical host" in (context.critical_host_reason("SRV-FILE-01") or "")
        assert "pattern 'dc-*'" in (context.critical_host_reason("DC-PRIMARY") or "")
        assert context.critical_host_reason("WIN-LAB-01") is None

    def test_domain_prefixes_are_stripped_from_accounts(self) -> None:
        context = load_context(PROJECT_ROOT / "data" / "context" / "environment.yaml")
        assert context.privileged_account_reason("LAB\\svc-helper") is not None
        assert context.privileged_account_reason("lab-user") is None

    def test_a_missing_file_degrades_without_raising(self, tmp_path: Path) -> None:
        """Scoring still works; it stops applying factors it has no basis for."""
        context = load_context(tmp_path / "absent.yaml")
        assert context.critical_hosts == frozenset()
        assert "not found" in context.errors[0]

    def test_a_malformed_file_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("just a string", encoding="utf-8")
        assert "must be a mapping" in load_context(path).errors[0]

    @pytest.mark.parametrize(
        "moment, inside",
        [
            (datetime(2026, 9, 23, 13, tzinfo=UTC), True),  # Wednesday afternoon
            (datetime(2026, 9, 23, 3, tzinfo=UTC), False),  # Wednesday night
            (datetime(2026, 9, 27, 13, tzinfo=UTC), False),  # Sunday
        ],
    )
    def test_business_hours(self, moment: datetime, inside: bool) -> None:
        context = load_context(PROJECT_ROOT / "data" / "context" / "environment.yaml")
        assert context.is_out_of_hours(moment) is not inside


# ---------------------------------------------------------------------------
# Factors
# ---------------------------------------------------------------------------
class TestSeverityFactors:
    def test_the_base_score_is_the_worst_rule_not_the_sum(self) -> None:
        """Five LOW rules firing is five low observations, not a CRITICAL alert."""
        lows = [detection(rule_id=f"SF-000{i}", rule_severity=Severity.LOW) for i in range(1, 6)]
        verdict = engine().score(detections=lows, events=[event()])
        base = next(f for f in verdict.factors if f.name == "rule_severity")
        assert base.points == Severity.LOW.base_score

    def test_independent_rules_corroborate(self) -> None:
        one = engine().score(detections=[detection()], events=[event()])
        three = engine().score(
            detections=[
                detection(),
                detection(rule_id="SF-0004", rule_name="Download"),
                detection(rule_id="SF-0008", rule_name="Temp path"),
            ],
            events=[event()],
        )
        assert three.score > one.score
        assert any(f.name == "corroboration" for f in three.factors)

    def test_the_same_rule_twice_does_not_corroborate(self) -> None:
        """Repetition of one rule is not two rules agreeing."""
        verdict = engine().score(detections=[detection(), detection()], events=[event()])
        assert not any(f.name == "corroboration" for f in verdict.factors)

    def test_corroboration_is_capped(self) -> None:
        many = [detection(rule_id=f"SF-{i:04d}") for i in range(1, 12)]
        verdict = engine().score(detections=many, events=[event()])
        factor = next(f for f in verdict.factors if f.name == "corroboration")
        assert factor.points == SeverityWeights().corroboration_cap

    def test_low_confidence_reduces_the_score(self) -> None:
        """A rule that admits it is a heuristic should not carry full weight."""
        verdict = engine().score(
            detections=[detection(confidence=Confidence.LOW)], events=[event()]
        )
        factor = next(f for f in verdict.factors if f.name == "detection_confidence")
        assert factor.points < 0

    def test_high_confidence_raises_it(self) -> None:
        verdict = engine().score(
            detections=[detection(confidence=Confidence.HIGH)], events=[event()]
        )
        assert next(f for f in verdict.factors if f.name == "detection_confidence").points > 0

    def test_medium_confidence_is_neutral(self) -> None:
        verdict = engine().score(detections=[detection()], events=[event()])
        assert not any(f.name == "detection_confidence" for f in verdict.factors)

    def test_a_privileged_account_raises_the_score_and_says_why(self) -> None:
        context = EnvironmentContext(
            privileged_accounts=frozenset({"administrator"}),
            business_hours=BusinessHours(enabled=False),
        )
        verdict = engine(context).score(
            detections=[detection()], events=[event(username="LAB\\Administrator")]
        )
        factor = next(f for f in verdict.factors if f.name == "privileged_account")
        assert factor.points == SeverityWeights().privileged_account
        assert "Administrator" in factor.detail

    def test_a_critical_host_raises_the_score(self) -> None:
        context = EnvironmentContext(
            critical_host_patterns=("dc-*",), business_hours=BusinessHours(enabled=False)
        )
        verdict = engine(context).score(detections=[detection()], events=[event(hostname="DC-01")])
        assert any(f.name == "critical_host" for f in verdict.factors)

    def test_a_decoy_access_carries_extra_weight(self) -> None:
        """Deception has almost no legitimate background rate."""
        verdict = engine().score(
            detections=[detection()], events=[event(event_type="decoy_credential_access")]
        )
        factor = next(f for f in verdict.factors if f.name == "deception_signal")
        assert factor.points == SeverityWeights().deception_signal

    def test_an_external_source_address_is_noted(self) -> None:
        verdict = engine().score(detections=[detection()], events=[event(src_ip="192.0.2.77")])
        assert any(f.name == "external_source" for f in verdict.factors)

    def test_an_internal_source_address_is_not(self) -> None:
        verdict = engine().score(detections=[detection()], events=[event(src_ip="10.0.0.5")])
        assert not any(f.name == "external_source" for f in verdict.factors)

    def test_external_indicators_add_breadth(self) -> None:
        indicators = [
            Indicator(indicator_type=IndicatorType.IPV4, value="192.0.2.77"),
            Indicator(indicator_type=IndicatorType.DOMAIN, value="updates.example"),
        ]
        verdict = engine().score(detections=[detection()], events=[event()], indicators=indicators)
        factor = next(f for f in verdict.factors if f.name == "external_indicators")
        assert factor.points == 2 * SeverityWeights().external_indicator_each

    def test_internal_indicators_do_not(self) -> None:
        internal = [Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.5")]
        verdict = engine().score(detections=[detection()], events=[event()], indicators=internal)
        assert not any(f.name == "external_indicators" for f in verdict.factors)

    def test_out_of_hours_activity_is_weighted(self) -> None:
        context = EnvironmentContext(business_hours=BusinessHours(enabled=True))
        verdict = engine(context).score(
            detections=[detection()], events=[event(timestamp="2026-09-23T03:00:00Z")]
        )
        factor = next(f for f in verdict.factors if f.name == "out_of_hours")
        assert "outside working hours" in factor.detail

    def test_repeat_activity_raises_and_is_capped(self) -> None:
        one = engine().score(detections=[detection()], events=[event()], prior_alerts=1)
        many = engine().score(detections=[detection()], events=[event()], prior_alerts=50)
        assert any(f.name == "repeat_activity" for f in one.factors)
        assert next(f for f in many.factors if f.name == "repeat_activity").points == (
            SeverityWeights().repeat_activity_cap
        )

    def test_no_detections_means_no_factors(self) -> None:
        verdict = engine().score(detections=[], events=[event()])
        assert verdict.score == 0
        assert verdict.level is Severity.LOW


# ---------------------------------------------------------------------------
# The verdict itself
# ---------------------------------------------------------------------------
class TestVerdict:
    def test_scoring_is_reproducible(self) -> None:
        """Same inputs, same score. No randomness, no clock, no model."""
        detections, events = [detection()], [event()]
        first = engine().score(detections=detections, events=events)
        second = engine().score(detections=detections, events=events)
        assert first.score == second.score
        assert [f.detail for f in first.factors] == [f.detail for f in second.factors]

    def test_the_score_is_clamped_to_the_range(self) -> None:
        context = EnvironmentContext(
            critical_host_patterns=("*",),
            privileged_account_patterns=("*",),
            business_hours=BusinessHours(enabled=False),
        )
        verdict = engine(context).score(
            detections=[
                detection(rule_severity=Severity.CRITICAL, confidence=Confidence.HIGH),
                detection(rule_id="SF-0004"),
                detection(rule_id="SF-0008"),
                detection(rule_id="SF-0011"),
            ],
            events=[event(event_type="decoy_credential_access", src_ip="192.0.2.77")],
            prior_alerts=10,
        )
        assert verdict.score == 100
        assert verdict.level is Severity.CRITICAL

    @pytest.mark.parametrize(
        "score, band",
        [
            (0, Severity.LOW),
            (29, Severity.LOW),
            (30, Severity.MEDIUM),
            (59, Severity.MEDIUM),
            (60, Severity.HIGH),
            (84, Severity.HIGH),
            (85, Severity.CRITICAL),
            (100, Severity.CRITICAL),
        ],
    )
    def test_band_boundaries(self, score: int, band: Severity) -> None:
        assert AlertSeverity(score=score, level=band).level is band

    def test_every_factor_explains_itself(self) -> None:
        verdict = engine().score(
            detections=[detection(confidence=Confidence.HIGH)],
            events=[event(src_ip="192.0.2.77")],
        )
        for factor in verdict.factors:
            assert len(factor.detail) > 10
        assert "Score" in verdict.explain()

    def test_the_verdict_is_always_labelled_deterministic(self) -> None:
        assert engine().score(detections=[detection()], events=[event()]).method == "deterministic"


class TestTheAiCannotInfluenceSeverity:
    def test_every_factor_comes_from_the_engines_own_vocabulary(self) -> None:
        """No factor can originate outside this module."""
        verdict = engine().score(
            detections=[detection(), detection(rule_id="SF-0004")],
            events=[event(src_ip="192.0.2.77", event_type="decoy_credential_access")],
            indicators=[Indicator(indicator_type=IndicatorType.IPV4, value="192.0.2.77")],
            prior_alerts=2,
        )
        for factor in verdict.factors:
            assert factor.name in FACTOR_NAMES

    def test_the_engine_takes_no_ai_input(self) -> None:
        import inspect

        signature = inspect.signature(SeverityEngine.score)
        assert not any("ai" in name.lower() for name in signature.parameters)

    def test_no_factor_name_mentions_ai(self) -> None:
        assert not any(name.split("_")[0] == "ai" for name in FACTOR_NAMES)


# ---------------------------------------------------------------------------
# Alert assembly
# ---------------------------------------------------------------------------
class TestAlertAssembly:
    def test_a_title_names_the_worst_rule_the_host_and_the_user(self) -> None:
        title = build_title([detection()], event())
        assert "Encoded PowerShell command" in title
        assert "WIN-LAB-01" in title
        assert "lab-user" in title

    def test_a_title_says_when_more_than_one_rule_fired(self) -> None:
        title = build_title([detection(), detection(rule_id="SF-0004")], event())
        assert "+1 more rule" in title

    def test_the_worst_rule_leads_the_title(self) -> None:
        title = build_title(
            [
                detection(rule_id="SF-0014", rule_name="Low thing", rule_severity=Severity.LOW),
                detection(rule_id="SF-0003", rule_name="High thing", rule_severity=Severity.HIGH),
            ],
            event(),
        )
        assert title.startswith("High thing")

    def test_an_alert_carries_its_evidence_and_verdict(self) -> None:
        factory = AlertFactory(severity_engine=engine())
        alert, unknown = factory.build_alert(
            event=event(), detections=[detection(mitre_technique_ids=["T1059.001"])]
        )
        assert alert.severity.method == "deterministic"
        assert alert.rule_ids == ["SF-0003"]
        assert alert.technique_ids == ["T1059.001"]
        assert alert.status is AlertStatus.NEW
        assert unknown == []

    def test_alert_confidence_follows_the_most_confident_rule(self) -> None:
        factory = AlertFactory(severity_engine=engine())
        alert, _ = factory.build_alert(
            event=event(),
            detections=[
                detection(confidence=Confidence.LOW),
                detection(rule_id="SF-0004", confidence=Confidence.HIGH),
            ],
        )
        assert alert.confidence is Confidence.HIGH

    def test_an_unnameable_technique_is_reported_not_rendered(self) -> None:
        factory = AlertFactory(severity_engine=engine())
        alert, unknown = factory.build_alert(
            event=event(), detections=[detection(mitre_technique_ids=["T9999"])]
        )
        assert alert.mitre == []
        assert unknown == ["T9999"]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestTriagePipeline:
    def _events(self, records):
        return [get_adapter(r.adapter).normalise(r.record) for r in records]

    def test_the_demo_scenario_produces_a_spread_of_alerts(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        result = TriagePipeline(db_session, db_settings).process(events)
        db_session.commit()

        assert result.alerts_created >= 8
        counts = result.severity_counts()
        assert counts.get("critical", 0) >= 1
        assert counts.get("medium", 0) >= 1
        assert result.unknown_techniques == []

    def test_benign_activity_produces_no_alerts(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        events = self._events(
            generate_normal_activity(80, seed=5, base_time=datetime(2026, 9, 23, 9, tzinfo=UTC))
        )
        repository.save_events(db_session, events)
        result = TriagePipeline(db_session, db_settings).process(events)
        assert result.alerts_created == 0

    def test_alerts_are_persisted_with_their_factors(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        result = TriagePipeline(db_session, db_settings).process(events)
        db_session.commit()
        db_session.expunge_all()

        stored = repository.get_alert(db_session, result.alerts[0].alert_id)
        assert stored is not None
        assert stored.severity.factors
        assert stored.severity.method == "deterministic"
        assert stored.severity.score == result.alerts[0].severity.score

    def test_every_alert_creation_is_audited(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        result = TriagePipeline(db_session, db_settings).process(events)
        db_session.commit()

        trail = repository.list_audit(db_session, limit=100)
        created = [entry for entry in trail if entry.action is AuditAction.ALERT_CREATED]
        assert len(created) == result.alerts_created

    def test_a_dry_run_stores_nothing(self, db_session: Session, db_settings: Settings) -> None:
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        result = TriagePipeline(db_session, db_settings).process(events, persist=False)
        db_session.commit()

        assert result.alerts_created > 0
        assert repository.count_alerts(db_session) == 0

    def test_triaging_stored_events_is_idempotent(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """Re-running must not produce a second copy of every alert."""
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        db_session.commit()

        first = TriagePipeline(db_session, db_settings).process_stored()
        db_session.commit()
        second = TriagePipeline(db_session, db_settings).process_stored()
        db_session.commit()

        assert first.alerts_created > 0
        assert second.events_processed == 0
        assert repository.count_alerts(db_session) == first.alerts_created

    def test_the_pipeline_is_reproducible(self, db_session: Session, db_settings: Settings) -> None:
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        first = TriagePipeline(db_session, db_settings).process(events, persist=False)
        second = TriagePipeline(db_session, db_settings).process(events, persist=False)
        assert [a.severity.score for a in first.alerts] == [a.severity.score for a in second.alerts]
        assert [a.title for a in first.alerts] == [a.title for a in second.alerts]

    def test_repeat_activity_raises_a_later_alert(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """A host that has already generated alerts is a noisier host."""
        rules = load_rules(PROJECT_ROOT / "rules")
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)

        pipeline = TriagePipeline(db_session, db_settings, rules=rules)
        first = pipeline.process(events)
        db_session.commit()

        later = [
            e.model_copy(
                update={"event_id": new_id(), "timestamp": e.timestamp + timedelta(minutes=30)}
            )
            for e in events
        ]
        repository.save_events(db_session, later)
        second = TriagePipeline(db_session, db_settings, rules=rules).process(later)
        db_session.commit()

        assert any(
            f.name == "repeat_activity" for alert in second.alerts for f in alert.severity.factors
        )
        assert max(a.severity.score for a in second.alerts) >= max(
            a.severity.score for a in first.alerts
        )

    def test_detections_and_alerts_agree(self, db_session: Session, db_settings: Settings) -> None:
        rules = load_rules(PROJECT_ROOT / "rules")
        events = self._events(generate_demo_scenario())
        repository.save_events(db_session, events)
        run = DetectionEngine(rules.enabled).evaluate_events(events)
        result = TriagePipeline(db_session, db_settings, rules=rules).process(events, persist=False)
        assert result.alerts_created == len(run.results)
