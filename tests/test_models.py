"""Stage 2 — indicators, detections, MITRE mappings, alerts, incidents, audit."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import (
    Actor,
    Alert,
    AlertSeverity,
    AlertStatus,
    AnalystNote,
    AuditAction,
    AuditEntry,
    Classification,
    Confidence,
    DetectionMatch,
    DetectionResult,
    Incident,
    IncidentStatus,
    Indicator,
    IndicatorType,
    MitreMapping,
    MitreTechnique,
    Severity,
    SeverityFactor,
    utcnow,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class TestSeverityOrdering:
    def test_ordering_is_by_rank_not_alphabetical(self) -> None:
        """'high' < 'low' as strings. Getting this wrong would silently invert triage."""
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
        assert not Severity.HIGH < Severity.LOW

    def test_max_picks_the_worst(self) -> None:
        assert (
            Severity.highest([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])
            is Severity.CRITICAL
        )
        assert Severity.highest([]) is None

    @pytest.mark.parametrize(
        "score, expected",
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
    def test_score_bands(self, score: int, expected: Severity) -> None:
        assert Severity.from_score(score) is expected


class TestStatusSemantics:
    @pytest.mark.parametrize(
        "status, expected",
        [
            (AlertStatus.NEW, True),
            (AlertStatus.INVESTIGATING, True),
            (AlertStatus.ESCALATED, True),
            (AlertStatus.BENIGN, False),
            (AlertStatus.CLOSED, False),
        ],
    )
    def test_open_statuses(self, status: AlertStatus, expected: bool) -> None:
        assert status.is_open is expected

    def test_incidents_start_as_potential(self) -> None:
        """SentinelFlow never declares a compromise on its own."""
        assert Incident(title="t", severity=Severity.HIGH, correlation_key="k").status is (
            IncidentStatus.POTENTIAL
        )


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------
class TestIndicator:
    def test_values_are_normalised_by_type(self) -> None:
        assert Indicator(indicator_type=IndicatorType.DOMAIN, value="EVIL.Example.com.").value == (
            "evil.example.com"
        )
        assert Indicator(indicator_type=IndicatorType.SHA256, value="A" * 64).value == "a" * 64

    def test_hash_length_must_match_the_declared_type(self) -> None:
        with pytest.raises(ValidationError, match="64 hex characters"):
            Indicator(indicator_type=IndicatorType.SHA256, value="a" * 32)

    @pytest.mark.parametrize(
        "value, expected", [("10.0.0.5", True), ("127.0.0.1", True), ("8.8.8.8", False)]
    )
    def test_internal_address_detection(self, value: str, expected: bool) -> None:
        assert Indicator(indicator_type=IndicatorType.IPV4, value=value).is_internal is expected

    def test_non_ip_indicators_are_never_internal(self) -> None:
        assert (
            Indicator(indicator_type=IndicatorType.DOMAIN, value="a.example").is_internal is False
        )

    def test_merging_extends_the_sighting_window(self) -> None:
        now = utcnow()
        first = Indicator(
            indicator_type=IndicatorType.IPV4,
            value="10.0.0.5",
            first_seen=now - timedelta(hours=2),
            last_seen=now - timedelta(hours=2),
        )
        second = Indicator(
            indicator_type=IndicatorType.IPV4, value="10.0.0.5", first_seen=now, last_seen=now
        )
        merged = first.merged_with(second)
        assert merged.occurrences == 2
        assert merged.first_seen == first.first_seen
        assert merged.last_seen == second.last_seen

    def test_merging_different_indicators_is_refused(self) -> None:
        a = Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.5")
        b = Indicator(indicator_type=IndicatorType.IPV4, value="10.0.0.6")
        with pytest.raises(ValueError, match="different type or value"):
            a.merged_with(b)

    def test_empty_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Indicator(indicator_type=IndicatorType.DOMAIN, value="   ")


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------
class TestMitre:
    def test_technique_ids_are_validated_and_upper_cased(self) -> None:
        assert (
            MitreTechnique(technique_id="t1059.001", name="PowerShell").technique_id == "T1059.001"
        )

    @pytest.mark.parametrize("bad", ["T105", "1059", "TA0002", "T1059.1", "powershell"])
    def test_invalid_technique_ids_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not a valid ATT&CK technique ID"):
            MitreTechnique(technique_id=bad, name="x")

    def test_subtechnique_relationships(self) -> None:
        technique = MitreTechnique(technique_id="T1059.001", name="PowerShell")
        assert technique.is_subtechnique
        assert technique.parent_id == "T1059"
        assert technique.url == "https://attack.mitre.org/techniques/T1059/001/"

    def test_base_technique_is_its_own_parent(self) -> None:
        technique = MitreTechnique(technique_id="T1110", name="Brute Force")
        assert not technique.is_subtechnique
        assert technique.parent_id == "T1110"

    def test_a_mapping_must_justify_itself(self) -> None:
        """Fabricated ATT&CK decoration is how analysts learn to distrust a tool."""
        technique = MitreTechnique(technique_id="T1110", name="Brute Force")
        with pytest.raises(ValidationError):
            MitreMapping(technique=technique, reason="yes")

    def test_a_valid_mapping_carries_its_evidence(self) -> None:
        technique = MitreTechnique(technique_id="T1110", name="Brute Force")
        mapping = MitreMapping(
            technique=technique,
            reason="12 failed logons for lab-user on WIN-LAB-01 within 5 minutes",
            source_rule_id="SF-0001",
        )
        assert mapping.technique_id == "T1110"
        assert mapping.confidence is Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------
class TestDetectionResult:
    def _result(self, **overrides: object) -> DetectionResult:
        payload: dict[str, object] = {
            "rule_id": "SF-0003",
            "rule_name": "Encoded PowerShell command",
            "rule_severity": Severity.HIGH,
            "description": "PowerShell invoked with an encoded command block.",
        }
        payload.update(overrides)
        return DetectionResult(**payload)

    def test_minimal_result(self) -> None:
        result = self._result()
        assert result.rule_id == "SF-0003"
        assert result.confidence is Confidence.MEDIUM
        assert result.matched == []

    @pytest.mark.parametrize("bad", ["", "ab", "rule id with spaces", "x" * 80])
    def test_invalid_rule_ids_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not a valid rule id"):
            self._result(rule_id=bad)

    def test_technique_ids_are_validated(self) -> None:
        assert self._result(mitre_technique_ids="t1059.001").mitre_technique_ids == ["T1059.001"]
        with pytest.raises(ValidationError):
            self._result(mitre_technique_ids=["NOPE"])

    def test_duplicate_technique_ids_are_collapsed(self) -> None:
        result = self._result(mitre_technique_ids=["T1059.001", "t1059.001"])
        assert result.mitre_technique_ids == ["T1059.001"]

    def test_explain_shows_the_working(self) -> None:
        result = self._result(
            matched=[
                DetectionMatch(
                    field_name="command_line",
                    condition="contains '-enc'",
                    observed_value="-enc AAA=",
                )
            ]
        )
        explanation = result.explain()
        assert "SF-0003" in explanation
        assert "command_line contains '-enc' -> -enc AAA=" in explanation

    def test_detections_are_frozen(self) -> None:
        with pytest.raises(ValidationError):
            self._result().rule_id = "SF-9999"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class TestAlertSeverity:
    def test_score_is_summed_and_clamped(self) -> None:
        verdict = AlertSeverity.from_factors(
            [
                SeverityFactor(name="rule", points=65, detail="Rule is HIGH severity"),
                SeverityFactor(name="privileged", points=60, detail="Administrator account"),
            ]
        )
        assert verdict.score == 100
        assert verdict.level is Severity.CRITICAL

    def test_negative_factors_cannot_push_below_zero(self) -> None:
        verdict = AlertSeverity.from_factors(
            [
                SeverityFactor(name="rule", points=20, detail="Rule is LOW severity"),
                SeverityFactor(
                    name="known_good", points=-90, detail="Host is an approved build server"
                ),
            ]
        )
        assert verdict.score == 0
        assert verdict.level is Severity.LOW

    def test_level_must_agree_with_score(self) -> None:
        """Prevents a hand-built verdict from disagreeing with its own evidence."""
        with pytest.raises(ValidationError, match="does not match score"):
            AlertSeverity(score=10, level=Severity.CRITICAL)

    def test_method_is_always_deterministic(self) -> None:
        verdict = AlertSeverity.from_factors([])
        assert verdict.method == "deterministic"
        with pytest.raises(ValidationError):
            AlertSeverity(score=0, level=Severity.LOW, method="ai")

    def test_explanation_lists_every_factor(self) -> None:
        verdict = AlertSeverity.from_factors(
            [SeverityFactor(name="rule", points=65, detail="Rule SF-0003 is HIGH severity")]
        )
        assert "Rule SF-0003 is HIGH severity (+65)" in verdict.explain()


class TestAlert:
    def _alert(self, **overrides: object) -> Alert:
        payload: dict[str, object] = {
            "title": "Encoded PowerShell on WIN-LAB-01",
            "primary_event_id": uuid4(),
            "severity": AlertSeverity.from_factors(
                [SeverityFactor(name="rule", points=65, detail="Rule is HIGH severity")]
            ),
        }
        payload.update(overrides)
        return Alert(**payload)

    def test_defaults_to_a_new_open_alert(self) -> None:
        alert = self._alert()
        assert alert.status is AlertStatus.NEW
        assert alert.is_open
        assert alert.classification is None
        assert alert.severity_level is Severity.HIGH

    def test_primary_event_is_always_in_the_event_list(self) -> None:
        event_id = uuid4()
        alert = self._alert(primary_event_id=event_id)
        assert alert.event_ids[0] == event_id

    def test_a_bare_severity_cannot_be_used_as_the_verdict(self) -> None:
        """The structured verdict type is what keeps an AI opinion out of this field."""
        with pytest.raises(ValidationError):
            self._alert(severity=Severity.CRITICAL)

    def test_status_changes_are_validated_on_assignment(self) -> None:
        alert = self._alert()
        alert.status = AlertStatus.INVESTIGATING
        assert alert.status is AlertStatus.INVESTIGATING
        with pytest.raises(ValidationError):
            alert.status = "resolved"  # type: ignore[assignment]

    def test_touch_advances_updated_at(self) -> None:
        alert = self._alert()
        before = alert.updated_at
        alert.touch()
        assert alert.updated_at >= before

    def test_derived_lists_are_deduplicated(self) -> None:
        technique = MitreTechnique(technique_id="T1059.001", name="PowerShell")
        reason = "powershell.exe ran with an encoded command on WIN-LAB-01"
        alert = self._alert(
            mitre=[
                MitreMapping(technique=technique, reason=reason),
                MitreMapping(technique=technique, reason=reason, source_rule_id="SF-0003"),
            ]
        )
        assert alert.technique_ids == ["T1059.001"]

    def test_classification_is_optional_and_analyst_set(self) -> None:
        alert = self._alert()
        alert.classification = Classification.FALSE_POSITIVE
        assert alert.classification is Classification.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class TestIncident:
    def _incident(self, **overrides: object) -> Incident:
        payload: dict[str, object] = {
            "title": "Possible credential attack on WIN-LAB-01",
            "severity": Severity.HIGH,
            "correlation_key": "hostname:win-lab-01",
        }
        payload.update(overrides)
        return Incident(**payload)

    def test_label_reflects_the_claim_being_made(self) -> None:
        assert self._incident().display_label == "Potential Incident"
        assert not self._incident().is_confirmed

    def test_confirmation_is_an_explicit_state(self) -> None:
        incident = self._incident()
        incident.status = IncidentStatus.CONFIRMED
        assert incident.is_confirmed
        assert incident.display_label == "Confirmed"

    def test_host_and_user_lists_are_normalised(self) -> None:
        incident = self._incident(hostnames=["WIN-LAB-01", "win-lab-01"], usernames="Lab-User")
        assert incident.hostnames == ["win-lab-01"]
        assert incident.usernames == ["lab-user"]

    def test_timeline_must_be_ordered(self) -> None:
        now = utcnow()
        with pytest.raises(ValidationError, match="earlier than first_event_at"):
            self._incident(first_event_at=now, last_event_at=now - timedelta(hours=1))

    def test_alert_count_tracks_membership(self) -> None:
        assert self._incident(alert_ids=[uuid4(), uuid4()]).alert_count == 2


# ---------------------------------------------------------------------------
# Notes and audit
# ---------------------------------------------------------------------------
class TestAnalystNote:
    def test_a_note_must_attach_to_something(self) -> None:
        with pytest.raises(ValidationError, match="must reference an alert or an incident"):
            AnalystNote(author="miaad", body="Checked the host.")

    def test_a_valid_note(self) -> None:
        note = AnalystNote(author="miaad", body="Confirmed with the user.", alert_id=uuid4())
        assert note.author == "miaad"

    def test_empty_notes_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AnalystNote(author="miaad", body="   ", alert_id=uuid4())

    def test_notes_are_immutable(self) -> None:
        note = AnalystNote(author="miaad", body="First take.", alert_id=uuid4())
        with pytest.raises(ValidationError):
            note.body = "Rewritten later."  # type: ignore[misc]


class TestAuditEntry:
    def test_entry_describes_a_state_change(self) -> None:
        entry = AuditEntry(
            actor=Actor.ANALYST,
            actor_name="miaad",
            action=AuditAction.ALERT_STATUS_CHANGED,
            object_type="Alert",
            object_id=uuid4(),
            before="new",
            after="investigating",
        )
        assert entry.object_type == "alert"
        assert "miaad alert_status_changed alert (new -> investigating)" in entry.describe()

    def test_audit_entries_are_immutable(self) -> None:
        entry = AuditEntry(action=AuditAction.ALERT_CREATED, object_type="alert")
        with pytest.raises(ValidationError):
            entry.action = AuditAction.ALERT_CLASSIFIED  # type: ignore[misc]

    def test_default_actor_is_the_system(self) -> None:
        assert (
            AuditEntry(action=AuditAction.EVENT_INGESTED, object_type="event").actor is Actor.SYSTEM
        )
