"""Stage 6 — operators, conditions and rule evaluation.

The property under test throughout is that a detection is reproducible and
explains itself. Given the same event and rule, the same result, carrying the
field, the test and the observed value that caused it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.detection import (
    Condition,
    DetectionEngine,
    Logic,
    RuleDefinition,
    ThresholdHistory,
    available_operators,
    evaluate_condition,
    evaluate_logic,
    resolve_field,
    shannon_entropy,
)
from app.detection.operators import OPERATORS
from app.models.enums import EventType, Severity
from app.models.event import SecurityEvent

pytestmark = pytest.mark.unit


def event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "hostname": "WIN-LAB-01",
        "username": "LAB\\lab-user",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


def rule(**overrides: object) -> RuleDefinition:
    payload: dict[str, object] = {
        "id": "SF-9001",
        "name": "Test rule",
        "description": "A rule used only by the test suite, long enough to validate.",
        "severity": Severity.MEDIUM,
        "detection": {"event_types": ["process_creation"]},
    }
    payload.update(overrides)
    return RuleDefinition(**payload)


def condition(**kwargs: object) -> Condition:
    return Condition(**kwargs)


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------
class TestFieldResolution:
    def test_plain_attribute(self) -> None:
        assert resolve_field(event(), "process_name") == "powershell.exe"

    def test_derived_correlation_key(self) -> None:
        assert resolve_field(event(), "username_key") == "lab-user"

    def test_raw_event_key(self) -> None:
        source = event(raw_event={"EventID": 1, "GroupName": "Administrators"})
        assert resolve_field(source, "raw_event.GroupName") == "Administrators"

    def test_raw_event_lookup_is_case_insensitive(self) -> None:
        """The same export writes EventID, eventid or event_id depending on tooling."""
        source = event(raw_event={"EventID": 4625})
        assert resolve_field(source, "raw_event.eventid") == 4625

    def test_nested_raw_event_path(self) -> None:
        source = event(raw_event={"Event": {"System": {"EventID": 4688}}})
        assert resolve_field(source, "raw_event.Event.System.EventID") == 4688

    def test_missing_field_is_none_not_an_error(self) -> None:
        assert resolve_field(event(), "raw_event.absent") is None
        assert resolve_field(event(), "file_hash") is None


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------
class TestOperators:
    def test_every_registered_operator_is_callable(self) -> None:
        assert set(available_operators()) == set(OPERATORS)
        assert all(callable(function) for function in OPERATORS.values())

    @pytest.mark.parametrize(
        "operator, value, argument, expected",
        [
            ("equals", "powershell.exe", "POWERSHELL.EXE", True),
            ("equals", "powershell.exe", ["cmd.exe", "powershell.exe"], True),
            ("not_equals", "powershell.exe", "cmd.exe", True),
            ("contains", "C:\\Windows\\Temp\\a.exe", "\\temp\\", True),
            ("contains", "notepad.exe", ["powershell", "pwsh"], False),
            ("contains_all", "a -enc b", ["-enc", "a"], True),
            ("contains_all", "a -enc b", ["-enc", "zzz"], False),
            ("startswith", "powershell.exe", "power", True),
            ("endswith", "a.exe", [".dll", ".exe"], True),
            ("regex", "-enc AAAAAAAAAAAAAAAAAAAA", r"-enc\s+[A-Za-z0-9+/=]{16,}", True),
            ("gt", 443, 80, True),
            ("lte", 80, 80, True),
            ("cidr", "10.0.0.5", "10.0.0.0/8", True),
            ("cidr", "192.0.2.77", "10.0.0.0/8", False),
            ("not_cidr", "192.0.2.77", "10.0.0.0/8", True),
            ("length_gt", "abcdef", 3, True),
        ],
    )
    def test_operator_behaviour(
        self, operator: str, value: object, argument: object, expected: bool
    ) -> None:
        assert OPERATORS[operator](value, argument) is expected

    def test_list_fields_are_tested_element_by_element(self) -> None:
        """`tags contains deception` means one of the tags contains it."""
        assert OPERATORS["contains"](["lab", "deception"], "decep") is True

    def test_exists_handles_absence_and_inversion(self) -> None:
        assert OPERATORS["exists"](None, True) is False
        assert OPERATORS["exists"]("value", True) is True
        assert OPERATORS["exists"](None, False) is True
        assert OPERATORS["exists"]([], True) is False

    def test_is_private_distinguishes_internal_from_documentation(self) -> None:
        assert OPERATORS["is_private"]("10.0.0.5", True) is True
        assert OPERATORS["is_private"]("192.0.2.77", False) is True
        assert OPERATORS["is_private"]("192.0.2.77", True) is False

    def test_operators_do_not_raise_on_absent_fields(self) -> None:
        for name, function in OPERATORS.items():
            argument = 1 if name in {"gt", "gte", "lt", "lte", "length_gt", "entropy_gt"} else "x"
            function(None, argument)  # must not raise

    def test_entropy_separates_text_from_encoded_blobs(self) -> None:
        assert shannon_entropy("aaaaaaaa") < 1.0
        assert shannon_entropy("powershell.exe -File C:\\scripts\\daily.ps1") < 4.6
        assert shannon_entropy("TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFz") > 4.6
        assert shannon_entropy("") == 0.0


# ---------------------------------------------------------------------------
# Conditions and logic
# ---------------------------------------------------------------------------
class TestConditionEvidence:
    def test_a_match_records_field_test_and_observed_value(self) -> None:
        matched, evidence = evaluate_condition(
            condition(field="process_name", operator="contains", value="powershell"), event()
        )
        assert matched
        assert evidence is not None
        assert evidence.field_name == "process_name"
        assert evidence.condition == "contains powershell"
        assert evidence.observed_value == "powershell.exe"

    def test_a_custom_label_replaces_the_generated_description(self) -> None:
        _, evidence = evaluate_condition(
            condition(
                field="command_line",
                operator="contains",
                value="-enc",
                label="carries an encoded command block",
            ),
            event(command_line="powershell -enc AAA"),
        )
        assert evidence is not None
        assert evidence.condition == "carries an encoded command block"

    def test_a_failing_operator_does_not_match_and_does_not_raise(self) -> None:
        """A broken condition must not stop the other rules from running."""
        broken = condition(field="src_port", operator="cidr", value="not-a-network")
        matched, evidence = evaluate_condition(broken, event(src_port=443))
        assert matched is False
        assert evidence is None


class TestLogic:
    def test_event_type_prefilter(self) -> None:
        logic = Logic(event_types=[EventType.AUTHENTICATION_FAILURE])
        assert evaluate_logic(logic, event()) is None
        assert evaluate_logic(logic, event(event_type="authentication_failure")) is not None

    def test_a_prefilter_only_rule_still_produces_evidence(self) -> None:
        logic = Logic(event_types=[EventType.PROCESS_CREATION])
        evidence = evaluate_logic(logic, event())
        assert evidence is not None and evidence[0].field_name == "event_type"

    def test_all_requires_every_condition(self) -> None:
        logic = Logic.model_validate(
            {
                "all": [
                    {"field": "process_name", "operator": "contains", "value": "powershell"},
                    {"field": "parent_process", "operator": "contains", "value": "cmd"},
                ]
            }
        )
        assert len(evaluate_logic(logic, event()) or []) == 2
        assert evaluate_logic(logic, event(parent_process="explorer.exe")) is None

    def test_any_requires_at_least_one(self) -> None:
        logic = Logic.model_validate(
            {
                "any": [
                    {"field": "process_name", "operator": "contains", "value": "nomatch"},
                    {"field": "process_name", "operator": "contains", "value": "powershell"},
                ]
            }
        )
        assert len(evaluate_logic(logic, event()) or []) == 1

    def test_none_excludes(self) -> None:
        """Most real rules are 'this pattern, except when it is our own tooling'."""
        logic = Logic.model_validate(
            {
                "all": [{"field": "process_name", "operator": "contains", "value": "powershell"}],
                "none": [{"field": "parent_process", "operator": "contains", "value": "cmd"}],
            }
        )
        assert evaluate_logic(logic, event()) is None
        assert evaluate_logic(logic, event(parent_process="explorer.exe")) is not None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class TestEngine:
    def test_a_matching_rule_produces_a_result_that_explains_itself(self) -> None:
        engine = DetectionEngine(
            [
                rule(
                    detection={
                        "event_types": ["process_creation"],
                        "all": [
                            {"field": "process_name", "operator": "contains", "value": "powershell"}
                        ],
                    },
                    mitre=["T1059.001"],
                    recommendation="Decode the command and confirm with the user.",
                )
            ]
        )
        results = engine.evaluate_event(event())
        assert len(results) == 1
        assert results[0].rule_id == "SF-9001"
        assert results[0].mitre_technique_ids == ["T1059.001"]
        assert "process_name contains powershell -> powershell.exe" in results[0].explain()

    def test_evaluation_is_reproducible(self) -> None:
        engine = DetectionEngine([rule()])
        source = event()
        first = engine.evaluate_event(source)
        second = engine.evaluate_event(source)
        assert [r.rule_id for r in first] == [r.rule_id for r in second]
        assert [m.observed_value for m in first[0].matched] == [
            m.observed_value for m in second[0].matched
        ]

    def test_disabled_rules_never_run(self) -> None:
        assert DetectionEngine([rule(enabled=False)]).evaluate_event(event()) == []

    def test_the_result_snapshots_the_rule(self) -> None:
        """Editing a rule later must not rewrite alerts it already produced."""
        source_rule = rule(severity=Severity.HIGH)
        result = DetectionEngine([source_rule]).evaluate_event(event())[0]
        assert result.rule_severity is Severity.HIGH
        assert result.rule_name == source_rule.name
        assert result.description == source_rule.description


# ---------------------------------------------------------------------------
# Threshold rules
# ---------------------------------------------------------------------------
def _failures(count: int, *, gap_seconds: int = 30, user: str = "lab-user") -> list:
    start = datetime(2026, 9, 23, 13, 0, tzinfo=UTC)
    return [
        event(
            event_type="authentication_failure",
            username=user,
            timestamp=start + timedelta(seconds=gap_seconds * index),
        )
        for index in range(count)
    ]


def _threshold_rule(**threshold: object):
    spec = {"count": 5, "within_minutes": 10, "group_by": ["hostname_key", "username_key"]}
    spec.update(threshold)
    return rule(
        detection={"event_types": ["authentication_failure"]},
        threshold=spec,
    )


class TestThresholdRules:
    def test_below_the_threshold_nothing_fires(self) -> None:
        run = DetectionEngine([_threshold_rule()]).evaluate_events(_failures(4))
        assert run.detection_count == 0

    def test_at_the_threshold_one_detection_fires(self) -> None:
        run = DetectionEngine([_threshold_rule()]).evaluate_events(_failures(5))
        assert run.detection_count == 1

    def test_a_burst_produces_one_detection_not_one_per_event(self) -> None:
        """An analyst wants to know a burst happened, not receive nine alerts."""
        run = DetectionEngine([_threshold_rule()]).evaluate_events(_failures(9))
        assert run.detection_count == 1

    def test_two_separate_bursts_produce_two_detections(self) -> None:
        run = DetectionEngine([_threshold_rule()]).evaluate_events(_failures(10))
        assert run.detection_count == 2

    def test_events_outside_the_window_do_not_accumulate(self) -> None:
        """Five failures over five hours is not a brute-force attempt."""
        spread = _failures(5, gap_seconds=3_600)
        assert DetectionEngine([_threshold_rule()]).evaluate_events(spread).detection_count == 0

    def test_counting_is_grouped_by_key(self) -> None:
        mixed = _failures(4, user="alice") + _failures(4, user="bob")
        assert DetectionEngine([_threshold_rule()]).evaluate_events(mixed).detection_count == 0

    def test_events_missing_a_group_key_are_not_counted(self) -> None:
        """Activity that cannot be attributed must not be counted as if it could."""
        start = datetime(2026, 9, 23, 13, 0, tzinfo=UTC)
        anonymous = [
            SecurityEvent(
                timestamp=start + timedelta(seconds=30 * index),
                source="windows_security",
                event_type=EventType.AUTHENTICATION_FAILURE,
                hostname="WIN-LAB-01",
            )
            for index in range(8)
        ]
        assert DetectionEngine([_threshold_rule()]).evaluate_events(anonymous).detection_count == 0

    def test_the_detection_records_the_count_and_the_window(self) -> None:
        run = DetectionEngine([_threshold_rule()]).evaluate_events(_failures(6))
        evidence = run.all_results()[0].matched
        assert "5 events" in (evidence[0].observed_value or "")
        assert "to" in (evidence[1].observed_value or "")

    def test_the_detection_is_anchored_on_a_real_event(self) -> None:
        failures = _failures(6)
        run = DetectionEngine([_threshold_rule()]).evaluate_events(failures)
        assert run.all_results()[0].event_id in {e.event_id for e in failures}


class TestThresholdAcrossBatches:
    """Stage 17: a burst is one burst, whichever triage runs its events fell into."""

    def _fire(
        self,
        batch: list[SecurityEvent],
        *,
        events: list[SecurityEvent] | None = None,
        triggers: dict[str, list[SecurityEvent]] | None = None,
    ) -> list:
        history = ThresholdHistory(events=events or [], triggers=triggers or {})
        run = DetectionEngine([_threshold_rule()]).evaluate_events(batch, history=history)
        return [result.event_id for result in run.all_results()]

    def test_earlier_events_count_towards_the_burst(self) -> None:
        failures = _failures(5)
        assert self._fire(failures[4:], events=failures[:4]) == [failures[4].event_id]

    def test_an_earlier_event_is_never_fired_on_again(self) -> None:
        """It was triaged already; only the batch can raise something new."""
        failures = _failures(5)
        assert self._fire([], events=failures) == []

    def test_a_burst_that_already_fired_does_not_fire_again(self) -> None:
        failures = _failures(7)
        fired = {_threshold_rule().rule_id: [failures[4]]}
        assert self._fire(failures[5:], events=failures[:5], triggers=fired) == []

    def test_counting_restarts_after_the_last_firing(self) -> None:
        """Ten failures fire twice in one batch, and twice split five and five."""
        failures = _failures(10)
        fired = {_threshold_rule().rule_id: [failures[4]]}
        assert self._fire(failures[5:], events=failures[:5], triggers=fired) == [
            failures[9].event_id
        ]

    def test_earlier_events_outside_the_window_do_not_count(self) -> None:
        failures = _failures(5, gap_seconds=180)  # twelve minutes end to end
        assert self._fire(failures[4:], events=failures[:4]) == []

    def test_earlier_events_in_another_group_do_not_count(self) -> None:
        alice, bob = _failures(4, user="alice"), _failures(1, user="bob")
        assert self._fire(bob, events=alice) == []


class TestDetectionRun:
    def test_run_reports_totals_and_grouping(self) -> None:
        engine = DetectionEngine([rule(), rule(id="SF-9002", name="Second rule")])
        run = engine.evaluate_events([event(), event(timestamp="2026-09-23T14:00:00Z")])
        assert run.events_evaluated == 2
        assert run.detection_count == 4
        assert run.by_rule() == {"SF-9001": 2, "SF-9002": 2}
        assert "4 detections" in run.summary()

    def test_an_empty_run_is_not_an_error(self) -> None:
        run = DetectionEngine([]).evaluate_events([])
        assert run.detection_count == 0
        assert run.all_results() == []
