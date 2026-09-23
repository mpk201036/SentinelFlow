"""Stage 6 — the rule language, the loader, and the rules SentinelFlow ships.

The loader's job is to fail loudly and specifically. A detection stack where a
typo produces a rule that silently never fires is worse than one that refuses
to start, because it looks like coverage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.detection import (
    DetectionEngine,
    load_rule_document,
    load_rules,
    rules_by_technique,
)
from app.ingestion import generate_demo_scenario, generate_normal_activity, get_adapter
from app.models.enums import Severity

pytestmark = pytest.mark.unit

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

MINIMAL = {
    "id": "SF-9001",
    "name": "Test rule",
    "description": "A rule used only by the test suite, long enough to pass validation.",
    "severity": "medium",
    "detection": {"event_types": ["process_creation"]},
}


def document(**overrides: object) -> dict[str, object]:
    payload = dict(MINIMAL)
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------
class TestRuleValidation:
    def test_a_minimal_rule_is_valid(self) -> None:
        rule = load_rule_document(document())
        assert rule.rule_id == "SF-9001"
        assert rule.enabled is True
        assert rule.kind == "match"

    def test_an_unknown_field_name_is_rejected_at_load_time(self) -> None:
        """A typo would otherwise produce a rule that quietly never fires."""
        with pytest.raises(ValidationError, match="unknown event field"):
            load_rule_document(
                document(
                    detection={
                        "all": [{"field": "proces_name", "operator": "contains", "value": "a"}]
                    }
                )
            )

    def test_raw_event_paths_are_allowed(self) -> None:
        rule = load_rule_document(
            document(
                detection={
                    "all": [
                        {"field": "raw_event.GroupName", "operator": "contains", "value": "admins"}
                    ]
                }
            )
        )
        assert rule.detection.all_of[0].field_name == "raw_event.GroupName"

    def test_a_bare_raw_event_prefix_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            load_rule_document(
                document(
                    detection={
                        "all": [{"field": "raw_event.", "operator": "exists", "value": True}]
                    }
                )
            )

    def test_an_unknown_operator_lists_the_alternatives(self) -> None:
        with pytest.raises(ValidationError, match="unknown operator"):
            load_rule_document(
                document(
                    detection={
                        "all": [{"field": "process_name", "operator": "sounds_like", "value": "a"}]
                    }
                )
            )

    def test_a_broken_regex_fails_when_the_rule_loads(self) -> None:
        """Not halfway through a triage."""
        with pytest.raises(ValidationError):
            load_rule_document(
                document(
                    detection={
                        "all": [{"field": "command_line", "operator": "regex", "value": "([a-z"}]
                    }
                )
            )

    def test_an_enormous_regex_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            load_rule_document(
                document(
                    detection={
                        "all": [
                            {"field": "command_line", "operator": "regex", "value": "a" * 2_000}
                        ]
                    }
                )
            )

    def test_a_numeric_operator_needs_a_number(self) -> None:
        with pytest.raises(ValidationError, match="needs a number"):
            load_rule_document(
                document(
                    detection={
                        "all": [{"field": "command_line", "operator": "length_gt", "value": "lots"}]
                    }
                )
            )

    def test_a_rule_with_only_exclusions_is_refused(self) -> None:
        """It would match every event, which is never what the author meant."""
        with pytest.raises(ValidationError, match="must test something"):
            load_rule_document(
                document(
                    detection={
                        "none": [{"field": "process_name", "operator": "contains", "value": "a"}]
                    }
                )
            )

    def test_a_fabricated_technique_id_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="ATT&CK technique ID"):
            load_rule_document(document(mitre=["T99", "not-a-technique"]))

    def test_technique_ids_are_normalised_and_deduplicated(self) -> None:
        rule = load_rule_document(document(mitre=["t1059.001", "T1059.001"]))
        assert rule.mitre == ["T1059.001"]

    def test_a_rule_needs_a_usable_description(self) -> None:
        with pytest.raises(ValidationError, match="description"):
            load_rule_document(document(description="bad"))

    def test_a_malformed_rule_id_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="not a valid rule id"):
            load_rule_document(document(id="rule with spaces"))

    def test_a_rule_document_must_be_a_mapping(self) -> None:
        with pytest.raises(ValueError, match="expected a mapping"):
            load_rule_document(["not", "a", "rule"])


class TestThresholdValidation:
    def test_a_threshold_rule_is_recognised(self) -> None:
        rule = load_rule_document(
            document(threshold={"count": 5, "within_minutes": 10, "group_by": ["hostname_key"]})
        )
        assert rule.is_threshold
        assert rule.kind == "threshold"
        assert "5 or more within 10 minutes" in rule.threshold.describe()

    def test_grouping_by_an_unknown_field_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="unknown field"):
            load_rule_document(
                document(threshold={"count": 5, "within_minutes": 10, "group_by": ["hostnam"]})
            )

    @pytest.mark.parametrize(
        "spec",
        [
            {"count": 1, "within_minutes": 10, "group_by": ["hostname_key"]},
            {"count": 5, "within_minutes": 0, "group_by": ["hostname_key"]},
            {"count": 5, "within_minutes": 10, "group_by": []},
        ],
    )
    def test_nonsensical_thresholds_are_refused(self, spec: dict) -> None:
        with pytest.raises(ValidationError):
            load_rule_document(document(threshold=spec))


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
class TestLoader:
    def _write(self, directory: Path, name: str, content: str) -> Path:
        path = directory / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_a_directory(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            "rule.yaml",
            "id: SF-1000\nname: A rule\n"
            "description: A description that is comfortably long enough to validate.\n"
            "severity: low\ndetection:\n  event_types: [process_creation]\n",
        )
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 1
        assert rule_set.errors == []
        assert rule_set.get("SF-1000") is not None

    def test_multi_document_files_are_supported(self, tmp_path: Path) -> None:
        body = (
            "id: SF-{n}\nname: Rule {n}\n"
            "description: A description that is comfortably long enough to validate.\n"
            "severity: low\ndetection:\n  event_types: [process_creation]\n"
        )
        self._write(tmp_path, "pair.yaml", body.format(n=1001) + "---\n" + body.format(n=1002))
        assert len(load_rules(tmp_path)) == 2

    def test_a_broken_file_does_not_stop_the_others(self, tmp_path: Path) -> None:
        """One bad file silently disabling everything is the worst outcome."""
        self._write(tmp_path, "broken.yaml", "id: [unclosed\n")
        self._write(
            tmp_path,
            "good.yaml",
            "id: SF-1003\nname: Good\n"
            "description: A description that is comfortably long enough to validate.\n"
            "severity: low\ndetection:\n  event_types: [process_creation]\n",
        )
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 1
        assert len(rule_set.errors) == 1
        assert "invalid YAML" in rule_set.errors[0].message

    def test_a_validation_failure_names_the_file_and_the_problem(self, tmp_path: Path) -> None:
        self._write(tmp_path, "bad.yaml", "id: SF-1004\nname: Bad\nseverity: low\n")
        rule_set = load_rules(tmp_path)
        assert rule_set.errors[0].path == "bad.yaml"
        assert "description" in rule_set.errors[0].message

    def test_duplicate_rule_ids_are_an_error(self, tmp_path: Path) -> None:
        """Otherwise one silently wins and nobody can tell which fired."""
        body = (
            "id: SF-1005\nname: Rule\n"
            "description: A description that is comfortably long enough to validate.\n"
            "severity: low\ndetection:\n  event_types: [process_creation]\n"
        )
        self._write(tmp_path, "a.yaml", body)
        self._write(tmp_path, "b.yaml", body)
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 1
        assert "duplicate rule id" in rule_set.errors[0].message

    def test_yaml_python_object_tags_are_refused(self, tmp_path: Path) -> None:
        """safe_load, never load. PyYAML's default loader builds Python objects
        from tags like !!python/object/apply, which turns a rule file into code
        execution."""
        self._write(
            tmp_path,
            "evil.yaml",
            "id: SF-1006\nname: !!python/object/apply:os.system ['echo pwned']\n",
        )
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 0
        assert rule_set.errors

    def test_an_oversized_file_is_refused(self, tmp_path: Path) -> None:
        self._write(tmp_path, "huge.yaml", "# " + "a" * (300 * 1024))
        assert "exceeds" in load_rules(tmp_path).errors[0].message

    def test_a_missing_directory_is_reported_not_raised(self, tmp_path: Path) -> None:
        rule_set = load_rules(tmp_path / "absent")
        assert len(rule_set) == 0
        assert "does not exist" in rule_set.errors[0].message

    def test_an_empty_directory_is_not_an_error(self, tmp_path: Path) -> None:
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 0 and rule_set.errors == []

    def test_disabled_rules_load_but_are_excluded_from_enabled(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            "off.yaml",
            "id: SF-1007\nname: Off\nenabled: false\n"
            "description: A description that is comfortably long enough to validate.\n"
            "severity: low\ndetection:\n  event_types: [process_creation]\n",
        )
        rule_set = load_rules(tmp_path)
        assert len(rule_set) == 1 and rule_set.enabled == []


# ---------------------------------------------------------------------------
# The rules SentinelFlow ships
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def shipped():
    return load_rules(RULES_DIR)


class TestShippedRules:
    def test_every_rule_loads(self, shipped) -> None:
        assert shipped.errors == [], [str(error) for error in shipped.errors]

    def test_at_least_ten_rules_ship(self, shipped) -> None:
        assert len(shipped) >= 10

    def test_rule_ids_are_unique(self, shipped) -> None:
        ids = [rule.rule_id for rule in shipped.rules]
        assert len(ids) == len(set(ids))

    def test_every_rule_tells_an_analyst_what_to_do(self, shipped) -> None:
        """A detection without a next step is a notification, not triage."""
        for rule in shipped.rules:
            assert rule.recommendation, f"{rule.rule_id} has no recommendation"
            assert len(rule.description) >= 60, f"{rule.rule_id} description is too thin"

    def test_every_rule_admits_its_false_positives(self, shipped) -> None:
        """A rule that claims none is a rule nobody has run in production."""
        for rule in shipped.rules:
            assert rule.false_positives, f"{rule.rule_id} lists no false positives"

    def test_severities_are_spread_across_the_range(self, shipped) -> None:
        severities = {rule.severity for rule in shipped.rules}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_technique_ids_are_well_formed(self, shipped) -> None:
        for technique in rules_by_technique(shipped.rules):
            assert technique.startswith("T")

    def test_a_rule_may_map_to_no_technique(self, shipped) -> None:
        """Restraint is the point: exposure change is a configuration fact, and
        T1133 describes an adversary *using* a remote service, which that
        evidence does not show."""
        exposure = shipped.get("SF-0010")
        assert exposure is not None
        assert exposure.mitre == []

    def test_threshold_rules_declare_their_window(self, shipped) -> None:
        for rule in shipped.rules:
            if rule.is_threshold:
                assert rule.threshold is not None
                assert rule.threshold.group_by


class TestShippedRulesAgainstData:
    def _events(self, records):
        return [get_adapter(r.adapter).normalise(r.record) for r in records]

    def test_the_demo_scenario_fires_the_expected_rules(self, shipped) -> None:
        events = self._events(generate_demo_scenario())
        run = DetectionEngine(shipped.enabled).evaluate_events(events)
        fired = set(run.by_rule())
        assert {
            "SF-0001",  # repeated authentication failures
            "SF-0002",  # success from an external address
            "SF-0003",  # encoded PowerShell
            "SF-0005",  # account created
            "SF-0006",  # added to a privileged group
            "SF-0008",  # executable in a temporary directory
            "SF-0009",  # decoy credential
            "SF-0010",  # newly exposed service
            "SF-0011",  # script host to an external web service
        } <= fired

    def test_benign_background_activity_produces_no_detections(self, shipped) -> None:
        """The number that decides whether anyone will use the tool."""
        from datetime import UTC, datetime

        events = self._events(
            generate_normal_activity(120, seed=99, base_time=datetime(2026, 9, 23, 6, tzinfo=UTC))
        )
        run = DetectionEngine(shipped.enabled).evaluate_events(events)
        assert run.detection_count == 0, run.by_rule()

    def test_every_detection_explains_itself(self, shipped) -> None:
        events = self._events(generate_demo_scenario())
        for result in DetectionEngine(shipped.enabled).evaluate_events(events).all_results():
            assert result.matched, f"{result.rule_id} fired with no evidence"
            assert "matched because" in result.explain()
