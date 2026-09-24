"""Stage 7 — the ATT&CK catalogue and evidence-backed mapping.

ATT&CK decoration is the easiest thing in security tooling to fake, so most of
these tests are about refusal: what the mapper declines to claim, and what it
records when it declines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.database import repository
from app.detection import DetectionEngine, load_rules
from app.ingestion import generate_demo_scenario, get_adapter
from app.mitre import (
    Catalogue,
    MitreMapper,
    build_reason,
    load_catalogue,
    tactic_coverage,
    validate_rule_techniques,
)
from app.models.detection import DetectionMatch, DetectionResult
from app.models.enums import Confidence, Severity
from app.models.event import SecurityEvent
from app.models.mitre import MitreTechnique

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOGUE_PATH = PROJECT_ROOT / "data" / "mitre" / "techniques.json"


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(CATALOGUE_PATH)


def detection(**overrides: object) -> DetectionResult:
    payload: dict[str, object] = {
        "rule_id": "SF-0003",
        "rule_name": "Encoded PowerShell command",
        "rule_severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "description": "PowerShell invoked with an encoded command block.",
        "matched": [
            DetectionMatch(
                field_name="command_line",
                condition="carries an encoded command block",
                observed_value="powershell.exe -enc AAA=",
            )
        ],
        "mitre_technique_ids": ["T1059.001"],
    }
    payload.update(overrides)
    return DetectionResult(**payload)


def event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "hostname": "WIN-LAB-01",
        "username": "lab-user",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestCatalogueLoading:
    def test_the_shipped_catalogue_loads_cleanly(self, catalogue: Catalogue) -> None:
        assert catalogue.errors == []
        assert len(catalogue) >= 25
        assert len(catalogue.tactics) == 14

    def test_it_records_its_provenance(self, catalogue: Catalogue) -> None:
        """A local copy of someone else's framework must say where it came from."""
        assert "MITRE ATT&CK" in catalogue.source
        assert "attack.mitre.org" in catalogue.attribution
        assert catalogue.version

    def test_every_technique_has_a_name_and_a_tactic(self, catalogue: Catalogue) -> None:
        for technique in catalogue.techniques.values():
            assert technique.name
            assert technique.tactics, f"{technique.technique_id} has no tactic"

    def test_every_tactic_a_technique_claims_is_listed(self, catalogue: Catalogue) -> None:
        known = set(catalogue.tactic_names())
        for technique in catalogue.techniques.values():
            assert set(technique.tactics) <= known

    def test_a_missing_file_degrades_rather_than_raising(self, tmp_path: Path) -> None:
        """Detections still fire and severity is unaffected without ATT&CK names."""
        result = load_catalogue(tmp_path / "absent.json")
        assert len(result) == 0
        assert "not found" in result.errors[0]

    def test_malformed_json_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        assert "could not read" in load_catalogue(path).errors[0]

    def test_a_non_object_document_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "list.json"
        path.write_text("[]", encoding="utf-8")
        assert "must be a JSON object" in load_catalogue(path).errors[0]

    def test_bad_entries_are_skipped_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "mixed.json"
        path.write_text(
            json.dumps(
                {
                    "tactics": [{"id": "TA0002", "name": "Execution"}, {"id": "TA0003"}],
                    "techniques": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "tactics": ["Execution"],
                        },
                        {"id": "NOT-A-TECHNIQUE", "name": "Nonsense"},
                        {"id": "T1059", "name": "Duplicate"},
                        "not an object",
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = load_catalogue(path)
        assert len(result) == 1
        assert len(result.errors) == 4

    def test_an_oversized_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "huge.json"
        path.write_text(" " * (9 * 1024 * 1024), encoding="utf-8")
        assert "exceeds" in load_catalogue(path).errors[0]


@pytest.mark.unit
class TestCatalogueLookup:
    def test_exact_lookup(self, catalogue: Catalogue) -> None:
        technique = catalogue.get("T1059.001")
        assert technique is not None
        assert technique.name.endswith("PowerShell")
        assert technique.url == "https://attack.mitre.org/techniques/T1059/001/"

    def test_lookup_is_case_insensitive(self, catalogue: Catalogue) -> None:
        assert catalogue.get("t1110") is not None
        assert "T1110" in catalogue

    def test_an_unknown_sub_technique_falls_back_to_its_parent(self, catalogue: Catalogue) -> None:
        """T1059.009 is genuinely a kind of T1059, so naming the parent is
        accurate rather than invented."""
        resolved = catalogue.resolve("T1059.009")
        assert resolved is not None and resolved.technique_id == "T1059"

    def test_a_technique_with_no_parent_resolves_to_nothing(self, catalogue: Catalogue) -> None:
        assert catalogue.resolve("T9999") is None
        assert catalogue.get("T1059.009") is None

    def test_grouping_by_tactic(self, catalogue: Catalogue) -> None:
        grouped = catalogue.by_tactic()
        assert "T1059.001" in [t.technique_id for t in grouped["Execution"]]
        assert grouped["Reconnaissance"] == []


# ---------------------------------------------------------------------------
# Reasons
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestReasons:
    def test_a_reason_names_the_rule_the_host_and_the_evidence(self) -> None:
        reason = build_reason(detection(), event())
        assert "SF-0003" in reason
        assert "WIN-LAB-01" in reason
        assert "lab-user" in reason
        assert "carries an encoded command block" in reason
        assert "powershell.exe -enc AAA=" in reason

    def test_a_reason_works_without_an_event(self) -> None:
        reason = build_reason(detection())
        assert "SF-0003" in reason
        assert len(reason) >= 10

    def test_a_detection_with_no_evidence_still_produces_a_usable_reason(self) -> None:
        reason = build_reason(detection(matched=[]), event())
        assert reason.endswith(".")
        assert len(reason) >= 10

    def test_a_very_long_reason_is_truncated_visibly(self) -> None:
        huge = [
            DetectionMatch(
                field_name="command_line", condition="contains", observed_value="A" * 900
            )
            for _ in range(5)
        ]
        reason = build_reason(detection(matched=huge), event())
        assert len(reason) <= 1_024
        assert "truncated" in reason


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestMapping:
    def test_a_declared_technique_is_mapped_with_its_evidence(self, catalogue: Catalogue) -> None:
        result = MitreMapper(catalogue).map_detection(detection(), event())
        assert len(result) == 1
        mapping = result.mappings[0]
        assert mapping.technique_id == "T1059.001"
        assert mapping.source_rule_id == "SF-0003"
        assert "carries an encoded command block" in mapping.reason

    def test_confidence_is_inherited_from_the_detection(self, catalogue: Catalogue) -> None:
        result = MitreMapper(catalogue).map_detection(detection(confidence=Confidence.LOW), event())
        assert result.mappings[0].confidence is Confidence.LOW

    def test_a_technique_the_catalogue_cannot_name_is_refused(self, catalogue: Catalogue) -> None:
        """Rendering a bare T9999 would look authoritative and say nothing."""
        result = MitreMapper(catalogue).map_detection(
            detection(mitre_technique_ids=["T9999"]), event()
        )
        assert result.mappings == []
        assert result.unknown_techniques == ["T9999"]

    def test_a_parent_fallback_says_so_in_the_reason(self, catalogue: Catalogue) -> None:
        result = MitreMapper(catalogue).map_detection(
            detection(mitre_technique_ids=["T1059.009"]), event()
        )
        assert result.mappings[0].technique_id == "T1059"
        assert "mapped to parent technique" in result.mappings[0].reason

    def test_a_detection_declaring_nothing_maps_nothing(self, catalogue: Catalogue) -> None:
        result = MitreMapper(catalogue).map_detection(detection(mitre_technique_ids=[]), event())
        assert len(result) == 0

    def test_the_mapper_invents_no_techniques(self, catalogue: Catalogue) -> None:
        """Only what the rule declared, and only if the catalogue can name it."""
        result = MitreMapper(catalogue).map_detection(
            detection(mitre_technique_ids=["T1110"]), event()
        )
        assert result.technique_ids == ["T1110"]

    def test_identical_technique_and_rule_pairs_are_deduplicated(
        self, catalogue: Catalogue
    ) -> None:
        source = event()
        detections = [detection(event_id=source.event_id) for _ in range(3)]
        result = MitreMapper(catalogue).map_detections(detections, {source.event_id: source})
        assert len(result) == 1

    def test_the_same_technique_from_two_rules_is_kept_twice(self, catalogue: Catalogue) -> None:
        """Two independent rules reaching the same technique is corroboration."""
        detections = [
            detection(mitre_technique_ids=["T1027"]),
            detection(rule_id="SF-0014", rule_name="High entropy", mitre_technique_ids=["T1027"]),
        ]
        result = MitreMapper(catalogue).map_detections(detections)
        assert len(result) == 2
        assert result.technique_ids == ["T1027"]

    def test_the_result_reports_tactics(self, catalogue: Catalogue) -> None:
        result = MitreMapper(catalogue).map_detection(detection(), event())
        assert result.tactics() == ["Execution"]

    def test_an_empty_catalogue_maps_nothing_and_says_why(self) -> None:
        result = MitreMapper(Catalogue()).map_detection(detection(), event())
        assert result.mappings == []
        assert result.unknown_techniques == ["T1059.001"]
        assert "not in the catalogue" in result.summary()


# ---------------------------------------------------------------------------
# Rules and coverage
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestRulesAgainstTheCatalogue:
    def test_every_shipped_rule_reference_resolves(self, catalogue: Catalogue) -> None:
        rule_set = load_rules(PROJECT_ROOT / "rules")
        assert validate_rule_techniques(rule_set.rules, catalogue) == []

    def test_an_unresolvable_reference_is_reported(self, catalogue: Catalogue) -> None:
        class FakeRule:
            rule_id = "SF-9999"
            mitre: ClassVar[list[str]] = ["T9999"]

        problems = validate_rule_techniques([FakeRule()], catalogue)
        assert len(problems) == 1
        assert "no parent technique either" in problems[0]

    def test_a_sub_technique_reference_reports_its_fallback(self, catalogue: Catalogue) -> None:
        class FakeRule:
            rule_id = "SF-9998"
            mitre: ClassVar[list[str]] = ["T1059.009"]

        assert "would fall back to T1059" in validate_rule_techniques([FakeRule()], catalogue)[0]

    def test_coverage_names_the_gaps(self, catalogue: Catalogue) -> None:
        """Coverage is a map, not a score. Gaps are the useful part."""
        rule_set = load_rules(PROJECT_ROOT / "rules")
        coverage = tactic_coverage(rule_set.rules, catalogue)
        assert coverage["Execution"]
        assert coverage["Credential Access"]
        assert coverage["Exfiltration"] == []
        assert set(coverage) == set(catalogue.tactic_names())


@pytest.mark.unit
class TestTheDemoScenario:
    def test_the_attack_chain_maps_across_several_tactics(self, catalogue: Catalogue) -> None:
        rule_set = load_rules(PROJECT_ROOT / "rules")
        events = [get_adapter(r.adapter).normalise(r.record) for r in generate_demo_scenario()]
        by_id = {e.event_id: e for e in events}
        run = DetectionEngine(rule_set.enabled).evaluate_events(events)

        result = MitreMapper(catalogue).map_detections(run.all_results(), by_id)
        assert result.unknown_techniques == []
        assert {"T1110", "T1078", "T1059.001", "T1098", "T1136.001", "T1555"} <= set(
            result.technique_ids
        )
        assert {"Credential Access", "Execution", "Persistence"} <= set(result.tactics())

    def test_every_mapping_carries_a_justification(self, catalogue: Catalogue) -> None:
        rule_set = load_rules(PROJECT_ROOT / "rules")
        events = [get_adapter(r.adapter).normalise(r.record) for r in generate_demo_scenario()]
        run = DetectionEngine(rule_set.enabled).evaluate_events(events)
        for mapping in MitreMapper(catalogue).map_detections(run.all_results()).mappings:
            assert len(mapping.reason) >= 10
            assert mapping.source_rule_id
            assert mapping.reason.startswith("Rule ")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestCataloguePersistence:
    def test_the_catalogue_can_be_synchronised(
        self, db_session: Session, catalogue: Catalogue
    ) -> None:
        for technique in catalogue.techniques.values():
            repository.upsert_technique(db_session, technique)
        db_session.commit()

        brute_force = catalogue.get("T1110")
        assert brute_force is not None
        stored = repository.upsert_technique(db_session, brute_force)
        assert stored.name == "Brute Force"

    def test_a_mapping_to_an_unsynchronised_technique_is_refused_by_the_database(
        self, db_session: Session, catalogue: Catalogue
    ) -> None:
        """The same guarantee as the mapper, enforced one layer lower."""
        from sqlalchemy.exc import IntegrityError

        from app.database.tables import MitreMappingRow

        db_session.add(
            MitreMappingRow(
                mapping_id=uuid4(),
                alert_id=uuid4(),
                technique_id="T1110",
                reason="a reason long enough to pass validation",
                confidence=Confidence.MEDIUM,
            )
        )
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()


@pytest.mark.unit
class TestTechniqueModel:
    def test_sub_technique_relationships(self) -> None:
        technique = MitreTechnique(technique_id="T1543.003", name="Windows Service")
        assert technique.is_subtechnique
        assert technique.parent_id == "T1543"
        assert technique.url.endswith("/T1543/003/")
