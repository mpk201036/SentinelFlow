"""Stage 4 — ingestion orchestration, idempotency and the generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.paths import FileTooLargeError, UnsafePathError
from app.database import repository
from app.ingestion import (
    IngestionService,
    generate_dataset,
    generate_demo_scenario,
    generate_normal_activity,
    get_adapter,
    group_by_adapter,
)
from app.models.enums import AuditAction, EventType
from app.models.ingestion import RejectionReason

pytestmark = pytest.mark.integration

VALID = {
    "timestamp": "2026-09-23T13:42:10Z",
    "source": "canonical",
    "event_type": "process_creation",
    "hostname": "WIN-LAB-01",
}


@pytest.fixture
def service(db_session: Session, db_settings: Settings) -> IngestionService:
    return IngestionService(db_session, db_settings)


class TestCountsAlwaysAddUp:
    def test_accepted_plus_rejected_equals_input(self, service: IngestionService) -> None:
        """The contract: an import never silently loses a record."""
        payload = json.dumps([VALID, {"broken": True}, VALID, 42, {**VALID, "dst_port": 99999}])
        outcome = service.ingest_json(payload, adapter_name="canonical", origin="t.json")
        assert outcome.report.total == 5
        assert outcome.accepted + outcome.rejected == 5

    def test_every_rejection_carries_an_index_and_a_reason(self, service: IngestionService) -> None:
        payload = json.dumps([VALID, "bad", VALID])
        outcome = service.ingest_json(payload, adapter_name="canonical", origin="t.json")
        rejection = outcome.report.rejections[0]
        assert rejection.index == 1
        assert rejection.reason is RejectionReason.NOT_AN_OBJECT
        assert rejection.origin == "t.json"

    def test_success_rate_is_reported(self, service: IngestionService) -> None:
        payload = json.dumps([VALID, "bad", VALID, VALID])
        outcome = service.ingest_json(payload, adapter_name="canonical", origin="t.json")
        assert outcome.report.success_rate == 0.75


class TestIdempotency:
    def test_identical_content_is_not_imported_twice(
        self, service: IngestionService, db_session: Session
    ) -> None:
        payload = json.dumps([VALID, VALID])
        first = service.ingest_json(payload, origin="events.json")
        db_session.commit()
        second = service.ingest_json(payload, origin="events.json")
        db_session.commit()

        assert first.accepted == 2
        assert second.report.duplicate_batch is True
        assert second.accepted == 2  # reports what the original import stored
        assert repository.count_events(db_session) == 2

    def test_force_re_imports(self, service: IngestionService, db_session: Session) -> None:
        payload = json.dumps([VALID])
        service.ingest_json(payload, origin="events.json")
        db_session.commit()
        again = service.ingest_json(payload, origin="events.json", force=True)
        db_session.commit()

        assert again.report.duplicate_batch is False
        assert repository.count_events(db_session) == 2

    def test_different_content_is_a_different_batch(
        self, service: IngestionService, db_session: Session
    ) -> None:
        service.ingest_json(json.dumps([VALID]), origin="a.json")
        service.ingest_json(json.dumps([{**VALID, "hostname": "WIN-LAB-02"}]), origin="b.json")
        db_session.commit()
        assert len(repository.list_batches(db_session)) == 2

    def test_identical_events_within_one_batch_are_all_kept(
        self, service: IngestionService, db_session: Session
    ) -> None:
        """Deliberately not deduplicated: five identical failed logons are five
        failures, and collapsing them would break every rule that counts."""
        failure = {
            "timestamp": "2026-09-23T13:42:10Z",
            "source": "canonical",
            "event_type": "authentication_failure",
            "hostname": "WIN-LAB-01",
            "username": "lab-user",
        }
        service.ingest_json(json.dumps([failure] * 5), origin="brute.json")
        db_session.commit()
        assert repository.count_events(db_session) == 5


class TestAdapterResolution:
    def test_explicit_source_overrides_detection(self, service: IngestionService) -> None:
        payload = json.dumps(
            [{"UtcTime": "2026-09-23 13:00:00.000", "EventID": 1, "Image": "a.exe"}]
        )
        outcome = service.ingest_json(payload, adapter_name="sysmon", origin="x.json")
        assert outcome.report.adapter == "sysmon"

    def test_unrecognisable_content_is_reported_not_guessed(
        self, service: IngestionService
    ) -> None:
        outcome = service.ingest_json(json.dumps([{"colour": "blue"}]), origin="x.json")
        assert outcome.accepted == 0
        assert outcome.report.rejections[0].reason is RejectionReason.UNKNOWN_SOURCE

    def test_unknown_adapter_name_is_reported(self, service: IngestionService) -> None:
        outcome = service.ingest_json(json.dumps([VALID]), adapter_name="splunk", origin="x.json")
        assert outcome.report.rejections[0].reason is RejectionReason.UNKNOWN_SOURCE
        assert "Available" in outcome.report.rejections[0].detail


class TestFileImport:
    def test_json_file(self, service: IngestionService, tmp_path: Path) -> None:
        path = tmp_path / "events.json"
        path.write_text(json.dumps([VALID]), encoding="utf-8")
        assert service.ingest_file(path).accepted == 1

    def test_ndjson_file(self, service: IngestionService, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        path.write_text("\n".join(json.dumps(VALID) for _ in range(3)), encoding="utf-8")
        assert service.ingest_file(path).accepted == 3

    def test_csv_file(self, service: IngestionService, tmp_path: Path) -> None:
        path = tmp_path / "events.csv"
        path.write_text(
            "timestamp,source,hostname\n2026-09-23T13:42:10Z,canonical,H\n", encoding="utf-8"
        )
        assert service.ingest_file(path).accepted == 1

    def test_unsupported_extension_is_refused(
        self, service: IngestionService, tmp_path: Path
    ) -> None:
        path = tmp_path / "events.xml"
        path.write_text("<events/>", encoding="utf-8")
        with pytest.raises(ValueError, match="unsupported file type"):
            service.ingest_file(path)

    def test_missing_file_is_reported_clearly(
        self, service: IngestionService, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            service.ingest_file(tmp_path / "absent.json")

    def test_oversized_file_is_refused_before_reading(
        self, db_session: Session, db_settings: Settings, tmp_path: Path
    ) -> None:
        small_limit = db_settings.model_copy(update={"max_upload_bytes": 1_024})
        path = tmp_path / "huge.json"
        path.write_text(json.dumps([VALID] * 500), encoding="utf-8")
        with pytest.raises(FileTooLargeError):
            IngestionService(db_session, small_limit).ingest_file(path)

    def test_path_confinement_is_applied_when_roots_are_given(
        self, service: IngestionService, tmp_path: Path
    ) -> None:
        """The API passes roots because the path comes from a request."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.json"
        outside.write_text(json.dumps([VALID]), encoding="utf-8")
        with pytest.raises(UnsafePathError):
            service.ingest_file(outside, allowed_roots=[allowed])

    def test_confinement_permits_files_inside_the_root(
        self, service: IngestionService, tmp_path: Path
    ) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        inside = allowed / "events.json"
        inside.write_text(json.dumps([VALID]), encoding="utf-8")
        assert service.ingest_file(inside, allowed_roots=[allowed]).accepted == 1


class TestRecordLimit:
    def test_import_stops_at_the_configured_limit(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        limited = db_settings.model_copy(update={"max_events_per_import": 5})
        payload = json.dumps([VALID] * 20)
        outcome = IngestionService(db_session, limited).ingest_json(payload, origin="big.json")
        assert outcome.accepted == 5
        assert outcome.report.rejections[-1].reason is RejectionReason.LIMIT_EXCEEDED


class TestAuditTrail:
    def test_every_import_is_audited(self, service: IngestionService, db_session: Session) -> None:
        outcome = service.ingest_json(json.dumps([VALID]), origin="events.json")
        db_session.commit()

        trail = repository.list_audit(db_session)
        assert len(trail) == 1
        assert trail[0].action is AuditAction.EVENT_INGESTED
        assert trail[0].object_id == outcome.report.batch_id
        assert "1 accepted" in (trail[0].detail or "")

    def test_batch_record_links_to_its_rejections(
        self, service: IngestionService, db_session: Session
    ) -> None:
        payload = json.dumps([VALID, "bad", "worse"])
        outcome = service.ingest_json(payload, adapter_name="canonical", origin="events.json")
        db_session.commit()

        stored = repository.list_rejections(db_session, batch_id=outcome.report.batch_id)
        assert len(stored) == 2


class TestApiStyleIngestion:
    def test_mappings_are_ingested_directly(
        self, service: IngestionService, db_session: Session
    ) -> None:
        outcome = service.ingest_mappings([VALID, VALID], origin="api")
        db_session.commit()
        assert outcome.accepted == 2
        assert repository.count_events(db_session) == 2

    def test_repeated_api_posts_are_not_treated_as_duplicates(
        self, service: IngestionService, db_session: Session
    ) -> None:
        """Two identical posts usually mean two real occurrences."""
        service.ingest_mappings([VALID], origin="api")
        service.ingest_mappings([VALID], origin="api")
        db_session.commit()
        assert repository.count_events(db_session) == 2


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
class TestGenerator:
    def test_scenario_covers_the_whole_attack_chain(self) -> None:
        records = generate_demo_scenario()
        events = [get_adapter(r.adapter).normalise(r.record) for r in records]
        observed = {event.event_type for event in events}
        assert {
            EventType.AUTHENTICATION_FAILURE,
            EventType.AUTHENTICATION_SUCCESS,
            EventType.PROCESS_CREATION,
            EventType.NETWORK_CONNECTION,
            EventType.FILE_CREATION,
            EventType.DECOY_CREDENTIAL_ACCESS,
            EventType.ACCOUNT_CREATED,
            EventType.GROUP_MEMBERSHIP_CHANGE,
            EventType.NETWORK_EXPOSURE_CHANGE,
        } <= observed

    def test_scenario_spans_four_sources(self) -> None:
        grouped = group_by_adapter(generate_demo_scenario())
        assert set(grouped) == {"windows_security", "sysmon", "ghostcredential", "driftwatch"}

    def test_scenario_is_chronological(self) -> None:
        records = generate_demo_scenario()
        events = [get_adapter(r.adapter).normalise(r.record) for r in records]
        timestamps = [event.timestamp for event in events]
        assert timestamps == sorted(timestamps)

    def test_repeated_failures_precede_the_success(self) -> None:
        records = generate_demo_scenario()
        events = [get_adapter(r.adapter).normalise(r.record) for r in records]
        failures = [e for e in events if e.event_type is EventType.AUTHENTICATION_FAILURE]
        success = next(e for e in events if e.event_type is EventType.AUTHENTICATION_SUCCESS)
        assert len(failures) >= 5
        assert all(failure.timestamp < success.timestamp for failure in failures)

    def test_generation_is_reproducible(self) -> None:
        first = generate_normal_activity(20, seed=7)
        second = generate_normal_activity(20, seed=7)
        assert [r.record for r in first] == [r.record for r in second]

    def test_different_seeds_differ(self) -> None:
        a = generate_normal_activity(20, seed=1)
        b = generate_normal_activity(20, seed=2)
        assert [r.record for r in a] != [r.record for r in b]

    def test_sample_data_contains_no_routable_external_addresses(self) -> None:
        """Synthetic data must not point at anyone's real infrastructure."""
        import ipaddress

        text = json.dumps([r.record for r in generate_dataset()], default=str)
        import re

        for candidate in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
            address = ipaddress.ip_address(candidate)
            assert address.is_private or address.is_global is False, (
                f"{candidate} is a routable public address"
            )

    def test_the_whole_generated_dataset_ingests_cleanly(
        self, service: IngestionService, db_session: Session
    ) -> None:
        grouped = group_by_adapter(generate_dataset(normal_count=25))
        total = 0
        for adapter_name, records in grouped.items():
            outcome = service.ingest_mappings(records, adapter_name=adapter_name, origin="demo")
            assert outcome.rejected == 0, outcome.report.rejections
            total += outcome.accepted
        db_session.commit()
        assert repository.count_events(db_session) == total
