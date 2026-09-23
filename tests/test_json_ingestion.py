"""Stage 4 — JSON ingestion.

The rule under test throughout: one bad record costs one event, never the
batch, and the counts always add up.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import repository
from app.ingestion.parsers import MAX_JSON_DEPTH, parse_json_records
from app.ingestion.service import IngestionService
from app.models.enums import EventType
from app.models.ingestion import RejectionReason

pytestmark = pytest.mark.unit

VALID = {
    "timestamp": "2026-09-23T13:42:10Z",
    "source": "canonical",
    "event_type": "process_creation",
    "hostname": "WIN-LAB-01",
    "process_name": "powershell.exe",
}


def reasons(text: str) -> list[RejectionReason | None]:
    return [record.reason for record in parse_json_records(text)]


class TestFormatDetection:
    def test_array_of_objects(self) -> None:
        records = list(parse_json_records(json.dumps([VALID, VALID])))
        assert len(records) == 2
        assert all(record.ok for record in records)

    def test_single_object(self) -> None:
        records = list(parse_json_records(json.dumps(VALID)))
        assert len(records) == 1 and records[0].ok

    def test_newline_delimited(self) -> None:
        text = "\n".join(json.dumps(VALID) for _ in range(3))
        records = list(parse_json_records(text))
        assert len(records) == 3 and all(record.ok for record in records)

    @pytest.mark.parametrize("key", ["events", "records", "data", "results", "items"])
    def test_wrapped_array(self, key: str) -> None:
        records = list(parse_json_records(json.dumps({key: [VALID, VALID]})))
        assert len(records) == 2 and all(record.ok for record in records)

    def test_utf8_bom_is_tolerated(self) -> None:
        data = ("﻿" + json.dumps([VALID])).encode("utf-8")
        assert next(iter(parse_json_records(data))).ok

    def test_bytes_and_text_behave_identically(self) -> None:
        text = json.dumps([VALID])
        assert len(list(parse_json_records(text))) == len(list(parse_json_records(text.encode())))


class TestMalformedInput:
    def test_empty_file(self) -> None:
        assert reasons("   ") == [RejectionReason.EMPTY_RECORD]

    def test_not_json_at_all(self) -> None:
        assert reasons("this is not json") == [RejectionReason.MALFORMED_JSON]

    def test_one_bad_ndjson_line_costs_one_record(self) -> None:
        text = f"{json.dumps(VALID)}\nbroken {{\n{json.dumps(VALID)}"
        records = list(parse_json_records(text))
        assert [record.ok for record in records] == [True, False, True]
        assert records[1].reason is RejectionReason.MALFORMED_JSON

    def test_non_object_entries_are_rejected_individually(self) -> None:
        records = list(parse_json_records(json.dumps([VALID, "a string", 42, None])))
        assert [record.ok for record in records] == [True, False, False, False]
        assert all(r.reason is RejectionReason.NOT_AN_OBJECT for r in records[1:])

    def test_empty_object_is_rejected(self) -> None:
        assert reasons(json.dumps([{}])) == [RejectionReason.EMPTY_RECORD]

    def test_top_level_scalar_is_rejected(self) -> None:
        assert reasons("42") == [RejectionReason.NOT_AN_OBJECT]

    def test_the_rejected_payload_is_kept_for_diagnosis(self) -> None:
        records = list(parse_json_records("{oops}"))
        assert records[0].raw is not None and "oops" in records[0].raw


class TestResourceLimits:
    def test_deeply_nested_object_is_rejected(self) -> None:
        nested = '{"a":' * (MAX_JSON_DEPTH + 10) + "1" + "}" * (MAX_JSON_DEPTH + 10)
        assert reasons(f"[{nested}]") == [RejectionReason.NESTING_TOO_DEEP]

    def test_nesting_at_the_limit_is_accepted(self) -> None:
        depth = MAX_JSON_DEPTH - 2
        nested = '{"a":' * depth + "1" + "}" * depth
        assert next(iter(parse_json_records(f"[{nested}]"))).ok

    def test_a_bracket_bomb_does_not_crash_the_process(self) -> None:
        """Enough nesting to exhaust the C stack inside json.loads."""
        bomb = "[" * 200_000 + "]" * 200_000
        assert reasons(bomb) == [RejectionReason.NESTING_TOO_DEEP]

    def test_record_count_is_capped(self) -> None:
        records = list(parse_json_records(json.dumps([VALID] * 10), max_records=4))
        assert len(records) == 5  # four accepted plus the limit notice
        assert records[-1].reason is RejectionReason.LIMIT_EXCEEDED

    def test_ndjson_record_count_is_capped(self) -> None:
        text = "\n".join(json.dumps(VALID) for _ in range(10))
        records = list(parse_json_records(text, max_records=3))
        assert records[-1].reason is RejectionReason.LIMIT_EXCEEDED


class TestEndToEnd:
    def test_valid_events_are_stored(self, db_session: Session, db_settings: Settings) -> None:
        service = IngestionService(db_session, db_settings)
        outcome = service.ingest_json(json.dumps([VALID, VALID]), origin="test.json")
        db_session.commit()

        assert outcome.accepted == 2
        assert outcome.rejected == 0
        assert repository.count_events(db_session) == 2
        stored = repository.list_events(db_session)
        assert stored[0].event_type is EventType.PROCESS_CREATION

    def test_mixed_batch_keeps_the_good_and_records_the_bad(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        payload = json.dumps(
            [
                VALID,
                {**VALID, "src_ip": "10.0.0.999"},
                {"source": "canonical", "hostname": "H"},
                "not an object",
            ]
        )
        outcome = IngestionService(db_session, db_settings).ingest_json(
            payload, origin="mixed.json"
        )
        db_session.commit()

        assert outcome.accepted == 1
        assert outcome.rejected == 3
        assert outcome.report.total == 4
        assert outcome.report.rejection_counts() == {
            "schema_validation": 1,
            "adapter_error": 1,
            "not_an_object": 1,
        }

    def test_rejections_are_persisted_with_their_reasons(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """An analyst must be able to see the gap, not just experience it."""
        payload = json.dumps([{**VALID, "file_hash": "deadbeef"}])
        IngestionService(db_session, db_settings).ingest_json(payload, origin="bad.json")
        db_session.commit()

        stored = repository.list_rejections(db_session)
        assert len(stored) == 1
        assert stored[0].reason is RejectionReason.SCHEMA_VALIDATION
        assert "SHA256" in stored[0].detail
        assert stored[0].origin == "bad.json"

    def test_forward_dated_events_are_rejected(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        payload = json.dumps([{**VALID, "timestamp": "2099-01-01T00:00:00Z"}])
        outcome = IngestionService(db_session, db_settings).ingest_json(
            payload, origin="future.json"
        )
        assert outcome.rejected == 1
        assert "too far in the future" in outcome.report.rejections[0].detail

    def test_adapter_is_detected_from_the_content(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        payload = json.dumps(
            [
                {
                    "UtcTime": "2026-09-23 13:42:10.000",
                    "EventID": 1,
                    "Image": "a.exe",
                    "Computer": "H",
                }
            ]
        )
        outcome = IngestionService(db_session, db_settings).ingest_json(payload, origin="s.json")
        assert outcome.report.adapter == "sysmon"

    def test_dry_run_stores_nothing(self, db_session: Session, db_settings: Settings) -> None:
        outcome = IngestionService(db_session, db_settings).ingest_json(
            json.dumps([VALID]), origin="dry.json", persist=False
        )
        db_session.commit()
        assert outcome.accepted == 1
        assert repository.count_events(db_session) == 0
