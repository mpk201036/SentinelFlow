"""Stage 4 — CSV ingestion.

CSV is where real exports are messiest: a delimiter that is not a comma, a BOM
from Excel, ragged rows, blank lines, and columns that are empty rather than
absent.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database import repository
from app.ingestion.parsers import parse_csv_records
from app.ingestion.service import IngestionService
from app.models.ingestion import RejectionReason

pytestmark = pytest.mark.unit

HEADER = "timestamp,source,event_type,hostname,process_name"
ROW = "2026-09-23T13:42:10Z,canonical,process_creation,WIN-LAB-01,powershell.exe"


def records(text: str):
    return list(parse_csv_records(text))


class TestParsing:
    def test_header_and_rows(self) -> None:
        parsed = records(f"{HEADER}\n{ROW}\n{ROW}")
        assert len(parsed) == 2
        assert parsed[0].record["hostname"] == "WIN-LAB-01"

    @pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
    def test_delimiter_is_detected(self, delimiter: str) -> None:
        """Semicolon exports are normal wherever the comma is a decimal separator."""
        header = delimiter.join(["timestamp", "source", "hostname"])
        row = delimiter.join(["2026-09-23T13:42:10Z", "canonical", "WIN-LAB-01"])
        parsed = records(f"{header}\n{row}\n{row}")
        assert len(parsed) == 2
        assert parsed[0].record["hostname"] == "WIN-LAB-01"

    def test_excel_bom_is_stripped_from_the_first_header(self) -> None:
        parsed = records(f"﻿{HEADER}\n{ROW}")
        assert "timestamp" in parsed[0].record

    def test_empty_cells_are_omitted_rather_than_stored_as_empty_strings(self) -> None:
        parsed = records(f"{HEADER}\n2026-09-23T13:42:10Z,canonical,,WIN-LAB-01,")
        assert "event_type" not in parsed[0].record
        assert "process_name" not in parsed[0].record

    def test_blank_rows_are_reported_not_silently_skipped(self) -> None:
        parsed = records(f"{HEADER}\n{ROW}\n,,,,\n{ROW}")
        assert [p.ok for p in parsed] == [True, False, True]
        assert parsed[1].reason is RejectionReason.EMPTY_RECORD

    def test_ragged_row_is_rejected_with_its_position(self) -> None:
        parsed = records(f"{HEADER}\n{ROW},extra")
        assert parsed[0].reason is RejectionReason.MALFORMED_CSV
        assert "more fields than the header" in (parsed[0].detail or "")

    def test_quoted_fields_containing_delimiters(self) -> None:
        text = 'timestamp,source,command_line\n2026-09-23T13:42:10Z,canonical,"a,b,c"'
        assert records(text)[0].record["command_line"] == "a,b,c"

    def test_empty_file(self) -> None:
        assert records("")[0].reason is RejectionReason.EMPTY_RECORD

    def test_header_only_yields_nothing(self) -> None:
        assert records(HEADER) == []

    def test_row_count_is_capped(self) -> None:
        text = f"{HEADER}\n" + "\n".join([ROW] * 10)
        parsed = list(parse_csv_records(text, max_records=3))
        assert parsed[-1].reason is RejectionReason.LIMIT_EXCEEDED

    def test_whitespace_in_headers_is_trimmed(self) -> None:
        text = " timestamp , source , hostname \n2026-09-23T13:42:10Z,canonical,H"
        assert "timestamp" in records(text)[0].record


class TestEndToEnd:
    def test_firewall_export_is_ingested(self, db_session: Session, db_settings: Settings) -> None:
        csv_text = (
            "timestamp,action,src_ip,dst_ip,dst_port,protocol,hostname\n"
            "2026-09-23T12:03:52Z,deny,192.0.2.77,10.0.0.5,3389,tcp,FW-EDGE-01\n"
            "2026-09-23T12:07:31Z,deny,192.0.2.77,10.0.0.5,445,tcp,FW-EDGE-01\n"
        )
        outcome = IngestionService(db_session, db_settings).ingest_csv(csv_text, origin="fw.csv")
        db_session.commit()

        assert outcome.report.adapter == "firewall"
        assert outcome.accepted == 2
        stored = repository.list_events(db_session)
        assert {event.dst_port for event in stored} == {3389, 445}
        assert all("blocked" in event.tags for event in stored)

    def test_numbers_arrive_as_strings_and_are_coerced(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """Everything in a CSV is text; ports must still end up as integers."""
        csv_text = f"{HEADER},src_port\n{ROW},51022"
        outcome = IngestionService(db_session, db_settings).ingest_csv(csv_text, origin="p.csv")
        assert outcome.accepted == 1
        assert outcome.events[0].src_port == 51022

    def test_bad_row_does_not_abort_the_import(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        csv_text = f"{HEADER},src_ip\n{ROW},10.0.0.5\n{ROW},10.0.0.999\n{ROW},10.0.0.6\n"
        outcome = IngestionService(db_session, db_settings).ingest_csv(csv_text, origin="mix.csv")
        db_session.commit()
        assert outcome.accepted == 2
        assert outcome.rejected == 1
        assert repository.count_events(db_session) == 2

    def test_csv_formula_content_is_stored_as_data(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        """A cell beginning with '=' is text here. Neutralising it belongs at
        export time, not at import, where it would corrupt the evidence."""
        csv_text = f"{HEADER}\n2026-09-23T13:42:10Z,canonical,,WIN-LAB-01,\"=cmd|'/c calc'!A1\""
        outcome = IngestionService(db_session, db_settings).ingest_csv(csv_text, origin="f.csv")
        assert outcome.accepted == 1
        assert outcome.events[0].process_name == "=cmd|'/c calc'!A1"
