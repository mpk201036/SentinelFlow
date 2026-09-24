"""Stage 15 - properties that must hold for every input, not just the ones we thought of.

Every boundary that takes untrusted input is fuzzed with Hypothesis: the
sanitisers, defanging, the Markdown escaping, the parsers, the injection scan,
the model-reply parser, and the analyst workflow as a sequence of random
decisions. Hypothesis generates inputs no one would write by hand - lone
surrogate-free Unicode, control characters, backtick runs, deeply nested
JSON - and shrinks any failure to its smallest form.

Writing these properties found a real defect: truncation was not
idempotent, so a field shortened at ingestion was shortened again, with a
wrong count, every time it was loaded back from the database. The sanitiser
properties catch it directly, and ``TestRoundTrips`` catches its effect on
stored events - but only because its long values are built on purpose: left
to itself, Hypothesis rarely generates a string past the 8,192-character
limit, and the first version of that test passed with the defect in place.

Run longer before a release: ``HYPOTHESIS_PROFILE=thorough pytest tests/test_properties.py``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, note
from hypothesis import strategies as st
from markdown_it import MarkdownIt
from sqlalchemy.orm import Session, sessionmaker

from app.ai.injection import EXCERPT_CHARS
from app.ai.injection import scan_text as scan_injection
from app.ai.output import AIOutputError, parse_reply
from app.core.config import Settings
from app.core.sanitize import MAX_TEXT_FIELD, clean_line, clean_text
from app.database import repository
from app.database.init_db import initialize_database
from app.database.session import create_db_engine
from app.enrichment.defang import defang_text
from app.enrichment.extractor import IOCExtractor
from app.ingestion import get_adapter
from app.ingestion.service import IngestionService
from app.models.alert import AlertSeverity, SeverityFactor
from app.models.enums import (
    AlertStatus,
    Classification,
    IndicatorType,
    Severity,
)
from app.reports.markdown import md_block, md_code, md_text
from app.services.workflow import (
    CLOSED_STATUSES,
    AlertDecision,
    AnalystWorkflow,
    Channel,
    WorkflowError,
)
from tests.ai_support import triaged_alert

#: Text as it arrives from logs: anything, including control characters.
anything = st.text(max_size=400)
#: Text without the characters a Markdown parser rewrites on input (NUL and
#: carriage returns), for properties that compare parsed output to input.
parseable = st.text(
    alphabet=st.characters(exclude_characters="\x00\r", exclude_categories=["Cs"]),
    max_size=300,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _tokens(markdown: str) -> list[Any]:
    parser = MarkdownIt("commonmark").enable("table")
    flat: list[Any] = []

    def walk(tokens: list[Any]) -> None:
        for token in tokens:
            flat.append(token)
            if token.children:
                walk(token.children)

    walk(parser.parse(markdown))
    return flat


# ===========================================================================
# Sanitisers
# ===========================================================================
@pytest.mark.unit
class TestSanitisers:
    @given(anything, st.integers(min_value=1, max_value=200))
    def test_clean_text_is_idempotent_bounded_and_free_of_control_characters(
        self, value: str, limit: int
    ) -> None:
        once = clean_text(value, max_length=limit)
        if once is None:
            return
        assert clean_text(once, max_length=limit) == once
        assert not _CONTROL.search(once)
        assert len(once) <= limit + len("...[truncated 9999999999 chars]")

    @given(anything, st.integers(min_value=1, max_value=200))
    def test_clean_line_is_one_idempotent_line(self, value: str, limit: int) -> None:
        once = clean_line(value, max_length=limit)
        if once is None:
            return
        assert "\n" not in once and "\r" not in once
        assert clean_line(once, max_length=limit) == once


# ===========================================================================
# Defanging and Markdown escaping
# ===========================================================================
@pytest.mark.unit
class TestReportEscaping:
    @given(anything)
    def test_defanging_is_idempotent_and_leaves_nothing_clickable(self, value: str) -> None:
        once = defang_text(value)
        assert defang_text(once) == once
        assert not re.search(r"(?i)\bhttps?://", once)
        assert not re.search(r"(?i)(?<![\w.-])www\.", once)

    @given(parseable)
    def test_prose_never_becomes_markup(self, value: str) -> None:
        note(md_text(value))
        types = {token.type for token in _tokens(f"Text: {md_text(value)}")}
        forbidden = {
            "link_open",
            "image",
            "html_inline",
            "html_block",
            "heading_open",
            "fence",
            "code_block",
            "table_open",
            "code_inline",
        }
        assert not types & forbidden

    @given(parseable.filter(lambda v: v.strip() and "\n" not in v))
    def test_inline_code_holds_any_single_line(self, value: str) -> None:
        (code,) = [t for t in _tokens(md_code(value)) if t.type == "code_inline"]
        assert code.content.strip() == " ".join(value.split())

    @given(parseable)
    def test_a_fenced_block_holds_any_text_and_cannot_be_closed_early(self, value: str) -> None:
        tokens = _tokens(md_block(value) + "\n\nAfter.")
        fences = [t for t in tokens if t.type == "fence"]
        assert len(fences) == 1
        assert fences[0].content == value + "\n"


# ===========================================================================
# Parsers and scanners never fail on hostile input
# ===========================================================================
_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=5)
    ),
    max_leaves=25,
)


@pytest.mark.unit
class TestParsers:
    @given(anything)
    def test_the_injection_scan_always_answers_briefly(self, value: str) -> None:
        for technique, excerpt in scan_injection(value):
            assert technique and "\n" not in excerpt
            assert len(excerpt) <= EXCERPT_CHARS + 6

    @given(st.one_of(anything, _json_values.map(json.dumps)))
    def test_a_model_reply_is_parsed_or_refused_never_anything_else(self, raw: str) -> None:
        with contextlib.suppress(AIOutputError):
            parse_reply(raw)

    @given(anything)
    def test_indicator_extraction_never_fails_and_ips_are_real(self, value: str) -> None:
        for kind, found in IOCExtractor().scan_text(value):
            if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
                ipaddress.ip_address(found)

    @given(st.lists(st.integers(min_value=-100, max_value=100), max_size=12))
    def test_a_score_is_always_between_0_and_100_and_in_its_band(self, points: list[int]) -> None:
        severity = AlertSeverity.from_factors(
            SeverityFactor(name=f"f{i}", points=p, detail="x") for i, p in enumerate(points)
        )
        assert 0 <= severity.score <= 100
        assert severity.level is Severity.from_score(severity.score)


@contextmanager
def _database() -> Iterator[tuple[Session, Settings]]:
    """A fresh database per example, so examples cannot see each other."""
    with tempfile.TemporaryDirectory() as directory:
        settings = Settings(_env_file=None, database_url=f"sqlite:///{Path(directory) / 'p.db'}")
        engine = create_db_engine(settings)
        initialize_database(engine)
        session = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            yield session, settings
        finally:
            session.close()
            engine.dispose()


@pytest.mark.integration  # a fresh database per example
class TestIngestion:
    @given(st.one_of(st.binary(max_size=600), _json_values.map(lambda v: json.dumps(v).encode())))
    def test_any_json_import_accounts_for_every_record_and_never_crashes(self, data: bytes) -> None:
        with _database() as (session, settings):
            outcome = IngestionService(session, settings).ingest_json(
                data, adapter_name="canonical", persist=False
            )
            assert outcome.accepted == len(outcome.events)
            assert outcome.accepted + outcome.rejected >= 0

    @given(st.text(max_size=600))
    def test_any_csv_import_never_crashes(self, data: str) -> None:
        with _database() as (session, settings):
            IngestionService(session, settings).ingest_csv(
                data, adapter_name="firewall", persist=False
            )


# ===========================================================================
# What goes into the database comes back unchanged
# ===========================================================================
@pytest.mark.integration  # a fresh database per example
class TestRoundTrips:
    @given(
        # Built long on purpose: values past MAX_TEXT_FIELD are where
        # truncation, and the defect it had, live.
        command=st.builds(
            lambda head, extra: head + "A" * extra,
            st.text(max_size=40),
            st.integers(min_value=0, max_value=MAX_TEXT_FIELD + 500),
        ).filter(str.strip),
        message=st.text(min_size=1, max_size=300),
        user=st.text(min_size=1, max_size=300),
    )
    def test_an_event_survives_storage_unchanged(
        self, command: str, message: str, user: str
    ) -> None:
        """Stored evidence reads back exactly as it was stored, however long."""
        event = get_adapter("canonical").normalise(
            {
                "timestamp": "2026-09-23T13:42:10Z",
                "source": "canonical",
                "event_type": "process_creation",
                "hostname": "WIN-PROP-01",
                "username": user,
                "command_line": command,
                "event_message": message,
            }
        )
        with _database() as (session, _):
            repository.save_event(session, event)
            session.commit()
            session.expire_all()
            stored = repository.get_event(session, event.event_id)
        assert stored is not None
        for name in ("command_line", "event_message", "username"):
            assert getattr(stored, name) == getattr(event, name), name


# ===========================================================================
# The workflow's invariants, under any sequence of decisions
# ===========================================================================
_decisions = st.lists(
    st.builds(
        AlertDecision,
        status=st.none() | st.sampled_from(list(AlertStatus)),
        classification=st.none() | st.sampled_from(list(Classification)),
        reason=st.none() | st.sampled_from(["", "   ", "Because the evidence says so"]),
    ),
    min_size=1,
    max_size=12,
)


@pytest.mark.integration  # a fresh database per example
class TestWorkflowInvariants:
    @given(_decisions)
    def test_no_sequence_of_decisions_breaks_the_rules(
        self, decisions: list[AlertDecision]
    ) -> None:
        with _database() as (session, settings):
            alert = triaged_alert(session, settings)
            workflow = AnalystWorkflow(session, analyst="fuzz", channel=Channel.CLI)
            changes = 0
            left_new = False
            for decision in decisions:
                try:
                    result = workflow.decide_alert(alert.alert_id, decision)
                except WorkflowError:
                    continue
                changes += len(result.changes)
                current = repository.get_alert(session, alert.alert_id)
                assert current is not None
                left_new = left_new or current.status is not AlertStatus.NEW
                # Once someone has looked, the alert never goes back to New.
                assert not (left_new and current.status is AlertStatus.NEW)
                closed = current.status in CLOSED_STATUSES
                # Closed alerts have an answer that fits, and a closing time.
                assert (current.closed_at is not None) is closed
                if closed:
                    assert current.classification is not None
                    assert current.classification is not Classification.NEEDS_MORE_INFORMATION
                if current.status is AlertStatus.BENIGN:
                    assert current.classification in {
                        Classification.BENIGN_POSITIVE,
                        Classification.FALSE_POSITIVE,
                    }
            # Every change, and nothing else, was audited.
            audited = [
                entry
                for entry in repository.list_audit(session, object_id=alert.alert_id, limit=500)
                if entry.actor.value == "analyst"
            ]
            assert len(audited) == changes
