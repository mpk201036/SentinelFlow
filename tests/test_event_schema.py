"""Stage 2 — the canonical event schema.

The event model is the only thing downstream components see, so its guarantees
matter more than any other model's: what is present is valid, what is absent is
genuinely absent, and nothing that arrived is silently thrown away.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.models import EventType, SecurityEvent, Severity, utcnow

pytestmark = pytest.mark.unit


def make_event(**overrides: object) -> SecurityEvent:
    payload: dict[str, object] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "sysmon",
    }
    payload.update(overrides)
    return SecurityEvent(**payload)  # type: ignore[arg-type]


class TestMinimalEvent:
    def test_only_timestamp_and_source_are_required(self) -> None:
        event = make_event()
        assert event.source == "sysmon"
        assert isinstance(event.event_id, UUID)
        assert event.event_type is EventType.OTHER

    def test_every_other_field_defaults_to_none_or_empty(self) -> None:
        """Sources populate wildly different subsets; absence must be representable."""
        event = make_event()
        for field in ("hostname", "username", "src_ip", "command_line", "file_hash", "url"):
            assert getattr(event, field) is None
        assert event.tags == []
        assert event.raw_event == {}

    @pytest.mark.parametrize("missing", ["timestamp", "source"])
    def test_required_fields_are_enforced(self, missing: str) -> None:
        payload = {"timestamp": "2026-09-23T13:42:10Z", "source": "sysmon"}
        payload.pop(missing)
        with pytest.raises(ValidationError):
            SecurityEvent(**payload)  # type: ignore[arg-type]


class TestEvidenceIsImmutable:
    def test_events_are_frozen(self) -> None:
        event = make_event(hostname="WIN-LAB-01")
        with pytest.raises(ValidationError):
            event.hostname = "OTHER-HOST"  # type: ignore[misc]

    def test_unknown_fields_are_rejected(self) -> None:
        """A typo in a payload is an error, not a silently ignored key."""
        with pytest.raises(ValidationError):
            make_event(hostnmae="WIN-LAB-01")


class TestTimestamps:
    def test_zulu_suffix_is_parsed_as_utc(self) -> None:
        assert make_event().timestamp == datetime(2026, 9, 23, 13, 42, 10, tzinfo=UTC)

    def test_naive_timestamps_are_assumed_utc(self) -> None:
        event = make_event(timestamp="2026-09-23T13:42:10")
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.utcoffset() == timedelta(0)

    def test_offset_timestamps_are_converted(self) -> None:
        event = make_event(timestamp="2026-09-23T15:42:10+02:00")
        assert event.timestamp == datetime(2026, 9, 23, 13, 42, 10, tzinfo=UTC)

    def test_received_at_is_generated_and_aware(self) -> None:
        assert make_event().received_at.tzinfo is not None

    def test_far_future_timestamps_are_rejected(self) -> None:
        """Forward-dating pushes an event off the bottom of a time-sorted queue."""
        with pytest.raises(ValidationError, match="too far in the future"):
            make_event(timestamp=utcnow() + timedelta(days=30))

    def test_modest_clock_skew_is_tolerated(self) -> None:
        assert make_event(timestamp=utcnow() + timedelta(hours=2)) is not None

    def test_implausibly_old_timestamps_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="implausibly old"):
            make_event(timestamp="1970-01-01T00:00:00Z")


class TestEventTypeNormalisation:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("process_creation", EventType.PROCESS_CREATION),
            ("Process Creation", EventType.PROCESS_CREATION),
            ("AUTHENTICATION-FAILURE", EventType.AUTHENTICATION_FAILURE),
        ],
    )
    def test_recognised_types_are_canonicalised(self, raw: str, expected: EventType) -> None:
        assert make_event(event_type=raw).event_type is expected

    def test_unknown_types_fall_back_without_losing_data(self) -> None:
        """An unrecognised category must never cause an event to be dropped."""
        event = make_event(event_type="ProcessCreate")
        assert event.event_type is EventType.OTHER
        assert event.event_type_raw == "ProcessCreate"

    def test_the_original_is_preserved_for_known_types_too(self) -> None:
        assert make_event(event_type="Process Creation").event_type_raw == "Process Creation"


class TestNetworkFields:
    def test_ips_are_canonicalised(self) -> None:
        event = make_event(src_ip="::ffff:10.0.0.5", dst_ip="2001:0DB8::1")
        assert event.src_ip == "10.0.0.5"
        assert event.dst_ip == "2001:db8::1"

    def test_invalid_ip_is_rejected_rather_than_stored(self) -> None:
        """A field labelled 'source IP' in the UI must actually contain one."""
        with pytest.raises(ValidationError, match="not a valid IP address"):
            make_event(src_ip="10.0.0.999")

    def test_blank_ip_becomes_none(self) -> None:
        assert make_event(src_ip="   ").src_ip is None

    @pytest.mark.parametrize("port", [-1, 65536, 99999])
    def test_out_of_range_ports_are_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError):
            make_event(dst_port=port)

    def test_valid_ports_are_accepted(self) -> None:
        assert make_event(src_port=0, dst_port=65535).dst_port == 65535


class TestContentFields:
    def test_domain_is_normalised(self) -> None:
        assert make_event(domain="Evil.Example.COM.").domain == "evil.example.com"

    def test_hash_is_lower_cased_and_typed(self) -> None:
        event = make_event(file_hash="A" * 64)
        assert event.file_hash == "a" * 64
        assert event.file_hash_algorithm == "sha256"

    def test_malformed_hash_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_event(file_hash="deadbeef")

    def test_absolute_urls_are_accepted(self) -> None:
        url = "http://updates.example.com/tool.exe"
        assert make_event(url=url).url == url

    @pytest.mark.parametrize("bad", ["tool.exe", "/tmp/tool.exe", "www.example.com"])
    def test_relative_urls_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not a valid absolute URL"):
            make_event(url=bad)

    def test_command_line_keeps_newlines_but_loses_control_characters(self) -> None:
        event = make_event(command_line="powershell.exe\n-enc AAA=\x00")
        assert event.command_line == "powershell.exe\n-enc AAA="

    def test_hostname_loses_bidi_disguise(self) -> None:
        assert make_event(hostname="WIN-LAB‮-01").hostname == "WIN-LAB-01"

    def test_oversized_command_line_is_truncated_visibly(self) -> None:
        event = make_event(command_line="A" * 20_000)
        assert event.command_line is not None
        assert "truncated" in event.command_line


class TestTagsAndRawEvent:
    def test_tags_are_slugged_and_deduplicated(self) -> None:
        event = make_event(tags=["Lab", "lab", "Needs Review"])
        assert event.tags == ["lab", "needs_review"]

    def test_tags_accept_a_comma_separated_string(self) -> None:
        assert make_event(tags="lab, demo").tags == ["lab", "demo"]

    def test_unusable_tags_are_dropped_not_fatal(self) -> None:
        assert make_event(tags=["ok", "!!!"]).tags == ["ok"]

    def test_raw_event_is_preserved(self) -> None:
        assert make_event(raw_event={"EventID": 1}).raw_event == {"EventID": 1}

    def test_oversized_raw_event_is_replaced_by_a_visible_marker(self) -> None:
        event = make_event(raw_event={"blob": "x" * 100_000})
        assert event.raw_event["_sentinelflow_truncated"] is True
        assert event.raw_event["_original_size_bytes"] > 64 * 1024


class TestSourceHints:
    def test_source_severity_is_stored_separately_from_any_verdict(self) -> None:
        """The source's claim is a hint, and it is named so nobody mistakes it."""
        event = make_event(source_severity="critical")
        assert event.source_severity is Severity.CRITICAL
        assert not hasattr(event, "severity")

    def test_event_carries_no_verdict_fields(self) -> None:
        """Interpretation lives on the Alert, never on the evidence."""
        for forbidden in ("severity", "status", "mitre_techniques", "classification"):
            assert forbidden not in SecurityEvent.model_fields


class TestCorrelationHelpers:
    def test_hostname_key_is_case_insensitive(self) -> None:
        assert make_event(hostname="WIN-LAB-01").hostname_key == "win-lab-01"

    def test_username_key_strips_domain_prefix(self) -> None:
        assert make_event(username="LAB\\Lab-User").username_key == "lab-user"

    def test_username_key_strips_machine_account_suffix(self) -> None:
        assert make_event(username="WIN-LAB-01$").username_key == "win-lab-01"

    def test_correlation_identity_omits_empty_values(self) -> None:
        identity = make_event(hostname="WIN-LAB-01", src_ip="10.0.0.5").correlation_identity()
        assert identity == {"hostname": "win-lab-01", "src_ip": "10.0.0.5"}

    def test_describe_is_human_readable(self) -> None:
        event = make_event(
            event_type="process_creation", process_name="powershell.exe", hostname="WIN-LAB-01"
        )
        assert event.describe() == "process creation process=powershell.exe host=WIN-LAB-01"


class TestSerialisation:
    def test_round_trip_through_json_is_lossless(self) -> None:
        event = make_event(
            event_type="process_creation",
            hostname="WIN-LAB-01",
            username="lab-user",
            process_name="powershell.exe",
            command_line="powershell.exe -enc AAA=",
            src_ip="10.0.0.5",
            tags=["lab"],
            raw_event={"EventID": 1},
        )
        assert SecurityEvent.model_validate_json(event.to_json()) == event
