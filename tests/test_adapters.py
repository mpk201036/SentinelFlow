"""Stage 4 — source adapters.

An adapter is where a real export meets a strict schema, so these tests lean on
the messy parts: inconsistent casing, Windows' ``-`` placeholder, hex process
ids, several spellings of the same field, and event types nobody has mapped yet.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.ingestion.adapters import (
    AdapterError,
    CanonicalAdapter,
    DriftWatchAdapter,
    FirewallAdapter,
    GhostCredentialAdapter,
    SysmonAdapter,
    UnknownAdapterError,
    WindowsSecurityAdapter,
    adapter_names,
    detect_adapter,
    get_adapter,
    resolve_adapter,
)
from app.ingestion.adapters.base import RecordView, first_ip, image_basename, preferred_hash
from app.models.enums import Confidence, EventType, Severity

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
class TestRecordView:
    def test_lookup_is_case_insensitive(self) -> None:
        view = RecordView({"Computer": "WIN-LAB-01"})
        assert view.text("computer") == "WIN-LAB-01"
        assert view.text("COMPUTER") == "WIN-LAB-01"

    def test_first_non_empty_spelling_wins(self) -> None:
        view = RecordView({"host": "", "hostname": "WIN-LAB-01"})
        assert view.text("host", "hostname") == "WIN-LAB-01"

    def test_windows_placeholder_counts_as_absent(self) -> None:
        """Windows writes '-' where a field does not apply."""
        assert RecordView({"IpAddress": "-"}).text("ipaddress") is None

    def test_hex_process_ids_are_parsed(self) -> None:
        assert RecordView({"ProcessId": "0x10a4"}).integer("processid") == 4260

    def test_unparseable_numbers_become_none(self) -> None:
        assert RecordView({"ProcessId": "N/A"}).integer("processid") is None

    def test_empty_record_is_detected(self) -> None:
        assert RecordView({"a": "", "b": "-", "c": None}).is_empty()
        assert not RecordView({"a": "x"}).is_empty()


class TestParsingHelpers:
    @pytest.mark.parametrize(
        "path, expected",
        [
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("/usr/bin/curl", "curl"),
            ("powershell.exe", "powershell.exe"),
            (None, None),
        ],
    )
    def test_image_basename(self, path: str | None, expected: str | None) -> None:
        assert image_basename(path) == expected

    def test_strongest_hash_is_preferred(self) -> None:
        value = f"MD5={'b' * 32},SHA256={'a' * 64}"
        assert preferred_hash(value) == "a" * 64

    def test_bare_digest_is_accepted(self) -> None:
        assert preferred_hash("A" * 64) == "A" * 64

    def test_unrecognised_hash_field_returns_none(self) -> None:
        assert preferred_hash("not-a-hash") is None

    @pytest.mark.parametrize("value", ["-", "", "WORKSTATION", None])
    def test_non_addresses_are_dropped_rather_than_failing_the_event(self, value: str) -> None:
        assert first_ip(value) is None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class TestRegistry:
    def test_every_adapter_is_registered(self) -> None:
        assert set(adapter_names()) == {
            "ghostcredential",
            "driftwatch",
            "sysmon",
            "windows_security",
            "firewall",
            "canonical",
        }

    @pytest.mark.parametrize(
        "alias, expected",
        [
            ("windows", "windows_security"),
            ("decoy", "ghostcredential"),
            ("fw", "firewall"),
            ("SYSMON", "sysmon"),
            ("drift-watch", "driftwatch"),
        ],
    )
    def test_aliases_resolve(self, alias: str, expected: str) -> None:
        assert get_adapter(alias).name == expected

    def test_unknown_name_lists_the_alternatives(self) -> None:
        with pytest.raises(UnknownAdapterError, match="Available"):
            get_adapter("splunk")

    def test_explicit_name_beats_detection(self) -> None:
        """Guessing wrong silently mislabels evidence, so an explicit name wins."""
        sysmon_record = {"UtcTime": "2026-09-23 13:00:00.000", "EventID": 1, "Image": "a.exe"}
        assert resolve_adapter(name="firewall", sample=sysmon_record).name == "firewall"

    def test_detection_without_a_match_is_an_error_not_a_guess(self) -> None:
        with pytest.raises(UnknownAdapterError):
            resolve_adapter(sample={"totally": "unrecognised"})

    def test_a_broken_matcher_does_not_break_detection(self, monkeypatch) -> None:
        adapter = get_adapter("sysmon")
        monkeypatch.setattr(
            adapter, "matches", lambda record: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        record = {"TimeCreated": "2026-09-23T13:00:00Z", "EventID": 4625, "Computer": "H"}
        assert detect_adapter(record) is not None


# ---------------------------------------------------------------------------
# Sysmon
# ---------------------------------------------------------------------------
class TestSysmonAdapter:
    adapter = SysmonAdapter()

    def _record(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "UtcTime": "2026-09-23 13:42:10.123",
            "EventID": 1,
            "Computer": "WIN-LAB-01",
            "User": "LAB\\lab-user",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "powershell.exe -enc AAA=",
            "ProcessId": 4242,
            "ParentProcessId": 1180,
            "Hashes": f"SHA256={'a' * 64}",
        }
        record.update(overrides)
        return record

    def test_process_creation(self) -> None:
        event = self.adapter.normalise(self._record())
        assert event.source == "sysmon"
        assert event.event_type is EventType.PROCESS_CREATION
        assert event.process_name == "powershell.exe"
        assert event.parent_process == "cmd.exe"
        assert event.process_id == 4242
        assert event.file_hash_algorithm == "sha256"

    @pytest.mark.parametrize(
        "event_id, expected",
        [
            (1, EventType.PROCESS_CREATION),
            (3, EventType.NETWORK_CONNECTION),
            (11, EventType.FILE_CREATION),
            (22, EventType.DNS_QUERY),
            (13, EventType.REGISTRY_MODIFICATION),
            (23, EventType.FILE_DELETION),
        ],
    )
    def test_event_id_mapping(self, event_id: int, expected: EventType) -> None:
        assert self.adapter.normalise(self._record(EventID=event_id)).event_type is expected

    def test_unmapped_event_id_is_kept_not_dropped(self) -> None:
        event = self.adapter.normalise(self._record(EventID=255))
        assert event.event_type is EventType.OTHER
        assert event.event_type_raw == "sysmon:255"

    def test_original_record_is_preserved(self) -> None:
        event = self.adapter.normalise(self._record())
        assert event.raw_event["Hashes"].startswith("SHA256=")

    def test_missing_timestamp_is_an_adapter_error(self) -> None:
        record = self._record()
        del record["UtcTime"]
        with pytest.raises(AdapterError, match="no timestamp"):
            self.adapter.normalise(record)

    def test_empty_record_is_refused(self) -> None:
        with pytest.raises(AdapterError, match="empty"):
            self.adapter.normalise({"Computer": "-", "Image": ""})

    def test_detection_by_provider_name(self) -> None:
        assert self.adapter.matches({"Provider": "Microsoft-Windows-Sysmon", "EventID": 1})


# ---------------------------------------------------------------------------
# Windows Security
# ---------------------------------------------------------------------------
class TestWindowsSecurityAdapter:
    adapter = WindowsSecurityAdapter()

    def _record(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "TimeCreated": "2026-09-23T13:40:00Z",
            "EventID": 4625,
            "Computer": "WIN-LAB-01",
            "TargetUserName": "lab-user",
            "IpAddress": "192.0.2.77",
            "LogonType": 3,
        }
        record.update(overrides)
        return record

    @pytest.mark.parametrize(
        "event_id, expected",
        [
            (4625, EventType.AUTHENTICATION_FAILURE),
            (4624, EventType.AUTHENTICATION_SUCCESS),
            (4720, EventType.ACCOUNT_CREATED),
            (4732, EventType.GROUP_MEMBERSHIP_CHANGE),
            (4688, EventType.PROCESS_CREATION),
            (1102, EventType.LOG_CLEARED),
            (7045, EventType.SERVICE_INSTALLED),
        ],
    )
    def test_event_id_mapping(self, event_id: int, expected: EventType) -> None:
        assert self.adapter.normalise(self._record(EventID=event_id)).event_type is expected

    def test_logon_type_is_described_for_the_analyst(self) -> None:
        event = self.adapter.normalise(self._record())
        assert event.event_message == "Logon type 3 (network)"
        assert "remote_logon" in event.tags

    def test_target_account_is_preferred_over_the_subject(self) -> None:
        """For a logon or account change, the account acted upon is the story."""
        event = self.adapter.normalise(
            self._record(TargetUserName="svc-helper", SubjectUserName="lab-user")
        )
        assert event.username == "svc-helper"

    def test_placeholder_ip_is_dropped(self) -> None:
        assert self.adapter.normalise(self._record(IpAddress="-")).src_ip is None

    def test_missing_event_id_is_an_adapter_error(self) -> None:
        record = self._record()
        del record["EventID"]
        with pytest.raises(AdapterError, match="EventID"):
            self.adapter.normalise(record)


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
class TestFirewallAdapter:
    adapter = FirewallAdapter()

    def test_blocked_traffic_is_tagged(self) -> None:
        event = self.adapter.normalise(
            {
                "timestamp": "2026-09-23T12:03:52Z",
                "action": "deny",
                "src_ip": "192.0.2.77",
                "dst_ip": "10.0.0.5",
                "dst_port": "3389",
                "protocol": "tcp",
            }
        )
        assert event.event_type is EventType.NETWORK_CONNECTION
        assert "blocked" in event.tags
        assert event.dst_port == 3389
        assert event.event_message == "Firewall deny: 192.0.2.77 -> 10.0.0.5"

    @pytest.mark.parametrize("spelling", ["src_ip", "srcip", "source_ip", "src"])
    def test_field_spellings_are_tolerated(self, spelling: str) -> None:
        record = {"timestamp": "2026-09-23T12:00:00Z", "action": "allow", spelling: "10.0.0.5"}
        assert self.adapter.normalise(record).src_ip == "10.0.0.5"

    def test_allowed_traffic_is_not_tagged_as_blocked(self) -> None:
        event = self.adapter.normalise(
            {"timestamp": "2026-09-23T12:00:00Z", "action": "allow", "src_ip": "10.0.0.5"}
        )
        assert "blocked" not in event.tags


# ---------------------------------------------------------------------------
# Sibling projects
# ---------------------------------------------------------------------------
class TestDriftWatchAdapter:
    adapter = DriftWatchAdapter()

    def test_exposure_change(self) -> None:
        event = self.adapter.normalise(
            {
                "detected_at": "2026-09-23T13:10:00Z",
                "asset": "WIN-LAB-01",
                "asset_ip": "10.0.0.5",
                "change_type": "service_exposed",
                "port": 3389,
                "service": "rdp",
                "previous_state": "closed",
                "current_state": "open",
                "severity": "medium",
            }
        )
        assert event.event_type is EventType.NETWORK_EXPOSURE_CHANGE
        assert event.source_severity is Severity.MEDIUM
        assert "exposure_change" in event.tags
        assert "rdp on port 3389 (closed -> open)" in (event.event_message or "")

    def test_source_severity_is_only_a_claim(self) -> None:
        """It is recorded in a field named as a claim, not as a verdict."""
        event = self.adapter.normalise(
            {"detected_at": "2026-09-23T13:10:00Z", "asset": "H", "change_type": "port_opened"}
        )
        assert "severity" not in type(event).model_fields

    def test_nonsense_severity_is_ignored_rather_than_failing(self) -> None:
        event = self.adapter.normalise(
            {
                "detected_at": "2026-09-23T13:10:00Z",
                "asset": "H",
                "change_type": "port_opened",
                "severity": "catastrophic",
            }
        )
        assert event.source_severity is None

    def test_detection_by_change_type(self) -> None:
        assert self.adapter.matches({"change_type": "tls_downgrade"})


class TestGhostCredentialAdapter:
    adapter = GhostCredentialAdapter()

    def _record(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "triggered_at": "2026-09-23T14:05:00Z",
            "decoy_id": "decoy-svc-backup",
            "accessed_by": "LAB\\lab-user",
            "source_ip": "10.0.0.5",
            "hostname": "WIN-LAB-01",
            "access_method": "credential_store_read",
        }
        record.update(overrides)
        return record

    def test_decoy_access_is_high_confidence(self) -> None:
        """Nothing legitimate touches a decoy - but it is still only a claim."""
        event = self.adapter.normalise(self._record())
        assert event.event_type is EventType.DECOY_CREDENTIAL_ACCESS
        assert event.source_confidence is Confidence.HIGH
        assert event.source_severity is Severity.HIGH
        assert event.username_key == "lab-user"

    def test_the_decoy_is_identified_in_tags_and_message(self) -> None:
        event = self.adapter.normalise(self._record())
        assert "decoy-svc-backup" in event.tags
        assert "decoy-svc-backup" in (event.event_message or "")

    def test_access_without_a_decoy_id_is_refused(self) -> None:
        """An unattributable decoy alert is not useful evidence."""
        record = self._record()
        del record["decoy_id"]
        with pytest.raises(AdapterError, match="decoy identifier"):
            self.adapter.normalise(record)


# ---------------------------------------------------------------------------
# Canonical
# ---------------------------------------------------------------------------
class TestCanonicalAdapter:
    adapter = CanonicalAdapter()

    def test_canonical_record_passes_through(self) -> None:
        event = self.adapter.normalise(
            {
                "timestamp": "2026-09-23T13:42:10Z",
                "source": "custom_tool",
                "event_type": "process_creation",
                "hostname": "WIN-LAB-01",
            }
        )
        assert event.source == "custom_tool"
        assert event.event_type is EventType.PROCESS_CREATION

    def test_unknown_fields_are_preserved_rather_than_rejected(self) -> None:
        """SecurityEvent forbids extra fields, so a producer adding one would
        otherwise break ingestion entirely."""
        event = self.adapter.normalise(
            {
                "timestamp": "2026-09-23T13:42:10Z",
                "source": "custom_tool",
                "vendor_specific_id": "abc-123",
            }
        )
        assert event.raw_event["vendor_specific_id"] == "abc-123"

    def test_missing_timestamp_is_an_adapter_error(self) -> None:
        with pytest.raises(AdapterError, match="timestamp"):
            self.adapter.normalise({"source": "custom_tool", "hostname": "H"})

    def test_invalid_field_values_still_fail_validation(self) -> None:
        """Passing through is not the same as trusting."""
        with pytest.raises(ValidationError):
            self.adapter.normalise(
                {"timestamp": "2026-09-23T13:42:10Z", "source": "x", "src_ip": "10.0.0.999"}
            )
