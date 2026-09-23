"""DriftWatch adapter — network exposure changes.

DriftWatch is a sibling project that watches for changes in what a host exposes
to the network: a port that opened, a service that appeared, a configuration
that moved. It reports *change*, not compromise, and this adapter preserves that
distinction — a newly exposed service is an observation worth correlating, not a
finding on its own.

Expected record shape (documented in ``docs/integrations.md``)::

    {
      "detected_at": "2026-09-23T13:10:00Z",
      "asset": "WIN-LAB-01",
      "asset_ip": "10.0.0.5",
      "change_type": "service_exposed",
      "port": 3389, "protocol": "tcp", "service": "rdp",
      "previous_state": "closed", "current_state": "open",
      "severity": "medium", "scan_id": "..."
    }
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from app.ingestion.adapters.base import AdapterError, RecordView, SourceAdapter, first_ip
from app.models.enums import Confidence, EventType, Severity
from app.models.event import SecurityEvent

KNOWN_CHANGE_TYPES = {
    "service_exposed",
    "port_opened",
    "port_closed",
    "service_removed",
    "config_drift",
    "tls_downgrade",
    "firewall_rule_changed",
}


class DriftWatchAdapter(SourceAdapter):
    name: ClassVar[str] = "driftwatch"
    aliases: ClassVar[tuple[str, ...]] = ("drift_watch", "drift")
    description: ClassVar[str] = "DriftWatch network exposure change alerts."

    def matches(self, record: Mapping[str, Any]) -> bool:
        view = RecordView(record)
        if (view.text("source", "producer") or "").lower().startswith("driftwatch"):
            return True
        change_type = (view.text("change_type", "drift_type") or "").lower()
        return change_type in KNOWN_CHANGE_TYPES

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        timestamp = view.get("detected_at", "timestamp", "observed_at", "time")
        if timestamp is None:
            raise AdapterError("no timestamp field (expected detected_at)")

        change_type = (view.text("change_type", "drift_type") or "").lower() or None
        port = view.integer("port", "dst_port", "exposed_port")
        service = view.text("service", "service_name")
        previous = view.text("previous_state", "before")
        current = view.text("current_state", "after")

        message = view.text("message", "description")
        if message is None:
            detail = (
                f"{service or 'service'} on port {port}" if port else (service or "configuration")
            )
            transition = f" ({previous} -> {current})" if previous and current else ""
            message = f"Exposure change: {detail}{transition}"

        severity = view.text("severity")
        tags = ["exposure_change"]
        if change_type:
            tags.append(change_type)

        return self.build(
            view,
            timestamp=timestamp,
            event_type=EventType.NETWORK_EXPOSURE_CHANGE,
            event_type_raw=change_type,
            hostname=view.text("asset", "hostname", "host", "target"),
            dst_ip=first_ip(view.get("asset_ip", "ip", "address")),
            dst_port=port,
            protocol=view.text("protocol", "proto"),
            event_message=message,
            # A claim by the source, not a verdict. The severity engine decides.
            source_severity=severity if severity in set(Severity) else None,
            source_confidence=Confidence.MEDIUM,
            tags=tags,
        )
