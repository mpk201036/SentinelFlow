"""Generic firewall / network flow adapter.

Deliberately vendor-neutral: it accepts the field names that most firewall CSV
exports use in some spelling or another. A specific vendor with an awkward
format gets its own adapter rather than more special cases in this one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from app.ingestion.adapters.base import AdapterError, RecordView, SourceAdapter, first_ip
from app.models.enums import EventType
from app.models.event import SecurityEvent

BLOCKING_ACTIONS = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject"}


class FirewallAdapter(SourceAdapter):
    name: ClassVar[str] = "firewall"
    aliases: ClassVar[tuple[str, ...]] = ("fw", "netflow", "network")
    description: ClassVar[str] = "Firewall and network flow logs."

    def matches(self, record: Mapping[str, Any]) -> bool:
        view = RecordView(record)
        has_endpoints = ("src_ip" in view or "srcip" in view or "source_ip" in view) and (
            "dst_ip" in view or "dstip" in view or "destination_ip" in view
        )
        return has_endpoints and "action" in view

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        timestamp = view.get("timestamp", "time", "date", "@timestamp", "eventtime")
        if timestamp is None:
            raise AdapterError("no timestamp field")

        action = (view.text("action", "disposition", "verdict") or "").lower()
        src = first_ip(view.get("src_ip", "srcip", "source_ip", "source", "src"))
        dst = first_ip(view.get("dst_ip", "dstip", "destination_ip", "destination", "dst"))

        tags = ["blocked"] if action in BLOCKING_ACTIONS else []
        message = view.text("message", "description")
        if message is None and action:
            message = f"Firewall {action}: {src or '?'} -> {dst or '?'}"

        return self.build(
            view,
            timestamp=timestamp,
            event_type=EventType.NETWORK_CONNECTION,
            event_type_raw=action or None,
            hostname=view.text("hostname", "host", "device", "firewall"),
            username=view.text("user", "username"),
            src_ip=src,
            dst_ip=dst,
            src_port=view.integer("src_port", "srcport", "source_port", "sport"),
            dst_port=view.integer("dst_port", "dstport", "destination_port", "dport"),
            protocol=view.text("protocol", "proto", "ip_protocol"),
            domain=view.text("domain", "hostname_requested", "url_host"),
            url=view.text("url", "uri"),
            event_message=message,
            tags=tags,
        )
