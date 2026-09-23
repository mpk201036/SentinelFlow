"""Sysmon adapter.

Sysmon identifies activity by numeric Event ID. The mapping below covers the
events that matter for the detections SentinelFlow ships; anything else becomes
``OTHER`` with the original ID preserved, rather than being dropped.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from app.ingestion.adapters.base import (
    AdapterError,
    RecordView,
    SourceAdapter,
    first_ip,
    image_basename,
    preferred_hash,
)
from app.models.enums import EventType
from app.models.event import SecurityEvent

EVENT_ID_MAP: dict[int, EventType] = {
    1: EventType.PROCESS_CREATION,
    3: EventType.NETWORK_CONNECTION,
    5: EventType.PROCESS_TERMINATION,
    11: EventType.FILE_CREATION,
    12: EventType.REGISTRY_MODIFICATION,
    13: EventType.REGISTRY_MODIFICATION,
    14: EventType.REGISTRY_MODIFICATION,
    15: EventType.FILE_CREATION,
    22: EventType.DNS_QUERY,
    23: EventType.FILE_DELETION,
    26: EventType.FILE_DELETION,
}


class SysmonAdapter(SourceAdapter):
    name: ClassVar[str] = "sysmon"
    aliases: ClassVar[tuple[str, ...]] = ("microsoft-windows-sysmon", "sysmon-operational")
    description: ClassVar[str] = "Sysinternals Sysmon operational log."

    def matches(self, record: Mapping[str, Any]) -> bool:
        view = RecordView(record)
        provider = (view.text("provider", "provider_name", "channel") or "").lower()
        if "sysmon" in provider:
            return True
        return "utctime" in view and ("image" in view or "eventid" in view)

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        timestamp = view.get("utctime", "utc_time", "timestamp", "eventtime", "@timestamp")
        if timestamp is None:
            raise AdapterError("no timestamp field (expected UtcTime)")

        event_id = view.integer("eventid", "event_id", "id")
        event_type = EVENT_ID_MAP.get(event_id or -1, EventType.OTHER)

        return self.build(
            view,
            timestamp=timestamp,
            event_type=event_type,
            event_type_raw=f"sysmon:{event_id}" if event_id is not None else None,
            hostname=view.text("computer", "hostname", "host"),
            username=view.text("user", "username", "subjectusername"),
            process_name=image_basename(view.get("image", "processname", "sourceimage")),
            parent_process=image_basename(view.get("parentimage", "parentprocessname")),
            process_id=view.integer("processid", "pid"),
            parent_process_id=view.integer("parentprocessid", "ppid"),
            command_line=view.text("commandline", "command_line"),
            file_path=view.text("targetfilename", "image", "filename"),
            file_hash=preferred_hash(view.get("hashes", "hash", "sha256")),
            src_ip=first_ip(view.get("sourceip", "src_ip")),
            dst_ip=first_ip(view.get("destinationip", "dst_ip")),
            src_port=view.integer("sourceport", "src_port"),
            dst_port=view.integer("destinationport", "dst_port"),
            protocol=view.text("protocol"),
            domain=view.text("queryname", "destinationhostname"),
            event_message=view.text("message", "ruledescription", "description"),
        )
