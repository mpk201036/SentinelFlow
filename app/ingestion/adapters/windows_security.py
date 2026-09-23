"""Windows Security log adapter.

Maps the Event IDs a triage tool actually cares about. The ones that carry the
most weight for the shipped detections are 4625 (failed logon), 4624
(successful logon), 4720 (account created) and 4732 (added to a privileged
group) — the sequence the demo scenario walks through.
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
)
from app.models.enums import EventType
from app.models.event import SecurityEvent

EVENT_ID_MAP: dict[int, EventType] = {
    4624: EventType.AUTHENTICATION_SUCCESS,
    4625: EventType.AUTHENTICATION_FAILURE,
    4648: EventType.AUTHENTICATION_SUCCESS,
    4672: EventType.AUTHENTICATION_SUCCESS,
    4688: EventType.PROCESS_CREATION,
    4698: EventType.SCHEDULED_TASK_CREATED,
    4719: EventType.ACCOUNT_MODIFIED,
    4720: EventType.ACCOUNT_CREATED,
    4722: EventType.ACCOUNT_MODIFIED,
    4724: EventType.ACCOUNT_MODIFIED,
    4726: EventType.ACCOUNT_MODIFIED,
    4728: EventType.GROUP_MEMBERSHIP_CHANGE,
    4732: EventType.GROUP_MEMBERSHIP_CHANGE,
    4738: EventType.ACCOUNT_MODIFIED,
    4756: EventType.GROUP_MEMBERSHIP_CHANGE,
    1102: EventType.LOG_CLEARED,
    7045: EventType.SERVICE_INSTALLED,
}

#: Logon types worth showing an analyst, for the event message.
LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}


class WindowsSecurityAdapter(SourceAdapter):
    name: ClassVar[str] = "windows_security"
    aliases: ClassVar[tuple[str, ...]] = ("windows", "security", "wineventlog", "winlogbeat")
    description: ClassVar[str] = "Windows Security event log."

    def matches(self, record: Mapping[str, Any]) -> bool:
        view = RecordView(record)
        channel = (view.text("channel", "logname", "provider") or "").lower()
        if "security" in channel:
            return True
        event_id = view.integer("eventid", "event_id")
        return event_id in EVENT_ID_MAP

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        timestamp = view.get("timecreated", "time_created", "timestamp", "eventtime", "@timestamp")
        if timestamp is None:
            raise AdapterError("no timestamp field (expected TimeCreated)")

        event_id = view.integer("eventid", "event_id", "id")
        if event_id is None:
            raise AdapterError("no EventID field")
        event_type = EVENT_ID_MAP.get(event_id, EventType.OTHER)

        logon_type = view.integer("logontype", "logon_type")
        message = view.text("message", "description")
        if message is None and logon_type is not None:
            message = f"Logon type {logon_type} ({LOGON_TYPES.get(logon_type, 'unknown')})"

        tags = []
        if logon_type in (3, 10):
            tags.append("remote_logon")

        return self.build(
            view,
            timestamp=timestamp,
            event_type=event_type,
            event_type_raw=f"windows:{event_id}",
            hostname=view.text("computer", "hostname", "workstationname", "host"),
            # TargetUserName is the account acted upon, which is the one an
            # analyst cares about for logons and account changes.
            username=view.text("targetusername", "subjectusername", "username", "user"),
            src_ip=first_ip(view.get("ipaddress", "sourcenetworkaddress", "clientaddress")),
            src_port=view.integer("ipport", "sourceport"),
            process_name=image_basename(
                view.get("newprocessname", "processname", "callerprocessname")
            ),
            parent_process=image_basename(view.get("parentprocessname", "creatorprocessname")),
            process_id=view.integer("newprocessid", "processid"),
            command_line=view.text("commandline", "processcommandline"),
            event_message=message,
            tags=tags,
        )
