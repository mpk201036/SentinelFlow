"""Adapter for records already in SentinelFlow's canonical shape.

Used by the REST API, by the sample generator, and by any producer that has
been written against SentinelFlow's schema directly.

It exists as a real adapter rather than a shortcut because of one detail:
:class:`~app.models.event.SecurityEvent` forbids unknown fields, so a payload
with an extra key would be rejected outright. This adapter keeps the fields it
recognises and moves everything else into ``raw_event`` — so a producer that
adds a field does not break ingestion, and the extra data is still visible.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from app.ingestion.adapters.base import AdapterError, RecordView, SourceAdapter
from app.models.event import SecurityEvent

#: Fields a caller may set. Generated ones are excluded.
ACCEPTED_FIELDS = frozenset(SecurityEvent.model_fields) - {"event_id", "received_at", "raw_event"}


class CanonicalAdapter(SourceAdapter):
    name: ClassVar[str] = "canonical"
    aliases: ClassVar[tuple[str, ...]] = ("sentinelflow", "native", "json")
    description: ClassVar[str] = "Records already using SentinelFlow's field names."

    def matches(self, record: Mapping[str, Any]) -> bool:
        keys = {str(key).lower() for key in record}
        return "timestamp" in keys and bool(keys & {"event_type", "source", "event_message"})

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        known: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for key, value in record.items():
            if str(key).lower() in ACCEPTED_FIELDS:
                known[str(key).lower()] = value
            else:
                extra[str(key)] = value

        if "timestamp" not in known:
            raise AdapterError("a canonical record must carry a timestamp")
        known.setdefault("source", record.get("source") or self.name)

        payload = {key: value for key, value in known.items() if value not in (None, "")}
        # Unrecognised keys are preserved rather than rejected, so a producer
        # adding a field never breaks ingestion.
        payload["raw_event"] = dict(record)
        if extra:
            payload.setdefault("tags", [])
        return SecurityEvent(**payload)
