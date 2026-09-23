"""GhostCredential adapter — decoy credential access.

GhostCredential is a sibling project that plants credentials which no
legitimate process has any reason to touch. That property is what makes its
events unusual: unlike almost every other source, a signal here is not
ambiguous background noise.

So this adapter sets ``source_confidence`` to HIGH. Note carefully what that
does and does not mean. It is still a *claim by the source*, recorded in a field
whose name says so, and it is still only an input to the deterministic severity
engine in Stage 8. High-confidence deception is a strong signal, not a verdict,
and a decoy can still be tripped by a misconfigured backup agent or by the blue
team's own testing — which is exactly why a human confirms.

Expected record shape::

    {
      "triggered_at": "2026-09-23T14:05:00Z",
      "decoy_id": "decoy-svc-backup",
      "decoy_type": "service_account",
      "accessed_by": "LAB\\\\lab-user",
      "source_ip": "10.0.0.5",
      "hostname": "WIN-LAB-01",
      "access_method": "lsass_read",
      "process_name": "powershell.exe"
    }
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
from app.models.enums import Confidence, EventType, Severity
from app.models.event import SecurityEvent


class GhostCredentialAdapter(SourceAdapter):
    name: ClassVar[str] = "ghostcredential"
    aliases: ClassVar[tuple[str, ...]] = ("ghost_credential", "ghostcred", "decoy")
    description: ClassVar[str] = "GhostCredential decoy credential access alerts."

    def matches(self, record: Mapping[str, Any]) -> bool:
        view = RecordView(record)
        if (view.text("source", "producer") or "").lower().startswith("ghost"):
            return True
        return "decoy_id" in view or "decoy_name" in view or "decoy_type" in view

    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        view = RecordView(record)
        if view.is_empty():
            raise AdapterError("record is empty")

        timestamp = view.get("triggered_at", "accessed_at", "timestamp", "time")
        if timestamp is None:
            raise AdapterError("no timestamp field (expected triggered_at)")

        decoy = view.text("decoy_id", "decoy_name", "credential_name")
        if decoy is None:
            raise AdapterError("no decoy identifier - cannot attribute the access")

        method = view.text("access_method", "method", "technique")
        message = view.text("message", "description")
        if message is None:
            message = f"Decoy credential '{decoy}' accessed"
            if method:
                message += f" via {method}"

        return self.build(
            view,
            timestamp=timestamp,
            event_type=EventType.DECOY_CREDENTIAL_ACCESS,
            event_type_raw=method,
            hostname=view.text("hostname", "host", "asset"),
            username=view.text("accessed_by", "username", "user", "actor"),
            src_ip=first_ip(view.get("source_ip", "src_ip", "client_ip")),
            process_name=image_basename(view.get("process_name", "process", "image")),
            process_id=view.integer("process_id", "pid"),
            event_message=message,
            # Nothing legitimate touches a decoy, so the source's confidence is
            # high. It remains a claim, in a field named as one.
            source_severity=Severity.HIGH,
            source_confidence=Confidence.HIGH,
            tags=["deception", "decoy_credential", decoy],
        )
