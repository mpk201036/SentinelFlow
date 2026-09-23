"""The canonical security event — SentinelFlow's single source of truth.

Every source (Sysmon, Windows Security, firewall logs, DriftWatch,
GhostCredential, a CSV export, a REST call) is translated into exactly this
shape before anything else happens. Downstream components — IOC extraction,
detection, correlation, reporting — only ever see a ``SecurityEvent`` and never
need to know where it came from.

Three design decisions are worth stating, because they deviate from a naive
reading of the field list and they are deliberate:

1. **The event holds observation, not interpretation.** There is no ``severity``
   verdict, no ``status`` and no ``mitre_techniques`` list on this model. Those
   are conclusions, they belong to :class:`~app.models.alert.Alert`, and mixing
   them in here would blur the exact line this project exists to draw. What the
   *source claimed* is kept, clearly named ``source_severity`` — an untrusted
   hint, never the verdict.

2. **Events are frozen.** Evidence does not change after it is recorded.

3. **Every field is optional except the four that make an event meaningful**
   (``timestamp``, ``source``, plus the generated id and receipt time). Sources
   populate wildly different subsets, and demanding more would mean either
   dropping real events or inventing data.

Fields that *are* present are validated strictly. A malformed IP address is an
error rather than a string that merely looks like an address, because a value
that reaches an analyst labelled "source IP" must actually be one. Ingestion
adapters decide whether a rejected event is dropped or quarantined.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import (
    MAX_PATH_FIELD,
    MAX_SHORT_FIELD,
    MAX_TEXT_FIELD,
    clean_line,
    clean_text,
    hash_algorithm,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_slug,
)
from app.models.base import (
    MAX_TAGS,
    EvidenceModel,
    ObservedDatetime,
    UtcDatetime,
    bounded_json,
    new_id,
    utcnow,
)
from app.models.enums import Confidence, EventType, Severity

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+$")


class SecurityEvent(EvidenceModel):
    """A single normalised observation from any source."""

    # --- Identity -------------------------------------------------------
    event_id: UUID = Field(default_factory=new_id, description="Internal identifier.")
    timestamp: ObservedDatetime = Field(description="When the activity occurred, per the source.")
    received_at: UtcDatetime = Field(
        default_factory=utcnow, description="When SentinelFlow ingested the event."
    )
    source: str = Field(description="Producer of the event, e.g. 'sysmon', 'driftwatch'.")

    # --- Classification of the activity ---------------------------------
    event_type: EventType = Field(
        default=EventType.OTHER, description="Canonical activity category."
    )
    event_type_raw: str | None = Field(
        default=None, description="The source's own event type, preserved verbatim."
    )

    # --- Identity of the actors -----------------------------------------
    hostname: str | None = None
    username: str | None = None

    # --- Network --------------------------------------------------------
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None

    # --- Process --------------------------------------------------------
    process_name: str | None = None
    parent_process: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    parent_process_id: int | None = Field(default=None, ge=0)
    command_line: str | None = None

    # --- File -----------------------------------------------------------
    file_path: str | None = None
    file_hash: str | None = None

    # --- Web / naming ---------------------------------------------------
    domain: str | None = None
    url: str | None = None

    # --- Description ----------------------------------------------------
    event_message: str | None = Field(
        default=None, description="Human-readable description supplied by the source."
    )

    # --- Untrusted hints from the source --------------------------------
    source_severity: Severity | None = Field(
        default=None,
        description="Severity the source claimed. Advisory only; never the alert verdict.",
    )
    source_confidence: Confidence | None = Field(
        default=None, description="Confidence the source claimed. Advisory only."
    )

    # --- Extras ---------------------------------------------------------
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)
    raw_event: dict[str, Any] = Field(
        default_factory=dict, description="The original payload, size-bounded."
    )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @model_validator(mode="before")
    @classmethod
    def _normalise_event_type(cls, data: Any) -> Any:
        """Accept any event type, canonicalise what we recognise, keep the rest.

        An unknown category must never cause an event to be lost: the canonical
        field falls back to ``OTHER`` and the original string is preserved in
        ``event_type_raw`` so no information is destroyed.
        """
        if not isinstance(data, dict):
            return data
        raw = data.get("event_type")
        if raw is None or isinstance(raw, EventType):
            return data

        original = clean_line(raw, max_length=MAX_SHORT_FIELD)
        candidate = re.sub(r"[\s\-]+", "_", (original or "").lower()).strip("_")
        try:
            data["event_type"] = EventType(candidate)
        except ValueError:
            data["event_type"] = EventType.OTHER
        data.setdefault("event_type_raw", original)
        return data

    @field_validator("source", mode="before")
    @classmethod
    def _validate_source(cls, value: Any) -> str:
        return normalize_slug(value)

    @field_validator(
        "hostname", "username", "process_name", "parent_process", "protocol", mode="before"
    )
    @classmethod
    def _clean_identifier(cls, value: Any) -> str | None:
        return clean_line(value, max_length=MAX_SHORT_FIELD)

    @field_validator("event_type_raw", mode="before")
    @classmethod
    def _clean_event_type_raw(cls, value: Any) -> str | None:
        return clean_line(value, max_length=MAX_SHORT_FIELD)

    @field_validator("file_path", mode="before")
    @classmethod
    def _clean_path(cls, value: Any) -> str | None:
        return clean_line(value, max_length=MAX_PATH_FIELD)

    @field_validator("command_line", "event_message", mode="before")
    @classmethod
    def _clean_free_text(cls, value: Any) -> str | None:
        return clean_text(value, max_length=MAX_TEXT_FIELD)

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _validate_ip(cls, value: Any) -> str | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return normalize_ip(value)

    @field_validator("domain", mode="before")
    @classmethod
    def _validate_domain(cls, value: Any) -> str | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return normalize_domain(value)

    @field_validator("file_hash", mode="before")
    @classmethod
    def _validate_hash(cls, value: Any) -> str | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return normalize_hash(value)

    @field_validator("url", mode="before")
    @classmethod
    def _validate_url(cls, value: Any) -> str | None:
        cleaned = clean_line(value, max_length=MAX_PATH_FIELD)
        if cleaned is None:
            return None
        if not _URL_RE.match(cleaned):
            raise ValueError(f"not a valid absolute URL: {cleaned!r}")
        return cleaned

    @field_validator("tags", mode="before")
    @classmethod
    def _normalise_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [part for part in re.split(r"[,\s]+", value) if part]
        seen: dict[str, None] = {}
        for item in value:
            try:
                seen.setdefault(normalize_slug(item), None)
            except ValueError:
                continue  # an unusable tag is dropped, never fatal
        return list(seen)[:MAX_TAGS]

    @field_validator("raw_event", mode="before")
    @classmethod
    def _bound_raw_event(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            return {"_sentinelflow_original": str(value)[:1024]}
        return bounded_json(value)

    # ------------------------------------------------------------------
    # Correlation helpers
    # ------------------------------------------------------------------
    @property
    def hostname_key(self) -> str | None:
        """Case-insensitive host key. ``WIN-LAB-01`` and ``win-lab-01`` are one host."""
        return self.hostname.lower() if self.hostname else None

    @property
    def username_key(self) -> str | None:
        """Case-insensitive user key with any domain prefix removed."""
        if not self.username:
            return None
        user = self.username.lower()
        for separator in ("\\", "/"):
            if separator in user:
                user = user.rsplit(separator, 1)[-1]
        return user.removesuffix("$") or None

    @property
    def process_name_key(self) -> str | None:
        """Case-insensitive process name; Windows treats these as equivalent."""
        return self.process_name.lower() if self.process_name else None

    @property
    def file_hash_algorithm(self) -> str | None:
        """Algorithm implied by the length of ``file_hash``."""
        return hash_algorithm(self.file_hash) if self.file_hash else None

    def correlation_identity(self) -> dict[str, str]:
        """Non-empty keys used to decide whether two events are related."""
        candidates = {
            "hostname": self.hostname_key,
            "username": self.username_key,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "process": self.process_name_key,
        }
        return {key: value for key, value in candidates.items() if value}

    def describe(self) -> str:
        """One-line human summary, used for alert titles and report timelines."""
        parts: list[str] = [self.event_type.value.replace("_", " ")]
        if self.process_name:
            parts.append(f"process={self.process_name}")
        if self.username:
            parts.append(f"user={self.username}")
        if self.hostname:
            parts.append(f"host={self.hostname}")
        if self.dst_ip:
            parts.append(f"dst={self.dst_ip}")
        if self.domain:
            parts.append(f"domain={self.domain}")
        return " ".join(parts)
