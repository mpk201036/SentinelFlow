"""Shared base classes, field types and constants for the domain models.

Two base classes exist, and the choice between them is a statement about the
data:

* :class:`EvidenceModel` is **frozen**. Once an observation has been recorded —
  an event, an extracted indicator, a detection result, a piece of AI output —
  it must not change. If the facts change, that is a new record, not an edit.
* :class:`WorkflowModel` is mutable and re-validates on assignment. Alerts and
  incidents carry analyst state that legitimately changes over time.

Both forbid unknown fields. A typo in an API payload is an error, not a
silently-ignored extra key, and an attacker cannot smuggle an unexpected
attribute into a model by adding it to a JSON body.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import AfterValidator, BaseModel, ConfigDict

# --- Structural limits ----------------------------------------------------
#: Largest JSON serialisation of an original source event we will retain.
MAX_RAW_EVENT_BYTES = 64 * 1024
#: Maximum number of tags on a single object.
MAX_TAGS = 32
#: Maximum items in any bounded list field (detections, indicators, notes...).
MAX_LIST_ITEMS = 250
#: How far into the future a source timestamp may be before we reject it.
#: Clock skew of a few hours is normal; a year is an attempt to hide an event
#: at the bottom of a time-sorted queue.
MAX_CLOCK_SKEW = timedelta(hours=24)
#: Earliest plausible timestamp. Anything older is a parsing accident
#: (epoch 0, "0000-01-01") rather than a real security event.
MIN_TIMESTAMP = datetime(2000, 1, 1, tzinfo=UTC)


def utcnow() -> datetime:
    """Current time, always timezone-aware and in UTC."""
    return datetime.now(UTC)


def new_id() -> UUID:
    """Generate an external identifier."""
    return uuid4()


def _to_utc(value: datetime) -> datetime:
    """Coerce any datetime to UTC.

    Naive datetimes are assumed to be UTC rather than local time. Security logs
    that omit a timezone are overwhelmingly UTC, and guessing the *developer's*
    local zone would silently shift every timestamp in a correlation window.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _reject_implausible(value: datetime) -> datetime:
    """Reject timestamps that cannot be real observations."""
    if value < MIN_TIMESTAMP:
        raise ValueError(f"timestamp {value.isoformat()} is implausibly old")
    if value > utcnow() + MAX_CLOCK_SKEW:
        raise ValueError(f"timestamp {value.isoformat()} is too far in the future")
    return value


#: A timezone-aware UTC datetime. Used for anything we generate ourselves.
UtcDatetime = Annotated[datetime, AfterValidator(_to_utc)]

#: A UTC datetime that must also be a plausible observation time. Used for
#: timestamps that arrive from an untrusted source.
ObservedDatetime = Annotated[datetime, AfterValidator(_to_utc), AfterValidator(_reject_implausible)]


class SentinelModel(BaseModel):
    """Common configuration for every SentinelFlow model."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
        populate_by_name=True,
        ser_json_timedelta="iso8601",
    )

    def to_json(self, **kwargs: Any) -> str:
        """Serialise to JSON with enums and UUIDs rendered as strings."""
        return self.model_dump_json(**kwargs)


class EvidenceModel(SentinelModel):
    """Immutable record of something that was observed or derived."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
        populate_by_name=True,
        frozen=True,
    )


class WorkflowModel(SentinelModel):
    """Mutable record carrying analyst workflow state."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
        populate_by_name=True,
        validate_assignment=True,
    )


def bounded_json(
    payload: dict[str, Any], *, max_bytes: int = MAX_RAW_EVENT_BYTES
) -> dict[str, Any]:
    """Return ``payload`` if it serialises within ``max_bytes``, else a stub.

    The original event is kept for the analyst, but a hostile or simply broken
    producer must not be able to push an unbounded blob into the database. When
    the payload is too large it is replaced by a marker that records the size,
    so the truncation is visible rather than mysterious.
    """
    try:
        encoded = json.dumps(payload, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        return {"_sentinelflow_error": f"raw event is not serialisable: {exc}"}
    size = len(encoded.encode("utf-8"))
    if size > max_bytes:
        return {
            "_sentinelflow_truncated": True,
            "_original_size_bytes": size,
            "_limit_bytes": max_bytes,
            "_preview": encoded[:1024],
        }
    return payload
