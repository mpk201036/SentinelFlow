"""Indicators of compromise extracted from events.

An indicator is a *fact about a string that appeared in an event*, not a
judgement. ``8.8.8.8`` appearing in a DNS query is an indicator; it is not
malicious. Keeping that distinction is why this model records where a value
came from and when it was seen, and says nothing at all about whether it is
bad.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.sanitize import (
    MAX_PATH_FIELD,
    clean_line,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
)
from app.models.base import EvidenceModel, UtcDatetime, new_id, utcnow
from app.models.enums import IndicatorType

#: Networks that are genuinely on somebody's internal estate.
#:
#: Deliberately not ``ipaddress.is_private``: that property is true for the
#: RFC 5737 documentation ranges (192.0.2.0/24 and friends) because they are
#: not globally routable. Labelling those "internal" in the UI would be
#: actively misleading - they are exactly what synthetic and report data uses
#: to represent an *external* attacker.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

#: Reserved for documentation (RFC 5737, RFC 3849). Never real infrastructure.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


class Indicator(EvidenceModel):
    """A single indicator observed in one or more events."""

    indicator_id: UUID = Field(default_factory=new_id)
    indicator_type: IndicatorType
    value: str = Field(max_length=MAX_PATH_FIELD)
    source_event_id: UUID | None = Field(
        default=None, description="Event this indicator was first extracted from."
    )
    source_field: str | None = Field(
        default=None, description="Event field it came from, e.g. 'command_line'."
    )
    first_seen: UtcDatetime = Field(default_factory=utcnow)
    last_seen: UtcDatetime = Field(default_factory=utcnow)
    occurrences: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _normalise_value_for_type(self) -> Self:
        """Canonicalise the value according to its type.

        Runs after field validation so the type is known. Uses
        ``object.__setattr__`` because the model is frozen.
        """
        normalisers = {
            IndicatorType.IPV4: normalize_ip,
            IndicatorType.IPV6: normalize_ip,
            IndicatorType.DOMAIN: normalize_domain,
            IndicatorType.EMAIL: normalize_email,
            IndicatorType.MD5: normalize_hash,
            IndicatorType.SHA1: normalize_hash,
            IndicatorType.SHA256: normalize_hash,
        }
        normaliser = normalisers.get(self.indicator_type)
        if normaliser is not None:
            object.__setattr__(self, "value", normaliser(self.value))

        if self.indicator_type is IndicatorType.PROCESS_NAME:
            object.__setattr__(self, "value", self.value.lower())

        expected_length = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
        wanted = expected_length.get(self.indicator_type)
        if wanted is not None and len(self.value) != wanted:
            raise ValueError(f"{self.indicator_type.value} must be {wanted} hex characters")

        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot be earlier than first_seen")
        return self

    @field_validator("value", mode="before")
    @classmethod
    def _clean_value(cls, value: Any) -> str:
        cleaned = clean_line(value, max_length=MAX_PATH_FIELD)
        if not cleaned:
            raise ValueError("indicator value is empty")
        return cleaned

    @field_validator("source_field", mode="before")
    @classmethod
    def _clean_source_field(cls, value: Any) -> str | None:
        return clean_line(value, max_length=64)

    @property
    def _address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if self.indicator_type not in (IndicatorType.IPV4, IndicatorType.IPV6):
            return None
        try:
            return ipaddress.ip_address(self.value)
        except ValueError:  # pragma: no cover - validated on construction
            return None

    @property
    def is_internal(self) -> bool:
        """True for addresses on a private, loopback or link-local network.

        Useful context, not a verdict: internal addresses are still worth
        recording, they just rarely belong in an external threat feed.
        """
        address = self._address
        if address is None:
            return False
        return any(address in network for network in _INTERNAL_NETWORKS)

    @property
    def is_documentation(self) -> bool:
        """True for the RFC 5737 / RFC 3849 documentation ranges.

        Seeing one of these in data that is supposed to be real is itself worth
        noticing - it usually means test data leaked into a production feed.
        """
        address = self._address
        if address is None:
            return False
        return any(address in network for network in _DOCUMENTATION_NETWORKS)

    def merged_with(self, other: Indicator) -> Indicator:
        """Combine two sightings of the same indicator into one record."""
        if (other.indicator_type, other.value) != (self.indicator_type, self.value):
            raise ValueError("cannot merge indicators with different type or value")
        return self.model_copy(
            update={
                "first_seen": min(self.first_seen, other.first_seen),
                "last_seen": max(self.last_seen, other.last_seen),
                "occurrences": self.occurrences + other.occurrences,
            }
        )
