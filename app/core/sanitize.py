"""Normalisation and sanitisation helpers for untrusted event data.

Everything SentinelFlow ingests is attacker-influenced. Before a value is
stored, correlated or displayed it passes through here.

What this module does **and does not** do matters, because doing it twice is a
bug:

* It **does** remove characters that are dangerous to *storage and display in a
  terminal*: NUL and other C0 control codes, zero-width characters, and Unicode
  bidirectional overrides. A process named ``cmd.exe\\u202ecod.bat`` renders as
  something else entirely in an analyst's console; that is a real technique, not
  a theoretical one.
* It **does** normalise representations so that correlation works: Unicode is
  NFC-normalised, hashes and domains are lower-cased, IP addresses are put in
  canonical form.
* It **does not** HTML-escape. Jinja2 autoescapes at render time; escaping here
  as well would double-encode evidence and corrupt what the analyst reads.
* It **does not** strip "suspicious" content such as prompt-injection phrases.
  Evidence is preserved verbatim. Neutralising injection is the job of the AI
  boundary in ``app/ai``, which delimits untrusted text rather than editing it.

Truncation is always marked, never silent — an analyst must be able to tell the
difference between a short command line and a shortened one.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import unicodedata
from typing import Any

# --- Field length limits --------------------------------------------------
#: Identifiers: hostname, username, process name, source.
MAX_SHORT_FIELD = 256
#: Paths, URLs and other long single-line values.
MAX_PATH_FIELD = 2_048
#: Free text: command lines, event messages.
MAX_TEXT_FIELD = 8_192
#: Slugs: source names and tags.
MAX_SLUG_FIELD = 64

TRUNCATION_MARKER = "...[truncated {count} chars]"

#: C0/C1 control characters. Tab and newline are handled separately.
_CONTROL_ALL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CONTROL_KEEP_WHITESPACE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

#: Zero-width characters and bidirectional overrides. These are invisible and
#: are used to disguise what a string actually says.
_INVISIBLE_RE = re.compile(r"[​-‏‪-‮⁦-⁩﻿]")

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Hash length (hex characters) to algorithm name.
HASH_ALGORITHMS: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256"}


def _truncate(value: str, max_length: int) -> str:
    """Shorten ``value`` to ``max_length``, marking that it was shortened."""
    if len(value) <= max_length:
        return value
    removed = len(value) - max_length
    return value[:max_length] + TRUNCATION_MARKER.format(count=removed)


def strip_unsafe_characters(value: str, *, allow_newlines: bool = False) -> str:
    """Remove invisible and control characters, and normalise Unicode form."""
    value = unicodedata.normalize("NFC", value)
    value = _INVISIBLE_RE.sub("", value)
    if allow_newlines:
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        return _CONTROL_KEEP_WHITESPACE_RE.sub("", value)
    return _CONTROL_ALL_RE.sub(" ", value)


def clean_line(value: Any, *, max_length: int = MAX_SHORT_FIELD) -> str | None:
    """Clean a single-line field. Returns ``None`` when nothing survives.

    Newlines are never legitimate in a hostname or a process name, so they are
    collapsed to spaces rather than preserved.
    """
    if value is None:
        return None
    text = strip_unsafe_characters(str(value), allow_newlines=False)
    text = re.sub(r"\s+", " ", text).strip()
    return _truncate(text, max_length) if text else None


def clean_text(value: Any, *, max_length: int = MAX_TEXT_FIELD) -> str | None:
    """Clean a multi-line field such as a command line or event message.

    Newlines are preserved: a PowerShell command legitimately contains them and
    removing them would destroy evidence.
    """
    if value is None:
        return None
    text = strip_unsafe_characters(str(value), allow_newlines=True).strip()
    return _truncate(text, max_length) if text else None


def normalize_slug(value: Any, *, max_length: int = MAX_SLUG_FIELD) -> str:
    """Normalise a source name or tag to a lower-case slug."""
    text = clean_line(value, max_length=max_length * 4) or ""
    text = _SLUG_RE.sub("_", text.lower()).strip("_.-")
    if not text:
        raise ValueError("value is empty after normalisation")
    return text[:max_length]


def normalize_ip(value: Any) -> str:
    """Validate and canonicalise an IPv4 or IPv6 address.

    Canonicalisation matters for correlation: ``::FFFF:10.0.0.1`` and
    ``10.0.0.1`` must not look like two different hosts.
    """
    text = (clean_line(value, max_length=64) or "").strip("[]")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"not a valid IP address: {text!r}") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_domain(value: Any) -> str:
    """Validate and lower-case a domain name, handling IDN and trailing dots."""
    text = (clean_line(value, max_length=MAX_SHORT_FIELD) or "").strip().rstrip(".").lower()
    if not text:
        raise ValueError("domain is empty")
    # Internationalised domains are compared in their ASCII (punycode) form so
    # that a lookalike Unicode domain cannot masquerade as an ASCII one. If the
    # value will not encode, keep it as-is; the pattern check below decides.
    with contextlib.suppress(UnicodeError):
        text = text.encode("idna").decode("ascii")
    if len(text) > 253 or not _DOMAIN_RE.match(text):
        raise ValueError(f"not a valid domain name: {text!r}")
    return text


def normalize_hash(value: Any) -> str:
    """Validate and lower-case an MD5, SHA1 or SHA256 digest."""
    text = (clean_line(value, max_length=128) or "").lower()
    if len(text) not in HASH_ALGORITHMS or not _HEX_RE.match(text):
        raise ValueError(f"not a valid MD5, SHA1 or SHA256 hash: {text!r}")
    return text


def hash_algorithm(value: str) -> str | None:
    """Return the algorithm name for a hash, or ``None`` if unrecognised."""
    return HASH_ALGORITHMS.get(len(value))


def normalize_email(value: Any) -> str:
    """Validate and lower-case an email address (deliberately permissive)."""
    text = (clean_line(value, max_length=320) or "").lower()
    if not _EMAIL_RE.match(text):
        raise ValueError(f"not a valid email address: {text!r}")
    return text
