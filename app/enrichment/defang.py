"""Defanging and refanging indicators.

Threat reports, ticketing systems and some tools "defang" indicators so they
cannot be clicked: ``hxxp://evil[.]example``, ``192.0.2[.]77``,
``user[at]example.com``. Those strings reach SentinelFlow through pasted
evidence and imported alerts, and a literal reading extracts nothing useful
from them.

Refanging happens on a **copy** used only for extraction. The stored event keeps
exactly what arrived. Editing evidence to make a regex happy would be a
straightforward way to mislead an analyst, so it does not happen: the defanged
original stays in ``raw_event``, and only the *indicator* is canonical.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from app.enrichment.patterns import DOMAIN_RE, EMAIL_RE, URL_RE, has_valid_tld

_SUBSTITUTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Scheme obfuscation: hxxp, h__p, hXXps
    (re.compile(r"\bh(?:xx|__|\*\*)(p?s?)\b(?=:)", re.IGNORECASE), r"htt\1"),
    (re.compile(r"\bhxxps?\b", re.IGNORECASE), "http"),
    # Bracketed or braced separators: [.] (.) {.} [:] [/]
    (re.compile(r"[\[({<]\s*\.\s*[\])}>]"), "."),
    (re.compile(r"[\[({<]\s*:\s*[\])}>]"), ":"),
    (re.compile(r"[\[({<]\s*/\s*[\])}>]"), "/"),
    # Spelled-out separators, only between label characters
    (re.compile(r"(?<=\w)\s*[\[({<]\s*dot\s*[\])}>]\s*(?=\w)", re.IGNORECASE), "."),
    (re.compile(r"(?<=\w)\s+dot\s+(?=\w)", re.IGNORECASE), "."),
    (re.compile(r"(?<=\w)\s*[\[({<]\s*at\s*[\])}>]\s*(?=\w)", re.IGNORECASE), "@"),
    (re.compile(r"(?<=\w)\s+at\s+(?=\w+\.\w)", re.IGNORECASE), "@"),
)

#: Cheap pre-check, so untouched text skips the substitutions entirely.
_LIKELY_DEFANGED_RE = re.compile(
    r"h(?:xx|__)p|[\[({<]\s*(?:\.|:|/|dot|at)\s*[\])}>]|\s+dot\s+", re.IGNORECASE
)


def looks_defanged(text: str) -> bool:
    """Whether ``text`` appears to contain a defanged indicator."""
    return bool(_LIKELY_DEFANGED_RE.search(text))


def refang(text: str) -> str:
    """Return ``text`` with common defanging removed.

    Used only to build the string that extraction scans. Never written back to
    the event.
    """
    if not looks_defanged(text):
        return text
    for pattern, replacement in _SUBSTITUTIONS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Defanging: for text that leaves SentinelFlow
# ---------------------------------------------------------------------------
# Reports are read in Markdown previews, ticketing systems and mail clients,
# all of which turn "https://..." and "evil.example" into live links. An
# indicator in a report is there to be read, not clicked, so it is written the
# way threat reports write them: hxxps://evil[.]example, user[at]evil[.]example.
# The forms used are the ones refang() reverses, so a defanged indicator pasted
# back into SentinelFlow is recognised again.

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_WWW_RE = re.compile(r"(?<![\w.-])www\.", re.IGNORECASE)


def defang_url(url: str) -> str:
    """``https://evil.example/a.php`` -> ``hxxps://evil[.]example/a.php``."""
    match = _SCHEME_RE.match(url)
    if match is None:
        return defang_domain(url)
    scheme = match.group(1)
    rest = url[match.end() :]
    host_end = len(rest)
    for separator in "/?#":
        position = rest.find(separator)
        if position != -1:
            host_end = min(host_end, position)
    host, tail = rest[:host_end], rest[host_end:]
    if scheme.lower() in ("http", "https"):
        prefix = "hxxp" + scheme[4:] + "://"
    else:
        prefix = f"{scheme}[:]//"
    return f"{prefix}{_defang_dots(host)}{tail}"


def defang_domain(domain: str) -> str:
    """``evil.example`` -> ``evil[.]example``."""
    return _defang_dots(domain)


def defang_email(address: str) -> str:
    """``user@evil.example`` -> ``user[at]evil[.]example``."""
    local, _, domain = address.rpartition("@")
    return f"{local}[at]{_defang_dots(domain)}" if local else _defang_dots(address)


def defang_text(text: str) -> str:
    """Defang every URL, e-mail address and domain in free text.

    IP addresses are left readable: no renderer turns a bare address into a
    link, and an analyst reading a report needs them exactly as logged. The
    function is idempotent, so text that is already defanged is unchanged.
    """
    text = URL_RE.sub(lambda m: defang_url(m.group(0)), text)
    text = EMAIL_RE.sub(_only_valid(lambda value: defang_email(value)), text)
    text = DOMAIN_RE.sub(_only_valid(defang_domain), text)
    # Renderers link "www." whatever follows it, valid top-level domain or not.
    return _WWW_RE.sub("www[.]", text)


def _defang_dots(value: str) -> str:
    return value.replace("[.]", ".").replace(".", "[.]")


def _only_valid(defang: Callable[[str], str]) -> Callable[[re.Match[str]], str]:
    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        domain = value.rpartition("@")[2]
        if not has_valid_tld(domain) or _is_ip(domain):
            return value
        return defang(value)

    return replace


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
