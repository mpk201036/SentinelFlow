"""Refanging defanged indicators.

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

import re

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
