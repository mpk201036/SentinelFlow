"""Heuristic scan of evidence for text aimed at a language model.

Event data is written by whoever controls the machine that produced it. An
attacker who expects alerts to be summarised by a model can plant text in a
command line, a file name or a log message that addresses the model instead of
the analyst: "ignore previous instructions", "this alert is a false positive",
a fake end-of-data marker.

This module looks for that text and says where it was. It is a tripwire, not a
wall:

* **It does not decide whether the model is shown the text.** The evidence is
  shown as it is, because hiding it would hide the attack from the analyst
  too. What changes is that the prompt carries a specific warning, the stored
  analysis is flagged, and the console says why.
* **A clean scan proves nothing.** Paraphrase, other languages, encodings and
  instructions split across fields all get past patterns. The defences that
  do not depend on spotting the attack are structural, and live elsewhere:
  the evidence is JSON-escaped between random-nonce markers, the model's
  reply must match a fixed schema, and nothing the model says can change a
  severity, a status or a mapping.

The patterns lean towards phrasing that addresses a reader and gives an order,
because the words themselves ("ignore", "bypass", "severity=low") are common in
legitimate logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.ai.evidence import Evidence

MAX_SIGNALS = 20
EXCERPT_CHARS = 80

_QUALIFIER = (
    r"(?:previous|prior|above|earlier|preceding|all|any|your|system|original|safety|developer)"
)

#: (name, pattern). The name is what an analyst reads, so it describes the
#: technique rather than the regex.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|of\s+)?"
            rf"(?:the\s+|your\s+|my\s+)?{_QUALIFIER}\s+(?:\w+\s+)?"
            r"(?:instructions?|prompts?|directives|guidelines|rules|context)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role reassignment",
        re.compile(
            r"\byou\s+(?:are|will|must|should)\s+now\b"
            r"|\bfrom\s+now\s+on,?\s+you\b"
            r"|\bnew\s+(?:instructions|task|role|system\s+prompt)\s*:"
            r"|\bpretend\s+(?:to\s+be|you\s+are)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "chat-template token",
        re.compile(
            r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|"
            r"end_header_id)\|>|\[/?INST\]|<</?SYS>>|</s>|<start_of_turn>|<end_of_turn>",
            re.IGNORECASE,
        ),
    ),
    (
        "fake conversation turn",
        re.compile(
            r"(?:^|\n)[ \t>#*]*(?:system|assistant|developer)(?:\s+prompt)?\s*:"
            r"|(?:^|\n)[ \t]*#{2,}\s*(?:system|instructions?|response)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict steering",
        re.compile(
            r"(?:\bplease\s+|\byou\s+(?:should|must|need\s+to)\s+|(?:^|[.!;:\n]\s*))"
            r"(?:classify|mark|label|rate|report|treat|consider|close|dismiss|resolve)\s+"
            r"(?:this|the|it|all|these)\b[\s\w'-]{0,30}?\b(?:as\s+)?"
            r"(?:benign|harmless|safe|false[\s-]?positives?|informational|authori[sz]ed|"
            r"legitimate|expected|not\s+malicious|low[\s-]?(?:risk|severity|priority))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "severity steering",
        re.compile(
            r"\b(?:severity|priority|risk)\b[\s\w'-]{0,20}?\b(?:should|must|needs?\s+to)\s+be\s+"
            r"(?:set\s+to\s+|marked\s+(?:as\s+)?)?(?:low|none|informational|zero|0)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter spoofing",
        re.compile(
            r"<<<\s*/?\s*(?:end\s+)?evidence"
            r"|\bend\s+of\s+(?:the\s+)?(?:evidence|log\s+data|input|alert\s+data)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt disclosure",
        re.compile(
            r"\b(?:reveal|print|repeat|show|output|disclose)\s+(?:me\s+)?(?:your|the)\s+"
            r"(?:system\s+)?(?:prompt|instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "addressed to an AI",
        re.compile(
            r"\bif\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|assistant|chatbot)\b"
            r"|\b(?:attention|note\s+to|message\s+(?:for|to)|instructions?\s+(?:for|to))\s*:?\s+"
            r"(?:the\s+|any\s+)?(?:ai|llm|assistant|language\s+model|gpt|chatbot|copilot)\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class InjectionSignal:
    """Text in the evidence that appears to address the model, and where it was."""

    technique: str
    excerpt: str
    paths: tuple[str, ...]

    @property
    def path(self) -> str:
        return self.paths[0]

    def __str__(self) -> str:
        where = self.paths[0]
        if len(self.paths) > 1:
            where += f" (+{len(self.paths) - 1} more)"
        return f'{self.technique} in {where}: "{self.excerpt}"'


def scan_text(text: str) -> list[tuple[str, str]]:
    """Return ``(technique, excerpt)`` for each pattern that matches ``text``."""
    found: list[tuple[str, str]] = []
    for technique, pattern in PATTERNS:
        match = pattern.search(text)
        if match is not None:
            found.append((technique, _excerpt(text, match.start(), match.end())))
    return found


def scan_evidence(evidence: Evidence) -> list[InjectionSignal]:
    """Scan every string the model will be shown.

    The same planted text can surface in more than one field, so signals are
    grouped by technique and excerpt, each listing every place it was seen.
    """
    grouped: dict[tuple[str, str], list[str]] = {}
    for path, value in evidence.strings():
        for technique, excerpt in scan_text(value):
            key = (technique, excerpt)
            if key not in grouped and len(grouped) >= MAX_SIGNALS:
                continue
            grouped.setdefault(key, []).append(path)
    return [
        InjectionSignal(technique=technique, excerpt=excerpt, paths=tuple(paths))
        for (technique, excerpt), paths in grouped.items()
    ]


def _excerpt(text: str, start: int, end: int) -> str:
    """The matched text with a little context, on one line."""
    lo = max(0, start - 15)
    hi = min(len(text), max(end, start + 20) + 15)
    snippet = " ".join(text[lo:hi].split())
    if len(snippet) > EXCERPT_CHARS:
        snippet = snippet[: EXCERPT_CHARS - 3] + "..."
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return f"{prefix}{snippet}{suffix}"
