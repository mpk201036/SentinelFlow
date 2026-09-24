"""Checking the model's claims against the evidence it was given.

A model told to label a claim ``observed`` only when the evidence shows it will
still, sometimes, "observe" an IP address that is not there. This module
catches the checkable part of that:

* **Indicators in observed statements.** Every IP address, domain, URL, hash,
  e-mail address, file path and executable name in an ``observed`` statement
  is looked up in the evidence, using the same extractor that enrichment
  uses. If any is missing, the statement is shown as ``inferred`` and marked
  as downgraded, and a note names the missing value.
* **ATT&CK technique IDs anywhere in the reply.** SentinelFlow's mappings come
  from rules and a local catalogue, and each carries a reason. A technique the
  model mentions that is not mapped to this alert is not a mapping, and a note
  says so. If the mention is in an ``observed`` statement, that statement is
  downgraded too.

What this cannot check is said plainly in docs/ai-safety.md: a hostname or
username the model invents, a wrong relationship between two real values, or
a fluent claim with no specific value in it at all. Grounding narrows what a
model can get away with; the analyst is still the check.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.ai.evidence import Evidence
from app.enrichment.extractor import IOCExtractor
from app.models.ai import AIStatement
from app.models.enums import IndicatorType, StatementType

#: Indicator types precise enough to check by lookup.
CHECKED_TYPES = frozenset(
    {
        IndicatorType.IPV4,
        IndicatorType.IPV6,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.MD5,
        IndicatorType.SHA1,
        IndicatorType.SHA256,
        IndicatorType.EMAIL,
        IndicatorType.FILE_PATH,
        IndicatorType.PROCESS_NAME,
    }
)

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_EXTRACTOR = IOCExtractor()


@dataclass
class GroundingResult:
    statements: list[AIStatement]
    notes: list[str] = field(default_factory=list)

    @property
    def downgraded(self) -> int:
        return sum(1 for s in self.statements if s.downgraded)


def unsupported_values(text: str, evidence: Evidence) -> list[str]:
    """Indicators and technique IDs in ``text`` that the evidence does not contain."""
    missing: dict[str, None] = {}
    for indicator_type, value in _EXTRACTOR.scan_text(text):
        if indicator_type in CHECKED_TYPES and not evidence.contains(value):
            missing[value] = None
    for technique in unmapped_techniques([text], evidence):
        missing[technique] = None
    return list(missing)


def unmapped_techniques(texts: Iterable[str], evidence: Evidence) -> list[str]:
    """ATT&CK IDs mentioned in ``texts`` that are not mapped to the alert.

    Naming the parent of a mapped sub-technique (T1059 when T1059.001 is
    mapped) is supported by the mapping. Naming a sub-technique of a mapped
    parent is not: it claims more precision than the rules established.
    """
    mapped = evidence.mapped_techniques
    parents = {technique.split(".")[0] for technique in mapped}
    found: dict[str, None] = {}
    for text in texts:
        for match in TECHNIQUE_RE.findall(text):
            technique = match.upper()
            if technique not in mapped and technique not in parents:
                found[technique] = None
    return list(found)


def ground(
    statements: Sequence[AIStatement], evidence: Evidence, *, other_text: Iterable[str] = ()
) -> GroundingResult:
    """Downgrade unsupported observed statements and note unmapped techniques."""
    result: list[AIStatement] = []
    notes: list[str] = []

    for position, statement in enumerate(statements, start=1):
        if statement.statement_type is not StatementType.OBSERVED:
            result.append(statement)
            continue
        missing = unsupported_values(statement.text, evidence)
        if not missing:
            result.append(statement)
            continue
        result.append(
            AIStatement(statement_type=StatementType.INFERRED, text=statement.text, downgraded=True)
        )
        notes.append(
            f"Statement {position} was labelled observed but cites {_quote(missing)}, which "
            "the evidence does not contain. It is shown as inferred."
        )

    # Techniques anywhere else in the reply get a note but nothing to downgrade.
    elsewhere = unmapped_techniques(
        [
            *other_text,
            *(s.text for s in statements if s.statement_type is not StatementType.OBSERVED),
        ],
        evidence,
    )
    if elsewhere:
        notes.append(
            f"The analysis mentions ATT&CK {', '.join(elsewhere)}, which SentinelFlow did not "
            "map to this alert. A model mentioning a technique is not a mapping."
        )
    return GroundingResult(statements=result, notes=notes)


def _quote(values: list[str], limit: int = 3) -> str:
    shown = ", ".join(repr(value[:80]) for value in values[:limit])
    extra = len(values) - limit
    return f"{shown} and {extra} more" if extra > 0 else shown
