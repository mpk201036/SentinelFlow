"""The local ATT&CK catalogue.

A curated subset of the Enterprise matrix ships in ``data/mitre/techniques.json``
— every technique the rules reference, plus the neighbouring ones a triage tool
tends to need. It is local and offline on purpose: SentinelFlow makes no network
call, and a technique name should not depend on whether attack.mitre.org is
reachable at three in the morning.

The catalogue exists to make one guarantee enforceable: **SentinelFlow cannot
show a technique it cannot name.** A mapping to an identifier absent from the
catalogue is refused rather than rendered as a bare ``T1234`` that looks
authoritative and says nothing. The database enforces the same rule with a
foreign key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.mitre import TECHNIQUE_ID_RE, MitreTechnique

logger = get_logger(__name__)

CATALOGUE_FILENAME = "techniques.json"

#: A catalogue file larger than this is not a catalogue file.
MAX_CATALOGUE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class Tactic:
    """One ATT&CK tactic — the "why" a technique serves."""

    tactic_id: str
    name: str
    shortname: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/tactics/{self.tactic_id}/"


@dataclass
class Catalogue:
    """Techniques and tactics available to the mapper."""

    techniques: dict[str, MitreTechnique] = field(default_factory=dict)
    tactics: dict[str, Tactic] = field(default_factory=dict)
    source: str = "MITRE ATT&CK Enterprise"
    attribution: str = ""
    version: str = "unknown"
    retrieved: str = ""
    errors: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.techniques)

    def __contains__(self, technique_id: object) -> bool:
        return str(technique_id).upper() in self.techniques

    def get(self, technique_id: str) -> MitreTechnique | None:
        """Exact lookup. Returns ``None`` for anything not in the catalogue."""
        return self.techniques.get(str(technique_id).strip().upper())

    def resolve(self, technique_id: str) -> MitreTechnique | None:
        """Look up a technique, falling back to its parent.

        A sub-technique the catalogue does not carry still tells us something
        real — ``T1059.009`` is a kind of ``T1059`` — so naming the parent is
        accurate rather than invented. Returning nothing at all would lose
        information the rule author legitimately had.
        """
        exact = self.get(technique_id)
        if exact is not None:
            return exact
        text = str(technique_id).strip().upper()
        if "." in text:
            return self.get(text.split(".", 1)[0])
        return None

    def by_tactic(self) -> dict[str, list[MitreTechnique]]:
        """Techniques grouped by tactic, in the matrix's own order."""
        grouped: dict[str, list[MitreTechnique]] = {name: [] for name in self.tactics}
        for technique in self.techniques.values():
            for tactic in technique.tactics:
                grouped.setdefault(tactic, []).append(technique)
        return {
            name: sorted(items, key=lambda t: t.technique_id) for name, items in grouped.items()
        }

    def tactic_names(self) -> list[str]:
        return list(self.tactics)

    def summary(self) -> str:
        parts = [f"{len(self.techniques)} techniques", f"{len(self.tactics)} tactics"]
        if self.errors:
            parts.append(f"{len(self.errors)} entries rejected")
        return ", ".join(parts)


def default_catalogue_path() -> Path:
    return get_settings().mitre_dir / CATALOGUE_FILENAME


def load_catalogue(path: str | Path | None = None) -> Catalogue:
    """Load and validate the catalogue.

    A missing or broken file yields an empty catalogue with the reason
    recorded, not an exception. SentinelFlow keeps working without ATT&CK
    names: detections still fire and severity is unaffected. ``doctor`` reports
    the gap so it is visible rather than mysterious.
    """
    target = Path(path) if path is not None else default_catalogue_path()
    catalogue = Catalogue()

    if not target.is_file():
        catalogue.errors.append(f"catalogue not found at {target}")
        logger.warning("ATT&CK catalogue missing at %s - techniques will not be named", target)
        return catalogue

    try:
        if target.stat().st_size > MAX_CATALOGUE_BYTES:
            catalogue.errors.append(f"catalogue exceeds {MAX_CATALOGUE_BYTES:,} bytes")
            return catalogue
        payload: Any = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        catalogue.errors.append(f"could not read catalogue: {exc}")
        logger.warning("ATT&CK catalogue could not be read: %s", exc)
        return catalogue

    if not isinstance(payload, dict):
        catalogue.errors.append("catalogue must be a JSON object")
        return catalogue

    catalogue.source = str(payload.get("source", catalogue.source))
    catalogue.attribution = str(payload.get("attribution", ""))
    catalogue.version = str(payload.get("version", "unknown"))
    catalogue.retrieved = str(payload.get("retrieved", ""))

    for entry in payload.get("tactics", []) or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            catalogue.errors.append(f"skipped malformed tactic: {entry!r}")
            continue
        tactic = Tactic(
            tactic_id=str(entry.get("id", "")),
            name=str(entry["name"]),
            shortname=str(entry.get("shortname", "")),
        )
        catalogue.tactics[tactic.name] = tactic

    for entry in payload.get("techniques", []) or []:
        if not isinstance(entry, dict):
            catalogue.errors.append(f"skipped malformed technique: {entry!r}")
            continue
        identifier = str(entry.get("id", "")).strip().upper()
        if not TECHNIQUE_ID_RE.match(identifier):
            catalogue.errors.append(f"skipped invalid technique id {identifier!r}")
            continue
        if identifier in catalogue.techniques:
            catalogue.errors.append(f"skipped duplicate technique {identifier}")
            continue
        try:
            catalogue.techniques[identifier] = MitreTechnique(
                technique_id=identifier,
                name=entry.get("name", ""),
                tactics=entry.get("tactics", []),
                description=entry.get("description"),
            )
        except ValueError as exc:
            catalogue.errors.append(f"skipped {identifier}: {exc}")

    unknown_tactics = {
        name
        for technique in catalogue.techniques.values()
        for name in technique.tactics
        if name not in catalogue.tactics
    }
    for name in sorted(unknown_tactics):
        catalogue.errors.append(f"technique references unlisted tactic {name!r}")

    logger.info("loaded ATT&CK catalogue: %s", catalogue.summary())
    return catalogue


@lru_cache(maxsize=1)
def get_catalogue() -> Catalogue:
    """Process-wide catalogue, loaded once."""
    return load_catalogue()
