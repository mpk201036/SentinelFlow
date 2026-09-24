"""Loading rules from disk.

``yaml.safe_load`` is used, never ``yaml.load``. PyYAML's default loader
constructs arbitrary Python objects from tags like ``!!python/object/apply``,
which turns a rule file into code execution. Rule files are trusted content,
but "trusted" and "a deserialisation sink" should not overlap.

A broken rule file does not stop the others from loading. It is collected as an
error and reported, because a detection stack where one bad file silently
disables everything is worse than one that tells you which file is wrong.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.core.config import get_settings
from app.core.display import counted
from app.core.logging import get_logger
from app.detection.schema import RuleDefinition

logger = get_logger(__name__)

RULE_SUFFIXES = (".yaml", ".yml")

#: A rule file that is larger than this is not a rule file.
MAX_RULE_FILE_BYTES = 256 * 1024


@dataclass(frozen=True)
class RuleError:
    """A rule file that could not be loaded, and why."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass
class RuleSet:
    """Everything found in the rules directory."""

    rules: list[RuleDefinition] = field(default_factory=list)
    errors: list[RuleError] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    @property
    def enabled(self) -> list[RuleDefinition]:
        return [rule for rule in self.rules if rule.enabled]

    @property
    def by_id(self) -> dict[str, RuleDefinition]:
        return {rule.rule_id: rule for rule in self.rules}

    def get(self, rule_id: str) -> RuleDefinition | None:
        return self.by_id.get(rule_id)

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.severity.value] = counts.get(rule.severity.value, 0) + 1
        return counts

    def summary(self) -> str:
        parts = [f"{counted(len(self.rules), 'rule')} ({len(self.enabled)} enabled)"]
        if self.errors:
            parts.append(f"{len(self.errors)} failed to load")
        return ", ".join(parts)


def _describe_validation_error(error: ValidationError) -> str:
    """Condense a Pydantic error into something a rule author can act on."""
    parts = []
    for item in error.errors()[:4]:
        location = ".".join(str(piece) for piece in item["loc"]) or "rule"
        parts.append(f"{location}: {item['msg']}")
    if len(error.errors()) > 4:
        parts.append(f"and {len(error.errors()) - 4} more")
    return "; ".join(parts)


def load_rule_document(document: Any, *, source_path: str | None = None) -> RuleDefinition:
    """Build a rule from one already-parsed YAML document."""
    if not isinstance(document, dict):
        raise ValueError(f"expected a mapping, got {type(document).__name__}")
    payload = dict(document)
    payload["source_path"] = source_path
    return RuleDefinition(**payload)


def load_rule_file(path: Path) -> tuple[list[RuleDefinition], list[RuleError]]:
    """Load every rule document in one file.

    Multi-document YAML is supported, so related rules can share a file.
    """
    rules: list[RuleDefinition] = []
    errors: list[RuleError] = []
    name = path.name

    try:
        if path.stat().st_size > MAX_RULE_FILE_BYTES:
            return ([], [RuleError(name, f"file exceeds {MAX_RULE_FILE_BYTES:,} bytes")])
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ([], [RuleError(name, f"could not read file: {exc}")])

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return ([], [RuleError(name, f"invalid YAML: {exc}")])

    for index, document in enumerate(documents):
        if document is None:
            continue
        label = name if len(documents) == 1 else f"{name}[{index}]"
        try:
            rules.append(load_rule_document(document, source_path=str(path)))
        except ValidationError as exc:
            errors.append(RuleError(label, _describe_validation_error(exc)))
        except ValueError as exc:
            errors.append(RuleError(label, str(exc)))
    return (rules, errors)


def load_rules(directory: str | Path | None = None) -> RuleSet:
    """Load and validate every rule in a directory."""
    root = Path(directory) if directory is not None else get_settings().rules_dir
    result = RuleSet()

    if not root.is_dir():
        result.errors.append(RuleError(str(root), "rules directory does not exist"))
        return result

    paths = sorted(p for p in root.rglob("*") if p.suffix.lower() in RULE_SUFFIXES)
    seen: dict[str, str] = {}

    for path in paths:
        rules, errors = load_rule_file(path)
        result.errors.extend(errors)
        for rule in rules:
            previous = seen.get(rule.rule_id)
            if previous is not None:
                # Two rules with one id means one of them silently wins, and an
                # analyst cannot tell which fired.
                result.errors.append(
                    RuleError(
                        path.name, f"duplicate rule id {rule.rule_id!r}, first seen in {previous}"
                    )
                )
                continue
            seen[rule.rule_id] = path.name
            result.rules.append(rule)

    result.rules.sort(key=lambda rule: rule.rule_id)
    logger.info("loaded rules from %s: %s", root, result.summary())
    for error in result.errors:
        logger.warning("rule error - %s", error)
    return result


def rules_by_technique(rules: Iterable[RuleDefinition]) -> dict[str, list[str]]:
    """ATT&CK technique to the rules that reference it."""
    mapping: dict[str, list[str]] = {}
    for rule in rules:
        for technique in rule.mitre:
            mapping.setdefault(technique, []).append(rule.rule_id)
    return dict(sorted(mapping.items()))
