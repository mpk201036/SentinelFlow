"""Stage 16 - the documentation is tested like the code.

Documentation rots quietly: a flag is renamed, an endpoint moves, a test is
split, and the page that describes them keeps saying the old thing. These
tests read every Markdown file and check each concrete claim against the code:

* every relative link and ``#anchor`` resolves;
* every ``sentinelflow`` command and flag written in the docs exists;
* every ``/api/v1/...`` path written in the docs is a real route;
* every ``SENTINELFLOW_*`` variable is a real setting;
* every repository path in code spans exists, and every test named in
  docs/testing.md's traceability table is a real test;
* every detection rule and ATT&CK technique named is one SentinelFlow has:
  the documentation may not cite a technique the project cannot back, any more
  than the code may;

and, the other way round, that nothing real goes undocumented: every CLI
command, every API route and every page in docs/ is mentioned somewhere.

The roadmap is history: it may name things that were later removed (the old
``/api/v1/ingest``), so it is checked for links only.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache
from pathlib import Path

import pytest
import typer.main

from app.api.app import create_app
from app.cli import app as cli_app
from app.core.config import Settings
from app.detection import load_rules
from app.mitre import load_catalogue

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted([ROOT / "README.md", ROOT / "SECURITY.md", *(ROOT / "docs").glob("*.md")])
HISTORY = {ROOT / "docs" / "roadmap.md"}
CURRENT = [doc for doc in DOCS if doc not in HISTORY]

_FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)
_INLINE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$", re.MULTILINE)
_API_RE = re.compile(r"/api/v1(?:/[A-Za-z0-9_{},\-]+)*")
_ENV_RE = re.compile(r"\bSENTINELFLOW_[A-Z][A-Z_]*[A-Z]\b")
_REPO_PATH_RE = re.compile(
    r"^(?:app|tests|docs|rules|data|dashboard|\.github)/[\w./-]+$|^[\w.-]+\.(?:md|toml|yml)$"
)
_TEST_REF_RE = re.compile(r"(test_\w+\.py)((?:::[\w…]+)*)")
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RULE_RE = re.compile(r"\bSF-\d{4}\b")

#: Techniques the docs name *because* the catalogue does not have them.
OUTSIDE_THE_CATALOGUE = {
    "T1234": "mitre-attack.md: the made-up identifier that is refused",
    "T1059.009": "mitre-attack.md: a sub-technique that falls back to its parent",
    "T1003.001": "ai-safety.md: a technique a model names that SentinelFlow never mapped",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(path: Path) -> Iterator[str]:
    """Every fenced block line and every inline code span in a document."""
    text = _text(path)
    for block in _FENCE_RE.findall(text):
        yield from block.splitlines()
    prose = _FENCE_RE.sub("", text)
    yield from _INLINE_RE.findall(prose)


# ===========================================================================
# Links
# ===========================================================================
def _slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"[`*_]", "", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


@cache
def _anchors(path: Path) -> frozenset[str]:
    return frozenset(_slug(h) for h in _HEADING_RE.findall(_FENCE_RE.sub("", _text(path))))


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_relative_link_resolves(doc: Path) -> None:
    broken = []
    for target in _LINK_RE.findall(_FENCE_RE.sub("", _text(doc))):
        if re.match(r"^[a-z]+:", target):
            continue  # https:, mailto:
        path_part, _, anchor = target.partition("#")
        destination = (doc.parent / path_part).resolve() if path_part else doc
        if not destination.exists() or (
            anchor and destination.suffix == ".md" and anchor not in _anchors(destination)
        ):
            broken.append(target)
    assert not broken, f"{doc.name}: broken links {broken}"


# ===========================================================================
# CLI
# ===========================================================================
@cache
def _cli() -> dict[str, set[str]]:
    """Every command path ("report", "ai status") with its option flags."""
    root = typer.main.get_command(cli_app)
    found: dict[str, set[str]] = {}

    def visit(command: object, prefix: str) -> None:
        subcommands = getattr(command, "commands", None)
        if subcommands:
            for name, sub in subcommands.items():
                visit(sub, f"{prefix} {name}".strip())
            return
        found[prefix] = {
            opt
            for param in getattr(command, "params", [])
            for opt in [*param.opts, *param.secondary_opts]
            if opt.startswith("-")
        } | {"--help"}

    visit(root, "")
    return found


def _cli_uses(doc: Path) -> Iterator[tuple[str, list[str]]]:
    for line in _code(doc):
        line = re.sub(r"\s#\s.*$", "", line).strip()
        for match in re.finditer(r"(?:^|[\s$|;&(])sentinelflow\s+([^|;&]*)", line):
            tokens = match.group(1).split()
            if not tokens or tokens[0].startswith("<") or not re.match(r"^[a-z-]+$", tokens[0]):
                continue
            command = tokens[0]
            rest = tokens[1:]
            if rest and f"{command} {rest[0]}" in _cli():
                command, rest = f"{command} {rest[0]}", rest[1:]
            yield command, [t.split("=")[0] for t in rest if t.startswith("-")]


@pytest.mark.parametrize("doc", CURRENT, ids=lambda p: p.name)
def test_every_documented_command_and_flag_exists(doc: Path) -> None:
    commands = _cli()
    wrong = []
    for command, flags in _cli_uses(doc):
        if command not in commands:
            wrong.append(f"sentinelflow {command}")
            continue
        wrong.extend(f"sentinelflow {command} {f}" for f in flags if f not in commands[command])
    assert not wrong, f"{doc.name}: {sorted(set(wrong))}"


def test_every_command_is_documented() -> None:
    documented = {command for doc in CURRENT for command, _ in _cli_uses(doc)}
    missing = sorted(set(_cli()) - documented)
    assert not missing, f"commands no document mentions: {missing}"


# ===========================================================================
# API
# ===========================================================================
@cache
def _routes() -> frozenset[str]:
    """Every API route, from the OpenAPI schema: the public description of the API."""
    app = create_app(Settings(_env_file=None, database_url="sqlite:///:memory:"))
    return frozenset(
        _normalise(path) for path in app.openapi()["paths"] if path.startswith("/api/v1")
    )


def _normalise(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", path.rstrip("/"))


def _expand(path: str) -> list[str]:
    """``/api/v1/{alerts,incidents}/{id}`` names two routes, not one."""
    match = re.search(r"\{([^{}]*,[^{}]*)\}", path)
    if match is None:
        return [path]
    return [
        variant
        for option in match.group(1).split(",")
        for variant in _expand(path[: match.start()] + option.strip() + path[match.end() :])
    ]


def _api_mentions(doc: Path) -> set[str]:
    return {
        _normalise(variant)
        for chunk in _code(doc)
        for path in _API_RE.findall(chunk)
        for variant in _expand(path)
    }


@pytest.mark.parametrize("doc", CURRENT, ids=lambda p: p.name)
def test_every_documented_endpoint_exists(doc: Path) -> None:
    unknown = sorted(p for p in _api_mentions(doc) if p not in _routes() and p != "/api/v1")
    assert not unknown, f"{doc.name}: {unknown}"


def test_every_endpoint_is_in_the_readme_table() -> None:
    missing = sorted(_routes() - _api_mentions(ROOT / "README.md"))
    assert not missing, f"endpoints missing from the README's API table: {missing}"


# ===========================================================================
# Settings, paths and tests named in the docs
# ===========================================================================
@pytest.mark.parametrize("doc", [*CURRENT, ROOT / ".env.example"], ids=lambda p: p.name)
def test_every_documented_setting_exists(doc: Path) -> None:
    fields = set(Settings.model_fields)
    unknown = sorted(
        name
        for name in set(_ENV_RE.findall(_text(doc)))
        if name.removeprefix("SENTINELFLOW_").lower() not in fields
    )
    assert not unknown, f"{doc.name}: {unknown}"


@pytest.mark.parametrize("doc", CURRENT, ids=lambda p: p.name)
def test_every_repository_path_exists(doc: Path) -> None:
    missing = sorted(
        span
        for span in _code(doc)
        if _REPO_PATH_RE.match(span)
        and "<" not in span
        and "*" not in span
        and not (ROOT / span).exists()
    )
    assert not missing, f"{doc.name}: {missing}"


def test_every_test_in_the_traceability_table_exists() -> None:
    """docs/testing.md promises that named tests back each claim. They must exist."""
    missing = []
    for span in _code(ROOT / "docs" / "testing.md"):
        for filename, parts in _TEST_REF_RE.findall(span):
            path = ROOT / "tests" / filename
            if not path.exists():
                missing.append(filename)
                continue
            source = _text(path)
            for part in filter(None, parts.split("::")):
                fragment = part.strip("…")
                if fragment and fragment not in source:
                    missing.append(f"{filename}::{part}")
    assert not missing, missing


def test_every_technique_named_in_the_docs_is_in_the_catalogue() -> None:
    catalogue = set(load_catalogue(ROOT / "data" / "mitre" / "techniques.json").techniques)
    named = {t for doc in CURRENT for t in _TECHNIQUE_RE.findall(_text(doc))}
    assert not sorted(named - catalogue - set(OUTSIDE_THE_CATALOGUE))
    # An example of refusal only illustrates it while the catalogue still refuses.
    assert not sorted(set(OUTSIDE_THE_CATALOGUE) & catalogue)


def test_every_rule_named_in_the_docs_exists() -> None:
    rules = {rule.rule_id for rule in load_rules(ROOT / "rules").rules}
    named = {r for doc in CURRENT for r in _RULE_RE.findall(_text(doc))}
    assert not sorted(named - rules)


def test_every_page_in_docs_is_linked_from_the_readme() -> None:
    readme = _text(ROOT / "README.md")
    unlinked = [p.name for p in (ROOT / "docs").glob("*.md") if f"(docs/{p.name})" not in readme]
    assert not unlinked, f"docs not linked from the README: {unlinked}"
