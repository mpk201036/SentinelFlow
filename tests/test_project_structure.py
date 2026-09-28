"""Stage 1 — repository hygiene.

A portfolio project is judged partly on its repository. These tests keep the
layout and the secret-handling guarantees honest as the project grows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REQUIRED_DIRS = [
    "app/api",
    "app/ai",
    "app/core",
    "app/database",
    "app/detection",
    "app/enrichment",
    "app/ingestion",
    "app/mitre",
    "app/models",
    "app/reports",
    "app/services",
    "dashboard/templates",
    "dashboard/static",
    "rules",
    "data/samples",
    "data/mitre",
    "tests",
    "docs",
    "scripts",
]

REQUIRED_FILES = [
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    ".env.example",
    ".gitignore",
    "README.md",
    "SECURITY.md",
    "LICENSE",
    "Makefile",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "RELEASING.md",
    "docs/images/overview.png",
    "docs/images/alert-detail.png",
    "docs/images/investigation-detail.png",
]


@pytest.mark.parametrize("directory", REQUIRED_DIRS)
def test_required_directory_exists(project_root: Path, directory: str) -> None:
    assert (project_root / directory).is_dir(), f"missing directory: {directory}"


@pytest.mark.parametrize("filename", REQUIRED_FILES)
def test_required_file_exists(project_root: Path, filename: str) -> None:
    assert (project_root / filename).is_file(), f"missing file: {filename}"


def test_version_is_consistent(project_root: Path) -> None:
    from app import __version__

    pyproject = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in pyproject


class TestSecretHygiene:
    def test_env_is_gitignored_but_the_example_is_not(self, project_root: Path) -> None:
        gitignore = (project_root / ".gitignore").read_text(encoding="utf-8")
        assert ".env" in gitignore
        assert "!.env.example" in gitignore

    def test_database_and_logs_are_ignored(self, project_root: Path) -> None:
        gitignore = (project_root / ".gitignore").read_text(encoding="utf-8")
        for pattern in ("*.db", "*.log", ".venv/", "__pycache__/"):
            assert pattern in gitignore, f"{pattern} must be gitignored"

    def test_env_example_ships_ai_disabled(self, project_root: Path) -> None:
        content = (project_root / ".env.example").read_text(encoding="utf-8")
        assert "SENTINELFLOW_AI_ENABLED=false" in content
        assert "SENTINELFLOW_AI_PROVIDER=none" in content

    def test_env_example_contains_no_credential_values(self, project_root: Path) -> None:
        """Placeholder config only — never a real key, even an expired one."""
        content = (project_root / ".env.example").read_text(encoding="utf-8").lower()
        for marker in ("sk-", "aws_secret", "-----begin", "ghp_", "xoxb-"):
            assert marker not in content, f"suspicious value in .env.example: {marker}"


class TestSupplyChain:
    """Security pass: what runs in CI and the release job is fixed, not whatever a tag says."""

    def test_every_action_is_pinned_to_a_commit(self, project_root: Path) -> None:
        import re

        unpinned = []
        for workflow in sorted((project_root / ".github" / "workflows").glob("*.yml")):
            for line in workflow.read_text(encoding="utf-8").splitlines():
                match = re.search(r"uses:\s*([^\s#]+)", line)
                if match and not re.search(r"@[0-9a-f]{40}$", match.group(1)):
                    unpinned.append(f"{workflow.name}: {match.group(1)}")
        assert not unpinned, f"pin these to a full commit SHA: {unpinned}"

    def test_checkout_does_not_leave_the_token_behind(self, project_root: Path) -> None:
        for workflow in (project_root / ".github" / "workflows").glob("*.yml"):
            text = workflow.read_text(encoding="utf-8")
            assert text.count("actions/checkout@") == text.count("persist-credentials: false")

    def test_dependencies_and_actions_get_reviewed_updates(self, project_root: Path) -> None:
        config = (project_root / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        assert "package-ecosystem: github-actions" in config
        assert "package-ecosystem: pip" in config
