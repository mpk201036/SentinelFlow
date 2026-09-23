"""Stage 4 — path confinement for imported files."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.paths import FileTooLargeError, UnsafePathError, check_file_size, resolve_within

pytestmark = pytest.mark.unit


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "allowed"
    (root / "nested").mkdir(parents=True)
    (root / "events.json").write_text("[]", encoding="utf-8")
    (root / "nested" / "more.json").write_text("[]", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("not for import", encoding="utf-8")
    return root


class TestContainment:
    def test_file_inside_the_root_is_allowed(self, sandbox: Path) -> None:
        assert resolve_within(sandbox / "events.json", [sandbox]).name == "events.json"

    def test_nested_file_is_allowed(self, sandbox: Path) -> None:
        assert resolve_within(sandbox / "nested" / "more.json", [sandbox]).exists()

    def test_traversal_is_rejected(self, sandbox: Path) -> None:
        with pytest.raises(UnsafePathError):
            resolve_within(sandbox / ".." / "secret.txt", [sandbox])

    def test_absolute_path_outside_the_root_is_rejected(
        self, sandbox: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(UnsafePathError):
            resolve_within(tmp_path / "secret.txt", [sandbox])

    def test_symlink_escaping_the_root_is_rejected(self, sandbox: Path, tmp_path: Path) -> None:
        """The reason containment is checked *after* resolution.

        This path contains no '..' and still lands outside the sandbox.
        """
        link = sandbox / "innocent.json"
        link.symlink_to(tmp_path / "secret.txt")
        with pytest.raises(UnsafePathError):
            resolve_within(link, [sandbox])

    def test_symlink_staying_inside_the_root_is_allowed(self, sandbox: Path) -> None:
        link = sandbox / "alias.json"
        link.symlink_to(sandbox / "events.json")
        assert resolve_within(link, [sandbox]).name == "events.json"

    def test_several_roots_are_supported(self, sandbox: Path, tmp_path: Path) -> None:
        other = tmp_path / "also-allowed"
        other.mkdir()
        (other / "x.json").write_text("[]", encoding="utf-8")
        assert resolve_within(other / "x.json", [sandbox, other]).exists()

    def test_no_roots_means_nothing_is_permitted(self, sandbox: Path) -> None:
        with pytest.raises(UnsafePathError, match="no permitted roots"):
            resolve_within(sandbox / "events.json", [])

    def test_missing_file_is_reported_as_missing(self, sandbox: Path) -> None:
        with pytest.raises(FileNotFoundError):
            resolve_within(sandbox / "absent.json", [sandbox])

    def test_missing_file_is_allowed_when_not_required(self, sandbox: Path) -> None:
        resolved = resolve_within(sandbox / "absent.json", [sandbox], must_exist=False)
        assert resolved.parent == sandbox.resolve()


class TestSizeLimit:
    def test_small_file_passes(self, sandbox: Path) -> None:
        assert check_file_size(sandbox / "events.json", 1_024) == 2

    def test_oversized_file_is_refused_before_reading(self, sandbox: Path) -> None:
        big = sandbox / "big.json"
        big.write_text("x" * 5_000, encoding="utf-8")
        with pytest.raises(FileTooLargeError, match="exceeds"):
            check_file_size(big, 1_024)
