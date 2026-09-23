"""Safe filesystem path handling for imported files.

SentinelFlow takes a file path from a CLI argument or an API request and opens
it. That is a directory-traversal sink, and the usual mistakes are all
available: ``../../etc/passwd``, an absolute path outside the project, or a
symlink that looks innocuous and points somewhere else.

:func:`resolve_within` resolves the path *fully* — including symlinks — and
then checks the result against an allow-list of roots. Checking before
resolution is the classic error: ``data/samples/link`` contains no ``..`` and
still lands wherever the link points.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


class UnsafePathError(ValueError):
    """Raised when a path escapes every permitted root."""


class FileTooLargeError(ValueError):
    """Raised when a file exceeds the configured import limit."""


def resolve_within(
    candidate: str | Path,
    allowed_roots: Iterable[str | Path],
    *,
    must_exist: bool = True,
) -> Path:
    """Resolve ``candidate`` and confirm it sits inside one of ``allowed_roots``.

    Returns the fully resolved path. Raises :class:`UnsafePathError` if it
    escapes, or :class:`FileNotFoundError` when ``must_exist`` and it does not.
    """
    roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    if not roots:
        raise UnsafePathError("no permitted roots were configured")

    # strict=False so a non-existent path still has its symlinks resolved,
    # rather than raising before the containment check runs.
    resolved = Path(candidate).expanduser().resolve(strict=False)

    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise UnsafePathError(
            f"{resolved} is outside the permitted directories: "
            + ", ".join(str(root) for root in roots)
        )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"no such file: {resolved}")
    return resolved


def check_file_size(path: Path, max_bytes: int) -> int:
    """Return the file size, raising if it exceeds ``max_bytes``.

    Checked before reading, so an oversized file is never loaded into memory.
    """
    size = path.stat().st_size
    if size > max_bytes:
        raise FileTooLargeError(
            f"{path.name} is {size:,} bytes, which exceeds the {max_bytes:,} byte limit"
        )
    return size
