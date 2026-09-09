from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable

# Windows FILE_ATTRIBUTE_REPARSE_POINT. stat.FILE_ATTRIBUTE_REPARSE_POINT is
# available on Windows, but keeping the documented value makes the check
# portable for tests and for Python builds that omit the constant.
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400))


def absolute_lexical_path(path: str | Path) -> Path:
    """Return an absolute path without resolving links/reparse points."""
    raw = os.path.expandvars(os.path.expanduser(str(path)))
    return Path(os.path.abspath(raw))


def canonical_path(path: str | Path) -> str:
    """Canonical comparison key for paths.

    Resolution is best-effort. Windows comparisons are case-insensitive through
    normcase; on POSIX normcase is a no-op.
    """
    p = absolute_lexical_path(path)
    try:
        p = p.resolve(strict=False)
    except (OSError, RuntimeError):
        pass
    return os.path.normcase(os.path.normpath(str(p)))


def same_path(left: str | Path, right: str | Path) -> bool:
    return canonical_path(left) == canonical_path(right)


def is_within(path: str | Path, root: str | Path) -> bool:
    """Boundary-safe containment check (never uses string prefix matching)."""
    p = canonical_path(path)
    r = canonical_path(root)
    try:
        return os.path.commonpath([p, r]) == r
    except (ValueError, OSError):
        return False


def is_within_any(path: str | Path, roots: Iterable[str | Path]) -> bool:
    return any(is_within(path, root) for root in roots)


def is_reparse_point(path: str | Path) -> bool:
    """Detect symlinks and Windows junction/reparse-point leaf objects."""
    p = absolute_lexical_path(path)
    try:
        if p.is_symlink():
            return True
        st = os.lstat(p)
    except (FileNotFoundError, OSError):
        return False
    attrs = int(getattr(st, "st_file_attributes", 0) or 0)
    return bool(attrs & _REPARSE_POINT)


def has_reparse_component(path: str | Path, *, include_leaf: bool = True) -> bool:
    """Return True if an existing path component is a symlink/reparse point.

    This is intentionally used for security-sensitive *write* destinations
    (quarantine/restore/config). Ordinary scanning only rejects a reparse leaf,
    avoiding unnecessary coverage loss on legitimate redirected user folders.
    """
    current = absolute_lexical_path(path)
    if not include_leaf:
        current = current.parent

    visited: set[str] = set()
    while True:
        key = os.path.normcase(str(current))
        if key in visited:
            return True
        visited.add(key)

        if current.exists() and is_reparse_point(current):
            return True

        parent = current.parent
        if parent == current:
            break
        current = parent
    return False


def ensure_regular_non_reparse_file(path: str | Path) -> Path:
    p = absolute_lexical_path(path)
    if is_reparse_point(p):
        raise ValueError(f"Refusing reparse-point/symlink file: {p}")
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Expected a regular file: {p}")
    return p


def secure_write_parent(path: str | Path) -> Path:
    """Validate the existing destination ancestry before a sensitive write."""
    p = absolute_lexical_path(path)
    if has_reparse_component(p, include_leaf=False):
        raise ValueError("Refusing to write through a symlink/reparse-point parent.")
    return p


def same_file_snapshot(before, after) -> bool:
    """Compare file identity + mutable metadata for race detection.

    On filesystems exposing stable device/inode identifiers, a path swap with
    identical size/timestamps is rejected. Where identifiers are unavailable,
    the check conservatively falls back to size + mtime.
    """
    before_id = (int(getattr(before, "st_dev", 0) or 0), int(getattr(before, "st_ino", 0) or 0))
    after_id = (int(getattr(after, "st_dev", 0) or 0), int(getattr(after, "st_ino", 0) or 0))
    identity_ok = (
        before_id == after_id
        or before_id == (0, 0)
        or after_id == (0, 0)
    )
    return (
        identity_ok
        and int(getattr(before, "st_size", -1)) == int(getattr(after, "st_size", -2))
        and int(getattr(before, "st_mtime_ns", -1)) == int(getattr(after, "st_mtime_ns", -2))
    )
