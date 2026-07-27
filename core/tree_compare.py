"""Compare two directory trees, possibly on different backends.

``core.multi_view`` answers "is this one path the same on N hosts?".
This module answers the tree-level question behind a sync: which files
exist only on the left, only on the right, which are the same, and which
differ.

Cost is the whole design. Metadata is nearly free — one listing per
directory — while content hashing means downloading both sides. So:

1. A cheap pass classifies everything it can from size, type and mtime.
2. Hashing runs only where metadata is genuinely ambiguous (equal size,
   different mtime) AND the file is small enough to be worth the bytes.
3. Anything left over is reported as :data:`Status.UNKNOWN` with the
   reason. An unresolved comparison is a useful answer; a guessed one
   is not — telling a user "differs" about a file nobody read would
   send them copying over data that may be identical.

Timestamps are compared with a tolerance. FAT stores mtime at 2-second
granularity, S3 and WebDAV report whole seconds, and a faithful copy
between two such backends legitimately lands a second or two off. rsync
uses the same convention for the same reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from models.file_item import FileItem

log = logging.getLogger(__name__)

#: Files at or below this size are hashed automatically when metadata is
#: ambiguous. Above it the comparison is reported unresolved rather than
#: pulling the content down uninvited.
DEFAULT_HASH_LIMIT = 10 * 1024 * 1024  # 10 MiB

#: Seconds of mtime drift treated as "the same moment".
MTIME_TOLERANCE_S = 2.0

#: Directory-recursion cap, guarding against symlink loops on backends
#: that do not report ``is_link``.
DEFAULT_MAX_DEPTH = 64


class Status:
    """Classification of one path across the two trees."""

    LEFT_ONLY = "left_only"
    RIGHT_ONLY = "right_only"
    SAME = "same"
    DIFFERS = "differs"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ComparedEntry:
    """One path, as seen from both sides."""

    rel_path: str
    status: str
    reason: str
    left: FileItem | None = None
    right: FileItem | None = None

    @property
    def size(self) -> int:
        """Size of whichever side exists, for display and budgeting."""
        item = self.left or self.right
        return item.size if item is not None else 0


def walk(
    backend,
    root: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    should_continue: Callable[[], bool] | None = None,
) -> dict[str, FileItem]:
    """Map every entry under ``root`` to its path relative to ``root``.

    Symlinked directories are recorded as entries but never descended
    into: following them duplicates whole subtrees and, on a backend
    without loop detection, does not terminate. Unreadable directories
    are skipped — a permission-denied subtree should cost the caller
    that subtree, not the entire comparison.

    ``should_continue`` is checked before every listing. Walking a remote
    tree is unbounded work, and a caller that has gone away (a closed
    window) needs the walk to stop rather than merely be waited on:
    ``QThread.quit()`` ends an event loop but cannot interrupt a slot
    that is already running.
    """
    found: dict[str, FileItem] = {}

    def _descend(path: str, prefix: str, depth: int) -> None:
        if should_continue is not None and not should_continue():
            return
        if depth >= max_depth:
            log.debug("tree_compare: depth cap reached at %s", path)
            return
        try:
            entries = backend.list_dir(path)
        except OSError as exc:
            log.debug("tree_compare: skipping %s: %s", path, exc)
            return
        for item in entries:
            rel = f"{prefix}{item.name}"
            found[rel] = item
            if item.is_dir and not item.is_link:
                _descend(backend.join(path, item.name), f"{rel}/", depth + 1)

    _descend(root, "", 0)
    return found


def _mtime_matches(left: FileItem, right: FileItem) -> bool:
    try:
        delta = abs((left.modified - right.modified).total_seconds())
    except (TypeError, AttributeError):
        return False
    return delta <= MTIME_TOLERANCE_S


def _classify(
    rel: str,
    left: FileItem | None,
    right: FileItem | None,
    *,
    left_backend,
    left_root: str,
    right_backend,
    right_root: str,
    hash_limit: int,
    hasher: Callable[[object, str], str],
) -> ComparedEntry:
    if right is None:
        return ComparedEntry(rel, Status.LEFT_ONLY, "missing on the right", left, right)
    if left is None:
        return ComparedEntry(rel, Status.RIGHT_ONLY, "missing on the left", left, right)

    if left.is_dir != right.is_dir:
        return ComparedEntry(
            rel, Status.DIFFERS, "type differs (directory vs file)", left, right
        )
    if left.is_dir:
        # Directories are compared for existence only; their contents
        # show up as their own entries.
        return ComparedEntry(rel, Status.SAME, "directory on both sides", left, right)

    if left.size != right.size:
        # Decisive on its own — never read content to confirm.
        return ComparedEntry(
            rel, Status.DIFFERS, f"size differs ({left.size} vs {right.size})", left, right
        )

    if _mtime_matches(left, right):
        return ComparedEntry(rel, Status.SAME, "same size and mtime", left, right)

    # Equal size, different mtime: metadata cannot decide.
    if hash_limit <= 0 or left.size > hash_limit:
        return ComparedEntry(
            rel,
            Status.UNKNOWN,
            f"same size, mtime differs — too large to hash automatically "
            f"({left.size} bytes)",
            left,
            right,
        )

    try:
        left_digest = hasher(left_backend, _join(left_backend, left_root, rel))
        right_digest = hasher(right_backend, _join(right_backend, right_root, rel))
    except OSError as exc:
        # Not evidence of a difference — say so rather than guessing.
        return ComparedEntry(rel, Status.UNKNOWN, f"could not read: {exc}", left, right)

    if left_digest == right_digest:
        return ComparedEntry(rel, Status.SAME, "same content (hash)", left, right)
    return ComparedEntry(rel, Status.DIFFERS, "content differs (hash)", left, right)


def _join(backend, root: str, rel: str) -> str:
    path = root
    for part in rel.split("/"):
        path = backend.join(path, part)
    return path


def compare_trees(
    left_backend,
    left_root: str,
    right_backend,
    right_root: str,
    *,
    hash_limit: int = DEFAULT_HASH_LIMIT,
    hasher: Callable[[object, str], str] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    should_continue: Callable[[], bool] | None = None,
) -> list[ComparedEntry]:
    """Compare two trees, returning one entry per distinct relative path.

    ``hasher`` defaults to :func:`core.scripting.hash_file`, which
    deliberately avoids server-side fingerprints: an S3 ETag compared
    against a local SHA-256 would be meaningless, so algorithm parity
    across backends matters more than the round trip a native checksum
    would save.
    """
    if hasher is None:
        from core.scripting import hash_file

        hasher = hash_file

    left_items = walk(
        left_backend, left_root, max_depth=max_depth, should_continue=should_continue
    )
    right_items = walk(
        right_backend, right_root, max_depth=max_depth, should_continue=should_continue
    )

    return [
        _classify(
            rel,
            left_items.get(rel),
            right_items.get(rel),
            left_backend=left_backend,
            left_root=left_root,
            right_backend=right_backend,
            right_root=right_root,
            hash_limit=hash_limit,
            hasher=hasher,
        )
        for rel in sorted(set(left_items) | set(right_items))
    ]


def summarize(entries: list[ComparedEntry]) -> dict[str, int]:
    """Count entries per status, for a one-line result summary."""
    counts = {
        Status.LEFT_ONLY: 0,
        Status.RIGHT_ONLY: 0,
        Status.SAME: 0,
        Status.DIFFERS: 0,
        Status.UNKNOWN: 0,
    }
    for entry in entries:
        counts[entry.status] = counts.get(entry.status, 0) + 1
    return counts


__all__ = [
    "DEFAULT_HASH_LIMIT",
    "DEFAULT_MAX_DEPTH",
    "MTIME_TOLERANCE_S",
    "ComparedEntry",
    "Status",
    "compare_trees",
    "summarize",
    "walk",
]
