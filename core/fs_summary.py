"""Totalling up a selection of files and directories.

Select everything and ask for properties: the answer wanted is one
summary — how many files, how many directories, how much in total.

What decides whether that total means anything is the handling of
entries the user cannot read. Silently skipping them is not "best
effort": it produces a wrong number presented as a fact, and wrong in
the direction that hurts. It UNDER-reports, so somebody checking
whether a copy will fit is told yes and then runs out of space.

So every unreadable path is counted, a sample of them is kept for the
dialog to show, and :attr:`Summary.complete` says plainly that the total
is partial. The same flag covers the other two ways a walk can stop
early — the depth cap and cancellation — because from the caller's point
of view they mean the same thing: this number is a floor, not a total.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from models.file_item import FileItem

log = logging.getLogger(__name__)

#: Recursion cap, guarding against symlink loops on backends that do not
#: report ``is_link``.
DEFAULT_MAX_DEPTH = 64

#: How many unreadable paths to keep for display. Selecting a whole
#: filesystem can deny thousands; the count stays exact regardless.
DEFAULT_UNREADABLE_SAMPLE = 20


@dataclass
class Summary:
    """What a selection adds up to."""

    files: int = 0
    directories: int = 0
    total_bytes: int = 0
    #: A sample of paths that could not be read, for display.
    unreadable: list[str] = field(default_factory=list)
    #: How many were unreadable in total — not capped.
    unreadable_count: int = 0
    #: False when anything was skipped: a denial, the depth cap, or a
    #: cancellation. The total is then a floor, not a total.
    complete: bool = True


def summarize_selection(
    backend,
    parent_path: str,
    items: list[FileItem],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    unreadable_sample: int = DEFAULT_UNREADABLE_SAMPLE,
    should_continue: Callable[[], bool] | None = None,
) -> Summary:
    """Count and total ``items`` under ``parent_path``.

    Directories are descended into; their own reported size is ignored,
    because several backends report an inode size for a directory and
    adding that to the recursive total inflates the answer.

    Symlinked directories are counted as entries but never followed —
    doing so double-counts a tree, or on a backend without loop
    detection does not terminate.
    """
    summary = Summary()

    def _note_unreadable(path: str) -> None:
        summary.unreadable_count += 1
        summary.complete = False
        if len(summary.unreadable) < unreadable_sample:
            summary.unreadable.append(path)

    def _descend(path: str, depth: int) -> None:
        if should_continue is not None and not should_continue():
            summary.complete = False
            return
        if depth >= max_depth:
            log.debug("fs_summary: depth cap reached at %s", path)
            summary.complete = False
            return
        try:
            entries = backend.list_dir(path)
        except OSError as exc:
            log.debug("fs_summary: cannot read %s: %s", path, exc)
            _note_unreadable(path)
            return
        for item in entries:
            _account(path, item, depth)

    def _account(parent: str, item: FileItem, depth: int) -> None:
        child = backend.join(parent, item.name)
        if item.is_dir and not item.is_link:
            summary.directories += 1
            _descend(child, depth + 1)
            return
        if item.is_dir:  # symlinked directory: an entry, not a subtree
            summary.directories += 1
            return
        summary.files += 1
        summary.total_bytes += int(item.size or 0)

    for item in items:
        if should_continue is not None and not should_continue():
            summary.complete = False
            break
        _account(parent_path, item, 0)

    return summary


def describe(summary: Summary) -> str:
    """One line for the properties sheet."""
    parts = [
        f"{summary.files} file(s)",
        f"{summary.directories} director{'y' if summary.directories == 1 else 'ies'}",
    ]
    text = ", ".join(parts)
    if summary.unreadable_count:
        text += f" — {summary.unreadable_count} entr"
        text += "y" if summary.unreadable_count == 1 else "ies"
        text += " could not be read"
    elif not summary.complete:
        text += " — the walk stopped early"
    return text


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_UNREADABLE_SAMPLE",
    "Summary",
    "describe",
    "summarize_selection",
]
