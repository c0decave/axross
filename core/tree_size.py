"""The total size of a folder tree on any backend.

Walked with an explicit stack, so a deep tree cannot exhaust Python's
recursion limit. A link is counted with its own size and never followed,
a folder that cannot be listed is counted and skipped, and the walk stops
at ``max_depth`` levels below the root or as soon as ``cancel()`` is true.
Meant to run off the UI thread (see ui.scan_job.ScanJob).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from core.path_policy import MAX_RECURSIVE_DELETE_DEPTH, safe_join

log = logging.getLogger(__name__)

#: How many unreadable folders a result names.
UNREADABLE_SAMPLE = 10


@dataclass
class TreeSize:
    bytes: int = 0
    files: int = 0  # everything that is not a followed folder, links included
    folders: int = 0  # folders listed, the root included
    unreadable: int = 0
    #: The first folders that could not be listed (UNREADABLE_SAMPLE of them).
    unreadable_paths: list = field(default_factory=list)
    #: Entries listed but not stat'ed (a folder without search permission
    #: lists its names, not their sizes): their size is not in ``bytes``.
    unstattable: int = 0
    depth_capped: bool = False
    cancelled: bool = False


def tree_size(
    backend,
    root: str,
    *,
    cancel: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int, str], None] | None = None,
    max_depth: int = MAX_RECURSIVE_DELETE_DEPTH,
) -> TreeSize:
    """Sum the sizes below *root*; ``progress(folders, files, path)`` after
    each listed folder."""
    result = TreeSize()
    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        if cancel():
            result.cancelled = True
            break
        path, depth = stack.pop()
        try:
            items = backend.list_dir(path)
        except OSError as exc:
            log.warning("Size: cannot list %s: %s", path, exc)
            result.unreadable += 1
            if len(result.unreadable_paths) < UNREADABLE_SAMPLE:
                result.unreadable_paths.append(path)
            continue
        result.folders += 1
        for item in items:
            name = getattr(item, "name", "")
            if not name or name in (".", ".."):
                continue
            if getattr(item, "is_dir", False) and not getattr(item, "is_link", False):
                if depth + 1 > max_depth:
                    result.depth_capped = True
                    continue
                try:
                    stack.append((safe_join(backend, path, name), depth + 1))
                except ValueError as exc:
                    log.warning("Size: skipping unsafe name %r in %s: %s", name, path, exc)
                continue
            if getattr(item, "stat_error", ""):
                result.unstattable += 1  # size unknown: not an exact 0
            result.bytes += int(getattr(item, "size", 0) or 0)
            result.files += 1
        if progress is not None:
            progress(result.folders, result.files, path)
    return result
