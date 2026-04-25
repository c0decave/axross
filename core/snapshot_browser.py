"""Virtual snapshot browser — a uniform timeline view across backends.

Phase 3b gave every backend an ``list_versions()`` API. This module
merges those per-backend histories into one sorted list so the GUI
can render a timeline without caring which protocol provided a
given revision.

Typical UI flow:

    entries = browse(s3_backend, "/docs/report.txt")
    for e in entries:
        row.label = e.label or e.version_id
        row.when  = e.modified
    # On user click:
    with read_snapshot(entry) as stream:
        bytes_ = stream.read()

Merging multiple backend views of the "same logical file" (e.g. a
file that's copied across buckets):

    timeline = merge_timelines(
        (s3_backend,     "/docs/report.txt"),
        (dropbox_backend,"/shared/report.txt"),
    )

Each entry keeps a reference to the originating backend so the UI
can stream the bytes when the user picks a revision.
"""
from __future__ import annotations

import io
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Iterable

from models.file_version import FileVersion

log = logging.getLogger("core.snapshot_browser")


@dataclass(frozen=True)
class SnapshotEntry:
    """One versioned point-in-time of a file, tagged with its origin."""

    backend: object      # the FileBackend that knows how to fetch it
    path: str            # path on *that* backend
    version: FileVersion

    # ------------------------------------------------------------------
    # Convenience passthroughs — so UIs don't have to dig into .version
    # ------------------------------------------------------------------
    @property
    def version_id(self) -> str:
        return self.version.version_id

    @property
    def modified(self) -> datetime:
        return self.version.modified

    @property
    def size(self) -> int:
        return self.version.size

    @property
    def is_current(self) -> bool:
        return self.version.is_current

    @property
    def label(self) -> str:
        return self.version.label or self.version.version_id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def browse(backend, path: str) -> list[SnapshotEntry]:
    """List versions of *path* on *backend* as :class:`SnapshotEntry`.

    Returns an empty list for backends without versioning. Swallows
    :class:`OSError` into an empty list because snapshot browsing is
    an augmentation, not a primary operation — a UI shouldn't break
    just because one backend can't enumerate.
    """
    try:
        versions = backend.list_versions(path)
    except (OSError, NotImplementedError) as exc:
        log.warning("snapshot_browser.browse(%s, %s) failed: %s",
                    type(backend).__name__, path, exc)
        return []
    return [SnapshotEntry(backend=backend, path=path, version=v)
            for v in versions]


def merge_timelines(
    *targets: tuple[object, str],
) -> list[SnapshotEntry]:
    """Merge ``list_versions()`` outputs from several (backend, path)
    pairs into one newest-first timeline.

    Ordering is by :attr:`FileVersion.modified`; ties break by
    ``version_id`` so the list is deterministic.
    """
    merged: list[SnapshotEntry] = []
    for backend, path in targets:
        merged.extend(browse(backend, path))
    merged.sort(
        key=lambda e: (e.modified, e.version_id),
        reverse=True,
    )
    return merged


def filter_by_size(
    entries: Iterable[SnapshotEntry],
    *, min_size: int = 0, max_size: int | None = None,
) -> list[SnapshotEntry]:
    """Keep entries whose size is within the given bounds."""
    out: list[SnapshotEntry] = []
    for e in entries:
        if e.size < min_size:
            continue
        if max_size is not None and e.size > max_size:
            continue
        out.append(e)
    return out


def filter_by_date(
    entries: Iterable[SnapshotEntry],
    *, since: datetime | None = None,
    until: datetime | None = None,
) -> list[SnapshotEntry]:
    """Keep entries whose modified timestamp falls in the window."""
    out: list[SnapshotEntry] = []
    for e in entries:
        if since is not None and e.modified < since:
            continue
        if until is not None and e.modified > until:
            continue
        out.append(e)
    return out


def read_snapshot(entry: SnapshotEntry) -> IO[bytes]:
    """Stream the bytes of a specific historical version.

    Thin shim over ``backend.open_version_read()`` that returns a
    BytesIO if the backend returned an unclosable stream, so callers
    can always use ``with`` safely.
    """
    handle = entry.backend.open_version_read(entry.path, entry.version_id)
    if isinstance(handle, io.IOBase):
        return handle
    # If a backend returns something weird (e.g. raw bytes) wrap it.
    if isinstance(handle, (bytes, bytearray)):
        return io.BytesIO(bytes(handle))
    return handle  # trust the backend


def latest(entry_list: Iterable[SnapshotEntry]) -> SnapshotEntry | None:
    """Return the single newest entry, or None if the list is empty."""
    best: SnapshotEntry | None = None
    for e in entry_list:
        if best is None or e.modified > best.modified:
            best = e
    return best


__all__ = [
    "SnapshotEntry",
    "browse",
    "filter_by_date",
    "filter_by_size",
    "latest",
    "merge_timelines",
    "read_snapshot",
]
