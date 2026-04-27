"""snapshot_walk.py — version timeline via core.snapshot_browser.

Backends with native version history (S3, Azure Blob, Dropbox,
Google Drive, OneDrive, WebDAV DeltaV) expose past revisions of a
file. ``core.snapshot_browser`` is the unified walker on top.

Use case: on an audit, list every historical revision of a hot
file and read the *previous* version into a buffer for diffing —
without committing it back.

Usage::

    backend = axross.open("backup-target")
    versions = list_versions(backend, "/etc/app/config.yaml")
    for v in versions:
        print(v.timestamp, v.size, v.version_id)
    older = snapshot_at(backend, versions[1])
"""
from __future__ import annotations

from core import snapshot_browser as _snap


def list_versions(backend, path: str):
    """Return every snapshot entry for ``path`` (newest first)."""
    return _snap.browse(backend, path)


def latest_snapshot(backend, path: str):
    """The newest entry, or None when the file has no version history."""
    return _snap.latest(_snap.browse(backend, path))


def snapshot_at(backend, entry) -> bytes:
    """Read the bytes of a specific historical snapshot. ``entry`` is
    one of the :class:`SnapshotEntry`s returned by :func:`list_versions`."""
    with _snap.read_snapshot(entry) as fh:
        return fh.read()
