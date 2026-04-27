"""cas_dedupe.py — content-addressable dedupe across backends.

Indexes every file under ROOT on BACKEND into the CAS sqlite store
(``core.cas``), then reports duplicates *across all indexed
backends*. Different from ``dedupe.py``: that one walks one tree;
this one persists hashes in a database, so a second run from a
different backend cross-correlates with the first.

Usage::

    db = "/tmp/axross-cas.sqlite"
    src1 = axross.open("server-a")
    src2 = axross.open("server-b")
    cas_index(src1, "/var/data", db, backend_id="srv-a")
    cas_index(src2, "/srv/data", db, backend_id="srv-b")
    for group in cas_duplicates(db):
        for entry in group:
            print(entry.backend_id, entry.path, entry.size)
"""
from __future__ import annotations

from pathlib import Path

from core import cas as _cas


def cas_index(backend, root: str, db_path: str,
              backend_id: str, algorithm: str = "sha256") -> int:
    """Walk ``root`` on ``backend`` and (re)build the CAS index for
    that backend. Returns the number of entries indexed."""
    return _cas.rebuild(
        backend, root,
        backend_id=backend_id,
        db_path=Path(db_path),
        algorithm=algorithm,
    )


def cas_duplicates(db_path: str, algorithm: str = "sha256") -> list:
    """Return groups of entries that share a content hash. Each group
    is a list of :class:`core.cas.CasEntry` with ``backend_id`` /
    ``path`` / ``size`` / ``algorithm`` / ``value`` populated."""
    return _cas.duplicates(Path(db_path), algorithm=algorithm)
