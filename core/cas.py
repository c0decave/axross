"""Content-Addressable storage layer — find files by their checksum.

The CAS is a *client-side* index: a SQLite database on the user's
machine mapping ``(backend_id, path) -> (algorithm, value, size, mtime)``.
It does not live on any remote; rebuild is a walk + checksum() pass.

Why this is useful
------------------
* "Do I already have this file somewhere?" — look up a hash from a
  friend or a receipt and find every path that carries the same
  content.
* "Find duplicates across protocols" — rows that share
  ``(algorithm, value)`` are duplicates regardless of where they live.
* "Verify remote against a known good" — compare the stored checksum
  against a fresh one without downloading.

URL form
--------
:func:`cas_url` serializes a hash as ``ax-cas://<algo>:<hex>`` so
links can be copy-pasted between users. Anyone with the CAS index
can resolve the URL to real paths via :func:`resolve_url`.

We deliberately do **not** make this transparent to FileBackend —
the abstraction is "I have a local directory of pointers", not
"every backend supports hash lookup." Most protocols don't and
fighting that would lead to bad fallbacks.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("core.cas")

# Default location follows XDG. Callers can override by passing their
# own path to every function that takes ``db_path``.
_DEFAULT_DB = Path(
    os.environ.get("AXROSS_CAS_DB")
    or Path.home() / ".local" / "share" / "axross" / "cas.sqlite"
)

CAS_URL_SCHEME = "ax-cas"

# See core/metadata_index.py for the rationale on LIKE escaping.
_LIKE_ESCAPE = "!"


def _like_escape(s: str) -> str:
    return (
        s.replace(_LIKE_ESCAPE, _LIKE_ESCAPE + _LIKE_ESCAPE)
         .replace("%", _LIKE_ESCAPE + "%")
         .replace("_", _LIKE_ESCAPE + "_")
    )

# Hard caps on the walk to defeat hostile backends that return fake
# symlink loops, multi-thousand-deep directories, or millions of
# entries in one directory. Both are deliberately loose for real
# trees but tight enough to stop OOM / stack-overflow attacks.
MAX_WALK_DEPTH = 50
MAX_WALK_ENTRIES = 1_000_000


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CasEntry:
    """One row from the CAS index."""

    backend_id: str
    path: str
    algorithm: str
    value: str
    size: int
    indexed_at: datetime


# ---------------------------------------------------------------------------
# Schema + connection helpers
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cas (
    backend_id TEXT NOT NULL,
    path       TEXT NOT NULL,
    algorithm  TEXT NOT NULL,
    value      TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    indexed_at TEXT NOT NULL,
    PRIMARY KEY (backend_id, path, algorithm)
);
CREATE INDEX IF NOT EXISTS cas_by_value
    ON cas (algorithm, value);
CREATE INDEX IF NOT EXISTS cas_by_backend
    ON cas (backend_id);
"""


_lock = threading.Lock()

# NOTE: serialises threads within one process. Cross-process access
# should rely on SQLite's file locking, not this lock.


@contextmanager
def _connect(db_path: Path | None):
    path = Path(db_path) if db_path else _DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = sqlite3.connect(str(path))
        try:
            conn.executescript(SCHEMA_SQL)
            yield conn
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Low-level index ops
# ---------------------------------------------------------------------------

def _split_prefix(raw: str) -> tuple[str, str]:
    """Checksums from FileBackend come as ``algo:hex``. Split them."""
    if ":" in raw:
        algo, _, value = raw.partition(":")
        return algo.strip().lower(), value.strip().lower()
    return "sha256", raw.strip().lower()


def upsert(db_path, backend_id: str, path: str,
           algorithm: str, value: str, size: int) -> None:
    """Insert or replace a row for this backend+path+algorithm.

    Rejects attacker-controlled inputs that would pollute the index:
    NUL bytes, bidi override chars, absurdly long strings. See
    :mod:`core.remote_name` for the full policy.
    """
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES, validate_remote_name,
    )
    validate_remote_name(
        path, max_bytes=MAX_REMOTE_PATH_BYTES, allow_separators=True,
    )
    validate_remote_name(backend_id, max_bytes=256)
    # algorithm / value are short tokens, enforce here rather than
    # trust the caller.
    if not algorithm or len(algorithm) > 32:
        raise ValueError("algorithm must be a short non-empty token")
    if not value or len(value) > 256:
        raise ValueError("checksum value must fit in 256 chars")
    if "\x00" in algorithm or "\x00" in value:
        raise ValueError("algorithm / value contain NUL")
    when = datetime.now().isoformat(timespec="seconds")
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO cas(backend_id, path, algorithm, value, size, "
            "indexed_at) VALUES(?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(backend_id, path, algorithm) DO UPDATE SET "
            "value=excluded.value, size=excluded.size, "
            "indexed_at=excluded.indexed_at",
            (backend_id, path, algorithm.lower(), value.lower(),
             int(size), when),
        )


def remove(db_path, backend_id: str, path: str) -> int:
    """Drop every row for *path* on *backend_id*. Returns rows removed."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM cas WHERE backend_id=? AND path=?",
            (backend_id, path),
        )
        return cur.rowcount


def find_by_value(db_path, algorithm: str, value: str) -> list[CasEntry]:
    """Return every file whose checksum matches."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT backend_id, path, algorithm, value, size, indexed_at "
            "FROM cas WHERE algorithm=? AND value=?",
            (algorithm.lower(), value.lower()),
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


def list_for_backend(db_path, backend_id: str) -> list[CasEntry]:
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT backend_id, path, algorithm, value, size, indexed_at "
            "FROM cas WHERE backend_id=? ORDER BY path",
            (backend_id,),
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


def duplicates(db_path, algorithm: str = "sha256") -> list[list[CasEntry]]:
    """Groups of 2+ files that share a checksum. Empty list if none."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT value FROM cas WHERE algorithm=? "
            "GROUP BY value HAVING COUNT(*) >= 2",
            (algorithm.lower(),),
        )
        dup_values = [r[0] for r in cur.fetchall()]
    return [find_by_value(db_path, algorithm, v) for v in dup_values]


def _row_to_entry(row) -> CasEntry:
    backend_id, path, algorithm, value, size, indexed_at = row
    try:
        when = datetime.fromisoformat(indexed_at)
    except ValueError:
        when = datetime.now()
    return CasEntry(
        backend_id=backend_id, path=path, algorithm=algorithm,
        value=value, size=int(size), indexed_at=when,
    )


# ---------------------------------------------------------------------------
# Backend walk — optional, builds the index from a live backend
# ---------------------------------------------------------------------------

def _walk_files(backend, root: str, *, depth: int = 0,
                counter: list | None = None):
    """Depth-first walk yielding absolute file paths under *root*.

    Capped at :data:`MAX_WALK_DEPTH` and :data:`MAX_WALK_ENTRIES` —
    hostile backends can't drive an infinite recursion via fake
    symlink loops, and can't explode the SQLite DB with millions of
    entries.

    *counter* is a single-element list passed by reference so the
    recursive calls can share a running total. The top-level caller
    passes ``None`` and gets a fresh one.
    """
    if counter is None:
        counter = [0]
    if depth > MAX_WALK_DEPTH:
        log.warning(
            "cas walk: depth %d exceeds MAX_WALK_DEPTH=%d at %s — "
            "refusing to recurse further (symlink loop?)",
            depth, MAX_WALK_DEPTH, root,
        )
        return
    try:
        entries = backend.list_dir(root)
    except OSError as exc:
        log.warning("cas walk: list_dir(%s) failed: %s", root, exc)
        return
    for it in entries:
        if counter[0] >= MAX_WALK_ENTRIES:
            log.warning(
                "cas walk: reached MAX_WALK_ENTRIES=%d — aborting",
                MAX_WALK_ENTRIES,
            )
            return
        counter[0] += 1
        name = getattr(it, "name", "") or ""
        if not name or name in (".", ".."):
            continue
        try:
            full = backend.join(root, name)
        except Exception:
            continue
        if bool(getattr(it, "is_dir", False)):
            yield from _walk_files(
                backend, full, depth=depth + 1, counter=counter,
            )
        else:
            yield full, int(getattr(it, "size", 0) or 0)


def rebuild(backend, root: str, *, backend_id: str,
            algorithm: str = "sha256",
            db_path=None) -> int:
    """Walk *root* on *backend* and (re)populate the index for that tree.

    Old rows for paths we didn't visit are **not** pruned — rebuilds
    are additive. Call :func:`prune_missing` to clean up after a
    rebuild if you also deleted files.

    Returns the number of rows upserted.
    """
    count = 0
    for path, size in _walk_files(backend, root):
        try:
            raw = backend.checksum(path, algorithm=algorithm)
        except (OSError, NotImplementedError) as exc:
            log.debug("cas: skip %s — checksum failed: %s", path, exc)
            continue
        if not raw:
            continue
        algo, value = _split_prefix(raw)
        # If the backend returned a different algo than requested
        # (e.g. S3 ETag for MD5) we still index it — callers querying
        # by that algo will find it.
        try:
            upsert(db_path, backend_id, path, algo, value, size)
        except ValueError as exc:
            log.warning(
                "cas.rebuild: rejecting %s@%s: %s",
                backend_id, path[:80], exc,
            )
            continue
        count += 1
    return count


def prune_missing(backend, root: str, *, backend_id: str,
                  db_path=None) -> int:
    """Drop rows for *backend_id* paths under *root* that no longer
    exist on the backend. Returns number of rows removed."""
    # Escape wildcards in root so ``/a_b`` isn't pruned as ``/aXb``.
    like_pat = _like_escape(root.rstrip("/")) + "/%"
    with _connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT DISTINCT path FROM cas WHERE backend_id=? AND "
            f"path LIKE ? ESCAPE '{_LIKE_ESCAPE}'",
            (backend_id, like_pat),
        )
        candidate_paths = [r[0] for r in cur.fetchall()]
    removed = 0
    for p in candidate_paths:
        try:
            if not backend.exists(p):
                removed += remove(db_path, backend_id, p)
        except OSError:
            continue
    return removed


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def cas_url(algorithm: str, value: str) -> str:
    """Render an ``ax-cas://<algo>:<hex>`` URL."""
    algo = (algorithm or "sha256").strip().lower()
    val = (value or "").strip().lower()
    if not val:
        raise ValueError("cas_url: value is required")
    return f"{CAS_URL_SCHEME}://{algo}:{val}"


def parse_cas_url(url: str) -> tuple[str, str]:
    """``ax-cas://sha256:abc`` -> ``("sha256", "abc")``."""
    prefix = f"{CAS_URL_SCHEME}://"
    if not url.startswith(prefix):
        raise ValueError(f"not a CAS url: {url!r}")
    payload = url[len(prefix):]
    if ":" not in payload:
        raise ValueError(f"CAS url missing algo: {url!r}")
    algo, _, value = payload.partition(":")
    algo = algo.strip().lower()
    value = value.strip().lower()
    if not algo or not value:
        raise ValueError(f"CAS url malformed: {url!r}")
    return algo, value


def resolve_url(url: str, db_path=None) -> list[CasEntry]:
    """Look up every file matching the CAS URL."""
    algo, value = parse_cas_url(url)
    return find_by_value(db_path, algo, value)


__all__ = [
    "CasEntry",
    "CAS_URL_SCHEME",
    "cas_url",
    "duplicates",
    "find_by_value",
    "list_for_backend",
    "parse_cas_url",
    "prune_missing",
    "rebuild",
    "remove",
    "resolve_url",
    "upsert",
]
