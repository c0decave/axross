"""Offline metadata index — search files across backends without hitting the network.

The index is a SQLite database populated on demand by
:func:`index_dir`. Once a directory has been browsed, its contents
remain searchable even when the backend is offline.

Distinct from :mod:`core.cas` on purpose:
* cas  indexes *content hashes* (expensive to compute).
* this indexes *metadata* (free with every list_dir).

They share the same pattern (client-side SQLite, URL-free,
per-backend id) but are orthogonal — a user can enable one and not
the other.

Query surface:

    search("report")                     -> substring match on name
    search_by_ext("pdf")                 -> extension match
    search_by_size(min=1000, max=None)   -> size range
    search_by_mtime(since=dt, until=dt)  -> mtime window
    search_all(...)                      -> combine any subset

Everything returns a list of :class:`MetaEntry` sorted newest-first.
"""
from __future__ import annotations

import logging
import os
import posixpath
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("core.metadata_index")

_DEFAULT_DB = Path(
    os.environ.get("AXROSS_METADATA_DB")
    or Path.home() / ".local" / "share" / "axross" / "metadata.sqlite"
)

# See core/cas.py: hostile backends can't drive infinite recursion or
# million-entry explosions.
MAX_WALK_DEPTH = 50
MAX_WALK_ENTRIES = 1_000_000


@dataclass(frozen=True)
class MetaEntry:
    """One indexed item."""

    backend_id: str
    path: str
    name: str
    size: int
    is_dir: bool
    extension: str
    modified: datetime | None
    indexed_at: datetime


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    backend_id TEXT NOT NULL,
    path       TEXT NOT NULL,
    name       TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    is_dir     INTEGER NOT NULL DEFAULT 0,
    extension  TEXT NOT NULL DEFAULT '',
    modified   TEXT,
    indexed_at TEXT NOT NULL,
    PRIMARY KEY (backend_id, path)
);
CREATE INDEX IF NOT EXISTS meta_by_name  ON metadata(name);
CREATE INDEX IF NOT EXISTS meta_by_ext   ON metadata(extension);
CREATE INDEX IF NOT EXISTS meta_by_size  ON metadata(size);
CREATE INDEX IF NOT EXISTS meta_by_mtime ON metadata(modified);
"""

_lock = threading.Lock()

# NOTE: this lock only coordinates threads inside a single process.
# If you fork subprocesses that share the same DB file, prefer
# per-process connections and rely on SQLite's own locking (busy
# retries via ``PRAGMA busy_timeout`` or the default 5s lock timeout)
# instead of expecting this lock to serialise across processes.


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
# Small helpers
# ---------------------------------------------------------------------------

def _extension(name: str) -> str:
    if not name or name.startswith(".") and name.count(".") == 1:
        return ""
    _, dot, ext = name.rpartition(".")
    return ext.lower() if dot else ""


def _row_to_entry(row) -> MetaEntry:
    backend_id, path, name, size, is_dir, ext, modified, indexed_at = row
    try:
        mod = datetime.fromisoformat(modified) if modified else None
    except ValueError:
        mod = None
    try:
        ixd = datetime.fromisoformat(indexed_at)
    except ValueError:
        ixd = datetime.now()
    return MetaEntry(
        backend_id=backend_id, path=path, name=name,
        size=int(size), is_dir=bool(is_dir),
        extension=ext or "", modified=mod, indexed_at=ixd,
    )


# ---------------------------------------------------------------------------
# Index write side
# ---------------------------------------------------------------------------

def upsert(db_path, backend_id: str, path: str, *,
           name: str, size: int, is_dir: bool,
           modified: datetime | None = None) -> None:
    """Insert or replace a single metadata row.

    Rejects attacker-controlled inputs that would pollute the index:
    NUL bytes, bidi override chars, absurdly long strings. See
    :mod:`core.remote_name`.
    """
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES, validate_remote_name,
    )
    validate_remote_name(
        path, max_bytes=MAX_REMOTE_PATH_BYTES, allow_separators=True,
    )
    validate_remote_name(name, allow_separators=False) if name else None
    validate_remote_name(backend_id, max_bytes=256)
    when = datetime.now().isoformat(timespec="seconds")
    mod_iso = modified.isoformat(timespec="seconds") if modified else None
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO metadata(backend_id, path, name, size, is_dir, "
            "extension, modified, indexed_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(backend_id, path) DO UPDATE SET "
            "name=excluded.name, size=excluded.size, "
            "is_dir=excluded.is_dir, extension=excluded.extension, "
            "modified=excluded.modified, indexed_at=excluded.indexed_at",
            (backend_id, path, name, int(size), 1 if is_dir else 0,
             _extension(name), mod_iso, when),
        )


def remove(db_path, backend_id: str, path: str) -> int:
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM metadata WHERE backend_id=? AND path=?",
            (backend_id, path),
        )
        return cur.rowcount


def _index_item(db_path, backend_id: str, path: str, item) -> None:
    name = getattr(item, "name", "") or posixpath.basename(path)
    try:
        upsert(
            db_path, backend_id, path,
            name=name,
            size=int(getattr(item, "size", 0) or 0),
            is_dir=bool(getattr(item, "is_dir", False)),
            modified=getattr(item, "modified", None),
        )
    except ValueError as exc:
        # Backend returned a name/path we refuse to index (NUL byte,
        # traversal, bidi override, too long). Skip this entry and
        # log — don't let one hostile row abort the whole walk.
        log.warning(
            "metadata_index: rejecting %s@%s: %s",
            backend_id, path[:80], exc,
        )


def index_dir(backend, root: str, *, backend_id: str,
              recursive: bool = True, db_path=None,
              _depth: int = 0, _counter: list | None = None) -> int:
    """Walk *root* on *backend* and index every entry we find.

    Capped at :data:`MAX_WALK_DEPTH` and :data:`MAX_WALK_ENTRIES` to
    defeat hostile backends that return fake symlink loops or
    million-entry directories.

    Returns the number of rows touched. Missing permissions or
    list_dir failures on sub-paths are logged and skipped; we don't
    let one inaccessible folder abort the whole walk.
    """
    if _counter is None:
        _counter = [0]
    if _depth > MAX_WALK_DEPTH:
        log.warning(
            "metadata_index: depth %d exceeds MAX_WALK_DEPTH=%d at %s — "
            "refusing to recurse further (symlink loop?)",
            _depth, MAX_WALK_DEPTH, root,
        )
        return 0
    count = 0
    try:
        entries = backend.list_dir(root)
    except OSError as exc:
        log.warning("metadata_index: list_dir(%s) failed: %s", root, exc)
        return 0
    for it in entries:
        if _counter[0] >= MAX_WALK_ENTRIES:
            log.warning(
                "metadata_index: reached MAX_WALK_ENTRIES=%d — aborting",
                MAX_WALK_ENTRIES,
            )
            return count
        _counter[0] += 1
        name = getattr(it, "name", "") or ""
        if not name or name in (".", ".."):
            continue
        try:
            full = backend.join(root, name)
        except Exception as exc:
            log.warning("metadata_index: join(%s, %s) failed: %s",
                        root, name, exc)
            continue
        _index_item(db_path, backend_id, full, it)
        count += 1
        if recursive and bool(getattr(it, "is_dir", False)):
            count += index_dir(
                backend, full,
                backend_id=backend_id, recursive=True, db_path=db_path,
                _depth=_depth + 1, _counter=_counter,
            )
    return count


def prune_missing(backend, root: str, *, backend_id: str,
                  db_path=None) -> int:
    """Drop rows whose path no longer exists on the backend."""
    # Escape wildcards in root so a path like ``/a_b/`` doesn't match
    # ``/aXb/`` on prune (SQLite ``_`` wildcard).
    like_pat = _like_escape(root.rstrip("/")) + "/%"
    with _connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT path FROM metadata WHERE backend_id=? AND "
            f"path LIKE ? ESCAPE '{_LIKE_ESCAPE}'",
            (backend_id, like_pat),
        )
        paths = [r[0] for r in cur.fetchall()]
    removed = 0
    for p in paths:
        try:
            if not backend.exists(p):
                removed += remove(db_path, backend_id, p)
        except OSError:
            continue
    return removed


# ---------------------------------------------------------------------------
# Query side
# ---------------------------------------------------------------------------

_ORDER = " ORDER BY modified DESC, indexed_at DESC"


# SQLite LIKE uses ``%`` (any) and ``_`` (one) as wildcards. When we
# build a pattern from user input, we need to ESCAPE those characters
# or a malicious filename like ``a%b`` would match unrelated names at
# query time. ``!`` as escape so the pattern stays readable; any
# printable char works as long as the query declares it.
_LIKE_ESCAPE = "!"


def _like_escape(s: str) -> str:
    return (
        s.replace(_LIKE_ESCAPE, _LIKE_ESCAPE + _LIKE_ESCAPE)
         .replace("%", _LIKE_ESCAPE + "%")
         .replace("_", _LIKE_ESCAPE + "_")
    )


def _query(db_path, where_sql: str, params: tuple) -> list[MetaEntry]:
    # SAFETY: ``where_sql`` is never user-supplied — every call site in
    # this module hand-writes the clause with ``?`` placeholders and
    # supplies the user-controlled values via *params*. Static scanners
    # flag the string concatenation; the concat is of trusted literals.
    # Do NOT add a public wrapper that forwards untrusted strings into
    # *where_sql* or this guarantee breaks.
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT backend_id, path, name, size, is_dir, extension, "
            "modified, indexed_at FROM metadata WHERE " + where_sql + _ORDER,
            params,
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


def search(needle: str, *, db_path=None) -> list[MetaEntry]:
    """Case-insensitive substring match on ``name``.

    ``%`` and ``_`` in the needle are escaped so a user literally
    searching for ``"100%"`` matches the literal 3-char string,
    not "1" followed by 2 anything chars.
    """
    pat = f"%{_like_escape((needle or '').lower())}%"
    return _query(
        db_path,
        f"LOWER(name) LIKE ? ESCAPE '{_LIKE_ESCAPE}'",
        (pat,),
    )


def search_by_ext(ext: str, *, db_path=None) -> list[MetaEntry]:
    """Match by extension (without the dot)."""
    return _query(
        db_path,
        "extension = ?",
        ((ext or "").strip().lower().lstrip("."),),
    )


def search_by_size(*, min_size: int = 0,
                   max_size: int | None = None,
                   db_path=None) -> list[MetaEntry]:
    if max_size is None:
        return _query(db_path, "size >= ?", (int(min_size),))
    return _query(
        db_path,
        "size >= ? AND size <= ?",
        (int(min_size), int(max_size)),
    )


def search_by_mtime(*, since: datetime | None = None,
                    until: datetime | None = None,
                    db_path=None) -> list[MetaEntry]:
    clauses = ["modified IS NOT NULL"]
    params: list = []
    if since is not None:
        clauses.append("modified >= ?")
        params.append(since.isoformat(timespec="seconds"))
    if until is not None:
        clauses.append("modified <= ?")
        params.append(until.isoformat(timespec="seconds"))
    return _query(db_path, " AND ".join(clauses), tuple(params))


def search_all(*, needle: str | None = None,
               ext: str | None = None,
               min_size: int = 0,
               max_size: int | None = None,
               since: datetime | None = None,
               until: datetime | None = None,
               backend_id: str | None = None,
               db_path=None) -> list[MetaEntry]:
    """Combine any subset of the filters. Empty clauses are skipped."""
    clauses: list[str] = []
    params: list = []
    if needle:
        clauses.append(f"LOWER(name) LIKE ? ESCAPE '{_LIKE_ESCAPE}'")
        params.append(f"%{_like_escape(needle.lower())}%")
    if ext:
        clauses.append("extension = ?")
        params.append(ext.strip().lower().lstrip("."))
    if min_size > 0:
        clauses.append("size >= ?")
        params.append(int(min_size))
    if max_size is not None:
        clauses.append("size <= ?")
        params.append(int(max_size))
    if since is not None:
        clauses.append("modified IS NOT NULL AND modified >= ?")
        params.append(since.isoformat(timespec="seconds"))
    if until is not None:
        clauses.append("modified IS NOT NULL AND modified <= ?")
        params.append(until.isoformat(timespec="seconds"))
    if backend_id:
        clauses.append("backend_id = ?")
        params.append(backend_id)
    where = " AND ".join(clauses) if clauses else "1=1"
    return _query(db_path, where, tuple(params))


def row_count(db_path=None) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM metadata").fetchone()
        return int(row[0]) if row else 0


__all__ = [
    "MetaEntry",
    "index_dir",
    "prune_missing",
    "remove",
    "row_count",
    "search",
    "search_all",
    "search_by_ext",
    "search_by_mtime",
    "search_by_size",
    "upsert",
]
