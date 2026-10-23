"""Offline metadata index — search files across backends without hitting the network.

The index is a SQLite database populated on demand by
:func:`index_dir` (Edit > Index Active Folder… in the UI; browsing a
folder does not index it). Once a directory has been indexed, its
contents remain searchable even when the backend is offline. The file
is :func:`default_db_path`.

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
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.secure_storage import data_file_path

log = logging.getLogger(__name__)

# $AXROSS_METADATA_DB, else $XDG_DATA_HOME/axross (an index already at the old
# ~/.local/share/axross stays in use), else ~/.local/share/axross.
_DEFAULT_DB = data_file_path("metadata.sqlite", "AXROSS_METADATA_DB")

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
    # The index lists backend ids (user@host) and full remote paths of
    # everything indexed: private to the user, like core.cas's index.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        try:
            os.chmod(path, 0o600)  # written world-readable by older versions
        except OSError as exc:
            log.debug("metadata_index: cannot chmod %s: %s", path, exc)
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
        backend_id=backend_id,
        path=path,
        name=name,
        size=int(size),
        is_dir=bool(is_dir),
        extension=ext or "",
        modified=mod,
        indexed_at=ixd,
    )


# ---------------------------------------------------------------------------
# Index write side
# ---------------------------------------------------------------------------


_UPSERT_SQL = (
    "INSERT INTO metadata(backend_id, path, name, size, is_dir, "
    "extension, modified, indexed_at) "
    "VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(backend_id, path) DO UPDATE SET "
    "name=excluded.name, size=excluded.size, "
    "is_dir=excluded.is_dir, extension=excluded.extension, "
    "modified=excluded.modified, indexed_at=excluded.indexed_at"
)


def upsert(
    db_path,
    backend_id: str,
    path: str,
    *,
    name: str,
    size: int,
    is_dir: bool,
    modified: datetime | None = None,
) -> None:
    """Insert or replace a single metadata row.

    Rejects attacker-controlled inputs that would pollute the index:
    NUL bytes, bidi override chars, absurdly long strings. See
    :mod:`core.remote_name`.
    """
    row = _checked_row(backend_id, path, name=name, size=size, is_dir=is_dir, modified=modified)
    with _connect(db_path) as conn:
        conn.execute(_UPSERT_SQL, row)


def _checked_row(
    backend_id: str,
    path: str,
    *,
    name: str,
    size: int,
    is_dir: bool,
    modified: datetime | None = None,
    literal_backslash: bool = False,
) -> tuple:
    """Validate one metadata row; raises ValueError for anything refused.
    *literal_backslash*: the backend treats a backslash in a name as an
    ordinary character (core.path_policy.BackendPathPolicy)."""
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES,
        validate_remote_name,
    )

    validate_remote_name(
        path,
        max_bytes=MAX_REMOTE_PATH_BYTES,
        allow_separators=True,
    )
    if name:
        validate_remote_name(name, allow_separators=False, allow_backslash=literal_backslash)
    validate_remote_name(backend_id, max_bytes=256)
    when = datetime.now().isoformat(timespec="seconds")
    mod_iso = modified.isoformat(timespec="seconds") if modified else None
    return (
        backend_id,
        path,
        name,
        int(size),
        1 if is_dir else 0,
        _extension(name),
        mod_iso,
        when,
    )


class _BatchWriter:
    """Rows of one walk, written in one transaction per batch: a connection,
    schema script and commit per entry was most of the indexing time. The
    walk flushes in ``finally``, so an interrupted walk loses nothing."""

    BATCH = 500

    def __init__(self, db_path) -> None:
        self._db_path = db_path
        self._rows: list[tuple] = []

    def add(self, row: tuple) -> None:
        self._rows.append(row)
        if len(self._rows) >= self.BATCH:
            self.flush()

    def flush(self) -> None:
        if not self._rows:
            return
        rows, self._rows = self._rows, []
        with _connect(self._db_path) as conn:
            conn.executemany(_UPSERT_SQL, rows)


def remove(db_path, backend_id: str, path: str) -> int:
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM metadata WHERE backend_id=? AND path=?",
            (backend_id, path),
        )
        return cur.rowcount


def _index_item(writer: _BatchWriter, backend_id: str, path: str, item,
                literal_backslash: bool = False) -> None:
    name = getattr(item, "name", "") or posixpath.basename(path)
    try:
        writer.add(
            _checked_row(
                backend_id,
                path,
                name=name,
                size=int(getattr(item, "size", 0) or 0),
                is_dir=bool(getattr(item, "is_dir", False)),
                modified=getattr(item, "modified", None),
                literal_backslash=literal_backslash,
            )
        )
    except ValueError as exc:
        # Backend returned a name/path we refuse to index (NUL byte,
        # traversal, bidi override, too long). Skip this entry and
        # log — don't let one hostile row abort the whole walk.
        log.warning(
            "metadata_index: rejecting %s@%s: %s",
            backend_id,
            path[:80],
            exc,
        )


def index_dir(
    backend,
    root: str,
    *,
    backend_id: str,
    recursive: bool = True,
    db_path=None,
    cancel=None,
    progress=None,
    _depth: int = 0,
    _counter: list | None = None,
    _done: list | None = None,
    _writer: _BatchWriter | None = None,
    _walk: dict | None = None,
) -> int:
    """Walk *root* on *backend* and index every entry we find.

    *cancel* (zero-argument callable) is polled between entries; once it
    returns true the walk stops and what was indexed so far is kept.
    *progress* is called as ``progress(scanned, indexed, path)`` after
    each entry; an exception in it never aborts the walk.

    Capped at :data:`MAX_WALK_DEPTH` and :data:`MAX_WALK_ENTRIES` to
    defeat hostile backends that return fake symlink loops or
    million-entry directories.

    Returns the number of rows touched. Missing permissions or
    list_dir failures on sub-paths are logged and skipped; we don't
    let one inaccessible folder abort the whole walk.
    """
    if _writer is None:
        writer = _BatchWriter(db_path)
        try:
            return index_dir(
                backend,
                root,
                backend_id=backend_id,
                recursive=recursive,
                db_path=db_path,
                cancel=cancel,
                progress=progress,
                _depth=_depth,
                _counter=_counter,
                _done=_done,
                _writer=writer,
                _walk=_walk,
            )
        finally:
            writer.flush()
    if _counter is None:
        _counter = [0]
    if _done is None:
        _done = [0]
    if cancel is not None and cancel():
        if _walk is not None:
            _walk["complete"] = False
        return 0
    if _depth > MAX_WALK_DEPTH:
        log.warning(
            "metadata_index: depth %d exceeds MAX_WALK_DEPTH=%d at %s — "
            "refusing to recurse further (symlink loop?)",
            _depth,
            MAX_WALK_DEPTH,
            root,
        )
        if _walk is not None:
            _walk["skipped"].append(root)
        return 0
    from core.path_policy import BackendPathPolicy

    # A backslash is an ordinary name character only where the backend
    # says so (LocalFS on POSIX); elsewhere a server may split on it.
    literal_backslash = BackendPathPolicy.for_backend(backend).literal_backslash
    count = 0
    try:
        entries = backend.list_dir(root)
    except OSError as exc:
        log.warning("metadata_index: list_dir(%s) failed: %s", root, exc)
        if _walk is not None:
            _walk["skipped"].append(root)  # unknown, not gone
        return 0
    for it in entries:
        if cancel is not None and cancel():
            if _walk is not None:
                _walk["complete"] = False
            return count
        if _counter[0] >= MAX_WALK_ENTRIES:
            log.warning(
                "metadata_index: reached MAX_WALK_ENTRIES=%d — aborting",
                MAX_WALK_ENTRIES,
            )
            if _walk is not None:
                _walk["complete"] = False
            return count
        _counter[0] += 1
        name = getattr(it, "name", "") or ""
        if not name or name in (".", ".."):
            continue
        try:
            from core.remote_name import validate_remote_name

            validate_remote_name(name, allow_separators=False, allow_backslash=literal_backslash)
        except ValueError as exc:
            log.warning(
                "metadata_index: skipping unsafe entry name at %s: %s",
                root,
                exc,
            )
            continue
        try:
            from core.path_policy import safe_join

            full = safe_join(backend, root, name)
        except Exception as exc:
            log.warning("metadata_index: join(%s, %s) failed: %s", root, name, exc)
            continue
        _index_item(_writer, backend_id, full, it, literal_backslash=literal_backslash)
        if _walk is not None:
            _walk["seen"].add(hash(full))
        count += 1
        _done[0] += 1
        if progress is not None:
            try:
                progress(_counter[0], _done[0], full)
            except Exception as exc:  # noqa: BLE001 — a UI callback must not kill the walk
                log.debug("metadata_index: progress callback failed: %s", exc)
        if recursive and bool(getattr(it, "is_dir", False)):
            count += index_dir(
                backend,
                full,
                backend_id=backend_id,
                recursive=True,
                db_path=db_path,
                cancel=cancel,
                progress=progress,
                _depth=_depth + 1,
                _counter=_counter,
                _done=_done,
                _writer=_writer,
                _walk=_walk,
            )
    return count


def reindex_dir(
    backend,
    root: str,
    *,
    backend_id: str,
    db_path=None,
    cancel=None,
    progress=None,
) -> tuple[int, int]:
    """Index *root* like :func:`index_dir`, then drop the rows under it
    that the walk did not see: what was deleted since the last index.
    Returns ``(indexed, removed)``.

    Only a complete walk removes anything. A cancelled walk or one that hit
    MAX_WALK_ENTRIES removes nothing, and rows under a folder whose listing
    failed (or that lies below MAX_WALK_DEPTH) stay: unknown, not gone.
    The walk keeps 64-bit hashes of the paths it saw, not the paths (a
    million entries are ~60 MB of hashes, not ~150 MB of strings); a
    collision can only keep a stale row, never drop a live one."""
    walk: dict = {"seen": set(), "skipped": [], "complete": True}
    indexed = index_dir(backend, root, backend_id=backend_id, db_path=db_path, cancel=cancel,
                        progress=progress, _walk=walk)
    if not walk["complete"]:
        return indexed, 0
    return indexed, _drop_unseen(db_path, backend_id, root, walk["seen"], walk["skipped"])


def _subtree_bounds(root: str) -> tuple[str, str]:
    """``[low, high)`` such that every path strictly below *root* sorts in
    it and nothing else does: "/" is 0x2F and "0" the next character, so
    "/data-x" (0x2D) and "/data0" fall outside ["/data/", "/data0")."""
    prefix = root.rstrip("/") + "/"
    return prefix, prefix[:-1] + "0"


def _drop_unseen(db_path, backend_id: str, root: str, seen: set, skipped: list) -> int:
    low, high = _subtree_bounds(root)
    keep = tuple(s.rstrip("/") + "/" for s in skipped)
    kept_exact = set(skipped)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT path FROM metadata WHERE backend_id=? AND path >= ? AND path < ?",
            (backend_id, low, high),
        ).fetchall()
        gone = [(backend_id, p) for (p,) in rows
                if hash(p) not in seen and p not in kept_exact and not p.startswith(keep)]
        conn.executemany("DELETE FROM metadata WHERE backend_id=? AND path=?", gone)
    return len(gone)


def prune_missing(backend, root: str, *, backend_id: str, db_path=None) -> int:
    """Drop rows whose path no longer exists on the backend."""
    # Escape wildcards in root so a path like ``/a_b/`` doesn't match
    # ``/aXb/`` on prune (SQLite ``_`` wildcard).
    like_pat = _like_escape(root.rstrip("/")) + "/%"
    with _connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT path FROM metadata WHERE backend_id=? AND path LIKE ? ESCAPE '{_LIKE_ESCAPE}'",
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


def search_by_size(
    *, min_size: int = 0, max_size: int | None = None, db_path=None
) -> list[MetaEntry]:
    if max_size is None:
        return _query(db_path, "size >= ?", (int(min_size),))
    return _query(
        db_path,
        "size >= ? AND size <= ?",
        (int(min_size), int(max_size)),
    )


def search_by_mtime(
    *, since: datetime | None = None, until: datetime | None = None, db_path=None
) -> list[MetaEntry]:
    clauses = ["modified IS NOT NULL"]
    params: list = []
    if since is not None:
        clauses.append("modified >= ?")
        params.append(since.isoformat(timespec="seconds"))
    if until is not None:
        clauses.append("modified <= ?")
        params.append(until.isoformat(timespec="seconds"))
    return _query(db_path, " AND ".join(clauses), tuple(params))


def search_all(
    *,
    needle: str | None = None,
    ext: str | None = None,
    min_size: int = 0,
    max_size: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    backend_id: str | None = None,
    db_path=None,
) -> list[MetaEntry]:
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


def default_db_path() -> Path:
    """Where the index lives unless a caller passes ``db_path``:
    ``$AXROSS_METADATA_DB``, else ``$XDG_DATA_HOME/axross/metadata.sqlite``,
    else ``~/.local/share/axross/metadata.sqlite`` - an index already at
    that old place stays in use while the new one does not exist
    (:func:`core.secure_storage.data_file_path`; read when this module was
    imported)."""
    return _DEFAULT_DB


def iter_entries(*, db_path=None, batch: int = 2000, cancel=None) -> Iterator[MetaEntry]:
    """Every row of the index, *batch* rows per query in rowid order, so a
    million-row index is never held in memory and no connection (or the
    module lock) stays open between batches. *cancel* (zero-argument
    callable) is polled before each batch."""
    if batch < 1:
        raise ValueError("batch must be at least 1")
    last = 0
    while True:
        if cancel is not None and cancel():
            return
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT rowid, backend_id, path, name, size, is_dir, extension, "
                "modified, indexed_at FROM metadata WHERE rowid > ? ORDER BY rowid LIMIT ?",
                (last, int(batch)),
            ).fetchall()
        if not rows:
            return
        last = rows[-1][0]
        for row in rows:
            yield _row_to_entry(row[1:])


def row_count(db_path=None) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM metadata").fetchone()
        return int(row[0]) if row else 0


__all__ = [
    "MetaEntry",
    "default_db_path",
    "index_dir",
    "iter_entries",
    "prune_missing",
    "reindex_dir",
    "remove",
    "row_count",
    "search",
    "search_all",
    "search_by_ext",
    "search_by_mtime",
    "search_by_size",
    "upsert",
]
