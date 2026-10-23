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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from core.secure_storage import data_file_path
from core.trash import TRASH_DIRNAME

log = logging.getLogger(__name__)

# Default location follows XDG (core.secure_storage.data_file_path). Callers
# can override by passing their own path to every function that takes
# ``db_path``.
_DEFAULT_DB = data_file_path("cas.sqlite", "AXROSS_CAS_DB")

CAS_URL_SCHEME = "ax-cas"


def default_db_path() -> Path:
    """Where the duplicate index lives unless a caller passes ``db_path``:
    ``$AXROSS_CAS_DB``, else ``$XDG_DATA_HOME/axross/cas.sqlite``, else
    ``~/.local/share/axross/cas.sqlite`` - an index already at that old
    place stays in use while the new one does not exist (read when this
    module was imported)."""
    return _DEFAULT_DB


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
    #: Modification time as a timestamp; None when the backend had none or
    #: the row predates stored times.
    mtime: float | None = None
    #: The recorded scan that last indexed (or confirmed) this row; None for
    #: rows written before scans were recorded.
    scan_id: int | None = None


#: ``scan_id`` of the pseudo entry that holds every row no recorded scan
#: owns: rows from before scan history existed, or written by :func:`upsert`.
EARLIER_SCANS = 0

SCAN_RUNNING = "running"
SCAN_COMPLETE = "complete"
SCAN_CANCELLED = "cancelled"
SCAN_FAILED = "failed"
SCAN_EARLIER = "earlier"


@dataclass(frozen=True)
class ScanRecord:
    """One rebuild of the index, as the history shows it."""

    scan_id: int
    backend_id: str
    root: str
    algorithm: str
    started_at: datetime | None
    finished_at: datetime | None
    #: Files the rebuild indexed or confirmed unchanged, counted when it ended.
    files_indexed: int
    status: str
    #: Rows that belong to this scan now (a later scan of the same files
    #: takes them over; trashed copies leave the index).
    files_in_index: int = 0
    #: Duplicate groups that have at least one copy from this scan, now.
    duplicate_groups: int = 0
    error: str = ""


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
    mtime      REAL,
    scan_id    INTEGER,
    PRIMARY KEY (backend_id, path, algorithm)
);
CREATE INDEX IF NOT EXISTS cas_by_value
    ON cas (algorithm, value);
CREATE INDEX IF NOT EXISTS cas_by_backend
    ON cas (backend_id);
CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    backend_id    TEXT NOT NULL,
    root          TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    files_indexed INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL,
    error         TEXT NOT NULL DEFAULT ''
);
"""


_lock = threading.Lock()

# NOTE: serialises threads within one process. Cross-process access
# should rely on SQLite's file locking, not this lock.


@contextmanager
def _connect(db_path: Path | None):
    path = Path(db_path) if db_path else _DEFAULT_DB
    # The index lists backend ids, full remote paths and checksums of
    # everything indexed: private to the user, like trail.py's store.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
    with _lock:
        conn = sqlite3.connect(str(path))
        try:
            conn.executescript(SCHEMA_SQL)
            _migrate(conn)
            yield conn
            conn.commit()
        finally:
            conn.close()


def _migrate(conn) -> None:
    """Bring an index written by an older release up to the current schema.

    Before 0.7.5 there was no ``mtime`` column; such rows keep NULL, which
    means "hash again" on the next rebuild. Before scans were recorded there
    was no ``scan_id`` column; such rows keep NULL and belong to the
    :data:`EARLIER_SCANS` pseudo entry until a rebuild sees them again. The
    ``scans`` table itself comes from :data:`SCHEMA_SQL`."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(cas)")}
    if "mtime" not in cols:
        conn.execute("ALTER TABLE cas ADD COLUMN mtime REAL")
    if "scan_id" not in cols:
        conn.execute("ALTER TABLE cas ADD COLUMN scan_id INTEGER")
    # Created here, not in SCHEMA_SQL: on an old table the column only
    # exists after the ALTER above.
    conn.execute("CREATE INDEX IF NOT EXISTS cas_by_scan ON cas (scan_id)")


# ---------------------------------------------------------------------------
# Low-level index ops
# ---------------------------------------------------------------------------

_UPSERT_SQL = (
    "INSERT INTO cas(backend_id, path, algorithm, value, size, indexed_at, mtime, scan_id) "
    "VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(backend_id, path, algorithm) DO UPDATE SET "
    "value=excluded.value, size=excluded.size, "
    "indexed_at=excluded.indexed_at, mtime=excluded.mtime, "
    "scan_id=COALESCE(excluded.scan_id, cas.scan_id)"
)

# A file a rebuild found unchanged is not hashed again, but it is now
# vouched for by that rebuild: it moves into its scan.
_TOUCH_SQL = "UPDATE cas SET scan_id=? WHERE backend_id=? AND path=? AND algorithm=?"


def _split_prefix(raw: str) -> tuple[str, str]:
    """Checksums from FileBackend come as ``algo:hex``. Split them."""
    if ":" in raw:
        algo, _, value = raw.partition(":")
        return algo.strip().lower(), value.strip().lower()
    return "sha256", raw.strip().lower()


def upsert(
    db_path,
    backend_id: str,
    path: str,
    algorithm: str,
    value: str,
    size: int,
    mtime: float | None = None,
) -> None:
    """Insert or replace a row for this backend+path+algorithm.

    Rejects attacker-controlled inputs that would pollute the index:
    NUL bytes, bidi override chars, absurdly long strings. See
    :mod:`core.remote_name` for the full policy.
    """
    row = _checked_row(backend_id, path, algorithm, value, size, mtime)
    with _connect(db_path) as conn:
        conn.execute(_UPSERT_SQL, (*row, None))


def _checked_row(backend_id, path, algorithm, value, size, mtime) -> tuple:
    """Validate one index row; raises ValueError for anything we refuse."""
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES,
        validate_remote_name,
    )

    validate_remote_name(
        path,
        max_bytes=MAX_REMOTE_PATH_BYTES,
        allow_separators=True,
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
    return (backend_id, path, algorithm.lower(), value.lower(), int(size), when, mtime)


class _BatchWriter:
    """Collects index rows and writes them in one transaction per batch.

    One connection + schema script + commit per file was the slowest part
    of a rebuild. Batches stay small so the lock is held only briefly and
    an interrupted rebuild loses nothing: the owner flushes in ``finally``.
    """

    BATCH = 500

    def __init__(self, db_path, scan: _ScanLog | None = None) -> None:
        self._db_path = db_path
        self._scan = scan
        self._rows: list[tuple] = []
        self._touched: list[tuple] = []

    def add(self, row: tuple) -> None:
        self._rows.append(row)
        self._maybe_flush()

    def touch(self, backend_id: str, path: str, algorithm: str) -> None:
        """Attribute an unchanged, already indexed file to this scan."""
        if self._scan is not None:
            self._touched.append((backend_id, path, algorithm))
            self._maybe_flush()

    def _maybe_flush(self) -> None:
        if len(self._rows) + len(self._touched) >= self.BATCH:
            self.flush()

    def flush(self) -> None:
        if not self._rows and not self._touched:
            return
        rows, self._rows = self._rows, []
        touched, self._touched = self._touched, []
        with _connect(self._db_path) as conn:
            scan_id = self._scan.ensure(conn) if self._scan is not None else None
            conn.executemany(_UPSERT_SQL, [(*row, scan_id) for row in rows])
            conn.executemany(_TOUCH_SQL, [(scan_id, *key) for key in touched])


class _ScanLog:
    """The ``scans`` row of one rebuild.

    The row is written lazily — with the first batch of index rows, or when
    the rebuild ends — so a rebuild never creates the database before its
    walk (an index kept inside the scanned tree must not index itself)."""

    def __init__(self, db_path, backend_id: str, root: str, algorithm: str) -> None:
        self._db_path = db_path
        self._fields = (backend_id, root, algorithm)
        self._started = datetime.now().isoformat(timespec="seconds")
        self.scan_id: int | None = None

    def ensure(self, conn) -> int:
        if self.scan_id is None:
            cur = conn.execute(
                "INSERT INTO scans(backend_id, root, algorithm, started_at, status) "
                "VALUES(?, ?, ?, ?, ?)",
                (*self._fields, self._started, SCAN_RUNNING),
            )
            self.scan_id = int(cur.lastrowid)
        return self.scan_id

    def finish(self, status: str, files: int, error: str = "") -> None:
        with _connect(self._db_path) as conn:
            scan_id = self.ensure(conn)
            conn.execute(
                "UPDATE scans SET finished_at=?, status=?, files_indexed=?, error=? "
                "WHERE scan_id=?",
                (
                    datetime.now().isoformat(timespec="seconds"),
                    status,
                    int(files),
                    error[:500],
                    scan_id,
                ),
            )


def remove(db_path, backend_id: str, path: str) -> int:
    """Drop every row for *path* on *backend_id*. Returns rows removed."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM cas WHERE backend_id=? AND path=?",
            (backend_id, path),
        )
        return cur.rowcount


_ENTRY_COLUMNS = "backend_id, path, algorithm, value, size, indexed_at, mtime, scan_id"


def find_by_value(db_path, algorithm: str, value: str) -> list[CasEntry]:
    """Return every file whose checksum matches."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT {_ENTRY_COLUMNS} FROM cas WHERE algorithm=? AND value=?",
            (algorithm.lower(), value.lower()),
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


def list_for_backend(db_path, backend_id: str) -> list[CasEntry]:
    with _connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT {_ENTRY_COLUMNS} FROM cas WHERE backend_id=? ORDER BY path",
            (backend_id,),
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Which copy survives
# ---------------------------------------------------------------------------


def survivor_key(entry: CasEntry) -> tuple:
    """Sort key of the survivor rule: the copy that sorts first stays.

    Oldest modification time first; a tie goes to the shorter full path,
    then to the alphabetically first path (the backend id only breaks an
    exact tie, so the order is total). A copy without a modification time
    sorts after every dated copy — its age is unknown, so it never wins
    against a copy whose age is known."""
    undated = entry.mtime is None
    return (undated, 0.0 if undated else entry.mtime, len(entry.path), entry.path, entry.backend_id)


def order_by_survivor(group) -> list[CasEntry]:
    """*group* sorted by :func:`survivor_key`: the survivor comes first."""
    return sorted(group, key=survivor_key)


def has_undated(group) -> bool:
    """True when the survivor rule could not use a modification time for
    every copy of *group* (it then falls back to the path rule)."""
    return any(e.mtime is None for e in group)


def _folder_clause(folder: str) -> tuple[str, list]:
    """SQL matching paths strictly inside *folder*, on whole components.

    ``substr`` instead of ``LIKE``: LIKE folds ASCII case and needs its
    wildcards escaped; a prefix comparison does neither. Both separators
    count, so a Windows path matches too."""
    if not folder:
        raise ValueError("folder must be a non-empty path")
    trimmed = folder.rstrip("/\\")
    prefixes = [folder[0]] if not trimmed else [trimmed + "/", trimmed + "\\"]
    clause = " OR ".join("substr(path, 1, ?) = ?" for _ in prefixes)
    params: list = []
    for prefix in prefixes:
        params += [len(prefix), prefix]
    return f"({clause})", params


_UNOWNED_SQL = "(scan_id IS NULL OR scan_id NOT IN (SELECT scan_id FROM scans))"


def duplicates(
    db_path,
    algorithm: str | None = "sha256",
    *,
    scan_id: int | None = None,
    folder: str | None = None,
    backend_id: str | None = None,
) -> list[list[CasEntry]]:
    """Groups of 2+ files that share a checksum. Empty list if none.

    ``algorithm=None`` returns the groups of every algorithm in the index.
    Groups come in ``(algorithm, value)`` order; the rows of a group in
    survivor order (:func:`order_by_survivor`), so the first row is the
    copy that a "keep first" removal keeps.

    Scopes, combinable:

    * *folder* (with an optional *backend_id*) — only copies strictly inside
      that folder count; a group needs two of them.
    * *scan_id* — groups that have at least one copy indexed by that scan,
      shown with all their copies; :data:`EARLIER_SCANS` selects the rows no
      recorded scan owns.

    One query for all groups."""
    where: list[str] = []
    params: list = []
    if algorithm:
        where.append("algorithm=?")
        params.append(algorithm.lower())
    if backend_id:
        where.append("backend_id=?")
        params.append(backend_id)
    if folder is not None:
        clause, folder_params = _folder_clause(folder)
        where.append(clause)
        params += folder_params
    having = "COUNT(*) >= 2"
    if scan_id is not None:
        if int(scan_id) == EARLIER_SCANS:
            having += f" AND SUM({_UNOWNED_SQL}) > 0"
        else:
            having += " AND SUM(scan_id = ?) > 0"
            params.append(int(scan_id))
    sql = (
        f"WITH r AS (SELECT rowid AS rid, {_ENTRY_COLUMNS} FROM cas"
        + (" WHERE " + " AND ".join(where) if where else "")
        + f"), g AS (SELECT algorithm, value FROM r GROUP BY algorithm, value HAVING {having}) "
        + "SELECT "
        + ", ".join(f"r.{c.strip()}" for c in _ENTRY_COLUMNS.split(","))
        + " FROM r JOIN g ON r.algorithm = g.algorithm AND r.value = g.value"
        " ORDER BY r.algorithm, r.value, r.rid"
    )
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    groups: list[list[CasEntry]] = []
    for row in rows:
        entry = _row_to_entry(row)
        head = groups[-1][0] if groups else None
        if head is not None and (head.algorithm, head.value) == (entry.algorithm, entry.value):
            groups[-1].append(entry)
        else:
            groups.append([entry])
    return [order_by_survivor(g) for g in groups]


def _row_to_entry(row) -> CasEntry:
    backend_id, path, algorithm, value, size, indexed_at, *rest = row
    mtime = rest[0] if rest else None
    scan_id = rest[1] if len(rest) > 1 else None
    try:
        when = datetime.fromisoformat(indexed_at)
    except ValueError:
        when = datetime.now()
    return CasEntry(
        backend_id=backend_id,
        path=path,
        algorithm=algorithm,
        value=value,
        size=int(size),
        indexed_at=when,
        mtime=float(mtime) if mtime is not None else None,
        scan_id=int(scan_id) if scan_id is not None else None,
    )


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------


def _parse_when(text) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def list_scans(db_path=None) -> list[ScanRecord]:
    """Every recorded scan, newest first, plus — last — the
    :data:`EARLIER_SCANS` pseudo entry when rows no recorded scan owns
    exist. File and duplicate-group counts are those of the index now."""
    owner = f"CASE WHEN {_UNOWNED_SQL} THEN {EARLIER_SCANS} ELSE scan_id END"
    with _connect(db_path) as conn:
        files = dict(conn.execute(f"SELECT {owner} AS o, COUNT(*) FROM cas GROUP BY o"))
        dupes = dict(
            conn.execute(
                f"SELECT {owner} AS o, COUNT(DISTINCT algorithm || ':' || value) FROM cas "
                "WHERE (algorithm, value) IN (SELECT algorithm, value FROM cas "
                "GROUP BY algorithm, value HAVING COUNT(*) >= 2) GROUP BY o"
            )
        )
        rows = conn.execute(
            "SELECT scan_id, backend_id, root, algorithm, started_at, finished_at, "
            "files_indexed, status, error FROM scans ORDER BY scan_id DESC"
        ).fetchall()
    scans = [
        ScanRecord(
            scan_id=int(sid),
            backend_id=bid,
            root=root,
            algorithm=algo,
            started_at=_parse_when(started),
            finished_at=_parse_when(finished),
            files_indexed=int(count or 0),
            status=status,
            files_in_index=int(files.get(sid, 0)),
            duplicate_groups=int(dupes.get(sid, 0)),
            error=error or "",
        )
        for sid, bid, root, algo, started, finished, count, status, error in rows
    ]
    if files.get(EARLIER_SCANS):
        scans.append(
            ScanRecord(
                scan_id=EARLIER_SCANS,
                backend_id="",
                root="",
                algorithm="",
                started_at=None,
                finished_at=None,
                files_indexed=int(files[EARLIER_SCANS]),
                status=SCAN_EARLIER,
                files_in_index=int(files[EARLIER_SCANS]),
                duplicate_groups=int(dupes.get(EARLIER_SCANS, 0)),
            )
        )
    return scans


def remove_scan(db_path, scan_id: int) -> int:
    """Forget one scan: its rows leave the index and its entry the history.

    Files are never touched. :data:`EARLIER_SCANS` removes the rows no
    recorded scan owns. Returns the number of index rows removed."""
    with _connect(db_path) as conn:
        if int(scan_id) == EARLIER_SCANS:
            return conn.execute(f"DELETE FROM cas WHERE {_UNOWNED_SQL}").rowcount
        removed = conn.execute("DELETE FROM cas WHERE scan_id=?", (int(scan_id),)).rowcount
        conn.execute("DELETE FROM scans WHERE scan_id=?", (int(scan_id),))
        return removed


def clear_index(db_path=None) -> int:
    """Empty the whole index and its scan history; files are never touched.

    Returns the number of index rows removed. A database that does not
    exist is not created."""
    path = Path(db_path) if db_path else _DEFAULT_DB
    if not path.exists():
        return 0
    with _connect(db_path) as conn:
        removed = conn.execute("DELETE FROM cas").rowcount
        conn.execute("DELETE FROM scans")
        return removed


# ---------------------------------------------------------------------------
# Backend walk — optional, builds the index from a live backend
# ---------------------------------------------------------------------------


def _walk_files(
    backend,
    root: str,
    *,
    depth: int = 0,
    counter: list | None = None,
    cancel=None,
):
    """Depth-first walk yielding absolute file paths under *root*.

    Capped at :data:`MAX_WALK_DEPTH` and :data:`MAX_WALK_ENTRIES` —
    hostile backends can't drive an infinite recursion via fake
    symlink loops, and can't explode the SQLite DB with millions of
    entries.

    *counter* is a single-element list passed by reference so the
    recursive calls can share a running total. The top-level caller
    passes ``None`` and gets a fresh one.

    *cancel* is an optional zero-argument callable polled between
    entries; once it returns true the walk ends quietly.
    """
    if counter is None:
        counter = [0]
    if cancel is not None and cancel():
        return
    if depth > MAX_WALK_DEPTH:
        log.warning(
            "cas walk: depth %d exceeds MAX_WALK_DEPTH=%d at %s — "
            "refusing to recurse further (symlink loop?)",
            depth,
            MAX_WALK_DEPTH,
            root,
        )
        return
    try:
        entries = backend.list_dir(root)
    except OSError as exc:
        log.warning("cas walk: list_dir(%s) failed: %s", root, exc)
        return
    for it in entries:
        if cancel is not None and cancel():
            return
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
        # A symlink is not a copy: hashing through it pairs the link with
        # its target as "duplicates", and deleting the target then leaves
        # only a dangling link. The axross trash holds what the user already
        # removed; indexing it would offer trashed files as surviving copies.
        if bool(getattr(it, "is_link", False)) or name == TRASH_DIRNAME:
            continue
        try:
            from core.remote_name import validate_remote_name

            validate_remote_name(name, allow_separators=False)
        except ValueError as exc:
            log.warning(
                "cas walk: skipping unsafe entry name at %s: %s",
                root,
                exc,
            )
            continue
        try:
            from core.path_policy import safe_join

            full = safe_join(backend, root, name)
        except Exception as exc:
            log.warning("cas walk: join(%s, %s) failed: %s", root, name, exc)
            continue
        if bool(getattr(it, "is_dir", False)):
            yield from _walk_files(
                backend,
                full,
                depth=depth + 1,
                counter=counter,
                cancel=cancel,
            )
        else:
            yield full, int(getattr(it, "size", 0) or 0), _mtime_of(it)


def _mtime_of(item) -> float | None:
    """Modification time as a timestamp; None when the backend has none
    (an epoch-0 placeholder counts as none)."""
    modified = getattr(item, "modified", None)
    try:
        stamp = modified.timestamp() if modified is not None else 0.0
    except (OSError, OverflowError, ValueError):
        return None
    return stamp if stamp > 0 else None


def rebuild(
    backend,
    root: str,
    *,
    backend_id: str,
    algorithm: str = "sha256",
    db_path=None,
    cancel=None,
    progress=None,
    rehash: bool = False,
) -> int:
    """Walk *root* on *backend* and (re)populate the index for that tree.

    Old rows for paths we didn't visit are **not** pruned — rebuilds
    are additive. Call :func:`prune_missing` to clean up after a
    rebuild if you also deleted files.

    A file whose size and modification time match its row is not hashed
    again (the rsync / git-index rule); ``rehash=True`` hashes everything.
    The index only *finds* candidates — deleting re-verifies every file
    on the live backend (:func:`delete_duplicates`), so a stale row can
    never cost data.

    *cancel* (zero-argument callable) is polled between files; when it
    returns true the run stops and the rows indexed so far are kept.
    *progress* is called as ``progress(scanned, indexed, path)`` after
    every file; an exception in it never aborts the rebuild.

    Every rebuild is recorded as a scan (see :func:`list_scans`): status
    ``complete``, ``cancelled`` or ``failed`` (the exception still
    propagates), and every row it indexed or found unchanged belongs to it.

    Returns the number of files that are indexed and current.
    """
    algo = algorithm.lower()
    known = {} if rehash else _known_rows(db_path, backend_id, algo)
    scan = _ScanLog(db_path, backend_id, root, algo)
    writer = _BatchWriter(db_path, scan)
    count = 0
    scanned = 0
    status, error = SCAN_FAILED, ""
    try:
        for path, size, mtime in _walk_files(backend, root, cancel=cancel):
            if cancel is not None and cancel():
                break
            scanned += 1
            if mtime is not None and known.get(path) == (size, mtime):
                writer.touch(backend_id, path, algo)
                count += 1
            elif _index_one(backend, backend_id, path, size, mtime, algo, writer):
                count += 1
            if progress is not None:
                try:
                    progress(scanned, count, path)
                except Exception as exc:  # noqa: BLE001 — a UI callback must not kill the run
                    log.debug("cas.rebuild: progress callback failed: %s", exc)
        status = SCAN_CANCELLED if cancel is not None and cancel() else SCAN_COMPLETE
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            writer.flush()
        finally:
            try:
                scan.finish(status, count, error)
            except Exception as exc:  # noqa: BLE001 — the history must not mask the result
                log.warning("cas.rebuild: could not record the scan: %s", exc)
    return count


def _known_rows(db_path, backend_id: str, algorithm: str) -> dict[str, tuple[int, float]]:
    """``path -> (size, mtime)`` of rows that can vouch for an unchanged file.

    Never creates the database: an index kept inside the scanned tree
    must not appear in the walk it is about to index."""
    path = Path(db_path) if db_path else _DEFAULT_DB
    if not path.exists():
        return {}
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT path, size, mtime FROM cas "
            "WHERE backend_id=? AND algorithm=? AND mtime IS NOT NULL",
            (backend_id, algorithm),
        )
        return {row[0]: (int(row[1]), float(row[2])) for row in cur}


def _index_one(
    backend, backend_id: str, path: str, size: int, mtime, algorithm: str, writer
) -> bool:
    """Hash one file and queue its row; ``False`` when it was skipped."""
    try:
        raw = backend.checksum(path, algorithm=algorithm)
    except (OSError, NotImplementedError) as exc:
        log.debug("cas: skip %s — checksum failed: %s", path, exc)
        return False
    if not raw:
        return False
    algo, value = _split_prefix(raw)
    # If the backend returned a different algo than requested
    # (e.g. S3 ETag for MD5) we still index it — callers querying
    # by that algo will find it.
    try:
        writer.add(_checked_row(backend_id, path, algo, value, size, mtime))
    except ValueError as exc:
        log.warning(
            "cas.rebuild: rejecting %s@%s: %s",
            backend_id,
            path[:80],
            exc,
        )
        return False
    return True


def prune_missing(backend, root: str, *, backend_id: str, db_path=None) -> int:
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
# Deleting duplicates — re-verified on the live backend, never on the index
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeleteOutcome:
    """What :func:`delete_duplicates` did, file by file."""

    #: Entries moved to the axross trash.
    removed: list = field(default_factory=list)
    #: ``(entry, reason)`` — left alone because removing it was not proven safe.
    refused: list = field(default_factory=list)
    #: ``(entry, reason)`` — safe to remove, but the backend refused.
    failed: list = field(default_factory=list)


def _in_trash(path: str) -> bool:
    return TRASH_DIRNAME in path.replace("\\", "/").split("/")


def _still_holds(backend, entry: CasEntry) -> bool:
    """True when *entry* is still a regular file with the indexed content."""
    try:
        info = backend.stat(entry.path)
    except OSError:
        return False
    if bool(getattr(info, "is_dir", False)):
        return False
    # Cheap reject before reading the whole file. A size of 0 may mean
    # "unknown" on some backends, so only two known sizes can disagree.
    live_size = int(getattr(info, "size", 0) or 0)
    if live_size and entry.size and live_size != entry.size:
        return False
    try:
        raw = backend.checksum(entry.path, algorithm=entry.algorithm)
    except (OSError, NotImplementedError, ValueError):
        return False
    if not raw:
        return False
    algo, value = _split_prefix(raw)
    return algo == entry.algorithm and value == entry.value


def _reached_through_link(backend, path: str) -> bool:
    """True when a folder on the way to *path* is a symlink.

    For a backend that cannot compare file identity, such a path may be
    another name for a file we are about to remove. Ancestors that cannot
    be stat'ed (an object store's virtual prefixes) cannot be links."""
    current = path
    for _ in range(MAX_WALK_DEPTH + 1):
        try:
            parent = backend.parent(current)
        except Exception:  # noqa: BLE001 — unknown shape: cannot clear it
            return True
        if not parent or parent == current:
            return False
        try:
            if bool(getattr(backend.stat(parent), "is_link", False)):
                return True
        except OSError:
            pass
        current = parent
    return True


def _is_genuine_copy(backends, survivor: CasEntry, removing: list[CasEntry]) -> bool:
    """True when *survivor* is a separate, intact copy of the content.

    Not a copy: a symlink (it dies with its target), a file in the axross
    trash (the user already discarded it), a file that changed or vanished
    since indexing, and another name for one of the files being removed —
    a hardlink, a bind mount, a path through a symlinked folder, or the
    same file reached through another backend (SMB and SFTP to one NAS,
    LocalFS and SFTP to localhost; see :mod:`core.storage_identity`)."""
    from core.storage_identity import may_be_same_file

    backend = backends[survivor.backend_id]
    if _in_trash(survivor.path):
        return False
    try:
        if bool(getattr(backend.stat(survivor.path), "is_link", False)):
            return False
    except OSError:
        return False
    if not _still_holds(backend, survivor):
        return False
    for gone in removing:
        if gone.backend_id != survivor.backend_id and may_be_same_file(
            backends[gone.backend_id], gone.path, backend, survivor.path
        ):
            return False
    same_file = getattr(backend, "same_file", None)
    same_backend = [e for e in removing if e.backend_id == survivor.backend_id]
    if same_file is None:
        if not same_backend:
            return True
        # Either side behind a symlinked folder may be an alias of the other.
        paths = [survivor.path, *(e.path for e in same_backend)]
        return not any(_reached_through_link(backend, p) for p in paths)
    for gone in same_backend:
        try:
            if same_file(gone.path, survivor.path):
                return False
        except OSError:
            return False
    return True


def delete_duplicates(
    candidates,
    groups,
    backends,
    *,
    db_path=None,
    trash_root: str | None = None,
    cancel=None,
    progress=None,
) -> DeleteOutcome:
    """Move *candidates* to the axross trash, but only where that is safe.

    *groups* are the duplicate groups the candidates were chosen from and
    *backends* maps a ``backend_id`` to a connected backend. The index is
    only a claim about the past, so every check runs on the live backend
    right before acting: a candidate must still hold the indexed content,
    and its group must keep at least one genuine copy (see
    :func:`_is_genuine_copy`) that is not itself being removed. A
    candidate whose backend is not connected is refused.

    Removal goes through :func:`core.trash.trash`, so it stays reversible;
    a trash failure is reported, never answered with a permanent delete.
    *cancel* is polled between files, *progress* is called as
    ``progress(handled, removed, path)``.
    """
    from core import trash as T

    removed: list = []
    refused: list = []
    failed: list = []
    keys = {(e.backend_id, e.path, e.algorithm, e.value) for e in candidates}
    handled = 0

    def _key(e: CasEntry):
        return (e.backend_id, e.path, e.algorithm, e.value)

    for group in groups:
        mine = [e for e in group if _key(e) in keys]
        if not mine:
            continue
        if cancel is not None and cancel():
            break
        live: list = []
        for entry in mine:
            backend = backends.get(entry.backend_id)
            if backend is None:
                refused.append((entry, f"backend {entry.backend_id} is not connected"))
            elif not _still_holds(backend, entry):
                refused.append((entry, "changed since indexing — rebuild the index"))
            else:
                live.append(entry)
        if not live:
            continue
        others = [e for e in group if _key(e) not in keys]
        if not any(
            backends.get(s.backend_id) is not None and _is_genuine_copy(backends, s, live)
            for s in others
        ):
            refused.extend((e, "no other verified copy would remain") for e in live)
            continue
        for entry in live:
            if cancel is not None and cancel():
                break
            backend = backends[entry.backend_id]
            try:
                T.trash(backend, entry.path, root=trash_root)
            except OSError as exc:
                failed.append((entry, str(exc)))
            else:
                removed.append(entry)
                try:
                    remove(db_path, entry.backend_id, entry.path)
                except Exception as exc:  # noqa: BLE001 — index drift must not mask success
                    log.warning("cas: index cleanup failed for %s: %s", entry.path, exc)
            handled += 1
            if progress is not None:
                try:
                    progress(handled, len(removed), entry.path)
                except Exception as exc:  # noqa: BLE001 — a UI callback must not kill the run
                    log.debug("cas.delete_duplicates: progress callback failed: %s", exc)

    return DeleteOutcome(removed=removed, refused=refused, failed=failed)


# ---------------------------------------------------------------------------
# Planning a removal — which selected copies go, which copy stays
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeletionPlan:
    """What a delete request resolves to, before the live re-verification."""

    #: Entries that may be removed.
    deletable: list = field(default_factory=list)
    #: Hash values of selected groups that are not duplicates (one copy).
    refused_groups: list = field(default_factory=list)
    #: Copies that would remain across the affected groups.
    survivors: int = 0
    #: The first copy (:func:`order_by_survivor`) of every group whose copies
    #: were ALL selected — kept automatically instead of removed.
    auto_kept: list = field(default_factory=list)


def _entry_key(e: CasEntry) -> tuple:
    return (e.backend_id, e.path, e.algorithm, e.value)


def plan_deletion(selected, groups) -> DeletionPlan:
    """Resolve a selection into a plan that cannot erase content.

    A duplicate group exists because the same bytes live in more than one
    place. When every copy of a group is selected ("select all, delete"),
    the first copy by the survivor rule — the oldest — is kept and only the
    others are planned for removal; a partial selection is taken as it is,
    so the user can keep a newer copy on purpose. Either way at least one
    copy of every group remains, and :func:`delete_duplicates` re-checks on
    the live backend that it is a genuine, intact copy before anything goes.

    A group of one is not a duplicate and is refused; deleting a lone file
    is ordinary deletion and belongs in the file pane.
    """
    selected_keys = {_entry_key(e) for e in selected}
    deletable: list = []
    refused: list = []
    auto_kept: list = []
    survivors = 0

    for group in groups:
        in_group = [e for e in group if _entry_key(e) in selected_keys]
        if not in_group:
            continue
        if len(group) < 2:
            refused.append(group[0].value)
            continue
        if len(in_group) == len(group):
            keep = order_by_survivor(group)[0]
            auto_kept.append(keep)
            in_group = [e for e in in_group if _entry_key(e) != _entry_key(keep)]
        deletable.extend(in_group)
        survivors += len(group) - len(in_group)

    return DeletionPlan(
        deletable=deletable, refused_groups=refused, survivors=survivors, auto_kept=auto_kept
    )


def backend_id_for(backend) -> str:
    """The id the index files a backend's rows under: ``<class>:<name>``,
    or just ``<class>`` when the backend has no display name."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


#: Survivor rules :func:`dedupe` knows.
KEEP_RULES = ("oldest",)


@dataclass(frozen=True)
class DedupeResult:
    """What :func:`dedupe` planned and, unless a dry run, did."""

    dry_run: bool
    #: Duplicate groups considered.
    groups: int
    #: The copy kept in each group (the first by the survivor rule).
    keep: list = field(default_factory=list)
    #: The copies planned for the trash.
    trash: list = field(default_factory=list)
    #: Groups where a copy had no modification time (path rule used).
    undated_groups: int = 0
    #: Real run only — see :class:`DeleteOutcome`.
    removed: list = field(default_factory=list)
    refused: list = field(default_factory=list)
    failed: list = field(default_factory=list)

    def render(self) -> str:
        """A short human-readable summary."""
        head = "Dry run" if self.dry_run else "Dedupe"
        lines = [
            f"{head}: {self.groups} duplicate group(s), keep {len(self.keep)}, "
            f"trash {len(self.trash)}"
        ]
        if self.undated_groups:
            lines.append(
                f"{self.undated_groups} group(s) have copies without a modification "
                "time; those sort after dated copies, then by path."
            )
        if not self.dry_run:
            lines.append(
                f"moved to the axross trash: {len(self.removed)}, kept after "
                f"re-checking: {len(self.refused)}, failed: {len(self.failed)}"
            )
            lines += [f"  kept {e.path}: {why}" for e, why in self.refused[:20]]
            lines += [f"  failed {e.path}: {why}" for e, why in self.failed[:20]]
        else:
            lines += [f"  keep  {e.backend_id} {e.path}" for e in self.keep[:20]]
            lines += [f"  trash {e.backend_id} {e.path}" for e in self.trash[:20]]
        return "\n".join(lines)


def dedupe(
    groups,
    backends,
    *,
    keep: str = "oldest",
    dry_run: bool = True,
    db_path=None,
    trash_root: str | None = None,
    cancel=None,
    progress=None,
) -> DedupeResult:
    """Keep the first copy of every group in *groups*, trash the others.

    *backends* maps a ``backend_id`` to a connected backend (copies on any
    other backend are refused, never guessed). With ``dry_run=True`` (the
    default) nothing is touched and the plan is returned; otherwise the
    planned copies go through :func:`delete_duplicates` — re-verified on
    the live backend, moved to the axross trash, restorable.
    """
    if keep not in KEEP_RULES:
        raise ValueError(f"keep must be one of {KEEP_RULES}, not {keep!r}")
    groups = [order_by_survivor(g) for g in groups if len(g) >= 2]
    plan = plan_deletion([e for g in groups for e in g], groups)
    undated = sum(1 for g in groups if has_undated(g))
    if dry_run:
        return DedupeResult(
            dry_run=True,
            groups=len(groups),
            keep=list(plan.auto_kept),
            trash=list(plan.deletable),
            undated_groups=undated,
        )
    outcome = delete_duplicates(
        plan.deletable,
        groups,
        backends,
        db_path=db_path,
        trash_root=trash_root,
        cancel=cancel,
        progress=progress,
    )
    return DedupeResult(
        dry_run=False,
        groups=len(groups),
        keep=list(plan.auto_kept),
        trash=list(plan.deletable),
        undated_groups=undated,
        removed=outcome.removed,
        refused=outcome.refused,
        failed=outcome.failed,
    )


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
    payload = url[len(prefix) :]
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
    "default_db_path",
    "CasEntry",
    "DedupeResult",
    "DeleteOutcome",
    "DeletionPlan",
    "CAS_URL_SCHEME",
    "EARLIER_SCANS",
    "KEEP_RULES",
    "SCAN_CANCELLED",
    "SCAN_COMPLETE",
    "SCAN_EARLIER",
    "SCAN_FAILED",
    "SCAN_RUNNING",
    "ScanRecord",
    "backend_id_for",
    "cas_url",
    "clear_index",
    "dedupe",
    "delete_duplicates",
    "duplicates",
    "find_by_value",
    "has_undated",
    "list_for_backend",
    "list_scans",
    "order_by_survivor",
    "parse_cas_url",
    "plan_deletion",
    "prune_missing",
    "rebuild",
    "remove",
    "remove_scan",
    "resolve_url",
    "survivor_key",
    "upsert",
]
