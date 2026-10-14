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

from core.trash import TRASH_DIRNAME

log = logging.getLogger(__name__)

# Default location follows XDG. Callers can override by passing their
# own path to every function that takes ``db_path``.
_DEFAULT_DB = Path(
    os.environ.get("AXROSS_CAS_DB") or Path.home() / ".local" / "share" / "axross" / "cas.sqlite"
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
    mtime      REAL,
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
    """Indexes written before 0.7.5 have no ``mtime`` column; their rows
    keep NULL, which means "hash again" on the next rebuild."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(cas)")}
    if "mtime" not in cols:
        conn.execute("ALTER TABLE cas ADD COLUMN mtime REAL")


# ---------------------------------------------------------------------------
# Low-level index ops
# ---------------------------------------------------------------------------

_UPSERT_SQL = (
    "INSERT INTO cas(backend_id, path, algorithm, value, size, indexed_at, mtime) "
    "VALUES(?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(backend_id, path, algorithm) DO UPDATE SET "
    "value=excluded.value, size=excluded.size, "
    "indexed_at=excluded.indexed_at, mtime=excluded.mtime"
)


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
        conn.execute(_UPSERT_SQL, row)


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
    """Groups of 2+ files that share a checksum. Empty list if none.

    One query for all groups (it used to be one connection and one query
    per group); groups come in value order, rows within a group in
    insertion order, as before."""
    algo = algorithm.lower()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "SELECT backend_id, path, algorithm, value, size, indexed_at FROM cas "
            "WHERE algorithm=? AND value IN ("
            "SELECT value FROM cas WHERE algorithm=? GROUP BY value HAVING COUNT(*) >= 2"
            ") ORDER BY value, rowid",
            (algo, algo),
        )
        rows = cur.fetchall()
    groups: list[list[CasEntry]] = []
    for row in rows:
        entry = _row_to_entry(row)
        if groups and groups[-1][0].value == entry.value:
            groups[-1].append(entry)
        else:
            groups.append([entry])
    return groups


def _row_to_entry(row) -> CasEntry:
    backend_id, path, algorithm, value, size, indexed_at = row
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
    )


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

    Returns the number of files that are indexed and current.
    """
    algo = algorithm.lower()
    known = {} if rehash else _known_rows(db_path, backend_id, algo)
    writer = _BatchWriter(db_path)
    count = 0
    scanned = 0
    try:
        for path, size, mtime in _walk_files(backend, root, cancel=cancel):
            if cancel is not None and cancel():
                break
            scanned += 1
            if mtime is not None and known.get(path) == (size, mtime):
                count += 1
            elif _index_one(backend, backend_id, path, size, mtime, algo, writer):
                count += 1
            if progress is not None:
                try:
                    progress(scanned, count, path)
                except Exception as exc:  # noqa: BLE001 — a UI callback must not kill the run
                    log.debug("cas.rebuild: progress callback failed: %s", exc)
    finally:
        writer.flush()
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
    "CasEntry",
    "DeleteOutcome",
    "CAS_URL_SCHEME",
    "cas_url",
    "delete_duplicates",
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
