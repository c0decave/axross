"""Time-lapse / "trail" — periodic snapshots of a directory tree.

Forensic / change-tracking move: pick a path, axross periodically
walks it and records ``(name, size, mtime, sha-prefix)`` per file
plus a synthesised "tree hash" for the snapshot. Later, you replay
the timeline and see *what changed when*.

Compared to a real version-control system this is rough and read-only
— there's no rollback, no content storage, only a ledger of
``(timestamp → tree-state)``. The output is good for:

* "did anyone touch /etc/cron.d in the last 24h?"
* "this log directory grew 800 MB overnight — when?"
* "this binary was replaced, when did the mtime jump?"

Storage:

* SQLite database at ``~/.config/axross/trail.db`` by default.
* One row per file per snapshot — bounded by ``MAX_FILES_PER_SNAPSHOT``
  (default 5000) so a runaway tree doesn't fill the disk.
* Metadata only — no file content. The optional ``--with-head-hash``
  pulls the first 32 KiB of each file and stores a SHA-256 prefix; OFF
  by default because it pays N reads against the backend per snapshot.

The snapshot loop runs in a daemon thread; callers
:func:`start_trail` / :func:`stop_trail`. Snapshots are also runnable
on demand via :func:`snapshot_now`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from security.trail_walk_caps import budget_exhausted as _dir_budget_exhausted
from security.trail_walk_caps import compute_dir_budget as _compute_dir_budget

log = logging.getLogger(__name__)


CONFIG_DIR = Path.home() / ".config" / "axross"
DB_FILE = CONFIG_DIR / "trail.db"
_DEFAULT_CONFIG_DIR = CONFIG_DIR
_DEFAULT_DB_FILE = DB_FILE


def _config_dir() -> Path:
    if CONFIG_DIR != _DEFAULT_CONFIG_DIR:
        return CONFIG_DIR
    return Path.home() / ".config" / "axross"


def _db_file() -> Path:
    if DB_FILE != _DEFAULT_DB_FILE:
        return DB_FILE
    return _config_dir() / "trail.db"


DEFAULT_INTERVAL_S = 300.0
MIN_INTERVAL_S = 30.0
MAX_FILES_PER_SNAPSHOT = 5000
HEAD_HASH_BYTES = 32 * 1024


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    backend_label TEXT NOT NULL,
    path TEXT NOT NULL,
    interval_s REAL NOT NULL,
    started_at REAL NOT NULL,
    head_hash INTEGER NOT NULL DEFAULT 0,
    last_snapshot_at REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trail_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    file_count INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    tree_hash TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (trail_id) REFERENCES trails(id)
);

CREATE TABLE IF NOT EXISTS files (
    snapshot_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime REAL NOT NULL,
    sha_prefix TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, path),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_trail_ts
    ON snapshots(trail_id, ts);
"""


def _connect() -> sqlite3.Connection:
    path = _db_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError as exc:
        log.debug("trail: cannot chmod %s: %s", path.parent, exc)
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.executescript(_SCHEMA)
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        log.debug("trail: cannot chmod db: %s", exc)
    return conn


# ---------------------------------------------------------------------------
# Snapshot data
# ---------------------------------------------------------------------------


@dataclass
class Snapshot:
    snapshot_id: int
    trail_name: str
    ts: float
    file_count: int
    total_bytes: int
    tree_hash: str
    truncated: bool = False


@dataclass
class TrailDiff:
    """Diff between two snapshots of the same trail."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)  # mtime / size / hash changed
    unchanged: int = 0

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.modified)

    def summary(self) -> str:
        return (
            f"+{len(self.added)} added, -{len(self.removed)} removed, "
            f"~{len(self.modified)} modified, {self.unchanged} unchanged"
        )


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------


def _walk_collect(
    backend,
    root: str,
    *,
    max_files: int,
    head_hash: bool,
) -> tuple[list[dict], bool]:
    """Walk ``root`` recursively. Return list of file rows + truncated flag.

    Each row: ``{"path", "size", "mtime", "sha_prefix"}``.
    """
    rows: list[dict] = []
    truncated = False
    visited: set[str] = set()
    stack: list[str] = [root]
    # Defense-in-depth: the directory budget is computed by
    # the security/ helper so a regression that drops max(1, ...) here
    # still cannot disable directory bounding — the helper floors at
    # MIN_DIR_BUDGET. budget_exhausted() centralises the comparison.
    max_dirs = _compute_dir_budget(max_files)
    while stack:
        path = stack.pop()
        if path in visited:
            continue
        if _dir_budget_exhausted(visited=len(visited), budget=max_dirs):
            truncated = True
            break
        visited.add(path)
        if len(rows) >= max_files:
            truncated = True
            break
        try:
            entries = backend.list_dir(path)
        except OSError as exc:
            log.debug("trail: list_dir(%s) failed: %s", path, exc)
            continue
        for item in entries:
            if hasattr(backend, "join"):
                full = backend.join(path, item.name)
            else:
                full = f"{path.rstrip('/')}/{item.name}"
            if getattr(item, "is_dir", False):
                stack.append(full)
                continue
            if len(rows) >= max_files:
                truncated = True
                break
            sha = ""
            if head_hash:
                sha = _hash_head(backend, full)
            rows.append(
                {
                    "path": full,
                    "size": int(getattr(item, "size", 0) or 0),
                    "mtime": _to_epoch(getattr(item, "modified", None)),
                    "sha_prefix": sha,
                }
            )
    return rows, truncated


def _hash_head(backend, path: str) -> str:
    """SHA-256 prefix of the first ``HEAD_HASH_BYTES`` bytes of a file.
    Returns empty on failure — never raises out of the trail loop."""
    try:
        h = backend.open_read(path)
    except OSError:
        return ""
    try:
        data = h.read(HEAD_HASH_BYTES)
    except OSError:
        return ""
    finally:
        try:
            h.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("trail: close raised: %s", exc)
    return hashlib.sha256(data).hexdigest()[:16]


def _to_epoch(raw) -> float:
    if raw is None:
        return 0.0
    if hasattr(raw, "timestamp"):
        try:
            return float(raw.timestamp())
        except (OSError, OverflowError, ValueError):
            return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _compute_tree_hash(rows: list[dict]) -> str:
    """A stable hash of the *manifest* of a snapshot — useful for
    "did anything change between this snapshot and the previous one"
    in O(1)."""
    h = hashlib.sha256()
    for r in sorted(rows, key=lambda x: x["path"]):
        # path|size|mtime|sha_prefix newline-terminated.
        h.update(f"{r['path']}|{r['size']}|{r['mtime']:.3f}|{r['sha_prefix']}\n".encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_trails() -> list[dict]:
    """Return every recorded trail with a brief summary."""
    out: list[dict] = []
    with _connect() as conn:
        cur = conn.execute(
            "SELECT name, backend_label, path, interval_s, head_hash, "
            "last_snapshot_at, started_at FROM trails ORDER BY name"
        )
        for row in cur.fetchall():
            out.append(
                {
                    "name": row[0],
                    "backend_label": row[1],
                    "path": row[2],
                    "interval_s": float(row[3]),
                    "head_hash": bool(row[4]),
                    "last_snapshot_at": float(row[5]),
                    "started_at": float(row[6]),
                }
            )
    return out


def snapshot_now(
    backend,
    path: str,
    *,
    name: str = "",
    interval_s: float = DEFAULT_INTERVAL_S,
    head_hash: bool = False,
    max_files: int = MAX_FILES_PER_SNAPSHOT,
) -> Snapshot:
    """Take an immediate snapshot. If a trail with this ``name`` does
    not exist, it is created on-the-fly. ``name`` defaults to
    ``"<backend>:<path>"`` when omitted.
    """
    label = getattr(backend, "name", type(backend).__name__)
    trail_name = name or f"{label}:{path}"
    rows, truncated = _walk_collect(
        backend,
        path,
        max_files=max_files,
        head_hash=head_hash,
    )
    tree_hash = _compute_tree_hash(rows)
    total_bytes = sum(r["size"] for r in rows)
    ts = time.time()
    with _connect() as conn:
        conn.execute("BEGIN")
        # upsert the trail
        cur = conn.execute(
            "SELECT id FROM trails WHERE name = ?",
            (trail_name,),
        )
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO trails (name, backend_label, path, interval_s, "
                "started_at, head_hash, last_snapshot_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (trail_name, label, path, interval_s, ts, 1 if head_hash else 0, ts),
            )
            trail_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            trail_id = row[0]
            conn.execute(
                "UPDATE trails SET last_snapshot_at = ? WHERE id = ?",
                (ts, trail_id),
            )
        # snapshot
        conn.execute(
            "INSERT INTO snapshots (trail_id, ts, file_count, total_bytes, "
            "tree_hash, truncated) VALUES (?, ?, ?, ?, ?, ?)",
            (trail_id, ts, len(rows), total_bytes, tree_hash, 1 if truncated else 0),
        )
        snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        # files
        conn.executemany(
            "INSERT INTO files (snapshot_id, path, size, mtime, sha_prefix) VALUES (?, ?, ?, ?, ?)",
            [(snapshot_id, r["path"], r["size"], r["mtime"], r["sha_prefix"]) for r in rows],
        )
        conn.execute("COMMIT")
    return Snapshot(
        snapshot_id=snapshot_id,
        trail_name=trail_name,
        ts=ts,
        file_count=len(rows),
        total_bytes=total_bytes,
        tree_hash=tree_hash,
        truncated=truncated,
    )


def list_snapshots(trail_name: str, *, limit: int = 100) -> list[Snapshot]:
    out: list[Snapshot] = []
    with _connect() as conn:
        cur = conn.execute(
            "SELECT s.id, t.name, s.ts, s.file_count, s.total_bytes, "
            "       s.tree_hash, s.truncated "
            "FROM snapshots s JOIN trails t ON t.id = s.trail_id "
            "WHERE t.name = ? ORDER BY s.ts DESC LIMIT ?",
            (trail_name, limit),
        )
        for row in cur.fetchall():
            out.append(
                Snapshot(
                    snapshot_id=row[0],
                    trail_name=row[1],
                    ts=float(row[2]),
                    file_count=int(row[3]),
                    total_bytes=int(row[4]),
                    tree_hash=row[5],
                    truncated=bool(row[6]),
                )
            )
    return out


def diff_snapshots(snapshot_a: int, snapshot_b: int) -> TrailDiff:
    """Diff snapshot A → snapshot B (B is the newer / target).

    Files present in both but with a different size, mtime, or
    head-hash count as ``modified``. Files only in A are ``removed``;
    only in B are ``added``.
    """
    diff = TrailDiff()
    with _connect() as conn:
        cur = conn.execute(
            "SELECT path, size, mtime, sha_prefix FROM files WHERE snapshot_id = ?",
            (snapshot_a,),
        )
        a = {row[0]: (int(row[1]), float(row[2]), row[3]) for row in cur.fetchall()}
        cur = conn.execute(
            "SELECT path, size, mtime, sha_prefix FROM files WHERE snapshot_id = ?",
            (snapshot_b,),
        )
        b = {row[0]: (int(row[1]), float(row[2]), row[3]) for row in cur.fetchall()}

    a_keys = set(a.keys())
    b_keys = set(b.keys())
    diff.added = sorted(b_keys - a_keys)
    diff.removed = sorted(a_keys - b_keys)
    for path in sorted(a_keys & b_keys):
        if a[path] == b[path]:
            diff.unchanged += 1
        else:
            diff.modified.append(path)
    return diff


def render_timeline(trail_name: str, *, limit: int = 30) -> str:
    """One-line-per-snapshot timeline render."""
    snaps = list_snapshots(trail_name, limit=limit)
    if not snaps:
        return f"trail {trail_name!r}: no snapshots."
    lines = [f"trail {trail_name}:"]
    for s in snaps:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.ts))
        marker = "✂" if s.truncated else "·"
        lines.append(
            f"  {marker} #{s.snapshot_id:<5} {when}  "
            f"files={s.file_count:<6} bytes={s.total_bytes:<12} "
            f"tree={s.tree_hash[:12]}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Background trail manager
# ---------------------------------------------------------------------------


class TrailRunner:
    """One-shot scheduler — fires snapshots on a wall-clock interval."""

    def __init__(
        self,
        backend,
        path: str,
        *,
        name: str = "",
        interval_s: float = DEFAULT_INTERVAL_S,
        head_hash: bool = False,
        max_files: int = MAX_FILES_PER_SNAPSHOT,
        on_snapshot: Callable[[Snapshot], None] | None = None,
    ) -> None:
        self.backend = backend
        self.path = path
        self.name = name or f"{getattr(backend, 'name', type(backend).__name__)}:{path}"
        self.interval_s = max(MIN_INTERVAL_S, float(interval_s))
        self.head_hash = head_hash
        self.max_files = max_files
        self.on_snapshot = on_snapshot
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"axross-trail-{self.name}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        # Take an immediate snapshot so the trail has a t=0 anchor.
        self._take_one()
        while not self._stop.wait(self.interval_s):
            self._take_one()

    def _take_one(self) -> None:
        try:
            snap = snapshot_now(
                self.backend,
                self.path,
                name=self.name,
                interval_s=self.interval_s,
                head_hash=self.head_hash,
                max_files=self.max_files,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("trail %s: snapshot failed: %s", self.name, exc)
            return
        if self.on_snapshot is not None:
            try:
                self.on_snapshot(snap)
            except Exception as exc:  # noqa: BLE001
                log.warning("trail %s: on_snapshot raised: %s", self.name, exc)


_RUNNERS: dict[str, TrailRunner] = {}
_RUNNERS_LOCK = threading.Lock()


def start_trail(
    backend,
    path: str,
    *,
    name: str = "",
    interval_s: float = DEFAULT_INTERVAL_S,
    head_hash: bool = False,
    max_files: int = MAX_FILES_PER_SNAPSHOT,
    on_snapshot: Callable[[Snapshot], None] | None = None,
) -> str:
    """Start a background trail. Returns its name."""
    runner = TrailRunner(
        backend,
        path,
        name=name,
        interval_s=interval_s,
        head_hash=head_hash,
        max_files=max_files,
        on_snapshot=on_snapshot,
    )
    with _RUNNERS_LOCK:
        existing = _RUNNERS.get(runner.name)
        if existing is not None:
            existing.stop()
        _RUNNERS[runner.name] = runner
    runner.start()
    return runner.name


def stop_trail(name: str) -> bool:
    with _RUNNERS_LOCK:
        runner = _RUNNERS.pop(name, None)
    if runner is None:
        return False
    runner.stop()
    return True


def stop_all_trails() -> int:
    with _RUNNERS_LOCK:
        runners = list(_RUNNERS.values())
        _RUNNERS.clear()
    for r in runners:
        r.stop()
    return len(runners)


def export_trail_jsonl(trail_name: str, dst_path: str | os.PathLike[str]) -> int:
    """Dump every snapshot of a trail to JSONL. Useful for archival /
    diff-ing outside axross. Returns the row count written."""
    snaps = list_snapshots(trail_name, limit=10_000_000)
    p = Path(dst_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        raise OSError(f"trail export refuses symlinked destination: {p}")
    written = 0
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{p.name}.",
        suffix=".tmp",
        dir=str(p.parent),
    )
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            log.debug("trail export: cannot chmod tmpfile: %s", exc)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for snap in snaps:
                fh.write(
                    json.dumps(
                        {
                            "snapshot_id": snap.snapshot_id,
                            "trail_name": snap.trail_name,
                            "ts": snap.ts,
                            "file_count": snap.file_count,
                            "total_bytes": snap.total_bytes,
                            "tree_hash": snap.tree_hash,
                            "truncated": snap.truncated,
                        }
                    )
                    + "\n"
                )
                written += 1
        os.replace(tmp_path, p)
        try:
            os.chmod(p, 0o600)
        except OSError as exc:
            log.debug("trail export: cannot chmod %s: %s", p, exc)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return written


__all__ = [
    "DEFAULT_INTERVAL_S",
    "MAX_FILES_PER_SNAPSHOT",
    "Snapshot",
    "TrailDiff",
    "TrailRunner",
    "diff_snapshots",
    "export_trail_jsonl",
    "list_snapshots",
    "list_trails",
    "render_timeline",
    "snapshot_now",
    "start_trail",
    "stop_all_trails",
    "stop_trail",
]
