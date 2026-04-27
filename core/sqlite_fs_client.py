"""SQLite-as-storage backend.

Maps an entire FileBackend onto a single SQLite database file. Every
file/directory is one row in ``axross_files``::

    CREATE TABLE axross_files (
        path     TEXT PRIMARY KEY,
        parent   TEXT NOT NULL,
        is_dir   INTEGER NOT NULL,
        mode     INTEGER NOT NULL DEFAULT 420,   -- 0o644
        mtime    TEXT,                            -- ISO-8601
        content  BLOB
    );
    CREATE INDEX axross_files_parent ON axross_files(parent);

Use cases:

* A self-contained vault: one file holds an entire directory tree
  (manageable, copyable, encryptable).
* Drop-in storage for the encrypted-overlay flow without exposing a
  filesystem.
* CI artefact bundles where a single ``.sqlite`` is easier to ship
  than a tarball.

The backend is pure-stdlib (``sqlite3``) — no extra dependency.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime
from typing import Iterable

from core.db_fs_base import DbFsBackend

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS axross_files (
    path     TEXT PRIMARY KEY,
    parent   TEXT NOT NULL,
    is_dir   INTEGER NOT NULL,
    mode     INTEGER NOT NULL DEFAULT 420,
    mtime    TEXT,
    content  BLOB
);
CREATE INDEX IF NOT EXISTS axross_files_parent ON axross_files(parent);
"""


class SqliteFsSession(DbFsBackend):
    """SQLite-backed FileBackend. ``url`` is the path to a ``.sqlite``
    file; the file is created on open if it doesn't exist."""

    def __init__(self, url: str = "", **_ignored):
        # Accept ``url`` for profile compatibility (other DB backends
        # use a real URL); for SQLite the relevant bit is just the
        # filesystem path. ``sqlite:///foo.db`` and bare paths both
        # work.
        path = url
        if url.startswith("sqlite:///"):
            path = url[len("sqlite:///"):]
        elif url.startswith("sqlite://"):
            path = url[len("sqlite://"):]
        if not path:
            raise OSError("SQLite backend requires a database file path")
        self._db_path = os.path.abspath(path)
        # check_same_thread=False — Qt slots routinely cross thread
        # boundaries (transfer worker → UI). We protect with our own
        # lock so SQLite itself stays consistent.
        self._conn = sqlite3.connect(
            self._db_path, isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            for stmt in _SCHEMA.strip().split(";"):
                if stmt.strip():
                    self._conn.execute(stmt)
        log.info("SQLite-FS session opened: %s", self._db_path)

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"SQLite: {self._db_path}"

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Query passthrough — run arbitrary SQL (slice 3 of API_GAPS)
    # ------------------------------------------------------------------

    def query(
        self,
        sql: str,
        params: tuple | list | dict = (),
        *,
        max_rows: int = 10_000,
    ) -> list[dict]:
        """Run a parameterised SQL statement and return the result rows
        as a list of dicts (column-name → value). For DDL / DML that
        returns no rows, returns ``[]``.

        ``max_rows`` clips the result to keep a stray ``SELECT * FROM
        big_table`` from filling client memory; ``cursor.fetchmany``
        is the underlying mechanism, so the unread rows stay on the
        server until cursor close.

        Parameterise — never f-string user input into ``sql``::

            rows = sess.query(
                "SELECT * FROM users WHERE id = ?", (user_id,),
            )
        """
        cur = self._conn.execute(sql, params)
        try:
            if cur.description is None:
                # Statement returned no rows (INSERT/UPDATE/DELETE/DDL).
                return []
            cols = [c[0] for c in cur.description]
            out: list[dict] = []
            while len(out) < max_rows:
                rows = cur.fetchmany(min(1000, max_rows - len(out)))
                if not rows:
                    break
                for r in rows:
                    out.append({c: r[i] for i, c in enumerate(cols)})
            return out
        finally:
            cur.close()

    def tables(self) -> list[str]:
        """Return every user table in the SQLite database (excludes the
        ``sqlite_*`` internal tables)."""
        return [
            r["name"] for r in self.query(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]

    def schema(self, table: str) -> list[dict]:
        """Return PRAGMA table_info(<table>) — one dict per column with
        cid/name/type/notnull/dflt_value/pk."""
        # PRAGMA can't take parameters; whitelist table name against
        # the actual schema first to defeat injection.
        if table not in self.tables():
            raise OSError(f"sqlite_fs: unknown table {table!r}")
        return self.query(f"PRAGMA table_info({table})")

    # ------------------------------------------------------------------
    # Adapter — translate row dicts ↔ SQLite rows
    # ------------------------------------------------------------------

    def _row_dict(self, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return {
            "path": row["path"],
            "parent": row["parent"],
            "is_dir": bool(row["is_dir"]),
            "mode": int(row["mode"]),
            "mtime": row["mtime"],
            "content": bytes(row["content"]) if row["content"] is not None else None,
        }

    def _db_get(self, path: str) -> dict | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM axross_files WHERE path = ?", (path,),
            )
            return self._row_dict(cur.fetchone())

    def _db_list(self, parent: str) -> Iterable[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM axross_files WHERE parent = ? ORDER BY path",
                (parent,),
            )
            for row in cur.fetchall():
                d = self._row_dict(row)
                if d is not None:
                    yield d

    def _db_insert(self, row: dict) -> None:
        mtime = row.get("mtime")
        if isinstance(mtime, datetime):
            mtime = mtime.isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO axross_files "
                "(path, parent, is_dir, mode, mtime, content) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    row["path"], row["parent"],
                    1 if row.get("is_dir") else 0,
                    int(row.get("mode") or 0o644),
                    mtime,
                    row.get("content"),
                ),
            )

    def _db_update(self, path: str, **fields) -> None:
        if not fields:
            return
        cols = []
        vals = []
        for k, v in fields.items():
            if k == "is_dir":
                cols.append("is_dir = ?")
                vals.append(1 if v else 0)
            elif k == "mtime" and isinstance(v, datetime):
                cols.append("mtime = ?")
                vals.append(v.isoformat())
            else:
                cols.append(f"{k} = ?")
                vals.append(v)
        vals.append(path)
        with self._lock:
            self._conn.execute(
                f"UPDATE axross_files SET {', '.join(cols)} WHERE path = ?",
                vals,
            )

    def _db_delete(self, path: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM axross_files WHERE path = ?", (path,))

    def _db_delete_subtree(self, path: str) -> None:
        # LIKE-escape '%' and '_' so a path containing those wildcards
        # cannot accidentally widen the deletion across siblings
        # (e.g. delete('/fo%') matching '/foo/...').
        escaped = (
            path.rstrip("/")
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
        )
        with self._lock:
            self._conn.execute(
                "DELETE FROM axross_files "
                "WHERE path = ? OR path LIKE ? || '/%' ESCAPE '\\'",
                (path, escaped),
            )

    # ------------------------------------------------------------------
    # Capabilities specific to a real on-disk SQLite file
    # ------------------------------------------------------------------

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Report the SQLite file's size as "used"; total/free come
        # from the host FS.
        try:
            st = os.statvfs(self._db_path)
            free = st.f_bavail * st.f_frsize
            total = st.f_blocks * st.f_frsize
            db_size = os.path.getsize(self._db_path)
            return (total, db_size, free)
        except OSError:
            return (0, 0, 0)
