"""PostgreSQL-as-storage backend.

Same shape as :mod:`core.sqlite_fs_client`, but backed by a real
PostgreSQL server via ``psycopg`` (the v3 driver). One row per file
lives in ``axross_files`` with a ``BYTEA`` content column. PG's
TOAST handles arbitrarily large blobs without us needing the LO
API; rows above ~1 GiB will start to look painful, but axross's
typical workloads stay well below.

Use cases:

* A multi-user vault: PG handles concurrent reads/writes natively.
* Cross-tenant filesystem within an existing PG cluster.

Connection URL is the standard ``postgres://user:pw@host:port/db``
shape; the table is auto-created on first use. Schema lives in the
search-path's first writable schema (usually ``public``).

Requires: ``pip install axross[postgres]`` — psycopg>=3.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Iterable
from urllib.parse import urlsplit

from core.db_fs_base import DbFsBackend

log = logging.getLogger(__name__)

try:
    import psycopg  # type: ignore[import-not-found]
except ImportError:
    psycopg = None  # type: ignore[assignment]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS axross_files (
    path     TEXT PRIMARY KEY,
    parent   TEXT NOT NULL,
    is_dir   BOOLEAN NOT NULL,
    mode     INTEGER NOT NULL DEFAULT 420,
    mtime    TIMESTAMP WITH TIME ZONE,
    content  BYTEA
);
CREATE INDEX IF NOT EXISTS axross_files_parent ON axross_files(parent);
"""


class PostgresFsSession(DbFsBackend):
    """PostgreSQL-backed FileBackend."""

    def __init__(
        self, host: str = "", port: int = 5432, username: str = "",
        password: str = "", database: str = "", url: str = "", **_ignored,
    ):
        if psycopg is None:
            raise ImportError(
                "PostgreSQL backend requires psycopg. "
                "Install with: pip install axross[postgres]",
            )
        if url:
            parts = urlsplit(url)
            host = host or (parts.hostname or "")
            port = port or (parts.port or 5432)
            username = username or (parts.username or "")
            password = password or (parts.password or "")
            database = database or parts.path.lstrip("/")
        if not host or not database:
            raise OSError("PostgreSQL backend needs host and database")
        self._dsn = (
            f"host={host} port={port} user={username} "
            f"password={password} dbname={database}"
        )
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        self._lock = threading.RLock()
        with self._lock, self._conn.cursor() as cur:
            cur.execute(_SCHEMA)
        self._display = f"postgres://{username}@{host}:{port}/{database}"
        log.info("PostgreSQL-FS connected: %s", self._display)

    @property
    def name(self) -> str:
        return f"PostgreSQL: {self._display}"

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Query passthrough — slice 3 of API_GAPS.
    # ------------------------------------------------------------------

    def query(
        self,
        sql: str,
        params: tuple | list | dict = (),
        *,
        max_rows: int = 10_000,
    ) -> list[dict]:
        """Run an SQL statement against the connected database. Returns
        a list of dicts (column-name → value) for ``SELECT``-shaped
        cursors; ``[]`` for DDL/DML that returns no rows.

        Parameterised queries use psycopg's ``%s`` placeholder, NOT
        SQLite's ``?``::

            rows = sess.query(
                "SELECT * FROM users WHERE id = %s", (user_id,),
            )

        ``max_rows`` clips with ``cursor.fetchmany`` so the unread
        rows stay on the server.
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, params)
            if cur.description is None:
                return []
            cols = [d[0] for d in cur.description]
            out: list[dict] = []
            while len(out) < max_rows:
                rows = cur.fetchmany(min(1000, max_rows - len(out)))
                if not rows:
                    break
                for r in rows:
                    out.append({c: r[i] for i, c in enumerate(cols)})
            return out

    def tables(self, schema: str = "public") -> list[str]:
        """Return every table in the named schema (default ``public``).
        Use ``schema='*'`` to enumerate every schema's tables."""
        if schema == "*":
            rows = self.query(
                "SELECT schemaname || '.' || tablename AS qname "
                "FROM pg_tables ORDER BY 1"
            )
            return [r["qname"] for r in rows]
        return [
            r["tablename"] for r in self.query(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = %s ORDER BY tablename",
                (schema,),
            )
        ]

    def schemas(self) -> list[str]:
        """Every visible schema — useful as a starting point for
        ``tables(schema=...)``."""
        return [
            r["nspname"] for r in self.query(
                "SELECT nspname FROM pg_namespace "
                "WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' "
                "ORDER BY nspname"
            )
        ]

    def explain(self, sql: str, params: tuple | list = ()) -> list[str]:
        """Return the textual EXPLAIN plan for ``sql`` — quick way to
        see whether a query hits an index without leaving the REPL."""
        rows = self.query(f"EXPLAIN {sql}", params)
        # EXPLAIN returns a single 'QUERY PLAN' column.
        return [r.get("QUERY PLAN") or list(r.values())[0] for r in rows]

    # ------------------------------------------------------------------
    # Adapter
    # ------------------------------------------------------------------

    @staticmethod
    def _row_dict(row) -> dict | None:
        if row is None:
            return None
        path, parent, is_dir, mode, mtime, content = row
        return {
            "path": path, "parent": parent,
            "is_dir": bool(is_dir), "mode": int(mode),
            "mtime": mtime,
            "content": bytes(content) if content is not None else None,
        }

    def _db_get(self, path: str) -> dict | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                "SELECT path, parent, is_dir, mode, mtime, content "
                "FROM axross_files WHERE path = %s",
                (path,),
            )
            return self._row_dict(cur.fetchone())

    def _db_list(self, parent: str) -> Iterable[dict]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                "SELECT path, parent, is_dir, mode, mtime, content "
                "FROM axross_files WHERE parent = %s ORDER BY path",
                (parent,),
            )
            for row in cur.fetchall():
                d = self._row_dict(row)
                if d is not None:
                    yield d

    def _db_insert(self, row: dict) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO axross_files "
                "(path, parent, is_dir, mode, mtime, content) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (path) DO UPDATE SET "
                "parent = EXCLUDED.parent, is_dir = EXCLUDED.is_dir, "
                "mode = EXCLUDED.mode, mtime = EXCLUDED.mtime, "
                "content = EXCLUDED.content",
                (
                    row["path"], row["parent"],
                    bool(row.get("is_dir")), int(row.get("mode") or 0o644),
                    row.get("mtime") or datetime.now(),
                    row.get("content"),
                ),
            )

    def _db_update(self, path: str, **fields) -> None:
        if not fields:
            return
        cols = []
        vals = []
        for k, v in fields.items():
            cols.append(f"{k} = %s")
            vals.append(v)
        vals.append(path)
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                f"UPDATE axross_files SET {', '.join(cols)} WHERE path = %s",
                vals,
            )

    def _db_delete(self, path: str) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("DELETE FROM axross_files WHERE path = %s", (path,))

    def _db_delete_subtree(self, path: str) -> None:
        # LIKE with ESCAPE: a path with '%' or '_' would otherwise widen
        # the deletion to siblings (e.g. delete('/fo%') matching '/foo/...').
        # Escape both wildcards plus the escape char itself.
        escaped = (
            path.rstrip("/")
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
        )
        prefix = escaped + "/%"
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                "DELETE FROM axross_files WHERE path = %s OR path LIKE %s ESCAPE '\\'",
                (path, prefix),
            )
