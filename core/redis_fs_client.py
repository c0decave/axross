"""Redis-as-storage backend.

Uses Redis hashes as a tiny per-path record. The schema:

* ``axross:meta:<path>`` — hash with ``parent``, ``is_dir``, ``mode``,
  ``mtime``. The bytes live in ``axross:data:<path>`` (a separate
  string key) so directory listings don't pull every blob into memory.
* ``axross:children:<parent>`` — set of child paths. Cheaper than
  scanning ``axross:meta:*`` to enumerate a directory.
* TTL: optional. Per-key TTL is honoured but not set by axross —
  callers can set it manually after a write to make the entry
  ephemeral.

Use cases:

* A volatile, network-reachable workspace: parking small artefacts
  for a few hours during a security engagement.
* Cross-process scratch space behind axross MCP without provisioning
  a real DB.

Requires: ``pip install axross[redis]`` — redis-py>=5.
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
    import redis  # type: ignore[import-not-found]
except ImportError:
    redis = None  # type: ignore[assignment]


_NS_META = "axross:meta:"
_NS_DATA = "axross:data:"
_NS_KIDS = "axross:children:"


class RedisFsSession(DbFsBackend):
    """Redis-backed FileBackend."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 6379,
        password: str = "", database: int | str = 0,
        url: str = "", use_tls: bool = False, **_ignored,
    ):
        if redis is None:
            raise ImportError(
                "Redis backend requires redis-py. "
                "Install with: pip install axross[redis]",
            )
        if url:
            parts = urlsplit(url)
            host = host or (parts.hostname or "127.0.0.1")
            port = port or (parts.port or 6379)
            password = password or (parts.password or "")
            try:
                database = int((parts.path or "/").lstrip("/") or 0)
            except ValueError:
                database = 0
            use_tls = use_tls or parts.scheme == "rediss"
        self._client = redis.Redis(
            host=host, port=int(port),
            password=password or None,
            db=int(database),
            ssl=bool(use_tls),
            decode_responses=False,
        )
        self._client.ping()
        self._lock = threading.RLock()
        self._display = f"{'rediss' if use_tls else 'redis'}://{host}:{port}/{database}"
        log.info("Redis-FS connected: %s", self._display)

    @property
    def name(self) -> str:
        return f"Redis: {self._display}"

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Raw-Redis passthrough — slice 3 of API_GAPS.
    # ------------------------------------------------------------------

    def cmd(self, *args):
        """Run an arbitrary Redis command and return its raw reply.
        Equivalent to ``redis-cli`` for one shot — useful for the
        operations that don't fit ``GET``/``SET``::

            sess.cmd("CONFIG", "GET", "maxmemory")
            sess.cmd("CLIENT", "LIST")

        Returns whatever redis-py's ``execute_command`` returns;
        bytes for string replies, lists for multi-bulk, dicts for
        XINFO etc.
        """
        if not args:
            raise ValueError("cmd: at least one argument required")
        with self._lock:
            return self._client.execute_command(*args)

    def scan(self, pattern: str = "*", *,
             count: int = 100, max_keys: int = 10_000) -> list[str]:
        """Iterate keys matching ``pattern`` using ``SCAN`` (cursor-
        based, safe on a busy server — ``KEYS *`` would block). Caps
        at ``max_keys`` to keep the REPL prompt responsive."""
        out: list[str] = []
        with self._lock:
            for raw in self._client.scan_iter(match=pattern, count=count):
                if isinstance(raw, bytes):
                    out.append(raw.decode("utf-8", errors="replace"))
                else:
                    out.append(str(raw))
                if len(out) >= max_keys:
                    break
        return out

    def ttl(self, key: str) -> int:
        """TTL of ``key`` in seconds. -1 = no expiry, -2 = no such key."""
        return int(self.cmd("TTL", key))

    def info(self, section: str | None = None) -> dict:
        """``INFO`` server stats parsed into a dict (one entry per
        ``key:value`` pair). Pass ``section='memory'`` etc. to scope."""
        with self._lock:
            return self._client.info(section) if section else self._client.info()

    # ------------------------------------------------------------------
    # Adapter
    # ------------------------------------------------------------------

    def _db_get(self, path: str) -> dict | None:
        with self._lock:
            meta = self._client.hgetall(_NS_META + path)
        if not meta:
            return None
        # All fields come back as bytes.
        def get(k: str) -> bytes | None:
            return meta.get(k.encode())
        is_dir = (get("is_dir") or b"0") == b"1"
        mtime_raw = (get("mtime") or b"").decode("utf-8", "replace")
        try:
            mtime = datetime.fromisoformat(mtime_raw) if mtime_raw else None
        except ValueError:
            mtime = None
        content = None
        if not is_dir:
            content = self._client.get(_NS_DATA + path)
        return {
            "path": path,
            "parent": (get("parent") or b"/").decode("utf-8", "replace"),
            "is_dir": is_dir,
            "mode": int(get("mode") or b"0o644".decode(), 0)
            if (get("mode") or b"").startswith(b"0o")
            else int(get("mode") or b"420"),
            "mtime": mtime,
            "content": bytes(content) if content is not None else None,
        }

    def _db_list(self, parent: str) -> Iterable[dict]:
        with self._lock:
            children = self._client.smembers(_NS_KIDS + parent)
        for raw in sorted(children or []):
            child_path = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            d = self._db_get(child_path)
            if d is not None:
                yield d

    def _db_insert(self, row: dict) -> None:
        path = row["path"]
        parent = row["parent"]
        mtime = row.get("mtime") or datetime.now()
        if isinstance(mtime, datetime):
            mtime = mtime.isoformat()
        with self._lock:
            pipe = self._client.pipeline()
            pipe.hset(_NS_META + path, mapping={
                "parent": parent,
                "is_dir": "1" if row.get("is_dir") else "0",
                "mode": str(int(row.get("mode") or 0o644)),
                "mtime": mtime,
            })
            if not row.get("is_dir"):
                pipe.set(_NS_DATA + path, row.get("content") or b"")
            else:
                pipe.delete(_NS_DATA + path)
            pipe.sadd(_NS_KIDS + parent, path)
            pipe.execute()

    def _db_update(self, path: str, **fields) -> None:
        if not fields:
            return
        with self._lock:
            pipe = self._client.pipeline()
            mapping = {}
            for k, v in fields.items():
                if k == "content":
                    if v is None:
                        pipe.delete(_NS_DATA + path)
                    else:
                        pipe.set(_NS_DATA + path, v)
                elif k == "is_dir":
                    mapping["is_dir"] = "1" if v else "0"
                elif k == "mtime" and isinstance(v, datetime):
                    mapping["mtime"] = v.isoformat()
                else:
                    mapping[k] = str(v)
            if mapping:
                pipe.hset(_NS_META + path, mapping=mapping)
            pipe.execute()

    def _db_delete(self, path: str) -> None:
        with self._lock:
            meta = self._client.hgetall(_NS_META + path)
            parent = (meta.get(b"parent") or b"/").decode("utf-8", "replace")
            pipe = self._client.pipeline()
            pipe.delete(_NS_META + path)
            pipe.delete(_NS_DATA + path)
            pipe.srem(_NS_KIDS + parent, path)
            pipe.execute()

    def _db_delete_subtree(self, path: str) -> None:
        # Walk children breadth-first; Redis has no LIKE.
        with self._lock:
            stack = [path]
            while stack:
                current = stack.pop()
                kids = self._client.smembers(_NS_KIDS + current)
                for raw in kids or []:
                    child = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
                    stack.append(child)
                self._db_delete(current)
                self._client.delete(_NS_KIDS + current)
