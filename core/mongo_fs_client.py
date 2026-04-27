"""MongoDB GridFS-as-storage backend.

Uses GridFS — Mongo's purpose-built large-file store — to back a
FileBackend. Each file becomes a GridFS object; directories are
synthetic and live in a sibling collection ``axross_dirs``.

Why both: GridFS files have ``filename`` + metadata but no native
hierarchy. We track the tree in ``axross_dirs`` so listings are
O(children) rather than scanning every file. Path-uniqueness is
enforced by an index on ``filename`` (one path = at most one file
revision unless the user opts into version history).

Use cases:

* Vault backed by an existing MongoDB cluster.
* Storage for blobs that are too big for SQLite-FS rows.

Requires: ``pip install axross[mongo]`` — pymongo>=4.
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
    import gridfs  # type: ignore[import-not-found]
    import pymongo  # type: ignore[import-not-found]
except ImportError:
    gridfs = None  # type: ignore[assignment]
    pymongo = None  # type: ignore[assignment]


class MongoFsSession(DbFsBackend):
    """MongoDB-backed FileBackend (GridFS for content, axross_dirs
    for the synthetic tree)."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 27017,
        username: str = "", password: str = "",
        database: str = "axross", url: str = "", **_ignored,
    ):
        if pymongo is None:
            raise ImportError(
                "MongoDB backend requires pymongo. "
                "Install with: pip install axross[mongo]",
            )
        if url:
            parts = urlsplit(url)
            host = host or (parts.hostname or "127.0.0.1")
            port = port or (parts.port or 27017)
            username = username or (parts.username or "")
            password = password or (parts.password or "")
            if parts.path and parts.path != "/":
                database = parts.path.lstrip("/")

        client_kwargs: dict = {"host": host, "port": int(port)}
        if username:
            client_kwargs["username"] = username
        if password:
            client_kwargs["password"] = password
        self._client = pymongo.MongoClient(**client_kwargs)
        self._db = self._client[database]
        self._fs = gridfs.GridFS(self._db, collection="axross_files")
        self._dirs = self._db["axross_dirs"]
        self._dirs.create_index("path", unique=True)
        self._dirs.create_index("parent")
        self._lock = threading.RLock()
        self._display = f"mongodb://{host}:{port}/{database}"
        log.info("Mongo-FS connected: %s", self._display)

    @property
    def name(self) -> str:
        return f"MongoDB GridFS: {self._display}"

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Pymongo passthrough — slice 3 of API_GAPS.
    # ------------------------------------------------------------------

    def collections(self) -> list[str]:
        """Every user collection in the connected database (excludes
        the ``system.*`` internals + axross's own ``axross_files`` /
        ``axross_dirs`` housekeeping collections)."""
        with self._lock:
            names = list(self._db.list_collection_names())
        return sorted(
            n for n in names
            if not n.startswith("system.")
            and n not in ("axross_files.files", "axross_files.chunks",
                          "axross_dirs")
        )

    def find(
        self,
        collection: str,
        filter: dict | None = None,
        *,
        projection: dict | None = None,
        limit: int = 100,
        sort: list[tuple] | None = None,
    ) -> list[dict]:
        """``db[collection].find(filter, projection)`` with a hard
        ``limit`` (default 100, max enforced by caller)::

            sess.find("orders", {"status": "open"}, limit=50)
        """
        with self._lock:
            cur = self._db[collection].find(
                filter or {},
                projection=projection,
            )
            if sort:
                cur = cur.sort(sort)
            cur = cur.limit(int(limit))
            return list(cur)

    def command(self, *args, **kwargs):
        """Run a MongoDB admin command, e.g. ``serverStatus`` or
        ``dbStats``. Same signature as ``pymongo.database.Database.command``."""
        with self._lock:
            return self._db.command(*args, **kwargs)

    def gridfs_metadata(self, path: str) -> dict | None:
        """Return the GridFS file-document metadata for the file at
        ``path`` — uploadDate, chunkSize, md5 (if present), length —
        without streaming the body."""
        with self._lock:
            f = self._fs.find_one({"filename": path})
            if f is None:
                return None
            return {
                "filename": f.filename,
                "length": f.length,
                "chunk_size": f.chunk_size,
                "upload_date": f.upload_date,
                "md5": getattr(f, "md5", None),
                "metadata": getattr(f, "metadata", None),
            }

    # ------------------------------------------------------------------
    # Adapter
    # ------------------------------------------------------------------

    def _db_get(self, path: str) -> dict | None:
        with self._lock:
            dir_doc = self._dirs.find_one({"path": path})
            if dir_doc is not None:
                return {
                    "path": path, "parent": dir_doc["parent"],
                    "is_dir": True, "mode": dir_doc.get("mode", 0o755),
                    "mtime": dir_doc.get("mtime"), "content": None,
                }
            f = self._fs.find_one({"filename": path})
            if f is None:
                return None
            return {
                "path": path,
                "parent": f.metadata.get("parent", "/") if f.metadata else "/",
                "is_dir": False,
                "mode": f.metadata.get("mode", 0o644) if f.metadata else 0o644,
                "mtime": f.upload_date,
                "content": f.read(),
            }

    def _db_list(self, parent: str) -> Iterable[dict]:
        with self._lock:
            for d in self._dirs.find({"parent": parent}):
                yield {
                    "path": d["path"], "parent": parent,
                    "is_dir": True, "mode": d.get("mode", 0o755),
                    "mtime": d.get("mtime"), "content": None,
                }
            for f in self._fs.find({"metadata.parent": parent}):
                yield {
                    "path": f.filename, "parent": parent,
                    "is_dir": False,
                    "mode": (f.metadata or {}).get("mode", 0o644),
                    "mtime": f.upload_date,
                    "content": None,  # Lazy: read on demand via _db_get
                }

    def _db_insert(self, row: dict) -> None:
        path = row["path"]
        parent = row["parent"]
        with self._lock:
            if row.get("is_dir"):
                self._dirs.update_one(
                    {"path": path},
                    {"$set": {
                        "path": path, "parent": parent,
                        "mode": int(row.get("mode") or 0o755),
                        "mtime": row.get("mtime") or datetime.now(),
                    }},
                    upsert=True,
                )
                return
            # Replace any prior version of the same filename.
            for old in self._fs.find({"filename": path}):
                self._fs.delete(old._id)
            self._fs.put(
                row.get("content") or b"",
                filename=path,
                metadata={
                    "parent": parent,
                    "mode": int(row.get("mode") or 0o644),
                },
            )

    def _db_update(self, path: str, **fields) -> None:
        with self._lock:
            existing = self._db_get(path)
            if existing is None:
                return
            updated = {**existing, **fields}
            self._db_insert(updated)

    def _db_delete(self, path: str) -> None:
        with self._lock:
            self._dirs.delete_one({"path": path})
            for old in self._fs.find({"filename": path}):
                self._fs.delete(old._id)

    def _db_delete_subtree(self, path: str) -> None:
        with self._lock:
            stack = [path]
            while stack:
                current = stack.pop()
                for d in self._dirs.find({"parent": current}):
                    stack.append(d["path"])
                for f in self._fs.find({"metadata.parent": current}):
                    self._fs.delete(f._id)
                self._dirs.delete_many({"parent": current})
                self._db_delete(current)
