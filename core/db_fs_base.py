"""Base class for backends that store the filesystem inside a
relational / key-value DB.

Common shape — every concrete subclass populates a single logical
table or collection of rows::

    (path TEXT PRIMARY KEY,
     parent TEXT NOT NULL,
     is_dir BOOLEAN NOT NULL,
     mode INTEGER,
     mtime TIMESTAMP,
     content BLOB)

The base class implements the FileBackend protocol against a tiny
adapter interface that subclasses provide:

* :meth:`_db_get(path)` → row dict or None
* :meth:`_db_list(parent)` → list of row dicts
* :meth:`_db_insert(row)`
* :meth:`_db_update(path, **fields)`
* :meth:`_db_delete(path)`
* :meth:`_db_delete_subtree(path)`

That's it. Adding a new DB then means writing the adapter (~150
LOC) without touching the FileBackend semantics.

Path semantics: POSIX-style; ``/`` is the root. The root row is
implicit — ``stat("/")`` always returns a synthetic dir entry so
the UI can pivot off it without the table needing an explicit row
for ``/``.
"""
from __future__ import annotations

import io
import logging
import posixpath
from datetime import datetime
from typing import IO, Any, Iterable

from models.file_item import FileItem

log = logging.getLogger(__name__)


class _RowAdapter:
    """Subclass interface. Subclasses MUST override every method."""

    def _db_get(self, path: str) -> dict | None:
        raise NotImplementedError

    def _db_list(self, parent: str) -> Iterable[dict]:
        raise NotImplementedError

    def _db_insert(self, row: dict) -> None:
        raise NotImplementedError

    def _db_update(self, path: str, **fields: Any) -> None:
        raise NotImplementedError

    def _db_delete(self, path: str) -> None:
        raise NotImplementedError

    def _db_delete_subtree(self, path: str) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Public mixin
# ---------------------------------------------------------------------------

class DbFsBackend(_RowAdapter):
    """FileBackend implementation backed by ``_RowAdapter`` ops.

    Concrete subclasses inherit from this AND from ``_RowAdapter``
    (provided by inheritance — they only need to override the six
    adapter methods)."""

    supports_symlinks = False
    supports_hardlinks = False

    # ------------------------------------------------------------------
    # Identity / lifecycle — subclasses set these.
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "db-fs"

    @property
    def connected(self) -> bool:
        return True

    def close(self) -> None:
        pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        # Collapse any '..' / '//' to keep DB lookups deterministic.
        return posixpath.normpath(path) or "/"

    @staticmethod
    def _strict_normalize_or_reject(path: str) -> str:
        """Normalise ``path`` and refuse if the input wasn't already
        canonical. ``posixpath.normpath('/..') == '/'`` would otherwise
        let `mkdir('..')` succeed silently as a root no-op, masking
        caller bugs. Callers that legitimately want lenient normalising
        should call :meth:`normalize` directly.
        """
        if not path:
            raise OSError("empty path")
        rooted = path if path.startswith("/") else "/" + path
        canonical = posixpath.normpath(rooted) or "/"
        # The only legal difference between input and canonical is the
        # implicit leading slash and the root case.
        if rooted not in (canonical, canonical + "/"):
            raise OSError(
                f"non-canonical path {path!r} (would normalise to {canonical!r})"
            )
        return canonical

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        # Implicit root: any path that doesn't exist as a row but
        # equals "/" is treated as an empty directory; deeper paths
        # require a real row.
        if path != "/":
            row = self._db_get(path)
            if row is None or not row.get("is_dir"):
                raise OSError(f"Not a directory: {path}")
        items: list[FileItem] = []
        for row in self._db_list(path):
            items.append(self._row_to_item(row))
        return items

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o755,
            )
        row = self._db_get(path)
        if row is None:
            raise OSError(f"No such path: {path}")
        return self._row_to_item(row)

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        if path == "/":
            return True
        row = self._db_get(path)
        return bool(row and row.get("is_dir"))

    def exists(self, path: str) -> bool:
        path = self.normalize(path)
        if path == "/":
            return True
        return self._db_get(path) is not None

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        row = self._db_get(path)
        if row is None:
            raise OSError(f"No such path: {path}")
        if row.get("is_dir"):
            raise OSError(f"Is a directory: {path}")
        data = row.get("content") or b""
        return io.BytesIO(bytes(data))

    def readlink(self, path: str) -> str:
        raise OSError("DB-FS backends do not model symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("DB-FS backends do not expose version history")

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def mkdir(self, path: str) -> None:
        # Strict normalise so mkdir("..") / mkdir("/foo/../..") /
        # mkdir("/") fail loudly instead of being silent no-ops that
        # mask caller bugs. Read paths use the lenient normalize().
        path = self._strict_normalize_or_reject(path)
        if path == "/":
            return
        existing = self._db_get(path)
        if existing is not None:
            if existing.get("is_dir"):
                return
            raise OSError(f"Path exists and is a file: {path}")
        # Ensure parent exists (or is root).
        parent = self.parent(path)
        if parent != "/" and not self.is_dir(parent):
            raise OSError(f"Parent does not exist: {parent}")
        self._db_insert({
            "path": path,
            "parent": parent,
            "is_dir": True,
            "mode": 0o755,
            "mtime": datetime.now(),
            "content": None,
        })

    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        if path == "/":
            raise OSError("Refusing to remove root")
        row = self._db_get(path)
        if row is None:
            raise OSError(f"No such path: {path}")
        if row.get("is_dir"):
            children = list(self._db_list(path))
            if children and not recursive:
                raise OSError(f"Directory not empty: {path}")
            self._db_delete_subtree(path)
        else:
            self._db_delete(path)

    def rename(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        if src == "/" or dst == "/":
            raise OSError("Refusing to rename root")
        # Defensive: rename(/a, /a/b) would re-traverse the just-inserted
        # destination tree. _db_list materialises before we insert, so
        # this can't actually loop today — but a buggy adapter (one whose
        # _db_list scans live state) would. Cheap insurance.
        if dst == src or dst.startswith(src.rstrip("/") + "/"):
            raise OSError(
                f"Refusing rename {src!r} -> {dst!r}: destination is at "
                "or under source"
            )
        row = self._db_get(src)
        if row is None:
            raise OSError(f"No such path: {src}")
        # Use copy-then-delete via DB ops: read the bytes, insert
        # under the new path, drop the old. Subclasses with native
        # rename can override this whole method.
        self._db_insert({
            "path": dst,
            "parent": self.parent(dst),
            "is_dir": row.get("is_dir", False),
            "mode": row.get("mode", 0o644),
            "mtime": datetime.now(),
            "content": row.get("content"),
        })
        if row.get("is_dir"):
            for child in list(self._db_list(src)):
                child_dst = posixpath.join(dst, posixpath.basename(child["path"]))
                self.rename(child["path"], child_dst)
        self._db_delete(src)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        existing = self._db_get(path)
        if existing is not None and existing.get("is_dir"):
            raise OSError(f"Is a directory: {path}")
        prelude = b""
        if append and existing is not None:
            prelude = bytes(existing.get("content") or b"")
        return _DbWriter(self, path, prelude)

    def chmod(self, path: str, mode: int) -> None:
        path = self.normalize(path)
        if path == "/":
            return
        if self._db_get(path) is None:
            raise OSError(f"No such path: {path}")
        self._db_update(path, mode=int(mode))

    def copy(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        row = self._db_get(src)
        if row is None:
            raise OSError(f"No such path: {src}")
        if row.get("is_dir"):
            raise OSError("DB-FS copy: source is a directory")
        # Mirror mkdir's parent-existence guard so copy can't insert an
        # orphan row that no list_dir() would ever surface.
        dst_parent = self.parent(dst)
        if dst_parent != "/" and not self.is_dir(dst_parent):
            raise OSError(f"Parent does not exist: {dst_parent}")
        self._db_insert({
            "path": dst,
            "parent": dst_parent,
            "is_dir": False,
            "mode": row.get("mode", 0o644),
            "mtime": datetime.now(),
            "content": row.get("content"),
        })

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        # Subclasses with native hashing can override; the base just
        # returns "" so the transfer engine streams + hashes itself.
        return ""

    # ------------------------------------------------------------------
    # Internal: row → FileItem
    # ------------------------------------------------------------------

    def _row_to_item(self, row: dict) -> FileItem:
        path = row["path"]
        is_dir = bool(row.get("is_dir"))
        content = row.get("content")
        size = 0 if is_dir or content is None else len(content)
        mtime = row.get("mtime")
        if isinstance(mtime, str):
            try:
                mtime = datetime.fromisoformat(mtime)
            except ValueError:
                mtime = datetime.fromtimestamp(0)
        if not isinstance(mtime, datetime):
            mtime = datetime.fromtimestamp(0)
        return FileItem(
            name=posixpath.basename(path) or path,
            size=size, modified=mtime,
            permissions=int(row.get("mode") or (0o755 if is_dir else 0o644)),
            is_dir=is_dir, is_link=False,
        )


# ---------------------------------------------------------------------------
# Writer — buffers in memory, commits on close
# ---------------------------------------------------------------------------

class _DbWriter:
    """Buffer bytes in memory, then upsert on close."""

    def __init__(self, backend: DbFsBackend, path: str, prelude: bytes = b""):
        self._backend = backend
        self._path = path
        self._buf = io.BytesIO(prelude)
        if prelude:
            self._buf.seek(0, io.SEEK_END)
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        data = self._buf.getvalue()
        existing = self._backend._db_get(self._path)
        row = {
            "path": self._path,
            "parent": self._backend.parent(self._path),
            "is_dir": False,
            "mode": (existing or {}).get("mode") or 0o644,
            "mtime": datetime.now(),
            "content": data,
        }
        if existing is None:
            self._backend._db_insert(row)
        else:
            self._backend._db_update(
                self._path,
                content=data, mtime=row["mtime"], is_dir=False,
            )
        self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
