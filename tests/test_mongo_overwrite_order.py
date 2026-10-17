"""MongoDB-FS overwrites upload the new GridFS file before deleting the old.

``_db_insert`` deleted every stored version of a filename and only then
called ``GridFS.put``. When the put failed (connection drop, size or
quota error) the file was gone: an overwrite, a chmod or an append that
failed half way destroyed the previous content.

Driven through the backend's public open_write / chmod against an
in-memory stand-in with GridFS's find / find_one / put / delete surface.
"""

from __future__ import annotations

import itertools
import sys
import threading
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from core import mongo_fs_client as MC

    PYMONGO = True
except ImportError:  # pragma: no cover - optional extra
    PYMONGO = False


class _Stored:
    def __init__(self, _id, filename, data, metadata) -> None:
        self._id, self.filename, self._data, self.metadata = _id, filename, data, metadata
        self.length, self.upload_date = len(data), datetime(2026, 1, 1)

    def read(self) -> bytes:
        return self._data


class _GridFS:
    def __init__(self) -> None:
        self.files: dict[int, _Stored] = {}
        self._ids = itertools.count(1)
        self.fail_put = False

    def find(self, q):
        if "filename" in q:
            return [f for f in list(self.files.values()) if f.filename == q["filename"]]
        return [
            f for f in list(self.files.values()) if f.metadata["parent"] == q["metadata.parent"]
        ]

    def find_one(self, q):
        hits = self.find(q)
        return hits[0] if hits else None

    def put(self, data, filename, metadata):
        if self.fail_put:
            raise OSError("connection reset during upload")
        _id = next(self._ids)
        self.files[_id] = _Stored(_id, filename, data, metadata)
        return _id

    def delete(self, _id) -> None:
        self.files.pop(_id, None)


@unittest.skipUnless(PYMONGO, "pymongo not installed")
class MongoOverwriteOrderTest(unittest.TestCase):
    def setUp(self) -> None:
        s = object.__new__(MC.MongoFsSession)
        s._lock = threading.RLock()
        s._fs = _GridFS()
        s._dirs = SimpleNamespace(
            find_one=lambda q: {"path": "/", "parent": "/"} if q["path"] == "/" else None,
            find=lambda q: [],
            update_one=lambda *a, **k: None,
            delete_one=lambda *a, **k: None,
        )
        self.s = s
        with s.open_write("/a.txt") as fh:
            fh.write(b"version one")

    def _read(self) -> bytes:
        with self.s.open_read("/a.txt") as fh:
            return fh.read()

    def test_happy_overwrite_leaves_one_new_version(self) -> None:
        with self.s.open_write("/a.txt") as fh:
            fh.write(b"version two")
        self.assertEqual(self._read(), b"version two")
        self.assertEqual(len(self.s._fs.find({"filename": "/a.txt"})), 1)

    def test_sad_failed_upload_keeps_the_old_content(self) -> None:
        self.s._fs.fail_put = True
        with self.assertRaises(OSError):
            with self.s.open_write("/a.txt") as fh:
                fh.write(b"version two")
        self.s._fs.fail_put = False
        self.assertEqual(self._read(), b"version one")

    def test_edge_failed_chmod_keeps_the_file(self) -> None:
        self.s._fs.fail_put = True
        with self.assertRaises(OSError):
            self.s.chmod("/a.txt", 0o600)
        self.s._fs.fail_put = False
        self.assertEqual(self._read(), b"version one")


if __name__ == "__main__":
    unittest.main()
