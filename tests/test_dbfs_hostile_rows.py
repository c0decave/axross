"""DB-FS backends: driver errors and rows of the wrong shape are OSError.

The Redis / MongoDB / PostgreSQL backends store the tree in the database,
where any other client can write anything. DbFsBackend called its
adapters bare, so a driver failure - redis.RedisError (a dropped
connection, or WRONGTYPE for a key holding another type),
pymongo.PyMongoError, psycopg.Error, none of them an OSError - escaped
list_dir / stat / open_read to callers that handle OSError. And rows were
read unchecked: ``int(row["mode"])`` / ``int(row["size"])`` raised
ValueError for a value that is no number (Redis also for a STRLEN reply
that is no integer), ``posixpath.basename(row["path"])`` TypeError for a
document without a path, Mongo's ``d["path"]`` / ``dir_doc["parent"]``
KeyError. Found by tests/test_fuzz_dbfs.py.
"""

from __future__ import annotations

import sys
import threading
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db_fs_base import DbFsBackend  # noqa: E402


class DriverError(Exception):
    """Stands in for a DB driver's own exception base class."""


class ScriptedDb(DbFsBackend):
    _DRIVER_ERRORS = (DriverError,)

    def __init__(self, rows=(), meta=None, fail: BaseException | None = None) -> None:
        self.rows, self.meta, self.fail = list(rows), meta, fail

    def _check(self):
        if self.fail is not None:
            raise self.fail

    def _db_get(self, path):
        self._check()
        return self.meta

    def _db_list(self, parent):
        self._check()
        return list(self.rows)

    def _db_insert(self, row):
        self._check()

    def _db_update(self, path, **fields):
        self._check()

    def _db_delete(self, path):
        self._check()

    def _db_delete_subtree(self, path):
        self._check()


DIR_ROW = {"path": "/d", "parent": "/", "is_dir": True, "mode": 0o755, "mtime": None}


def test_happy_rows_list():
    rows = [
        {"path": "/a.txt", "parent": "/", "is_dir": False, "mode": 0o644, "size": 5},
        DIR_ROW,
    ]
    items = {i.name: i for i in ScriptedDb(rows).list_dir("/")}
    assert items["a.txt"].size == 5 and items["d"].is_dir


@pytest.mark.parametrize("op", ["list_dir", "stat", "is_dir", "exists", "open_read", "mkdir"])
def test_sad_driver_error_is_an_oserror(op):
    db = ScriptedDb(fail=DriverError("connection reset"))
    call = {
        "list_dir": lambda: db.list_dir("/"),
        "stat": lambda: db.stat("/a"),
        "is_dir": lambda: db.is_dir("/a"),
        "exists": lambda: db.exists("/a"),
        "open_read": lambda: db.open_read("/a"),
        "mkdir": lambda: db.mkdir("/a"),
    }[op]
    with pytest.raises(OSError, match="connection reset"):
        call()


def test_sad_writer_close_driver_error_is_an_oserror():
    db = ScriptedDb()
    writer = db.open_write("/a")
    db.fail = DriverError("gone")
    with pytest.raises(OSError, match="gone"):
        writer.close()


def test_edge_rows_of_the_wrong_shape():
    rows = [
        {"path": None, "is_dir": False},
        {"path": "", "is_dir": False},
        {"parent": "/"},
        {"path": "/mode", "mode": "abc", "size": 1},
        {"path": "/size", "mode": 0o644, "size": "x"},
        {"path": "/neg", "size": -5},
        {"path": "/huge-mode", "mode": 2**70},
        {"path": "/time", "mtime": 12345},
    ]
    items = {i.name: i for i in ScriptedDb(rows).list_dir("/")}
    assert set(items) == {"mode", "size", "neg", "huge-mode", "time"}
    assert items["mode"].permissions == 0o644
    assert items["size"].size == 0 and items["neg"].size == 0
    assert 0 <= items["huge-mode"].permissions <= 0o7777
    assert isinstance(items["time"].modified, datetime)


def test_edge_stat_row_without_a_path_is_an_oserror():
    with pytest.raises(OSError):
        ScriptedDb(meta={"is_dir": False, "path": None}).stat("/a")


def test_happy_content_reads():
    db = ScriptedDb(meta={"path": "/a", "content": memoryview(b"abc")})
    assert db.open_read("/a").read() == b"abc"


@pytest.mark.parametrize("content", [5, 2**70, "text", datetime(2024, 1, 2)])
def test_sad_content_that_is_not_bytes_is_an_oserror(content):
    # bytes(5) would have been five zero bytes, bytes(2**70) a MemoryError.
    db = ScriptedDb(meta={"path": "/a", "content": content})
    with pytest.raises(OSError, match="not bytes"):
        db.open_read("/a")
    with pytest.raises(OSError, match="not bytes"):
        db.open_write("/a", append=True)


# -- Redis adapter -------------------------------------------------------------


def _redis_session(client):
    pytest.importorskip("redis")
    from core.redis_fs_client import RedisFsSession

    s = RedisFsSession.__new__(RedisFsSession)
    s._client = client
    s._lock = threading.Lock()
    return s


class _RedisFake:
    def __init__(self, meta: dict, strlen=5, fail: BaseException | None = None) -> None:
        self.meta, self.strlen_reply, self.fail = meta, strlen, fail

    def _check(self):
        if self.fail is not None:
            raise self.fail

    def hgetall(self, key):
        self._check()
        return self.meta

    def smembers(self, key):
        self._check()
        return {b"/a"}

    def strlen(self, key):
        self._check()
        return self.strlen_reply

    def get(self, key):
        self._check()
        return b"hello"

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self):
                self.n = 0

            def hgetall(self, key):
                self.n += 1

            def strlen(self, key):
                pass

            def execute(self):
                outer._check()
                return [outer.meta, outer.strlen_reply] * self.n

        return _Pipe()


def test_happy_redis_listing():
    s = _redis_session(_RedisFake({b"is_dir": b"0", b"mode": b"420", b"parent": b"/"}))
    [item] = s.list_dir("/")
    assert (item.name, item.size, item.permissions) == ("a", 5, 0o644)


@pytest.mark.parametrize("mode", [b"abc", b"0o9", b"", b"-1", b"\xff"])
def test_edge_redis_mode_that_is_no_number(mode):
    s = _redis_session(_RedisFake({b"is_dir": b"0", b"mode": mode, b"parent": b"/"}))
    [item] = s.list_dir("/")
    assert 0 <= item.permissions <= 0o7777


@pytest.mark.parametrize("reply", [b"x", None, -1, b"5"])
def test_edge_redis_strlen_reply_that_is_no_integer(reply):
    s = _redis_session(_RedisFake({b"is_dir": b"0", b"mode": b"420"}, strlen=reply))
    [item] = s.list_dir("/")
    assert item.size in (0, 5)


def test_sad_redis_wrongtype_is_an_oserror():
    redis = pytest.importorskip("redis")
    fail = redis.exceptions.ResponseError(
        "WRONGTYPE Operation against a key holding the wrong kind"
    )
    s = _redis_session(_RedisFake({}, fail=fail))
    with pytest.raises(OSError, match="WRONGTYPE"):
        s.list_dir("/")
    with pytest.raises(OSError):
        s.stat("/a")


# -- MongoDB adapter -----------------------------------------------------------


class _Coll:
    def __init__(self, docs, fail=None) -> None:
        self.docs, self.fail = docs, fail

    def find(self, query):
        if self.fail is not None:
            raise self.fail
        return iter(self.docs)

    def find_one(self, query):
        if self.fail is not None:
            raise self.fail
        return self.docs[0] if self.docs else None


def _mongo_session(dirs, files, fail=None):
    pytest.importorskip("pymongo")
    from core.mongo_fs_client import MongoFsSession

    s = MongoFsSession.__new__(MongoFsSession)
    s._dirs = _Coll(dirs, fail)
    s._fs = _Coll(files, fail)
    s._lock = threading.RLock()
    return s


def _gridout(**kw):
    base = {"filename": "/f.bin", "metadata": {"parent": "/", "mode": 0o644}, "length": 3}
    base.update(kw)
    base.setdefault("upload_date", datetime(2024, 1, 2))
    return types.SimpleNamespace(read=lambda: b"abc", **base)


def test_happy_mongo_listing():
    s = _mongo_session([{"path": "/d", "parent": "/", "mode": 0o755}], [_gridout()])
    assert sorted(i.name for i in s.list_dir("/")) == ["d", "f.bin"]


def test_edge_mongo_documents_of_the_wrong_shape():
    dirs = [{"parent": "/"}, {"path": 5, "mode": "x"}, {"path": "/ok", "mode": "rwx"}]
    files = [_gridout(filename=None), _gridout(metadata={"mode": "x"}, length=-1)]
    names = sorted(i.name for i in _mongo_session(dirs, files).list_dir("/"))
    assert names == ["f.bin", "ok"]


def test_edge_mongo_dir_document_without_a_parent_stats():
    s = _mongo_session([{"path": "/d"}], [])
    assert s.stat("/d").is_dir


def test_sad_mongo_driver_error_is_an_oserror():
    errors = pytest.importorskip("pymongo.errors")
    s = _mongo_session([], [], fail=errors.AutoReconnect("connection closed"))
    with pytest.raises(OSError, match="connection closed"):
        s.list_dir("/")
