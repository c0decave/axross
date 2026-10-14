"""DB-backed file systems list and stat without fetching file contents.

Before: ``list_dir``, ``stat``, ``is_dir`` and ``exists`` went through
``_db_get`` / ``_db_list``, which return every row WITH its content;
``_row_to_item`` then only took ``len(content)``. A Postgres listing of
1 000 files of 1 MiB moved 1 GiB, Redis fetched every value with GET
(plus one round trip per child), Mongo read every GridFS file for a stat.

Now those four go through ``_db_get_meta`` / ``_db_list_meta``: rows with
``size`` (computed by the database) instead of ``content``. The default
falls back to the full rows, so a backend without the override behaves
as before. Each test compares against the old full-row path.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db_fs_base import DbFsBackend  # noqa: E402
from core.sqlite_fs_client import SqliteFsSession  # noqa: E402

FILES = {"/a.bin": b"x" * 1000, "/empty.bin": b"", "/d/inner.txt": b"hello"}


def _old_items(backend, path, paths=tuple(FILES)):
    """The listing and stats as the full-row path builds them."""
    with mock.patch.object(type(backend), "_db_list_meta", type(backend)._db_list), mock.patch.object(
        type(backend), "_db_get_meta", type(backend)._db_get
    ):
        return backend.list_dir(path), {p: backend.stat(p) for p in paths}


def _fill(backend) -> None:
    backend.mkdir("/d")
    for p, data in FILES.items():
        with backend.open_write(p) as f:
            f.write(data)


class SqliteMetaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.s = SqliteFsSession(":memory:")
        _fill(self.s)
        self.statements: list[str] = []
        self.s._conn.set_trace_callback(self.statements.append)

    def test_happy_listing_and_stat_equal_the_full_row_path(self) -> None:
        old_list, old_stat = _old_items(self.s, "/")
        self.assertEqual(self.s.list_dir("/"), old_list)
        self.assertEqual({p: self.s.stat(p) for p in FILES}, old_stat)
        self.assertEqual(self.s.list_dir("/d"), _old_items(self.s, "/d")[0])

    def test_happy_metadata_reads_select_no_content(self) -> None:
        self.statements.clear()
        self.s.list_dir("/")
        self.s.list_dir("/d")
        for p in FILES:
            self.s.stat(p)
            self.s.exists(p)
            self.s.is_dir(p)
        self.assertTrue(self.statements)
        for sql in self.statements:
            self.assertNotIn("SELECT *", sql)
            self.assertNotRegex(sql, r"(?i)(,|select)\s*content\s*(,|from)")

    def test_sad_missing_paths_behave_as_before(self) -> None:
        with self.assertRaises(OSError):
            self.s.stat("/nope")
        with self.assertRaises(OSError):
            self.s.list_dir("/a.bin")  # a file, not a directory
        self.assertFalse(self.s.exists("/nope"))
        self.assertFalse(self.s.is_dir("/a.bin"))
        self.assertTrue(self.s.is_dir("/d"))

    def test_edge_open_read_still_returns_the_content(self) -> None:
        with self.s.open_read("/a.bin") as f:
            self.assertEqual(f.read(), FILES["/a.bin"])


class DefaultFallbackTest(unittest.TestCase):
    def test_edge_a_backend_without_overrides_uses_the_full_rows(self) -> None:
        self.assertEqual(DbFsBackend._db_get_meta.__qualname__, "_RowAdapter._db_get_meta")
        rows = {"/f": {"path": "/f", "parent": "/", "is_dir": False, "mode": 0o644,
                       "mtime": None, "content": b"abc"}}

        class Plain(DbFsBackend):
            def _db_get(self, path):
                return rows.get(path)

            def _db_list(self, parent):
                return [r for r in rows.values() if r["parent"] == parent]

        b = object.__new__(Plain)
        self.assertEqual(b.stat("/f").size, 3)
        self.assertEqual([i.size for i in b.list_dir("/")], [3])


class _FakeCursor:
    def __init__(self, rows) -> None:
        self.rows, self.sql = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        self.sql.append(sql)
        self._params = params

    def fetchone(self):
        return next((r for r in self.rows if r[0] == self._params[0]), None)

    def fetchall(self):
        return [r for r in self.rows if r[1] == self._params[0]]


class PostgresMetaTest(unittest.TestCase):
    def setUp(self) -> None:
        from core import postgres_fs_client as PG

        mtime = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.full = [
            ("/a.bin", "/", False, 0o644, mtime, b"x" * 1000),
            ("/e.bin", "/", False, 0o644, mtime, None),
            ("/d", "/", True, 0o755, mtime, None),
        ]
        self.meta = [(p, par, d, m, t, None if c is None else len(c)) for p, par, d, m, t, c in self.full]
        self.s = object.__new__(PG.PostgresFsSession)
        self.s._lock = mock.MagicMock()

    def _with(self, rows):
        cur = _FakeCursor(rows)
        self.s._conn = SimpleNamespace(cursor=lambda: cur)
        return cur

    def test_happy_listing_equals_and_selects_only_the_length(self) -> None:
        self._with(self.full)
        paths = [r[0] for r in self.full]
        old_list, old_stat = _old_items(self.s, "/", paths)
        cur = self._with(self.meta)
        self.assertEqual(self.s.list_dir("/"), old_list)
        self.assertEqual({p: self.s.stat(p) for p in paths}, old_stat)
        self.assertTrue(all("octet_length(content)" in q for q in cur.sql))

    def test_sad_stat_of_missing_path(self) -> None:
        self._with(self.meta)
        with self.assertRaises(OSError):
            self.s.stat("/nope")

    def test_edge_null_content_is_size_zero(self) -> None:
        self._with(self.meta)
        self.assertEqual(self.s.stat("/e.bin").size, 0)


class _FakeRedis:
    def __init__(self) -> None:
        self.meta, self.data, self.kids = {}, {}, {}
        self.calls: list[str] = []

    def hgetall(self, key):
        self.calls.append("hgetall")
        return dict(self.meta.get(key, {}))

    def get(self, key):
        self.calls.append("get")
        return self.data.get(key)

    def strlen(self, key):
        self.calls.append("strlen")
        return len(self.data.get(key, b""))

    def smembers(self, key):
        self.calls.append("smembers")
        return set(self.kids.get(key, set()))

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self) -> None:
                self.ops = []

            def __getattr__(self, name):
                return lambda *a, **k: self.ops.append((name, a))

            def execute(self):
                outer.calls.append("pipeline")
                saved, outer.calls = outer.calls, []
                out = [getattr(outer, n)(*a) for n, a in self.ops]
                outer.calls = saved
                return out

        return _Pipe()


class RedisMetaTest(unittest.TestCase):
    def setUp(self) -> None:
        from core import redis_fs_client as RC

        self.RC = RC
        r = _FakeRedis()
        for path, data in (("/a.bin", b"x" * 1000), ("/e.bin", b"")):
            r.meta[RC._NS_META + path] = {b"parent": b"/", b"is_dir": b"0", b"mode": b"420",
                                          b"mtime": b"2026-01-01T00:00:00"}
            r.data[RC._NS_DATA + path] = data
        r.meta[RC._NS_META + "/d"] = {b"parent": b"/", b"is_dir": b"1", b"mode": b"493"}
        r.kids[RC._NS_KIDS + "/"] = {b"/a.bin", b"/e.bin", b"/d", b"/ghost"}
        self.r = r
        self.s = object.__new__(RC.RedisFsSession)
        self.s._client = r
        self.s._lock = mock.MagicMock()

    def test_happy_listing_equals_without_get_and_in_one_round_trip(self) -> None:
        paths = ["/a.bin", "/e.bin", "/d"]
        old_list, old_stat = _old_items(self.s, "/", paths)
        self.r.calls.clear()
        self.assertEqual(self.s.list_dir("/"), old_list)
        self.assertNotIn("get", self.r.calls)
        self.assertEqual(self.r.calls, ["smembers", "pipeline"])  # "/" needs no row
        self.assertEqual({p: self.s.stat(p) for p in paths}, old_stat)

    def test_sad_missing_and_ghost_children_are_skipped(self) -> None:
        self.assertNotIn("ghost", [i.name for i in self.s.list_dir("/")])
        with self.assertRaises(OSError):
            self.s.stat("/nope")

    def test_edge_stat_uses_strlen(self) -> None:
        self.r.calls.clear()
        self.assertEqual(self.s.stat("/e.bin").size, 0)
        self.assertNotIn("get", self.r.calls)


class MongoMetaTest(unittest.TestCase):
    def setUp(self) -> None:
        from core import mongo_fs_client as MC

        when = datetime(2026, 1, 1)

        class _Grid:
            def __init__(self, name, data):
                self.filename, self.length, self.upload_date = name, len(data), when
                self.metadata = {"parent": "/", "mode": 0o644}
                self._data = data

            def read(self):
                raise AssertionError("content read for metadata")

        self.files = [_Grid("/a.bin", b"x" * 1000), _Grid("/e.bin", b"")]
        files = self.files
        self.s = object.__new__(MC.MongoFsSession)
        self.s._lock = mock.MagicMock()
        self.s._dirs = SimpleNamespace(
            find_one=lambda q: {"path": "/d", "parent": "/", "mode": 0o755} if q["path"] == "/d" else None,
            find=lambda q: [{"path": "/d", "parent": "/", "mode": 0o755}] if q["parent"] == "/" else [],
        )
        self.s._fs = SimpleNamespace(
            find_one=lambda q: next((f for f in files if f.filename == q["filename"]), None),
            find=lambda q: [f for f in files if f.metadata["parent"] == q["metadata.parent"]],
        )

    def test_happy_stat_and_listing_give_real_sizes_without_reading(self) -> None:
        self.assertEqual(self.s.stat("/a.bin").size, 1000)
        self.assertEqual({i.name: i.size for i in self.s.list_dir("/")}, {"d": 0, "a.bin": 1000, "e.bin": 0})

    def test_sad_missing_path(self) -> None:
        with self.assertRaises(OSError):
            self.s.stat("/nope")

    def test_edge_directory_stat(self) -> None:
        self.assertTrue(self.s.stat("/d").is_dir)


if __name__ == "__main__":
    unittest.main()
