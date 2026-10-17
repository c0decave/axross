"""SQLite-FS and what other clients put into the table, and what the
database itself fails with.

SQLite types per value, not per column: a ``mode`` of 'rw-r--r--' or a
``content`` of TEXT is a legal row in the INTEGER / BLOB columns. The
adapter ran ``int(mode)`` and ``bytes(content)`` on every row, so one
such row made list_dir / stat / open_read / exists of its folder raise
ValueError or TypeError. And sqlite3.Error ("database is locked", a
corrupt file) is no OSError: the session named no driver errors, so it
escaped every caller that handles OSError. Measured 2026-10-17.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sqlite_fs_client import SqliteFsSession  # noqa: E402


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "fs.db"
    session = SqliteFsSession(str(path))
    yield session, path
    session.close()


def _foreign(path, sql, *params):
    conn = sqlite3.connect(path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


_ROW = (
    "INSERT INTO axross_files (path, parent, is_dir, mode, mtime, content) "
    "VALUES (?, '/', 0, ?, ?, ?)"
)


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_row_with_a_text_mode_is_listed_with_the_default_mode(db):
    session, path = db
    _foreign(path, _ROW, "/odd.txt", "rw-r--r--", "2026-01-01T00:00:00+00:00", b"\x00\x01")
    (item,) = session.list_dir("/")
    assert (item.name, item.size, item.permissions) == ("odd.txt", 2, 0o644)
    assert session.stat("/odd.txt").permissions == 0o644
    assert session.exists("/odd.txt")
    assert session.open_read("/odd.txt").read() == b"\x00\x01"


def test_happy_a_locked_database_is_an_oserror(db):
    session, path = db
    session._conn.execute("PRAGMA busy_timeout = 100")
    other = sqlite3.connect(path, isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(OSError, match="locked"):
            session.mkdir("/d")
        with pytest.raises(OSError, match="locked"):
            session.list_dir("/")
    finally:
        other.execute("ROLLBACK")
        other.close()


# -- sad -----------------------------------------------------------------------------------


def test_sad_content_that_is_a_number_is_an_oserror_on_read_only(db):
    session, path = db
    _foreign(path, _ROW, "/num.txt", 420, "2026-01-01", 12345)
    assert [i.name for i in session.list_dir("/")] == ["num.txt"]
    with pytest.raises(OSError, match="not bytes"):
        session.open_read("/num.txt")


def test_sad_a_write_that_the_lock_refuses_fails_on_close(db):
    session, path = db
    session._conn.execute("PRAGMA busy_timeout = 100")
    writer = session.open_write("/w.txt")
    writer.write(b"data")
    other = sqlite3.connect(path, isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(OSError, match="locked"):
            writer.close()
    finally:
        other.execute("ROLLBACK")
        other.close()
    assert not session.exists("/w.txt")


# -- edge ----------------------------------------------------------------------------------


def test_edge_text_content_reads_as_its_utf8_bytes_and_sizes_alike(db):
    session, path = db
    _foreign(path, _ROW, "/t.txt", 420, "2026-01-01", "grüße")
    (item,) = session.list_dir("/")
    data = session.open_read("/t.txt").read()
    assert data == "grüße".encode("utf-8") and item.size == len(data)


def test_edge_a_foreign_row_can_be_copied_and_renamed(db):
    session, path = db
    _foreign(path, _ROW, "/odd.txt", "rw-r--r--", "x", "text body")
    session.copy("/odd.txt", "/copy.txt")
    session.rename("/odd.txt", "/moved.txt")
    assert sorted(i.name for i in session.list_dir("/")) == ["copy.txt", "moved.txt"]
    assert session.open_read("/copy.txt").read() == b"text body"
    assert session.stat("/moved.txt").permissions == 0o644


# -- the twin in DbFsBackend: copy / rename / overwrite carry a stored mode ----------------
# Mongo and Redis are schemaless: a foreign row's mode can be any value, and
# their _db_insert runs int(mode) (core/mongo_fs_client.py, core/redis_fs_client.py)
# - a ValueError, no driver error, out of copy and rename.


def _dict_backend(stored_mode):
    from core.db_fs_base import DbFsBackend

    class Store(DbFsBackend):
        def __init__(self):
            self.rows = {
                "/odd.txt": {
                    "path": "/odd.txt",
                    "parent": "/",
                    "is_dir": False,
                    "mode": stored_mode,
                    "mtime": None,
                    "content": b"body",
                }
            }

        def _db_get(self, path):
            row = self.rows.get(path)
            return dict(row) if row else None

        def _db_list(self, parent):
            return [dict(r) for r in self.rows.values() if r["parent"] == parent]

        def _db_insert(self, row):
            row = dict(row, mode=int(row.get("mode") or 0o644))  # as Mongo's and Redis' adapters do
            self.rows[row["path"]] = row

        def _db_update(self, path, **fields):
            self.rows[path].update(fields)

        def _db_delete(self, path):
            self.rows.pop(path, None)

        def _db_delete_subtree(self, path):
            for key in [k for k in self.rows if k == path or k.startswith(path + "/")]:
                del self.rows[key]

    return Store()


@pytest.mark.parametrize("stored", ["rw-r--r--", None, -1, 3.5, "0o600"])
def test_edge_copy_rename_and_overwrite_of_a_foreign_mode_work_in_every_db_backend(stored):
    store = _dict_backend(stored)
    store.copy("/odd.txt", "/copy.txt")
    store.rename("/odd.txt", "/moved.txt")
    with store.open_write("/moved.txt") as handle:
        handle.write(b"new")
    expected = 0o600 if stored == "0o600" else 0o644
    assert store.rows["/copy.txt"]["mode"] == expected
    assert store.stat("/moved.txt").permissions == expected
    assert store.open_read("/moved.txt").read() == b"new"
