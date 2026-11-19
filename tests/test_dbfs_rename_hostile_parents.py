"""DB filesystems (SQLite, PostgreSQL, ...): rename() of a folder whose
rows lie about their parent, and SQLite schema() of an odd table name
(review round 2).

* A row whose ``parent`` is its own path (or a row of another folder that
  names this one as its parent) made the subtree walk of rename() call
  itself until RecursionError - out of the transaction, a traceback; a
  row of /x/y claiming parent /a was moved to /b/y and deleted at /x/y.
  Only rows whose path is directly under the folder are its children.
* ``PRAGMA table_info(my table)``: a table name with a blank or a quote
  (any name the file holds) was a syntax error; it is quoted now.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.sqlite_fs_client import SqliteFsSession  # noqa: E402


@pytest.fixture
def db(tmp_path):
    s = SqliteFsSession(str(tmp_path / "fs.sqlite"))
    yield s, tmp_path / "fs.sqlite"
    s.close()


def _raw(path, sql, *args):
    conn = sqlite3.connect(path)
    conn.execute(sql, args)
    conn.commit()
    conn.close()


def test_sad_rename_of_a_folder_that_is_its_own_parent(db) -> None:
    s, file = db
    s.mkdir("/a")
    s.mkdir("/a/sub")
    with s.open_write("/a/sub/f.txt") as fh:
        fh.write(b"x")
    _raw(file, "UPDATE axross_files SET parent = path WHERE path = '/a'")
    s.rename("/a", "/b")
    assert s.open_read("/b/sub/f.txt").read() == b"x"
    assert not s.exists("/a/sub/f.txt")


def test_sad_rename_never_moves_a_row_of_another_folder(db) -> None:
    s, file = db
    s.mkdir("/a")
    s.mkdir("/x")
    with s.open_write("/x/keep.txt") as fh:
        fh.write(b"keep")
    _raw(file, "UPDATE axross_files SET parent = '/a' WHERE path = '/x/keep.txt'")
    s.rename("/a", "/b")
    rows = {r[0] for r in sqlite3.connect(file).execute("SELECT path FROM axross_files")}
    assert "/x/keep.txt" in rows and "/b/keep.txt" not in rows


def test_edge_rename_of_a_deep_tree(db) -> None:
    s, _file = db
    path = ""
    for _ in range(1200):
        path += "/d"
        s.mkdir(path)
    s.rename("/d", "/e")
    assert s.exists("/e" + "/d" * 1199)


@pytest.mark.parametrize("name", ["my table", 'we"ird', "a)b"])
def test_sad_schema_of_an_odd_table_name(db, name) -> None:
    s, file = db
    quoted = '"' + name.replace('"', '""') + '"'
    _raw(file, f"CREATE TABLE {quoted} (col INTEGER)")
    assert [c["name"] for c in s.schema(name)] == ["col"]
