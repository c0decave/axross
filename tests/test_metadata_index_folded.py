"""Index Search: the casefolded name is stored, not worked out per row.

Measured before (200,000 rows): a name search called the Python SQL
function ``ax_casefold`` once per row - 630 ms for a rare name against
156 ms for a bare LIKE. Now the column ``name_folded`` holds
``ax_casefold(name)``, written with the row; an index of an older version
gets the column (and its values) on its first connection, and rows an
older version adds later are filled on the next one.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import metadata_index as MI  # noqa: E402

#: The table as versions before the folded column made it.
OLD_SCHEMA = """
CREATE TABLE metadata (
    backend_id TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0, is_dir INTEGER NOT NULL DEFAULT 0,
    extension TEXT NOT NULL DEFAULT '', modified TEXT, indexed_at TEXT NOT NULL,
    PRIMARY KEY (backend_id, path)
);
CREATE INDEX meta_by_name ON metadata(name);
"""


def _old_db(path: Path, names) -> Path:
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(OLD_SCHEMA)
        conn.executemany(
            "INSERT INTO metadata (backend_id, path, name, size, is_dir, extension, indexed_at) "
            "VALUES ('local', ?, ?, 1, 0, 'txt', '2026-11-08T00:00:00')",
            ((f"/data/{n}", n) for n in names))
    path.chmod(0o600)
    return path


def _folded(path: Path) -> dict[str, str | None]:
    with sqlite3.connect(str(path)) as conn:
        return dict(conn.execute("SELECT name, name_folded FROM metadata"))


# -- happy ------------------------------------------------------------------------------------


def test_happy_written_rows_carry_their_folded_name(tmp_path):
    db = tmp_path / "idx.sqlite"
    MI.upsert(db, "local", "/data/Straße.PDF", name="Straße.PDF", size=1, is_dir=False)
    MI.upsert(db, "local", "/data/Ärger.txt", name="Ärger.txt", size=1, is_dir=False)
    assert _folded(db) == {"Straße.PDF": "strasse.pdf", "Ärger.txt": "ärger.txt"}
    assert [e.name for e in MI.search("STRASSE", db_path=db)] == ["Straße.PDF"]
    assert [e.name for e in MI.search_all(needle="ärger", db_path=db)] == ["Ärger.txt"]


def test_happy_an_index_of_an_older_version_is_migrated_once(tmp_path):
    db = _old_db(tmp_path / "old.sqlite", ["Ärger.txt", "plain.txt", "100%.txt"])
    assert [e.name for e in MI.search("ärger", db_path=db)] == ["Ärger.txt"]
    assert _folded(db) == {"Ärger.txt": "ärger.txt", "plain.txt": "plain.txt",
                           "100%.txt": "100%.txt"}
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == MI._SCHEMA_VERSION
    assert [e.name for e in MI.search("100%", db_path=db)] == ["100%.txt"]
    assert MI.search("1_0", db_path=db) == []


# -- edge -------------------------------------------------------------------------------------


def test_edge_rows_an_older_version_adds_later_are_found(tmp_path):
    db = tmp_path / "idx.sqlite"
    MI.upsert(db, "local", "/data/a.txt", name="a.txt", size=1, is_dir=False)
    with sqlite3.connect(str(db)) as conn:  # an older axross: no name_folded
        conn.execute("INSERT INTO metadata (backend_id, path, name, size, is_dir, extension, "
                     "indexed_at) VALUES ('local', '/data/ÉCOLE.doc', 'ÉCOLE.doc', 1, 0, 'doc', "
                     "'2026-11-08T00:00:00')")
    assert [e.name for e in MI.search("école", db_path=db)] == ["ÉCOLE.doc"]
    assert _folded(db)["ÉCOLE.doc"] == "école.doc"


def test_edge_an_upsert_with_a_new_name_updates_the_folded_one(tmp_path):
    db = tmp_path / "idx.sqlite"
    MI.upsert(db, "local", "/data/x", name="Old.txt", size=1, is_dir=False)
    MI.upsert(db, "local", "/data/x", name="NEW.txt", size=2, is_dir=False)
    assert _folded(db) == {"NEW.txt": "new.txt"}
    assert MI.search("old", db_path=db) == []


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_column_added_by_another_process_meanwhile_is_no_error(tmp_path):
    db = _old_db(tmp_path / "old.sqlite", ["a.txt"])
    with sqlite3.connect(str(db)) as conn:
        conn.execute("ALTER TABLE metadata ADD COLUMN name_folded TEXT")  # user_version still 0
    assert [e.name for e in MI.search("A.TXT", db_path=db)] == ["a.txt"]


def test_sad_a_damaged_table_is_reported_not_hidden(tmp_path):
    db = tmp_path / "bad.sqlite"
    with sqlite3.connect(str(db)) as conn:
        conn.execute("CREATE TABLE metadata (x TEXT)")  # not an index at all
    db.chmod(0o600)
    with pytest.raises(sqlite3.OperationalError):
        MI.search("a", db_path=db)


# -- regression guard (counted) ---------------------------------------------------------------


def test_perf_happy_a_name_search_calls_no_python_per_row(tmp_path):
    db = tmp_path / "idx.sqlite"
    with MI._connect(db) as conn:
        conn.executemany(MI._UPSERT_SQL, (
            MI._checked_row("local", f"/data/f{i}.txt", name=f"f{i}.txt", size=1, is_dir=False)
            for i in range(3000)))
    calls = []
    real = MI._casefold
    with mock.patch.object(MI, "_casefold", lambda v: calls.append(v) or real(v)):
        hits = MI.search_all(needle="F29", db_path=db)
    assert len(hits) == 111  # f29, f290..f299, f2900..f2999
    assert len(calls) <= 1  # the needle; before: once per row (3000)
