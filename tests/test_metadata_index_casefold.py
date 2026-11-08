"""Index Search: non-ASCII names, a result limit, a stoppable query.

What was wrong: the name filter was ``LOWER(name) LIKE ?`` - SQLite's
LOWER and LIKE fold ASCII only, so "ärger" did not find "Ärger.txt",
"école" not "ÉCOLE.doc", "strasse" not "Straße.pdf" (the GUI's Index
Search and the MCP ``search`` tool alike). And every match came back:
a search for "" listed the whole index. Now an ``ax_casefold`` SQL
function (NFC + str.casefold) is on every connection, ``search_all`` takes
a ``limit`` and a ``cancel``.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import metadata_index as MX  # noqa: E402

NAMES = ("Ärger.txt", "ÉCOLE.doc", "Straße.pdf", "plain.txt", "Äpfel.txt")   # the last one decomposed


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "idx.sqlite"
    for name in NAMES:
        MX.upsert(path, "local", f"/data/{name}", name=name, size=1, is_dir=False)
    return path


@pytest.mark.parametrize("needle, found", [
    ("ärger", "Ärger.txt"), ("ÄRGER", "Ärger.txt"), ("école", "ÉCOLE.doc"),
    ("strasse", "Straße.pdf"), ("STRASSE", "Straße.pdf"), ("äpfel", "Äpfel.txt"),
])
def test_sad_non_ascii_names_are_found_case_insensitively(db, needle, found):
    """LOWER/LIKE folded ASCII only: these found nothing."""
    assert [e.name for e in MX.search_all(needle=needle, db_path=db)] == [found]
    assert [e.name for e in MX.search(needle, db_path=db)] == [found]


def test_happy_limit_caps_the_result_and_like_wildcards_stay_literal(db):
    """There was no limit: every row of the index came back."""
    assert len(MX.search_all(db_path=db)) == len(NAMES)
    assert len(MX.search_all(db_path=db, limit=2)) == 2
    MX.upsert(db, "local", "/data/100%.txt", name="100%.txt", size=1, is_dir=False)
    assert [e.name for e in MX.search_all(needle="100%", db_path=db)] == ["100%.txt"]
    assert MX.search_all(needle="1_0", db_path=db) == []


def test_edge_a_cancelled_query_is_interrupted(db):
    """The dialog's search runs on a worker; Close or a new search stops it
    while SQLite is still reading (it ran to its end)."""
    with MX._connect(db) as conn:
        conn.executemany(
            "INSERT INTO metadata (backend_id, path, name, size, is_dir, extension, indexed_at) "
            "VALUES ('local', ?, ?, 1, 0, 'txt', '2026-11-08T00:00:00')",
            ((f"/data/f{i}.txt", f"f{i}.txt") for i in range(60_000)))
    polls = []

    def cancel() -> bool:
        polls.append(1)
        return len(polls) > 1          # the first poll goes on, the next one stops
    with pytest.raises(sqlite3.OperationalError):
        MX.search_all(needle="zz", db_path=db, cancel=cancel)
    assert len(polls) == 2
    assert len(MX.search_all(needle="f1", db_path=db, cancel=lambda: False, limit=10)) == 10


def test_sad_the_mcp_search_tool_folds_non_ascii_names(db):
    """The MCP ``search`` tool went through the same LOWER/LIKE."""
    from core import mcp_server as M
    from core.local_fs import LocalFS

    tools = M._build_tools(LocalFS(), allow_write=False, backend_id="local", root="/data")
    tool = next(t for t in tools if t.name == "search")
    real = MX.search_all
    with mock.patch.object(MX, "search_all", lambda **kw: real(**{**kw, "db_path": db})), \
            mock.patch("os.path.realpath", side_effect=lambda p, **k: os.path.normpath(p)):
        rows = tool.handler({"needle": "ärger"}, M._ToolContext())
    assert [r["name"] for r in rows] == ["Ärger.txt"]
