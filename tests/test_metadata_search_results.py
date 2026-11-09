"""Find in Index: the search runs off the GUI thread and shows at most
RESULT_LIMIT matches.

What was wrong: ``_do_search`` ran the SQLite query on the GUI thread
(the window froze for the whole query) and ``_populate`` inserted every
match one ``insertRow`` at a time - a search for "" in a large index
filled the table with every row and froze the window for minutes. Now
the query runs on a ScanJob with ``limit=RESULT_LIMIT + 1``, the table is
filled in one pass, and the status says when there were more matches.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import metadata_index as MX  # noqa: E402
from ui import metadata_search_dialog as MSD  # noqa: E402

APP = QApplication.instance() or QApplication([])
LIMIT = 5000


def _entries(n: int) -> list:
    when = datetime(2026, 11, 8)
    return [MX.MetaEntry("local", f"/d/f{i}.txt", f"f{i}.txt", i, False, "txt", when, when) for i in range(n)]


def _wait(cond, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def dialog(monkeypatch):
    monkeypatch.setattr(MX, "row_count", lambda db_path=None: 123_456)
    dlg = MSD.MetadataSearchDialog()
    yield dlg
    dlg.reject()
    dlg.deleteLater()


def test_sad_more_matches_than_the_limit_are_cut_and_said(dialog, monkeypatch):
    """Every match went into the table; now the first RESULT_LIMIT, and the
    status says there are more. The query asks for one more than it shows."""
    asked = {}

    def search_all(**kw):
        asked.update(kw)
        return _entries(min(kw.get("limit") or 10**9, LIMIT + 300))
    monkeypatch.setattr(MX, "search_all", search_all)
    dialog._do_search()
    assert _wait(lambda: dialog._table.rowCount() > 0)
    assert dialog._table.rowCount() == LIMIT
    assert asked["limit"] == LIMIT + 1
    # UX round 7 (L3): one separator convention - "→" in menu paths, "–" as dash.
    assert dialog._status.text().startswith(
        f"Showing the first {MSD.format_count(LIMIT)} matches – there are more; narrow the search.")
    assert dialog._table.item(LIMIT - 1, 0).text() == f"f{LIMIT - 1}.txt"


def test_sad_the_query_does_not_block_the_window(dialog, monkeypatch):
    """_do_search waited for SQLite on the GUI thread."""
    release = threading.Event()

    def slow(**kw):
        release.wait(3)
        return _entries(3)
    monkeypatch.setattr(MX, "search_all", slow)
    start = time.monotonic()
    dialog._do_search()
    assert time.monotonic() - start < 1.0
    assert dialog._table.rowCount() == 0
    release.set()
    assert _wait(lambda: dialog._table.rowCount() == 3)
    assert "3 matches" in dialog._status.text() and "there are more" not in dialog._status.text()


def test_edge_a_newer_search_replaces_the_running_one(dialog, monkeypatch):
    """Two searches in a row: only the newer one's matches are shown."""
    first_running = threading.Event()
    release = threading.Event()
    calls = []

    def search_all(**kw):
        calls.append(kw.get("needle"))
        if kw.get("needle") == "old":
            first_running.set()
            release.wait(3)
            return _entries(7)
        return _entries(2)
    monkeypatch.setattr(MX, "search_all", search_all)
    start = time.monotonic()
    dialog._needle_edit.setText("old")
    dialog._do_search()
    assert first_running.wait(3)
    dialog._needle_edit.setText("new")
    dialog._do_search()
    assert _wait(lambda: dialog._table.rowCount() == 2)
    assert time.monotonic() - start < 2.0      # not after the old search's 3 s
    release.set()
    _wait(lambda: False, 0.3)
    assert dialog._table.rowCount() == 2 and calls == ["old", "new"]
