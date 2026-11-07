"""A change the pane listed already is not listed again for the watcher.

Measured on 2026-11-02: every New Folder or Rename in a watched folder
listed it twice - the operation's own refresh, and 250 ms later the
watcher's report of the same change (on a server: one more list_dir round
trip per operation). A late report also landed after a refresh and threw
away what was shown since: tests/test_dir_size_results.py lost its
calculated sizes that way in parallel runs. The watcher's refresh now
runs only for a change reported after the listing shown was asked for:
an operation lists its folder once whenever the watcher's report came
before the operation's refresh began (7 of 8 New Folders here; a later
report still refreshes, it may be a change of its own). A change made by
another program is shown as before.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QInputDialog  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class CountingFS(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.listings = 0

    def list_dir(self, path):
        self.listings += 1
        return super().list_dir(path)


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


def _names(pane) -> set[str]:
    proxy = pane._proxy
    return {proxy.index(r, 0).data() for r in range(proxy.rowCount())}


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "a.txt").write_text("a")
    p = FilePaneWidget(CountingFS())
    p.navigate(str(tmp_path))
    pump(1.0)  # the watcher is up
    p._backend.listings = 0
    yield p
    p.shutdown()
    p.deleteLater()


def _wait_for_report(pane, before: int) -> None:
    """Until the watcher thread has reported a change (nothing pumped: its
    report waits in the GUI thread's queue)."""
    deadline = time.monotonic() + 10
    while pane._watch_report == before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pane._watch_report != before


def test_happy_an_operations_refresh_after_the_report_lists_the_folder_once(pane, tmp_path):
    """What New Folder, Rename and the others do: change the folder, then
    refresh_after_change(). When the watcher reported the change before that
    refresh began, its own refresh is left out. (A report that comes later
    still refreshes - it may be a change of its own.)"""
    before = pane._watch_report
    (tmp_path / "made").mkdir()
    _wait_for_report(pane, before)
    pane.refresh_after_change()
    pump(2.0)
    assert "made" in _names(pane)
    assert pane._backend.listings == 1


def test_happy_e2e_new_folder_lists_the_folder_at_most_twice(pane, tmp_path):
    with mock.patch.object(QInputDialog, "getText", return_value=("made", True)):
        pane._create_folder()
        pump(2.0)  # the operation, its refresh and the watcher's report
    assert (tmp_path / "made").is_dir() and "made" in _names(pane)
    assert 1 <= pane._backend.listings <= 2


def test_sad_a_change_by_another_program_is_still_shown(pane, tmp_path):
    (tmp_path / "from-elsewhere.txt").write_text("x")
    deadline = time.monotonic() + 10
    while "from-elsewhere.txt" not in _names(pane) and time.monotonic() < deadline:
        pump(0.05)
    assert "from-elsewhere.txt" in _names(pane)
    assert pane._backend.listings >= 1


def test_edge_a_report_older_than_the_refresh_lists_nothing_more(pane, tmp_path):
    """The case of the size test: a change, a refresh that shows it, and
    the watcher's report of it arriving after the refresh."""
    before = pane._watch_report
    (tmp_path / "empty").mkdir()
    _wait_for_report(pane, before)  # delivered during the refresh
    pane.refresh()
    assert "empty" in _names(pane)
    pump(2.0)
    assert pane._backend.listings == 1


class _HeldFS(CountingFS):
    """A server whose listing can be held while the test changes the folder."""

    def __init__(self) -> None:
        super().__init__()
        import threading

        self.gate = threading.Event()
        self.gate.set()

    def list_dir(self, path):
        self.gate.wait(10)
        return super().list_dir(path)


def test_sad_a_change_reported_while_the_folder_is_listed_is_shown(tmp_path):
    """Found in review (0.14.245): a report that came while a load was
    running was dropped - the debounce found the pane loading - and a change
    made after the server had listed the folder stayed unseen. Since then
    the report is numbered, and a listing shown with a report newer than
    its start is looked at again."""
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(_HeldFS())
    try:
        pane.navigate(str(tmp_path))
        pump(1.0)
        pane._backend.gate.clear()
        pane.refresh_async()  # held inside list_dir
        pump(0.2)
        assert pane.is_loading
        (tmp_path / "late.txt").write_text("x")  # after the listing began
        pane._note_watch_report()  # the watcher's report of it
        pane._on_debounce_fired()  # while loading: nothing yet
        pane._backend.gate.set()
        deadline = time.monotonic() + 10
        while "late.txt" not in _names(pane) and time.monotonic() < deadline:
            pump(0.05)
        assert "late.txt" in _names(pane)
    finally:
        pane._backend.gate.set()
        pane.shutdown()
        pane.deleteLater()


def test_edge_a_report_numbered_after_the_listing_began_refreshes_in_the_same_tick(pane, tmp_path):
    """Found in review (0.14.245): with times, a report in the same clock tick
    as the listing's start (Windows, Python 3.12: 15.6 ms ticks) counted as
    older and the change was never shown. Report numbers have no ticks."""
    listed_after = pane._shown_listing_after
    (tmp_path / "same-tick.txt").write_text("x")
    pane._note_watch_report()
    assert pane._watch_report > listed_after
    pane._on_debounce_fired()
    assert pane.is_loading  # it refreshes
    deadline = time.monotonic() + 10
    while "same-tick.txt" not in _names(pane) and time.monotonic() < deadline:
        pump(0.05)
    assert "same-tick.txt" in _names(pane)
