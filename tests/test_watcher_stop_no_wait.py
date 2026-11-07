"""A folder change does not wait for the old folder's watcher.

Found by the second audit (feedback: no blocked windows): every
navigation stopped the pane's watcher and joined its thread for up to a
second - a polling watcher (every remote pane) spends that time in a
list_dir on the server. The pane no longer waits for it (only closing
the pane does, so no watcher thread outlives it), and a stopped watcher
reports nothing more - a poll under way when it stopped was about the
folder the pane left.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_APP = None


class SlowListing(LocalFS):
    """A server: listing takes a while (and a polling watcher is used)."""

    def __init__(self) -> None:
        super().__init__()
        self.listing = threading.Event()

    def list_dir(self, path):
        self.listing.set()
        time.sleep(0.8)
        return super().list_dir(path)


def test_happy_a_stop_without_waiting_returns_at_once_and_says_nothing_more(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    events: list = []
    fs = SlowListing()
    watcher = W.PollingWatcher(fs, str(tmp_path), lambda *e: events.append(e), interval=0.05,
                               initial_entries=fs.__class__.__mro__[1].list_dir(fs, str(tmp_path)))
    watcher.start()
    assert fs.listing.wait(3)  # a poll is under way
    (tmp_path / "new.txt").write_text("n")  # it will see this
    start = time.perf_counter()
    watcher.stop(timeout=0.0)
    assert time.perf_counter() - start < 0.1
    time.sleep(1.2)  # the poll ends after the stop
    assert events == []


def test_happy_the_pane_moves_on_without_waiting_for_the_poll(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from ui.file_pane import FilePaneWidget

    global _APP  # held: a QApplication nobody references is collected at once
    _APP = QApplication.instance() or QApplication([])
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    fs = SlowListing()
    pane = FilePaneWidget(fs)
    try:
        pane.navigate(str(tmp_path / "one"))
        pane._watch_enabled = True
        pane._watcher = W.PollingWatcher(fs, str(tmp_path / "one"), lambda *e: None,
                                         interval=0.05, initial_entries=[])
        pane._watcher.start()
        pane._watched_path = str(tmp_path / "one")
        assert fs.listing.wait(3)
        start = time.perf_counter()
        pane._stop_watcher()
        assert time.perf_counter() - start < 0.1
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_edge_closing_the_pane_still_waits_for_its_watcher(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from ui.file_pane import FilePaneWidget

    global _APP  # held: a QApplication nobody references is collected at once
    _APP = QApplication.instance() or QApplication([])
    fs = LocalFS()
    pane = FilePaneWidget(fs)
    pane.navigate(str(tmp_path))
    watcher = W.PollingWatcher(fs, str(tmp_path), lambda *e: None, interval=0.05,
                               initial_entries=[])
    watcher.start()
    pane._watcher, pane._watched_path = watcher, str(tmp_path)
    thread = watcher._thread
    pane.shutdown()
    assert not thread.is_alive()
    pane.deleteLater()
