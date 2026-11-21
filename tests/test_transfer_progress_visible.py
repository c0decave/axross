"""A running folder copy is in sight while the Transfers dock is closed.

Reported: a folder copy showed its folders at once and the files minutes
later; with the Transfers dock closed nothing said that the copy was still
running, and the files looked lost. While the folders were walked and the
jobs queued not even the dock showed anything ("No transfers yet").

Now the window's status bar holds "Preparing: 3,210 files queued…", then
"Copying 1,210 of 10,000 files – 12 %" (a click opens the Transfers dock)
until the copy ends; the destination pane's status line says "Copy in
progress: 1,210 of 10,000" with a thin bar; and the dock says "Preparing:
… files queued…" and then "12 % – 1,210 of 10,000 files".
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 30.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return False


class _GatedFS(LocalFS):
    """LocalFS whose listing of the folder ``late`` waits for *listing*,
    and whose reads wait for *reading* once *free_reads* files were read."""

    def __init__(self) -> None:
        super().__init__()
        self.listing = threading.Event()
        self.reading = threading.Event()
        self.free_reads = 3
        self._reads = 0

    def list_dir(self, path):
        if os.path.basename(path) == "late":
            self.listing.wait(30)
        return super().list_dir(path)

    def open_read(self, path):
        self._reads += 1
        if self._reads > self.free_reads:
            self.reading.wait(30)
        return super().open_read(path)


@pytest.fixture
def window(tmp_path, monkeypatch):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    win._quit_with_transfers = True
    for pane in list(win._panes)[1:]:
        win._close_pane(pane)
    win._transfer_dock.hide()  # the user closed the Transfers dock
    yield win
    win._transfer_manager.cancel_all()
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _setup(win, tmp_path):
    src_root, dst = tmp_path / "a", tmp_path / "b"
    proj = src_root / "proj"
    for d in ("early", "late"):
        (proj / d).mkdir(parents=True)
        for i in range(10):
            (proj / d / f"f{i}.txt").write_text(f"{d} {i}")
    dst.mkdir()
    fs = _GatedFS()
    left = win._add_pane_to_splitter(win._root_splitter, fs)
    left.navigate(str(src_root))
    right = win._add_pane_to_splitter(win._root_splitter, LocalFS())
    right.navigate(str(dst))
    return fs, left, right, proj, dst


def _status_item(win) -> str:
    button = win._transfer_progress.button
    return button.text().replace("&&", "&") if not button.isHidden() else ""


def test_happy_the_status_bar_and_the_pane_show_a_running_copy(window, tmp_path):
    win = window
    fs, left, right, proj, dst = _setup(win, tmp_path)
    win._request_transfer(left, right, [str(proj)])

    # The walk waits in "late": folders are made, no file job shows yet.
    assert _wait(lambda: "Preparing" in _status_item(win)), _status_item(win)
    assert "files queued" in _status_item(win) or "file queued" in _status_item(win)
    assert "preparing" in right.transfer_progress_text()
    assert win._transfer_dock.isHidden()

    fs.listing.set()
    # Three files go through, the fourth waits: the copy is half done.
    assert _wait(lambda: "Copying 3 of 20 files" in _status_item(win)), _status_item(win)
    assert "%" in _status_item(win)
    assert _wait(lambda: right.transfer_progress_text() == "Copy in progress: 3 of 20"), \
        right.transfer_progress_text()
    assert not right._transfer_bar.isHidden()

    # A click on the item opens the Transfers dock.
    win._transfer_progress.button.click()
    assert not win._transfer_dock.isHidden()
    win._transfer_dock.hide()

    fs.reading.set()
    assert _wait(lambda: win._transfer_manager.unfinished() == 0
                 and not win._transfer_progress.running())
    assert _wait(lambda: _status_item(win) == "")
    assert right.transfer_progress_text() == ""
    assert sorted(p.name for p in (dst / "proj" / "late").iterdir()) == \
        sorted(f"f{i}.txt" for i in range(10))
    # The summary the window gives at the end is still there.
    assert "20 copied" in win.statusBar().currentMessage()


def test_happy_the_dock_says_files_are_still_being_queued(window, tmp_path):
    win = window
    fs, left, right, proj, _dst = _setup(win, tmp_path)
    dock = win._transfer_dock
    win._request_transfer(left, right, [str(proj)])
    assert _wait(lambda: win._transfer_manager.preparing() is not None)
    assert _wait(lambda: dock._overall_progress.format().startswith("Preparing:")), \
        dock._overall_progress.format()
    assert not dock.idle  # not "No transfers yet"
    fs.listing.set()
    assert _wait(lambda: " of 20 files" in dock._overall_progress.format()), \
        dock._overall_progress.format()
    fs.reading.set()
    assert _wait(lambda: win._transfer_manager.unfinished() == 0)


def test_edge_the_texts_in_german(monkeypatch):
    from core import i18n
    from ui.transfer_dock import files_text, preparing_text

    i18n.install("de")
    try:
        assert preparing_text(3210, None) == "Vorbereitung: 3.210 Dateien eingereiht…"
        assert preparing_text(3210, 10000) == "Vorbereitung: 3.210 von 10.000 Dateien eingereiht"
        assert files_text(12, 1210, 10000) == "12 % – 1.210 von 10.000 Dateien"
    finally:
        i18n.install("en")


def test_edge_no_signal_per_file_reaches_the_status_bar(window, tmp_path):
    """The item is redrawn by a timer (about 4 a second), not per file."""
    from ui import transfer_progress as TP

    assert TP.INTERVAL_MS >= 200
    tracker = window._transfer_progress
    assert tracker._timer.interval() == TP.INTERVAL_MS


def test_edge_the_status_bar_item_does_not_make_the_bar_taller(window):
    """QStatusBar takes the height of every permanent widget, a hidden one
    too: the item as a plain push button made the bar 9 px taller for good
    (the panes lost that height and a vertical split was refused, "no room":
    tests/test_layout_preset_root_splitter.py). It is drawn as text, as the
    version beside it."""
    bar = window.statusBar()
    item = window._transfer_progress.button
    APP.processEvents()
    hidden = bar.sizeHint().height()
    item.setText("Copying 1,210 of 10,000 files – 12 %")
    item.show()
    APP.processEvents()
    shown = bar.sizeHint().height()
    item.hide()
    bar.removeWidget(item)
    APP.processEvents()
    without = bar.sizeHint().height()
    assert hidden == without, (hidden, without)
    assert shown == without, (shown, without)


def test_edge_the_pane_progress_needs_no_room_of_its_own(window):
    """The destination pane's "Copy in progress" line fits in the status row
    as it is: a plain label widened the pane's least width by its text,
    which can refuse a split or widen the window while a copy runs."""
    pane = window._panes[0]
    APP.processEvents()
    before = pane.minimumSizeHint()
    pane.show_transfer_progress("Copy in progress: 1,210,000 of 10,000,000 files – a long text", 12)
    APP.processEvents()
    assert pane.minimumSizeHint() == before
    assert pane.transfer_progress_text().startswith("Copy in progress")
    pane.show_transfer_progress("")
    assert pane.transfer_progress_text() == ""
