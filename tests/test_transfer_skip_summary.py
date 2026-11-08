"""A copy or move says in the status bar what it skipped.

Review round 3: F6 of three entries whose names were all taken, answered
"Skip" for all, moved nothing and said nothing - the skips were only
logged (``core.transfer_manager``: "Transfer skipped (destination kept)").
"Overwrite if Newer" on files whose destination was not older ended the
same way: done rows or no rows, no reason.

Now the window sums the operation up in the status bar once its jobs have
ended: "2 copied, 1 skipped (destination kept)", "3 skipped (destinations
not older)", failures counted too.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_conflicts import ConflictAction  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    for pane in list(window._panes)[1:]:
        window._close_pane(pane)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    left = window._panes[0]
    left.navigate(str(a))
    right = window._add_pane_to_splitter(window._root_splitter, LocalFS())
    right.navigate(str(b))
    window.test_ctx = {"a": a, "b": b, "left": left, "right": right}
    yield window
    _wait(lambda: window._transfer_manager.unfinished() == 0)
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _answer(monkeypatch, action) -> None:
    import ui.transfer_conflict_dialog as TCD

    def fake_exec(self):
        self.apply_all.setChecked(True)
        self.buttons[action].click()
        return 1

    monkeypatch.setattr(TCD.TransferConflictDialog, "exec", fake_exec)


def _run(win, names, move=False) -> str:
    ctx = win.test_ctx
    win.statusBar().clearMessage()
    win._request_transfer(ctx["left"], ctx["right"], [str(ctx["a"] / n) for n in names],
                          move=move)
    assert _wait(lambda: not win._conflict_checks and not win._transfer_manager._walks
                 and win._transfer_manager.unfinished() == 0 and not win._transfer_summaries
                 and win.statusBar().currentMessage() != "")
    return win.statusBar().currentMessage()


def test_happy_a_copy_says_what_it_copied_and_what_it_kept(win, monkeypatch):
    ctx = win.test_ctx
    for name in ("one.txt", "two.txt", "new.txt"):
        (ctx["a"] / name).write_text("new " + name)
    (ctx["b"] / "one.txt").write_text("old")
    _answer(monkeypatch, ConflictAction.SKIP)
    assert _run(win, ["one.txt", "two.txt", "new.txt"]) == "2 copied, 1 skipped (destination kept)"
    assert (ctx["b"] / "one.txt").read_text() == "old"


def test_sad_a_move_that_skips_everything_says_so(win, monkeypatch):
    ctx = win.test_ctx
    for name in ("x.txt", "y.txt"):
        (ctx["a"] / name).write_text("mine")
        (ctx["b"] / name).write_text("theirs")
    _answer(monkeypatch, ConflictAction.SKIP)
    assert _run(win, ["x.txt", "y.txt"], move=True) == "0 moved, 2 skipped (destinations kept)"
    assert (ctx["a"] / "x.txt").exists()


def test_edge_overwrite_if_newer_names_the_destinations_it_kept(win, monkeypatch):
    """The scan saw the source as newer by a fraction of a second; the job
    found the destination not older in whole seconds and kept it."""
    ctx = win.test_ctx
    for i, name in enumerate(("f0.txt", "f1.txt")):
        (ctx["a"] / name).write_text("same")
        (ctx["b"] / name).write_text("same")
        os.utime(ctx["a"] / name, (1_700_000_000.6 + i, 1_700_000_000.6 + i))
        os.utime(ctx["b"] / name, (1_700_000_000 + i, 1_700_000_000 + i))
    _answer(monkeypatch, ConflictAction.OVERWRITE_IF_NEWER)
    assert _run(win, ["f0.txt", "f1.txt"]) == "0 copied, 2 skipped (destinations not older)"
