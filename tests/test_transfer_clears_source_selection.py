"""After a copy or move is queued, its entries are no longer marked in the
source pane. Before: after F5 the copied files stayed selected, and the next
F5 or Delete took them again without the user noticing. Rows that were not
part of the transfer keep their mark; a cancelled transfer keeps them all."""

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
    for name in ("one.txt", "two.txt", "three.txt"):
        (a / name).write_text(name)
    left = window._panes[0]
    left.navigate(str(a))
    right = window._add_pane_to_splitter(window._root_splitter, LocalFS())
    right.navigate(str(b))
    assert _wait(lambda: left._model.rowCount() >= 3)
    window.test_ctx = {"a": a, "b": b, "left": left, "right": right}
    yield window
    _wait(lambda: window._transfer_manager.unfinished() == 0)
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _selected_names(pane) -> set[str]:
    return {os.path.basename(p) for p in pane.selected_items()}


def _settle(win) -> None:
    assert _wait(lambda: not win._conflict_checks and not win._transfer_manager._walks
                 and win._transfer_manager.unfinished() == 0)


def test_happy_the_copied_entries_are_no_longer_selected(win):
    ctx = win.test_ctx
    left = ctx["left"]
    left._select_all()
    assert _selected_names(left) == {"one.txt", "two.txt", "three.txt"}
    win._request_transfer(left, ctx["right"], [str(ctx["a"] / "one.txt"),
                                               str(ctx["a"] / "two.txt")])
    _settle(win)
    assert (ctx["b"] / "one.txt").exists() and (ctx["b"] / "two.txt").exists()
    assert _selected_names(left) == {"three.txt"}


def test_sad_a_cancelled_copy_keeps_the_selection(win, monkeypatch):
    ctx = win.test_ctx
    left = ctx["left"]
    (ctx["b"] / "one.txt").write_text("taken")
    monkeypatch.setattr(win, "_resolve_transfer_conflicts", lambda *_a, **_k: None)
    left._select_all()
    win._request_transfer(left, ctx["right"], [str(ctx["a"] / "one.txt")])
    _settle(win)
    assert _selected_names(left) == {"one.txt", "two.txt", "three.txt"}
