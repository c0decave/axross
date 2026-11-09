"""Every move off a production connection asks the countdown first.

Before: only the pane's context-menu "Move to Target" and Paste called the
production gate (``FilePaneWidget._production_ok``). The window-wide F6
shortcut and the toolbar's Move to Target (``MainWindow._move_files``), a
plain drag & drop (a move by default, ``_on_drop_transfer``) and Delete in
the image or media viewer (``ui.viewer_file_actions.delete_file``) went
straight to the move or the delete - files left the production server
without the countdown its profile promised.

Now the gate is in the one place every move passes
(``MainWindow._request_transfer`` with ``move=True``), the pane's menu
entry no longer asks a second time, and the viewers' Delete asks
``confirm_production`` after its question.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox  # noqa: E402

from core import safety_tarpit  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from ui import production_gate as PG  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _fresh_tarpit(monkeypatch):
    monkeypatch.delenv(safety_tarpit.ENV_DISABLE, raising=False)
    safety_tarpit.reset_all()
    yield
    safety_tarpit.reset_all()


def _make_production(fs) -> None:
    fs._axross_profile = ConnectionProfile(
        name="prod-box", protocol="sftp", host="prod.example", production=True
    )
    fs._axross_profile_key = f"key-{id(fs)}"


def _countdown(monkeypatch, answer: int) -> list[str]:
    """The countdown dialog answers *answer* at once; the operations it
    was shown for are returned."""
    shown: list[str] = []
    real_init = PG.ProductionCountdownDialog.__init__

    def init(self, label, op_desc, seconds, parent=None):
        real_init(self, label, op_desc, seconds, parent)
        shown.append(op_desc)

    monkeypatch.setattr(PG.ProductionCountdownDialog, "__init__", init)
    monkeypatch.setattr(PG.ProductionCountdownDialog, "exec", lambda self: answer)
    return shown


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui import main_window as MW
    from ui import scan_job

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._quit_with_transfers = True
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "f.txt").write_text("payload")
    window._split_pane(Qt.Orientation.Horizontal)
    a, b = window._panes[0], window._panes[1]
    a.navigate(str(src))
    b.navigate(str(dst))
    window._set_active_pane(a)
    window._target_pane = b
    _make_production(a.backend)
    # The destination check is the first step of a queued move: counted,
    # not run (no background thread, no transfer).
    started: list = []
    monkeypatch.setattr(scan_job.ScanJob, "start", lambda self, *a, **k: started.append(1))
    path = str(src / "f.txt")
    monkeypatch.setattr(a, "selected_items", lambda: [path])
    window.test_ctx = {"a": a, "b": b, "path": path, "started": started}
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _toolbar_move(window):
    from PyQt6.QtWidgets import QToolBar

    for bar in window.findChildren(QToolBar):
        for action in bar.actions():
            if action.text().replace("&", "") == "Move to Target Pane":
                return action
    raise AssertionError("no Move to Target on the toolbar")


def test_sad_a_cancelled_countdown_stops_f6_the_toolbar_and_a_drop(win, monkeypatch):
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    action = _toolbar_move(win)
    assert action.shortcut().toString() == "F6"
    action.trigger()  # the toolbar button and its F6 shortcut
    win._move_files()
    win._on_drop_transfer([ctx["path"]], ctx["b"], str(id(ctx["a"])), is_move=True)
    assert len(shown) == 3 and all("move" in op for op in shown)
    assert ctx["started"] == []  # nothing queued


def test_edge_the_context_menu_asks_once_and_the_toolbar_asks_too(win, monkeypatch):
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Accepted)
    ctx["a"]._move_to_target()  # the pane's context menu entry
    assert len(shown) == 1  # not once in the pane and again in the window
    assert ctx["started"] == [1]
    safety_tarpit.reset_all()  # a new connection session: the toll is due again
    _toolbar_move(win).trigger()
    assert len(shown) == 2
    assert ctx["started"] == [1, 1]


def test_happy_a_copy_asks_nothing(win, monkeypatch):
    """Copies remove nothing: F5 stays free of the countdown. (With a move
    in the same run, which the old code let through.)"""
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    win._on_drop_transfer([ctx["path"]], ctx["b"], str(id(ctx["a"])), is_move=False)
    assert shown == [] and ctx["started"] == [1]
    win._on_drop_transfer([ctx["path"]], ctx["b"], str(id(ctx["a"])), is_move=True)
    assert len(shown) == 1 and ctx["started"] == [1]


# -- the viewers' Delete ----------------------------------------------------------


def test_sad_a_cancelled_countdown_keeps_the_file_a_viewer_deletes(tmp_path, monkeypatch):
    from ui import viewer_file_actions as VFA

    fs = LocalFS()
    _make_production(fs)
    victim = tmp_path / "keep.png"
    victim.write_bytes(b"x")
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert VFA.delete_file(None, fs, str(victim), None) is False
    assert victim.exists()
    assert len(shown) == 1 and str(victim) in shown[0]


def test_happy_an_accepted_countdown_lets_the_viewer_delete(tmp_path, monkeypatch):
    from ui import viewer_file_actions as VFA

    fs = LocalFS()
    _make_production(fs)
    victim = tmp_path / "gone.png"
    victim.write_bytes(b"x")
    shown = _countdown(monkeypatch, QDialog.DialogCode.Accepted)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert VFA.delete_file(None, fs, str(victim), None) is True
    assert not victim.exists()
    assert len(shown) == 1
