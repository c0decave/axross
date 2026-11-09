"""A connection opens in the untouched target pane instead of a new pane
(UX review round 7, M3).

The first connection at the first start gave three panes (375/375/291 px)
and the server landed in the narrowest. Now a connection takes the place
of the target pane while nobody has used it: a local pane in the workspace
on screen, not the active one, still at the home folder it opened with,
nothing selected, no filter, nothing running. Shift on the click, or
"Open in a new pane" in the Connection Manager, still adds a new pane.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(monkeypatch):
    from core import credentials
    from core.local_fs import LocalFS
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump()
    # Two local panes at the home folder, as at the first start.
    while len(win._panes) < 2:
        win._add_pane_to_splitter(win._root_splitter, LocalFS())
    home = LocalFS().home()
    for pane in win._panes:
        pane.navigate(home)
        pane._history = [pane.current_path]
        pane._history_pos = 0
    win._set_active_pane(win._panes[0])
    pump(0.2)
    monkeypatch.setattr(credentials, "get_password", lambda name: "pw")  # no prompt
    yield win
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    pump()


def _connect(win, monkeypatch, **kw):
    from core.local_fs import LocalFS
    from core.profiles import ConnectionProfile

    remote = type("RemoteFS", (LocalFS,), {})()
    monkeypatch.setattr(
        win, "_run_connect_async", lambda profile, pw, kp, ok, fail: ok(remote)
    )
    win._quick_connect_profile(
        ConnectionProfile(name="srv", protocol="sftp", host="h", username="u"), **kw
    )
    pump(0.1)
    return remote


# --- happy -----------------------------------------------------------------


def test_happy_the_first_connection_replaces_the_untouched_target(window, monkeypatch):
    left, right = window._panes[0], window._panes[1]
    splitter = right.parent()
    index = splitter.indexOf(right)
    remote = _connect(window, monkeypatch)
    assert len(window._panes) == 2
    assert right not in window._panes
    new = next(p for p in window._panes if p.backend is remote)
    assert splitter.indexOf(new) == index  # in the same place
    assert window._active_pane is new
    assert window._target_pane is left
    assert "Shift" in window.statusBar().currentMessage()


def test_happy_shift_or_new_pane_still_adds_a_pane(window, monkeypatch):
    _connect(window, monkeypatch, new_pane=True)
    assert len(window._panes) == 3
    from PyQt6.QtCore import Qt

    monkeypatch.setattr(
        QApplication, "keyboardModifiers", staticmethod(lambda: Qt.KeyboardModifier.ShiftModifier)
    )
    _connect(window, monkeypatch)
    assert len(window._panes) == 4


# --- sad -------------------------------------------------------------------


def test_sad_a_navigated_target_is_kept(window, monkeypatch, tmp_path):
    right = window._panes[1]
    right.navigate(str(tmp_path))
    pump(0.1)
    _connect(window, monkeypatch)
    assert right in window._panes and len(window._panes) == 3


def test_sad_a_target_with_a_selection_or_filter_is_kept(window, monkeypatch):
    right = window._panes[1]
    right._filter_edit.setText("x")
    _connect(window, monkeypatch)
    assert right in window._panes and len(window._panes) == 3


def test_sad_a_remote_target_is_never_replaced(window, monkeypatch):
    _connect(window, monkeypatch)  # replaces the local target
    first = window._active_pane
    window._set_active_pane(window._panes[0])  # the remote pane is the target now
    assert window._target_pane is first
    _connect(window, monkeypatch)
    assert first in window._panes and len(window._panes) == 3


# --- edge ------------------------------------------------------------------


def test_edge_the_active_pane_is_never_replaced(window, monkeypatch):
    left = window._panes[0]
    window._target_pane = None  # a single pane: no target to take
    _connect(window, monkeypatch)
    assert left in window._panes


def test_edge_background_connect_keeps_the_active_pane(window, monkeypatch):
    left = window._panes[0]
    remote = _connect(window, monkeypatch, activate=False)
    assert window._active_pane is left
    assert window._target_pane.backend is remote
    assert len(window._panes) == 2


def test_edge_connection_manager_box_means_a_new_pane(window, monkeypatch):
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(window._profile_manager, parent=window)
    try:
        assert dialog.result_new_pane is False
        dialog._new_pane_box.setChecked(True)
        monkeypatch.setattr(dialog, "_validate", lambda: True)
        monkeypatch.setattr(dialog, "_store_profile_credentials", lambda profile: None)
        dialog._on_accept()
        assert dialog.result_new_pane is True
    finally:
        dialog.deleteLater()
