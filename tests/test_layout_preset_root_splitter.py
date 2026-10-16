"""After a layout preset, new panes still have a place to go.

Reported from real use: after a connect, "post-connect handler failed:
wrapped C/C++ object of type QSplitter has been deleted" - every later
connection failed the same way. apply_preset() set a new central widget,
which makes QMainWindow delete the old one: the splitter
``MainWindow._root_splitter`` still pointed at. Every consumer of that
reference (connect, Extract Pane, terminal panes, the saved session)
then touched a deleted object. The "single" preset's root is not even a
splitter but a bare file pane.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication, QSplitter  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    from PyQt6.QtCore import QEvent

    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    # processEvents() leaves deleteLater() alone; the real event loop runs
    # it - and that is when the old central widget is gone for good.
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


@pytest.fixture
def window(monkeypatch):
    from ui import main_window as MW

    home = tempfile.mkdtemp()
    with mock.patch("pathlib.Path.home", return_value=Path(home)):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    # Terminal presets would start real shells; a plain widget stands in.
    monkeypatch.setattr(
        MW.MainWindow,
        "_preset_make_terminal_pane",
        lambda self, spec: QSplitter(),
    )
    win.show()
    yield win
    win.close()
    win.deleteLater()
    pump()
    shutil.rmtree(home, ignore_errors=True)


def _root_ok(win) -> None:
    root = win._root_splitter
    assert not sip.isdeleted(root)
    assert isinstance(root, QSplitter)
    assert win.centralWidget() is root


def _connect_like_quick_connect(win, monkeypatch) -> None:
    """The success path of _quick_connect_profile with a fake connect."""
    from core.profiles import ConnectionProfile

    monkeypatch.setattr(
        win, "_run_connect_async", lambda profile, pw, kp, ok, fail: ok(LocalFS())
    )
    from core import credentials

    monkeypatch.setattr(credentials, "get_password", lambda name: "pw")
    win._quick_connect_profile(
        ConnectionProfile(name="p", protocol="sftp", host="h", username="u")
    )


# --- happy -----------------------------------------------------------------


@pytest.mark.parametrize("preset", ["dual", "single", "quad-files"])
def test_happy_a_connect_after_a_preset_adds_its_pane(window, monkeypatch, preset) -> None:
    window.apply_layout_preset(preset)
    pump()
    _root_ok(window)
    before = len(window._panes)
    _connect_like_quick_connect(window, monkeypatch)
    assert len(window._panes) == before + 1
    assert window._panes[-1].parent() is not None


def test_happy_every_preset_leaves_a_live_root_splitter(window) -> None:
    from ui.layout_presets import PRESET_ORDER

    for name in PRESET_ORDER:
        window.apply_layout_preset(name)
        pump()
        _root_ok(window)


# --- sad -------------------------------------------------------------------


def test_sad_saving_the_session_after_a_preset_works(window) -> None:
    window.apply_layout_preset("dual")
    pump()
    data = window._serialize_splitter(window._root_splitter)
    assert data and data.get("type") == "splitter"


def test_sad_extract_pane_after_a_preset(window) -> None:
    window.apply_layout_preset("quad-files")
    pump()
    nested = next(p for p in window._panes if p.parent() is not window._root_splitter)
    window._active_pane = nested
    window._extract_pane_from_split()
    pump()
    assert nested.parent() is window._root_splitter


# --- edge ------------------------------------------------------------------


def test_edge_cycling_presets_and_splitting(window) -> None:
    window.cycle_layout_preset()
    window.cycle_layout_preset()
    pump()
    _root_ok(window)
    pane = window._panes[0]
    window._active_pane = pane
    from PyQt6.QtCore import Qt

    count = len(window._panes)
    window._split_pane(Qt.Orientation.Vertical)
    pump()
    assert len(window._panes) == count + 1
    _root_ok(window)
