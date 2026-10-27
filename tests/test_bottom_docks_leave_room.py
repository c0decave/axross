"""The bottom docks open at the height of the tab in front, not of the
tallest tab behind it - the file panes keep most of the window.

Seen at 1280x800 on a first start: the panes got 160 px, the bottom area
(Transfers in front; Terminal, Log, Console and Scripts tabbed behind it)
464 px. The minimums were not the cause (the tab group needs 272 px at
least); Qt opens a dock tab group at the largest size hint of its tabs,
and Console asked for 490 px, Scripts for 500 px (their editor and output
panes stacked), while Transfers, Terminal and Log ask for 253-259 px. Qt
reads a dock's content hint (QDockWidget.sizeHint() is not asked), so
Console and Scripts now sit in a scrolling frame (ui.dock_frame) that asks
for no more than BOTTOM_DOCK_HINT_PX; a height the user set and saved still
comes back.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui import dock_frame as DF  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.1) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


def _window(monkeypatch, width: int, height: int):
    from core import multimedia_probe
    from tests.test_media_player_late_engine import OK
    from ui.main_window import MainWindow

    monkeypatch.setattr(multimedia_probe, "probe", lambda *a, **k: OK)
    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(width, height)
    win.show()
    pump(0.3)
    return win


def _close(win) -> None:
    if not sip.isdeleted(win):
        win.close()
        win.deleteLater()
        pump()


BOTTOM = ("_transfer_dock", "_terminal_dock", "_log_dock", "_console_dock", "_scripts_dock")


# --- happy -----------------------------------------------------------------


@pytest.mark.parametrize("size", [(1280, 800), (1600, 980)])
def test_happy_e2e_a_first_start_leaves_the_panes_most_of_the_window(monkeypatch, size):
    win = _window(monkeypatch, *size)
    try:
        central = win.centralWidget().height()
        bottom = win._transfer_dock.height()
        assert central >= bottom, (central, bottom)
        assert bottom <= DF.BOTTOM_DOCK_HINT_PX + 40, bottom  # title bar and tab bar on top
    finally:
        _close(win)


def test_happy_no_bottom_dock_asks_for_more_than_the_shared_hint(monkeypatch):
    win = _window(monkeypatch, 1280, 800)
    try:
        for name in BOTTOM:
            dock = getattr(win, name)
            assert dock.sizeHint().height() <= DF.BOTTOM_DOCK_HINT_PX + 40, \
                (name, dock.sizeHint().height())
    finally:
        _close(win)


# --- sad -------------------------------------------------------------------


def test_sad_a_taller_bottom_area_the_user_saved_comes_back(monkeypatch):
    win = _window(monkeypatch, 1280, 900)
    try:
        win.resizeDocks([win._transfer_dock], [520], Qt.Orientation.Vertical)
        pump(0.2)
        tall = win._transfer_dock.height()
        assert tall > 450, tall
        state = win.saveState()
    finally:
        _close(win)
    again = _window(monkeypatch, 1280, 900)
    try:
        assert again.restoreState(state)
        pump(0.3)
        assert abs(again._transfer_dock.height() - tall) <= 10, \
            (again._transfer_dock.height(), tall)
    finally:
        _close(again)


# --- edge ------------------------------------------------------------------


def test_edge_console_and_scripts_scroll_instead_of_holding_the_area_up(monkeypatch):
    """Their content keeps its own minimum inside a frame that scrolls, as
    the other panels' do: the bottom group can be lower than Scripts'
    editor and buttons without hiding anything for good."""
    win = _window(monkeypatch, 1280, 800)
    try:
        for name in ("_console_dock", "_scripts_dock"):
            frame = getattr(win, name).widget()
            assert isinstance(frame, DF.PanelFrame), name
            content = frame.content()
            assert content is not None
            assert frame.content_minimum().height() >= content.minimumSizeHint().height()
            assert frame.minimumSizeHint().height() < content.minimumSizeHint().height()
    finally:
        _close(win)


def test_edge_the_hint_is_at_least_what_the_other_bottom_docks_ask(monkeypatch):
    """Derived, not typed twice: the shared hint covers Transfers, Terminal
    and Log as they are, so only the two tall tabs are capped."""
    win = _window(monkeypatch, 1280, 800)
    try:
        natural = max(getattr(win, n).widget().sizeHint().height()
                      for n in ("_transfer_dock", "_terminal_dock", "_log_dock"))
        assert DF.BOTTOM_DOCK_HINT_PX >= natural, (DF.BOTTOM_DOCK_HINT_PX, natural)
    finally:
        _close(win)


def test_edge_capped_hint_helper():
    from PyQt6.QtCore import QSize

    assert DF.capped_hint(QSize(400, 900)) == QSize(400, DF.BOTTOM_DOCK_HINT_PX)
    assert DF.capped_hint(QSize(400, 100)) == QSize(400, 100)
    assert DF.capped_hint(QSize(400, 900), minimum=QSize(0, 300)).height() == \
        max(300, DF.BOTTOM_DOCK_HINT_PX)
    assert DF.capped_hint(QSize(400, 900), cap=120).height() == 120
