"""The first start fits a 1280x800 / 1366x768 screen: names stay whole,
the panes show more than a handful of rows.

Reported: with both panes and the Bookmarks sidebar, the Name column was
60 px of a 445 px pane ("p...") while Size, Modified, Permissions and
Owner kept their full widths; an empty Transfers dock took ~290 px of
the height and the empty sidebar ~330 px of the width, leaving 3-5 file
rows. Name now gets its width first (the other columns shrink, then the
rightmost step aside), and the docks start small on a first start only.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

NAME = "quarterly-report.pdf"  # 20 characters
assert len(NAME) == 20


def pump(rounds: int = 10) -> None:
    for _ in range(rounds):
        APP.processEvents()


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import column_prefs as CP
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    # The window stands for the whole screen here (1280x800, 1366x768); the
    # offscreen platform's screen is only 800 px wide, so the empty Bookmarks
    # sidebar would fold away as on a netbook (UX review round 7, L7 - tested
    # in tests/test_ux_round7_lows.py).
    monkeypatch.setattr(MW.MainWindow, "_small_screen",
                        lambda self: self.width() < self.SMALL_SCREEN_WIDTH)
    monkeypatch.setattr(CP, "DEFAULT_PATH", home / "column_prefs.json")
    folder = home / "files"
    folder.mkdir()
    for name in [NAME, "a.txt", "Documents"] + [f"file-{i:02d}.txt" for i in range(30)]:
        (folder / name).write_text("x")
    return folder


@pytest.fixture
def windows():
    made = []
    yield made
    for win in made:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
    pump()


def start(windows, folder, size):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    windows.append(win)
    if not win.restore_layout_on_start():
        win.apply_first_start_layout()
    win.resize(*size)
    win.show()
    pump(30)
    for pane in win._panes:
        pane.navigate(str(folder))
    pump(30)
    return win


def _name_row(pane) -> int:
    proxy = pane._proxy
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == NAME:
            return row
    raise AssertionError(f"{NAME} not listed")


@pytest.mark.parametrize("size", [(1280, 800), (1366, 768)])
def test_happy_a_20_character_name_is_whole_in_each_default_pane(home, windows, size):
    win = start(windows, home, size)
    assert len(win._panes) == 2
    for pane in win._panes:
        table = pane._table
        need = table.sizeHintForIndex(pane._proxy.index(_name_row(pane), 0)).width()
        width = table.horizontalHeader().sectionSize(0)
        assert width >= need, (size, width, need)
        # the columns still fill the pane exactly
        header = table.horizontalHeader()
        shown = [c for c in range(header.count()) if not header.isSectionHidden(c)]
        assert sum(header.sectionSize(c) for c in shown) == table.viewport().width()


@pytest.mark.parametrize("size", [(1280, 800), (1366, 768)])
def test_happy_the_first_start_docks_leave_the_panes_room(home, windows, size):
    win = start(windows, home, size)
    assert win._bookmark_sidebar.width() <= 260
    assert win._transfer_dock.height() <= 240
    # the Transfers buttons stay whole
    assert win._transfer_dock.height() >= win._transfer_dock.minimumSizeHint().height()
    for pane in win._panes:
        table = pane._table
        rows = table.viewport().height() // table.rowHeight(0)
        assert rows >= 9, (size, rows)


def test_edge_a_saved_layout_keeps_its_dock_sizes(home, windows):
    from PyQt6.QtCore import Qt

    first = start(windows, home, (1280, 800))
    assert not first._first_start_docks_pending
    first.resizeDocks([first._bookmark_sidebar], [330], Qt.Orientation.Horizontal)
    pump()
    saved = first._bookmark_sidebar.width()
    first._save_session()
    first.close()
    pump()
    again = start(windows, home, (1280, 800))
    assert not getattr(again, "_first_start_docks_pending", False)
    assert abs(again._bookmark_sidebar.width() - saved) <= 4, (saved, again._bookmark_sidebar.width())
