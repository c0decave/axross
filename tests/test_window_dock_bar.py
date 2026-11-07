"""Extra windows: name and _ [] x in one row, a dock bar, a soft minimum.

Feedback: the window buttons go into the row where the name is; a ``_``
button puts the window into a bar above the status bar (task bar like, one
button per window, shown only when one is there; a click on the name
brings it back); the windows may be made as small as their title row.
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

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QLabel,
    QMainWindow,
    QToolButton,
    QVBoxLayout,
)

from tests.markup_probe import shown  # noqa: E402
from ui import window_dock_bar as WDB  # noqa: E402
from ui.close_corner import add_close_corner  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def main():
    win = QMainWindow()
    win.setCentralWidget(QLabel("content"))
    win.statusBar().showMessage("status")
    WDB.install(win)
    win.resize(800, 600)
    win.show()
    _pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _dialog(parent, title="Calculate Size") -> QDialog:
    d = QDialog(parent)
    d.setWindowTitle(title)
    layout = QVBoxLayout(d)
    big = QLabel("x")
    big.setMinimumSize(400, 300)
    layout.addWidget(big)
    d.setMinimumSize(450, 350)
    add_close_corner(d)
    return d


def test_happy_the_name_and_the_buttons_share_one_row(main):
    d = _dialog(main)
    d.show()
    _pump()
    title = d.findChild(QLabel, "axCornerTitle")
    buttons = [d.findChild(QToolButton, n) for n in ("axDockCorner", "axMaximizeCorner",
                                                      "axCloseCorner")]
    assert title is not None and all(buttons)
    assert shown(title.toolTip()) == "Calculate Size"
    centres = {title.geometry().center().y(), *(b.geometry().center().y() for b in buttons)}
    assert max(centres) - min(centres) <= 4  # one row
    assert title.geometry().right() < buttons[0].geometry().left()
    d.setWindowTitle("Calculate Size: /home")
    assert shown(title.toolTip()) == "Calculate Size: /home"
    d.close()


def test_happy_dock_and_bring_back(main):
    bar = main.window_dock_bar
    assert bar.isHidden()  # nothing docked: no bar
    d = _dialog(main)
    d.show()
    _pump()
    d.findChild(QToolButton, "axDockCorner").click()
    _pump()
    assert not d.isVisible()
    assert bar.isVisible() and bar.windows() == [d]
    assert main.toolBarArea(bar) == Qt.ToolBarArea.BottomToolBarArea
    (button,) = [b for b in bar.findChildren(QToolButton) if b.text() == "Calculate Size"]
    button.click()
    _pump()
    assert d.isVisible()
    assert bar.windows() == [] and bar.isHidden()
    d.close()


def test_sad_a_closed_docked_window_leaves_the_bar(main):
    bar = main.window_dock_bar
    d = _dialog(main)
    d.show()
    bar.dock(d)
    d.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    _pump()
    assert bar.windows() == [] and bar.isHidden()


def test_edge_showing_a_docked_window_otherwise_takes_it_off(main):
    bar = main.window_dock_bar
    d = _dialog(main)
    d.show()
    bar.dock(d)
    d.show()  # e.g. its menu entry again
    _pump()
    assert bar.windows() == []
    bar.dock(d)
    assert bar.windows() == [d]
    bar.restore(d)
    d.close()


def test_happy_a_window_shrinks_to_its_title_row(main):
    d = _dialog(main)
    d.show()
    _pump()
    assert d.width() >= 450 and d.height() >= 350  # opens at least as big as it asked
    assert d.minimumHeight() < 60
    d.resize(200, d.minimumHeight())
    _pump()
    assert d.height() < 100
    d.close()
