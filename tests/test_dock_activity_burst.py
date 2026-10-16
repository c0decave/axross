"""A burst of dock activity recolours the tabs once, not once per event.

Every log record makes the log dock emit ``activity``; with the dock
hidden behind another tab each one walked every QTabBar of the window
again (measured: 1000 records, 1000 recolours, 1.0 s on the GUI thread)
although only the first changes a colour.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDockWidget, QMainWindow, QTabBar  # noqa: E402

from ui.main_window import MainWindow  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _FakeDock(QDockWidget):
    activity = pyqtSignal()


class _Stub(QMainWindow):
    """The indicator helpers of MainWindow, without its __init__."""

    _ACTIVITY_COLOR = MainWindow._ACTIVITY_COLOR
    _wire_dock_activity_indicators = MainWindow._wire_dock_activity_indicators
    _watch_dock_activity = MainWindow._watch_dock_activity
    _flag_dock_activity = MainWindow._flag_dock_activity
    _on_dock_visibility_changed = MainWindow._on_dock_visibility_changed

    def __init__(self) -> None:
        super().__init__()
        self.recolours = 0
        self._transfer_dock = _FakeDock("Transfers", self)
        self._terminal_dock = _FakeDock("Terminal", self)
        self._log_dock = _FakeDock("Log", self)
        self._console_dock = _FakeDock("Console", self)
        self._log_dock.setProperty("_test_visible", False)
        self._wire_dock_activity_indicators()
        self.tabbar = QTabBar(self)
        for title in ("Transfers", "Log"):
            self.tabbar.addTab(title)
        self.setCentralWidget(self.tabbar)

    def _is_dock_currently_visible(self, dock) -> bool:
        return bool(dock.property("_test_visible"))

    def _apply_tab_colors(self) -> None:
        self.recolours += 1
        MainWindow._apply_tab_colors(self)

    def log_tab_colour(self):
        return self.tabbar.tabTextColor(1)


@pytest.fixture
def window():
    win = _Stub()
    yield win
    win.deleteLater()


def test_happy_a_burst_on_a_hidden_dock_recolours_once(window) -> None:
    for _ in range(50):
        window._log_dock.activity.emit()
    assert window._dock_has_activity[window._log_dock] is True
    assert window.recolours == 1
    assert window.log_tab_colour() == MainWindow._ACTIVITY_COLOR


def test_sad_activity_on_the_raised_dock_flags_and_recolours_nothing(window) -> None:
    window._log_dock.setProperty("_test_visible", True)
    for _ in range(5):
        window._log_dock.activity.emit()
    assert window._dock_has_activity[window._log_dock] is False
    assert window.recolours == 0


def test_edge_activity_after_the_user_looked_flags_the_tab_again(window) -> None:
    window._log_dock.activity.emit()
    window._on_dock_visibility_changed(window._log_dock, True)  # user raised it
    assert window._dock_has_activity[window._log_dock] is False
    assert window.log_tab_colour() != MainWindow._ACTIVITY_COLOR
    for _ in range(3):  # hidden again, new records arrive
        window._log_dock.activity.emit()
    assert window._dock_has_activity[window._log_dock] is True
    assert window.log_tab_colour() == MainWindow._ACTIVITY_COLOR
    assert window.recolours == 3  # flag, clear, flag again
