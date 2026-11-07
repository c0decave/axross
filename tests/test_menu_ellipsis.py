"""Every menu entry that opens a dialog ends in one "…", not three dots.

The product review found the File menu (Quick Connect..., Connection
Manager..., Import Profiles (JSON)...) and Bookmarks > Manage Bookmarks...
with "..." while every other menu uses "…".
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

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(params=["en", "de"])
def window(request, monkeypatch):
    from core import i18n
    from ui.main_window import MainWindow

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator(request.param))
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _texts(window) -> list[str]:
    out = []

    def walk(menu) -> None:
        menu.aboutToShow.emit()
        for action in menu.actions():
            if not action.isSeparator():
                out.append(action.text())
            if action.menu() is not None:
                walk(action.menu())

    for top in window.menuBar().actions():
        walk(top.menu())
    return out


def test_happy_no_menu_entry_ends_in_three_dots(window):
    texts = _texts(window)
    assert [t for t in texts if "..." in t] == []
    file_menu = [t for t in texts if t.replace("&", "").startswith(("Quick Connect",
                                                                    "Connection Manager"))]
    if file_menu:  # English
        assert all(t.endswith("…") for t in file_menu)
