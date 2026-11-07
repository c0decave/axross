"""Tools > Bluetooth opens the Bluetooth panel, like Tools > Audio Mixer.

The product review found the Bluetooth extension reachable only through
Extensions > Manage Extensions…: unlike the Audio Mixer and System
Information it had no Tools entry.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _tools(window):
    return next(a.menu() for a in window.menuBar().actions() if a.text() == "&Tools")


def test_happy_bluetooth_sits_beside_the_audio_mixer(window):
    texts = [a.text() for a in _tools(window).actions()]
    assert texts.index("&Bluetooth") == texts.index("Audio Mi&xer") + 1
    action = window._bluetooth_action
    assert "Bluetooth extension" in action.toolTip()


def test_happy_it_toggles_the_bluetooth_panel(window):
    with mock.patch.object(window, "_toggle_extension_tool") as toggle:
        window._bluetooth_action.trigger()
    toggle.assert_called_once_with("bundled:bluetooth", "Bluetooth")


def test_sad_switched_off_it_asks_first_and_a_no_loads_nothing(window):
    host = window.extension_host
    assert "bundled:bluetooth" not in host.loaded_ids()
    with mock.patch.object(QMessageBox, "question",
                           return_value=QMessageBox.StandardButton.No) as ask, \
            mock.patch.object(host, "set_enabled") as enable:
        window._bluetooth_action.trigger()
    assert "Bluetooth" in ask.call_args.args[1]
    enable.assert_not_called()
    assert "bundled:bluetooth" not in host.loaded_ids()
