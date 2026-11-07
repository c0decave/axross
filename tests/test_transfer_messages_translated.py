"""The Transfer and Move message boxes speak the interface language.

The product review found "Select files in one pane and activate a second
pane as the target first." (Copy to Target / Move to Target with one pane)
hard-coded in English, the Security Mode, Diagnostics and Recovery boxes
next to them too.
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


@pytest.fixture(params=["en", "de"])
def window(request, monkeypatch):
    from core import i18n
    from ui.main_window import MainWindow

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator(request.param))
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    win.language = request.param
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


EXPECTED = {
    "en": ("Transfer", "Move",
           "Select files in one pane and activate a second pane as the target first."),
    "de": ("Übertragen", "Verschieben",
           "Erst Dateien in einem Pane auswählen und ein zweites Pane als Ziel aktivieren."),
}


def test_happy_without_a_target_pane_both_boxes_are_in_the_language(window):
    transfer, move, text = EXPECTED[window.language]
    pane = window._active_pane
    window._target_pane = None
    with mock.patch.object(QMessageBox, "information") as info:
        window._start_transfer(pane, [pane.current_path])
        window._move_from_pane(pane, [pane.current_path])
    shown = [(c.args[1], c.args[2]) for c in info.call_args_list]
    assert shown == [(transfer, text), (move, text)]


def test_edge_the_recovery_box_without_a_pane_too(window):
    with mock.patch.object(window, "_active_pane", None), \
            mock.patch.object(QMessageBox, "information") as info:
        window._run_recovery_scan()
    title, text = info.call_args.args[1:3]
    if window.language == "de":
        assert (title, text) == ("Recovery", "Kein aktives Pane.")
    else:
        assert (title, text) == ("Recovery", "No active pane.")
