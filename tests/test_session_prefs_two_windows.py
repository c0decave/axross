"""A preference stored by one axross is not undone when another one quits.

Review 2026-11-20 (sessions round 2): every window preference is stored
in session.json the moment it changes (store_window_prefs), but
_save_session - at every quit - wrote them all again from the quitting
window's memory. Two axross processes on one session.json: B switched
Restore Layout on Start off and set the font size 18; A quit afterwards
and wrote back True and no font size. The quit writes the window's
layout, size and docks now, not the preferences that are stored as they
change; every writer of session.json takes its file lock for its
read-change-write.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def windows():
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication, QEvent
    from PyQt6.QtGui import QCloseEvent

    from ui import main_window as MW

    home = Path(tempfile.mkdtemp())
    session = home / "session.json"
    made = []
    font = APP.font()  # set_font_size changes the application's font
    patchers = [mock.patch.object(MW.MainWindow, "_SESSION_FILE", session),
                mock.patch.object(MW.MainWindow, "_RECENTS_FILE", home / "recents.json")]
    for p in patchers:
        p.start()

    def make():
        with mock.patch("pathlib.Path.home", return_value=home):
            win = MW.MainWindow()
        win._reconnect_timer.stop()
        made.append(win)
        return win

    yield make, session
    for win in made:
        if not sip.isdeleted(win):
            win.closeEvent(QCloseEvent())
            win.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    APP.setFont(font)
    for p in patchers:
        p.stop()
    shutil.rmtree(home, ignore_errors=True)


def _window(session: Path) -> dict:
    return json.loads(session.read_text(encoding="utf-8"))["window"]


def test_sad_a_quit_keeps_what_another_window_stored_since(windows):
    make, session = windows
    session.write_text(json.dumps({"window": {"language": "de"}}), encoding="utf-8")
    a, b = make(), make()
    b.set_restore_on_start(False)
    b.set_font_size(18)
    a._save_session()
    stored = _window(session)
    assert stored["restore_layout_on_start"] is False
    assert stored["font_size"] == 18
    assert stored["language"] == "de"


def test_happy_the_quit_still_writes_the_layout_and_the_size(windows):
    make, session = windows
    a = make()
    a.resize(700, 500)
    a._save_session()
    stored = json.loads(session.read_text(encoding="utf-8"))
    assert stored["workspaces"] and stored["window"]["width"] == a.width()
    assert "geometry" in stored["window"] and "dock_state" in stored["window"]
