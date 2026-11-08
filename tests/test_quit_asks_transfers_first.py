"""Quitting asks "Transfers running" before it closes anything.

Before: ``MainWindow.closeEvent`` closed the editor window and every
viewer window of its own first and only then asked whether to quit with
transfers still running. Answering No kept the main window - and left the
editor and the viewers gone (their tabs closed, their windows deleted).

Now the transfer question comes first (after the scripts dock's, which
also asks before anything closes); the editor and the viewers close only
once quitting is decided.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle() -> None:
    for _ in range(3):
        APP.processEvents()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_sad_no_at_transfers_running_keeps_the_editor_and_the_viewers(tmp_path, monkeypatch):
    from ui import main_window as MW
    from ui import viewer_window as VW
    from ui.image_viewer import ImageViewerDialog

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win.show()
    text = tmp_path / "f.txt"
    text.write_text("x\n")
    editor = win._editor()
    editor.open_file(LocalFS(), str(text))
    win._show_editor_window()
    image = QImage(20, 20, QImage.Format.Format_RGB32)
    image.fill(QColor("blue"))
    picture = tmp_path / "a.png"
    image.save(str(picture))
    viewer = VW.show_independent(ImageViewerDialog(LocalFS(), str(picture), [str(picture)], win))
    _settle()
    monkeypatch.setattr(win._transfer_manager, "unfinished", lambda: 2)
    asked: list[str] = []

    def answer(box):
        asked.append(box.text())
        return answer.reply

    answer.reply = QMessageBox.StandardButton.No
    monkeypatch.setattr(QMessageBox, "exec", answer)

    win.close()
    _settle()
    assert asked and "transfer(s) are running" in asked[0]
    assert win.isVisible()
    assert editor.isVisible() and editor.tabs.count() == 1
    assert not sip.isdeleted(viewer) and viewer.isVisible()
    assert VW.independent_windows(win) == [viewer]

    # Yes quits: then the editor and the viewer close with the window.
    answer.reply = QMessageBox.StandardButton.Yes
    win.close()
    _settle()
    assert not win.isVisible()
    assert sip.isdeleted(editor) or not editor.isVisible()
    assert sip.isdeleted(viewer)
    win.deleteLater()
    _settle()
