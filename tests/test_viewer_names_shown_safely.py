"""The viewers and editors show a file's name as the pane does: a bidi
override, a control or an invisible character is U+FFFD, never obeyed.

Review: the pane cleans names (core.remote_name.sanitize_for_display), but
the media viewer's tiles and status line, the image viewer's info line, the
text and hex windows' titles and the editor's tabs showed them raw - a
picture named "holiday\\u202egnp.exe" read "holidayexe.png" there, and a
name with line breaks broke the tile's two lines.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, MediaItem  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402

APP = QApplication.instance() or QApplication([])

RLO = "\u202e"
NAME = f"holiday{RLO}gnp.png"


def _wait(cond, seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def picture(tmp_path):
    return str(write_image(tmp_path / NAME, size=(20, 10)))


def test_sad_the_media_viewer_shows_a_bidi_name_neutralised(picture):
    from ui import media_viewer as MV

    item = MediaItem(path=picture, name=NAME, kind=IMAGE, size=1, mtime=0.0,
                     folder=f"sub{RLO}dir")
    model = MV.MediaListModel()
    model.set_items([item])
    shown = model.data(model.index(0, 0), Qt.ItemDataRole.DisplayRole)
    assert RLO not in shown and "\ufffd" in shown
    viewer = MV.MediaViewer(LocalFS())
    viewer.set_items([item], 0)
    try:
        assert _wait(lambda: viewer.mode == "image")
        assert RLO not in viewer.status_text() and "\ufffd" in viewer.status_text()
    finally:
        viewer.shutdown()


def test_sad_the_image_viewer_info_line_neutralises_a_bidi_name(picture):
    from ui.image_viewer import ImageViewerDialog

    dlg = ImageViewerDialog(LocalFS(), picture, siblings=[picture])
    try:
        assert dlg.loaded
        assert RLO not in dlg._info.text() and "\ufffd" in dlg._info.text()
    finally:
        dlg.close()


def test_sad_text_and_hex_titles_neutralise_a_bidi_name(tmp_path):
    from ui.hex_editor import HexEditorDialog
    from ui.text_editor import TextEditorDialog

    path = tmp_path / f"notes{RLO}txt.sh"
    path.write_text("hi\n")
    for cls in (TextEditorDialog, HexEditorDialog):
        dlg = cls(LocalFS(), str(path))
        try:
            assert RLO not in dlg.windowTitle() and "\ufffd" in dlg.windowTitle()
        finally:
            dlg.close()


def test_sad_the_editor_tab_neutralises_a_bidi_name(tmp_path):
    from unittest import mock

    from PyQt6.QtWidgets import QMessageBox

    from ui import editor_window as EW

    path = tmp_path / f"notes{RLO}txt.sh"
    path.write_text("hi\n")
    win = EW.EditorWindow()
    try:
        win.open_file(LocalFS(), str(path))
        text = win.tabs.tabText(0)
        assert RLO not in text and "\ufffd" in text
    finally:
        with mock.patch("ui.editor_window.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Discard):
            win.close()
        win.deleteLater()
        APP.processEvents()
