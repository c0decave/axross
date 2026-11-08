"""Edit (F4) after View (F3) gives a writable tab.

Before: ``EditorWindow.open_file`` handed back the tab already open for
the file - the read-only one View opened - however it was asked: F4 then
showed a tab that refused every key and whose Save said "is open
read-only". The same happened when Edit came while View's background read
was still running.

Now an Edit of a file open read-only makes its tab writable (the editor,
the tab title); a View of a file open for editing leaves it writable.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def editor():
    from ui.editor_window import EditorWindow

    window = EditorWindow()
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_happy_edit_after_view_is_writable(editor, tmp_path):
    path = tmp_path / "g.txt"
    path.write_text("hello\n")
    viewed = editor.open_file(LocalFS(), str(path), read_only=True)  # F3
    assert "[read-only]" in editor.tabs.tabText(editor.tabs.indexOf(viewed))
    edited = editor.open_file(LocalFS(), str(path), read_only=False)  # F4
    assert edited is viewed  # the same tab, not a second one
    assert editor.tabs.count() == 1
    assert edited.read_only is False and not edited.editor.isReadOnly()
    assert "[read-only]" not in editor.tabs.tabText(editor.tabs.indexOf(edited))
    edited.editor.setPlainText("changed\n")
    assert editor.save_tab(edited) is True
    assert path.read_text() == "changed\n"


def test_edge_view_after_edit_stays_writable(editor, tmp_path):
    path = tmp_path / "h.txt"
    path.write_text("x\n")
    editor.open_file(LocalFS(), str(path), read_only=True)
    tab = editor.open_file(LocalFS(), str(path))
    again = editor.open_file(LocalFS(), str(path), read_only=True)
    assert again is tab and not tab.read_only and not tab.editor.isReadOnly()


def test_sad_edit_while_the_view_is_still_being_read(editor, tmp_path):
    path = tmp_path / "slow.txt"
    path.write_text("x\n")
    opened: list = []
    editor.opened.connect(opened.append)
    assert editor.open_file(LocalFS(), str(path), read_only=True, background=True) is None
    assert editor.open_file(LocalFS(), str(path), background=True) is None
    end = time.monotonic() + 5
    while not opened and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    assert len(opened) == 1 and editor.tabs.count() == 1
    assert opened[0].read_only is False and not opened[0].editor.isReadOnly()
