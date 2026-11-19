"""The single-file text editor (TextEditorDialog: the text view and editor
of a pane without a main window) reads off the GUI thread and opens a
file with a very long line wrapped and read-only.

Review: it read and decoded the file in its constructor on the GUI thread
- a slow share froze every window until the last byte - and laid out a
line of megabytes unwrapped, which held the window for tens of seconds
(the tabbed editor guards both since earlier rounds).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QPlainTextEdit  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(cond, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


class SlowFS(LocalFS):
    """A local file system whose reads wait for :attr:`gate`."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()

    def open_read(self, path):
        self.gate.wait(10)
        return super().open_read(path)


def test_sad_a_slow_read_does_not_hold_the_window(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "notes.txt"
    path.write_text("hello\n")
    fs = SlowFS()
    started = time.monotonic()
    dlg = TextEditorDialog(fs, str(path), background=True)
    try:
        assert time.monotonic() - started < 2
        assert not dlg.loaded and dlg._editor.isReadOnly()
        assert not dlg._btn_save.isEnabled()
        assert "Loading" in dlg._status_label.text()
        fs.gate.set()
        assert _wait(lambda: dlg.loaded)
        assert dlg._editor.toPlainText() == "hello\n"
        assert not dlg._editor.isReadOnly()
    finally:
        fs.gate.set()
        dlg.close()


def test_sad_a_failed_background_read_says_why_and_closes(tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from ui.text_editor import TextEditorDialog

    said = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *a, **k: said.append(a[2]))
    dlg = TextEditorDialog(LocalFS(), str(tmp_path / "missing.txt"), background=True)
    assert _wait(lambda: said)
    assert not dlg.loaded and not dlg.isVisible()


def test_sad_a_very_long_line_opens_wrapped_and_read_only(tmp_path):
    from ui import editor_window as EW
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "one.json"
    path.write_text("x" * (EW.READ_ONLY_LINE_CHARS + 10) + "\nend\n")
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        assert dlg.loaded
        assert dlg._editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
        assert dlg._editor.isReadOnly()
        assert "characters long" in dlg._status_label.text()
    finally:
        dlg.close()


def test_edge_a_long_but_editable_line_is_wrapped_only(tmp_path):
    from ui import editor_window as EW
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "one.txt"
    path.write_text("y" * (EW.WRAP_LINE_CHARS + 10))
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        assert dlg._editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
        assert not dlg._editor.isReadOnly()
    finally:
        dlg.close()


def test_happy_the_panes_fallback_reads_in_the_background():
    source = (Path(__file__).resolve().parent.parent / "ui" / "file_pane.py").read_text()
    calls = source.split("TextEditorDialog(")[1:]
    assert len(calls) == 2
    assert all("background=True" in call[:200] for call in calls)


def _unbreakable(chars: int) -> str:
    """A line with no place to break it (a hex dump, a long token): Qt's
    word wrapping looked for a word boundary from every character on - one
    of a million characters took 82-145 s to lay out wrapped."""
    return "0123456789abcdef" * (chars // 16 + 1)


def test_perf_an_unbreakable_long_line_is_wrapped_anywhere(tmp_path):
    from PyQt6.QtGui import QTextOption

    from ui import editor_window as EW
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "dump.hex"
    path.write_text(_unbreakable(EW.READ_ONLY_LINE_CHARS + 10))
    started = time.monotonic()
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        dlg.show()
        APP.processEvents()
        assert dlg._editor.wordWrapMode() == QTextOption.WrapMode.WrapAnywhere
        assert time.monotonic() - started < 40
    finally:
        dlg.close()


def test_perf_the_tabbed_editor_wraps_an_unbreakable_line_anywhere(tmp_path):
    from unittest import mock

    from PyQt6.QtGui import QTextOption
    from PyQt6.QtWidgets import QMessageBox

    from ui import editor_window as EW

    path = tmp_path / "dump.hex"
    path.write_text(_unbreakable(EW.READ_ONLY_LINE_CHARS + 10))
    win = EW.EditorWindow()
    win.show()
    try:
        started = time.monotonic()
        tab = win.open_file(LocalFS(), str(path))
        APP.processEvents()
        assert tab.editor.wordWrapMode() == QTextOption.WrapMode.WrapAnywhere
        assert time.monotonic() - started < 40
    finally:
        with mock.patch("ui.editor_window.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Discard):
            win.close()
        win.deleteLater()
        APP.processEvents()


def test_sad_a_slow_save_keeps_the_windows_live_and_the_text_still(tmp_path):
    from PyQt6.QtCore import QTimer

    from ui.text_editor import TextEditorDialog

    path = tmp_path / "notes.txt"
    path.write_text("hello\n")
    fs = SlowFS()
    fs.gate.set()
    dlg = TextEditorDialog(fs, str(path))
    try:
        dlg._editor.appendPlainText("more")
        fs.gate.clear()  # the conflict check's read waits now
        seen = []

        def during_save():
            seen.append(dlg._editor.isReadOnly())
            fs.gate.set()

        QTimer.singleShot(100, during_save)
        dlg._save_file()
        assert seen == [True]
        assert not dlg._editor.isReadOnly() and not dlg._modified
        assert path.read_text().split() == ["hello", "more"]
    finally:
        fs.gate.set()
        dlg.close()
