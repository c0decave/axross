"""The editor saves, saves as and reloads without freezing its window.

Audit (feedback: no blocked windows): Ctrl+S re-read the file (the
conflict check) and wrote it through the backend on the GUI thread; Save
As asked the backend whether the target existed there; Reload read the
whole file there - on a server every one of them froze all windows. Save
must still answer whether the file was written (closing a tab with
unsaved changes depends on it), so it waits - in a local event loop
(ui.off_gui.run_off_gui): the windows keep painting, timers run, the
call runs on a worker; keys and clicks are held back until the file is
written and then delivered.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QKeyEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui import off_gui  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class SlowFS(LocalFS):
    """A server: every read and write takes a while; who called is noted."""

    delay = 0.4

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[str] = []
        self.fail: Exception | None = None

    def _note(self) -> None:
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail

    def open_write(self, path, *args, **kwargs):
        self._note()
        return super().open_write(path, *args, **kwargs)

    def open_read(self, path):
        self._note()
        return super().open_read(path)

    def exists(self, path):
        self._note()
        return super().exists(path)


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.show()
    yield win
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


@pytest.fixture
def tab(window, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("one\n")
    fs = SlowFS()
    fs.delay = 0.0
    t = window.open_file(fs, str(path))
    fs.delay = SlowFS.delay
    fs.threads.clear()
    return t


def _ticks_during(fn) -> tuple[object, int]:
    """fn()'s result and how often a 20 ms timer fired meanwhile."""
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        value = fn()
    finally:
        timer.stop()
    return value, len(ticks)


# -- happy ------------------------------------------------------------------------------------


def test_happy_save_writes_off_the_gui_thread_and_the_window_stays_live(window, tab, tmp_path):
    tab.editor.setPlainText("one\ntwo\n")
    tab.editor.document().setModified(True)
    saved, ticks = _ticks_during(lambda: window.save_tab(tab))
    assert saved is True
    assert (tmp_path / "notes.txt").read_text() == "one\ntwo\n"
    assert ticks >= 1  # the event loop ran while the server worked
    assert tab.backend.threads and "MainThread" not in tab.backend.threads
    assert not tab.is_modified()


def test_happy_keys_typed_during_the_save_land_after_it(window, tab, tmp_path):
    tab.editor.setPlainText("saved")
    tab.editor.document().setModified(True)
    cursor = tab.editor.textCursor()
    cursor.movePosition(cursor.MoveOperation.End)
    tab.editor.setTextCursor(cursor)
    tab.editor.setFocus()
    QTimer.singleShot(50, lambda: APP.postEvent(
        tab.editor,
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_X, Qt.KeyboardModifier.NoModifier, "x")))
    assert window.save_tab(tab)
    assert (tmp_path / "notes.txt").read_text() == "saved"  # the file has the text of the save
    APP.processEvents()
    assert tab.editor.toPlainText() == "savedx"  # the key was not lost
    assert tab.is_modified()  # and the tab knows the file lacks it


def test_happy_reload_reads_off_the_gui_thread(window, tab, tmp_path):
    (tmp_path / "notes.txt").write_text("changed outside\n")
    _none, ticks = _ticks_during(window.reload_current)
    assert tab.editor.toPlainText() == "changed outside\n"
    assert ticks >= 1 and "MainThread" not in tab.backend.threads


def test_happy_save_as_checks_the_target_off_the_gui_thread(window, tab, tmp_path):
    target = tmp_path / "copy.txt"
    with mock.patch.object(window, "_ask_save_path", return_value=(tab.backend, str(target))):
        assert window.save_as(tab)
    assert target.read_text() == "one\n"
    assert "MainThread" not in tab.backend.threads


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_failing_write_is_reported_and_answers_false(window, tab, tmp_path):
    tab.editor.setPlainText("lost?")
    tab.editor.document().setModified(True)
    tab.backend.fail = PermissionError(13, "Permission denied")
    with mock.patch("ui.editor_window.QMessageBox.critical") as critical:
        assert window.save_tab(tab) is False
    critical.assert_called_once()
    assert "Permission denied" in critical.call_args.args[2]
    assert tab.is_modified()  # still unsaved: closing will ask


def test_sad_closing_a_modified_tab_waits_for_its_save(window, tab, tmp_path):
    tab.editor.setPlainText("keep me")
    tab.editor.document().setModified(True)
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Save):
        assert window._confirm_close(tab) is True
    assert (tmp_path / "notes.txt").read_text() == "keep me"


# -- edge -------------------------------------------------------------------------------------


def test_edge_run_off_gui_hands_back_the_value_and_the_exception():
    assert off_gui.run_off_gui(lambda: threading.current_thread().name) != "MainThread"
    with pytest.raises(KeyError):
        off_gui.run_off_gui(lambda: {}["missing"])


def test_edge_off_the_gui_thread_it_just_calls():
    seen = []
    worker = threading.Thread(target=lambda: seen.append(
        off_gui.run_off_gui(lambda: threading.current_thread().name)))
    worker.start()
    worker.join()
    assert seen == [worker.name]


def test_edge_a_slow_call_says_so_and_clears_it():
    texts: list[str] = []
    off_gui.run_off_gui(lambda: time.sleep(off_gui.BUSY_CURSOR_AFTER_MS / 1000 + 0.2),
                        status=texts.append, text="Writing x…")
    assert texts == ["Writing x…", ""]
    assert QApplication.overrideCursor() is None


def test_edge_a_quick_call_says_nothing():
    texts: list[str] = []
    off_gui.run_off_gui(lambda: None, status=texts.append, text="Writing x…")
    assert texts == []


def test_edge_highlighting_anew_during_the_save_still_counts_as_saved(window, tab, tmp_path):
    """Found by the review: the check compared the document's revision,
    which every rehighlight() raises - a save while the highlighter ran
    (200 ms after the last key, or while the conflict question was open)
    stayed marked modified. The written text is compared now."""
    tab.editor.setPlainText("def f():\n    return 1\n")
    tab.editor.document().setModified(True)
    highlighter = (getattr(tab.editor, "_highlighter", None)
                   or getattr(tab.editor, "highlighter", None))
    doc = tab.editor.document()

    def rehighlight():
        if highlighter is not None and hasattr(highlighter, "rehighlight"):
            highlighter.rehighlight()
        else:  # any format change raises the revision the same way
            from PyQt6.QtGui import QTextCharFormat, QTextCursor

            cursor = QTextCursor(doc)
            cursor.select(QTextCursor.SelectionType.Document)
            fmt = QTextCharFormat()
            fmt.setFontWeight(400)
            cursor.mergeCharFormat(fmt)
            doc.setModified(True)

    QTimer.singleShot(100, rehighlight)
    assert window.save_tab(tab)
    assert not tab.is_modified()
    assert (tmp_path / "notes.txt").read_text() == "def f():\n    return 1\n"
