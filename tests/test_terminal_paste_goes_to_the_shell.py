"""Paste, a text drop and input-method text go to the shell, and the
terminal's document only ever shows the screen.

Reproduced 2026-10-17: Paste from the context menu, a middle click or a
text dropped on the terminal went through QPlainTextEdit.insertFromMimeData
into the document - nothing reached the pty, and the next output drew over
a document with extra lines ("out0" twice, the prompt in the wrong row).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QInputMethodEvent, QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


@pytest.fixture
def term(app):
    from ui.terminal_widget import TerminalEmulator

    t = TerminalEmulator()
    t.resize(700, 300)
    t.show()
    _pump(app)
    t.sent = []
    t.data_ready.connect(t.sent.append)
    t.append_output("".join(f"out{i}\r\n" for i in range(3)) + "$ ")
    yield t
    t.deleteLater()
    _pump(app)


def _shows_the_screen(t) -> bool:
    screen = t.screen
    expected = list(screen.scrollback) + [line.rstrip() for line in screen.screen_lines()]
    return [line.rstrip() for line in t.toPlainText().split("\n")] == expected


def _text_mime(text: str) -> QMimeData:
    mime = QMimeData()
    mime.setText(text)
    return mime


def _drop(t, mime: QMimeData, action=Qt.DropAction.MoveAction):
    """Deliver a drag as Qt does: DragEnter to the viewport, and only when
    that was accepted the Drop. Returns (enter, drop or None)."""
    actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
    enter = QDragEnterEvent(
        QPoint(10, 10), actions, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier
    )
    enter.setDropAction(action)
    enter.ignore()
    QApplication.sendEvent(t.viewport(), enter)
    if not enter.isAccepted():
        return enter, None
    drop = QDropEvent(
        QPointF(10, 10), actions, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier
    )
    drop.setDropAction(action)
    drop.ignore()
    QApplication.sendEvent(t.viewport(), drop)
    return enter, drop


# -- happy ---------------------------------------------------------------------


def test_happy_pasted_text_goes_to_the_shell_not_into_the_document(app, term):
    term.insertFromMimeData(_text_mime("rm -rf build\nmake install"))
    assert term.sent == [b"rm -rf build\nmake install"]
    assert _shows_the_screen(term)
    term.append_output("y")
    assert _shows_the_screen(term)
    assert term.toPlainText().split("\n")[:4] == ["out0", "out1", "out2", "$ y"]


def test_happy_the_paste_action_sends_the_clipboard(app, term):
    QApplication.clipboard().setText("make install")
    term.paste()
    assert term.sent == [b"make install"]
    assert _shows_the_screen(term)


def test_happy_a_text_drop_goes_to_the_shell_as_a_copy(app, term):
    _enter, drop = _drop(term, _text_mime("ls -l"))
    assert term.sent == [b"ls -l"]
    assert drop is not None and drop.isAccepted()
    assert drop.dropAction() == Qt.DropAction.CopyAction
    assert _shows_the_screen(term)


def test_happy_input_method_text_goes_to_the_shell(app, term):
    event = QInputMethodEvent()
    event.setCommitString("日本")
    term.inputMethodEvent(event)
    assert term.sent == ["日本".encode()]
    assert _shows_the_screen(term)


# -- sad -----------------------------------------------------------------------


def test_sad_data_without_text_is_not_pasted_or_dropped(app, term):
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile("/tmp/a file")])
    mime.setData("application/x-axross-transfer", b"{}")
    assert term.canInsertFromMimeData(mime) is False
    term.insertFromMimeData(mime)
    enter, drop = _drop(term, mime)
    assert term.sent == []
    assert not enter.isAccepted() and drop is None
    assert _shows_the_screen(term)


def test_sad_empty_text_sends_nothing(app, term):
    term.insertFromMimeData(_text_mime(""))
    event = QInputMethodEvent()
    event.setCommitString("")
    term.inputMethodEvent(event)
    assert term.sent == []
    assert _shows_the_screen(term)


def test_sad_the_context_menu_offers_no_editing_of_the_screen(app, term):
    menu = term._context_menu()
    names = [
        a.text().replace("&", "").split("\t")[0] for a in menu.actions() if not a.isSeparator()
    ]
    assert names == ["Copy", "Paste", "Select All"]
    menu.deleteLater()


# -- edge ----------------------------------------------------------------------


def test_edge_an_edit_of_the_document_is_drawn_over_with_the_screen(app, term):
    """Whatever path edits the document (a drag that moves the selection
    out, a cut), the terminal shows the screen again."""
    cursor = term.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
    cursor.removeSelectedText()
    cursor.insertText("junk")
    _pump(app)
    assert _shows_the_screen(term)
    term.append_output("z")
    assert _shows_the_screen(term)
    assert term.toPlainText().split("\n")[:4] == ["out0", "out1", "out2", "$ z"]

