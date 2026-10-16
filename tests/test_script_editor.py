"""ui.script_editor: the Scripts dock's Python editor.

QPlainTextEdit plus our own highlighter (no new dependency): line
numbers, auto-indent, Tab = four spaces, and a way to jump to a line
from a traceback.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui.script_editor import CodeEditor, PythonHighlighter  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def editor():
    ed = CodeEditor()
    ed.resize(600, 400)
    ed.show()
    APP.processEvents()
    yield ed
    ed.close()
    ed.deleteLater()
    APP.processEvents()


def _kinds(editor: CodeEditor, line: int) -> dict[str, str]:
    """{token text: format kind} for one line, as the highlighter set it."""
    block = editor.document().findBlockByNumber(line)
    text = block.text()
    out: dict[str, str] = {}
    for rng in block.layout().formats():
        kind = rng.format.property(PythonHighlighter.KIND_PROPERTY)
        out[text[rng.start : rng.start + rng.length]] = kind
    return out


def _type(editor: CodeEditor, text: str) -> None:
    QTest.keyClicks(editor, text)


def _key(editor: CodeEditor, key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    QTest.keyClick(editor, key, mods)


# ---------------------------------------------------------------------------
# Highlighting
# ---------------------------------------------------------------------------


def test_happy_keywords_strings_comments_and_numbers_are_highlighted(editor) -> None:
    editor.setPlainText("def main(x=42):\n    return 'hi'  # done\n")
    APP.processEvents()
    first = _kinds(editor, 0)
    assert first["def"] == "keyword"
    assert first["main"] == "definition"
    assert first["42"] == "number"
    second = _kinds(editor, 1)
    assert second["return"] == "keyword"
    assert second["'hi'"] == "string"
    assert second["# done"] == "comment"


def test_sad_a_hash_inside_a_string_is_not_a_comment(editor) -> None:
    editor.setPlainText("url = 'http://h/#anchor'\n")
    APP.processEvents()
    kinds = _kinds(editor, 0)
    assert kinds["'http://h/#anchor'"] == "string"
    assert "comment" not in kinds.values()


def test_edge_a_triple_quoted_string_spans_lines(editor) -> None:
    editor.setPlainText('doc = """first\nif while\nend""" + x\nif y:\n')
    APP.processEvents()
    assert _kinds(editor, 1) == {"if while": "string"}  # keywords inside stay string
    third = _kinds(editor, 2)
    assert third['end"""'] == "string"
    assert _kinds(editor, 3)["if"] == "keyword"  # and the string ended


def test_edge_decorators_and_builtins(editor) -> None:
    editor.setPlainText("@staticmethod\nprint(None, True)\n")
    APP.processEvents()
    assert _kinds(editor, 0)["@staticmethod"] == "decorator"
    second = _kinds(editor, 1)
    assert second["print"] == "builtin"
    assert second["None"] == "keyword"


# ---------------------------------------------------------------------------
# Indentation
# ---------------------------------------------------------------------------


def test_happy_tab_inserts_four_spaces(editor) -> None:
    _key(editor, Qt.Key.Key_Tab)
    _type(editor, "x")
    assert editor.toPlainText() == "    x"


def test_happy_return_keeps_the_indent_and_opens_a_block_after_a_colon(editor) -> None:
    _type(editor, "def f():")
    _key(editor, Qt.Key.Key_Return)
    _type(editor, "x = 1")
    _key(editor, Qt.Key.Key_Return)
    _type(editor, "y = 2")
    assert editor.toPlainText() == "def f():\n    x = 1\n    y = 2"


def test_sad_return_on_an_unindented_line_adds_no_indent(editor) -> None:
    _type(editor, "x = 1")
    _key(editor, Qt.Key.Key_Return)
    _type(editor, "y")
    assert editor.toPlainText() == "x = 1\ny"


def test_edge_return_after_return_or_pass_dedents(editor) -> None:
    editor.setPlainText("def f():\n    return 1")
    editor.moveCursor(editor.textCursor().MoveOperation.End)
    _key(editor, Qt.Key.Key_Return)
    _type(editor, "z")
    assert editor.toPlainText().splitlines()[-1] == "z"


def test_edge_shift_tab_removes_up_to_four_leading_spaces(editor) -> None:
    editor.setPlainText("      x")  # six spaces
    editor.moveCursor(editor.textCursor().MoveOperation.End)
    _key(editor, Qt.Key.Key_Backtab, Qt.KeyboardModifier.ShiftModifier)
    assert editor.toPlainText() == "  x"
    _key(editor, Qt.Key.Key_Backtab, Qt.KeyboardModifier.ShiftModifier)
    assert editor.toPlainText() == "x"
    _key(editor, Qt.Key.Key_Backtab, Qt.KeyboardModifier.ShiftModifier)
    assert editor.toPlainText() == "x"  # nothing left to remove: no change


def test_edge_tab_and_shift_tab_work_on_every_selected_line(editor) -> None:
    editor.setPlainText("a\nb\nc")
    editor.selectAll()
    _key(editor, Qt.Key.Key_Tab)
    assert editor.toPlainText() == "    a\n    b\n    c"
    editor.selectAll()
    _key(editor, Qt.Key.Key_Backtab, Qt.KeyboardModifier.ShiftModifier)
    assert editor.toPlainText() == "a\nb\nc"


def test_edge_tab_and_return_are_ignored_when_read_only(editor) -> None:
    editor.setPlainText("x")
    editor.setReadOnly(True)
    _key(editor, Qt.Key.Key_Tab)
    _key(editor, Qt.Key.Key_Return)
    assert editor.toPlainText() == "x"


# ---------------------------------------------------------------------------
# Line numbers and jumping to a line
# ---------------------------------------------------------------------------


def test_happy_the_line_number_area_grows_with_the_line_count(editor) -> None:
    editor.setPlainText("x\n")
    narrow = editor.line_number_area_width()
    editor.setPlainText("x\n" * 12000)
    assert editor.line_number_area_width() > narrow
    assert editor.viewportMargins().left() == editor.line_number_area_width()


def test_happy_go_to_line_moves_the_cursor_and_marks_the_line(editor) -> None:
    editor.setPlainText("a\nb\nc\nd\n")
    assert editor.go_to_line(3) is True
    assert editor.textCursor().blockNumber() == 2
    marked = [s.cursor.blockNumber() for s in editor.extraSelections()]
    assert 2 in marked


def test_sad_go_to_a_line_past_the_end_is_refused(editor) -> None:
    editor.setPlainText("a\nb\n")
    editor.moveCursor(editor.textCursor().MoveOperation.Start)
    assert editor.go_to_line(99) is False
    assert editor.go_to_line(0) is False
    assert editor.textCursor().blockNumber() == 0
