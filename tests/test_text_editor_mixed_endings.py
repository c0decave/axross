"""A file with mixed line endings keeps the endings of the lines not edited.

Found in review (round 2): the editor remembered ONE line ending per file
- CRLF as soon as any CRLF was present - and joined every line with it on
save. A one-character edit to a file holding both LF and CRLF lines
rewrote every LF line as CRLF; a U+2029 paragraph separator (which the
text widget also treats as a line break) became a plain line ending. The
same kind of change to bytes the user did not touch that 0.7.72 fixed for
single-ending files.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.test_text_editor_save_fidelity import _edit_and_save  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _edit_with(path: Path, action) -> bytes:
    """Open *path*, run *action(editor)*, press Save, return the file's bytes."""
    from ui.text_editor import TextEditorDialog

    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        action(dlg._editor)
        dlg._btn_save.click()
        return path.read_bytes()
    finally:
        dlg._modified = False
        dlg.deleteLater()
        APP.processEvents()


def _at_line_end(editor, line: int, text: str) -> None:
    block = editor.document().findBlockByNumber(line)
    cursor = editor.textCursor()
    cursor.setPosition(block.position() + block.length() - 1)
    editor.setTextCursor(cursor)
    editor.insertPlainText(text)


# -- happy ----------------------------------------------------------------


def test_happy_editing_the_end_keeps_each_lines_own_ending(tmp_path):
    path = tmp_path / "mixed.txt"
    path.write_bytes(b"a\nb\r\nc\n")
    assert _edit_and_save(path) == b"a\nb\r\nc\nZ"


def test_happy_an_edited_line_keeps_its_ending(tmp_path):
    path = tmp_path / "mixed.txt"
    path.write_bytes(b"one\ntwo\r\nthree\n")
    assert _edit_with(path, lambda ed: _at_line_end(ed, 1, "!")) == b"one\ntwo!\r\nthree\n"


# -- sad ------------------------------------------------------------------


def test_sad_a_paragraph_separator_is_not_turned_into_a_line_ending(tmp_path):
    path = tmp_path / "para.txt"
    path.write_bytes("a b\n".encode("utf-8"))
    assert _edit_and_save(path) == "a b\nZ".encode("utf-8")


def test_sad_deleting_a_line_leaves_the_others_alone(tmp_path):
    path = tmp_path / "mixed.txt"
    path.write_bytes(b"keep\ndrop\r\nlast\n")

    def drop_line(editor):
        block = editor.document().findBlockByNumber(1)
        cursor = editor.textCursor()
        cursor.setPosition(block.position())
        cursor.setPosition(block.position() + block.length(), cursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()

    assert _edit_with(path, drop_line) == b"keep\nlast\n"


# -- edge -----------------------------------------------------------------


def test_edge_a_new_line_gets_the_files_most_common_ending(tmp_path):
    path = tmp_path / "mixed.txt"
    path.write_bytes(b"a\nb\r\nc\r\n")
    assert _edit_with(path, lambda ed: _at_line_end(ed, 0, "\nX")) == b"a\nX\r\nb\r\nc\r\n"


def test_edge_saving_twice_keeps_the_endings(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "mixed.txt"
    path.write_bytes(b"a\nb\r\n")
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        _at_line_end(dlg._editor, 0, "1")
        dlg._btn_save.click()
        _at_line_end(dlg._editor, 1, "2")
        dlg._btn_save.click()
        assert path.read_bytes() == b"a1\nb2\r\n"
    finally:
        dlg._modified = False
        dlg.deleteLater()
        APP.processEvents()


def test_edge_a_bare_cr_and_crlf_mix_is_kept(tmp_path):
    path = tmp_path / "mixed.txt"
    path.write_bytes(b"a\rb\r\nc")
    assert _edit_and_save(path) == b"a\rb\r\ncZ"
