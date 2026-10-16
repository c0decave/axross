"""Saving in the text editor writes back the bytes it did not touch.

Found in review: QPlainTextEdit folds every line ending into a block
break and ``toPlainText()`` rewrites no-break spaces and U+2028, so a
one-character edit to a Windows file saved every line as LF, turned
each NBSP into a plain space and dropped a UTF-8 BOM. These tests drive
the real dialog: open, type, press Save, read the file back.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _edit_and_save(path: Path, typed: str = "Z", click: bool = True) -> bytes:
    """Open *path*, type *typed* at the very end, click Save.

    ``click=False`` calls the save slot directly, so an exception that
    escapes it fails the test instead of aborting the Qt process."""
    from ui.text_editor import TextEditorDialog

    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        cursor = dlg._editor.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        dlg._editor.setTextCursor(cursor)
        dlg._editor.insertPlainText(typed)
        assert dlg._btn_save.isEnabled()
        if click:
            dlg._btn_save.click()
        else:
            dlg._save_file()
        return path.read_bytes()
    finally:
        dlg._modified = False
        dlg.deleteLater()
        APP.processEvents()


# -- happy ----------------------------------------------------------------


def test_happy_a_crlf_file_keeps_crlf_on_every_line(tmp_path):
    path = tmp_path / "dos.txt"
    path.write_bytes(b"line one\r\nline two\r\n")
    assert _edit_and_save(path) == b"line one\r\nline two\r\nZ"


def test_happy_an_lf_file_stays_lf(tmp_path):
    path = tmp_path / "unix.txt"
    path.write_bytes(b"one\ntwo\n")
    assert _edit_and_save(path) == b"one\ntwo\nZ"


def test_happy_a_utf8_bom_survives_the_save(tmp_path):
    path = tmp_path / "bom.txt"
    path.write_bytes(b"\xef\xbb\xbfhello\n")
    assert _edit_and_save(path) == b"\xef\xbb\xbfhello\nZ"


# -- edge -----------------------------------------------------------------


def test_edge_no_break_space_and_line_separator_are_kept(tmp_path):
    path = tmp_path / "nbsp.txt"
    body = "a b c\n"
    path.write_bytes(body.encode("utf-8"))
    assert _edit_and_save(path) == (body + "Z").encode("utf-8")


def test_edge_a_latin1_no_break_space_byte_is_kept(tmp_path):
    path = tmp_path / "latin.txt"
    path.write_bytes(b"caf\xe9\xa0z\n")
    assert _edit_and_save(path) == b"caf\xe9\xa0z\nZ"


def test_edge_old_mac_cr_line_endings_are_kept(tmp_path):
    path = tmp_path / "mac.txt"
    path.write_bytes(b"a\rb\r")
    assert _edit_and_save(path) == b"a\rb\rZ"


def test_edge_an_empty_file_saves_only_what_was_typed(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    assert _edit_and_save(path, "x") == b"x"


def test_edge_a_text_without_final_newline_gets_none_added(tmp_path):
    path = tmp_path / "bare.txt"
    path.write_bytes(b"one\r\ntwo")
    assert _edit_and_save(path) == b"one\r\ntwoZ"


# -- sad ------------------------------------------------------------------


def test_sad_a_character_latin1_cannot_store_is_reported_and_nothing_written(tmp_path):
    path = tmp_path / "latin.txt"
    original = b"caf\xe9\n"
    path.write_bytes(original)
    with mock.patch("ui.text_editor.QMessageBox.critical") as critical:
        _edit_and_save(path, "€", click=False)  # the euro sign has no Latin-1 byte
    critical.assert_called_once()
    assert "LATIN-1" in critical.call_args[0][2]
    assert path.read_bytes() == original


def test_sad_declining_a_changed_file_still_writes_nothing(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "dos.txt"
    path.write_bytes(b"a\r\n")
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        path.write_bytes(b"changed elsewhere\r\n")
        dlg._editor.insertPlainText("Z")
        with mock.patch(
            "ui.text_editor.QMessageBox.question", return_value=QMessageBox.StandardButton.No
        ):
            dlg._btn_save.click()
        assert path.read_bytes() == b"changed elsewhere\r\n"
    finally:
        dlg._modified = False
        dlg.deleteLater()
        APP.processEvents()
