"""The text editor dialog reads and writes UTF-16 files.

Review: TextEditorDialog (the Markdown viewer's Edit fallback, the text
view without a main window) decoded only UTF-8 and Latin-1: a UTF-16 file
showed as "\\xff\\xfe#\\x00 \\x00..." and one typed letter saved a file
that was no UTF-16 any more. It decodes as the tabbed editor does now
(core.text_document.decode) and writes back the encoding, the BOM and
the byte order it read.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

TEXT = "# Überschrift\r\nHallo\r\n"


@pytest.mark.parametrize("codec, bom", [("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")])
def test_happy_a_utf16_file_opens_as_text_and_saves_as_utf16(tmp_path, codec, bom):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "notes.md"
    path.write_bytes(bom + TEXT.encode(codec))
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        assert dlg._editor.document().begin().text() == "# Überschrift"
        assert dlg._encoding_label.text() == "UTF-16"
        cursor = dlg._editor.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        dlg._editor.setTextCursor(cursor)
        dlg._editor.insertPlainText("!")
        dlg._save_file()
    finally:
        dlg.close()
    assert path.read_bytes() == bom + (TEXT + "!").encode(codec)


def test_edge_an_untouched_utf16_file_saves_its_own_bytes(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "notes.txt"
    raw = b"\xff\xfe" + TEXT.encode("utf-16-le")
    path.write_bytes(raw)
    dlg = TextEditorDialog(LocalFS(), str(path))
    try:
        assert dlg._encoded_text() == raw
    finally:
        dlg.close()
