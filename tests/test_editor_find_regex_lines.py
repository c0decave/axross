"""The text editor's regex Find and Replace work line by line (review round 3).

Before: the pattern was compiled without ``re.MULTILINE``, so ``^`` and
``$`` meant the start and end of the whole file: ``^#include`` was not
found on line 2, and Replace All of ``\\s+$`` (trailing whitespace) removed
only the file's final newline. Now ``^`` and ``$`` are each line's.
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


def _bar(window, tmp_path, text: str):
    path = tmp_path / "t.c"
    path.write_text(text)
    tab = window.open_file(LocalFS(), str(path))
    window.show_find(replace=True)
    bar = window.find_bar
    bar.regex.setChecked(True)
    return tab, bar


def test_sad_a_line_start_anchor_finds_a_later_line(window, tmp_path):
    tab, bar = _bar(window, tmp_path, "int a;\n#include <x.h>\n")
    bar.find_edit.setText("^#include")
    assert bar.find_next(), bar.message.text()
    assert tab.editor.textCursor().selectedText() == "#include"


def test_sad_replace_all_trailing_whitespace_cleans_every_line(window, tmp_path):
    tab, bar = _bar(window, tmp_path, "foo  \nbar\t\nbaz\n")
    bar.find_edit.setText("[ \\t]+$")
    bar.replace_edit.setText("")
    assert bar.replace_all() == 2
    assert tab.editor.toPlainText() == "foo\nbar\nbaz\n"


def test_edge_a_whole_line_anchor_and_replace_one(window, tmp_path):
    """``^bar$`` is the middle line only; Replace takes the match found."""
    tab, bar = _bar(window, tmp_path, "foobar\nbar\nbarbaz\n")
    bar.find_edit.setText("^bar$")
    assert bar.find_next()
    bar.replace_edit.setText("BAR")
    bar.replace_one()
    assert tab.editor.toPlainText() == "foobar\nBAR\nbarbaz\n"
