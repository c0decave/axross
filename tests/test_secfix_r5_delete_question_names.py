"""Round-5 finding: the Delete question showed names escaped twice and let
bidi overrides and line breaks through (ui/file_pane.py _dialog_item_names).

The names were HTML-escaped, then the whole question again and handed to
the static QMessageBox.question(), which guesses the format: a question
without markup is plain text, so "Tom & Jerry.mp3" read "Tom &amp;
Jerry.mp3"; "invoice\\u202efdp.exe" read "invoiceexe.pdf"; a name with 40
line breaks pushed the names after it out of sight - the user confirmed
deleting files they could not see. Now each name shows its control and
format characters as codes, and the question is shown as written.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.test_trash_question_verb import pane  # noqa: E402,F401 - the fixture
from ui.file_pane import _dialog_item_names, _shown_name  # noqa: E402

RLO = "\u202e"


def _reads(text: str) -> str:
    """What the user reads in a message box showing *text*."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QTextDocument

    from ui import markup_guard as MG

    shown = MG.defuse_message(text)
    if not Qt.mightBeRichText(shown):
        return shown
    doc = QTextDocument()
    doc.setHtml(shown)
    return doc.toPlainText()


def test_happy_ordinary_names_are_shown_as_they_are():
    items = [NS(name=n) for n in ("Tom & Jerry.mp3", "a<b.txt", "a&lt;b.txt", "Übersicht.pdf")]
    assert _dialog_item_names(items) == "Tom & Jerry.mp3, a<b.txt, a&lt;b.txt, Übersicht.pdf"


def test_sad_bidi_overrides_and_line_breaks_show_as_codes():
    assert _shown_name("invoice" + RLO + "fdp.exe") == "invoice\\u202efdp.exe"
    assert _shown_name("keep.txt" + "\n" * 3 + "x") == "keep.txt" + "\\u000a" * 3 + "x"
    assert "\n" not in _dialog_item_names([NS(name="a\nb"), NS(name="c\rd")])


def test_edge_a_very_long_name_is_cut_in_the_middle_and_more_items_are_counted():
    cut = _shown_name("x" * 5000 + ".exe")
    assert len(cut) == 200 and "…" in cut and cut.endswith(".exe")
    names = _dialog_item_names([NS(name=str(i)) for i in range(8)])
    assert names.endswith("(+3 more)")


def _ask_about(pane, names: list[str]) -> str:
    from PyQt6.QtCore import QItemSelectionModel
    from PyQt6.QtWidgets import QMessageBox

    for name in names:
        Path(pane.current_path, name).write_text("x")
    pane.navigate(pane.current_path)
    model = pane._table.model()
    assert pane.test_wait(lambda: model.rowCount() >= 4 + len(names))
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    for row in range(model.rowCount()):
        shown = str(model.index(row, 0).data())
        if any(shown.startswith(name[:5]) for name in names):
            pane._table.selectionModel().select(model.index(row, 0), flags)
    asked: list[str] = []

    def question(_parent, _title, text, *a, **k):
        asked.append(text)
        return QMessageBox.StandardButton.No

    with mock.patch("ui.file_pane.QMessageBox.question", side_effect=question):
        pane._start_removal(trash=False)
        assert pane.test_wait(lambda: bool(asked) and not pane.removal_running)
    return _reads(asked[0])


def test_e2e_the_delete_question_reads_each_name_once_and_as_it_is(pane):
    hidden = "keep.txt" + "\n" * 40 + "ALSO-DELETED"
    names = ["Tom & Jerry.mp3", "invoice" + RLO + "fdp.exe", hidden]
    text = _ask_about(pane, names)
    assert "Tom & Jerry.mp3" in text and "&amp;" not in text
    assert RLO not in text and "invoice\\u202efdp.exe" in text
    line = next(line for line in text.splitlines() if "keep.txt" in line)
    assert "ALSO-DELETED" in line, "the rest of the name is pushed out of sight"
