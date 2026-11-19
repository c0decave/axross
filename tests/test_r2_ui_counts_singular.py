"""Counts of one read "1 item", not "1 item(s)" or "1 files".

Found in review (round 2 of the 2026-11 reviews, UI shell): Cut said
"Cut 1 item(s): ...", Batch Rename "Batch Rename – 1 files" and "1 files
selected", the production countdown "overwrite 1 item(s)" and the Move
check "1 source(s) cannot be removed" - in German "1 Element(e)",
"1 Dateien". core.i18n.tr_n picks the singular for one.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import i18n  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(params=["en", "de"])
def language(request):
    i18n.install(request.param)
    yield request.param
    i18n.install("en")


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    for name in ("a.txt", "b.txt"):
        (tmp_path / name).write_text("x")
    widget = FilePaneWidget(LocalFS())
    widget.resize(600, 300)
    widget.show()
    widget.navigate(str(tmp_path))
    APP.processEvents()
    yield widget
    from ui.cut_clipboard import cut_clipboard

    cut_clipboard().clear()
    widget.close()
    widget.deleteLater()
    APP.processEvents()


def _select(pane, names: set[str]) -> None:
    pane._restore_selection(names, sorted(names)[0])
    APP.processEvents()


def test_happy_cut_of_two_counts_in_the_plural(pane, language):
    _select(pane, {"a.txt", "b.txt"})
    assert pane.cut_selected()
    want = {"en": "Cut 2 items:", "de": "2 Elemente ausgeschnitten:"}[language]
    assert pane._status.text().startswith(want)


def test_sad_cut_of_one_counts_in_the_singular(pane, language):
    _select(pane, {"a.txt"})
    assert pane.cut_selected()
    want = {"en": "Cut 1 item: Paste (Ctrl+V) in a folder moves it there",
            "de": "1 Element ausgeschnitten: Einfügen (Strg+V) in einem Ordner "
                  "verschiebt es dorthin"}[language]
    assert pane._status.text() == want


def test_sad_batch_rename_of_one_file(tmp_path, language):
    from ui.batch_rename_dialog import BatchRenameDialog

    dlg = BatchRenameDialog(LocalFS(), str(tmp_path), [FileItem(name="a.txt")])
    title = {"en": "Batch Rename – 1 file", "de": "Mehrere umbenennen – 1 Datei"}[language]
    status = {"en": "1 file selected, 0 will be renamed",
              "de": "1 Datei ausgewählt, 0 werden umbenannt"}[language]
    assert dlg.windowTitle() == title
    assert dlg._status.text() == status
    dlg.deleteLater()


def test_edge_no_item_s_left_in_the_pane_and_the_window():
    """The source keeps none of the "(s)" counts that tr_n replaced."""
    for rel in ("ui/file_pane.py", "ui/main_window.py", "ui/batch_rename_dialog.py",
                "ui/tag_ui.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        found = re.findall(r'tr\("[^"]*\{(?:n|count)\} [A-Za-z]+\(s\)', text)
        assert found == [], (rel, found)
    catalogue = (ROOT / "resources/i18n/de.json").read_text(encoding="utf-8")
    for key in ("Cut {count} item(s)", "overwrite {count} item(s)", "move {count} item(s) here",
                "{count} source(s) cannot", "{count} selected item(s) left out"):
        assert key not in catalogue
