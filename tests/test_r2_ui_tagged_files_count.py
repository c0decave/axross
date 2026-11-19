"""Tagged Files counts in the singular for one file.

Found in review (round 2 of the 2026-11 reviews, UI shell): the note
under the list and a tag's tooltip read "1 files" ("1 Dateien" in
German) - tr("{n} files") was formatted for every count.
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

from core import i18n  # noqa: E402
from core import tags as T  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


@pytest.fixture
def german():
    i18n.install("de")
    yield
    i18n.install("en")


def _dialog():
    from ui.tag_ui import TaggedFilesDialog

    dlg = TaggedFilesDialog()
    dlg.select_tag("Important")
    return dlg


def test_happy_two_files_are_counted_in_the_plural(store):
    store.tag("Local", "", "/data/a.txt", "Important")
    store.tag("Local", "", "/data/b.txt", "Important")
    dlg = _dialog()
    assert dlg.note.text() == "2 files"
    assert dlg.tags.item(0).toolTip() == "2 files"
    dlg.deleteLater()


def test_sad_one_file_is_counted_in_the_singular(store):
    store.tag("Local", "", "/data/a.txt", "Important")
    dlg = _dialog()
    assert dlg.note.text() == "1 file"
    assert dlg.tags.item(0).toolTip() == "1 file"
    dlg.deleteLater()


def test_edge_one_file_in_german(store, german):
    store.tag("Local", "", "/data/a.txt", "Important")
    dlg = _dialog()
    assert dlg.note.text() == "1 Datei"
    assert dlg.tags.item(0).toolTip() == "1 Datei"
    dlg.deleteLater()
