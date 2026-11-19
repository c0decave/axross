"""Round 3 (low from round 2): Tagged Files' Where column showed the
connection's profile name as it is - a profile named
``nas\\u202e3pm.exe`` (a name the user may have taken over from an
imported profile list) read reversed there, where every other column and
the pane show a bidi override as U+FFFD. A profile name holding markup
stays text (an item's text is plain)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as T  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


def test_sad_a_bidi_profile_name_is_defused_in_the_where_column(store, tmp_path):
    from ui.tag_ui import TaggedFilesDialog

    store.define("work", "#3366cc")
    store.tag(f"SFTP{RLO}x", f"nas{RLO}3pm.exe", "/srv/report.txt", "work")
    dialog = TaggedFilesDialog()
    try:
        dialog.select_tag("work")
        where = dialog.files.item(0, 2).text()
        assert RLO not in where
        assert "\ufffd" in where
        assert where.startswith("SFTP\ufffdx")
        assert "nas\ufffd3pm.exe" in where
    finally:
        dialog.deleteLater()


def test_edge_choosing_a_tag_fills_the_table_once(store, monkeypatch):
    """select_tag (Go to a tag from the menu) filled the table twice - the
    row change fills it, and then select_tag again: 4 s instead of 2 s for
    a tag on 100 000 files (the store's limit)."""
    from ui.tag_ui import TaggedFilesDialog

    store.define("one", "#3366cc")
    store.define("two", "#cc6633")
    store.tag("Local", "", "/a.txt", "one")
    store.tag("Local", "", "/b.txt", "two")
    dialog = TaggedFilesDialog()
    try:
        calls = []
        original = TaggedFilesDialog._show
        monkeypatch.setattr(TaggedFilesDialog, "_show",
                            lambda self, item: (calls.append(item), original(self, item)))
        dialog.select_tag("two")
        assert len(calls) == 1
        assert dialog.files.item(0, 0).text() == "b.txt"
        dialog.select_tag("two")                   # already shown: filled again, once
        assert len(calls) == 2
    finally:
        dialog.deleteLater()
