#!/usr/bin/env python3
"""What the file pane's right-click menu offers.

The duplicate finder existed for a while under the name "CAS Duplicate
Finder", buried in the View menu — named for the storage technique
rather than for what it does, which is why nobody found it. It is now
reachable where a user actually looks for it: on the directory they are
standing in.
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
from ui.file_pane import FilePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def pane(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "sub").mkdir()
    widget = FilePaneWidget(LocalFS())
    widget.resize(600, 400)
    widget.show()
    APP.processEvents()
    widget.navigate(str(tmp_path))
    APP.processEvents()
    try:
        yield widget
    finally:
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def _menu_texts(widget) -> list[str]:
    return [a.text() for a in widget._build_context_menu().actions()]


def test_happy_duplicate_finder_is_offered_without_a_selection(pane):
    """It acts on the current directory, so it must not require the
    user to select a file first — that is the state you are in right
    after navigating somewhere you suspect has duplicates."""
    assert any("Duplicate" in t for t in _menu_texts(pane)), _menu_texts(pane)


def test_happy_entry_is_named_for_what_it_does_not_for_cas(pane):
    entry = next(t for t in _menu_texts(pane) if "Duplicate" in t)
    assert "CAS" not in entry, entry


def test_happy_triggering_the_entry_emits_the_request(pane):
    """The pane does not own the dialog; the main window does. Same
    pattern as the bookmarks popup."""
    seen: list[bool] = []
    pane.open_duplicates_requested.connect(lambda: seen.append(True))

    action = next(
        a for a in pane._build_context_menu().actions() if "Duplicate" in a.text()
    )
    action.trigger()
    APP.processEvents()
    assert seen == [True]


def test_edge_menu_still_offers_the_pre_existing_entries(pane):
    """Guard against an insertion that displaces something."""
    texts = _menu_texts(pane)
    for expected in ("Refresh", "New Folder", "New File…"):
        assert any(expected in t for t in texts), (expected, texts)
