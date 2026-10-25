"""Esc clears the pane's filter.

Operator: "wenn in der pane der filter aktiviert ist und man auf ESC drückt
sollte der filter gelöscht werden".

Before: Esc in the file list stopped a running load or cleared the
selection, and Esc in the filter line did nothing - the filter stayed and
hid most of the folder. Now Esc in the filter line clears it and returns
to the list; Esc in the list stops a load first, then clears a filter,
then the selection, then drops a pending Cut of this pane.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
NAMES = ("alpha.txt", "beta.txt", "gamma.log")


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_for(predicate, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def shown(pane) -> list[str]:
    proxy = pane._table.model()
    return sorted(
        proxy.index(r, 0).data() for r in range(proxy.rowCount())
        if proxy.index(r, 0).data() != ".."
    )


def select(pane, name: str) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )


def key(widget, k, modifiers=Qt.KeyboardModifier.NoModifier) -> None:
    widget.activateWindow()
    widget.setFocus()
    pump(0.02)
    QTest.keyClick(widget, k, modifiers)
    pump(0.02)


@pytest.fixture
def pane(tmp_path):
    from ui.cut_clipboard import cut_clipboard
    from ui.file_pane import FilePaneWidget

    cut_clipboard().clear()
    for name in NAMES:
        (tmp_path / name).write_text(name)
    widget = FilePaneWidget(LocalFS())
    widget.resize(800, 500)
    widget.show()
    widget.navigate(str(tmp_path))
    assert wait_for(lambda: shown(widget) == sorted(NAMES))
    yield widget
    cut_clipboard().clear()
    widget.close()
    widget.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def type_filter(pane, text: str) -> None:
    pane._filter_edit.setFocus()
    pump(0.02)
    QTest.keyClicks(pane._filter_edit, text)
    pump(0.02)


# --- happy -----------------------------------------------------------------


def test_happy_e2e_esc_in_the_filter_line_clears_it_and_returns_to_the_list(pane) -> None:
    type_filter(pane, "alp")
    assert shown(pane) == ["alpha.txt"]
    key(pane._filter_edit, Qt.Key.Key_Escape)
    assert pane._filter_edit.text() == ""
    assert shown(pane) == sorted(NAMES)
    assert pane._table.hasFocus()


def test_happy_e2e_esc_in_the_list_clears_an_active_filter_before_the_selection(pane) -> None:
    type_filter(pane, "a")
    select(pane, "alpha.txt")
    key(pane._table, Qt.Key.Key_Escape)
    assert pane._filter_edit.text() == ""
    assert shown(pane) == sorted(NAMES)
    assert pane._table.selectionModel().hasSelection()  # the selection is next
    key(pane._table, Qt.Key.Key_Escape)
    assert not pane._table.selectionModel().hasSelection()


def test_happy_ctrl_f_then_esc_round_trip(pane) -> None:
    key(pane._table, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert pane._filter_edit.hasFocus()
    QTest.keyClicks(pane._filter_edit, "gam")
    pump(0.02)
    assert shown(pane) == ["gamma.log"]
    key(pane._filter_edit, Qt.Key.Key_Escape)
    assert shown(pane) == sorted(NAMES) and pane._table.hasFocus()


# --- sad -------------------------------------------------------------------


def test_sad_esc_during_a_load_stops_the_load_and_keeps_the_filter(pane) -> None:
    type_filter(pane, "alp")
    stopped: list[int] = []
    pane.cancel_navigation = lambda: stopped.append(1)
    # A load in flight (is_loading reads the context of the running load).
    pane._nav_ctx = {"path": pane.current_path, "history": "keep", "quiet": True,
                     "fallback": None}
    try:
        assert pane.is_loading
        key(pane._table, Qt.Key.Key_Escape)
    finally:
        pane._nav_ctx = {}
    assert stopped == [1]
    assert pane._filter_edit.text() == "alp"


def test_sad_shift_esc_in_the_filter_line_is_not_taken(pane) -> None:
    type_filter(pane, "alp")
    key(pane._filter_edit, Qt.Key.Key_Escape, Qt.KeyboardModifier.ShiftModifier)
    assert pane._filter_edit.text() == "alp"
    assert shown(pane) == ["alpha.txt"]


# --- edge ------------------------------------------------------------------


def test_edge_esc_in_an_empty_filter_line_only_returns_to_the_list(pane) -> None:
    select(pane, "beta.txt")
    key(pane._filter_edit, Qt.Key.Key_Escape)
    assert pane._table.hasFocus()
    assert pane._table.selectionModel().hasSelection()  # untouched


def test_edge_esc_clears_a_tag_filter_too(pane) -> None:
    type_filter(pane, "tag:nonexistent")
    assert shown(pane) == []
    key(pane._filter_edit, Qt.Key.Key_Escape)
    assert pane._proxy._tag_filter is None
    assert shown(pane) == sorted(NAMES)


def test_edge_e2e_in_the_thumbnail_view_esc_returns_to_the_thumbnails(pane) -> None:
    pane.set_view_mode("thumbnails")
    pump(0.05)
    type_filter(pane, "bet")
    assert shown(pane) == ["beta.txt"]
    key(pane._filter_edit, Qt.Key.Key_Escape)
    assert pane._filter_edit.text() == "" and pane.thumbnail_view.hasFocus()
    type_filter(pane, "bet")
    key(pane.thumbnail_view, Qt.Key.Key_Escape)  # Esc in the thumbnails clears it too
    assert pane._filter_edit.text() == "" and shown(pane) == sorted(NAMES)
    pane.set_view_mode("details")


def test_edge_esc_order_in_the_list_filter_selection_then_cut(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    select(pane, "alpha.txt")
    key(pane._table, Qt.Key.Key_X, Qt.KeyboardModifier.ControlModifier)
    assert cut_clipboard().pending is not None
    type_filter(pane, "a")
    select(pane, "alpha.txt")
    key(pane._table, Qt.Key.Key_Escape)  # 1: the filter
    assert pane._filter_edit.text() == "" and cut_clipboard().pending is not None
    key(pane._table, Qt.Key.Key_Escape)  # 2: the selection
    assert not pane._table.selectionModel().hasSelection()
    assert cut_clipboard().pending is not None
    key(pane._table, Qt.Key.Key_Escape)  # 3: the cut
    assert cut_clipboard().pending is None
    assert sorted(p.name for p in Path(pane.current_path).iterdir()) == sorted(NAMES)


def test_edge_the_help_lists_cut_paste_and_the_esc_order() -> None:
    from ui.shortcuts_dialog import SHORTCUTS

    by_key = {k: d for _s, keys, d in SHORTCUTS for k in keys}
    assert "Cut" in by_key["Ctrl+X"]
    assert "Paste" in by_key["Ctrl+V"]
    assert "filter" in by_key["Esc"].lower() and "cut" in by_key["Esc"].lower()
