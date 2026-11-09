#!/usr/bin/env python3
"""Space (mark the file and move down) and the current row across a refresh.

Round-5 review: Space marked the row and then moved the cursor with the
view's setCurrentIndex, which in ExtendedSelection applies ClearAndSelect -
every mark but the new row was wiped, so three presses left one wrong
file marked. And a refresh (the watcher, a transfer writing into the
folder) gave the current row back only when it was itself selected: after
Space it is the next, unmarked row, so the cursor was lost.
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

from PyQt6.QtCore import QItemSelectionModel, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])
FLAGS = QItemSelectionModel.SelectionFlag


@pytest.fixture()
def pane(tmp_path):
    for i in range(12):
        (tmp_path / f"doc{i:02d}.txt").write_text("x")
    widget = FilePaneWidget(LocalFS())
    widget._stop_watcher(wait=True)
    widget.resize(900, 700)
    widget.show()
    widget.navigate(str(tmp_path))
    APP.processEvents()
    widget._table.setFocus()
    try:
        yield widget
    finally:
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def _row_of(pane, name: str) -> int:
    for row in range(pane._proxy.rowCount()):
        if _name(pane, pane._proxy.index(row, 0)) == name:
            return row
    raise AssertionError(name)


def _name(pane, index) -> str | None:
    if not index.isValid():
        return None
    item = pane._model.get_item(pane._proxy.mapToSource(index).row())
    return item.name if item is not None else None


def _put_cursor(pane, name: str) -> None:
    sel = pane._table.selectionModel()
    sel.setCurrentIndex(pane._proxy.index(_row_of(pane, name), 0), FLAGS.NoUpdate)
    sel.clearSelection()


def _marked(pane) -> list[str]:
    return sorted(i.name for i in pane.selected_file_items())


def _current(pane) -> str | None:
    return _name(pane, pane._table.currentIndex())


def _refresh(pane, folder: Path) -> None:
    (folder / "incoming.part").write_text("")  # a transfer writes here
    pane.refresh_async(quiet=True, keep_sizes=True)  # what the watcher does
    end = time.time() + 10
    while pane.is_loading and time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.processEvents()


# -- happy ------------------------------------------------------------------------------------


def test_happy_space_three_times_marks_three_files_and_moves_down(pane):
    _put_cursor(pane, "doc00.txt")
    for _ in range(3):
        QTest.keyClick(pane._table, Qt.Key.Key_Space)
    assert _marked(pane) == ["doc00.txt", "doc01.txt", "doc02.txt"]
    assert _current(pane) == "doc03.txt"


def test_happy_the_cursor_row_survives_a_refresh_when_other_rows_are_marked(pane, tmp_path):
    _put_cursor(pane, "doc03.txt")
    for _ in range(3):
        pane._toggle_select_and_move_down()
    assert _current(pane) == "doc06.txt"
    _refresh(pane, tmp_path)
    assert _marked(pane) == ["doc03.txt", "doc04.txt", "doc05.txt"]
    assert _current(pane) == "doc06.txt"


# -- sad --------------------------------------------------------------------------------------


def test_sad_space_on_a_marked_row_unmarks_it_and_keeps_the_others(pane):
    _put_cursor(pane, "doc00.txt")
    QTest.keyClick(pane._table, Qt.Key.Key_Space)
    QTest.keyClick(pane._table, Qt.Key.Key_Space)
    sel = pane._table.selectionModel()
    sel.setCurrentIndex(pane._proxy.index(_row_of(pane, "doc00.txt"), 0), FLAGS.NoUpdate)
    QTest.keyClick(pane._table, Qt.Key.Key_Space)
    assert _marked(pane) == ["doc01.txt"]
    assert _current(pane) == "doc01.txt"


def test_sad_a_refresh_does_not_mark_the_unmarked_cursor_row(pane, tmp_path):
    _put_cursor(pane, "doc07.txt")
    _refresh(pane, tmp_path)
    assert _current(pane) == "doc07.txt"
    assert _marked(pane) == []


# -- edge -------------------------------------------------------------------------------------


def test_edge_space_in_the_thumbnail_view_keeps_the_marks(pane):
    pane.set_view_mode("thumbnails")
    APP.processEvents()
    thumbs = pane.thumbnail_view
    thumbs.setFocus()
    _put_cursor(pane, "doc04.txt")
    for _ in range(2):
        QTest.keyClick(thumbs, Qt.Key.Key_Space)
    assert _marked(pane) == ["doc04.txt", "doc05.txt"]
    assert _current(pane) == "doc06.txt"


def test_edge_space_on_the_last_row_marks_it_and_stays(pane):
    last = pane._proxy.rowCount() - 1
    name = _name(pane, pane._proxy.index(last, 0))
    _put_cursor(pane, name)
    QTest.keyClick(pane._table, Qt.Key.Key_Space)
    assert _marked(pane) == [name]
    assert _current(pane) == name


def test_edge_down_after_a_refresh_starts_from_the_kept_cursor(pane, tmp_path):
    _put_cursor(pane, "doc08.txt")
    _refresh(pane, tmp_path)
    QTest.keyClick(pane._table, Qt.Key.Key_Down)
    assert _current(pane) == "doc09.txt"
