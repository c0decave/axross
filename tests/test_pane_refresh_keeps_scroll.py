"""A refresh of the folder shown leaves the view where the user scrolled it.

Reported: scrolling up through a folder with the mouse wheel (or PgUp)
went to the top and then started again at the bottom. A refresh of the
same folder - the watcher seeing a change (a transfer writing into it),
F5, an operation - reset the model, which put the view at the top, and
gave the selection back, which made Qt's auto-scroll jump to the current
row: wherever the user had last clicked, typically further down. So
while scrolling up the view jumped back down, or up to the top, with
every change in the folder.
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

from PyQt6.QtCore import (  # noqa: E402
    QItemSelectionModel,
    QPoint,
    QPointF,  # noqa: E402
    Qt,
)
from PyQt6.QtGui import QWheelEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.2) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    for i in range(400):
        (tmp_path / f"file{i:04d}.txt").write_text("x")
    p = FilePaneWidget(LocalFS())
    p.resize(600, 400)
    p.show()
    p.navigate(str(tmp_path))
    _pump()
    yield p
    p.close()
    p.deleteLater()


def _bar(pane):
    return pane._table.verticalScrollBar()


def _row_of(pane, name: str) -> int:
    proxy = pane._proxy
    return next(r for r in range(proxy.rowCount()) if proxy.index(r, 0).data() == name)


def _click(pane, name: str) -> None:
    index = pane._proxy.index(_row_of(pane, name), 0)
    pane._table.scrollTo(index)
    rect = pane._table.visualRect(index)
    from PyQt6.QtTest import QTest

    QTest.mouseClick(pane._table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    _pump(0.05)


def _wheel_up(pane, notches: int = 1) -> None:
    viewport = pane._table.viewport()
    for _ in range(notches):
        event = QWheelEvent(QPointF(50, 50), QPointF(viewport.mapToGlobal(QPoint(50, 50))),
                            QPoint(0, 0), QPoint(0, 120), Qt.MouseButton.NoButton,
                            Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
        QApplication.sendEvent(viewport, event)
    _pump(0.05)


def _refresh_same_folder(pane, tmp_path, new: str | None = None) -> None:
    """What the watcher does when a file appears: list again, apply."""
    if new:
        (tmp_path / new).write_text("n")
    path, items = pane._fetch_listing(pane._current_path)
    pane._apply_listing(path, items, history="keep")
    _pump(0.05)


# -- happy ------------------------------------------------------------------------------------


def test_happy_scrolled_up_after_a_click_further_down_a_refresh_keeps_the_view(pane, tmp_path):
    _click(pane, "file0350.txt")
    bar = _bar(pane)
    clicked_at = bar.value()
    assert clicked_at > 0
    _wheel_up(pane, 3)
    up = bar.value()
    assert up < clicked_at
    _refresh_same_folder(pane, tmp_path, new="zzz-new.txt")
    assert bar.value() == up  # not back at the clicked row, not at the top


def test_happy_at_the_top_a_refresh_stays_at_the_top(pane, tmp_path):
    _click(pane, "file0350.txt")
    _bar(pane).setValue(0)
    _refresh_same_folder(pane, tmp_path, new="zzz-new.txt")
    assert _bar(pane).value() == 0


def test_happy_the_selection_and_current_row_come_back_too(pane, tmp_path):
    _click(pane, "file0350.txt")
    _wheel_up(pane, 5)
    _refresh_same_folder(pane, tmp_path, new="zzz-new.txt")
    current = pane._table.selectionModel().currentIndex()
    assert current.isValid() and current.data() == "file0350.txt"
    assert [i.name for i in pane.selected_file_items()] == ["file0350.txt"]


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_refresh_with_fewer_rows_stays_within_the_list(pane, tmp_path):
    _bar(pane).setValue(_bar(pane).maximum())
    for i in range(300, 400):
        (tmp_path / f"file{i:04d}.txt").unlink()
    _refresh_same_folder(pane, tmp_path)
    bar = _bar(pane)
    assert 0 <= bar.value() <= bar.maximum()


def test_sad_another_folder_starts_at_the_top(pane, tmp_path):
    """Only a refresh keeps the place: a navigation shows the new folder
    from its top, as before."""
    other = tmp_path / "other"
    other.mkdir()
    for i in range(200):
        (other / f"o{i:04d}").write_text("o")
    _bar(pane).setValue(_bar(pane).maximum())
    pane.navigate(str(other))
    _pump()
    assert _bar(pane).value() == 0


# -- edge -------------------------------------------------------------------------------------


def test_edge_keyboard_moves_still_scroll_to_the_current_row(pane, tmp_path):
    """Auto-scroll is held only while the refresh gives the selection back."""
    _click(pane, "file0010.txt")
    _bar(pane).setValue(0)
    pane._table.selectionModel().setCurrentIndex(
        pane._proxy.index(_row_of(pane, "file0380.txt"), 0),
        QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
    _pump(0.05)
    assert _bar(pane).value() > 0  # Qt scrolled to it
    assert pane._table.hasAutoScroll()


def test_edge_the_horizontal_place_is_kept_too(pane, tmp_path):
    pane.resize(200, 400)
    _pump()
    hbar = pane._table.horizontalScrollBar()
    if hbar.maximum() == 0:
        pytest.skip("the columns fit: nothing to scroll sideways")
    hbar.setValue(hbar.maximum())
    _refresh_same_folder(pane, tmp_path, new="zzz-new.txt")
    assert hbar.value() == hbar.maximum()


def test_edge_the_thumbnail_view_keeps_its_place_too(pane, tmp_path):
    pane.set_view_mode("thumbnails")
    _pump(0.3)
    thumbs = pane.thumbnail_view
    bar = thumbs.verticalScrollBar()
    if bar.maximum() == 0:
        pytest.skip("all thumbnails fit: nothing to scroll")
    _click(pane, "file0350.txt")
    bar.setValue(bar.maximum() // 3)
    place = bar.value()
    _refresh_same_folder(pane, tmp_path, new="zzz-new.txt")
    assert bar.value() == place
