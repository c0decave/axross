"""A drag near the top or bottom edge of a pane scrolls it.

Reported: dragging within one pane, a target folder out of sight could not
be reached - the pane's views replace Qt's dragMoveEvent, and with it the
item views' own edge scrolling. Now the top and bottom tenth scroll.
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

from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QDragLeaveEvent, QDragMoveEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.drag_autoscroll import DragAutoScroll  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    for i in range(200):
        (tmp_path / f"f{i:03}.txt").write_text("x")
    p = FilePaneWidget(LocalFS())
    p.resize(500, 400)
    p.show()
    p.navigate(str(tmp_path))
    _pump(0.5)
    yield p
    p.close()
    p.deleteLater()


def _drag_move(view, y: int) -> None:
    mime = QMimeData()
    mime.setText("x")
    event = QDragMoveEvent(QPointF(30, y).toPoint(), Qt.DropAction.MoveAction, mime,
                           Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    view.dragMoveEvent(event)


def test_happy_hovering_the_bottom_edge_scrolls_down_and_the_top_up(pane):
    table = pane._table
    bar = table.verticalScrollBar()
    assert bar.maximum() > 0
    height = table.viewport().height()
    _drag_move(table, height - 2)
    _pump(0.4)
    down = bar.value()
    assert down > 0
    _drag_move(table, 1)
    _pump(0.3)
    assert bar.value() < down
    table.dragLeaveEvent(QDragLeaveEvent())
    assert not table.drag_scroll.active


def test_sad_the_middle_does_not_scroll(pane):
    table = pane._table
    bar = table.verticalScrollBar()
    _drag_move(table, table.viewport().height() // 2)
    _pump(0.3)
    assert bar.value() == 0
    assert not table.drag_scroll.active


def test_edge_zones_are_a_tenth_and_faster_at_the_edge():
    from PyQt6.QtWidgets import QListView

    view = QListView()
    view.resize(300, 500)
    view.show()
    APP.processEvents()
    scroller = DragAutoScroll(view)
    h = view.viewport().height()
    band = max(16, int(h * 0.1))
    assert scroller.zone(QPoint(5, h // 2)) == (0, 0)
    up_edge = scroller.zone(QPoint(5, 0))
    up_inner = scroller.zone(QPoint(5, band - 2))
    assert up_edge[0] == up_inner[0] == -1 and up_edge[1] > up_inner[1]
    assert scroller.zone(QPoint(5, h - 1))[0] == 1
    assert scroller.zone(QPoint(5, h - band - 2)) == (0, 0)
    view.deleteLater()
