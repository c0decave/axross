"""Archive view columns: every divider can be dragged, Name gets the free
width and the numbers fit their content, as in the normal listing.
Reported: in a tar/zip view the columns could not be resized and the space
for name/size/... was not used well; the Qt default gave every column
100 px and the free width to Modified."""

from __future__ import annotations

import os
import zipfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QHeaderView  # noqa: E402

from ui.archive_pane import ArchivePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])
LONG = "a-rather-long-member-name-inside-the-archive-to-see-the-layout.txt"


@pytest.fixture
def pane(tmp_path):
    zp = tmp_path / "s.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr(LONG, "x" * 5000)
        zf.writestr("b.txt", "y")
    p = ArchivePaneWidget(str(zp))
    p.resize(900, 400)
    p.show()
    APP.processEvents()
    yield p
    p.deleteLater()


def _widths(tree):
    h = tree.header()
    return [h.sectionSize(c) for c in range(h.count())]


def test_happy_name_takes_the_free_width_and_numbers_fit(pane):
    tree = pane._tree
    w = _widths(tree)
    assert w[0] >= tree.sizeHintForColumn(0), w
    for c in range(1, len(w)):
        assert w[c] >= tree.header().sectionSizeHint(c), (c, w)
        assert w[c] < w[0], w
    assert sum(w) == tree.viewport().width(), w


def test_happy_every_divider_is_draggable(pane):
    h = pane._tree.header()
    modes = [h.sectionResizeMode(c) for c in range(h.count())]
    assert all(m == QHeaderView.ResizeMode.Interactive for m in modes), modes


def test_sad_a_dragged_column_keeps_its_width_when_the_view_resizes(pane):
    h = pane._tree.header()
    x = h.sectionViewportPosition(1) + h.sectionSize(1) - 1
    y = h.height() // 2
    before = h.sectionSize(1)
    vp = h.viewport()
    QTest.mousePress(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x, y))
    for step in range(1, 6):
        QTest.mouseMove(vp, QPoint(x + 8 * step, y))
    QTest.mouseRelease(
        vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x + 40, y)
    )
    APP.processEvents()
    dragged = h.sectionSize(1)
    assert dragged >= before + 30
    pane.resize(1200, 400)
    APP.processEvents()
    assert h.sectionSize(1) == dragged


def test_edge_the_status_line_is_english(pane):
    assert pane._status_label.text() == "Ready"
