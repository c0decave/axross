"""Every overview tile keeps its caption, whatever the thumbnail's shape.

The grid uses uniform item sizes, taken from one item. A portrait
thumbnail (a PDF page, a phone photo) is taller than a landscape one, so
its delegate pushed the name and folder below the uniform tile and they
were clipped away: the tile showed only the picture.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QSize  # noqa: E402
from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QStyleOptionViewItem  # noqa: E402

from core.media_collect import IMAGE, PDF, MediaItem  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])
_OPEN: list = []


@pytest.fixture(autouse=True)
def _close_overviews():
    yield
    while _OPEN:
        overview = _OPEN.pop()
        overview.close()
        overview.deleteLater()
    APP.processEvents()


def _image(width: int, height: int) -> QImage:
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor("teal"))
    return image


def _overview(shapes: dict[str, tuple[int, int]]):
    model = MV.MediaListModel()
    items = [
        MediaItem(f"/r/{name}", name, "sub", PDF if name.endswith(".pdf") else IMAGE, 1, 0.0)
        for name in shapes
    ]
    model.set_items(items)
    overview = MV.MediaOverview(model)
    # The overview's proxy does not own its source model: without a parent
    # the model dies with this function while the shown view still paints it.
    model.setParent(overview)
    _OPEN.append(overview)
    overview.resize(900, 600)
    overview.show()
    for name, (w, h) in shapes.items():
        model.set_thumbnail(f"/r/{name}", _image(w, h))
    APP.processEvents()
    return overview


def _needed_heights(overview) -> list[int]:
    view = overview.view
    delegate = view.itemDelegate()
    option = QStyleOptionViewItem()
    option.initFrom(view)
    option.decorationSize = view.iconSize()
    option.decorationPosition = QStyleOptionViewItem.Position.Top
    option.features |= QStyleOptionViewItem.ViewItemFeature.WrapText
    model = view.model()
    return [
        delegate.sizeHint(option, model.index(row, 0)).height()
        for row in range(model.rowCount())
    ]


def test_happy_landscape_and_portrait_tiles_need_the_same_height() -> None:
    overview = _overview({"a.png": (256, 170), "b.pdf": (180, 256), "c.png": (120, 256)})
    heights = _needed_heights(overview)
    assert len(set(heights)) == 1, heights


def test_sad_a_portrait_thumbnail_leaves_room_for_its_caption() -> None:
    overview = _overview({"a.png": (256, 170), "tall.png": (60, 256)})
    view = overview.view
    tile = view.visualRect(view.model().index(1, 0)).size()
    assert max(_needed_heights(overview)) <= tile.height(), (tile, _needed_heights(overview))


def test_edge_a_square_and_a_tiny_thumbnail_keep_the_icon_size() -> None:
    overview = _overview({"sq.png": (256, 256), "tiny.png": (8, 4)})
    model = overview.view.model()
    for row in range(model.rowCount()):
        icon = model.index(row, 0).data(1)
        sizes = icon.availableSizes()
        assert sizes and sizes[0].width() == sizes[0].height(), sizes
    assert overview.view.iconSize() == QSize(MV.THUMB_DEFAULT, MV.THUMB_DEFAULT)
