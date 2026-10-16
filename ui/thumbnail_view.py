"""The thumbnail face of a file pane.

The same listing as the details table - the pane's proxy model and its
selection model - shown as tiles. Images, PDFs and videos get a small
picture, everything else keeps its icon. Because model and selection are
shared, every pane action (copy, move, delete, rename, the context menu,
drag & drop, the keyboard) works on what is selected here, and switching
back to the table keeps the selection.

Pictures are made by :func:`core.media_load.thumbnail` on the media
viewer's :class:`ui.media_viewer.TaskRunner` - plain worker threads, newest
request first, so the tiles in view come first and a dead remote cannot
freeze the window. Only tiles that are painted ask for a picture. A file
that cannot be shown (broken, too large, blocked by the security mode, a
read error) keeps its icon and is not asked for again until the folder is
listed anew with a different size or time.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from PyQt6.QtCore import QItemSelectionModel, QModelIndex, QRect, QSize, Qt
from PyQt6.QtGui import QPainter, QPixmap
from PyQt6.QtWidgets import QAbstractItemView, QListView, QStyle, QStyledItemDelegate

from core import media_collect as MC
from models.file_table_model import COL_NAME

log = logging.getLogger(__name__)

#: Edge of a tile's picture in px.
TILE_EDGE = 128
#: Pictures kept in memory per pane; the oldest go first.
MAX_CACHED = 600
_TEXT_HEIGHT = 34
_PAD = 6


class _TileDelegate(QStyledItemDelegate):
    def __init__(self, view: ThumbnailView) -> None:
        super().__init__(view)
        self._view = view

    def sizeHint(self, option, index) -> QSize:  # noqa: N802 - Qt override
        return self._view.gridSize()

    def paint(self, painter: QPainter, option, index: QModelIndex) -> None:
        view = self._view
        style = view.style()
        painter.save()
        try:
            style.drawPrimitive(
                QStyle.PrimitiveElement.PE_PanelItemViewItem, option, painter, view
            )
            rect = option.rect.adjusted(_PAD, _PAD, -_PAD, -_PAD)
            pic_rect = QRect(rect.left(), rect.top(), rect.width(), rect.height() - _TEXT_HEIGHT)
            pixmap = view.picture_for(index)
            if pixmap is None:
                icon = index.data(Qt.ItemDataRole.DecorationRole)
                side = min(48, pic_rect.width(), pic_rect.height())
                if icon is not None and hasattr(icon, "pixmap"):
                    pixmap = icon.pixmap(QSize(side, side))
            if pixmap is not None and not pixmap.isNull():
                scaled = pixmap
                if pixmap.width() > pic_rect.width() or pixmap.height() > pic_rect.height():
                    scaled = pixmap.scaled(
                        pic_rect.size(),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                x = pic_rect.left() + (pic_rect.width() - scaled.width()) // 2
                y = pic_rect.top() + (pic_rect.height() - scaled.height()) // 2
                painter.drawPixmap(x, y, scaled)
            text_rect = QRect(rect.left(), pic_rect.bottom() + 2, rect.width(), _TEXT_HEIGHT - 2)
            name = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
            text = option.fontMetrics.elidedText(
                name, Qt.TextElideMode.ElideMiddle, text_rect.width()
            )
            selected = bool(option.state & QStyle.StateFlag.State_Selected)
            role = (
                option.palette.ColorRole.HighlightedText
                if selected
                else option.palette.ColorRole.Text
            )
            painter.setPen(option.palette.color(role))
            painter.drawText(
                text_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text
            )
        finally:
            painter.restore()


class ThumbnailView(QListView):
    """Tiles over the pane's listing. Create through the pane."""

    def __init__(self, pane, parent=None) -> None:
        super().__init__(parent or pane)
        self._pane = pane
        self._edge = TILE_EDGE
        self.setViewMode(QListView.ViewMode.IconMode)
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setMovement(QListView.Movement.Static)
        self.setWrapping(True)
        self.setUniformItemSizes(True)
        self.setSpacing(4)
        self.setGridSize(QSize(self._edge + 2 * _PAD + 8, self._edge + _TEXT_HEIGHT + 2 * _PAD))
        self.setModel(pane._proxy)
        self.setModelColumn(COL_NAME)
        # One selection for both faces of the pane.
        self.setSelectionModel(pane._table.selectionModel())
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setItemDelegate(_TileDelegate(self))
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(pane._show_context_menu)
        self.doubleClicked.connect(pane._on_double_click)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)

        from ui.media_viewer import TaskRunner

        # No Qt parent: the runner must outlive a deleted view long enough
        # to drop the results still in flight (it checks for that itself).
        self._runner = TaskRunner(workers=2, max_pending=128)
        self._runner.finished.connect(self._on_loaded)
        runner = self._runner
        self.destroyed.connect(lambda _obj=None: runner.shutdown())
        self._pictures: OrderedDict[tuple, QPixmap] = OrderedDict()
        self._failed: set[tuple] = set()
        self._pending: set[tuple] = set()
        self._folder = None
        #: How many pictures were asked for (tests read it).
        self.requests_made = 0
        pane._proxy.modelReset.connect(self._on_listing)
        # path_changed comes after the pane has taken the new path; the
        # model reset comes before, while current_path is still the old one.
        pane.path_changed.connect(self._on_folder)
        self._on_folder()

    # -- shared selection ---------------------------------------------------
    def selectionCommand(self, index, event=None):  # noqa: N802 - Qt override
        # The pane reads whole rows (selectedRows); a tile is one cell, so
        # every selection made here covers the row.
        return super().selectionCommand(index, event) | QItemSelectionModel.SelectionFlag.Rows

    # -- drag & drop goes through the pane, like the table's -----------------
    def startDrag(self, supportedActions) -> None:  # noqa: N802 - Qt override
        self._pane._start_drag()

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane.dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane.dragMoveEvent(event, self._pane._folder_at(event.position().toPoint(), self))

    def dragLeaveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane.dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane.dropEvent(event, self._pane._folder_at(event.position().toPoint(), self))

    # -- pictures -----------------------------------------------------------
    def _media_item(self, index: QModelIndex):
        pane = self._pane
        item = pane._model.get_item(pane._proxy.mapToSource(index).row())
        if item is None or item.is_dir or item.name == "..":
            return None
        kind = MC.classify(item.name)
        if kind is None:
            return None
        path = pane._safe_item_path(item, warn=False)
        if path is None:
            return None
        mtime = item.modified.timestamp() if getattr(item, "modified", None) else 0.0
        return MC.MediaItem(
            path=path, name=item.name, folder="", kind=kind, size=int(item.size or 0), mtime=mtime
        )

    @staticmethod
    def _key(media) -> tuple:
        return (media.path, media.size, media.mtime)

    def picture_for(self, index: QModelIndex) -> QPixmap | None:
        """The tile's picture, asking for it on first sight; None meanwhile
        and for files that have none."""
        media = self._media_item(index)
        if media is None:
            return None
        key = self._key(media)
        pixmap = self._pictures.get(key)
        if pixmap is not None:
            self._pictures.move_to_end(key)
            return pixmap
        if key not in self._failed and key not in self._pending:
            self._request(media, key)
        return None

    def _request(self, media, key: tuple) -> None:
        from core import media_load

        backend, edge = self._pane._backend, self._edge

        def work(cancel):
            return media_load.thumbnail(backend, media, cancel=cancel, edge=edge)

        if self._runner.submit(key, work):
            self._pending.add(key)
            self.requests_made += 1

    def _on_loaded(self, key, value, error) -> None:
        if key not in self._pending:
            return  # asked for under an earlier listing
        self._pending.discard(key)
        if error is not None or value is None or value.isNull():
            if error is not None:
                log.debug("No thumbnail for %s: %s", key[0], error)
            self._failed.add(key)
        else:
            self._pictures[key] = QPixmap.fromImage(value)
            while len(self._pictures) > MAX_CACHED:
                self._pictures.popitem(last=False)
        self.viewport().update()

    def _on_listing(self) -> None:
        """A new listing: what is still queued belongs to the old one."""
        self._runner.reset()
        self._pending.clear()
        self.viewport().update()

    def _on_folder(self, _path: str = "") -> None:
        """Another folder, or the same path on another connection: forget
        the pictures of the old one."""
        folder = (id(self._pane._backend), getattr(self._pane, "current_path", None))
        if folder != self._folder:
            self._folder = folder
            self._pictures.clear()
            self._failed.clear()
            self.viewport().update()

    def shutdown(self) -> None:
        self._runner.shutdown()
        self._pending.clear()

    # -- state for tests and the status line --------------------------------
    def _key_for_path(self, path: str):
        for key in list(self._pictures) + list(self._failed) + list(self._pending):
            if key[0] == path:
                return key
        return None

    def thumbnail_state(self, path: str) -> str | None:
        """``loaded``, ``failed``, ``pending`` or None (never asked for)."""
        key = self._key_for_path(path)
        if key is None:
            return None
        if key in self._pictures:
            return "loaded"
        if key in self._failed:
            return "failed"
        return "pending"

    def thumbnail(self, path: str) -> QPixmap | None:
        key = self._key_for_path(path)
        return self._pictures.get(key) if key is not None else None


__all__ = ["ThumbnailView", "TILE_EDGE"]
