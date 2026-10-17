"""Media viewer: all images, PDFs and videos of a folder, as an overview
grid, a click-through viewer or a slideshow.

Opened from the pane's context menu or *View -> View Media...* for the
current folder (optionally recursive) or the selection. Layers:

* :class:`MediaViewOptionsDialog` - which types, how deep, how to start.
* :class:`MediaViewerDialog` - the window: runs the walk
  (:func:`core.media_collect.collect_media`) on a :class:`~ui.scan_job.ScanJob`
  with progress and Cancel, then shows the overview or the viewer.
* :class:`MediaOverview` - thumbnail grid (lazy: a thumbnail is made when
  its tile is first painted), filter, sort, tile size.
* :class:`MediaViewer` - one item at a time: zoom / rotate for images, pages
  for PDFs, playback for videos, slideshow, fullscreen.

All file I/O and decoding runs on :class:`TaskRunner` threads through
:mod:`core.media_load`; the GUI thread only turns finished QImages into
pixmaps. A result that arrives after its request was superseded (new
items, dialog closed) is dropped.

Navigation decision: Left / Right / PageUp / PageDown / Space stop at the
first and last item (the status line says so) - stepping past the end by
accident should not throw away your place. The slideshow loops. Inside a
PDF the same keys turn pages; past the last page they go to the next item.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from PyQt6.QtCore import (
    QAbstractListModel,
    QModelIndex,
    QObject,
    QPointF,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QIcon,
    QImage,
    QKeyEvent,
    QKeySequence,
    QPainter,
    QPixmap,
    QShortcut,
    QTransform,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QPushButton,
    QRadioButton,
    QSlider,
    QSpinBox,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from core import media_collect as MC
from core import media_load as ML
from core.i18n import tr
from ui import viewer_file_actions as VFA
from ui import viewer_window as VW
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob, shorten

log = logging.getLogger("ui.media_viewer")

START_OVERVIEW = "overview"
START_SLIDESHOW = "slideshow"
START_BROWSE = "browse"

DEFAULT_INTERVAL_S = 5
THUMB_MIN, THUMB_MAX, THUMB_DEFAULT = 64, 256, 160
#: Prepared items (decoded image / PDF or video copy) kept around the current one.
PREPARED_KEPT = 4


_video_ok: bool | None = None


_pdf_ok: bool | None = None


def pdf_supported() -> bool:
    """True when QtPdf and its widgets import. They need libatomic from the
    host, which the one-file binary does not bundle."""
    global _pdf_ok
    if _pdf_ok is None:
        try:
            from PyQt6.QtPdf import QPdfDocument  # noqa: F401
            from PyQt6.QtPdfWidgets import QPdfView  # noqa: F401

            _pdf_ok = True
        except Exception as exc:  # noqa: BLE001 - any import failure means "no PDF"
            log.info("PDF viewing unavailable: %s", exc)
            _pdf_ok = False
    return _pdf_ok


def video_supported() -> bool:
    """True when QtMultimedia and its widgets import (FFmpeg backend)."""
    global _video_ok
    if _video_ok is None:
        try:
            from PyQt6.QtMultimedia import QMediaPlayer  # noqa: F401
            from PyQt6.QtMultimediaWidgets import QVideoWidget  # noqa: F401

            _video_ok = True
        except Exception as exc:  # noqa: BLE001 - any import failure means "no video"
            log.info("Video playback unavailable: %s", exc)
            _video_ok = False
    return _video_ok


@dataclass(frozen=True)
class MediaViewOptions:
    kinds: frozenset = field(default_factory=lambda: frozenset({MC.IMAGE, MC.PDF}))
    recursive: bool = False
    max_depth: int = MC.DEFAULT_MAX_DEPTH
    start_mode: str = START_OVERVIEW
    interval: int = DEFAULT_INTERVAL_S
    max_items: int = MC.MAX_ITEMS


# ---------------------------------------------------------------------------
# Background work
# ---------------------------------------------------------------------------


class TaskRunner(QObject):
    """A few worker threads over a newest-first queue.

    ``submit(key, fn)`` runs ``fn(cancel_event)`` on a worker; ``finished
    (key, value, error)`` fires in the GUI thread. The queue keeps at most
    ``max_pending`` requests - the oldest are dropped, since a tile that
    scrolled away long ago is no longer worth the read. :meth:`reset` drops
    the queue, tells running work to stop and discards its results.
    """

    finished = pyqtSignal(object, object, object)
    _done = pyqtSignal(int, object, object, object)

    def __init__(self, workers: int = 2, max_pending: int = 256, parent: QObject | None = None):
        super().__init__(parent)
        self._cond = threading.Condition()
        self._queue: deque = deque()
        self._active: set = set()
        self._running = 0
        self._generation = 0
        self._cancel = threading.Event()
        self._stopped = False
        self._max_pending = max(1, max_pending)
        self._done.connect(self._deliver)
        self._threads = [
            threading.Thread(target=self._work, name="media-task", daemon=True)
            for _ in range(max(1, workers))
        ]
        for t in self._threads:
            t.start()

    def submit(self, key, fn: Callable[[threading.Event], Any]) -> bool:
        """Queue *fn* under *key*; ``False`` when *key* is already queued or
        running, or the runner is shut down."""
        with self._cond:
            if self._stopped or key in self._active:
                return False
            self._queue.append((self._generation, key, fn))
            self._active.add(key)
            while len(self._queue) > self._max_pending:
                _gen, old_key, _fn = self._queue.popleft()
                self._active.discard(old_key)
            self._cond.notify()
            return True

    def active(self, key) -> bool:
        with self._cond:
            return key in self._active

    def running_count(self) -> int:
        with self._cond:
            return self._running

    def reset(self) -> None:
        with self._cond:
            self._generation += 1
            self._queue.clear()
            self._active.clear()
            self._cancel.set()
            self._cancel = threading.Event()

    def shutdown(self) -> None:
        self.reset()
        with self._cond:
            self._stopped = True
            self._cond.notify_all()

    def _work(self) -> None:
        while True:
            with self._cond:
                while not self._queue and not self._stopped:
                    self._cond.wait()
                if self._stopped:
                    return
                gen, key, fn = self._queue.pop()  # newest first
                cancel = self._cancel
                self._running += 1
            value, error = None, None
            try:
                value = fn(cancel)
            except Exception as exc:  # noqa: BLE001 - handed to the GUI thread
                error = exc
            with self._cond:
                self._running -= 1
                current = gen == self._generation and not self._stopped
                if current:
                    self._active.discard(key)
            if not current:
                _release(value)
                continue
            try:
                self._done.emit(gen, key, value, error)
            except RuntimeError:  # the owner is gone
                _release(value)
                return

    def _deliver(self, gen: int, key, value, error) -> None:
        if gen != self._generation or self._stopped:
            _release(value)
            return
        self.finished.emit(key, value, error)


def _release(value) -> None:
    release = getattr(value, "release", None)
    if callable(release):
        try:
            release()
        except Exception:  # noqa: BLE001 - cleanup only
            log.debug("release failed", exc_info=True)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


class MediaViewOptionsDialog(QDialog):
    """Types, recursion and start mode for one media view."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        selection: bool = False,
        defaults: MediaViewOptions | None = None,
    ) -> None:
        super().__init__(parent)
        d = defaults or MediaViewOptions(
            kinds=frozenset(
                {MC.IMAGE}
                | ({MC.PDF} if pdf_supported() else set())
                | ({MC.VIDEO} if video_supported() else set())
            )
        )
        self.setWindowTitle(tr("View Selected Media") if selection else tr("View Media"))
        root = QVBoxLayout(self)
        add_close_corner(self)
        form = QFormLayout()

        types = QHBoxLayout()
        self.image_box = QCheckBox(tr("Images"))
        self.image_box.setToolTip(tr("PNG, JPEG, GIF, BMP, WebP, TIFF, PPM and SVG"))
        self.pdf_box = QCheckBox(tr("PDFs"))
        self.video_box = QCheckBox(tr("Videos"))
        for box, kind in (
            (self.image_box, MC.IMAGE),
            (self.pdf_box, MC.PDF),
            (self.video_box, MC.VIDEO),
        ):
            box.setChecked(kind in d.kinds)
            box.toggled.connect(self._update_ok)
            types.addWidget(box)
        if not pdf_supported():
            self.pdf_box.setChecked(False)
            self.pdf_box.setEnabled(False)
            self.pdf_box.setToolTip(tr("PDF viewing needs QtPdf, which cannot be loaded here"))
        if not video_supported():
            self.video_box.setChecked(False)
            self.video_box.setEnabled(False)
            self.video_box.setToolTip(
                tr("Video playback needs QtMultimedia, which is not installed")
            )
        types.addStretch(1)
        form.addRow(tr("Types:"), types)

        self.recursive_box = QCheckBox(
            tr("Include subfolders of the selected folders")
            if selection
            else tr("Include subfolders")
        )
        self.recursive_box.setChecked(d.recursive)
        form.addRow("", self.recursive_box)
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, MC.MAX_DEPTH)
        self.depth_spin.setValue(max(1, d.max_depth))
        self.depth_spin.setToolTip(tr("How many folder levels below the start to search"))
        self.recursive_box.toggled.connect(self.depth_spin.setEnabled)
        self.depth_spin.setEnabled(d.recursive)
        form.addRow(tr("Depth:"), self.depth_spin)
        cap = QLabel(tr("At most {n} files are collected.").format(n=d.max_items))
        cap.setProperty("role", "muted")
        form.addRow("", cap)

        self.overview_radio = QRadioButton(tr("Overview first"))
        self.slideshow_radio = QRadioButton(tr("Start slideshow"))
        self.browse_radio = QRadioButton(tr("Click through"))
        self._mode_group = QButtonGroup(self)
        modes = QVBoxLayout()
        for radio, mode in (
            (self.overview_radio, START_OVERVIEW),
            (self.slideshow_radio, START_SLIDESHOW),
            (self.browse_radio, START_BROWSE),
        ):
            self._mode_group.addButton(radio)
            radio.setChecked(mode == d.start_mode)
            modes.addWidget(radio)
        form.addRow(tr("Start with:"), modes)
        root.addLayout(form)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        root.addWidget(self.buttons)
        self._interval = d.interval
        self._max_items = d.max_items
        self._update_ok()

    def _kinds(self) -> frozenset:
        return frozenset(
            kind
            for box, kind in (
                (self.image_box, MC.IMAGE),
                (self.pdf_box, MC.PDF),
                (self.video_box, MC.VIDEO),
            )
            if box.isChecked() and box.isEnabled()
        )

    def _update_ok(self, *_args) -> None:
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(self._kinds()))

    def options(self) -> MediaViewOptions:
        if self.slideshow_radio.isChecked():
            mode = START_SLIDESHOW
        elif self.browse_radio.isChecked():
            mode = START_BROWSE
        else:
            mode = START_OVERVIEW
        return MediaViewOptions(
            kinds=self._kinds(),
            recursive=self.recursive_box.isChecked(),
            max_depth=self.depth_spin.value(),
            start_mode=mode,
            interval=self._interval,
            max_items=self._max_items,
        )


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


_KIND_ICONS = {
    MC.IMAGE: QStyle.StandardPixmap.SP_FileIcon,
    MC.PDF: QStyle.StandardPixmap.SP_FileDialogDetailedView,
    MC.VIDEO: QStyle.StandardPixmap.SP_MediaPlay,
}


def _square_canvas(image: QImage) -> QImage:
    """``image`` centred on a transparent square. The grid sizes every tile
    from one item, so a portrait thumbnail (a PDF page) taller than the
    others pushed its caption out of the tile; on a square every tile lays
    out the same."""
    edge = max(image.width(), image.height(), 1)
    if image.width() == image.height():
        return image
    canvas = QImage(edge, edge, QImage.Format.Format_ARGB32_Premultiplied)
    canvas.fill(0)
    painter = QPainter(canvas)
    painter.drawImage((edge - image.width()) // 2, (edge - image.height()) // 2, image)
    painter.end()
    return canvas


class MediaListModel(QAbstractListModel):
    """The collected items, their thumbnails and why a thumbnail failed."""

    ItemRole = Qt.ItemDataRole.UserRole + 1
    #: A tile without a thumbnail was painted (queued: never re-enters data()).
    thumbnail_needed = pyqtSignal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._items: list[MC.MediaItem] = []
        self._rows: dict[str, int] = {}
        self._thumbs: dict[str, QIcon] = {}
        self._failed: dict[str, str] = {}
        self._icons: dict[str, QIcon] = {}

    def set_items(self, items: list[MC.MediaItem]) -> None:
        self.beginResetModel()
        self._items = list(items)
        self._rows = {item.path: row for row, item in enumerate(self._items)}
        self._thumbs.clear()
        self._failed.clear()
        self.endResetModel()

    def items(self) -> list[MC.MediaItem]:
        return list(self._items)

    def remove_path(self, path: str) -> bool:
        """Take the item at *path* out (deleted or moved away)."""
        row = self._rows.get(path)
        if row is None:
            return False
        self.beginRemoveRows(QModelIndex(), row, row)
        del self._items[row]
        self._rows = {item.path: r for r, item in enumerate(self._items)}
        self._thumbs.pop(path, None)
        self._failed.pop(path, None)
        self.endRemoveRows()
        return True

    def thumbnail_count(self) -> int:
        return len(self._thumbs)

    def set_thumbnail(self, path: str, image: QImage) -> None:
        row = self._rows.get(path)
        if row is None:
            return
        self._thumbs[path] = QIcon(QPixmap.fromImage(_square_canvas(image)))
        index = self.index(row, 0)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.DecorationRole])

    def set_failed(self, path: str, reason: str) -> None:
        row = self._rows.get(path)
        if row is None:
            return
        self._failed[path] = reason
        index = self.index(row, 0)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.ToolTipRole])

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008 - Qt signature
        return 0 if parent.isValid() else len(self._items)

    def _kind_icon(self, kind: str) -> QIcon:
        icon = self._icons.get(kind)
        if icon is None:
            from PyQt6.QtWidgets import QApplication

            icon = QApplication.style().standardIcon(_KIND_ICONS[kind])
            self._icons[kind] = icon
        return icon

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._items):
            return None
        item = self._items[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return f"{item.name}\n{item.folder or '.'}"
        if role == Qt.ItemDataRole.DecorationRole:
            icon = self._thumbs.get(item.path)
            if icon is not None:
                return icon
            if item.kind != MC.VIDEO and item.path not in self._failed:
                self.thumbnail_needed.emit(item)
            return self._kind_icon(item.kind)
        if role == Qt.ItemDataRole.ToolTipRole:
            text = f"{item.path}\n{item.size:,} bytes"
            reason = self._failed.get(item.path)
            return f"{text}\n{reason}" if reason else text
        if role == self.ItemRole:
            return item
        return None


SORT_KEYS = ("name", "date", "folder")


class MediaSortProxy(QSortFilterProxyModel):
    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._key = "name"
        self._needle = ""

    def set_sort_key(self, key: str) -> None:
        if key not in SORT_KEYS:
            raise ValueError(f"unknown sort key {key!r}")
        self._key = key
        self.invalidate()
        self.sort(0)

    def set_needle(self, text: str) -> None:
        self._needle = text.strip().lower()
        self.invalidateFilter()

    def _sort_tuple(self, item: MC.MediaItem) -> tuple:
        if self._key == "date":
            return (item.mtime, item.name.lower(), item.folder.lower())
        if self._key == "folder":
            return (item.folder.lower(), item.name.lower())
        return (item.name.lower(), item.folder.lower())

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        a = left.data(MediaListModel.ItemRole)
        b = right.data(MediaListModel.ItemRole)
        return self._sort_tuple(a) < self._sort_tuple(b)

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        item = self.sourceModel().index(row, 0, parent).data(MediaListModel.ItemRole)
        return self._needle in item.name.lower() or self._needle in item.folder.lower()


class _TileDelegate(QStyledItemDelegate):
    """Every tile is the grid cell, whatever its icon or text: the view
    takes one uniform size from a single item, and that item may still
    carry its small type icon when the layout runs."""

    def __init__(self, view: QListView) -> None:
        super().__init__(view)
        self._view = view

    def sizeHint(self, option, index):  # noqa: N802 - Qt name
        grid = self._view.gridSize()
        return QSize(grid.width() - 4, grid.height() - 4)


class MediaOverview(QWidget):
    """Thumbnail grid with filter, sort and tile size."""

    open_requested = pyqtSignal(int)  # row in the proxy (display order)

    def __init__(self, model: MediaListModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.proxy = MediaSortProxy(self)
        self.proxy.setSourceModel(model)
        self.proxy.sort(0)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        bar = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(tr("Filter by name or folder"))
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.proxy.set_needle)
        bar.addWidget(self.filter_edit, stretch=1)
        bar.addWidget(QLabel(tr("Sort:")))
        self.sort_combo = QComboBox()
        for label, key in ((tr("Name"), "name"), (tr("Date"), "date"), (tr("Folder"), "folder")):
            self.sort_combo.addItem(label, key)
        self.sort_combo.currentIndexChanged.connect(
            lambda _i: self.proxy.set_sort_key(self.sort_combo.currentData())
        )
        bar.addWidget(self.sort_combo)
        bar.addWidget(QLabel(tr("Size:")))
        self.size_slider = QSlider(Qt.Orientation.Horizontal)
        self.size_slider.setRange(THUMB_MIN, THUMB_MAX)
        self.size_slider.setValue(THUMB_DEFAULT)
        self.size_slider.setFixedWidth(140)
        self.size_slider.valueChanged.connect(self._set_tile_size)
        bar.addWidget(self.size_slider)
        layout.addLayout(bar)

        self.view = QListView()
        self.view.setViewMode(QListView.ViewMode.IconMode)
        self.view.setResizeMode(QListView.ResizeMode.Adjust)
        self.view.setMovement(QListView.Movement.Static)
        self.view.setUniformItemSizes(True)
        self.view.setItemDelegate(_TileDelegate(self.view))
        self.view.setWordWrap(True)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setModel(self.proxy)
        self.view.activated.connect(lambda index: self.open_requested.emit(index.row()))
        self.view.doubleClicked.connect(lambda index: self.open_requested.emit(index.row()))
        layout.addWidget(self.view, stretch=1)
        self._set_tile_size(THUMB_DEFAULT)

    def _set_tile_size(self, size: int) -> None:
        self.view.setIconSize(QSize(size, size))
        self.view.setGridSize(QSize(size + 24, size + 2 * self.fontMetrics().height() + 16))

    def count(self) -> int:
        return self.proxy.rowCount()

    def visible_items(self) -> list[MC.MediaItem]:
        return [
            self.proxy.index(row, 0).data(MediaListModel.ItemRole)
            for row in range(self.proxy.rowCount())
        ]

    def display_texts(self) -> list[str]:
        return [self.proxy.index(row, 0).data() for row in range(self.proxy.rowCount())]


# ---------------------------------------------------------------------------
# Viewer
# ---------------------------------------------------------------------------


class _ImageView(QGraphicsView):
    """Image with fit / 100 % / zoom steps / rotation; the wheel zooms."""

    zoom_changed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self._pixmap = QGraphicsPixmapItem()
        self._pixmap.setTransformationMode(Qt.TransformationMode.SmoothTransformation)
        self.scene().addItem(self._pixmap)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.fit_mode = True
        self.zoom = 1.0
        self.rotation = 0

    def set_image(self, image: QImage) -> None:
        self._pixmap.setPixmap(QPixmap.fromImage(image))
        self.scene().setSceneRect(self._pixmap.boundingRect())
        self.rotation = 0
        self.fit()

    def clear(self) -> None:
        self._pixmap.setPixmap(QPixmap())

    def _apply(self) -> None:
        self.setTransform(QTransform().rotate(self.rotation).scale(self.zoom, self.zoom))
        self.zoom_changed.emit()

    def fit(self) -> None:
        self.fit_mode = True
        rect = self._pixmap.sceneBoundingRect()
        if rect.isEmpty():
            return
        if self.rotation % 180:
            w, h = rect.height(), rect.width()
        else:
            w, h = rect.width(), rect.height()
        vp = self.viewport().size()
        self.zoom = max(0.01, min(vp.width() / w, vp.height() / h))
        self._apply()

    def actual_size(self) -> None:
        self.fit_mode = False
        self.zoom = 1.0
        self._apply()

    def zoom_by(self, factor: float) -> None:
        self.fit_mode = False
        self.zoom = max(0.02, min(50.0, self.zoom * factor))
        self._apply()

    def rotate_cw(self) -> None:
        self.rotation = (self.rotation + 90) % 360
        if self.fit_mode:
            self.fit()
        else:
            self._apply()

    def wheelEvent(self, event) -> None:  # noqa: N802 - Qt override
        steps = event.angleDelta().y() / 120.0
        if steps:
            self.zoom_by(1.25**steps)
        event.accept()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        if self.fit_mode:
            self.fit()


class MediaViewer(QWidget):
    """One item at a time, with keyboard navigation and a slideshow."""

    back_requested = pyqtSignal()
    index_changed = pyqtSignal(int)

    def __init__(self, backend, parent: QWidget | None = None, *, workers: int = 1) -> None:
        super().__init__(parent)
        self._backend = backend
        self._items: list[MC.MediaItem] = []
        self.current_index = -1
        self.current_page = 0
        self.page_count = 0
        self.mode = "empty"
        self._status = ""
        self._prepared: OrderedDict[int, Any] = OrderedDict()
        self._runner = TaskRunner(workers=workers, max_pending=8, parent=self)
        self._runner.finished.connect(self._on_prepared)
        self._pdf_doc = None
        self._pdf_view = None
        self._player = None
        self._video_widget = None
        self._slideshow = False
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._build_ui()

    # -- construction -------------------------------------------------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.pages = QStackedWidget()
        self.loading_label = QLabel(tr("Loading…"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.placeholder_label = QLabel("", alignment=Qt.AlignmentFlag.AlignCenter)
        self.placeholder_label.setWordWrap(True)
        self.image_view = _ImageView()
        self.image_view.zoom_changed.connect(self._update_status)
        for w in (self.loading_label, self.placeholder_label, self.image_view):
            self.pages.addWidget(w)
        # Metadata side panel, hidden until I (or the Info button) shows it.
        from ui.metadata_dialog import MetadataPanel

        body = QHBoxLayout()
        body.addWidget(self.pages, stretch=1)
        self.metadata_panel = MetadataPanel(self)
        self.metadata_panel.setVisible(False)
        body.addWidget(self.metadata_panel)
        layout.addLayout(body, stretch=1)

        bar = QHBoxLayout()

        def button(text: str, tip: str, slot) -> QPushButton:
            b = QPushButton(text)
            b.setToolTip(tip)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            b.clicked.connect(slot)
            bar.addWidget(b)
            return b

        button(tr("Overview"), tr("Back to the overview (Esc)"), self.back_requested.emit)
        button("◀", tr("Previous (Left, PageUp)"), self.prev_item)
        button("▶", tr("Next (Right, PageDown, Space)"), self.next_item)
        self.counter_label = QLabel("")
        bar.addWidget(self.counter_label)
        bar.addStretch(1)
        button(tr("Fit"), tr("Fit to window (F)"), self.fit)
        button("1:1", tr("Actual size (1)"), self.actual_size)
        button("−", tr("Zoom out (-)"), lambda: self.zoom_by(0.8))
        button("+", tr("Zoom in (+)"), lambda: self.zoom_by(1.25))
        button("⟳", tr("Rotate 90° clockwise (R)"), self.rotate)
        bar.addStretch(1)
        self.slideshow_button = button(
            tr("Slideshow"), tr("Start / pause the slideshow (S)"), self.toggle_slideshow
        )
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 3600)
        self.interval_spin.setValue(DEFAULT_INTERVAL_S)
        self.interval_spin.setSuffix(" s")
        self.interval_spin.setToolTip(tr("Slideshow interval"))
        self.interval_spin.valueChanged.connect(self._interval_changed)
        bar.addWidget(self.interval_spin)
        button(tr("Fullscreen"), tr("Toggle fullscreen (F11)"), self.toggle_fullscreen)
        button(tr("Info"), tr("Show / hide the metadata (I)"), self.toggle_metadata)
        layout.addLayout(bar)
        self.status_label = QLabel("")
        self.status_label.setProperty("role", "muted")
        layout.addWidget(self.status_label)

        self.slideshow_timer = QTimer(self)
        self.slideshow_timer.setSingleShot(True)
        self.slideshow_timer.timeout.connect(self._slideshow_tick)

    def _ensure_pdf_view(self):
        if self._pdf_view is None:
            from PyQt6.QtPdf import QPdfDocument
            from PyQt6.QtPdfWidgets import QPdfView

            self._pdf_doc = QPdfDocument(self)
            self._pdf_view = QPdfView(None)
            self._pdf_view.setDocument(self._pdf_doc)
            self._pdf_view.setPageMode(QPdfView.PageMode.SinglePage)
            self._pdf_view.setZoomMode(QPdfView.ZoomMode.FitInView)
            self._pdf_view.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.pages.addWidget(self._pdf_view)
        return self._pdf_view

    def _ensure_player(self):
        if self._player is None:
            from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer
            from PyQt6.QtMultimediaWidgets import QVideoWidget

            self._video_widget = QVideoWidget()
            self._video_widget.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.pages.addWidget(self._video_widget)
            self._player = QMediaPlayer(self)
            try:
                self._audio = QAudioOutput(self)
                self._player.setAudioOutput(self._audio)
            except Exception:  # noqa: BLE001 - no audio device: play silently
                log.debug("no audio output", exc_info=True)
            self._player.setVideoOutput(self._video_widget)
            self._player.mediaStatusChanged.connect(self._on_media_status)
            self._player.errorOccurred.connect(self._on_media_error)
        return self._player

    # -- public state --------------------------------------------------------
    def items(self) -> list[MC.MediaItem]:
        return list(self._items)

    def current_item(self) -> MC.MediaItem | None:
        if 0 <= self.current_index < len(self._items):
            return self._items[self.current_index]
        return None

    @property
    def slideshow_active(self) -> bool:
        return self._slideshow

    @property
    def fit_mode(self) -> bool:
        if self.mode == "pdf" and self._pdf_view is not None:
            from PyQt6.QtPdfWidgets import QPdfView

            return self._pdf_view.zoomMode() != QPdfView.ZoomMode.Custom
        return self.image_view.fit_mode

    @property
    def zoom_factor(self) -> float:
        if self.mode == "pdf" and self._pdf_view is not None:
            return self._pdf_view.zoomFactor()
        return self.image_view.zoom

    @property
    def rotation(self) -> int:
        return self.image_view.rotation

    def placeholder_text(self) -> str:
        return self.placeholder_label.text()

    def status_text(self) -> str:
        return self.status_label.text()

    def is_prepared(self, index: int) -> bool:
        return index in self._prepared

    def current_local_path(self) -> str:
        entry = self._prepared.get(self.current_index)
        return getattr(entry, "local_path", "")

    # -- items ------------------------------------------------------------
    def set_items(self, items: list[MC.MediaItem], index: int = 0) -> None:
        self._runner.reset()
        self._release_all()
        self._items = list(items)
        self.current_index = -1
        if not self._items:
            self.mode = "empty"
            self._show_placeholder(tr("Nothing to show"))
            return
        self.show_index(max(0, min(index, len(self._items) - 1)))

    def remove_path(self, path: str) -> None:
        """Drop the item at *path*; the viewer stays on the next one."""
        rows = [i for i, item in enumerate(self._items) if item.path == path]
        if not rows:
            return
        items = [item for item in self._items if item.path != path]
        current = self.current_index - sum(1 for r in rows if r < self.current_index)
        self.set_items(items, max(0, min(current, len(items) - 1)))

    def show_index(self, index: int, *, page: int = 0) -> None:
        if not 0 <= index < len(self._items):
            return
        self._stop_media()
        self.slideshow_timer.stop()
        self.current_index = index
        self.current_page = page
        self.page_count = 0
        self.metadata_panel.set_target(self._backend, self._items[index].path)
        self._status = ""
        entry = self._prepared.get(index)
        if entry is None:
            self.mode = "loading"
            self.pages.setCurrentWidget(self.loading_label)
            self._request(index)
        else:
            self._prepared.move_to_end(index)
            self._display(entry)
        self._prefetch()
        self._update_status()
        self.index_changed.emit(index)
        self.setFocus()

    def _request(self, index: int) -> None:
        item = self._items[index]
        backend = self._backend
        self._runner.submit(
            ("prepare", index, item.path),
            lambda cancel, item=item: ML.prepare(backend, item, cancel=cancel),
        )

    def _prefetch(self) -> None:
        n = len(self._items)
        if n < 2:
            return
        nxt = self.current_index + 1
        if nxt >= n:
            if not self._slideshow:
                return
            nxt = 0
        if nxt not in self._prepared:
            self._request(nxt)

    def _on_prepared(self, key, value, error) -> None:
        _kind, index, path = key
        if not (0 <= index < len(self._items)) or self._items[index].path != path:
            _release(value)
            return
        if error is not None:
            if not isinstance(error, ML.MediaUnavailable):
                log.warning("Media viewer: %s failed: %r", path, error)
            value = ML.MediaUnavailable(str(error) or type(error).__name__)
        old = self._prepared.pop(index, None)
        if old is not None and old is not value:
            _release(old)
        self._prepared[index] = value
        self._trim_prepared()
        if index == self.current_index and self.mode == "loading":
            self._display(value)
            self._update_status()

    def _trim_prepared(self) -> None:
        while len(self._prepared) > PREPARED_KEPT:
            for index in list(self._prepared):
                if index != self.current_index:
                    _release(self._prepared.pop(index))
                    break
            else:
                return

    def _release_all(self) -> None:
        self._stop_media()
        if self._pdf_doc is not None:
            self._pdf_doc.close()
        for entry in self._prepared.values():
            _release(entry)
        self._prepared.clear()

    def shutdown(self) -> None:
        """Stop everything and remove temp copies (the window closes)."""
        self.stop_slideshow()
        self._runner.shutdown()
        self.metadata_panel.job.abandon()
        self._release_all()
        if self._player is not None:
            self._player.setSource(QUrl())

    # -- display ------------------------------------------------------------
    def _show_placeholder(self, text: str) -> None:
        self.placeholder_label.setText(text)
        self.pages.setCurrentWidget(self.placeholder_label)

    def _display(self, entry) -> None:
        item = self._items[self.current_index]
        if isinstance(entry, ML.MediaUnavailable):
            self.mode = "placeholder"
            self._show_placeholder(
                tr("Cannot show {name}").format(name=item.name) + f"\n\n{entry}"
            )
            self._arm_slideshow()
            return
        if item.kind == MC.IMAGE:
            self.mode = "image"
            self.image_view.set_image(entry.image)
            self.pages.setCurrentWidget(self.image_view)
            self._arm_slideshow()
        elif item.kind == MC.PDF:
            self._display_pdf(entry)
        else:
            self._display_video(entry)

    def _display_pdf(self, entry) -> None:
        from PyQt6.QtPdf import QPdfDocument

        view = self._ensure_pdf_view()
        self._pdf_doc.close()
        error = self._pdf_doc.load(entry.local_path)
        if error != QPdfDocument.Error.None_:
            self.mode = "placeholder"
            self._show_placeholder(
                tr("Cannot show {name}").format(name=entry.item.name)
                + f"\n\n{ML._pdf_error_text(error)}"
            )
            self._arm_slideshow()
            return
        self.mode = "pdf"
        self.page_count = self._pdf_doc.pageCount()
        self.current_page = max(0, min(self.current_page, self.page_count - 1))
        self.pages.setCurrentWidget(view)
        self._jump_page(self.current_page)
        self._arm_slideshow()

    def _jump_page(self, page: int) -> None:
        self.current_page = page
        if self._pdf_view is not None:
            self._pdf_view.pageNavigator().jump(page, QPointF(), 0)
        self._update_status()

    def _display_video(self, entry) -> None:
        if not video_supported():
            self.mode = "placeholder"
            self._show_placeholder(tr("Video playback needs QtMultimedia, which is not installed"))
            self._arm_slideshow()
            return
        player = self._ensure_player()
        self.mode = "video"
        self.pages.setCurrentWidget(self._video_widget)
        player.setSource(QUrl.fromLocalFile(entry.local_path))
        player.play()

    def _stop_media(self) -> None:
        if self._player is not None:
            self._player.stop()

    def _on_media_status(self, status) -> None:
        from PyQt6.QtMultimedia import QMediaPlayer

        if self.mode != "video":
            return
        if status == QMediaPlayer.MediaStatus.EndOfMedia and self._slideshow:
            self.step(+1, wrap=True)
        elif status == QMediaPlayer.MediaStatus.InvalidMedia:
            self._video_failed(self._player.errorString() or tr("unsupported or broken video"))

    def _on_media_error(self, _error, text: str) -> None:
        if self.mode == "video":
            self._video_failed(text)

    def _video_failed(self, text: str) -> None:
        item = self.current_item()
        self.mode = "placeholder"
        self._show_placeholder(
            tr("Cannot show {name}").format(name=item.name if item else "") + f"\n\n{text}"
        )
        self._arm_slideshow()

    # -- navigation ------------------------------------------------------------
    def step(self, delta: int, *, wrap: bool = False, whole_items: bool = False) -> None:
        if not self._items:
            return
        if self.mode == "pdf" and not whole_items:
            page = self.current_page + delta
            if 0 <= page < self.page_count:
                self._jump_page(page)
                if self._slideshow:
                    self._arm_slideshow()
                return
        index = self.current_index + delta
        n = len(self._items)
        if not 0 <= index < n:
            if not wrap:
                self._status = tr("Last item") if delta > 0 else tr("First item")
                self._update_status()
                return
            index %= n
        self.show_index(index)

    def next_item(self) -> None:
        self.step(+1)

    def prev_item(self) -> None:
        self.step(-1)

    def first(self) -> None:
        self.show_index(0)

    def last(self) -> None:
        self.show_index(len(self._items) - 1)

    # -- zoom ---------------------------------------------------------------
    def fit(self) -> None:
        if self.mode == "pdf" and self._pdf_view is not None:
            from PyQt6.QtPdfWidgets import QPdfView

            self._pdf_view.setZoomMode(QPdfView.ZoomMode.FitInView)
        else:
            self.image_view.fit()
        self._update_status()

    def actual_size(self) -> None:
        if self.mode == "pdf" and self._pdf_view is not None:
            from PyQt6.QtPdfWidgets import QPdfView

            self._pdf_view.setZoomMode(QPdfView.ZoomMode.Custom)
            self._pdf_view.setZoomFactor(1.0)
        else:
            self.image_view.actual_size()
        self._update_status()

    def zoom_by(self, factor: float) -> None:
        if self.mode == "pdf" and self._pdf_view is not None:
            from PyQt6.QtPdfWidgets import QPdfView

            current = self._pdf_view.zoomFactor()
            self._pdf_view.setZoomMode(QPdfView.ZoomMode.Custom)
            self._pdf_view.setZoomFactor(max(0.05, min(20.0, current * factor)))
        else:
            self.image_view.zoom_by(factor)
        self._update_status()

    def rotate(self) -> None:
        if self.mode == "image":
            self.image_view.rotate_cw()

    # -- slideshow -----------------------------------------------------------
    def start_slideshow(self, *, interval_ms: int | None = None) -> None:
        self._slideshow = True
        self._interval_ms = interval_ms
        self.slideshow_button.setText(tr("Pause"))
        self._arm_slideshow()
        self._prefetch()
        self._update_status()

    def stop_slideshow(self) -> None:
        self._slideshow = False
        self.slideshow_timer.stop()
        self.slideshow_button.setText(tr("Slideshow"))
        self._update_status()

    def toggle_slideshow(self) -> None:
        if self._slideshow:
            self.stop_slideshow()
        else:
            self.start_slideshow()

    def _interval(self) -> int:
        override = getattr(self, "_interval_ms", None)
        return override if override else self.interval_spin.value() * 1000

    def _interval_changed(self, _value: int) -> None:
        self._interval_ms = None
        if self.slideshow_timer.isActive():
            self._arm_slideshow()

    def _arm_slideshow(self) -> None:
        """(Re)start the countdown for the item on screen; a video plays to
        its end instead, a loading item starts it once shown."""
        self.slideshow_timer.stop()
        if self._slideshow and self.mode not in ("loading", "video", "empty"):
            self.slideshow_timer.start(self._interval())

    def _slideshow_tick(self) -> None:
        if self._slideshow:
            self.step(+1, wrap=True)

    # -- window -------------------------------------------------------------
    def toggle_fullscreen(self) -> None:
        VW.toggle_fullscreen(self.window())

    def toggle_metadata(self) -> None:
        self.metadata_panel.setVisible(not self.metadata_panel.isVisible())

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 - Qt override
        key = event.key()
        ctrl = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        K = Qt.Key
        if key in (K.Key_Right, K.Key_Space) or (key == K.Key_PageDown and not ctrl):
            self.step(+1)
        elif key in (K.Key_Left, K.Key_Backspace) or (key == K.Key_PageUp and not ctrl):
            self.step(-1)
        elif key == K.Key_PageDown:
            self.step(+1, whole_items=True)
        elif key == K.Key_PageUp:
            self.step(-1, whole_items=True)
        elif key == K.Key_Home:
            self.first()
        elif key == K.Key_End:
            self.last()
        elif key in (K.Key_Plus, K.Key_Equal):
            self.zoom_by(1.25)
        elif key == K.Key_Minus:
            self.zoom_by(0.8)
        elif key in (K.Key_1, K.Key_0):
            self.actual_size()
        elif key == K.Key_F:
            self.fit()
        elif key == K.Key_R:
            self.rotate()
        elif key == K.Key_S:
            self.toggle_slideshow()
        elif key == K.Key_F11:
            self.toggle_fullscreen()
        elif key == K.Key_I:
            self.toggle_metadata()
        elif key == K.Key_Escape:
            VW.leave_fullscreen(self.window())
            self.stop_slideshow()
            self._stop_media()
            self.back_requested.emit()
        else:
            super().keyPressEvent(event)
            return
        event.accept()

    def _update_status(self) -> None:
        item = self.current_item()
        if item is None:
            self.counter_label.setText("")
            self.status_label.setText(self._status)
            return
        self.counter_label.setText(f"{self.current_index + 1} / {len(self._items)}")
        parts = [item.name]
        if item.folder:
            parts.append(item.folder)
        if self.mode == "pdf":
            parts.append(
                tr("page {n} of {total}").format(n=self.current_page + 1, total=self.page_count)
            )
        if self.mode in ("image", "pdf"):
            parts.append(tr("fit") if self.fit_mode else f"{self.zoom_factor * 100:.0f} %")
        if self._slideshow:
            parts.append(tr("slideshow"))
        if self._status:
            parts.append(self._status)
        self.status_label.setText(" — ".join(parts))


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


class MediaViewerDialog(QDialog):
    """Walk a folder for media, then show the overview or the viewer."""

    def __init__(
        self,
        backend,
        folder: str,
        options: MediaViewOptions,
        *,
        only_names: set[str] | None = None,
        include_hidden: bool = False,
        parent: QWidget | None = None,
        source_pane=None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        VW.allow_maximize(self)
        self._backend = backend
        # The pane the files belong to: Delete refreshes it, a drag out
        # moves or copies as if it started there (none: no drag).
        self._pane = source_pane if source_pane is not None else VFA.owning_pane(parent)
        self._folder = folder
        self._options = options
        self._only_names = set(only_names) if only_names is not None else None
        self._include_hidden = include_hidden
        self.scan_finished = False
        self.scan_result: MC.MediaScan | None = None
        self._closed = False
        title = tr("Media") + f" — {folder}"
        self.setWindowTitle(title)
        VW.restore_window_state(self, "media")
        # F11 stays a viewer key (MediaViewer.keyPressEvent); Ctrl+M works
        # on the overview and in the viewer alike.
        VW.install_window_keys(self, fullscreen=False)

        root = QVBoxLayout(self)
        add_close_corner(self)
        self.status_label = QLabel(tr("Scanning…"))
        self.status_label.setProperty("role", "muted")
        root.addWidget(self.status_label)
        self.scan_job = ScanJob(
            self,
            formatter=lambda s: tr("Scanning… {folders} folders, {items} media files").format(
                folders=s["scanned"], items=s["indexed"]
            )
            + f" — {shorten(s['path'])}",
        )
        self.scan_job.finished.connect(self._on_scan_finished)
        self.busy = BusyStrip(self.scan_job, self)
        root.addWidget(self.busy)

        from core.file_analysis import is_local_backend

        self.thumbs = TaskRunner(workers=3 if is_local_backend(backend) else 1, parent=self)
        self.thumbs.finished.connect(self._on_thumbnail)
        self.model = MediaListModel(self)
        self.model.thumbnail_needed.connect(
            self._want_thumbnail, Qt.ConnectionType.QueuedConnection
        )
        self.overview = MediaOverview(self.model)
        self.overview.open_requested.connect(self.open_viewer)
        self.viewer = MediaViewer(backend)
        self.viewer.interval_spin.setValue(options.interval)
        self.viewer.back_requested.connect(self.show_overview)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.overview)
        self.stack.addWidget(self.viewer)
        root.addWidget(self.stack, stretch=1)

        # The shown file (or the selected tile): Delete, and a drag onto a
        # pane - move, or copy with Ctrl. A zoomed-in image pans instead.
        QShortcut(QKeySequence(QKeySequence.StandardKey.Delete), self).activated.connect(
            self.delete_current
        )
        image_view = self.viewer.image_view
        VFA.DragOut(
            image_view.viewport(),
            backend,
            self._pane,
            path_at=lambda _pos: self._viewer_path(),
            done=self._after_drag,
            allowed=lambda: image_view.horizontalScrollBar().maximum() <= 0
            and image_view.verticalScrollBar().maximum() <= 0,
        )
        tiles = self.overview.view
        VFA.DragOut(
            tiles.viewport(),
            backend,
            self._pane,
            path_at=lambda pos: self._tile_path(tiles.indexAt(pos)),
            done=self._after_drag,
        )
        self._move_watch = VFA.MoveWatch(self, backend, self._pane, self.remove_path)

    # -- scan -----------------------------------------------------------------
    def start(self) -> None:
        o = self._options
        backend, folder = self._backend, self._folder
        only, hidden = self._only_names, self._include_hidden

        def work(cancel, progress):
            return MC.collect_media(
                backend,
                folder,
                kinds=o.kinds,
                recursive=o.recursive,
                max_depth=o.max_depth,
                max_items=o.max_items,
                include_hidden=hidden,
                only_names=only,
                cancel=cancel,
                progress=progress,
            )

        self.scan_finished = False
        self.scan_job.start(work, replace=True)

    def _on_scan_finished(self, kind: str, value, cancelled: bool) -> None:
        self.scan_finished = True
        if kind != "done":
            self.status_label.setText(tr("Scan failed: {error}").format(error=value))
            return
        scan: MC.MediaScan = value
        self.scan_result = scan
        self.model.set_items(scan.items)
        self.status_label.setText(self._summary(scan, cancelled or scan.cancelled))
        if not scan.items:
            return
        mode = self._options.start_mode
        if mode in (START_SLIDESHOW, START_BROWSE):
            self.open_viewer(0)
            if mode == START_SLIDESHOW:
                self.viewer.start_slideshow()
        else:
            self.overview.view.setFocus()
            self.overview.view.setCurrentIndex(self.overview.proxy.index(0, 0))

    @staticmethod
    def _summary(scan: MC.MediaScan, cancelled: bool) -> str:
        n = len(scan.items)
        if n == 0:
            parts = [tr("No matching media found")]
        elif n == 1:
            parts = [tr("1 item")]
        else:
            parts = [tr("{n} items").format(n=n)]
        if scan.unreadable:
            parts.append(
                tr("1 unreadable folder skipped")
                if scan.unreadable == 1
                else tr("{n} unreadable folders skipped").format(n=scan.unreadable)
            )
        if scan.truncated:
            parts.append(tr("stopped at the limit"))
        if scan.depth_capped:
            parts.append(tr("depth limit reached"))
        if scan.links_skipped:
            parts.append(tr("{n} linked folders not followed").format(n=scan.links_skipped))
        text = ", ".join(parts)
        if cancelled:
            text += " " + tr("(cancelled)")
        return text

    # -- thumbnails ------------------------------------------------------------
    def _want_thumbnail(self, item: MC.MediaItem) -> None:
        if self._closed or self.thumbs.active(item.path):
            return
        backend = self._backend
        self.thumbs.submit(
            item.path, lambda cancel, item=item: ML.thumbnail(backend, item, cancel=cancel)
        )

    def _on_thumbnail(self, path: str, image, error) -> None:
        if self._closed:
            return
        if error is not None:
            if not isinstance(error, ML.MediaUnavailable):
                log.warning("Media thumbnail for %s failed: %r", path, error)
            self.model.set_failed(path, str(error) or type(error).__name__)
        elif isinstance(image, QImage) and not image.isNull():
            self.model.set_thumbnail(path, image)
        else:
            self.model.set_failed(path, tr("no thumbnail"))

    # -- pages ---------------------------------------------------------------
    def open_viewer(self, proxy_row: int) -> None:
        items = self.overview.visible_items()
        if not 0 <= proxy_row < len(items):
            return
        showing = self.stack.currentWidget() is self.viewer
        if showing and self.viewer.current_item() == items[proxy_row]:
            return  # a double-click also reports "activated" on some styles
        self.stack.setCurrentWidget(self.viewer)
        self.viewer.set_items(items, proxy_row)
        self.viewer.setFocus()

    def show_overview(self) -> None:
        self.viewer.stop_slideshow()
        self.stack.setCurrentWidget(self.overview)
        item = self.viewer.current_item()
        if item is not None:
            for row in range(self.overview.proxy.rowCount()):
                index = self.overview.proxy.index(row, 0)
                if index.data(MediaListModel.ItemRole) == item:
                    self.overview.view.setCurrentIndex(index)
                    self.overview.view.scrollTo(index)
                    break
        self.overview.view.setFocus()

    # -- the file itself: delete, drag out -------------------------------------
    def _viewer_path(self) -> str | None:
        item = self.viewer.current_item()
        return item.path if item is not None else None

    @staticmethod
    def _tile_path(index) -> str | None:
        item = index.data(MediaListModel.ItemRole) if index.isValid() else None
        return item.path if item is not None else None

    def current_path(self) -> str | None:
        """The shown file in the viewer, else the selected tile's."""
        if self.stack.currentWidget() is self.viewer:
            return self._viewer_path()
        return self._tile_path(self.overview.view.currentIndex())

    def drag_surface(self) -> QWidget:
        """The widget a drag out starts on, for the page that is shown."""
        if self.stack.currentWidget() is self.viewer:
            return self.viewer.image_view.viewport()
        return self.overview.view.viewport()

    def delete_current(self) -> None:
        path = self.current_path()
        if path and VFA.delete_file(self, self._backend, path, self._pane):
            self.remove_path(path)

    def _after_drag(self, path: str, action) -> None:
        # A drop accepted as a move has not moved anything yet: the file
        # leaves the grid when the source pane shows it gone.
        if action == Qt.DropAction.MoveAction:
            self._move_watch.watch(path)

    def remove_path(self, path: str) -> None:
        """*path* is gone (deleted, moved): out of the grid and the viewer."""
        self.model.remove_path(path)
        if self.stack.currentWidget() is self.viewer:
            self.viewer.remove_path(path)
            if self.viewer.current_item() is None:
                self.show_overview()

    # -- teardown ---------------------------------------------------------------
    def _teardown(self) -> None:
        if self._closed:
            return
        self._closed = True
        VW.save_window_state(self, "media")
        self.scan_job.abandon()
        self.thumbs.shutdown()
        self.viewer.shutdown()

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        self._teardown()
        super().done(result)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._teardown()
        super().closeEvent(event)


__all__ = [
    "MediaListModel",
    "MediaOverview",
    "MediaSortProxy",
    "MediaViewOptions",
    "MediaViewOptionsDialog",
    "MediaViewer",
    "MediaViewerDialog",
    "START_BROWSE",
    "START_OVERVIEW",
    "START_SLIDESHOW",
    "TaskRunner",
    "pdf_supported",
    "video_supported",
]
