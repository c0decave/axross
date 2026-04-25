from __future__ import annotations

import json
import logging
import threading
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, QMimeData, QModelIndex, QPoint, Qt, QThread, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDrag, QKeySequence, QMouseEvent, QPainter, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)


def _is_safe_leaf_name(name: str) -> bool:
    """Reject filenames / link names that carry a path-traversal
    component, a NUL byte, or empty strings. Used by the
    Create-Symlink / Create-Hardlink / Rename dialogs to stop a
    clipboard-paste typo from unintentionally placing the new entry
    outside the current directory.

    This is a UX guard, not a security barrier — the backend is free
    to refuse anything its own permissions check would reject anyway.
    But refusing ``..`` upfront means the user sees a clean dialog
    error instead of an OSError after a partial create.
    """
    if not name:
        return False
    if "\x00" in name:
        return False
    # Reject path separators — either Unix or Windows — and the
    # canonical traversal segment. A leaf "name" containing a slash
    # is definitionally not a leaf.
    if "/" in name or "\\" in name:
        return False
    if name in (".", ".."):
        return False
    return True


def _sanitize_clipboard_text(text: str) -> tuple[str, bool]:
    """Escape control characters that would turn a clipboard payload
    into a shell-injection primitive when pasted into a terminal.

    Remote filesystems can expose files with newlines in their names
    (deliberate on most POSIX backends). If the user selects such a
    file and copies its path to the clipboard, a later paste into a
    shell promptly runs whatever came after the newline. We escape
    ``\\n`` / ``\\r`` / ``\\t`` / NUL to backslash-escapes so the
    clipboard stays a single visible line and the next paste is
    obviously-weird rather than silently-dangerous.

    Returns ``(sanitized, had_control_chars)``.
    """
    translations = {
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\x00": "\\x00",
    }
    had_any = any(ch in text for ch in translations)
    if not had_any:
        return text, False
    out = text
    for raw, escaped in translations.items():
        out = out.replace(raw, escaped)
    return out, True


class _DragTableView(QTableView):
    """QTableView subclass that delegates drag initiation and drop handling to the parent pane."""

    def __init__(self, pane: FilePaneWidget, parent=None):
        super().__init__(parent or pane)
        self._pane = pane

    def startDrag(self, supportedActions) -> None:
        self._pane._start_drag()

    def dragEnterEvent(self, event) -> None:
        self._pane.dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:
        self._pane.dragMoveEvent(event)

    def dragLeaveEvent(self, event) -> None:
        self._pane.dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        self._pane.dropEvent(event)

from models.file_item import FileItem
from models.file_table_model import COL_NAME, FileTableModel, FileSortProxyModel
from ui.layout_utils import detect_drop_zone

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)
TRANSFER_MIME_TYPE = "application/x-axross-transfer"
PANE_MIME_TYPE = "application/x-axross-pane-drag"

_DRAG_THRESHOLD = 10  # pixels before header drag starts


class _DraggableHeader(QLabel):
    """Header label that can be dragged to rearrange panes."""

    def __init__(self, pane: FilePaneWidget, parent=None):
        super().__init__(parent)
        self._pane = pane
        self._drag_start: QPoint | None = None

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if (
            self._drag_start is not None
            and (event.pos() - self._drag_start).manhattanLength() >= _DRAG_THRESHOLD
        ):
            self._drag_start = None
            self._start_pane_drag()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_start = None
        super().mouseReleaseEvent(event)

    def _start_pane_drag(self) -> None:
        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(PANE_MIME_TYPE, str(id(self._pane)).encode())
        drag.setMimeData(mime)
        # Small pixmap as drag icon
        pix = QPixmap(120, 24)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setPen(Qt.GlobalColor.white)
        painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, "Move pane")
        painter.end()
        drag.setPixmap(pix)
        drag.exec(Qt.DropAction.MoveAction)


class _DropOverlay(QWidget):
    """Semi-transparent overlay showing which zone a pane will be dropped into."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        # Overlay is purely visual; drag/drop must stay on the pane itself.
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAcceptDrops(False)
        self._zone: str = ""
        self.hide()

    def set_zone(self, zone: str) -> None:
        if zone != self._zone:
            self._zone = zone
            self.update()

    def paintEvent(self, event) -> None:
        if not self._zone:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = Qt.GlobalColor.cyan
        painter.setBrush(color)
        painter.setOpacity(0.25)
        w, h = self.width(), self.height()
        if self._zone == "left":
            painter.drawRect(0, 0, w // 2, h)
        elif self._zone == "right":
            painter.drawRect(w // 2, 0, w // 2, h)
        elif self._zone == "top":
            painter.drawRect(0, 0, w, h // 2)
        elif self._zone == "bottom":
            painter.drawRect(0, h // 2, w, h // 2)
        painter.end()


class FilePaneWidget(QWidget):
    """Reusable file browser pane, works with any FileBackend."""

    path_changed = pyqtSignal(str)
    file_activated = pyqtSignal(str)  # full path of activated file
    transfer_requested = pyqtSignal(list)  # list of full paths to transfer (copy)
    move_requested = pyqtSignal(list)  # list of full paths to move
    drop_transfer_requested = pyqtSignal(list, object, str, bool)  # paths, target pane, source pane id, is_move
    selection_changed = pyqtSignal()
    pane_focused = pyqtSignal()
    bookmark_requested = pyqtSignal(str, str)  # path, backend_name
    close_requested = pyqtSignal()  # user clicked X on pane
    set_as_target_requested = pyqtSignal()  # user wants this pane as target
    pane_drop_requested = pyqtSignal(str, object, str)  # dragged_pane_id, target_pane, position ("left"/"right"/"top"/"bottom")
    cycle_pane_requested = pyqtSignal(bool)  # True = next, False = previous
    open_bookmarks_requested = pyqtSignal()  # Ctrl+B
    # Emitted from the watcher background thread so the GUI thread
    # owns the actual list refresh. Internal: connect via Qt's auto
    # cross-thread queueing (PyQt does this when the receiver lives
    # on a different thread than the emitter).
    _watch_event = pyqtSignal()

    def __init__(self, backend: FileBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self._backend = backend
        self._current_path = backend.home()
        self._loading = False
        self._history: list[str] = []
        self._history_pos: int = 0
        self._history_navigating = False  # suppress history push during back/forward
        # Auto-refresh via core.watch — one watcher at a time, scoped
        # to the currently displayed directory. Toggleable per-pane.
        self._watcher = None
        self._watched_path: str | None = None
        self._watch_enabled = True
        self._watch_debounce: QTimer | None = None

        self._setup_ui()
        # The debounce timer is created in the GUI thread so its
        # singleShot fire happens in this thread too. Both ends of
        # the chain go through wrapper methods so subclasses (and
        # tests) can intercept by patching the instance attribute —
        # connecting straight to ``self.refresh`` would freeze the
        # bound method at connect time.
        self._watch_debounce = QTimer(self)
        self._watch_debounce.setSingleShot(True)
        self._watch_debounce.setInterval(250)
        # Lambdas (not bound-method connects) so attribute lookup
        # happens at fire time — important for tests that patch the
        # instance method post-construction.
        self._watch_debounce.timeout.connect(lambda: self._on_debounce_fired())
        self._watch_event.connect(lambda: self._on_watch_event_signal())

        self.navigate(self._current_path)

    @property
    def backend(self) -> FileBackend:
        return self._backend

    @property
    def current_path(self) -> str:
        return self._current_path

    def _setup_ui(self) -> None:
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAcceptDrops(True)
        self.setMinimumWidth(220)
        self.setMinimumHeight(150)

        # Outer frame for visible colored border
        self._border_frame = QFrame(self)
        self._border_frame.setFrameShape(QFrame.Shape.Box)
        self._border_frame.setLineWidth(3)
        self._border_frame.setStyleSheet("QFrame { border: 3px solid #888; border-radius: 4px; }")

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer_layout.addWidget(self._border_frame)

        layout = QVBoxLayout(self._border_frame)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Header with backend name + role badge + target button + close button
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)

        header = _DraggableHeader(self)
        header.setCursor(Qt.CursorShape.OpenHandCursor)
        header.setToolTip("Drag to rearrange pane")
        header_layout.addWidget(header)
        self._header_label = header
        self.update_header_color()

        # Role badge (SOURCE / TARGET / —)
        self._role_label = QLabel()
        self._role_label.setFixedHeight(20)
        self._role_label.setStyleSheet(
            "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; border-radius: 3px; }"
        )
        header_layout.addWidget(self._role_label)

        header_layout.addStretch()

        # "Set as Target" button
        self._btn_target = QPushButton("\u25ce")  # ◎
        self._btn_target.setFixedSize(20, 20)
        self._btn_target.setToolTip("Set as transfer target")
        self._btn_target.setStyleSheet(
            "QPushButton { border: none; font-size: 14px; } "
            "QPushButton:hover { background: #58a55c; color: white; border-radius: 3px; }"
        )
        self._btn_target.clicked.connect(self.set_as_target_requested.emit)
        header_layout.addWidget(self._btn_target)

        self._btn_close = QPushButton("\u2715")
        self._btn_close.setFixedSize(20, 20)
        self._btn_close.setToolTip("Close pane")
        self._btn_close.setStyleSheet(
            "QPushButton { border: none; font-size: 12px; } "
            "QPushButton:hover { background: #c0392b; color: white; border-radius: 3px; }"
        )
        self._btn_close.clicked.connect(self.close_requested.emit)
        header_layout.addWidget(self._btn_close)

        layout.addLayout(header_layout)

        # Path bar
        path_bar = QHBoxLayout()
        path_bar.setSpacing(2)

        self._btn_up = QPushButton("\u2191")
        self._btn_up.setFixedWidth(30)
        self._btn_up.setToolTip("Parent directory")
        self._btn_up.clicked.connect(self._go_up)
        path_bar.addWidget(self._btn_up)

        self._btn_home = QPushButton("\u2302")
        self._btn_home.setFixedWidth(30)
        self._btn_home.setToolTip("Home directory")
        self._btn_home.clicked.connect(self._go_home)
        path_bar.addWidget(self._btn_home)

        self._btn_bookmark = QPushButton("\u2606")
        self._btn_bookmark.setFixedWidth(30)
        self._btn_bookmark.setToolTip("Bookmark current directory")
        self._btn_bookmark.clicked.connect(self._add_bookmark)
        path_bar.addWidget(self._btn_bookmark)

        self._path_edit = QLineEdit()
        self._path_edit.returnPressed.connect(self._on_path_entered)
        path_bar.addWidget(self._path_edit)

        self._btn_refresh = QPushButton("\u21bb")
        self._btn_refresh.setFixedWidth(30)
        self._btn_refresh.setToolTip("Refresh")
        self._btn_refresh.clicked.connect(self.refresh)
        path_bar.addWidget(self._btn_refresh)

        # Auto-refresh toggle. Default ON; backends that are expensive
        # to list (S3, deep SFTP trees) can be opted out per-pane.
        self._btn_watch = QPushButton("\u25C9")  # ◉ (filled = on)
        self._btn_watch.setFixedWidth(30)
        self._btn_watch.setCheckable(True)
        self._btn_watch.setChecked(True)
        self._btn_watch.setToolTip(
            "Auto-refresh on backend changes (toggle off for expensive backends)"
        )
        self._btn_watch.toggled.connect(self._on_watch_toggled)
        path_bar.addWidget(self._btn_watch)

        layout.addLayout(path_bar)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(2)

        filter_label = QLabel("Filter:")
        filter_label.setFixedWidth(40)
        filter_bar.addWidget(filter_label)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Type to filter files...")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        filter_bar.addWidget(self._filter_edit)

        layout.addLayout(filter_bar)

        # Loading indicator
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # Indeterminate
        self._progress_bar.setFixedHeight(3)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.hide()
        layout.addWidget(self._progress_bar)

        # File table
        self._model = FileTableModel(self)
        self._proxy = FileSortProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.DisplayRole)

        self._table = _DragTableView(self)
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.selectionModel().selectionChanged.connect(
            lambda: self.selection_changed.emit()
        )

        # Enable drag & drop on the table
        self._table.setDragEnabled(True)
        self._table.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self._table.setAcceptDrops(True)
        self._table.viewport().setAcceptDrops(True)
        self._table.setDefaultDropAction(Qt.DropAction.CopyAction)
        self._table.setDropIndicatorShown(True)

        # Column sizing — fully interactive so the user can drag
        # any divider. The right-most section still stretches to
        # absorb leftover width so there's no empty gap on resize.
        header = self._table.horizontalHeader()
        header.setSectionsMovable(True)
        header.setStretchLastSection(True)
        for col in range(self._model.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        # Apply persisted prefs (widths + hidden columns) and wire
        # up the right-click "show/hide column" menu and the
        # save-on-resize hook. ``_apply_column_prefs`` handles bad /
        # missing files gracefully.
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_menu)
        header.sectionResized.connect(self._on_section_resized)
        self._apply_column_prefs()

        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)

        layout.addWidget(self._table, stretch=1)

        # Status bar with disk usage
        status_layout = QHBoxLayout()
        status_layout.setSpacing(8)

        self._status = QLabel()
        status_layout.addWidget(self._status)

        status_layout.addStretch()

        self._disk_label = QLabel()
        self._disk_label.setStyleSheet("color: #666;")
        status_layout.addWidget(self._disk_label)

        layout.addLayout(status_layout)

        for widget in (
            self,
            self._table,
            self._table.viewport(),
            self._path_edit,
            self._filter_edit,
            self._btn_up,
            self._btn_home,
            self._btn_refresh,
            self._btn_bookmark,
        ):
            widget.installEventFilter(self)

        # Drop overlay for pane rearrangement
        self._drop_overlay = _DropOverlay(self)
        self._drop_overlay.hide()

    def navigate(self, path: str) -> None:
        self._progress_bar.show()
        self._status.setText("Loading...")
        QApplication.processEvents()

        try:
            path = self._backend.normalize(path)
            items = self._backend.list_dir(path)

            # Prepend ".." entry for navigating up (except at root)
            parent = self._backend.parent(path)
            if parent != path:
                items.insert(0, FileItem(name="..", is_dir=True))

            self._model.set_items(items)
            # Track history (skip during back/forward and refresh)
            if not self._history_navigating:
                if not self._history or path != self._history[self._history_pos]:
                    # Truncate forward history and append
                    self._history = self._history[:self._history_pos + 1]
                    self._history.append(path)
                    self._history_pos = len(self._history) - 1
            self._current_path = path
            self._path_edit.setText(path)
            real_count = sum(1 for i in items if i.name != "..")
            self._status.setText(f"{real_count} items")
            self.path_changed.emit(path)
            log.debug("Navigated to %s", path)
            self._update_disk_usage()
            # Switch the auto-refresh watcher to the new path. We
            # start AFTER the successful navigation so a transient
            # OSError above doesn't leave a stale watcher attached.
            self._start_watcher()
            # Opportunistic crash-recovery sweep — only the directory
            # we just landed in, only files older than the conservative
            # default age. Reuse the listing we already fetched so a
            # remote backend doesn't pay for a second list_dir.
            # Wrapped so a backend that doesn't support remove() (e.g.
            # read-only mount) can't break navigation.
            try:
                from core import atomic_recovery as AR
                removed = AR.sweep_orphans(
                    self._backend, path, prefetched_entries=items,
                )
                if removed:
                    log.info(
                        "atomic_recovery: removed %d orphan(s) under %s",
                        removed, path,
                    )
            except Exception as exc:  # noqa: BLE001 — never block navigate
                log.debug("atomic_recovery sweep skipped for %s: %s",
                          path, exc)
        except OSError as e:
            log.error("Navigation failed: %s", e)
            self._status.setText(f"Error: {e}")
        finally:
            self._progress_bar.hide()

    def refresh(self) -> None:
        self._history_navigating = True
        try:
            self.navigate(self._current_path)
        finally:
            self._history_navigating = False

    # ------------------------------------------------------------------
    # Auto-refresh via core.watch
    # ------------------------------------------------------------------
    def _on_watch_toggled(self, on: bool) -> None:
        self._watch_enabled = on
        if on:
            self._start_watcher()
        else:
            self._stop_watcher()

    def _start_watcher(self) -> None:
        """Start a watcher for ``self._current_path`` when needed.

        Skips the (expensive) restart when the existing watcher is
        already pointing at the current path — refresh() goes through
        navigate() which calls us, so without this guard every poll
        event would tear down and rebuild a watcher thread for the
        same directory.
        """
        if not self._watch_enabled:
            self._stop_watcher()
            return
        if (self._watcher is not None
                and self._watched_path == self._current_path):
            return
        self._stop_watcher()
        try:
            from core import watch as W
            self._watcher = W.watch(
                self._backend, self._current_path,
                self._on_backend_change, interval=2.0,
            )
            self._watched_path = self._current_path
            log.debug("Watcher started for %s", self._current_path)
        except Exception as exc:  # noqa: BLE001 — never let watch crash the pane
            log.warning("Could not start watcher for %s: %s",
                        self._current_path, exc)
            self._watcher = None
            self._watched_path = None

    def _stop_watcher(self) -> None:
        """Idempotently stop the current watcher and forget it."""
        if self._watcher is None:
            self._watched_path = None
            return
        try:
            self._watcher.stop(timeout=1.0)
        except Exception as exc:  # noqa: BLE001 — never block shutdown
            log.debug("Watcher.stop() raised: %s", exc)
        finally:
            self._watcher = None
            self._watched_path = None

    def _on_backend_change(self, event_type: str, path: str, kind: str) -> None:
        """Watcher callback. Runs on a background thread, so we just
        emit a signal — the GUI thread debounces it into a refresh."""
        log.debug("Watch event: %s %s (%s)", event_type, path, kind)
        # pyqtSignal.emit is thread-safe and the connection is
        # auto-queued because the receiver lives on another thread.
        self._watch_event.emit()

    def _on_watch_event_signal(self) -> None:
        """GUI-thread bounce for ``_watch_event``: just (re)start the
        debounce timer. Wrapped so tests can patch this attribute."""
        if self._watch_debounce is not None:
            self._watch_debounce.start()

    def _on_debounce_fired(self) -> None:
        """Debounce timeout — issue the actual refresh. Wrapped so
        tests can patch this attribute and so subclasses can override."""
        self.refresh()

    def closeEvent(self, event) -> None:
        """Stop the watcher thread and unmount any active FUSE mount
        before the widget goes away.

        deleteLater()-only paths (used by main_window when removing
        a pane) don't trigger closeEvent, so callers that want a
        clean teardown should call ``_stop_watcher`` directly. The
        watcher thread is daemonised so a missed stop won't outlive
        the process.

        FUSE: a mount holding a stale backend reference would hang
        kernel callers when the connection dies; unmount here so the
        kernel detaches before we let go of the backend handle.
        """
        self._stop_watcher()
        handle = getattr(self, "_fuse_handle", None)
        if handle is not None:
            try:
                handle.unmount()
            except Exception as exc:  # noqa: BLE001 — never block close
                log.debug("closeEvent: FUSE unmount failed: %s", exc)
            self._fuse_handle = None
        super().closeEvent(event)

    def _go_back(self) -> None:
        """Navigate to the previous path in history (Alt+Left)."""
        if self._history_pos > 0:
            old_pos = self._history_pos
            self._history_pos -= 1
            self._history_navigating = True
            try:
                self.navigate(self._history[self._history_pos])
            except Exception:
                log.warning("History back navigation failed for %s", self._history[self._history_pos], exc_info=True)
                self._history_pos = old_pos
            finally:
                self._history_navigating = False

    def _go_forward(self) -> None:
        """Navigate to the next path in history (Alt+Right)."""
        if self._history_pos < len(self._history) - 1:
            old_pos = self._history_pos
            self._history_pos += 1
            self._history_navigating = True
            try:
                self.navigate(self._history[self._history_pos])
            except Exception:
                log.warning("History forward navigation failed for %s", self._history[self._history_pos], exc_info=True)
                self._history_pos = old_pos
            finally:
                self._history_navigating = False

    def _view_selected(self) -> None:
        """Open selected file read-only (F3) — routes to the best
        viewer: image for supported MIMEs (local only), text for text
        files, hex for everything else binary."""
        items = self.selected_file_items()
        files = [i for i in items if not i.is_dir]
        if len(files) != 1:
            return
        item = files[0]
        full_path = self._backend.join(self._current_path, item.name)
        if self._looks_like_image(item.name) and self._open_image_viewer(full_path):
            return
        if self._is_binary_file(full_path, item.name):
            self._open_hex_editor(full_path, read_only=True)
        else:
            self._open_editor(full_path, read_only=True)

    @staticmethod
    def _looks_like_image(name: str) -> bool:
        """Cheap extension-based sniff; the real allowlist check lives
        inside core.previews.thumbnail(). This just avoids calling
        into the image pipeline for a .txt file."""
        lower = name.lower()
        return lower.endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".bmp",
             ".webp", ".tif", ".tiff", ".ppm", ".pgm", ".pbm", ".pnm")
        )

    def _open_image_viewer(self, path: str) -> bool:
        """Open *path* in the ImageViewerDialog. Returns True if the
        dialog opened, False if we should fall back to another viewer
        (e.g. remote backend where previews are disabled)."""
        from ui.image_viewer import ImageViewerDialog
        from core import previews as P
        # Gate on is_local — previews refuses remote anyway, but we
        # short-circuit here to avoid a pop-up that just says "remote
        # not supported" when the user probably expects a text fallback.
        if not P._is_local_backend(self._backend):
            return False
        # Build a sibling list so Prev/Next works inside the current dir.
        siblings: list[str] = []
        try:
            for it in self._backend.list_dir(self._current_path):
                if not it.is_dir and self._looks_like_image(it.name):
                    siblings.append(
                        self._backend.join(self._current_path, it.name)
                    )
        except OSError:
            siblings = [path]
        if path not in siblings:
            siblings.append(path)
        dlg = ImageViewerDialog(
            self._backend, path, siblings=sorted(siblings), parent=self,
        )
        dlg.exec()
        return True

    def _edit_selected(self) -> None:
        """Open selected file in editor (F4) — text or hex based on type."""
        items = self.selected_file_items()
        files = [i for i in items if not i.is_dir]
        if len(files) != 1:
            return
        item = files[0]
        full_path = self._backend.join(self._current_path, item.name)
        if self._is_binary_file(full_path, item.name):
            self._open_hex_editor(full_path)
        else:
            self._open_editor(full_path)

    def _copy_to_target(self) -> None:
        """Copy selected items to the target pane (F5)."""
        selected = self.selected_items()
        if selected:
            self.transfer_requested.emit(selected)

    def _move_to_target(self) -> None:
        """Move selected items to the target pane (F6)."""
        selected = self.selected_items()
        if selected:
            self.move_requested.emit(selected)

    def _select_all(self) -> None:
        """Select all items except '..' (Ctrl+A)."""
        sel = self._table.selectionModel()
        sel.blockSignals(True)
        self._table.selectAll()
        # Deselect ".." row if present
        for row in range(self._proxy.rowCount()):
            source_idx = self._proxy.mapToSource(self._proxy.index(row, 0))
            item = self._model.get_item(source_idx.row())
            if item and item.name == "..":
                sel.select(
                    self._proxy.index(row, 0),
                    sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows,
                )
                break
        sel.blockSignals(False)
        self.selection_changed.emit()

    def _toggle_select_and_move_down(self) -> None:
        """Toggle selection on current row and move cursor down (Space, MC-style)."""
        current = self._table.currentIndex()
        if not current.isValid():
            return
        source_idx = self._proxy.mapToSource(current)
        item = self._model.get_item(source_idx.row())
        if item and item.name == "..":
            # Don't toggle "..", just move down
            pass
        else:
            sel = self._table.selectionModel()
            row_idx = self._proxy.index(current.row(), 0)
            if sel.isSelected(row_idx):
                sel.select(row_idx, sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows)
            else:
                sel.select(row_idx, sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
        # Move cursor down
        next_row = current.row() + 1
        if next_row < self._proxy.rowCount():
            next_idx = self._proxy.index(next_row, current.column())
            self._table.setCurrentIndex(next_idx)

    def _invert_selection(self) -> None:
        """Invert selection on all items except '..' (Ctrl+Shift+A)."""
        sel = self._table.selectionModel()
        sel.blockSignals(True)
        for row in range(self._proxy.rowCount()):
            source_idx = self._proxy.mapToSource(self._proxy.index(row, 0))
            item = self._model.get_item(source_idx.row())
            if item and item.name == "..":
                continue
            row_idx = self._proxy.index(row, 0)
            if sel.isSelected(row_idx):
                sel.select(row_idx, sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows)
            else:
                sel.select(row_idx, sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
        sel.blockSignals(False)
        self.selection_changed.emit()

    def _copy_paths_to_clipboard(self) -> None:
        """Copy selected file paths to clipboard (Ctrl+C).

        A remote filesystem is free to have files with newlines (or
        any other control char) in their names. Without sanitising,
        a later shell paste of ``/tmp/harmless\\n; rm -rf /`` would
        execute whatever came after the newline. We escape control
        characters to backslash-escapes so the clipboard stays a
        single visible line per path and the user gets a warning
        when anything non-trivial was re-encoded."""
        paths = self.selected_items()
        if not paths:
            return
        safe_lines: list[str] = []
        any_escaped = False
        for p in paths:
            sanitized, had_control = _sanitize_clipboard_text(p)
            if had_control:
                any_escaped = True
            safe_lines.append(sanitized)
        QApplication.clipboard().setText("\n".join(safe_lines))
        status = f"Copied {len(paths)} path(s) to clipboard"
        if any_escaped:
            status += " (control chars escaped)"
            log.warning(
                "Clipboard copy: %d path(s) contained control "
                "characters — escaped before copy",
                sum(1 for p in paths
                    if _sanitize_clipboard_text(p)[1]),
            )
        self._status.setText(status)

    def selected_items(self) -> list[str]:
        """Return full paths of selected items."""
        paths = []
        for index in self._table.selectionModel().selectedRows(COL_NAME):
            source_idx = self._proxy.mapToSource(index)
            item = self._model.get_item(source_idx.row())
            if item and item.name != "..":
                paths.append(self._backend.join(self._current_path, item.name))
        return paths

    def selected_file_items(self) -> list[FileItem]:
        """Return FileItem objects for selected rows."""
        items = []
        for index in self._table.selectionModel().selectedRows(COL_NAME):
            source_idx = self._proxy.mapToSource(index)
            item = self._model.get_item(source_idx.row())
            if item and item.name != "..":
                items.append(item)
        return items

    def set_show_hidden(self, show: bool) -> None:
        self._proxy.show_hidden = show

    def set_backend(self, backend: FileBackend) -> None:
        self._backend = backend
        self._current_path = backend.home()
        self._history = []
        self._history_pos = 0
        self.update_header_color()
        self.navigate(self._current_path)

    def get_session_type(self) -> str:
        """Return 'local', 'remote', or 'root' based on the backend type."""
        from core.local_fs import LocalFS
        if isinstance(self._backend, LocalFS):
            return "local"
        # Check for root user (SSH backends have _profile)
        if hasattr(self._backend, "_profile"):
            if getattr(self._backend._profile, "username", "") == "root":
                return "root"
        if hasattr(self._backend, "_username"):
            if self._backend._username == "root":
                return "root"
        return "remote"

    def update_header_color(self, theme: str = "default") -> None:
        """Update header label color based on session type and current theme."""
        session_type = self.get_session_type()

        # Color schemes: {theme: {session_type: (bg_color, text_color)}}
        color_schemes = {
            "default": {
                "local":  ("#3498db", "#ffffff"),  # Blue
                "remote": ("#27ae60", "#ffffff"),  # Green
                "root":   ("#e74c3c", "#ffffff"),  # Red
            },
            "dark": {
                "local":  ("#45475a", "#89b4fa"),  # Catppuccin blue
                "remote": ("#45475a", "#a6e3a1"),  # Catppuccin green
                "root":   ("#5c2d2d", "#f38ba8"),  # Catppuccin red
            },
            "hacker": {
                "local":  ("#0a2a0a", "#00ff41"),  # Matrix green
                "remote": ("#0a0a2a", "#41ff00"),  # Lime
                "root":   ("#2a0a0a", "#ff4141"),  # Red alert
            },
            "amber": {
                "local":  ("#1a1000", "#ff8c00"),  # Amber
                "remote": ("#0a1a0a", "#ffaa00"),  # Gold
                "root":   ("#2a0a0a", "#ff4500"),  # Orange-red
            },
        }

        scheme = color_schemes.get(theme, color_schemes["default"])
        bg, fg = scheme.get(session_type, scheme["local"])

        type_label = {"local": "LOCAL", "remote": "REMOTE", "root": "ROOT"}[session_type]
        self._header_label.setText(
            f"<b>{escape(self._backend.name)}</b> <small>[{type_label}]</small>"
        )
        self._header_label.setStyleSheet(
            f"QLabel {{ background-color: {bg}; color: {fg}; "
            f"padding: 2px 6px; border-radius: 3px; }}"
        )

    def set_pane_role(self, role: str, theme: str = "default") -> None:
        """Set the pane role: 'source', 'target', or '' (none).

        Updates the border frame color and role badge.
        """
        # Border colors per role
        border_colors = {
            "source":  "#4a90d9",  # Blue
            "target":  "#58a55c",  # Green
            "":        "#555555",  # Gray
        }
        color = border_colors.get(role, border_colors[""])
        self._border_frame.setStyleSheet(
            f"QFrame {{ border: 3px solid {color}; border-radius: 4px; }}"
        )

        # Role badge
        if role == "source":
            self._role_label.setText("SOURCE")
            self._role_label.setStyleSheet(
                "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; "
                "border-radius: 3px; background-color: #4a90d9; color: white; }"
            )
            self._role_label.show()
        elif role == "target":
            self._role_label.setText("TARGET")
            self._role_label.setStyleSheet(
                "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; "
                "border-radius: 3px; background-color: #58a55c; color: white; }"
            )
            self._role_label.show()
        else:
            self._role_label.hide()

    def _update_disk_usage(self) -> None:
        """Update disk usage display in status bar."""
        try:
            total, used, free = self._backend.disk_usage(self._current_path)
            if total > 0:
                def _fmt(b: int) -> str:
                    for unit in ("B", "KB", "MB", "GB", "TB"):
                        if abs(b) < 1024:
                            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
                        b /= 1024
                    return f"{b:.1f} PB"
                pct = int((used / total) * 100) if total else 0
                self._disk_label.setText(f"Free: {_fmt(free)} / {_fmt(total)} ({pct}% used)")
            else:
                self._disk_label.setText("")
        except Exception as e:
            log.debug(
                "Disk usage unavailable for %s on %s: %s",
                self._current_path,
                self._backend.name,
                e,
            )
            self._disk_label.setText("")

    # --- Filter ---

    def _on_filter_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)
        self._proxy.setFilterKeyColumn(0)  # Filter on name column
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    # --- Bookmark ---

    def _add_bookmark(self) -> None:
        self.bookmark_requested.emit(self._current_path, self._backend.name)

    # --- Drag & Drop ---

    def _start_drag(self) -> None:
        """Called by _DragTableView.startDrag when user drags from the table."""
        selected = self.selected_items()
        if not selected:
            log.debug("Drag start ignored: no selected items")
            return

        drag = QDrag(self._table)
        mime = QMimeData()
        from core.local_fs import LocalFS

        urls: list[QUrl] = []
        for path in selected:
            if isinstance(self._backend, LocalFS):
                urls.append(QUrl.fromLocalFile(path))
            else:
                url = QUrl()
                url.setScheme("sftp")
                url.setPath(path)
                urls.append(url)
        mime.setUrls(urls)
        mime.setData(TRANSFER_MIME_TYPE, self._encode_transfer_payload(selected))
        drag.setMimeData(mime)
        log.debug("Starting drag with %d item(s) from %s", len(selected), self._backend.name)
        result = drag.exec(Qt.DropAction.CopyAction | Qt.DropAction.MoveAction, Qt.DropAction.CopyAction)
        log.debug("Drag finished with action %s", result)

    def dragEnterEvent(self, event) -> None:
        # Pane rearrangement drag
        if event.mimeData().hasFormat(PANE_MIME_TYPE):
            source_id = bytes(event.mimeData().data(PANE_MIME_TYPE)).decode()
            if source_id != str(id(self)):
                event.setDropAction(Qt.DropAction.MoveAction)
                event.accept()
                self._drop_overlay.setGeometry(self.rect())
                self._drop_overlay.show()
                self._drop_overlay.raise_()
                return
        # File transfer drag
        payload = self._decode_transfer_payload(event.mimeData())
        if payload and payload["source_pane_id"] != str(id(self)):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
            return
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        # Pane rearrangement — show drop zone
        if event.mimeData().hasFormat(PANE_MIME_TYPE):
            source_id = bytes(event.mimeData().data(PANE_MIME_TYPE)).decode()
            if source_id != str(id(self)):
                zone = self._detect_drop_zone(event.position().toPoint())
                self._drop_overlay.setGeometry(self.rect())
                self._drop_overlay.set_zone(zone)
                event.setDropAction(Qt.DropAction.MoveAction)
                event.accept()
                return
            event.ignore()
            return
        # File transfer drag
        payload = self._decode_transfer_payload(event.mimeData())
        if not payload or payload["source_pane_id"] == str(id(self)):
            event.ignore()
            return
        mods = QApplication.keyboardModifiers()
        if mods & Qt.KeyboardModifier.ControlModifier:
            event.setDropAction(Qt.DropAction.MoveAction)
        else:
            event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()

    def dragLeaveEvent(self, event) -> None:
        self._drop_overlay.hide()
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        self._drop_overlay.hide()
        # Pane rearrangement drop
        if event.mimeData().hasFormat(PANE_MIME_TYPE):
            source_id = bytes(event.mimeData().data(PANE_MIME_TYPE)).decode()
            if source_id != str(id(self)):
                zone = self._detect_drop_zone(event.position().toPoint())
                event.acceptProposedAction()
                # Emit signal — main_window handles the actual reparenting
                self.pane_drop_requested.emit(source_id, self, zone)
                log.info("Pane drop: zone=%s onto %s", zone, self._backend.name)
                return
            event.ignore()
            return
        # File transfer drop
        payload = self._decode_transfer_payload(event.mimeData())
        if not payload:
            event.ignore()
            return

        paths = payload["paths"]
        source_pane_id = payload["source_pane_id"]
        is_move = event.dropAction() == Qt.DropAction.MoveAction
        if not is_move:
            mods = QApplication.keyboardModifiers()
            is_move = bool(mods & Qt.KeyboardModifier.ControlModifier)

        if paths:
            self.drop_transfer_requested.emit(paths, self, source_pane_id, is_move)
            event.acceptProposedAction()
            action = "Move" if is_move else "Copy"
            log.info("Drop %s received: %d items", action, len(paths))
        else:
            event.ignore()

    def _detect_drop_zone(self, pos: QPoint) -> str:
        """Determine which zone the cursor is in: left, right, top, or bottom."""
        return detect_drop_zone(pos.x(), pos.y(), self.width(), self.height())

    def _encode_transfer_payload(self, paths: list[str]) -> bytes:
        payload = {
            "paths": paths,
            "source_pane_id": str(id(self)),
        }
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _decode_transfer_payload(mime: QMimeData | None) -> dict[str, object] | None:
        if mime is None or not mime.hasFormat(TRANSFER_MIME_TYPE):
            return None
        try:
            raw = bytes(mime.data(TRANSFER_MIME_TYPE)).decode("utf-8")
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            log.debug("Ignoring malformed drag payload", exc_info=True)
            return None
        if not isinstance(payload, dict):
            return None
        paths = payload.get("paths")
        source_pane_id = payload.get("source_pane_id")
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            return None
        if not isinstance(source_pane_id, str):
            return None
        return {"paths": paths, "source_pane_id": source_pane_id}

    # --- Slots ---

    def _go_up(self) -> None:
        parent = self._backend.parent(self._current_path)
        if parent != self._current_path:
            self.navigate(parent)

    def _go_home(self) -> None:
        self.navigate(self._backend.home())

    def _on_path_entered(self) -> None:
        path = self._path_edit.text().strip()
        if path:
            self.navigate(path)

    def _on_double_click(self, index: QModelIndex) -> None:
        source_idx = self._proxy.mapToSource(index)
        item = self._model.get_item(source_idx.row())
        if not item:
            return
        if item.name == "..":
            self.navigate(self._backend.parent(self._current_path))
            return
        full_path = self._backend.join(self._current_path, item.name)
        if item.is_dir:
            self.navigate(full_path)
        elif item.is_link and self._link_points_to_directory(full_path):
            # Symlink pointing to a directory — navigate into it
            self.navigate(full_path)
        else:
            # Route to the best viewer:
            #   images (local only) → ImageViewerDialog
            #   binaries            → hex
            #   text                → text editor
            #   fallthrough         → emit for other handlers
            if self._looks_like_image(item.name) and self._open_image_viewer(full_path):
                return
            if self._is_binary_file(full_path, item.name):
                self._open_hex_editor(full_path)
            elif self._is_editable_file(item.name, item.size):
                self._open_editor(full_path)
            else:
                self.file_activated.emit(full_path)

    # Known binary extensions
    _BINARY_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
        ".mp3", ".mp4", ".avi", ".mkv", ".flac", ".wav", ".ogg", ".webm",
        ".zip", ".gz", ".bz2", ".xz", ".tar", ".7z", ".rar", ".zst",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".pyc", ".pyo",
        ".class", ".wasm", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
        ".iso", ".img", ".dmg", ".deb", ".rpm",
    }

    # Known text extensions
    _TEXT_EXTENSIONS = {
        ".txt", ".md", ".py", ".js", ".ts", ".json", ".xml", ".html",
        ".css", ".csv", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
        ".sh", ".bash", ".zsh", ".fish", ".c", ".h", ".cpp", ".hpp",
        ".java", ".rs", ".go", ".rb", ".pl", ".lua", ".sql", ".log",
        ".env", ".gitignore", ".dockerfile", ".makefile", ".tsx", ".jsx",
        ".svelte", ".vue", ".scss", ".less", ".sass", ".php", ".swift",
        ".kt", ".scala", ".zig", ".nim", ".r", ".jl", ".ex", ".exs",
        ".erl", ".hs", ".ml", ".v", ".sv", ".vhd", ".tcl", ".cmake",
        ".service", ".timer", ".socket", ".desktop", ".rules",
    }

    # Known text filenames (no extension)
    _TEXT_FILENAMES = {
        "makefile", "dockerfile", "readme", "license", "changelog",
        "authors", "todo", "copying", "contributing", "cmakelists.txt",
    }

    # Binary magic bytes: (offset, signature)
    _BINARY_MAGIC = [
        (0, b"\x89PNG"),          # PNG
        (0, b"\xff\xd8\xff"),     # JPEG
        (0, b"GIF8"),             # GIF
        (0, b"PK\x03\x04"),      # ZIP/DOCX/XLSX/JAR
        (0, b"\x1f\x8b"),        # gzip
        (0, b"BZ"),              # bzip2
        (0, b"\xfd7zXZ"),        # xz
        (0, b"\x7fELF"),         # ELF binary
        (0, b"MZ"),              # PE/EXE
        (0, b"\xca\xfe\xba\xbe"),  # Mach-O / Java class
        (0, b"%PDF"),            # PDF
        (0, b"SQLite"),          # SQLite
        (0, b"\x00asm"),         # WebAssembly
        (0, b"RIFF"),            # WAV/AVI/WEBP
        (0, b"\xff\xfb"),        # MP3
        (0, b"ID3"),             # MP3 with ID3 tag
        (0, b"fLaC"),            # FLAC
        (0, b"OggS"),            # OGG
        (0, b"\x1a\x45\xdf\xa3"),  # MKV/WEBM
    ]

    def _is_binary_file(self, path: str, name: str) -> bool:
        """Detect if a file is binary using extension + magic bytes."""
        lower = name.lower()

        # Check extension first (fast path)
        for ext in self._BINARY_EXTENSIONS:
            if lower.endswith(ext):
                return True

        # If it's a known text extension, not binary
        for ext in self._TEXT_EXTENSIONS:
            if lower.endswith(ext):
                return False

        # Read first 512 bytes and check magic bytes + null bytes
        try:
            with self._backend.open_read(path) as f:
                header = f.read(512)
        except OSError:
            return False

        if not header:
            return False

        # Check magic bytes
        for offset, magic in self._BINARY_MAGIC:
            if header[offset:offset + len(magic)] == magic:
                return True

        # Heuristic: if there are null bytes in the first 512 bytes, likely binary
        if b"\x00" in header:
            return True

        return False

    def _is_editable_file(self, name: str, size: int) -> bool:
        """Check if a file should be opened in the text/hex editor."""
        # Limit: 10 MB for hex, 1 MB for text
        if size > 10 * 1024 * 1024:
            return False

        lower = name.lower()

        # Known text extensions
        for ext in self._TEXT_EXTENSIONS:
            if lower.endswith(ext):
                return True

        # Known text filenames
        if "." not in name and lower in self._TEXT_FILENAMES:
            return True

        # Unknown extension — try to open as text if small enough
        return size <= 1 * 1024 * 1024

    def _open_editor(self, path: str, read_only: bool = False) -> None:
        from ui.text_editor import TextEditorDialog

        dialog = TextEditorDialog(self._backend, path, parent=self, read_only=read_only)
        dialog.exec()
        if not read_only:
            self.refresh()

    def _open_hex_editor(self, path: str, read_only: bool = False) -> None:
        from ui.hex_editor import HexEditorDialog

        dialog = HexEditorDialog(self._backend, path, parent=self, read_only=read_only)
        dialog.exec()
        if not read_only:
            self.refresh()

    def _link_points_to_directory(self, path: str) -> bool:
        try:
            target = self._backend.readlink(path)
            if not target:
                return False
            sep = self._backend.separator()
            if not target.startswith(sep):
                target = self._backend.join(self._current_path, target)
            target_item = self._backend.stat(target)
            return target_item.is_dir
        except OSError:
            return False

    def _show_context_menu(self, pos) -> None:
        menu = QMenu(self)
        selected = self.selected_file_items()

        refresh_action = menu.addAction("Refresh")
        refresh_action.triggered.connect(self.refresh)

        menu.addSeparator()

        mkdir_action = menu.addAction("New Folder")
        mkdir_action.triggered.connect(self._create_folder)

        newfile_action = menu.addAction("New File…")
        newfile_action.triggered.connect(self._create_empty_file)

        # Symlink / Hardlink are backend-dependent. Hide when the
        # backend doesn't flag support so users don't see actions
        # that will fail the moment they click them.
        if getattr(self._backend, "supports_symlinks", False):
            sym_action = menu.addAction("New Symlink…")
            sym_action.triggered.connect(self._create_symlink)
        if getattr(self._backend, "supports_hardlinks", False):
            hard_action = menu.addAction("New Hardlink…")
            hard_action.triggered.connect(self._create_hardlink)

        bookmark_action = menu.addAction("Bookmark This Directory")
        bookmark_action.triggered.connect(self._add_bookmark)

        xlink_action = menu.addAction("Create XLink…")
        xlink_action.triggered.connect(self._create_xlink)

        # FUSE mount toggle — only shown when fusepy is importable.
        # Two separate entries (read-only + read-write) make the
        # chosen mode explicit rather than hiding it behind a dialog
        # toggle. When a mount is already active only "Unmount" shows.
        try:
            from core import fuse_mount as FM
            if FM.is_available():
                if getattr(self, "_fuse_handle", None) is not None:
                    fuse_action = menu.addAction("Unmount FUSE")
                    fuse_action.triggered.connect(self._unmount_fuse)
                else:
                    ro_action = menu.addAction("Mount as FUSE (read-only)…")
                    ro_action.triggered.connect(
                        lambda: self._mount_as_fuse(writeable=False),
                    )
                    rw_action = menu.addAction("Mount as FUSE (read-write)…")
                    rw_action.triggered.connect(
                        lambda: self._mount_as_fuse(writeable=True),
                    )
        except Exception as exc:  # noqa: BLE001 — never let fuse break the menu
            log.debug("Skipping FUSE menu entry: %s", exc)

        trash_browser_action = menu.addAction("Show Trash…")
        trash_browser_action.triggered.connect(self._show_trash_browser)

        if selected:
            menu.addSeparator()

            copy_action = menu.addAction("Copy to Target Pane")
            copy_action.triggered.connect(
                lambda: self.transfer_requested.emit(self.selected_items())
            )

            # Open in editor (for single file selection)
            files = [i for i in selected if not i.is_dir]
            if len(files) == 1:
                menu.addSeparator()
                item = files[0]
                full_path = self._backend.join(self._current_path, item.name)

                text_action = menu.addAction("Open as Text")
                text_action.triggered.connect(lambda: self._open_editor(full_path))

                hex_action = menu.addAction("Open as Hex")
                hex_action.triggered.connect(lambda: self._open_hex_editor(full_path))

                # "Open as root…" only shows for local backends and only
                # if pkexec + the helper binaries (cat/tee/stat/ls) are
                # actually present. Hiding it on remote / pkexec-less
                # systems avoids the "click → error dialog" UX dead-end.
                if self._elevated_io_available():
                    elev_action = menu.addAction("Open as root…")
                    elev_action.triggered.connect(
                        lambda: self._open_as_root(full_path)
                    )

            menu.addSeparator()

            rename_action = menu.addAction("Rename")
            rename_action.triggered.connect(self._rename_selected)

            if len(selected) > 1:
                batch_rename_action = menu.addAction("Batch Rename...")
                batch_rename_action.triggered.connect(self._batch_rename)

            trash_action = menu.addAction("Move to Trash")
            trash_action.triggered.connect(self._trash_selected)

            delete_action = menu.addAction("Delete Permanently")
            delete_action.triggered.connect(self._delete_selected)

            menu.addSeparator()

            perms_action = menu.addAction("Permissions...")
            perms_action.triggered.connect(self._show_permissions)

            # Checksum is a single-file action — most backends return a
            # native fingerprint (S3 ETag, Drive md5Checksum, ssh
            # sha256sum etc.) cheaply; the rest fall back to streaming
            # via open_read after a confirmation prompt.
            files_for_csum = [i for i in selected if not i.is_dir]
            if len(files_for_csum) == 1:
                csum_action = menu.addAction("Show Checksum…")
                csum_action.triggered.connect(
                    lambda: self._show_checksum(files_for_csum[0])
                )

                versions_action = menu.addAction("Show Versions…")
                versions_action.triggered.connect(
                    lambda: self._show_versions(files_for_csum[0])
                )

            # Directory size
            dirs = [i for i in selected if i.is_dir]
            if dirs:
                size_action = menu.addAction(f"Calculate Size ({len(dirs)} dirs)")
                size_action.triggered.connect(self._calculate_dir_size)

            # Symlink info
            links = [i for i in selected if i.is_link]
            if links:
                link_target_action = menu.addAction("Show Link Target")
                link_target_action.triggered.connect(self._show_link_target)

            # Encryption (single file only — passphrase prompt flow).
            if len(files) == 1:
                item = files[0]
                menu.addSeparator()
                if item.name.endswith(".axenc"):
                    dec_action = menu.addAction("Decrypt with passphrase…")
                    dec_action.triggered.connect(
                        lambda: self._decrypt_selected_file(item)
                    )
                else:
                    enc_action = menu.addAction("Encrypt with passphrase…")
                    enc_action.triggered.connect(
                        lambda: self._encrypt_selected_file(item)
                    )

            # Archive extraction — offered only for local backends
            # and only when the filename actually matches a format
            # we can extract. The safety caps + zip-slip guard live
            # in :mod:`core.archive`; the UI just picks a unique
            # target dir and drives a progress dialog.
            if len(files) == 1:
                from core import archive as _ARCH
                from core import previews as _PV
                if (_PV._is_local_backend(self._backend)
                        and _ARCH.is_supported_archive(files[0].name)):
                    menu.addSeparator()
                    extract_action = menu.addAction("Extract to folder…")
                    extract_action.triggered.connect(
                        lambda: self._extract_archive(files[0])
                    )

        # ``pos`` arrives in viewport-local coordinates per Qt's
        # QAbstractScrollArea contract, but user reports show the
        # menu landing in the wrong place on some window-manager /
        # Qt-version combos (likely a HiDPI scaling mismatch or a
        # viewport geometry quirk when the pane is split). Using the
        # current cursor's global position sidesteps the coordinate-
        # system conversion entirely — the menu opens where the
        # user actually clicked, every time.
        from PyQt6.QtGui import QCursor
        menu.exec(QCursor.pos())

    def _create_folder(self) -> None:
        from PyQt6.QtWidgets import QInputDialog

        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name:
            try:
                path = self._backend.join(self._current_path, name)
                self._backend.mkdir(path)
                log.info("Created folder: %s", path)
                self.refresh()
            except OSError as e:
                log.error("Failed to create folder: %s", e)
                QMessageBox.warning(
                    self, "New Folder", f"Could not create folder:\n{e}",
                )

    def _create_empty_file(self) -> None:
        """Create a zero-byte file at a user-supplied name.

        Uses the backend's own ``open_write`` rather than a
        filesystem-specific syscall; this means "New File" works on
        every backend that supports writes (SFTP, S3, Dropbox, …),
        not just LocalFS. An empty file is semantically unambiguous
        across backends — no MIME guessing, no attribute defaults
        that differ per protocol.
        """
        from PyQt6.QtWidgets import QInputDialog

        name, ok = QInputDialog.getText(self, "New File", "File name:")
        if not ok or not name:
            return
        path = self._backend.join(self._current_path, name)
        try:
            with self._backend.open_write(path) as fh:
                fh.write(b"")
            log.info("Created empty file: %s", path)
            self.refresh()
        except OSError as e:
            log.error("Failed to create file: %s", e)
            QMessageBox.warning(
                self, "New File", f"Could not create file:\n{e}",
            )

    def _create_symlink(self) -> None:
        """Prompt for target + link name, then create a symlink.

        Target may be absolute or relative (dangling symlinks are a
        legitimate POSIX pattern and we don't second-guess). The link
        is created under the current directory using the user-supplied
        name. Backends flag support via ``supports_symlinks``; this
        action is hidden from the menu otherwise.
        """
        from PyQt6.QtWidgets import QInputDialog

        target, ok = QInputDialog.getText(
            self, "New Symlink", "Target (what the symlink points to):",
        )
        if not ok or not target:
            return
        link_name, ok = QInputDialog.getText(
            self, "New Symlink", "Link name (created in this directory):",
        )
        if not ok or not link_name:
            return
        if not _is_safe_leaf_name(link_name):
            QMessageBox.warning(
                self, "New Symlink",
                "Link name must be a plain filename — no path "
                "separators, no '..', no NUL bytes.",
            )
            return
        link_path = self._backend.join(self._current_path, link_name)
        try:
            self._backend.symlink(target, link_path)
            log.info("Created symlink: %s → %s", link_path, target)
            self.refresh()
        except OSError as e:
            log.error("Failed to create symlink: %s", e)
            QMessageBox.warning(
                self, "New Symlink", f"Could not create symlink:\n{e}",
            )

    def _create_hardlink(self) -> None:
        """Prompt for target + link name, then create a hardlink.

        Both paths must live on the same filesystem — cross-device
        hardlinks raise OSError(EXDEV) which we surface verbatim so
        the user understands why. Backends flag support via
        ``supports_hardlinks``; this action is hidden from the menu
        otherwise.
        """
        from PyQt6.QtWidgets import QInputDialog

        target, ok = QInputDialog.getText(
            self, "New Hardlink",
            "Target (existing file to link to):",
        )
        if not ok or not target:
            return
        link_name, ok = QInputDialog.getText(
            self, "New Hardlink", "Link name (created in this directory):",
        )
        if not ok or not link_name:
            return
        if not _is_safe_leaf_name(link_name):
            QMessageBox.warning(
                self, "New Hardlink",
                "Link name must be a plain filename — no path "
                "separators, no '..', no NUL bytes.",
            )
            return
        link_path = self._backend.join(self._current_path, link_name)
        try:
            self._backend.hardlink(target, link_path)
            log.info("Created hardlink: %s → %s", link_path, target)
            self.refresh()
        except OSError as e:
            log.error("Failed to create hardlink: %s", e)
            QMessageBox.warning(
                self, "New Hardlink", f"Could not create hardlink:\n{e}",
            )

    def _rename_selected(self) -> None:
        from PyQt6.QtWidgets import QInputDialog

        items = self.selected_file_items()
        if not items:
            return
        item = items[0]
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=item.name)
        if ok and new_name and new_name != item.name:
            if not _is_safe_leaf_name(new_name):
                QMessageBox.warning(
                    self, "Rename",
                    "New name must be a plain filename — no path "
                    "separators, no '..', no NUL bytes.",
                )
                return
            try:
                old_path = self._backend.join(self._current_path, item.name)
                new_path = self._backend.join(self._current_path, new_name)
                self._backend.rename(old_path, new_path)
                log.info("Renamed %s -> %s", old_path, new_path)
                self.refresh()
            except OSError as e:
                log.error("Rename failed: %s", e)

    def _batch_rename(self) -> None:
        from ui.batch_rename_dialog import BatchRenameDialog

        items = self.selected_file_items()
        if not items:
            return
        dialog = BatchRenameDialog(self._backend, self._current_path, items, parent=self)
        if dialog.exec():
            self.refresh()

    def _delete_selected(self) -> None:
        items = self.selected_file_items()
        if not items:
            return
        names = ", ".join(i.name for i in items[:5])
        if len(items) > 5:
            names += f" ... (+{len(items) - 5} more)"

        reply = QMessageBox.question(
            self,
            "Delete",
            f"Delete {len(items)} item(s)?\n{names}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            errors = []
            for item in items:
                try:
                    path = self._backend.join(self._current_path, item.name)
                    self._backend.remove(path, recursive=item.is_dir)
                    log.info("Deleted: %s", path)
                except OSError as e:
                    log.error("Delete failed for %s: %s", item.name, e)
                    errors.append(f"{item.name}: {e}")
            if errors:
                QMessageBox.warning(
                    self, "Delete Errors",
                    f"{len(errors)} item(s) failed:\n" + "\n".join(errors[:10]),
                )
            self.refresh()

    def _show_permissions(self) -> None:
        from ui.permissions_dialog import PermissionsDialog

        items = self.selected_file_items()
        if not items:
            return
        item = items[0]
        path = self._backend.join(self._current_path, item.name)
        dialog = PermissionsDialog(self._backend, path, item, parent=self)
        if dialog.exec():
            self.refresh()

    def _calculate_dir_size(self) -> None:
        """Calculate total size of selected directories."""
        items = self.selected_file_items()
        dirs = [i for i in items if i.is_dir]
        if not dirs:
            return

        self._status.setText("Calculating sizes...")
        self._progress_bar.show()
        QApplication.processEvents()

        results = []
        for item in dirs:
            dir_path = self._backend.join(self._current_path, item.name)
            total = self._recursive_size(dir_path)
            results.append((item.name, total))

        self._progress_bar.hide()

        msg_parts = []
        for name, size in results:
            def _fmt(b: int) -> str:
                for unit in ("B", "KB", "MB", "GB", "TB"):
                    if abs(b) < 1024:
                        return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
                    b /= 1024
                return f"{b:.1f} PB"
            msg_parts.append(f"{name}: {_fmt(size)}")

        QMessageBox.information(self, "Directory Size", "\n".join(msg_parts))
        self._status.setText(f"{self._model.rowCount()} items")

    def _recursive_size(self, path: str) -> int:
        total = 0
        try:
            for item in self._backend.list_dir(path):
                child = self._backend.join(path, item.name)
                if item.is_dir and not item.is_link:
                    total += self._recursive_size(child)
                else:
                    total += item.size
        except OSError as e:
            log.warning("Could not calculate recursive size for %s: %s", path, e)
        return total

    # Known checksum-string prefixes that the backends return. Keeping
    # this as an explicit allowlist (rather than a "looks like
    # ``<word>:<hex>``" heuristic) avoids two failure modes:
    #   * a hex-only value that happens to contain a ":" being split
    #     in the wrong place
    #   * a backend later returning some new "<word>:<value>" format
    #     where the tail isn't a hex digest (would have been silently
    #     reinterpreted as the algorithm by the old code)
    # Order matters: longer prefixes (s3-etag) must come before any
    # shorter one they could overlap with.
    _CHECKSUM_PREFIXES = (
        "s3-etag", "etag", "dropbox", "quickxor",
        "md5", "sha1", "sha256", "sha512",
    )

    @classmethod
    def _split_checksum(cls, value: str) -> tuple[str, str]:
        """Return ``(algorithm, hex_value)`` for a string returned by
        ``backend.checksum``. Strings without a known prefix are
        treated as raw SHA-256 (the requested default algorithm)."""
        for prefix in cls._CHECKSUM_PREFIXES:
            head = prefix + ":"
            if value.startswith(head):
                return prefix, value[len(head):]
        return "sha256", value

    def _show_checksum(self, item) -> None:
        """Compute or fetch a checksum for *item* and show it in a copy
        dialog. Backends that have a cheap native fingerprint return it
        from ``backend.checksum`` immediately; the rest return ``""``,
        in which case we offer a stream-hash fallback."""
        from PyQt6.QtCore import Qt
        from ui.checksum_dialog import ChecksumDialog

        full_path = self._backend.join(self._current_path, item.name)
        # Cursor stack discipline: exactly one push and exactly one
        # pop, no matter what exits below. The pop happens in the
        # outer finally; the OSError is captured and surfaced AFTER
        # the pop so the warning dialog doesn't render under a wait
        # cursor. A non-OSError raised by the backend still propagates
        # but the cursor is restored on the way out.
        error: OSError | None = None
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            try:
                value = self._backend.checksum(full_path)
            except OSError as exc:
                error = exc
        finally:
            QApplication.restoreOverrideCursor()
        if error is not None:
            QMessageBox.warning(
                self, "Checksum",
                f"Failed to compute checksum:\n{error}",
            )
            return

        source = "native"
        if value:
            algo, value = self._split_checksum(value)
        # A backend that returned a known prefix with an empty tail
        # (e.g. ``"md5:"``) is still "no native checksum" from the
        # user's perspective — fall through to the stream-hash flow.
        if not value:
            reply = QMessageBox.question(
                self, "Checksum",
                f"{item.name}: this backend has no native checksum.\n\n"
                "Compute SHA-256 by reading the entire file?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            try:
                value = self._stream_sha256(full_path, item.size)
            except OSError as exc:
                QMessageBox.warning(
                    self, "Checksum",
                    f"Failed to read file for hashing:\n{exc}",
                )
                return
            if value is None:  # user clicked Cancel on the progress dialog
                return
            algo = "sha256"
            source = "stream-read"

        dlg = ChecksumDialog(full_path, algo, value, source=source, parent=self)
        dlg.exec()

    def _stream_sha256(self, path: str, total_size: int = 0) -> str | None:
        """Read *path* through the backend and return its SHA-256 hex,
        or ``None`` if the user clicks Cancel on the progress dialog.

        A QProgressDialog is shown after a brief delay (so a small
        local file finishes silently). When the file size is known we
        render a determinate bar; otherwise the dialog stays in busy
        mode. Either way the user can abort the read at any time.
        """
        import hashlib
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QProgressDialog

        chunk_size = 1024 * 1024
        # Use a determinate range only when total_size > 0; otherwise
        # the dialog renders as a busy indicator (range 0..0).
        if total_size and total_size > 0:
            progress = QProgressDialog(
                f"Hashing {path}…", "Cancel", 0, total_size, self,
            )
        else:
            progress = QProgressDialog(
                f"Hashing {path}…", "Cancel", 0, 0, self,
            )
        progress.setWindowTitle("Checksum")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(500)  # don't flash for tiny files
        progress.setValue(0)

        h = hashlib.sha256()
        bytes_done = 0
        cancelled = False
        try:
            with self._backend.open_read(path) as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
                    bytes_done += len(chunk)
                    if total_size and total_size > 0:
                        progress.setValue(min(bytes_done, total_size))
                    QApplication.processEvents()
                    if progress.wasCanceled():
                        cancelled = True
                        break
        finally:
            progress.close()
        if cancelled:
            return None
        return h.hexdigest()

    # ------------------------------------------------------------------
    # Column header — show/hide + persist widths
    # ------------------------------------------------------------------
    def _apply_column_prefs(self) -> None:
        from ui import column_prefs as CP
        prefs = CP.load()
        # Defensive: if a hand-edited prefs file claims col 0 is
        # hidden, ignore it — the Name column must always be visible.
        if 0 in prefs.hidden:
            prefs.hidden.discard(0)
        # Cache so the resize / hide handlers can mutate-and-save
        # without re-reading the file every time.
        self._column_prefs = prefs
        header = self._table.horizontalHeader()
        n = self._model.columnCount()
        for col in range(n):
            width = prefs.widths.get(col)
            if width and width > 10:
                header.resizeSection(col, int(width))
            self._table.setColumnHidden(col, col in prefs.hidden)

    def _save_column_prefs(self) -> None:
        """Persist this pane's column prefs without losing changes
        another pane (in the same process) wrote concurrently.

        Uses ``column_prefs.update`` which holds a per-path lock for
        the entire load+modify+save cycle. The mutator merges *our*
        deltas onto the on-disk state so two panes saving at the
        same time don't clobber each other's widths."""
        from ui import column_prefs as CP
        local = getattr(self, "_column_prefs", None)
        if local is None:
            return
        try:
            merged = CP.update(self._merge_into_prefs)
            # Refresh our cached copy so subsequent mutations start
            # from the merged baseline.
            self._column_prefs = merged
        except OSError as exc:
            log.warning("Could not persist column prefs: %s", exc)

    def _merge_into_prefs(self, on_disk) -> None:
        """Apply our local widths/hidden onto the freshly-loaded
        on-disk prefs.

        widths: per-column merge — ``on_disk.widths.update(local)``
                preserves another pane's edit on column N when ours
                edited column M. This is the lost-update fix: without
                it, two panes resizing different columns concurrently
                would each clobber the other's change.

        hidden: last-writer-wins — replace ``on_disk.hidden`` with
                ours. Hidden is a per-user preference (same human
                drives both panes); merging would lock columns visible
                that the user explicitly hid in the latest pane.
        """
        local = getattr(self, "_column_prefs", None)
        if local is None:
            return
        on_disk.widths.update(local.widths)
        on_disk.hidden = set(local.hidden)

    def _on_section_resized(self, idx: int, _old: int, new: int) -> None:
        if getattr(self, "_column_prefs", None) is None:
            return
        # Tiny / negative widths happen during programmatic moves —
        # ignore them so we don't persist garbage.
        if new < 10:
            return
        self._column_prefs.widths[int(idx)] = int(new)
        self._save_column_prefs()

    def _show_header_menu(self, pos) -> None:
        """Right-click on the header opens a checkbox list of columns
        — checked = visible. Toggling a column hides/shows it and
        persists the change. The Name column (0) is pinned visible
        because hiding it leaves the pane unusable."""
        from PyQt6.QtGui import QCursor
        if getattr(self, "_column_prefs", None) is None:
            return
        n = self._model.columnCount()
        menu = QMenu(self)
        for col in range(n):
            label = self._model.headerData(
                col, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole,
            ) or f"Column {col}"
            action = menu.addAction(str(label))
            action.setCheckable(True)
            action.setChecked(not self._table.isColumnHidden(col))
            if col == 0:
                # Pinning: never let the user hide the Name column.
                action.setEnabled(False)
            else:
                action.toggled.connect(
                    lambda visible, c=col: self._toggle_column(c, visible)
                )
        menu.exec(QCursor.pos())

    def _toggle_column(self, col: int, visible: bool) -> None:
        if getattr(self, "_column_prefs", None) is None:
            return
        # Pin: the Name column is the row identity; hiding it
        # leaves the pane unusable. The right-click menu disables
        # the action for col=0, but a programmatic call (test, future
        # API, restored prefs file edited by hand) would still get
        # through without this guard.
        if col == 0 and not visible:
            return
        self._table.setColumnHidden(col, not visible)
        if visible:
            self._column_prefs.hidden.discard(col)
        else:
            self._column_prefs.hidden.add(col)
        self._save_column_prefs()

    # ------------------------------------------------------------------
    # FUSE mount integration (Phase 6a)
    # ------------------------------------------------------------------
    def _mount_as_fuse(self, writeable: bool = False) -> None:
        """Pop a directory chooser and start a FUSE mount of the
        current backend at the chosen empty mount point.

        Read-only by default; ``writeable=True`` enables the
        create/write/unlink/mkdir/rename callbacks. The wiring adds
        two menu entries (read-only + writeable) so the user sees
        the mode they're picking up front rather than a hidden
        toggle buried in a dialog."""
        from PyQt6.QtWidgets import QFileDialog
        from core import fuse_mount as FM
        if getattr(self, "_fuse_handle", None) is not None:
            QMessageBox.information(
                self, "FUSE",
                f"This pane already has a FUSE mount at "
                f"{self._fuse_handle.mount_point}.",
            )
            return
        mount_point = QFileDialog.getExistingDirectory(
            self, "Pick an empty mount point",
        )
        if not mount_point:
            return
        try:
            handle = FM.mount(
                self._backend, mount_point,
                root=self._current_path, writeable=writeable,
            )
        except Exception as exc:  # noqa: BLE001 — surface to user
            QMessageBox.critical(
                self, "FUSE",
                f"Could not mount:\n{exc}",
            )
            return
        self._fuse_handle = handle
        mode = "read-write" if writeable else "read-only"
        QMessageBox.information(
            self, "FUSE",
            f"Mounted {self._current_path} ({mode}) at {mount_point}.",
        )

    def _unmount_fuse(self) -> None:
        handle = getattr(self, "_fuse_handle", None)
        if handle is None:
            return
        try:
            handle.unmount()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(
                self, "FUSE",
                f"Unmount reported an error (mount may still be live):\n{exc}",
            )
        self._fuse_handle = None
        QMessageBox.information(
            self, "FUSE",
            f"Unmounted {handle.mount_point}.",
        )

    def _create_xlink(self) -> None:
        """Pop the create-xlink dialog and write a new ``.axlink``
        pointer file in the current directory."""
        from core import xlink as XL
        from ui.create_xlink_dialog import CreateXlinkDialog
        dlg = CreateXlinkDialog(parent=self)
        if not dlg.exec():
            return
        name = dlg.name()
        url = dlg.target_url()
        display = dlg.display_name()
        target_path = self._backend.join(self._current_path, name)
        try:
            final = XL.create_xlink(
                self._backend, target_path, url, display_name=display,
            )
            log.info("Created xlink %s → %s", final, url)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(
                self, "Create XLink",
                f"Could not create xlink:\n{exc}",
            )
            return
        self.refresh()

    def _show_versions(self, item) -> None:
        """Open the snapshot/versions browser for a single file."""
        from ui.snapshot_browser_dialog import SnapshotBrowserDialog
        full_path = self._backend.join(self._current_path, item.name)
        dlg = SnapshotBrowserDialog(self._backend, full_path, parent=self)
        dlg.finished.connect(lambda _code: self.refresh())
        dlg.open()

    def _elevated_io_available(self) -> bool:
        """True when the menu entry "Open as root…" should be shown:
        backend is local AND pkexec + helper binaries are on PATH."""
        try:
            from core import elevated_io as E
            return E._is_local_backend(self._backend) and E.is_pkexec_available()
        except Exception:
            return False

    def _open_as_root(self, full_path: str) -> None:
        """Read *full_path* via pkexec and pop a read-only viewer.

        The polkit prompt is handled by the system agent (a separate
        process); during the prompt our subprocess.run blocks the GUI
        thread for up to ELEVATED_TIMEOUT_SECS. That's a known wart of
        the synchronous first cut — acceptable because the user just
        triggered this action and is expecting an auth dialog.
        """
        from core import elevated_io as E
        from ui.elevated_viewer import ElevatedViewerDialog
        try:
            data = E.elevated_read(self._backend, full_path)
        except E.ElevatedCancelled:
            log.info("Open-as-root cancelled by user: %s", full_path)
            return
        except E.ElevatedNotAvailable as exc:
            QMessageBox.information(
                self, "Open as root",
                f"Cannot elevate access:\n{exc}",
            )
            return
        except E.ElevatedOutputTooLarge as exc:
            QMessageBox.warning(
                self, "Open as root",
                f"File is too large to read into memory:\n{exc}",
            )
            return
        except (E.ElevatedIOError, ValueError) as exc:
            QMessageBox.critical(
                self, "Open as root",
                f"Elevated read failed:\n{exc}",
            )
            return
        dlg = ElevatedViewerDialog(full_path, data, parent=self)
        dlg.exec()

    def _trash_selected(self) -> None:
        """Move selected items to ``core.trash`` for the current backend.

        Trash lives at ``<backend.home()>/.axross-trash`` by default,
        so the entry survives restart and can be restored through
        "Show Trash…". Uses the typed error contract: per-item OSError
        is collected and reported at the end, one bad item doesn't
        abort the rest.
        """
        from core import trash as T
        items = self.selected_file_items()
        if not items:
            return
        names = ", ".join(i.name for i in items[:5])
        if len(items) > 5:
            names += f" … (+{len(items) - 5} more)"
        reply = QMessageBox.question(
            self, "Move to Trash",
            f"Move {len(items)} item(s) to trash?\n{names}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        errors: list[str] = []
        moved = 0
        for item in items:
            path = self._backend.join(self._current_path, item.name)
            try:
                T.trash(self._backend, path)
                moved += 1
                log.info("Trashed: %s", path)
            except OSError as e:
                errors.append(f"{item.name}: {e}")
                log.error("Trash failed for %s: %s", item.name, e)
        if errors:
            QMessageBox.warning(
                self, "Trash Errors",
                f"{len(errors)} item(s) failed:\n" + "\n".join(errors[:10]),
            )
        self.refresh()

    def _show_trash_browser(self) -> None:
        """Open a dialog listing ``core.trash`` entries for the current
        backend. User can restore or permanently delete from there."""
        from ui.trash_browser import TrashBrowserDialog
        dlg = TrashBrowserDialog(self._backend, parent=self)
        dlg.finished.connect(lambda _code: self.refresh())
        dlg.open()

    def _extract_archive(self, item) -> None:
        """Extract the archive at *item* into a same-named sibling
        folder (extension stripped). On collision (``foo/`` already
        exists) the target auto-suffixes to ``foo-1/``, ``foo-2/``, …
        so repeated extracts of the same archive don't clobber.

        Runs on a QThread with a QProgressDialog; cancel aborts the
        worker and removes the partially-populated target directory
        (cleanup lives in :func:`core.archive.extract` — we just
        raise ExtractCancelled from the progress callback and let
        the library roll back).

        Local-backend-only: the caller gates the menu entry on
        ``_is_local_backend``. Remote-backend archives would need a
        download-then-extract flow which is intentionally out of
        scope for V1 — use "Copy to Target Pane" + extract locally.
        """
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QProgressDialog
        from core import archive as ARCH

        src_path = self._backend.join(self._current_path, item.name)
        parent_dir = self._backend.parent(src_path)
        base = ARCH.strip_archive_extension(item.name)
        try:
            target_dir = ARCH.auto_suffix_dir(parent_dir, base)
        except OSError as exc:
            QMessageBox.warning(
                self, "Extract Archive",
                f"Cannot pick a unique target folder:\n{exc}",
            )
            return

        progress = QProgressDialog(
            f"Extracting {item.name} → {Path(target_dir).name}…",
            "Cancel", 0, 0, self,
        )
        progress.setWindowTitle("Extract Archive")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(250)
        progress.setValue(0)

        # Shared state between the worker and the dialog poller.
        done_event = threading.Event()
        # Pre-seed with something the types in the pipeline accept.
        state: dict = {"ok": False, "count": 0, "error": None,
                       "current": 0, "total": 0, "name": ""}

        def _progress_cb(done: int, total: int, name: str) -> None:
            state["current"] = done
            state["total"] = total
            state["name"] = name
            if progress.wasCanceled():
                raise ARCH.ExtractCancelled(
                    "user cancelled via progress dialog",
                )

        def _worker() -> None:
            try:
                state["count"] = ARCH.extract(
                    src_path, target_dir, progress=_progress_cb,
                )
                state["ok"] = True
            except ARCH.ExtractCancelled:
                state["error"] = "cancelled"
            except ARCH.UnsafeArchive as exc:
                state["error"] = f"refused as unsafe: {exc}"
            except Exception as exc:  # noqa: BLE001
                state["error"] = f"extraction failed: {exc}"
            finally:
                done_event.set()

        t = threading.Thread(
            target=_worker, daemon=True,
            name=f"extract:{item.name}",
        )
        t.start()

        # Pump the Qt event loop while the worker runs so the
        # progress dialog stays responsive. ``done_event.wait(short)``
        # parks us cheaply when the worker is busy AND gives the
        # event loop a chance to fire the Cancel button.
        while not done_event.is_set():
            QApplication.processEvents()
            done_event.wait(0.05)
        # Drain any pending UI events so the final progress update
        # lands before we close the dialog.
        QApplication.processEvents()
        progress.close()

        if state["ok"]:
            log.info(
                "Extracted %s → %s (%d files)",
                src_path, target_dir, state["count"],
            )
            self.refresh()
            QMessageBox.information(
                self, "Extract Archive",
                f"Extracted {state['count']} files to\n{target_dir}",
            )
            return
        if state["error"] == "cancelled":
            log.info("Extraction cancelled: %s", src_path)
            return
        QMessageBox.warning(
            self, "Extract Archive",
            f"Could not extract {item.name}:\n{state['error']}",
        )

    def _encrypt_selected_file(self, item) -> None:
        """Encrypt *item* in place (writes ``<name>.axenc`` next to it).

        Prompts for a passphrase twice (confirm) via QInputDialog, then
        reads the source, encrypts via core.encrypted_overlay, writes
        the resulting ``.axenc``. Does NOT delete the plaintext — user
        decides when they're comfortable.
        """
        from PyQt6.QtWidgets import QInputDialog, QLineEdit
        from core import encrypted_overlay as E

        pw, ok = QInputDialog.getText(
            self, "Encrypt File",
            f"Passphrase for '{item.name}':",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
        pw_confirm, ok = QInputDialog.getText(
            self, "Encrypt File",
            "Repeat passphrase:",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if pw != pw_confirm:
            QMessageBox.warning(
                self, "Encrypt File", "Passphrases do not match.",
            )
            return

        src_path = self._backend.join(self._current_path, item.name)
        try:
            with self._backend.open_read(src_path) as fh:
                data = fh.read()
            dst_path = E.write_encrypted(
                self._backend, src_path, data, pw,
            )
            log.info("Encrypted %s -> %s", src_path, dst_path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Encrypt Failed", f"Could not encrypt file:\n{exc}",
            )
            return
        QMessageBox.information(
            self, "Encrypted",
            f"{item.name} → {dst_path.rsplit('/', 1)[-1]}\n\n"
            "Original plaintext is still in place — delete it manually "
            "when you've verified the encrypted copy decrypts cleanly.",
        )
        self.refresh()

    def _decrypt_selected_file(self, item) -> None:
        """Decrypt a ``.axenc`` file in place (writes the original
        filename minus the ``.axenc`` suffix)."""
        from PyQt6.QtWidgets import QInputDialog, QLineEdit
        from core import encrypted_overlay as E

        pw, ok = QInputDialog.getText(
            self, "Decrypt File",
            f"Passphrase for '{item.name}':",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return

        src_path = self._backend.join(self._current_path, item.name)
        dst_name = item.name[:-len(E.ENC_SUFFIX)] or item.name + ".decrypted"
        dst_path = self._backend.join(self._current_path, dst_name)
        try:
            plain = E.read_encrypted(self._backend, src_path, pw)
        except E.InvalidCiphertext as exc:
            QMessageBox.warning(
                self, "Decrypt Failed",
                f"Wrong passphrase or corrupted file:\n{exc}",
            )
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Decrypt Failed", f"Could not decrypt file:\n{exc}",
            )
            return

        try:
            if self._backend.exists(dst_path):
                reply = QMessageBox.question(
                    self, "Overwrite?",
                    f"'{dst_name}' already exists. Overwrite?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
                self._backend.remove(dst_path)
            with self._backend.open_write(dst_path) as fh:
                fh.write(plain)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Decrypt Failed", f"Could not write plaintext:\n{exc}",
            )
            return
        log.info("Decrypted %s -> %s", src_path, dst_path)
        self.refresh()

    def _show_link_target(self) -> None:
        items = self.selected_file_items()
        links = [i for i in items if i.is_link]
        if not links:
            return

        msg_parts = []
        for item in links:
            path = self._backend.join(self._current_path, item.name)
            try:
                target = self._backend.readlink(path)
                msg_parts.append(f"{item.name} -> {target}")
            except OSError as e:
                msg_parts.append(f"{item.name} -> (error: {e})")

        QMessageBox.information(self, "Symlink Targets", "\n".join(msg_parts))

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self.pane_focused.emit()

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.FocusIn, QEvent.Type.MouseButtonPress):
            self.pane_focused.emit()

        # Keyboard shortcuts when the table (or its viewport) has focus
        if event.type() == QEvent.Type.KeyPress and watched in (
            self._table, self._table.viewport(),
        ):
            key = event.key()
            mods = event.modifiers()
            ctrl = mods == Qt.KeyboardModifier.ControlModifier
            ctrl_shift = mods == (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
            )
            alt = mods == Qt.KeyboardModifier.AltModifier
            no_mods = mods == Qt.KeyboardModifier.NoModifier

            # --- Alt+Enter → permissions (must be before bare Enter) ---
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and alt:
                self._show_permissions()
                return True

            # --- File operations ---
            if key in (Qt.Key.Key_Delete, Qt.Key.Key_F8) and no_mods:
                self._delete_selected()
                return True
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and no_mods:
                rows = self._table.selectionModel().selectedRows(COL_NAME)
                if len(rows) == 1:
                    self._on_double_click(rows[0])
                return True
            if key == Qt.Key.Key_F2 and no_mods:
                self._rename_selected()
                return True
            if key == Qt.Key.Key_F3 and no_mods:
                self._view_selected()
                return True
            if key == Qt.Key.Key_F4 and no_mods:
                self._edit_selected()
                return True
            if key == Qt.Key.Key_F5 and no_mods:
                self._copy_to_target()
                return True
            if key == Qt.Key.Key_F6 and no_mods:
                self._move_to_target()
                return True
            if key == Qt.Key.Key_F7 and no_mods:
                self._create_folder()
                return True
            if key == Qt.Key.Key_F9 and no_mods:
                self._rename_selected()
                return True
            if key == Qt.Key.Key_F10 and no_mods:
                idx = self._table.currentIndex()
                if idx.isValid():
                    pos = self._table.visualRect(idx).bottomLeft()
                else:
                    vp = self._table.viewport()
                    pos = QPoint(vp.width() // 2, vp.height() // 2)
                self._show_context_menu(pos)
                return True

            # --- Navigation ---
            if key == Qt.Key.Key_R and ctrl:
                self.refresh()
                return True
            if key == Qt.Key.Key_Backspace and no_mods:
                self._go_up()
                return True
            if key == Qt.Key.Key_Left and alt:
                self._go_back()
                return True
            if key == Qt.Key.Key_Right and alt:
                self._go_forward()
                return True

            # --- Selection ---
            if key == Qt.Key.Key_Escape and no_mods:
                self._table.clearSelection()
                return True
            if key == Qt.Key.Key_A and ctrl_shift:
                self._invert_selection()
                return True
            if key == Qt.Key.Key_A and ctrl:
                self._select_all()
                return True
            if key == Qt.Key.Key_Space and no_mods:
                self._toggle_select_and_move_down()
                return True

            # --- Misc ---
            if key == Qt.Key.Key_H and ctrl:
                self._proxy.show_hidden = not self._proxy.show_hidden
                self._status.setText(
                    "Hidden files: ON" if self._proxy.show_hidden else "Hidden files: OFF"
                )
                return True
            if key == Qt.Key.Key_F and ctrl:
                self._filter_edit.setFocus()
                self._filter_edit.selectAll()
                return True
            if key == Qt.Key.Key_L and ctrl:
                self._path_edit.setFocus()
                self._path_edit.selectAll()
                return True
            if key == Qt.Key.Key_D and ctrl:
                self._add_bookmark()
                return True
            if key == Qt.Key.Key_B and ctrl:
                self.open_bookmarks_requested.emit()
                return True
            if key == Qt.Key.Key_C and ctrl:
                if self.selected_items():
                    self._copy_paths_to_clipboard()
                    return True
                return False  # let Ctrl+C propagate if nothing selected

            # --- Pane cycling ---
            if key == Qt.Key.Key_Tab and no_mods:
                self.cycle_pane_requested.emit(True)
                return True
            if key == Qt.Key.Key_Backtab:  # Shift+Tab
                self.cycle_pane_requested.emit(False)
                return True

        return super().eventFilter(watched, event)
