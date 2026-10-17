"""Delete and drag-out for the image and the media viewer.

A viewer shows files of the pane it was opened from. Delete removes the
shown file after a question; a drag carries the pane transfer payload of
that pane (``FilePaneWidget._encode_transfer_payload``), so a drop on any
pane runs the same move / copy as a drag that started in the pane: Ctrl
copies, anything else moves, the destination is checked for conflicts,
and a move removes the source only after the copy arrived.

A viewer without a pane (opened on its own) offers no drag: the drop
side resolves the source by its pane and would refuse it anyway.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from html import escape

from PyQt6.QtCore import QEvent, QMimeData, QObject, QPoint, Qt, QUrl
from PyQt6.QtGui import QDrag
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

log = logging.getLogger("ui.viewer_file_actions")


def owning_pane(widget: QWidget | None):
    """The FilePaneWidget *widget* is (or lies) inside, else None."""
    from ui.file_pane import FilePaneWidget

    while widget is not None:
        if isinstance(widget, FilePaneWidget):
            return widget
        widget = widget.parentWidget()
    return None


def _name(backend, path: str) -> str:
    try:
        return backend.basename(path) if hasattr(backend, "basename") else path.rsplit("/", 1)[-1]
    except Exception:  # noqa: BLE001 - a name for a label only
        return path.rsplit("/", 1)[-1]


def start_file_drag(source: QWidget, backend, path: str, pane) -> Qt.DropAction:
    """Drag *path* out of a viewer as if from *pane*. Returns what the
    drop did: MoveAction, CopyAction, or IgnoreAction (refused / no pane)."""
    if pane is None:
        return Qt.DropAction.IgnoreAction
    from core.local_fs import LocalFS
    from ui.file_pane import TRANSFER_MIME_TYPE, drag_pixmap

    mime = QMimeData()
    mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload([path]))  # noqa: SLF001
    if isinstance(backend, LocalFS):
        mime.setUrls([QUrl.fromLocalFile(path)])
    drag = QDrag(source)
    drag.setMimeData(mime)
    drag.setPixmap(drag_pixmap([_name(backend, path)], dirs=0))
    drag.setHotSpot(QPoint(0, 0))
    result = drag.exec(
        Qt.DropAction.CopyAction | Qt.DropAction.MoveAction, Qt.DropAction.MoveAction
    )
    log.debug("Viewer drag of %s finished with %s", path, result)
    return result


def delete_file(parent: QWidget, backend, path: str, pane) -> bool:
    """Ask, then remove *path*. True when it is gone; the pane is refreshed."""
    name = _name(backend, path)
    reply = QMessageBox.question(
        parent,
        "Delete",
        f"Delete {escape(name)}?\n{escape(path)}",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    if reply != QMessageBox.StandardButton.Yes:
        return False
    try:
        backend.remove(path)
    except OSError as exc:
        log.error("Delete failed for %s: %s", path, exc)
        QMessageBox.warning(parent, "Delete", f"Could not delete {escape(name)}:\n{escape(str(exc))}")
        return False
    log.info("Deleted: %s", path)
    if pane is not None:
        pane.refresh_after_change()
    return True


class DragOut(QObject):
    """Starts a file drag when the left button moves past the drag
    distance on *widget*. *path_at(pos)* names the file under the press
    (None: no drag there), *allowed()* can veto (a zoomed image pans),
    *done(path, action)* hears how the drop went."""

    def __init__(
        self,
        widget: QWidget,
        backend,
        pane,
        path_at: Callable[[QPoint], str | None],
        done: Callable[[str, Qt.DropAction], None],
        allowed: Callable[[], bool] = lambda: True,
    ) -> None:
        super().__init__(widget)
        self._widget = widget
        self._backend = backend
        self._pane = pane
        self._path_at = path_at
        self._done = done
        self._allowed = allowed
        self._press: QPoint | None = None
        widget.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        kind = event.type()
        if kind == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
            self._press = event.position().toPoint()
        elif kind == QEvent.Type.MouseButtonRelease:
            self._press = None
        elif kind == QEvent.Type.MouseMove and self._press is not None:
            if not event.buttons() & Qt.MouseButton.LeftButton:
                self._press = None
                return False
            moved = (event.position().toPoint() - self._press).manhattanLength()
            if moved < QApplication.startDragDistance():
                return False
            press, self._press = self._press, None
            if self._pane is None or not self._allowed():
                return False
            path = self._path_at(press)
            if not path:
                return False
            action = start_file_drag(self._widget, self._backend, path, self._pane)
            self._done(path, action)
            return True
        return False


__all__ = ["DragOut", "delete_file", "owning_pane", "start_file_drag"]
