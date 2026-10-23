"""Dragging panes to rearrange them - the part file panes and terminal panes
share.

A pane's header is the drag handle (:class:`DraggableHeader`); the drag
carries only :data:`PANE_MIME_TYPE` with the dragged pane's ``id()`` - no
text, so neither a terminal nor an editor takes it as input. A pane that
takes the drop shows where it would land (:class:`DropOverlay`) and asks
the window to split; :class:`PaneDropZones` is that drop half, so both
pane kinds decide the same way. The window does the moving
(``MainWindow._on_pane_drop``).
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QMimeData, QPoint, Qt
from PyQt6.QtGui import QDrag, QMouseEvent, QPainter, QPixmap
from PyQt6.QtWidgets import QLabel, QWidget

from core.i18n import tr
from ui.layout_utils import detect_drop_zone

log = logging.getLogger(__name__)

PANE_MIME_TYPE = "application/x-axross-pane-drag"

#: Pixels (Manhattan) the mouse moves on a header before a pane drag starts:
#: a click on the header stays a click.
PANE_DRAG_THRESHOLD = 10

#: Longest pane id payload read; ``id()`` is at most 20 digits.
_MAX_PANE_ID = 32


def pane_drag_source_id(mime: QMimeData | None) -> str | None:
    """The dragged pane's id from a pane drag, or None for any other drag
    and for a payload that is no pane id (empty, not ASCII digits)."""
    if mime is None or not mime.hasFormat(PANE_MIME_TYPE):
        return None
    raw = bytes(mime.data(PANE_MIME_TYPE))
    if not raw or len(raw) > _MAX_PANE_ID or not raw.isdigit():
        return None
    return raw.decode("ascii")


def start_pane_drag(origin: QWidget, pane: QWidget) -> None:
    """Drag *pane* (from its header *origin*): the payload is the pane id."""
    drag = QDrag(origin)
    mime = QMimeData()
    mime.setData(PANE_MIME_TYPE, str(id(pane)).encode("ascii"))
    drag.setMimeData(mime)
    pix = QPixmap(120, 24)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setPen(Qt.GlobalColor.white)
    painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, tr("Move pane"))
    painter.end()
    drag.setPixmap(pix)
    drag.exec(Qt.DropAction.MoveAction)


class DraggableHeader(QLabel):
    """A pane's header label: dragging it past PANE_DRAG_THRESHOLD drags the
    pane; a click stays a click (it reaches the pane, which takes focus)."""

    def __init__(self, pane: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pane = pane
        self._drag_start: QPoint | None = None

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if (
            self._drag_start is not None
            and (event.pos() - self._drag_start).manhattanLength() >= PANE_DRAG_THRESHOLD
        ):
            self._drag_start = None
            self._start_pane_drag()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        self._drag_start = None
        super().mouseReleaseEvent(event)

    def _start_pane_drag(self) -> None:
        start_pane_drag(self, self._pane)


class DropOverlay(QWidget):
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

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        if not self._zone:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(Qt.GlobalColor.cyan)
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


class PaneDropZones:
    """The pane-drag half of a pane's drop handling. Each method returns
    whether the event was a pane drag (then it is decided here: accepted or
    ignored); the pane handles any other drag itself.

    A pane never takes a drag of itself, nor a payload that names no pane.

    *origin* is the widget whose coordinates the event carries when a child
    hands its event on (a file pane's table viewport); the zone is judged
    in the pane's own coordinates either way."""

    def __init__(self, pane: QWidget) -> None:
        self._pane = pane
        self.overlay = DropOverlay(pane)

    def _foreign_source(self, event) -> str | None:
        source_id = pane_drag_source_id(event.mimeData())
        if source_id is None or source_id == str(id(self._pane)):
            return None
        return source_id

    def _zone(self, event, origin: QWidget | None) -> str:
        pos = event.position().toPoint()
        if origin is not None and origin is not self._pane:
            pos = origin.mapTo(self._pane, pos)
        return detect_drop_zone(pos.x(), pos.y(), self._pane.width(), self._pane.height())

    def enter(self, event, origin: QWidget | None = None) -> bool:
        if not event.mimeData().hasFormat(PANE_MIME_TYPE):
            return False
        if self._foreign_source(event) is None:
            event.ignore()
            return True
        event.setDropAction(Qt.DropAction.MoveAction)
        event.accept()
        self.overlay.setGeometry(self._pane.rect())
        self.overlay.set_zone(self._zone(event, origin))
        self.overlay.show()
        self.overlay.raise_()
        return True

    def move(self, event, origin: QWidget | None = None) -> bool:
        if not event.mimeData().hasFormat(PANE_MIME_TYPE):
            return False
        if self._foreign_source(event) is None:
            event.ignore()
            return True
        self.overlay.setGeometry(self._pane.rect())
        self.overlay.set_zone(self._zone(event, origin))
        event.setDropAction(Qt.DropAction.MoveAction)
        event.accept()
        return True

    def leave(self) -> None:
        self.overlay.hide()

    def drop(self, event, origin: QWidget | None = None) -> tuple[str, str] | None:
        """``(source pane id, zone)`` for a pane drop the window should
        carry out (the event is accepted), else None. None too for a
        drag that is not a pane drag: ``event.mimeData()`` tells them apart."""
        self.overlay.hide()
        if not event.mimeData().hasFormat(PANE_MIME_TYPE):
            return None
        source_id = self._foreign_source(event)
        if source_id is None:
            event.ignore()
            return None
        zone = self._zone(event, origin)
        event.acceptProposedAction()
        return source_id, zone
