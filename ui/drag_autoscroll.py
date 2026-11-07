"""A drag over a pane scrolls it near the top or bottom edge.

Reported: dragging within a pane, a target folder out of sight could not be
reached. Qt's item views scroll near their edge during a drag, but in their
own ``dragMoveEvent`` - which the pane's views replace (the pane decides
the drop). This puts the scrolling back: the top and bottom tenth of the
viewport (at least a row's height) scroll while the cursor stays there,
faster the closer it is to the edge.
"""

from __future__ import annotations

from PyQt6.QtCore import QObject, QPoint, QTimer

#: Share of the viewport's height, top and bottom, that scrolls.
EDGE_SHARE = 0.10
#: The band is at least this many pixels (a short pane).
MIN_EDGE_PX = 16
#: Milliseconds between two scroll steps.
INTERVAL_MS = 40
#: Scroll bar steps per tick at the very edge (fewer further in).
MAX_STEPS = 6


class DragAutoScroll(QObject):
    """Scrolls *view* (a QAbstractScrollArea) while a drag hovers an edge.
    Call :meth:`move` from dragMoveEvent and :meth:`stop` from
    dragLeaveEvent and dropEvent."""

    def __init__(self, view) -> None:
        super().__init__(view)
        self._view = view
        self._direction = 0
        self._steps = 0
        self._timer = QTimer(self)
        self._timer.setInterval(INTERVAL_MS)
        self._timer.timeout.connect(self._tick)

    def zone(self, pos: QPoint) -> tuple[int, int]:
        """``(direction, steps)`` for the viewport position *pos*: -1 up,
        1 down, 0 not in an edge band."""
        height = self._view.viewport().height()
        band = max(MIN_EDGE_PX, int(height * EDGE_SHARE))
        if height <= 2 * band:
            band = max(1, height // 4)
        y = pos.y()
        if y < band:
            depth = band - max(y, 0)
            return -1, max(1, round(MAX_STEPS * depth / band))
        if y > height - band:
            depth = min(y, height) - (height - band)
            return 1, max(1, round(MAX_STEPS * depth / band))
        return 0, 0

    def move(self, pos: QPoint) -> None:
        self._direction, self._steps = self.zone(pos)
        if self._direction and not self._timer.isActive():
            self._timer.start()
        elif not self._direction:
            self._timer.stop()

    def stop(self) -> None:
        self._direction = 0
        self._timer.stop()

    @property
    def active(self) -> bool:
        return self._timer.isActive()

    def _tick(self) -> None:
        bar = self._view.verticalScrollBar()
        if not self._direction or bar is None:
            self._timer.stop()
            return
        before = bar.value()
        bar.setValue(before + self._direction * self._steps * max(1, bar.singleStep()))
        if bar.value() == before:  # at the end: nothing more to scroll
            self._timer.stop()


__all__ = ["DragAutoScroll", "EDGE_SHARE"]
