"""The Agent dock's connection lamp: a coloured dot in its title bar.

Green: the LLM answered the last request; orange: a check or a request is
on its way; red: not connected (core.agent_link has the states and what
counts as evidence). The colours are mid-tone, with a ring in the
palette's text colour, so the dot reads on light and dark themes alike;
the state is also in the tooltip and the accessible name. A click asks
for a new check.
"""

from __future__ import annotations

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QPainter, QPalette, QPen
from PyQt6.QtWidgets import QToolButton

from core import agent_link as L
from core.i18n import tr

#: Mid-tone colours: at least 2:1 against white and against a dark theme.
COLOURS = {L.ONLINE: "#2e9d4f", L.TRYING: "#e08a00", L.OFFLINE: "#d63c32"}
NAMES = {L.ONLINE: "LLM connected", L.TRYING: "Connecting to the LLM",
         L.OFFLINE: "LLM not connected"}
DOT = 10


class LinkLamp(QToolButton):
    """A dot in one of three colours; clicked: check again."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.state = L.OFFLINE
        self.setAutoRaise(True)
        self.setFixedSize(QSize(22, 22))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_state(L.OFFLINE, tr("Not connected to the LLM"))

    def colour(self) -> QColor:
        return QColor(COLOURS[self.state])

    def set_state(self, state: str, tooltip: str) -> None:
        self.state = state if state in COLOURS else L.OFFLINE
        self.setToolTip(tooltip)
        self.setAccessibleName(tr(NAMES[self.state]))
        self.setAccessibleDescription(tooltip)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().paintEvent(event)  # the hover frame of an auto-raise button
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        ring = QColor(self.palette().color(QPalette.ColorRole.WindowText))
        ring.setAlpha(110)
        painter.setPen(QPen(ring, 1.0))
        painter.setBrush(self.colour())
        x = (self.width() - DOT) / 2
        y = (self.height() - DOT) / 2
        painter.drawEllipse(QRectF(x, y, DOT, DOT))
        painter.end()
