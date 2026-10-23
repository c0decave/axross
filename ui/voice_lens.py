"""A camera lens drawn with QPainter over the Agent dock's conversation:
a dark bezel, a red glowing eye whose glow follows the sound level, a small
highlight. Shown while one fixed line is spoken, then it fades out. Own
artwork only."""

from __future__ import annotations

from PyQt6.QtCore import QPointF, Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import QWidget


class LensOverlay(QWidget):
    FADE_STEP = 0.08

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.caption = ""
        self._level = 0.0
        self._shown_level = 0.0
        self._alpha = 0.0
        self._fading = False
        self._timer = QTimer(self)
        self._timer.setInterval(30)
        self._timer.timeout.connect(self._tick)
        self.hide()

    @property
    def alpha(self) -> float:
        return self._alpha

    def start(self, caption: str = "") -> None:
        self.caption = caption
        self._fading = False
        self._alpha = 1.0
        self._level = self._shown_level = 0.0
        self.cover()
        self.show()
        self.raise_()
        self._timer.start()

    def cover(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())

    def set_level(self, value: float) -> None:
        self._level = max(0.0, min(1.0, float(value)))

    def finish(self) -> None:
        """Fade out, then hide."""
        if not self.isHidden():
            self._fading = True
            self._timer.start()

    def _tick(self) -> None:
        # The glow eases toward the level: a pulse, not a flicker.
        self._shown_level += (self._level - self._shown_level) * 0.35
        if self._fading:
            self._alpha = max(0.0, self._alpha - self.FADE_STEP)
            if self._alpha <= 0.0:
                self._timer.stop()
                self._fading = False
                self.hide()
                return
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(self._alpha)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 170))
        side = min(self.width(), self.height())
        radius = side * 0.28
        center = QPointF(self.width() / 2, self.height() / 2 - (side * 0.05 if self.caption else 0))
        # Bezel: brushed metal ring around a black housing.
        ring = QRadialGradient(center, radius * 1.35)
        ring.setColorAt(0.70, QColor(70, 70, 76))
        ring.setColorAt(0.86, QColor(190, 190, 198))
        ring.setColorAt(1.00, QColor(40, 40, 44))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(ring))
        painter.drawEllipse(center, radius * 1.35, radius * 1.35)
        painter.setBrush(QColor(8, 8, 10))
        painter.drawEllipse(center, radius * 1.08, radius * 1.08)
        # The eye: a red glow, brighter and wider with the level.
        glow = 0.55 + 0.45 * self._shown_level
        eye = QRadialGradient(center, radius)
        eye.setColorAt(0.0, QColor(255, int(210 * glow), int(120 * glow)))
        eye.setColorAt(0.12, QColor(255, int(60 + 120 * glow), 30))
        eye.setColorAt(0.45, QColor(int(150 + 105 * glow), 0, 0))
        eye.setColorAt(1.0, QColor(25, 0, 0))
        painter.setBrush(QBrush(eye))
        painter.drawEllipse(center, radius, radius)
        # A cool reflection of the room on the glass.
        painter.setBrush(QColor(255, 255, 255, 60))
        painter.drawEllipse(QPointF(center.x() - radius * 0.38, center.y() - radius * 0.42),
                            radius * 0.16, radius * 0.10)
        if self.caption:
            painter.setPen(QPen(QColor(235, 235, 235)))
            font = painter.font()
            font.setPointSizeF(max(9.0, side / 28))
            painter.setFont(font)
            box = self.rect().adjusted(12, int(center.y() + radius * 1.45), -12, -8)
            painter.drawText(box, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop
                             | Qt.TextFlag.TextWordWrap, self.caption)
        painter.end()
