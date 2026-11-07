"""The map of the Bluetooth devices nearby, and a device's signal graph.

:class:`NearbyMap` is the Bluetooth panel's *Map* tab: this computer in
the middle, every device with a signal around it at its estimated
distance (core.bluetooth.estimate_distance - log-distance path loss from
the signal and the advertised transmit power). Bluetooth does not tell a
direction, so a device's angle is only its place on the map: fixed per
address, so it stays where it is between scans. Rings mark 1, 3, 10 and
30 m on a logarithmic scale (near devices spread out, far ones bunch at
the edge). Colour says the radio (Classic, BLE, both), a filled dot a
paired device, a ring around it a connected one. A click selects the
device in the list, a double-click opens its details.

Painting is cheap enough for hundreds of devices: the rings are a cached
pixmap, labels go to the nearest few, and dots glide to new positions
with a timer that runs only while one is moving.

:class:`SignalGraph` draws a device's recent signal readings (the
details dialog).
"""

from __future__ import annotations

import math
import zlib
from dataclasses import dataclass

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import QSizePolicy, QToolTip, QWidget

from core import bluetooth as BT
from core.i18n import tr
from ui.plain_text import plain_tooltip

#: Rings (metres) and the distance at the map's edge.
RINGS = (1.0, 3.0, 10.0, 30.0)
EDGE_DISTANCE = 40.0
#: Names written next to the nearest this many devices (and the selected
#: and hovered one); the rest only on hover.
LABELLED = 12
#: Dot radius (px) and how near a click must be to hit one.
DOT = 5.0
HIT = 9.0
#: Gliding: a frame every this many ms, a dot covers this share of the
#: remaining way per frame and stops when nearer than SETTLED px.
FRAME_MS = 33
EASE = 0.25
SETTLED = 0.5
#: Radio -> colour (readable on light and dark backgrounds).
COLOURS = {"Classic": QColor(52, 120, 246), "LE": QColor(22, 163, 74),
           "Dual": QColor(147, 51, 234), "": QColor(120, 120, 120)}


def angle_of(address: str) -> float:
    """A fixed angle (radians) for *address*: its place on the map."""
    return (zlib.crc32(address.upper().encode()) % 3600) / 3600 * 2 * math.pi


def radius_of(distance: float, outer: float) -> float:
    """Pixels from the centre for *distance* metres on a map of radius
    *outer*: logarithmic, 0 m in the centre, EDGE_DISTANCE at the edge."""
    distance = min(max(distance, 0.0), EDGE_DISTANCE)
    return outer * math.log10(1 + distance) / math.log10(1 + EDGE_DISTANCE)


@dataclass
class Dot:
    path: str
    device: BT.Device
    target: QPointF
    at: QPointF


class NearbyMap(QWidget):
    #: a device was clicked (its path)
    device_clicked = pyqtSignal(str)
    #: a device was double-clicked (its path)
    device_activated = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumSize(220, 220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._dots: dict[str, Dot] = {}
        #: devices known but without a signal (not on the map)
        self.unplaced = 0
        self.selected: str | None = None
        self._hover: str | None = None
        self._background: QPixmap | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(FRAME_MS)
        self._timer.timeout.connect(self._step)
        #: frames painted / glide steps run (for the tests: the timer stops)
        self.frames = 0
        self.steps = 0

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(420, 420)

    # -- geometry ---------------------------------------------------------------------------

    def _margins(self) -> tuple[float, float]:
        """Room above the rings (the note, two lines) and below (the legend)."""
        line = self.fontMetrics().height()
        return 2 * line + 8, line + 10

    def _centre(self) -> QPointF:
        top, bottom = self._margins()
        return QPointF(self.width() / 2, top + max(0.0, self.height() - top - bottom) / 2)

    def _outer(self) -> float:
        top, bottom = self._margins()
        return max(10.0, min(self.width(), self.height() - top - bottom) / 2 - 12)

    def _target(self, device: BT.Device) -> QPointF:
        r = radius_of(device.distance or EDGE_DISTANCE, self._outer())
        a = angle_of(device.address or device.path)
        c = self._centre()
        return QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a))

    # -- data -------------------------------------------------------------------------------

    def set_devices(self, devices) -> None:
        """Put *devices* on the map (those with a signal); new ones appear
        at their place, known ones glide there."""
        placed = {d.path: d for d in devices if d.distance is not None}
        self.unplaced = sum(1 for d in devices if d.distance is None)
        for path in list(self._dots):
            if path not in placed:
                del self._dots[path]
        for path, device in placed.items():
            self._place(device)
        self._kick()
        self.update()

    def update_device(self, device: BT.Device | None, path: str) -> None:
        """One device changed: it glides to its new distance (or leaves the
        map when it has no signal any more)."""
        if device is None or device.distance is None:
            if self._dots.pop(path, None) is not None:
                if device is not None:  # still known, only without a signal now
                    self.unplaced += 1
                self.update()
            return
        if path not in self._dots:
            self.unplaced = max(0, self.unplaced - 1)
        self._place(device)
        self._kick()
        self.update()

    def _place(self, device: BT.Device) -> None:
        target = self._target(device)
        dot = self._dots.get(device.path)
        if dot is None:
            self._dots[device.path] = Dot(device.path, device, target, QPointF(target))
        else:
            dot.device = device
            dot.target = target

    def set_selected(self, path: str | None) -> None:
        if path != self.selected:
            self.selected = path
            self.update()

    def paths(self) -> list[str]:
        return list(self._dots)

    def position(self, path: str) -> QPointF | None:
        dot = self._dots.get(path)
        return QPointF(dot.at) if dot is not None else None

    def moving(self) -> bool:
        return self._timer.isActive()

    # -- gliding ----------------------------------------------------------------------------

    def _kick(self) -> None:
        if not self._timer.isActive() and any(self._far(d) for d in self._dots.values()):
            self._timer.start()

    @staticmethod
    def _far(dot: Dot) -> bool:
        return abs(dot.at.x() - dot.target.x()) > SETTLED or \
            abs(dot.at.y() - dot.target.y()) > SETTLED

    def _step(self) -> None:
        self.steps += 1
        moving = False
        for dot in self._dots.values():
            if self._far(dot):
                dot.at = QPointF(dot.at.x() + (dot.target.x() - dot.at.x()) * EASE,
                                 dot.at.y() + (dot.target.y() - dot.at.y()) * EASE)
                moving = True
            else:
                dot.at = QPointF(dot.target)
        if not moving:
            self._timer.stop()
        self.update()

    def settle(self) -> None:
        """Every dot at its place at once (tests, a resize)."""
        for dot in self._dots.values():
            dot.at = QPointF(dot.target)
        self._timer.stop()
        self.update()

    # -- events -----------------------------------------------------------------------------

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._background = None
        for dot in self._dots.values():
            dot.target = self._target(dot.device)
        self.settle()

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().changeEvent(event)
        self._background = None  # palette or font: the rings again

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().hideEvent(event)
        self.settle()  # nothing glides unseen

    def dot_at(self, pos: QPointF) -> str | None:
        best, best_d = None, HIT
        for dot in self._dots.values():
            d = math.hypot(dot.at.x() - pos.x(), dot.at.y() - pos.y())
            if d <= best_d:
                best, best_d = dot.path, d
        return best

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        path = self.dot_at(event.position())
        if path != self._hover:
            self._hover = path
            self.update()
        if path is not None:
            QToolTip.showText(event.globalPosition().toPoint(), self.tooltip_markup(path), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._hover is not None:
            self._hover = None
            self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            path = self.dot_at(event.position())
            if path is not None:
                self.set_selected(path)
                self.device_clicked.emit(path)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 - Qt override
        path = self.dot_at(event.position())
        if path is not None:
            self.device_activated.emit(path)
        super().mouseDoubleClickEvent(event)

    def tooltip(self, path: str) -> str:
        dot = self._dots.get(path)
        if dot is None:
            return ""
        d = dot.device
        lines = [d.display_name, d.address, tr(d.kind)]
        if d.rssi is not None:
            lines.append(tr("Signal: {dbm} dBm, about {distance}").format(
                dbm=d.rssi, distance=BT.distance_text(d.distance)))
        if d.vendor:
            lines.append(d.vendor)
        return "\n".join(lines)

    def tooltip_markup(self, path: str) -> str:
        """:meth:`tooltip` as shown: Qt takes a tooltip that looks like
        markup for rich text, and its first line is the name the device
        chose - so it is escaped."""
        text = self.tooltip(path)
        return plain_tooltip(text)

    # -- painting ---------------------------------------------------------------------------

    def _paint_background(self) -> QPixmap:
        ratio = self.devicePixelRatioF()
        pix = QPixmap(int(self.width() * ratio), int(self.height() * ratio))
        pix.setDevicePixelRatio(ratio)
        pix.fill(self.palette().base().color())
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c, outer = self._centre(), self._outer()
        line = QColor(self.palette().text().color())
        line.setAlpha(60)
        text = QColor(self.palette().text().color())
        text.setAlpha(140)
        small = QFont(self.font())
        small.setPointSizeF(max(6.0, small.pointSizeF() * 0.85))
        p.setFont(small)
        for metres in RINGS:
            r = radius_of(metres, outer)
            p.setPen(QPen(line, 1, Qt.PenStyle.DashLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(c, r, r)
            p.setPen(text)
            p.drawText(QPointF(c.x() + 3, c.y() - r - 2), f"{metres:g} m")
        p.setPen(QPen(line, 1))
        p.drawEllipse(c, outer, outer)
        # this computer
        p.setBrush(self.palette().text().color())
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(c, 4, 4)
        p.end()
        return pix

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.frames += 1
        if self._background is None or self._background.size() != \
                self.size() * self.devicePixelRatioF():
            self._background = self._paint_background()
        p = QPainter(self)
        p.drawPixmap(0, 0, self._background)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        text = self.palette().text().color()
        # the nearest named ones get a label (a nameless beacon's address is noise
        # on the map: hover shows it); far ones are drawn first, near ones on top
        ordered = sorted(self._dots.values(), key=lambda d: d.device.distance or EDGE_DISTANCE)
        named = [d.path for d in ordered if d.device.named or d.device.paired]
        labelled = set(named[:LABELLED]) | {self.selected, self._hover}
        for dot in reversed(ordered):
            colour = COLOURS.get(dot.device.bearer, COLOURS[""])
            fill = QColor(colour)
            if not (dot.device.paired or dot.device.connected):
                fill.setAlpha(70)
            p.setPen(QPen(colour, 1.5))
            p.setBrush(fill)
            p.drawEllipse(dot.at, DOT, DOT)
            if dot.device.connected:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(dot.at, DOT + 3, DOT + 3)
            if dot.path in (self.selected, self._hover):
                p.setPen(QPen(text, 2))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(dot.at, DOT + 6, DOT + 6)
        p.setPen(text)
        for dot, rect in self._label_places(ordered, labelled, p.fontMetrics()):
            p.drawText(rect, int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                       dot.device.display_name)
        self._paint_legend(p)
        p.end()

    def _label_places(self, ordered, labelled, metrics) -> list[tuple[Dot, QRectF]]:
        """Where the labels go: right of the dot, else left of it, never over
        another label; one that fits nowhere is left out - unless it is the
        selected or hovered device, which is always named (drawn last, on top)."""
        placed: list[tuple[Dot, QRectF]] = []
        must = []
        for dot in ordered:
            if dot.path not in labelled:
                continue
            width = metrics.horizontalAdvance(dot.device.display_name) + 2
            height = metrics.height()
            y = dot.at.y() - height / 2
            right = QRectF(dot.at.x() + DOT + 4, y, width, height)
            left = QRectF(dot.at.x() - DOT - 4 - width, y, width, height)
            spot = next((r for r in (right, left)
                         if not any(r.intersects(other) for _d, other in placed)), None)
            if spot is not None:
                placed.append((dot, spot))
            elif dot.path in (self.selected, self._hover):
                must.append((dot, right))
        return placed + must

    def _paint_legend(self, p: QPainter) -> None:
        metrics = p.fontMetrics()
        y = self.height() - 6
        x = 8.0
        for radio, label in (("Classic", "Classic"), ("LE", "BLE"), ("Dual", "Classic + BLE"),
                             ("", "Radio unknown")):
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(COLOURS[radio])
            p.drawEllipse(QPointF(x + 4, y - metrics.ascent() / 2 + 1), 4, 4)
            p.setPen(self.palette().text().color())
            text = tr(label)
            p.drawText(QPointF(x + 11, y), text)
            x += 11 + metrics.horizontalAdvance(text) + 12
        note = tr("Distance estimated from the signal; direction is not measured.")
        if self.unplaced:
            note = tr("{n} without a signal not shown. ").format(n=self.unplaced) + note
        p.drawText(QRectF(8, 4, self.width() - 16, metrics.height() * 2 + 4),
                   int(Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap), note)


class SignalGraph(QWidget):
    """A device's recent signal readings as a line (-100 dBm at the
    bottom, -30 at the top), the newest at the right."""

    LOW, HIGH = -100, -30

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.readings: list[tuple[float, int]] = []
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(240, 56)

    def one_reading_text(self) -> str:
        """What the graph says while it has a single reading."""
        return tr("{dbm} dBm - one reading so far; more come while it is heard").format(
            dbm=self.readings[-1][1])

    def set_readings(self, readings) -> None:
        readings = list(readings)
        if readings != self.readings:
            self.readings = readings
            self.update()

    def points(self) -> list[QPointF]:
        """Where the readings are drawn (oldest first)."""
        n = len(self.readings)
        if n == 0:
            return []
        w, h = max(1, self.width() - 4), max(1, self.height() - 4)
        span = self.HIGH - self.LOW
        out = []
        for i, (_t, dbm) in enumerate(self.readings):
            x = 2 + (w * i / (n - 1) if n > 1 else w)
            level = (min(max(dbm, self.LOW), self.HIGH) - self.LOW) / span
            out.append(QPointF(x, 2 + h * (1 - level)))
        return out

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.fillRect(self.rect(), self.palette().base())
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        points = self.points()
        if not points:
            p.setPen(self.palette().placeholderText().color())
            p.drawText(self.rect(), int(Qt.AlignmentFlag.AlignCenter),
                       tr("No signal readings - scan to see them."))
            p.end()
            return
        if len(points) == 1:
            # One reading draws no line: its level across, the dot and the
            # value - not a box that looked empty.
            level = points[0].y()
            p.setPen(QPen(self.palette().highlight().color(), 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(2, level), QPointF(self.width() - 2, level))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(self.palette().highlight())
            p.drawEllipse(QPointF(self.width() / 2, level), 3, 3)
            p.setPen(self.palette().text().color())
            p.drawText(self.rect().adjusted(4, 2, -4, -2),
                       int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop),
                       self.one_reading_text())
            p.end()
            return
        path = QPainterPath(points[0])
        for point in points[1:]:
            path.lineTo(point)
        p.setPen(QPen(self.palette().highlight().color(), 1.5))
        p.drawPath(path)
        p.setBrush(self.palette().highlight())
        p.drawEllipse(points[-1], 2.5, 2.5)
        p.end()


__all__ = ["NearbyMap", "SignalGraph", "angle_of", "radius_of"]
