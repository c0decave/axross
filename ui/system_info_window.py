"""The System Information window: everything :mod:`core.system_info` finds
about this machine, as an overview dashboard and one page per area.

* **Overview** - a header card (computer name, maker and model, OS) and
  tiles: rings for CPU load, memory, swap, the root file system and the
  battery, the hottest sensors on a colour scale, graphics, network and
  the platform (bare metal, VM, container); CPU and memory have sparklines.
* **Pages** - CPU (per-core bars, caches, feature chips), Memory, Storage
  (a bar per disk with its partitions and mount points), Graphics &
  Displays (a sketch of the screens), Network, Audio, USB & Peripherals
  and PCI (trees), Battery & Power, Sensors, System & OS, Virtualisation.
* A search field filters every page at once; Copy Section, Copy All and
  Save Report… (text or JSON) export what is shown. Serial numbers, MAC
  and IP addresses and UUIDs are hidden unless *Show identifiers* is on.

Nothing here blocks: the report is gathered on a worker thread (the status
line counts the sources), the live values (CPU, memory, temperatures,
network) are sampled on another one once a second while the window is on
screen, and both report through :class:`core.thread_relay.GuiCall` - the
GUI thread only copies numbers into widgets.
"""

from __future__ import annotations

import collections
import datetime as _dt
import logging
import re
import threading
import weakref
from pathlib import Path

from PyQt6 import sip
from PyQt6.QtCore import QByteArray, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QGuiApplication,
    QIcon,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
    QShortcut,
)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QStyledItemDelegate,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from core import system_info as SI
from core.i18n import tr
from core.thread_relay import GuiCall
from ui.plain_text import plain_tooltip, set_plain
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: Name of the window in session.json (ui.viewer_window).
STATE_NAME = "system_info"
#: Seconds between two live samples.
LIVE_INTERVAL = 1.0
#: Live samples a sparkline keeps (two minutes at one per second).
HISTORY = 120

#: (page key, title, icon, sections shown on it).
PAGES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("overview", "Overview", "overview", ("machine", "os")),
    ("cpu", "CPU", "cpu", ("cpu",)),
    ("memory", "Memory", "memory", ("memory",)),
    ("storage", "Storage", "storage", ("storage",)),
    ("graphics", "Graphics & Displays", "display", ("graphics", "screens")),
    ("network", "Network", "network", ("network", "bluetooth")),
    ("audio", "Audio", "audio", ("audio",)),
    ("usb", "USB & Peripherals", "usb", ("usb", "input")),
    ("pci", "PCI", "pci", ("pci",)),
    ("battery", "Battery & Power", "battery", ("battery",)),
    ("sensors", "Sensors", "sensors", ("sensors",)),
    ("system", "System & OS", "system", ("machine", "os")),
    ("virtualization", "Virtualisation", "layers", ("virtualization",)),
)

# Status colours (fixed in both themes; never the only carrier of meaning -
# every mark has its number or word beside it).
GOOD = "#0ca30c"
WARNING = "#e09a00"
SERIOUS = "#ec835a"
CRITICAL = "#d03b3b"
SERIES_LIGHT = ("#2a78d6", "#eb6834")
SERIES_DARK = ("#3987e5", "#d95926")


# --------------------------------------------------------------------------- colours


def is_dark(palette: QPalette) -> bool:
    return palette.color(QPalette.ColorRole.Window).lightness() < 128


def series(widget: QWidget, index: int = 0) -> QColor:
    return QColor((SERIES_DARK if is_dark(widget.palette()) else SERIES_LIGHT)[index])


def level_colour(pct: float | None, warn: float = 75, crit: float = 90) -> QColor:
    """Green, amber or red for a use in percent."""
    if pct is None:
        return QColor("#888888")
    if pct >= crit:
        return QColor(CRITICAL)
    if pct >= warn:
        return QColor(WARNING)
    return QColor(GOOD)


def temp_colour(value: float | None, high: float | None = None,
                crit: float | None = None) -> QColor:
    """Colour of a temperature: up to 60 °C green, then amber, from 80 °C
    (or the sensor's own high mark) orange, from 90 °C (or critical) red."""
    if value is None:
        return QColor("#888888")
    red = min(crit or 95, 95) if crit else 90
    hot = min(high, red) if high and high > 40 else 80
    if value >= red:
        return QColor(CRITICAL)
    if value >= hot:
        return QColor(SERIOUS)
    if value >= 60:
        return QColor(WARNING)
    return QColor(GOOD)


def battery_colour(pct: float | None) -> QColor:
    if pct is None:
        return QColor("#888888")
    if pct <= 10:
        return QColor(CRITICAL)
    if pct <= 25:
        return QColor(WARNING)
    return QColor(GOOD)


def muted(widget: QWidget) -> QColor:
    pal = widget.palette()
    text = pal.color(QPalette.ColorRole.Text)
    base = pal.color(QPalette.ColorRole.Base)
    return _mix(text, base, 0.42)


def track(widget: QWidget) -> QColor:
    pal = widget.palette()
    return _mix(pal.color(QPalette.ColorRole.Text), pal.color(QPalette.ColorRole.Base), 0.86)


def card_colour(widget: QWidget) -> QColor:
    pal = widget.palette()
    base, window = pal.color(QPalette.ColorRole.Base), pal.color(QPalette.ColorRole.Window)
    return _mix(base, window, 0.35)


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    """*a* moved the share *t* towards *b*."""
    return QColor(round(a.red() + (b.red() - a.red()) * t),
                  round(a.green() + (b.green() - a.green()) * t),
                  round(a.blue() + (b.blue() - a.blue()) * t))


def scaled_font(widget: QWidget, factor: float, bold: bool = False) -> QFont:
    font = QFont(widget.font())
    size = font.pointSizeF()
    if size > 0:
        font.setPointSizeF(max(6.0, size * factor))
    else:
        font.setPixelSize(max(8, round(font.pixelSize() * factor)))
    font.setBold(bold)
    return font


# --------------------------------------------------------------------------- icons

_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        'stroke="{c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{b}</svg>')
ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" '
                'height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>'
                '<rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "cpu": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" '
           'height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "memory": '<rect x="2" y="7" width="20" height="10" rx="1.5"/><path d="M6 10v4M10 10v4M14 '
              '10v4M18 10v4M5 17v3M19 17v3"/>',
    "storage": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 14h18"/>'
               '<circle cx="17" cy="17" r="0.8"/><path d="M7 17h5"/>',
    "display": '<rect x="2" y="4" width="20" height="13" rx="1.5"/><path d="M8 21h8M12 17v4"/>',
    "network": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 '
               '14 0 0 0 0 18"/>',
    "audio": '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.5 8.5a5 5 0 0 1 '
             '0 7M18.5 5.5a9 9 0 0 1 0 13"/>',
    "usb": '<path d="M12 2v14M8 6l4-4 4 4M7 10v3l5 3 5-3v-3"/><circle cx="12" cy="19" r="2.5"/>'
           '<rect x="5.5" y="8" width="3" height="2"/><circle cx="17" cy="9" r="1.2"/>',
    "pci": '<rect x="2" y="5" width="20" height="11" rx="1.5"/><path d="M5 16v3M8 16v3M11 16v3M14 '
           '16v3M17 16v3"/><rect x="6" y="8" width="6" height="5"/>',
    "battery": '<rect x="2" y="7" width="17" height="10" rx="2"/><path d="M22 11v2"/>'
               '<path d="M10 9l-2 3h4l-2 3"/>',
    "sensors": '<path d="M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0z"/><path d="M12 9v7"/>',
    "system": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/>'
              '<polyline points="2 12 12 17 22 12"/>',
    "laptop": '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
    "desktop": '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
    "server": '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" '
              'height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
    "vm": '<rect x="2" y="3" width="20" height="14" rx="1.5"/><rect x="6" y="6" width="12" '
          'height="8" rx="1"/><path d="M8 21h8"/>',
}
_ICON_CACHE: dict[tuple[str, str, int], QIcon] = {}


def glyph(name: str, colour: QColor | str, size: int = 20) -> QIcon:
    """One of :data:`ICONS` in *colour*."""
    hex_colour = QColor(colour).name()
    key = (name, hex_colour, size)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached
    svg = _SVG.format(c=hex_colour, b=ICONS.get(name, ICONS["overview"]))
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    icon = QIcon()
    for scale in (1, 2):
        pix = QPixmap(size * scale, size * scale)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        renderer.render(painter)
        painter.end()
        pix.setDevicePixelRatio(scale)
        icon.addPixmap(pix)
    _ICON_CACHE[key] = icon
    return icon


# --------------------------------------------------------------------------- painted widgets


class Card(QWidget):
    """A rounded panel in the theme's colours."""

    clicked = pyqtSignal()

    def __init__(self, parent: QWidget | None = None, *, clickable: bool = False) -> None:
        super().__init__(parent)
        self._clickable = clickable
        self._hover = False
        if clickable:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        border = muted(self) if self._hover else track(self)
        p.setPen(QPen(border, 1))
        p.setBrush(card_colour(self))
        p.drawRoundedRect(rect, 10, 10)

    def enterEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._clickable:
            self._hover = True
            self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._clickable and event.button() == Qt.MouseButton.LeftButton \
                and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class RingGauge(QWidget):
    """A ring filled to a percentage, the number in the middle."""

    def __init__(self, diameter: int = 92, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.value: float | None = None
        self.text = "–"
        self.caption = ""
        self.colour = QColor("#888888")
        self.setFixedSize(diameter, diameter)

    def set_value(self, value: float | None, text: str | None = None, *,
                  caption: str = "", colour: QColor | None = None) -> None:
        self.value = None if value is None else max(0.0, min(100.0, float(value)))
        self.text = text if text is not None else SI.percent(value)
        self.caption = caption
        self.colour = colour or level_colour(value)
        self.setToolTip(plain_tooltip(f"{caption} {self.text}".strip()))
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height())
        width = max(6.0, side * 0.1)
        rect = QRectF(width / 2 + 1, width / 2 + 1, side - width - 2, side - width - 2)
        pen = QPen(track(self), width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 0, 360 * 16)
        if self.value is not None and self.value > 0:
            pen.setColor(self.colour)
            p.setPen(pen)
            p.drawArc(rect, 90 * 16, -round(360 * 16 * self.value / 100))
        p.setPen(self.palette().color(QPalette.ColorRole.Text))
        p.setFont(scaled_font(self, 1.35 if len(self.text) <= 5 else 1.0, bold=True))
        text_rect = QRectF(rect)
        if self.caption:
            text_rect.adjust(0, -side * 0.08, 0, -side * 0.08)
        p.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, self.text)
        if self.caption:
            p.setPen(muted(self))
            p.setFont(scaled_font(self, 0.8))
            p.drawText(QRectF(rect).adjusted(0, side * 0.22, 0, side * 0.22),
                       Qt.AlignmentFlag.AlignCenter, self.caption)


class Sparkline(QWidget):
    """The last values (0-100) as a line with a light area under it."""

    def __init__(self, values: collections.deque, colour_index: int = 0,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.values = values
        self.colour_index = colour_index
        self.setMinimumHeight(34)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(160, 38)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(QPen(track(self), 1))
        p.drawLine(QPointF(0, h - 1), QPointF(w, h - 1))
        values = [v for v in self.values if v is not None]
        if len(values) < 2:
            p.setPen(muted(self))
            p.setFont(scaled_font(self, 0.85))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "collecting…")
            return
        step = w / (HISTORY - 1)
        x0 = w - step * (len(values) - 1)
        path = QPainterPath()
        for i, v in enumerate(values):
            pt = QPointF(x0 + i * step, (h - 3) - (h - 6) * max(0.0, min(100.0, v)) / 100)
            if i == 0:
                path.moveTo(pt)
            else:
                path.lineTo(pt)
        colour = series(self, self.colour_index)
        area = QPainterPath(path)
        area.lineTo(QPointF(w, h - 1))
        area.lineTo(QPointF(x0, h - 1))
        area.closeSubpath()
        fill = QColor(colour)
        fill.setAlpha(46)
        p.fillPath(area, fill)
        p.setPen(QPen(colour, 2))
        p.drawPath(path)


class UsageBar(QWidget):
    """A label left, a rounded bar, the number right."""

    def __init__(self, parent: QWidget | None = None, *, label_width: int = 0) -> None:
        super().__init__(parent)
        self.fraction: float | None = None
        self.label = ""
        self.value_text = ""
        self.colour = QColor(GOOD)
        self.label_width = label_width
        self.setMinimumHeight(22)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(220, max(22, self.fontMetrics().height() + 8))

    def set_value(self, fraction: float | None, label: str, value_text: str,
                  colour: QColor | None = None) -> None:
        self.fraction = None if fraction is None else max(0.0, min(1.0, fraction))
        self.label = label
        self.value_text = value_text
        self.colour = colour or level_colour(None if fraction is None else fraction * 100)
        self.setToolTip(plain_tooltip(f"{label}: {value_text}"))
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        fm = self.fontMetrics()
        h = self.height()
        text = self.palette().color(QPalette.ColorRole.Text)
        label_w = self.label_width or (fm.horizontalAdvance(self.label) + 10 if self.label else 0)
        value_w = max(fm.horizontalAdvance(self.value_text) + 10, 54)
        if self.label:
            p.setPen(text)
            p.drawText(QRectF(0, 0, label_w - 6, h), Qt.AlignmentFlag.AlignVCenter
                       | Qt.AlignmentFlag.AlignLeft,
                       fm.elidedText(self.label, Qt.TextElideMode.ElideMiddle, label_w - 6))
        bar = QRectF(label_w, h / 2 - 4, max(10, self.width() - label_w - value_w), 8)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track(self))
        p.drawRoundedRect(bar, 4, 4)
        if self.fraction:
            filled = QRectF(bar.x(), bar.y(), max(8.0, bar.width() * self.fraction), bar.height())
            p.setBrush(self.colour)
            p.drawRoundedRect(filled, 4, 4)
        p.setPen(text)
        p.drawText(QRectF(bar.right() + 8, 0, value_w - 8, h),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, self.value_text)


class CoreBars(QWidget):
    """One vertical bar per logical CPU, its use in percent."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.values: list[float | None] = []
        #: CPU number -> "P-core" / "E-core" / "".
        self.kinds: dict[int, str] = {}
        #: The CPU number of each value (offline CPUs are left out).
        self.ids: list[int] = []
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_values(self, values: list[float | None], kinds: dict[int, str] | None = None,
                   ids: list[int] | None = None) -> None:
        self.values = list(values)
        if kinds is not None:
            self.kinds = dict(kinds)
        if ids is not None and len(ids) == len(self.values):
            self.ids = list(ids)
        elif len(self.ids) != len(self.values):
            self.ids = list(range(len(self.values)))
        busy = [v for v in values if v is not None]
        self.setToolTip("\n".join(
            f"CPU {n}{' (' + self.kinds[n] + ')' if self.kinds.get(n) else ''}: {SI.percent(v)}"
            for n, v in zip(self.ids, values)) if busy else "")
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        n = len(self.values)
        fm = self.fontMetrics()
        if not n:
            p.setPen(muted(self))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, tr("Measuring CPU use…"))
            return
        label_h = fm.height() + 2
        h = self.height() - label_h - 4
        gap = 4 if n <= 32 else 2
        bar_w = min(44.0, max(3.0, (self.width() - gap * (n - 1)) / n))
        for i, v in enumerate(self.values):
            x = i * (bar_w + gap)
            rect = QRectF(x, 2, bar_w, h)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(track(self))
            p.drawRoundedRect(rect, 3, 3)
            if v:
                fill_h = max(3.0, h * v / 100)
                p.setBrush(level_colour(v, 80, 95) if v >= 80 else series(self))
                p.drawRoundedRect(QRectF(x, 2 + h - fill_h, bar_w, fill_h), 3, 3)
            if v is not None and bar_w >= fm.horizontalAdvance("100") + 4:
                p.setPen(self.palette().color(QPalette.ColorRole.Text))
                p.drawText(QRectF(x, 4, bar_w, fm.height()), Qt.AlignmentFlag.AlignHCenter,
                           f"{v:.0f}")
            if bar_w >= fm.horizontalAdvance("88") or i % 4 == 0:
                p.setPen(muted(self))
                n = self.ids[i] if i < len(self.ids) else i
                kind = self.kinds.get(n, "")
                p.drawText(QRectF(x - 6, h + 4, bar_w + 12, label_h),
                           Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                           f"{n}{kind[:1].lower() if kind else ''}")


class Chips(QWidget):
    """Feature names as rounded chips: present ones solid, missing ones faint."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.features: list[dict] = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def set_features(self, features: list[dict]) -> None:
        self.features = list(features)
        self.updateGeometry()
        self.update()

    def group_width(self) -> int:
        fm = self.fontMetrics()
        return max((fm.horizontalAdvance(f["group"]) for f in self.features), default=0) + 16

    @staticmethod
    def label(feature: dict) -> str:
        return ("✓ " if feature["present"] else "") + feature["name"]

    def _layout(self, width: int) -> list[tuple[QRectF, dict]]:
        """A row per group (its name left), chips wrapping within it; a
        group's name has an entry of its own with ``rect`` for the label."""
        fm = self.fontMetrics()
        indent = self.group_width()
        row_h = fm.height() + 10
        x, y = float(indent), -row_h - 6.0
        out: list[tuple[QRectF, dict]] = []
        last_group = None
        for f in self.features:
            w = fm.horizontalAdvance(self.label(f)) + 24
            if f["group"] != last_group:
                last_group = f["group"]
                x, y = float(indent), y + row_h + 6
                out.append((QRectF(0, y, indent - 8, row_h), {"group_label": f["group"]}))
            elif x + w > width and x > indent:
                x, y = float(indent), y + row_h + 6
            out.append((QRectF(x, y, w, row_h), f))
            x += w + 6
        return out

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt override
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802 - Qt override
        boxes = self._layout(width)
        return int(max((r.bottom() for r, _f in boxes), default=0)) + 2

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(400, self.heightForWidth(400))

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        accent = series(self)
        for rect, f in self._layout(self.width()):
            if "group_label" in f:
                p.setPen(muted(self))
                p.drawText(rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                           f["group_label"])
                continue
            if f["present"]:
                fill = QColor(accent)
                fill.setAlpha(40)
                p.setBrush(fill)
                p.setPen(QPen(accent, 1.2))
                colour = self.palette().color(QPalette.ColorRole.Text)
            else:
                p.setBrush(Qt.BrushStyle.NoBrush)
                pen = QPen(track(self), 1.2)
                pen.setStyle(Qt.PenStyle.DashLine)
                p.setPen(pen)
                colour = muted(self)
            p.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), rect.height() / 2,
                              rect.height() / 2)
            p.setPen(colour)
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label(f))


class PartitionBar(QWidget):
    """A disk as one bar: a segment per partition, as wide as its share,
    filled as far as its file system is used; below it a line per
    partition with its mount points, size and use."""

    BAR_H = 22

    def __init__(self, disk: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.disk = disk
        line = self.fontMetrics().height() + 4
        self.setFixedHeight(self.BAR_H + 8 + line * len(self.segments()))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def segments(self) -> list[dict]:
        disk = self.disk
        parts = disk.get("partitions") or []
        if not parts:
            usage = (disk.get("usage") or [None])[0]
            return [{"name": disk["name"], "size": disk["size"], "mounts": disk.get("mounts", []),
                     "percent": usage.get("percent") if usage else None}]
        out = []
        for part in parts:
            usage = (part.get("usage") or [None])[0]
            out.append({"name": part["name"], "size": part["size"], "mounts": part["mounts"],
                        "percent": usage.get("percent") if usage else None})
        return out

    def segment_colour(self, seg: dict) -> QColor:
        if seg["percent"] is not None:
            return level_colour(seg["percent"], 85, 95)
        return muted(self)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        fm = self.fontMetrics()
        total = max(1, self.disk.get("size") or 1)
        segs = self.segments()
        width = self.width() - 2
        bar_h = self.BAR_H
        widths = [max(6.0, width * s["size"] / total) for s in segs]
        scale = min(1.0, width / max(1.0, sum(widths) + 3 * (len(widths) - 1)))
        x = 1.0
        text = self.palette().color(QPalette.ColorRole.Text)
        for seg, w in zip(segs, widths):
            w *= scale
            rect = QRectF(x, 1, w, bar_h)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(track(self))
            p.drawRoundedRect(rect, 5, 5)
            if seg["percent"] is not None:
                used = QRectF(x, 1, max(4.0, w * seg["percent"] / 100), bar_h)
                p.setBrush(self.segment_colour(seg))
                p.drawRoundedRect(used, 5, 5)
            elif not seg["mounts"]:
                p.setBrush(QBrush(muted(self), Qt.BrushStyle.BDiagPattern))
                p.drawRoundedRect(rect, 5, 5)
            if w > fm.horizontalAdvance(seg["name"]) + 12:
                p.setPen(text if seg["percent"] is None else QColor("white"))
                p.drawText(rect.adjusted(6, 0, -4, 0), Qt.AlignmentFlag.AlignVCenter
                           | Qt.AlignmentFlag.AlignLeft, seg["name"])
            x += w + 3
        # The legend: a line per partition.
        line = fm.height() + 4
        y = bar_h + 8
        name_w = max(fm.horizontalAdvance(s["name"]) for s in segs) + 16
        mount_w = min(320, max(fm.horizontalAdvance(", ".join(s["mounts"]) or "not mounted")
                               for s in segs) + 20)
        for seg in segs:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(self.segment_colour(seg) if seg["mounts"] else track(self))
            p.drawRoundedRect(QRectF(1, y + line / 2 - 5, 10, 10), 2, 2)
            p.setPen(text)
            p.drawText(QRectF(18, y, name_w, line), Qt.AlignmentFlag.AlignVCenter, seg["name"])
            mounts = ", ".join(seg["mounts"]) or "not mounted"
            p.setPen(text if seg["mounts"] else muted(self))
            p.drawText(QRectF(18 + name_w, y, mount_w, line), Qt.AlignmentFlag.AlignVCenter,
                       fm.elidedText(mounts, Qt.TextElideMode.ElideMiddle, mount_w - 8))
            note = SI.human_bytes(seg["size"])
            if seg["percent"] is not None:
                note += f" · {SI.percent(seg['percent'])} used"
            p.setPen(muted(self))
            p.drawText(QRectF(18 + name_w + mount_w, y, width - name_w - mount_w, line),
                       Qt.AlignmentFlag.AlignVCenter, note)
            y += line


class DisplaySketch(QWidget):
    """The screens as rectangles in their arrangement (or side by side when
    the arrangement is unknown), each with its name and resolution."""

    def __init__(self, screens: list[dict], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.screens = screens
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.screens:
            p.setPen(muted(self))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, tr("No connected display found"))
            return
        left = min(s["x"] for s in self.screens)
        top = min(s["y"] for s in self.screens)
        right = max(s["x"] + s["w"] for s in self.screens)
        bottom = max(s["y"] + s["h"] for s in self.screens)
        span_w, span_h = max(1, right - left), max(1, bottom - top)
        scale = min((self.width() - 20) / span_w, (self.height() - 20) / span_h)
        off_x = (self.width() - span_w * scale) / 2
        off_y = (self.height() - span_h * scale) / 2
        fm = self.fontMetrics()
        accent = series(self)
        for s in self.screens:
            rect = QRectF(off_x + (s["x"] - left) * scale + 3, off_y + (s["y"] - top) * scale + 3,
                          s["w"] * scale - 6, s["h"] * scale - 6)
            fill = QColor(accent)
            fill.setAlpha(60 if s.get("primary") else 30)
            p.setBrush(fill)
            p.setPen(QPen(accent, 2 if s.get("primary") else 1.2))
            p.drawRoundedRect(rect, 6, 6)
            p.setPen(self.palette().color(QPalette.ColorRole.Text))
            lines = [s["name"], s.get("detail", "")]
            p.setFont(scaled_font(self, 1.0, bold=True))
            y = rect.center().y() - fm.height()
            p.drawText(QRectF(rect.x() + 4, y, rect.width() - 8, fm.height() + 2),
                       Qt.AlignmentFlag.AlignCenter,
                       fm.elidedText(lines[0], Qt.TextElideMode.ElideRight, int(rect.width() - 8)))
            p.setFont(self.font())
            for i, line in enumerate(lines[1].split("\n")):
                p.drawText(QRectF(rect.x() + 4, y + (i + 1) * (fm.height() + 1),
                                  rect.width() - 8, fm.height() + 2),
                           Qt.AlignmentFlag.AlignCenter,
                           fm.elidedText(line, Qt.TextElideMode.ElideRight, int(rect.width() - 8)))


class BatteryGlyph(QWidget):
    """A battery outline filled to its charge, the percentage inside."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.level: float | None = None
        self.charging = False
        self.setFixedSize(120, 58)

    def set_level(self, level: float | None, charging: bool) -> None:
        self.level, self.charging = level, charging
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        body = QRectF(2, 4, self.width() - 14, self.height() - 8)
        text = self.palette().color(QPalette.ColorRole.Text)
        p.setPen(QPen(muted(self), 2))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(body, 7, 7)
        p.setBrush(muted(self))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(body.right() + 2, body.center().y() - 7, 6, 14), 2, 2)
        if self.level is not None:
            inner = body.adjusted(4, 4, -4, -4)
            p.setBrush(battery_colour(self.level))
            p.drawRoundedRect(QRectF(inner.x(), inner.y(), max(4.0, inner.width() * self.level
                                                               / 100), inner.height()), 4, 4)
        p.setPen(text)
        p.setFont(scaled_font(self, 1.25, bold=True))
        label = SI.percent(self.level) + (" ⚡" if self.charging else "")
        p.drawText(body, Qt.AlignmentFlag.AlignCenter, label)


# --------------------------------------------------------------------------- tables


class _UseDelegate(QStyledItemDelegate):
    """A "Use" cell ("61 %") as a small bar with the number."""

    def paint(self, painter, option, index) -> None:
        text = index.data() or ""
        m = re.fullmatch(r"(\d+(?:\.\d+)?) %", text)
        if not m:
            super().paint(painter, option, index)
            return
        pct = float(m.group(1))
        widget = option.widget
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(option.rect).adjusted(4, 0, -4, 0)
        bar = QRectF(rect.x(), rect.center().y() - 3.5, max(10.0, rect.width() - 44), 7)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track(widget))
        painter.drawRoundedRect(bar, 3.5, 3.5)
        painter.setBrush(level_colour(pct, 85, 95))
        painter.drawRoundedRect(QRectF(bar.x(), bar.y(), max(6.0, bar.width() * pct / 100),
                                       bar.height()), 3.5, 3.5)
        painter.setPen(widget.palette().color(QPalette.ColorRole.Text))
        painter.drawText(QRectF(bar.right() + 6, option.rect.y(), 40, option.rect.height()),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, text)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802 - Qt override
        size = super().sizeHint(option, index)
        return QSize(max(size.width(), 140), size.height())


class FitTree(QTreeWidget):
    """A table (or tree) as tall as its visible rows: the page scrolls, not
    the table."""

    def __init__(self, spec: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.spec = spec
        columns = spec["columns"]
        parents = spec.get("parents")
        self.setColumnCount(len(columns))
        self.setHeaderLabels(columns)
        self.setRootIsDecorated(bool(parents))
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.items: list[QTreeWidgetItem] = []
        hidden = muted(self)
        for i, row in enumerate(spec["rows"]):
            item = QTreeWidgetItem([str(c) for c in row])
            item.setData(0, Qt.ItemDataRole.UserRole, " ".join(row).lower())
            for c, cell in enumerate(row):
                if cell == SI.HIDDEN:
                    item.setForeground(c, hidden)
                    item.setToolTip(c, tr("Hidden: tick Show identifiers to see it"))
                elif len(cell) > 40:
                    item.setToolTip(c, plain_tooltip(cell))
            parent_index = parents[i] if parents and i < len(parents) else None
            if parent_index is not None and 0 <= parent_index < len(self.items):
                self.items[parent_index].addChild(item)
            else:
                self.addTopLevelItem(item)
            self.items.append(item)
        if "Use" in columns:
            self.setItemDelegateForColumn(columns.index("Use"), _UseDelegate(self))
        self.expandAll()
        header = self.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for c in range(len(columns)):
            self.resizeColumnToContents(c)
            if self.columnWidth(c) > 360:
                self.setColumnWidth(c, 360)
        self.expanded.connect(lambda _i: self.fit())
        self.collapsed.connect(lambda _i: self.fit())
        self.fit()

    def filter(self, words: list[str], show_all: bool = False) -> int:
        """Show the rows with every word (and the parents of such rows)."""
        shown = 0
        matches = []
        for item in self.items:
            hay = item.data(0, Qt.ItemDataRole.UserRole)
            match = show_all or all(w in hay for w in words)
            matches.append(match)
            shown += match
        for item, match in zip(self.items, matches):
            item.setHidden(not match)
        if not show_all:
            for item, match in zip(self.items, matches):
                if match:
                    parent = item.parent()
                    while parent is not None:
                        parent.setHidden(False)
                        parent = parent.parent()
        self.fit()
        return shown

    def visible_rows(self) -> int:
        count = 0
        it = QTreeWidgetItemIterator(self, QTreeWidgetItemIterator.IteratorFlag.NotHidden)
        while it.value() is not None:
            item = it.value()
            parent, visible = item.parent(), True
            while parent is not None:
                if not parent.isExpanded() or parent.isHidden():
                    visible = False
                    break
                parent = parent.parent()
            count += visible
            it += 1
        return count

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        if event.oldSize().width() != event.size().width():
            self.fit()

    def fit(self) -> None:
        rows = self.visible_rows()
        row_h = self.sizeHintForRow(0) if self.topLevelItemCount() else 22
        row_h = max(row_h, self.fontMetrics().height() + 6)
        height = self.header().sizeHint().height() + rows * row_h + 2 * self.frameWidth() + 2
        natural = sum(self.columnWidth(c) for c in range(self.columnCount() - 1)) + \
            max(40, self.sizeHintForColumn(self.columnCount() - 1))
        if natural > self.width() - 2 * self.frameWidth():
            height += self.horizontalScrollBar().sizeHint().height()
        self.setFixedHeight(height)


class FieldGrid(QWidget):
    """Label / value rows; values selectable."""

    def __init__(self, fields: list[dict], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(5)
        grid.setColumnStretch(1, 1)
        self.rows: list[tuple[QLabel, QLabel, str]] = []
        colour = muted(self).name()
        for r, f in enumerate(fields):
            label = set_plain(QLabel(f["label"]))
            label.setStyleSheet(f"color: {colour};")
            label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            value = set_plain(QLabel(f["value"]))
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if f["value"] == SI.HIDDEN:
                value.setStyleSheet(f"color: {colour}; font-style: italic;")
                value.setToolTip(tr("Hidden: tick Show identifiers to see it"))
            grid.addWidget(label, r, 0)
            grid.addWidget(value, r, 1)
            self.rows.append((label, value, f"{f['label']} {f['value']}".lower()))

    def filter(self, words: list[str], show_all: bool = False) -> int:
        shown = 0
        for label, value, hay in self.rows:
            match = show_all or all(w in hay for w in words)
            label.setVisible(match)
            value.setVisible(match)
            shown += match
        return shown


def heading(text: str, factor: float = 1.15) -> QLabel:
    label = set_plain(QLabel(text))
    label.setFont(scaled_font(label, factor, bold=True))
    return label


class SectionView(QWidget):
    """One section of the report: its title, what is special to it (a
    chart), its fields and its tables; or why it is not available."""

    def __init__(self, section: dict, extra: QWidget | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.section = section
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(heading(section["title"], 1.3))
        self.title_words = section["title"].lower()
        self.grid: FieldGrid | None = None
        self.tables: list[FitTree] = []
        self.table_titles: list[QLabel] = []
        self.extra = extra
        if not section.get("available", True):
            note = set_plain(QLabel(tr("Not available: {reason}").format(
                reason=section.get("reason", ""))))
            note.setWordWrap(True)
            note.setStyleSheet(f"color: {muted(self).name()};")
            layout.addWidget(note)
            self.rows_text = f"{self.title_words} not available {section.get('reason', '')}"
            self.note = note
            return
        self.note = None
        if extra is not None:
            layout.addWidget(extra)
        if section.get("fields"):
            self.grid = FieldGrid(section["fields"])
            layout.addWidget(self.grid)
        for spec in section.get("tables", []):
            title = set_plain(QLabel(spec["title"]))
            title.setFont(scaled_font(title, 1.0, bold=True))
            layout.addSpacing(4)
            layout.addWidget(title)
            tree = FitTree(spec)
            layout.addWidget(tree)
            self.tables.append(tree)
            self.table_titles.append(title)

    def filter(self, words: list[str]) -> int:
        if not words:
            if self.grid:
                self.grid.filter([], True)
            for tree, title in zip(self.tables, self.table_titles):
                tree.filter([], True)
                tree.setVisible(True)
                title.setVisible(True)
            if self.extra is not None:
                self.extra.setVisible(True)
            self.setVisible(True)
            return 1
        if self.note is not None:
            hit = all(w in self.rows_text for w in words)
            self.setVisible(hit)
            return int(hit)
        whole = all(w in self.title_words for w in words)
        count = self.grid.filter(words, whole) if self.grid else 0
        for tree, title in zip(self.tables, self.table_titles):
            table_whole = whole or all(w in tree.spec["title"].lower() for w in words)
            n = tree.filter(words, table_whole)
            tree.setVisible(n > 0)
            title.setVisible(n > 0)
            count += n
        if self.extra is not None:
            self.extra.setVisible(whole)
        self.setVisible(count > 0 or whole)
        return count or int(whole)


class Page(QScrollArea):
    """A scrolling page of sections."""

    def __init__(self, key: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.key = key
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.body = QWidget()
        self.body.setObjectName("axSysInfoPage")
        self.layout_ = QVBoxLayout(self.body)
        self.layout_.setContentsMargins(18, 14, 18, 18)
        self.layout_.setSpacing(18)
        self.setWidget(self.body)
        self.sections: list[SectionView] = []
        self.empty = QLabel(tr("Nothing on this page matches the search."))
        self.empty.setStyleSheet(f"color: {muted(self).name()};")
        self.empty.hide()

    def add(self, widget: QWidget) -> None:
        self.layout_.addWidget(widget)
        if isinstance(widget, SectionView):
            self.sections.append(widget)

    def finish(self) -> None:
        self.layout_.addWidget(self.empty)
        self.layout_.addStretch(1)

    def filter(self, words: list[str]) -> int:
        count = sum(s.filter(words) for s in self.sections)
        self.empty.setVisible(bool(words) and count == 0)
        return count


class FlowGrid(QWidget):
    """Tiles in as many columns as fit (at least *min_width* each)."""

    def __init__(self, min_width: int = 270, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.min_width = min_width
        self.tiles: list[QWidget] = []
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(12)
        self._columns = 0

    def add(self, tile: QWidget) -> None:
        body = getattr(tile, "body", None)
        if body is not None:
            body.addStretch(1)  # content at the top, however tall the row is
        self.tiles.append(tile)
        self._columns = 0
        self._reflow()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._reflow()

    def _reflow(self) -> None:
        columns = max(1, min(4, (self.width() + 12) // (self.min_width + 12)))
        if columns == self._columns:
            return
        self._columns = columns
        for tile in self.tiles:
            self.grid.removeWidget(tile)
        for c in range(4):
            self.grid.setColumnStretch(c, 1 if c < columns else 0)
        for i, tile in enumerate(self.tiles):
            self.grid.addWidget(tile, i // columns, i % columns)


# --------------------------------------------------------------------------- the overview


class Tile(Card):
    """An overview tile: an icon and a title, then its content."""

    def __init__(self, title: str, icon_name: str, page: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent, clickable=True)
        self.page = page
        self.setMinimumHeight(150)
        title = tr(title)
        self.setToolTip(tr("Open {title}").format(title=title))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(8)
        head = QHBoxLayout()
        head.setSpacing(8)
        icon = QLabel()
        icon.setPixmap(glyph(icon_name, muted(self), 18).pixmap(18, 18))
        head.addWidget(icon)
        title_label = QLabel(title)
        title_label.setFont(scaled_font(title_label, 1.05, bold=True))
        head.addWidget(title_label, 1)
        outer.addLayout(head)
        self.body = QVBoxLayout()
        self.body.setSpacing(6)
        outer.addLayout(self.body, 1)

    def ring_row(self, ring: RingGauge, lines: list[QLabel]) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)
        row.addWidget(ring, 0, Qt.AlignmentFlag.AlignVCenter)
        col = QVBoxLayout()
        col.setSpacing(3)
        for label in lines:
            col.addWidget(label)
        col.addStretch(1)
        row.addLayout(col, 1)
        self.body.addLayout(row)


def small(text: str = "", widget_muted: bool = False, wrap: bool = True) -> QLabel:
    """A line of what the machine reports (a model, a name): plain text."""
    label = set_plain(QLabel(text))
    label.setWordWrap(wrap)
    if widget_muted:
        label.setStyleSheet(f"color: {muted(label).name()};")
    return label


class HeaderCard(Card):
    """The machine: its name, maker and model, OS and a few facts."""

    def __init__(self, report: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        sections = {s["key"]: s for s in report.get("sections", [])}
        machine = sections.get("machine", {}).get("data", {})
        os_data = sections.get("os", {}).get("data", {})
        virt = sections.get("virtualization", {}).get("data", {})
        row = QHBoxLayout(self)
        row.setContentsMargins(18, 16, 18, 16)
        row.setSpacing(18)
        form = machine.get("form") or ""
        kind = virt.get("kind", "")
        icon_name = ("vm" if kind in ("vm", "vm+container") else "laptop" if form == "laptop"
                     else "server" if form == "server" else "desktop")
        icon = QLabel()
        icon.setPixmap(glyph(icon_name, series(self), 56).pixmap(56, 56))
        row.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(4)
        # The computer name is an identifier: hidden, the card says so in words.
        hostname = os_data.get("hostname")
        name = set_plain(QLabel(hostname if hostname and hostname != SI.HIDDEN
                                else tr("This computer")))
        name.setFont(scaled_font(name, 1.7, bold=True))
        name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        col.addWidget(name)
        maker = " ".join(x for x in (machine.get("vendor_short") or machine.get("vendor", ""),
                                     machine.get("model") or machine.get("product", "")) if x)
        chassis = machine.get("chassis", "")
        line1 = " · ".join(x for x in (maker, chassis) if x) or tr("Maker and model not reported")
        col.addWidget(small(line1))
        session = os_data.get("session", "")
        desktop = os_data.get("desktop", "")
        de = f"{desktop} on {session.capitalize() if session != 'x11' else 'X11'}" \
            if desktop and session else desktop or session
        kernel = os_data.get("kernel", "")
        line2 = " · ".join(x for x in (os_data.get("name", ""),
                                        f"kernel {kernel}" if kernel else "", de) if x)
        col.addWidget(small(line2))
        uptime = os_data.get("uptime_s")
        when = report.get("generated", "")
        try:
            when = _dt.datetime.fromisoformat(when).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass
        facts = " · ".join(x for x in (
            f"up {SI.human_duration(uptime)}" if uptime is not None else "",
            virt.get("verdict", "").split(" (no sign")[0],
            f"axross {os_data.get('axross')}" if os_data.get("axross") else "",
            f"gathered {when}" if when else "") if x)
        col.addWidget(small(facts, widget_muted=True))
        row.addLayout(col, 1)
        self.title = name
        cpu = sections.get("cpu", {}).get("data", {})
        mem = sections.get("memory", {}).get("data", {})
        disks = [d for d in sections.get("storage", {}).get("data", {}).get("disks", [])
                 if not d["name"].startswith(("dm-", "md"))]
        displays = [d for d in sections.get("graphics", {}).get("data", {}).get("displays", [])
                    if d.get("status") == "connected"]
        figures = [
            (str(cpu["threads"]) if cpu.get("threads") else "", tr("CPU threads")),
            (_round_bytes(max(mem.get("installed") or 0, mem.get("total") or 0) or None),
             tr("memory")),
            (_round_bytes(sum(d["size"] for d in disks)) if disks else "", tr("storage")),
            (str(len(displays)) if displays else "", tr("displays") if len(displays) != 1
             else tr("display")),
        ]
        for value, label in figures:
            if not value:
                continue
            box = QVBoxLayout()
            box.setSpacing(0)
            number = set_plain(QLabel(value))
            number.setFont(scaled_font(number, 1.6, bold=True))
            number.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            box.addWidget(number)
            caption = small(label, widget_muted=True, wrap=False)
            caption.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            box.addWidget(caption)
            box.addStretch(1)
            row.addSpacing(8)
            row.addLayout(box)


def _round_bytes(n: int | None) -> str:
    """32 GiB, 1 TB-ish disks as "954 GiB" -> short: "32 GiB", "0.9 TiB"."""
    if not n:
        return ""
    gib = n / 1024**3
    if gib >= 1000:
        return f"{gib / 1024:.1f} TiB"
    if gib >= 10:
        return f"{gib:.0f} GiB"
    return SI.human_bytes(n)


class Overview(Page):
    """The dashboard."""

    open_page = pyqtSignal(str)

    def __init__(self, report: dict, history: dict, parent: QWidget | None = None) -> None:
        super().__init__("overview", parent)
        self.report = report
        self.sections = []
        sections = {s["key"]: s for s in report.get("sections", [])}
        self.header = HeaderCard(report)
        self.add(self.header)
        grid = FlowGrid()
        self.grid = grid
        self.add(grid)
        self.live_targets: list = []
        self._cpu_tile(grid, sections.get("cpu"), history)
        self._memory_tiles(grid, sections.get("memory"), history)
        self._storage_tile(grid, sections.get("storage"))
        self._battery_tile(grid, sections.get("battery"))
        self._temps_tile(grid, sections.get("sensors"))
        self._graphics_tile(grid, sections.get("graphics"))
        self._network_tile(grid, sections.get("network"))
        for tile in grid.tiles:
            tile.clicked.connect(lambda t=tile: self.open_page.emit(t.page))
        hint = small(tr("Click a tile for its details. Live values are sampled once a second "
                        "while this window is open."), widget_muted=True)
        self.add(hint)
        self.finish()

    def _cpu_tile(self, grid: FlowGrid, section: dict | None, history: dict) -> None:
        tile = Tile("CPU", "cpu", "cpu")
        data = (section or {}).get("data", {})
        ring = RingGauge()
        ring.set_value(None, "–", caption=tr("load"))
        model = data.get("model") or tr("Unknown processor")
        model = re.sub(r"\((R|TM)\)|\bCPU\b|@.*$", "", model).replace("  ", " ").strip()
        facts = " · ".join(x for x in (
            f"{data['cores']} cores" if data.get("cores") else "",
            f"{data['threads']} threads" if data.get("threads") else "",
            f"up to {SI.human_mhz(data['max_mhz'])}" if data.get("max_mhz") else "") if x)
        freq = small("", widget_muted=True)
        tile.ring_row(ring, [small(model), small(facts, widget_muted=True), freq])
        spark = Sparkline(history["cpu"])
        tile.body.addWidget(spark)
        grid.add(tile)

        def live(sample: dict) -> None:
            # The history grew: draw it (it stayed on "collecting…" otherwise).
            spark.update()
            cpu = sample.get("cpu")
            ring.set_value(cpu, caption=tr("load"), colour=level_colour(cpu, 80, 95)
                           if cpu is not None and cpu >= 80 else series(ring))
            per = [v for v in sample.get("per_cpu", []) if v is not None]
            if per:
                busiest = max(per)
                freq.setText(tr("busiest core {percent}").format(percent=SI.percent(busiest)))
        self.live_targets.append(live)

    def _memory_tiles(self, grid: FlowGrid, section: dict | None, history: dict) -> None:
        data = (section or {}).get("data", {})
        tile = Tile("Memory", "memory", "memory")
        ring = RingGauge()
        used, total = data.get("used"), data.get("total")
        pct = 100 * used / total if used is not None and total else None
        ring.set_value(pct, caption=tr("used"), colour=level_colour(pct, 80, 92))
        amount = small(tr("{used} of {total}").format(used=SI.human_bytes(used),
                                                      total=SI.human_bytes(total)) if total
                       else tr("Not available"))
        avail = small(tr("{amount} available").format(amount=SI.human_bytes(data.get("available")))
                      if data.get("available") is not None else "", widget_muted=True)
        cache = small(tr("{amount} cache").format(amount=SI.human_bytes(data["cache"]))
                      if data.get("cache") else "",
                      widget_muted=True)
        tile.ring_row(ring, [amount, avail, cache])
        mem_spark = Sparkline(history["memory"], 1)
        tile.body.addWidget(mem_spark)
        grid.add(tile)

        swap = Tile("Swap", "memory", "memory")
        sring = RingGauge()
        st, su = data.get("swap_total") or 0, data.get("swap_used") or 0
        spct = 100 * su / st if st else None
        sring.set_value(spct, tr("none") if not st else None, caption=tr("used") if st else "",
                        colour=level_colour(spct, 60, 85))
        samount = small(tr("{used} of {total}").format(used=SI.human_bytes(su),
                                                       total=SI.human_bytes(st)) if st
                        else tr("No swap space"))
        kinds = ", ".join(_dedupe(("zram" if "zram" in s["name"] else s["type"])
                                  for s in data.get("swaps", [])))
        swap.ring_row(sring, [samount, small(kinds, widget_muted=True)])
        grid.add(swap)

        def live(sample: dict) -> None:
            mem_spark.update()
            mem = sample.get("memory")
            if mem and mem.get("total"):
                p = 100 * mem["used"] / mem["total"]
                ring.set_value(p, caption=tr("used"), colour=level_colour(p, 80, 92))
                amount.setText(tr("{used} of {total}").format(
                    used=SI.human_bytes(mem["used"]), total=SI.human_bytes(mem["total"])))
                avail.setText(tr("{amount} available").format(
                    amount=SI.human_bytes(mem["available"])))
            sw = sample.get("swap")
            if sw and sw.get("total"):
                p = 100 * sw["used"] / sw["total"]
                sring.set_value(p, caption=tr("used"), colour=level_colour(p, 60, 85))
                samount.setText(tr("{used} of {total}").format(
                    used=SI.human_bytes(sw["used"]), total=SI.human_bytes(sw["total"])))
        self.live_targets.append(live)

    def _storage_tile(self, grid: FlowGrid, section: dict | None) -> None:
        tile = Tile("Storage", "storage", "storage")
        data = (section or {}).get("data", {})
        filesystems = [f for f in data.get("filesystems", []) if f.get("total")]
        root = next((f for f in filesystems if f["mount"] in ("/", "C:\\")),
                    filesystems[0] if filesystems else None)
        ring = RingGauge()
        if root:
            ring.set_value(root["percent"], caption=root["mount"] if len(root["mount"]) < 8
                           else tr("used"), colour=level_colour(root["percent"], 85, 95))
        else:
            ring.set_value(None, "–")
        disks = [d for d in data.get("disks", []) if not d["name"].startswith(("dm-", "md"))]
        lines = [small(tr("{free} free of {total}").format(free=SI.human_bytes(root["free"]),
                                                           total=SI.human_bytes(root["total"]))
                       if root else tr("No file system measured"))]
        if disks:
            lines.append(small(", ".join(f"{d['kind']} {SI.human_bytes(d['size'])}"
                                         for d in disks[:3]), widget_muted=True))
        tile.ring_row(ring, lines)
        for fs in [f for f in filesystems if f is not root][:3]:
            bar = UsageBar(label_width=110)
            bar.set_value(fs["percent"] / 100 if fs["percent"] is not None else None,
                          fs["mount"], SI.percent(fs["percent"]),
                          level_colour(fs["percent"], 85, 95))
            tile.body.addWidget(bar)
        grid.add(tile)

    def _battery_tile(self, grid: FlowGrid, section: dict | None) -> None:
        data = (section or {}).get("data", {})
        bats = [b for b in data.get("batteries", []) if b.get("scope") != "Device"]
        tile = Tile("Battery", "battery", "battery")
        if not bats:
            tile.body.addWidget(small(tr("No battery – runs on mains power") if section and
                                      section.get("available") else
                                      tr("No battery information"), widget_muted=True))
            grid.add(tile)
            return
        b = bats[0]
        ring = RingGauge()
        ring.set_value(b.get("capacity"), caption=tr("charge"),
                       colour=battery_colour(b.get("capacity")))
        lines = [small(f"{b.get('status', '')}"
                       + (f", {b['time_text']}" if b.get("time_text") else ""))]
        if b.get("cycles"):
            lines.append(small(tr("{count} charge cycles").format(count=b["cycles"]),
                               widget_muted=True))
        tile.ring_row(ring, lines)
        if b.get("health") is not None:
            bar = UsageBar(label_width=60)
            h = b["health"]
            bar.set_value(min(1.0, h / 100), "Health", f"{h:.0f} %",
                          QColor(GOOD) if h >= 80 else QColor(WARNING) if h >= 60
                          else QColor(CRITICAL))
            tile.body.addWidget(bar)
        grid.add(tile)

    def _temps_tile(self, grid: FlowGrid, section: dict | None) -> None:
        tile = Tile("Temperatures", "sensors", "sensors")
        data = (section or {}).get("data", {})
        temps = data.get("temperatures", [])
        bars: list[UsageBar] = []
        # The chips' own sensors; the thermal zones mostly repeat them.
        if any(t["chip"] != "thermal zone" for t in temps):
            temps = [t for t in temps if t["chip"] != "thermal zone"]
        shown = sorted(temps, key=lambda t: -t["celsius"])[:4]
        if not shown:
            tile.body.addWidget(small(tr("No temperature sensor exposed"), widget_muted=True))
        for t in shown:
            bar = UsageBar(label_width=120)
            bars.append(bar)
            tile.body.addWidget(bar)
        grid.add(tile)

        def show(rows: list[dict]) -> None:
            if any(t["chip"] != "thermal zone" for t in rows):
                rows = [t for t in rows if t["chip"] != "thermal zone"]
            rows = sorted(rows, key=lambda t: -t["celsius"])[: len(bars)]
            for bar, t in zip(bars, rows):
                bar.set_value(max(0.0, min(1.0, (t["celsius"] - 20) / 80)), temp_name(t),
                              SI.celsius(t["celsius"]),
                              temp_colour(t["celsius"], t.get("high"), t.get("crit")))
        show(shown)
        self.live_targets.append(lambda sample: show(sample["temperatures"])
                                 if sample.get("temperatures") else None)

    def _graphics_tile(self, grid: FlowGrid, section: dict | None) -> None:
        tile = Tile("Graphics & Displays", "display", "graphics")
        data = (section or {}).get("data", {})
        gpus = data.get("gpus", [])
        if gpus:
            for g in gpus[:2]:
                tile.body.addWidget(small(f"{_short_vendor(g['vendor'])} {g['name']}"))
        else:
            tile.body.addWidget(small(tr("No graphics adapter reported"), widget_muted=True))
        for d in [d for d in data.get("displays", []) if d["status"] == "connected"][:3]:
            res = d.get("resolution") or d.get("preferred") or ""
            hz = f" @ {d['refresh']:.0f} Hz" if d.get("refresh") else ""
            tile.body.addWidget(small(f"{d['connector']}: {d.get('monitor') or 'display'} · "
                                      f"{res}{hz}", widget_muted=True))
        grid.add(tile)

    def _network_tile(self, grid: FlowGrid, section: dict | None) -> None:
        tile = Tile("Network", "network", "network")
        data = (section or {}).get("data", {})
        ifaces = [i for i in data.get("interfaces", []) if i["kind"] != "Loopback"]
        up = [i for i in ifaces if i["state"] == "up"]
        labels: dict[str, QLabel] = {}
        if not ifaces:
            tile.body.addWidget(small(tr("No network interface reported"), widget_muted=True))
        for i in (up or ifaces)[:3]:
            speed = (f"{i['speed_mbps']} Mb/s" if i.get("speed_mbps")
                     else f"{i['signal_dbm']} dBm" if i.get("signal_dbm") is not None else "")
            tile.body.addWidget(small(" · ".join(x for x in (
                f"{i['name']}", i["kind"], i["state"], speed) if x)))
            rate = small("", widget_muted=True)
            labels[i["name"]] = rate
            tile.body.addWidget(rate)
        rest = len(ifaces) - len((up or ifaces)[:3])
        if rest > 0:
            tile.body.addWidget(small(tr("and {count} more").format(count=rest),
                                      widget_muted=True))
        grid.add(tile)

        def live(sample: dict) -> None:
            for name, label in labels.items():
                rate = sample.get("net", {}).get(name)
                if rate:
                    label.setText(f"↓ {SI.human_rate(rate['rx'])}   ↑ {SI.human_rate(rate['tx'])}")
        self.live_targets.append(live)

    def filter(self, words: list[str]) -> int:
        return 0 if words else 1


#: hwmon chip -> what a person calls it.
CHIP_NAMES = {
    "coretemp": "CPU", "k10temp": "CPU", "zenpower": "CPU", "cpu_thermal": "CPU",
    "nvme": "NVMe", "drivetemp": "Disk", "amdgpu": "GPU", "nouveau": "GPU", "radeon": "GPU",
    "i915": "GPU", "acpitz": "ACPI", "thinkpad": "ThinkPad", "dell_smm": "Dell",
    "iwlwifi_1": "Wi-Fi", "pch_cannonlake": "Chipset", "pch_skylake": "Chipset",
}


def temp_name(t: dict) -> str:
    """"coretemp" / "Package id 0" -> "CPU package"; "nvme" / "Composite" -> "NVMe"."""
    chip, label = t.get("chip", ""), t.get("label", "")
    if chip == "thermal zone":
        return {"x86_pkg_temp": "CPU package (zone)", "acpitz": "ACPI zone"}.get(label, label)
    name = CHIP_NAMES.get(chip, chip)
    low = label.lower()
    if low.startswith("package id") or low in ("tctl", "tdie"):
        return f"{name} package" if name == "CPU" else f"{name} {label}"
    if low in ("composite", chip.lower()) or re.fullmatch(r"temp\d+", low):
        return name
    return f"{name} {label}"


def _short_vendor(vendor: str) -> str:
    return re.sub(r"\s+(Corporation|Corp\.|Inc\.|Co\., Ltd\.?|Ltd\.?|Technology.*)$", "",
                  vendor or "").strip()


def _dedupe(items) -> list:
    out = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


# --------------------------------------------------------------------------- detail extras


def cpu_extra(section: dict, history: dict, live_targets: list) -> QWidget:
    data = section["data"]
    box = QWidget()
    col = QVBoxLayout(box)
    col.setContentsMargins(0, 0, 0, 0)
    col.setSpacing(8)
    if data.get("model"):
        model = set_plain(QLabel(data["model"]))
        model.setFont(scaled_font(model, 1.05, bold=True))
        model.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        col.addWidget(model)
    row = QHBoxLayout()
    ring = RingGauge(110)
    ring.set_value(None, "–", caption=tr("load"))
    row.addWidget(ring)
    spark_col = QVBoxLayout()
    spark_col.addWidget(small(tr("CPU use, last two minutes"), widget_muted=True))
    spark = Sparkline(history["cpu"])
    spark.setMinimumHeight(70)
    spark_col.addWidget(spark)
    row.addLayout(spark_col, 1)
    col.addLayout(row)
    per_cpu = data.get("per_cpu", [])
    kinds = {c["cpu"]: c.get("type", "") for c in per_cpu if c.get("cpu") is not None}
    col.addWidget(small(tr("Use per logical CPU") + (" " + tr("(p = P-core, e = E-core)")
                                                     if any(kinds.values()) else ""),
                        widget_muted=True))
    bars = CoreBars()
    bars.set_values([None] * len(per_cpu), kinds,
                    [c["cpu"] if c.get("cpu") is not None else i for i, c in enumerate(per_cpu)])
    col.addWidget(bars)
    if data.get("features"):
        col.addWidget(small(tr("Instruction set features"), widget_muted=True))
        chips = Chips()
        chips.set_features(data["features"])
        col.addWidget(chips)

    def live(sample: dict) -> None:
        cpu = sample.get("cpu")
        ring.set_value(cpu, caption=tr("load"), colour=level_colour(cpu, 80, 95)
                       if cpu is not None and cpu >= 80 else series(ring))
        if sample.get("per_cpu"):
            bars.set_values(sample["per_cpu"], ids=sample.get("cpu_ids"))
            spark.update()
    live_targets.append(live)
    return box


class StackBar(QWidget):
    """One bar split into parts (in use, cache, free), a legend below."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.parts: list[tuple[str, float, QColor]] = []
        fm = self.fontMetrics()
        self.setFixedHeight(24 + 8 + fm.height() + 4)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_parts(self, parts: list[tuple[str, float, QColor]]) -> None:
        self.parts = [(label, max(0.0, float(value)), colour) for label, value, colour in parts]
        self.setToolTip(plain_tooltip("\n".join(f"{label}: {SI.human_bytes(value)}"
                                                for label, value, _c in self.parts)))
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        total = sum(v for _l, v, _c in self.parts)
        if total <= 0:
            return
        width = self.width() - 2
        x = 1.0
        for i, (_label, value, colour) in enumerate(self.parts):
            w = width * value / total
            if w <= 0:
                continue
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(colour)
            p.drawRoundedRect(QRectF(x, 1, max(2.0, w - (2 if i < len(self.parts) - 1 else 0)),
                                     24), 5, 5)
            x += w
        fm = self.fontMetrics()
        x, y = 1.0, 32
        for label, value, colour in self.parts:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(colour)
            p.drawRoundedRect(QRectF(x, y + fm.height() / 2 - 5, 10, 10), 2, 2)
            text = f"{label} {SI.human_bytes(value)} ({100 * value / total:.0f} %)"
            p.setPen(self.palette().color(QPalette.ColorRole.Text))
            p.drawText(QRectF(x + 16, y, fm.horizontalAdvance(text) + 4, fm.height() + 2),
                       Qt.AlignmentFlag.AlignVCenter, text)
            x += 16 + fm.horizontalAdvance(text) + 22


def memory_parts(widget: QWidget, total: int, used: int, free: int | None) -> list:
    """In use / cache (what the kernel can give back) / free, adding up to *total*."""
    used = max(0, min(total, used))
    if free is None:
        return [("In use", used, series(widget)), ("Available", total - used, track(widget))]
    free = max(0, min(total - used, free))
    cache_colour = QColor(series(widget))
    cache_colour.setAlpha(110)
    return [("In use", used, series(widget)), ("Cache", total - used - free, cache_colour),
            ("Free", free, track(widget))]


def memory_extra(section: dict, history: dict, live_targets: list) -> QWidget:
    data = section["data"]
    box = QWidget()
    col = QVBoxLayout(box)
    col.setContentsMargins(0, 0, 0, 0)
    col.setSpacing(6)
    stack = StackBar()
    swap_bar = UsageBar(label_width=90)

    def show(total, used, free, swap_total, swap_used) -> None:
        if total:
            stack.set_parts(memory_parts(stack, total, used, free))
        if swap_total:
            swap_bar.set_value(swap_used / swap_total, "Swap",
                               f"{SI.human_bytes(swap_used)} of {SI.human_bytes(swap_total)}",
                               level_colour(100 * swap_used / swap_total, 60, 85))
        else:
            swap_bar.set_value(None, "Swap", "none")

    show(data.get("total"), data.get("used") or 0, data.get("free"), data.get("swap_total"),
         data.get("swap_used") or 0)
    col.addWidget(stack)
    col.addWidget(swap_bar)
    col.addSpacing(4)
    col.addWidget(small(tr("Memory in use, last two minutes"), widget_muted=True))
    spark = Sparkline(history["memory"], 1)
    spark.setMinimumHeight(60)
    col.addWidget(spark)

    def live(sample: dict) -> None:
        mem, sw = sample.get("memory"), sample.get("swap") or {}
        if mem:
            show(mem["total"], mem["used"], mem.get("free"), sw.get("total"), sw.get("used", 0))
            spark.update()
    live_targets.append(live)
    return box


def storage_extra(section: dict) -> QWidget | None:
    disks = section["data"].get("disks", [])
    if not disks:
        return None
    box = QWidget()
    col = QVBoxLayout(box)
    col.setContentsMargins(0, 0, 0, 0)
    col.setSpacing(10)
    for disk in disks:
        card = Card()
        inner = QVBoxLayout(card)
        inner.setContentsMargins(14, 10, 14, 12)
        title = " ".join(x for x in (disk.get("vendor", ""), disk.get("model", "")) if x) \
            or disk.get("mapped") or disk["name"]
        head = QLabel(f"<b>{_esc(title)}</b>  <span style='color:{muted(card).name()}'>"
                      f"{_esc(disk['name'])} · {_esc(disk['kind'])} · "
                      f"{SI.human_bytes(disk['size'])}"
                      + (" · removable" if disk.get("removable") else "") + "</span>")
        inner.addWidget(head)
        inner.addWidget(PartitionBar(disk))
        col.addWidget(card)
    return box


def displays_extra(section: dict, screens: list[dict]) -> QWidget:
    displays = [d for d in section["data"].get("displays", []) if d["status"] == "connected"]
    by_name = {d["connector"]: d for d in displays}
    shapes = []
    if any(s["name"] in by_name for s in screens):
        for s in screens:
            d = by_name.get(s["name"], {})
            detail = f"{s['width']}×{s['height']}"
            if s.get("refresh"):
                detail += f" @ {s['refresh']:.0f} Hz"
            if d.get("monitor"):
                detail = f"{d['monitor']}\n{detail}"
            shapes.append({"name": s["name"], "x": s["x"], "y": s["y"], "w": s["width"],
                           "h": s["height"], "detail": detail, "primary": s.get("primary")})
    else:
        x = 0
        for d in displays:
            w, h = d.get("width_px"), d.get("height_px")
            if not (w and h):
                m = re.match(r"(\d+)x(\d+)", d.get("preferred", ""))
                w, h = (int(m.group(1)), int(m.group(2))) if m else (1920, 1080)
            detail = f"{w}×{h}" + (f" @ {d['refresh']:.0f} Hz" if d.get("refresh") else "")
            if d.get("monitor"):
                detail = f"{d['monitor']}\n{detail}"
            if d.get("diagonal_in"):
                detail += f"\n{d['diagonal_in']:.1f}\""
            shapes.append({"name": d["connector"], "x": x, "y": -h, "w": w, "h": h,
                           "detail": detail, "primary": d.get("internal")})
            x += w + max(40, w // 20)  # side by side, standing on one line
        if not shapes:
            for s in screens:
                shapes.append({"name": s["name"] or "Screen", "x": s["x"], "y": s["y"],
                               "w": s["width"], "h": s["height"],
                               "detail": f"{s['width']}×{s['height']}",
                               "primary": s.get("primary")})
    sketch = DisplaySketch(shapes)
    sketch.setToolTip("The displays as arranged by the desktop where it tells; otherwise side "
                      "by side at their native resolution")
    return sketch


def battery_extra(section: dict) -> QWidget | None:
    bats = section["data"].get("batteries", [])
    if not bats:
        return None
    box = QWidget()
    row = QHBoxLayout(box)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(16)
    for b in bats:
        card = Card()
        col = QVBoxLayout(card)
        col.setContentsMargins(14, 10, 14, 12)
        title = b["name"] + (f" ({b['model']})" if b.get("model") else "")
        col.addWidget(heading(title, 1.0))
        glyph_w = BatteryGlyph()
        glyph_w.set_level(b.get("capacity"), b.get("status") == "Charging")
        col.addWidget(glyph_w)
        col.addWidget(small(b.get("status", "") + (f" · {b['time_text']}"
                                                   if b.get("time_text") else "")))
        if b.get("health") is not None:
            bar = UsageBar(label_width=60)
            h = b["health"]
            bar.set_value(min(1.0, h / 100), "Health", f"{h:.0f} %",
                          QColor(GOOD) if h >= 80 else QColor(WARNING) if h >= 60
                          else QColor(CRITICAL))
            col.addWidget(bar)
        row.addWidget(card)
    row.addStretch(1)
    return box


def sensors_extra(section: dict, live_targets: list) -> QWidget | None:
    temps = section["data"].get("temperatures", [])
    if not temps:
        return None
    box = QWidget()
    col = QVBoxLayout(box)
    col.setContentsMargins(0, 0, 0, 0)
    col.setSpacing(2)
    scale = small("Scale 20 – 100 °C · green up to 60 °C, amber up to 80 °C (or the "
                  "sensor's high mark), orange above it, red at 90 °C or critical",
                  widget_muted=True)
    col.addWidget(scale)
    def keyed(rows: list[dict]):
        """(chip, label, n) per sensor: two NVMe drives both report
        nvme/Composite - the n-th of a name keeps its own bar (the readings
        come in the same order every time)."""
        seen: dict[tuple[str, str], int] = {}
        for t in rows:
            name = (t["chip"], t["label"])
            seen[name] = seen.get(name, -1) + 1
            yield (*name, seen[name]), t

    bars: dict[tuple[str, str, int], UsageBar] = {}
    for key, _t in keyed(temps):
        bar = UsageBar(label_width=190)
        bars[key] = bar
        col.addWidget(bar)

    def show(rows: list[dict]) -> None:
        for key, t in keyed(rows):
            bar = bars.get(key)
            if bar is None:
                continue
            label = temp_name(t)
            bar.set_value(max(0.0, min(1.0, (t["celsius"] - 20) / 80)), label,
                          SI.celsius(t["celsius"]),
                          temp_colour(t["celsius"], t.get("high"), t.get("crit")))
    show(temps)
    live_targets.append(lambda sample: show(sample.get("temperatures") or []))
    return box


def virtualization_extra(section: dict) -> QWidget:
    data = section["data"]
    card = Card()
    row = QHBoxLayout(card)
    row.setContentsMargins(16, 12, 16, 12)
    kind = data.get("kind", "bare")
    icon = QLabel()
    icon.setPixmap(glyph("vm" if "vm" in kind else "layers" if kind == "container"
                         else "desktop", series(card), 40).pixmap(40, 40))
    row.addWidget(icon)
    col = QVBoxLayout()
    text = QLabel(f"<b>{_esc(data.get('verdict', ''))}</b>")
    text.setWordWrap(True)
    text.setFont(scaled_font(text, 1.1))
    col.addWidget(text)
    if data.get("checked"):
        col.addWidget(small("Checked: " + "; ".join(data["checked"]) + ".", widget_muted=True))
    row.addLayout(col, 1)
    return card


class InterfaceCard(Card):
    """A network interface: a state dot, its name and kind, speed or
    signal, and its live throughput."""

    def __init__(self, iface: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.iface = iface
        self.setMinimumWidth(200)
        col = QVBoxLayout(self)
        col.setContentsMargins(12, 9, 12, 10)
        col.setSpacing(2)
        up = iface["state"] == "up"
        dot = GOOD if up else muted(self).name()
        head = QLabel(f"<span style='color:{dot}'>●</span> <b>{_esc(iface['name'])}</b>")
        col.addWidget(head)
        facts = [iface["kind"], iface["state"]]
        if iface.get("speed_mbps"):
            speed = iface["speed_mbps"]
            facts.append(f"{speed / 1000:g} Gb/s" if speed >= 1000 else f"{speed} Mb/s")
        if iface.get("signal_dbm") is not None:
            facts.append(f"signal {iface['signal_dbm']} dBm")
        col.addWidget(small(" · ".join(f for f in facts if f), widget_muted=True))
        self.rate = small("↓ –   ↑ –" if up else "", widget_muted=False)
        col.addWidget(self.rate)

    def set_rate(self, rate: dict | None) -> None:
        if rate:
            self.rate.setText(f"↓ {SI.human_rate(rate['rx'])}   ↑ {SI.human_rate(rate['tx'])}")


def network_extra(section: dict, live_targets: list) -> QWidget | None:
    ifaces = [i for i in section["data"].get("interfaces", []) if i.get("kind") != "Loopback"]
    if not ifaces:
        return None
    ifaces.sort(key=lambda i: (i["state"] != "up", i["name"]))
    box = FlowGrid(200)
    cards = []
    for iface in ifaces:
        card = InterfaceCard(iface)
        cards.append(card)
        box.add(card)

    def live(sample: dict) -> None:
        for card in cards:
            card.set_rate(sample.get("net", {}).get(card.iface["name"]))
    live_targets.append(live)
    return box


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# --------------------------------------------------------------------------- Qt's screens


def screens_section() -> dict:
    """The screens as Qt sees them (name, maker, geometry, refresh, scale)."""
    rows, screens = [], []
    primary = QGuiApplication.primaryScreen()
    for s in QGuiApplication.screens():
        g = s.geometry()
        size = s.physicalSize()
        info = {"name": s.name(), "manufacturer": s.manufacturer(), "model": s.model(),
                "x": g.x(), "y": g.y(), "width": g.width(), "height": g.height(),
                "refresh": round(s.refreshRate(), 2), "scale": s.devicePixelRatio(),
                "width_mm": round(size.width()), "height_mm": round(size.height()),
                "primary": s is primary, "serial": s.serialNumber()}
        screens.append(info)
        rows.append([info["name"], " ".join(x for x in (info["manufacturer"], info["model"])
                                            if x), f"{g.width()}×{g.height()} at {g.x()},{g.y()}",
                     f"{info['refresh']:.0f} Hz" if info["refresh"] else "",
                     f"{info['scale']:g}×", f"{info['width_mm']}×{info['height_mm']} mm"
                     if info["width_mm"] else "", "yes" if info["primary"] else "",
                     info["serial"]])
    section = SI.make_section(
        "screens", "Screens (as the desktop shows them)",
        [SI.field("Screens", len(screens))],
        [SI.table("Screens", ["Name", "Monitor", "Geometry", "Refresh", "Scale", "Size",
                              "Primary", "Serial"], rows, ident_columns=(7,))],
        {"screens": screens})
    return section


# --------------------------------------------------------------------------- workers


#: One lock per sampler: a quick hide / show starts a new loop while the
#: old one may still be inside sample() - both updated the sampler's previous
#: readings at once (a wrong CPU or network-rate spike).
_SAMPLER_LOCKS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_SAMPLER_LOCKS_GUARD = threading.Lock()


def _sampler_lock(sampler) -> threading.Lock:
    with _SAMPLER_LOCKS_GUARD:
        try:
            lock = _SAMPLER_LOCKS.get(sampler)
            if lock is None:
                lock = _SAMPLER_LOCKS[sampler] = threading.Lock()
        except TypeError:   # not weakly referenceable: a lock of its own
            lock = threading.Lock()
        return lock


class _LiveLoop:
    """Samples on a worker thread every *interval* seconds until stopped;
    each sample goes to the GUI thread through *deliver* (a GuiCall)."""

    def __init__(self, sampler: SI.LiveSampler, deliver, interval: float,
                 owner: QWidget | None = None) -> None:
        self.sampler = sampler
        self.deliver = deliver
        self.interval = interval
        # Ends by itself once the window is gone, even without a close.
        self._owner = weakref.ref(owner) if owner is not None else None
        self.stopped = threading.Event()
        self._lock = _sampler_lock(sampler)
        self.thread = threading.Thread(target=self._run, name="axross-sysinfo-live",
                                       daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stopped.set()

    def _run(self) -> None:
        while not self.stopped.is_set():
            owner = self._owner() if self._owner is not None else None
            if self._owner is not None and (owner is None or sip.isdeleted(owner)):
                return
            del owner
            try:
                with self._lock:
                    sample = None if self.stopped.is_set() else self.sampler.sample()
            except Exception:  # noqa: BLE001 - a missed tick, not a crash
                log.debug("Live sample failed", exc_info=True)
                sample = None
            if sample is not None and not self.stopped.is_set():
                self.deliver(sample)
            self.stopped.wait(self.interval)


# --------------------------------------------------------------------------- the window


class SystemInfoWindow(QDialog):
    """The System Information window (non-modal, a window of its own)."""

    def __init__(self, parent: QWidget | None = None, *, info_factory=None,
                 sampler_factory=None, interval: float = LIVE_INTERVAL,
                 live: bool = True) -> None:
        super().__init__(parent)
        set_window_icon(self, "system-info")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setWindowTitle(tr("System Information"))
        self.setObjectName("axSystemInfo")
        self.setModal(False)
        self._info_factory = info_factory or (lambda: SI.SystemInfo())
        self._sampler_factory = sampler_factory or (lambda: SI.LiveSampler())
        self._interval = interval
        self._live_enabled = live
        self._live: _LiveLoop | None = None
        self._sampler: SI.LiveSampler | None = None
        self._cancel: threading.Event | None = None
        self._generation = 0
        self.report: dict | None = None
        self.history = {"cpu": collections.deque(maxlen=HISTORY),
                        "memory": collections.deque(maxlen=HISTORY)}
        self.live_targets: list = []
        self.pages: dict[str, Page] = {}
        self.last_sample: dict | None = None
        self.gather_thread: threading.Thread | None = None
        self._deliver_report = GuiCall(self._on_gathered)
        self._deliver_progress = GuiCall(self._on_progress)
        self._deliver_live = GuiCall(self._on_live)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 10)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Search everything  ( / )"))
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(120)
        self._search_timer.timeout.connect(self.apply_filter)
        self.search.textChanged.connect(lambda _t: self._search_timer.start())
        bar.addWidget(self.search, 1)
        self.show_ids = QCheckBox(tr("Show identifiers"))
        self.show_ids.setToolTip(tr("Serial numbers, MAC and IP addresses and UUIDs. Hidden by "
                                    "default - also in copies and saved reports - because such "
                                    "reports get pasted in public."))
        self.show_ids.toggled.connect(lambda _on: self.render())
        bar.addWidget(self.show_ids)
        self.refresh_button = QPushButton(tr("Refresh"))
        self.refresh_button.setToolTip(tr("Gather everything again"))
        self.refresh_button.clicked.connect(lambda _c=False: self.refresh())
        bar.addWidget(self.refresh_button)
        self.copy_section_button = QPushButton(tr("Copy Section"))
        self.copy_section_button.setToolTip(tr("Copy the page shown as text"))
        self.copy_section_button.clicked.connect(lambda _c=False: self.copy_section())
        bar.addWidget(self.copy_section_button)
        self.copy_all_button = QPushButton(tr("Copy All"))
        self.copy_all_button.clicked.connect(lambda _c=False: self.copy_all())
        bar.addWidget(self.copy_all_button)
        self.save_button = QPushButton(tr("Save Report…"))
        self.save_button.setToolTip(tr("Save everything as a text or JSON file"))
        self.save_button.clicked.connect(lambda _c=False: self.save_report())
        bar.addWidget(self.save_button)
        # Feedback: JSON was only a file type in the save dialog - not found.
        self.json_button = QPushButton(tr("JSON Export"))
        self.json_button.setToolTip(tr("Everything as JSON - every value, table and raw reading - "
                                       "to a file or the clipboard"))
        json_menu = QMenu(self.json_button)
        json_menu.addAction(tr("Save as JSON File…"), lambda: self.save_report(as_json=True))
        json_menu.addAction(tr("Copy All as JSON"), self.copy_all_json)
        json_menu.addAction(tr("Copy Section as JSON"), self.copy_section_json)
        self.json_button.setMenu(json_menu)
        bar.addWidget(self.json_button)
        layout.addLayout(bar)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.nav = QListWidget()
        self.nav.setIconSize(QSize(20, 20))
        self.nav.setSpacing(1)
        self.nav.setFrameShape(QFrame.Shape.NoFrame)
        for key, title, icon_name, _keys in PAGES:
            item = QListWidgetItem(glyph(icon_name, self.palette().color(
                QPalette.ColorRole.Text), 20), tr(title))
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(180, 34))
            self.nav.addItem(item)
        self.nav.setMinimumWidth(170)
        self.nav.setMaximumWidth(260)
        self.nav.currentRowChanged.connect(self._page_changed)
        split.addWidget(self.nav)
        self.stack = QStackedWidget()
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setSizes([200, 900])
        layout.addWidget(split, 1)
        self.status = set_plain(QLabel(""))  # names errors and paths
        self.status.setStyleSheet(f"color: {muted(self).name()};")
        layout.addWidget(self.status)
        self._placeholder = QLabel(tr("Gathering system information…"))
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.stack.addWidget(self._placeholder)

        QShortcut(QKeySequence("/"), self, activated=self._focus_search)
        QShortcut(QKeySequence.StandardKey.Find, self, activated=self._focus_search)
        QShortcut(QKeySequence.StandardKey.Copy, self.nav, activated=self.copy_section)

        from ui.close_corner import add_close_corner

        add_close_corner(self)
        self.nav.setCurrentRow(0)
        self.refresh()

    # -- gathering ----------
    def refresh(self) -> None:
        """Gather everything again on a worker thread."""
        if self._cancel is not None:
            self._cancel.set()
        self._generation += 1
        generation = self._generation
        cancel = threading.Event()
        self._cancel = cancel
        self.refresh_button.setEnabled(False)
        self.status.setText(tr("Gathering system information…"))
        info_factory = self._info_factory
        deliver, progress = self._deliver_report, self._deliver_progress

        def work() -> None:
            try:
                report = info_factory().gather(
                    progress=lambda done, total, title: progress(generation, done, total, title),
                    cancel=cancel.is_set)
                error = ""
            except Exception as exc:  # noqa: BLE001 - shown in the window
                log.warning("System information could not be gathered", exc_info=True)
                report, error = None, str(exc) or type(exc).__name__
            if not cancel.is_set():
                deliver(generation, report, error)

        self.gather_thread = threading.Thread(target=work, name="axross-sysinfo-gather",
                                              daemon=True)
        self.gather_thread.start()

    def _on_progress(self, generation: int, done: int, total: int, title: str) -> None:
        if generation == self._generation:
            self.status.setText(tr("Gathering… {done} of {total} sources ({title})").format(
                done=done, total=total, title=title))

    def _on_gathered(self, generation: int, report: dict | None, error: str) -> None:
        if generation != self._generation:
            return
        self.refresh_button.setEnabled(True)
        #: Why the last gathering failed ("" when it did not): --json waits for it.
        self.gather_error = "" if report is not None else (error or "unknown error")
        if report is None:
            self.status.setText(tr("Could not gather the system information: {error}").format(
                error=error))
            return
        try:
            report["sections"].insert(
                next((i + 1 for i, s in enumerate(report["sections"])
                      if s["key"] == "graphics"), len(report["sections"])), screens_section())
        except Exception:  # noqa: BLE001 - Qt's screen list is a nicety
            log.debug("No screen list", exc_info=True)
        self.report = report
        self.render()
        missing = [s["title"] for s in report["sections"] if not s.get("available", True)]
        when = report.get("generated", "")
        try:
            when = _dt.datetime.fromisoformat(when).strftime("%H:%M:%S")
        except ValueError:
            pass
        note = tr("Gathered at {when} in {seconds} s").format(
            when=when, seconds=f"{report.get('elapsed_ms', 0) / 1000:.1f}")
        if missing:
            note += " · " + tr("not available: {sections}").format(sections=", ".join(missing))
        self.status.setText(note)
        self.status.setToolTip(plain_tooltip("\n".join(
            f"{s['title']}: {s.get('reason', '')}" for s in report["sections"]
            if not s.get("available", True))))

    # -- rendering ----------
    def shown_report(self) -> dict | None:
        if self.report is None:
            return None
        return self.report if self.show_ids.isChecked() else SI.redact(self.report)

    def render(self) -> None:
        """Build every page from the report (identifiers as the toggle says)."""
        report = self.shown_report()
        if report is None:
            return
        current = self.current_page_key()
        for page in list(self.pages.values()):
            self.stack.removeWidget(page)
            page.deleteLater()
        self.pages.clear()
        self.live_targets = []
        sections = {s["key"]: s for s in report["sections"]}
        screens = sections.get("screens", {}).get("data", {}).get("screens", [])
        for key, title, _icon, keys in PAGES:
            if key == "overview":
                page: Page = Overview(report, self.history)
                page.open_page.connect(self.show_page)
                self.live_targets.extend(page.live_targets)
            else:
                page = Page(key)
                for skey in keys:
                    section = sections.get(skey)
                    if section is None:
                        continue
                    page.add(SectionView(section, self._extra(skey, section, screens)))
                page.finish()
            self.pages[key] = page
            self.stack.addWidget(page)
            available = [sections[k].get("available", True) for k in keys if k in sections]
            item = self.nav.item([p[0] for p in PAGES].index(key))
            reasons = [f"{sections[k]['title']}: {sections[k].get('reason')}" for k in keys
                       if k in sections and not sections[k].get("available", True)]
            dim = key != "overview" and available and not any(available)
            item.setForeground(muted(self) if dim else self.palette().color(
                QPalette.ColorRole.Text))
            item.setToolTip(plain_tooltip(tr("Not available - {reasons}").format(
                reasons="; ".join(reasons))) if reasons else tr(title))
        self.show_page(current or "overview")
        if self.last_sample is not None:
            self._apply_live(self.last_sample)
        self.apply_filter()

    def _extra(self, key: str, section: dict, screens: list[dict]) -> QWidget | None:
        if not section.get("available", True):
            return None
        try:
            if key == "cpu":
                return cpu_extra(section, self.history, self.live_targets)
            if key == "memory":
                return memory_extra(section, self.history, self.live_targets)
            if key == "storage":
                return storage_extra(section)
            if key == "graphics":
                return displays_extra(section, screens)
            if key == "battery":
                return battery_extra(section)
            if key == "network":
                return network_extra(section, self.live_targets)
            if key == "sensors":
                return sensors_extra(section, self.live_targets)
            if key == "virtualization":
                return virtualization_extra(section)
        except Exception:  # noqa: BLE001 - a chart less, the tables stay
            log.warning("System information chart for %s failed", key, exc_info=True)
        return None

    def current_page_key(self) -> str:
        row = self.nav.currentRow()
        return PAGES[row][0] if 0 <= row < len(PAGES) else "overview"

    def show_page(self, key: str) -> None:
        keys = [p[0] for p in PAGES]
        if key not in keys:
            return
        if self.nav.currentRow() != keys.index(key):
            self.nav.setCurrentRow(keys.index(key))
        else:
            self._page_changed(keys.index(key))

    def _page_changed(self, row: int) -> None:
        if not (0 <= row < len(PAGES)):
            return
        page = self.pages.get(PAGES[row][0])
        if page is not None:
            self.stack.setCurrentWidget(page)

    # -- search ----------
    def _focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def apply_filter(self) -> None:
        words = self.search.text().lower().split()
        counts = {}
        for key, page in self.pages.items():
            counts[key] = page.filter(words)
        for row, (key, title, _icon, _keys) in enumerate(PAGES):
            item = self.nav.item(row)
            n = counts.get(key, 0)
            item.setText(f"{tr(title)}  ({n})" if words and key != "overview" else tr(title))
            item.setHidden(bool(words) and n == 0)
        if words and counts.get(self.current_page_key(), 0) == 0:
            first = next((k for k, *_r in PAGES if counts.get(k)), None)
            if first:
                self.show_page(first)
        self.search_counts = counts

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.key() == Qt.Key.Key_Escape and self.search.text():
            self.search.clear()
            return
        super().keyPressEvent(event)

    # -- export ----------
    def page_section_keys(self, key: str | None = None) -> list[str]:
        key = key or self.current_page_key()
        return list(next(p[3] for p in PAGES if p[0] == key))

    def section_text(self, key: str | None = None) -> str:
        if self.report is None:
            return ""
        return SI.export_text(self.report, show_identifiers=self.show_ids.isChecked(),
                              keys=self.page_section_keys(key))

    def all_text(self) -> str:
        if self.report is None:
            return ""
        return SI.export_text(self.report, show_identifiers=self.show_ids.isChecked())

    def copy_section(self) -> None:
        text = self.section_text()
        if text:
            QApplication.clipboard().setText(text)
            self.status.setText(tr("Copied {page} to the clipboard").format(
                page=tr(PAGES[self.nav.currentRow()][1])))

    def copy_all(self) -> None:
        text = self.all_text()
        if text:
            QApplication.clipboard().setText(text)
            self.status.setText(tr("Copied everything to the clipboard"))

    def section_json(self, key: str | None = None) -> str:
        if self.report is None:
            return ""
        return SI.export_json(self.report, show_identifiers=self.show_ids.isChecked(),
                              keys=self.page_section_keys(key))

    def all_json(self) -> str:
        if self.report is None:
            return ""
        return SI.export_json(self.report, show_identifiers=self.show_ids.isChecked())

    def copy_section_json(self) -> None:
        text = self.section_json()
        if text:
            QApplication.clipboard().setText(text)
            self.status.setText(tr("Copied {page} as JSON to the clipboard").format(
                page=tr(PAGES[self.nav.currentRow()][1])))

    def copy_all_json(self) -> None:
        text = self.all_json()
        if text:
            QApplication.clipboard().setText(text)
            self.status.setText(tr("Copied everything as JSON to the clipboard"))

    def save_report(self, path: str | None = None, *, as_json: bool | None = None) -> bool:
        """Save everything to *path* (asked when None): JSON for a ``.json``
        path or *as_json*, else text."""
        if self.report is None:
            return False
        if path is None:
            # The computer name is an identifier: in the file name only
            # when identifiers are shown.
            host = re.sub(r"[^\w.-]+", "_", next(
                (s["data"].get("hostname", "") for s in self.report["sections"]
                 if s["key"] == "os"), "") or "") if self.show_ids.isChecked() else ""
            suffix = "json" if as_json else "txt"
            stem = f"system-info-{host}-" if host else "system-info-"
            default = str(Path.home() / f"{stem}{_dt.date.today():%Y%m%d}.{suffix}")
            filters = [tr("Text report (*.txt)"), tr("JSON (*.json)")]
            if as_json:
                filters.reverse()
            path, chosen = QFileDialog.getSaveFileName(
                self, tr("Save as JSON") if as_json else tr("Save Report"), default,
                ";;".join(filters))
            if not path:
                return False
            if chosen == tr("JSON (*.json)") and not path.lower().endswith(".json"):
                path += ".json"
        if as_json and not path.lower().endswith(".json"):
            path += ".json"
        as_json = path.lower().endswith(".json")
        ids = self.show_ids.isChecked()
        text = (SI.export_json(self.report, show_identifiers=ids) if as_json
                else SI.export_text(self.report, show_identifiers=ids))
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            self.status.setText(tr("Could not save the report to {path}: {reason}").format(
                path=path, reason=exc.strerror or str(exc)))
            return False
        self.status.setText(tr("Saved the report to {path}").format(path=path)
                            + ("" if ids else " " + tr("(identifiers hidden)")))
        return True

    # -- live values ----------
    def start_live(self) -> None:
        if not self._live_enabled or self._live is not None:
            return
        if self._sampler is None:
            self._sampler = self._sampler_factory()
        self._live = _LiveLoop(self._sampler, self._deliver_live, self._interval, self)
        self._live.start()

    def stop_live(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    @property
    def live_running(self) -> bool:
        return self._live is not None

    def _on_live(self, sample: dict) -> None:
        if self._live is None:
            return
        self.history["cpu"].append(sample.get("cpu"))
        mem = sample.get("memory")
        self.history["memory"].append(100 * mem["used"] / mem["total"]
                                      if mem and mem.get("total") else None)
        self.last_sample = sample
        self._apply_live(sample)

    def _apply_live(self, sample: dict) -> None:
        for target in self.live_targets:
            try:
                target(sample)
            except RuntimeError:  # a widget of a page being rebuilt
                continue

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self.start_live()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.stop_live()
        super().hideEvent(event)

    def _finish(self) -> None:
        """Closing (the [x], Esc, the window manager): remember the size,
        stop the live values and any gathering."""
        from ui import viewer_window as VW

        if self.isVisible():
            try:
                VW.save_window_state(self, STATE_NAME)
            except Exception:  # noqa: BLE001 - the size is a nicety
                log.debug("Window state not saved", exc_info=True)
        self.stop_live()
        if self._cancel is not None:
            self._cancel.set()

    def reject(self) -> None:
        self._finish()
        super().reject()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._finish()
        super().closeEvent(event)


def open_window(parent: QWidget | None = None, **kwargs) -> SystemInfoWindow:
    """A new System Information window, sized as last time, on screen."""
    from ui import viewer_window as VW

    window = SystemInfoWindow(parent, **kwargs)
    VW.restore_window_state(window, STATE_NAME)
    VW.show_independent(window)
    return window


__all__ = ["PAGES", "SystemInfoWindow", "open_window", "screens_section"]
