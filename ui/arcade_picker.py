"""The Arcade's game picker: four cards, painted - each with its game's
emblem drawn by the game's own painters (Byte and a daemon, Bitling on a
block, the digger with a rock and a crystal, two ribbons), the best score,
a glow on the chosen one.

Keys as in the games: arrows or W A S D move between the cards, Enter or
Space starts, Esc closes the Arcade window; a click starts a card, the
mouse over a card chooses it. The picture moves only while the picker is
on screen (its timer stops when it is hidden).
"""

from __future__ import annotations

import math
import random
import time

from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QFontMetricsF, QLinearGradient, QPainter, QPen, QPolygonF
from PyQt6.QtWidgets import QWidget

from core.i18n import tr
from ui import arcade_common as AC

ACCENTS = {"chase": "#5eead4", "tilt": "#a5b4fc", "rockfall": "#ffd166", "trails": "#ff4fa3"}
MOVE = {Qt.Key.Key_Left: (-1, 0), Qt.Key.Key_A: (-1, 0), Qt.Key.Key_Right: (1, 0), Qt.Key.Key_D: (1, 0),
        Qt.Key.Key_Up: (0, -1), Qt.Key.Key_W: (0, -1), Qt.Key.Key_Down: (0, 1), Qt.Key.Key_S: (0, 1)}


class ArcadePicker(QWidget):
    """*games*: kind -> (name, text); ``choose(kind)`` starts one,
    ``close_window()`` closes the Arcade."""

    def __init__(self, games: dict, *, choose, close_window, audio=None, parent=None):
        super().__init__(parent)
        self.games = games
        self.kinds = list(games)
        self.choose = choose
        self.close_window = close_window
        self.audio = audio
        self.best: dict[str, int] = {}
        self.selected = 0
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.setMinimumSize(560, 420)
        rng = random.Random(11)
        self.stars = [(rng.random(), rng.random(), rng.uniform(0.3, 1.0)) for _ in range(90)]
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)

    def best_text(self, kind: str) -> str:
        return tr("best {n}").format(n=self.best[kind]) if kind in self.best else ""

    # -- showing -------------------------------------------------------------------------------

    def showEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.timer.start(33)
        super().showEvent(event)

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.timer.stop()
        super().hideEvent(event)

    # -- keys and the mouse --------------------------------------------------------------------

    def handle_key(self, event, pressed: bool) -> bool:
        if not pressed:
            return event.key() in MOVE
        key = event.key()
        if key == Qt.Key.Key_Escape:
            if not event.isAutoRepeat():
                self.close_window()
            return True
        if key in MOVE:
            self.move(*MOVE[key])
            return True
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            if not event.isAutoRepeat():
                self.start_selected()
            return True
        return False

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt API
        if not self.handle_key(event, True):
            super().keyPressEvent(event)

    def move(self, dx: int, dy: int) -> None:
        cols = self._columns()
        i = self.selected
        if dx:
            i = (i + dx) % len(self.kinds)
        elif dy:
            i = (i + dy * cols) % len(self.kinds)
        if i != self.selected:
            self.selected = i
            if self.audio is not None:
                self.audio.play("select", 0.6)
            self.update()

    def start_selected(self) -> None:
        if self.audio is not None:
            self.audio.play("start")
        self.choose(self.kinds[self.selected])

    def _hit(self, pos) -> int | None:
        for i, r in enumerate(self.card_rects()):
            if r.contains(QPointF(pos)):
                return i
        return None

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt API
        i = self._hit(event.position())
        if i is not None and i != self.selected:
            self.selected = i
            self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.setFocus(Qt.FocusReason.MouseFocusReason)
        i = self._hit(event.position())
        if i is not None and event.button() == Qt.MouseButton.LeftButton:
            self.selected = i
            self.start_selected()

    # -- layout --------------------------------------------------------------------------------

    def _columns(self) -> int:
        return 4 if self.width() >= 1180 else 2

    def card_rects(self) -> list[QRectF]:
        cols = self._columns()
        rows = math.ceil(len(self.kinds) / cols)
        top, bottom, side, gap = 118.0, 48.0, 28.0, 18.0
        w = (self.width() - 2 * side - gap * (cols - 1)) / cols
        h = min(260.0, (self.height() - top - bottom - gap * (rows - 1)) / rows)
        total_h = rows * h + gap * (rows - 1)
        y0 = top + max(0.0, (self.height() - top - bottom - total_h) / 2)
        return [QRectF(side + (i % cols) * (w + gap), y0 + (i // cols) * (h + gap), w, h)
                for i in range(len(self.kinds))]

    # -- painting ------------------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        p = QPainter(self)
        try:
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            now = time.monotonic()
            bg = QLinearGradient(0, 0, 0, self.height())
            bg.setColorAt(0, QColor("#0b1222"))
            bg.setColorAt(1, QColor("#03050a"))
            p.fillRect(self.rect(), bg)
            p.setPen(Qt.PenStyle.NoPen)
            for x, y, z in self.stars:
                yy = (y + now * 0.012 * z) % 1.0
                p.setBrush(QColor(200, 220, 255, int(60 + 120 * z * (0.6 + 0.4 * math.sin(now * 2 + x * 40)))))
                p.drawEllipse(QPointF(x * self.width(), yy * self.height()), 0.6 + z, 0.6 + z)
            accent = QColor(ACCENTS[self.kinds[self.selected]])
            AC.glow_text(p, QRectF(0, 22, self.width(), 52), "AXROSS ARCADE", AC.font(30, weight=QFont.Weight.Black),
                         QColor("#f8fafc"), halo=QColor(accent.red(), accent.green(), accent.blue(), 110))
            AC.glow_text(p, QRectF(0, 72, self.width(), 24), tr("axross's own games - four of them"),
                         AC.font(10.5, weight=QFont.Weight.DemiBold), QColor("#94a3b8"))
            for i, r in enumerate(self.card_rects()):
                self._card(p, r, self.kinds[i], i == self.selected, now)
            AC.glow_text(p, QRectF(0, self.height() - 40, self.width(), 26),
                         tr("Arrows or W A S D choose - Enter or a click starts - Esc closes"),
                         AC.font(9.5, weight=QFont.Weight.DemiBold), QColor("#94a3b8"))
        finally:
            p.end()

    def _card(self, p: QPainter, r: QRectF, kind: str, chosen: bool, now: float) -> None:
        accent = QColor(ACCENTS[kind])
        if chosen:
            lift = 2 + math.sin(now * 3) * 1.5
            r = r.translated(0, -lift)
            for width, alpha in ((14, 22), (7, 50)):
                c = QColor(accent)
                c.setAlpha(alpha)
                p.setPen(QPen(c, width))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRoundedRect(r, 16, 16)
        bg = QLinearGradient(r.topLeft(), r.bottomLeft())
        bg.setColorAt(0, QColor(22, 30, 48, 240))
        bg.setColorAt(1, QColor(8, 11, 20, 240))
        p.setBrush(bg)
        edge = QColor(accent)
        edge.setAlpha(230 if chosen else 70)
        p.setPen(QPen(edge, 1.6 if chosen else 1.0))
        p.drawRoundedRect(r, 16, 16)
        p.setPen(Qt.PenStyle.NoPen)
        emblem = QRectF(r.left() + 14, r.top() + 14, min(r.width() * 0.36, r.height() - 28), r.height() - 28)
        p.save()
        p.setClipRect(emblem)
        art = QLinearGradient(emblem.topLeft(), emblem.bottomLeft())
        art.setColorAt(0, QColor(accent.red() // 6, accent.green() // 6, accent.blue() // 6))
        art.setColorAt(1, QColor(4, 6, 12))
        p.setBrush(art)
        p.drawRoundedRect(emblem, 10, 10)
        EMBLEMS[kind](p, emblem, now, chosen)
        p.restore()
        name, text = self.games[kind]
        tx = emblem.right() + 16
        tw = r.right() - tx - 14
        AC.glow_text(p, QRectF(tx, r.top() + 14, tw, 34), name.upper(), AC.font(16, weight=QFont.Weight.Black),
                     accent, align=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        p.setFont(AC.font(9.2, weight=QFont.Weight.Normal))
        p.setPen(QColor("#cbd5e1"))
        p.drawText(QRectF(tx, r.top() + 52, tw, r.height() - 92),
                   Qt.TextFlag.TextWordWrap | Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop, text)
        best = self.best_text(kind)
        if best:
            f = AC.font(10, mono=True)
            bw = QFontMetricsF(f).horizontalAdvance(best) + 20
            pill = QRectF(tx, r.bottom() - 34, bw, 22)
            p.setBrush(QColor(accent.red(), accent.green(), accent.blue(), 40))
            p.drawRoundedRect(pill, 11, 11)
            p.setFont(f)
            p.setPen(accent)
            p.drawText(pill, Qt.AlignmentFlag.AlignCenter, best)
            p.setPen(Qt.PenStyle.NoPen)
        if chosen:
            p.setFont(AC.font(9.5))
            p.setPen(QColor("#f8fafc"))
            p.drawText(QRectF(r.left(), r.bottom() - 34, r.width() - 16, 22),
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, tr("Enter: play ▸"))
            p.setPen(Qt.PenStyle.NoPen)


# -- the emblems ---------------------------------------------------------------------------------


def _emblem_chase(p: QPainter, r: QRectF, now: float, chosen: bool) -> None:
    from core.arcade import chase as C
    from ui.arcade_chase_view import paint_byte, paint_daemon

    s = min(r.width(), r.height()) * 0.3
    c = r.center()
    run = 0.2 + ((now * 0.3) % 0.75 if chosen else 0.45)
    for i in range(6):
        x = r.left() + (i + 0.5) * r.width() / 6
        if (x - r.left()) / r.width() > run + 0.05:
            AC.blit_centred(p, AC.glow("#a7f3d0", s * 0.18), x, c.y())
    bx = r.left() + run * r.width()
    paint_byte(p, QPointF(bx, c.y()), s, C.RIGHT, now)
    paint_daemon(p, QPointF(bx - s * 1.5, c.y() + s * 0.1), s * 0.9, "Tracker", C.RIGHT, 0, now)


def _emblem_tilt(p: QPainter, r: QRectF, now: float, chosen: bool) -> None:
    from core.arcade import chase as C
    from ui.arcade_tilt_view import paint_bitling

    tw = min(r.width(), r.height()) * 0.28
    th = tw / 2
    c = r.center() + QPointF(0, tw * 0.3)
    for gx in range(3):
        for gy in range(3):
            x = c.x() + (gx - gy) * tw / 2
            y = c.y() + (gx + gy - 2) * th / 2
            top = QPolygonF([QPointF(x, y - th / 2), QPointF(x + tw / 2, y), QPointF(x, y + th / 2),
                             QPointF(x - tw / 2, y)])
            p.setBrush(QColor("#364fc7") if (gx + gy) % 2 else QColor("#5c7cfa"))
            p.drawPolygon(top)
    hop = abs(math.sin(now * (3.5 if chosen else 1.5))) * th * 1.4
    paint_bitling(p, c, tw * 0.22, th, now, C.RIGHT, hop, 1.0)


def _emblem_rockfall(p: QPainter, r: QRectF, now: float, chosen: bool) -> None:
    from core.arcade import rockfall as R
    from ui.arcade_rockfall_view import _draw_gem, _draw_rock, paint_digger

    s = min(r.width(), r.height()) * 0.34
    c = r.center()
    p.setBrush(QColor("#6b4a2f"))
    p.drawRect(QRectF(r.left(), c.y() + s * 0.5, r.width(), r.height()))
    fall = ((now * (0.8 if chosen else 0.3)) % 1.0)
    rock = AC.sprite(("rock", 3), s, s, lambda q, w, _h: _draw_rock(q, w, 3 * math.pi / 8))
    p.drawPixmap(QPointF(c.x() + s * 0.15, r.top() - s + (c.y() - r.top()) * fall), rock)
    gem = AC.sprite(("rock-gem",), s * 0.8, s * 0.8, _draw_gem)
    p.drawPixmap(QPointF(c.x() - s * 1.35, c.y() - s * 0.3), gem)
    paint_digger(p, QRectF(c.x() - s * 0.6, c.y() - s * 0.5, s, s), s, now, R.RIGHT, chosen, False)


def _emblem_trails(p: QPainter, r: QRectF, now: float, chosen: bool) -> None:
    from core.arcade import trails as T
    from ui.arcade_trails_view import _cut, _paint_rider, _ribbon

    u = 0.3 + (now * (0.3 if chosen else 0.08)) % 1.0
    m = 12.0
    a = [QPointF(r.left() + m, r.bottom() - m * 2), QPointF(r.center().x(), r.bottom() - m * 2),
         QPointF(r.center().x(), r.top() + m * 2), QPointF(r.right() - m, r.top() + m * 2)]
    b = [QPointF(r.right() - m, r.bottom() - m), QPointF(r.left() + m * 2.5, r.bottom() - m),
         QPointF(r.left() + m * 2.5, r.top() + m)]
    for pts, colour in ((a, T.COLOURS[0]), (b, T.COLOURS[1])):
        shown = _cut(pts, min(1.0, u))
        _ribbon(p, shown, 4, colour)
        if len(shown) > 1:
            d = shown[-1] - shown[-2]
            facing = (1 if d.x() > 0.1 else -1 if d.x() < -0.1 else 0, 1 if d.y() > 0.1 else -1 if d.y() < -0.1 else 0)
            _paint_rider(p, shown[-1], 4, colour, facing, chosen, 1.0)


EMBLEMS = {"chase": _emblem_chase, "tilt": _emblem_tilt, "rockfall": _emblem_rockfall, "trails": _emblem_trails}
