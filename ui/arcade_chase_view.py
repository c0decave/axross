"""Byte Chase in the Arcade window: core.arcade.chase drawn and animated
here - no image from anywhere.

The maze is a circuit board: its walls are traces with a neon edge,
merged into one outline and drawn once per level into a cached pixmap
(the board never changes while a level runs - only the bits and the
actors are painted per frame). Each level has its own colours. Byte, the
player, is a little chip with LED eyes and pins; the daemons are hovering
hexagonal drones, blue and wobbling while a root key turns them, blinking
before they turn back. Byte and the daemons glide between cells (the
painting interpolates between two ticks of the rules), sparks fly when a
bit, a key or a daemon is taken, the screen flashes when Byte is caught.
The title intro assembles BYTE CHASE out of flying bits. Sounds and the
level's tune: ui/arcade_audio.py.
"""

from __future__ import annotations

import math
import random
import time

from PyQt6.QtCore import QLineF, QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPen, QPixmap, QPolygonF

from core.arcade import chase as C
from core.i18n import tr
from ui import arcade_common as AC

KEYS = {Qt.Key.Key_Up: C.UP, Qt.Key.Key_W: C.UP, Qt.Key.Key_Down: C.DOWN, Qt.Key.Key_S: C.DOWN,
        Qt.Key.Key_Left: C.LEFT, Qt.Key.Key_A: C.LEFT, Qt.Key.Key_Right: C.RIGHT, Qt.Key.Key_D: C.RIGHT}
DAEMON_COLOURS = {"Tracker": "#ff4d6d", "Cutter": "#ffb703", "Drifter": "#7dd3fc", "Warden": "#c084fc"}
#: per level (cycling): (background top, background bottom, trace fill, trace edge, bit, accent)
PALETTES = (
    ("#04121a", "#020609", "#0b2b33", "#2dd4bf", "#a7f3d0", "#5eead4"),
    ("#0d0a1f", "#04030a", "#211a45", "#a78bfa", "#ddd6fe", "#c4b5fd"),
    ("#1a1004", "#080502", "#3a2408", "#f59e0b", "#fde68a", "#fbbf24"),
    ("#071a0c", "#020803", "#123a1d", "#4ade80", "#d9f99d", "#86efac"),
    ("#1a0612", "#080206", "#3b0d2a", "#f472b6", "#fbcfe8", "#f9a8d4"),
)
EVENT_SOUNDS = {"bit": ("bit", 0.45), "key": ("key", 1.0), "daemon": ("daemon", 1.0), "caught": ("caught", 1.0),
                "level": ("level", 1.0), "jump": ("jump", 1.0)}
HUD_H = 36


class ChaseView(AC.ArcadeView):
    """Byte Chase: a generated maze, four daemons, root keys."""

    kind = "chase"
    TICK_MS = 120
    JINGLE = "intro-chase"
    ACCENT = "#5eead4"
    DIRECTION_KEYS = frozenset(KEYS)

    def __init__(self, *, seed: int | None = None, audio=None, on_exit=None, on_progress=None, on_restart=None,
                 intro: bool = True, parent=None):
        super().__init__(audio=audio, on_exit=on_exit, on_progress=on_progress, on_restart=on_restart,
                         intro=intro, parent=parent)
        self.setMinimumSize(480, 400)
        self.seed = seed if seed is not None else random.randrange(1, 10**6)
        self.game = C.ChaseGame(seed=self.seed)
        self.held = AC.HeldKeys(KEYS)
        self.rng = random.Random(self.seed)
        self._snapshot()
        self._layer: QPixmap | None = None
        self._layer_key = None
        self.flash = 0.0
        self.banner_t = time.monotonic()
        self.popups: list[list] = []           # [x, y, text, life]
        self._title_cache = None
        self._hud = AC.HudCache()
        self._music()
        self.start_loop()

    def _music(self) -> None:
        if self.audio is not None:
            k = (self.game.level - 1) % 4
            self.audio.music(6100 + k, mood=("dorian", "minor", "mixolydian", "phrygian")[k])

    def _snapshot(self) -> None:
        g = self.game
        self.prev_player = g.player
        self.prev_daemons = [d.pos for d in g.daemons]

    # -- keys ----------------------------------------------------------------------------------

    def game_key(self, key, pressed, auto_repeat) -> bool:
        if key in KEYS:
            if pressed:
                self.held.press(key, auto_repeat)
                self.game.steer(KEYS[key])
            else:
                self.held.release(key, auto_repeat)
            return True
        return False

    def release_all(self) -> None:
        self.held.clear()

    # -- the loop ------------------------------------------------------------------------------

    def step(self) -> None:
        g = self.game
        if self.report_end(g.level, g.score):
            return
        if self.paused or self.intro_running():
            return
        held = self.held.held()
        if held is not None and g.wanted == (0, 0):
            g.steer(held)                      # caught while a key is held: it still steers
        level = g.level
        self._snapshot()
        g.tick()
        self._last_tick = time.monotonic()
        px, py = g.player
        pal = self.palette()
        for event in g.events:
            name_gain = EVENT_SOUNDS.get(event)
            if name_gain:
                self.sound(*name_gain)
            if event == "bit":
                self.particles.burst(px + 0.5, py + 0.5, pal[4], self.rng, n=5, speed=3.0, life=0.35, size=0.08)
            elif event == "key":
                self.particles.burst(px + 0.5, py + 0.5, "#fde047", self.rng, n=24, speed=6.0, life=0.7, size=0.12)
            elif event == "daemon":
                self.particles.burst(px + 0.5, py + 0.5, "#93c5fd", self.rng, n=26, speed=7.0, life=0.6, size=0.13)
                self.popups.append([px + 0.5, py, str(100 * 2 ** g.chain), 1.0])
            elif event == "caught":
                self.particles.burst(self.prev_player[0] + 0.5, self.prev_player[1] + 0.5, "#f8fafc", self.rng,
                                     n=40, speed=8.0, life=0.9, size=0.14)
                self.flash = 1.0
        g.events.clear()
        if g.level != level:
            self._snapshot()
            self.banner_t = time.monotonic()
            self._music()
            held = self.held.held()
            if held is not None:
                g.steer(held)
            self.report(g.level, g.score)
        self.report_end(g.level, g.score)

    # -- geometry ------------------------------------------------------------------------------

    def palette(self):
        return PALETTES[(self.game.level - 1) % len(PALETTES)]

    def board_rect(self) -> tuple[float, float, float]:
        g = self.game
        avail = QRectF(self.rect()).adjusted(12, HUD_H + 10, -12, -12)
        s = max(4.0, min(avail.width() / g.width, avail.height() / g.height))
        ox = avail.left() + (avail.width() - s * g.width) / 2
        oy = avail.top() + (avail.height() - s * g.height) / 2
        return s, ox, oy

    # -- the cached board ----------------------------------------------------------------------

    def _board_layer(self, s: float) -> QPixmap:
        g = self.game
        dpr = self.dpr()
        key = (self.width(), self.height(), g.level, id(g.grid), round(s, 2), dpr)
        if self._layer is not None and self._layer_key == key:
            return self._layer
        pal = self.palette()
        pm = QPixmap(max(1, int(self.width() * dpr)), max(1, int(self.height() * dpr)))
        pm.setDevicePixelRatio(dpr)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QLinearGradient(0, 0, 0, self.height())
        bg.setColorAt(0, QColor(pal[0]))
        bg.setColorAt(1, QColor(pal[1]))
        p.fillRect(QRectF(0, 0, self.width(), self.height()), bg)
        s, ox, oy = self.board_rect()
        # the floor: a faint grid of vias
        via = QColor(pal[3])
        via.setAlpha(26)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(via)
        for y in range(g.height):
            for x in range(g.width):
                if g.grid[y][x] != C.WALL:
                    p.drawEllipse(QPointF(ox + (x + 0.5) * s, oy + (y + 0.5) * s), s * 0.05, s * 0.05)
        # the traces: every wall cell joined to its wall neighbours by a
        # thick line - an outline pass, then the body over it, so they merge
        # into one shape (a path union of ~200 rounded cells took a second)
        lines = []
        for y, row in enumerate(g.grid):
            for x, c in enumerate(row):
                if c != C.WALL:
                    continue
                a = QPointF(ox + (x + 0.5) * s, oy + (y + 0.5) * s)
                lines.append(QLineF(a, a))
                if x + 1 < g.width and row[x + 1] == C.WALL:
                    lines.append(QLineF(a, a + QPointF(s, 0)))
                if y + 1 < g.height and g.grid[y + 1][x] == C.WALL:
                    lines.append(QLineF(a, a + QPointF(0, s)))
        edge = QColor(pal[3])
        body = s * 0.62

        def stroke(painter, width, brush):
            painter.setPen(QPen(brush, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                Qt.PenJoinStyle.RoundJoin))
            painter.drawLines(lines)
        halo = QPixmap(pm.size())
        halo.setDevicePixelRatio(dpr)
        for width, opacity in ((body + s * 0.6, 0.10), (body + s * 0.3, 0.22)):
            halo.fill(Qt.GlobalColor.transparent)
            hp = QPainter(halo)
            hp.setRenderHint(QPainter.RenderHint.Antialiasing)
            stroke(hp, width, QBrush(edge))
            hp.end()
            p.setOpacity(opacity)
            p.drawPixmap(0, 0, halo)
        p.setOpacity(1.0)
        stroke(p, body + max(2.0, s * 0.1), QBrush(edge.lighter(115)))
        fill = QLinearGradient(0, oy, 0, oy + g.height * s)
        fill.setColorAt(0, QColor(pal[2]).lighter(135))
        fill.setColorAt(1, QColor(pal[2]))
        stroke(p, body, QBrush(fill))
        sheen = QColor(pal[3])
        sheen.setAlpha(45)
        stroke(p, max(1.0, s * 0.08), QBrush(sheen))
        # solder pads where traces meet
        pad = QColor(pal[3]).lighter(140)
        p.setPen(Qt.PenStyle.NoPen)
        for y, row in enumerate(g.grid):
            for x, c in enumerate(row):
                if c == C.WALL and (x + y) % 3 == 0:
                    n = sum(1 for dx, dy in C.DIRS if 0 <= x + dx < g.width and 0 <= y + dy < g.height
                            and g.grid[y + dy][x + dx] == C.WALL)
                    if n >= 3:
                        p.setBrush(pad)
                        p.drawEllipse(QPointF(ox + (x + 0.5) * s, oy + (y + 0.5) * s), s * 0.08, s * 0.08)
        p.end()
        self._layer, self._layer_key = pm, key
        return pm

    # -- painting ------------------------------------------------------------------------------

    def paint_game(self, p: QPainter, dt: float) -> None:
        g = self.game
        pal = self.palette()
        dpr = self.dpr()
        s, ox, oy = self.board_rect()
        p.drawPixmap(0, 0, self._board_layer(s))
        now = time.monotonic()
        t = self.tick_progress()

        def at(x, y):
            return QPointF(ox + x * s, oy + y * s)

        bit = AC.sprite(("chase-bit", pal[4]), s * 0.6, s * 0.6, lambda q, w, _h: self._draw_bit(q, w, pal[4]), dpr)
        half = s * 0.3
        for x, y in g.bits:
            p.drawPixmap(QPointF(ox + (x + 0.5) * s - half, oy + (y + 0.5) * s - half), bit)
        for x, y in g.keys:
            self._paint_key(p, at(x + 0.5, y + 0.5), s, now + x)
        for i, d in enumerate(g.daemons):
            prev = self.prev_daemons[i] if i < len(self.prev_daemons) else d.pos
            pos = _lerp(prev, d.pos, t)
            paint_daemon(p, at(pos[0] + 0.5, pos[1] + 0.5), s, d.name, d.facing, g.scared, now, dpr)
        pos = _lerp(self.prev_player, g.player, t)
        paint_byte(p, at(pos[0] + 0.5, pos[1] + 0.5), s, g.facing, now, dpr,
                   hop=(math.sin((1 - g.airborne / C.JUMP_TICKS) * math.pi) if g.airborne else 0.0))
        self.particles.advance(dt)
        self.particles.draw(p, at, s, dpr)
        self._paint_popups(p, at, s, dt)
        if self.flash > 0:
            AC.fill_fast(p, QRectF(self.rect()), QColor(255, 60, 90, int(110 * self.flash)))
            self.flash = max(0.0, self.flash - dt * 2.5)
        self._paint_hud(p, pal)
        since = now - self.banner_t
        title, hint = self.end_message()
        if title:
            AC.overlay(p, QRectF(self.rect()), title, hint, QColor(pal[5]))
        elif since < 1.6 and not self.intro_running():
            a = min(1.0, (1.6 - since) * 2)
            c = QColor(pal[5])
            c.setAlphaF(a)
            AC.glow_text(p, QRectF(0, oy + g.height * s * 0.35, self.width(), 60),
                         tr("Level {n}").format(n=g.level), AC.font(30, weight=QFont.Weight.Black), c)

    @staticmethod
    def _draw_bit(p: QPainter, w: float, colour: str) -> None:
        g = AC.glow(colour, w / 2, 1.0, 120)
        p.drawPixmap(QRectF(0, 0, w, w), g, QRectF(0, 0, g.width(), g.height()))
        p.setBrush(QColor(colour))
        k = w * 0.14
        p.drawRoundedRect(QRectF(w / 2 - k, w / 2 - k, 2 * k, 2 * k), k * 0.3, k * 0.3)

    @staticmethod
    def _paint_key(p: QPainter, c: QPointF, s: float, phase: float) -> None:
        """A root key: a turning diamond with a pulsing ring."""
        pulse = 0.5 + 0.5 * math.sin(phase * 4)
        AC.blit_centred(p, AC.glow("#fde047", s * (0.5 + 0.15 * pulse)), c.x(), c.y())
        w = abs(math.cos(phase * 2.5)) * s * 0.26 + s * 0.04
        p.setPen(QPen(QColor(255, 236, 140, int(120 + 100 * pulse)), max(1.0, s * 0.05)))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(c, s * (0.3 + 0.08 * pulse), s * (0.3 + 0.08 * pulse))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#facc15"))
        p.drawPolygon(QPolygonF([c + QPointF(0, -s * 0.3), c + QPointF(w, 0), c + QPointF(0, s * 0.3),
                                 c + QPointF(-w, 0)]))
        p.setBrush(QColor(255, 255, 255, 170))
        p.drawPolygon(QPolygonF([c + QPointF(0, -s * 0.3), c + QPointF(w, 0), c + QPointF(0, -s * 0.05)]))

    def _paint_popups(self, p, at, s, dt) -> None:
        keep = []
        p.setFont(AC.font(max(8.0, s * 0.45), weight=QFont.Weight.Black))
        for q in self.popups:
            q[1] -= dt * 1.2
            q[3] -= dt * 1.1
            if q[3] <= 0:
                continue
            keep.append(q)
            pt = at(q[0], q[1])
            p.setPen(QColor(255, 255, 255, int(255 * min(1.0, q[3] * 2))))
            p.drawText(QRectF(pt.x() - s * 2, pt.y() - s, s * 4, s), Qt.AlignmentFlag.AlignCenter, q[2])
        self.popups = keep

    def _paint_hud(self, p: QPainter, pal) -> None:
        g = self.game
        key = (g.score, g.level, g.lives, getattr(self, "best", 0), pal)
        self._hud.draw(p, key, self.width(), HUD_H, self.dpr(), lambda q: self._draw_hud(q, pal))

    def _draw_hud(self, p: QPainter, pal) -> None:
        g = self.game
        accent = QColor(pal[5])
        AC.hud_bar(p, self.width(), HUD_H, accent)
        AC.glow_text(p, QRectF(12, 0, 200, HUD_H), "BYTE CHASE", AC.font(12, weight=QFont.Weight.Black), accent,
                     align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        best = getattr(self, "best", 0)
        AC.hud_items(p, 150, 5, ((tr("SCORE"), g.score), (tr("LEVEL"), g.level), (tr("BEST"), max(best, g.score))),
                     accent)
        for i in range(max(0, min(g.lives, 6))):
            paint_byte(p, QPointF(self.width() - 22 - i * 24, HUD_H / 2), 22, C.RIGHT, 0.0, self.dpr(), glow=False)

    # -- the title intro -----------------------------------------------------------------------

    def paint_title(self, p: QPainter, rect: QRectF, t: float, dt: float) -> None:
        pal = PALETTES[0]
        bg = QLinearGradient(0, 0, 0, rect.height())
        bg.setColorAt(0, QColor("#06141c"))
        bg.setColorAt(1, QColor("#010406"))
        p.fillRect(rect, bg)
        traces, path, points, starts = self._title_assets(rect)
        now = time.monotonic()
        # circuit traces with a signal running along them
        p.setPen(QPen(QColor(45, 212, 191, 40), 2))
        for a, b in traces:
            p.drawLine(a, b)
        for i, (a, b) in enumerate(traces):
            k = (now * 0.8 + i * 0.137) % 1.0
            AC.blit_centred(p, AC.glow(pal[3], 5), a.x() + (b.x() - a.x()) * k, a.y() + (b.y() - a.y()) * k)
        box = path.boundingRect()
        off = QPointF(rect.center().x() - box.width() / 2, rect.height() * 0.36 - box.height() / 2)
        # bits fly in and become the title
        fly = AC.ease_out(min(1.0, t / 0.42))
        bit = AC.glow(pal[4], 4)
        for i, (pt, st) in enumerate(zip(points, starts)):
            k = max(0.0, min(1.0, fly * 1.25 - (i % 17) / 17 * 0.25))
            x = st.x() + (pt.x() + off.x() - st.x()) * k
            y = st.y() + (pt.y() + off.y() - st.y()) * k
            AC.blit_centred(p, bit, x, y)
        reveal = max(0.0, min(1.0, (t - 0.3) / 0.25))
        if reveal > 0:
            shown = path.translated(off)
            p.save()
            p.setClipRect(QRectF(off.x() - 10, 0, (box.width() + 20) * reveal, rect.height()))
            for width, alpha in ((14, 25), (7, 60)):
                c = QColor(pal[3])
                c.setAlpha(alpha)
                p.strokePath(shown, QPen(c, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                         Qt.PenJoinStyle.RoundJoin))
            fill = QLinearGradient(0, off.y(), 0, off.y() + box.height())
            fill.setColorAt(0, QColor("#ecfeff"))
            fill.setColorAt(0.55, QColor(pal[3]))
            fill.setColorAt(1, QColor("#0f766e"))
            p.fillPath(shown, fill)
            p.restore()
        # Byte runs across with the daemons behind
        run = max(0.0, min(1.0, (t - 0.45) / 0.5))
        if run > 0:
            s = max(26.0, min(44.0, rect.width() / 22))
            y = off.y() + box.height() + s * 1.6
            x = rect.left() - s + (rect.width() + 7 * s) * run
            paint_byte(p, QPointF(x, y), s, C.RIGHT, now, self.dpr())
            for i, name in enumerate(DAEMON_COLOURS):
                paint_daemon(p, QPointF(x - s * (1.6 + i * 1.25), y), s, name, C.RIGHT, 0, now + i, self.dpr())
        sub = QColor("#99f6e4")
        sub.setAlphaF(reveal)
        AC.glow_text(p, QRectF(rect.left(), off.y() + box.height() + 4, rect.width(), 26),
                     tr("collect every bit – turn the daemons with a root key"), AC.font(10.5), sub)
        AC.intro_hint(p, rect, t, QColor("#5eead4"))

    def _title_assets(self, rect: QRectF):
        key = (round(rect.width()), round(rect.height()))
        if self._title_cache is not None and self._title_cache[0] == key:
            return self._title_cache[1]
        rng = random.Random(42)
        traces = []
        for _ in range(16):
            x, y = rng.uniform(0, rect.width()), rng.uniform(0, rect.height())
            for _ in range(3):
                if rng.random() < 0.5:
                    nx, ny = x + rng.choice((-1, 1)) * rng.uniform(40, 160), y
                else:
                    nx, ny = x, y + rng.choice((-1, 1)) * rng.uniform(30, 120)
                traces.append((QPointF(x, y), QPointF(nx, ny)))
                x, y = nx, ny
        path = AC.fit_title("BYTE CHASE", rect.width() * 0.8, rect.height() * 0.25, start=80)
        points = [path.pointAtPercent(i / 160) for i in range(160)]
        starts = [QPointF(rng.uniform(0, rect.width()), rng.uniform(0, rect.height())) for _ in points]
        assets = (traces, path, points, starts)
        self._title_cache = (key, assets)
        return assets


def _lerp(a, b, t):
    if abs(a[0] - b[0]) + abs(a[1] - b[1]) > 1:      # a respawn or a jump across: no glide
        return b
    return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)


def paint_byte(p: QPainter, c: QPointF, s: float, facing, now: float, dpr: float = 1.0, *, hop: float = 0.0,
               glow: bool = True) -> None:
    """Byte: a small chip with pins and two LED eyes looking where it goes."""
    bob = math.sin(now * 9) * s * 0.03
    c = c + QPointF(0, bob - hop * s * 0.4)
    r = s * 0.34
    if glow:
        AC.blit_centred(p, AC.glow("#67e8f9", s * 0.7, dpr, 150), c.x(), c.y())
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#94a3b8"))
    for k in (-1, 0, 1):                                   # the pins
        p.drawRect(QRectF(c.x() - r - s * 0.08, c.y() + k * r * 0.55 - s * 0.03, s * 0.08, s * 0.06))
        p.drawRect(QRectF(c.x() + r, c.y() + k * r * 0.55 - s * 0.03, s * 0.08, s * 0.06))
    body = QLinearGradient(c.x(), c.y() - r, c.x(), c.y() + r)
    body.setColorAt(0, QColor("#f0fdff"))
    body.setColorAt(0.5, QColor("#a5f3fc"))
    body.setColorAt(1, QColor("#0891b2"))
    p.setBrush(body)
    p.drawRoundedRect(QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r), r * 0.35, r * 0.35)
    p.setBrush(QColor("#0b1320"))                         # the visor
    p.drawRoundedRect(QRectF(c.x() - r * 0.75, c.y() - r * 0.45, r * 1.5, r * 0.7), r * 0.3, r * 0.3)
    fx, fy = facing
    eye = QPointF(fx * r * 0.22, fy * r * 0.12)
    blink = 0.25 if int(now * 1.3) % 5 == 0 and (now * 1.3) % 1 < 0.12 else 1.0
    p.setBrush(QColor("#5eead4"))
    for side in (-1, 1):
        p.drawEllipse(c + eye + QPointF(side * r * 0.36, -r * 0.1), r * 0.15, r * 0.17 * blink)


def paint_daemon(p: QPainter, c: QPointF, s: float, name: str, facing, scared: int, now: float,
                 dpr: float = 1.0) -> None:
    """A daemon: a hovering hexagonal drone with an antenna."""
    bob = math.sin(now * 6 + len(name)) * s * 0.06
    c = c + QPointF(0, bob)
    colour = QColor(DAEMON_COLOURS.get(name, "#ffffff"))
    if scared:
        colour = QColor("#3b82f6")
        if scared < 15 and int(now * 8) % 2:
            colour = QColor("#f8fafc")
    AC.blit_centred(p, AC.glow(colour.name(), s * 0.75, dpr, 130), c.x(), c.y())
    r = s * 0.4
    pts = [c + QPointF(r * math.cos(math.pi / 3 * k + math.pi / 6), r * 0.92 * math.sin(math.pi / 3 * k + math.pi / 6))
           for k in range(6)]
    p.setPen(Qt.PenStyle.NoPen)
    body = QLinearGradient(c.x(), c.y() - r, c.x(), c.y() + r)
    body.setColorAt(0, colour.lighter(150))
    body.setColorAt(1, colour.darker(140))
    p.setBrush(body)
    p.drawPolygon(QPolygonF(pts))
    p.setPen(QPen(colour.lighter(160), max(1.0, s * 0.05)))
    tip = c + QPointF(0, -r * 1.45)
    p.drawLine(c + QPointF(0, -r * 0.9), tip)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#fef3c7") if int(now * 3) % 2 else colour.lighter(170))
    p.drawEllipse(tip, s * 0.06, s * 0.06)
    fx, fy = facing
    look = QPointF(fx * r * 0.18, fy * r * 0.1)
    if scared:
        p.setBrush(QColor("#e0f2fe"))
        for side in (-1, 1):
            p.drawEllipse(c + QPointF(side * r * 0.32, -r * 0.12), r * 0.11, r * 0.11)
        p.setPen(QPen(QColor("#e0f2fe"), max(1.0, s * 0.04)))
        wave = [c + QPointF(-r * 0.45 + k * r * 0.15, r * 0.3 + (r * 0.07 if k % 2 else -r * 0.07)) for k in range(7)]
        p.drawPolyline(QPolygonF(wave))
        p.setPen(Qt.PenStyle.NoPen)
        return
    p.setBrush(QColor("#f8fafc"))
    for side in (-1, 1):
        p.drawEllipse(c + QPointF(side * r * 0.32, -r * 0.08), r * 0.2, r * 0.22)
    p.setBrush(QColor("#0b1320"))
    for side in (-1, 1):
        p.drawEllipse(c + look + QPointF(side * r * 0.32, -r * 0.08), r * 0.1, r * 0.12)
