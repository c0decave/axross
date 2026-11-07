"""Tilt Maze in the Arcade window: the isometric board of core.arcade.tilt,
animated at 60 frames a second between the game's ticks.

Everything is drawn here - no image from anywhere: the board as a
floating slab in each world's colours with raised blocks, pits with
depth, pulsing teleporter rings, glowing bits and spinning keys; Bitling
(the player: an orb with an antenna) gliding between tiles, with a
squash-and-stretch jump and its shadow; the daemons as hovering
hexagonal drones that blink when they flee; sparks when something is
collected or caught; the board dropping in at the start of a level; the
camera following on boards larger than the window. The title intro drops
TILT MAZE in as blocks and lets Bitling hop across them. Sounds and each
world's music come from ui/arcade_audio.py.

What is cached, and why: the board - floor, pits, the slab's sides,
teleporter plates, the walls and the bits, in depth order - is drawn once
per level into a pixmap; a bit that is eaten is painted out by drawing
just that patch again (clipped). Per frame the layer is one blit; keys,
teleporter rings and the actors are drawn over it, and after each the few
walls standing in front of it are blitted again, so Bitling still walks
behind a block. (Blitting every wall and bit each frame was ~460 blits.)
"""

from __future__ import annotations

import math
import random
import time

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontMetricsF,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
    QTransform,
)

from core.arcade import chase as C
from core.arcade import tilt_levels as L
from core.arcade.tilt import TiltGame
from core.i18n import tr
from ui import arcade_common as AC

TICK_MS = 120
FRAME_MS = AC.FRAME_MS
KEYS = {Qt.Key.Key_Up: C.UP, Qt.Key.Key_W: C.UP, Qt.Key.Key_Down: C.DOWN, Qt.Key.Key_S: C.DOWN,
        Qt.Key.Key_Left: C.LEFT, Qt.Key.Key_A: C.LEFT, Qt.Key.Key_Right: C.RIGHT, Qt.Key.Key_D: C.RIGHT}
DAEMON_COLOURS = {"Tracker": "#ff4d6d", "Cutter": "#ffb703", "Drifter": "#8ecae6", "Warden": "#b388ff",
                  "Hopper": "#7bd88f"}
#: per world: (sky top, sky bottom, floor, block top, block side, accent)
PALETTES = (
    ("#10261c", "#05100b", "#1e3b2b", "#4caf7d", "#2f6e4f", "#d9f99d"),
    ("#121a33", "#060912", "#1c2747", "#5c7cfa", "#364fc7", "#a5d8ff"),
    ("#0b2530", "#040d12", "#173b4a", "#3bc9db", "#1c7c8c", "#c5f6fa"),
    ("#2b1d0e", "#110a04", "#40301c", "#e0a458", "#9c6b2f", "#ffe8cc"),
    ("#26112b", "#0e0611", "#3a1f42", "#c77dff", "#7b2cbf", "#f3d9fa"),
    ("#0f2a22", "#04100c", "#1d4337", "#63e6be", "#2b9a7a", "#e6fcf5"),
    ("#2a1515", "#100606", "#422323", "#ff8787", "#c0392b", "#ffe3e3"),
    ("#13202b", "#060b10", "#21384b", "#74c0fc", "#1971c2", "#e7f5ff"),
    ("#1b1b1b", "#080808", "#2d2d2d", "#ced4da", "#868e96", "#fff3bf"),
    ("#291a33", "#0d0711", "#3b2649", "#ffd43b", "#e8590c", "#fff9db"),
)
#: "jump" is sounded on the key itself - from the event it came a tick late, and twice
EVENT_SOUNDS = {"bit": "bit", "key": "key", "daemon": "daemon", "caught": "caught", "fall": "caught",
                "level": "level", "extra-life": "extra-life", "teleport": "gem", "complete": "exit-open"}
HUD_H = 36


class TiltView(AC.ArcadeView):
    """Tilt Maze, from *level* (the level select's choice)."""

    kind = "tilt"
    TICK_MS = TICK_MS
    JINGLE = "intro-tilt"
    DIRECTION_KEYS = frozenset(KEYS)

    def __init__(self, *, level: int = 1, audio=None, on_exit=None, on_progress=None, on_restart=None,
                 intro: bool = True, parent=None):
        super().__init__(audio=audio, on_exit=on_exit, on_progress=on_progress, on_restart=on_restart,
                         intro=intro, parent=parent)
        self.setMinimumSize(520, 400)
        self.game = TiltGame(level=level)
        self.held = AC.HeldKeys(KEYS)
        self.rng = random.Random(5)
        self._snapshot()
        self.cam = None
        self.intro = 1.0          # 1 -> 0: the board drops in
        self.dying = 0.0
        self._level_seen = self.game.level
        self._floor: QPixmap | None = None
        self._floor_key = None
        self._walls: set = set()
        self._teleports: list = []
        self._bits_drawn: set = set()
        self._floor_origin = QPointF()
        self._title_cache = None
        self._hud = AC.HudCache()
        self._start_music()
        self.start_loop()

    # -- the loop ------------------------------------------------------------------------------

    def _snapshot(self) -> None:
        g = self.game
        self.prev_player = g.player
        self.prev_daemons = [d.pos for d in g.daemons]

    def _start_music(self) -> None:
        if self.audio is not None:
            self.audio.music(9100 + self.game.spec.world, mood=("major", "dorian", "mixolydian", "minor",
                                                                 "phrygian")[self.game.spec.world % 5])

    def step(self) -> None:
        g = self.game
        if self.report_end(g.level, g.score):
            return
        if self.paused or self.intro_running() or self.intro > 0.35:
            return
        held = self.held.held()
        if held is not None and g.wanted == (0, 0):
            g.steer(held)              # caught or fallen while a key is held: it still steers
        self._snapshot()
        g.tick()
        self._last_tick = time.monotonic()
        pal = PALETTES[g.spec.world % len(PALETTES)]
        for event in g.events:
            if event in EVENT_SOUNDS:
                self.sound(EVENT_SOUNDS[event], 0.55 if event == "bit" else 1.0)
            px, py = g.player
            if event == "bit":
                self.particles.burst(px + 0.5, py + 0.5, "#86efac", self.rng, n=6, speed=2.5, life=0.45, size=0.07,
                                     gravity=0.0)
            elif event == "key":
                self.particles.burst(px + 0.5, py + 0.5, "#fde047", self.rng, n=22, speed=4.0, life=0.8, size=0.1)
            elif event == "daemon":
                self.particles.burst(px + 0.5, py + 0.5, "#ffffff", self.rng, n=22, speed=4.5, life=0.7, size=0.1)
            elif event == "teleport":
                self.particles.burst(px + 0.5, py + 0.5, pal[5], self.rng, n=18, speed=3.0, life=0.6, size=0.09)
            if event in ("caught", "fall"):
                self.dying = 1.0
                self.particles.burst(self.prev_player[0] + 0.5, self.prev_player[1] + 0.5, "#67e8f9", self.rng,
                                     n=30, speed=4.0, life=0.8, size=0.1)
        g.events.clear()
        if g.level != self._level_seen:
            self._level_seen = g.level
            self.intro = 1.0
            self._snapshot()
            self._start_music()
            held = self.held.held()
            if held is not None:
                g.steer(held)          # a key held through the level change still steers
            self.report(g.level, g.score)
        self.report_end(g.level, g.score)

    def game_key(self, key, pressed, auto_repeat) -> bool:
        g = self.game
        if key in KEYS:
            if pressed:
                self.held.press(key, auto_repeat)
                g.steer(KEYS[key])
            else:
                self.held.release(key, auto_repeat)
            return True
        if key == Qt.Key.Key_Space:
            if pressed and not auto_repeat and not g.airborne and not g.falling and not self.finished():
                g.jump_now()
                self.sound("jump")
            return True
        return False

    def release_all(self) -> None:
        self.held.clear()

    # -- geometry ------------------------------------------------------------------------------

    @staticmethod
    def _lerp(a, b, t):
        if abs(a[0] - b[0]) + abs(a[1] - b[1]) > 2:     # a teleport or a respawn: no glide
            return b
        return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)

    def _progress(self) -> float:
        return self.tick_progress()

    def tile(self) -> tuple[float, float, float]:
        tw = max(26.0, min(self.width() / 14, 54.0))
        th = tw / 2
        return tw, th, th * 0.55          # low walls: the floor (bits, pits, daemons) stays in sight

    # -- the cached board ----------------------------------------------------------------------

    def _board_layer(self, tw: float, th: float, lift: float):
        """(pixmap, origin): the level's board; origin is where iso(0, 0) is in it."""
        g = self.game
        dpr = self.dpr()
        key = (g.level, id(g.grid), round(tw, 2), dpr)
        if self._floor is not None and self._floor_key == key:
            gone = self._bits_drawn - g.bits
            if gone:                                   # eaten: paint those patches again
                p = QPainter(self._floor)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                for x, y in gone:
                    self._paint_board(p, tw, th, lift, self._cell_box(x, y, tw, th, lift).adjusted(-2, -2, 2, 2))
                p.end()
                self._bits_drawn = set(g.bits)
            return self._floor, self._floor_origin
        w, h = g.width, g.height
        slab = th * 1.2
        margin = 4.0
        self._floor_origin = QPointF(h * tw / 2 + margin, lift + margin)
        width, height = (w + h) * tw / 2 + 2 * margin, (w + h) * th / 2 + lift + slab + 2 * margin
        pm = QPixmap(max(1, math.ceil(width * dpr)), max(1, math.ceil(height * dpr)))
        pm.setDevicePixelRatio(dpr)
        pm.fill(Qt.GlobalColor.transparent)
        self._floor, self._floor_key = pm, key
        self._walls = {(x, y) for y in range(h) for x in range(w) if g.grid[y][x] == C.WALL}
        self._teleports = [(x, y) for y in range(h) for x in range(w) if g.grid[y][x] == L.TELEPORT]
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_board(p, tw, th, lift, None)
        p.end()
        self._bits_drawn = set(g.bits)
        return pm, self._floor_origin

    def _cell_box(self, x: int, y: int, tw: float, th: float, lift: float) -> QRectF:
        """Where cell (x, y) - with a block on it - is in the board layer."""
        o = self._floor_origin
        return QRectF(o.x() + (x - y - 1) * tw / 2, o.y() + (x + y) * th / 2 - lift, tw, th + lift)

    def _paint_board(self, p: QPainter, tw: float, th: float, lift: float, clip: QRectF | None) -> None:
        """The board in depth order - all of it, or only what touches *clip*
        (cleared first)."""
        g = self.game
        pal = PALETTES[g.spec.world % len(PALETTES)]
        w, h = g.width, g.height
        o = self._floor_origin
        slab = th * 1.2
        p.setPen(Qt.PenStyle.NoPen)
        if clip is not None:
            p.setClipRect(clip)
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
            p.fillRect(clip, Qt.GlobalColor.transparent)
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)

        def iso(x, y):
            return QPointF(o.x() + (x - y) * tw / 2, o.y() + (x + y) * th / 2)

        down = QPointF(0, slab)
        left = QLinearGradient(iso(0, h), iso(0, h) + down)
        left.setColorAt(0, QColor(pal[4]).darker(160))
        left.setColorAt(1, QColor(pal[1]))
        p.setBrush(left)
        p.drawPolygon(QPolygonF([iso(0, h), iso(w, h), iso(w, h) + down, iso(0, h) + down]))
        right = QLinearGradient(iso(w, 0), iso(w, 0) + down)
        right.setColorAt(0, QColor(pal[4]).darker(200))
        right.setColorAt(1, QColor(pal[1]))
        p.setBrush(right)
        p.drawPolygon(QPolygonF([iso(w, h), iso(w, 0), iso(w, 0) + down, iso(w, h) + down]))
        floor_a, floor_b = QColor(pal[2]), QColor(pal[2]).lighter(110)
        edge = QColor(pal[3])
        edge.setAlpha(28)
        block = self._block(tw, th, lift)
        bit = AC.sprite("tilt-bit", tw * 0.3, tw * 0.3, _draw_bit, self.dpr())
        bw = tw * 0.15
        for depth in range(w + h - 1):
            for x in range(max(0, depth - h + 1), min(w, depth + 1)):
                y = depth - x
                if clip is not None and not self._cell_box(x, y, tw, th, lift).intersects(clip):
                    continue
                c = g.grid[y][x]
                a, b, cc, dd = iso(x, y), iso(x + 1, y), iso(x + 1, y + 1), iso(x, y + 1)
                if c == L.PIT:
                    p.setBrush(QColor(0, 0, 0, 235))
                    p.drawPolygon(QPolygonF([a, b, cc, dd]))
                    inner = QPointF(0, th * 0.35)
                    depth_grad = QLinearGradient(a, a + inner)
                    depth_grad.setColorAt(0, QColor(pal[2]).darker(220))
                    depth_grad.setColorAt(1, QColor(0, 0, 0, 0))
                    p.setBrush(depth_grad)
                    p.drawPolygon(QPolygonF([a, b, b + inner, a + inner]))
                    p.drawPolygon(QPolygonF([a, dd, dd + inner, a + inner]))
                    continue
                if c == C.WALL:
                    p.drawPixmap(QPointF(dd.x(), a.y() - lift), block)
                    continue
                p.setBrush(floor_a if (x + y) % 2 else floor_b)
                p.drawPolygon(QPolygonF([a, b, cc, dd]))
                p.setBrush(edge)
                p.drawPolygon(QPolygonF([a, b, b + QPointF(0, 1.2), a + QPointF(0, 1.2)]))
                centre = iso(x + 0.5, y + 0.5)
                if c == L.TELEPORT:
                    p.setBrush(QColor(pal[5]).darker(250))
                    p.drawEllipse(centre, tw * 0.3, th * 0.3)
                    p.setBrush(QColor(pal[5]).darker(150))
                    p.drawEllipse(centre, tw * 0.18, th * 0.18)
                if (x, y) in g.bits:
                    p.drawPixmap(QPointF(centre.x() - bw, centre.y() - th * 0.3 - bw), bit)
        p.setClipping(False)

    def _walls_in_front(self, p: QPainter, pos, depth: int, box: QRectF, iso, tw: float, lift: float) -> None:
        """Blit again, clipped to *box* (what was just drawn) and in depth
        order, the blocks standing in front of something at *pos*: inside
        the box the picture is then what drawing everything in depth order
        gives, outside it nothing changes."""
        block = self._block(tw, tw / 2, lift)
        ix, iy = math.floor(pos[0]), math.floor(pos[1])
        walls = self._walls
        front = sorted((x + y, x, y) for x in range(ix - 2, ix + 4) for y in range(iy - 2, iy + 4)
                       if x + y > depth and (x, y) in walls)
        if not front:
            return
        p.save()
        p.setClipRect(box)
        for _d, x, y in front:
            p.drawPixmap(QPointF(iso(x, y + 1).x(), iso(x, y).y() - lift), block)
        p.restore()

    def _block(self, tw: float, th: float, lift: float) -> QPixmap:
        pal = PALETTES[self.game.spec.world % len(PALETTES)]

        def draw(p, w, _h):
            a, b, c, d = QPointF(w / 2, 0), QPointF(w, th / 2), QPointF(w / 2, th), QPointF(0, th / 2)
            up = QPointF(0, lift)
            p.setBrush(QColor(pal[4]).darker(125))
            p.drawPolygon(QPolygonF([d, c, c + up, d + up]))
            p.setBrush(QColor(pal[4]))
            p.drawPolygon(QPolygonF([c, b, b + up, c + up]))
            top = QLinearGradient(a, c)
            top.setColorAt(0, QColor(pal[3]).lighter(125))
            top.setColorAt(1, QColor(pal[3]))
            p.setBrush(top)
            p.drawPolygon(QPolygonF([a, b, c, d]))
            p.setPen(QPen(QColor(255, 255, 255, 70), 1))
            p.drawLine(d, a)
            p.drawLine(a, b)
        return AC.sprite(("tilt-block", pal), tw, th + lift, draw, self.dpr())

    # -- painting ------------------------------------------------------------------------------

    def _background(self, pal) -> QPixmap:
        def draw(p, w, h):
            sky = QLinearGradient(0, 0, 0, h)
            sky.setColorAt(0, QColor(pal[0]))
            sky.setColorAt(1, QColor(pal[1]))
            p.fillRect(QRectF(0, 0, w, h), sky)
            rng = random.Random(len(pal[0]) + w)
            for _ in range(70):
                c = QColor(pal[5])
                c.setAlpha(rng.randrange(20, 70))
                p.setBrush(c)
                r = rng.uniform(0.6, 1.8)
                p.drawEllipse(QPointF(rng.uniform(0, w), rng.uniform(0, h)), r, r)
        return AC.sprite(("tilt-sky", pal), self.width(), self.height(), draw, self.dpr())

    def paint_game(self, p: QPainter, dt: float) -> None:
        g = self.game
        pal = PALETTES[g.spec.world % len(PALETTES)]
        p.drawPixmap(0, 0, self._background(pal))
        t = self.tick_progress()
        player = self._lerp(self.prev_player, g.player, t)
        tw, th, lift = self.tile()
        target = ((player[0] - player[1]) * tw / 2, (player[0] + player[1]) * th / 2)
        if self.cam is None:
            self.cam = target
        k = 1 - math.exp(-dt * 7.5)
        self.cam = (self.cam[0] + (target[0] - self.cam[0]) * k, self.cam[1] + (target[1] - self.cam[1]) * k)
        if self.intro > 0:
            self.intro = max(0.0, self.intro - dt * 1.5)
        drop = (self.intro ** 2) * self.height()
        ox, oy = self.width() / 2 - self.cam[0], self.height() / 2 - self.cam[1] - drop

        def iso(x, y, z=0.0):
            return QPointF(ox + (x - y) * tw / 2, oy + (x + y) * th / 2 - z * lift)

        board, origin = self._board_layer(tw, th, lift)
        p.drawPixmap(QPointF(ox - origin.x(), oy - origin.y()), board)
        now = time.monotonic()
        dpr = self.dpr()
        # what moves or spins, in depth order; after each, the blocks in front of it
        things = []
        for x, y in g.keys:
            things.append((x + y, 0, "key", (x, y), None))
        for x, y in self._teleports:
            things.append((x + y, 0, "tele", (x, y), None))
        for i, d in enumerate(g.daemons):
            prev = self.prev_daemons[i] if i < len(self.prev_daemons) else d.pos
            pos = self._lerp(prev, d.pos, t)
            things.append((math.ceil(pos[0] + pos[1] - 1e-6), 1, "daemon", pos, d))
        things.append((math.ceil(player[0] + player[1] - 1e-6), 2, "player", player, None))
        things.sort(key=lambda th_: (th_[0], th_[1]))
        for depth, _order, kind, pos, actor in things:
            centre = iso(pos[0] + 0.5, pos[1] + 0.5)
            up = th * (2.6 if kind in ("player", "daemon") else 1.3)
            box = QRectF(centre.x() - tw * 0.6, centre.y() - up, tw * 1.2, up + th * 0.5)
            if kind == "key":
                _paint_key(p, centre, tw, th, now + pos[0])
            elif kind == "tele":
                pulse = 0.5 + 0.5 * math.sin(now * 5 + pos[0])
                p.setPen(QPen(QColor(pal[5]), 2))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(centre, tw * (0.22 + 0.08 * pulse), th * (0.22 + 0.08 * pulse))
                p.setPen(Qt.PenStyle.NoPen)
            elif kind == "daemon":
                self._paint_daemon(p, centre, tw, th, actor, now)
            else:
                self._paint_bitling(p, centre, tw, th, now, dt)
            self._walls_in_front(p, pos, depth, box, iso, tw, lift)
        self.particles.advance(dt)
        self.particles.draw(p, lambda x, y: iso(x, y, 1.2), tw, dpr)
        self._paint_hud(p, pal)

    def _paint_bitling(self, p, centre, tw, th, now, dt=0.016) -> None:
        g = self.game
        hop = 0.0
        squash = 1.0
        if g.airborne:
            k = 1 - (g.airborne - self.tick_progress()) / C.JUMP_TICKS
            hop = math.sin(max(0.0, min(1.0, k)) * math.pi) * th * 1.6
            squash = 1.0 + 0.15 * math.sin(k * math.pi)
        if g.falling:
            k = max(0.05, (g.falling - self.tick_progress()) / 8)
            squash = k
            hop = -(1 - k) * th
        if self.dying > 0:
            self.dying = max(0.0, self.dying - dt * 1.8)
        paint_bitling(p, centre, tw * 0.21, th, now, g.facing, hop, squash, self.dpr())

    def _paint_daemon(self, p, centre, tw, th, d, now) -> None:
        g = self.game
        bob = math.sin(now * 6 + len(d.name)) * th * 0.12
        fleeing = g.scared > 0
        colour = QColor("#3b82f6") if fleeing else QColor(DAEMON_COLOURS.get(d.name, "#ffffff"))
        if fleeing and g.scared < 15 and int(now * 8) % 2:
            colour = QColor("#f8fafc")
        r = tw * 0.22
        p.setBrush(QColor(0, 0, 0, 80))
        p.drawEllipse(centre, r, r * 0.45)
        body = centre - QPointF(0, th * 0.8 + bob)
        AC.blit_centred(p, AC.glow(colour.name(), r * 2.2, self.dpr(), 110), body.x(), body.y())
        pts = [body + QPointF(r * math.cos(math.pi / 3 * k + math.pi / 6),
                              r * 0.9 * math.sin(math.pi / 3 * k + math.pi / 6)) for k in range(6)]
        p.setBrush(colour.darker(140))
        p.drawPolygon(QPolygonF([q + QPointF(0, r * 0.35) for q in pts]))
        grad = QLinearGradient(body - QPointF(0, r), body + QPointF(0, r))
        grad.setColorAt(0, colour.lighter(140))
        grad.setColorAt(1, colour)
        p.setBrush(grad)
        p.drawPolygon(QPolygonF(pts))
        p.setBrush(QColor("#0b1320"))
        look = QPointF((d.facing[0] - d.facing[1]) * r * 0.15, 0)
        for side in (-1, 1):
            p.drawEllipse(body + look + QPointF(side * r * 0.33, -r * 0.05), r * 0.13, r * (0.05 if fleeing else 0.17))

    def _paint_hud(self, p, pal) -> None:
        g = self.game
        accent = QColor(pal[5])
        key = (g.spec.name, g.level, g.score, g.lives, pal)
        self._hud.draw(p, key, self.width(), HUD_H, self.dpr(), lambda q: self._draw_hud(q, pal))
        self._paint_message(p, accent)

    def _draw_hud(self, p, pal) -> None:
        g = self.game
        accent = QColor(pal[5])
        AC.hud_bar(p, self.width(), HUD_H, accent)
        AC.glow_text(p, QRectF(12, 0, 220, HUD_H), g.spec.name.upper(), AC.font(11.5, weight=QFont.Weight.Black),
                     accent, align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        x = AC.hud_items(p, 170, 5, ((tr("LEVEL"), f"{g.level}/100"), (tr("SCORE"), g.score)), accent)
        for i in range(max(0, min(g.lives, 6))):
            paint_bitling(p, QPointF(x + 8 + i * 20, HUD_H / 2 + 6), 7, 12, 0.0, C.RIGHT, 0, 1, self.dpr(),
                          shadow=False)
        p.setFont(AC.font(9))
        p.setPen(QColor(accent.red(), accent.green(), accent.blue(), 190))
        p.drawText(QRectF(0, 0, self.width() - 12, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                   tr("world code {code}").format(code=L.password(g.spec.world)))

    def _paint_message(self, p, accent) -> None:
        g = self.game
        title, hint = self.end_message()
        if title:
            AC.overlay(p, QRectF(self.rect()), title, hint, accent)
        elif self.intro > 0.05:
            c = QColor(accent)
            c.setAlphaF(min(1.0, self.intro * 1.6))
            AC.glow_text(p, QRectF(0, self.height() * 0.3, self.width(), 50), g.spec.name,
                         AC.font(28, weight=QFont.Weight.Black), c)
            c2 = QColor("#e2e8f0")
            c2.setAlphaF(min(1.0, self.intro * 1.6))
            AC.glow_text(p, QRectF(0, self.height() * 0.3 + 48, self.width(), 26),
                         tr("Level {n} of 100").format(n=g.level), AC.font(11), c2)

    def end_message(self):
        if self.game.completed and not self.paused:
            return tr("All 100 levels done!"), tr("Esc goes back")
        return super().end_message()

    # -- the title intro -----------------------------------------------------------------------

    def paint_title(self, p: QPainter, rect: QRectF, t: float, dt: float) -> None:
        pal = PALETTES[1]
        sky = QLinearGradient(0, 0, 0, rect.height())
        sky.setColorAt(0, QColor("#1b2a5c"))
        sky.setColorAt(1, QColor("#070a16"))
        p.fillRect(rect, sky)
        letters, size = self._title_letters(rect)
        total = sum(adv for _ch, _path, adv in letters)
        base_x = rect.center().x() - total / 2
        base_y = rect.height() * 0.42
        depth = size * 0.16
        # the tilt: letters sit on a plane seen from the corner
        tilt = QTransform()
        tilt.translate(rect.center().x(), base_y)
        tilt.shear(0.0, -0.18)
        tilt.translate(-rect.center().x(), -base_y)
        p.save()
        p.setTransform(tilt, True)
        x = base_x
        tops = []
        for i, (ch, path, adv) in enumerate(letters):
            k = (t - 0.05 - i * 0.045) / 0.22
            drop = AC.ease_out_back(k) if k > 0 else 0.0
            if k <= 0:
                x += adv
                tops.append(None)
                continue
            dy = (1 - drop) * -rect.height() * 0.7
            box = path.boundingRect()
            pos = QPointF(x, base_y - box.height() + dy)
            shape = path.translated(pos)
            for j in range(int(depth), 0, -2):                 # the extrusion
                p.fillPath(shape.translated(j * 0.5, j), QColor(pal[4]).darker(130 + j * 3))
            face = QLinearGradient(0, pos.y(), 0, pos.y() + box.height())
            face.setColorAt(0, QColor("#e0e7ff"))
            face.setColorAt(0.5, QColor(pal[3]).lighter(130))
            face.setColorAt(1, QColor(pal[3]))
            p.fillPath(shape, face)
            p.strokePath(shape, QPen(QColor(255, 255, 255, 120), 1.2))
            tops.append(tilt.map(QPointF(x + box.width() / 2, pos.y())) if ch != " " else None)
            x += adv
        p.restore()
        # Bitling hops from letter top to letter top
        hop_t = (t - 0.5) / 0.42
        stops = [q for q in tops if q is not None]
        if 0 <= hop_t <= 1 and len(stops) > 1:
            f = hop_t * (len(stops) - 1)
            i = min(len(stops) - 2, int(f))
            k = f - i
            a, b = stops[i], stops[i + 1]
            pos = QPointF(a.x() + (b.x() - a.x()) * k, a.y() + (b.y() - a.y()) * k - math.sin(k * math.pi) * size * 0.6)
            squash = 1 + 0.12 * math.sin(k * math.pi)
            paint_bitling(p, pos, size * 0.16, size * 0.2, time.monotonic(), C.RIGHT, 0, squash, self.dpr(),
                          shadow=False)
        sub = QColor("#c7d2fe")
        sub.setAlphaF(max(0.0, min(1.0, (t - 0.45) * 3)))
        AC.glow_text(p, QRectF(rect.left(), base_y + depth + 18, rect.width(), 26),
                     tr("100 levels on a tilted board - Space jumps"), AC.font(10.5), sub)
        AC.intro_hint(p, rect, t, QColor("#a5d8ff"))

    def _title_letters(self, rect: QRectF):
        key = (round(rect.width()), round(rect.height()))
        if self._title_cache is not None and self._title_cache[0] == key:
            return self._title_cache[1]
        size = max(24.0, min(rect.width() / 9.5, rect.height() / 5))
        f = AC.font(size, weight=QFont.Weight.Black)
        fm = QFontMetricsF(f)
        letters = []
        for ch in "TILT MAZE":
            path = AC.title_path(ch, size) if ch != " " else QPainterPath()
            letters.append((ch, path, fm.horizontalAdvance(ch) * 1.08))
        self._title_cache = (key, (letters, size))
        return letters, size


def _draw_bit(p: QPainter, w: float, _h: float) -> None:
    g = AC.glow("#4ade80", w / 2, 1.0, 140)
    p.drawPixmap(QRectF(0, 0, w, w), g, QRectF(0, 0, g.width(), g.height()))
    p.setBrush(QColor("#bbf7d0"))
    k = w * 0.14
    p.drawRect(QRectF(w / 2 - k, w / 2 - k, 2 * k, 2 * k))


def _paint_key(p: QPainter, centre: QPointF, tw: float, th: float, phase: float) -> None:
    w = abs(math.cos(phase * 3)) * tw * 0.16 + 1
    top = centre - QPointF(0, th * (0.7 + 0.15 * math.sin(phase * 4)))
    AC.blit_centred(p, AC.glow("#fde047", tw * 0.3), top.x(), top.y())
    p.setBrush(QColor("#fde047"))
    p.drawPolygon(QPolygonF([top - QPointF(0, tw * 0.18), top + QPointF(w, 0),
                             top + QPointF(0, tw * 0.18), top - QPointF(w, 0)]))
    p.setBrush(QColor(255, 255, 255, 160))
    p.drawPolygon(QPolygonF([top - QPointF(0, tw * 0.18), top + QPointF(w, 0), top]))


def paint_bitling(p: QPainter, centre: QPointF, r: float, th: float, now: float, facing, hop: float,
                  squash: float, dpr: float = 1.0, *, shadow: bool = True) -> None:
    """Bitling: a glowing orb with an antenna, *centre* its spot on the floor."""
    if shadow:
        p.setBrush(QColor(0, 0, 0, 90))
        p.drawEllipse(centre, r * max(0.4, 1.1 - hop / (th * 4)), r * 0.5)
    body = centre - QPointF(0, th * 0.55 + hop)
    AC.blit_centred(p, AC.glow("#22d3ee", r * 2.4, dpr, 120), body.x(), body.y())
    grad = QLinearGradient(body - QPointF(r, r), body + QPointF(r, r))
    grad.setColorAt(0, QColor("#e0fbff"))
    grad.setColorAt(0.55, QColor("#22d3ee"))
    grad.setColorAt(1, QColor("#0e7490"))
    p.setBrush(grad)
    p.drawEllipse(body, r / squash ** 0.5, r * squash)
    p.setPen(QPen(QColor("#a5f3fc"), max(1.0, r / 6)))
    tip = body - QPointF(r * 0.2, r * 1.6 * squash)
    p.drawLine(body - QPointF(0, r * squash * 0.9), tip)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#fef08a") if int(now * 4) % 2 else QColor("#facc15"))
    p.drawEllipse(tip, r * 0.18, r * 0.18)
    fx, fy = facing
    eye = QPointF((fx - fy) * r * 0.35, (fx + fy) * r * 0.12)
    p.setBrush(QColor("#0b1320"))
    for side in (-1, 1):
        p.drawEllipse(body + eye + QPointF(side * r * 0.3, -r * 0.1), r * 0.1, r * 0.16)
