"""Rockfall in the Arcade window: core.arcade.rockfall_campaign's caves,
drawn and animated here - no image from anywhere.

The digger is a small round mining robot with a headlamp: it bobs as it
walks, its lamp lights the cave around it, it taps its foot when left
waiting. Earth has texture and lit ledges, walls are bevelled stone
blocks, rocks are shaded stones that turn as they fall and roll - and
glide down between two ticks instead of jumping a cell -, crystals
sparkle, prisms glint, crawlers and seekers move with a step animation,
the exit pulses once it opens; dust and shards fly, the screen shakes
when something is crushed. The camera follows the digger over caves
larger than the window. W A S D (or the arrows) move - a tap moves one
cell, a held key keeps walking; Space with a direction takes the cell
beside without stepping into it; P pauses, M mutes, Esc goes back. The
title intro drops ROCKFALL in as stone letters. Sounds and each world's
tune: ui/arcade_audio.py.

What is cached, and why: earth, walls and prisms (the terrain) change a
few cells a tick at most, so they live in one pixmap of the whole cave;
after a tick only the cells that changed (and the neighbours whose lit
edge depends on them) are drawn again. Rocks and crystals are sprites.
"""

from __future__ import annotations

import math
import random
import time

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
    QPolygonF,
    QRadialGradient,
)

from core.arcade import rockfall as R
from core.arcade import rockfall_campaign as RC
from core.i18n import tr
from ui import arcade_common as AC

TICK_MS = 95
FRAME_MS = AC.FRAME_MS
DIRS = {Qt.Key.Key_W: R.UP, Qt.Key.Key_Up: R.UP, Qt.Key.Key_S: R.DOWN, Qt.Key.Key_Down: R.DOWN,
        Qt.Key.Key_A: R.LEFT, Qt.Key.Key_Left: R.LEFT, Qt.Key.Key_D: R.RIGHT, Qt.Key.Key_Right: R.RIGHT}
#: per world: (background, earth, earth fleck, wall, wall edge, accent)
PALETTES = (
    ("#140d07", "#6b4a2f", "#8a6644", "#5e6670", "#8d96a0", "#ffd166"),
    ("#140a0a", "#8a4b3a", "#a8634f", "#615b57", "#8f8781", "#ffb4a2"),
    ("#0a0c16", "#3d3f6b", "#565991", "#4b5563", "#7b8794", "#a5b4fc"),
    ("#071210", "#2f5446", "#447565", "#45515a", "#6f7d88", "#99f6e4"),
    ("#160707", "#5b1f1f", "#7d2e2e", "#3f3f46", "#71717a", "#fdba74"),
)
EVENT_SOUNDS = {"dig": "dig", "gem": "gem", "exit-open": "exit-open", "crushed": "crushed", "crawler": "crawler",
                "time": "time", "level": "level", "prism": "gem", "complete": "exit-open"}
TERRAIN = (R.EARTH, R.WALL, RC.PRISM)
HUD_H = 36


class RockfallView(AC.ArcadeView):
    kind = "rockfall"
    TICK_MS = TICK_MS
    JINGLE = "intro-rockfall"
    DIRECTION_KEYS = frozenset(DIRS)
    ACTION_KEYS = frozenset({Qt.Key.Key_Space})

    def __init__(self, *, level: int = 1, audio=None, on_exit=None, on_progress=None, on_restart=None,
                 intro: bool = True, parent=None):
        super().__init__(audio=audio, on_exit=on_exit, on_progress=on_progress, on_restart=on_restart,
                         intro=intro, parent=parent)
        self.setMinimumSize(520, 400)
        self.game = RC.CaveGame(level=level)
        self.held = AC.HeldKeys(DIRS)
        self.space = False
        self._space_tap = False
        self.rng = random.Random(7)
        self.shake = 0.0
        self.cam = None
        self.spin: dict[tuple[int, int], float] = {}     # rock rotation by cell
        self.moving: dict[tuple[int, int], tuple[int, int]] = {}   # cell -> where it came from this tick
        self.idle = 0
        self.facing = R.RIGHT
        self.prev_player = self.game.player
        self._level_seen = self.game.level
        self.intro = 1.0
        self._ticks = 0
        self._terrain: QPixmap | None = None
        self._terrain_key = None
        self._terrain_rows: list[str] = []
        self._terrain_seen = -1
        self.title_sparks = AC.Particles()
        self._title_cache = None
        self._title_landed: set = set()
        self._title_shake = 0.0
        self._hud_cache = AC.HudCache()
        self._music()
        self.start_loop()

    def _music(self) -> None:
        if self.audio is not None:
            self.audio.music(8200 + self.game.spec.world, mood=("dorian", "minor", "phrygian", "mixolydian",
                                                                 "minor")[self.game.spec.world % 5])

    # -- input ---------------------------------------------------------------------------------

    def game_key(self, key, pressed, auto_repeat) -> bool:
        if key == Qt.Key.Key_Space:
            if pressed:
                self.space = True
                self._space_tap = self._space_tap or not auto_repeat
            elif not auto_repeat:
                self.space = False
            return True
        if key in DIRS:
            if pressed:
                self.held.press(key, auto_repeat)
                if DIRS[key][0]:
                    self.facing = DIRS[key]
            else:
                self.held.release(key, auto_repeat)
            return True
        return False

    def release_all(self) -> None:
        self.held.clear()
        self.space = self._space_tap = False

    # -- the loop ------------------------------------------------------------------------------

    def step(self) -> None:
        g = self.game
        if self.report_end(g.level, g.score):
            return
        if self.paused or self.intro_running() or self.intro > 0.4:
            return
        direction = self.held.take()
        grab = self.space or self._space_tap
        self._space_tap = False
        g.steer(direction, grab=grab)
        self.idle = 0 if direction else self.idle + 1
        self.prev_player = g.player
        grid_before = g.grid
        before = {(x, y): c for y, row in enumerate(g.grid) for x, c in enumerate(row) if c in (R.ROCK, R.GEM)}
        g.tick()
        self._ticks += 1
        after = {(x, y): c for y, row in enumerate(g.grid) for x, c in enumerate(row) if c in (R.ROCK, R.GEM)}
        moving = {}
        if g.grid is grid_before:
            for cell, kind in after.items():
                if before.get(cell) == kind:
                    continue
                x, y = cell
                for src in ((x, y - 1), (x - 1, y), (x + 1, y)):
                    if before.get(src) == kind and after.get(src) != kind:
                        moving[cell] = src
                        if kind == R.ROCK:
                            self.spin[cell] = self.spin.pop(src, (src[0] * 31 + src[1]) % 6) + \
                                (math.pi / 2 if src[0] <= x else -math.pi / 2)
                        break
        self.moving = moving
        self._last_tick = time.monotonic()
        pal = PALETTES[g.spec.world % len(PALETTES)]
        px, py = g.player
        for event in g.events:
            if event in EVENT_SOUNDS:
                self.sound(EVENT_SOUNDS[event], 0.6 if event == "dig" else 1.0)
            if event == "dig":
                self.particles.burst(px + 0.5 + self.facing[0] * 0.6, py + 0.5, pal[2], self.rng, n=6, speed=2.5,
                                     life=0.5, size=0.07, gravity=9.0, up=1.5)
            elif event in ("gem", "prism"):
                self.particles.burst(px + 0.5, py + 0.5, "#7dd3fc", self.rng, n=12, speed=3.5, life=0.6, size=0.08)
            elif event in ("crushed", "crawler"):
                self.shake = 1.0
                self.particles.burst(px + 0.5, py + 0.5, "#e5e7eb" if event == "crushed" else "#fb923c", self.rng,
                                     n=34, speed=6.0, life=0.8, size=0.12, gravity=6.0, up=2.0)
            elif event == "exit-open":
                ex, ey = g.exit
                self.particles.burst(ex + 0.5, ey + 0.5, "#86efac", self.rng, n=30, speed=4.0, life=1.0, size=0.1)
        g.events.clear()
        if g.level != self._level_seen:
            self._level_seen = g.level
            self.intro = 1.0
            self.cam = None
            self.spin.clear()
            self._music()
            self.report(g.level, g.score)
        self.report_end(g.level, g.score)

    # -- the cached terrain ----------------------------------------------------------------------

    def _terrain_layer(self, s: float, pal) -> QPixmap:
        g = self.game
        dpr = self.dpr()
        if g.width * s * g.height * s * dpr * dpr > 8e6:
            dpr = 1.0                          # a big cave on a HiDPI screen: keep the layer small
        key = (g.level, id(g.grid), round(s, 2), dpr)
        rows = ["".join(c if c in TERRAIN else " " for c in row) for row in g.grid] \
            if (self._terrain_key != key or self._terrain_seen != self._ticks) else self._terrain_rows
        if self._terrain is None or self._terrain_key != key:
            pm = QPixmap(max(1, math.ceil(g.width * s * dpr)), max(1, math.ceil(g.height * s * dpr)))
            pm.setDevicePixelRatio(dpr)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(Qt.PenStyle.NoPen)
            for y in range(g.height):
                for x in range(g.width):
                    self._paint_cell(p, rows, x, y, s, pal, dpr)
            p.end()
            self._terrain, self._terrain_key = pm, key
        elif rows is not self._terrain_rows:
            dirty = set()
            for y, (old, new) in enumerate(zip(self._terrain_rows, rows)):
                if old != new:
                    for x, (a, b) in enumerate(zip(old, new)):
                        if a != b:
                            dirty |= {(x, y), (x, y - 1), (x, y + 1)}
            if dirty:
                p = QPainter(self._terrain)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                p.setPen(Qt.PenStyle.NoPen)
                for x, y in dirty:
                    if 0 <= x < g.width and 0 <= y < g.height:
                        self._paint_cell(p, rows, x, y, s, pal, dpr)
                p.end()
        self._terrain_rows, self._terrain_seen = rows, self._ticks
        return self._terrain

    @staticmethod
    def _paint_cell(p: QPainter, rows, x: int, y: int, s: float, pal, dpr: float) -> None:
        """One cell of the terrain layer, from scratch (it covers the cell):
        sprites - a few variants of each kind - and the lit edges."""
        r = QRectF(x * s, y * s, s, s)
        c = rows[y][x]
        v = (x * 7 + y * 13) % 6
        p.drawPixmap(r.topLeft(), AC.sprite(("rf-back", pal, v % 3), s, s,
                                            lambda q, w, _h: _draw_back(q, w, pal, v % 3), dpr))
        if c == R.EARTH:
            p.drawPixmap(r.topLeft(), AC.sprite(("rf-earth", pal, v), s, s,
                                                lambda q, w, _h: _draw_earth(q, w, pal, v), dpr))
            above = rows[y - 1][x] if y > 0 else R.WALL
            below = rows[y + 1][x] if y + 1 < len(rows) else R.WALL
            base = QColor(pal[1])
            if above not in (R.EARTH, R.WALL):          # a lit ledge
                p.fillRect(QRectF(r.left(), r.top(), s, s * 0.09), base.lighter(150))
            if below not in (R.EARTH, R.WALL):          # its shadowed underside
                p.fillRect(QRectF(r.left(), r.bottom() - s * 0.1, s, s * 0.1), base.darker(170))
        elif c == R.WALL:
            p.drawPixmap(r.topLeft(), AC.sprite(("rf-wall", pal, y % 2), s, s,
                                                lambda q, w, _h: _draw_wall(q, w, pal, y % 2), dpr))
        elif c == RC.PRISM:
            p.drawPixmap(r.topLeft(), AC.sprite(("rf-prism", pal), s, s, lambda q, w, _h: _draw_prism(q, w, pal), dpr))

    # -- painting ------------------------------------------------------------------------------

    def cell_size(self) -> float:
        """Whole pixels: the terrain's sprites then meet without seams."""
        return float(int(max(28.0, min(self.width() / 20, self.height() / 13, 48.0))))

    def paint_game(self, p: QPainter, dt: float) -> None:
        g = self.game
        pal = PALETTES[g.spec.world % len(PALETTES)]
        dpr = self.dpr()
        AC.fill_fast(p, QRectF(self.rect()), QColor(pal[0]).darker(140))
        s = self.cell_size()
        t = self.tick_progress()
        px = self.prev_player[0] + (g.player[0] - self.prev_player[0]) * t
        py = self.prev_player[1] + (g.player[1] - self.prev_player[1]) * t
        if abs(g.player[0] - self.prev_player[0]) + abs(g.player[1] - self.prev_player[1]) > 1:
            px, py = g.player
        target = (px * s - self.width() / 2 + s / 2, py * s - self.height() / 2 + s / 2)
        target = (max(-s, min(g.width * s - self.width() + s, target[0])),
                  max(-s * 1.2 - HUD_H, min(g.height * s - self.height() + s, target[1])))
        k = 1 - math.exp(-dt * 9)
        self.cam = target if self.cam is None else (self.cam[0] + (target[0] - self.cam[0]) * k,
                                                    self.cam[1] + (target[1] - self.cam[1]) * k)
        if self.intro > 0:
            self.intro = max(0.0, self.intro - dt * 1.8)
        shake = (self.rng.uniform(-1, 1) * self.shake * s * 0.15, self.rng.uniform(-1, 1) * self.shake * s * 0.15)
        self.shake = max(0.0, self.shake - dt * 3)
        ox, oy = -self.cam[0] + shake[0], -self.cam[1] + shake[1] + (self.intro ** 2) * self.height()
        now = time.monotonic()
        p.drawPixmap(QRectF(ox, oy, g.width * s, g.height * s), self._terrain_layer(s, pal),
                     QRectF(0, 0, self._terrain.width(), self._terrain.height()))
        x0, x1 = max(0, int(self.cam[0] / s) - 1), min(g.width, int((self.cam[0] + self.width()) / s) + 2)
        y0, y1 = max(0, int(self.cam[1] / s) - 1), min(g.height, int((self.cam[1] + self.height()) / s) + 2)
        p.setPen(Qt.PenStyle.NoPen)
        gem = AC.sprite(("rock-gem",), s, s, _draw_gem, dpr)
        for y in range(y0, y1):
            row = g.grid[y]
            for x in range(x0, x1):
                c = row[x]
                if c not in (R.ROCK, R.GEM, R.EXIT):
                    continue
                cx, cy = x, y
                src = self.moving.get((x, y))
                if src is not None:
                    cx, cy = src[0] + (x - src[0]) * t, src[1] + (y - src[1]) * t
                if c == R.ROCK:
                    angle = self.spin.get((x, y), (x * 31 + y) % 6)
                    if src is not None:
                        angle -= (1 - t) * (math.pi / 2 if src[0] <= x else -math.pi / 2)
                    idx = round(angle / (math.pi / 8)) % 16
                    rock = AC.sprite(("rock", idx), s, s,
                                     lambda q, w, _h, a=idx * math.pi / 8: _draw_rock(q, w, a), dpr)
                    p.drawPixmap(QPointF(ox + cx * s, oy + cy * s), rock)
                elif c == R.GEM:
                    p.drawPixmap(QPointF(ox + cx * s, oy + cy * s), gem)
                    tw = 0.5 + 0.5 * math.sin((now + x * 0.37 + y * 0.11) * 4)
                    if tw > 0.85:
                        p.setOpacity((tw - 0.85) / 0.15)
                        AC.blit_centred(p, AC.glow("#ffffff", s * 0.18, dpr, 255),
                                        ox + (cx + 0.68) * s, oy + (cy + 0.28) * s)
                        p.setOpacity(1.0)
                else:
                    self._exit(p, QRectF(ox + x * s, oy + y * s, s, s), s, now)
        for cr in g.crawlers:
            paint_crawler(p, QRectF(ox + cr.pos[0] * s, oy + cr.pos[1] * s, s, s), s, now, "#fb923c", dpr)
        for sk in g.seekers:
            paint_crawler(p, QRectF(ox + sk.pos[0] * s, oy + sk.pos[1] * s, s, s), s, now, "#c084fc", dpr, eye=True)
        moving = self.prev_player != g.player and t < 1
        paint_digger(p, QRectF(ox + px * s, oy + py * s, s, s), s, now, self.facing, moving,
                     self.idle > 40, dpr)
        self.particles.advance(dt)
        self.particles.draw(p, lambda x, y: QPointF(ox + x * s, oy + y * s), s, dpr)
        # the cave darkens towards the window's edges; the headlamp warms the digger's spot
        p.drawPixmap(0, 0, AC.sprite(("rock-vignette",), self.width(), self.height(), _draw_vignette, dpr))
        AC.blit_centred(p, AC.glow("#fde68a", s * 2.2, dpr, 40), ox + (px + 0.5) * s, oy + (py + 0.4) * s)
        self._hud(p, pal, now)

    def _exit(self, p, r, s, now) -> None:
        pulse = 0.5 + 0.5 * math.sin(now * 6)
        AC.blit_centred(p, AC.glow("#4ade80", s * (0.75 + 0.15 * pulse), self.dpr(), 200), r.center().x(),
                        r.center().y())
        p.setBrush(QColor(4, 30, 14, 230))
        p.drawRoundedRect(r.adjusted(s * 0.18, s * 0.1, -s * 0.18, 0), s * 0.25, s * 0.25)
        p.setPen(QPen(QColor(134, 239, 172, int(160 + 90 * pulse)), max(1.5, s / 16)))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(r.adjusted(s * 0.18, s * 0.1, -s * 0.18, 0), s * 0.25, s * 0.25)
        p.setPen(Qt.PenStyle.NoPen)

    def _hud(self, p, pal, now) -> None:
        g = self.game
        accent = QColor(pal[5])
        seconds = g.time_left // 10
        blink = seconds <= 20 and int(now * 4) % 2
        key = (g.spec.name, g.gems, g.quota, g.level, g.score, g.lives, seconds, blink, pal)
        self._hud_cache.draw(p, key, self.width(), HUD_H, self.dpr(), lambda q: self._draw_hud(q, pal, blink))
        self._paint_message(p, accent)

    def _draw_hud(self, p, pal, blink) -> None:
        g = self.game
        accent = QColor(pal[5])
        AC.hud_bar(p, self.width(), HUD_H, accent)
        AC.glow_text(p, QRectF(12, 0, 200, HUD_H), g.spec.name.upper(), AC.font(11.5, weight=QFont.Weight.Black),
                     accent, align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        x = 160.0
        # crystals: a bar that fills to the quota
        p.setFont(AC.font(8.5))
        p.setPen(QColor(accent.red(), accent.green(), accent.blue(), 170))
        p.drawText(QRectF(x, 0, 70, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr("CRYSTALS"))
        x += QFontMetricsF(AC.font(8.5)).horizontalAdvance(tr("CRYSTALS")) + 8
        bar = QRectF(x, HUD_H / 2 - 5, 90, 10)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 255, 255, 30))
        p.drawRoundedRect(bar, 5, 5)
        frac = min(1.0, g.gems / max(1, g.quota))
        fill = QLinearGradient(bar.topLeft(), bar.topRight())
        fill.setColorAt(0, QColor("#0ea5e9"))
        fill.setColorAt(1, QColor("#a5f3fc") if frac < 1 else QColor("#86efac"))
        p.setBrush(fill)
        p.drawRoundedRect(QRectF(bar.left(), bar.top(), bar.width() * frac, bar.height()), 5, 5)
        p.setFont(AC.font(9, mono=True))
        p.setPen(QColor("#f1f5f9"))
        p.drawText(bar.adjusted(0, -1, 0, 1), Qt.AlignmentFlag.AlignCenter, f"{g.gems}/{g.quota}")
        x = bar.right() + 18
        seconds = g.time_left // 10
        x = AC.hud_items(p, x, 5, ((tr("CAVE"), f"{g.level}/40"), (tr("SCORE"), g.score), (tr("LIVES"), g.lives)),
                         accent)
        tcol = QColor("#f87171") if blink else QColor("#f1f5f9")
        p.setFont(AC.font(8.5))
        p.setPen(QColor(accent.red(), accent.green(), accent.blue(), 170))
        p.drawText(QRectF(x, 0, 50, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr("TIME"))
        x += QFontMetricsF(AC.font(8.5)).horizontalAdvance(tr("TIME")) + 6
        p.setFont(AC.font(12, mono=True))
        p.setPen(tcol)
        p.drawText(QRectF(x, 0, 60, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, str(seconds))
        p.setFont(AC.font(9))
        p.setPen(QColor(accent.red(), accent.green(), accent.blue(), 190))
        p.drawText(QRectF(0, 0, self.width() - 12, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                   tr("world code {code}").format(code=RC.password(g.spec.world)))

    def _paint_message(self, p, accent) -> None:
        g = self.game
        title, hint = self.end_message()
        if title:
            AC.overlay(p, QRectF(self.rect()), title, hint, accent)
        elif self.intro > 0.05:
            c = QColor(accent)
            c.setAlphaF(min(1.0, self.intro * 1.6))
            AC.glow_text(p, QRectF(0, self.height() * 0.32, self.width(), 50), g.spec.name,
                         AC.font(28, weight=QFont.Weight.Black), c)
            c2 = QColor("#e2e8f0")
            c2.setAlphaF(min(1.0, self.intro * 1.6))
            AC.glow_text(p, QRectF(0, self.height() * 0.32 + 48, self.width(), 26),
                         tr("{n} crystals – then the exit").format(n=g.quota), AC.font(11), c2)

    def end_message(self):
        if self.game.completed and not self.paused:
            return tr("All 40 caves done!"), tr("Esc goes back")
        return super().end_message()

    # -- the title intro -----------------------------------------------------------------------

    def paint_title(self, p: QPainter, rect: QRectF, t: float, dt: float) -> None:
        bg = QLinearGradient(0, 0, 0, rect.height())
        bg.setColorAt(0, QColor("#1c130b"))
        bg.setColorAt(1, QColor("#060402"))
        p.fillRect(rect, bg)
        letters, size, texture = self._title_assets(rect)
        total = sum(adv for _ch, _path, adv in letters)
        base_y = rect.height() * 0.46
        x = rect.center().x() - total / 2
        landed = self._title_landed
        jolt = self._title_shake
        p.save()
        p.translate(self.rng.uniform(-1, 1) * jolt * 6, self.rng.uniform(-1, 1) * jolt * 6)
        for i, (_ch, path, adv) in enumerate(letters):
            k = (t - 0.04 - i * 0.07) / 0.18
            if k <= 0:
                x += adv
                continue
            box = path.boundingRect()
            if k < 1:                                  # falling: from above the window to the floor
                y = -box.height() + base_y * k * k
            else:                                      # landed: a small bounce
                after = k - 1
                y = base_y - box.height() - abs(math.sin(after * 9)) * size * 0.08 * max(0.0, 1 - after * 3)
                if i not in landed:
                    landed.add(i)
                    jolt = 1.0
                    self.title_sparks.burst(x + box.width() / 2, base_y, "#c8a27a", self.rng, n=16, speed=160,
                                            life=0.7, size=5, gravity=300, up=90)
            shape = path.translated(x, y)
            p.fillPath(shape.translated(3, 4), QColor(0, 0, 0, 150))
            p.fillPath(shape, QBrush(texture))
            p.strokePath(shape, QPen(QColor(255, 220, 160, 90), 1.4))
            x += adv
        p.restore()
        self._title_shake = max(0.0, jolt - dt * 6)
        self.title_sparks.advance(dt)
        self.title_sparks.draw(p, QPointF, 1.0, self.dpr())
        # crystals light up around the title
        if t > 0.62:
            gem = AC.sprite(("rock-gem",), 30, 30, _draw_gem, self.dpr())
            rng = random.Random(9)
            for i in range(9):
                gx = rect.center().x() + rng.uniform(-0.45, 0.45) * rect.width()
                gy = base_y + rng.choice((-1, 1)) * rng.uniform(size * 0.9, size * 1.6)
                p.setOpacity(max(0.0, min(1.0, (t - 0.62 - i * 0.02) * 5)))
                p.drawPixmap(QPointF(gx - 15, gy - 15), gem)
            p.setOpacity(1.0)
        # the digger walks in under the title
        walk = max(0.0, min(1.0, (t - 0.55) / 0.4))
        if walk > 0:
            s = max(30.0, min(48.0, rect.width() / 20))
            dx = rect.left() - s + (rect.center().x() + s) * AC.ease_out(walk)
            paint_digger(p, QRectF(dx, base_y + size * 0.45, s, s), s, time.monotonic(), R.RIGHT, walk < 1, False,
                         self.dpr())
        sub = QColor("#fcd9a8")
        sub.setAlphaF(max(0.0, min(1.0, (t - 0.65) * 4)))
        AC.glow_text(p, QRectF(rect.left(), base_y + size * 0.45 + 52, rect.width(), 26),
                     tr("dig for crystals – mind the rocks"), AC.font(10.5), sub)
        AC.intro_hint(p, rect, t, QColor("#ffd166"))

    def _title_assets(self, rect: QRectF):
        key = (round(rect.width()), round(rect.height()))
        if self._title_cache is not None and self._title_cache[0] == key:
            return self._title_cache[1]
        size = max(24.0, min(rect.width() / 8.5, rect.height() / 4.5))
        while size > 14 and QFontMetricsF(AC.font(size, weight=QFont.Weight.Black)).horizontalAdvance("ROCKFALL") \
                * 1.06 > rect.width() * 0.88:
            size *= 0.92
        f = AC.font(size, weight=QFont.Weight.Black)
        fm = QFontMetricsF(f)
        letters = [(ch, AC.title_path(ch, size), fm.horizontalAdvance(ch) * 1.06) for ch in "ROCKFALL"]
        texture = QPixmap(160, 160)
        texture.fill(QColor("#8a7766"))
        tp = QPainter(texture)
        tp.setRenderHint(QPainter.RenderHint.Antialiasing)
        tp.setPen(Qt.PenStyle.NoPen)
        rng = random.Random(3)
        grad = QLinearGradient(0, 0, 0, 160)
        grad.setColorAt(0, QColor("#b8a491"))
        grad.setColorAt(1, QColor("#5c4a3b"))
        tp.fillRect(QRectF(0, 0, 160, 160), grad)
        for _ in range(260):
            c = QColor("#3d3027") if rng.random() < 0.6 else QColor("#d6c4b1")
            c.setAlpha(rng.randrange(60, 160))
            tp.setBrush(c)
            r = rng.uniform(0.8, 3.5)
            tp.drawEllipse(QPointF(rng.uniform(0, 160), rng.uniform(0, 160)), r, r * rng.uniform(0.5, 1))
        tp.end()
        assets = (letters, size, texture)
        self._title_cache = (key, assets)
        return assets


def _draw_rock(p: QPainter, s: float, angle: float) -> None:
    centre = QPointF(s / 2, s / 2)
    p.setBrush(QColor(0, 0, 0, 70))
    p.drawEllipse(centre + QPointF(s * 0.03, s * 0.36), s * 0.3, s * 0.07)
    grad = QRadialGradient(centre - QPointF(s * 0.15, s * 0.15), s * 0.6)
    grad.setColorAt(0, QColor("#e5e7eb"))
    grad.setColorAt(0.5, QColor("#9ca3af"))
    grad.setColorAt(1, QColor("#374151"))
    p.setBrush(grad)
    pts = []
    for k in range(8):
        a = angle + k * math.pi / 4
        rad = s * (0.43 if k % 2 else 0.38)
        pts.append(centre + QPointF(math.cos(a) * rad, math.sin(a) * rad))
    p.drawPolygon(QPolygonF(pts))
    p.setPen(QPen(QColor(31, 41, 55, 170), max(1.0, s / 24)))
    p.drawLine(centre + QPointF(math.cos(angle) * s * 0.1, math.sin(angle) * s * 0.1),
               centre + QPointF(math.cos(angle + 0.8) * s * 0.3, math.sin(angle + 0.8) * s * 0.3))
    p.drawLine(centre + QPointF(math.cos(angle + 3) * s * 0.05, math.sin(angle + 3) * s * 0.05),
               centre + QPointF(math.cos(angle + 2.6) * s * 0.25, math.sin(angle + 2.6) * s * 0.25))
    p.setPen(Qt.PenStyle.NoPen)


def _draw_gem(p: QPainter, s: float, _h: float) -> None:
    c = QPointF(s / 2, s / 2)
    g = AC.glow("#38bdf8", s * 0.5, 1.0, 110)
    p.drawPixmap(QRectF(0, 0, s, s), g, QRectF(0, 0, g.width(), g.height()))
    pts = [c + QPointF(0, -s * 0.38), c + QPointF(s * 0.3, -s * 0.08), c + QPointF(0, s * 0.38),
           c + QPointF(-s * 0.3, -s * 0.08)]
    grad = QLinearGradient(pts[0], pts[2])
    grad.setColorAt(0, QColor("#e0f2fe"))
    grad.setColorAt(0.5, QColor("#38bdf8"))
    grad.setColorAt(1, QColor("#0369a1"))
    p.setBrush(grad)
    p.drawPolygon(QPolygonF(pts))
    p.setBrush(QColor(255, 255, 255, 130))
    p.drawPolygon(QPolygonF([pts[0], pts[1], c + QPointF(0, -s * 0.05)]))
    p.setBrush(QColor(3, 105, 161, 120))
    p.drawPolygon(QPolygonF([pts[2], pts[3], c + QPointF(0, -s * 0.05)]))


def _draw_vignette(p: QPainter, w: float, h: float) -> None:
    g = QRadialGradient(QPointF(w / 2, h / 2), max(w, h) * 0.75)
    g.setColorAt(0, QColor(0, 0, 0, 0))
    g.setColorAt(0.45, QColor(0, 0, 0, 0))
    g.setColorAt(1, QColor(0, 0, 0, 150))
    p.fillRect(QRectF(0, 0, w, h), g)


def _draw_back(p: QPainter, s: float, pal, v: int) -> None:
    bg = QColor(pal[0])
    p.fillRect(QRectF(0, 0, s, s), bg)
    rng = random.Random(v * 977)
    p.setBrush(bg.lighter(140))
    for _ in range(2):
        p.drawEllipse(QPointF(rng.uniform(0.1, 0.9) * s, rng.uniform(0.1, 0.9) * s), s * 0.03, s * 0.03)


def _draw_earth(p: QPainter, s: float, pal, v: int) -> None:
    rng = random.Random(v * 7919 + 3)
    base = QColor(pal[1])
    shade = 100 + rng.randrange(-8, 9)
    grad = QLinearGradient(0, 0, 0, s)
    grad.setColorAt(0, base.lighter(shade + 8))
    grad.setColorAt(1, base.darker(112))
    p.fillRect(QRectF(0, 0, s, s), grad)
    p.setBrush(QColor(pal[2]))
    for _ in range(4):
        p.drawEllipse(QPointF(rng.uniform(0.12, 0.88) * s, rng.uniform(0.15, 0.88) * s),
                      s * rng.uniform(0.04, 0.08), s * rng.uniform(0.03, 0.06))
    p.setBrush(base.darker(150))
    for _ in range(3):
        p.drawEllipse(QPointF(rng.uniform(0.1, 0.9) * s, rng.uniform(0.1, 0.9) * s), s * 0.025, s * 0.025)


def _draw_wall(p: QPainter, s: float, pal, odd: int) -> None:
    p.fillRect(QRectF(0, 0, s, s), QColor(pal[0]))
    r = QRectF(0, 0, s, s)
    grad = QLinearGradient(r.topLeft(), r.bottomRight())
    grad.setColorAt(0, QColor(pal[4]))
    grad.setColorAt(1, QColor(pal[3]).darker(115))
    p.setBrush(grad)
    p.drawRoundedRect(r.adjusted(0.8, 0.8, -0.8, -0.8), s * 0.12, s * 0.12)
    p.setBrush(QColor(255, 255, 255, 40))
    p.drawRect(QRectF(s * 0.1, s * 0.08, s * 0.8, s * 0.07))
    p.setBrush(QColor(0, 0, 0, 70))
    p.drawRect(QRectF(s * 0.05, s * 0.5, s * 0.9, s * 0.05))
    p.drawRect(QRectF(s * (0.3 if odd else 0.65), s * 0.08, s * 0.05, s * 0.42))


def _draw_prism(p: QPainter, s: float, pal) -> None:
    pts = [QPointF(s / 2, s * 0.12), QPointF(s * 0.88, s * 0.85), QPointF(s * 0.12, s * 0.85)]
    face = QLinearGradient(pts[0], pts[2])
    face.setColorAt(0, QColor(255, 255, 255, 110))
    face.setColorAt(1, QColor(pal[5]).darker(150))
    p.setBrush(face)
    p.drawPolygon(QPolygonF(pts))
    p.setPen(QPen(QColor(pal[5]), max(1.0, s / 20)))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolygon(QPolygonF(pts))


def paint_crawler(p, r, s, now, colour, dpr=1.0, eye=False) -> None:
    c = r.center()
    wob = math.sin(now * 10) * s * 0.05
    AC.blit_centred(p, AC.glow(colour, s * 0.55, dpr, 90), c.x(), c.y())
    grad = QLinearGradient(c - QPointF(0, s * 0.3), c + QPointF(0, s * 0.3))
    grad.setColorAt(0, QColor(colour).lighter(140))
    grad.setColorAt(1, QColor(colour).darker(130))
    p.setBrush(grad)
    p.drawEllipse(c + QPointF(0, wob), s * 0.32, s * 0.26)
    p.setBrush(QColor(colour).darker(160))
    for k in (-1, 1):
        p.drawEllipse(c + QPointF(k * s * 0.22, s * 0.2 - wob), s * 0.09, s * 0.06)
    p.setBrush(QColor("#fefce8"))
    for k in (-1, 1):
        p.drawEllipse(c + QPointF(k * s * 0.1, -s * 0.05 + wob), s * 0.07, s * (0.08 if eye else 0.06))
    p.setBrush(QColor("#111827"))
    for k in (-1, 1):
        p.drawEllipse(c + QPointF(k * s * 0.1, -s * 0.04 + wob), s * 0.035, s * (0.05 if eye else 0.035))


def paint_digger(p, r, s, now, facing, moving, waiting, dpr=1.0) -> None:
    """The digger: a round mining robot with tracks, a helmet and a headlamp."""
    c = r.center()
    bob = math.sin(now * 16) * s * 0.04 if moving else 0.0
    tap = (math.sin(now * 8) > 0.6) if waiting else False
    body = c + QPointF(0, s * 0.06 + bob)
    p.setBrush(QColor(0, 0, 0, 80))
    p.drawEllipse(c + QPointF(0, s * 0.38), s * 0.3, s * 0.07)
    p.setBrush(QColor("#374151"))
    for k in (-1, 1):                                  # tracks
        p.drawRoundedRect(QRectF(body.x() + k * s * 0.18 - s * 0.1, body.y() + s * 0.16, s * 0.2,
                                 s * (0.12 if not (tap and k > 0) else 0.08)), s * 0.04, s * 0.04)
    grad = QRadialGradient(body - QPointF(s * 0.1, s * 0.12), s * 0.4)
    grad.setColorAt(0, QColor("#fde68a"))
    grad.setColorAt(1, QColor("#d97706"))
    p.setBrush(grad)
    p.drawEllipse(body, s * 0.28, s * 0.26)
    p.setBrush(QColor("#1f2937"))                      # helmet
    p.drawChord(QRectF(body.x() - s * 0.3, body.y() - s * 0.34, s * 0.6, s * 0.4), 0, 180 * 16)
    lamp = body + QPointF(facing[0] * s * 0.08, -s * 0.24)
    AC.blit_centred(p, AC.glow("#fffbbf", s * 0.45, dpr, 230), lamp.x(), lamp.y())
    p.setBrush(QColor("#fef9c3"))
    p.drawEllipse(lamp, s * 0.06, s * 0.06)
    p.setBrush(QColor("#111827"))
    eye = QPointF(facing[0] * s * 0.07, 0)
    for k in (-1, 1):
        p.drawEllipse(body + eye + QPointF(k * s * 0.09, -s * 0.02), s * 0.04, s * 0.05)
