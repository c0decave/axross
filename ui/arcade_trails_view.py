"""Trail Runner in the Arcade window: core.arcade.trails_arena drawn and
animated here - neon ribbons on a dark grid, riders with a halo that
glide between cells, a streak while they boost, sparks and a shaking
screen when one crashes, a 3-2-1-GO countdown, energy bars and the
match's score as pips. W A S D + Space (player 2: the arrows + Enter)
steer and boost; P pauses, M mutes, Esc goes back. Once every human
rider is out, Space or Enter ends the round at once - nobody has to
watch the computer riders finish (core.arcade.trails_arena's
``finish_round`` gives the point). The title intro lets two riders draw
a frame round TRAIL RUNNER. Sounds and the arena's tune:
ui/arcade_audio.py.

Turns are queued, one per tick: two quick presses inside one tick used
to be applied at once - the second checked against the first, not
against where the rider was going - so up-then-left from a rider going
right turned it round into its own trail.

What is cached, and why: the floor and the arena's walls change once a
round - one pixmap; the ribbons only grow, so each tick draws just the
new cells onto a second pixmap. Per frame only the newest piece of each
ribbon (the one the head glides along) and the heads are drawn.
"""

from __future__ import annotations

import itertools
import math
import random
import time

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
)
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.arcade import trails as T
from core.arcade import trails_arena as A
from core.i18n import tr
from ui import arcade_common as AC

TICK_MS = 70
P1 = {Qt.Key.Key_W: T.UP, Qt.Key.Key_S: T.DOWN, Qt.Key.Key_A: T.LEFT, Qt.Key.Key_D: T.RIGHT}
P2 = {Qt.Key.Key_Up: T.UP, Qt.Key.Key_Down: T.DOWN, Qt.Key.Key_Left: T.LEFT, Qt.Key.Key_Right: T.RIGHT}
SKIP_KEYS = (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter)
HUD_H = 40
FORM_STYLE = """
QWidget#arcadeForm { background: #070b14; color: #e2e8f0; }
QWidget#arcadeForm QLabel { color: #cbd5e1; }
QWidget#arcadeForm QPushButton { background: #111c2e; color: #e2e8f0; border: 1px solid #2a3b55;
    border-radius: 8px; padding: 8px 18px; font-weight: bold; }
QWidget#arcadeForm QPushButton:hover, QWidget#arcadeForm QPushButton:focus { border-color: #5eead4;
    background: #15253b; }
QWidget#arcadeForm QPushButton:disabled { color: #5b6b80; border-color: #1c2638; }
QWidget#arcadeForm QSpinBox, QWidget#arcadeForm QComboBox, QWidget#arcadeForm QLineEdit {
    background: #0d1626; color: #e2e8f0; border: 1px solid #2a3b55; border-radius: 6px; padding: 4px 8px; }
QWidget#arcadeForm QCheckBox { color: #cbd5e1; }
"""


class TrailsSetup(QWidget):
    """The match's settings before it starts."""

    def __init__(self, *, start, back):
        super().__init__()
        self.setObjectName("arcadeForm")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setStyleSheet(FORM_STYLE)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.addWidget(QLabel(tr("<h1 style='color:#2ee6c5'>Trail Runner</h1><p>Your rider leaves a wall "
                                   "behind. Make the others run into one first.</p>")))
        form = QFormLayout()
        self.opponents = QSpinBox()
        self.opponents.setRange(1, 3)
        self.opponents.setValue(2)
        self.difficulty = QComboBox()
        for key in ("easy", "normal", "hard"):
            self.difficulty.addItem(tr(key.capitalize()), key)
        self.difficulty.setCurrentIndex(1)
        self.two = QCheckBox(tr("Two players on this keyboard (W A S D + Space against the arrows + Enter)"))
        self.arena = QComboBox()
        self.arena.addItem(tr("Tournament (all arenas)"), -1)
        for i, name in enumerate(A.ARENAS):
            self.arena.addItem(tr(name), i)
        self.points = QSpinBox()
        self.points.setRange(1, 15)
        self.points.setValue(5)
        form.addRow(tr("Computer riders:"), self.opponents)
        form.addRow(tr("Difficulty:"), self.difficulty)
        form.addRow("", self.two)
        form.addRow(tr("Arena:"), self.arena)
        form.addRow(tr("Round wins to take the match:"), self.points)
        layout.addLayout(form)
        go = QPushButton(tr("Start"))
        go.clicked.connect(lambda: start(self.settings()))
        layout.addWidget(go)
        b = QPushButton(tr("Back"))
        b.clicked.connect(back)
        layout.addWidget(b)
        layout.addWidget(QLabel(tr("Esc goes back")))
        layout.addStretch(1)
        go.setAutoDefault(True)                     # Enter starts, as Space does
        b.setAutoDefault(True)
        self.default_focus = go

    def settings(self) -> A.Settings:
        return A.Settings(opponents=self.opponents.value(), difficulty=self.difficulty.currentData(),
                          two_players=self.two.isChecked(), arena=self.arena.currentData(),
                          target_points=self.points.value())


class TrailsView(AC.ArcadeView):
    kind = "trails"
    TICK_MS = TICK_MS
    JINGLE = "intro-trails"
    DIRECTION_KEYS = frozenset(P1) | frozenset(P2)
    ACTION_KEYS = frozenset(SKIP_KEYS)

    def __init__(self, *, settings: A.Settings | None = None, audio=None, on_exit=None, on_progress=None,
                 on_restart=None, intro: bool = True, parent=None):
        super().__init__(audio=audio, on_exit=on_exit, on_progress=on_progress, on_restart=on_restart,
                         intro=intro, parent=parent)
        self.setMinimumSize(560, 400)
        self.settings = settings or A.Settings()
        self.game = A.ArenaGame(self.settings, seed=random.randrange(1, 10**6))
        self.rng = random.Random(3)
        self.shake = 0.0
        self.banner = ""
        self.banner_t = 0.0
        self.turns: dict[int, list] = {0: [], 1: []}
        self._unboost: set[int] = set()          # boost keys let go during a pause
        self._floor: QPixmap | None = None
        self._floor_key = None
        self._ribbons: QPixmap | None = None
        self._ribbon_key = None
        self._paths: dict[int, list] = {}
        self._drawn: dict[int, int] = {}
        self._fresh: dict[int, int] = {}         # cells each rider made in the last tick
        self._trail_seen = 0
        self._border_drawn = None
        self._round_seen = self.game.round_no
        self._title_cache = None
        self._hud = AC.HudCache()
        if audio is not None:
            audio.music(7300 + (self.settings.arena if self.settings.arena >= 0 else 9), mood="minor")
        self._sync_paths()
        self.start_loop()

    # -- keys ----------------------------------------------------------------------------------

    def _turn(self, rider: int, direction) -> None:
        q = self.turns.setdefault(rider, [])
        if (not q or q[-1] != direction) and len(q) < 3:
            q.append(direction)
        self.sound("turn", 0.35)

    def game_key(self, key, pressed, auto_repeat) -> bool:
        g = self.game
        two = self.settings.two_players
        if not pressed:
            if auto_repeat:
                return key in SKIP_KEYS
            if key == Qt.Key.Key_Space:
                self._end_boost(0)
                return True
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if two:
                    self._end_boost(1)
                return True
            return key in P1 or key in P2
        if key in P1:
            if not auto_repeat:
                self._turn(0, P1[key])
            return True
        if key in P2:
            if not auto_repeat:
                self._turn(1 if two else 0, P2[key])     # one player: the arrows work too
            return True
        if key in SKIP_KEYS:
            if g.humans_out():
                if not auto_repeat:
                    self.next_round()
                return True
            rider = 0 if key == Qt.Key.Key_Space else 1
            if rider == 0 or two:
                self._unboost.discard(rider)
                g.boost(rider)
            return True
        return False

    def _end_boost(self, rider: int) -> None:
        """A boost key let go; during a pause the boost ends when the game
        goes on - a paused game does not change."""
        if self.paused:
            self._unboost.add(rider)
        else:
            self._unboost.discard(rider)
            self.game.boost(rider, False)

    def release_all(self) -> None:
        for i in range(len(self.game.boosting)):
            self.game.boost(i, False)
        self.turns = {0: [], 1: []}

    def next_round(self) -> None:
        """Space / Enter once the humans are out: the round ends now and the
        next one starts (its countdown) - or the match is over."""
        g = self.game
        if not g.finish_round():
            return
        self._handle_events()
        if not g.over:
            g.tick()                                     # the new round
            self._handle_events()
        self._sync_paths()
        self._last_tick = time.monotonic()
        self.report_end(0, g.riders[0].points * 100)

    # -- the loop ------------------------------------------------------------------------------

    def step(self) -> None:
        g = self.game
        if self.report_end(0, g.riders[0].points * 100):
            return
        if self.paused or self.intro_running():
            return
        for i in self._unboost:
            g.boost(i, False)
        self._unboost.clear()
        for i, q in self.turns.items():
            if q and i < len(g.riders):
                g.steer_rider(i, q.pop(0))
        alive_before = [r.alive for r in g.riders]
        g.tick()
        self._last_tick = time.monotonic()
        for i, r in enumerate(g.riders):
            if alive_before[i] and not r.alive and i < len(alive_before):
                self.sound("crash")
                self.shake = 1.0
                self.particles.burst(r.pos[0] + 0.5, r.pos[1] + 0.5, r.colour, self.rng, n=46, speed=14.0, life=0.9,
                                     size=0.35)
                self.particles.burst(r.pos[0] + 0.5, r.pos[1] + 0.5, "#ffffff", self.rng, n=14, speed=8.0, life=0.5,
                                     size=0.3)
        self._handle_events()
        self._sync_paths()
        self.report_end(0, g.riders[0].points * 100)

    def _handle_events(self) -> None:
        g = self.game
        for event in g.events:
            if event == "countdown":
                self.sound("countdown")
            elif event == "go":
                self.sound("go")
            elif event == "boost":
                self.sound("boost", 0.45)
            elif event.startswith("round:"):
                who = event.split(":", 1)[1]
                self.banner = tr("Draw") if who == "draw" else tr("{who} wins the round").format(who=who)
                self.banner_t = time.monotonic()
                self.sound("round")
        g.events.clear()

    def _sync_paths(self) -> None:
        """Bring each rider's ribbon (its cells in order) up to the trail."""
        g = self.game
        if g.round_no != self._round_seen or len(g.trail) < self._trail_seen:
            self._round_seen = g.round_no
            self._trail_seen = 0
            self._paths, self._drawn = {}, {}
            self._ribbons = None
            self.turns = {0: [], 1: []}
        fresh: dict[int, int] = {}
        for cell, i in itertools.islice(g.trail.items(), self._trail_seen, None):
            if i >= 0:
                self._paths.setdefault(i, []).append(cell)
                fresh[i] = fresh.get(i, 0) + 1
        self._trail_seen = len(g.trail)
        self._fresh = fresh

    # -- geometry ------------------------------------------------------------------------------

    def board(self) -> tuple[float, float, float]:
        g = self.game
        s = min((self.width() - 16) / g.width, (self.height() - HUD_H - 14) / g.height)
        ox = (self.width() - s * g.width) / 2
        oy = HUD_H + 6 + (self.height() - HUD_H - 14 - s * g.height) / 2
        return max(2.0, s), ox, oy

    # -- the cached layers ---------------------------------------------------------------------

    def _floor_layer(self, s: float, ox: float, oy: float) -> QPixmap:
        g = self.game
        dpr = self.dpr()
        key = (self.width(), self.height(), g.round_no, g.arena, dpr)
        if self._floor is not None and self._floor_key == key:
            return self._floor
        pm = QPixmap(max(1, int(self.width() * dpr)), max(1, int(self.height() * dpr)))
        pm.setDevicePixelRatio(dpr)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QLinearGradient(0, 0, 0, self.height())
        bg.setColorAt(0, QColor("#070b16"))
        bg.setColorAt(1, QColor("#020308"))
        p.fillRect(QRectF(0, 0, self.width(), self.height()), bg)
        floor = QRectF(ox, oy, g.width * s, g.height * s)
        p.fillRect(floor, QColor("#060a14"))
        p.setPen(QPen(QColor(90, 110, 160, 26), 1))
        for x in range(0, g.width + 1, 2):
            p.drawLine(QPointF(ox + x * s, oy), QPointF(ox + x * s, oy + g.height * s))
        for y in range(0, g.height + 1, 2):
            p.drawLine(QPointF(ox, oy + y * s), QPointF(ox + g.width * s, oy + y * s))
        p.setPen(QPen(QColor(120, 140, 200, 45), 1))
        for x in range(0, g.width + 1, 8):
            p.drawLine(QPointF(ox + x * s, oy), QPointF(ox + x * s, oy + g.height * s))
        for y in range(0, g.height + 1, 8):
            p.drawLine(QPointF(ox, oy + y * s), QPointF(ox + g.width * s, oy + y * s))
        p.setPen(Qt.PenStyle.NoPen)
        for x, y in g.walls:
            r = QRectF(ox + x * s, oy + y * s, s, s)
            p.setBrush(QColor("#28324a"))
            p.drawRect(r)
            p.setBrush(QColor("#3b4a6b"))
            p.drawRect(QRectF(r.left(), r.top(), s, max(1.0, s * 0.22)))
        p.end()
        self._floor, self._floor_key = pm, key
        return pm

    def _board_layer(self, s: float, ox: float, oy: float) -> QPixmap:
        """The floor with every finished piece of ribbon on it - one opaque
        pixmap, one blit a frame; new cells are drawn onto it once."""
        g = self.game
        dpr = self.dpr()
        key = (self.width(), self.height(), g.round_no, dpr)
        if self._ribbons is None or self._ribbon_key != key:
            pm = QPixmap(self._floor_layer(s, ox, oy))      # a copy: the floor stays clean
            self._ribbons, self._ribbon_key = pm, key
            self._drawn = {}
            self._border_drawn = None
        if self._border_drawn != g.shrink:                  # the border: once a round, again when it shrinks
            p = QPainter(self._ribbons)
            self._paint_border(p, s, ox, oy)
            p.end()
            self._border_drawn = g.shrink
        todo = []
        for i, path in self._paths.items():
            alive = i < len(g.riders) and g.riders[i].alive and not g.round_over
            upto = len(path) - (self._fresh.get(i, 0) if alive else 0)
            start = self._drawn.get(i, 0)
            if upto > start:
                todo.append((i, path[max(0, start - 1):upto]))
                self._drawn[i] = upto
        if todo:
            p = QPainter(self._ribbons)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            for i, cells in todo:
                colour = g.riders[i].colour if i < len(g.riders) else "#888888"
                _ribbon(p, [QPointF(ox + (x + 0.5) * s, oy + (y + 0.5) * s) for x, y in cells], s, colour,
                        gap=s * 2.5)
            p.end()
        return self._ribbons

    # -- painting ------------------------------------------------------------------------------

    def paint_game(self, p: QPainter, dt: float) -> None:
        g = self.game
        s, ox0, oy0 = self.board()
        jx = self.rng.uniform(-1, 1) * self.shake * 5
        jy = self.rng.uniform(-1, 1) * self.shake * 5
        self.shake = max(0.0, self.shake - dt * 2.5)
        ox, oy = ox0 + jx, oy0 + jy
        board = self._board_layer(s, ox0, oy0)
        if jx or jy:
            AC.fill_fast(p, QRectF(self.rect()), QColor("#020308"))
        p.drawPixmap(QPointF(jx, jy), board)
        self._paint_gates(p, s, ox, oy)
        t = self.tick_progress() if g.countdown == 0 and not g.round_over else 1.0
        dpr = self.dpr()
        for i, r in enumerate(g.riders):
            path = self._paths.get(i, [])
            start = max(0, self._drawn.get(i, 0) - 1)
            cells = path[start:]
            pts = [QPointF(ox + (x + 0.5) * s, oy + (y + 0.5) * s) for x, y in cells]
            if not r.alive:
                continue
            head = _along(pts, t) if len(pts) > 1 else (pts[0] if pts else
                                                         QPointF(ox + (r.pos[0] + 0.5) * s, oy + (r.pos[1] + 0.5) * s))
            if len(pts) > 1:
                shown = _cut(pts, t)
                _ribbon(p, shown, s, r.colour, gap=s * 2.5)
            boosting = i < len(g.boosting) and g.boosting[i]
            _paint_rider(p, head, s, r.colour, r.facing, boosting, dpr)
        self.particles.advance(dt)
        self.particles.draw(p, lambda x, y: QPointF(ox + x * s, oy + y * s), s, dpr)
        self._paint_hud(p)
        self._paint_message(p)

    def _paint_border(self, p, s, ox, oy) -> None:
        g = self.game
        m = g.shrink
        if m:                                                            # the field shrank: the lost band
            dark = QColor(0, 0, 0, 150)
            band = m * s
            for r in (QRectF(ox, oy, g.width * s, band), QRectF(ox, oy + (g.height - m) * s, g.width * s, band),
                      QRectF(ox, oy + band, band, (g.height - 2 * m) * s),
                      QRectF(ox + (g.width - m) * s, oy + band, band, (g.height - 2 * m) * s)):
                AC.fill_fast(p, r, dark)
        rect = QRectF(ox + m * s, oy + m * s, (g.width - 2 * m) * s, (g.height - 2 * m) * s)
        colour = QColor("#fbbf24") if g.wrap else QColor("#7dd3fc")
        for width, alpha in ((8, 30), (4, 70), (1.6, 230)):
            c = QColor(colour)
            c.setAlpha(alpha)
            _frame(p, rect, width, c)

    def _paint_gates(self, p, s, ox, oy) -> None:
        g = self.game
        if g.wrap:                                                       # the gates
            pulse = 0.5 + 0.5 * math.sin(time.monotonic() * 6)
            p.setPen(QPen(QColor(4, 6, 12), 6))
            left, right, top, bottom = ox, ox + g.width * s, oy, oy + g.height * s
            y1, y2 = oy + g.height / 3 * s, oy + 2 * g.height / 3 * s
            x1, x2 = ox + g.width / 3 * s, ox + 2 * g.width / 3 * s
            gates = ((QPointF(left, y1), QPointF(left, y2)), (QPointF(right, y1), QPointF(right, y2)),
                     (QPointF(x1, top), QPointF(x2, top)), (QPointF(x1, bottom), QPointF(x2, bottom)))
            for a, b in gates:
                p.drawLine(a, b)
            p.setPen(QPen(QColor(167, 243, 208, int(80 + 120 * pulse)), 1.5, Qt.PenStyle.DashLine))
            for a, b in gates:
                p.drawLine(a, b)
        p.setPen(Qt.PenStyle.NoPen)

    def _paint_hud(self, p) -> None:
        g = self.game
        key = (tuple((r.name, r.points, r.alive) for r in g.riders), g.countdown > 0, g.arena, g.round_no,
               g.target_points)
        self._hud.draw(p, key, self.width(), HUD_H, self.dpr(), self._draw_hud)
        x = 12.0
        p.setPen(Qt.PenStyle.NoPen)
        for i, r in enumerate(g.riders):                       # energy: changes every tick
            bar = QRectF(x + 18, 33, 96, 3.5)
            energy = g.energy[i] if i < len(g.energy) else 0
            p.setBrush(QColor(r.colour))
            p.drawRect(QRectF(bar.left(), bar.top(), bar.width() * energy / A.BOOST_MAX, bar.height()))
            x += max(140.0, 18 + g.target_points * 9 + 16)

    def _draw_hud(self, p) -> None:
        g = self.game
        AC.hud_bar(p, self.width(), HUD_H, QColor("#7dd3fc"))
        x = 12.0
        for i, r in enumerate(g.riders):
            c = QColor(r.colour)
            AC.blit_centred(p, AC.glow(r.colour, 9, self.dpr(), 200), x + 6, 13)
            p.setBrush(c)
            p.drawEllipse(QPointF(x + 6, 13), 4, 4)
            p.setFont(AC.font(9.5))
            p.setPen(QColor("#f1f5f9") if r.alive or g.countdown else QColor("#64748b"))
            p.drawText(QRectF(x + 16, 2, 110, 22), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       tr(r.name))
            p.setPen(Qt.PenStyle.NoPen)
            for k in range(g.target_points):                              # the match's pips
                p.setBrush(c if k < r.points else QColor(255, 255, 255, 35))
                p.drawEllipse(QPointF(x + 18 + k * 9 + 3, 27), 3, 3)
            p.setBrush(QColor(255, 255, 255, 30))
            p.drawRect(QRectF(x + 18, 33, 96, 3.5))
            x += max(140.0, 18 + g.target_points * 9 + 16)
        p.setFont(AC.font(9.5))
        p.setPen(QColor("#cbd5e1"))
        p.drawText(QRectF(0, 0, self.width() - 12, HUD_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                   tr("{arena} - round {n}").format(arena=tr(g.arena), n=g.round_no))

    def _paint_message(self, p) -> None:
        g = self.game
        accent = QColor(g.riders[0].colour)
        if g.countdown > 0 and not self.paused:
            n = g.countdown // 10 + 1
            frac = (g.countdown % 10 + 1 - self.tick_progress()) / 10
            size = 40 + 50 * max(0.0, frac)
            c = QColor("#f8fafc")
            c.setAlphaF(max(0.2, min(1.0, frac * 1.5)))
            AC.glow_text(p, QRectF(self.rect()), str(n), AC.font(size, weight=QFont.Weight.Black), c,
                         halo=QColor(accent.red(), accent.green(), accent.blue(), 120))
            if self.banner and time.monotonic() - self.banner_t < 3.0:
                AC.glow_text(p, QRectF(0, self.height() / 2 + 60, self.width(), 30), self.banner, AC.font(13),
                             QColor("#e2e8f0"))
            return
        title, hint = self.message()
        if title and g.humans_out() and not self.paused:     # leave the riders in sight
            AC.overlay(p, QRectF(self.rect()), title, hint, accent, dim=0, centre_y=self.height() * 0.8)
        elif title:
            AC.overlay(p, QRectF(self.rect()), title, hint, accent)
        elif self.banner and time.monotonic() - self.banner_t < 1.5:
            AC.glow_text(p, QRectF(self.rect()), self.banner, AC.font(22, weight=QFont.Weight.Black), QColor("#e0f2fe"))

    def message(self) -> tuple[str, str]:
        """(title, hint) of the overlay after the countdown, ("", "") for none."""
        g = self.game
        if g.over and not self.paused:
            best = max(g.riders, key=lambda rr: rr.points)
            return tr("{who} takes the match").format(who=tr(best.name)), tr("R plays again - Esc goes back")
        title, hint = self.end_message()
        if not title and g.humans_out():
            title = tr("You are out") if not self.settings.two_players else tr("Both of you are out")
            hint = tr("Space / Enter: next round")
        return title, hint

    # -- the title intro -----------------------------------------------------------------------

    def paint_title(self, p: QPainter, rect: QRectF, t: float, dt: float) -> None:
        p.fillRect(rect, QColor("#03050b"))
        p.setPen(QPen(QColor(90, 110, 160, 30), 1))
        step = 24
        shift = (time.monotonic() * 40) % step
        x = -shift
        while x < rect.width():
            p.drawLine(QPointF(x, 0), QPointF(x, rect.height()))
            x += step
        y = 0.0
        while y < rect.height():
            p.drawLine(QPointF(0, y), QPointF(rect.width(), y))
            y += step
        path = self._title_path(rect)
        box = path.boundingRect()
        off = QPointF(rect.center().x() - box.width() / 2, rect.height() * 0.42 - box.height() / 2)
        frame = QRectF(off.x() - 30, off.y() - 26, box.width() + 60, box.height() + 52)
        u = AC.ease_out(min(1.0, t / 0.55))
        a_path = [QPointF(-40, frame.top()), frame.topRight(), frame.bottomRight()]
        b_path = [QPointF(rect.width() + 40, frame.bottom()), frame.bottomLeft(), frame.topLeft()]
        dpr = self.dpr()
        for pts, colour in ((a_path, T.COLOURS[0]), (b_path, T.COLOURS[1])):
            shown = _cut(pts, u)
            _ribbon(p, shown, 9, colour)
            head = shown[-1]
            d = (shown[-1].x() - shown[-2].x(), shown[-1].y() - shown[-2].y()) if len(shown) > 1 else (1, 0)
            facing = (int(math.copysign(1, d[0])) if abs(d[0]) > abs(d[1]) else 0,
                      int(math.copysign(1, d[1])) if abs(d[1]) >= abs(d[0]) else 0)
            if u < 1:
                _paint_rider(p, head, 9, colour, facing, True, dpr)
        k = max(0.0, min(1.0, (t - 0.45) / 0.25))
        if k > 0:
            split = (1 - AC.ease_out(k)) * 16
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)   # where they meet: white
            for colour, dx in ((T.COLOURS[0], -split), (T.COLOURS[1], split)):
                c = QColor(colour)
                c.setAlphaF(k)
                p.fillPath(path.translated(off + QPointF(dx, 0)), c)
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
            core = QColor("#f8fafc")
            core.setAlphaF(k)
            for width, alpha in ((10, 30), (5, 70)):
                g = QColor(T.COLOURS[0])
                g.setAlpha(int(alpha * k))
                p.strokePath(path.translated(off), QPen(g, width))
            p.fillPath(path.translated(off), core)
        sub = QColor("#a7f3d0")
        sub.setAlphaF(max(0.0, min(1.0, (t - 0.6) * 4)))
        AC.glow_text(p, QRectF(rect.left(), frame.bottom() + 14, rect.width(), 26),
                     tr("leave a wall - make the others hit it first"), AC.font(10.5), sub)
        AC.intro_hint(p, rect, t, QColor(T.COLOURS[0]))

    def _title_path(self, rect: QRectF) -> QPainterPath:
        key = (round(rect.width()), round(rect.height()))
        if self._title_cache is None or self._title_cache[0] != key:
            self._title_cache = (key, AC.fit_title("TRAIL RUNNER", rect.width() * 0.72, rect.height() * 0.22, start=78))
        return self._title_cache[1]


def _frame(p: QPainter, rect: QRectF, width: float, colour: QColor) -> None:
    """A rectangle's outline as four filled bands - a wide antialiased pen
    round the whole arena cost more than the rest of the frame."""
    h = max(1, round(width / 2))
    r = rect.toAlignedRect()
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    p.fillRect(r.left() - h, r.top() - h, r.width() + 2 * h, 2 * h, colour)
    p.fillRect(r.left() - h, r.bottom() - h, r.width() + 2 * h, 2 * h, colour)
    p.fillRect(r.left() - h, r.top() + h, 2 * h, r.height() - 2 * h, colour)
    p.fillRect(r.right() - h, r.top() + h, 2 * h, r.height() - 2 * h, colour)
    p.restore()


def _cut(pts: list, u: float) -> list:
    """The polyline *pts* up to the fraction *u* of its length."""
    if len(pts) < 2:
        return list(pts)
    lengths = [math.hypot(b.x() - a.x(), b.y() - a.y()) for a, b in zip(pts, pts[1:])]
    total = sum(lengths) or 1.0
    want = max(0.0, min(1.0, u)) * total
    out = [pts[0]]
    for (a, b), seg in zip(zip(pts, pts[1:]), lengths):
        if want >= seg:
            out.append(b)
            want -= seg
            continue
        k = want / seg if seg else 0.0
        out.append(QPointF(a.x() + (b.x() - a.x()) * k, a.y() + (b.y() - a.y()) * k))
        break
    return out


def _along(pts: list, u: float) -> QPointF:
    return _cut(pts, u)[-1]


def _ribbon(p: QPainter, pts: list, s: float, colour: str, *, gap: float | None = None) -> None:
    """A neon ribbon along *pts*: a wide soft glow, the colour, a bright core.
    Points further apart than *gap* (a wrap gate on the board) are not joined."""
    if len(pts) < 2:
        return
    runs, run = [], [pts[0]]
    for a, b in zip(pts, pts[1:]):
        if gap is not None and abs(a.x() - b.x()) + abs(a.y() - b.y()) > gap:
            runs.append(run)
            run = [b]
        else:
            run.append(b)
    runs.append(run)
    base = QColor(colour)
    for width, alpha, c in ((s * 1.6, 34, base), (s * 0.7, 150, base), (max(1.0, s * 0.24), 235, base.lighter(170))):
        col = QColor(c)
        col.setAlpha(alpha)
        p.setPen(QPen(col, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        for r in runs:
            if len(r) > 1:
                p.drawPolyline(QPolygonF(r))
    p.setPen(Qt.PenStyle.NoPen)


def _paint_rider(p: QPainter, c: QPointF, s: float, colour: str, facing, boosting: bool, dpr: float) -> None:
    """A rider's head: a halo, a pointed light pod facing where it goes."""
    AC.blit_centred(p, AC.glow(colour, s * (2.6 if boosting else 1.9), dpr, 210), c.x(), c.y())
    fx, fy = facing
    if boosting:
        for k in range(1, 5):
            AC.blit_centred(p, AC.glow("#ffffff", s * (0.9 - k * 0.15), dpr, 160 - k * 30),
                            c.x() - fx * s * k * 0.9, c.y() - fy * s * k * 0.9)
    nose = QPointF(c.x() + fx * s * 0.9, c.y() + fy * s * 0.9)
    left = QPointF(c.x() - fy * s * 0.55 - fx * s * 0.5, c.y() + fx * s * 0.55 - fy * s * 0.5)
    right = QPointF(c.x() + fy * s * 0.55 - fx * s * 0.5, c.y() - fx * s * 0.55 - fy * s * 0.5)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(colour))
    p.drawPolygon(QPolygonF([nose, left, right]))
    p.setBrush(QColor("#ffffff"))
    p.drawEllipse(c, s * 0.32, s * 0.32)
