"""What the Arcade's four game views share: the loop, the keys, the title
intro, the cached sprites and the HUD's look.

Why a base class: every view had its own copy of pause / mute / Esc / R,
its own timers and its own idea of which key is held - and each copy had
its own gaps (a tap shorter than a tick was lost, a held key was dropped
by a death or a level change). One :class:`ArcadeView` now owns them:

* **keys** come in through :meth:`ArcadeView.handle_key` - from the
  window's router (ui/arcade_window.py hands every key of the window to
  the current view, wherever Qt's focus is) or from the view's own
  keyPressEvent; :class:`HeldKeys` keeps the held direction keys (newest
  wins) and a tap made between two ticks, so a quick press still moves;
* **the title intro** (:class:`TitleIntro`, 2-4 s, any key or click
  skips it) runs before the first tick, painted in each game's own style;
* **the frame** is painted at 60 Hz with Qt's precise timer, the game
  ticks on its own timer; views interpolate between ticks with
  :meth:`ArcadeView.tick_progress`;
* **sprites** (glows, dots) are rendered once into a QPixmap
  (:func:`sprite`) and blitted - a radial gradient per dot per frame was
  most of the paint time.
"""

from __future__ import annotations

import logging
import math
import time
from collections import OrderedDict

from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontMetricsF,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PyQt6.QtWidgets import QWidget

from core.i18n import tr

log = logging.getLogger(__name__)

FRAME_MS = 16
INTRO_SECONDS = 3.0
TITLE_FAMILIES = ["DejaVu Sans", "Noto Sans", "Liberation Sans", "sans-serif"]
MONO_FAMILIES = ["DejaVu Sans Mono", "Noto Sans Mono", "Liberation Mono", "monospace"]


def font(size: float, *, weight=QFont.Weight.Bold, mono: bool = False) -> QFont:
    f = QFont()
    f.setFamilies(MONO_FAMILIES if mono else TITLE_FAMILIES)
    f.setPointSizeF(max(1.0, size))
    f.setWeight(weight)
    return f


# -- keys ----------------------------------------------------------------------------------------


class HeldKeys:
    """The direction keys held down (newest last) and the taps since the
    last tick.

    Why both: a game that moves while a key is held samples the keys once
    per tick; a press and release between two ticks (a quick tap, ~60 ms)
    was gone by then. :meth:`take` gives the newest held key, else the
    last tap. Auto-repeat presses count as held (the first, real press may
    have gone to another window); auto-repeat releases are ignored (X11
    sends a release before each repeat)."""

    def __init__(self, mapping: dict):
        self.mapping = mapping
        self.order: list = []
        self.taps: list = []

    def press(self, key, auto_repeat: bool = False) -> bool:
        if key not in self.mapping:
            return False
        if key not in self.order:
            self.order.append(key)
        if not auto_repeat:
            self.taps.append(key)
        return True

    def release(self, key, auto_repeat: bool = False) -> bool:
        if key not in self.mapping:
            return False
        if not auto_repeat and key in self.order:
            self.order.remove(key)
        return True

    def held(self):
        """The newest held direction, or None."""
        return self.mapping[self.order[-1]] if self.order else None

    def take(self):
        """The direction for this tick (held, else a tap), and the taps reset."""
        d = self.held()
        if d is None and self.taps:
            d = self.mapping[self.taps[-1]]
        self.taps.clear()
        return d

    def clear(self) -> None:
        self.order.clear()
        self.taps.clear()


# -- the title intro -----------------------------------------------------------------------------


class TitleIntro:
    """A game's opening title: *seconds* long, skipped by any key or click.
    ``t`` runs 0 -> 1 on the wall clock, so it plays at the same speed
    whatever the frame rate."""

    def __init__(self, seconds: float = INTRO_SECONDS):
        self.seconds = seconds
        self.started = time.monotonic()
        self.skipped = False

    @property
    def t(self) -> float:
        return 1.0 if self.skipped else min(1.0, (time.monotonic() - self.started) / self.seconds)

    @property
    def active(self) -> bool:
        return not self.skipped and self.t < 1.0

    def skip(self) -> None:
        self.skipped = True


def ease_out(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


def ease_out_back(t: float) -> float:
    t = max(0.0, min(1.0, t))
    c = 1.70158
    return 1 + (c + 1) * (t - 1) ** 3 + c * (t - 1) ** 2


def title_path(text: str, size: float) -> QPainterPath:
    """*text* as an outline, its bounding box at the origin."""
    path = QPainterPath()
    path.addText(QPointF(0, 0), font(size, weight=QFont.Weight.Black), text)
    box = path.boundingRect()
    return path.translated(-box.left(), -box.top())


def fit_title(text: str, width: float, height: float, *, start: float = 72.0) -> QPainterPath:
    """The largest title outline (from *start* pt down) that fits."""
    size = start
    while True:
        path = title_path(text, size)
        box = path.boundingRect()
        if (box.width() <= width and box.height() <= height) or size <= 10:
            return path
        size *= 0.9


# -- sprites -------------------------------------------------------------------------------------

_SPRITES: OrderedDict = OrderedDict()
_SPRITE_LIMIT = 800


def sprite(key, width: float, height: float, draw, dpr: float = 1.0) -> QPixmap:
    """A pixmap drawn once by ``draw(painter, w, h)`` and kept (LRU) under
    *key* - the views blit these instead of building gradients per frame."""
    full = (key, round(width, 1), round(height, 1), dpr)
    pm = _SPRITES.get(full)
    if pm is not None:
        _SPRITES.move_to_end(full)
        return pm
    pm = QPixmap(max(1, math.ceil(width * dpr)), max(1, math.ceil(height * dpr)))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    draw(p, width, height)
    p.end()
    _SPRITES[full] = pm
    while len(_SPRITES) > _SPRITE_LIMIT:
        _SPRITES.popitem(last=False)
    return pm


def glow(colour: str, radius: float, dpr: float = 1.0, strength: int = 200) -> QPixmap:
    """A soft round glow of *colour*, 2*radius wide."""
    radius = max(1.0, round(radius * 2) / 2)

    def draw(p, w, _h):
        g = QRadialGradient(QPointF(w / 2, w / 2), w / 2)
        c = QColor(colour)
        c.setAlpha(strength)
        g.setColorAt(0, c)
        c2 = QColor(colour)
        c2.setAlpha(strength // 3)
        g.setColorAt(0.45, c2)
        c3 = QColor(colour)
        c3.setAlpha(0)
        g.setColorAt(1, c3)
        p.setBrush(g)
        p.drawEllipse(QRectF(0, 0, w, w))
    return sprite(("glow", colour, strength), radius * 2, radius * 2, draw, dpr)


def blit_centred(p: QPainter, pm: QPixmap, x: float, y: float) -> None:
    dpr = pm.devicePixelRatio() or 1.0
    p.drawPixmap(QPointF(x - pm.width() / dpr / 2, y - pm.height() / dpr / 2), pm)


# -- particles -----------------------------------------------------------------------------------


class Particles:
    """Sparks in board units: [x, y, vx, vy, life, fade, colour, size, gravity].
    Advanced by the frame's real time (``dt`` seconds), drawn as glow
    sprites - no QColor or gradient made per spark per frame."""

    LIMIT = 600

    def __init__(self):
        self.items: list[list] = []

    def burst(self, x, y, colour, rng, n=12, speed=4.0, life=0.8, size=0.12, gravity=0.0, up=0.0) -> None:
        for _ in range(n):
            a = rng.uniform(0, 2 * math.pi)
            s = rng.uniform(0.25, 1.0) * speed
            self.items.append([x, y, math.cos(a) * s, math.sin(a) * s - up, 1.0, 1.0 / max(0.05, life),
                               colour, size * rng.uniform(0.6, 1.3), gravity])
        if len(self.items) > self.LIMIT:
            del self.items[:len(self.items) - self.LIMIT]

    def advance(self, dt: float) -> None:
        keep = []
        for q in self.items:
            q[0] += q[2] * dt
            q[1] += q[3] * dt
            q[3] += q[8] * dt
            q[4] -= q[5] * dt
            if q[4] > 0:
                keep.append(q)
        self.items = keep

    def draw(self, p: QPainter, to_screen, scale: float, dpr: float = 1.0) -> None:
        for q in self.items:
            r = max(1.0, q[7] * scale * (0.5 + q[4]))
            pm = glow(q[6], round(r * 2) / 2, dpr, 230)
            p.setOpacity(min(1.0, q[4] * 1.4))
            pt = to_screen(q[0], q[1])
            blit_centred(p, pm, pt.x(), pt.y())
        p.setOpacity(1.0)


def fill_fast(p: QPainter, rect: QRectF, colour) -> None:
    """fillRect on whole pixels without antialiasing: Qt's antialiased
    path rasterises a tall rectangle scanline by scanline (a band down the
    side of the board cost 2 ms, a full-window dim 3 ms+)."""
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    p.fillRect(rect.toAlignedRect(), colour)
    p.restore()


# -- HUD -----------------------------------------------------------------------------------------


def glow_text(p: QPainter, rect: QRectF, text: str, f: QFont, colour: QColor, *,
              align=Qt.AlignmentFlag.AlignCenter, halo: QColor | None = None) -> None:
    """Text with a soft dark (or coloured) halo - legible on any board."""
    if colour.alpha() == 0:
        return
    p.setFont(f)
    h = QColor(halo) if halo is not None else QColor(0, 0, 0, 170)
    h.setAlpha(int(h.alpha() * colour.alphaF()))         # fades with the text
    p.setPen(h)
    for dx, dy in ((-1.5, 0), (1.5, 0), (0, -1.5), (0, 1.5), (2, 2)):
        p.drawText(rect.translated(dx, dy), align, text)
    p.setPen(colour)
    p.drawText(rect, align, text)


def hud_bar(p: QPainter, width: float, height: float, accent: QColor) -> None:
    """The translucent strip the HUD sits on, with a thin accent line."""
    g = QLinearGradient(0, 0, 0, height)
    g.setColorAt(0, QColor(4, 6, 12, 220))
    g.setColorAt(1, QColor(4, 6, 12, 150))
    p.fillRect(QRectF(0, 0, width, height), g)
    line = QColor(accent)
    line.setAlpha(150)
    p.fillRect(QRectF(0, height - 1.5, width, 1.5), line)


def hud_items(p: QPainter, x: float, y: float, items, accent: QColor, *, height: float = 26) -> float:
    """``label VALUE`` pairs left to right; returns the x after the last."""
    small, big = font(8.5), font(12, mono=True)
    for label, value in items:
        p.setFont(small)
        p.setPen(QColor(accent.red(), accent.green(), accent.blue(), 170))
        lw = QFontMetricsF(small).horizontalAdvance(label)
        p.drawText(QRectF(x, y, lw + 4, height), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, label)
        x += lw + 6
        p.setFont(big)
        p.setPen(QColor("#f1f5f9"))
        vw = QFontMetricsF(big).horizontalAdvance(str(value))
        p.drawText(QRectF(x, y, vw + 4, height), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, str(value))
        x += vw + 18
    return x


def overlay(p: QPainter, rect: QRectF, title: str, hint: str, accent: QColor, *, dim: int = 120,
            centre_y: float | None = None) -> None:
    """A message over the board: dimmed, a panel, a title and a hint line
    (the panel at *centre_y*, else in the middle)."""
    if dim:
        fill_fast(p, rect, QColor(0, 0, 0, dim))
    tf, hf = font(max(14.0, min(26.0, rect.width() / 30))), font(10.5, weight=QFont.Weight.DemiBold)
    tw = QFontMetricsF(tf).horizontalAdvance(title)
    hw = QFontMetricsF(hf).horizontalAdvance(hint) if hint else 0
    w = min(rect.width() - 24, max(tw, hw) + 64)
    h = 64 + (26 if hint else 0)
    cy = rect.center().y() if centre_y is None else centre_y
    panel = QRectF(rect.center().x() - w / 2, cy - h / 2, w, h)
    p.setPen(QPen(QColor(accent.red(), accent.green(), accent.blue(), 200), 1.5))
    bg = QLinearGradient(panel.topLeft(), panel.bottomLeft())
    bg.setColorAt(0, QColor(10, 14, 24, 235))
    bg.setColorAt(1, QColor(4, 6, 12, 235))
    p.setBrush(bg)
    p.drawRoundedRect(panel, 12, 12)
    glow_text(p, QRectF(panel.left(), panel.top() + 10, panel.width(), 44), title, tf, accent)
    if hint:
        glow_text(p, QRectF(panel.left(), panel.bottom() - 36, panel.width(), 24), hint, hf, QColor("#cbd5e1"))


def intro_hint(p: QPainter, rect: QRectF, t: float, colour: QColor) -> None:
    """The blinking "any key" line at the bottom of a title intro."""
    a = 0.55 + 0.45 * math.sin(time.monotonic() * 5)
    c = QColor(colour)
    c.setAlphaF(max(0.0, min(1.0, a * min(1.0, t * 4))))
    glow_text(p, QRectF(rect.left(), rect.bottom() - 46, rect.width(), 30),
              tr("Any key or a click starts"), font(10.5, weight=QFont.Weight.DemiBold), c)


class HudCache:
    """One pixmap of a view's HUD, drawn again only when what it shows
    changed (*key*): text with a halo is the dearest thing in a frame."""

    def __init__(self):
        self.key = None
        self.pixmap: QPixmap | None = None

    def draw(self, p: QPainter, key, width: float, height: float, dpr: float, paint) -> None:
        full = (key, round(width), round(height), dpr)
        if self.pixmap is None or self.key != full:
            pm = QPixmap(max(1, math.ceil(width * dpr)), max(1, math.ceil(height * dpr)))
            pm.setDevicePixelRatio(dpr)
            pm.fill(Qt.GlobalColor.transparent)
            q = QPainter(pm)
            q.setRenderHint(QPainter.RenderHint.Antialiasing)
            paint(q)
            q.end()
            self.pixmap, self.key = pm, full
        p.drawPixmap(0, 0, self.pixmap)


# -- the view ------------------------------------------------------------------------------------


class ArcadeView(QWidget):
    """A running game: a tick timer for the rules, a frame timer for the
    picture, the keys every game shares (P pause, M mute, Esc back, R
    again when it is over) and the title intro. Subclasses make
    ``self.game`` and call :meth:`start_loop`; they implement
    :meth:`step` (one tick), :meth:`game_key`, :meth:`paint_game` and
    :meth:`paint_title`."""

    kind = ""
    TICK_MS = 100
    JINGLE = ""
    ACCENT = "#e2e8f0"
    DIRECTION_KEYS: frozenset = frozenset()
    #: The game's other keys (jump, grab, boost): with the directions, what a
    #: pause swallows.
    ACTION_KEYS: frozenset = frozenset()

    def __init__(self, *, audio=None, on_exit=None, on_progress=None, on_restart=None, intro: bool = True,
                 parent=None):
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.setMouseTracking(False)
        self.audio = audio
        self.on_exit, self.on_progress, self.on_restart = on_exit, on_progress, on_restart
        self.paused = False
        self._reported = False
        self.title: TitleIntro | None = TitleIntro() if intro else None
        self._last_tick = time.monotonic()
        self._last_frame = time.monotonic()
        self.particles = Particles()

    def start_loop(self) -> None:
        self.tick_timer = QTimer(self)
        self.tick_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.tick_timer.timeout.connect(self.step)
        self.tick_timer.start(self.TICK_MS)
        self.timer = self.tick_timer          # the name ArcadeWindow.back stops
        self.frame_timer = QTimer(self)
        self.frame_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.frame_timer.timeout.connect(self.update)
        self.frame_timer.start(FRAME_MS)
        if self.title is not None:
            self.sound(self.JINGLE)

    # -- state ---------------------------------------------------------------------------------

    def intro_running(self) -> bool:
        return self.title is not None and self.title.active

    def skip_intro(self) -> None:
        if self.title is not None:
            self.title.skip()
        self._last_tick = time.monotonic()

    def finished(self) -> bool:
        g = self.game
        return bool(getattr(g, "over", False) or getattr(g, "completed", False))

    def tick_progress(self) -> float:
        """0 -> 1 between the last tick and the next: what the painting
        interpolates with."""
        if self.paused:
            return 1.0
        return max(0.0, min(1.0, (time.monotonic() - self._last_tick) * 1000 / self.TICK_MS))

    def frame_dt(self) -> float:
        """Seconds since the last frame (capped: a stall is no jump)."""
        now = time.monotonic()
        dt, self._last_frame = min(0.05, max(0.0, now - self._last_frame)), now
        return 0.0 if self.paused else dt

    def sound(self, name: str, gain: float = 1.0) -> None:
        if self.audio is not None and name:
            self.audio.play(name, gain)

    def report(self, level: int, score: int, done: bool = False) -> None:
        if self.on_progress is not None:
            self.on_progress(level, score, done=done)

    def report_end(self, level: int, score: int) -> bool:
        """Keep the end once (game over or completed); True when it ended."""
        if self.finished() and not self._reported:
            self._reported = True
            self.report(level, score, done=True)
            self.tick_timer.stop()
            return True
        return self._reported

    # -- keys ----------------------------------------------------------------------------------

    def handle_key(self, event, pressed: bool) -> bool:
        """Every key of the window lands here (ArcadeWindow routes them);
        True when it was taken."""
        key, auto = event.key(), event.isAutoRepeat()
        if not pressed:
            # also while paused: a key let go must not stay held. The views
            # only forget held keys then, the game itself is not touched.
            return self.game_key(key, False, auto)
        if self.intro_running():
            if not auto:
                self.skip_intro()
            if key in self.DIRECTION_KEYS:     # a direction held through the intro counts
                self.game_key(key, True, auto)
            return True
        if key == Qt.Key.Key_P:
            if not auto:
                self.paused = not self.paused
                # the last move stays finished: no glide back to where it came from
                self._last_tick = time.monotonic() - self.TICK_MS / 1000
                self.update()
            return True
        if key == Qt.Key.Key_M:
            if not auto and self.audio is not None:
                self.audio.muted = not self.audio.muted
            return True
        if key == Qt.Key.Key_Escape:
            if not auto:
                self.leave()
            return True
        if key == Qt.Key.Key_R and self.finished():
            if not auto and self.on_restart is not None:
                self.shutdown()
                self.on_restart()
            return True
        if self.paused:
            # paused: no key changes the game (no jump, no turn, no boost)
            return key in self.DIRECTION_KEYS or key in self.ACTION_KEYS
        return self.game_key(key, True, auto)

    def game_key(self, key, pressed: bool, auto_repeat: bool) -> bool:  # noqa: ARG002 - for subclasses
        return False

    def release_all(self) -> None:
        """The window lost the keyboard: nothing is held any more."""

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt API
        if self.handle_key(event, True):
            event.accept()
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event) -> None:  # noqa: N802 - Qt API
        if self.handle_key(event, False):
            event.accept()
        else:
            super().keyReleaseEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.setFocus(Qt.FocusReason.MouseFocusReason)
        if self.intro_running():
            self.skip_intro()
        event.accept()

    def focusOutEvent(self, event) -> None:  # noqa: N802 - Qt API
        # a key released while another widget had the focus never arrives
        if event.reason() in (Qt.FocusReason.ActiveWindowFocusReason, Qt.FocusReason.PopupFocusReason):
            self.release_all()
        super().focusOutEvent(event)

    # -- leaving -------------------------------------------------------------------------------

    def leave(self) -> None:
        self.shutdown()
        if self.on_exit is not None:
            self.on_exit()

    def shutdown(self) -> None:
        for name in ("tick_timer", "frame_timer"):
            t = getattr(self, name, None)
            if t is not None:
                t.stop()
        if self.audio is not None:
            self.audio.music(None)

    # -- painting ------------------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        p = QPainter(self)
        try:
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            dt = self.frame_dt()
            title = self.title
            showing = title is not None and title.active
            t = title.t if title is not None else 1.0
            if not showing or t > 0.82:
                self.paint_game(p, dt)
            if showing:
                fade = 1.0 if t < 0.82 else max(0.0, 1 - (t - 0.82) / 0.18)
                p.setOpacity(fade)
                self.paint_title(p, QRectF(self.rect()), t, dt)
                p.setOpacity(1.0)
        finally:
            p.end()

    def paint_game(self, p: QPainter, dt: float) -> None:
        raise NotImplementedError

    def paint_title(self, p: QPainter, rect: QRectF, t: float, dt: float) -> None:
        raise NotImplementedError

    def dpr(self) -> float:
        return float(self.devicePixelRatioF() or 1.0)

    def end_message(self) -> tuple[str, str]:
        """(title, hint) of the overlay, ("", "") for none."""
        g = self.game
        if self.paused:
            return tr("Paused"), tr("P goes on – M mutes – Esc goes back")
        if getattr(g, "completed", False):
            return tr("All done!"), tr("Esc goes back")
        if getattr(g, "over", False):
            return tr("Game over"), tr("R plays again – Esc goes back")
        return "", ""
