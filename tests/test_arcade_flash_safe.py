"""The arcade never flashes red and blinks at most 3 times a second.

Photosensitivity: the screen used to flash pink-red (255, 60, 90) when
Byte was caught, and frightened daemons blinked 8 times a second. Now the
screen dims with a dark veil and the daemons blink twice a second.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPointF  # noqa: E402
from PyQt6.QtGui import QImage, QPainter  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_caught_dims_the_screen_without_red():
    from ui.arcade_chase_view import ChaseView

    view = ChaseView(seed=1, intro=False)
    try:
        view.resize(320, 240)
        view.flash = 0.0
        before = view.grab().toImage()
        view.flash = 1.0
        after = view.grab().toImage()
        for x, y in ((5, 5), (160, 5), (315, 235)):
            b, a = before.pixelColor(x, y), after.pixelColor(x, y)
            dr, dg, db = a.red() - b.red(), a.green() - b.green(), a.blue() - b.blue()
            # the veil may darken or tint, but never push the picture toward red
            assert dr <= max(dg, db) + 10, (x, y, b.name(), a.name())
    finally:
        view.close()


def test_happy_frightened_daemons_blink_at_most_twice_a_second():
    from ui import arcade_chase_view as V

    def colour_at(now: float) -> str:
        img = QImage(64, 64, QImage.Format.Format_ARGB32)
        img.fill(0)
        p = QPainter(img)
        V.paint_daemon(p, QPointF(32, 32), 40.0, "root", (1, 0), 5, now, 1.0)
        p.end()
        c = img.pixelColor(32, 32)
        return "white" if c.blue() - c.red() < 60 else "blue"  # motion changes shade, not this

    samples = [colour_at(k / 100) for k in range(100)]  # one second
    assert {"white", "blue"} <= set(samples)  # it does blink
    changes = sum(1 for a, b in zip(samples, samples[1:]) if a != b)
    assert changes <= 6, changes  # 3 flashes = 6 transitions


# -- every game under the flash meter (review round 2) --------------------------------------

import random  # noqa: E402
import types  # noqa: E402

import pytest  # noqa: E402

np = pytest.importorskip("numpy")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flash_meter import ALLOWED, FlashMeter  # noqa: E402

FPS = 60


def _pixels(image: QImage):
    image = image.convertToFormat(QImage.Format.Format_RGB888)
    data = np.frombuffer(image.constBits().asstring(image.sizeInBytes()), np.uint8)
    rows = data.reshape(image.height(), image.bytesPerLine())
    return rows[:, : image.width() * 3].reshape(image.height(), image.width(), 3)


def _game(kind: str, level: int):
    if kind == "chase":
        from ui.arcade_chase_view import ChaseView

        view = ChaseView(seed=level, intro=True)
        view.game.level = level  # its palette
        return view
    if kind == "rockfall":
        from ui.arcade_rockfall_view import RockfallView

        return RockfallView(level=level, intro=True)
    if kind == "tilt":
        from ui.arcade_tilt_view import TiltView

        return TiltView(level=level, intro=True)
    from ui.arcade_trails_view import TrailsView

    return TrailsView(intro=True)


@pytest.mark.parametrize("kind, level", [("chase", 5), ("rockfall", 33), ("tilt", 61),
                                         ("trails", 1)])
def test_safety_no_game_flashes_from_its_title_through_its_worst_moments(monkeypatch, kind, level):
    """The title intro, then play with random keys while the game's jolts
    (Byte caught: the veil; a rock or a crash: the shake) come three times
    a second - more than play ever brings - under the flash meter at
    60 frames a second, in a world whose palette has the reddest accent."""
    from ui import (arcade_chase_view, arcade_common, arcade_rockfall_view, arcade_tilt_view,
                    arcade_trails_view)

    clock = [1000.0]
    fake = types.SimpleNamespace(monotonic=lambda: clock[0])
    for module in (arcade_common, arcade_chase_view, arcade_rockfall_view, arcade_tilt_view,
                   arcade_trails_view):
        monkeypatch.setattr(module, "time", fake)
    view = _game(kind, level)
    try:
        view.resize(view.minimumSize().expandedTo(view.minimumSizeHint()))
        width, height = view.width(), view.height()
        rng = random.Random(level)
        keys = sorted(view.DIRECTION_KEYS, key=int)
        meter = FlashMeter(width, height, FPS)
        image = QImage(width, height, QImage.Format.Format_RGB32)
        held, next_step = None, clock[0]
        for frame in range(6 * FPS):
            clock[0] += 1.0 / FPS
            if frame % 18 == 0:
                if held is not None:
                    view.game_key(held, False, False)
                held = rng.choice(keys)
                view.game_key(held, True, False)
            if frame > 3.2 * FPS and frame % (FPS // 3) == 0:
                for jolt in ("flash", "shake"):
                    if hasattr(view, jolt):
                        setattr(view, jolt, 1.0)
            while clock[0] >= next_step:
                view.step()
                next_step += view.TICK_MS / 1000
            view.render(image)
            meter.push(_pixels(image))
        luminance, red = meter.worst("luminance"), meter.worst("red")
        assert luminance <= ALLOWED and red <= ALLOWED, (kind, luminance, red)
    finally:
        view.shutdown()
        view.close()
