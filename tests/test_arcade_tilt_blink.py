"""The tilt maze's fleeing drones blink at most twice a second, as Chase's.

Chase's frightened daemons were slowed to two blinks a second (at most 3
flashes a second are allowed anywhere); the tilt maze's drones near the
end of their flight still went blue-white-blue 4 times a second (8
transitions) - each drone too small for the area rule, the user's rule
counts any area.
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


def test_safety_fleeing_drones_blink_at_most_twice_a_second():
    from ui.arcade_tilt_view import TiltView

    view = TiltView(level=1, intro=False)
    try:
        view.game.scared = 5  # near the end of the flight: the blinking part
        daemon = view.game.daemons[0]

        def colour_at(now: float) -> str:
            img = QImage(160, 160, QImage.Format.Format_ARGB32)
            img.fill(0)
            p = QPainter(img)
            view._paint_daemon(p, QPointF(80, 110), 80.0, 40.0, daemon, now)
            p.end()
            c = img.pixelColor(80, 110 - 32)
            return "white" if c.blue() - c.red() < 60 else "blue"

        samples = [colour_at(k / 120) for k in range(120)]  # one second
        assert {"white", "blue"} <= set(samples)  # it does blink
        changes = sum(1 for a, b in zip(samples, samples[1:]) if a != b)
        assert changes <= 4, changes  # two blinks a second, as Chase's
    finally:
        view.close()
        view.deleteLater()
