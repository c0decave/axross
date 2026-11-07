"""ui/arcade_window.py and the Arcade extension offscreen: every game
starts, ticks, paints and takes its keys; best scores are kept."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.mark.parametrize("kind", ["chase", "tilt", "rockfall", "trails"])
def test_happy_every_game_starts_ticks_paints_and_steers(tmp_path, kind):
    from ui.arcade_window import ArcadeWindow

    win = ArcadeWindow(scores=tmp_path / "scores.json")
    win.show()
    view = win.start(kind, seed=7)
    view.timer.stop()
    QTest.keyClick(view, Qt.Key.Key_Left)
    for _ in range(40):
        view.step()
    image = QImage(view.size(), QImage.Format.Format_ARGB32)
    view.render(image)
    colours = {image.pixel(x, y) for x in range(0, image.width(), 13) for y in range(40, image.height(), 13)}
    assert len(colours) > 3, "the board was painted"
    QTest.keyClick(view, Qt.Key.Key_P)
    assert view.paused
    tick = getattr(view.game, "tick_count", None)
    view.step()
    assert getattr(view.game, "tick_count", None) == tick
    QTest.keyClick(view, Qt.Key.Key_Escape)
    APP.processEvents()
    assert win.view is None and win.stack.currentWidget() is win.picker
    win.close()


def test_happy_tilt_maze_jumps(tmp_path):
    from ui.arcade_window import ArcadeWindow

    win = ArcadeWindow(scores=tmp_path / "s.json")
    view = win.start("tilt", seed=3)
    view.timer.stop()
    view.skip_intro()
    view.intro = 0
    QTest.keyClick(view, Qt.Key.Key_Space)
    assert view.game.airborne > 0
    win.close()


def test_happy_a_best_score_is_kept_and_shown(tmp_path):
    from ui import arcade_window as AW

    path = tmp_path / "scores.json"
    assert AW.save_score("chase", 120, path) and not AW.save_score("chase", 80, path)
    assert AW.load_scores(path) == {"chase": 120}
    win = AW.ArcadeWindow(scores=path)
    assert win.picker.best_text("chase") == "best 120"
    view = win.start("rockfall", seed=1)
    view.timer.stop()
    view.skip_intro()
    view.game.score, view.game.over = 999, True
    view.step()
    assert AW.load_scores(path)["rockfall"] == 999
    QTest.keyClick(view, Qt.Key.Key_R)                # plays again
    assert win.view is not view and win.view.kind == "rockfall"
    win.close()


def test_happy_the_extension_opens_one_window():
    import importlib

    ext = importlib.import_module("resources.extensions.arcade")

    class Api:
        window = None
        actions = []

        def add_menu_action(self, text, callback, **_kw):
            self.actions.append((text, callback))
    api = Api()
    ext.activate(api)
    assert api.actions[0][0] == "Arcade…"
    first = api.actions[0][1]()
    assert api.actions[0][1]() is first
    ext.deactivate(api)
