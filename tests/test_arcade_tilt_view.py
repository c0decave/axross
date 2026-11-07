"""Tilt Maze in the Arcade window offscreen: the level select, the view
(ticks, animation frames, keys, sounds asked for), progress kept."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeAudio:
    def __init__(self):
        self.played, self.tunes, self.muted = [], [], False

    def play(self, name, gain=1.0):
        self.played.append(name)

    def music(self, seed, mood=""):
        self.tunes.append(seed)

    def stop(self):
        pass


def _window(tmp_path):
    from ui.arcade_window import ArcadeWindow

    audio = FakeAudio()
    win = ArcadeWindow(scores=tmp_path / "s.json", progress=tmp_path / "p.json", audio=audio)
    win.show()
    return win, audio


def test_happy_the_level_select_starts_continues_and_opens_worlds(tmp_path):
    from core.arcade import tilt_levels as L
    from ui import arcade_window as AW

    win, _audio = _window(tmp_path)
    sel = win.choose("tilt")
    assert not sel.cont.isEnabled()                      # nothing reached yet
    AW.save_progress("tilt", 37, tmp_path / "p.json")
    sel = win.choose("tilt")
    assert sel.cont.isEnabled() and "37" in sel.cont.text()
    sel.code.setText("nonsense")
    sel.code.returnPressed.emit()
    assert "no world code" in sel.message.text()
    sel.code.setText(L.password(6))
    sel.code.returnPressed.emit()
    assert win.view.game.level == 61
    win.close()


def test_happy_the_view_plays_animates_and_sounds(tmp_path):
    win, audio = _window(tmp_path)
    view = win.start_level("tilt", 1)
    view.tick_timer.stop()
    view.skip_intro()
    view.intro = 0
    assert audio.tunes and audio.tunes[-1] is not None    # the world's music
    QTest.keyClick(view, Qt.Key.Key_A)
    for _ in range(40):
        view.step()
    QTest.keyClick(view, Qt.Key.Key_Space)
    assert view.game.airborne and "jump" in audio.played
    assert "bit" in audio.played                         # bits were collected and sounded
    view._last_tick = time.monotonic() - 0.06            # half way between two ticks
    image = QImage(view.size(), QImage.Format.Format_ARGB32)
    view.render(image)
    assert len({image.pixel(x, y) for x in range(0, image.width(), 17) for y in range(0, image.height(), 17)}) > 20
    QTest.keyClick(view, Qt.Key.Key_P)
    assert view.paused
    QTest.keyClick(view, Qt.Key.Key_Escape)
    APP.processEvents()
    assert win.view is None and audio.tunes[-1] is None   # music off when leaving
    win.close()


def test_happy_reaching_a_level_is_kept(tmp_path):
    from ui import arcade_window as AW

    win, _audio = _window(tmp_path)
    view = win.start_level("tilt", 4)
    view.tick_timer.stop()
    view.skip_intro()
    view.intro = 0
    view.game.bits, view.game.keys = set(), set()
    view.step()
    assert view.game.level == 5 and AW.load_progress(tmp_path / "p.json")["tilt"] == 5
    win.close()


def test_happy_rockfall_view_wasd_space_sounds_and_paint(tmp_path):
    from core.arcade import rockfall as R

    win, audio = _window(tmp_path)
    view = win.start_level("rockfall", 1)
    view.tick_timer.stop()
    view.skip_intro()
    view.intro = 0
    g = view.game
    x, y = g.player
    g.grid[y][x + 1] = R.EARTH
    QTest.keyPress(view, Qt.Key.Key_Space)
    QTest.keyPress(view, Qt.Key.Key_D)
    view.step()
    assert g.player == (x, y) and g.grid[y][x + 1] == R.EMPTY      # taken, not stepped into
    assert "dig" in audio.played
    QTest.keyRelease(view, Qt.Key.Key_Space)
    view.step()
    assert g.player == (x + 1, y)                                   # now it walks
    QTest.keyRelease(view, Qt.Key.Key_D)
    view.step()
    assert g.player == (x + 1, y)                                   # released: stands
    image = QImage(view.size(), QImage.Format.Format_ARGB32)
    view.render(image)
    assert len({image.pixel(i, j) for i in range(0, image.width(), 17) for j in range(40, image.height(), 17)}) > 15
    QTest.keyClick(view, Qt.Key.Key_Escape)
    APP.processEvents()
    assert win.view is None
    win.close()


def test_happy_trail_runner_setup_two_players_boost_and_paint(tmp_path):
    from core.arcade import trails as T

    win, audio = _window(tmp_path)
    setup = win.choose("trails")
    setup.two.setChecked(True)
    setup.opponents.setValue(1)
    view = win.start_trails(setup.settings())
    view.tick_timer.stop()
    view.skip_intro()
    g = view.game
    assert len(g.riders) == 3 and g.riders[1].human
    for _ in range(31):
        view.step()                                         # the countdown
    assert "countdown" in audio.played and "go" in audio.played
    QTest.keyClick(view, Qt.Key.Key_W)
    QTest.keyClick(view, Qt.Key.Key_Up)
    view.step()
    assert g.riders[0].facing == T.UP and g.riders[1].facing == T.UP
    QTest.keyPress(view, Qt.Key.Key_Space)
    view.step()
    assert g.energy[0] < 100
    QTest.keyRelease(view, Qt.Key.Key_Space)
    image = QImage(view.size(), QImage.Format.Format_ARGB32)
    view.render(image)
    assert len({image.pixel(i, j) for i in range(0, image.width(), 13) for j in range(0, image.height(), 13)}) > 8
    QTest.keyClick(view, Qt.Key.Key_Escape)
    APP.processEvents()
    assert win.view is None
    win.close()
