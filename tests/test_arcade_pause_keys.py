"""The Arcade's pause: while a game is paused, no key changes it.

Only P (go on), M (mute) and Esc (back) did anything visible, but the game
keys still went to the games: Space started a Tilt Maze jump (and its
sound) while the board stood still, an arrow turned Bitling and the daemons'
chase, a tap moved the digger as soon as the game went on, Space boosted
a Trail Runner rider or even skipped to the next round. Letting go of a
key during the pause still counts - it is no longer held afterwards - but
the game itself only sees that when it goes on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
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


@pytest.fixture
def win(tmp_path):
    from ui.arcade_window import ArcadeWindow

    w = ArcadeWindow(scores=tmp_path / "s.json", progress=tmp_path / "p.json", audio=FakeAudio())
    w.show()
    w.activateWindow()
    QTest.qWaitForWindowActive(w)
    yield w
    w.close()


def _key(win, key, release=True):
    if release:
        QTest.keyClick(win.windowHandle(), key)
    else:
        QTest.keyPress(win.windowHandle(), key)
    APP.processEvents()


def _start(win, kind):
    view = win.start(kind, seed=5)
    view.tick_timer.stop()
    view.frame_timer.stop()
    view.skip_intro()
    if hasattr(view, "intro"):
        view.intro = 0
    APP.processEvents()
    return view


def _pause(win, view):
    _key(win, Qt.Key.Key_P)
    assert view.paused


def test_sad_space_does_not_jump_in_a_paused_tilt_maze(win):
    view = _start(win, "tilt")
    g = view.game
    _pause(win, view)
    played = list(win.audio.played)
    _key(win, Qt.Key.Key_Space)
    assert g.airborne == 0 and "jump" not in g.events
    assert win.audio.played == played                  # no jump sound either
    _key(win, Qt.Key.Key_P)                            # going on: Space jumps again
    _key(win, Qt.Key.Key_Space)
    assert g.airborne > 0


@pytest.mark.parametrize("kind", ["chase", "tilt"])
def test_sad_an_arrow_does_not_steer_a_paused_maze(win, kind):
    view = _start(win, kind)
    g = view.game
    wanted, facing = g.wanted, g.facing
    _pause(win, view)
    for key in (Qt.Key.Key_A, Qt.Key.Key_S, Qt.Key.Key_Left):
        _key(win, key)
    assert (g.wanted, g.facing) == (wanted, facing)
    view.step()                                        # paused: no tick
    _key(win, Qt.Key.Key_P)
    view.step()
    assert view.held.held() is None                    # nothing pressed in the pause is held


def test_sad_a_tap_in_a_pause_does_not_move_the_digger_later(win):
    from core.arcade import rockfall as R

    view = _start(win, "rockfall")
    g = view.game
    x, y = g.player
    g.grid[y][x + 1] = R.EARTH
    g.grid[y + 1][x] = R.EARTH
    _pause(win, view)
    _key(win, Qt.Key.Key_D)
    _key(win, Qt.Key.Key_Space)
    _key(win, Qt.Key.Key_S)
    _key(win, Qt.Key.Key_P)
    view.step()
    assert g.player == (x, y)
    assert g.grid[y][x + 1] == R.EARTH and g.grid[y + 1][x] == R.EARTH    # nothing dug either


def test_sad_space_does_not_boost_a_paused_rider(win):
    view = _start(win, "trails")
    g = view.game
    g.countdown = 0
    _pause(win, view)
    _key(win, Qt.Key.Key_Space, release=False)
    assert not g.boosting[0]
    QTest.keyRelease(win.windowHandle(), Qt.Key.Key_Space)
    APP.processEvents()


def test_sad_space_does_not_skip_a_round_while_paused(win):
    from core.arcade import trails_arena as A

    view = win.start_trails(A.Settings(opponents=2))
    view.tick_timer.stop()
    view.skip_intro()
    g = view.game
    g.countdown = 0
    g.riders[0].alive = False
    assert g.humans_out()
    round_no = g.round_no
    _pause(win, view)
    _key(win, Qt.Key.Key_Space)
    _key(win, Qt.Key.Key_Return)
    assert g.round_no == round_no and g.humans_out()


def test_edge_a_boost_let_go_in_the_pause_ends_when_the_game_goes_on(win):
    """The release is not lost (the rider would boost on for ever), and the
    paused game does not change before it goes on."""
    view = _start(win, "trails")
    g = view.game
    g.countdown = 0
    _key(win, Qt.Key.Key_Space, release=False)
    assert g.boosting[0]
    _pause(win, view)
    QTest.keyRelease(win.windowHandle(), Qt.Key.Key_Space)
    APP.processEvents()
    assert g.boosting[0]                               # paused: unchanged
    _key(win, Qt.Key.Key_P)
    view.step()
    assert not g.boosting[0]

