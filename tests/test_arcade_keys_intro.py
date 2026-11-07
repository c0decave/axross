"""The Arcade's keys, title intros and cached layers, offscreen.

Keys go the way a real key goes: into the window's QWindow
(QTest.keyClick on ``windowHandle()``), not straight into the view - the
bug was keys that reached another widget of the window (W A S D went
nowhere, an arrow key moved the focus back). Every game, every state:
from the picker, wherever the focus is, after a restart, a level change,
a death, a pause, a click.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QToolButton  # noqa: E402

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
    win.activateWindow()
    QTest.qWaitForWindowActive(win)
    return win, audio


def _key(win, key, release=True):
    """A key the way the keyboard sends it: to the window, not a widget."""
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


def _steered(view, direction) -> bool:
    if view.kind in ("chase", "tilt"):
        return view.game.wanted == direction
    if view.kind == "rockfall":
        return view.held.held() == direction
    return direction in view.turns.get(0, [])


# -- WASD wherever the focus is ------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["chase", "tilt", "rockfall", "trails"])
def test_happy_wasd_reaches_every_game_even_with_the_focus_on_a_corner_button(tmp_path, kind):
    from core.arcade import chase as C

    win, _audio = _window(tmp_path)
    view = _start(win, kind)
    buttons = [b for b in win.findChildren(QToolButton) if b.isVisible()]
    target = buttons[0] if buttons else win
    target.setFocus()                                  # what a click on the corner or Tab did
    APP.processEvents()
    if view.kind == "rockfall":
        _key(win, Qt.Key.Key_W, release=False)
        assert _steered(view, C.UP)
    else:
        _key(win, Qt.Key.Key_W)
        assert _steered(view, C.UP), "W reached the game"
    assert APP.focusWidget() is view                   # and the game has the focus back
    win.close()


def test_happy_wasd_after_restart_level_change_pause_and_a_click(tmp_path):
    from core.arcade import chase as C

    win, _audio = _window(tmp_path)
    view = _start(win, "chase")
    view.game.over = True
    _key(win, Qt.Key.Key_R)                            # plays again: a new view
    assert win.view is not view and win.view.kind == "chase"
    assert win.view.title is None                      # a restart skips the title intro
    view = win.view
    view.tick_timer.stop()
    _key(win, Qt.Key.Key_A)
    assert view.game.wanted == C.LEFT
    win.back()
    view = win.start_level("tilt", 4)
    view.tick_timer.stop()
    view.skip_intro()
    view.intro = 0
    view.game.bits, view.game.keys = set(), set()
    view.step()                                        # the next level
    assert view.game.level == 5
    _key(win, Qt.Key.Key_D)
    assert view.game.wanted == C.RIGHT
    _key(win, Qt.Key.Key_P)
    assert view.paused
    _key(win, Qt.Key.Key_P)
    assert not view.paused
    QTest.mouseClick(view, Qt.MouseButton.LeftButton, pos=QPoint(40, 200))
    _key(win, Qt.Key.Key_S)
    assert view.game.wanted == C.DOWN
    win.close()


def test_happy_a_held_key_still_steers_after_a_death_in_tilt_maze(tmp_path):
    from core.arcade import chase as C

    win, _audio = _window(tmp_path)
    view = _start(win, "tilt")
    _key(win, Qt.Key.Key_A, release=False)             # held down
    view.game._lose_life()                             # the rules stop Bitling: wanted (0, 0)
    assert view.game.wanted == (0, 0)
    view.step()
    assert view.game.wanted == C.LEFT                  # the held key steers again
    QTest.keyRelease(win.windowHandle(), Qt.Key.Key_A)
    win.close()


def test_happy_a_tap_between_two_ticks_still_moves_the_digger(tmp_path):
    from core.arcade import rockfall as R

    win, _audio = _window(tmp_path)
    view = _start(win, "rockfall")
    g = view.game
    x, y = g.player
    g.grid[y][x + 1] = R.EARTH
    _key(win, Qt.Key.Key_D)                            # press and release before the tick
    view.step()
    assert g.player == (x + 1, y)
    view.step()
    assert g.player == (x + 1, y)                      # one tap, one cell
    win.close()


def test_happy_two_quick_turns_in_one_tick_do_not_turn_the_rider_round(tmp_path):
    from core.arcade import trails as T

    win, _audio = _window(tmp_path)
    view = _start(win, "trails")
    g = view.game
    g.countdown = 0
    me = g.riders[0]
    assert me.facing == T.RIGHT
    _key(win, Qt.Key.Key_W)
    _key(win, Qt.Key.Key_A)                            # up, then left - inside one tick
    view.step()
    assert me.alive and me.facing == T.UP
    view.step()
    assert me.alive and me.facing == T.LEFT
    win.close()


def test_happy_a_lost_window_forgets_held_keys(tmp_path):
    win, _audio = _window(tmp_path)
    view = _start(win, "rockfall")
    _key(win, Qt.Key.Key_D, release=False)
    _key(win, Qt.Key.Key_Space, release=False)
    view.release_all()                                 # what the window does when it loses the keyboard
    assert view.held.held() is None and not view.space
    win.close()


# -- Esc -----------------------------------------------------------------------------------------


def test_happy_esc_leaves_a_game_for_the_picker_and_closes_the_window_from_the_picker(tmp_path):
    win, _audio = _window(tmp_path)
    _start(win, "chase")
    _key(win, Qt.Key.Key_Escape)
    assert win.view is None and win.stack.currentWidget() is win.picker and win.isVisible()
    win.choose("tilt")                                 # a form: Esc goes back too
    _key(win, Qt.Key.Key_Escape)
    assert win.view is None and win.isVisible()
    _key(win, Qt.Key.Key_Escape)                       # on the picker: the window closes
    assert not win.isVisible()


def test_happy_the_picker_is_played_with_the_game_keys(tmp_path):
    win, audio = _window(tmp_path)
    assert win.picker.kinds[win.picker.selected] == "chase"
    _key(win, Qt.Key.Key_D)
    assert win.picker.kinds[win.picker.selected] == "tilt" and "select" in audio.played
    _key(win, Qt.Key.Key_Right)
    _key(win, Qt.Key.Key_Return)
    assert win.view is not None and win.view.kind == "rockfall" and win.view.__class__.__name__ == "LevelSelect"
    win.close()


# -- Trail Runner: Space / Enter once the humans are out --------------------------------------


@pytest.mark.parametrize("key", [Qt.Key.Key_Space, Qt.Key.Key_Return])
def test_happy_space_or_enter_goes_to_the_next_round_once_the_human_crashed(tmp_path, key):
    from core.arcade import trails_arena as A

    win, audio = _window(tmp_path)
    view = win.start_trails(A.Settings(opponents=2))
    view.tick_timer.stop()
    view.skip_intro()
    g = view.game
    g.countdown = 0
    g.riders[0].alive = False                          # the human crashed, two computer riders ride on
    assert g.humans_out()
    title, hint = view.message()
    assert title and "Space / Enter" in hint            # the hint on the overlay
    round_no = g.round_no
    _key(win, key)
    assert g.round_no == round_no + 1 and g.countdown > 0      # the next round, its countdown
    assert sum(r.points for r in g.riders[1:]) == 1 and g.riders[0].points == 0
    assert "round" in audio.played
    assert all(r.alive for r in g.riders)
    win.close()


def test_happy_space_still_boosts_while_the_human_rides(tmp_path):
    from core.arcade import trails_arena as A

    win, _audio = _window(tmp_path)
    view = win.start_trails(A.Settings(opponents=1))
    view.tick_timer.stop()
    view.skip_intro()
    g = view.game
    g.countdown = 0
    round_no = g.round_no
    _key(win, Qt.Key.Key_Space, release=False)
    assert g.boosting[0] and g.round_no == round_no
    QTest.keyRelease(win.windowHandle(), Qt.Key.Key_Space)
    APP.processEvents()
    assert not g.boosting[0]
    win.close()


def test_happy_two_players_skip_only_when_both_are_out(tmp_path):
    from core.arcade import trails_arena as A

    win, _audio = _window(tmp_path)
    view = win.start_trails(A.Settings(opponents=1, two_players=True))
    view.tick_timer.stop()
    view.skip_intro()
    g = view.game
    g.countdown = 0
    g.riders[0].alive = False                          # player 1 out, player 2 still rides
    round_no = g.round_no
    _key(win, Qt.Key.Key_Return)                       # player 2's boost, no skip
    assert g.round_no == round_no and not g.humans_out()
    g.riders[1].alive = False
    assert g.humans_out() and "Space / Enter" in view.message()[1]
    _key(win, Qt.Key.Key_Return)
    assert g.round_no == round_no + 1
    win.close()


# -- the title intro -----------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["chase", "tilt", "rockfall", "trails"])
def test_happy_every_game_opens_with_a_title_intro_any_key_skips_it(tmp_path, kind):
    win, audio = _window(tmp_path)
    view = win.start(kind, seed=5)
    view.tick_timer.stop()
    assert view.intro_running() and f"intro-{kind}" in audio.played    # the jingle
    ticks = getattr(view.game, "tick_count", None), getattr(view.game, "countdown", None)
    view.step()
    assert (getattr(view.game, "tick_count", None), getattr(view.game, "countdown", None)) == ticks
    view.grab()                                        # the intro paints
    _key(win, Qt.Key.Key_Space)                        # any key - and Space does not jump / boost
    assert not view.intro_running()
    if kind == "tilt":
        assert not view.game.airborne
    win.close()


def test_happy_a_click_skips_the_intro_and_it_ends_by_itself(tmp_path):
    win, _audio = _window(tmp_path)
    view = win.start("chase", seed=1)
    view.tick_timer.stop()
    QTest.mouseClick(view, Qt.MouseButton.LeftButton, pos=QPoint(100, 100))
    assert not view.intro_running()
    win.back()
    view = win.start("rockfall")
    view.tick_timer.stop()
    view.title.started = time.monotonic() - view.title.seconds - 0.1
    assert not view.intro_running() and 2.0 <= view.title.seconds <= 4.0
    win.close()


# -- cached layers -------------------------------------------------------------------------------


def test_happy_static_layers_are_drawn_once_not_every_frame(tmp_path, monkeypatch):
    from ui import arcade_rockfall_view as RV

    win, _audio = _window(tmp_path)
    view = _start(win, "chase")
    view.grab()
    layer = view._layer
    view.step()
    view.grab()
    assert view._layer is layer                        # the maze: the same pixmap
    win.back()
    view = _start(win, "tilt")
    view.grab()
    floor = view._floor
    view.step()
    view.grab()
    assert view._floor is floor
    win.back()
    calls = []
    real = RV.RockfallView._paint_cell
    monkeypatch.setattr(RV.RockfallView, "_paint_cell",
                        staticmethod(lambda *a: (calls.append(a[2:4]), real(*a))[1]))
    view = _start(win, "rockfall")
    view.grab()
    g = view.game
    assert len(calls) == g.width * g.height            # built once
    calls.clear()
    x, y = g.player
    g.grid[y][x + 1] = RV.R.EARTH
    view.grab()
    view.step()                                        # nothing pressed: only the falls change cells
    QTest.keyClick(view, Qt.Key.Key_D)
    view.step()                                        # one cell dug
    view.grab()
    assert 0 < len(calls) < g.width * g.height // 4     # only what changed, and its neighbours
    win.back()
    view = _start(win, "trails")
    view.game.countdown = 0
    view.grab()
    board = view._ribbons
    for _ in range(3):
        view.step()
        view.grab()
    assert view._ribbons is board                      # the ribbons grow on the same pixmap
    win.close()


def test_happy_going_on_after_a_pause_does_not_glide_back(tmp_path):
    win, _audio = _window(tmp_path)
    view = _start(win, "chase")
    _key(win, Qt.Key.Key_P)
    _key(win, Qt.Key.Key_P)
    assert not view.paused and view.tick_progress() == 1.0
    win.close()


def test_happy_the_forms_are_played_with_the_keyboard_too(tmp_path):
    win, _audio = _window(tmp_path)
    _key(win, Qt.Key.Key_Right)
    _key(win, Qt.Key.Key_Right)
    _key(win, Qt.Key.Key_Right)
    _key(win, Qt.Key.Key_Return)                       # the picker: Trail Runner
    assert win.view.__class__.__name__ == "TrailsSetup"
    _key(win, Qt.Key.Key_Return)                       # its Start button has the focus
    assert win.view.__class__.__name__ == "TrailsView"
    win.close()
