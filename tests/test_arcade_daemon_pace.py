"""Byte Chase and Tilt Maze: the daemons get faster each level, and a key
slows them below their slowest pace.

The old tick stepped the daemons when ``tick % every != 0`` while
``every`` shrank with the level, so they moved on 80 % of the ticks at
level 1 and on only 50 % from level 6 (Tilt Maze: from speed 3) - the
daemons got slower each level, and "scared" (also 50 %) no longer slowed
them at all.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import chase as C  # noqa: E402
from core.arcade.tilt import TiltGame  # noqa: E402


def _rate(game, ticks: int = 200, scared: bool = False) -> float:
    """Share of ticks on which the first daemon (out of its den, never
    catching the player, never scared unless asked) takes a step."""
    d = game.daemons[0]
    d.wait = 0
    game.lives = 10 ** 6
    moved = 0
    for _ in range(ticks):
        game.scared = 50 if scared else 0
        game.airborne = 99                       # it passes under: no catches
        game.bits.add((0, 0))                    # never finishes the level
        before = d.pos
        game.tick()
        moved += d.pos != before
    return moved / ticks


def test_happy_chase_daemons_move_more_often_on_later_levels():
    """Level 1 keeps the old 80 %; later levels move on more ticks, never
    on fewer than the level before."""
    rates = [_rate(C.ChaseGame(seed=5, level=lvl)) for lvl in (1, 2, 4, 6, 10)]
    assert rates[0] == pytest.approx(0.8, abs=0.02)
    assert rates == sorted(rates)
    assert rates[-1] > rates[0] + 0.05


def test_happy_tilt_daemons_move_more_often_with_the_level_speed():
    slow, fast = TiltGame(level=1), TiltGame(level=100)
    assert slow.spec.speed < fast.spec.speed
    assert _rate(fast) > _rate(slow) + 0.05


def test_edge_scared_daemons_are_slower_than_the_slowest_normal_pace():
    """A key must slow the daemons even on the last levels: below their
    own pace there and below the pace of level 1."""
    slowest = _rate(C.ChaseGame(seed=5, level=1))
    for make in (lambda: C.ChaseGame(seed=5, level=1), lambda: C.ChaseGame(seed=5, level=12),
                 lambda: TiltGame(level=100)):
        normal, scared = _rate(make()), _rate(make(), scared=True)
        assert scared < normal - 0.1
        assert scared < slowest - 0.1


@pytest.mark.parametrize("pace", range(-1, 12))
def test_sad_the_pace_rule_stays_between_the_bounds(pace):
    """Out-of-range paces clamp: never a stand-still, never every tick."""
    rate = sum(C.daemons_move(t, pace, False) for t in range(1, 1001)) / 1000
    assert 0.79 <= rate <= 0.91
    scared = sum(C.daemons_move(t, pace, True) for t in range(1, 1001)) / 1000
    assert scared < rate
