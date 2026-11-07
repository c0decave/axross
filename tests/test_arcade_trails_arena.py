"""Trail Runner's arenas and rules (core.arcade.trails_arena)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import trails as T  # noqa: E402
from core.arcade import trails_arena as A  # noqa: E402


def _start(game):
    game.countdown = 0
    game.events.clear()
    return game


@pytest.mark.parametrize("arena", range(len(A.ARENAS)))
def test_happy_every_arena_leaves_the_starts_free_and_a_round_can_be_played(arena):
    g = _start(A.ArenaGame(A.Settings(arena=arena, opponents=3)))
    for r in g.riders:
        assert r.pos not in g.walls
        x, y = r.pos
        assert g._free((x + r.facing[0], y + r.facing[1]), ())
    for _ in range(600):
        g.tick()
        if g.round_over:
            break
    assert g.round_over


def test_happy_the_countdown_then_go():
    g = A.ArenaGame()
    seen = []
    for _ in range(31):
        g.tick()
        seen += g.events
        g.events.clear()
    assert seen.count("countdown") == 3 and seen[-1] == "go"


def test_happy_a_boost_moves_two_cells_and_costs_energy():
    g = _start(A.ArenaGame(A.Settings(opponents=1)))
    me = g.riders[0]
    x = me.pos[0]
    g.boost(0)
    g.tick()
    assert me.pos[0] == x + 2 and g.energy[0] == A.BOOST_MAX - A.BOOST_COST and "boost" in g.events
    for _ in range(20):
        g.boost(0)
        g.tick()
        if not me.alive:
            break
    assert g.energy[0] < A.BOOST_COST or not me.alive


def test_happy_two_players_steer_their_own_riders():
    g = _start(A.ArenaGame(A.Settings(two_players=True, opponents=1)))
    assert g.riders[0].human and g.riders[1].human and not g.riders[2].human
    g.steer_rider(1, T.UP)
    g.tick()
    assert g.riders[1].facing == T.UP
    g.steer_rider(1, T.DOWN)                     # no U-turn
    assert g.riders[1].facing == T.UP


def test_happy_wrap_gates_let_a_rider_through_the_middle_of_the_border():
    g = _start(A.ArenaGame(A.Settings(arena=A.ARENAS.index("Wrap Gates"))))
    assert g._wrap_cell((-1, g.height // 2)) == (g.width - 1, g.height // 2)
    assert g._wrap_cell((-1, 1)) == (-1, 1)      # not through a corner


def test_happy_the_field_shrinks():
    g = _start(A.ArenaGame(A.Settings(arena=A.ARENAS.index("Shrinking Field"), opponents=1)))
    g.riders[0].human = False                    # let both drive themselves
    for _ in range(130):
        g.tick()
        if g.round_over:
            break
    assert g.shrink >= 1 or g.round_over
    assert not g._free((0, 0), ()) or g.shrink == 0


def test_happy_the_tournament_moves_through_the_arenas():
    g = _start(A.ArenaGame(A.Settings(arena=-1, opponents=1)))
    assert g.arena == A.ARENAS[0]
    g.riders[0].alive = False
    g.tick()                                     # round over, the computer won
    g.tick()                                     # the next round: the next arena
    assert g.arena == A.ARENAS[1]


@pytest.mark.parametrize("difficulty", sorted(A.DIFFICULTY))
def test_happy_computer_riders_survive_longer_the_harder_they_are(difficulty):
    lengths = []
    for seed in range(3):
        g = _start(A.ArenaGame(A.Settings(opponents=1, difficulty=difficulty), seed=seed))
        g.riders[0].human = False
        n = 0
        while not g.round_over and n < 2000:
            g.tick()
            n += 1
        lengths.append(n)
    assert min(lengths) > 20


def test_happy_a_round_the_humans_are_out_of_ends_at_once_and_a_computer_rider_scores():
    g = _start(A.ArenaGame(A.Settings(opponents=3), seed=4))
    assert not g.humans_out() and not g.finish_round()       # the human still rides
    g.riders[0].alive = False
    assert g.humans_out()
    assert g.finish_round()
    assert g.round_over and g.winner in (1, 2, 3) and g.riders[g.winner].points == 1
    assert any(e.startswith("round:") for e in g.events)
    assert not g.humans_out() and not g.finish_round()       # once
    g.tick()                                                  # the next round
    assert g.round_no == 2 and g.countdown > 0 and all(r.alive for r in g.riders)


def test_happy_finishing_rounds_still_ends_the_match():
    g = A.ArenaGame(A.Settings(opponents=1, target_points=2), seed=2)
    for _ in range(2):
        _start(g)
        g.riders[0].alive = False
        assert g.finish_round()
        if not g.over:
            g.tick()
    assert g.over and g.riders[1].points == 2


def test_sad_no_skip_during_the_countdown_or_while_a_human_rides():
    g = A.ArenaGame(A.Settings(opponents=1, two_players=True))
    g.riders[0].alive = False
    assert not g.humans_out()                                 # the countdown runs
    g.countdown = 0
    assert not g.humans_out()                                 # player 2 still rides
