"""Tilt Maze's campaign (core.arcade.tilt_levels) and rules (core.arcade.tilt)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import chase as C  # noqa: E402
from core.arcade import tilt_levels as L  # noqa: E402
from core.arcade.tilt import TiltGame  # noqa: E402


def test_happy_the_campaign_has_100_levels_in_10_worlds_and_every_board_is_winnable():
    camp = L.campaign()
    assert [s.number for s in camp] == list(range(1, 101))
    assert len({s.world for s in camp}) == 10
    for spec in camp:
        b = L.build(spec)
        reach = L.reachable(b.grid, b.start, b.links)
        assert b.bits <= reach and b.keys <= reach, spec.number
        assert len(b.links) // 2 == spec.teleports, spec.number
        assert sum(row.count(L.PIT) for row in b.grid) >= min(spec.pits, 2) if spec.pits else True
    assert L.build(camp[57]).grid == L.build(camp[57]).grid      # the same level every time
    sizes = [s.size for s in camp]
    assert sizes == sorted(sizes) and sizes[0] < sizes[-1]       # the boards grow


def test_happy_world_passwords():
    codes = [L.password(w) for w in range(10)]
    assert len(set(codes)) == 10 and all(len(c) == 6 and c.isalpha() for c in codes)
    assert L.world_of(codes[4].lower()) == 4 and L.world_of("XXXXXX") is None


def _game_with_pit():
    g = TiltGame(level=31)                                       # a world with pits
    pit = next((x, y) for y, row in enumerate(g.grid) for x, c in enumerate(row) if c == L.PIT)
    for d in C.DIRS:
        before, after = (pit[0] - d[0], pit[1] - d[1]), (pit[0] + d[0], pit[1] + d[1])
        if g._open(before) and g._open(after):
            return g, pit, before, after, d
    raise AssertionError("no straight pit")


def test_sad_walking_into_a_pit_falls_and_costs_a_life():
    g, pit, before, _after, d = _game_with_pit()
    g.daemons = []
    g.player, g.wanted, g.facing = before, d, d
    g.tick()
    assert g.player == pit and g.falling and "fall" in g.events
    lives = g.lives
    for _ in range(10):
        g.tick()
    assert g.lives == lives - 1 and g.player == g.board.start


def test_happy_a_jump_carries_over_a_pit():
    g, _pit, before, after, d = _game_with_pit()
    g.daemons = []
    g.player, g.wanted, g.facing = before, d, d
    g.jump_now()
    g.tick()
    g.tick()
    assert g.player == after and not g.falling


def test_happy_a_teleporter_takes_you_to_its_partner():
    g = TiltGame(level=41)
    a, b = next(iter(g.board.links.items()))
    g.daemons = []
    for d in C.DIRS:
        nxt = (a[0] - d[0], a[1] - d[1])
        if g._cell(nxt) == C.OPEN:
            g.player, g.wanted, g.facing = nxt, d, d
            break
    g.tick()
    assert "teleport" in g.events
    assert abs(g.player[0] - b[0]) + abs(g.player[1] - b[1]) <= 1


def test_happy_the_hopper_jumps_pits():
    g, pit, before, after, d = _game_with_pit()
    hopper = C.Daemon("Hopper", before, before)
    hopper.facing = d
    g.daemons = [hopper]
    g.player = (after[0] + d[0] * 3, after[1] + d[1] * 3) if g._open((after[0] + d[0] * 3, after[1] + d[1] * 3)) else after
    g._step_daemon(hopper)
    assert hopper.pos == after


def test_happy_extra_lives_and_the_end_of_the_campaign():
    g = TiltGame(level=100, score=9_990)
    g.daemons = []
    lives = g.lives
    g.score = 10_005
    g.tick()
    assert g.lives == lives + 1 and "extra-life" in g.events and g.next_extra == 30_000
    g.bits, g.keys = set(), set()
    g.tick()
    assert g.completed and "complete" in g.events


def test_happy_finishing_a_level_starts_the_next():
    g = TiltGame(level=9)
    g.bits, g.keys = set(), set()
    g.tick()
    assert g.level == 10 and g.bits
