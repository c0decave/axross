"""Rockfall's campaign and its rules (core.arcade.rockfall_campaign)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import rockfall as R  # noqa: E402
from core.arcade import rockfall_campaign as RC  # noqa: E402


def _cave(rows, **kw):
    g = RC.CaveGame(level=1)
    g.grid = [list(r) for r in rows]
    g.height, g.width = len(rows), len(rows[0])
    g.crawlers, g.seekers, g.falling = [], [], set()
    for k, v in kw.items():
        setattr(g, k, v)
    return g


def test_happy_40_caves_in_5_worlds_every_one_winnable():
    camp = RC.campaign()
    assert [c.number for c in camp] == list(range(1, 41)) and len({c.world for c in camp}) == 5
    for spec in camp:
        g = RC.CaveGame(level=spec.number)
        assert sum(row.count(R.GEM) for row in g.grid) >= spec.quota, spec.number
        assert g.grid[g.exit[1]][g.exit[0]] == R.WALL              # closed until the quota
    assert RC.CaveGame(level=13).grid == RC.CaveGame(level=13).grid
    codes = {RC.password(w) for w in range(5)}
    assert len(codes) == 5 and RC.world_of(RC.password(2)) == 2


def test_happy_space_takes_the_cell_beside_without_stepping():
    g = _cave(["######", "# :* #", "######"], player=(1, 1), quota=1)
    g.exit = (4, 1)
    g.steer(R.RIGHT, grab=True)
    g._move_player()
    assert g.player == (1, 1) and g.grid[1][2] == R.EMPTY and "dig" in g.events
    g.player = (2, 1)
    g.steer(R.RIGHT, grab=True)
    g._move_player()
    assert g.player == (2, 1) and g.gems == 1 and g.grid[1][3] == R.EMPTY
    assert g.grid[1][4] == R.EXIT and "exit-open" in g.events


def test_happy_a_prism_splits_a_falling_rock_into_two_crystals():
    g = _cave(["#######", "#  o  #", "#     #", "#  ^  #", "#######"], player=(1, 1))
    for _ in range(4):
        g._physics()
    assert g.grid[3][2] == R.GEM and g.grid[3][4] == R.GEM and "prism" in g.events
    assert R.ROCK not in "".join("".join(r) for r in g.grid)


def test_sad_prisms_are_solid_to_the_digger():
    g = _cave(["#####", "# ^ #", "#####"], player=(1, 1))
    g.steer(R.RIGHT)
    g._move_player()
    assert g.player == (1, 1)


def test_happy_a_seeker_comes_closer_and_a_rock_makes_it_crystals():
    g = _cave(["##########", "#        #", "#        #", "##########"], player=(1, 1))
    g.seekers = [RC.Seeker((8, 2))]
    for _ in range(12):
        g._move_seekers()
    assert g.seekers[0].pos[0] < 8
    g2 = _cave(["#######", "#  o  #", "#     #", "#     #", "#######"], player=(1, 1))
    g2.seekers = [RC.Seeker((3, 3))]
    for _ in range(3):
        g2._physics()
    assert not g2.seekers and sum(row.count(R.GEM) for row in g2.grid) >= 3


def test_happy_the_last_cave_completes_the_campaign():
    g = RC.CaveGame(level=40)
    g.won_level = True
    g.tick()
    assert g.completed and "complete" in g.events


def test_happy_creatures_start_far_from_the_digger_and_there_is_grace():
    for spec in RC.campaign():
        g = RC.CaveGame(level=spec.number)
        for c in list(g.crawlers) + list(g.seekers):
            assert abs(c.pos[0] - 2) + abs(c.pos[1] - 2) >= 8, spec.number
    g = RC.CaveGame(level=1)
    lives = g.lives
    g._crushed_player()                     # within the grace: nothing happens
    assert g.lives == lives
    for _ in range(25):
        g.tick()
    g._crushed_player()
    assert g.lives == lives - 1
