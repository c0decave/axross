"""Rockfall: rocks and crystals treat a creature's cell like the digger's.

A crawler's or seeker's cell reads EMPTY in the grid, and the physics
took it for empty space: a rock fell, rolled or was pushed right into the
creature's cell and on through it, the creature lived on inside the rock.
And a prism that split a rock beside the digger dropped a crystal onto the
digger's cell, where it was lost when the digger walked on - a cave could
then no longer reach its quota.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import rockfall as R  # noqa: E402
from core.arcade import rockfall_campaign as RC  # noqa: E402


def _cave(rows, game=None, **kw):
    g = game or R.RockfallGame(seed=1)
    g.grid = [list(r) for r in rows]
    g.height, g.width = len(rows), len(rows[0])
    g.crawlers, g.falling = [], set()
    if isinstance(g, RC.CaveGame):
        g.seekers = []
        g.grace = 0
    for k, v in kw.items():
        setattr(g, k, v)
    return g


def _rocks(g):
    return {(x, y) for y, row in enumerate(g.grid) for x, c in enumerate(row) if c == R.ROCK}


# a falling rock at (3, 2) over a creature at (3, 3), a closed shaft
SHAFT = ["#######",
         "#:: ::#",
         "#::o::#",
         "#:: ::#",
         "#::#::#",
         "#######"]


def test_happy_a_falling_rock_crushes_a_crawler_that_walked_under_it():
    """The rock was in motion: the crawler under it dies, leaves crystals
    and scores - the rock does not move into its cell."""
    g = _cave(SHAFT, player=(1, 1), falling={(3, 2)})
    g.crawlers = [R.Crawler((3, 3))]
    score = g.score
    g._physics()
    assert g.crawlers == []
    assert "crawler" in g.events and g.score == score + 50
    assert g.grid[3][3] == R.GEM                     # crystals where it was
    assert (3, 3) not in _rocks(g)


def test_sad_a_resting_rock_does_not_drop_into_a_crawler():
    """Not in motion yet: like over the digger, it stays on top."""
    g = _cave(SHAFT, player=(1, 1))
    g.crawlers = [R.Crawler((3, 3))]
    g._physics()
    assert [c.pos for c in g.crawlers] == [(3, 3)]
    assert _rocks(g) == {(3, 2)} and g.grid[3][3] == R.EMPTY


def test_sad_a_rock_does_not_roll_into_a_crawler():
    g = _cave(["#######",
               "#:::::#",
               "#:o  :#",
               "#:o  :#",
               "#######"], player=(5, 1))
    g.crawlers = [R.Crawler((3, 2))]
    g._physics()
    assert _rocks(g) == {(2, 2), (2, 3)}
    assert [c.pos for c in g.crawlers] == [(3, 2)]


def test_sad_a_rock_does_not_roll_onto_the_cell_above_a_crawler():
    g = _cave(["#######",
               "#:::::#",
               "#:o  :#",
               "#:o  :#",
               "#######"], player=(5, 1))
    g.crawlers = [R.Crawler((3, 3))]
    g._physics()
    assert _rocks(g) == {(2, 2), (2, 3)}


def test_sad_the_digger_cannot_push_a_rock_into_a_crawler():
    g = _cave(["######",
               "# o  #",
               "######"], player=(1, 1))
    g.crawlers = [R.Crawler((3, 1))]
    g.steer(R.RIGHT)
    g._move_player()
    assert g.player == (1, 1) and _rocks(g) == {(2, 1)}


def test_happy_a_falling_rock_crushes_a_seeker_that_crept_under_it():
    g = _cave(SHAFT, game=RC.CaveGame(level=1), player=(1, 1), falling={(3, 2)})
    g.seekers = [RC.Seeker((3, 3))]
    score = g.score
    g._physics()
    assert g.seekers == [] and g.score == score + 75
    assert (3, 3) not in _rocks(g) and g.grid[3][3] == R.GEM


def test_sad_a_rock_does_not_roll_into_a_seeker():
    g = _cave(["#######",
               "#:::::#",
               "#:o  :#",
               "#:o  :#",
               "#######"], game=RC.CaveGame(level=1), player=(5, 1))
    g.seekers = [RC.Seeker((3, 2))]
    g._physics()
    assert _rocks(g) == {(2, 2), (2, 3)} and len(g.seekers) == 1


def test_happy_a_prism_crystal_split_onto_the_digger_is_collected():
    """The crystal is the digger's, not lost under it."""
    g = _cave(["#######",
               "#::o::#",
               "#:: ::#",
               "#: ^ :#",
               "#:###:#",
               "#######"], game=RC.CaveGame(level=1), player=(4, 3), quota=99)
    g.falling = {(3, 1)}
    for _ in range(3):
        g._physics()
    assert "prism" in g.events
    assert g.gems == 1 and "gem" in g.events
    assert g.grid[3][4] == R.EMPTY                   # nothing sits in the digger's cell
    assert g.grid[3][2] == R.GEM                     # the other half on the free side


def test_edge_a_prism_puts_no_crystal_on_a_creature():
    g = _cave(["#######",
               "#::o::#",
               "#:: ::#",
               "#: ^ :#",
               "#:###:#",
               "#######"], game=RC.CaveGame(level=1), player=(1, 1))
    g.falling = {(3, 1)}
    g.crawlers = [R.Crawler((4, 3))]
    for _ in range(3):
        g._physics()
    assert "prism" in g.events
    assert g.grid[3][4] == R.EMPTY and g.grid[3][2] == R.GEM
    assert [c.pos for c in g.crawlers] == [(4, 3)]
