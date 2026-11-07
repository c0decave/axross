"""core.arcade: the rules of Byte Chase / Tilt Maze, Rockfall and Trail Runner."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.arcade import chase as C  # noqa: E402
from core.arcade import rockfall as R  # noqa: E402
from core.arcade import trails as T  # noqa: E402


# --- Byte Chase -------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(12))
def test_happy_every_maze_is_connected_symmetric_and_walled(seed):
    g = C.generate_maze(seed)
    h, w = len(g), len(g[0])
    assert all(g[0][x] == g[h - 1][x] == C.WALL for x in range(w))
    assert all(row == row[::-1] for row in g)
    open_cells = {(x, y) for y in range(h) for x in range(w) if g[y][x] == C.OPEN}
    assert C.reachable(g, next(iter(open_cells))) == open_cells
    dead_ends = sum(1 for (x, y) in open_cells
                    if sum(g[y + dy][x + dx] == C.WALL for dx, dy in C.DIRS) == 3)
    assert dead_ends < len(open_cells) // 10          # braided: mostly loops


def test_happy_bits_and_keys_score_and_a_key_scares_the_daemons():
    game = C.ChaseGame(seed=3)
    assert len(game.bits) > 100 and len(game.keys) == 4
    bit = next(iter(game.bits))
    # stand next to the bit and walk onto it
    for d in C.DIRS:
        nxt = (bit[0] - d[0], bit[1] - d[1])
        if game._open(nxt):
            game.player = nxt
            game.steer(d)
            break
    before = game.score
    game._step_player()
    assert game.player == bit and bit not in game.bits and game.score == before + C.BIT_POINTS
    key = next(iter(game.keys))
    for d in C.DIRS:
        nxt = (key[0] - d[0], key[1] - d[1])
        if game._open(nxt):
            game.player = nxt
            game.steer(d)
            break
    before = game.score
    game._step_player()
    assert game.player == key and game.score == before + C.KEY_POINTS
    assert game.scared > 0 and "key" in game.events


def test_happy_catching_a_scared_daemon_scores_and_sends_it_home():
    game = C.ChaseGame(seed=5)
    d = game.daemons[0]
    d.pos = game.player
    game.scared = 20
    before = game.score
    game._collide()
    assert game.score == before + 200 and d.pos == d.home


def test_sad_a_daemon_costs_a_life_unless_the_player_is_in_the_air():
    game = C.ChaseGame(seed=5, jump=True)
    game.daemons[0].pos = game.player
    game.jump_now()
    game._collide()
    assert game.lives == 3
    game.airborne = 0
    game._collide()
    assert game.lives == 2 and "caught" in game.events
    for _ in range(2):
        game.daemons[0].pos = game.player
        game._collide()
    assert game.over


def test_happy_eating_everything_starts_the_next_level():
    game = C.ChaseGame(seed=2)
    game.bits, game.keys = set(), set()
    game.tick()
    assert game.level == 2 and "level" in game.events and game.bits


def test_happy_daemons_leave_the_den_one_after_another():
    game = C.ChaseGame(seed=4)
    assert [d.wait for d in game.daemons] == [0, C.RELEASE, 2 * C.RELEASE, 3 * C.RELEASE]
    cutter = game.daemons[1]
    for _ in range(C.RELEASE):
        game._step_daemon(cutter)
    assert cutter.pos == cutter.home
    game._step_daemon(cutter)
    assert cutter.pos != cutter.home


def test_happy_the_tracker_closes_in():
    game = C.ChaseGame(seed=4)
    tracker = game.daemons[0]

    def dist():
        return abs(tracker.pos[0] - game.player[0]) + abs(tracker.pos[1] - game.player[1])
    start = dist()
    for _ in range(60):
        game._step_daemon(tracker)
        if tracker.pos == game.player:
            break
    assert tracker.pos == game.player, (start, dist())


# --- Rockfall ------------------------------------------------------------------------------

def _cave(rows):
    game = R.RockfallGame(seed=1)
    game.grid = [list(r) for r in rows]
    game.height, game.width = len(rows), len(rows[0])
    game.crawlers = []
    game.falling = set()
    return game


def test_happy_rocks_fall_and_roll_off():
    game = _cave(["#######",
                  "#o    #",
                  "#     #",
                  "#  o  #",
                  "#  o  #",
                  "#######"])
    game.player = (5, 1)
    for _ in range(4):
        game._physics()
    assert game.grid[4][1] == R.ROCK                 # fell to the floor
    assert game.grid[3][3] == R.EMPTY                # the upper of the stacked rocks rolled off ...
    assert R.ROCK in (game.grid[4][2], game.grid[4][4])   # ... to one side, down to the floor


def test_sad_a_falling_rock_crushes_the_digger():
    game = _cave(["#####", "# o #", "#   #", "#   #", "#####"])
    game.player = (2, 3)
    game.lives = 1
    game._physics()                                   # starts falling
    game._physics()                                   # lands on the digger
    assert game.over and "crushed" in game.events


def test_happy_digging_collecting_pushing_and_the_exit():
    game = _cave(["########", "#  :*o #", "#::::::#", "#######E", "########"])
    game.player = (1, 1)
    game.exit = (6, 3)
    game.grid[3][6] = R.WALL
    game.quota = 1
    for d in (R.RIGHT, R.RIGHT, R.RIGHT):
        game.steer(d)
        game._move_player()
    assert game.player == (4, 1) and game.gems == 1 and game.grid[3][6] == R.EXIT
    game.steer(R.RIGHT)
    game._move_player()                               # pushes the rock right
    assert game.player == (5, 1) and game.grid[1][6] == R.ROCK
    game.steer(R.DOWN)
    game._move_player()
    assert game.grid[2][5] == R.EMPTY                 # dug


def test_happy_a_crushed_crawler_leaves_crystals():
    game = _cave(["#######", "#  o  #", "#     #", "#     #", "#######"])
    game.player = (1, 3)
    game.crawlers = [R.Crawler((3, 3))]
    for _ in range(3):
        game._physics()
    assert not game.crawlers and sum(row.count(R.GEM) for row in game.grid) >= 3


@pytest.mark.parametrize("seed", range(6))
def test_happy_generated_caves_have_enough_crystals(seed):
    game = R.RockfallGame(seed=seed)
    gems = sum(row.count(R.GEM) for row in game.grid)
    assert gems >= game.quota
    assert game.grid[game.exit[1]][game.exit[0]] == R.WALL      # closed until the quota


# --- Trail Runner ----------------------------------------------------------------------------

def test_happy_riders_leave_trails_and_crash_into_them():
    game = T.TrailsGame(seed=1, opponents=1)
    me = game.riders[0]
    start = me.pos
    game.tick()
    assert start in game.trail and me.pos != start
    game.steer(T.UP)
    game.tick()
    game.steer(T.LEFT)
    game.tick()
    game.steer(T.DOWN)
    game.tick()                                        # back into my own trail
    assert not me.alive and game.round_over and game.winner == 1


def test_happy_a_computer_rider_avoids_a_dead_end():
    game = T.TrailsGame(seed=2, opponents=1)
    bot = game.riders[1]
    bot.pos, bot.facing = (10, 10), T.RIGHT
    game.trail = {(11, y): 9 for y in range(0, 40)}   # a wall straight ahead
    game._choose(bot)
    assert bot.facing in (T.UP, T.DOWN)


def test_happy_points_end_the_game():
    game = T.TrailsGame(seed=3, opponents=1, target_points=1)
    game.riders[0].alive = False
    game.riders[0].facing = T.RIGHT
    game.tick()
    assert game.over and game.riders[1].points == 1


def test_edge_no_u_turn():
    game = T.TrailsGame(seed=1)
    game.steer(T.LEFT)                                 # starts facing right
    assert game.riders[0].facing == T.RIGHT
