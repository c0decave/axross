"""Trail Runner's arenas, modes and rules - axross's own light-trail game.

On top of core.arcade.trails: eight arenas (open floor, pillars, a cross,
islands, a ring, gates that wrap round the edge, a field that shrinks, a
labyrinth of short walls); a boost - Space (rider 2: Enter) - that moves
a rider two cells a tick while its energy lasts and recharges slowly;
two players on one keyboard (W A S D against the arrows); computer riders
in three difficulties (easy turns at random now and then, hard looks
further and boosts to cut a rider off); a tournament over all arenas.

When every human rider is out but computer riders still ride, nobody has
to watch them finish: :meth:`ArenaGame.finish_round` ends the round at
once (Space / Enter in the window) and gives the point to the computer
rider with the most room left - the one the flood fill says would have
lasted longest - so a match still ends.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass

from core.arcade import trails as T

ARENAS = ("Open Floor", "Pillars", "Crossing", "Islands", "Ring", "Wrap Gates", "Shrinking Field", "Short Walls")
DIFFICULTY = {"easy": (60, 0.08), "normal": (220, 0.02), "hard": (600, 0.0)}   # look-ahead, random turns
BOOST_MAX, BOOST_COST, BOOST_REGEN = 100, 12, 1


def arena_walls(name: str, w: int, h: int, seed: int = 0) -> set:
    rng = random.Random(seed * 31 + len(name))
    cells: set = set()
    if name == "Pillars":
        for x in range(8, w - 6, 10):
            for y in range(6, h - 4, 8):
                cells |= {(x + dx, y + dy) for dx in range(2) for dy in range(2)}
    elif name == "Crossing":
        cells |= {(w // 2, y) for y in range(6, h - 6) if abs(y - h // 2) > 3}
        cells |= {(x, h // 2) for x in range(8, w - 8) if abs(x - w // 2) > 4}
    elif name == "Islands":
        for _ in range(9):
            cx, cy = rng.randrange(10, w - 10), rng.randrange(6, h - 6)
            cells |= {(cx + dx, cy + dy) for dx in range(-2, 3) for dy in range(-1, 2)}
    elif name == "Ring":
        for x in range(w):
            for y in range(h):
                d = ((x - w / 2) / (w / 3)) ** 2 + ((y - h / 2) / (h / 3)) ** 2
                if 0.95 < d < 1.08 and not (abs(x - w // 2) < 3 or abs(y - h // 2) < 2):
                    cells.add((x, y))
    elif name == "Short Walls":
        for _ in range(26):
            x, y = rng.randrange(4, w - 6), rng.randrange(4, h - 4)
            horizontal = rng.random() < 0.5
            cells |= {(x + k, y) if horizontal else (x, y + k) for k in range(rng.randrange(3, 6))}
    starts = {(w // 4, h // 2), (3 * w // 4, h // 2), (w // 2, h // 4), (w // 2, 3 * h // 4)}
    return {c for c in cells if all(abs(c[0] - s[0]) + abs(c[1] - s[1]) > 4 for s in starts)}


@dataclass
class Settings:
    opponents: int = 2           # computer riders
    difficulty: str = "normal"
    two_players: bool = False
    arena: int = 0               # index into ARENAS; -1: the tournament (all of them)
    target_points: int = 5


class ArenaGame(T.TrailsGame):
    def __init__(self, settings: Settings | None = None, seed: int = 1):
        self.settings = settings or Settings()
        st = self.settings
        self.tournament = st.arena < 0
        self.arena_index = 0 if self.tournament else st.arena
        self.energy: list[int] = []
        self.boosting: list[bool] = []
        self.walls: set = set()
        self.wrap = False
        self.shrink = 0
        self.ticks = 0
        self.countdown = 0
        total_riders = 1 + (1 if st.two_players else 0) + st.opponents
        super().__init__(seed=seed, width=64, height=40, opponents=max(1, min(3, total_riders - 1)),
                         target_points=st.target_points)
        if st.two_players:
            self.riders[1].human = True
            self.riders[1].name = "Player 2"
        self.riders[0].name = "Player 1" if st.two_players else "You"

    @property
    def arena(self) -> str:
        return ARENAS[self.arena_index]

    def new_round(self) -> None:
        super().new_round()
        self.walls = arena_walls(self.arena, self.width, self.height, self.round_no)
        self.wrap = self.arena == "Wrap Gates"
        self.shrink = 0
        self.ticks = 0
        self.countdown = 30            # 3 seconds at 10 ticks
        self.energy = [BOOST_MAX] * len(self.riders)
        self.boosting = [False] * len(self.riders)
        for cell in self.walls:
            self.trail[cell] = -1

    # -- the board ----------------------------------------------------------------------------

    def _wrap_cell(self, cell):
        x, y = cell
        if not self.wrap:
            return cell
        # gates: the middle third of each border lets a rider through to the other side
        if x < 0 and self.height // 3 <= y < 2 * self.height // 3:
            return (self.width - 1, y)
        if x >= self.width and self.height // 3 <= y < 2 * self.height // 3:
            return (0, y)
        if y < 0 and self.width // 3 <= x < 2 * self.width // 3:
            return (x, self.height - 1)
        if y >= self.height and self.width // 3 <= x < 2 * self.width // 3:
            return (x, 0)
        return cell

    def _free(self, cell, taken) -> bool:
        cell = self._wrap_cell(cell)
        x, y = cell
        m = self.shrink
        return m <= x < self.width - m and m <= y < self.height - m and cell not in self.trail \
            and cell not in taken

    # -- riders ----------------------------------------------------------------------------------

    def steer_rider(self, index: int, direction) -> None:
        r = self.riders[index]
        if r.human and direction != (-r.facing[0], -r.facing[1]):
            r.facing = direction

    def steer(self, direction) -> None:
        self.steer_rider(0, direction)

    def boost(self, index: int, on: bool = True) -> None:
        if index < len(self.boosting):
            self.boosting[index] = on and self.energy[index] >= BOOST_COST

    def _choose(self, r) -> None:
        look, randomness = DIFFICULTY[self.settings.difficulty]
        options = [r.facing, (r.facing[1], -r.facing[0]), (-r.facing[1], r.facing[0])]
        if randomness and self.rng.random() < randomness:
            # a careless turn - but only where there is room to keep riding
            free = [d for d in options
                    if self._room(self._wrap_cell((r.pos[0] + d[0], r.pos[1] + d[1])), 40) >= 40]
            if free:
                r.facing = self.rng.choice(free)
                return
        heads = {o.pos for o in self.riders if o is not r and o.alive}
        scored = []
        for d in options:
            n = self._wrap_cell((r.pos[0] + d[0], r.pos[1] + d[1]))
            # a cell next to another rider's head may be where it goes next: a head-on crash
            near_head = any(abs(n[0] - hx) + abs(n[1] - hy) <= 1 for hx, hy in heads)
            room = self._room(n, look)
            scored.append((room // 4 if near_head else room, d == r.facing, self.rng.random(), d))
        scored.sort(reverse=True)
        r.facing = scored[0][3]
        i = self.riders.index(r)
        if self.settings.difficulty == "hard" and self.energy[i] > 60:
            me = self.riders[0]
            dist = abs(me.pos[0] - r.pos[0]) + abs(me.pos[1] - r.pos[1])
            self.boosting[i] = dist < 12 and scored[0][0] > 40

    def _room(self, start, limit: int = 400) -> int:
        if not self._free(start, ()):
            return 0
        seen, todo = {start}, deque([start])
        while todo and len(seen) < limit:
            x, y = todo.popleft()
            for dx, dy in (T.UP, T.DOWN, T.LEFT, T.RIGHT):
                n = self._wrap_cell((x + dx, y + dy))
                if n not in seen and self._free(n, ()):
                    seen.add(n)
                    todo.append(n)
        return len(seen)

    # -- a round the humans are out of --------------------------------------------------------

    def humans_out(self) -> bool:
        """Every human rider crashed while the round goes on (computer
        riders still riding): the round is decided for the humans."""
        if self.over or self.round_over or self.countdown > 0:
            return False
        humans = [r for r in self.riders if r.human]
        return bool(humans) and not any(r.alive for r in humans) and any(r.alive for r in self.riders)

    def finish_round(self) -> bool:
        """End a round the humans are out of at once; True when it ended.
        The point goes to the computer rider with the most room ahead
        (ties: the first)."""
        if not self.humans_out():
            return False
        best, best_room = None, -1
        for i, r in enumerate(self.riders):
            if not r.alive:
                continue
            room = max(self._room(self._wrap_cell((r.pos[0] + d[0], r.pos[1] + d[1])), 600)
                       for d in (T.UP, T.DOWN, T.LEFT, T.RIGHT))
            if room > best_room:
                best, best_room = i, room
        for r in self.riders:
            r.alive = r is self.riders[best]
        self.round_over = True
        self.winner = best
        winner = self.riders[best]
        winner.points += 1
        self.events.append(f"round:{winner.name}")
        if winner.points >= self.target_points:
            self.over = True
        return True

    # -- the tick ------------------------------------------------------------------------------

    def _move_once(self) -> None:
        targets = {}
        for i, r in enumerate(self.riders):
            if r.alive:
                targets[i] = self._wrap_cell((r.pos[0] + r.facing[0], r.pos[1] + r.facing[1]))
        counts: dict = {}
        for cell in targets.values():
            counts[cell] = counts.get(cell, 0) + 1
        for i, cell in targets.items():
            if not self._free(cell, ()) or counts[cell] > 1:
                self.riders[i].alive = False
                self.events.append(f"out:{self.riders[i].name}")
        for i, cell in targets.items():
            r = self.riders[i]
            if r.alive:
                r.pos = cell
                self.trail[cell] = i

    def tick(self) -> None:
        if self.over:
            return
        if self.round_over:
            if self.tournament and self.winner is not None:
                self.arena_index = (self.arena_index + 1) % len(ARENAS)
            self.new_round()
            return
        if self.countdown > 0:
            if self.countdown % 10 == 0:
                self.events.append("countdown")
            self.countdown -= 1
            if self.countdown == 0:
                self.events.append("go")
            return
        self.ticks += 1
        if self.arena == "Shrinking Field" and self.ticks % 60 == 0 and self.shrink < 12:
            self.shrink += 1
            self.events.append("shrink")
        for r in self.riders:
            if r.alive and not r.human:
                self._choose(r)
        self._move_once()
        # boosting riders move a second time; the others stand for that step
        extra = [i for i, r in enumerate(self.riders) if r.alive and self.boosting[i]]
        if extra:
            standing = {i: r.alive for i, r in enumerate(self.riders) if i not in extra}
            for i in standing:
                self.riders[i].alive = False
            self._move_once()
            for i, was_alive in standing.items():
                self.riders[i].alive = was_alive
            for i in extra:
                self.energy[i] = max(0, self.energy[i] - BOOST_COST)
                if self.energy[i] < BOOST_COST:
                    self.boosting[i] = False
            self.events.append("boost")
        for i in range(len(self.riders)):
            if not self.boosting[i]:
                self.energy[i] = min(BOOST_MAX, self.energy[i] + BOOST_REGEN)
        alive = [i for i, r in enumerate(self.riders) if r.alive]
        if len(alive) <= 1:
            self.round_over = True
            if len(alive) == 1:
                self.winner = alive[0]
                self.riders[alive[0]].points += 1
                self.events.append(f"round:{self.riders[alive[0]].name}")
                if self.riders[alive[0]].points >= self.target_points:
                    self.over = True
            else:
                self.winner = None
                self.events.append("round:draw")
