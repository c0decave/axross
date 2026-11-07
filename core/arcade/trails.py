"""Trail Runner: a light-trail arena game of axross's own.

Riders move one cell per tick and leave a wall behind them; a rider that
runs into a wall, a trail or another rider is out. The last one moving
wins the round (a point); a round where everyone is out is a draw. The
computer's riders look ahead: each tick a rider takes the turn that keeps
the most room open (a flood fill of what it can still reach), so it does
not drive into a corner it could have avoided.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field

UP, DOWN, LEFT, RIGHT = (0, -1), (0, 1), (-1, 0), (1, 0)
#: The riders' colours - axross's own set (mint, magenta, lime, amber), not the
#: blue-against-orange of the light-cycle films.
COLOURS = ("#2ee6c5", "#ff4fa3", "#c6f432", "#ffb627")


@dataclass
class Rider:
    name: str
    pos: tuple[int, int]
    facing: tuple[int, int]
    human: bool = False
    alive: bool = True
    points: int = 0
    colour: str = "#ffffff"


@dataclass
class TrailsGame:
    seed: int = 1
    width: int = 60
    height: int = 40
    opponents: int = 2
    round_no: int = 0
    riders: list = field(default_factory=list)
    trail: dict = field(default_factory=dict)       # cell -> rider index
    over: bool = False
    winner: int | None = None
    events: list = field(default_factory=list)
    target_points: int = 5

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        starts = [((self.width // 4, self.height // 2), RIGHT), ((3 * self.width // 4, self.height // 2), LEFT),
                  ((self.width // 2, self.height // 4), DOWN), ((self.width // 2, 3 * self.height // 4), UP)]
        names = ["You", "Blaze", "Volt", "Ember"]
        self.riders = [Rider(names[i], starts[i][0], starts[i][1], human=(i == 0), colour=COLOURS[i])
                       for i in range(1 + max(1, min(3, self.opponents)))]
        self.new_round()

    def new_round(self) -> None:
        self.round_no += 1
        starts = [((self.width // 4, self.height // 2), RIGHT), ((3 * self.width // 4, self.height // 2), LEFT),
                  ((self.width // 2, self.height // 4), DOWN), ((self.width // 2, 3 * self.height // 4), UP)]
        self.trail = {}
        for i, r in enumerate(self.riders):
            r.pos, r.facing = starts[i]
            r.alive = True
            self.trail[r.pos] = i
        self.winner = None
        self.round_over = False

    def steer(self, direction: tuple[int, int]) -> None:
        me = self.riders[0]
        if direction != (-me.facing[0], -me.facing[1]):   # no U-turn into your own trail
            me.facing = direction

    def _free(self, cell, taken) -> bool:
        x, y = cell
        return 0 <= x < self.width and 0 <= y < self.height and cell not in self.trail and cell not in taken

    def _room(self, start, limit: int = 400) -> int:
        """How many cells are reachable from *start* (capped)."""
        if not self._free(start, ()):
            return 0
        seen, todo = {start}, deque([start])
        while todo and len(seen) < limit:
            x, y = todo.popleft()
            for dx, dy in (UP, DOWN, LEFT, RIGHT):
                n = (x + dx, y + dy)
                if n not in seen and self._free(n, ()):
                    seen.add(n)
                    todo.append(n)
        return len(seen)

    def _choose(self, r: Rider) -> None:
        options = [d for d in (r.facing, (r.facing[1], -r.facing[0]), (-r.facing[1], r.facing[0]))]
        scored = []
        for d in options:
            n = (r.pos[0] + d[0], r.pos[1] + d[1])
            scored.append((self._room(n), d == r.facing, self.rng.random(), d))
        scored.sort(reverse=True)
        r.facing = scored[0][3]

    def tick(self) -> None:
        if self.over:
            return
        if self.round_over:
            self.new_round()
            return
        for r in self.riders:
            if r.alive and not r.human:
                self._choose(r)
        targets = {}
        for i, r in enumerate(self.riders):
            if r.alive:
                targets[i] = (r.pos[0] + r.facing[0], r.pos[1] + r.facing[1])
        counts: dict = {}
        for cell in targets.values():
            counts[cell] = counts.get(cell, 0) + 1
        for i, cell in targets.items():
            r = self.riders[i]
            if not self._free(cell, ()) or counts[cell] > 1:
                r.alive = False
                self.events.append(f"out:{r.name}")
        for i, cell in targets.items():
            r = self.riders[i]
            if r.alive:
                r.pos = cell
                self.trail[cell] = i
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
                self.events.append("round:draw")
