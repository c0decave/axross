"""Rockfall: a cave-digging game of axross's own.

The cave is generated from a seed: walls round it and in a few stretches
inside, earth everywhere else, rocks and crystals scattered, a few empty
pockets, crawlers in some of them. The digger moves through earth (it
becomes empty), collects crystals, pushes a single rock sideways into an
empty cell. Rocks and crystals fall into empty space, and roll off a rock,
a crystal or a wall when the cell beside and the one below it are empty.
Something falling onto the digger or a crawler ends it - a crawler hit
leaves crystals where it was; nothing falls, rolls or is pushed into a
creature's cell. Collect the level's quota and the exit
opens; reach it before the time runs out.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

WALL, EARTH, EMPTY, ROCK, GEM, EXIT = "#", ":", " ", "o", "*", "E"
UP, DOWN, LEFT, RIGHT = (0, -1), (0, 1), (-1, 0), (1, 0)


@dataclass
class Crawler:
    pos: tuple[int, int]
    facing: tuple[int, int] = LEFT


@dataclass
class RockfallGame:
    seed: int = 1
    level: int = 1
    width: int = 32
    height: int = 18
    grid: list = field(default_factory=list)
    player: tuple[int, int] = (1, 1)
    exit: tuple[int, int] = (1, 1)
    crawlers: list = field(default_factory=list)
    quota: int = 10
    gems: int = 0
    score: int = 0
    lives: int = 3
    time_left: int = 0
    falling: set = field(default_factory=set)
    over: bool = False
    won_level: bool = False
    events: list = field(default_factory=list)
    _wanted: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        self.new_level()

    def new_level(self) -> None:
        rng = random.Random(self.seed * 104729 + self.level)
        w, h = self.width, self.height
        g = [[EARTH] * w for _ in range(h)]
        for x in range(w):
            g[0][x] = g[h - 1][x] = WALL
        for y in range(h):
            g[y][0] = g[y][w - 1] = WALL
        for _ in range(3 + self.level):            # inner wall stretches
            x, y = rng.randrange(3, w - 4), rng.randrange(3, h - 3)
            length = rng.randrange(3, 8)
            horizontal = rng.random() < 0.6
            for k in range(length):
                cx, cy = (x + k, y) if horizontal else (x, y + k)
                if 1 < cx < w - 2 and 1 < cy < h - 2:
                    g[cy][cx] = WALL
        cells = [(x, y) for y in range(1, h - 1) for x in range(1, w - 1) if g[y][x] == EARTH]
        rng.shuffle(cells)
        n_rock = len(cells) // 7
        n_gem = 12 + 2 * self.level
        for x, y in cells[:n_rock]:
            g[y][x] = ROCK
        for x, y in cells[n_rock:n_rock + n_gem]:
            g[y][x] = GEM
        self.crawlers = []
        for x, y in cells[n_rock + n_gem:n_rock + n_gem + min(1 + self.level, 6)]:
            for dx in (-1, 0, 1):                    # a small pocket for each crawler
                if g[y][x + dx] not in (WALL,):
                    g[y][x + dx] = EMPTY
            self.crawlers.append(Crawler((x, y)))
        self.player = (2, 2)
        for dx in (-1, 0, 1):                        # the start and what is above it is clear
            for dy in (-1, 0, 1):
                x, y = 2 + dx, 2 + dy
                if g[y][x] != WALL:
                    g[y][x] = EARTH
        g[2][2] = EMPTY
        self.exit = (w - 3, h - 3)
        g[h - 3][w - 3] = WALL                       # closed until the quota is reached
        self.grid = g
        self.quota = 8 + 2 * self.level
        self.gems = 0
        self.time_left = 150 * 10 + 20 * self.level  # ticks (10 per second)
        self.falling = set()
        self.won_level = False

    # --- the player -----------------------------------------------------------------------

    def steer(self, direction: tuple[int, int] | None) -> None:
        self._wanted = direction

    def _at(self, x, y) -> str:
        return self.grid[y][x]

    def _move_player(self) -> None:
        d = self._wanted
        if d is None:
            return
        x, y = self.player
        nx, ny = x + d[0], y + d[1]
        cell = self._at(nx, ny)
        if cell in (EARTH, EMPTY, GEM) or (cell == EXIT):
            if cell == GEM:
                self._collect_gem()
            if cell == EXIT:
                self.score += self.time_left // 10
                self.won_level = True
                self.events.append("level")
            self.grid[y][x] = EMPTY
            self.player = (nx, ny)
            self.grid[ny][nx] = EMPTY if cell != EXIT else EXIT
        elif cell == ROCK and d in (LEFT, RIGHT):
            bx = nx + d[0]
            if self._at(bx, ny) == EMPTY and (nx, ny) not in self.falling \
                    and not self._creature_at((bx, ny)):
                self.grid[ny][bx] = ROCK
                self.grid[ny][nx] = EMPTY
                self.grid[y][x] = EMPTY
                self.player = (nx, ny)

    def _collect_gem(self) -> None:
        """The digger takes a crystal: points, and the exit opens at the quota."""
        self.gems += 1
        self.score += 10 + (5 if self.gems > self.quota else 0)
        self.events.append("gem")
        if self.gems == self.quota:
            self.grid[self.exit[1]][self.exit[0]] = EXIT
            self.events.append("exit-open")

    # --- physics ----------------------------------------------------------------------------

    def _creature_at(self, cell) -> bool:
        """A creature stands in *cell* (its grid cell reads EMPTY): rocks and
        crystals treat it like the digger's cell - they neither fall, roll
        nor get pushed into it."""
        return cell in self._creature_cells()

    def _creature_cells(self) -> set:
        return {c.pos for c in self.crawlers}

    def _fall_onto_creature(self, cell, kind: str) -> None:
        """Something of *kind* that was falling comes down onto the creature
        in *cell*: a crawler is crushed (crystals, points)."""
        for c in list(self.crawlers):
            if c.pos == cell:
                self._crush_crawler(c)
                return

    def _physics(self) -> None:
        g = self.grid
        falling = set()
        moved = set()
        crushed = False
        for y in range(self.height - 2, 0, -1):         # bottom up
            for x in range(1, self.width - 1):
                if (x, y) in moved or g[y][x] not in (ROCK, GEM):
                    continue
                below = g[y + 1][x]
                was_falling = (x, y) in self.falling
                target = None
                occupied = {self.player} | self._creature_cells()
                if below == EMPTY and (x, y + 1) not in occupied:
                    target = (x, y + 1)
                elif below in (ROCK, GEM, WALL) and (x, y + 1) not in self.falling:
                    for dx in (-1, 1):
                        if g[y][x + dx] == EMPTY and g[y + 1][x + dx] == EMPTY \
                                and (x + dx, y) not in occupied and (x + dx, y + 1) not in occupied:
                            target = (x + dx, y)
                            break
                elif was_falling and (x, y + 1) == self.player:
                    crushed = True      # handled after the loop: it replaces the grid
                    continue
                elif was_falling and below == EMPTY:
                    # a creature under it: crushed, and the rock stops where it is
                    self._fall_onto_creature((x, y + 1), g[y][x])
                    continue
                if target is None:
                    continue
                kind = g[y][x]
                g[y][x] = EMPTY
                g[target[1]][target[0]] = kind
                moved.add(target)
                falling.add(target)
                for c in list(self.crawlers):
                    if c.pos == (target[0], target[1] + 1) and target[1] > y:
                        self._crush_crawler(c)
        self.falling = falling
        if crushed:
            self._crushed_player()

    def _crushed_player(self) -> None:
        self.lives -= 1
        self.events.append("crushed")
        if self.lives <= 0:
            self.over = True
        else:
            self.new_level()

    def _crush_crawler(self, c: Crawler) -> None:
        self.crawlers.remove(c)
        x, y = c.pos
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if self.grid[y + dy][x + dx] in (EMPTY, EARTH) and (x + dx, y + dy) != self.player:
                    self.grid[y + dy][x + dx] = GEM
        self.score += 50
        self.events.append("crawler")

    # --- crawlers: keep a wall on their left ------------------------------------------------------

    def _move_crawlers(self) -> None:
        for c in self.crawlers:
            f = c.facing
            left = (f[1], -f[0])
            right = (-f[1], f[0])
            for d in (left, f, right, (-f[0], -f[1])):
                nx, ny = c.pos[0] + d[0], c.pos[1] + d[1]
                if (nx, ny) == self.player:
                    self._crushed_player()
                    return
                if self.grid[ny][nx] == EMPTY:
                    c.facing, c.pos = d, (nx, ny)
                    break
            if abs(c.pos[0] - self.player[0]) + abs(c.pos[1] - self.player[1]) == 1:
                self._crushed_player()
                return

    def tick(self) -> None:
        if self.over:
            return
        if self.won_level:
            self.level += 1
            self.new_level()
            return
        self._move_player()
        if self.won_level:
            return
        self._physics()
        if self.over:
            return
        if self.time_left % 2 == 0:
            self._move_crawlers()
        self.time_left -= 1
        if self.time_left <= 0:
            self.events.append("time")
            self._crushed_player()
