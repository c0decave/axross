"""Byte Chase: a maze-chase game of axross's own.

The maze is generated from a seed (a depth-first maze on a half-width
grid, braided so most dead ends become loops, mirrored left to right);
every open cell holds a bit, four cells a root key. Four daemons start in
their den in the middle:

* **Tracker** walks the shortest path to the player,
* **Cutter** heads for the cell four steps ahead of the player,
* **Drifter** turns at random at each crossing,
* **Warden** patrols the four corners and chases only when close.

A root key makes the daemons flee for a while; caught then, a daemon goes
back to its den and the player scores 200, 400, 800, 1600. A daemon that
catches the player costs a life. All bits eaten: the next, faster level.
Tilt Maze (``jump=True``) adds a jump: for a few ticks the player is in
the air and daemons pass under.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field

WALL, OPEN = "#", "."
UP, DOWN, LEFT, RIGHT = (0, -1), (0, 1), (-1, 0), (1, 0)
DIRS = (UP, LEFT, DOWN, RIGHT)
BIT_POINTS, KEY_POINTS = 10, 50
SCARED_TICKS, JUMP_TICKS = 60, 6
#: Ticks between two daemons leaving the den at the start and after a catch.
RELEASE = 15
DAEMONS = ("Tracker", "Cutter", "Drifter", "Warden")


def generate_maze(seed: int, width: int = 21, height: int = 21, braid: float = 0.75) -> list[list[str]]:
    """A symmetric maze of WALL / OPEN, odd *width* and *height*, a border
    of walls, every open cell reachable from every other."""
    if width % 2 == 0 or height % 2 == 0 or width < 11 or height < 11:
        raise ValueError("the maze needs odd sizes of at least 11")
    rng = random.Random(seed)
    half = width // 2 + 1                       # columns 0..half-1, mirrored
    grid = [[WALL] * width for _ in range(height)]
    start = (1, 1)
    grid[1][1] = OPEN
    stack = [start]
    while stack:
        x, y = stack[-1]
        options = [(x + 2 * dx, y + 2 * dy, dx, dy) for dx, dy in DIRS
                   if 0 < x + 2 * dx < half and 0 < y + 2 * dy < height - 1 and grid[y + 2 * dy][x + 2 * dx] == WALL]
        if not options:
            stack.pop()
            continue
        nx, ny, dx, dy = rng.choice(options)
        grid[y + dy][x + dx] = OPEN
        grid[ny][nx] = OPEN
        stack.append((nx, ny))
    # open the middle column's cells so both halves join
    mid = width // 2
    for y in range(1, height - 1, 2):
        if rng.random() < 0.5 or y in (1, height - 2):
            grid[y][mid] = OPEN
            grid[y][mid - 1] = OPEN
    # braid: knock through most dead ends
    for y in range(1, height - 1):
        for x in range(1, half):
            if grid[y][x] != OPEN:
                continue
            walls = [(dx, dy) for dx, dy in DIRS if grid[y + dy][x + dx] == WALL]
            if len(walls) == 3 and rng.random() < braid:
                rng.shuffle(walls)
                for dx, dy in walls:
                    tx, ty = x + dx, y + dy
                    if 0 < tx < half and 0 < ty < height - 1:
                        grid[ty][tx] = OPEN
                        break
    for y in range(height):                       # mirror
        for x in range(half):
            grid[y][width - 1 - x] = grid[y][x]
    # the daemons' den: a 3x3 room in the middle
    cx, cy = width // 2, height // 2
    for y in range(cy - 1, cy + 2):
        for x in range(cx - 1, cx + 2):
            grid[y][x] = OPEN
    grid[cy - 2][cx] = OPEN
    return grid


def reachable(grid, start) -> set[tuple[int, int]]:
    seen, todo = {start}, deque([start])
    while todo:
        x, y = todo.popleft()
        for dx, dy in DIRS:
            n = (x + dx, y + dy)
            if n not in seen and grid[n[1]][n[0]] != WALL:
                seen.add(n)
                todo.append(n)
    return seen


@dataclass
class Daemon:
    name: str
    pos: tuple[int, int]
    home: tuple[int, int]
    facing: tuple[int, int] = UP
    patrol: int = 0
    #: Ticks it still waits in the den (released one after another).
    wait: int = 0


@dataclass
class ChaseGame:
    seed: int = 1
    jump: bool = False
    level: int = 1
    width: int = 21
    height: int = 21
    grid: list = field(default_factory=list)
    bits: set = field(default_factory=set)
    keys: set = field(default_factory=set)
    player: tuple[int, int] = (1, 1)
    facing: tuple[int, int] = RIGHT
    wanted: tuple[int, int] = RIGHT
    daemons: list = field(default_factory=list)
    score: int = 0
    lives: int = 3
    scared: int = 0
    chain: int = 0
    airborne: int = 0
    tick_count: int = 0
    over: bool = False
    events: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed * 7919 + self.level)
        self.new_level()

    # --- set-up --------------------------------------------------------------------

    def new_level(self) -> None:
        self.grid = generate_maze(self.seed * 1000 + self.level, self.width, self.height)
        cx, cy = self.width // 2, self.height // 2
        den = {(x, y) for y in range(cy - 1, cy + 2) for x in range(cx - 1, cx + 2)} | {(cx, cy - 2)}
        start = (cx, self.height - 2) if self.grid[self.height - 2][cx] == OPEN else (1, self.height - 2)
        self.player = start
        open_cells = reachable(self.grid, start) - den
        corners = [(1, 1), (self.width - 2, 1), (1, self.height - 2), (self.width - 2, self.height - 2)]
        self.keys = {c for c in corners if c in open_cells and c != start}
        self.bits = open_cells - self.keys - {start}
        homes = [(cx - 1, cy), (cx, cy), (cx + 1, cy), (cx, cy - 1)]
        self.daemons = [Daemon(n, h, h, wait=RELEASE * i) for i, (n, h) in enumerate(zip(DAEMONS, homes))]
        self.scared = self.airborne = 0

    # --- moving ---------------------------------------------------------------------

    def _open(self, cell) -> bool:
        x, y = cell
        return 0 <= y < self.height and 0 <= x < self.width and self.grid[y][x] != WALL

    def steer(self, direction: tuple[int, int]) -> None:
        self.wanted = direction

    def jump_now(self) -> None:
        if self.jump and not self.airborne:
            self.airborne = JUMP_TICKS
            self.events.append("jump")

    def _step_player(self) -> None:
        for d in (self.wanted, self.facing):
            n = (self.player[0] + d[0], self.player[1] + d[1])
            if self._open(n):
                self.facing = d
                self.player = n
                break
        if self.player in self.bits:
            self.bits.discard(self.player)
            self.score += BIT_POINTS
        if self.player in self.keys:
            self.keys.discard(self.player)
            self.score += KEY_POINTS
            self.scared = max(10, SCARED_TICKS - 5 * (self.level - 1))
            self.chain = 0
            self.events.append("key")

    def _path_step(self, start, goal) -> tuple[int, int] | None:
        """First step of a shortest path (BFS)."""
        if start == goal:
            return None
        prev = {start: None}
        todo = deque([start])
        while todo:
            cur = todo.popleft()
            if cur == goal:
                break
            for dx, dy in DIRS:
                n = (cur[0] + dx, cur[1] + dy)
                if n not in prev and self._open(n):
                    prev[n] = cur
                    todo.append(n)
        if goal not in prev:
            return None
        step = goal
        while prev[step] != start:
            step = prev[step]
        return (step[0] - start[0], step[1] - start[1])

    def _target(self, d: Daemon) -> tuple[int, int]:
        px, py = self.player
        if d.name == "Tracker":
            return self.player
        if d.name == "Cutter":
            for k in range(4, -1, -1):
                t = (px + self.facing[0] * k, py + self.facing[1] * k)
                if self._open(t):
                    return t
            return self.player
        if d.name == "Warden":
            if abs(d.pos[0] - px) + abs(d.pos[1] - py) <= 6:
                return self.player
            corners = [(1, 1), (self.width - 2, 1), (self.width - 2, self.height - 2), (1, self.height - 2)]
            if d.pos == corners[d.patrol % 4]:
                d.patrol += 1
            return corners[d.patrol % 4]
        return d.pos   # Drifter: chooses at random below

    def _step_daemon(self, d: Daemon) -> None:
        if d.wait > 0:
            d.wait -= 1
            return
        options = [dd for dd in DIRS if self._open((d.pos[0] + dd[0], d.pos[1] + dd[1]))
                   and dd != (-d.facing[0], -d.facing[1])] or \
            [dd for dd in DIRS if self._open((d.pos[0] + dd[0], d.pos[1] + dd[1]))]
        if not options:
            return
        if self.scared:
            # flee: the option that ends farthest from the player
            px, py = self.player
            choice = max(options, key=lambda dd: (abs(d.pos[0] + dd[0] - px) + abs(d.pos[1] + dd[1] - py),
                                                  self.rng.random()))
        elif d.name == "Drifter":
            choice = self.rng.choice(options)
        else:
            step = self._path_step(d.pos, self._target(d))
            choice = step if step in options else (step if step else self.rng.choice(options))
        d.facing = choice
        d.pos = (d.pos[0] + choice[0], d.pos[1] + choice[1])

    def _collide(self) -> None:
        if self.airborne:
            return
        for d in self.daemons:
            if d.pos != self.player:
                continue
            if self.scared:
                self.chain += 1
                self.score += 100 * 2 ** self.chain
                d.pos, d.facing = d.home, UP
                self.events.append("daemon")
            else:
                self.lives -= 1
                self.events.append("caught")
                if self.lives <= 0:
                    self.over = True
                    return
                self.player = (self.width // 2, self.height - 2) if self._open((self.width // 2, self.height - 2)) else (1, self.height - 2)
                for i, dd in enumerate(self.daemons):
                    dd.pos, dd.wait = dd.home, RELEASE * i
                self.scared = 0
                return

    def tick(self) -> None:
        """One step of the game (the window calls it on its timer)."""
        if self.over:
            return
        self.tick_count += 1
        self._step_player()
        self._collide()
        # daemons are a little slower than the player, faster each level
        every = max(2, 5 - self.level // 2) if not self.scared else 2
        if self.tick_count % every != 0:
            for d in self.daemons:
                self._step_daemon(d)
        self._collide()
        if self.scared:
            self.scared -= 1
        if self.airborne:
            self.airborne -= 1
        if not self.bits and not self.keys:
            self.level += 1
            self.score += 500
            self.events.append("level")
            self.new_level()
