"""Tilt Maze's campaign: 100 levels in 10 worlds, each level a fixed seed
and a set of parameters, every board built and checked by :func:`build`.

World by world the boards grow (21x21 up to 33x33, larger than the screen:
the camera follows), the maze opens up or narrows, pits appear (a jump
crosses one), then teleporter pairs, the Hopper (a daemon that jumps pits
too), shorter key times and faster daemons. A level is only accepted when
every bit can be reached from the start - walking, through teleporters or
jumping a single pit - so no level is unwinnable.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass

from core.arcade import chase as C

PIT, TELEPORT = " ", "T"
WORLDS = (
    # name,          size, braid, pits, teleports, daemons,                                      speed, scared
    ("Meadow",        21, 0.80, 0, 0, ("Tracker", "Drifter"),                                     0, 70),
    ("Lattice",       23, 0.75, 0, 0, ("Tracker", "Cutter", "Drifter"),                           0, 65),
    ("Brook",         23, 0.70, 4, 0, ("Tracker", "Cutter", "Drifter"),                           1, 60),
    ("Terraces",      25, 0.85, 8, 0, ("Tracker", "Cutter", "Drifter", "Warden"),                 1, 55),
    ("Relay",         25, 0.70, 6, 1, ("Tracker", "Cutter", "Drifter", "Warden"),                 1, 50),
    ("Springs",       27, 0.80, 10, 1, ("Tracker", "Cutter", "Hopper", "Warden"),                 2, 48),
    ("Switchyard",    27, 0.65, 8, 2, ("Tracker", "Cutter", "Drifter", "Hopper", "Warden"),       2, 44),
    ("Causeway",      29, 0.90, 16, 1, ("Tracker", "Cutter", "Hopper", "Hopper", "Warden"),       3, 40),
    ("Labyrinth",     31, 0.55, 10, 2, ("Tracker", "Cutter", "Drifter", "Hopper", "Warden"),      3, 36),
    ("Summit",        33, 0.75, 18, 3, ("Tracker", "Tracker", "Cutter", "Hopper", "Hopper", "Warden"), 4, 32),
)


@dataclass(frozen=True)
class LevelSpec:
    number: int            # 1 .. 100
    world: int             # 0 .. 9
    name: str
    size: int
    braid: float
    pits: int
    teleports: int
    daemons: tuple[str, ...]
    speed: int             # 0 .. 4: how much of the player's pace the daemons keep
    scared: int            # ticks a key turns them
    seed: int


def campaign() -> list[LevelSpec]:
    out = []
    for w, (name, size, braid, pits, tele, daemons, speed, scared) in enumerate(WORLDS):
        # the board grows late in a world, but never past where the next world starts
        nxt = WORLDS[w + 1][1] if w + 1 < len(WORLDS) else size + 2
        for i in range(10):
            n = w * 10 + i + 1
            out.append(LevelSpec(
                number=n, world=w, name=f"{name} {i + 1}", size=min(size + (2 if i >= 6 else 0), nxt),
                braid=max(0.4, braid - 0.02 * (i % 5)), pits=pits + i // 2 * (1 if pits else 0),
                teleports=tele, daemons=daemons, speed=min(4, speed + (1 if i >= 8 else 0)),
                scared=max(24, scared - i), seed=7000 + n * 131))
    return out


def password(world: int) -> str:
    """The code that opens a world in the level select: six letters derived
    from its number (no vowels: no words by chance)."""
    rng = random.Random(world * 2654435761 + 97)
    return "".join(rng.choice("BCDFGHJKLMNPQRSTVWXZ") for _ in range(6))


def world_of(code: str) -> int | None:
    code = code.strip().upper()
    return next((w for w in range(len(WORLDS)) if password(w) == code), None)


def _neighbours(grid, cell):
    """Moves from *cell*: a step onto open ground or a teleporter, or a jump
    over one pit onto open ground in a straight line."""
    x, y = cell
    h, w = len(grid), len(grid[0])
    for dx, dy in C.DIRS:
        nx, ny = x + dx, y + dy
        if not (0 <= nx < w and 0 <= ny < h):
            continue
        c = grid[ny][nx]
        if c in (C.OPEN, TELEPORT):
            yield (nx, ny)
        elif c == PIT:
            jx, jy = nx + dx, ny + dy
            if 0 <= jx < w and 0 <= jy < h and grid[jy][jx] in (C.OPEN, TELEPORT):
                yield (jx, jy)


def reachable(grid, start, links=None) -> set:
    links = links or {}
    seen, todo = {start}, deque([start])
    while todo:
        cur = todo.popleft()
        nxt = list(_neighbours(grid, cur))
        if cur in links:
            nxt.append(links[cur])
        for n in nxt:
            if n not in seen:
                seen.add(n)
                todo.append(n)
    return seen


@dataclass
class Board:
    spec: LevelSpec
    grid: list
    start: tuple[int, int]
    keys: set
    bits: set
    links: dict            # teleporter -> its partner
    den: set


def build(spec: LevelSpec) -> Board:
    """The level's board, checked; tries the next seeds until a board passes."""
    for attempt in range(40):
        board = _try(spec, spec.seed + attempt * 7919)
        if board is not None:
            return board
    raise RuntimeError(f"level {spec.number}: no board passed the checks")


def _try(spec: LevelSpec, seed: int) -> Board | None:
    rng = random.Random(seed)
    size = spec.size
    grid = C.generate_maze(seed, size, size, braid=spec.braid)
    cx, cy = size // 2, size // 2
    den = {(x, y) for y in range(cy - 1, cy + 2) for x in range(cx - 1, cx + 2)} | {(cx, cy - 2)}
    start = (cx, size - 2) if grid[size - 2][cx] == C.OPEN else (1, size - 2)
    # pits: straight corridor cells with open ground on both sides along the corridor
    candidates = [(x, y) for y in range(2, size - 2) for x in range(2, size - 2)
                  if grid[y][x] == C.OPEN and (x, y) not in den and abs(x - start[0]) + abs(y - start[1]) > 3
                  and ((grid[y][x - 1] == grid[y][x + 1] == C.OPEN and grid[y - 1][x] == grid[y + 1][x] == C.WALL)
                       or (grid[y - 1][x] == grid[y + 1][x] == C.OPEN and grid[y][x - 1] == grid[y][x + 1] == C.WALL))]
    rng.shuffle(candidates)
    pits = []
    for x, y in candidates:
        if len(pits) >= spec.pits:
            break
        if any(abs(x - px) + abs(y - py) < 3 for px, py in pits):
            continue
        mx = size - 1 - x                         # keep the board symmetric
        grid[y][x] = PIT
        grid[y][mx] = PIT
        pits += [(x, y), (mx, y)]
    # teleporters: pairs on opposite dead-ish corners of the board
    links = {}
    open_cells = [(x, y) for y in range(1, size - 1) for x in range(1, size - 1)
                  if grid[y][x] == C.OPEN and (x, y) not in den and (x, y) != start]
    pairs, tries = 0, 0
    while pairs < spec.teleports and tries < 200:
        tries += 1
        a = rng.choice([c for c in open_cells if c[0] < size // 3 and c not in links])
        b = (size - 1 - a[0], size - 1 - a[1])
        if b in links or grid[b[1]][b[0]] != C.OPEN or b == start or b == a:
            continue
        grid[a[1]][a[0]] = grid[b[1]][b[0]] = TELEPORT
        links[a], links[b] = b, a
        pairs += 1
    if pairs < spec.teleports:
        return None
    reach = reachable(grid, start, links)
    corners = [(1, 1), (size - 2, 1), (1, size - 2), (size - 2, size - 2)]
    keys = {c for c in corners if c in reach and grid[c[1]][c[0]] == C.OPEN}
    if len(keys) < 2:
        return None
    walkable = {(x, y) for y in range(size) for x in range(size) if grid[y][x] in (C.OPEN, TELEPORT)}
    bits = {c for c in reach if grid[c[1]][c[0]] == C.OPEN} - keys - den - {start}
    if walkable - reach - den or len(bits) < 60:  # something unreachable: try another board
        return None
    return Board(spec, grid, start, keys, bits, links, den)
