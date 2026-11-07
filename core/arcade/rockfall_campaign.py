"""Rockfall's campaign: 40 caves in 5 worlds, and the rules that came with
them - axross's own cave game.

On top of core.arcade.rockfall: Space with a direction *takes* the cell
beside the digger (digs earth, collects a crystal) without stepping into
it; **prisms** split a rock that falls onto them into two crystals (left
and right, where there is room); **seekers** creep through empty space
towards the digger and turn into crystals under a rock, like crawlers.
Caves are larger than the window (the camera scrolls). Every cave is
built from a seed and its world's parameters and accepted only when
enough crystals can be reached by digging - none is unwinnable.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass

from core.arcade import rockfall as R

PRISM = "^"
WORLDS = (
    # name,       w,  h, rocks, gems, walls, crawlers, seekers, prisms, quota, seconds
    ("Topsoil",   32, 18, 0.12, 16, 3, 1, 0, 0, 10, 150),
    ("Clay Pits", 36, 20, 0.15, 18, 5, 2, 0, 2, 12, 140),
    ("Prism Hall", 40, 22, 0.16, 18, 6, 2, 1, 5, 14, 140),
    ("Deep Vein", 44, 24, 0.18, 20, 8, 3, 2, 4, 16, 130),
    ("The Core",  48, 26, 0.20, 22, 10, 4, 3, 6, 18, 120),
)


@dataclass(frozen=True)
class CaveSpec:
    number: int          # 1 .. 40
    world: int
    name: str
    width: int
    height: int
    rocks: float
    gems: int
    walls: int
    crawlers: int
    seekers: int
    prisms: int
    quota: int
    seconds: int
    seed: int


def campaign() -> list[CaveSpec]:
    out = []
    for w, (name, width, height, rocks, gems, walls, crawlers, seekers, prisms, quota, secs) in enumerate(WORLDS):
        for i in range(8):
            n = w * 8 + i + 1
            out.append(CaveSpec(n, w, f"{name} {i + 1}", width, height, rocks + 0.005 * i, gems + i,
                                walls + i // 2, crawlers + i // 4, seekers + (1 if i >= 6 else 0),
                                prisms + i // 3, quota + i, max(70, secs - 4 * i), 5100 + n * 89))
    return out


def password(world: int) -> str:
    rng = random.Random(world * 40503 + 11)
    return "".join(rng.choice("BCDFGHJKLMNPQRSTVWXZ") for _ in range(6))


def world_of(code: str) -> int | None:
    code = code.strip().upper()
    return next((w for w in range(len(WORLDS)) if password(w) == code), None)


@dataclass
class Seeker:
    pos: tuple[int, int]
    wait: int = 0


class CaveGame(R.RockfallGame):
    """A campaign cave; *level* is the cave number."""

    def __init__(self, level: int = 1, lives: int = 3, score: int = 0):
        self.campaign = campaign()
        self.grab = False
        self.seekers: list[Seeker] = []
        super().__init__(seed=1, level=max(1, min(len(self.campaign), level)))
        self.lives, self.score = lives, score
        self.completed = False

    @property
    def spec(self) -> CaveSpec:
        return self.campaign[self.level - 1]

    def new_level(self) -> None:
        spec = self.spec
        for attempt in range(40):
            if self._build(spec, spec.seed + attempt * 7919):
                return
        raise RuntimeError(f"cave {spec.number}: no cave passed the checks")

    def _build(self, spec: CaveSpec, seed: int) -> bool:
        rng = random.Random(seed)
        w, h = spec.width, spec.height
        self.width, self.height = w, h
        g = [[R.EARTH] * w for _ in range(h)]
        for x in range(w):
            g[0][x] = g[h - 1][x] = R.WALL
        for y in range(h):
            g[y][0] = g[y][w - 1] = R.WALL
        for _ in range(spec.walls):
            x, y = rng.randrange(4, w - 6), rng.randrange(3, h - 3)
            length = rng.randrange(4, 10)
            horizontal = rng.random() < 0.65
            for k in range(length):
                cx, cy = (x + k, y) if horizontal else (x, y + k)
                if 1 < cx < w - 2 and 1 < cy < h - 2:
                    g[cy][cx] = R.WALL
        cells = [(x, y) for y in range(1, h - 1) for x in range(1, w - 1) if g[y][x] == R.EARTH
                 and not (x < 5 and y < 5)]
        rng.shuffle(cells)
        # creatures start well away from the digger (at least 8 cells)
        far = [c for c in cells if abs(c[0] - 2) + abs(c[1] - 2) >= 8]
        near = [c for c in cells if c not in set(far)]
        cells = near[:len(near) // 2] + far + near[len(near) // 2:]
        creature_cells = [c for c in far if 2 <= c[0] <= w - 3]
        n_rock = int(len(cells) * spec.rocks)
        i = 0
        for x, y in cells[i:i + n_rock]:
            g[y][x] = R.ROCK
        i += n_rock
        for x, y in cells[i:i + spec.gems]:
            g[y][x] = R.GEM
        i += spec.gems
        for x, y in cells[i:i + spec.prisms]:
            g[y][x] = PRISM
        i += spec.prisms
        self.crawlers = []
        rng.shuffle(creature_cells)
        for x, y in creature_cells[:spec.crawlers]:
            for dx in (-1, 0, 1):
                if g[y][x + dx] != R.WALL:
                    g[y][x + dx] = R.EMPTY
            self.crawlers.append(R.Crawler((x, y)))
        self.seekers = []
        for x, y in creature_cells[spec.crawlers:spec.crawlers + spec.seekers]:
            g[y][x] = R.EMPTY
            self.seekers.append(Seeker((x, y)))
        self.grace = 20                               # two seconds before anything can catch the digger
        for dy in range(1, 4):
            for dx in range(1, 4):
                g[dy][dx] = R.EARTH
        g[2][2] = R.EMPTY
        self.player = (2, 2)
        self.exit = (w - 3, h - 3)
        g[h - 3][w - 3] = R.WALL
        # the exit's way in: earth around it
        for dx, dy in ((-1, 0), (0, -1), (-1, -1)):
            if g[h - 3 + dy][w - 3 + dx] in (R.ROCK, PRISM):
                g[h - 3 + dy][w - 3 + dx] = R.EARTH
        self.grid = g
        self.quota = spec.quota
        self.gems = 0
        self.time_left = spec.seconds * 10
        self.falling = set()
        self.won_level = False
        # accepted only when the quota can be dug to (rocks and walls block; pushing is extra)
        seen, todo = {(2, 2)}, deque([(2, 2)])
        reached_gems = 0
        while todo:
            x, y = todo.popleft()
            for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nx, ny = x + dx, y + dy
                if (nx, ny) in seen or not (0 <= nx < w and 0 <= ny < h):
                    continue
                if g[ny][nx] in (R.EARTH, R.EMPTY, R.GEM):
                    seen.add((nx, ny))
                    todo.append((nx, ny))
                    reached_gems += g[ny][nx] == R.GEM
        exit_near = any((self.exit[0] + dx, self.exit[1] + dy) in seen
                        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)))
        return reached_gems >= spec.quota + 2 and exit_near

    # -- the digger ----------------------------------------------------------------------

    def steer(self, direction, grab: bool = False) -> None:
        self._wanted = direction
        self.grab = bool(grab) and direction is not None

    def _move_player(self) -> None:
        d = self._wanted
        if d is None:
            return
        if not self.grab:
            x, y = self.player
            if self._at(x + d[0], y + d[1]) == PRISM:
                return                                 # prisms are solid
            return super()._move_player()
        x, y = self.player
        nx, ny = x + d[0], y + d[1]
        cell = self._at(nx, ny)
        if cell == R.EARTH:
            self.grid[ny][nx] = R.EMPTY
            self.events.append("dig")
        elif cell == R.GEM and (nx, ny) not in self.falling:
            self.grid[ny][nx] = R.EMPTY
            self.gems += 1
            self.score += 10 + (5 if self.gems > self.quota else 0)
            self.events.append("gem")
            if self.gems == self.quota:
                self.grid[self.exit[1]][self.exit[0]] = R.EXIT
                self.events.append("exit-open")

    # -- prisms and seekers ----------------------------------------------------------------

    def _physics(self) -> None:
        before = set(self.falling)
        super()._physics()
        g = self.grid
        for (x, y) in list(before | self.falling):
            if not (0 < y < self.height - 1) or g[y][x] != R.ROCK:
                continue
            if g[y + 1][x] == PRISM and (x, y) in before | self.falling:
                g[y][x] = R.EMPTY
                split = 0
                for dx in (-1, 1):
                    if g[y + 1][x + dx] == R.EMPTY:
                        g[y + 1][x + dx] = R.GEM
                        self.falling.add((x + dx, y + 1))
                        split += 1
                if not split:
                    g[y][x] = R.GEM
                self.events.append("prism")
        for s in list(self.seekers):
            if g[s.pos[1] - 1][s.pos[0]] == R.ROCK and (s.pos[0], s.pos[1] - 1) in self.falling:
                self.seekers.remove(s)
                x, y = s.pos
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        if g[y + dy][x + dx] in (R.EMPTY, R.EARTH) and (x + dx, y + dy) != self.player:
                            g[y + dy][x + dx] = R.GEM
                self.score += 75
                self.events.append("crawler")

    def _move_seekers(self) -> None:
        px, py = self.player
        for s in self.seekers:
            if s.wait > 0:
                s.wait -= 1
                continue
            s.wait = 3
            options = []
            for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nx, ny = s.pos[0] + dx, s.pos[1] + dy
                if (nx, ny) == self.player:
                    self._crushed_player()
                    return
                if self.grid[ny][nx] == R.EMPTY:
                    options.append((abs(nx - px) + abs(ny - py), (nx, ny)))
            if options:
                s.pos = min(options)[1]

    def _crushed_player(self) -> None:
        if getattr(self, "grace", 0) > 0:
            return
        super()._crushed_player()

    def tick(self) -> None:
        if self.completed:
            return
        if getattr(self, "grace", 0) > 0:
            self.grace -= 1
        if self.won_level and self.level >= len(self.campaign):
            self.completed = True
            self.events.append("complete")
            return
        super().tick()
        if not self.over and not self.won_level:
            self._move_seekers()
