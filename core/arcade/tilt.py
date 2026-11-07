"""Tilt Maze: the chase on an isometric board - axross's own game.

The rules of core.arcade.chase on the campaign's boards
(core.arcade.tilt_levels): pits (a fall costs a life; a jump carries over
one), teleporter pairs, the Hopper - a daemon that jumps pits as well -,
the level's daemon speed and key time, extra lives at 10 000, 30 000 and
every 50 000 after. The window animates between ticks (``progress``).
"""

from __future__ import annotations

import random

from core.arcade import chase as C
from core.arcade import tilt_levels as L

EXTRA_LIVES = (10_000, 30_000)
EXTRA_EVERY = 50_000


class TiltGame(C.ChaseGame):
    def __init__(self, level: int = 1, seed: int = 1, lives: int = 3, score: int = 0):
        self.campaign = L.campaign()
        self._start_level = max(1, min(len(self.campaign), level))
        self._lives0, self._score0 = lives, score
        self.next_extra = next((x for x in EXTRA_LIVES if x > score), None) or \
            ((score // EXTRA_EVERY) + 1) * EXTRA_EVERY
        self.completed = False
        self.falling = 0
        super().__init__(seed=seed, jump=True, level=self._start_level)
        self.lives, self.score = lives, score

    # -- the board -------------------------------------------------------------------------

    @property
    def spec(self) -> L.LevelSpec:
        return self.campaign[self.level - 1]

    def new_level(self) -> None:
        board = L.build(self.spec)
        self.board = board
        self.grid = board.grid
        self.width = self.height = len(board.grid)
        self.player = board.start
        self.facing = self.wanted = C.UP
        self.bits, self.keys = set(board.bits), set(board.keys)
        cx, cy = self.width // 2, self.height // 2
        homes = [(cx - 1, cy), (cx, cy), (cx + 1, cy), (cx, cy - 1), (cx - 1, cy - 1), (cx + 1, cy - 1)]
        self.daemons = [C.Daemon(n, homes[i % len(homes)], homes[i % len(homes)], wait=C.RELEASE * i)
                        for i, n in enumerate(self.spec.daemons)]
        self.scared = self.airborne = self.falling = 0
        self.rng = random.Random(self.spec.seed)

    def _cell(self, cell) -> str:
        x, y = cell
        if 0 <= y < self.height and 0 <= x < self.width:
            return self.grid[y][x]
        return C.WALL

    def _open(self, cell) -> bool:
        """Walkable for the daemons' paths: open ground and teleporters."""
        return self._cell(cell) in (C.OPEN, L.TELEPORT)

    # -- the player ------------------------------------------------------------------------

    def _step_player(self) -> None:
        if self.falling:
            return
        for d in (self.wanted, self.facing):
            n = (self.player[0] + d[0], self.player[1] + d[1])
            c = self._cell(n)
            if c in (C.OPEN, L.TELEPORT, L.PIT):     # a pit without a jump: a fall
                self.facing = d
                self.player = n
                break
        c = self._cell(self.player)
        if c == L.PIT and not self.airborne:
            self.falling = 8
            self.events.append("fall")
            return
        if c == L.TELEPORT and not self.airborne and self.player in self.board.links:
            self.player = self.board.links[self.player]
            self.events.append("teleport")
            # step off the far one so the pair does not bounce
            for d in (self.facing, *C.DIRS):
                n = (self.player[0] + d[0], self.player[1] + d[1])
                if self._cell(n) == C.OPEN:
                    self.player = n
                    break
        if self.player in self.bits:
            self.bits.discard(self.player)
            self.score += C.BIT_POINTS
            self.events.append("bit")
        if self.player in self.keys:
            self.keys.discard(self.player)
            self.score += C.KEY_POINTS
            self.scared = self.spec.scared
            self.chain = 0
            self.events.append("key")

    # -- the daemons -------------------------------------------------------------------------

    def _step_daemon(self, d: C.Daemon) -> None:
        if d.name != "Hopper" or d.wait > 0:
            return super()._step_daemon(d)
        # the Hopper: may also jump a single pit towards the player
        px, py = self.player
        options = []
        for dd in C.DIRS:
            one = (d.pos[0] + dd[0], d.pos[1] + dd[1])
            if self._open(one):
                options.append((one, dd))
            elif self._cell(one) == L.PIT:
                two = (one[0] + dd[0], one[1] + dd[1])
                if self._open(two):
                    options.append((two, dd))
        back = (-d.facing[0], -d.facing[1])
        forward = [o for o in options if o[1] != back] or options
        if not forward:
            return
        if self.scared:
            pick = max(forward, key=lambda o: abs(o[0][0] - px) + abs(o[0][1] - py))
        else:
            pick = min(forward, key=lambda o: (abs(o[0][0] - px) + abs(o[0][1] - py), self.rng.random()))
        d.pos, d.facing = pick

    # -- the tick -----------------------------------------------------------------------------

    def _lose_life(self) -> None:
        self.lives -= 1
        self.events.append("caught")
        if self.lives <= 0:
            self.over = True
            return
        self.player = self.board.start
        self.wanted = self.facing = (0, 0)        # stands still until the next key
        for i, dd in enumerate(self.daemons):
            dd.pos, dd.wait = dd.home, C.RELEASE * i
        self.scared = self.airborne = 0

    def _collide(self) -> None:
        if self.airborne or self.falling:
            return
        for d in self.daemons:
            if d.pos != self.player:
                continue
            if self.scared:
                self.chain += 1
                self.score += 100 * 2 ** self.chain
                d.pos, d.facing, d.wait = d.home, C.UP, 10
                self.events.append("daemon")
            else:
                self._lose_life()
                return

    def tick(self) -> None:
        if self.over or self.completed:
            return
        if self.falling:
            self.falling -= 1
            if self.falling == 0:
                self._lose_life()
            return
        self.tick_count += 1
        self._step_player()
        self._collide()
        every = max(2, 5 - self.spec.speed) if not self.scared else 2
        if self.tick_count % every != 0:
            for d in self.daemons:
                self._step_daemon(d)
        self._collide()
        if self.scared:
            self.scared -= 1
        if self.airborne:
            self.airborne -= 1
            if not self.airborne and self._cell(self.player) == L.PIT:
                self.falling = 8
                self.events.append("fall")
        if self.score >= self.next_extra:
            self.lives += 1
            self.events.append("extra-life")
            later = [x for x in EXTRA_LIVES if x > self.score]
            self.next_extra = later[0] if later else (self.score // EXTRA_EVERY + 1) * EXTRA_EVERY
        if not self.bits and not self.keys:
            self.score += 500 + 50 * self.level
            self.events.append("level")
            if self.level >= len(self.campaign):
                self.completed = True
                self.events.append("complete")
                return
            self.level += 1
            self.new_level()
