"""The Arcade over a long session, offscreen: "smooth at first, then
overloaded, slow and stuttering".

Each game is played for minutes of game time on a fixed clock - random
keys, deaths, restarts with R, Trail Runner's next rounds, the window
resized now and then as a user drags its corner - and painted into a
QImage every frame. What must stay flat: the CPU time of a frame (the
last minute against the first), the timers and their connections, the
pages of the window, Python's objects, the particles, the held keys -
and the shared sprite cache, which used to keep a full-window pixmap for
every window size and world (~400 MiB after one drag of the corner).
"""

from __future__ import annotations

import gc
import os
import random
import statistics
import sys
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEvent, QTimer  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

FPS = 30
MINUTES = 3
#: What the sprite cache may hold at most, whatever the session did.
SPRITE_CEILING = 64 * 1024 * 1024
SIZES = [(900 + 20 * k, 640 + 9 * k) for k in range(40)]


class FakeAudio:
    muted = False

    def __init__(self):
        self.played = 0

    def play(self, name, gain=1.0):
        self.played += 1

    def music(self, seed, mood=""):
        pass

    def stop(self):
        pass


def _sprite_bytes() -> int:
    from ui import arcade_common as AC

    return sum(pm.width() * pm.height() * 4 for pm in AC._SPRITES.values())


@pytest.fixture
def fixed_clock(monkeypatch):
    from ui import (arcade_chase_view, arcade_common, arcade_picker, arcade_rockfall_view, arcade_tilt_view,
                    arcade_trails_view)

    clock = [1000.0]
    fake = types.SimpleNamespace(monotonic=lambda: clock[0])
    for module in (arcade_common, arcade_chase_view, arcade_rockfall_view, arcade_tilt_view, arcade_trails_view,
                   arcade_picker):
        monkeypatch.setattr(module, "time", fake)
    arcade_common._SPRITES.clear()
    if hasattr(arcade_common, "clear_sprites"):
        arcade_common.clear_sprites()
    return clock


def _counts(win) -> dict:
    gc.collect()
    timers = win.findChildren(QTimer)
    view = win.view
    return {
        "timers": len(timers),
        "active": sum(t.isActive() for t in timers),
        "connections": max(t.receivers(t.timeout) for t in timers),
        "pages": win.stack.count(),
        "objects": len(gc.get_objects()),
        "particles": len(view.particles.items),
        "taps": len(view.held.taps) if hasattr(view, "held") else 0,
        "sprites": _sprite_bytes(),
    }


@pytest.mark.parametrize("kind", ["chase", "tilt", "rockfall", "trails"])
def test_safety_a_long_session_stays_as_fast_as_its_first_minute(tmp_path, fixed_clock, kind):
    from ui.arcade_window import ArcadeWindow

    clock = fixed_clock
    win = ArcadeWindow(scores=tmp_path / "s.json", progress=tmp_path / "p.json", audio=FakeAudio())
    win.resize(*SIZES[0])
    win.show()
    win.start(kind, seed=5, intro=True)
    rng = random.Random(7)
    held, next_step, image = None, clock[0], None
    minutes: list[list[float]] = []
    counts = []
    restarts = 0
    frames_per_minute = 60 * FPS
    try:
        for frame in range(MINUTES * frames_per_minute):
            clock[0] += 1.0 / FPS
            view = win.view
            if frame % (2 * FPS) == 0:               # the window's corner dragged now and then
                win.resize(*SIZES[(frame // (2 * FPS)) % len(SIZES)])
            if frame % 8 == 0:                       # four key presses a second
                if held is not None:
                    view.game_key(held, False, False)
                held = rng.choice(sorted(view.DIRECTION_KEYS, key=int))
                view.handle_key(types.SimpleNamespace(key=lambda k=held: k, isAutoRepeat=lambda: False), True)
            if view.intro_running() and frame % FPS == FPS - 1:
                view.skip_intro()
            if hasattr(view, "intro") and frame % FPS == 0:
                view.intro = min(view.intro, 0.3)
            while clock[0] >= next_step:
                view.step()
                next_step += view.TICK_MS / 1000
            if image is None or image.size() != view.size():
                image = QImage(view.size(), QImage.Format.Format_RGB32)
            start = time.thread_time()
            view.render(image)
            took = (time.thread_time() - start) * 1000
            if frame % frames_per_minute == 0:
                minutes.append([])
            minutes[-1].append(took)
            if kind == "trails" and view.game.humans_out():
                view.next_round()
            if view.finished() and frame % FPS == 0:
                restarts += 1
                held = None
                view.shutdown()
                view.on_restart()                    # R: what the key does
                APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
                next_step = clock[0]
            if frame % frames_per_minute == frames_per_minute - 1:
                counts.append(_counts(win))
    finally:
        win.close()
    first, last = statistics.median(minutes[0]), statistics.median(minutes[-1])
    assert last <= 1.5 * first + 0.3, (kind, "ms a frame", first, last)
    # 2 timers of the game (tick, frame) + the picker's (stopped while a game runs)
    for c in counts:
        assert c["timers"] <= 3 and c["active"] <= 2, (kind, c)
        assert c["connections"] == 1, (kind, c)      # no slot connected twice
        assert c["pages"] <= 2, (kind, c)            # the picker and one game
        assert c["particles"] <= 600, (kind, c)
        assert c["taps"] <= 8, (kind, c)
        assert c["sprites"] <= SPRITE_CEILING, (kind, c["sprites"] / 2**20, "MiB of sprites")
    assert counts[-1]["objects"] <= counts[0]["objects"] * 1.1 + 2000, (kind, counts)


@pytest.mark.parametrize("kind", ["chase", "tilt", "rockfall", "trails"])
def test_safety_dragging_the_window_corner_keeps_no_full_window_pixmaps(fixed_clock, kind):
    from ui import arcade_chase_view, arcade_rockfall_view, arcade_tilt_view, arcade_trails_view

    view = {"chase": arcade_chase_view.ChaseView, "tilt": arcade_tilt_view.TiltView,
            "rockfall": arcade_rockfall_view.RockfallView, "trails": arcade_trails_view.TrailsView}[kind](intro=False)
    try:
        view.tick_timer.stop()
        view.frame_timer.stop()
        if hasattr(view, "intro"):
            view.intro = 0
        for width in range(900, 1700, 8):
            view.resize(width, 800)
            image = QImage(view.size(), QImage.Format.Format_RGB32)
            view.render(image)
        assert _sprite_bytes() <= 16 * 1024 * 1024, (kind, _sprite_bytes() / 2**20, "MiB")
    finally:
        view.shutdown()
        view.deleteLater()


def test_safety_the_sprite_cache_keeps_to_its_byte_budget():
    from ui import arcade_common as AC

    AC.clear_sprites()
    for k in range(60):                              # 60 pictures of 4 MB each
        AC.sprite(("big", k), 1000, 1000, lambda p, w, h: None)
        assert AC.sprite_bytes() <= AC.SPRITE_BUDGET
    assert AC.sprite_bytes() == _sprite_bytes()
    small = AC.sprite(("small",), 10, 10, lambda p, w, h: None)
    assert AC.sprite(("small",), 10, 10, lambda p, w, h: None) is small       # still a cache
    AC.clear_sprites()


def test_happy_a_layer_holds_one_picture_and_replaces_it_on_a_new_size():
    from ui import arcade_common as AC

    drawn = []
    layer = AC.Layer()
    a = layer.get("sky", 400, 300, 1.0, lambda p, w, h: drawn.append((w, h)))
    assert layer.get("sky", 400, 300, 1.0, lambda p, w, h: drawn.append((w, h))) is a
    b = layer.get("sky", 500, 300, 1.0, lambda p, w, h: drawn.append((w, h)))
    assert b is not a and layer.pixmap is b and drawn == [(400, 300), (500, 300)]


def test_safety_held_keys_keep_only_the_last_taps():
    from PyQt6.QtCore import Qt

    from ui.arcade_common import HeldKeys

    keys = HeldKeys({Qt.Key.Key_Left: (-1, 0), Qt.Key.Key_Right: (1, 0)})
    for k in range(5000):                            # a session of presses, never taken
        key = Qt.Key.Key_Left if k % 2 else Qt.Key.Key_Right
        keys.press(key)
        keys.release(key)
    assert len(keys.taps) <= 8
    assert keys.take() == (-1, 0)                    # the last tap still counts


class _CountingTrail(dict):
    """A trail that counts the cells read from it."""

    read = 0

    def items(self):
        trail = self

        class Items:
            def __iter__(self):
                for item in dict.items(trail):
                    trail.read += 1
                    yield item

            def __reversed__(self):
                for item in reversed(dict.items(trail)):
                    trail.read += 1
                    yield item

        return Items()


def test_safety_trail_runner_reads_only_the_new_cells_of_its_trail_each_tick(fixed_clock):
    from ui.arcade_trails_view import TrailsView

    view = TrailsView(intro=False)
    try:
        view.tick_timer.stop()
        view.frame_timer.stop()
        g = view.game
        g.countdown = 0
        for r in g.riders:
            r.human = False                          # the computer rides: a long round
        for _ in range(40):
            view.step()
        trail = _CountingTrail(g.trail)
        g.trail = trail
        reads = []
        for _ in range(30):
            if g.round_over:
                break
            before = len(trail)
            trail.read = 0
            view.step()
            reads.append((trail.read, len(trail) - before, len(trail)))
        assert reads and all(read <= new + 1 for read, new, _total in reads), reads
        paths = {i: list(p) for i, p in view._paths.items()}
        cells = {i: [c for c, j in dict.items(trail) if j == i] for i in paths}
        assert paths == cells                        # the ribbons are still the whole trail, in order
    finally:
        view.shutdown()
        view.deleteLater()


def test_safety_a_frame_leaves_hundreds_of_frames_a_second_of_headroom(fixed_clock):
    """At a typical window size a frame costs a few ms at most."""
    from ui import arcade_chase_view, arcade_rockfall_view, arcade_tilt_view, arcade_trails_view

    for cls in (arcade_chase_view.ChaseView, arcade_tilt_view.TiltView, arcade_rockfall_view.RockfallView,
                arcade_trails_view.TrailsView):
        view = cls(intro=False)
        try:
            view.tick_timer.stop()
            view.frame_timer.stop()
            if hasattr(view, "intro"):
                view.intro = 0
            view.resize(960, 680)
            image = QImage(view.size(), QImage.Format.Format_RGB32)
            took = []
            for frame in range(240):
                fixed_clock[0] += 1 / 60
                if frame % 6 == 0:
                    view.step()
                start = time.thread_time()
                view.render(image)
                took.append((time.thread_time() - start) * 1000)
            assert statistics.median(took[30:]) < 5.0, (cls.__name__, statistics.median(took[30:]))
        finally:
            view.shutdown()
            view.deleteLater()


class _WallSink:
    """A sink that plays in real time (no device needed): a ring of *size*
    bytes drained by the wall clock."""

    def __init__(self, size: int):
        self.size, self.queued, self.t = size, 0, time.monotonic()

    def _drain(self) -> None:
        now = time.monotonic()
        n = int((now - self.t) * 22050) * 2
        if n > 0:
            self.t = now
            self.queued = max(0, self.queued - n)

    def bufferSize(self):  # noqa: N802 - Qt's name
        return self.size

    def bytesFree(self):  # noqa: N802 - Qt's name
        self._drain()
        return self.size - self.queued

    def setVolume(self, _v):  # noqa: N802 - Qt's name
        pass

    def stop(self):
        pass


class _WallIO:
    def __init__(self, sink: _WallSink):
        self.sink = sink

    def write(self, data: bytes) -> int:
        take = min(len(data), self.sink.bytesFree())
        self.sink.queued += take
        return take


def _proc() -> dict:
    status = {}
    with open("/proc/self/status") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            status[key] = value.split()
    return {"threads": int(status["Threads"][0]), "rss_kb": int(status["VmRSS"][0]),
            "fds": len(os.listdir("/proc/self/fd")), "cpu": time.process_time()}


@pytest.mark.skipif(not os.path.isdir("/proc/self/task"), reason="reads /proc")
def test_safety_trail_runner_live_for_two_minutes_keeps_threads_fds_memory_and_cpu_flat(tmp_path):
    """The real event loop, real timers and the Arcade's real mixer (on a
    sink that plays in real time), Trail Runner in a small window for two
    minutes: random keys, rounds ended with Space, matches played again.
    Sampled every second - nothing may grow with the time played."""
    from PyQt6.QtCore import QEventLoop

    from ui.arcade_audio import ArcadeAudio
    from ui.arcade_window import ArcadeWindow

    seconds = float(os.environ.get("AXROSS_ARCADE_LIVE_S", "120"))
    sink = _WallSink(int(22050 * 0.25) * 2)
    audio = ArcadeAudio(sink_factory=lambda: (sink, _WallIO(sink)))
    win = ArcadeWindow(scores=tmp_path / "s.json", progress=tmp_path / "p.json", audio=audio)
    win.resize(560, 400)
    win.show()
    win.start("trails", seed=5)
    rng = random.Random(4)
    samples = []
    loop = QEventLoop()

    def drive():
        view = win.view
        if view is None:
            return
        if view.intro_running():
            view.skip_intro()
        view.game_key(rng.choice(sorted(view.DIRECTION_KEYS, key=int)), True, False)
        if view.game.humans_out() and rng.random() < 0.2:
            view.next_round()
        if view.finished():
            view.shutdown()
            view.on_restart()

    def sample():
        row = _proc()
        timers = win.findChildren(QTimer)
        row["timers"] = len(timers)
        row["active"] = sum(t.isActive() for t in timers)
        row["voices"] = len(audio._playing)
        samples.append(row)
        if len(samples) > seconds:
            loop.quit()

    keys, every_second = QTimer(), QTimer()
    keys.timeout.connect(drive)
    every_second.timeout.connect(sample)
    keys.start(150)
    every_second.start(1000)
    try:
        loop.exec()
    finally:
        keys.stop()
        every_second.stop()
        win.close()
        audio.close()
    settled = samples[10:]                             # the first seconds: imports, the tune rendered
    base = settled[0]
    cpu = [(b["cpu"] - a["cpu"]) * 100 for a, b in zip(settled, settled[1:])]
    assert max(s["threads"] for s in settled) <= base["threads"] + 2, [s["threads"] for s in settled]
    assert max(s["fds"] for s in settled) <= base["fds"] + 4, [s["fds"] for s in settled]
    assert settled[-1]["rss_kb"] - base["rss_kb"] <= 40 * 1024, (base["rss_kb"], settled[-1]["rss_kb"])
    assert max(s["timers"] for s in settled) <= 3 and max(s["active"] for s in settled) <= 2
    assert max(s["voices"] for s in settled) <= 12
    # a few % of one core while playing; the last half no dearer than the first
    half = len(cpu) // 2
    assert statistics.median(cpu) < 50, statistics.median(cpu)
    assert statistics.median(cpu[half:]) <= 1.5 * statistics.median(cpu[:half]) + 5, cpu
