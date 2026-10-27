"""The visualizer does no work nobody sees.

Measured (PlayerPanel playing into a test sink, offscreen, 3 s per state):
the GUI thread spent 0.7-0.9 % of a core with the visualizer's timer off,
3.9-4.1 % showing the spectrum - and 2.3-2.9 % with the panel hidden (a
closed dock or another tab: an FFT 30 times a second for nothing) and
4.0-4.4 % paused (the same picture painted 31 times a second). Now a hidden
visualizer's timer asks for nothing, and a tick whose picture would not
change does not repaint - except the starfield and the waterfall, which
move on their own.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QEvent, QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_visualizer_idle_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_visualizer_idle_ext"] = MP
_spec.loader.exec_module(MP)

RATE = MP.RATE


def noise(seed: int = 1):
    return (np.random.default_rng(seed).standard_normal((MP.FRAME, 2)) * 0.3).astype(np.float32)


class Engine:
    """Samples the test sets; counts what the visualizer asks for."""

    def __init__(self, samples) -> None:
        self.samples = samples
        self.bars_asked = 0
        self.samples_asked = 0

    def current_bars(self, n=32):
        self.bars_asked += 1
        return None if self.samples is None else MP.spectrum_bars(self.samples, RATE, n)

    def current_samples(self):
        self.samples_asked += 1
        return self.samples


class Counting(MP.Visualizer):
    """Counts its paints."""

    def __init__(self, engine) -> None:
        super().__init__(engine)
        self.paints = 0

    def paintEvent(self, event):  # noqa: N802 - Qt
        self.paints += 1
        super().paintEvent(event)


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.003)


def make(samples, mode="spectrum", size=(320, 160)):
    vis = Counting(Engine(samples))
    vis.resize(*size)
    vis.set_mode(mode, announce=False)
    vis._label_until = 0.0
    vis.show()
    pump(0.05)
    return vis


def ticks(vis, n: int) -> int:
    """Paints caused by *n* ticks."""
    before = vis.paints
    for _ in range(n):
        vis.tick()
        APP.processEvents()
    return vis.paints - before


# --- happy -------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["spectrum", "mirror", "radial", "line", "polar",
                                  "scope", "vu", "lissajous", "led", "particles", "ribbon",
                                  "ridges", "terrain", "ring", "kaleidoscope", "bells"])
def test_happy_a_still_picture_is_not_painted_again(mode) -> None:
    """Paused or stopped the engine hands out the same samples: once the
    face has settled, ticks paint nothing - the ridges and the terrain once
    their history holds the same row throughout, the particle columns once
    their sparks have died out, the ribbon and the kaleidoscope because only
    an onset turns them."""
    vis = make(noise(), mode)
    try:
        ticks(vis, 600)  # settled: the peaks have fallen onto the levels
        assert ticks(vis, 30) == 0
    finally:
        vis.close()


@pytest.mark.parametrize("mode", ["spectrum", "scope", "lissajous", "vu", "led", "particles",
                                  "ribbon", "ridges", "terrain", "ring", "kaleidoscope",
                                  "bells"])
def test_happy_new_samples_are_painted_at_once(mode) -> None:
    vis = make(noise(1), mode)
    try:
        ticks(vis, 600)
        vis.engine.samples = noise(2)  # playing on
        assert ticks(vis, 1) == 1
    finally:
        vis.close()


def test_happy_a_hidden_visualizer_asks_for_nothing_on_its_timer() -> None:
    vis = make(noise(), "spectrum")
    try:
        vis.timer.start()
        pump(0.2)
        assert vis.engine.bars_asked > 0  # shown: it ticks
        vis.hide()
        asked = vis.engine.bars_asked
        pump(0.3)
        assert vis.engine.bars_asked == asked
        vis.show()
        pump(0.2)
        assert vis.engine.bars_asked > asked
    finally:
        vis.timer.stop()
        vis.close()


def test_happy_e2e_a_paused_panel_stops_repainting_and_resumes(tmp_path) -> None:
    import threading
    import wave

    class Sink(MP.MemorySink):
        """Takes audio at real time (a quarter second ahead), like a sound card."""

        def __init__(self) -> None:
            super().__init__()
            self._lock = threading.Lock()
            self._t0 = None

        def bytes_free(self):
            with self._lock:
                if not self.running:
                    return 0
                if self._t0 is None:
                    self._t0 = time.monotonic()
                due = int(((time.monotonic() - self._t0) + 0.25) * RATE) * 8
                return max(0, due - len(self.data))

        def write(self, data):
            with self._lock:
                return super().write(data)

    path = tmp_path / "n.wav"
    pcm = (np.clip(np.tile(noise(3), (80, 1)), -1, 1) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm.tobytes())
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: Sink()))
    vis = panel.visualizer
    paints = [0]

    class PaintCounter(QObject):
        def eventFilter(self, obj, event):  # noqa: N802 - Qt
            if event.type() == QEvent.Type.Paint:
                paints[0] += 1
            return False

    counter = PaintCounter()
    vis.installEventFilter(counter)
    try:
        panel.resize(600, 400)
        panel.show()
        panel.add_files([str(path)])
        panel.play_selected()
        pump(0.8)
        paints[0] = 0
        pump(0.5)
        assert paints[0] >= 5  # playing: it moves
        panel.toggle_play()  # pause
        assert panel.engine.state == "paused"
        pump(3.0)  # the bars settle
        paints[0] = 0
        pump(1.0)
        assert paints[0] <= 2, paints[0]
        panel.toggle_play()  # on again
        pump(0.6)
        assert paints[0] >= 5
    finally:
        vis.removeEventFilter(counter)
        panel.shutdown()
        panel.deleteLater()


# --- sad ---------------------------------------------------------------------


def test_sad_an_engine_without_samples_paints_nothing_new() -> None:
    vis = make(None, "spectrum")
    try:
        assert ticks(vis, 10) == 0
        vis.set_mode("scope", announce=False)
        APP.processEvents()
        assert ticks(vis, 10) == 0
    finally:
        vis.close()


# --- edge --------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["starfield", "waterfall"])
def test_edge_the_moving_faces_keep_moving_on_still_samples(mode) -> None:
    vis = make(noise(), mode)
    try:
        ticks(vis, 50)
        assert ticks(vis, 10) == 10
    finally:
        vis.close()


def test_edge_a_switch_a_scheme_or_a_resize_still_repaints_a_still_picture() -> None:
    vis = make(noise(), "spectrum")
    try:
        ticks(vis, 600)
        before = vis.paints
        vis.set_mode("mirror", announce=False)
        APP.processEvents()
        assert vis.paints > before
        before = vis.paints
        vis.set_scheme(next(n for n in MP.SCHEME_NAMES if n != vis.scheme))
        APP.processEvents()
        assert vis.paints > before
        before = vis.paints
        vis.resize(400, 200)
        APP.processEvents()
        assert vis.paints > before
    finally:
        vis.close()


def test_edge_the_bar_count_and_a_new_size_change_the_scope_trace() -> None:
    vis = make(noise(), "scope", size=(120, 100))
    try:
        ticks(vis, 3)
        assert len(vis.trace) == 120
        vis.resize(300, 100)
        APP.processEvents()
        ticks(vis, 1)
        assert len(vis.trace) == min(vis.SCOPE_POINTS, 300)
    finally:
        vis.close()
