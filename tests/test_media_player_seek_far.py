"""On the way to a far seek target the decoder does not wait for the sound card.

A seek beyond the decoded audio (ahead, or back beyond the memory) decodes
up to the target and drops what lies before it. The decoder hands out its
next buffer only after the last one was read, and it read only while the
queue to the audio thread held less than MAX_AHEAD_SECONDS - audio that
was going to be dropped anyway. The audio thread empties that queue on its
10 ms tick, so the decoder stood still for up to a tick after every 2 s of
audio it decoded on the way. Measured with the seek probe of the change
(engine only): the waits are counted here, not timed - the times are in
the report of the change.

The queue's bound while dropping is the memory's (what is dropped goes
there) plus MAX_AHEAD_SECONDS: a stalled audio thread still bounds it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import wave
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QEventLoop, QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
RATE = 44100
PEAK = 0.9


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_seek_far_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


def ramp_wav(path, seconds: float) -> Path:
    frames = int(seconds * RATE)
    left = (np.arange(frames) / frames * PEAK * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(np.stack([left, np.zeros_like(left)], axis=1).tobytes())
    return Path(path)


def ramp_seconds(sample: float, seconds: float) -> float:
    return sample / PEAK * seconds


def wait(cond, timeout: float = 15.0) -> bool:
    if cond():
        return True
    end = time.time() + timeout
    loop = QEventLoop()
    timer = QTimer()
    timer.setInterval(1)
    timer.timeout.connect(lambda: (cond() or time.time() > end) and loop.quit())
    timer.start()
    loop.exec()
    timer.stop()
    return bool(cond())


class ThrottledSink(MP.MemorySink):
    def __init__(self, frames: int = 4410) -> None:
        super().__init__()
        self.frames = frames

    def bytes_free(self) -> int:
        return self.frames * 8 if self.running else 0


def written(sink) -> int:
    return len(sink.data) // 8


def hold(engine, sink) -> int:
    frames, sink.frames = sink.frames, 0
    engine.set_volume(engine.volume)
    return frames


@pytest.fixture
def waits(monkeypatch):
    """Each buffer the decoder left unread (it waited) while the run's
    frames were still before the seek target; and the largest queue."""
    seen = {"waits": 0, "queued": 0}
    real = MP.EqEngine._dec_buffer_ready

    def counted(self):
        before_target = (self._drop_to is not None
                         and getattr(self, "_decoder_frames", 0) < self._drop_to)
        real(self)
        with self._queue_lock:
            seen["queued"] = max(seen["queued"], self._queued_bytes)
        if before_target and self._decoder_holding:
            seen["waits"] += 1

    monkeypatch.setattr(MP.EqEngine, "_dec_buffer_ready", counted)
    return seen


def far_seek(tmp_path, target_ms, seconds=60.0, start_s=1.0):
    path = ramp_wav(tmp_path / "r.wav", seconds)
    sink = ThrottledSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(path))
    engine.play()
    assert wait(lambda: written(sink) > start_s * RATE, 30)
    frames = hold(engine, sink)
    before = written(sink)
    engine.seek(target_ms)
    sink.frames = frames
    assert wait(lambda: written(sink) > before, 30), engine.error
    return engine, sink, before


# A 16-bit ramp of 60 s resolves 2 ms, of 90 s 3 ms: the tolerances below.


# -- happy ------------------------------------------------------------------------------


def test_happy_a_far_jump_ahead_decodes_without_waiting_and_lands(tmp_path, waits):
    engine, sink, before = far_seek(tmp_path, 50_000)
    try:
        assert waits["waits"] == 0, waits
        assert abs(ramp_seconds(float(sink.samples()[before, 0]), 60.0) - 50.0) < 0.005
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_a_far_seek_back_beyond_the_memory_does_not_wait_either(tmp_path, waits):
    seconds = 90.0
    engine, sink, before = far_seek(tmp_path, 85_000, seconds=seconds)  # memory: 25-85 s
    try:
        frames = hold(engine, sink)
        before = written(sink)
        starts = engine._decoder_starts
        waits["waits"] = 0
        engine.seek(10_000)  # behind the memory: from the top
        assert engine._decoder_starts == starts + 1
        sink.frames = frames
        assert wait(lambda: written(sink) > before, 30), engine.error
        assert waits["waits"] == 0, waits
        assert abs(ramp_seconds(float(sink.samples()[before, 0]), seconds) - 10.0) < 0.006
    finally:
        engine.close()


# -- sad --------------------------------------------------------------------------------


def test_sad_a_stalled_audio_thread_still_bounds_the_queue(tmp_path, waits, monkeypatch):
    """The audio thread takes nothing from the queue for a while: the
    decoder stops at the bound and goes on after."""
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 1)
    stalled = [False]
    real_drain = MP.EqEngine._drain

    def drain(self):
        if not stalled[0]:
            real_drain(self)

    monkeypatch.setattr(MP.EqEngine, "_drain", drain)
    path = ramp_wav(tmp_path / "r.wav", 60.0)
    sink = ThrottledSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(path))
        engine.play()
        assert wait(lambda: written(sink) > RATE, 30)
        frames = hold(engine, sink)
        before = written(sink)
        stalled[0] = True
        engine.seek(50_000)
        assert wait(lambda: waits["waits"] >= 1, 10), waits  # it did stop
        stalled[0] = False
        bound = (MP.MAX_AHEAD_SECONDS * engine.rate + MP.history_frames(engine.rate)) * 8
        # one buffer past the bound at most: a buffer is read, then the next waits
        assert waits["queued"] <= bound + 8192 * 8, (waits["queued"], bound)
        sink.frames = frames
        assert wait(lambda: written(sink) > before, 30), engine.error
        assert abs(ramp_seconds(float(sink.samples()[before, 0]), 60.0) - 50.0) < 0.005
    finally:
        engine.close()


# -- edge -------------------------------------------------------------------------------


def test_edge_after_the_target_the_decoder_waits_for_the_sound_card_again(tmp_path):
    """Past the target only MAX_AHEAD_SECONDS are decoded ahead, as ever."""
    engine, sink, _before = far_seek(tmp_path, 20_000)
    try:
        frames = hold(engine, sink)
        time.sleep(0.5)
        wait(lambda: False, 0.5)
        with engine._queue_lock:
            queued = engine._queued_bytes
        ahead = (queued + len(engine._pending) + len(engine._ready)) / 8 / engine.rate
        assert ahead <= MP.MAX_AHEAD_SECONDS + 0.2, ahead
        sink.frames = frames
    finally:
        engine.close()


def test_edge_the_decoder_counts_its_frames_per_run(tmp_path):
    engine, sink, _before = far_seek(tmp_path, 10_000, seconds=20.0)
    try:
        assert engine._decoder_frames >= 10 * RATE
        hold(engine, sink)
        engine.stop()
        sink.frames = 4410
        engine.play()  # a new run counts from 0
        assert wait(lambda: 0 < engine._decoder_frames < 5 * RATE, 10)
    finally:
        engine.close()
