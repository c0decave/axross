"""A seek back into what was just played comes from memory, not from the top.

QAudioDecoder cannot seek: a seek behind the decoded audio started the
decoder again from the start of the track and dropped everything up to the
target. Measured on PulseAudio and PipeWire null sinks with the panel
playing (scratch bench, 3 runs, host load 12-14): a seek back from 48 s to
40 s of a 60 s chirp was heard after 330 ms median, 820 ms at worst
(WAV/MP3/FLAC/Ogg); a seek back to 20 s of an Ogg file took 353 ms with an
idle GUI thread and 1042 ms with a GUI thread busy in Python - the decoder
hands out one buffer (about 21 ms of Ogg) per round trip through its
thread's event loop, and each one needs the GIL. Every five-second step
back with the Left key paid that, more the later in the track.

The engine now keeps the decoded audio it fed to the equalizer for the
last HISTORY_SECONDS (bounded by HISTORY_MAX_BYTES). A seek back into it
puts that audio in front of the queue and starts the equalizer afresh at
the target - the same samples a decoder restart gave, without touching the
decoder.
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

from PyQt6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
RATE = 44100
PEAK = 0.9


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_seek_memory_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


def ramp_wav(path, seconds: float, right: float = 0.0) -> Path:
    """Left: 0.9 * t / length (the position); right: a constant (the file)."""
    frames = int(seconds * RATE)
    left = (np.arange(frames) / frames * PEAK * 32767).astype("<i2")
    other = np.full(frames, int(right * 32767), "<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(np.stack([left, other], axis=1).tobytes())
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


def pump(seconds: float) -> None:
    end = time.time() + seconds
    wait(lambda: time.time() > end, seconds + 1)


class ThrottledSink(MP.MemorySink):
    """Takes *frames* per pump tick (10 ms): 4410 is ten times real time."""

    def __init__(self, frames: int = 4410) -> None:
        super().__init__()
        self.frames = frames

    def bytes_free(self) -> int:
        return self.frames * 8 if self.running else 0


def eq_engine(sink=None):
    sink = sink if sink is not None else ThrottledSink()
    return MP.EqEngine(sink_factory=lambda fmt: sink), sink


def written(sink) -> int:
    return len(sink.data) // 8


def hold(engine, sink) -> int:
    """The sink takes nothing more; the audio thread's step in progress is
    waited out (a control call runs after it). The frames per tick."""
    frames, sink.frames = sink.frames, 0
    engine.set_volume(engine.volume)
    return frames


def settle(engine) -> None:
    """Wait until the equalizer thread has filled what it keeps ready (it
    feeds the memory) and stopped."""
    def still():
        with engine._lock:
            return not engine._eq_busy and (
                len(engine._ready) // 8 >= MP.EQ_AHEAD_SECONDS * engine.rate
                or not engine._pending)
    assert wait(still, 5)
    pump(0.05)


def play_to(engine, sink, seconds: float) -> None:
    assert wait(lambda: written(sink) > seconds * RATE, 30), engine.error


def seek_and_take(engine, sink, target_ms, frames):
    """Seek with the sink held, give it its frames back; the first sample
    played after the seek and how many decoder starts the seek made."""
    before = written(sink)
    starts = engine._decoder_starts
    engine.seek(target_ms)
    restarted = engine._decoder_starts - starts
    sink.frames = frames
    assert wait(lambda: written(sink) > before, 10), engine.error
    return sink.samples()[before:], restarted


# -- the memory itself ---------------------------------------------------------------------


def frames(start: int, count: int) -> bytes:
    """*count* float stereo frames whose left sample is their track frame."""
    left = np.arange(start, start + count, dtype=np.float32)
    return np.stack([left, -left], axis=1).astype(np.float32).tobytes()


def test_happy_the_memory_keeps_one_stretch_and_gives_back_from_a_frame():
    memory = MP.DecodedMemory(lambda: 1000)
    memory.append(frames(100, 300), 100)
    memory.append(frames(400, 200), 400)
    assert (memory.start, memory.end, memory.nbytes) == (100, 600, 500 * 8)
    taken = memory.take_from(250)
    assert taken == frames(250, 350)
    assert (memory.start, memory.end) == (100, 250)
    memory.append(frames(250, 10), 250)  # follows on: kept
    assert (memory.start, memory.end) == (100, 260)


def test_sad_the_memory_refuses_a_frame_it_does_not_hold_and_restarts_on_a_gap():
    memory = MP.DecodedMemory(lambda: 1000)
    memory.append(frames(0, 100), 0)
    for frame in (-1, 100, 5000):
        with pytest.raises(ValueError):
            memory.take_from(frame)
    memory.append(frames(500, 50), 500)  # does not follow on: replaces
    assert (memory.start, memory.end, memory.nbytes) == (500, 550, 50 * 8)
    assert memory.take_from(500) == frames(500, 50)


def test_edge_the_memory_drops_its_oldest_frames_exactly_at_the_limit():
    limit = [250]
    memory = MP.DecodedMemory(lambda: limit[0])
    for start in range(0, 1000, 70):  # chunks that do not divide the limit
        memory.append(frames(start, 70), start)
    assert memory.nbytes == 250 * 8 and memory.end == 1050 and memory.start == 800
    assert memory.take_from(800) == frames(800, 250)
    memory.append(b"", 1234)  # nothing: nothing changes
    assert (memory.start, memory.end) == (800, 800)
    limit[0] = 0
    memory.append(frames(800, 5), 800)
    assert memory.nbytes == 0 and memory.end == 805
    memory.forget(7)
    assert (memory.start, memory.end, memory.nbytes) == (7, 7, 0)


def test_edge_a_full_memory_appends_without_moving_what_it_holds():
    """A bytearray dropping its oldest bytes moved the whole memory now and
    then: at 23 MB 25 us an append on average, 9 ms at worst, against 3 us
    at 96 kB (measured). In chunks an append costs the same at any size:
    CPU time, so a busy host does not decide it."""
    raw = bytes(4800 * 8)  # 0.1 s at 48 kHz, an equalizer block

    def cost(limit_frames):
        memory = MP.DecodedMemory(lambda: limit_frames)
        frame = 0
        for _ in range(limit_frames // 4800 + 10):  # full first
            memory.append(raw, frame)
            frame += 4800
        start = time.process_time()
        for _ in range(3000):
            memory.append(raw, frame)
            frame += 4800
        return time.process_time() - start

    small = min(cost(12_000) for _ in range(3))
    large = min(cost(MP.history_frames(48_000)) for _ in range(3))
    assert large < 3 * small + 0.005, (large, small)


# -- happy ------------------------------------------------------------------------------


def test_happy_a_seek_back_comes_from_memory_and_lands_exactly(tmp_path):
    seconds = 20.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 12.0)
        frames = hold(engine, sink)
        before = written(sink)
        after, restarted = seek_and_take(engine, sink, 4000, frames)
        assert restarted == 0, "the decoder started again from the top"
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 4.0) < 0.002
        # The rest of the track whole: no gap, nothing twice.
        assert wait(lambda: engine.finished, 30), engine.error
        rest = sink.samples()[before:]
        assert abs(len(rest) - int((seconds - 4.0) * RATE)) < 64, len(rest)
        assert np.max(np.abs(np.diff(rest[:, 0]))) < 1e-3
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_the_samples_equal_a_decoder_restart_at_the_target(tmp_path):
    """A/B: what a seek back from memory plays is what the equalizer gives
    for the track from the target on, started fresh - the output of the
    old decoder restart (equalizer on, Rock preset)."""
    seconds = 10.0
    path = ramp_wav(tmp_path / "r.wav", seconds)
    gains = list(MP.PRESETS["Rock"])
    engine, sink = eq_engine()
    try:
        engine.set_gains(gains)
        engine.load(str(path))
        engine.play()
        play_to(engine, sink, 6.0)
        frames = hold(engine, sink)
        before = written(sink)
        starts = engine._decoder_starts
        engine.seek(2500)
        assert engine._decoder_starts == starts
        sink.frames = frames
        assert wait(lambda: engine.finished, 30), engine.error
        after = sink.samples()[before:]
    finally:
        engine.close()
    with wave.open(str(path)) as w:
        pcm = np.frombuffer(w.readframes(w.getnframes()), "<i2").reshape(-1, 2)
    source = pcm.astype(np.float32)[int(2.5 * RATE):] / 32768.0
    eq = MP.Equalizer(RATE, 2)
    eq.set_gains(gains)
    ref = np.concatenate([eq.process(source), eq.flush()])[eq.latency:eq.latency + len(source)]
    assert abs(len(after) - len(ref)) < 64, (len(after), len(ref))
    n = min(len(ref), len(after))
    assert np.max(np.abs(after[:n] - ref[:n])) < 1e-5


def test_happy_a_big_keyboard_step_back_fits_in_the_memory():
    """Shift+Left goes back SEEK_BIG_STEP_MS: the memory holds at least
    that, at the sound card rates that fit HISTORY_MAX_BYTES with it."""
    assert MP.HISTORY_SECONDS * 1000 >= MP.SEEK_BIG_STEP_MS
    assert MP.HISTORY_MAX_BYTES >= MP.HISTORY_SECONDS * 96_000 * 8 // 2  # 48 kHz at least
    assert MP.history_frames(48_000) == MP.HISTORY_SECONDS * 48_000
    assert MP.history_frames(192_000) == MP.HISTORY_MAX_BYTES // 8


# -- sad --------------------------------------------------------------------------------


def test_sad_a_seek_back_beyond_the_memory_starts_the_decoder_again(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 1)
    seconds = 8.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 5.0)
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 1000, frames)
        assert restarted == 1
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 1.0) < 0.002
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_after_a_jump_ahead_the_skipped_part_is_in_memory_too(tmp_path):
    """A seek beyond the decoded audio decodes up to the target and drops
    it: dropped into the memory, a step back into it needs no decoder."""
    seconds = 16.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 2.0)
        frames = hold(engine, sink)
        _after, restarted = seek_and_take(engine, sink, 10_000, frames)  # beyond 2 s ahead
        assert restarted == 0  # the decoder ran on
        play_to(engine, sink, 2.0 + 1.0)
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 6000, frames)  # in the skipped part
        assert restarted == 0
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 6.0) < 0.002
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_after_a_decoder_restart_a_step_back_is_in_memory(tmp_path, monkeypatch):
    """The restart from the top drops everything up to the target into the
    memory: the next step back does not start the decoder again."""
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 3)
    seconds = 16.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 9.0)
        frames = hold(engine, sink)
        _after, restarted = seek_and_take(engine, sink, 4000, frames)  # 5 s back: beyond
        assert restarted == 1
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 2500, frames)
        assert restarted == 0
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 2.5) < 0.002
        assert engine.error == ""
    finally:
        engine.close()


def test_sad_a_new_track_never_plays_the_last_ones_memory(tmp_path):
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "a.wav", 10.0, right=0.0)))
        engine.play()
        play_to(engine, sink, 5.0)
        engine.load(str(ramp_wav(tmp_path / "b.wav", 10.0, right=0.5)))
        assert engine._memory.nbytes == 0
        engine.play()
        start = written(sink)
        assert wait(lambda: written(sink) > start + 2 * RATE, 30)
        frames = hold(engine, sink)
        after, _restarted = seek_and_take(engine, sink, 500, frames)
        assert abs(float(after[0, 1]) - 0.5) < 1e-3  # b's right channel
        assert abs(ramp_seconds(float(after[0, 0]), 10.0) - 0.5) < 0.002
    finally:
        engine.close()


# -- edge -------------------------------------------------------------------------------


def test_edge_the_memory_is_bounded_and_its_first_frame_is_the_border(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 2)
    seconds = 12.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 6.0)
        frames = hold(engine, sink)
        settle(engine)
        with engine._lock:
            assert engine._memory.nbytes == 2 * RATE * 8  # full and not more
            first = engine._memory.start
        after, restarted = seek_and_take(engine, sink, first * 1000 // RATE + 1, frames)
        assert restarted == 0  # inside: memory
        frames = hold(engine, sink)
        settle(engine)
        with engine._lock:
            first = engine._memory.start
        border_ms = -(-first * 1000 // RATE)  # the first whole ms inside
        after, restarted = seek_and_take(engine, sink, border_ms - 2, frames)
        assert restarted == 1  # before it: the decoder
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - (border_ms - 2) / 1000) < 0.002
        assert engine.error == ""
    finally:
        engine.close()


def test_edge_a_seek_back_while_paused_stays_paused_then_plays_from_there(tmp_path):
    seconds = 10.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 5.0)
        engine.pause()
        starts = engine._decoder_starts
        engine.seek(2000)
        assert engine.state == "paused" and engine.position_ms() == 2000
        assert engine._decoder_starts == starts
        before = written(sink)
        pump(0.3)
        assert written(sink) == before
        engine.play()
        assert wait(lambda: written(sink) > before, 10)
        assert abs(ramp_seconds(float(sink.samples()[before, 0]), seconds) - 2.0) < 0.002
    finally:
        engine.close()


def test_edge_a_new_sound_card_rate_refills_the_memory_in_that_rate(tmp_path):
    """Another rate starts the decoder again: what the memory held counted
    in the old rate is gone, a seek back lands exactly in the new one."""
    seconds = 10.0
    rates = [RATE]
    sink = ThrottledSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink,
                         negotiate=lambda fmt: MP.qt_format(rates[0], 2, "Float"))
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 4.0)
        rates[0] = 48000
        engine.reroute()  # another rate: the decoder starts again at the position
        assert engine.rate == 48000
        start = written(sink)
        assert wait(lambda: written(sink) > start + 48000, 10)
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 3000, frames)
        assert restarted == 0
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 3.0) < 0.002
        engine.stop()
        assert engine._memory.nbytes == 0
    finally:
        engine.close()


def test_edge_a_long_way_to_a_target_keeps_only_the_last_part(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 2)
    seconds = 12.0
    engine, sink = eq_engine()
    try:
        engine.load(str(ramp_wav(tmp_path / "r.wav", seconds)))
        engine.play()
        play_to(engine, sink, 1.0)
        frames = hold(engine, sink)
        seek_and_take(engine, sink, 9000, frames)
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 7500, frames)  # within 2 s before 9 s
        assert restarted == 0
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 7.5) < 0.002
        frames = hold(engine, sink)
        after, restarted = seek_and_take(engine, sink, 5000, frames)
        assert restarted == 1
        assert abs(ramp_seconds(float(after[0, 0]), seconds) - 5.0) < 0.002
    finally:
        engine.close()


# -- e2e --------------------------------------------------------------------------------


def test_e2e_the_left_key_steps_back_from_memory_in_the_panel(tmp_path):
    seconds = 30.0
    path = ramp_wav(tmp_path / "r.wav", seconds)
    sink = ThrottledSink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.resize(600, 500)
        panel.show()
        panel.add_files([str(path)])
        panel.play_selected()
        play_to(panel.engine, sink, 12.0)
        frames = hold(panel.engine, sink)
        position = panel.engine.position_ms()
        before = written(sink)
        starts = panel.engine._decoder_starts
        panel.playlist.setFocus()
        QTest.keyClick(panel.playlist, Qt.Key.Key_Left)
        assert panel.engine._decoder_starts == starts
        sink.frames = frames
        assert wait(lambda: written(sink) > before, 10)
        where = ramp_seconds(float(sink.samples()[before, 0]), seconds)
        assert abs(where - (position - MP.SEEK_STEP_MS) / 1000) < 0.002
        assert panel.engine.error == ""
    finally:
        panel.shutdown()
        panel.close()
