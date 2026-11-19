"""Play and seek do not wait for the decoder to open the file.

Measured (EqEngine, a local 20 s WAV): play() held the GUI thread for
21 ms per track change, 20 of them in QAudioDecoder.start() - Qt's FFmpeg
decoder opens and probes the file there, and the audio thread waited for
the decoder thread, the GUI thread for the audio thread. A file on a slow
mount held the window for as long as the open took, and every seek did the
same. The decoder thread now starts the decoder on its own; an error it
reports reaches the engine the way a later decoder error always did.

The GUI thread's stall is measured in the time it slept (schedstat), less
what the engine's threads hold the GIL for while it plays: on a loaded host
the wall clock between two looks of a busy loop said 30-90 ms with the fix
in place (the test preempted, threads holding the GIL preempted). That no
Python frame calls QAudioDecoder.start() - the cause - is checked on its
own, on any host.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
import wave
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)  # or no libpulse.so.0

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_play_no_wait_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_play_no_wait_ext"] = MP
_spec.loader.exec_module(MP)

#: How long the slowed decoder start takes (a slow mount).
SLOW_START = 0.6


def tone_wav(path: Path, seconds: float, rate: int = MP.RATE) -> Path:
    n = int(seconds * rate)
    t = np.arange(n) / rate
    pcm = (np.sin(2 * np.pi * 440 * t) * 0.3 * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.repeat(pcm, 2).tobytes())
    return path


class Sink(MP.MemorySink):
    """Takes everything it is given, from any thread."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()

    def write(self, data: bytes) -> int:
        with self._lock:
            return super().write(data)

    def frames(self) -> int:
        with self._lock:
            return len(self.data) // 8


def gui(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def wait_for(cond, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        gui(0.02)
    return cond()


@pytest.fixture
def slow_start(monkeypatch):
    """QAudioDecoder.start() takes SLOW_START, like a file on a slow mount;
    the starts are counted."""
    starts = []
    real = MP.EqEngine._dec_start

    def slow(self):
        starts.append(threading.get_ident())
        time.sleep(SLOW_START)
        real(self)

    monkeypatch.setattr(MP.EqEngine, "_dec_start", slow)
    return starts


def timed(fn, *args) -> float:
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


# --- happy -------------------------------------------------------------------


def test_happy_play_returns_before_the_decoder_has_opened_the_file(tmp_path, slow_start):
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 3.0)))
        took = timed(engine.play)
        assert took < SLOW_START / 3, f"play() waited {took:.3f} s"
        assert engine.state == "playing"
        assert wait_for(lambda: slow_start)  # started in its own thread, later
        assert slow_start[0] != threading.get_ident()
        assert wait_for(lambda: sink.frames() > MP.RATE // 2)
        assert engine.error == ""
    finally:
        engine.close()


def _sleep_clock():
    """A reader of the seconds the calling thread has spent asleep (blocked:
    waiting for the GIL, a lock, I/O) - wall time less its CPU time and less
    the time it waited in the run queue for a CPU (/proc's schedstat): a
    loaded host keeping the test from a CPU is no stall. Wall time where
    there is no schedstat."""
    try:
        handle = open(f"/proc/self/task/{threading.get_native_id()}/schedstat", "rb")  # noqa: SIM115
        handle.read()
    except (OSError, AttributeError):
        return time.perf_counter

    def asleep() -> float:
        handle.seek(0)
        ran, queued = (int(v) for v in handle.read().split()[:2])
        return time.perf_counter() - (ran + queued) / 1e9

    return asleep


def longest_sleep(action, window: float = 0.15) -> float:
    """The longest the GUI thread was held asleep in *action()* and in the
    *window* after it (a busy loop that only reads the clock)."""
    clock = _sleep_clock()
    t0 = clock()
    action()
    last = clock()
    longest = last - t0
    end = time.perf_counter() + window
    while time.perf_counter() < end:
        now = clock()
        longest = max(longest, now - last)
        last = now
    return longest


@pytest.fixture
def python_starts(monkeypatch):
    """Records every call of QAudioDecoder.start() made from Python, in any
    thread: such a call holds the GIL for as long as the decoder opens and
    probes the file. The slot started by Qt's event loop (the fix) is the
    C++ one and is never seen here - start() is no virtual to override."""
    from PyQt6.QtMultimedia import QAudioDecoder

    seen: list[str] = []
    real = QAudioDecoder.start

    def start(self):
        seen.append(threading.current_thread().name)
        return real(self)

    monkeypatch.setattr(QAudioDecoder, "start", start)
    return seen


def test_happy_the_real_decoder_is_started_without_the_gil(tmp_path, python_starts):
    """QAudioDecoder.start() called from Python holds the GIL for the 20 ms
    it takes to open a WAV (as long as a slow mount takes): the GUI thread
    stood still that long even with the call in the decoder thread. Started
    from Qt's event loop it holds nothing - and no Python frame calls it,
    which holds on any host, loaded or not."""
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    path = str(tone_wav(tmp_path / "t.wav", 20.0))
    try:
        for _ in range(3):
            engine.load(path)
            gui(0.05)
            engine.play()
            assert wait_for(lambda: sink.frames() > 0)
        assert python_starts == []
        assert engine._decoder_starts >= 3
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_the_gui_thread_runs_on_while_the_real_decoder_opens_the_file(tmp_path):
    """The stall itself. Measured: the longest the GUI thread was held around
    play() 21-24 ms before, about 1 ms after (the shortest of five tries).
    Counted is the time the GUI thread slept, never the time a loaded host
    gave its CPU to something else; and what the engine's other threads
    hold the GIL for while it plays (preempted on a busy host, measured with
    the track playing) is this host's floor, not the decoder's start."""
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    path = str(tone_wav(tmp_path / "t.wav", 20.0))
    over = []
    try:
        for _ in range(5):
            engine.load(path)
            gui(0.05)
            stall = longest_sleep(engine.play)
            assert wait_for(lambda: sink.frames() > 0)
            floor = longest_sleep(lambda: None)  # playing, no decoder start
            over.append((stall, floor))
            if stall < 0.010:
                break
        assert min(stall - floor for stall, floor in over) < 0.010, [
            f"{stall * 1000:.1f} ms (floor {floor * 1000:.1f} ms)" for stall, floor in over]
        assert engine.error == ""
    finally:
        engine.close()


def test_edge_a_start_called_from_python_is_seen(tmp_path, monkeypatch, python_starts):
    """The checks above catch what they guard: with start() called from
    Python in the decoder thread (as before the fix) it is recorded."""

    def post_slot_from_python(self, obj, slot, before=None):
        def call():
            if before is not None:
                before()
            getattr(obj, slot)()

        self.post(call)

    monkeypatch.setattr(MP._ThreadHost, "post_slot", post_slot_from_python)
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 3.0)))
        engine.play()
        assert wait_for(lambda: sink.frames() > 0)
        assert python_starts, "a start() from Python went unseen"
    finally:
        engine.close()


def test_happy_e2e_the_panel_changes_tracks_without_waiting(tmp_path, slow_start):
    sink = Sink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.show()
        panel.add_files([str(tone_wav(tmp_path / f"t{i}.wav", 2.0)) for i in range(3)])
        took = timed(panel.play_selected)
        assert took < SLOW_START / 3, f"play_selected() waited {took:.3f} s"
        took = timed(panel.next_track)
        # The second start may wait for the first one to finish (one decoder),
        # never for its own.
        assert took < SLOW_START * 1.5, f"next_track() waited {took:.3f} s"
        assert panel.current_row() == 1
        assert wait_for(lambda: sink.frames() > MP.RATE // 4)
        assert panel.engine.error == ""
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_happy_the_samples_played_are_the_files_from_its_start(tmp_path, monkeypatch):
    """An equivalence check: the first second written is the file's first
    second (flat equalizer: the identity after its latency)."""
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        path = tone_wav(tmp_path / "t.wav", 2.0)
        engine.load(str(path))
        engine.play()
        assert wait_for(lambda: sink.frames() >= MP.RATE)
        written = np.frombuffer(bytes(sink.data[: MP.RATE * 8]), "<f4").reshape(-1, 2)
        with wave.open(str(path)) as w:
            source = np.frombuffer(w.readframes(MP.RATE), "<i2").reshape(-1, 2) / 32768.0
        assert np.allclose(written, source, atol=2e-4)
    finally:
        engine.close()


# --- sad ---------------------------------------------------------------------


def test_sad_an_unreadable_file_still_fails_after_a_slow_start(tmp_path, slow_start):
    bad = tmp_path / "bad.wav"
    bad.write_bytes(b"RIFF\x00\x00\x00\x00WAVEjunk" * 10)
    failures = []
    engine = MP.EqEngine(sink_factory=lambda fmt: Sink())
    engine.failed.connect(failures.append)
    try:
        engine.load(str(bad))
        took = timed(engine.play)
        assert took < SLOW_START / 3
        assert wait_for(lambda: failures, 10)
        assert engine.error and engine.state == "stopped"
    finally:
        engine.close()


# --- edge --------------------------------------------------------------------


def test_edge_a_seek_does_not_wait_either(tmp_path, slow_start, monkeypatch):
    # No memory of the audio played: the seek back starts the decoder again
    # (with it, a seek this short comes from memory - test_media_player_seek_memory.py).
    monkeypatch.setattr(MP, "HISTORY_SECONDS", 0)
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 6.0)))
        engine.play()
        assert wait_for(lambda: engine.position_ms() > 1000)
        starts = len(slow_start)
        # Back to where the decoder has been already: it starts again.
        took = timed(engine.seek, 200)
        assert took < SLOW_START / 3, f"seek() waited {took:.3f} s"
        assert engine.position_ms() == 200
        assert wait_for(lambda: len(slow_start) > starts)
        assert wait_for(lambda: engine.position_ms() > 400)
        assert engine.error == ""
    finally:
        engine.close()


def test_edge_stop_right_after_play_leaves_it_stopped_and_silent(tmp_path, slow_start):
    sink = Sink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 3.0)))
        engine.play()
        engine.stop()  # the decoder has not started yet
        assert engine.state == "stopped"
        gui(SLOW_START + 0.5)
        assert engine.state == "stopped"
        assert sink.frames() == 0
        assert engine.error == ""
    finally:
        engine.close()


def test_edge_a_call_after_a_queued_slot_runs_after_the_slot():
    """post_slot hands the slot to Qt's event loop; whatever is posted after
    it must still run after it - also when the host's thread was busy while
    both were posted (the wake-up of the slot's entry then finds the later
    call waiting too)."""
    from PyQt6.QtCore import QObject, pyqtSlot

    order: list[str] = []
    thread = MP.media_thread(MP.DECODER_THREAD)

    class Target(QObject):
        @pyqtSlot()
        def ping(self) -> None:
            order.append("slot")

    class Owner(QObject):
        pass

    owner = Owner()
    host = MP._ThreadHost(owner, thread)
    target = Target()
    target.moveToThread(thread)
    try:
        host.post(time.sleep, 0.3)  # the thread is busy while the rest is posted
        host.post_slot(target, "ping", lambda: order.append("before"))
        host.post(order.append, "after")
        done = host.call(lambda: "done")  # waits for all of it
        assert done == "done"
        assert order == ["before", "slot", "after"], order
    finally:
        host.call(target.deleteLater)
        host.call(host.deleteLater)
