"""Seeking forward keeps the sound card writable.

Seen in the 0.14.102 binary: skipping ahead in a song
logged "the audio feed failed in _pump ... RuntimeError: wrapped C/C++
object of type QIODevice has been deleted" on every feed tick. Reproduced
on a PulseAudio null sink (Qt's pulseaudio backend; the pipewire backend
was not affected): 20 seeks gave 311 such errors and no sound.

Root cause, traced (tests here, and a trace of the real run): seek()
stopped the old sink - QAudioSink.stop() deletes the stream's QIODevice -
and then started a new QAudioSink. Its QIODevice got the C++ address the
deleted one had (every seek, PulseAudio backend; the pipewire backend
allocated elsewhere). Within milliseconds the new device's wrapper was
marked deleted (sip.isdeleted True) while its C++ object was alive (its
destroyed signal came only at its own stop()); the flag was set while the
GUI thread processed its events, not in the audio thread - consistent with
the old device's deletion being applied, later and by address, to the
wrapper now at that address. Which PyQt part applies it is not proven.
Single-threaded, the same sequence does not mark anything. Opening the new
sink before stopping the old one leaves no freed address to reuse: 0
errors in 60 seeks (PulseAudio, 100 ms and 5 ms apart). A sink whose
stream is gone anyway is opened once more instead of failing each tick.

The same happened on a track change: load() stopped the sink, play() opened the
next - 10 of 10 changes lost the stream (PulseAudio; the reopen above
caught them). stop() now suspends the sink at once and keeps its stream
open ("parked") until the next sink has opened, or PARK_MS have passed.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import subprocess
import sys
import time
import weakref
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
_spec = importlib.util.spec_from_file_location(
    "media_player_seek_sink_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_seek_sink_ext"] = MP
_spec.loader.exec_module(MP)


def _tone(path: Path, seconds=6.0, rate=44100) -> Path:
    import wave
    n = int(seconds * rate)
    t = np.arange(n) / rate
    pcm = (np.sin(2 * math.pi * 440 * t) * 0.3 * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.repeat(pcm, 2).tobytes())
    return path


def _spin(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


class Recorder:
    """A sink factory that logs when each sink is made, stopped and freed."""

    def __init__(self, sink_class=MP.MemorySink):
        self.events: list[str] = []
        self.sinks: list[weakref.ref] = []
        self.sink_class = sink_class

    def __call__(self, fmt):
        n = len(self.sinks)
        self.events.append(f"new {n}")
        events = self.events

        class Logged(self.sink_class):
            def stop(self):
                events.append(f"stop {n}")
                super().stop()
        sink = Logged()
        weakref.finalize(sink, events.append, f"gone {n}")
        self.sinks.append(weakref.ref(sink))
        return sink


# --- happy -----------------------------------------------------------------


def test_happy_seek_opens_the_next_sink_before_it_stops_the_old(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _spin(0.3)
    engine.seek(engine.position_ms() + 2000)
    _spin(0.1)
    engine.stop()
    assert factory.events[:4] == ["new 0", "new 1", "stop 0", "gone 0"], factory.events


def test_happy_every_seek_of_a_burst_keeps_the_order(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=12.0)))
    engine.play()
    _spin(0.2)
    for _ in range(5):
        engine.seek(engine.position_ms() + 1000)
        _spin(0.02)
    engine.stop()
    for n in range(5):
        i = factory.events.index(f"new {n + 1}")
        assert i < factory.events.index(f"stop {n}") < factory.events.index(f"gone {n}"), \
            factory.events


# --- sad -------------------------------------------------------------------


class LostSink(MP.MemorySink):
    """A stream that is gone after its first write, like a wrapper sip
    marked deleted: writes raise the RuntimeError PyQt raises then."""

    def __init__(self):
        super().__init__()
        self.writes = 0

    def alive(self) -> bool:
        return self.writes == 0

    def write(self, data: bytes) -> int:
        if self.writes:
            raise RuntimeError("wrapped C/C++ object of type QIODevice has been deleted")
        self.writes += 1
        return super().write(data)


def test_sad_a_sink_whose_stream_is_gone_is_opened_again_not_failed_each_tick(
        tmp_path, caplog):
    made = []

    def factory(fmt):
        sink = LostSink() if not made else MP.MemorySink()
        made.append(sink)
        return sink
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=1.0)))
    with caplog.at_level(logging.WARNING):
        engine.play()
        _spin(2.5)
    assert len(made) == 2
    assert not engine.error
    assert len(made[1].data) > 0  # it played on through the new one
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == []
    assert sum("opening it again" in r.getMessage() for r in caplog.records) == 1


def test_sad_a_sink_that_keeps_losing_its_stream_ends_in_one_message(tmp_path, caplog):
    made = []

    def factory(fmt):
        made.append(LostSink())
        return made[-1]
    failed = []
    engine = MP.EqEngine(sink_factory=factory)
    engine.failed.connect(failed.append)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=3.0)))
    with caplog.at_level(logging.WARNING):
        engine.play()
        _spin(2.0)
    assert len(failed) == 1 and "sound card" in failed[0]
    assert len(made) == MP.MAX_SINK_REOPENS + 1
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


# --- edge ------------------------------------------------------------------


def test_edge_a_sink_without_alive_counts_as_alive(tmp_path):
    sink = MP.MemorySink()
    assert not hasattr(sink, "alive")
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=0.5)))
    engine.play()
    _spin(1.5)
    assert engine.finished and not engine.error


def test_edge_seek_while_paused_keeps_the_order_and_stays_paused(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _spin(0.2)
    engine.pause()
    engine.seek(3000)
    _spin(0.05)
    assert factory.events[:4] == ["new 0", "new 1", "stop 0", "gone 0"]
    assert engine.state == "paused"
    assert factory.sinks[1]().running is False  # the new sink is suspended
    engine.stop()


def test_edge_a_new_output_device_opens_before_the_old_stops(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _spin(0.2)
    engine.reroute()
    _spin(0.05)
    engine.stop()
    assert factory.events[:4] == ["new 0", "new 1", "stop 0", "gone 0"], factory.events


def test_happy_a_track_change_opens_the_next_sink_before_the_old_stops(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    first, second = _tone(tmp_path / "a.wav"), _tone(tmp_path / "b.wav")
    engine.load(str(first))
    engine.play()
    _spin(0.2)
    engine.load(str(second))
    assert factory.sinks[0]().running is False  # silent at once
    assert "stop 0" not in factory.events
    engine.play()
    _spin(0.05)
    engine.stop()
    assert factory.events[:4] == ["new 0", "new 1", "stop 0", "gone 0"], factory.events


def test_happy_a_stopped_player_closes_its_parked_stream_after_a_while(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "PARK_MS", 100)
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _spin(0.2)
    engine.stop()
    assert "stop 0" not in factory.events
    _spin(0.4)
    assert factory.events[-2:] == ["stop 0", "gone 0"], factory.events


def test_edge_closing_the_engine_stops_a_parked_stream(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _spin(0.2)
    engine.stop()
    engine.close()
    _spin(0.05)
    assert "stop 0" in factory.events


def test_edge_a_seek_past_the_end_then_play_keeps_the_order(tmp_path):
    factory = Recorder()
    engine = MP.EqEngine(sink_factory=factory)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=2.0)))
    engine.play()
    _spin(0.2)
    engine.seek(60_000)  # past the end: the track ends
    assert engine.state == "stopped"
    engine.play()
    _spin(0.05)
    engine.stop()
    assert factory.events[:4] == ["new 0", "new 1", "stop 0", "gone 0"], factory.events


def test_edge_qt_sink_reports_a_deleted_stream_as_not_alive():
    from PyQt6 import sip
    from PyQt6.QtCore import QBuffer

    sink = MP.QtSink.__new__(MP.QtSink)
    sink._io = None
    assert sink.alive() is False
    buf = QBuffer()
    sink._io = buf
    assert sink.alive() is True
    sip.delete(buf)
    assert sink.alive() is False
    assert sink.write(b"x") == 0 and sink.bytes_free() == 0


# --- e2e: a real PulseAudio null sink ---------------------------------------

def _runtime() -> str:
    for folder in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}"):
        if folder and os.path.exists(os.path.join(folder, "pulse", "native")) or \
                folder and os.path.exists(os.path.join(folder or "", "pipewire-0")):
            return folder
    return ""


RUNTIME = _runtime()
FROZEN = os.environ.get("AXROSS_FROZEN_BINARY", "")
_SEEKS = """\
import os, sys, time, importlib.util, logging
sys.path.insert(0, {root!r})
errors, reopens = [], []
class H(logging.Handler):
    def emit(self, rec):
        if "opening it again" in rec.getMessage(): reopens.append(rec)
        if rec.levelno >= logging.ERROR: errors.append(rec.getMessage())
logging.getLogger().addHandler(H())
from PyQt6.QtCore import QCoreApplication, QEvent
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication(["x"])
QCoreApplication.sendEvent(app, QEvent(QEvent.Type.User))
import core
ext = os.path.join(os.path.dirname(os.path.dirname(core.__file__)), "resources", "extensions",
                   "media_player.py")
spec = importlib.util.spec_from_file_location("mpx", ext); MPX = importlib.util.module_from_spec(spec)
sys.modules["mpx"] = MPX; spec.loader.exec_module(MPX)
from PyQt6.QtMultimedia import QMediaDevices
from core import audio_route
dev = next(d for d in QMediaDevices.audioOutputs() if d.description() == {sink!r})
audio_route.output_device = lambda: dev
def spin(s):
    t = time.monotonic()
    while time.monotonic() - t < s:
        app.processEvents(); time.sleep(0.002)
eng = MPX.default_engine()
for i in range(6):  # track changes
    eng.load({track!r} if i % 2 else {track2!r}); eng.play(); spin(0.15)
eng.load({track!r}); eng.play()
spin(0.8)
for gap in (0.1,) * 8 + (0.01,) * 8:
    eng.seek(eng.position_ms() + 1000); spin(gap)
p0 = (eng.position_ms(), time.monotonic()); spin(1.5)
p1 = (eng.position_ms(), time.monotonic())
line = "SEEKS reopens=%d errors=%d speed=%.2f state=%s error=%r" % (
    len(reopens), len(errors), (p1[0] - p0[0]) / 1000 / (p1[1] - p0[1]), eng.state, eng.error)
open(os.environ["SEEK_OUT"], "w").write(line)
"""


@pytest.fixture
def null_sink():
    if not RUNTIME:
        pytest.skip("no PulseAudio/PipeWire server")
    env = {**os.environ, "XDG_RUNTIME_DIR": RUNTIME}
    if subprocess.run(["pactl", "info"], env=env, capture_output=True, timeout=20).returncode:
        pytest.skip("pactl cannot reach the server")
    name = f"axseek{os.getpid()}"
    out = subprocess.run(["pactl", "load-module", "module-null-sink", f"sink_name={name}",
                          "format=s16le", "rate=48000", "channels=2",
                          f"sink_properties=device.description={name}"],
                         env=env, capture_output=True, text=True, timeout=20)
    if out.returncode:
        pytest.skip(f"no null sink: {out.stderr.strip()}")
    yield env, name
    subprocess.run(["pactl", "unload-module", out.stdout.strip()], env=env,
                   capture_output=True, timeout=20)


@pytest.mark.parametrize("backend", ["pulseaudio", "pipewire"])
def test_e2e_track_changes_and_seeks_on_a_real_sink_lose_no_stream(
        tmp_path, null_sink, backend):
    env, name = null_sink
    track = _tone(tmp_path / "t.wav", seconds=40.0)
    track2 = _tone(tmp_path / "t2.wav", seconds=4.0)
    script, out, home = tmp_path / "seeks.py", tmp_path / "seeks.out", tmp_path / "home"
    home.mkdir()
    script.write_text(_SEEKS.format(root=str(ROOT), sink=name, track=str(track),
                                   track2=str(track2)))
    env = {**env, "QT_AUDIO_BACKEND": backend, "QT_QPA_PLATFORM": "offscreen",
           "SEEK_OUT": str(out), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
           "XDG_STATE_HOME": str(home / ".state"), "XDG_DATA_HOME": str(home / ".data"),
           "XDG_CACHE_HOME": str(home / ".cache")}
    env.pop("DISPLAY", None)
    cmd = [FROZEN, "--script", str(script)] if FROZEN else [sys.executable, str(script)]
    subprocess.run(cmd, env=env, capture_output=True, timeout=120)
    line = out.read_text() if out.exists() else "SEEKS no output"
    assert "reopens=0 errors=0 " in line, line
    speed = float(line.split("speed=")[1].split()[0])
    assert 0.8 < speed < 1.2, line
    assert "error=''" in line, line
