"""The Media Player opens its sound card in a format the device takes.

Reported: over a Bluetooth output the player ran at 0.5x or 0.25x speed and
MP3s did not sound right. Measured here against real PipeWire sinks: the
engine always opened QAudioSink as float stereo 44.1 kHz. Where the device
reports that format unsupported - every mono sink (8, 16, 48 kHz; Bluetooth
in its headset profile is one) - Qt's PipeWire backend leaves the stream in
StoppedState: nothing plays, the position stands. Float mono 44.1 kHz or
the device's preferred format played at 1.00x on the same sinks. The
decoder itself was right for every MP3 tried (44.1/48 kHz stereo,
22.05/16 kHz mono, VBR: decoded length = track length).

Now the engine asks the device: float stereo where it takes it, else the
device's channel count (the engine mixes down), else the device's preferred
format (the decoder resamples, the engine converts the sample format). A
playback monitor reports a sound card that plays measurably too slow, too
fast or not at all, with the measured speed, instead of staying silent.
"""

from __future__ import annotations

import importlib.util
import math
import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_sink_format_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_sink_format_ext"] = MP
_spec.loader.exec_module(MP)


# -- choosing the format ---------------------------------------------------------------

def _device(supported, preferred=(48000, 2, "Int16")):
    """Rules: supported(rate, channels, sample_format) -> bool."""
    return supported, preferred


def test_happy_float_stereo_where_the_device_takes_it():
    supported, preferred = _device(lambda r, c, f: True)
    assert MP.choose_sink_format(supported, preferred) == (MP.RATE, 2, "Float")


def test_happy_a_mono_device_gets_mono_at_the_players_rate():
    supported, preferred = _device(lambda r, c, f: c == 1, (16000, 1, "Int16"))
    assert MP.choose_sink_format(supported, preferred) == (MP.RATE, 1, "Float")


def test_sad_a_device_without_float_gets_its_preferred_format():
    supported, preferred = _device(lambda r, c, f: (r, c, f) == (16000, 1, "Int16"),
                                   (16000, 1, "Int16"))
    assert MP.choose_sink_format(supported, preferred) == (16000, 1, "Int16")


def test_edge_a_preferred_format_with_more_than_two_channels_is_kept():
    supported, preferred = _device(lambda r, c, f: (r, c, f) == (48000, 6, "Int32"),
                                   (48000, 6, "Int32"))
    assert MP.choose_sink_format(supported, preferred) == (48000, 6, "Int32")


# -- converting the samples ------------------------------------------------------------

STEREO = np.array([[0.5, -0.5], [1.5, -1.5], [0.25, 0.75]], np.float32)


def test_happy_float_stereo_passes_unchanged():
    assert MP.convert_frames(STEREO, 2, "Float") == STEREO.tobytes()


def test_happy_mono_is_the_mean_of_both_channels():
    out = np.frombuffer(MP.convert_frames(STEREO, 1, "Float"), np.float32)
    assert out.tolist() == pytest.approx([0.0, 0.0, 0.5])


def test_happy_int16_is_scaled_and_clipped():
    out = np.frombuffer(MP.convert_frames(STEREO, 2, "Int16"), np.int16).reshape(-1, 2)
    assert out[0].tolist() == [16383, -16383]
    assert out[1].tolist() == [32767, -32767]  # 1.5 clipped


@pytest.mark.parametrize(("name", "dtype", "top"), [("Int32", np.int32, 2**31 - 1),
                                                     ("UInt8", np.uint8, None)])
def test_edge_the_other_sample_formats(name, dtype, top):
    out = np.frombuffer(MP.convert_frames(STEREO[:1], 2, name), dtype)
    if top:
        assert out.tolist() == [top // 2, -(top // 2)]
    else:
        assert out.tolist() == [191, 64]  # 128 +- 63.5


def test_edge_more_channels_than_two_get_the_pair_and_silence():
    out = np.frombuffer(MP.convert_frames(STEREO[:1], 4, "Float"), np.float32)
    assert out.tolist() == [0.5, -0.5, 0.0, 0.0]


def test_sad_an_unknown_sample_format_is_refused():
    with pytest.raises(ValueError):
        MP.convert_frames(STEREO, 2, "Float64")


# -- the playback monitor ----------------------------------------------------------------

def _feed(monitor, speed, seconds=4.0, rate=44100, step=0.05):
    t = 0.0
    frames = 0
    problem = None
    while t <= seconds:
        problem = monitor.update(t, frames) or problem
        t += step
        frames += int(rate * speed * step)
    return problem


def test_happy_real_time_playback_is_no_problem():
    assert _feed(MP.PlaybackMonitor(44100), 1.0) is None


@pytest.mark.parametrize("speed", [0.5, 0.25, 2.0])
def test_sad_a_wrong_speed_is_reported_with_the_measured_value(speed):
    problem = _feed(MP.PlaybackMonitor(44100), speed)
    assert problem is not None and f"x{speed:.2f}" in problem


def test_sad_a_sound_card_that_takes_nothing_is_reported():
    problem = _feed(MP.PlaybackMonitor(44100), 0.0)
    assert problem is not None and "takes no audio" in problem


def test_edge_the_monitor_reports_once_and_forgets_on_reset():
    monitor = MP.PlaybackMonitor(44100)
    assert _feed(monitor, 0.5) is not None
    assert _feed(monitor, 0.5) is None  # once per track
    monitor.reset()
    assert _feed(monitor, 0.5) is not None


def test_edge_a_short_or_paused_run_is_not_judged():
    monitor = MP.PlaybackMonitor(44100)
    assert _feed(monitor, 0.5, seconds=1.0) is None


# -- the engine against a mono Int16 sound card ----------------------------------------

def _tone(path: Path, seconds=2.0, rate=44100) -> Path:
    import wave
    n = int(seconds * rate)
    t = np.arange(n) / rate
    pcm = (np.sin(2 * math.pi * 440 * t) * 0.5 * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.repeat(pcm, 2).tobytes())
    return path


def _run(engine, seconds=8.0):
    end = time.monotonic() + seconds
    while engine.state == "playing" and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def test_happy_e2e_the_engine_plays_into_a_mono_int16_card(tmp_path):
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink,
                         negotiate=lambda fmt: MP.qt_format(MP.RATE, 1, "Int16"))
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _run(engine)
    assert engine.finished and not engine.error
    pcm = np.frombuffer(bytes(sink.data), np.int16)
    assert abs(len(pcm) - 2.0 * MP.RATE) < MP.RATE * 0.02  # one value per frame: mono
    assert 15000 < int(np.abs(pcm[MP.RATE // 2: MP.RATE]).max()) < 17500  # 0.5 of full scale


def test_happy_e2e_a_card_at_another_rate_gets_the_track_resampled(tmp_path):
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink,
                         negotiate=lambda fmt: MP.qt_format(16000, 1, "Int16"))
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    _run(engine)
    assert engine.finished and not engine.error
    pcm = np.frombuffer(bytes(sink.data), np.int16)
    assert abs(len(pcm) - 2.0 * 16000) < 16000 * 0.02  # still two seconds
    spectrum = np.abs(np.fft.rfft(pcm[4000:12000].astype(np.float32)))
    peak_hz = np.argmax(spectrum) * 16000 / 8000
    assert abs(peak_hz - 440) < 5  # the pitch is right: no 0.36x, no 2.76x


def test_edge_position_and_seek_count_in_the_cards_rate(tmp_path):
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink,
                         negotiate=lambda fmt: MP.qt_format(16000, 1, "Int16"))
    engine.load(str(_tone(tmp_path / "t.wav", seconds=3.0)))
    engine.seek(1500)
    engine.play()
    APP.processEvents()
    assert 1400 <= engine.position_ms() <= 1700
    _run(engine)
    pcm = np.frombuffer(bytes(sink.data), np.int16)
    assert abs(len(pcm) - 1.5 * 16000) < 16000 * 0.03


def test_sad_e2e_a_card_that_takes_nothing_turns_into_a_message(tmp_path, monkeypatch):
    class DeafSink(MP.MemorySink):
        def bytes_free(self):
            return 0

    monkeypatch.setattr(MP, "MONITOR_WINDOW_SECONDS", 0.6)
    problems = []
    engine = MP.EqEngine(sink_factory=lambda fmt: DeafSink())
    engine.playback_problem.connect(problems.append)
    engine.load(str(_tone(tmp_path / "t.wav")))
    engine.play()
    end = time.monotonic() + 3
    while not problems and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)
    engine.stop()
    assert problems and "takes no audio" in problems[0]
    assert "PulseAudio" in problems[0]


# -- e2e: real PipeWire sinks ----------------------------------------------------------------

def _runtime() -> str:
    for folder in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}"):
        if folder and os.path.exists(os.path.join(folder, "pipewire-0")):
            return folder
    return ""


RUNTIME = _runtime()
_SPEED = """\
import os, sys, time, importlib.util
sys.path.insert(0, {root!r})
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
eng = MPX.default_engine(); eng.load({track!r}); eng.play()
t0 = time.monotonic(); p0 = None
while time.monotonic() - t0 < 3.0:
    app.processEvents(); time.sleep(0.005)
    if p0 is None and time.monotonic() - t0 > 1.0: p0 = (eng.position_ms(), time.monotonic())
p1 = (eng.position_ms(), time.monotonic())
line = "SPEED %s %r" % ((p1[0] - p0[0]) / 1000 / (p1[1] - p0[1]), eng.error)
if os.environ.get("SPEED_OUT"):
    open(os.environ["SPEED_OUT"], "w").write(line)
else:
    print(line)
"""


@pytest.fixture
def pipewire_sinks():
    if not RUNTIME:
        pytest.skip("no PipeWire server")
    env = {**os.environ, "XDG_RUNTIME_DIR": RUNTIME}
    if subprocess.run(["pactl", "info"], env=env, capture_output=True, timeout=20).returncode:
        pytest.skip("pactl cannot reach the server")
    made, names = [], []
    tag = f"axtest{os.getpid()}"
    for rate, channels in ((16000, 1), (48000, 1), (48000, 2)):
        name = f"{tag}_{rate}_{channels}"
        out = subprocess.run(["pactl", "load-module", "module-null-sink", f"sink_name={name}",
                              "format=s16le", f"rate={rate}", f"channels={channels}",
                              f"sink_properties=device.description={name}"],
                             env=env, capture_output=True, text=True, timeout=20)
        if out.returncode == 0:
            made.append(out.stdout.strip())
            names.append(name)
    yield env, names
    for module in made:
        subprocess.run(["pactl", "unload-module", module], env=env, capture_output=True, timeout=20)


FROZEN = os.environ.get("AXROSS_FROZEN_BINARY", "")


def _speed_run(code: str, env: dict, tmp_path) -> str:
    """Run *code* with this tree's Python, or inside the built binary
    (AXROSS_FROZEN_BINARY: its own Qt 6.10) through --script."""
    if not FROZEN:
        return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                              text=True, timeout=60).stdout
    script, out = tmp_path / "speed.py", tmp_path / "speed.out"
    script.write_text(code)
    out.unlink(missing_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    subprocess.run([FROZEN, "--script", str(script)],
                   env={**env, "HOME": str(home), "SPEED_OUT": str(out)},
                   capture_output=True, timeout=120)
    return out.read_text() if out.exists() else ""


@pytest.mark.parametrize("backend", ["pipewire", "pulseaudio"])
def test_e2e_the_player_plays_in_real_time_on_mono_and_stereo_pipewire_sinks(
        tmp_path, pipewire_sinks, backend):
    env, names = pipewire_sinks
    track = _tone(tmp_path / "t.wav", seconds=6.0)
    env = {**env, "QT_AUDIO_BACKEND": backend, "QT_QPA_PLATFORM": "offscreen"}
    env.pop("DISPLAY", None)
    for name in names:
        code = _SPEED.format(root=str(ROOT), sink=name, track=str(track))
        out = _speed_run(code, env, tmp_path)
        line = next((ln for ln in out.splitlines() if ln.startswith("SPEED")), "SPEED 0 none")
        speed = float(line.split()[1])
        assert 0.9 < speed < 1.1, f"{backend} {name}: {line}"


# -- the equalizer is heard at once -------------------------------------------------------

class RealTimeSink(MP.MemorySink):
    """Takes float stereo at real time, with a 250 ms buffer like QtSink."""

    def __init__(self, rate=MP.RATE):
        super().__init__()
        self.rate = rate
        self.t0 = time.monotonic()
        self.taken = 0

    def bytes_free(self):
        played = int((time.monotonic() - self.t0) * self.rate) * 8
        return max(0, played + self.rate * 8 // 4 - self.taken)

    def write(self, data):
        self.taken += len(data)
        return super().write(data)


def test_happy_e2e_a_gain_change_is_heard_within_half_a_second(tmp_path):
    """The equalizer ran when a buffer was decoded, up to 2 s ahead of the
    sound card: a slider moved during playback was heard 2 s later."""
    sink = RealTimeSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(_tone(tmp_path / "t.wav", seconds=6.0)))
    engine.play()
    end = time.monotonic() + 2.0
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    gains = [0.0] * 10
    gains[MP.BANDS.index(500)] = -12.0
    gains[MP.BANDS.index(250)] = -12.0
    changed_at = len(sink.data) // 8           # the frame the change was made at
    engine.set_gains(gains)
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    engine.stop()
    left = np.frombuffer(bytes(sink.data), np.float32).reshape(-1, 2)[:, 0]
    level = np.array([np.sqrt(np.mean(left[i:i + 2205] ** 2))
                      for i in range(changed_at, len(left) - 2205, 2205)])  # 50 ms steps
    before = np.sqrt(np.mean(left[changed_at - 22050:changed_at] ** 2))
    quiet = np.nonzero(level < before * 0.5)[0]
    assert len(quiet), "the gain change was never heard"
    heard_after = quiet[0] * 0.05 + 0.25    # what the sink already held plays first
    assert heard_after < 0.5, f"heard after {heard_after:.2f} s"


def test_happy_e2e_the_panel_says_what_the_monitor_found(tmp_path, monkeypatch):
    class DeafSink(MP.MemorySink):
        def bytes_free(self):
            return 0

    monkeypatch.setattr(MP, "MONITOR_WINDOW_SECONDS", 0.6)
    notices = []
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: DeafSink()))
    panel.engine_failed.connect(notices.append)
    panel.add_files([str(_tone(tmp_path / "t.wav"))])
    panel.play_item(panel.playlist.item(0))
    end = time.monotonic() + 3
    while not notices and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)
    panel.engine.stop()
    assert notices and "takes no audio" in notices[0]
    assert "takes no audio" in panel.note.text()
