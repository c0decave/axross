"""Edit > Settings… > Audio against a real sound server, end to end.

tests/test_audio_settings_page.py drives the page with fake players and
recorders. Here the real chain runs: the probe child, Qt's device list,
ui.voice.QtPlayer / QtRecorder on the device chosen in the combo box. A
PipeWire null sink is the speaker (its monitor is recorded with parec to
hear what reached it); a second null sink fed by pacat, remapped to a
source, is the microphone. Each backend Qt offers is tried.

Every run is a child process: Qt reads QT_AUDIO_BACKEND once per process.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RATE = 48000

np = pytest.importorskip("numpy")


def _runtime() -> str:
    for folder in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}"):
        if folder and os.path.exists(os.path.join(folder, "pipewire-0")):
            return folder
    return ""


RUNTIME = _runtime()

pytestmark = pytest.mark.skipif(
    not (RUNTIME and shutil.which("pactl") and shutil.which("parec") and shutil.which("pacat")),
    reason="needs a PipeWire server with pactl, parec and pacat")


_PAGE = """\
import json, os, sys, time
sys.path.insert(0, {root!r})
from PyQt6.QtCore import QCoreApplication, QEvent
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication(["x"])
QCoreApplication.sendEvent(app, QEvent(QEvent.Type.User))
from ui import audio_settings_page as AP

def pump(seconds, until=lambda: False):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not until():
        app.processEvents(); time.sleep(0.005)

def pick(combo, text):
    index = next((i for i in range(combo.count()) if combo.itemText(i) == text), -1)
    combo.setCurrentIndex(index)
    return index

page = AP.AudioPage(None)
page.show()
pump(30, lambda: not page._checking and page._result is not None)
out = {{"ok": bool(page._result and page._result.ok)}}
out["output"] = pick(page.output_combo, {sink!r}) if {sink!r} else page.output_combo.currentIndex()
out["output_text"] = page.output_combo.currentText()
out["input"] = pick(page.input_combo, {source!r})
page.output_slider.setValue({volume})
step = {step!r}
if step == "tone":
    page.tone_button.click()
    start = time.monotonic()
    pump(6, lambda: page.test_label.text() == "Test tone played.")
    out["took"] = time.monotonic() - start
elif step == "level":
    page.mic_button.click()
    peak = 0
    end = time.monotonic() + 2.5
    while time.monotonic() < end:
        pump(0.02); peak = max(peak, page.level_bar.value())
    out["peak"] = peak
elif step == "record":
    page.record_button.click()
    pump(12, lambda: page.test_label.text().startswith("Played back"))
out["label"] = page.test_label.text()
page.shutdown()
print("RESULT " + json.dumps(out), flush=True)
"""


def _pactl(env, *args) -> str:
    out = subprocess.run(["pactl", *args], env=env, capture_output=True, text=True, timeout=20)
    if out.returncode:
        pytest.skip(f"pactl {args[0]} failed: {out.stderr.strip()}")
    return out.stdout.strip()


@pytest.fixture
def devices():
    """A speaker sink, and a microphone source fed through a second sink."""
    env = {**os.environ, "XDG_RUNTIME_DIR": RUNTIME}
    tag = f"axap{os.getpid()}"
    modules = []
    try:
        speaker, feed, mic = f"{tag}_speaker", f"{tag}_feed", f"{tag}_mic"
        for name in (speaker, feed):
            modules.append(_pactl(env, "load-module", "module-null-sink", f"sink_name={name}",
                                  "format=s16le", f"rate={RATE}", "channels=1",
                                  f"sink_properties=device.description={name}"))
        modules.append(_pactl(env, "load-module", "module-remap-source",
                              f"master={feed}.monitor", f"source_name={mic}",
                              f"source_properties=device.description={mic}"))
        yield env, speaker, feed, mic
    finally:
        for module in reversed(modules):
            subprocess.run(["pactl", "unload-module", module], env=env, capture_output=True,
                           timeout=20)


def _tone(seconds: float, amplitude: int = 12000) -> bytes:
    return b"".join(struct.pack("<h", int(amplitude * math.sin(2 * math.pi * 440 * i / RATE)))
                    for i in range(int(seconds * RATE)))


def _feed(env, sink: str, seconds: float) -> subprocess.Popen:
    proc = subprocess.Popen(["pacat", f"--device={sink}", "--format=s16le", f"--rate={RATE}",
                             "--channels=1", "--raw"], env=env, stdin=subprocess.PIPE)
    proc.stdin.write(_tone(seconds))
    proc.stdin.close()
    return proc


def _capture(env, sink: str, path: Path) -> subprocess.Popen:
    return subprocess.Popen(["parec", f"--device={sink}.monitor", "--format=s16le",
                             f"--rate={RATE}", "--channels=1", "--raw",
                             "--latency-msec=50"], env=env, stdout=path.open("wb"))


def _stop(recorder: subprocess.Popen) -> None:
    """SIGINT: parec writes what it holds before it ends (SIGTERM loses
    up to a fragment - a whole 1 s tone on an idle sink)."""
    time.sleep(0.5)
    recorder.send_signal(signal.SIGINT)
    try:
        recorder.wait(10)
    except subprocess.TimeoutExpired:
        recorder.kill()
        recorder.wait(10)


def _peak(path: Path) -> int:
    data = np.fromfile(path, dtype=np.int16)
    return int(np.abs(data.astype(np.int32)).max()) if data.size else 0


def _run_page(tmp_path, env, backend, *, step, sink="", source="", volume=100,
              saved: dict | None = None) -> dict:
    script = tmp_path / f"page_{step}.py"
    script.write_text(_PAGE.format(root=str(ROOT), sink=sink, source=source, volume=volume,
                                   step=step))
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    if saved is not None:
        (home / ".config" / "axross").mkdir(parents=True, exist_ok=True)
        (home / ".config" / "axross" / "audio.json").write_text(json.dumps(saved))
    run_env = {**env, "QT_AUDIO_BACKEND": backend, "QT_QPA_PLATFORM": "offscreen",
               "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}
    run_env.pop("DISPLAY", None)
    out = subprocess.run([sys.executable, str(script)], env=run_env, capture_output=True,
                         text=True, timeout=90)
    line = next((ln for ln in out.stdout.splitlines() if ln.startswith("RESULT ")), "")
    assert line, f"rc={out.returncode}\n{out.stderr[-3000:]}"
    result = json.loads(line[len("RESULT "):])
    assert result["ok"], result
    return result


BACKENDS = ["pipewire", "pulseaudio"]


@pytest.mark.parametrize("backend", BACKENDS)
def test_happy_e2e_the_test_tone_reaches_the_chosen_speaker(tmp_path, devices, backend):
    env, speaker, _feed_sink, _mic = devices
    captured = tmp_path / "speaker.raw"
    recorder = _capture(env, speaker, captured)
    try:
        time.sleep(0.3)
        result = _run_page(tmp_path, env, backend, step="tone", sink=speaker)
    finally:
        _stop(recorder)
    assert result["output"] > 0, result
    assert result["label"] == "Test tone played.", result
    assert result["took"] < 3.0, result
    assert _peak(captured) > 3000


@pytest.mark.parametrize("backend", BACKENDS)
def test_happy_e2e_the_output_volume_scales_what_the_speaker_gets(tmp_path, devices, backend):
    env, speaker, _feed_sink, _mic = devices
    peaks = {}
    for volume in (100, 25):
        captured = tmp_path / f"speaker_{volume}.raw"
        recorder = _capture(env, speaker, captured)
        try:
            time.sleep(0.3)
            _run_page(tmp_path, env, backend, step="tone", sink=speaker, volume=volume)
        finally:
            _stop(recorder)
        peaks[volume] = _peak(captured)
    assert peaks[100] > 3000, peaks
    assert 0.1 < peaks[25] / peaks[100] < 0.45, peaks


@pytest.mark.parametrize("backend", BACKENDS)
def test_happy_e2e_the_microphone_level_moves_with_sound(tmp_path, devices, backend):
    env, _speaker, feed, mic = devices
    feeder = _feed(env, feed, 6.0)
    try:
        result = _run_page(tmp_path, env, backend, step="level", source=mic)
    finally:
        feeder.kill()
        feeder.wait(10)
    assert result["input"] > 0, result
    assert result["peak"] >= 20, result


@pytest.mark.parametrize("backend", BACKENDS)
def test_sad_e2e_a_silent_microphone_shows_no_level(tmp_path, devices, backend):
    env, _speaker, _feed_sink, mic = devices
    result = _run_page(tmp_path, env, backend, step="level", source=mic)
    assert result["input"] > 0, result
    assert result["peak"] <= 2, result


@pytest.mark.parametrize("backend", BACKENDS)
def test_happy_e2e_record_and_play_back_goes_from_microphone_to_speaker(
        tmp_path, devices, backend):
    env, speaker, feed, mic = devices
    captured = tmp_path / "speaker.raw"
    recorder = _capture(env, speaker, captured)
    feeder = _feed(env, feed, 5.0)
    try:
        result = _run_page(tmp_path, env, backend, step="record", sink=speaker, source=mic)
        time.sleep(0.3)
    finally:
        feeder.kill()
        feeder.wait(10)
        _stop(recorder)
    assert result["label"].startswith("Played back"), result
    assert _peak(captured) > 1000


@pytest.mark.parametrize("backend", BACKENDS)
def test_edge_e2e_a_saved_speaker_that_is_gone_plays_on_the_default(tmp_path, devices, backend):
    """The combo keeps the saved id as "(not connected)" (saving the page
    must not lose it); the tone plays on the system's default instead of
    failing."""
    env, *_ = devices
    result = _run_page(tmp_path, env, backend, step="tone",
                       saved={"output_device": "axross-unplugged-speaker"})
    assert result["output_text"] == "axross-unplugged-speaker (not connected)", result
    assert result["label"] == "Test tone played.", result
