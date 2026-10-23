"""The voice's microphone and speaker touch Qt Multimedia only after it answered.

ui.voice opens the microphone (QMediaDevices + QAudioSource) and the speaker
(QMediaDevices + QAudioSink) on the GUI thread. Both start Qt's multimedia
backend and talk to the audio server - measured: a deaf audio server makes
QMediaDevices hang for ever, the hanging GPU driver stand-in too. So both
ask core.multimedia_probe first: while it runs the microphone says "try
again in a moment" and the speaker keeps its queue; when it failed both say
that audio is unavailable and why.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import multimedia_probe as MPROBE  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402
from ui import voice as V  # noqa: E402

APP = QApplication.instance() or QApplication([])
HUNG = MPROBE.ProbeResult(ok=False, reason="Qt Multimedia did not answer within 15 s "
                                              "(it hung while listing the audio devices)")
OK = MPROBE.ProbeResult(ok=True)
FFMPEG_VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")


def pump(until, seconds=5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return until()


@pytest.fixture(autouse=True)
def _fresh_probe():
    MPROBE.reset()
    yield
    MPROBE.reset()


class GatedProbe:
    def __init__(self, result) -> None:
        self.result = result
        self.gate = threading.Event()
        self.calls = 0

    def __call__(self, timeout=None, **_kw):
        self.calls += 1
        self.gate.wait(10)
        return self.result


class Null:
    """A voice worker that is never asked anything here."""

    def call(self, *a, **kw):
        raise AssertionError("not called")

    def kill(self):
        pass

    def close(self):
        pass


def controller(**kw):
    ctl = V.VoiceController(settings_loader=lambda: VS.VoiceSettings(output_enabled=True),
                            settings_saver=lambda s: None, tts_worker=Null(), stt_worker=Null(),
                            packages=lambda: (False, False), **kw)
    notices = []
    ctl.notice.connect(notices.append)
    return ctl, notices


# --- happy -------------------------------------------------------------------------------


def test_happy_a_passed_probe_lets_the_microphone_reach_qt(monkeypatch):
    """Past the guard the real code runs: no microphone on the test host."""
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: OK)
    MPROBE.probe()
    with pytest.raises(OSError) as info:
        V.QtRecorder().start()
    assert not isinstance(info.value, (V.AudioPending, V.AudioUnavailable))


def test_happy_the_real_sound_card_starts_the_probe_early(monkeypatch):
    probe = GatedProbe(OK)
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    ctl, _ = controller()
    try:
        assert pump(lambda: probe.calls == 1)
    finally:
        probe.gate.set()
        ctl.shutdown()
        assert pump(lambda: MPROBE.cached() is not None)


def test_happy_fakes_start_no_probe(monkeypatch):
    calls = []
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: calls.append(1) or OK)

    class Recorder:
        pass

    ctl, _ = controller(recorder_factory=Recorder, player=V.QtPlayer(sink_factory=lambda r: None))
    try:
        pump(lambda: False, 0.3)
        assert calls == []
    finally:
        ctl.shutdown()


def test_happy_the_speaker_waits_for_the_probe_then_plays(monkeypatch):
    probe = GatedProbe(OK)
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    opened = []

    def sink(rate):
        V._audio_ready()  # what _qt_sink checks first
        opened.append(rate)
        raise OSError("no device in the test")

    player = V.QtPlayer(sink_factory=sink)
    failed, drained = [], []
    player.failed.connect(failed.append)
    player.drained.connect(lambda: drained.append(1))
    player.enqueue(b"\0\0" * 100, 16000)
    pump(lambda: False, 0.3)
    assert failed == [] and drained == [] and player.busy()  # still waiting
    probe.gate.set()
    assert pump(lambda: failed)
    assert opened == [16000] and failed == ["no device in the test"] and drained


# --- sad ---------------------------------------------------------------------------------


def test_sad_a_failed_probe_keeps_the_microphone_closed_and_says_why(monkeypatch):
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: HUNG)
    MPROBE.probe()
    ctl, notices = controller()
    try:
        assert ctl.start_listening() is False
        assert ctl.state == "idle" and not ctl.listening()
        assert len(notices) == 1 and HUNG.reason in notices[0]
    finally:
        ctl.shutdown()


def test_sad_a_failed_probe_keeps_the_speaker_silent_and_says_why(monkeypatch):
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: HUNG)
    MPROBE.probe()
    with pytest.raises(V.AudioUnavailable) as info:
        V._qt_sink(22050)
    assert HUNG.reason in str(info.value)
    player = V.QtPlayer()  # the real factory
    failed, drained = [], []
    player.failed.connect(failed.append)
    player.drained.connect(lambda: drained.append(1))
    player.enqueue(b"\0\0" * 100, 22050)
    assert pump(lambda: failed)
    assert HUNG.reason in failed[0] and drained and not player.busy()


def test_sad_the_microphone_while_the_probe_runs_asks_to_try_again(monkeypatch):
    probe = GatedProbe(OK)
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    ctl, notices = controller()
    try:
        assert ctl.start_listening() is False
        assert not ctl.listening()
        assert notices and "try again in a moment" in notices[-1]
        assert pump(lambda: probe.calls == 1)
        ctl.start_listening()
        pump(lambda: False, 0.2)
        assert probe.calls == 1  # one child, however often it is pressed
    finally:
        probe.gate.set()
        ctl.shutdown()
        assert pump(lambda: MPROBE.cached() is not None)


# --- edge --------------------------------------------------------------------------------


def test_edge_stop_while_waiting_drops_the_queue(monkeypatch):
    probe = GatedProbe(HUNG)
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    player = V.QtPlayer()
    failed = []
    player.failed.connect(failed.append)
    player.enqueue(b"\0\0" * 100, 16000)
    pump(lambda: False, 0.2)
    player.stop()
    assert not player.busy()
    probe.gate.set()
    assert pump(lambda: MPROBE.cached() is not None)
    pump(lambda: False, 0.3)
    assert failed == []  # nothing was waiting any more


def test_edge_the_pending_error_is_an_oserror_for_old_callers():
    assert issubclass(V.AudioPending, OSError) and issubclass(V.AudioUnavailable, OSError)


def test_edge_paranoid_mode_still_wins_over_the_probe(monkeypatch):
    from core import security_mode

    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: HUNG)
    MPROBE.probe()
    previous = security_mode.current_policy().name
    security_mode.set_policy("paranoid")
    ctl, notices = controller()
    try:
        assert ctl.start_listening() is False
        assert "paranoid" in notices[-1]
    finally:
        security_mode.set_policy(previous)
        ctl.shutdown()


# --- e2e: the real hanging driver, the real controller and sound card --------------------

_VOICE_UNDER_DRIVER = textwrap.dedent("""
    import json, sys, time
    sys.path.insert(0, {root!r})
    from PyQt6.QtWidgets import QApplication
    app = QApplication([])
    from core import voice_settings as VS
    from ui import voice as V
    if {direct!r}:
        # what QtRecorder.start() calls first, without the guard
        from PyQt6.QtMultimedia import QMediaDevices
        QMediaDevices.defaultAudioInput()
        raise SystemExit(0)
    ctl = V.VoiceController(settings_loader=lambda: VS.VoiceSettings(output_enabled=True),
                            settings_saver=lambda s: None, packages=lambda: (False, False))
    notices, failed = [], []
    ctl.notice.connect(notices.append)
    player = V.QtPlayer()
    player.failed.connect(failed.append)
    player.enqueue(b"\\0\\0" * 1000, 16000)
    first = ctl.start_listening()
    start = time.monotonic()
    while time.monotonic() - start < 20 and not failed:
        app.processEvents()
        time.sleep(0.01)
    second = ctl.start_listening()
    print(json.dumps({{"first": first, "second": second, "notices": notices,
                      "failed": failed, "seconds": round(time.monotonic() - start, 2)}}),
          flush=True)
    ctl.shutdown()
""")


def _run_under_driver(tmp_path, *, direct=False, timeout=45):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    env = {k: v for k, v in os.environ.items() if k not in FFMPEG_VARS}
    env.update(QT_QPA_PLATFORM="offscreen", **{MPROBE.SECONDS_ENV: "3"})
    code = _VOICE_UNDER_DRIVER.format(root=str(ROOT), direct=direct)
    try:
        return subprocess.run(HGD.command(lib, [sys.executable, "-c", code]), env=env,
                              capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return None


def test_e2e_negative_control_the_old_microphone_hangs_under_the_driver(tmp_path):
    assert _run_under_driver(tmp_path, direct=True, timeout=10) is None


def test_e2e_under_the_hanging_driver_the_voice_says_why(tmp_path):
    result = _run_under_driver(tmp_path)
    assert result is not None, "the voice froze under the hanging driver"
    assert result.returncode == 0, result.stderr[-1500:]
    state = json.loads(result.stdout.strip().splitlines()[-1])
    assert state["first"] is False and state["second"] is False
    assert any("try again in a moment" in n for n in state["notices"])
    assert any("did not answer within 3 s" in n for n in state["notices"])
    assert state["failed"] and "did not answer within 3 s" in state["failed"][0]
