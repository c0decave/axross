"""Where axross's sound goes (core.audio_route): the saved output and input
device looked up by its id among Qt's devices, the saved volumes as gains,
and one app-wide signal when the Audio page saves.

Rule (core.multimedia_probe): no in-process Qt Multimedia object before the
probe answered ok - the lookup asks Qt for its device lists only then, and
"" (the system's default) needs no list at all.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_route as AR  # noqa: E402
from core import audio_settings as AS  # noqa: E402
from core import multimedia_probe as MPROBE  # noqa: E402

APP = QApplication.instance() or QApplication([])
OK = MPROBE.ProbeResult(ok=True, backend="pipewire")
FAILED = MPROBE.ProbeResult(ok=False, reason="no server")


class Device:
    """QAudioDevice as the lookup uses it."""

    def __init__(self, device_id: str, description: str = "") -> None:
        self._id = device_id.encode()
        self._description = description or device_id

    def id(self):  # noqa: A003 - Qt's name
        return self._id

    def description(self):
        return self._description


SPEAKERS = [Device("alsa_output.analog"), Device("bluez_output.headset")]
MICS = [Device("alsa_input.analog")]


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(AS, "settings_file", lambda: tmp_path / "audio.json")
    AR.forget()
    MPROBE.reset()
    yield
    AR.forget()
    MPROBE.reset()


def _probe(monkeypatch, result) -> None:
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: result)
    MPROBE.probe()


def _lister(devices, calls):
    def lister():
        calls.append(1)
        return devices
    return lister


# --- happy -------------------------------------------------------------------------------


def test_happy_the_saved_output_is_found_by_its_id(monkeypatch):
    _probe(monkeypatch, OK)
    calls = []
    found = AR.find_device("bluez_output.headset", _lister(SPEAKERS, calls), "output")
    assert found is SPEAKERS[1] and calls == [1]


def test_happy_the_saved_settings_choose_the_devices(monkeypatch, tmp_path):
    _probe(monkeypatch, OK)
    AS.AudioSettings(output_device="alsa_output.analog", input_device="alsa_input.analog",
                     output_volume=40, input_volume=70).save()
    AR.forget()
    monkeypatch.setattr(AR, "_outputs", lambda: SPEAKERS)
    monkeypatch.setattr(AR, "_inputs", lambda: MICS)
    assert AR.output_device() is SPEAKERS[0]
    assert AR.input_device() is MICS[0]
    assert AR.output_gain() == pytest.approx(0.4)
    assert AR.input_gain() == pytest.approx(0.7)


def test_happy_an_explicit_id_wins_over_the_saved_one(monkeypatch):
    _probe(monkeypatch, OK)
    AS.AudioSettings(output_device="alsa_output.analog").save()
    AR.forget()
    monkeypatch.setattr(AR, "_outputs", lambda: SPEAKERS)
    assert AR.output_device("bluez_output.headset") is SPEAKERS[1]
    assert AR.output_device("") is None  # the page's "System default"


def test_happy_publish_tells_every_listener_and_is_what_later_reads_see():
    seen = []
    AR.notifier().changed.connect(seen.append)
    saved = AS.AudioSettings(output_volume=25, output_device="x")
    AR.publish(saved)
    assert len(seen) == 1 and seen[0].output_volume == 25
    assert AR.settings().output_device == "x" and AR.output_gain() == pytest.approx(0.25)
    seen[0].output_volume = 99  # a listener changing its copy changes nothing here
    assert AR.settings().output_volume == 25


# --- sad ---------------------------------------------------------------------------------


def test_sad_a_device_no_longer_there_is_the_default_with_one_log_line(monkeypatch, caplog):
    _probe(monkeypatch, OK)
    calls = []
    with caplog.at_level(logging.INFO, logger="core.audio_route"):
        assert AR.find_device("usb_output.gone", _lister(SPEAKERS, calls), "output") is None
        assert AR.find_device("usb_output.gone", _lister(SPEAKERS, calls), "output") is None
    lines = [r.getMessage() for r in caplog.records if "usb_output.gone" in r.getMessage()]
    assert len(lines) == 1 and "system default" in lines[0]


def test_sad_before_the_probe_answered_qt_is_not_asked(monkeypatch):
    calls = []
    assert MPROBE.cached() is None
    assert AR.find_device("alsa_output.analog", _lister(SPEAKERS, calls), "output") is None
    assert calls == []


def test_sad_after_a_failed_probe_qt_is_not_asked(monkeypatch):
    _probe(monkeypatch, FAILED)
    calls = []
    assert AR.find_device("alsa_output.analog", _lister(SPEAKERS, calls), "output") is None
    assert calls == []


def test_sad_a_broken_settings_file_is_the_defaults(tmp_path):
    (tmp_path / "audio.json").write_text("{not json", encoding="utf-8")
    AR.forget()
    assert AR.settings() == AS.AudioSettings()
    assert AR.output_gain() == 1.0 and AR.input_gain() == 1.0


def test_sad_a_lister_that_raises_is_the_default(monkeypatch):
    _probe(monkeypatch, OK)

    def broken():
        raise RuntimeError("backend gone")

    assert AR.find_device("alsa_output.analog", broken, "output") is None


# --- edge --------------------------------------------------------------------------------


def test_edge_the_system_default_needs_no_device_list(monkeypatch):
    _probe(monkeypatch, OK)
    calls = []
    assert AR.find_device("", _lister(SPEAKERS, calls), "output") is None
    assert calls == []


def test_edge_volume_zero_is_silence_not_the_default(monkeypatch):
    AR.publish(AS.AudioSettings(output_volume=0, input_volume=0))
    assert AR.output_gain() == 0.0 and AR.input_gain() == 0.0


def test_edge_a_device_coming_back_is_logged_again_when_it_goes_again(monkeypatch, caplog):
    _probe(monkeypatch, OK)
    gone = [Device("alsa_output.analog")]
    with caplog.at_level(logging.INFO, logger="core.audio_route"):
        AR.find_device("bluez_output.headset", lambda: gone, "output")
        assert AR.find_device("bluez_output.headset", lambda: SPEAKERS, "output") is SPEAKERS[1]
        AR.find_device("bluez_output.headset", lambda: gone, "output")
    lines = [r for r in caplog.records if "bluez_output.headset" in r.getMessage()]
    assert len(lines) == 2


def test_edge_the_notifier_is_one_object():
    assert AR.notifier() is AR.notifier()


# --- the backend of this run (core.multimedia_probe.active_backend) -------------------------


def test_happy_the_first_answering_backend_is_this_runs(monkeypatch):
    MPROBE._active_backend = None
    assert MPROBE.active_backend() is None
    _probe(monkeypatch, OK)
    assert MPROBE.active_backend() == "pipewire"


def test_sad_a_failed_probe_names_no_backend(monkeypatch):
    MPROBE._active_backend = None
    _probe(monkeypatch, FAILED)
    assert MPROBE.active_backend() is None


def test_edge_check_again_with_another_backend_keeps_this_runs(monkeypatch):
    """Qt reads QT_AUDIO_BACKEND once per process: a later check that
    answered with PulseAudio does not change what this run uses."""
    MPROBE._active_backend = None
    _probe(monkeypatch, OK)
    MPROBE.reset()
    _probe(monkeypatch, MPROBE.ProbeResult(ok=True, backend="pulseaudio"))
    assert MPROBE.cached().backend == "pulseaudio"
    assert MPROBE.active_backend() == "pipewire"
