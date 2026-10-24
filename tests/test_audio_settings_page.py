"""Edit > Settings… > Audio (ui.audio_settings_page).

Operator: *„insbesondere brauchen wir natürlich einen bereich in dem wir auch
input und output devices configen koennen und testen."* / *„ein interface in
axross fuer die konfiguration von input/output/volume etc.pp. einbauen"* /
*„und wir sollten natuerlich pulse und pipewire sinnvoll und korrekt
supporten"*.

The page: the audio backend (Automatic / PipeWire / PulseAudio, the one of
this run shown, a change applies at the next start), the output device and
volume with a test tone, the input device and gain with a level meter and a
record-and-play-back test, the probe's answer and "Check Audio Again".

Before the probe answered the page asks Qt nothing (the device lists come
from the probe's child); the tests drive the real page in the real Settings
dialog with QTest. Qt's speaker is the real ui.voice.QtPlayer over a fake
QAudioSink; the microphone is a fake recorder with QtRecorder's interface.
The real-device run is tests/test_audio_page_real.py.
"""

from __future__ import annotations

import array
import json
import math
import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtMultimedia = pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QObject, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialogButtonBox  # noqa: E402

from core import audio_route as AR  # noqa: E402
from core import audio_settings as AS  # noqa: E402
from core import multimedia_env as ME  # noqa: E402
from core import multimedia_probe as MPROBE  # noqa: E402
from core.multimedia_probe import AudioDeviceInfo as Dev  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()

SPEAKER = Dev("alsa_output.pci-0000_00_05.0.analog-stereo", "Built-in Audio Analog Stereo", True)
HEADSET = Dev("bluez_output.00_11_22.1", "Headset")
MIC = Dev("alsa_input.pci-0000_00_05.0.analog-stereo", "Built-in Audio Analog Stereo", True)
OK = MPROBE.ProbeResult(ok=True, backend="pipewire", outputs=2, inputs=1,
                        output_devices=(SPEAKER, HEADSET), input_devices=(MIC,))
HUNG = MPROBE.ProbeResult(ok=False, reason="Qt Multimedia did not answer within 15 s (it hung "
                                           "while listing the audio devices of the audio server)")


def pump(cond, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


class Probe:
    """run_probe answering the queued results; with *gate* it waits for it."""

    def __init__(self, *results, gate: bool = False) -> None:
        self.results = list(results)
        self.calls = 0
        self.gate = threading.Event()
        if not gate:
            self.gate.set()

    def __call__(self, timeout=None, **_kw):
        self.calls += 1
        self.gate.wait(10)
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


# -- the speaker: the real QtPlayer over a fake QAudioSink -----------------------------------


class FakeIO:
    def __init__(self, sink) -> None:
        self.sink = sink

    def write(self, data) -> int:
        self.sink.written += bytes(data)
        return len(data)


class FakeSink:
    """QAudioSink in push mode that plays everything at once."""

    def __init__(self) -> None:
        self.written = b""
        self.stopped = False

    def bytesFree(self):  # noqa: N802 - Qt API
        return 1 << 20

    def bufferSize(self):  # noqa: N802 - Qt API
        return 1 << 20

    def state(self):
        return QtMultimedia.QAudio.State.IdleState

    def stop(self):
        self.stopped = True

    def deleteLater(self):  # noqa: N802 - Qt API
        pass


class Speakers:
    """The page's player factory: records (device, volume) per player."""

    def __init__(self, fail: str = "") -> None:
        self.made: list[tuple[str, float, FakeSink]] = []
        self.fail = fail

    def __call__(self, device_id, volume):
        from ui import voice as V

        def sink_factory(rate):
            if self.fail:
                raise OSError(self.fail)
            sink = FakeSink()
            self.made.append((device_id, volume, sink))
            return sink, FakeIO(sink), rate

        return V.QtPlayer(sink_factory=sink_factory)


class Recorder(QObject):
    """QtRecorder's interface: start() (OSError when it cannot), data(bytes)
    of 16 kHz mono int16, stop()."""

    data = pyqtSignal(bytes)
    made: list = []
    fail = ""

    def __init__(self, device_id, volume) -> None:
        super().__init__()
        self.device_id, self.volume = device_id, volume
        self.running = False
        Recorder.made.append(self)

    def start(self):
        if Recorder.fail:
            raise OSError(Recorder.fail)
        self.running = True

    def stop(self):
        self.running = False


def loud(seconds: float, amplitude: int = 16000) -> bytes:
    n = int(16000 * seconds)
    return array.array("h", (int(amplitude * math.sin(i * 0.3)) for i in range(n))).tobytes()


class Watcher(QObject):
    audioOutputsChanged = pyqtSignal()  # noqa: N815 - Qt's name
    audioInputsChanged = pyqtSignal()  # noqa: N815 - Qt's name


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def audio(stores, monkeypatch):
    """The page's Qt seams: the live device lists, the hotplug watcher, the
    speaker and the microphone."""
    from ui import audio_settings_page as AP

    monkeypatch.delenv(ME.AUDIO_BACKEND_VAR, raising=False)
    ME._SET_BY_AXROSS.discard(ME.AUDIO_BACKEND_VAR)
    MPROBE.reset()
    monkeypatch.setattr(MPROBE, "_active_backend", None)  # a fresh process
    AR.forget()
    state = type("State", (), {})()
    state.devices = (OK.output_devices, OK.input_devices)
    state.lister_calls = 0
    state.watchers = []
    state.speakers = Speakers()
    Recorder.made, Recorder.fail = [], ""

    def lister():
        state.lister_calls += 1
        return state.devices

    def watcher(parent):
        w = Watcher(parent)
        state.watchers.append(w)
        return w

    monkeypatch.setattr(AP, "_qt_devices", lister)
    monkeypatch.setattr(AP, "_qt_watcher", watcher)
    monkeypatch.setattr(AP, "_make_player", lambda d, v: state.speakers(d, v))
    monkeypatch.setattr(AP, "_make_recorder", Recorder)
    state.AP = AP
    yield state
    MPROBE.reset()
    AR.forget()
    ME._SET_BY_AXROSS.discard(ME.AUDIO_BACKEND_VAR)


def open_page(stores, probe, monkeypatch):
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    win = stores.make_window()
    dialog = stores.settings_dialog(win)
    dialog.show()
    dialog.show_page("audio")
    return dialog, dialog.page("audio")


def combo_ids(combo) -> list[str]:
    return [combo.itemData(i) for i in range(combo.count())]


def saved_json(stores) -> dict:
    return json.loads((stores.config / "audio.json").read_text(encoding="utf-8"))


# --- happy -------------------------------------------------------------------------------


def test_happy_the_dialog_has_an_audio_page_titled_audio(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert dialog.current_page_id() == "audio"
    assert dialog.title_label.text() == "Audio"
    titles = [dialog.tree.topLevelItem(i).text(0) for i in range(dialog.tree.topLevelItemCount())]
    assert "Audio" in titles
    dialog.apply_filter("microphone")
    assert "audio" in dialog.visible_page_ids()
    dialog.apply_filter("pipewire")
    assert "audio" in dialog.visible_page_ids()


def test_happy_the_lists_wait_for_the_probe_then_fill(stores, audio, monkeypatch):
    probe = Probe(OK, gate=True)
    dialog, page = open_page(stores, probe, monkeypatch)
    try:
        assert pump(lambda: probe.calls == 1)
        assert "Checking audio" in page.status_label.text()
        assert combo_ids(page.output_combo) == [""] and combo_ids(page.input_combo) == [""]
        assert not page.tone_button.isEnabled() and not page.mic_button.isEnabled()
        assert audio.lister_calls == 0  # Qt not asked before the probe answered
    finally:
        probe.gate.set()
    assert pump(lambda: page.tone_button.isEnabled())
    assert combo_ids(page.output_combo) == ["", SPEAKER.device_id, HEADSET.device_id]
    assert combo_ids(page.input_combo) == ["", MIC.device_id]
    assert page.output_combo.itemText(0) == "System default"
    assert "Headset" in page.output_combo.itemText(2)
    assert page.status_label.text() == "Audio works: PipeWire, 2 output devices, 1 input device."
    assert "PipeWire" in page.active_label.text()
    assert page.mic_button.isEnabled() and page.record_button.isEnabled()
    assert len(audio.watchers) == 1  # hotplug is watched once audio works


def test_happy_e2e_choose_devices_and_volumes_then_ok_writes_audio_json(
        stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    heard = []
    AR.notifier().changed.connect(heard.append)
    page.backend_combo.setFocus()
    QTest.keyClick(page.backend_combo, Qt.Key.Key_End)  # Automatic, PipeWire, PulseAudio
    page.output_combo.setFocus()
    QTest.keyClick(page.output_combo, Qt.Key.Key_End)
    page.input_combo.setFocus()
    QTest.keyClick(page.input_combo, Qt.Key.Key_End)
    page.output_slider.setFocus()
    QTest.keyClick(page.output_slider, Qt.Key.Key_Home)
    for _ in range(4):
        QTest.keyClick(page.output_slider, Qt.Key.Key_PageUp)  # 10 a page
    page.input_slider.setFocus()
    QTest.keyClick(page.input_slider, Qt.Key.Key_PageDown)
    assert page.output_value.text() == "40 %"
    assert dialog.dirty_page_ids() == ["audio"]
    QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok),
                     Qt.MouseButton.LeftButton)
    assert saved_json(stores) == {"version": 1, "backend": "pulseaudio",
                                  "output_device": HEADSET.device_id, "output_volume": 40,
                                  "input_device": MIC.device_id, "input_volume": 90}
    assert len(heard) == 1 and heard[0].output_device == HEADSET.device_id
    assert AR.output_gain() == pytest.approx(0.4)


def test_happy_e2e_the_test_tone_plays_on_the_chosen_device_at_the_chosen_volume(
        stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    page.output_combo.setCurrentIndex(2)
    page.output_slider.setValue(25)
    QTest.mouseClick(page.tone_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: page.test_label.text() == "Test tone played.")
    (device, volume, sink), = audio.speakers.made
    assert device == HEADSET.device_id and volume == pytest.approx(0.25)
    rate = audio.AP.TONE_RATE
    assert len(sink.written) == int(rate * audio.AP.TONE_SECONDS) * 2  # 1 s, int16 mono
    samples = array.array("h", sink.written)
    assert max(samples) > 10000 and abs(samples[0]) < 500  # a sine, faded in
    assert not (stores.config / "audio.json").exists()  # a test stores nothing


def test_happy_e2e_the_microphone_test_shows_the_level(stores, audio, monkeypatch):
    monkeypatch.setattr(audio.AP, "LEVEL_SECONDS", 0.3)
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.mic_button.isEnabled())
    page.input_combo.setCurrentIndex(1)
    page.input_slider.setValue(70)
    QTest.mouseClick(page.mic_button, Qt.MouseButton.LeftButton)
    recorder, = Recorder.made
    assert recorder.running and recorder.device_id == MIC.device_id
    assert recorder.volume == pytest.approx(0.7)
    assert page.mic_button.text() == "Stop"
    recorder.data.emit(loud(0.1))
    assert page.level_bar.value() > 50
    assert pump(lambda: not recorder.running, 3)  # ends by itself
    assert page.level_bar.value() == 0 and page.mic_button.text() == "Test Microphone"


def test_happy_e2e_record_and_play_back(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.record_button.isEnabled())
    page.output_combo.setCurrentIndex(1)
    page.output_slider.setValue(60)
    QTest.mouseClick(page.record_button, Qt.MouseButton.LeftButton)
    recorder, = Recorder.made
    assert "Recording" in page.test_label.text()
    voice = loud(audio.AP.RECORD_SECONDS)
    recorder.data.emit(voice[: len(voice) // 2])
    assert recorder.running
    recorder.data.emit(voice[len(voice) // 2:])
    assert not recorder.running  # 3 s are there: recording ends, playback starts
    assert pump(lambda: page.test_label.text().startswith("Played back"))
    (device, volume, sink), = audio.speakers.made
    assert device == SPEAKER.device_id and volume == pytest.approx(0.6)
    assert sink.written == voice  # 16 kHz mono int16 as recorded
    assert "3.0 s" in page.test_label.text()


def test_happy_e2e_check_audio_again_refreshes_the_lists(stores, audio, monkeypatch):
    usb = Dev("usb_output.dac", "USB DAC")
    later = MPROBE.ProbeResult(ok=True, backend="pipewire", outputs=1, inputs=0,
                               output_devices=(usb,))
    probe = Probe(OK, later)
    dialog, page = open_page(stores, probe, monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    audio.devices = (later.output_devices, later.input_devices)
    QTest.mouseClick(page.check_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: probe.calls == 2 and page.check_button.isEnabled())
    assert combo_ids(page.output_combo) == ["", "usb_output.dac"]
    assert combo_ids(page.input_combo) == [""]
    assert page.status_label.text() == "Audio works: PipeWire, 1 output device, 0 input devices."


def test_happy_hotplug_refreshes_the_lists(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    page.output_combo.setCurrentIndex(2)
    usb = Dev("usb_output.dac", "USB DAC")
    audio.devices = ((SPEAKER, HEADSET, usb), (MIC,))
    audio.watchers[0].audioOutputsChanged.emit()
    assert combo_ids(page.output_combo)[-1] == "usb_output.dac"
    assert page.output_combo.currentData() == HEADSET.device_id  # the choice stays


# --- sad ---------------------------------------------------------------------------------


def test_sad_a_failed_probe_says_why_tests_off_backend_still_saveable(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(HUNG), monkeypatch)
    assert pump(lambda: "did not answer" in page.status_label.text())
    assert page.status_label.text().startswith("Audio and video do not start on this system")
    for button in (page.tone_button, page.mic_button, page.record_button):
        assert not button.isEnabled()
    assert page.check_button.isEnabled() and page.backend_combo.isEnabled()
    assert "off" in page.active_label.text()
    assert audio.lister_calls == 0 and audio.watchers == []
    page.backend_combo.setCurrentIndex(page.backend_combo.findData("pulseaudio"))
    assert dialog.apply()
    assert saved_json(stores)["backend"] == "pulseaudio"


def test_sad_check_again_after_a_failure_turns_the_tests_on(stores, audio, monkeypatch):
    probe = Probe(HUNG, OK)
    dialog, page = open_page(stores, probe, monkeypatch)
    assert pump(lambda: "did not answer" in page.status_label.text())
    QTest.mouseClick(page.check_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: page.tone_button.isEnabled())
    assert probe.calls == 2 and MPROBE.cached().ok


def test_sad_no_sound_device_is_said_not_hung(stores, audio, monkeypatch):
    audio.speakers.fail = "No audio output found"
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    QTest.mouseClick(page.tone_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: "No audio output found" in page.test_label.text())
    assert page.test_label.text().startswith("No sound:")


def test_sad_a_microphone_that_cannot_open_is_said(stores, audio, monkeypatch):
    Recorder.fail = "The microphone could not be opened"
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.mic_button.isEnabled())
    QTest.mouseClick(page.mic_button, Qt.MouseButton.LeftButton)
    assert "could not be opened" in page.test_label.text()
    assert page.mic_button.text() == "Test Microphone"
    QTest.mouseClick(page.record_button, Qt.MouseButton.LeftButton)
    assert "could not be opened" in page.test_label.text()
    assert audio.speakers.made == []


def test_sad_a_silent_recording_plays_nothing(stores, audio, monkeypatch):
    monkeypatch.setattr(audio.AP, "RECORD_SECONDS", 0.2)
    monkeypatch.setattr(audio.AP, "_RECORD_GRACE_SECONDS", 0.1)
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.record_button.isEnabled())
    QTest.mouseClick(page.record_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: "Nothing was recorded" in page.test_label.text(), 4)
    assert audio.speakers.made == []


def test_sad_a_disk_error_keeps_the_dialog_open_and_names_it(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())

    def broken(self, path=None):
        raise OSError("No space left on device")

    monkeypatch.setattr(AS.AudioSettings, "save", broken)
    page.output_slider.setValue(10)
    assert not dialog.apply()
    assert "Not saved - Audio" in dialog.error_text() and "No space left" in dialog.error_text()
    assert page.is_dirty()


# --- edge --------------------------------------------------------------------------------


def test_edge_a_saved_device_that_is_not_connected_is_kept(stores, audio, monkeypatch):
    AS.AudioSettings(output_device="usb_output.gone", output_volume=55).save(
        stores.config / "audio.json")
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    assert page.output_combo.currentData() == "usb_output.gone"
    assert "not connected" in page.output_combo.currentText()
    assert page.output_slider.value() == 55
    assert not page.is_dirty()
    page.input_slider.setValue(20)
    assert dialog.apply()
    assert saved_json(stores)["output_device"] == "usb_output.gone"  # not lost by saving


def test_edge_no_devices_at_all(stores, audio, monkeypatch):
    audio.devices = ((), ())
    empty = MPROBE.ProbeResult(ok=True, backend="pulseaudio")
    dialog, page = open_page(stores, Probe(empty), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    assert combo_ids(page.output_combo) == [""] and combo_ids(page.input_combo) == [""]
    assert page.status_label.text() == "Audio works: PulseAudio, 0 output devices, 0 input " \
                                       "devices."


def test_edge_closing_the_dialog_stops_a_running_test(stores, audio, monkeypatch):
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.mic_button.isEnabled())
    QTest.mouseClick(page.mic_button, Qt.MouseButton.LeftButton)
    recorder, = Recorder.made
    dialog.reject()
    assert not recorder.running


def test_edge_building_the_page_starts_no_check_showing_it_does(audio, monkeypatch, tmp_path):
    """(The main window starts this run's check itself - the voice's
    speaker - so the page is built alone here.)"""
    probe = Probe(OK)
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    page = audio.AP.AudioPage(path=tmp_path / "audio.json")
    try:
        pump(lambda: False, 0.2)
        assert probe.calls == 0 and MPROBE.cached() is None
        assert page.status_label.text() == "Audio is checked when this page is shown."
        page.show()
        assert pump(lambda: page.tone_button.isEnabled())
        assert probe.calls == 1
    finally:
        page.shutdown()
        page.deleteLater()


def test_edge_the_users_own_variable_is_named(stores, audio, monkeypatch):
    monkeypatch.setenv(ME.AUDIO_BACKEND_VAR, "pulseaudio")
    dialog, page = open_page(stores, Probe(OK), monkeypatch)
    assert pump(lambda: page.tone_button.isEnabled())
    assert "QT_AUDIO_BACKEND=pulseaudio" in page.backend_note.text()


def test_edge_check_again_is_off_while_a_check_runs(stores, audio, monkeypatch):
    probe = Probe(OK, gate=True)
    dialog, page = open_page(stores, probe, monkeypatch)
    try:
        assert pump(lambda: probe.calls == 1)
        assert not page.check_button.isEnabled()
    finally:
        probe.gate.set()
    assert pump(lambda: page.check_button.isEnabled())


def test_edge_the_tone_is_a_faded_sine():
    from ui import audio_settings_page as AP

    pcm = AP.sine_tone(8000, 0.5, 1000.0, amplitude=0.5)
    samples = array.array("h", pcm)
    assert len(samples) == 4000
    assert samples[0] == 0 and abs(samples[-1]) < 200  # no click at either end
    assert 16000 <= max(samples) <= 16384
    assert AP.sine_tone(8000, 0.0, 440.0) == b""
    with pytest.raises(ValueError):
        AP.sine_tone(0, 1.0, 440.0)
