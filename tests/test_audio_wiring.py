"""The saved audio choice reaches every player (core.audio_route).

Operator: *„ein interface in axross fuer die konfiguration von
input/output/volume etc.pp. einbauen"*. The Audio page stores an output
and an input device (by id) and two volumes; this file checks each user of
Qt Multimedia takes them: the voice's microphone (device, gain) and speaker
(device, gain), the Media Player's sink and QMediaPlayer output (device,
the output volume scaling its own slider, a live change), the media
preview's QAudioOutput (device, volume, a live change). Qt's classes are
replaced by fakes with their interface (the test host has no sound card);
the code under test is the real one.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtMultimedia = pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import audio_route as AR  # noqa: E402
from core import audio_settings as AS  # noqa: E402
from core import extensions as EX  # noqa: E402
from core import multimedia_probe as MPROBE  # noqa: E402

APP = QApplication.instance() or QApplication([])
OK = MPROBE.ProbeResult(ok=True, backend="pipewire")
HUNG = MPROBE.ProbeResult(ok=False, reason="Qt Multimedia did not answer within 15 s")


def _load_player():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_audio_wiring", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load_player()


# -- fakes of Qt Multimedia -----------------------------------------------------------------


class Device:
    def __init__(self, device_id: str, null: bool = False) -> None:
        self._id = device_id.encode()
        self._null = null

    def id(self):  # noqa: A003 - Qt's name
        return self._id

    def description(self):
        return self._id.decode()

    def isNull(self):  # noqa: N802 - Qt API
        return self._null

    def isFormatSupported(self, fmt):  # noqa: N802 - Qt API
        return True

    def preferredFormat(self):  # noqa: N802 - Qt API
        return QtMultimedia.QAudioFormat()

    def __repr__(self) -> str:
        return f"Device({self._id.decode()!r})"


DEFAULT_OUT = Device("default.out")
DEFAULT_IN = Device("default.in")
SPEAKER = Device("alsa_output.analog")
HEADSET = Device("bluez_output.headset")
MIC = Device("alsa_input.analog")


class MediaDevices:
    outputs = [DEFAULT_OUT, SPEAKER, HEADSET]
    inputs = [DEFAULT_IN, MIC]

    @staticmethod
    def audioOutputs():  # noqa: N802 - Qt API
        return list(MediaDevices.outputs)

    @staticmethod
    def audioInputs():  # noqa: N802 - Qt API
        return list(MediaDevices.inputs)

    @staticmethod
    def defaultAudioOutput():  # noqa: N802 - Qt API
        return DEFAULT_OUT

    @staticmethod
    def defaultAudioInput():  # noqa: N802 - Qt API
        return DEFAULT_IN


class IO(QObject):
    readyRead = pyqtSignal()  # noqa: N815 - Qt's name

    def __init__(self) -> None:
        super().__init__()
        self.written = b""

    def write(self, data):
        self.written += bytes(data)
        return len(data)

    def readAll(self):  # noqa: N802 - Qt API
        return b""


class Source(QObject):
    made: list = []

    def __init__(self, device, fmt, parent=None) -> None:
        super().__init__(parent)
        self.device, self.volume = device, None
        Source.made.append(self)

    def setVolume(self, v):  # noqa: N802 - Qt API
        self.volume = v

    def start(self):
        return IO()

    def stop(self):
        pass


class Sink(QObject):
    made: list = []

    def __init__(self, device, fmt, parent=None) -> None:
        super().__init__(parent)
        self.device, self.volume = device, None
        Sink.made.append(self)

    def setBufferSize(self, n):  # noqa: N802 - Qt API
        pass

    def setVolume(self, v):  # noqa: N802 - Qt API
        self.volume = v

    def start(self):
        return IO()

    def error(self):
        return QtMultimedia.QAudio.Error.NoError

    def bytesFree(self):  # noqa: N802 - Qt API
        return 0

    def stop(self):
        pass


class AudioOutput(QObject):
    made: list = []

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.device, self.volume = None, 1.0
        AudioOutput.made.append(self)

    def setDevice(self, device):  # noqa: N802 - Qt API
        self.device = device

    def setVolume(self, v):  # noqa: N802 - Qt API
        self.volume = v


class MediaPlayer(QObject):
    mediaStatusChanged = pyqtSignal(object)  # noqa: N815 - Qt's name
    errorOccurred = pyqtSignal(object, str)  # noqa: N815 - Qt's name

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.output = None

    def setAudioOutput(self, output):  # noqa: N802 - Qt API
        self.output = output

    def setVideoOutput(self, widget):  # noqa: N802 - Qt API
        pass

    def setSource(self, url):  # noqa: N802 - Qt API
        pass

    def stop(self):
        pass


class VideoWidget(QWidget):
    pass


@pytest.fixture(autouse=True)
def fakes(monkeypatch, tmp_path):
    import PyQt6.QtMultimediaWidgets as QtMultimediaWidgets

    monkeypatch.setattr(AS, "settings_file", lambda: tmp_path / "audio.json")
    for name, fake in (("QMediaDevices", MediaDevices), ("QAudioSource", Source),
                       ("QAudioSink", Sink), ("QAudioOutput", AudioOutput),
                       ("QMediaPlayer", MediaPlayer)):
        monkeypatch.setattr(QtMultimedia, name, fake)
    monkeypatch.setattr(QtMultimediaWidgets, "QVideoWidget", VideoWidget)
    Source.made, Sink.made, AudioOutput.made = [], [], []
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: OK)
    MPROBE.reset()
    MPROBE.probe()
    AR.forget()
    yield
    AR.forget()
    MPROBE.reset()


def save(**values) -> None:
    AR.publish(AS.AudioSettings(**values))


# --- the voice -----------------------------------------------------------------------------


def test_happy_the_microphone_takes_the_saved_device_and_gain():
    from ui import voice as V

    save(input_device="alsa_input.analog", input_volume=60)
    V.QtRecorder().start()
    source = Source.made[-1]
    assert source.device is MIC and source.volume == pytest.approx(0.6)


def test_happy_the_speaker_takes_the_saved_device_and_gain():
    from ui import voice as V

    save(output_device="bluez_output.headset", output_volume=30)
    _sink, _io, _rate = V._qt_sink(22050)
    assert Sink.made[-1].device is HEADSET and Sink.made[-1].volume == pytest.approx(0.3)


def test_happy_the_page_tests_an_unsaved_choice():
    """The Audio page's Test buttons use what is chosen there, not yet saved."""
    from ui import voice as V

    save(input_device="alsa_input.analog", output_device="alsa_output.analog")
    V.QtRecorder(device_id="", volume=0.25).start()
    assert Source.made[-1].device is DEFAULT_IN and Source.made[-1].volume == 0.25
    V._qt_sink(16000, device_id="bluez_output.headset", volume=0.5)
    assert Sink.made[-1].device is HEADSET and Sink.made[-1].volume == 0.5


def test_sad_a_microphone_no_longer_there_records_from_the_default(caplog):
    from ui import voice as V

    save(input_device="usb_input.gone")
    with caplog.at_level(logging.INFO, logger="core.audio_route"):
        V.QtRecorder().start()
    assert Source.made[-1].device is DEFAULT_IN
    assert any("usb_input.gone" in r.getMessage() for r in caplog.records)


def test_edge_volume_zero_mutes_the_speaker():
    from ui import voice as V

    save(output_volume=0)
    V._qt_sink(22050)
    assert Sink.made[-1].volume == 0.0 and Sink.made[-1].device is DEFAULT_OUT


# --- the Media Player ----------------------------------------------------------------------


def test_happy_the_players_sink_takes_the_saved_device():
    save(output_device="alsa_output.analog")
    MP.QtSink(MP._audio_format())
    assert Sink.made[-1].device is SPEAKER


def test_happy_the_simple_engine_takes_the_saved_device_and_follows_a_change():
    save(output_device="alsa_output.analog")
    engine = MP.SimpleEngine()
    output = AudioOutput.made[-1]
    assert output.device is SPEAKER
    save(output_device="bluez_output.headset")
    engine.reroute()
    assert output.device is HEADSET
    save(output_device="")
    engine.reroute()
    assert output.device is DEFAULT_OUT


class RecordingSink(MP.MemorySink):
    def __init__(self) -> None:
        super().__init__()
        self.suspended = False

    def suspend(self) -> None:
        super().suspend()
        self.suspended = True


def test_happy_the_eq_engine_moves_a_playing_track_to_the_new_device():
    made = []

    def factory(fmt):
        made.append(RecordingSink())
        return made[-1]

    engine = MP.EqEngine(sink_factory=factory)
    engine.state = "playing"
    engine._sink = factory(None)
    old = engine._sink
    engine.reroute()
    assert engine._sink is not old and not old.running and engine._sink.running
    engine.state = "paused"
    engine.reroute()
    assert engine._sink.suspended  # paused stays paused on the new device


def test_edge_a_stopped_eq_engine_opens_nothing_on_a_change():
    made = []
    engine = MP.EqEngine(sink_factory=lambda fmt: made.append(1) or MP.MemorySink())
    engine.reroute()
    assert made == [] and engine._sink is None


class FakeEngine(QObject):
    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.state, self.error, self.loaded, self.path = "stopped", "", False, ""
        self.volume = None

    def set_volume(self, v):
        self.volume = v

    def load(self, path):
        pass

    def play(self):
        pass

    def pause(self):
        pass

    def stop(self):
        pass

    def seek(self, ms):
        pass

    def set_gains(self, g):
        pass

    def position_ms(self):
        return 0

    def duration_ms(self):
        return 0

    def current_bars(self, n=32):
        return None


class RoutingEngine(FakeEngine):
    """An engine that can move to another output device while it plays."""

    def __init__(self) -> None:
        super().__init__()
        self.reroutes = 0

    def reroute(self):
        self.reroutes += 1


def test_happy_the_output_volume_scales_the_players_own_slider():
    save(output_volume=50)
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine)
    try:
        panel.volume.setValue(80)
        assert engine.volume == pytest.approx(MP.perceptual_to_linear(0.8) * 0.5)
        save(output_volume=100)  # saved on the Audio page: the running player follows
        assert engine.volume == pytest.approx(MP.perceptual_to_linear(0.8))
    finally:
        panel.close()


def test_happy_a_saved_device_change_reaches_the_running_engine():
    engine = RoutingEngine()
    panel = MP.PlayerPanel(engine=engine)
    try:
        save(output_device="bluez_output.headset")
        assert engine.reroutes == 1
        save(output_device="bluez_output.headset", output_volume=40)  # same device
        assert engine.reroutes == 1
    finally:
        panel.close()


def test_edge_an_engine_without_reroute_is_left_alone():
    """PendingEngine and older engines: the next playback takes the device."""
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        save(output_device="bluez_output.headset")  # no AttributeError
    finally:
        panel.close()


def test_edge_a_closed_panel_no_longer_listens():
    from PyQt6 import sip

    panel = MP.PlayerPanel(engine=RoutingEngine())
    sip.delete(panel)
    save(output_device="bluez_output.headset", output_volume=10)  # nothing raises


# --- the media preview ---------------------------------------------------------------------


def test_happy_the_preview_takes_the_saved_device_and_volume_and_follows_a_change():
    from core.local_fs import LocalFS
    from ui import media_viewer as MV

    save(output_device="alsa_output.analog", output_volume=70)
    viewer = MV.MediaViewer(LocalFS())
    try:
        viewer._ensure_player()
        output = AudioOutput.made[-1]
        assert output.device is SPEAKER and output.volume == pytest.approx(0.7)
        save(output_device="bluez_output.headset", output_volume=20)
        assert output.device is HEADSET and output.volume == pytest.approx(0.2)
        save(output_device="", output_volume=20)
        assert output.device is DEFAULT_OUT
    finally:
        viewer.shutdown()


def test_edge_a_preview_without_a_player_ignores_a_change():
    from core.local_fs import LocalFS
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    try:
        save(output_device="bluez_output.headset")
        assert AudioOutput.made == []  # nothing created by the change
    finally:
        viewer.shutdown()
