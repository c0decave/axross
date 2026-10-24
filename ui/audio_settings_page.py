"""Edit > Settings… > Audio: backend, devices, volumes - and a test of each.

* **Audio backend** - Automatic, PipeWire or PulseAudio (core.audio_settings,
  QT_AUDIO_BACKEND). The backend this run plays through is shown
  (core.multimedia_probe.active_backend); Qt reads the choice once per
  process, so a change takes effect when axross restarts.
* **Output** - the device ("System default" or one by its id), the output
  volume (it scales everything axross plays) and *Play Test Tone*: a 1 s
  sine through QAudioSink in push mode on the chosen device at the chosen
  volume (ui.voice.QtPlayer; nothing blocks).
* **Input** - the device, its volume (gain), *Test Microphone* (a live
  level meter for a few seconds through QAudioSource) and *Record 3 s and
  Play Back* (on the chosen output).
* **Status** - the probe's answer and *Check Audio Again*.

The rule of core.multimedia_probe holds: before the probe answered ok the
page creates no Qt Multimedia object; its device lists come from the probe's
child. After ok it lists Qt's devices itself and follows hotplug
(QMediaDevices.audioOutputsChanged / audioInputsChanged). The probe starts
when the page is first shown, not when the dialog is built. When the probe
failed the reason is shown, the tests are off, and the backend can still be
chosen and saved - the usual way out.

A saved device that is not connected stays in its list as "(not connected)"
so saving the page does not lose it; the players use the system's default
for it meanwhile (core.audio_route). Saving publishes the settings
(core.audio_route.publish): running players take the volume and the output
device where Qt allows, else at their next playback.
"""

from __future__ import annotations

import array
import logging
import math
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from core import audio_route as AR
from core import multimedia_probe as MPROBE
from core import voice_audio as VA
from core.audio_settings import FIELDS, VOLUME_RANGE, AudioSettings
from core.i18n import tr
from core.multimedia_env import users_audio_backend
from core.multimedia_probe import AudioDeviceInfo

log = logging.getLogger(__name__)

TITLE = "Audio"
KEYWORDS = ("audio", "sound", "speaker", "headphones", "microphone", "input", "output",
            "volume", "gain", "device", "pipewire", "pulseaudio", "backend", "test tone")
BACKEND_LABELS = {"auto": "Automatic", "pipewire": "PipeWire", "pulseaudio": "PulseAudio"}

#: The test tone: a sine of TONE_HZ for TONE_SECONDS at TONE_RATE, int16 mono.
TONE_SECONDS = 1.0
TONE_HZ = 440.0
TONE_RATE = 48000
#: How long Test Microphone shows the level.
LEVEL_SECONDS = 5.0
#: How long Record and Play Back records; a microphone that delivers less
#: is stopped this long after its time.
RECORD_SECONDS = 3.0
_RECORD_GRACE_SECONDS = 1.0


def sine_tone(rate: int, seconds: float, freq: float, *, amplitude: float = 0.5,
              fade: float = 0.01) -> bytes:
    """*seconds* of a sine at *freq* Hz as int16 mono PCM at *rate*, faded
    in and out over *fade* seconds (no click at either end)."""
    if rate <= 0:
        raise ValueError(f"no sample rate: {rate!r}")
    count = max(0, int(rate * seconds))
    ramp = max(1, int(rate * fade))
    peak = 32767 * max(0.0, min(1.0, amplitude))
    samples = array.array("h", bytes(2 * count))
    for i in range(count):
        envelope = min(1.0, i / ramp, (count - 1 - i) / ramp)
        samples[i] = int(peak * envelope * math.sin(2 * math.pi * freq * i / rate))
    return samples.tobytes()


# -- the Qt seams (replaced by the tests) ------------------------------------------------------


def _qt_devices() -> tuple[tuple[AudioDeviceInfo, ...], tuple[AudioDeviceInfo, ...]]:
    """Qt's output and input devices - only after the probe answered ok."""
    from PyQt6.QtMultimedia import QMediaDevices

    def infos(devices, default) -> tuple[AudioDeviceInfo, ...]:
        default_id = AR.device_id(default) if not default.isNull() else ""
        return tuple(AudioDeviceInfo(AR.device_id(d), d.description(),
                                     AR.device_id(d) == default_id) for d in devices)

    return (infos(QMediaDevices.audioOutputs(), QMediaDevices.defaultAudioOutput()),
            infos(QMediaDevices.audioInputs(), QMediaDevices.defaultAudioInput()))


def _qt_watcher(parent):
    """A QMediaDevices whose signals report plugged and unplugged devices."""
    from PyQt6.QtMultimedia import QMediaDevices

    return QMediaDevices(parent)


def _make_player(device_id: str, volume: float):
    """ui.voice.QtPlayer on *device_id* ("" - the default) at *volume*."""
    from ui import voice as V

    return V.QtPlayer(sink_factory=lambda rate: V._qt_sink(rate, device_id=device_id,
                                                          volume=volume))


def _make_recorder(device_id: str, volume: float):
    """ui.voice.QtRecorder on *device_id* at *volume* (16 kHz mono int16)."""
    from ui import voice as V

    return V.QtRecorder(device_id=device_id, volume=volume)


def _count(n: int, one: str, many: str) -> str:
    return (tr(one) if n == 1 else tr(many)).format(n=n)


class AudioPage(QWidget):
    """The Audio page (see the module docstring)."""

    TITLE = TITLE

    def __init__(self, parent: QWidget | None = None, *, path: Path | None = None) -> None:
        super().__init__(parent)
        #: The store (None: core.audio_settings.settings_file()).
        self._path = path
        self._result: MPROBE.ProbeResult | None = None
        self._checking = False
        self._started = False
        self._watcher = None
        self._outputs: tuple[AudioDeviceInfo, ...] = ()
        self._inputs: tuple[AudioDeviceInfo, ...] = ()
        # The running test: its player and/or recorder.
        self._player = None
        self._recorder = None
        self._recording: bytearray | None = None
        self._test_failed = False
        self._test_timer = QTimer(self)
        self._test_timer.setSingleShot(True)
        self._test_timer.timeout.connect(self._test_time_up)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        backend_box = QGroupBox(tr("Audio Backend"))
        backend_form = QFormLayout(backend_box)
        self.backend_combo = QComboBox()
        for value, label in BACKEND_LABELS.items():
            self.backend_combo.addItem(tr(label), value)
        self.backend_combo.setToolTip(tr(
            "Automatic tries PipeWire where it runs, then PulseAudio (which PipeWire's "
            "pipewire-pulse serves too)."))
        backend_form.addRow(tr("Backend"), self.backend_combo)
        self.active_label = QLabel()
        backend_form.addRow(tr("This run"), self.active_label)
        self.backend_note = _muted(tr("A change of the backend takes effect when axross "
                                      "restarts."))
        backend_form.addRow("", self.backend_note)
        layout.addWidget(backend_box)

        output_box = QGroupBox(tr("Output"))
        output_form = QFormLayout(output_box)
        self.output_combo = QComboBox()
        output_form.addRow(tr("Device"), self.output_combo)
        self.output_slider, self.output_value = self._volume_row(output_form, tr("Volume"))
        self.output_slider.setToolTip(tr("Scales everything axross plays: the Media Player, "
                                         "the media preview and the voice"))
        self.tone_button = QPushButton(tr("Play Test Tone"))
        self.tone_button.setToolTip(tr("A 1 s tone on the chosen device at the chosen volume"))
        self.tone_button.clicked.connect(self.play_test_tone)
        output_form.addRow("", _left(self.tone_button))
        layout.addWidget(output_box)

        input_box = QGroupBox(tr("Input"))
        input_form = QFormLayout(input_box)
        self.input_combo = QComboBox()
        input_form.addRow(tr("Device"), self.input_combo)
        self.input_slider, self.input_value = self._volume_row(input_form, tr("Volume"))
        self.input_slider.setToolTip(tr("The microphone's gain"))
        self.mic_button = QPushButton(tr("Test Microphone"))
        self.mic_button.setToolTip(tr("Shows the microphone's level for a few seconds"))
        self.mic_button.clicked.connect(self.toggle_microphone_test)
        self.record_button = QPushButton(tr("Record 3 s and Play Back"))
        self.record_button.setToolTip(tr("Records 3 s from the chosen input and plays them on "
                                         "the chosen output"))
        self.record_button.clicked.connect(self.record_and_play_back)
        input_form.addRow("", _left(self.mic_button, self.record_button))
        self.level_bar = QProgressBar()
        self.level_bar.setRange(0, 100)
        self.level_bar.setValue(0)
        self.level_bar.setTextVisible(False)
        self.level_bar.setMaximumHeight(12)
        self.level_bar.setAccessibleName(tr("Microphone level"))
        input_form.addRow(tr("Level"), self.level_bar)
        layout.addWidget(input_box)

        self.test_label = QLabel()
        self.test_label.setWordWrap(True)
        self.test_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.test_label)

        status_box = QGroupBox(tr("Status"))
        status_layout = QVBoxLayout(status_box)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_layout.addWidget(self.status_label)
        self.check_button = QPushButton(tr("Check Audio Again"))
        self.check_button.setToolTip(tr("Try Qt Multimedia once more (in a separate process) "
                                        "and list the devices again"))
        self.check_button.clicked.connect(self.check_again)
        status_layout.addWidget(_left(self.check_button))
        layout.addWidget(status_box)
        layout.addStretch(1)

        self.load(AudioSettings.load(path))
        cached = MPROBE.cached()
        if cached is not None:
            self._result = cached
            if cached.ok:  # the child's lists; Qt's own once the page is shown
                self._outputs, self._inputs = cached.output_devices, cached.input_devices
        self._refill()
        self._show_state()

    # -- building ----------------------------------------------------------------------------

    @staticmethod
    def _volume_row(form: QFormLayout, label: str) -> tuple[QSlider, QLabel]:
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setRange(*VOLUME_RANGE)
        slider.setSingleStep(1)
        slider.setPageStep(10)
        value = QLabel()
        value.setMinimumWidth(48)
        slider.valueChanged.connect(lambda v: value.setText(f"{v} %"))
        row = QHBoxLayout()
        row.addWidget(slider, 1)
        row.addWidget(value)
        form.addRow(label, row)
        return slider, value

    # -- values ------------------------------------------------------------------------------

    def load(self, settings: AudioSettings) -> None:
        self.backend_combo.setCurrentIndex(max(0, self.backend_combo.findData(settings.backend)))
        self._refill(output=settings.output_device, input_=settings.input_device)
        self.output_slider.setValue(settings.output_volume)
        self.input_slider.setValue(settings.input_volume)
        self.output_value.setText(f"{settings.output_volume} %")
        self.input_value.setText(f"{settings.input_volume} %")
        self._baseline = self.values()

    def values(self) -> dict:
        return {
            "backend": self.backend_combo.currentData(),
            "output_device": self.output_combo.currentData() or "",
            "output_volume": self.output_slider.value(),
            "input_device": self.input_combo.currentData() or "",
            "input_volume": self.input_slider.value(),
        }

    def is_dirty(self) -> bool:
        return self.values() != self._baseline

    def problems(self) -> list[str]:
        return [tr("Invalid audio setting: {name}").format(name=name)
                for name, value in self.values().items() if not FIELDS[name](value)]

    def save(self, path: Path | None = None) -> bool:
        """Store the page's values (OSError on a disk error) and publish them
        to the running players; False when a value is invalid."""
        if self.problems():
            return False
        path = path if path is not None else self._path
        settings = AudioSettings.load(path)
        for name, value in self.values().items():
            settings.set(name, value)
        settings.save(path)
        self._baseline = self.values()
        AR.publish(settings)
        return True

    # -- the device lists --------------------------------------------------------------------

    def _refill(self, *, output: str | None = None, input_: str | None = None) -> None:
        """Fill both lists, keeping the choice (or selecting *output* /
        *input_*); a chosen id that is not listed stays, "(not connected)"."""
        _fill(self.output_combo, self._outputs,
              self.output_combo.currentData() if output is None else output)
        _fill(self.input_combo, self._inputs,
              self.input_combo.currentData() if input_ is None else input_)

    def _refresh_live(self) -> None:
        """After ok: Qt's own lists (hotplug, Check Audio Again). Nothing
        while the last check failed or runs."""
        if self._checking or self._result is None or not self._result.ok:
            return
        try:
            self._outputs, self._inputs = _qt_devices()
        except Exception:  # noqa: BLE001 - the child's lists are still right
            log.warning("the audio devices could not be listed", exc_info=True)
        self._refill()
        self._show_state()

    # -- the probe ---------------------------------------------------------------------------

    def showEvent(self, event) -> None:  # noqa: N802 - Qt
        super().showEvent(event)
        if not self._started:
            self._started = True
            self._check()

    def _check(self) -> None:
        self._checking = True
        self._show_state()
        MPROBE.probe_async(self._probe_answered, context=self)

    def check_again(self) -> None:
        """Check Audio Again: forget this run's answer and try once more."""
        if self._checking:
            return
        self._stop_test()
        MPROBE.reset()
        self._check()

    def _probe_answered(self, result: MPROBE.ProbeResult) -> None:
        self._checking = False
        self._result = result
        if result.ok:
            self._outputs, self._inputs = result.output_devices, result.input_devices
            if self._watcher is None:
                try:
                    self._watcher = _qt_watcher(self)
                    self._watcher.audioOutputsChanged.connect(self._refresh_live)
                    self._watcher.audioInputsChanged.connect(self._refresh_live)
                except Exception:  # noqa: BLE001 - no hotplug; Check Audio Again still lists
                    log.warning("audio hotplug is not watched", exc_info=True)
            self._refresh_live()
        else:
            self._outputs = self._inputs = ()
            self._refill()
        self._show_state()

    def _show_state(self) -> None:
        result, ok = self._result, self._result is not None and self._result.ok
        if self._checking:
            status = tr("Checking audio…")
        elif result is None:
            status = tr("Audio is checked when this page is shown.")
        elif ok:
            status = tr("Audio works: {backend}, {outputs}, {inputs}.").format(
                backend=MPROBE.BACKEND_NAMES.get(result.backend, result.backend),
                outputs=_count(len(self._outputs), "{n} output device", "{n} output devices"),
                inputs=_count(len(self._inputs), "{n} input device", "{n} input devices"))
        else:
            status = MPROBE.unavailable_text(result) + " " + tr(
                "The tests are off; the backend can still be chosen and saved.")
        self.status_label.setText(status)
        active = MPROBE.active_backend()
        if active is not None:
            self.active_label.setText(MPROBE.BACKEND_NAMES.get(active, active))
        elif self._checking or result is None:
            self.active_label.setText(tr("checking…"))
        else:
            self.active_label.setText(tr("none - audio is off"))
        note = tr("A change of the backend takes effect when axross restarts.")
        own = users_audio_backend()
        if own is not None:
            note += " " + tr("QT_AUDIO_BACKEND={value} is set in the environment and wins over "
                             "this choice.").format(value=own)
        self.backend_note.setText(note)
        self.check_button.setEnabled(not self._checking)
        for button in (self.tone_button, self.mic_button, self.record_button):
            button.setEnabled(ok and not self._checking)

    # -- the tests ---------------------------------------------------------------------------

    def _output_choice(self) -> tuple[str, float]:
        return self.output_combo.currentData() or "", self.output_slider.value() / 100.0

    def _input_choice(self) -> tuple[str, float]:
        return self.input_combo.currentData() or "", self.input_slider.value() / 100.0

    def play_test_tone(self) -> None:
        self._stop_test()
        self._play(sine_tone(TONE_RATE, TONE_SECONDS, TONE_HZ), TONE_RATE,
                   tr("Playing the test tone…"), lambda: tr("Test tone played."))

    def _play(self, pcm: bytes, rate: int, running: str, done) -> None:
        """*pcm* (int16 mono at *rate*) on the chosen output; *done()* gives
        the text once it was played."""
        device, volume = self._output_choice()
        self._test_failed = False
        try:
            player = _make_player(device, volume)
        except OSError as exc:
            self._say_failed(str(exc))
            return
        self._player = player
        player.failed.connect(self._say_failed)
        player.drained.connect(lambda: self._played(player, done))
        self.test_label.setText(running)
        player.enqueue(pcm, rate)

    def _played(self, player, done) -> None:
        if player is not self._player:
            return  # an older test's late signal
        self._player = None
        player.stop()
        if not self._test_failed:
            self.test_label.setText(done())

    def _say_failed(self, why: str) -> None:
        self._test_failed = True
        self.test_label.setText(tr("No sound: {error}").format(error=why))

    def toggle_microphone_test(self) -> None:
        if self._recorder is not None and self._recording is None:
            self._stop_test()
            return
        self._stop_test()
        if self._start_recorder(LEVEL_SECONDS, None):
            self.mic_button.setText(tr("Stop"))
            self.test_label.setText(tr("Speak into the microphone…"))

    def record_and_play_back(self) -> None:
        self._stop_test()
        if self._start_recorder(RECORD_SECONDS + _RECORD_GRACE_SECONDS, bytearray()):
            self.test_label.setText(tr("Recording {seconds:g} s…").format(seconds=RECORD_SECONDS))

    def _start_recorder(self, seconds: float, recording: bytearray | None) -> bool:
        device, volume = self._input_choice()
        try:
            recorder = _make_recorder(device, volume)
            recorder.data.connect(self._heard)
            recorder.start()
        except OSError as exc:
            self.test_label.setText(tr("The microphone does not work: {error}").format(error=exc))
            return False
        self._recorder, self._recording = recorder, recording
        self._test_timer.start(int(seconds * 1000))
        return True

    def _heard(self, pcm: bytes) -> None:
        if self._recorder is None:
            return
        self.level_bar.setValue(int(round(VA.level(pcm) * 100)))
        if self._recording is None:
            return
        self._recording += pcm
        if len(self._recording) >= int(RECORD_SECONDS * VA.RATE) * 2:
            self._recorded()

    def _test_time_up(self) -> None:
        if self._recording is not None:
            self._recorded()
        else:
            self._stop_recorder()
            self.test_label.setText(tr("Microphone test finished."))

    def _recorded(self) -> None:
        recording = bytes(self._recording or b"")[: int(RECORD_SECONDS * VA.RATE) * 2]
        self._stop_recorder()
        if not recording:
            self.test_label.setText(tr("Nothing was recorded: the microphone delivered no "
                                       "sound."))
            return
        seconds = VA.seconds(recording)
        self._play(recording, VA.RATE, tr("Playing back…"),
                   lambda: tr("Played back {seconds:.1f} s.").format(seconds=seconds))

    def _stop_recorder(self) -> None:
        self._test_timer.stop()
        recorder, self._recorder, self._recording = self._recorder, None, None
        if recorder is not None:
            try:
                recorder.stop()
            except Exception:  # noqa: BLE001 - stopping must not fail
                log.debug("the microphone test did not stop cleanly", exc_info=True)
        self.level_bar.setValue(0)
        self.mic_button.setText(tr("Test Microphone"))

    def _stop_test(self) -> None:
        self._stop_recorder()
        player, self._player = self._player, None
        if player is not None:
            player.stop()

    def shutdown(self) -> None:
        """The dialog closes: every test stops."""
        self._stop_test()


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "muted")
    return label


def _left(*widgets: QWidget) -> QWidget:
    holder = QWidget()
    row = QHBoxLayout(holder)
    row.setContentsMargins(0, 0, 0, 0)
    for widget in widgets:
        row.addWidget(widget)
    row.addStretch(1)
    return holder


def _fill(combo: QComboBox, devices: tuple[AudioDeviceInfo, ...], chosen: str | None) -> None:
    chosen = chosen or ""
    combo.blockSignals(True)
    combo.clear()
    combo.addItem(tr("System default"), "")
    for device in devices:
        text = device.description or device.device_id
        if device.is_default:
            text = tr("{name} (default)").format(name=text)
        combo.addItem(text, device.device_id)
        combo.setItemData(combo.count() - 1, device.device_id, Qt.ItemDataRole.ToolTipRole)
    index = combo.findData(chosen)
    if index < 0:
        combo.addItem(tr("{name} (not connected)").format(name=chosen), chosen)
        index = combo.count() - 1
    combo.setCurrentIndex(index)
    combo.blockSignals(False)


def settings_page(parent, window) -> AudioPage:
    return AudioPage(parent)


__all__ = ["KEYWORDS", "TITLE", "AudioPage", "settings_page", "sine_tone"]
