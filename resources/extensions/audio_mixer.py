"""The Audio Mixer: every sound setting of axross - and of the system - in one panel.

* **axross** - the master volume with its mute and output device, and a
  channel per sound source (Media Player, Agent voice, media preview) with
  its own volume, mute and output (*Same as the output* or a device of its
  own: the voice on the headset, the music on the speakers). Saved like
  Edit > Settings > Audio saves (core.audio_route.update); running players
  follow at once.
* **Equalizer** - axross's one equalizer (core.audio_eq): on/off, presets,
  ten bands. The Media Player's equalizer row shows the same setting; the
  Agent's voice goes through it too. Needs numpy to be heard.
* **System** - the sound server (PipeWire or PulseAudio, through pactl):
  output and input devices with volume, mute and the default, the programs
  playing and recording with their volume and device, and the cards'
  profiles (a Bluetooth headset's A2DP or headset mode). Only where pactl
  is there and answers; the tab says why not otherwise.

Nothing here creates a Qt Multimedia object before core.multimedia_probe
answered ok (its rule for every device list).
"""

from __future__ import annotations

import logging

from PyQt6 import sip
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import audio_eq as AEQ
from core import audio_route as AR
from core.i18n import tr

log = logging.getLogger(__name__)

EXTENSION = {
    "name": "Audio Mixer",
    "version": "1.0",
    "description": "Every sound setting in one panel: axross's master volume, a volume, mute "
    "and output per source (Media Player, Agent voice, media preview), the one equalizer "
    "for all of axross, and the system's sound server (PipeWire / PulseAudio): devices, "
    "programs, defaults and card profiles.",
    "author": "axross",
}

#: A change is saved this long after the last slider move (a drag is many).
SAVE_DELAY_MS = 250
#: The sources' labels (core.audio_route.SOURCE_LABELS) in the panel's order.
SOURCES = AR.SOURCES


def qt_outputs() -> list[tuple[str, str]]:
    """Qt's audio outputs as (id, description) - after the probe answered ok."""
    from core.audio_route import qt_audio_outputs

    return qt_audio_outputs()


def narrow_combo(combo: QComboBox, chars: int = 12) -> QComboBox:
    """*combo* fills its place but gives way down to *chars* characters (the
    open list still shows each entry whole): a device name is long."""
    combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
    combo.setMinimumContentsLength(chars)
    combo.setSizePolicy(QSizePolicy.Policy.Expanding, combo.sizePolicy().verticalPolicy())
    return combo


class _Channel:
    """Two lines in the grid: the label and the output combo, then the
    volume slider, its value and the mute button. In one line of five the
    panel needed 490 px and scrolled sideways in a narrow dock."""

    def __init__(self, grid: QGridLayout, row: int, label: str, *, same_text: str) -> None:
        self.label = QLabel(label)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 100)
        self.slider.setMinimumWidth(100)
        self.value = QLabel("100 %")
        self.value.setMinimumWidth(42)
        self.mute = QToolButton()
        self.mute.setCheckable(True)
        self.mute.setText(tr("Mute"))
        self.mute.setToolTip(tr("Mute"))
        self.output = narrow_combo(QComboBox())
        self.output.setToolTip(tr("Where this plays"))
        self.same_text = same_text
        head = QHBoxLayout()
        head.addWidget(self.label)
        head.addWidget(self.output, 1)
        top = 3 * row  # the head, the slider, a gap to the next channel
        grid.setRowMinimumHeight(top + 2, 6)
        grid.addLayout(head, top, 0, 1, 3)
        for col, widget in enumerate((self.slider, self.value, self.mute)):
            grid.addWidget(widget, top + 1, col)
        self.slider.valueChanged.connect(lambda v: self.value.setText(f"{v} %"))

    def set_values(self, volume: int, muted: bool) -> None:
        for widget, setter, value in ((self.slider, "setValue", volume),
                                      (self.mute, "setChecked", muted)):
            widget.blockSignals(True)
            getattr(widget, setter)(value)
            widget.blockSignals(False)
        self.value.setText(f"{volume} %")
        self.slider.setEnabled(not muted)

    def fill_outputs(self, devices: list[tuple[str, str]], chosen: str) -> None:
        combo = self.output
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(self.same_text, "")
        for ident, description in devices:
            combo.addItem(description or ident, ident)
        index = combo.findData(chosen)
        if index < 0 and chosen:  # a saved device that is not connected stays
            combo.addItem(tr("{device} (not connected)").format(device=chosen), chosen)
            index = combo.count() - 1
        combo.setCurrentIndex(max(0, index))
        combo.blockSignals(False)


class MixerPanel(QWidget):
    """The Audio Mixer panel (see the module docstring)."""

    def __init__(self, *, settings_path=None, device_lister=None, system_mixer=None,
                 open_audio_settings=None) -> None:
        super().__init__()
        self._path = settings_path
        #: Qt's outputs as (id, description); None: ask after the probe
        self._device_lister = device_lister
        self._devices: list[tuple[str, str]] = []
        self._open_audio_settings = open_audio_settings
        self._pending: dict = {}
        self._applying = False
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(SAVE_DELAY_MS)
        self._save_timer.timeout.connect(self.save_now)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.message = QLabel("")
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

        self._build_axross_tab()
        self._build_eq_tab()
        self.system_page = None
        if system_mixer is not None:
            self.add_system_tab(system_mixer)

        AR.notifier().changed.connect(self._saved_elsewhere)
        self.refresh()

    # -- the axross tab ------------------------------------------------------------------------

    def _build_axross_tab(self) -> None:
        page = QWidget()
        box = QVBoxLayout(page)
        grid = QGridLayout()
        grid.setColumnStretch(0, 1)
        self.master = _Channel(grid, 0, tr("Master"), same_text=tr("System default"))
        self.master.label.setStyleSheet("font-weight: bold")
        self.master.output.setToolTip(tr("axross's output device (Edit > Settings > Audio)"))
        self.channels: dict[str, _Channel] = {}
        for row, source in enumerate(SOURCES, start=1):
            self.channels[source] = _Channel(grid, row, tr(AR.SOURCE_LABELS[source]),
                                             same_text=tr("Same as the output"))
        # The output boxes start in one column.
        label_width = max(c.label.sizeHint().width()
                          for c in (self.master, *self.channels.values()))
        for channel in (self.master, *self.channels.values()):
            channel.label.setMinimumWidth(label_width)
        box.addLayout(grid)
        self.master.slider.valueChanged.connect(lambda v: self._change(output_volume=v))
        self.master.mute.toggled.connect(lambda on: self._change(output_muted=on))
        self.master.output.activated.connect(
            lambda _i: self._change(output_device=self.master.output.currentData() or ""))
        for source, channel in self.channels.items():
            channel.slider.valueChanged.connect(
                lambda v, s=source: self._change(**{f"{s}_volume": v}))
            channel.mute.toggled.connect(lambda on, s=source: self._change(**{f"{s}_muted": on}))
            channel.output.activated.connect(
                lambda _i, s=source, c=channel: self._change(
                    **{f"{s}_output": c.output.currentData() or ""}))
        row = QHBoxLayout()
        self.devices_button = QPushButton(tr("Find Devices"))
        self.devices_button.setToolTip(tr("List the audio devices again (a headset plugged in)."))
        self.devices_button.clicked.connect(self.find_devices)
        row.addWidget(self.devices_button)
        row.addStretch(1)
        self.settings_button = QPushButton(tr("Audio Settings…"))
        self.settings_button.setToolTip(tr("Backend, input device and the tests: Edit > "
                                           "Settings > Audio."))
        self.settings_button.clicked.connect(self._settings_clicked)
        self.settings_button.setVisible(callable(self._open_audio_settings))
        row.addWidget(self.settings_button)
        box.addLayout(row)
        box.addStretch(1)
        self.tabs.addTab(page, tr("axross"))

    # -- the equalizer tab ---------------------------------------------------------------------

    def _build_eq_tab(self) -> None:
        page = QWidget()
        box = QVBoxLayout(page)
        header = QHBoxLayout()
        self.eq_check = QCheckBox(tr("Equalizer"))
        self.eq_check.setToolTip(tr("axross's one equalizer: the Media Player and the Agent's "
                                    "voice go through it."))
        self.eq_check.toggled.connect(lambda on: self._change(eq_enabled=on))
        header.addWidget(self.eq_check)
        self.preset_combo = QComboBox()
        self.preset_combo.addItems([*AEQ.PRESETS, AEQ.CUSTOM])
        self.preset_combo.activated.connect(lambda _i: self._preset_chosen())
        header.addWidget(self.preset_combo, 1)
        self.flat_button = QPushButton(tr("Flat"))
        self.flat_button.setToolTip(tr("Every band to 0 dB"))
        self.flat_button.clicked.connect(lambda: self._set_preset("Flat"))
        header.addWidget(self.flat_button)
        box.addLayout(header)
        grid = QGridLayout()
        self.bands: list[QSlider] = []
        self.band_values: list[QLabel] = []
        for i, freq in enumerate(AEQ.BANDS):
            value = QLabel("0")
            value.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            slider = QSlider(Qt.Orientation.Vertical)
            slider.setRange(-int(AEQ.MAX_GAIN_DB), int(AEQ.MAX_GAIN_DB))
            slider.setMinimumHeight(110)
            slider.setToolTip(tr("{freq} Hz, dB").format(freq=freq))
            slider.valueChanged.connect(lambda v, k=i: self._band_moved(k, v))
            label = QLabel(f"{freq // 1000}k" if freq >= 1000 else str(freq))
            label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            grid.addWidget(value, 0, i)
            grid.addWidget(slider, 1, i, Qt.AlignmentFlag.AlignHCenter)
            grid.addWidget(label, 2, i)
            self.bands.append(slider)
            self.band_values.append(value)
        box.addLayout(grid, 1)
        self.eq_note = QLabel(tr("The equalizer needs numpy (pip install numpy) to be heard; "
                                 "its setting is kept all the same."))
        self.eq_note.setWordWrap(True)
        self.eq_note.setVisible(not AEQ.available())
        box.addWidget(self.eq_note)
        self.tabs.addTab(page, tr("Equalizer"))

    def gains(self) -> list[float]:
        return [float(s.value()) for s in self.bands]

    def _band_moved(self, index: int, value: int) -> None:
        self.band_values[index].setText(f"{value:+d}" if value else "0")
        if self._applying:
            return
        name = AEQ.preset_of(self.gains())
        self.preset_combo.setCurrentText(name)
        self._change(eq_gains=self.gains(), eq_preset=name)

    def _preset_chosen(self) -> None:
        name = self.preset_combo.currentText()
        if name in AEQ.PRESETS:
            self._set_preset(name)

    def _set_preset(self, name: str) -> None:
        gains = AEQ.PRESETS[name]
        self._applying = True
        try:
            for slider, gain in zip(self.bands, gains):
                slider.setValue(round(gain))
            self.preset_combo.setCurrentText(name)
        finally:
            self._applying = False
        self._change(eq_gains=list(gains), eq_preset=name)

    # -- the system tab --------------------------------------------------------------------------

    def add_system_tab(self, mixer) -> None:
        """The sound server's page (ui.system_mixer_page) for *mixer*
        (core.system_mixer.SystemMixer)."""
        from ui.system_mixer_page import SystemMixerPage

        self.system_page = SystemMixerPage(mixer)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.system_page)
        self.tabs.addTab(scroll, tr("System"))

    # -- saving and showing --------------------------------------------------------------------

    def _change(self, **changes) -> None:
        if self._applying:
            return
        self._pending.update(changes)
        for name in ("output_muted", *(f"{s}_muted" for s in SOURCES)):
            if name in changes:
                self.refresh_enabled()
        self._save_timer.start()

    def save_now(self) -> None:
        """Save what changed (the timer does it after the last move)."""
        self._save_timer.stop()
        pending, self._pending = self._pending, {}
        if not pending:
            return
        try:
            AR.update(self._path, **pending)
        except (OSError, ValueError) as exc:
            self.message.setText(tr("Could not save the audio settings: {error}").format(
                error=exc))
            self.refresh()
            return
        self.message.setText("")

    def _saved_elsewhere(self, _saved) -> None:
        """The Audio page, the Media Player or this panel saved: shown here
        (what the user is changing right now stays)."""
        if sip.isdeleted(self) or self._pending:
            return
        self.refresh()

    def refresh(self) -> None:
        saved = AR.settings()
        self._applying = True
        try:
            self.master.set_values(saved.output_volume, saved.output_muted)
            self.master.fill_outputs(self._devices, saved.output_device)
            for source, channel in self.channels.items():
                channel.set_values(getattr(saved, f"{source}_volume"),
                                   getattr(saved, f"{source}_muted"))
                channel.fill_outputs(self._devices, getattr(saved, f"{source}_output"))
            self.eq_check.setChecked(saved.eq_enabled)
            for slider, gain in zip(self.bands, saved.eq_gains):
                slider.setValue(round(gain))
            preset = saved.eq_preset if self.preset_combo.findText(saved.eq_preset) >= 0 \
                else AEQ.preset_of(saved.eq_gains)
            self.preset_combo.setCurrentText(preset)
        finally:
            self._applying = False
        self.refresh_enabled()

    def refresh_enabled(self) -> None:
        master_muted = self.master.mute.isChecked()
        self.master.slider.setEnabled(not master_muted)
        for channel in self.channels.values():
            channel.slider.setEnabled(not master_muted and not channel.mute.isChecked())
            channel.mute.setEnabled(not master_muted)
        for slider in self.bands:
            slider.setEnabled(self.eq_check.isChecked())

    # -- devices -----------------------------------------------------------------------------------

    def find_devices(self) -> None:
        """The output lists from Qt's devices - after the probe answered ok."""
        if self._device_lister is not None:
            self._took_devices(self._device_lister())
            return
        from core import multimedia_probe as MPROBE

        def probed(result) -> None:
            if sip.isdeleted(self):
                return
            if not result.ok:
                self.message.setText(MPROBE.unavailable_text(result))
                return
            try:
                self._took_devices(qt_outputs())
            except Exception as exc:  # noqa: BLE001 - the panel says it
                log.warning("Audio Mixer: the devices could not be listed", exc_info=True)
                self.message.setText(str(exc))

        MPROBE.probe_async(probed, context=self)

    def _took_devices(self, devices) -> None:
        self._devices = [(str(i), str(d)) for i, d in devices]
        self.refresh()

    def _settings_clicked(self) -> None:
        self.save_now()
        if callable(self._open_audio_settings):
            self._open_audio_settings()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        if not self._devices:
            self.find_devices()

    def shutdown(self) -> None:
        self.save_now()
        try:
            AR.notifier().changed.disconnect(self._saved_elsewhere)
        except (TypeError, RuntimeError):
            pass
        if self.system_page is not None:
            self.system_page.shutdown()


def make_system_mixer():
    """The sound server's mixer, or None where there is none (a seam)."""
    try:
        from core.system_mixer import SystemMixer
    except ImportError:  # pragma: no cover - axross ships it
        return None
    return SystemMixer()


_PANELS: list[MixerPanel] = []


def activate(api):
    window = getattr(api, "window", None)
    open_settings = getattr(window, "open_settings", None)
    panel = MixerPanel(system_mixer=make_system_mixer(),
                       open_audio_settings=(lambda: open_settings("audio"))
                       if callable(open_settings) else None)
    _PANELS.append(panel)
    api.add_dock(tr("Audio Mixer"), panel, icon="mixer")


def deactivate(api):
    while _PANELS:
        panel = _PANELS.pop()
        try:
            panel.shutdown()
        except RuntimeError:  # pragma: no cover - the widget is gone already
            pass
