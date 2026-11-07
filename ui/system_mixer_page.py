"""The Audio Mixer's *System* page: the sound server's devices, programs and cards.

Built on core.system_mixer.SystemMixer (pactl; PipeWire or PulseAudio):

* **Outputs** and **Inputs** - each device with its volume (0-150 %), mute
  and *Default* (where new sound goes); monitors are left out.
* **Playback** and **Recording** - every program playing or recording, with
  its volume, mute and the device it uses (a choice moves it there);
  axross's own streams are marked.
* **Cards** - each sound card's profile (a Bluetooth headset: A2DP for
  music, the headset profile for its microphone).

Nothing is changed on screen ahead of the server: a change is sent and the
page shows what the server reports back (``changed``). Rows are updated in
place while their set stays the same; a slider being dragged is never
replaced under the mouse - the page catches up when it is let go.
"""

from __future__ import annotations

import os

from PyQt6 import sip
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import system_mixer as SM
from core.i18n import tr
from ui.plain_text import plain_tooltip

#: The volume sliders' top: the sound server allows amplification.
MAX_PERCENT = 150
#: The device's normal level, marked on each slider.
NORMAL_PERCENT = 100


def _narrow_combo(combo: QComboBox, chars: int = 12) -> QComboBox:
    """*combo* fills its place but gives way down to *chars* characters (the
    open list still shows each entry whole): device names are long."""
    combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
    combo.setMinimumContentsLength(chars)
    combo.setSizePolicy(QSizePolicy.Policy.Expanding, combo.sizePolicy().verticalPolicy())
    return combo


def _grid_rows(row: int) -> tuple[int, int]:
    """The grid rows of list row *row* (1, 2, ...): its head line and its
    slider line. Row 0 is the "(none)" label."""
    return 2 * row - 1, 2 * row


class _Row:
    """Two lines: the label (and a Default radio or a device combo, see
    :meth:`set_extra`), then the volume slider, its value and mute. In one
    line the page needed some 500 px and scrolled sideways in a narrow
    Audio Mixer."""

    def __init__(self, page: SystemMixerPage, grid: QGridLayout, row: int, key) -> None:
        self.key = key
        self.label = QLabel("")
        # A device's description (a Bluetooth device names itself) and a
        # program's name are not axross's text: never markup.
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.label.setMinimumWidth(80)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, MAX_PERCENT)
        self.slider.setMinimumWidth(100)
        # A mark at 100 %: the slider goes to 150 %, and without it the
        # device's normal level was nowhere to be seen (beyond it amplifies).
        self.slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.slider.setTickInterval(NORMAL_PERCENT)
        self.slider.setToolTip(tr("Volume - the mark is 100 %, the normal level; "
                                  "above it the sound is amplified"))
        self.value = QLabel("")
        self.value.setMinimumWidth(42)
        self.mute = QToolButton()
        self.mute.setCheckable(True)
        self.mute.setText(tr("Mute"))
        self.extra: QWidget | None = None
        self.head = QWidget()
        self._head = QHBoxLayout(self.head)
        self._head.setContentsMargins(0, 0, 0, 0)
        self._head.addWidget(self.label, 1)
        head_row, slider_row = _grid_rows(row)
        grid.addWidget(self.head, head_row, 0, 1, 3)
        for col, widget in enumerate((self.slider, self.value, self.mute)):
            grid.addWidget(widget, slider_row, col)
        self.slider.valueChanged.connect(lambda v: self.value.setText(f"{v} %"))
        self.slider.sliderReleased.connect(page._slider_released)
        self.widgets = [self.label, self.slider, self.value, self.mute, self.head]

    def set_extra(self, widget: QWidget) -> None:
        """*widget* (the Default radio, the device combo) after the label."""
        if isinstance(widget, QComboBox):
            _narrow_combo(widget)
            self._head.setStretch(0, 0)
            self._head.addWidget(widget, 1)
        else:
            self._head.addWidget(widget)
        self.extra = widget
        self.widgets.append(widget)

    def show_values(self, label: str, percent: int, muted: bool, has_volume: bool = True) -> None:
        if self.label.text() != label:
            self.label.setText(label)
            self.label.setToolTip(plain_tooltip(label))
        if not self.slider.isSliderDown():
            self.slider.blockSignals(True)
            self.slider.setValue(min(MAX_PERCENT, max(0, int(round(percent)))))
            self.slider.blockSignals(False)
            self.value.setText(f"{int(round(percent))} %")
        self.slider.setEnabled(has_volume and not muted)
        self.mute.blockSignals(True)
        self.mute.setChecked(muted)
        self.mute.blockSignals(False)

    def dispose(self) -> None:
        for widget in self.widgets:
            widget.setParent(None)
            widget.deleteLater()


class SystemMixerPage(QWidget):
    def __init__(self, mixer: SM.SystemMixer, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.mixer = mixer
        self._started = False
        self._dirty = False
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.status = QLabel("")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        top.addWidget(self.status, 1)
        self.retry_button = QPushButton(tr("Try Again"))
        self.retry_button.clicked.connect(self.mixer.refresh)
        top.addWidget(self.retry_button)
        layout.addLayout(top)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)  # pactl's errors name devices
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

        self.sections: dict[str, tuple[QGroupBox, QGridLayout]] = {}
        self.rows: dict[str, dict] = {}
        for key, title in (("outputs", tr("Outputs")), ("inputs", tr("Inputs")),
                           ("playback", tr("Playback")), ("recording", tr("Recording")),
                           ("cards", tr("Cards"))):
            box = QGroupBox(title)
            grid = QGridLayout(box)
            grid.setColumnStretch(0, 1)
            layout.addWidget(box)
            self.sections[key] = (box, grid)
            self.rows[key] = {}
        self.empty_labels = {key: QLabel(tr("(none)")) for key in self.sections}
        for key, label in self.empty_labels.items():
            self.sections[key][1].addWidget(label, 0, 0)
        self.default_groups = {"outputs": QButtonGroup(self), "inputs": QButtonGroup(self)}
        layout.addStretch(1)

        mixer.changed.connect(self._changed)
        mixer.state_changed.connect(lambda _s: self._show_state())
        mixer.error.connect(self.message.setText)
        self._show_state()

    # -- start, state --------------------------------------------------------------------------

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        if not self._started:  # the sound server is asked once the page is seen
            self._started = True
            self.mixer.start()

    def _show_state(self) -> None:
        state = self.mixer.state()
        ready = state == SM.STATE_READY
        text = {SM.STATE_PROBING: tr("Asking the sound server…"),
                SM.STATE_IDLE: tr("The sound server is asked when this page is shown.")}.get(
            state, "" if ready else self.mixer.reason())
        self.status.setText(text)
        self.status.setVisible(bool(text))
        self.retry_button.setVisible(state in (SM.STATE_UNAVAILABLE, SM.STATE_TOO_OLD))
        for box, _grid in self.sections.values():
            box.setVisible(ready)

    def shutdown(self) -> None:
        self.mixer.shutdown()

    # -- filling -------------------------------------------------------------------------------

    def _slider_released(self) -> None:
        if self._dirty:
            self._changed()

    def _changed(self) -> None:
        if sip.isdeleted(self):
            return
        if any(row.slider.isSliderDown() for rows in self.rows.values() for row in rows.values()
               if isinstance(row, _Row)):
            self._dirty = True  # not under the mouse: when it is let go
            return
        self._dirty = False
        mixer = self.mixer
        self._fill_devices("outputs", mixer.sinks())
        self._fill_devices("inputs", mixer.sources())
        self._fill_streams("playback", mixer.sink_inputs(), mixer.sinks())
        self._fill_streams("recording", mixer.source_outputs(), mixer.sources())
        self._fill_cards(mixer.cards())
        self._show_state()

    def _sync(self, section: str, keys: list) -> tuple[dict, bool]:
        """The rows of *section* for *keys*: kept when the set is the same,
        else made anew (True)."""
        rows = self.rows[section]
        if list(rows) == keys:
            return rows, False
        for row in rows.values():
            row.dispose()
        rows.clear()
        self.empty_labels[section].setVisible(not keys)
        return rows, True

    def _fill_devices(self, section: str, devices) -> None:
        grid = self.sections[section][1]
        rows, fresh = self._sync(section, [d.name for d in devices])
        group = self.default_groups[section]
        # An exclusive group ignores unchecking its checked radio: a default
        # the list leaves out (a monitor), or none, kept the old one checked.
        group.setExclusive(False)
        for index, device in enumerate(devices):
            row = rows.get(device.name)
            if fresh or row is None:
                row = _Row(self, grid, index + 1, device.name)
                radio = QRadioButton(tr("Default"))
                radio.setToolTip(tr("New sound goes here"))
                group.addButton(radio)
                row.set_extra(radio)
                name = device.name
                row.slider.valueChanged.connect(
                    lambda v, n=name, s=section: self._set_device_volume(s, n, v))
                row.mute.toggled.connect(
                    lambda on, n=name, s=section: self._device_op(s, n, "mute", on))
                radio.toggled.connect(
                    lambda on, n=name, s=section: on and self._device_op(s, n, "default", True))
                rows[device.name] = row
            row.show_values(device.label, device.volume_percent, device.muted)
            row.extra.blockSignals(True)
            row.extra.setChecked(device.is_default)
            row.extra.blockSignals(False)
        group.setExclusive(True)

    def _fill_streams(self, section: str, streams, devices) -> None:
        grid = self.sections[section][1]
        rows, fresh = self._sync(section, [s.index for s in streams])
        own = os.getpid()
        for index, stream in enumerate(streams):
            row = rows.get(stream.index)
            if fresh or row is None:
                row = _Row(self, grid, index + 1, stream.index)
                combo = QComboBox()
                combo.setToolTip(tr("The device it uses - choose one to move it there"))
                row.set_extra(combo)
                key = stream.index
                row.slider.valueChanged.connect(
                    lambda v, k=key, s=section: self._set_stream_volume(s, k, v))
                row.mute.toggled.connect(
                    lambda on, k=key, s=section: self._stream_op(s, k, "mute", on))
                combo.activated.connect(
                    lambda _i, k=key, s=section, c=combo: self._stream_op(
                        s, k, "move", c.currentData()))
                rows[stream.index] = row
            label = stream.label
            if stream.pid == own:
                label = tr("{name} (axross)").format(name=label)
            row.show_values(label, stream.volume_percent, stream.muted, stream.has_volume)
            combo = row.extra
            wanted = [(d.label, d.index) for d in devices]
            if stream.device_index not in {index for _text, index in wanted}:
                # It uses a device the list leaves out (a monitor it records)
                # or none known: shown as it is - falling back to the first
                # entry claimed another device, and choosing that moved it.
                wanted.insert(0, (self._unlisted_label(section, stream.device_index),
                                  stream.device_index))
            if [(combo.itemText(i), combo.itemData(i)) for i in range(combo.count())] != wanted:
                combo.blockSignals(True)
                combo.clear()
                for text, data in wanted:
                    combo.addItem(text, data)
                combo.blockSignals(False)
            combo.blockSignals(True)
            combo.setCurrentIndex(max(0, combo.findData(stream.device_index)))
            combo.blockSignals(False)

    def _fill_cards(self, cards) -> None:
        grid = self.sections["cards"][1]
        rows, fresh = self._sync("cards", [c.name for c in cards])
        for index, card in enumerate(cards):
            entry = rows.get(card.name)
            if fresh or entry is None:
                label = QLabel(card.label)
                label.setTextFormat(Qt.TextFormat.PlainText)
                combo = _narrow_combo(QComboBox())
                combo.setToolTip(tr("The card's profile: which outputs and inputs it offers"))
                # The card's name above its profile: a profile is long.
                head_row, combo_row = _grid_rows(index + 1)
                grid.addWidget(label, head_row, 0, 1, 3)
                grid.addWidget(combo, combo_row, 0, 1, 3)
                name = card.name
                combo.activated.connect(
                    lambda _i, n=name, c=combo: self._set_profile(n, c.currentData()))
                entry = _CardRow(label, combo)
                rows[card.name] = entry
            entry.label.setText(card.label)
            wanted = [((p.description or p.name) + ("" if p.available else
                                                   " " + tr("(not available)")), p.name)
                      for p in card.profiles]
            combo = entry.combo
            combo.blockSignals(True)
            if [(combo.itemText(i), combo.itemData(i)) for i in range(combo.count())] != wanted:
                combo.clear()
                for text, data in wanted:
                    combo.addItem(text, data)
            combo.setCurrentIndex(max(0, combo.findData(card.active_profile)))
            combo.blockSignals(False)

    def _unlisted_label(self, section: str, index: int) -> str:
        if index < 0:
            return tr("(unknown device)")
        kind = SM.SINK if section == "playback" else SM.SOURCE
        lookup = getattr(self.mixer, "device", None)
        device = lookup(kind, index) if callable(lookup) else None
        return device.label if device is not None else tr("(device #{n})").format(n=index)

    # -- changes ---------------------------------------------------------------------------------

    def _device(self, section: str, name: str):
        devices = self.mixer.sinks() if section == "outputs" else self.mixer.sources()
        return next((d for d in devices if d.name == name), None)

    def _stream(self, section: str, index: int):
        streams = self.mixer.sink_inputs() if section == "playback" else \
            self.mixer.source_outputs()
        return next((s for s in streams if s.index == index), None)

    def _set_device_volume(self, section: str, name: str, value: int) -> None:
        device = self._device(section, name)
        if device is not None:
            self.mixer.set_volume(device, value)

    def _set_stream_volume(self, section: str, index: int, value: int) -> None:
        stream = self._stream(section, index)
        if stream is not None:
            self.mixer.set_volume(stream, value)

    def _device_op(self, section: str, name: str, op: str, value) -> None:
        device = self._device(section, name)
        if device is None:
            return
        if op == "mute":
            self.mixer.set_mute(device, bool(value))
        elif op == "default":
            self.mixer.set_default(device)

    def _stream_op(self, section: str, index: int, op: str, value) -> None:
        stream = self._stream(section, index)
        if stream is None:
            return
        if op == "mute":
            self.mixer.set_mute(stream, bool(value))
        elif op == "move":
            if value == stream.device_index:
                return  # where it is already
            devices = self.mixer.sinks() if section == "playback" else self.mixer.sources()
            device = next((d for d in devices if d.index == value), None)
            if device is not None:
                self.mixer.move_stream(stream, device)

    def _set_profile(self, card_name: str, profile) -> None:
        card = next((c for c in self.mixer.cards() if c.name == card_name), None)
        if card is not None and profile:
            self.mixer.set_card_profile(card, profile)


class _CardRow:
    def __init__(self, label: QLabel, combo: QComboBox) -> None:
        self.label = label
        self.combo = combo

    def dispose(self) -> None:
        for widget in (self.label, self.combo):
            widget.setParent(None)
            widget.deleteLater()


__all__ = ["MAX_PERCENT", "NORMAL_PERCENT", "SystemMixerPage"]
