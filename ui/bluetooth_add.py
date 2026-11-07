"""Add Device: a new Bluetooth device in one go.

Opened from the Bluetooth panel (*Add Device…*). Adding a device took five
buttons in the right order - Scan, Pair, Trust, Connect, and for a speaker
or headset *Use as Audio Output*. This dialog does them in a row:

1. The adapter is switched on when it is off (the user is asked first:
   *Switch On*), and a scan runs while the dialog is open (both radios,
   every advertisement) - the dialog stops the scan it started.
2. The devices nearby that are not paired yet show as they are found,
   named ones first, the strongest signal on top (*Show unnamed* adds the
   nameless beacons).
3. *Add* pairs the chosen device (a question it asks - a passkey, a PIN -
   comes from the panel's pairing dialog), trusts it so it may reconnect by
   itself, connects it and, for a speaker or headset with *Use as audio
   output* ticked, makes it axross's output. Each step shows as it runs
   and ends with a tick or with what went wrong; *Cancel* stops the running
   step (a pairing, a connection, the wait for the audio output).

It drives core.bluetooth.BluezClient through its signals - nothing waits.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from core import bluetooth as BT
from core.i18n import tr
from ui.plain_text import plain_tooltip, set_plain
from ui.icon_provider import set_window_icon

#: The steps of Add, in order: (key, label).
STEPS = (("pair", "Pair"), ("trust", "Trust"), ("connect", "Connect"),
         ("output", "Use as audio output"))
_MARKS = {"wait": "○", "run": "◔", "done": "✓", "skip": "–", "fail": "✗"}


def signal_bars(rssi: int | None) -> str:
    """Four bars for a signal: ▂▄▆█ by strength, dim ones as ·."""
    if rssi is None:
        return ""
    level = 4 if rssi >= -55 else 3 if rssi >= -67 else 2 if rssi >= -78 else 1
    return "".join("▂▄▆█"[:level]) + "·" * (4 - level)


class AddDeviceDialog(QDialog):
    def __init__(self, panel, parent=None) -> None:
        super().__init__(parent or panel)
        set_window_icon(self, "bluetooth")
        self.panel = panel
        self.client: BT.BluezClient = panel.client
        self.setWindowTitle(tr("Add Bluetooth Device"))
        self.resize(560, 480)
        #: the adapter this dialog scans on, and whether it started the scan
        self.adapter_path: str | None = None
        self._started_scan = False
        self._asked_power = False
        #: the device being added and the state of each step
        self.target: str | None = None
        self.steps: dict[str, str] = {}
        self.finished_ok: bool | None = None
        self._left = False  # see _leave

        layout = QVBoxLayout(self)
        self.intro = QLabel(tr("Put the device into pairing mode (often: hold its power or "
                               "Bluetooth button until a light blinks), then choose it below."))
        self.intro.setWordWrap(True)
        layout.addWidget(self.intro)
        power_row = QHBoxLayout()
        self.power_label = set_plain(QLabel(""))  # BlueZ's error
        self.power_label.setWordWrap(True)
        power_row.addWidget(self.power_label, 1)
        self.power_button = QPushButton(tr("Switch On"))
        self.power_button.clicked.connect(self._power_on)
        power_row.addWidget(self.power_button)
        layout.addLayout(power_row)
        self.scan_label = set_plain(QLabel(""))  # BlueZ's error
        layout.addWidget(self.scan_label)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.itemSelectionChanged.connect(self._update_buttons)
        self.list.itemDoubleClicked.connect(lambda _i: self.add_selected())
        layout.addWidget(self.list, 1)
        options = QHBoxLayout()
        self.unnamed_check = QCheckBox(tr("Show unnamed"))
        self.unnamed_check.setToolTip(tr("Also list devices that do not tell their name "
                                         "(beacons, trackers)."))
        self.unnamed_check.toggled.connect(lambda _on: self._fill())
        options.addWidget(self.unnamed_check)
        self.output_check = QCheckBox(tr("Use as audio output"))
        self.output_check.setChecked(True)
        self.output_check.setToolTip(tr("For a speaker or headset: make it axross's audio "
                                        "output once it is connected."))
        options.addWidget(self.output_check)
        options.addStretch(1)
        layout.addLayout(options)
        self.progress = QLabel("")
        self.progress.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.progress)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)  # names the device
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.add_button = QPushButton(tr("Add"))
        self.add_button.setDefault(True)
        self.add_button.clicked.connect(self.add_selected)
        self.close_button = QPushButton(tr("Close"))
        self.close_button.clicked.connect(self._close_clicked)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.close_button)
        layout.addLayout(buttons)
        from ui.close_corner import add_close_corner

        add_close_corner(self)  # the [x] closes as Close does (closeEvent cancels a step)

        self.client.adapters_changed.connect(self._adapters_changed)
        self.client.devices_changed.connect(self._fill)
        self.client.device_updated.connect(self._device_updated)
        self.client.operation_finished.connect(self._finished)
        panel.output_result.connect(self._output_result)
        self._adapters_changed()

    # -- the adapter and the scan --------------------------------------------------------------

    def _adapter(self) -> BT.Adapter | None:
        adapter = self.panel.current_adapter()
        self.adapter_path = adapter.path if adapter is not None else None
        return adapter

    def _adapters_changed(self) -> None:
        adapter = self._adapter()
        if adapter is None:
            self.power_label.setText(tr("No Bluetooth adapter."))
            self.power_button.hide()
            self._update_buttons()
            return
        if not adapter.powered:
            self.power_label.setText(tr("The Bluetooth adapter is off."))
            self.power_button.setVisible(True)
            self.power_button.setEnabled(self.client.busy(adapter.path) is None)
            self.scan_label.setText("")
        else:
            self.power_label.setText("")
            self.power_button.hide()
            if not self.client.scanning(adapter.path) and self.client.busy(adapter.path) is None \
                    and self.isVisible() and self.finished_ok is None:
                self._start_scan()
            self.scan_label.setText(tr("Looking for devices nearby…") if adapter.discovering
                                    else "")
        self._update_buttons()

    def _power_on(self) -> None:
        if self.adapter_path:
            self.client.set_powered(self.adapter_path, True)
            self.power_button.setEnabled(False)

    def _start_scan(self) -> None:
        if self.adapter_path is None:
            return
        self._started_scan = True
        self.client.start_discovery(self.adapter_path)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self._adapters_changed()
        self._fill()

    # -- the list ------------------------------------------------------------------------------

    def candidates(self) -> list[BT.Device]:
        """The devices one would add: not paired, named unless asked."""
        adapter = self._adapter()
        devices = self.client.devices(adapter.path) if adapter is not None else []
        shown = [d for d in devices if not d.paired
                 and (self.unnamed_check.isChecked() or d.named)]
        return sorted(shown, key=lambda d: (not d.named, d.rssi is None, -(d.rssi or -999),
                                            d.display_name.lower()))

    def _fill(self) -> None:
        selected = self.selected_path()
        self.list.blockSignals(True)
        self.list.clear()
        for device in self.candidates():
            text = f"{device.display_name}    {tr(device.kind)}"
            bars = signal_bars(device.rssi)
            if bars:
                text += f"    {bars}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, device.path)
            item.setToolTip(plain_tooltip(
                f"{device.address}\n{', '.join(device.services)}".strip()))
            self.list.addItem(item)
            if device.path == selected:
                item.setSelected(True)
        self.list.blockSignals(False)
        # Before any Add has ended only: afterwards the message is its outcome
        # ("… is added", "… could not be added: why", "Canceled."), and the
        # added device leaving the list (it is paired now) must not wipe it.
        if self.finished_ok is None and not self._adding():
            self.message.setText(tr("No new device found yet.") if self.list.count() == 0
                                 else "")
        self._update_buttons()

    def _adding(self) -> bool:
        """An Add is under way (not before one, not after it ended)."""
        return self.target is not None and self.finished_ok is None

    def _device_updated(self, path: str) -> None:
        if not self._adding() and any(
                self.list.item(i).data(Qt.ItemDataRole.UserRole) == path
                for i in range(self.list.count())):
            # a new signal: the text only; rows do not jump while one is chosen
            device = self.client.device(path)
            for i in range(self.list.count()):
                item = self.list.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == path and device is not None:
                    text = f"{device.display_name}    {tr(device.kind)}"
                    bars = signal_bars(device.rssi)
                    item.setText(text + (f"    {bars}" if bars else ""))
        elif path == self.target:
            self._update_buttons()

    def selected_path(self) -> str | None:
        items = self.list.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def _update_buttons(self) -> None:
        adapter = self.panel.current_adapter()
        running = self.target is not None and self.finished_ok is None
        self.add_button.setEnabled(not running and self.selected_path() is not None
                                   and bool(adapter and adapter.powered))
        self.close_button.setText(tr("Cancel") if running else tr("Close"))
        self.list.setEnabled(not running)

    # -- adding --------------------------------------------------------------------------------

    def add_selected(self) -> None:
        path = self.selected_path()
        if path is None or (self.target is not None and self.finished_ok is None):
            return
        device = self.client.device(path)
        if device is None:
            return
        self.target = path
        self.finished_ok = None
        audio = BT.is_audio_output(device)
        self.steps = {key: "wait" for key, _label in STEPS}
        if not (audio and self.output_check.isChecked()):
            self.steps["output"] = "skip"
        self.message.setText(tr("Adding {device}…").format(device=device.display_name))
        self._show_steps()
        self._update_buttons()
        if device.paired:
            self._step_done("pair")
        else:
            self._run("pair")

    def _run(self, step: str) -> None:
        self.steps[step] = "run"
        self._show_steps()
        path = self.target
        if step == "pair":
            self.client.pair(path)
        elif step == "trust":
            device = self.client.device(path)
            if device is not None and device.trusted:
                self._step_done("trust")
                return
            self.client.set_trusted(path, True)
        elif step == "connect":
            device = self.client.device(path)
            if device is not None and device.connected:
                self._step_done("connect")
                return
            self.client.connect_device(path)
        elif step == "output":
            self.panel.use_as_output(path)

    def _next(self, after: str) -> None:
        order = [key for key, _label in STEPS]
        for step in order[order.index(after) + 1:]:
            if self.steps.get(step) == "wait":
                self._run(step)
                return
        self._done(True)

    def _step_done(self, step: str) -> None:
        self.steps[step] = "done"
        self._show_steps()
        self._next(step)

    def _finished(self, path: str, op: str, error: str) -> None:
        if path == self.adapter_path and op == "power":
            if error:
                # Refused (rfkill, a failure): Powered never changes, so
                # nothing else enables the button again - say why here.
                self.power_label.setText(error)
                self.power_button.setEnabled(True)
            return  # on success the adapter's PropertiesChanged starts the scan
        if path == self.adapter_path and op == "scan" and error:
            self.scan_label.setText(error)
            return
        if path != self.target or self.finished_ok is not None:
            return
        step = {"pair": "pair", "trust": "trust", "connect": "connect"}.get(op)
        if step is None or self.steps.get(step) != "run":
            if op == "cancel-pairing" and not error:
                self._fail("pair", tr("Pairing was canceled."))
            return
        if error:
            if step == "pair" and "already" in error.lower():
                self._step_done("pair")
                return
            self._fail(step, error)
            return
        self._step_done(step)

    def _output_result(self, path: str, ok: bool, text: str) -> None:
        if path != self.target or self.steps.get("output") != "run":
            return
        if ok:
            self._step_done("output")
        else:
            self._fail("output", text)

    def _fail(self, step: str, why: str) -> None:
        self.steps[step] = "fail"
        self._show_steps()
        device = self.client.device(self.target) if self.target else None
        name = device.display_name if device is not None else ""
        self.message.setText(tr("{device} could not be added: {why}").format(
            device=name, why=why))
        self._done(False)

    def _done(self, ok: bool) -> None:
        self.finished_ok = ok
        if ok:
            device = self.client.device(self.target)
            name = device.display_name if device is not None else ""
            self.message.setText(tr("{device} is added and connected.").format(device=name))
            self._stop_scan()
        self._update_buttons()

    def _show_steps(self) -> None:
        self.progress.setText("    ".join(
            f"{_MARKS[self.steps.get(key, 'wait')]} {tr(label)}" for key, label in STEPS
            if self.steps.get(key) != "skip"))

    # -- leaving -------------------------------------------------------------------------------

    def _cancel_running_step(self) -> None:
        """Stop what the running step started, so nothing of a canceled
        Add happens after Cancel: a pairing is canceled, a connection that
        is still being made is dropped when it comes, and the wait for the
        audio output ends without switching axross's output."""
        if self.target is None or self.finished_ok is not None:
            return
        if self.steps.get("pair") == "run":
            self.client.cancel_pairing(self.target)
        elif self.steps.get("connect") == "run":
            # the client drops it: this dialog may be closed before it comes
            self.client.drop_when_connected(self.target)
        elif self.steps.get("output") == "run":
            self.panel.cancel_output(self.target)

    def _close_clicked(self) -> None:
        if self.target is not None and self.finished_ok is None:
            self._cancel_running_step()
            self.finished_ok = False
            self.message.setText(tr("Canceled."))
            self._update_buttons()
            return
        self.close()

    def _stop_scan(self) -> None:
        adapter = self.client.adapter(self.adapter_path) if self.adapter_path else None
        if self._started_scan and adapter is not None and self.client.scanning(adapter.path):
            self.client.stop_discovery(self.adapter_path)
        self._started_scan = False

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._leave()
        super().closeEvent(event)

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        # reject() (Escape, the corner's [x]) ends here without a closeEvent
        self._leave()
        super().done(result)

    def _leave(self) -> None:
        """What leaving the dialog undoes, once however it is left: the
        running step is canceled, the scan it started stops, and the
        client's signals no longer reach it."""
        if self._left:
            return
        self._left = True
        self._cancel_running_step()
        self._stop_scan()
        for signal, slot in ((self.client.adapters_changed, self._adapters_changed),
                             (self.client.devices_changed, self._fill),
                             (self.client.device_updated, self._device_updated),
                             (self.client.operation_finished, self._finished),
                             (self.panel.output_result, self._output_result)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass


__all__ = ["AddDeviceDialog", "STEPS", "signal_bars"]
