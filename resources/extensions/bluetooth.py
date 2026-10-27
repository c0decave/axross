"""A panel to connect Bluetooth devices - speakers and headphones first.

BlueZ (the Linux Bluetooth service) over the system D-Bus, through
core.bluetooth: the adapter with its power switch, a scan with the
devices it finds (name, address, kind, signal while scanning, battery,
state), and Pair, Trust, Connect, Disconnect and Remove. A pairing that
asks something (confirm a passkey, type a PIN) asks the user in a dialog;
nothing is accepted without an answer. *Use as Audio Output* connects a
speaker or headset if needed, waits for its output to appear in the sound
server and makes it axross's output (Edit > Settings > Audio), which the
Media Player and the other players follow.
"""

from __future__ import annotations

from PyQt6 import sip
from PyQt6.QtCore import QRegularExpression, Qt, QTimer
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import bluetooth as BT
from core.i18n import tr

EXTENSION = {
    "name": "Bluetooth",
    "version": "1.0",
    "description": "A panel to scan for, pair, connect and remove Bluetooth devices (BlueZ); "
    "a speaker or headset becomes axross's audio output with one click.",
    "author": "axross",
}

COLUMNS = ("Name", "Address", "Type", "Signal", "Battery", "State")
COL_NAME, COL_ADDRESS, COL_TYPE, COL_SIGNAL, COL_BATTERY, COL_STATE = range(len(COLUMNS))
#: A scan runs at most this long (it keeps the radio busy); Scan starts a new one.
SCAN_LIMIT_MS = 120_000
#: Seconds to wait for a connected headset's output to appear.
SINK_TIMEOUT = 20.0

_RUNNING = {
    "pair": "Pairing…",
    "connect": "Connecting…",
    "disconnect": "Disconnecting…",
    "remove": "Removing…",
    "trust": "Saving…",
}


def make_client() -> BT.BluezClient:
    """The client of the system bus (a seam for the tests)."""
    return BT.BluezClient()


class AgentDialog(QDialog):
    """One question of a pairing: confirm, type a PIN or passkey, allow,
    or (display-*) just show a code. Closing it is a no."""

    def __init__(self, request: BT.AgentRequest, parent: QWidget) -> None:
        super().__init__(parent)
        self.request = request
        #: BlueZ took the question back: closing sends no answer.
        self.cancelled = False
        self.setWindowTitle(tr("Bluetooth Pairing"))
        layout = QVBoxLayout(self)
        name = request.device_name
        passkey = f"{request.passkey or 0:06d}"
        texts = {
            "confirm": tr("Does {device} show the passkey {passkey}? Confirm only if it does.")
            .format(device=name, passkey=passkey),
            "pin": tr("Enter the PIN for {device} - the one it shows, or the one in its manual "
                      "(often 0000 or 1234):").format(device=name),
            "passkey": tr("Enter the 6-digit passkey {device} shows:").format(device=name),
            "display-passkey": tr("Type {passkey} on {device} and press Enter there.")
            .format(device=name, passkey=passkey),
            "display-pin": tr("Enter the PIN {pin} on {device}.").format(device=name,
                                                                        pin=request.pin),
            "authorize": tr("Allow pairing with {device}?").format(device=name),
            "authorize-service": tr("Allow {device} to use the service {uuid}?")
            .format(device=name, uuid=request.uuid),
        }
        self.text_label = QLabel(texts.get(request.kind, request.kind))
        self.text_label.setWordWrap(True)
        layout.addWidget(self.text_label)
        self.edit: QLineEdit | None = None
        if request.kind in ("pin", "passkey"):
            self.edit = QLineEdit()
            if request.kind == "pin":
                self.edit.setMaxLength(16)
            else:
                self.edit.setValidator(QRegularExpressionValidator(
                    QRegularExpression(r"^\d{1,6}$"), self.edit))
            self.edit.textChanged.connect(self._update)
            layout.addWidget(self.edit)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        accept_text = {"confirm": tr("Confirm"), "pin": tr("Pair"), "passkey": tr("Pair"),
                       "authorize": tr("Allow"), "authorize-service": tr("Allow")}
        self.accept_button = QPushButton(accept_text.get(request.kind, tr("OK")))
        self.reject_button = QPushButton(tr("Reject") if request.needs_answer else tr("Close"))
        self.accept_button.clicked.connect(self.accept)
        self.reject_button.clicked.connect(self.reject)
        self.accept_button.setVisible(request.needs_answer)
        self.accept_button.setDefault(request.needs_answer)
        buttons.addWidget(self.accept_button)
        buttons.addWidget(self.reject_button)
        layout.addLayout(buttons)
        try:
            from ui.close_corner import add_close_corner

            add_close_corner(self)
        except ImportError:  # pragma: no cover - axross ships ui
            pass
        self._update()

    def value(self):
        if self.edit is None:
            return None
        text = self.edit.text().strip()
        return int(text) if self.request.kind == "passkey" and text.isdigit() else text

    def _update(self) -> None:
        if self.edit is not None:
            text = self.edit.text().strip()
            self.accept_button.setEnabled(bool(text) and (self.request.kind != "passkey"
                                                          or text.isdigit()))

    def accept(self) -> None:
        if self.accept_button.isVisible() and not self.accept_button.isEnabled():
            return  # Enter in an empty field
        super().accept()


class BluetoothPanel(QWidget):
    """The adapter row, the device table, the buttons and a message line."""

    def __init__(self, client: BT.BluezClient, *, sink_lister=None,
                 sink_timeout: float = SINK_TIMEOUT, open_audio_settings=None,
                 audio_settings_path=None) -> None:
        super().__init__()
        self.client = client
        self._sink_lister = sink_lister
        self._sink_timeout = sink_timeout
        self._open_audio_settings = open_audio_settings
        self._audio_settings_path = audio_settings_path
        self._dialogs: list[QDialog] = []
        self._agent_dialogs: dict[int, AgentDialog] = {}
        self._waiter: BT.SinkWaiter | None = None
        #: device path whose output to use once its Connect worked
        self._output_after_connect: str | None = None
        #: device paths whose pairing the user canceled or rejected
        self._quiet_failures: set[str] = set()
        #: device path -> the name last shown (a removed device has none at BlueZ)
        self._names: dict[str, str] = {}
        self._scan_timer = QTimer(self)
        self._scan_timer.setSingleShot(True)
        self._scan_timer.timeout.connect(self._scan_time_up)

        layout = QVBoxLayout(self)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.controls = QWidget()
        controls = QVBoxLayout(self.controls)
        controls.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        top.addWidget(QLabel(tr("Adapter:")))
        self.adapter_combo = QComboBox()
        self.adapter_combo.currentIndexChanged.connect(lambda _i: self._refresh_all())
        top.addWidget(self.adapter_combo, 1)
        self.power_check = QCheckBox(tr("Powered"))
        self.power_check.clicked.connect(self._power_clicked)
        top.addWidget(self.power_check)
        self.scan_button = QPushButton(tr("Scan"))
        self.scan_button.clicked.connect(self._scan_clicked)
        top.addWidget(self.scan_button)
        controls.addLayout(top)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        controls.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.pair_button = QPushButton(tr("Pair"))
        self.pair_button.clicked.connect(self._pair_clicked)
        self.trust_button = QPushButton(tr("Trust"))
        self.trust_button.clicked.connect(self._trust_clicked)
        self.connect_button = QPushButton(tr("Connect"))
        self.connect_button.clicked.connect(lambda: self._device_op("connect"))
        self.disconnect_button = QPushButton(tr("Disconnect"))
        self.disconnect_button.clicked.connect(lambda: self._device_op("disconnect"))
        self.remove_button = QPushButton(tr("Remove"))
        self.remove_button.clicked.connect(self._remove_clicked)
        self.output_button = QPushButton(tr("Use as Audio Output"))
        self.output_button.setToolTip(tr("Connect the speaker or headset and make it axross's "
                                         "audio output (Edit > Settings > Audio)."))
        self.output_button.clicked.connect(self._output_clicked)
        for button in (self.pair_button, self.trust_button, self.connect_button,
                       self.disconnect_button, self.remove_button, self.output_button):
            row.addWidget(button)
        row.addStretch(1)
        controls.addLayout(row)
        layout.addWidget(self.controls, 1)

        self.message = QLabel("")
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        layout.addStretch(0)  # takes the room only while the controls are hidden

        client.state_changed.connect(lambda _s: self._refresh_all())
        client.adapters_changed.connect(self._refresh_all)
        client.devices_changed.connect(self._fill_devices)
        client.device_updated.connect(self._update_device)
        client.operation_started.connect(self._started)
        client.operation_finished.connect(self._finished)
        client.agent_request.connect(self._agent_request)
        client.agent_cancelled.connect(self._agent_cancelled)
        self._refresh_all()

    # -- start and stop ------------------------------------------------------------------

    def start(self) -> None:
        self.client.start()
        self._refresh_all()

    def shutdown(self) -> None:
        self._scan_timer.stop()
        if self._waiter is not None:
            self._waiter.stop()
        for dialog in list(self._agent_dialogs.values()):
            dialog.cancelled = True
            dialog.reject()
        self.client.shutdown()
        for dialog in list(self._dialogs):
            dialog.close()

    # -- what is shown -------------------------------------------------------------------

    def current_adapter(self) -> BT.Adapter | None:
        path = self.adapter_combo.currentData()
        return self.client.adapter(path) if path else None

    def selected_path(self) -> str | None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if not rows:
            return None
        item = self.table.item(min(rows), COL_NAME)
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def selected_device(self) -> BT.Device | None:
        path = self.selected_path()
        return self.client.device(path) if path else None

    def open_dialog(self) -> QDialog | None:
        """The newest dialog of the panel on screen, or None."""
        for dialog in reversed(self._dialogs):
            if dialog.isVisible():
                return dialog
        return None

    def _refresh_all(self) -> None:
        ready = self.client.state == "ready"
        text = self.client.state_text()
        self.status.setText(text)
        self.status.setVisible(bool(text))
        self.controls.setVisible(ready)
        self._fill_adapters()
        self._fill_devices()

    def _fill_adapters(self) -> None:
        adapters = self.client.adapters()
        current = self.adapter_combo.currentData()
        combo = self.adapter_combo
        combo.blockSignals(True)
        combo.clear()
        for adapter in adapters:
            label = adapter.display_name
            if adapter.address and adapter.address != label:
                label = f"{label} ({adapter.address})"
            combo.addItem(label, adapter.path)
        index = combo.findData(current)
        combo.setCurrentIndex(index if index >= 0 else (0 if adapters else -1))
        combo.setEnabled(len(adapters) > 1)
        combo.blockSignals(False)
        self._update_adapter_row()

    def _update_adapter_row(self) -> None:
        adapter = self.current_adapter()
        busy = adapter is not None and self.client.busy(adapter.path) is not None
        self.power_check.setChecked(bool(adapter and adapter.powered))
        self.power_check.setEnabled(adapter is not None and not busy)
        scanning = bool(adapter and adapter.discovering)
        self.scan_button.setText(tr("Stop Scan") if scanning else tr("Scan"))
        self.scan_button.setEnabled(bool(adapter and adapter.powered) and not busy)
        if not scanning:
            self._scan_timer.stop()

    def _devices(self) -> list[BT.Device]:
        adapter = self.current_adapter()
        devices = self.client.devices(adapter.path) if adapter is not None else []
        return sorted(devices, key=lambda d: (not d.connected, not d.paired, d.rssi is None,
                                              -(d.rssi or 0), d.display_name.lower()))

    def _fill_devices(self) -> None:
        selected = self.selected_path()
        table = self.table
        devices = self._devices()
        table.blockSignals(True)
        table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            self._fill_row(row, device)
        table.blockSignals(False)
        table.clearSelection()
        for row, device in enumerate(devices):
            if device.path == selected:
                table.selectRow(row)
        table.resizeColumnsToContents()
        self._update_buttons()

    def _state_text(self, device: BT.Device) -> str:
        running = self.client.busy(device.path)
        if running in _RUNNING:
            return tr(_RUNNING[running])
        words = [w for w, on in ((tr("Connected"), device.connected), (tr("Paired"), device.paired),
                                 (tr("Trusted"), device.trusted), (tr("Blocked"), device.blocked))
                 if on]
        return ", ".join(words)

    def _fill_row(self, row: int, device: BT.Device) -> None:
        cells = (device.display_name, device.address, tr(device.kind),
                 f"{device.rssi} dBm" if device.rssi is not None else "",
                 f"{device.battery} %" if device.battery is not None else "",
                 self._state_text(device))
        for col, text in enumerate(cells):
            item = self.table.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                self.table.setItem(row, col, item)
            item.setText(text)
        self.table.item(row, COL_NAME).setData(Qt.ItemDataRole.UserRole, device.path)
        self._names[device.path] = device.display_name
        self.table.item(row, COL_NAME).setToolTip(device.path)

    def _row_of(self, path: str) -> int:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_NAME)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == path:
                return row
        return -1

    def _update_device(self, path: str) -> None:
        """One device changed: its row in place (rows do not jump while a
        scan updates the signal)."""
        device = self.client.device(path)
        row = self._row_of(path)
        if device is None or row < 0:
            return
        self._fill_row(row, device)
        if path == self.selected_path():
            self._update_buttons()

    def _update_buttons(self) -> None:
        device = self.selected_device()
        adapter = self.current_adapter()
        powered = bool(adapter and adapter.powered)
        busy = self.client.busy(device.path) if device is not None else None
        idle = device is not None and busy is None
        pairing = busy == "pair"
        self.pair_button.setText(tr("Cancel Pairing") if pairing else tr("Pair"))
        self.pair_button.setEnabled(pairing or (idle and powered and not device.paired))
        self.trust_button.setText(tr("Untrust") if device is not None and device.trusted
                                  else tr("Trust"))
        self.trust_button.setEnabled(idle)
        self.connect_button.setEnabled(idle and powered and not device.connected)
        self.disconnect_button.setEnabled(idle and device.connected)
        self.remove_button.setEnabled(idle)
        waiting = self._waiter is not None and self._waiter.running
        self.output_button.setEnabled(idle and powered and not waiting
                                      and self._output_after_connect is None
                                      and BT.is_audio_output(device))

    # -- the user's clicks ---------------------------------------------------------------

    def _power_clicked(self, checked: bool) -> None:
        adapter = self.current_adapter()
        if adapter is not None:
            self.client.set_powered(adapter.path, checked)
            self.power_check.setEnabled(False)

    def _scan_clicked(self) -> None:
        adapter = self.current_adapter()
        if adapter is None:
            return
        if adapter.discovering:
            self.client.stop_discovery(adapter.path)
        else:
            self.client.start_discovery(adapter.path)
        self.scan_button.setEnabled(False)

    def _scan_time_up(self) -> None:
        adapter = self.current_adapter()
        if adapter is not None and adapter.discovering:
            self.client.stop_discovery(adapter.path)
            self.message.setText(tr("The scan stopped after {minutes} minutes; Scan looks "
                                    "again.").format(minutes=max(1, SCAN_LIMIT_MS // 60_000)))

    def _pair_clicked(self) -> None:
        device = self.selected_device()
        if device is None:
            return
        if self.client.busy(device.path) == "pair":
            self._quiet_failures.add(device.path)
            self.client.cancel_pairing(device.path)
            return
        self._device_op("pair")

    def _trust_clicked(self) -> None:
        device = self.selected_device()
        if device is not None:
            self.client.set_trusted(device.path, not device.trusted)

    def _device_op(self, op: str) -> None:
        device = self.selected_device()
        if device is None:
            return
        {"pair": self.client.pair, "connect": self.client.connect_device,
         "disconnect": self.client.disconnect_device}[op](device.path)

    def _remove_clicked(self) -> None:
        device = self.selected_device()
        if device is None:
            return
        path = device.path
        box = QMessageBox(QMessageBox.Icon.Question, tr("Bluetooth"),
                          tr("Remove {device}? It has to be paired again before it can be "
                             "used.").format(device=device.display_name),
                          QMessageBox.StandardButton.NoButton, self)
        remove = box.addButton(tr("Remove"), QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.button_for_remove = remove
        box.buttonClicked.connect(lambda b: self.client.remove_device(path) if b is remove
                                  else None)
        self._show(box)

    def _output_clicked(self) -> None:
        device = self.selected_device()
        if device is None:
            return
        if device.connected:
            self._wait_for_sink(device)
            return
        self._output_after_connect = device.path
        self.message.setText(tr("Connecting to {device}…").format(device=device.display_name))
        self.client.connect_device(device.path)
        self._update_buttons()

    # -- results -------------------------------------------------------------------------

    def _started(self, path: str, _op: str) -> None:
        if path == self.adapter_combo.currentData():
            self._update_adapter_row()
        else:
            self._update_device(path)

    def _finished(self, path: str, op: str, error: str) -> None:
        device = self.client.device(path)
        name = device.display_name if device is not None else \
            self._names.get(path, path.rsplit("/", 1)[-1])
        if op == "pair":
            for dialog in list(self._agent_dialogs.values()):
                if dialog.request.device_path == path and not dialog.request.needs_answer:
                    dialog.cancelled = True
                    dialog.reject()
        if op in ("power", "scan", "stop-scan"):
            self._update_adapter_row()
            if op == "scan" and not error:
                self._scan_timer.start(SCAN_LIMIT_MS)
        else:
            self._update_device(path)
            self._update_buttons()
        if op == "connect" and path == self._output_after_connect:
            self._output_after_connect = None
            if not error and device is not None:
                self._wait_for_sink(self.client.device(path) or device)
        if not error:
            done = {"pair": tr("Paired with {device}."), "connect": tr("Connected to {device}."),
                    "disconnect": tr("Disconnected from {device}."),
                    "remove": tr("Removed {device}.")}
            if op in done:
                self.message.setText(done[op].format(device=name))
            return
        if op == "pair" and path in self._quiet_failures:
            self._quiet_failures.discard(path)
            self.message.setText(error)
            return
        if op == "cancel-pairing":
            return
        what = {
            "power": tr("Could not switch the adapter on or off."),
            "scan": tr("Could not start the scan."),
            "stop-scan": tr("Could not stop the scan."),
            "pair": tr("Could not pair with {device}."),
            "trust": tr("Could not change the trust of {device}."),
            "connect": tr("Could not connect to {device}."),
            "disconnect": tr("Could not disconnect {device}."),
            "remove": tr("Could not remove {device}."),
        }.get(op, tr("The operation failed."))
        self.message.setText(error)
        self._error(f"{what.format(device=name)}\n\n{error}")

    def _wait_for_sink(self, device: BT.Device) -> None:
        if self._waiter is not None:
            self._waiter.stop()
            self._waiter.deleteLater()
        waiter = BT.SinkWaiter(device, lister=self._sink_lister, timeout=self._sink_timeout,
                               parent=self)
        waiter.found.connect(lambda ident, desc: self._sink_found(device, ident, desc))
        waiter.timed_out.connect(lambda: self._sink_missing(device))
        waiter.failed.connect(lambda text: self._sink_failed(text))
        self._waiter = waiter
        self.message.setText(tr("Waiting for the audio output of {device}…")
                             .format(device=device.display_name))
        waiter.start()
        self._update_buttons()

    def _sink_found(self, device: BT.Device, ident: str, description: str) -> None:
        try:
            BT.set_audio_output(ident, path=self._audio_settings_path)
        except (OSError, ValueError) as exc:
            self.message.setText("")
            self._error(tr("Could not save the audio output: {error}").format(error=exc))
        else:
            self.message.setText(tr("{device} is now axross's audio output ({output}) - see "
                                    "Edit > Settings > Audio.")
                                 .format(device=device.display_name, output=description))
        self._update_buttons()

    def _sink_missing(self, device: BT.Device) -> None:
        self.message.setText("")
        text = tr("No audio output for {device} appeared within {seconds} s. The device is "
                  "connected, but the sound server made no output for it: its A2DP profile "
                  "may not be available (does PipeWire or PulseAudio have its Bluetooth "
                  "support installed?), or the device is playing for another computer.") \
            .format(device=device.display_name, seconds=f"{self._sink_timeout:g}")
        self._error(text, audio_settings=True)
        self._update_buttons()

    def _sink_failed(self, text: str) -> None:
        self.message.setText("")
        self._error(text, audio_settings=True)
        self._update_buttons()

    # -- dialogs -------------------------------------------------------------------------

    def _show(self, dialog: QDialog) -> None:
        self._dialogs.append(dialog)

        def gone(_result=None) -> None:
            if dialog in self._dialogs:
                self._dialogs.remove(dialog)
            dialog.deleteLater()

        dialog.finished.connect(gone)
        dialog.open()

    def _error(self, text: str, *, audio_settings: bool = False) -> None:
        box = QMessageBox(QMessageBox.Icon.Warning, tr("Bluetooth"), text,
                          QMessageBox.StandardButton.Close, self)
        box.audio_settings_button = None
        if audio_settings and callable(self._open_audio_settings):
            button = box.addButton(tr("Audio Settings…"), QMessageBox.ButtonRole.ActionRole)
            button.clicked.connect(self._open_audio_settings)
            box.audio_settings_button = button
        self._show(box)

    def _agent_request(self, request: BT.AgentRequest) -> None:
        dialog = AgentDialog(request, self)
        self._agent_dialogs[request.token] = dialog

        def done(result: int) -> None:
            self._agent_dialogs.pop(request.token, None)
            if dialog.cancelled or not request.needs_answer:
                return
            accepted = result == QDialog.DialogCode.Accepted
            if not accepted:
                self._quiet_failures.add(request.device_path)
            self.client.answer(request.token, accepted, dialog.value() if accepted else None)

        dialog.finished.connect(done)
        self._show(dialog)

    def _agent_cancelled(self, token: int) -> None:
        dialog = self._agent_dialogs.pop(token, None)
        if dialog is not None:
            dialog.cancelled = True
            dialog.reject()


#: The panels activate() made, for deactivate().
_PANELS: list[BluetoothPanel] = []


def activate(api):
    window = getattr(api, "window", None)
    open_settings = getattr(window, "open_settings", None)
    panel = BluetoothPanel(make_client(),
                           open_audio_settings=(lambda: open_settings("audio"))
                           if callable(open_settings) else None)
    _PANELS.append(panel)
    api.add_dock(tr("Bluetooth"), panel)

    def start() -> None:
        if not sip.isdeleted(panel):  # switched off again before the window ran
            panel.start()

    # The system bus is asked once the window runs, not while the extension loads.
    QTimer.singleShot(0, start)


def deactivate(api):
    while _PANELS:
        panel = _PANELS.pop()
        try:
            panel.shutdown()
        except RuntimeError:  # pragma: no cover - the widget is gone already
            pass
