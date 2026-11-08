"""A panel to connect Bluetooth devices - speakers and headphones first.

BlueZ (the Linux Bluetooth service) over the system D-Bus, through
core.bluetooth: the adapter with its power switch, a scan for Classic
and/or BLE devices (optionally only the nearer ones) with the devices it
finds (name, address, kind, radio, signal while scanning, vendor from
the BLE advertisement, battery, when last heard, state), a filter row,
a *Map* of the devices nearby by estimated distance (ui/bluetooth_map.py),
*Details…* (ui/bluetooth_details.py), *Presence…* - when which device was
in range, kept in a log and exported (ui/bluetooth_presence.py,
core.bluetooth_presence), *Streams…* - the connections and channels of
an HCI capture with their protocols and traffic, also as a visualization
(ui/bluetooth_streams.py, core.bluetooth_stream) - and Pair, Trust, Connect,
Disconnect and Remove. A pairing that
asks something (confirm a passkey, type a PIN) asks the user in a dialog;
nothing is accepted without an answer. *Use as Audio Output* connects a
speaker or headset if needed, waits for its output to appear in the sound
server and makes it axross's output (Edit > Settings > Audio), which the
Media Player and the other players follow.
"""

from __future__ import annotations

import time

from PyQt6 import sip
from PyQt6.QtCore import QRegularExpression, Qt, QTimer, pyqtSignal
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
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import bluetooth as BT
from core import bluetooth_link as BTL
from core import bluetooth_presence as BP
from core import bluetooth_vendor as BV
from core.i18n import tr

EXTENSION = {
    "name": "Bluetooth",
    "version": "1.0",
    "description": "A panel to scan for Bluetooth Classic and BLE devices nearby (BlueZ), "
    "pair, connect and remove them; a speaker or headset becomes axross's audio output "
    "with one click.",
    "author": "axross",
}

COLUMNS = ("Name", "Address", "Type", "Radio", "Signal", "Vendor", "Battery", "Seen", "State")
(COL_NAME, COL_ADDRESS, COL_TYPE, COL_RADIO, COL_SIGNAL, COL_VENDOR, COL_BATTERY, COL_SEEN,
 COL_STATE) = range(len(COLUMNS))
#: A scan runs at most this long (it keeps the radio busy); Scan starts a new one.
SCAN_LIMIT_MS = 120_000
#: What Scan looks for: (label, transport of core.bluetooth.TRANSPORTS).
SCAN_MODES = (("Classic + BLE", "auto"), ("Classic only", "bredr"), ("BLE only", "le"))
#: Weakest signal a scan lists: (label, dBm or None).
MIN_SIGNALS = (("Any signal", None), ("-90 dBm or stronger", -90),
               ("-80 dBm or stronger", -80), ("-70 dBm or stronger", -70),
               ("-60 dBm or stronger", -60))
#: The radio column's words for core.bluetooth's bearers.
RADIO_TEXT = {"Classic": "Classic", "LE": "BLE", "Dual": "Classic + BLE", "": ""}
#: A burst of new devices (a BLE scan finds dozens a second) refills the
#: table once per this many milliseconds, not once per device.
FILL_DELAY_MS = 80
#: Seconds to wait for a connected headset's output to appear.
SINK_TIMEOUT = 20.0

_RUNNING = {
    "pair": "Pairing…",
    "connect": "Connecting…",
    "disconnect": "Disconnecting…",
    "remove": "Removing…",
    "trust": "Saving…",
}


def seen_text(last_seen: float | None, now: float | None = None) -> str:
    """When a device was last heard: "now", "12 s ago", "3 min ago", ""."""
    if last_seen is None:
        return ""
    age = max(0.0, (time.time() if now is None else now) - last_seen)
    if age < 2:
        return tr("now")
    if age < 60:
        return tr("{n} s ago").format(n=int(age))
    if age < 3600:
        return tr("{n} min ago").format(n=int(age // 60))
    return tr("{n} h ago").format(n=int(age // 3600))


def make_client(source: str = "bluez") -> BT.BluezClient:
    """The client of *source*: "bluez" (the system bus) or a Bumble
    transport name of a stick used directly ("usb:0"; core.bluetooth_direct).
    A seam for the tests."""
    if source and source != "bluez":
        from core.bluetooth_direct import DirectClient

        return DirectClient(source)
    return BT.BluezClient()


SOURCE_FILE = "bluetooth.json"


def source_file():
    from pathlib import Path

    return Path.home() / ".config" / "axross" / SOURCE_FILE


def read_source(path=None) -> str:
    """The adapter source chosen last: "bluez" or a stick ("usb:0")."""
    import json

    try:
        data = json.loads((path or source_file()).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return "bluez"
    source = data.get("source") if isinstance(data, dict) else None
    if isinstance(source, str) and (source == "bluez" or source.startswith("usb:")) \
            and len(source) <= 40:
        return source
    return "bluez"


def write_source(source: str, path=None) -> None:
    import json
    import os

    from core.secure_storage import write_secret_file

    target = path or source_file()
    os.makedirs(target.parent, mode=0o700, exist_ok=True)
    write_secret_file(str(target), json.dumps({"source": source}) + "\n")


class AgentDialog(QDialog):
    """One question of a pairing: confirm, type a PIN or passkey, allow,
    or (display-*) just show a code. Closing it is a no."""

    def __init__(self, request: BT.AgentRequest, parent: QWidget) -> None:
        super().__init__(parent)
        from ui.icon_provider import set_window_icon

        set_window_icon(self, "bluetooth")
        self.request = request
        #: BlueZ took the question back: closing sends no answer.
        self.cancelled = False
        self.setWindowTitle(tr("Bluetooth Pairing"))
        layout = QVBoxLayout(self)
        self.text_label = QLabel(self.text_of(request))
        # The device chose its name: as markup it could restyle or hide the
        # passkey and the question it is asked to confirm.
        self.text_label.setTextFormat(Qt.TextFormat.PlainText)
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

    @staticmethod
    def text_of(request: BT.AgentRequest) -> str:
        """What the dialog says for *request*."""
        name = request.device_name
        passkey = f"{request.passkey or 0:06d}"
        if request.kind == "display-passkey" and request.entered:
            return tr("Type {passkey} on {device} and press Enter there ({entered} of 6 "
                      "digits typed).").format(device=name, passkey=passkey,
                                                entered=min(request.entered, 6))
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
        return texts.get(request.kind, request.kind)

    def show_request(self, request: BT.AgentRequest) -> None:
        """BlueZ asked again for the same code (DisplayPasskey once per digit
        typed on the device): this dialog shows the new state."""
        self.request = request
        self.text_label.setText(self.text_of(request))

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

    #: (device path, worked, text) - the end of a Use as Audio Output
    output_result = pyqtSignal(str, bool, str)

    def __init__(self, client: BT.BluezClient, *, sink_lister=None,
                 sink_timeout: float = SINK_TIMEOUT, open_audio_settings=None,
                 audio_settings_path=None, source_lister=None, make_player=None,
                 make_recorder=None, link_settings_path=None, reconnect_delays=None,
                 test_options: dict | None = None, presence_path=None,
                 presence_options: dict | None = None) -> None:
        """*presence_path*: the presence log's file (None: kept in memory
        only); *presence_options*: more PresenceLog arguments (tests)."""
        super().__init__()
        self.client = client
        #: Use as Audio Output needs BlueZ's audio profiles (not a stick used directly)
        self.audio_available = True
        self.presence = BP.PresenceLog(client, path=presence_path, parent=self,
                                       **(presence_options or {}))
        self._presence_dialog = None
        self._sink_lister = sink_lister
        #: seams of the details dialog's audio tests
        self._details_options = {"sink_lister": sink_lister, "source_lister": source_lister,
                                 "make_player": make_player, "make_recorder": make_recorder,
                                 "test_options": test_options}
        self.reconnector = BTL.Reconnector(
            client, path=link_settings_path, parent=self,
            **({"delays": tuple(reconnect_delays)} if reconnect_delays else {}))
        self.reconnector.attempting.connect(self._reconnecting)
        self.reconnector.reconnected.connect(
            lambda path: self.message.setText(tr("Reconnected to {device}.").format(
                device=self._names.get(path, path.rsplit("/", 1)[-1]))))
        self.reconnector.gave_up.connect(
            lambda path: self.message.setText(tr(
                "Could not reconnect to {device}; it reconnects when you connect it again.")
                .format(device=self._names.get(path, path.rsplit("/", 1)[-1]))))
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
        #: device path -> its open details dialog
        self._details: dict[str, QDialog] = {}
        #: device path -> its row in the table
        self._rows: dict[str, int] = {}
        self._scan_timer = QTimer(self)
        self._scan_timer.setSingleShot(True)
        self._scan_timer.timeout.connect(self._scan_time_up)
        self._fill_timer = QTimer(self)
        self._fill_timer.setSingleShot(True)
        self._fill_timer.setInterval(FILL_DELAY_MS)
        self._fill_timer.timeout.connect(self._fill_devices)
        #: the Seen column ages once a second while the panel is shown
        self._seen_timer = QTimer(self)
        self._seen_timer.setInterval(1000)
        self._seen_timer.timeout.connect(self._update_seen)

        layout = QVBoxLayout(self)
        self.status = QLabel("")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
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
        self.scan_mode_combo = QComboBox()
        for label, transport in SCAN_MODES:
            self.scan_mode_combo.addItem(tr(label), transport)
        self.scan_mode_combo.setToolTip(tr("What a scan looks for: Classic (BR/EDR) devices "
                                           "such as speakers and phones, Bluetooth Low Energy "
                                           "devices such as watches, tags and sensors, or both."))
        top.addWidget(self.scan_mode_combo)
        self.min_signal_combo = QComboBox()
        for label, dbm in MIN_SIGNALS:
            self.min_signal_combo.addItem(tr(label), dbm)
        self.min_signal_combo.setToolTip(tr("A scan lists only devices at least this strong "
                                            "(nearer ones)."))
        top.addWidget(self.min_signal_combo)
        self.scan_button = QPushButton(tr("Scan"))
        self.scan_button.clicked.connect(self._scan_clicked)
        top.addWidget(self.scan_button)
        self.add_button = QPushButton(tr("Add Device…"))
        self.add_button.setToolTip(tr("Find a new device nearby and pair, trust, connect it - "
                                      "and make a speaker or headset the audio output - in "
                                      "one go."))
        self.add_button.clicked.connect(self.open_add_device)
        top.addWidget(self.add_button)
        self.presence_button = QPushButton(tr("Presence…"))
        self.presence_button.setToolTip(tr("When which device was in range: a log of every "
                                           "device heard while scanning, with an export to "
                                           "CSV or JSON."))
        self.presence_button.clicked.connect(self.open_presence)
        top.addWidget(self.presence_button)
        self.streams_button = QPushButton(tr("Streams…"))
        self.streams_button.setToolTip(tr("The connections and channels in an HCI capture "
                                          "(btmon -w, Android's btsnoop log): which protocol, "
                                          "how much traffic when, and as a visualization."))
        self.streams_button.clicked.connect(lambda: self.open_streams())
        top.addWidget(self.streams_button)
        self._streams_dialog = None
        self._add_dialog = None
        controls.addLayout(top)

        show = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("Filter by name, address, type or vendor…"))
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(lambda _t: self._fill_devices())
        show.addWidget(self.search_edit, 1)
        self.show_combo = QComboBox()
        for label, radio in (("All radios", ""), ("Classic", "Classic"), ("BLE", "LE")):
            self.show_combo.addItem(tr(label), radio)
        self.show_combo.currentIndexChanged.connect(lambda _i: self._fill_devices())
        show.addWidget(self.show_combo)
        self.named_check = QCheckBox(tr("Named only"))
        self.named_check.setToolTip(tr("Hide devices that did not tell their name (many BLE "
                                       "beacons and trackers)."))
        self.named_check.toggled.connect(lambda _on: self._fill_devices())
        show.addWidget(self.named_check)
        self.count_label = QLabel("")
        show.addWidget(self.count_label)
        controls.addLayout(show)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item: self.open_details())
        from ui.bluetooth_map import NearbyMap

        self.map = NearbyMap()
        self.map.device_clicked.connect(self.select_path)
        self.map.device_activated.connect(self.open_details)
        self.views = QTabWidget()
        self.views.addTab(self.table, tr("List"))
        self.views.addTab(self.map, tr("Map"))
        self.views.setTabToolTip(1, tr("The devices nearby by estimated distance (scan to see "
                                       "them)."))
        controls.addWidget(self.views, 1)

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
        self.details_button = QPushButton(tr("Details…"))
        self.details_button.setToolTip(tr("Everything BlueZ knows of the device, and the map "
                                          "of its GATT services (double-click a device)."))
        self.details_button.clicked.connect(lambda: self.open_details())
        self.test_button = QPushButton(tr("Test…"))
        self.test_button.setToolTip(tr("Connection options and tests: profiles, reconnect "
                                       "automatically, test the connection, a test sound and "
                                       "the microphone of a headset."))
        self.test_button.clicked.connect(lambda: self.open_details(tab="connection"))
        for button in (self.pair_button, self.trust_button, self.connect_button,
                       self.disconnect_button, self.remove_button, self.output_button,
                       self.details_button, self.test_button):
            row.addWidget(button)
        row.addStretch(1)
        controls.addLayout(row)
        layout.addWidget(self.controls, 1)

        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)  # names devices
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        layout.addStretch(0)  # takes the room only while the controls are hidden

        client.state_changed.connect(lambda _s: self._refresh_all())
        client.adapters_changed.connect(self._refresh_all)
        client.devices_changed.connect(self._schedule_fill)
        client.device_updated.connect(self._update_device)
        client.operation_started.connect(self._started)
        client.operation_finished.connect(self._finished)
        client.agent_request.connect(self._agent_request)
        client.agent_cancelled.connect(self._agent_cancelled)
        self._refresh_all()

    # -- start and stop ------------------------------------------------------------------

    def start(self) -> None:
        self.client.start()
        self.presence.start()
        BV.notifier().loaded.connect(self._schedule_fill)
        BV.preload()  # the makers of public addresses, read in the background
        self._refresh_all()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self._seen_timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().hideEvent(event)
        self._seen_timer.stop()

    def shutdown(self) -> None:
        self.reconnector.stop()
        self.presence.stop()
        try:
            BV.notifier().loaded.disconnect(self._schedule_fill)
        except (TypeError, RuntimeError):
            pass
        for dialog in (self._presence_dialog, self._streams_dialog):
            if dialog is not None and not sip.isdeleted(dialog):
                dialog.close()
        self._scan_timer.stop()
        self._fill_timer.stop()
        self._seen_timer.stop()
        if self._waiter is not None:
            self._waiter.stop()
        for dialog in list(self._agent_dialogs.values()):
            dialog.cancelled = True
            dialog.reject()
        for dialog in list(self._details.values()):
            if not sip.isdeleted(dialog):
                dialog.close()
        if self._add_dialog is not None and not sip.isdeleted(self._add_dialog):
            self._add_dialog.close()
        self._details.clear()
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
        scanning = bool(adapter and self.client.scanning(adapter.path))
        self.scan_button.setText(tr("Stop Scan") if scanning else tr("Scan"))
        # BlueZ scans for each program on its own: another one's scan finds
        # devices here too, but only a scan of ours can be stopped
        self.scan_button.setToolTip(
            tr("Another program is scanning; Scan starts axross's own scan with the filter "
               "chosen here.") if adapter is not None and adapter.discovering and not scanning
            else "")
        self.scan_button.setEnabled(bool(adapter and adapter.powered) and not busy)
        self.add_button.setEnabled(adapter is not None)
        # a running scan keeps its filter: change it, then scan again
        self.scan_mode_combo.setEnabled(not scanning)
        self.min_signal_combo.setEnabled(not scanning)
        if not scanning:
            self._scan_timer.stop()

    def _all_devices(self) -> list[BT.Device]:
        adapter = self.current_adapter()
        return self.client.devices(adapter.path) if adapter is not None else []

    def _shown(self, device: BT.Device) -> bool:
        """Whether the filter row lets *device* through."""
        radio = self.show_combo.currentData()
        if radio and device.bearer not in (radio, "Dual"):
            return False
        if self.named_check.isChecked() and not device.named and not device.paired:
            return False
        words = self.search_edit.text().strip().lower().split()
        if words:
            hay = " ".join((device.display_name, device.name, device.address, tr(device.kind),
                            device.kind, device.vendor, RADIO_TEXT.get(device.bearer, ""),
                            *device.services, *(i.name for i in device.idents))).lower()
            return all(word in hay for word in words)
        return True

    def _devices(self) -> list[BT.Device]:
        devices = [d for d in self._all_devices() if self._shown(d)]
        return sorted(devices, key=lambda d: (not d.connected, not d.paired, d.rssi is None,
                                              -(d.rssi or 0), d.display_name.lower()))

    def _schedule_fill(self) -> None:
        if not self._fill_timer.isActive():
            self._fill_timer.start()

    def _fill_devices(self) -> None:
        self._fill_timer.stop()
        selected = self.selected_path()
        table = self.table
        everything = self._all_devices()
        devices = sorted((d for d in everything if self._shown(d)),
                         key=lambda d: (not d.connected, not d.paired, d.rssi is None,
                                        -(d.rssi or 0), d.display_name.lower()))
        table.setUpdatesEnabled(False)
        table.blockSignals(True)
        try:
            table.setRowCount(len(devices))
            self._rows = {}
            for row, device in enumerate(devices):
                self._fill_row(row, device)
            table.clearSelection()
            if selected in self._rows:
                table.selectRow(self._rows[selected])
        finally:
            table.blockSignals(False)
            table.setUpdatesEnabled(True)
        table.resizeColumnsToContents()
        self.map.set_devices(devices)
        self.map.set_selected(self.selected_path())
        hidden = len(everything) - len(devices)
        self.count_label.setText(
            tr("{shown} of {total}").format(shown=len(devices), total=len(everything))
            if hidden else tr("{n} devices").format(n=len(devices)) if devices else "")
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
                 tr(RADIO_TEXT.get(device.bearer, "")) if device.bearer else "",
                 f"{device.rssi} dBm" if device.rssi is not None else "",
                 device.vendor,
                 f"{device.battery} %" if device.battery is not None else "",
                 seen_text(device.last_seen),
                 self._state_text(device))
        for col, text in enumerate(cells):
            item = self.table.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                self.table.setItem(row, col, item)
            if item.text() != text:
                item.setText(text)
        name = self.table.item(row, COL_NAME)
        name.setData(Qt.ItemDataRole.UserRole, device.path)
        self._rows[device.path] = row
        self._names[device.path] = device.display_name
        tip = [device.path]
        if device.services:
            tip.append(tr("Services: {names}").format(names=", ".join(device.services)))
        if device.tx_power is not None:
            tip.append(tr("Transmit power: {dbm} dBm").format(dbm=device.tx_power))
        tip += [ident.text() for ident in device.idents]
        name.setToolTip("\n".join(tip))

    def _row_of(self, path: str) -> int:
        row = self._rows.get(path, -1)
        item = self.table.item(row, COL_NAME) if row >= 0 else None
        if item is not None and item.data(Qt.ItemDataRole.UserRole) == path:
            return row
        return -1

    def _update_seen(self) -> None:
        """Age the Seen column (only the cells whose text changes)."""
        now = time.time()
        for path, row in self._rows.items():
            item = self.table.item(row, COL_SEEN)
            if item is None:
                continue
            device = self.client.device(path)
            text = seen_text(device.last_seen, now) if device is not None else ""
            if item.text() != text:
                item.setText(text)

    def _update_device(self, path: str) -> None:
        """One device changed: its row in place (rows do not jump while a
        scan updates the signal)."""
        device = self.client.device(path)
        row = self._row_of(path)
        if device is None or row < 0:
            return
        self._fill_row(row, device)
        self.map.update_device(device, path)
        if path == self.selected_path():
            self._update_buttons()

    def select_path(self, path: str) -> None:
        """Select *path*'s row (a click on the map)."""
        row = self._row_of(path)
        if row >= 0:
            self.table.selectRow(row)
            self.table.scrollToItem(self.table.item(row, COL_NAME))

    def _update_buttons(self) -> None:
        self.map.set_selected(self.selected_path())
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
        self.details_button.setEnabled(device is not None)
        self.test_button.setEnabled(device is not None)
        waiting = self._waiter is not None and self._waiter.running
        self.output_button.setEnabled(idle and powered and not waiting
                                      and self._output_after_connect is None
                                      and self.audio_available
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
        if self.client.scanning(adapter.path):
            if self.presence.monitoring == adapter.path:
                self.presence.set_monitoring(None)  # stops our scan with it
            else:
                self.client.stop_discovery(adapter.path)
        else:
            self.client.start_discovery(adapter.path,
                                        transport=self.scan_mode_combo.currentData(),
                                        rssi=self.min_signal_combo.currentData())
        self.scan_button.setEnabled(False)

    def _scan_time_up(self) -> None:
        adapter = self.current_adapter()
        if adapter is not None and self.presence.monitoring == adapter.path:
            return  # Presence keeps this scan running
        if adapter is not None and self.client.scanning(adapter.path):
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
        if op == "disconnect":
            self.reconnector.expect_disconnect(device.path)  # no drop to repair
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
        box.setTextFormat(Qt.TextFormat.PlainText)
        remove = box.addButton(tr("Remove"), QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.button_for_remove = remove
        box.buttonClicked.connect(lambda b: self.client.remove_device(path) if b is remove
                                  else None)
        self._show(box)

    def _reconnecting(self, path: str, attempt: int) -> None:
        self.message.setText(tr("The connection to {device} dropped - reconnecting "
                                "(attempt {n} of {total})…").format(
            device=self._names.get(path, path.rsplit("/", 1)[-1]), n=attempt,
            total=self.reconnector.max_attempts))

    def open_details(self, path: str | None = None, tab: str | None = None):
        """The details dialog of *path* (the selected device), one per
        device: a second call brings the open one to the front; *tab*
        ("overview", "services", "connection") picks its page."""
        from ui.bluetooth_details import DeviceDialog

        path = path or self.selected_path()
        if not path or self.client.device(path) is None:
            return None
        dialog = self._details.get(path)
        if dialog is None or sip.isdeleted(dialog):
            dialog = DeviceDialog(self.client, path, self, reconnector=self.reconnector,
                                  **self._details_options)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self._details[path] = dialog
            dialog.finished.connect(self._details_closed(path))
        if tab:
            dialog.show_tab(tab)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def _details_closed(self, path: str):
        def closed(_result: int) -> None:
            self._details.pop(path, None)
        return closed

    def open_add_device(self):
        """The Add Device dialog (one at a time; a second call raises it)."""
        from ui.bluetooth_add import AddDeviceDialog

        dialog = self._add_dialog
        if dialog is None or sip.isdeleted(dialog):
            dialog = AddDeviceDialog(self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.finished.connect(self._add_dialog_closed)
            self._add_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def _add_dialog_closed(self, _result: int) -> None:
        self._add_dialog = None

    def open_presence(self, *, ask_save=None):
        """The Presence dialog (one at a time; a second call raises it)."""
        from ui.bluetooth_presence import PresenceDialog

        dialog = self._presence_dialog
        if dialog is None or sip.isdeleted(dialog):
            dialog = PresenceDialog(
                self.presence, parent=self, ask_save=ask_save,
                adapter=lambda: (self.current_adapter().path
                                 if self.current_adapter() is not None else None))
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.finished.connect(lambda _r: setattr(self, "_presence_dialog", None))
            dialog.destroyed.connect(lambda _o=None: setattr(self, "_presence_dialog", None))
            self._presence_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def open_streams(self, *, path: str | None = None, ask_open=None):
        """The Streams dialog (one at a time; a second call raises it)."""
        from ui.bluetooth_streams import StreamsDialog

        dialog = self._streams_dialog
        if dialog is None or sip.isdeleted(dialog):
            dialog = StreamsDialog(path=path, ask_open=ask_open, parent=self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda _o=None: setattr(self, "_streams_dialog", None))
            self._streams_dialog = dialog
        elif path:
            dialog.open_capture(path)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def use_as_output(self, path: str) -> None:
        """Make *path* axross's audio output: connected first if needed,
        then its output waited for (output_result says how it ended)."""
        device = self.client.device(path)
        if device is None:
            self.output_result.emit(path, False, tr("The device is no longer known to BlueZ."))
            return
        if device.connected:
            self._wait_for_sink(device)
            return
        self._output_after_connect = device.path
        self.message.setText(tr("Connecting to {device}…").format(device=device.display_name))
        self.client.connect_device(device.path)
        self._update_buttons()

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
            # "already connected": BlueZ said Connected a moment after its reply
            # to an earlier Connect - as good as connected now
            already = error == BT.error_text("org.bluez.Error.AlreadyConnected", "")
            if (not error or already) and device is not None:
                self._wait_for_sink(self.client.device(path) or device)
                if already:
                    return
            elif error:
                self.output_result.emit(path, False, error)
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

    def cancel_output(self, path: str) -> None:
        """Stop making *path* the audio output (Add Device's Cancel): a
        connect it waits for no longer leads to the output, a wait for the
        output ends, and axross's output stays as it is. No output_result -
        the caller canceled and knows."""
        if self._output_after_connect == path:
            self._output_after_connect = None
        waiter = self._waiter
        if waiter is not None and waiter.device.path == path:
            self._waiter = None
            waiter.stop()
            waiter.deleteLater()
            self.message.setText("")
        self._update_buttons()

    def _wait_for_sink(self, device: BT.Device) -> None:
        pending = self._output_after_connect
        if pending is not None and pending != device.path:
            # an output still to come after a connect: this choice is newer
            self._output_after_connect = None
            self.output_result.emit(pending, False,
                                    tr("Another device was chosen as the audio output."))
        old = self._waiter
        if old is not None:
            self._waiter = None
            old.stop()
            old.deleteLater()
            if old.device.path != device.path:
                # whoever waited for that output (Add Device) hears how it ended
                self.output_result.emit(
                    old.device.path, False,
                    tr("Another device was chosen as the audio output."))
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
            self.output_result.emit(device.path, False, str(exc))
        else:
            self.output_result.emit(device.path, True, description)
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
        self.output_result.emit(device.path, False, text)
        self._update_buttons()

    def _sink_failed(self, text: str) -> None:
        self.message.setText("")
        self._error(text, audio_settings=True)
        waiter = self._waiter
        if waiter is not None:
            self.output_result.emit(waiter.device.path, False, text)
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
        box.setTextFormat(Qt.TextFormat.PlainText)  # names a device, BlueZ's error
        box.audio_settings_button = None
        if audio_settings and callable(self._open_audio_settings):
            button = box.addButton(tr("Audio Settings…"), QMessageBox.ButtonRole.ActionRole)
            button.clicked.connect(self._open_audio_settings)
            box.audio_settings_button = button
        self._show(box)

    def _agent_request(self, request: BT.AgentRequest) -> None:
        if not request.needs_answer:
            # The same code again (BlueZ calls DisplayPasskey for every digit
            # typed): the dialog that shows it is updated - before, each call
            # opened one more.
            shown = self._agent_dialogs.get(request.token) or next(
                (d for d in self._agent_dialogs.values()
                 if not sip.isdeleted(d) and not d.request.needs_answer
                 and d.request.kind == request.kind
                 and d.request.device_path == request.device_path), None)
            if shown is not None and not sip.isdeleted(shown):
                if shown.request.token != request.token:
                    self._agent_dialogs.pop(shown.request.token, None)
                    self._agent_dialogs[request.token] = shown
                shown.show_request(request)
                return
        dialog = AgentDialog(request, self)
        self._agent_dialogs[request.token] = dialog

        def done(result: int) -> None:
            self._agent_dialogs.pop(dialog.request.token, None)  # its latest request
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
class BluetoothHost(QWidget):
    """The dock's widget: which adapter the panel uses - BlueZ's, or a USB
    stick driven directly (core.bluetooth_direct; without BlueZ, also on
    Windows and macOS) - over the BluetoothPanel of that client. Choosing
    another source builds the panel again with a new client; the dock and
    this widget stay."""

    def __init__(self, source: str = "bluez", *, panel_options: dict | None = None,
                 sticks=None, confirm=None, source_path=None) -> None:
        """*sticks()*: the sticks to offer (core.bluetooth_direct.list_sticks);
        *confirm(text)*: True to go on (a QMessageBox without); *source_path*:
        where the choice is kept. Seams for the tests."""
        super().__init__()
        self._options = dict(panel_options or {})
        self._sticks = sticks
        self._confirm = confirm
        self._source_path = source_path
        self.source = source
        self.panel: BluetoothPanel | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.setContentsMargins(6, 4, 6, 0)
        row.addWidget(QLabel(tr("Adapter:")))
        self.source_combo = QComboBox()
        self.source_combo.setToolTip(tr(
            "BlueZ: the system's Bluetooth service (Linux). A USB stick used directly: "
            "axross drives it itself (Bumble), without BlueZ - also on Windows and macOS; "
            "the system cannot use the stick meanwhile, and audio output needs BlueZ."))
        row.addWidget(self.source_combo, 1)
        self.refresh_button = QPushButton(tr("Look Again"))
        self.refresh_button.setToolTip(tr("List the USB Bluetooth sticks again."))
        self.refresh_button.clicked.connect(self.fill_sources)
        row.addWidget(self.refresh_button)
        layout.addLayout(row)
        self._layout = layout
        self.fill_sources()
        self.source_combo.activated.connect(self._chosen)
        if self.source != "bluez" and not self._plugged_in(self.source):
            self.source = "bluez"  # for this run; the choice stays kept for when it is back
            self.source_combo.setCurrentIndex(0)
        self._build()

    @property
    def client(self):
        return self.panel.client if self.panel is not None else None

    def _plugged_in(self, source: str) -> bool:
        index = self.source_combo.findData(source)
        return index >= 0 and self.source_combo.model().item(index).isEnabled()

    def fill_sources(self) -> None:
        from core import bluetooth_direct as BDIR

        combo = self.source_combo
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(tr("BlueZ (system)"), "bluez")
        if BDIR.available():
            sticks = (self._sticks or BDIR.list_sticks)()
            for stick in sticks:
                combo.addItem(tr("USB stick directly: {name} (bus {bus}, device {dev})").format(
                    name=stick["name"], bus=stick["bus"], dev=stick["address"]),
                    stick["transport"])
            if self.source != "bluez" and combo.findData(self.source) < 0:
                # the stick chosen last is not plugged in: shown, not taken -
                # another adapter is never used in its place
                combo.addItem(tr("USB stick directly: {stick} (not found)").format(
                    stick=self.source), self.source)
                combo.model().item(combo.count() - 1).setEnabled(False)
        else:
            # Help > Features… installs it, as every other extra (before:
            # a pip command to type).
            combo.addItem(tr("USB stick directly - needs Bumble: install it in Help > Features… "
                             "(Bluetooth USB stick without BlueZ)"), None)
            item = combo.model().item(combo.count() - 1)
            item.setEnabled(False)
        combo.setCurrentIndex(max(0, combo.findData(self.source)))
        combo.blockSignals(False)

    def _chosen(self, index: int) -> None:
        source = self.source_combo.itemData(index)
        if not source or source == self.source:
            return
        if source != "bluez":
            text = tr("axross will drive this stick itself. While it does, the system "
                      "(BlueZ, Windows, macOS) cannot use it, and devices paired through the "
                      "system are not paired here. Use it?")
            ok = self._confirm(text) if self._confirm is not None else \
                QMessageBox.question(self, tr("Use a USB Stick Directly"), text) == \
                QMessageBox.StandardButton.Yes
            if not ok:
                self.source_combo.setCurrentIndex(max(0, self.source_combo.findData(
                    self.source)))
                return
        self.set_source(source)

    def set_source(self, source: str) -> None:
        """Use *source* from now on (kept for the next start)."""
        self.source = source
        try:
            write_source(source, self._source_path)
        except OSError:
            log_warning("the Bluetooth adapter choice cannot be kept")
        self._build()
        self.panel.start()

    def _build(self) -> None:
        old = self.panel
        if old is not None:
            old.shutdown()
            self._layout.removeWidget(old)
            old.deleteLater()
        self.panel = BluetoothPanel(make_client(self.source), **self._options)
        self.panel.audio_available = self.source == "bluez"
        if not self.panel.audio_available:
            self.panel.output_button.setToolTip(tr("Audio output needs BlueZ: choose BlueZ "
                                                   "(system) as the adapter."))
        self._layout.addWidget(self.panel, 1)

    def start(self) -> None:
        if self.panel is not None:
            self.panel.start()

    def shutdown(self) -> None:
        if self.panel is not None:
            self.panel.shutdown()


def log_warning(text: str) -> None:
    import logging

    logging.getLogger(__name__).warning(text)


_PANELS: list[BluetoothHost] = []


def activate(api):
    window = getattr(api, "window", None)
    open_settings = getattr(window, "open_settings", None)
    panel = BluetoothHost(read_source(), panel_options={
        "open_audio_settings": (lambda: open_settings("audio"))
        if callable(open_settings) else None,
        "presence_path": BP.default_path()})
    _PANELS.append(panel)
    api.add_dock(tr("Bluetooth"), panel, icon="bluetooth")

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
