"""The details of one Bluetooth device, and the map of its GATT services.

Opened from the Bluetooth panel (resources/extensions/bluetooth.py) with
*Details…* or a double-click on a device. *Overview* lists everything
BlueZ knows of the device: address and its type, kind, radio, vendor,
class and appearance, signal and transmit power, battery, when it was
last heard, its state and the raw advertising data. *Services* lists the
services and profiles it offers and, for a connected BLE device, the
GATT services BlueZ resolved with their characteristics. A readable one
can be read (*Read*, *Read All*), one that notifies can be watched
(*Watch*): each new value then shows as it comes. Known formats are
decoded (core.bluetooth.decode_value): names, battery level, heart rate,
temperature, humidity.

The dialog follows the client's signals while it is open; it changes
nothing on the device but reads and notifications - and, on *Connection*,
what the user asks for there (core.bluetooth_link): connect or
disconnect one profile (A2DP, the headset profile with its microphone,
HID ...), *Reconnect automatically* when the connection drops, *Test
Connection* (connect, resolve, GATT round trip and audio output, each
timed), and for a speaker or headset *Play Test Sound* on its own output
and *Test Microphone* (a level meter on the headset's microphone).
"""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import bluetooth as BT
from core import bluetooth_adv as BA
from core import bluetooth_link as BTL
from core.i18n import format_percent, tr
from ui.icon_provider import set_window_icon

#: The test sound: two rising tones (Hz, seconds) - easy to tell from noise.
TEST_SOUND = ((660.0, 0.35), (880.0, 0.45))
TEST_RATE = 48000
#: How long Test Microphone shows the level.
MIC_SECONDS = 5.0

#: Overview rows: (key, label).
OVERVIEW = (
    ("name", "Name"), ("address", "Address"), ("kind", "Type"), ("radio", "Radio"),
    ("vendor", "Vendor"), ("class", "Device class"), ("appearance", "Appearance"),
    ("signal", "Signal"), ("tx_power", "Transmit power"), ("battery", "Battery"),
    ("seen", "Last heard"), ("state", "State"), ("advertises", "Advertises"),
    ("manufacturer", "Manufacturer data"),
    ("service_data", "Service data"), ("path", "BlueZ object"),
)
#: Shown for an Overview row the device does not report (blank looked broken).
NOT_REPORTED = "—"
TREE_COLUMNS = ("Name", "UUID", "Properties", "Value")
COL_NAME, COL_UUID, COL_FLAGS, COL_VALUE = range(len(TREE_COLUMNS))


def _hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def overview(device: BT.Device, now: float | None = None) -> dict[str, str]:
    """The Overview tab's texts of *device* (pure, for the tests)."""
    now = time.time() if now is None else now
    state = [w for w, on in (("Connected", device.connected), ("Paired", device.paired),
                             ("Bonded", device.bonded), ("Trusted", device.trusted),
                             ("Blocked", device.blocked),
                             ("Services resolved", device.services_resolved),
                             ("Legacy pairing", device.legacy_pairing)) if on]
    address = device.address
    if device.address_type:
        address = f"{address} ({tr(device.address_type)})"
    seen = ""
    if device.last_seen is not None:
        seen = tr("{n} s ago").format(n=max(0, int(now - device.last_seen)))
    return {
        "name": device.display_name if device.named or device.name else tr("(no name)"),
        "address": address,
        "kind": tr(device.kind),
        "radio": {"Classic": "Classic (BR/EDR)", "LE": "Bluetooth Low Energy",
                  "Dual": "Classic + Bluetooth Low Energy"}.get(device.bearer, ""),
        "vendor": device.vendor,
        "class": f"0x{device.device_class:06X} ({BA.class_text(device.device_class)})"
                 if device.device_class else "",
        "appearance": f"{tr(BT.device_kind('', 0, device.appearance))} "
                      f"(0x{device.appearance:04X})" if device.appearance else "",
        "signal": (f"{device.rssi} dBm, " + tr("about {distance}").format(
            distance=BT.distance_text(device.distance))) if device.rssi is not None else "",
        "tx_power": f"{device.tx_power} dBm" if device.tx_power is not None else "",
        "battery": format_percent(device.battery) if device.battery is not None else "",
        "seen": seen,
        "state": ", ".join(tr(w) for w in state),
        "advertises": "\n".join(ident.text() for ident in device.idents),
        "manufacturer": "\n".join(f"{BT.company_name(cid)}: {_hex(data)}"
                                  for cid, data in device.manufacturer_data),
        "service_data": "\n".join(f"{BT.uuid_name(uuid)}: {_hex(data)}"
                                  for uuid, data in device.service_data),
        "path": device.path,
    }


def test_sound() -> bytes:
    """The test sound as int16 mono PCM at TEST_RATE."""
    from ui.audio_settings_page import sine_tone

    return b"".join(sine_tone(TEST_RATE, seconds, hz) for hz, seconds in TEST_SOUND)


def _default_player(device_id: str):
    from core import audio_route
    from ui.audio_settings_page import _make_player

    return _make_player(device_id, audio_route.output_gain())


def _default_recorder(device_id: str):
    from ui.audio_settings_page import _make_recorder

    return _make_recorder(device_id, 1.0)


class DeviceDialog(QDialog):
    def __init__(self, client: BT.BluezClient, path: str, parent: QWidget | None = None, *,
                 reconnector: BTL.Reconnector | None = None, sink_lister=None,
                 source_lister=None, make_player=None, make_recorder=None,
                 test_options: dict | None = None) -> None:
        super().__init__(parent)
        set_window_icon(self, "bluetooth")
        self.client = client
        self.path = path
        self.gone = False
        self._left = False  # see _leave
        self.reconnector = reconnector
        #: seams: Qt's outputs / inputs as (id, description), the players
        self._sink_lister = sink_lister
        self._source_lister = source_lister
        self._make_player = make_player or _default_player
        self._make_recorder = make_recorder or _default_recorder
        self._test_options = dict(test_options or {})
        self._test: BTL.ConnectionTest | None = None
        self._player = None
        self._recorder = None
        self._mic_timer = QTimer(self)
        self._mic_timer.setSingleShot(True)
        self._mic_timer.timeout.connect(self._mic_time_up)
        self.setWindowTitle(tr("Bluetooth Device"))
        self.resize(640, 520)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        # -- overview
        page = QWidget()
        form = QFormLayout(page)
        self.fields: dict[str, QLabel] = {}
        for key, label in OVERVIEW:
            value = QLabel("")
            # The device's own texts: Qt would take "<b>" in a name for markup.
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            self.fields[key] = value
            form.addRow(tr(label) + ":", value)
        from ui.bluetooth_map import SignalGraph

        self.graph = SignalGraph()
        self.graph.setToolTip(tr("The signal of the last readings (-100 to -30 dBm)."))
        form.addRow(tr("Signal history") + ":", self.graph)
        self.tabs.addTab(page, tr("Overview"))

        # -- services
        page = QWidget()
        box = QVBoxLayout(page)
        box.addWidget(QLabel(tr("Offered services and profiles:")))
        self.offered = QListWidget()
        self.offered.setMaximumHeight(110)
        box.addWidget(self.offered)
        self.gatt_label = QLabel("")
        self.gatt_label.setWordWrap(True)
        box.addWidget(self.gatt_label)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(TREE_COLUMNS))
        self.tree.setHeaderLabels([tr(c) for c in TREE_COLUMNS])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        box.addWidget(self.tree, 1)
        row = QHBoxLayout()
        self.connect_button = QPushButton(tr("Connect"))
        self.connect_button.setToolTip(tr("Connect the device so BlueZ resolves its GATT "
                                          "services."))
        self.connect_button.clicked.connect(lambda: self.client.connect_device(self.path))
        self.read_button = QPushButton(tr("Read"))
        self.read_button.clicked.connect(self._read_selected)
        self.read_all_button = QPushButton(tr("Read All"))
        self.read_all_button.clicked.connect(self.read_all)
        self.watch_button = QPushButton(tr("Watch"))
        self.watch_button.setToolTip(tr("Show each new value the device sends (notifications)."))
        self.watch_button.clicked.connect(self._watch_clicked)
        for button in (self.connect_button, self.read_button, self.read_all_button,
                       self.watch_button):
            row.addWidget(button)
        row.addStretch(1)
        box.addLayout(row)
        self.tabs.addTab(page, tr("Services"))
        self._build_connection_tab()

        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)  # names and errors of the device
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        try:
            from ui.close_corner import add_close_corner

            add_close_corner(self)
        except ImportError:  # pragma: no cover - axross ships ui
            pass

        client.device_updated.connect(self._device_updated)
        client.devices_changed.connect(self._devices_changed)
        client.gatt_changed.connect(self._gatt_changed)
        client.operation_finished.connect(self._finished)
        self.refresh()

    def _build_connection_tab(self) -> None:
        page = QWidget()
        box = QVBoxLayout(page)
        group = QGroupBox(tr("Profiles"))
        row = QHBoxLayout(group)
        self.profile_combo = QComboBox()
        self.profile_combo.setToolTip(tr("Connect or disconnect one profile – e.g. the headset "
                                         "profile for the microphone next to A2DP for music."))
        row.addWidget(self.profile_combo, 1)
        self.profile_connect_button = QPushButton(tr("Connect Profile"))
        self.profile_connect_button.clicked.connect(lambda: self._profile(True))
        self.profile_disconnect_button = QPushButton(tr("Disconnect Profile"))
        self.profile_disconnect_button.clicked.connect(lambda: self._profile(False))
        row.addWidget(self.profile_connect_button)
        row.addWidget(self.profile_disconnect_button)
        box.addWidget(group)

        self.reconnect_check = QCheckBox(tr("Reconnect automatically when the connection drops"))
        self.reconnect_check.setToolTip(tr(
            "axross connects the device again after 2, 5, 15, 30 and 60 s while it runs. "
            "Trust lets the device reconnect by itself as well."))
        self.reconnect_check.toggled.connect(self._reconnect_toggled)
        self.reconnect_check.setVisible(self.reconnector is not None)
        box.addWidget(self.reconnect_check)

        group = QGroupBox(tr("Tests"))
        tests = QVBoxLayout(group)
        row = QHBoxLayout()
        self.test_button = QPushButton(tr("Test Connection"))
        self.test_button.setToolTip(tr("Connect if needed, then time the connection, the "
                                       "services, a few reads and the audio output."))
        self.test_button.clicked.connect(self.toggle_connection_test)
        row.addWidget(self.test_button)
        self.sound_button = QPushButton(tr("Play Test Sound"))
        self.sound_button.setToolTip(tr("Two short tones on this device's own audio output, "
                                        "whatever axross's output is."))
        self.sound_button.clicked.connect(self.play_test_sound)
        row.addWidget(self.sound_button)
        self.mic_button = QPushButton(tr("Test Microphone"))
        self.mic_button.setToolTip(tr("The level of this headset's microphone for a few "
                                      "seconds (needs the headset profile, HFP)."))
        self.mic_button.clicked.connect(self.toggle_microphone_test)
        row.addWidget(self.mic_button)
        row.addStretch(1)
        tests.addLayout(row)
        self.level_bar = QProgressBar()
        self.level_bar.setRange(0, 100)
        self.level_bar.setTextVisible(False)
        self.level_bar.setMaximumHeight(10)
        tests.addWidget(self.level_bar)
        self.test_label = QLabel("")
        self.test_label.setTextFormat(Qt.TextFormat.PlainText)  # names the device
        self.test_label.setWordWrap(True)
        tests.addWidget(self.test_label)
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText(tr("Test Connection reports here."))
        tests.addWidget(self.report, 1)
        box.addWidget(group, 1)
        self.tabs.addTab(page, tr("Connection"))

    def show_tab(self, name: str) -> None:
        """Bring a tab to the front: "overview", "services" or "connection"."""
        index = {"overview": 0, "services": 1, "connection": 2}.get(name)
        if index is not None:
            self.tabs.setCurrentIndex(index)

    # -- what is shown -------------------------------------------------------------------

    def device(self) -> BT.Device | None:
        return self.client.device(self.path)

    def refresh(self) -> None:
        self._fill_overview()
        self._fill_offered()
        self._fill_gatt()
        self._fill_connection()

    def _fill_connection(self) -> None:
        device = self.device()
        profiles = BTL.profiles_of(device) if device is not None else []
        current = self.profile_combo.currentData()
        wanted = [(tr(label), uuid) for uuid, label in profiles]
        if [(self.profile_combo.itemText(i), self.profile_combo.itemData(i))
                for i in range(self.profile_combo.count())] != wanted:
            self.profile_combo.clear()
            for label, uuid in wanted:
                self.profile_combo.addItem(label, uuid)
            index = self.profile_combo.findData(current)
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)
        if not wanted:
            self.profile_combo.addItem(tr("(no profile to connect on its own)"), None) \
                if self.profile_combo.count() == 0 else None
        if self.reconnector is not None and device is not None:
            self.reconnect_check.blockSignals(True)
            self.reconnect_check.setChecked(self.reconnector.enabled(device))
            self.reconnect_check.blockSignals(False)
        self._update_connection_buttons()

    def _update_connection_buttons(self) -> None:
        device = self.device()
        alive = device is not None and not self.gone
        idle = alive and self.client.busy(self.path) is None
        has_profile = self.profile_combo.currentData() is not None
        self.profile_connect_button.setEnabled(idle and has_profile)
        self.profile_disconnect_button.setEnabled(idle and has_profile and device.connected)
        self.reconnect_check.setEnabled(alive)
        testing = self._test is not None and self._test.running
        self.test_button.setText(tr("Stop Test") if testing else tr("Test Connection"))
        self.test_button.setEnabled(alive or testing)
        audio = alive and BT.is_audio_output(device)
        self.sound_button.setVisible(audio)
        self.mic_button.setVisible(audio)
        self.level_bar.setVisible(audio)
        self.sound_button.setEnabled(audio and device.connected and self._player is None)
        self.mic_button.setEnabled(audio and (device.connected or self._recorder is not None))

    def _fill_overview(self) -> None:
        device = self.device()
        if device is None:
            return
        self.setWindowTitle(tr("Bluetooth Device – {name}").format(name=device.display_name))
        for key, text in overview(device).items():
            label = self.fields[key]
            shown = text or NOT_REPORTED
            if label.text() != shown:
                label.setText(shown)
                label.setToolTip("" if text else tr("Not reported by the device"))
        self.graph.set_readings(self.client.rssi_history(self.path))

    def _fill_offered(self) -> None:
        device = self.device()
        uuids = device.uuids if device is not None else ()
        texts = [f"{BT.uuid_name(u)}  ({u})" if BT.uuid_name(u) != u else u for u in uuids]
        if [self.offered.item(i).text() for i in range(self.offered.count())] != texts:
            self.offered.clear()
            self.offered.addItems(texts)

    def selected_characteristic(self) -> str | None:
        items = self.tree.selectedItems()
        if not items or items[0].parent() is None:
            return None
        return items[0].data(COL_NAME, Qt.ItemDataRole.UserRole)

    def characteristic_item(self, path: str) -> QTreeWidgetItem | None:
        for i in range(self.tree.topLevelItemCount()):
            service = self.tree.topLevelItem(i)
            for j in range(service.childCount()):
                child = service.child(j)
                if child.data(COL_NAME, Qt.ItemDataRole.UserRole) == path:
                    return child
        return None

    def _structure(self) -> list:
        return [(self.tree.topLevelItem(i).data(COL_NAME, Qt.ItemDataRole.UserRole),
                 [self.tree.topLevelItem(i).child(j).data(COL_NAME, Qt.ItemDataRole.UserRole)
                  for j in range(self.tree.topLevelItem(i).childCount())])
                for i in range(self.tree.topLevelItemCount())]

    def _char_texts(self, char: BT.GattCharacteristic) -> list[str]:
        flags = ", ".join(char.flags)
        if char.notifying:
            flags = f"{flags} - {tr('watching')}"
        return [char.name, char.uuid, flags, char.value_text]

    def _fill_gatt(self) -> None:
        """The GATT tree: rebuilt when services come or go, else only the
        texts change (selection and folding stay)."""
        services = self.client.gatt_services(self.path)
        wanted = [(s.path, [c.path for c in s.characteristics]) for s in services]
        if wanted != self._structure():
            selected = self.selected_characteristic()
            self.tree.clear()
            for service in services:
                top = QTreeWidgetItem([service.name if service.primary
                                       else tr("{name} (secondary)").format(name=service.name),
                                       service.uuid, "", ""])
                top.setData(COL_NAME, Qt.ItemDataRole.UserRole, service.path)
                for char in service.characteristics:
                    child = QTreeWidgetItem(self._char_texts(char))
                    child.setData(COL_NAME, Qt.ItemDataRole.UserRole, char.path)
                    top.addChild(child)
                self.tree.addTopLevelItem(top)
                top.setExpanded(True)
            if selected:
                item = self.characteristic_item(selected)
                if item is not None:
                    item.setSelected(True)
            for col in (COL_NAME, COL_UUID, COL_FLAGS):
                self.tree.resizeColumnToContents(col)
        else:
            for service in services:
                for char in service.characteristics:
                    item = self.characteristic_item(char.path)
                    for col, text in enumerate(self._char_texts(char)):
                        if item is not None and item.text(col) != text:
                            item.setText(col, text)
        self._update_gatt_label(services)
        self._update_buttons()

    def _update_gatt_label(self, services) -> None:
        device = self.device()
        if self.gone or device is None:
            text = tr("The device is gone.")
        elif services:
            count = sum(len(s.characteristics) for s in services)
            text = tr("GATT: {services} services, {chars} characteristics.").format(
                services=len(services), chars=count)
        elif not device.connected:
            text = tr("Connect the device to map its GATT services (BLE devices).")
        elif not device.services_resolved:
            text = tr("Waiting for BlueZ to resolve the services…")
        else:
            text = tr("The device offers no GATT services.")
        self.gatt_label.setText(text)

    def _characteristics(self) -> list[BT.GattCharacteristic]:
        return [c for s in self.client.gatt_services(self.path) for c in s.characteristics]

    def _update_buttons(self) -> None:
        device = self.device()
        alive = device is not None and not self.gone
        self.connect_button.setVisible(alive and not device.connected)
        self.connect_button.setEnabled(alive and self.client.busy(self.path) is None)
        selected = self.selected_characteristic()
        char = next((c for c in self._characteristics() if c.path == selected), None)
        idle = alive and char is not None and self.client.busy(char.path) is None
        self.read_button.setEnabled(idle and char.readable)
        self.read_all_button.setEnabled(alive and any(c.readable for c in self._characteristics()))
        self.watch_button.setEnabled(idle and char.notifiable)
        self.watch_button.setText(tr("Stop Watching") if char is not None and char.notifying
                                  else tr("Watch"))

    # -- actions ---------------------------------------------------------------------------

    def _read_selected(self) -> None:
        path = self.selected_characteristic()
        if path:
            self.client.read_characteristic(path)

    def read_all(self) -> None:
        for char in self._characteristics():
            if char.readable and self.client.busy(char.path) is None:
                self.client.read_characteristic(char.path)

    def _watch_clicked(self) -> None:
        path = self.selected_characteristic()
        char = next((c for c in self._characteristics() if c.path == path), None)
        if char is not None:
            self.client.set_notify(char.path, not char.notifying)

    # -- the client's signals --------------------------------------------------------------

    def _device_updated(self, path: str) -> None:
        if path == self.path:
            self._fill_overview()
            self._fill_offered()
            self._fill_connection()
            self._update_gatt_label(self.client.gatt_services(self.path))
            self._update_buttons()

    def _devices_changed(self) -> None:
        if self.device() is None and not self.gone:
            self.gone = True
            self.message.setText(tr("BlueZ forgot the device (removed, or out of range)."))
            self._stop_audio_tests()
            self._fill_gatt()
            self._update_connection_buttons()
        elif self.gone and self.device() is not None:
            # Back under the same path (BlueZ drops a device it has not
            # heard for a while and adds it again when found): alive again.
            self.gone = False
            self.message.setText("")
            self._device_updated(self.path)
            self._fill_gatt()

    def _gatt_changed(self, device: str) -> None:
        if device == self.path:
            self._fill_gatt()

    def _finished(self, path: str, op: str, error: str) -> None:
        if path != self.path and self.client.device_of(path) != self.path:
            return
        if error and op in ("read", "notify", "stop-notify", "connect", "connect-profile",
                            "disconnect-profile"):
            item = self.characteristic_item(path)
            what = item.text(COL_NAME) if item is not None else self.path.rsplit("/", 1)[-1]
            if item is None and self.device() is not None:
                what = self.device().display_name
            self.message.setText(f"{what}: {error}")
        elif not error and op in ("connect-profile", "disconnect-profile"):
            self.message.setText((tr("{profile} connected.") if op == "connect-profile"
                                  else tr("{profile} disconnected."))
                                 .format(profile=self.profile_combo.currentText()))
        self._update_buttons()
        self._update_connection_buttons()

    # -- connection options and tests ------------------------------------------------------

    def _profile(self, connect: bool) -> None:
        uuid = self.profile_combo.currentData()
        if not uuid:
            return
        if connect:
            self.client.connect_profile(self.path, uuid)
        else:
            if self.reconnector is not None:
                self.reconnector.expect_disconnect(self.path)
            self.client.disconnect_profile(self.path, uuid)

    def _reconnect_toggled(self, on: bool) -> None:
        device = self.device()
        if self.reconnector is None or device is None:
            return
        try:
            self.reconnector.set_enabled(device, on)
        except OSError as exc:
            self.reconnect_check.blockSignals(True)
            self.reconnect_check.setChecked(not on)
            self.reconnect_check.blockSignals(False)
            self.message.setText(tr("Could not save the choice: {error}").format(error=exc))

    def toggle_connection_test(self) -> None:
        if self._test is not None and self._test.running:
            self._test.cancel()
            self.test_label.setText(tr("Test stopped."))
            self._update_connection_buttons()
            return
        test = BTL.ConnectionTest(self.client, self.path, sink_lister=self._sink_lister,
                                  parent=self, **self._test_options)
        test.progress.connect(self.test_label.setText)
        test.finished.connect(self._test_finished)
        self._test = test
        self.report.clear()
        test.start()
        self._update_connection_buttons()

    def _test_finished(self, steps) -> None:
        self.report.setPlainText(BTL.report_text(steps))
        failed = [s for s in steps if s.ok is False]
        self.test_label.setText(tr("Test finished: {n} problems.").format(n=len(failed))
                                if failed else tr("Test finished: everything worked."))
        self._update_connection_buttons()

    def _with_audio(self, then) -> None:
        """*then()* once Qt's devices may be listed (the multimedia probe
        answered ok - its rule); a failed probe is said instead."""
        if self._sink_lister is not None or self._source_lister is not None:
            then()
            return
        from core import multimedia_probe as MPROBE

        def probed(result) -> None:
            if sip_alive(self):
                if result.ok:
                    then()
                else:
                    self.test_label.setText(MPROBE.unavailable_text(result))

        MPROBE.probe_async(probed, context=self)

    def play_test_sound(self) -> None:
        device = self.device()
        if device is None or self._player is not None:
            return
        self.test_label.setText(tr("Looking for the audio output of {device}…")
                                .format(device=device.display_name))
        self._with_audio(lambda: self._play_on(device))

    def _play_on(self, device: BT.Device) -> None:
        lister = self._sink_lister or BT.qt_audio_outputs
        try:
            sink = BT.find_sink(lister(), device)
        except Exception as exc:  # noqa: BLE001 - the audio stack said no: say it
            self.test_label.setText(tr("No sound: {error}").format(error=exc))
            return
        if sink is None:
            self.test_label.setText(tr(
                "{device} has no audio output in the sound server – its A2DP profile may not "
                "be connected (Connect Profile: Audio playback).").format(
                device=device.display_name))
            return
        try:
            player = self._make_player(sink[0])
        except OSError as exc:
            self.test_label.setText(tr("No sound: {error}").format(error=exc))
            return
        self._player = player
        player.failed.connect(lambda why: self.test_label.setText(
            tr("No sound: {error}").format(error=why)))
        player.drained.connect(lambda: self._sound_played(player))
        self.test_label.setText(tr("Playing the test sound on {output}…").format(output=sink[1]))
        player.enqueue(test_sound(), TEST_RATE)
        self._update_connection_buttons()

    def _sound_played(self, player) -> None:
        if player is not self._player:
            return
        self._player = None
        player.stop()
        if not self.test_label.text().startswith(tr("No sound: {error}").split("{")[0]):
            self.test_label.setText(tr("Test sound played."))
        self._update_connection_buttons()

    def toggle_microphone_test(self) -> None:
        if self._recorder is not None:
            self._stop_recorder()
            self.test_label.setText(tr("Microphone test stopped."))
            return
        device = self.device()
        if device is None:
            return
        self._with_audio(lambda: self._record_from(device))

    def _record_from(self, device: BT.Device) -> None:
        lister = self._source_lister or BTL.qt_audio_inputs
        try:
            source = BTL.find_source(lister(), device)
        except Exception as exc:  # noqa: BLE001
            self.test_label.setText(tr("The microphone does not work: {error}").format(error=exc))
            return
        if source is None:
            hfp = BTL.HFP_UUID in device.uuids
            self.test_label.setText(
                tr("{device} has no microphone in the sound server. A headset offers it only "
                   "in its headset profile: Connect Profile: Headset with microphone (HFP).")
                .format(device=device.display_name) if hfp else
                tr("{device} offers no microphone (no headset profile).")
                .format(device=device.display_name))
            return
        try:
            recorder = self._make_recorder(source[0])
            recorder.data.connect(self._heard)
            recorder.start()
        except OSError as exc:
            self.test_label.setText(tr("The microphone does not work: {error}").format(error=exc))
            return
        self._recorder = recorder
        self._mic_timer.start(int(MIC_SECONDS * 1000))
        self.mic_button.setText(tr("Stop"))
        self.test_label.setText(tr("Speak into {input}…").format(input=source[1]))
        self._update_connection_buttons()

    def _heard(self, pcm: bytes) -> None:
        if self._recorder is None:
            return
        from core import voice_audio as VA

        self.level_bar.setValue(int(round(VA.level(pcm) * 100)))

    def _mic_time_up(self) -> None:
        self._stop_recorder()
        self.test_label.setText(tr("Microphone test finished."))

    def _stop_recorder(self) -> None:
        self._mic_timer.stop()
        recorder, self._recorder = self._recorder, None
        if recorder is not None:
            try:
                recorder.stop()
            except Exception:  # noqa: BLE001 - stopping must not fail
                pass
        self.level_bar.setValue(0)
        self.mic_button.setText(tr("Test Microphone"))
        self._update_connection_buttons()

    def _stop_audio_tests(self) -> None:
        self._stop_recorder()
        player, self._player = self._player, None
        if player is not None:
            player.stop()
        if self._test is not None and self._test.running:
            self._test.cancel()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._leave()
        super().closeEvent(event)

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        # reject() (Escape, the corner's [x]) ends here without a closeEvent
        self._leave()
        super().done(result)

    def _leave(self) -> None:
        """What leaving the dialog undoes, once however it is left: the
        audio tests stop, the notifications it watches are switched off and
        the client's signals no longer reach it. It lived in closeEvent
        only, which Escape and the corner's [x] (reject()) never send: the
        watched characteristics went on notifying, at the device's battery."""
        if self._left:
            return
        self._left = True
        self._stop_audio_tests()
        # notifications cost the device's battery: stop the ones we started
        for char in self._characteristics():
            if char.notifying:
                self.client.set_notify(char.path, False)
        for signal, slot in ((self.client.device_updated, self._device_updated),
                             (self.client.devices_changed, self._devices_changed),
                             (self.client.gatt_changed, self._gatt_changed),
                             (self.client.operation_finished, self._finished)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass


def sip_alive(obj) -> bool:
    from PyQt6 import sip

    return not sip.isdeleted(obj)


__all__ = ["DeviceDialog", "OVERVIEW", "TEST_SOUND", "overview", "test_sound"]
