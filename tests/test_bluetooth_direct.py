"""The Bluetooth panel without BlueZ: a stick driven directly (core.bluetooth_direct).

The request: the Bumble bridge as a product option - the panel on a USB
stick of its own, without BlueZ (also Windows, macOS). DirectClient is
BluezClient with Bumble in place of the D-Bus; these tests run it on
Bumble's virtual controllers (a LocalLink in the client's radio thread):
one is axross's stick, the other a BLE sensor with a Battery service. Over
the air with real sticks: tests/test_bluetooth_radio.py.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("bumble", reason="Bumble is not installed")

from bluez_testkit import wait_until  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from core import bluetooth_direct as BD  # noqa: E402

APP = QApplication.instance() or QApplication([])
HCI = BD.ADAPTER_PATH
OWN = "F0:F1:F2:F3:F4:01"
PEER = "F0:F1:F2:F3:F4:02"
BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"


class World:
    """The virtual radio: axross's controller and a peer device."""

    def __init__(self, peer_name: str = "axross-sensor", passkey: int | None = None) -> None:
        self.peer = None
        self.peer_name = peer_name
        self.passkey = passkey
        self.battery = None

    async def opener(self):
        from bumble.controller import Controller
        from bumble.core import AdvertisingData
        from bumble.device import Device
        from bumble.gatt import (
            GATT_BATTERY_LEVEL_CHARACTERISTIC,
            GATT_BATTERY_SERVICE,
            Characteristic,
            Service,
        )
        from bumble.hci import Address
        from bumble.link import LocalLink

        link = LocalLink()
        own = Controller("own", link=link, public_address=OWN)
        theirs = Controller("peer", link=link, public_address=PEER)
        peer = Device.with_hci(self.peer_name, Address(PEER), theirs, theirs)
        self.battery = Characteristic(
            GATT_BATTERY_LEVEL_CHARACTERISTIC,
            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
            Characteristic.READABLE, bytes([77]))
        peer.add_service(Service(GATT_BATTERY_SERVICE, [self.battery]))
        if self.passkey is not None:
            from bumble.pairing import PairingConfig, PairingDelegate

            world = self

            class Shows(PairingDelegate):
                def __init__(self):
                    super().__init__(io_capability=PairingDelegate.DISPLAY_OUTPUT_ONLY)

                async def generate_passkey(self) -> int:
                    return world.passkey

            peer.pairing_config_factory = lambda _c: PairingConfig(
                sc=True, mitm=True, bonding=True, delegate=Shows())
        await peer.power_on()
        peer.advertising_data = bytes(AdvertisingData([
            (AdvertisingData.FLAGS, bytes([0x06])),
            (AdvertisingData.COMPLETE_LOCAL_NAME, self.peer_name.encode()),
            (AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, bytes([0x0F, 0x18])),
            (AdvertisingData.MANUFACTURER_SPECIFIC_DATA, bytes([0x4C, 0x00, 0x12, 0x02, 0, 0])),
        ]))
        await peer.start_advertising(auto_restart=True)
        self.peer = peer
        return own, own, lambda: None


@pytest.fixture
def direct(tmp_path):
    made = []

    def build(world: World | None = None, keys: Path | None = None):
        world = world or World()
        client = BD.DirectClient("virtual", opener=world.opener,
                                 keys=keys or tmp_path / "keys.json", address=OWN)
        finished = []
        requests = []
        client.operation_finished.connect(lambda p, op, err: finished.append((p, op, err)))
        client.agent_request.connect(requests.append)
        client.finished, client.requests, client.world = finished, requests, world
        client.start()
        made.append(client)
        assert wait_until(lambda: client.state == "ready", 10), client.state_text()
        return client

    yield build
    for client in made:
        client.shutdown()


def result(client, path, op, timeout=15.0):
    def found():
        return next((err for p, o, err in client.finished if p == path and o == op), None)

    assert wait_until(lambda: found() is not None, timeout), client.finished
    return found()


def scan_for(client, name="axross-sensor") -> BT.Device:
    client.start_discovery(HCI, transport="le")
    assert result(client, HCI, "scan") == ""
    assert wait_until(lambda: any(d.name == name for d in client.devices()), 10)
    return next(d for d in client.devices() if d.name == name)


# =====================================================================================
# pure helpers
# =====================================================================================

def test_happy_adv_props_as_bluez_has_them():
    props = BD.adv_props([(0x01, b"\x06"), (0x09, b"Sensor"), (0x0A, b"\xfc"),
                          (0x19, b"\xc1\x00"), (0x03, b"\x0f\x18\x0a\x18"),
                          (0xFF, b"\x4c\x00\x01\x02"), (0x16, b"\xaa\xfe\x10")])
    assert props["Name"] == props["Alias"] == "Sensor"
    assert props["TxPower"] == -4 and props["Appearance"] == 0xC1
    assert props["UUIDs"] == [BD.uuid16(0x180F), BD.uuid16(0x180A)]
    assert props["ManufacturerData"] == {0x004C: b"\x01\x02"}
    assert props["ServiceData"] == {BD.uuid16(0xFEAA): b"\x10"}
    assert props["AdvertisingFlags"] == b"\x06"


def test_sad_a_name_from_the_air_is_plain_text():
    props = BD.adv_props([(0x09, b"Evil\n\x1b[31mName")])
    assert "\n" not in props["Name"] and "\x1b" not in props["Name"]


def test_edge_uuid_text_of_128_bits_and_flags():
    raw = bytes(range(16))
    assert BD.uuid_text(raw) == "0f0e0d0c-0b0a-0908-0706-050403020100"
    assert BD.gatt_flags(0x12) == ["read", "notify"]


def test_sad_without_libusb_there_are_no_sticks(monkeypatch):
    monkeypatch.setitem(sys.modules, "usb1", None)
    assert BD.list_sticks() == []


# =====================================================================================
# the client on the virtual radio
# =====================================================================================

def test_happy_scan_connect_read_notify_disconnect(direct):
    client = direct()
    [adapter] = client.adapters()
    assert adapter.address == OWN and adapter.powered
    sensor = scan_for(client)
    assert sensor.bearer == "LE" and sensor.rssi is not None
    assert "Battery" in sensor.services
    assert [i.name for i in sensor.idents] == ["Find My"]  # the Apple data decoded
    assert client.scanning(HCI)

    client.connect_device(sensor.path)
    assert result(client, sensor.path, "connect") == ""
    device = client.device(sensor.path)
    assert device.connected and device.services_resolved
    chars = {c.uuid: c for s in client.gatt_services(sensor.path) for c in s.characteristics}
    battery = chars[BATTERY_LEVEL]
    client.read_characteristic(battery.path)
    assert result(client, battery.path, "read") == ""

    def level():
        return next(c.value for s in client.gatt_services(sensor.path)
                    for c in s.characteristics if c.uuid == BATTERY_LEVEL)

    assert level() == bytes([77])
    client.set_notify(battery.path, True)
    assert result(client, battery.path, "notify") == ""
    world = client.world

    async def notify():
        world.battery.value = bytes([42])
        await world.peer.notify_subscribers(world.battery, bytes([42]))

    client._radio(notify())
    assert wait_until(lambda: level() == bytes([42]), 5)

    client.disconnect_device(sensor.path)
    assert result(client, sensor.path, "disconnect") == ""
    assert not client.device(sensor.path).connected
    assert client.gatt_services(sensor.path) == []


def test_happy_stop_scan_invalidates_the_signal_as_bluez(direct):
    client = direct()
    sensor = scan_for(client)
    client.stop_discovery(HCI)
    assert result(client, HCI, "stop-scan") == ""
    assert not client.scanning(HCI) and not client.adapter(HCI).discovering
    assert client.device(sensor.path).rssi is None
    assert client.device(sensor.path).name == "axross-sensor"  # the data stays


def test_happy_pairing_asks_the_user_and_the_bond_is_kept(direct, tmp_path):
    keys = tmp_path / "keys.json"
    client = direct(World(passkey=123456), keys=keys)
    sensor = scan_for(client)
    client.pair(sensor.path)
    assert wait_until(lambda: client.requests, 10), client.finished
    request = client.requests[0]
    assert request.kind == "passkey" and request.device_path == sensor.path
    client.answer(request.token, True, 123456)
    assert result(client, sensor.path, "pair", 20) == ""
    assert client.device(sensor.path).paired
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    assert PEER in json.dumps(json.loads(keys.read_text()))
    client.shutdown()

    again = direct(World(passkey=123456), keys=keys)
    known = again.device(BD.device_path(PEER))
    assert known is not None and known.paired  # bonded devices are known at the start

    again.remove_device(known.path)
    assert result(again, known.path, "remove") == ""
    assert again.device(known.path) is None
    assert PEER not in keys.read_text()


def test_sad_a_rejected_passkey_fails_the_pairing(direct):
    client = direct(World(passkey=123456))
    sensor = scan_for(client)
    client.pair(sensor.path)
    assert wait_until(lambda: client.requests, 10)
    client.answer(client.requests[0].token, False)
    error = result(client, sensor.path, "pair", 20)
    assert error and not client.device(sensor.path).paired


def test_sad_profiles_need_bluez(direct):
    client = direct()
    sensor = scan_for(client)
    client.connect_profile(sensor.path, BD.uuid16(0x110B))
    assert "BlueZ" in result(client, sensor.path, "connect-profile")


def test_sad_a_stick_that_cannot_be_opened_says_so(tmp_path):
    async def broken():
        raise OSError("LIBUSB_ERROR_ACCESS")

    client = BD.DirectClient("usb:9", opener=broken, keys=tmp_path / "k.json")
    client.start()
    try:
        assert wait_until(lambda: client.state == "unavailable", 10)
        assert "usb:9" in client.state_text() and "LIBUSB_ERROR_ACCESS" in client.state_text()
        client.start_discovery(HCI)  # refused, not a crash
        assert wait_until(lambda: False, 0.2) is False
    finally:
        client.shutdown()


def test_happy_the_panel_runs_on_the_direct_client(direct):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bundled_bluetooth_ext_direct", ROOT / "resources" / "extensions" / "bluetooth.py")
    ext = importlib.util.module_from_spec(spec)
    sys.modules["bundled_bluetooth_ext_direct"] = ext
    spec.loader.exec_module(ext)
    client = direct()
    panel = ext.BluetoothPanel(client, sink_lister=list)
    panel.show()
    try:
        panel.start()
        panel.scan_button.click()
        assert wait_until(lambda: panel.table.rowCount() >= 1, 10)
        row = panel._row_of(BD.device_path(PEER))
        assert row >= 0 and panel.table.item(row, ext.COL_NAME).text() == "axross-sensor"
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()


# =====================================================================================
# choosing the adapter: BlueZ or a stick used directly
# =====================================================================================

def _extension():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bundled_bluetooth_ext_host", ROOT / "resources" / "extensions" / "bluetooth.py")
    ext = importlib.util.module_from_spec(spec)
    sys.modules["bundled_bluetooth_ext_host"] = ext
    spec.loader.exec_module(ext)
    return ext


def test_happy_switching_to_a_stick_asks_first_and_is_kept(tmp_path, monkeypatch):
    ext = _extension()
    made = []

    def make_client(source="bluez"):
        if source == "bluez":
            client = BT.BluezClient(bus=None)  # no system bus here: "unavailable"
        else:
            client = BD.DirectClient(source, opener=World().opener,
                                     keys=tmp_path / "keys.json", address=OWN)
        made.append(client)
        return client

    monkeypatch.setattr(ext, "make_client", make_client)
    asked = []
    answer = {"ok": False}
    stick = {"transport": "usb:0A12:0001#0", "name": "CSR / Qualcomm 0A12:0001",
             "vid": 0x0A12, "pid": 1, "bus": 1, "address": 3, "serial": ""}
    choice = tmp_path / "bluetooth.json"
    host = ext.BluetoothHost("bluez", panel_options={"sink_lister": list},
                             sticks=lambda: [stick],
                             confirm=lambda text: asked.append(text) or answer["ok"],
                             source_path=choice)
    host.show()
    try:
        combo = host.source_combo
        assert [combo.itemData(i) for i in range(combo.count())] == ["bluez", "usb:0A12:0001#0"]
        assert "0A12:0001" in combo.itemText(1)
        first = host.panel
        combo.setCurrentIndex(1)
        combo.activated.emit(1)  # the user says no
        assert asked and host.source == "bluez" and host.panel is first
        assert combo.currentData() == "bluez"
        answer["ok"] = True
        combo.setCurrentIndex(1)
        combo.activated.emit(1)
        assert host.source == "usb:0A12:0001#0" and host.panel is not first
        assert isinstance(host.client, BD.DirectClient)
        assert wait_until(lambda: host.client.state == "ready", 10)
        assert ext.read_source(choice) == "usb:0A12:0001#0"
        assert stat.S_IMODE(choice.stat().st_mode) == 0o600
        assert not host.panel.audio_available
        assert "BlueZ" in host.panel.output_button.toolTip()
    finally:
        host.shutdown()
        host.close()
        host.deleteLater()


def test_edge_a_stick_not_plugged_in_stays_offered_and_bad_files_mean_bluez(tmp_path):
    ext = _extension()
    assert ext.read_source(tmp_path / "missing.json") == "bluez"
    bad = tmp_path / "bad.json"
    for text in ("not json", '{"source": 5}', '{"source": "/dev/evil"}', "[1]"):
        bad.write_text(text)
        assert ext.read_source(bad) == "bluez"
    host = ext.BluetoothHost.__new__(ext.BluetoothHost)  # only the combo filling
    from PyQt6.QtWidgets import QComboBox

    host.source_combo, host.source, host._sticks = QComboBox(), "usb:0A12:0001#4", lambda: []
    ext.BluetoothHost.fill_sources(host)
    assert host.source_combo.currentData() == "usb:0A12:0001#4"
    assert "not found" in host.source_combo.currentText()
    assert not ext.BluetoothHost._plugged_in(host, "usb:0A12:0001#4")  # shown, never taken


def test_sad_without_bumble_the_stick_entry_says_what_to_install(monkeypatch):
    ext = _extension()
    monkeypatch.setattr(BD, "available", lambda: False)
    from PyQt6.QtWidgets import QComboBox

    host = ext.BluetoothHost.__new__(ext.BluetoothHost)
    host.source_combo, host.source, host._sticks = QComboBox(), "bluez", None
    ext.BluetoothHost.fill_sources(host)
    assert host.source_combo.count() == 2
    assert "bluetooth-raw" in host.source_combo.itemText(1)
    assert not host.source_combo.model().item(1).isEnabled()


# =====================================================================================
# found in review: the stick is closed to strangers, pairings are ours only
# =====================================================================================

def test_sad_the_stick_is_not_open_to_devices_nearby(direct):
    client = direct()
    device = client._device
    assert not device.discoverable and not device.connectable
    assert not device.classic_accept_any


def test_sad_a_pairing_a_device_nearby_starts_is_refused_without_a_question(direct):
    import asyncio

    client = direct()
    conn = type("Conn", (), {"peer_address": PEER + "/P"})()
    delegate = BD._Delegate(client, conn)
    loop = asyncio.new_event_loop()
    try:
        assert loop.run_until_complete(delegate.accept()) is False
        assert loop.run_until_complete(delegate.confirm(auto=True)) is False
        assert loop.run_until_complete(delegate.get_number()) is None
    finally:
        loop.close()
    assert client.requests == []


def test_happy_cancel_stops_a_pairing_waiting_for_the_user(direct):
    client = direct(World(passkey=123456))
    sensor = scan_for(client)
    client.pair(sensor.path)
    assert wait_until(lambda: client.requests, 10)
    client.cancel_pairing(sensor.path)
    error = result(client, sensor.path, "pair", 20)
    assert error and not client.device(sensor.path).paired
    assert client.busy(sensor.path) is None and client._direct_requests == {}


def test_happy_connecting_while_scanning_keeps_the_scan(direct):
    client = direct()
    sensor = scan_for(client)
    client.connect_device(sensor.path)
    assert result(client, sensor.path, "connect") == ""
    assert client.scanning(HCI) and client.adapter(HCI).discovering
    assert wait_until(lambda: client._device.is_scanning, 5)


def test_happy_devices_not_heard_are_forgotten_as_bluez_does(direct):
    import time

    client = direct()
    sensor = scan_for(client)
    client.stop_discovery(HCI)
    assert result(client, HCI, "stop-scan") == ""
    client.forget_stale(now=time.time() + 5)
    assert client.device(sensor.path) is not None  # heard just now
    client.forget_stale(now=time.time() + BD.TEMPORARY_TIMEOUT_S + 5)
    assert client.device(sensor.path) is None and sensor.path not in client._addresses


def test_edge_a_bond_of_a_random_address_comes_back_random(tmp_path, direct):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({OWN: {"D4:11:22:33:44:55": {"address_type": 1},
                                      "00:01:95:53:6F:BC/P": {"address_type": 0}}}))
    os.chmod(keys, 0o600)
    client = direct(keys=keys)
    random_one = client.device(BD.device_path("D4:11:22:33:44:55"))
    public_one = client.device(BD.device_path("00:01:95:53:6F:BC"))
    assert random_one.paired and random_one.address_type == "random"
    assert public_one.address_type == "public"
