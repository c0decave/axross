"""A Bluetooth device's details and the map of its GATT services.

The request: the Bluetooth panel should show the devices nearby and map
them - for a BLE device that is its GATT database: the services BlueZ
resolves once it is connected, their characteristics, and their values.
core.bluetooth keeps GattService1 / GattCharacteristic1 objects, reads a
characteristic (ReadValue), turns notifications on and off and decodes
the known formats; ui/bluetooth_details.py shows all of it, opened from
the panel with *Details…* or a double-click.

Driven against tests/fake_bluez.py on a private D-Bus: the fake adds a
device's GATT objects when it connects and removes them when it
disconnects, as BlueZ does.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from ui import bluetooth_details as BD  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_details", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_details"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
BAND = "E0:11:22:33:44:88"
SPEAKER = "AA:BB:CC:DD:EE:01"


def u16(n: int) -> str:
    return f"0000{n:04x}-0000-1000-8000-00805f9b34fb"


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


#: A fitness band: Generic Access (name), Battery (level, notifies), Heart
#: Rate (measurement notifies, not readable), and a vendor service.
BAND_GATT = [
    {"uuid": u16(0x1800), "chars": [
        {"uuid": u16(0x2A00), "flags": ["read"], "value": list(b"Band 7")},
        {"uuid": u16(0x2A01), "flags": ["read"], "value": [0xC1, 0x00]}]},
    {"uuid": u16(0x180F), "chars": [
        {"uuid": u16(0x2A19), "flags": ["read", "notify"], "value": [64]}]},
    {"uuid": u16(0x180D), "chars": [
        {"uuid": u16(0x2A37), "flags": ["notify"]}]},
    {"uuid": "6e400001-b5a3-f393-e0a9-e50e24dcca9e", "primary": False, "chars": [
        {"uuid": "6e400003-b5a3-f393-e0a9-e50e24dcca9e", "flags": ["read"],
         "read": "error:org.bluez.Error.NotAuthorized:Not Authorized"}]},
]


def band(connected=False, **over):
    spec = {"address": BAND, "gatt": BAND_GATT,
            "props": {"Name": "Band 7", "Alias": "Band 7", "AddressType": "random",
                      "Appearance": 0x00C1, "TxPower": 0, "RSSI": -61, "Paired": True,
                      "Connected": connected, "UUIDs": [u16(0x180F), u16(0x180D)],
                      "ManufacturerData": {"135": [1, 2, 3]},
                      "ServiceData": {u16(0xFE95): [0x30, 0x58]}}}
    spec.update(over)
    return spec


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


@pytest.fixture
def client(fake):
    made = []

    def build(*devices):
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        for spec in devices:
            fake.command("add_device", **spec)
        c = BT.BluezClient(bus=fake.qt_connection())
        c.finished = []
        c.operation_finished.connect(lambda p, op, err: c.finished.append((p, op, err)))
        c.start()
        assert wait_until(lambda: c.state == "ready")
        made.append(c)
        return c

    yield build
    for c in made:
        c.shutdown()


def chars(c, device=dev_path(BAND)) -> dict[str, BT.GattCharacteristic]:
    return {ch.uuid: ch for s in c.gatt_services(device) for ch in s.characteristics}


def result(c, path, op, timeout=8.0):
    def found():
        return next((e for p, o, e in c.finished if p == path and o == op), None)

    assert wait_until(lambda: found() is not None, timeout), c.finished
    return found()


# =====================================================================================
# decoding
# =====================================================================================

class TestDecode:
    def test_happy_known_formats(self):
        assert BT.decode_value(u16(0x2A00), b"Band 7\x00") == "Band 7"
        assert BT.decode_value(u16(0x2A19), b"\x40") == "64 %"
        assert BT.decode_value(u16(0x2A01), b"\xc1\x00") == "Watch (0x00C1)"
        assert BT.decode_value(u16(0x2A07), b"\xfc") == "-4 dBm"
        assert BT.decode_value(u16(0x2A37), b"\x00\x48") == "72 bpm"
        assert BT.decode_value(u16(0x2A37), b"\x01\x2c\x01") == "300 bpm"
        assert BT.decode_value(u16(0x2A6E), b"\x2a\x09") == "23.46 °C"
        assert BT.decode_value(u16(0x2A6E), b"\x00\xff") == "-2.56 °C"
        assert BT.decode_value(u16(0x2A6F), b"\x88\x13") == "50.00 %"
        assert BT.decode_value(u16(0x2A6D), (101325 * 10).to_bytes(4, "little")) \
            == "1013.2 hPa"

    def test_happy_unknown_is_text_or_hex(self):
        assert BT.decode_value("custom", b"hello") == '"hello"'
        assert BT.decode_value("custom", b"\x00\x01\xff") == "00 01 FF"

    def test_sad_short_or_empty_values_do_not_raise(self):
        assert BT.decode_value(u16(0x2A19), b"") == "(empty)"
        assert BT.decode_value(u16(0x2A37), b"\x01\x2c") == "01 2C"
        assert BT.decode_value(u16(0x2A6E), b"\x01") == "01"
        assert BT.decode_value(u16(0x2A00), b"\xff\xfe") == "��"


# =====================================================================================
# the client
# =====================================================================================

class TestGatt:
    def test_happy_services_appear_on_connect_and_go_on_disconnect(self, client):
        c = client(band())
        path = dev_path(BAND)
        assert c.gatt_services(path) == []
        seen = []
        c.gatt_changed.connect(seen.append)
        c.connect_device(path)
        assert result(c, path, "connect") == ""
        assert wait_until(lambda: len(c.gatt_services(path)) == 4)
        assert wait_until(lambda: c.device(path).services_resolved)
        services = c.gatt_services(path)
        assert [s.name for s in services] == ["Generic Access", "Battery", "Heart Rate",
                                              "6e400001-b5a3-f393-e0a9-e50e24dcca9e"]
        assert services[3].primary is False
        assert [ch.name for ch in services[0].characteristics] == ["Device Name", "Appearance"]
        hr = services[2].characteristics[0]
        assert hr.notifiable and not hr.readable and hr.value is None
        assert set(seen) == {path}
        assert c.device_of(hr.path) == path
        c.disconnect_device(path)
        assert wait_until(lambda: c.gatt_services(path) == [])
        assert not any(p.startswith(path + "/") for p in c._objects)

    def test_happy_read_a_characteristic(self, client):
        c = client(band(connected=True))
        battery = chars(c)[u16(0x2A19)]
        c.read_characteristic(battery.path)
        assert result(c, battery.path, "read") == ""
        assert chars(c)[u16(0x2A19)].value == b"\x40"
        assert chars(c)[u16(0x2A19)].value_text == "64 %"

    def test_happy_notifications_deliver_values(self, client, fake):
        c = client(band(connected=True))
        hr = chars(c)[u16(0x2A37)]
        c.set_notify(hr.path, True)
        assert result(c, hr.path, "notify") == ""
        assert wait_until(lambda: chars(c)[u16(0x2A37)].notifying)
        fake.command("notify", path=hr.path, value=[0, 81])
        assert wait_until(lambda: chars(c)[u16(0x2A37)].value_text == "81 bpm")
        c.set_notify(hr.path, False)
        assert result(c, hr.path, "stop-notify") == ""
        assert wait_until(lambda: not chars(c)[u16(0x2A37)].notifying)

    def test_sad_reading_what_is_not_readable(self, client):
        c = client(band(connected=True))
        hr = chars(c)[u16(0x2A37)]
        c.read_characteristic(hr.path)
        assert "does not allow" in result(c, hr.path, "read")
        secret = chars(c)["6e400003-b5a3-f393-e0a9-e50e24dcca9e"]
        c.read_characteristic(secret.path)
        assert "not authorized" in result(c, secret.path, "read")
        assert chars(c)["6e400003-b5a3-f393-e0a9-e50e24dcca9e"].value is None

    def test_sad_notify_on_a_characteristic_that_cannot(self, client):
        c = client(band(connected=True))
        name = chars(c)[u16(0x2A00)]
        c.set_notify(name.path, True)
        assert "does not support" in result(c, name.path, "notify")

    def test_sad_read_on_something_that_is_no_characteristic(self, client):
        c = client(band(connected=True))
        c.read_characteristic(dev_path(BAND))
        assert result(c, dev_path(BAND), "read")  # refused, said through the signal

    def test_edge_a_device_without_gatt_has_none(self, client):
        c = client({"address": SPEAKER, "props": {"Name": "Desk", "Class": 0x240414}})
        c.connect_device(dev_path(SPEAKER))
        assert result(c, dev_path(SPEAKER), "connect") == ""
        assert c.gatt_services(dev_path(SPEAKER)) == []

    def test_edge_a_cached_value_is_there_before_a_read(self, client):
        gatt = [{"uuid": u16(0x180F), "chars": [
            {"uuid": u16(0x2A19), "flags": ["read"], "value": [10], "cached": [55]}]}]
        c = client(band(connected=True, gatt=gatt))
        assert chars(c)[u16(0x2A19)].value_text == "55 %"

    def test_edge_device_of_a_stranger(self, client):
        c = client()
        assert c.device_of("/org/bluez/hci0/dev_00/service0001") is None
        assert c.device_of("") is None


# =====================================================================================
# the dialog
# =====================================================================================

def test_happy_overview_texts():
    device = BT.Device.from_props(dev_path(BAND), {
        "Address": BAND, "AddressType": "random", "Name": "Band 7", "Appearance": 0x00C1,
        "TxPower": 0, "RSSI": -61, "Paired": True, "Bonded": True, "Class": 0x5A020C,
        "ManufacturerData": {0x0087: b"\x01\x02"},
        "ServiceData": {u16(0xFE95): b"\x30"}}, {"Percentage": 80}, 100.0)
    texts = BD.overview(device, now=112.0)
    assert texts["address"] == f"{BAND} (random)"
    assert texts["kind"] == "Watch" and texts["radio"] == "Classic + Bluetooth Low Energy"
    assert texts["appearance"] == "Watch (0x00C1)"
    assert texts["class"] == ("0x5A020C (Phone; services: Networking, Capturing, "
                              "Object transfer, Telephony)")
    assert texts["signal"] == "-61 dBm, about ~8 m" and texts["tx_power"] == "0 dBm"
    assert texts["battery"] == "80 %" and texts["seen"] == "12 s ago"
    assert texts["state"] == "Paired, Bonded"
    assert texts["manufacturer"] == "Garmin: 01 02"
    assert texts["service_data"] == "Xiaomi: 30"


def test_edge_overview_of_a_bare_device():
    texts = BD.overview(BT.Device.from_props("/x/dev_1", {"Address": BAND,
                                                         "Alias": "E0-11-22-33-44-88"}, None))
    assert texts["name"] == "(no name)"
    assert texts["signal"] == texts["battery"] == texts["seen"] == texts["appearance"] == ""


class Panel:
    def __init__(self, fake, *devices):
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        for spec in devices:
            fake.command("add_device", **spec)
        self.client = BT.BluezClient(bus=fake.qt_connection())
        self.panel = BTX.BluetoothPanel(self.client, sink_lister=list)
        self.panel.resize(900, 420)
        self.panel.show()
        self.panel.start()
        assert wait_until(lambda: self.client.state == "ready")

    def double_click(self, path: str) -> None:
        assert wait_until(lambda: self.panel._row_of(path) >= 0)
        table = self.panel.table
        rect = table.visualItemRect(table.item(self.panel._row_of(path), 0))
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
        QTest.mouseDClick(table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())

    def close(self):
        self.panel.shutdown()
        self.panel.close()
        self.panel.deleteLater()


@pytest.fixture
def panel(fake):
    made = []

    def build(*devices):
        p = Panel(fake, *devices)
        made.append(p)
        return p

    yield build
    for p in made:
        p.close()


def select_char(dialog, name: str):
    for i in range(dialog.tree.topLevelItemCount()):
        top = dialog.tree.topLevelItem(i)
        for j in range(top.childCount()):
            if top.child(j).text(BD.COL_NAME) == name:
                dialog.tree.setCurrentItem(top.child(j))
                return top.child(j)
    raise AssertionError(f"no characteristic {name}")


def test_happy_details_map_and_read_the_gatt_services_e2e(panel, fake):
    p = panel(band())
    p.double_click(dev_path(BAND))
    dialog = p.panel._details.get(dev_path(BAND))
    assert dialog is not None and dialog.isVisible()
    assert dialog.fields["kind"].text() == "Watch"
    assert dialog.fields["vendor"].text() == "Garmin"
    assert "Battery" in [dialog.offered.item(i).text().split("  ")[0]
                         for i in range(dialog.offered.count())]
    dialog.tabs.setCurrentIndex(1)
    assert "Connect the device" in dialog.gatt_label.text()
    assert dialog.connect_button.isVisible()
    QTest.mouseClick(dialog.connect_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: dialog.tree.topLevelItemCount() == 4)
    assert wait_until(lambda: "4 services, 5 characteristics" in dialog.gatt_label.text())
    assert not dialog.connect_button.isVisible()
    # read all: what is readable gets its value, the refusal is said
    QTest.mouseClick(dialog.read_all_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: select_char(dialog, "Battery Level").text(BD.COL_VALUE) == "64 %")
    assert select_char(dialog, "Device Name").text(BD.COL_VALUE) == "Band 7"
    assert select_char(dialog, "Appearance").text(BD.COL_VALUE) == "Watch (0x00C1)"
    assert wait_until(lambda: "not authorized" in dialog.message.text())
    # watch the heart rate
    select_char(dialog, "Heart Rate Measurement")
    assert dialog.watch_button.isEnabled() and not dialog.read_button.isEnabled()
    QTest.mouseClick(dialog.watch_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: dialog.watch_button.text() == "Stop Watching")
    hr_path = select_char(dialog, "Heart Rate Measurement").data(BD.COL_NAME,
                                                                Qt.ItemDataRole.UserRole)
    fake.command("notify", path=hr_path, value=[0, 77])
    assert wait_until(lambda: select_char(dialog, "Heart Rate Measurement")
                      .text(BD.COL_VALUE) == "77 bpm")
    # closing stops the notifications it started
    dialog.close()
    assert wait_until(lambda: not chars(p.client)[u16(0x2A37)].notifying)
    assert wait_until(lambda: dev_path(BAND) not in p.panel._details)


def test_happy_one_dialog_per_device(panel):
    p = panel(band())
    assert wait_until(lambda: p.panel._row_of(dev_path(BAND)) >= 0)
    first = p.panel.open_details(dev_path(BAND))
    assert p.panel.open_details(dev_path(BAND)) is first
    assert p.panel.open_details("/org/bluez/hci0/dev_nothing") is None


def test_sad_the_device_goes_while_its_dialog_is_open(panel, fake):
    p = panel(band(connected=True))
    assert wait_until(lambda: p.panel._row_of(dev_path(BAND)) >= 0)
    dialog = p.panel.open_details(dev_path(BAND))
    assert wait_until(lambda: dialog.tree.topLevelItemCount() == 4)
    fake.command("remove", path=dev_path(BAND))
    assert wait_until(lambda: dialog.gone)
    assert "forgot the device" in dialog.message.text()
    assert dialog.gatt_label.text() == "The device is gone."
    assert not dialog.read_all_button.isEnabled()


def test_edge_the_device_comes_back_while_its_dialog_is_open(panel, fake):
    """BlueZ drops a device it has not heard for a while and adds it again
    under the same path when it is found again. The dialog stayed "gone"
    for good: every button disabled, "The device is gone." - until it was
    closed and opened again."""
    p = panel(band())
    assert wait_until(lambda: p.panel._row_of(dev_path(BAND)) >= 0)
    dialog = p.panel.open_details(dev_path(BAND))
    fake.command("remove", path=dev_path(BAND))
    assert wait_until(lambda: dialog.gone)
    fake.command("add_device", **band())
    assert wait_until(lambda: not dialog.gone)
    assert "forgot the device" not in dialog.message.text()
    assert dialog.gatt_label.text() != "The device is gone."
    assert dialog.connect_button.isEnabled()


def test_edge_values_update_without_rebuilding_the_tree(panel):
    p = panel(band(connected=True))
    assert wait_until(lambda: p.panel._row_of(dev_path(BAND)) >= 0)
    dialog = p.panel.open_details(dev_path(BAND))
    assert wait_until(lambda: dialog.tree.topLevelItemCount() == 4)
    item = select_char(dialog, "Battery Level")
    QTest.mouseClick(dialog.read_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: item.text(BD.COL_VALUE) == "64 %")
    assert dialog.tree.currentItem() is item  # the same item: no rebuild


def test_edge_shutdown_closes_the_details(panel):
    p = panel(band())
    assert wait_until(lambda: p.panel._row_of(dev_path(BAND)) >= 0)
    dialog = p.panel.open_details(dev_path(BAND))
    p.panel.shutdown()
    assert sip.isdeleted(dialog) or not dialog.isVisible()
    assert p.panel._details == {}


def test_edge_details_button_follows_the_selection(panel):
    p = panel(band())
    assert not p.panel.details_button.isEnabled()
    p.double_click(dev_path(BAND))
    assert p.panel.details_button.isEnabled()


def test_edge_what_a_device_does_not_report_shows_a_dash_not_a_blank(panel):
    """Product review: Vendor, Device class, Appearance, Transmit power,
    Battery and the advertising data were empty rows, as if broken."""
    bare = {"address": "E0:11:22:33:44:99", "props": {"Alias": "E0-11-22-33-44-99", "RSSI": -70}}
    p = panel(bare)
    p.double_click(dev_path("E0:11:22:33:44:99"))
    dialog = p.panel._details.get(dev_path("E0:11:22:33:44:99"))
    assert dialog is not None
    for key in ("vendor", "class", "appearance", "tx_power", "battery", "manufacturer",
                "service_data"):
        field = dialog.fields[key]
        assert field.text() == BD.NOT_REPORTED, key
        assert field.toolTip() == "Not reported by the device"
    assert dialog.fields["signal"].text().startswith("-70 dBm")
    assert dialog.fields["signal"].toolTip() == ""
