"""Scanning for Bluetooth Classic and BLE devices nearby.

The request: extend the Bluetooth panel with scanning, devices and a map of
the Bluetooth and BLE devices nearby. This file is the scanning half:
core.bluetooth reads what a BLE advertisement carries (address type,
appearance, TX power, manufacturer and service data, flags), says which
radio a device was seen on (Classic, LE, both), names services and
vendors, notes when a device was last heard, and scans with BlueZ's
discovery filter (Classic only, BLE only, a minimum signal). The panel
offers those as scan options, has a filter row and shows radio, vendor
and "seen" columns.

The client talks to tests/fake_bluez.py on a private D-Bus; the fake
checks SetDiscoveryFilter's argument types the way BlueZ does (RSSI must
be an int16) and reveals only the devices the filter lets through.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6.QtCore import QByteArray, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_scan", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_scan"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
SPEAKER = "AA:BB:CC:DD:EE:01"
TAG = "D4:11:22:33:44:55"
WATCH = "E0:11:22:33:44:66"
FAR = "C0:11:22:33:44:77"
A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"
BATTERY_SVC = "0000180f-0000-1000-8000-00805f9b34fb"
GAP = "00001800-0000-1000-8000-00805f9b34fb"


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


def classic_speaker(**over):
    spec = {"address": SPEAKER, "props": {"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                          "Icon": "audio-card", "Class": 0x240414,
                                          "UUIDs": [A2DP_SINK], "RSSI": -50}}
    spec.update(over)
    return spec


def ble_tag(**over):
    """A nameless BLE tracker: random address, Apple manufacturer data."""
    spec = {"address": TAG, "props": {"AddressType": "random",
                                      "ManufacturerData": {"76": [0x12, 0x19, 0x10]},
                                      "AdvertisingFlags": [0x06], "RSSI": -66}}
    spec.update(over)
    return spec


def ble_watch(**over):
    spec = {"address": WATCH, "props": {"Name": "Forerunner", "Alias": "Forerunner",
                                        "AddressType": "random", "Appearance": 0x00C1,
                                        "TxPower": 4, "UUIDs": [BATTERY_SVC],
                                        "ManufacturerData": {"135": [1, 2]}, "RSSI": -58}}
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

    def build(*devices, powered=True):
        fake.command("add_adapter", name="hci0", props={"Powered": powered, "Alias": "ws"})
        for spec in devices:
            fake.command("add_device", **spec)
        c = BT.BluezClient(bus=fake.qt_connection())
        finished = []
        c.operation_finished.connect(lambda p, op, err: finished.append((p, op, err)))
        c.finished = finished
        c.start()
        assert wait_until(lambda: c.state == "ready"), c.state
        made.append(c)
        return c

    yield build
    for c in made:
        c.shutdown()


def result(c, path, op, timeout=8.0):
    def found():
        return next((err for p, o, err in c.finished if p == path and o == op), None)

    assert wait_until(lambda: found() is not None, timeout), c.finished
    return found()


# =====================================================================================
# pure helpers
# =====================================================================================

class TestBearer:
    def test_happy_a_class_of_device_is_classic(self):
        assert BT.bearer(device_class=0x240414) == "Classic"

    def test_happy_a_random_address_or_advertising_data_is_le(self):
        assert BT.bearer(address_type="random") == "LE"
        assert BT.bearer(manufacturer_data=((76, b"\x01"),)) == "LE"
        assert BT.bearer(appearance=0x00C1) == "LE"
        assert BT.bearer(uuids=(BATTERY_SVC,)) == "LE"

    def test_happy_both_is_dual(self):
        assert BT.bearer(device_class=0x5a020c, tx_power=4) == "Dual"

    def test_edge_generic_access_alone_says_nothing(self):
        """BR/EDR devices list Generic Access / Attribute through SDP too."""
        assert BT.bearer(uuids=(GAP,)) == ""
        assert BT.bearer(uuids=(GAP, A2DP_SINK)) == "Classic"

    def test_edge_the_le_only_flag_wins(self):
        assert BT.bearer(device_class=0x240414, adv_flags=0x06) == "LE"
        assert BT.bearer(device_class=0x240414, adv_flags=0x02) == "Dual"


class TestNames:
    def test_happy_uuids_by_name(self):
        assert BT.uuid_name(A2DP_SINK) == "Audio Sink"
        assert BT.uuid_name(BATTERY_SVC.upper()) == "Battery"
        assert BT.short_uuid(BATTERY_SVC) == 0x180F

    def test_edge_unknown_uuids_stay_readable(self):
        assert BT.uuid_name("0000abcd-0000-1000-8000-00805f9b34fb") == "0xABCD"
        custom = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        assert BT.short_uuid(custom) is None and BT.uuid_name(custom) == custom
        assert BT.uuid_name("") == ""
        assert BT.short_uuid("0000zzzz-0000-1000-8000-00805f9b34fb") is None

    def test_happy_companies(self):
        assert BT.company_name(0x004C) == "Apple"
        assert BT.company_name(0xBEEF) == "Company 0xBEEF"


class TestKind:
    def test_happy_an_exact_appearance_beats_the_icon(self):
        assert BT.device_kind("audio-headset", 0, 0x0941) == "Earbuds"

    def test_happy_the_appearance_category_names_ble_devices(self):
        assert BT.device_kind("", 0, 0x00C1) == "Watch"
        assert BT.device_kind("", 0, 0x0200) == "Tag"
        assert BT.device_kind("", 0, 0x0A41) == "Hearing Aid"

    def test_edge_the_icon_beats_a_category(self):
        assert BT.device_kind("phone", 0, 0x00C1) == "Phone"

    def test_sad_nonsense_appearance_falls_back(self):
        assert BT.device_kind("", 0x240414, True) == "Speaker"
        assert BT.device_kind("", 0, 0x3FFF << 6) == "Device"
        assert BT.device_kind("", 0, -5) == "Device"

    def test_happy_earbuds_take_sound(self):
        device = BT.Device.from_props("/x/dev_1", {"Appearance": 0x0941}, None)
        assert BT.is_audio_output(device)


class TestDiscoveryFilter:
    def test_happy_rssi_is_a_typed_short(self):
        flt = BT.discovery_filter("le", -70)
        assert flt["Transport"] == "le" and flt["DuplicateData"] is True
        assert flt["RSSI"].typeName() == "short" and flt["RSSI"].value() == -70

    def test_sad_nonsense_is_refused_before_bluez_sees_it(self):
        with pytest.raises(ValueError):
            BT.discovery_filter("wifi")
        for bad in (-200, 50, True, "-70"):
            with pytest.raises(ValueError):
                BT.discovery_filter("auto", bad)

    def test_edge_no_rssi_no_key(self):
        assert "RSSI" not in BT.discovery_filter()


class TestDeviceFromProps:
    def test_happy_advertising_data_as_python(self):
        props = {"Address": TAG, "AddressType": "random",
                 "ManufacturerData": {76: QByteArray(b"\x12\x19"), 6: QByteArray(b"\x01")},
                 "ServiceData": {BATTERY_SVC.upper(): QByteArray(b"\x55")},
                 "AdvertisingFlags": QByteArray(b"\x06"), "TxPower": -4, "Bonded": True}
        device = BT.Device.from_props(dev_path(TAG), props, None, 123.0)
        assert device.manufacturer_data == ((6, b"\x01"), (76, b"\x12\x19"))
        assert device.service_data == ((BATTERY_SVC, b"\x55"),)
        assert device.adv_flags == 6 and device.tx_power == -4 and device.bonded
        assert device.bearer == "LE" and device.vendor == "Microsoft, Apple"
        assert device.last_seen == 123.0

    def test_sad_broken_advertising_data_is_left_out(self):
        props = {"ManufacturerData": "garbage", "ServiceData": [1, 2],
                 "AdvertisingFlags": "x"}
        device = BT.Device.from_props("/x/dev_1", props, None)
        assert device.manufacturer_data == () and device.service_data == ()
        assert device.adv_flags is None

    def test_edge_named_tells_a_real_name_from_bluez_s_address_alias(self):
        assert not BT.Device.from_props("/x", {"Address": TAG, "Alias": "D4-11-22-33-44-55"},
                                        None).named
        assert BT.Device.from_props("/x", {"Address": TAG, "Alias": "Keys"}, None).named
        assert BT.Device.from_props("/x", {"Address": TAG, "Name": "Keys"}, None).named


# =====================================================================================
# against the fake BlueZ
# =====================================================================================

class TestScanFilter:
    def test_happy_ble_only_scan_finds_only_ble_devices(self, client, fake):
        c = client(classic_speaker(on_scan=True), ble_watch(on_scan=True))
        c.start_discovery(HCI, transport="le", rssi=-80)
        assert result(c, HCI, "scan") == ""
        assert wait_until(lambda: [d.address for d in c.devices()] == [WATCH])
        flt = next(iter(fake.command("filters").values()))
        assert flt == {"Transport": "le", "RSSI": -80, "DuplicateData": True}
        watch = c.device(dev_path(WATCH))
        assert watch.kind == "Watch" and watch.bearer == "LE" and watch.vendor == "Garmin"
        assert watch.services == ["Battery"] and watch.tx_power == 4

    def test_happy_classic_only_and_a_minimum_signal(self, client, fake):
        far = classic_speaker(address=FAR, on_scan=True,
                              props={"Name": "Far", "Class": 0x240414, "RSSI": -92})
        c = client(classic_speaker(on_scan=True), ble_tag(on_scan=True), far)
        c.start_discovery(HCI, transport="bredr", rssi=-70)
        assert result(c, HCI, "scan") == ""
        assert wait_until(lambda: [d.address for d in c.devices()] == [SPEAKER])
        time.sleep(0.2)
        assert [d.address for d in c.devices()] == [SPEAKER]

    def test_sad_a_filter_the_user_asked_for_that_bluez_refuses_is_an_error(self, client, fake):
        c = client(ble_tag(on_scan=True))
        fake.command("adapter_behave", path=HCI,
                     behaviour={"filter": "error:org.bluez.Error.NotSupported:no LE"})
        c.start_discovery(HCI, transport="le")
        assert "does not support" in result(c, HCI, "scan")
        assert not c.adapters()[0].discovering and c.busy(HCI) is None

    def test_edge_the_default_filter_refused_still_scans(self, client, fake):
        c = client(ble_tag(on_scan=True))
        fake.command("adapter_behave", path=HCI,
                     behaviour={"filter": "error:org.bluez.Error.NotSupported:old"})
        c.start_discovery(HCI)
        assert result(c, HCI, "scan") == ""
        assert wait_until(lambda: len(c.devices()) == 1)

    def test_sad_a_bad_filter_raises_and_claims_nothing(self, client):
        c = client()
        with pytest.raises(ValueError):
            c.start_discovery(HCI, transport="nfc")
        assert c.busy(HCI) is None


class TestLastSeen:
    def test_happy_heard_on_discovery_and_on_every_advertisement(self, client, fake):
        c = client(ble_tag(on_scan=True))
        before = time.time()
        c.start_discovery(HCI)
        assert wait_until(lambda: c.devices() and c.devices()[0].last_seen is not None)
        first = c.device(dev_path(TAG)).last_seen
        assert first >= before - 1
        c._seen[dev_path(TAG)] = first - 100  # long ago ...
        fake.command("set", path=dev_path(TAG), iface="org.bluez.Device1",
                     props={"ManufacturerData": {"76": [9]}})
        # ... until the next advertisement
        assert wait_until(lambda: c.device(dev_path(TAG)).last_seen >= first)
        assert c.device(dev_path(TAG)).manufacturer_data == ((76, b"\x09"),)

    def test_edge_a_paired_device_out_of_range_was_never_heard(self, client):
        c = client(classic_speaker(props={"Name": "Desk", "Paired": True, "Class": 0x240414}))
        assert c.device(dev_path(SPEAKER)).last_seen is None

    def test_edge_a_trust_change_is_not_a_sign_of_life(self, client, fake):
        c = client(classic_speaker(props={"Name": "Desk", "Paired": True, "Class": 0x240414}))
        fake.command("set", path=dev_path(SPEAKER), iface="org.bluez.Device1",
                     props={"Trusted": True})
        assert wait_until(lambda: c.device(dev_path(SPEAKER)).trusted)
        assert c.device(dev_path(SPEAKER)).last_seen is None

    def test_edge_a_removed_device_is_forgotten(self, client, fake):
        c = client(ble_tag())
        assert dev_path(TAG) in c._seen
        fake.command("remove", path=dev_path(TAG))
        assert wait_until(lambda: dev_path(TAG) not in c._seen)


# =====================================================================================
# the panel
# =====================================================================================

class Panel:
    def __init__(self, fake, *devices):
        fake.command("add_adapter", name="hci0", props={"Powered": True, "Alias": "ws"})
        for spec in devices:
            fake.command("add_device", **spec)
        self.fake = fake
        self.client = BT.BluezClient(bus=fake.qt_connection())
        self.panel = BTX.BluetoothPanel(self.client, sink_lister=list)
        self.panel.resize(900, 420)
        self.panel.show()
        self.panel.start()
        assert wait_until(lambda: self.client.state == "ready")

    def paths(self) -> list[str]:
        table = self.panel.table
        return [table.item(r, BTX.COL_NAME).data(Qt.ItemDataRole.UserRole)
                for r in range(table.rowCount())]

    def cell(self, path: str, col: int) -> str:
        row = self.panel._row_of(path)
        return self.panel.table.item(row, col).text() if row >= 0 else ""

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


def choose(combo, data) -> None:
    index = combo.findData(data)
    assert index >= 0, data
    combo.setCurrentIndex(index)


def test_happy_ble_scan_from_the_panel_e2e(panel, fake):
    p = panel(classic_speaker(on_scan=True), ble_watch(on_scan=True), ble_tag(on_scan=True))
    choose(p.panel.scan_mode_combo, "le")
    choose(p.panel.min_signal_combo, -70)
    QTest.mouseClick(p.panel.scan_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: set(p.paths()) == {dev_path(WATCH), dev_path(TAG)})
    assert wait_until(lambda: p.panel.scan_button.text() == "Stop Scan")
    # a running scan keeps its filter
    assert not p.panel.scan_mode_combo.isEnabled()
    assert p.cell(dev_path(WATCH), BTX.COL_TYPE) == "Watch"
    assert p.cell(dev_path(WATCH), BTX.COL_RADIO) == "BLE"
    assert p.cell(dev_path(WATCH), BTX.COL_VENDOR) == "Garmin"
    assert p.cell(dev_path(WATCH), BTX.COL_SEEN) == "now"
    assert p.cell(dev_path(TAG), BTX.COL_VENDOR) == "Apple"
    assert p.paths()[0] == dev_path(WATCH)  # stronger first
    tip = p.panel.table.item(p.panel._row_of(dev_path(WATCH)), BTX.COL_NAME).toolTip()
    assert "Battery" in tip and "4 dBm" in tip


def test_happy_the_filter_row_narrows_the_list(panel):
    p = panel(classic_speaker(), ble_watch(), ble_tag())
    assert wait_until(lambda: len(p.paths()) == 3)
    QTest.keyClicks(p.panel.search_edit, "garmin")
    assert p.paths() == [dev_path(WATCH)]
    assert p.panel.count_label.text() == "1 of 3"
    p.panel.search_edit.clear()
    p.panel.named_check.setChecked(True)  # the nameless tag goes
    assert set(p.paths()) == {dev_path(WATCH), dev_path(SPEAKER)}
    choose(p.panel.show_combo, "Classic")
    assert p.paths() == [dev_path(SPEAKER)]
    choose(p.panel.show_combo, "")
    p.panel.named_check.setChecked(False)
    assert len(p.paths()) == 3 and p.panel.count_label.text() == "3 devices"


def test_happy_search_matches_services_and_kinds(panel):
    p = panel(classic_speaker(), ble_watch())
    assert wait_until(lambda: len(p.paths()) == 2)
    QTest.keyClicks(p.panel.search_edit, "audio sink")
    assert p.paths() == [dev_path(SPEAKER)]
    p.panel.search_edit.setText("watch ble")
    assert p.paths() == [dev_path(WATCH)]


def test_sad_a_refused_filter_says_so(panel, fake):
    p = panel(ble_tag(on_scan=True))
    fake.command("adapter_behave", path=HCI,
                 behaviour={"filter": "error:org.bluez.Error.NotSupported:no LE"})
    choose(p.panel.scan_mode_combo, "le")
    QTest.mouseClick(p.panel.scan_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: "does not support" in p.panel.message.text())
    assert wait_until(lambda: p.panel.scan_button.isEnabled())
    assert p.panel.scan_button.text() == "Scan"


def test_edge_a_burst_of_new_devices_refills_the_table_once(panel, fake, monkeypatch):
    p = panel()
    fills = []
    real = p.panel._fill_devices
    monkeypatch.setattr(p.panel, "_fill_devices", lambda: (fills.append(1), real()))
    p.panel._fill_timer.timeout.disconnect()
    p.panel._fill_timer.timeout.connect(p.panel._fill_devices)
    for i in range(30):
        fake.command("add_device", address=f"C1:00:00:00:00:{i:02X}",
                     props={"AddressType": "random", "RSSI": -60 - i})
    assert wait_until(lambda: len(p.paths()) == 30)
    assert len(fills) < 10, len(fills)


def test_edge_the_seen_column_ages(panel):
    p = panel(ble_tag())
    assert wait_until(lambda: p.cell(dev_path(TAG), BTX.COL_SEEN) == "now")
    p.client._seen[dev_path(TAG)] = time.time() - 125
    p.panel._update_seen()
    assert p.cell(dev_path(TAG), BTX.COL_SEEN) == "2 min ago"


def test_edge_seen_text():
    assert BTX.seen_text(None) == ""
    assert BTX.seen_text(100.0, 100.5) == "now"
    assert BTX.seen_text(100.0, 145.0) == "45 s ago"
    assert BTX.seen_text(100.0, 100.0 + 7300) == "2 h ago"
    assert BTX.seen_text(200.0, 100.0) == "now"  # a clock that went back


def test_edge_the_seen_timer_runs_only_while_shown(panel):
    p = panel()
    assert p.panel._seen_timer.isActive()
    p.panel.hide()
    assert not p.panel._seen_timer.isActive()


# =====================================================================================
# BlueZ keeps one scan per program
# =====================================================================================
#
# Found reviewing the client against real BlueZ: a discovery belongs to the D-Bus
# client that started it, while Adapter1.Discovering is true when any program scans.
# The panel and Add Device went by Discovering: with another program scanning
# (a desktop's Bluetooth settings), "Stop Scan" answered "No discovery started", our
# own scan with its filter could not be started, and Add Device found nothing once
# the other program stopped. And a device's advertising data that BlueZ keeps after
# a scan made it "seen just now" each time the panel started.

class TestScanPerProgram:
    def test_happy_our_scan_runs_and_stops_beside_another_programs(self, client, fake):
        c = client(ble_tag(on_scan=True))
        fake.command("other_scan", path=HCI)
        assert wait_until(lambda: c.adapters()[0].discovering)
        assert not c.scanning(HCI)
        c.start_discovery(HCI, transport="le")
        assert result(c, HCI, "scan") == "" and c.scanning(HCI)
        c.stop_discovery(HCI)
        assert result(c, HCI, "stop-scan") == ""
        assert not c.scanning(HCI)
        assert c.adapters()[0].discovering  # the other program still scans

    def test_edge_the_last_scan_ending_drops_signal_and_tx_power(self, client, fake):
        c = client(ble_watch(on_scan=True))
        c.start_discovery(HCI)
        assert wait_until(lambda: c.device(dev_path(WATCH)) is not None)
        assert c.device(dev_path(WATCH)).tx_power == 4
        c.stop_discovery(HCI)
        assert wait_until(lambda: c.device(dev_path(WATCH)).rssi is None)
        watch = c.device(dev_path(WATCH))
        assert watch.tx_power is None and watch.distance is None
        assert watch.manufacturer_data == ((135, b"\x01\x02"),)  # BlueZ keeps it

    def test_edge_switching_the_adapter_off_ends_our_scan(self, client):
        c = client()
        c.start_discovery(HCI)
        assert result(c, HCI, "scan") == "" and c.scanning(HCI)
        c.set_powered(HCI, False)
        assert wait_until(lambda: not c.scanning(HCI))

    def test_edge_kept_advertising_data_is_no_sign_of_life_at_start(self, client):
        stale = ble_tag(props={"AddressType": "random", "ManufacturerData": {"76": [1]},
                               "AdvertisingFlags": [6]})
        c = client(stale, ble_watch())
        assert c.device(dev_path(TAG)).last_seen is None
        # a device with a signal is seen by a scan running right now
        assert c.device(dev_path(WATCH)).last_seen is not None


def test_sad_stop_scan_only_offered_for_our_own_scan(panel, fake):
    p = panel(ble_tag(on_scan=True))
    fake.command("other_scan", path=HCI)
    assert wait_until(lambda: p.client.adapters()[0].discovering)
    APP.processEvents()
    assert p.panel.scan_button.text() == "Scan"
    assert "Another program" in p.panel.scan_button.toolTip()
    choose(p.panel.scan_mode_combo, "le")
    QTest.mouseClick(p.panel.scan_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: p.panel.scan_button.text() == "Stop Scan")
    ours = [f for s, f in fake.command("filters").items()]
    assert ours and ours[0]["Transport"] == "le"
    QTest.mouseClick(p.panel.scan_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: p.panel.scan_button.text() == "Scan"
                      and p.panel.scan_button.isEnabled())
    assert "No discovery" not in p.panel.message.text()
    assert p.client.adapters()[0].discovering
