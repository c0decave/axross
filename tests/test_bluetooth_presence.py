"""The Bluetooth presence log: when were which devices in range.

The request: a BT/BLE scanner with a presence log and data export ("when
are my devices reachable"), with vendor names. core.bluetooth_presence
keeps sessions (a stretch of time a device was heard) and listening
periods (when anybody scanned) in a JSON-lines file and exports them;
ui/bluetooth_presence.py shows them; core.bluetooth_vendor names the maker
of a public address (its OUI) and the company of BLE manufacturer data.

The log's logic runs against a small stand-in client with a test clock;
the panel end to end against tests/fake_bluez.py on a private D-Bus.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from core import bluetooth_presence as BP  # noqa: E402
from core import bluetooth_vendor as BV  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_presence", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_presence"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
PHONE = "AA:BB:CC:DD:EE:01"
TAG = "D4:11:22:33:44:55"


# =====================================================================================
# a stand-in client and a clock
# =====================================================================================

class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class StubClient(QObject):
    device_heard = pyqtSignal(str)
    device_updated = pyqtSignal(str)
    adapters_changed = pyqtSignal()
    operation_finished = pyqtSignal(str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self.devices: dict[str, SimpleNamespace] = {}
        self.adapter_info = SimpleNamespace(path=HCI, powered=True, discovering=False)
        self.ours = False
        self.calls: list[str] = []

    def add(self, address: str, **over) -> str:
        path = f"{HCI}/dev_{address.replace(':', '_')}"
        values = {"address": address, "path": path, "rssi": -60, "named": True,
                  "display_name": "Phone", "vendor": "", "kind": "Phone", "bearer": "BLE",
                  "paired": False, "connected": False}
        values.update(over)
        self.devices[path] = SimpleNamespace(**values)
        return path

    def device(self, path):
        return self.devices.get(path)

    def adapters(self):
        return [self.adapter_info]

    def adapter(self, path):
        return self.adapter_info if path == HCI else None

    def scanning(self, path) -> bool:
        return self.ours

    def busy(self, path):
        return None

    def start_discovery(self, path, **_kw) -> None:
        self.calls.append("start")
        self.ours = True
        self.adapter_info.discovering = True
        self.adapters_changed.emit()

    def stop_discovery(self, path) -> None:
        self.calls.append("stop")
        self.ours = False
        self.adapter_info.discovering = False
        self.adapters_changed.emit()


@pytest.fixture
def log(tmp_path):
    made = []

    def build(path=..., **kw):
        client = StubClient()
        clock = Clock()
        p = BP.PresenceLog(client, path=tmp_path / "presence.jsonl" if path is ... else path,
                           clock=clock, sweep_ms=3_600_000, **kw)
        p.clock = clock
        p.start()
        made.append(p)
        return client, p

    yield build
    for p in made:
        p.stop()


# =====================================================================================
# sessions
# =====================================================================================

def test_happy_a_device_heard_twice_is_one_session(log):
    client, p = log()
    path = client.add(PHONE, rssi=-70)
    client.device_heard.emit(path)
    p.clock.t += 30
    client.devices[path].rssi = -50
    client.device_heard.emit(path)
    [s] = p.sessions()
    assert (s.address, s.duration, s.name) == (PHONE, 30, "Phone")
    assert (s.rssi_min, s.rssi_max, s.rssi_avg) == (-70, -50, -60)
    assert p.present() == {PHONE}


def test_happy_a_device_not_heard_leaves_when_it_was_last_heard(log):
    client, p = log(absent_after=120)
    path = client.add(PHONE)
    client.device_heard.emit(path)
    start = p.clock.t
    p.clock.t += 10
    client.device_heard.emit(path)
    p.clock.t += 119
    p.sweep()
    assert p.present() == {PHONE}
    p.clock.t += 2
    p.sweep()
    assert p.present() == set()
    [s] = p.sessions()
    assert (s.start, s.end) == (start, start + 10)  # not when that was noticed
    # heard again later: a second session
    p.clock.t += 600
    client.device_heard.emit(path)
    assert len(p.sessions()) == 2


def test_happy_a_connected_device_stays_in_range_without_advertising(log):
    client, p = log(absent_after=120)
    path = client.add(PHONE, connected=True)
    client.device_updated.emit(path)
    p.clock.t += 3600
    p.sweep()
    assert p.present() == {PHONE}
    [s] = p.sessions()
    assert s.connected and s.duration == 3600


def test_edge_a_device_forgotten_and_found_again_keeps_its_session(log):
    """BlueZ drops an unpaired device ~30 s after it was last seen and makes
    a new object when it is heard again: sessions go by address."""
    client, p = log()
    path = client.add(PHONE)
    client.device_heard.emit(path)
    del client.devices[path]
    p.clock.t += 60
    path = client.add(PHONE.lower().upper())
    client.device_heard.emit(path)
    assert len(p.sessions()) == 1


def test_sad_a_device_without_an_address_is_not_logged(log):
    client, p = log()
    path = client.add("", named=False)
    client.device_heard.emit(path)
    client.device_heard.emit("/org/bluez/hci0/dev_gone")
    assert p.sessions() == []


# =====================================================================================
# listening and monitoring
# =====================================================================================

def test_happy_listening_periods_follow_the_adapters_discovering(log):
    client, p = log()
    client.adapter_info.discovering = True
    client.adapters_changed.emit()
    p.clock.t += 300
    client.adapter_info.discovering = False
    client.adapters_changed.emit()
    [period] = p.listening()
    assert period.end - period.start == 300


def test_happy_monitoring_keeps_our_scan_running(log):
    client, p = log()
    p.set_monitoring(HCI)
    assert client.calls == ["start"] and p.monitoring == HCI
    # BlueZ ends the scan (the adapter was reset): scanning again
    client.ours = False
    client.adapter_info.discovering = False
    client.adapters_changed.emit()
    assert client.calls == ["start", "start"]
    p.set_monitoring(None)
    assert client.calls[-1] == "stop" and p.monitoring is None


def test_sad_monitoring_waits_for_a_switched_off_adapter(log):
    client, p = log()
    client.adapter_info.powered = False
    p.set_monitoring(HCI)
    assert client.calls == []
    client.adapter_info.powered = True
    client.adapters_changed.emit()
    assert client.calls == ["start"]


def test_sad_a_refused_scan_is_tried_again_later(log):
    client, p = log(retry_ms=50)
    client.start_discovery = lambda path, **kw: client.calls.append("refused")
    p.set_monitoring(HCI)
    client.operation_finished.emit(HCI, "scan", "org.bluez.Error.InProgress")
    assert wait_until(lambda: client.calls.count("refused") >= 2, 2)


# =====================================================================================
# the file
# =====================================================================================

def test_happy_the_log_survives_a_restart(log, tmp_path):
    client, p = log()
    path = client.add(PHONE)
    client.device_heard.emit(path)
    p.clock.t += 40
    client.device_heard.emit(path)
    p.stop()
    file = tmp_path / "presence.jsonl"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    _client2, p2 = log()
    [s] = p2.sessions()
    assert (s.address, s.duration) == (PHONE, 40)


def test_edge_old_and_broken_lines_are_dropped_on_load(log, tmp_path):
    file = tmp_path / "presence.jsonl"
    now = Clock().t
    good = BP.Session(address=PHONE, start=now - 100, end=now - 50).record()
    old = BP.Session(address=TAG, start=now - 100 * 86400, end=now - 99 * 86400).record()
    bad_address = {**good, "address": "=cmd|' /C calc'!A0"}
    backwards = {**good, "end": now - 200}
    file.write_text("\n".join([json.dumps(good), json.dumps(old), "{broken",
                               json.dumps(bad_address), json.dumps(backwards), "[1]"]) + "\n")
    _client, p = log(keep_days=90)
    assert [s.address for s in p.sessions()] == [PHONE]
    assert len(file.read_text().splitlines()) == 1  # rewritten without them


def test_edge_the_log_keeps_at_most_max_records(log, tmp_path):
    client, p = log(max_records=3, absent_after=1)
    for n in range(5):
        path = client.add(f"AA:BB:CC:DD:EE:{n:02X}")
        client.device_heard.emit(path)
        p.clock.t += 5
        p.sweep()
    assert len(p.sessions()) == 3
    assert len((tmp_path / "presence.jsonl").read_text().splitlines()) == 3


def test_sad_an_unwritable_log_says_so_and_keeps_logging(log, tmp_path):
    client, p = log(path=tmp_path / "missing-dir-is-a-file" / "presence.jsonl",
                    absent_after=1)
    (tmp_path / "missing-dir-is-a-file").write_text("")
    path = client.add(PHONE)
    client.device_heard.emit(path)
    p.clock.t += 5
    p.sweep()
    assert p.write_error
    assert len(p.sessions()) == 1


def test_happy_clear_forgets_the_log(log, tmp_path):
    client, p = log(absent_after=1)
    path = client.add(PHONE)
    client.device_heard.emit(path)
    p.clock.t += 5
    p.sweep()
    p.clear()
    assert p.sessions() == [] and not (tmp_path / "presence.jsonl").exists()


# =====================================================================================
# summaries and export
# =====================================================================================

def sessions_of_two_days():
    t = 1_800_000_000.0
    return [BP.Session(address=PHONE, start=t, end=t + 600, name="Phone", rssi_sum=-120,
                       samples=2, rssi_min=-70, rssi_max=-50),
            BP.Session(address=PHONE, start=t + 86400, end=t + 86400 + 60, name="Phone 2",
                       rssi_sum=-40, samples=1, rssi_min=-40, rssi_max=-40),
            BP.Session(address=TAG, start=t + 100, end=t + 200, vendor="Apple")]


def test_happy_summaries_per_device():
    t = 1_800_000_000.0
    phone, tag = BP.summaries(sessions_of_two_days(), present=[TAG.lower()])
    assert (phone.address, phone.sessions, phone.present, phone.name) == (PHONE, 2, 660,
                                                                          "Phone 2")
    assert phone.rssi_avg == pytest.approx(-160 / 3)
    assert tag.present_now and not phone.present_now
    # a period clips the sessions
    [only] = BP.summaries(sessions_of_two_days(), since=t + 300, until=t + 900)
    assert (only.address, only.present) == (PHONE, 300)


def test_happy_export_csv_and_json(tmp_path):
    out = tmp_path / "p.csv"
    assert BP.export_csv(out, sessions_of_two_days()) == 3
    rows = list(csv.DictReader(out.open()))
    assert [r["address"] for r in rows] == [PHONE, TAG, PHONE]
    assert rows[0]["duration_s"] == "600" and rows[0]["rssi_avg"] == "-60.0"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    doc_path = tmp_path / "p.json"
    BP.export_json(doc_path, sessions_of_two_days(),
                   listening=[BP.Listening(1_800_000_000.0, 1_800_001_000.0)])
    doc = json.loads(doc_path.read_text())
    assert [d["address"] for d in doc["devices"]] == [PHONE, TAG]
    assert len(doc["sessions"]) == 3 and len(doc["listening"]) == 1


def test_sad_a_device_name_is_no_spreadsheet_formula(tmp_path):
    out = tmp_path / "p.csv"
    BP.export_csv(out, [BP.Session(address=PHONE, start=1.0, end=2.0,
                                   name='=HYPERLINK("http://x")')])
    [row] = list(csv.DictReader(out.open()))
    assert row["name"].startswith("'=")


def test_edge_duration_text():
    assert [BP.duration_text(s) for s in (45, 720, 3 * 3600 + 300, 52 * 3600)] == \
        ["45 s", "12 min", "3 h 05 min", "2 d 4 h"]


# =====================================================================================
# vendors
# =====================================================================================

MANUF = """# Wireshark manuf
00:01:95\tSenaTech\tSena Technologies, Inc.
00:55:DA\tIEEE\tIEEE Registration Authority
00:55:DA:10:00:00/28\tKoolPOS\tKoolPOS Inc.
70:B3:D5:00:10:00/36\tTiny\tTiny Corp
broken line
"""


@pytest.fixture
def oui_table():
    BV._reset_for_tests("ready", BV.parse_table(MANUF.splitlines(True)))
    yield
    BV._reset_for_tests()


def test_happy_the_maker_of_a_public_address(oui_table):
    assert BV.address_vendor("00:01:95:53:6F:BC") == "SenaTech"
    assert BV.address_vendor("00:55:DA:1F:00:01") == "KoolPOS"  # the smaller block wins
    assert BV.address_vendor("00:55:DA:2F:00:01") == "IEEE"
    assert BV.address_vendor("70:B3:D5:00:1A:BC") == "Tiny"


def test_sad_random_and_local_addresses_have_no_maker(oui_table):
    assert BV.address_vendor("00:01:95:53:6F:BC", "random") == ""
    assert BV.address_vendor("02:01:95:53:6F:BC") == ""  # locally administered
    assert BV.address_vendor("nonsense") == ""


def test_happy_company_names_from_the_sig_list():
    assert BV.company_name(0x004C) == "Apple"  # the short name
    assert BV.company_name(0x0013) == "Atmel Corporation"  # the full list
    assert BV.company_name(0xFFFE) == ""
    assert BT.company_name(0xFFFE) == "Company 0xFFFE"


def test_happy_the_device_vendor_falls_back_to_the_address(oui_table):
    device = BT.Device.from_props(f"{HCI}/dev_00_01_95_53_6F_BC", {
        "Address": "00:01:95:53:6F:BC", "AddressType": "public", "Adapter": HCI}, None)
    assert device.vendor == "SenaTech"


def test_edge_the_table_loads_in_the_background(tmp_path, monkeypatch):
    table = tmp_path / "manuf"
    table.write_text(MANUF)
    monkeypatch.setattr(BV, "table_file", lambda: str(table))
    BV._reset_for_tests()
    try:
        loaded = []
        BV.notifier().loaded.connect(lambda: loaded.append(1))
        assert BV.address_vendor("00:01:95:53:6F:BC") == ""  # not yet: loading
        assert wait_until(lambda: BV.oui_state() == "ready" and loaded, 5)
        assert BV.address_vendor("00:01:95:53:6F:BC") == "SenaTech"
    finally:
        BV._reset_for_tests()


def test_sad_no_table_is_no_vendor(monkeypatch):
    monkeypatch.setattr(BV, "table_file", lambda: None)
    BV._reset_for_tests()
    try:
        BV.preload()
        assert wait_until(lambda: BV.oui_state() == "missing", 5)
        assert BV.address_vendor("00:01:95:53:6F:BC") == ""
    finally:
        BV._reset_for_tests()


# =====================================================================================
# the panel and the dialog, end to end on the fake BlueZ
# =====================================================================================

@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


def test_happy_presence_from_the_panel_e2e(fake, tmp_path):
    fake.command("add_adapter", name="hci0", props={"Powered": True, "Alias": "ws"})
    fake.command("add_device", address=TAG, on_scan=True,
                 props={"AddressType": "random", "ManufacturerData": {"76": [0x12, 0x19]},
                        "RSSI": -66})
    client = BT.BluezClient(bus=fake.qt_connection())
    panel = BTX.BluetoothPanel(client, sink_lister=list,
                               presence_path=tmp_path / "presence.jsonl")
    panel.show()
    panel.start()
    try:
        assert wait_until(lambda: client.state == "ready")
        saved = tmp_path / "out.json"
        dialog = panel.open_presence(ask_save=lambda *_a: str(saved))
        assert panel.open_presence() is dialog  # one at a time
        dialog.monitor_check.setChecked(True)  # keeps a scan running
        assert wait_until(lambda: TAG in panel.presence.present(), 8)
        assert wait_until(lambda: dialog.devices.rowCount() == 1, 4)
        assert dialog.devices.item(0, 2).text() == "Apple"
        assert panel.presence.listening()
        assert dialog.export("json")
        doc = json.loads(saved.read_text())
        assert doc["devices"][0]["address"] == TAG and doc["devices"][0]["present_now"]
        dialog.monitor_check.setChecked(False)
        assert wait_until(lambda: not client.scanning(HCI), 4)
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()
    # the session was written when the panel shut down
    lines = [json.loads(line) for line in (tmp_path / "presence.jsonl").read_text().splitlines()]
    assert any(r["t"] == "session" and r["address"] == TAG for r in lines)


# =====================================================================================
# found in review: a full log, a tampered log
# =====================================================================================

def test_edge_a_full_log_is_cut_in_steps_not_at_every_line(log, tmp_path, monkeypatch):
    client, p = log(max_records=100, absent_after=1)
    rewrites = []
    original = p._rewrite
    monkeypatch.setattr(p, "_rewrite", lambda: (rewrites.append(1), original()))
    for n in range(300):
        path = client.add(f"AA:BB:CC:DD:{n // 256:02X}:{n % 256:02X}")
        client.device_heard.emit(path)
        p.clock.t += 5
        p.sweep()
    assert len(p.sessions()) <= 110
    assert len(rewrites) <= 20  # about once per tenth, not 200 times


def test_sad_non_finite_times_in_the_log_are_dropped(log, tmp_path):
    file = tmp_path / "presence.jsonl"
    now = Clock().t
    good = BP.Session(address=PHONE, start=now - 100, end=now - 50).record()
    file.write_text("\n".join([
        json.dumps(good),
        json.dumps({**good, "start": float("nan")}),
        json.dumps({**good, "end": float("inf"), "address": TAG}),
        '{"t": "listen", "start": NaN, "end": NaN}']) + "\n")
    _client, p = log()
    assert [s.address for s in p.sessions()] == [PHONE]
    assert p.listening() == []
