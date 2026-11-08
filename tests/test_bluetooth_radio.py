"""axross's Bluetooth over the air: two real sticks, no host BlueZ.

The request: test the Bluetooth support completely - with the passed-
through USB sticks talking to each other. One stick is axross's adapter
(tests/bumble_bluez.py: org.bluez on a private D-Bus, Bumble behind it),
the other plays an ordinary device (tests/bumble_peer.py): a BLE sensor
with a Battery service, or a Classic loudspeaker. core.bluetooth.BluezClient
then scans, reads the advertisement, connects, resolves GATT, reads,
gets notifications and disconnects - all over the radio.

Runs only with two sticks named in ``AXROSS_BT_STICKS`` (Bumble transport
names, e.g. ``usb:0,usb:1``) and Bumble installed; skipped otherwise. One
test at a time per pair of sticks (xdist puts them in one group).
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "tests"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

STICKS = [s.strip() for s in os.environ.get("AXROSS_BT_STICKS", "").split(",") if s.strip()]
pytestmark = [
    pytest.mark.skipif(len(STICKS) < 2, reason="AXROSS_BT_STICKS names no two sticks"),
    pytest.mark.xdist_group("bt-sticks"),
]

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")
pytest.importorskip("bumble", reason="Bumble is not installed")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])
HCI = "/org/bluez/hci0"
BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"
MODEL_NUMBER = "00002a24-0000-1000-8000-00805f9b34fb"


class Peer:
    def __init__(self, transport: str, role: str) -> None:
        self.proc = subprocess.Popen([sys.executable, str(HERE / "bumble_peer.py"), transport,
                                      role], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        ready, _w, _x = select.select([self.proc.stdout], [], [], 30)
        line = self.proc.stdout.readline().split() if ready else []
        if line[:1] != ["ready"]:
            self.close()
            raise RuntimeError(f"the peer did not start: {line} {self.proc.stderr.read()}")
        self.address = line[1].upper()

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()  # it powers off and quits
                self.proc.wait(10)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
                self.proc.wait(5)


@pytest.fixture
def radio():
    made = []

    def build(role: str):
        bus = FakeBluezBus(service=[HERE / "bumble_bluez.py", STICKS[0]], ready_timeout=40)
        made.append(bus)
        peer = Peer(STICKS[1], role)
        made.append(peer)
        client = BT.BluezClient(bus=bus.qt_connection())
        finished = []
        client.operation_finished.connect(lambda p, op, err: finished.append((p, op, err)))
        client.finished = finished
        client.start()
        made.append(client)
        assert wait_until(lambda: client.state == "ready", 10), client.state
        return client, peer, bus

    yield build
    for thing in reversed(made):
        if isinstance(thing, BT.BluezClient):
            thing.shutdown()
        else:
            thing.close()


def result(client, path, op, timeout=30.0):
    def found():
        return next((err for p, o, err in client.finished if p == path and o == op), None)

    assert wait_until(lambda: found() is not None, timeout), client.finished
    return found()


def find(client, name: str, timeout: float = 30.0) -> BT.Device:
    def device():
        return next((d for d in client.devices() if d.name == name), None)

    assert wait_until(lambda: device() is not None, timeout), \
        [(d.address, d.name) for d in client.devices()]
    return device()


def test_happy_ble_scan_connect_read_notify_over_the_air(radio, tmp_path, monkeypatch):
    capture = tmp_path / "hci.btsnoop"
    monkeypatch.setenv("AXROSS_BT_SNOOP", str(capture))
    client, peer, _bus = radio("sensor")
    client.start_discovery(HCI, transport="le")
    sensor = find(client, "axross-sensor")
    assert sensor.bearer == "LE"
    assert sensor.rssi is not None and -100 < sensor.rssi < 0
    assert sensor.manufacturer_data == ((0xFFFF, b"\x01\x02"),)
    assert "Battery" in sensor.services
    client.stop_discovery(HCI)

    client.connect_device(sensor.path)
    assert result(client, sensor.path, "connect", 40) == ""
    assert wait_until(lambda: client.device(sensor.path).services_resolved, 10)
    chars = {c.uuid: c for s in client.gatt_services(sensor.path) for c in s.characteristics}
    assert {BATTERY_LEVEL, MODEL_NUMBER} <= chars.keys()

    client.read_characteristic(chars[MODEL_NUMBER].path)
    assert result(client, chars[MODEL_NUMBER].path, "read") == ""

    def value(uuid):
        return next(c.value for s in client.gatt_services(sensor.path)
                    for c in s.characteristics if c.uuid == uuid)

    assert value(MODEL_NUMBER) == b"axross test sensor"
    client.read_characteristic(chars[BATTERY_LEVEL].path)
    assert result(client, chars[BATTERY_LEVEL].path, "read") == ""
    first = value(BATTERY_LEVEL)[0]
    assert 1 <= first <= 90

    client.set_notify(chars[BATTERY_LEVEL].path, True)
    assert result(client, chars[BATTERY_LEVEL].path, "notify") == ""
    assert wait_until(lambda: value(BATTERY_LEVEL)[0] < first, 10)  # it counts down

    client.disconnect_device(sensor.path)
    assert result(client, sensor.path, "disconnect") == ""
    assert wait_until(lambda: not client.device(sensor.path).connected, 10)
    assert client.gatt_services(sensor.path) == []

    # the capture of all that: one LE link to the sensor, its ATT streams
    from core import bluetooth_stream as BS

    parsed = BS.parse_file(capture)
    [link] = [k for k in parsed.all_links() if k.address == sensor.address]
    assert link.radio == "LE" and link.end is not None
    att = {s.direction: s for s in parsed.streams.values()
           if (s.controller, s.handle) == link.key and s.protocol == "ATT (GATT)"}
    assert att["out"].att.get("read", 0) >= 2  # our two reads (and discovery)
    assert att["in"].att.get("notify", 0) >= 1  # the battery counting down
    assert parsed.errors == 0


def test_happy_classic_inquiry_finds_the_speaker_with_its_class(radio):
    client, peer, _bus = radio("speaker")
    client.start_discovery(HCI, transport="bredr")
    speaker = find(client, "axross-speaker", 40)
    assert speaker.address == peer.address
    assert speaker.device_class == 0x240414 and speaker.kind == "Speaker"
    assert speaker.bearer == "Classic"
    client.stop_discovery(HCI)
    assert wait_until(lambda: client.device(speaker.path).rssi is None, 10)  # invalidated


# =====================================================================================
# the stick used directly (core.bluetooth_direct): no D-Bus, no BlueZ
# =====================================================================================

@pytest.fixture
def direct_radio(tmp_path):
    made = []

    def build(role: str):
        from core.bluetooth_direct import DirectClient

        peer = Peer(STICKS[1], role)
        made.append(peer)
        client = DirectClient(STICKS[0], keys=tmp_path / "keys.json")
        finished = []
        client.operation_finished.connect(lambda p, op, err: finished.append((p, op, err)))
        client.finished = finished
        client.start()
        made.append(client)
        assert wait_until(lambda: client.state == "ready", 30), client.state_text()
        return client, peer

    yield build
    for thing in reversed(made):
        if isinstance(thing, BT.BluezClient):
            thing.shutdown()
        else:
            thing.close()


def test_happy_direct_ble_over_the_air(direct_radio):
    client, _peer = direct_radio("sensor")
    client.start_discovery(HCI, transport="le")
    assert result(client, HCI, "scan") == ""
    sensor = find(client, "axross-sensor")
    assert sensor.manufacturer_data == ((0xFFFF, b"\x01\x02"),)
    client.connect_device(sensor.path)
    assert result(client, sensor.path, "connect", 40) == ""
    chars = {c.uuid: c for s in client.gatt_services(sensor.path) for c in s.characteristics}
    client.read_characteristic(chars[MODEL_NUMBER].path)
    assert result(client, chars[MODEL_NUMBER].path, "read") == ""
    assert next(c.value for s in client.gatt_services(sensor.path) for c in s.characteristics
                if c.uuid == MODEL_NUMBER) == b"axross test sensor"
    client.disconnect_device(sensor.path)
    assert result(client, sensor.path, "disconnect") == ""


def test_happy_direct_classic_inquiry_over_the_air(direct_radio):
    client, peer = direct_radio("speaker")
    client.start_discovery(HCI, transport="bredr")
    assert result(client, HCI, "scan") == ""
    speaker = find(client, "axross-speaker", 40)
    assert speaker.address == peer.address and speaker.kind == "Speaker"
    client.stop_discovery(HCI)
    assert result(client, HCI, "stop-scan") == ""
    assert client.device(speaker.path).rssi is None
