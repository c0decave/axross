"""The map of the Bluetooth devices nearby.

The request: map the Bluetooth and BLE devices nearby. Bluetooth tells a
signal strength, not a place: core.bluetooth estimates a distance from
the signal and the advertised transmit power (log-distance path loss),
smoothed over the last readings, and keeps the readings for a graph.
ui/bluetooth_map.py draws the devices around this computer at those
distances (the angle is only a fixed place per address), the panel shows
it as its *Map* tab, and a click there selects the device in the list.
"""

from __future__ import annotations

import importlib.util
import math
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
from PyQt6.QtCore import QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from ui import bluetooth_map as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_map", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_map"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
NEAR = "D4:00:00:00:00:01"
FAR = "D4:00:00:00:00:02"
QUIET = "D4:00:00:00:00:03"


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


def device(address: str, rssi=None, **props) -> BT.Device:
    base = {"Address": address, "Name": address[-2:], "AddressType": "random"}
    if rssi is not None:
        base["RSSI"] = rssi
    base.update(props)
    return BT.Device.from_props(dev_path(address), base, None)


# =====================================================================================
# the estimate
# =====================================================================================

class TestDistance:
    def test_happy_stronger_is_nearer(self):
        assert BT.estimate_distance(-59) == pytest.approx(1.0)
        assert BT.estimate_distance(-40) < 1 < BT.estimate_distance(-80)

    def test_happy_the_advertised_transmit_power_calibrates(self):
        # TX power 0 dBm: -41 dBm at 1 m
        assert BT.estimate_distance(-41, 0) == pytest.approx(1.0)
        loud = BT.estimate_distance(-70, 8)
        quiet = BT.estimate_distance(-70, -12)
        assert loud > quiet  # the same signal from a loud device is farther

    def test_edge_held_to_its_range(self):
        assert BT.estimate_distance(10) == BT.MIN_DISTANCE
        assert BT.estimate_distance(-127) == BT.MAX_DISTANCE

    def test_sad_no_or_nonsense_signal_is_no_distance(self):
        for bad in (None, True, "x", -128, 21, float("nan")):
            assert BT.estimate_distance(bad) is None
        assert BT.estimate_distance(-59, tx_power="loud") == pytest.approx(1.0)

    def test_happy_text_is_as_coarse_as_the_guess(self):
        assert BT.distance_text(0.42) == "~0.4 m"
        assert BT.distance_text(3.4) == "~3 m"
        assert BT.distance_text(23.0) == "~25 m"
        assert BT.distance_text(None) == "" and BT.distance_text(math.inf) == ""

    def test_happy_a_device_s_distance_uses_the_smoothed_signal(self):
        raw = device(NEAR, -80)
        smooth = BT.Device.from_props(dev_path(NEAR), {"Address": NEAR, "RSSI": -80}, None,
                                      None, -60.0)
        assert smooth.distance < raw.distance
        assert device(NEAR).distance is None


# =====================================================================================
# the client's signal readings
# =====================================================================================

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
        c.start()
        assert wait_until(lambda: c.state == "ready")
        made.append(c)
        return c

    yield build
    for c in made:
        c.shutdown()


def test_happy_readings_are_smoothed_and_kept(client, fake):
    c = client({"address": NEAR, "props": {"AddressType": "random", "RSSI": -60}})
    path = dev_path(NEAR)
    assert c.device(path).rssi_smoothed == -60
    for rssi in (-70, -50):
        fake.command("set", path=path, iface="org.bluez.Device1", props={"RSSI": rssi})
        assert wait_until(lambda r=rssi: c.device(path).rssi == r)
    expected = -60 + BT.RSSI_SMOOTHING * (-70 + 60)
    expected = expected + BT.RSSI_SMOOTHING * (-50 - expected)
    assert c.device(path).rssi_smoothed == pytest.approx(expected)
    assert [dbm for _t, dbm in c.rssi_history(path)] == [-60, -70, -50]


def test_edge_a_scan_s_end_starts_the_next_one_afresh(client, fake):
    c = client({"address": NEAR, "props": {"AddressType": "random", "RSSI": -60},
                "on_scan": False})
    path = dev_path(NEAR)
    c.start_discovery(HCI)
    assert wait_until(lambda: c.adapters()[0].discovering)
    c.stop_discovery(HCI)  # the fake invalidates RSSI, as BlueZ does
    assert wait_until(lambda: c.device(path).rssi is None)
    assert c.device(path).rssi_smoothed is None and c.device(path).distance is None
    assert c.rssi_history(path)  # the graph keeps what it saw


def test_edge_history_is_bounded(client, fake):
    c = client({"address": NEAR, "props": {"AddressType": "random", "RSSI": -60}})
    for i in range(BT.RSSI_HISTORY + 5):
        c._heard(dev_path(NEAR), {"RSSI": -60 - i % 7})
    assert len(c.rssi_history(dev_path(NEAR))) == BT.RSSI_HISTORY
    c._heard(dev_path(NEAR), {"RSSI": 99})  # nonsense is no reading
    assert len(c.rssi_history(dev_path(NEAR))) == BT.RSSI_HISTORY


# =====================================================================================
# the map widget
# =====================================================================================

@pytest.fixture
def nearby():
    widget = BM.NearbyMap()
    widget.resize(400, 400)
    widget.show()
    yield widget
    widget.close()
    widget.deleteLater()


def from_centre(widget, path) -> float:
    pos = widget.position(path)
    return math.hypot(pos.x() - 200, pos.y() - 200)


def test_happy_nearer_devices_are_nearer_the_middle(nearby):
    nearby.set_devices([device(NEAR, -45), device(FAR, -85), device(QUIET)])
    nearby.settle()
    assert set(nearby.paths()) == {dev_path(NEAR), dev_path(FAR)}
    assert nearby.unplaced == 1
    assert from_centre(nearby, dev_path(NEAR)) < from_centre(nearby, dev_path(FAR))
    assert from_centre(nearby, dev_path(FAR)) <= nearby._outer() + 0.5


def test_happy_a_device_glides_and_the_timer_stops(nearby):
    nearby.set_devices([device(NEAR, -80)])
    nearby.settle()
    before = from_centre(nearby, dev_path(NEAR))
    nearby.update_device(device(NEAR, -40), dev_path(NEAR))
    assert nearby.moving()
    assert wait_until(lambda: not nearby.moving(), 3)
    assert from_centre(nearby, dev_path(NEAR)) < before
    target = nearby._dots[dev_path(NEAR)].target
    assert nearby.position(dev_path(NEAR)) == target
    steps = nearby.steps
    QTest.qWait(150)
    assert nearby.steps == steps  # nothing runs while nothing moves


def test_happy_click_and_double_click(nearby):
    clicked, activated = [], []
    nearby.device_clicked.connect(clicked.append)
    nearby.device_activated.connect(activated.append)
    nearby.set_devices([device(NEAR, -50)])
    nearby.settle()
    at = nearby.position(dev_path(NEAR)).toPoint()
    QTest.mouseClick(nearby, Qt.MouseButton.LeftButton, pos=at)
    assert clicked == [dev_path(NEAR)] and nearby.selected == dev_path(NEAR)
    QTest.mouseDClick(nearby, Qt.MouseButton.LeftButton, pos=at)
    assert activated == [dev_path(NEAR)]
    QTest.mouseClick(nearby, Qt.MouseButton.LeftButton, pos=at + QPointF(30, 30).toPoint())
    assert clicked == [dev_path(NEAR)] * 2  # (the double-click's press) and no miss


def test_happy_tooltip_says_signal_and_distance(nearby):
    nearby.set_devices([device(NEAR, -59, ManufacturerData={76: b"\x01"})])
    tip = nearby.tooltip(dev_path(NEAR))
    assert "-59 dBm" in tip and "~1 m" in tip and "Apple" in tip
    assert nearby.tooltip("/nothing") == ""


def test_sad_a_device_losing_its_signal_leaves_the_map(nearby):
    nearby.set_devices([device(NEAR, -50)])
    nearby.update_device(device(NEAR), dev_path(NEAR))
    assert nearby.paths() == [] and nearby.unplaced == 1
    nearby.update_device(device(NEAR, -60), dev_path(NEAR))
    assert nearby.paths() == [dev_path(NEAR)] and nearby.unplaced == 0
    nearby.update_device(None, dev_path(NEAR))  # BlueZ forgot it
    assert nearby.paths() == [] and nearby.unplaced == 0


def test_edge_hundreds_of_devices_paint(nearby):
    devices = [device(f"C0:00:00:00:{i // 256:02X}:{i % 256:02X}", -40 - i % 60,
                      Paired=i % 5 == 0, Connected=i % 17 == 0) for i in range(400)]
    nearby.set_devices(devices)
    nearby.settle()
    image = QImage(nearby.size(), QImage.Format.Format_ARGB32)
    image.fill(0)
    nearby.render(image)
    assert nearby.frames >= 1
    assert len(nearby.paths()) == 400


def test_edge_resize_keeps_dots_inside(nearby):
    nearby.set_devices([device(FAR, -100)])
    nearby.resize(160, 500)
    APP.processEvents()
    assert not nearby.moving()
    pos = nearby.position(dev_path(FAR))
    assert 0 <= pos.x() <= 160 and 0 <= pos.y() <= 500


def test_edge_hidden_settles(nearby):
    nearby.set_devices([device(NEAR, -80)])
    nearby.settle()
    nearby.update_device(device(NEAR, -40), dev_path(NEAR))
    nearby.hide()
    assert not nearby.moving()


def test_edge_angles_and_radii():
    assert BM.angle_of("aa:bb:cc:dd:ee:ff") == BM.angle_of("AA:BB:CC:DD:EE:FF")
    assert 0 <= BM.angle_of("x") < 2 * math.pi
    assert BM.radius_of(0, 100) == 0 and BM.radius_of(BM.EDGE_DISTANCE, 100) == 100
    assert BM.radius_of(1, 100) < BM.radius_of(3, 100) < BM.radius_of(1000, 100) == 100


def test_happy_signal_graph():
    graph = BM.SignalGraph()
    graph.resize(204, 54)
    assert graph.points() == []
    graph.set_readings([(0, -100), (1, -30), (2, -65)])
    low, high, mid = graph.points()
    assert high.y() < mid.y() < low.y()
    assert low.x() < high.x() < mid.x()
    image = QImage(graph.size(), QImage.Format.Format_ARGB32)
    graph.render(image)
    graph.set_readings([])
    graph.render(image)


# =====================================================================================
# in the panel
# =====================================================================================

def test_happy_the_map_tab_follows_the_scan_e2e(fake):
    fake.command("add_adapter", name="hci0", props={"Powered": True})
    fake.command("add_device", address=NEAR, on_scan=True,
                 props={"Name": "Keys", "AddressType": "random", "RSSI": -45})
    fake.command("add_device", address=FAR, on_scan=True,
                 props={"Name": "Neighbour TV", "Class": 0x200414, "RSSI": -88})
    client = BT.BluezClient(bus=fake.qt_connection())
    panel = BTX.BluetoothPanel(client, sink_lister=list)
    panel.resize(900, 600)
    panel.show()
    try:
        panel.start()
        assert wait_until(lambda: client.state == "ready")
        panel.views.setCurrentWidget(panel.map)
        QTest.mouseClick(panel.scan_button, Qt.MouseButton.LeftButton)
        assert wait_until(lambda: len(panel.map.paths()) == 2)
        panel.map.settle()
        assert from_centre_of(panel.map, dev_path(NEAR)) < from_centre_of(panel.map,
                                                                          dev_path(FAR))
        # a click on the map selects the device in the list
        at = panel.map.position(dev_path(FAR)).toPoint()
        QTest.mouseClick(panel.map, Qt.MouseButton.LeftButton, pos=at)
        assert panel.selected_path() == dev_path(FAR)
        # moving nearer moves the dot
        before = from_centre_of(panel.map, dev_path(FAR))
        fake.command("set", path=dev_path(FAR), iface="org.bluez.Device1", props={"RSSI": -50})
        assert wait_until(lambda: client.device(dev_path(FAR)).rssi == -50)
        assert wait_until(lambda: not panel.map.moving(), 3)
        assert from_centre_of(panel.map, dev_path(FAR)) < before
        # a double-click opens the details
        at = panel.map.position(dev_path(FAR)).toPoint()
        QTest.mouseDClick(panel.map, Qt.MouseButton.LeftButton, pos=at)
        assert dev_path(FAR) in panel._details
        dialog = panel._details[dev_path(FAR)]
        assert "about" in dialog.fields["signal"].text()
        assert len(dialog.graph.readings) >= 2
        # the filter row narrows the map too
        panel.search_edit.setText("keys")
        assert panel.map.paths() == [dev_path(NEAR)]
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()


def from_centre_of(widget, path) -> float:
    pos = widget.position(path)
    c = widget._centre()
    return math.hypot(pos.x() - c.x(), pos.y() - c.y())


def test_edge_labels_never_overlap(nearby):
    """Two named devices at nearly the same place: the second label goes to
    the other side or is left out, never over the first."""
    devices = [device(f"AA:00:00:00:00:{i:02X}", -50 - i % 3, Name=f"Device number {i}")
               for i in range(25)]
    nearby.set_devices(devices)
    nearby.settle()
    ordered = sorted(nearby._dots.values(), key=lambda d: d.device.distance)
    places = nearby._label_places(ordered, {d.path for d in ordered}, nearby.fontMetrics())
    rects = [r for _d, r in places]
    assert rects
    assert not any(a.intersects(b) for i, a in enumerate(rects) for b in rects[i + 1:])


def test_edge_the_selected_device_is_always_named(nearby):
    devices = [device(f"AA:00:00:00:00:{i:02X}", -50, Name=f"Device number {i}")
               for i in range(25)]
    nearby.set_devices(devices)
    nearby.settle()
    last = devices[-1].path
    nearby.set_selected(last)
    ordered = sorted(nearby._dots.values(), key=lambda d: d.device.distance)
    places = nearby._label_places(ordered, {last}, nearby.fontMetrics())
    assert [d.path for d, _r in places] == [last]


def test_edge_nameless_devices_get_no_label(nearby):
    nearby.set_devices([device(NEAR, -50, Name="", Alias="D4-00-00-00-00-01")])
    nearby.settle()
    ordered = list(nearby._dots.values())
    named = [d.path for d in ordered if d.device.named or d.device.paired]
    assert named == []


def test_edge_one_signal_reading_shows_its_value_not_an_empty_box():
    """Product review: with a single reading the graph drew nothing."""
    graph = BM.SignalGraph()
    graph.resize(204, 54)
    graph.set_readings([(0, -58)])
    assert graph.one_reading_text().startswith("-58 dBm")
    image = QImage(graph.size(), QImage.Format.Format_ARGB32)
    image.fill(0)
    graph.render(image)
    base = graph.palette().base().color().rgba()
    level = int(graph.points()[0].y())
    across = {image.pixel(x, level) for x in range(10, 190, 9)}
    assert across - {base}, "no line at the reading's level"


def test_edge_the_map_legend_names_the_grey_dot():
    """Product review: devices whose radio is unknown are grey, the legend
    did not say so."""
    world = BM.NearbyMap()
    world.resize(520, 320)
    image = QImage(world.size(), QImage.Format.Format_ARGB32)
    world.render(image)
    grey = BM.COLOURS[""].rgb() & 0xFFFFFF
    legend_rows = range(world.height() - 20, world.height())
    found = {(image.pixel(x, y) & 0xFFFFFF) for y in legend_rows for x in range(world.width())}
    for radio in ("Classic", "LE", "Dual"):
        assert BM.COLOURS[radio].rgb() & 0xFFFFFF in found, radio
    assert grey in found, "no grey dot in the legend"
