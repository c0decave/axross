"""The Bluetooth dialogs clean up however they are left (review round 2).

Before: the device details, the presence and the streams dialogs did
their cleanup in ``closeEvent`` only. Escape and the corner's [x] call
``reject()``, which sends no closeEvent: the GATT characteristics the
details dialog watched went on notifying (at the device's battery) and
it stayed connected to the client's signals; the presence dialog stayed
connected to the presence log; the streams dialog kept following its
capture and left its visualizer window open. Now each has a one-time
``_leave()`` called from ``closeEvent`` and ``done()``, as
``ui/bluetooth_add.py`` does.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])
DEV = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01"
CHAR = DEV + "/service000c/char000d"


def _bluetooth_extension():
    spec = importlib.util.spec_from_file_location(
        "bt_escape_cleanup", ROOT / "resources" / "extensions" / "bluetooth.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _client_with_a_notifying_heart_rate_strap():
    client = BT.BluezClient(bus=None)
    client._objects[DEV] = {BT.DEVICE: {"Address": "AA:BB:CC:DD:EE:01", "Name": "HR strap",
                                        "Connected": True, "ServicesResolved": True,
                                        "Adapter": "/org/bluez/hci0"}}
    service = DEV + "/service000c"
    client._objects[service] = {BT.GATT_SERVICE: {
        "UUID": "0000180d-0000-1000-8000-00805f9b34fb", "Primary": True}}
    client._objects[CHAR] = {BT.GATT_CHARACTERISTIC: {
        "UUID": "00002a37-0000-1000-8000-00805f9b34fb", "Service": service,
        "Flags": ["notify"], "Notifying": True}}
    client.notify_calls = []
    client.set_notify = lambda path, on: client.notify_calls.append((path, on))
    return client


@pytest.mark.parametrize("leave", ["escape", "reject"])
def test_sad_details_left_with_escape_stop_the_notifications(leave):
    BTX = _bluetooth_extension()
    client = _client_with_a_notifying_heart_rate_strap()
    panel = BTX.BluetoothPanel(client, sink_lister=lambda: [])
    try:
        dialog = panel.open_details(DEV)
        APP.processEvents()
        connected = client.receivers(client.gatt_changed)
        if leave == "escape":
            QTest.keyClick(dialog, Qt.Key.Key_Escape)
        else:
            dialog.reject()
        APP.processEvents()
        assert client.notify_calls == [(CHAR, False)]
        assert client.receivers(client.gatt_changed) < connected
    finally:
        panel.close()
        panel.deleteLater()


def test_edge_details_closed_after_reject_clean_up_once():
    from ui.bluetooth_details import DeviceDialog

    client = _client_with_a_notifying_heart_rate_strap()
    dialog = DeviceDialog(client, DEV, sink_lister=lambda: [])
    dialog.show()
    dialog.reject()
    dialog.close()
    APP.processEvents()
    assert client.notify_calls == [(CHAR, False)]


def test_sad_presence_left_with_escape_no_longer_follows_the_log(tmp_path):
    from core import bluetooth_presence as BP
    from tests.test_bluetooth_presence import Clock, StubClient
    from ui.bluetooth_presence import PresenceDialog

    log = BP.PresenceLog(StubClient(), path=tmp_path / "presence.jsonl", clock=Clock(),
                         sweep_ms=3_600_000)
    dialog = PresenceDialog(log)
    try:
        dialog.show()
        APP.processEvents()
        connected = log.receivers(log.changed)
        QTest.keyClick(dialog, Qt.Key.Key_Escape)
        APP.processEvents()
        assert not dialog.isVisible()
        assert log.receivers(log.changed) < connected
    finally:
        dialog.deleteLater()
        log.stop()


def test_sad_streams_left_with_escape_stop_following_and_close_the_visualizer():
    from ui.bluetooth_streams import StreamsDialog

    dialog = StreamsDialog()
    try:
        dialog.show()
        dialog._follow.start()
        window = QWidget(dialog, Qt.WindowType.Window)  # stands in for the visualizer
        window.show()
        dialog.visual_window = window
        QTest.keyClick(dialog, Qt.Key.Key_Escape)
        APP.processEvents()
        assert not dialog.isVisible()
        assert not dialog._follow.isActive()
        assert not window.isVisible()
    finally:
        dialog.deleteLater()
