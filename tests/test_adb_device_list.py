"""Connect to Server, ADB over USB: the phones connected now are listed.

Before: the dialog did not show which phones are on USB - a
serial had to be typed from "adb devices". Now a Device list with Refresh
shows the adb server's phones with their states (a phone that has not
allowed this computer yet, an offline one, one without permission, each
with what to do), or - when no server runs - the phones with USB
debugging found on USB (libusb, from their descriptors).
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import adb_server  # noqa: E402
from tests.fake_adb_server import FakeAdbServer  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def dialog(tmp_path):
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    with mock.patch("core.profiles.CONFIG_DIR", tmp_path), mock.patch(
            "core.profiles.PROFILES_FILE", tmp_path / "profiles.json"), mock.patch.object(
            QMessageBox, "warning"):
        dlg = ConnectionDialog(ProfileManager())
        dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index("adb"))
        dlg._adb_mode.setCurrentIndex(dlg._adb_mode.findData("usb"))
        with mock.patch.object(adb_server, "discover",
                               return_value=adb_server.Discovery("none")):
            APP.processEvents()  # the first look at USB lists the phones
        assert dlg._adb_discovery is not None
        dlg._adb_discovery = None
        yield dlg
        dlg.deleteLater()


@pytest.fixture()
def server(monkeypatch):
    srv = FakeAdbServer([
        ("R58M12ABCDE", "device", None, "usb:1-4 product:panther model:Pixel_7 device:p"),
        ("0123456789ABCDEF", "unauthorized", None, "usb:1-2 transport_id:4"),
        ("emulator-5554", "offline", None, "product:sdk model:sdk"),
    ])
    for key, value in srv.env.items():
        monkeypatch.setenv(key, value)
    yield srv
    srv.stop()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_happy_the_device_list_shows_the_adb_servers_phones_with_their_states(dialog, server):
    assert not dialog._adb_devices_row.isHidden()
    dialog._refresh_adb_devices()
    combo = dialog._adb_devices
    items = [combo.itemText(i) for i in range(combo.count())]
    assert items == ["any connected device", "R58M12ABCDE - Pixel 7 (ready)",
                     "0123456789ABCDEF (not allowed yet)", "emulator-5554 - sdk (offline)"]
    assert "adb server" in dialog._adb_devices_hint.text()
    # Choosing a phone fills in its serial; an unauthorized one says what to do.
    dialog._on_adb_device_chosen(1)
    assert dialog._adb_usb_serial.text() == "R58M12ABCDE"
    dialog._on_adb_device_chosen(2)
    assert "Allow" in dialog._adb_devices_hint.text()
    assert not dialog._adb_devices_hint.isHidden()
    dialog._on_adb_device_chosen(3)
    assert "adb reconnect" in dialog._adb_devices_hint.text()
    assert dialog._validate()
    assert dialog._build_profile().adb_usb_serial == "emulator-5554"


def test_happy_refresh_lists_again_and_keeps_the_chosen_serial(dialog, server):
    dialog._refresh_adb_devices()
    dialog._on_adb_device_chosen(1)
    server.devices.append(("SECOND01", "device", None, "usb:1-5 model:Tab"))
    dialog._adb_refresh.click()
    combo = dialog._adb_devices
    assert combo.count() == 5
    assert combo.currentData() == "R58M12ABCDE"


def test_happy_a_saved_serial_with_a_colon_survives(dialog):
    dialog._adb_usb_serial.setText("192.168.1.5:5555")
    assert dialog._validate()
    from core.profiles import ConnectionProfile

    profile = dialog._build_profile()
    again = ConnectionProfile.from_dict(profile.to_dict())
    assert again.adb_usb_serial == "192.168.1.5:5555"


def test_happy_without_a_server_the_usb_descriptors_are_listed(dialog, monkeypatch):
    monkeypatch.setenv("ADB_SERVER_SOCKET", f"tcp:127.0.0.1:{_closed_port()}")
    phones = [adb_server.ServerDevice("R58M12ABCDE", "device", usb="1-4", model="Pixel_7"),
              adb_server.ServerDevice("18d1:4ee7", "no permissions", usb="1-5")]
    with mock.patch.object(adb_server, "usb_descriptors", return_value=phones):
        found = adb_server.discover()
    assert found.source == "usb"
    dialog._show_adb_devices(found)
    assert dialog._adb_devices.count() == 3
    assert "No adb server runs" in dialog._adb_devices_hint.text()
    assert "udev" in dialog._adb_devices_hint.text()  # a phone lacks rights
    dialog._on_adb_device_chosen(2)
    assert dialog._adb_usb_serial.text() == ""  # a vendor:product id is no serial
    dialog._show_adb_devices(adb_server.Discovery("usb", tuple(phones[:1])))
    assert "adb start-server" in dialog._adb_devices_hint.text()


def test_sad_neither_a_server_nor_libusb(dialog, monkeypatch):
    monkeypatch.setenv("ADB_SERVER_SOCKET", f"tcp:127.0.0.1:{_closed_port()}")
    with mock.patch.object(adb_server, "usb_descriptors", side_effect=ImportError("usb1")):
        found = adb_server.discover()
    assert found.source == "none"
    dialog._show_adb_devices(found)
    assert dialog._adb_devices.count() == 1
    assert "could not be listed" in dialog._adb_devices_hint.text()


def test_edge_usb_descriptors_pick_the_adb_interface_and_survive_no_permission():
    def setting(cls, sub, proto):
        return SimpleNamespace(getClass=lambda: cls, getSubClass=lambda: sub,
                               getProtocol=lambda: proto)

    def device(vid, pid, settings, serial=None, product="Pixel 7"):
        def read_serial():
            if serial is None:
                raise OSError("LIBUSB_ERROR_ACCESS [-3]")
            return serial
        return SimpleNamespace(
            iterConfigurations=lambda: [[settings]], getVendorID=lambda: vid,
            getProductID=lambda: pid, getBusNumber=lambda: 1, getPortNumber=lambda: 4,
            getSerialNumber=read_serial, getProduct=lambda: product)

    devices = [
        device(0x18D1, 0x4EE7, [setting(0x06, 0x01, 0x01), setting(0xFF, 0x42, 0x01)],
               serial="R58M12ABCDE"),
        device(0x046D, 0xC52B, [setting(0x03, 0x01, 0x02)], serial="MOUSE"),
        device(0x04E8, 0x6860, [setting(0xFF, 0x42, 0x01)]),
        device(0x04E8, 0x6861, [setting(0xFF, 0x42, 0x01)], serial="bad\x1b[2Jserial"),
    ]

    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def getDeviceIterator(self, skip_on_error=True):  # noqa: N802
            return iter(devices)

    fake = SimpleNamespace(USBContext=Context)
    with mock.patch.dict(sys.modules, {"usb1": fake}):
        found = adb_server.usb_descriptors()
    assert [(d.serial, d.state, d.model) for d in found] == [
        ("R58M12ABCDE", "device", "Pixel_7"), ("04e8:6860", "no permissions", ""),
        ("04e8:6861", "no permissions", "")]


def test_happy_the_mode_says_usb_and_the_adb_server(dialog):
    assert dialog._adb_mode.itemText(dialog._adb_mode.findData("usb")) == "USB / adb server"
    assert "adb server" in dialog._adb_mode.toolTip()
