"""ADB over USB: installed with the extra, and its failures in words.

Review 2026-11-18 (finding 7): the ``adb`` extra installed adb-shell
without its ``usb`` extra (libusb1), so USB mode failed with "To enable
USB support you must install this package via `pip install
adb-shell[usb]`" - also when only the libusb library was missing. "No
phone plugged in" was a bare UsbDeviceNotFoundError (raised outside the
connect's try), and a phone held by a running adb server or without udev
rights was "LIBUSB_ERROR_BUSY [-6]" / "LIBUSB_ERROR_ACCESS [-3]".

The USB transport is replaced here (there is no phone and maybe no
libusb on the test machine).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from adb_shell import exceptions as adb_errors  # noqa: E402

from core.user_errors import describe  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_adb_server(monkeypatch):
    """No adb server answers (tests/test_adb_server.py has the server):
    USB mode goes to libusb, whatever runs on this machine's 5037."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    monkeypatch.setenv("ADB_SERVER_SOCKET", f"tcp:127.0.0.1:{s.getsockname()[1]}")
    s.close()


def _usb_session(tmp_path, **kwargs):
    return adb.AdbSession(usb=True, adb_key_path=str(tmp_path / "adbkey"), **kwargs)


def test_happy_the_adb_extra_brings_usb_support():
    from core.features import EXTRAS

    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'adb = ["adb-shell[usb]>=0.4"]' in pyproject
    assert EXTRAS["adb"] == ("adb-shell[usb]>=0.4",)


def test_sad_no_phone_on_usb_says_plug_it_in(tmp_path):
    with mock.patch.object(adb, "AdbDeviceUsb", side_effect=adb_errors.UsbDeviceNotFoundError(
            "No device available, or it is in the wrong configuration.")):
        with pytest.raises(adb.AdbUsbError) as info:
            _usb_session(tmp_path, usb_serial="ABC123")
    assert info.value.kind == "not-found"
    assert isinstance(info.value, OSError)
    text = describe(info.value)
    assert "ABC123" in text and "USB debugging" in text


def test_sad_without_libusb_the_install_is_named(tmp_path):
    with mock.patch.object(adb, "AdbDeviceUsb", side_effect=adb_errors.InvalidTransportError(
            "To enable USB support you must install this package via `pip install "
            "adb-shell[usb]`")):
        with pytest.raises(adb.AdbUsbError) as info:
            _usb_session(tmp_path)
    assert info.value.kind in ("missing-package", "missing-library")
    text = describe(info.value)
    assert "libusb" in text
    assert "axross[adb]" in text or "libusb-1.0" in text


@pytest.mark.parametrize("error, kind, words", [
    # 2026-11-20: a running adb server is used, not stopped (test_adb_server.py).
    ("LIBUSB_ERROR_BUSY [-6]", "busy", "adb start-server"),
    ("LIBUSB_ERROR_ACCESS [-3]", "access", "udev"),
])
def test_sad_a_held_or_forbidden_phone_says_what_to_do(tmp_path, error, kind, words):
    import usb1

    exc_type = usb1.USBErrorBusy if kind == "busy" else usb1.USBErrorAccess
    fake = mock.MagicMock()
    fake.connect.side_effect = exc_type()
    assert error.split()[0] in str(exc_type())
    with mock.patch.object(adb, "AdbDeviceUsb", return_value=fake):
        with pytest.raises(adb.AdbUsbError) as info:
            _usb_session(tmp_path)
    assert info.value.kind == kind
    assert words in describe(info.value)


def test_sad_test_connection_without_a_usb_phone_says_what_to_do(tmp_path, monkeypatch):
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    from core.profiles import ConnectionProfile
    from ui.connection_dialog import _ConnectThread

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(adb, "DEFAULT_ADB_KEY_PATH", str(tmp_path / "adbkey"))
    thread = _ConnectThread(ConnectionProfile(name="u", protocol="adb", adb_mode="usb"), "", "")
    seen: list[str] = []
    thread.error.connect(seen.append)
    with mock.patch.object(adb, "AdbDeviceUsb", side_effect=adb_errors.UsbDeviceNotFoundError(
            "No device available, or it is in the wrong configuration.")):
        thread.run()
    assert len(seen) == 1 and "USB debugging" in seen[0]
