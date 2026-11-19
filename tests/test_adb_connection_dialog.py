"""Connect to Server with ADB: a profile can be made, tested and saved.

Review 2026-11-18 (findings 1 and 2): the dialog had no ADB fields. It
asked ADB for a username ("Username is required." - ADB has none), had
no TCP / USB choice and no USB serial, so a USB profile could neither be
made nor tested ("Host is required."), and it showed the Username, IP
Version and proxy rows for USB, where none of them applies.

Now: a Mode row (TCP / Wi-Fi or USB) and an optional USB serial; USB
hides host, port, IP Version and the proxy box; no username; port 5555;
the name is ``adb://host:port`` or ``adb-usb:<serial>``; Test Connection
works for both modes and says "Check the phone" while the phone asks.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def manager():
    with tempfile.TemporaryDirectory() as tmp:
        warnings: list[str] = []
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
            "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"
        ), mock.patch.object(QMessageBox, "information"), mock.patch.object(
            QMessageBox, "warning", side_effect=lambda *a, **_k: warnings.append(a[2])
        ):
            mgr = ProfileManager()
            mgr.warnings = warnings
            yield mgr


@pytest.fixture()
def adb_key(tmp_path, monkeypatch):
    path = tmp_path / "android" / "adbkey"
    monkeypatch.setattr(adb, "DEFAULT_ADB_KEY_PATH", str(path))
    adb.ensure_adb_key(str(path))
    return path


def _dialog(manager, profile=None):
    from ui.connection_dialog import ConnectionDialog

    return ConnectionDialog(manager, profile=profile)


def _choose_adb(dlg, mode: str = "tcp") -> None:
    dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index("adb"))
    dlg._adb_mode.setCurrentIndex(dlg._adb_mode.findData(mode))


def _shown(dlg, widget) -> bool:
    return not widget.isHidden()


# -- finding 1: no username -------------------------------------------------------


def test_happy_an_adb_profile_needs_no_username(manager):
    dlg = _dialog(manager)
    _choose_adb(dlg)
    assert not _shown(dlg, dlg._username)
    dlg._host.setText("192.168.1.50")
    assert dlg._validate(), manager.warnings
    profile = dlg._build_profile()
    assert (profile.protocol, profile.host, profile.port, profile.username) == (
        "adb", "192.168.1.50", 5555, "")
    assert profile.adb_mode == "tcp"
    assert profile.name == "adb://192.168.1.50:5555"


def test_sad_tcp_mode_still_needs_a_host(manager):
    dlg = _dialog(manager)
    _choose_adb(dlg)
    assert not dlg._validate()
    assert manager.warnings == ["Host is required."]


# -- finding 2: TCP / USB and the serial -------------------------------------------


def test_happy_tcp_mode_shows_host_port_and_the_proxy_not_the_serial(manager):
    dlg = _dialog(manager)
    _choose_adb(dlg, "tcp")
    assert _shown(dlg, dlg._adb_mode)
    assert _shown(dlg, dlg._host) and _shown(dlg, dlg._port) and _shown(dlg, dlg._addr_family)
    assert _shown(dlg, dlg._proxy_group)
    assert not _shown(dlg, dlg._adb_usb_serial)
    assert dlg._port.value() == 5555


def test_happy_usb_mode_hides_host_port_ip_version_and_the_proxy(manager):
    dlg = _dialog(manager)
    _choose_adb(dlg, "usb")
    assert _shown(dlg, dlg._adb_usb_serial)
    assert dlg._adb_usb_serial.placeholderText() == "any connected device"
    for widget in (dlg._host, dlg._port, dlg._addr_family, dlg._username, dlg._proxy_group):
        assert not _shown(dlg, widget)
    assert not dlg._proxy_group.isChecked()
    assert dlg._validate(), manager.warnings  # no host, no username
    profile = dlg._build_profile()
    assert (profile.adb_mode, profile.adb_usb_serial, profile.proxy_type) == ("usb", "", "none")
    assert profile.name == "adb-usb"
    dlg._adb_usb_serial.setText("R58M12ABCDE")
    assert dlg._build_profile().name == "adb-usb:R58M12ABCDE"
    assert dlg._build_profile().adb_usb_serial == "R58M12ABCDE"


def test_sad_a_serial_with_other_characters_is_refused(manager):
    dlg = _dialog(manager)
    _choose_adb(dlg, "usb")
    dlg._adb_usb_serial.setText("AB C;rm")
    assert not dlg._validate()
    assert "serial" in manager.warnings[0]


def test_happy_other_protocols_do_not_show_the_adb_rows(manager):
    dlg = _dialog(manager)
    dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index("sftp"))
    assert not _shown(dlg, dlg._adb_mode) and not _shown(dlg, dlg._adb_usb_serial)


def test_happy_a_saved_usb_profile_loads_tests_and_saves_with_its_mode(manager):
    manager.add(ConnectionProfile(name="pixel", protocol="adb", adb_mode="usb",
                                  adb_usb_serial="ABC123", port=0))
    dlg = _dialog(manager, manager.get("pixel"))
    assert dlg._adb_mode.currentData() == "usb"
    assert dlg._adb_usb_serial.text() == "ABC123"
    assert not _shown(dlg, dlg._host)
    assert dlg._validate(), manager.warnings  # was: "Host is required."
    dlg._save_profile()
    saved = manager.get("pixel")
    assert (saved.adb_mode, saved.adb_usb_serial, saved.host) == ("usb", "ABC123", "")


def test_edge_switching_a_loaded_usb_profile_to_tcp_keeps_its_port(manager):
    manager.add(ConnectionProfile(name="tv", protocol="adb", host="10.0.0.7", port=5037))
    dlg = _dialog(manager, manager.get("tv"))
    assert dlg._adb_mode.currentData() == "tcp"
    assert dlg._port.value() == 5037
    _choose_adb(dlg, "usb")
    _choose_adb(dlg, "tcp")
    assert dlg._port.value() == 5037


# -- Test Connection, both modes ---------------------------------------------------


def _run_test_thread(profile):
    from ui.connection_dialog import _ConnectThread

    thread = _ConnectThread(profile, "", "")
    seen: list[tuple[str, str]] = []
    thread.success.connect(lambda home: seen.append(("success", home)))
    thread.error.connect(lambda text: seen.append(("error", text)))
    thread.notice.connect(lambda text: seen.append(("notice", text)))
    thread.run()
    return seen


def test_happy_test_connection_over_tcp_says_check_the_phone_while_it_asks(adb_key, tmp_path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key", accept_delay=1.0)  # the key is new: the phone asks
    try:
        seen = _run_test_thread(ConnectionProfile(
            name="p", protocol="adb", host="127.0.0.1", port=device.port))
    finally:
        device.stop()
    kinds = [kind for kind, _ in seen]
    assert kinds == ["notice", "success"], seen
    assert "Check the phone" in seen[0][1]
    assert seen[1][1] == "/sdcard"


def test_happy_test_connection_in_usb_mode_reaches_the_usb_device(adb_key, tmp_path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key", authorized=[Path(str(adb_key) + ".pub").read_text()])
    made = []

    def usb_device(serial=None, **kwargs):
        made.append(serial)
        return adb.AdbDeviceTcp("127.0.0.1", device.port, **kwargs)  # the cable, simulated

    try:
        with mock.patch.object(adb, "AdbDeviceUsb", side_effect=usb_device):
            seen = _run_test_thread(ConnectionProfile(
                name="u", protocol="adb", adb_mode="usb", adb_usb_serial="ABC123"))
    finally:
        device.stop()
    assert seen == [("success", "/sdcard")]
    assert made == ["ABC123"]


def test_happy_the_dialog_shows_the_notice_and_clears_it_when_done(manager):
    dlg = _dialog(manager)
    dlg._on_test_notice("Check the phone: allow USB debugging")
    assert not dlg._test_status.isHidden()
    assert "Check the phone" in dlg._test_status.text()
    dlg._on_test_done()
    assert dlg._test_status.isHidden()
