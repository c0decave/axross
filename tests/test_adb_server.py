"""ADB through the adb server of this computer (core.adb_server).

Before: with the platform tools' adb server running (the
console's ``adb`` works, several sessions at once), USB mode failed with
"Another program holds the phone's USB connection, usually a running adb
server. Stop it with "adb kill-server" and try again." - axross claimed the
USB device itself (libusb), which the server already held. TCP mode
pointed at localhost:5037 (the server's port) failed too: the server does
not speak the phone's protocol. And the dialog did not show which phones
are connected.

Now USB mode goes through the server when one answers on 127.0.0.1:5037
(libusb stays the fallback); the server's answers are read as untrusted
input (bounded lengths, a time-out on every read, checked serials).
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from core import adb_server, connect_notice  # noqa: E402
from core.user_errors import describe  # noqa: E402
from tests.fake_adb_server import FakeAdbServer  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
USB = "usb:1-4 product:panther model:Pixel_7 device:panther transport_id:3"


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def phone(tmp_path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root)
    yield device
    device.stop()


@pytest.fixture()
def server(phone, monkeypatch):
    srv = FakeAdbServer([("R58M12ABCDE", "device", phone, USB)])
    for key, value in srv.env.items():
        monkeypatch.setenv(key, value)
    yield srv
    srv.stop()


@pytest.fixture()
def no_server(monkeypatch):
    monkeypatch.setenv("ADB_SERVER_SOCKET", f"tcp:127.0.0.1:{_closed_port()}")


def _usb(tmp_path, **kwargs):
    return adb.AdbSession(usb=True, adb_key_path=str(tmp_path / "adbkey"), **kwargs)


def _no_libusb():
    return mock.patch.object(adb, "AdbDeviceUsb", side_effect=AssertionError("libusb used"))


# --------------------------------------------------------------------------
# Where the server is
# --------------------------------------------------------------------------
@pytest.mark.parametrize("env, expected", [
    ({}, ("127.0.0.1", 5037)),
    ({"ADB_SERVER_SOCKET": "tcp:localhost:5038"}, ("127.0.0.1", 5038)),
    ({"ADB_SERVER_SOCKET": "tcp:127.0.0.2:5039"}, ("127.0.0.2", 5039)),
    ({"ADB_SERVER_SOCKET": "tcp:[::1]:5040"}, ("::1", 5040)),
    ({"ADB_SERVER_SOCKET": "tcp:5041"}, ("127.0.0.1", 5041)),
    ({"ANDROID_ADB_SERVER_PORT": "5042"}, ("127.0.0.1", 5042)),
])
def test_happy_the_server_address_is_on_this_computer(env, expected):
    address = adb_server.server_address(env)
    assert (address.host, address.port, address.refused) == (*expected, "")


@pytest.mark.parametrize("env", [
    {"ADB_SERVER_SOCKET": "tcp:192.168.1.10:5037"},
    {"ADB_SERVER_SOCKET": "tcp:example.org:5037"},
    {"ADB_SERVER_SOCKET": "localfilesystem:/tmp/adb"},
    {"ADB_SERVER_SOCKET": "tcp:127.0.0.1:99999"},
    {"ANDROID_ADB_SERVER_PORT": "50 37"},
])
def test_sad_a_server_address_off_this_computer_is_never_used(env):
    address = adb_server.server_address(env)
    assert address.refused
    assert adb_server.server_version(address) is None
    with pytest.raises(OSError):
        adb_server.list_devices(address)


# --------------------------------------------------------------------------
# host:devices-l
# --------------------------------------------------------------------------
def test_happy_devices_l_is_read_with_every_state():
    text = (
        "R58M12ABCDE            device usb:1-4 product:panther model:Pixel_7 device:panther "
        "transport_id:3\n"
        "0123456789ABCDEF       unauthorized usb:1-2 transport_id:4\n"
        "emulator-5554          offline product:sdk model:sdk device:emu transport_id:5\n"
        "192.168.1.5:5555       device product:a model:b device:c transport_id:6\n"
        "XYZ                    no permissions (missing udev rules? user is in the plugdev "
        "group); see [http://developer.android.com/tools/device.html] usb:1-3 transport_id:7\n"
    )
    devices = adb_server.parse_devices(text)
    assert [(d.serial, d.state, d.on_usb) for d in devices] == [
        ("R58M12ABCDE", "device", True), ("0123456789ABCDEF", "unauthorized", True),
        ("emulator-5554", "offline", False), ("192.168.1.5:5555", "device", False),
        ("XYZ", "no permissions", True)]
    assert devices[0].model == "Pixel_7" and devices[0].label() == "R58M12ABCDE - Pixel 7"


@pytest.mark.parametrize("line", [
    "bad\x1b[31mserial device usb:1",
    "-flag device usb:1",
    "x" * 200 + " device",
    "ser;rm device",
    "ser\u202enoisrev device",
])
def test_sad_a_line_with_an_unusable_serial_is_left_out(line):
    assert adb_server.parse_devices(line + "\nGOOD device usb:1-1\n")[0].serial == "GOOD"
    assert len(adb_server.parse_devices(line + "\nGOOD device usb:1-1\n")) == 1


def test_edge_devices_l_is_bounded():
    many = "".join(f"S{i:05d} device usb:1-{i}\n" for i in range(5000))
    assert len(adb_server.parse_devices(many)) == adb_server.MAX_DEVICES
    long_line = "LONG device model:" + "a" * 5000 + "\nOK device\n"
    assert [d.serial for d in adb_server.parse_devices(long_line)] == ["OK"]
    odd = adb_server.parse_devices("P1 weird-state model:Bad\x07Model usb:1\nP1 device\n")
    assert [(d.serial, d.state, d.model) for d in odd] == [("P1", "unknown", "")]


@pytest.mark.parametrize("serial, ok", [
    ("R58M12ABCDE", True), ("emulator-5554", True), ("192.168.1.5:5555", True),
    ("adb-R58M12-AbCd._adb-tls-connect._tcp", True), ("", False), ("a b", False),
    ("a\nb", False), ("-x", False), ("x" * 129, False), ("a/b", False),
])
def test_edge_serials_checked_before_host_transport(serial, ok):
    assert adb_server.valid_serial(serial) is ok


def test_sad_an_unusable_serial_never_reaches_the_server(server):
    with pytest.raises(OSError):
        adb_server.AdbServerDevice(adb_server.server_address(), "a\x00b")
    assert not [r for r in server.requests if r.startswith(b"host:transport:")]


# --------------------------------------------------------------------------
# Hostile answers
# --------------------------------------------------------------------------
def test_sad_a_huge_or_broken_length_is_an_error_not_a_hang(server):
    address = adb_server.server_address()
    server.raw[b"host:devices-l"] = b"OKAYffff" + b"x" * 10  # then the end
    started = time.monotonic()
    with pytest.raises(OSError):
        adb_server.list_devices(address, timeout=1.0)
    server.raw[b"host:devices-l"] = b"OKAY-001R58 device"
    with pytest.raises(adb_server.AdbServerProtocolError):
        adb_server.list_devices(address, timeout=1.0)
    server.raw[b"host:devices-l"] = b"OKAY0x10R58 device usb:1"
    with pytest.raises(adb_server.AdbServerProtocolError):
        adb_server.list_devices(address, timeout=1.0)
    server.raw[b"host:devices-l"] = b"FAIL000fno " + b"\x1b[2J" + b"devices!"
    with pytest.raises(adb_server.AdbServerError) as info:
        adb_server.list_devices(address, timeout=1.0)
    assert "\x1b" not in str(info.value)
    server.raw[b"host:version"] = b"HTTP/1.1 400 Bad Request\r\n\r\n"
    assert adb_server.server_version(address, timeout=1.0) is None
    assert time.monotonic() - started < 5


def test_sad_a_server_that_keeps_quiet_times_out(server):
    server.raw[b"host:devices-l"] = b"OK"
    server.close_after_raw = False
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        adb_server.list_devices(adb_server.server_address(), timeout=0.5)
    assert time.monotonic() - started < 3


def test_sad_a_server_that_trickles_is_cut_off_by_the_deadline(server):
    server.slow = 0.2  # one byte every 0.2 s: each read is in time
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        adb_server.list_devices(adb_server.server_address(), timeout=1.0)
    assert time.monotonic() - started < 3


def test_sad_a_sync_data_block_over_64k_is_refused(server, tmp_path):
    device = adb_server.AdbServerDevice(adb_server.server_address(), "R58M12ABCDE")
    device.connect()
    server.data_block = 512 * 1024 * 1024
    sink = open(tmp_path / "out", "wb")
    with sink, pytest.raises(adb_server.AdbServerProtocolError):
        device.pull("/sdcard/Download/hello.txt", sink)
    assert (tmp_path / "out").stat().st_size == 0


def test_sad_a_sync_fail_text_is_bounded(server, tmp_path):
    device = adb_server.AdbServerDevice(adb_server.server_address(), "R58M12ABCDE")
    device.connect()
    with pytest.raises(adb_server.AdbServerCommandFailed) as info:
        device.pull("/sdcard/Download/missing.txt", open(os.devnull, "wb"))
    assert "No such file" in str(info.value)


# --------------------------------------------------------------------------
# USB mode through the server
# --------------------------------------------------------------------------
def test_happy_usb_mode_uses_the_running_adb_server(server, phone, tmp_path):
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            assert [i.name for i in s.list_dir("/sdcard/Download")] == ["hello.txt"]
            with s.open_read("/sdcard/Download/hello.txt") as fh:
                assert fh.read() == b"hello android\n"
            with s.open_write("/sdcard/Download/new.txt") as fh:
                fh.write(b"through the server\n" * 10000)
            local = Path(phone.root, "storage/emulated/0/Download/new.txt")
            assert local.read_bytes() == b"through the server\n" * 10000
            assert oct(local.stat().st_mode & 0o777) == oct(0o644)
            assert s.shell("echo hi").strip() == "hi"
            assert s.connected
        finally:
            s.close()
    assert b"host:transport:R58M12ABCDE" in server.requests


def test_happy_a_push_is_atomic_temp_name_then_rename(server, phone, tmp_path):
    target = Path(phone.root, "storage/emulated/0/Download/hello.txt")
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            with s.open_write("/sdcard/Download/hello.txt") as fh:
                fh.write(b"new content\n")
        finally:
            s.close()
    sends = [op for op in phone.sync_ops if op[0] == "SEND"]
    assert len(sends) == 1
    temp = sends[0][1]
    assert temp != "/sdcard/Download/hello.txt"
    assert temp.startswith("/sdcard/Download/.hello.txt.axross-part-")
    assert target.read_bytes() == b"new content\n"
    assert sorted(os.listdir(target.parent)) == ["hello.txt"]


def test_sad_a_refused_push_leaves_the_old_file_and_no_temp(server, phone, tmp_path):
    target = Path(phone.root, "storage/emulated/0/Download/hello.txt")
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            with mock.patch.object(s, "_commit_push", side_effect=OSError("mv: refused")):
                with pytest.raises(OSError):
                    with s.open_write("/sdcard/Download/hello.txt") as fh:
                        fh.write(b"never seen\n")
        finally:
            s.close()
    assert target.read_bytes() == b"hello android\n"
    assert sorted(os.listdir(target.parent)) == ["hello.txt"]


def test_happy_a_transfer_and_a_listing_run_side_by_side(server, phone, tmp_path):
    big = Path(phone.root, "storage/emulated/0/Download/video.mp4")
    big.write_bytes(os.urandom(2 * 1024 * 1024))
    phone.recv_delay = 0.03
    got = {}
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            def pull():
                with s.open_read("/sdcard/Download/video.mp4") as fh:
                    got["data"] = fh.read()

            th = threading.Thread(target=pull)
            th.start()
            time.sleep(0.2)
            started = time.monotonic()
            assert [i.name for i in s.list_dir("/sdcard/DCIM")] == ["Camera"]
            took = time.monotonic() - started
            th.join(30)
        finally:
            s.close()
    assert got["data"] == big.read_bytes()
    assert took < 0.5


def test_happy_the_serial_picks_the_phone(server, phone, tmp_path):
    other_root = str(tmp_path / "other")
    make_device_tree(other_root)
    Path(other_root, "storage/emulated/0/Download/other.txt").write_bytes(b"2")
    other = FakeAdbd(other_root)
    server.devices.append(("SECOND01", "device", other, "usb:1-5 model:Tab"))
    try:
        with _no_libusb():
            s = _usb(tmp_path, usb_serial="SECOND01")
            try:
                assert "other.txt" in [i.name for i in s.list_dir("/sdcard/Download")]
            finally:
                s.close()
            with pytest.raises(adb_server.AdbServerError) as info:
                _usb(tmp_path)
        assert info.value.kind == "several"
        text = describe(info.value)
        assert "R58M12ABCDE" in text and "SECOND01" in text
    finally:
        other.stop()


@pytest.mark.parametrize("state, kind, words", [
    ("offline", "offline", "adb reconnect"),
    ("no permissions (user in plugdev group; are your udev rules wrong?)", "no-permissions",
     "udev"),
])
def test_sad_a_phone_the_server_cannot_use_says_why(server, tmp_path, state, kind, words):
    server.set_state("R58M12ABCDE", state)
    with _no_libusb(), pytest.raises(adb_server.AdbServerError) as info:
        _usb(tmp_path)
    assert info.value.kind == kind
    assert words in describe(info.value)


def test_sad_an_unknown_serial_names_the_phones_the_server_sees(server, tmp_path):
    with _no_libusb(), pytest.raises(adb_server.AdbServerError) as info:
        _usb(tmp_path, usb_serial="NOPE123")
    assert info.value.kind == "not-found"
    assert "NOPE123" in describe(info.value)


def test_happy_an_unauthorized_phone_is_waited_for_with_a_notice(server, tmp_path):
    server.set_state("R58M12ABCDE", "unauthorized")
    notices: list[str] = []

    def allow():
        time.sleep(1.0)
        server.set_state("R58M12ABCDE", "device")

    threading.Thread(target=allow, daemon=True).start()
    with _no_libusb(), connect_notice.receiving(notices.append):
        s = _usb(tmp_path)
    try:
        assert s.shell("echo ok").strip() == "ok"
    finally:
        s.close()
    assert notices and "allow USB debugging" in notices[0]


def test_sad_an_unauthorized_phone_that_is_never_allowed(server, tmp_path):
    server.set_state("R58M12ABCDE", "unauthorized")
    with _no_libusb(), pytest.raises(adb.AdbAuthTimeout) as info:
        _usb(tmp_path, auth_timeout=1.0)
    assert "Allow" in describe(info.value)


def test_happy_without_a_server_libusb_is_the_fallback(no_server, tmp_path):
    fake = mock.MagicMock()
    with mock.patch.object(adb, "AdbDeviceUsb", return_value=fake) as usb:
        s = _usb(tmp_path, usb_serial="ABC123")
    s.close()
    assert usb.call_args.kwargs["serial"] == "ABC123"


def test_sad_busy_says_axross_could_share_through_a_server(no_server, tmp_path):
    import usb1

    fake = mock.MagicMock()
    fake.connect.side_effect = usb1.USBErrorBusy()
    with mock.patch.object(adb, "AdbDeviceUsb", return_value=fake):
        with pytest.raises(adb.AdbUsbError) as info:
            _usb(tmp_path)
    text = describe(info.value)
    assert info.value.kind == "busy"
    assert "adb start-server" in text and "127.0.0.1" in text
    assert "kill-server" not in text


def test_sad_busy_with_a_remote_server_address_says_why_it_is_not_used(monkeypatch, tmp_path):
    import usb1

    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:192.168.1.10:5037")
    fake = mock.MagicMock()
    fake.connect.side_effect = usb1.USBErrorBusy()
    with mock.patch.object(adb, "AdbDeviceUsb", return_value=fake):
        with pytest.raises(adb.AdbUsbError) as info:
            _usb(tmp_path)
    text = describe(info.value)
    assert "ADB_SERVER_SOCKET" in text and "192.168.1.10" in text


# --------------------------------------------------------------------------
# TCP mode pointed at the server's port
# --------------------------------------------------------------------------
def test_happy_tcp_to_the_server_port_uses_the_server(server, tmp_path):
    s = adb.AdbSession("localhost", server.port, adb_key_path=str(tmp_path / "adbkey"))
    try:
        assert [i.name for i in s.list_dir("/sdcard/Download")] == ["hello.txt"]
    finally:
        s.close()


def test_sad_tcp_to_the_server_port_with_several_phones_says_choose_usb(server, phone,
                                                                         tmp_path):
    server.devices.append(("SECOND01", "device", phone, "usb:1-5"))
    with pytest.raises(adb_server.AdbServerError) as info:
        adb.AdbSession("127.0.0.1", server.port, adb_key_path=str(tmp_path / "adbkey"))
    text = describe(info.value)
    assert "USB" in text and "SECOND01" in text


# --------------------------------------------------------------------------
# Words
# --------------------------------------------------------------------------
def test_happy_the_new_sentences_are_german_too():
    import ast
    import json

    de = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))
    wanted = []
    for name in ("core/user_errors.py", "core/adb_client.py", "ui/connection_dialog.py"):
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "tr"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and ("adb server" in node.args[0].value
                         or "adb start-server" in node.args[0].value)):
                wanted.append(node.args[0].value)
    assert len(wanted) >= 6
    missing = [w for w in wanted if w not in de]
    assert not missing, missing


def test_edge_a_folder_that_takes_no_new_file_gets_the_bytes_in_place(server, phone, tmp_path):
    target = Path(phone.root, "storage/emulated/0/Download/hello.txt")
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            real = s._send_file
            sent: list[str] = []

            def send(local, remote, hooks):
                sent.append(remote)
                if ".axross-part-" in remote:
                    raise OSError("push refused") from adb_server.AdbServerCommandFailed(
                        "push: couldn't create file: Permission denied")
                return real(local, remote, hooks)

            with mock.patch.object(s, "_send_file", side_effect=send):
                with s.open_write("/sdcard/Download/hello.txt") as fh:
                    fh.write(b"in place\n")
        finally:
            s.close()
    assert sent[-1] == "/sdcard/Download/hello.txt" and len(sent) == 2
    assert target.read_bytes() == b"in place\n"


def test_sad_a_lost_server_connection_is_not_retried_in_place(server, phone, tmp_path):
    target = Path(phone.root, "storage/emulated/0/Download/hello.txt")
    with _no_libusb():
        s = _usb(tmp_path)
        try:
            with mock.patch.object(s, "_send_file", side_effect=OSError("connection reset")):
                with pytest.raises(OSError):
                    with s.open_write("/sdcard/Download/hello.txt") as fh:
                        fh.write(b"never\n")
        finally:
            s.close()
    assert target.read_bytes() == b"hello android\n"
