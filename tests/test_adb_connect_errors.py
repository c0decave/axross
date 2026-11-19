"""A port that is no plain ADB port is named for what it is.

Review 2026-11-18 (finding 6): Android 11+'s "Wireless debugging" port
answers with STLS (TLS, after pairing), which adb_shell does not speak;
the user read "Unknown command: 1397511251 = 'b'STLS'' (arg0 = 16777216,
...)". Any other service on the port gave the same kind of byte dump.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from core.user_errors import describe  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402


def test_sad_the_wireless_debugging_port_says_use_adb_tcpip(tmp_path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="stls")
    try:
        with pytest.raises(adb.AdbTlsPortError) as info:
            adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(tmp_path / "adbkey"))
    finally:
        device.stop()
    text = describe(info.value)
    assert "Wireless debugging" in text and "adb tcpip 5555" in text
    assert "Unknown command" not in text


def test_sad_another_service_on_the_port_is_no_android_device(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def http():
        conn, _ = srv.accept()
        conn.recv(100)
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n" + b"x" * 40)

    threading.Thread(target=http, daemon=True).start()
    try:
        with pytest.raises(adb.AdbNotAdbError) as info:
            adb.AdbSession("127.0.0.1", srv.getsockname()[1],
                           adb_key_path=str(tmp_path / "adbkey"))
    finally:
        srv.close()
    text = describe(info.value)
    assert "did not answer as an Android device" in text and "5555" in text
    assert "Unknown command" not in text
