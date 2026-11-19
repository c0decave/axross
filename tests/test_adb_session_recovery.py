"""A lost ADB connection is noticed, reported as lost and reconnected.

Review 2026-11-18 (finding 3): AdbSession had no ``connected`` state, so
ConnectionManager took a dead session for alive and handed it out again
on every reconnect ("The connection was closed by the other side.
Reconnect and try again." - and Reconnect gave the same dead session). A
device that closed the connection while a command ran made adb_shell spin
on ``recv() == b""`` for 10 s at full CPU and report "Timeout: read 0 of
24 bytes".
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from core.user_errors import describe  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402


@pytest.fixture()
def phone(tmp_path, monkeypatch):
    key = tmp_path / "android" / "adbkey"
    monkeypatch.setattr(adb, "DEFAULT_ADB_KEY_PATH", str(key))
    adb.ensure_adb_key(str(key))
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key", authorized=[Path(str(key) + ".pub").read_text()])
    yield device
    device.stop()


def test_happy_a_dropped_connection_is_reported_and_the_next_call_reconnects(phone):
    s = adb.AdbSession("127.0.0.1", phone.port, transport_timeout=5)
    assert s.connected
    assert [i.name for i in s.list_dir("/sdcard")] == ["DCIM", "Download"]
    phone.drop_connections()  # adbd restarted / Wi-Fi back
    started = time.monotonic()
    with pytest.raises(OSError) as info:
        s.list_dir("/sdcard")
    assert time.monotonic() - started < 3
    assert "closed by the other side" in describe(info.value)
    assert not s.connected
    # The next operation connects again: a refresh of the pane works.
    assert [i.name for i in s.list_dir("/sdcard")] == ["DCIM", "Download"]
    assert s.connected
    assert phone.connections >= 2
    s.close()
    assert not s.connected


def test_sad_the_device_closing_during_a_command_fails_at_once_without_spinning(phone):
    def hook(cmd):
        if cmd.startswith("TZ=UTC0 ls -la -d"):
            time.sleep(0.3)
            for conn in list(phone.open_conns):
                conn.shutdown(socket.SHUT_RDWR)  # FIN from the device
            return b""
        return None

    phone.shell_hook = hook
    s = adb.AdbSession("127.0.0.1", phone.port, transport_timeout=5)
    started, cpu = time.monotonic(), time.process_time()
    with pytest.raises(OSError) as info:
        s.stat("/sdcard/Download/hello.txt")
    assert time.monotonic() - started < 3  # was: 10 s
    assert time.process_time() - cpu < 2  # was: a busy loop
    assert "closed by the other side" in describe(info.value)
    assert not s.connected


def test_happy_the_connection_manager_replaces_a_dead_session(phone):
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(name="phone", protocol="adb", host="127.0.0.1", port=phone.port)
    mgr = ConnectionManager()
    first = mgr.connect(profile)
    phone.drop_connections()
    with pytest.raises(OSError):
        first.list_dir("/sdcard")
    second = mgr.connect(profile)  # the user opens the profile again
    assert second is not first
    assert [i.name for i in second.list_dir("/sdcard")] == ["DCIM", "Download"]
    mgr.disconnect_all()


def test_edge_a_closed_session_does_not_come_back(phone):
    s = adb.AdbSession("127.0.0.1", phone.port)
    s.close()
    with pytest.raises(OSError):
        s.list_dir("/sdcard")
    assert phone.connections == 1


def test_edge_a_failed_command_is_no_lost_connection(phone):
    s = adb.AdbSession("127.0.0.1", phone.port)
    with pytest.raises(FileNotFoundError):
        s.stat("/sdcard/nothing-here")
    with pytest.raises(OSError):
        s.open_read("/sdcard/nothing-here")
    assert s.connected
    assert phone.connections == 2  # the command and the transfer connection, no reconnect


def test_happy_after_a_drop_the_next_transfer_works_too(phone):
    s = adb.AdbSession("127.0.0.1", phone.port)
    with s.open_read("/sdcard/Download/hello.txt") as fh:  # the transfer connection is up
        assert fh.read() == b"hello android\n"
    phone.drop_connections()
    with pytest.raises(OSError):
        s.list_dir("/sdcard")  # this finds the loss
    with s.open_read("/sdcard/Download/hello.txt") as fh:  # was: a second failure
        assert fh.read() == b"hello android\n"
    assert s.list_dir("/sdcard")
