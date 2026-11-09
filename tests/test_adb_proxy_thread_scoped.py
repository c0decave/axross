"""An ADB connect through a proxy routes only its own connection.

Round 7 found (repro proxy/repro_adb_global_patch.py): AdbSession
connected inside core.proxy.patched_create_connection, which swapped
``socket.create_connection`` for the whole process. While an ADB-over-
proxy connect waited - for the phone's "Allow USB debugging?" tap, up to
the auth time-out - every other thread's connection (ftplib, imaplib,
smtplib, ...) went to the ADB profile's proxy instead of its own server.
Round 6 fixed the same for SMB only.

Now ADB uses core.proxy.routed_create_connection (adb_shell's TCP module,
the connecting thread only), and the process-wide patch is gone.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

import core.proxy as proxy  # noqa: E402


class _Listener:
    """Accepts connections and keeps their first bytes; holds each one
    open (no answer) until :meth:`close` - a SOCKS proxy that is slow to
    answer, as a connect waiting for the phone."""

    def __init__(self) -> None:
        self.seen: list[bytes] = []
        self.connected = threading.Event()
        self._held: list[socket.socket] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self._held.append(conn)
            self.connected.set()
            conn.settimeout(5)
            try:
                self.seen.append(conn.recv(64))
            except OSError:
                self.seen.append(b"")

    def close(self) -> None:
        self._sock.close()
        for conn in self._held:
            conn.close()


@pytest.fixture
def private_proxy_ok(monkeypatch):
    monkeypatch.setenv("AXROSS_ALLOW_PRIVATE_PROXY", "1")


def _adb_connect_through(proxy_port: int, key: Path, box: dict, port: int = 5555) -> None:
    try:
        adb.AdbSession(
            host="127.0.0.1", port=port, adb_key_path=str(key),
            connect_timeout=3, transport_timeout=3,
            proxy_type="socks5", proxy_host="127.0.0.1", proxy_port=proxy_port,
        )
    except BaseException as exc:  # noqa: BLE001 - the proxy never answers
        box["exc"] = exc


def test_happy_other_threads_connect_directly_while_adb_waits(tmp_path, private_proxy_ok):
    adb_proxy, target = _Listener(), _Listener()
    box: dict = {}
    th = threading.Thread(
        target=_adb_connect_through, args=(adb_proxy.port, tmp_path / "adbkey", box), daemon=True
    )
    th.start()
    try:
        assert adb_proxy.connected.wait(20), "the ADB connect never reached its proxy"
        # Meanwhile an unrelated profile (no proxy) connects in this thread.
        direct = socket.create_connection(("127.0.0.1", target.port), timeout=3)
        direct.sendall(b"other profile")
        assert target.connected.wait(5)
        direct.close()
    finally:
        adb_proxy.close()
        th.join(15)
        target.close()
    assert not th.is_alive()
    # Was: the other thread's connect went to the ADB proxy instead.
    assert len(adb_proxy.seen) == 1
    assert adb_proxy.seen[0].startswith(b"\x05"), adb_proxy.seen  # the ADB SOCKS5 greeting
    assert isinstance(box.get("exc"), OSError)


def test_sad_adb_over_a_proxy_never_connects_directly(tmp_path, private_proxy_ok):
    """The routed module goes through the proxy - a proxy that does not
    answer fails the connect; the device port itself is never dialled."""
    adb_proxy = _Listener()
    device = _Listener()
    box: dict = {}
    adb_proxy.close()  # nobody listens there any more
    _adb_connect_through(adb_proxy.port, tmp_path / "adbkey", box, port=device.port)
    device.close()
    assert isinstance(box.get("exc"), OSError)
    assert device.seen == []


def test_edge_the_process_wide_patch_is_gone():
    assert not hasattr(proxy, "patched_create_connection")
    # Without a proxy adb_shell's module is not touched, and after a
    # routed connect no route is left behind in this thread.
    assert adb._adb_tcp_module(proxy.ProxyConfig("none")) is None
    assert proxy.routed_proxy() is None
