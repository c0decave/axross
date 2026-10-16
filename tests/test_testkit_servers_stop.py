"""Test servers stop their serving thread when closed.

On Linux close() on a socket does not wake a thread blocked in accept() or
recvfrom() on it: every closed test server left its thread behind. A long
run collected 100+ of them, and faulthandler, which prints at most 100
threads, then dropped the main thread's stack from a crash report.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.socket_lifecycle import close_socket  # noqa: E402


def _new_threads_end(make_and_close, timeout: float = 2.0) -> list[str]:
    """Run *make_and_close*; return the names of threads it started that
    are still alive after *timeout*."""
    before = set(threading.enumerate())
    make_and_close()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        alive = [t for t in threading.enumerate() if t not in before and t.is_alive()]
        if not alive:
            return []
        time.sleep(0.02)
    return [t.name for t in alive]


def _close_after_start(server) -> None:
    time.sleep(0.05)  # let the serving thread block in accept/recvfrom
    server.close()


# --- happy -----------------------------------------------------------------


def test_happy_fuzz_scripted_server_thread_ends() -> None:
    from fuzz_testkit import ScriptedServer

    assert _new_threads_end(lambda: _close_after_start(ScriptedServer(lambda c: None))) == []


def test_happy_socks_proxy_and_echo_threads_end() -> None:
    from proxy_testkit import EchoServer, FakeSocks5Server, UdpEchoServer

    for cls in (FakeSocks5Server, EchoServer, UdpEchoServer):
        assert _new_threads_end(lambda cls=cls: _close_after_start(cls())) == [], cls


def test_happy_http_proxy_and_origin_threads_end() -> None:
    from proxy_http_testkit import FakeHttpProxy, OriginHttpServer

    assert _new_threads_end(lambda: _close_after_start(FakeHttpProxy())) == []
    assert _new_threads_end(lambda: _close_after_start(OriginHttpServer())) == []


def test_happy_snmp_fake_agent_thread_ends() -> None:
    pytest.importorskip("pysnmp")
    from snmp_fuzz_agent import FakeAgent

    assert _new_threads_end(lambda: _close_after_start(FakeAgent())) == []


def test_happy_scp_shell_server_thread_ends(tmp_path) -> None:
    pytest.importorskip("paramiko")
    from test_scp_large_upload import _ShellServer

    assert _new_threads_end(lambda: _close_after_start(_ShellServer(str(tmp_path)))) == []


# --- sad -------------------------------------------------------------------


def test_sad_closing_twice_or_an_unconnected_socket_does_not_raise() -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # shutdown: ENOTCONN
    close_socket(udp)
    close_socket(udp)  # already closed
    close_socket(None)


# --- edge ------------------------------------------------------------------


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_edge_a_blocked_reader_wakes_up(kind) -> None:
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(("127.0.0.1", 0))
    if kind == socket.SOCK_STREAM:
        sock.listen(1)
        block = sock.accept
    else:
        block = lambda: sock.recvfrom(16)  # noqa: E731

    def reader() -> None:
        try:
            block()
        except OSError:
            pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    time.sleep(0.05)
    close_socket(sock)
    thread.join(1.0)
    assert not thread.is_alive()
