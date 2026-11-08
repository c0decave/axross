"""The sandbox's host relay checks every address an allowed name resolves
to, and connects to the checked address (review 1 of 0.15.176).

Before: core.agent_net.HostRelay.open called ``socket.create_connection``
on the allowed NAME with no address check. An allowed name re-pointed by
DNS (rebinding) at 127.0.0.1 or a LAN address reached the host's own
services from inside the sandbox - core.mcp_egress's proxy already
refused that for the same name.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_net as N  # noqa: E402

NAME = "api.allowed.example"


@pytest.fixture
def local_service():
    """A service on the host's loopback that the sandbox must not reach."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    reached = []

    def accept():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            reached.append(conn)

    threading.Thread(target=accept, daemon=True).start()
    yield server.getsockname()[1], reached
    server.close()
    for conn in reached:
        conn.close()


def _answers(*addresses):
    lookups = []

    def resolve(host, port, *a, **k):
        lookups.append(host)
        out = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return out

    return resolve, lookups


@pytest.mark.parametrize("address", ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1",
                                     "10.1.2.3", "192.168.1.20", "172.16.0.9", "169.254.1.1",
                                     "100.64.0.1", "0.0.0.0", "fd00::1", "fe80::1"])
def test_sad_an_allowed_name_that_resolves_to_a_host_local_address_is_refused(
        monkeypatch, local_service, address):
    port, reached = local_service
    monkeypatch.setattr(N, "CONNECT_TIMEOUT", 1.0)
    resolve, _ = _answers(address)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)  # what the old relay looked up with
    relay = N.HostRelay(lambda message: None, lambda h, p: (h, p) == (NAME, port))
    with pytest.raises(PermissionError, match="not reached from the sandbox"):
        relay.open(NAME, port)
    assert reached == []
    relay.close_all()


def test_sad_the_connection_goes_to_the_checked_address_not_the_name(monkeypatch):
    """A second lookup could answer differently: the relay looks up once
    and connects to that address."""
    resolve, lookups = _answers("93.184.215.14")
    connected = []

    class Socket:
        def __init__(self, *a):
            pass

        def settimeout(self, value):
            pass

        def connect(self, address):
            connected.append(address)

        def recv(self, n):
            return b""

        def shutdown(self, how):
            pass

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", Socket)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: pytest.fail("connected by name"))
    relay = N.HostRelay(lambda message: None, lambda h, p: True, resolver=resolve)
    relay.open(NAME, 443)
    assert lookups == [NAME]
    assert connected == [("93.184.215.14", 443)]
    relay.close_all()


def test_happy_a_mixed_answer_reaches_its_public_address_only(monkeypatch):
    resolve, _ = _answers("127.0.0.1", "93.184.215.14")
    connected = []

    def fake_connect(self, address):
        connected.append(address)

    monkeypatch.setattr(socket.socket, "connect", fake_connect)
    relay = N.HostRelay(lambda message: None, lambda h, p: True, resolver=resolve)
    relay.open(NAME, 443)
    assert connected == [("93.184.215.14", 443)]
    relay.close_all()


def test_edge_a_private_address_allowed_as_an_address_is_reached(monkeypatch):
    """The user typed 10.0.0.5:22: that decision stands (like the egress
    proxy); loopback stays refused even typed."""
    connected = []
    monkeypatch.setattr(socket.socket, "connect", lambda self, a: connected.append(a))
    relay = N.HostRelay(lambda message: None, lambda h, p: True,
                        resolver=_answers("10.0.0.5")[0])
    relay.open("10.0.0.5", 22)
    assert connected == [("10.0.0.5", 22)]
    relay.close_all()
    loop = N.HostRelay(lambda message: None, lambda h, p: True,
                       resolver=_answers("127.0.0.1")[0])
    with pytest.raises(PermissionError):
        loop.open("127.0.0.1", 22)


def test_edge_a_name_that_does_not_resolve_is_an_oserror():
    def resolve(*a, **k):
        raise socket.gaierror("no such name")

    relay = N.HostRelay(lambda message: None, lambda h, p: True, resolver=resolve)
    with pytest.raises(OSError, match="cannot resolve"):
        relay.open(NAME, 443)
