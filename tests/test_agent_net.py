"""Allowed hosts of an agent sandbox (core.agent_net): the entries, the
relay on axross's side and the bridge in the worker - here wired to each
other in one process; tests/test_agent_sandbox.py runs them through a
real bubblewrap sandbox."""

from __future__ import annotations

import socket
import threading

import pytest

from core import agent_net as N


@pytest.fixture
def echo_server():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return

            def handle(c=conn):
                with c:
                    while True:
                        data = c.recv(65536)
                        if not data:
                            return
                        c.sendall(data)

            threading.Thread(target=handle, daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def _wire(allowed, hosts):
    """A bridge and a relay that talk to each other like worker and axross."""
    state = {}

    def to_worker(message):
        bridge = state["bridge"]
        if message["type"] == "tcp_data":
            bridge.deliver(message["stream"], message["data"])
        elif message["type"] == "tcp_close":
            bridge.closed(message["stream"])

    relay = N.HostRelay(to_worker, allowed)

    def request(message):
        try:
            return {"value": {"stream": relay.open(message["host"], message["port"])}}
        except (OSError, ValueError) as exc:
            return {"error": str(exc)}

    def to_host(message):
        if message["type"] == "tcp_data":
            relay.write(message["stream"], message["data"])
        elif message["type"] == "tcp_close":
            relay.close(message["stream"])

    state["bridge"] = N.WorkerBridge(request, to_host, hosts)
    return state["bridge"], relay


# -- happy ---------------------------------------------------------------------


def test_happy_entries_parse_to_host_and_port():
    assert N.parse_host("DB.Example:5432") == ("db.example", 5432)
    assert N.parse_host("10.0.0.5:22") == ("10.0.0.5", 22)
    assert N.parse_host("[::1]:8080") == ("::1", 8080)
    assert N.parse_hosts(["a:1", "bad", "a:1", "b:2"]) == (("a", 1), ("b", 2))


def test_happy_bytes_flow_both_ways_through_bridge_and_relay(echo_server):
    bridge, relay = _wire(lambda h, p: True, [f"127.0.0.1:{echo_server}"])
    local = bridge.mapping[("127.0.0.1", echo_server)]
    payload = bytes(range(256)) * 1024  # 256 KiB: several frames
    with socket.create_connection(("127.0.0.1", local), timeout=5) as conn:
        conn.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = conn.recv(65536)
            if not chunk:
                break
            got += chunk
    assert got == payload
    bridge.close()
    relay.close_all()


def test_happy_the_allowed_name_resolves_to_its_listener(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", socket.getaddrinfo)  # restored after the test
    bridge, relay = _wire(lambda h, p: True, ["db.internal:5432"])
    bridge.install()
    info = socket.getaddrinfo("DB.internal", 5432)
    assert info[0][4] == ("127.0.0.1", bridge.mapping[("db.internal", 5432)])
    assert (
        socket.getaddrinfo("db.internal", "5432")[0][4][1] == bridge.mapping[("db.internal", 5432)]
    )
    bridge.close()


# -- sad -----------------------------------------------------------------------


@pytest.mark.parametrize("entry", ["", "host", "host:", "host:0", "host:70000", "*:22",
                                   "user@host:22", "::1:22", "[nope]:22", "a/b:1"])
def test_sad_an_entry_that_is_no_host_and_port_is_refused(entry):
    with pytest.raises(ValueError):
        N.parse_host(entry)


def test_sad_the_relay_refuses_a_host_that_is_not_allowed(echo_server):
    relay = N.HostRelay(lambda message: None, lambda h, p: False)
    with pytest.raises(PermissionError):
        relay.open("127.0.0.1", echo_server)


def test_sad_a_refused_connection_is_closed_in_the_worker(echo_server):
    bridge, relay = _wire(lambda h, p: False, [f"127.0.0.1:{echo_server}"])
    local = bridge.mapping[("127.0.0.1", echo_server)]
    with socket.create_connection(("127.0.0.1", local), timeout=5) as conn:
        conn.settimeout(5)
        assert conn.recv(10) == b""
    bridge.close()


# -- edge ----------------------------------------------------------------------


def test_edge_other_names_resolve_as_before(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: calls.append(a) or ["original"])
    bridge, _relay = _wire(lambda h, p: True, ["db.internal:5432"])
    bridge.install()
    assert socket.getaddrinfo("example.org", 443) == ["original"]
    assert socket.getaddrinfo("db.internal", 5433) == ["original"]
    assert len(calls) == 2
    bridge.close()


def test_edge_a_server_that_closes_closes_the_worker_side():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def close_at_once():
        conn, _ = server.accept()
        conn.sendall(b"bye")
        conn.close()

    threading.Thread(target=close_at_once, daemon=True).start()
    bridge, relay = _wire(lambda h, p: True, [f"127.0.0.1:{port}"])
    with socket.create_connection(
        ("127.0.0.1", bridge.mapping[("127.0.0.1", port)]), timeout=5
    ) as conn:
        conn.settimeout(5)
        data = b""
        while True:
            chunk = conn.recv(10)
            if not chunk:
                break
            data += chunk
    assert data == b"bye"
    server.close()
    bridge.close()
    relay.close_all()


def test_edge_bytes_that_arrive_before_the_answer_are_kept():
    """axross may send a server's first bytes (an SSH banner) before the
    worker has read the answer naming the stream: they must not be lost."""
    import base64

    frames = []
    release = threading.Event()

    def request(message):
        # The banner and the close arrive while the answer is on its way.
        bridge.deliver(7, base64.b64encode(b"SSH-2.0-banner").decode())
        bridge.closed(7)
        release.set()
        return {"value": {"stream": 7}}

    bridge = N.WorkerBridge(request, frames.append, ["srv.internal:22"])
    local = bridge.mapping[("srv.internal", 22)]
    with socket.create_connection(("127.0.0.1", local), timeout=5) as conn:
        conn.settimeout(5)
        data = b""
        while True:
            chunk = conn.recv(100)
            if not chunk:
                break
            data += chunk
    assert data == b"SSH-2.0-banner"
    # A late close for a finished stream leaves nothing behind.
    bridge.closed(7)
    assert bridge._early == {}
    bridge.close()
