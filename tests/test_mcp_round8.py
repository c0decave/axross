"""Round 8 of the headless MCP review: each test is the reviewer's repro
(/root/mcptest/round8/...) reduced to what it proves."""

from __future__ import annotations

import socket
import threading
import time

import pytest


class _S:
    def __init__(self, sent=0, silence=0):
        self.shut = False
        self.sent = sent
        self.silence = silence

    def shutdown(self, how):
        self.shut = True


@pytest.fixture
def stub_progress(monkeypatch):
    from core import mcp_http as H

    monkeypatch.setattr(H, "_bytes_received", lambda s: s.sent)
    monkeypatch.setattr(H, "_silence_ms", lambda s: s.silence)
    monkeypatch.setattr(H, "_tcp_info", lambda s: None)
    return H


# --- F1: attackers spread thin do not push out an authenticated client --------------


@pytest.mark.parametrize("legit_conns", [1, 2])
def test_sad_an_authenticated_connection_is_never_pushed_out(stub_progress, legit_conns):
    """One silent connection from each of 420 addresses: the legit client's
    authenticated connection (marked reading again here, which the server
    itself does not do - HTTP/1.0, one request each) was taken - its group was the busiest (2 vs 1) or, at a tie,
    came first. 0/6 SDK sessions survived."""
    H = stub_progress
    table = H._ConnectionTable(max_connections=40, per_ip=32)
    legit = [_S(sent=6000, silence=80) for _ in range(legit_conns)]
    for s in legit:
        table.admit(s, "198.51.100.7")
        table.authenticated(s)
        table.reading(s, True)  # even if it were reading again
    for n in range(40 - legit_conns):
        table.admit(_S(sent=0, silence=3000), "2001:db8:%x::1" % n)
    for row in table._open.values():
        row[1] -= 1.0
    for n in range(5):
        assert table.admit(_S(sent=0, silence=3000), "2001:db8:ff%02x::1" % n)
        for row in table._open.values():
            row[1] -= 0.3
    assert sum(s.shut for s in legit) == 0


def test_sad_two_waiting_connections_do_not_make_an_address_the_busiest(stub_progress):
    """Three clients behind one NAT: 1/61 requests - two of them briefly
    waiting made their address the busiest. A group is preferred only when
    it clearly holds more (three or more, twice the median)."""
    H = stub_progress
    table = H._ConnectionTable(max_connections=40, per_ip=32)
    nat = [_S(sent=600, silence=50) for _ in range(2)]  # handshakes in flight
    for s in nat:
        table.admit(s, "198.51.100.7")
    for n in range(38):
        table.admit(_S(sent=0, silence=3000), "203.0.113.%d" % n)
    for row in table._open.values():
        row[1] -= 1.0
    for n in range(10):
        assert table.admit(_S(sent=0, silence=3000), "192.0.2.%d" % n)
        for row in table._open.values():
            row[1] -= 0.3
    assert sum(s.shut for s in nat) == 0


def test_happy_a_clearly_busier_address_still_goes_first(stub_progress):
    """Attackers concentrated on one address that keep trickling (never
    silent) still lose to the busiest-address rule."""
    H = stub_progress
    table = H._ConnectionTable(max_connections=40, per_ip=40)
    legit = _S(sent=0, silence=3000)  # even a silent one from elsewhere
    table.admit(legit, "198.51.100.7")
    for _ in range(39):
        table.admit(_S(sent=4000, silence=20), "203.0.113.9")
    for row in table._open.values():
        row[1] -= 1.0
    for _ in range(20):
        assert table.admit(_S(sent=4000, silence=20), "203.0.113.9")
    assert not legit.shut


# --- F3: the cap recovers --------------------------------------------------------------


def test_sad_one_failed_thread_start_does_not_ruin_the_cap_for_good():
    """One failed start with 5 open set the cap to 1 for good and evicted
    every connection."""
    from core import mcp_http as H

    table = H._ConnectionTable(max_connections=100, per_ip=100)
    socks = [_S() for _ in range(5)]
    for s in socks:
        table.admit(s, "127.0.0.1")
    newcomer = _S()
    table.admit(newcomer, "127.0.0.1")
    table.thread_failed(newcomer)
    assert not any(s.shut for s in socks)  # nobody pushed out at 5 open
    lowered = table._max
    assert lowered < 100
    for _ in range(H.CAP_RECOVERY_STARTS * 20):
        table.thread_started()
    assert table._max == 100


# --- info: a refused body sees its 503 ----------------------------------------------------


def test_happy_a_refused_upload_reads_its_503(monkeypatch):
    from core import mcp_http as H
    from core.local_fs import LocalFS

    monkeypatch.setattr(H, "MAX_SLOW_BODIES_PER_CLIENT", 0)
    config = H.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0, auth_token="t" * 32)
    server = H.build_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        s = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=10)
        body = b"x" * (192 * 1024)
        s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                  + b"t" * 32 + b"\r\nContent-Type: application/json\r\n"
                  + b"Content-Length: %d\r\n\r\n" % len(body))
        send_error = None
        for i in range(0, len(body), 16384):
            try:
                s.sendall(body[i:i + 16384])
            except OSError as exc:
                send_error = exc
                break
            time.sleep(0.02)
        got = s.recv(64)
        # The 17th upload got BrokenPipe while still sending, never its 503.
        assert send_error is None, send_error
        assert got.startswith(b"HTTP/1.0 503"), got
        s.close()
    finally:
        server.shutdown()
        server.server_close()
        fwd = getattr(server, "_mcp_log_forwarder", None)
        if fwd is not None:
            H._mcp._detach_log_forwarder(fwd)
