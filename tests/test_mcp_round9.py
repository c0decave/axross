"""Round 9 of the headless MCP review: the reviewer's in-process repros
(/root/mcptest/round9/local/t101, t105, t107) as tests."""

from __future__ import annotations

import types

import pytest


class _S:
    def __init__(self, sent=0, silence=0):
        self.shut = False
        self.sent = sent
        self.silence = silence

    def shutdown(self, how):
        self.shut = True


@pytest.fixture
def H(monkeypatch):
    from core import mcp_http

    monkeypatch.setattr(mcp_http, "_bytes_received", lambda s: s.sent)
    monkeypatch.setattr(mcp_http, "_silence_ms", lambda s: s.silence)
    monkeypatch.setattr(mcp_http, "_tcp_info", lambda s: None)
    # A stopped clock: the ages below are exact, however slow the run.
    clock = types.SimpleNamespace(monotonic=lambda: 1000.0)
    monkeypatch.setattr(mcp_http, "time", clock)
    return mcp_http


def test_sad_a_table_turning_over_faster_than_the_minimum_age_spares_the_handshake(H):
    """N2 (t105): every connection younger than 0.2 s - the fallback took the
    oldest, the slow legit handshake, 20 times in 20."""
    hits = 0
    for trial in range(20):
        t = H._ConnectionTable(max_connections=384, per_ip=32)
        legit = _S(600, 100)
        t.admit(legit, "198.51.100.7")
        t._open[legit][1] -= 0.18
        for i in range(383):
            s = _S(4000, 50)
            t.admit(s, "10.0.%d.1" % (i % 40))
            t._open[s][1] -= 0.15 * (i / 383)
        t.admit(_S(4000, 0), "10.0.%d.1" % (trial % 40))
        hits += legit.shut
    assert hits == 0


@pytest.mark.parametrize("k,per", [(3, 1), (4, 1), (6, 1), (3, 2), (6, 2), (6, 3)])
def test_sad_one_client_making_parallel_calls_is_not_the_busy_address(H, k, per):
    """N1 (t101): one connection per call (HTTP/1.0), so K parallel calls of
    one client made its address "busy" and its handshakes the victims."""
    cap = 384
    t = H._ConnectionTable(max_connections=cap, per_ip=32)
    for i in range(cap - k):
        a = i // per
        t.admit(_S(0, 3000), "10.%d.%d.1" % (a // 250, a % 250))
    for row in t._open.values():
        row[1] -= 2.0
    legit = [_S(600, 150) for _ in range(k)]
    for s in legit:
        t.admit(s, "198.51.100.7")
    for row in t._open.values():
        row[1] -= 0.1
    for n in range(10):
        t.admit(_S(0, 3000), "172.16.0.%d" % (n + 1))
    assert sum(s.shut for s in legit) == 0


def test_sad_on_a_tie_the_address_holding_the_oldest_handshake_does_not_lose(H):
    """t107: a legit address with 3 handshakes tied with attacker addresses
    of 3 fresh connections; the tie went to the oldest connection - legit."""
    t = H._ConnectionTable(max_connections=384, per_ip=32)
    for i in range(372):
        t.admit(_S(0, 3000), "10.%d.%d.1" % (i // 250, i % 250))
    for row in t._open.values():
        row[1] -= 2.0
    legit = [_S(600, 100) for _ in range(3)]
    for s in legit:
        t.admit(s, "198.51.100.7")
        t._open[s][1] -= 0.15
    for g in range(3):
        for _ in range(3):
            s = _S(4000, 10)
            t.admit(s, "203.0.113.%d" % g)
            t._open[s][1] -= 0.05
    t.admit(_S(0, 0), "172.16.0.1")
    assert sum(s.shut for s in legit) == 0


def test_sad_on_a_tie_of_young_connections_the_oldest_handshake_does_not_lose(H):
    """The same tie with every connection younger than 0.2 s (nothing to
    judge yet): the address that came first - the legit one - lost."""
    t = H._ConnectionTable(max_connections=12, per_ip=32)
    legit = [_S(600, 100) for _ in range(3)]
    for s in legit:
        t.admit(s, "198.51.100.7")
        t._open[s][1] -= 0.15
    for g in range(3):
        for _ in range(3):
            s = _S(4000, 10)
            t.admit(s, "203.0.113.%d" % g)
            t._open[s][1] -= 0.05
    for n in range(6):
        t.admit(_S(4000, 0), "203.0.113.%d" % (n % 3))
    assert sum(s.shut for s in legit) == 0

def test_happy_health_checks_are_not_trusted(monkeypatch):
    """GET /health passes without a token; it must not mark its connection
    as one that is never pushed out."""
    import socket
    import threading

    from core import mcp_http
    from core.local_fs import LocalFS

    config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                       auth_token="t" * 32)
    server = mcp_http.build_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    trusted = []
    real = mcp_http._ConnectionTable.authenticated

    def spy(self, sock):
        trusted.append(sock)
        return real(self, sock)

    monkeypatch.setattr(mcp_http._ConnectionTable, "authenticated", spy)
    try:
        s = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        assert s.recv(64).startswith(b"HTTP/1.0 200")
        s.close()
        assert trusted == []
    finally:
        server.shutdown()
        server.server_close()
        fwd = getattr(server, "_mcp_log_forwarder", None)
        if fwd is not None:
            mcp_http._mcp._detach_log_forwarder(fwd)
