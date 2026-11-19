"""Round 7 of the headless MCP review: each test is the reviewer's repro
(/root/mcptest/round7/...) reduced to what it proves."""

from __future__ import annotations

import os
import socket
import statistics
import threading
import time

import pytest

from core import mcp_server as M


# --- N1: the victim comes from the busiest address ------------------------------------


class _Sock:
    def __init__(self, sent=0):
        self.shut = False
        self.sent = sent

    def shutdown(self, how):
        self.shut = True


def test_sad_attackers_sending_more_bytes_do_not_push_out_a_slow_handshake(monkeypatch):
    """Attacker connections that send 4 KB at once and then sit silent had
    received more bytes than a real handshake in flight, so a newcomer
    always replaced the handshake (slow mTLS clients: 0/9). The victim now
    comes from the address holding the most unauthenticated connections."""
    from core import mcp_http as H

    monkeypatch.setattr(H, "_bytes_received", lambda sock: sock.sent)
    # Round 8: three equally busy attacker addresses are no "clearly
    # busier" one; what tells them apart is that they sent their burst and
    # went silent, while the handshake keeps receiving.
    monkeypatch.setattr(H, "_silence_ms", lambda sock: 120 if sock.sent == 300 else 5000)
    table = H._ConnectionTable(max_connections=40, per_ip=32)
    legit = _Sock(sent=300)
    assert table.admit(legit, "198.51.100.7")
    attackers = []
    for n in range(39):
        s = _Sock(sent=4000)
        attackers.append(s)
        assert table.admit(s, f"203.0.113.{n % 3}")
    for row in table._open.values():
        row[1] -= 1.0  # everyone a second old
    for n in range(60):
        newcomer = _Sock(sent=4000)
        assert table.admit(newcomer, f"203.0.113.{n % 3}")
        for row in table._open.values():
            row[1] -= 0.3
    assert not legit.shut and legit in table._open


def test_sad_an_ipv6_slash_64_is_one_address():
    from core import mcp_http as H

    table = H._ConnectionTable(max_connections=100, per_ip=4)
    socks = [_Sock() for _ in range(8)]
    for n, s in enumerate(socks):
        table.admit(s, f"2001:db8:1:2::{n + 1}")
    assert sum(1 for s in socks if not s.shut) == 4


# --- N2: a thread that cannot start makes the table full --------------------------------


def test_sad_when_threads_cannot_start_the_table_counts_as_full(monkeypatch):
    """With an address-space limit allowing ~490 threads the table never
    filled; every newcomer's thread failed to start and the token holder
    was locked out. A failed start now lowers the cap and pushes one out."""
    from core import mcp_http as H

    table = H._ConnectionTable(max_connections=100, per_ip=100)
    socks = [_Sock() for _ in range(10)]
    for s in socks:
        table.admit(s, "127.0.0.1")
    for row in table._open.values():
        row[1] -= 1.0
    newcomer = _Sock()
    table.admit(newcomer, "127.0.0.1")
    table.thread_failed(newcomer)
    assert table._max < 10
    assert sum(1 for s in socks if s.shut) >= 1  # room for the next newcomers


def test_happy_the_cap_respects_the_process_and_address_space_limits(monkeypatch):
    import resource

    from core import mcp_http as H

    def limits(what):
        if what == resource.RLIMIT_NPROC:
            return (300, 300)
        if what == resource.RLIMIT_AS:
            return (36_000_000_000, 36_000_000_000)
        return (1 << 20, 1 << 20)

    monkeypatch.setattr(resource, "getrlimit", limits)
    cap = H.connection_cap()
    assert cap < 300


# --- N3/N4: the body rules ------------------------------------------------------------


def test_sad_a_healthy_upload_is_not_replaced_by_a_fresh_request(monkeypatch):
    """A 2 MiB upload at 150 KiB/s was cut after 1.3 s because a fresh
    request took the place of the slowest body."""
    from core import mcp_http as H

    monkeypatch.setattr(H, "MAX_SLOW_BODIES_PER_CLIENT", 1)
    slots = H._BodySlots()

    class Handler:
        def __init__(self, got):
            self._body_got = got
            self.connection = _Sock()

    healthy = Handler(got=200_000)
    assert slots.enter("c", healthy)
    slots._active["c"][healthy] -= 1.3  # arriving for 1.3 s at ~150 KiB/s
    assert slots.enter("c", Handler(got=0)) is False
    assert not healthy.connection.shut


def test_happy_the_minimum_body_rate_is_low_and_can_be_set(monkeypatch):
    from core import mcp_http as H

    assert H.min_body_rate() <= 1024
    monkeypatch.setenv("AXROSS_MCP_MIN_BODY_RATE", "256")
    assert H.min_body_rate() == 256


# --- N5/N6: write locks ---------------------------------------------------------------


class _Ctx:
    is_cancelled = False


def test_sad_two_writes_never_run_on_one_backend_at_once():
    """With more than 64 backends a lock was dropped while a call backed off
    holding the old lock object: two writes on backend X at once (3/3)."""
    remotes = {f"profile:r{i}": object() for i in range(70)}
    inside: dict = {}
    worst: dict = {}
    guard = threading.Lock()

    def work(args, ctx):
        b = args["backend"]
        with guard:
            inside[b] = inside.get(b, 0) + 1
            worst[b] = max(worst.get(b, 0), inside[b])
        time.sleep(args.get("hold", 0.05))
        with guard:
            inside[b] -= 1
        return {}

    w = M._serialized(work, "write_file", lambda kind, value: remotes[value])
    x = "profile:r0"
    t1 = threading.Thread(target=w, args=({"backend": x, "hold": 0.5}, _Ctx()))
    t1.start()
    time.sleep(0.05)
    t2 = threading.Thread(target=w, args=({"backend": x, "hold": 1.0}, _Ctx()))
    t2.start()
    t1.join()
    for i in range(1, 70):
        w({"backend": f"profile:r{i}", "hold": 0}, _Ctx())
    t3 = threading.Thread(target=w, args=({"backend": x, "hold": 1.0}, _Ctx()))
    t3.start()
    t2.join()
    t3.join()
    assert worst[x] == 1


def test_sad_a_short_write_does_not_starve_behind_busy_writers():
    """Try-lock polling: a 30 ms write waited up to 20.7 s behind 16 busy
    writers. Waiting is first come, first served now."""
    stop = time.time() + 10
    write = M._serialized(lambda a, c: time.sleep(0.03), "write_file",
                          lambda kind, value: None)

    def writer():
        while time.time() < stop:
            write({"path": "x"}, _Ctx())
            time.sleep(0.005)

    threads = [threading.Thread(target=writer, daemon=True) for _ in range(16)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    waits = []
    while time.time() < stop - 1:
        started = time.time()
        write({"path": "y"}, _Ctx())
        waits.append(time.time() - started)
        time.sleep(0.2)
    for t in threads:
        t.join(5)
    # First come, first served: at most one turn of the 16 writers (0.5 s).
    assert max(waits) < 1.0, (statistics.median(waits), max(waits))


# --- info: no TLS renegotiation --------------------------------------------------------


def test_happy_the_tls_context_refuses_renegotiation():
    import ssl

    from core import mcp_http as H

    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        pytest.skip("no OP_NO_RENEGOTIATION in this ssl")
    assert H._TLS_SERVER_OPTIONS & ssl.OP_NO_RENEGOTIATION


def test_sad_on_one_address_a_progressing_handshake_outlives_stalled_connections(monkeypatch):
    """Loopback mTLS at 100 ms with the attackers on the same address:
    0/14 - by bytes the handshake always lost. Within one address the
    connection silent longest goes: attackers send their burst and stall,
    a handshake in flight keeps receiving."""
    from core import mcp_http as H

    monkeypatch.setattr(H, "_bytes_received", lambda sock: sock.sent)
    monkeypatch.setattr(H, "_silence_ms", lambda sock: sock.silence)
    table = H._ConnectionTable(max_connections=20, per_ip=100)
    legit = _Sock(sent=300)
    legit.silence = 120  # a round trip ago
    assert table.admit(legit, "127.0.0.1")
    for _ in range(19):
        s = _Sock(sent=4000)
        s.silence = 5000
        table.admit(s, "127.0.0.1")
    for row in table._open.values():
        row[1] -= 1.0
    for _ in range(40):
        s = _Sock(sent=4000)
        s.silence = 5000
        assert table.admit(s, "127.0.0.1")
        for row in table._open.values():
            row[1] -= 0.3
    assert not legit.shut
