"""Round 6 (independent verification) of the headless MCP server.

Each test is the reviewer's repro (/root/mcptest/round6/...) reduced to
what it proves; the section headers name the review's item.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from core import mcp_server as M
from tests import mcp_group_testkit as T
from tests.test_mcp_round3 import _backend, ram  # noqa: F401 - the RAM-profile fixture

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "t" * 32


def _http_server(monkeypatch, config_args=None, **consts):
    from core import mcp_http as H
    from core.local_fs import LocalFS

    for key, value in consts.items():
        monkeypatch.setattr(H, key, value)
    config = H.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                auth_token=TOKEN, **(config_args or {}))
    server = H.build_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return H, server


def _stop(H, server):
    server.shutdown()
    server.server_close()
    fwd = getattr(server, "_mcp_log_forwarder", None)
    if fwd is not None:
        H._mcp._detach_log_forwarder(fwd)


def _health(port, timeout=5.0):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("GET", "/health")
    status = conn.getresponse().status
    conn.close()
    return status


# --- 1/2: one connection's reading never holds another's ---------------------------


def test_sad_one_connection_stuck_in_its_first_read_does_not_hold_the_others(monkeypatch):
    """One TLS client kept OpenSSL busy inside a single recv of the shared
    selector thread (KeyUpdate after KeyUpdate): every other client - a
    legitimate mTLS /health too - waited 60 s. Each connection is read on
    its own thread: a read that blocks holds that connection only."""
    H, server = _http_server(monkeypatch)
    blocked = threading.Event()
    release = threading.Event()
    real_recv = socket.socket.recv
    real_recv_into = socket.socket.recv_into
    stuck_fds: set = set()

    def stuck(sock):
        if sock.fileno() in stuck_fds and not release.is_set():
            blocked.set()
            release.wait(10)

    def recv(self, *a, **k):
        stuck(self)
        return real_recv(self, *a, **k)

    def recv_into(self, *a, **k):
        stuck(self)
        return real_recv_into(self, *a, **k)

    monkeypatch.setattr(socket.socket, "recv", recv)
    monkeypatch.setattr(socket.socket, "recv_into", recv_into)
    real_get_request = server.get_request

    def get_request():
        sock, addr = real_get_request()
        if not stuck_fds:
            stuck_fds.add(sock.fileno())  # the first connection: its reads block
        return sock, addr

    monkeypatch.setattr(server, "get_request", get_request)
    try:
        port = server.server_address[1]
        hog = socket.create_connection(("127.0.0.1", port), timeout=5)
        hog.sendall(b"GET /health HTTP/1.1\r\n")
        assert blocked.wait(5)
        started = time.monotonic()
        assert _health(port, timeout=5) == 200
        assert time.monotonic() - started < 2
    finally:
        release.set()
        hog.close()
        _stop(H, server)


# --- 3: file descriptors -------------------------------------------------------------


def test_sad_the_connection_caps_fit_the_fd_limit(monkeypatch):
    """2048 pending connections at a soft limit of 1024: /health timed out
    and tools failed with EMFILE."""
    import resource

    from core import mcp_http as H

    # (Round 7: the cap follows the thread limits as well - unlimited here.)
    monkeypatch.setattr(H, "_thread_room", lambda: None)
    monkeypatch.setattr(resource, "getrlimit", lambda what: (1024, 1024))
    cap = H.connection_cap()
    assert cap <= (1024 - H.FD_HEADROOM) // 2
    monkeypatch.setattr(resource, "getrlimit", lambda what: (1 << 20, 1 << 20))
    assert H.connection_cap() == H.MAX_CONNECTIONS


def test_sad_a_socket_above_fd_1024_is_watched_not_taken_for_a_hang_up():
    """select() raises ValueError for an fd above 1024; the hang-up watch
    took that for "client hung up" and cancelled a token holder's call."""
    import resource

    from core import mcp_http as H

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 2048:
        pytest.skip("the hard fd limit is below 2048")
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 2048), hard))
    a, b = socket.socketpair()
    high = os.dup2(a.fileno(), 1600)
    sock = socket.socket(fileno=high)
    cancelled = []

    class Cancels:
        def cancel(self, request_id):
            cancelled.append(request_id)

    watch = H._HangupWatch()
    try:
        key = watch.add(sock, Cancels(), 7)
        time.sleep(1.0)
        assert cancelled == []
        watch.discard(key)
    finally:
        sock.close()
        a.close()
        b.close()
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


# --- 4/5: write locks ----------------------------------------------------------------


def test_sad_unknown_backend_strings_keep_no_lock_and_take_the_local_one(tmp_path):
    """A lock was created per raw `backend` string (8 MB strings took the
    server to 1.1 GB) - and on a one-backend server any string means local,
    so `backend: "zz"` wrote while `local` was held."""
    root = tmp_path / "root"
    root.mkdir()
    tools = T.build(root, set(), allow_write=True)
    for n in range(50):
        try:
            T.call(tools, "write_file", {"path": str(root / f"f{n}.txt"), "content": "x",
                                         "backend": "zz" + "x" * (1 << 16) + str(n)})
        except T.RpcError:
            pass
    assert len(M._MUTATIONS._held) == 0  # nothing kept per unknown string
    M._MUTATIONS.acquire([M.LOCAL_LOCK_KEY], None)
    try:
        done = []
        worker = threading.Thread(target=lambda: done.append(
            T.call(tools, "write_file", {"path": str(root / "alias.txt"), "content": "x",
                                         "backend": "zz"})), daemon=True)
        worker.start()
        worker.join(1.0)
        assert done == [] and not (root / "alias.txt").exists()  # waits for local
    finally:
        M._MUTATIONS.release([M.LOCAL_LOCK_KEY])
    worker.join(5)


def test_sad_waiting_for_one_backend_holds_no_other(tmp_path, monkeypatch, ram):
    """An upload with a hung CLOSE held profile:nas; a transfer_move from
    nas to local took `local` and then waited for nas - every local write
    timed out for minutes."""
    root = tmp_path / "root"
    root.mkdir()
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    remote = _backend(bid)
    with remote.open_write("/m.txt") as fh:
        fh.write(b"data")
    remote_key = M._lock_key_for(remote)
    holder_ready = threading.Event()
    holder_done = threading.Event()

    def hold():  # a transfer with a hung CLOSE holds the remote (another thread)
        M._MUTATIONS.acquire([remote_key], None)
        holder_ready.set()
        holder_done.wait(20)
        M._MUTATIONS.release([remote_key])

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert holder_ready.wait(5)
    try:
        mover = threading.Thread(target=lambda: T.call(tools, "transfer_move", {
            "src_backend": bid, "src": "/m.txt", "dst": str(root / "m.txt")}), daemon=True)
        mover.start()
        time.sleep(0.5)  # the move now waits for the remote
        started = time.monotonic()
        T.call(tools, "write_file", {"path": str(root / "local.txt"), "content": "x"})
        assert time.monotonic() - started < 2
    finally:
        holder_done.set()
        holder.join(5)
    mover.join(10)
    assert (root / "m.txt").read_bytes() == b"data"


# --- 6: authenticated slow bodies are bounded per client -----------------------------


def _slow_body(port, stop):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
              + TOKEN.encode() + b"\r\nContent-Type: application/json\r\n"
              + b"Content-Length: 100000\r\n\r\n")
    try:
        while not stop.is_set():
            s.sendall(b" ")
            time.sleep(0.3)
    except OSError:
        pass
    finally:
        s.close()


def test_sad_token_holders_trickling_bodies_cannot_hold_every_slot(monkeypatch):
    """300 token-holding connections with slowly trickled bodies (300 s
    each) shut every new client out."""
    H, server = _http_server(monkeypatch, MAX_CONNECTIONS=12, MAX_SLOW_BODIES_PER_CLIENT=4)
    stop = threading.Event()
    trick = [threading.Thread(target=_slow_body, args=(server.server_address[1], stop),
                              daemon=True) for _ in range(20)]
    try:
        for t in trick:
            t.start()
        time.sleep(1.5)
        port = server.server_address[1]
        assert all(_health(port, timeout=5) == 200 for _ in range(5))
    finally:
        stop.set()
        for t in trick:
            t.join(5)
        _stop(H, server)


def test_sad_a_body_slower_than_the_minimum_rate_is_cut(monkeypatch):
    H, server = _http_server(monkeypatch, MIN_BODY_RATE=10_000, BODY_RATE_GRACE_SECONDS=1.0)
    stop = threading.Event()
    s = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=10)
    try:
        s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                  + TOKEN.encode() + b"\r\nContent-Type: application/json\r\n"
                  + b"Content-Length: 100000\r\n\r\n")
        started = time.monotonic()
        answer = b""
        while time.monotonic() - started < 6:
            try:
                s.sendall(b" ")
                s.settimeout(0.3)
                chunk = s.recv(200)
                if not chunk:
                    break
                answer += chunk
                break
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
        assert time.monotonic() - started < 5
    finally:
        stop.set()
        s.close()
        _stop(H, server)


# --- 8: an over-budget listing is an OSError -----------------------------------------


def test_sad_an_over_budget_listing_reports_an_os_error():
    pytest.importorskip("paramiko")
    from core import ssh_client

    exc = ssh_client._over_budget("/x")
    assert type(exc) is OSError and exc.errno == __import__("errno").EFBIG


def test_sad_a_fresh_request_takes_the_place_of_the_slowest_trickling_body(monkeypatch):
    """With every body slot of the (loopback) client held by trickling
    bodies, a fresh request got 503: it now takes the place of the slowest
    body that has been arriving for a while."""
    H, server = _http_server(monkeypatch, MAX_SLOW_BODIES_PER_CLIENT=4)
    stop = threading.Event()
    trick = [threading.Thread(target=_slow_body, args=(server.server_address[1], stop),
                              daemon=True) for _ in range(4)]
    try:
        for t in trick:
            t.start()
        time.sleep(1.5)
        port = server.server_address[1]
        statuses = []
        for _ in range(4):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
            s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                      + TOKEN.encode() + b"\r\nContent-Type: application/json\r\n"
                      + b"Content-Length: %d\r\n\r\n" % len(body) + body)
            statuses.append(s.recv(64).split(b" ")[1])
            s.close()
        assert b"503" not in statuses, statuses
    finally:
        stop.set()
        for t in trick:
            t.join(5)
        _stop(H, server)


def test_sad_the_victim_is_the_connection_that_sent_least_not_a_slow_handshake(monkeypatch):
    """mTLS behind 40 ms: a legitimate handshake takes a few round trips;
    attackers reconnecting 4000 times a second made it the oldest
    connection still sending, and closed it (0/65 in the thread model).
    A newcomer now takes the place of the connection that has sent the
    fewest bytes (a trickler's one), once it is a moment old."""
    import socket as _socket

    from core import mcp_http as H

    if not hasattr(_socket, "TCP_INFO"):
        pytest.skip("no TCP_INFO here: the oldest goes, as before")
    listener = _socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    table = H._ConnectionTable(max_connections=3)
    clients, served = [], []
    for payload in (b"x" * 600, b"\x16", b"\x16"):  # a handshake in progress, two tricklers
        c = _socket.create_connection(listener.getsockname())
        c.sendall(payload)
        s, _ = listener.accept()
        clients.append(c)
        served.append(s)
        assert table.admit(s, "127.0.0.1")
    for row in table._open.values():
        row[1] -= 1.0  # every one a second old
    progressing = served[0]
    c = _socket.create_connection(listener.getsockname())
    s, _ = listener.accept()
    try:
        time.sleep(0.05)
        assert table.admit(s, "127.0.0.1")
        assert progressing in table._open
    finally:
        for sock in clients + served + [c, s, listener]:
            sock.close()
