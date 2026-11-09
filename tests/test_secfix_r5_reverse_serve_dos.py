"""Reverse serve: clients without the token cannot lock a token holder out
or make the server hold their headers (security review round 5).

Measured before (rserve/v_slots, v_headermem):

* 64 idle sockets that never sent a byte held every connection slot for
  HEADER_DEADLINE_S (30 s): a token holder got 503. 64 sockets sending an
  unauthenticated ``GET`` every 3 s on keep-alive (401, connection kept)
  held them as long as their client liked.
* 64 connections each sending 99 header lines of 65 KB (http.server's own
  limits) and stalling before the blank line grew the server to 433 MB.
"""

from __future__ import annotations

import http.client
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

TOKEN = "r5-dos-" + "t" * 28


@pytest.fixture
def root(tmp_path):
    served = tmp_path / "root"
    (served / "b").mkdir(parents=True)
    (served / "b" / "f").write_bytes(b"old")
    return served


def _serve(root, kind="webdav"):
    fn = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return fn(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), auth_token=TOKEN)


def _legit_get(server, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=timeout)
    try:
        conn.request("GET", "/b/f", headers={"Authorization": f"Bearer {TOKEN}"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _closed(sock, wait=5.0) -> bool:
    sock.settimeout(wait)
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


# -- sad --------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["webdav", "s3"])
def test_sad_idle_connections_without_the_token_do_not_lock_a_token_holder_out(
        root, monkeypatch, kind):
    monkeypatch.setattr(RS, "MAX_CONNECTIONS", 4)
    server = _serve(root, kind)
    held = []
    try:
        for _ in range(4):
            held.append(socket.create_connection(("127.0.0.1", server.port), timeout=5))
        time.sleep(0.3)
        assert _legit_get(server) == (200, b"old")
    finally:
        for s in held:
            s.close()
        server.shutdown()


def test_sad_a_401_ends_the_connection(root):
    server = _serve(root)
    try:
        s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        s.sendall(b"GET /b/f HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        s.settimeout(5)
        head = s.recv(65536)
        assert head.startswith(b"HTTP/1.1 401")
        assert b"Connection: close" in head
        assert _closed(s)
        s.close()
    finally:
        server.shutdown()


def test_sad_keep_alive_requests_without_the_token_do_not_hold_the_slots(root, monkeypatch):
    monkeypatch.setattr(RS, "MAX_CONNECTIONS", 4)
    server = _serve(root)
    held = []
    try:
        for _ in range(4):
            s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
            s.sendall(b"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")  # no token needed
            s.recv(65536)
            held.append(s)
        assert _legit_get(server) == (200, b"old")
    finally:
        for s in held:
            s.close()
        server.shutdown()


def test_sad_headers_over_the_cap_are_answered_431_and_closed(root):
    server = _serve(root)
    try:
        s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        line = b"X-A: " + b"a" * 60000 + b"\r\n"
        try:
            s.sendall(b"GET /b/f HTTP/1.1\r\nHost: 127.0.0.1\r\n" + line * 3)
        except (BrokenPipeError, ConnectionResetError):
            pass  # closed while it still sent: what the cap means
        s.settimeout(5)
        try:
            answer = s.recv(65536)
        except ConnectionResetError:
            answer = b""
        assert answer == b"" or answer.startswith(b"HTTP/1.1 431")
        assert _closed(s)
        s.close()
        assert _legit_get(server) == (200, b"old")
    finally:
        server.shutdown()


# -- edge -------------------------------------------------------------------------------------


def test_edge_one_address_holds_only_a_few_connections_without_the_token(root, monkeypatch):
    monkeypatch.setattr(RS, "MAX_PENDING_PER_ADDRESS", 3)
    server = _serve(root)
    socks = []
    try:
        for _ in range(4):
            socks.append(socket.create_connection(("127.0.0.1", server.port), timeout=5))
            time.sleep(0.1)
        assert _closed(socks[0])  # the oldest gave its place up
        socks[3].settimeout(0.3)
        with pytest.raises(socket.timeout):
            socks[3].recv(1)  # the newest is still served
    finally:
        for s in socks:
            s.close()
        server.shutdown()


def test_edge_a_token_holders_kept_alive_connection_is_never_given_up(root, monkeypatch):
    monkeypatch.setattr(RS, "MAX_CONNECTIONS", 2)
    monkeypatch.setattr(RS, "KEEPALIVE_IDLE_S", 30.0)
    monkeypatch.setattr(RS, "EVICT_WAIT_S", 0.2)
    server = _serve(root)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        conn.request("GET", "/b/f", headers={"Authorization": f"Bearer {TOKEN}"})
        assert conn.getresponse().read() == b"old"
        idle = [socket.create_connection(("127.0.0.1", server.port), timeout=5)
                for _ in range(3)]
        time.sleep(0.3)
        # The authenticated connection still carries its next request.
        conn.request("GET", "/b/f", headers={"Authorization": f"Bearer {TOKEN}"})
        assert conn.getresponse().read() == b"old"
        conn.close()
        for s in idle:
            s.close()
    finally:
        server.shutdown()


# -- happy ------------------------------------------------------------------------------------


def test_happy_one_connection_carries_several_requests_with_the_token(root):
    server = _serve(root)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        for _ in range(3):
            conn.request("GET", "/b/f", headers={"Authorization": f"Bearer {TOKEN}"})
            resp = conn.getresponse()
            assert (resp.status, resp.read()) == (200, b"old")
            assert resp.getheader("Connection", "").lower() != "close"
        conn.close()
    finally:
        server.shutdown()


def test_happy_ordinary_headers_pass(root):
    server = _serve(root)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        headers = {"Authorization": f"Bearer {TOKEN}"}
        headers.update({f"X-Meta-{i}": "v" * 200 for i in range(50)})  # ~11 KB
        conn.request("GET", "/b/f", headers=headers)
        resp = conn.getresponse()
        assert (resp.status, resp.read()) == (200, b"old")
        conn.close()
    finally:
        server.shutdown()
