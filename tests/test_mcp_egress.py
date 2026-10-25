"""The allowlist proxy of container MCP servers (core.mcp_egress): CONNECT
to an allowed host:port only, everything else refused with a reason."""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_egress as E  # noqa: E402


@pytest.fixture
def echo_server():
    """A TCP server on loopback that answers "hello" and echoes."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            def one(c=conn):
                with c:
                    try:
                        c.sendall(b"hello\n")
                        while True:
                            data = c.recv(4096)
                            if not data:
                                return
                            c.sendall(data)
                    except OSError:
                        return  # the proxy cut the tunnel
            threading.Thread(target=one, daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield sock.getsockname()[1]
    sock.close()


def _proxy(hosts, **kw):
    proxy = E.EgressProxy(hosts, **kw)
    proxy.start()
    return proxy


def _ask(port: int, head: bytes, timeout: float = 5.0) -> tuple[socket.socket, bytes]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.sendall(head)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return sock, data


# -- happy ---------------------------------------------------------------------------


def test_happy_an_allowed_host_is_tunnelled(echo_server):
    proxy = _proxy([f"localhost:{echo_server}"], allow_loopback=True)
    try:
        sock, head = _ask(proxy.port, f"CONNECT localhost:{echo_server} HTTP/1.1\r\n"
                                      f"Host: localhost\r\n\r\n".encode())
        assert head.startswith(b"HTTP/1.1 200")
        rest = head.split(b"\r\n\r\n", 1)[1]
        while b"hello\n" not in rest:
            rest += sock.recv(4096)
        sock.sendall(b"ping")
        echoed = b""
        while len(echoed) < 4:
            echoed += sock.recv(4096)
        assert echoed == b"ping"
        sock.close()
    finally:
        proxy.close()


def test_happy_a_shared_proxy_per_allowlist():
    one = E.shared_proxy(("a.example:443", "b.example:443"))
    two = E.shared_proxy(("b.example:443", "a.example:443"))
    other = E.shared_proxy(("c.example:443",))
    assert one is two and one.port == two.port
    assert other is not one


# -- sad -----------------------------------------------------------------------------


def test_sad_a_host_not_on_the_list_is_refused(echo_server):
    proxy = _proxy([f"localhost:{echo_server}"], allow_loopback=True)
    try:
        sock, head = _ask(proxy.port, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 403") and b"not allowed" in head
        sock.close()
        sock, head = _ask(proxy.port, f"CONNECT localhost:{echo_server + 1} HTTP/1.1\r\n\r\n"
                          .encode())
        assert head.startswith(b"HTTP/1.1 403")  # the right host, another port
        sock.close()
    finally:
        proxy.close()


def test_sad_plain_http_and_garbage_are_refused():
    proxy = _proxy(["a.example:80"])
    try:
        sock, head = _ask(proxy.port, b"GET http://a.example/ HTTP/1.1\r\nHost: a\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 405")
        sock.close()
        sock, head = _ask(proxy.port, b"\x16\x03\x01 not http at all\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 400")
        sock.close()
    finally:
        proxy.close()


def test_sad_a_name_that_resolves_to_loopback_is_refused(echo_server):
    # Allowed by name, but resolving to the host's own loopback: refused,
    # or an allowed name could reach the host's local services.
    proxy = _proxy([f"localhost:{echo_server}"])
    try:
        sock, head = _ask(proxy.port, f"CONNECT localhost:{echo_server} HTTP/1.1\r\n\r\n"
                          .encode())
        assert head.startswith(b"HTTP/1.1 403") and b"loopback" in head.lower()
        sock.close()
    finally:
        proxy.close()


def test_sad_a_slow_or_huge_request_head_is_cut():
    proxy = _proxy(["a.example:443"], head_timeout=0.5)
    try:
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        sock.sendall(b"CONNECT a.exa")
        start = time.monotonic()
        data = sock.recv(4096)
        assert time.monotonic() - start < 3
        assert data == b"" or data.startswith(b"HTTP/1.1 408")
        sock.close()
        sock, head = _ask(proxy.port, b"CONNECT a.example:443 HTTP/1.1\r\nX: " + b"a" * 10000)
        assert head.startswith(b"HTTP/1.1 431") or head == b""
        sock.close()
    finally:
        proxy.close()


def test_sad_an_unreachable_allowed_host_says_so():
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()  # nothing listens there now
    proxy = _proxy([f"127.0.0.1:{port}"], allow_loopback=True)
    try:
        sock, head = _ask(proxy.port, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        assert head.startswith(b"HTTP/1.1 502")
        sock.close()
    finally:
        proxy.close()


def test_sad_bad_allowlists_are_refused():
    with pytest.raises(ValueError):
        E.EgressProxy(["no-port"])
    with pytest.raises(ValueError):
        E.EgressProxy([])


# -- edge ----------------------------------------------------------------------------


def test_edge_host_names_match_case_insensitively(echo_server):
    proxy = _proxy([f"LocalHost:{echo_server}"], allow_loopback=True)
    try:
        sock, head = _ask(proxy.port, f"CONNECT LOCALHOST:{echo_server} HTTP/1.1\r\n\r\n"
                          .encode())
        assert head.startswith(b"HTTP/1.1 200")
        sock.close()
    finally:
        proxy.close()


def test_edge_connections_beyond_the_cap_are_refused(echo_server):
    proxy = _proxy([f"localhost:{echo_server}"], allow_loopback=True, max_connections=2)
    held = []
    try:
        for _ in range(2):
            sock, head = _ask(proxy.port, f"CONNECT localhost:{echo_server} HTTP/1.1\r\n\r\n"
                              .encode())
            assert head.startswith(b"HTTP/1.1 200")
            held.append(sock)
        sock, head = _ask(proxy.port, f"CONNECT localhost:{echo_server} HTTP/1.1\r\n\r\n"
                          .encode())
        assert head.startswith(b"HTTP/1.1 503")
        sock.close()
    finally:
        for sock in held:
            sock.close()
        proxy.close()


def test_edge_close_stops_listening():
    proxy = _proxy(["a.example:443"])
    port = proxy.port
    proxy.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)
