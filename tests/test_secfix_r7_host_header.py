"""Round-7 security L6: the loopback ``Host`` check of the MCP HTTP server
and of reverse-serve split ``localhost:1@evil.example`` at its one colon and
took ``localhost`` for the host. ``Host`` is now parsed strictly as
``host[:port]`` (port digits only; no ``@``, ``/``, spaces, bare IPv6), and a
request with two ``Host`` or ``Origin`` headers is refused."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_http  # noqa: E402
from core import reverse_serve as RS  # noqa: E402

HOSTILE = ["localhost:1@evil.example", "localhost:1@evil", "127.0.0.1:80@evil.example",
           "localhost/evil", "localhost x", "localhost:", "localhost:99999", "::1",
           "[::1", "127.0.0.1:80:1", "user@localhost", "localhost:+80", "localhost:٣",
           "localhost\r\nX: y"]
ALLOWED = ["localhost", "LOCALHOST", "localhost:7331", "127.0.0.1", "127.0.0.1:1", "[::1]",
           "[::1]:7331", " localhost:80 "]


@pytest.mark.parametrize("value", HOSTILE)
def test_sad_a_host_with_userinfo_path_or_junk_is_not_loopback(value):
    assert not mcp_http._loopback_host_header(value)
    assert not RS._loopback_authority(value)


@pytest.mark.parametrize("value", ALLOWED)
def test_happy_plain_loopback_authorities_still_pass(value):
    assert mcp_http._loopback_host_header(value)
    assert RS._loopback_authority(value)


def _raw(port: int, head: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(head)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return data
            data += chunk


def _status(data: bytes) -> int:
    return int(data.split(b" ", 2)[1])


def test_edge_the_reverse_server_without_a_token_refuses_tricked_and_doubled_hosts(tmp_path):
    from core.local_fs import LocalFS

    root = tmp_path / "root"
    root.mkdir()
    (root / "f").write_bytes(b"secret")
    srv = RS.serve_webdav(LocalFS(), port=0, root_path=str(root), auth_token=None)
    try:
        port = int(srv.base_url.rsplit(":", 1)[1].split("/", 1)[0])

        def get(extra: bytes) -> int:
            return _status(_raw(port, b"GET /f HTTP/1.1\r\n" + extra + b"Connection: close\r\n\r\n"))

        assert get(b"Host: 127.0.0.1\r\n") == 200
        assert get(b"Host: localhost:1@evil.example\r\n") == 403
        assert get(b"Host: 127.0.0.1\r\nHost: evil.example\r\n") == 403
        assert get(b"Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n"
                   b"Origin: http://evil.example\r\n") == 403
    finally:
        srv.shutdown()


def test_edge_the_mcp_http_server_refuses_a_userinfo_host():
    from core.local_fs import LocalFS

    token = "r7-host-test-token-0123456789abcdef"
    server = mcp_http.build_server(mcp_http.HTTPServerConfig(
        backend=LocalFS(), host="127.0.0.1", port=0, auth_token=token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    body = (b'{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": '
            b'{"protocolVersion": "2025-03-26", "capabilities": {}, '
            b'"clientInfo": {"name": "t", "version": "0"}}}')

    def post(hosts: bytes) -> int:
        head = (b"POST /messages HTTP/1.1\r\n" + hosts +
                b"Authorization: Bearer " + token.encode() + b"\r\n"
                b"Content-Type: application/json\r\nConnection: close\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        return _status(_raw(port, head))

    try:
        assert post(f"Host: localhost:{port}\r\n".encode()) == 200
        assert post(b"Host: localhost:1@evil.example\r\n") == 403
        assert post(f"Host: localhost:{port}\r\nHost: evil.example\r\n".encode()) in (400, 403)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
