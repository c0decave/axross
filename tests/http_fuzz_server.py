"""A raw HTTP/1.1 fake server for the HTTP-based fuzz suites.

``responder(method, path, headers, body)`` returns the complete raw
response bytes (so a test can send malformed HTTP), ``STALL`` to go silent,
or ``None`` to hang up. Connections are kept alive between requests.
"""

from __future__ import annotations

import socket

from fuzz_testkit import ScriptedServer, stall

STALL = object()
MAX_REQUEST_BODY = 64 * 1024 * 1024


def response(status: int = 200, body: bytes = b"", headers: dict | None = None, reason: str = "X"):
    """Well-formed raw response bytes."""
    hdrs = {"Content-Length": str(len(body)), **(headers or {})}
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    return head.encode("latin-1") + b"\r\n" + body


def _read_request(conn: socket.socket, buf: bytearray):
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 1 << 20:
            return None
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    buf[:] = rest
    lines = head.decode("latin-1").split("\r\n")
    method, path, *_ = lines[0].split(" ") + ["", ""]
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    body = b""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        while True:
            while b"\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            line, _, rest = bytes(buf).partition(b"\r\n")
            size = int(line.split(b";")[0] or b"0", 16)
            buf[:] = rest
            while len(buf) < size + 2:
                chunk = conn.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            body += bytes(buf[:size])
            buf[:] = buf[size + 2 :]
            if size == 0:
                break
    else:
        length = int(headers.get("content-length", "0") or 0)
        length = min(length, MAX_REQUEST_BODY)
        while len(buf) < length:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buf += chunk
        body = bytes(buf[:length])
        buf[:] = buf[length:]
    return method, path, headers, body


class FakeHttpServer:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port
        self.url = f"http://127.0.0.1:{self.port}"

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(20)
        buf = bytearray()
        while True:
            req = _read_request(conn, buf)
            if req is None:
                return
            self.requests.append(req)
            out = self.responder(*req)
            if out is None:
                return
            if out is STALL:
                stall(conn, 15)
                return
            conn.sendall(out)

    def close(self) -> None:
        self.server.close()

    def __enter__(self) -> "FakeHttpServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
