"""The allowlist network of a container MCP server: an HTTPS proxy in axross.

A server installed with the network "Allowlist" (core.mcp_install) runs in
podman with pasta set up so that its only way out is one port on the host's
loopback (``--network=pasta:--no-map-gw,--no-udp,--no-icmp,--ipv4-only,
-o,127.0.0.1,-T,<port>``: outbound sockets are bound to 127.0.0.1, so no
address outside the host is reachable, and ``-T`` forwards that one port).
On that port listens an :class:`EgressProxy`: it accepts ``CONNECT
host:port`` for the allowed ``host:port`` entries only and opens the
connection itself. Measured with podman 6.1.4 / pasta 2026_10_02: the
container reached the forwarded port and nothing else (another loopback
port, 1.1.1.1:443, pypi's address: refused; plain pasta: both reachable).

The server must honour ``HTTPS_PROXY`` (Python's httpx/requests, npm and
pip do; Node's built-in fetch does not): a server that ignores it has no
route at all and fails closed.

Refused, with a reason in the answer: a host or port not on the list, a
request other than CONNECT, a request head over :data:`MAX_HEAD` bytes or
slower than *head_timeout*, an allowed name that resolves to a loopback,
link-local, multicast or unspecified address (it could reach the host's
own services), more than *max_connections* tunnels at once.
"""

from __future__ import annotations

import ipaddress
import logging
import select
import socket
import threading
import time
from typing import Iterable

from core.agent_net import parse_host

log = logging.getLogger(__name__)

#: Bytes a request head may have.
MAX_HEAD = 8192
#: Seconds to send the request head.
HEAD_TIMEOUT = 10.0
#: Seconds to open the connection to the allowed host.
CONNECT_TIMEOUT = 15.0
#: Seconds a tunnel may stay silent in both directions.
IDLE_TIMEOUT = 300.0
MAX_CONNECTIONS = 64


def _refused_address(address: str) -> str:
    """Why *address* may not be connected to ("" = it may)."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "not an address"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "not a host address"
    return ""


class EgressProxy:
    """A CONNECT-only proxy on 127.0.0.1 for the allowed ``host:port``
    entries. *allow_loopback* is for tests (their upstream is local)."""

    def __init__(self, hosts: Iterable[str], *, allow_loopback: bool = False,
                 head_timeout: float = HEAD_TIMEOUT, max_connections: int = MAX_CONNECTIONS,
                 resolver=socket.getaddrinfo) -> None:
        allowed = {parse_host(h) for h in hosts}
        if not allowed:
            raise ValueError("an allowlist needs at least one host:port")
        self.allowed = frozenset(allowed)
        self._allow_loopback = allow_loopback
        self._head_timeout = head_timeout
        self._resolver = resolver
        self._slots = threading.BoundedSemaphore(max(1, int(max_connections)))
        self._sock: socket.socket | None = None
        self._closed = threading.Event()
        self.port = 0

    def start(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(64)
        self._sock = sock
        self.port = sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True, name="mcp-egress").start()
        log.info("mcp egress: proxy on 127.0.0.1:%d for %s", self.port,
                 ", ".join(f"{h}:{p}" for h, p in sorted(self.allowed)))
        return self.port

    def close(self) -> None:
        self._closed.set()
        if self._sock is not None:
            try:
                # shutdown first: close alone leaves a blocked accept() - and
                # the listening port - alive on Linux.
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass

    def _accept(self) -> None:
        while not self._closed.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                self._answer(conn, 503, "too many connections")
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="mcp-egress-conn").start()

    @staticmethod
    def _answer(conn: socket.socket, code: int, reason: str) -> None:
        texts = {200: "Connection established", 400: "Bad Request", 403: "Forbidden",
                 405: "Method Not Allowed", 408: "Request Timeout",
                 431: "Request Header Fields Too Large", 502: "Bad Gateway",
                 503: "Service Unavailable"}
        head = f"HTTP/1.1 {code} {texts.get(code, 'Error')}\r\n"
        if code != 200:
            head += f"X-Axross-Egress: {reason}\r\nContent-Length: 0\r\nConnection: close\r\n"
        try:
            conn.sendall((head + "\r\n").encode("ascii", "replace"))
        except OSError:
            pass

    def _read_head(self, conn: socket.socket) -> bytes | int:
        """The request head, or the error code to answer."""
        conn.settimeout(self._head_timeout)
        deadline = time.monotonic() + self._head_timeout
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) > MAX_HEAD:
                return 431
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 408
            conn.settimeout(remaining)
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                return 408
            except OSError:
                return 400
            if not chunk:
                return 400
            data += chunk
        if data.index(b"\r\n\r\n") > MAX_HEAD:
            return 431
        return data

    def _serve(self, conn: socket.socket) -> None:
        upstream = None
        try:
            head = self._read_head(conn)
            if isinstance(head, int):
                self._answer(conn, head, "bad request head")
                return
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                self._answer(conn, 400, "not an HTTP request")
                return
            if parts[0] != "CONNECT":
                self._answer(conn, 405, "only CONNECT (https) is proxied")
                return
            try:
                host, port = parse_host(parts[1])
            except ValueError:
                self._answer(conn, 400, "CONNECT needs host:port")
                return
            if (host, port) not in self.allowed:
                log.info("mcp egress: refused %s:%d - not allowed", host, port)
                self._answer(conn, 403, f"{host}:{port} is not allowed")
                return
            upstream, why = self._connect(host, port)
            if upstream is None:
                code = 403 if why.startswith("resolves to") else 502
                log.info("mcp egress: refused %s:%d - %s", host, port, why)
                self._answer(conn, code, why)
                return
            self._answer(conn, 200, "")
            self._pipe(conn, upstream)
        finally:
            for sock in (conn, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._slots.release()

    def _connect(self, host: str, port: int) -> tuple[socket.socket | None, str]:
        try:
            infos = self._resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            return None, f"cannot resolve {host}: {exc}"
        last = "no address"
        refused = ""
        for family, kind, proto, _canon, address in infos:
            why = _refused_address(address[0])
            if why and not (self._allow_loopback and why == "a loopback address"):
                refused = f"resolves to {why} ({address[0]})"
                continue
            sock = socket.socket(family, kind, proto)
            sock.settimeout(CONNECT_TIMEOUT)
            try:
                sock.connect(address)
            except OSError as exc:
                sock.close()
                last = f"cannot connect to {host}:{port}: {exc}"
                continue
            sock.settimeout(None)
            return sock, ""
        return None, refused or last

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        a.settimeout(None)
        pair = {a: b, b: a}
        while not self._closed.is_set():
            readable, _, _ = select.select(list(pair), [], [], IDLE_TIMEOUT)
            if not readable:
                return  # idle
            for sock in readable:
                try:
                    data = sock.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    pair[sock].sendall(data)
                except OSError:
                    return


_SHARED: dict[frozenset, EgressProxy] = {}
_SHARED_LOCK = threading.Lock()


def shared_proxy(hosts: Iterable[str]) -> EgressProxy:
    """The running proxy for this allowlist (started on first use, kept
    while axross runs): every server with the same list shares it."""
    key = frozenset(parse_host(h) for h in hosts)
    with _SHARED_LOCK:
        proxy = _SHARED.get(key)
        if proxy is None or proxy._closed.is_set():
            proxy = EgressProxy([f"[{h}]:{p}" if ":" in h else f"{h}:{p}" for h, p in key])
            proxy.start()
            _SHARED[key] = proxy
        return proxy
