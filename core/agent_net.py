"""The allowed hosts of an agent sandbox: TCP through axross, nothing else.

A sandbox on the ``normal`` or ``high`` level has no network of its own.
For every allowed ``host:port`` the worker listens on its loopback and
resolves the host name to that listener (:class:`WorkerBridge`); a
connection there becomes a stream over the worker's channel, and axross
(:class:`HostRelay`) opens the real TCP connection - after checking the
host against the sandbox profile as it is *now*, so removing a host
takes effect at the next connection without a restart.

Entries are ``host:port`` (``[v6]:port`` for IPv6), lower-cased; the port
is required. No wildcards: an allowed host is a decision about one
machine and one service.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import socket
import threading
import urllib.error
import urllib.request
from typing import Callable

log = logging.getLogger(__name__)

#: Bytes per data frame on the channel.
CHUNK = 64 * 1024
#: Seconds to open a TCP connection on the host.
CONNECT_TIMEOUT = 15.0
#: Bytes kept for a stream whose answer has not arrived yet.
EARLY_LIMIT = 4 * 1024 * 1024


def parse_host(entry: str) -> tuple[str, int]:
    """``(host, port)`` of an allowed-host entry; ValueError if it is none."""
    text = str(entry).strip().lower()
    if not text:
        raise ValueError("an empty host entry")
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError(f"{entry!r}: write an IPv6 host as [address]:port")
        ipaddress.IPv6Address(host)
        port_text = rest[1:]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep or not host:
            raise ValueError(f"{entry!r}: the port is missing (host:port)")
        if ":" in host:
            raise ValueError(f"{entry!r}: write an IPv6 host as [address]:port")
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError(f"{entry!r}: the port must be 1-65535")
    if any(c in host for c in " /\\*?@") or len(host) > 253:
        raise ValueError(f"{entry!r}: not a host name or address")
    return host, int(port_text)


def parse_hosts(entries) -> tuple[tuple[str, int], ...]:
    """The valid entries of *entries*, in order, without duplicates."""
    out: list[tuple[str, int]] = []
    for entry in entries or ():
        try:
            pair = parse_host(entry)
        except ValueError:
            continue
        if pair not in out:
            out.append(pair)
    return tuple(out)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class HostRelay:
    """axross's side: opens the allowed TCP connections and pumps them.

    *send* writes a message to the worker; *allowed* answers whether
    ``(host, port)`` may be reached right now.
    """

    def __init__(self, send: Callable[[dict], None], allowed: Callable[[str, int], bool]) -> None:
        self._send = send
        self._allowed = allowed
        self._lock = threading.Lock()
        self._streams: dict[int, socket.socket] = {}
        self._next = 0

    def open(self, host: str, port: int) -> int:
        host = str(host).lower()
        if not self._allowed(host, int(port)):
            raise PermissionError(f"{host}:{port} is not an allowed host of this sandbox")
        sock = socket.create_connection((host, int(port)), timeout=CONNECT_TIMEOUT)
        sock.settimeout(None)
        with self._lock:
            self._next += 1
            stream = self._next
            self._streams[stream] = sock
        threading.Thread(target=self._pump, args=(stream, sock), daemon=True,
                         name=f"agent-relay-{stream}").start()
        log.info("agent sandbox: opened %s:%s (stream %s)", host, port, stream)
        return stream

    def _pump(self, stream: int, sock: socket.socket) -> None:
        try:
            while True:
                data = sock.recv(CHUNK)
                if not data:
                    break
                self._send({"type": "tcp_data", "stream": stream, "data": _b64(data)})
        except OSError:
            pass
        self._drop(stream)
        self._send({"type": "tcp_close", "stream": stream})

    def write(self, stream, data: str) -> None:
        with self._lock:
            sock = self._streams.get(stream)
        if sock is None:
            return
        try:
            sock.sendall(base64.b64decode(data, validate=True))
        except (OSError, ValueError, TypeError):
            self.close(stream)

    def _drop(self, stream) -> socket.socket | None:
        with self._lock:
            return self._streams.pop(stream, None)

    def close(self, stream) -> None:
        sock = self._drop(stream)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def close_all(self) -> None:
        with self._lock:
            streams = list(self._streams)
        for stream in streams:
            self.close(stream)


class WorkerBridge:
    """The worker's side: a loopback listener per allowed host, and the
    host names resolved to them.

    *request* sends a message and waits for axross's answer (the
    worker channel's ``request``); *send* sends one without waiting.
    """

    def __init__(self, request: Callable[[dict], dict], send: Callable[[dict], None],
                 hosts) -> None:
        self._request = request
        self._send = send
        self._lock = threading.Lock()
        self._conns: dict[int, socket.socket] = {}
        #: Frames that arrived before their stream was registered: axross's
        #: side may send a server's first bytes (an SSH banner) before the
        #: worker has read the answer that names the stream. None = closed.
        self._early: dict[int, list] = {}
        #: Streams that were registered and are closed: a late close or
        #: frame for them is no early frame.
        self._finished: set[int] = set()
        self._listeners: list[socket.socket] = []
        #: (host, port) -> the loopback port that stands for it
        self.mapping: dict[tuple[str, int], int] = {}
        for host, port in parse_hosts(hosts):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            self._listeners.append(listener)
            self.mapping[(host, port)] = listener.getsockname()[1]
            threading.Thread(target=self._accept, args=(listener, host, port), daemon=True).start()

    def install(self) -> None:
        """Resolve the allowed hosts to their listeners; everything else
        resolves as before (and finds no network)."""
        original = socket.getaddrinfo
        mapping = self.mapping

        def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
            key = (str(host).lower() if host is not None else "", _port_number(port))
            local = mapping.get(key)
            if local is not None:
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                         ("127.0.0.1", local))]
            return original(host, port, family, type, proto, flags)

        socket.getaddrinfo = getaddrinfo

    def _accept(self, listener: socket.socket, host: str, port: int) -> None:
        while True:
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, host, port), daemon=True).start()

    def _serve(self, conn: socket.socket, host: str, port: int) -> None:
        try:
            reply = self._request({"type": "tcp_open", "host": host, "port": port})
        except Exception:  # noqa: BLE001 - the channel is gone
            conn.close()
            return
        stream = (
            (reply.get("value") or {}).get("stream")
            if isinstance(reply.get("value"), dict)
            else None
        )
        if "error" in reply or not isinstance(stream, int):
            log.warning("agent sandbox: %s:%s refused: %s", host, port, reply.get("error"))
            conn.close()
            return
        with self._lock:
            self._conns[stream] = conn
            early = self._early.pop(stream, [])
        for frame in early:
            if frame is None:
                self.closed(stream)
                return
            try:
                conn.sendall(frame)
            except OSError:
                self.closed(stream)
                return
        try:
            while True:
                data = conn.recv(CHUNK)
                if not data:
                    break
                self._send({"type": "tcp_data", "stream": stream, "data": _b64(data)})
        except OSError:
            pass
        self._send({"type": "tcp_close", "stream": stream})
        self.closed(stream)

    def deliver(self, stream, data: str) -> None:
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, TypeError):
            self.closed(stream)
            return
        with self._lock:
            conn = self._conns.get(stream)
            if conn is None:
                if isinstance(stream, int) and stream not in self._finished:
                    early = self._early.setdefault(stream, [])
                    if sum(len(f) for f in early if f) + len(raw) <= EARLY_LIMIT:
                        early.append(raw)
                return
        try:
            conn.sendall(raw)
        except OSError:
            self.closed(stream)

    def closed(self, stream) -> None:
        with self._lock:
            conn = self._conns.pop(stream, None)
            if conn is not None:
                self._finished.add(stream)
            elif isinstance(stream, int) and stream not in self._finished:
                self._early.setdefault(stream, []).append(None)
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def close(self) -> None:
        for listener in self._listeners:
            listener.close()
        with self._lock:
            streams = list(self._conns)
        for stream in streams:
            self.closed(stream)


def _port_number(port) -> int | None:
    if isinstance(port, int):
        return port
    if isinstance(port, (str, bytes)):
        text = port.decode() if isinstance(port, bytes) else port
        if text.isdigit():
            return int(text)
        try:
            return socket.getservbyname(text, "tcp")
        except OSError:
            return None
    return None


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"a redirect to {newurl} is not followed", headers, fp
        )


def opener_without_redirects(*handlers) -> urllib.request.OpenerDirector:
    """urllib's opener (environment proxies included) that never follows a
    redirect: urllib would send the Authorization header on to the host the
    redirect names - an API key or token past the allowed hosts. *handlers*
    are added (an :class:`AbortableConnections`' ones)."""
    return urllib.request.build_opener(_RefuseRedirects, *handlers)


class AbortableConnections:
    """The connections of one opener, so another thread can cut them: Stop
    during a model request. Shutting the socket down wakes the request's
    blocked read at once, and the server sees the client leave and stops
    generating. A connection made after :meth:`abort` is cut as it opens."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connections: list = []
        self.aborted = False

    def handlers(self) -> tuple:
        return (_TrackingHTTPHandler(self), _TrackingHTTPSHandler(self))

    def _factory(self, http_class):
        def make(host, **kwargs):
            connection = http_class(host, **kwargs)
            connect = connection.connect

            def connect_and_track() -> None:
                connect()
                self._opened(connection)

            connection.connect = connect_and_track
            return connection

        return make

    def _opened(self, connection) -> None:
        with self._lock:
            self._connections.append(connection)
            aborted = self.aborted
        if aborted:
            _cut(connection)

    def abort(self) -> None:
        with self._lock:
            self.aborted = True
            connections = list(self._connections)
        for connection in connections:
            _cut(connection)


def _cut(connection) -> None:
    sock = getattr(connection, "sock", None)
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # already closed


class _TrackingHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, tracker: AbortableConnections) -> None:
        super().__init__()
        self._tracker = tracker

    def do_open(self, http_class, req, **kwargs):  # noqa: D401 - urllib API
        return super().do_open(self._tracker._factory(http_class), req, **kwargs)


class _TrackingHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, tracker: AbortableConnections) -> None:
        super().__init__()
        self._tracker = tracker

    def do_open(self, http_class, req, **kwargs):  # noqa: D401 - urllib API
        return super().do_open(self._tracker._factory(http_class), req, **kwargs)
