"""Tiny in-process SOCKS5 proxy for proxy-routing tests.

The server records every CONNECT / UDP target it is asked for and maps it
to a real loopback endpoint, so tests can assert that a backend asked the
proxy for ``db.internal:5432`` while the bytes actually reach a local fake.
"""
from __future__ import annotations

import socket
import struct
import threading
from tests.socket_lifecycle import close_socket  # noqa: E402
from contextlib import contextmanager
from unittest import mock


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def _read_address(sock: socket.socket, atyp: int) -> str:
    if atyp == 1:
        return socket.inet_ntoa(_recv_exact(sock, 4))
    if atyp == 3:
        length = _recv_exact(sock, 1)[0]
        return _recv_exact(sock, length).decode()
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    raise ConnectionError(f"bad atyp {atyp}")


class FakeSocks5Server:
    """Loopback SOCKS5 server (CONNECT + UDP ASSOCIATE)."""

    def __init__(self, routes=None, username: str = "", password: str = ""):
        self.routes = dict(routes or {})  # (host, port) -> (real_host, real_port)
        self.username = username
        self.password = password
        self.connects: list[tuple[str, int]] = []
        self.udp_targets: list[tuple[str, int]] = []
        self.auth_seen: list[tuple[str, str]] = []
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._udp_relays: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._stop.set()
        close_socket(self._listener)
        for relay in self._udp_relays:
            close_socket(relay)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- protocol ----------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            _ver, nmethods = _recv_exact(client, 2)
            methods = _recv_exact(client, nmethods)
            if self.username:
                if 2 not in methods:
                    client.sendall(b"\x05\xff")
                    return
                client.sendall(b"\x05\x02")
                _recv_exact(client, 1)
                user = _recv_exact(client, _recv_exact(client, 1)[0]).decode()
                pw = _recv_exact(client, _recv_exact(client, 1)[0]).decode()
                self.auth_seen.append((user, pw))
                ok = (user, pw) == (self.username, self.password)
                client.sendall(b"\x01\x00" if ok else b"\x01\x01")
                if not ok:
                    return
            else:
                client.sendall(b"\x05\x00")
            _ver, cmd, _rsv, atyp = _recv_exact(client, 4)
            host = _read_address(client, atyp)
            port = struct.unpack("!H", _recv_exact(client, 2))[0]
            if cmd == 1:
                self._connect(client, host, port)
            elif cmd == 3:
                self._udp_associate(client)
            else:
                client.sendall(b"\x05\x07\x00\x01" + b"\0" * 6)
        except (OSError, ConnectionError):
            pass
        finally:
            if not getattr(client, "_keep", False):
                client.close()

    def _connect(self, client: socket.socket, host: str, port: int) -> None:
        self.connects.append((host, port))
        target = self.routes.get((host, port))
        if target is None:
            client.sendall(b"\x05\x05\x00\x01" + b"\0" * 6)  # connection refused
            return
        upstream = socket.create_connection(target, timeout=5)
        client.sendall(b"\x05\x00\x00\x01" + b"\0" * 6)
        done = threading.Event()

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                done.set()
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        t.start()
        pump(client, upstream)
        t.join(timeout=2)
        upstream.close()

    def _udp_associate(self, client: socket.socket) -> None:
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        self._udp_relays.append(relay)
        rport = relay.getsockname()[1]
        reply = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1")
        client.sendall(reply + struct.pack("!H", rport))
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.settimeout(3)
        origin = None
        relay.settimeout(0.2)
        client.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = relay.recvfrom(65535)
            except socket.timeout:
                try:
                    if client.recv(1) == b"":
                        break  # control connection closed
                except socket.timeout:
                    pass
                except OSError:
                    break
                continue
            except OSError:
                break
            origin = addr
            atyp = data[3]
            if atyp == 1:
                host = socket.inet_ntoa(data[4:8])
                off = 8
            elif atyp == 3:
                n = data[4]
                host = data[5 : 5 + n].decode()
                off = 5 + n
            else:
                continue
            port = struct.unpack("!H", data[off : off + 2])[0]
            payload = data[off + 2 :]
            self.udp_targets.append((host, port))
            real = self.routes.get((host, port))
            if real is None:
                continue
            out.sendto(payload, real)
            try:
                reply, src = out.recvfrom(65535)
            except socket.timeout:
                continue
            # A real relay reports the remote's address: the requested
            # (literal) host, and the requested port unless the server
            # answered from a fresh port (TFTP transfer ID).
            try:
                socket.inet_aton(host)
                rhost = host
            except OSError:
                rhost = "127.0.0.1"
            rport = port if src[1] == real[1] else src[1]
            header = b"\x00\x00\x00\x01" + socket.inet_aton(rhost) + struct.pack("!H", rport)
            relay.sendto(header + reply, origin)
        out.close()


class HostileUdpRelay(FakeSocks5Server):
    """SOCKS5 server whose UDP relay answers the first relayed datagram
    with ``self.datagrams``, sent to the client exactly as given (no SOCKS
    UDP header added) - for malformed-relay tests."""

    def __init__(self, datagrams: list[bytes] | None = None) -> None:
        super().__init__()
        self.datagrams: list[bytes] = list(datagrams or [])

    def _udp_associate(self, client: socket.socket) -> None:
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        self._udp_relays.append(relay)
        rport = relay.getsockname()[1]
        client.sendall(
            b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", rport)
        )
        relay.settimeout(3)
        try:
            _data, origin = relay.recvfrom(65535)
        except OSError:
            return
        for datagram in self.datagrams:
            relay.sendto(datagram, origin)
        try:
            client.settimeout(3)
            client.recv(1)
        except OSError:
            pass


class EchoServer:
    """TCP server that sends ``banner`` then echoes; records peer addresses."""

    def __init__(self, banner: bytes = b"HELLO\n"):
        self.banner = banner
        self.clients: list[tuple[str, int]] = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, addr = self._listener.accept()
            except OSError:
                return
            self.clients.append(addr)
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    def _echo(self, conn: socket.socket) -> None:
        try:
            conn.sendall(self.banner)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        close_socket(self._listener)


class UdpEchoServer:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                return
            self._sock.sendto(b"ECHO:" + data, addr)

    def close(self) -> None:
        close_socket(self._sock)


@contextmanager
def allow_loopback_proxy():
    """The SSRF guard refuses a loopback proxy host; tests bypass it."""
    with mock.patch("core.proxy._assert_proxy_host_not_private"):
        yield


def socks_kwargs(server: FakeSocks5Server, **extra) -> dict:
    kw = {
        "proxy_type": "socks5",
        "proxy_host": "127.0.0.1",
        "proxy_port": server.port,
        "proxy_username": "",
        "proxy_password": "",
    }
    kw.update(extra)
    return kw
