"""A fake adb server (platform-tools' ``adb`` on 127.0.0.1:5037) for the tests.

It speaks the host protocol - ``host:version``, ``host:devices-l``,
``host:transport:<serial>`` - and, after a transport, the services
``shell:<command>`` and ``sync:`` of the phone. The phones are
:class:`tests.fake_adbd.FakeAdbd` instances: their shell and sync code
runs the command / file operation against their local folder, here with
the raw stream of the server instead of ADB packets.

Hostile answers for the client's bounds: :attr:`FakeAdbServer.raw` maps a
request to the bytes sent instead of the answer, :attr:`slow` sends every
answer byte by byte with a pause, :attr:`data_block` sends a DATA header
of that length in a pull.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

from tests.fake_adbd import A_CLSE, A_WRTE, FakeAdbd


class FakeAdbServer:
    """*devices*: ``[(serial, state, phone_or_None, fields)]`` -
    *fields* the ``key:value`` words of devices-l (``usb:1-1 model:Pixel_7``)."""

    def __init__(self, devices=(), *, version: int = 41) -> None:
        self.devices = list(devices)
        self.version = version
        self.requests: list[bytes] = []
        self.raw: dict[bytes, bytes] = {}
        self.slow = 0.0
        self.data_block: int | None = None
        self.close_after_raw = True
        self.connections = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stopped = False
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def env(self) -> dict[str, str]:
        """The environment that points axross at this server."""
        return {"ADB_SERVER_SOCKET": f"tcp:127.0.0.1:{self.port}"}

    def stop(self) -> None:
        self._stopped = True
        try:
            self._sock.close()
        except OSError:
            pass

    def set_state(self, serial: str, state: str) -> None:
        self.devices = [(s, state if s == serial else st, p, f) for s, st, p, f in self.devices]

    def devices_text(self) -> bytes:
        lines = []
        for serial, state, _phone, fields in self.devices:
            lines.append(f"{serial:<22} {state} {fields}".rstrip())
        return ("\n".join(lines) + ("\n" if lines else "")).encode()

    # -- wire ------------------------------------------------------------
    def _accept(self) -> None:
        while not self._stopped:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _send(self, conn: socket.socket, data: bytes) -> None:
        if not self.slow:
            conn.sendall(data)
            return
        for i in range(len(data)):
            conn.sendall(data[i:i + 1])
            time.sleep(self.slow)

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def _read_request(self, conn: socket.socket) -> bytes:
        length = int(self._recv_exact(conn, 4), 16)
        request = self._recv_exact(conn, length)
        self.requests.append(request)
        return request

    def _okay(self, conn, payload: bytes | None = None) -> None:
        data = b"OKAY" if payload is None else b"OKAY" + b"%04x" % len(payload) + payload
        self._send(conn, data)

    def _fail(self, conn, text: str) -> None:
        msg = text.encode()
        self._send(conn, b"FAIL" + b"%04x" % len(msg) + msg)

    def _serve(self, conn: socket.socket) -> None:
        try:
            request = self._read_request(conn)
            if request in self.raw:
                self._send(conn, self.raw[request])
                if not self.close_after_raw:
                    time.sleep(30)
                return
            if request == b"host:version":
                self._okay(conn, b"%04x" % self.version)
            elif request == b"host:devices-l":
                self._okay(conn, self.devices_text())
            elif request.startswith(b"host:transport:"):
                self._transport(conn, request[len(b"host:transport:"):].decode())
            else:
                self._fail(conn, f"unknown host service {request.decode(errors='replace')}")
        except (EOFError, OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _transport(self, conn: socket.socket, serial: str) -> None:
        entry = next((d for d in self.devices if d[0] == serial), None)
        if entry is None:
            self._fail(conn, f"device '{serial}' not found")
            return
        _serial, state, phone, _fields = entry
        if state == "unauthorized":
            self._fail(conn, "device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not "
                             "set\nTry 'adb kill-server' if that seems wrong.\nOtherwise check "
                             "for a confirmation dialog on your device.")
            return
        if state != "device":
            self._fail(conn, f"device {state}")
            return
        self._okay(conn)
        service = self._read_request(conn)
        if service.startswith(b"shell:"):
            self._okay(conn)
            phone._shell(self._stream_send(conn), 1, 1, service[len(b"shell:"):])
        elif service == b"sync:":
            self._okay(conn)
            self._sync(conn, phone)
        else:
            self._fail(conn, "unknown service")

    def _stream_send(self, conn):
        """A FakeAdbd send() that writes the payload of WRTE raw and ends
        the stream at CLSE (as the server relays the phone's stream)."""
        def send(cmd, _a0, _a1, data=b""):
            if cmd == A_WRTE:
                self._send(conn, data)
            elif cmd == A_CLSE:
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        return send

    def _sync(self, conn: socket.socket, phone: FakeAdbd) -> None:
        stream = {"peer": 1, "buf": b"", "send": None}
        send = self._stream_send(conn)
        while True:
            if len(stream["buf"]) >= 8 and stream["buf"][:4] == b"QUIT":
                return
            if (self.data_block is not None and len(stream["buf"]) >= 8
                    and stream["buf"][:4] == b"RECV"):
                self._send(conn, struct.pack("<4sI", b"DATA", self.data_block) + b"x" * 64)
                return
            data = conn.recv(256 * 1024)
            if not data:
                return
            stream["buf"] += data
            if stream["buf"][:4] == b"QUIT":
                return
            if self.data_block is not None and stream["buf"][:4] == b"RECV":
                continue
            phone._sync(lambda cmd, a0, a1, d=b"": send(cmd, a0, a1, d), 1, stream)
