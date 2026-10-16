"""A scriptable fake FTP server for the FTP fuzz suite.

Control replies come from a table (verb -> bytes, or a callable taking the
argument and returning bytes / None to hang up / ``STALL`` to go silent).
Data-channel verbs (LIST, NLST, MLSD, RETR) send ``data[verb]`` over a PASV
connection on 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading

from fuzz_testkit import ScriptedServer, recv_line, stall

STALL = object()

DATA_VERBS = ("LIST", "NLST", "MLSD", "RETR")


class FakeFtpServer:
    def __init__(
        self,
        replies: dict | None = None,
        data: dict | None = None,
        welcome: bytes = b"220 fuzz ready\r\n",
        pasv_host: str = "127,0,0,1",
    ) -> None:
        self.replies = {
            "USER": b"331 password please\r\n",
            "PASS": b"230 logged in\r\n",
            "OPTS": b"200 ok\r\n",
            "TYPE": b"200 ok\r\n",
            "NOOP": b"200 ok\r\n",
            "PWD": b'257 "/" is cwd\r\n',
            "CWD": b"250 ok\r\n",
            "QUIT": b"221 bye\r\n",
            **(replies or {}),
        }
        self.data = dict(data or {})
        self.welcome = welcome
        self.pasv_host = pasv_host
        self.commands: list[str] = []
        self.raw_commands: list[bytes] = []
        self._data_sock: socket.socket | None = None
        self._lock = threading.Lock()
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port

    def close(self) -> None:
        self.server.close()
        if self._data_sock is not None:
            try:
                self._data_sock.close()
            except OSError:
                pass

    def __enter__(self) -> "FakeFtpServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def _open_pasv(self) -> bytes:
        ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ds.bind(("127.0.0.1", 0))
        ds.listen(1)
        ds.settimeout(5)
        self._data_sock = ds
        port = ds.getsockname()[1]
        return (
            f"227 Entering Passive Mode ({self.pasv_host},{port >> 8},{port & 255})\r\n"
        ).encode()

    def _send_data(self, conn: socket.socket, verb: str, arg: str) -> bool:
        payload = self.data.get(verb, b"")
        if callable(payload):
            payload = payload(arg)
        ds = self._data_sock
        self._data_sock = None
        if ds is None:
            conn.sendall(b"425 no data connection\r\n")
            return True
        conn.sendall(b"150 opening data connection\r\n")
        try:
            dconn, _ = ds.accept()
        except OSError:
            ds.close()
            conn.sendall(b"425 no data connection\r\n")
            return True
        ds.close()
        if payload is STALL:
            stall(dconn, 15)
            dconn.close()
            return True
        try:
            dconn.sendall(payload)
        except OSError:
            pass
        dconn.close()
        conn.sendall(b"226 transfer complete\r\n")
        return True

    def _handle(self, conn: socket.socket) -> None:
        conn.sendall(self.welcome)
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            self.commands.append(line)
            self.raw_commands.append(raw)
            if verb == "PASV" and "PASV" not in self.replies:
                conn.sendall(self._open_pasv())
                continue
            if verb in DATA_VERBS and verb not in self.replies:
                self._send_data(conn, verb, arg)
                continue
            reply = self.replies.get(verb, b"502 not implemented\r\n")
            if callable(reply):
                reply = reply(arg)
            if reply is None:
                return
            if reply is STALL:
                stall(conn, 15)
                return
            conn.sendall(reply)
