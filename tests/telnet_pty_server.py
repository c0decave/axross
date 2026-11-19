"""A telnet server in front of a REAL shell on a pseudo-terminal.

Where tests/telnet_fuzz_server.py answers from a table, this one runs
``sh`` (or another shell) in a pty, as telnetd does after login, so the
client's quoting, heredocs, markers and transfers meet a real shell and a
real terminal line discipline. Only what a telnetd does around the shell
is faked: a login dialogue (``login:`` / ``Password:``, "Login incorrect"
and a new ``login:`` for a wrong password, an optional message of the
day), CR LF from the client becoming one line end, and no option
negotiation at all (a server may decline everything).

POSIX only (pty); the tests that use it skip elsewhere.
"""

from __future__ import annotations

import os
import select
import signal
import socket
import subprocess
import threading


class PtyTelnetServer:
    def __init__(
        self,
        *,
        username: str = "u",
        password: str = "pw",
        motd: str = "",
        shell: str = "/bin/sh",
        cwd: str | None = None,
        env: dict | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.motd = motd
        self.shell = shell
        self.cwd = cwd
        self.env = env
        self.connections = 0
        self.failed_logins = 0
        self._children: list[subprocess.Popen] = []
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()
        self._closed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.host, self.port = self._listener.getsockname()
        threading.Thread(target=self._accept, daemon=True).start()

    # -- lifecycle -------------------------------------------------------
    def __enter__(self) -> "PtyTelnetServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        try:
            # shutdown wakes the accept() blocked in the server thread;
            # close() alone leaves it accepting on Linux.
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._listener.close()
        except OSError:
            pass
        self.drop_all()

    def drop_all(self) -> None:
        """Cut every open connection and kill its shell (a dropped line)."""
        with self._lock:
            socks, self._socks = self._socks, []
            children, self._children = self._children, []
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                pass

    # -- serving ---------------------------------------------------------
    def _accept(self) -> None:
        while not self._closed:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            if self._closed:
                conn.close()
                return
            with self._lock:
                self.connections += 1
                self._socks.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_line(conn: socket.socket) -> str | None:
        data = b""
        while not data.endswith(b"\n") and not data.endswith(b"\r\x00"):
            try:
                chunk = conn.recv(1)
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return data.decode("utf-8", "replace").rstrip("\r\n\x00")

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(60)
        try:
            while True:
                conn.sendall(b"login: ")
                user = self._read_line(conn)
                if user is None:
                    return
                conn.sendall(b"Password: ")
                password = self._read_line(conn)
                if password is None:
                    return
                if user == self.username and password == self.password:
                    break
                self.failed_logins += 1
                conn.sendall(b"\r\nLogin incorrect\r\n")
            if self.motd:
                conn.sendall(self.motd.replace("\n", "\r\n").encode())
            self._relay(conn)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _relay(self, conn: socket.socket) -> None:
        master, slave = os.openpty()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.cwd or "/",
               "PS1": "$ ", "TERM": "vt100", **(self.env or {})}
        child = subprocess.Popen(
            [self.shell, "-i"], stdin=slave, stdout=slave, stderr=slave,
            cwd=self.cwd, env=env, start_new_session=True, close_fds=True,
            preexec_fn=lambda: __import__("fcntl").ioctl(0, __import__("termios").TIOCSCTTY, 0),
        )
        os.close(slave)
        with self._lock:
            self._children.append(child)
        conn.setblocking(False)
        pending_cr = False
        try:
            while True:
                try:
                    ready, _, _ = select.select([conn, master], [], [], 0.5)
                except (OSError, ValueError):
                    return
                if child.poll() is not None and master not in ready:
                    return
                if master in ready:
                    try:
                        out = os.read(master, 65536)
                    except OSError:
                        return
                    if not out:
                        return
                    conn.setblocking(True)
                    try:
                        conn.sendall(out.replace(b"\xff", b"\xff\xff"))
                    except OSError:
                        return
                    conn.setblocking(False)
                if conn in ready:
                    try:
                        data = conn.recv(65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        return
                    if not data:
                        return
                    # telnetd: CR LF (or CR NUL) from the client is ONE line end.
                    if pending_cr and data[:1] in (b"\n", b"\x00"):
                        data = data[1:]
                    pending_cr = data.endswith(b"\r")
                    data = data.replace(b"\r\n", b"\r").replace(b"\r\x00", b"\r")
                    view = memoryview(data)
                    while view:
                        try:
                            n = os.write(master, view)
                        except BlockingIOError:
                            continue
                        except OSError:
                            return
                        view = view[n:]
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                pass
            os.close(master)
