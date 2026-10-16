"""In-process SFTP server (paramiko) over a local directory, plus a TCP relay
that adds latency — enough to test and measure SFTP transfer behaviour
without a container."""

from __future__ import annotations

import os
import socket
import threading
import time

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK

_HOST_KEY = None


def _host_key() -> paramiko.RSAKey:
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(1024)
    return _HOST_KEY


class _Handle(SFTPHandle):
    def stat(self):
        f = self.readfile or self.writefile
        try:
            return SFTPAttributes.from_stat(os.fstat(f.fileno()))
        except OSError as exc:
            return _Sftp._err(exc)


class _Sftp(SFTPServerInterface):
    def __init__(self, server, *args, root: str = "/", stats=None, **kw) -> None:
        super().__init__(server, *args, **kw)
        self.root = root
        self.stats = stats if stats is not None else {}

    def _real(self, path: str) -> str:
        return os.path.join(self.root, self.canonicalize(path).lstrip("/"))

    @staticmethod
    def _err(exc: OSError) -> int:
        return SFTP_NO_SUCH_FILE if isinstance(exc, FileNotFoundError) else SFTP_FAILURE

    def list_folder(self, path):
        try:
            out = []
            for name in os.listdir(self._real(path)):
                attr = SFTPAttributes.from_stat(os.lstat(os.path.join(self._real(path), name)))
                attr.filename = name
                out.append(attr)
            return out
        except OSError as exc:
            return self._err(exc)

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as exc:
            return self._err(exc)

    lstat = stat

    def open(self, path, flags, attr):
        real = self._real(path)
        try:
            fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o644)
            mode = "r+b" if flags & os.O_RDWR else ("wb" if flags & os.O_WRONLY else "rb")
            if flags & os.O_APPEND:
                mode = "ab"
            fobj = os.fdopen(fd, mode)
        except OSError as exc:
            return self._err(exc)
        stats = self.stats
        handle = _Handle(flags)

        class _Counting:
            """Counts READ/WRITE requests so tests can see pipelining."""

            def __init__(self, inner) -> None:
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def read(self, n=-1):
                stats["reads"] = stats.get("reads", 0) + 1
                fail = stats.get("fail_reads_at")
                if fail is not None and self._inner.tell() >= fail:
                    raise OSError("simulated read failure")
                return self._inner.read(n)

            def write(self, data):
                stats["writes"] = stats.get("writes", 0) + 1
                if stats.get("fail_writes"):
                    raise OSError("simulated disk full")
                return self._inner.write(data)

        class _FailingClose(_Counting):
            """A write handle whose close reports an error, as close(2)
            does on NFS when the server only then runs out of quota."""

            def close(self):
                self._inner.close()
                if stats.get("fail_close"):
                    raise OSError("simulated EDQUOT at close")

        handle.filename = real
        handle.readfile = _Counting(fobj) if "r" in mode or "+" in mode else None
        handle.writefile = _FailingClose(fobj) if mode != "rb" else None
        return handle

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._real(oldpath), self._real(newpath))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        return self.rename(oldpath, newpath)

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._real(path))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(self._real(path))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

    def chattr(self, path, attr):
        return SFTP_OK


class _Auth(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        return False  # no remote shell: checksum falls back to streaming


class SftpServer:
    """``SftpServer(root)`` listens on 127.0.0.1:<port>; any password works."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.stats: dict = {}
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._transports: list = []
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._sock.close()
        for t in self._transports:
            t.close()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            root, stats = self.root, self.stats
            t.set_subsystem_handler("sftp", SFTPServer, _Sftp, root=root, stats=stats)
            t.start_server(server=_Auth())
            self._transports.append(t)


class LatencyRelay:
    """TCP relay to *target* that holds every chunk for *delay* seconds in
    each direction, so one round trip costs ``2 * delay``."""

    def __init__(self, target_port: int, delay: float) -> None:
        self.delay = delay
        self.target = ("127.0.0.1", target_port)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(self.target)
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _pump(self, src, dst) -> None:
        import queue

        q: queue.Queue = queue.Queue()

        def sender() -> None:
            while True:
                due, data = q.get()
                if data is None:
                    return
                wait = due - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                try:
                    dst.sendall(data)
                except OSError:
                    return

        threading.Thread(target=sender, daemon=True).start()
        try:
            while data := src.recv(65536):
                q.put((time.monotonic() + self.delay, data))
        except OSError:
            pass
        q.put((0, None))
