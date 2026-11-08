"""In-process SFTP server (paramiko) over a local directory, plus a TCP relay
that adds latency — enough to test and measure SFTP transfer behaviour
without a container.

Where the backend contract depends on it, the server answers as
OpenSSH's sftp-server does: names are bytes on the wire (a latin-1 name
is listed as stored and can be addressed by those bytes), a plain RENAME
refuses an existing target while posix-rename@openssh.com replaces it,
SETSTAT applies mode, times and size, and EACCES is
SSH_FX_PERMISSION_DENIED."""

from __future__ import annotations

import os
import socket
import threading
import time

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_PERMISSION_DENIED

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
        real = os.path.join(self.root, self.canonicalize(path).lstrip("/"))
        # OpenSSH hands the path to the system as sent: "file/" is
        # ENOTDIR, not the file (canonicalize drops the slash).
        if path.endswith("/") and path.strip("/"):
            real += "/"
        return real

    @staticmethod
    def _err(exc: OSError) -> int:
        """OpenSSH's errno_to_portable (sftp-server.c): ENOENT, ENOTDIR,
        EBADF and ELOOP are SSH_FX_NO_SUCH_FILE; EPERM, EACCES
        SSH_FX_PERMISSION_DENIED; the rest SSH_FX_FAILURE."""
        import errno

        if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP):
            return SFTP_NO_SUCH_FILE
        if exc.errno in (errno.EPERM, errno.EACCES):
            return SFTP_PERMISSION_DENIED
        return SFTP_FAILURE

    def list_folder(self, path):
        try:
            out = []
            for name in os.listdir(self._real(path)):
                attr = SFTPAttributes.from_stat(os.lstat(os.path.join(self._real(path), name)))
                # The stored bytes, as OpenSSH sends them (paramiko would
                # encode a str strictly as UTF-8).
                attr.filename = os.fsencode(name)
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
        """SSH_FXP_RENAME as OpenSSH's sftp-server (process_rename): an
        existing target - a dangling link too - is SSH_FX_FAILURE, never
        replaced (draft-ietf-secsh-filexfer-02 6.5)."""
        old, new = self._real(oldpath), self._real(newpath)
        try:
            os.lstat(old)
        except OSError as exc:
            return self._err(exc)
        if os.path.lexists(new):
            return SFTP_FAILURE
        try:
            os.rename(old, new)
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        """posix-rename@openssh.com: rename(2), which replaces a target."""
        try:
            os.rename(self._real(oldpath), self._real(newpath))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK

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
        """SSH_FXP_SETSTAT, applied as OpenSSH's sftp-server does: size,
        permissions, owner and times, each when the request carries it."""
        real = self._real(path)
        try:
            if attr._flags & attr.FLAG_SIZE:
                os.truncate(real, attr.st_size)
            if attr._flags & attr.FLAG_PERMISSIONS:
                os.chmod(real, attr.st_mode & 0o7777)
            if attr._flags & attr.FLAG_UIDGID:
                os.chown(real, attr.st_uid, attr.st_gid)
            if attr._flags & attr.FLAG_AMTIME:
                os.utime(real, (attr.st_atime, attr.st_mtime))
        except OSError as exc:
            return self._err(exc)
        return SFTP_OK


class _BytesPathSftpServer(SFTPServer):
    """paramiko's SFTP subsystem with request paths decoded as Python
    decodes a local file name (``surrogateescape``): paramiko decodes
    them strictly as UTF-8, so a client asking for a latin-1 name - which
    OpenSSH serves as the bytes it is - got the connection dropped."""

    def _process(self, t, request_number, msg):
        msg.get_text = lambda: msg.get_string().decode("utf-8", "surrogateescape")
        return super()._process(t, request_number, msg)


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

    def __init__(self, root: str, extra_host_keys: tuple = ()) -> None:
        self.root = root
        self.stats: dict = {}
        #: Host keys offered beside the RSA one (another key type each).
        self.extra_host_keys = tuple(extra_host_keys)
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
            for key in self.extra_host_keys:
                t.add_server_key(key)
            root, stats = self.root, self.stats
            t.set_subsystem_handler("sftp", _BytesPathSftpServer, _Sftp, root=root, stats=stats)
            try:
                t.start_server(server=_Auth())
            except (paramiko.SSHException, OSError, EOFError):
                # The client hung up in the handshake (it refused the host
                # key, say). That ends this connection, not the server: the
                # loop must keep accepting the next one.
                t.close()
                continue
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
