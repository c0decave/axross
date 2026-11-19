"""A loopback SSH server for whole-session SFTP / SCP tests.

paramiko's server classes speaking the real protocol, with what a
default OpenSSH sshd offers a client:

* exec requests run through the local ``/bin/sh -c`` in *cwd* (as sshd
  runs ``$SHELL -c``) with stdin, stdout and stderr streamed both ways
  at the same time - uploads on stdin, ``scp -t`` / ``scp -f`` and
  commands that run for a while all work as against sshd;
* the SFTP subsystem over the same folder (tests/sftp_testkit.py);
* the login methods to offer (``auths``): "password",
  "keyboard-interactive" (one "Password: " prompt, as PAM asks) and
  "publickey" (any key in ``authorized_keys``);
* :meth:`drop` cuts every connection without a goodbye (a lost network
  as the client sees it once its socket notices).

``SshShellServer(root)`` listens on 127.0.0.1:<port>; :func:`profile`
builds a ConnectionProfile for it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time

import paramiko

from tests.sftp_testkit import _BytesPathSftpServer, _host_key, _Sftp

USER = "tester"
PASSWORD = "s3cret pw"


def _pump_stdin(channel: paramiko.Channel, proc: subprocess.Popen) -> None:
    try:
        while True:
            data = channel.recv(65536)
            if not data:
                break
            proc.stdin.write(data)
            proc.stdin.flush()
    except (OSError, EOFError, paramiko.SSHException):
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass


def _pump_out(stream, send) -> None:
    try:
        while True:
            data = stream.read1(65536)
            if not data:
                return
            send(data)
    except (OSError, EOFError, paramiko.SSHException):
        pass


def run_exec(channel: paramiko.Channel, command: bytes, cwd: str, env: dict | None) -> None:
    """Run *command* as sshd does and stream it over *channel*."""
    # paramiko sends the exec reply after check_channel_exec_request
    # returns: a channel closed before it makes the client's exec fail.
    time.sleep(0.05)
    try:
        proc = subprocess.Popen(
            [b"/bin/sh", b"-c", command],
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        channel.sendall_stderr(f"sh: {exc}\n".encode())
        channel.send_exit_status(127)
        channel.close()
        return
    threading.Thread(target=_pump_stdin, args=(channel, proc), daemon=True).start()
    err = threading.Thread(
        target=_pump_out, args=(proc.stderr, channel.sendall_stderr), daemon=True
    )
    err.start()
    _pump_out(proc.stdout, channel.sendall)
    err.join()
    code = proc.wait()
    try:
        channel.send_exit_status(code)
        channel.shutdown_write()
        channel.close()
    except (OSError, EOFError, paramiko.SSHException):
        pass


class _Server(paramiko.ServerInterface):
    def __init__(self, owner: "SshShellServer") -> None:
        self.owner = owner

    # --- logins ---------------------------------------------------------
    def get_allowed_auths(self, username):
        return ",".join(self.owner.auths)

    def check_auth_password(self, username, password):
        if "password" in self.owner.auths and (username, password) == (USER, PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        if "keyboard-interactive" not in self.owner.auths:
            return paramiko.AUTH_FAILED
        self._kbd_user = username
        query = paramiko.server.InteractiveQuery("", "")
        query.add_prompt("Password: ", False)
        return query

    def check_auth_interactive_response(self, responses):
        if getattr(self, "_kbd_user", None) == USER and list(responses) == [PASSWORD]:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if "publickey" in self.owner.auths and username == USER and any(
            key.asbytes() == k.asbytes() for k in self.owner.authorized_keys
        ):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    # --- channels ---------------------------------------------------------
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_exec_request(self, channel, command):
        command = bytes(command)
        self.owner.commands.append(command)
        threading.Thread(
            target=run_exec,
            args=(channel, command, self.owner.root, self.owner.env),
            daemon=True,
        ).start()
        return True


class SshShellServer:
    def __init__(
        self,
        root: str,
        *,
        auths: tuple[str, ...] = ("password",),
        authorized_keys: tuple = (),
        sftp: bool = True,
        env: dict | None = None,
        bind: str = "127.0.0.1",
    ) -> None:
        self.root = root
        self.auths = tuple(auths)
        self.authorized_keys = tuple(authorized_keys)
        self.env = env if env is not None else {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": root, "LC_ALL": "C",
        }
        self.commands: list[bytes] = []
        self.stats: dict = {}
        self._sftp = sftp
        family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        self._sock = socket.create_server((bind, 0), family=family)
        self.port = self._sock.getsockname()[1]
        self._transports: list[paramiko.Transport] = []
        self._lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            if self._sftp:
                t.set_subsystem_handler(
                    "sftp", _BytesPathSftpServer, _Sftp, root=self.root, stats=self.stats
                )
            try:
                t.start_server(server=_Server(self))
            except (paramiko.SSHException, OSError, EOFError):
                t.close()
                continue
            with self._lock:
                self._transports.append(t)

    def drop(self) -> None:
        """Cut every open connection (the client sees its socket close)."""
        with self._lock:
            transports, self._transports = self._transports, []
        for t in transports:
            try:
                t.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            t.close()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
        self.drop()


def profile(server: SshShellServer, protocol: str = "sftp", **fields):
    from core.profiles import ConnectionProfile

    return ConnectionProfile(
        name=f"test-{protocol}",
        protocol=protocol,
        host="127.0.0.1",
        port=server.port,
        username=fields.pop("username", USER),
        **fields,
    )


def connect(session, password: str = PASSWORD, known_hosts=None, **kw):
    """Connect *session* (SSHSession / SCPSession), trusting the host key
    into *known_hosts* (a path in a temp folder, never ~/.ssh)."""
    if known_hosts is not None:
        session._known_hosts_path = known_hosts
    session.connect(password=password, on_unknown_host=lambda _e: True, **kw)
    return session


class FreezableRelay:
    """TCP relay to 127.0.0.1:*target_port*; :meth:`freeze` stops it
    forwarding in both directions without closing anything - a network
    gone silent (Wi-Fi gone, a NAT entry dropped): no FIN, no RST."""

    def __init__(self, target_port: int) -> None:
        self.target = ("127.0.0.1", target_port)
        self.frozen = threading.Event()
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._conns: list[socket.socket] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def freeze(self) -> None:
        self.frozen.set()

    def close(self) -> None:
        self.frozen.set()
        for s in [self._sock, *self._conns]:
            try:
                s.close()
            except OSError:
                pass

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(self.target)
            self._conns += [client, upstream]
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _pump(self, src, dst) -> None:
        try:
            while data := src.recv(65536):
                if self.frozen.is_set():
                    continue  # swallowed: nothing arrives, nothing fails
                dst.sendall(data)
        except OSError:
            pass
