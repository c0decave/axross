"""A loopback paramiko SSH server that only answers exec requests.

With ``shell=True`` each command runs in the local /bin/sh. Otherwise
the command text picks the behaviour:

* ``hang``         - never answers and never sends an exit status
* ``out:N``        - N bytes of ``x`` on stdout, then exit 0
* ``err:N``        - N bytes of ``e`` on stderr, then exit 0
* ``both:N``       - N bytes on stdout and N bytes on stderr, then exit 0
* ``slow:S``       - ``tick`` on stdout, exit 3 after S seconds
* ``echo:TEXT``    - TEXT on stdout, exit 0
* anything else    - exit 0, no output
"""

from __future__ import annotations

import socket
import threading
import time

import paramiko

_HOST_KEY: paramiko.RSAKey | None = None


def host_key() -> paramiko.RSAKey:
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(2048)
    return _HOST_KEY


def _send(channel, data: bytes, *, stderr: bool = False) -> None:
    send = channel.sendall_stderr if stderr else channel.sendall
    for i in range(0, len(data), 32768):
        send(data[i : i + 32768])


def _run_in_shell(channel, cmd: str, env: dict | None, cwd: str | None) -> None:
    """Run *cmd* with the local /bin/sh; stream its output, send its status."""
    import subprocess

    proc = subprocess.run(
        ["/bin/sh", "-c", cmd], capture_output=True, env=env, cwd=cwd, timeout=60
    )
    _send(channel, proc.stdout)
    _send(channel, proc.stderr, stderr=True)
    channel.send_exit_status(proc.returncode)


class _Server(paramiko.ServerInterface):
    def __init__(
        self, shell: bool = False, env: dict | None = None, cwd: str | None = None
    ) -> None:
        self.commands: list[str] = []
        self.shell = shell
        self.env = env
        self.cwd = cwd

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace")
        self.commands.append(cmd)

        def run() -> None:
            # Let paramiko send the exec reply first: a channel closed
            # before it makes the client's exec_command fail.
            time.sleep(0.1)
            try:
                if self.shell:
                    _run_in_shell(channel, cmd, self.env, self.cwd)
                    channel.shutdown_write()
                    channel.close()
                    return
                if cmd == "hang":
                    return
                rc = 0
                if cmd.startswith("out:"):
                    _send(channel, b"x" * int(cmd[4:]))
                elif cmd.startswith("err:"):
                    _send(channel, b"e" * int(cmd[4:]), stderr=True)
                elif cmd.startswith("both:"):
                    n = int(cmd[5:])
                    out = threading.Thread(target=_send, args=(channel, b"x" * n), daemon=True)
                    out.start()
                    _send(channel, b"e" * n, stderr=True)
                    out.join()
                elif cmd.startswith("slow:"):
                    channel.sendall(b"tick")
                    time.sleep(float(cmd[5:]))
                    rc = 3
                elif cmd.startswith("echo:"):
                    channel.sendall(cmd[5:].encode())
                channel.send_exit_status(rc)
                channel.shutdown_write()
                channel.close()
            except (OSError, EOFError, paramiko.SSHException):
                pass

        threading.Thread(target=run, daemon=True).start()
        return True

    def check_channel_subsystem_request(self, channel, name):
        return False


class ExecServer:
    """Start with ``ExecServer()``, stop with :meth:`close`.

    ``ExecServer(shell=True, env=..., cwd=...)`` runs every exec request
    with the local /bin/sh instead of the canned behaviours above.
    """

    def __init__(
        self, shell: bool = False, env: dict | None = None, cwd: str | None = None
    ) -> None:
        self.server = _Server(shell=shell, env=env, cwd=cwd)
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", 0))
        self._lsock.listen(5)
        self.port = self._lsock.getsockname()[1]
        self._transports: list[paramiko.Transport] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._lsock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(host_key())
            t.start_server(server=self.server)
            self._transports.append(t)

    def client_transport(self) -> paramiko.Transport:
        """An authenticated client transport to this server."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        t = paramiko.Transport(sock)
        t.start_client(timeout=10)
        t.auth_password("u", "pw")
        return t

    def close(self) -> None:
        try:
            self._lsock.close()
        except OSError:
            pass
        for t in self._transports:
            t.close()
