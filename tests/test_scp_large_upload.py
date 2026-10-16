"""SCP uploads stream the payload on stdin, not inside the command line.

The writer put the whole base64 payload into the exec_command string
(``base64 -d > path << EOF ... EOF``). sshd runs that string as one
argument of ``$SHELL -c <command>``, and Linux refuses any single exec
argument above MAX_ARG_STRLEN (32 pages, 128 KiB): every upload larger
than about 96 KiB failed with "Argument list too long".

Driven end to end: paramiko client -> in-process paramiko server whose
exec handler runs the command through ``/bin/sh -c`` the way sshd does,
inside a temp directory.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from tests.socket_lifecycle import close_socket  # noqa: E402
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402

from core.scp_client import SCPSession, _Capabilities  # noqa: E402
from tests.sftp_testkit import _host_key  # noqa: E402


def _run_exec(channel: paramiko.Channel, command: str, cwd: str) -> None:
    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-c", command],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:  # E2BIG and friends, as sshd reports them
        channel.sendall_stderr(f"sh: {exc}\n".encode())
        channel.send_exit_status(127)
        channel.close()
        return

    def pump_stdin() -> None:
        try:
            while True:
                data = channel.recv(65536)
                if not data:
                    break
                proc.stdin.write(data)
        finally:
            proc.stdin.close()

    feeder = threading.Thread(target=pump_stdin, daemon=True)
    feeder.start()
    out, err = proc.stdout.read(), proc.stderr.read()
    proc.wait()
    if out:
        channel.sendall(out)
    if err:
        channel.sendall_stderr(err)
    channel.send_exit_status(proc.returncode)
    channel.close()


class _ShellAuth(paramiko.ServerInterface):
    def __init__(self, cwd: str) -> None:
        self.cwd = cwd

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode() if isinstance(command, bytes) else command
        threading.Thread(target=_run_exec, args=(channel, cmd, self.cwd), daemon=True).start()
        return True


class _ShellServer:
    def __init__(self, cwd: str) -> None:
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.cwd = cwd
        self._transports: list[paramiko.Transport] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            t.start_server(server=_ShellAuth(self.cwd))
            self._transports.append(t)

    def close(self) -> None:
        close_socket(self._sock)
        for t in self._transports:
            t.close()


@unittest.skipUnless(shutil.which("base64") and os.path.exists("/bin/sh"), "needs sh + base64")
class ScpLargeUploadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="axross-scp-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.srv = _ShellServer(self.root)
        self.addCleanup(self.srv.close)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1",
            port=self.srv.port,
            username="u",
            password="p",
            allow_agent=False,
            look_for_keys=False,
        )
        self.addCleanup(client.close)
        s = SCPSession.__new__(SCPSession)
        s._client = client
        s._lock = threading.Lock()
        s._caps = _Capabilities(has_base64=True, transfer_method="base64")
        self.s = s

    def _roundtrip(self, name: str, data: bytes) -> None:
        target = os.path.join(self.root, name)
        with self.s.open_write(target) as fh:
            fh.write(data)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertEqual(self.s.open_read(target).read(), data)

    def test_happy_small_binary_upload(self) -> None:
        self._roundtrip("small.bin", bytes(range(256)) * 4)

    def test_sad_upload_above_the_exec_argument_limit(self) -> None:
        payload = os.urandom(512 * 1024)  # base64: ~683 KiB, 5x MAX_ARG_STRLEN
        self._roundtrip("large.bin", payload)

    def test_edge_empty_file_and_eof_marker_in_payload(self) -> None:
        self._roundtrip("empty.bin", b"")
        self._roundtrip("marker.txt", b"__AXX_EOF__\n__AXX_EOF__")


if __name__ == "__main__":
    unittest.main()
