"""SFTP verbs that run a remote command work on a name that is not UTF-8.

A latin-1 name lists as ``caf\\udce9.txt`` (surrogateescape) and every SFTP
request encodes it back to its bytes. The verbs that run a shell command
(checksum, copy, hardlink, exec, the df fallback of disk_usage) handed
paramiko a str, which it encodes strictly as UTF-8: UnicodeEncodeError -
not an OSError, so server_side_copy and New Hardlink let it escape, the
channel opened just before stayed open, and disk_usage swallowed it and
reported an empty disk (0, 0, 0). Commands are now sent as bytes
(core.ssh_client.command_bytes), quoted by shlex.quote as before.

The test server accepts exec requests as OpenSSH does and runs them with
/bin/sh, absolute paths rewritten onto its root folder.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402
import sftp_testkit  # noqa: E402
from test_sftp_non_utf8_names import _BytesNamesSftp, _BytesServer  # noqa: E402

from core import server_ops  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession, command_bytes  # noqa: E402

LATIN = b"caf\xe9.txt"


class _ExecAuth(sftp_testkit._Auth):
    root = b""
    commands: list = []

    def check_channel_exec_request(self, channel, command):
        cmd = command if isinstance(command, bytes) else command.encode()
        _ExecAuth.commands.append(cmd)
        root = self.root
        cmd = cmd.replace(b" /", b" " + root + b"/").replace(b"'/", b"'" + root + b"/")

        def run():
            p = subprocess.run([b"/bin/sh", b"-c", cmd], capture_output=True)
            channel.sendall(p.stdout)
            channel.sendall_stderr(p.stderr)
            channel.send_exit_status(p.returncode)
            channel.close()

        threading.Thread(target=run, daemon=True).start()
        return True


class _ExecServer(_BytesServer):
    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(sftp_testkit._host_key())
            t.set_subsystem_handler(
                "sftp", sftp_testkit._BytesPathSftpServer, _BytesNamesSftp,
                root=self.root, stats=self.stats,
            )
            t.start_server(server=_ExecAuth())
            self._transports.append(t)


@pytest.fixture
def remote(tmp_path):
    root = (tmp_path / "srv").resolve()
    root.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    _ExecAuth.root = os.fsencode(str(root))
    _ExecAuth.commands = []
    (root / os.fsdecode(LATIN)).write_bytes(b"latin")
    with mock.patch("pathlib.Path.home", return_value=home):
        srv = _ExecServer(str(root))
        s = SSHSession(ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"))
        s.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            name = "/" + next(i.name for i in s.list_dir("/"))
            yield os.fsencode(str(root)), s, name
        finally:
            s.disconnect()
            srv.close()


def _open_channels(s) -> int:
    return len([c for c in s._transport._channels.values() if not c.closed])


# -- happy -------------------------------------------------------------------


def test_happy_checksum_copy_hardlink_and_exec_of_a_latin1_name(remote):
    root, s, name = remote
    assert name == "/caf\udce9.txt"
    assert s.checksum(name).startswith("sha256:")
    s.copy(name, name + ".cp")
    s.hardlink(name, name + ".hl")
    assert s.exec(f"cat {name}").stdout == b"latin"
    on_disk = set(os.listdir(root))
    assert {LATIN + b".cp", LATIN + b".hl"} <= on_disk
    # The command carried the name's own bytes, quoted.
    assert any(b"'/" + LATIN + b"'" in c for c in _ExecAuth.commands)


def test_happy_server_side_copy_of_a_latin1_name(remote):
    root, s, name = remote
    server_ops.server_side_copy(s, name, name + ".ssc")
    assert LATIN + b".ssc" in os.listdir(root)


def test_happy_disk_usage_of_a_latin1_name(remote):
    _root, s, name = remote
    total, _used, free = s.disk_usage(name)
    assert total > 0 and free >= 0


# -- sad ---------------------------------------------------------------------


def test_sad_disk_usage_of_a_missing_path_is_an_error_not_an_empty_disk(remote):
    _root, s, _name = remote
    with pytest.raises(OSError):
        s.disk_usage("/no/such/folder")


def test_sad_hardlink_onto_a_taken_latin1_name_is_file_exists(remote):
    _root, s, name = remote
    s.copy(name, name + ".cp")
    with pytest.raises(FileExistsError):
        s.hardlink(name, name + ".cp")


# -- edge --------------------------------------------------------------------


def test_edge_a_surrogate_that_stands_for_no_byte_is_oserror_without_a_channel(remote):
    _root, s, _name = remote
    before = _open_channels(s)
    bad = "/x\ud800y"
    for verb in (
        lambda: s.checksum(bad),
        lambda: s.copy(bad, bad + ".c"),
        lambda: s.hardlink(bad, bad + ".h"),
        lambda: s.exec(f"cat {bad}"),
        lambda: s.disk_usage(bad),
    ):
        with pytest.raises(OSError):
            verb()
    assert _open_channels(s) == before


def test_edge_command_bytes_keeps_quoting_and_bytes():
    import shlex

    cmd = f"ls -- {shlex.quote('/a b/caf' + chr(0xDCE9))}"
    assert command_bytes(cmd) == b"ls -- '/a b/caf\xe9'"
    assert command_bytes(b"raw") == b"raw"
