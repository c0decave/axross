"""SSHSession: a hash tool missing on Windows OpenSSH is remembered too.

Review round 9: cmd.exe and PowerShell - the shells of Windows OpenSSH -
exit 1, not 127, for an unknown command and say so only in words
("'sha256sum' is not recognized as an internal or external command",
"The term 'sha256sum' is not recognized as the name of a cmdlet").
checksum() remembered only exit 126/127, so a copy of 20 files opened 20
exec channels (a process start each on Windows) to hear the same answer.
"""

from __future__ import annotations

import collections
import os
import stat

import pytest

from core.exec_util import command_missing
from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession
from tests.ssh_exec_testkit import ExecServer

_CMD_EXE = ("'sha256sum' is not recognized as an internal or external command,\r\n"
            "operable program or batch file.\r\n")
_POWERSHELL = ("sha256sum : The term 'sha256sum' is not recognized as the name of a "
               "cmdlet, function, script file, or operable program.\r\n")


@pytest.fixture
def windows_ssh(tmp_path):
    """An SSH server whose ``sha256sum`` answers like the Windows shells: a
    script on PATH that prints *message* to stderr and exits 1."""
    opened = []

    def make(message: str):
        bin_dir = tmp_path / f"bin{len(opened)}"
        bin_dir.mkdir()
        (bin_dir / "msg").write_text(message, encoding="utf-8", newline="")
        script = bin_dir / "sha256sum"
        script.write_text(f"#!/bin/sh\ncat '{bin_dir / 'msg'}' >&2\nexit 1\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
        server = ExecServer(shell=True, env=env, cwd=str(tmp_path))
        sess = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                            port=server.port, username="u"))
        sess._transport = server.client_transport()
        opened.append((server, sess))
        counts: collections.Counter = collections.Counter()
        real = sess._transport.open_session

        def counted(*a, **k):
            counts["open_session"] += 1
            return real(*a, **k)

        sess._transport.open_session = counted
        return sess, counts

    yield make
    for server, sess in opened:
        sess._transport.close()
        server.close()


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("message", [_CMD_EXE, _POWERSHELL], ids=["cmd.exe", "powershell"])
def test_happy_windows_not_found_is_asked_once(windows_ssh, message):
    sess, counts = windows_ssh(message)
    assert [sess.checksum(f"/f{i}") for i in range(5)] == [""] * 5
    assert counts["open_session"] == 1
    assert sess.checksum_kinds("x") == frozenset()


@pytest.mark.parametrize("stderr", [
    "bash: line 1: sha256sum: command not found\n",
    "sh: 1: sha256sum: not found\n",
    "zsh:1: command not found: sha256sum\n",
    _CMD_EXE,
    _POWERSHELL,
    "sha256sum : The term 'sha256sum' is not recognized as a name of a cmdlet\n",
])
def test_happy_the_words_of_every_shell_say_missing(stderr):
    assert command_missing(1, stderr, "sha256sum")
    assert command_missing(127, "", "sha256sum")


# -- sad -----------------------------------------------------------------------------------


def test_sad_another_failure_is_asked_again(windows_ssh):
    sess, counts = windows_ssh("sha256sum: /f: Permission denied\r\n")
    for _ in range(2):
        with pytest.raises(OSError, match="Permission denied"):
            sess.checksum("/f")
    assert counts["open_session"] == 2
    assert sess.checksum_kinds("x") is None


# -- edge ----------------------------------------------------------------------------------


@pytest.mark.parametrize("stderr", [
    # The tool ran and complains about a FILE named like the message.
    "sha256sum: '/x/sha256sum: command not found': No such file or directory\n",
    "sha256sum: /x/sha256sum: not found: No such file or directory\n",
    # Another tool is missing, not this one.
    "'md5sum' is not recognized as an internal or external command,\r\n",
])
def test_edge_words_about_something_else_are_no_missing_tool(stderr):
    assert not command_missing(1, stderr, "sha256sum")


def test_edge_a_tool_that_succeeded_is_never_missing():
    assert not command_missing(0, "bash: sha256sum: command not found\n", "sha256sum")
