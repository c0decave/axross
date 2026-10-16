"""SCP lists folders on a shell that takes no environment prefix.

GUI end-to-end run against test.rebex.net: the SCP pane stayed empty.
Rebex's virtual shell runs ``ls -la /`` but answers every command that
starts with a variable assignment with "-sh: Command 'LANG=C' not
supported." (exit 127) - also ``export`` and ``env``. SCP put
``LANG=... ls`` in front of every listing (before 0.10.37 ``LANG=C
LC_ALL=C``, after it the UTF-8 variant), so no folder could be listed.
The capability probe now asks once whether the shell takes the prefix;
only then it is used.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scp_client  # noqa: E402
from core.telnet_client import SHELL_ENV  # noqa: E402

LS_ROOT = (
    "drwx------ 2 demo users          0 Mar 31  2023 .\n"
    "drwx------ 2 demo users          0 Apr 30 13:38 ..\n"
    "drwx------ 2 demo users          0 Mar 31  2023 pub\n"
    "-rw------- 1 demo users        379 Sep 19  2023 readme.txt\n"
)


def _restricted(cmd: str, timeout: float = 0.0) -> tuple[str, int]:
    """Rebex Virtual Shell as measured: ls and echo, nothing POSIX."""
    word = cmd.split()[0]
    if word not in ("ls", "echo", "uname"):
        return f"-sh: Command '{word}' not supported.", 127
    if word == "echo":
        return cmd.split(" ", 1)[1], 0
    if word == "uname":
        return "Rebex Virtual Shell", 0
    if cmd.endswith("'/'") or cmd.endswith(" /"):
        return LS_ROOT, 0
    return "ls: no such file or directory", 2


def _posix(cmd: str, timeout: float = 0.0) -> tuple[str, int]:
    """A POSIX shell: takes the prefix, echo prints its argument."""
    if cmd.startswith(SHELL_ENV + " "):
        cmd = cmd[len(SHELL_ENV) + 1 :]
    word = cmd.split()[0]
    if word == "echo":
        return cmd.split(" ", 1)[1], 0
    if word == "uname":
        return "Linux", 0
    if word == "ls":
        return LS_ROOT, 0
    return "", 0


def _session(exec_raw):
    s = scp_client.SCPSession.__new__(scp_client.SCPSession)
    s.sent = []

    def raw(cmd, timeout=None, stdin_data=None):
        s.sent.append(cmd)
        return exec_raw(cmd)

    s._exec_raw = raw
    s._caps = scp_client._probe_capabilities(lambda c, t: raw(c, t))
    s.sent.clear()
    return s


# --- happy ----------------------------------------------------------------


def test_happy_a_restricted_shell_lists_without_the_prefix():
    s = _session(_restricted)
    assert s._caps.has_env_prefix is False
    names = [i.name for i in s.list_dir("/")]
    assert names == ["pub", "readme.txt"]
    assert s.sent == ["ls -la /"]


def test_happy_a_posix_shell_keeps_the_utf8_prefix():
    s = _session(_posix)
    assert s._caps.has_env_prefix is True
    s.list_dir("/")
    assert s.sent[0].startswith(SHELL_ENV + " ls -la ")


# --- sad ------------------------------------------------------------------


def test_sad_a_missing_folder_still_raises_on_a_restricted_shell():
    s = _session(_restricted)
    with pytest.raises(OSError):
        s.list_dir("/no-such-folder")


# --- edge -----------------------------------------------------------------


def test_edge_stat_without_a_stat_command_uses_plain_ls_ld():
    s = _session(_restricted)
    assert not s._caps.has_stat_gnu
    with pytest.raises(OSError):
        s.stat("/missing")
    assert s.sent == ["ls -ld /missing"]


def test_edge_unprobed_capabilities_keep_the_prefix():
    assert scp_client._Capabilities().has_env_prefix is True
