"""Shell backends: a path that starts with "-" is a path, never an option.

0.14.98 ended rm's options with ``--`` because a relative Telnet name
"-rf" was taken as an option (tests/test_remove_matrix.py). The other
commands SCP, Telnet and ADB build from a path did not: SCP and Telnet
keep a relative path relative (posixpath.normpath), ADB quotes what it is
given. Measured with a POSIX sh and GNU coreutils in a folder holding the
files "-R" and "-l":

* stat("-R") ran ``ls -ld -R`` and found no line for it: the existing
  FILE "-R" was reported as not found (FileNotFoundError on SCP); with
  GNU stat ``stat --format=... -R`` failed "invalid option".
* list_dir("-l") ran ``ls -la -l/`` ("invalid option -- '/'"), mkdir("-p")
  ran ``mkdir -p -p`` ("missing operand"), and ADB's readlink("-f") ran
  ``readlink -f`` and RETURNED its error text "readlink: missing operand"
  as the link target (adb shell has one stream and no exit status).

Every path operand now goes through exec_util.shell_path(), which makes a
relative path that starts with "-" start with "./" instead - the one form
every ls, cat, test, readlink, df and scp reads as a name.
"""

from __future__ import annotations

import os
import subprocess
import threading

import pytest

from core.adb_client import AdbSession
from core.exec_util import shell_path
from core.scp_client import SCPSession
from core.scp_client import _Capabilities as ScpCaps
from core.telnet_client import TelnetSession
from core.telnet_client import _Capabilities as TelnetCaps

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}


def _sh(cmd, cwd):
    return subprocess.run(["sh", "-c", cmd], capture_output=True, env=_ENV, cwd=cwd, timeout=30)


def _exec_pair(session, cwd):
    def run(cmd, timeout=30, stdin_data=None):
        p = _sh(cmd, cwd)
        if p.returncode != 0:
            raise OSError(f"Command failed (exit {p.returncode}): {p.stderr.decode()}")
        return p.stdout.decode()

    def raw(cmd, timeout=30, stdin_data=None):
        p = _sh(cmd, cwd)
        return (p.stdout + p.stderr).decode(), p.returncode

    session._exec = run
    session._exec_raw = raw
    return session


def _scp(cwd, gnu_stat=False):
    s = object.__new__(SCPSession)
    s._caps = ScpCaps(has_env_prefix=False, has_stat_gnu=gnu_stat, has_readlink=True, has_chmod=True)
    return _exec_pair(s, cwd)


def _telnet(cwd, gnu_stat=False):
    s = object.__new__(TelnetSession)
    s._caps = TelnetCaps(has_stat_gnu=gnu_stat, has_readlink=True, has_chmod=True)
    return _exec_pair(s, cwd)


def _adb(cwd):
    s = object.__new__(AdbSession)
    s._conn_lock = threading.Lock()

    def shell(cmd):
        p = _sh(cmd.replace("ls -la", "ls -la --time-style=long-iso", 1), cwd)
        return (p.stdout + p.stderr).decode()

    s._shell = shell
    return s


@pytest.fixture
def cwd(tmp_path):
    (tmp_path / "-R").write_text("a file named -R\n")
    (tmp_path / "-l").mkdir()
    (tmp_path / "-l" / "inside.txt").write_text("x")
    (tmp_path / "plain.txt").write_text("plain")
    os.symlink("plain.txt", tmp_path / "-f")
    return tmp_path


SHELLS = {
    "scp": _scp,
    "scp-gnu-stat": lambda c: _scp(c, gnu_stat=True),
    "telnet": _telnet,
    "telnet-gnu-stat": lambda c: _telnet(c, gnu_stat=True),
}


# ------------------------------------------------------------------ the helper

def test_happy_shell_path_leaves_ordinary_paths_alone():
    assert shell_path("/etc/passwd") == "/etc/passwd"
    assert shell_path("rel/name") == "rel/name"
    assert shell_path("with space") == "'with space'"


def test_sad_shell_path_turns_a_leading_dash_into_a_name():
    assert shell_path("-rf") == "./-rf"
    assert shell_path("-") == "./-"
    assert shell_path("--help") == "./--help"


def test_edge_shell_path_quotes_after_prefixing():
    assert shell_path("-a b") == "'./-a b'"
    assert shell_path("") == "''"


# ------------------------------------------------------------------ the backends

@pytest.mark.parametrize("kind", list(SHELLS))
def test_happy_stat_of_a_file_named_like_an_option_is_that_file(cwd, kind):
    b = SHELLS[kind](cwd)
    item = b.stat("-R")
    assert item.is_dir is False and item.size == len("a file named -R\n")


@pytest.mark.parametrize("kind", ["scp", "telnet"])
def test_sad_list_dir_of_a_folder_named_like_an_option_lists_it(cwd, kind):
    b = SHELLS[kind](cwd)
    assert [i.name for i in b.list_dir("-l") if i.name not in (".", "..")] == ["inside.txt"]


@pytest.mark.parametrize("kind", ["scp", "telnet"])
def test_sad_mkdir_readlink_chmod_take_the_name(cwd, kind):
    b = SHELLS[kind](cwd)
    b.mkdir("-p")
    assert (cwd / "-p").is_dir()
    assert b.readlink("-f") == "plain.txt"
    b.chmod("-R", 0o600)
    assert (os.stat(cwd / "-R").st_mode & 0o777) == 0o600


def test_edge_adb_commands_take_the_name(cwd):
    b = _adb(cwd)
    assert b.readlink("-f") == "plain.txt"
    b.mkdir("-m")
    assert (cwd / "-m").is_dir()
    b.chmod("-R", 0o640)
    assert (os.stat(cwd / "-R").st_mode & 0o777) == 0o640
    assert [i.name for i in b.list_dir("-l") if i.name not in (".", "..")] == ["inside.txt"]
