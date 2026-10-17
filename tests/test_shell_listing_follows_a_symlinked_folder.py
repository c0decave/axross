"""Shell backends list the CONTENT of a folder reached through a symlink.

``ls -la <path>`` lists a symlink operand itself, not the folder it
points to (POSIX ls follows a symlink operand only with -H/-L or a
trailing slash). SCP, Telnet, ADB and rsh ran exactly that, so opening
``linkdir -> realdir`` showed one entry - the link, named with its full
path (SCP then dropped it as unsafe and showed an empty folder). They
now list ``<path>/``.

The remote shell is the local /bin/sh with GNU ls; for ADB with
``--time-style=long-iso``, the date shape Android's toybox prints.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from core.adb_client import AdbSession
from core.rsh_client import RshSession
from core.scp_client import SCPSession, _Capabilities
from core.telnet_client import TelnetSession

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}


def _sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", cmd], capture_output=True, env=_ENV, timeout=30)


def _scp(sent):
    s = object.__new__(SCPSession)
    s._caps = _Capabilities(has_env_prefix=False)

    def run(cmd, timeout=30, stdin_data=None):
        sent.append(cmd)
        p = _sh(cmd)
        if p.returncode != 0:
            raise OSError(f"Command failed (exit {p.returncode}): {p.stderr.decode()}")
        return p.stdout.decode()

    s._exec = run
    return s


def _telnet(sent):
    s = object.__new__(TelnetSession)

    def run(cmd, timeout=30):
        sent.append(cmd)
        p = _sh(cmd)
        if p.returncode != 0:
            raise OSError(p.stderr.decode())
        return p.stdout.decode()

    s._exec = run
    return s


def _adb(sent):
    s = object.__new__(AdbSession)

    def shell(cmd):
        sent.append(cmd)
        # adb shell does not report the exit status; stderr is mixed in.
        p = _sh(cmd.replace("ls -la", "ls -la --time-style=long-iso", 1))
        return (p.stdout + p.stderr).decode()

    s._shell = shell
    return s


def _rsh(sent):
    s = object.__new__(RshSession)

    def run_remote(cmd, *, stdin=None):
        sent.append(cmd)
        p = _sh(cmd)
        if p.returncode != 0:
            raise OSError(p.stderr.decode())
        return p.stdout

    s._run_remote = run_remote
    return s


MAKERS = {"scp": _scp, "telnet": _telnet, "adb": _adb, "rsh": _rsh}


@pytest.fixture
def tree(tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "a.txt").write_text("a")
    (real / "b c.txt").write_text("b")
    (real / "sub").mkdir()
    os.symlink("realdir", tmp_path / "linkdir")
    os.symlink("realdir", tmp_path / "it's linked")
    (tmp_path / "plain.txt").write_text("p")
    return tmp_path


def _names(items) -> set[str]:
    return {i.name for i in items if i.name not in (".", "..")}


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_symlinked_folder_lists_its_content(tree, maker):
    sess = MAKERS[maker]([])
    assert _names(sess.list_dir(str(tree / "linkdir"))) == {"a.txt", "b c.txt", "sub"}


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_real_folder_lists_as_before(tree, maker):
    sess = MAKERS[maker]([])
    names = _names(sess.list_dir(str(tree)))
    assert {"realdir", "linkdir", "plain.txt"} <= names


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_sad_a_file_is_never_listed_as_its_own_content(tree, maker):
    sess = MAKERS[maker]([])
    path = str(tree / "plain.txt")
    try:
        items = sess.list_dir(path)
    except OSError:
        return
    assert path not in _names(items) and "plain.txt" not in _names(items)


@pytest.mark.parametrize("maker", ["scp", "telnet", "rsh"])
def test_sad_a_missing_folder_still_raises(tree, maker):
    with pytest.raises(OSError):
        MAKERS[maker]([]).list_dir(str(tree / "missing"))


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_quoted_link_name_lists_its_content(tree, maker):
    sess = MAKERS[maker]([])
    assert _names(sess.list_dir(str(tree / "it's linked"))) == {"a.txt", "b c.txt", "sub"}


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_the_root_is_listed_as_a_single_slash(maker):
    sent: list[str] = []
    sess = MAKERS[maker](sent)
    sess.list_dir("/")
    assert sent and sent[0].endswith("ls -la /"), sent


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_trailing_slash_is_not_doubled(tree, maker):
    sent: list[str] = []
    sess = MAKERS[maker](sent)
    assert _names(sess.list_dir(str(tree / "linkdir") + "/")) == {"a.txt", "b c.txt", "sub"}
    assert "//" not in sent[0]
