"""SCP: listing dates in UTC, a missing remove is FileNotFoundError, no
control characters in a path, long tree commands under a long timeout.

* ``list_dir`` ran ``ls`` without ``TZ=UTC0``: its dates were the
  server's wall clock handed out as client-local time (off by the zone
  difference; stat() was right). ls runs under ``TZ=UTC0`` now and the
  shared parser returns aware UTC times.
* ``remove`` of a missing path was a plain OSError ("Command failed"):
  it is FileNotFoundError, typed by core.exec_util.ls_error as on Telnet.
* A path with a control character went into the command line; every
  path is refused first (core.path_policy.refuse_control_chars).
* ``cp`` / ``mv`` / ``rm -rf`` ran under the 30 s command timeout: a long
  copy was reported failed while it kept running. They run under
  TREE_OP_TIMEOUT, once; a timeout says the command may still be running.
"""

from __future__ import annotations

import io
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

import pytest

from core.scp_client import CMD_TIMEOUT, SCPSession, _Capabilities
from core.telnet_client import TREE_OP_TIMEOUT


class _Stream:
    def __init__(self, data: bytes, code: int, *, hang: bool = False) -> None:
        self._buf = io.BytesIO(data)
        self._hang = hang
        self.channel = self
        self._code = code

    def read(self, n=-1):
        if self._hang:
            raise socket.timeout("timed out")
        return self._buf.read(n)

    def recv_exit_status(self):
        return self._code

    def sendall(self, data):
        pass

    def shutdown_write(self):
        pass


class _Client:
    """paramiko.SSHClient stand-in: runs each command in the local sh
    (in UTC, where the client is in another zone) and records it."""

    def __init__(self, *, hang_on: str | None = None) -> None:
        self.calls: list[tuple[str, float]] = []
        self.hang_on = hang_on

    def exec_command(self, cmd, timeout=None, **kw):
        self.calls.append((cmd, timeout))
        if self.hang_on and self.hang_on in cmd:
            hung = _Stream(b"", -1, hang=True)
            return hung, hung, hung
        env = {**os.environ, "TZ": "UTC"}
        p = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, env=env, timeout=30)
        return _Stream(b"", 0), _Stream(p.stdout, p.returncode), _Stream(p.stderr, p.returncode)


def _scp(**kw) -> tuple[SCPSession, _Client]:
    s = object.__new__(SCPSession)
    s._client = _Client(**kw)
    s._lock = threading.Lock()
    s._caps = _Capabilities(has_stat_gnu=True, has_chmod=True, has_readlink=True)
    return s, s._client


@pytest.fixture
def berlin(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Berlin")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


# -- happy -------------------------------------------------------------------


def test_happy_list_dir_dates_match_stat_in_another_zone(tmp_path, berlin):
    f = tmp_path / "f.txt"
    f.write_text("x")
    old = time.time() - 86400
    os.utime(f, (old, old))
    s, client = _scp()
    listed = next(i for i in s.list_dir(str(tmp_path)) if i.name == "f.txt")
    assert "TZ=UTC0 ls" in client.calls[-1][0]
    exact = datetime.fromtimestamp(int(old), timezone.utc).astimezone().replace(tzinfo=None)
    # ls -la shows minutes: the listing is within a minute of the real time.
    assert abs((listed.modified - exact).total_seconds()) < 60


def test_happy_remove_of_an_existing_file(tmp_path):
    (tmp_path / "a").write_text("x")
    s, _ = _scp()
    s.remove(str(tmp_path / "a"))
    assert not (tmp_path / "a").exists()


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("recursive", [False, True])
def test_sad_remove_of_a_missing_path_is_not_found(tmp_path, recursive):
    s, _ = _scp()
    with pytest.raises(FileNotFoundError):
        s.remove(str(tmp_path / "missing"), recursive=recursive)


@pytest.mark.parametrize(
    "op",
    [
        lambda s, p: s.list_dir(p + "/a\x15b"),
        lambda s, p: s.stat(p + "/a\nb"),
        lambda s, p: s.exists(p + "/a\x03"),
        lambda s, p: s.mkdir(p + "/a\rb"),
        lambda s, p: s.remove(p + "/a\x17"),
        lambda s, p: s.rename(p + "/a", p + "/b\nrm -rf x"),
        lambda s, p: s.copy(p + "/a\x7f", p + "/b"),
        lambda s, p: s.open_read(p + "/a\x00"),
        lambda s, p: s.open_write(p + "/a\x1b"),
    ],
    ids=["list_dir", "stat", "exists", "mkdir", "remove", "rename", "copy", "open_read",
         "open_write"],
)
def test_sad_a_control_character_path_is_refused_before_any_command(tmp_path, op):
    s, client = _scp()
    with pytest.raises(OSError) as info:
        op(s, str(tmp_path))
    assert info.value.errno == 22
    assert client.calls == []


def test_sad_a_tree_command_that_times_out_is_sent_once_and_says_so(tmp_path):
    s, client = _scp(hang_on="cp ")
    (tmp_path / "a").write_text("x")
    with pytest.raises(TimeoutError, match="may still be running"):
        s.copy(str(tmp_path / "a"), str(tmp_path / "b"))
    assert [c for c, _ in client.calls if "cp " in c] and len(client.calls) == 1


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize(
    "op",
    [
        lambda s, p: s.copy(p + "/a", p + "/b"),
        lambda s, p: s.rename(p + "/a", p + "/c"),
        lambda s, p: s.remove(p + "/d", recursive=True),
    ],
    ids=["cp", "mv", "rm-rf"],
)
def test_edge_tree_commands_run_under_the_long_timeout(tmp_path, op):
    (tmp_path / "a").write_text("x")
    (tmp_path / "d").mkdir()
    s, client = _scp()
    op(s, str(tmp_path))
    assert client.calls[-1][1] == TREE_OP_TIMEOUT > CMD_TIMEOUT


def test_edge_without_an_env_prefix_the_listing_stays_naive(tmp_path):
    (tmp_path / "f").write_text("x")
    s, client = _scp()
    s._caps = _Capabilities(has_env_prefix=False)
    s.list_dir(str(tmp_path))
    assert "TZ=" not in client.calls[-1][0]
