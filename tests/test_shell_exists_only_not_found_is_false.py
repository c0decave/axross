"""ADB and rsh: exists() and is_dir() say False only for "not found".

Both backends answered exists() and is_dir() from stat() under a bare
``except OSError: return False``. stat() raised OSError for a dropped
connection, a timeout, a refused permission and an answer it could not
read alike, so each of them came back as "absent" - and
server_side_copy(overwrite=False) / the transfer worker take False as the
go-ahead to write over the destination they were told to keep. stat() now
raises FileNotFoundError (or NotADirectoryError for a path below a file)
only when ``ls`` says so; every other failure stays an OSError.

The remote shell is the local /bin/sh with GNU ls (ADB: the date shape of
Android's toybox), so the ``ls`` wording is the real one.
"""

from __future__ import annotations

import os
import subprocess
import threading

import pytest

from core import rsh_client as R
from core.adb_client import AdbSession
from core.rsh_client import RshSession
from core.server_ops import server_side_copy

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}


def _sh(cmd: str, env: dict = _ENV) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", cmd], capture_output=True, env=env, timeout=30)


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "keep.txt").write_text("PRECIOUS")
    (tmp_path / "new.txt").write_text("new")
    (tmp_path / "sub").mkdir()
    yield tmp_path
    for p in tmp_path.rglob("*"):
        if p.is_dir():
            p.chmod(0o700)


# -- ADB ---------------------------------------------------------------------


class _Device:
    """adb_shell's device: runs the command in sh, stderr mixed in (adb
    shell has one stream and no exit status); ``fail`` makes the
    transport raise."""

    def __init__(self) -> None:
        self.fail: Exception | None = None
        self.fail_ls_only = False
        self.sent: list[str] = []
        self.answer: str | None = None

    def shell(self, cmd, transport_timeout_s=None):
        self.sent.append(cmd)
        if self.fail is not None and (cmd.startswith("ls ") or not self.fail_ls_only):
            raise self.fail
        if self.answer is not None:
            return self.answer
        p = _sh(cmd.replace("ls -la", "ls -la --time-style=long-iso", 1))
        return (p.stdout + p.stderr).decode()


def _adb() -> AdbSession:
    s = object.__new__(AdbSession)
    s._device = _Device()
    s._conn_lock = threading.Lock()
    s._transport_timeout = 1.0
    s._label = "fake"
    return s


def test_happy_adb_present_and_absent(tree):
    s = _adb()
    assert s.exists(str(tree / "keep.txt")) is True
    assert s.exists(str(tree / "sub")) is True
    assert s.exists(str(tree / "gone.txt")) is False
    assert s.is_dir(str(tree / "sub")) is True
    assert s.is_dir(str(tree / "gone")) is False


def test_happy_adb_stat_of_a_missing_path_is_file_not_found(tree):
    with pytest.raises(FileNotFoundError):
        _adb().stat(str(tree / "gone.txt"))


@pytest.mark.parametrize(
    "fail",
    [ConnectionResetError("reset by peer"), TimeoutError("read timed out"), RuntimeError("CLSE")],
)
def test_sad_adb_a_transport_failure_is_an_oserror(tree, fail):
    s = _adb()
    s._device.fail = fail
    with pytest.raises(OSError, match="ADB shell"):
        s.exists(str(tree / "keep.txt"))
    with pytest.raises(OSError, match="ADB shell"):
        s.is_dir(str(tree / "sub"))


def test_sad_adb_permission_denied_is_not_absent(tree):
    (tree / "sub").chmod(0)
    s = _adb()
    with pytest.raises(PermissionError):
        s.exists(str(tree / "sub" / "hidden.txt"))
    with pytest.raises(PermissionError):
        s.is_dir(str(tree / "sub" / "hidden"))


@pytest.mark.parametrize("answer", ["", "garbage\n", "error: device offline\n"])
def test_sad_adb_an_answer_without_a_listing_line_is_an_oserror(tree, answer):
    s = _adb()
    s._device.answer = answer
    with pytest.raises(OSError) as info:
        s.exists(str(tree / "keep.txt"))
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_adb_no_clobber_copy_keeps_the_target_when_the_probe_fails(tree):
    # Only the existence probe fails (a dropped connection); the copy
    # itself would go through and replace the file.
    s = _adb()
    s._device.fail = ConnectionResetError("reset by peer")
    s._device.fail_ls_only = True
    with pytest.raises(OSError):
        server_side_copy(s, str(tree / "new.txt"), str(tree / "keep.txt"), overwrite=False)
    assert (tree / "keep.txt").read_text() == "PRECIOUS"


def test_edge_adb_a_file_is_no_folder_and_a_path_below_it_is_absent(tree):
    s = _adb()
    assert s.is_dir(str(tree / "keep.txt")) is False
    assert s.exists(str(tree / "keep.txt" / "x")) is False
    assert s.is_dir(str(tree / "keep.txt" / "x")) is False


def test_edge_adb_toybox_wording_is_classified():
    s = _adb()
    s._device.answer = "ls: /sdcard/x: No such file or directory\n"
    assert s.exists("/sdcard/x") is False
    s._device.answer = "ls: /data/x: Permission denied\n"
    with pytest.raises(PermissionError):
        s.exists("/data/x")


# -- rsh ---------------------------------------------------------------------


class _Rsh:
    """The remote end of ``_run_status``: runs the command in sh and
    returns (status, stdout, stderr); ``fail`` raises like a cut or
    timed-out rsh connection."""

    def __init__(self) -> None:
        self.fail: Exception | None = None
        self.fail_ls_only = False
        self.sent: list[str] = []
        self.answer: tuple[int, bytes, bytes] | None = None
        self.env = _ENV

    def run_status(self, command, *, stdin=None, timeout=None):
        self.sent.append(command)
        if self.fail is not None and ("ls -la" in command or not self.fail_ls_only):
            raise self.fail
        if self.answer is not None:
            return self.answer
        p = _sh(command, self.env)
        return p.returncode, p.stdout, p.stderr


def _rsh() -> RshSession:
    s = object.__new__(RshSession)
    s._host = "fake"
    s._fake = _Rsh()
    s._run_status = s._fake.run_status
    return s


def test_happy_rsh_present_and_absent(tree):
    s = _rsh()
    assert s.exists(str(tree / "keep.txt")) is True
    assert s.exists(str(tree / "sub")) is True
    assert s.exists(str(tree / "gone.txt")) is False
    assert s.exists(str(tree / "gone" / "deeper.txt")) is False
    assert s.is_dir(str(tree / "sub")) is True
    assert s.is_dir(str(tree / "gone")) is False


def test_happy_rsh_stat_reads_the_entry(tree):
    item = _rsh().stat(str(tree / "keep.txt"))
    assert (item.name, item.size, item.is_dir) == ("keep.txt", 8, False)
    with pytest.raises(FileNotFoundError):
        _rsh().stat(str(tree / "gone.txt"))


@pytest.mark.parametrize(
    "fail",
    [
        R.RshError("rsh timed out: Command 'rsh' timed out after 30 seconds"),
        R.RshError("rsh 'ls' on fake: output ended without the remote exit status"),
        R.RshError("rsh 'ls' on fake exited 1: connect to address 10.0.0.1: No route to host"),
    ],
)
def test_sad_rsh_a_transport_failure_is_an_oserror(tree, fail):
    s = _rsh()
    s._fake.fail = fail
    with pytest.raises(OSError) as info:
        s.exists(str(tree / "keep.txt"))
    assert not isinstance(info.value, FileNotFoundError)
    with pytest.raises(OSError):
        s.is_dir(str(tree / "sub"))


def test_sad_rsh_permission_denied_is_not_absent(tree):
    (tree / "sub").chmod(0)
    s = _rsh()
    with pytest.raises(PermissionError):
        s.exists(str(tree / "sub" / "hidden.txt"))
    with pytest.raises(PermissionError):
        s.is_dir(str(tree / "sub" / "hidden"))


@pytest.mark.parametrize(
    "answer",
    [(0, b"", b""), (0, b"garbage\n", b""), (2, b"", b"ls: unrecognized option\n")],
)
def test_sad_rsh_an_unreadable_answer_is_an_oserror(tree, answer):
    s = _rsh()
    s._fake.answer = answer
    with pytest.raises(OSError) as info:
        s.exists(str(tree / "keep.txt"))
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_rsh_no_clobber_copy_keeps_the_target_when_the_probe_fails(tree):
    s = _rsh()
    s._fake.fail = R.RshError("rsh timed out")
    s._fake.fail_ls_only = True
    with pytest.raises(OSError):
        server_side_copy(s, str(tree / "new.txt"), str(tree / "keep.txt"), overwrite=False)
    assert (tree / "keep.txt").read_text() == "PRECIOUS"


def test_edge_rsh_a_file_is_no_folder_and_a_path_below_it_is_absent(tree):
    s = _rsh()
    assert s.is_dir(str(tree / "keep.txt")) is False
    assert s.exists(str(tree / "keep.txt" / "x")) is False
    assert s.is_dir(str(tree / "keep.txt" / "x")) is False


def test_edge_rsh_root_is_a_folder_without_a_round_trip():
    s = _rsh()
    s._fake.fail = R.RshError("must not be asked")
    assert s.exists("/") is True and s.is_dir("/") is True


def test_edge_rsh_a_german_remote_still_reads_a_missing_path_as_absent(tree):
    # rshd runs the command in the user's locale: GNU ls then says "Datei
    # oder Verzeichnis nicht gefunden", which no wording check knows - every
    # exists() of a new upload target would raise "cannot tell".
    german = {**_ENV, "LC_ALL": "de_DE.UTF-8", "LANG": "de_DE.UTF-8", "LANGUAGE": "de"}
    probe = _sh(f"ls -d {tree / 'gone.txt'}", german)
    if b"nicht gefunden" not in probe.stderr:
        pytest.skip("no German coreutils messages on this host")
    s = _rsh()
    s._fake.env = german
    assert s.exists(str(tree / "gone.txt")) is False
    assert s.is_dir(str(tree / "gone")) is False
    assert s.exists(str(tree / "keep.txt")) is True
