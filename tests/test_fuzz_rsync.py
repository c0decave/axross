"""Fuzz: RsyncSession against a hostile rsync daemon.

Two layers: the system ``rsync`` binary talking to a fake daemon on
127.0.0.1 that answers the text phase of the protocol (greeting, MOTD,
module list) with mutants; and the ``--list-only`` output parser fed
hostile listings through a fake ``subprocess.run``. Every call must return
sane items or raise OSError - never UnicodeDecodeError / ValueError, never
a hang.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import (  # noqa: E402
    ScriptedServer,
    check_contract,
    iterations,
    mutants,
    recv_line,
    stall,
)

from core import rsync_client as RC  # noqa: E402

STALL = object()

MODULES = b"Welcome to the fuzz daemon\n\npublic          Public files\nbackup  \tNightly backups\n"


class FakeRsyncd:
    def __init__(self) -> None:
        self.greeting = b"@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n"
        self.listing: object = MODULES
        self.server = ScriptedServer(self._handle)
        self.port = self.server.port

    def _handle(self, conn) -> None:
        conn.settimeout(5)
        conn.sendall(self.greeting)
        recv_line(conn)  # client greeting
        recv_line(conn)  # module name (empty: list modules)
        if self.listing is STALL:
            stall(conn, 10)
            return
        if self.listing is None:
            return
        conn.sendall(self.listing + b"@RSYNCD: EXIT\n")

    def close(self) -> None:
        self.server.close()


needs_rsync = pytest.mark.skipif(shutil.which("rsync") is None, reason="no rsync binary")


@pytest.fixture
def rsyncd(monkeypatch):
    srv = FakeRsyncd()
    orig = RC.RsyncSession._run_rsync

    def run(self, extra_args, *, capture=True, timeout=60):
        return orig(
            self, ["--contimeout=2", "--timeout=2", *extra_args], capture=capture, timeout=5
        )

    monkeypatch.setattr(RC.RsyncSession, "_run_rsync", run)
    yield srv
    srv.close()


def _modules(srv):
    def call():
        s = RC.RsyncSession("127.0.0.1", srv.port)
        return s.list_dir("/")

    return check_contract(call, (OSError,), timeout=20.0, context=repr(srv.listing)[:120])


@needs_rsync
def test_happy_module_list(rsyncd):
    names = [i.name for i in _modules(rsyncd)]
    assert "public" in names and "backup" in names


@needs_rsync
@pytest.mark.parametrize(
    "listing",
    [
        b"caf\xe9 latin-1 module\n\xff\xfe\n",
        b"../../etc  traversal\n/abs  absolute\n",
        b"@ERROR: access denied\n",
        b"@RSYNCD: AUTHREQD abc\n",
        b"x" * 100000 + b"\n",
        b"",
        STALL,
        None,
    ],
)
def test_sad_hostile_module_list(rsyncd, listing):
    rsyncd.listing = listing
    result = _modules(rsyncd)
    if isinstance(result, list):
        assert all(isinstance(i.name, str) for i in result)


@needs_rsync
@pytest.mark.parametrize(
    "greeting", [b"garbage\n", b"@RSYNCD: 99999999999999999.0\n", b"", b"\xff\xfe\n"]
)
def test_sad_hostile_greeting(rsyncd, greeting):
    rsyncd.greeting = greeting
    _modules(rsyncd)


@needs_rsync
def test_fuzz_module_list_mutants(rsyncd):
    for payload in mutants([MODULES], 0x4C5, iterations(8)):
        rsyncd.listing = payload
        _modules(rsyncd)


# ------------------------------------------------- --list-only parser layer
LIST_ONLY = (
    "drwxr-xr-x          4,096 2026/01/01 12:00:00 .\n"
    "-rw-r--r--          1,234 2026/01/02 03:04:05 a.txt\n"
    "lrwxrwxrwx             12 2024/01/15 10:30:00 link -> target\n"
    "drwxr-xr-x          4,096 2026/01/01 12:00:00 sub dir\n"
)


def _fake_run(stdout: str, returncode: int = 0):
    def run(cmd, env=None, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    return run


def _session(monkeypatch, stdout: str):
    monkeypatch.setattr(RC.subprocess, "run", _fake_run(stdout))
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    return RC.RsyncSession("h", module="m")


def test_happy_list_only(monkeypatch):
    s = _session(monkeypatch, LIST_ONLY)
    assert [i.name for i in s.list_dir("/")] == ["a.txt", "link", "sub dir"]


def test_fuzz_list_only_mutants(monkeypatch):
    s = _session(monkeypatch, LIST_ONLY)
    for payload in mutants([LIST_ONLY.encode()], 0x4C6, iterations(400)):
        text = payload.decode("utf-8", "replace")
        monkeypatch.setattr(RC.subprocess, "run", _fake_run(text))
        result = check_contract(lambda: s.list_dir("/x"), (OSError,), context=repr(text))
        for item in result:
            assert isinstance(item.name, str) and isinstance(item.size, int)
