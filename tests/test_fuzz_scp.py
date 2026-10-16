"""Fuzz: the SCP backend against a hostile remote shell.

SCPSession runs ordinary shell commands over SSH exec channels and parses
what they print. paramiko's client is replaced by a fake whose
``exec_command`` answers from a script: mutated ``ls -la`` / ``stat`` /
``df`` / ``readlink`` / ``sha256sum`` output, base64 downloads with
garbage, wrong padding or non-alphabet bytes, odd exit statuses (-1 for a
cut channel), invalid UTF-8, and channels that fail mid-read. Every call
returns sane data or raises OSError. (The parsers it shares with the
telnet backend are also fuzzed directly in tests/test_fuzz_telnet.py.)
"""

from __future__ import annotations

import base64
import io
import socket
import sys
import threading
from pathlib import Path

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

from core.profiles import ConnectionProfile  # noqa: E402
from core.scp_client import SCPSession, _Capabilities  # noqa: E402

LS = (
    b"total 8\n"
    b"drwxr-xr-x 3 root root 4096 Jan  2 03:04 .\n"
    b"drwxr-xr-x 3 root root 4096 Jan  2 03:04 ..\n"
    b"-rw-r--r-- 1 root root    5 Jan  2 03:04 a.txt\n"
    b"drwxr-xr-x 2 root root 4096 Jan  2  2023 sub\n"
    b"lrwxrwxrwx 1 root root    5 Jan  2 03:04 link -> a.txt\n"
)
STAT = b"/a.txt|5|1704164645|81a4|root|root|regular file\n"
DF = b"Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 1000 400 600 40% /\n"
SUM = b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  /a.txt\n"


class _Chan:
    def __init__(self, status: int) -> None:
        self.status = status

    def recv_exit_status(self) -> int:
        return self.status

    def shutdown_write(self) -> None:
        pass

    def sendall(self, data) -> None:
        pass


class _Stream(io.BytesIO):
    def __init__(self, data: bytes, status: int, fail: Exception | None = None) -> None:
        super().__init__(data)
        self.channel = _Chan(status)
        self._fail = fail

    def read(self, n: int = -1) -> bytes:
        if self._fail is not None:
            raise self._fail
        return super().read(n)


class FakeClient:
    """Stands in for paramiko.SSHClient: exec_command answers from
    ``outputs`` (first key contained in the command wins)."""

    def __init__(self) -> None:
        self.outputs: dict[str, tuple[bytes, int]] = {
            "ls -la": (LS, 0),
            "ls -ld": (LS.splitlines(True)[3], 0),
            "stat --format": (STAT, 0),
            "test -d": (b"", 0),
            "test -e": (b"", 0),
            "base64 <": (base64.encodebytes(b"hello"), 0),
            "cat ": (b"hello", 0),
            "readlink": (b"a.txt\n", 0),
            "sha256sum": (SUM, 0),
            "df -B1": (DF, 0),
            "df -k": (DF, 0),
        }
        self.stderr = b""
        self.fail: Exception | None = None

    def exec_command(self, cmd, timeout=None, environment=None):
        out, status = next((v for k, v in self.outputs.items() if k in cmd), (b"", 127))
        return (
            _Stream(b"", status),
            _Stream(out, status, self.fail),
            _Stream(self.stderr, status),
        )

    def close(self) -> None:
        pass


@pytest.fixture(params=["base64", "raw"])
def scp(request):
    client = FakeClient()
    s = SCPSession.__new__(SCPSession)
    s._profile = ConnectionProfile(name="t", protocol="scp", host="h", username="u")
    s._client = client
    s._home_dir = "/"
    s._lock = threading.Lock()
    s._caps = _Capabilities(
        has_base64=request.param == "base64",
        has_stat_gnu=True,
        has_chmod=True,
        has_readlink=True,
        has_df=True,
        transfer_method=request.param,
    )
    yield client, s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "readlink": lambda: s.readlink("/link"),
        "checksum": lambda: s.checksum("/a.txt"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if name == "list_dir" and isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and item.name
                assert "/" not in item.name


def test_happy_session(scp):
    _client, s = scp
    names = sorted(i.name for i in s.list_dir("/"))
    assert {"a.txt", "sub", "link"} <= set(names)
    assert s.stat("/a.txt").size == 5
    assert s.open_read("/a.txt").read() == b"hello"
    assert s.checksum("/a.txt").startswith("sha256:2cf24d")


HOSTILE_DOWNLOADS = {
    "garbage": b"!!!not base64!!!\n",
    "non-alphabet": b"aGVs\xffbG8=\n",
    "mid-group": b"aGVsbG8\n",
    "padding-inside": b"aG==VsbG8=\n",
    "invalid-utf8": b"\xff\xfe\xfd\n",
    "huge-line": b"A" * 3_000_001 + b"\n",
}


@pytest.mark.parametrize("out", list(HOSTILE_DOWNLOADS.values()), ids=list(HOSTILE_DOWNLOADS))
def test_sad_hostile_base64_download(scp, out):
    client, s = scp
    client.outputs["base64 <"] = (out, 0)
    check_contract(lambda: s.open_read("/a.txt").read(), (OSError,), timeout=10.0)


@pytest.mark.parametrize("status", [-1, 1, 2, 126, 127, 255])
def test_sad_failing_commands(scp, status):
    client, s = scp
    client.outputs = {k: (b"\xff garbage\n", status) for k in client.outputs}
    client.stderr = b"\xff\xfe error\n"
    _all_ops(s, f"status {status}")


@pytest.mark.parametrize(
    "exc",
    [paramiko.SSHException("channel closed"), socket.timeout("slow")],
    ids=["ssh-exception", "timeout"],
)
def test_sad_channel_fails_mid_read(scp, exc):
    client, s = scp
    client.fail = exc
    _all_ops(s, type(exc).__name__)


def test_sad_mutated_command_output(scp):
    client, s = scp
    keys = ["ls -la", "stat --format", "readlink", "sha256sum", "df -B1", "base64 <", "ls -ld"]
    corpus = [client.outputs[k][0] for k in keys]
    for n, out in enumerate(mutants(corpus, seed=0x534350, per_entry=iterations(40))):
        for k in keys:
            client.outputs[k] = (out, 0)
        _all_ops(s, f"mutant {n}")
