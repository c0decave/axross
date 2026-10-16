"""Fuzz: RshSession against hostile remote output.

The rsh binary is replaced by a fake ``subprocess.run`` that answers like
a hostile rshd: garbage ``ls -la`` lines, lying sizes, traversal names, a
missing or forged exit-status trailer, non-UTF-8 bytes, a timeout. Every
call must return sane items or raise OSError (RshError is one).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

from core import rsh_client as R  # noqa: E402

LS = (
    b"total 8\n"
    b"drwxr-xr-x  2 u u 4096 Jan  1 12:00 .\n"
    b"drwxr-xr-x. 3 u u 4096 Jan  1 12:00 ..\n"
    b"-rw-r--r--+ 1 u u    5 Jan  1 12:00 a.txt\n"
    b"lrwxrwxrwx  1 u u    4 Mar 16  2025 l -> /etc\n"
    b"crw-rw----  1 root tty 4, 1 Jan  1 12:00 tty1\n"
)
TAG_RE = re.compile(rb"__AXROSS_RSH_STATUS_[0-9a-f]+__")


class FakeRsh:
    """Answers by command prefix: ``(stdout, status)``, raw bytes (sent
    without the trailer), or an exception to raise from subprocess.run."""

    def __init__(self) -> None:
        self.answers: dict[str, object] = {
            "echo axross-rsh-probe": (b"axross-rsh-probe\n", 0),
            "ls -la": (LS, 0),
            "head -c": (b"hello", 0),
            "df -P": (
                b"Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 100 40 60 40% /\n",
                0,
            ),
            "sha256sum": (b"ab" * 32 + b"  /a.txt\n", 0),
            "readlink": (b"/etc\n", 0),
        }

    def run(self, argv, input=None, capture_output=True, timeout=None, check=False, env=None):
        script = argv[-1]
        tag = TAG_RE.search(script.encode()).group(0)
        inner = script.split("sh -c ", 1)[1].strip("'")
        best = None
        for prefix, ans in self.answers.items():
            if inner.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, ans)
        ans = best[1] if best else (b"", 0)
        if isinstance(ans, BaseException):
            raise ans
        if isinstance(ans, bytes):
            out = ans
        else:
            body, status = ans
            out = body + b"\n" + tag + b" " + str(status).encode() + b"\n"
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr=b"")


@pytest.fixture
def rsh(monkeypatch):
    fake = FakeRsh()
    monkeypatch.setattr(R, "_ensure_rsh_available", lambda: "/usr/bin/rsh")
    monkeypatch.setattr(R.subprocess, "run", fake.run)
    return fake


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/home/u"),
        "stat": lambda: s.stat("/home/u/a.txt"),
        "open_read": lambda: s.open_read("/a.txt"),
        "disk_usage": lambda: s.disk_usage("/"),
        "checksum": lambda: s.checksum("/a.txt"),
        "readlink": lambda: s.readlink("/l"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing(rsh):
    s = R.RshSession("h", username="u")
    assert [i.name for i in s.list_dir("/home/u")] == ["a.txt", "l", "tty1"]
    assert s.open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize(
    "prefix, answer",
    [
        ("ls -la", (b"-rw-r--r-- 1 u u 99999999999999999999 Jan  1 12:00 big\n", 0)),
        ("ls -la", (b"-rw-r--r-- 1 u u 5 Jan  1 12:00 ../../etc/passwd\n\xff\xfe junk\n", 0)),
        ("ls -la", (b"ls: cannot open directory: Permission denied", 2)),
        ("ls -la", b"no trailer at all"),
        ("ls -la", b"\n__AXROSS_RSH_STATUS_0000000000000000__ 0\n"),  # forged tag
        ("ls -la", subprocess.TimeoutExpired(cmd="rsh", timeout=1)),
        ("head -c", b""),
        ("df -P", (b"garbage", 0)),
        ("df -P", (b"h\n/dev/x \xb2 1 1 1% /\n", 0)),
        ("sha256sum", (b"", 0)),
        ("readlink", (b"\xff\xfe", 0)),
    ],
)
def test_sad_hostile_output(rsh, prefix, answer):
    s = R.RshSession("h", username="u")
    rsh.answers[prefix] = answer
    _all_ops(s, f"{prefix} {answer!r}"[:100])


def test_fuzz_ls_and_trailer_mutants(rsh):
    s = R.RshSession("h", username="u")
    for n, payload in enumerate(mutants([LS], 0x854, iterations(200))):
        rsh.answers["ls -la"] = (payload, 0) if n % 3 else payload
        _all_ops(s, f"ls mutant #{n}: {payload[:80]!r}", only=("list_dir", "stat"))
