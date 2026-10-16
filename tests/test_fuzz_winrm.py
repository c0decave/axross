"""Fuzz: the WinRM backend against hostile PowerShell output.

pywinrm's session is replaced by a fake whose ``run_ps`` answers with
mutated output of the scripts the backend runs - listing / stat JSON,
base64 file bodies, Get-FileHash and Get-PSDrive lines, CIM JSON - plus
non-zero exit codes with garbage on stderr and a transport that fails.
Every call returns sane data or raises OSError.
"""

from __future__ import annotations

import base64
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

from core.winrm_client import WinRMSession  # noqa: E402

ROWS = (
    b'[{"Name":"a.txt","IsDir":false,"Size":5,"Mtime":"2024-01-02T03:04:05.1234567Z",'
    b'"IsLink":false},{"Name":"sub","IsDir":true,"Size":0,"Mtime":"2024-01-02T03:04:05Z",'
    b'"IsLink":true}]'
)
CORPUS = [
    ROWS,
    ROWS[1:-1].split(b"},{")[0] + b"}",
    base64.b64encode(b"hello") + b"\r\n",
    b"YES\r\n",
    b"2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824\r\n",
    b"1000 2000\r\n",
    b'[{"Caption":"Windows","Version":"10.0"}]',
]


class FakePs:
    def __init__(self) -> None:
        self.out = ROWS
        self.status = 0
        self.err = b""
        self.fail: Exception | None = None

    def run_ps(self, script):
        if self.fail is not None:
            raise self.fail
        return types.SimpleNamespace(status_code=self.status, std_out=self.out, std_err=self.err)


@pytest.fixture
def winrm():
    ps = FakePs()
    s = WinRMSession.__new__(WinRMSession)
    s._session = ps
    s._host, s._username = "h", "u"
    return ps, s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("C:\\"),
        "stat": lambda: s.stat("C:\\a.txt"),
        "is_dir": lambda: s.is_dir("C:\\sub"),
        "exists": lambda: s.exists("C:\\a.txt"),
        "open_read": lambda: s.open_read("C:\\a.txt").read(),
        "checksum": lambda: s.checksum("C:\\a.txt"),
        "disk_usage": lambda: s.disk_usage("C:\\"),
        "cim_query": lambda: s.cim_query("SELECT * FROM Win32_OperatingSystem"),
        "home": lambda: s.home(),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            for item in result if isinstance(result, list) else [result]:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str)
                    assert isinstance(item.size, int) and item.size >= 0


def test_happy_listing(winrm):
    _ps, s = winrm
    assert [(i.name, i.size) for i in s.list_dir("C:\\")] == [("a.txt", 5), ("sub", 0)]


def test_sad_mutated_output(winrm):
    ps, s = winrm
    for n, out in enumerate(mutants(CORPUS, seed=0x57524D, per_entry=iterations(80))):
        ps.out = out
        _all_ops(s, f"mutant {n}")


@pytest.mark.parametrize("status", [1, -1, 255])
def test_sad_failing_scripts(winrm, status):
    ps, s = winrm
    ps.status, ps.out, ps.err = status, b"\xff garbage", b"\xfe\xff error"
    _all_ops(s, f"status {status}")


@pytest.mark.parametrize(
    "exc", [ConnectionResetError(104, "reset"), RuntimeError("pywinrm"), ValueError("bad")]
)
def test_sad_transport_failures(winrm, exc):
    ps, s = winrm
    ps.fail = exc
    _all_ops(s, type(exc).__name__)
