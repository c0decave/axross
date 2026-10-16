"""Fuzz: the SMB backend against hostile smbprotocol results.

No in-process SMB2 server exists to aim smbprotocol at, so smbclient is
replaced by a scripted fake (tests/smb_fake_client.py) and the fuzzing
happens at the boundary SmbSession owns: directory entries and stat
results with random attributes, FILETIMEs across and beyond datetime's
range (naive datetime.max placeholders included), sizes up to 2**64-1,
odd names, and every exception class smbprotocol raises for a broken or
hostile server. Every call returns sane data or raises OSError.
"""

from __future__ import annotations

import random
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from fuzz_testkit import check_contract, iterations  # noqa: E402
from smb_fake_client import (  # noqa: E402
    DirEntry,
    FakeSmbClient,
    StatResult,
    make_session,
    smb_info,
)
from smbprotocol.exceptions import (  # noqa: E402
    SMBAuthenticationError,
    SMBConnectionClosed,
    SMBException,
    SMBOSError,
)

from core import smb_client  # noqa: E402

NAMES = ["a.txt", "", ".", "..", "../x", "a\\b", "nul\x00", "caf�", "x" * 4096, "‮.exe"]
TIMES = [
    datetime(2024, 1, 2, tzinfo=timezone.utc),
    datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
    datetime(1601, 1, 1, tzinfo=timezone.utc),
    datetime(1, 1, 1, tzinfo=timezone.utc),
    datetime.max,  # smbprotocol's naive placeholder for an out-of-range FILETIME
]
FAILURES = [
    SMBOSError(0xC0000034, "\\\\h\\s\\a"),
    SMBException("Server message signature could not be verified"),
    SMBConnectionClosed("SMB socket was closed"),
    SMBAuthenticationError("expired"),
    KeyError(17),
    struct.error("unpack requires a buffer of 4 bytes"),
    ValueError("bad"),
    IndexError("short"),
    ConnectionResetError(104, "reset"),
    TimeoutError("timed out"),
]


@pytest.fixture
def smb(monkeypatch):
    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    return fake, make_session(fake)


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "mkdir": lambda: s.mkdir("/new"),
        "remove_tree": lambda: s.remove("/sub", recursive=True),
        "rename": lambda: s.rename("/a.txt", "/b.txt"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            for item in result if isinstance(result, list) else [result]:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str)
                    assert isinstance(item.size, int) and item.size >= 0
                    assert isinstance(item.modified, datetime)


def test_happy_session(smb):
    _fake, s = smb
    assert sorted((i.name, i.is_dir) for i in s.list_dir("/")) == [("a.txt", False), ("sub", True)]


@pytest.mark.parametrize("exc", FAILURES, ids=[type(e).__name__ for e in FAILURES])
def test_sad_every_library_failure(smb, exc):
    fake, s = smb
    fake.fail = exc
    _all_ops(s, type(exc).__name__)


def test_sad_random_entries_and_stat_results(smb):
    fake, s = smb
    rng = random.Random(0x534D42)
    for n in range(iterations(400)):
        entries = []
        for _ in range(rng.randint(0, 6)):
            written = rng.choice(TIMES) + timedelta(seconds=rng.choice([0, -1, 1]) * 0)
            info = smb_info(
                written=written,
                attrs=rng.choice([0, 0x10, 0x01, 0x11, 0xFFFFFFFF, rng.getrandbits(32)]),
                size=rng.choice([0, 5, 2**63, 2**64 - 1]),
            )
            entries.append(DirEntry(rng.choice(NAMES), info, symlink=rng.random() < 0.2))
        fake.entries = entries
        fake.stat_value = StatResult(
            rng.choice([0o100644, 0o040755, 0o120777, 0, 0o177777]),
            rng.choice([0, 5, 2**64 - 1]),
            rng.choice([0, 1_704_164_645_000_000_000, -(2**63), 2**63 - 1, 253402300799 * 10**9]),
        )
        fake.fail = rng.choice(FAILURES) if rng.random() < 0.2 else None
        _all_ops(s, f"case {n}")
