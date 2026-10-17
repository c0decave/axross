"""Fuzz: PjlSession against a hostile PJL device.

FSDIRLIST / FSUPLOAD / INFO answers with garbage, lying sizes, traversal
names, missing UEL frames, stalls and hang-ups must end in sane items or an
OSError (PjlNotSupported is one) - never a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import ScriptedServer, check_contract, iterations, mutants, stall  # noqa: E402

from core import pjl_client as PJ  # noqa: E402

UEL = PJ.UEL
STALL = object()

PROBE = (
    b'@PJL INFO ID\r\n"HP LaserJet fuzz"\r\n@PJL INFO STATUS\r\nCODE=10001\r\nONLINE=TRUE\r\n\x0c'
    + UEL
)
DIRLIST = (
    b'@PJL INFO STATUS\r\nCODE=10001\r\n@PJL FSDIRLIST NAME="0:/" ENTRY=1\r\n'
    b". TYPE=DIR\r\n.. TYPE=DIR\r\nPJL TYPE=DIR\r\nreport.txt TYPE=FILE SIZE=1234\r\n\x0c" + UEL
)
UPLOAD = (
    b"@PJL INFO STATUS\r\nCODE=10001\r\n"
    b'@PJL FSUPLOAD NAME="0:/report.txt" OFFSET=0 SIZE=5\r\n\r\nhello' + UEL
)


class PjlDevice:
    def __init__(self) -> None:
        self.answers: dict[bytes, object] = {
            b"FSDIRLIST": DIRLIST,
            b"FSUPLOAD": UPLOAD,
            b"INFO ID": PROBE,
            b"INFO STATUS": b"@PJL INFO STATUS\r\nCODE=10001\r\n" + UEL,
        }
        self.server = ScriptedServer(self._handle)

    def _handle(self, conn) -> None:
        conn.settimeout(5)
        buf = b""
        while buf.count(UEL) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        for key in (b"FSDIRLIST", b"FSUPLOAD", b"INFO ID", b"INFO STATUS"):
            if key in buf:
                out = self.answers[key]
                break
        else:
            out = self.answers[b"INFO STATUS"]
        if out is STALL:
            stall(conn, 10)
            return
        if out is None:
            return
        conn.sendall(out)

    def close(self) -> None:
        self.server.close()


@pytest.fixture
def pjl():
    dev = PjlDevice()
    yield dev
    dev.close()


def _session(dev) -> PJ.PjlSession:
    return PJ.PjlSession("127.0.0.1", dev.server.port, timeout=1.0)


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/report.txt"),
        "is_dir": lambda: s.is_dir("/PJL"),
        "open_read": lambda: s.open_read("/report.txt"),
        "info": lambda: s.info("CONFIG"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing_and_read(pjl):
    s = _session(pjl)
    # "." and ".." of the device are not entries of the folder (review B28)
    assert [i.name for i in s.list_dir("/")] == ["PJL", "report.txt"]
    assert s.open_read("/report.txt").read() == b"hello"


@pytest.mark.parametrize(
    "key, answer",
    [
        (
            b"FSDIRLIST",
            b'@PJL INFO STATUS\r\n../../etc TYPE=FILE SIZE=-1\r\n"a\x00b" SIZE=\xb2\r\n' + UEL,
        ),
        (
            b"FSDIRLIST",
            b"@PJL INFO STATUS\r\n" + b"x TYPE=FILE SIZE=99999999999999999999999\r\n" + UEL,
        ),
        (b"FSDIRLIST", b"plain text a printer would print\r\n" + UEL),
        (b"FSDIRLIST", b"@PJL INFO STATUS\r\nno UEL ever"),
        (b"FSDIRLIST", STALL),
        (b"FSDIRLIST", None),
        (b"FSUPLOAD", b"@PJL FSUPLOAD SIZE=99999\r\n\r\nshort" + UEL),
        (b"FSUPLOAD", b"@PJL FSUPLOAD\r\n"),
        (b"FSUPLOAD", STALL),
        (b"INFO STATUS", b"garbage" + UEL),
    ],
)
def test_sad_hostile_answers(pjl, key, answer):
    s = _session(pjl)
    pjl.answers[key] = answer
    _all_ops(s, f"{key!r} {answer!r}"[:100])


@pytest.mark.parametrize("probe", [b"", b"%!PS-Adobe garbage", STALL, None, b"\xff" * 5000])
def test_sad_non_pjl_device_is_refused(pjl, probe):
    pjl.answers[b"INFO ID"] = probe
    result = check_contract(lambda: _session(pjl), (OSError,), timeout=15.0, context=repr(probe))
    assert isinstance(result, OSError)


def test_fuzz_dirlist_mutants(pjl):
    s = _session(pjl)
    for n, payload in enumerate(mutants([DIRLIST], 0x9100, iterations(80))):
        pjl.answers[b"FSDIRLIST"] = payload if UEL in payload else payload + UEL
        _all_ops(s, f"FSDIRLIST mutant #{n}: {payload[:80]!r}", only=("list_dir", "stat"))


def test_fuzz_parse_fsdirlist_direct():
    for payload in mutants([DIRLIST], 0x9101, iterations(800)):
        check_contract(
            lambda: PJ.PjlSession._parse_fsdirlist(payload), (OSError,), context=repr(payload)
        )
