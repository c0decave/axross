"""A PJL FSUPLOAD answer shorter than the size it declares is an error.

_recv_until() returns what arrived when the device stalls or hangs up, and
open_read() handed that back as the file: a transfer cut off half-way was
saved as complete (found by tests/test_fuzz_pjl.py). The device's own
``@PJL FSUPLOAD ... SIZE=N`` line says how much must arrive.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import ScriptedServer, stall  # noqa: E402

from core import pjl_client as PJ  # noqa: E402

UEL = PJ.UEL
PROBE = b'@PJL INFO ID\r\n"fuzz"\r\n@PJL INFO STATUS\r\nCODE=10001\r\n' + UEL


class _Device:
    def __init__(self, upload: bytes, hang: bool = False) -> None:
        self.upload, self.hang = upload, hang
        self.server = ScriptedServer(self._handle)

    def _handle(self, conn) -> None:
        conn.settimeout(5)
        buf = b""
        while buf.count(UEL) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        if b"FSUPLOAD" not in buf:
            conn.sendall(PROBE)
            return
        conn.sendall(self.upload)
        if self.hang:
            stall(conn, 10)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.close()


def _read(dev) -> bytes:
    s = PJ.PjlSession("127.0.0.1", dev.server.port, timeout=1.0)
    return s.open_read("/report.txt").read()


HEAD = (
    b'@PJL INFO STATUS\r\nCODE=10001\r\n@PJL FSUPLOAD NAME="0:/report.txt" OFFSET=0 SIZE=%d\r\n\r\n'
)


def test_happy_complete_upload_is_returned():
    with _Device(HEAD % 5 + b"hello" + UEL) as dev:
        assert _read(dev) == b"hello"


@pytest.mark.parametrize(
    "upload, hang",
    [
        (HEAD % 10 + b"hello" + UEL, False),  # device declares more than it sends
        (HEAD % 10 + b"hello", False),  # hang-up mid-transfer
        (HEAD % 10 + b"hello", True),  # stall mid-transfer: recv times out
    ],
    ids=["short-with-uel", "hangup", "stall"],
)
def test_sad_short_upload_is_an_oserror(upload, hang):
    with _Device(upload, hang) as dev:
        with pytest.raises(OSError, match="truncated"):
            _read(dev)


def test_edge_answer_without_a_declared_size_is_unchanged():
    upload = b'@PJL INFO STATUS\r\nCODE=10001\r\n@PJL FSUPLOAD NAME="0:/r"\r\n\r\nhello' + UEL
    with _Device(upload) as dev:
        assert _read(dev) == b"hello"
