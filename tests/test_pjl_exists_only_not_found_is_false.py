"""PJL: exists() and is_dir() say False only for "not found".

stat() lists the parent with FSDIRLIST and looks the name up; exists()
and is_dir() turned every OSError of it into False - a refused or
dropped connection, a device that hung up without an answer, an answer
that is no PJL. server_side_copy(overwrite=False) and the transfer worker
take False as the go-ahead to write (FSDOWNLOAD replaces the file).

A listing that arrives and lacks the name - also a missing parent, which
the device answers with a FILEERROR line and no entries - is "not found",
a FileNotFoundError; every other failure stays an OSError.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import ScriptedServer  # noqa: E402

from core import pjl_client as PJ  # noqa: E402

UEL = PJ.UEL
STATUS = b"@PJL INFO STATUS\r\nCODE=10001\r\n"
PROBE = b'@PJL INFO ID\r\n"HP LaserJet"\r\n' + STATUS + b"\x0c" + UEL
LISTINGS = {
    b"0:/": b"PJL TYPE=DIR\r\nreport.txt TYPE=FILE SIZE=5\r\n",
    b"0:/PJL": b"jobs TYPE=DIR\r\n",
}


class _Device:
    """FSDIRLIST answers from LISTINGS (FILEERROR=3 for an unknown
    folder); ``mode`` breaks the answers after the safety probe."""

    def __init__(self) -> None:
        self.mode = "ok"
        self.server = ScriptedServer(self._handle)

    def _handle(self, conn) -> None:
        conn.settimeout(5)
        buf = b""
        while buf.count(UEL) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        if b"FSDIRLIST" not in buf:
            conn.sendall(PROBE)
            return
        if self.mode == "hangup":
            return
        if self.mode == "not-pjl":
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        name = buf.split(b'NAME="', 1)[1].split(b'"', 1)[0]
        head = STATUS + b'@PJL FSDIRLIST NAME="' + name + b'" ENTRY=1\r\n'
        body = LISTINGS.get(name, b"FILEERROR=3\r\n")
        conn.sendall(head + body + b"\x0c" + UEL)

    def close(self) -> None:
        self.server.close()


@pytest.fixture
def dev():
    d = _Device()
    yield d
    d.close()


def _session(dev) -> PJ.PjlSession:
    return PJ.PjlSession("127.0.0.1", dev.server.port, timeout=1.0)


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_happy_present_and_absent(dev):
    s = _session(dev)
    assert s.exists("/report.txt") is True
    assert s.exists("/PJL") is True
    assert s.exists("/gone.txt") is False
    assert s.is_dir("/PJL") is True
    assert s.is_dir("/gone") is False


def test_happy_stat_of_a_missing_name_is_file_not_found(dev):
    with pytest.raises(FileNotFoundError):
        _session(dev).stat("/gone.txt")


def test_edge_a_missing_parent_is_absent(dev):
    s = _session(dev)
    assert s.exists("/nodir/report.txt") is False
    assert s.is_dir("/nodir/sub") is False


def test_edge_a_file_is_no_folder(dev):
    assert _session(dev).is_dir("/report.txt") is False


@pytest.mark.parametrize("mode", ["refused", "hangup", "not-pjl"])
def test_sad_a_failed_answer_is_an_oserror(dev, mode):
    s = _session(dev)
    if mode == "refused":
        s._port = _closed_port()
    else:
        dev.mode = mode
    with pytest.raises(OSError) as info:
        s.exists("/report.txt")
    assert not isinstance(info.value, FileNotFoundError)
    with pytest.raises(OSError) as info:
        s.is_dir("/PJL")
    assert not isinstance(info.value, FileNotFoundError)
