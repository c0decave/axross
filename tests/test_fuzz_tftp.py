"""Fuzz: TftpSession (tftpy) against a hostile TFTP server.

Wrong / duplicated block numbers, oversized DATA packets, ERROR packets,
unknown opcodes, garbage, an endless transfer and silence must end in data
or an OSError within the timeout - never a tftpy exception class that is
not an OSError, and never more than the size cap in memory.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

pytest.importorskip("tftpy")

from core import tftp_client as TC  # noqa: E402

OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 3, 4, 5, 6


def data(block: int, payload: bytes) -> bytes:
    return struct.pack(">HH", OP_DATA, block & 0xFFFF) + payload


def error(code: int, msg: bytes) -> bytes:
    return struct.pack(">HH", OP_ERROR, code) + msg + b"\x00"


class TftpServer:
    """Answers an RRQ from a fresh transfer port.

    ``script`` maps the step number (0 = after the RRQ, n = after the n-th
    ACK) to the datagrams sent in reply; a missing step means silence.
    """

    def __init__(self, script: dict[int, list[bytes]]) -> None:
        self.script = script
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            _req, client = self.sock.recvfrom(2048)
        except OSError:
            return
        xfer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        xfer.bind(("127.0.0.1", 0))
        xfer.settimeout(0.5)
        step = 0
        while not self._stop.is_set() and step in self.script:
            for dgram in self.script[step]:
                xfer.sendto(dgram, client)
            step += 1
            try:
                xfer.recvfrom(2048)
            except OSError:
                break
        xfer.close()

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


def _read(script, cap: int = 1 << 20):
    srv = TftpServer(script)
    s = TC.TftpSession("127.0.0.1", srv.port, timeout=0.5, retries=1, max_size_bytes=cap)
    try:
        return check_contract(
            lambda: s.open_read("/f.bin").read(),
            (OSError,),
            timeout=20.0,
            context=repr(script)[:200],
        )
    finally:
        srv.close()


def test_happy_two_block_file():
    assert _read({0: [data(1, b"a" * 512)], 1: [data(2, b"tail")]}) == b"a" * 512 + b"tail"


@pytest.mark.parametrize(
    "script",
    [
        {0: [error(1, b"File not found")]},
        {0: [error(99, b"\xff\xfe no terminator")]},
        {0: [b"\x00\x09garbage-opcode"]},
        {0: [b""]},
        {0: [b"\x00"]},
        {0: [data(7, b"wrong first block")]},
        {0: [data(1, b"a" * 512), data(1, b"a" * 512)], 1: [data(2, b"")]},  # duplicate block
        {0: [data(1, b"x" * 9000)]},  # oversized DATA packet
        {0: [struct.pack(">H", OP_OACK) + b"tsize\x00abc\x00"]},  # OACK nobody asked for
        {0: [data(1, b"a" * 512)]},  # then silence: no last block
        {},  # silence
    ],
)
def test_sad_hostile_transfers(script):
    _read(script)


def test_edge_endless_transfer_stops_at_the_cap():
    script = {i: [data(i + 1, b"z" * 512)] for i in range(200)}
    result = _read(script, cap=10 * 512)
    assert isinstance(result, OSError)


def test_sad_size_probe_with_hostile_oack():
    for opts in (
        b"tsize\x00-5\x00",
        b"tsize\x00\xb2\x00",
        b"tsize\x00" + b"9" * 50 + b"\x00",
        b"\x00\x00",
    ):
        srv = TftpServer({0: [struct.pack(">H", OP_OACK) + opts]})
        s = TC.TftpSession("127.0.0.1", srv.port, timeout=0.5, retries=1)
        try:
            item = check_contract(
                lambda: s.stat("/f.bin"), (OSError,), timeout=20.0, context=repr(opts)
            )
            if not isinstance(item, OSError):
                assert isinstance(item.size, int)
        finally:
            srv.close()


def test_fuzz_data_packet_mutants():
    corpus = [data(1, b"a" * 512) + b"|" + data(2, b"tail")]
    for payload in mutants(corpus, 0x7F7, iterations(20)):
        first, _, second = payload.partition(b"|")
        _read({0: [first], 1: [second]})
