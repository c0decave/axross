"""An unterminated telnet subnegotiation cannot grow memory without bound.

_negotiate() keeps an incomplete IAC sequence for the next read. For
"IAC SB" without "IAC SE" that was everything after it, re-scanned and
re-kept on every read with no cap: a server sending IAC SB and then
endless bytes made the transport buffer it all (8 MB for an 8 MB stream,
found by tests/test_fuzz_telnet.py).
"""

from __future__ import annotations

import codecs
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as T  # noqa: E402

IAC, SB, SE = bytes([T.IAC]), bytes([T.SB]), bytes([T.SE])


def _transport():
    a, b = socket.socketpair()
    t = T._TelnetTransport.__new__(T._TelnetTransport)
    t._sock = a
    a.setblocking(False)
    t._buffer = b""
    t._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    t._closed = False
    t._naws_width, t._naws_height = 80, 24
    return t, b


def test_happy_complete_subnegotiation_is_answered_and_stripped():
    t, peer = _transport()
    peer.sendall(b"before" + IAC + SB + bytes([T.OPT_TTYPE, 1]) + IAC + SE + b"after")
    assert t.read_some(timeout=1.0) == "beforeafter"
    peer.settimeout(1)
    assert b"xterm" in peer.recv(100)


def test_sad_unterminated_subnegotiation_over_the_cap_is_an_oserror():
    t, peer = _transport()
    peer.sendall(IAC + SB + bytes([T.OPT_TTYPE]))
    with pytest.raises(OSError, match="subnegotiation"):
        for _ in range(T.MAX_SUBNEGOTIATION_BYTES // 4096 + 4):
            peer.sendall(b"A" * 4096)
            t._read_chunk(1.0)
    assert len(t._buffer) <= T.MAX_SUBNEGOTIATION_BYTES + 4096


def test_edge_subnegotiation_split_across_reads_still_works():
    t, peer = _transport()
    peer.sendall(b"x" + IAC + SB + bytes([T.OPT_TTYPE]))
    assert t._read_chunk(1.0) == "x"
    peer.sendall(bytes([1]) + IAC + SE + b"y")
    assert t._read_chunk(1.0) == "y"
