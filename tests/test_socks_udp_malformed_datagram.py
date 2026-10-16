"""A malformed datagram from a SOCKS5 UDP relay is an OSError.

PySocks' socksocket.recvfrom() unwraps the SOCKS5 UDP header with
``ord(frag)`` (TypeError on a datagram shorter than three bytes) and
raises NotImplementedError for a fragment. SLP (slp_lib.query_udp) and
TFTP read through create_udp_proxy_socket, so a broken or hostile relay
crashed them past every OSError handler (found by
tests/test_fuzz_socks_udp.py).
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proxy_testkit import HostileUdpRelay, allow_loopback_proxy  # noqa: E402

from core import proxy as P  # noqa: E402

HEADER = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 427)


def _recv(datagrams: list[bytes]):
    relay = HostileUdpRelay(datagrams)
    try:
        with allow_loopback_proxy():
            sock = P.create_udp_proxy_socket(P.ProxyConfig("socks5", "127.0.0.1", relay.port), 2.0)
            try:
                sock.sendto(b"req", ("127.0.0.1", 427))
                return sock.recvfrom(4096)
            finally:
                sock.close()
    finally:
        relay.close()


def test_happy_wellformed_datagram_is_unwrapped():
    assert _recv([HEADER + b"answer"]) == (b"answer", ("127.0.0.1", 427))


@pytest.mark.parametrize(
    "datagram",
    [b"", b"\x00", b"\x00\x00", b"\x00\x00\x01" + HEADER[3:] + b"frag"],
    ids=["empty", "one-byte", "two-bytes", "fragment"],
)
def test_sad_malformed_datagram_is_an_oserror(datagram):
    with pytest.raises(OSError, match="SOCKS5 UDP"):
        _recv([datagram])


def test_edge_header_without_payload_is_an_empty_datagram():
    assert _recv([HEADER]) == (b"", ("127.0.0.1", 427))
