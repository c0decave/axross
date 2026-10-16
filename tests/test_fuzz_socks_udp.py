"""Fuzz: SOCKS5 UDP relay datagrams (UDP ASSOCIATE) against a hostile relay.

SLP and TFTP read their answers through core.proxy.create_udp_proxy_socket
(PySocks). A relay that sends a datagram too short for the SOCKS5 UDP
header, a fragment, an unknown address type or garbage must end in an
OSError (or the next valid datagram) - never TypeError /
NotImplementedError from the datagram unwrapping, and never a hang.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from proxy_testkit import HostileUdpRelay  # noqa: E402

from core import proxy as P  # noqa: E402
from core import slp_lib as SL  # noqa: E402

GOOD = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 427) + b"answer"


@pytest.fixture(autouse=True)
def _loopback_proxy_allowed():
    with mock.patch("core.proxy._assert_proxy_host_not_private"):
        yield


def _query(datagrams: list[bytes]):
    relay = HostileUdpRelay(datagrams)
    cfg = P.ProxyConfig("socks5", "127.0.0.1", relay.port)
    try:
        return check_contract(
            lambda: SL.query_udp("127.0.0.1", b"req", port=427, timeout=0.5, proxy=cfg),
            (OSError,),
            timeout=15.0,
            context=repr(datagrams)[:200],
        )
    finally:
        relay.close()


def test_happy_relayed_answer_is_unwrapped():
    assert _query([GOOD]) == b"answer"


@pytest.mark.parametrize(
    "datagram",
    [
        b"",
        b"\x00\x00",
        b"\x00\x00\x01" + GOOD[3:],  # a fragment
        b"\x00\x00\x00\x09garbage",  # unknown address type
        b"\x00\x00\x00\x03\xff" + b"a" * 10,  # domain length lies
        b"\x00\x00\x00\x04" + b"\x00" * 5,  # truncated IPv6
        b"\x00\x00\x00\x01\x7f\x00",  # truncated IPv4
    ],
)
def test_sad_hostile_datagram_then_silence(datagram):
    _query([datagram])


def test_fuzz_relay_datagram_mutants():
    for payload in mutants([GOOD], 0x50D, iterations(25)):
        _query([payload])
