"""SLP: no query to any multicast / broadcast address, and a reply that
says it overflowed is fetched again over TCP.

Review of 2026-10-17 (B27):
- the multicast refusal (CVE-2023-29552 amplification) knew only 224.*
  and 239.255.255.253; datagrams went out to 239.1.2.3 and 232.0.0.9,
  and a host name resolving to multicast was not checked at all.
- a UDP SrvRply with the OVERFLOW flag (RFC 2608 8.1: truncated, retry
  over TCP) was parsed as the complete URL list.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from core import slp_lib as L
from core.slp_client import SlpSession

PKT = L.build_srv_type_req(b"DEFAULT")


def _srv_rply(urls, flags=0, count=None):
    body = struct.pack(">HH", 0, len(urls) if count is None else count)
    for url in urls:
        body += b"\x00" + struct.pack(">H", 60) + struct.pack(">H", len(url)) + url + b"\x00"
    header = bytearray(L._build_header(L.FN_SRV_RPLY, len(body)))
    header[5:7] = struct.pack(">H", flags)
    return bytes(header) + body


@pytest.fixture
def sent(monkeypatch):
    out = []
    original = socket.socket.sendto
    monkeypatch.setattr(
        socket.socket,
        "sendto",
        lambda self, data, addr: out.append(addr) or original(self, data, addr),
    )
    return out


@pytest.mark.parametrize("target", ["224.0.0.1", "239.255.255.253", "239.1.2.3", "232.0.0.9",
                                    "255.255.255.255"])
def test_sad_multicast_and_broadcast_are_refused_before_sending(target, sent):
    with pytest.raises(OSError, match="multicast|broadcast"):
        L.query_udp(target, PKT, port=42700, timeout=0.2)
    assert sent == []


def test_sad_a_name_that_resolves_to_multicast_is_refused(sent, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("239.9.9.9", 427))])
    with pytest.raises(OSError, match="multicast"):
        L.query_udp("slp.example", PKT, port=427, timeout=0.2)
    assert sent == []


def test_happy_a_unicast_host_is_asked_and_answers():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    reply = _srv_rply([b"service:wbem://10.0.0.1"])

    def answer():
        _data, addr = server.recvfrom(65535)
        server.sendto(reply, addr)

    threading.Thread(target=answer, daemon=True).start()
    try:
        assert L.query_udp("127.0.0.1", PKT, port=port, timeout=3) == reply
    finally:
        server.close()


def _session(monkeypatch, udp_reply, tcp_reply):
    s = SlpSession.__new__(SlpSession)
    s._host, s._port, s._timeout, s._proxy, s._use_tcp = "10.0.0.5", 427, 1.0, None, False
    asked = []
    monkeypatch.setattr(L, "query_udp", lambda *a, **k: asked.append("udp") or udp_reply)
    monkeypatch.setattr(L, "query_tcp", lambda *a, **k: asked.append("tcp") or tcp_reply)
    return s, asked


def test_edge_an_overflowed_udp_reply_is_fetched_again_over_tcp(monkeypatch):
    full = _srv_rply([b"service:wbem://10.0.0.%d" % i for i in range(1, 4)])
    s, asked = _session(
        monkeypatch, _srv_rply([b"service:wbem://10.0.0.1"], flags=L.OVERFLOW_FLAG, count=3), full
    )
    assert s._query(PKT) == full and asked == ["udp", "tcp"]
    assert len(L.parse_srv_reply(full)) == 3


def test_sad_a_tcp_reply_that_still_overflows_is_an_error(monkeypatch):
    cut = _srv_rply([b"service:a://x"], flags=L.OVERFLOW_FLAG, count=9)
    s, asked = _session(monkeypatch, cut, cut)
    with pytest.raises(OSError, match="truncated"):
        s._query(PKT)
    plain = _srv_rply([b"service:a://x"])
    s, asked = _session(monkeypatch, plain, plain)
    assert s._query(PKT) == plain and asked == ["udp"]
