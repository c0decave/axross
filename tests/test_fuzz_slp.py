"""Fuzz: SlpSession / slp_lib against a hostile SLP daemon (UDP and TCP).

Malformed SrvTypeRply / SrvRply / AttrRply packets - truncated headers,
lying lengths, wrong function ids, URL-auth blocks, non-UTF-8 names - must
end in sane items or an OSError, never a ValueError / struct.error from the
packet parser or a hang.
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

from fuzz_testkit import ScriptedServer, check_contract, iterations, mutants  # noqa: E402

from core import slp_client as SC  # noqa: E402
from core import slp_lib as SL  # noqa: E402


def _reply(function: int, body: bytes, xid: int = 1) -> bytes:
    lang = b"en"
    total = 14 + len(lang) + len(body)
    return (
        struct.pack(">BB", 2, function)
        + total.to_bytes(3, "big")
        + struct.pack(">H", 0)
        + b"\x00\x00\x00"
        + struct.pack(">HH", xid, len(lang))
        + lang
        + body
    )


def _strf(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


TYPES = _reply(SL.FN_SRV_TYPE_RPLY, struct.pack(">H", 0) + _strf(b"service:printer,service:wbem"))
URLS = _reply(
    SL.FN_SRV_RPLY,
    struct.pack(">HH", 0, 2)
    + b"\x00"
    + struct.pack(">H", 300)
    + _strf(b"service:printer://10.0.0.5")
    + b"\x00"
    + b"\x00"
    + struct.pack(">H", 60)
    + _strf(b"service:printer://10.0.0.6")
    + b"\x00",
)
ATTRS = _reply(
    SL.FN_ATTR_RPLY, struct.pack(">H", 0) + _strf(b"(name=lp1),(location=lab\\,2)") + b"\x00"
)


class SlpDaemon:
    """Answers each request by its function id; UDP and TCP on one port."""

    def __init__(self) -> None:
        self.answers = {SL.FN_SRV_TYPE_REQ: TYPES, SL.FN_SRV_REQ: URLS, SL.FN_ATTR_REQ: ATTRS}
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve_udp, daemon=True).start()
        self.tcp = ScriptedServer(self._serve_tcp)

    def _answer(self, req: bytes):
        fn = req[1] if len(req) > 1 else 0
        return self.answers.get(fn)

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65536)
            except OSError:
                return
            out = self._answer(data)
            if out is not None:
                self.udp.sendto(out[:65000], addr)

    def _serve_tcp(self, conn) -> None:
        conn.settimeout(3)
        data = conn.recv(65536)
        out = self._answer(data)
        if out is not None:
            conn.sendall(out)

    def close(self) -> None:
        self._stop.set()
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def slp():
    d = SlpDaemon()
    yield d
    d.close()


def _session(d, use_tcp=False) -> SC.SlpSession:
    port = d.tcp.port if use_tcp else d.port
    return SC.SlpSession("127.0.0.1", port, use_tcp=use_tcp, timeout=0.5)


def _ops(s):
    return {
        "list_root": lambda: s.list_dir("/"),
        "list_type": lambda: s.list_dir("/service_printer"),
        "open_read": lambda: s.open_read("/service_printer/service_printer___10.0.0.5.attrs"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        s._urls_cache.clear()
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and "/" not in item.name


def test_happy_browse(slp):
    s = _session(slp)
    assert [i.name for i in s.list_dir("/")] == ["service_printer", "service_wbem"]
    urls = [i.name for i in s.list_dir("/service_printer")]
    assert urls == ["service_printer___10.0.0.5.attrs", "service_printer___10.0.0.6.attrs"]
    assert b"location=lab" in s.open_read("/service_printer/" + urls[0]).read()


HOSTILE = [
    b"",
    b"\x02",
    _reply(SL.FN_SRV_RPLY, b"")[:10],  # shorter than a header
    _reply(SL.FN_SRV_RPLY, b"\x00\x00\x00\x05" + b"\x00" * 4),  # url_count lies
    _reply(SL.FN_SRV_RPLY, b"\x00\x00\x00\x01\x00\x01\x00\xff\xffshort"),  # url length lies
    _reply(SL.FN_SRV_RPLY, b"\x00\x00\x00\x01\x00\x01\x00\x00\x03abc\x05" + b"\x00\x00\x00\x02"),
    _reply(SL.FN_ATTR_RPLY, b"\x00\x00\xff\xff"),  # attr length lies
    _reply(SL.FN_SRV_TYPE_RPLY, b"\x00\x00"),  # wrong function for SrvRqst
    _reply(SL.FN_SRV_RPLY, b"\x00\x00\x00\x01\x00\x00\x00\x00\x04\xff\xfe/\x00\x00"),
    b"\x02\x02\x00\x00\x10\x00\x00\x00\x00\x00\x00\x01\xff\xff",  # lang-tag length lies
]


@pytest.mark.parametrize("use_tcp", [False, True], ids=["udp", "tcp"])
@pytest.mark.parametrize("packet", HOSTILE, ids=[f"p{i}" for i in range(len(HOSTILE))])
def test_sad_hostile_srv_and_attr_replies(slp, packet, use_tcp):
    s = _session(slp, use_tcp)
    slp.answers[SL.FN_SRV_REQ] = packet
    slp.answers[SL.FN_ATTR_REQ] = packet
    _all_ops(s, f"{packet[:40]!r}", only=("list_type", "open_read"))


def test_sad_silent_daemon_times_out(slp):
    s = _session(slp)
    slp.answers[SL.FN_SRV_REQ] = None
    assert isinstance(check_contract(lambda: s.list_dir("/service_printer"), (OSError,)), OSError)


@pytest.mark.parametrize("packet", HOSTILE[:4] + [_reply(SL.FN_SRV_TYPE_RPLY, b"\x00\x00\xff\xff")])
def test_sad_hostile_type_reply_at_connect(slp, packet):
    slp.answers[SL.FN_SRV_TYPE_REQ] = packet
    check_contract(lambda: _session(slp), (OSError,), timeout=10.0, context=repr(packet))


def test_fuzz_reply_mutants_udp(slp):
    s = _session(slp)
    for n, payload in enumerate(mutants([URLS, ATTRS], 0x5170, iterations(60))):
        slp.answers[SL.FN_SRV_REQ] = payload
        slp.answers[SL.FN_ATTR_REQ] = payload
        _all_ops(s, f"mutant #{n}: {payload[:60]!r}", only=("list_type", "open_read"))


def test_fuzz_parsers_direct():
    corpus = [TYPES, URLS, ATTRS]
    # SlpProtocolError is an OSError (and, for older callers, a ValueError);
    # a bare ValueError - UnicodeDecodeError included - is a parser bug.
    allowed = (OSError,)
    for payload in mutants(corpus, 0x5171, iterations(1500)):
        for parse in (SL.parse_srv_type_reply, SL.parse_srv_reply, SL.parse_attr_reply):
            check_contract(lambda: parse(payload), allowed, context=f"{parse.__name__} {payload!r}")
