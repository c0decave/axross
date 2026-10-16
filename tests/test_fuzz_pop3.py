"""Fuzz: Pop3Session against a hostile POP3 server.

LIST / TOP / RETR answers with garbage, dot-stuffing edge cases, overlong
lines, a missing terminating dot, hang-ups and stalls must end in sane items
or an OSError - never poplib.error_proto (not an OSError), ValueError or a
hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from mail_fuzz_servers import STALL, FakePop3Server  # noqa: E402

from core import pop3_client as PC  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    import poplib

    orig = poplib.POP3.__init__

    def init(self, host, port=110, timeout=30.0):
        orig(self, host, port, 1.0)

    monkeypatch.setattr(poplib.POP3, "__init__", init)


@pytest.fixture
def pop():
    srv = FakePop3Server()
    yield srv
    srv.close()


def _session(srv) -> PC.Pop3Session:
    return PC.Pop3Session(srv.host, srv.port, "u", "p", use_ssl=False)


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/1_hello.eml"),
        "open_read": lambda: s.open_read("/1_hello.eml"),
        "exists": lambda: s.exists("/2_x.eml"),
        "remove": lambda: s.remove("/1_hello.eml"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing_and_dot_unstuffing(pop):
    s = _session(pop)
    assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_hello.eml"]
    assert s.open_read("/1_hello.eml").read().endswith(b"\r\n.dot-stuffed")


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("LIST", b"+OK\r\n1 abc\r\n\xff\xfe 5\r\n-1 -1\r\n99999999999999999999 1\r\n.\r\n"),
        ("LIST", b"+OK\r\n1 100\r\n"),  # no terminating dot, then EOF
        ("LIST", b"+OK\r\n" + b"1 " + b"9" * 5000 + b"\r\n.\r\n"),  # overlong line
        ("LIST", b"-ERR no\r\n"),
        ("LIST", b"garbage\r\n"),
        ("LIST", STALL),
        ("LIST", None),
        ("TOP", b"+OK\r\nSubject: =?x-bogus?Q?a?=\r\n.\r\n"),
        ("TOP", b"+OK\r\nSubject: =?utf-8?B?S?=\r\n.\r\n"),
        ("TOP", b"+OK\r\nSubject: ../../etc/passwd\x00\r\n.\r\n"),
        ("TOP", STALL),
        ("RETR", b"+OK\r\nno terminating dot"),
        ("RETR", b"+OK\r\n..\r\n...\r\n.\r\n"),
        ("RETR", b"-ERR gone\r\n"),
        ("RETR", None),
        ("DELE", b"-ERR locked\r\n"),
        ("DELE", None),
    ],
)
def test_sad_hostile_replies(pop, verb, reply):
    pop.replies[verb] = reply
    s = _session(pop)
    _all_ops(s, f"{verb} {reply!r}"[:100])


def test_edge_endless_message_is_cut_off_at_the_cap(pop, monkeypatch):
    """A server that never ends a RETR must not grow memory without bound:
    the size cap applies while reading, not after."""
    import tracemalloc

    monkeypatch.setattr(PC, "MAX_MESSAGE_BYTES", 1 << 20)
    line = b"x" * 1000 + b"\r\n"
    pop.replies["RETR"] = b"+OK\r\n" + line * 8000 + b".\r\n"  # ~8 MB
    s = _session(pop)
    tracemalloc.start()
    try:
        result = check_contract(lambda: s.open_read("/1_a.eml"), (OSError,), timeout=30.0)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert isinstance(result, OSError)
    assert peak < 4 << 20, f"peak {peak} bytes for a 1 MiB cap"


def test_fuzz_list_mutants(pop):
    s = _session(pop)
    for n, payload in enumerate(mutants([pop.replies["LIST"]], 0x9091, iterations(60))):
        pop.replies["LIST"] = payload if payload.endswith(b"\n") else payload + b"\r\n.\r\n"
        _all_ops(s, f"LIST mutant #{n}: {payload[:80]!r}", only=("list_dir", "stat"))


def test_fuzz_top_retr_mutants(pop):
    s = _session(pop)
    corpus = [pop.replies["TOP"], pop.replies["RETR"]]
    for n, payload in enumerate(mutants(corpus, 0x9092, iterations(40))):
        if not payload.endswith(b"\n"):
            payload += b"\r\n.\r\n"
        pop.replies["TOP"] = payload
        pop.replies["RETR"] = payload
        _all_ops(s, f"TOP/RETR mutant #{n}: {payload[:80]!r}", only=("list_dir", "open_read"))
