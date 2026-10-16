"""Fuzz: NntpSession / nntp_lib against a hostile NNTP server.

Status lines, LIST ACTIVE, OVER and ARTICLE answers with garbage, lying
numbers, dot-stuffing edge cases, missing terminators, hang-ups and stalls
must end in sane items or an OSError (NntpError is one) - never a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from mail_fuzz_servers import STALL, FakeNntpServer  # noqa: E402

from core import nntp_client as NC  # noqa: E402
from core import nntp_lib as NL  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(NL, "DEFAULT_TIMEOUT", 0.4)
    orig = NL.NntpClient.__init__

    def init(self, *a, timeout=0.4, **kw):
        orig(self, *a, timeout=0.4, **kw)

    monkeypatch.setattr(NL.NntpClient, "__init__", init)


@pytest.fixture
def nntp():
    srv = FakeNntpServer()
    yield srv
    srv.close()


def _session(srv) -> NC.NntpSession:
    return NC.NntpSession(srv.host, srv.port, use_tls=False)


def _ops(s):
    return {
        "list_root": lambda: s.list_dir("/"),
        "list_group": lambda: s.list_dir("/comp.lang.python"),
        "stat": lambda: s.stat("/comp.lang.python/1_Hello.eml"),
        "stat_uncached": lambda: s.stat("/alt.test/7_x.eml"),
        "open_read": lambda: s.open_read("/comp.lang.python/1_Hello.eml"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def _fresh(srv):
    """A session whose connection may have been dropped by the last case."""
    return _session(srv)


def test_happy_listing(nntp):
    s = _session(nntp)
    assert [i.name for i in s.list_dir("/")] == ["comp.lang.python", "alt.test"]
    assert [i.name for i in s.list_dir("/comp.lang.python")] == ["1_Hello.eml", "2_World.eml"]
    assert s.open_read("/comp.lang.python/1_Hello.eml").read().endswith(b"\r\n.dot\r\n")


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("LIST", b"215 list\r\n\xff\xfe 1 2 y\r\ngroup \xb2 3 y\r\n../../etc 9 1 y\r\n.\r\n"),
        ("LIST", b"215 list\r\nno terminator\r\n"),
        ("LIST", b"215 list\r\n" + b"g" * (2 << 20) + b"\r\n.\r\n"),  # line over the cap
        ("LIST", b"2x5 broken status\r\n"),
        ("LIST", STALL),
        ("LIST", None),
        ("GROUP", b"211 abc def ghi g\r\n"),
        ("GROUP", b"211\r\n"),
        ("GROUP", b"211 1 99999999999999999999 1 g\r\n"),
        ("GROUP", b"211 1 5 1 g\r\n"),  # high < low
        ("GROUP", b"480 auth required\r\n"),
        ("OVER", b"224 ov\r\nabc\tsubj\tf\tnot a date\tid\t\t-5\tx\r\n.\r\n"),
        ("OVER", b"224 ov\r\n1\t../../x\tf\tThu, 1 Jan 2026 10:00:00 +9999\tid\t\tbig\r\n.\r\n"),
        ("OVER", b"224 ov\r\n1\t\xff\xfe\r\n.\r\n"),
        ("OVER", b"500 what\r\n"),
        ("ARTICLE", b"220 1 <a@x>\r\nno terminator"),
        ("ARTICLE", b"423 no such article\r\n"),
        ("ARTICLE", b"220 1 <a@x>\r\n..\r\n.\r\n"),
        ("ARTICLE", STALL),
        ("HEAD", b"221 1\r\n" + b"..x\r\n" * 3 + b".\r\n"),
        ("HEAD", None),
    ],
)
def test_sad_hostile_replies(nntp, verb, reply):
    nntp.replies[verb] = reply
    _all_ops(_fresh(nntp), f"{verb} {reply[:60]!r}" if isinstance(reply, bytes) else verb)


@pytest.mark.parametrize("greeting", [b"", b"500 go away\r\n", b"\xff\r\n", b"200"])
def test_sad_greeting_is_an_oserror(greeting):
    srv = FakeNntpServer()
    srv.greeting = greeting
    try:
        result = check_contract(
            lambda: _session(srv), (OSError,), timeout=10.0, context=repr(greeting)
        )
        assert isinstance(result, OSError) or greeting == b"200"
    finally:
        srv.close()


def test_fuzz_list_over_article_mutants(nntp):
    corpus = {v: nntp.replies[v] for v in ("LIST", "OVER", "ARTICLE", "GROUP")}
    for verb, seed in (("LIST", 0x770), ("OVER", 0x771), ("ARTICLE", 0x772), ("GROUP", 0x773)):
        for n, payload in enumerate(mutants([corpus[verb]], seed, iterations(25))):
            if not payload.endswith(b"\n"):
                payload += b"\r\n.\r\n"
            nntp.replies[verb] = payload
            _all_ops(_fresh(nntp), f"{verb} mutant #{n}: {payload[:80]!r}")
        nntp.replies[verb] = corpus[verb]


def test_fuzz_status_line_parser_direct():
    corpus = [b"200 ok\r\n", b"211 2 1 2 group\r\n", b"101-caps\r\n"]
    for payload in mutants(corpus, 0x774, iterations(500)):
        check_contract(lambda: NL._parse_status_line(payload), (OSError,), context=repr(payload))


def test_fuzz_overview_date_direct():
    corpus = [b"Thu, 1 Jan 2026 10:00:00 +0000", b"1 Jan 2026 10:00 GMT"]
    for payload in mutants(corpus, 0x775, iterations(500)):
        text = payload.decode("utf-8", "replace")
        check_contract(lambda: NL.parse_overview_date(text), (OSError,), context=repr(text))
