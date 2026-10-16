"""Fuzz: ImapSession against a hostile IMAP server.

Mailbox names (modified UTF-7), SEARCH results, FETCH envelopes, literals
with lying sizes, BYE in the middle of a command and stalls must end in sane
items or an OSError - never imaplib.IMAP4.error / abort (plain Exception
subclasses), binascii.Error, UnicodeDecodeError, LookupError or a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from mail_fuzz_servers import STALL, FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 0.4)


@pytest.fixture
def imap():
    srv = FakeImapServer()
    yield srv
    srv.close()


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _ops(s):
    return {
        "list_root": lambda: s.list_dir("/"),
        "list_inbox": lambda: s.list_dir("/INBOX"),
        "stat_msg": lambda: s.stat("/INBOX/1_Hello.eml"),
        "list_attachments": lambda: s.list_dir("/INBOX/1"),
        "open_read": lambda: s.open_read("/INBOX/1_Hello.eml"),
        "exists": lambda: s.exists("/Archive"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        s._mailbox_cache = None
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing(imap):
    s = _session(imap)
    assert sorted(i.name for i in s.list_dir("/")) == ["Archive", "INBOX"]
    [msg] = [i for i in s.list_dir("/INBOX") if i.name.startswith("1_")]
    assert msg.size == 120 and msg.name == "1_Hello world.eml"
    assert s.open_read("/INBOX/1_Hello.eml").read().startswith(b"Subject: hi")


@pytest.mark.parametrize(
    "listing",
    [
        b'* LIST () "/" "&A-"\r\n',  # modified base64 that does not decode
        b'* LIST () "/" "&ZZZZ-"\r\n',  # odd number of UTF-16 bytes
        b'* LIST () "/" "&2D3cAA-"\r\n',  # lone surrogate pair half
        b'* LIST () "/" "a&"\r\n',
        b'* LIST () "/" "\xff\xfe"\r\n',
        b'* LIST () "/" "../../etc"\r\n',
        b"* LIST garbage\r\n",
        b"* LIST\r\n",
    ],
)
def test_sad_hostile_mailbox_names(imap, listing):
    imap.replies["LIST"] = listing
    s = _session(imap)
    _all_ops(s, repr(listing), only=("list_root", "list_inbox", "exists"))


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("SEARCH", b"* SEARCH 1 \xff 2\r\n"),
        ("SEARCH", b"* SEARCH abc\r\n"),
        ("SEARCH", b"* SEARCH " + b"9" * 400 + b"\r\n"),
        ("FETCH", b'* 1 FETCH (UID 1 ENVELOPE (NIL "=?x-bogus?Q?abc?=" NIL))\r\n'),
        ("FETCH", b'* 1 FETCH (UID 1 ENVELOPE (NIL "=?utf-8?B?!!!?=" NIL))\r\n'),
        ("FETCH", b'* 1 FETCH (UID 1 INTERNALDATE "99-Foo-99999 99:99:99 +9999")\r\n'),
        ("FETCH", b"* 1 FETCH (UID 1 RFC822.SIZE 99999999999999999999)\r\n"),
        ("FETCH", b'* 1 FETCH (UID 1 ENVELOPE ("unterminated\r\n'),
        ("FETCH", b"* 1 FETCH (UID 1 ENVELOPE (" + b"(" * 5000 + b")\r\n"),
        ("BODY", b"* 1 FETCH (UID 1 RFC822 {5}\r\nab)\r\n"),  # literal shorter than announced
        ("BODY", b"* 1 FETCH (UID 1 RFC822 {99999999999}\r\nabc"),  # lying huge literal
        ("BODY", b"* 1 FETCH (UID 1)\r\n"),  # no body at all
        ("BODY", b"* 1 FETCH (UID 1 RFC822 {30}\r\nContent-Type: multipart/mixed\r\n\r\n)\r\n"),
        ("SELECT", b"* BYE going away\r\n"),
        ("EXAMINE", b"* BYE going away\r\n"),
        ("EXAMINE", None),
        ("EXAMINE", STALL),
        ("SEARCH", STALL),
        ("FETCH", None),
        ("GETQUOTAROOT", b"* QUOTA x (STORAGE 99999999999999999999999 1)\r\n"),
        ("GETQUOTAROOT", b"* QUOTA x (STORAGE \xb2 1)\r\n"),
    ],
)
def test_sad_hostile_replies(imap, verb, reply):
    imap.replies[verb] = reply
    s = _session(imap)
    _all_ops(s, f"{verb} {reply!r}"[:120])


def test_sad_tagged_no_and_bad(imap):
    def no(tag, arg):
        return f"{tag} NO [ALERT] refused\r\n".encode()

    for verb in ("LIST", "EXAMINE", "SEARCH", "FETCH", "BODY", "GETQUOTAROOT"):
        imap.replies[verb] = lambda tag, arg: f"{tag} BAD nonsense\r\n".encode()
    s = _session(imap)
    _all_ops(s, "BAD")
    imap.replies["EXAMINE"] = no
    _all_ops(s, "NO")


def test_fuzz_list_mutants(imap):
    s = _session(imap)
    corpus = [imap.replies["LIST"], b'* LIST (\\Noselect) "." "&ZeVnLIqe-"\r\n']
    for n, payload in enumerate(mutants(corpus, 0x1A0, iterations(25))):
        if not payload.endswith(b"\r\n"):
            payload += b"\r\n"
        imap.replies["LIST"] = payload
        _all_ops(s, f"LIST mutant #{n}: {payload[:100]!r}", only=("list_root", "list_inbox"))


def test_fuzz_fetch_mutants(imap):
    s = _session(imap)
    corpus = [imap.replies["FETCH"], imap.replies["SEARCH"] + imap.replies["FETCH"]]
    for n, payload in enumerate(mutants(corpus, 0x1A1, iterations(25))):
        if not payload.endswith(b"\r\n"):
            payload += b"\r\n"
        imap.replies["FETCH"] = payload
        _all_ops(s, f"FETCH mutant #{n}: {payload[:100]!r}", only=("list_inbox", "stat_msg"))


def test_fuzz_body_mutants(imap):
    s = _session(imap)
    for n, payload in enumerate(mutants([imap.replies["BODY"]], 0x1A2, iterations(25))):
        if not payload.endswith(b"\r\n"):
            payload += b"\r\n"
        imap.replies["BODY"] = payload
        _all_ops(s, f"BODY mutant #{n}: {payload[:100]!r}", only=("open_read", "list_attachments"))


def test_fuzz_utf7_decoder_direct():
    corpus = [b"INBOX", b"&ZeVnLIqe-", b"a&-b", b"&AOQ-rger"]
    for payload in mutants(corpus, 0x1A3, iterations(500)):
        check_contract(lambda: IC._imap_utf7_decode(payload), (OSError,), context=repr(payload))


def test_fuzz_envelope_subject_direct():
    s = IC.ImapSession.__new__(IC.ImapSession)
    corpus = [
        b'ENVELOPE ("Thu, 1 Jan 2026" "=?utf-8?B?SGVsbG8=?=" (("a" NIL "b" "c")) NIL)',
        b'ENVELOPE (NIL "plain \\"quoted\\" subject" NIL)',
    ]
    for payload in mutants(corpus, 0x1A4, iterations(500)):
        text = payload.decode("ascii", "replace")
        if "(" not in text:
            continue
        check_contract(lambda: s._extract_envelope_subject(text), (OSError,), context=repr(text))
