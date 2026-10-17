"""IMAP: a server may send any string as a literal (RFC 3501 4.3).

imaplib splits a response at each literal: ``(line ending in {n},
literal)`` followed by the rest of the line as the next data element.

* LIST: a mailbox name sent as a literal (Dovecot does it for names
  with ``"`` or ``\\``) arrived as a tuple, and ``entry.encode()`` raised
  AttributeError out of list_dir - not the OSError the callers handle.
* FETCH: with the ENVELOPE subject as a literal, RFC822.SIZE and
  INTERNALDATE came in the element after the tuple and were never read:
  the message listed as 0 bytes from 1970, named ``no_subject``.

Each response is now joined back together and read by one parser that
knows quoted strings, literals and parenthesised lists.

Driven against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402

_DATE = '"01-Jan-2026 10:00:00 +0000"'
_WHEN = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _fetch_server(fetch: bytes, uids: bytes = b"1 2") -> FakeImapServer:
    return FakeImapServer(replies={"FETCH": fetch, "SEARCH": b"* SEARCH " + uids + b"\r\n"})


def _listing(s) -> list[tuple[str, int, datetime]]:
    # FileItem keeps a naive local time; astimezone() reads it as such.
    return [(i.name, i.size, i.modified.astimezone(timezone.utc)) for i in s.list_dir("/INBOX")]


# --- happy ----------------------------------------------------------------


def test_happy_a_mailbox_name_sent_as_a_literal_lists_and_stats():
    lst = b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\HasNoChildren) "/" {7}\r\nMy"Name\r\n'
    with FakeImapServer(replies={"LIST": lst}) as srv:
        s = _session(srv)
        assert [i.name for i in s.list_dir("/")] == ["INBOX", 'My"Name']
        s._mailbox_cache = None
        assert s.stat('/My"Name').is_dir
        assert s.is_dir('/My"Name')


def test_happy_a_subject_literal_keeps_size_date_and_subject():
    fetch = (
        b'* 1 FETCH (UID 1 ENVELOPE ("Thu, 1 Jan 2026" {9}\r\nquote"it\\ NIL NIL NIL NIL NIL '
        b"NIL NIL NIL) RFC822.SIZE 5000 INTERNALDATE " + _DATE.encode() + b")\r\n"
        b'* 2 FETCH (UID 2 ENVELOPE ("Thu, 1 Jan 2026" "plain" NIL NIL NIL NIL NIL NIL NIL NIL) '
        b"RFC822.SIZE 6000 INTERNALDATE " + _DATE.encode() + b")\r\n"
    )
    with _fetch_server(fetch) as srv:
        got = _listing(_session(srv))
    assert got == [("1_quote_it_.eml", 5000, _WHEN), ("2_plain.eml", 6000, _WHEN)]


# --- sad ------------------------------------------------------------------


def test_sad_unparseable_list_entries_are_skipped_not_raised():
    lst = (
        b"* LIST garbage\r\n"
        b'* LIST (\\HasNoChildren) "/"\r\n'  # no name at all
        b'* LIST (\\HasNoChildren) "/" "ok"\r\n'
    )
    with FakeImapServer(replies={"LIST": lst}) as srv:
        assert [i.name for i in _session(srv).list_dir("/")] == ["ok"]


def test_sad_text_inside_a_subject_literal_is_not_read_as_items():
    # The literal carries what looks like FETCH items; only the real ones count.
    subject = b"x) RFC822.SIZE 1 UID 99 INTERNALDATE \"01-Jan-1999 00:00:00 +0000\""
    fetch = (
        b'* 1 FETCH (UID 1 ENVELOPE (NIL {%d}\r\n' % len(subject) + subject
        + b" NIL NIL NIL NIL NIL NIL NIL NIL) RFC822.SIZE 5000 INTERNALDATE "
        + _DATE.encode() + b")\r\n"
    )
    with _fetch_server(fetch, b"1") as srv:
        [(name, size, when)] = _listing(_session(srv))
    assert name.startswith("1_x) RFC822.SIZE 1 UID 99")
    assert (size, when) == (5000, _WHEN)


# --- edge -----------------------------------------------------------------


def test_edge_the_hierarchy_separator_is_read_from_a_literal_name():
    lst = b'* LIST (\\Noselect) "." {0}\r\n\r\n'
    with FakeImapServer(replies={"LIST": lst}) as srv:
        assert _session(srv)._hierarchy_sep == "."


def test_edge_several_literals_in_one_response_and_an_escaped_quoted_name():
    fetch = (
        b"* 1 FETCH (UID 1 ENVELOPE ({4}\r\ndate {3}\r\nabc NIL NIL NIL NIL NIL NIL NIL NIL) "
        b"RFC822.SIZE 7 INTERNALDATE " + _DATE.encode() + b")\r\n"
    )
    lst = b'* LIST () "/" "a\\"b"\r\n'
    with FakeImapServer(replies={"FETCH": fetch, "SEARCH": b"* SEARCH 1\r\n", "LIST": lst}) as srv:
        s = _session(srv)
        assert _listing(s) == [("1_abc.eml", 7, _WHEN)]
        assert [i.name for i in s.list_dir("/")] == ['a"b']


def test_edge_a_utf8_subject_literal_decodes():
    subject = "Grüße".encode()
    fetch = (
        b"* 1 FETCH (UID 1 RFC822.SIZE 3 ENVELOPE (NIL {%d}\r\n" % len(subject) + subject
        + b" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n"
    )
    with _fetch_server(fetch, b"1") as srv:
        assert [i.name for i in _session(srv).list_dir("/INBOX")] == ["1_Grüße.eml"]
