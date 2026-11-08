"""IMAP: a mailbox of more than ~125,000 messages can be listed.

The listing sends one ``UID SEARCH ALL``; its answer is one untagged line,
and imaplib refuses every line over 1,000,000 bytes - 7-digit UIDs and a
space are 8 bytes each, so an archive folder or Gmail's All Mail could
not be opened at all. That one command now reads a line of up to
_SEARCH_LINE_CAP; every other one keeps imaplib's limit.

Driven against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import imaplib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402

N = 130_000
_UIDS = [str(1_000_000 + i) for i in range(N)]


@pytest.fixture(autouse=True)
def _timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 20.0)


def _fetch(tag, arg):
    uids = arg.split(" ", 1)[0].split(",")
    return b"".join(
        f'* {i + 1} FETCH (UID {u} RFC822.SIZE 10 INTERNALDATE "01-Jan-2026 10:00:00 +0000" '
        f'ENVELOPE (NIL "s" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n'.encode()
        for i, u in enumerate(uids)
    )


def test_edge_a_mailbox_of_130000_messages_is_listed_whole():
    search = b"* SEARCH " + " ".join(_UIDS).encode() + b"\r\n"
    assert len(search) > imaplib._MAXLINE
    with FakeImapServer(replies={"SEARCH": search, "FETCH": _fetch}) as srv:
        s = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        items = s.list_dir("/INBOX")
        assert len(items) == N
        assert items[0].name.startswith(_UIDS[0] + "_")
        assert items[-1].name.startswith(_UIDS[-1] + "_")


def test_sad_after_the_listing_a_long_line_is_refused_again():
    # The raised limit is for the listing's SEARCH alone: a LIST line of
    # more than imaplib's limit, sent after it, is refused as before.
    search = b"* SEARCH " + " ".join(_UIDS).encode() + b"\r\n"
    state = {"huge": False}
    normal = FakeImapServer.default_replies(None)["LIST"]
    huge = b'* LIST (\\HasNoChildren) "/" "' + b"x" * (imaplib._MAXLINE + 10) + b'"\r\n'

    def listing(tag, arg):
        return huge if state["huge"] else normal

    with FakeImapServer(replies={"SEARCH": search, "FETCH": _fetch, "LIST": listing}) as srv:
        s = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        assert len(s.list_dir("/INBOX")) == N
        state["huge"] = True
        with pytest.raises(OSError, match="more than 1000000 bytes"):
            s.list_dir("/")
