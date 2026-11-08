"""IMAP and POP3: remove() deletes only the message the path names.

stat() checks that ``5_invoice.eml`` is message 5 (its subject matches
the name the listing gives it); remove() acted on the number alone. A
name from a stale listing, another mailbox or another session then
deleted ANOTHER message - IMAP's UID 5 "salary letter", POP3's
message 1 "hello". Both now check first and raise FileNotFoundError on a
mismatch, deleting nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from core import imap_client as IC  # noqa: E402


class _FakeImap:
    capabilities = ("IMAP4REV1", "UIDPLUS")

    def __init__(self) -> None:
        self.log: list[tuple] = []
        self.msgs = {"5": "salary letter"}

    def noop(self):
        return "OK", [b""]

    def select(self, mailbox, readonly=True):
        self.log.append(("SELECT", mailbox, readonly))
        return "OK", [b"1"]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def close(self):
        return "OK", []

    def uid(self, cmd, *args):
        self.log.append((cmd, *args))
        if cmd == "FETCH":
            uid = args[0]
            if uid not in self.msgs:
                return "OK", [None]
            subject = self.msgs[uid].encode()
            return "OK", [
                b'5 (UID %s RFC822.SIZE 10 INTERNALDATE "01-Jul-2026 11:00:00 +0200" '
                b'ENVELOPE (NIL "%s" NIL NIL NIL NIL NIL NIL NIL NIL))' % (uid.encode(), subject)
            ]
        if cmd == "EXPUNGE":
            self.msgs.pop(args[0], None)
        return "OK", [b""]


@pytest.fixture
def imap():
    s = object.__new__(IC.ImapSession)
    s._imap = _FakeImap()
    s._hierarchy_sep = "/"
    s._selected_mailbox = None
    s._mailbox_cache = None
    s._host, s._username, s._use_ssl = "h", "u", False
    return s


def _deletes(imap) -> list:
    return [c for c in imap._imap.log if c[0] in ("STORE", "EXPUNGE")]


def test_sad_imap_remove_of_a_stale_name_deletes_nothing(imap) -> None:
    with pytest.raises(FileNotFoundError):
        imap.remove("/INBOX/5_invoice.eml")
    assert "5" in imap._imap.msgs
    assert _deletes(imap) == []


def test_edge_imap_remove_of_the_listed_name_or_bare_uid_still_deletes(imap) -> None:
    imap.remove("/INBOX/5_salary letter.eml")
    assert "5" not in imap._imap.msgs
    imap._imap.msgs["5"] = "other"
    imap.remove("/INBOX/5.eml")
    assert "5" not in imap._imap.msgs
    with pytest.raises(FileNotFoundError):
        imap.remove("/INBOX/5.eml")  # gone: no STORE for a missing UID either
    assert len(_deletes(imap)) == 4


@pytest.fixture
def pop3():
    from mail_fuzz_servers import FakePop3Server

    from core import pop3_client as P

    srv = FakePop3Server()
    srv.replies["LIST"] = lambda a: (
        (b"+OK %s 100\r\n" % a.encode()) if a else b"+OK\r\n1 100\r\n2 200\r\n.\r\n"
    )
    s = P.Pop3Session(srv.host, srv.port, "u", "p", use_ssl=False)
    yield s, srv
    try:
        s.close()
    finally:
        srv.close()


def test_sad_pop3_remove_checks_the_subject_before_dele(pop3) -> None:
    """A fresh session (never listed): the path's number was all that
    counted. Message 1's subject is "hello"."""
    s, srv = pop3
    with pytest.raises(FileNotFoundError):
        s.remove("/1_salary-letter.eml")
    assert not any(c.startswith("DELE") for c in srv.commands)
    # The name the listing gives message 1 still deletes it.
    assert "1_hello.eml" in [i.name for i in s.list_dir("/")]
    s.remove("/1_hello.eml")
    assert [c for c in srv.commands if c.startswith("DELE")] == ["DELE 1"]
