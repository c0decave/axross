"""stat() of a message tells its real size and date; a missing group is missing.

Measured against test.rebex.net (IMAP) and news.gmane.io (NNTP):

* IMAP: ``stat()`` of a message returned 0 bytes dated 1970 while the
  listing showed 1157 bytes. imaplib hands ``UID FETCH ... (RFC822.SIZE
  INTERNALDATE)`` back as plain bytes when the reply carries no literal
  (``[b'1 (RFC822.SIZE 1157 INTERNALDATE "..." UID 100003)']``); stat()
  read only tuple parts and dropped it.
* NNTP: ``stat()`` and ``is_dir()`` called every one-segment path a group
  without asking the server, so a missing group "existed". Now GROUP's
  411 answer is FileNotFoundError, for stat, is_dir and list_dir.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.imap_client import ImapSession  # noqa: E402
from core.nntp_client import NntpSession  # noqa: E402
from tests.test_nntp_group_state import _StatefulNntp  # noqa: E402


class _FakeImap:
    def __init__(self, reply):
        self.reply = reply

    def uid(self, *args):
        return "OK", self.reply


def _imap(reply) -> ImapSession:
    s = ImapSession.__new__(ImapSession)
    s._mailbox_cache = ["Inbox"]
    s._hierarchy_sep = "/"
    s._ensure_connected = lambda: _FakeImap(reply)
    s._select_mailbox = lambda *a, **k: None
    return s


PLAIN = [b'1 (RFC822.SIZE 1157 INTERNALDATE "01-Nov-2013 13:34:52 +0100" UID 100003)']
LITERAL = [(b'1 (UID 100003 RFC822.SIZE 1157 INTERNALDATE "01-Nov-2013 13:34:52 +0100"', b""), b")"]


@pytest.fixture
def nntp():
    srv = _StatefulNntp()
    s = NntpSession("127.0.0.1", srv.port, use_tls=False)
    yield s
    s.close() if hasattr(s, "close") else None


# --- happy ----------------------------------------------------------------


@pytest.mark.parametrize("reply", [PLAIN, LITERAL], ids=["plain-bytes", "tuple"])
def test_happy_imap_stat_has_the_size_and_date(reply):
    item = _imap(reply).stat("/Inbox/100003_Hello.eml")
    assert item.size == 1157
    assert item.modified.astimezone(timezone.utc) == datetime(
        2013, 11, 1, 12, 34, 52, tzinfo=timezone.utc
    )


def test_happy_nntp_an_existing_group_is_a_folder(nntp):
    assert nntp.stat("/alt.a").is_dir
    assert nntp.is_dir("/alt.a")


# --- sad ------------------------------------------------------------------


def test_sad_nntp_a_missing_group_is_missing(nntp):
    with pytest.raises(FileNotFoundError):
        nntp.stat("/alt.nope")
    assert not nntp.is_dir("/alt.nope")
    assert not nntp.exists("/alt.nope")
    with pytest.raises(FileNotFoundError):
        nntp.list_dir("/alt.nope")


# --- edge -----------------------------------------------------------------


def test_edge_imap_a_reply_without_size_stays_zero_not_a_crash():
    item = _imap([b"1 (UID 100003)"]).stat("/Inbox/100003_Hello.eml")
    assert item.size == 0


def test_edge_nntp_the_root_needs_no_round_trip(nntp):
    assert nntp.stat("/").is_dir and nntp.is_dir("/")


# --- IMAP: a missing UID, a failed SELECT -----------------------------------
# Lab (Dovecot): stat("/INBOX/999999_none.eml") returned a 0-byte message
# dated 1970 - UID FETCH of a UID that is not there answers OK with no data
# ([None]). And after list_dir("/no-such-mailbox") failed, reading a
# message in INBOX failed with "FETCH illegal in state AUTH": a failed
# SELECT deselects the current mailbox (RFC 3501 6.3.1), but the session
# still believed INBOX was selected and skipped the SELECT.


def test_sad_imap_stat_of_a_missing_uid_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        _imap([None]).stat("/Inbox/999999_none.eml")


class _SelectingImap:
    def __init__(self):
        self.selected = None
        self.selects = []

    def select(self, mailbox, readonly=True):
        self.selects.append(mailbox)
        if mailbox == "Inbox":
            self.selected = mailbox
            return "OK", [b"3"]
        self.selected = None  # a failed SELECT leaves no mailbox selected
        return "NO", [b"Mailbox doesn't exist"]


def test_edge_imap_a_failed_select_forgets_the_selected_mailbox():
    s = ImapSession.__new__(ImapSession)
    fake = _SelectingImap()
    s._ensure_connected = lambda: fake
    s._selected_mailbox = None
    s._select_mailbox("Inbox")
    with pytest.raises(OSError):
        s._select_mailbox("Nope")
    s._select_mailbox("Inbox")
    assert fake.selects == ["Inbox", "Nope", "Inbox"]
    assert fake.selected == "Inbox"
