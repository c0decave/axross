"""IMAP as a destination: what "exists" means, and answers that failed.

What was wrong:

* Any name that starts with digits was read as a UID. "2024_report.pdf"
  was message 2024's attachment folder, and it "existed" without a
  question to the server: an upload of it was refused with "fail" and
  prompted for nothing.
* A message file "existed" whenever its UID did: "1_Invoice.eml" copied
  from another mailbox was this mailbox's message 1 ("Hello world").
* A FETCH batch the server refused was skipped with a warning. The listing
  came back without those messages, as if it were complete.
* A failed STATUS counted as 0 messages, so a non-recursive delete of the
  mailbox went ahead on a mailbox that may hold mail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import imap_client as IC  # noqa: E402
from mail_fuzz_servers import FakeImapServer  # noqa: E402

FETCH_ONE = (b"* 1 FETCH (UID 1 RFC822.SIZE 26 INTERNALDATE \"01-Jan-2026 10:00:00 +0000\" "
             b"ENVELOPE (\"Thu, 1 Jan 2026\" \"Hello world\" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n")


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


@pytest.fixture
def session():
    servers, sessions = [], []

    def make(**replies):
        server = FakeImapServer(replies=replies or None)
        servers.append(server)
        s = IC.ImapSession(server.host, server.port, "u", "p", use_ssl=False)
        sessions.append(s)
        return server, s

    yield make
    for s in sessions:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass
    for server in servers:
        server.close()


def _only_uid_1(tag, arg):
    """UID FETCH: message 1 is there; any other UID answers OK, no data."""
    return FETCH_ONE if arg.split()[0] == "1" else b""


def test_sad_a_file_name_that_starts_with_digits_is_no_message_folder(session):
    server, s = session(FETCH=_only_uid_1)
    before = len(server.commands)
    assert s.exists("/INBOX/2024_report.pdf") is False
    assert s.is_dir("/INBOX/2024_report.pdf") is False
    assert not any("FETCH" in c for c in server.commands[before:])  # nothing to ask


def test_sad_a_message_name_of_another_message_does_not_exist(session):
    _server, s = session(FETCH=_only_uid_1)
    assert s.exists("/INBOX/1_Invoice.eml") is False  # UID 1 is "Hello world"


def test_happy_the_listed_name_and_the_bare_uid_name_exist(session):
    """Guard (passes on the old code too): the names the listing and a bare
    UID give a message still exist."""
    _server, s = session(FETCH=_only_uid_1)
    assert s.exists("/INBOX/1_Hello world.eml") is True
    assert s.exists("/INBOX/1.eml") is True
    assert s.stat("/INBOX/1_Hello world.eml").size == 26


def test_edge_an_attachment_folder_of_a_message_that_is_gone(session):
    """The bare-UID folder of the attachments: there only with its message."""
    _server, s = session(FETCH=_only_uid_1)
    assert s.exists("/INBOX/7") is False


def test_sad_a_refused_fetch_batch_fails_the_listing(session):
    uids = list(range(1, 151))

    def fetch(tag, arg):
        first = int(arg.split()[0].split(",")[0])
        if first > 100:  # the second batch: a transient NO
            return f"{tag} NO [UNAVAILABLE] try again later\r\n".encode()
        return b"".join(
            (f'* {u} FETCH (UID {u} RFC822.SIZE 10 INTERNALDATE "01-Jan-2026 10:00:00 +0000" '
             f'ENVELOPE (NIL "m{u}" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n').encode()
            for u in arg.split()[0].split(","))

    _server, s = session(SEARCH=("* SEARCH " + " ".join(map(str, uids)) + "\r\n").encode(),
                         FETCH=fetch)
    with pytest.raises(OSError, match="101-150"):
        s.list_dir("/INBOX")


def _status_refused(tag, arg):
    return f"{tag} NO [UNAVAILABLE] try again later\r\n".encode()


def test_sad_a_failed_status_does_not_delete_the_mailbox(session):
    # Not INBOX: that one is refused before any question (review round 9).
    server, s = session(
        STATUS=_status_refused,
        LIST=b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\HasNoChildren) "/" "Work"\r\n',
    )
    with pytest.raises(OSError, match="Cannot tell whether"):
        s.remove("/Work")
    assert not any(" DELETE " in c for c in server.commands)


def test_edge_a_noselect_name_without_children_is_still_deleted(session):
    """Guard (passes on the old code too): a name that cannot hold mail
    (listed \\Noselect) refuses STATUS - it is empty, and still goes."""
    server, s = session(
        STATUS=_status_refused,
        LIST=b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\Noselect) "/" "Old"\r\n',
    )
    s.remove("/Old")
    assert any(' DELETE "Old"' in c or " DELETE Old" in c for c in server.commands)
