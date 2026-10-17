"""IMAP remove() fails when the message stays in the mailbox.

Without UIDPLUS a bare EXPUNGE would also wipe every other message
flagged \\Deleted (perhaps by another client), so _expunge_one leaves
the flag in place when others are flagged. remove() then logged a
warning and reported success: the pane dropped the file, the next
listing showed it again, and a script believed the mail was gone. An
EXPUNGE the server answered NO was reported as success the same way.

remove() now raises OSError in both cases; the \\Deleted flag stays, as
the user asked for the deletion and an expunge from any client
completes it.

Driven against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402

_PLAIN = b"* CAPABILITY IMAP4rev1\r\n"
_UIDPLUS = b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n"


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _server(caps: bytes, flagged: bytes, expunge=b"") -> FakeImapServer:
    return FakeImapServer(
        replies={
            "CAPABILITY": caps,
            "SEARCH": b"* SEARCH " + flagged + b"\r\n",
            "EXPUNGE": expunge,
        }
    )


def _expunges(srv) -> list[str]:
    return [c.split(" ", 1)[1] for c in srv.commands if "EXPUNGE" in c]


def test_happy_the_only_flagged_message_is_expunged():
    with _server(_PLAIN, b"5") as srv:
        IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False).remove("/INBOX/5_x.eml")
        assert _expunges(srv) == ["EXPUNGE"]


def test_sad_other_flagged_messages_leave_it_in_place_and_remove_fails():
    with _server(_PLAIN, b"3 5") as srv:
        s = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        with pytest.raises(OSError, match="not expunged"):
            s.remove("/INBOX/5_x.eml")
        assert _expunges(srv) == []  # message 3 is not wiped with it
        assert any("UID STORE 5 +FLAGS (\\Deleted)" in c for c in srv.commands)


def test_sad_an_expunge_the_server_refuses_fails_the_remove():
    def refuse(tag, arg):
        return f"{tag} NO expunge refused\r\n".encode()

    with _server(_UIDPLUS, b"5", expunge=refuse) as srv:
        s = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        with pytest.raises(OSError, match="expunge refused"):
            s.remove("/INBOX/5_x.eml")


def test_edge_uidplus_expunges_only_this_message_among_flagged_ones():
    with _server(_UIDPLUS, b"3 5") as srv:
        IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False).remove("/INBOX/5_x.eml")
        assert _expunges(srv) == ["UID EXPUNGE 5"]
