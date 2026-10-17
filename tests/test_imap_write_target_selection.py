"""IMAP: probing a write target leaves the selected-mailbox state true.

open_write("/<mailbox>") EXAMINEd the mailbox to see whether it exists
and set ``_selected_mailbox`` - but not ``_selected_readonly``. After a
read-write SELECT of the same mailbox, the session still believed it
was read-write, so a following remove() skipped the SELECT and sent
``UID STORE ... \\Deleted`` to a mailbox the server had open read-only.

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

_CAPS = b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n"


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _commands(srv) -> list[str]:
    """The commands after login, without tag and NOOP probes."""
    out = [c.split(" ", 1)[1] for c in srv.commands]
    return [c for c in out if not c.startswith(("NOOP", "LOGIN", "CAPABILITY", "LIST"))]


def _command_before_store(srv) -> str:
    cmds = _commands(srv)
    store = next(i for i, c in enumerate(cmds) if c.startswith("UID STORE 5 +FLAGS (\\Deleted)"))
    return [c for c in cmds[:store] if c.startswith(("SELECT", "EXAMINE"))][-1]


def test_happy_remove_after_a_write_probe_selects_read_write_again():
    with FakeImapServer(replies={"CAPABILITY": _CAPS}) as srv:
        s = _session(srv)
        s.set_flags(5, ["\\Seen"], mailbox="INBOX", mode="add")  # SELECT INBOX, read-write
        s.open_write("/Archive").discard()  # EXAMINE Archive: read-only
        s.remove("/Archive/5_x.eml")
        assert _command_before_store(srv) == "SELECT Archive"
        assert (s._selected_mailbox, s._selected_readonly) != ("Archive", True)


def test_sad_a_failed_probe_forgets_the_selection():
    def examine(tag, arg):
        if "Archive" in arg:
            return b"* 2 EXISTS\r\n"
        return f"{tag} NO no such mailbox\r\n".encode()

    with FakeImapServer(replies={"CAPABILITY": _CAPS, "EXAMINE": examine}) as srv:
        s = _session(srv)
        s.set_flags(5, ["\\Seen"], mailbox="Archive", mode="add")
        writer = s.open_write("/report.txt")  # no such mailbox: a file for INBOX
        assert (writer._mailbox, writer._filename) == ("INBOX", "report.txt")
        writer.discard()
        assert s._selected_mailbox is None
        s.remove("/Archive/5_x.eml")
        assert _command_before_store(srv) == "SELECT Archive"


def test_edge_probing_the_mailbox_already_selected_keeps_it_read_write():
    with FakeImapServer(replies={"CAPABILITY": _CAPS}) as srv:
        s = _session(srv)
        s.set_flags(5, ["\\Seen"], mailbox="Archive", mode="add")
        s.open_write("/Archive").discard()
        s.remove("/Archive/5_x.eml")
        assert [c for c in _commands(srv) if c.startswith(("SELECT", "EXAMINE"))] == [
            "SELECT Archive"
        ]
