"""An IMAP writer opened before a reconnect APPENDs on the live connection.

Round 6 found: ``_SpooledWriter`` kept the handle of ``open_write()``
time. When the session reconnected meanwhile (a dropped connection, the
next command logged in again), ``close()`` sent APPEND on the dead
handle and failed with an OSError without errno - the message was not
stored and the error said nothing usable. Now close() asks the session
for its live connection, and a connection lost under the APPEND is a
ConnectionResetError (ECONNRESET) that says the message may not be in
the mailbox.
"""

from __future__ import annotations

import errno
import imaplib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import imap_memory_server as M  # noqa: E402


@pytest.fixture
def imap(monkeypatch):
    srv = M.Server()
    srv.add_box("INBOX")
    return srv, M.session(monkeypatch, srv)


def _kill(handle) -> None:
    """The connection behind *handle* is gone: every command aborts."""
    def dead(*_a, **_k):
        raise imaplib.IMAP4.abort("socket error: EOF")

    for name in ("noop", "append", "select", "uid", "list", "capability"):
        setattr(handle, name, dead)


def test_happy_a_writer_appends_on_the_connection_the_session_has_now(imap):
    srv, s = imap
    fh = s.open_write("/INBOX/note.eml")
    fh.write(b"Subject: after the drop\r\n\r\nhello\r\n")
    old = s._imap
    _kill(old)
    s.list_dir("/INBOX")  # the session notices and reconnects
    assert s._imap is not old
    fh.close()  # was: APPEND on the dead handle -> OSError, errno None
    assert "after the drop" in srv.subjects("INBOX")


def test_sad_a_connection_lost_under_the_append_is_typed(imap, monkeypatch):
    srv, s = imap
    fh = s.open_write("/INBOX/note.eml")
    fh.write(b"Subject: lost\r\n\r\nhello\r\n")

    def lost(*_a, **_k):
        raise imaplib.IMAP4.abort("socket error: EOF")

    monkeypatch.setattr(s._imap, "append", lost)
    with pytest.raises(ConnectionResetError) as info:
        fh.close()
    assert info.value.errno == errno.ECONNRESET
    assert "may not have been stored" in str(info.value)
    assert "lost" not in srv.subjects("INBOX")


def test_edge_a_refused_append_keeps_its_answer_and_gets_an_errno(imap):
    srv, s = imap
    fh = s.open_write("/INBOX/note.eml")
    fh.write(b"Subject: x\r\n\r\n")
    del srv.boxes["INBOX"]  # NO [TRYCREATE]
    with pytest.raises(OSError) as info:
        fh.close()
    assert info.value.errno == errno.EIO
    assert "TRYCREATE" in str(info.value)
