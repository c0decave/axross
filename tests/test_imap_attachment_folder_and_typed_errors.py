"""IMAP: a message's attachments folder does not delete the message, and
"exists" / "not there" are said by their class.

Round 5 (repro_imap_attack.py):

* ``remove("/INBOX/1", recursive=False)`` - the folder listing message 1's
  attachments - deleted the whole message (and recursive=True did too).
  The folder is a view of the message: removing it is refused; deleting
  the message's .eml file deletes the message.
* mkdir of an existing mailbox and rename of a mailbox onto an existing
  one were a bare OSError (no errno), list_dir of a missing mailbox too;
  a move to a missing mailbox ([TRYCREATE]) as well. Now FileExistsError
  / FileNotFoundError, as the pane, the transfer engine and FUSE expect.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import imap_memory_server as M  # noqa: E402

_WITH_ATTACHMENT = (
    b"Subject: with-att\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
    b"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
    b"--b\r\nContent-Type: application/pdf\r\n"
    b"Content-Disposition: attachment; filename=a.pdf\r\n"
    b"Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--b--\r\n"
)


@pytest.fixture
def srv():
    server = M.Server(caps=("IMAP4REV1", "UIDPLUS", "MOVE", "UNSELECT"))
    for box in ("INBOX", "A", "B"):
        server.add_box(box)
    server.add_msg("INBOX", "with-att", raw=_WITH_ATTACHMENT)
    return server


@pytest.mark.parametrize("recursive", [False, True])
def test_sad_removing_the_attachments_folder_keeps_the_message(monkeypatch, srv, recursive):
    s = M.session(monkeypatch, srv)
    assert [i.name for i in s.list_dir("/INBOX/1")] == ["a.pdf"]
    with pytest.raises(PermissionError) as err:
        s.remove("/INBOX/1", recursive=recursive)
    assert err.value.errno == errno.EPERM
    assert ".eml" in str(err.value)
    assert srv.subjects("INBOX") == ["with-att"]


def test_happy_removing_the_message_file_still_deletes_it(monkeypatch, srv):
    s = M.session(monkeypatch, srv)
    s.remove("/INBOX/1_with-att.eml")
    assert srv.subjects("INBOX") == []


def test_edge_mkdir_and_rename_onto_an_existing_mailbox_are_file_exists(monkeypatch, srv):
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileExistsError):
        s.mkdir("/A")
    with pytest.raises(FileExistsError):
        s.rename("/A", "/B")
    assert set(srv.boxes) == {"INBOX", "A", "B"}
    # A server that answers without the [ALREADYEXISTS] code: the LIST
    # decides before anything is sent.
    srv.add_box("C")  # made by another client since the last LIST
    with pytest.raises(FileExistsError):
        s.mkdir("/C")
    s.mkdir("/D")
    assert "D" in srv.boxes


def test_edge_a_missing_mailbox_is_file_not_found(monkeypatch, srv):
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.list_dir("/Nope")
    with pytest.raises(FileNotFoundError):
        s.rename("/INBOX/1_with-att.eml", "/Nope/1_with-att.eml")
    assert srv.subjects("INBOX") == ["with-att"]
