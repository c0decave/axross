"""IMAP exists() says False only when the mailbox, message or attachment
is not there.

exists() read any OSError from stat() as "absent". stat() raises one for
a refused SELECT (also of a mailbox that exists), a NO or BAD to UID
FETCH, a dropped connection (imaplib's abort), a timeout and a LIST that
failed - all answered False. The transfer worker's no-clobber check takes
False as the go-ahead to write.

Absence is now FileNotFoundError at its source: a mailbox LIST does not
carry, a UID FETCH that answers OK without data, a message without the
named attachment, a path that names nothing. Every other failure is an
OSError that exists() passes on.

Driven end to end (imaplib) against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import STALL, FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402
from core.transfer_worker import TransferWorker  # noqa: E402

MSG = "/INBOX/1_Hello.eml"


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 0.4)


def _with_attachment() -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Hello"
    msg.set_content("body")
    msg.add_attachment(b"%PDF", maintype="application", subtype="pdf", filename="a.pdf")
    raw = msg.as_bytes()
    return b"* 1 FETCH (UID 1 RFC822 {%d}\r\n%s)\r\n" % (len(raw), raw)


def _tagged(text: bytes):
    return lambda tag, arg: f"{tag} ".encode() + text + b"\r\n"


@pytest.fixture
def srv():
    server = FakeImapServer({"BODY": _with_attachment()})
    yield server
    server.close()


@pytest.fixture
def s(srv):
    session = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
    yield session
    try:
        session.close()
    except Exception:  # noqa: BLE001 - the connection may be gone on purpose
        pass


def _not_a_miss(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and not isinstance(exc, FileNotFoundError)


def _raises_not_a_miss(fn):
    with pytest.raises(OSError) as info:
        fn()
    assert _not_a_miss(info.value), repr(info.value)


# --- happy ------------------------------------------------------------------


def test_happy_present_and_absent_mailboxes_and_messages(srv, s):
    assert s.exists("/") is True
    assert s.exists("/INBOX") is True
    assert s.exists("/Nope") is False
    assert s.exists(MSG) is True
    assert s.exists("/INBOX/readme.txt") is False
    srv.replies["FETCH"] = b""  # UID FETCH of a UID that is not there: OK, no data
    assert s.exists("/INBOX/9_gone.eml") is False


def test_happy_a_message_in_a_mailbox_that_does_not_exist_is_absent(srv, s):
    srv.replies["EXAMINE"] = _tagged(b"NO [NONEXISTENT] Mailbox doesn't exist: Nope")
    assert s.exists("/Nope/1_x.eml") is False
    with pytest.raises(FileNotFoundError):
        s.stat("/Nope/1_x.eml")


def test_happy_attachments_present_and_absent(srv, s):
    assert s.exists("/INBOX/1/a.pdf") is True
    assert s.exists("/INBOX/1/other.pdf") is False
    srv.replies["BODY"] = b""
    assert s.exists("/INBOX/9/a.pdf") is False


# --- sad --------------------------------------------------------------------


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("FETCH", _tagged(b"NO [UNAVAILABLE] try again later")),
        ("FETCH", _tagged(b"BAD internal error")),
        ("FETCH", None),  # the server hangs up
        ("FETCH", STALL),  # the server goes silent: a timeout
        ("EXAMINE", _tagged(b"NO [UNAVAILABLE] mailbox is locked")),
        ("EXAMINE", None),
    ],
    ids=["fetch-no", "fetch-bad", "fetch-drop", "fetch-timeout", "examine-no", "examine-drop"],
)
def test_sad_a_message_that_cannot_be_checked_is_an_oserror(srv, s, verb, reply):
    srv.replies[verb] = reply
    _raises_not_a_miss(lambda: s.exists(MSG))


@pytest.mark.parametrize(
    "reply",
    [_tagged(b"NO [UNAVAILABLE] try again later"), None, STALL],
    ids=["no", "drop", "timeout"],
)
def test_sad_a_mailbox_that_cannot_be_checked_is_an_oserror(srv, s, reply):
    srv.replies["LIST"] = reply
    s._mailbox_cache = None
    _raises_not_a_miss(lambda: s.exists("/Archive"))


def test_sad_an_unconfirmed_missing_mailbox_is_an_oserror(srv, s):
    # SELECT refused, and the LIST that would decide it fails as well.
    srv.replies["EXAMINE"] = _tagged(b"NO no such mailbox")
    srv.replies["LIST"] = _tagged(b"NO [UNAVAILABLE] try again later")
    _raises_not_a_miss(lambda: s.exists("/Nope/1_x.eml"))


def test_sad_an_attachment_that_cannot_be_checked_is_an_oserror(srv, s):
    srv.replies["BODY"] = _tagged(b"NO [UNAVAILABLE] try again later")
    _raises_not_a_miss(lambda: s.exists("/INBOX/1/a.pdf"))


def test_sad_the_transfer_worker_does_not_write_over_an_unchecked_destination(srv, s):
    srv.replies["FETCH"] = _tagged(b"NO [UNAVAILABLE] try again later")
    job = NS(
        if_exists="fail",
        dest_backend=s,
        dest_path=MSG,
        source_backend=None,
        source_path="/local/1_Hello.eml",
    )
    with pytest.raises(OSError, match="cannot check"):
        TransferWorker._check_existing_destination(job)


# --- edge -------------------------------------------------------------------


def test_edge_a_mailbox_that_cannot_be_selected_holds_no_message(srv, s):
    srv.replies["LIST"] = (
        b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
        b'* LIST (\\Noselect \\HasChildren) "/" "Work"\r\n'
        b'* LIST (\\HasNoChildren) "/" "Work/2025"\r\n'
    )
    srv.replies["EXAMINE"] = _tagged(b"NO [CANNOT] Mailbox is not selectable")
    s._mailbox_cache = None
    assert s.exists("/Work") is True
    assert s.exists("/Work/1_x.eml") is False


def test_edge_a_listed_mailbox_whose_select_is_refused_is_not_absent(srv, s):
    srv.replies["EXAMINE"] = _tagged(b"NO no such mailbox")  # wording proves nothing
    _raises_not_a_miss(lambda: s.exists(MSG))


def test_edge_paths_that_name_nothing_are_absent(s):
    assert s.exists("/INBOX/foo/bar") is False
    assert s.exists("/INBOX/1/a.pdf/deeper") is False
    with pytest.raises(FileNotFoundError):
        s.stat("/INBOX/foo/bar")
