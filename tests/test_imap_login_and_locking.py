"""IMAP: the login of a user name with a blank or a backslash, a refused
login, is_dir() beside a running command, and an upload whose local name
carries a line break.

Before:

* imaplib quotes only the password of LOGIN: ``DOMAIN\\user`` or a name
  with a blank went on the wire as bare words - a syntax error on strict
  servers, so these users could not log in at all;
* a refused login was imaplib's own error, no OSError, and showed the raw
  server bytes (``b'[AUTHENTICATIONFAILED] ...'``) without saying to check
  the user name and password;
* ``is_dir`` was the one method that talked to the server without the
  session lock: with the mailbox cache empty (after a connect, mkdir,
  rename or remove) it sent NOOP and LIST while another thread's command
  waited for its answer - the two threads read each other's replies;
* a local file name with CR/LF raised HeaderParseError (a ValueError) from
  the upload, no OSError.
"""

from __future__ import annotations

import email
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 3.0)


def test_happy_a_user_name_with_a_blank_and_a_backslash_is_one_quoted_word():
    with FakeImapServer() as srv:
        IC.ImapSession(srv.host, srv.port, "CORP\\john doe", 'p"w\\', use_ssl=False)
        login = next(c for c in srv.commands if " LOGIN " in c)
    args = login.split(" ", 2)[2]
    assert args.startswith('"CORP\\\\john doe" '), login


def test_sad_a_refused_login_is_an_oserror_that_says_check_the_password():
    def no(tag, _arg):
        return f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n".encode()

    with FakeImapServer({"LOGIN": no}) as srv:
        with pytest.raises(OSError) as info:
            IC.ImapSession(srv.host, srv.port, "u", "bad", use_ssl=False)
    text = describe(info.value)
    assert "refused the login" in text
    assert "b'" not in text


LIST = (b'* LIST (\\HasNoChildren) "." "INBOX"\r\n'
        b'* LIST (\\HasNoChildren) "." "Work"\r\n')


def _slow_search(_tag, _arg):
    time.sleep(1.0)
    return b"* SEARCH 1 2\r\n"


def test_sad_is_dir_waits_for_a_running_command():
    with FakeImapServer({"LIST": LIST, "SEARCH": _slow_search}) as srv:
        s = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        out: dict = {}

        def lister():
            try:
                out["list"] = [i.name for i in s.list_dir("/INBOX")]
            except Exception as exc:  # noqa: BLE001
                out["list"] = repr(exc)

        thread = threading.Thread(target=lister)
        thread.start()
        time.sleep(0.4)  # the lister waits for its SEARCH answer
        s._mailbox_cache = None  # as after a mkdir / rename / remove
        out["is_dir"] = s.is_dir("/Work")
        thread.join(10)
        commands = list(srv.commands)
    assert out["is_dir"] is True
    assert isinstance(out["list"], list), out["list"]
    i_search = next(i for i, c in enumerate(commands) if "UID SEARCH" in c)
    after = commands[i_search + 1:]
    assert "UID FETCH" in after[0], f"sent during the SEARCH: {after[:3]}"


def test_sad_an_upload_name_with_a_line_break_is_no_header():
    raw = IC._SpooledWriter._wrap_as_email(b"data", "a.txt\r\nBcc: victim@example.org")
    msg = email.message_from_bytes(raw)
    assert msg.get("Bcc") is None
