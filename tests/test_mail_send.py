"""core.mail_send: building (no header injection), SMTP sending against a
scripted local server, drafts through IMAP APPEND."""

from __future__ import annotations

import socket
import sys
import threading
from email import message_from_bytes
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mail_send as MS  # noqa: E402


class FakeSmtp:
    """EHLO / AUTH PLAIN / MAIL / RCPT / DATA / QUIT on 127.0.0.1, no TLS."""

    def __init__(self, starttls: bool = False):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.starttls = starttls
        self.mail_from, self.rcpt, self.data, self.auth = "", [], b"", ""
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.sock.accept()
        f = conn.makefile("rb")
        conn.sendall(b"220 fake ESMTP\r\n")
        while True:
            line = f.readline()
            if not line:
                return
            cmd = line.decode().strip()
            up = cmd.upper()
            if up.startswith("EHLO"):
                ext = b"250-STARTTLS\r\n" if self.starttls else b""
                conn.sendall(b"250-fake\r\n" + ext + b"250 AUTH PLAIN\r\n")
            elif up.startswith("AUTH"):
                self.auth = cmd
                conn.sendall(b"235 ok\r\n")
            elif up.startswith("MAIL FROM"):
                self.mail_from = cmd[10:]
                conn.sendall(b"250 ok\r\n")
            elif up.startswith("RCPT TO"):
                self.rcpt.append(cmd[8:])
                conn.sendall(b"250 ok\r\n")
            elif up == "DATA":
                conn.sendall(b"354 go\r\n")
                buf = b""
                while not buf.endswith(b"\r\n.\r\n"):
                    buf += f.readline()
                self.data = buf[:-5]
                conn.sendall(b"250 queued\r\n")
            elif up == "QUIT":
                conn.sendall(b"221 bye\r\n")
                conn.close()
                return
            else:
                conn.sendall(b"502 no\r\n")


def test_happy_a_message_goes_out_with_bcc_only_in_the_envelope():
    srv = FakeSmtp()
    out = MS.build_message(from_addr="Me <me@example.org>", to=["Bob <bob@example.net>"], cc="c@example.net",
                           bcc=["secret@example.com"], subject="Re: lunch", body="Thursday works.\n",
                           in_reply_to="<1@example.net>")
    ok = MS.send(MS.SmtpSettings("127.0.0.1", srv.port, "plain", "me", "pw"), out)
    assert sorted(ok) == ["bob@example.net", "c@example.net", "secret@example.com"]
    assert srv.mail_from.startswith("<me@example.org>")
    assert len(srv.rcpt) == 3 and srv.auth.startswith("AUTH PLAIN")
    sent = message_from_bytes(srv.data)
    assert sent["Subject"] == "Re: lunch" and sent["In-Reply-To"] == "<1@example.net>"
    assert "secret@example.com" not in srv.data.decode() and sent["Bcc"] is None
    assert sent.get_payload().strip() == "Thursday works."


@pytest.mark.parametrize("kw", [
    dict(subject="hi\r\nBcc: victim@example.com"),
    dict(to=["bob@example.net\r\nX-Evil: 1"]),
    dict(to=["not an address"]),
    dict(to=[]),
    dict(from_addr="a@b\nc"),
    dict(in_reply_to="<x>\r\nX: y"),
])
def test_sad_nothing_can_inject_a_header(kw):
    base = dict(from_addr="me@example.org", to=["bob@example.net"], subject="s", body="b")
    with pytest.raises(ValueError):
        MS.build_message(**{**base, **kw})


def test_sad_plain_smtp_only_to_this_machine_and_starttls_must_be_offered():
    out = MS.build_message(from_addr="me@example.org", to=["b@example.net"], subject="s", body="b")
    with pytest.raises(ValueError, match="only to this machine"):
        MS.send(MS.SmtpSettings("smtp.example.org", 25, "plain"), out)
    srv = FakeSmtp(starttls=False)
    with pytest.raises(OSError, match="no STARTTLS"):
        MS.send(MS.SmtpSettings("127.0.0.1", srv.port, "starttls"), out)


class FakeImap:
    def __init__(self):
        self.appended = []

    def special_mailbox(self, use):
        return {"drafts": "Entwürfe", "sent": "Sent"}.get(use, "")

    def append_message(self, box, data, flags):
        self.appended.append((box, data, flags))


def test_happy_drafts_and_sent_copies_go_to_the_special_mailboxes():
    imap = FakeImap()
    out = MS.build_message(from_addr="me@example.org", to=["b@example.net"], subject="s", body="b")
    assert MS.save_draft(imap, out) == "Entwürfe"
    assert MS.save_sent(imap, out) == "Sent"
    assert imap.appended[0][2] == ("\\Draft", "\\Seen") and imap.appended[1][2] == ("\\Seen",)
    assert b"Subject: s" in imap.appended[0][1]
