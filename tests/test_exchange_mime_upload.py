"""Exchange: an uploaded .eml is saved whole, and every listed attachment
name stats.

Review of 2026-10-17:
- B2: open_write built a new Message from Subject, To/Cc/Bcc and the first
  text part only - attachments, the HTML part, From, Date and every other
  header were dropped, and close() reported success. The raw RFC 822
  bytes now go to EWS as the item's MIME content.
- B24: stat compared the raw sanitised attachment name, while the listing
  shows de-duplicated names ("report.1.pdf"), so a listed entry was "not
  found".
"""

from __future__ import annotations

from email.message import EmailMessage
from types import SimpleNamespace as NS

import pytest

from core import exchange_client as X


@pytest.fixture
def saved(monkeypatch):
    out = []

    class FakeMessage:
        def __init__(self, **kw):
            self.kw = kw

        def save(self):
            out.append(self.kw)

    monkeypatch.setattr(X, "Message", FakeMessage)
    monkeypatch.setattr(X, "Mailbox", lambda email_address: email_address)
    return out


def _session():
    s = X.ExchangeSession.__new__(X.ExchangeSession)
    s._account = NS(root=None)
    s._resolve_folder = lambda parts: NS(name="/".join(parts))
    return s


def _mail(subject="Q3 numbers"):
    m = EmailMessage()
    m["From"] = "boss@example.com"
    m["To"] = "me@example.com"
    if subject is not None:
        m["Subject"] = subject
    m["Date"] = "Thu, 01 Oct 2026 10:00:00 +0000"
    m.set_content("plain text")
    m.add_alternative("<p><b>html</b> text</p>", subtype="html")
    m.add_attachment(b"%PDF-1.7 ...", maintype="application", subtype="pdf", filename="q3.pdf")
    return m.as_bytes()


def _upload(s, path, raw):
    with s.open_write(path) as handle:
        handle.write(raw)


def test_happy_the_whole_message_is_saved_as_its_mime(saved):
    raw = _mail()
    _upload(_session(), "/Inbox/q3.eml", raw)
    (fields,) = saved
    assert fields["mime_content"] == raw
    assert fields["folder"].name == "Inbox"
    assert "body" not in fields and "subject" not in fields  # nothing rebuilt from parts


def test_sad_a_message_without_a_subject_gets_the_file_name(saved):
    raw = _mail(subject=None)
    _upload(_session(), "/Inbox/meeting notes.eml", raw)
    mime = saved[0]["mime_content"]
    assert mime.startswith(b"Subject: meeting notes\r\n") and mime.endswith(raw)


def test_edge_attachment_names_the_listing_shows_all_stat(saved):
    s = _session()
    att1, att2 = NS(name="report.pdf", size=10), NS(name="report.pdf", size=20)
    msg = NS(attachments=[att1, att2], datetime_received=None, datetime_sent=None,
             last_modified_time=None, size=0)
    s._fetch_message = lambda folder, seg, only=None: msg

    def resolve(parts):
        if parts and parts[-1] == "AAMk-1" or len(parts) >= 3:
            raise OSError("Exchange folder lookup: folder not found")
        return NS(name="/".join(parts))

    s._resolve_folder = resolve
    names = [i.name for i in s._list_attachments(NS(), "AAMk-1")]
    assert names == ["report.pdf", "report.1.pdf"]
    assert [s.stat(f"/Inbox/AAMk-1/{n}").size for n in names] == [10, 20]
    with pytest.raises(OSError, match="not found"):
        s.stat("/Inbox/AAMk-1/report.2.pdf")
