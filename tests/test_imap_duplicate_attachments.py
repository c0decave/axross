"""IMAP: attachments that share a file name each get their own name.

A message with two attachments named ``report.pdf`` listed both as
``report.pdf``; stat and open_read matched the first part by name, so
saving the second one silently saved the first one's bytes. Later
duplicates now get ``.1``, ``.2`` ... before the extension (like the
Exchange backend), and listing, stat and open_read use the same names.

Driven against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _serve(attachments: list[tuple[str | None, bytes]]) -> FakeImapServer:
    msg = EmailMessage()
    msg["Subject"] = "reports"
    msg.set_content("see attached")
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="pdf", filename=name)
    raw = msg.as_bytes().replace(b"\n", b"\r\n")
    srv = FakeImapServer()
    srv.replies["BODY"] = b"* 1 FETCH (UID 1 RFC822 {%d}\r\n" % len(raw) + raw + b")\r\n"
    return srv


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _contents(s: IC.ImapSession) -> dict[str, tuple[int, int, bytes]]:
    """name -> (listed size, stat size, bytes read) for every listed attachment."""
    out = {}
    for item in s.list_dir("/INBOX/1"):
        path = f"/INBOX/1/{item.name}"
        out[item.name] = (item.size, s.stat(path).size, s.open_read(path).read())
    return out


def test_happy_same_named_attachments_list_stat_and_read_their_own_bytes():
    with _serve([("report.pdf", b"FIRST"), ("report.pdf", b"SECOND-LONGER")]) as srv:
        got = _contents(_session(srv))
    assert got == {
        "report.pdf": (5, 5, b"FIRST"),
        "report.1.pdf": (13, 13, b"SECOND-LONGER"),
    }


def test_sad_a_suffix_beyond_the_duplicates_is_not_found():
    with _serve([("report.pdf", b"FIRST"), ("report.pdf", b"SECOND")]) as srv:
        s = _session(srv)
        with pytest.raises(OSError):
            s.open_read("/INBOX/1/report.2.pdf")
        with pytest.raises(OSError):
            s.stat("/INBOX/1/report.2.pdf")


def test_edge_a_real_name_that_looks_like_a_suffix_keeps_its_own_bytes():
    parts = [("report.pdf", b"A"), ("report.pdf", b"BB"), ("report.1.pdf", b"CCC")]
    with _serve(parts) as srv:
        got = _contents(_session(srv))
    assert sorted(v[2] for v in got.values()) == [b"A", b"BB", b"CCC"]
    assert got["report.1.pdf"][2] == b"CCC"  # the attachment that carries that name
    assert all(listed == stat == len(data) for listed, stat, data in got.values())


def test_edge_names_without_extension_and_unnamed_parts_are_disambiguated():
    parts = [("README", b"one"), ("README", b"two"), (None, b"x"), (None, b"yy")]
    with _serve(parts) as srv:
        got = _contents(_session(srv))
    assert got["README"][2] == b"one" and got["README.1"][2] == b"two"
    assert got["attachment.pdf"][2] == b"x" and got["attachment.1.pdf"][2] == b"yy"
