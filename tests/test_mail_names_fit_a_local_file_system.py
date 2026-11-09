"""Mail message and attachment names fit a local file system.

Round 5 (repro_mail_name_bytes.py): the names were capped in
*characters* - IMAP 80, POP3 120, Exchange the ItemId (~150) plus 120 -
so a CJK or emoji subject (3-4 bytes a character), or any long subject
behind an EWS ItemId, gave a name over NAME_MAX (255 bytes): copying the
message to a local folder failed with errno 36 (ENAMETOOLONG).

Now every mail backend names a message ``<id>_<subject>.eml`` in at most
core.mail_names.MAX_NAME_BYTES UTF-8 bytes, the id and extension whole.
Names that fitted are unchanged; IMAP (and POP3, see
test_pop3_reconnect_and_lost_deletes.py) still accept the name a message
had before, and a mail dock does not take a renamed message for new.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import imap_memory_server as M  # noqa: E402

from core import mail_dock as MD  # noqa: E402
from core.mail_names import MAX_NAME_BYTES, cap_bytes, cap_file_name, message_file_name  # noqa: E402

CJK = "請求書" * 40  # 120 characters, 360 bytes
EMOJI = "📦 Lieferung " * 12


def _fits_locally(tmp_path: Path, name: str) -> None:
    assert len(name.encode()) <= MAX_NAME_BYTES, name
    (tmp_path / name).write_bytes(b"x")  # no ENAMETOOLONG


def test_edge_the_cap_cuts_at_a_character_and_keeps_id_and_extension():
    assert cap_bytes("aé", 2) == "a"  # never half of "é"
    name = message_file_name("12345", CJK)
    assert name.startswith("12345_請求書") and name.endswith(".eml")
    assert len(name.encode()) <= MAX_NAME_BYTES
    assert message_file_name("7", "short subject") == "7_short subject.eml"  # unchanged
    att = cap_file_name("報告" * 100 + ".pdf")
    assert att.endswith(".pdf") and len(att.encode()) <= MAX_NAME_BYTES


@pytest.mark.parametrize("subject", [CJK, EMOJI], ids=["cjk", "emoji"])
def test_sad_an_imap_message_with_a_long_subject_can_be_copied_locally(
        monkeypatch, tmp_path, subject):
    srv = M.Server(caps=("IMAP4REV1", "UIDPLUS"))
    srv.add_box("INBOX")
    srv.boxes["INBOX"]["uidnext"] = 1234567  # a long UID
    srv.add_msg("INBOX", subject)
    s = M.session(monkeypatch, srv)
    (item,) = s.list_dir("/INBOX")
    _fits_locally(tmp_path, item.name)
    assert item.name.startswith("1234567_")
    assert s.open_read("/INBOX/" + item.name).read().startswith(b"Subject:")
    # The name the message had before (80 characters), as a bookmark or a
    # mail dock's seen-state keeps it, still names it.
    legacy = f"1234567_{subject[:80]}.eml"
    assert s.exists("/INBOX/" + legacy)


def test_sad_an_imap_attachment_with_a_long_name_keeps_its_extension(monkeypatch, tmp_path):
    long_name = "報告書" * 40 + ".pdf"
    raw = (
        "Subject: att\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        "--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/pdf\r\n"
        f"Content-Disposition: attachment; filename*=utf-8''{_pct(long_name)}\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--b--\r\n"
    ).encode()
    srv = M.Server(caps=("IMAP4REV1", "UIDPLUS"))
    srv.add_box("INBOX")
    srv.add_msg("INBOX", "att", raw=raw)
    s = M.session(monkeypatch, srv)
    (att,) = s.list_dir("/INBOX/1")
    assert att.name.endswith(".pdf")
    _fits_locally(tmp_path, att.name)
    assert s.open_read("/INBOX/1/" + att.name).read() == b"ABC"


def _pct(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


def test_sad_an_exchange_message_behind_a_long_item_id_can_be_copied_locally(tmp_path):
    EC = pytest.importorskip("core.exchange_client")
    item_id = "AAMkAGI2TG93AAA=" * 9 + "AAAAAAA="  # ~150 characters, as real ItemIds
    msg = SimpleNamespace(id=item_id, subject="Re: " + "quarterly report review " * 5, size=10,
                          datetime_received=datetime(2026, 1, 2, tzinfo=timezone.utc),
                          has_attachments=False)

    class _Query:
        def only(self, *fields):
            return self

        def __iter__(self):
            return iter([msg])

    session = object.__new__(EC.ExchangeSession)
    (item,) = session._list_messages(SimpleNamespace(all=lambda: _Query()))
    _fits_locally(tmp_path, item.name)
    # The message is found by the id in its name, whole.
    assert EC._parse_msg_segment(item.name)[0] == item_id


def test_edge_a_mail_dock_does_not_take_a_renamed_message_for_new(tmp_path):
    legacy = f"12345_{CJK[:80]}.eml"  # how IMAP named it before (250 bytes)
    current = message_file_name("12345", CJK[:80])
    assert current != legacy

    class _Backend:
        def list_dir(self, path):
            from models.file_item import FileItem

            return [FileItem(name=current, size=1, modified=datetime(2026, 1, 1))]

    state = tmp_path / "seen.json"
    state.write_text('{"seen": ["%s"]}' % legacy, encoding="utf-8")
    box = MD.Mailbox(_Backend(), "INBOX", state)
    assert box.new() == []
