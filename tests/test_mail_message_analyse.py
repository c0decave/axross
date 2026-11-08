"""core.mail_message (.eml and Outlook .msg) and core.mail_analyse."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cfb_writer  # noqa: E402

from core import cfb  # noqa: E402
from core.mail_analyse import analyse  # noqa: E402
from core.mail_message import parse_any, parse_eml, parse_msg  # noqa: E402

PHISH = b"""Received: from mx.victim.example (mx.victim.example [192.0.2.25])
\tby inbox.victim.example with ESMTPS; Tue, 04 Nov 2026 10:00:05 +0000
Received: from evil-host.example (unknown [198.51.100.7])
\tby mx.victim.example with ESMTP; Tue, 04 Nov 2026 10:00:00 +0000
Authentication-Results: mx.victim.example; spf=fail smtp.mailfrom=bank.example;
 dkim=none; dmarc=fail header.from=bank.example
DKIM-Signature: v=1; a=rsa-sha256; d=evil-host.example; s=x; b=abc
From: "support@bank.example" <alerts@bank-security.example>
Reply-To: collect@elsewhere.example
To: you@victim.example
Subject: Your account
Date: Tue, 04 Nov 2026 09:59:58 +0000
Message-ID: <1@evil-host.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset=utf-8

<p>Log in at <a href="http://203.0.113.9/login">https://www.bank.example/login</a>
or <a href='https://bit.ly/x'>here</a>.</p>
--b1
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--b1--
"""

CLEAN = b"""Received: from mail.example.org (mail.example.org [192.0.2.1])
\tby mx.example.net; Tue, 04 Nov 2026 10:00:00 +0000
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org;
 dmarc=pass
DKIM-Signature: v=1; d=example.org; s=s1; b=abc
From: Alice <alice@example.org>
To: bob@example.net
Subject: Lunch
Date: Tue, 04 Nov 2026 09:59:00 +0000
Content-Type: text/plain; charset=utf-8

See https://www.example.org/menu - Thursday?
"""


def _areas(report, severity):
    return [(f.area, f.text) for f in report.findings if f.severity == severity]


def test_happy_an_eml_parses_with_every_header_and_attachment():
    m = parse_eml(PHISH, "phish.eml")
    assert m.subject == "Your account" and m.message_id == "<1@evil-host.example>"
    assert len(m.header_all("Received")) == 2
    assert m.reply_to == ["collect@elsewhere.example"]
    assert [a.name for a in m.attachments] == ["invoice.pdf.exe"]
    assert m.attachments[0].data.startswith(b"MZ")
    assert "Log in" in m.html and m.date.year == 2026


def test_happy_a_phishing_message_is_named_for_what_it_is():
    report = analyse(parse_eml(PHISH))
    high = " | ".join(t for _a, t in _areas(report, "high"))
    assert "SPF fail" in high and "DMARC fail" in high
    assert "the From name shows an address at bank.example" in high
    assert "the text shows www.bank.example, the link leads to 203.0.113.9" in high
    assert "invoice.pdf.exe: a double extension" in high
    assert "invoice.pdf.exe: a program or script" in high
    warn = " | ".join(t for _a, t in _areas(report, "warn"))
    assert "replies go to elsewhere.example" in warn
    assert "DKIM signed by evil-host.example" in warn
    assert "a URL shortener" in warn
    assert [h.from_host for h in report.hops] == ["evil-host.example", "mx.victim.example"]
    assert report.hops[0].from_ip == "198.51.100.7" and report.hops[1].delay_s == 5
    assert report.score >= 80
    assert report.to_dict()["score"] == report.score


def test_happy_a_clean_message_has_no_warnings():
    report = analyse(parse_eml(CLEAN))
    assert _areas(report, "high") == [] and _areas(report, "warn") == []
    assert report.auth == {"spf": ["pass"], "dkim": ["pass"], "dmarc": ["pass"]}
    assert [link.host for link in report.links] == ["www.example.org"]


def test_edge_headers_cannot_inject_lines_or_control_characters():
    m = parse_eml(b"Subject: a\x07b\x1b[31m\r\nFrom: x@y\r\n\r\nbody")
    assert "\x07" not in m.subject and "\x1b" not in m.subject


def test_happy_an_outlook_msg_parses():
    headers = ("Received: from a.example (a.example [192.0.2.5]) by b.example; Tue, 04 Nov 2026 10:00:00 +0000\r\n"
               "Authentication-Results: b.example; spf=pass; dkim=pass; dmarc=pass\r\n"
               "Reply-To: other@else.example\r\n")
    big = os.urandom(9000)   # > the mini stream cutoff: regular sectors
    data = cfb_writer.msg_file("Quarterly report", "Carol", "carol@corp.example", "Hello Bob\r\n",
                               headers=headers, recipients=[("Bob", "bob@corp.example", 1),
                                                            ("Dan", "dan@corp.example", 2)],
                               attachments=[("report.xlsm", big), ("note.txt", b"small")])
    m = parse_any(data, "q.msg")
    assert m.kind == "msg" and m.subject == "Quarterly report"
    assert m.from_ == "Carol <carol@corp.example>"
    assert m.to == ["Bob <bob@corp.example>"] and m.cc == ["Dan <dan@corp.example>"]
    assert m.text == "Hello Bob\r\n"
    assert [(a.name, a.data) for a in m.attachments] == [("report.xlsm", big), ("note.txt", b"small")]
    assert m.header_all("Received") and m.reply_to == ["other@else.example"]
    report = analyse(m)
    assert any("report.xlsm: an Office file with macros" in f.text for f in report.findings)
    assert any("replies go to else.example" in f.text for f in report.findings)


def test_sad_broken_compound_files_are_refused_not_looped():
    data = bytearray(cfb_writer.msg_file("s", "a", "a@b", "x"))
    with pytest.raises(cfb.CfbError):
        cfb.CompoundFile(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100)
    # a FAT that points the directory chain at itself
    first_dir = struct.unpack_from("<I", data, 0x30)[0]
    fat_sector = struct.unpack_from("<I", data, 0x4C)[0]
    off = (fat_sector + 1) * 512 + first_dir * 4
    data[off:off + 4] = struct.pack("<I", first_dir)
    with pytest.raises(cfb.CfbError, match="loop"):
        parse_msg(bytes(data))
    with pytest.raises(cfb.CfbError):
        cfb.CompoundFile(b"not a compound file at all" * 30)


# --- mail projects ---------------------------------------------------------------------

def test_happy_a_project_imports_every_kind_and_dedupes(tmp_path):
    import mailbox

    from core.mail_project import MailProject

    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "phish.eml").write_bytes(PHISH)
    (src / "sub" / "q.msg").write_bytes(cfb_writer.msg_file("Q", "Carol", "c@corp.example", "hi"))
    box = mailbox.mbox(str(src / "archive.mbox"))
    box.add(CLEAN)
    box.add(PHISH)                       # the same message again: one in the project
    box.flush()
    md = mailbox.Maildir(str(src / "Maildir"))
    md.add(CLEAN.replace(b"Lunch", b"Dinner"))
    md.flush()
    (src / "notes.txt").write_text("not mail")
    os.symlink("/etc", src / "escape")   # never followed
    with MailProject(tmp_path / "proj") as p:
        r = p.import_paths([str(src)])
        assert (r.added, r.known, r.errors) == (4, 1, []), r
        rows = p.messages()
        assert rows[0]["subject"] == "Your account" and rows[0]["high"] >= 4
        assert {row["subject"] for row in rows} == {"Your account", "Q", "Lunch", "Dinner"}
        assert p.messages(search="Carol")[0]["subject"] == "Q"
        sha = rows[0]["sha256"]
        assert p.report(sha)["score"] == rows[0]["score"]
        assert (tmp_path / "proj" / "messages" / f"{sha}.eml").read_bytes() == PHISH
        assert p.message(sha).subject == "Your account"
        again = p.import_paths([str(src / "phish.eml")])
        assert (again.added, again.known) == (0, 1)
    assert (tmp_path / "proj" / "PROJECT.md").exists()
    assert "Your account" in (tmp_path / "proj" / "index.csv").read_text()


def test_happy_a_project_imports_from_a_mail_backend(tmp_path):
    from core.mail_project import MailProject
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    ram.mkdir("/INBOX")
    with ram.open_write("/INBOX/1.eml") as f:
        f.write(CLEAN)
    ram.mkdir("/INBOX/Archive")
    with ram.open_write("/INBOX/Archive/2.eml") as f:
        f.write(PHISH)
    with MailProject(tmp_path / "proj") as p:
        r = p.import_backend(ram, "/INBOX")
        assert (r.added, r.errors) == (2, [])
        assert any(row["source"].endswith("/INBOX/Archive/2.eml") for row in p.messages())


def test_sad_a_broken_message_does_not_end_the_import_and_csv_is_safe(tmp_path):
    from core.mail_project import MailProject

    (tmp_path / "bad.msg").write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 600)
    (tmp_path / "formula.eml").write_bytes(b"Subject: =HYPERLINK(\"http://x\")\r\nFrom: a@b\r\n\r\nx")
    with MailProject(tmp_path / "proj") as p:
        r = p.import_paths([str(tmp_path / "bad.msg"), str(tmp_path / "formula.eml")])
        assert r.added == 1 and len(r.errors) == 1 and "bad.msg" in r.errors[0]
    assert "'=HYPERLINK" in (tmp_path / "proj" / "index.csv").read_text()
    with pytest.raises(ValueError):
        MailProject(tmp_path / "proj").report("../../etc/passwd")


def test_sad_a_right_to_left_override_in_an_attachment_name_is_named():
    from core.mail_message import Attachment, MailMessage

    m = MailMessage(attachments=[Attachment("invoice\u202efdp.exe", "application/pdf", 2, "0" * 64, b"MZ")])
    assert any("right-to-left override" in f.text for f in analyse(m).findings)


def _msg_with(recipients, root_props: bytes = b"", html: bytes = b""):
    tree = {"__substg1.0_0037001F": cfb_writer.unicode("s"),
            "__substg1.0_1000001F": cfb_writer.unicode("x"),
            "__properties_version1.0": b"\0" * 32 + root_props}
    if html:
        tree["__substg1.0_10130102"] = html
    for i, (name, addr, rtype) in enumerate(recipients):
        tree[f"__recip_version1.0_#{i:08X}"] = {
            "__substg1.0_3001001F": cfb_writer.unicode(name), "__substg1.0_39FE001F": cfb_writer.unicode(addr),
            "__properties_version1.0": b"\0" * 8 + struct.pack("<IIQ", (0x0C15 << 16) | 0x0003, 0, rtype)}
    return cfb_writer.build(tree)


def test_sad_msg_bcc_recipients_are_not_shown_as_to():
    """Every recipient that was not Cc (PR_RECIPIENT_TYPE 2) was listed as
    To - a Bcc (3) recipient of a sent .msg showed as an open To. Bcc is
    its own list now; the flag bits above the type do not change it."""
    m = parse_msg(_msg_with([("Bob", "bob@corp.example", 1), ("Dan", "dan@corp.example", 2),
                             ("Eve", "eve@corp.example", 3), ("Ann", "ann@corp.example", 0x10000001)]))
    assert m.to == ["Bob <bob@corp.example>", "Ann <ann@corp.example>"]
    assert m.cc == ["Dan <dan@corp.example>"] and m.bcc == ["Eve <eve@corp.example>"]
    assert m.summary()["bcc"] == ["Eve <eve@corp.example>"]
    assert parse_eml(b"Bcc: Eve <eve@corp.example>\r\nTo: bob@corp.example\r\n\r\nx").bcc == [
        "Eve <eve@corp.example>"]


def test_sad_msg_html_body_is_read_in_its_codepage():
    """A .msg's HTML body (bytes) was read as UTF-8 whatever its code page:
    a cp1252 body lost every umlaut. PR_INTERNET_CPID names it now."""
    cpid = struct.pack("<IIQ", (0x3FDE << 16) | 0x0003, 0, 1252)
    m = parse_msg(_msg_with([], cpid, "<p>Grüße, café</p>".encode("cp1252")))
    assert m.html == "<p>Grüße, café</p>"
    assert parse_msg(_msg_with([], b"", "<p>Grüße</p>".encode())).html == "<p>Grüße</p>"
