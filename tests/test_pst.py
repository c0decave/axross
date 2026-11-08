"""core.pst against real Outlook data files (java-libpst's test files, a
Unicode .pst and an Outlook 2013 .ost with 4 KB pages and compressed
blocks): what java-libpst's own tests state about them holds here too."""

from __future__ import annotations

import gzip
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.pst import PstError, PstFile, to_eml  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "mail"


@pytest.fixture(scope="module")
def files(tmp_path_factory):
    d = tmp_path_factory.mktemp("pst")
    out = {}
    for name in ("dist-list.pst", "example-2013.ost"):
        (d / name).write_bytes(gzip.decompress((FIX / f"{name}.gz").read_bytes()))
        out[name] = d / name
    return out


def test_happy_a_unicode_pst(files):
    with PstFile(files["dist-list.pst"]) as p:
        assert p.version == 23 and p.crypt == 1           # compressible encoding, decoded
        folders = set(p.folders().values())
        assert {"Top of Personal Folders/Inbox", "Top of Personal Folders/Contacts",
                "Top of Personal Folders/Calendar"} <= folders
        msgs = {m.nid: m for m in p.messages()}
        assert msgs[2097188].subject == "test dist list" and msgs[2097188].folder.endswith("Contacts")
        appointment = msgs[2097348]
        assert appointment.subject == "Test appointment" and len(appointment.attachments) == 2


def test_happy_an_outlook_2013_ost(files):
    with PstFile(files["example-2013.ost"]) as p:
        assert p.version == 36 and p.page == 4096
        inbox = [m for m in p.messages() if m.folder.endswith("IPM_SUBTREE/Inbox")]
        assert len(inbox) == 2                               # java-libpst: inbox.getContentCount() == 2
        msg = p.message(2097284)
        html = msg.props[0x1013]
        html = html.decode("utf-8") if isinstance(html, bytes) else html
        assert ("This is an e-mail message sent automatically by Microsoft Outlook while testing the "
                "settings for your account.") in html
        assert msg.recipients and "@" in str(msg.recipients[0].get(0x39FE) or msg.recipients[0].get(0x3003))


def test_happy_a_message_becomes_an_eml_with_its_transport_headers(files):
    from core.mail_analyse import analyse
    from core.mail_message import parse_eml

    with PstFile(files["example-2013.ost"]) as p:
        eml = to_eml(p.message(2097284))
    m = parse_eml(eml)
    assert m.subject == "Microsoft Outlook Test Message"
    assert m.header_all("Received") and m.header("Return-Path")
    assert "testing the settings" in m.html
    assert analyse(m).hops                                   # the real Received chain is there


def test_happy_a_mail_project_imports_pst_and_ost(files, tmp_path):
    from core.mail_project import MailProject

    with MailProject(tmp_path / "proj") as proj:
        r = proj.import_paths([str(files["dist-list.pst"]), str(files["example-2013.ost"])])
        assert r.added >= 6 and not r.errors, r
        subjects = {row["subject"] for row in proj.messages()}
        assert {"Microsoft Outlook Test Message", "Test 2", "test dist list"} <= subjects
        assert any("#Root - Mailbox/IPM_SUBTREE/Inbox/0x200084" in row["source"] for row in proj.messages())


def test_sad_broken_and_unsupported_files_are_refused(files, tmp_path):
    bad = tmp_path / "bad.pst"
    bad.write_bytes(b"not a pst" * 100)
    with pytest.raises(PstError, match="not an Outlook"):
        PstFile(bad)
    data = bytearray(files["dist-list.pst"].read_bytes())
    struct.pack_into("<H", data, 10, 14)                     # an ANSI file
    (tmp_path / "ansi.pst").write_bytes(bytes(data))
    with pytest.raises(PstError, match="ANSI"):
        PstFile(tmp_path / "ansi.pst")
    data = bytearray(files["dist-list.pst"].read_bytes())
    data[513] = 2                                            # the cyclic encoding
    (tmp_path / "cyclic.pst").write_bytes(bytes(data))
    with pytest.raises(PstError, match="cyclic"):
        PstFile(tmp_path / "cyclic.pst")
    data = bytearray(files["dist-list.pst"].read_bytes())
    nbt_ib = struct.unpack_from("<Q", data, 224)[0]
    struct.pack_into("<Q", data, 224, len(data) + 4096)      # the node tree points outside the file
    (tmp_path / "trunc.pst").write_bytes(bytes(data))
    with pytest.raises(PstError, match="outside the file"):
        PstFile(tmp_path / "trunc.pst")
    assert nbt_ib


def _html_message():
    from core.pst import PstMessage

    return PstMessage("Inbox", 0x24, {0x0037: "Report", 0x1000: "see html", 0x1013: b"<p>hi</p>",
                                      0x0C1A: "Bob", 0x5D01: "bob@example.net"},
                      attachments=[{0x3701: b"data", 0x3707: "a.bin"}])


def test_sad_a_multipart_message_rebuilds_to_the_same_bytes(tmp_path):
    """to_eml let the email package draw a random MIME boundary, so the
    same PST message rebuilt twice had other bytes and another SHA-256 - a
    second import of a PST added every multipart message again. The
    boundary is derived from the PST path, folder and node id now."""
    from core.mail_project import MailProject

    m = _html_message()
    a, b = to_eml(m, "/x/archive.pst"), to_eml(m, "/x/archive.pst")
    assert a == b and b"multipart/alternative" in a and b"multipart/mixed" in a
    assert to_eml(m, "/y/other.pst") != a
    with MailProject(tmp_path / "proj") as project:
        label = "/x/archive.pst#Inbox/0x24"
        assert project.add_bytes(a, label) is not None
        assert project.add_bytes(b, label) is None
        assert len(project.messages()) == 1


def test_edge_a_boundary_that_occurs_in_the_content_is_changed():
    """The derived boundary must never be a line of the message's own text."""
    import hashlib

    from core.mail_message import parse_eml

    m = _html_message()
    digest = hashlib.sha256(f"\0{m.folder}\0{m.nid}".encode()).hexdigest()[:32]
    m.props[0x1000] = f"--=_axross_{digest}_0\nand --=_axross_{digest}_1"
    eml = to_eml(m)
    assert eml == to_eml(m)
    parsed = parse_eml(eml)
    assert parsed.text.startswith(f"--=_axross_{digest}_0") and parsed.html == "<p>hi</p>\n"
    assert [a.name for a in parsed.attachments] == ["a.bin"]


def test_sad_the_html_body_is_read_in_the_message_codepage():
    """The HTML body (PR_HTML, bytes) was always read as UTF-8: a cp1252
    body showed "Grüße" as "Gr\\ufffd\\ufffde". PR_INTERNET_CPID (else
    PR_MESSAGE_CODEPAGE) names its code page now."""
    from core.mail_message import parse_eml
    from core.pst import PstMessage

    for props in ({0x3FDE: 1252}, {0x3FFD: 1252}, {0x3FDE: 28592, 0x3FFD: 1252}):
        html = "<p>Grüße, café</p>" if 0x3FDE not in props or props[0x3FDE] == 1252 else "<p>Łódź</p>"
        codec = "cp1252" if html.startswith("<p>G") else "iso-8859-2"
        m = PstMessage("Inbox", 0x24, {0x0037: "s", 0x1013: html.encode(codec), **props})
        assert parse_eml(to_eml(m)).html.strip() == html, props
    utf8 = PstMessage("Inbox", 0x24, {0x0037: "s", 0x1013: "<p>Grüße</p>".encode()})   # no code page
    assert parse_eml(to_eml(utf8)).html.strip() == "<p>Grüße</p>"
