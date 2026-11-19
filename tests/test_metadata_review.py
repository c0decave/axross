"""Remove Metadata review (2026-11-19): what survived while the result said
"cleaned", "unchanged" or "nothing left". Each test names what was measured
before its fix."""

from __future__ import annotations

import os
import stat
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import metadata_testkit as K  # noqa: E402

from core import metadata_tools as MT  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FS = LocalFS()


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(home / "ops.jsonl"))
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _has(path: Path, marker: bytes) -> bool:
    return marker in K.plain(path)


# -- 1. a folder: what was not looked at is said, never "done" ---------------------

def _tree(root: Path) -> Path:
    (root / "visible.jpg").write_bytes(K.jpeg_bytes())
    (root / ".hidden.jpg").write_bytes(K.jpeg_bytes())
    (root / ".hiddendir").mkdir()
    (root / ".hiddendir" / "inside.jpg").write_bytes(K.jpeg_bytes())
    (root / "iphone.heic").write_bytes(b"ftypheic SECRETMAKE")
    (root / "scan.dng").write_bytes(b"II*\x00 SECRETMAKE")
    (root / "notes.txt").write_text("plain text: no metadata to speak of")
    deep = root
    for i in range(10):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "deep.jpg").write_bytes(K.jpeg_bytes())
    locked = root / "locked"
    locked.mkdir()
    (locked / "inlocked.jpg").write_bytes(K.jpeg_bytes())
    os.chmod(locked, 0)
    return locked


def test_sad_a_folder_cleans_hidden_files_and_says_what_it_left(tmp_path):
    """Measured before: Remove Metadata on a folder with Include subfolders
    cleaned visible.jpg alone and said "Metadata removed from 1 file(s)" -
    .hidden.jpg, a hidden folder, a folder it could not read, one deeper than
    8 levels and an iPhone HEIC kept their GPS without a word. Hidden files
    are cleaned now; the rest is named in the result (skip_notes)."""
    root = tmp_path / "photos"
    root.mkdir()
    locked = _tree(root)
    try:
        batch = MT.remove_folder(FS, str(root), recursive=True)
    finally:
        os.chmod(locked, 0o755)
    assert not _has(root / "visible.jpg", b"SECRET")
    assert not _has(root / ".hidden.jpg", b"SECRET")
    assert not _has(root / ".hiddendir" / "inside.jpg", b"SECRET")
    skips = MT.skip_notes(batch)
    kinds = {s.kind for s in skips}
    assert kinds == {"unreadable", "too_deep", "unsupported"}
    unsupported = next(s for s in skips if s.kind == "unsupported")
    assert unsupported.count == 2
    assert sorted(os.path.basename(p) for p in unsupported.paths) == ["iphone.heic", "scan.dng"]
    assert next(s for s in skips if s.kind == "unreadable").paths == [str(locked)]


def test_edge_without_subfolders_the_subfolders_are_said_to_be_left_out(tmp_path):
    root = tmp_path / "photos"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.jpg").write_bytes(K.jpeg_bytes())
    (root / "b.jpg").write_bytes(K.jpeg_bytes())
    batch = MT.remove_folder(FS, str(root), recursive=False)
    assert [s.kind for s in MT.skip_notes(batch)] == ["subfolders"]
    assert _has(root / "sub" / "a.jpg", b"SECRET")


def test_happy_a_folder_with_nothing_left_out_has_no_notes(tmp_path):
    root = tmp_path / "photos"
    root.mkdir()
    (root / "a.jpg").write_bytes(K.jpeg_bytes())
    (root / "readme.txt").write_text("x")
    assert MT.skip_notes(MT.remove_folder(FS, str(root), recursive=True)) == []


def test_sad_the_dialog_does_not_report_a_folder_as_done_when_files_were_left(tmp_path):
    import time

    from PyQt6.QtWidgets import QApplication

    from ui.metadata_dialog import MetadataDialog

    app = QApplication.instance() or QApplication([])
    root = tmp_path / "photos"
    root.mkdir()
    locked = _tree(root)
    try:
        dialog = MetadataDialog(FS, [(str(root), True)], action="remove", recursive=True)
        dialog.start()
        end = time.monotonic() + 30
        while (dialog.job.running or not dialog._first_scan_done) and time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        scan_text = dialog.status_label.text()
        dialog.remove()
        while dialog.job.running and time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        while dialog.job.running and time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        for _ in range(5):
            app.processEvents()
        while dialog.job.running and time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        done_text = dialog.status_label.text()
        dialog.close()
        dialog.deleteLater()
    finally:
        os.chmod(locked, 0o755)
    for text in (scan_text, done_text):
        assert "not supported" in text, text
        assert "could not be read" in text, text
        assert "deeper than" in text, text
    assert "Metadata removed from 3 files" in done_text, done_text


# -- 2. PDF: XMP and PieceInfo on images and forms -----------------------------------

def _xmp(name: bytes) -> bytes:
    return (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
            b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description '
            b'rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator><rdf:Seq>'
            b"<rdf:li>" + name + b"</rdf:li></rdf:Seq></dc:creator></rdf:Description>"
            b"</rdf:RDF></x:xmpmeta>")


def _stream(head: bytes, data: bytes) -> bytes:
    return b"<< " + head + b" /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def _pdf(objs, trailer=b"") -> bytes:
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += (b"trailer\n<< /Size %d /Root 1 0 R " % (len(objs) + 1) + trailer
            + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref)
    return bytes(out)


def _pdf_bytes(path: Path) -> bytes:
    """The file and every stream decompressed (a marker inside a Flate
    stream counts)."""
    import zlib

    from pypdf import PdfReader

    raw = path.read_bytes()
    out = [raw]
    reader = PdfReader(str(path), strict=False)
    for idnum in range(1, len(reader.xref_objStm) + sum(len(v) for v in reader.xref.values()) + 64):
        try:
            obj = reader.get_object(idnum)
        except Exception:  # noqa: BLE001 - not every number is an object
            continue
        data = getattr(obj, "get_data", None)
        if callable(data):
            try:
                out.append(data())
            except Exception:  # noqa: BLE001
                pass
    try:
        out.append(zlib.decompress(raw))
    except zlib.error:
        pass
    return b"".join(out)


def _xobject_pdf() -> bytes:
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R "
        b"/Resources << /XObject << /Im1 5 0 R /Fx1 7 0 R >> >> >>",
        _stream(b"", b"q 64 0 0 48 10 10 cm /Im1 Do Q q /Fx1 Do Q"),
        _stream(b"/Type /XObject /Subtype /Image /Width 64 /Height 48 /ColorSpace /DeviceRGB "
                b"/BitsPerComponent 8 /Filter /DCTDecode /Metadata 6 0 R",
                K.jpeg_bytes(everything=False)),
        _stream(b"/Type /Metadata /Subtype /XML", _xmp(b"MARKIMAGEXMP")),
        _stream(b"/Type /XObject /Subtype /Form /BBox [0 0 5 5] /Metadata 8 0 R "
                b"/PieceInfo << /Illustrator << /Private (MARKPIECEFORM) >> >>",
                b"0 0 1 rg 0 0 5 5 re f"),
        _stream(b"/Type /Metadata /Subtype /XML", _xmp(b"MARKFORMXMP")),
    ])


def test_sad_pdf_xmp_on_images_and_forms_is_listed_and_removed(tmp_path):
    """Measured before: XMP on an image or form XObject and a form's
    PieceInfo were neither listed nor removed - with nothing else in the
    file the result was "unchanged" and the file stayed as it was."""
    pytest.importorskip("pypdf")
    path = tmp_path / "x.pdf"
    path.write_bytes(_xobject_pdf())
    report = MT.read_metadata(FS, str(path))
    assert report.removable >= 3, report.fields
    result = MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY)
    assert result.status == MT.CLEANED, result.error
    blob = _pdf_bytes(Path(result.output))
    for marker in (b"MARKIMAGEXMP", b"MARKFORMXMP", b"MARKPIECEFORM"):
        assert marker not in blob, marker
    assert MT.read_metadata(FS, result.output).removable == 0


# -- 4. PDF: earlier revisions and objects nothing uses -------------------------------

def _two_revisions() -> bytes:
    base = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        _stream(b"/Type /Metadata /Subtype /XML", _xmp(b"MARKOLDREVISION")),
    ])
    first = int(base[base.rfind(b"startxref") + 10:].split()[0])
    out = bytearray(base)
    offset = len(out)
    out += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    xref = len(out)
    out += b"xref\n1 1\n%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size 5 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (first, xref)
    return bytes(out)


def test_sad_an_earlier_pdf_revision_is_listed_and_dropped(tmp_path):
    """Measured before: a PDF whose author is left only in an earlier
    revision (an incremental save that "removed" it) read as empty and was
    left "unchanged" - the author still in the file."""
    pytest.importorskip("pypdf")
    path = tmp_path / "old.pdf"
    path.write_bytes(_two_revisions())
    assert MT.read_metadata(FS, str(path)).removable >= 1
    result = MT.remove_metadata(FS, str(path), mode=MT.MODE_IN_PLACE)
    assert result.status == MT.CLEANED, result.error
    assert b"MARKOLDREVISION" not in _pdf_bytes(path)
    assert path.read_bytes().count(b"startxref") == 1
    assert MT.read_metadata(FS, str(path)).removable == 0


def test_sad_an_object_nothing_uses_is_listed_and_dropped(tmp_path):
    pytest.importorskip("pypdf")
    path = tmp_path / "orphan.pdf"
    path.write_bytes(_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Author (MARKORPHANAUTHOR) >>",
    ]))
    assert MT.read_metadata(FS, str(path)).removable >= 1
    result = MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY)
    assert result.status == MT.CLEANED, result.error
    assert b"MARKORPHANAUTHOR" not in _pdf_bytes(Path(result.output))


def test_happy_a_clean_pdf_is_still_unchanged(tmp_path):
    pytest.importorskip("pypdf")
    path = tmp_path / "plain.pdf"
    path.write_bytes(_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ]))
    assert MT.read_metadata(FS, str(path)).removable == 0
    assert MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY).status == MT.UNCHANGED


# -- 5. / 6. Office: the zip's comment and extra fields, more property parts ----------

def _zip(path: Path, members: dict[str, bytes], *, comment: bytes = b"",
         extra: bytes = b"") -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 3, 4, 17, 42, 58))
            info.compress_type = zipfile.ZIP_STORED if name == "mimetype" else zipfile.ZIP_DEFLATED
            if extra and name != "mimetype":
                info.extra = extra
            zf.writestr(info, data)
        zf.comment = comment
    return path


_CT = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
       b'content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
_EMPTY_CORE = (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.'
               b'openxmlformats.org/package/2006/metadata/core-properties"/>')


def _core(author: bytes) -> bytes:
    return (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
            b'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b"<dc:creator>" + author + b"</dc:creator></cp:coreProperties>")


def _rels(*entries: tuple[str, str]) -> bytes:
    rows = b"".join(
        b'<Relationship Id="r%d" Type="%s" Target="%s"/>' % (n, t.encode(), target.encode())
        for n, (t, target) in enumerate(entries))
    return (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
            b'package/2006/relationships">' + rows + b"</Relationships>")


_UID_GID = b"ux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00"  # uid/gid 1000


def test_sad_the_zip_comment_and_extra_fields_are_listed_and_removed(tmp_path):
    """Measured before: a docx whose properties were already empty but whose
    zip comment held C:\\Users\\<name>, and an xlsx without docProps whose
    entries carried the owner's uid/gid, were "unchanged" - both kept."""
    docx = _zip(tmp_path / "a.docx", {
        "[Content_Types].xml": _CT, "_rels/.rels": _rels(), "docProps/core.xml": _EMPTY_CORE,
        "word/document.xml": b"<w:document/>"}, comment=b"C:\\Users\\MARKWINUSER\\a.docx")
    xlsx = _zip(tmp_path / "b.xlsx", {
        "[Content_Types].xml": _CT, "xl/workbook.xml": b"<workbook/>"}, extra=_UID_GID)
    for path in (docx, xlsx):
        assert MT.read_metadata(FS, str(path)).removable >= 1, path
        result = MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY)
        assert result.status == MT.CLEANED, (path, result.error)
        with zipfile.ZipFile(result.output) as zf:
            assert zf.comment == b""
            assert all(not i.extra for i in zf.infolist())
            assert zf.testzip() is None
        assert MT.read_metadata(FS, result.output).removable == 0


def test_sad_an_odf_object_s_own_meta_is_removed(tmp_path):
    """Measured before: odt kept "Object 1/meta.xml" (a chart's own
    properties, with its author) while reporting "cleaned"."""
    meta = (b'<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:'
            b'opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:'
            b'meta:1.0" office:version="1.3"><office:meta><meta:initial-creator>%s'
            b"</meta:initial-creator></office:meta></office:document-meta>")
    path = _zip(tmp_path / "c.odt", {
        "mimetype": b"application/vnd.oasis.opendocument.text",
        "content.xml": b"<office:document-content/>",
        "meta.xml": meta % b"MARKTOPAUTHOR",
        "Object 1/content.xml": b"<chart/>",
        "Object 1/meta.xml": meta % b"MARKOBJECTAUTHOR",
    })
    result = MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY)
    assert result.status == MT.CLEANED, result.error
    assert not _has(Path(result.output), b"MARKOBJECTAUTHOR")
    assert not _has(Path(result.output), b"MARKTOPAUTHOR")


@pytest.mark.parametrize("variant", ["case", "strict"])
def test_sad_ooxml_property_parts_are_found_by_any_case_and_in_strict(tmp_path, variant):
    """Measured before: docProps/Core.xml named /docProps/core.xml in its
    relationship (OPC names ignore case; Office opens it), and a Strict
    document's extendedProperties part at its own path, were "unchanged"."""
    if variant == "case":
        members = {
            "[Content_Types].xml": _CT,
            "_rels/.rels": _rels(("http://schemas.openxmlformats.org/package/2006/relationships/"
                                  "metadata/core-properties", "/docProps/core.xml")),
            "docProps/Core.xml": _core(b"MARKCASEAUTHOR"),
            "word/document.xml": b"<w:document/>",
        }
        marker = b"MARKCASEAUTHOR"
    else:
        members = {
            "[Content_Types].xml": _CT,
            "_rels/.rels": _rels(("http://purl.oclc.org/ooxml/officeDocument/relationships/"
                                  "extendedProperties", "/props/app-strict.xml")),
            "props/app-strict.xml": (
                b'<?xml version="1.0"?><Properties xmlns="http://purl.oclc.org/ooxml/'
                b'officeDocument/extendedProperties"><Company>MARKSTRICTCOMPANY</Company>'
                b"</Properties>"),
            "word/document.xml": b"<w:document/>",
        }
        marker = b"MARKSTRICTCOMPANY"
    path = _zip(tmp_path / f"{variant}.docx", members)
    result = MT.remove_metadata(FS, str(path), mode=MT.MODE_COPY)
    assert result.status == MT.CLEANED, result.error
    assert not _has(Path(result.output), marker)


# -- 3. the trash keeps an original as private as it was -------------------------------

@pytest.fixture
def sftp(tmp_path):
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession
    from sftp_testkit import SftpServer

    root = tmp_path / "srv"
    root.mkdir()
    server = SftpServer(str(root))
    session = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                           port=server.port, username="u"))
    (Path.home() / ".ssh").mkdir(exist_ok=True)
    session.connect(password="x", on_unknown_host=lambda _e: True)
    try:
        yield root, session
    finally:
        session.disconnect()
        server.close()


def _modes(folder: Path) -> dict[str, int]:
    return {p.name: stat.S_IMODE(p.stat().st_mode) for p in folder.iterdir()}


def test_sad_an_in_place_removal_on_sftp_keeps_the_original_private(sftp):
    """Measured before: on SFTP the original of a 0600 photo went into
    /.axross-trash as 0644 - with its GPS - in a 0755 folder: readable by
    every account on the server."""
    from core import trash as T

    root, session = sftp
    photo = root / "p.jpg"
    photo.write_bytes(K.jpeg_bytes())
    os.chmod(photo, 0o600)
    result = MT.remove_metadata(session, "/p.jpg", mode=MT.MODE_IN_PLACE)
    assert result.status == MT.CLEANED, result.error
    trash = root / T.TRASH_DIRNAME
    assert stat.S_IMODE(trash.stat().st_mode) == 0o700
    modes = _modes(trash)
    assert modes[result.trash_id] == 0o600
    assert all(mode & 0o077 == 0 for mode in modes.values()), modes


def test_sad_the_trash_folder_is_private_locally_and_on_sftp(sftp, tmp_path):
    from core import trash as T

    root, session = sftp
    (root / "f.txt").write_text("x")
    T.trash(session, "/f.txt")
    assert stat.S_IMODE((root / T.TRASH_DIRNAME).stat().st_mode) == 0o700
    assert all(m & 0o077 == 0 for name, m in _modes(root / T.TRASH_DIRNAME).items()
               if name.endswith(T.META_SUFFIX)), _modes(root / T.TRASH_DIRNAME)
    local = tmp_path / "l.txt"
    local.write_text("y")
    T.trash(FS, str(local))
    folder = Path(T._resolve_root(FS, None))
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_edge_an_existing_open_trash_folder_is_made_private(sftp):
    from core import trash as T

    root, session = sftp
    (root / T.TRASH_DIRNAME).mkdir(mode=0o755)
    os.chmod(root / T.TRASH_DIRNAME, 0o755)
    (root / "g.txt").write_text("x")
    T.trash(session, "/g.txt")
    assert stat.S_IMODE((root / T.TRASH_DIRNAME).stat().st_mode) == 0o700

