"""Format-level metadata reading and removal (core.metadata_formats).

Per format: happy (everything personal found, then gone; orientation and
ICC kept; pixels identical), sad (damaged / hostile input) and edge cases.
"""

from __future__ import annotations

import io
import os
import struct
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import metadata_formats as MF  # noqa: E402
from tests import metadata_testkit as K  # noqa: E402

IMAGE_MAKERS = {
    "jpeg": K.jpeg_bytes,
    "png": K.png_bytes,
    "webp": K.webp_bytes,
    "gif": K.gif_bytes,
    "tiff": K.tiff_bytes,
}


def _open(data: bytes):
    from PIL import Image

    im = Image.open(io.BytesIO(data))
    return im


def _orientation(data: bytes):
    im = _open(data)
    if im.format == "TIFF":
        return im.tag_v2.get(274)
    return im.getexif().get(0x0112)


def _values(fields) -> str:
    return " | ".join(f"{f.group}/{f.name}={f.value}" for f in fields)


# ---------------------------------------------------------------------------
# Images - happy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", sorted(IMAGE_MAKERS))
def test_happy_image_metadata_is_listed(fmt):
    data = IMAGE_MAKERS[fmt]()
    fields, error, truncated = MF.image_fields(data)
    assert error == ""
    assert not truncated
    text = _values(fields)
    assert "SECRET" in text
    assert any(f.removable for f in fields)
    if fmt in ("jpeg", "webp"):
        assert "GPS/GPSLatitude" in text
        assert "SECRETSERIAL" in text
    if fmt in ("jpeg", "png", "webp", "gif", "tiff"):
        assert "XMP/" in text and "SECRETXMPCREATOR" in text


@pytest.mark.parametrize("fmt", sorted(IMAGE_MAKERS))
def test_happy_image_clean_removes_everything_personal_and_keeps_the_picture(fmt):
    data = IMAGE_MAKERS[fmt]()
    cleaned = MF.image_clean(data)
    assert K.MARK not in cleaned, fmt
    assert MF.pixels_equal(data, cleaned)
    im = _open(cleaned)
    im.load()  # still a valid file
    assert im.format == _open(data).format
    if fmt != "gif":
        assert _orientation(cleaned) == 6
        assert _open(cleaned).info.get("icc_profile") == K.icc_profile()
    fields, error, _ = MF.image_fields(cleaned)
    assert error == ""
    assert [f for f in fields if f.removable] == []
    kept = _values(fields)
    if fmt != "gif":
        assert "colour profile (kept)" in kept


def test_happy_jpeg_lists_gps_iptc_thumbnail_comment_and_trailer():
    fields, error, _ = MF.image_fields(K.jpeg_bytes())
    text = _values(fields)
    assert error == ""
    assert "IPTC/By-line=SECRETBYLINE" in text
    assert "IPTC/Copyright Notice=SECRETIPTCCOPYRIGHT" in text
    assert "EXIF thumbnail/embedded preview" in text
    assert "Comment/JPEG comment=SECRETCOMMENT" in text
    assert "Trailer/data after the end of the image=13 bytes" in text
    assert "APP12/Ducky" in text
    orientation = [f for f in fields if f.name == "Orientation"]
    assert orientation and not orientation[0].removable


def test_happy_png_lists_text_chunks_time_and_private_chunk():
    text = _values(MF.image_fields(K.png_bytes())[0])
    assert "PNG text/Author=SECRETAUTHOR" in text
    assert "PNG text/Comment=SECRETZTXT" in text
    assert "PNG text/Description=SECRETITXT" in text
    assert "PNG/last modified (tIME)=2026-01-02 03:04:05" in text
    assert "PNG/chunk prVt" in text


def test_happy_gif_keeps_animation_and_loop():
    data = K.gif_bytes()
    cleaned = MF.image_clean(data)
    a, b = _open(data), _open(cleaned)
    assert b.n_frames == a.n_frames == 2
    assert b.info.get("loop") == a.info.get("loop") == 0
    assert b"NETSCAPE2.0" in cleaned


def test_happy_jpeg_entropy_data_is_copied_byte_for_byte():
    data = K.jpeg_bytes()
    cleaned = MF.image_clean(data)
    # rindex: the EXIF thumbnail is a JPEG of its own, with its own SOS.
    sos = data.rindex(b"\xff\xda")
    sos_clean = cleaned.rindex(b"\xff\xda")
    eoi = data.index(b"\xff\xd9", sos) + 2
    assert cleaned[sos_clean:] == data[sos:eoi]


# ---------------------------------------------------------------------------
# Images - sad
# ---------------------------------------------------------------------------


def test_sad_jpeg_segment_length_beyond_the_end_is_an_error_not_a_crash():
    data = bytearray(K.jpeg_bytes())
    app1 = data.index(b"\xff\xe1")
    data[app1 + 2 : app1 + 4] = b"\xff\xff"
    fields, error, _ = MF.image_fields(bytes(data))
    assert "out of range" in error
    with pytest.raises(MF.FormatError):
        MF.image_clean(bytes(data))


def test_sad_truncated_jpeg_is_refused():
    data = K.jpeg_bytes(everything=False)
    with pytest.raises(MF.FormatError):
        MF.image_clean(data[: len(data) // 2])


def test_sad_png_with_an_absurd_chunk_length_is_refused_quickly():
    data = bytearray(K.png_bytes())
    data[8:12] = struct.pack(">I", 0x7FFFFFF0)
    _fields, error, _ = MF.image_fields(bytes(data))
    assert "out of range" in error
    with pytest.raises(MF.FormatError):
        MF.image_clean(bytes(data))


def test_sad_not_an_image():
    fields, error, _ = MF.image_fields(b"just some text, named photo.jpg")
    assert fields == [] and "not a supported image" in error
    with pytest.raises(MF.FormatError):
        MF.image_clean(b"just some text")


def test_sad_gif_without_trailer_and_webp_with_a_lying_chunk_size():
    gif = K.gif_bytes()
    gif = gif[: gif.rindex(b"\x3b")]
    with pytest.raises(MF.FormatError):
        MF.image_clean(gif)
    webp = bytearray(K.webp_bytes())
    webp[16:20] = struct.pack("<I", 10_000_000)
    with pytest.raises(MF.FormatError):
        MF.image_clean(bytes(webp))


def test_sad_hostile_exif_ifd_does_not_raise():
    # An IFD that claims 60000 entries and points past the end.
    tiff = b"MM\x00\x2a" + struct.pack(">I", 8) + struct.pack(">H", 60000) + b"\x00" * 20
    assert MF.exif_orientation(tiff) is None
    fields = MF._Fields()
    MF.exif_fields(b"Exif\x00\x00" + tiff, fields)  # never raises
    assert MF.exif_orientation(b"") is None
    assert MF.exif_orientation(b"Exif\x00\x00II*\x00\xff\xff\xff\xff") is None


def test_sad_jpeg_compressed_tiff_is_refused_because_it_would_be_reencoded():
    data = K.tiff_bytes(compression="jpeg")
    with pytest.raises(MF.FormatError, match="re-encode"):
        MF.image_clean(data)


def test_sad_pixel_difference_is_detected():
    a = K.jpeg_bytes(everything=False)
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (64, 48), (0, 0, 0)).save(buf, "JPEG")
    assert not MF.pixels_equal(a, buf.getvalue())
    assert not MF.pixels_equal(a, b"garbage")


# ---------------------------------------------------------------------------
# Images - edge
# ---------------------------------------------------------------------------


def test_edge_bare_jpeg_has_nothing_removable_and_cleans_to_the_same_picture():
    data = K.jpeg_bytes(everything=False)
    fields, error, _ = MF.image_fields(data)
    assert error == "" and not any(f.removable for f in fields)
    cleaned = MF.image_clean(data)
    assert MF.pixels_equal(data, cleaned)
    assert b"Exif" not in cleaned


def test_edge_without_orientation_no_exif_is_written():
    for maker in (K.jpeg_bytes, K.png_bytes, K.webp_bytes):
        cleaned = MF.image_clean(maker(orientation=None))
        assert _orientation(cleaned) is None
        assert K.MARK not in cleaned


def test_edge_progressive_jpeg_with_fill_bytes():
    from PIL import Image

    buf = io.BytesIO()
    K._pixels().save(
        buf,
        "JPEG",
        progressive=True,
        comment=b"SECRETPROGRESSIVE",
        exif=b"Exif\x00\x00" + K.exif_tiff(3, thumbnail=False),
    )
    data = buf.getvalue()
    assert data.count(b"\xff\xda") > 1
    # A fill byte before a marker is legal.
    pos = data.index(b"\xff\xdb")
    data = data[:pos] + b"\xff" + data[pos:]
    cleaned = MF.image_clean(data)
    assert K.MARK not in cleaned
    assert MF.pixels_equal(data, cleaned)
    assert Image.open(io.BytesIO(cleaned)).getexif().get(0x0112) == 3


def test_edge_lossy_webp_and_simple_webp():
    data = K.webp_bytes(lossless=False)
    cleaned = MF.image_clean(data)
    assert K.MARK not in cleaned and MF.pixels_equal(data, cleaned)
    buf = io.BytesIO()
    K._pixels().save(buf, "WEBP", lossless=True)
    simple = buf.getvalue()
    assert MF.image_clean(simple) == simple


def test_edge_values_are_bounded_and_control_characters_removed():
    assert MF.bounded("a‮b\x00c") == "a b c"
    long = MF.bounded("x" * 10_000)
    assert len(long) < MF.MAX_VALUE_CHARS + 30 and "10000 chars" in long
    assert MF.bounded(bytes(range(256)) * 10) == "<binary, 2560 bytes>"
    assert MF.bounded(tuple(range(100))) == "<100 values>"


def test_edge_huge_comment_is_shown_truncated():
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (8, 8)).save(buf, "JPEG", comment=b"SECRET" + b"A" * 60000)
    fields, error, _ = MF.image_fields(buf.getvalue())
    comment = [f for f in fields if f.group == "Comment"][0]
    assert len(comment.value) < 1000


def test_edge_field_count_is_capped():
    fields = MF._Fields()
    for n in range(MF.MAX_FIELDS + 10):
        fields.add("g", str(n), "v")
    assert len(fields) == MF.MAX_FIELDS and fields.truncated


def test_edge_minimal_exif_round_trips():
    for value in range(1, 9):
        assert MF.exif_orientation(MF.minimal_exif(value)) == value


def test_edge_kind_by_extension():
    assert MF.kind_of("a.JPG") == MF.IMAGE
    assert MF.kind_of("report.docx") == MF.OFFICE
    assert MF.kind_of("x.ods") == MF.OFFICE
    assert MF.kind_of("a.pdf") == MF.PDF
    assert MF.kind_of("-song.mp3") == MF.AUDIO
    assert MF.kind_of("clip.mkv") == MF.VIDEO
    assert MF.kind_of(".jpg") is None
    assert MF.kind_of("notes.txt") is None


# ---------------------------------------------------------------------------
# Office
# ---------------------------------------------------------------------------


def _entries(path: Path) -> list[tuple[str, int, bytes]]:
    with zipfile.ZipFile(path) as zf:
        return [(i.filename, i.compress_type, zf.read(i)) for i in zf.infolist()]


def test_happy_docx_fields_and_clean(tmp_path):
    src = K.write(tmp_path / "report.docx", K.docx_bytes())
    fields, error, _ = MF.office_fields(str(src))
    text = _values(fields)
    assert error == ""
    for marker in (
        "SECRETTITLE",
        "SECRETCREATOR",
        "SECRETLASTMODIFIED",
        "SECRETAPP",
        "SECRETCOMPANY",
        "Client=SECRETCLIENT",
    ):
        assert marker in text
    dst = tmp_path / "clean.docx"
    MF.office_clean(str(src), str(dst))
    before, after = _entries(src), _entries(dst)
    assert [e[0] for e in before] == [e[0] for e in after]
    assert [e[1] for e in before] == [e[1] for e in after]
    for (name, _c, a), (_n, _c2, b) in zip(before, after):
        if not name.startswith("docProps/"):
            assert a == b, name
        assert K.MARK not in b
    assert MF.office_fields(str(dst))[0] == []


def test_happy_odt_keeps_mimetype_first_and_stored(tmp_path):
    src = K.write(tmp_path / "letter.odt", K.odt_bytes())
    text = _values(MF.office_fields(str(src))[0])
    assert "Project=SECRETPROJECT" in text and "meta:initial-creator=SECRETINITIAL" in text
    dst = tmp_path / "clean.odt"
    MF.office_clean(str(src), str(dst))
    with zipfile.ZipFile(dst) as zf:
        first = zf.infolist()[0]
        assert first.filename == "mimetype" and first.compress_type == zipfile.ZIP_STORED
        meta = zf.read("meta.xml")
    assert K.MARK not in meta and b'office:version="1.3"' in meta
    assert MF.office_fields(str(dst))[0] == []


def test_sad_office_zip_bomb_is_refused_by_declared_size(tmp_path):
    src = tmp_path / "bomb.docx"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", K.CONTENT_TYPES)
        zf.writestr("docProps/core.xml", K.CORE_XML)
        info = zipfile.ZipInfo("word/huge.bin")
        info.compress_type = zipfile.ZIP_DEFLATED
        with zf.open(info, "w", force_zip64=True) as fh:
            chunk = b"\x00" * (1024 * 1024)
            for _ in range(MF.MAX_ZIP_UNCOMPRESSED // len(chunk) + 1):
                fh.write(chunk)
    _fields, error, _ = MF.office_fields(str(src))
    assert "unpack" in error
    with pytest.raises(MF.FormatError):
        MF.office_clean(str(src), str(tmp_path / "out.docx"))


def test_sad_office_entity_expansion_is_refused_not_expanded(tmp_path):
    laughs = (
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        '<cp:coreProperties xmlns:cp="x"><dc:title xmlns:dc="y">&b;</dc:title></cp:coreProperties>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", K.CONTENT_TYPES)
        zf.writestr("docProps/core.xml", laughs)
    src = K.write(tmp_path / "laughs.docx", buf.getvalue())
    fields, error, _ = MF.office_fields(str(src))
    assert "DTD" in error and fields == []
    # Cleaning replaces the part without parsing it, so it still works.
    dst = tmp_path / "clean.docx"
    MF.office_clean(str(src), str(dst))
    with zipfile.ZipFile(dst) as zf:
        assert b"ENTITY" not in zf.read("docProps/core.xml")


def test_sad_not_a_zip_and_not_office(tmp_path):
    src = K.write(tmp_path / "x.docx", b"PK\x03\x04 not really")
    assert "zip" in MF.office_fields(str(src))[1]
    other = io.BytesIO()
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("readme.txt", "plain zip")
    src2 = K.write(tmp_path / "y.xlsx", other.getvalue())
    assert "neither" in MF.office_fields(str(src2))[1]
    with pytest.raises(MF.FormatError):
        MF.office_clean(str(src2), str(tmp_path / "out.xlsx"))


def test_edge_office_without_custom_part_and_with_comment(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", K.CONTENT_TYPES)
        zf.writestr("docProps/core.xml", K.CORE_XML)
        zf.writestr("xl/workbook.xml", "<workbook/>")
        zf.comment = b"SECRETZIPCOMMENT"
    src = K.write(tmp_path / "book.xlsx", buf.getvalue())
    dst = tmp_path / "clean.xlsx"
    assert K.MARK in K.plain(src)
    MF.office_clean(str(src), str(dst))
    assert K.MARK not in K.plain(dst)
    with zipfile.ZipFile(dst) as zf:
        assert zf.read("xl/workbook.xml") == b"<workbook/>"


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def _need_qtpdf() -> None:
    try:
        import PyQt6.QtPdf  # noqa: F401
    except ImportError as exc:  # also a QtPdf whose libraries are missing
        pytest.skip(f"QtPdf cannot be loaded here: {exc}")


def test_happy_pdf_is_read_through_qtpdf_without_pypdf(tmp_path, monkeypatch):
    _need_qtpdf()
    from PyQt6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    src = K.write(tmp_path / "doc.pdf", K.pdf_bytes())
    fields, error, _ = MF.pdf_fields(str(src))
    text = _values(fields)
    assert error == ""
    assert "PDF Info/Author=SECRETAUTHOR" in text
    assert "PDF Info/Title=SECRETTITLE" in text
    assert "SECRETXMPCREATOR" in text


def test_sad_pdf_removal_without_pypdf_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    src = K.write(tmp_path / "doc.pdf", K.pdf_bytes())
    with pytest.raises(MF.Unavailable, match="pypdf"):
        MF.pdf_clean(str(src), str(tmp_path / "out.pdf"))


def test_sad_broken_pdf_is_an_error_not_a_crash(tmp_path, monkeypatch):
    _need_qtpdf()
    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    src = K.write(tmp_path / "broken.pdf", b"%PDF-1.4\nthis is not a pdf")
    fields, error, _ = MF.pdf_fields(str(src))
    assert fields == [] and error


def test_happy_pypdf_removes_info_xmp_and_old_revisions(tmp_path):
    pytest.importorskip("pypdf")
    from pypdf import PdfReader

    src = K.write(tmp_path / "doc.pdf", K.pdf_bytes(incremental=True))
    fields, error, _ = MF.pdf_fields(str(src))
    assert error == "" and "SECRETNEWAUTHOR" in _values(fields)
    dst = tmp_path / "clean.pdf"
    MF.pdf_clean(str(src), str(dst))
    out = dst.read_bytes()
    assert K.MARK not in out
    reader = PdfReader(str(dst))
    assert len(reader.pages) == 1
    assert not reader.metadata
    assert "/Metadata" not in reader.trailer["/Root"]
    assert MF.pdf_fields(str(dst))[0] == []


def test_edge_pypdf_cleaning_uses_no_deprecated_call(tmp_path):
    # pypdf 6 deprecated remove_orphans (gone in 7.0); the cleaner must
    # pick the keyword the installed pypdf understands.
    pytest.importorskip("pypdf")
    import warnings

    src = K.write(tmp_path / "doc.pdf", K.pdf_bytes(incremental=True))
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        MF.pdf_clean(str(src), str(tmp_path / "clean.pdf"))
    assert K.MARK not in (tmp_path / "clean.pdf").read_bytes()


def test_sad_pypdf_refuses_an_encrypted_pdf(tmp_path):
    pytest.importorskip("pypdf")
    from tests.media_testkit import encrypted_pdf_bytes

    src = K.write(tmp_path / "locked.pdf", encrypted_pdf_bytes())
    with pytest.raises(MF.FormatError, match="encrypted"):
        MF.pdf_clean(str(src), str(tmp_path / "out.pdf"))


# ---------------------------------------------------------------------------
# Audio / video
# ---------------------------------------------------------------------------

needs_ffmpeg = pytest.mark.skipif(not K.have_ffmpeg(), reason="ffmpeg / ffprobe not installed")


@needs_ffmpeg
@pytest.mark.parametrize(
    "ext,kind",
    [
        ("mp4", MF.VIDEO),
        ("mkv", MF.VIDEO),
        ("mp3", MF.AUDIO),
        ("flac", MF.AUDIO),
        ("m4a", MF.AUDIO),
        ("ogg", MF.AUDIO),
    ],
)
def test_happy_av_fields_and_clean(tmp_path, ext, kind):
    src = K.ffmpeg_make(tmp_path / f"-clip.{ext}", ext)  # a name that starts with '-'
    fields, error, _ = MF.av_fields(str(src), kind)
    text = _values(fields)
    assert error == ""
    assert "SECRETTITLE" in text and "SECRETARTIST" in text
    dst = tmp_path / f"-clean.{ext}"
    MF.av_clean(str(src), str(dst), kind)
    assert K.MARK not in dst.read_bytes()
    after, error, _ = MF.av_fields(str(dst), kind)
    assert error == ""
    assert [f for f in after if f.removable] == []
    if kind == MF.AUDIO:
        assert "attached picture" not in _values(after)
    streams = [f for f in after if f.name == "codec"]
    assert streams


@needs_ffmpeg
def test_sad_corrupt_media_is_an_error(tmp_path):
    src = K.write(tmp_path / "broken.mp4", b"\x00\x00\x00\x18ftypisom" + os.urandom(2000))
    fields, error, _ = MF.av_fields(str(src), MF.VIDEO)
    assert fields == [] and error
    with pytest.raises(MF.FormatError):
        MF.av_clean(str(src), str(tmp_path / "out.mp4"), MF.VIDEO)


@needs_ffmpeg
def test_sad_a_playlist_disguised_as_mp4_is_not_followed(tmp_path):
    secret = K.write(tmp_path / "secret.ts", b"SECRET" * 100)
    playlist = "#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1,\n%s\n#EXT-X-ENDLIST\n" % secret
    src = K.write(tmp_path / "evil.mp4", playlist.encode())
    fields, error, _ = MF.av_fields(str(src), MF.VIDEO)
    assert fields == [] and error


def test_sad_missing_ffmpeg_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(MF, "ffprobe_path", lambda: None)
    monkeypatch.setattr(MF, "ffmpeg_path", lambda: None)
    fields, error, _ = MF.av_fields(str(tmp_path / "x.mp4"), MF.VIDEO)
    assert "ffprobe" in error
    with pytest.raises(MF.Unavailable, match="ffmpeg"):
        MF.av_clean(str(tmp_path / "x.mp4"), str(tmp_path / "y.mp4"), MF.VIDEO)


def test_edge_run_bounded_caps_output_and_time():
    with pytest.raises(MF.FormatError, match="output larger"):
        MF.run_bounded([sys.executable, "-c", "print('x' * 1000000)"], timeout=30, max_output=1000)
    with pytest.raises(MF.FormatError, match="timed out"):
        MF.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5, max_output=1000
        )
    code, out, _err = MF.run_bounded(
        [sys.executable, "-c", "print('ok')"], timeout=30, max_output=1000
    )
    assert code == 0 and out.strip() == b"ok"


def test_edge_run_bounded_cancel():
    import threading

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(MF.FormatError, match="cancelled"):
        MF.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30,
            max_output=1000,
            cancel=cancel,
        )


def test_edge_the_fixture_colour_profile_is_stable_across_seconds():
    # The ICC header holds a creation time; a profile rebuilt a second
    # later differs at byte 35 and made the comparison above flaky.
    import time

    first = K.icc_profile()
    time.sleep(1.05)
    assert K.icc_profile() == first
