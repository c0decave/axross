"""Files full of metadata for the metadata tests, generated on the spot.

Every personal value carries the marker ``SECRET`` so a test can assert
with one byte search that a cleaned file holds none of it. Images come
from Pillow (segments Pillow cannot write - IPTC, PNG tIME, GIF XMP - are
spliced in by hand), Office files from the stdlib ``zipfile``, PDFs by
hand, audio and video from the host's ffmpeg. Nothing is checked in.
"""

from __future__ import annotations

import functools

import io
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

MARK = b"SECRET"

XMP = (
    b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
    b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="SECRETTOOL">'
    b"<dc:creator><rdf:Seq><rdf:li>SECRETXMPCREATOR</rdf:li></rdf:Seq></dc:creator>"
    b"</rdf:Description></rdf:RDF></x:xmpmeta>"
    b'<?xpacket end="w"?>'
)


# ---------------------------------------------------------------------------
# EXIF (TIFF structure) built by hand, so GPS and an IFD1 thumbnail are real
# ---------------------------------------------------------------------------

_TYPES = {"byte": (1, 1), "ascii": (2, 1), "short": (3, 2), "long": (4, 4), "rational": (5, 8)}


def _pack_value(kind: str, value) -> tuple[int, int, bytes]:
    type_id, _size = _TYPES[kind]
    if kind == "ascii":
        raw = value.encode("latin-1") + b"\x00"
        return type_id, len(raw), raw
    if kind == "short":
        vals = value if isinstance(value, (list, tuple)) else [value]
        return type_id, len(vals), b"".join(struct.pack(">H", v) for v in vals)
    if kind == "long":
        vals = value if isinstance(value, (list, tuple)) else [value]
        return type_id, len(vals), b"".join(struct.pack(">I", v) for v in vals)
    if kind == "byte":
        raw = bytes(value)
        return type_id, len(raw), raw
    vals = value  # rational: list of (num, den)
    return type_id, len(vals), b"".join(struct.pack(">II", n, d) for n, d in vals)


def _ifd(entries: list[tuple[int, str, object]], start: int, next_ifd: int = 0) -> bytes:
    """One big-endian IFD placed at *start*, its out-of-line data after it."""
    entries = sorted(entries, key=lambda e: e[0])
    head = struct.pack(">H", len(entries))
    data_off = start + 2 + 12 * len(entries) + 4
    body = b""
    blob = b""
    for tag, kind, value in entries:
        type_id, count, raw = _pack_value(kind, value)
        if len(raw) <= 4:
            field = raw.ljust(4, b"\x00")
        else:
            field = struct.pack(">I", data_off + len(blob))
            blob += raw
            if len(blob) % 2:
                blob += b"\x00"
        body += struct.pack(">HHI", tag, type_id, count) + field
    return head + body + struct.pack(">I", next_ifd) + blob


def exif_tiff(orientation: int | None = 6, *, gps: bool = True, thumbnail: bool = True) -> bytes:
    """TIFF-structured EXIF: IFD0 with camera, artist, orientation, an Exif
    IFD (time, serial), a GPS IFD and an IFD1 thumbnail."""
    thumb = b""
    if thumbnail:
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, "JPEG", comment=b"SECRETTHUMB")
        thumb = buf.getvalue()

    ifd0 = [
        (0x010F, "ascii", "SECRETMAKE"),
        (0x0110, "ascii", "SECRETMODEL"),
        (0x0131, "ascii", "SECRETSOFTWARE"),
        (0x013B, "ascii", "SECRETARTIST"),
        (0x8298, "ascii", "SECRETCOPYRIGHT"),
    ]
    if orientation is not None:
        ifd0.append((0x0112, "short", orientation))
    exif_entries = [
        (0x9003, "ascii", "2026:01:02 03:04:05"),
        (0xA431, "ascii", "SECRETSERIAL"),
    ]
    gps_entries = [
        (0x0001, "ascii", "N"),
        (0x0002, "rational", [(52, 1), (31, 1), (12, 1)]),
        (0x0003, "ascii", "E"),
        (0x0004, "rational", [(13, 1), (24, 1), (1, 1)]),
    ]
    # Two passes: lay out with placeholder pointers, then with the real ones.
    pointers = {"exif": 0, "gps": 0, "ifd1": 0, "thumb": 0}
    for _ in range(2):
        entries0 = list(ifd0) + [(0x8769, "long", pointers["exif"])]
        if gps:
            entries0.append((0x8825, "long", pointers["gps"]))
        blob0 = _ifd(entries0, 8, pointers["ifd1"] if thumbnail else 0)
        off = 8 + len(blob0)
        pointers["exif"] = off
        blob_exif = _ifd(exif_entries, off)
        off += len(blob_exif)
        blob_gps = b""
        if gps:
            pointers["gps"] = off
            blob_gps = _ifd(gps_entries, off)
            off += len(blob_gps)
        blob_ifd1 = b""
        if thumbnail:
            pointers["ifd1"] = off
            ifd1_entries = [
                (0x0103, "short", 6),
                (0x0201, "long", pointers["thumb"]),
                (0x0202, "long", len(thumb)),
            ]
            blob_ifd1 = _ifd(ifd1_entries, off)
            off += len(blob_ifd1)
            pointers["thumb"] = off
    return b"MM\x00\x2a" + struct.pack(">I", 8) + blob0 + blob_exif + blob_gps + blob_ifd1 + thumb


@functools.cache
def icc_profile() -> bytes:
    # Built once: the ICC header carries its creation time (bytes 24-35),
    # so two profiles made a second apart differ and a fixture compared
    # with a fresh one failed whenever a second boundary fell in between.
    from PIL import ImageCms

    return ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()


def iptc_app13(marker: bytes = b"SECRETBYLINE") -> bytes:
    """A complete APP13 segment (marker included) with IPTC By-line and
    Copyright in a Photoshop 8BIM 0x0404 resource."""
    iim = b""
    for dataset, value in ((80, marker), (116, b"SECRETIPTCCOPYRIGHT"), (25, b"SECRETKEYWORD")):
        iim += b"\x1c\x02" + bytes([dataset]) + struct.pack(">H", len(value)) + value
    res = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00\x00" + struct.pack(">I", len(iim)) + iim
    if len(iim) % 2:
        res += b"\x00"
    payload = b"Photoshop 3.0\x00" + res
    return b"\xff\xed" + struct.pack(">H", len(payload) + 2) + payload


def _pixels(size=(64, 48)):
    from PIL import Image

    im = Image.new("RGB", size)
    px = im.load()
    for y in range(size[1]):
        for x in range(size[0]):
            px[x, y] = ((x * 7) % 256, (y * 11) % 256, ((x + y) * 5) % 256)
    return im


def jpeg_bytes(*, orientation: int | None = 6, everything: bool = True) -> bytes:
    """A JPEG with EXIF (GPS, camera, serial, thumbnail), XMP, IPTC, ICC, a
    comment and trailing data after EOI. ``everything=False`` gives a bare one."""
    im = _pixels()
    buf = io.BytesIO()
    if not everything:
        im.save(buf, "JPEG", quality=90)
        return buf.getvalue()
    im.save(
        buf,
        "JPEG",
        quality=90,
        exif=b"Exif\x00\x00" + exif_tiff(orientation),
        icc_profile=icc_profile(),
        xmp=XMP,
        comment=b"SECRETCOMMENT",
    )
    data = buf.getvalue()
    # IPTC right after SOI, an APP12 "Ducky" and a trailer after EOI.
    app12 = b"Ducky" + b"SECRETDUCKY"
    app12_seg = b"\xff\xec" + struct.pack(">H", len(app12) + 2) + app12
    return data[:2] + iptc_app13() + app12_seg + data[2:] + b"SECRETTRAILER"


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png_bytes(*, orientation: int | None = 6) -> bytes:
    from PIL import PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "SECRETAUTHOR")
    info.add_text("Comment", "SECRETZTXT" * 20, zip=True)
    info.add_itxt("XML:com.adobe.xmp", XMP.decode())
    info.add_itxt("Description", "SECRETITXT", lang="en", tkey="Beschreibung", zip=True)
    im = _pixels()
    buf = io.BytesIO()
    kwargs = {"pnginfo": info, "icc_profile": icc_profile()}
    if orientation is not None:
        kwargs["exif"] = exif_tiff(orientation)
    im.save(buf, "PNG", **kwargs)
    data = buf.getvalue()
    tim = _png_chunk(b"tIME", struct.pack(">HBBBBB", 2026, 1, 2, 3, 4, 5))
    private = _png_chunk(b"prVt", b"SECRETPRIVATECHUNK")
    iend = data.rindex(b"IEND") - 4
    return data[:iend] + tim + private + data[iend:] + b"SECRETTRAILER"


def webp_bytes(*, orientation: int | None = 6, lossless: bool = True) -> bytes:
    im = _pixels()
    buf = io.BytesIO()
    kwargs = {"icc_profile": icc_profile(), "xmp": XMP, "lossless": lossless}
    if orientation is not None:
        kwargs["exif"] = b"Exif\x00\x00" + exif_tiff(orientation)
    im.save(buf, "WEBP", **kwargs)
    return buf.getvalue()


def gif_bytes() -> bytes:
    """A two-frame looping GIF with a comment, an XMP application extension
    and trailing data."""
    from PIL import Image

    frames = [_pixels().convert("P"), Image.new("RGB", (64, 48), (9, 9, 9)).convert("P")]
    buf = io.BytesIO()
    frames[0].save(
        buf,
        "GIF",
        save_all=True,
        append_images=frames[1:],
        loop=0,
        duration=100,
        comment=b"SECRETGIFCOMMENT",
    )
    data = buf.getvalue()
    xmp_payload = XMP + bytes(range(255, -1, -1)) + b"\x00"  # the "magic trailer"
    blocks = b""
    for i in range(0, len(xmp_payload), 255):
        chunk = xmp_payload[i : i + 255]
        blocks += bytes([len(chunk)]) + chunk
    ext = b"\x21\xff\x0bXMP DataXMP" + blocks + b"\x00"
    trailer = data.rindex(b"\x3b")
    return data[:trailer] + ext + data[trailer:] + b"SECRETTRAILER"


def tiff_bytes(*, orientation: int | None = 6, compression: str = "tiff_lzw") -> bytes:
    from PIL import TiffImagePlugin

    im = _pixels()
    info = TiffImagePlugin.ImageFileDirectory_v2()
    info[315] = "SECRETARTIST"
    info[270] = "SECRETDESCRIPTION"
    info[305] = "SECRETSOFTWARE"
    info[700] = XMP
    info.tagtype[700] = 1
    info[33723] = b"\x1c\x02\x50\x00\x0cSECRETBYLINE"
    info.tagtype[33723] = 7
    if orientation is not None:
        info[274] = orientation
    buf = io.BytesIO()
    im.save(buf, "TIFF", tiffinfo=info, compression=compression, icc_profile=icc_profile())
    return buf.getvalue()


def plain(path) -> bytes:
    """The bytes of a file as a byte search should see them: a zip (Office)
    adds every decompressed entry and its comment, because compressed
    entries would hide a marker from a plain search."""
    data = Path(path).read_bytes()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return data + zf.comment + b"".join(zf.read(i) for i in zf.infolist())
    except zipfile.BadZipFile:
        return data


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Office
# ---------------------------------------------------------------------------

CORE_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
    'core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    "<dc:title>SECRETTITLE</dc:title><dc:creator>SECRETCREATOR</dc:creator>"
    "<cp:lastModifiedBy>SECRETLASTMODIFIED</cp:lastModifiedBy><cp:revision>7</cp:revision>"
    '<dcterms:created xsi:type="dcterms:W3CDTF">2026-01-02T03:04:05Z</dcterms:created>'
    "</cp:coreProperties>"
)
APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
    'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    "<Application>SECRETAPP</Application><Company>SECRETCOMPANY</Company>"
    "<TotalTime>42</TotalTime></Properties>"
)
CUSTOM_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
    'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Client">'
    "<vt:lpwstr>SECRETCLIENT</vt:lpwstr></property></Properties>"
)
CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8"?><Types '
    'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)
RELS = (
    '<?xml version="1.0" encoding="UTF-8"?><Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/'
    'relationships/metadata/core-properties" Target="docProps/core.xml"/>'
    '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/extended-properties" Target="docProps/app.xml"/>'
    '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/custom-properties" Target="docProps/custom.xml"/></Relationships>'
)
DOCUMENT_XML = b"<w:document>body text that must survive</w:document>" * 50


def docx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES)
        zf.writestr("_rels/.rels", RELS)
        zf.writestr("word/document.xml", DOCUMENT_XML)
        zf.writestr("docProps/core.xml", CORE_XML)
        zf.writestr("docProps/app.xml", APP_XML)
        zf.writestr("docProps/custom.xml", CUSTOM_XML)
        zf.writestr(
            "word/media/image1.bin", bytes(range(256)) * 4, compress_type=zipfile.ZIP_STORED
        )
    return buf.getvalue()


META_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3"><office:meta>'
    "<meta:initial-creator>SECRETINITIAL</meta:initial-creator><dc:creator>SECRETODFCREATOR</dc:creator>"
    "<meta:generator>SECRETGENERATOR</meta:generator>"
    '<meta:user-defined meta:name="Project">SECRETPROJECT</meta:user-defined>'
    '<meta:document-statistic meta:page-count="1" meta:word-count="3"/>'
    "</office:meta></office:document-meta>"
)


def odt_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "mimetype", "application/vnd.oasis.opendocument.text", compress_type=zipfile.ZIP_STORED
        )
        zf.writestr("content.xml", b"<office:document-content>body</office:document-content>" * 20)
        zf.writestr("meta.xml", META_XML)
        zf.writestr("META-INF/manifest.xml", "<manifest:manifest/>")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def pdf_bytes(*, xmp: bool = True, incremental: bool = False) -> bytes:
    """A one-page PDF with an Info dict (incl. a custom key) and an XMP
    stream. ``incremental=True`` appends an update that changes the title,
    so the old value only survives in the earlier revision."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R" + (b" /Metadata 5 0 R" if xmp else b"") + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 6 0 R >>",
        b"<< /Author (SECRETAUTHOR) /Title (SECRETTITLE) /Creator (SECRETCREATOR) "
        b"/Producer (SECRETPRODUCER) /CreationDate (D:20260102030405Z) /Custom (SECRETCUSTOM) >>",
        b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(XMP)
        + XMP
        + b"\nendstream",
    ]
    content = b"0 0 1 rg 10 10 100 100 re f"
    objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1,
        xref,
    )
    if incremental:
        new_info = len(out)
        out += b"4 0 obj\n<< /Title (Plain) /Author (SECRETNEWAUTHOR) >>\nendobj\n"
        xref2 = len(out)
        out += b"xref\n4 1\n%010d 00000 n \n" % new_info
        out += (
            b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, xref, xref2)
        )
    return bytes(out)


# ---------------------------------------------------------------------------
# Audio / video (host ffmpeg)
# ---------------------------------------------------------------------------


def have_ffmpeg() -> bool:
    return bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))


def ffmpeg_make(path: Path, kind: str) -> Path:
    """``kind`` is ``mp4`` (video + audio, GPS-style location), ``mkv``,
    ``mp3`` / ``flac`` / ``m4a`` (with an attached cover picture), ``ogg``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cover = path.parent / ".cover-for-test.png"
    md = [
        "-metadata",
        "title=SECRETTITLE",
        "-metadata",
        "artist=SECRETARTIST",
        "-metadata",
        "comment=SECRETCOMMENT",
    ]
    sine = ["-f", "lavfi", "-i", "sine=frequency=440:duration=0.4"]
    color = ["-f", "lavfi", "-i", "color=c=red:s=32x32:d=0.4"]
    if kind in ("mp3", "flac", "m4a"):
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-v",
                "error",
                "-nostdin",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "color=c=blue:s=16x16:d=0.04",
                "-frames:v",
                "1",
                "file:" + str(cover),
            ],
            check=True,
            timeout=60,
        )
    argv = {
        "mp4": [
            *sine,
            *color,
            "-map",
            "0",
            "-map",
            "1",
            "-c:a",
            "aac",
            "-c:v",
            "mpeg4",
            *md,
            "-metadata",
            "location=+52.5200+013.4050/",
            "-metadata:s:v:0",
            "handler_name=SECRETCAMERA",
        ],
        "mkv": [
            *sine,
            *color,
            "-map",
            "0",
            "-map",
            "1",
            "-c:a",
            "flac",
            "-c:v",
            "ffv1",
            *md,
            "-metadata:s:a:0",
            "title=SECRETSTREAM",
        ],
        "mp3": [
            *sine,
            "-i",
            "file:" + str(cover),
            "-map",
            "0",
            "-map",
            "1",
            "-c:a",
            "libmp3lame",
            "-c:v",
            "png",
            "-disposition:v",
            "attached_pic",
            "-id3v2_version",
            "3",
            *md,
        ],
        "flac": [
            *sine,
            "-i",
            "file:" + str(cover),
            "-map",
            "0",
            "-map",
            "1",
            "-c:a",
            "flac",
            "-c:v",
            "png",
            "-disposition:v",
            "attached_pic",
            *md,
        ],
        "m4a": [
            *sine,
            "-i",
            "file:" + str(cover),
            "-map",
            "0",
            "-map",
            "1",
            "-c:a",
            "aac",
            "-c:v",
            "png",
            "-disposition:v",
            "attached_pic",
            *md,
        ],
        "ogg": [*sine, "-c:a", "libvorbis", *md],
    }[kind]
    subprocess.run(
        ["ffmpeg", "-hide_banner", "-v", "error", "-nostdin", "-y", *argv, "file:" + str(path)],
        check=True,
        timeout=120,
    )
    if cover.exists():
        cover.unlink()
    return path
