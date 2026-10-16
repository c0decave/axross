"""Reading and removing metadata, one file format at a time.

Everything here works on local bytes or local paths; :mod:`core.metadata_tools`
does the backend I/O, the write modes and the bookkeeping around it. No Qt
except the optional QtPdf fallback for reading PDFs.

What "removing" means per format
--------------------------------
Images (JPEG, PNG, WebP, GIF)
    Rewritten at the container level, never re-encoded: the compressed
    pixel data is copied byte for byte. Everything goes except the EXIF
    Orientation tag (rebuilt as a one-entry EXIF block) and the ICC colour
    profile: GPS, camera and serial numbers, times, author / artist /
    copyright, software, comments, embedded thumbnails, XMP, IPTC, PNG text
    chunks, private chunks and data after the end of the image. Segments
    that change how pixels decode stay (JPEG tables, the Adobe colour
    transform, PNG gamma / chromaticities / transparency, animation).
TIFF
    Re-saved through Pillow with the same lossless compression; a TIFF
    whose pixels are JPEG / WebP compressed is refused, because re-saving
    it would re-encode them.
Office (docx / xlsx / pptx and the macro variants, odt / ods / odp)
    The zip is rewritten entry by entry with the same order and compression
    method; only the property parts (``docProps/core.xml``, ``app.xml``,
    ``custom.xml`` or ODF ``meta.xml``) are replaced by empty ones, so every
    other entry decompresses to the same bytes. The zip comment and the
    per-entry extra fields (which can carry timestamps and user ids) go too.
PDF
    Read through pypdf when installed, else QtPdf. Removal needs pypdf and is
    a full rewrite (Info dictionary, XMP streams of the catalog and pages,
    PieceInfo): an incremental update would leave the old bytes in the file.
Audio / video
    ``ffprobe`` to read, ``ffmpeg -map_metadata -1 -map_chapters -1 -c copy``
    to remove (streams copied, never re-encoded). Data streams (camera GPS
    tracks) are dropped; for audio files the attached cover picture too.

Every reader is bounded and never raises on hostile input: a damaged segment
becomes an error on the report. A cleaner raises :class:`FormatError` when it
cannot produce a file it can vouch for; the caller then leaves the original
alone.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import threading
import warnings
import zipfile
import zlib
from dataclasses import dataclass

log = logging.getLogger(__name__)

#: Longest value shown for one field; longer text is cut and labelled.
MAX_VALUE_CHARS = 512
#: Most fields one report lists.
MAX_FIELDS = 2000
#: Longest XML part (Office property part, XMP packet) that is parsed.
MAX_XML_BYTES = 4 * 1024 * 1024
#: Office: most zip entries, and most bytes all entries may decompress to.
MAX_ZIP_ENTRIES = 20_000
MAX_ZIP_UNCOMPRESSED = 1024 * 1024 * 1024
#: Most frames compared when verifying an animated image.
MAX_VERIFY_FRAMES = 2000
#: ffprobe output bound and the external tools' time limits.
MAX_PROBE_OUTPUT = 8 * 1024 * 1024
PROBE_TIMEOUT = 60.0
REMUX_TIMEOUT = 900.0

IMAGE = "image"
OFFICE = "office"
PDF = "pdf"
AUDIO = "audio"
VIDEO = "video"
KINDS = (IMAGE, OFFICE, PDF, AUDIO, VIDEO)

IMAGE_EXTENSIONS = {
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".jpe": "jpeg",
    ".jfif": "jpeg",
    ".png": "png",
    ".webp": "webp",
    ".gif": "gif",
    ".tif": "tiff",
    ".tiff": "tiff",
}
OFFICE_EXTENSIONS = frozenset(
    {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".odg"}
)
PDF_EXTENSIONS = frozenset({".pdf"})
AUDIO_EXTENSIONS = frozenset(
    {".mp3", ".flac", ".ogg", ".oga", ".opus", ".m4a", ".wav", ".aac", ".wma", ".aiff", ".aif"}
)
VIDEO_EXTENSIONS = frozenset(
    {".mp4", ".m4v", ".mkv", ".webm", ".mov", ".avi", ".ogv", ".mpg", ".mpeg", ".wmv", ".3gp"}
)
#: Demuxers ffprobe / ffmpeg may use. A file whose content probes as
#: anything else (an HLS playlist named .mp4, a concat script) is refused
#: instead of being followed to other files.
FFMPEG_FORMATS = "mov,mp4,m4a,3gp,matroska,webm,mp3,flac,ogg,wav,avi,mpeg,mpegts,asf,aac,aiff"


class FormatError(ValueError):
    """The file is malformed, or cleaning it could not be verified."""


class Unavailable(RuntimeError):
    """A tool or library this operation needs is not installed."""


@dataclass(frozen=True)
class Field:
    group: str
    name: str
    value: str
    #: False for what is kept on purpose (orientation, ICC profile) and for
    #: technical facts (codec, duration) shown for context.
    removable: bool = True


def kind_of(name: str) -> str | None:
    """The metadata kind of a file name, by its extension."""
    stem, ext = os.path.splitext(name or "")
    if not stem or stem == ".":
        return None
    ext = ext.lower()
    if ext in IMAGE_EXTENSIONS:
        return IMAGE
    if ext in OFFICE_EXTENSIONS:
        return OFFICE
    if ext in PDF_EXTENSIONS:
        return PDF
    if ext in AUDIO_EXTENSIONS:
        return AUDIO
    if ext in VIDEO_EXTENSIONS:
        return VIDEO
    return None


# ---------------------------------------------------------------------------
# Bounded values
# ---------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‎‏‪-‮⁦-⁩]")


def bounded(value) -> str:
    """Display text for any value: control and bidi characters removed,
    binary shown as its size, long text cut with its full length noted."""
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        head = raw[:4096].rstrip(b"\x00")
        if len(raw) > 4096 or (head and sum(c < 9 or 13 < c < 32 for c in head) > len(head) // 10):
            return f"<binary, {len(raw)} bytes>"
        text = head.decode("utf-8", errors="replace")
    elif isinstance(value, (tuple, list)):
        if len(value) > 64:
            return f"<{len(value)} values>"
        text = ", ".join(bounded(v) for v in value)
    else:
        text = str(value)
    text = _CONTROL.sub(" ", text).strip()
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS] + f"… ({len(text)} chars)"
    return text


class _Fields(list):
    """A list of :class:`Field` that stops growing at :data:`MAX_FIELDS`."""

    truncated = False

    def add(self, group: str, name: str, value, removable: bool = True) -> None:
        if len(self) >= MAX_FIELDS:
            self.truncated = True
            return
        self.append(Field(group, bounded(name), bounded(value), removable))


# ---------------------------------------------------------------------------
# XML (Office parts, XMP): no DTDs, no entities, bounded
# ---------------------------------------------------------------------------


def parse_xml(data: bytes):
    """An ElementTree root, or :class:`FormatError`.

    defusedxml when installed; otherwise the stdlib parser behind a check
    that refuses any DTD, which is what entity expansion attacks need."""
    if len(data) > MAX_XML_BYTES:
        raise FormatError(f"XML part too large ({len(data)} bytes)")
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise FormatError("XML with a DTD is refused")
    try:
        try:
            from defusedxml import ElementTree as ET  # type: ignore[import-not-found]

            return ET.fromstring(data, forbid_dtd=True)
        except ImportError:
            import xml.etree.ElementTree as ET  # noqa: N817

            return ET.fromstring(data)
    except Exception as exc:  # noqa: BLE001 - any parser failure is malformed input
        raise FormatError(f"malformed XML: {exc}") from exc


_NS_PREFIX = {
    "http://purl.org/dc/elements/1.1/": "dc",
    "http://purl.org/dc/terms/": "dcterms",
    "http://ns.adobe.com/xap/1.0/": "xmp",
    "http://ns.adobe.com/xap/1.0/mm/": "xmpMM",
    "http://ns.adobe.com/xap/1.0/rights/": "xmpRights",
    "http://ns.adobe.com/photoshop/1.0/": "photoshop",
    "http://ns.adobe.com/exif/1.0/": "exif",
    "http://ns.adobe.com/tiff/1.0/": "tiff",
    "http://ns.adobe.com/pdf/1.3/": "pdf",
    "http://ns.adobe.com/camera-raw-settings/1.0/": "crs",
    "http://ns.adobe.com/exif/1.0/aux/": "aux",
    "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/": "Iptc4xmpCore",
    "http://schemas.openxmlformats.org/package/2006/metadata/core-properties": "cp",
    "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties": "",
    "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties": "",
    "urn:oasis:names:tc:opendocument:xmlns:meta:1.0": "meta",
    "urn:oasis:names:tc:opendocument:xmlns:office:1.0": "office",
}
_RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"


def _qname(tag: str) -> str:
    if tag.startswith("{"):
        ns, _, local = tag[1:].partition("}")
        prefix = _NS_PREFIX.get(ns)
        if prefix is None:
            prefix = ns.rstrip("/#").rsplit("/", 1)[-1] or "ns"
        return f"{prefix}:{local}" if prefix else local
    return tag


def _text_of(elem) -> str:
    parts = [t.strip() for t in elem.itertext() if t and t.strip()]
    return ", ".join(parts)


def _xmp_parses(data: bytes) -> bool:
    start = data.find(b"<x:xmpmeta")
    end = data.find(b"</x:xmpmeta>", max(start, 0))
    if start < 0 or end < 0:
        return False
    try:
        parse_xml(data[start : end + 12])
    except FormatError:
        return False
    return True


def xmp_fields(data: bytes, fields: _Fields, group: str = "XMP") -> None:
    """Each leaf property of an XMP packet as one field."""
    start = data.find(b"<x:xmpmeta")
    if start < 0:
        start = data.find(b"<rdf:RDF")
    end_tag = b"</x:xmpmeta>" if data[start : start + 10] == b"<x:xmpmeta" else b"</rdf:RDF>"
    end = data.find(end_tag, max(start, 0))
    if start < 0 or end < 0:
        fields.add(group, "packet", f"<{len(data)} bytes, not parsed>")
        return
    try:
        root = parse_xml(data[start : end + len(end_tag)])
    except FormatError as exc:
        fields.add(group, "packet", f"<{len(data)} bytes, {exc}>")
        return
    found = False
    for desc in root.iter(f"{{{_RDF}}}Description"):
        for key, value in desc.attrib.items():
            if key.startswith(f"{{{_RDF}}}"):
                continue
            fields.add(group, _qname(key), value)
            found = True
        for child in desc:
            text = _text_of(child)
            if text:
                fields.add(group, _qname(child.tag), text)
                found = True
    if not found:
        fields.add(group, "packet", f"<{len(data)} bytes>")


# ---------------------------------------------------------------------------
# TIFF structures (EXIF): a bounded reader and a one-tag writer
# ---------------------------------------------------------------------------

_TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def _read_ifd(tiff: bytes, offset: int) -> tuple[dict, int]:
    """``{tag: (type, count, value_bytes)}`` of one IFD and the next offset.

    Values longer than 4 bytes are resolved through their offset; anything
    out of bounds is left out. Never raises on garbage: an unusable IFD is
    empty."""
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return {}, 0
    order = "<" if tiff[:2] == b"II" else ">"
    if not 8 <= offset <= len(tiff) - 2:
        return {}, 0
    (count,) = struct.unpack_from(order + "H", tiff, offset)
    if count > 1000 or offset + 2 + 12 * count + 4 > len(tiff):
        return {}, 0
    out: dict = {}
    for i in range(count):
        base = offset + 2 + 12 * i
        tag, typ, n = struct.unpack_from(order + "HHI", tiff, base)
        size = _TIFF_TYPE_SIZE.get(typ, 0) * n
        if size <= 4:
            raw = tiff[base + 8 : base + 8 + size]
        else:
            (ptr,) = struct.unpack_from(order + "I", tiff, base + 8)
            if size > len(tiff) or ptr + size > len(tiff):
                continue
            raw = tiff[ptr : ptr + size]
        out[tag] = (typ, n, raw)
    (nxt,) = struct.unpack_from(order + "I", tiff, offset + 2 + 12 * count)
    return out, nxt


def _tiff_int(tiff: bytes, entry) -> int | None:
    typ, n, raw = entry
    order = "<" if tiff[:2] == b"II" else ">"
    if n < 1:
        return None
    if typ == 3 and len(raw) >= 2:
        return struct.unpack_from(order + "H", raw)[0]
    if typ == 4 and len(raw) >= 4:
        return struct.unpack_from(order + "I", raw)[0]
    return None


def _strip_exif_header(data: bytes) -> bytes:
    return data[6:] if data[:6] == b"Exif\x00\x00" else data


def exif_orientation(data: bytes) -> int | None:
    """The Orientation tag (1-8) of an EXIF block, or ``None``."""
    tiff = _strip_exif_header(data)
    if len(tiff) < 8:
        return None
    order = "<" if tiff[:2] == b"II" else ">"
    try:
        (first,) = struct.unpack_from(order + "I", tiff, 4)
    except struct.error:
        return None
    ifd0, _ = _read_ifd(tiff, first)
    entry = ifd0.get(0x0112)
    value = _tiff_int(tiff, entry) if entry else None
    return value if value is not None and 1 <= value <= 8 else None


def minimal_exif(orientation: int) -> bytes:
    """A TIFF-structured EXIF block holding only the Orientation tag."""
    return (
        b"MM\x00\x2a"
        + struct.pack(">I", 8)
        + struct.pack(">H", 1)
        + struct.pack(">HHIHH", 0x0112, 3, 1, orientation, 0)
        + struct.pack(">I", 0)
    )


_SUB_IFDS = ((0x8769, "EXIF"), (0x8825, "GPS"), (0xA005, "EXIF interop"))
_POINTER_TAGS = frozenset(t for t, _ in _SUB_IFDS) | {0x0201, 0x0202}


def exif_fields(data: bytes, fields: _Fields) -> None:
    """Every EXIF tag as a field; the Orientation tag is marked as kept."""
    from PIL import ExifTags, Image

    tiff = _strip_exif_header(data)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # "Corrupt EXIF data" is reported below
            exif = Image.Exif()
            exif.load(tiff)
            base = dict(exif)
    except Exception as exc:  # noqa: BLE001 - hostile EXIF
        fields.add("EXIF", "block", f"<{len(tiff)} bytes, unreadable: {type(exc).__name__}>")
        return
    for tag, value in base.items():
        if tag in _POINTER_TAGS:
            continue
        name = ExifTags.TAGS.get(tag, f"0x{tag:04X}")
        fields.add("EXIF", name, value, removable=tag != 0x0112)
    for ifd_tag, group in _SUB_IFDS:
        if ifd_tag not in base:
            continue
        try:
            sub = dict(exif.get_ifd(ifd_tag))
        except Exception as exc:  # noqa: BLE001
            fields.add(group, "IFD", f"<unreadable: {type(exc).__name__}>")
            continue
        names = ExifTags.GPSTAGS if ifd_tag == 0x8825 else ExifTags.TAGS
        for tag, value in sub.items():
            if tag == 0x927C:  # MakerNote: vendor binary
                value = bytes(value) if isinstance(value, (bytes, bytearray)) else value
            fields.add(group, names.get(tag, f"0x{tag:04X}"), value)
    # IFD1 is the embedded thumbnail.
    order = "<" if tiff[:2] == b"II" else ">"
    try:
        (first,) = struct.unpack_from(order + "I", tiff, 4)
    except struct.error:
        return
    _ifd0, nxt = _read_ifd(tiff, first)
    if nxt:
        ifd1, _ = _read_ifd(tiff, nxt)
        if ifd1:
            length = _tiff_int(tiff, ifd1[0x0202]) if 0x0202 in ifd1 else None
            fields.add(
                "EXIF thumbnail",
                "embedded preview",
                f"{length} bytes" if length is not None else f"{len(ifd1)} tags",
            )


# ---------------------------------------------------------------------------
# IPTC (IIM) inside Photoshop image resources
# ---------------------------------------------------------------------------

_IIM_NAMES = {
    5: "Object Name",
    7: "Edit Status",
    10: "Urgency",
    15: "Category",
    20: "Supplemental Category",
    25: "Keywords",
    40: "Special Instructions",
    55: "Date Created",
    60: "Time Created",
    62: "Digital Creation Date",
    63: "Digital Creation Time",
    65: "Originating Program",
    70: "Program Version",
    80: "By-line",
    85: "By-line Title",
    90: "City",
    92: "Sub-location",
    95: "Province/State",
    100: "Country Code",
    101: "Country",
    103: "Transmission Reference",
    105: "Headline",
    110: "Credit",
    115: "Source",
    116: "Copyright Notice",
    118: "Contact",
    120: "Caption/Abstract",
    122: "Writer/Editor",
}


def iim_fields(data: bytes, fields: _Fields) -> None:
    pos = 0
    while pos + 5 <= len(data) and not fields.truncated:
        if data[pos] != 0x1C:
            break
        record, dataset = data[pos + 1], data[pos + 2]
        (size,) = struct.unpack_from(">H", data, pos + 3)
        pos += 5
        if size & 0x8000:  # extended length: not used for text, stop here
            fields.add("IPTC", f"{record}:{dataset}", "<extended dataset>")
            break
        value = data[pos : pos + size]
        pos += size
        if record == 1 and dataset == 90:
            continue  # coded character set, technical
        name = (
            _IIM_NAMES.get(dataset, f"{record}:{dataset}") if record == 2 else f"{record}:{dataset}"
        )
        fields.add("IPTC", name, value)


def photoshop_fields(data: bytes, fields: _Fields) -> None:
    """8BIM resources of a Photoshop APP13 block (after its signature)."""
    pos = 0
    while pos + 12 <= len(data) and not fields.truncated:
        if data[pos : pos + 4] != b"8BIM":
            break
        (rid,) = struct.unpack_from(">H", data, pos + 4)
        name_len = data[pos + 6]
        pos += 7 + name_len + ((name_len + 1) % 2)
        if pos + 4 > len(data):
            break
        (size,) = struct.unpack_from(">I", data, pos)
        pos += 4
        body = data[pos : pos + size]
        pos += size + (size % 2)
        if rid == 0x0404:
            iim_fields(body, fields)
        else:
            fields.add("Photoshop", f"resource 0x{rid:04X}", f"{len(body)} bytes")


def icc_field(icc: bytes, fields: _Fields) -> None:
    desc = f"{len(icc)} bytes"
    if len(icc) >= 20:
        space = icc[16:20].decode("latin-1", "replace").strip()
        cls = icc[12:16].decode("latin-1", "replace").strip()
        desc += f", {space} {cls}"
    fields.add("ICC profile", "colour profile (kept)", desc, removable=False)


# ---------------------------------------------------------------------------
# JPEG
# ---------------------------------------------------------------------------


def _jpeg_scan_end(data: bytes, pos: int) -> int:
    """Offset of the first marker after entropy-coded data starting at *pos*."""
    n = len(data)
    i = pos
    while True:
        j = data.find(b"\xff", i)
        if j < 0 or j + 1 >= n:
            raise FormatError("truncated JPEG scan data")
        nxt = data[j + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
            i = j + 1 if nxt == 0xFF else j + 2
            continue
        return j


def _jpeg_segments(data: bytes):
    """Yield ``(marker, payload_start, end)``; SOS is followed by its scan
    (end includes the entropy-coded data). Raises FormatError on damage."""
    if data[:2] != b"\xff\xd8":
        raise FormatError("not a JPEG (no SOI marker)")
    pos, n = 2, len(data)
    while pos < n:
        if data[pos] != 0xFF:
            raise FormatError(f"JPEG: expected a marker at offset {pos}")
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            raise FormatError("JPEG: truncated after a marker")
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            yield marker, pos, pos
            return
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            yield marker, pos, pos
            continue
        if pos + 2 > n:
            raise FormatError("JPEG: truncated segment header")
        (length,) = struct.unpack_from(">H", data, pos)
        if length < 2 or pos + length > n:
            raise FormatError(f"JPEG: segment 0x{marker:02X} length {length} out of range")
        end = pos + length
        if marker == 0xDA:
            end = _jpeg_scan_end(data, end)
        yield marker, pos + 2, end
        pos = end
    raise FormatError("JPEG: no end-of-image marker")


def jpeg_fields(data: bytes) -> tuple[_Fields, str]:
    fields = _Fields()
    error = ""
    end_of_image = None
    icc_parts = []
    try:
        for marker, start, end in _jpeg_segments(data):
            if marker == 0xD9:
                end_of_image = end
                break
            if marker == 0xDA:
                continue
            payload = data[start:end] if end > start else b""
            if marker == 0xE0 and payload.startswith(b"JFIF\x00") and len(payload) >= 14:
                fields.add("JFIF", "version", f"{payload[5]}.{payload[6]:02d}", removable=False)
                if payload[12] and payload[13]:
                    fields.add("JFIF", "thumbnail", f"{payload[12]}x{payload[13]}")
            elif marker == 0xE0:
                fields.add("APP0", "segment", f"{payload[:5]!r} {len(payload)} bytes")
            elif marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                exif_fields(payload, fields)
            elif marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                xmp_fields(payload[29:], fields)
            elif marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xmp/extension/\x00"):
                fields.add("XMP", "extended packet", f"{len(payload)} bytes")
            elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"):
                icc_parts.append(payload[14:])
            elif marker == 0xED and payload.startswith(b"Photoshop 3.0\x00"):
                photoshop_fields(payload[14:], fields)
            elif marker == 0xEE and payload.startswith(b"Adobe"):
                fields.add(
                    "Adobe", "colour transform (kept)", f"{len(payload)} bytes", removable=False
                )
            elif marker == 0xFE:
                fields.add("Comment", "JPEG comment", payload)
            elif 0xE0 <= marker <= 0xEF:
                ident = payload[:16].split(b"\x00", 1)[0]
                fields.add(
                    f"APP{marker - 0xE0}", bounded(ident) or "segment", f"{len(payload)} bytes"
                )
    except FormatError as exc:
        error = str(exc)
    if icc_parts:
        icc_field(b"".join(icc_parts), fields)
    if end_of_image is not None and end_of_image < len(data):
        fields.add(
            "Trailer", "data after the end of the image", f"{len(data) - end_of_image} bytes"
        )
    return fields, error


def jpeg_clean(data: bytes) -> bytes:
    out = bytearray(b"\xff\xd8")
    exif_done = False
    for marker, start, end in _jpeg_segments(data):
        if marker == 0xD9:
            out += b"\xff\xd9"
            return bytes(out)
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            out += bytes((0xFF, marker))
            continue
        payload = data[start:end] if marker != 0xDA else b""
        keep = True
        if marker == 0xE0:
            keep = False
            if payload.startswith(b"JFIF\x00") and len(payload) >= 12:
                jfif = b"JFIF\x00" + payload[5:12] + b"\x00\x00"
                out += b"\xff\xe0" + struct.pack(">H", len(jfif) + 2) + jfif
        elif marker == 0xE1:
            keep = False
            if not exif_done and payload.startswith(b"Exif\x00\x00"):
                exif_done = True
                orientation = exif_orientation(payload)
                if orientation is not None:
                    block = b"Exif\x00\x00" + minimal_exif(orientation)
                    out += b"\xff\xe1" + struct.pack(">H", len(block) + 2) + block
        elif marker == 0xE2:
            keep = payload.startswith(b"ICC_PROFILE\x00")
        elif marker == 0xEE:
            keep = payload.startswith(b"Adobe")
        elif 0xE3 <= marker <= 0xEF or marker == 0xFE:
            keep = False
        if keep:
            # start - 4 is the marker (fill bytes normalised away).
            out += bytes((0xFF, marker)) + data[start - 2 : end]
    raise FormatError("JPEG: no end-of-image marker")


# ---------------------------------------------------------------------------
# PNG
# ---------------------------------------------------------------------------

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_KEEP = frozenset(
    {
        b"IHDR",
        b"PLTE",
        b"IDAT",
        b"IEND",
        b"tRNS",
        b"gAMA",
        b"cHRM",
        b"sRGB",
        b"iCCP",
        b"sBIT",
        b"bKGD",
        b"pHYs",
        b"hIST",
        b"sPLT",
        b"acTL",
        b"fcTL",
        b"fdAT",
        b"cICP",
        b"mDCV",
        b"cLLI",
        b"mDCv",
        b"cLLi",
    }
)


def _png_chunks(data: bytes):
    """Yield ``(type, data_start, data_end, chunk_start, chunk_end)``."""
    if data[:8] != _PNG_SIG:
        raise FormatError("not a PNG (bad signature)")
    pos, n = 8, len(data)
    while True:
        if pos + 12 > n:
            raise FormatError("PNG: truncated chunk (no IEND)")
        (length,) = struct.unpack_from(">I", data, pos)
        kind = data[pos + 4 : pos + 8]
        if length > 0x7FFFFFFF or pos + 12 + length > n:
            raise FormatError(f"PNG: chunk {kind!r} length {length} out of range")
        if not kind.isalpha():
            raise FormatError(f"PNG: invalid chunk type {kind!r}")
        yield kind, pos + 8, pos + 8 + length, pos, pos + 12 + length
        pos += 12 + length
        if kind == b"IEND":
            return


def _inflate_bounded(data: bytes, limit: int = 256 * 1024) -> bytes:
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, limit)
    except zlib.error as exc:
        raise FormatError(f"bad compressed text: {exc}") from exc
    if d.unconsumed_tail:
        out += b"..."
    return out


def png_fields(data: bytes) -> tuple[_Fields, str]:
    fields = _Fields()
    error = ""
    end = None
    try:
        for kind, s, e, _cs, ce in _png_chunks(data):
            body = data[s:e]
            if kind == b"tEXt":
                key, _, text = body.partition(b"\x00")
                fields.add("PNG text", key.decode("latin-1"), text.decode("latin-1"))
            elif kind == b"zTXt":
                key, _, rest = body.partition(b"\x00")
                try:
                    text = _inflate_bounded(rest[1:]).decode("latin-1")
                except FormatError as exc:
                    text = f"<{exc}>"
                fields.add("PNG text", key.decode("latin-1"), text)
            elif kind == b"iTXt":
                key, _, rest = body.partition(b"\x00")
                flag, rest = rest[:1], rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _tkey, _, text = rest.partition(b"\x00")
                if flag == b"\x01":
                    try:
                        text = _inflate_bounded(text)
                    except FormatError as exc:
                        text = f"<{exc}>".encode()
                if key == b"XML:com.adobe.xmp":
                    xmp_fields(text, fields)
                else:
                    fields.add("PNG text", key.decode("latin-1"), text.decode("utf-8", "replace"))
            elif kind == b"tIME" and len(body) == 7:
                y, mo, d, h, mi, sec = struct.unpack(">HBBBBB", body)
                fields.add(
                    "PNG",
                    "last modified (tIME)",
                    f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{sec:02d}",
                )
            elif kind == b"eXIf":
                exif_fields(body, fields)
            elif kind == b"iCCP":
                name, _, rest = body.partition(b"\x00")
                fields.add(
                    "ICC profile",
                    "colour profile (kept)",
                    f"{name.decode('latin-1')} {len(rest)} bytes compressed",
                    removable=False,
                )
            elif kind not in _PNG_KEEP:
                fields.add("PNG", f"chunk {kind.decode('latin-1')}", f"{len(body)} bytes")
            end = ce
    except FormatError as exc:
        error = str(exc)
    if end is not None and end < len(data):
        fields.add("Trailer", "data after the end of the image", f"{len(data) - end} bytes")
    return fields, error


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png_clean(data: bytes) -> bytes:
    out = bytearray(_PNG_SIG)
    for kind, s, e, cs, ce in _png_chunks(data):
        if kind == b"eXIf":
            orientation = exif_orientation(data[s:e])
            if orientation is not None:
                out += _png_chunk(b"eXIf", minimal_exif(orientation))
            continue
        if kind in _PNG_KEEP:
            out += data[cs:ce]
    return bytes(out)


# ---------------------------------------------------------------------------
# WebP
# ---------------------------------------------------------------------------

_WEBP_KEEP = frozenset({b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP"})


def _webp_chunks(data: bytes):
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise FormatError("not a WebP (bad RIFF header)")
    (riff_size,) = struct.unpack_from("<I", data, 4)
    n = min(len(data), 8 + riff_size)
    pos = 12
    while pos < n:
        if pos + 8 > n:
            raise FormatError("WebP: truncated chunk header")
        kind = data[pos : pos + 4]
        (size,) = struct.unpack_from("<I", data, pos + 4)
        if pos + 8 + size > n:
            raise FormatError(f"WebP: chunk {kind!r} size {size} out of range")
        yield kind, pos + 8, pos + 8 + size
        pos += 8 + size + (size & 1)


def webp_fields(data: bytes) -> tuple[_Fields, str]:
    fields = _Fields()
    error = ""
    try:
        for kind, s, e in _webp_chunks(data):
            body = data[s:e]
            if kind == b"EXIF":
                exif_fields(body, fields)
            elif kind == b"XMP ":
                xmp_fields(body, fields)
            elif kind == b"ICCP":
                icc_field(body, fields)
            elif kind not in _WEBP_KEEP:
                fields.add("WebP", f"chunk {kind.decode('latin-1')}", f"{len(body)} bytes")
    except FormatError as exc:
        error = str(exc)
    return fields, error


def webp_clean(data: bytes) -> bytes:
    chunks = []
    vp8x_index = None
    has_exif = False
    for kind, s, e in _webp_chunks(data):
        body = data[s:e]
        if kind == b"EXIF":
            orientation = exif_orientation(body)
            if orientation is None or has_exif:
                continue
            body = minimal_exif(orientation)
            has_exif = True
        elif kind not in _WEBP_KEEP:
            continue
        if kind == b"VP8X":
            vp8x_index = len(chunks)
        chunks.append([kind, bytearray(body)])
    if vp8x_index is not None and chunks[vp8x_index][1]:
        flags = chunks[vp8x_index][1][0]
        flags &= ~0x04  # XMP
        flags = (flags | 0x08) if has_exif else (flags & ~0x08)
        chunks[vp8x_index][1][0] = flags
    elif has_exif:
        # A simple-format WebP cannot carry EXIF without VP8X; drop it.
        chunks = [c for c in chunks if c[0] != b"EXIF"]
    body = bytearray(b"WEBP")
    for kind, payload in chunks:
        body += kind + struct.pack("<I", len(payload)) + payload
        if len(payload) & 1:
            body += b"\x00"
    return b"RIFF" + struct.pack("<I", len(body)) + bytes(body)


# ---------------------------------------------------------------------------
# GIF
# ---------------------------------------------------------------------------

_GIF_KEEP_APPS = (b"NETSCAPE2.0", b"ANIMEXTS1.0", b"ICCRGBG1012")


def _gif_subblocks_end(data: bytes, pos: int) -> int:
    n = len(data)
    while True:
        if pos >= n:
            raise FormatError("GIF: truncated data sub-blocks")
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size


def _gif_blocks(data: bytes):
    """Yield ``(kind, label, start, end)``; kind is header / ext / image / trailer."""
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        raise FormatError("not a GIF (bad header)")
    packed = data[10]
    pos = 13
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 7) + 1))
    if pos > len(data):
        raise FormatError("GIF: truncated colour table")
    yield "header", 0, 0, pos
    while True:
        if pos >= len(data):
            raise FormatError("GIF: no trailer")
        intro = data[pos]
        if intro == 0x3B:
            yield "trailer", 0, pos, pos + 1
            return
        if intro == 0x21:
            if pos + 2 > len(data):
                raise FormatError("GIF: truncated extension")
            label = data[pos + 1]
            end = _gif_subblocks_end(data, pos + 2)
            yield "ext", label, pos, end
            pos = end
        elif intro == 0x2C:
            if pos + 10 > len(data):
                raise FormatError("GIF: truncated image descriptor")
            p = data[pos + 9]
            body = pos + 10
            if p & 0x80:
                body += 3 * (2 ** ((p & 7) + 1))
            end = _gif_subblocks_end(data, body + 1)
            yield "image", 0, pos, end
            pos = end
        else:
            raise FormatError(f"GIF: unknown block 0x{intro:02X} at offset {pos}")


def _gif_app_id(data: bytes, start: int) -> bytes:
    return data[start + 3 : start + 14] if data[start + 2] == 11 else b""


def _gif_payload(data: bytes, start: int, end: int, skip_first: bool) -> bytes:
    pos, out = start + 2, bytearray()
    first = True
    while pos < end:
        size = data[pos]
        if size == 0:
            break
        if not (first and skip_first):
            out += data[pos + 1 : pos + 1 + size]
        first = False
        pos += 1 + size
    return bytes(out)


def gif_fields(data: bytes) -> tuple[_Fields, str]:
    fields = _Fields()
    error = ""
    end = None
    try:
        for kind, label, s, e in _gif_blocks(data):
            if kind == "trailer":
                end = e
            if kind != "ext":
                continue
            if label == 0xFE:
                fields.add("Comment", "GIF comment", _gif_payload(data, s, e, False))
            elif label == 0xFF:
                app = _gif_app_id(data, s)
                if app in _GIF_KEEP_APPS:
                    continue
                if app == b"XMP DataXMP":
                    # The XMP spec stores the packet raw (the sub-block length
                    # bytes are part of its text); some writers chunk it.
                    raw = data[s + 14 : e]
                    xmp_fields(raw if _xmp_parses(raw) else _gif_payload(data, s, e, True), fields)
                else:
                    fields.add("GIF", f"application {bounded(app)}", f"{e - s} bytes")
            elif label not in (0xF9, 0x01):
                fields.add("GIF", f"extension 0x{label:02X}", f"{e - s} bytes")
    except FormatError as exc:
        error = str(exc)
    if end is not None and end < len(data):
        fields.add("Trailer", "data after the end of the image", f"{len(data) - end} bytes")
    return fields, error


def gif_clean(data: bytes) -> bytes:
    out = bytearray()
    for kind, label, s, e in _gif_blocks(data):
        if kind == "ext":
            if label == 0xFE:
                continue
            if label == 0xFF and _gif_app_id(data, s) not in _GIF_KEEP_APPS:
                continue
            if label not in (0xF9, 0x01, 0xFF):
                continue
        out += data[s:e]
        if kind == "trailer":
            return bytes(out)
    raise FormatError("GIF: no trailer")


# ---------------------------------------------------------------------------
# TIFF (Pillow)
# ---------------------------------------------------------------------------

_TIFF_LOSSY = frozenset({"jpeg", "tiff_jpeg", "webp", "tiff_sgilog", "tiff_sgilog24"})
_TIFF_SHOWN = {
    269: "DocumentName",
    270: "ImageDescription",
    271: "Make",
    272: "Model",
    285: "PageName",
    305: "Software",
    306: "DateTime",
    315: "Artist",
    316: "HostComputer",
    33432: "Copyright",
    37724: "ImageSourceData",
    50341: "PrintIM",
    34377: "Photoshop",
}
_TIFF_STRUCTURAL = frozenset(
    {
        254,
        255,
        256,
        257,
        258,
        259,
        262,
        263,
        266,
        273,
        274,
        277,
        278,
        279,
        280,
        281,
        282,
        283,
        284,
        286,
        287,
        290,
        291,
        296,
        297,
        317,
        318,
        319,
        320,
        321,
        322,
        323,
        324,
        325,
        330,
        332,
        333,
        334,
        338,
        339,
        340,
        341,
        342,
        347,
        530,
        531,
        532,
        34675,
        700,
        33723,
        34665,
        34853,
        40965,
    }
)
# Pillow applies the orientation when it loads a TIFF; this undoes it.
_UNDO_ORIENTATION = {
    2: "FLIP_LEFT_RIGHT",
    3: "ROTATE_180",
    4: "FLIP_TOP_BOTTOM",
    5: "TRANSPOSE",
    6: "ROTATE_90",
    7: "TRANSVERSE",
    8: "ROTATE_270",
}


def tiff_fields(data: bytes) -> tuple[_Fields, str]:
    from PIL import ExifTags, Image, TiffTags

    fields = _Fields()
    try:
        im = Image.open(io.BytesIO(data))
        if im.format != "TIFF":
            return fields, f"not a TIFF ({im.format})"
        tags = dict(im.tag_v2)
    except Exception as exc:  # noqa: BLE001
        return fields, f"unreadable TIFF: {exc}"
    for tag, value in tags.items():
        if tag == 274:
            fields.add("TIFF", "Orientation", value, removable=False)
        elif tag == 34675:
            icc_field(bytes(value) if isinstance(value, (bytes, bytearray)) else b"", fields)
        elif tag == 700:
            xmp_fields(
                bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode(),
                fields,
            )
        elif tag == 33723:
            raw = value if isinstance(value, (bytes, bytearray)) else b""
            iim_fields(bytes(raw), fields)
        elif tag in _TIFF_SHOWN or (tag not in _TIFF_STRUCTURAL and tag not in TiffTags.TAGS_V2):
            fields.add("TIFF", _TIFF_SHOWN.get(tag, f"tag {tag}"), value)
        elif tag not in _TIFF_STRUCTURAL:
            fields.add("TIFF", TiffTags.lookup(tag).name, value)
    try:
        exif = im.getexif()
        for ifd_tag, group in _SUB_IFDS:
            if ifd_tag in tags:
                table = ExifTags.GPSTAGS if ifd_tag == 0x8825 else ExifTags.TAGS
                for tag, value in exif.get_ifd(ifd_tag).items():
                    fields.add(group, table.get(tag, f"0x{tag:04X}"), value)
    except Exception as exc:  # noqa: BLE001
        fields.add("EXIF", "IFD", f"<unreadable: {type(exc).__name__}>")
    return fields, ""


def tiff_clean(data: bytes) -> bytes:
    from PIL import Image, ImageSequence

    try:
        im = Image.open(io.BytesIO(data))
        compression = im.info.get("compression", "raw")
        if compression in _TIFF_LOSSY:
            raise FormatError(
                f"TIFF with {compression} compressed pixels: re-saving would re-encode them"
            )
        frames = []
        for n, frame in enumerate(ImageSequence.Iterator(im)):
            if n >= 256:
                raise FormatError("TIFF with more than 256 pages")
            orientation = frame.tag_v2.get(274)
            frame.load()
            copy = frame.copy()
            if orientation in _UNDO_ORIENTATION and frame.getexif().get(274) is None:
                method = getattr(Image.Transpose, _UNDO_ORIENTATION[orientation])
                copy = copy.transpose(method)
            frames.append((copy, orientation, frame.info.get("icc_profile"), frame.info.get("dpi")))
    except FormatError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise FormatError(f"unreadable TIFF: {exc}") from exc
    from PIL import TiffImagePlugin

    def options(orientation, icc, dpi) -> dict:
        info = TiffImagePlugin.ImageFileDirectory_v2()
        if orientation in range(1, 9):
            info[274] = orientation
        opts = {"compression": compression, "tiffinfo": info}
        if icc:
            opts["icc_profile"] = icc
        if dpi:
            opts["dpi"] = dpi
        return opts

    first, orientation, icc, dpi = frames[0]
    out = io.BytesIO()
    try:
        if len(frames) == 1:
            first.save(out, "TIFF", **options(orientation, icc, dpi))
        else:
            first.encoderinfo = {}
            rest = []
            for img, o, i, d in frames[1:]:
                img.encoderinfo = options(o, i, d)
                rest.append(img)
            first.save(
                out, "TIFF", save_all=True, append_images=rest, **options(orientation, icc, dpi)
            )
    except Exception as exc:  # noqa: BLE001
        raise FormatError(f"TIFF could not be re-saved losslessly: {exc}") from exc
    return out.getvalue()


# ---------------------------------------------------------------------------
# Image dispatch + verification
# ---------------------------------------------------------------------------

_IMAGE_READERS = {
    "jpeg": jpeg_fields,
    "png": png_fields,
    "webp": webp_fields,
    "gif": gif_fields,
    "tiff": tiff_fields,
}
_IMAGE_CLEANERS = {
    "jpeg": jpeg_clean,
    "png": png_clean,
    "webp": webp_clean,
    "gif": gif_clean,
    "tiff": tiff_clean,
}


def sniff_image(data: bytes) -> str | None:
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == _PNG_SIG:
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    return None


def image_fields(data: bytes, name: str = "") -> tuple[list[Field], str, bool]:
    fmt = sniff_image(data)
    if fmt is None:
        return [], "not a supported image (JPEG, PNG, WebP, GIF or TIFF)", False
    fields, error = _IMAGE_READERS[fmt](data)
    return list(fields), error, fields.truncated


def _frames(data: bytes):
    from PIL import Image, ImageSequence

    im = Image.open(io.BytesIO(data))
    for n, frame in enumerate(ImageSequence.Iterator(im)):
        if n >= MAX_VERIFY_FRAMES:
            return
        frame.load()
        yield frame


def pixels_equal(before: bytes, after: bytes) -> bool:
    """True when both decode to the same frames, pixel for pixel."""
    try:
        a_frames = _frames(before)
        b_frames = _frames(after)
        while True:
            fa = next(a_frames, None)
            fb = next(b_frames, None)
            if fa is None or fb is None:
                return fa is None and fb is None
            if fa.mode != fb.mode or fa.size != fb.size or fa.tobytes() != fb.tobytes():
                return False
            if fa.mode == "P" and fa.convert("RGBA").tobytes() != fb.convert("RGBA").tobytes():
                return False
    except Exception as exc:  # noqa: BLE001 - a decode failure is "not verified"
        log.info("metadata: pixel verification failed: %s", exc)
        return False


def image_clean(data: bytes) -> bytes:
    """Cleaned bytes, verified: the pixels decode identically and nothing
    removable is left. Raises FormatError otherwise."""
    fmt = sniff_image(data)
    if fmt is None:
        raise FormatError("not a supported image (JPEG, PNG, WebP, GIF or TIFF)")
    cleaned = _IMAGE_CLEANERS[fmt](data)
    if not pixels_equal(data, cleaned):
        raise FormatError("the cleaned image would not look the same; left unchanged")
    left, error, _ = image_fields(cleaned)
    if error or any(f.removable for f in left):
        raise FormatError(f"cleaning left metadata behind ({error or len(left)})")
    return cleaned


# ---------------------------------------------------------------------------
# Office (OOXML / ODF)
# ---------------------------------------------------------------------------

_OOXML_REL_TYPES = {
    "core-properties": "Office core",
    "extended-properties": "Office app",
    "custom-properties": "Office custom",
}
_OOXML_DEFAULTS = {
    "docProps/core.xml": "Office core",
    "docProps/app.xml": "Office app",
    "docProps/custom.xml": "Office custom",
}
_EMPTY_PARTS = {
    "Office core": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
        'core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'
    ),
    "Office app": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
        'extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>'
    ),
    "Office custom": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
        'custom-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>'
    ),
}
_ODF_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
_ODF_META = "urn:oasis:names:tc:opendocument:xmlns:meta:1.0"


def _odf_empty_meta(version: str | None) -> str:
    attr = f' office:version="{version}"' if version and re.fullmatch(r"\d\.\d", version) else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<office:document-meta xmlns:office="{_ODF_OFFICE}" xmlns:meta="{_ODF_META}" '
        f'xmlns:dc="http://purl.org/dc/elements/1.1/"{attr}><office:meta/></office:document-meta>'
    )


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.flag_bits & 0x1:
        raise FormatError(f"encrypted entry {info.filename!r}")
    with zf.open(info) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise FormatError(f"{info.filename!r} is larger than {limit} bytes")
    return data


def _office_open(path: str) -> tuple[zipfile.ZipFile, str, dict[str, str]]:
    """The zip, its flavour (``ooxml`` / ``odf``) and ``{member: group}`` of
    its property parts."""
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise FormatError(f"not a valid Office file (zip): {exc}") from exc
    try:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise FormatError(f"Office file with {len(infos)} entries (limit {MAX_ZIP_ENTRIES})")
        names = [i.filename for i in infos]
        if len(set(names)) != len(names):
            raise FormatError("Office file with duplicate entry names")
        declared = sum(i.file_size for i in infos)
        if declared > MAX_ZIP_UNCOMPRESSED:
            raise FormatError(
                f"Office file would unpack to {declared} bytes (limit {MAX_ZIP_UNCOMPRESSED})"
            )
        by_name = {i.filename: i for i in infos}
        if "[Content_Types].xml" in by_name:
            parts: dict[str, str] = {}
            rels = by_name.get("_rels/.rels")
            if rels is not None:
                try:
                    root = parse_xml(_read_member(zf, rels, MAX_XML_BYTES))
                    for rel in root:
                        rtype = rel.get("Type", "")
                        target = rel.get("Target", "").lstrip("/")
                        for suffix, group in _OOXML_REL_TYPES.items():
                            if rtype.endswith("/" + suffix) and target in by_name:
                                parts[target] = group
                except FormatError as exc:
                    log.info("metadata: unreadable _rels/.rels: %s", exc)
            for name, group in _OOXML_DEFAULTS.items():
                if name in by_name and name not in parts:
                    parts[name] = group
            return zf, "ooxml", parts
        mimetype = by_name.get("mimetype")
        if mimetype is not None:
            kind = _read_member(zf, mimetype, 256)
            if kind.startswith(b"application/vnd.oasis.opendocument"):
                return zf, "odf", ({"meta.xml": "ODF meta"} if "meta.xml" in by_name else {})
        raise FormatError("neither an OOXML nor an OpenDocument file")
    except BaseException:
        zf.close()
        raise


def office_fields(path: str) -> tuple[list[Field], str, bool]:
    fields = _Fields()
    try:
        zf, flavour, parts = _office_open(path)
    except FormatError as exc:
        return [], str(exc), False
    error = ""
    with zf:
        for member, group in parts.items():
            try:
                root = parse_xml(_read_member(zf, zf.getinfo(member), MAX_XML_BYTES))
            except (
                FormatError,
                zipfile.BadZipFile,
                OSError,
                RuntimeError,
                EOFError,
                zlib.error,
            ) as exc:
                error = error or f"{member}: {exc}"
                continue
            if flavour == "odf":
                meta = root.find(f"{{{_ODF_OFFICE}}}meta")
                for child in meta if meta is not None else []:
                    tag = _qname(child.tag)
                    if tag == "meta:user-defined":
                        fields.add(
                            group,
                            child.get(f"{{{_ODF_META}}}name", "user-defined"),
                            _text_of(child),
                        )
                    elif tag == "meta:document-statistic":
                        for key, value in child.attrib.items():
                            fields.add(group, _qname(key), value)
                    else:
                        fields.add(group, tag, _text_of(child) or " ".join(child.attrib.values()))
                continue
            for child in root:
                if group == "Office custom":
                    fields.add(group, child.get("name", _qname(child.tag)), _text_of(child))
                else:
                    fields.add(group, _qname(child.tag), _text_of(child))
    return list(fields), error, fields.truncated


def office_clean(src: str, dst: str) -> None:
    """Write *src* to *dst* with empty property parts (see the module docstring)."""
    zf, flavour, parts = _office_open(src)
    total = 0
    with zf:
        replacements: dict[str, bytes] = {}
        for member, group in parts.items():
            if flavour == "odf":
                version = None
                try:
                    root = parse_xml(_read_member(zf, zf.getinfo(member), MAX_XML_BYTES))
                    version = root.get(f"{{{_ODF_OFFICE}}}version")
                except FormatError:
                    pass
                replacements[member] = _odf_empty_meta(version).encode("utf-8")
            else:
                replacements[member] = _EMPTY_PARTS[group].encode("utf-8")
        try:
            with zipfile.ZipFile(dst, "w") as out:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        raise FormatError(f"encrypted entry {info.filename!r}")
                    new = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    new.compress_type = info.compress_type
                    new.external_attr = info.external_attr
                    new.create_system = info.create_system
                    if info.filename in replacements:
                        out.writestr(new, replacements[info.filename])
                        continue
                    with zf.open(info) as fh, out.open(new, "w") as sink:
                        while True:
                            chunk = fh.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_ZIP_UNCOMPRESSED:
                                raise FormatError(
                                    f"Office file unpacks to more than {MAX_ZIP_UNCOMPRESSED} bytes"
                                )
                            sink.write(chunk)
        except FormatError:
            raise
        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError,
            EOFError,
            zlib.error,
            NotImplementedError,
        ) as exc:
            raise FormatError(f"Office file could not be rewritten: {exc}") from exc
    left, error, _ = office_fields(dst)
    if error or any(f.removable for f in left):
        raise FormatError(f"cleaning left metadata behind ({error or len(left)})")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def have_pypdf() -> bool:
    try:
        import pypdf  # noqa: F401
    except Exception:  # noqa: BLE001 - any import failure means "not available"
        return False
    return True


def have_qtpdf() -> bool:
    try:
        from PyQt6.QtPdf import QPdfDocument  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _xmp_scan(data: bytes, fields: _Fields) -> None:
    """XMP packets visible in the raw bytes (uncompressed streams only)."""
    start = data.find(b"<x:xmpmeta")
    if start >= 0:
        end = data.find(b"</x:xmpmeta>", start)
        if 0 <= end < start + MAX_XML_BYTES:
            xmp_fields(data[start : end + 12], fields)
            return
        fields.add("XMP", "packet", "present")


def pdf_fields(path: str) -> tuple[list[Field], str, bool]:
    if have_pypdf():
        return _pdf_fields_pypdf(path)
    if have_qtpdf():
        return _pdf_fields_qt(path)
    return [], "reading PDF metadata needs pypdf or QtPdf, neither is installed", False


def _pdf_fields_pypdf(path: str) -> tuple[list[Field], str, bool]:
    from pypdf import PdfReader

    fields = _Fields()
    try:
        reader = PdfReader(path, strict=False)
        if reader.is_encrypted:
            return [], "the PDF is encrypted", False
        info = reader.metadata
        for key in list(info or {}):
            # Indexing (not .items()) resolves indirect references.
            fields.add("PDF Info", str(key).lstrip("/"), info[key])
        root = reader.trailer["/Root"]
        if "/Metadata" in root:
            stream = root["/Metadata"].get_object()
            raw = stream.get_data()
            xmp_fields(raw[:MAX_XML_BYTES], fields)
        for n, page in enumerate(reader.pages):
            if n >= 10_000:
                break
            if "/Metadata" in page:
                fields.add("XMP", f"page {n + 1}", "page-level XMP stream")
            if "/PieceInfo" in page:
                fields.add("PDF", f"page {n + 1} PieceInfo", "application private data")
        if "/PieceInfo" in root:
            fields.add("PDF", "PieceInfo", "application private data")
    except Exception as exc:  # noqa: BLE001 - pypdf raises many types on hostile input
        return list(fields), f"unreadable PDF: {exc}", fields.truncated
    return list(fields), "", fields.truncated


_QT_PDF_NAMES = (
    "Title",
    "Subject",
    "Author",
    "Keywords",
    "Producer",
    "Creator",
    "CreationDate",
    "ModificationDate",
)


def _pdf_fields_qt(path: str) -> tuple[list[Field], str, bool]:
    from PyQt6.QtPdf import QPdfDocument

    fields = _Fields()
    doc = QPdfDocument(None)
    try:
        error = doc.load(path)
        if error != QPdfDocument.Error.None_:
            name = getattr(error, "name", str(error))
            return [], f"QtPdf cannot read the PDF ({name})", False
        for key in _QT_PDF_NAMES:
            value = doc.metaData(getattr(QPdfDocument.MetaDataField, key))
            if hasattr(value, "isValid"):
                if not value.isValid():
                    continue
                value = value.toString("yyyy-MM-dd HH:mm:ss t")
            if value not in (None, ""):
                fields.add("PDF Info", key, value)
    finally:
        doc.close()
        doc.deleteLater()
    try:
        with open(path, "rb") as fh:
            _xmp_scan(fh.read(64 * 1024 * 1024), fields)
    except OSError:
        pass
    return list(fields), "", fields.truncated


def _pypdf_compress_options(compress) -> dict:
    """Keywords for "drop unreferenced objects, keep duplicates".

    pypdf renamed them (remove_orphans -> remove_unreferenced,
    remove_identicals -> remove_duplicates) and deprecated the old names
    for removal in 7.0, so ask the installed version which it takes.
    """
    import inspect

    params = inspect.signature(compress).parameters
    unreferenced = "remove_unreferenced" if "remove_unreferenced" in params else "remove_orphans"
    duplicates = "remove_duplicates" if "remove_duplicates" in params else "remove_identicals"
    return {duplicates: False, unreferenced: True}


def pdf_clean(src: str, dst: str) -> None:
    """Full rewrite without Info dictionary, XMP and PieceInfo (pypdf)."""
    if not have_pypdf():
        raise Unavailable("removing PDF metadata needs pypdf (pip install 'axross[metadata]')")
    from pypdf import PdfReader, PdfWriter

    try:
        reader = PdfReader(src, strict=False)
        if reader.is_encrypted:
            raise FormatError("the PDF is encrypted; its metadata cannot be rewritten")
        writer = PdfWriter(clone_from=reader)
        writer.metadata = None
        root = writer.root_object
        for key in ("/Metadata", "/PieceInfo"):
            if key in root:
                del root[key]
        for page in writer.pages:
            for key in ("/Metadata", "/PieceInfo"):
                if key in page:
                    del page[key]
        # The Info dictionary and the XMP stream are unreferenced now but
        # still among the writer's objects; without dropping orphans their
        # bytes would be written out again.
        compress = getattr(writer, "compress_identical_objects", None)
        if compress is None:
            raise Unavailable("this pypdf is too old to drop unreferenced objects; update it")
        compress(**_pypdf_compress_options(compress))
        with open(dst, "wb") as fh:
            writer.write(fh)
    except (FormatError, Unavailable):
        raise
    except Exception as exc:  # noqa: BLE001
        raise FormatError(f"the PDF could not be rewritten: {exc}") from exc
    left, error, _ = _pdf_fields_pypdf(dst)
    if error or any(f.removable for f in left):
        raise FormatError(f"cleaning left metadata behind ({error or len(left)})")


# ---------------------------------------------------------------------------
# Audio / video (external ffprobe / ffmpeg)
# ---------------------------------------------------------------------------


def ffprobe_path() -> str | None:
    return shutil.which("ffprobe")


def ffmpeg_path() -> str | None:
    return shutil.which("ffmpeg")


def run_bounded(
    argv: list[str], *, timeout: float, max_output: int, cancel: threading.Event | None = None
) -> tuple[int, bytes, bytes]:
    """Run *argv* (no shell) with a time limit, output bounds and a cancel
    event. Raises FormatError when a bound is hit or it was cancelled."""
    from core.subprocess_env import clean_child_env

    proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_child_env(),
    )
    out: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()

    def pump(name: str, stream, limit: int) -> None:
        buf = out[name]
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            if len(buf) < limit:
                buf += chunk[: limit - len(buf)]
            else:
                overflow.set()

    threads = [
        threading.Thread(target=pump, args=("stdout", proc.stdout, max_output), daemon=True),
        threading.Thread(target=pump, args=("stderr", proc.stderr, 64 * 1024), daemon=True),
    ]
    for t in threads:
        t.start()
    import time

    deadline = time.monotonic() + timeout
    reason = ""
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            reason = "cancelled"
        elif overflow.is_set():
            reason = f"output larger than {max_output} bytes"
        elif time.monotonic() > deadline:
            reason = f"timed out after {timeout:.0f} s"
        if reason:
            proc.kill()
            break
        time.sleep(0.02)
    proc.wait()
    for t in threads:
        t.join(timeout=5)
    if reason:
        raise FormatError(f"{os.path.basename(argv[0])}: {reason}")
    if overflow.is_set():
        raise FormatError(f"{os.path.basename(argv[0])}: output larger than {max_output} bytes")
    return proc.returncode, bytes(out["stdout"]), bytes(out["stderr"])


def _ff_input(path: str) -> str:
    """An input / output spec that can never be read as an option or as
    another protocol: an absolute path behind the ``file:`` prefix."""
    return "file:" + os.path.abspath(path)


_DEFAULT_HANDLERS = frozenset({"VideoHandler", "SoundHandler", "SubtitleHandler", "DataHandler"})


def _structural_tag(scope: str, key: str, value: str) -> bool:
    """Tags a remux writes on its own and that say nothing about the author."""
    k = key.lower()
    if scope == "format":
        return k in ("major_brand", "minor_version", "compatible_brands") or (
            k == "encoder" and value == "Lavf"
        )
    if k in ("language", "duration"):
        return True
    if k == "handler_name":
        return value in _DEFAULT_HANDLERS
    if k == "vendor_id":
        return value in ("FFMP", "[0][0][0][0]")
    return False


def av_fields(
    path: str, kind: str, cancel: threading.Event | None = None
) -> tuple[list[Field], str, bool]:
    probe = ffprobe_path()
    if not probe:
        return (
            [],
            "reading audio/video metadata needs ffprobe (FFmpeg), which is not installed",
            False,
        )
    argv = [
        probe,
        "-v",
        "error",
        "-hide_banner",
        "-protocol_whitelist",
        "file",
        "-format_whitelist",
        FFMPEG_FORMATS,
        "-show_format",
        "-show_streams",
        "-show_chapters",
        "-of",
        "json",
        "-i",
        _ff_input(path),
    ]
    try:
        code, out, err = run_bounded(
            argv, timeout=PROBE_TIMEOUT, max_output=MAX_PROBE_OUTPUT, cancel=cancel
        )
    except (FormatError, OSError) as exc:
        return [], str(exc), False
    if code != 0:
        return (
            [],
            "ffprobe: "
            + bounded(err.decode("utf-8", "replace").strip().splitlines()[-1:] or ["failed"]),
            False,
        )
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except ValueError as exc:
        return [], f"ffprobe output unreadable: {exc}", False
    if not isinstance(doc, dict):
        return [], "ffprobe output unreadable", False
    fields = _Fields()
    fmt = doc.get("format") if isinstance(doc.get("format"), dict) else {}
    if fmt.get("format_name"):
        fields.add(
            "Format",
            "container",
            fmt.get("format_long_name") or fmt["format_name"],
            removable=False,
        )
    if fmt.get("duration"):
        fields.add("Format", "duration", f"{fmt['duration']} s", removable=False)
    for key, value in (fmt.get("tags") or {}).items():
        fields.add("Tags", key, value, removable=not _structural_tag("format", key, str(value)))
    for stream in doc.get("streams") or []:
        if not isinstance(stream, dict):
            continue
        idx = stream.get("index", "?")
        group = f"Stream {idx}"
        ctype = stream.get("codec_type", "?")
        attached = bool((stream.get("disposition") or {}).get("attached_pic"))
        desc = f"{ctype} {stream.get('codec_name', '?')}"
        if stream.get("width"):
            desc += f" {stream['width']}x{stream['height']}"
        if attached:
            fields.add(group, "attached picture", desc, removable=(kind == AUDIO))
        elif ctype == "data":
            fields.add(group, "data stream (e.g. GPS track)", desc)
        else:
            fields.add(group, "codec", desc, removable=False)
        for key, value in (stream.get("tags") or {}).items():
            removable = not _structural_tag("stream", key, str(value))
            fields.add(group, key, value, removable=removable)
    for n, chapter in enumerate(doc.get("chapters") or []):
        if isinstance(chapter, dict):
            title = (chapter.get("tags") or {}).get("title", "")
            fields.add("Chapters", f"chapter {n + 1}", title or chapter.get("start_time", ""))
    return list(fields), "", fields.truncated


def av_clean(src: str, dst: str, kind: str, cancel: threading.Event | None = None) -> None:
    """Remux *src* into *dst* without metadata (dst must not exist; its
    extension picks the container)."""
    ffmpeg = ffmpeg_path()
    if not ffmpeg:
        raise Unavailable("removing audio/video metadata needs ffmpeg, which is not installed")
    maps = ["-map", "0", "-map", "-0:d?"]
    if kind == AUDIO:
        maps += ["-map", "-0:v?"]
    argv = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-v",
        "error",
        "-protocol_whitelist",
        "file",
        "-format_whitelist",
        FFMPEG_FORMATS,
        "-i",
        _ff_input(src),
        *maps,
        "-map_metadata",
        "-1",
        "-map_chapters",
        "-1",
        "-c",
        "copy",
        "-fflags",
        "+bitexact",
        "-flags:v",
        "+bitexact",
        "-flags:a",
        "+bitexact",
        "-n",
        _ff_input(dst),
    ]
    code, _out, err = run_bounded(argv, timeout=REMUX_TIMEOUT, max_output=64 * 1024, cancel=cancel)
    if code != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or ["failed"]
        raise FormatError("ffmpeg: " + bounded(tail[0]))
    left, error, _ = av_fields(dst, kind, cancel)
    if error or any(f.removable for f in left):
        names = ", ".join(f.name for f in left if f.removable)
        raise FormatError(f"cleaning left metadata behind ({error or names})")


__all__ = [
    "AUDIO",
    "AUDIO_EXTENSIONS",
    "Field",
    "FormatError",
    "IMAGE",
    "IMAGE_EXTENSIONS",
    "KINDS",
    "MAX_FIELDS",
    "MAX_VALUE_CHARS",
    "OFFICE",
    "OFFICE_EXTENSIONS",
    "PDF",
    "Unavailable",
    "VIDEO",
    "VIDEO_EXTENSIONS",
    "av_clean",
    "av_fields",
    "bounded",
    "exif_orientation",
    "ffmpeg_path",
    "ffprobe_path",
    "have_pypdf",
    "have_qtpdf",
    "image_clean",
    "image_fields",
    "kind_of",
    "minimal_exif",
    "office_clean",
    "office_fields",
    "parse_xml",
    "pdf_clean",
    "pdf_fields",
    "pixels_equal",
    "run_bounded",
    "sniff_image",
]
