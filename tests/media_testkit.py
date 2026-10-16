"""Media files for the media-viewer tests, generated on the spot.

Images come from Pillow, PDFs from QPdfWriter (or by hand for the encrypted
one), the video is a raw YUV4MPEG2 clip FFmpeg plays without a codec. No
downloads, nothing checked in.
"""

from __future__ import annotations

import hashlib
import io
import struct
from datetime import datetime
from pathlib import Path

from models.file_item import FileItem


def write_image(path: Path, size=(40, 30), color=(200, 30, 30), fmt: str | None = None) -> Path:
    from PIL import Image

    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", size, color).save(path, format=fmt)
    return path


def write_pdf(path: Path, pages: int = 2) -> Path:
    from PyQt6.QtGui import QColor, QPageSize, QPainter, QPdfWriter

    path.parent.mkdir(parents=True, exist_ok=True)
    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A6))
    painter = QPainter(writer)
    colors = ("red", "blue", "green", "black")
    for n in range(pages):
        if n:
            writer.newPage()
        painter.fillRect(0, 0, writer.width(), writer.height(), QColor(colors[n % len(colors)]))
    painter.end()
    return path


_PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def encrypted_pdf_bytes(user: bytes = b"secret", owner: bytes = b"owner") -> bytes:
    """A one-page PDF behind the standard security handler (RC4-40, R2)
    with a non-empty user password: it opens only with that password."""
    up = (user + _PAD)[:32]
    op = (owner + _PAD)[:32]
    o_entry = _rc4(hashlib.md5(op).digest()[:5], up)
    perms = -44
    doc_id = b"0123456789abcdef"
    key = hashlib.md5(up + o_entry + struct.pack("<i", perms) + doc_id).digest()[:5]
    u_entry = _rc4(key, _PAD)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Filter /Standard /V 1 /R 2 /O <%s> /U <%s> /P %d >>"
        % (o_entry.hex().encode(), u_entry.hex().encode(), perms),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    hex_id = doc_id.hex().encode()
    out += b"trailer\n<< /Size %d /Root 1 0 R /Encrypt 4 0 R /ID [<%s> <%s>] >>\n" % (
        len(objs) + 1,
        hex_id,
        hex_id,
    )
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def video_bytes(frames: int = 5, width: int = 16, height: int = 16, fps: int = 10) -> bytes:
    """A raw YUV4MPEG2 clip; FFmpeg probes the content, not the extension."""
    data = bytearray(b"YUV4MPEG2 W%d H%d F%d:1 Ip A1:1 C420jpeg\n" % (width, height, fps))
    for n in range(frames):
        data += b"FRAME\n" + bytes([n * 40 % 256]) * (width * height)
        data += bytes([128]) * (width * height // 2)
    return bytes(data)


class MemoryBackend:
    """A non-local backend over a dict of path -> bytes.

    ``listed_sizes`` lets a test make the listing lie about a size;
    ``fail_reads`` makes open_read raise for those paths.
    """

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = dict(files)
        self.listed_sizes: dict[str, int] = {}
        self.fail_reads: set[str] = set()
        self.reads: list[str] = []

    @property
    def name(self) -> str:
        return "memory"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return "/".join(p.rstrip("/") for p in parts)

    def normalize(self, path: str) -> str:
        return path

    def list_dir(self, path: str) -> list[FileItem]:
        prefix = path.rstrip("/") + "/"
        names: dict[str, FileItem] = {}
        for full, data in self.files.items():
            if not full.startswith(prefix):
                continue
            rest = full[len(prefix) :]
            head = rest.split("/", 1)[0]
            if "/" in rest:
                names[head] = FileItem(name=head, is_dir=True)
            else:
                size = self.listed_sizes.get(full, len(data))
                names[head] = FileItem(name=head, size=size, modified=datetime(2026, 1, 2))
        if not names and not any(f.startswith(prefix) for f in self.files):
            raise OSError(f"no such folder: {path}")
        return list(names.values())

    def open_read(self, path: str):
        self.reads.append(path)
        if path in self.fail_reads:
            raise OSError("connection reset")
        if path not in self.files:
            raise FileNotFoundError(path)
        return io.BytesIO(self.files[path])
