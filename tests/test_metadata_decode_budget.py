"""Decode and inflate budgets of the image metadata reader and cleaner.

Security review round 2 found three unbounded paths:

* ``image_clean`` / ``pixels_equal`` decoded both images in full and
  ``tobytes()``-copied them with no pixel budget: a 1.5 MB PNG declaring
  20000 x 20000 pixels took about 7.7 GB. ``core.previews`` made it worse
  by raising Pillow's *global* ``MAX_IMAGE_PIXELS`` to 20000**2 at import.
* PNG zTXt / compressed iTXt chunks were capped at 256 KiB each but had no
  budget per file, and inflating went on after ``MAX_FIELDS`` was reached:
  a 32 MiB file cost about 2.5 minutes of CPU, with no way to cancel.

The tests use counters and mocks instead of real gigabyte decodes, so they
stay small; each carries a timeout.
"""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import threading
import zlib
from pathlib import Path

import pytest

from core import metadata_formats as MF

pytestmark = pytest.mark.timeout(60)

ROOT = Path(__file__).resolve().parent.parent


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def _png(width: int, height: int, colour_type: int, *chunks: bytes, idat: bytes = b"") -> bytes:
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, colour_type, 0, 0, 0))
    return (
        b"\x89PNG\r\n\x1a\n"
        + ihdr
        + b"".join(chunks)
        + _chunk(b"IDAT", idat or zlib.compress(b"\0\0"))
        + _chunk(b"IEND", b"")
    )


def _ztxt(key: bytes, inflated: int) -> bytes:
    return _chunk(b"zTXt", key + b"\0\0" + zlib.compress(b"A" * inflated, 9))


class _CountingZlib:
    """Stands in for ``zlib`` inside metadata_formats and counts what every
    ``decompressobj().decompress`` call produced."""

    error = zlib.error

    def __init__(self) -> None:
        self.calls = 0
        self.inflated = 0

    def decompressobj(self, *a, **kw):
        real = zlib.decompressobj(*a, **kw)
        outer = self

        class _D:
            def decompress(self, data, limit=0):
                outer.calls += 1
                out = real.decompress(data, limit)
                outer.inflated += len(out)
                return out

            @property
            def unconsumed_tail(self):
                return real.unconsumed_tail

        return _D()

    def __getattr__(self, name):
        return getattr(zlib, name)


# ---------------------------------------------------------------------------
# Pixel budget
# ---------------------------------------------------------------------------


def test_sad_image_clean_refuses_a_pixel_bomb_before_decoding(monkeypatch):
    """A PNG declaring 12000 x 12000 RGBA (549 MiB decoded) was decoded in
    full - twice, plus two ``tobytes()`` copies. Now it is refused from the
    header and no pixel is decoded."""
    from PIL import ImageFile

    loads = []

    def no_load(self, *a, **kw):
        loads.append(self.size)
        raise MemoryError("decoded although over the budget")

    monkeypatch.setattr(ImageFile.ImageFile, "load", no_load)
    data = _png(12000, 12000, 6, _chunk(b"tEXt", b"Author\0someone"))
    with pytest.raises(MF.FormatError, match="too large to verify"):
        MF.image_clean(data)
    assert loads == []


def test_sad_previews_import_leaves_pillows_global_pixel_limit_alone():
    """Importing core.previews raised ``PIL.Image.MAX_IMAGE_PIXELS`` to
    400 million for the whole process."""
    code = (
        "from PIL import Image; before = Image.MAX_IMAGE_PIXELS; "
        "import core.previews; print(before == Image.MAX_IMAGE_PIXELS)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60
    )
    assert out.stdout.strip() == "True", out.stderr


def test_happy_pixels_equal_compares_in_strips_never_a_whole_frame(monkeypatch):
    """``pixels_equal`` copied every frame whole with ``tobytes()``; now it
    hashes strips, and still sees one changed pixel in the last row and a
    changed palette."""
    from PIL import Image

    def png_bytes(im) -> bytes:
        buf = io.BytesIO()
        im.save(buf, "PNG")
        return buf.getvalue()

    a = Image.new("RGB", (200, 200), (10, 20, 30))
    b = a.copy()
    b.putpixel((199, 199), (10, 20, 31))
    monkeypatch.setattr(MF, "VERIFY_STRIP_BYTES", 8 * 1024, raising=False)
    sizes = []
    real = Image.Image.tobytes

    def counting(self, *args, **kw):
        out = real(self, *args, **kw)
        sizes.append(len(out))
        return out

    monkeypatch.setattr(Image.Image, "tobytes", counting)
    assert MF.pixels_equal(png_bytes(a), png_bytes(a.copy()))
    assert not MF.pixels_equal(png_bytes(a), png_bytes(b))
    assert sizes and max(sizes) < 200 * 200 * 3

    p1 = Image.new("P", (64, 64), 1)
    p1.putpalette([0, 0, 0, 255, 0, 0] + [0] * 762)
    p2 = p1.copy()
    p2.putpalette([0, 0, 0, 0, 255, 0] + [0] * 762)
    assert not MF.pixels_equal(png_bytes(p1), png_bytes(p2))


def test_sad_tiff_clean_stops_when_the_pages_exceed_what_it_may_hold(monkeypatch):
    """The TIFF re-save keeps every page decoded (up to 256) with no byte
    budget."""
    from PIL import Image

    pages = [Image.new("L", (100, 100), n) for n in range(3)]
    buf = io.BytesIO()
    pages[0].save(buf, "TIFF", save_all=True, append_images=pages[1:])
    monkeypatch.setattr(MF, "MAX_TIFF_HELD_BYTES", 25_000, raising=False)
    with pytest.raises(MF.FormatError, match="too large"):
        MF.tiff_clean(buf.getvalue())


# ---------------------------------------------------------------------------
# PNG compressed text
# ---------------------------------------------------------------------------


def test_sad_png_compressed_text_has_one_inflate_budget_per_file(monkeypatch):
    """40 zTXt chunks of 256 KiB each inflated to 10 MiB; one file now
    inflates at most MAX_PNG_INFLATE_TOTAL, and the rest are listed as not
    expanded."""
    counter = _CountingZlib()
    data = _png(1, 1, 0, *(_ztxt(b"k%d" % n, 256 * 1024) for n in range(40)))
    monkeypatch.setattr(MF, "zlib", counter)
    fields, error, _truncated = MF.image_fields(data)
    assert error == ""
    assert counter.inflated <= 4 * 1024 * 1024
    assert len([f for f in fields if f.group == "PNG text"]) == 40
    assert "budget" in fields[-1].value


def test_sad_png_stops_inflating_once_the_fields_are_truncated(monkeypatch):
    """After MAX_FIELDS fields the reader went on inflating every further
    chunk although nothing more was listed."""
    counter = _CountingZlib()
    texts = [_chunk(b"tEXt", b"k\0v") for _ in range(MF.MAX_FIELDS + 5)]
    data = _png(1, 1, 0, *texts, *(_ztxt(b"z", 1024) for _ in range(50)))
    monkeypatch.setattr(MF, "zlib", counter)
    fields, _error, truncated = MF.image_fields(data)
    assert truncated
    assert len(fields) == MF.MAX_FIELDS
    assert counter.calls == 0


def test_edge_png_reader_honours_a_cancel_event(monkeypatch):
    """The zTXt walk could not be cancelled."""
    counter = _CountingZlib()
    data = _png(1, 1, 0, *(_ztxt(b"z", 1024) for _ in range(10)))
    monkeypatch.setattr(MF, "zlib", counter)
    cancel = threading.Event()
    cancel.set()
    _fields, error, _truncated = MF.image_fields(data, cancel=cancel)
    assert error == "cancelled"
    assert counter.calls == 0
