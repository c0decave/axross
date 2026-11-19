"""A Markdown document's pictures cannot hold the reader: no SVG drawn in the
process, no PDF or PostScript taken for a picture.

Review (round 1 of the release reviews):

* ui.markdown_view.decode() drew an SVG with Qt's image reader in this
  process. Its check (svg_refers) looks at what an SVG names, not at what it
  draws: ten levels of ten ``<use>`` - 1.9 KB, also as a ``data:`` image in
  the text, of any file on any connection - held a reader thread 7.6 s, a
  ninth level more than a minute, uninterruptible, 200 such pictures a page.
  The media viewer had long sent SVG through core.previews' gate and the
  killable drawing process (core.svg_worker); the reader now does too
  (core.svg_gate, a time budget per document).
* The image reader picked its decoder by the content: a "picture" that is a
  PDF was drawn by pdfium in the reader's process. Only raster formats (and
  SVG, as above) are read now.
* axross-mdcat let Pillow pick the decoder too: a file named pic.png holding
  PostScript went to Ghostscript (Pillow's EPS plugin runs ``gs`` on load).
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

from core.local_fs import LocalFS  # noqa: E402
from ui import markdown_view as MDV  # noqa: E402

HEAD = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        b'width="100" height="100">')


def fan_out(levels: int, fan: int = 10) -> bytes:
    parts = [HEAD, b'<defs><g id="l0"><path d="M0 0 L100 100 L0 100 Z" fill="red"/></g>']
    for level in range(1, levels):
        uses = b"".join(b'<use xlink:href="#l%d"/>' % (level - 1) for _ in range(fan))
        parts.append(b'<g id="l%d">%s</g>' % (level, uses))
    parts.append(b'</defs><use xlink:href="#l%d"/></svg>' % (levels - 1))
    return b"".join(parts)


def costly() -> bytes:
    """Within the gate (about a thousand elements drawn), slow to draw: one
    filled path of many segments, drawn again and again."""
    path = "M0 0 " + " ".join(f"L{(i * 37) % 100} {(i * 61) % 100}" for i in range(6000)) + " Z"
    uses = "".join('<use xlink:href="#p"/>' for _ in range(900))
    return HEAD + f'<defs><path id="p" d="{path}" fill="blue"/></defs>{uses}</svg>'.encode()


def test_safety_a_use_bomb_is_refused_at_once():
    started = time.monotonic()
    image, why = MDV.decode(fan_out(8))
    assert image is None and why
    assert time.monotonic() - started < 3.0


def test_safety_a_use_bomb_as_a_data_image_is_refused(tmp_path):
    source = MDV.ImageSource(LocalFS(), str(tmp_path / "a.md"))
    name = "data:image/svg+xml;base64," + base64.b64encode(fan_out(9)).decode()
    started = time.monotonic()
    found = source.read([name])
    assert isinstance(found[name], str)
    assert time.monotonic() - started < 3.0


def test_safety_a_slow_svg_is_stopped_by_the_documents_time(monkeypatch):
    budget = {"left": MDV.IMAGES_PIXELS, "lock": __import__("threading").Lock(), "svg": 1.0}
    started = time.monotonic()
    image, why = MDV.decode(costly(), budget)
    took = time.monotonic() - started
    assert image is None and why, "drawn after all"
    assert took < 6.0, took
    # the document's time is used up: the next SVG is not drawn at all
    started = time.monotonic()
    image, why = MDV.decode(costly(), budget)
    assert image is None and time.monotonic() - started < 1.0


def test_happy_an_svg_is_still_drawn_at_its_size():
    data = (b'<?xml version="1.0"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
            b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
            b'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20">'
            b'<rect width="40" height="20" fill="#00ff00"/></svg>')
    image, why = MDV.decode(data)
    assert why is None and isinstance(image, QImage)
    assert (image.width(), image.height()) == (40, 20)
    assert image.pixelColor(20, 10).green() > 200


def test_safety_a_pdf_is_no_picture():
    pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
           b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
           b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 50 50]>>endobj\n"
           b"trailer<</Root 1 0 R>>\n%%EOF\n")
    image, why = MDV.decode(pdf)
    assert image is None and why


def test_happy_raster_pictures_are_still_read():
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice

    picture = QImage(30, 10, QImage.Format.Format_RGB32)
    picture.fill(0x336699)
    for fmt in ("PNG", "BMP", "JPG", "TIFF", "PPM"):
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        assert picture.save(buffer, fmt)
        image, why = MDV.decode(bytes(data))
        assert why is None and (image.width(), image.height()) == (30, 10), fmt


# -- the terminal ---------------------------------------------------------------------------


def test_safety_mdcat_never_hands_postscript_to_ghostscript(tmp_path, monkeypatch):
    PIL = pytest.importorskip("PIL")
    from PIL import EpsImagePlugin

    from core import markdown_term as MT

    opened = []
    monkeypatch.setattr(EpsImagePlugin.EpsImageFile, "_open",
                        lambda self: opened.append(1) or (_ for _ in ()).throw(SyntaxError("no")))
    eps = (b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n"
           b"newpath 0 0 moveto 10 10 lineto stroke showpage\n")
    (tmp_path / "pic.png").write_bytes(eps)
    found = MT.read_picture(str(tmp_path / "pic.png"), folder=str(tmp_path))
    assert isinstance(found, str)
    assert isinstance(MT.decode_picture(eps), str)
    assert not opened, "Pillow tried the file as EPS (Ghostscript)"
    assert PIL is not None


def test_happy_mdcat_still_reads_a_png(tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image

    from core import markdown_term as MT

    Image.new("RGB", (8, 4), (10, 200, 30)).save(tmp_path / "p.png")
    found = MT.read_picture(str(tmp_path / "p.png"), folder=str(tmp_path))
    assert not isinstance(found, str) and found.size == (8, 4)


def test_happy_the_frozen_program_answers_as_the_svg_drawing_process(monkeypatch):
    """A frozen axross-markdown has no ``python -c``: core.svg_worker starts
    the program itself with --svg-worker, which must draw, not open windows
    for files named "-1" and "6324"."""
    from core import svg_worker
    from ui import markdown_app

    called = []
    monkeypatch.setattr(svg_worker, "_child_main", lambda: called.append(1) or 0)
    monkeypatch.setattr(markdown_app, "run", lambda *a, **k: pytest.fail("a window was opened"))
    monkeypatch.setattr(svg_worker.sys, "frozen", True, raising=False)
    argv = ["axross-markdown", *svg_worker.worker_argv(-100)[1:]]
    assert argv[1] == "--svg-worker"
    assert markdown_app.main(argv) == 0 and called == [1]
