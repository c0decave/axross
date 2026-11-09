"""Round-9 content findings: drawings and texts from outside on the GUI side.

* An SVG under a raster name (``x.png``, ``x.jpg``): QMimeDatabase answers
  by the extension, the raster path's QImageReader decided the format from
  the content and Qt's svg imageformat plugin drew it in this process -
  past ``svg_refusal()`` and the killable ``svg_worker`` child (a 1.9 KB
  ``<use>`` fan-out 14.2 s, 2.2 KB more than 90 s). A PDF under a raster
  name went to Qt's pdf plugin the same way. The raster path now decodes
  with the one raster format the content check found, an SVG goes through
  the gate and the worker (media viewer) or is refused (pane), a PDF is
  refused.
* ui.markup_guard's CSS declaration regex tried every letter of a long run
  of letters: a remote file name ``<span style="aaa…">`` of 16 KB kept the
  Permissions dialog 5.8 s (24 KB 12 s, a 64 KB label 79 s). Declarations
  are now split in one pass; and rich text longer than MAX_RICH_CHARS is
  shown as written (nested allowed tags laid out in quadratic time:
  100 KB of ``<div>`` 28.7 s).
* Metadata Properties laid out every field: 2000 text chunks of Hebrew and
  Latin joined by no-break spaces, 11.6 s. Each text is cut as the mail
  view cuts one and what is laid out is capped in total.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6")

from PyQt6.QtWidgets import QApplication  # noqa: E402

import ui  # noqa: E402,F401 - installs the markup guard
from core import metadata_tools as MT  # noqa: E402
from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from ui import markup_guard as MG  # noqa: E402
from ui import metadata_dialog as MD  # noqa: E402
from ui import plain_text as PT  # noqa: E402

APP = QApplication.instance() or QApplication([])

_SVG_HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
             'width="100" height="100" viewBox="0 0 100 100">')
PLAIN_SVG = _SVG_HEAD + '<circle cx="50" cy="50" r="40" fill="red"/></svg>'


def _use_bomb(levels: int) -> str:
    body = '<path id="l0" d="M0 0 l100 100 l-100 0z" fill="red"/>'
    for i in range(1, levels + 1):
        body += f'<g id="l{i}">' + f'<use xlink:href="#l{i - 1}"/>' * 10 + "</g>"
    return _SVG_HEAD + "<defs>" + body + f'</defs><use xlink:href="#l{levels}"/></svg>'


def _write(path: Path, data) -> str:
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    return str(path)


@pytest.fixture
def backend():
    return LocalFS()


# -- M3: vector content under a raster name ------------------------------------------------------


@pytest.mark.parametrize("ext", ["png", "jpg", "gif", "webp", "tiff"])
def test_sad_an_svg_named_like_a_raster_is_not_drawn_in_the_pane(backend, tmp_path, ext) -> None:
    path = _write(tmp_path / f"x.{ext}", PLAIN_SVG)
    assert P.guess_mime(backend, path) != P.SVG_MIME  # the extension decides the MIME
    with pytest.raises(P.PreviewNotAvailable, match="SVG"):
        P.thumbnail(backend, path, edge=64, use_cache=False)
    with pytest.raises(P.PreviewNotAvailable, match="SVG"):
        P.decode_image(backend, path)


def test_sad_an_svg_bomb_named_jpg_meets_the_svg_gate_in_the_media_viewer(backend, tmp_path) -> None:
    """allow_svg=True (the media viewer): the drawing goes through
    svg_refusal() - the 10x10x10x10x10 <use> fan-out is refused at once
    instead of being drawn in this process."""
    data = _use_bomb(5)
    assert P.svg_refusal(data.encode())
    path = _write(tmp_path / "bomb.jpg", data)
    started = time.perf_counter()
    with pytest.raises(P.PreviewNotAvailable, match="references draw more"):
        P.thumbnail(backend, path, edge=64, use_cache=False, allow_svg=True)
    with pytest.raises(P.PreviewNotAvailable, match="references draw more"):
        P.decode_image(backend, path, allow_svg=True)
    assert time.perf_counter() - started < 5


def test_happy_an_svg_named_png_in_the_media_viewer_is_drawn_by_the_worker(
    backend, tmp_path, monkeypatch
) -> None:
    from core import svg_worker

    calls = []
    real = svg_worker.render_png

    def spy(data, edge, options):
        calls.append(len(data))
        return real(data, edge, options)

    monkeypatch.setattr(svg_worker, "render_png", spy)
    path = _write(tmp_path / "logo.png", PLAIN_SVG)
    result = P.thumbnail(backend, path, edge=64, use_cache=False, allow_svg=True)
    assert result.width == 64 and result.height == 64
    assert calls == [len(PLAIN_SVG)]


def _pdf_bytes(tmp_path: Path) -> bytes:
    from PyQt6.QtGui import QPageSize, QPainter, QPdfWriter

    out = tmp_path / "made.pdf"
    writer = QPdfWriter(str(out))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A6))
    painter = QPainter(writer)
    painter.drawText(100, 100, "page")
    painter.end()
    return out.read_bytes()


def test_sad_a_pdf_named_png_is_refused_not_rendered(backend, tmp_path) -> None:
    path = _write(tmp_path / "doc.png", _pdf_bytes(tmp_path))
    for allow_svg in (False, True):
        with pytest.raises(P.PreviewNotAvailable, match="PDF"):
            P.thumbnail(backend, path, edge=64, use_cache=False, allow_svg=allow_svg)
        with pytest.raises(P.PreviewNotAvailable, match="PDF"):
            P.decode_image(backend, path, allow_svg=allow_svg)


def test_happy_a_jpeg_named_png_still_decodes_with_qt(backend, tmp_path, monkeypatch) -> None:
    from PyQt6.QtGui import QColor, QImage

    image = QImage(40, 20, QImage.Format.Format_RGB32)
    image.fill(QColor(10, 200, 30))
    real = tmp_path / "real.jpg"
    assert image.save(str(real), "JPEG")
    path = _write(tmp_path / "photo.png", real.read_bytes())

    def no_pillow(*_a, **_k):
        raise AssertionError("Qt reads a JPEG")

    monkeypatch.setattr(P, "_decode_with_pillow", no_pillow)
    assert P._raster_route(path, allow_svg=False) == "jpeg"
    result = P.thumbnail(backend, path, edge=64, use_cache=False)
    assert (result.width, result.height) == (40, 20)


def test_edge_a_file_swapped_for_an_svg_after_the_check_is_not_drawn(tmp_path) -> None:
    """The decoder keeps the format the check found: SVG content read as
    PNG fails (Pillow does not read SVG either) - it is never drawn."""
    path = _write(tmp_path / "x.png", PLAIN_SVG)
    with pytest.raises(P.PreviewError):
        image, pillow = P._read_raster(path, 64, "png")
        assert image is None and pillow is None


# -- markup guard: CSS declarations, long rich text --------------------------------------------------

_OLD_DECLARATION = re.compile(r"(-?[a-z][a-z-]*)\s*:\s*([^;{}]*)", re.IGNORECASE)


@pytest.mark.parametrize("css", [
    "font-size:4000px", "color: red; font-size : 300px", "x y font-size:40px", "1:2 font-size:3px",
    "a{width:3000px}b{height:1px}", "--a-b:1px", "-qt-block-indent:99", "--:3; -a:1", ":::",
    "color:red font-size:3000px", "  ;;; width :\n 5000px ;", "a b c", "", "a:", ":a", "a-:1",
    "Font-Size:12PX", "ſ:1", "a :b:c", "　width　:　1px", "é-color:1",
])
def test_happy_declarations_are_the_pairs_the_regex_found(css) -> None:
    assert list(MG._declarations(css)) == [(m.group(1), m.group(2)) for m in _OLD_DECLARATION.finditer(css)]


def test_happy_declarations_agree_with_the_regex_on_random_styles() -> None:
    import random

    rng = random.Random(9)
    alphabet = "ab-:; {}\t1pxſK"
    for _ in range(3000):
        css = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 24)))
        expected = [(m.group(1), m.group(2)) for m in _OLD_DECLARATION.finditer(css)]
        assert list(MG._declarations(css)) == expected, repr(css)


def test_sad_a_long_run_of_letters_in_a_style_costs_linear_time() -> None:
    """24 KB took the regex about 12 s."""
    for value in ("a" * 24_000, "a-" * 12_000, "-" * 24_000, "a " * 12_000):
        started = time.perf_counter()
        assert not MG._too_large_style(value)
        assert time.perf_counter() - started < 1.0, value[:4]


def test_sad_a_huge_size_after_a_long_run_is_still_found() -> None:
    assert MG._too_large_style("a" * 20_000 + ";font-size:4000px")
    assert MG._too_large_style("b:1;" * 5000 + "width:40000px")


def test_sad_a_remote_name_with_a_long_style_builds_the_permissions_widget_quickly() -> None:
    from models.file_item import FileItem
    from ui.permissions_dialog import PermissionsWidget

    name = '<span style="' + "a" * 24_000 + '">report.pdf</span>'
    started = time.perf_counter()
    widget = PermissionsWidget(backend=None, file_path="/srv/" + name,
                               item=FileItem(name=name, permissions=0o644))
    elapsed = time.perf_counter() - started
    widget.deleteLater()
    assert elapsed < 3.0  # was 12 s


@pytest.mark.parametrize("tag", ["div", "center", "b"])
def test_sad_long_nested_allowed_tags_are_shown_as_written(tag) -> None:
    text = f"<{tag}>" * 1500 + "x" + f"</{tag}>" * 1500
    assert MG._vouched(text) and len(text) > MG.MAX_RICH_CHARS
    started = time.perf_counter()
    out = MG.defuse(text)
    assert out != text and MG.original_of(out) == text
    from PyQt6.QtWidgets import QLabel

    label = QLabel(text)
    label.adjustSize()
    assert time.perf_counter() - started < 3.0
    assert label.text() == out


def test_happy_short_rich_text_stays_rich() -> None:
    text = "<b>Hello</b> <i>world</i> " + "x" * 3000
    assert len(text) <= MG.MAX_RICH_CHARS
    assert MG.defuse(text) == text


def test_edge_the_limit_and_texts_already_escaped() -> None:
    at = "<b>x</b>" + "y" * (MG.MAX_RICH_CHARS - 8)
    assert len(at) == MG.MAX_RICH_CHARS and MG.defuse(at) == at
    over = at + "y"
    once = MG.defuse(over)
    assert once != over
    assert MG.defuse(once) == once           # not escaped twice
    assert MG.defuse("y" * 50_000) == "y" * 50_000   # plain text is no rich text
    assert not MG.too_long(once)


# -- metadata Properties ------------------------------------------------------------------------


def _report(value: str, count: int) -> MT.MetadataReport:
    return MT.MetadataReport(
        path="/x/evil.png", name="evil.png", kind="png",
        fields=[MT.Field(group=f"G{i // 50}", name=f"Tag{i}", value=value) for i in range(count)])


def _nbsp_hebrew(chars: int) -> str:
    unit = "\u05d0\u00a0a\u00a0"
    return (unit * (chars // len(unit) + 1))[:chars]


def test_sad_two_thousand_hebrew_nbsp_fields_are_capped() -> None:
    report = _report(_nbsp_hebrew(512), 2000)
    page = MD._details_html(report)
    shown = page.count("<tr") - page.count('colspan="2"')
    assert 0 < shown < 2000
    assert "more field(s) are not shown here" in page
    started = time.perf_counter()
    dialog = MD.MetadataDetailsDialog(report)
    dialog.resize(700, 600)
    dialog.show()
    APP.processEvents()
    elapsed = time.perf_counter() - started
    dialog.close()
    assert elapsed < 4.0  # was 11.6 s
    assert len(MD._field_lines(report)) == 2000  # Copy keeps every field


def test_happy_a_normal_report_is_shown_whole() -> None:
    report = _report("Canon EOS 5D", 30)
    page = MD._details_html(report)
    assert page.count("Canon EOS 5D") == 30
    assert "not shown here" not in page


def test_edge_one_huge_value_is_cut_where_the_mail_view_cuts_it() -> None:
    value = "a\u200f\u00a0" * 6000
    report = _report(value, 3)
    page = MD._details_html(report)
    end = PT.shown_length(value, MD.DETAIL_VALUE_CHARS)
    assert end < len(value)
    assert f"({len(value) - end} more characters)" in page
    assert "Tag0" in page


def _image_item(path: str):
    from core.media_collect import IMAGE, MediaItem

    st = os.stat(path)
    return MediaItem(path=path, name=os.path.basename(path), folder="", kind=IMAGE,
                     size=st.st_size, mtime=st.st_mtime)


def test_happy_a_pdf_named_png_opened_in_the_media_viewer_shows_its_first_page(tmp_path) -> None:
    """Refused by the picture decoders, the user still sees it on purpose:
    the media viewer draws its first page the way it draws a .pdf."""
    import threading

    pytest.importorskip("PyQt6.QtPdf")
    from core import media_load as ML

    path = _write(tmp_path / "scan.png", _pdf_bytes(tmp_path))
    item = _image_item(path)
    cancel = threading.Event()
    thumb = ML.thumbnail(LocalFS(), item, cancel=cancel, edge=64)
    assert max(thumb.width(), thumb.height()) == 64
    prepared = ML.prepare(LocalFS(), item, cancel=cancel, max_edge=300)
    assert prepared.image is not None and max(prepared.image.width(), prepared.image.height()) == 300


def test_happy_an_svg_named_png_opened_in_the_media_viewer_is_shown(tmp_path) -> None:
    import threading

    from core import media_load as ML

    path = _write(tmp_path / "logo.png", PLAIN_SVG)
    prepared = ML.prepare(LocalFS(), _image_item(path), cancel=threading.Event(), max_edge=200)
    assert prepared.image is not None and prepared.image.width() == 200
