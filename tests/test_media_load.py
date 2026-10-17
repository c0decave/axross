"""Turning one collected media item into something the viewer can show.

Covers the decoder entry points the media viewer adds to core.previews
(full-size decode, the SVG gate), the bounded remote copy shared with the
analysis dock, and core.media_load: thumbnails and prepared items for
local and remote files, with every refusal ending in a reason, not a crash.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_analysis as FA  # noqa: E402
from core import media_load as ML  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import previews as P  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, PDF, VIDEO, MediaItem  # noqa: E402
from tests.media_testkit import (  # noqa: E402
    MemoryBackend,
    encrypted_pdf_bytes,
    video_bytes,
    write_image,
    write_pdf,
)

APP = QApplication.instance() or QApplication([])
MIB = 1024 * 1024

SVG_OK = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100">
  <rect width="200" height="100" fill="#00ff00"/>
</svg>
"""


@pytest.fixture(autouse=True)
def _normal_mode_and_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)


def _item(path: str, kind: str, size: int) -> MediaItem:
    return MediaItem(
        path=path, name=os.path.basename(path), folder="", kind=kind, size=size, mtime=0.0
    )


def _local_item(path: Path, kind: str) -> MediaItem:
    return _item(str(path), kind, path.stat().st_size)


# -- previews.decode_image ------------------------------------------------------


def test_happy_decode_image_keeps_full_size_beyond_the_thumbnail_clamp(tmp_path):
    p = write_image(tmp_path / "big.png", size=(3000, 1000))
    img = P.decode_image(LocalFS(), str(p))
    assert (img.width(), img.height()) == (3000, 1000)


def test_edge_decode_image_scales_down_to_max_edge(tmp_path):
    p = write_image(tmp_path / "big.png", size=(3000, 1000))
    img = P.decode_image(LocalFS(), str(p), max_edge=600)
    assert (img.width(), img.height()) == (600, 200)


def test_sad_decode_image_refuses_a_dimension_bomb(tmp_path):
    p = write_image(tmp_path / "wide.png", size=(P.MAX_DIMENSION + 1, 2))
    with pytest.raises(P.PreviewTooLarge):
        P.decode_image(LocalFS(), str(p))


def test_sad_decode_image_refuses_a_corrupt_file(tmp_path):
    p = tmp_path / "broken.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00garbage" * 50)
    with pytest.raises(P.PreviewError):
        P.decode_image(LocalFS(), str(p))


def test_sad_decode_image_is_blocked_in_paranoid_mode(tmp_path):
    p = write_image(tmp_path / "a.png")
    security_mode.set_policy("paranoid")
    with pytest.raises(PermissionError):
        P.decode_image(LocalFS(), str(p))


# -- the SVG gate -----------------------------------------------------------------


def test_happy_a_plain_svg_renders_to_the_requested_edge(tmp_path):
    p = tmp_path / "a.svg"
    p.write_bytes(SVG_OK)
    img = P.decode_image(LocalFS(), str(p), max_edge=400, allow_svg=True)
    assert (img.width(), img.height()) == (400, 200)
    assert img.pixelColor(10, 10).green() == 255


def test_happy_svg_thumbnail_when_allowed(tmp_path):
    p = tmp_path / "a.svg"
    p.write_bytes(SVG_OK)
    result = P.thumbnail(LocalFS(), str(p), edge=64, use_cache=False, allow_svg=True)
    assert (result.width, result.height) == (64, 32)
    assert result.mime == "image/svg+xml"


def test_happy_svg_options_name_each_animation_kind(tmp_path):
    # Qt 6.10.0 (the one in the 0.10.24 bundle) segfaults in
    # QSvgRenderer.load() for every SVG when the options carry the combined
    # DisableAnimations value (0xF0); the same kinds named one by one load.
    from PyQt6.QtSvg import QtSvg

    opts = P._svg_options(QtSvg)
    O = QtSvg.Option
    assert opts.value == (
        O.Tiny12FeaturesOnly.value | O.DisableSMILAnimations.value | O.DisableCSSAnimations.value
    )


def test_sad_the_pane_thumbnail_still_refuses_svg_by_default(tmp_path):
    p = tmp_path / "a.svg"
    p.write_bytes(SVG_OK)
    with pytest.raises(P.PreviewNotAvailable):
        P.thumbnail(LocalFS(), str(p), use_cache=False)
    with pytest.raises(P.PreviewNotAvailable):
        P.decode_image(LocalFS(), str(p))


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg xmlns="http://www.w3.org/2000/svg">&a;</svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
        b'<image xlink:href="file:///etc/passwd" width="5" height="5"/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.invalid/x.png"/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://x.invalid/a)"/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject/></svg>',
        b'<?xml-stylesheet href="evil.css"?><svg xmlns="http://www.w3.org/2000/svg"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><style>@import "x.css";</style></svg>',
    ],
)
def test_sad_the_svg_gate_refuses_entities_scripts_and_outside_references(tmp_path, body):
    p = tmp_path / "evil.svg"
    p.write_bytes(body)
    assert P.svg_refusal(body) is not None
    with pytest.raises(P.PreviewNotAvailable):
        P.decode_image(LocalFS(), str(p), allow_svg=True)


def test_edge_the_svg_gate_accepts_internal_references_and_embedded_rasters():
    body = (
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
        b'<defs><linearGradient id="g"/></defs><rect fill="url(#g)"/>'
        b'<use xlink:href="#g"/><image href="data:image/png;base64,AAAA"/></svg>'
    )
    assert P.svg_refusal(body) is None


def test_sad_svg_options_never_carry_the_combined_animation_value():
    from PyQt6.QtSvg import QtSvg

    combined = QtSvg.Option.DisableAnimations.value
    single = QtSvg.Option.DisableSMILAnimations.value | QtSvg.Option.DisableCSSAnimations.value
    assert P._svg_options(QtSvg).value & combined & ~single == 0


def test_edge_svg_options_on_a_qt_without_animation_options():
    import enum
    import types

    class Option(enum.Enum):  # Qt 6.7: no animation options yet
        NoOption = 0
        Tiny12FeaturesOnly = 1

    assert P._svg_options(types.SimpleNamespace(Option=Option)).value == 1
    assert P._svg_options(types.SimpleNamespace()) is None  # Qt < 6.7


def test_edge_the_svg_gate_refuses_utf16_and_oversized_input(tmp_path):
    assert P.svg_refusal(SVG_OK.decode().encode("utf-16")) is not None
    p = tmp_path / "huge.svg"
    p.write_bytes(SVG_OK + b"<!--" + b"x" * (P.MAX_SVG_INPUT_SIZE + 1) + b"-->")
    with pytest.raises(P.PreviewTooLarge):
        P.decode_image(LocalFS(), str(p), allow_svg=True)


# -- the bounded remote copy ------------------------------------------------------


def _target(backend, path: str, size: int) -> FA.Target:
    return FA.Target(backend=backend, path=path, name=os.path.basename(path), size=size, mtime=0.0)


def test_happy_copy_bounded_copies_and_cleans_up():
    backend = MemoryBackend({"/r/a.bin": b"hello"})
    copy = FA.copy_bounded(_target(backend, "/r/a.bin", 5), 100, threading.Event(), 5.0)
    try:
        assert copy.status == "ok"
        assert Path(copy.path).read_bytes() == b"hello"
    finally:
        copy.cleanup()
    assert not os.path.exists(copy.path)


def test_sad_copy_bounded_reports_a_file_bigger_than_the_limit():
    backend = MemoryBackend({"/r/a.bin": b"x" * 50})
    copy = FA.copy_bounded(_target(backend, "/r/a.bin", 5), 10, threading.Event(), 5.0)
    copy.cleanup()
    assert copy.status == "too_large"
    assert copy.total == 11  # one byte past the limit is enough to know


def test_sad_copy_bounded_reports_a_read_error():
    backend = MemoryBackend({"/r/a.bin": b"x"})
    backend.fail_reads.add("/r/a.bin")
    copy = FA.copy_bounded(_target(backend, "/r/a.bin", 1), 10, threading.Event(), 5.0)
    copy.cleanup()
    assert copy.status == "error"
    assert "connection reset" in copy.error


def test_edge_copy_bounded_honours_a_cancel_set_before_it_starts():
    backend = MemoryBackend({"/r/a.bin": b"x"})
    cancel = threading.Event()
    cancel.set()
    copy = FA.copy_bounded(_target(backend, "/r/a.bin", 1), 10, cancel, 5.0)
    copy.cleanup()
    assert copy.status == "cancelled"


# -- media_load: local ------------------------------------------------------------


def test_happy_local_image_thumbnail_and_prepare(tmp_path):
    p = write_image(tmp_path / "a.png", size=(800, 400))
    item = _local_item(p, IMAGE)
    thumb = ML.thumbnail(LocalFS(), item, cancel=threading.Event(), edge=100)
    assert (thumb.width(), thumb.height()) == (100, 50)
    prepared = ML.prepare(LocalFS(), item, cancel=threading.Event())
    assert (prepared.image.width(), prepared.image.height()) == (800, 400)
    prepared.release()


def test_happy_local_pdf_prepare_counts_pages_and_thumbnail_renders(tmp_path):
    p = write_pdf(tmp_path / "doc.pdf", pages=3)
    item = _local_item(p, PDF)
    prepared = ML.prepare(LocalFS(), item, cancel=threading.Event())
    assert prepared.page_count == 3
    assert prepared.local_path == str(p)
    prepared.release()
    assert p.exists()  # a local file is never removed by release()
    thumb = ML.thumbnail(LocalFS(), item, cancel=threading.Event(), edge=120)
    assert max(thumb.width(), thumb.height()) == 120
    assert thumb.pixelColor(thumb.width() // 2, thumb.height() // 2).red() > 200


def test_sad_encrypted_pdf_gives_a_reason(tmp_path):
    p = tmp_path / "locked.pdf"
    p.write_bytes(encrypted_pdf_bytes())
    with pytest.raises(ML.MediaUnavailable, match="password"):
        ML.prepare(LocalFS(), _local_item(p, PDF), cancel=threading.Event())
    with pytest.raises(ML.MediaUnavailable, match="password"):
        ML.thumbnail(LocalFS(), _local_item(p, PDF), cancel=threading.Event())


def test_sad_broken_pdf_gives_a_reason(tmp_path):
    p = tmp_path / "broken.pdf"
    p.write_bytes(b"%PDF-1.4\nnot really")
    with pytest.raises(ML.MediaUnavailable, match="not a valid PDF"):
        ML.prepare(LocalFS(), _local_item(p, PDF), cancel=threading.Event())


def test_sad_corrupt_image_gives_a_reason(tmp_path):
    p = tmp_path / "broken.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 64)
    with pytest.raises(ML.MediaUnavailable):
        ML.prepare(LocalFS(), _local_item(p, IMAGE), cancel=threading.Event())


def test_sad_huge_image_gives_a_size_reason(tmp_path):
    p = write_image(tmp_path / "wide.png", size=(P.MAX_DIMENSION + 1, 2))
    with pytest.raises(ML.MediaUnavailable, match="too large"):
        ML.prepare(LocalFS(), _local_item(p, IMAGE), cancel=threading.Event())


def test_sad_local_pdf_over_the_open_limit_is_refused(tmp_path):
    OL.set_max_open_mb(1)
    p = tmp_path / "big.pdf"
    p.write_bytes(b"%PDF-1.4\n" + b"0" * (MIB + 10))
    with pytest.raises(ML.MediaUnavailable, match="Open Size Limit"):
        ML.prepare(LocalFS(), _local_item(p, PDF), cancel=threading.Event())


def test_edge_local_video_is_streamed_without_a_size_limit(tmp_path):
    OL.set_max_open_mb(1)
    p = tmp_path / "clip.mp4"
    p.write_bytes(video_bytes() + b"\x00" * (MIB + 10))
    prepared = ML.prepare(LocalFS(), _local_item(p, VIDEO), cancel=threading.Event())
    assert prepared.local_path == str(p)
    with pytest.raises(ML.MediaUnavailable):
        ML.thumbnail(LocalFS(), _local_item(p, VIDEO), cancel=threading.Event())


def test_sad_a_local_item_that_vanished_gives_a_reason(tmp_path):
    item = _item(str(tmp_path / "gone.png"), IMAGE, 10)
    with pytest.raises(ML.MediaUnavailable):
        ML.prepare(LocalFS(), item, cancel=threading.Event())


def test_sad_paranoid_mode_blocks_every_kind(tmp_path):
    p = write_pdf(tmp_path / "doc.pdf", pages=1)
    security_mode.set_policy("paranoid")
    with pytest.raises(ML.MediaUnavailable, match="security mode"):
        ML.prepare(LocalFS(), _local_item(p, PDF), cancel=threading.Event())


# -- media_load: remote -----------------------------------------------------------


def _png_bytes(tmp_path, size=(64, 32)) -> bytes:
    return write_image(tmp_path / "src.png", size=size).read_bytes()


def test_happy_remote_image_goes_through_a_temp_copy_that_is_removed(tmp_path, monkeypatch):
    made = []
    real = FA.copy_bounded

    def spy(*a, **kw):
        copy = real(*a, **kw)
        made.append(copy)
        return copy

    monkeypatch.setattr(FA, "copy_bounded", spy)
    backend = MemoryBackend({"/r/a.png": _png_bytes(tmp_path)})
    item = _item("/r/a.png", IMAGE, len(backend.files["/r/a.png"]))
    prepared = ML.prepare(backend, item, cancel=threading.Event())
    assert prepared.image.width() == 64
    thumb = ML.thumbnail(backend, item, cancel=threading.Event(), edge=16)
    assert thumb.width() == 16
    assert len(made) == 2
    assert all(not os.path.exists(c.tmpdir) for c in made)


def test_happy_remote_pdf_keeps_its_copy_until_released(tmp_path):
    data = write_pdf(tmp_path / "src.pdf", pages=2).read_bytes()
    backend = MemoryBackend({"/r/doc.pdf": data})
    prepared = ML.prepare(backend, _item("/r/doc.pdf", PDF, len(data)), cancel=threading.Event())
    assert prepared.page_count == 2
    assert os.path.exists(prepared.local_path)
    prepared.release()
    assert not os.path.exists(prepared.local_path)


def test_sad_remote_item_listed_over_the_limit_is_not_downloaded(tmp_path):
    OL.set_max_open_mb(1)
    backend = MemoryBackend({"/r/clip.mp4": b"x"})
    item = _item("/r/clip.mp4", VIDEO, 5 * MIB)
    with pytest.raises(ML.MediaUnavailable, match="Open Size Limit"):
        ML.prepare(backend, item, cancel=threading.Event())
    assert backend.reads == []


def test_sad_remote_item_bigger_than_listed_is_cut_off(tmp_path):
    OL.set_max_open_mb(1)
    backend = MemoryBackend({"/r/doc.pdf": b"%PDF" + b"0" * (2 * MIB)})
    item = _item("/r/doc.pdf", PDF, 10)  # the listing lied
    with pytest.raises(ML.MediaUnavailable, match="Open Size Limit"):
        ML.prepare(backend, item, cancel=threading.Event())


def test_edge_remote_image_limit_is_the_smaller_of_open_limit_and_decoder_cap(tmp_path):
    OL.set_max_open_mb(OL.MAX_MAX_OPEN_MB)
    backend = MemoryBackend({"/r/a.png": b"x"})
    item = _item("/r/a.png", IMAGE, P.MAX_INPUT_SIZE + 1)
    with pytest.raises(ML.MediaUnavailable, match="too large"):
        ML.prepare(backend, item, cancel=threading.Event())
    assert backend.reads == []


def test_sad_remote_read_error_gives_a_reason(tmp_path):
    backend = MemoryBackend({"/r/a.png": b"x"})
    backend.fail_reads.add("/r/a.png")
    with pytest.raises(ML.MediaUnavailable, match="connection reset"):
        ML.prepare(backend, _item("/r/a.png", IMAGE, 1), cancel=threading.Event())


def test_edge_remote_cancel_gives_cancelled():
    backend = MemoryBackend({"/r/a.png": b"x"})
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ML.MediaUnavailable, match="cancelled"):
        ML.prepare(backend, _item("/r/a.png", IMAGE, 1), cancel=cancel)
