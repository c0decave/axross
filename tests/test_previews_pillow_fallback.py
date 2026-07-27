"""Tests for the Pillow decode fallback in :mod:`core.previews`.

Qt in this environment has no TIFF plugin
(``QImageReader.supportedImageFormats()`` lacks ``tiff``), so
``thumbnail()`` used to raise ``PreviewDecodeFailed`` for ``.tif``/
``.tiff``. Pillow IS installed and can decode those, so ``thumbnail()``
now falls back to Pillow whenever the Qt ``QImageReader`` path cannot
decode the image.

Covers happy path (TIFF/multi-page/CMYK), sad path (Pillow absent /
unreadable), and edge cases (dimension + input-size caps, and that
Qt-decodable formats like PNG still take the Qt path).
"""

from __future__ import annotations

import pytest

# Hard-skip the whole module if PyQt6 or Pillow aren't importable —
# these tests are meaningless without both.
pytest.importorskip("PyQt6")
pytest.importorskip("PIL")

from PIL import Image  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402

from core import previews  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture
def backend():
    return LocalFS()


# ---------------------------------------------------------------------------
# Happy path — formats Qt can't decode here, Pillow can
# ---------------------------------------------------------------------------


def test_tiff_decodes_via_pillow_fallback(backend, tmp_path):
    """A plain RGB TIFF (no Qt plugin) is decoded by the Pillow
    fallback and returns non-empty PNG bytes that QImage can load at
    the original 40x30 size. This would raise PreviewDecodeFailed
    before the fix."""
    p = tmp_path / "img.tiff"
    Image.new("RGB", (40, 30), (10, 20, 30)).save(p)

    result = previews.thumbnail(backend, str(p), edge=10000, use_cache=False)

    assert result.data, "expected non-empty PNG bytes"
    assert result.mime == "image/tiff"
    qimg = QImage.fromData(result.data, "PNG")
    assert not qimg.isNull()
    assert qimg.width() == 40
    assert qimg.height() == 30


def test_multipage_tiff_decodes_first_page(backend, tmp_path):
    """A multi-page TIFF decodes its first page without error; the
    returned dimensions match page 0 (40x30), not page 1 (10x10)."""
    p = tmp_path / "multi.tiff"
    page0 = Image.new("RGB", (40, 30), (1, 2, 3))
    page1 = Image.new("RGB", (10, 10), (9, 9, 9))
    page0.save(p, save_all=True, append_images=[page1])

    result = previews.thumbnail(backend, str(p), edge=10000, use_cache=False)

    qimg = QImage.fromData(result.data, "PNG")
    assert not qimg.isNull()
    assert qimg.width() == 40
    assert qimg.height() == 30


def test_cmyk_tiff_decodes_via_pillow(backend, tmp_path):
    """A CMYK TIFF (not a PNG-friendly mode) is converted to RGBA and
    decoded without error."""
    p = tmp_path / "cmyk.tiff"
    Image.new("CMYK", (20, 20)).save(p)

    result = previews.thumbnail(backend, str(p), edge=10000, use_cache=False)

    qimg = QImage.fromData(result.data, "PNG")
    assert not qimg.isNull()
    assert qimg.width() == 20
    assert qimg.height() == 20


# ---------------------------------------------------------------------------
# Qt-decodable formats must NOT use the Pillow fallback
# ---------------------------------------------------------------------------


def test_png_uses_qt_path_not_pillow(backend, tmp_path, monkeypatch):
    """PNG is decodable by Qt, so the Pillow fallback must never run.
    We sabotage the fallback to raise; PNG must still succeed."""
    p = tmp_path / "ok.png"
    Image.new("RGB", (24, 24), (5, 5, 5)).save(p)

    def _boom(*_a, **_k):
        raise AssertionError("Pillow fallback should not run for PNG")

    monkeypatch.setattr(previews, "_decode_with_pillow", _boom)

    result = previews.thumbnail(backend, str(p), edge=10000, use_cache=False)

    assert result.mime == "image/png"
    qimg = QImage.fromData(result.data, "PNG")
    assert not qimg.isNull()
    assert qimg.width() == 24
    assert qimg.height() == 24


# ---------------------------------------------------------------------------
# Caps — dimension bomb + input-size gate still enforced
# ---------------------------------------------------------------------------


def test_dimension_cap_enforced_in_pillow_fallback(backend, tmp_path, monkeypatch):
    """A TIFF larger than MAX_DIMENSION is rejected with
    PreviewTooLarge — the Pillow path must enforce the cap before a
    full decode."""
    monkeypatch.setattr(previews, "MAX_DIMENSION", 8)
    p = tmp_path / "big.tiff"
    Image.new("RGB", (40, 30)).save(p)

    with pytest.raises(previews.PreviewTooLarge):
        previews.thumbnail(backend, str(p), edge=10000, use_cache=False)


def test_input_size_gate_enforced_before_decode(backend, tmp_path, monkeypatch):
    """The existing MAX_INPUT_SIZE gate (file st_size) still fires
    before any decode."""
    monkeypatch.setattr(previews, "MAX_INPUT_SIZE", 4)
    p = tmp_path / "toobig.tiff"
    Image.new("RGB", (40, 30)).save(p)

    with pytest.raises(previews.PreviewTooLarge):
        previews.thumbnail(backend, str(p), edge=10000, use_cache=False)


# ---------------------------------------------------------------------------
# Sad path — Pillow not installed
# ---------------------------------------------------------------------------


def test_pillow_absent_raises_decode_failed_with_hint(backend, tmp_path, monkeypatch):
    """When Pillow isn't importable and Qt can't decode, the fallback
    raises PreviewDecodeFailed carrying an install hint."""
    p = tmp_path / "img.tiff"
    Image.new("RGB", (40, 30)).save(p)

    monkeypatch.setattr(previews, "_PILImage", None)

    with pytest.raises(previews.PreviewDecodeFailed) as exc:
        previews.thumbnail(backend, str(p), edge=10000, use_cache=False)
    assert "Pillow" in str(exc.value)
