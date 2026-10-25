"""Decoding for the media viewer and the thumbnails does no needless work.

Measured (8000x8000 PNG, 4000x4000 TIFF; core.media_load.prepare, the media
viewer's decode):

* A picture Qt does not read here (TIFF: no plugin) or not at full size
  (over QIMAGE_ALLOC_LIMIT_MIB: an 8000x8000 PNG) goes through Pillow, which
  handed back PNG bytes that were then decoded again: 0.4 s PNG encode plus
  0.1 s decode of a 4096x4096 picture, a third of the 1.5 s the viewer
  waited for the 8000x8000 PNG and two thirds of the 0.7 s for the TIFF. The
  viewer now gets the pixels directly - the same pixels.
* A thumbnail is stored as PNG. Qt's default PNG compression took 5.9 ms for
  a 128 px tile of a photo (28 ms at 256 px), most of a thumbnail's cost;
  compression level 4 takes 1.7 ms (8 ms) for files of the same size.
"""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6")
pytest.importorskip("PIL")
np = pytest.importorskip("numpy")

from PIL import Image  # noqa: E402
from PyQt6.QtCore import QBuffer, QIODevice  # noqa: E402
from PyQt6.QtGui import QGuiApplication, QImage  # noqa: E402

from core import previews  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QGuiApplication.instance() or QGuiApplication([])


@pytest.fixture
def backend():
    return LocalFS()


def _noise(mode: str, size=(96, 64), seed: int = 1) -> Image.Image:
    rng = np.random.default_rng(seed)
    w, h = size
    bands = {"RGB": 3, "RGBA": 4, "L": 1, "LA": 2}
    if mode == "P":
        img = _noise("RGB", size, seed).quantize(64)
        return img
    if mode == "I;16":
        return Image.fromarray(rng.integers(0, 65535, (h, w), dtype=np.uint16))
    arr = rng.integers(0, 256, (h, w, bands[mode]), dtype=np.uint8)
    return Image.fromarray(arr[:, :, 0] if bands[mode] == 1 else arr, mode)


def _argb(image: QImage) -> bytes:
    """The pixels as ARGB32 bytes, row padding removed (a comparable form)."""
    img = image.convertToFormat(QImage.Format.Format_ARGB32)
    ptr = img.constBits()
    ptr.setsize(img.sizeInBytes())
    data = bytes(ptr)
    row = img.width() * 4
    return b"".join(data[y * img.bytesPerLine(): y * img.bytesPerLine() + row]
                    for y in range(img.height()))


def _old_path(path: str, edge: int) -> QImage:
    """What the viewer got before: Pillow's PNG bytes decoded by Qt."""
    return QImage.fromData(previews._decode_with_pillow(path, edge), "PNG")


# --- happy -------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["RGB", "RGBA", "L", "LA", "P", "I;16"])
def test_happy_the_viewer_gets_the_same_pixels_from_pillow_without_png(
    backend, tmp_path, monkeypatch, mode
) -> None:
    path = tmp_path / f"pic_{mode.replace(';', '')}.tif"
    _noise(mode).save(path)
    expected = _old_path(str(path), 4096)
    assert not expected.isNull()

    real_save = Image.Image.save

    def no_png(self, fp, format=None, **params):  # noqa: A002 - PIL's name
        if (format or "").upper() == "PNG":
            raise AssertionError("the viewer's decode encoded a PNG")
        return real_save(self, fp, format, **params)

    monkeypatch.setattr(Image.Image, "save", no_png)
    image = previews.decode_image(backend, str(path))
    assert (image.width(), image.height()) == (expected.width(), expected.height())
    assert image.hasAlphaChannel() == expected.hasAlphaChannel()
    assert _argb(image) == _argb(expected)


def test_happy_a_big_png_over_the_qt_budget_has_the_same_pixels(
    backend, tmp_path, monkeypatch
) -> None:
    """Over QIMAGE_ALLOC_LIMIT_MIB Qt refuses and Pillow decodes, scaled
    to the viewer's edge - the same result as before."""
    monkeypatch.setattr(previews, "QIMAGE_ALLOC_LIMIT_MIB", 1)
    path = tmp_path / "big.png"
    _noise("RGB", size=(900, 700)).save(path)
    expected = _old_path(str(path), 600)
    image = previews.decode_image(backend, str(path), max_edge=600)
    assert (image.width(), image.height()) == (600, 467)
    assert _argb(image) == _argb(expected)


def test_happy_a_thumbnail_png_is_lossless_and_of_the_measured_level(backend, tmp_path) -> None:
    path = tmp_path / "photo.png"
    _noise("RGB", size=(300, 200)).save(path)
    result = previews.thumbnail(backend, str(path), edge=128, use_cache=False)
    decoded = QImage.fromData(result.data, "PNG")
    reader_image = previews._read_raster(str(path), 128)[0]
    assert _argb(decoded) == _argb(reader_image)
    # Qt maps a quality to zlib's level as (100 - quality) * 9 // 91.
    assert (100 - previews.THUMBNAIL_PNG_QUALITY) * 9 // 91 == previews.THUMBNAIL_PNG_LEVEL == 4


def test_happy_a_thumbnail_png_encodes_much_faster_than_qt_default() -> None:
    # Like a photo's tile: a noisy picture saved as JPEG, read back and
    # scaled down (pure noise does not compress at any level, so every
    # level takes the same time on it). Measured: 17 ms against 8 ms; on
    # tiles of real photos 28 against 8.
    from PyQt6.QtCore import Qt

    rng = np.random.default_rng(7)
    y, x = np.mgrid[0:768, 0:1024].astype(np.float32)
    rgb = np.stack([np.sin(x / 50) * 127 + 128, np.cos(y / 40) * 127 + 128,
                    (x + y) / 1800 * 255], -1) + rng.normal(0, 10, (768, 1024, 3))
    arr = np.ascontiguousarray(np.clip(rgb, 0, 255).astype(np.uint8))
    big = QImage(arr.data, 1024, 768, 1024 * 3, QImage.Format.Format_RGB888)
    jpeg = QBuffer()
    jpeg.open(QIODevice.OpenModeFlag.ReadWrite)
    assert big.save(jpeg, "JPEG", 88)
    image = QImage.fromData(bytes(jpeg.data()), "JPEG").scaled(
        256, 192, Qt.AspectRatioMode.IgnoreAspectRatio,
        Qt.TransformationMode.SmoothTransformation).convertToFormat(QImage.Format.Format_RGB32)

    def best(fn, runs: int = 9) -> float:
        times = []
        for _ in range(runs):
            start = time.perf_counter()
            fn()
            times.append(time.perf_counter() - start)
        return min(times)

    def default() -> bytes:
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        image.save(buf, "PNG")
        return bytes(buf.data())

    ours = best(lambda: previews._png_bytes(image))
    theirs = best(default)
    assert ours < 0.75 * theirs, (ours, theirs)
    assert QImage.fromData(previews._png_bytes(image), "PNG").convertToFormat(
        QImage.Format.Format_RGB32) == image


def test_happy_a_pillow_thumbnail_reports_its_size_without_decoding_it(
    backend, tmp_path, monkeypatch
) -> None:
    path = tmp_path / "t.tif"
    _noise("RGB", size=(400, 100)).save(path)
    calls = []
    real = QImage.fromData

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(QImage, "fromData", staticmethod(counting))
    result = previews.thumbnail(backend, str(path), edge=128, use_cache=False)
    assert (result.width, result.height) == (128, 32)
    assert calls == []
    assert Image.open(io.BytesIO(result.data)).size == (128, 32)


# --- sad ---------------------------------------------------------------------


def test_sad_a_broken_tiff_still_fails_to_decode(backend, tmp_path) -> None:
    path = tmp_path / "broken.tif"
    path.write_bytes(b"II*\x00" + b"\x00" * 64)
    with pytest.raises(previews.PreviewDecodeFailed):
        previews.decode_image(backend, str(path))


def test_sad_the_pillow_memory_budget_still_holds_for_the_viewer(backend, tmp_path) -> None:
    path = tmp_path / "huge.tif"
    Image.new("1", (12000, 12000)).save(path)  # tiny on disk, 576 MiB as RGBA
    with pytest.raises(previews.PreviewTooLarge):
        previews.decode_image(backend, str(path))


# --- edge --------------------------------------------------------------------


def test_edge_a_one_pixel_and_an_odd_width_picture_keep_their_rows(backend, tmp_path) -> None:
    for size in ((1, 1), (3, 5), (101, 7)):
        path = tmp_path / f"odd_{size[0]}x{size[1]}.tif"
        _noise("RGB", size=size).save(path)
        expected = _old_path(str(path), 4096)
        image = previews.decode_image(backend, str(path))
        assert _argb(image) == _argb(expected), size


def test_edge_a_palette_picture_with_transparency_keeps_it(backend, tmp_path) -> None:
    img = _noise("P", size=(40, 30))
    img.info["transparency"] = 0
    path = tmp_path / "pal.gif"
    img.save(path, transparency=0)
    expected = _old_path(str(path), 4096)
    image = previews._qimage_from_pillow(
        previews._decode_with_pillow(str(path), 4096, encode=False))
    assert image.hasAlphaChannel() == expected.hasAlphaChannel()
    assert _argb(image) == _argb(expected)
