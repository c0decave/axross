"""Photos are shown and converted upright (review round 3).

Before: the EXIF orientation was ignored everywhere. A phone photo stored
sideways with "rotate 90 degrees" in its EXIF data was shown sideways in
the image viewer, the thumbnails and the media viewer (``core.previews``
read it with a plain ``QImageReader``, the Pillow fallback with no
``exif_transpose``), and Image Batch made that permanent: its copy was
sideways and carried no orientation tag any more. Image Batch also wrote
a transparent PNG as a JPEG on black. Now both decoders turn the picture
upright, and a JPEG gets its transparent parts on white.
"""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path

import pytest

pytest.importorskip("PyQt6")
pytest.importorskip("PIL")

from PIL import Image  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import previews  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ORIENTATION = 0x0112


@pytest.fixture(scope="module", autouse=True)
def app():
    return QApplication.instance() or QApplication([])


def _sideways(fmt: str = "JPEG", orientation: int = 6) -> bytes:
    """A 400 x 200 picture, red left half and blue right half, whose
    EXIF data says: turn 90 degrees clockwise to show it (200 x 400)."""
    image = Image.new("RGB", (400, 200), (0, 0, 255))
    image.paste((255, 0, 0), (0, 0, 200, 200))
    exif = Image.Exif()
    exif[ORIENTATION] = orientation
    buf = io.BytesIO()
    image.save(buf, fmt, exif=exif.tobytes())
    return buf.getvalue()


def _batch():
    spec = importlib.util.spec_from_file_location(
        "image_batch_upright", ROOT / "resources" / "extensions" / "image_batch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_happy_the_viewer_shows_a_sideways_photo_upright(tmp_path):
    photo = tmp_path / "phone.jpg"
    photo.write_bytes(_sideways())
    image = previews.decode_image(LocalFS(), str(photo))
    assert (image.width(), image.height()) == (200, 400)
    # Turned clockwise: the stored left (red) half is now on top.
    top = image.pixelColor(100, 50)
    assert top.red() > 200 and top.blue() < 60


def test_happy_the_thumbnail_is_upright_too(tmp_path):
    photo = tmp_path / "phone.jpg"
    photo.write_bytes(_sideways())
    result = previews.thumbnail(LocalFS(), str(photo), edge=100, use_cache=False)
    thumb = QImage.fromData(result.data, "PNG")
    assert (thumb.width(), thumb.height()) == (50, 100)


def test_edge_the_pillow_fallback_turns_the_picture_upright(tmp_path, monkeypatch):
    """A picture that Qt cannot read here goes through Pillow - upright too."""
    import PyQt6.QtGui as QtGui

    class _Reader(QtGui.QImageReader):
        def canRead(self) -> bool:
            return False

    monkeypatch.setattr(QtGui, "QImageReader", _Reader)
    photo = tmp_path / "phone.jpg"
    photo.write_bytes(_sideways())
    image = previews.decode_image(LocalFS(), str(photo))
    assert (image.width(), image.height()) == (200, 400)


def test_edge_a_thumbnail_cached_sideways_is_not_served_again(tmp_path, monkeypatch):
    """The cache key changed with the orientation, so a thumbnail cached
    by an older axross is made again."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    photo = tmp_path / "phone.jpg"
    photo.write_bytes(_sideways())
    st = photo.stat()
    old = __import__("hashlib").sha256()
    old.update(str(photo).encode())
    old.update(b"\x00")
    old.update(f"{st.st_mtime:.6f}:{st.st_size}:100".encode())
    root = previews._cache_root()
    sideways = QImage(100, 50, QImage.Format.Format_RGB32)
    sideways.fill(0)
    sideways.save(str(root / (old.hexdigest() + ".png")), "PNG")
    result = previews.thumbnail(LocalFS(), str(photo), edge=100)
    assert not result.from_cache
    assert (result.width, result.height) == (50, 100)


def test_happy_image_batch_writes_the_photo_upright_without_the_tag():
    out = _batch().convert(_sideways(), 100, "JPEG")
    written = Image.open(io.BytesIO(out))
    assert written.size == (50, 100)
    # No orientation left that would turn the upright copy once more.
    assert written.getexif().get(ORIENTATION) in (None, 1)


def test_edge_image_batch_honours_every_orientation_value():
    """8: turn 90 degrees counter-clockwise - the red half lands at the bottom."""
    out = _batch().convert(_sideways(orientation=8), 0, "PNG")
    written = Image.open(io.BytesIO(out)).convert("RGB")
    assert written.size == (200, 400)
    assert written.getpixel((100, 350))[0] > 200
    assert written.getpixel((100, 50))[2] > 200


def test_sad_a_transparent_png_becomes_a_jpeg_on_white_not_black():
    image = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    image.paste((0, 128, 0, 255), (0, 0, 16, 16))
    buf = io.BytesIO()
    image.save(buf, "PNG")
    out = _batch().convert(buf.getvalue(), 0, "JPEG")
    written = Image.open(io.BytesIO(out)).convert("RGB")
    assert all(channel > 240 for channel in written.getpixel((24, 24)))
    red, green, blue = written.getpixel((4, 4))  # the opaque part is kept
    assert green > 90 and red < 40 and blue < 40
    # A PNG keeps its transparency.
    out = _batch().convert(buf.getvalue(), 0, "PNG")
    assert Image.open(io.BytesIO(out)).convert("RGBA").getpixel((24, 24))[3] == 0

