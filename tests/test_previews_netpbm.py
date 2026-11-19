"""F3 on a .pgm, .pbm or .pnm picture shows it.

Review: the pane sends these to the image viewer (_looks_like_image), and
the viewer refused them: their MIME types were not on core.previews'
allow-list, although .ppm was and the same decoders (Qt's ppm plugin,
which reads pbm and pgm too; Pillow's PPM plugin, all of P1-P6) under the
same caps read them all.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.mark.parametrize("ext, fmt", [(".pgm", "PGM"), (".pbm", "PBM"), (".pnm", "PPM"),
                                      (".ppm", "PPM")])
def test_happy_netpbm_pictures_decode(tmp_path, ext, fmt):
    path = tmp_path / ("x" + ext)
    img = QImage(64, 48, QImage.Format.Format_RGB32)
    img.fill(QColor("blue"))
    assert img.save(str(path), fmt)
    decoded = P.decode_image(LocalFS(), str(path))
    assert (decoded.width(), decoded.height()) == (64, 48)


def test_happy_the_image_viewer_opens_a_pgm(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    path = tmp_path / "x.pgm"
    img = QImage(32, 16, QImage.Format.Format_Grayscale8)
    img.fill(QColor("gray"))
    assert img.save(str(path), "PGM")
    with mock.patch("ui.image_viewer.QMessageBox") as box:
        dlg = ImageViewerDialog(LocalFS(), str(path), siblings=[str(path)])
    try:
        assert not box.warning.called
        assert dlg.loaded
    finally:
        dlg.close()


@pytest.mark.parametrize("magic, mime", [
    (b"P1", "image/x-portable-bitmap"), (b"P4", "image/x-portable-bitmap"),
    (b"P2", "image/x-portable-graymap"), (b"P5", "image/x-portable-graymap"),
    (b"P3", "image/x-portable-pixmap"), (b"P6", "image/x-portable-pixmap"),
])
def test_edge_the_headless_sniff_knows_every_netpbm_kind(tmp_path, magic, mime):
    path = tmp_path / "x"
    path.write_bytes(magic + b"\n1 1\n" + (b"" if magic in (b"P1", b"P4") else b"255\n") + b"\x00\x00\x00")
    assert P._sniff(str(path)) == ("PPM", mime)
    assert mime in P.ALLOWED_THUMBNAIL_MIMES
