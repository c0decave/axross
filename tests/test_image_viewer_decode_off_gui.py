"""The image viewer decodes off the GUI thread, without a PNG round trip.

Measured: opening a 4000x3000 photo took 14 s on the GUI thread - the
viewer went through core.previews.thumbnail, which encoded the decoded
picture as a PNG (11.8 s) for the viewer to decode that again (1.0-1.4 s),
capped at 2048 px; every Prev / Next did it again with the window frozen.
It uses core.previews.decode_image now (the media viewer's full-window
decode: the same security gates, no PNG, up to 4096 px) on a worker
through ui.off_gui.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _photos(tmp_path, n=2):
    paths = []
    for i in range(n):
        image = QImage(640, 480, QImage.Format.Format_RGB32)
        image.fill(QColor(40 * i, 90, 160))
        path = tmp_path / f"p{i}.png"
        image.save(str(path))
        paths.append(str(path))
    return paths


def test_happy_open_and_next_decode_off_the_gui_thread_without_a_png(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    paths = _photos(tmp_path)
    real = P.decode_image
    threads: list[str] = []

    def decode(backend, path, **kw):
        threads.append(threading.current_thread().name)
        return real(backend, path, **kw)

    with mock.patch.object(P, "decode_image", decode), \
            mock.patch.object(P, "thumbnail", side_effect=AssertionError("PNG round trip")):
        dlg = ImageViewerDialog(LocalFS(), paths[0], siblings=paths)
        try:
            assert dlg._original is not None and dlg._original.width() == 640
            dlg._idx = 1
            dlg._load_current()
            assert dlg._original.pixelColor(0, 0) == QColor(40, 90, 160)
        finally:
            dlg.close()
            dlg.deleteLater()
    assert len(threads) == 2 and "MainThread" not in threads


def test_sad_a_refused_picture_is_still_said_and_closes_the_viewer(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    paths = _photos(tmp_path, 1)
    with mock.patch.object(P, "decode_image", side_effect=P.PreviewTooLarge("bomb")), \
            mock.patch.object(QMessageBox, "warning") as warning:
        dlg = ImageViewerDialog(LocalFS(), paths[0], siblings=paths)
    assert "bomb" in warning.call_args.args[2]
    dlg.deleteLater()
