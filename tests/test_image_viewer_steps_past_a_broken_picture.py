"""One corrupt picture no longer closes the image viewer (review round 3).

Before: any picture that failed to decode showed a box and closed the
viewer - stepping with Next onto a corrupt file in a folder of photos
ended the whole session, and Prev / Next could not step past it. Now a
picture that fails after one was shown says so in its place; the viewer
stays, and Next goes on to the following picture. (A viewer whose very
first picture fails still says why and does not open.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _folder(tmp_path):
    paths = []
    for name, colour in (("a.png", QColor(200, 0, 0)), ("c.png", QColor(0, 0, 200))):
        image = QImage(64, 48, QImage.Format.Format_RGB32)
        image.fill(colour)
        image.save(str(tmp_path / name))
    (tmp_path / "b.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"broken" * 50)
    for name in ("a.png", "b.png", "c.png"):
        paths.append(str(tmp_path / name))
    return paths


def test_sad_next_onto_a_corrupt_picture_keeps_the_viewer_open(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    paths = _folder(tmp_path)
    with mock.patch.object(QMessageBox, "warning") as warning:
        dlg = ImageViewerDialog(LocalFS(), paths[0], siblings=paths)
        try:
            dlg.show()
            assert dlg.loaded
            dlg._next()
            APP.processEvents()
            assert dlg.isVisible(), "the corrupt picture closed the viewer"
            assert warning.call_count == 0  # said in place, not in a box
            assert "b.png" in dlg._label.text() and "b.png" in dlg._info.text()
            assert dlg._label.pixmap() is None or dlg._label.pixmap().isNull()

            dlg._next()  # steps past it
            assert dlg._original is not None
            assert dlg._original.pixelColor(0, 0) == QColor(0, 0, 200)
            assert "c.png" in dlg._info.text()
        finally:
            dlg.close()
            dlg.deleteLater()


def test_edge_prev_steps_back_past_it_too_and_zoom_is_harmless(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    paths = _folder(tmp_path)
    with mock.patch.object(QMessageBox, "warning"):
        dlg = ImageViewerDialog(LocalFS(), paths[2], siblings=paths)
        try:
            dlg.show()
            dlg._prev()  # onto b.png
            assert dlg.isVisible() and dlg._original is None
            dlg._zoom_by(2.0)  # nothing to zoom: no error
            dlg._fit_window()
            dlg._rotate_cw()
            dlg._prev()
            assert dlg._original is not None
            assert dlg._original.pixelColor(0, 0) == QColor(200, 0, 0)
        finally:
            dlg.close()
            dlg.deleteLater()
