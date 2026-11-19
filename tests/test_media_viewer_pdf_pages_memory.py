"""The drawn pages a PDF keeps are bounded in bytes, not only in number.

Six pages were kept whatever their size; zoomed in, each is up to
core.pdf_worker.MAX_PIXELS (24 million pixels, 96 MB): 576 MB for pages
turned back and forth. Now the pages kept stay under PDF_PAGES_BYTES
together (the page shown is always kept).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_big_drawn_pages_are_dropped_past_the_byte_bound(monkeypatch):
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    try:
        monkeypatch.setattr(MV, "PDF_PAGES_BYTES", 3 * 400 * 400 * 4)
        for page in range(6):
            image = QImage(400, 400, QImage.Format.Format_RGB32)
            viewer._on_pdf_page(("page", "/x.pdf", page, "fit", (1.0,)), (image, (400.0, 400.0)),
                                None)
        assert len(viewer._pdf_pages) == 3
        assert [k[1] for k in viewer._pdf_pages] == [3, 4, 5]
        huge = QImage(2000, 2000, QImage.Format.Format_RGB32)
        viewer._on_pdf_page(("page", "/x.pdf", 9, "fit", (1.0,)), (huge, (400.0, 400.0)), None)
        assert [k[1] for k in viewer._pdf_pages] == [9]  # the newest stays, alone
    finally:
        viewer.shutdown()
        viewer.deleteLater()
