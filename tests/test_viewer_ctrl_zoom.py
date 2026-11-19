"""Ctrl + / Ctrl - / Ctrl 0 and Ctrl + wheel zoom images and PDFs.

The user: "the pdf/image viewer should support Ctrl + and - to zoom in or
out of images / PDFs". The image viewer (F3 on a picture) only knew the
bare + / - / 0, so Ctrl + did nothing there; in the media viewer a PDF
ignored Ctrl + wheel, and its first zoom step from "fit" jumped to 125 %
of the page's own size - smaller than the fitted page on a big window.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QWheelEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import open_limits as OL  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, PDF, MediaItem  # noqa: E402
from tests.media_testkit import requires_qtpdf, write_image, write_pdf  # noqa: E402

APP = QApplication.instance() or QApplication([])
CTRL = Qt.KeyboardModifier.ControlModifier
KEYPAD = Qt.KeyboardModifier.KeypadModifier


def wait_until(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)


def _focused(window):
    window.activateWindow()
    APP.processEvents()
    return APP.focusWidget() or window


def _ctrl_wheel(widget, up: bool = True) -> None:
    pos = QPointF(widget.width() / 2, widget.height() / 2)
    event = QWheelEvent(
        pos,
        widget.mapToGlobal(pos),
        QPoint(0, 0),
        QPoint(0, 120 if up else -120),
        Qt.MouseButton.NoButton,
        CTRL,
        Qt.ScrollPhase.NoScrollPhase,
        False,
    )
    APP.sendEvent(widget, event)
    APP.processEvents()


def _item(path: Path, kind: str) -> MediaItem:
    return MediaItem(str(path), path.name, "", kind, path.stat().st_size, path.stat().st_mtime)


def test_happy_image_viewer_zooms_with_ctrl_plus_minus_and_zero(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    path = str(write_image(tmp_path / "a.png", size=(300, 200)))
    dlg = ImageViewerDialog(LocalFS(), path, siblings=[path])
    try:
        dlg.resize(800, 600)
        dlg.show()
        assert wait_until(lambda: dlg._original is not None)
        dlg._reset_zoom()
        for key, mods, expected in (
            (Qt.Key.Key_Plus, CTRL, 1.25),
            (Qt.Key.Key_Equal, CTRL, 1.5625),
            (Qt.Key.Key_Minus, CTRL, 1.25),
            (Qt.Key.Key_0, CTRL, 1.0),
            (Qt.Key.Key_Plus, CTRL | KEYPAD, 1.25),
            (Qt.Key.Key_Minus, CTRL | KEYPAD, 1.0),
            (Qt.Key.Key_Plus, Qt.KeyboardModifier.NoModifier, 1.25),  # bare + still zooms
            (Qt.Key.Key_0, Qt.KeyboardModifier.NoModifier, 1.0),
        ):
            QTest.keyClick(_focused(dlg), key, mods)
            assert dlg._zoom == pytest.approx(expected), (key, mods)
    finally:
        dlg.close()


def test_happy_image_viewer_zooms_with_ctrl_wheel(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    path = str(write_image(tmp_path / "a.png", size=(300, 200)))
    dlg = ImageViewerDialog(LocalFS(), path, siblings=[path])
    try:
        dlg.resize(800, 600)
        dlg.show()
        assert wait_until(lambda: dlg._original is not None)
        dlg._reset_zoom()
        _ctrl_wheel(dlg._scroll.viewport(), up=True)
        assert dlg._zoom == pytest.approx(1.25)
        _ctrl_wheel(dlg._scroll.viewport(), up=False)
        assert dlg._zoom == pytest.approx(1.0)
    finally:
        dlg.close()


def test_happy_media_viewer_image_zooms_with_ctrl_keys(tmp_path):
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(640, 480)
    viewer.show()
    viewer.set_items([_item(write_image(tmp_path / "i.png", size=(200, 100)), IMAGE)], 0)
    try:
        assert wait_until(lambda: viewer.mode == "image")
        QTest.keyClick(_focused(viewer), Qt.Key.Key_0, CTRL)
        assert viewer.zoom_factor == pytest.approx(1.0)
        QTest.keyClick(_focused(viewer), Qt.Key.Key_Plus, CTRL)
        assert viewer.zoom_factor == pytest.approx(1.25)
        QTest.keyClick(_focused(viewer), Qt.Key.Key_Minus, CTRL)
        assert viewer.zoom_factor == pytest.approx(1.0)
    finally:
        viewer.shutdown()


@requires_qtpdf
def test_happy_pdf_zooms_in_from_fit_and_with_ctrl_wheel(tmp_path):
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(1200, 1000)  # an A6 page fits at well over 125 %
    viewer.show()
    viewer.set_items([_item(write_pdf(tmp_path / "d.pdf", pages=2), PDF)], 0)
    try:
        assert wait_until(lambda: viewer.mode == "pdf")
        assert viewer.fit_mode
        fitted = viewer._pdf_shown_zoom()
        assert fitted > 1.5
        QTest.keyClick(_focused(viewer), Qt.Key.Key_Plus, CTRL)
        assert not viewer.fit_mode
        assert viewer.zoom_factor == pytest.approx(fitted * 1.25, rel=0.02)
        QTest.keyClick(_focused(viewer), Qt.Key.Key_Minus, CTRL)
        assert viewer.zoom_factor == pytest.approx(fitted, rel=0.02)
        QTest.keyClick(_focused(viewer), Qt.Key.Key_0, CTRL)
        assert viewer.zoom_factor == pytest.approx(1.0)
        _ctrl_wheel(viewer._pdf_view.viewport(), up=True)
        assert viewer.zoom_factor == pytest.approx(1.25)
        _ctrl_wheel(viewer._pdf_view.viewport(), up=False)
        assert viewer.zoom_factor == pytest.approx(1.0)
    finally:
        viewer.shutdown()
