"""A mouse button a test left held is released before the next test.

Found on 2026-11-02: under the offscreen platform QTest.mouseDClick leaves
the left button held for the rest of the process. ui.dock_fit leaves the
docks alone while a button is down (a user may be dragging one), so after
tests/test_folder_treemap_layout.py's double-click, 16 tests of
tests/test_dock_column_fit.py in the same process found nothing fitted.
tests/conftest.py releases it after every test, as it does for keyboard
modifiers.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from tests.qt_modifier_guard import release_held_mouse_buttons  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_a_held_button_is_released():
    widget = QWidget()
    widget.resize(100, 100)
    widget.show()
    try:
        QTest.mouseDClick(widget, Qt.MouseButton.LeftButton, pos=QPoint(10, 10))
        held = APP.mouseButtons()
        if held == Qt.MouseButton.NoButton:
            pytest.skip("this Qt releases the button after a double-click")
        released = release_held_mouse_buttons(APP)
        assert released == held
        assert APP.mouseButtons() == Qt.MouseButton.NoButton
    finally:
        widget.close()
        widget.deleteLater()


def test_edge_nothing_held_is_left_alone():
    assert APP.mouseButtons() == Qt.MouseButton.NoButton  # the guard ran after the test above
    assert release_held_mouse_buttons(APP) == Qt.MouseButton.NoButton
