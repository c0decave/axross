"""The test-suite guard that releases keyboard modifiers a test left held."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLineEdit  # noqa: E402

from tests.qt_modifier_guard import release_held_modifiers  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_a_held_shift_is_released_and_reported() -> None:
    edit = QLineEdit()
    edit.show()
    QTest.keyPress(edit, Qt.Key.Key_Shift, Qt.KeyboardModifier.ShiftModifier)
    assert APP.keyboardModifiers() == Qt.KeyboardModifier.ShiftModifier
    held = release_held_modifiers(APP)
    assert held == Qt.KeyboardModifier.ShiftModifier
    assert APP.keyboardModifiers() == Qt.KeyboardModifier.NoModifier
    edit.deleteLater()


def test_sad_nothing_held_is_left_alone() -> None:
    assert release_held_modifiers(APP) == Qt.KeyboardModifier.NoModifier


def test_sad_a_modifier_shortcut_is_not_an_error_of_the_test() -> None:
    # Under the offscreen platform every QTest event with a modifier
    # leaves it held - keyClick(Ctrl+A) included. The autouse guard
    # releases it after this test; failing the test would fail every
    # shortcut test in the suite.
    edit = QLineEdit()
    edit.show()
    QTest.keyClick(edit, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
    assert APP.keyboardModifiers() == Qt.KeyboardModifier.ControlModifier
    edit.deleteLater()


def test_edge_the_next_test_starts_with_no_modifier_held() -> None:
    # Runs after the test above (pytest keeps file order).
    assert APP.keyboardModifiers() == Qt.KeyboardModifier.NoModifier


def test_edge_ctrl_and_shift_without_any_window() -> None:
    edit = QLineEdit()
    edit.show()
    QTest.keyPress(edit, Qt.Key.Key_Control, Qt.KeyboardModifier.ControlModifier)
    QTest.keyPress(
        edit,
        Qt.Key.Key_Shift,
        Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
    )
    edit.close()
    edit.deleteLater()
    APP.processEvents()
    held = release_held_modifiers(APP)
    assert held & Qt.KeyboardModifier.ControlModifier and held & Qt.KeyboardModifier.ShiftModifier
    assert APP.keyboardModifiers() == Qt.KeyboardModifier.NoModifier
