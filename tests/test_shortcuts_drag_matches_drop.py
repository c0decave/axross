"""F1 help says what a drag does, read from the code that decides it.

Found in review (round 1, UI): the shortcuts dialog listed "Drag: Copy"
and "Ctrl+Drag: Move", the reverse of ``file_pane._drop_action`` (Ctrl
copies, anything else moves; also docs/USAGE.md). A user following the
help moved files they meant to copy.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui.file_pane import _drop_action  # noqa: E402
from ui.shortcuts_dialog import SHORTCUTS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Event:
    def __init__(self, mods) -> None:
        self._mods = mods

    def modifiers(self):
        return self._mods


def _help(keys: str) -> str:
    found = [d for s, k, d in SHORTCUTS if s == "Drag and drop" and k == (keys,)]
    assert len(found) == 1, (keys, found)
    return found[0]


def _name(action) -> str:
    return {Qt.DropAction.MoveAction: "Move", Qt.DropAction.CopyAction: "Copy"}[action]


def test_happy_plain_drag_help_matches_the_drop():
    assert _help("Drag") == _name(_drop_action(_Event(Qt.KeyboardModifier.NoModifier)))


def test_happy_ctrl_drag_help_matches_the_drop():
    assert _help("Ctrl+Drag") == _name(_drop_action(_Event(Qt.KeyboardModifier.ControlModifier)))


def test_edge_plain_drag_is_a_move():
    """Pinned explicitly: the help must never say the opposite again."""
    assert _help("Drag") == "Move"
    assert _help("Ctrl+Drag") == "Copy"


def test_sad_shift_does_not_turn_a_drag_into_a_copy():
    assert _drop_action(_Event(Qt.KeyboardModifier.ShiftModifier)) == Qt.DropAction.MoveAction
