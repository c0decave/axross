"""A compare shows names a sync cannot use, and the pane tooltip filters bidi.

Before: SFTP and SCP listings kept names with control characters or bidi
overrides (an entry left out is one a folder copy never sees), but
core.tree_compare still dropped them through drop_unsafe_names: a compare
or sync quietly left them out and looked complete. Now such a name is a
"not compared" entry (UNKNOWN, "name not usable here") that a sync never
acts on. Names no folder can hold (``..``, ``a/b``) stay dropped. The file
pane's tooltip escaped the name but kept a bidi override, which reordered
the tooltip's text.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.sync import plan_sync  # noqa: E402
from core.tree_compare import Status, compare_trees  # noqa: E402
from models.file_item import FileItem  # noqa: E402

BASE = datetime(2026, 1, 1, 12, 0, 0)
BIDI = "evil\u202etxt.exe"
CONTROL = "bell\x07.txt"


def _f(name, size=10, *, is_dir=False) -> FileItem:
    return FileItem(name=name, size=size, modified=BASE, is_dir=is_dir)


class _Tree:
    def __init__(self, tree):
        self._tree = tree

    @property
    def name(self) -> str:
        return "Stub"

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str):
        return self._tree.get(path, [])


def _compare(left_names):
    left = _Tree({"/l": [_f(n) for n in left_names]})
    right = _Tree({"/r": [_f("ok.txt")]})
    return compare_trees(left, "/l", right, "/r", hasher=lambda b, p: "same")


def test_sad_a_name_a_sync_cannot_use_is_shown_not_left_out():
    entries = {e.rel_path: e for e in _compare(["ok.txt", BIDI, CONTROL])}
    for name in (BIDI, CONTROL):
        assert name in entries, f"{name!r} was left out of the compare"
        assert entries[name].status is Status.UNKNOWN
        assert "name not usable here" in entries[name].reason
    assert entries["ok.txt"].status is Status.SAME


def test_happy_a_sync_never_acts_on_a_name_it_cannot_use():
    plan = plan_sync(_compare(["ok.txt", BIDI]))
    acted = [a.rel_path for a in plan.actions]
    assert BIDI not in acted


@pytest.mark.parametrize("name", ["..", "a/b", "x\x00y"])
def test_edge_names_no_folder_can_hold_stay_dropped(name):
    assert name not in {e.rel_path for e in _compare(["ok.txt", name])}


def test_sad_the_pane_tooltip_shows_a_bidi_override_defused():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtCore import Qt

    from models.file_table_model import COL_NAME, FileTableModel

    model = FileTableModel()
    model.set_items([_f(BIDI)])
    tip = model.data(model.index(0, COL_NAME), Qt.ItemDataRole.ToolTipRole)
    assert "\u202e" not in tip and "evil" in tip
