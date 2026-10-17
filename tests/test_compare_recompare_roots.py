#!/usr/bin/env python3
"""Re-compare must not rebase the rows on screen onto the new folders.

``refresh()`` stored the panes' current folders as the comparison roots
the moment Re-compare was clicked, while the table still showed the rows
of the previous comparison until the new walk finished. Every action in
that window — Delete, Copy, Reveal, Sync — resolved an OLD row against
the NEW root: deleting the left-only ``foo.txt`` of folder X removed the
unrelated ``foo.txt`` in folder Z the pane had moved to. The roots now
change together with the rows, when the new result arrives.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.tree_compare import ComparedEntry, Status  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from ui.compare_dialog import CompareDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Pane:
    def __init__(self, path: str) -> None:
        self.backend = None
        self.current_path = path


def _left_only(rel: str) -> ComparedEntry:
    return ComparedEntry(
        rel_path=rel, status=Status.LEFT_ONLY, reason="", left=FileItem(name=rel, size=1)
    )


@pytest.fixture()
def slow_second_walk(monkeypatch):
    """A dialog whose first walk returns one row and whose second walk
    blocks until the test releases it — a slow remote Re-compare."""
    monkeypatch.setattr(
        QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
    )
    gate = threading.Event()
    calls: list[str] = []
    second_result: list = []

    def compare_fn(lb, lroot, rb, rroot, should_continue=None):
        calls.append(lroot)
        if len(calls) > 1:
            gate.wait(10)
            return list(second_result)
        return [_left_only("foo.txt")]

    left, right = _Pane("/x"), _Pane("/y")
    dlg = CompareDialog(left, right, compare_fn=compare_fn)
    dlg.wait_for_compare(5000)
    yield dlg, left, right, gate, second_result
    gate.set()
    dlg.wait_for_compare(5000)
    dlg.deleteLater()
    APP.processEvents()


def test_sad_delete_during_recompare_targets_the_compared_folder(slow_second_walk):
    dlg, left, _right, _gate, _ = slow_second_walk
    dlg._table.selectRow(0)
    left.current_path = "/z"
    dlg.refresh()
    seen: list = []
    dlg.delete_requested.connect(lambda side, paths: seen.append((side, paths)))
    dlg._delete_btn.click()
    assert seen == [("left", ["/x/foo.txt"])]


def test_sad_copy_and_reveal_during_recompare_use_the_old_roots(slow_second_walk):
    dlg, left, right, _gate, _ = slow_second_walk
    dlg._table.selectRow(0)
    left.current_path = "/z"
    right.current_path = "/w"
    dlg.refresh()
    copies: list = []
    reveals: list = []
    dlg.copy_requested.connect(lambda d, p: copies.append((d, p)))
    dlg.reveal_requested.connect(lambda s, p: reveals.append((s, p)))
    dlg._copy_btn.click()
    dlg._reveal_btn.click()
    assert copies == [("to_right", [("/x/foo.txt", "/y/foo.txt")])]
    assert reveals == [("left", "/x/foo.txt")]


def test_happy_finished_recompare_switches_to_the_new_roots(slow_second_walk):
    dlg, left, _right, gate, second_result = slow_second_walk
    second_result.append(_left_only("bar.txt"))
    left.current_path = "/z"
    dlg.refresh()
    gate.set()
    dlg.wait_for_compare(5000)
    assert dlg.absolute_path("left", "bar.txt") == "/z/bar.txt"
    dlg._table.selectRow(0)
    seen: list = []
    dlg.delete_requested.connect(lambda side, paths: seen.append((side, paths)))
    dlg._delete_btn.click()
    assert seen == [("left", ["/z/bar.txt"])]


def test_edge_empty_recompare_takes_the_new_roots_with_the_empty_rows(slow_second_walk):
    """The rows and the roots switch in one step even when the new
    result is empty."""
    dlg, left, _right, gate, _ = slow_second_walk
    left.current_path = "/z"
    dlg.refresh()
    gate.set()
    dlg.wait_for_compare(5000)
    assert dlg._table.rowCount() == 0
    assert dlg.absolute_path("left", "q") == "/z/q"
