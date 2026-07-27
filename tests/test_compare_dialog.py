#!/usr/bin/env python3
"""The compare window: filtering, export, and what each action asks for.

The comparison itself is tested in tests/test_tree_compare.py. What this
file pins is the part a user can get hurt by: which rows an action
applies to, and in which direction a copy goes. A copy that silently
runs the wrong way overwrites the good side with the stale one, so the
direction is derived from the row's status rather than from whichever
pane happens to be focused.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.tree_compare import ComparedEntry, Status  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from ui.compare_dialog import (  # noqa: E402
    FILTERS,
    CompareDialog,
    copy_direction,
    export_text,
)

APP = QApplication.instance() or QApplication([])


def _item(name="a.txt", size=10) -> FileItem:
    return FileItem(name=name, size=size)


def _e(rel, status, *, reason="", left=True, right=True) -> ComparedEntry:
    return ComparedEntry(
        rel_path=rel,
        status=status,
        reason=reason or status,
        left=_item(rel) if left else None,
        right=_item(rel) if right else None,
    )


ENTRIES = [
    _e("only-left.txt", Status.LEFT_ONLY, right=False),
    _e("only-right.txt", Status.RIGHT_ONLY, left=False),
    _e("same.txt", Status.SAME),
    _e("differs.txt", Status.DIFFERS),
    _e("huge.bin", Status.UNKNOWN, reason="too large to hash automatically"),
]


class _Pane:
    """Stands in for FilePaneWidget via its public properties only."""

    def __init__(self, label, path="/root"):
        self.backend = object()
        self.current_path = path
        self.label = label


@pytest.fixture()
def dialog():
    made: list = []

    def factory(entries=ENTRIES):
        dlg = CompareDialog(
            _Pane("left"), _Pane("right"), compare_fn=lambda *a, **kw: list(entries)
        )
        dlg.show()
        APP.processEvents()
        dlg.wait_for_compare()
        made.append(dlg)
        return dlg

    yield factory
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.processEvents()


# --------------------------------------------------------------------------
# Filtering
# --------------------------------------------------------------------------


def test_happy_default_filter_hides_identical_files(dialog):
    """The point of the window is the differences; a tree of thousands
    of matching files buries them."""
    dlg = dialog()
    assert "same.txt" not in [e.rel_path for e in dlg.visible_entries()]


def test_happy_every_filter_is_selectable(dialog):
    dlg = dialog()
    for name in FILTERS:
        dlg.set_filter(name)
        assert dlg.current_filter() == name


def test_happy_filters_select_the_matching_rows(dialog):
    dlg = dialog()
    dlg.set_filter("Left only")
    assert [e.rel_path for e in dlg.visible_entries()] == ["only-left.txt"]
    dlg.set_filter("Right only")
    assert [e.rel_path for e in dlg.visible_entries()] == ["only-right.txt"]
    dlg.set_filter("Differs")
    assert [e.rel_path for e in dlg.visible_entries()] == ["differs.txt"]
    dlg.set_filter("Unresolved")
    assert [e.rel_path for e in dlg.visible_entries()] == ["huge.bin"]


def test_happy_all_filter_shows_everything_including_matches(dialog):
    dlg = dialog()
    dlg.set_filter("All")
    assert len(dlg.visible_entries()) == len(ENTRIES)


def test_edge_summary_counts_every_status(dialog):
    text = dialog().summary_text()
    for fragment in ("1 only left", "1 only right", "1 differ", "1 unresolved"):
        assert fragment in text, text


# --------------------------------------------------------------------------
# Copy direction — the part that can destroy data
# --------------------------------------------------------------------------


def test_happy_left_only_copies_left_to_right():
    assert copy_direction(_e("a", Status.LEFT_ONLY, right=False)) == "to_right"


def test_happy_right_only_copies_right_to_left():
    assert copy_direction(_e("a", Status.RIGHT_ONLY, left=False)) == "to_left"


def test_sad_a_differing_file_has_no_implied_direction():
    """Both sides exist and disagree. Picking a direction here would be
    guessing which copy the user considers authoritative."""
    assert copy_direction(_e("a", Status.DIFFERS)) is None


def test_sad_an_unresolved_file_has_no_implied_direction():
    assert copy_direction(_e("a", Status.UNKNOWN)) is None


def test_sad_an_identical_file_has_no_direction():
    assert copy_direction(_e("a", Status.SAME)) is None


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def test_happy_export_lists_status_and_path():
    text = export_text(ENTRIES)
    assert "only-left.txt" in text
    assert Status.LEFT_ONLY in text
    assert text.count("\n") >= len(ENTRIES)


def test_edge_export_of_an_empty_result_is_not_empty_text():
    assert export_text([]).strip() != ""


def test_edge_export_includes_the_reason_so_unresolved_rows_explain_themselves():
    assert "too large to hash automatically" in export_text(ENTRIES)


# --------------------------------------------------------------------------
# Sad path
# --------------------------------------------------------------------------


def test_sad_comparison_failure_is_reported_not_raised():
    def _boom(*_a, **_kw):
        raise OSError("host went away mid-walk")

    dlg = CompareDialog(_Pane("l"), _Pane("r"), compare_fn=_boom)
    dlg.show()
    APP.processEvents()
    dlg.wait_for_compare()
    try:
        assert dlg.visible_entries() == []
        assert "host went away mid-walk" in dlg.summary_text()
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_edge_empty_comparison_reports_the_trees_match(dialog):
    dlg = dialog(entries=[])
    assert dlg.visible_entries() == []
    assert "match" in dlg.summary_text().lower()


# --------------------------------------------------------------------------
# Teardown while the walk is still running
# --------------------------------------------------------------------------


def test_sad_closing_mid_walk_cancels_instead_of_only_waiting():
    """QThread.quit() ends an event loop; it cannot interrupt a slot
    that is already running. Without a cancel path, closing the window
    during a large remote walk either blocks the GUI for the full wait
    or drops a live QThread — which Qt answers with an abort."""
    import threading
    import time

    started = threading.Event()
    observed: list[bool] = []

    def _slow_compare(*_a, should_continue=None, **_kw):
        started.set()
        # Stands in for a walk that spends real time between listings —
        # without that there is nothing left to cancel by the time the
        # window closes, and the test proves nothing.
        for _ in range(500):
            if should_continue is not None and not should_continue():
                observed.append(True)
                return []
            time.sleep(0.01)
        return []

    dlg = CompareDialog(_Pane("l"), _Pane("r"), compare_fn=_slow_compare)
    dlg.show()
    APP.processEvents()
    assert started.wait(5), "worker never started"
    dlg.reject()
    dlg.wait_for_compare(timeout_ms=5000)

    assert observed == [True], "the walk was never told to stop"
    dlg.deleteLater()
    APP.processEvents()


# --------------------------------------------------------------------------
# The action signals must carry usable paths
#
# The buttons emitted relative paths and nothing was connected to them,
# so "Copy to other side" and "Delete…" did nothing at all — the delete
# even asked for confirmation first and then silently dropped it.
# --------------------------------------------------------------------------


class _JoiningBackend:
    def join(self, a, b):
        return f"{a.rstrip('/')}/{b}"


def _wired_pane(label, path):
    pane = _Pane(label, path)
    pane.backend = _JoiningBackend()
    return pane


def _dialog_with(entries, left_root="/l", right_root="/r"):
    dlg = CompareDialog(
        _wired_pane("left", left_root),
        _wired_pane("right", right_root),
        compare_fn=lambda *a, **kw: list(entries),
    )
    dlg.show()
    APP.processEvents()
    dlg.wait_for_compare()
    return dlg


def _select_all(dlg):
    dlg._table.selectAll()
    APP.processEvents()


def test_happy_copy_emits_absolute_paths_for_the_compared_roots():
    dlg = _dialog_with([_e("sub/only-left.txt", Status.LEFT_ONLY, right=False)])
    seen: list[tuple[str, list[str]]] = []
    dlg.copy_requested.connect(lambda d, p: seen.append((d, list(p))))
    try:
        _select_all(dlg)
        dlg._copy_selected()
        assert seen == [("to_right", ["/l/sub/only-left.txt"])]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_happy_right_only_copy_resolves_against_the_right_root():
    dlg = _dialog_with([_e("x.txt", Status.RIGHT_ONLY, left=False)])
    seen: list[tuple[str, list[str]]] = []
    dlg.copy_requested.connect(lambda d, p: seen.append((d, list(p))))
    try:
        _select_all(dlg)
        dlg._copy_selected()
        assert seen == [("to_left", ["/r/x.txt"])]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_edge_paths_resolve_against_the_root_that_was_compared():
    """A pane can navigate away while the window is open. Resolving
    against the pane's CURRENT directory would then point the copy at
    the wrong place, so the roots captured at compare time are used."""
    dlg = _dialog_with([_e("a.txt", Status.LEFT_ONLY, right=False)], left_root="/l")
    seen: list[tuple[str, list[str]]] = []
    dlg.copy_requested.connect(lambda d, p: seen.append((d, list(p))))
    try:
        dlg._left_pane.current_path = "/somewhere/else"
        _select_all(dlg)
        dlg._copy_selected()
        assert seen == [("to_right", ["/l/a.txt"])]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------


def test_happy_sync_plan_covers_the_whole_comparison_not_the_filtered_view():
    """The table hides identical files by default. Planning off the
    visible rows would silently sync a subset of what was compared."""
    dlg = _dialog_with(ENTRIES)
    try:
        dlg.set_filter("Left only")
        plan = dlg.sync_plan()
        paths = {a.rel_path for a in plan.actions}
        assert "only-right.txt" in paths, paths
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_happy_default_policy_leaves_the_two_sided_difference_alone():
    dlg = _dialog_with(ENTRIES)
    try:
        plan = dlg.sync_plan()
        assert "differs.txt" in {c.rel_path for c in plan.conflicts}
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_happy_policy_selection_reaches_the_plan():
    from core.sync import ConflictPolicy

    dlg = _dialog_with(ENTRIES)
    try:
        dlg.set_policy(ConflictPolicy.LEFT_WINS)
        plan = dlg.sync_plan()
        assert "differs.txt" in {a.rel_path for a in plan.actions}
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_edge_sync_actions_carry_absolute_paths_for_both_ends():
    """The receiver copies between backends and needs real paths, not
    fragments relative to a root it cannot see."""
    dlg = _dialog_with([_e("sub/a.txt", Status.LEFT_ONLY, right=False)])
    seen: list = []
    dlg.sync_requested.connect(lambda items: seen.append(list(items)))
    try:
        dlg._emit_sync(dlg.sync_plan())
        assert seen, "nothing emitted"
        first = seen[0][0]
        assert first["source"] == "/l/sub/a.txt"
        assert first["dest"] == "/r/sub/a.txt"
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()
