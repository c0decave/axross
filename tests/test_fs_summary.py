#!/usr/bin/env python3
"""Totalling up a multi-file selection.

Select everything with Ctrl+A and ask for properties: the answer wanted
is one summary — how many files, how many directories, how much in
total — not a sheet about whichever entry happened to be first.

The part that decides whether the number can be trusted is what happens
to entries the user cannot read. A total that silently omits an
unreadable subtree is not "best effort", it is a wrong number presented
as a fact, and it is wrong in the direction that matters: it under-
reports, so a user checking whether a copy will fit says yes and runs
out of space. Every unreadable path is therefore counted and named, and
the total is explicitly marked partial.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.fs_summary import summarize_selection  # noqa: E402
from models.file_item import FileItem  # noqa: E402


def _f(name, size=0, *, is_dir=False, is_link=False) -> FileItem:
    return FileItem(
        name=name,
        size=size,
        modified=datetime(2026, 1, 1),
        is_dir=is_dir,
        is_link=is_link,
    )


class _Backend:
    """Tree stub; paths listed in ``denied`` raise on list_dir."""

    def __init__(self, tree: dict[str, list[FileItem]], denied=()):
        self._tree = tree
        self._denied = set(denied)
        self.listings = 0

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str) -> list[FileItem]:
        self.listings += 1
        if path in self._denied:
            raise PermissionError(f"permission denied: {path}")
        if path not in self._tree:
            raise OSError(f"no such directory: {path}")
        return self._tree[path]


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_happy_counts_files_and_sums_their_sizes():
    items = [_f("a.txt", 100), _f("b.txt", 23)]
    s = summarize_selection(_Backend({}), "/d", items)
    assert s.files == 2
    assert s.directories == 0
    assert s.total_bytes == 123
    assert s.complete is True


def test_happy_recurses_into_selected_directories():
    backend = _Backend({
        "/d/sub": [_f("x", 10), _f("deeper", is_dir=True)],
        "/d/sub/deeper": [_f("y", 5)],
    })
    s = summarize_selection(backend, "/d", [_f("sub", is_dir=True)])
    # Both the selected directory and the nested one count: the summary
    # describes everything inside the selection, not just its top level.
    assert s.directories == 2
    assert s.files == 2          # x and y
    assert s.total_bytes == 15


def test_happy_mixed_selection_counts_both_kinds():
    backend = _Backend({"/d/sub": [_f("x", 10)]})
    items = [_f("a.txt", 100), _f("sub", is_dir=True)]
    s = summarize_selection(backend, "/d", items)
    assert (s.files, s.directories, s.total_bytes) == (2, 1, 110)


def test_edge_empty_selection_is_an_empty_summary():
    s = summarize_selection(_Backend({}), "/d", [])
    assert (s.files, s.directories, s.total_bytes) == (0, 0, 0)
    assert s.complete is True


# --------------------------------------------------------------------------
# Entries the user cannot read — the part that decides whether the
# number means anything
# --------------------------------------------------------------------------


def test_sad_an_unreadable_directory_is_counted_and_named():
    backend = _Backend({"/d/ok": [_f("x", 10)]}, denied=["/d/locked"])
    items = [_f("ok", is_dir=True), _f("locked", is_dir=True)]
    s = summarize_selection(backend, "/d", items)

    assert s.total_bytes == 10
    assert s.unreadable == ["/d/locked"]
    assert s.complete is False, "a partial total must not claim to be complete"


def test_sad_the_readable_part_is_still_totalled():
    """One denied subtree must cost the user that subtree, not the
    whole answer."""
    backend = _Backend(
        {"/d/a": [_f("x", 100)], "/d/b": [_f("y", 7)]},
        denied=["/d/b"],
    )
    items = [_f("a", is_dir=True), _f("b", is_dir=True)]
    s = summarize_selection(backend, "/d", items)
    assert s.total_bytes == 100
    assert len(s.unreadable) == 1


def test_sad_a_nested_denial_is_reported_with_its_full_path():
    backend = _Backend(
        {"/d/top": [_f("x", 5), _f("inner", is_dir=True)]},
        denied=["/d/top/inner"],
    )
    s = summarize_selection(backend, "/d", [_f("top", is_dir=True)])
    assert s.total_bytes == 5
    assert s.unreadable == ["/d/top/inner"]


def test_edge_unreadable_list_is_capped_but_the_count_is_not():
    """Selecting a whole filesystem can deny thousands of paths. The
    dialog cannot show them all, but it must not misreport how many
    there were."""
    denied = [f"/d/x{i}" for i in range(50)]
    backend = _Backend({}, denied=denied)
    items = [_f(f"x{i}", is_dir=True) for i in range(50)]
    s = summarize_selection(backend, "/d", items, unreadable_sample=5)
    assert len(s.unreadable) == 5
    assert s.unreadable_count == 50


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_edge_symlinked_directories_are_not_followed():
    """Following them double-counts a tree, or does not terminate."""
    backend = _Backend({"/d/link": [_f("huge", 999)]})
    s = summarize_selection(backend, "/d", [_f("link", is_dir=True, is_link=True)])
    assert s.total_bytes == 0
    assert backend.listings == 0


def test_edge_depth_cap_marks_the_result_partial():
    class _Endless(_Backend):
        def list_dir(self, path):
            self.listings += 1
            return [_f("deeper", is_dir=True)]

    s = summarize_selection(_Endless({}), "/d", [_f("top", is_dir=True)], max_depth=3)
    assert s.complete is False


def test_edge_cancellation_marks_the_result_partial():
    backend = _Backend({"/d/a": [_f("x", 10)]})
    s = summarize_selection(
        backend, "/d", [_f("a", is_dir=True)], should_continue=lambda: False
    )
    assert s.complete is False


def test_edge_a_directory_entry_reporting_a_size_does_not_double_count():
    """Some backends report a directory's own inode size. Adding it to
    the recursive total inflates the answer."""
    backend = _Backend({"/d/sub": [_f("x", 10)]})
    s = summarize_selection(backend, "/d", [_f("sub", 4096, is_dir=True)])
    assert s.total_bytes == 10
