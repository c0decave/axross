#!/usr/bin/env python3
"""Comparing two directory trees across backends.

``core/multi_view.py`` can already answer "is this one path the same on
N hosts?". What was missing is the tree-level question: which files
exist only here, only there, or differ — the local-vs-remote sanity
check before a sync.

The expensive decision is when to hash. Reading content is the only way
to be certain, and it is also the one operation that can pull tens of
gigabytes over a link the user did not expect to saturate. So the cheap
metadata pass classifies everything it can, and hashing runs only where
metadata is ambiguous AND the file is small enough to be worth it.
Anything larger is reported as unresolved rather than guessed at.

Timestamps get a tolerance on purpose: FAT stores mtime at 2-second
granularity, S3 and WebDAV report whole seconds, and a file copied
between two such backends legitimately lands a second or two off. rsync
uses the same convention.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.tree_compare import (  # noqa: E402
    DEFAULT_HASH_LIMIT,
    MTIME_TOLERANCE_S,
    ComparedEntry,
    Status,
    compare_trees,
    walk,
)
from models.file_item import FileItem  # noqa: E402

BASE = datetime(2026, 5, 1, 12, 0, 0)


def _f(name, size=10, *, mtime=BASE, is_dir=False, is_link=False) -> FileItem:
    return FileItem(
        name=name, size=size, modified=mtime, is_dir=is_dir, is_link=is_link
    )


class _Tree:
    """Backend stub over a ``{path: [FileItem]}`` mapping."""

    def __init__(self, tree: dict[str, list[FileItem]], *, contents=None, fail_read=()):
        self._tree = tree
        self._contents = contents or {}
        self._fail_read = set(fail_read)
        self.listed: list[str] = []

    @property
    def name(self) -> str:
        return "Stub"

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str) -> list[FileItem]:
        self.listed.append(path)
        if path not in self._tree:
            raise OSError(f"no such directory: {path}")
        return self._tree[path]

    def read_bytes(self, path: str) -> bytes:
        if path in self._fail_read:
            raise OSError("permission denied")
        return self._contents.get(path, b"")


def _hasher(backend, path):
    """Stand-in for scripting.hash_file — hashes the stub's content."""
    import hashlib

    return hashlib.sha256(backend.read_bytes(path)).hexdigest()


def _entry(entries: list[ComparedEntry], rel: str) -> ComparedEntry:
    for e in entries:
        if e.rel_path == rel:
            return e
    raise AssertionError(f"{rel!r} not in {[e.rel_path for e in entries]}")


# --------------------------------------------------------------------------
# walk
# --------------------------------------------------------------------------


def test_happy_walk_returns_relative_paths():
    tree = _Tree({
        "/r": [_f("a.txt"), _f("sub", is_dir=True)],
        "/r/sub": [_f("b.txt")],
    })
    assert set(walk(tree, "/r")) == {"a.txt", "sub", "sub/b.txt"}


def test_edge_walk_does_not_follow_symlinked_directories():
    """A symlinked directory is an entry, not a subtree — following it
    is how a walk ends up in a loop or duplicates a whole tree."""
    tree = _Tree({
        "/r": [_f("link", is_dir=True, is_link=True)],
        "/r/link": [_f("should-not-appear")],
    })
    result = walk(tree, "/r")
    assert set(result) == {"link"}


def test_edge_walk_skips_unreadable_subtrees():
    tree = _Tree({"/r": [_f("ok.txt"), _f("locked", is_dir=True)]})  # /r/locked missing
    assert set(walk(tree, "/r")) == {"ok.txt", "locked"}


def test_edge_walk_respects_the_depth_cap():
    # A backend that reports the same directory forever must not
    # recurse until the stack dies.
    class _Endless(_Tree):
        def list_dir(self, path):
            self.listed.append(path)
            return [_f("deeper", is_dir=True)]

    result = walk(_Endless({}), "/r", max_depth=3)
    assert len(result) == 3


def test_sad_walk_on_a_missing_root_returns_empty():
    assert walk(_Tree({}), "/nope") == {}


# --------------------------------------------------------------------------
# compare_trees — the cheap metadata pass
# --------------------------------------------------------------------------


def _pair(left_items, right_items, **kw):
    left = _Tree({"/l": left_items}, contents=kw.pop("left_contents", None))
    right = _Tree({"/r": right_items}, contents=kw.pop("right_contents", None))
    return compare_trees(left, "/l", right, "/r", hasher=_hasher, **kw)


def test_happy_file_only_on_the_left():
    entries = _pair([_f("only-here.txt")], [])
    assert _entry(entries, "only-here.txt").status == Status.LEFT_ONLY


def test_happy_file_only_on_the_right():
    entries = _pair([], [_f("only-there.txt")])
    assert _entry(entries, "only-there.txt").status == Status.RIGHT_ONLY


def test_happy_identical_size_and_mtime_is_same():
    entries = _pair([_f("a.txt", 10)], [_f("a.txt", 10)])
    assert _entry(entries, "a.txt").status == Status.SAME


def test_happy_different_size_differs_without_reading_anything():
    left = _Tree({"/l": [_f("a.txt", 10)]}, contents={"/l/a.txt": b"x" * 10})
    right = _Tree({"/r": [_f("a.txt", 20)]}, contents={"/r/a.txt": b"x" * 20})

    reads: list[str] = []

    def _spy(backend, path):
        reads.append(path)
        return _hasher(backend, path)

    entries = compare_trees(left, "/l", right, "/r", hasher=_spy)
    assert _entry(entries, "a.txt").status == Status.DIFFERS
    assert reads == [], "a size mismatch is decisive; nothing should be downloaded"


def test_edge_mtime_within_tolerance_counts_as_same():
    """FAT has 2-second granularity and S3/WebDAV report whole seconds,
    so a faithful copy legitimately lands a second off."""
    later = BASE + timedelta(seconds=MTIME_TOLERANCE_S - 0.5)
    entries = _pair([_f("a.txt", 10)], [_f("a.txt", 10, mtime=later)])
    assert _entry(entries, "a.txt").status == Status.SAME


def test_edge_directory_present_on_both_sides_is_same_and_never_hashed():
    entries = _pair([_f("d", is_dir=True)], [_f("d", is_dir=True)])
    assert _entry(entries, "d").status == Status.SAME


def test_edge_directory_on_one_side_file_on_the_other_differs():
    entries = _pair([_f("x", is_dir=True)], [_f("x")])
    entry = _entry(entries, "x")
    assert entry.status == Status.DIFFERS
    assert "type" in entry.reason


# --------------------------------------------------------------------------
# compare_trees — hashing, and its budget
# --------------------------------------------------------------------------


def test_happy_same_size_different_mtime_is_resolved_by_hashing():
    entries = _pair(
        [_f("a.txt", 5, mtime=BASE)],
        [_f("a.txt", 5, mtime=BASE + timedelta(hours=3))],
        left_contents={"/l/a.txt": b"hello"},
        right_contents={"/r/a.txt": b"hello"},
    )
    entry = _entry(entries, "a.txt")
    assert entry.status == Status.SAME
    assert "hash" in entry.reason


def test_happy_hashing_detects_content_that_actually_differs():
    entries = _pair(
        [_f("a.txt", 5, mtime=BASE)],
        [_f("a.txt", 5, mtime=BASE + timedelta(hours=3))],
        left_contents={"/l/a.txt": b"hello"},
        right_contents={"/r/a.txt": b"world"},
    )
    entry = _entry(entries, "a.txt")
    assert entry.status == Status.DIFFERS
    assert "hash" in entry.reason


def test_edge_file_over_the_limit_is_reported_unresolved_not_guessed():
    """The whole point of the budget: never silently pull a huge file,
    and never claim a verdict that was not measured."""
    big = DEFAULT_HASH_LIMIT + 1
    reads: list[str] = []

    def _spy(backend, path):
        reads.append(path)
        return "x"

    left = _Tree({"/l": [_f("big.bin", big, mtime=BASE)]})
    right = _Tree({"/r": [_f("big.bin", big, mtime=BASE + timedelta(hours=3))]})
    entries = compare_trees(left, "/l", right, "/r", hasher=_spy)

    entry = _entry(entries, "big.bin")
    assert entry.status == Status.UNKNOWN
    assert reads == []
    assert "too large" in entry.reason


def test_edge_hash_limit_is_configurable():
    reads: list[str] = []

    def _spy(backend, path):
        reads.append(path)
        return "same"

    left = _Tree({"/l": [_f("m.bin", 500, mtime=BASE)]})
    right = _Tree({"/r": [_f("m.bin", 500, mtime=BASE + timedelta(hours=3))]})
    entries = compare_trees(left, "/l", right, "/r", hasher=_spy, hash_limit=1000)

    assert _entry(entries, "m.bin").status == Status.SAME
    assert len(reads) == 2


def test_edge_hash_limit_of_zero_disables_hashing_entirely():
    def _boom(backend, path):
        raise AssertionError("must not hash when the limit is zero")

    left = _Tree({"/l": [_f("a.txt", 5, mtime=BASE)]})
    right = _Tree({"/r": [_f("a.txt", 5, mtime=BASE + timedelta(hours=3))]})
    entries = compare_trees(left, "/l", right, "/r", hasher=_boom, hash_limit=0)
    assert _entry(entries, "a.txt").status == Status.UNKNOWN


# --------------------------------------------------------------------------
# Sad paths
# --------------------------------------------------------------------------


def test_sad_unreadable_file_is_unresolved_not_different():
    """A file we could not read is not evidence of a difference. Saying
    "differs" here would send the user copying over a file that may be
    identical."""
    left = _Tree(
        {"/l": [_f("a.txt", 5, mtime=BASE)]},
        contents={"/l/a.txt": b"hello"},
        fail_read=["/l/a.txt"],
    )
    right = _Tree(
        {"/r": [_f("a.txt", 5, mtime=BASE + timedelta(hours=3))]},
        contents={"/r/a.txt": b"hello"},
    )
    entries = compare_trees(left, "/l", right, "/r", hasher=_hasher)
    entry = _entry(entries, "a.txt")
    assert entry.status == Status.UNKNOWN
    assert "permission denied" in entry.reason


def test_sad_both_roots_empty_yields_no_entries():
    assert _pair([], []) == []


# --------------------------------------------------------------------------
# Result shape
# --------------------------------------------------------------------------


def test_entries_are_sorted_by_path():
    entries = _pair([_f("b"), _f("a"), _f("c")], [])
    assert [e.rel_path for e in entries] == ["a", "b", "c"]


def test_entries_carry_both_sides_for_the_ui():
    entries = _pair([_f("a.txt", 10)], [_f("a.txt", 20)])
    entry = _entry(entries, "a.txt")
    assert entry.left is not None and entry.left.size == 10
    assert entry.right is not None and entry.right.size == 20


def test_left_only_entry_has_no_right_side():
    entry = _entry(_pair([_f("a")], []), "a")
    assert entry.left is not None
    assert entry.right is None


# --------------------------------------------------------------------------
# Cancellation
#
# A walk over a remote tree is unbounded work. Without a way to stop it,
# closing the window can only wait for it — QThread.quit() ends an event
# loop but cannot interrupt a slot that is already running, so the UI
# either blocks or drops a still-running thread on the floor.
# --------------------------------------------------------------------------


def test_happy_walk_stops_when_the_caller_withdraws():
    class _Counting(_Tree):
        def __init__(self):
            super().__init__({})
            self.calls = 0

        def list_dir(self, path):
            self.calls += 1
            return [_f(f"d{self.calls}", is_dir=True)]

    backend = _Counting()
    # Withdraw after the second listing.
    result = walk(backend, "/r", should_continue=lambda: backend.calls < 2)
    assert backend.calls <= 3, backend.calls
    assert len(result) < 10


def test_edge_walk_without_a_predicate_runs_to_completion():
    tree = _Tree({"/r": [_f("a"), _f("sub", is_dir=True)], "/r/sub": [_f("b")]})
    assert len(walk(tree, "/r")) == 3


def test_happy_compare_trees_passes_cancellation_through():
    class _Counting(_Tree):
        def __init__(self):
            super().__init__({})
            self.calls = 0

        def list_dir(self, path):
            self.calls += 1
            return [_f(f"d{self.calls}", is_dir=True)]

    left, right = _Counting(), _Counting()
    entries = compare_trees(
        left, "/l", right, "/r", hasher=_hasher, should_continue=lambda: False
    )
    assert entries == []
    assert left.calls == 0 and right.calls == 0
