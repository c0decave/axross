"""core.tree_size: the total size of a folder tree, walked iteratively.

Calculate Size used to recurse through the tree in the UI thread; this is
the walk it now hands to a background job. It never follows a link, skips
what it cannot read instead of stopping, stops at a depth bound and when
asked to cancel.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.local_fs import LocalFS  # noqa: E402
from core.tree_size import tree_size  # noqa: E402
from models.file_item import FileItem  # noqa: E402


def _tree(root: Path) -> Path:
    (root / "a" / "deep").mkdir(parents=True)
    (root / "b").mkdir()
    (root / "top.bin").write_bytes(b"x" * 10)
    (root / "a" / "one.bin").write_bytes(b"x" * 100)
    (root / "a" / "deep" / "two.bin").write_bytes(b"x" * 1000)
    (root / "b" / "three.bin").write_bytes(b"x" * 5)
    return root


class _Deep:
    """An in-memory chain of *levels* nested folders, one 1-byte file each."""

    def __init__(self, levels: int) -> None:
        self.levels = levels

    def join(self, *parts):
        return "/".join(p.strip("/") for p in parts if p) if parts[0] != "/" else "/" + "/".join(
            p.strip("/") for p in parts[1:] if p
        )

    def separator(self) -> str:
        return "/"

    def normalize(self, path: str) -> str:
        return path

    def list_dir(self, path):
        depth = 0 if path == "/" else path.count("/")
        items = [FileItem(name="f", size=1)]
        if depth < self.levels:
            items.append(FileItem(name="d", is_dir=True))
        return items


# --- happy ----------------------------------------------------------------


def test_happy_sums_every_file_below_the_folder(tmp_path):
    root = _tree(tmp_path / "t")
    r = tree_size(LocalFS(), str(root))
    assert (r.bytes, r.files, r.folders) == (1115, 4, 4)
    assert not r.cancelled and r.unreadable == 0


def test_happy_reports_progress_per_folder(tmp_path):
    root = _tree(tmp_path / "t")
    seen = []
    tree_size(LocalFS(), str(root), progress=lambda folders, files, path: seen.append(folders))
    assert seen == [1, 2, 3, 4]


# --- sad ------------------------------------------------------------------


def test_sad_an_unreadable_folder_is_counted_and_skipped(tmp_path):
    root = _tree(tmp_path / "t")

    class Refusing(LocalFS):
        def list_dir(self, path):
            if path.endswith("/a"):
                raise PermissionError(13, "Permission denied", path)
            return super().list_dir(path)

    r = tree_size(Refusing(), str(root))
    assert r.unreadable == 1
    assert r.bytes == 15  # top.bin + b/three.bin


def test_sad_cancel_stops_the_walk(tmp_path):
    root = _tree(tmp_path / "t")
    calls = []

    def cancel():
        calls.append(1)
        return len(calls) > 1  # stop after the first folder

    r = tree_size(LocalFS(), str(root), cancel=cancel)
    assert r.cancelled
    assert r.folders == 1


# --- edge -----------------------------------------------------------------


def test_edge_a_link_to_a_folder_is_not_followed(tmp_path):
    root = _tree(tmp_path / "t")
    os.symlink(str(root / "a"), root / "link-to-a")
    r = tree_size(LocalFS(), str(root))
    assert r.folders == 4  # a is walked once, through its real path
    assert r.bytes - 1115 == os.lstat(root / "link-to-a").st_size


def test_edge_a_tree_deeper_than_the_recursion_limit_is_walked(tmp_path):
    r = tree_size(_Deep(sys.getrecursionlimit() + 500), "/", max_depth=10**6)
    assert r.files == sys.getrecursionlimit() + 501
    assert not r.depth_capped


def test_edge_the_depth_bound_is_reported(tmp_path):
    r = tree_size(_Deep(50), "/", max_depth=10)
    assert r.depth_capped
    assert r.folders == 11  # the root and ten levels below it
