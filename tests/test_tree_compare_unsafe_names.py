"""A compare/sync never carries a server-chosen name out of its root.

Measured before: ``tree_compare.walk`` took ``item.name`` from the listing
verbatim. A listing name is server-controlled (WebDAV fills it from
``<D:displayname>``), so an entry named ``../outside.txt`` became the
relative path ``../outside.txt``, :func:`core.sync.plan_sync` turned it
into a "missing on the right -- copy" action, and the compare window joined
it onto the right-hand root: the sync wrote outside the folder the user
picked. A directory named ``..`` was even descended into, walking up the
server's tree.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.local_fs import LocalFS  # noqa: E402
from core.sync import ConflictPolicy, plan_sync  # noqa: E402
from core.tree_compare import Status, compare_trees, walk  # noqa: E402
from models.file_item import FileItem  # noqa: E402

BASE = datetime(2026, 5, 1, 12, 0, 0)


def _f(name, *, is_dir=False, size=5) -> FileItem:
    return FileItem(name=name, size=size, modified=BASE, is_dir=is_dir)


class _HostileListing:
    """A server whose listing names try to leave the compared folder."""

    def __init__(self, tree):
        self._tree = tree
        self.listed: list[str] = []

    name = "Hostile"

    def join(self, a, b):
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path):
        self.listed.append(path)
        if path not in self._tree:
            raise OSError(f"no such directory: {path}")
        return self._tree[path]


def _no_hash(backend, path):
    raise AssertionError("no hashing expected")


class UnsafeNameTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.right_root = self.tmp / "sync" / "right"
        self.right_root.mkdir(parents=True)

    def _right_dest(self, rel_path: str) -> str:
        """How the compare window resolves a row on the right side."""
        fs = LocalFS()
        path = str(self.right_root)
        for part in rel_path.split("/"):
            path = fs.join(path, part)
        return path

    def test_happy_ordinary_names_still_compare_and_sync(self) -> None:
        left = _HostileListing({"/r": [_f("ok.txt"), _f("sub", is_dir=True)],
                                "/r/sub": [_f("deep.txt")]})
        entries = compare_trees(left, "/r", LocalFS(), str(self.right_root), hasher=_no_hash)
        self.assertEqual(
            sorted(e.rel_path for e in entries), ["ok.txt", "sub", "sub/deep.txt"]
        )
        plan = plan_sync(entries, policy=ConflictPolicy.ASK)
        self.assertEqual(len(plan.actions), 3)

    def test_sad_a_traversal_name_never_reaches_a_sync_action(self) -> None:
        left = _HostileListing({"/r": [_f("../outside.txt"), _f("ok.txt")]})
        entries = compare_trees(left, "/r", LocalFS(), str(self.right_root), hasher=_no_hash)
        plan = plan_sync(entries, policy=ConflictPolicy.LEFT_WINS)
        root = os.path.realpath(self.right_root)
        for action in plan.actions:
            dest = os.path.realpath(self._right_dest(action.rel_path))
            self.assertTrue(dest.startswith(root + os.sep), (action.rel_path, dest))
        self.assertEqual([a.rel_path for a in plan.actions], ["ok.txt"])

    def test_sad_a_dot_dot_directory_is_not_descended(self) -> None:
        left = _HostileListing({
            "/r": [_f("..", is_dir=True), _f(".", is_dir=True)],
            "/r/..": [_f("passwd")],
            "/r/.": [_f("loop")],
        })
        found = walk(left, "/r")
        self.assertEqual(found, {})
        self.assertEqual(left.listed, ["/r"])

    def test_edge_a_separator_inside_a_name_is_dropped(self) -> None:
        """``a/b`` as ONE name would collide with the real ``a/b`` and
        split into two components when joined."""
        left = _HostileListing({"/r": [_f("a/b"), _f("c\\d"), _f("nul\x00")]})
        self.assertEqual(walk(left, "/r"), {})

    def test_edge_unusual_but_legal_names_survive(self) -> None:
        names = ["with space.txt", "..hidden", "emoji-\U0001f600", "line\nbreak.txt"]
        left = _HostileListing({"/r": [_f(n) for n in names]})
        entries = compare_trees(left, "/r", LocalFS(), str(self.right_root), hasher=_no_hash)
        self.assertEqual(sorted(e.rel_path for e in entries), sorted(names))
        self.assertTrue(all(e.status == Status.LEFT_ONLY for e in entries))


if __name__ == "__main__":
    unittest.main()
