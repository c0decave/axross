"""Git-FS reaches branches whose names contain '/'.

``feature/x`` and ``release/1.2`` are the common case, but the path
split took the first component as the branch: ``/feature/x`` asked for
a branch ``feature`` and failed with "No such branch: feature", while
the root listing showed the unreachable name ``feature/x`` (a name with
a separator in it). Branch namespaces are now directories: ``/`` lists
``feature``, ``/feature`` lists ``x``, ``/feature/x`` is the branch.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from dulwich.repo import Repo

    DULWICH = True
except ImportError:  # pragma: no cover - optional extra
    DULWICH = False


@unittest.skipUnless(DULWICH, "dulwich not installed")
class SlashBranchTest(unittest.TestCase):
    def setUp(self) -> None:
        from core.git_fs_client import GitFsSession

        tmp = Path(tempfile.mkdtemp(prefix="axross-gitfs-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        Repo.init_bare(str(tmp / "r.git"), mkdir=True)
        self.s = GitFsSession(
            path=str(tmp / "r.git"), author_name="T", author_email="t@example.com"
        )
        with self.s.open_write("/main/a.txt") as fh:
            fh.write(b"main-a")
        tip = self.s._branch_tips["main"]
        refs = self.s._repo.refs
        refs[b"refs/heads/feature/x"] = tip
        refs[b"refs/heads/release/1.2/hotfix"] = tip
        self.s._refresh_branch_tips()

    def test_happy_root_lists_namespaces_as_directories(self) -> None:
        items = {i.name: i.is_dir for i in self.s.list_dir("/")}
        self.assertEqual(items, {"feature": True, "main": True, "release": True})
        self.assertEqual([i.name for i in self.s.list_dir("/feature")], ["x"])
        self.assertEqual([i.name for i in self.s.list_dir("/release/1.2")], ["hotfix"])

    def test_happy_branch_with_slash_reads_and_writes(self) -> None:
        self.assertEqual([i.name for i in self.s.list_dir("/feature/x")], ["a.txt"])
        self.assertEqual(self.s.open_read("/feature/x/a.txt").read(), b"main-a")
        with self.s.open_write("/feature/x/b.txt") as fh:
            fh.write(b"fx")
        self.assertEqual(self.s.open_read("/feature/x/b.txt").read(), b"fx")
        self.assertFalse(self.s.exists("/main/b.txt"))

    def test_sad_unknown_names_still_fail(self) -> None:
        with self.assertRaises(OSError):
            self.s.list_dir("/feature/nope")
        self.assertFalse(self.s.exists("/nope"))
        self.assertFalse(self.s.exists("/feature/x/missing.txt"))

    def test_edge_namespace_and_branch_stat(self) -> None:
        self.assertTrue(self.s.stat("/feature").is_dir)
        self.assertTrue(self.s.is_dir("/release/1.2"))
        self.assertTrue(self.s.stat("/feature/x").is_dir)
        self.assertEqual(self.s.stat("/feature/x/a.txt").size, 6)


if __name__ == "__main__":
    unittest.main()
