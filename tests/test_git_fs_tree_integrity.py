"""Git-FS writes keep the tree intact and refuse what git cannot express.

Each case was reproduced against a bare dulwich repository:

* ``open_write("/main/a.txt/child")`` silently turned the file
  ``a.txt`` into a directory, and ``open_write("/main/d")`` replaced
  the whole directory ``d`` with a blob - both committed, both data loss.
* ``remove("/main/d", recursive=False)`` deleted the whole subtree, and
  ``remove`` of a path that does not exist committed an empty change.
* A submodule entry (gitlink, mode 160000) made ``stat`` / ``exists`` /
  ``open_read`` raise ``KeyError`` instead of following the OSError
  contract; ``exists`` raised instead of answering.
* The fast-forward guard only refused a local tip that is an ancestor
  of origin, so a diverged tip (and a walk that hit the cap, which the
  code calls "fail-closed") was committed onto anyway.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from dulwich.objects import Commit, Tree
    from dulwich.repo import Repo

    DULWICH = True
except ImportError:  # pragma: no cover - optional extra
    DULWICH = False


@unittest.skipUnless(DULWICH, "dulwich not installed")
class _GitCase(unittest.TestCase):
    def setUp(self) -> None:
        from core.git_fs_client import GitFsSession

        self.tmp = Path(tempfile.mkdtemp(prefix="axross-gitfs-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        repo_path = self.tmp / "repo.git"
        Repo.init_bare(str(repo_path), mkdir=True)
        self.s = GitFsSession(
            path=str(repo_path), author_name="Tester", author_email="t@example.com"
        )
        self._write("/main/a.txt", b"alpha")
        self._write("/main/d/f1", b"one")
        self._write("/main/d/e/f2", b"two")

    def _write(self, path: str, data: bytes) -> None:
        with self.s.open_write(path) as fh:
            fh.write(data)

    def _tip(self, branch: str = "main") -> bytes:
        return self.s._branch_tips[branch]

    def _commit(self, tree: Tree, parents: list[bytes], msg: bytes = b"m") -> bytes:
        c = Commit()
        c.tree = tree.id
        c.parents = parents
        c.author = c.committer = b"T <t@x>"
        c.author_time = c.commit_time = 0
        c.author_timezone = c.commit_timezone = 0
        c.message = msg
        self.s._repo.object_store.add_object(c)
        return c.id


class WriteKeepsTreeTest(_GitCase):
    def test_happy_overwrite_of_a_file_replaces_its_content(self) -> None:
        self._write("/main/a.txt", b"beta")
        self.assertEqual(self.s.open_read("/main/a.txt").read(), b"beta")

    def test_sad_write_below_a_file_is_refused_and_keeps_the_file(self) -> None:
        tip = self._tip()
        with self.assertRaises(OSError):
            self._write("/main/a.txt/child", b"c")
        self.assertEqual(self._tip(), tip)
        self.assertEqual(self.s.open_read("/main/a.txt").read(), b"alpha")

    def test_edge_write_over_a_directory_is_refused_and_keeps_it(self) -> None:
        tip = self._tip()
        with self.assertRaises(OSError):
            self._write("/main/d", b"blob")
        self.assertEqual(self._tip(), tip)
        self.assertEqual(self.s.open_read("/main/d/e/f2").read(), b"two")


class RemoveTest(_GitCase):
    def test_happy_recursive_remove_drops_the_subtree(self) -> None:
        self.s.remove("/main/d", recursive=True)
        self.assertFalse(self.s.exists("/main/d"))
        self.assertTrue(self.s.exists("/main/a.txt"))

    def test_sad_non_recursive_remove_of_a_directory_is_refused(self) -> None:
        tip = self._tip()
        with self.assertRaises(OSError):
            self.s.remove("/main/d", recursive=False)
        self.assertEqual(self._tip(), tip)
        self.assertTrue(self.s.exists("/main/d/e/f2"))

    def test_sad_missing_path_raises_and_commits_nothing(self) -> None:
        tip = self._tip()
        with self.assertRaises(FileNotFoundError):
            self.s.remove("/main/nope.txt")
        self.assertEqual(self._tip(), tip)

    def test_edge_file_remove_ignores_the_recursive_flag(self) -> None:
        self.s.remove("/main/a.txt", recursive=True)
        self.assertFalse(self.s.exists("/main/a.txt"))
        self.assertTrue(self.s.exists("/main/d/f1"))


class SubmoduleEntryTest(_GitCase):
    def setUp(self) -> None:
        super().setUp()
        tip = self._tip()
        old = self.s._repo[self.s._repo[tip].tree]
        tree = Tree()
        for e in old.items():
            tree.add(e.path, e.mode, e.sha)
        tree.add(b"sub", 0o160000, b"1" * 40)  # commit of another repository
        self.s._repo.object_store.add_object(tree)
        self.s._repo.refs[b"refs/heads/main"] = self._commit(tree, [tip])
        self.s._refresh_branch_tips()

    def test_happy_listing_shows_the_submodule(self) -> None:
        self.assertIn("sub", [i.name for i in self.s.list_dir("/main")])

    def test_sad_stat_and_exists_follow_the_contract(self) -> None:
        self.assertTrue(self.s.exists("/main/sub"))
        item = self.s.stat("/main/sub")
        self.assertEqual(item.name, "sub")
        self.assertEqual(item.size, 0)

    def test_edge_reading_a_submodule_raises_oserror(self) -> None:
        with self.assertRaises(OSError):
            self.s.open_read("/main/sub")
        self.assertEqual(self.s.checksum("/main/a.txt")[:4], "git:")


class FastForwardGuardTest(_GitCase):
    def _set_origin(self, sha: bytes) -> None:
        self.s._repo.refs[b"refs/remotes/origin/main"] = sha

    def test_happy_local_ahead_of_origin_commits(self) -> None:
        base = self._tip()
        self._write("/main/x", b"x")
        self._set_origin(base)
        self._write("/main/y", b"y")
        self.assertEqual(self.s.open_read("/main/y").read(), b"y")

    def test_sad_diverged_tip_is_refused(self) -> None:
        from core.git_fs_client import GitForceRefused

        base = self._tip()
        self._write("/main/x", b"x")  # local: base -> X
        tree = self.s._repo[self.s._repo[base].tree]
        self._set_origin(self._commit(tree, [base], b"remote side"))  # origin: base -> R
        tip = self._tip()
        with self.assertRaises(GitForceRefused):
            self._write("/main/y", b"y")
        self.assertEqual(self._tip(), tip)

    def test_edge_ancestry_walk_cap_fails_closed(self) -> None:
        from core.git_fs_client import GitForceRefused

        base = self._tip()
        self._write("/main/x", b"x")
        self._set_origin(base)
        self.s._ANCESTOR_WALK_CAP = 1
        with self.assertRaises(GitForceRefused):
            self._write("/main/y", b"y")


if __name__ == "__main__":
    unittest.main()
