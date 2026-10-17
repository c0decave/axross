"""Git-FS file history: list_versions and open_version_read.

Every commit on a branch that changed a file is one version of it,
newest first, its id the commit sha. A version reads the file as that
commit had it. list_versions returned [] and open_version_read raised
"not yet implemented" before (core/git_fs_client.py, a TODO since v1).
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
class GitFsVersionsTest(unittest.TestCase):
    def setUp(self) -> None:
        from core.git_fs_client import GitFsSession

        tmp = Path(tempfile.mkdtemp(prefix="axross-gitfs-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        Repo.init_bare(str(tmp / "r.git"), mkdir=True)
        self.s = GitFsSession(
            path=str(tmp / "r.git"), author_name="T", author_email="t@example.com"
        )

    def _write(self, path: str, data: bytes) -> str:
        with self.s.open_write(path) as fh:
            fh.write(data)
        branch, _sub = self.s._split_branch(path)
        return self.s._branch_tips[branch].decode("ascii")

    # -- happy ---------------------------------------------------------------------

    def test_happy_every_change_is_a_version_newest_first(self) -> None:
        shas = [self._write("/main/a.txt", data) for data in (b"one", b"two!", b"three")]
        versions = self.s.list_versions("/main/a.txt")
        self.assertEqual([v.version_id for v in versions], list(reversed(shas)))
        self.assertEqual([v.size for v in versions], [5, 4, 3])
        self.assertEqual([v.is_current for v in versions], [True, False, False])
        self.assertTrue(all(v.label for v in versions))
        self.assertTrue(versions[0].modified >= versions[-1].modified)

    def test_happy_a_version_reads_the_file_as_it_was(self) -> None:
        first = self._write("/main/a.txt", b"one")
        self._write("/main/a.txt", b"two")
        with self.s.open_version_read("/main/a.txt", first) as fh:
            self.assertEqual(fh.read(), b"one")
        self.assertEqual(self.s.open_read("/main/a.txt").read(), b"two")

    def test_happy_changes_of_other_files_are_no_versions(self) -> None:
        mine = self._write("/main/dir/a.txt", b"mine")
        self._write("/main/b.txt", b"other")
        self._write("/main/dir/c.txt", b"other")
        self.assertEqual([v.version_id for v in self.s.list_versions("/main/dir/a.txt")], [mine])

    # -- sad -----------------------------------------------------------------------

    def test_sad_a_version_id_that_is_no_sha_is_refused(self) -> None:
        self._write("/main/a.txt", b"one")
        for bad in ("", "HEAD", "main", "../x", "zz" * 20, "abc"):
            with self.assertRaises(OSError):
                self.s.open_version_read("/main/a.txt", bad)

    def test_sad_an_unknown_sha_is_not_found(self) -> None:
        self._write("/main/a.txt", b"one")
        with self.assertRaises(FileNotFoundError):
            self.s.open_version_read("/main/a.txt", "0" * 40)

    def test_sad_a_version_before_the_file_existed_is_not_found(self) -> None:
        before = self._write("/main/other.txt", b"x")
        self._write("/main/a.txt", b"one")
        with self.assertRaises(FileNotFoundError):
            self.s.open_version_read("/main/a.txt", before)

    def test_sad_a_commit_outside_the_branchs_history_is_refused(self) -> None:
        self._write("/main/a.txt", b"main")
        refs = self.s._repo.refs
        refs[b"refs/heads/side"] = self.s._branch_tips["main"]
        self.s._refresh_branch_tips()
        side = self._write("/side/a.txt", b"side only")
        with self.assertRaises(OSError) as caught:
            self.s.open_version_read("/main/a.txt", side)
        self.assertNotIsInstance(caught.exception, FileNotFoundError)
        self.assertIn("history", str(caught.exception))
        with self.s.open_version_read("/side/a.txt", side) as fh:
            self.assertEqual(fh.read(), b"side only")

    def test_sad_a_blob_sha_is_no_version(self) -> None:
        self._write("/main/a.txt", b"one")
        blob = self.s._repo[self.s._repo[self.s._branch_tips["main"]].tree][b"a.txt"][1].decode()
        with self.assertRaises(OSError):
            self.s.open_version_read("/main/a.txt", blob)

    def test_sad_a_folder_has_no_versions_and_reads_as_no_file(self) -> None:
        sha = self._write("/main/dir/a.txt", b"one")
        self.assertEqual(self.s.list_versions("/main/dir"), [])
        with self.assertRaises(IsADirectoryError):
            self.s.open_version_read("/main/dir", sha)

    def test_sad_an_unknown_branch_raises(self) -> None:
        self._write("/main/a.txt", b"one")
        with self.assertRaises(OSError):
            self.s.list_versions("/nope/a.txt")

    # -- edge ----------------------------------------------------------------------

    def test_edge_a_deleted_file_keeps_its_history_and_none_is_current(self) -> None:
        first = self._write("/main/a.txt", b"one")
        self._write("/main/keep.txt", b"k")
        self.s.remove("/main/a.txt")
        versions = self.s.list_versions("/main/a.txt")
        self.assertEqual([v.version_id for v in versions], [first])
        self.assertFalse(versions[0].is_current)
        with self.s.open_version_read("/main/a.txt", first) as fh:
            self.assertEqual(fh.read(), b"one")

    def test_edge_the_branch_root_and_a_missing_file_have_no_versions(self) -> None:
        self._write("/main/a.txt", b"one")
        self.assertEqual(self.s.list_versions("/main"), [])
        self.assertEqual(self.s.list_versions("/main/missing.txt"), [])

    def test_edge_a_branch_with_a_slash_and_an_upper_case_sha(self) -> None:
        self._write("/main/a.txt", b"one")
        self.s._repo.refs[b"refs/heads/feature/x"] = self.s._branch_tips["main"]
        self.s._refresh_branch_tips()
        sha = self._write("/feature/x/a.txt", b"fx")
        (newest, *_rest) = self.s.list_versions("/feature/x/a.txt")
        self.assertEqual(newest.version_id, sha)
        with self.s.open_version_read("/feature/x/a.txt", sha.upper()) as fh:
            self.assertEqual(fh.read(), b"fx")

    def test_edge_the_list_is_bounded(self) -> None:
        from core import git_fs_client as G

        for i in range(5):
            self._write("/main/a.txt", str(i).encode())
        old = G.MAX_VERSIONS
        G.MAX_VERSIONS = 3
        try:
            self.assertEqual(len(self.s.list_versions("/main/a.txt")), 3)
        finally:
            G.MAX_VERSIONS = old


if __name__ == "__main__":
    unittest.main()
