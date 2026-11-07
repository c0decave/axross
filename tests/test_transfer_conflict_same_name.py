"""Two selected files with one name each keep their own conflict answer.

Copying ``x/a.txt`` and ``y/a.txt`` (a search result, a multi-folder
selection) into a folder that holds ``a.txt`` asks twice - but the
``ConflictPlan`` kept one answer per destination path, so the second
answer replaced the first and both jobs got it: "Rename" sent both to
the same new name (the second then failed), "overwrite x, skip y"
skipped both, "skip x, overwrite y" overwrote with both.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_conflicts import ConflictAction, ConflictPlan, scan_conflicts  # noqa: E402


class SameNameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        for name in ("x", "y", "dst"):
            (self.tmp / name).mkdir()
        (self.tmp / "x" / "a.txt").write_text("x")
        (self.tmp / "y" / "a.txt").write_text("y")
        (self.tmp / "dst" / "a.txt").write_text("old")
        self.paths = [str(self.tmp / "x" / "a.txt"), str(self.tmp / "y" / "a.txt")]
        self.dst = self.tmp / "dst"
        self.mgr = TransferManager()
        self.addCleanup(self._stop)
        patch = mock.patch.object(self.mgr._worker, "enqueue")  # inspect jobs only
        patch.start()
        self.addCleanup(patch.stop)

    def _stop(self) -> None:
        self.mgr._worker.stop()
        self.mgr._thread.quit()
        self.mgr._thread.wait(2000)

    def jobs(self, *answers):
        scan = scan_conflicts(self.fs, self.fs, self.paths, str(self.dst))
        self.assertEqual(len(scan.conflicts), 2)
        plan = ConflictPlan(self.fs, scan)
        for conflict, answer in zip(scan.conflicts, answers):
            plan.decide(conflict, answer)
        jobs = self.mgr.transfer_files(self.fs, self.fs, self.paths, str(self.dst),
                                       conflict_plan=plan)
        return {(j.source_path, j.dest_path, j.if_exists) for j in jobs}

    def test_happy_rename_gives_each_its_own_free_name(self) -> None:
        jobs = self.jobs(ConflictAction.RENAME, ConflictAction.RENAME)
        self.assertEqual(jobs, {
            (self.paths[0], str(self.dst / "a (1).txt"), "fail"),
            (self.paths[1], str(self.dst / "a (2).txt"), "fail"),
        })

    def test_sad_overwrite_one_and_skip_the_other(self) -> None:
        jobs = self.jobs(ConflictAction.OVERWRITE, ConflictAction.SKIP)
        self.assertEqual(jobs, {(self.paths[0], str(self.dst / "a.txt"), "overwrite")})

    def test_edge_skip_one_and_overwrite_the_other(self) -> None:
        jobs = self.jobs(ConflictAction.SKIP, ConflictAction.OVERWRITE)
        self.assertEqual(jobs, {(self.paths[1], str(self.dst / "a.txt"), "overwrite")})

    def test_edge_resolve_by_destination_alone_still_answers(self) -> None:
        scan = scan_conflicts(self.fs, self.fs, self.paths[:1], str(self.dst))
        plan = ConflictPlan(self.fs, scan)
        plan.decide(scan.conflicts[0], ConflictAction.OVERWRITE)
        self.assertEqual(plan.resolve(str(self.dst / "a.txt")),
                         (str(self.dst / "a.txt"), "overwrite"))
