""""Rename" never picks a name another item of the same copy creates.

Measured before: copying ``a.txt`` and ``a (1).txt`` into a folder that
holds ``a.txt`` and answering "Rename" gave ``a.txt`` the new name
``a (1).txt`` - free in the destination listing, but the other item of
the batch was about to create it. The second job then failed with
"already exists" and ``a (1).txt`` was not copied.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_conflicts import ConflictAction, ConflictPlan, scan_conflicts  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402


class RenameTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        self.fs = LocalFS()

    def _plan(self, sources: list[Path]) -> ConflictPlan:
        scan = scan_conflicts(self.fs, self.fs, [str(s) for s in sources], str(self.dst))
        plan = ConflictPlan(self.fs, scan)
        for c in scan.conflicts:
            plan.decide(c, ConflictAction.RENAME)
        return plan

    def test_sad_a_rename_skips_a_name_the_batch_creates(self) -> None:
        for name in ("a.txt", "a (1).txt"):
            (self.src / name).write_text(name)
        (self.dst / "a.txt").write_text("dest")
        plan = self._plan([self.src / "a.txt", self.src / "a (1).txt"])
        renamed, _ = plan.resolve(str(self.dst / "a.txt"))
        kept, _ = plan.resolve(str(self.dst / "a (1).txt"))
        self.assertEqual(os.path.basename(renamed), "a (2).txt")
        self.assertEqual(os.path.basename(kept), "a (1).txt")

    def test_edge_names_inside_a_merged_folder_count_too(self) -> None:
        (self.src / "d").mkdir()
        (self.dst / "d").mkdir()
        for name in ("x.txt", "x (1).txt"):
            (self.src / "d" / name).write_text(name)
        (self.dst / "d" / "x.txt").write_text("dest")
        plan = self._plan([self.src / "d"])
        renamed, _ = plan.resolve(str(self.dst / "d" / "x.txt"))
        self.assertEqual(os.path.basename(renamed), "x (2).txt")

    def test_happy_a_lone_conflict_still_gets_the_first_number(self) -> None:
        (self.src / "a.txt").write_text("s")
        (self.dst / "a.txt").write_text("d")
        plan = self._plan([self.src / "a.txt"])
        renamed, _ = plan.resolve(str(self.dst / "a.txt"))
        self.assertEqual(os.path.basename(renamed), "a (1).txt")

    def test_happy_the_whole_batch_is_copied(self) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        app = QApplication.instance() or QApplication([])
        from core.transfer_manager import TransferManager

        for name in ("a.txt", "a (1).txt"):
            (self.src / name).write_text("SOURCE " + name)
        (self.dst / "a.txt").write_text("DEST")
        sources = [self.src / "a.txt", self.src / "a (1).txt"]
        plan = self._plan(sources)
        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        jobs = mgr.transfer_files(self.fs, self.fs, [str(s) for s in sources], str(self.dst),
                                  conflict_plan=plan)
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)
        self.assertEqual([j.status for j in jobs], [TransferStatus.DONE] * 2)
        contents = {p.name: p.read_text() for p in self.dst.iterdir()}
        self.assertEqual(contents, {"a.txt": "DEST", "a (1).txt": "SOURCE a (1).txt",
                                    "a (2).txt": "SOURCE a.txt"})


if __name__ == "__main__":
    unittest.main()
