"""Cancel All also stops a copy or move whose folder walk is still running.

Measured before: F5 / F6 walk the source tree on a worker thread
(``transfer_files_in_background``) and register the jobs only when the
walk is done. ``cancel_all`` only knew registered jobs, so pressing Cancel
All while a large (or slow remote) tree was still being walked did
nothing: a moment later every job was queued and ran - a cancelled move
still moved the files and removed the source folders.

Now Cancel All marks every walk in flight: the walk stops listing, its
jobs are never queued, and a move's source folders are not cleaned up.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402


class _GatedLocal(LocalFS):
    """LocalFS whose listings wait for *gate*; counts them."""

    def __init__(self, gate: threading.Event) -> None:
        self.gate = gate
        self.listed: list[str] = []

    def list_dir(self, path):
        self.listed.append(path)
        self.gate.wait(10)
        return super().list_dir(path)


class CancelDuringWalkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.walks_done = 0
        self.mgr.walk_finished.connect(self._walk_done)

    def _walk_done(self) -> None:
        self.walks_done += 1

    def pump(self, cond, timeout: float = 10.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.005)
        self.app.processEvents()
        return cond()

    def _tree(self, folders: int = 3, files: int = 2) -> None:
        for d in range(folders):
            for f in range(files):
                path = self.src / "tree" / f"d{d}" / f"f{f}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x" * 10)

    def _source_files(self) -> list[str]:
        return sorted(str(p.relative_to(self.src)) for p in self.src.rglob("*") if p.is_file())

    def _dest_files(self) -> list[str]:
        return sorted(str(p.relative_to(self.dst)) for p in self.dst.rglob("*") if p.is_file())

    def test_happy_cancel_all_in_the_dock_stops_a_move_still_walking(self) -> None:
        """e2e: the real dock's Cancel All button, a real LocalFS move."""
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        from ui.transfer_dock import TransferDock

        self._tree()
        before = self._source_files()
        dock = TransferDock(self.mgr)
        self.addCleanup(dock.deleteLater)
        gate = threading.Event()
        src_fs = _GatedLocal(gate)
        got: list = []
        self.mgr.transfer_files_in_background(
            src_fs, LocalFS(), [str(self.src / "tree")], str(self.dst), move=True,
            on_done=got.append,
        )
        self.assertTrue(self.pump(lambda: src_fs.listed))
        QTest.mouseClick(dock._btn_cancel, Qt.MouseButton.LeftButton)
        gate.set()
        self.assertTrue(self.pump(lambda: self.walks_done == 1))
        self.pump(lambda: False, timeout=0.3)  # a queued job would run now
        self.assertEqual(got, [[]])
        self.assertEqual(self.mgr.all_jobs(), [])
        self.assertEqual(dock._model.rowCount(), 0)
        self.assertEqual(self._source_files(), before)
        self.assertEqual(self._dest_files(), [])
        self.assertFalse(self.mgr.busy(src_fs))

    def test_sad_a_cancelled_walk_stops_listing_the_rest_of_the_tree(self) -> None:
        self._tree(folders=5)
        gate = threading.Event()
        src_fs = _GatedLocal(gate)
        self.mgr.transfer_files_in_background(
            src_fs, LocalFS(), [str(self.src / "tree")], str(self.dst)
        )
        self.assertTrue(self.pump(lambda: src_fs.listed))
        self.mgr.cancel_all()
        gate.set()
        self.assertTrue(self.pump(lambda: self.walks_done == 1))
        # The listing in progress finishes; none of the five subfolders is listed.
        self.assertEqual(src_fs.listed, [str(self.src / "tree")])
        self.assertEqual(self._dest_files(), [])

    def test_edge_a_cancelled_move_walk_keeps_its_source_folders(self) -> None:
        # A folder without files: the walk queues no job, only the
        # cleanup of the source folders would run.
        (self.src / "empty" / "sub").mkdir(parents=True)
        gate = threading.Event()
        src_fs = _GatedLocal(gate)
        self.mgr.transfer_files_in_background(
            src_fs, LocalFS(), [str(self.src / "empty")], str(self.dst), move=True
        )
        self.assertTrue(self.pump(lambda: src_fs.listed))
        self.mgr.cancel_all()
        gate.set()
        self.assertTrue(self.pump(lambda: self.walks_done == 1))
        self.assertTrue((self.src / "empty" / "sub").is_dir())

    def test_edge_a_walk_started_after_cancel_all_runs_normally(self) -> None:
        self._tree(folders=1, files=2)
        self.mgr.cancel_all()  # nothing in flight
        got: list = []
        self.mgr.transfer_files_in_background(
            LocalFS(), LocalFS(), [str(self.src / "tree")], str(self.dst), on_done=got.extend
        )
        self.assertTrue(self.pump(lambda: self.walks_done == 1))
        self.assertTrue(self.pump(lambda: len(self._dest_files()) == 2))
        self.assertEqual(len(got), 2)

    def test_edge_cancel_all_leaves_a_second_walk_of_the_same_backends_apart(self) -> None:
        """Two walks over one backend pair: the one that already finished
        keeps its jobs, the one still walking is dropped."""
        self._tree(folders=1, files=1)
        (self.src / "other").mkdir()
        (self.src / "other" / "o.txt").write_bytes(b"o")
        fs, dest = LocalFS(), LocalFS()
        first: list = []
        self.mgr.transfer_files_in_background(
            fs, dest, [str(self.src / "tree")], str(self.dst), on_done=first.extend
        )
        self.assertTrue(self.pump(lambda: self.walks_done == 1))
        gate = threading.Event()
        slow = _GatedLocal(gate)
        second: list = []
        self.mgr.transfer_files_in_background(
            slow, dest, [str(self.src / "other")], str(self.dst), on_done=second.extend
        )
        self.assertTrue(self.pump(lambda: slow.listed))
        self.mgr.cancel_all()
        gate.set()
        self.assertTrue(self.pump(lambda: self.walks_done == 2))
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertFalse((self.dst / "other" / "o.txt").exists())

    def test_edge_the_journal_closes_the_jobs_it_never_queued(self) -> None:
        """Each job the walk built opened an operation in the journal; a
        cancelled walk finishes them as cancelled instead of leaving them
        open for good."""
        import json
        from unittest import mock

        journal = self.tmp / "journal.jsonl"
        with mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": str(journal)}):
            self._tree(folders=2, files=2)
            gate = threading.Event()

            class _GateAfterFirst(LocalFS):
                listed = 0

                def list_dir(self, path):
                    _GateAfterFirst.listed += 1
                    if _GateAfterFirst.listed == 3:
                        gate.wait(10)  # the first subfolder's two jobs are built
                    return super().list_dir(path)

            self.mgr.transfer_files_in_background(
                _GateAfterFirst(), LocalFS(), [str(self.src / "tree")], str(self.dst)
            )
            self.assertTrue(self.pump(lambda: _GateAfterFirst.listed >= 3))
            self.mgr.cancel_all()
            gate.set()
            self.assertTrue(self.pump(lambda: self.walks_done == 1))
        rows = [json.loads(line) for line in journal.read_text().splitlines()]
        started = {r["operation_id"] for r in rows if r.get("phase") == "start"}
        finished = {r["operation_id"]: r["status"] for r in rows if r.get("phase") == "finish"}
        self.assertEqual(len(started), 2)
        self.assertEqual({finished.get(op) for op in started}, {"cancelled"})


if __name__ == "__main__":
    unittest.main()
