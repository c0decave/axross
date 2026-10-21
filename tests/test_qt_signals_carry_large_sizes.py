"""Byte counts above 2 GiB survive Qt signals.

A ``pyqtSignal(int)`` argument is a 32-bit C++ int: 3 GiB arrives as
-1 GiB. Reported: after a move some files showed 0 % and a negative size
in the Transfers dock - the files larger than 2 GiB. Sizes, offsets and
byte counts travel as ``object``; a test holds every ``int`` signal in the
tree to a reviewed list, so a new one gets looked at.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

GiB = 1024**3
#: Values that a 32-bit int wraps (3 GiB -> negative, 5 GiB -> 1 GiB), and
#: the small and "unknown" ones that must stay as they are.
SIZES = (3 * GiB, 5 * GiB, 2**31 - 1, 0, -1)

#: Signals that carry int arguments, reviewed: none of them is a size, an
#: offset or a byte count (tokens, rows, levels, modes, ids, grid cells).
REVIEWED_INT_SIGNALS = {
    "ui/log_dock.py:log_record",
    "ui/permissions_dialog.py:mode_changed",
    "ui/llm_settings_dialog.py:done",
    "ui/agent_dock.py:recall",
    "ui/terminal_widget.py:grid_resized",
    "ui/analysis_dock.py:finished",
    "ui/analysis_dock.py:event",
    "ui/analysis_dock.py:started",
    "ui/analysis_dock.py:listed",
    "ui/cas_history_dialog.py:show_duplicates_requested",
    "ui/media_viewer.py:_done",
    "ui/media_viewer.py:open_requested",
    "ui/media_viewer.py:index_changed",
}


def _app():
    from PyQt6.QtCore import QCoreApplication
    from PyQt6.QtWidgets import QApplication

    return QCoreApplication.instance() or QApplication([])


class TransferProgressTest(unittest.TestCase):
    def test_happy_worker_progress_carries_sizes_above_2_gib(self) -> None:
        _app()
        from core.transfer_worker import TransferWorker

        worker = TransferWorker()
        got = []
        worker.progress.connect(lambda j, done, total: got.append((done, total)))
        for size in SIZES:
            worker.progress.emit("j", size, size)
        self.assertEqual(got, [(s, s) for s in SIZES])

    def test_happy_the_dock_shows_a_3_gib_file_finished_not_negative(self) -> None:
        app = _app()
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferJob
        from models.transfer_model import COL_PROGRESS, COL_SIZE, TransferModel

        manager = TransferManager()
        self.addCleanup(manager.shutdown)
        job = TransferJob(source_path="/a/big.img", dest_path="/b/big.img", filename="big.img")
        manager._jobs[job.job_id] = job
        manager._worker.progress.emit(job.job_id, 3 * GiB, 3 * GiB)
        app.processEvents()
        self.assertEqual(job.total_bytes, 3 * GiB)
        self.assertEqual(job.progress_percent, 100.0)
        model = TransferModel()
        model.add_job(job)
        size_text = model.index(0, COL_SIZE).data()
        self.assertEqual(size_text, "3.0 GB")
        self.assertEqual(model.index(0, COL_PROGRESS).data(), "100%")

    def test_edge_half_of_5_gib_is_50_percent(self) -> None:
        app = _app()
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferJob

        manager = TransferManager()
        self.addCleanup(manager.shutdown)
        job = TransferJob(source_path="/a/x", dest_path="/b/x", filename="x")
        manager._jobs[job.job_id] = job
        manager._worker.progress.emit(job.job_id, 5 * GiB // 2, 5 * GiB)
        app.processEvents()
        self.assertEqual((job.transferred_bytes, job.total_bytes), (5 * GiB // 2, 5 * GiB))
        self.assertAlmostEqual(job.progress_percent, 50.0)


class PropertiesSizeTest(unittest.TestCase):
    def test_happy_the_folder_size_walk_reports_above_2_gib(self) -> None:
        _app()
        from ui.properties_dialog import _SizeWorker

        worker = _SizeWorker(backend=None, path="/")
        got = []
        worker.done.connect(got.append)
        for size in SIZES:
            worker.done.emit(size)
        self.assertEqual(got, list(SIZES))


class IntSignalReviewTest(unittest.TestCase):
    """Every pyqtSignal with an int argument is on the reviewed list."""

    @staticmethod
    def _int_signals() -> set[str]:
        found = set()
        for top in ("core", "ui", "models"):
            for path in sorted((ROOT / top).rglob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                        continue
                    func = node.value.func
                    name = getattr(func, "id", None) or getattr(func, "attr", None)
                    if name != "pyqtSignal":
                        continue
                    if any(
                        (isinstance(a, ast.Name) and a.id == "int")
                        or (isinstance(a, ast.Constant) and a.value in ("int", "qint32"))
                        for a in node.value.args
                    ):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                rel = path.relative_to(ROOT).as_posix()
                                found.add(f"{rel}:{target.id}")
        return found

    def test_sad_no_unreviewed_int_signal(self) -> None:
        self.assertEqual(self._int_signals() - REVIEWED_INT_SIGNALS, set())

    def test_edge_the_reviewed_list_has_no_stale_entries(self) -> None:
        self.assertEqual(REVIEWED_INT_SIGNALS - self._int_signals(), set())


if __name__ == "__main__":
    unittest.main()
