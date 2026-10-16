"""Undo of a transfer-engine move reads the direction and the backend.

Measured before: the transfer engine recorded the direction and the
destination backend only on the operation's START event, while undo reads
the FINISH event (only it knows whether the move succeeded). The finish
event carried neither, so every cross-backend move was planned as a
same-backend ``rename(dest, source)`` with an empty backend label, and the
main window then ran that rename on whichever backend happened to be open
first -- the source path of one host applied to another.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.undo import undoable  # noqa: E402


def _row(phase, *, operation_id="op1", status="", backend="", details=None,
         source="/remote/a.txt", dest="/local/a.txt") -> dict:
    return {
        "operation_id": operation_id,
        "operation": "move",
        "phase": phase,
        "status": status,
        "source": source,
        "dest": dest,
        "backend": backend,
        "details": details or {},
    }


class FinishEventFieldsTest(unittest.TestCase):
    def test_happy_a_finish_event_with_its_own_fields_is_used_as_is(self) -> None:
        plans = undoable([
            _row("finish", status="done", backend="Local", details={"direction": "UPLOAD"}),
        ])
        self.assertEqual(plans[0].action, "transfer_back")
        self.assertEqual(plans[0].backend, "Local")

    def test_sad_an_older_journal_takes_direction_and_backend_from_the_start(self) -> None:
        """Journals written before the fix have the fields on the start
        event only; undoing those must not degrade into a rename."""
        plans = undoable([
            _row("start", status="active", backend="Local",
                 details={"direction": "DOWNLOAD", "temp_file": True}),
            _row("worker_start", status="active"),
            _row("finish", status="done"),
        ])
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].action, "transfer_back")
        self.assertEqual(plans[0].direction, "DOWNLOAD")
        self.assertEqual(plans[0].backend, "Local")

    def test_edge_a_start_event_of_another_operation_is_not_borrowed(self) -> None:
        plans = undoable([
            _row("start", operation_id="other", backend="SFTP: prod",
                 details={"direction": "UPLOAD"}),
            _row("finish", operation_id="mine", status="done", backend="Local"),
        ])
        self.assertEqual(plans[0].action, "move_back")
        self.assertEqual(plans[0].backend, "Local")

    def test_edge_the_finish_event_wins_over_the_start_event(self) -> None:
        plans = undoable([
            _row("start", backend="Old", details={"direction": "UPLOAD"}),
            _row("finish", status="done", backend="New", details={"direction": "RELAY"}),
        ])
        self.assertEqual(plans[0].backend, "New")
        self.assertEqual(plans[0].direction, "RELAY")


class TransferEngineJournalTest(unittest.TestCase):
    """End to end: a real move through TransferManager, then the journal."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.journal = self.tmp / "operations.jsonl"
        previous = os.environ.get("AXROSS_OPERATION_JOURNAL")
        os.environ["AXROSS_OPERATION_JOURNAL"] = str(self.journal)

        def _restore() -> None:
            if previous is None:
                os.environ.pop("AXROSS_OPERATION_JOURNAL", None)
            else:
                os.environ["AXROSS_OPERATION_JOURNAL"] = previous

        self.addCleanup(_restore)

    def _run(self, job) -> None:
        from core.transfer_worker import TransferStatus

        deadline = time.monotonic() + 10
        while job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)

    def _finish_events(self) -> list[dict]:
        rows = [json.loads(line) for line in self.journal.read_text().splitlines()]
        return [r for r in rows if r.get("phase") == "finish"]

    def test_happy_a_move_is_undone_by_transferring_it_back(self) -> None:
        from core.local_fs import LocalFS
        from core.operation_journal import read_recent
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferDirection, TransferStatus

        src = self.tmp / "a.txt"
        src.write_bytes(b"payload")
        (self.tmp / "out").mkdir()
        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        job = mgr.transfer_file(
            LocalFS(), LocalFS(), str(src), str(self.tmp / "out" / "a.txt"),
            TransferDirection.UPLOAD, move=True,
        )
        self._run(job)
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)

        finish = self._finish_events()
        self.assertEqual(finish[-1]["details"].get("direction"), "UPLOAD")
        self.assertEqual(finish[-1]["backend"], "Local")

        plans = undoable(read_recent(limit=50))
        self.assertEqual(plans[0].action, "transfer_back")
        self.assertEqual(plans[0].backend, "Local")

    def test_sad_a_failed_move_stays_non_reversible(self) -> None:
        from core.local_fs import LocalFS
        from core.operation_journal import read_recent
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferDirection, TransferStatus

        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        job = mgr.transfer_file(
            LocalFS(), LocalFS(), str(self.tmp / "missing.txt"), str(self.tmp / "x.txt"),
            TransferDirection.DOWNLOAD, move=True,
        )
        self._run(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(self._finish_events()[-1]["details"].get("direction"), "DOWNLOAD")
        plans = undoable(read_recent(limit=50))
        self.assertFalse(plans[0].reversible)


if __name__ == "__main__":
    unittest.main()
