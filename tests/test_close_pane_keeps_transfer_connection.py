"""Closing a remote pane does not cut the transfers that use its connection.

Transfer jobs hold no reference
on the session they read from or write to. Closing the pane released the
last reference, the session was disconnected while its transfers ran,
and every remaining job failed ("Socket is closed" / "Server connection
dropped"), leaving a .part file behind. The pane now closes at once,
but its connection is given back only when its transfers are over.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Remote:
    """A remote session whose reads fail once it is disconnected; each
    read waits for *gate*, so a transfer stays in flight on demand."""

    name = "remote"

    def __init__(self, gate: threading.Event) -> None:
        self.connected = True
        self.gate = gate

    def disconnect(self) -> None:
        self.connected = False

    def separator(self) -> str:
        return "/"

    def home(self) -> str:
        return "/"

    def list_dir(self, path):
        return []

    def is_dir(self, path) -> bool:
        return path == "/"

    def exists(self, path) -> bool:
        return True

    def normalize(self, path):
        return path

    def join(self, *parts):
        return "/".join(p.rstrip("/") for p in parts)

    def parent(self, path):
        return path.rsplit("/", 1)[0] or "/"

    def checksum(self, path):
        return ""

    def stat(self, path):
        return mock.Mock(size=3 * 65536, mtime=0, permissions=0o644, is_dir=False)

    def open_read(self, path):
        session = self

        class _Reader(io.RawIOBase):
            chunks = 0

            def readable(self):
                return True

            def read(self, size=-1):
                session.gate.wait(10)
                if not session.connected:
                    raise OSError("Socket is closed")
                if self.chunks >= 3:
                    return b""
                self.chunks += 1
                return b"x" * 65536

        return _Reader()


class TransferManagerJobsUsingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_happy_edge_sad_jobs_using_names_only_unfinished_jobs_of_that_backend(self):
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferJob, TransferStatus

        tm = TransferManager()
        self.addCleanup(tm.shutdown)
        mine, other = object(), object()
        jobs = []
        for status, src, dst in (
            (TransferStatus.ACTIVE, mine, other),
            (TransferStatus.PENDING, other, mine),
            (TransferStatus.DONE, mine, other),
            (TransferStatus.ERROR, mine, other),
            (TransferStatus.ACTIVE, other, other),
        ):
            job = TransferJob(source_path="/a", dest_path="/b")
            job.status, job.source_backend, job.dest_backend = status, src, dst
            jobs.append(job)
        tm._jobs = {job.job_id: job for job in jobs}
        self.assertEqual(tm.jobs_using(mine), jobs[:2])  # happy: source and target
        self.assertEqual(tm.jobs_using(object()), [])  # sad: unknown backend
        self.assertEqual(tm.jobs_using(None), [])  # edge: nothing to match


class ClosePaneDuringTransferTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.profiles import ConnectionProfile
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.gate = threading.Event()
        self.addCleanup(self.gate.set)
        cm = self.win._connection_manager
        cm._create_session = lambda *a, **k: _Remote(self.gate)
        cm._enroll_health = cm._unenroll_health = cm._record_visit = lambda *a, **k: None
        self.profile = ConnectionProfile(name="srv", protocol="sftp", host="srv", username="u")
        self.session = cm.connect(self.profile)
        self.pane = self.win._add_pane_to_splitter(
            self.win._root_splitter, self.session, profile=self.profile
        )
        self.addCleanup(self.win._pane_profiles.clear)
        self.dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dest, ignore_errors=True)

    def pump_until(self, cond, timeout=10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return cond()

    def start_transfers(self, count=2):
        from core.local_fs import LocalFS

        paths = [f"/data/f{i}.bin" for i in range(count)]
        return self.win._transfer_manager.transfer_files(self.session, LocalFS(), paths, self.dest)

    def test_happy_transfers_finish_after_the_pane_closed(self) -> None:
        from core.transfer_worker import TransferStatus

        jobs = self.start_transfers()
        self.assertTrue(self.pump_until(lambda: jobs[0].status == TransferStatus.ACTIVE))
        self.win._close_pane(self.pane)
        self.assertNotIn(self.pane, self.win._panes)
        self.assertTrue(self.session.connected)  # kept for the transfers
        self.gate.set()
        done = (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)
        self.assertTrue(self.pump_until(lambda: all(j.status in done for j in jobs)))
        self.assertEqual([j.status for j in jobs], [TransferStatus.DONE] * 2)
        self.assertEqual(sorted(os.listdir(self.dest)), ["f0.bin", "f1.bin"])
        # ... and then the connection is given back.
        self.assertTrue(self.pump_until(lambda: not self.session.connected))

    def test_sad_no_transfers_releases_at_once(self) -> None:
        self.win._close_pane(self.pane)
        self.assertFalse(self.session.connected)

    def test_edge_a_cancelled_transfer_also_gives_the_connection_back(self) -> None:
        from core.transfer_worker import TransferStatus

        jobs = self.start_transfers(1)
        self.assertTrue(self.pump_until(lambda: jobs[0].status == TransferStatus.ACTIVE))
        self.win._close_pane(self.pane)
        self.assertTrue(self.session.connected)
        self.win._transfer_manager.cancel_all()
        self.gate.set()
        self.assertTrue(self.pump_until(lambda: not self.session.connected))
        self.assertEqual(jobs[0].status, TransferStatus.CANCELLED)


if __name__ == "__main__":
    unittest.main()
