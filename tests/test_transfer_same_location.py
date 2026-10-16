"""A transfer never targets its own source, nor a folder inside itself.

Measured before, with two panes on the same local folder:

* F6 (move) of a file onto itself copied the file over itself and then
  deleted "the source" -- the only copy. The job reported DONE.
* F5 (copy) of a folder into itself created ``dir/dir/dir/...`` 992 levels
  deep until a RecursionError escaped ``transfer_files`` on the GUI thread.
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

from core import storage_identity as SI  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402


class _Remote:
    """A network session that names its server, like SFTP/SMB do."""

    def __init__(self, host, port=22) -> None:
        self._profile = type("P", (), {"host": host, "port": port})()

    def separator(self) -> str:
        return "/"


class _OtherRemote(_Remote):
    pass


class SameEntryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "d").mkdir()
        (self.tmp / "d" / "f.txt").write_text("x")

    def test_happy_two_local_panes_on_one_folder_are_the_same_entry(self) -> None:
        f = str(self.tmp / "d" / "f.txt")
        self.assertTrue(SI.same_entry(LocalFS(), f, LocalFS(), f))

    def test_happy_a_different_folder_is_not_the_same_entry(self) -> None:
        (self.tmp / "e").mkdir()
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "d" / "f.txt"),
                          LocalFS(), str(self.tmp / "e" / "f.txt"))
        )

    def test_edge_a_symlinked_folder_is_seen_through(self) -> None:
        os.symlink(self.tmp / "d", self.tmp / "alias")
        self.assertTrue(
            SI.same_entry(LocalFS(), str(self.tmp / "d" / "f.txt"),
                          LocalFS(), str(self.tmp / "alias" / "f.txt"))
        )

    def test_edge_a_symlinked_file_is_its_own_entry(self) -> None:
        """Moving a link next to its target removes the link, not the data."""
        (self.tmp / "e").mkdir()
        os.symlink(self.tmp / "d" / "f.txt", self.tmp / "e" / "f.txt")
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "e" / "f.txt"),
                          LocalFS(), str(self.tmp / "d" / "f.txt"))
        )

    def test_edge_one_backend_object_compares_normalised_paths(self) -> None:
        ram = RamFsSession()
        self.assertTrue(SI.same_entry(ram, "/a/b.txt", ram, "/a/./b.txt"))
        self.assertFalse(SI.same_entry(ram, "/a/b.txt", RamFsSession(), "/a/b.txt"))

    def test_edge_two_sessions_to_one_server_compare_paths(self) -> None:
        self.assertTrue(SI.same_entry(_Remote("nas"), "/x", _Remote("NAS."), "/x"))
        self.assertFalse(SI.same_entry(_Remote("nas"), "/x", _Remote("nas", port=2222), "/x"))
        self.assertFalse(SI.same_entry(_Remote("nas"), "/x", _OtherRemote("nas"), "/x"))

    def test_sad_within_catches_a_folder_inside_itself(self) -> None:
        d = str(self.tmp / "d")
        self.assertTrue(SI.is_within(LocalFS(), d, LocalFS(), os.path.join(d, "d")))
        self.assertTrue(SI.is_within(LocalFS(), d, LocalFS(), d))
        self.assertFalse(SI.is_within(LocalFS(), d, LocalFS(), str(self.tmp / "dd")))


class ManagerTest(unittest.TestCase):
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
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.errors: list[tuple[str, str]] = []
        self.mgr.job_error.connect(lambda jid, msg: self.errors.append((jid, msg)))

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)
        self.app.processEvents()

    def test_happy_a_move_to_another_folder_still_works(self) -> None:
        src = self.tmp / "a.txt"
        src.write_bytes(b"data")
        (self.tmp / "out").mkdir()
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "out"),
                                       move=True)
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.DONE])
        self.assertEqual((self.tmp / "out" / "a.txt").read_bytes(), b"data")
        self.assertFalse(src.exists())

    def test_sad_moving_a_file_onto_itself_keeps_it(self) -> None:
        src = self.tmp / "only-copy.txt"
        src.write_bytes(b"precious")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp), move=True)
        self._wait(jobs)
        self.assertEqual(src.read_bytes(), b"precious")
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertIn("same", jobs[0].error_message)
        self.assertEqual([e[0] for e in self.errors], [jobs[0].job_id])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["only-copy.txt"])

    def test_sad_copying_a_folder_into_itself_is_refused(self) -> None:
        d = self.tmp / "dir"
        d.mkdir()
        (d / "a.txt").write_bytes(b"x")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(d)], str(d))
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual(sorted(os.listdir(d)), ["a.txt"])

    def test_sad_moving_a_folder_onto_itself_keeps_its_files(self) -> None:
        d = self.tmp / "dir"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "a.txt").write_bytes(b"x")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(d)], str(self.tmp), move=True)
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual((d / "sub" / "a.txt").read_bytes(), b"x")

    def test_edge_through_a_symlinked_target_folder(self) -> None:
        src = self.tmp / "f.txt"
        src.write_bytes(b"keep")
        os.symlink(self.tmp, self.tmp.parent / (self.tmp.name + "-alias"))
        self.addCleanup(os.unlink, self.tmp.parent / (self.tmp.name + "-alias"))
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)],
                                       str(self.tmp.parent / (self.tmp.name + "-alias")),
                                       move=True)
        self._wait(jobs)
        self.assertEqual(src.read_bytes(), b"keep")

    def test_edge_retrying_a_refused_move_is_still_refused(self) -> None:
        src = self.tmp / "f.txt"
        src.write_bytes(b"keep")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp), move=True)
        self._wait(jobs)
        retry = self.mgr.retry_job(jobs[0].job_id)
        assert retry is not None
        self._wait([retry])
        self.assertEqual(retry.status, TransferStatus.ERROR)
        self.assertEqual(src.read_bytes(), b"keep")

    def test_edge_one_ram_session_move_onto_itself(self) -> None:
        ram = RamFsSession()
        with ram.open_write("/d/x.bin") as fh:
            fh.write(b"ram")
        jobs = self.mgr.transfer_files(ram, ram, ["/d/x.bin"], "/d", move=True)
        self._wait(jobs)
        with ram.open_read("/d/x.bin") as fh:
            self.assertEqual(fh.read(), b"ram")


class WorkerNetTest(unittest.TestCase):
    """The worker refuses on its own: jobs also arrive via transfer_file."""

    def test_sad_a_same_entry_move_job_fails_before_touching_anything(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        f = tmp / "f.txt"
        f.write_bytes(b"keep")
        job = TransferJob(source_path=str(f), dest_path=str(f), total_bytes=4, filename="f.txt",
                          move=True, source_backend=LocalFS(), dest_backend=LocalFS())
        TransferWorker()._process_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(f.read_bytes(), b"keep")
        self.assertEqual(os.listdir(tmp), ["f.txt"])


if __name__ == "__main__":
    unittest.main()
