"""A move within one remote session is a rename on the server.

Review round 3: dragging a 40 MiB file onto a subfolder in an SFTP pane
(F6 between two panes of one connection, Cut/Paste) downloaded and
uploaded every byte (5.7 s; 1313 READs and 1280 WRITEs on the server),
where one SFTP RENAME takes 4 ms. ``TransferWorker._move_by_rename``
covered only LocalFS -> LocalFS.

Now a move whose source and destination are the same backend session
renames on the server first (``TransferWorker._move_on_server``) and takes
the transfer engine only when that is not possible. The move's rules
stay: an existing destination is not replaced unless the answers allow it
(and a planned overwrite takes the copy, with its temp file), the journal
records the move, and a refused rename falls back to the copy.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.transfer_worker import TransferDirection, TransferStatus  # noqa: E402

DATA = os.urandom(256 * 1024)


class SameServerMoveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.profiles import ConnectionProfile
        from core.ssh_client import SSHSession
        from core.transfer_manager import TransferManager
        from tests.sftp_testkit import SftpServer

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "srv"
        (self.root / "in" / "archive").mkdir(parents=True)
        (self.root / "in" / "big.bin").write_bytes(DATA)
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        patch = mock.patch("pathlib.Path.home", return_value=home)
        patch.start()
        self.addCleanup(patch.stop)
        server = SftpServer(str(self.root))
        self.addCleanup(server.close)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"
        )
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.reads: list[str] = []
        real_open_read = self.s.open_read

        def counting_open_read(path):
            self.reads.append(path)
            return real_open_read(path)

        self.s.open_read = counting_open_read

    def _wait(self, jobs):
        deadline = time.monotonic() + 30
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            self.assertLess(time.monotonic(), deadline, "move did not finish")
            time.sleep(0.01)
        self.app.processEvents()
        return jobs

    def _move(self, paths, dest_dir="/in/archive", **kw):
        return self._wait(self.mgr.transfer_files(
            self.s, self.s, paths, dest_dir, TransferDirection.RELAY, move=True, **kw))

    # --- happy ---------------------------------------------------------------

    def test_happy_a_file_moved_within_one_server_is_renamed_there(self) -> None:
        [job] = self._move(["/in/big.bin"])
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual((self.root / "in" / "archive" / "big.bin").read_bytes(), DATA)
        self.assertFalse((self.root / "in" / "big.bin").exists())
        self.assertEqual(self.reads, [], "the move read the file through the client")

    def test_happy_a_folder_moved_within_one_server_reads_no_byte(self) -> None:
        proj = self.root / "in" / "proj"
        (proj / "sub").mkdir(parents=True)
        (proj / "a.txt").write_text("a")
        (proj / "sub" / "b.txt").write_text("b")
        jobs = self._move(["/in/proj"])
        self.assertTrue(all(j.status is TransferStatus.DONE for j in jobs),
                        [(j.filename, j.error_message) for j in jobs])
        moved = self.root / "in" / "archive" / "proj"
        self.assertEqual((moved / "a.txt").read_text(), "a")
        self.assertEqual((moved / "sub" / "b.txt").read_text(), "b")
        self.assertFalse(proj.exists())
        self.assertEqual(self.reads, [])

    # --- sad -----------------------------------------------------------------

    def test_sad_a_rename_the_server_refuses_falls_back_to_the_copy(self) -> None:
        with mock.patch.object(type(self.s), "rename_no_replace",
                               side_effect=OSError("Permission denied")) as refused:
            [job] = self._move(["/in/big.bin"])
        self.assertTrue(refused.called)
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual((self.root / "in" / "archive" / "big.bin").read_bytes(), DATA)
        self.assertFalse((self.root / "in" / "big.bin").exists())
        self.assertEqual(self.reads, ["/in/big.bin"])  # the copy

    def test_sad_an_existing_destination_is_not_replaced_without_an_answer(self) -> None:
        (self.root / "in" / "archive" / "big.bin").write_bytes(b"keep me")
        job = self.mgr.transfer_file(self.s, self.s, "/in/big.bin", "/in/archive/big.bin",
                                     TransferDirection.RELAY, move=True, if_exists="fail")
        self._wait([job])
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("already exists", job.error_message)
        self.assertEqual((self.root / "in" / "archive" / "big.bin").read_bytes(), b"keep me")
        self.assertEqual((self.root / "in" / "big.bin").read_bytes(), DATA)
        self.assertEqual(self.reads, [], "refused before a byte was read")

    # --- edge ----------------------------------------------------------------

    def test_edge_a_planned_overwrite_takes_the_copy_not_a_rename(self) -> None:
        (self.root / "in" / "archive" / "big.bin").write_bytes(b"old")
        with mock.patch.object(type(self.s), "rename_no_replace",
                               wraps=self.s.rename_no_replace) as renamed:
            job = self.mgr.transfer_file(self.s, self.s, "/in/big.bin", "/in/archive/big.bin",
                                         TransferDirection.RELAY, move=True)
            self._wait([job])
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertFalse(renamed.called, "posix-rename would replace without the copy's rollback")
        self.assertEqual((self.root / "in" / "archive" / "big.bin").read_bytes(), DATA)
        self.assertFalse((self.root / "in" / "big.bin").exists())

    def test_edge_the_journal_records_the_renamed_move(self) -> None:
        from core.operation_journal import read_recent

        journal = self.tmp / "ops.jsonl"
        with mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": str(journal)}):
            [job] = self._move(["/in/big.bin"])
            events = [e for e in read_recent(50) if e.get("phase") == "finish"]
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual(self.reads, [])
        [finish] = events
        self.assertEqual((finish["operation"], finish["status"]), ("move", "done"))
        self.assertEqual(finish["source"], "/in/big.bin")
        self.assertEqual(finish["dest"], "/in/archive/big.bin")


if __name__ == "__main__":
    unittest.main()
