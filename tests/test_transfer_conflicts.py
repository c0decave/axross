"""Copy / move onto an existing name asks first, and never overwrites by accident.

Measured before: F5 / F6 / drag & drop handed the selection straight to
``TransferManager.transfer_files``, which queued one job per file with no
existence check; the worker then snapshot and overwrote whatever was at
the destination. This file covers the engine half:

* ``scan_conflicts`` finds every name the transfer would replace,
  including inside folders that merge into an existing folder;
* a ``ConflictPlan`` turns the user's answers into jobs (skip, rename to
  ``name (1).ext``, overwrite, overwrite if newer);
* the worker re-checks at run time, so a file that appears after the
  prompt is not overwritten silently, and a move whose copy was skipped
  keeps its source.
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

from core.local_fs import LocalFS  # noqa: E402


def _age(path: Path, seconds: float) -> None:
    """Set *path*'s mtime *seconds* into the past."""
    t = time.time() - seconds
    os.utime(path, (t, t))


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        self.fs = LocalFS()


class UniqueNameTest(unittest.TestCase):
    def test_happy_first_free_number_before_the_extension(self) -> None:
        from core.transfer_conflicts import unique_name

        self.assertEqual(unique_name("a.txt", {"a.txt"}), "a (1).txt")

    def test_edge_skips_numbers_already_taken(self) -> None:
        from core.transfer_conflicts import unique_name

        taken = {"a.txt", "a (1).txt", "a (2).txt"}
        self.assertEqual(unique_name("a.txt", taken), "a (3).txt")

    def test_edge_dotfile_and_no_extension_and_folder(self) -> None:
        from core.transfer_conflicts import unique_name

        self.assertEqual(unique_name(".bashrc", {".bashrc"}), ".bashrc (1)")
        self.assertEqual(unique_name("Makefile", {"Makefile"}), "Makefile (1)")
        self.assertEqual(unique_name("v1.2", {"v1.2"}, is_dir=True), "v1.2 (1)")

    def test_edge_a_free_name_is_kept(self) -> None:
        from core.transfer_conflicts import unique_name

        self.assertEqual(unique_name("b.txt", {"a.txt"}), "b.txt")


class ScanTest(_Tree):
    def scan(self, *names):
        from core.transfer_conflicts import scan_conflicts

        paths = [str(self.src / n) for n in names]
        return scan_conflicts(self.fs, self.fs, paths, str(self.dst))

    def test_happy_an_existing_file_is_a_conflict(self) -> None:
        (self.src / "a.txt").write_text("new")
        (self.src / "b.txt").write_text("new")
        (self.dst / "a.txt").write_text("old!")
        scan = self.scan("a.txt", "b.txt")
        self.assertEqual([c.dest_path for c in scan.conflicts], [str(self.dst / "a.txt")])
        c = scan.conflicts[0]
        self.assertEqual((c.name, c.source_size, c.dest_size), ("a.txt", 3, 4))
        self.assertFalse(c.source_is_dir or c.dest_is_dir)

    def test_happy_folders_merge_and_report_conflicts_inside(self) -> None:
        (self.src / "d" / "e").mkdir(parents=True)
        (self.src / "d" / "x.txt").write_text("new")
        (self.src / "d" / "only-new.txt").write_text("new")
        (self.src / "d" / "e" / "y.txt").write_text("new")
        (self.dst / "d" / "e").mkdir(parents=True)
        (self.dst / "d" / "x.txt").write_text("old")
        (self.dst / "d" / "e" / "y.txt").write_text("old")
        scan = self.scan("d")
        self.assertEqual(
            sorted(c.dest_path for c in scan.conflicts),
            sorted([str(self.dst / "d" / "x.txt"), str(self.dst / "d" / "e" / "y.txt")]),
        )

    def test_happy_nothing_to_report_into_an_empty_folder(self) -> None:
        (self.src / "d").mkdir()
        (self.src / "d" / "x.txt").write_text("new")
        (self.src / "a.txt").write_text("new")
        self.assertEqual(self.scan("d", "a.txt").conflicts, [])

    def test_edge_file_against_folder_is_a_type_mismatch(self) -> None:
        (self.src / "a").write_text("new")
        (self.dst / "a").mkdir()
        (self.src / "d").mkdir()
        (self.dst / "d").write_text("old")
        scan = self.scan("a", "d")
        self.assertEqual(len(scan.conflicts), 2)
        self.assertTrue(all(c.type_mismatch for c in scan.conflicts))

    def test_sad_an_unreadable_destination_raises(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        (self.src / "a.txt").write_text("new")
        with self.assertRaises(OSError):
            scan_conflicts(self.fs, self.fs, [str(self.src / "a.txt")], str(self.tmp / "missing"))

    def test_edge_cancel_stops_the_walk(self) -> None:
        from core.transfer_conflicts import ScanCancelled, scan_conflicts

        (self.src / "a.txt").write_text("new")
        with self.assertRaises(ScanCancelled):
            scan_conflicts(
                self.fs, self.fs, [str(self.src / "a.txt")], str(self.dst), cancel=lambda: True
            )


class _Manager(_Tree):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        super().setUp()
        self.mgr = TransferManager()
        self.addCleanup(self._stop)
        p = mock.patch.object(self.mgr._worker, "enqueue")  # inspect jobs only
        p.start()
        self.addCleanup(p.stop)

    def _stop(self) -> None:
        self.mgr._worker.stop()
        self.mgr._thread.quit()
        self.mgr._thread.wait(2000)

    def plan(self, names, answer):
        from core.transfer_conflicts import ConflictPlan, scan_conflicts

        paths = [str(self.src / n) for n in names]
        scan = scan_conflicts(self.fs, self.fs, paths, str(self.dst))
        plan = ConflictPlan(self.fs, scan)
        for c in scan.conflicts:
            plan.decide(c, answer)
        return paths, plan

    def enqueue(self, names, answer, move=False):
        paths, plan = self.plan(names, answer)
        return self.mgr.transfer_files(
            self.fs, self.fs, paths, str(self.dst), move=move, conflict_plan=plan
        )


class PlanToJobsTest(_Manager):
    def setUp(self) -> None:
        super().setUp()
        (self.src / "a.txt").write_text("new")
        (self.src / "b.txt").write_text("new")
        (self.dst / "a.txt").write_text("old")

    def test_happy_skip_queues_nothing_for_that_name(self) -> None:
        from core.transfer_conflicts import ConflictAction

        jobs = self.enqueue(["a.txt", "b.txt"], ConflictAction.SKIP)
        self.assertEqual([j.dest_path for j in jobs], [str(self.dst / "b.txt")])
        self.assertEqual(jobs[0].if_exists, "fail")

    def test_happy_rename_targets_a_free_name(self) -> None:
        from core.transfer_conflicts import ConflictAction

        (self.dst / "a (1).txt").write_text("taken")
        jobs = self.enqueue(["a.txt"], ConflictAction.RENAME)
        self.assertEqual([j.dest_path for j in jobs], [str(self.dst / "a (2).txt")])
        self.assertEqual(jobs[0].if_exists, "fail")

    def test_happy_overwrite_is_explicit_on_the_job(self) -> None:
        from core.transfer_conflicts import ConflictAction

        jobs = self.enqueue(["a.txt"], ConflictAction.OVERWRITE)
        self.assertEqual([(j.dest_path, j.if_exists) for j in jobs],
                         [(str(self.dst / "a.txt"), "overwrite")])

    def test_edge_overwrite_if_newer_drops_an_older_source(self) -> None:
        from core.transfer_conflicts import ConflictAction

        _age(self.src / "a.txt", 3600)
        self.assertEqual(self.enqueue(["a.txt"], ConflictAction.OVERWRITE_IF_NEWER), [])

    def test_edge_overwrite_if_newer_keeps_a_newer_source(self) -> None:
        from core.transfer_conflicts import ConflictAction

        _age(self.dst / "a.txt", 3600)
        jobs = self.enqueue(["a.txt"], ConflictAction.OVERWRITE_IF_NEWER)
        self.assertEqual([j.if_exists for j in jobs], ["newer"])

    def test_edge_without_a_plan_the_old_overwrite_semantics_stay(self) -> None:
        jobs = self.mgr.transfer_files(self.fs, self.fs, [str(self.src / "a.txt")], str(self.dst))
        self.assertEqual([j.if_exists for j in jobs], ["overwrite"])

    def test_edge_two_renames_in_one_batch_do_not_collide(self) -> None:
        from core.transfer_conflicts import ConflictAction

        (self.src / "d").mkdir()
        (self.src / "d" / "a.txt").write_text("other")
        (self.dst / "d").mkdir()
        (self.dst / "d" / "a.txt").write_text("old")
        (self.dst / "d" / "a (1).txt").write_text("taken")
        jobs = self.enqueue(["a.txt", "d"], ConflictAction.RENAME)
        self.assertEqual(
            sorted(j.dest_path for j in jobs),
            sorted([str(self.dst / "a (1).txt"), str(self.dst / "d" / "a (2).txt")]),
        )

    def test_sad_a_skipped_folder_queues_nothing_inside(self) -> None:
        from core.transfer_conflicts import ConflictAction

        (self.src / "d").mkdir()
        (self.src / "d" / "x.txt").write_text("new")
        (self.dst / "d").write_text("a file named like the folder")
        self.assertEqual(self.enqueue(["d"], ConflictAction.SKIP), [])


class WorkerRecheckTest(_Tree):
    """The worker re-checks: the prompt's answer is not a licence to clobber."""

    def job(self, name, if_exists, *, move=False, use_temp=True):
        from core.transfer_worker import TransferJob

        job = TransferJob(
            source_path=str(self.src / name),
            dest_path=str(self.dst / name),
            filename=name,
            total_bytes=(self.src / name).stat().st_size,
            move=move,
            use_temp_file=use_temp,
        )
        job.if_exists = if_exists
        job.source_backend = self.fs
        job.dest_backend = self.fs
        return job

    def run_job(self, job) -> None:
        from core.transfer_worker import TransferWorker

        TransferWorker()._process_job(job)

    def test_sad_a_file_that_appeared_after_the_prompt_is_not_overwritten(self) -> None:
        from core.transfer_worker import TransferStatus

        for use_temp in (True, False):
            with self.subTest(use_temp=use_temp):
                (self.src / "a.txt").write_text("new")
                (self.dst / "a.txt").write_text("appeared later")
                job = self.job("a.txt", "fail", move=True, use_temp=use_temp)
                self.run_job(job)
                self.assertEqual(job.status, TransferStatus.ERROR)
                self.assertIn("already exists", job.error_message)
                self.assertEqual((self.dst / "a.txt").read_text(), "appeared later")
                self.assertTrue((self.src / "a.txt").exists())
                self.assertEqual(sorted(p.name for p in self.dst.iterdir()), ["a.txt"])

    def test_sad_a_file_that_appears_during_the_copy_is_not_overwritten(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        job = self.job("a.txt", "fail")
        real_open_read = self.fs.open_read
        dest = self.dst / "a.txt"

        def open_then_appear(path):
            handle = real_open_read(path)
            dest.write_text("raced in")  # another program, mid-copy
            return handle

        with mock.patch.object(self.fs, "open_read", open_then_appear):
            self.run_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual((self.dst / "a.txt").read_text(), "raced in")
        self.assertEqual(sorted(p.name for p in self.dst.iterdir()), ["a.txt"])

    def test_happy_fail_mode_writes_a_free_name(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        job = self.job("a.txt", "fail")
        self.run_job(job)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "a.txt").read_text(), "new")

    def _count_dest_exists(self, job) -> list[str]:
        """Runs *job*; the destination paths its backend was asked
        ``exists`` about."""
        asked: list[str] = []
        real_exists = self.fs.exists

        def exists(path):
            if path == job.dest_path:
                asked.append(path)
            return real_exists(path)

        with mock.patch.object(self.fs, "exists", exists):
            self.run_job(job)
        return asked

    def test_happy_fail_mode_through_a_temp_file_asks_once_right_before_the_rename(self) -> None:
        # Every F5 job onto a free name runs in "fail" mode; a remote
        # destination paid a round trip per check. Through a temp file
        # nothing is replaced before the rename, so that check is enough.
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        job = self.job("a.txt", "fail")
        self.assertEqual(self._count_dest_exists(job), [job.dest_path])
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "a.txt").read_text(), "new")

    def test_happy_fail_mode_writing_directly_asks_once(self) -> None:
        # FTP, WebDAV, S3: the no-overwrite check and the rollback snapshot
        # asked exists() back to back - on FTP a missing file is four
        # commands and a listing, and the server slows down every refusal.
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        job = self.job("a.txt", "fail", use_temp=False)
        self.assertEqual(self._count_dest_exists(job), [job.dest_path])
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "a.txt").read_text(), "new")

    def test_sad_a_failed_direct_write_in_fail_mode_leaves_no_partial(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new" * 1000)
        job = self.job("a.txt", "fail", use_temp=False)

        class Broken:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n=-1):
                raise OSError("source vanished")

        with mock.patch.object(self.fs, "open_read", lambda path: Broken()):
            self.run_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertFalse((self.dst / "a.txt").exists())

    def test_edge_overwrite_and_present_newer_destinations_still_snapshot(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        job = self.job("a.txt", "overwrite", use_temp=False)
        self.assertEqual(len(self._count_dest_exists(job)), 1)  # the snapshot's
        (self.dst / "b.txt").write_text("old")
        _age(self.dst / "b.txt", 3600)
        (self.src / "b.txt").write_text("new")
        job = self.job("b.txt", "newer", use_temp=False)
        # Present: the check's answer is not reused, the snapshot asks.
        self.assertEqual(len(self._count_dest_exists(job)), 2)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "b.txt").read_text(), "new")

    def test_edge_a_fail_mode_resume_still_checks_before_touching_its_partial(self) -> None:
        from core.transfer_worker import TransferStatus, partial_name

        (self.src / "a.txt").write_text("new content")
        (self.dst / "a.txt").write_text("appeared later")
        job = self.job("a.txt", "fail")
        partial = self.dst / partial_name("a.txt", job.job_id, "")
        partial.write_text("new")
        job.resume, job.temp_path = True, str(partial)
        self.run_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(partial.read_text(), "new")  # untouched
        self.assertEqual((self.dst / "a.txt").read_text(), "appeared later")

    def test_edge_fail_mode_writing_directly_still_checks_before_the_first_write(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        (self.dst / "a.txt").write_text("appeared later")
        job = self.job("a.txt", "fail", use_temp=False)
        with mock.patch.object(self.fs, "open_write", side_effect=AssertionError("wrote")):
            self.run_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("already exists", job.error_message)
        self.assertEqual((self.dst / "a.txt").read_text(), "appeared later")

    def test_edge_newer_mode_still_decides_before_reading_the_source(self) -> None:
        (self.src / "a.txt").write_text("new")
        (self.dst / "a.txt").write_text("newer at the destination")
        _age(self.src / "a.txt", 3600)
        job = self.job("a.txt", "newer")
        with mock.patch.object(self.fs, "open_read", side_effect=AssertionError("read")):
            self.run_job(job)
        self.assertTrue(job.skipped)
        self.assertEqual((self.dst / "a.txt").read_text(), "newer at the destination")

    def test_edge_newer_mode_keeps_a_newer_destination_and_the_moved_source(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        (self.dst / "a.txt").write_text("newer at the destination")
        _age(self.src / "a.txt", 3600)
        job = self.job("a.txt", "newer", move=True)
        self.run_job(job)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertTrue(job.skipped)
        self.assertEqual((self.dst / "a.txt").read_text(), "newer at the destination")
        self.assertTrue((self.src / "a.txt").exists(), "a skipped move deleted its source")
        self.assertEqual(sorted(p.name for p in self.dst.iterdir()), ["a.txt"])

    def test_happy_newer_mode_replaces_an_older_destination(self) -> None:
        from core.transfer_worker import TransferStatus

        (self.src / "a.txt").write_text("new")
        (self.dst / "a.txt").write_text("old")
        _age(self.dst / "a.txt", 3600)
        job = self.job("a.txt", "newer", move=True)
        self.run_job(job)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertFalse(job.skipped)
        self.assertEqual((self.dst / "a.txt").read_text(), "new")
        self.assertFalse((self.src / "a.txt").exists())

    def test_edge_retry_keeps_the_no_overwrite_mode(self) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            self.skipTest("PyQt6 not installed")
        QApplication.instance() or QApplication([])
        from core.transfer_manager import TransferManager
        from core.transfer_worker import TransferStatus

        mgr = TransferManager()
        try:
            with mock.patch.object(mgr._worker, "enqueue"):
                (self.src / "a.txt").write_text("new")
                old = self.job("a.txt", "fail")
                old.status = TransferStatus.ERROR
                mgr._jobs[old.job_id] = old
                new = mgr.retry_job(old.job_id)
            self.assertEqual(new.if_exists, "fail")
        finally:
            mgr._worker.stop()
            mgr._thread.quit()
            mgr._thread.wait(2000)


if __name__ == "__main__":
    unittest.main()
