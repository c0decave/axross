"""Enqueueing a folder copy: no stat per file, one destination listing per
folder — and exactly the same jobs as before.

Measured before (1 000 files): ``transfer_file`` stat'ed every source file
although the folder listing already carried its size, and the auto-resume
probe listed the whole destination folder once per file (1 001 listings;
with 1 000 files already there, a million entries) — on the GUI thread.
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


def _fields(job) -> tuple:
    return (
        job.source_path,
        job.dest_path,
        job.total_bytes,
        job.resume,
        job.temp_path,
        job.use_temp_file,
        job.move,
    )


class _Base(unittest.TestCase):
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
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        (self.src / "sub").mkdir(parents=True)
        self.dst.mkdir()
        for i in range(30):
            (self.src / f"f{i}.bin").write_bytes(b"x" * (i + 1))
        (self.src / "empty.bin").write_bytes(b"")
        for i in range(5):
            (self.src / "sub" / f"g{i}.bin").write_bytes(b"y" * 100)
        self.fs = LocalFS()
        self.mgr = TransferManager()
        self.addCleanup(self._stop)
        p = mock.patch.object(self.mgr._worker, "enqueue")  # no real transfers
        p.start()
        self.addCleanup(p.stop)

    def _stop(self) -> None:
        self.mgr._worker.stop()
        self.mgr._thread.quit()
        self.mgr._thread.wait(2000)

    def enqueue(self, paths=None, dest=None):
        paths = paths or [str(self.src)]
        return self.mgr.transfer_files(self.fs, self.fs, paths, str(dest or self.dst))

    def reference(self, paths=None, dest=None):
        """The jobs the per-file path produces (no size, no listing hint)."""
        jobs = []
        real = self.mgr.transfer_file

        def per_file(*a, **kw):
            kw.pop("size", None)
            kw.pop("dest_listing", None)
            job = real(*a, **kw)
            jobs.append(job)
            return job

        with mock.patch.object(self.mgr, "transfer_file", per_file):
            self.enqueue(paths, dest)
        return jobs


class EnqueueCostTest(_Base):
    def test_happy_no_source_stat_per_file(self) -> None:
        with mock.patch.object(LocalFS, "stat", wraps=self.fs.stat) as st:
            jobs = self.enqueue()
        self.assertEqual(len(jobs), 36)
        # only the empty file (size 0 in the listing) is stat'ed, as a fallback
        self.assertEqual(st.call_count, 1)

    def test_happy_one_destination_listing_per_folder(self) -> None:
        # dst/src and dst/src/sub are created fresh: nothing to list there.
        listed = []
        real = self.fs.list_dir
        with mock.patch.object(
            LocalFS, "list_dir", side_effect=lambda p: listed.append(p) or real(p)
        ):
            self.enqueue()
        dest_listings = [p for p in listed if p.startswith(str(self.dst))]
        self.assertEqual(dest_listings, [])

    def test_existing_destination_folder_is_listed_once(self) -> None:
        (self.dst / "src").mkdir()
        listed = []
        real = self.fs.list_dir
        with mock.patch.object(
            LocalFS, "list_dir", side_effect=lambda p: listed.append(p) or real(p)
        ):
            self.enqueue()
        self.assertEqual(listed.count(str(self.dst / "src")), 1)


class SameJobsTest(_Base):
    def _same(self, paths=None, dest=None) -> None:
        ref = [_fields(j) for j in self.reference(paths, dest)]
        new = [_fields(j) for j in self.enqueue(paths, dest)]
        self.assertEqual(new, ref)

    def test_happy_fresh_destination(self) -> None:
        self._same()

    def test_sad_partial_leftovers_are_still_resumed(self) -> None:
        target = self.dst / "src"
        target.mkdir()
        (target / ".f9.bin.part-abc123").write_bytes(b"x" * 4)  # partial of a 10-byte file
        (target / ".f3.bin.part-zzz").write_bytes(b"x" * 9)  # bigger than the 4-byte source
        self._same()
        jobs = {j.source_path.rsplit("/", 1)[-1]: j for j in self.enqueue()}
        self.assertTrue(jobs["f9.bin"].resume)
        self.assertTrue(jobs["f9.bin"].temp_path.endswith(".f9.bin.part-abc123"))
        self.assertFalse(jobs["f3.bin"].resume)

    def test_edge_single_files_at_the_top_level(self) -> None:
        (self.dst / ".f1.bin.part-q").write_bytes(b"x")
        self._same([str(self.src / "f1.bin"), str(self.src / "f2.bin")])

    def test_edge_a_symlinked_leftover_is_not_resumed(self) -> None:
        target = self.dst / "src"
        target.mkdir()
        (self.tmp / "elsewhere").write_bytes(b"x" * 3)
        (target / ".f9.bin.part-lnk").symlink_to(self.tmp / "elsewhere")
        self._same()


class GuiCopyPathTest(_Base):
    def test_the_copy_command_enqueues_without_a_preview_walk(self) -> None:
        from ui.main_window import MainWindow

        class _Pane:
            def __init__(self, backend, path) -> None:
                self.backend, self.current_path = backend, path

        fake = mock.MagicMock()
        fake._transfer_target_panes = set()
        fake._transfer_manager = self.mgr
        src, dst = _Pane(self.fs, str(self.src)), _Pane(self.fs, str(self.dst))
        with mock.patch("core.destructive_preview.preview_transfer") as preview:
            MainWindow._start_transfer_between(fake, src, dst, [str(self.src / "f1.bin")])
        preview.assert_not_called()
        self.assertEqual([j.dest_path for j in self.mgr.all_jobs()], [str(self.dst / "f1.bin")])
        self.assertIn(dst, fake._transfer_target_panes)


if __name__ == "__main__":
    unittest.main()
