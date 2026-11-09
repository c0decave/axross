"""Auto-resume must only adopt a genuine partial regular file of axross's
own shape, and none another transfer may still be writing.

Measured before (review round 8): a user's ``.video.mp4.part-1-notes`` was
adopted as the partial of ``video.mp4`` (then removed by the worker or by
Clear Finished), and a second copy of a file adopted the first copy's live
partial: both appended to it, and the first job committed a 4.8 MB "copy"
of a 4 MB file.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest

from core import transfer_manager as TM
from core import transfer_worker as TW
from core.local_fs import LocalFS
from core.transfer_manager import _probe_resumable_temp

FP = "deadbeef"


def _age(path: str, seconds: float = 3600) -> None:
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp), follow_symlinks=False)


class ResumeProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.dest = os.path.join(self.dir, "report.pdf")
        self.backend = LocalFS()

    def _partial(self, name: str, data: bytes = b"12345", *, age: float = 3600) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        _age(path, age)
        return path

    def test_happy_an_idle_partial_of_this_source_is_adopted(self) -> None:
        partial = self._partial(TW.partial_name("report.pdf", "0123abcd", FP))
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP),
                         (partial, 5))

    def test_happy_the_partial_of_this_version_is_preferred(self) -> None:
        self._partial(TW.partial_name("report.pdf", "00000000", "0badf00d"))
        good = self._partial(TW.partial_name("report.pdf", "11111111", FP), b"123")
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP),
                         (good, 3))

    def test_edge_an_older_versions_partial_is_handed_over_for_removal(self) -> None:
        # The worker sees the other fingerprint and discards it.
        old = self._partial(TW.partial_name("report.pdf", "00000000", "0badf00d"))
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP),
                         (old, 5))

    def test_sad_a_users_file_named_like_a_partial_is_left_alone(self) -> None:
        for name in (".report.pdf.part-1-notes", ".report.pdf.part-abc",
                     ".report.pdf.part-0123abcd", ".report.pdf.part-0123ABCD-DEADBEEF",
                     ".report.pdf.part-0123abcd-deadbeef.txt"):
            self._partial(name)
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))

    def test_sad_a_partial_written_to_lately_is_not_adopted(self) -> None:
        self._partial(TW.partial_name("report.pdf", "0123abcd", FP), age=2)
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))

    def test_sad_a_partial_another_job_writes_is_not_adopted(self) -> None:
        partial = self._partial(TW.partial_name("report.pdf", "0123abcd", FP))
        # Queued in this manager ...
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP,
                                                busy={partial}))
        # ... or written by a worker of this process.
        self.assertTrue(TW._claim_live_partial(partial))
        try:
            self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))
        finally:
            TW._release_live_partials([partial])
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP),
                         (partial, 5))

    def test_edge_the_idle_time_is_the_listings(self) -> None:
        partial = self._partial(TW.partial_name("report.pdf", "0123abcd", FP),
                                age=TM.RESUME_IDLE_SECONDS + 5)
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP),
                         (partial, 5))
        _age(partial, -60)  # a clock ahead: counts as written just now
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))

    def test_symlink_partial_is_ignored(self) -> None:
        victim = os.path.join(self.dir, "bashrc")
        with open(victim, "wb") as fh:
            fh.write(b"safe")
        link = os.path.join(self.dir, TW.partial_name("report.pdf", "0123abcd", FP))
        os.symlink(victim, link)
        _age(link)
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))

    def test_directory_partial_is_ignored(self) -> None:
        folder = os.path.join(self.dir, TW.partial_name("report.pdf", "0123abcd", FP))
        os.mkdir(folder)
        _age(folder)
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))

    def test_empty_partial_is_ignored(self) -> None:
        self._partial(TW.partial_name("report.pdf", "0123abcd", FP), b"")
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest, fingerprint=FP))

    def test_no_partial(self) -> None:
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))

    def test_edge_partial_names_of_the_exact_shape(self) -> None:
        self.assertTrue(TW.is_partial_name(".a.b.part-0123abcd-deadbeef", "a.b"))
        self.assertTrue(TW.is_partial_name(".a.b.part-0123abcd-deadbeef"))
        self.assertFalse(TW.is_partial_name(".a.b.part-0123abcd-deadbeef", "other"))
        self.assertFalse(TW.is_partial_name(".video.mp4.part-1-notes"))
        self.assertFalse(TW.is_partial_name("a.part-0123abcd-deadbeef"))
        self.assertFalse(TW.is_partial_name("..part-0123abcd-deadbeef"))
        long_name = "n" * 250 + ".bin"
        self.assertTrue(TW.is_partial_name(TW.partial_name(long_name, "0123abcd", FP),
                                           long_name))


if __name__ == "__main__":
    unittest.main()
