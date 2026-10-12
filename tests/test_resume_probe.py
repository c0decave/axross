"""Auto-resume must only adopt a genuine partial regular file."""
from __future__ import annotations

import os
import tempfile
import unittest

from core.local_fs import LocalFS
from core.transfer_manager import _probe_resumable_temp


class ResumeProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.dest = os.path.join(self.dir, "report.pdf")
        self.backend = LocalFS()

    def test_regular_partial_is_adopted(self) -> None:
        partial = os.path.join(self.dir, ".report.pdf.part-abc")
        with open(partial, "wb") as fh:
            fh.write(b"12345")
        self.assertEqual(_probe_resumable_temp(self.backend, self.dest), (partial, 5))

    def test_symlink_partial_is_ignored(self) -> None:
        victim = os.path.join(self.dir, "bashrc")
        with open(victim, "wb") as fh:
            fh.write(b"safe")
        os.symlink(victim, os.path.join(self.dir, ".report.pdf.part-evil"))
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))

    def test_directory_partial_is_ignored(self) -> None:
        os.mkdir(os.path.join(self.dir, ".report.pdf.part-dir"))
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))

    def test_empty_partial_is_ignored(self) -> None:
        open(os.path.join(self.dir, ".report.pdf.part-empty"), "wb").close()
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))

    def test_no_partial(self) -> None:
        self.assertIsNone(_probe_resumable_temp(self.backend, self.dest))


if __name__ == "__main__":
    unittest.main()
