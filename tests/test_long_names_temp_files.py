"""A file whose name is near the 255-byte limit can be copied and renamed.

Measured before: a 245-byte name (legal, NAME_MAX is 255) failed F5/F6
with "File name too long": the transfer's temp file
``.<name>.part-<job id>`` added 15 bytes, the stream copy's
``.<name>.copy-<32 hex>.tmp`` 44, the batch rename's
``.<name>.rename-<12 hex>`` 21. Every temp name now fits; a cut name ends
in a digest of the whole name so two long names stay apart.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.path_policy import MAX_FS_NAME_BYTES, hidden_sibling_name  # noqa: E402


def _blen(name: str) -> int:
    return len(name.encode("utf-8"))


LONG = ("Meeting notes - quarterly planning " * 8)[:251] + ".txt"  # 255 bytes


class HelperTest(unittest.TestCase):
    def test_happy_a_short_name_is_unchanged(self) -> None:
        self.assertEqual(hidden_sibling_name("a.txt", ".copy-x.tmp"), ".a.txt.copy-x.tmp")

    def test_edge_a_255_byte_name_gives_a_fitting_name(self) -> None:
        self.assertEqual(_blen(LONG), 255)
        for suffix, reserve in ((".copy-" + "f" * 32 + ".tmp", 0), (TW.PARTIAL_MARK, 17)):
            name = hidden_sibling_name(LONG, suffix, reserve=reserve)
            self.assertLessEqual(_blen(name) + reserve, MAX_FS_NAME_BYTES)
            self.assertTrue(name.startswith(".Meeting notes"))
            self.assertTrue(name.endswith(suffix))

    def test_edge_multibyte_characters_are_never_split(self) -> None:
        name = "ü" * 127  # 254 bytes
        cut = hidden_sibling_name(name, ".rename-0123456789ab")
        cut.encode("utf-8")  # no lone surrogate / broken character
        self.assertLessEqual(_blen(cut), MAX_FS_NAME_BYTES)

    def test_sad_two_long_names_with_one_beginning_stay_apart(self) -> None:
        a = hidden_sibling_name(LONG[:-5] + "A.txt", ".part-")
        b = hidden_sibling_name(LONG[:-5] + "B.txt", ".part-")
        self.assertNotEqual(a, b)

    def test_edge_partial_names_of_a_long_name_carry_the_fingerprint(self) -> None:
        name = TW.partial_name(LONG, "0123abcd", "deadbeef")
        self.assertLessEqual(_blen(name), MAX_FS_NAME_BYTES)
        self.assertEqual(TW.partial_fingerprint(name, LONG), "deadbeef")


class CopyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "src").mkdir()
        (self.tmp / "dst").mkdir()
        self.src = self.tmp / "src" / LONG
        self.src.write_bytes(b"hello")

    def test_happy_the_transfer_worker_moves_a_255_byte_name(self) -> None:
        job = TW.TransferJob(source_path=str(self.src), dest_path=str(self.tmp / "dst" / LONG),
                             total_bytes=5, filename=LONG, move=True,
                             source_backend=LocalFS(), dest_backend=LocalFS())
        TW.TransferWorker()._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(os.listdir(self.tmp / "dst"), [LONG])
        self.assertFalse(self.src.exists())

    def test_happy_the_stream_copy_copies_a_255_byte_name(self) -> None:
        from core.server_ops import stream_copy_between_backends

        stream_copy_between_backends(LocalFS(), str(self.src), LocalFS(),
                                     str(self.tmp / "dst" / LONG))
        self.assertEqual((self.tmp / "dst" / LONG).read_bytes(), b"hello")
        self.assertEqual(os.listdir(self.tmp / "dst"), [LONG])

    def test_edge_the_stream_copy_replaces_an_existing_255_byte_name(self) -> None:
        from core.server_ops import stream_copy_between_backends

        (self.tmp / "dst" / LONG).write_bytes(b"old")
        stream_copy_between_backends(LocalFS(), str(self.src), LocalFS(),
                                     str(self.tmp / "dst" / LONG))
        self.assertEqual((self.tmp / "dst" / LONG).read_bytes(), b"hello")
        self.assertEqual(os.listdir(self.tmp / "dst"), [LONG])


class BatchRenameTempTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_edge_the_staging_name_of_a_long_name_fits(self) -> None:
        from models.file_item import FileItem
        from ui.batch_rename_dialog import BatchRenameDialog

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / LONG).write_bytes(b"x")
        dlg = BatchRenameDialog(LocalFS(), str(tmp), [FileItem(name=LONG, size=1)])
        self.addCleanup(dlg.deleteLater)
        temp = dlg._unique_temp_path(LONG)
        self.assertLessEqual(_blen(os.path.basename(temp)), MAX_FS_NAME_BYTES)
        os.rename(tmp / LONG, temp)  # the filesystem accepts it
        self.assertTrue(os.path.exists(temp))


if __name__ == "__main__":
    unittest.main()
