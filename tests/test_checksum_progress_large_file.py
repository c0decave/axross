"""Show Checksum on a file over 2 GiB from a backend without a native
checksum.

Found in review (round 3, files): the stream-hash fallback built its
QProgressDialog with ``maximum=total_size``. Qt's range is a C int, so a
3 GiB file raised OverflowError straight into the global error dialog
before a byte was read. Since 0.14.158 the hash runs on the pane's
ScanJob and says how far it is in the status line - no Qt range at all.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

GIB = 1024**3


class _NoNativeChecksumFS(LocalFS):
    """Answers "" for checksum (SMB, FTP ...) and serves *data* for any
    read, so a "3 GiB" file needs no 3 GiB on disk."""

    data = b"hello world\n" * 100

    def checksum(self, path, algorithm="sha256"):
        return ""

    def open_read(self, path):
        return io.BytesIO(self.data)


class ChecksumLargeFileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        self.pane = FilePaneWidget(_NoNativeChecksumFS())
        self.addCleanup(self.pane.deleteLater)
        self.pane.navigate(str(self.root))

    def _drain(self) -> None:
        from tests.off_gui_wait import _drain_checksum

        self.assertTrue(_drain_checksum(self.pane))

    def test_happy_stream_hash_of_a_3_gib_file_does_not_overflow(self) -> None:
        from ui import file_pane as FP

        seen: list = []
        digest = FP._stream_sha256(self.pane._backend, str(self.root / "video.mkv"), 3 * GIB,
                                   lambda: False, lambda *a: seen.append(a))
        self.assertEqual(digest, hashlib.sha256(_NoNativeChecksumFS.data).hexdigest())
        self.assertEqual(seen[-1][1], 3 * GIB)
        self.pane._checksum_target = (FileItem(name="video.mkv", size=3 * GIB), "x")
        self.pane._checksum_phase = "stream"
        text = self.pane._checksum_progress_text({"scanned": 2 * GIB + 7, "indexed": 3 * GIB})
        self.assertIn("2.0 GB of 3.0 GB", text)

    def test_happy_show_checksum_reaches_the_result_dialog(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        item = FileItem(name="video.mkv", size=3 * GIB)
        shown: list = []
        with mock.patch(
            "ui.file_pane.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes
        ), mock.patch("ui.viewer_window.show_independent", lambda dlg: shown.append(dlg)):
            self.pane._show_checksum(item)
            self._drain()
        self.assertEqual(len(shown), 1)

    def test_sad_read_error_is_still_reported(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        def broken(path):
            raise OSError("connection lost")

        self.pane._backend.open_read = broken
        item = FileItem(name="video.mkv", size=3 * GIB)
        with mock.patch(
            "ui.file_pane.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes
        ), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            self.pane._show_checksum(item)
            self._drain()
        warning.assert_called_once()
        self.assertIn("connection lost", warning.call_args.args[2])

    def test_edge_the_status_line_without_a_size_counts_up(self) -> None:
        self.pane._checksum_target = (FileItem(name="pipe", size=0), "x")
        self.pane._checksum_phase = "stream"
        self.assertEqual(self.pane._checksum_progress_text({"scanned": 1024, "indexed": 0}),
                         "Hashing pipe… 1.0 KB")
