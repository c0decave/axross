"""Cancelling an archive extraction no longer touches the dialog from the
worker thread.

Found by the second audit: the extraction worker's progress callback
asked the QProgressDialog wasCanceled() - a widget read from a thread
other than the GUI thread, a data race Qt does not allow (both the
pane's Extract Archive and the archive view's Extract All / Selected /
To). The dialog's canceled signal now sets a threading.Event on the GUI
thread, and the worker reads only that.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox, QProgressDialog  # noqa: E402

from core import archive as ARCH  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_cancel_stops_the_worker_which_never_reads_the_dialog(tmp_path):
    from ui.file_pane import FilePaneWidget

    archive = tmp_path / "pack.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "a")
    readers: list[str] = []
    real = QProgressDialog.wasCanceled

    def watched(self):
        readers.append(threading.current_thread().name)
        return real(self)

    steps: list[int] = []

    def slow_extract(path, target, progress=None):
        for i in range(200):
            steps.append(i)
            progress(i, 200, f"m{i}")
            time.sleep(0.01)
        return 200

    def press_cancel():
        for dialog in APP.topLevelWidgets() + [w for w in APP.allWidgets()]:
            if isinstance(dialog, QProgressDialog):
                dialog.cancel()
                return

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    try:
        QTimer.singleShot(300, press_cancel)
        with mock.patch.object(QProgressDialog, "wasCanceled", watched), \
                mock.patch.object(ARCH, "extract", slow_extract), \
                mock.patch.object(QMessageBox, "information"), \
                mock.patch.object(QMessageBox, "warning"):
            pane._extract_archive(FileItem(name="pack.zip", size=archive.stat().st_size))
    finally:
        pane.shutdown()
        pane.deleteLater()
    assert 0 < len(steps) < 200  # it stopped on the cancel
    assert all(name == "MainThread" for name in readers)  # never read by the worker
