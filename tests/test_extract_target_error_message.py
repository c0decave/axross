"""Extract Archive's "Cannot pick a target folder" message is shown: a
local import of as_written further down the method made the name local,
and the message ended in UnboundLocalError inside a Qt slot."""
from __future__ import annotations

import os
import zipfile
from unittest import mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import archive as ARCH  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_no_target_folder_is_said(tmp_path):
    from ui.file_pane import FilePaneWidget

    with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
        zf.writestr("x", "y")
    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    warned = []
    try:
        with mock.patch.object(ARCH, "auto_suffix_dir", side_effect=OSError("full")), \
                mock.patch.object(QMessageBox, "warning", lambda *a: warned.append(a[2])):
            pane._extract_archive(FileItem(name="a.zip", size=1))
    finally:
        pane.shutdown()
        pane.deleteLater()
    assert warned and "Cannot pick a target folder" in warned[0] and "full" in warned[0]
