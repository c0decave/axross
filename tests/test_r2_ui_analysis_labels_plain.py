"""The Disk Image and folder File Type windows show a path as text.

Found in review (round 2 of the 2026-11 reviews, UI shell): their first
line ("Reading {name}…", "Listing {folder}…") was a QLabel guessing the
text format - a folder named ``<img width=4000 height=4000 src=x>``
was drawn as a 4,000 px image and pushed the window off the screen.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
WIDE = "<img width=4000 height=4000 src=x>"


@pytest.fixture
def wide_folder(tmp_path):
    folder = tmp_path / WIDE
    folder.mkdir()
    (folder / "a.txt").write_text("x")
    return folder


def test_happy_and_sad_the_folder_file_type_window(wide_folder):
    from ui.file_type_dialog import FolderFileTypeDialog

    dlg = FolderFileTypeDialog(LocalFS(), str(wide_folder))
    label = dlg.status_label
    assert label.textFormat() == Qt.TextFormat.PlainText
    assert label.sizeHint().width() < 2000
    dlg.close()
    dlg.deleteLater()


def test_edge_the_disk_image_window(wide_folder):
    from ui.disk_image_dialog import DiskImageDialog

    dlg = DiskImageDialog(LocalFS(), str(wide_folder / "disk.img"))
    assert dlg.summary.textFormat() == Qt.TextFormat.PlainText
    assert dlg.summary.sizeHint().width() < 2000
    dlg.close()
    dlg.deleteLater()
