"""The archive pane shows member names with bidi overrides and controls
replaced, as the file table does (review 2 of 0.15.176).

Before: ``_make_row`` put the member name into the Name column verbatim,
so ``invoice\\u202efdp.exe`` (an executable) read as ``invoiceexe.pdf``.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.archive import ArchiveEntry  # noqa: E402
from ui.archive_pane import build_archive_tree  # noqa: E402

_app = QApplication.instance() or QApplication([])


def _entry(name: str, is_dir: bool = False) -> ArchiveEntry:
    return ArchiveEntry(name=name, size=1, compressed=1, mtime=None, is_dir=is_dir)


def test_sad_bidi_override_in_a_member_name_is_not_shown():
    name = "invoice\u202efdp.exe"
    model = build_archive_tree([_entry(name)])
    item = model.item(0, 0)
    assert "\u202e" not in item.text() and item.text() == "invoice\ufffdfdp.exe"
    # The member itself is still addressed by its real name.
    assert item.data(Qt.ItemDataRole.UserRole) == name


def test_sad_controls_in_a_folder_name_are_not_shown():
    model = build_archive_tree([_entry("ev\x1b[2Jil\u2066/a.txt")])
    folder = model.item(0, 0)
    assert "\x1b" not in folder.text() and "\u2066" not in folder.text()
    assert folder.data(Qt.ItemDataRole.UserRole) == "ev\x1b[2Jil\u2066/"
