"""New Group in a group 16 levels deep says why instead of making one that
the next start drops with all it holds (load() reads 16 levels of groups)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox  # noqa: E402

import core.bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_new_group_past_16_levels_is_told(tmp_path, monkeypatch):
    from ui import bookmark_sidebar as SB

    with mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        mgr = BM.BookmarkManager()
        parent = None
        for depth in range(16):
            parent = mgr.add_group(f"g{depth}", parent=parent)
        side = SB.BookmarkSidebar(mgr)

        class _Dialog:
            def __init__(self, *a, **k):
                pass

            def exec(self):
                return QDialog.DialogCode.Accepted

            def result(self):
                return ("deeper", "folder", "")

        told = []
        monkeypatch.setattr(SB, "GroupEditDialog", _Dialog)
        monkeypatch.setattr(QMessageBox, "information", lambda *a: told.append(a[2]))
        side._new_group(parent)
        assert len(told) == 1 and "16" in told[0]
        assert len(mgr.groups()) == 16
        side._new_group(mgr.parent_of(parent))  # 16th level: still fine
        assert len(mgr.groups()) == 17
        side.deleteLater()
