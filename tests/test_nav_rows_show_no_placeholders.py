"""The pane's "." and ".." rows show no made-up time, permissions or owner.

Both rows are made by the pane without a stat (ui/file_pane.py), so their
FileItem carries defaults: the table showed "1970-01-01 00:00" and
"d---------" in every pane - what the axross intro video's footage showed
on every listing. Those cells are empty now; real entries are unchanged.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from models.file_table_model import (  # noqa: E402
    COL_MODIFIED,
    COL_NAME,
    COL_OWNER,
    COL_PERMS,
    FileTableModel,
)

APP = QApplication.instance() or QApplication([])


def test_happy_nav_rows_have_only_their_name():
    model = FileTableModel()
    for name in (".", ".."):
        item = FileItem(name=name, is_dir=True)
        assert model.display_text(item, COL_NAME) == name
        for col in (COL_MODIFIED, COL_PERMS, COL_OWNER):
            assert model.display_text(item, col) == ""


def test_edge_a_real_folder_keeps_its_cells():
    model = FileTableModel()
    item = FileItem(name="docs", is_dir=True, modified=datetime(2026, 11, 3, 14, 39),
                    permissions=0o755, owner="demo", group="demo")
    assert model.display_text(item, COL_MODIFIED) == "2026-11-03 14:39"
    assert model.display_text(item, COL_PERMS).startswith("d")
    assert model.display_text(item, COL_OWNER) == "demo:demo"


def test_sad_a_folder_named_like_a_nav_row_with_dots_inside_is_not_one():
    model = FileTableModel()
    item = FileItem(name="...", is_dir=True, modified=datetime(2026, 1, 1))
    assert model.display_text(item, COL_MODIFIED) == "2026-01-01 00:00"
