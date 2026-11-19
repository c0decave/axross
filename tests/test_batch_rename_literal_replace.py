"""Batch Rename's plain Find & Replace takes the replacement as written.

Review: with "Case sensitive" off, the plain-text mode ran re.sub with the
replacement as a regex template: "C:\\temp" made a TAB of "\\t", "\\1" or
"\\d" made the whole rename silently do nothing (re.error). Now the
replacement is literal in both cases, and a new name with a control
character (a TAB from a regex template, say) is refused before anything
is renamed - safe_leaf lets a TAB through, as a remote listing may hold
one.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _dialog(names, base="/nonexistent"):
    from ui.batch_rename_dialog import BatchRenameDialog

    items = [FileItem(name=n, size=1, is_dir=False, modified=datetime.now()) for n in names]
    return BatchRenameDialog(LocalFS(), base, items)


@pytest.mark.parametrize("case_sensitive", [True, False])
@pytest.mark.parametrize("replace", ["C:\\temp", "\\1", "\\d", "\\g<0>", "Q\\1-"])
def test_happy_the_plain_replacement_is_taken_as_written(case_sensitive, replace):
    dlg = _dialog(["Report_2025.txt", "report_2024.txt"])
    dlg._find_edit.setText("report")
    dlg._replace_edit.setText(replace)
    dlg._case_sensitive.setChecked(case_sensitive)
    names = dict(dlg._compute_new_names())
    assert names["report_2024.txt"] == replace + "_2024.txt"
    expected = "Report_2025.txt" if case_sensitive else replace + "_2025.txt"
    assert names["Report_2025.txt"] == expected


def test_hostile_a_new_name_with_a_control_character_is_refused(tmp_path):
    (tmp_path / "a_b.txt").write_text("x")
    dlg = _dialog(["a_b.txt"], str(tmp_path))
    dlg._mode.setCurrentIndex(1)  # regex: "\t" in the template is a TAB
    dlg._find_edit.setText("_")
    dlg._replace_edit.setText("\\t")
    assert dict(dlg._compute_new_names()) == {"a_b.txt": "a\tb.txt"}
    with mock.patch.object(QMessageBox, "warning") as warned:
        dlg._apply()
    warned.assert_called_once()
    assert os.listdir(tmp_path) == ["a_b.txt"]
