"""Find Files shows a name with a control or bidi character as the file
pane does.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro: a file
``inv\\u202efdp.exe`` found by Find Files): the file pane shows a name's
controls and bidi overrides as U+FFFD (``core.remote_name.
sanitize_for_display``) - "invoice\\u202efdp.exe" would read as
"invoiceexe.pdf" - but the result list of Find Files (name, folder,
the content snippet and their tooltips) showed the name raw: the override
reversed the rest of the cell, a line break split it. (Find in Index and
the Duplicate Finder never get such a name: both indexes refuse it.) The
list shows the defused form now; opening, revealing and copying a hit
still use the real path.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"
SPOOF = f"inv{RLO}fdp.exe"
SHOWN = "inv\ufffdfdp.exe"


def _wait(cond, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _clean(text: str) -> bool:
    return RLO not in text and "\n" not in text and "\x1b" not in text


@pytest.fixture
def found(tmp_path):
    from ui.find_files_dialog import FindFilesDialog, ScopeChoice

    folder = tmp_path / f"dir{RLO}x"
    folder.mkdir()
    (folder / SPOOF).write_text(f"needle {RLO}evil\x1b[31m tail")
    (folder / "line\nbreak.txt").write_text("needle")
    (folder / "plain.txt").write_text("needle")
    dlg = FindFilesDialog([ScopeChoice(LocalFS(), str(folder))])
    dlg.contains_edit.setText("needle")
    dlg.start_search()
    assert _wait(lambda: not dlg.is_running)
    yield dlg, folder
    dlg.reject()
    dlg.deleteLater()


# -- happy ---------------------------------------------------------------------


def test_happy_a_plain_name_is_shown_as_it_is(found):
    dlg, _folder = found
    names = [dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())]
    assert "plain.txt" in names


def test_happy_find_files_opens_the_real_path(found):
    dlg, folder = found
    row = next(r for r in range(dlg.table.rowCount()) if dlg.table.item(r, 0).text() == SHOWN)
    seen = []
    dlg.reveal_requested.connect(lambda _b, path: seen.append(path))
    dlg.table.setCurrentCell(row, 0)
    dlg._activate_current()
    assert seen == [str(folder / SPOOF)]


# -- sad -----------------------------------------------------------------------


def test_sad_find_files_cells_and_tooltips_are_defused(found):
    dlg, _folder = found
    table = dlg.table
    assert table.rowCount() == 3
    names = {table.item(r, 0).text() for r in range(table.rowCount())}
    assert SHOWN in names
    for r in range(table.rowCount()):
        for c in range(table.columnCount()):
            item = table.item(r, c)
            assert _clean(item.text()), (r, c, item.text())
            assert _clean(item.toolTip()), (r, c, item.toolTip())


# -- edge ----------------------------------------------------------------------


def test_edge_copy_path_copies_the_real_name(found):
    dlg, folder = found
    row = next(r for r in range(dlg.table.rowCount()) if dlg.table.item(r, 0).text() == SHOWN)
    dlg.table.selectRow(row)
    dlg._copy_paths(dlg._selected_entries())
    assert QApplication.clipboard().text() == str(folder / SPOOF)
