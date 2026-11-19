"""After a folder cannot be opened, the path bar names the folder shown.

Found in review (round 2 of the 2026-11 reviews, UI shell): a path
typed into the path bar that does not exist stayed in the bar after the
error - right, to correct it - but also after the user went back to the
list, and through later failures: opening a folder without permission
from the list left the bar on the typed, missing path while the pane
listed another folder.

Now the bar keeps a typed path while it has the focus; otherwise a
failure puts the current folder back.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return done()


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "sub").mkdir()
    widget = FilePaneWidget(LocalFS())
    widget.resize(700, 400)
    widget.show()
    widget.activateWindow()
    widget.navigate(str(tmp_path))
    APP.processEvents()
    yield widget
    widget.close()
    widget.deleteLater()
    APP.processEvents()


def _type(pane, text: str) -> None:
    pane._path_edit.setFocus()
    _wait(pane._path_edit.hasFocus, 2)
    pane._path_edit.setText(text)
    QTest.keyClick(pane._path_edit, Qt.Key.Key_Return)
    _wait(lambda: False, 0.05)
    _wait(lambda: not pane.is_loading)


def test_happy_a_good_path_is_shown(pane, tmp_path):
    _type(pane, str(tmp_path / "sub"))
    assert _wait(lambda: pane.current_path == str(tmp_path / "sub"))
    assert pane._path_edit.text() == str(tmp_path / "sub")


def test_sad_a_typed_missing_path_stays_to_be_corrected(pane, tmp_path):
    _type(pane, str(tmp_path / "nope"))
    assert pane.current_path == str(tmp_path)
    assert pane._path_edit.text() == str(tmp_path / "nope")


def test_sad_a_later_failure_from_the_list_puts_the_folder_back(pane, tmp_path):
    _type(pane, str(tmp_path / "nope"))
    pane._table.setFocus()
    _wait(pane._table.hasFocus, 2)
    pane._status.setText("")
    pane.navigate_async(str(tmp_path / "gone"))
    assert _wait(lambda: "Error" in pane._status.text() and not pane.is_loading)
    assert pane.current_path == str(tmp_path)
    assert pane._path_edit.text() == str(tmp_path)


def test_edge_the_waiting_navigate_puts_the_folder_back_too(pane, tmp_path):
    pane._path_edit.setText(str(tmp_path / "typed"))
    pane._table.setFocus()
    _wait(pane._table.hasFocus, 2)
    pane.navigate(str(tmp_path / "gone"))
    assert pane._path_edit.text() == str(tmp_path)
