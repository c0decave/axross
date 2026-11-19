"""Going up selects the folder just left.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro:
Backspace in a file list): the parent folder opened with no row selected
and none current, so the next Return opened nothing and Down started at
the top - in a long folder the user had to look for the folder they came
from. As in Total Commander, Backspace, the Up button and ".." now land
on it, selected as a click selects it; a hidden one stays hidden.
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(cond, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def pane(tmp_path):
    for i in range(40):
        (tmp_path / f"folder{i:02d}").mkdir()
    (tmp_path / ".secret").mkdir()
    widget = FilePaneWidget(LocalFS())
    widget.resize(800, 300)
    widget.show()
    widget.navigate(str(tmp_path / "folder33"))
    assert _wait(lambda: widget.current_path == str(tmp_path / "folder33"))
    widget._table.setFocus()
    yield widget, tmp_path
    widget.close()
    widget.deleteLater()


def _current(widget) -> str | None:
    return widget._table.currentIndex().data()


def _up_and_wait(widget, parent: Path, press) -> None:
    press()
    assert _wait(lambda: widget.current_path == str(parent) and not widget.is_loading)
    _wait(lambda: _current(widget) is not None, 1.0)


# -- happy ---------------------------------------------------------------------


def test_happy_backspace_lands_on_the_folder_left(pane):
    widget, parent = pane
    _up_and_wait(widget, parent, lambda: QTest.keyClick(widget._table, Qt.Key.Key_Backspace))
    assert _current(widget) == "folder33"
    assert widget.selected_items() == [str(parent / "folder33")]
    assert widget._table.viewport().rect().intersects(
        widget._table.visualRect(widget._table.currentIndex()))  # scrolled into view
    # ... so Return goes back into it.
    QTest.keyClick(widget._table, Qt.Key.Key_Return)
    assert _wait(lambda: widget.current_path == str(parent / "folder33"))


def test_happy_the_up_button_and_dotdot_land_on_it_too(pane):
    widget, parent = pane
    _up_and_wait(widget, parent, widget._btn_up.click)
    assert _current(widget) == "folder33"
    widget.navigate(str(parent / "folder05"))
    assert _wait(lambda: widget.current_path == str(parent / "folder05"))
    dotdot = next(i for i in range(widget._proxy.rowCount())
                  if widget._proxy.index(i, 0).data() == "..")
    widget._table.setCurrentIndex(widget._proxy.index(dotdot, 0))
    _up_and_wait(widget, parent, lambda: QTest.keyClick(widget._table, Qt.Key.Key_Return))
    assert _current(widget) == "folder05"


# -- sad -----------------------------------------------------------------------


def test_sad_a_hidden_folder_left_stays_hidden(pane):
    widget, parent = pane
    widget.navigate(str(parent / ".secret"))
    assert _wait(lambda: widget.current_path == str(parent / ".secret"))
    widget.set_show_hidden(False)
    _up_and_wait(widget, parent, lambda: QTest.keyClick(widget._table, Qt.Key.Key_Backspace))
    shown = [widget._proxy.index(i, 0).data() for i in range(widget._proxy.rowCount())]
    assert ".secret" not in shown
    assert _current(widget) != ".secret"


# -- edge ----------------------------------------------------------------------


def test_edge_the_root_has_no_parent_and_nothing_changes(tmp_path):
    widget = FilePaneWidget(LocalFS())
    try:
        widget.show()
        widget.navigate("/")
        assert _wait(lambda: widget.current_path == "/")
        widget._go_up()
        APP.processEvents()
        assert widget.current_path == "/"
    finally:
        widget.close()
        widget.deleteLater()
