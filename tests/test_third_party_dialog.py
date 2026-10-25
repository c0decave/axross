"""Help > Third-Party Software…: the projects axross uses and ships, from
resources/credits/third_party.json, with a thank-you, a filter and links
that open in the browser only when one is clicked.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QDesktopServices  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QToolButton  # noqa: E402

from core import third_party as T  # noqa: E402
from ui import third_party_dialog as D  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def opened(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(QDesktopServices, "openUrl",
                        staticmethod(lambda url: calls.append(url.toString()) or True))
    return calls


@pytest.fixture
def dialog(opened):
    dlg = D.ThirdPartyDialog()
    dlg.show()
    pump()
    yield dlg
    dlg.close()
    dlg.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _row_of(dlg, name: str) -> int:
    view = dlg.table
    for row in range(view.model().rowCount()):
        if view.model().index(row, D.COL_NAME).data() == name:
            return row
    raise AssertionError(f"{name} not shown")


def _click(dlg, row: int, column: int) -> None:
    view = dlg.table
    index = view.model().index(row, column)
    view.scrollTo(index)
    pump()
    rect = view.visualRect(index)
    QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    pump()


# --- happy -----------------------------------------------------------------


def test_happy_e2e_from_the_help_menu_filter_and_click_a_link(opened):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    try:
        help_menu = next(a.menu() for a in win.menuBar().actions() if a.text() == "&Help")
        action = next(a for a in help_menu.actions() if a.text() == "&Third-Party Software…")
        action.trigger()
        pump()
        dlg = win._third_party_dialog
        assert dlg is not None and dlg.isVisible()
        assert dlg.table.model().rowCount() == len(T.load())
        assert "Thank you" in dlg.thanks.text()
        assert opened == []  # opening shows, it does not browse

        QTest.keyClicks(dlg.filter_edit, "ripgrep")
        pump()
        assert dlg.table.model().rowCount() == 1
        assert opened == []  # typing does not browse either

        _click(dlg, 0, D.COL_NAME)
        assert opened == []  # a click outside the link column selects only
        _click(dlg, 0, D.COL_LINK)
        assert opened == ["https://github.com/BurntSushi/ripgrep"]

        action.trigger()  # a second Help click raises the same window
        pump()
        assert win._third_party_dialog is dlg
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        pump()


def test_happy_every_entry_is_shown_with_licence_and_shipping(dialog):
    row = _row_of(dialog, "PyQt6")
    model = dialog.table.model()
    assert model.index(row, D.COL_LICENSE).data().startswith("GPL-3.0-only")
    assert "axross-slim" in model.index(row, D.COL_SHIPS).data()
    assert model.index(row, D.COL_LINK).data() == \
        "https://www.riverbankcomputing.com/software/pyqt/"
    assert dialog.count_label.text() == f"{len(T.load())} of {len(T.load())}"


def test_happy_the_open_link_button_opens_the_selected_row(dialog, opened):
    assert not dialog.open_button.isEnabled()
    _click(dialog, _row_of(dialog, "paramiko"), D.COL_NAME)
    assert dialog.open_button.isEnabled() and opened == []
    QTest.mouseClick(dialog.open_button, Qt.MouseButton.LeftButton)
    assert opened == ["https://github.com/paramiko/paramiko"]


def test_happy_the_dialog_has_the_close_corner(dialog):
    assert dialog.findChildren(QToolButton, "axCloseCorner")


# --- sad -------------------------------------------------------------------


def test_sad_a_broken_data_file_shows_an_error_instead_of_a_table(tmp_path, opened):
    bad = tmp_path / "third_party.json"
    bad.write_text(json.dumps({"schema": 1, "entries": [{"id": "x"}]}), encoding="utf-8")
    dlg = D.ThirdPartyDialog(data_file=bad)
    try:
        assert dlg.table.model().rowCount() == 0
        assert "could not be read" in dlg.error_label.text()
        assert not dlg.error_label.isHidden()
        assert not dlg.filter_edit.isEnabled()
    finally:
        dlg.deleteLater()


def test_sad_keyboard_selection_and_enter_do_not_open_a_link(dialog, opened):
    view = dialog.table
    view.setFocus()
    view.setCurrentIndex(view.model().index(0, D.COL_LINK))
    QTest.keyClick(view, Qt.Key.Key_Down)
    QTest.keyClick(view, Qt.Key.Key_Return)
    pump()
    assert opened == []


# --- edge ------------------------------------------------------------------


def test_edge_a_filter_without_match_shows_none_and_clearing_restores(dialog):
    total = len(T.load())
    QTest.keyClicks(dialog.filter_edit, "zz-no-such-project-zz")
    pump()
    assert dialog.table.model().rowCount() == 0
    assert dialog.count_label.text() == f"0 of {total}"
    assert not dialog.open_button.isEnabled()
    dialog.filter_edit.clear()
    pump()
    assert dialog.table.model().rowCount() == total


def test_edge_the_filter_also_finds_licences_and_purposes(dialog):
    QTest.keyClicks(dialog.filter_edit, "Find Files")
    pump()
    names = {dialog.table.model().index(r, D.COL_NAME).data()
             for r in range(dialog.table.model().rowCount())}
    assert {"ripgrep", "fd"} <= names


def test_edge_the_name_tooltip_carries_version_via_and_note(dialog):
    row = _row_of(dialog, "ripgrep")
    tip = dialog.table.model().index(row, D.COL_NAME).data(Qt.ItemDataRole.ToolTipRole)
    assert "15.2.0" in tip
    row = _row_of(dialog, "botocore")
    tip = dialog.table.model().index(row, D.COL_NAME).data(Qt.ItemDataRole.ToolTipRole)
    assert "boto3" in tip


def test_edge_the_licence_column_is_spelt_as_in_the_rest_of_the_ui(dialog):
    """The MCP catalog and the rest of axross write "Licence" (British
    spelling, like "Colour"); the credits table said "License"."""
    from PyQt6.QtCore import Qt

    model = dialog.table.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    assert "Licence" in headers and "License" not in headers
