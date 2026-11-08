"""Reveal in Pane shows the entry even when the pane's filter or the
hidden-files setting hid it.

Review round 3: with "notes" typed in a pane's filter, Find Files' (or the
transfer dock's) Reveal of ``report.txt`` opened the folder and selected
nothing - the row was filtered out - and said nothing. A dotfile revealed
while hidden files are not shown did the same. ``reveal_path`` ->
``_restore_selection`` skips rows the proxy does not show.

Now the reveal clears the filter, or shows hidden entries in that folder
(until the pane goes to another folder), when the revealed name would not
be visible otherwise, and the status line says what it changed.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.005)
    return False


def _names(pane) -> list[str]:
    proxy = pane._table.model()
    return [proxy.index(r, 0).data() for r in range(proxy.rowCount())]


@pytest.fixture
def pane(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    sub = tmp_path / "a" / "sub"
    sub.mkdir(parents=True)
    (tmp_path / "other").mkdir()
    for name in ("report.txt", "notes.md", ".env"):
        (sub / name).write_text(name)
    p = window._panes[0]
    p.navigate(str(tmp_path / "a"))
    assert _wait(lambda: "sub" in _names(p))
    p.test_sub = sub
    p.test_window = window
    yield p
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _reveal(pane, path: Path) -> None:
    pane.reveal_path(str(path))
    assert _wait(lambda: pane.current_path == str(path.parent) and not pane.is_loading)
    _wait(lambda: False, 0.2)


def test_happy_a_filter_that_hides_the_entry_is_cleared(pane):
    pane.test_window.set_show_hidden(True)
    pane._filter_edit.setText("notes")
    _reveal(pane, pane.test_sub / "report.txt")
    assert pane._filter_edit.text() == ""
    assert pane.selected_items() == [str(pane.test_sub / "report.txt")]
    assert "Filter cleared" in pane._status.text()


def test_sad_a_hidden_entry_is_shown_for_its_reveal_only(pane):
    pane.test_window.set_show_hidden(False)
    _reveal(pane, pane.test_sub / ".env")
    assert pane.selected_items() == [str(pane.test_sub / ".env")]
    assert "Hidden entries shown" in pane._status.text()
    assert pane.test_window._hidden_action.isChecked() is False  # the setting stays
    # Another folder: hidden entries are hidden again.
    pane.navigate(str(pane.test_sub.parent.parent / "other"))
    assert _wait(lambda: pane.current_path.endswith("other"))
    assert pane._proxy.show_hidden is False


def test_edge_a_visible_entry_changes_nothing_and_a_gone_one_is_said(pane):
    pane.test_window.set_show_hidden(True)
    pane._filter_edit.setText("re")
    _reveal(pane, pane.test_sub / "report.txt")
    assert pane._filter_edit.text() == "re"  # it matched: the filter stays
    assert pane.selected_items() == [str(pane.test_sub / "report.txt")]
    pane.reveal_path(str(pane.test_sub / "gone.txt"))
    _wait(lambda: False, 0.2)
    assert "gone.txt is not in this folder" in pane._status.text()
