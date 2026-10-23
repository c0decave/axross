"""The Log dock's Auto-Scroll keeps the newest line in view.

Reported: "auto scroll ... scheint in LOG pane logs nicht zu funktionieren".
Reproduced: one click into the log (to read or copy a line) moved the
view's text cursor there, and Auto-Scroll called ``ensureCursorVisible()``
- which shows that cursor, not the newest line. From then on every new
record pinned the view to the clicked line.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
LOG = logging.getLogger("test.log_dock_autoscroll")


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1100, 800)
    win.show()
    win._log_dock.show()
    win._log_dock.raise_()
    pump()
    old_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.DEBUG)
    yield win
    logging.getLogger().setLevel(old_level)
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


#: The number of the newest record emitted by _emit().
_newest = [-1]


def _emit(start: int, stop: int) -> None:
    for i in range(start, stop):
        LOG.info("record %d", i)
    _newest[0] = stop - 1
    pump()


def _bottom_text(view) -> str:
    """The text of the last non-empty line shown at the bottom of *view*."""
    cursor = view.cursorForPosition(QPoint(2, view.viewport().height() - 2))
    block = cursor.block()
    while block.isValid() and not block.text():
        block = block.previous()
    return block.text()


def _at_newest(dock) -> bool:
    return _bottom_text(dock._log_view).endswith(f"record {_newest[0]}")


def test_happy_auto_scroll_shows_the_newest_line(window) -> None:
    dock = window._log_dock
    assert dock._btn_scroll.isChecked()
    _emit(0, 200)
    assert dock._log_view.verticalScrollBar().maximum() > 0  # the log does overflow
    assert _at_newest(dock), _bottom_text(dock._log_view)


def test_sad_a_click_into_the_log_no_longer_pins_the_view(window) -> None:
    """The reported bug: after a click, new records stayed out of sight."""
    dock = window._log_dock
    view = dock._log_view
    _emit(0, 200)
    bar = view.verticalScrollBar()
    bar.setValue(bar.maximum() // 2)
    pump()
    QTest.mouseClick(
        view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(20, 10)
    )
    pump()
    _emit(200, 400)
    assert _at_newest(dock), _bottom_text(view)


def test_sad_auto_scroll_off_leaves_the_view_where_the_user_put_it(window) -> None:
    dock = window._log_dock
    view = dock._log_view
    _emit(0, 200)
    QTest.mouseClick(dock._btn_scroll, Qt.MouseButton.LeftButton)
    assert not dock._btn_scroll.isChecked()
    bar = view.verticalScrollBar()
    bar.setValue(10)
    pump()
    first = view.firstVisibleBlock().blockNumber()
    _emit(200, 300)
    assert view.firstVisibleBlock().blockNumber() == first
    assert not _at_newest(dock)


def test_edge_switching_auto_scroll_on_jumps_to_the_newest_line(window) -> None:
    dock = window._log_dock
    QTest.mouseClick(dock._btn_scroll, Qt.MouseButton.LeftButton)  # off
    _emit(0, 200)
    dock._log_view.verticalScrollBar().setValue(0)
    pump()
    QTest.mouseClick(dock._btn_scroll, Qt.MouseButton.LeftButton)  # on again
    pump()
    assert dock._btn_scroll.isChecked()
    assert _at_newest(dock), _bottom_text(dock._log_view)


def test_edge_records_arriving_behind_another_tab_are_in_view_when_raised(window) -> None:
    dock = window._log_dock
    window._transfer_dock.raise_()
    pump()
    _emit(0, 300)
    dock.raise_()
    pump()
    assert _at_newest(dock), _bottom_text(dock._log_view)


def test_edge_a_selection_survives_auto_scroll(window) -> None:
    """Following the newest line must not take away what the user marked."""
    dock = window._log_dock
    view = dock._log_view
    _emit(0, 50)
    cursor = view.document().find("record 0")
    assert not cursor.isNull()
    cursor.movePosition(cursor.MoveOperation.StartOfBlock)
    cursor.movePosition(cursor.MoveOperation.EndOfBlock, cursor.MoveMode.KeepAnchor)
    view.setTextCursor(cursor)
    marked = view.textCursor().selectedText()
    assert "record 0" in marked
    _emit(50, 250)
    assert view.textCursor().selectedText() == marked
    assert _at_newest(dock), _bottom_text(view)


def test_edge_the_line_cap_keeps_following(window) -> None:
    """Past setMaximumBlockCount the first lines go; the view still follows."""
    dock = window._log_dock
    dock._log_view.setMaximumBlockCount(100)
    _emit(0, 400)
    assert dock._log_view.document().blockCount() <= 100
    assert _at_newest(dock), _bottom_text(dock._log_view)
