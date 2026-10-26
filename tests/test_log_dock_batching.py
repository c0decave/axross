"""The Log dock writes a burst of records in one go, not one edit per record.

Measured 2026-10-25 (scripts/ui_bench.py ``log_burst_5000``): 5000 records
cost 324-700 ms on the GUI thread - LogDock._on_log_record inserted each
line with its own cursor edit (the document trims its oldest line on every
one once it is full), set the count label, moved the scroll bar and emitted
``activity`` per record. Now records are collected and written at the next
turn of the event loop: one edit per run of lines of the same level, the
label, the scroll bar and ``activity`` once.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QColor  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow  # noqa: E402

APP = QApplication.instance() or QApplication([])
LOG = logging.getLogger("test.log_dock_batching")


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def dock():
    from ui.log_dock import LogDock

    old_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.DEBUG)
    LOG.setLevel(logging.DEBUG)
    win = QMainWindow()
    d = LogDock(win)
    win.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, d)
    win.resize(900, 600)
    win.show()
    pump()
    d._clear()
    yield d
    d.shutdown()
    logging.getLogger().setLevel(old_level)
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _ours(dock) -> list[str]:
    return [ln for ln in dock._log_view.toPlainText().split("\n") if "test.log_dock_batching" in ln]


def _edits(dock) -> list:
    changes = []
    dock._log_view.document().contentsChange.connect(lambda *a: changes.append(a))
    return changes


# -- happy ---------------------------------------------------------------------


def test_happy_a_burst_is_written_in_one_edit_and_every_line_arrives(dock) -> None:
    changes = _edits(dock)
    activity = []
    dock.activity.connect(lambda: activity.append(1))
    for i in range(2000):
        LOG.info("record %d", i)
    pump()
    lines = _ours(dock)
    assert [ln.rsplit(" ", 1)[1] for ln in lines] == [str(i) for i in range(2000)]
    assert len(changes) <= 3  # one run of INFO lines (other loggers may add one)
    assert len(activity) <= 3
    assert dock._count_label.text() == f"{dock._msg_count} messages"
    assert dock._msg_count >= 2000


def test_happy_each_line_keeps_the_colour_of_its_level(dock) -> None:
    from ui.log_dock import LEVEL_COLORS

    LOG.debug("a debug line")
    LOG.info("an info line")
    LOG.warning("a warning line")
    LOG.warning("another warning line")
    LOG.error("an error line")
    LOG.critical("a critical line")
    pump()
    expected = {"a debug line": logging.DEBUG, "an info line": logging.INFO,
                "a warning line": logging.WARNING, "another warning line": logging.WARNING,
                "an error line": logging.ERROR, "a critical line": logging.CRITICAL}
    block = dock._log_view.document().firstBlock()
    seen = {}
    while block.isValid():
        for text, level in expected.items():
            if block.text().endswith(text):
                fmt = block.begin().fragment().charFormat()
                seen[text] = fmt.foreground().color()
        block = block.next()
    assert seen == {text: QColor(LEVEL_COLORS[level]) for text, level in expected.items()}


# -- sad -----------------------------------------------------------------------


def test_sad_records_below_the_level_are_not_shown_or_counted(dock) -> None:
    dock._level_combo.setCurrentText("WARNING")
    LOG.info("quiet")
    LOG.warning("loud")
    pump()
    assert [ln.split(": ", 1)[1] for ln in _ours(dock)] == ["loud"]
    assert dock._msg_count == 1


def test_sad_clear_drops_records_not_written_yet(dock) -> None:
    for i in range(50):
        LOG.info("before clear %d", i)
    QTest.mouseClick(dock._btn_clear, Qt.MouseButton.LeftButton)
    pump()
    assert _ours(dock) == []
    assert dock._msg_count == 0 and dock._count_label.text() == "0 messages"
    LOG.info("after clear")
    pump()
    assert len(_ours(dock)) == 1


def test_sad_records_from_another_thread_arrive_in_order(dock) -> None:
    def work() -> None:
        for i in range(500):
            LOG.info("thread record %d", i)

    t = threading.Thread(target=work)
    t.start()
    t.join()
    pump(0.2)
    assert [ln.rsplit(" ", 1)[1] for ln in _ours(dock)] == [str(i) for i in range(500)]


# -- edge ----------------------------------------------------------------------


def test_edge_a_burst_past_the_line_cap_keeps_the_newest_lines(dock) -> None:
    dock._log_view.setMaximumBlockCount(300)
    changes = _edits(dock)
    for i in range(1000):
        LOG.info("capped %d", i)
    pump()
    lines = _ours(dock)
    assert lines[-1].endswith("capped 999")
    assert dock._log_view.document().blockCount() <= 300
    assert [int(ln.rsplit(" ", 1)[1]) for ln in lines] == list(range(1000 - len(lines), 1000))
    assert dock._msg_count >= 1000  # every record is counted, also those dropped by the cap
    assert len(changes) <= 3


def test_edge_auto_scroll_shows_the_newest_line_after_a_burst(dock) -> None:
    for i in range(400):
        LOG.info("scroll %d", i)
    pump()
    bar = dock._log_view.verticalScrollBar()
    assert bar.maximum() > 0 and bar.value() == bar.maximum()
    dock._btn_scroll.setChecked(False)
    bar.setValue(0)
    for i in range(50):
        LOG.info("more %d", i)
    pump()
    assert bar.value() == 0  # off: the view stays where the user put it


# -- e2e -----------------------------------------------------------------------


def test_e2e_the_main_windows_log_dock_takes_a_burst_in_few_edits(tmp_path, monkeypatch) -> None:
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    old_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.DEBUG)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.resize(1100, 800)
        win.show()
        dock = win._log_dock
        dock.show()
        dock.raise_()
        pump(0.2)
        changes = _edits(dock)
        for i in range(3000):
            LOG.info("window record %d", i)
        pump(0.2)
        lines = _ours(dock)
        assert lines[-1].endswith("window record 2999")
        assert len(lines) == 3000
        assert len(changes) < 30  # 3000 before
        bar = dock._log_view.verticalScrollBar()
        assert bar.value() == bar.maximum()
    finally:
        logging.getLogger().setLevel(old_level)
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
