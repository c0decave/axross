"""The Log dock's area filter: next to the level, a multi-select of the
logging areas (core.log_areas). Changing either filter shows the records
already received again, filtered; identical records in a burst collapse."""

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

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow  # noqa: E402

APP = QApplication.instance() or QApplication([])

SMB = logging.getLogger("core.smb_client")
FTP = logging.getLogger("core.ftp_client")
UI = logging.getLogger("ui.main_window")
OTHER = logging.getLogger("test.log_dock_areas")


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def dock():
    from ui.log_dock import LogDock

    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.DEBUG)
    win = QMainWindow()
    d = LogDock(win)
    win.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, d)
    win.resize(900, 600)
    win.show()
    pump()
    d._clear()
    yield d
    d.shutdown()
    root.setLevel(old_level)
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _lines(dock, *needles) -> list[str]:
    text = dock._log_view.toPlainText().split("\n")
    return [ln for ln in text if any(n in ln for n in needles)]


def _messages(dock) -> list[str]:
    return [ln.split(": ", 1)[1] for ln in _lines(dock, "core.smb_client", "core.ftp_client",
                                                       "ui.main_window", "test.log_dock_areas")]


def _emit_four():
    SMB.info("smb line")
    FTP.info("ftp line")
    UI.info("ui line")
    OTHER.info("other line")
    pump()


# -- happy ------------------------------------------------------------------------------------


def test_happy_all_areas_by_default(dock):
    assert dock.area_filter() is None
    assert dock._area_button.text() == "Areas: All"
    _emit_four()
    assert _messages(dock) == ["smb line", "ftp line", "ui line", "other line"]


def test_happy_one_area_shows_only_its_records_also_those_received_before(dock):
    _emit_four()
    dock.set_area_filter({"protocols.smb"})
    assert _messages(dock) == ["smb line"]
    SMB.info("smb again")
    FTP.info("ftp again")
    pump()
    assert _messages(dock) == ["smb line", "smb again"]
    assert dock._area_button.text() == "Areas: 1"
    dock.set_area_filter(None)
    assert _messages(dock) == ["smb line", "ftp line", "ui line", "other line",
                               "smb again", "ftp again"]


def test_happy_a_parent_area_takes_its_sub_areas(dock):
    _emit_four()
    dock.set_area_filter({"protocols"})
    assert _messages(dock) == ["smb line", "ftp line"]


def test_happy_the_menu_offers_every_area_and_toggling_one_filters(dock):
    from core import log_areas as LA

    menu = dock._area_button.menu()
    ids = [a.data() for a in menu.actions() if a.isCheckable()]
    assert ids[0] == "all" and ids[-1] == "other"
    assert ids[1:-1] == list(LA.AREA_IDS)
    _emit_four()
    dock._area_actions["ui"].trigger()  # ticks ui, unticks All
    assert not dock._area_actions["all"].isChecked()
    assert _messages(dock) == ["ui line"]
    dock._area_actions["other"].trigger()
    assert _messages(dock) == ["ui line", "other line"]
    dock._area_actions["all"].trigger()
    assert dock.area_filter() is None
    assert all(not a.isChecked() for k, a in dock._area_actions.items() if k != "all")


def test_happy_the_level_combo_refilters_what_is_shown(dock):
    SMB.debug("smb debug")
    SMB.warning("smb warning")
    pump()
    dock._level_combo.setCurrentText("WARNING")
    assert _messages(dock) == ["smb warning"]
    dock._level_combo.setCurrentText("DEBUG")
    assert _messages(dock) == ["smb debug", "smb warning"]


# -- sad --------------------------------------------------------------------------------------


def test_sad_an_empty_selection_means_all(dock):
    _emit_four()
    dock.set_area_filter(set())
    assert dock.area_filter() is None
    assert len(_messages(dock)) == 4


def test_sad_unknown_area_ids_are_dropped(dock):
    dock.set_area_filter({"no.such.area", "ui"})
    assert dock.area_filter() == frozenset({"ui"})
    dock.set_area_filter({"no.such.area"})
    assert dock.area_filter() is None


def test_sad_a_record_through_the_old_two_argument_path_still_lands(dock):
    dock._on_log_record("plain message", logging.INFO)
    pump()
    assert "plain message" in dock._log_view.toPlainText()
    dock.set_area_filter({"ui"})
    assert "plain message" not in dock._log_view.toPlainText()
    dock.set_area_filter({"other"})
    assert "plain message" in dock._log_view.toPlainText()


# -- edge -------------------------------------------------------------------------------------


def test_edge_the_kept_records_are_bounded_by_the_line_cap(dock):
    dock._log_view.setMaximumBlockCount(100)
    for i in range(300):
        SMB.info("kept %d", i)
    pump()
    assert len(dock._records) <= 100 + 50  # the view's cap, rounded up to the buffer's
    dock.set_area_filter({"protocols.smb"})
    lines = _lines(dock, "kept ")
    assert lines[-1].endswith("kept 299")
    assert len(lines) <= 100


def test_edge_a_burst_of_identical_records_collapses_in_the_dock(dock):
    for _ in range(1000):
        SMB.error("Media Player tick failed")
    pump()
    assert len(_lines(dock, "Media Player tick failed")) == 1
    dock._handler.filters[0].flush()
    pump()
    lines = _lines(dock, "Media Player tick failed")
    assert len(lines) == 2 and "repeated 999 more times" in lines[1]


def test_edge_the_menu_stays_open_while_ticking(dock):
    menu = dock._area_button.menu()
    menu.popup(dock.mapToGlobal(dock.rect().center()))
    pump()
    action = dock._area_actions["ui"]
    rect = menu.actionGeometry(action)
    QTest.mouseClick(menu, Qt.MouseButton.LeftButton, pos=rect.center())
    pump()
    assert action.isChecked() and menu.isVisible()
    menu.hide()


# -- e2e --------------------------------------------------------------------------------------


def test_e2e_the_main_windows_log_dock_filters_by_area(tmp_path, monkeypatch):
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.DEBUG)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        dock = win._log_dock
        pump(0.2)
        dock._clear()
        _emit_four()
        dock.set_area_filter({"protocols.ftp", "ui"})
        assert _messages(dock) == ["ftp line", "ui line"]
    finally:
        root.setLevel(old_level)
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_edge_an_ampersand_in_an_area_label_is_shown_not_a_mnemonic(dock):
    action = dock._area_actions["protocols.connections"]
    assert "&&" in action.text()
    assert action.text().replace("&&", "&").strip() == "Connections & Proxy"
