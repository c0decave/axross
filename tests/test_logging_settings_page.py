"""Edit > Settings… > Logging (ui.logging_settings_page): the overall level,
a level per area, the log file's size and count, the terminal, the collapse
of repeated records, Reset. Saved to ~/.config/axross/logging.json and
applied at once - and at the next start."""

from __future__ import annotations

import json
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
from PyQt6.QtWidgets import QApplication, QDialogButtonBox  # noqa: E402

from core import log_areas as LA  # noqa: E402
from core import log_config as LC  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture(autouse=True)
def clean_logging():
    root = logging.getLogger()
    old_level = root.level
    yield
    LC.teardown()
    root.setLevel(old_level)


@pytest.fixture
def store(tmp_path):
    return tmp_path / "logging.json"


@pytest.fixture
def page(store):
    from ui.logging_settings_page import LoggingPage

    p = LoggingPage(path=store)
    yield p
    p.deleteLater()


def _choose(combo, data) -> None:
    index = combo.findData(data)
    assert index >= 0, data
    combo.setCurrentIndex(index)


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_fresh_page_shows_the_defaults(page):
    assert page.level_combo.currentData() == "INFO"
    assert page.area_combos["protocols.smb"].currentData() == "inherit"
    assert page.area_combos["third_party"].currentData() == "WARNING"
    assert page.file_size_spin.value() == 5 and page.backups_spin.value() == 3
    assert not page.terminal_check.isChecked()
    assert page.collapse_check.isChecked() and page.window_spin.value() == 10
    assert not page.is_dirty() and page.problems() == []


def test_happy_the_tree_lists_every_area_under_its_parent(page):
    tree = page.area_tree
    top = [tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
           for i in range(tree.topLevelItemCount())]
    assert top == [a.id for a in LA.AREAS if a.parent is None]
    protocols = tree.topLevelItem(top.index("protocols"))
    kids = [protocols.child(i).data(0, Qt.ItemDataRole.UserRole)
            for i in range(protocols.childCount())]
    assert kids == LA.children("protocols")
    assert set(page.area_combos) == set(LA.AREA_IDS)


def test_happy_save_stores_and_applies_at_once(page, store):
    _choose(page.area_combos["protocols.smb"], "DEBUG")
    _choose(page.level_combo, "WARNING")
    page.file_size_spin.setValue(12)
    assert page.is_dirty()
    assert page.save() is True
    data = json.loads(store.read_text(encoding="utf-8"))
    assert data["areas"] == {"protocols.smb": "DEBUG"} and data["level"] == "WARNING"
    assert data["file_max_mib"] == 12
    assert logging.getLogger("core.smb_client").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("core.ftp_client").isEnabledFor(logging.INFO)
    assert not page.is_dirty()


def test_happy_the_page_shows_what_is_stored(store):
    from ui.logging_settings_page import LoggingPage

    s = LC.LogSettings()
    s.set_area("mcp.server", "ERROR")
    s.set_area("third_party.http", "off")
    s.set("terminal", True)
    s.set("repeat_window", 60)
    s.save(store)
    p = LoggingPage(path=store)
    assert p.area_combos["mcp.server"].currentData() == "ERROR"
    assert p.area_combos["third_party.http"].currentData() == "off"
    assert p.terminal_check.isChecked() and p.window_spin.value() == 60
    p.deleteLater()


def test_happy_reset_shows_the_defaults_until_saved(page, store):
    s = LC.LogSettings()
    s.set_area("ui", "DEBUG")
    s.set("collapse_repeats", False)
    s.save(store)
    from ui.logging_settings_page import LoggingPage

    p = LoggingPage(path=store)
    QTest.mouseClick(p.reset_button, Qt.MouseButton.LeftButton)
    assert p.area_combos["ui"].currentData() == "inherit"
    assert p.collapse_check.isChecked()
    assert p.is_dirty()
    assert LC.LogSettings.load(store).area_choice("ui") == "DEBUG"  # nothing saved yet
    assert p.save()
    assert LC.LogSettings.load(store) == LC.LogSettings()
    p.deleteLater()


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_corrupt_store_shows_the_defaults_and_saving_repairs_it(store):
    from ui.logging_settings_page import LoggingPage

    store.write_text("{broken", encoding="utf-8")
    p = LoggingPage(path=store)
    assert p.values() == LC.LogSettings()
    _choose(p.area_combos["transfers"], "DEBUG")
    assert p.save()
    assert LC.LogSettings.load(store).area_choice("transfers") == "DEBUG"
    p.deleteLater()


def test_sad_a_failed_save_raises_and_applies_nothing(page, monkeypatch):
    def refuse(self, path=None):
        raise OSError("disk full")

    monkeypatch.setattr(LC.LogSettings, "save", refuse)
    _choose(page.area_combos["protocols.smb"], "DEBUG")
    with pytest.raises(OSError):
        page.save()
    assert not logging.getLogger("core.smb_client").isEnabledFor(logging.DEBUG)
    assert page.is_dirty()


def test_sad_the_window_spin_is_off_while_collapse_is_off(page):
    page.collapse_check.setChecked(False)
    assert not page.window_spin.isEnabled()
    page.collapse_check.setChecked(True)
    assert page.window_spin.isEnabled()


# -- edge -------------------------------------------------------------------------------------


def test_edge_the_spins_hold_the_bounds(page):
    assert (page.file_size_spin.minimum(), page.file_size_spin.maximum()) == LC.FILE_MIB_RANGE
    assert (page.backups_spin.minimum(), page.backups_spin.maximum()) == LC.BACKUPS_RANGE
    assert (page.window_spin.minimum(), page.window_spin.maximum()) == LC.WINDOW_RANGE


def test_edge_every_area_offers_inherit_the_levels_and_off(page):
    for combo in page.area_combos.values():
        assert [combo.itemData(i) for i in range(combo.count())] == list(LC.AREA_CHOICES)
    assert [page.level_combo.itemData(i) for i in range(page.level_combo.count())] == \
        list(LC.LEVELS)


def test_edge_third_party_set_to_inherit_is_stored_explicitly(page, store):
    _choose(page.area_combos["third_party"], "inherit")
    page.save()
    assert json.loads(store.read_text(encoding="utf-8"))["areas"] == {"third_party": "inherit"}
    assert logging.getLogger("paramiko").getEffectiveLevel() == logging.INFO


def test_edge_the_page_names_a_run_floor(store, tmp_path):
    from ui.logging_settings_page import LoggingPage

    LC.configure(tmp_path / "axross.log", debug=True, settings=LC.LogSettings())
    p = LoggingPage(path=store)
    assert not p.floor_note.isHidden()
    assert "--debug" in p.floor_note.text()
    p.deleteLater()
    LC.teardown()
    p = LoggingPage(path=store)
    assert p.floor_note.isHidden()
    p.deleteLater()


# -- e2e --------------------------------------------------------------------------------------


def test_e2e_settings_dialog_area_level_reaches_logging_the_log_dock_and_the_next_start(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui.main_window import MainWindow
    from ui.settings_dialog import SettingsDialog

    log_file = tmp_path / "logs" / "axross.log"
    LC.configure(log_file)  # a start on an empty home: the defaults
    smb = logging.getLogger("core.smb_client")
    assert not smb.isEnabledFor(logging.DEBUG)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        dialog = SettingsDialog(win, window=win)
        dialog.show()
        dialog.show_page("logging")
        pump()
        page = dialog.page("logging")
        _choose(page.area_combos["protocols.smb"], "DEBUG")
        assert dialog.dirty_page_ids() == ["logging"]
        apply_button = dialog.buttons.button(QDialogButtonBox.StandardButton.Apply)
        QTest.mouseClick(apply_button, Qt.MouseButton.LeftButton)
        assert dialog.dirty_page_ids() == []
        # Live: SMB debug records are made, written and shown - FTP's are not.
        assert smb.isEnabledFor(logging.DEBUG)
        dock = win._log_dock
        dock._clear()
        smb.debug("e2e smb handshake detail")
        logging.getLogger("core.ftp_client").debug("e2e ftp detail")
        pump()
        dock.set_area_filter({"protocols.smb"})
        text = dock._log_view.toPlainText()
        assert "e2e smb handshake detail" in text and "e2e ftp detail" not in text
        for handler in logging.getLogger().handlers:
            handler.flush()
        file_text = log_file.read_text(encoding="utf-8")
        assert "e2e smb handshake detail" in file_text and "e2e ftp detail" not in file_text
        dialog.reject()
        dialog.deleteLater()
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    # The next start reads it back.
    LC.teardown()
    LC.configure(log_file)
    assert smb.isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("core.ftp_client").isEnabledFor(logging.DEBUG)
