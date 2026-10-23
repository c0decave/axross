"""Remember the sudo password (Edit > Settings > Security; once Tools >
Remember sudo Password): the switch for remembering the sudo password while
axross runs (see tests/test_sudo_password.py for the core)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import open_limits as OL  # noqa: E402
from core import security_mode as SM  # noqa: E402
from core import sudo_password as SP  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def window(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("normal"))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    SP.forget()
    win = MainWindow()
    win._reconnect_timer.stop()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    SP.forget()


def _security(win):
    from ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(win, window=win)
    dialog.show_page("security")
    return dialog, dialog.page("security")


def test_happy_the_switch_is_on_by_default_and_turns_remembering_off(window):
    dialog, page = _security(window)
    box = page.remember_check
    assert box.isChecked() and box.isEnabled()
    SP.remember("pw")
    box.click()  # off
    assert dialog.apply()
    assert not SP.remember_enabled()
    assert SP.remembered() is None and OL.read_setting(SP.SETTING) is False
    box.click()  # on again
    assert dialog.apply()
    assert box.isChecked() and SP.remember_enabled()


def test_sad_paranoid_mode_forgets_and_disables_the_switch(window):
    dialog, page = _security(window)
    box = page.remember_check
    SP.remember("pw")
    page.paranoid_check.click()
    # Shown at once on the page, applied with OK / Apply.
    assert not box.isEnabled() and not box.isChecked()
    assert dialog.apply()
    assert SP.remembered() is None
    assert OL.read_setting(SP.SETTING, True) is True  # the stored choice is kept
    page.paranoid_check.click()  # back to normal
    assert box.isEnabled() and box.isChecked()  # the stored choice shows again
    assert dialog.apply()
    assert SP.remember_enabled()


def test_edge_a_stored_off_shows_unchecked_in_a_new_window(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("normal"))
    SP.set_remember(False)
    win = MainWindow()
    win._reconnect_timer.stop()
    try:
        _dialog, page = _security(win)
        assert not page.remember_check.isChecked()
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_edge_the_tools_menu_has_no_switches_any_more(window):
    tools = next(a.menu() for a in window.menuBar().actions() if a.text() == "&Tools")
    labels = [a.text().replace("&", "") for a in tools.actions()]
    assert "Remember sudo Password" not in labels
    assert "Paranoid Security Mode" not in labels
