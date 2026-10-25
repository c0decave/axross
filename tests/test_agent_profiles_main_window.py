"""Agent profiles from the menu bar: Tools > New Agent Tab from Profile
lists the presets and the user's profiles and opens a tab for the active
pane's folder; the dock's Edit Agent Profiles… opens Agent Settings on its
Profiles page."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent_profiles as AP  # noqa: E402
from core import agent_settings as S  # noqa: E402
from core import agent_session as AS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui import main_window as MW

    settings = S.AgentSettings()
    settings.agent_profiles = [AP.AgentProfile("Mine", mode="plan")]
    path = tmp_path / "agent.json"
    settings.save(path)
    monkeypatch.setattr(S, "settings_file", lambda: path)
    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "sessions")
    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    APP.processEvents()


def _tools(window):
    return next(a.menu() for a in window.menuBar().actions()
                if a.menu() is not None and a.text().replace("&", "") == "Tools")


def _entry(menu, text):
    menu.aboutToShow.emit()
    return next(a for a in menu.actions() if a.text().replace("&", "") == text)


def test_happy_tools_menu_opens_a_tab_from_a_profile(win):
    sub = _entry(_tools(win), "New Agent Tab from Profile").menu()
    sub.aboutToShow.emit()
    labels = [a.text() for a in sub.actions() if not a.isSeparator()]
    assert labels[0] == "Files Assistant (preset)" and labels[-1] == "Mine"
    dock = win._agent_dock
    before = dock.tabs.count()
    next(a for a in sub.actions() if a.text() == "Mine").trigger()
    tab = dock.current_tab()
    assert dock.tabs.count() == before + 1 and dock.isVisibleTo(win)
    assert tab.session.agent_profile == "Mine" and tab.session.mode == "plan"
    assert tab.session.folder == win._agent_root()


def test_sad_edit_agent_profiles_opens_the_profiles_page(win, monkeypatch):
    opened = []
    monkeypatch.setattr(win, "open_settings", lambda *a, **k: opened.append(a) or 0)
    win._agent_dock.profiles_requested.emit()
    assert opened == [("agent", "profiles")]


def test_edge_the_entry_has_a_mnemonic_of_its_own(win):
    action = _entry(_tools(win), "New Agent Tab from Profile")
    letter = action.text().split("&", 1)[1][0].lower()
    others = [a.text() for a in _tools(win).actions()
              if a is not action and "&" + letter in a.text().lower().replace("&&", "")]
    assert others == []
