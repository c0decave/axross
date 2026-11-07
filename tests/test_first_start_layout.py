"""The first start shows two file panes; later starts keep what was saved.

A fresh start showed a single pane, though axross is a two-pane file
manager (source and target of a transfer). main.py lays out
MainWindow.FIRST_START_PRESET when nothing was saved yet.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(rounds: int = 5) -> None:
    for _ in range(rounds):
        APP.processEvents()


@pytest.fixture
def session_file(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    path = home / "session.json"
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path)
    return path


@pytest.fixture
def windows():
    made = []
    yield made
    for win in made:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
    pump()


def start(windows, **attrs):
    """What main.py does: restore the saved layout, else the first-start one."""
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    for name, value in attrs.items():
        setattr(win, name, value)
    windows.append(win)
    if not win.restore_layout_on_start():
        win.apply_first_start_layout()
    win.resize(1200, 800)
    win.show()
    pump()
    return win


def test_happy_the_first_start_shows_two_file_panes(session_file, windows):
    assert not session_file.exists()
    win = start(windows)
    assert len(win._panes) == 2
    assert not win._terminal_panes


def test_happy_a_saved_single_pane_stays_single(session_file, windows):
    first = start(windows)
    first.apply_layout_preset("single")
    pump()
    assert len(first._panes) == 1
    first._save_session()
    first.close()
    pump()
    again = start(windows)
    assert len(again._panes) == 1


def test_sad_layout_restore_switched_off_keeps_one_pane(session_file, windows):
    win = start(windows, _restore_on_start=False)
    assert len(win._panes) == 1


def test_edge_a_damaged_session_file_is_not_overridden(session_file, windows):
    session_file.write_text("{not json")
    win = start(windows)
    assert len(win._panes) == 1
    session_file.write_text(json.dumps(["a list"]))
    from ui.main_window import MainWindow

    assert MainWindow.apply_first_start_layout(win) is False


def test_edge_settings_without_a_layout_count_as_a_first_start(session_file, windows):
    session_file.write_text(json.dumps({"language": "en"}))
    win = start(windows)
    assert len(win._panes) == 2
