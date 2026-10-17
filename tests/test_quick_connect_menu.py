"""Right click on a profile in the Quick Connect list.

Operator request: right click opens a menu with "Connect", "Connect in
Background" (a new pane with the connection, the list stays open) and
"Edit Config", in that order. Before, a right click connected at once,
like a left click: a QMenu triggers on the release of any button.
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

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from core.profiles import ConnectionProfile
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    for name in ("alpha", "beta"):
        win._profile_manager.add(
            ConnectionProfile(name=name, protocol="sftp", host=f"{name}.lab", username="u")
        )
    win.resize(900, 600)
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def calls(window, monkeypatch):
    seen = []
    monkeypatch.setattr(
        window,
        "_quick_connect_profile",
        lambda profile, **kw: seen.append(("connect", profile.name, kw.get("activate", True))),
    )
    monkeypatch.setattr(window, "_on_connect", lambda *a, **kw: seen.append(("edit", kw)))
    return seen


def _menu(window):
    menu = window._build_quick_connect_menu()
    menu.popup(QPoint(10, 10))
    pump()
    return menu


def _entry(menu, name):
    return next(a for a in menu.actions() if a.text().find(name) >= 0 and menu.profile_of(a))


def _right_click(menu, action):
    QTest.mouseClick(menu, Qt.MouseButton.RightButton, pos=menu.actionGeometry(action).center())


# --- happy -----------------------------------------------------------------


def test_happy_the_right_click_menu_lists_the_three_entries_in_order(window) -> None:
    menu = _menu(window)
    profile = menu.profile_of(_entry(menu, "alpha"))
    labels = [a.text() for a in menu.build_profile_menu(profile).actions()]
    assert labels == ["Connect", "Connect in Background", "Edit Config…"]
    menu.close()


def test_happy_connect_in_background_keeps_the_list_open(window, calls, monkeypatch) -> None:
    menu = _menu(window)
    shown = []

    def pick(sub, _pos, text="Connect in Background"):
        shown.append([a.text() for a in sub.actions()])
        next(a for a in sub.actions() if a.text() == text).trigger()

    monkeypatch.setattr(menu, "exec_profile_menu", pick)
    _right_click(menu, _entry(menu, "alpha"))
    _right_click(menu, _entry(menu, "beta"))
    pump()
    assert calls == [("connect", "alpha", False), ("connect", "beta", False)]
    assert menu.isVisible()  # still open for the next profile
    assert shown and shown[0][1] == "Connect in Background"
    menu.close()


def test_happy_connect_closes_the_list_and_connects(window, calls, monkeypatch) -> None:
    menu = _menu(window)
    monkeypatch.setattr(
        menu,
        "exec_profile_menu",
        lambda sub, _pos: next(a for a in sub.actions() if a.text() == "Connect").trigger(),
    )
    _right_click(menu, _entry(menu, "beta"))
    pump()
    assert calls == [("connect", "beta", True)]
    assert not menu.isVisible()


def test_happy_edit_config_opens_the_dialog_with_that_profile(window, calls, monkeypatch) -> None:
    menu = _menu(window)
    monkeypatch.setattr(
        menu,
        "exec_profile_menu",
        lambda sub, _pos: next(a for a in sub.actions() if a.text() == "Edit Config…").trigger(),
    )
    _right_click(menu, _entry(menu, "alpha"))
    pump()
    assert len(calls) == 1 and calls[0][0] == "edit"
    assert calls[0][1]["profile"].name == "alpha"
    assert not menu.isVisible()


def test_happy_edit_config_loads_the_profile_into_the_dialog(window, monkeypatch) -> None:
    from ui import connection_dialog as CD

    opened = []

    def fake_exec(self):
        opened.append(self._profile_combo.currentText())
        return CD.ConnectionDialog.DialogCode.Rejected

    monkeypatch.setattr(CD.ConnectionDialog, "exec", fake_exec)
    window._on_connect(profile=window._profile_manager.get("beta"))
    assert opened == ["beta"]


def test_sad_edit_config_of_an_unsaved_profile_still_fills_the_form(window, monkeypatch) -> None:
    from core.profiles import ConnectionProfile
    from ui import connection_dialog as CD

    seen = []

    def fake_exec(self):
        seen.append((self._profile_combo.currentText(), self._host.text()))
        return CD.ConnectionDialog.DialogCode.Rejected

    monkeypatch.setattr(CD.ConnectionDialog, "exec", fake_exec)
    ghost = ConnectionProfile(name="ghost", protocol="sftp", host="ghost.lab", username="u")
    window._on_connect(profile=ghost)
    assert seen == [("(New Connection)", "ghost.lab")]


def test_happy_a_left_click_still_connects(window, calls) -> None:
    menu = _menu(window)
    action = _entry(menu, "alpha")
    QTest.mouseClick(menu, Qt.MouseButton.LeftButton, pos=menu.actionGeometry(action).center())
    pump()
    assert calls == [("connect", "alpha", True)]


# --- sad -------------------------------------------------------------------


def test_sad_a_right_click_never_connects_by_itself(window, calls, monkeypatch) -> None:
    menu = _menu(window)
    monkeypatch.setattr(menu, "exec_profile_menu", lambda sub, _pos: None)  # menu dismissed
    _right_click(menu, _entry(menu, "alpha"))
    pump()
    assert calls == []
    assert menu.isVisible()
    menu.close()


def test_sad_a_right_click_on_connection_manager_opens_no_profile_menu(
    window, calls, monkeypatch
) -> None:
    menu = _menu(window)
    opened = []
    monkeypatch.setattr(menu, "exec_profile_menu", lambda sub, _pos: opened.append(sub))
    manager = next(a for a in menu.actions() if a.text().startswith("Connection Manager"))
    _right_click(menu, manager)
    pump()
    assert opened == [] and calls == []
    menu.close()


# --- edge ------------------------------------------------------------------


def test_edge_background_connect_leaves_the_active_pane_alone(window, monkeypatch) -> None:
    from core.local_fs import LocalFS

    before = window._active_pane
    monkeypatch.setattr(
        window,
        "_run_connect_async",
        lambda profile, pw, kp, on_success, on_failure: on_success(LocalFS()),
    )
    from core import credentials

    monkeypatch.setattr(credentials, "get_password", lambda name: "pw")  # no prompt
    profile = window._profile_manager.get("alpha")
    count = len(window._panes)
    window._quick_connect_profile(profile, activate=False)
    pump()
    assert len(window._panes) == count + 1
    assert window._active_pane is before
    window._quick_connect_profile(profile)
    pump()
    assert window._active_pane is window._panes[-1]


def test_edge_the_keyboard_menu_key_opens_the_profile_menu(window, calls, monkeypatch) -> None:
    menu = _menu(window)
    opened = []
    monkeypatch.setattr(
        menu,
        "exec_profile_menu",
        lambda sub, _pos: opened.append([a.text() for a in sub.actions()]),
    )
    menu.setActiveAction(_entry(menu, "beta"))
    QTest.keyClick(menu, Qt.Key.Key_Menu)
    pump()
    assert opened and opened[0][0] == "Connect"
    assert calls == []
    menu.close()


def test_edge_connection_manager_entry_still_works(window, calls) -> None:
    menu = _menu(window)
    manager = next(a for a in menu.actions() if a.text().startswith("Connection Manager"))
    manager.trigger()
    assert calls and calls[0][0] == "edit"
