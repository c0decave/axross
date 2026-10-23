"""Deleting a saved connection config from a right-click menu.

Operator punch list item 27: "configs im connection manager muessen auch
gelöscht werden können, auch beim quick connect und dann rechter maustaste
delete connection config supporten".

Before: only the connection dialog's Delete button removed a profile. Now
the Quick Connect list's right-click menu has "Delete Connection Config…"
(beside Edit Config…), and so does a right click on the connection dialog's
profile list. Both ask first and remove the profile the way the Delete
button does - with its password in the keyring (ProfileManager.remove).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])
YES = QMessageBox.StandardButton.Yes
NO = QMessageBox.StandardButton.No


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(scope="module")
def _window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(900, 600)
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def win(_window):
    from core.profiles import ConnectionProfile

    pm = _window._profile_manager
    for name in list(pm.list_names()):
        pm.remove(name)
    for name in ("alpha", "beta"):
        pm.add(ConnectionProfile(name=name, protocol="sftp", host=f"{name}.lab", username="u"))
    _window._recent_profiles = ["beta", "alpha"]
    _window._save_recents()
    yield _window


@pytest.fixture
def keyring_deletes(monkeypatch):
    import core.profiles as P

    seen: list[str] = []
    monkeypatch.setattr(P, "delete_password", lambda name: seen.append(name) or True)
    return seen


def _menu(win):
    menu = win._build_quick_connect_menu()
    menu.popup(QPoint(10, 10))
    pump()
    return menu


def _entries(menu, name):
    return [a for a in menu.actions() if menu.profile_of(a) and name in a.text()]


def _labels(menu: QMenu) -> list[str]:
    return [a.text() for a in menu.actions() if not a.isSeparator()]


def _picker(picked: list):
    """An exec_profile_menu that triggers Delete when the menu has it. No
    exception may leave it: it runs inside a Qt event handler."""

    def pick(sub, _pos):
        found = [a for a in sub.actions() if a.text() == "Delete Connection Config…"]
        picked.extend(found)
        if found:
            found[0].trigger()

    return pick


def _right_click_delete(win, menu, name, monkeypatch, *, index=-1):
    picked: list = []
    monkeypatch.setattr(menu, "exec_profile_menu", _picker(picked))
    action = _entries(menu, name)[index]
    QTest.mouseClick(menu, Qt.MouseButton.RightButton, pos=menu.actionGeometry(action).center())
    pump()
    assert picked, "the right-click menu has no Delete Connection Config…"


# --- happy -----------------------------------------------------------------


def test_happy_the_right_click_menu_offers_delete_after_edit(win) -> None:
    menu = _menu(win)
    profile = menu.profile_of(_entries(menu, "alpha")[0])
    sub = menu.build_profile_menu(profile)
    assert _labels(sub) == [
        "Connect", "Connect in Background", "Edit Config…", "Delete Connection Config…"
    ]
    assert sub.actions()[3].isSeparator()  # set apart from the harmless entries
    menu.close()


def test_happy_e2e_quick_connect_delete_removes_profile_recent_and_password(
    win, monkeypatch, keyring_deletes
) -> None:
    menu = _menu(win)
    with mock.patch("ui.main_window.QMessageBox.question", return_value=YES) as ask:
        _right_click_delete(win, menu, "alpha", monkeypatch)
    assert ask.call_count == 1 and "alpha" in ask.call_args.args[2]
    assert not menu.isVisible()
    assert win._profile_manager.get("alpha") is None
    assert keyring_deletes == ["alpha"]
    assert "alpha" not in win._recent_profiles
    assert json.loads(win._RECENTS_FILE.read_text()) == ["beta"]
    from core.profiles import ProfileManager

    assert ProfileManager().list_names() == ["beta"]  # gone from the file too
    fresh = _menu(win)
    assert _entries(fresh, "alpha") == [] and _entries(fresh, "beta")
    fresh.close()


def test_happy_e2e_connection_dialog_right_click_deletes_the_shown_profile(
    win, monkeypatch, keyring_deletes
) -> None:
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(win._profile_manager, parent=win)
    try:
        dialog.show()
        dialog._profile_combo.setCurrentText("beta")
        pump()
        shown = []

        def run(menu, *_a):
            shown.append([a.text() for a in menu.actions()])
            for a in menu.actions():
                if a.text() == "Delete Connection Config…":
                    a.trigger()

        monkeypatch.setattr(QMenu, "exec", run)
        with mock.patch("ui.connection_dialog.QMessageBox.question", return_value=YES):
            combo = dialog._profile_combo
            # What a right click becomes in Qt: a context-menu event on the
            # combo (QTest's mouse clicks do not synthesise it).
            from PyQt6.QtGui import QContextMenuEvent

            centre = combo.rect().center()
            QApplication.sendEvent(
                combo,
                QContextMenuEvent(
                    QContextMenuEvent.Reason.Mouse, centre, combo.mapToGlobal(centre)
                ),
            )
            pump()
        assert shown and "Delete Connection Config…" in shown[0]
        assert win._profile_manager.get("beta") is None
        assert keyring_deletes == ["beta"]
        assert dialog._profile_combo.findText("beta") < 0
    finally:
        dialog.close()
        dialog.deleteLater()
        pump()


# --- sad -------------------------------------------------------------------


def test_sad_saying_no_keeps_the_profile_and_its_password(
    win, monkeypatch, keyring_deletes
) -> None:
    menu = _menu(win)
    with mock.patch("ui.main_window.QMessageBox.question", return_value=NO):
        _right_click_delete(win, menu, "beta", monkeypatch)
    assert win._profile_manager.get("beta") is not None
    assert keyring_deletes == []
    assert win._recent_profiles == ["beta", "alpha"]


def test_sad_a_profile_deleted_meanwhile_is_reported_not_crashed(win, keyring_deletes) -> None:
    profile = win._profile_manager.get("alpha")
    win._profile_manager.remove("alpha")
    keyring_deletes.clear()
    with mock.patch("ui.main_window.QMessageBox.question", return_value=YES) as ask:
        win._delete_connection_config(profile)
    assert ask.call_count == 0
    assert keyring_deletes == []
    assert "alpha" in win.statusBar().currentMessage()


def test_sad_the_dialog_menu_cannot_delete_a_new_unsaved_connection(win) -> None:
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(win._profile_manager, parent=win)
    try:
        dialog._profile_combo.setCurrentIndex(0)  # (New Connection)
        menu = dialog._build_profile_menu()
        delete = next(a for a in menu.actions() if a.text() == "Delete Connection Config…")
        assert not delete.isEnabled()
    finally:
        dialog.deleteLater()


# --- edge ------------------------------------------------------------------


def test_edge_deleting_from_the_recent_section_removes_both_entries(
    win, monkeypatch, keyring_deletes
) -> None:
    menu = _menu(win)
    assert len(_entries(menu, "beta")) == 2  # Recent and All Profiles
    with mock.patch("ui.main_window.QMessageBox.question", return_value=YES):
        _right_click_delete(win, menu, "beta", monkeypatch, index=0)  # the Recent one
    fresh = _menu(win)
    assert _entries(fresh, "beta") == []
    fresh.close()


def test_edge_an_open_pane_on_the_profile_is_left_alone(win, keyring_deletes) -> None:
    pane = win._active_pane
    profile = win._profile_manager.get("beta")
    win._pane_profiles[pane] = profile
    try:
        with mock.patch("ui.main_window.QMessageBox.question", return_value=YES):
            win._delete_connection_config(profile)
        assert win._profile_manager.get("beta") is None
        assert win._pane_profiles[pane] is profile  # the running connection keeps it
    finally:
        win._pane_profiles.pop(pane, None)
