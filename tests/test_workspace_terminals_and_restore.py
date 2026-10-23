"""Workspaces with terminals, renamed, and back after a restart.

Operator:

* *„wenn man einen neuen workspace hat soll nicht nur open filelist machen
  können sondern auch terminal zur auswahl stehen, sodass man z.b. mehrere
  shells im neuen workspace hat."* - Workspace > New Workspace offers a file
  list or a terminal; Add Terminal Pane puts another local shell into the
  workspace on screen, side by side.
* *„die workspaces sollen auch namen haben können durch z.b. umbennen und
  ebenfalls restored werden bei neustart."* - renaming is reachable from the
  menu, a double-click on the tab and the tab's context menu; the session
  keeps names, order, the current workspace (also one that holds only
  terminals, which came back as the first workspace instead), the panes and
  terminals with their folders, and detached windows - never a password.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait_until(predicate, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def _make_window(home: Path):
    from ui import main_window as MW

    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    return win


def _destroy(win) -> None:
    if win is None or sip.isdeleted(win):
        return
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def home():
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def window(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    win.show()
    yield win
    _destroy(win)


def names(win) -> list[str]:
    return [ws.name for ws in win.workspaces()]


def files_in(win, ws) -> list:
    return win._widgets_of(ws)[0]


def terms_in(win, ws) -> list:
    return win._widgets_of(ws)[1]


def _same_dir(a, b) -> bool:
    return a is not None and os.path.realpath(a) == os.path.realpath(b)


def _menu_action(menu: QMenu, text: str):
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"{text!r} not in {[a.text() for a in menu.actions()]}")


# -- item 2: a terminal in a new workspace ----------------------------------------------


def test_happy_a_new_workspace_with_a_terminal_holds_one_local_shell(window, home):
    from ui.workspaces import START_TERMINAL

    folder = home / "work"
    folder.mkdir()
    window._active_pane.navigate(str(folder))
    ws = window.new_workspace("Shells", start=START_TERMINAL)
    assert ws is not None and window.current_workspace() is ws
    assert files_in(window, ws) == []
    (term,) = terms_in(window, ws)
    assert term.is_local and term.isVisible()
    # The shell starts in the folder the active (local) pane showed.
    assert wait_until(lambda: _same_dir(term.working_directory(), folder))


def test_happy_add_terminal_pane_gives_a_workspace_several_shells(window):
    from ui.workspaces import START_TERMINAL

    ws = window.new_workspace("Shells", start=START_TERMINAL)
    second = window.add_terminal_pane()
    third = window.add_terminal_pane(ws)
    assert second is not None and third is not None
    assert terms_in(window, ws)[-2:] == [second, third]
    assert len(terms_in(window, ws)) == 3
    assert all(t.parent() is ws.root for t in terms_in(window, ws))  # side by side


def test_e2e_the_workspace_menu_offers_a_file_list_or_a_terminal(window):
    menu = window._workspace_menu
    new = _menu_action(menu, "New Workspace").menu()
    assert new is not None
    _menu_action(new, "With Terminal").trigger()
    ws = window.current_workspace()
    assert len(terms_in(window, ws)) == 1 and files_in(window, ws) == []
    _menu_action(menu, "Add Terminal Pane").trigger()
    assert len(terms_in(window, ws)) == 2
    _menu_action(new, "With File List").trigger()
    other = window.current_workspace()
    assert other is not ws and len(files_in(window, other)) == 1
    assert terms_in(window, other) == []
    assert len(window.workspaces()) == 3


def test_e2e_a_key_opens_a_new_workspace_with_a_terminal(window):
    window.activateWindow()
    pump(0.2)
    keys = (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
            | Qt.KeyboardModifier.ShiftModifier)
    QTest.keyClick(window._active_pane._table, Qt.Key.Key_N, keys)
    pump(0.2)
    assert len(window.workspaces()) == 2
    ws = window.current_workspace()
    assert len(terms_in(window, ws)) == 1 and files_in(window, ws) == []


def test_happy_the_tab_menu_offers_the_terminal_entries(window):
    window.new_workspace("Second")
    pump()
    seen: list[str] = []

    def fake_exec(menu, *_args):
        for action in menu.actions():
            seen.append(action.text().replace("&", ""))
            if action.menu() is not None:
                seen.extend("> " + a.text().replace("&", "") for a in action.menu().actions())
        return None

    bar = window._workspace_tabs.tabBar()
    with mock.patch.object(QMenu, "exec", fake_exec):
        window._show_workspace_tab_menu(bar.tabRect(1).center())
    assert "Add Terminal Pane" in seen
    assert "> With File List" in seen and "> With Terminal" in seen


def test_edge_add_terminal_pane_on_a_background_tab_lands_there_and_shows_it(window):
    first = window.current_workspace()
    second = window.new_workspace("Second")
    window.switch_workspace(first)
    pump()

    def fake_exec(menu, *_args):
        next(a for a in menu.actions()
             if a.text().replace("&", "") == "Add Terminal Pane").trigger()

    bar = window._workspace_tabs.tabBar()
    with mock.patch.object(QMenu, "exec", fake_exec):
        window._show_workspace_tab_menu(bar.tabRect(1).center())
    pump()
    assert len(terms_in(window, second)) == 1 and terms_in(window, first) == []
    assert window.current_workspace() is second
    assert window._workspace_tabs.currentWidget() is second.root
    # The shared New Workspace submenu outlived the tab menu.
    new = _menu_action(window._workspace_menu, "New Workspace").menu()
    _menu_action(new, "With Terminal").trigger()
    assert len(window.workspaces()) == 3


def test_sad_an_unknown_start_kind_is_refused_before_anything_is_made(window):
    with pytest.raises(ValueError):
        window.new_workspace("Odd", start="browser")
    assert names(window) == ["Workspace 1"]
    assert window._terminal_panes == []


def test_sad_at_the_ceiling_a_terminal_workspace_starts_no_shell(window, monkeypatch):
    from ui import workspaces as WS

    monkeypatch.setattr(WS, "MAX_WORKSPACES", 1)
    assert window.new_workspace(start=WS.START_TERMINAL) is None
    assert window._terminal_panes == []


def test_sad_a_terminal_for_a_workspace_that_is_gone_is_refused(window):
    from PyQt6.QtWidgets import QSplitter

    from ui.workspaces import Workspace

    stranger = Workspace("Stranger", QSplitter())
    assert window.add_terminal_pane(stranger) is None
    assert window._terminal_panes == []


def test_edge_a_terminal_workspace_starts_at_home_when_the_pane_folder_is_gone(window, home):
    from ui.workspaces import START_TERMINAL

    gone = home / "gone"
    gone.mkdir()
    window._active_pane.navigate(str(gone))
    gone.rmdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        ws = window.new_workspace(start=START_TERMINAL)
    (term,) = terms_in(window, ws)
    assert wait_until(lambda: _same_dir(term.working_directory(), home))


def test_edge_add_terminal_pane_in_a_detached_workspace_lands_in_its_window(window):
    from ui.workspaces import START_TERMINAL

    ws = window.new_workspace("Side", start=START_TERMINAL)
    side = window.detach_workspace(ws)
    assert side is not None
    term = window.add_terminal_pane(ws)
    assert term.window() is side and len(terms_in(window, ws)) == 2


def test_edge_the_shells_share_the_width_evenly(window):
    from ui.workspaces import START_TERMINAL

    window.resize(1200, 700)
    ws = window.new_workspace("Shells", start=START_TERMINAL)
    window.add_terminal_pane()
    window.add_terminal_pane()
    pump(0.3)
    sizes = ws.root.sizes()
    assert len(sizes) == 3 and min(sizes) > 0
    assert max(sizes) - min(sizes) <= 2


# -- item 3: rename reachable -----------------------------------------------------------


def test_e2e_a_double_click_on_a_workspace_tab_renames_it(window):
    window.new_workspace("Second")
    pump()
    bar = window._workspace_tabs.tabBar()
    assert bar.isVisible()
    with mock.patch("ui.workspaces.QInputDialog.getText", return_value=("Logs", True)) as ask:
        QTest.mouseDClick(bar, Qt.MouseButton.LeftButton, pos=bar.tabRect(1).center())
    ask.assert_called_once()
    assert names(window) == ["Workspace 1", "Logs"]
    assert bar.tabText(1) == "Logs"


def test_e2e_the_tab_menu_renames(window):
    window.new_workspace("Second")
    pump()

    def fake_exec(menu, *_args):
        next(a for a in menu.actions() if a.text().replace("&", "") == "Rename…").trigger()

    bar = window._workspace_tabs.tabBar()
    with mock.patch.object(QMenu, "exec", fake_exec), \
            mock.patch("ui.workspaces.QInputDialog.getText", return_value=("Build", True)):
        window._show_workspace_tab_menu(bar.tabRect(0).center())
    assert names(window) == ["Build", "Second"]


def test_happy_the_workspace_menu_renames_the_current_one(window):
    with mock.patch("ui.workspaces.QInputDialog.getText", return_value=("Main", True)):
        _menu_action(window._workspace_menu, "Rename Workspace…").trigger()
    assert names(window) == ["Main"]


def test_sad_a_blank_name_is_refused_and_said_so(window):
    with mock.patch("ui.workspaces.QInputDialog.getText", return_value=("   ", True)), \
            mock.patch("ui.workspaces.QMessageBox.information") as told:
        window._ask_rename_workspace()
    told.assert_called_once()
    assert names(window) == ["Workspace 1"]


# -- item 3: back after a restart -------------------------------------------------------


def _build_session(win, home):
    """Main (file pane), Shells (two terminals, current), Logs (detached file
    pane) - and the tabs moved: Shells first."""

    (home / "main").mkdir()
    (home / "t1").mkdir()
    (home / "t2").mkdir()
    (home / "logs").mkdir()
    win._active_pane.navigate(str(home / "main"))
    win.rename_workspace(win.current_workspace(), "Main")
    logs = win.new_workspace("Logs")
    win._active_pane.navigate(str(home / "logs"))
    shells = win.new_workspace("Shells", with_pane=False)
    win.add_terminal_pane(shells, cwd=str(home / "t1"))
    win.add_terminal_pane(shells, cwd=str(home / "t2"))
    win.detach_workspace(logs)
    bar = win._workspace_tabs.tabBar()
    bar.moveTab(bar.count() - 1, 0)  # Shells before Main
    assert all(wait_until(lambda t=t: t.working_directory()) for t in terms_in(win, shells))
    # Worked in last: Shells (the detached window took the focus meanwhile).
    win.activateWindow()
    win.switch_workspace(shells)
    pump(0.2)
    assert win.current_workspace() is shells
    return shells


def test_happy_workspaces_come_back_after_a_restart(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    try:
        win.show()
        _build_session(win, home)
        assert win.close()  # the real close: closeEvent saves the session
        pump()
    finally:
        _destroy(win)
    data = json.loads((home / "session.json").read_text())
    assert [w["name"] for w in data["workspaces"]] == ["Shells", "Main", "Logs"]
    assert [w.get("current", False) for w in data["workspaces"]] == [True, False, False]

    again = _make_window(home)
    try:
        assert again.restore_layout_on_start()
        again.show()
        pump(0.2)
        assert names(again) == ["Shells", "Main", "Logs"]
        shells, main, logs = again.workspaces()
        assert again.current_workspace() is shells
        assert again._workspace_tabs.currentWidget() is shells.root
        cwds = [t.working_directory() for t in terms_in(again, shells)]
        assert len(cwds) == 2
        assert wait_until(lambda: all(t.working_directory() for t in terms_in(again, shells)))
        cwds = [t.working_directory() for t in terms_in(again, shells)]
        assert _same_dir(cwds[0], home / "t1") and _same_dir(cwds[1], home / "t2")
        assert [p.current_path for p in files_in(again, main)] == [str(home / "main")]
        assert logs.window is not None and logs.window.isVisible()
        assert [p.current_path for p in files_in(again, logs)] == [str(home / "logs")]
    finally:
        _destroy(again)


def test_edge_a_current_workspace_of_terminals_only_is_current_again(home, monkeypatch):
    """Found while verifying: the active file pane lives in another
    workspace, and the restore made that one current."""
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    try:
        win.show()
        ws = win.new_workspace("Shells", with_pane=False)
        ws.root.addWidget(win._preset_make_terminal_pane("local", cwd=str(home)))
        assert win.current_workspace() is ws
        win._save_session()
    finally:
        _destroy(win)
    again = _make_window(home)
    try:
        assert again.restore_layout_on_start()
        again.show()
        pump(0.2)
        assert again.current_workspace().name == "Shells"
        assert again._workspace_tabs.currentWidget() is again.current_workspace().root
        # The active file pane is still the one of the other workspace.
        assert again.workspace_of(again._active_pane).name == "Workspace 1"
    finally:
        _destroy(again)


def test_sad_an_old_session_with_terminals_and_without_workspaces_loads(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    (home / "session.json").write_text(json.dumps({
        "splitter": {"type": "splitter", "orientation": "horizontal", "sizes": [1, 1],
                     "children": [{"type": "pane", "local": True, "path": str(home)},
                                  {"type": "terminal", "local": True, "cwd": str(home)}]},
    }))
    win = _make_window(home)
    try:
        assert win.restore_layout_on_start()
        assert names(win) == ["Workspace 1"]
        ws = win.current_workspace()
        assert len(files_in(win, ws)) == 1 and len(terms_in(win, ws)) == 1
    finally:
        _destroy(win)


def test_edge_no_password_reaches_the_session_and_remote_panes_wait_for_reconnect(
        home, monkeypatch):
    from core.profiles import ConnectionProfile
    from ui import main_window as MW
    from ui.disconnected_pane import DisconnectedPanePlaceholder

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    try:
        win.show()
        ws = win.new_workspace("Remote")
        (pane,) = files_in(win, ws)
        win._pane_profiles[pane] = ConnectionProfile(name="srv", protocol="sftp", host="h")
        win._pane_passwords[pane] = "pw-never-on-disk"
        win._save_session()
        text = (home / "session.json").read_text()
        win._pane_profiles.pop(pane, None)
        win._pane_passwords.pop(pane, None)
    finally:
        _destroy(win)  # saves again, without the fake profile
    assert "pw-never-on-disk" not in text
    entry = next(w for w in json.loads(text)["workspaces"] if w["name"] == "Remote")
    assert entry["splitter"]["children"][0]["profile"] == "srv"
    (home / "session.json").write_text(text)
    again = _make_window(home)
    try:
        assert again.restore_layout_on_start()
        remote = next(w for w in again.workspaces() if w.name == "Remote")
        holders = again._widgets_of(remote)[2]
        assert len(holders) == 1 and isinstance(holders[0], DisconnectedPanePlaceholder)
    finally:
        _destroy(again)
