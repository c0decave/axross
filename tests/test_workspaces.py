"""Workspaces: several named pane layouts in one axross (punch-list item 49).

Operator: *„brauchen support für mehrere "windows" die mehrere panes halten
können sodass wir z.b. auch windows auf andere screens verteilen können, aber
windows sollen auch z.b. hintereinander stackbar sein, sodass man dann in
axross windows tabs hat die man durchschalten kann, bennen kann und in den
windows dann die verschiedenen panes sind, panes sollen dann auch zwischen
windows austauschbar sein"*.

A workspace is a tab (named, renamable, switchable) holding its own pane
layout; it detaches to a window of its own (another screen) and comes back
as a tab when that window closes; panes move between workspaces from the
menu or by dragging them onto a pane of another workspace. The session keeps
all of it.
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
from PyQt6.QtWidgets import QApplication, QMessageBox, QSplitter  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


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


def panes_in(win, ws) -> list:
    return [p for p in win._panes if win.workspace_of(p) is ws]


# -- happy ----------------------------------------------------------------------------


def test_happy_one_workspace_by_default_and_no_tab_bar(window):
    assert names(window) == ["Workspace 1"]
    tabs = window._workspace_tabs
    assert window.centralWidget() is tabs
    assert tabs.tabBarAutoHide() and tabs.tabBar().isHidden()
    assert window._root_splitter is tabs.currentWidget()
    assert len(panes_in(window, window.current_workspace())) == 1


def test_happy_a_new_workspace_is_a_tab_with_its_own_pane(window):
    first = window.current_workspace()
    old_pane = window._active_pane
    ws = window.new_workspace("Logs")
    pump()
    assert names(window) == ["Workspace 1", "Logs"]
    tabs = window._workspace_tabs
    assert tabs.count() == 2 and not tabs.tabBar().isHidden()
    assert tabs.tabText(1) == "Logs" and tabs.currentIndex() == 1
    assert window.current_workspace() is ws
    assert window._root_splitter is ws.root
    (pane,) = panes_in(window, ws)
    assert window._active_pane is pane
    assert panes_in(window, first) == [old_pane]
    # Every path that adds a pane lands in the current workspace now.
    window._add_local_pane()
    assert len(panes_in(window, ws)) == 2 and panes_in(window, first) == [old_pane]


def test_happy_switching_tabs_switches_the_active_pane(window):
    first = window.current_workspace()
    a = window._active_pane
    window.new_workspace("Two")
    b = window._active_pane
    window._workspace_tabs.setCurrentIndex(0)
    pump()
    assert window.current_workspace() is first and window._active_pane is a
    window._workspace_tabs.setCurrentIndex(1)
    pump()
    assert window._active_pane is b
    window.next_workspace()
    assert window.current_workspace() is first
    window.next_workspace(forward=False)
    assert window._active_pane is b


def test_happy_a_workspace_remembers_its_source_and_target(window):
    first = window.current_workspace()
    p1 = window._active_pane
    window._split_pane(Qt.Orientation.Horizontal)
    p2 = next(p for p in panes_in(window, first) if p is not p1)
    window._set_active_pane(p2)
    window._set_target_pane(p1)
    window.new_workspace("Other")
    window.switch_workspace(first)
    assert window._active_pane is p2 and window._target_pane is p1


def test_happy_clicking_a_pane_of_another_workspace_remembers_the_old_one(window):
    first = window.current_workspace()
    window._split_pane(Qt.Orientation.Horizontal)
    a, b = panes_in(window, first)
    window._set_active_pane(b)
    ws = window.new_workspace("Away")
    window.detach_workspace(ws)
    window.switch_workspace(first)
    window._set_active_pane(panes_in(window, ws)[0])  # a click into the detached window
    assert window.current_workspace() is ws
    window.switch_workspace(first)
    assert window._active_pane is b


def test_happy_rename(window):
    ws = window.current_workspace()
    assert window.rename_workspace(ws, "  Project X  ")
    assert ws.name == "Project X"
    assert window._workspace_tabs.tabText(0) == "Project X"


def test_happy_move_a_pane_to_another_workspace(window):
    first = window.current_workspace()
    p1 = window._active_pane
    window._split_pane(Qt.Orientation.Vertical)
    pump()
    p2 = next(p for p in panes_in(window, first) if p is not p1)
    nested = p2.parent()
    assert nested is not first.root
    second = window.new_workspace("B")
    count = len(window._panes)
    assert window.move_pane_to_workspace(p2, second)
    pump()
    assert window.workspace_of(p2) is second and p2.parent() is second.root
    assert len(window._panes) == count
    # The nested splitter that held p1 and p2 collapsed into p1.
    assert p1.parent() is first.root and sip.isdeleted(nested)
    assert window.current_workspace() is second and window._active_pane is p2


def test_happy_move_the_active_pane_into_a_new_workspace(window):
    p1 = window._active_pane
    window._add_local_pane()
    p2 = window._panes[-1]
    window._set_active_pane(p2)
    ws = window.move_active_pane_to_new_workspace()
    assert ws is not None and window.workspace_of(p2) is ws
    assert window.workspace_of(p1) is not ws
    assert names(window) == ["Workspace 1", "Workspace 2"]


def test_happy_detach_puts_the_workspace_on_its_own_window_and_closing_brings_it_back(window):
    window.new_workspace("Away")
    ws = window.current_workspace()
    (pane,) = panes_in(window, ws)
    win = window.detach_workspace(ws)
    pump()
    assert win is not None and win.isVisible() and win.isWindow()
    assert win.centralWidget() is ws.root and ws.window is win
    assert window._workspace_tabs.count() == 1
    assert pane.window() is win
    # A pane in the detached window still reaches the main window's services.
    assert pane.window().open_in_editor == window.open_in_editor
    assert "Away" in win.windowTitle()
    win.close()
    pump()
    assert ws.window is None and window._workspace_tabs.count() == 2
    assert window._workspace_tabs.indexOf(ws.root) == 1
    assert pane.window() is window and pane in window._panes


def test_happy_activating_a_detached_window_makes_it_current(window):
    first = window.current_workspace()
    ws = window.new_workspace("Away")
    window.detach_workspace(ws)
    window.switch_workspace(first)
    assert window.current_workspace() is first
    ws.window.activated()  # what its ActivationChange calls
    assert window.current_workspace() is ws
    assert window.workspace_of(window._active_pane) is ws


def test_happy_drag_a_pane_onto_a_pane_of_another_workspace(window):
    first = window.current_workspace()
    target = window._active_pane
    ws = window.new_workspace("Away")
    window.detach_workspace(ws)
    (source,) = panes_in(window, ws)
    window._on_pane_drop(str(id(source)), target, "right")
    pump()
    assert window.workspace_of(source) is first
    # The emptied workspace and its window are gone.
    assert names(window) == ["Workspace 1"]
    assert ws.window is None


def test_happy_session_round_trip(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    folders = [home / "a", home / "b", home / "c"]
    for f in folders:
        f.mkdir()
    win = _make_window(home)
    try:
        win.show()
        win._active_pane.navigate(str(folders[0]))
        win.rename_workspace(win.current_workspace(), "Main")
        second = win.new_workspace("Second")
        win._active_pane.navigate(str(folders[1]))
        third = win.new_workspace("Floating")
        win._active_pane.navigate(str(folders[2]))
        win.detach_workspace(third)
        win.switch_workspace(second)
        win._save_session()
    finally:
        _destroy(win)
    data = json.loads((home / "session.json").read_text())
    assert [w["name"] for w in data["workspaces"]] == ["Main", "Second", "Floating"]
    assert [w.get("detached", False) for w in data["workspaces"]] == [False, False, True]
    # An older axross reads "splitter": the first workspace.
    assert data["splitter"] == data["workspaces"][0]["splitter"]

    again = _make_window(home)
    try:
        # As main.py starts: restore, then show the window - which takes
        # the focus, so its shown tab is current, not the detached one.
        assert again.restore_layout_on_start()
        again.show()
        pump()
        assert names(again) == ["Main", "Second", "Floating"]
        paths = {ws.name: [p.current_path for p in panes_in(again, ws)] for ws in again.workspaces()}
        assert paths == {"Main": [str(folders[0])], "Second": [str(folders[1])],
                         "Floating": [str(folders[2])]}
        floating = again.workspaces()[2]
        assert floating.window is not None
        assert again._workspace_tabs.count() == 2
        assert again.current_workspace().name == "Second"
    finally:
        _destroy(again)


def test_happy_a_layout_preset_changes_only_the_current_workspace(window, monkeypatch):
    first = window.current_workspace()
    keep = window._active_pane
    ws = window.new_workspace("Presets")
    window.apply_layout_preset("quad-files")
    pump()
    assert keep in window._panes and window.workspace_of(keep) is first
    assert len(panes_in(window, ws)) == 4
    assert window._root_splitter is ws.root is window._workspace_tabs.currentWidget()
    assert window._workspace_tabs.tabText(window._workspace_tabs.currentIndex()) == "Presets"


# -- sad ------------------------------------------------------------------------------


def test_sad_the_last_workspace_cannot_be_closed(window):
    ws = window.current_workspace()
    assert not window.close_workspace(ws, ask=False)
    assert names(window) == ["Workspace 1"]


def test_sad_bad_names_are_refused(window):
    from ui.workspaces import MAX_NAME

    ws = window.current_workspace()
    for bad in ("", "   ", "a\nb", "x" * (MAX_NAME + 1), None):
        assert not window.rename_workspace(ws, bad)
    assert ws.name == "Workspace 1"


def test_sad_moving_a_pane_to_its_own_workspace_does_nothing(window):
    pane = window._active_pane
    assert not window.move_pane_to_workspace(pane, window.current_workspace())
    assert pane.parent() is window._root_splitter


def test_sad_a_closed_workspace_asks_and_no_keeps_it(window, monkeypatch):
    window.new_workspace("Busy")
    ws = window.current_workspace()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    assert not window.close_workspace(ws)
    assert "Busy" in names(window)


@pytest.mark.parametrize(
    "workspaces, why",
    [
        ("nope", "not a list"),
        (["x"], "not an object"),
        ([{"name": 3, "splitter": {}}], "name"),
        ([{"name": "a", "splitter": []}], "object"),
        ([{"name": "a", "splitter": {}}] * 40, "more than"),
    ],
)
def test_sad_a_bad_workspaces_entry_is_refused_before_anything_closes(workspaces, why):
    from ui.main_window import _session_problem

    problem = _session_problem({"splitter": {"children": []}, "workspaces": workspaces})
    assert why in problem


def test_sad_a_legacy_session_restores_into_one_workspace(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    (home / "session.json").write_text(json.dumps({
        "splitter": {"type": "splitter", "orientation": "horizontal", "sizes": [1, 1],
                     "children": [{"type": "pane", "local": True, "path": str(home)},
                                  {"type": "pane", "local": True, "path": str(home)}]},
    }))
    win = _make_window(home)
    try:
        assert win.restore_layout_on_start()
        assert names(win) == ["Workspace 1"] and len(win._panes) == 2
        assert win._workspace_tabs.count() == 1
    finally:
        _destroy(win)


# -- edge -----------------------------------------------------------------------------


def test_edge_closing_a_workspace_closes_its_panes(window, monkeypatch):
    keep = window._active_pane
    ws = window.new_workspace("Gone")
    window._add_local_pane()
    gone = panes_in(window, ws)
    assert len(gone) == 2
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert window.close_workspace(ws)
    pump()
    assert names(window) == ["Workspace 1"]
    assert window._panes == [keep] and window._active_pane is keep
    assert all(sip.isdeleted(p) for p in gone)


def test_edge_closing_the_last_pane_of_a_workspace_closes_the_workspace(window):
    keep = window._active_pane
    ws = window.new_workspace("Short")
    (pane,) = panes_in(window, ws)
    window._close_pane(pane)
    pump()
    assert names(window) == ["Workspace 1"] and window._active_pane is keep


def test_edge_closing_the_main_window_closes_detached_ones_and_keeps_them_detached(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    win.show()
    ws = win.new_workspace("Side")
    side = win.detach_workspace(ws)
    win.close()
    pump()
    try:
        assert not side.isVisible()
        data = json.loads((home / "session.json").read_text())
        assert [w.get("detached", False) for w in data["workspaces"]] == [False, True]
    finally:
        _destroy(win)


def test_edge_the_main_window_keeps_a_workspace_while_another_is_detached(window, monkeypatch):
    """Detach refuses to take the main window's last tab; closing that
    workspace, closing its last pane or moving that pane away must not
    empty the main window either."""
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    first = window.current_workspace()
    side = window.new_workspace("Side")
    window.detach_workspace(side)
    pump()
    assert not window.close_workspace(first)
    assert first in window.workspaces() and window._workspace_tabs.count() == 1

    (pane,) = panes_in(window, first)
    window._close_pane(pane)
    pump()
    assert window._workspace_tabs.count() == 1
    assert first in window.workspaces() and first.window is None
    assert side.window is not None and side.window.isVisible()
    # New panes land in the main window's workspace again once it is current.
    window.switch_workspace(first)
    assert window._root_splitter is first.root is window._workspace_tabs.currentWidget()
    window._add_local_pane()
    assert len(panes_in(window, first)) == 1


def test_edge_moving_the_main_windows_last_pane_away_keeps_its_tab(window):
    first = window.current_workspace()
    side = window.new_workspace("Side")
    window.detach_workspace(side)
    pump()
    (pane,) = panes_in(window, first)
    assert window.move_pane_to_workspace(pane, side)
    pump()
    assert window.workspace_of(pane) is side
    assert window._workspace_tabs.count() == 1 and first in window.workspaces()


def test_e2e_main_window_shortcuts_work_in_a_detached_window(window):
    """A workspace on another screen is worked with the keyboard as the
    main window is: its keys reach the main window's actions."""
    from PyQt6.QtTest import QTest

    window.activateWindow()
    pump(0.2)
    ctrl_alt = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
    ctrl_shift = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
    # Control: the key works in the main window.
    QTest.keyClick(window._active_pane._table, Qt.Key.Key_N, ctrl_alt)
    pump(0.2)
    assert len(window.workspaces()) == 2
    ws = window.current_workspace()
    side = window.detach_workspace(ws)
    side.activateWindow()
    pump(0.2)
    (pane,) = panes_in(window, ws)
    pane._table.setFocus()
    window._set_active_pane(pane)
    pump(0.2)
    assert QApplication.activeWindow() is side
    QTest.keyClick(pane._table, Qt.Key.Key_H, ctrl_shift)  # Split Horizontal
    pump(0.2)
    assert len(panes_in(window, ws)) == 2
    QTest.keyClick(pane._table, Qt.Key.Key_N, ctrl_alt)  # New Workspace
    pump(0.2)
    assert len(window.workspaces()) == 3


def test_edge_a_detached_window_shares_only_the_main_windows_own_keys(window):
    """Window keys, menus and the main toolbar are shared; an action inside
    a pane is not - the detached window's own panes bring theirs, and a
    second owner of the same key would make it ambiguous."""
    from PyQt6.QtGui import QAction, QKeySequence

    from ui.workspaces import window_shortcut_actions

    in_pane = QAction("pane-local", window._active_pane)
    in_pane.setShortcut(QKeySequence("Ctrl+Alt+F9"))
    window._active_pane.addAction(in_pane)
    shared = window_shortcut_actions(window)
    assert in_pane not in shared
    assert window._new_workspace_action in shared  # added to the window
    keys = {a.shortcut().toString() for a in shared}
    assert {"Ctrl+W", "F5", "Ctrl+Shift+H"} <= keys  # Pane menu and main toolbar
    assert len({id(a) for a in shared}) == len(shared)


def test_edge_workspace_count_is_capped(window, monkeypatch):
    from ui import workspaces as WS

    monkeypatch.setattr(WS, "MAX_WORKSPACES", 3)
    assert window.new_workspace() and window.new_workspace()
    assert window.new_workspace() is None
    assert len(window.workspaces()) == 3


def test_edge_default_names_fill_the_lowest_gap(window, monkeypatch):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    two = window.new_workspace()
    window.new_workspace()
    assert names(window) == ["Workspace 1", "Workspace 2", "Workspace 3"]
    window.close_workspace(two)
    assert window.new_workspace().name == "Workspace 2"


def test_edge_extract_pane_works_in_any_workspace(window):
    ws = window.new_workspace("Nest")
    window._split_pane(Qt.Orientation.Horizontal)
    pump()
    nested = next(p for p in panes_in(window, ws) if p.parent() is not ws.root)
    window._set_active_pane(nested)
    window._extract_pane_from_split()
    pump()
    assert nested.parent() is ws.root


def test_edge_workspace_menu_lists_and_moves(window):
    window.new_workspace("Second")
    window._workspace_tabs.setCurrentIndex(0)
    pump()
    menu = window._workspace_menu
    menu.aboutToShow.emit()
    labels = [a.text().replace("&", "") for a in menu.actions()]
    assert "New Workspace" in labels and "Rename Workspace…" in labels
    move = next(a for a in menu.actions() if a.menu() and "Move Pane" in a.text().replace("&", ""))
    move.menu().aboutToShow.emit()
    targets = [a.text() for a in move.menu().actions()]
    assert "Second" in targets and "Workspace 1" not in targets
    pane = window._active_pane
    next(a for a in move.menu().actions() if a.text() == "Second").trigger()
    assert window.workspace_of(pane).name == "Second"


# -- terminal panes move too (operator: "panes sollen dann auch zwischen windows
# austauschbar sein"; the verification round found only file panes moved) -------


def _terminal(window):
    from PyQt6.QtWidgets import QWidget

    from ui.terminal_pane import TerminalPaneWidget

    term = TerminalPaneWidget(label="Local Shell", cwd=str(Path.home()))
    window._terminal_panes.append(term)
    window._root_splitter.addWidget(term)
    term.show()
    return term


def test_happy_a_terminal_pane_moves_to_another_workspace(window):
    first = window.current_workspace()
    term = _terminal(window)
    second = window.new_workspace("Shells")
    assert window.move_pane_to_workspace(term, second)
    pump()
    assert window.workspace_of(term) is second and term.parent() is second.root
    assert term in window._terminal_panes
    assert window.workspace_of(window._panes[0]) is first
    term.shutdown()


def test_happy_the_terminal_header_offers_the_workspaces(window):
    term = _terminal(window)
    window.new_workspace("Other")
    window.switch_workspace(window.workspaces()[0])
    menu = term.workspace_menu()
    menu.aboutToShow.emit()
    labels = [a.text() for a in menu.actions()]
    assert "Other" in labels and "Workspace 1" not in labels and "New Workspace" in labels
    next(a for a in menu.actions() if a.text() == "Other").trigger()
    assert window.workspace_of(term).name == "Other"
    term.shutdown()


def test_happy_the_workspace_menu_moves_a_focused_terminal(window, monkeypatch):
    term = _terminal(window)
    window.new_workspace("Target")
    window.switch_workspace(window.workspaces()[0])
    monkeypatch.setattr(QApplication, "focusWidget", staticmethod(lambda: term._terminal))
    assert window._pane_to_move() is term
    menu = window._workspace_menu
    menu.aboutToShow.emit()
    move = next(a for a in menu.actions() if a.menu() and "Move Pane" in a.text())
    move.menu().aboutToShow.emit()
    next(a for a in move.menu().actions() if a.text() == "Target").trigger()
    assert window.workspace_of(term).name == "Target"
    term.shutdown()


def test_sad_a_foreign_widget_does_not_move(window):
    from PyQt6.QtWidgets import QLabel

    stray = QLabel("x")
    assert not window.move_pane_to_workspace(stray, window.new_workspace("B"))


def test_edge_moving_the_last_terminal_out_closes_its_workspace(window):
    window.new_workspace("Only a shell", with_pane=False)
    ws = window.current_workspace()
    term = _terminal(window)
    assert window.workspace_of(term) is ws
    target = window.workspaces()[0]
    assert window.move_pane_to_workspace(term, target)
    pump()
    assert ws not in window.workspaces() and window.workspace_of(term) is target
    term.shutdown()


def test_e2e_a_moved_terminal_keeps_its_shell_in_a_detached_window(window, tmp_path):
    """Round-2 verification: after moving a running local shell to another
    workspace and detaching that one to its own window, the same shell
    still runs commands (the pty is not lost with the reparenting)."""
    term = window.open_terminal_command(["sh", "-c", f"echo first > '{tmp_path / 'one'}'"],
                                        cwd=str(tmp_path), label="test")
    end = time.time() + 15
    while not (tmp_path / "one").exists() and time.time() < end:
        pump(0.05)
    assert (tmp_path / "one").read_text() == "first\n"
    target = window.new_workspace("Shells")
    assert window.move_pane_to_workspace(term, target)
    window.detach_workspace(target)
    pump(0.2)
    assert target.window is not None and term.window() is target.window
    assert term.run_command(["sh", "-c", f"echo second > '{tmp_path / 'two'}'"])
    end = time.time() + 15
    while not (tmp_path / "two").exists() and time.time() < end:
        pump(0.05)
    assert (tmp_path / "two").read_text() == "second\n"
    term.shutdown()


# -- a pinned terminal captures the keys of the window it is in (bughunt
# 2026-10-22: the pin filter stayed on the window the pane was pinned in, so
# after a detach or a move the main window's keys went on to the terminal
# even after it was unpinned) --------------------------------------------------


def _key_catcher(term) -> list:
    seen: list = []
    term._terminal.keyPressEvent = lambda event: seen.append(event.key())
    return seen


def _press(widget, key=Qt.Key.Key_A) -> None:
    from PyQt6.QtGui import QKeyEvent

    QApplication.sendEvent(
        widget, QKeyEvent(QEvent.Type.KeyPress, key, Qt.KeyboardModifier.NoModifier, "a"))


def test_edge_an_unpinned_terminal_leaves_the_main_window_after_a_detach(window):
    term = _terminal(window)
    ws = window.current_workspace()
    window.new_workspace("Other")
    window.switch_workspace(ws)
    term._btn_pin.setChecked(True)
    detached = window.detach_workspace(ws)
    pump()
    assert detached is not None and term.window() is detached
    term._btn_pin.setChecked(False)
    seen = _key_catcher(term)
    _press(window)
    _press(detached)
    term.shutdown()
    assert seen == []


def test_edge_a_pinned_terminal_moved_away_captures_in_its_new_window_only(window):
    term = _terminal(window)
    other = window.new_workspace("Shells")
    detached = window.detach_workspace(other)
    window.switch_workspace(window.workspaces()[0])
    term._btn_pin.setChecked(True)
    assert window.move_pane_to_workspace(term, other)
    pump()
    assert term.window() is detached
    seen = _key_catcher(term)
    _press(window)  # the main window's keys are its own again
    assert seen == []
    _press(detached)  # the pin holds where the terminal is now
    assert seen == [Qt.Key.Key_A]
    term._btn_pin.setChecked(False)
    _press(detached)
    _press(window)
    term.shutdown()
    assert seen == [Qt.Key.Key_A]


def test_edge_a_pinned_terminal_keeps_its_pin_when_its_window_is_reattached(window):
    term = _terminal(window)
    ws = window.current_workspace()
    window.new_workspace("Other")
    detached = window.detach_workspace(ws)
    pump()
    term._btn_pin.setChecked(True)
    detached.close()  # back as a tab; the window is deleted
    pump(0.1)
    pump(0.05)  # the pin moves on once the window is gone
    assert term.window() is window and term.is_pinned
    seen = _key_catcher(term)
    _press(window)
    assert seen == [Qt.Key.Key_A]
    term._btn_pin.setChecked(False)
    _press(window)
    term.shutdown()
    assert seen == [Qt.Key.Key_A]


def test_edge_a_pinned_terminal_lifted_out_of_its_layout_keeps_the_pin_for_its_window(window):
    term = _terminal(window)
    term._btn_pin.setChecked(True)
    root = term.parent()
    term.setParent(None)  # between two layouts it is a window of its own
    _press(window)
    assert term._pin_window is window  # not moved onto the pane itself
    root.addWidget(term)
    term.show()
    seen = _key_catcher(term)
    _press(window)
    term._btn_pin.setChecked(False)
    term.shutdown()
    assert seen == [Qt.Key.Key_A]


def test_sad_unpinning_a_never_pinned_terminal_changes_nothing(window):
    term = _terminal(window)
    term._toggle_pin(False)  # no filter was installed: nothing to remove, no error
    seen = _key_catcher(term)
    _press(window)
    term.shutdown()
    assert seen == []


# -- a workspace name is shown as typed (bughunt 2026-10-22: "R&D" showed as
# "RD" with an underlined D in the tab, the Workspace menu and the Move Pane
# menus, where "&" marks a mnemonic) -----------------------------------------------


def _shown(text: str) -> str:
    """A tab or menu label as Qt shows it: "&x" is a mnemonic, "&&" one "&"."""
    from PyQt6.QtGui import QAction

    return QAction(text).iconText()


def test_edge_an_ampersand_in_a_workspace_name_is_shown_as_typed(window):
    ws = window.new_workspace("R&D")
    tabs = window._workspace_tabs
    assert _shown(tabs.tabText(tabs.indexOf(ws.root))) == "R&D"
    window.switch_workspace(window.workspaces()[0])
    menu = window._workspace_menu
    menu.aboutToShow.emit()
    assert "R&D" in [_shown(a.text()) for a in menu.actions()]
    move = next(a for a in menu.actions() if a.menu() and "Move Pane" in a.text())
    move.menu().aboutToShow.emit()
    target = next(a for a in move.menu().actions() if _shown(a.text()) == "R&D")
    pane = window._active_pane
    target.trigger()
    assert window.workspace_of(pane) is ws


def test_edge_a_renamed_and_reattached_workspace_keeps_its_ampersand(window):
    ws = window.new_workspace("A")
    assert window.rename_workspace(ws, "Tom & Jerry")
    assert ws.name == "Tom & Jerry"  # the name itself stays as typed
    tabs = window._workspace_tabs
    assert _shown(tabs.tabText(tabs.indexOf(ws.root))) == "Tom & Jerry"
    detached = window.detach_workspace(ws)
    assert detached.windowTitle().startswith("Tom & Jerry")  # titles have no mnemonics
    detached.close()
    pump()
    assert _shown(tabs.tabText(tabs.indexOf(ws.root))) == "Tom & Jerry"


def test_happy_a_plain_workspace_name_is_unchanged(window):
    ws = window.new_workspace("Logs")
    tabs = window._workspace_tabs
    assert tabs.tabText(tabs.indexOf(ws.root)) == "Logs"


# -- a new terminal lands in the workspace on screen (bughunt 2026-10-22: in a
# workspace without file panes the active file pane is in another workspace,
# and a terminal bookmark or Open Shell put the new shell beside it - into a
# workspace that was not shown, so nothing seemed to happen) ------------------------


def _terminal_only_workspace(window):
    first = window.current_workspace()
    term = _terminal(window)
    ws = window.move_active_pane_to_new_workspace(term)
    assert ws is not None and window.current_workspace() is ws
    assert window.workspace_of(window._active_pane) is first  # the source stays there
    return first, ws, term


def test_edge_a_terminal_bookmark_opens_in_the_shown_workspace(window, home):
    from core.bookmarks import KIND_TERMINAL, LOCAL_SHELL, Bookmark

    first, ws, term = _terminal_only_workspace(window)
    bookmark = Bookmark(name="here", path=str(home), backend_name="Local",
                        profile_name=LOCAL_SHELL, kind=KIND_TERMINAL)
    opened = window._open_terminal_bookmark(bookmark)
    pump()
    assert opened is not None and window.workspace_of(opened) is ws
    assert opened.isVisible()
    opened.shutdown()
    term.shutdown()


def test_edge_open_shell_in_a_terminal_only_workspace_opens_there(window):
    first, ws, term = _terminal_only_workspace(window)
    before = list(window._terminal_panes)
    window._open_shell_pane()  # only the local shell is offered: opens at once
    pump()
    (new,) = [t for t in window._terminal_panes if t not in before]
    assert window.workspace_of(new) is ws
    new.shutdown()
    term.shutdown()


def test_happy_a_terminal_bookmark_still_opens_beside_the_active_pane(window, home):
    from core.bookmarks import KIND_TERMINAL, LOCAL_SHELL, Bookmark

    pane = window._active_pane
    bookmark = Bookmark(name="here", path=str(home), backend_name="Local",
                        profile_name=LOCAL_SHELL, kind=KIND_TERMINAL)
    opened = window._open_terminal_bookmark(bookmark)
    pump()
    assert opened.parent() is pane.parent()  # split beside it, as before
    assert window.workspace_of(opened) is window.current_workspace()
    opened.shutdown()


def _renders_as_rich_text(text: str) -> bool:
    from PyQt6.QtWidgets import QLabel

    auto, plain, rich = QLabel(text), QLabel(text), QLabel(text)
    auto.setTextFormat(Qt.TextFormat.AutoText)
    plain.setTextFormat(Qt.TextFormat.PlainText)
    rich.setTextFormat(Qt.TextFormat.RichText)
    return auto.sizeHint() == rich.sizeHint() and auto.sizeHint() != plain.sizeHint()


def test_sad_markup_in_a_workspace_name_is_not_rendered_in_the_close_question(
        window, monkeypatch):
    """Bughunt 2026-10-22: the name stood in the first line of the question,
    where a message box renders markup."""
    assert _renders_as_rich_text("Close the workspace '<b>Loud</b>' and its 1 panes?")  # control
    ws = window.new_workspace("<b>Loud</b> & Co")
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda _p, _t, text, *a, **k: asked.append(text)
                        or QMessageBox.StandardButton.No)
    assert not window.close_workspace(ws)
    (text,) = asked
    assert "<b>Loud</b> & Co" in text and not _renders_as_rich_text(text)
    assert "1 panes" in text or "1 pane" in text
