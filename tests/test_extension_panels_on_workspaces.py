"""Extension panels on workspaces: a panel an extension adds belongs to one
workspace and is laid out there like a pane - or, as before and by default,
to all of them (the window's dock area).

Operator: *„es soll möglich sein extensions auf workspaces zu packen und dort
wie panes zu behandeln, aktuell sind extensios immer auf jedem workspace und
equlizer wird auhc nicht beachtet."*

Before, ``ExtensionAPI.add_dock`` put every panel into the main window's
right dock area, so it showed on every workspace and never went along with
a detached one. Now a panel moves to a workspace from its title bar (Move to
Workspace > <name> / New Workspace / All Workspaces) or from a workspace's
Add Extension Panel menu; there it sits in the workspace's splitters like a
pane (drag it, drop panes on it, resize it, close it), hides with its
workspace, goes along with a detached one and comes back there after a
restart. Closing the workspace parks the panel (the extension keeps its
state); switching the extension off takes it out of the workspace and
switching it on again puts it back.

"equalizer wird auch nicht beachtet": Pane > Equalize Pane Sizes (and its
toolbar button) evened out the layout of the active *file* pane, which in a
workspace holding only terminals or extension panels is another workspace,
one not on screen - the workspace on screen stayed as it was.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent, QMimeData, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QDragEnterEvent, QDropEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDockWidget,
    QMenu,
    QMessageBox,
    QSplitter,
)

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

PANEL = """
from PyQt6.QtWidgets import QLabel

def activate(api):
    label = QLabel("panel body")
    label.setObjectName("panel-body")
    api.add_dock("Panel", label)
"""

TWO_PANELS = """
from PyQt6.QtWidgets import QLabel

def activate(api):
    api.add_dock("First", QLabel("first"))
    api.add_dock("Second", QLabel("second"))
"""


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait(cond, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def write_ext(name: str, body: str) -> Path:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(
        f'EXTENSION = {{"name": "{name.title()}", "version": "1.0", "description": "test"}}\n\n'
        + textwrap.dedent(body)
    )
    return path


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


def new_window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1200, 800)
    win.show()
    pump()
    return win


def close_window(win) -> None:
    if win is None or sip.isdeleted(win):
        return
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def window():
    win = new_window()
    yield win
    close_window(win)


def load_panel(win, name: str = "panel", body: str = PANEL):
    write_ext(name, body)
    EX.set_enabled(f"user:{name}", True)
    host = win.extension_host
    host.set_enabled(f"user:{name}", True)
    docks = host.docks(f"user:{name}")
    assert docks, host.error(f"user:{name}")
    return docks[0] if len(docks) == 1 else docks


def in_layout(win, dock) -> bool:
    """*dock* sits in a workspace's splitters, not in the dock area."""
    return isinstance(dock.parentWidget(), QSplitter)


def menu_texts(menu: QMenu) -> list[str]:
    menu.aboutToShow.emit()
    return [a.text().replace("&", "") for a in menu.actions() if not a.isSeparator()]


def menu_action(menu: QMenu, text: str):
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"{text!r} not in {[a.text() for a in menu.actions()]}")


def two_workspaces(win):
    a = win.current_workspace()
    b = win.new_workspace("B")
    pump()
    win.switch_workspace(a)
    pump()
    return a, b


# -- the default stays as it was ------------------------------------------------------------


def test_happy_a_panel_is_on_all_workspaces_by_default(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    dock.show()
    pump()
    assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    assert window.extension_panel_workspace(dock) is None
    assert dock.isVisible()
    window.switch_workspace(b)
    pump()
    assert dock.isVisible()  # all workspaces: as before
    assert dock.features() & QDockWidget.DockWidgetFeature.DockWidgetFloatable


# -- moving a panel to a workspace -------------------------------------------------------------


def test_happy_a_panel_moved_to_a_workspace_shows_only_there_like_a_pane(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    assert window.move_extension_panel(dock, b)
    pump()
    assert in_layout(window, dock)
    assert window.workspace_of(dock) is b and window.extension_panel_workspace(dock) is b
    assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.NoDockWidgetArea
    # Moving it shows that workspace, with the panel.
    assert window.current_workspace() is b and dock.isVisible()
    window.switch_workspace(a)
    pump()
    assert not dock.isVisible()
    window.switch_workspace(b)
    pump()
    assert dock.isVisible()
    # A pane does not float: the float button and the double-click are off.
    assert not dock.features() & QDockWidget.DockWidgetFeature.DockWidgetFloatable
    assert dock.titleBarWidget().pane_mode


def test_e2e_the_title_bar_menu_moves_a_panel_to_a_workspace_and_back(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    dock.show()
    pump()
    bar = dock.titleBarWidget()
    button = bar.move_button
    assert button.isVisible() and button.toolTip() == "Move to Workspace"
    menu = bar.move_menu
    texts = menu_texts(menu)
    assert texts[:2] == ["Workspace 1", "B"]
    assert "New Workspace" in texts and "All Workspaces" in texts
    assert menu_action(menu, "All Workspaces").isChecked()

    def pick(text):
        def fake_exec(m, *_args):
            menu_action(m, text).trigger()
        return fake_exec

    # A click on the button opens the menu; picking "B" moves the panel.
    with mock.patch.object(QMenu, "exec", pick("B")):
        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    pump()
    assert window.extension_panel_workspace(dock) is b
    assert menu_action(menu, "B").isChecked()
    menu_action(menu, "All Workspaces").trigger()
    pump()
    assert window.extension_panel_workspace(dock) is None
    assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    assert dock.isVisible() and not in_layout(window, dock)
    assert dock.features() & QDockWidget.DockWidgetFeature.DockWidgetFloatable
    assert not bar.pane_mode


def test_e2e_the_title_bar_right_click_menu_offers_the_same(window):
    dock = load_panel(window)
    two_workspaces(window)
    dock.show()
    pump()
    seen: list[str] = []

    def fake_exec(menu, *_args):
        for action in menu.actions():
            seen.append(action.text().replace("&", ""))
            if action.menu() is not None:
                action.menu().aboutToShow.emit()
                seen.extend("> " + a.text().replace("&", "") for a in action.menu().actions())

    bar = dock.titleBarWidget()
    with mock.patch.object(QMenu, "exec", fake_exec):
        bar.show_context_menu(QPoint(5, 5))
    assert "Move to Workspace" in seen
    assert "> B" in seen and "> All Workspaces" in seen and "> New Workspace" in seen


def test_e2e_the_workspace_tab_menu_adds_an_extension_panel(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)

    def fake_exec(menu, *_args):
        add = menu_action(menu, "Add Extension Panel").menu()
        menu_action(add, "Panel").trigger()

    bar = window._workspace_tabs.tabBar()
    with mock.patch.object(QMenu, "exec", fake_exec):
        window._show_workspace_tab_menu(bar.tabRect(1).center())
    pump()
    assert window.extension_panel_workspace(dock) is b and window.current_workspace() is b


def test_happy_the_workspace_menu_adds_an_extension_panel_to_the_one_on_screen(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.switch_workspace(b)
    window._fill_workspace_menu()
    add = menu_action(window._workspace_menu, "Add Extension Panel").menu()
    assert menu_texts(add) == ["Panel"]
    menu_action(add, "Panel").trigger()
    pump()
    assert window.extension_panel_workspace(dock) is b


def test_happy_new_workspace_from_the_title_bar(window):
    dock = load_panel(window)
    dock.show()
    menu = dock.titleBarWidget().move_menu
    menu_action(menu, "New Workspace").trigger()
    pump()
    ws = window.extension_panel_workspace(dock)
    assert ws is not None and ws.name == "Workspace 2" and window.current_workspace() is ws
    # The new workspace holds the panel only - and stays (it is not empty).
    assert ws in window.workspaces() and window._widgets_of(ws) == ([], [], [])


def test_happy_panes_drop_on_the_panel_and_the_panel_drops_on_panes(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    # A file pane dropped below the panel: they share a vertical splitter.
    window._on_pane_drop(str(id(pane)), dock, "bottom")
    pump()
    parent = dock.parentWidget()
    assert parent is pane.parentWidget()
    assert parent.orientation() == Qt.Orientation.Vertical
    assert [parent.widget(i) for i in range(parent.count())] == [dock, pane]
    # The panel dragged onto a pane of workspace A: it moves there.
    a_pane = window._widgets_of(a)[0][0]
    window._on_pane_drop(str(id(dock)), a_pane, "left")
    pump()
    assert window.workspace_of(dock) is a
    assert dock.parentWidget() is a_pane.parentWidget()
    assert dock.parentWidget().indexOf(dock) == 0


def test_e2e_a_pane_drag_over_a_panel_on_a_workspace_is_taken(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    from ui.pane_drag import PANE_MIME_TYPE

    mime = QMimeData()
    mime.setData(PANE_MIME_TYPE, str(id(pane)).encode("ascii"))
    pos = QPointF(dock.width() - 5, dock.height() / 2)
    enter = QDragEnterEvent(pos.toPoint(), Qt.DropAction.MoveAction, mime,
                            Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(dock, enter)
    assert enter.isAccepted()
    drop = QDropEvent(pos, Qt.DropAction.MoveAction, mime, Qt.MouseButton.LeftButton,
                      Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(dock, drop)
    pump()
    parent = dock.parentWidget()
    assert parent is pane.parentWidget() and parent.indexOf(pane) == 1


def test_edge_a_docked_panel_takes_no_pane_drag(window):
    dock = load_panel(window)
    dock.show()
    pump()
    from ui.pane_drag import PANE_MIME_TYPE

    mime = QMimeData()
    mime.setData(PANE_MIME_TYPE, str(id(window._active_pane)).encode("ascii"))
    enter = QDragEnterEvent(QPoint(5, 5), Qt.DropAction.MoveAction, mime,
                            Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(dock, enter)
    assert not enter.isAccepted()


def test_happy_the_panel_resizes_and_equalizes_like_a_pane(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump(0.2)
    root = b.root
    assert root.count() == 2
    root.setSizes([900, 200])
    pump()
    before = root.sizes()
    assert before[0] > before[1] * 2
    window._equalize_action.trigger()
    pump()
    sizes = root.sizes()
    assert abs(sizes[0] - sizes[1]) <= 6, sizes


def test_edge_a_workspace_with_only_the_panel_is_not_closed_but_goes_when_it_leaves(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    (pane,) = window._widgets_of(b)[0]
    window.move_extension_panel(dock, b)
    window._close_pane(pane)
    pump()
    assert b in window.workspaces()  # the panel keeps it open
    window.move_extension_panel(dock, a)
    pump()
    assert b not in window.workspaces()  # empty now: closed like after its last pane


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_workspace_that_is_gone_or_no_panel_is_refused(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    from ui.workspaces import Workspace

    stranger = Workspace("Stranger", QSplitter())
    assert not window.move_extension_panel(dock, stranger)
    assert window.extension_panel_workspace(dock) is None
    assert not window.move_extension_panel(window._active_pane, b)  # a file pane is no panel
    assert not window.move_extension_panel(None, b)
    assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea


def test_edge_moving_to_the_workspace_it_is_on_changes_nothing(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    assert window.move_extension_panel(dock, b)
    pump()
    parent = dock.parentWidget()
    assert not window.move_extension_panel(dock, b)
    assert dock.parentWidget() is parent
    assert not window.move_extension_panel(window.extension_panels()[0], b)
    assert window.move_extension_panel(dock, None)
    assert not window.move_extension_panel(dock, None)  # on all workspaces already


def test_sad_a_session_with_a_bad_panel_entry_is_refused(window, own_home):
    from ui.main_window import _session_problem

    def session(node):
        return {"workspaces": [{"name": "A", "splitter": {
            "type": "splitter", "children": [node]}}]}

    assert _session_problem(session({"type": "extension", "panel": "x"})) == ""
    assert "panel" in _session_problem(session({"type": "extension", "panel": 7}))
    assert "panel" in _session_problem(session({"type": "extension"}))
    assert "panel" in _session_problem(session({"type": "extension", "panel": "x" * 5000}))


def test_sad_an_unknown_panel_in_a_session_is_skipped_and_the_rest_restores(own_home):
    (own_home / "session.json").write_text(json.dumps({"workspaces": [
        {"name": "A", "splitter": {"type": "splitter", "sizes": [500, 500], "children": [
            {"type": "pane", "local": True, "path": str(own_home)},
            {"type": "extension", "panel": "extension-dock-user:nothere-0"}]}, "current": True},
    ]}))
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        (ws,) = win.workspaces()
        assert ws.name == "A" and ws.root.count() == 1 and len(win._panes) == 1
    finally:
        close_window(win)


def test_edge_a_panel_named_twice_in_a_session_is_placed_once(own_home):
    write_ext("panel", PANEL)
    EX.set_enabled("user:panel", True)
    name = "extension-dock-user:panel-0"
    (own_home / "session.json").write_text(json.dumps({"workspaces": [
        {"name": "A", "splitter": {"type": "splitter", "children": [
            {"type": "pane", "local": True, "path": str(own_home)}]}, "current": True},
        {"name": "B", "splitter": {"type": "splitter", "children": [
            {"type": "extension", "panel": name},
            {"type": "pane", "local": True, "path": str(own_home)},
            {"type": "extension", "panel": name}]}},
    ]}))
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        (dock,) = win.extension_host.docks("user:panel")
        b = win.workspaces()[1]
        assert win.extension_panel_workspace(dock) is b
        assert b.root.count() == 2 and b.root.indexOf(dock) == 0
    finally:
        close_window(win)


# -- session -----------------------------------------------------------------------------------


def test_happy_after_a_restart_the_panel_is_back_on_its_workspace_at_its_place(own_home):
    win = new_window()
    try:
        dock = load_panel(win)
        a, b = two_workspaces(win)
        win.move_extension_panel(dock, b)
        pump()
        (pane,) = win._widgets_of(b)[0]
        win._on_pane_drop(str(id(dock)), pane, "left")  # [panel | pane] nested
        pump(0.2)
        holder = dock.parentWidget()
        holder.setSizes([300, 700])
        pump()
        sizes = holder.sizes()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    names = json.dumps(data["workspaces"][1])
    assert '"type": "extension"' in names and "extension-dock-user:panel-0" in names

    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump(0.2)
        (dock,) = win.extension_host.docks("user:panel")
        a, b = win.workspaces()
        assert win.extension_panel_workspace(dock) is b
        holder = dock.parentWidget()
        assert holder.indexOf(dock) == 0 and holder.count() == 2
        assert isinstance(holder.widget(1), type(win._active_pane))
        win.switch_workspace(b)
        pump()
        got = holder.sizes()
        assert abs(got[0] / sum(got) - sizes[0] / sum(sizes)) < 0.05, (got, sizes)
        assert dock.isVisible() and dock.titleBarWidget().pane_mode
    finally:
        close_window(win)


def test_happy_a_detached_workspace_takes_its_panel_along_and_after_a_restart(own_home):
    win = new_window()
    try:
        dock = load_panel(win)
        a, b = two_workspaces(win)
        win.move_extension_panel(dock, b)
        pump()
        window = win.detach_workspace(b)
        pump()
        assert window is not None and window.isAncestorOf(dock) and dock.isVisible()
        assert win.extension_panel_workspace(dock) is b
        # Moved away and back while detached.
        win.move_extension_panel(dock, None)
        assert not window.isAncestorOf(dock)
        win.move_extension_panel(dock, b)
        pump()
        assert window.isAncestorOf(dock)
    finally:
        close_window(win)
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        (dock,) = win.extension_host.docks("user:panel")
        b = win.workspaces()[1]
        assert b.window is not None and b.window.isAncestorOf(dock)
    finally:
        close_window(win)


def test_edge_a_panel_on_all_workspaces_stays_there_after_a_restart(own_home):
    win = new_window()
    try:
        dock = load_panel(win)
        dock.show()
        two_workspaces(win)
    finally:
        close_window(win)
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        (dock,) = win.extension_host.docks("user:panel")
        assert win.extension_panel_workspace(dock) is None
        assert win.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    finally:
        close_window(win)


# -- switching the extension off and on ------------------------------------------------------


def test_happy_switching_the_extension_off_takes_the_panel_out_and_on_puts_it_back(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    window._on_pane_drop(str(id(dock)), pane, "left")
    pump()
    host = window.extension_host
    host.set_enabled("user:panel", False)
    pump()
    assert sip.isdeleted(dock)
    assert b in window.workspaces()
    # Only the pane is left - in the root, no splitter holding a single child.
    assert b.root.count() == 1 and b.root.widget(0) is pane
    host.set_enabled("user:panel", True)
    pump()
    (dock,) = host.docks("user:panel")
    assert window.extension_panel_workspace(dock) is b
    assert dock.parentWidget().indexOf(dock) == 0


def test_happy_reload_keeps_the_panel_on_its_workspace(window):
    load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(window.extension_host.docks("user:panel")[0], b)
    pump()
    window.extension_host.reload()
    pump()
    (dock,) = window.extension_host.docks("user:panel")
    assert window.extension_panel_workspace(dock) is b


def test_edge_a_panel_of_a_switched_off_extension_keeps_its_place_over_a_restart(own_home):
    win = new_window()
    try:
        dock = load_panel(win)
        a, b = two_workspaces(win)
        win.move_extension_panel(dock, b)
        pump()
        (pane,) = win._widgets_of(b)[0]
        win._on_pane_drop(str(id(dock)), pane, "top")  # nested: [panel / pane]
        pump()
        win.extension_host.set_enabled("user:panel", False)
        pump()
        assert b.root.count() == 1 and b.root.widget(0) is pane  # the nesting went
    finally:
        close_window(win)
    saved = json.loads((own_home / "session.json").read_text())["workspaces"][1]["splitter"]
    # Written at its place: above the pane, in a vertical splitter of its own.
    (nested,) = saved["children"]
    assert nested["orientation"] == "vertical" and len(nested["sizes"]) == 2
    assert [c["type"] for c in nested["children"]] == ["extension", "pane"]
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        assert win.extension_host.docks("user:panel") == []
        b = win.workspaces()[1]
        win.extension_host.set_enabled("user:panel", True)
        pump()
        (dock,) = win.extension_host.docks("user:panel")
        assert win.extension_panel_workspace(dock) is b
        holder = dock.parentWidget()
        assert holder.orientation() == Qt.Orientation.Vertical and holder.indexOf(dock) == 0
        assert isinstance(holder.widget(1), type(win._active_pane))
    finally:
        close_window(win)


def test_edge_a_workspace_holding_only_a_switched_off_panel_stays(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    (pane,) = window._widgets_of(b)[0]
    window._close_pane(pane)
    pump()
    window.extension_host.reload()  # off and on: the workspace must survive the off
    pump()
    (dock,) = window.extension_host.docks("user:panel")
    assert b in window.workspaces() and window.extension_panel_workspace(dock) is b
    window.extension_host.set_enabled("user:panel", False)
    pump()
    assert b in window.workspaces() and b.root.count() == 0


def test_edge_the_second_panel_of_an_extension_finds_its_own_place(window):
    first, second = load_panel(window, "two", TWO_PANELS)
    a, b = two_workspaces(window)
    window.move_extension_panel(second, b)
    pump()
    window.extension_host.set_enabled("user:two", False)
    window.extension_host.set_enabled("user:two", True)
    pump()
    first, second = window.extension_host.docks("user:two")
    assert window.extension_panel_workspace(first) is None
    assert window.extension_panel_workspace(second) is b


# -- closing --------------------------------------------------------------------------------------


def test_happy_closing_a_workspace_parks_its_panel_with_its_state(window, monkeypatch):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    body = dock.widget()
    body.setText("changed by the user")
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert window.close_workspace(b)
    pump()
    assert not sip.isdeleted(dock) and dock.widget() is body
    assert body.text() == "changed by the user"
    assert window.extension_panel_workspace(dock) is None and not dock.isVisible()
    assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    dock.toggleViewAction().trigger()  # Extensions menu: it shows again
    pump()
    assert dock.isVisible()


def test_e2e_the_close_button_closes_the_panel_like_a_pane_and_the_menu_brings_it_back(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    window._on_pane_drop(str(id(dock)), pane, "right")
    pump()
    QTest.mouseClick(dock.titleBarWidget()._close_btn, Qt.MouseButton.LeftButton)
    pump()
    assert not dock.isVisible() and not in_layout(window, dock)
    assert b.root.count() == 1 and b.root.widget(0) is pane
    window.switch_workspace(a)
    pump()
    dock.toggleViewAction().trigger()  # Extensions > Panel: back at its place, on screen
    pump()
    assert window.extension_panel_workspace(dock) is b and window.current_workspace() is b
    assert dock.parentWidget() is pane.parentWidget()
    assert dock.parentWidget().indexOf(dock) == 1 and dock.isVisible()


def test_edge_a_closed_panel_whose_workspace_is_gone_comes_back_on_all_workspaces(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    dock.close()
    window._close_pane(pane)  # B empty: closed
    pump()
    assert b not in window.workspaces()
    dock.toggleViewAction().trigger()
    pump()
    assert window.extension_panel_workspace(dock) is None and dock.isVisible()


def test_edge_a_layout_preset_parks_the_panel_of_the_workspace(window, monkeypatch):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    monkeypatch.setattr(window, "_layout_switch_confirmed", lambda: True)
    from ui import layout_presets

    window.apply_layout_preset(next(iter(layout_presets.PRESETS)))
    pump()
    assert not sip.isdeleted(dock)
    assert window.extension_panel_workspace(dock) is None


def test_edge_the_toolbar_button_shows_a_workspace_panel_on_its_workspace(window):
    from ui.main_window import MainWindow

    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    window.switch_workspace(a)
    pump()
    with mock.patch.object(MainWindow, "TOOLBAR_EXTENSIONS", ()):
        window._toggle_extension_tool("user:panel", "Panel")
    pump()
    assert window.current_workspace() is b and dock.isVisible()


def test_edge_the_toolbar_button_hides_a_workspace_panel_like_its_close_button(window):
    from ui.main_window import MainWindow

    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    assert dock.isVisible()
    with mock.patch.object(MainWindow, "TOOLBAR_EXTENSIONS", ()):
        window._toggle_extension_tool("user:panel", "Panel")
        pump()
        assert not dock.isVisible() and not in_layout(window, dock)
        window._toggle_extension_tool("user:panel", "Panel")  # and back at its place
        pump()
    assert window.extension_panel_workspace(dock) is b and dock.isVisible()


def test_e2e_move_pane_to_workspace_moves_the_focused_panel(window):
    dock = load_panel(window)
    a, b = two_workspaces(window)
    window.move_extension_panel(dock, b)
    pump()
    body = dock.widget()
    body.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    window.activateWindow()
    body.setFocus()
    pump()
    if QApplication.focusWidget() is not body:
        pytest.skip("no keyboard focus on this platform plugin")
    assert window._pane_to_move() is dock
    window._fill_workspace_menu()
    move = menu_action(window._workspace_menu, "Move Pane to Workspace").menu()
    assert "All Workspaces" in menu_texts(move)
    menu_action(move, "Workspace 1").trigger()
    pump()
    assert window.extension_panel_workspace(dock) is a


# -- the equalizer finding -------------------------------------------------------------------------


def test_happy_equalize_evens_out_the_workspace_on_screen_not_the_active_panes(window):
    """Reproduced first: a workspace of two shells, Equalize pressed - the
    shells stayed 421 | 220 and workspace A (not on screen) was evened out."""
    a = window.current_workspace()
    window._add_local_pane()
    pump()
    a.root.setSizes([1000, 100])
    b = window.new_workspace("B", start="terminal")
    window.add_terminal_pane(b)
    pump(0.3)
    b.root.setSizes([1000, 100])
    pump()
    a_before = a.root.sizes()
    assert window.workspace_of(window._active_pane) is a and window.current_workspace() is b
    window._equalize_action.trigger()
    pump()
    sizes = b.root.sizes()
    assert abs(sizes[0] - sizes[1]) <= 6, sizes
    assert a.root.sizes() == a_before


def test_edge_equalize_in_a_detached_workspace_evens_out_that_window(window):
    a = window.current_workspace()
    b = window.new_workspace("B", start="terminal")
    window.add_terminal_pane(b)
    pump(0.3)
    detached = window.detach_workspace(b)
    pump(0.2)
    b.root.setSizes([1000, 100])
    pump()
    window.switch_workspace(b)  # the detached window got the focus
    window._equalize_pane_sizes()
    pump()
    sizes = b.root.sizes()
    assert detached is not None and abs(sizes[0] - sizes[1]) <= 6, sizes


# -- real bundled extensions ----------------------------------------------------------------------


def bundled(win, module: str):
    info = next(e for e in EX.discover() if e.module_name == module)
    EX.set_enabled(info.ext_id, True)
    win.extension_host.set_enabled(info.ext_id, True)
    (dock,) = win.extension_host.docks(info.ext_id)
    return info, dock


def test_e2e_bundled_markdown_preview_and_drives_overview_on_workspaces(own_home):
    win = new_window()
    try:
        md_info, md = bundled(win, "markdown_preview")
        dr_info, drives = bundled(win, "drives_overview")
        a, b = two_workspaces(win)
        win.move_extension_panel(md, b)
        menu_action(drives.titleBarWidget().move_menu, "B").trigger()
        pump(0.2)
        assert win.extension_panel_workspace(md) is b
        assert win.extension_panel_workspace(drives) is b
        win.switch_workspace(a)
        pump()
        assert not md.isVisible() and not drives.isVisible()
        win.switch_workspace(b)
        pump()
        assert md.isVisible() and drives.isVisible()
        win.extension_host.set_enabled(md_info.ext_id, False)
        pump()
        assert win.extension_host.docks(md_info.ext_id) == []
        win.extension_host.set_enabled(md_info.ext_id, True)
        pump()
        (md,) = win.extension_host.docks(md_info.ext_id)
        assert win.extension_panel_workspace(md) is b
    finally:
        close_window(win)
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        b = win.workspaces()[1]
        for info in (md_info, dr_info):
            (dock,) = win.extension_host.docks(info.ext_id)
            assert win.extension_panel_workspace(dock) is b, info.ext_id
    finally:
        close_window(win)


def test_e2e_media_player_keeps_playing_and_its_equalizer_fold_on_a_workspace(
        own_home, monkeypatch):
    from core import multimedia_probe
    from tests.test_media_player_late_engine import OK, FakeEngine

    monkeypatch.setattr(multimedia_probe, "probe", lambda *a, **k: OK)
    win = new_window()
    try:
        info = next(e for e in EX.discover() if e.module_name == "media_player")
        EX.set_enabled(info.ext_id, True)
        win.extension_host.set_enabled(info.ext_id, True)
        (dock,) = win.extension_host.docks(info.ext_id)
        panel = dock.widget()
        panel._engine_factory = FakeEngine  # before the probe's answer arrives
        assert wait(lambda: panel.engine_ready, 10)
        engine = panel.engine
        a, b = two_workspaces(win)
        panel.set_equalizer_open(False)
        engine.load("/x.mp3")
        engine.play()
        win.move_extension_panel(dock, b)
        pump()
        assert dock.widget() is panel and panel.engine is engine and engine.state == "playing"
        assert not panel._eq_open
        # The panel's own title (the track) still reaches its title bar.
        panel.track_changed.emit("Song")
        assert "Song" in dock.titleBarWidget()._title_label.text()
        win.detach_workspace(b)
        pump()
        assert engine.state == "playing" and b.window.isAncestorOf(dock)
    finally:
        close_window(win)
    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump()
        (dock,) = win.extension_host.docks(info.ext_id)
        b = win.workspaces()[1]
        assert win.extension_panel_workspace(dock) is b
        assert not dock.widget()._eq_open  # the fold state came back with the panel
    finally:
        close_window(win)
