"""Send to Workspace: a pane's right-click menu sends it to workspace n, and
an Agent dock tab goes onto a workspace in one step.

Asked for: a right-click on a pane offers "send to workspace (n)", and an
Agent conversation can become the main view of another or a new workspace.

Before: a file pane's right-click menu had no workspace entry at all, a
terminal pane only its header button (⇄), and an Agent conversation needed
two menus - the tab's Detach as Panel, then the panel's title bar Move to
Workspace. The workspaces were listed by name only.

Now every right-click on a pane - a file pane's list (on an item and on the
empty area), a pane's header, a terminal's screen, an extension or agent
panel's title bar - offers Send to Workspace ▸ with the workspaces numbered
as their tabs stand ("1: Workspace 1"), then New Workspace; an Agent dock
tab's right-click menu has the same submenu and lays the conversation out
on the picked workspace (detached into a panel on the way).
"""

from __future__ import annotations

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
from PyQt6.QtCore import QCoreApplication, QEvent, QItemSelectionModel, QPoint, Qt  # noqa: E402
from PyQt6.QtGui import QContextMenuEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QSplitter  # noqa: E402

from tests.test_agent_detach import Win, server_box  # noqa: E402,F401 - fixture

APP = QApplication.instance() or QApplication([])
SEND = "Send to Workspace"


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


@pytest.fixture
def home(monkeypatch):
    path = Path(tempfile.mkdtemp())
    monkeypatch.setenv("HOME", str(path))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path / "session.json")
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def window(home):
    from ui.main_window import MainWindow

    folder = home / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("x")
    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1100, 700)
    win.show()
    win._active_pane.navigate(str(folder))
    pump()
    yield win
    if not sip.isdeleted(win):
        win.close()
        win.deleteLater()
    pump(0.1)


@pytest.fixture
def mw(home, monkeypatch, server_box):  # noqa: F811 - the imported fixture
    w = Win(monkeypatch, server_box)
    pump()
    yield w
    w.close()


def plain(text: str) -> str:
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


def texts(menu: QMenu) -> list[str]:
    return [plain(a.text()) for a in menu.actions() if not a.isSeparator()]


def entry(menu: QMenu, text: str):
    for action in menu.actions():
        if plain(action.text()) == text:
            return action
    raise AssertionError(f"{text!r} not in {texts(menu)}")


def send_menu(menu: QMenu) -> QMenu:
    sub = entry(menu, SEND).menu()
    assert sub is not None
    sub.aboutToShow.emit()
    return sub


def has_send(menu: QMenu) -> bool:
    return SEND in texts(menu)


def picking(path: list[str], seen: list | None = None):
    """A QMenu.exec stand-in: walks *path* (submenu titles, then the entry)
    in the menu that opened and triggers the entry; *seen* gets the menu."""
    def fake_exec(menu, *_args):
        # Runs inside a Qt slot or event handler, where an exception aborts
        # the whole process: kept for the test's teardown instead.
        try:
            if seen is not None:
                seen.append([plain(a.text()) for a in menu.actions()])
            current = menu
            for text in path[:-1]:
                current = send_menu(current) if text == SEND else entry(current, text).menu()
            entry(current, path[-1]).trigger()
        except Exception as exc:  # noqa: BLE001 - reported by _no_menu_errors
            MENU_ERRORS.append(exc)
    return fake_exec


#: Failures inside a patched QMenu.exec (see picking).
MENU_ERRORS: list[Exception] = []


@pytest.fixture(autouse=True)
def _no_menu_errors():
    MENU_ERRORS.clear()
    yield
    assert not MENU_ERRORS, MENU_ERRORS


def three(win):
    """Workspaces 1 (the window's), B and C; 1 shown."""
    first = win.current_workspace()
    b = win.new_workspace("B")
    c = win.new_workspace("C")
    win.switch_workspace(first)
    pump()
    return first, b, c


def select(pane, name: str) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(proxy.index(row, 0),
                       QItemSelectionModel.SelectionFlag.Select
                       | QItemSelectionModel.SelectionFlag.Rows)


def right_click(widget, pos: QPoint | None = None) -> None:
    """A real right-click's context menu event on *widget*."""
    pos = pos or QPoint(5, 5)
    event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, pos, widget.mapToGlobal(pos))
    QApplication.sendEvent(widget, event)


# -- numbering ---------------------------------------------------------------------------------


def test_happy_workspaces_are_numbered_as_their_tabs_stand(window):
    first, b, c = three(window)
    assert window.numbered_workspaces() == [first, b, c]
    assert [window.workspace_label(w) for w in (first, b, c)] == [
        "&1: Workspace 1", "&2: B", "&3: C"]
    # A tab dragged to the front is number 1.
    window._workspace_tabs.tabBar().moveTab(2, 0)
    assert window.numbered_workspaces() == [c, first, b]
    assert window.workspace_label(c) == "&1: C"


def test_edge_a_detached_workspace_counts_after_the_tabs_and_says_window(window):
    first, b, c = three(window)
    window.detach_workspace(b)
    pump()
    assert window.numbered_workspaces() == [first, c, b]
    assert window.workspace_label(b) == "&3: B (window)"


def test_edge_from_ten_on_a_workspace_has_no_mnemonic(window):
    for n in range(2, 11):
        window.new_workspace(f"W{n}")
    tenth = window.numbered_workspaces()[9]
    assert window.workspace_label(tenth) == "10: W10"


def test_sad_an_ampersand_in_a_name_shows_as_typed(window):
    ws = window.new_workspace("R&D")
    assert window.workspace_label(ws) == "&2: R&&D"
    assert plain(window.workspace_label(ws)) == "2: R&D"


# -- file panes --------------------------------------------------------------------------------


def test_happy_the_file_pane_menu_lists_the_other_workspaces_then_new(window):
    first, b, c = three(window)
    pane = window._active_pane
    sub = send_menu(pane._build_context_menu())
    assert texts(sub) == ["2: B", "3: C", "New Workspace"]
    assert sub.actions()[-2].isSeparator()


@pytest.mark.parametrize("on_item", [True, False], ids=["item", "empty-area"])
def test_e2e_right_click_in_a_file_pane_sends_it_to_workspace_n(window, on_item):
    first, b, c = three(window)
    pane = window._active_pane
    if on_item:
        select(pane, "notes.txt")
    else:
        pane._table.clearSelection()
    with mock.patch.object(QMenu, "exec", picking([SEND, "3: C"])):
        pane._table.customContextMenuRequested.emit(QPoint(10, 10))
    pump()
    assert window.workspace_of(pane) is c and pane.isVisible()
    assert window.current_workspace() is c and window._active_pane is pane
    assert first not in window.workspaces()  # its last pane left: it closed


def test_edge_the_entry_sits_in_a_group_of_its_own_at_the_end(window):
    pane = window._active_pane
    for name in ("notes.txt", None):
        if name:
            select(pane, name)
        else:
            pane._table.clearSelection()
        actions = pane._build_context_menu().actions()
        send = next(a for a in actions if plain(a.text()) == SEND)
        index = actions.index(send)
        assert actions[index - 1].isSeparator()
        assert send.property("axCommand") == "send-to-workspace"


def test_edge_with_one_workspace_only_new_workspace_is_offered(window):
    pane = window._active_pane
    window._add_local_pane()  # a second pane: the first one can leave
    pump()
    sub = send_menu(pane._build_context_menu())
    assert texts(sub) == ["New Workspace"]
    entry(sub, "New Workspace").trigger()
    pump()
    ws = window.workspace_of(pane)
    assert len(window.workspaces()) == 2 and ws is window.current_workspace()
    assert window._widgets_of(ws)[0] == [pane]


def test_edge_the_last_pane_of_the_only_workspace_moves_and_nothing_is_lost(window):
    pane = window._active_pane
    entry(send_menu(pane._build_context_menu()), "New Workspace").trigger()
    pump()
    # The pane is on the new workspace; the one it left was empty and went.
    (ws,) = window.workspaces()
    assert ws.name == "Workspace 2" and window.workspace_of(pane) is ws
    assert window._panes == [pane] and pane.isVisible()


def test_e2e_a_pane_header_right_click_sends_it_too(window):
    first, b, c = three(window)
    pane = window._active_pane
    header = pane._header_label
    seen: list = []
    with mock.patch.object(QMenu, "exec", picking([SEND, "2: B"], seen)):
        right_click(header)
    pump()
    assert seen == [[SEND]]
    assert window.workspace_of(pane) is b


def test_sad_a_pane_of_no_window_offers_no_entry():
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    try:
        assert not has_send(pane._build_context_menu())
        seen: list = []
        with mock.patch.object(QMenu, "exec", lambda m, *_a: seen.append(m)):
            right_click(pane._header_label)
        assert seen == []  # no empty menu pops up
    finally:
        pane.deleteLater()
        pump()


def test_sad_a_workspace_closed_while_the_menu_is_open_moves_nothing(window):
    first, b, c = three(window)
    pane = window._active_pane
    sub = send_menu(pane._build_context_menu())
    window.close_workspace(c, ask=False)
    pump()
    entry(sub, "3: C").trigger()
    pump()
    assert window.workspace_of(pane) is first


def test_e2e_a_pane_in_a_detached_window_goes_back_to_a_tab(window):
    first, b, c = three(window)
    window.detach_workspace(b)
    pump()
    (pane,) = window._widgets_of(b)[0]
    assert pane.window() is b.window
    sub = send_menu(pane._build_context_menu())
    assert texts(sub) == ["1: Workspace 1", "2: C", "New Workspace"]
    with mock.patch.object(QMenu, "exec", picking([SEND, "1: Workspace 1"])):
        pane._table.customContextMenuRequested.emit(QPoint(10, 10))
    pump()
    assert window.workspace_of(pane) is first and pane.window() is window
    assert b not in window.workspaces()  # its window closed with its last pane


def test_happy_the_actions_menu_carries_the_entry_as_well(window):
    three(window)
    window._fill_actions_menu()
    assert has_send(window.actions_menu)


# -- terminal panes ----------------------------------------------------------------------------


def test_e2e_right_click_in_a_terminal_sends_it_to_workspace_n(window):
    first, b, c = three(window)
    term = window.add_terminal_pane(b)
    pump()
    seen: list = []
    with mock.patch.object(QMenu, "exec", picking([SEND, "1: Workspace 1"], seen)):
        right_click(term._terminal.viewport())
    pump()
    assert seen[0][:3] == ["Copy", "Paste", ""] and SEND in seen[0]
    assert window.workspace_of(term) is first and term.isVisible()


def test_e2e_a_terminal_header_right_click_sends_it_too(window):
    first, b, c = three(window)
    term = window.add_terminal_pane(first)
    pump()
    with mock.patch.object(QMenu, "exec", picking([SEND, "New Workspace"])):
        right_click(term._title)
    pump()
    ws = window.workspace_of(term)
    assert ws not in (first, b, c) and window._widgets_of(ws)[1] == [term]


def test_sad_the_terminal_dock_shell_has_no_workspace_entry():
    from ui.terminal_widget import TerminalEmulator

    emulator = TerminalEmulator()
    try:
        assert not has_send(emulator._context_menu())
    finally:
        emulator.deleteLater()
        pump()


def test_happy_the_terminal_header_button_shows_the_same_numbers(window):
    first, b, c = three(window)
    term = window.add_terminal_pane(c)
    pump()
    menu = term.workspace_menu()
    menu.aboutToShow.emit()
    assert texts(menu) == ["1: Workspace 1", "2: B", "New Workspace"]
    assert term._btn_workspace.toolTip() == SEND


# -- agent conversations -----------------------------------------------------------------------


def tab_menu_pick(dock, tab, path):
    bar = dock.tabs.tabBar()
    pos = bar.tabRect(dock.tabs.indexOf(tab)).center()
    with mock.patch.object(QMenu, "exec", picking(path)):
        dock._show_tab_menu(pos)
    pump()


def test_e2e_an_agent_tab_goes_alone_onto_a_new_workspace_and_into_a_window(mw):
    win, dock = mw.win, mw.dock
    win._focus_agent_action.trigger()
    pump()
    tab = dock.current_tab()
    session = tab.session
    before = list(win.workspaces())
    tab_menu_pick(dock, tab, [SEND, "New Workspace"])
    panel = dock.panel_of(tab)
    assert panel is not None and panel.widget() is tab and tab.session is session
    ws = win.extension_panel_workspace(panel)
    assert ws is not None and ws not in before and win.current_workspace() is ws
    # The conversation is the workspace's only content - its main view.
    assert ws.root.count() == 1 and ws.root.widget(0) is panel
    assert win._widgets_of(ws) == ([], [], []) and panel.isVisible()
    assert session.detached == "workspace"
    assert dock.tabs.count() >= 1  # the dock keeps a (fresh) tab
    # ... and onto a window of its own: the workspace tab's Detach to Window.
    bar = win._workspace_tabs.tabBar()
    index = win._workspace_tabs.indexOf(ws.root)
    with mock.patch.object(QMenu, "exec", picking(["Detach to Window"])):
        win._show_workspace_tab_menu(bar.tabRect(index).center())
    pump()
    assert ws.window is not None and panel.window() is ws.window and panel.isVisible()


def test_happy_an_agent_tab_goes_onto_an_existing_workspace(mw):
    win, dock = mw.win, mw.dock
    a = win.current_workspace()
    b = win.new_workspace("B")
    win.switch_workspace(a)
    pump()
    tab = dock.current_tab()
    menu = dock.tab_menu(dock.tabs.indexOf(tab))
    sub = send_menu(menu)
    assert texts(sub) == ["1: Workspace 1", "2: B", "New Workspace"]
    tab_menu_pick(dock, tab, [SEND, "2: B"])
    panel = dock.panel_of(tab)
    assert win.extension_panel_workspace(panel) is b and win.current_workspace() is b
    assert isinstance(panel.parentWidget(), QSplitter)
    assert len(win._widgets_of(b)[0]) == 1  # B keeps its file pane beside it


def test_sad_a_workspace_gone_before_the_pick_leaves_the_tab_in_the_dock(mw):
    win, dock = mw.win, mw.dock
    a = win.current_workspace()
    b = win.new_workspace("B")
    pump()
    tab = dock.current_tab()
    sub = send_menu(dock.tab_menu(dock.tabs.indexOf(tab)))
    win.close_workspace(b, ask=False)
    pump()
    entry(sub, "2: B").trigger()
    pump()
    assert dock.tabs.indexOf(tab) >= 0 and dock.panel_of(tab) is None
    assert win.current_workspace() is a


def test_edge_at_the_workspace_ceiling_new_workspace_is_off_and_the_tab_stays(mw):
    from ui.workspaces import MAX_WORKSPACES

    win, dock = mw.win, mw.dock
    while len(win.workspaces()) < MAX_WORKSPACES:
        win.new_workspace(activate=False, with_pane=False)
    tab = dock.current_tab()
    sub = send_menu(dock.tab_menu(dock.tabs.indexOf(tab)))
    assert not entry(sub, "New Workspace").isEnabled()
    assert dock.send_tab_to_workspace(tab, None) is None
    assert dock.tabs.indexOf(tab) >= 0 and dock.panels() == []


def test_sad_a_dock_without_a_window_offers_no_workspace_entry(tmp_path):
    from tests.test_agent_tabs import Env

    env = Env(tmp_path)
    env.fake()
    try:
        dock = env.dock()
        tab = dock.current_tab()
        menu = dock.tab_menu(dock.tabs.indexOf(tab))
        assert not has_send(menu) and "Detach as Panel" in texts(menu)
        assert dock.send_tab_to_workspace(tab, None) is None
    finally:
        env.close()


def test_sad_send_tab_refuses_what_is_no_tab_of_the_dock(mw):
    win, dock = mw.win, mw.dock
    assert dock.send_tab_to_workspace(object(), win.current_workspace()) is None
    assert dock.panels() == []


def test_e2e_an_agent_panel_title_bar_right_click_sends_it_on(mw):
    win, dock = mw.win, mw.dock
    a = win.current_workspace()
    b = win.new_workspace("B")
    win.switch_workspace(a)
    pump()
    panel = dock.new_window()
    pump()
    seen: list = []
    with mock.patch.object(QMenu, "exec", picking([SEND, "2: B"], seen)):
        right_click(panel.titleBarWidget())
    pump()
    assert SEND in seen[0] and "Attach to Agent Dock" in seen[0]
    assert win.extension_panel_workspace(panel) is b
    sub = panel.titleBarWidget().move_menu
    sub.aboutToShow.emit()
    # A panel's menu ticks where it is and offers All Workspaces as well.
    assert texts(sub) == ["1: Workspace 1", "2: B", "New Workspace", "All Workspaces"]
    assert entry(sub, "2: B").isChecked()
