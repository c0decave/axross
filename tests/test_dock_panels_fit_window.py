"""Panels never overlap: however many file panes, Agent conversations and
extension panels (the Media Player) are docked, floated and docked again,
on All Workspaces or on a workspace, each one keeps a rectangle of its own
inside the window.

Reported: with several file panes, Agent conversations and the Media
Player, docking and undocking them left the panels partly on top of each
other and no longer drawn cleanly.

Before, a panel's smallest size was its content's: a detached conversation
could not be smaller than 582x341 px, the Media Player not smaller than
355x568 px. The dock area stacks its panels, so their smallest heights
added up - two conversations and the player asked for a window at least
1446x1663 px - and on a workspace the panels' smallest widths added up
beside the panes. A window manager that holds the window at the screen's
size (tiling, maximized) then made Qt lay the panels out on top of each
other; one that does not left the window larger than the screen. Now a
panel's content sits in a scroll area: the panel takes the space it gets,
and its content scrolls when that is less than it needs.

The window is "held" smaller than its minimum the way a window manager
does it: Qt's own minimum is lifted (layout constraint and minimum size)
and the window resized - Qt's dock and splitter layouts then lay out in
what they were given, exactly as on a tiled screen (seen on a real X
server: Xvfb 1600x1000, the window forced with xdotool windowsize).
"""

from __future__ import annotations

import itertools
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDockWidget,
    QLabel,
    QLayout,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: A common laptop screen, smaller than what the panels asked for before.
HELD = (1280, 800)
#: A common desktop screen: five panes side by side on one workspace.
WIDE = (1600, 900)


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    APP.processEvents()


def wait(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


@pytest.fixture
def window(monkeypatch):
    from core import multimedia_probe
    from tests.test_media_player_late_engine import OK
    from ui.main_window import MainWindow

    monkeypatch.setattr(multimedia_probe, "probe", lambda *a, **k: OK)
    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1400, 900)
    win.show()
    pump(0.2)
    yield win
    if not sip.isdeleted(win):
        for panel in list(win._agent_dock.panels()):
            panel.closing = True
        win.close()
        win.deleteLater()
        pump()


def add_file_panes(win, count: int) -> list:
    from core.local_fs import LocalFS

    while len(win._panes) < count:
        win._add_pane_to_splitter(win._root_splitter, LocalFS()).show()
    pump()
    return list(win._panes)


def media_player(win):
    from tests.test_media_player_late_engine import FakeEngine

    info = next(e for e in EX.discover() if e.module_name == "media_player")
    EX.set_enabled(info.ext_id, True)
    win.extension_host.set_enabled(info.ext_id, True)
    (dock,) = win.extension_host.docks(info.ext_id)
    dock.widget()._engine_factory = FakeEngine
    assert wait(lambda: dock.widget().engine_ready)
    dock.show()
    pump()
    return dock


def crowd(win):
    """Three file panes, two detached conversations and the Media Player,
    all panels on All Workspaces - the reported setup."""
    add_file_panes(win, 3)
    agents = [win._agent_dock.new_window() for _ in range(2)]
    player = media_player(win)
    pump(0.2)
    return agents, player


def hold(win, width: int, height: int) -> None:
    """Hold the window at *width* x *height* as a window manager does,
    whatever minimum Qt computed."""
    win.layout().setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
    win.setMinimumSize(1, 1)
    win.resize(width, height)
    pump(0.2)
    assert (win.width(), win.height()) == (width, height)


def _name(widget) -> str:
    return f"{type(widget).__name__}({widget.objectName() or widget.windowTitle()})"


def overlaps(win) -> list[str]:
    """Every visible dock and the central widget inside the window and
    apart from each other; every visible child of a visible splitter
    inside it and apart from its siblings."""
    found = []
    rect = win.rect()
    items = [win.centralWidget()]
    for dock in win.findChildren(QDockWidget, options=Qt.FindChildOption.FindDirectChildrenOnly):
        if not dock.isVisible() or dock.isFloating():
            continue
        if win.tabifiedDockWidgets(dock) and not dock.geometry().intersects(rect):
            continue  # a tab behind another one: Qt keeps it outside
        items.append(dock)
    for item in items:
        if not rect.contains(item.geometry()):
            found.append(f"{_name(item)} {item.geometry()} outside {rect}")
    for a, b in itertools.combinations(items, 2):
        if a.geometry().intersects(b.geometry()):
            found.append(f"{_name(a)} {a.geometry()} overlaps {_name(b)} {b.geometry()}")
    root = win.centralWidget()
    for splitter in [root, *root.findChildren(QSplitter)]:
        if not isinstance(splitter, QSplitter) or not splitter.isVisible():
            continue
        kids = [splitter.widget(i) for i in range(splitter.count())]
        kids = [k for k in kids if k.isVisible()]
        for kid in kids:
            if not splitter.rect().contains(kid.geometry()):
                found.append(f"{_name(kid)} {kid.geometry()} outside its splitter")
        for a, b in itertools.combinations(kids, 2):
            if a.geometry().intersects(b.geometry()):
                found.append(f"{_name(a)} {a.geometry()} overlaps {_name(b)} {b.geometry()}")
    return found


def frame_of(dock) -> QScrollArea:
    """The scroll area around *dock*'s content."""
    frame = dock.widget().parentWidget()
    while frame is not None and not isinstance(frame, QScrollArea):
        frame = frame.parentWidget()
    assert isinstance(frame, QScrollArea) and frame.parentWidget() is dock
    return frame


# -- the reported case ---------------------------------------------------------------------


def test_e2e_panes_conversations_and_player_on_all_workspaces_do_not_overlap(window):
    agents, player = crowd(window)
    hold(window, *HELD)
    assert overlaps(window) == []
    for dock in (*agents, player):
        assert dock.isVisible() and dock.width() > 0 and dock.height() > 0


def test_e2e_floated_and_docked_again_the_panels_still_do_not_overlap(window):
    agents, player = crowd(window)
    for dock in (agents[0], player, agents[1]):
        dock.titleBarWidget()._float_btn.click()  # undock
        pump()
        assert dock.isFloating()
    for dock in (player, agents[1], agents[0]):
        dock.titleBarWidget()._float_btn.click()  # dock again
        pump()
        assert not dock.isFloating()
    hold(window, *HELD)
    assert overlaps(window) == []


def test_e2e_panes_conversation_and_player_on_one_workspace_do_not_overlap(window):
    agents, player = crowd(window)
    ws = window.current_workspace()
    window.move_extension_panel(agents[0], ws)
    window.move_extension_panel(player, ws)
    pump(0.2)
    assert window.extension_panel_workspace(player) is ws
    # Side by side the three file panes alone need 3 x ~243 px; the two
    # panels beside them asked for 582 + 355 px more before (a window at
    # least ~2400 px wide), now for their title bars only.
    assert window.minimumSizeHint().width() <= WIDE[0], window.minimumSizeHint()
    hold(window, *WIDE)
    assert overlaps(window) == []
    assert player.width() > 0 and agents[0].width() > 0


def test_edge_a_panel_adds_little_to_the_window_minimum(window):
    add_file_panes(window, 3)
    before = window.minimumSizeHint()
    crowd(window)
    after = window.minimumSizeHint()
    # Three panels stacked: each costs its title bar and a scroll area's
    # smallest size, not its content's height.
    assert after.height() - before.height() <= 3 * 140, (before, after)
    assert after.width() <= HELD[0] and after.height() <= HELD[1], after


# -- the content: whole when there is room, scrolled when not -------------------------------


def test_happy_with_room_a_panel_shows_its_content_whole(window):
    player = media_player(window)
    window.resize(1800, 1400)
    pump(0.2)
    content = player.widget()
    frame = frame_of(player)
    assert content.height() >= content.minimumSizeHint().height()
    assert content.width() >= content.minimumSizeHint().width()
    assert not frame.verticalScrollBar().isVisible()
    assert not frame.horizontalScrollBar().isVisible()
    # The content fills the panel, as before.
    assert content.width() == frame.viewport().width()
    assert content.height() == frame.viewport().height()


def test_sad_a_panel_given_less_than_its_content_needs_scrolls_it(window):
    agents, player = crowd(window)
    hold(window, *HELD)
    content = player.widget()
    frame = frame_of(player)
    # The content keeps the size it needs (nothing squeezed or drawn over)
    # and the panel scrolls it.
    assert content.height() >= content.minimumSizeHint().height()
    assert frame.viewport().height() < content.height()
    assert frame.verticalScrollBar().isVisible()
    assert frame.verticalScrollBar().maximum() > 0


def test_happy_a_panel_keeps_its_widget(window):
    agents, player = crowd(window)
    assert agents[0].widget() is agents[0].tab
    assert type(player.widget()).__name__ == "PlayerPanel"
    ws = window.current_workspace()
    window.move_extension_panel(player, ws)
    window.move_extension_panel(agents[0], ws)
    pump()
    assert agents[0].widget() is agents[0].tab
    assert type(player.widget()).__name__ == "PlayerPanel"


def test_edge_attaching_a_conversation_takes_it_out_of_the_panel(window):
    (panel, _other), _player = crowd(window)
    dock = window._agent_dock
    tab = panel.tab
    frame = frame_of(panel)
    assert dock.attach_panel(panel) is tab
    # The panel's frame let go of it when the tab moved: it does not hold
    # or size the tab that is now the Agent dock's.
    assert frame.content() is None and panel.widget() is None
    pump(0.2)
    assert dock.tabs.indexOf(tab) >= 0
    assert dock.tabs.isAncestorOf(tab)
    dock.show()
    pump(0.2)
    assert tab.geometry() == dock.tabs.currentWidget().geometry()


# -- the panel on its own --------------------------------------------------------------------


def _bare_dock():
    from ui.extension_panels import ExtensionDock

    owner = QWidget()
    dock = ExtensionDock("Bare", owner, "user:bare")
    return owner, dock


def test_edge_a_panel_without_a_widget_has_none():
    owner, dock = _bare_dock()
    try:
        assert dock.widget() is None
    finally:
        owner.deleteLater()


def test_edge_a_replaced_widget_stays_alive_like_in_a_plain_dock():
    owner, dock = _bare_dock()
    try:
        first, second = QLabel("first"), QLabel("second")
        dock.setWidget(first)
        dock.setWidget(second)
        pump()
        assert dock.widget() is second
        assert not sip.isdeleted(first)  # as QDockWidget.setWidget leaves it
        dock.setWidget(None)
        assert dock.widget() is None
        assert not sip.isdeleted(second)
    finally:
        owner.deleteLater()


def test_sad_a_tall_widget_does_not_set_the_panel_minimum():
    owner, dock = _bare_dock()
    try:
        tall = QWidget()
        column = QVBoxLayout(tall)
        for n in range(30):
            column.addWidget(QLabel(f"row {n}"))
        dock.setWidget(tall)
        assert tall.minimumSizeHint().height() > 400
        assert dock.minimumSizeHint().height() < 150
    finally:
        owner.deleteLater()


# -- the built-in docks of the same area -------------------------------------------------------


def test_e2e_the_agent_and_analysis_docks_with_the_panels_do_not_overlap(window):
    """The Agent dock (586x379 px of tabs) and the Analysis dock share the
    right dock area with the panels: the same scroll area holds their
    content."""
    agents, player = crowd(window)
    window._agent_dock.show()
    window._analysis_dock.show()
    pump(0.2)
    assert window.minimumSizeHint().height() <= WIDE[1], window.minimumSizeHint()
    hold(window, *WIDE)
    assert overlaps(window) == []
    assert window._agent_dock.height() > 0 and window._analysis_dock.height() > 0


def test_sad_the_agent_dock_minimum_is_not_its_tabs(window):
    dock = window._agent_dock
    dock.show()
    pump()
    assert dock.tabs.minimumSizeHint().height() > 300
    assert dock.minimumSizeHint().height() < 150
    assert dock.tabs.window() is window  # still in the window, in the frame


def test_edge_the_frame_asks_for_its_content_size_uncapped():
    from ui.dock_frame import framed

    tall = QLabel("\n".join(f"line {n}" for n in range(120)))
    frame = framed(tall)
    try:
        # QScrollArea alone caps its size hint at 24 lines of text.
        assert frame.sizeHint().height() == tall.sizeHint().height()
        assert frame.sizeHint().width() == tall.sizeHint().width()
        assert not tall.autoFillBackground()  # looks as it did unframed
    finally:
        frame.deleteLater()


def test_edge_a_styled_content_keeps_its_look_in_the_frame():
    """The themes make a scroll area's own widget transparent
    (``QScrollArea > QWidget > QWidget``); the content sits one level
    below it, so a styled content (the Markdown Preview's QTextBrowser)
    looks as it did in a plain panel."""
    from PyQt6.QtWidgets import QTextBrowser

    owner, dock = _bare_dock()
    try:
        owner.setStyleSheet(
            "QScrollArea > QWidget > QWidget { background: rgb(255, 0, 0); }"
            "QTextBrowser { background: rgb(10, 20, 30); border: none; }")
        view = QTextBrowser()
        dock.setWidget(view)
        owner.resize(300, 300)
        dock.setGeometry(0, 0, 300, 300)
        owner.show()
        pump()
        pixel = view.viewport().grab().toImage().pixelColor(5, 5)
        assert (pixel.red(), pixel.green(), pixel.blue()) == (10, 20, 30)
    finally:
        owner.deleteLater()


def test_edge_the_frame_takes_no_keyboard_focus(window):
    """A scroll area is a Tab stop of its own; the frame is not - the
    keys go through a panel's widgets as before, and the Agent's voice,
    which follows the focused conversation, never lands on the frame."""
    agents, player = crowd(window)
    for dock in (agents[0], player, window._agent_dock):
        frame = dock.findChild(QScrollArea, "panelFrame")
        assert frame is not None
        assert frame.focusPolicy() == Qt.FocusPolicy.NoFocus
        frame.setFocus()
        pump()
        assert QApplication.focusWidget() is not frame
