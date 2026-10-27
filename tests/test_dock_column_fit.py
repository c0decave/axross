"""The right dock column reaches the window's bottom edge, and the docks of
a column that do not fit its height are tabbed together - and stacked
again when room comes back.

Before, the bottom area (Transfers, Terminal, Log, Console, Scripts) took
the whole width of the window, so the right column ended above it, and
every dock in a column was stacked whatever the column's height: five
docks on the right of a 1600x980 window got 86 px each - their title bar
and nothing of their content - and on a window held smaller than that by
a window manager they were laid over each other.

Now (ui.dock_fit) the right column owns the bottom-right corner, and a
column whose docks need more than its height - a useful height each, not
only a title bar - gets docks tabbed together until they fit. Docks axross
tabbed go back to being stacked when there is room again (with a margin,
so a window resized by a pixel does not flip them back and forth); docks
the user tabbed stay tabbed, and a dock the user took out of an automatic
tab group is not tabbed again for comfort. Nothing changes while a mouse
button is down (a separator or a dock being dragged), panels laid out on
a workspace are not part of any column, and which tabs axross made is kept
in session.json beside Qt's own dock state.
"""

from __future__ import annotations

import itertools
import json
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
    QMainWindow,
    QStatusBar,
    QWidget,
)

APP = QApplication.instance() or QApplication([])

RIGHT = Qt.DockWidgetArea.RightDockWidgetArea
LEFT = Qt.DockWidgetArea.LeftDockWidgetArea
BOTTOM = Qt.DockWidgetArea.BottomDockWidgetArea
VERTICAL = Qt.Orientation.Vertical


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


def hold(win, width: int, height: int) -> None:
    """Hold *win* at *width* x *height* as a window manager does (tiling,
    maximized), whatever minimum Qt computed."""
    win.layout().setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
    win.setMinimumSize(1, 1)
    win.resize(width, height)
    pump(0.1)
    assert (win.width(), win.height()) == (width, height)


def docked(win, area=None) -> list[QDockWidget]:
    return [
        d for d in win.findChildren(QDockWidget, options=Qt.FindChildOption.FindDirectChildrenOnly)
        if d.isVisible() and not d.isFloating()
        and win.dockWidgetArea(d) != Qt.DockWidgetArea.NoDockWidgetArea
        and (area is None or win.dockWidgetArea(d) == area)
    ]


def shown(win, area=None) -> list[QDockWidget]:
    """The docks one sees: a tab behind another one is parked outside."""
    return [d for d in docked(win, area) if d.geometry().intersects(win.rect())]


def overlaps(win) -> list[str]:
    """Every visible dock and the central widget inside the window and
    apart from each other."""
    found = []
    rect = win.rect()
    items = [win.centralWidget(), *shown(win)]
    for item in items:
        if not rect.contains(item.geometry()):
            found.append(f"{item.objectName()} {item.geometry()} outside {rect}")
    for a, b in itertools.combinations(items, 2):
        if a.geometry().intersects(b.geometry()):
            found.append(f"{a.objectName()} {a.geometry()} overlaps "
                         f"{b.objectName()} {b.geometry()}")
    return found


def tabbed(win, dock) -> set[str]:
    return {d.objectName() for d in win.tabifiedDockWidgets(dock)}


def column_order(win, area=RIGHT) -> list[str]:
    return [d.objectName() for d in sorted(shown(win, area), key=lambda d: d.y())]


def viewport_heights_ok(win, area=RIGHT) -> list[str]:
    """Each dock one sees shows at least a useful height of its content
    (COMFORT_CONTENT_PX, or all of it when it needs less)."""
    from ui.dock_fit import COMFORT_CONTENT_PX
    from ui.dock_frame import PanelFrame

    short = []
    for dock in shown(win, area):
        frame = dock.findChild(PanelFrame, "panelFrame")
        if frame is None:
            continue
        want = min(frame.content_minimum().height(), COMFORT_CONTENT_PX)
        if frame.viewport().height() < want:
            short.append(f"{dock.objectName()} {frame.viewport().height()} < {want}")
    return short


# -- a plain window with a DockFit ---------------------------------------------------------------


def content(min_height: int = 300) -> QWidget:
    widget = QWidget()
    widget.setMinimumSize(120, min_height)
    return widget


def plain_window(count: int = 4, *, size=(900, 900), min_height: int = 300):
    from ui.dock_fit import DockFit
    from ui.dock_frame import framed

    win = QMainWindow()
    win.setCentralWidget(QLabel("central"))
    win.setStatusBar(QStatusBar())
    win.setCorner(Qt.Corner.BottomRightCorner, RIGHT)
    docks = []
    for n in range(count):
        dock = QDockWidget(f"d{n}", win)
        dock.setObjectName(f"d{n}")
        dock.setWidget(framed(content(min_height)))
        win.addDockWidget(RIGHT, dock)
        docks.append(dock)
    fit = DockFit(win)
    win.resize(*size)
    win.show()
    pump(0.1)
    return win, docks, fit


@pytest.fixture
def plain():
    made = []

    def make(*args, **kwargs):
        made.append(plain_window(*args, **kwargs))
        return made[-1]

    yield make
    for win, _docks, _fit in made:
        win.close()
        win.deleteLater()
    pump()


def test_happy_a_column_that_does_not_fit_is_tabbed_until_it_does(plain):
    from ui.dock_fit import COMFORT_CONTENT_PX

    win, docks, fit = plain(4, size=(900, 1400))
    hold(win, 900, 1400)
    assert fit.fit_now() is False  # 4 x (title + 200 px) fit 1400 px
    assert all(not tabbed(win, d) for d in docks)
    hold(win, 900, 2 * COMFORT_CONTENT_PX + 150)
    assert fit.fit_now() is True
    pump()
    assert overlaps(win) == []
    assert any(tabbed(win, d) for d in docks)
    assert fit.column_need(RIGHT) <= fit.column_room(RIGHT)
    assert viewport_heights_ok(win) == []
    assert sorted(fit.auto_tabbed()) and set(fit.auto_tabbed()) <= {d.objectName() for d in docks}


def test_happy_room_back_stacks_the_auto_tabbed_docks_in_their_order(plain):
    win, docks, fit = plain(4, size=(900, 1400))
    before = column_order(win)
    assert len(before) == 4
    hold(win, 900, 520)
    fit.fit_now()
    pump()
    assert len(shown(win, RIGHT)) < 4
    hold(win, 900, 1200)
    assert fit.fit_now() is True
    pump()
    assert all(not tabbed(win, d) for d in docks)
    assert column_order(win) == before
    assert fit.auto_tabbed() == []
    assert overlaps(win) == []


def test_happy_docks_the_user_tabbed_stay_tabbed(plain):
    win, docks, fit = plain(4, size=(900, 1400))
    win.tabifyDockWidget(docks[0], docks[1])  # the user's own tab group
    pump()
    hold(win, 900, 420)
    fit.fit_now()
    hold(win, 900, 1600)
    fit.fit_now()
    pump()
    assert tabbed(win, docks[0]) == {"d1"}
    assert not tabbed(win, docks[2]) and not tabbed(win, docks[3])
    assert "d1" not in fit.auto_tabbed() and "d0" not in fit.auto_tabbed()


def test_edge_no_flapping_between_need_and_need_plus_margin(plain):
    from ui.dock_fit import UNTAB_MARGIN_PX

    win, docks, fit = plain(2, size=(900, 1400))
    hold(win, 900, 400)
    assert fit.fit_now() is True
    pump()
    tabs = sorted(fit.auto_tabbed())
    assert len(tabs) == 1
    # Exactly the room the stacked column needs, but less than need +
    # margin: nothing goes back.
    stacked_need = fit.column_need(RIGHT, stacked=True)
    grow = stacked_need - fit.column_room(RIGHT) + UNTAB_MARGIN_PX // 2
    hold(win, 900, 400 + grow)
    assert fit.fit_now() is False
    assert sorted(fit.auto_tabbed()) == tabs
    # The same check again changes nothing either way.
    assert fit.fit_now() is False
    hold(win, 900, 400 + grow + UNTAB_MARGIN_PX)
    assert fit.fit_now() is True
    assert fit.auto_tabbed() == []


def test_edge_nothing_changes_while_a_mouse_button_is_down(plain, monkeypatch):
    win, docks, fit = plain(4, size=(900, 1400))
    monkeypatch.setattr(fit, "pointer_busy", lambda: True)
    hold(win, 900, 420)
    assert fit.fit_now() is False
    assert all(not tabbed(win, d) for d in docks)
    monkeypatch.setattr(fit, "pointer_busy", lambda: False)
    # The settle timer runs the check once the button is up.
    fit.schedule()
    assert wait(lambda: any(tabbed(win, d) for d in docks), 3)
    assert overlaps(win) == []


def test_edge_a_resize_alone_brings_the_check(plain):
    win, docks, fit = plain(4, size=(900, 1400))
    assert not any(tabbed(win, d) for d in docks)
    hold(win, 900, 420)
    assert wait(lambda: any(tabbed(win, d) for d in docks), 3)
    hold(win, 900, 1600)
    assert wait(lambda: not any(tabbed(win, d) for d in docks), 3)


def test_edge_a_dock_taken_out_by_the_user_is_not_tabbed_again_for_comfort(plain):
    win, docks, fit = plain(3)
    hold(win, 900, 470)
    fit.fit_now()
    pump()
    (moved,) = [d for d in docks if d.objectName() in fit.auto_tabbed()][:1]
    # The user drags it out of the tab group to the end of the column.
    win.removeDockWidget(moved)
    win.addDockWidget(RIGHT, moved, VERTICAL)
    moved.show()
    pump()
    assert not tabbed(win, moved)
    fit.fit_now()
    pump()
    assert not tabbed(win, moved), "tabbed again against the user"
    assert moved.objectName() not in fit.auto_tabbed()
    # Too small even for the docks' title bars: overlap is never allowed.
    hold(win, 900, 2 * moved.minimumSizeHint().height())
    fit.fit_now()
    pump()
    assert overlaps(win) == []


def test_edge_a_closed_anchor_keeps_the_record_and_the_dock_returns_later(plain):
    win, docks, fit = plain(3)
    hold(win, 900, 470)
    fit.fit_now()
    pump()
    record = fit.session_state()[0]
    anchor = win.findChild(QDockWidget, record["anchor"])
    anchor.close()
    pump()
    fit.fit_now()
    assert record["dock"] in fit.auto_tabbed()
    anchor.show()
    hold(win, 900, 1600)
    fit.fit_now()
    pump()
    assert all(not tabbed(win, d) for d in docks)
    assert overlaps(win) == []


def test_edge_floating_and_moved_away_docks_are_not_in_the_column(plain):
    win, docks, fit = plain(4)
    docks[3].setFloating(True)
    holder = QWidget(win)
    docks[2].setParent(holder)  # a panel laid out elsewhere (a workspace)
    pump()
    names = [d.objectName() for d in fit.column_docks(RIGHT)]
    assert names == ["d0", "d1"]
    hold(win, 900, 300)
    fit.fit_now()
    assert docks[3].isFloating()
    assert docks[2].parentWidget() is holder


def test_happy_the_room_is_the_column_as_qt_lays_it_out(plain):
    """column_room is the height Qt gives the right column: from the top
    of the dock area to the status bar (the right column owns the
    bottom-right corner), with and without a bottom dock."""
    win, docks, fit = plain(2, min_height=40)
    for with_bottom in (False, True):
        if with_bottom:
            bottom = QDockWidget("bottom", win)
            bottom.setObjectName("bottom")
            bottom.setWidget(QLabel("bottom"))
            win.addDockWidget(BOTTOM, bottom)
        hold(win, 900, 700)
        win.resizeDocks(docks, [100, 100], VERTICAL)
        pump()
        column = sorted(shown(win, RIGHT), key=lambda d: d.y())
        span = column[-1].geometry().bottom() - column[0].geometry().top() + 1
        assert fit.column_room(RIGHT) == span
        assert column[-1].geometry().bottom() + 1 == win.statusBar().geometry().top()


def test_happy_the_left_column_room_stops_above_the_bottom_area(plain):
    win, docks, fit = plain(1, min_height=40)
    left = [QDockWidget(f"l{n}", win) for n in range(2)]
    for n, dock in enumerate(left):
        dock.setObjectName(f"l{n}")
        dock.setWidget(QLabel("left"))
        win.addDockWidget(LEFT, dock)
    bottom = QDockWidget("bottom", win)
    bottom.setObjectName("bottom")
    bottom.setWidget(QLabel("bottom"))
    win.addDockWidget(BOTTOM, bottom)
    hold(win, 900, 700)
    pump()
    column = sorted(shown(win, LEFT), key=lambda d: d.y())
    span = column[-1].geometry().bottom() - column[0].geometry().top() + 1
    assert fit.column_room(LEFT) == span
    assert column[-1].geometry().bottom() < bottom.geometry().top()


def test_sad_bad_session_entries_are_ignored(plain):
    from ui.dock_fit import MAX_RECORDS

    win, docks, fit = plain(2)
    for value in (None, "x", 5, {"dock": "d1"}, [1, None, "d1"],
                  [{"dock": 1, "anchor": "d0"}], [{"dock": "d1", "anchor": ["d0"]}],
                  [{"dock": "d1", "anchor": "d1"}], [{"dock": "", "anchor": "d0"}],
                  [{"dock": "d1", "anchor": "d0", "after": 3}]):
        fit.load_session_state(value)
        assert fit.auto_tabbed() == [], value
    many = [{"dock": f"x{n}", "anchor": "d0"} for n in range(MAX_RECORDS + 10)]
    fit.load_session_state(many)
    assert len(fit.auto_tabbed()) == MAX_RECORDS
    # A record whose dock is not tabbed with its anchor is dropped at the check.
    fit.load_session_state([{"dock": "d1", "anchor": "d0", "after": "d0", "below": True}])
    fit.fit_now()
    assert fit.auto_tabbed() == []
    # Records of docks that do not exist are not written back.
    fit.load_session_state([{"dock": "gone", "anchor": "d0"}])
    assert fit.session_state() == []


def test_happy_session_state_survives_save_and_restore_state(plain):
    win, docks, fit = plain(4)
    win.tabifyDockWidget(docks[0], docks[1])  # the user's
    pump()
    hold(win, 900, 470)
    fit.fit_now()
    pump()
    state = win.saveState()
    records = json.loads(json.dumps(fit.session_state()))
    assert records
    win2, docks2, fit2 = plain(4)
    hold(win2, 900, 470)
    assert win2.restoreState(state)
    fit2.load_session_state(records)
    pump()
    assert sorted(fit2.auto_tabbed()) == sorted(r["dock"] for r in records)
    hold(win2, 900, 1600)
    fit2.fit_now()
    pump()
    assert tabbed(win2, docks2[0]) == {"d1"}
    assert not tabbed(win2, docks2[2]) and not tabbed(win2, docks2[3])
    assert overlaps(win2) == []


def test_sad_a_window_without_room_for_one_dock_changes_nothing_harmful(plain):
    win, docks, fit = plain(1)
    hold(win, 900, 120)
    assert fit.fit_now() is False
    assert fit.auto_tabbed() == []


# -- the real window ----------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


def make_window(monkeypatch, size=(1600, 980)):
    from core import multimedia_probe
    from tests.test_media_player_late_engine import OK
    from ui.main_window import MainWindow

    monkeypatch.setattr(multimedia_probe, "probe", lambda *a, **k: OK)
    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(*size)
    win.show()
    pump(0.2)
    return win


def close_window(win) -> None:
    if not sip.isdeleted(win):
        for panel in list(win._agent_dock.panels()):
            panel.closing = True
        win.close()
        win.deleteLater()
        pump()


@pytest.fixture
def window(monkeypatch):
    win = make_window(monkeypatch)
    yield win
    close_window(win)


def media_player(win):
    from core import extensions as EX
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
    """Analysis, Agent dock, two detached conversations and the Media
    Player: five docks in the right column."""
    win._analysis_dock.show()
    win._agent_dock.show()
    agents = [win._agent_dock.new_window() for _ in range(2)]
    player = media_player(win)
    pump(0.2)
    return agents, player


def settle(win) -> None:
    win._dock_fit.fit_now()
    pump(0.2)


def test_e2e_the_right_column_reaches_the_bottom_edge(window):
    assert window.corner(Qt.Corner.BottomRightCorner) == RIGHT
    assert window.corner(Qt.Corner.BottomLeftCorner) == BOTTOM
    window._agent_dock.show()
    pump(0.2)
    transfers = window._transfer_dock
    agent = window._agent_dock
    assert transfers.isVisible() and agent.isVisible()
    # The Agent dock goes down to the status bar; the bottom area ends
    # left of the right column (as wide as the panes and the left column).
    assert agent.geometry().bottom() + 1 == window.statusBar().geometry().top()
    assert transfers.geometry().right() < agent.geometry().left()
    assert transfers.geometry().left() == 0
    assert overlaps(window) == []


def test_e2e_five_right_docks_are_tabbed_to_fit_1600x980_and_1280x800(window):
    agents, player = crowd(window)
    for size in ((1600, 980), (1280, 800)):
        hold(window, *size)
        settle(window)
        assert overlaps(window) == [], size
        assert viewport_heights_ok(window) == [], size
        assert window._dock_fit.column_need(RIGHT) <= window._dock_fit.column_room(RIGHT), size
        assert window._dock_fit.auto_tabbed(), size
        # Every dock of the column is still there: shown or a tab of a group.
        for dock in (window._analysis_dock, window._agent_dock, *agents, player):
            assert dock.isVisible() and not dock.isFloating()
            assert window.dockWidgetArea(dock) == RIGHT


def test_e2e_room_back_the_column_is_stacked_again(window):
    agents, player = crowd(window)
    hold(window, 1600, 1900)
    settle(window)
    before = column_order(window)
    assert len(before) == 5
    hold(window, 1280, 800)
    settle(window)
    assert window._dock_fit.auto_tabbed()
    hold(window, 1600, 1900)
    settle(window)
    assert window._dock_fit.auto_tabbed() == []
    for dock in (window._analysis_dock, window._agent_dock, *agents, player):
        assert not tabbed(window, dock)
    assert column_order(window) == before
    assert overlaps(window) == []


def test_e2e_a_new_panel_in_a_full_column_is_tabbed_without_a_call(window):
    agents, player = crowd(window)
    hold(window, 1600, 1900)
    settle(window)
    assert window._dock_fit.auto_tabbed() == []
    hold(window, 1600, 980)
    pump(0.1)
    # The resize and the new panel bring the check themselves.
    window._agent_dock.new_window()
    assert wait(lambda: bool(window._dock_fit.auto_tabbed()) and overlaps(window) == [], 5)


def test_e2e_user_tabs_stay_and_auto_tabs_go_after_floating(window):
    agents, player = crowd(window)
    hold(window, 1600, 1900)
    settle(window)
    assert window._dock_fit.auto_tabbed() == []
    window.tabifyDockWidget(window._analysis_dock, window._agent_dock)  # the user's
    pump(0.2)
    hold(window, 1280, 800)
    settle(window)
    auto = window._dock_fit.auto_tabbed()
    assert auto
    # An auto-tabbed panel floated and docked again with its float button.
    name = auto[-1]
    dock = window.findChild(QDockWidget, name)
    dock.titleBarWidget()._float_btn.click()
    pump(0.2)
    assert dock.isFloating()
    dock.titleBarWidget()._float_btn.click()
    pump(0.2)
    settle(window)
    assert overlaps(window) == []
    hold(window, 1600, 1900)
    settle(window)
    assert tabbed(window, window._analysis_dock) == {"axAgentDock"}
    for other in (*agents, player):
        assert not tabbed(window, other)
    assert overlaps(window) == []


def test_e2e_a_panel_on_a_workspace_is_never_part_of_a_column(window):
    agents, player = crowd(window)
    ws = window.current_workspace()
    window.move_extension_panel(player, ws)
    pump(0.2)
    hold(window, 1280, 800)
    settle(window)
    assert player.objectName() not in window._dock_fit.auto_tabbed()
    assert player not in window._dock_fit.column_docks(RIGHT)
    assert window.extension_panel_workspace(player) is ws
    assert overlaps(window) == []
    # Back on All Workspaces in a full column: tabbed like any dock.
    window.move_extension_panel(player, None)
    pump(0.2)
    settle(window)
    assert player in window._dock_fit.column_docks(RIGHT)
    assert overlaps(window) == []
    assert viewport_heights_ok(window) == []


def test_e2e_auto_tabs_survive_a_restart_and_go_back_when_there_is_room(monkeypatch, own_home):
    win = make_window(monkeypatch)
    try:
        crowd(win)
        hold(win, 1280, 800)
        settle(win)
        auto = sorted(win._dock_fit.auto_tabbed())
        assert auto
        win._save_session()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    assert sorted(r["dock"] for r in data["window"]["auto_tabbed_docks"]) == auto

    win = make_window(monkeypatch, size=(1280, 800))
    try:
        media_player(win)
        assert win.restore_layout_on_start()
        pump(0.3)
        assert win.corner(Qt.Corner.BottomRightCorner) == RIGHT
        hold(win, 1280, 800)
        settle(win)
        assert overlaps(win) == []
        assert set(auto) <= set(win._dock_fit.auto_tabbed()) | {
            d.objectName() for d in docked(win, RIGHT) if not tabbed(win, d)}
        hold(win, 1600, 1900)
        settle(win)
        assert win._dock_fit.auto_tabbed() == []
        assert all(not tabbed(win, d) for d in docked(win, RIGHT))
        assert overlaps(win) == []
    finally:
        close_window(win)


def test_e2e_a_dock_state_of_an_older_version_restores_sanely(monkeypatch, own_home):
    """An older axross saved its dock state with the bottom area owning
    both bottom corners: restored, the right column still reaches the
    bottom edge and nothing overlaps."""
    win = make_window(monkeypatch)
    try:
        crowd(win)
        win.setCorner(Qt.Corner.BottomRightCorner, BOTTOM)  # as before
        win._dock_fit.load_session_state([])
        pump(0.2)
        win._save_session()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    data["window"].pop("auto_tabbed_docks", None)  # older versions had none
    (own_home / "session.json").write_text(json.dumps(data))

    win = make_window(monkeypatch, size=(1280, 800))
    try:
        media_player(win)
        assert win.restore_layout_on_start()
        pump(0.3)
        assert win.corner(Qt.Corner.BottomRightCorner) == RIGHT
        for size in ((1280, 800), (1600, 980)):
            hold(win, *size)
            settle(win)
            assert overlaps(win) == [], size
            assert viewport_heights_ok(win) == [], size
        assert win._agent_dock.geometry().bottom() + 1 <= win.statusBar().geometry().top()
    finally:
        close_window(win)


def test_e2e_closing_docks_gives_the_room_back(window):
    agents, player = crowd(window)
    hold(window, 1600, 980)
    settle(window)
    assert window._dock_fit.auto_tabbed()
    for panel in agents:
        panel.closing = True
    window._agent_dock.attach_panel(agents[0])
    player.close()
    pump(0.2)
    settle(window)
    # Analysis, Agent dock and one conversation fit 1600x980 stacked; only
    # the closed player may keep its record (it returns to its tab group
    # when shown, and comes apart then).
    assert set(window._dock_fit.auto_tabbed()) <= {player.objectName()}
    assert all(not tabbed(window, d) for d in docked(window, RIGHT))
    assert overlaps(window) == []
    assert viewport_heights_ok(window) == []


def test_e2e_a_malformed_entry_in_session_json_is_ignored(monkeypatch, own_home):
    win = make_window(monkeypatch)
    try:
        win._save_session()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    for value in ("x", {"dock": "axAgentDock"}, [[1, 2]], [{"dock": "axAgentDock"}] * 500):
        data["window"]["auto_tabbed_docks"] = value
        (own_home / "session.json").write_text(json.dumps(data))
        win = make_window(monkeypatch)
        try:
            assert win.restore_layout_on_start(), value
            assert win._dock_fit.auto_tabbed() == []
            settle(win)
            assert overlaps(win) == []
        finally:
            close_window(win)


def test_edge_the_bottom_area_beside_the_right_column_keeps_a_narrow_window(window):
    """The bottom area now sits beside the right column, so its smallest
    width adds to the column's: the Terminal's row of controls (694 px)
    made a window with a right dock at least ~890 px wide. In a scroll
    area like the other panels, the Terminal scrolls instead, and a
    720 px window with the Analysis dock still fits."""
    window._analysis_dock.show()
    pump(0.2)
    assert window.minimumSizeHint().width() <= 720, window.minimumSizeHint()
    window.resize(720, 720)
    pump(0.2)
    assert window.width() == 720
    assert overlaps(window) == []
    terminal = window._terminal_dock
    terminal.raise_()
    window.resize(1400, 900)
    pump(0.3)
    # With room the terminal fills its dock as before, without scrolling.
    from ui.dock_frame import PanelFrame

    frame = terminal.findChild(PanelFrame, "panelFrame")
    assert frame is not None and frame.parentWidget() is terminal
    assert frame.content().width() == frame.viewport().width()
    assert not frame.horizontalScrollBar().isVisible()
