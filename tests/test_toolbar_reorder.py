"""The toolbar buttons can be moved by drag and drop, and the order is kept.

Operator: *„die icons in der icon bar sollen verschiebbar sein"*. Before,
both bars were fixed: their order was the order of the code in
ui/main_window.py (_setup_toolbar, _add_feature_buttons, _add_tool_buttons).

Now a button is pressed, dragged along its bar and dropped between two
others; the order of each bar is stored in session.json (``window`` ->
``toolbar_order``) and comes back on the next start. A tool added by a later
version (not in the stored order) appears at its default place, an id the
stored order names but this version does not have is ignored, and the
toolbar's right-click menu has "Reset Toolbar Order". The wrap of the Tools
bar to a second row on a narrow window keeps working.
"""

from __future__ import annotations

import json
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
from PyQt6.QtWidgets import QApplication, QToolBar  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import toolbar_order as TO  # noqa: E402

APP = app()
SEP = TO.SEPARATOR


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.close_windows()
    s.restore()


def _open(stores, width: int = 2400):
    win = stores.make_window()
    win.resize(width, 700)
    win.show()
    pump()
    return win


def _bar(win, title: str) -> QToolBar:
    return next(tb for tb in win.findChildren(QToolBar) if tb.windowTitle() == title)


def _ids(bar) -> list[str]:
    return [a.property(TO.TOOL_ID_PROPERTY) for a in bar.actions() if not a.isSeparator()]


def _action(bar, tool_id: str):
    return next(a for a in bar.actions() if a.property(TO.TOOL_ID_PROPERTY) == tool_id)


def _stored(stores):
    if not stores.session.exists():
        return None
    return json.loads(stores.session.read_text()).get("window", {}).get(TO.ORDER_KEY)


def _drag(bar, tool_id: str, before_id: str | None, *, steps: int = 6) -> None:
    """Press on *tool_id*, move along the bar in *steps*, release just left
    of *before_id* (None: right of the last button) - real mouse events
    through the window system, as a user's drag."""
    source = bar.widgetForAction(_action(bar, tool_id))
    if before_id is None:
        last = [a for a in bar.actions() if bar.widgetForAction(a).isVisible()][-1]
        geo = bar.widgetForAction(last).geometry()
        target_in_bar = QPoint(geo.right() + 4, geo.center().y())
    else:
        geo = bar.widgetForAction(_action(bar, before_id)).geometry()
        target_in_bar = QPoint(geo.left() + 3, geo.center().y())
    start = source.rect().center()
    end = source.mapFrom(bar, target_in_bar)
    QTest.mousePress(source, Qt.MouseButton.LeftButton, pos=start)
    for i in range(1, steps + 1):
        QTest.mouseMove(source, start + (end - start) * i / steps)
        pump(0.01)
    QTest.mouseRelease(source, Qt.MouseButton.LeftButton, pos=end)
    pump()


# --- the order logic (ui.toolbar_order) -------------------------------------


def test_happy_merge_keeps_the_stored_order() -> None:
    default = ["a", "b", SEP, "c", "d"]
    assert TO.merge(["c", "a", SEP, "d", "b"], default) == ["c", "a", SEP, "d", "b"]


def test_happy_merge_puts_a_new_tool_after_its_default_neighbour() -> None:
    default = ["a", "b", SEP, "c", "new", "d"]
    assert TO.merge(["d", "c", SEP, "b", "a"], default) == ["d", "c", "new", SEP, "b", "a"]


def test_happy_parse_reads_a_list_per_bar() -> None:
    value = {"axMainToolbar": ["a", SEP, "b"], "axToolsToolbar": ["c"]}
    assert TO.parse(value) == value


def test_sad_merge_ignores_unknown_and_duplicate_ids() -> None:
    default = ["a", "b", "c"]
    assert TO.merge(["gone", "c", "c", "a", 7, None, "b"], default) == ["c", "a", "b"]


@pytest.mark.parametrize("value", [None, "a,b", 3, ["a"], {"bar": "a"}, {"bar": [1, 2]},
                                   {5: ["a"]}, {"bar": ["a", ["b"]]}])
def test_sad_parse_drops_what_is_not_a_list_of_ids(value) -> None:
    parsed = TO.parse(value)
    assert all(isinstance(k, str) and all(isinstance(i, str) for i in v)
               for k, v in parsed.items())
    assert "bar" not in parsed or parsed["bar"] == []


def test_edge_merge_without_a_stored_order_is_the_default() -> None:
    default = ["a", SEP, "b"]
    assert TO.merge(None, default) == default
    assert TO.merge([], default) == default


def test_edge_merge_tidies_separators_and_a_new_first_tool_goes_first() -> None:
    default = ["new", "a", SEP, "b"]
    assert TO.merge([SEP, SEP, "b", SEP, SEP, "a", SEP], default) == ["new", "b", SEP, "a"]


def test_edge_merge_of_only_unknown_ids_is_the_default() -> None:
    assert TO.merge(["x", "y"], ["a", SEP, "b"]) == ["a", SEP, "b"]


# --- the real window --------------------------------------------------------


def test_happy_every_button_has_a_tool_id(stores) -> None:
    win = _open(stores)
    for title in ("Main", "Tools"):
        ids = _ids(_bar(win, title))
        assert all(ids), (title, ids)
        assert len(ids) == len(set(ids)), title


def test_happy_e2e_drag_a_tool_and_the_next_start_has_the_order(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    before = _ids(tools)
    assert before.index("settings") > before.index("agent")
    _drag(tools, "settings", "agent")
    after = _ids(tools)
    assert after[0] == "settings"
    assert after[1:] == [i for i in before if i != "settings"]
    assert _stored(stores)["axToolsToolbar"][0] == "settings"
    # The bar that was not touched is not stored: a later default applies.
    assert "axMainToolbar" not in _stored(stores)
    win.close()
    pump()
    again = _open(stores)
    assert _ids(_bar(again, "Tools")) == after
    # The moved button still works (it is the menu's own action).
    assert _action(_bar(again, "Tools"), "settings") is again._settings_action


def test_happy_e2e_drag_to_the_right_end_and_across_a_separator(stores) -> None:
    win = _open(stores)
    main = _bar(win, "Main")
    _drag(main, "quick-connect", None)
    assert _ids(main)[-1] == "quick-connect"
    _drag(main, "refresh", "split-h")  # from the transfer group into the layout group
    ids = _ids(main)
    assert ids.index("refresh") == ids.index("split-h") - 1
    stored = _stored(stores)["axMainToolbar"]
    assert stored[-1] == "quick-connect" and SEP in stored


def test_happy_e2e_reset_toolbar_order_from_the_right_click_menu(stores) -> None:
    win = _open(stores)
    tools, main = _bar(win, "Tools"), _bar(win, "Main")
    default_tools, default_main = _ids(tools), _ids(main)
    _drag(tools, "features", "agent")
    _drag(main, "duplicates", "quick-connect")
    assert _ids(tools) != default_tools and _ids(main) != default_main
    menu = win.createPopupMenu()
    reset = next(a for a in menu.actions() if a.text().replace("&", "") == "Reset Toolbar Order")
    reset.trigger()
    pump()
    assert _ids(tools) == default_tools and _ids(main) == default_main
    assert not _stored(stores)
    win.close()
    pump()
    assert _ids(_bar(_open(stores), "Tools")) == default_tools


def test_sad_a_click_without_a_drag_triggers_the_button_and_moves_nothing(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    order = _ids(tools)
    agent = _action(tools, "agent")
    win._agent_dock.hide()
    pump()
    button = tools.widgetForAction(agent)
    QTest.mouseClick(button, Qt.MouseButton.LeftButton, pos=button.rect().center())
    pump()
    assert win._agent_dock.isVisible()
    # A jitter below the drag distance is still a click.
    start = button.rect().center()
    QTest.mousePress(button, Qt.MouseButton.LeftButton, pos=start)
    QTest.mouseMove(button, start + QPoint(1, 0))
    QTest.mouseRelease(button, Qt.MouseButton.LeftButton, pos=start + QPoint(1, 0))
    pump()
    assert not win._agent_dock.isVisible()
    assert _ids(tools) == order
    assert _stored(stores) is None


def test_sad_a_drag_does_not_trigger_the_button(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    win._agent_dock.hide()
    pump()
    _drag(tools, "agent", "settings")
    assert not win._agent_dock.isVisible()
    assert not _action(tools, "agent").isChecked()


def test_sad_unknown_ids_are_ignored_and_new_tools_keep_their_default_place(stores) -> None:
    win = _open(stores)
    default = _ids(_bar(win, "Tools"))
    win.close()
    pump()
    # An order stored by "another version": settings first, a tool this
    # version does not have, and the Trash button missing (new for it).
    stored = ["settings", "no-such-tool"] + [i for i in default if i not in ("settings", "trash")]
    stores.session.write_text(json.dumps({"window": {TO.ORDER_KEY: {"axToolsToolbar": stored}}}))
    again = _open(stores)
    ids = _ids(_bar(again, "Tools"))
    assert ids[0] == "settings"
    assert "no-such-tool" not in ids
    assert ids.index("trash") == ids.index("tag") + 1  # its default neighbour
    assert sorted(ids) == sorted(default)


@pytest.mark.parametrize("value", ["settings,agent", 7, ["settings"],
                                   {"axToolsToolbar": "settings"}, {"axToolsToolbar": [1, 2]}])
def test_sad_a_broken_stored_order_gives_the_default(stores, value) -> None:
    win = _open(stores)
    default = (_ids(_bar(win, "Main")), _ids(_bar(win, "Tools")))
    win.close()
    pump()
    stores.session.write_text(json.dumps({"window": {TO.ORDER_KEY: value}}))
    again = _open(stores)
    assert (_ids(_bar(again, "Main")), _ids(_bar(again, "Tools"))) == default


def test_edge_a_drop_on_its_own_place_changes_and_stores_nothing(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    order = _ids(tools)
    _drag(tools, "terminal", order[order.index("terminal") + 1])  # left of its right neighbour
    assert _ids(tools) == order
    assert _stored(stores) is None


def test_edge_after_a_reorder_the_narrow_window_still_wraps_with_every_tool_visible(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    _drag(tools, "features", "agent")
    win.resize(900, 700)
    pump(0.1)
    assert win.toolBarBreak(tools)
    hidden = [a.property(TO.TOOL_ID_PROPERTY) for a in tools.actions()
              if not a.isSeparator() and not tools.widgetForAction(a).isVisible()]
    assert hidden == []
    win.resize(2400, 700)
    pump(0.1)
    assert not win.toolBarBreak(tools)


def test_edge_a_moved_button_can_be_dragged_again_and_keeps_its_icon(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    _drag(tools, "drives", "agent")
    _drag(tools, "drives", "settings")  # the button was rebuilt by the first move
    ids = _ids(tools)
    assert ids.index("drives") == ids.index("settings") - 1
    assert not _action(tools, "drives").icon().isNull()
    theme = win._current_theme
    win._apply_theme("hacker")
    pump()
    try:
        assert _ids(tools) == ids  # a theme switch re-icons, it does not reorder
    finally:
        win._apply_theme(theme)


def test_edge_the_drop_indicator_shows_only_while_dragging(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    source = tools.widgetForAction(_action(tools, "features"))
    target = tools.widgetForAction(_action(tools, "agent")).geometry()
    start = source.rect().center()
    end = source.mapFrom(tools, QPoint(target.left() + 3, target.center().y()))
    QTest.mousePress(source, Qt.MouseButton.LeftButton, pos=start)
    for i in range(1, 5):
        QTest.mouseMove(source, start + (end - start) * i / 4)
    indicator = win._toolbar_reorder["axToolsToolbar"].indicator
    assert indicator.isVisible()
    assert abs(indicator.geometry().center().x() - target.left()) <= 6
    QTest.mouseRelease(source, Qt.MouseButton.LeftButton, pos=end)
    pump()
    assert not indicator.isVisible()
    assert QApplication.instance() is not None


# --- a bare toolbar ---------------------------------------------------------


def _bare_bar(order: list[str]) -> QToolBar:
    bar = QToolBar()
    for item in order:
        if item == SEP:
            bar.addSeparator()
        else:
            bar.addAction(item).setProperty(TO.TOOL_ID_PROPERTY, item)
    return bar


def _raw(bar) -> list[str]:
    return [SEP if a.isSeparator() else a.property(TO.TOOL_ID_PROPERTY) for a in bar.actions()]


def test_happy_apply_order_rearranges_and_reuses_the_separators() -> None:
    bar = _bare_bar(["a", "b", SEP, "c"])
    separator = next(a for a in bar.actions() if a.isSeparator())
    TO.apply_order(bar, ["c", SEP, "b", "a"])
    assert _raw(bar) == ["c", SEP, "b", "a"]
    assert separator in bar.actions()


def test_sad_apply_order_keeps_actions_the_order_does_not_name() -> None:
    bar = _bare_bar(["a", "b", "c"])
    plain = bar.addAction("no id")
    TO.apply_order(bar, ["c", "a", "gone"])
    assert _raw(bar)[:3] == ["c", "a", "b"]
    assert bar.actions()[-1] is plain


def test_edge_dragging_a_group_empty_leaves_no_double_separator() -> None:
    bar = _bare_bar(["a", SEP, "b", SEP, "c"])
    reorder = TO.ToolbarReorder(bar)
    moved = []
    reorder.reordered.connect(moved.append)
    b = next(a for a in bar.actions() if a.property(TO.TOOL_ID_PROPERTY) == "b")
    reorder._move(b, None)
    assert _raw(bar) == ["a", SEP, "c", "b"]
    assert moved == [bar]
    reorder._move(b, None)  # already last: nothing happens
    assert moved == [bar]


def test_happy_e2e_right_click_on_a_button_offers_reset_toolbar_order(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    default = _ids(tools)
    _drag(tools, "features", "agent")
    button = tools.widgetForAction(_action(tools, "trash"))
    from PyQt6.QtGui import QContextMenuEvent

    APP.sendEvent(button, QContextMenuEvent(QContextMenuEvent.Reason.Mouse,
                                            button.rect().center(),
                                            button.mapToGlobal(button.rect().center())))
    pump()
    popup = QApplication.activePopupWidget()
    assert popup is not None
    reset = next(a for a in popup.actions() if a.text().replace("&", "") == "Reset Toolbar Order")
    popup.close()
    reset.trigger()
    pump()
    assert _ids(tools) == default


# --- teardown: a filter whose Python state is gone --------------------------
# Found in the importer scope (tests/test_media_viewer_e2e.py, 4 of 10 runs
# segfaulted in PyQt after every test passed; 0 of 10 on the base tree).
# The filter held its bar strongly while the bar owns the filter - a cycle
# the collector clears, after which the bar's teardown events still reach
# the filter (as tests/test_window_move.py found for TopRowMover).

import subprocess  # noqa: E402
import textwrap  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_happy_the_filter_holds_no_strong_reference_to_its_bar() -> None:
    bar = _bare_bar(["a", "b"])
    reorder = TO.ToolbarReorder(bar)
    assert all(v is not bar for v in vars(reorder).values())
    assert reorder.bar is bar


def test_sad_a_filter_whose_state_is_gone_lets_the_events_pass() -> None:
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
        from PyQt6.QtGui import QMouseEvent
        from PyQt6.QtWidgets import QApplication, QToolBar, QToolButton
        app = QApplication([])
        from ui import toolbar_order as TO
        bar = QToolBar()
        for name in ("a", "b"):
            bar.addAction(name).setProperty(TO.TOOL_ID_PROPERTY, name)
        bar.show()
        reorder = TO.ToolbarReorder(bar)
        button = bar.widgetForAction(bar.actions()[0])
        reorder.__dict__.clear()
        left, none = Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton
        for kind, btn, btns in ((QEvent.Type.MouseButtonPress, left, left),
                                (QEvent.Type.MouseMove, none, left),
                                (QEvent.Type.MouseButtonRelease, left, none)):
            QApplication.sendEvent(button, QMouseEvent(kind, QPointF(5, 5), QPointF(50, 50),
                                                       btn, btns, Qt.KeyboardModifier.NoModifier))
        for kind in (QEvent.Type.Hide, QEvent.Type.Leave, QEvent.Type.Show):
            QApplication.sendEvent(button, QEvent(kind))
        print("alive", reorder.indicator is None, reorder.bar is bar)
    """)
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=60, env=env)
    assert r.returncode == 0, r.stderr[-800:]
    assert "alive True True" in r.stdout


# The filter is a Python object: every event of every button it watches is
# a call into Python. A button being destroyed sends itself a Destroy event
# when it is half gone, and those calls made PyQt crash at exit (traced:
# 108 Destroy events to the filter after the last test, then a SIGSEGV in
# sip_api_get_address from PyQt's cleanup_on_exit; 7 of 15 runs of
# tests/test_media_viewer_e2e.py, 0 of 12 with a C++ QObject as the filter).
# So the buttons are watched only while the bar is shown.


def _filter_calls(monkeypatch) -> list:
    calls: list = []
    original = TO.ToolbarReorder.eventFilter

    def spy(self, obj, event):
        calls.append(event.type())
        return original(self, obj, event)

    monkeypatch.setattr(TO.ToolbarReorder, "eventFilter", spy)
    return calls


def _poke(win) -> None:
    from PyQt6.QtCore import QEvent

    tools = _bar(win, "Tools")
    APP.sendEvent(tools.widgetForAction(_action(tools, "agent")), QEvent(QEvent.Type.User))


def test_happy_the_buttons_are_watched_while_the_window_is_shown(stores, monkeypatch) -> None:
    from PyQt6.QtCore import QEvent

    calls = _filter_calls(monkeypatch)
    win = _open(stores)
    _poke(win)
    assert QEvent.Type.User in calls


def test_sad_a_window_never_shown_has_no_filter_on_its_buttons(stores, monkeypatch) -> None:
    calls = _filter_calls(monkeypatch)
    win = stores.make_window()
    pump()
    _poke(win)
    assert calls == []


def test_edge_hiding_the_window_takes_the_filter_off_and_showing_puts_it_back(
    stores, monkeypatch
) -> None:
    from PyQt6.QtCore import QEvent

    calls = _filter_calls(monkeypatch)
    win = _open(stores)
    win.hide()
    pump()
    calls.clear()
    _poke(win)
    assert calls == []
    win.show()
    pump()
    _poke(win)
    assert QEvent.Type.User in calls
    # And the drag works again after the round trip.
    tools = _bar(win, "Tools")
    _drag(tools, "features", "agent")
    assert _ids(tools)[0] == "features"


def test_edge_a_hidden_tools_bar_is_not_watched_until_shown_again(stores, monkeypatch) -> None:
    from PyQt6.QtCore import QEvent

    calls = _filter_calls(monkeypatch)
    win = _open(stores)
    tools = _bar(win, "Tools")
    tools.hide()
    pump()
    calls.clear()
    APP.sendEvent(tools.widgetForAction(_action(tools, "agent")), QEvent(QEvent.Type.User))
    assert calls == []
    tools.show()
    pump()
    _poke(win)
    assert QEvent.Type.User in calls
