"""The toolbar buttons are grouped by category, and each category has a colour.

Operator: *„außerdem sollten die icons in der svg icon menubar, nach thema
geordnet sein und die hintergrundfarbe entsprechend die kategorie oder ober
thema zeigen. z.b. kategories: fenster/windows/panes, media, llm,
extensions. dieses feature soll auch in settings konfigurierbar sein und auch
die farben dort setzbar. jede kategorie hat ihre eigene farbe."*

Before (0.13.133) the two bars held the buttons in the order of the code in
ui/main_window.py (_setup_toolbar, _add_feature_buttons, _add_tool_buttons):
media tools sat on both bars, the Terminal toggle on the Tools bar next to
the Agent, and no button showed what kind of tool it is.

Now every button has exactly one category (ui.toolbar_categories). With
grouping on (the default) the bars show one category after another with a
separator between them; inside a group the drag order still applies, and a
drag cannot leave its group. Each category's colour is a subtle rounded tint
behind its buttons; the tint never makes an icon hard to read. Edit >
Settings... > Toolbar switches grouping and colours and sets each colour.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QObject, QPoint, Qt  # noqa: E402
from PyQt6.QtGui import QColor  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QToolBar  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import icon_provider, themes  # noqa: E402
from ui import toolbar_categories as TC  # noqa: E402
from ui import toolbar_order as TO  # noqa: E402

APP = app()
SEP = TO.SEPARATOR
ROOT = Path(__file__).resolve().parents[1]

#: The bars as the code builds them (0.13.133): the plain order.
MAIN_PLAIN = [
    "quick-connect", "connection-manager", "shell", "bookmark", SEP,
    "split-h", "split-v", "close-pane", "toggle-layout", "equalize", "extract-pane", SEP,
    "copy-right", "move-right", "refresh", "duplicates", SEP,
    "thumbnails", "media-view", "find-index", "compare", "disk-usage", "metadata", "pack",
    "extensions",
]
TOOLS_PLAIN = [
    "agent", "analysis", "terminal", "find-files", "scripts", "console", "tag", "trash",
    "media-player", "audio-settings", "treemap", "drives", "settings", "features",
]
PLAIN = {"axMainToolbar": MAIN_PLAIN, "axToolsToolbar": TOOLS_PLAIN}

#: The grouped default, derived by hand from what each button does.
GROUPS = {
    "connections": ["quick-connect", "connection-manager", "bookmark"],
    "panes": ["shell", "split-h", "split-v", "close-pane", "toggle-layout", "equalize",
              "extract-pane", "terminal"],
    "files": ["copy-right", "move-right", "refresh", "duplicates", "find-index", "compare",
              "disk-usage", "metadata", "pack", "find-files", "tag", "trash"],
    "media": ["thumbnails", "media-view", "media-player", "audio-settings"],
    "llm": ["agent", "analysis"],
    "system": ["scripts", "console", "drives", "settings", "features"],
    "extensions": ["extensions", "treemap"],
}
MAIN_GROUPED = (GROUPS["connections"] + [SEP] + GROUPS["panes"] + [SEP] + GROUPS["files"])
TOOLS_GROUPED = (GROUPS["media"] + [SEP] + GROUPS["llm"] + [SEP] + GROUPS["system"] + [SEP]
                 + GROUPS["extensions"])

#: Every resolved theme: (id, toolbar background, text colour, icon tint).
THEMES = ["modern-light", "modern-dark", "classic", "default", "hacker", "amber"]


def _theme_colours(resolved: str) -> tuple[str, str, str | None]:
    background = themes.toolbar_background(resolved) or "#efefef"  # Fusion's light window
    tokens = themes.palette_tokens_for(resolved)
    text = tokens["text"] if tokens else "#000000"
    return background, text, themes.icon_tint_for(resolved)


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


# --- the categories ---------------------------------------------------------


def test_happy_every_button_of_the_bars_has_its_category() -> None:
    for category, ids in GROUPS.items():
        for tool in ids:
            assert TC.category_of(tool) == category, tool
    assert sorted(t for ids in GROUPS.values() for t in ids) == sorted(
        t for t in MAIN_PLAIN + TOOLS_PLAIN if t != SEP)


def test_happy_the_categories_have_english_titles_and_their_own_colours() -> None:
    titles = [c.title for c in TC.CATEGORIES]
    assert titles == ["Connections", "Windows & Panes", "Files & Search", "Media",
                      "LLM & Agent", "Tools & System", "Extensions"]
    colours = [c.colour for c in TC.CATEGORIES]
    assert len(set(colours)) == len(colours)
    assert all(themes.is_hex_colour(c) for c in colours)
    assert [c.id for c in TC.CATEGORIES] == list(GROUPS)


def test_sad_an_unknown_tool_belongs_to_extensions() -> None:
    for tool in ("an-extension-tool", "", None):
        assert TC.category_of(tool) == TC.EXTENSIONS


def test_edge_the_main_bar_holds_the_first_three_categories() -> None:
    bars = {c.id: c.bar for c in TC.CATEGORIES}
    assert {bars[c] for c in ("connections", "panes", "files")} == {"axMainToolbar"}
    assert {bars[c] for c in ("media", "llm", "system", "extensions")} == {"axToolsToolbar"}


# --- the grouped layout -----------------------------------------------------


def test_happy_grouped_layout_puts_one_category_after_another() -> None:
    assert TC.grouped_layout(PLAIN, {}) == {"axMainToolbar": MAIN_GROUPED,
                                            "axToolsToolbar": TOOLS_GROUPED}


def test_happy_grouped_layout_keeps_the_drag_order_inside_a_group() -> None:
    stored = {"llm": ["analysis", "agent"], "media": ["audio-settings", "thumbnails"]}
    layout = TC.grouped_layout(PLAIN, stored)
    tools = layout["axToolsToolbar"]
    assert tools[:5] == ["audio-settings", "thumbnails", "media-view", "media-player", SEP]
    assert tools[5:8] == ["analysis", "agent", SEP]


def test_happy_group_orders_reads_each_category_from_the_bars() -> None:
    orders = {"axMainToolbar": MAIN_GROUPED, "axToolsToolbar": TOOLS_GROUPED}
    assert TC.group_orders(orders) == GROUPS


def test_sad_a_stored_group_order_cannot_pull_a_tool_out_of_its_category() -> None:
    stored = {"llm": ["settings", "agent", "no-such-tool", SEP, "agent"], "nope": ["agent"]}
    layout = TC.grouped_layout(PLAIN, stored)
    assert layout["axToolsToolbar"] == TOOLS_GROUPED  # agent, analysis is the default


@pytest.mark.parametrize("value", [None, "llm", 3, ["agent"], {"llm": "agent"},
                                   {"llm": [1, 2]}, {"llm": ["agent", ["x"]]}, {7: ["agent"]},
                                   {"no-category": ["agent"]}])
def test_sad_parse_group_order_drops_what_is_not_a_list_of_ids(value) -> None:
    assert TC.parse_group_order(value) == {}


def test_edge_an_empty_category_leaves_no_double_separator() -> None:
    plain = {"axMainToolbar": ["quick-connect", SEP, "copy-right"],
             "axToolsToolbar": ["agent", "settings"]}
    layout = TC.grouped_layout(plain, {})
    assert layout == {"axMainToolbar": ["quick-connect", SEP, "copy-right"],
                      "axToolsToolbar": ["agent", SEP, "settings"]}


def test_edge_a_tool_new_in_a_later_version_appears_at_its_default_place() -> None:
    stored = {"panes": ["terminal", "shell", "split-h"]}  # stored before the rest existed
    panes = TC.grouped_layout(PLAIN, stored)["axMainToolbar"][4:12]
    assert panes[:3] == ["terminal", "shell", "split-h"]
    assert sorted(panes) == sorted(GROUPS["panes"])


def test_edge_a_bar_the_layout_does_not_know_gets_its_categories_on_the_first_bar() -> None:
    layout = TC.grouped_layout({"bare": ["agent", "quick-connect"]}, {})
    assert layout == {"bare": ["quick-connect", SEP, "agent"]}


# --- the stored style -------------------------------------------------------


def test_happy_parse_style_reads_the_three_keys() -> None:
    style = TC.parse_style({TC.GROUPING_KEY: False, TC.TINT_KEY: False,
                            TC.COLORS_KEY: {"media": "#FF0000"}})
    assert (style.grouping, style.tint) == (False, False)
    assert style.colour("media") == "#ff0000"
    assert style.colour("llm") == TC.default_colours()["llm"]
    assert style.overrides() == {"media": "#ff0000"}


def test_happy_style_values_round_trip_through_parse() -> None:
    style = TC.ToolbarStyle(grouping=False, tint=True, colours=(("files", "#123456"),))
    assert TC.parse_style(TC.style_values(style)) == style


@pytest.mark.parametrize("window", [None, "x", {TC.GROUPING_KEY: "no"}, {TC.TINT_KEY: 0},
                                    {TC.COLORS_KEY: "red"}, {TC.COLORS_KEY: ["#ffffff"]},
                                    {TC.COLORS_KEY: {"media": "#12"}},
                                    {TC.COLORS_KEY: {"nope": "#ffffff"}},
                                    {TC.COLORS_KEY: {"media": 5}}])
def test_sad_a_broken_stored_style_reads_as_the_default(window) -> None:
    assert TC.parse_style(window) == TC.ToolbarStyle()


def test_edge_a_stored_colour_equal_to_the_default_is_no_override() -> None:
    default = TC.default_colours()["media"]
    style = TC.parse_style({TC.COLORS_KEY: {"media": default.upper()}})
    assert style.overrides() == {} and style == TC.ToolbarStyle()


# --- the colours: readable in every theme -----------------------------------


def _icon_colours(category: str, resolved: str, mono: bool) -> list[str]:
    _, text, tint = _theme_colours(resolved)
    out = []
    for tool in GROUPS[category]:
        out.append(tint or (text if mono else icon_provider._ICON_COLORS.get(tool) or "#000000"))
    return out


@pytest.mark.parametrize("resolved", THEMES)
@pytest.mark.parametrize("mono", [False, True], ids=["colour-icons", "monochrome"])
def test_happy_the_tint_keeps_every_icon_readable_in_every_state(resolved, mono) -> None:
    background, text, _ = _theme_colours(resolved)
    for category in TC.CATEGORIES:
        icons = _icon_colours(category.id, resolved, mono)
        colours = TC.button_colours(category.colour, background, text, icons)
        for state in (colours.normal, colours.hover, colours.pressed):
            for icon in icons:
                before = themes.contrast_ratio(icon, background)
                after = themes.contrast_ratio(icon, state)
                need = TC.MIN_ICON_CONTRAST if before >= TC.MIN_ICON_CONTRAST \
                    else before * TC.WEAK_ICON_KEEP
                assert after >= need - 1e-9, (resolved, category.id, state, icon, before, after)


@pytest.mark.parametrize("resolved", THEMES)
def test_happy_the_tint_is_visible_and_the_states_differ(resolved) -> None:
    background, text, _ = _theme_colours(resolved)
    for category in TC.CATEGORIES:
        colours = TC.button_colours(category.colour, background, text,
                                    _icon_colours(category.id, resolved, False))
        # A tint: the normal fill is not the bar's background.
        assert colours.normal.lower() != background.lower(), (resolved, category.id)
        # Hover and checked carry a border that reads on the bar (WCAG 1.4.11).
        assert themes.contrast_ratio(colours.strong, background) >= TC.MIN_ICON_CONTRAST
        assert colours.strong != colours.soft


@pytest.mark.parametrize("colour", ["#000000", "#ffffff", "#f1c40f", "#00ff41", "#14161b"])
def test_edge_any_chosen_colour_keeps_the_icons_readable(colour) -> None:
    for resolved in THEMES:
        background, text, _ = _theme_colours(resolved)
        for mono in (False, True):
            icons = _icon_colours("files", resolved, mono)
            colours = TC.button_colours(colour, background, text, icons)
            for icon in icons:
                before = themes.contrast_ratio(icon, background)
                after = themes.contrast_ratio(icon, colours.pressed)
                need = TC.MIN_ICON_CONTRAST if before >= TC.MIN_ICON_CONTRAST \
                    else before * TC.WEAK_ICON_KEEP
                assert after >= need - 1e-9, (colour, resolved, icon)
            assert themes.contrast_ratio(colours.strong, background) >= TC.MIN_ICON_CONTRAST


def test_sad_blend_and_button_colours_refuse_what_is_not_a_colour() -> None:
    with pytest.raises(ValueError):
        TC.blend("red", "#ffffff", 0.5)
    with pytest.raises(ValueError):
        TC.button_colours("#12", "#ffffff", "#000000", [])


def test_edge_blend_ends_and_the_stylesheet_names_every_state() -> None:
    assert TC.blend("#000000", "#ffffff", 0) == "#000000"
    assert TC.blend("#000000", "#ffffff", 1) == "#ffffff"
    assert TC.blend("#000000", "#ffffff", 0.5) in ("#7f7f7f", "#808080")
    colours = TC.button_colours("#3498db", "#14161b", "#e6e8ee", ["#e6e8ee"])
    css = TC.stylesheet({"connections": colours})
    for selector in ('QToolButton[axCategory="connections"] {',
                     'QToolButton[axCategory="connections"]:hover {',
                     'QToolButton[axCategory="connections"]:checked'):
        assert selector in css
    assert colours.normal in css and colours.strong in css
    assert TC.stylesheet({}) == ""


def test_edge_toolbar_background_comes_from_the_theme_stylesheet() -> None:
    assert themes.toolbar_background("modern-dark") == themes.MODERN_DARK["bg"]
    assert themes.toolbar_background("modern-light") == themes.MODERN_LIGHT["bg"]
    assert themes.toolbar_background("classic") == "#181825"
    assert themes.toolbar_background("hacker") == "#0d0d0d"
    assert themes.toolbar_background("default") is None  # the desktop's palette


def test_edge_stroke_colour_follows_tint_and_monochrome() -> None:
    try:
        icon_provider.set_tint(None)
        icon_provider.set_monochrome(False)
        assert icon_provider.stroke_colour("agent") == icon_provider._ICON_COLORS["agent"]
        icon_provider.set_monochrome(True)
        assert icon_provider.stroke_colour("agent") == "#000000"
        icon_provider.set_tint("#00ff41")
        assert icon_provider.stroke_colour("agent") == "#00ff41"
    finally:
        icon_provider.set_tint(None)
        icon_provider.set_monochrome(False)


# --- the real window --------------------------------------------------------


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.close_windows()
    s.restore()


def _open(stores, width: int = 2600):
    win = stores.make_window()
    win.resize(width, 700)
    win.show()
    pump()
    return win


def _bar(win, title: str) -> QToolBar:
    return next(tb for tb in win.findChildren(QToolBar) if tb.windowTitle() == title)


def _raw(bar) -> list[str]:
    return [SEP if a.isSeparator() else a.property(TO.TOOL_ID_PROPERTY) for a in bar.actions()]


def _action(win, tool_id: str):
    for title in ("Main", "Tools"):
        for a in _bar(win, title).actions():
            if a.property(TO.TOOL_ID_PROPERTY) == tool_id:
                return _bar(win, title), a
    raise KeyError(tool_id)


def _button(win, tool_id: str):
    bar, action = _action(win, tool_id)
    return bar.widgetForAction(action)


def _session(stores) -> dict:
    if not stores.session.exists():
        return {}
    return json.loads(stores.session.read_text()).get("window", {})


def _fill(button) -> QColor:
    """The colour painted in the button's padding, left of the icon."""
    image = button.grab().toImage()
    return image.pixelColor(3, image.height() // 2)


def _close(a: QColor, b: str, tolerance: int = 3) -> bool:
    c = QColor(b)
    return all(abs(x - y) <= tolerance for x, y in
               ((a.red(), c.red()), (a.green(), c.green()), (a.blue(), c.blue())))


def _expected(win, category: str):
    return win.toolbar_button_colours()[category]


def _drag(bar, tool_id: str, before_id: str, *, steps: int = 6) -> None:
    def action(tid):
        return next(a for a in bar.actions() if a.property(TO.TOOL_ID_PROPERTY) == tid)

    source = bar.widgetForAction(action(tool_id))
    geo = bar.widgetForAction(action(before_id)).geometry()
    start = source.rect().center()
    end = source.mapFrom(bar, QPoint(geo.left() + 3, geo.center().y()))
    QTest.mousePress(source, Qt.MouseButton.LeftButton, pos=start)
    for i in range(1, steps + 1):
        QTest.mouseMove(source, start + (end - start) * i / steps)
        pump(0.01)
    QTest.mouseRelease(source, Qt.MouseButton.LeftButton, pos=end)
    pump()


def test_happy_e2e_the_bars_show_the_groups_with_separators(stores) -> None:
    win = _open(stores)
    assert _raw(_bar(win, "Main")) == MAIN_GROUPED
    assert _raw(_bar(win, "Tools")) == TOOLS_GROUPED
    for title in ("Main", "Tools"):
        bar = _bar(win, title)
        for action in bar.actions():
            if action.isSeparator():
                continue
            tool = action.property(TO.TOOL_ID_PROPERTY)
            assert bar.widgetForAction(action).property(TC.CATEGORY_PROPERTY) == \
                TC.category_of(tool), tool
    # The buttons still are the menus' own actions.
    assert _action(win, "settings")[1] is win._settings_action
    assert _action(win, "terminal")[1] is win._terminal_dock.toggleViewAction()


def test_happy_e2e_each_button_shows_its_category_colour(stores) -> None:
    win = _open(stores)
    seen = {}
    for category, ids in GROUPS.items():
        colours = _expected(win, category)
        for tool in ids:
            painted = _fill(_button(win, tool))
            # A checked toggle (the bookmark sidebar, an open dock) shows
            # the pressed tint.
            want = colours.pressed if _action(win, tool)[1].isChecked() else colours.normal
            assert _close(painted, want), (tool, painted.name(), want)
        seen[category] = colours.normal
        # The tint leans to the category's colour, away from the bar.
        cat = QColor(TC.default_colours()[category])
        bar_bg = QColor(win.toolbar_background())
        fill = QColor(colours.normal)

        def dist(a, b):
            return sum(abs(x - y) for x, y in ((a.red(), b.red()), (a.green(), b.green()),
                                                (a.blue(), b.blue())))

        assert dist(fill, cat) < dist(bar_bg, cat), category
    assert len(set(seen.values())) == len(seen)  # every category its own tint


def test_happy_e2e_a_checked_button_shows_its_underline(stores) -> None:
    win = _open(stores)
    bar, bookmarks = _action(win, "bookmark")
    bookmarks.setChecked(True)
    pump()
    button = bar.widgetForAction(bookmarks)
    image = button.grab().toImage()
    strong = _expected(win, "connections").strong
    assert _close(image.pixelColor(image.width() // 2, image.height() - 2), strong), strong
    bookmarks.setChecked(False)
    pump()
    image = button.grab().toImage()
    assert not _close(image.pixelColor(image.width() // 2, image.height() - 2), strong)


def test_happy_e2e_settings_colour_changes_the_tint_live_and_persists(stores) -> None:
    win = _open(stores)
    before = _fill(_button(win, "media-player"))
    dialog = stores.settings_dialog(win, "toolbar")
    page = dialog.page("toolbar")
    with mock.patch("ui.settings_dialog.QColorDialog.getColor",
                    return_value=QColor("#ff0000")) as picker:
        QTest.mouseClick(page.colour_buttons["media"], Qt.MouseButton.LeftButton)
    assert picker.called
    assert page.colour_buttons["media"].text() == "#ff0000"
    assert dialog.dirty_page_ids() == ["toolbar"]
    assert _close(_fill(_button(win, "media-player")), before.name())  # not before OK
    QTest.mouseClick(dialog.buttons.button(dialog.buttons.StandardButton.Ok),
                     Qt.MouseButton.LeftButton)
    pump()
    expected = _expected(win, "media")
    painted = _fill(_button(win, "media-player"))
    assert _close(painted, expected.normal) and not _close(painted, before.name())
    assert _session(stores)[TC.COLORS_KEY] == {"media": "#ff0000"}
    # Other categories keep theirs.
    assert _close(_fill(_button(win, "agent")), _expected(win, "llm").normal)
    stores.close_windows()
    again = _open(stores)
    assert again.toolbar_style().colour("media") == "#ff0000"
    assert _close(_fill(_button(again, "thumbnails")), _expected(again, "media").normal)
    assert _expected(again, "media").normal == expected.normal


def test_happy_e2e_grouping_off_restores_the_plain_order_and_back(stores) -> None:
    win = _open(stores)
    dialog = stores.settings_dialog(win, "toolbar")
    dialog.page("toolbar").grouping_check.setChecked(False)
    assert dialog.apply()
    pump()
    assert _raw(_bar(win, "Main")) == MAIN_PLAIN
    assert _raw(_bar(win, "Tools")) == TOOLS_PLAIN
    assert _session(stores)[TC.GROUPING_KEY] is False
    # Colours stay on without grouping.
    terminal = _action(win, "terminal")[1]
    want = _expected(win, "panes")
    assert _close(_fill(_button(win, "terminal")),
                  want.pressed if terminal.isChecked() else want.normal)
    assert _close(_fill(_button(win, "split-h")), want.normal)
    stores.close_windows()
    again = _open(stores)
    assert _raw(_bar(again, "Tools")) == TOOLS_PLAIN
    again.set_toolbar_style(TC.ToolbarStyle(grouping=True))
    pump()
    assert _raw(_bar(again, "Main")) == MAIN_GROUPED
    assert _raw(_bar(again, "Tools")) == TOOLS_GROUPED


def test_happy_e2e_colours_off_leaves_the_theme_look(stores) -> None:
    win = _open(stores)
    tint = _fill(_button(win, "agent"))
    win.set_toolbar_style(TC.ToolbarStyle(tint=False))
    pump()
    assert _bar(win, "Tools").styleSheet() == ""
    assert not _close(_fill(_button(win, "agent")), tint.name())
    assert _raw(_bar(win, "Tools")) == TOOLS_GROUPED  # grouping is its own switch
    assert _session(stores)[TC.TINT_KEY] is False


def test_happy_e2e_drag_inside_a_group_and_the_next_start_keeps_it(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    _drag(tools, "features", "scripts")
    assert _raw(tools)[_raw(tools).index("features") + 1] == "scripts"
    stored = _session(stores)[TC.GROUP_ORDER_KEY]
    assert stored == {"system": ["features", "scripts", "console", "drives", "settings"]}
    assert TO.ORDER_KEY not in _session(stores) or not _session(stores)[TO.ORDER_KEY]
    stores.close_windows()
    again = _open(stores)
    assert TC.group_orders({"axToolsToolbar": _raw(_bar(again, "Tools"))})["system"][0] == \
        "features"


def test_sad_e2e_a_drag_into_another_group_stops_at_its_own_group(stores) -> None:
    win = _open(stores)
    tools = _bar(win, "Tools")
    _drag(tools, "settings", "agent")  # Tools & System -> into LLM & Agent: clamped
    raw = _raw(tools)
    assert raw[raw.index("settings") - 1] == SEP  # first of its own group
    assert TC.group_orders({"x": raw})["system"][0] == "settings"
    assert TC.group_orders({"x": raw})["llm"] == ["agent", "analysis"]
    assert raw.count(SEP) == TOOLS_GROUPED.count(SEP)
    _drag(tools, "media-player", "extensions")  # Media -> past its group's end
    raw = _raw(tools)
    assert raw[raw.index("media-player") + 1] == SEP  # last of its own group


def test_sad_e2e_a_broken_stored_style_starts_grouped_and_coloured(stores) -> None:
    stores.session.write_text(json.dumps({"window": {
        TC.GROUPING_KEY: "no", TC.TINT_KEY: 0, TC.COLORS_KEY: {"media": "red"},
        TC.GROUP_ORDER_KEY: {"llm": "agent"}}}))
    win = _open(stores)
    assert _raw(_bar(win, "Tools")) == TOOLS_GROUPED
    assert _close(_fill(_button(win, "agent")), _expected(win, "llm").normal)
    assert win.toolbar_style() == TC.ToolbarStyle()


def test_edge_e2e_reset_toolbar_order_restores_the_default_inside_the_groups(stores) -> None:
    win = _open(stores)
    tools, main = _bar(win, "Tools"), _bar(win, "Main")
    _drag(tools, "analysis", "agent")
    _drag(main, "trash", "copy-right")
    assert _raw(tools) != TOOLS_GROUPED and _raw(main) != MAIN_GROUPED
    menu = win.createPopupMenu()
    reset = next(a for a in menu.actions() if a.text().replace("&", "") == "Reset Toolbar Order")
    reset.trigger()
    pump()
    assert _raw(tools) == TOOLS_GROUPED and _raw(main) == MAIN_GROUPED
    assert not _session(stores).get(TC.GROUP_ORDER_KEY)
    # The buttons rebuilt by the reset still carry their tint.
    assert _close(_fill(_button(win, "analysis")), _expected(win, "llm").normal)


def test_edge_e2e_an_extension_button_lands_in_extensions(stores, monkeypatch) -> None:
    from ui.main_window import MainWindow

    monkeypatch.setattr(MainWindow, "TOOLBAR_EXTENSIONS", MainWindow.TOOLBAR_EXTENSIONS + (
        ("usb", "user:usbtool", "USB Tool"),))
    win = _open(stores)
    raw = _raw(_bar(win, "Tools"))
    assert raw[-3:] == ["extensions", "treemap", "usb"]
    assert raw[raw.index("extensions") - 1] == SEP
    assert _button(win, "usb").property(TC.CATEGORY_PROPERTY) == TC.EXTENSIONS
    assert _close(_fill(_button(win, "usb")), _expected(win, "extensions").normal)


def test_edge_e2e_a_theme_switch_recolours_the_tint_for_the_new_background(stores) -> None:
    win = _open(stores)
    theme = win._current_theme
    try:
        for resolved in ("modern-light", "hacker", "classic"):
            win._apply_theme(resolved)
            pump()
            assert win.toolbar_background() == themes.toolbar_background(resolved)
            expected = _expected(win, "media")
            assert _close(_fill(_button(win, "media-view")), expected.normal), resolved
        win.set_monochrome_icons(True, store=False)
        pump()
        assert _close(_fill(_button(win, "media-view")), _expected(win, "media").normal)
    finally:
        win.set_monochrome_icons(False, store=False)
        win._apply_theme(theme)


def test_edge_e2e_the_bars_get_no_new_python_objects(stores) -> None:
    """The crash class of 0.13.130: a Python object on the buttons that
    outlives the bar. The colours are a style sheet and a property."""
    win = _open(stores)
    win.set_toolbar_style(TC.ToolbarStyle(colours=(("llm", "#00ff00"),)))
    win.set_toolbar_style(TC.ToolbarStyle(grouping=False))
    for title in ("Main", "Tools"):
        python_made = [type(c).__name__ for c in _bar(win, title).findChildren(QObject)
                       if not type(c).__module__.startswith("PyQt6.")]
        assert python_made == ["ToolbarReorder"], python_made


def test_edge_a_process_that_regroups_and_recolours_exits_cleanly(tmp_path) -> None:
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from PyQt6.QtWidgets import QApplication
        app = QApplication([])
        from ui import toolbar_categories as TC
        from ui.main_window import MainWindow
        for round_ in range(3):
            win = MainWindow()
            win._reconnect_timer.stop()
            win.show()
            app.processEvents()
            win.set_toolbar_style(TC.ToolbarStyle(grouping=bool(round_ % 2),
                                                  colours=(("media", "#00ff00"),)), store=False)
            win.set_toolbar_style(TC.ToolbarStyle(tint=False), store=False)
            app.processEvents()
            win.close()
            win.deleteLater()
            app.processEvents()
        print("done")
    """)
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "HOME": str(home),
           "XDG_CONFIG_HOME": str(home / ".config"), "XDG_DATA_HOME": str(home / ".local")}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=180, env=env)
    assert r.returncode == 0, r.stderr[-1500:]
    assert "done" in r.stdout


# --- the Settings page ------------------------------------------------------


def test_happy_the_toolbar_page_follows_appearance_and_shows_the_stored_style(stores) -> None:
    from ui.settings_dialog import CATEGORY_ORDER

    assert CATEGORY_ORDER.index("toolbar") == CATEGORY_ORDER.index("appearance") + 1
    stores.session.write_text(json.dumps({"window": {
        TC.GROUPING_KEY: False, TC.COLORS_KEY: {"llm": "#00ff00"}}}))
    win = stores.make_window()
    page = stores.settings_dialog(win, "toolbar").page("toolbar")
    assert not page.grouping_check.isChecked() and page.tint_check.isChecked()
    assert page.colour_buttons["llm"].text() == "#00ff00"
    assert page.colour_buttons["media"].text() == TC.default_colours()["media"]
    assert [page.colour_labels[c.id].text() for c in TC.CATEGORIES] == \
        [c.title for c in TC.CATEGORIES]


def test_sad_a_cancelled_colour_dialog_changes_nothing(stores) -> None:
    win = stores.make_window()
    dialog = stores.settings_dialog(win, "toolbar")
    page = dialog.page("toolbar")
    with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor()):
        page.colour_buttons["files"].click()
    assert page.colour_buttons["files"].text() == TC.default_colours()["files"]
    assert dialog.dirty_page_ids() == []
    before = stores.files()
    with mock.patch("ui.settings_dialog.QColorDialog.getColor",
                    return_value=QColor("#abcdef")):
        page.colour_buttons["files"].click()
    dialog.reject()
    assert stores.files() == before  # Cancel writes nothing
    assert win.toolbar_style().colour("files") == TC.default_colours()["files"]


def test_edge_reset_to_defaults_on_the_page(stores) -> None:
    stores.session.write_text(json.dumps({"window": {
        TC.GROUPING_KEY: False, TC.TINT_KEY: False, TC.COLORS_KEY: {"llm": "#00ff00"}}}))
    win = stores.make_window()
    dialog = stores.settings_dialog(win, "toolbar")
    page = dialog.page("toolbar")
    assert not page.colour_buttons["llm"].isEnabled()  # colours off: nothing to choose
    page.reset_button.click()
    assert page.grouping_check.isChecked() and page.tint_check.isChecked()
    assert page.colour_buttons["llm"].isEnabled()
    assert page.colour_buttons["llm"].text() == TC.default_colours()["llm"]
    assert dialog.apply()
    window = _session(stores)
    assert window[TC.GROUPING_KEY] is True and window[TC.TINT_KEY] is True
    assert window[TC.COLORS_KEY] == {}
    assert win.toolbar_style() == TC.ToolbarStyle()
    page.reset_button.click()
    assert dialog.dirty_page_ids() == []  # the defaults again: nothing to save
