"""The categories of the toolbar buttons: the groups, their colours, the style.

Every button of the two bars (ui.main_window builds them; each QAction has
a stable id in ``axToolId``, see ui.toolbar_order) belongs to exactly one
:data:`CATEGORIES` entry. A tool this table does not name - a button an
extension brings - belongs to :data:`EXTENSIONS`.

**Grouping** (on by default): the bars show one category after another with
a separator between them; the first three categories sit on the Main bar,
the others on the Tools bar (``Category.bar``). Inside a group the order is
the default order (the order of the code, Main bar first) or the one the
user dragged, stored per category in session.json (``window`` ->
:data:`GROUP_ORDER_KEY`). Grouping off: the bars as the code builds them,
with their own stored order (``toolbar_order``, ui.toolbar_order).

**Colours**: each category's colour is a subtle rounded tint behind its
buttons (a style sheet on the bar and the ``axCategory`` property on each
button - no Python object on the buttons). The tint is mixed from white on
a light bar and from black on a dark one, and its strength is lowered until
no icon of the category loses readability (:func:`button_colours`): an icon
that reads at 3:1 or more on the bar (WCAG 1.4.11) keeps 3:1, a weaker one
keeps 90 % of its contrast. Hover and checked carry a border that reads on
the bar; checked and pressed add an underline.

The stored style (session.json ``window``): :data:`GROUPING_KEY`,
:data:`TINT_KEY` (both on unless stored as false) and :data:`COLORS_KEY`
(category id -> ``#rrggbb``, only the colours that differ from the default).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ui import themes
from ui.toolbar_order import SEPARATOR, merge, parse

MAIN_BAR = "axMainToolbar"
TOOLS_BAR = "axToolsToolbar"

#: The button property the style sheet selects on.
CATEGORY_PROPERTY = "axCategory"

GROUPING_KEY = "toolbar_grouping"
TINT_KEY = "toolbar_category_tint"
COLORS_KEY = "toolbar_category_colors"
GROUP_ORDER_KEY = "toolbar_group_order"

#: Contrast an icon keeps on its tint when it had at least this much (WCAG
#: 1.4.11, graphical objects).
MIN_ICON_CONTRAST = 3.0
#: Share of its contrast a weaker icon keeps on its tint.
WEAK_ICON_KEEP = 0.9
#: Tint strength of a state before the readability check lowers it.
NORMAL_STRENGTH = 0.20
HOVER_STRENGTH = 0.34
PRESSED_STRENGTH = 0.46
#: Share of the category colour in the normal state's border.
SOFT_BORDER = 0.45
#: Step by which a tint is weakened until every icon stays readable.
_STEP = 0.01


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    #: Default colour, ``#rrggbb``.
    colour: str
    #: Object name of the bar the group sits on while grouping is on.
    bar: str


#: In the order of the bars.
CATEGORIES: tuple[Category, ...] = (
    Category("connections", "Connections", "#3498db", MAIN_BAR),
    Category("panes", "Windows & Panes", "#00bcd4", MAIN_BAR),
    Category("files", "Files & Search", "#2ecc71", MAIN_BAR),
    Category("media", "Media", "#e84393", TOOLS_BAR),
    Category("llm", "LLM & Agent", "#9b59b6", TOOLS_BAR),
    Category("system", "Tools & System", "#e67e22", TOOLS_BAR),
    Category("extensions", "Extensions", "#f1c40f", TOOLS_BAR),
)
CATEGORY_IDS: tuple[str, ...] = tuple(c.id for c in CATEGORIES)
EXTENSIONS = "extensions"

#: Tool id -> category id. A tool not named here is an extension's.
TOOL_CATEGORIES: dict[str, str] = {
    # Connections: where the panes connect to.
    "quick-connect": "connections",
    "connection-manager": "connections",
    "bookmark": "connections",
    # Windows & Panes: the layout, the panes, the terminals.
    "shell": "panes",
    "split-h": "panes",
    "split-v": "panes",
    "close-pane": "panes",
    "toggle-layout": "panes",
    "equalize": "panes",
    "extract-pane": "panes",
    "terminal": "panes",
    # Files & Search: what is done with files and how they are found.
    "copy-right": "files",
    "move-right": "files",
    "refresh": "files",
    "duplicates": "files",
    "find-index": "files",
    "compare": "files",
    "disk-usage": "files",
    "metadata": "files",
    "pack": "files",
    "find-files": "files",
    "tag": "files",
    "trash": "files",
    # Media: images, video, audio.
    "thumbnails": "media",
    "media-view": "media",
    "media-player": "media",
    "audio-settings": "media",
    # LLM & Agent.
    "agent": "llm",
    "analysis": "llm",
    # Tools & System: scripting, the machine, axross itself.
    "scripts": "system",
    "console": "system",
    "drives": "system",
    "settings": "system",
    "features": "system",
    # Extensions: managing them; the Folder Treemap is an extension tool.
    "extensions": "extensions",
}


def category_of(tool_id: object) -> str:
    """The category id of the tool *tool_id* (:data:`EXTENSIONS` for a tool
    the table does not name)."""
    return TOOL_CATEGORIES.get(tool_id, EXTENSIONS) if isinstance(tool_id, str) \
        else EXTENSIONS


def default_colours() -> dict[str, str]:
    return {c.id: c.colour for c in CATEGORIES}


# --- the stored style --------------------------------------------------------


@dataclass(frozen=True)
class ToolbarStyle:
    grouping: bool = True
    tint: bool = True
    #: (category id, ``#rrggbb``) for each colour that differs from the
    #: default, sorted by category id.
    colours: tuple[tuple[str, str], ...] = ()

    def overrides(self) -> dict[str, str]:
        return dict(self.colours)

    def colour(self, category_id: str) -> str:
        return self.overrides().get(category_id) or default_colours()[category_id]

    def colour_map(self) -> dict[str, str]:
        return {c: self.colour(c) for c in CATEGORY_IDS}


def normalise_colours(colours: object) -> tuple[tuple[str, str], ...]:
    """The overrides of *colours* (category id -> colour): known categories,
    ``#rrggbb`` values (lower case) that differ from the default."""
    if not isinstance(colours, Mapping):
        return ()
    defaults = default_colours()
    out = {}
    for category, colour in colours.items():
        if category in defaults and themes.is_hex_colour(colour) \
                and colour.lower() != defaults[category]:
            out[category] = colour.lower()
    return tuple(sorted(out.items()))


def parse_style(window: object) -> ToolbarStyle:
    """The toolbar style of session.json's ``window`` object; anything that
    is not a valid value reads as its default."""
    if not isinstance(window, Mapping):
        return ToolbarStyle()
    return ToolbarStyle(
        grouping=window.get(GROUPING_KEY) is not False,
        tint=window.get(TINT_KEY) is not False,
        colours=normalise_colours(window.get(COLORS_KEY)),
    )


def style_values(style: ToolbarStyle) -> dict:
    """*style* as the keys of session.json's ``window`` object."""
    return {
        GROUPING_KEY: bool(style.grouping),
        TINT_KEY: bool(style.tint),
        COLORS_KEY: style.overrides(),
    }


def parse_group_order(value: object) -> dict[str, list[str]]:
    """The stored order per category (session.json ``toolbar_group_order``):
    known categories with a list of ids; anything else reads as none."""
    return {
        category: [item for item in order if item != SEPARATOR]
        for category, order in parse(value).items()
        if category in CATEGORY_IDS
    }


# --- the grouped layout ------------------------------------------------------


def _sequence(orders: Mapping[str, list[str]]) -> list[str]:
    return [item for order in orders.values() for item in order if item != SEPARATOR]


def grouped_layout(default_orders: Mapping[str, list[str]],
                   stored: Mapping[str, list[str]] | None = None) -> dict[str, list[str]]:
    """The bars' orders with grouping on. *default_orders* is each bar's
    plain default (bar name -> ids, in the order of the bars), *stored* the
    stored order per category (:func:`parse_group_order`). A category whose
    bar is not among the bars goes on the first one."""
    stored = stored or {}
    sequence = _sequence(default_orders)
    out: dict[str, list[str]] = {name: [] for name in default_orders}
    if not out:
        return out
    first = next(iter(out))
    for category in CATEGORIES:
        default_ids = [item for item in sequence if category_of(item) == category.id]
        if not default_ids:
            continue
        saved = [item for item in stored.get(category.id, ()) if item != SEPARATOR]
        ids = [item for item in merge(saved, default_ids) if item != SEPARATOR]
        target = out[category.bar if category.bar in out else first]
        if target:
            target.append(SEPARATOR)
        target.extend(ids)
    return out


def group_orders(orders: Mapping[str, list[str]]) -> dict[str, list[str]]:
    """Each category's tools in the order *orders* (bar name -> ids) shows
    them; categories without a tool are left out."""
    out: dict[str, list[str]] = {}
    for item in _sequence(orders):
        out.setdefault(category_of(item), []).append(item)
    return {c: out[c] for c in CATEGORY_IDS if c in out}


# --- the colours -------------------------------------------------------------


def _rgb(colour: str) -> tuple[int, int, int]:
    if not themes.is_hex_colour(colour):
        raise ValueError(f"not a #rrggbb colour: {colour!r}")
    return int(colour[1:3], 16), int(colour[3:5], 16), int(colour[5:7], 16)


def blend(a: str, b: str, share: float) -> str:
    """*a* mixed with *share* (0..1) of *b*, as ``#rrggbb``."""
    share = min(1.0, max(0.0, share))
    mixed = (round(x + (y - x) * share) for x, y in zip(_rgb(a), _rgb(b), strict=True))
    return "#" + "".join(f"{v:02x}" for v in mixed)


def _keeps_readable(icon: str, background: str, tinted: str) -> bool:
    before = themes.contrast_ratio(icon, background)
    after = themes.contrast_ratio(icon, tinted)
    need = MIN_ICON_CONTRAST if before >= MIN_ICON_CONTRAST else before * WEAK_ICON_KEEP
    return after >= need


def _is_light(colour: str) -> bool:
    return themes._relative_luminance(colour) > 0.5


def _tint(colour: str, background: str, icons: list[str], strength: float) -> str:
    """The strongest tint up to *strength* on which every icon stays
    readable; at strength 0 it is the background itself."""
    base = "#ffffff" if _is_light(background) else "#000000"
    steps = round(strength / _STEP)
    for step in range(steps, 0, -1):
        tinted = blend(base, colour, step * _STEP)
        if all(_keeps_readable(icon, background, tinted) for icon in icons):
            return tinted
    return background


def _strong(colour: str, background: str, text: str) -> str:
    """*colour*, moved towards *text* until it reads on *background*."""
    for step in range(0, 101):
        candidate = blend(colour, text, step / 100)
        if themes.contrast_ratio(candidate, background) >= MIN_ICON_CONTRAST:
            return candidate
    return text


@dataclass(frozen=True)
class ButtonColours:
    normal: str
    hover: str
    pressed: str
    #: Border of the normal state.
    soft: str
    #: Border of hover, pressed and checked; the underline of checked.
    strong: str


def button_colours(colour: str, background: str, text: str,
                   icons: Iterable[str]) -> ButtonColours:
    """The colours of a category's buttons: *colour* the category's, on a
    bar of *background* with *text* as its text colour, *icons* the stroke
    colours of the category's icons."""
    for value in (colour, background, text):
        _rgb(value)
    icons = [icon for icon in icons if themes.is_hex_colour(icon)]
    return ButtonColours(
        normal=_tint(colour, background, icons, NORMAL_STRENGTH),
        hover=_tint(colour, background, icons, HOVER_STRENGTH),
        pressed=_tint(colour, background, icons, PRESSED_STRENGTH),
        soft=blend(background, colour, SOFT_BORDER),
        strong=_strong(colour, background, text),
    )


def stylesheet(colours: Mapping[str, ButtonColours], *, compact: bool = False) -> str:
    """The bar's style sheet: a rule per category (category id ->
    colours). Pressed and checked draw a 3 px underline; their bottom
    padding shrinks by as much, so the icon does not move."""
    padding = 2 if compact else 3
    rules = []
    for category, c in colours.items():
        sel = f'QToolButton[{CATEGORY_PROPERTY}="{category}"]'
        rules.append(
            f"{sel} {{\n"
            f"    background-color: {c.normal};\n"
            f"    border: 1px solid {c.soft};\n"
            "    border-radius: 5px;\n"
            f"    padding: {padding}px;\n"
            "}\n"
            f"{sel}:hover {{\n"
            f"    background-color: {c.hover};\n"
            f"    border-color: {c.strong};\n"
            "}\n"
            f"{sel}:pressed, {sel}:checked {{\n"
            f"    background-color: {c.pressed};\n"
            f"    border-color: {c.strong};\n"
            f"    border-bottom: 3px solid {c.strong};\n"
            f"    padding-bottom: {padding - 2}px;\n"
            "}\n"
        )
    return "".join(rules)


__all__ = [
    "CATEGORIES",
    "CATEGORY_IDS",
    "CATEGORY_PROPERTY",
    "COLORS_KEY",
    "EXTENSIONS",
    "GROUPING_KEY",
    "GROUP_ORDER_KEY",
    "MIN_ICON_CONTRAST",
    "TINT_KEY",
    "TOOL_CATEGORIES",
    "WEAK_ICON_KEEP",
    "ButtonColours",
    "Category",
    "ToolbarStyle",
    "blend",
    "button_colours",
    "category_of",
    "default_colours",
    "group_orders",
    "grouped_layout",
    "normalise_colours",
    "parse_group_order",
    "parse_style",
    "style_values",
    "stylesheet",
]
