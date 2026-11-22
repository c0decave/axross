"""The Markdown reader's themes: the colours of a page in the window
(ui.markdown_html, ui.markdown_view) and in the terminal (core.markdown_term).

Each :class:`Theme` defines the page's background and text, its headings,
links, inline and fenced code (and the code's syntax colours), quotes,
tables, alerts, math, marks and the selection - for the window (``page``,
``code``) and for the terminal (``term``). "Light" and "Dark" are the
colours the reader always had (GitHub's); the others are named for what
they look like, not after a product (Solar for a Solarized-like palette,
Arctic for a Nord-like one, Retro for a warm Gruvbox-like one, Night Violet
for a Dracula-like one, Slate for a One-Dark-like one).

Every theme's body text and links reach WCAG 2.x contrast AA (4.5:1) on its
page - the two High Contrast themes AAA (7:1) - and the other text roles too
(tests/test_markdown_themes.py measures each: :func:`contrast`).

Nothing here imports Qt: the terminal (axross-mdcat) uses it as it is.

A :class:`Theme` stands where the reader's functions took ``dark`` (a bool)
before: it is true when it is a dark theme - ``colours(theme)`` gives its
page colours, ``colours(True)`` still the Dark ones.
"""

from __future__ import annotations

import functools
import os
from dataclasses import dataclass, field
from pathlib import Path

# -- the colours the reader always had (GitHub's) -----------------------------------------------

#: The page on a light ground (ui.markdown_html.LIGHT is this dict).
LIGHT_PAGE = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    # (headings in the text's colour - their size and weight make the order)
    "h1": "#1f2328", "h2": "#1f2328", "h3": "#1f2328", "h4": "#1f2328", "h5": "#1f2328", "h6": "#59636e",
    "code_bg": "#eff1f3", "code_fg": "#1f2328", "pre_bg": "#f6f8fa", "quote_bg": "#f6f8fa", "highlight": "#9a6700",
    "highlight_bg": "#fff8c5",
    "quote_fg": "#59636e", "rule": "#d1d9e0", "th_bg": "#eef2f7", "mark": "#1a7f37", "math": "#1f2328",
    "note": "#0969da", "tip": "#1a7f37", "important": "#8250df", "warning": "#9a6700", "caution": "#d1242f",
    "alert_bg": "#f6f8fa", "zebra": "#f6f8fa",
    "page_bg": "#ffffff", "selection_bg": "#b6d6ff", "selection_fg": "#1f2328",
}
#: ... on a dark ground (ui.markdown_html.DARK).
DARK_PAGE = {
    "text": "#e6edf3", "muted": "#9198a1", "link": "#4493f8",
    "h1": "#e6edf3", "h2": "#e6edf3", "h3": "#e6edf3", "h4": "#e6edf3", "h5": "#e6edf3", "h6": "#9198a1",
    "code_bg": "#2d333b", "code_fg": "#e6edf3", "pre_bg": "#161b22", "quote_bg": "#1c2128", "highlight": "#e3b341",
    "highlight_bg": "#4d3800",
    "quote_fg": "#9198a1", "rule": "#3d444d", "th_bg": "#212830", "mark": "#3fb950", "math": "#e6edf3",
    "note": "#4493f8", "tip": "#3fb950", "important": "#ab7df8", "warning": "#d29922", "caution": "#f85149",
    "alert_bg": "#161b22", "zebra": "#1c2128",
    "page_bg": "#0d1117", "selection_bg": "#264f78", "selection_fg": "#ffffff",
}
#: GitHub's colours of code on a light page (its "prettylights" palette - ui.markdown_html.GITHUB_LIGHT).
LIGHT_CODE = {"keyword": "#cf222e", "string": "#0a3069", "comment": "#6e7781", "number": "#0550ae",
              "function": "#8250df", "class": "#953800", "constant": "#0550ae", "tag": "#116329",
              "deleted": "#82071e"}
#: ... and on a dark one (GitHub's dark theme - ui.markdown_html.GITHUB_DARK).
DARK_CODE = {"keyword": "#ff7b72", "string": "#a5d6ff", "comment": "#8b949e", "number": "#79c0ff",
             "function": "#d2a8ff", "class": "#ffa657", "constant": "#79c0ff", "tag": "#7ee787",
             "deleted": "#ffa198"}
#: The terminal's colours on a dark ground (core.markdown_term.DARK).
DARK_TERM = {
    "text": "#e6edf3", "muted": "#8b949e", "link": "#58a6ff",
    "h1": "#79c0ff", "h2": "#d2a8ff", "h3": "#7ee787", "h4": "#e3b341", "h5": "#ffa657", "h6": "#8b949e",
    "code_fg": "#ff7b72", "code_bg": "#2d333b", "pre_bg": "#161b22", "quote": "#8b949e",
    "rule": "#3d444d", "mark": "#3fb950", "open": "#8b949e", "image": "#d2a8ff", "border": "#545d68",
    "math": "#ffa657", "note": "#4493f8", "tip": "#3fb950", "important": "#ab7df8", "warning": "#d29922",
    "caution": "#f85149",
}
#: ... on a light one (core.markdown_term.LIGHT).
LIGHT_TERM = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    "h1": "#0550ae", "h2": "#8250df", "h3": "#1a7f37", "h4": "#9a6700", "h5": "#bc4c00", "h6": "#59636e",
    "code_fg": "#b31d28", "code_bg": "#eff1f3", "pre_bg": "#f6f8fa", "quote": "#59636e",
    "rule": "#d1d9e0", "mark": "#1a7f37", "open": "#59636e", "image": "#8250df", "border": "#afb8c1",
    "math": "#953800", "note": "#0969da", "tip": "#1a7f37", "important": "#8250df", "warning": "#9a6700",
    "caution": "#d1242f",
}

#: The keys every theme's page, code and terminal colours have.
PAGE_KEYS = tuple(LIGHT_PAGE)
CODE_KEYS = tuple(LIGHT_CODE)
TERM_KEYS = tuple(DARK_TERM) + ("page_bg",)


@dataclass(frozen=True, eq=False)
class Theme:
    """A theme: *id* (kept in the settings, ``--theme``), *label* (shown,
    translated), *dark*, and its colours - ``page`` (the window's page: keys
    of :data:`PAGE_KEYS`), ``code`` (syntax colours: :data:`CODE_KEYS`) and
    ``term`` (the terminal's: :data:`TERM_KEYS`). *aaa*: its text and links
    reach 7:1 (WCAG AAA). Compared by identity: one object a theme."""

    id: str
    label: str
    dark: bool
    page: dict = field(repr=False)
    code: dict = field(repr=False)
    term: dict = field(repr=False)
    aaa: bool = False

    def __bool__(self) -> bool:  # (where a bool "dark" stood: true for a dark theme)
        return self.dark

    @property
    def background(self) -> str:
        return self.page["page_bg"]


def _theme(id_: str, label: str, dark: bool, page: dict, code: dict, aaa: bool = False,
           term: dict | None = None) -> Theme:
    """A theme whose terminal colours come from its page's (unless given)."""
    missing = [key for key in PAGE_KEYS if key not in page] + [key for key in CODE_KEYS if key not in code]
    if missing:
        raise ValueError(f"theme {id_}: no colour for {missing}")
    if term is None:
        term = {
            "text": page["text"], "muted": page["muted"], "link": page["link"],
            **{f"h{n}": page[f"h{n}"] for n in range(1, 7)},
            "code_fg": page["code_fg"], "code_bg": page["code_bg"], "pre_bg": page["pre_bg"],
            "quote": page["quote_fg"], "rule": page["rule"], "mark": page["mark"], "open": page["muted"],
            "image": page["important"], "border": page["muted"], "math": page["math"],
            **{kind: page[kind] for kind in ("note", "tip", "important", "warning", "caution")},
        }
    term = {**term, "page_bg": page["page_bg"]}
    return Theme(id_, label, dark, page, code, term, aaa)


def _page(*, bg, text, muted, link, headings, code_bg, code_fg, pre_bg, quote_bg, quote_fg, rule, th_bg,
          zebra, mark, math, alerts, alert_bg, highlight, highlight_bg, selection_bg, selection_fg) -> dict:
    h1, h2, h3, h4, h5, h6 = headings
    note, tip, important, warning, caution = alerts
    return {"text": text, "muted": muted, "link": link, "h1": h1, "h2": h2, "h3": h3, "h4": h4, "h5": h5,
            "h6": h6, "code_bg": code_bg, "code_fg": code_fg, "pre_bg": pre_bg, "quote_bg": quote_bg,
            "highlight": highlight, "highlight_bg": highlight_bg, "quote_fg": quote_fg, "rule": rule,
            "th_bg": th_bg, "mark": mark, "math": math, "note": note, "tip": tip, "important": important,
            "warning": warning, "caution": caution, "alert_bg": alert_bg, "zebra": zebra, "page_bg": bg,
            "selection_bg": selection_bg, "selection_fg": selection_fg}


def _code(keyword, string, comment, number, function, class_, constant, tag, deleted) -> dict:
    return {"keyword": keyword, "string": string, "comment": comment, "number": number, "function": function,
            "class": class_, "constant": constant, "tag": tag, "deleted": deleted}


THEMES: dict[str, Theme] = {theme.id: theme for theme in (
    Theme("light", "Light", False, LIGHT_PAGE, LIGHT_CODE, {**LIGHT_TERM, "page_bg": LIGHT_PAGE["page_bg"]}),
    Theme("dark", "Dark", True, DARK_PAGE, DARK_CODE, {**DARK_TERM, "page_bg": DARK_PAGE["page_bg"]}),
    _theme("sepia", "Sepia", False, _page(
        bg="#f4ecd8", text="#3b2f20", muted="#665441", link="#8a3a0f",
        headings=("#4a2c12", "#4a2c12", "#4a2c12", "#4a2c12", "#4a2c12", "#665441"),
        code_bg="#e8dcbf", code_fg="#4a2c12", pre_bg="#ede2c7", quote_bg="#ebdfc3", quote_fg="#5b4a36",
        rule="#cdbd98", th_bg="#e5d7b5", zebra="#efe5cc", mark="#3b6420", math="#3b2f20",
        alerts=("#1d5a8f", "#3b6420", "#663c8a", "#7f5200", "#9e2418"), alert_bg="#ede2c7",
        highlight="#7f5200", highlight_bg="#f0d78c", selection_bg="#d8c38c", selection_fg="#2a2016"),
        _code("#9e2418", "#3b6420", "#6f5d48", "#8a3a0f", "#663c8a", "#7f5200", "#1d5a8f", "#3b6420", "#9e2418")),
    _theme("solar-light", "Solar Light", False, _page(
        bg="#fdf6e3", text="#4f6369", muted="#5b6e74", link="#1a64a0",
        headings=("#8f4a00", "#8f4a00", "#2b6a1e", "#2b6a1e", "#4f6369", "#5b6e74"),
        code_bg="#eee8d5", code_fg="#a8312f", pre_bg="#eee8d5", quote_bg="#f3ecd6", quote_fg="#556a70",
        rule="#d9d2bc", th_bg="#eee8d5", zebra="#f6efdc", mark="#4d6b00", math="#5a4fa0",
        alerts=("#1a64a0", "#4d6b00", "#5a4fa0", "#8a5d00", "#b22a26"), alert_bg="#f3ecd6",
        highlight="#7a5300", highlight_bg="#f4e2a6", selection_bg="#e2d9bd", selection_fg="#073642"),
        _code("#4d6b00", "#1d6f69", "#5f7278", "#9e3430", "#1a64a0", "#8a5d00", "#8c3170", "#1a64a0", "#b22a26")),
    _theme("solar-dark", "Solar Dark", True, _page(
        bg="#002b36", text="#9fb0b0", muted="#93a1a1", link="#6cb4e8",
        headings=("#d4a62a", "#d4a62a", "#a3b84a", "#a3b84a", "#9fb0b0", "#93a1a1"),
        code_bg="#073642", code_fg="#f07b70", pre_bg="#073642", quote_bg="#05313c", quote_fg="#93a1a1",
        rule="#2a4f58", th_bg="#073642", zebra="#03303b", mark="#a3b84a", math="#a8a6ec",
        alerts=("#6cb4e8", "#a3b84a", "#a8a6ec", "#d4a62a", "#f07b70"), alert_bg="#05313c",
        highlight="#e6c15a", highlight_bg="#3d3a10", selection_bg="#1d4b57", selection_fg="#eee8d5"),
        _code("#a3b84a", "#4fc4b8", "#8a9a9a", "#f07b70", "#6cb4e8", "#d4a62a", "#e87ab4", "#6cb4e8", "#f07b70")),
    _theme("arctic", "Arctic", True, _page(
        bg="#2e3440", text="#e5e9f0", muted="#b0b8c8", link="#88c0d0",
        headings=("#8fbcbb", "#88c0d0", "#81a1c1", "#a3be8c", "#ebcb8b", "#b0b8c8"),
        code_bg="#3b4252", code_fg="#eceff4", pre_bg="#3b4252", quote_bg="#353b49", quote_fg="#c0c7d4",
        rule="#4c566a", th_bg="#3b4252", zebra="#333947", mark="#a3be8c", math="#b9a3cf",
        alerts=("#88c0d0", "#a3be8c", "#c7a8d4", "#ebcb8b", "#e48a92"), alert_bg="#353b49",
        highlight="#ebcb8b", highlight_bg="#4f4a33", selection_bg="#4c566a", selection_fg="#eceff4"),
        _code("#81a1c1", "#a3be8c", "#9aa3b5", "#c7a8d4", "#88c0d0", "#8fbcbb", "#d6a58e", "#81a1c1", "#e48a92")),
    _theme("retro", "Retro", True, _page(
        bg="#282828", text="#ebdbb2", muted="#bdae93", link="#83a598",
        headings=("#fabd2f", "#b8bb26", "#8ec07c", "#83a598", "#fe8019", "#bdae93"),
        code_bg="#3c3836", code_fg="#fe8019", pre_bg="#32302f", quote_bg="#32302f", quote_fg="#d5c4a1",
        rule="#504945", th_bg="#3c3836", zebra="#2f2d2c", mark="#b8bb26", math="#d3869b",
        alerts=("#83a598", "#b8bb26", "#d3869b", "#fabd2f", "#fb4934"), alert_bg="#32302f",
        highlight="#fabd2f", highlight_bg="#504228", selection_bg="#504945", selection_fg="#fbf1c7"),
        _code("#fb4934", "#b8bb26", "#a89984", "#d3869b", "#8ec07c", "#fabd2f", "#d3869b", "#83a598", "#fb4934")),
    _theme("night-violet", "Night Violet", True, _page(
        bg="#282a36", text="#f8f8f2", muted="#b3b8d6", link="#8be9fd",
        headings=("#bd93f9", "#ff79c6", "#50fa7b", "#ffb86c", "#f1fa8c", "#b3b8d6"),
        code_bg="#363848", code_fg="#ff79c6", pre_bg="#21222c", quote_bg="#2f3140", quote_fg="#c8cce4",
        rule="#44475a", th_bg="#343746", zebra="#2c2e3b", mark="#50fa7b", math="#f1fa8c",
        alerts=("#8be9fd", "#50fa7b", "#bd93f9", "#ffb86c", "#ff6e6e"), alert_bg="#2f3140",
        highlight="#f1fa8c", highlight_bg="#4a4a2c", selection_bg="#44475a", selection_fg="#f8f8f2"),
        _code("#ff79c6", "#f1fa8c", "#9ba3cf", "#bd93f9", "#50fa7b", "#8be9fd", "#bd93f9", "#ff79c6", "#ff6e6e")),
    _theme("high-contrast-light", "High Contrast Light", False, _page(
        bg="#ffffff", text="#000000", muted="#333333", link="#0000c8",
        headings=("#000000", "#000000", "#000000", "#000000", "#000000", "#333333"),
        code_bg="#ececec", code_fg="#000000", pre_bg="#f2f2f2", quote_bg="#f2f2f2", quote_fg="#1a1a1a",
        rule="#000000", th_bg="#e0e0e0", zebra="#f2f2f2", mark="#005a00", math="#000000",
        alerts=("#0000c8", "#005a00", "#5a0090", "#6b4000", "#a00000"), alert_bg="#f2f2f2",
        highlight="#000000", highlight_bg="#ffff66", selection_bg="#000080", selection_fg="#ffffff"),
        _code("#8b0000", "#004c00", "#3d3d3d", "#00008b", "#5a0090", "#6b3000", "#00008b", "#004c00", "#8b0000"),
        aaa=True),
    _theme("high-contrast-dark", "High Contrast Dark", True, _page(
        bg="#000000", text="#ffffff", muted="#d0d0d0", link="#7fd4ff",
        headings=("#ffffff", "#ffffff", "#ffffff", "#ffffff", "#ffffff", "#d0d0d0"),
        code_bg="#1f1f1f", code_fg="#ffffff", pre_bg="#141414", quote_bg="#141414", quote_fg="#e6e6e6",
        rule="#ffffff", th_bg="#262626", zebra="#121212", mark="#7dff7d", math="#ffffff",
        alerts=("#7fd4ff", "#7dff7d", "#e0b0ff", "#ffd54a", "#ff9a9a"), alert_bg="#141414",
        highlight="#ffd54a", highlight_bg="#4d3d00", selection_bg="#ffff00", selection_fg="#000000"),
        _code("#ff9a9a", "#a8ff9a", "#cfcfcf", "#ffd54a", "#e0b0ff", "#ffc580", "#7fd4ff", "#7dff7d", "#ff9a9a"),
        aaa=True),
    _theme("slate", "Slate", True, _page(
        bg="#282c34", text="#c3c9d4", muted="#a1a8b5", link="#6fb6f2",
        headings=("#e5c07b", "#61afef", "#c678dd", "#98c379", "#d19a66", "#a1a8b5"),
        code_bg="#333842", code_fg="#e88f97", pre_bg="#21252b", quote_bg="#2c313a", quote_fg="#b3b9c5",
        rule="#3e4451", th_bg="#2f343e", zebra="#2b2f37", mark="#98c379", math="#d19a66",
        alerts=("#6fb6f2", "#98c379", "#c98ee0", "#e5c07b", "#ef8a92"), alert_bg="#2c313a",
        highlight="#e5c07b", highlight_bg="#4a4430", selection_bg="#3e4451", selection_fg="#e6e9ef"),
        _code("#c98ee0", "#98c379", "#959cab", "#d19a66", "#6fb6f2", "#e5c07b", "#56c2cf", "#ef8a92", "#ef8a92")),
    _theme("paper", "Paper", False, _page(
        bg="#f8f6f0", text="#1c1b19", muted="#55524b", link="#1d4f91",
        headings=("#111110", "#111110", "#111110", "#111110", "#111110", "#55524b"),
        code_bg="#ebe8df", code_fg="#2b2a26", pre_bg="#efece4", quote_bg="#efece4", quote_fg="#4a4740",
        rule="#cfcabd", th_bg="#e7e3d8", zebra="#f1eee6", mark="#2d6a2d", math="#1c1b19",
        alerts=("#1d4f91", "#2d6a2d", "#5d3a8a", "#7a4f00", "#a02b20"), alert_bg="#efece4",
        highlight="#6e4a00", highlight_bg="#f2e3a6", selection_bg="#cfd8e8", selection_fg="#111110"),
        _code("#8a2a1c", "#2d5f2d", "#5f5b52", "#1d4f91", "#5d3a8a", "#7a4f00", "#1d4f91", "#2d5f2d", "#a02b20")),
)}

#: The choice that follows the window (axross's theme, the desktop's scheme): no theme of its own.
AUTO = "auto"
#: The themes' ids as offered (the menu, --list-themes), "auto" first.
CHOICES = (AUTO, *THEMES)


def get(theme_id) -> Theme | None:
    """The theme *theme_id* (its id, case and "_" / " " forgiven) - None for "auto" or one that is none."""
    if not isinstance(theme_id, str):
        return None
    return THEMES.get(theme_id.strip().lower().replace("_", "-").replace(" ", "-"))


def normalize(theme_id) -> str:
    """*theme_id* as a known id, else "auto"."""
    theme = get(theme_id)
    return theme.id if theme is not None else AUTO


def for_dark(dark: bool) -> Theme:
    """The theme "auto" stands for on a dark (or a light) ground: Dark or Light."""
    return THEMES["dark" if dark else "light"]


def colours_of(look) -> dict:
    """The page colours of *look*: a Theme's own, else (a bool, "dark") Dark's or Light's."""
    if isinstance(look, Theme):
        return look.page
    return DARK_PAGE if look else LIGHT_PAGE


def code_of(look) -> dict:
    """The syntax colours of *look* (a Theme, or a bool "dark")."""
    if isinstance(look, Theme):
        return look.code
    return DARK_CODE if look else LIGHT_CODE


_STYLES: dict = {}


def pygments_style(look):
    """A Pygments style of *look*'s code colours (a Theme, or a bool "dark": Dark's or Light's) - function
    names bold and comments italic, as Pygments' github-dark; made once a theme."""
    theme = look if isinstance(look, Theme) else for_dark(bool(look))
    style = _STYLES.get(theme.id)
    if style is not None and style[0] is theme:
        return style[1]
    from pygments.style import Style
    from pygments.token import Comment, Error, Generic, Keyword, Name, Number, Operator, String

    c = theme.code

    class GitHub(Style):  # (the name Light's and Dark's had: GitHub's colours)
        background_color = theme.page["pre_bg"]
        styles = {
            Comment: "italic " + c["comment"], Keyword: c["keyword"], Keyword.Constant: c["constant"],
            Name.Function: "bold " + c["function"], Name.Class: c["class"], Name.Builtin: c["constant"],
            Name.Decorator: c["function"], Name.Tag: c["tag"], Name.Attribute: c["constant"],
            Name.Constant: c["constant"], String: c["string"], String.Escape: c["constant"],
            String.Interpol: c["constant"], Number: c["number"], Operator: c["constant"],
            Operator.Word: c["keyword"], Generic.Deleted: c["deleted"], Generic.Inserted: c["tag"],
            Generic.Heading: "bold " + c["constant"], Error: c["deleted"],
        }

    _STYLES[theme.id] = (theme, GitHub)
    return GitHub


# -- contrast (WCAG 2.x) ----------------------------------------------------------------------------

def rgb(hex_colour: str) -> tuple[int, int, int]:
    value = hex_colour.lstrip("#")
    if len(value) == 3:
        value = "".join(c * 2 for c in value)
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def luminance(colour) -> float:
    """The relative luminance of *colour* ("#rrggbb" or (r, g, b)) as WCAG defines it."""
    r, g, b = rgb(colour) if isinstance(colour, str) else colour

    def linear(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)


def contrast(a, b) -> float:
    """The contrast ratio of two colours (1 to 21)."""
    la, lb = luminance(a), luminance(b)
    high, low = max(la, lb), min(la, lb)
    return (high + 0.05) / (low + 0.05)


#: (foreground role, background role, the least ratio) a theme's page must reach - AA's 4.5 for text,
#: 3 for the alerts' coloured bars and titles (bold, large: AA's large text) and the rules are no text.
PAGE_PAIRS = (
    ("text", "page_bg", 4.5), ("link", "page_bg", 4.5), ("muted", "page_bg", 4.5), ("math", "page_bg", 4.5),
    *((f"h{n}", "page_bg", 4.5) for n in range(1, 7)),
    ("code_fg", "code_bg", 4.5), ("text", "pre_bg", 4.5), ("quote_fg", "quote_bg", 4.5),
    ("text", "th_bg", 4.5), ("text", "zebra", 4.5),
    ("text", "highlight_bg", 4.5),  # (a <mark>, and Find's marks: ui.markdown_viewer.find_mark_format)
    ("mark", "page_bg", 3.0), ("selection_fg", "selection_bg", 4.5), ("text", "alert_bg", 4.5),
    *((kind, "alert_bg", 3.0) for kind in ("note", "tip", "important", "warning", "caution")),
    *((kind, "page_bg", 3.0) for kind in ("note", "tip", "important", "warning", "caution")),
)
#: The text and links of a High Contrast theme: AAA.
AAA_PAIRS = (("text", "page_bg", 7.0), ("link", "page_bg", 7.0), ("text", "pre_bg", 7.0),
             ("code_fg", "code_bg", 7.0), ("text", "highlight_bg", 7.0))  # (the last: <mark> and Find's marks)


def contrast_report(theme: Theme) -> list[tuple[str, str, float, float]]:
    """(foreground, background, ratio, the least allowed) of every pair the page and its code must reach -
    the syntax colours each on the code's ground (3:1: a token's colour sets it apart, the text's
    weight is the reader's)."""
    page = theme.page
    rows = [(fg, bg, contrast(page[fg], page[bg]), least) for fg, bg, least in PAGE_PAIRS]
    if theme.aaa:
        rows += [(fg, bg, contrast(page[fg], page[bg]), least) for fg, bg, least in AAA_PAIRS]
    rows += [(f"code.{kind}", "pre_bg", contrast(colour, page["pre_bg"]), 3.0)
             for kind, colour in theme.code.items()]
    term = theme.term
    rows += [(f"term.{role}", "term.page_bg", contrast(term[role], term["page_bg"]), 4.5)
             for role in ("text", "link")]
    return rows


# -- the terminal's 256 colours ---------------------------------------------------------------------

_STEPS = (0, 95, 135, 175, 215, 255)


def xterm256_rgb(index: int) -> tuple[int, int, int]:
    """The colour of xterm's colour *index* (16 to 255)."""
    if index >= 232:
        v = 8 + 10 * (index - 232)
        return v, v, v
    index -= 16
    return _STEPS[index // 36], _STEPS[(index // 6) % 6], _STEPS[index % 6]


def nearest256(hex_colour: str) -> int:
    """The nearest of xterm's 240 colours (the cube and the greys) to *hex_colour*."""
    r, g, b = rgb(hex_colour)
    return min(range(16, 256), key=lambda i: _distance(xterm256_rgb(i), (r, g, b)))


def _distance(a, b) -> int:
    return (a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2


@functools.lru_cache(maxsize=512)
def readable256(fg: str, bg: str) -> int:
    """The xterm colour for *fg* on the xterm colour of *bg*: the nearest that keeps the contrast the
    two had (at most 4.5) - the nearest alone took a link below AA on some grounds."""
    target = min(4.5, contrast(fg, bg))
    ground = xterm256_rgb(nearest256(bg))
    want = rgb(fg)
    ranked = sorted(range(16, 256), key=lambda i: _distance(xterm256_rgb(i), want))
    for index in ranked:
        if contrast(xterm256_rgb(index), ground) >= target - 0.05:
            return index
    return ranked[0]


# -- the choice kept --------------------------------------------------------------------------------

#: The setting of the window's theme and of the terminal's, in axross-markdown's settings.json.
SETTING_PAGE = "page_theme"
SETTING_TERM = "terminal_theme"
#: The environment's say over the terminal's theme (axross-mdcat, --term): a theme's id.
ENV_TERM = "AXROSS_MDCAT_THEME"


def terminal_default(environ=None, path: Path | None = None) -> str:
    """The terminal's theme when --theme is not given: AXROSS_MDCAT_THEME, else the settings'
    "terminal_theme", else "auto" (a value that names no theme counts as not given)."""
    from core.markdown_settings import read_settings

    environ = os.environ if environ is None else environ
    for value in (environ.get(ENV_TERM), read_settings(path).get(SETTING_TERM)):
        if isinstance(value, str) and value.strip():
            name = value.strip().lower()
            if name == AUTO or get(name) is not None:
                return normalize(name)
    return AUTO


__all__ = ["AUTO", "CHOICES", "CODE_KEYS", "DARK_CODE", "DARK_PAGE", "DARK_TERM", "ENV_TERM", "LIGHT_CODE",
           "LIGHT_PAGE", "LIGHT_TERM", "PAGE_KEYS", "SETTING_PAGE", "SETTING_TERM", "TERM_KEYS", "THEMES", "Theme",
           "code_of", "colours_of", "contrast", "contrast_report", "for_dark", "get", "luminance", "nearest256",
           "normalize", "pygments_style", "readable256", "terminal_default", "xterm256_rgb"]
