"""A parsed Markdown document (core.markdown_doc) as the HTML Qt's rich text
shows well - for ui.markdown_view when markdown-it-py is installed.

markdown-it renders the HTML - raw HTML of the file only as the events of
its allowed subset (core.markdown_doc: :func:`events_html` writes those
tags and attributes, nothing of the file's own markup) - and this module
shapes it for Qt's subset of HTML and CSS: every ``id`` also as an
``<a name>`` (Qt scrolls to those), table alignment as ``align``, borders and
padding as table attributes, task list boxes as ☑ / ☐, fenced code coloured
by Pygments (inline styles), GitHub's alerts as a box with a coloured bar
and title, math as text (core.markdown_doc.math_text), and a style sheet in
the colours of the light or dark palette (:func:`style_sheet`). Nothing here
loads anything: images are the view's (MarkdownBrowser.loadResource).

:func:`export_html` makes the same document a page of its own for a web
browser (Export HTML…, ``axross-markdown --html``): its own style sheet,
the images the viewer read put in it (data:), every other image a chip
naming it, and a Content-Security-Policy that lets it load nothing.
"""

from __future__ import annotations

import base64
import functools
import html
import logging
import posixpath
import re

from core import markdown_doc as MD

log = logging.getLogger(__name__)

#: A fenced block longer than this is shown uncoloured (Pygments' time grows
#: with it; a block of megabytes held up the window).
HIGHLIGHT_LIMIT = 200_000

LIGHT = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    # (headings in the text's colour - their size and weight make the order)
    "h1": "#1f2328", "h2": "#1f2328", "h3": "#1f2328", "h4": "#1f2328", "h5": "#1f2328", "h6": "#59636e",
    "code_bg": "#eff1f3", "code_fg": "#1f2328", "pre_bg": "#f6f8fa", "quote_bg": "#f6f8fa", "highlight": "#9a6700",
    "highlight_bg": "#fff8c5",
    "quote_fg": "#59636e", "rule": "#d1d9e0", "th_bg": "#eef2f7", "mark": "#1a7f37", "math": "#1f2328",
    "note": "#0969da", "tip": "#1a7f37", "important": "#8250df", "warning": "#9a6700", "caution": "#d1242f",
    "alert_bg": "#f6f8fa", "zebra": "#f6f8fa",
}
DARK = {
    "text": "#e6edf3", "muted": "#9198a1", "link": "#4493f8",
    "h1": "#e6edf3", "h2": "#e6edf3", "h3": "#e6edf3", "h4": "#e6edf3", "h5": "#e6edf3", "h6": "#9198a1",
    "code_bg": "#2d333b", "code_fg": "#e6edf3", "pre_bg": "#161b22", "quote_bg": "#1c2128", "highlight": "#e3b341",
    "highlight_bg": "#4d3800",
    "quote_fg": "#9198a1", "rule": "#3d444d", "th_bg": "#212830", "mark": "#3fb950", "math": "#e6edf3",
    "note": "#4493f8", "tip": "#3fb950", "important": "#ab7df8", "warning": "#d29922", "caution": "#f85149",
    "alert_bg": "#161b22", "zebra": "#1c2128",
}

#: The faces a formula is set in - inline and displayed, cells of cases and
#: matrices too (in a monospace font they stood apart from the text): a math
#: face, else a serif text face of the same kind, DejaVu Serif last (with none
#: of them the sans text's own italic was the formulas' - the thirteenth review).
MATH_FONTS = ("STIX Two Math", "Latin Modern Math", "Cambria Math", "STIX Two Text", "Latin Modern Roman",
              "Libertinus Serif", "TeX Gyre Termes", "Liberation Serif", "Times New Roman", "DejaVu Serif")
MATH_FAMILIES = ", ".join(f'"{name}"' if " " in name else name for name in MATH_FONTS)

#: GitHub's alerts: (sign, title) of each kind - the title translated.
ALERT_TITLES = {kind: (sign, title) for kind, sign, title in (
    ("note", "ℹ", "Note"), ("tip", "✓", "Tip"), ("important", "❖", "Important"),
    ("warning", "⚠", "Warning"), ("caution", "✖", "Caution"))}


def colours(dark: bool) -> dict[str, str]:
    return DARK if dark else LIGHT


def style_sheet(dark: bool) -> str:
    """The document's style sheet (QTextDocument.setDefaultStyleSheet).
    Lines of prose are 6 pixels apart (about 1.5 times a line, as GitHub's)
    - as a distance, not in per cent: Qt makes a line holding an image that
    much taller too, a logo left a gap of 100 pixels under it. A list's
    items further apart than the lines of one; a rule (``hr``) takes the
    colour of its background - Qt draws it so."""
    c = colours(dark)
    return f"""
body {{ color: {c['text']}; }}
h1 {{ color: {c['h1']}; font-size: xx-large; font-weight: 700; margin-top: 24px; margin-bottom: 0px; }}
h2 {{ color: {c['h2']}; font-size: x-large; font-weight: 700; margin-top: 24px; margin-bottom: 0px; }}
h3 {{ color: {c['h3']}; font-size: large; font-weight: 700; margin-top: 22px; margin-bottom: 12px; }}
h4 {{ color: {c['h4']}; font-size: medium; font-weight: 700; margin-top: 18px; margin-bottom: 8px; }}
h5 {{ color: {c['h5']}; font-size: medium; font-weight: 700; margin-top: 16px; margin-bottom: 4px; }}
h6 {{ color: {c['h6']}; font-size: small; font-weight: 700; margin-top: 16px; margin-bottom: 4px; }}
hr {{ background-color: {c['rule']}; margin-top: 14px; margin-bottom: 14px; }}
hr.heading-rule {{ margin-top: 0px; margin-bottom: 10px; }}
p {{ margin-top: 4px; margin-bottom: 10px; line-height: 6px; -qt-line-height-type: line-distance; }}
li {{ margin-top: 3px; line-height: 4px; -qt-line-height-type: line-distance; }}
td, th {{ line-height: 6px; -qt-line-height-type: line-distance; }}
table.data td, table.data th {{ padding-top: 3px; padding-bottom: 3px; }}  /* (a row 37 pixels high: GitHub's is 37 at 16 px letters) */
ul, ol {{ margin-bottom: 10px; }}
li ul, li ol {{ margin-bottom: 0px; }}
li ul {{ list-style-type: circle; }}
li li ul {{ list-style-type: square; }}
div {{ margin-bottom: 10px; }}
dd {{ line-height: 6px; -qt-line-height-type: line-distance; }}
a {{ color: {c['link']}; text-decoration: none; }}
code {{ background-color: {c['code_bg']}; color: {c['code_fg']}; font-family: monospace; }}
pre {{ background-color: {c['pre_bg']}; font-family: monospace; margin-top: 0px; margin-bottom: 0px; }}
pre code {{ background-color: {c['pre_bg']}; color: {c['text']}; }}
blockquote {{ background-color: {c['quote_bg']}; color: {c['quote_fg']}; margin-left: 12px;
              margin-right: 12px; }}
th {{ background-color: {c['th_bg']}; font-weight: 700; }}
dt {{ font-weight: 700; margin-top: 6px; }}
dd {{ margin-left: 28px; margin-bottom: 6px; }}
s, del {{ color: {c['muted']}; }}
.task-done {{ color: {c['mark']}; font-weight: 700; }}
.task-open {{ color: {c['muted']}; font-weight: 700; }}
.footnotes {{ color: {c['muted']}; }}
.front-matter {{ color: {c['muted']}; font-size: small; }}
.math {{ color: {c['math']}; font-family: {MATH_FAMILIES}; }}
.math-block {{ color: {c['math']}; font-family: {MATH_FAMILIES}; margin-top: 6px; margin-bottom: 10px; }}
.math-rows {{ color: {c['math']}; font-family: monospace; background-color: transparent; }}
.alert-title {{ font-weight: 700; margin-top: 0px; margin-bottom: 4px; }}
.code-label {{ color: {c['muted']}; font-size: small; margin-top: 0px; margin-bottom: 6px; }}
.code-gap {{ font-size: 4px; margin-top: 0px; margin-bottom: 0px; }}
.image-chip {{ color: {c['muted']}; }}
a .image-chip {{ color: {c['link']}; }}
.kbd {{ background-color: {c['code_bg']}; font-family: monospace; }}
.mark {{ background-color: {c['highlight_bg']}; color: {c['text']}; }}
.summary {{ margin-top: 6px; }}
a.fold {{ color: {c['text']}; text-decoration: none; }}
.details {{ margin-left: 0px; }}
"""


def _highlight(code: str, lang: str, dark: bool) -> str | None:
    """*code* as HTML coloured by Pygments for *lang*, or None (no Pygments,
    an unknown language, a block too long)."""
    if not lang or len(code) > HIGHLIGHT_LIMIT:
        return None
    try:
        from pygments import format as formatted
        from pygments.formatters import HtmlFormatter
    except ImportError:
        return None
    # (lexed in a child: a lexer's pattern stuck in backtracking held Python's lock - the window froze;
    # too slow, the block plain - core.markdown_doc.code_tokens)
    tokens = MD.code_tokens(code if code.endswith("\n") else code + "\n", lang)
    if tokens is None:
        return None
    style = _github_style(dark)  # (GitHub's colours, as Qt's own parser's page colours code - Pygments'
    # github-dark left builtins (print, len, str) uncoloured, its numbers as strings)
    try:
        formatter = HtmlFormatter(noclasses=True, nowrap=True, style=style)
    except Exception:  # noqa: BLE001 - an older Pygments without the style
        formatter = HtmlFormatter(noclasses=True, nowrap=True)
    return formatted(tokens, formatter)


#: GitHub's colours of code on a light page (its "prettylights" palette):
#: Pygments' own default was a Qt-era green and blue.
GITHUB_LIGHT = {"keyword": "#cf222e", "string": "#0a3069", "comment": "#6e7781", "number": "#0550ae",
                "function": "#8250df", "class": "#953800", "constant": "#0550ae", "tag": "#116329",
                "deleted": "#82071e"}
#: ... and on a dark one (GitHub's dark theme - Pygments' github-dark left builtins uncoloured).
GITHUB_DARK = {"keyword": "#ff7b72", "string": "#a5d6ff", "comment": "#8b949e", "number": "#79c0ff",
               "function": "#d2a8ff", "class": "#ffa657", "constant": "#79c0ff", "tag": "#7ee787",
               "deleted": "#ffa198"}


def _github_light():
    """A Pygments style of GITHUB_LIGHT."""
    return _github_style(False)


@functools.lru_cache(maxsize=2)
def _github_style(dark: bool):
    """A Pygments style of GITHUB_DARK or GITHUB_LIGHT."""
    from pygments.style import Style
    from pygments.token import Comment, Error, Generic, Keyword, Name, Number, Operator, String

    c = GITHUB_DARK if dark else GITHUB_LIGHT

    class GitHub(Style):
        background_color = "#161b22" if dark else "#f6f8fa"
        styles = {
            # (function names bold, comments italic: as Pygments' github-dark)
            Comment: "italic " + c["comment"], Keyword: c["keyword"], Keyword.Constant: c["constant"],
            Name.Function: "bold " + c["function"], Name.Class: c["class"], Name.Builtin: c["constant"],
            Name.Decorator: c["function"], Name.Tag: c["tag"], Name.Attribute: c["constant"],
            Name.Constant: c["constant"], String: c["string"], String.Escape: c["constant"],
            String.Interpol: c["constant"], Number: c["number"], Operator: c["constant"],
            Operator.Word: c["keyword"], Generic.Deleted: c["deleted"], Generic.Inserted: c["tag"],
            Generic.Heading: "bold " + c["constant"], Error: c["deleted"],
        }

    return GitHub


def _code_gap(tokens, idx: int, env) -> str:
    """Between two code blocks one after the other, a line that is no code:
    Qt joined them into one (Copy Code Block copied both)."""
    if env.get("browser") or not idx or tokens[idx - 1].type not in ("fence", "code_block"):
        return ""
    return '<p class="code-gap">&nbsp;</p>\n'


def _last_in_box(tokens, idx: int) -> bool:
    """Is the code block at *idx* the last thing of a quote or an alert?"""
    return idx + 1 < len(tokens) and tokens[idx + 1].type == "blockquote_close"


def _image_html(src: str, alt: str, extra: str, env) -> str:
    """An image of the page: for Qt an <img> the view decides on (beside the
    file, data:) or a chip (on the network: never loaded); for a page of its
    own (*env* "browser") only an image the viewer read and checked, put in
    it (*env* "images") - any other a chip."""
    if env.get("browser"):
        found = (env.get("images") or {}).get(src)
        if found is None:
            return image_chip(src, alt, tr_text("Image not in the exported page"))
        src = found
    elif _remote(src):
        return image_chip(src, alt, tr_text("Remote image, not loaded"))
    return f'<img src="{html.escape(src)}" alt="{html.escape(alt)}"{extra} />'


def _title(kind: str) -> tuple[str, str]:
    """(sign, translated title) of the alert *kind*."""
    sign, title = ALERT_TITLES.get(kind, ("", kind.title()))
    try:
        from core.i18n import tr
    except ImportError:  # pragma: no cover - an export without it
        return sign, title
    return sign, tr(title)


#: Fenced languages that are drawings GitHub draws; shown here as their
#: source, said so in the block's label.
DIAGRAMS = ("mermaid", "geojson", "topojson", "stl", "plantuml")


def _code_label(lang: str) -> str:
    """The label over a fenced block: its language - a diagram's said to be
    shown as its source."""
    lang = MD.clean(lang)[:40]
    if lang.lower() in DIAGRAMS:
        try:
            from core.i18n import tr
        except ImportError:  # pragma: no cover
            return f"{lang} – diagram, shown as its source"
        return tr("{language} – diagram, shown as its source").format(language=lang)
    return lang


#: Boxes (tables: a quote's or an alert's bar, a code block's padding) drawn
#: inside each other at most; deeper, a plain quote or code block.
BOXES = 3
#: Tags of raw HTML (core.markdown_doc's allowed subset) as Qt's rich text
#: shows them: (start, end) - what Qt does not know, or would count as a
#: heading of the outline, in the HTML it knows.
_QT_TAGS = {
    # (its contents indented under the summary; one folded: fold_details -
    # its summary a link that folds or unfolds it)
    "details": ('<div class="details">', "</div>"),
    "summary": ('<p class="summary"><b>▾ ', "</b></p>"),
    "kbd": ('<span class="kbd">', "</span>"), "mark": ('<span class="mark">', "</span>"),
    "ins": ("<u>", "</u>"), "strike": ("<s>", "</s>"),
}


def events_html(events, browser: bool = False, images: dict | None = None, links: list | None = None) -> str:
    """The HTML of raw HTML's allowed events (core.markdown_doc.html_events):
    only the tags and attributes they hold, every text and value escaped -
    for Qt (*browser* False: in tags it shows) or a browser page (*images*:
    the ``data:`` address of each image read for it). *links*: the <a>
    open (across one page's raw HTML: an <a name> without an address is
    an anchor before its text, not a link around it - Qt drew it as one)."""
    out = []
    for event in events:
        if event[0] == "text":
            out.append(html.escape(event[1], quote=False))
            continue
        tag = event[1]
        if event[0] == "end":
            if tag == "a" and links and not links.pop():
                continue  # (an anchor without an address: closed where it began)
            if tag not in MD.HTML_BLOCK or tag in ("br", "img", "hr"):
                continue
            if not browser and tag == "summary" and len(event) > 2:
                out.append("</b></a></p>")
                continue
            out.append(_QT_TAGS[tag][1] if not browser and tag in _QT_TAGS else f"</{tag}>")
            continue
        values = event[2]
        if tag == "a":
            if links is not None:
                links.append(bool(values.get("href")))
            if not values.get("href") and values.get("name"):
                out.append(f'<a name="{html.escape(values["name"])}"></a>')
                continue
        if tag == "img":
            src = values.get("src", "")
            if browser and (images or {}).get(src) is None:
                out.append(image_chip(src, values.get("alt", ""), tr_text("Image not in the exported page")))
                continue
            if not browser and _remote(src):
                out.append(image_chip(src, values.get("alt", ""), tr_text("Remote image, not loaded")))
                continue
            if browser:
                values = {**values, "src": images[src]}
        attrs = "".join(f' {name}="{html.escape(value)}"' for name, value in values.items()
                        if name in ("align", "src", "alt", "title", "width", "height", "href", "name",
                                    "colspan", "rowspan"))
        if tag == "ol" and str(values.get("start", "")).isdigit():  # (a list's piece going on: _html_pieces)
            attrs += f' start="{int(values["start"])}"'
        if browser and tag == "details" and "open" in values:
            attrs += " open"
        if tag in ("br", "hr", "img"):
            out.append(f"<{tag}{attrs} />")
        elif not browser and tag == "summary" and values.get("fold"):
            # (a folded <details>' summary: a click on it shows what it holds)
            out.append(f'<p class="summary"><a class="fold" href="#{FOLD}{values["fold"]}"><b>'
                       f'{"▾" if values.get("open") else "▸"} ')
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6") and values.get("id"):
            # (a heading of the outline: its anchor, as a Markdown heading's)
            anchor = html.escape(values["id"])
            out.append(f'<{tag}{attrs} id="{anchor}">' if browser else f'<{tag}{attrs}><a name="{anchor}"></a>')
        elif not browser and tag in _QT_TAGS:
            start = _QT_TAGS[tag][0]
            out.append(f"{start}{attrs}>" if start.endswith('"') else start)
        elif tag in MD.HTML_BLOCK:
            out.append(f"<{tag}{attrs}>")
    return "".join(out)


#: A folded <details>' summary links to "#axross-details-N" - the N-th of
#: the page (fold_details; ui.markdown_view folds or unfolds it on a click).
FOLD = "axross-details-"


def fold_details(tokens: list, toggled=frozenset(), hidden: dict | None = None, first: int = 0) -> list:
    """*tokens* with what each closed ``<details>`` holds after its summary
    left out - closed as GitHub shows it: unless it says ``open``, or its
    number (1, 2 ... in the order of the text) is in *toggled* (a click
    turned it). Its summary carries its number (``fold``) and whether it is
    open; one without a summary gets "Details". Blocks a details' container
    closes (a list item it is in) end what it hides: the page stays whole.
    *hidden* gets what each closed one hides: ``{"text": {number: text},
    "anchors": {anchor: number}}`` (find and a link to a heading in it open
    it, as a browser does) and how many there are (``"count"``). *first*:
    the number before the first (a long text's later part)."""
    out: list = []
    if hidden is not None:
        hidden.setdefault("text", {})
        hidden.setdefault("anchors", {})

    def note(text: str = "", anchor: str = "") -> None:  # (what the closed details hiding it holds)
        if hidden is None or not hiding or hiding > len(stack):
            return
        owner = stack[hiding - 1][0]
        if text:
            hidden["text"][owner] = hidden["text"].get(owner, "") + " " + text
        if anchor:
            hidden["anchors"].setdefault(anchor, owner)
    number = first
    stack: list[list] = []  # per open details: [number, open, summary (0 not yet, 1 in it, 2 done), level]
    hiding = 0  # the depth of the stack whose details' contents are left out (0: none)
    level = 0  # the level of the tokens of that details
    dropped = 0  # the nesting of the tokens left out (their ends go too)

    def summary(entry) -> list[tuple]:
        mark = {"fold": str(entry[0]), "open": "1" if entry[1] else ""}
        return [("start", "summary", mark), ("text", tr_text("Details")), ("end", "summary", mark)]

    def summarised(entry) -> None:  # (its summary ended: closed, what follows is left out)
        nonlocal hiding, level
        entry[2] = 2
        if not entry[1]:
            hiding, level = len(stack), entry[3]

    for token in tokens:
        if hiding and token.level < level:
            hiding = 0  # (the container it is in closes: so does it)
        if token.type != "safe_html_block":
            if not hiding and not dropped and stack and stack[-1][2] == 0:
                entry = stack[-1]
                synthetic = token.copy(type="safe_html_block", tag="", nesting=0, content="", children=None,
                                       meta={"html": summary(entry)}, map=None, info="", markup="")
                synthetic.block = True
                out.append(synthetic)
                summarised(entry)
            if hiding or dropped:
                dropped = max(0, dropped + token.nesting)
                if token.type == "inline":
                    note(text=token.content)
                elif token.type == "heading_open":
                    note(anchor=str(token.attrGet("id") or ""))
                continue
            out.append(token)
            continue
        kept: list[tuple] = []
        for event in MD.html_events(token):
            visible = not hiding and not dropped
            kind, tag = event[0], (event[1] if event[0] != "text" else "")
            if tag == "details":
                if kind == "start":
                    number += 1
                    stack.append([number, ("open" in event[2]) != (number in toggled), 0, token.level])
                elif stack:
                    entry = stack.pop()
                    if entry[2] == 0 and visible:
                        kept.extend(summary(entry))
                    if hiding and len(stack) < hiding:
                        hiding = 0
                        visible = not dropped
                if visible:
                    kept.append(event)
                continue
            top = stack[-1] if stack else None
            if visible and top is not None and top[2] == 0:
                if kind == "start" and tag == "summary":
                    top[2] = 1
                    kept.append(("start", "summary", {"fold": str(top[0]), "open": "1" if top[1] else ""}))
                    continue
                if kind != "text" or event[1].strip():
                    kept.extend(summary(top))
                    summarised(top)
                    visible = not hiding
            elif visible and top is not None and top[2] == 1:
                if kind == "end" and tag == "summary":
                    kept.append(("end", "summary", {"fold": str(top[0])}))
                    summarised(top)
                    continue
                if tag == "a":
                    continue  # (a link in the summary: the summary is the fold's link)
            if visible:
                kept.append(event)
            elif kind == "text":
                note(text=event[1])
            elif kind == "start" and event[2].get("id"):
                note(anchor=event[2]["id"])
        if kept:
            out.append(token.copy(meta={"html": kept}))
    if hidden is not None:
        hidden["count"] = number - first
    return out


#: Raw HTML's tags of a block (a paragraph, a list …): _loose
_BLOCK_TAGS = frozenset("p div details summary h1 h2 h3 h4 h5 h6 hr blockquote pre table thead tbody tr th "
                        "td ul ol li center".split())


def _loose_paragraphs(events) -> list:
    """An HTML block's events with its text outside any block of its own
    (after a <p>: "<p>a</p> loose words") in a paragraph each - it ran into
    the next block."""
    if not any(e[0] in ("start", "end") and e[1] in _BLOCK_TAGS for e in events):
        return events  # (all of it loose: _loose makes it one paragraph)
    out, depth, run = [], 0, []

    def flush() -> None:
        if any(e[0] == "text" and e[1].strip() for e in run) or any(e[0] == "start" and e[1] == "img" for e in run):
            out.extend([("start", "p", {}), *run, ("end", "p")])
        else:
            out.extend(run)
        run.clear()

    for event in events:
        block = event[0] in ("start", "end") and event[1] in _BLOCK_TAGS
        if depth == 0 and not block:
            run.append(event)
            continue
        flush()
        if block and event[1] not in ("hr",):
            depth += 1 if event[0] == "start" else -1
            depth = max(0, depth)
        out.append(event)
    flush()
    return out


def _loose(events) -> bool:
    """Whether an HTML block's events are text (and inline tags) only - an
    image too: a block of one <img> went up into the paragraph before it."""
    return any(event[0] == "text" and event[1].strip() or event[:2] == ("start", "img") for event in events) \
        and not any(event[0] in ("start", "end") and event[1] in _BLOCK_TAGS for event in events)


def _math_table(grid, label: str = "", rule: str = "#1f2328") -> str:
    """A formula's grid (core.markdown_doc.math_grid) as a table without
    borders in the middle of the page: its cells in their columns, what
    stands before and after the rows beside all of them."""
    rows, spans, aligns, gaps, ruled, tall = grid
    tall = {(entry[0], entry[1]): entry[3] for entry in tall}
    span = {(entry[0], entry[1]): entry[2] for entry in spans}
    sits = {(entry[0], entry[1]): entry[4] for entry in spans if len(entry) > 4}
    covered = {(entry[0] + n, entry[1]) for entry in spans for n in range(1, entry[2])}
    gaps = {gap: 16 for gap in gaps if isinstance(gap, int)} | {gap[0]: gap[1] for gap in gaps if not isinstance(gap, int)}
    out = ['<table class="math-grid" align="center" border="0" cellspacing="0" cellpadding="1" '
           'style="margin-top: 12px; margin-bottom: 12px">']
    for number, row in enumerate(rows):
        out.append("<tr>")
        for column, cell in enumerate(row):
            if (number, column) in covered:
                continue
            down = f' rowspan="{span[number, column]}"' if (number, column) in span else ""
            if (number, column) in span:  # (in the middle of its rows - a fraction's part at the bar)
                down += f' valign="{sits.get((number, column), "middle")}"'
            barred = {c for _r, c in ruled}  # (a fraction's column: its room in the cell before - the bar
            style = f"padding-left: {gaps[column]}px; " if column in gaps and column not in barred else ""
            if column + 1 in gaps and column + 1 in barred:  # (ran under it)
                style += f"padding-right: {gaps[column + 1]}px; "
            if (number, column) in ruled:  # (a fraction's numerator over its bar)
                style += f"border-bottom: 1px solid {rule}; "
            room = f' style="{style.strip()}"' if style else ""
            limit = tall.get((number, column), 0) < 0  # (an operator's limit: tight, as a script)
            shown = (html.escape(cell) if cell in _GLYPHS else MD.math_html(cell, tight=limit)) if cell else ""
            if (number, column) in tall:  # (a brace of one piece as tall as its rows, an operator, its limits:
                # Qt's relative size, so it grows with a zoom as the letters do)
                shown = f'<font size="{3 + tall[number, column]}">{shown}</font>'
            if cell and cell not in _GLYPHS:  # (a glyph drawn large in the page's face: the math face's lines
                shown = f'<span class="math">{shown}</span>'  # at twice the size were twice as far apart)
            out.append(f'<td align="{aligns[column]}"{down}{room}>{shown}</td>')
        if number == 0 and label:
            out.append(f'<td rowspan="{len(rows)}" valign="middle"><span class="math-block">{label}</span></td>')
        out.append("</tr>")
    return "".join(out) + "</table>\n"


#: A grid's cells that are a glyph to draw large, not TeX (a brace, a bracket, an operator).
_GLYPHS = frozenset("{}()[]|‖∑∏∐⋃⋂⨁⨂⋁⋀∫∬∭∮")


# -- display math: a row of items on one axis -------------------------------------------------------------

#: The most tables inside each other a display formula is laid out as (8: 10 ms in Qt, 10: 80 ms,
#: 14: 1 s), and the most tables of one formula; more: in its line, as text.
TABLE_DEPTH, TABLES = 8, 120
_TABLE_TAG = re.compile(r"<(/?)table\b")
#: The anchor a display formula's TeX is kept in (base64 after it): a copy holds the TeX.
TEX_ANCHOR = "axross-tex:"
#: ... an inline formula's (on its first letter).
TEX_INLINE = "axross-itex:"
#: Qt's size steps of a display formula's large glyphs: an operator, an integral, its limits.
OPERATOR_STEP, INTEGRAL_STEP, LIMIT_STEP = 2, 3, -1
_BIG_OPERATORS = {"sum": "∑", "prod": "∏", "coprod": "∐", "bigcup": "⋃", "bigcap": "⋂", "bigoplus": "⨁",
                  "bigotimes": "⨂", "bigvee": "⋁", "bigwedge": "⋀"}
_INTEGRALS = {"int": "∫", "iint": "∬", "iiint": "∭", "oint": "∮"}
_LIMITS = ("lim", "max", "min", "sup", "inf", "limsup", "liminf", "det", "gcd")
_DELIMITERS = {"(": "(", ")": ")", "[": "[", "]": "]", "\\{": "{", "\\}": "}", "|": "|", "\\|": "‖",
               "\\vert": "|", "\\Vert": "‖", "\\langle": "⟨", "\\rangle": "⟩", "\\lfloor": "⌊", "\\rfloor": "⌋",
               "\\lceil": "⌈", "\\rceil": "⌉", "/": "/", ".": ""}
_MATRIX_BRACKETS = {"pmatrix": ("(", ")"), "bmatrix": ("[", "]"), "Bmatrix": ("{", "}"), "vmatrix": ("|", "|"),
                    "Vmatrix": ("‖", "‖"), "matrix": ("", ""), "smallmatrix": ("", ""), "array": ("", "")}
_ALIGNED_NAMES = ("aligned", "align", "split", "gathered", "alignat", "eqnarray", "gather")
_COMMAND = re.compile(r"\\([A-Za-z]+)\*?")
_MIDDLE = re.compile(r"\\middle\s*(\\[A-Za-z]+|\\[{}|]|[()\[\]|./])")
_DELIMITER = re.compile(r"\s*(\\[A-Za-z]+|\\[{}|]|[()\[\]|./])")
#: How deep display items go inside each other (a fraction in a fraction...): deeper, as text.
DISPLAY_DEPTH = 6
#: A display formula longer than this is shown in its line, as text (laid out it is a table of tables:
#: Qt took seconds for a few thousand cells).
DISPLAY_CHARS = 3000


def _group_at(tex: str, at: int):
    """(the inside of the {group} at *at* - spaces skipped - or its one token, where it ends) or None."""
    while at < len(tex) and tex[at].isspace():
        at += 1
    if at >= len(tex):
        return None
    if tex[at] == "{":
        depth = 0
        for index in range(at, len(tex)):
            depth += {"{": 1, "}": -1}.get(tex[index], 0)
            if depth == 0:
                return tex[at + 1:index], index + 1
        return None
    token = re.compile(r"\\[A-Za-z]+|\\.|[^\s{}]").match(tex, at)
    return (token.group(0), token.end()) if token else None


def _scripts_at(tex: str, at: int):
    """(lower, upper, where they end) of "_x^y" (either first; \\limits skipped) at *at*."""
    skipped = re.compile(r"\s*\\(?:limits|nolimits)(?![A-Za-z])").match(tex, at)
    at = skipped.end() if skipped else at
    lower = upper = None
    for _round in range(2):
        mark = re.compile(r"\s*([_^])").match(tex, at)
        if not mark or (mark.group(1) == "_" and lower is not None) or (mark.group(1) == "^" and upper is not None):
            break
        found = _group_at(tex, mark.end())
        if found is None:
            break
        if mark.group(1) == "_":
            lower = found[0]
        else:
            upper = found[0]
        at = found[1]
    return lower, upper, at


_PAIRED = re.compile(r"\\(left|right)(?![A-Za-z])|\\(begin|end)\s*\{([A-Za-z]+\*?)\}")


def _pairs(tex: str) -> dict:
    """Where each \\left and \\begin{...} of *tex* is closed: {where the
    command begins: (where its closing begins, where it ends)} - one pass
    with a stack (a search for each from its place on held the window 19 s
    for 600 of them inside each other)."""
    pairs, lefts, begins = {}, [], []
    for found in _PAIRED.finditer(tex):
        if found.group(1) == "left":
            lefts.append(found.start())
        elif found.group(1) == "right":
            if lefts:
                pairs[lefts.pop()] = (found.start(), found.end())
        elif found.group(2) == "begin":
            begins.append((found.start(), found.group(3)))
        elif begins and begins[-1][1] == found.group(3):
            pairs[begins.pop()[0]] = (found.start(), found.end())
    return pairs


def display_items(tex: str) -> list:
    """The items of a display formula's row at its top level: ("text", tex),
    ("frac", upper, lower), ("binom", upper, lower), ("big", glyph, lower,
    upper), ("integral", glyph, lower, upper), ("limit", tex, lower),
    ("delimited", left, inside, right, lower, upper), ("env", name, body), ("tag", text),
    ("stack", base, upper, lower),
    ("lines", [rows]) - or [] when it has none but text."""
    items, text, at, depth = [], [], 0, 0
    if len(tex) > DISPLAY_CHARS or MD.math_too_deep(tex):  # (as text, in its line: laid out it held the
        return []  # window - deeper than MATH_DEPTH, as written with its note)
    rows = _top_level_rows(tex)  # (lines of its own: "\\" at its top level)
    if len(rows) > 1:
        return [("lines", rows)]
    pairs = _pairs(tex) if "\\left" in tex or "\\begin" in tex else {}

    def flush():
        if "".join(text).strip():
            items.append(("text", "".join(text)))
        text.clear()

    while at < len(tex):
        ch = tex[at]
        if ch in "{}":
            depth += 1 if ch == "{" else -1
            text.append(ch)
            at += 1
            continue
        command = _COMMAND.match(tex, at) if ch == "\\" else None
        if command is None or depth:
            text.append(tex[at:command.end()] if command else ch)
            at = command.end() if command else at + 1
            continue
        name = command.group(1)
        if name in ("overset", "stackrel", "underset"):  # (a sign over or under another, stacked: "=" with "!")
            first = _group_at(tex, command.end())
            base = _group_at(tex, first[1]) if first else None
            if first and base:
                flush()
                over = name != "underset"
                items.append(("stack", base[0], first[0] if over else None, None if over else first[0]))
                at = base[1]
                continue
        if name in ("frac", "dfrac", "tfrac", "cfrac", "binom", "dbinom", "tbinom"):
            upper = _group_at(tex, command.end())
            lower = _group_at(tex, upper[1]) if upper else None
            if upper and lower:
                flush()
                items.append(("binom" if "binom" in name else "frac", upper[0], lower[0]))
                at = lower[1]
                continue
        elif name in _BIG_OPERATORS or name in _INTEGRALS:
            lower, upper, end = _scripts_at(tex, command.end())
            flush()
            items.append(("big" if name in _BIG_OPERATORS else "integral",
                          _BIG_OPERATORS.get(name) or _INTEGRALS[name], lower, upper))
            at = end
            continue
        elif name in _LIMITS:
            lower, upper, end = _scripts_at(tex, command.end())
            if lower is not None and upper is None:
                flush()
                items.append(("limit", "\\" + name, lower))
                at = end
                continue
        elif name == "begin":
            found = re.compile(r"\s*\{([A-Za-z]+\*?)\}").match(tex, command.end())
            if found:
                env = found.group(1)
                matched = pairs.get(command.start())
                if matched:
                    flush()
                    items.append(("env", env, tex[found.end():matched[0]]))
                    at = matched[1]
                    continue
        elif name == "left":
            found = _DELIMITER.match(tex, command.end())
            if found and found.group(1) in _DELIMITERS:
                matched = pairs.get(command.start())
                closing = _DELIMITER.match(tex, matched[1]) if matched else None
                if closing and closing.group(1) in _DELIMITERS:
                    flush()
                    lower, upper, end = _scripts_at(tex, closing.end())  # ("\right)^2": the 2 its own)
                    items.append(("delimited", _DELIMITERS[found.group(1)], tex[found.end():matched[0]],
                                  _DELIMITERS[closing.group(1)], lower, upper))
                    at = end
                    continue
        elif name in ("underbrace", "overbrace"):  # (a brace under or over it - as a rule - its label there)
            found = _group_at(tex, command.end())
            if found:
                lower, upper, end = _scripts_at(tex, found[1])
                flush()
                items.append(("brace", name == "underbrace", found[0], lower if name == "underbrace" else upper))
                at = end
                continue
        elif name in ("sqrt", "boxed", "fbox"):
            index = re.compile(r"\s*\[([^\]]*)\]").match(tex, command.end()) if name == "sqrt" else None
            found = _group_at(tex, index.end() if index else command.end())
            if found and (name != "sqrt" or display_items(found[0][:DISPLAY_CHARS])):  # (a root of a fraction, a sum:
                flush()  # laid out - a root of a letter stays in its line, its bar over it)
                items.append(("root", index.group(1).strip() if index else "", found[0]) if name == "sqrt"
                             else ("boxed", found[0]))
                at = found[1]
                continue
        elif name == "tag":
            found = _group_at(tex, command.end())
            if found:
                flush()
                starred = tex[command.start():command.end()].endswith("*")
                items.append(("tag", found[0].strip() if starred else f"({found[0].strip()})"))
                at = found[1]
                continue
        text.append(command.group(0))
        at = command.end()
    flush()
    return items if any(item[0] != "text" for item in items) else []


def _top_level_rows(tex: str) -> list[str]:
    """*tex* cut at each "\\\\" outside groups and environments."""
    rows, depth, envs, start, at = [], 0, 0, 0, 0
    while at < len(tex):
        if tex.startswith("\\begin", at):
            envs += 1
        elif tex.startswith("\\end", at):
            envs -= 1
        elif tex[at] in "{}":
            depth += 1 if tex[at] == "{" else -1
        elif tex.startswith("\\\\", at):
            if not depth and not envs:
                rows.append(tex[start:at])
                start = at + 2
            at += 2
            continue
        at += 1
    rows.append(tex[start:])
    return [row for row in rows if row.strip()] or [tex]


def display_html(tex: str, palette: dict, label: str = "") -> str | None:
    """(_display_html - any fault of its in one formula: that one in its line, as text - a KeyError of a
    Bmatrix's brace blanked all of the page.)"""
    try:
        return _display_html(tex, palette, label)
    except Exception:  # noqa: BLE001 - a formula's layout never takes the page down
        log.warning("A display formula could not be laid out; shown as text", exc_info=True)
        return None


def _display_html(tex: str, palette: dict, label: str = "") -> str | None:
    """A display formula as HTML for Qt's rich text and a browser - as KaTeX's
    display style: a row of items on one axis, each in a cell in the middle
    of the row - a fraction its numerator over a bar over its denominator, a
    sum large with its limits above and below it (an integral's beside it),
    a matrix or cases a grid of their own in brackets as tall as they are,
    \\left( \\right) as tall as what they hold, \\tag at the right - or None
    (no such item: a line of text, math_html)."""
    if len(tex) > MD.MATH_LIMIT or MD.math_too_deep(tex):
        return None  # (in its line: math_html - deeper than MATH_DEPTH, as written with its note)
    written, tex = tex, MD.math_normal(tex)  # (\\frac12, {n \\choose k}: stacked as written in braces)
    items = display_items(tex)
    if not items:
        if not label:
            return None
        items = [("text", tex)]
    tags = [item[1] for item in items if item[0] == "tag"]
    label = label or (tags[0] if tags else "")
    row = _row_html([item for item in items if item[0] != "tag"], palette, 0)
    # (its TeX on it: a copy holds that, as KaTeX's - its cells' pieces were scattered over lines)
    depth, deepest = 0, 0
    for found in _TABLE_TAG.finditer(row):  # (Qt lays tables inside tables out in time that grows fast with
        depth += -1 if found.group(1) else 1  # their depth: 7 matrices in each other held the window 18 s)
        deepest = max(deepest, depth)
    if deepest > TABLE_DEPTH or row.count("<table") > TABLES:
        return None  # (in its line, as text - math_html)
    # (in a cell of its own before the row's first: in that one, before a fraction's table, a line of its own)
    mark = f'<td><a name="{TEX_ANCHOR}{base64.b64encode(written.encode("utf-8")).decode("ascii")}"></a>&#8203;</td>'
    row = row.replace("<tr>", "<tr>" + mark, 1)
    if label:  # (the formula in the middle of the page, its tag at the right)
        return ('<table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin-top: 10px; '
                'margin-bottom: 12px"><tr><td width="12%"></td>'
                f'<td align="center" valign="middle">{row}</td>'
                f'<td width="12%" align="right" valign="middle">{_math_span(html.escape(label), palette)}</td>'
                "</tr></table>\n")
    return row.replace('<table ', '<table align="center" style="margin-top: 10px; margin-bottom: 12px" ', 1) + "\n"


def _math_span(inner: str, palette: dict) -> str:
    families = MATH_FAMILIES.replace('"', "'")  # (in a double-quoted attribute: it ended at the first name)
    return f'<span style="font-family: {families}; color: {palette["math"]}">{inner}</span>'


def _glyph(glyph: str, step: int) -> str:
    return f'<font size="{3 + step}">{html.escape(glyph)}</font>' if glyph else ""


def _small(inner: str) -> str:
    return f'<font size="{3 + LIMIT_STEP}">{inner}</font>'


def _inline(tex: str, palette: dict, tight: bool = False) -> str:
    return _math_span(MD.math_html(tex, tight=tight).replace("<br />", " "), palette) if tex.strip() else ""


def _part(tex: str, palette: dict, depth: int) -> str:
    """*tex* (a numerator, a cell): a row of its own when it has items, else in its line."""
    items = display_items(tex) if depth < DISPLAY_DEPTH else []
    items = [item for item in items if item[0] != "tag"]
    return _row_html(items, palette, depth + 1) if items else _inline(tex, palette)


def _table(cells: str, extra: str = "") -> str:
    return f'<table border="0" cellspacing="0" cellpadding="0"{extra}><tr>{cells}</tr></table>'


def _row_html(items: list, palette: dict, depth: int) -> str:
    cells = []
    for item in items:
        kind = item[0]
        if kind == "text":
            shown = _inline(item[1], palette)
            if shown:
                cells.append(f'<td valign="middle" style="padding-left: 3px; padding-right: 3px">{shown}</td>')
        elif kind == "lines":
            rows = "".join(f'<tr><td align="center" style="padding: 2px">{_part(row, palette, depth)}</td></tr>'
                           for row in item[1])
            cells.append(f'<td valign="middle"><table border="0" cellspacing="0" cellpadding="0">{rows}</table></td>')
        elif kind in ("frac", "binom"):
            bar = f"border-bottom: 1px solid {palette['text']}; " if kind == "frac" else ""
            stack = ('<table border="0" cellspacing="0" cellpadding="0">'
                     f'<tr><td align="center" valign="bottom" style="{bar}padding: 0px 3px 1px 3px">'
                     f'{_part(item[1], palette, depth)}</td></tr>'
                     f'<tr><td align="center" valign="top" style="padding: 1px 3px 0px 3px">'
                     f'{_part(item[2], palette, depth)}</td></tr></table>')
            if kind == "binom":  # (n over k in parentheses as tall as they are)
                cells.append(f'<td valign="middle">{_glyph("(", 3)}</td><td valign="middle">{stack}</td>'
                             f'<td valign="middle">{_glyph(")", 3)}</td>')
            else:
                cells.append(f'<td valign="middle" style="padding-left: 2px; padding-right: 2px">{stack}</td>')
        elif kind == "big":  # (its limits above and below it - a space where one is not: on its axis still)
            _kind, glyph, lower, upper = item
            stack = ('<table border="0" cellspacing="0" cellpadding="0">'
                     f'<tr><td align="center" valign="bottom">{_small(_inline(upper or "", palette, True) or "&#8203;")}'
                     f'</td></tr><tr><td align="center">{_glyph(glyph, OPERATOR_STEP)}</td></tr>'
                     f'<tr><td align="center" valign="top">{_small(_inline(lower or "", palette, True) or "&#8203;")}'
                     "</td></tr></table>")
            cells.append(f'<td valign="middle" style="padding-left: 2px; padding-right: 2px">{stack}</td>')
        elif kind == "integral":  # (its limits beside it, at its top and its foot)
            _kind, glyph, lower, upper = item
            cells.append(f'<td valign="middle">{_glyph(glyph, INTEGRAL_STEP)}</td>')
            if lower is not None or upper is not None:
                cells.append('<td valign="middle"><table border="0" cellspacing="0" cellpadding="0">'
                             f'<tr><td valign="top" style="padding-bottom: 10px">'
                             f'{_small(_inline(upper or "", palette, True) or "&#8203;")}</td></tr>'
                             f'<tr><td valign="bottom" style="padding-top: 10px">'
                             f'{_small(_inline(lower or "", palette, True) or "&#8203;")}</td></tr></table></td>')
        elif kind == "stack":  # (\\overset, \\underset: the sign, the other small over or under it)
            _kind, base, upper, lower = item
            stack = ('<table border="0" cellspacing="0" cellpadding="0">'
                     f'<tr><td align="center" valign="bottom">{_small(_inline(upper or "", palette, True) or "&#8203;")}'
                     f'</td></tr><tr><td align="center">{_part(base, palette, depth)}</td></tr>'
                     f'<tr><td align="center" valign="top">{_small(_inline(lower or "", palette, True) or "&#8203;")}'
                     "</td></tr></table>")
            cells.append(f'<td valign="middle" style="padding-left: 2px; padding-right: 2px">{stack}</td>')
        elif kind == "limit":  # (lim with its limit below it - a space above it: on its axis still)
            _kind, word, lower = item
            stack = ('<table border="0" cellspacing="0" cellpadding="0">'
                     f'<tr><td>{_small("&#8203;")}</td></tr><tr><td align="center">{_inline(word, palette)}</td></tr>'
                     f'<tr><td align="center" valign="top">{_small(_inline(lower, palette, True))}</td></tr></table>')
            cells.append(f'<td valign="middle" style="padding-left: 2px; padding-right: 2px">{stack}</td>')
        elif kind == "delimited":
            _kind, left, inside, right, lower, upper = item
            # (\middle| between them: a delimiter as tall as they are - it showed as written)
            pieces = _MIDDLE.split(inside)
            segments, middles = pieces[0::2], [_DELIMITERS.get(found, found) for found in pieces[1::2]]
            inner = [[entry for entry in display_items(segment) if entry[0] != "tag"]
                     if depth < DISPLAY_DEPTH else [] for segment in segments]
            step = 3 if any(inner) else 0  # (as tall as what they hold: a fraction, a sum)

            def glyph(sign: str) -> str:
                return _glyph(sign, step) if step else _math_span(html.escape(sign), palette)

            shown = []
            for index, segment in enumerate(segments):
                if index:
                    shown.append(f'<td valign="middle">{glyph(middles[index - 1])}</td>')
                laid = _row_html(inner[index], palette, depth + 1) if inner[index] else _inline(segment, palette)
                shown.append(f'<td valign="middle">{laid}</td>')
            cells.append(f'<td valign="middle">{glyph(left)}</td>{"".join(shown)}'
                         f'<td valign="middle">{glyph(right)}</td>')
            if lower is not None or upper is not None:  # (its scripts at its top and its foot)
                cells.append('<td valign="middle"><table border="0" cellspacing="0" cellpadding="0">'
                             f'<tr><td valign="top" style="padding-bottom: {8 if step else 0}px">'
                             f'{_small(_inline(upper or "", palette, True) or "&#8203;")}</td></tr>'
                             f'<tr><td valign="bottom" style="padding-top: {8 if step else 0}px">'
                             f'{_small(_inline(lower or "", palette, True) or "&#8203;")}</td></tr></table></td>')
        elif kind == "env":
            cells.append(_env_html(item[1], item[2], palette, depth))
        elif kind == "root":  # (its sign, its index above it, a bar over what it holds - one style of root)
            _kind, index, inside = item
            # (over a stacked part - a fraction, a sum: the sign as tall as it, up to its bar - a small one
            # stood at its foot, apart from the bar above)
            tall = any(entry[0] != "text" for entry in display_items(inside)[:DISPLAY_CHARS]) \
                if depth < DISPLAY_DEPTH else False
            sign = (f'<sup>{_small(_inline(index, palette, True))}</sup>' if index else "") + _glyph("√", 4 if tall else 2)
            cells.append(f'<td valign="{"top" if tall else "bottom"}">{sign}</td><td valign="bottom" '
                         f'style="border-top: 1px solid {palette["text"]}; padding: 2px 2px 0px 2px">'
                         f'{_part(inside, palette, depth)}</td>')
        elif kind == "brace":  # (its brace a rule under or over it with its ends, its label beyond it)
            _kind, under, inside, label = item
            rule = f"1px solid {palette['text']}"
            body = (f'<td align="center" style="border-{_EDGES[under]}: {rule}; '
                    f'border-left: {rule}; border-right: {rule}; padding: 0px 3px">{_part(inside, palette, depth)}</td>')
            note = f'<td align="center">{_small(_inline(label or "", palette, True) or "&#8203;")}</td>'
            rows = (f"<tr>{body}</tr><tr>{note}</tr>" if under else f"<tr>{note}</tr><tr>{body}</tr>")
            cells.append(f'<td valign="middle"><table border="0" cellspacing="0" cellpadding="0">{rows}</table></td>')
        elif kind == "boxed":  # (a box drawn round it)
            cells.append(f'<td valign="middle" style="border: 1px solid {palette["text"]}; padding: 2px 4px">'
                         f'{_part(item[1], palette, depth)}</td>')
    return _table("".join(cells))


def _split_top(text: str, separator: str) -> list[str]:
    """*text* cut at each *separator* ("\\\\", "&") outside groups and
    environments inside it (a matrix in a matrix came out as scrambled rows)."""
    pieces, depth, envs, start, at = [], 0, 0, 0, 0
    while at < len(text):
        if text.startswith("\\begin", at):
            envs += 1
        elif text.startswith("\\end", at):
            envs -= 1
        elif text[at] == "\\" and text[at + 1:at + 2] in ("{", "}", "&", "\\") and separator != text[at:at + 2]:
            at += 2  # (an escaped brace or ampersand: no group, no column)
            continue
        elif text[at] in "{}":
            depth += 1 if text[at] == "{" else -1
        if not depth and not envs and text.startswith(separator, at):
            pieces.append(text[start:at])
            start = at = at + len(separator)
            continue
        at += 1
    pieces.append(text[start:])
    return pieces


#: A row's number (\\tag{A}, \\tag*{A}) - and what gives none (\\notag, \\nonumber, \\label{…}).
_ROW_TAG = re.compile(r"\\tag(\*?)\s*\{([^{}]*)\}")
_NO_TAG = re.compile(r"\\(?:notag|nonumber)(?![A-Za-z])|\\label\s*\{[^{}]*\}")
_ROW_SPACE = re.compile(r"\A\s*\[[^\]]*\]")  # ("\\[4pt]": room after a row - none here)
_HLINE = re.compile(r"\\hline(?![A-Za-z])")


def _env_cells(name: str, body: str) -> tuple[list[list[str]], list[bool]]:
    """(the cells of an environment's rows - TeX each -, whether a rule is
    above each row: \\hline)."""
    rows = _split_top(body, "\\\\")
    rows = [_ROW_SPACE.sub("", row) for row in rows]
    bars = set()
    if name.rstrip("*") == "array" and rows:  # (its column spec: {c|c} - its "|" a rule between columns)
        spec = re.match(r"^\s*\{([^{}]*)\}", rows[0])
        if spec:
            column = 0
            for ch in spec.group(1):
                if ch == "|":
                    bars.add(column)
                elif ch.isalpha():
                    column += 1
            rows[0] = rows[0][spec.end():]
    ruled = [bool(_HLINE.search(row)) for row in rows]
    rows = [_HLINE.sub("", row) for row in rows]
    under = False
    while rows and not rows[-1].strip():  # (an empty last row - after "\\\\" or \\hline: none - its rule under the last)
        under = under or ruled[len(rows) - 1]
        rows.pop()
    ruled = ruled[:len(rows)]
    cells = [[cell.strip() for cell in _split_top(row, "&")] for row in rows] or [[""]]
    return cells, ruled or [False], bars, under


def _env_rows(tex: str) -> list[list[str]]:
    """(tests) the HTML of each cell of the environment *tex* is, by row."""
    found = re.match(r"\s*\\begin\s*\{([A-Za-z]+\*?)\}(.*)\\end\s*\{\1\}\s*\Z", tex, re.DOTALL)
    cells, _ruled, _bars, _under = _env_cells(found.group(1), found.group(2))
    return [[_part(cell, LIGHT, 0) if cell else "" for cell in row] for row in cells]


def _env_html(name: str, body: str, palette: dict, depth: int) -> str:
    """An environment (a matrix, cases, aligned lines) as a grid of its own in
    a cell of the row - its brackets as tall as its rows, \\hline a rule."""
    cells, ruled, bars, under = _env_cells(name, body)
    base = name.rstrip("*")
    # (a line's number - \\tag{A} in an align's row: at the row's right, it was gone; \\notag, \\label: none)
    tags = []
    for row in cells:
        found = ""
        for index, cell in enumerate(row):
            tagged = _ROW_TAG.search(cell)
            if tagged:
                found = tagged.group(2).strip() if tagged.group(1) else f"({tagged.group(2).strip()})"
            row[index] = _ROW_TAG.sub("", _NO_TAG.sub("", cell)).strip()
        tags.append(found)
    columns = max(len(row) for row in cells)
    if base in _ALIGNED_NAMES:
        aligns = ["right" if column % 2 == 0 else "left" for column in range(columns)]
    else:
        aligns = ["left" if base in ("cases", "dcases") else "center"] * columns
    left, right = _MATRIX_BRACKETS.get(base, ("{", "") if base in ("cases", "dcases") else ("", ""))
    step = 3 if len(cells) <= 2 else 4
    # (brackets exactly as tall as the rows - a glyph so large was 1.3 rows whatever their count: "[" "]" "|"
    # the rules of a cell beside the rows; "(" ")" "{" in pieces, a piece a row - ⎛⎜⎝ - when each row is a
    # line, its rows without room above and below so the pieces meet)
    ruled_sides = left in ("[", "|") and len(cells) > 1
    simple = len(cells) > (2 if left in _BRACE_MIDDLE else 1) and left in _PIECES \
        and all(not display_items(cell) for row in cells for cell in row)  # (two cases' ⎧⎩: a parenthesis)
    pad = "0px" if simple else "2px"
    tight = "-qt-line-height-type: proportional; line-height: 100%; " if simple else ""  # (the page's lines are
    # further apart than a line: the pieces met not)
    grid = []
    for number, row in enumerate(cells):
        out = []
        line = f"border-top: 1px solid {palette['text']}; " if number < len(ruled) and ruled[number] else ""
        if under and number == len(cells) - 1:
            line += f"border-bottom: 1px solid {palette['text']}; "
        for column in range(columns):
            cell = row[column] if column < len(row) else ""
            room = 16 if column and (base not in _ALIGNED_NAMES or column % 2 == 0) else 0
            sides = (f"border-left: 1px solid {palette['text']}; " if column in bars else "") + \
                (f"border-right: 1px solid {palette['text']}; " if column == columns - 1 and columns in bars else "")
            out.append(f'<td align="{aligns[column]}" valign="middle" style="{tight}{line}{sides}padding: {pad} 2px {pad} {room + 2}px">'
                       f'{_part(cell, palette, depth) if cell else ""}</td>')
        if simple:  # (a piece of each bracket in its row: top, middle, foot)
            spot = 0 if number == 0 else 2 if number == len(cells) - 1 else 1
            centre = spot == 1 and number == len(cells) // 2
            piece = _BRACE_MIDDLE[left] if centre and left in _BRACE_MIDDLE else _PIECES[left][spot]
            out.insert(0, f'<td style="padding: 0px; -qt-line-height-type: proportional; line-height: 100%">{piece}</td>')
            if right:
                shown = _BRACE_MIDDLE[right] if centre and right in _BRACE_MIDDLE else _PIECES[right][spot]
                out.append(f'<td style="padding: 0px; -qt-line-height-type: proportional; line-height: 100%">{shown}</td>')
        if any(tags):
            out.append(f'<td align="right" valign="middle" style="padding: {pad} 2px {pad} 32px">'
                       f'{html.escape(tags[number])}</td>')
        grid.append(f"<tr>{''.join(out)}</tr>")
    table = f'<table border="0" cellspacing="0" cellpadding="0">{"".join(grid)}</table>'
    if simple:
        return f'<td valign="middle">{table}</td>'
    if left in _PIECES and len(cells) > 1:  # (rows taller than a line - fractions, a matrix in it: pieces
        lines = sum(max(_lines(cell) for cell in row) for row in cells)  # stacked as high as they are, about)

        def stacked(sign: str) -> str:
            top, middle, foot = _PIECES[sign]
            pieces = [top] + [middle] * max(1 if sign in _BRACE_MIDDLE else 0, lines - 2) + [foot]
            if sign in _BRACE_MIDDLE:  # (its middle: a brace of two pieces read as a parenthesis)
                pieces[len(pieces) // 2] = _BRACE_MIDDLE[sign]
            return f'<td valign="middle" style="padding: 0px; -qt-line-height-type: proportional; line-height: 100%">{"<br />".join(pieces)}</td>'

        return (f'<td valign="middle"><table border="0" cellspacing="0" cellpadding="0"><tr>{stacked(left)}'
                f'<td valign="middle">{table}</td>{stacked(right) if right else ""}</tr></table></td>')
    if ruled_sides:
        rule = f"1px solid {palette['text']}"
        ticks = f"border-top: {rule}; border-bottom: {rule}; " if left == "[" else ""
        return (f'<td valign="middle"><table border="0" cellspacing="0" cellpadding="0"><tr>'
                f'<td width="4" style="border-left: {rule}; {ticks}padding: 0px"></td><td>{table}</td>'
                f'<td width="4" style="border-right: {rule}; {ticks}padding: 0px"></td></tr></table></td>')
    return (f'<td valign="middle">{_glyph(left, step)}</td>' if left else "") \
        + f'<td valign="middle">{table}</td>' \
        + (f'<td valign="middle">{_glyph(right, step)}</td>' if right else "")


def _lines(tex: str) -> int:
    """About how many lines of text a cell's formula is high (a fraction two, a matrix its rows)."""
    lines = 1 + tex.count("\\frac") + tex.count("\\dfrac")
    for found in re.finditer(r"\\begin\s*\{[A-Za-z]+\*?\}(.*?)\\end", tex, re.DOTALL):
        lines += len(_split_top(found.group(1), "\\\\")) - 1
    return min(lines, 12)


#: The edge of a brace's cell its rule is drawn on: under the group, over it (CSS names).
_EDGES = {True: "bottom", False: "top"}
#: The pieces of a bracket a row each (top, middle, foot) - as the terminal stacks them.
_PIECES = {"(": "⎛⎜⎝", ")": "⎞⎟⎠", "{": "⎧⎪⎩", "}": "⎫⎪⎭", "‖": "‖‖‖"}
_BRACE_MIDDLE = {"{": "⎨", "}": "⎬"}


def _install_rules(md, dark: bool) -> None:
    """The renderer rules this module changes (once per parser). What a rule
    makes for a browser page (``env["browser"]``: :func:`export_html`) and
    for Qt differs where Qt's HTML cannot do what a browser does."""
    renderer = md.renderer
    palette = colours(dark)
    # (the plugin's own rules under ours: this runs for each page with the same parser - wrapped
    # again each time, 1,000 pages made the rule a chain too deep for Python: RecursionError)
    notes_open = getattr(renderer.rules.get("footnote_block_open"), "plugin_rule", renderer.rules.get(
        "footnote_block_open"))
    if notes_open is not None:
        def footnote_block_open(tokens, idx, options, env):
            meta = tokens[idx].meta or {}
            if meta.get("continued"):  # (a later part of the list of notes: a list of its own, numbered on)
                return (f'<section class="footnotes">\n<ol class="footnotes-list" start="{meta.get("start", 1)}" '
                        'style="margin-top: 0px">\n')
            made = notes_open(tokens, idx, options, env)
            if idx and tokens[idx - 1].type == "hr":  # (a text ending in a rule: that one before its notes)
                made = re.sub(r'<hr class="footnotes-sep"\s*/?>\n?', "", made)
            return made

        footnote_block_open.plugin_rule = notes_open
        renderer.rules["footnote_block_open"] = footnote_block_open
    note_open = getattr(renderer.rules.get("footnote_open"), "plugin_rule", renderer.rules.get("footnote_open"))
    if note_open is not None:
        def footnote_open(tokens, idx, options, env):
            if (tokens[idx].meta or {}).get("going_on"):  # (cut inside the note: its anchor not again)
                return f'<li class="footnote-item"><p>{GOING_ON}</p>\n'
            return note_open(tokens, idx, options, env)

        footnote_open.plugin_rule = note_open
        renderer.rules["footnote_open"] = footnote_open
    note_back = getattr(renderer.rules.get("footnote_anchor"), "plugin_rule", renderer.rules.get("footnote_anchor"))
    if note_back is not None:
        def footnote_anchor(tokens, idx, options, env):
            made = note_back(tokens, idx, options, env)
            if idx + 1 < len(tokens) and tokens[idx + 1].type == "paragraph_close":
                return made  # (in the note's last paragraph)
            # (a note ending in a code block, a list: its way back a line of the note's own - Qt put it
            # under the note's number, on its own line)
            return f'<p class="footnote-back">{made.strip()}</p>\n'

        footnote_anchor.plugin_rule = note_back
        renderer.rules["footnote_anchor"] = footnote_anchor

    def math_inline(tokens, idx, options, env):
        # (real sub- and superscripts; what is not understood as code - that part only)
        # (its TeX on it: a copy holds "$TeX$", as KaTeX's - it held the letters drawn)
        tex = base64.b64encode(tokens[idx].content.encode("utf-8")).decode("ascii")
        mark = "" if env.get("browser") else f'<a name="{TEX_INLINE}{tex}"></a>'  # (the reader's copy only)
        return f'<span class="math">{mark}{MD.math_html(tokens[idx].content).replace("<br />", " ")}</span>'

    def math_block(tokens, idx, options, env):
        token = tokens[idx]
        shown = MD.math_text(token.content)
        label = f" &nbsp; ({html.escape(token.info)})" if token.type == "math_block_label" and token.info else ""
        laid = display_html(token.content, palette, f"({token.info})" if label else "")
        if laid is not None:  # (fractions, sums, matrices, cases: a row of items on one axis)
            return laid
        if "\n" in shown:  # (rows - a matrix, cases: in line, the block as a whole in the middle)
            rows = html.escape(shown + (f"   ({token.info})" if label else ""))
            if env.get("browser"):
                return f'<div class="math-block"><pre class="math-rows">{rows}</pre></div>\n'
            return (f'<table align="center" border="0" cellpadding="2"><tr><td>'
                    f'<pre class="math-rows">{rows}</pre></td></tr></table>\n')
        if env.get("browser"):
            return f'<div class="math-block">{MD.math_html(token.content)}{label}</div>\n'
        return f'<p class="math-block" align="center">{MD.math_html(token.content)}{label}</p>\n'

    def blockquote_open(tokens, idx, options, env):
        made = quote_open(tokens, idx, options, env)
        meta = tokens[idx].meta or {}
        if meta.get("continued"):  # (a part going on inside it: no room above, an alert's title not again)
            made = made.replace("margin-top: 10px", "margin-top: 0px")
            made = re.sub(r'<p class="alert-title"[^>]*>.*?</p>\n', "", made)
        if meta.get("continues"):  # (cut inside it: the rest in the next part's - no room below)
            made = made.replace("margin-bottom: 10px", "margin-bottom: 0px")
        return made

    def list_item_open(tokens, idx, options, env):
        made = renderer.renderToken(tokens, idx, options, env)
        if (tokens[idx].meta or {}).get("going_on"):  # (cut inside the item: a first block of no height)
            made += f"<p>{GOING_ON}</p>\n"
        return made

    def ordered_list_open(tokens, idx, options, env):
        return renderer.renderToken(tokens, idx, options, env)

    def quote_open(tokens, idx, options, env):
        kind = MD.alert_of(tokens[idx])
        boxes = env.setdefault("boxes", [])  # (each quote open: drawn as a box (1) or not (0))
        if not env.get("browser") and sum(boxes) >= BOXES:
            # (Qt lays out tables inside each other in time that grows fast with
            # their depth: 30 quotes inside each other held the window minutes)
            boxes.append(0)
            if kind:
                sign, title = _title(kind)
                return f'<blockquote>\n<p class="alert-title">{sign} {html.escape(title)}</p>\n'
            return "<blockquote>\n"
        boxes.append(0 if env.get("browser") else 1)
        # (each quote open: an alert's tint (1) or none (0) - a code box in
        # an alert on the alert's own grey was no box)
        if not env.get("browser"):
            env.setdefault("tints", []).append(1 if kind else 0)
        if not kind:
            if env.get("browser"):
                return "<blockquote>\n"
            # (as GitHub's: a bar in the rule's colour beside muted text - a
            # grey box was all Qt's <blockquote> drew, all but lost in dark)
            return (f'<table width="100%" cellspacing="0" cellpadding="4" border="0" class="quote" '
                    f'style="margin-top: 10px; margin-bottom: 10px">'
                    f'<tr><td width="4" bgcolor="{palette["rule"]}" style="padding: 0px"></td>'
                    f'<td style="color: {palette["quote_fg"]}; padding-left: 12px">\n')
        sign, title = _title(kind)
        colour = palette.get(kind, palette["link"])
        heading = f'<p class="alert-title" style="color: {colour}">{sign} {html.escape(title)}</p>\n'
        if env.get("browser"):
            return f'<div class="markdown-alert markdown-alert-{kind}">\n{heading}'
        # Qt's rich text draws no border of one side: a narrow cell in the
        # alert's colour is the bar beside it.
        return (f'<table width="100%" cellspacing="0" cellpadding="6" border="0" bgcolor="{palette["alert_bg"]}" '
                f'style="margin-top: 10px; margin-bottom: 10px">'
                f'<tr><td width="4" bgcolor="{colour}" style="padding: 0px"></td>'
                f'<td style="padding-left: 12px">\n{heading}')

    def blockquote_close(tokens, idx, options, env):
        boxed = env.setdefault("boxes", []).pop() if env.get("boxes") else 0
        if boxed and env.get("tints"):
            env["tints"].pop()
        if not env.get("browser") and not boxed:
            return "</blockquote>\n"
        # (a quote of nothing - a footnote's definition was all it held - a line of its own in it: Qt laid
        # an empty cell's table out with no line after it, a part ending there with one - in parts not whole)
        empty = "<p>&nbsp;</p>\n" if idx and tokens[idx - 1].type == "blockquote_open" else ""
        if not MD.alert_of(tokens[idx]):
            return "</blockquote>\n" if env.get("browser") else empty + "</td></tr></table>\n"
        return "</div>\n" if env.get("browser") else empty + "</td></tr></table>\n"

    def image(tokens, idx, options, env):
        token = tokens[idx]
        src = str(token.attrGet("src") or "")
        title = token.attrGet("title")
        extra = f' title="{html.escape(str(title))}"' if title else ""
        shown = renderer.renderInlineAsText(token.children or [], options, env)
        if (token.meta or {}).get("refused"):  # (file:, a data: of no image: a box naming it, never loaded)
            return image_chip("", shown, tr_text("Image not shown: its address is not allowed"))
        return _image_html(src, shown, extra, env)

    def fence(tokens, idx, options, env):
        token = tokens[idx]
        lang = (token.info or "").strip().split(maxsplit=1)[0] if token.info else ""
        if (token.meta or {}).get("band"):
            return code_band(token, lang)
        gap = _code_gap(tokens, idx, env)
        if lang.lower() == "math":  # (GitHub's other way of writing a math block)
            return math_block(tokens, idx, options, env)
        coloured = _highlight(token.content, lang, dark)
        body = coloured if coloured is not None else html.escape(token.content)
        label = _code_label(lang)
        if env.get("browser") or sum(env.get("boxes") or ()) >= BOXES:
            label = f'<p class="code-label">{html.escape(label)}</p>\n' if label else gap
            return label + code_box(body, env)
        # (its language on the box, the first line in it - a label above it
        # stood apart, nearer the text before)
        return gap + code_box(body, env, label, _last_in_box(tokens, idx))

    def code_block(tokens, idx, options, env):
        return _code_gap(tokens, idx, env) + code_box(html.escape(tokens[idx].content), env,
                                                      last=_last_in_box(tokens, idx))

    def code_band(token, lang: str) -> str:
        """A band of a long code block (_in_bands): its lines on the
        page's grey, no box - the bands one after another one block."""
        number, count = token.meta["band"]
        coloured = None if token.meta.get("plain") else _highlight(token.content, lang, dark)
        body = coloured if coloured is not None else html.escape(token.content)
        body = body[:-1] if body.endswith("\n") else body
        ground = palette["pre_bg"]
        top = 2 if number == 0 else 0
        bottom = 14 if number == count - 1 else 0
        head = ""
        if number == 0 and _code_label(lang):
            head = (f'<p class="code-label" style="background-color: {ground}; margin-top: {top}px; '
                    f'margin-bottom: 0px; line-height: 100%; -qt-line-height-type: proportional">'
                    f'{html.escape(_code_label(lang))}</p>')
            top = 0
        return (f"{head}<pre style='white-space: pre-wrap; background-color: {ground}; margin-top: {top}px; "
                f"margin-bottom: {bottom}px'><code>{body}</code></pre>\n")

    def code_box(body: str, env, label: str = "", last: bool = False) -> str:
        """A code block: for a browser a <pre> its style sheet pads; for Qt
        the <pre> in a box of one cell - Qt pads no block, the text stood
        against the edge of its grey."""
        if env.get("browser") or sum(env.get("boxes") or ()) >= BOXES:
            return f"<pre style='white-space: pre-wrap'><code>{body}</code></pre>\n"
        # (its last line end no empty line at the bottom of the box)
        body = body[:-1] if body.endswith("\n") else body
        ground = palette["code_bg"] if any(env.get("tints") or ()) else palette["pre_bg"]
        tint = "" if ground == palette["pre_bg"] else f"background-color: {ground}"
        tinted = f' style="{tint}"' if tint else ""
        wrap = f"white-space: pre-wrap; {tint}" if tint else "white-space: pre-wrap"
        pre = f"<pre style='{wrap}'><code{tinted}>{body}</code></pre>"
        if label:
            pre = f'<p class="code-label"{tinted}>{html.escape(label)}</p>{pre}'
        # (the last thing in a quote or an alert: no room below it - the
        # box's own bottom margin stood as an empty line inside the alert)
        below = 0 if last else 14
        return (f'<table width="100%" cellspacing="0" cellpadding="10" border="0" bgcolor="{ground}" '
                f'style="margin-top: 2px; margin-bottom: {below}px"><tr><td>{pre}</td></tr></table>\n')

    def front_matter(tokens, idx, options, env):
        token = tokens[idx]
        pairs = MD.front_matter_pairs(token.content)
        if pairs:  # (plain "key: value" lines: a table, as GitHub shows them - a big YAML box led the page)
            head = "".join(f"<th>{html.escape(key)}</th>" for key, _value in pairs)
            row = "".join(f"<td>{html.escape(value)}</td>" for _key, value in pairs)
            # (written as markdown-it writes a table: styled as the page's tables are)
            return f"<table>\n<thead>\n<tr>{head}</tr>\n</thead>\n<tbody>\n<tr>{row}</tr>\n</tbody>\n</table>\n"
        if not env.get("browser"):  # (a box labelled with its language, as Qt's own parser's page shows it)
            return code_box(html.escape(token.content), env, "toml" if token.markup.startswith("+") else "yaml")
        return f'<pre class="front-matter" style="white-space: pre-wrap">{html.escape(token.content)}</pre>\n'

    def footnote_caption(tokens, idx, options, env):
        # "[2]" for every reference to note 2, as GitHub (markdown-it wrote
        # "[2:1]" for the second one)
        return f"[{int(tokens[idx].meta['id']) + 1}]"

    def code_inline(tokens, idx, options, env):
        # (its spaces as written - "a   b" is not "a b"; as GitHub's break-spaces)
        return f'<code style="white-space: pre-wrap">{html.escape(tokens[idx].content, quote=False)}</code>'

    renderer.rules["code_inline"] = code_inline
    renderer.rules["fence"] = fence
    renderer.rules["code_block"] = code_block
    renderer.rules["math_inline"] = renderer.rules["math_inline_double"] = math_inline
    renderer.rules["math_block"] = renderer.rules["math_block_label"] = math_block
    renderer.rules["blockquote_open"] = blockquote_open
    renderer.rules["list_item_open"] = list_item_open
    renderer.rules["blockquote_close"] = blockquote_close
    renderer.rules["image"] = image
    def safe_html_block(tokens, idx, options, env):
        events = MD.html_events(tokens[idx])
        if not env.get("browser"):
            events = _loose_paragraphs(events)
        shown = events_html(events, bool(env.get("browser")), env.get("images"), env.setdefault("links", []))
        if not env.get("browser") and "<pre>" in shown:
            # (raw HTML's <pre> in a code block's box: no room inside it, the
            # next paragraph against it)
            shown = shown.replace("<pre>", f'<table width="100%" cellspacing="0" cellpadding="10" border="0" '
                                           f'bgcolor="{palette["pre_bg"]}" style="margin-top: 2px; margin-bottom: '
                                           f"14px\"><tr><td><pre style='white-space: pre-wrap'>")
            shown = shown.replace("</pre>", "</pre></td></tr></table>")
        if not env.get("browser") and _loose(events):
            # (text of no block of its own - a form's button left "Go": a
            # paragraph, as a browser shows it, not run into the next block)
            shown = f"<p>{shown}</p>"
        return shown + "\n"

    renderer.rules["safe_html_block"] = safe_html_block
    renderer.rules["safe_html_inline"] = lambda tokens, idx, options, env: events_html(
        MD.html_events(tokens[idx]), bool(env.get("browser")), env.get("images"), env.setdefault("links", []))
    renderer.rules["front_matter"] = front_matter
    if "footnote_caption" in renderer.rules:
        renderer.rules["footnote_caption"] = footnote_caption


#: Named anchors (``<a name>``) on one page: Qt's HTML reader takes time
#: that grows with their square (16,000: 2.6 s; a page of 50,000 footnotes
#: held up the window for minutes). Beyond these an ``id`` is dropped - a
#: heading is still found (the view jumps to its place in the document), a
#: footnote that far down is not.
ANCHORS = 2000
_ID = re.compile(r'<(\w+)([^<>]*?) id="([^"<>]*)"([^<>]*)>')
_ALIGN = re.compile(r'<(th|td) style="text-align:(left|center|right)">')
_TASK = re.compile(r'<input [^<>]*?type="checkbox"[^<>]*?>')  # (only the task list makes an input)


def _anchor(match: re.Match, counter: list[int] | None = None) -> str:
    tag, before, name, after = match.groups()
    if counter is not None:
        counter[0] += 1
        if counter[0] > ANCHORS:
            return f"<{tag}{before}{after}>"
    anchor = f'<a name="{name}"></a>'
    if tag == "a":
        return f"{anchor}<a{before}{after}>"
    return f"<{tag}{before}{after}>{anchor}"


def _task(match: re.Match) -> str:
    if "checked" in match.group(0):
        return '<span class="task-done">☑</span>'
    return '<span class="task-open">☐</span>'


def _mark_task_lists(tokens) -> None:
    """A list whose items are all tasks shows no bullets (the box is the
    bullet: class "task-list"); a list that mixes them keeps its bullets."""
    for index, token in enumerate(tokens):
        if token.type != "bullet_list_open" or "contains-task-list" not in str(token.attrGet("class") or ""):
            continue
        items = all_tasks = 0
        for inner in tokens[index + 1:]:
            if inner.type == "bullet_list_close" and inner.level == token.level:
                break
            if inner.type == "list_item_open" and inner.level == token.level + 1:
                items += 1
                all_tasks += "task-list-item" in str(inner.attrGet("class") or "")
        if items and all_tasks == items:
            token.attrSet("class", "task-list")
        else:
            token.attrs.pop("class", None)


_TBODY = re.compile(r"<tbody>.*?</tbody>", re.DOTALL)
#: A table's header cell that says nothing of its alignment.
_TH_UNALIGNED = re.compile(r"<th(?=[\s>])(?![^<>]*\balign=)")
#: (under a first and second level heading a light rule, as GitHub's)
_HEADING_END = re.compile(r"(</h[12]>)")
#: A table of the page without borders of its own (a math block's has them).
_TABLE = re.compile(r"<table((?: (?!border)[a-z]+=\"[^\"<>]*\")*)>")
_PIECE = re.compile(r'margin-top: 4px; margin-bottom: 14px"((?: [a-z]+="[^"<>]*")*?) piece="(first|mid|last)"')


def _piece_margins(match: re.Match) -> str:
    top = "4px" if match.group(2) == "first" else "0px"
    bottom = "14px" if match.group(2) == "last" else "0px"
    return f'margin-top: {top}; margin-bottom: {bottom}"{match.group(1)}'
#: Marks the header of a table's later part (as ui.markdown_view.CHUNK).
CHUNK = "\ue05d"


def _join_table_parts(tokens) -> tuple[list, set[int]]:
    """A big table ui.markdown_view.renderable cut into parts (each later
    part's header marked CHUNK) made one table again as Qt shows it: the
    later parts without their header, all of them as wide as the page with
    the same column widths (in proportion to the longest texts of the first
    part's columns). Returns the tokens and where each later part begins."""
    if not any(token.type == "inline" and token.content.startswith(CHUNK) for token in tokens):
        return tokens, set()
    out, chunks, index, widths = [], set(), 0, None
    while index < len(tokens):
        token = tokens[index]
        if token.type != "table_open" or token.level:
            out.append(token)
            index += 1
            continue
        close = next(k for k in range(index, len(tokens)) if tokens[k].type == "table_close"
                     and tokens[k].level == token.level)
        table = tokens[index:close + 1]
        first = next((t for t in table if t.type == "inline"), None)
        later = first is not None and first.content.startswith(CHUNK)
        if not later:
            widths = _widths(table)
        elif widths is not None:
            head_end = next(k for k, t in enumerate(table) if t.type == "thead_close")
            table = [table[0]] + table[head_end + 1:]
            chunks.add(len(out))
        if widths is not None and (later or _is_followed_by_parts(tokens, close)):
            table[0].attrSet("width", "100%")
            row = next(k for k, t in enumerate(table) if t.type == "tr_open")
            cells = [t for t in table[row:] if t.type in ("th_open", "td_open")][:len(widths)]
            for cell, width in zip(cells, widths):
                cell.attrSet("width", f"{width}%")
        out += table
        index = close + 1
    return out, chunks


def _is_followed_by_parts(tokens, close: int) -> bool:
    nxt = close + 1
    while nxt < len(tokens) and tokens[nxt].type != "table_open":
        if tokens[nxt].level == 0 and tokens[nxt].type not in ("table_close",):
            return False
        nxt += 1
    if nxt >= len(tokens):
        return False
    first = next((t for t in tokens[nxt:] if t.type == "inline"), None)
    return first is not None and first.content.startswith(CHUNK)


def _widths(table) -> list[int]:
    """Column widths in per cent, in proportion to the longest texts of the
    columns of *table* (tokens; each 3 to 40 characters' worth)."""
    longest, column = [], 0
    for token in table[:4000]:
        if token.type == "tr_open":
            column = 0
        elif token.type == "inline":
            if column >= len(longest):
                longest.append(3)
            longest[column] = min(40, max(longest[column], len(token.content)))
            column += 1
    longest = [n + 3 for n in longest]  # (the cell's padding: "370" wrapped as "37" "0")
    total = sum(longest) or 1
    return [max(1, round(100 * n / total)) for n in longest]


def to_html(doc: MD.Document, dark: bool = False) -> str:
    """The HTML of *doc* for Qt (see the module docstring)."""
    return "<html><body>" + "".join(to_html_parts(doc, dark, 0)) + "</body></html>"


def to_html_parts(doc: MD.Document, dark: bool = False, blocks: int = 2500, toggled=frozenset(),
                  hidden: dict | None = None, first_details: int = 0) -> list[str]:
    """The HTML of *doc* for Qt in parts (bodies without ``<html>``) of about
    *blocks* blocks each (paragraphs, list items, table cells - 0: one part),
    cut between blocks of the page's top level only: Qt lays out what it is
    given at once, on the GUI thread (ui.markdown_view lays out one part an
    event-loop turn). A ``<details>`` is folded (fold_details: *toggled*
    the numbers of those a click turned)."""
    md = doc.parser
    _install_rules(md, dark)
    _mark_task_lists(doc.tokens)
    tokens, chunks = _join_table_parts(fold_details(doc.tokens, toggled, hidden, first_details))
    if blocks:
        tokens = _html_pieces(_table_pieces(_paragraph_pieces(_in_bands(tokens))))
    ranges = _part_ranges(tokens, blocks, chunks)
    palette = colours(dark)
    table_tag = (r'<table class="data" border="1" cellspacing="0" cellpadding="6" style="border-collapse: collapse; '
                 f'border-color: {palette["rule"]}; border-style: solid; margin-top: 4px; margin-bottom: 14px"\\1>')

    def _zebra(match: re.Match) -> str:  # (every second row of a table's body on a tint)
        rows = match.group(0).split("<tr>")
        return rows[0] + "".join((f'<tr bgcolor="{palette["zebra"]}">' if n % 2 == 0 else "<tr>") + row
                                 for n, row in enumerate(rows[1:], 1))

    counter, parts = [0], []
    for begin, end, opened, closed in ranges:
        body = md.renderer.render(_part_tokens(tokens, begin, end, opened, closed), md.options, {"browser": False})
        if opened:  # (a part going on inside a container: see _part_ranges - ui.markdown_view looks for this)
            body = CONTINUED + body
        body = _ID.sub(lambda match: _anchor(match, counter), body)
        body = _ALIGN.sub(r'<\1 align="\2">', body)
        body = _TASK.sub(_task, body)
        body = _TABLE.sub(table_tag, body)
        if ' piece="' in body:  # (a table's pieces in a container one under another: no room between them)
            body = _PIECE.sub(_piece_margins, body)
        body = _TBODY.sub(_zebra, body)
        body = _HEADING_END.sub(r'\1<hr class="heading-rule" />', body)
        # (the line between a long list's parts - ui.markdown_view.renderable - as low as it gets)
        body = _TH_UNALIGNED.sub('<th align="left"', body)  # (a header on the left, as GitHub's - Qt centred it)
        body = body.replace("<p>\u200b</p>", '<p style="font-size: 1px; margin-top: 0px; margin-bottom: 0px">'
                                              '\u200b</p>')
        # (a task list keeps its list's style: its box is what Qt draws in the
        # bullet's place - ui.markdown_view._list_items; a list without a
        # style had no box at all)
        parts.append(body)
    return parts


#: What a part of the page may begin with (to_html_parts): a block of the
#: top level whose format its first block takes again (ui.markdown_view's
#: _append) - a heading, a paragraph, a table, a quote or an alert (a box),
#: a display formula, a code block (or a band of one). Not a list: its
#: items' numbers and its list are the page's - a run of 8,000 quotes, of
#: 8,000 display formulas was one part: 10 to 20 s.
_PART_STARTS = frozenset(("heading_open", "paragraph_open", "table_open", "blockquote_open", "math_block",
                          "math_block_label", "fence", "code_block", "hr", "safe_html_block"))
#: Lines of a code block of the top level in one part of the page (Qt's own
#: parser's ui.markdown_view.markdown_parts too).
CODE_PART_LINES = 200
#: Lines of a code block in a box (a table of one cell: Qt lays it out
#: whole, at once): a longer one is a band of the page's grey, laid out a
#: part at a time - 30,000 lines in a box held the window 5 to 30 s (as
#: Qt's own parser's page: ui.markdown_view.BOX_BLOCKS).
BOXED_LINES = 500
#: ... or characters (a table of 2,000 columns as written: 200 lines of 4,000 - 0.5 s in a box).
BOXED_CHARS = 40_000
#: Characters of a band at most.
BAND_CHARS = 16_000


#: The containers a part may be cut inside of (a big block in a list item,
#: a quote, an alert, a definition, a note): the part ends them, the next
#: begins them again going on (_part_tokens) - each container's own blocks
#: where they belong, laid out a part at a time (Qt lays out what is in a
#: box or a list at once: a table of 30,000 rows in a quote held the window
#: 48 s, a fence of 100,000 lines in a list item 6.5 s).
CONTAINERS = {"blockquote_open": "blockquote_close", "bullet_list_open": "bullet_list_close",
              "ordered_list_open": "ordered_list_close", "list_item_open": "list_item_close",
              "dl_open": "dl_close", "dd_open": "dd_close", "footnote_block_open": "footnote_block_close",
              "footnote_open": "footnote_close"}
#: A container of the top level heavier than this (blocks, lines, spans) is cut inside too.
HEAVY = 600
#: Begins a part that goes on inside a container (to_html_parts) - a comment Qt drops.
CONTINUED = "<!--axross-continued-->"
#: The first block of an item (or a note) a part goes on with: no number, no bullet, no height
#: (ui.markdown_view._continued) - its item's own were in the part before.
GOING_ON = "\ue05a"
#: Blocks that may begin a part (or follow a cut inside a container).
_BLOCK_STARTS = frozenset(("fence", "code_block", "math_block", "math_block_label", "hr", "html_block",
                           "safe_html_block"))


def _weight(token, blocks: int) -> int:
    """What *token* costs to lay out, in blocks (_part_ranges)."""
    weight = token.nesting == 1
    if token.type in ("math_block", "math_block_label"):  # (a display formula: tables in tables to lay out)
        weight += min(blocks, 1 + 12 * token.content.count("\\begin") + 3 * token.content.count("\\frac"))
    elif token.type in ("fence", "code_block"):  # (each of its lines a block of the page)
        weight += token.content.count("\n")
    elif token.type == "paragraph_open" and (token.meta or {}).get("piece"):
        weight += blocks  # (a long paragraph's piece: a part of its own)
    elif token.type == "inline":
        weight += len(token.children or ()) // 8
    elif token.type == "safe_html_block":
        events = MD.html_events(token)
        weight += (len(events) + sum(event[1].count("\n") for event in events if event[0] == "text")) // 6
    return weight


def _part_ranges(tokens: list, blocks: int, chunks: set) -> list:
    """The parts of *tokens*: (begin, end, the containers open at its begin,
    those still open at its end - indices of their open tokens). Cut between
    blocks of the top level (before a heading, a paragraph, a table, a box,
    a formula, a code block: a part's first block takes its format again -
    ui.markdown_view's _append), at a big table's later part, and inside a
    heavy container (HEAVY) between two of its blocks."""
    if not blocks:
        return [(0, len(tokens), [], [])]
    heavy, at = set(), 0
    while at < len(tokens):  # (the top level's heavy containers: their open token's index)
        token = tokens[at]
        if token.level == 0 and token.type in CONTAINERS:
            close, total, depth = at + 1, _weight(token, blocks), 1
            while close < len(tokens):
                kind = tokens[close].type
                depth += (kind == token.type) - (kind == CONTAINERS[token.type])
                if not depth:
                    break
                total += _weight(tokens[close], blocks)
                close += 1
            if total > HEAVY:
                heavy.add(at)
            at = close + 1
            continue
        at += 1
    ranges, start, weight, stack, opened, inside, leaves = [], 0, 0, [], [], None, 0
    first = max(1, blocks // 4)  # (the first part small: the page is there at once, the rest follows)
    ends = frozenset(CONTAINERS.values())
    for index, token in enumerate(tokens):
        weight += _weight(token, blocks)
        if token.type not in CONTAINERS and token.type not in ends:  # (blocks open that are no container: a
            leaves += token.nesting  # table, its rows and cells - a footnote's levels say nothing)
        if token.type in CONTAINERS:
            if not stack:
                inside = index if index in heavy else None
            stack.append(index)
        elif stack and token.nesting == -1 and token.type == CONTAINERS.get(tokens[stack[-1]].type):
            stack.pop()
        if index in chunks and index > start and not stack:  # (a table's later part: a part of its own)
            ranges.append((start, index, opened, []))
            start, weight, opened = index, 1, []
            continue
        if index + 1 >= len(tokens) or weight < (blocks if ranges else first) or token.nesting == 1:
            continue
        following = tokens[index + 1]
        if _is_code(token) and _is_code(following) and not (following.meta or {}).get("band"):
            continue  # (not between two code blocks: the line between them - _code_gap - is the first one's part's)
        if not stack and token.level == 0:
            if following.type not in _PART_STARTS:
                continue
        elif inside is None or not all(tokens[k].type in CONTAINERS for k in stack) \
                or not (following.nesting == 1 or following.type in _BLOCK_STARTS) or leaves:
            continue  # (between blocks of the containers only: never between a table's cells)
        ranges.append((start, index + 1, opened, list(stack)))
        start, weight, opened = index + 1, 0, list(stack)
    if start < len(tokens) or not ranges:
        ranges.append((start, len(tokens), opened, []))
    return ranges


def _part_tokens(tokens: list, begin: int, end: int, opened: list, closed: list) -> list:
    """The tokens of a part (_part_ranges): the containers it goes on inside
    begun again (meta "continued" - an ordered list's number, a note list's,
    on from where it was cut), its own, the containers it is cut inside of
    ended (their open tokens meta "continues": no room below)."""
    Token = MD.token_class()

    out = []
    for k, at in enumerate(opened):
        token = tokens[at]
        meta = {**(token.meta or {}), "continued": True}
        copy = token.copy(meta=meta)
        if token.type == "ordered_list_open":
            inside = k + 1 < len(opened) and tokens[opened[k + 1]].type == "list_item_open"
            copy.attrSet("start", str(_item_number(tokens, at, begin, inside)))
        elif token.type == "footnote_block_open":
            meta["start"] = _note_number(tokens, at, begin)
        elif token.type in ("list_item_open", "footnote_open"):
            meta["going_on"] = True  # (cut inside it: the part begins in the item - GOING_ON its first block)
        out.append(copy)
    ending = set(closed)
    for at in range(begin, end):
        token = tokens[at]
        out.append(token.copy(meta={**(token.meta or {}), "continues": True}) if at in ending else token)
    for at in reversed(closed):
        token = tokens[at]
        close = Token(CONTAINERS[token.type], token.tag, -1)
        close.level, close.markup, close.block = token.level, token.markup, True
        out.append(close)
    for k, at in enumerate(opened):  # (begun again and ended again by this part: no room below either)
        if at in ending:
            out[k].meta["continues"] = True
    return out


def _item_number(tokens: list, opened: int, begin: int, inside: bool) -> int:
    """The number an ordered list (opened at *opened*) goes on with at *begin*:
    its start, on by its items begun before (*inside*: the cut was in the last
    of them - its going-on block is taken out of the list, the next item gets
    the number after it)."""
    level = tokens[opened].level + 1
    items = sum(1 for at in range(opened + 1, begin) if tokens[at].type == "list_item_open"
                and tokens[at].level == level)
    del inside
    return int(tokens[opened].attrGet("start") or 1) + items


def _note_number(tokens: list, opened: int, begin: int) -> int:
    """The number a list of notes (opened at *opened*) goes on with at *begin*."""
    last = None
    for at in range(opened + 1, begin):
        if tokens[at].type == "footnote_open":
            last = at
    following = next((at for at in range(begin, len(tokens)) if tokens[at].type == "footnote_open"), None)
    if last is not None and not any(tokens[at].type == "footnote_close" and tokens[at].level == tokens[last].level
                                    for at in range(last, begin)):
        return int(tokens[last].meta.get("id", 0)) + 1  # (cut inside that note)
    return int(tokens[following].meta.get("id", 0)) + 1 if following is not None else 1


def _is_code(token) -> bool:
    return token.type in ("fence", "code_block")


def _in_bands(tokens: list) -> list:
    """*tokens* with a code block of the top level longer than BOXED_LINES
    as bands of ui.markdown_view.CODE_PART_LINES lines (fences, meta
    "band": (number, count)) - each may begin a part of the page."""
    out = []
    for token in tokens:
        if token.type not in ("fence", "code_block") \
                or (token.content.count("\n") <= BOXED_LINES and len(token.content) <= BOXED_CHARS) \
                or (token.info or "").strip().lower().startswith("math"):
            out.append(token)
            continue
        lines = token.content.splitlines(keepends=True)
        bands, band, size = [], [], 0
        for line in lines:  # (CODE_PART_LINES lines a band, or BAND_CHARS characters: long lines wrap)
            if band and (len(band) >= CODE_PART_LINES or size + len(line) > BAND_CHARS):
                bands.append(band)
                band, size = [], 0
            band.append(line)
            size += len(line)
        if band:
            bands.append(band)
        plain = len(token.content) > HIGHLIGHT_LIMIT  # (the block as a whole: past it, none coloured)
        for number, band in enumerate(bands):
            out.append(token.copy(type="fence", content="".join(band),
                                  meta={**(token.meta or {}), "band": (number, len(bands)), "plain": plain}))
    return out


#: Spans (pieces of inline content: a formula, an image, a link, emphasis)
#: of a paragraph of the top level laid out at once: a longer one is laid
#: out in pieces of this many, one a part of the page, the pieces one
#: paragraph to see (no room between them) - 6,000 formulas in one held
#: the window 7 s, 5,000 images 9 s.
PARAGRAPH_SPANS = 200
#: ... or of this many characters of text.
PARAGRAPH_TEXT = 6000


#: Characters past U+1F000 (emoji, pictures) count as this many letters in a paragraph's pieces.
PICTURE_WEIGHT = 8
_PICTURE_SIGNS = re.compile("[\U0001F000-\U0010FFFF]")


def _paragraph_pieces(tokens: list) -> list:
    """*tokens* with a paragraph of the top level of more than
    PARAGRAPH_SPANS spans in pieces (paragraphs, meta "piece": (number,
    count)) - cut only between two spans of its top level, before a space
    or a line end."""
    out, index = [], 0
    while index < len(tokens):
        token = tokens[index]
        inline = tokens[index + 1] if index + 2 < len(tokens) else None
        # (an emoji, a picture sign costs a font's colour bitmap each: eight letters' worth - 3,000 colour
        # emoji a piece held a CI runner's window 2.6 s)
        pictures, shown = 0, 0
        if inline is not None and inline.type == "inline" and token.type == "paragraph_open" \
                and len(inline.content) > PARAGRAPH_TEXT // PICTURE_WEIGHT:
            # (in the text as shown: ":tada:" is an emoji there, not in the source)
            texts = [child.content for child in inline.children or () if child.type == "text"]
            shown = sum(map(len, texts))
            pictures = sum(len(_PICTURE_SIGNS.findall(text)) for text in texts)
        step = PARAGRAPH_TEXT if not pictures else max(
            200, int(PARAGRAPH_TEXT * shown / (shown + (PICTURE_WEIGHT - 1) * pictures)))
        if token.type != "paragraph_open" or inline is None or inline.type != "inline" \
                or (len(inline.children or ()) <= PARAGRAPH_SPANS and max(len(inline.content), shown) <= step
                    and not pictures * PICTURE_WEIGHT > step):
            out.append(token)
            index += 1
            continue
        children = []
        for child in inline.children:  # (a long text in pieces at its spaces: 1.4 MB of emoji was one)
            if child.type == "text" and len(child.content) > step:
                words, at = child.content, 0
                while at < len(words):
                    cut = words.find(" ", at + step, at + 2 * step)
                    if cut < 0:  # (no space near: cut in the word - between two letters as they are seen;
                        # 99,000 letters in one word held the window 1.1 s)
                        cut = len(words) if at + 2 * step >= len(words) \
                            else MD.cluster_end(words, at + step - 1)
                    children.append(child.copy(content=words[at:cut]))
                    at = cut
            else:
                children.append(child)
        groups, group, depth, size = [], [], 0, 0
        for child in children:
            full = len(group) >= PARAGRAPH_SPANS or size >= step
            # (no space for twice as long: cut between two spans all the same - "`a" 49,500 times, 25,000
            # code spans and not one space, held the window 17 s in Qt's layout; "$a$" 30,000 times 3 s)
            if not depth and full and (child.type in ("softbreak", "text")
                                       and (child.type == "softbreak" or child.content[:1].isspace())
                                       or len(group) >= 2 * PARAGRAPH_SPANS or size >= 2 * step) \
                    and child.nesting != -1:
                groups.append(group)
                group, size = [], 0
                if child.type == "softbreak":
                    continue
                if child.type == "text":
                    child = child.copy(content=child.content.lstrip())
            depth += child.nesting
            size += len(child.content or "")
            group.append(child)
        groups.append(group)
        end = next(k for k in range(index + 2, len(tokens)) if tokens[k].type == "paragraph_close")
        last = tokens[index + 2:end]  # (a note's way back - footnote_anchor - before its end: the last piece's)
        closing = tokens[end].copy(hidden=False)
        for number, group in enumerate(groups):
            # (a tight list's paragraph is no <p>: its pieces are - of no room, as its lines)
            margins = ([] if number == 0 and not token.hidden else ["margin-top: 0px"]) \
                + ([] if number == len(groups) - 1 and not token.hidden else ["margin-bottom: 0px"])
            opening = token.copy(meta={**(token.meta or {}), "piece": (number, len(groups))}, hidden=False,
                                 attrs={**(token.attrs or {}), "style": "; ".join(margins)})
            out += [opening, inline.copy(children=group), *(last if number == len(groups) - 1 else ()), closing]
        index = end + 1
    return out


#: Cells of a table inside a container (a list item, a quote) in one piece
#: (a table of its own, as wide as the others: _table_pieces).
TABLE_PIECE_CELLS = 400


def _table_pieces(tokens: list) -> list:
    """*tokens* with a big table inside a container in pieces of at most
    TABLE_PIECE_CELLS cells - each a table of its own, the later ones without
    the header, all as wide as the page with the first's column widths (a
    big table of the top level comes in pieces already: ui.markdown_view's
    renderable)."""
    out, index = [], 0
    while index < len(tokens):
        token = tokens[index]
        if token.type != "table_open" or not token.level:
            out.append(token)
            index += 1
            continue
        close = next(k for k in range(index, len(tokens)) if tokens[k].type == "table_close"
                     and tokens[k].level == token.level)
        table = tokens[index:close + 1]
        rows = [k for k, t in enumerate(table) if t.type == "tr_open"]
        first_end = next((k for k in range(rows[0], len(table)) if table[k].type == "tr_close"), len(table)) \
            if rows else 0
        columns = sum(1 for t in table[rows[0]:first_end] if t.type in ("th_open", "td_open")) if rows else 1
        # (the first row's: counted over the whole table, every row was a table of its own)
        body = next((k for k, t in enumerate(table) if t.type == "tbody_open"), None)
        if body is None or (len(rows) * max(1, columns)) <= TABLE_PIECE_CELLS:
            out += table
            index = close + 1
            continue
        widths = _widths(table)
        head, tail = table[:body + 1], table[-2:]  # (table_open … tbody_open; tbody_close, table_close)
        body_rows = [k for k in rows if k > body]
        per = max(1, TABLE_PIECE_CELLS // max(1, columns))
        for first in range(0, len(body_rows), per):
            group = body_rows[first:first + per]
            end = body_rows[first + per] if first + per < len(body_rows) else len(table) - 2
            place = "first" if first == 0 else "last" if first + per >= len(body_rows) else "mid"
            opening = table[0].copy(attrs={**(table[0].attrs or {}), "width": "100%", "piece": place},
                                    meta={**(table[0].meta or {}), "piece": first // per})
            start = head[1:] if first == 0 else [t for t in head[1:] if t.type == "tbody_open"]
            piece = [opening, *start, *table[group[0]:end], *tail]
            row = next(k for k, t in enumerate(piece) if t.type == "tr_open")
            cells = [t for t in piece[row:] if t.type in ("th_open", "td_open")][:len(widths)]
            for cell, width in zip(cells, widths):
                cell.attrSet("width", f"{width}%")
            if first:  # (the line between two pieces as low as it gets - to_html_parts; a copy leaves it out)
                out += _seam_line(table[0].level)
            out += piece
        index = close + 1
    return out


def _seam_line(level: int) -> list:
    """The tokens of a line of no height between two pieces of a table ("<p>\u200b</p>")."""
    Token = MD.token_class()

    inline = Token("inline", "", 0, content="\u200b", level=level + 1)
    inline.children = [Token("text", "", 0, content="\u200b")]
    return [Token("paragraph_open", "p", 1, level=level, block=True), inline,
            Token("paragraph_close", "p", -1, level=level, block=True)]


#: Events of a block of raw HTML laid out at once (a table's rows, a list's
#: items, a <pre>'s lines in pieces: _html_pieces).
HTML_PIECE_EVENTS = 1200
#: Elements of no end (no end event: html_events).
_VOID = frozenset(("br", "img", "hr", "wbr"))


def _html_pieces(tokens: list) -> list:
    """*tokens* with a big block of raw HTML - a <table> of thousands of
    rows, a <ul> of thousands of items, a <pre> of thousands of lines, a
    <p> or a <div> of thousands of pieces - in pieces of about
    HTML_PIECE_EVENTS events: each the element begun again (an <ol> going on
    with its number), its children up to there, the element ended (10,000
    rows in one held the window 6 s)."""
    out = []
    for token in tokens:
        events = MD.html_events(token) if token.type == "safe_html_block" else ()
        if len(events) + sum(event[1].count("\n") for event in events if event[0] == "text") <= HTML_PIECE_EVENTS:
            out.append(token)
            continue
        pieces = _event_pieces(list(events))
        out += [token.copy(meta={**(token.meta or {}), "html": piece}) for piece in pieces]
    return out


def _event_pieces(events: list) -> list:
    """*events* (one block's) cut in pieces between the children of the
    element that holds most - see _html_pieces. As they are when there is
    no such place."""
    counts, path, paths = {}, [], {}
    for at, event in enumerate(events):
        if event[0] == "start":
            if path:
                counts[path[-1]] = counts.get(path[-1], 0) + 1
            if event[1] in _VOID:
                continue
            path.append(at)
            paths[at] = list(path)
        elif event[0] == "end":
            if path:
                path.pop()
        elif path and event[1].strip():
            counts[path[-1]] = counts.get(path[-1], 0) + max(1, event[1].count("\n"))
    if not counts:
        return [events]
    parent = max(counts, key=counts.get)
    chain = paths[parent]
    # (its children: element ranges and texts - a long text, a <pre>'s, by its lines)
    segments, at, depth, opened = [], parent + 1, 0, None
    while at < len(events):
        event = events[at]
        if event[0] == "start" and event[1] in _VOID:
            if depth == 0:
                segments.append([event])
        elif event[0] == "start":
            if depth == 0:
                opened = at
            depth += 1
        elif event[0] == "end":
            if depth == 0:
                break  # (the parent's own end)
            depth -= 1
            if depth == 0:
                segments.append(events[opened:at + 1])
        elif depth == 0:
            text = event[1]
            lines = text.splitlines(keepends=True) if "\n" in text.strip("\n") or len(text) > 4000 else [text]
            segments += [[("text", line)] for line in lines]
        at += 1
    end = at
    if len(segments) < 2 or end >= len(events):
        return [events]
    head = [events[k] for k in chain]
    tail = [("end", events[k][1]) for k in reversed(chain)]
    tag = events[parent][1]
    groups, group, size = [], [], 0
    for segment in segments:
        if group and size + len(segment) > HTML_PIECE_EVENTS:
            groups.append(group)
            group, size = [], 0
        group += segment
        size += len(segment)
    groups.append(group)
    out, items = [], 0
    for index, group in enumerate(groups):
        opening = events[:parent + 1] if index == 0 else list(head)
        if tag == "ol" and index:  # (a list of numbers going on with its own)
            attrs = dict(events[parent][2] or {}) if len(events[parent]) > 2 else {}
            first = int(attrs.get("start", "1")) if str(attrs.get("start", "1")).isdigit() else 1
            attrs["start"] = str(first + items)
            opening[-1] = ("start", "ol", attrs)
        items += sum(1 for event in group if event[0] == "start" and event[1] == "li")
        closing = events[end:] if index == len(groups) - 1 else tail
        out.append(opening + group + closing)
    return out


def _remote(src: str) -> bool:
    """Whether the image *src* is on the network (never loaded)."""
    from urllib.parse import urlsplit

    return urlsplit(src).scheme.lower() in ("http", "https", "ftp", "ftps") or src.startswith("//")


#: The sign of an image not shown - one every font has (🖼 needs an emoji
#: font: without one it was an empty box).
CHIP = "▣"


def image_chip(src: str, alt: str, why: str) -> str:
    """An image not shown, as a small chip in the line: "▣ its alt text"
    (or its file's name), the address and *why* in its tooltip (a badge row
    was a stack of grey boxes 420 pixels wide, the alt text lost)."""
    from urllib.parse import urlsplit

    name = alt or posixpath.basename(urlsplit(src).path) or tr_text("image")
    title = html.escape(f"{why}: {src}" if src[:5].lower() != "data:" else why)
    return f'<span class="image-chip" title="{title}">{CHIP} {html.escape(name)}</span>'


def tr_text(text: str) -> str:
    try:
        from core.i18n import tr
    except ImportError:  # pragma: no cover
        return text
    return tr(text)


#: What an exported page may load: its own styles and the images in it
#: (data:, those the viewer read and checked) - nothing else: no script, no
#: file beside it or on the network, no frame, no form target.
EXPORT_POLICY = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                 "form-action 'none'; base-uri 'none'")


def _export_style(dark: bool) -> str:
    c = colours(dark)
    alerts = "\n".join(f".markdown-alert-{kind} {{ border-left-color: {c[kind]}; }}" for kind in ALERT_TITLES)
    return f"""
body {{ color: {c['text']}; background: {'#0d1117' if dark else '#ffffff'}; max-width: 52em; margin: 2em auto;
       padding: 0 1em; font: 16px/1.6 -apple-system, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif; }}
h1, h2 {{ border-bottom: 1px solid {c['rule']}; padding-bottom: .3em; }}
h1 {{ color: {c['h1']}; }} h2 {{ color: {c['h2']}; }} h3 {{ color: {c['h3']}; }}
h4 {{ color: {c['h4']}; }} h5 {{ color: {c['h5']}; }} h6 {{ color: {c['h6']}; }}
a {{ color: {c['link']}; text-decoration: none; }} a:hover {{ text-decoration: underline; }}
code {{ background: {c['code_bg']}; color: {c['code_fg']}; padding: .1em .3em; border-radius: 4px;
        font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 90%; }}
pre {{ background: {c['pre_bg']}; padding: 1em; border-radius: 6px; overflow: auto; }}
pre code {{ background: none; color: {c['text']}; padding: 0; font-size: 90%; }}
blockquote {{ color: {c['quote_fg']}; border-left: 4px solid {c['rule']}; margin: 0; padding: 0 1em; }}
table {{ border-collapse: collapse; display: block; overflow: auto; }}
th, td {{ border: 1px solid {c['rule']}; padding: 6px 13px; }}
th {{ background: {c['th_bg']}; }}
img {{ max-width: 100%; }}
hr {{ border: 0; border-top: 1px solid {c['rule']}; }}
dt {{ font-weight: 700; margin-top: .5em; }} dd {{ margin-left: 2em; }}
s, del {{ color: {c['muted']}; }}
ul.task-list {{ list-style: none; padding-left: 1.2em; }}
.task-done {{ color: {c['mark']}; font-weight: 700; }} .task-open {{ color: {c['muted']}; font-weight: 700; }}
.footnotes {{ color: {c['muted']}; font-size: 90%; }}
.front-matter {{ color: {c['muted']}; font-size: 85%; }}
.math {{ color: {c['math']}; font-family: {MATH_FAMILIES}; }}
.math-block {{ color: {c['math']}; font-family: {MATH_FAMILIES}; font-size: 115%;
               text-align: center; margin: 1em 0; }}
.math-rows {{ display: inline-block; text-align: left; background: none; margin: 0; font-size: 100%; }}
.markdown-alert {{ border-left: 4px solid; padding: .5em 1em; margin: 1em 0; background: {c['alert_bg']}; }}
.alert-title {{ font-weight: 700; margin: 0 0 .3em; }}
.code-label {{ color: {c['muted']}; font-size: 80%; font-style: italic; margin: 1em 0 -.8em; }}
kbd {{ border: 1px solid {c['rule']}; border-radius: 4px; padding: 0 .3em; font-family: ui-monospace, monospace;
       font-size: 85%; background: {c['code_bg']}; }}
summary {{ cursor: pointer; font-weight: 700; }}
.image-chip {{ background: {c['code_bg']}; color: {c['muted']}; border-radius: 4px; padding: 0 .3em;
               font-size: 85%; }}
{alerts}
@media print {{ body {{ max-width: none; margin: 0; }} pre {{ white-space: pre-wrap; }} }}
"""


_IMG_TAG = re.compile(r"<img\b[^<>]*>", re.IGNORECASE)
_HREF = re.compile(r'(<a\b[^<>]*?)\s+href="([^"]*)"', re.IGNORECASE)
#: The links a page of its own keeps (others are text there) - and a
#: relative one (a sibling's "notes.md", "foo(and(bar))"): no scheme, no
#: host ("//host"), no root, no backslash (a browser reads "\\\\host" as "//host").
_KEPT_LINKS = ("http://", "https://", "mailto:", "#")
_RELATIVE_LINK = re.compile(r"(?![A-Za-z][A-Za-z0-9+.-]*:)[^/\\\s][^\\\s]*\Z|\Z")
#: The reader's own marks of a formula (its TeX for a copy): no part of a page of its own.
_TEX_MARK = re.compile(r'<td><a name="axross-tex:[^"]*"></a>&#8203;</td>|<a name="axross-i?tex:[^"]*">(.*?)</a>',
                       re.DOTALL)


def safe_page(page: str, images: dict | None = None) -> str:
    """*page* (any HTML - Qt's own, for one) made a page of its own as safe
    as :func:`export_html`'s without counting on its policy (a word
    processor or a mail program ignores it): every image is one the viewer
    read and checked (*images*, put in as data:) or a chip naming it, every
    link that is no http(s), mailto, #anchor or relative link (a sibling's
    "notes.md") loses its target; the reader's marks of formulas go."""
    images = images or {}
    put_in = set(images.values())  # (already put in: export_html's)

    def image(match: re.Match) -> str:
        tag = match.group(0)
        src = re.search(r'\bsrc="([^"]*)"', tag)
        alt = re.search(r'\balt="([^"]*)"', tag)
        name = html.unescape(src.group(1)) if src else ""
        if name in put_in:
            return tag
        if name in images:
            return tag.replace(src.group(0), f'src="{images[name]}"', 1)
        return image_chip(name, html.unescape(alt.group(1)) if alt else "",
                          tr_text("Image not in the exported page"))

    def link(match: re.Match) -> str:
        target = html.unescape(match.group(2)).strip()
        kept = target.lower().startswith(_KEPT_LINKS) or (target and _RELATIVE_LINK.match(target))
        return match.group(0) if kept else match.group(1)

    page = _TEX_MARK.sub(lambda match: match.group(1) or "", page)
    return _QT_LINE_HEIGHT.sub(_line_height, _HREF.sub(link, _IMG_TAG.sub(image, page)))


#: Qt's line heights in its own HTML: a number without unit and a type of
#: its own - "line-height:7" a browser reads as 7 times the letters' size.
_QT_LINE_HEIGHT = re.compile(r"line-height:\s*([\d.]+)(%?)\s*;\s*-qt-line-height-type:\s*([a-z-]+)\s*;?")


def _line_height(match: re.Match) -> str:
    number, percent, kind = match.groups()
    if kind == "proportional" or percent:
        return f"line-height:{number}%;"
    if kind == "fixed":
        return f"line-height:{number}px;"
    if kind == "line-distance":  # (pixels added to a line's own height)
        return f"line-height:calc(1.2em + {number}px);"
    return "line-height:normal;"  # (minimum: a line at least that high)


def export_html(doc: MD.Document, title: str = "", dark: bool = False, images: dict | None = None) -> str:
    """*doc* as an HTML page of its own, for a web browser (see the module
    docstring). *images*: ``{name: "data:…"}`` of the images the viewer read
    and checked (beside the file, bounded, not a secret) - only those are in
    it, every other image is a chip naming it; its policy lets it load
    nothing at all (:data:`EXPORT_POLICY`)."""
    md = doc.parser
    _install_rules(md, dark)
    _mark_task_lists(doc.tokens)
    try:
        body = md.renderer.render(doc.tokens, md.options, {"browser": True, "images": images or {}})
    except (Exception, RecursionError) as exc:  # noqa: BLE001 - a block's fault: the text as written,
        if not doc.source:  # never a traceback
            raise
        log.warning("A page could not be rendered; shown as written", exc_info=True)
        written = MD.as_written(doc.source, exc, md)
        body = md.renderer.render(written.tokens, md.options, {"browser": True, "images": images or {}})
    body = safe_page(_TASK.sub(_task, body), images)
    title = html.escape(MD.clean(title or (doc.headings[0].text if doc.headings else "Markdown")))
    return (f'<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n'
            f'<meta http-equiv="Content-Security-Policy" content="{EXPORT_POLICY}">\n'
            f'<meta name="referrer" content="no-referrer">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{title}</title>\n<style>{_export_style(dark)}</style>\n</head>\n"
            f'<body>\n<article class="markdown-body">\n{body}</article>\n</body>\n</html>\n')


def anchor_names(page: str) -> set[str]:
    """The anchors of a page :func:`to_html` made."""
    return set(re.findall(r'<a name="([^"<>]*)">', page))


__all__ = ["ALERT_TITLES", "ANCHORS", "DARK", "EXPORT_POLICY", "LIGHT", "anchor_names", "colours",
           "events_html", "export_html", "safe_page", "style_sheet", "to_html", "to_html_parts"]
