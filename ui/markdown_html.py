"""A parsed Markdown document (core.markdown_doc) as the HTML Qt's rich text
shows well - for ui.markdown_view when markdown-it-py is installed.

markdown-it renders the HTML (raw HTML in the file stays escaped text), and
this module shapes it for Qt's subset of HTML and CSS: every ``id`` also as an
``<a name>`` (Qt scrolls to those), table alignment as ``align``, borders and
padding as table attributes, task list boxes as ☑ / ☐, fenced code coloured
by Pygments (inline styles), and a style sheet in the colours of the light or
dark palette (:func:`style_sheet`). Nothing here loads anything: images are
the view's (MarkdownBrowser.loadResource).
"""

from __future__ import annotations

import html
import re

from core import markdown_doc as MD

#: A fenced block longer than this is shown uncoloured (Pygments' time grows
#: with it; a block of megabytes held up the window).
HIGHLIGHT_LIMIT = 200_000

LIGHT = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    "h1": "#0550ae", "h2": "#8250df", "h3": "#1a7f37", "h4": "#9a6700", "h5": "#bc4c00", "h6": "#59636e",
    "code_bg": "#f2f4f7", "code_fg": "#b31d28", "pre_bg": "#f6f8fa", "quote_bg": "#f6f8fa",
    "quote_fg": "#59636e", "rule": "#d1d9e0", "th_bg": "#eef2f7", "mark": "#1a7f37",
}
DARK = {
    "text": "#e6edf3", "muted": "#9198a1", "link": "#4493f8",
    "h1": "#79c0ff", "h2": "#d2a8ff", "h3": "#7ee787", "h4": "#e3b341", "h5": "#ffa657", "h6": "#9198a1",
    "code_bg": "#2a313c", "code_fg": "#ff7b72", "pre_bg": "#161b22", "quote_bg": "#1c2128",
    "quote_fg": "#9198a1", "rule": "#3d444d", "th_bg": "#212830", "mark": "#3fb950",
}


def colours(dark: bool) -> dict[str, str]:
    return DARK if dark else LIGHT


def style_sheet(dark: bool) -> str:
    """The document's style sheet (QTextDocument.setDefaultStyleSheet)."""
    c = colours(dark)
    return f"""
body {{ color: {c['text']}; }}
h1 {{ color: {c['h1']}; font-size: xx-large; font-weight: 700; margin-top: 18px; margin-bottom: 8px; }}
h2 {{ color: {c['h2']}; font-size: x-large; font-weight: 700; margin-top: 16px; margin-bottom: 6px; }}
h3 {{ color: {c['h3']}; font-size: large; font-weight: 700; margin-top: 14px; margin-bottom: 4px; }}
h4 {{ color: {c['h4']}; font-size: medium; font-weight: 700; }}
h5 {{ color: {c['h5']}; font-size: medium; font-weight: 700; }}
h6 {{ color: {c['h6']}; font-size: small; font-weight: 700; }}
p {{ margin-top: 4px; margin-bottom: 8px; }}
a {{ color: {c['link']}; text-decoration: none; }}
code {{ background-color: {c['code_bg']}; color: {c['code_fg']}; font-family: monospace; }}
pre {{ background-color: {c['pre_bg']}; font-family: monospace; margin-top: 6px; margin-bottom: 10px; }}
pre code {{ background-color: {c['pre_bg']}; color: {c['text']}; }}
blockquote {{ background-color: {c['quote_bg']}; color: {c['quote_fg']}; margin-left: 12px;
              margin-right: 12px; font-style: italic; }}
th {{ background-color: {c['th_bg']}; font-weight: 700; }}
dt {{ font-weight: 700; margin-top: 6px; }}
dd {{ margin-left: 28px; margin-bottom: 6px; }}
hr {{ color: {c['rule']}; }}
s, del {{ color: {c['muted']}; }}
.task-done {{ color: {c['mark']}; font-weight: 700; }}
.task-open {{ color: {c['muted']}; font-weight: 700; }}
.footnotes {{ color: {c['muted']}; font-size: small; }}
.front-matter {{ color: {c['muted']}; font-size: small; }}
"""


def _highlight(code: str, lang: str, dark: bool) -> str | None:
    """*code* as HTML coloured by Pygments for *lang*, or None (no Pygments,
    an unknown language, a block too long)."""
    if not lang or len(code) > HIGHLIGHT_LIMIT:
        return None
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import get_lexer_by_name
        from pygments.util import ClassNotFound
    except ImportError:
        return None
    try:
        lexer = get_lexer_by_name(lang.lower(), stripnl=False)
    except ClassNotFound:
        return None
    style = "github-dark" if dark else "default"
    try:
        formatter = HtmlFormatter(noclasses=True, nowrap=True, style=style)
    except Exception:  # noqa: BLE001 - an older Pygments without the style
        formatter = HtmlFormatter(noclasses=True, nowrap=True)
    return highlight(code, lexer, formatter)


def _install_rules(md, dark: bool) -> None:
    """The renderer rules this module changes (once per parser)."""
    renderer = md.renderer

    def fence(tokens, idx, options, env):
        token = tokens[idx]
        lang = (token.info or "").strip().split(maxsplit=1)[0] if token.info else ""
        coloured = _highlight(token.content, lang, dark)
        body = coloured if coloured is not None else html.escape(token.content)
        return f"<pre><code>{body}</code></pre>\n"

    def code_block(tokens, idx, options, env):
        return f"<pre><code>{html.escape(tokens[idx].content)}</code></pre>\n"

    def front_matter(tokens, idx, options, env):
        return f'<pre class="front-matter">{html.escape(tokens[idx].content)}</pre>\n'

    renderer.rules["fence"] = fence
    renderer.rules["code_block"] = code_block
    renderer.rules["front_matter"] = front_matter


_ID = re.compile(r'<(\w+)([^<>]*?) id="([^"<>]*)"([^<>]*)>')
_ALIGN = re.compile(r'<(th|td) style="text-align:(left|center|right)">')
_TASK = re.compile(r'<input [^<>]*?type="checkbox"[^<>]*?>')  # (only the task list makes an input)


def _anchor(match: re.Match) -> str:
    tag, before, name, after = match.groups()
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


def to_html(doc: MD.Document, dark: bool = False) -> str:
    """The HTML of *doc* for Qt (see the module docstring)."""
    md = doc.parser
    _install_rules(md, dark)
    _mark_task_lists(doc.tokens)
    body = md.renderer.render(doc.tokens, md.options, {})
    body = _ID.sub(_anchor, body)
    body = _ALIGN.sub(r'<\1 align="\2">', body)
    body = _TASK.sub(_task, body)
    body = body.replace("<table>", '<table border="1" cellspacing="0" cellpadding="6">')
    body = body.replace('<ul class="task-list">', '<ul style="list-style-type: none">')
    return f"<html><body>{body}</body></html>"


def anchor_names(page: str) -> set[str]:
    """The anchors of a page :func:`to_html` made."""
    return set(re.findall(r'<a name="([^"<>]*)">', page))


__all__ = ["DARK", "LIGHT", "anchor_names", "colours", "style_sheet", "to_html"]
