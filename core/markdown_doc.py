"""Markdown parsed once, for every view of it (no Qt here): the Qt viewer
(ui.markdown_html, ui.markdown_view) and the terminal (core.markdown_term).

The parser is markdown-it-py - CommonMark, plus GitHub's tables and
strike-through, footnotes, task lists, definition lists, YAML / TOML front
matter and GitHub's heading anchors (mdit-py-plugins); bare URLs become links
when linkify-it-py is there. It is optional for axross: :func:`available`
says whether it is installed, and the viewer falls back to Qt's own parser
(md4c) without it. axross-markdown requires it.

What a file holds is untrusted (a download, a server, an agent):

* **no raw HTML**: ``html=False`` - a tag is the text it is written as;
* **links are checked** by markdown-it's ``validateLink`` (no ``javascript:``,
  ``vbscript:``, ``file:``, nor ``data:`` but for images), and the views
  decide what a click does;
* **bounded**: at most :data:`MAX_NESTING` levels of nesting (markdown-it's
  own guard against deep structures), and :func:`core_renderable` cuts a text
  before the line that would hold up a view (as ui.markdown_view.renderable).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

#: Levels of nested blocks / inlines markdown-it follows (its default for
#: commonmark is 20; GitHub's documents rarely go past 6).
MAX_NESTING = 30


def available() -> bool:
    """Whether markdown-it-py and mdit-py-plugins are installed."""
    try:
        import markdown_it  # noqa: F401
        import mdit_py_plugins  # noqa: F401
    except ImportError:
        return False
    return True


def slug(text: str) -> str:
    """The anchor GitHub gives a heading: lower case, punctuation dropped,
    spaces as dashes (as ui.markdown_view.slug)."""
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


@dataclass
class Heading:
    level: int
    text: str
    anchor: str


@dataclass
class Document:
    """A parsed text: markdown-it's tokens, the headings (with unique GitHub
    anchors, also set on the heading tokens as ``id``), the front matter as
    written (YAML or TOML, not interpreted) and the parser itself (for its
    renderer)."""

    tokens: list
    headings: list[Heading] = field(default_factory=list)
    front_matter: str = ""
    parser: object = None
    #: the footnote labels in the order the notes are listed
    notes: list[str] = field(default_factory=list)


def make_parser():
    """A markdown-it parser with the full set this module promises."""
    from markdown_it import MarkdownIt
    from mdit_py_plugins.deflist import deflist_plugin
    from mdit_py_plugins.footnote import footnote_plugin
    from mdit_py_plugins.front_matter import front_matter_plugin
    from mdit_py_plugins.tasklists import tasklists_plugin

    linkify = _has_linkify()
    md = MarkdownIt("commonmark", {"html": False, "linkify": linkify, "typographer": False,
                                   "maxNesting": MAX_NESTING})
    md.enable(["table", "strikethrough"])
    if linkify:
        md.enable("linkify")
    md.use(front_matter_plugin).use(footnote_plugin).use(tasklists_plugin).use(deflist_plugin)
    return md


def _has_linkify() -> bool:
    try:
        import linkify_it  # noqa: F401
    except ImportError:
        return False
    return True


def _inline_text(token) -> str:
    """The plain text of an inline token (its children's text and code)."""
    parts = []
    for child in token.children or ():
        if child.type in ("text", "code_inline"):
            parts.append(child.content)
        elif child.type in ("softbreak", "hardbreak"):
            parts.append(" ")
        elif child.type == "image":
            parts.append(child.content)
    return "".join(parts)


def parse(text: str, parser=None) -> Document:
    """*text* parsed (see the module docstring)."""
    md = parser or make_parser()
    tokens = md.parse(text)
    doc = Document(tokens=tokens, parser=md)
    counts: dict[str, int] = {}
    for index, token in enumerate(tokens):
        if token.type == "front_matter":
            doc.front_matter = token.content
        elif token.type == "heading_open":
            inline = tokens[index + 1] if index + 1 < len(tokens) else None
            title = _inline_text(inline) if inline is not None else ""
            base = slug(title) or "section"
            number = counts.get(base, 0)
            counts[base] = number + 1
            anchor = base if number == 0 else f"{base}-{number}"
            token.attrSet("id", anchor)
            doc.headings.append(Heading(int(token.tag[1:]), title, anchor))
        elif token.type == "footnote_open":
            label = (token.meta or {}).get("label")
            doc.notes.append(str(label if label is not None else len(doc.notes) + 1))
    return doc


# -- shared helpers of the views --------------------------------------------------------------

#: C0 and C1 control characters but tab and newline, DEL, and the bidi
#: controls a text could use to make a name read as another one.
_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(text: str) -> str:
    """*text* without control characters: what a terminal or a label must
    never get from a file (an ESC starts an escape sequence)."""
    return _CONTROLS.sub("", text)


def cell_width(text: str) -> int:
    """The columns *text* takes in a terminal: wide (East Asian) characters
    two, combining marks none."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


__all__ = ["Document", "Heading", "MAX_NESTING", "available", "cell_width", "clean",
           "make_parser", "parse", "slug"]
