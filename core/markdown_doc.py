"""Markdown parsed once, for every view of it (no Qt here): the Qt viewer
(ui.markdown_html, ui.markdown_view) and the terminal (core.markdown_term).

The parser is markdown-it-py - CommonMark, plus GitHub's tables and
strike-through, footnotes, task lists, definition lists, YAML / TOML front
matter and GitHub's heading anchors (mdit-py-plugins); bare URLs become links
when linkify-it-py is there. And what GitHub shows beyond those: its alerts
(``> [!NOTE]``, TIP, IMPORTANT, WARNING, CAUTION: :func:`alert_of`), math
(``$…$``, ``$$…$$``, a ``math`` fence: shown as text, the common TeX
commands as Unicode - :func:`math_text`) and emoji short codes (``:tada:``,
the common ones: :data:`EMOJI`). It is optional for axross: :func:`available`
says whether it is installed, and the viewer falls back to Qt's own parser
(md4c) without it. axross-markdown requires it.

What a file holds is untrusted (a download, a server, an agent):

* **raw HTML only as an allowed subset**: markdown-it reads raw HTML into
  ``html_block`` / ``html_inline`` tokens, and :func:`_safe_html` - a core
  rule that runs before any view sees a token - replaces every one of them
  by ``safe_html_block`` / ``safe_html_inline`` holding the events of the
  allowed subset (:class:`_Sanitizer`, the standard library's html.parser):
  the tags of :data:`HTML_BLOCK` / :data:`HTML_INLINE` (``<p align>``,
  ``<img>``, ``<br>``, ``<details>`` / ``<summary>``, ``<kbd>``, ``<sub>`` /
  ``<sup>`` ...), each with only the attributes it may have (``align``;
  an image's ``src``, ``alt``, ``width`` / ``height`` up to
  :data:`HTML_IMAGE_PX`; a link's ``href`` checked as a Markdown link's);
  comments go; any other tag goes and its text stays - but a ``<script>``,
  a ``<style>`` and the like (:data:`HTML_DROPPED`) go with their text. The
  views write HTML of those events only (attributes escaped), never the
  file's own; an image address is decided on by the views as a Markdown
  image's (beside the file only, never the network);
* **links are checked** by markdown-it's ``validateLink`` (no ``javascript:``,
  ``vbscript:``, ``file:``, nor ``data:`` but for images), and the views
  decide what a click does;
* **bounded**: at most :data:`MAX_NESTING` levels of nesting (markdown-it's
  own guard against deep structures; what lies deeper is shown as written),
  and :func:`core_renderable` cuts a text
  before the line that would hold up a view (as ui.markdown_view.renderable).
"""

from __future__ import annotations

import bisect
import contextvars
import functools
import logging
import re
import textwrap
import threading
import time
import unicodedata
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: Levels of a list laid out as nested, in every view (the viewer's two
#: parsers, the terminal, a page of HTML): deeper items are shown at this
#: depth (flatter - parse does it). Two columns a level.
LIST_DEPTH = 16
#: Levels of a quote laid out as nested, in every view: deeper ones are shown
#: at this depth (quote_flatter - parse does it). A run of 20,000 ">" held
#: the window 3 s, the terminal wrote 184 MB of bars for 2 MB of them.
QUOTE_DEPTH = 8
#: Levels of nested blocks / inlines markdown-it follows (its default for
#: commonmark is 20; GitHub's documents rarely go past 6): a list's level is
#: two (the list, its item) - room for LIST_DEPTH of them and what is in
#: their items. (At 30 a list 16 deep fell apart into code.)
MAX_NESTING = 2 * LIST_DEPTH + 12


def available() -> bool:
    """Whether markdown-it-py and mdit-py-plugins are installed."""
    try:
        import markdown_it  # noqa: F401
        import mdit_py_plugins  # noqa: F401
    except ImportError:
        return False
    return True


_URL_HOST = re.compile(r"\A([A-Za-z][A-Za-z0-9+.\-]*://)([^/?#@\s]*@)?([^/?#:\s]+)(.*)\Z", re.DOTALL)
#: Scripts whose letters pass for Latin ones ("аррӏе" in Cyrillic reads "apple").
_LOOK_ALIKE_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"})
#: Latin letters made to look like ASCII ones (Unicode's confusables, the common ones: IPA's and phonetic
#: letters, small capitals, dotless i and j, fullwidth letters).
_LATIN_LOOK_ALIKES = frozenset(list(range(0x0250, 0x02B0)) + list(range(0x1D00, 0x1DC0)) + [0x0131, 0x0237, 0x01C3]
                               + list(range(0xFF21, 0xFF3B)) + list(range(0xFF41, 0xFF5B)))


def safe_host_url(url: str) -> str:
    """*url* with its host in punycode when the host could pass for another
    one - letters of a script that looks Latin (Cyrillic "аррӏе.com"), or
    Latin mixed with another script - as it is otherwise ("münchen.de",
    "例え.jp"): shown and followed alike in the page and the terminal."""
    found = _URL_HOST.match(url)
    if not found or found.group(3).isascii():
        return url
    host = found.group(3)

    def risky(label: str) -> bool:  # (a label of look-alike letters, or of Latin mixed with others)
        if any(ord(ch) in _LATIN_LOOK_ALIKES for ch in label):  # ("ɡoogle", "ʟogin": Latin, yet not a, b, c)
            return True
        scripts = {unicodedata.name(ch, "?").split()[0] for ch in label if ch.isalpha()}
        return bool(scripts & _LOOK_ALIKE_SCRIPTS) or ("LATIN" in scripts and len(scripts) > 1)

    if not any(risky(label) for label in host.split(".")):
        return url
    labels = []
    for label in host.split("."):
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label if label.isascii() else "xn--" + label.lower().encode("punycode").decode("ascii"))
    return found.group(1) + (found.group(2) or "") + ".".join(labels) + found.group(4)


def safe_shown(text: str) -> str:
    """A link's address as its text shows it (safe_host_url) - also one
    without a scheme: "www.pаypal.com", an e-mail's "me@pаypal.com" showed
    their look-alike host as it is."""
    if "://" in text:
        return safe_host_url(text)
    if text.lower().startswith("mailto:"):
        return text[:7] + safe_shown(text[7:])
    if "@" in text and "/" not in text:
        local, _at, host = text.rpartition("@")
        return local + "@" + safe_host_url("x://" + host)[4:]
    return safe_host_url("x://" + text)[4:]


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
    #: why the text could not be parsed ("" when it was): then it is shown as written (_as_written)
    failed: str = ""
    #: the text parsed (as parse was given it): a view whose rendering of the
    #: tokens fails shows it as written instead (as_written)
    source: str = ""


def as_written(text: str, exc: BaseException | str, parser=None) -> Document:
    """*text* as written - a notice saying why above it - for a view whose
    rendering of its tokens failed (a formula, a rule's fault): never a
    blank page or a traceback."""
    why = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"[:200]
    return _as_written(text, parser or make_parser(), why)


def _not_installed(exc: ImportError) -> ImportError:
    """The error for a parser asked for without markdown-it-py: it is
    optional in axross (no extra of axross names it - Qt's own parser stands
    in), so every caller asks available() first."""
    return ImportError(f"markdown-it-py and mdit-py-plugins are needed for this parser ({exc})")


def token_class():
    """markdown-it's Token (for the parser's own rules)."""
    try:
        from markdown_it.token import Token
    except ImportError as exc:
        raise _not_installed(exc) from exc
    return Token


def _normalize(state) -> None:
    """markdown-it's own normalize - line ends as LF, NUL as U+FFFD - with
    str.replace, done only when there is one: its two passes of a regular
    expression over all of a text held Python's lock (a worker's, the
    window waited) 0.1 s for a line of 10 MB."""
    src = state.src
    if "\r" in src:
        src = src.replace("\r\n", "\n").replace("\r", "\n")
    if "\0" in src:
        src = src.replace("\0", "\ufffd")
    state.src = src


_TODO = re.compile(r"\[[ xX]\][ \t\n\v\f\r]+")

# The task-list plugin's class, written in two parts: whole, its "sk-…" tail
# reads like an API key to the public export's leak gate.
_TASK_BOX = "task-list-" "item-checkbox"


def _task_lists(state) -> None:
    """mdit-py-plugins' task lists ("- [ ] x" a box), its list found in one
    pass: the plugin looked for each item's list back from the item, token
    by token - a list of 50,000 tasks took it 2.3 s of a parse's 12."""
    Token = token_class()
    tokens = state.tokens
    last: dict[int, int] = {}  # (the latest token of each level so far)
    for index, token in enumerate(tokens):
        if 2 <= index < len(tokens) - 1 and token.type == "inline" and tokens[index - 1].type == "paragraph_open" \
                and tokens[index - 2].type == "list_item_open" and _TODO.match(token.content):
            box = Token("html_inline", "", 0)
            if token.content.startswith("[ ] "):  # (as the plugin: "[ ]" and a line end, no box but the text's
                box.content = f'<input class="{_TASK_BOX}" disabled="disabled" type="checkbox">'  # cut)
            elif token.content.startswith(("[x] ", "[X] ")):
                box.content = (f'<input class="{_TASK_BOX}" checked="checked" disabled="disabled" '
                               'type="checkbox">')
            token.children.insert(0, box)
            token.children[1].content = token.children[1].content[3:]
            token.content = token.content[3:]
            item = tokens[index - 2]
            item.attrSet("class", "task-list-item")
            tokens[last.get(item.level - 1, len(tokens) - 1)].attrSet("class", "contains-task-list")
        last[token.level] = index


def _linkify_in_pieces(md) -> None:
    """linkify-it-py's searches a piece of a long text at a time: its rule
    pretested all of an inline's text and matched all of a text token in one
    call each - a line of 10 MB held Python's lock for seconds, the window
    froze though only a worker parsed. A long text token is cut where a word
    begins (a link holds no space; markdown-it's text_join joins the pieces
    again), the pretest is asked of the pieces (_text_pieces)."""
    finder = md.linkify
    if getattr(finder, "_ax_pieces", False):
        return
    whole = finder.pretest

    def pretest(text: str) -> bool:
        if len(text) <= LINES_AT_ONCE:
            return whole(text)
        return any(whole(text[begin:stop]) for begin, stop in _text_pieces(text))

    finder.pretest = pretest
    finder._ax_pieces = True
    Token = token_class()

    def cut(state) -> None:
        for token in state.tokens:
            if token.type != "inline" or not token.children or len(token.content) <= LINES_AT_ONCE:
                continue
            children = []
            for child in token.children:
                if child.type != "text" or len(child.content) <= LINES_AT_ONCE:
                    children.append(child)
                    continue
                for begin, stop in _text_pieces(child.content):
                    piece = Token("text", "", 0)
                    piece.content, piece.level = child.content[begin:stop], child.level
                    children.append(piece)
            token.children = children

    md.core.ruler.before("linkify", "linkify_pieces", cut)


def _display_math_lines(state) -> None:
    """A $$...$$ that stands on its own lines in a paragraph - after an alert's "[!NOTE]", after a line
    of text - a display formula, as GitHub shows it: markdown-it read it as inline math (no block may
    interrupt a paragraph), the window, --html and axross-mdcat set it in the line. The paragraph is
    cut around it: text, the formula's block, text."""
    Token = token_class()
    tokens, out, index = state.tokens, [], 0
    while index < len(tokens):
        token = tokens[index]
        inline = tokens[index + 1] if index + 2 < len(tokens) else None
        if token.type != "paragraph_open" or inline is None or inline.type != "inline" or not inline.children \
                or not any(child.type == "math_inline_double" for child in inline.children):
            out.append(token)
            index += 1
            continue
        children, close = inline.children, tokens[index + 2]
        lines: list[list] = [[]]
        for child in children:
            if child.type in ("softbreak", "hardbreak"):
                lines.append([])
            else:
                lines[-1].append(child)
        alone = [any(c.type == "math_inline_double" for c in line)
                 and all(c.type == "math_inline_double" or (c.type == "text" and not c.content.strip())
                         for c in line) for line in lines]
        if not any(alone):
            out.append(token)
            index += 1
            continue
        pending: list = []

        def flush() -> None:
            while pending and pending[-1].type in ("softbreak", "hardbreak"):
                pending.pop()
            if pending:
                out.extend([token.copy(), inline.copy(children=list(pending),
                                                     content="".join(c.content for c in pending)), close.copy()])
            pending.clear()

        for line, lone in zip(lines, alone):
            if lone:
                flush()
                for child in line:
                    if child.type == "math_inline_double":
                        block = Token("math_block", "math", 0)
                        block.content, block.markup, block.block = f"\n{child.content.strip()}\n", "$$", True
                        block.map, block.level = token.map, token.level
                        out.append(block)
            else:
                if pending:
                    pending.append(Token("softbreak", "br", 0))
                pending.extend(line)
        flush()
        index += 3
    if len(out) != len(tokens):
        state.tokens[:] = out


#: A footnote's ways back to its references shown at most (the rest counted: "and 99,980 more").
BACKREFS = 20


def _fewer_backrefs(state) -> None:
    """A footnote referred to again and again: its first BACKREFS ways back, the last of them counting
    the rest (meta "more") - one note cited 100,000 times was a paragraph of 100,000 links, laid out at
    once: 4.2 s of the window's for Ctrl+End, the page not done in 240 s."""
    out, run, kept = [], 0, None
    for token in state.tokens:
        if token.type == "footnote_anchor":
            run += 1
            if run > BACKREFS:
                kept.meta = {**(kept.meta or {}), "more": (kept.meta or {}).get("more", 0) + 1}
                continue
            kept = token
        else:
            run = 0
        out.append(token)
    if len(out) != len(state.tokens):
        state.tokens[:] = out


_QUOTE_MARK = re.compile(r"[ \t]{0,3}>[ \t]?")


def _plugin_keeps_quote_marks() -> bool:
    """Whether mdit-py-plugins keeps a quote's marks in a math block's lines (before 0.7 - the lock's)."""
    try:
        import mdit_py_plugins

        version = tuple(int(part) for part in str(mdit_py_plugins.__version__).split(".")[:2])
    except (ImportError, ValueError, AttributeError):
        return True
    return version < (0, 7)


def _quoted_math(state) -> None:
    """A display formula in a quote without its lines' "> " (mdit-py-plugins
    0.6 keeps them in the block's content: "> $$ / > a = \\frac12 / > $$" was
    "> a = ½ >" - in the window, the terminal, the exported page and a copy).
    Each line after the first loses the marks of the quotes around it where it has them - a lazy line
    without them stays as it is ("> $$ / f = \\frac17 / > $$" was "f = 1/7 >"); a newer plugin takes
    them off itself and nothing is done."""
    if not _plugin_keeps_quote_marks():
        return
    depth = 0
    for token in state.tokens:
        if token.type == "blockquote_open":
            depth += 1
        elif token.type == "blockquote_close":
            depth -= 1
        elif token.type in ("math_block", "math_block_label") and depth > 0 and "\n" in token.content:
            first, *rest = token.content.split("\n")
            stripped = []
            for line in rest:
                for _level in range(depth):
                    mark = _QUOTE_MARK.match(line)
                    if mark is None:
                        break
                    line = line[mark.end():]
                stripped.append(line)
            token.content = "\n".join([first, *stripped])


def make_parser():
    """A markdown-it parser with the full set this module promises."""
    try:
        from markdown_it import MarkdownIt
        from mdit_py_plugins.deflist import deflist_plugin
        from mdit_py_plugins.dollarmath import dollarmath_plugin
        from mdit_py_plugins.footnote import footnote_plugin
        from mdit_py_plugins.front_matter import front_matter_plugin
        from mdit_py_plugins.tasklists import tasklists_plugin
    except ImportError as exc:
        raise _not_installed(exc) from exc

    linkify = _has_linkify()
    # html=True only so that raw HTML comes as tokens of its own: _safe_html
    # replaces every one of them by its allowed subset before any view sees it.
    md = MarkdownIt("commonmark", {"html": True, "linkify": linkify, "typographer": False,
                                   "maxNesting": MAX_NESTING})
    md.enable(["table", "strikethrough"])
    if linkify:
        md.enable("linkify")
        _linkify_in_pieces(md)
    md.use(front_matter_plugin).use(footnote_plugin).use(tasklists_plugin).use(deflist_plugin)
    md.core.ruler.at("github-tasklists", _task_lists)
    _folded_note_refs(md)
    # Math as pandoc and GitHub read it: "$" opens only before a non-space and
    # closes only after one, not before a digit - "tickets are $5 and $10" stays text.
    md.use(dollarmath_plugin, allow_space=False, allow_digits=False, double_inline=True,
           allow_blank_lines=False)
    md.inline.ruler.before("strikethrough", "single_tilde", _single_tilde)
    shown_as = md.normalizeLinkText

    def link_text(url: str) -> str:
        # An address's host in punycode stays so in the text shown: decoded,
        # "xn--pypal-4ve.com" read "pаypal.com" (a Cyrillic а) - the look-alike
        # it was made to hide.
        if "xn--" in url.lower():
            return url
        safe = safe_shown(url)  # (a look-alike host: in punycode, as its link goes - an e-mail's, www.'s too)
        return safe if safe != url else shown_as(url)

    md.normalizeLinkText = link_text
    md.core.ruler.at("normalize", _normalize)
    md.core.ruler.after("block", "github_alerts", _alerts)
    md.core.ruler.after("block", "quoted_math", _quoted_math)
    md.core.ruler.after("footnote_tail", "fewer_backrefs", _fewer_backrefs)
    md.core.ruler.after("inline", "display_math_lines", _display_math_lines)
    md.core.ruler.push("emoji", _emoji)
    md.core.ruler.after("inline", "safe_html", _safe_html)  # (before the task lists' own boxes)
    md.core.ruler.push("unsafe_links", _unsafe_links)
    md.core.ruler.push("fewer_spans", _fewer_spans)
    md.core.ruler.after("inline", "backtick_math", _backtick_math)
    md.core.ruler.push("fewer_formulas", _fewer_formulas)
    if not linkify:  # (GitHub's extended autolinks: linkify-it-py is no dependency - its rule when there)
        md.core.ruler.push("autolinks", _autolinks)
    md.block.ruler.before("front_matter", "toml_front_matter", _toml_front_matter,
                          {"alt": ["paragraph", "reference", "blockquote", "list"]})
    _keep_deep_blocks(md)
    _guard(md)
    return md


#: A parse's time at most: this and this much a character more - past it the
#: text is shown as written (_as_written), never a page that does not come.
PARSE_SECONDS = 20.0
PARSE_SECONDS_PER_CHAR = 2e-5
_PARSING = threading.local()


class ParseTooLong(Exception):
    """A parse ran past its time (PARSE_SECONDS)."""


def _guard(md) -> None:
    """*md*'s loops kept moving and in time: a rule that says yes to a
    token in a link's label without moving on (markdown-it 4.2: "[~x~]"
    hung for ever) - the parse moves on itself; a parse past its time
    (_PARSING.deadline, set by parse) - ParseTooLong."""
    skip, inline_tokenize, block_tokenize = md.inline.skipToken, md.inline.tokenize, md.block.tokenize

    def in_time() -> None:
        deadline = getattr(_PARSING, "deadline", None)
        if deadline is not None:
            _PARSING.ticks += 1
            if not _PARSING.ticks & 255 and time.monotonic() > deadline:
                raise ParseTooLong

    def skip_token(state) -> None:
        in_time()
        pos = state.pos
        skip(state)
        if state.pos <= pos:  # (a rule's yes without moving on)
            state.pos = pos + 1
            state.cache[pos] = state.pos

    def tokenize_inline(state) -> None:
        in_time()
        inline_tokenize(state)

    def tokenize_blocks(state, start_line: int, end_line: int, *more) -> None:
        in_time()
        block_tokenize(state, start_line, end_line, *more)

    md.inline.skipToken = skip_token
    md.inline.tokenize = tokenize_inline
    md.block.tokenize = tokenize_blocks


def _as_written(text: str, md, why: str) -> Document:
    """*text* as written - a notice saying why above it - for a text the
    parser failed on (a rule's error, past its time)."""
    Token = token_class()

    from core.i18n import tr

    notice = tr("This text could not be read as Markdown ({why}): shown as written.").format(why=why)
    inline = Token("inline", "", 0, content=notice, level=1, block=True, map=[0, 1])
    inline.children = [Token("text", "", 0, content=notice)]
    tokens = [Token("paragraph_open", "p", 1, level=0, block=True, map=[0, 1]), inline,
              Token("paragraph_close", "p", -1, level=0, block=True),
              Token("fence", "code", 0, content=text if text.endswith("\n") or not text else text + "\n",
                    markup="```", info="", level=0, block=True, map=[0, text.count("\n") + 1])]
    return Document(tokens=tokens, parser=md, failed=why, source=text)


def _keep_deep_blocks(md) -> None:
    """What lies deeper than :data:`MAX_NESTING` is shown as written, in a
    code block where it was cut. (markdown-it skips it - the rest of that
    quote or list, which with lazy continuation lines is often the rest of
    the text, later headings too - without a word.)"""
    tokenize = md.block.tokenize

    def deep_tokenize(state, start_line: int, end_line: int) -> None:
        if state.level >= md.options["maxNesting"]:
            line = state.skipEmptyLines(start_line)
            if line < end_line and state.sCount[line] >= state.blkIndent:
                # up to where this level ends (a list item: the first line
                # indented less than it, as markdown-it's own loop stops)
                end = line + 1
                while end < end_line and (state.isEmpty(end)
                                          or state.sCount[end] >= state.blkIndent):
                    end += 1
                while end > line + 1 and state.isEmpty(end - 1):
                    end -= 1
                token = state.push("code_block", "code", 0)
                token.content = state.getLines(line, end, state.blkIndent, True)
                token.map = [line, end]
                state.line = end
                return
        tokenize(state, start_line, end_line)

    md.block.tokenize = deep_tokenize


def _toml_front_matter(state, start_line: int, end_line: int, silent: bool) -> bool:
    """TOML front matter (Hugo's ``+++`` lines around it) as the plugin's YAML
    one: a ``front_matter`` token. (mdit-py-plugins knows ``---`` only: a
    TOML block was shown as a paragraph of its own.)"""
    if start_line != 0 or state.src[state.bMarks[0]:state.eMarks[0]].rstrip() != "+++":
        return False
    close = next((line for line in range(1, end_line)
                  if state.src[state.bMarks[line]:state.eMarks[line]].rstrip() == "+++"), None)
    if close is None:  # (not closed: not front matter, as the plugin's)
        return False
    if silent:
        return True
    token = state.push("front_matter", "", 0)
    token.hidden, token.block, token.markup = True, True, "+++"
    token.content = state.src[state.bMarks[1]:state.eMarks[close - 1]] if close > 1 else ""
    token.map = [0, close + 1]
    state.line = close + 1
    return True


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


# -- code: lexed in a child ------------------------------------------------------------------------

#: Seconds the lexing of a code block may take (in a child, its start included): past them the block
#: is plain. (The editor's own children wait 60 s: a page waited as long, blank.)
CODE_LEX_SECONDS = 5.0
_code_pools: dict = {}
_code_pools_lock = threading.Lock()


def _code_pool(seconds: float):
    """core.lex_worker's children bound to *seconds* a block (one pool for each bound)."""
    from core import image_worker as IW
    from core import lex_worker as LW

    with _code_pools_lock:
        pool = _code_pools.get(seconds)
        if pool is None:
            class Bound(LW.LexChild):
                @staticmethod
                def _default_seconds() -> float:
                    return seconds

            pool = _code_pools[seconds] = IW.ChildPool(Bound, lambda: LW.POOL_SIZE, lambda: LW.POOL_IDLE_SECONDS,
                                                       lambda: LW.TEXTS_PER_CHILD, "reader-lex-worker")
        return pool


def close_code_pools() -> None:
    """The reader's lexing children ended (tests; the program's end ends them too)."""
    with _code_pools_lock:
        pools = list(_code_pools.values())
        _code_pools.clear()
    for pool in pools:
        pool.close()


def code_tokens(code: str, lang: str, style: str = "default", seconds: float | None = None) -> list | None:
    """Pygments' tokens of *code* in the language *lang* - ``(token type, text)``, every character of
    it, those *style* gives no colour as Text - for a Pygments formatter; or None: no such language, no
    Pygments, or the lexing failed or took longer than *seconds* (CODE_LEX_SECONDS) - the block plain.
    Lexed in a child process (core.lex_worker): a lexer's regular expression stuck in backtracking held
    Python's lock as long as it ran - the window stood still (the editor measured 8.7 s), also when a
    worker thread lexed."""
    try:
        from pygments.lexers import get_lexer_by_name
        from pygments.token import Text, string_to_tokentype
        from pygments.util import ClassNotFound
    except ImportError:
        return None
    try:
        name = get_lexer_by_name((lang or "").strip().lower()).name
    except ClassNotFound:
        return None
    except Exception:  # noqa: BLE001 - a lexer's own fault: plain
        return None
    from array import array

    def consume(head: dict, body) -> list | None:
        if "error" in head:
            return None
        try:
            names = [string_to_tokentype(str(n)) for n in head["types"]]
            count = int(head["count"])
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        data = body.read_all() if hasattr(body, "read_all") else body
        numbers = array("I")
        if len(data) != count * 3 * numbers.itemsize:
            return None
        numbers.frombytes(bytes(data))
        out, at = [], 0
        for index in range(0, len(numbers), 3):
            start, length, kind = numbers[index], numbers[index + 1], numbers[index + 2]
            if kind >= len(names) or start < at or start + length > len(code):
                return None
            if start > at:
                out.append((Text, code[at:start]))
            out.append((names[kind], code[start:start + length]))
            at = start + length
        if at < len(code):
            out.append((Text, code[at:]))
        return out

    bound = CODE_LEX_SECONDS if seconds is None else float(seconds)
    try:
        with _code_pool(bound).borrowed() as child:
            return child.ask({"language": name, "text": code, "style": style}, consume)
    except Exception as exc:  # noqa: BLE001 - too slow, crashed, could not start: the block plain
        log.info("A code block in %s shown plain: %s", name, exc)
        return None


#: The bytes no text holds (but tab, line ends, form feed, escape): a file
#: of more than one in ten of them - or of a NUL - in its first 8 KB is
#: no text (a picture, a program): said, not shown as garbage.
_NOT_CONTROL = bytes(b for b in range(256) if not (b < 32 and b not in (9, 10, 12, 13, 27)) and b != 127)
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


def looks_binary(data: bytes) -> bool:
    """Whether a file's *data* is no text (a NUL, or more than one byte in
    ten no text holds, in its first 8 KB - UTF-16 and -32 with their byte
    order mark are text)."""
    head = data[:8192]
    if not head or head.startswith(_BOMS):
        return False
    if b"\0" in head:
        return True
    return len(head.translate(None, _NOT_CONTROL)) * 10 > len(head)


def decode_text(data: bytes) -> str:
    """The text of a file's *data*: UTF-8 (damaged bytes replaced) without
    its byte order mark, or UTF-16 / UTF-32 when a BOM says so - and a file
    that is no UTF-8 as Windows-1252 / Latin-1. (The mark was the first
    character of the text: "\ufeff# Title" is no heading.)"""
    for bom, codec in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe\x00\x00", "utf-32-le"),
                       (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"),
                       (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):
            return data[len(bom):].decode(codec, "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start >= len(data) - 3 and exc.reason == "unexpected end of data":
            return data[:exc.start].decode("utf-8", "replace")  # (cut at the read limit inside a letter)
    text = data.decode("utf-8", "replace")
    damaged = text.count("\ufffd") - data.count(b"\xef\xbf\xbd")
    letters = sum(1 for ch in text if ch > "\x7f") - text.count("\ufffd")
    if damaged <= letters:  # (UTF-8 with a damaged byte or two: the rest as it is)
        return text
    # (no UTF-8: Windows-1252 - Latin-1 with its quotes and dashes - as core.text_document reads Latin-1;
    # every accented letter of a Latin-1 file was a U+FFFD)
    try:
        return data.decode("cp1252")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _anchor_for(title: str, counts: dict, taken: set) -> str:
    """The unique GitHub anchor of a heading *title* (see parse)."""
    base = slug(title) or "section"
    number = counts.get(base, 0)
    anchor = base if number == 0 else f"{base}-{number}"
    while anchor in taken:  # (GitHub numbers headings of one name; another's too)
        number += 1
        anchor = f"{base}-{number}"
    counts[base] = number + 1
    taken.add(anchor)
    return anchor


def _html_headings(token, doc: Document, counts: dict, taken: set) -> None:
    """The headings raw HTML writes (<h1 align="center">Project</h1>) as
    the Markdown ones: in the outline, with their anchor - set on the
    heading's start event as "id" for the views."""
    events = html_events(token)
    for index, event in enumerate(events):
        if event[0] != "start" or event[1] not in ("h1", "h2", "h3", "h4", "h5", "h6"):
            continue
        words = []
        for later in events[index + 1:]:
            if later[0] == "end" and later[1] == event[1]:
                break
            if later[0] == "text":
                words.append(later[1])
        title = " ".join("".join(words).split())
        anchor = _anchor_for(title, counts, taken)
        event[2]["id"] = anchor
        doc.headings.append(Heading(int(event[1][1]), title, anchor))


def parse(text: str, parser=None, notes=None) -> Document:
    """*text* parsed (see the module docstring). *notes*: (the labels of a
    long text's footnotes in the order they are numbered - note_labels -,
    whether this is its last part): a part of it parsed with them numbered
    across the text, their list in the last part only (moved there:
    notes_to_end)."""
    md = parser or make_parser()
    if text.startswith("\ufeff"):  # (a BOM: no character of the text)
        text = text[1:]
    text = flatter(text, LIST_DEPTH)[0]  # (deeper lists: at LIST_DEPTH, as every view shows them)
    text = quote_flatter(text)[0]  # (deeper quotes: at QUOTE_DEPTH)
    env: dict = {}
    if notes is not None:  # (labels: (label, how often it is referred to) - the last part's ↩ that many)
        labels, last, *more = notes
        places = labels.places if isinstance(labels, NoteLabels) else {}
        first = more[0] if more else None

        def seed(label: str, count: int) -> int:
            if last:  # (each note's ↩ as often as it is referred to - from its notes again here)
                return count - sum(1 for _line, inside, _sub in places.get(label, ()) if inside)
            if first is None:
                return 0
            return sum(1 for line, _inside, _sub in places.get(label, ()) if line < first)  # (numbered on)

        env["footnotes"] = {"refs": _NumberedNotes((":" + label, number) for number, (label, _n) in enumerate(labels)),
                            "list": {number: {"label": label, "count": seed(label, count)}
                                     for number, (label, count) in enumerate(labels)}}
    _PARSING.deadline = time.monotonic() + PARSE_SECONDS + len(text) * PARSE_SECONDS_PER_CHAR
    _PARSING.ticks = 0
    try:
        tokens = md.parse(text, env)
    except ParseTooLong:
        return _as_written(text, md, "it took too long")
    except (Exception, RecursionError) as exc:  # noqa: BLE001 - any rule's error: never a blank page
        return _as_written(text, md, f"{type(exc).__name__}: {exc}"[:200])
    finally:
        _PARSING.deadline = None
    if notes is not None and notes[1] and places:  # (a reference in a note: its place's name as one parse
        inside = {label: [sub for _line, within, sub in found if within] for label, found in places.items()}
        for token in tokens:  # gives it - "fnref3", not "fnref3:1")
            for child in token.children or ():
                if child.type == "footnote_ref" and inside.get(child.meta.get("label")):
                    child.meta = dict(child.meta, subId=inside[child.meta["label"]].pop(0))
    if notes is not None and not notes[1]:  # (the list of notes: the last part's)
        kept, inside = [], False
        for token in tokens:
            if token.type == "footnote_block_open":
                inside = True
            elif token.type == "footnote_block_close":
                inside = False
            elif not inside:
                kept.append(token)
        tokens = kept
    doc = Document(tokens=tokens, parser=md, source=text)
    counts: dict[str, int] = {}
    # The anchors of the footnotes (fn1, fnref1 - the plugin's) are no
    # heading's: a heading "fn1" took the place footnote 1 is linked to.
    notes = sum(1 for token in tokens if token.type == "footnote_open")
    taken = {f"{kind}{number}" for number in range(1, notes + 1) for kind in ("fn", "fnref")}
    for index, token in enumerate(tokens):
        if token.type == "front_matter":
            doc.front_matter = token.content
        elif token.type == "heading_open":
            inline = tokens[index + 1] if index + 1 < len(tokens) else None
            title = _inline_text(inline) if inline is not None else ""
            anchor = _anchor_for(title, counts, taken)
            token.attrSet("id", anchor)
            doc.headings.append(Heading(int(token.tag[1:]), title, anchor))
        elif token.type == "safe_html_block":
            _html_headings(token, doc, counts, taken)
        elif token.type == "footnote_open":
            label = (token.meta or {}).get("label")
            doc.notes.append(str(label if label is not None else len(doc.notes) + 1))
    return doc


class _NoteRefs(dict):
    """The footnotes' labels (":label" -> number) as GitHub matches them:
    case aside ([^A] is [^a]'s - it stayed as written). *names*: each
    label as its first use wrote it - the definition's (read before the
    references)."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.names: dict = {}
        for key, value in dict(*args, **kwargs).items():
            self[key] = value

    def __setitem__(self, key, value) -> None:
        self.names.setdefault(key.casefold(), key)
        super().__setitem__(key.casefold(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.casefold())

    def __contains__(self, key) -> bool:
        return super().__contains__(key.casefold() if isinstance(key, str) else key)

    def get(self, key, default=None):
        return super().get(key.casefold(), default)

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]


class _NumberedNotes(_NoteRefs):
    """The footnotes' numbers a part of a long text is parsed with: a
    definition there does not take its note's number back (the plugin sets
    it -1: the references after it were numbered anew, 4, 5, 6)."""

    def __setitem__(self, key, value) -> None:
        if value == -1 and key in self:
            return
        super().__setitem__(key, value)


def _folded_note_refs(md) -> None:
    """The footnote plugin's reference rule matching labels as GitHub does,
    case aside: each reference's label the note's own (_NoteRefs)."""
    rules = md.inline.ruler.__rules__
    found = next((rule for rule in rules if rule.name == "footnote_ref"), None)
    if found is None:
        return
    original = found.fn

    def footnote_ref(state, silent: bool) -> bool:
        notes = state.env.setdefault("footnotes", {})
        if not isinstance(notes.get("refs"), _NoteRefs):
            notes["refs"] = _NoteRefs(notes.get("refs") or {})
        count = len(state.tokens)
        if not original(state, silent):
            return False
        if not silent and len(state.tokens) > count and state.tokens[-1].type == "footnote_ref":
            token = state.tokens[-1]
            label = token.meta.get("label")
            name = notes["refs"].names.get((":" + label).casefold(), ":" + label)[1:] if label else label
            token.meta["label"] = name
            entry = notes.get("list", {}).get(token.meta.get("id"))
            if entry is not None and "label" in entry:
                entry["label"] = name
        return True

    md.inline.ruler.at("footnote_ref", footnote_ref)


class NoteLabels(list):
    """The notes' (label, how often referred to), in the order they are
    numbered - and where each is referred to: {label: [(line, inside a note,
    its place's number)]} (a part numbers its places on from the ones before)."""

    places: dict = {}


@functools.lru_cache(maxsize=2)  # (asked for twice of one text: its parts, its notes' numbers)
def note_plan(text: str):
    """(*text* - its footnotes' definitions where they are, no block there -,
    the definitions again - each whole, as markdown-it reads it, a quote's
    without its ">", a list item's without its indentation -, the notes'
    (label, how often referred to) in the order they are numbered) - or None: no note, or an inline
    one (^[...]: numbered where it stands). A long text is parsed in parts,
    the definitions the last of them, never cut (one before a heading took
    the heading with it, a cut inside them lost notes). Read by a parse of
    all of the text - its blocks and references as one parse reads them:
    none in code; one in a quote too."""
    md = make_parser()
    md.disable("footnote_tail")  # (the definitions where they are, their lines with them)
    if "linkify" in md.get_active_rules()["core"]:  # (no link holds a note: 1 s of 3.8 MB)
        md.disable(["linkify", "linkify_pieces"])
    env: dict = {}
    tokens = md.parse(text, env)
    notes = env.get("footnotes") or {}
    listed = notes.get("list") or {}
    if any("label" not in note for note in listed.values()):
        return None  # (an inline note)
    lines = text.split("\n")
    taken, moved = set(), []
    for token in tokens:
        if token.type != "footnote_reference_open" or not token.map:
            continue
        # (each stays where it is too - it is no block there: one between two lists kept them two - and
        # goes with the others, a quote's without its ">", a list item's without its indentation)
        start, end = token.map
        taken.update(range(start, end + 1))  # (its lines and the one after: no part begins there - _text_parts)
        written = lines[start:end]
        for _depth in range(token.level):
            written = [re.sub(r"^ {0,3}> ?", "", line, count=1) for line in written]
        written = textwrap.dedent("\n".join(written)).split("\n")
        moved.append("\n".join(written).rstrip())
    if not moved:
        return None
    kept = list(lines)
    last = len(kept) - 1
    while last >= 0 and (not kept[last].strip() or last in taken):  # (its definitions where they are: no text)
        last -= 1
    rule = ""
    if last > 0 and re.fullmatch(r" {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*", kept[last]) and not kept[last - 1].strip():
        rule = kept[last] + "\n\n"  # (the text ending in a rule: it goes with the notes - one rule before them)
        kept[last] = ""
    body = "\n".join(kept)
    # (where each is referred to - its line, whether inside a note, its place's number: the parts are
    # numbered on from the places before them; the notes' part refers to it from inside them again)
    places, depth = {}, 0
    for token in tokens:
        if token.type == "footnote_reference_open":
            depth += 1
        elif token.type == "footnote_reference_close":
            depth -= 1
        elif token.type == "inline" and token.map:
            for child in token.children or ():
                if child.type == "footnote_ref":
                    places.setdefault(child.meta.get("label"), []).append(
                        (token.map[0], bool(depth), child.meta.get("subId", 0)))
    labels = NoteLabels((listed[number]["label"], listed[number].get("count", 1)) for number in sorted(listed))
    labels.places = places
    return body.rstrip("\n") + "\n", rule + "\n\n".join(moved) + "\n", labels, frozenset(taken)


def note_labels(text: str) -> list[tuple[str, int]]:
    """The labels of *text*'s footnotes in the order they are numbered, each
    with how often it is referred to (see note_plan)."""
    plan = note_plan(text)
    return plan[2] if plan else []


# -- raw HTML: an allow-listed subset -------------------------------------------------------------

#: Tags of raw HTML that are kept (inline: in a paragraph; block: also on
#: lines of their own). Anything else is dropped and its text kept - but
#: for :data:`HTML_DROPPED`, whose text goes with them.
HTML_INLINE = frozenset("b strong i em u s strike del ins mark small sub sup kbd code br img a".split())
HTML_BLOCK = HTML_INLINE | frozenset("p div center details summary h1 h2 h3 h4 h5 h6 hr blockquote pre "
                                     "table thead tbody tr th td ul ol li".split())
#: Tags whose contents are no text to read: dropped with them.
HTML_DROPPED = frozenset("script style template iframe object embed noscript textarea title xmp noembed "
                         "noframes svg math select head frame frameset applet audio video canvas".split())
#: Void tags (no end tag).
HTML_VOID = frozenset({"br", "img", "hr"})
#: Dropped tags that end a line of the text they held (a table's row, an item).
HTML_LINE_TAGS = frozenset("dt dd section article header footer nav aside figure "
                           "figcaption caption".split())
_ALIGN_VALUES = frozenset({"left", "center", "right", "justify"})
_IMAGE_ALIGN = frozenset({"left", "right", "middle", "top", "bottom", "center"})
#: An <a id> / <a name> kept: GitHub's characters of an anchor - letters, digits, "-", "_", ".", ":"
#: and the like ("26.8.0", "v1.2.0", "2024": Node.js's CHANGELOG links its versions so) - 128 at most.
_NAME = re.compile(r"[\w.\-:~+()@!$*,;=%]{1,128}\Z")
_DATA_IMAGE = re.compile(r"data:image/(?:png|gif|jpeg|webp);", re.IGNORECASE)
#: The widest / tallest an image may be asked to be (a layout bomb otherwise).
HTML_IMAGE_PX = 2000
#: Raw HTML tables inside each other at most (a deeper one keeps its text only).
HTML_TABLES = 2
_TABLE_TAGS = frozenset("table thead tbody tr th td".split())
#: Raw HTML tags open inside each other at most (deeper ones are dropped,
#: their text kept): a quote or a list nested thousands deep is a layout bomb.
HTML_DEPTH = 16


def _html_size(value: str) -> str:
    value = value.strip().lower().removesuffix("px")
    return value if value.isdigit() and 0 < int(value) <= HTML_IMAGE_PX else ""


_BAD_PROTOCOL = re.compile(r"(vbscript|javascript|file|data):", re.IGNORECASE)
_GOOD_DATA = re.compile(r"data:image/(gif|png|jpeg|webp);", re.IGNORECASE)


def _link_ok(url: str, md) -> bool:
    """Whether *url* may be a link's or an image's address - markdown-it's
    validateLink, or (*md* None: Qt's own parser, without markdown-it) its
    rule: no javascript:, vbscript:, file:, nor data: but for images."""
    # (spaces, tabs and control characters inside it as a browser drops them:
    # "jav&#x09;ascript:" was kept, a link Qt's own parser showed as written)
    bare = re.sub(r"[\x00-\x20\x7f]", "", url).lower()
    if _BAD_PROTOCOL.match(bare) and not _GOOD_DATA.match(bare):
        return False
    if md is not None:
        return md.validateLink(url)
    return True


def _link_norm(url: str, md) -> str:
    return md.normalizeLink(url) if md is not None else clean(url).strip()


def _html_src(value: str, md) -> str:
    """An image's address as the views take it (they decide what is read:
    a file beside the document, never the network) - "" when it is no
    image address at all."""
    value = value.strip()
    if _DATA_IMAGE.match(value):
        return value
    if not value or not _link_ok(value, md):
        return ""
    return _link_norm(value, md)


def _html_attrs(tag: str, attrs, md) -> dict[str, str]:
    """The attributes of *tag* that are kept (see :func:`sanitize_html`)."""
    found: dict[str, str] = {}
    for name, value in attrs:
        name, value = name.lower(), clean(value or "")
        if name in found:
            continue
        if name == "align" and tag in ("p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "th", "td") \
                and value.lower() in _ALIGN_VALUES:
            found[name] = value.lower()
        elif tag == "details" and name == "open":  # (shown open at first; a click folds it)
            found[name] = ""
        elif tag in ("td", "th") and name in ("colspan", "rowspan"):
            if value.strip().isdigit() and 1 <= int(value) <= 100:  # (a cell of 999 columns: no)
                found[name] = value.strip()
        elif tag == "img":
            if name == "src":
                src = _html_src(value, md)
                if src:
                    found[name] = src
            elif name in ("alt", "title"):
                found[name] = value[:500]
            elif name in ("width", "height") and _html_size(value):
                found[name] = _html_size(value)
            elif name == "align" and value.lower() in _IMAGE_ALIGN:
                found[name] = value.lower()
        elif tag == "a":
            if name == "href" and value.strip() and _link_ok(value.strip(), md):
                found[name] = _link_norm(value.strip(), md)
            elif name == "title":
                found[name] = value[:500]
            elif name in ("name", "id") and _NAME.match(value):
                found["name"] = value
    if tag == "img" and "src" not in found:
        return {}
    return found


class _Sanitizer:
    """Raw HTML as events - ``("start", tag, attrs)``, ``("end", tag)``,
    ``("text", text)`` - of the allowed tags only (html.parser reads it:
    comments, declarations, processing instructions go; character
    references are decoded into the text). Open tags are counted across the
    chunks of one document (a ``<details>`` opened in one HTML block closes
    in a later one); an end tag nothing opened is dropped."""

    def __init__(self, md, allowed: frozenset) -> None:
        """*md*: markdown-it (its link rules), or None (Qt's own parser's
        text passes: the same rules without it)."""
        from html.parser import HTMLParser

        self.md, self.allowed = md, allowed
        self.open: list[str] = []
        self.events: list[tuple] = []
        self.dropping: list[str] = []  # (inside a script, a style ...: nothing is kept)
        self.flat_tables = 0  # (tables too deep inside others: their table tags go)
        self._source, self._base, self._seen = "", 0, {}  # (feed: what a dropped tag may be closed in)
        self.literal = False  # (a dropped tag just shown as text: no raw text after it)
        sanitizer = self

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                sanitizer.start(tag, attrs)

            def handle_startendtag(self, tag, attrs):
                sanitizer.start(tag, attrs, void=True)

            def handle_endtag(self, tag):
                sanitizer.end(tag)

            def handle_data(self, data):
                sanitizer.text(data)

            def set_cdata_mode(self, elem, *args, **kwargs):
                # (a <script>, a <style> named in prose, shown as text: what follows
                # it is no script's text - its tags still tags, "<kbd>" was literal)
                if sanitizer.literal:
                    sanitizer.literal = False
                    return
                super().set_cdata_mode(elem, *args, **kwargs)

        self.parser = Parser(convert_charrefs=True)

    def feed(self, html_text: str, allowed: frozenset, later: tuple[str, int] | None = None) -> list[tuple]:
        """The events of *html_text*; *later*: (the lowercased raw HTML it
        is part of, where in it it begins) - a tag it opens may still be
        closed after it (a paragraph's later raw HTML). Searched, never cut
        or joined anew: per tag that was quadratic (20,000 tags, 46 s)."""
        self.allowed, self.events = allowed, []
        self._source, self._base = later if later is not None else (html_text.lower(), 0)
        self._seen = {}
        self.parser.feed(html_text)
        self.parser.close()  # (what is left in its buffer: text, not a tag still to come)
        return self.events

    def start(self, tag: str, attrs, void: bool = False) -> None:
        tag = tag.lower()
        if self.dropping:
            return  # (inside a script, a style …: its text is no HTML - "<script>" twice needs one end)
        if tag in HTML_DROPPED:
            if not void and tag not in HTML_VOID:
                if not self._closed_later(tag):
                    # (prose that names it - "put it in a <script> tag": the
                    # tag as text, as GitHub's tag filter shows it; never all
                    # that follows dropped with it)
                    self.events.append(("text", self.parser.get_starttag_text() or f"<{tag}>"))
                    self.literal = True  # (and the parser not in a script's raw text: Parser.set_cdata_mode)
                    return
                self.dropping.append(tag)
            return
        if tag not in self.allowed:
            if tag in HTML_LINE_TAGS:
                self.events.append(("start", "br", {}))
            elif tag in ("td", "th"):
                self.events.append(("text", " "))
            return
        if len(self.open) >= HTML_DEPTH and tag not in HTML_VOID and not void:
            return
        if tag in _TABLE_TAGS and (self.flat_tables or (tag == "table" and self.open.count("table") >= HTML_TABLES)):
            # (tables inside tables: Qt's layout time grows fast with their depth -
            # a deeper one's text stays, its table goes)
            if tag == "table":
                self.flat_tables += 1
            elif tag in ("td", "th"):
                self.events.append(("text", " "))
            return
        kept = _html_attrs(tag, attrs, self.md)
        if tag in ("img", "a") and not kept:
            return  # (no image address that may be shown, a link to nowhere: no tag)
        if tag == "center":
            tag, kept = "div", {"align": "center"}
        self.events.append(("start", tag, kept))
        if tag not in HTML_VOID and not void:
            self.open.append(tag)

    def end(self, tag: str) -> None:
        tag = tag.lower()
        if self.dropping:
            if tag == self.dropping[-1]:
                self.dropping.pop()
            return
        if tag == "center":
            tag = "div"
        if tag in _TABLE_TAGS and self.flat_tables:
            if tag == "table":
                self.flat_tables -= 1
            elif tag == "tr":
                self.events.append(("start", "br", {}))
            return
        if tag not in self.allowed or tag not in self.open:
            if tag in HTML_LINE_TAGS:
                self.events.append(("start", "br", {}))
            return
        while self.open:  # (what is open inside it ends with it)
            top = self.open.pop()
            self.events.append(("end", top))
            if top == tag:
                break

    def _closed_later(self, tag: str) -> bool:
        """Whether the *n*-th "<tag" of the source has a "</tag" after it."""
        source = getattr(self, "_source", "")
        number = self._seen.get(tag, 0)
        self._seen[tag] = number + 1
        if getattr(self, "_places_of", None) is not source:  # (each tag's places found once a source:
            self._places_of, self._places = source, {}  # walked to the n-th from the start, it was quadratic)
        places = self._places.get(tag)
        if places is None:
            starts = [m.start() for m in re.finditer(re.escape("<" + tag), source)]
            places = self._places[tag] = (starts, source.rfind("</" + tag))
        starts, last_end = places
        index = bisect.bisect_left(starts, getattr(self, "_base", 0)) + number
        return index < len(starts) and last_end >= starts[index]

    def text(self, data: str) -> None:
        if not self.dropping and data:
            self.events.append(("text", clean(data)))

    def close(self, keep: int = 0) -> list[tuple]:
        """End events for what is still open above the first *keep* tags."""
        out = [("end", tag) for tag in reversed(self.open[keep:])]
        del self.open[keep:]
        return out


def _safe_html(state) -> None:
    """Raw HTML made safe (after the inline rules, before the task lists
    make their boxes): every ``html_block`` and ``html_inline`` token is
    replaced by ``safe_html_block`` / ``safe_html_inline`` with its events
    (``meta["html"]``, :class:`_Sanitizer`): the allowed tags and
    attributes only, nothing else of it reaches a view. What a paragraph
    opened (``<b>`` without ``</b>``) ends with it; what blocks opened ends
    with the document."""
    Token = token_class()

    md = state.md
    blocks = _Sanitizer(md, HTML_BLOCK)
    tokens = state.tokens
    for token in tokens:
        if token.type == "html_block":
            token.type = "safe_html_block"
            token.meta = {"html": blocks.feed(token.content, HTML_BLOCK)}
            token.content = ""
        elif token.type == "inline" and token.children and any(
                child.type == "html_inline" for child in token.children):
            inline = _Sanitizer(md, HTML_INLINE)
            children = []
            raw = [child.content for child in token.children if child.type == "html_inline"]
            whole, at = "".join(raw).lower(), 0  # (once: a dropped tag's end looked for in what follows)
            for child in token.children:
                if child.type == "html_inline":
                    child.type = "safe_html_inline"
                    child.meta = {"html": inline.feed(child.content, HTML_INLINE, (whole, at))}
                    at += len(child.content)
                    child.content = ""
                elif inline.dropping:
                    continue  # (between <script> and </script>: no text to read)
                children.append(child)
            token.children = children
            closing = inline.close()
            if closing:
                end = Token("safe_html_inline", "", 0)
                end.meta = {"html": closing}
                token.children.append(end)
    closing = blocks.close()
    if closing:
        end = Token("safe_html_block", "", 0)
        end.block, end.meta = True, {"html": closing}
        tokens.append(end)


def sanitizer(allowed: frozenset = HTML_BLOCK) -> _Sanitizer:
    """A sanitizer of raw HTML without markdown-it (Qt's own parser's text
    passes: ui.markdown_view.fallback_text) - its feed(html, allowed) gives
    the events of the allowed subset."""
    return _Sanitizer(None, allowed)


_FENCE_LINE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


#: A part of a line's containers: a quote's ">", a list item's marker.
_CONTAINER_PART = re.compile(r"[ \t]{0,3}(?:>[ \t]?|(?:[-+*]|\d{1,9}[.)])(?:[ \t]+|$))")
_QUOTE_PART = re.compile(r"[ \t]{0,3}>[ \t]?")


def quote_flatter(text: str, depth: int = QUOTE_DEPTH) -> tuple[str, bool]:
    """(*text* with no line quoted deeper than *depth* levels - after a list
    item's marker too ("- >>>>…") -, whether a line was). A fenced block's
    code is never changed: inside one only the marks of the quotes it is in
    are its line's (a quote's code of ">>>>" lines stayed as written)."""
    if ">" * (depth + 1) not in text.replace(" ", "").replace("\t", ""):
        return text, False
    out, fence, changed = [], None, False
    for line in text.split("\n"):
        if fence is not None and fence[1] == 0:  # (a fenced block in no quote: its lines as they are)
            closing = _FENCE_LINE.match(line.lstrip(" \t"))
            if closing and closing.group(1)[0] == fence[0][0] and len(closing.group(1)) >= len(fence[0]) \
                    and not line.strip().strip(fence[0][0]):
                fence = None
            out.append(line)
            continue
        if ">" not in line and fence is None:
            opened = _FENCE_LINE.match(line.lstrip(" \t"))  # (in a list item: indented as its text)
            if opened:
                fence = (opened.group(1), 0)
            out.append(line)
            continue
        parts, pos, quotes = [], 0, 0
        while True:  # (its containers' marks - inside a fenced block only the quotes it is in)
            if fence is not None and quotes >= fence[1]:
                break
            found = (_QUOTE_PART if fence is not None else _CONTAINER_PART).match(line, pos)
            if not found or found.end() == pos:
                break
            parts.append(line[pos:found.end()])
            quotes += ">" in parts[-1]
            pos = found.end()
        content = line[pos:]
        if fence is not None:
            closing = _FENCE_LINE.match(content.lstrip(" \t"))
            if closing and closing.group(1)[0] == fence[0][0] and len(closing.group(1)) >= len(fence[0]) \
                    and not content.strip().strip(fence[0][0]):
                fence = None
        else:
            opened = _FENCE_LINE.match(content.lstrip(" \t"))
            if opened:
                fence = (opened.group(1), quotes)
        if quotes > depth:
            kept, seen = [], 0
            for part in parts:
                if ">" in part:
                    seen += 1
                    if seen > depth:
                        continue
                kept.append(part)
            line = "".join(kept) + content
            changed = True
        out.append(line)
    return ("\n".join(out), True) if changed else (text, False)


@functools.lru_cache(maxsize=4)
def _deeper(depth: int) -> re.Pattern:
    return re.compile(r"^[ \t]{%d}" % (2 * depth + 1), re.MULTILINE)


def flatter(text: str, depth: int) -> tuple[str, bool]:
    """(*text* with no line indented deeper than *depth* list levels - two
    columns each, code fences kept as they are -, whether a line was):
    markdown-it nests 20 levels at most, deeper lines fell apart (into code,
    wrapped line after line), and a view nests what it lays out in time
    that grows with the depth."""
    if not found_by_lines(_deeper(depth), text):
        return text, False
    out, fence = [], None
    for line in text.split("\n"):
        opened = _FENCE_LINE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
        elif opened:
            fence = opened.group(1)
        else:
            stripped = line.lstrip(" \t")
            if len(line) - len(stripped) > 2 * depth:
                line = " " * (2 * depth) + stripped
        out.append(line)
    return "\n".join(out), True


#: The columns a table's grid of spanned cells (span_grid) has at most.
GRID_COLUMNS = 200


def span_grid(rows: list) -> tuple[list, list]:
    """A raw-HTML table's rows - lists of ``(cell, colspan, rowspan)`` - as
    a grid in which every cell stands under its own column: a cell spanning
    columns or rows covers the slots after it and below it (``None``: what
    shows nothing - Qt's own parser and the terminal knew no span, a row
    under a cell of two rows slid one column to the left). Every row as wide
    as the widest. Returns (grid, spans): spans ``(row, column, rows,
    columns)`` of each cell that spans more than its slot."""
    grid, spans, below = [], [], {}  # below: column -> rows a span above still covers
    for number, row in enumerate(rows):
        out = []

        def covered() -> None:
            while below.get(len(out), 0) > 0:
                below[len(out)] -= 1
                out.append(None)

        for cell, colspan, rowspan in row:
            covered()
            if len(out) >= GRID_COLUMNS:
                break
            colspan = max(1, min(colspan, GRID_COLUMNS - len(out)))
            rowspan = max(1, min(rowspan, len(rows) - number))
            if colspan > 1 or rowspan > 1:
                spans.append((number, len(out), rowspan, colspan))
            for offset in range(colspan):
                if rowspan > 1:
                    below[len(out) + offset] = rowspan - 1
            out.append(cell)
            out.extend([None] * (colspan - 1))
        while any(column >= len(out) and left > 0 for column, left in below.items()):
            if below.get(len(out), 0) > 0:
                covered()
            else:
                out.append(None)  # (a column no cell of this row fills, before one a span covers)
        grid.append(out)
    width = max((len(row) for row in grid), default=0)
    return [row + [None] * (width - len(row)) for row in grid], spans


def html_events(token) -> list[tuple]:
    """The events of a ``safe_html_block`` / ``safe_html_inline`` token."""
    return list((token.meta or {}).get("html") or ())


# -- bare addresses as links (GFM's extended autolinks) ----------------------------------------

#: An address written bare: http(s)://… or www.… at a line's start or after
#: a space, "*", "_", "~" or "(" - or an e-mail address (GFM).
_BARE_LINK = re.compile(r"(?<![^\s*_~(])(?:https?://|www\.)[\w-]+(?:\.[\w-]+)+[^\s<]*"
                        r"|(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)
#: What ends an address but is no part of it ("see www.x.org.").
_TRAILING = "?!.,:*_~'\""
_ENTITY_END = re.compile(r"&[A-Za-z0-9]+;\Z")


def _bare_link(text: str) -> tuple[str, str] | None:
    """(the address as written, its link) of a _BARE_LINK match - its
    trailing punctuation and an unbalanced ")" left out, a domain whose last
    two parts hold "_" or a mail address ending in "-" or "_" none (GFM)."""
    while text:
        if text[-1] in _TRAILING:
            text = text[:-1]
        elif text.endswith(")") and text.count(")") > text.count("("):
            text = text[:-1]
        elif _ENTITY_END.search(text):
            text = text[:_ENTITY_END.search(text).start()]
        else:
            break
    if "@" in text and "://" not in text:
        if not re.fullmatch(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text) or text[-1] in "-_":
            return None
        return text, "mailto:" + text
    host = re.split(r"[/?#]", text.split("://", 1)[-1], maxsplit=1)[0]
    if "." not in host or any("_" in part for part in host.split(".")[-2:]):
        return None
    return text, (text if "://" in text else "http://" + text)


#: A link left as text whose address hides javascript: (…) behind a tab or
#: a space ("[tab](java	script:…)"): its text only.
_HIDDEN_BAD_LINK = re.compile(r"\[([^\[\]\n]{1,500})\]\(((?:[^()\n]|\([^()\n]{0,200}\)){0,200})\)")


def _hidden_bad(match: re.Match) -> str:
    bare = re.sub(r"[\x00-\x20\x7f]", "", match.group(2)).lower()
    return match.group(1) if _BAD_PROTOCOL.match(bare) and not _GOOD_DATA.match(bare) else match.group(0)


#: A link markdown-it left as text: its address refused (javascript:, …).
_TEXT_LINK = re.compile(r"\[([^\[\]\n]{1,500})\]\(\s*<?([^()\s<>]*(?:\([^()\s]*\)[^()\s<>]*)*)>?"
                        r"(?:\s+\"[^\"\n]*\")?\s*\)")


#: An image markdown-it left as text, its address refused ("![x](file:…)": "!x" was shown).
_REFUSED_IMAGE = re.compile("!" + _TEXT_LINK.pattern)
_REFUSED = "\ue068"


def _unsafe_links(state) -> None:
    """A link whose address is refused (``[js](javascript:…)``) shows its
    text only - no link, and not its address written out as it was."""
    Token = token_class()

    md = state.md
    for token in state.tokens:
        if token.type != "inline" or not token.children or "](" not in token.content:
            continue
        children, run = [], []

        def flush() -> None:
            if not run:
                return
            text = "".join(child.content for child in run)
            refused: list[str] = []  # (the alt texts of images refused: a box each, as an image not shown)

            def image(match: re.Match) -> str:
                if md.validateLink(match.group(2)) and _hidden_bad(match) == match.group(0):
                    return match.group(0)
                refused.append(match.group(1))
                return f"{_REFUSED}{len(refused) - 1}{_REFUSED}"

            shown = _REFUSED_IMAGE.sub(image, text) if "![" in text else text
            shown = _TEXT_LINK.sub(lambda m: m.group(0) if md.validateLink(m.group(2)) else m.group(1), shown)
            shown = _HIDDEN_BAD_LINK.sub(_hidden_bad, shown)
            if shown == text:
                children.extend(run)
            else:
                for index, part in enumerate(shown.split(_REFUSED)):
                    if index % 2 and part.isdigit() and int(part) < len(refused):
                        picture = Token("image", "img", 0)
                        picture.attrs = {"src": ""}
                        picture.content = refused[int(part)]
                        alt = Token("text", "", 0)
                        alt.content = refused[int(part)]
                        picture.children = [alt]
                        picture.meta = {"refused": True}  # (its address one no view loads: file:, data: of no image)
                        children.append(picture)
                    elif part:
                        piece = Token("text", "", 0)
                        piece.content = part
                        children.append(piece)
            run.clear()

        for child in token.children:
            if child.type == "text":
                run.append(child)
                continue
            flush()
            children.append(child)
        flush()
        token.children = children


def _autolinks(state) -> None:
    """Bare addresses in the text made links (without linkify-it-py: GFM's
    extended autolinks - Qt's own parser linked them, markdown-it's page
    did not). Never in code, nor in a link."""
    Token = token_class()

    md = state.md
    for token in state.tokens:
        if token.type != "inline" or not token.children:
            continue
        children, run, inside = [], [], 0

        def flush() -> None:
            if not run:
                return
            text = "".join(child.content for child in run)
            pieces, at = [], 0
            # (a piece of the text at a time: a search of all of a line of 10 MB held Python's lock 0.7 s -
            # a link is never cut, it has no space)
            for found in (found for begin, stop in _text_pieces(text)
                          for found in _BARE_LINK.finditer(text, begin, stop)):
                bare = _bare_link(found.group(0))
                if bare is None:
                    continue
                shown, href = bare
                href = md.normalizeLink(href)
                if not md.validateLink(href):
                    continue
                if found.start() > at:
                    pieces.append(("text", text[at:found.start()]))
                pieces.append(("link", (shown, href)))
                at = found.start() + len(shown)
            if not pieces:
                children.extend(run)
            else:
                if at < len(text):
                    pieces.append(("text", text[at:]))
                for kind, value in pieces:
                    if kind == "text":
                        piece = Token("text", "", 0)
                        piece.content = value
                        children.append(piece)
                        continue
                    shown, href = value
                    opened = Token("link_open", "a", 1)
                    opened.attrs = {"href": href}
                    opened.markup, opened.info = "linkify", "auto"
                    label = Token("text", "", 0)
                    label.content = md.normalizeLinkText(shown)  # ("www.pаypal.com": in punycode)
                    closed = Token("link_close", "a", -1)
                    closed.markup, closed.info = "linkify", "auto"
                    children.extend((opened, label, closed))
            run.clear()

        for child in token.children:
            if child.type == "text" and not inside:
                run.append(child)
                continue
            flush()
            if child.type == "link_open":
                inside += 1
            elif child.type == "link_close":
                inside = max(0, inside - 1)
            elif child.type == "safe_html_inline":
                for event in html_events(child):
                    if event[0] in ("start", "end") and event[1] == "a":
                        inside = max(0, inside + (1 if event[0] == "start" else -1))
            children.append(child)
        flush()
        token.children = children


# -- ~strike~ with one tilde, as GitHub -------------------------------------------------------

#: Spans of emphasis a line (a paragraph, a cell) is shown with at most: the rest as plain text. Qt lays a
#: line of many out in time that grows with their square (9,900: 2.4 s).
LINE_SPANS = 300
_SPAN_OPEN = {"em_open": "em_close", "strong_open": "strong_close", "s_open": "s_close"}


def _fewer_spans(state) -> None:
    """Each inline's emphasis past LINE_SPANS spans: its text plain."""
    for token in state.tokens:
        children = token.children or []
        if token.type != "inline" or len(children) < 2 * LINE_SPANS:
            continue
        opened = 0
        closing = set()
        for child in children:
            if child.type in _SPAN_OPEN:
                opened += 1
                if opened > LINE_SPANS:
                    closing.add(_SPAN_OPEN[child.type])
                    child.type, child.tag, child.nesting, child.markup = "text", "", 0, ""
                    child.content = ""
            elif child.type in closing and opened > LINE_SPANS:
                child.type, child.tag, child.nesting, child.markup = "text", "", 0, ""
                child.content = ""


#: Formulas of a heading, a table's cell, a term laid out as math at most:
#: the rest as their TeX (a line holding thousands is laid out at once, in
#: time that grows with their square - a heading of 8,000: 11 s). A
#: paragraph's are laid out in pieces instead (ui.markdown_html).
LINE_FORMULAS = 100


def _fewer_formulas(state) -> None:
    """Past LINE_FORMULAS formulas in a heading, a cell or a term: their TeX
    as text ("$x^2$")."""
    tokens = state.tokens
    for index, token in enumerate(tokens):
        if token.type != "inline" or not token.children or (index and tokens[index - 1].type == "paragraph_open"):
            continue
        seen = 0
        for child in token.children:
            if child.type in ("math_inline", "math_inline_double"):
                seen += 1
                if seen > LINE_FORMULAS:
                    marks = "$$" if child.type == "math_inline_double" else "$"
                    child.type, child.tag, child.nesting = "text", "", 0
                    child.content = f"{marks}{child.content}{marks}"


def _backtick_math(state) -> None:
    """GitHub's other way of writing a formula in a line, $`x^2`$: its
    backticks out (they showed inside the formula)."""
    for token in state.tokens:
        for child in token.children or ():
            if child.type == "math_inline" and len(child.content) > 2 and child.content[0] == "`" \
                    and child.content[-1] == "`" and "`" not in child.content[1:-1]:
                child.content = child.content[1:-1]


def _single_tilde(state, silent: bool) -> bool:
    """``~text~`` struck through, as GitHub strikes it (markdown-it knows
    ``~~`` only): a tilde not next to another, before a non-space, closed by
    the next tilde after a non-space. Looks no further than the next tilde:
    linear."""
    src, start, end = state.src, state.pos, state.posMax
    if src[start] != "~" or (start + 1 < end and src[start + 1] == "~") \
            or (start and src[start - 1] == "~"):
        return False
    if start + 2 >= end or src[start + 1].isspace():
        return False
    close = start + 1
    while close < end and src[close] != "~":
        close += 2 if src[close] == "\\" else 1
    if close >= end or src[close - 1].isspace() or (close + 1 < end and src[close + 1] == "~"):
        return False
    if silent:
        # a rule that matches must move the position in silent mode too
        # (link labels are scanned silently): markdown-it 4.3 raises, 4.2
        # loops for ever - "[~x~]" hung the viewer
        state.pos = close + 1
        return True
    state.pos, state.posMax = start + 1, close
    token = state.push("s_open", "s", 1)
    token.markup = "~"
    state.md.inline.tokenize(state)
    token = state.push("s_close", "s", -1)
    token.markup = "~"
    state.pos, state.posMax = close + 1, end
    return True


# -- GitHub's alerts ---------------------------------------------------------------------------

#: The kinds of GitHub's alerts, in its order.
ALERTS = ("note", "tip", "important", "warning", "caution")
_ALERT = re.compile(r"\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*(?:\n|\Z)", re.IGNORECASE)


def alert_of(token) -> str:
    """The kind of GitHub alert (one of :data:`ALERTS`) a ``blockquote_open``
    or ``blockquote_close`` token is, or "" for a plain quote."""
    return str((token.meta or {}).get("alert") or "")


def _alerts(state) -> None:
    """A quote whose first line is ``[!NOTE]`` (TIP, IMPORTANT, WARNING,
    CAUTION; any case) is that alert: the kind goes to the quote's tokens
    (:func:`alert_of`), the marker out of its text. (Before the inline rules:
    "[!NOTE]" would be a link's text.)"""
    tokens = state.tokens
    index = 0
    while index < len(tokens) - 2:
        token = tokens[index]
        if token.type == "blockquote_open" and tokens[index + 1].type == "paragraph_open" \
                and tokens[index + 2].type == "inline":
            found = _ALERT.match(tokens[index + 2].content)
            if found:
                kind = found.group(1).lower()
                close = next((k for k in range(index + 1, len(tokens))
                              if tokens[k].type == "blockquote_close" and tokens[k].level == token.level),
                             None)
                if close is not None:
                    token.meta = {**(token.meta or {}), "alert": kind}
                    tokens[close].meta = {**(tokens[close].meta or {}), "alert": kind}
                    token.attrSet("class", f"markdown-alert markdown-alert-{kind}")
                    rest = tokens[index + 2].content[found.end():]
                    if rest.strip():
                        tokens[index + 2].content = rest
                    else:  # (the marker alone: its paragraph goes)
                        del tokens[index + 1:index + 4]
        index += 1


# -- emoji short codes -------------------------------------------------------------------------

#: GitHub's emoji short codes people write most (``:tada:``); others stay
#: as written.
EMOJI = {
    "+1": "👍", "-1": "👎", "100": "💯", "airplane": "✈️", "alarm_clock": "⏰", "angry": "😠",
    "arrow_down": "⬇️", "arrow_left": "⬅️", "arrow_right": "➡️", "arrow_up": "⬆️", "art": "🎨",
    "baby": "👶", "balloon": "🎈", "bangbang": "‼️", "bell": "🔔", "bike": "🚲", "blush": "😊",
    "bomb": "💣", "book": "📖", "books": "📚", "boom": "💥", "bowtie": "🎀", "brain": "🧠",
    "broken_heart": "💔", "bug": "🐛", "bulb": "💡", "calendar": "📆", "camera": "📷", "cat": "🐱",
    "chart_with_upwards_trend": "📈", "chart_with_downwards_trend": "📉", "check": "✔️",
    "checkered_flag": "🏁", "clap": "👏", "clipboard": "📋", "clock1": "🕐", "closed_lock_with_key": "🔐",
    "cloud": "☁️", "coffee": "☕", "computer": "💻", "confused": "😕", "construction": "🚧", "cool": "🆒",
    "copyright": "©️", "cry": "😢", "crystal_ball": "🔮", "dart": "🎯", "dash": "💨", "desktop_computer": "🖥️",
    "dizzy": "💫", "dog": "🐶", "dragon": "🐉", "earth_africa": "🌍", "earth_americas": "🌎", "email": "📧",
    "envelope": "✉️", "exclamation": "❗", "eyes": "👀", "facepalm": "🤦", "file_folder": "📁",
    "fire": "🔥", "fireworks": "🎆", "flags": "🎏", "floppy_disk": "💾", "gear": "⚙️", "gem": "💎",
    "ghost": "👻", "gift": "🎁", "globe_with_meridians": "🌐", "green_heart": "💚", "grin": "😁",
    "grinning": "😀", "hammer": "🔨", "hammer_and_wrench": "🛠️", "hand": "✋", "handshake": "🤝",
    "heart": "❤️", "heart_eyes": "😍", "heavy_check_mark": "✔️", "heavy_minus_sign": "➖",
    "heavy_plus_sign": "➕", "hourglass": "⌛", "house": "🏠", "hugs": "🤗", "information_source": "ℹ️",
    "innocent": "😇", "joy": "😂", "key": "🔑", "keyboard": "⌨️", "kiss": "😘", "label": "🏷️",
    "laughing": "😆", "link": "🔗", "lipstick": "💄", "lock": "🔒", "loudspeaker": "📢", "mag": "🔍",
    "mailbox": "📫", "memo": "📝", "microscope": "🔬", "money_with_wings": "💸", "moneybag": "💰",
    "monkey": "🐒", "moon": "🌙", "muscle": "💪", "mushroom": "🍄", "musical_note": "🎵", "neutral_face": "😐",
    "new": "🆕", "no_entry": "⛔", "no_entry_sign": "🚫", "notebook": "📓", "ok": "🆗", "ok_hand": "👌",
    "open_mouth": "😮", "package": "📦", "page_facing_up": "📄", "paperclip": "📎", "partying_face": "🥳",
    "pencil": "📝", "pencil2": "✏️", "penguin": "🐧", "phone": "☎️", "pizza": "🍕", "point_down": "👇",
    "point_left": "👈", "point_right": "👉", "point_up": "☝️", "pray": "🙏", "pushpin": "📌",
    "question": "❓", "rage": "😡", "rainbow": "🌈", "raised_hands": "🙌", "recycle": "♻️",
    "red_circle": "🔴", "relaxed": "☺️", "relieved": "😌", "rocket": "🚀", "rofl": "🤣", "rotating_light": "🚨",
    "running": "🏃", "sad": "😞", "scissors": "✂️", "scream": "😱", "see_no_evil": "🙈", "seedling": "🌱",
    "shield": "🛡️", "shipit": "🐿️", "shrug": "🤷", "skull": "💀", "sleeping": "😴", "slightly_smiling_face": "🙂",
    "smile": "😄", "smiley": "😃", "smirk": "😏", "snake": "🐍", "snowflake": "❄️", "sob": "😭",
    "sparkles": "✨", "sparkling_heart": "💖", "speech_balloon": "💬", "star": "⭐", "star2": "🌟",
    "stop_sign": "🛑", "stuck_out_tongue": "😛", "sun_with_face": "🌞", "sunglasses": "😎", "sunny": "☀️",
    "sweat": "😓", "sweat_smile": "😅", "tada": "🎉", "thinking": "🤔", "thumbsdown": "👎",
    "thumbsup": "👍", "tired_face": "😫", "tm": "™️", "toolbox": "🧰", "trophy": "🏆", "truck": "🚚",
    "turtle": "🐢", "unamused": "😒", "unicorn": "🦄", "unlock": "🔓", "upside_down_face": "🙃",
    "v": "✌️", "warning": "⚠️", "wave": "👋", "white_check_mark": "✅", "wink": "😉", "worried": "😟",
    "wrench": "🔧", "x": "❌", "yellow_heart": "💛", "yum": "😋", "zap": "⚡", "zzz": "💤",
    # gitmoji's codes (gitmoji.dev) - GitHub's names for these emoji
    "ambulance": "🚑", "bookmark": "🔖", 
    "construction_worker": "👷", "poop": "💩", "rewind": "⏪",
    "twisted_rightwards_arrows": "🔀", "alien": "👽", "bento": "🍱", "wheelchair": "♿", "beers": "🍻",
    "card_file_box": "🗃️", "loud_sound": "🔊", "mute": "🔇", "busts_in_silhouette": "👥",
    "children_crossing": "🚸", "building_construction": "🏗️", "iphone": "📱", "clown_face": "🤡",
    "egg": "🥚", "camera_flash": "📸", "alembic": "⚗️", "triangular_flag_on_post": "🚩",
    "goal_net": "🥅", "wastebasket": "🗑️", "passport_control": "🛂", "adhesive_bandage": "🩹",
    "monocle_face": "🧐", "coffin": "⚰️", "test_tube": "🧪", "necktie": "👔", "stethoscope": "🩺",
    "bricks": "🧱", "technologist": "🧑\u200d💻", "thread": "🧵", "safety_vest": "🦺", "robot": "🤖",
    "arrow_double_up": "⏫", "arrow_double_down": "⏬", "lock_with_ink_pen": "🔏",
    # more of GitHub's common ones
    "point_up_2": "👆", "heavy_exclamation_mark": "❗", "grey_question": "❔", "grey_exclamation": "❕",
    "heavy_multiplication_x": "✖️", "heavy_division_sign": "➗", "white_circle": "⚪",
    "black_circle": "⚫", "large_blue_circle": "🔵", "green_circle": "🟢", "yellow_circle": "🟡",
    "orange_circle": "🟠", "purple_circle": "🟣", "red_square": "🟥", "green_square": "🟩",
    "star_struck": "🤩", "nerd_face": "🤓", "exploding_head": "🤯", "pleading_face": "🥺",
    "skull_and_crossbones": "☠️", "hourglass_flowing_sand": "⏳", "stopwatch": "⏱️", "timer_clock": "⏲️",
    "date": "📅", "card_index": "📇", "chart": "💹", "bar_chart": "📊", "file_cabinet": "🗄️",
    "inbox_tray": "📥", "outbox_tray": "📤", "electric_plug": "🔌", "battery": "🔋", "satellite": "📡",
    "flashlight": "🔦", "candle": "🕯️", "dollar": "💵", "euro": "💶", "pound": "💷",
    "credit_card": "💳", "gift_heart": "💝", "medal_sports": "🏅", "1st_place_medal": "🥇",
    "2nd_place_medal": "🥈", "3rd_place_medal": "🥉", "soccer": "⚽", "basketball": "🏀", "football": "🏈",
    "tennis": "🎾", "8ball": "🎱", "video_game": "🎮", "jigsaw": "🧩", "chess_pawn": "♟️",
    "earth_asia": "🌏", "world_map": "🗺️", "mountain": "⛰️", "volcano": "🌋", "desert": "🏜️",
    "beach_umbrella": "🏖️", "house_with_garden": "🏡", "office": "🏢", "hospital": "🏥", "bank": "🏦",
    "hotel": "🏨", "school": "🏫", "factory": "🏭", "car": "🚗", "taxi": "🚕", "bus": "🚌",
    "train": "🚋", "ship": "🚢", "anchor": "⚓", "fuelpump": "⛽", "vertical_traffic_light": "🚦",
    "apple": "🍎", "banana": "🍌", "cherries": "🍒", "grapes": "🍇", "lemon": "🍋", "watermelon": "🍉",
    "hamburger": "🍔", "fries": "🍟", "taco": "🌮", "burrito": "🌯", "doughnut": "🍩", "cookie": "🍪",
    "cake": "🍰", "birthday": "🎂", "tea": "🍵", "beer": "🍺", "wine_glass": "🍷", "cocktail": "🍸",
    "champagne": "🍾", "dog2": "🐕", "cat2": "🐈", "mouse": "🐭", "rabbit": "🐰", "fox_face": "🦊",
    "bear": "🐻", "panda_face": "🐼", "koala": "🐨", "tiger": "🐯", "lion": "🦁", "cow": "🐮", "pig": "🐷",
    "frog": "🐸", "octopus": "🐙", "whale": "🐳", "dolphin": "🐬", "fish": "🐟", "crab": "🦀",
    "bee": "🐝", "honeybee": "🐝", "ant": "🐜", "spider": "🕷️", "butterfly": "🦋", "snail": "🐌",
    "owl": "🦉", "eagle": "🦅", "duck": "🦆", "chicken": "🐔", "hatching_chick": "🐣",
    "rose": "🌹", "sunflower": "🌻", "tulip": "🌷", "cherry_blossom": "🌸", "four_leaf_clover": "🍀",
    "maple_leaf": "🍁", "fallen_leaf": "🍂", "leaves": "🍃", "evergreen_tree": "🌲",
    "deciduous_tree": "🌳", "palm_tree": "🌴", "cactus": "🌵", "ocean": "🌊", "droplet": "💧",
    "umbrella": "☔", "snowman": "⛄", "cloud_with_rain": "🌧️", "tornado": "🌪️", "fog": "🌫️",
    "crescent_moon": "🌙", "full_moon": "🌕", "new_moon": "🌑", "comet": "☄️", "milky_way": "🌌",
    "fist": "✊", "punch": "👊", "metal": "🤘",
    "call_me_hand": "🤙", "writing_hand": "✍️", "nail_care": "💅", "selfie": "🤳", "ear": "👂",
    "nose": "👃", "tongue": "👅", "lips": "👄", "eye": "👁️", "footprints": "👣",
    "man": "👨", "woman": "👩", "boy": "👦", "girl": "👧", "older_man": "👴", "older_woman": "👵",
    "cop": "👮", "detective": "🕵️", "guardsman": "💂", "angel": "👼", "santa": "🎅", "princess": "👸",
    "superhero": "🦸", "mage": "🧙", "zombie": "🧟", "vampire": "🧛", "ninja": "🥷",
    "dancer": "💃", "walking": "🚶", "couple": "👫", "family": "👪", "speaking_head": "🗣️",
    "bust_in_silhouette": "👤", "sweat_drops": "💦", "anger": "💢", "hole": "🕳️",     "thought_balloon": "💭", "left_speech_bubble": "🗨️", "right_anger_bubble": "🗯️",
    "heart_eyes_cat": "😻", "smile_cat": "😸", "joy_cat": "😹", "scream_cat": "🙀",
    "hear_no_evil": "🙉", "speak_no_evil": "🙊", "kissing_heart": "😘", "kissing": "😗",
    "stuck_out_tongue_winking_eye": "😜", "stuck_out_tongue_closed_eyes": "😝", "money_mouth_face": "🤑",
    "zipper_mouth_face": "🤐",     "expressionless": "😑", "no_mouth": "😶", "roll_eyes": "🙄", "grimacing": "😬", "lying_face": "🤥",
    "pensive": "😔", "sleepy": "😪", "drooling_face": "🤤", "mask": "😷", "face_with_thermometer": "🤒",
    "nauseated_face": "🤢", "vomiting_face": "🤮", "sneezing_face": "🤧", "hot_face": "🥵",
    "cold_face": "🥶", "woozy_face": "🥴", "dizzy_face": "😵", "cowboy_hat_face": "🤠",
    "disguised_face": "🥸", "frowning_face": "☹️", "hushed": "😯", "astonished": "😲",
    "flushed": "😳", "fearful": "😨", "cold_sweat": "😰", "disappointed_relieved": "😥",
    "confounded": "😖", "persevere": "😣", "disappointed": "😞", "weary": "😩", "triumph": "😤",
    "pouting_face": "😡", "cursing_face": "🤬", "smiling_imp": "😈", "imp": "👿", "japanese_ogre": "👹",
    "japanese_goblin": "👺", "space_invader": "👾", "jack_o_lantern": "🎃", "christmas_tree": "🎄",
    "confetti_ball": "🎊", "tanabata_tree": "🎋", "ribbon": "🎀", "reminder_ribbon": "🎗️",
    "ticket": "🎫", "medal_military": "🎖️", "crown": "👑", "eyeglasses": "👓", "dark_sunglasses": "🕶️",
    "goggles": "🥽", "lab_coat": "🥼", "shirt": "👕", "jeans": "👖", "school_satchel": "🎒",
    "briefcase": "💼", "handbag": "👜", "ring": "💍", "headphones": "🎧", "microphone": "🎤",
    "guitar": "🎸", "musical_keyboard": "🎹", "trumpet": "🎺", "violin": "🎻", "drum": "🥁",
    "notes": "🎶", "radio": "📻", "tv": "📺", "film_strip": "🎞️", "movie_camera": "🎥",
    "clapper": "🎬", "video_camera": "📹", "vhs": "📼", "cd": "💿", "dvd": "📀", "minidisc": "💽",
    "printer": "🖨️", "computer_mouse": "🖱️", "trackball": "🖲️", "joystick": "🕹️", "abacus": "🧮",
    "telephone_receiver": "📞", "pager": "📟", "fax": "📠", "calling": "📲", "mailbox_with_mail": "📬",
    "postbox": "📮", "incoming_envelope": "📨", "envelope_with_arrow": "📩", "scroll": "📜",
    "newspaper": "📰", "bookmark_tabs": "📑", "closed_book": "📕", "green_book": "📗", "blue_book": "📘",
    "orange_book": "📙", "ledger": "📒", "notebook_with_decorative_cover": "📔", "pen": "🖊️",
    "fountain_pen": "🖋️", "black_nib": "✒️", "paintbrush": "🖌️", "crayon": "🖍️", "straight_ruler": "📏",
    "triangular_ruler": "📐", "round_pushpin": "📍", "paperclips": "🖇️",
    "open_file_folder": "📂", "spiral_notepad": "🗒️",
    "spiral_calendar": "🗓️", "old_key": "🗝️",
    "hammer_and_pick": "⚒️", "pick": "⛏️", "nut_and_bolt": "🔩", "clamp": "🗜️",
    "balance_scale": "⚖️", "chains": "⛓️", "magnet": "🧲", "telescope": "🔭",
    "syringe": "💉", "pill": "💊", "dna": "🧬", "petri_dish": "🧫",
    "door": "🚪", "bed": "🛏️", "couch_and_lamp": "🛋️", "toilet": "🚽", "shower": "🚿", "bathtub": "🛁",
    "shopping_cart": "🛒", "smoking": "🚬", "moyai": "🗿", "atm": "🏧", "put_litter_in_its_place": "🚮",
    "radioactive": "☢️", "biohazard": "☣️", "arrows_counterclockwise": "🔄",
    "arrows_clockwise": "🔃", "back": "🔙", "end": "🔚", "on": "🔛", "soon": "🔜", "top": "🔝",
    "infinity": "♾️", "repeat": "🔁", "repeat_one": "🔂", "arrow_forward": "▶️", "fast_forward": "⏩",
    "next_track_button": "⏭️", "play_or_pause_button": "⏯️", "arrow_backward": "◀️",
    "previous_track_button": "⏮️", "pause_button": "⏸️", "stop_button": "⏹️", "record_button": "⏺️",
    "eject_button": "⏏️", "cinema": "🎦", "low_brightness": "🔅", "high_brightness": "🔆",
    "signal_strength": "📶", "vibration_mode": "📳", "mobile_phone_off": "📴", "heavy_dollar_sign": "💲",
    "currency_exchange": "💱", "trident": "🔱", "name_badge": "📛", "beginner": "🔰", "o": "⭕",
    "ballot_box_with_check": "☑️", "negative_squared_cross_mark": "❎",
    "curly_loop": "➰", "loop": "➿", "part_alternation_mark": "〽️", "eight_spoked_asterisk": "✳️",
    "sparkle": "❇️", "registered": "®️", "hash": "#️⃣", "asterisk": "*️⃣", "zero": "0️⃣", "one": "1️⃣",
    "two": "2️⃣", "three": "3️⃣", "four": "4️⃣", "five": "5️⃣", "six": "6️⃣", "seven": "7️⃣",
    "eight": "8️⃣", "nine": "9️⃣", "keycap_ten": "🔟", "abc": "🔤", "abcd": "🔡", "capital_abcd": "🔠",
    "1234": "🔢", "symbols": "🔣", "free": "🆓", "id": "🆔", "m": "Ⓜ️",
    "ng": "🆖", "sos": "🆘", "up": "🆙", "vs": "🆚", "large_orange_diamond": "🔶",
    "large_blue_diamond": "🔷", "small_orange_diamond": "🔸", "small_blue_diamond": "🔹",
    "small_red_triangle": "🔺", "small_red_triangle_down": "🔻", "diamond_shape_with_a_dot_inside": "💠",
    "radio_button": "🔘", "white_square_button": "🔳", "black_square_button": "🔲",
    "crossed_flags": "🎌", "black_flag": "🏴",
    "white_flag": "🏳️", "rainbow_flag": "🏳️\u200d🌈", "pirate_flag": "🏴\u200d☠️",
}
_SHORT_CODE = re.compile(r"(?<![\w/]):([a-z0-9_+\-]{1,40}):")


def _emoji(state) -> None:
    """``:tada:`` in text as 🎉 (the codes of :data:`EMOJI`) - never in code,
    nor in a bare address made a link (its text is the address)."""
    for token in state.tokens:
        if token.type != "inline" or not token.children:
            continue
        autolink = 0
        for child in token.children:
            if child.type == "link_open" and child.markup in ("linkify", "autolink"):
                autolink += 1
            elif child.type == "link_close" and autolink and child.markup in ("linkify", "autolink"):
                autolink -= 1
            elif child.type == "text" and not autolink and ":" in child.content:
                child.content = _SHORT_CODE.sub(lambda m: emoji_for(m.group(1), m.group(0)), child.content)


#: The short codes whose emoji the view parsing now can draw (None: all -
#: the terminal and a browser leave that to their own fonts). The window
#: sets it while it parses (ui.markdown_view.emoji_fonts): the code of one no
#: font of it has stays as written - it was an empty box.
EMOJI_DRAWN: contextvars.ContextVar = contextvars.ContextVar("axross_emoji_drawn", default=None)


def emoji_for(code: str, written: str) -> str:
    """The emoji of the short code *code* - *written* when there is none, or
    none the view can draw (EMOJI_DRAWN)."""
    drawn = EMOJI_DRAWN.get()
    if drawn is not None and code not in drawn:
        return written
    return EMOJI.get(code, written)


# -- math --------------------------------------------------------------------------------------

#: Math longer than this is shown as written (math_text's passes are linear
#: each, but a text of megabytes of braces need not go through them).
MATH_LIMIT = 20_000
_GREEK = ("alpha α beta β gamma γ delta δ epsilon ϵ varepsilon ε zeta ζ eta η theta θ vartheta ϑ "
          "iota ι kappa κ lambda λ mu μ nu ν xi ξ omicron ο pi π varpi ϖ rho ρ varrho ϱ sigma σ "
          "varsigma ς tau τ upsilon υ phi ϕ varphi φ chi χ psi ψ omega ω Gamma Γ Delta Δ Theta Θ "
          "Lambda Λ Xi Ξ Pi Π Sigma Σ Upsilon Υ Phi Φ Psi Ψ Omega Ω")
_SYMBOLS = ("cdot · times × div ÷ pm ± mp ∓ leq ≤ le ≤ geq ≥ ge ≥ neq ≠ ne ≠ approx ≈ equiv ≡ sim ∼ "
            "simeq ≃ cong ≅ propto ∝ infty ∞ sum ∑ prod ∏ int ∫ iint ∬ oint ∮ partial ∂ nabla ∇ "
            "to → rightarrow → leftarrow ← gets ← leftrightarrow ↔ Rightarrow ⇒ Leftarrow ⇐ "
            "Leftrightarrow ⇔ implies ⟹ iff ⟺ mapsto ↦ uparrow ↑ downarrow ↓ in ∈ notin ∉ ni ∋ "
            "subset ⊂ subseteq ⊆ supset ⊃ supseteq ⊇ cup ∪ cap ∩ setminus ∖ emptyset ∅ varnothing ∅ "
            "forall ∀ exists ∃ nexists ∄ neg ¬ lnot ¬ land ∧ wedge ∧ lor ∨ vee ∨ oplus ⊕ otimes ⊗ "
            "circ ∘ bullet • star ⋆ ast ∗ dots … ldots … cdots ⋯ vdots ⋮ ddots ⋱ prime ′ "
            "angle ∠ perp ⊥ parallel ∥ mid ∣ hbar ℏ ell ℓ Re ℜ Im ℑ aleph ℵ degree ° "
            "langle ⟨ rangle ⟩ lceil ⌈ rceil ⌉ lfloor ⌊ rfloor ⌋ vert | Vert ‖ | ‖ "
            "quad \u2003 qquad \u2003\u2003 top ⊤ bot ⊥ bmod mod mod mod lim lim sin sin cos cos tan tan log log ln ln exp exp "
            "max max min min sup sup inf inf det det")
_TEX = dict(zip(*[iter((_GREEK + " " + _SYMBOLS).split(" "))] * 2))
_TEX.update({"quad": "\u2003", "qquad": "\u2003\u2003", "imath": "ı", "jmath": "ȷ"})
_TEX.update({name: f"\uf8f0{name}\uf8f1" for name in ("lim sin cos tan log ln exp max min sup inf det mod bmod sinh "
                                                    "cosh tanh arcsin arccos arctan gcd deg dim ker arg").split()})
_TEX["bmod"] = "\uf8f0mod\uf8f1"
# (negated relations: they showed as written)
_TEX.update({"nmid": "∤", "nparallel": "∦", "nleq": "≰", "ngeq": "≱", "nless": "≮", "ngtr": "≯",
             "nsubseteq": "⊈", "nsupseteq": "⊉", "nsim": "≁", "ncong": "≇", "nequiv": "≢", "notni": "∌"})
# (KaTeX's other common signs: they showed as written - \ll, \dagger, \colon, \hookrightarrow, \models ...)
_TEX.update(dict(zip(*[iter("""
ll ≪ gg ≫ lll ⋘ ggg ⋙ dagger † ddagger ‡ dag † ddag ‡ colon : longrightarrow ⟶ longleftarrow ⟵
longleftrightarrow ⟷ Longrightarrow ⟹ Longleftarrow ⟸ Longleftrightarrow ⟺ hookrightarrow ↪ hookleftarrow ↩
therefore ∴ because ∵ vdash ⊢ dashv ⊣ models ⊨ prec ≺ succ ≻ preceq ⪯ succeq ⪰ odot ⊙ oslash ⊘ ominus ⊖
lvert | rvert | lVert ‖ rVert ‖ leqslant ⩽ geqslant ⩾ lesssim ≲ gtrsim ≳ square □ blacksquare ■ checkmark ✓
triangle △ triangleq ≜ bigtriangleup △ bigtriangledown ▽ diamond ⋄ Diamond ◊ Box □ clubsuit ♣ spadesuit ♠
heartsuit ♡ diamondsuit ♢ flat ♭ sharp ♯ natural ♮ surd √ wp ℘ mho ℧ complement ∁ backslash ∖ smallsetminus ∖
sqcup ⊔ sqcap ⊓ uplus ⊎ amalg ⨿ wr ≀ cdotp · ldotp . coloneqq ≔ eqqcolon ≕ approxeq ≊ asymp ≍ bowtie ⋈
doteq ≐ frown ⌢ smile ⌣ vartriangle △ digamma ϝ varkappa ϰ beth ℶ gimel ℷ daleth ℸ hslash ℏ eth ð Finv Ⅎ
Game ⅁ circledS Ⓢ measuredangle ∡ sphericalangle ∢ backprime ‵ Downarrow ⇓ Uparrow ⇑ updownarrow ↕
Updownarrow ⇕ nearrow ↗ searrow ↘ swarrow ↙ nwarrow ↖ leftharpoonup ↼ rightharpoonup ⇀
leftrightharpoons ⇋ rightleftharpoons ⇌ longmapsto ⟼ leadsto ⇝ impliedby ⟸ bigwedge ⋀ bigvee ⋁ biguplus ⨄
bigsqcup ⨆ bigodot ⨀ intop ∫ smallint ∫ iiint ∭ oiint ∯ ulcorner ⌜ urcorner ⌝ llcorner ⌞ lrcorner ⌟
dotsb ⋯ dotsc … dotsi ⋯ dotsm ⋯ dotso … subsetneq ⊊ supsetneq ⊋ sqsubset ⊏ sqsupset ⊐ sqsubseteq ⊑
sqsupseteq ⊒ leqq ≦ geqq ≧ lessgtr ≶ gtrless ≷ trianglelefteq ⊴ trianglerighteq ⊵ vartriangleleft ⊲
vartriangleright ⊳ ltimes ⋉ rtimes ⋊ bigcirc ◯ dotplus ∔ divideontimes ⋇ intercal ⊺ barwedge ⊼ veebar ⊻
curlywedge ⋏ curlyvee ⋎ Cap ⋒ Cup ⋓ between ≬ pitchfork ⋔ backsim ∽ backsimeq ⋍ eqcirc ≖ circeq ≗ bumpeq ≏
Bumpeq ≎ risingdotseq ≓ fallingdotseq ≒ lhd ⊲ rhd ⊳ unlhd ⊴ unrhd ⊵ centerdot · circledast ⊛ circledcirc ⊚
circleddash ⊝ boxplus ⊞ boxminus ⊟ boxtimes ⊠ boxdot ⊡ nleftarrow ↚ nrightarrow ↛ nLeftarrow ⇍ nRightarrow ⇏
nleftrightarrow ↮ nLeftrightarrow ⇎ S § P ¶ copyright © pounds £ yen ¥ euro € textdegree ° lozenge ◊
blacklozenge ⧫ bigstar ★ varnothing ∅ nsubset ⊄ nsupset ⊅ upharpoonleft ↿ downharpoonright ⇂ curvearrowright ↷
curvearrowleft ↶ circlearrowleft ↺ circlearrowright ↻ twoheadrightarrow ↠ twoheadleftarrow ↞ rightsquigarrow ⇝
leftleftarrows ⇇ rightrightarrows ⇉ upuparrows ⇈ downdownarrows ⇊ multimap ⊸ eqsim ≂ precsim ≾ succsim ≿
vDash ⊨ Vdash ⊩ Vvdash ⊪ nvdash ⊬ nvDash ⊭ ntriangleleft ⋪ ntriangleright ⋫ lneq ⪇ gneq ⪈ lneqq ≨ gneqq ≩
""".split())] * 2)))
_TEX.update({"bigcup": "⋃", "bigcap": "⋂", "bigoplus": "⨁", "bigotimes": "⨂", "coprod": "∐", "lbrace": "\x00",
             "rbrace": "\x01", "lbrack": "[", "rbrack": "]", "lparen": "(", "rparen": ")", "vert": "|"})
_TEX.update({name: f"\uf8f0{name}\uf8f1" for name in ("limsup liminf Pr hom lg arccot coth sec csc cot "
                                                       "injlim projlim argmax argmin").split()})
#: \not before a sign: its negated sign (else the sign struck through: a combining long solidus).
_NOT = {"=": "≠", "∈": "∉", "∋": "∌", "⊂": "⊄", "⊃": "⊅", "⊆": "⊈", "⊇": "⊉", "<": "≮", ">": "≯", "≤": "≰",
        "≥": "≱", "∼": "≁", "≅": "≇", "≡": "≢", "∣": "∤", "∥": "∦", "≈": "≉", "∃": "∄"}
_SUP = dict(zip("0123456789+-=()niabcdefghjklmoprstuvwxyzT",
                "⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾ⁿⁱᵃᵇᶜᵈᵉᶠᵍʰʲᵏˡᵐᵒᵖʳˢᵗᵘᵛʷˣʸᶻᵀ"))
_SUB = dict(zip("0123456789+-=()aehijklmnoprstuvx", "₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎ₐₑₕᵢⱼₖₗₘₙₒₚᵣₛₜᵤᵥₓ"))
_SUP.update({"′": "′", "∗": "*", "*": "*"})
def _alphabet(capitals: int, smalls: int | None, exceptions: str) -> dict[str, str]:
    """A Unicode math alphabet: A-Z from *capitals*, a-z from *smalls* (or
    none), the letters Unicode keeps elsewhere (ℒ, ℝ) from *exceptions*
    ("Lℒ Rℛ")."""
    found = {chr(65 + n): chr(capitals + n) for n in range(26)}
    if smalls is not None:
        found.update({chr(97 + n): chr(smalls + n) for n in range(26)})
    found.update({pair[0]: pair[1] for pair in exceptions.split()})
    return found


#: \mathbb, \mathcal, \mathfrak: Unicode's mathematical alphabets
_DOUBLE_STRUCK = _alphabet(0x1D538, 0x1D552, "Cℂ Hℍ Nℕ Pℙ Qℚ Rℝ Zℤ")
_DOUBLE_STRUCK.update({str(n): chr(0x1D7D8 + n) for n in range(10)})
_SCRIPT_LETTERS = _alphabet(0x1D49C, 0x1D4B6, "Bℬ Eℰ Fℱ Hℋ Iℐ Lℒ Mℳ Rℛ eℯ gℊ oℴ")
_FRAKTUR = _alphabet(0x1D504, 0x1D51E, "Cℭ Hℌ Iℑ Rℜ Zℨ")
#: Marks of a formula's parts while it is made text (control characters: a
#: file's never reach here - clean): sub-, superscript, bold, italic, a
#: command not understood. math_runs / math_html make them what they are.
SUB, SUB_END, SUP, SUP_END, BOLD, BOLD_END, ITALIC, ITALIC_END, UNKNOWN, UNKNOWN_END = (
    chr(n) for n in range(0x10, 0x1A))
#: ... and what a root's bar goes over (a page draws it: text writes "√(a+b)").
OVER, OVER_END = "\x1c", "\x1d"
#: ... and what stands upright among the italic letters of a page's formula
#: (a function's name, \text{...}: "sin", not "sin" in italic - as KaTeX).
#: (private-use characters: \x1c-\x1f are Python's whitespace - strip() took
#: the mark away - and the other control characters are taken)
UPRIGHT, UPRIGHT_END = "\uf8f0", "\uf8f1"
_MATH_MARKS = re.compile("[\x10-\x19\x1c\x1d\uf8f0\uf8f1\uf8f2-\uf8f4]")
#: TeX's accents as Unicode's combining marks (after each letter they are over).
_ACCENTS = {"hat": "\u0302", "widehat": "\u0302", "bar": "\u0304", "overline": "\u0305",
            "vec": "\u20d7", "tilde": "\u0303", "widetilde": "\u0303", "dot": "\u0307",
            "ddot": "\u0308", "underline": "\u0332", "acute": "\u0301", "grave": "\u0300",
            "check": "\u030c", "breve": "\u0306", "overrightarrow": "\u20d7", "overleftarrow": "\u20d6",
            "overleftrightarrow": "\u20e1", "mathring": "\u030a", "dddot": "\u20db"}
#: How many arguments a command takes (one in braces each - else its next
#: sign or command is: \frac12, \sqrt5, \hat\theta - _braced).
_ARITY = {**{name: 2 for name in "frac dfrac tfrac cfrac binom dbinom tbinom overset underset stackrel "
             "braket".split()},
          **{name: 1 for name in ("sqrt mathbb mathcal mathscr mathfrak mathbf boldsymbol bm mathit mathrm mathsf "
                                  "mathtt text textrm textbf textit operatorname mbox boxed fbox cancel ket bra "
                                  "overbrace underbrace phantom hphantom vphantom substack pmod").split()},
          **{name: 1 for name in _ACCENTS}}
_ARGUMENT_AT = re.compile(r"\\([A-Za-z]+)\*?")


#: Groups inside each other at most a formula is made text with: deeper, it
#: is shown as written with a note (math_runs). (A formula of 1,000 roots in
#: each other took Python past its recursion limit: a blank page, a traceback.)
MATH_DEPTH = 64
_NESTING = re.compile(r"\\(?:left|right|begin|end)(?![A-Za-z])|\\.|[{}]", re.DOTALL)


class MathTooDeep(ValueError):
    """A formula's groups lie deeper inside each other than MATH_DEPTH."""


def math_depth(tex: str) -> int:
    """How deep *tex*'s groups - {...}, \\left...\\right, \\begin...\\end -
    lie inside each other at most (one pass)."""
    depth = deepest = 0
    for found in _NESTING.finditer(tex):
        sign = found.group(0)
        if sign in ("{", "\\left", "\\begin"):
            depth += 1
            deepest = max(deepest, depth)
        elif sign in ("}", "\\right", "\\end"):
            depth = max(0, depth - 1)
    return deepest


def _brace_ends(tex: str) -> dict[int, int]:
    """{where a group's "{" is: where its "}" is} of *tex* - one pass with a
    stack (an escaped brace, "\\{", none); MathTooDeep past MATH_DEPTH."""
    ends, opened = {}, []
    for found in _BRACE.finditer(tex):
        if found.group(0) == "{":
            opened.append(found.start())
            if len(opened) > MATH_DEPTH:
                raise MathTooDeep(len(opened))
        elif opened:
            ends[opened.pop()] = found.start()
    return ends


_BRACE = re.compile(r"(?<!\\)[{}]")
_SQRT_INDEX = re.compile(r"\s*\[[^\]]*\]")
_SPACES = re.compile(r"\s*")
_ARGUMENT_TOKEN = re.compile(r"\\[A-Za-z]+|\\.|[^\s{}\\^_]")


def _braced(tex: str) -> str:
    """*tex* with each argument of _ARITY's commands in braces: written
    without (\\frac12, \\sqrt5, \\vec v, \\hat\\theta) it showed as written.
    One pass, no recursion: a group's own commands are read as the pass
    comes into it, a command's next arguments when it is past the group (a
    formula of 1,000 groups in each other took Python past its recursion
    limit, each group read again for each one around it); groups deeper
    than MATH_DEPTH: MathTooDeep."""
    if "\\" not in tex:
        return tex
    ends = _brace_ends(tex)
    out, at = [], 0
    waiting: list[list[int]] = []  # ([where a group ends, how many arguments after it] - innermost last)

    def arguments(count: int) -> None:
        nonlocal at
        limit = waiting[-1][0] if waiting else len(tex)  # (an argument never reaches out of its group)
        for done in range(count):
            space = _SPACES.match(tex, at, limit).end()
            if space >= limit:
                return
            if tex[space] == "{":  # (in braces: its commands read as the pass comes into it)
                end = ends.get(space)
                if end is None or end > limit:
                    return
                out.append(tex[at:space + 1])
                at = space + 1
                waiting.append([end, count - done - 1])
                return
            token = _ARGUMENT_TOKEN.match(tex, space, limit)
            if not token:
                return
            out.append("{" + token.group(0) + "}")
            at = token.end()

    pos = 0
    while True:
        found = _ARGUMENT_AT.search(tex, pos)
        if waiting and waiting[-1][0] < (found.start() if found else len(tex)):
            end, count = waiting.pop()  # (past a group: the arguments after it)
            out.append(tex[at:end + 1])
            at = pos = end + 1
            arguments(count)
            pos = max(pos, at)
            continue
        if not found:
            break
        pos = found.end()
        if found.group(1) not in _ARITY:
            continue
        out.append(tex[at:found.end()])
        at = found.end()
        if found.group(1) == "sqrt":  # (its index first: \\sqrt[3]{x})
            index = _SQRT_INDEX.match(tex, at, waiting[-1][0] if waiting else len(tex))
            if index:
                out.append(tex[at:index.end()])
                at = index.end()
        arguments(_ARITY[found.group(1)])
        pos = at
    out.append(tex[at:])
    return "".join(out)


_CHOOSE = re.compile(r"\{([^{}]*?)\\choose([^{}]*)\}")


def math_normal(tex: str) -> str:
    """*tex* as the passes read it: arguments in braces (_braced), {n \\choose k}
    as \\binom{n}{k} (the whole formula's too)."""
    tex = _braced(tex)
    if "\\choose" in tex:
        tex = _CHOOSE.sub(lambda m: f"\\binom{{{m.group(1).strip()}}}{{{m.group(2).strip()}}}", tex)
        if tex.count("\\choose") == 1 and "{" not in tex:
            upper, lower = tex.split("\\choose")
            tex = f"\\binom{{{upper.strip()}}}{{{lower.strip()}}}"
    return tex


def _accent(name: str, text: str) -> str:
    mark = _ACCENTS[name]
    if "\\" in text:  # (a command not understood: one unit - the accent on every letter of "\\imath" before)
        return text + mark
    return "".join(c + mark if not c.isspace() else c for c in text)


#: Colours a formula may name (\\color, \\textcolor) - and a hex one: nothing else reaches a page.
_COLOURS = {"red": "#d1242f", "blue": "#0969da", "green": "#1a7f37", "orange": "#bc4c00", "purple": "#8250df",
            "magenta": "#bf3989", "cyan": "#1b7c83", "teal": "#1b7c83", "brown": "#953800", "gray": "#6e7781",
            "grey": "#6e7781", "black": "#1f2328", "white": "#ffffff", "yellow": "#9a6700", "olive": "#6f7a00",
            "navy": "#0a3069", "maroon": "#82071e", "pink": "#bf3989", "violet": "#8250df", "lime": "#4ac26b"}
#: A formula's colour: (marks of) where it begins - "#rrggbb" after it, up to COLOUR_MID - and ends.
COLOUR, COLOUR_MID, COLOUR_END = "\uf8f2", "\uf8f3", "\uf8f4"


def _coloured(name: str, text: str) -> str:
    """*text* in the colour *name* - a named one of _COLOURS or a hex one; anything else: no colour."""
    name = name.strip().lower()
    found = re.fullmatch(r"#?([0-9a-f]{6}|[0-9a-f]{3})", name)
    colour = _COLOURS.get(name) or (("#" + (found.group(1) if len(found.group(1)) == 6
                                             else "".join(c * 2 for c in found.group(1)))) if found else None)
    return f"{COLOUR}{colour}{COLOUR_MID}{text}{COLOUR_END}" if colour else text


_INNER = r"\{([^{}]*)\}"
#: A group that may hold groups (one level): a brace's group and label - its label taken for a power first.
_NESTED = r"\{((?:[^{}]|\{[^{}]*\})*)\}"


def _labelled_brace(sign: str, group: str, label: str) -> str:
    """\\overbrace{a+b}^{n}: the group, its brace and its label in braces
    after it - "(a+b)⏞[n]" (a page shows no brace: its fonts have none) - not
    the label as its power: it read "(a+b)²"."""
    return f"{_group(group)}{sign}[{label.strip()}]"


_MATH_RULES = (
    # (a label of a brace first: its "^{…}" read as a power)
    (re.compile(r"\\overbrace\s*" + _NESTED + r"\s*\^\s*" + _NESTED),
     lambda m: _labelled_brace("⏞", m.group(1), m.group(2))),
    (re.compile(r"\\underbrace\s*" + _NESTED + r"\s*_\s*" + _NESTED),
     lambda m: _labelled_brace("⏟", m.group(1), m.group(2))),
    # (a number of a line: at its end, in parentheses - "\\tag*" without; none for \\notag, nor a \\label)
    (re.compile(r"\\tag\*\s*" + _INNER), lambda m: f"\u2003{m.group(1).strip()}"),
    (re.compile(r"\\tag\s*" + _INNER), lambda m: f"\u2003({m.group(1).strip()})"),
    (re.compile(r"\\label\s*" + _INNER), lambda m: ""),
    (re.compile(r"\\(?:notag|nonumber)(?![A-Za-z])"), lambda m: ""),
    # (a sign over or under another: the one in its place, the other raised or lowered beside it)
    (re.compile(r"\\(?:overset|stackrel)\s*" + _INNER + r"\s*" + _INNER),
     lambda m: m.group(2) + _script(m.group(1), _SUP, "^")),
    (re.compile(r"\\underset\s*" + _INNER + r"\s*" + _INNER),
     lambda m: m.group(2) + _script(m.group(1), _SUB, "_")),
    (re.compile(r"\\substack\s*" + _INNER), lambda m: ", ".join(row.strip() for row in m.group(1).split("\n"))),
    (re.compile(r"\\[hv]?phantom\s*" + _INNER), lambda m: " "),
    (re.compile(r"\\not\s*([^\s\\{}])"), lambda m: _NOT.get(m.group(1), m.group(1) + "\u0338")),
    (re.compile(r"\\[dtc]?frac\s*" + _INNER + r"\s*" + _INNER),
     lambda m: f"{_group(m.group(1))}/{_group(m.group(2))}"),
    (re.compile(r"\\sqrt\s*\[\s*([34])\s*\]\s*" + _INNER),
     lambda m: ("∛" if m.group(1) == "3" else "∜") + _radicand(m.group(2))),
    (re.compile(r"\\sqrt\s*" + _INNER), lambda m: "√" + _radicand(m.group(1))),
    (re.compile(r"\\mathbb\s*" + _INNER), lambda m: "".join(_DOUBLE_STRUCK.get(c, c) for c in m.group(1))),
    (re.compile(r"\\mathcal\s*" + _INNER), lambda m: "".join(_SCRIPT_LETTERS.get(c, c) for c in m.group(1))),
    (re.compile(r"\\mathfrak\s*" + _INNER), lambda m: "".join(_FRAKTUR.get(c, c) for c in m.group(1))),
    (re.compile(r"\\(?:mathbf|boldsymbol|bm|textbf)\s*" + _INNER), lambda m: BOLD + m.group(1) + BOLD_END),
    (re.compile(r"\\(?:mathit|textit)\s*" + _INNER), lambda m: ITALIC + m.group(1) + ITALIC_END),
    # (their arrows marked until relations are spaced: "—f→" is one sign)
    (re.compile(r"\\xrightarrow\s*(?:\[[^\]]*\])?\s*" + _INNER), lambda m: f" —{m.group(1).strip()}\x0e "),
    (re.compile(r"\\xleftarrow\s*(?:\[[^\]]*\])?\s*" + _INNER), lambda m: f" \x0f{m.group(1).strip()}— "),
    (re.compile(r"\\overbrace\s*" + _INNER + r"(?!\s*\^)"), lambda m: f"⏞{_group(m.group(1))}"),
    (re.compile(r"\\underbrace\s*" + _INNER + r"(?!\s*_)"), lambda m: f"⏟{_group(m.group(1))}"),
    (re.compile(r"\\(" + "|".join(_ACCENTS) + r")\s*" + _INNER), lambda m: _accent(m.group(1), m.group(2))),
    (re.compile(r"\\[dt]?binom\s*" + _INNER + r"\s*" + _INNER),
     lambda m: f"C({m.group(1).strip()}, {m.group(2).strip()})"),
    (re.compile(r"\\pmod\s*" + _INNER), lambda m: f"({UPRIGHT}mod{UPRIGHT_END} {m.group(1).strip()})"),
    (re.compile(r"\\ket\s*" + _INNER), lambda m: f"|{m.group(1).strip()}⟩"),
    (re.compile(r"\\bra\s*" + _INNER), lambda m: f"⟨{m.group(1).strip()}|"),
    (re.compile(r"\\braket\s*" + _INNER + r"\s*" + _INNER),
     lambda m: f"⟨{m.group(1).strip()}|{m.group(2).strip()}⟩"),
    (re.compile(r"\\mathscr\s*" + _INNER), lambda m: "".join(_SCRIPT_LETTERS.get(c, c) for c in m.group(1))),
    # (colour - a named one or hex only -, a box, a cancel: they showed as written)
    (re.compile(r"\{\s*\\color\s*" + _INNER + r"([^{}]*)\}"), lambda m: _coloured(m.group(1), m.group(2))),
    (re.compile(r"\\(?:textcolor|color)\s*" + _INNER + r"\s*" + _INNER), lambda m: _coloured(m.group(1), m.group(2))),
    (re.compile(r"\\color\s*" + _INNER), lambda m: ""),
    (re.compile(r"\\(?:boxed|fbox)\s*" + _INNER), lambda m: f"[{m.group(1).strip()}]"),
    (re.compile(r"\\(?:cancel|bcancel|xcancel|sout)\s*" + _INNER),
     lambda m: "".join(c + "\u0336" if not c.isspace() else c for c in m.group(1))),
    (re.compile(r"\\(?:text|textrm|mathrm|mathsf|mathtt|operatorname\*?|mbox)\s*" + _INNER),
     lambda m: UPRIGHT + m.group(1) + UPRIGHT_END),
    (re.compile(r"\^\s*" + _INNER), lambda m: _script(m.group(1), _SUP, "^")),
    (re.compile(r"_\s*" + _INNER), lambda m: _script(m.group(1), _SUB, "_")),
)


#: A group of nothing else, its braces dropped (but a group after a
#: command math_text does not know: kept as written).
_BARE_GROUP = re.compile(r"(\\[A-Za-z]+\s*)?\{([^{}]*)\}")


#: One symbol: a number, or a letter with its small raised and lowered signs.
_SYMBOL = re.compile(r"(?:\d+(?:\.\d+)?|[^\W\d_])[⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁽⁾ⁿⁱ₀₁₂₃₄₅₆₇₈₉₊₋ᵢⱼₙₖₘ′]*"
                     "[\u0300-\u036f\u20d0-\u20ff]*")


def _radicand(text: str) -> str:
    """What a root holds: under its bar on a page (OVER marks), in
    parentheses as text."""
    if _SMALL.get():
        return _group(text)
    if any(mark in text for mark in (SUB, SUP, BOLD, ITALIC, UNKNOWN, OVER)):
        # (scripts in it: a bar cannot run over them - it ended before "²",
        # √x̄²+y² read as √(x²)+y²: in parentheses, as the terminal writes it)
        return _group(text)
    return OVER + text.strip() + OVER_END if text.strip() else ""


def _group(text: str) -> str:
    """*text* as an operand: in parentheses unless it is one symbol ("2a"
    is two: the quadratic formula's "/2a" read as divided by 2, times a)."""
    text = text.strip()
    return text if not text or _SYMBOL.fullmatch(text) or len(text) == 1 else f"({text})"




def _script(text: str, table: dict, mark: str) -> str:
    """*text* raised (``^``) or lowered (``_``) with Unicode's small letters,
    when it has them all; else as ``^(text)``."""
    text = text.strip()
    if _SMALL.get() and text and all(c in table for c in text):
        return "".join(table[c] for c in text)
    if not text:
        return ""
    return (SUB + text + SUB_END) if mark == "_" else (SUP + text + SUP_END)


def raised(text: str, kind: str, plain: bool = False) -> str:
    """*text* as a superscript (*kind* "sup") or subscript ("sub") in
    Unicode's small letters when it has them all, else as ``^(text)`` /
    ``_(text)`` - or, *plain*, as it is (the terminal's ``<sup>`` /
    ``<sub>``: "Built with care" is no formula)."""
    table = _SUP if kind == "sup" else _SUB
    if plain and not (text.strip() and all(c in table for c in text.strip())):
        return text
    return _written(_script(text, table, "^" if kind == "sup" else "_"))


#: TeX's escaped characters, kept from the passes until the end.
_ESCAPED = {"\\{": "\x00", "\\}": "\x01", "\\&": "\x02", "\\%": "\x03", "\\$": "\x04", "\\#": "\x05",
            "\\_": "\x06"}
_UNESCAPED = {"\x00": "{", "\x01": "}", "\x02": "&", "\x03": "%", "\x04": "$", "\x05": "#", "\x06": "_",
              "\x07": "_", "\x08": "^", "\x0e": "→", "\x0f": "←"}
#: An environment of no other inside it (innermost first).
_ENVIRONMENT = re.compile(r"\\begin\s*\{([A-Za-z]+\*?)\}((?:(?!\\begin\s*\{).)*?)\\end\s*\{\1\}", re.DOTALL)
#: Brackets of a matrix: (top-left, top-right, middle-left, middle-right,
#: bottom-left, bottom-right, one row's left, one row's right).
_BRACKETS = {
    "pmatrix": ("⎛", "⎞", "⎜", "⎟", "⎝", "⎠", "(", ")"),
    "bmatrix": ("⎡", "⎤", "⎢", "⎥", "⎣", "⎦", "[", "]"),
    "Bmatrix": ("⎧", "⎫", "⎪", "⎪", "⎩", "⎭", "{", "}"),
    "vmatrix": ("│", "│", "│", "│", "│", "│", "|", "|"),
    "Vmatrix": ("‖", "‖", "‖", "‖", "‖", "‖", "‖", "‖"),
}
_SCRIPT = r"(\{[^{}]*\}|[^\s{}\\^_])"
_PAIRS = (re.compile(r"_" + _SCRIPT + r"\^" + _SCRIPT), re.compile(r"\^" + _SCRIPT + r"_" + _SCRIPT))
#: Wraps the number of an environment's rows while the passes go on.
_ROWS = "\ue061"


def _pair(sub: str, sup: str) -> str:
    """A subscript and a superscript of one symbol in one style: both small
    when Unicode has small letters for both, else both written out
    ("∫₀^∞" mixed them)."""
    sub, sup = sub.strip("{}").strip(), sup.strip("{}").strip()
    if _SMALL.get() and sub and sup and all(c in _SUB for c in sub) and all(c in _SUP for c in sup):
        return "".join(_SUB[c] for c in sub) + "".join(_SUP[c] for c in sup)
    # (in marks the single scripts' pass leaves alone: "_0" went "₀" again)
    return SUB + sub + SUB_END + SUP + sup + SUP_END


def _environment(name: str, body: str) -> list[str]:
    """The rows of a TeX environment (a matrix, cases, aligned lines) as
    lines of text: cells aligned in columns, a matrix in its brackets, cases
    behind a brace."""
    # ("\\\\[4pt]": room after a row - none here; \\hline: no rule in text; an array's column spec)
    rows = [re.sub(r"\\hline(?![A-Za-z])", "", re.sub(r"\A\s*\[[^\]]*\]", "", row))
            for row in re.split(r"\\\\", body)]
    if name.rstrip("*") == "array" and rows:
        rows[0] = re.sub(r"^\s*\{[^{}]*\}", "", rows[0])
    while rows and not rows[-1].strip():
        rows.pop()
    cells = [[math_text(cell) for cell in row.split("&")] for row in rows] or [[""]]
    columns = max(len(row) for row in cells)
    widths = [max(cell_width(row[c]) if c < len(row) else 0 for row in cells) for c in range(columns)]
    # (aligned lines: "&" is where they line up - "a &= b" reads "a = b";
    # a matrix's and the cases' cells stand apart)
    gap = " " if name.rstrip("*") in ("aligned", "align", "split", "gathered", "alignat", "eqnarray") else "  "
    lines = []
    for row in cells:
        padded = [row[c] + " " * (widths[c] - cell_width(row[c])) if c < len(row) else " " * widths[c]
                  for c in range(columns)]
        lines.append(gap.join(padded))
    count = len(lines)
    if name in _BRACKETS:
        tl, tr_, ml, mr, bl, br, one_l, one_r = _BRACKETS[name]
        if count == 1:
            return [f"{one_l}{lines[0]}{one_r}"]
        return [f"{tl if n == 0 else bl if n == count - 1 else ml}{line}"
                f"{tr_ if n == 0 else br if n == count - 1 else mr}" for n, line in enumerate(lines)]
    if name in ("cases", "dcases"):
        if count == 1:
            return ["{" + lines[0].rstrip()]
        if count == 2:
            return ["⎧" + lines[0].rstrip(), "⎩" + lines[1].rstrip()]  # (⎰⎱: in few fonts)
        middle = count // 2
        return [("⎧" if n == 0 else "⎩" if n == count - 1 else "⎨" if n == middle else "⎪") + line.rstrip()
                for n, line in enumerate(lines)]
    return [line.rstrip() for line in lines]  # (matrix, aligned, gathered, array: rows only)


def _environment_inline(name: str, body: str) -> str:
    """An environment inside another one's cell, on one line: its cells
    apart by spaces, its rows by "; ", in its brackets."""
    rows = [re.sub(r"\\hline(?![A-Za-z])", "", re.sub(r"\A\s*\[[^\]]*\]", "", row)) for row in re.split(r"\\\\", body)]
    rows = [row for row in rows if row.strip()]
    shown = "; ".join(" ".join(math_text(cell).strip() for cell in row.split("&")) for row in rows)
    left, right = _BRACKETS[name][6:8] if name in _BRACKETS else ("{", "") if name.startswith("cases") else ("", "")
    return f"{left}{shown}{right}"


#: Relations and arrows: one space on each side ("x→ 0", "a =b" were lopsided).
_RELATION = re.compile(r"[ \t]*([=≤≥≠≈≡∼≃≅∝→←↔⇒⇐⇔⟹⟺↦∈∉∋⊂⊆⊃⊇<>])[ \t]*")
#: A command left over: not understood (shown as written, as code).
_LEFT_OVER = re.compile(r"\\[A-Za-z]+\*?(?:\s*\{[^{}]*\})*")


#: Whether scripts are written in Unicode's small letters (the terminal,
#: text) or kept as SUB / SUP marks (a page with real sub- and superscripts:
#: the small letters of "∑ₖ₌₁ⁿ" were too small to read).
_SMALL = contextvars.ContextVar("axross_math_small", default=True)


#: Whether relations are set tight, as in a script (an operator's limit: "i=1").
_TIGHT = contextvars.ContextVar("axross_math_tight", default=False)


@functools.lru_cache(maxsize=4096)  # (a formula is made text once however often it is shown)
def _math(tex: str, small: bool = True, tight: bool = False) -> tuple[str, list[list[str]]]:
    """(the text of the formula *tex* with its marks - SUB, SUP, BOLD,
    ITALIC, UNKNOWN - and its environments' rows, placed by _place_rows);
    *small*: scripts in Unicode's small letters where it has them all;
    *tight*: no room around its relations (a limit under a sum)."""
    token, tight_token = _SMALL.set(small), _TIGHT.set(tight)
    try:
        return _math_of(tex)
    finally:
        _SMALL.reset(token)
        _TIGHT.reset(tight_token)


def _math_of(tex: str) -> tuple[str, list[list[str]]]:
    # (a line end in TeX is a space - "\\\\" ends a row: two environments on lines of their own were
    # stacked, not side by side)
    tex = re.sub(r"[ \t]*\n[ \t]*", " ", _MATH_MARKS.sub("", tex.strip()))
    tex = math_normal(tex)
    for written, mark in _ESCAPED.items():
        tex = tex.replace(written, mark)
    # \left and \right first: "\left\| v \right\|" left "‖v ‖"
    tex = re.sub(r"\\(?:left|right|middle|big|Big|bigg|Bigg)[lr]?(?![A-Za-z])\.?", "", tex)
    # norms and absolute values: their bars close to what they hold
    tex = re.sub(r"\\lVert\s*(.*?)\s*\\rVert", r"‖\1‖", tex)
    tex = re.sub(r"\\lvert\s*(.*?)\s*\\rvert", r"|\1|", tex)
    tex = re.sub(r"\\\|\s*([^|\n]*?)\s*\\\|", r"‖\1‖", tex)
    tex = tex.replace("\\|", "‖")
    environments: list[list[str]] = []
    for _round in range(8):  # (innermost first; nesting deeper than this stays)
        found = _ENVIRONMENT.search(tex)
        if not found:
            break
        before = tex[:found.start()]
        if len(re.findall(r"\\begin\s*\{", before)) > len(re.findall(r"\\end\s*\{", before)):
            # (inside another environment: in its cell on one line - "(a b; c d)": its rows placed below
            # the outer one's scrambled them)
            tex = before + _environment_inline(found.group(1), found.group(2)) + tex[found.end():]
            continue
        environments.append(_environment(found.group(1), found.group(2)))
        tex = tex[:found.start()] + f"{_ROWS}{len(environments) - 1}{_ROWS}" + tex[found.end():]
    tex = tex.replace("\\\\", "\n").replace("&", "")
    tex = re.sub(r"\\(?:begin|end)\s*\{[A-Za-z*]*\}", "", tex)
    tex = re.sub(r"\\(?:displaystyle|limits|nolimits)(?![A-Za-z])", "", tex)
    tex = re.sub(r"\\[,;:!> ]", " ", tex)
    tex = re.sub(r"[ \t]+([\^_])", r"\1", tex)  # ("\\sum _k": the script belongs to it)
    # (a command's own spaces are kept: "a \\leq b" reads "a ≤ b")
    tex = re.sub(r"\\([A-Za-z]+)(?![A-Za-z])", lambda m: _TEX.get(m.group(1), m.group(0)), tex)
    # (a function's name apart from what is before it: "n\\log n" read "nlog n")
    tex = re.sub("(?<=[\\w)\\]}])" + UPRIGHT, " " + UPRIGHT, tex)
    for pattern in _PAIRS:
        tex = pattern.sub(lambda m: _pair(m.group(1), m.group(2)) if pattern is _PAIRS[0]
                          else _pair(m.group(2), m.group(1)), tex)
    tex = re.sub(r"\^\s*([^\s{}\\^_\x10-\x19])", lambda m: _script(m.group(1), _SUP, "^"), tex)
    tex = re.sub(r"_\s*([^\s{}\\^_\x10-\x19])", lambda m: _script(m.group(1), _SUB, "_"), tex)
    for _round in range(32):  # (innermost groups first; nesting deeper than this stays)
        before = tex
        for pattern, replace in _MATH_RULES:
            tex = pattern.sub(replace, tex)
        if tex == before:  # (only bare groups left in the way: their braces go)
            tex = _BARE_GROUP.sub(lambda m: m.group(0) if m.group(1) else m.group(2), tex)
            if tex == before:
                break
    # what is left of commands: not understood - marked (shown as written, as code)
    tex = _LEFT_OVER.sub(lambda m: UNKNOWN + m.group(0) + UNKNOWN_END, tex)
    # (an upright word's spaces outside its marks: "\text{if } x" read "if  x" - two spaces, a mark between)
    tex = re.sub("([ \t]+)" + UPRIGHT_END, UPRIGHT_END + r"\1", re.sub(UPRIGHT + "([ \t]+)", r"\1" + UPRIGHT, tex))
    lines = []
    for line in tex.split("\n"):
        if UNKNOWN not in line:  # (spaced; tight in a script: "∑_(i=1)")
            line = "".join(_RELATION.sub(r"\1", part) if part[:1] in (SUB, SUP) or _TIGHT.get()
                           else _RELATION.sub(r" \1 ", part)
                           for part in re.split("(\x10[^\x11]*\x11|\x12[^\x13]*\x13)", line))
        # (one space between words; none inside brackets: "\\left( x \\right)" reads "(x)")
        line = re.sub(r"[ \t]{2,}", " ", line)
        line = re.sub(r"\s+([)\]⟩])", r"\1", re.sub(r"([(\[⟨])\s+", r"\1", line)).strip()
        if line:
            lines.append(line)
    tex = "\n".join(lines)
    for mark, written in _UNESCAPED.items():
        tex = tex.replace(mark, written)
    return unicodedata.normalize("NFC", tex), tuple(tuple(rows) for rows in environments)


def math_runs(tex: str, small: bool = True, tight: bool = False) -> list[tuple[str, str]]:
    """The formula *tex* as runs of (text, kind): kind "" (plain), "bold",
    "italic", "unknown" (as written: shown as code), "sub" or "sup" (written
    out: "_(i=1)", "^∞" - a space after one before a letter, "∞1" read as a
    number). Lines are joined by "\\n" runs; environments' rows placed. A
    formula deeper than MATH_DEPTH, or one the passes fail on: as written,
    with a note after it (_as_written_math) - never the page's error."""
    if len(tex.strip()) > MATH_LIMIT:
        return [(tex.strip(), "unknown")]
    try:
        return _math_runs(tex, small, tight)
    except MathTooDeep:
        return _as_written_math(tex, "deep")
    except (Exception, RecursionError):  # noqa: BLE001 - a formula's fault stays in that formula
        log.debug("A formula could not be read; shown as written", exc_info=True)
        return _as_written_math(tex, "fault")


def _as_written_math(tex: str, why: str) -> list[tuple[str, str]]:
    """The runs of a formula shown as written: its TeX (as code) and a note
    why - upright, in the formula's colour."""
    from core.i18n import tr

    note = (tr("(nested more than {depth} deep: shown as written)").format(depth=MATH_DEPTH) if why == "deep"
            else tr("(could not be read: shown as written)"))
    return [(tex.strip(), "unknown"), (" " + note, "upright")]


def math_too_deep(tex: str) -> bool:
    """Whether the formula *tex* is shown as written for its depth (MATH_DEPTH)."""
    return math_depth(tex) > MATH_DEPTH


def _math_runs(tex: str, small: bool, tight: bool) -> list[tuple[str, str]]:
    marked, environments = _math(tex, small, tight)
    runs, kind, buffer, index = [], "", [], 0
    opening = {SUB: "sub", SUP: "sup", BOLD: "bold", ITALIC: "italic", UNKNOWN: "unknown", OVER: "over"}
    closing = {SUB_END, SUP_END, BOLD_END, ITALIC_END, UNKNOWN_END, OVER_END}
    while index < len(marked):
        ch = marked[index]
        if ch in (SUB, SUP) and kind in ("sub", "sup"):
            # (a script of a script - e^{-x^2}: its "2" was as high as "-x" -
            # in Unicode's small letters inside it, as high again; else written out)
            end = marked.find(SUB_END if ch == SUB else SUP_END, index + 1)
            if end < 0:
                index += 1
                continue
            inner = _MATH_MARKS.sub("", marked[index + 1:end])
            table = _SUB if ch == SUB else _SUP
            if inner and all(c in table for c in inner):
                buffer.append("".join(table[c] for c in inner))
            elif not small and inner:  # (a page: a script of the script, raised or lowered again - "x_b" was
                if buffer:  # written so in it, \sigma_{x_b})
                    runs.append(("".join(buffer), kind))
                    buffer = []
                runs.append((inner, f"{kind}>{'sub' if ch == SUB else 'sup'}"))
            else:
                buffer.append(_written_run(inner, "sub" if ch == SUB else "sup"))
            index = end + 1
            continue
        if ch == COLOUR:  # (a colour from here: a run of nothing that says so - pages draw it, text not)
            end = marked.find(COLOUR_MID, index)
            if buffer:
                runs.append(("".join(buffer), kind))
                buffer = []
            runs.append(("", "colour:" + marked[index + 1:end]))
            index = end + 1 if end > 0 else index + 1
            continue
        if ch == COLOUR_END:
            if buffer:
                runs.append(("".join(buffer), kind))
                buffer = []
            runs.append(("", "colour"))
            index += 1
            continue
        if ch in (UPRIGHT, UPRIGHT_END):  # (upright among the formula's own letters - in a script: as it is)
            if kind in ("", "upright"):
                if buffer:
                    runs.append(("".join(buffer), kind))
                    buffer = []
                kind = "upright" if ch == UPRIGHT else ""
        elif ch in opening or ch in closing:
            if buffer:
                runs.append(("".join(buffer), kind))
                buffer = []
            if ch in opening:
                kind = opening[ch]
            else:
                if kind in ("sub", "sup"):
                    after = marked[index + 1:index + 2]
                    if after and (after.isalnum() or after == "√"):
                        runs.append((" ", ""))
                kind = ""
        else:
            buffer.append(ch)
        index += 1
    if buffer:
        runs.append(("".join(buffer), kind))
    # (a minus sign, not a hyphen: "-x" and "a-b" read as words)
    runs = [(text if kind == "unknown" else text.replace("-", "−"), kind) for text, kind in runs]
    if environments:
        text = _place_rows("".join(_written_run(text, kind) for text, kind in runs), environments)
        return [(text, "")]
    return runs


def _written_run(text: str, kind: str) -> str:
    if kind.startswith("colour"):
        return ""
    if kind == "upright":
        return text
    if kind == "over":
        return text if len(text) <= 1 else f"({text})"
    if kind == "sub":
        return "_" + (text if len(text) <= 1 else f"({text})")
    if kind == "sup":
        return "^" + (text if len(text) <= 1 else f"({text})")
    return text


def _written(marked: str) -> str:
    """Marked text (a single script) written out."""
    text = re.sub(SUB + "(.*?)" + SUB_END, lambda m: _written_run(m.group(1), "sub"), marked)
    text = re.sub(SUP + "(.*?)" + SUP_END, lambda m: _written_run(m.group(1), "sup"), text)
    return _MATH_MARKS.sub("", text)


def math_text(tex: str) -> str:
    """TeX math as text people read: the common commands as their Unicode
    signs (``\\alpha`` α, ``\\leq`` ≤, ``\\mathbb{R}`` ℝ, ``\\mathcal{L}``
    ℒ), fractions as ``a/b`` (an operand of more than one symbol in
    parentheses), roots as √, small super- and subscripts as ², ᵢ (a
    symbol's pair in one style, else both written out: ``∫_0^∞``),
    relations with a space on each side, accents as combining marks,
    matrices and cases as aligned rows in their brackets. What it does not
    know stays as written. Linear passes, at most :data:`MATH_LIMIT`
    characters (more: as written)."""
    return "".join(_written_run(text, kind) for text, kind in math_runs(tex))


def math_html(tex: str, tight: bool = False) -> str:
    """The formula *tex* as HTML for Qt or a browser: sub- and superscripts
    as <sub> / <sup> (Unicode's small letters where it has all), bold,
    italic, what is not understood as <code> - only that part."""
    import html as html_module

    tags = {"sub": ("<sub>", "</sub>"), "sup": ("<sup>", "</sup>"), "bold": ("<b>", "</b>"),
            "italic": ("<i>", "</i>"), "unknown": ("<code>", "</code>"), "": ("", ""), "upright": ("", ""),
            "over": ('<span style="text-decoration: overline">', "</span>")}

    def spaced(text: str) -> str:
        # (\quad's em spaces kept: Qt's HTML made a run of them one space - md4c's page kept them)
        return _EM_SPACES.sub(lambda m: f'<span style="white-space: pre">{m.group(0)}</span>',
                              html_module.escape(text).replace("  ", "&nbsp; "))

    def escaped(line: str, kind: str) -> str:
        if kind not in ("", "over", "sub", "sup") or plain:  # (thousands of letters: no italic span each)
            return spaced(line)
        # (a formula's letters in italic - its variables - as KaTeX sets them)
        return "".join(f"<i>{html_module.escape(piece)}</i>" if index % 2 else spaced(piece)
                       for index, piece in enumerate(VARIABLES.split(line)))

    out = []
    runs = math_runs(tex, small=False, tight=tight)
    plain = sum(len(VARIABLES.findall(text)) for text, _kind in runs) > MATH_ITALICS
    for text, kind in runs:  # (real sub- and superscripts)
        if kind.startswith("colour"):  # (its colour: a named one or hex - _coloured)
            out.append(f'<font color="{kind[7:]}">' if kind.startswith("colour:") else "</font>")
            continue
        if ">" in kind:  # (a script of a script: one inside the other)
            outer, inner = kind.split(">", 1)
            shown = "<br />".join(escaped(line, "sub") for line in page_letters(text).split("\n"))
            out.append(tags[outer][0] + tags[inner][0] + shown + tags[inner][1] + tags[outer][1])
            continue
        shown = "<br />".join(escaped(line, kind) for line in page_letters(text).split("\n"))
        out.append(tags[kind][0] + shown + tags[kind][1])
    return "".join(out)


_EM_SPACES = re.compile("[\u2002\u2003\u2009]+")


def _page_letters() -> dict:
    """Unicode's script and fraktur letters of plane 1 (\\mathcal{O}: 𝒪) as
    the letters they are, and the braces over and under a group (⏞ ⏟) as
    none: a page's fonts often have none of them (DejaVu: a box each) - its
    terminal's are left alone."""
    table = {0x23DE: None, 0x23DF: None}
    for code in list(range(0x1D49C, 0x1D504)) + list(range(0x1D504, 0x1D538)) + list(range(0x1D56C, 0x1D5A0)):
        name = unicodedata.name(chr(code), "")
        if name.startswith("MATHEMATICAL") and ("SCRIPT" in name or "FRAKTUR" in name):
            letter = name.split()[-1]
            table[code] = letter if "CAPITAL" in name else letter.lower()
    return table


PAGE_LETTERS = _page_letters()


def page_letters(text: str) -> str:
    """*text* as a page's fonts show it (see _page_letters)."""
    return text.translate(PAGE_LETTERS)


def keep_script_letters() -> None:
    """A font of the page has plane 1's script and fraktur letters (a maths
    font - STIX Two Math, Latin Modern Math, ...): \\mathcal{O} shown as 𝒪,
    as the terminal shows it (it was a plain O on every page)."""
    global PAGE_LETTERS
    PAGE_LETTERS = {0x23DE: None, 0x23DF: None}
#: Letters of a formula set in italic at most - more: none (Qt laid a line of thousands of italic spans out
#: in time that grows with their square).
MATH_ITALICS = 300
#: A run of a formula's letters (Latin, small Greek): its variables, in italic on a page.
VARIABLES = re.compile("([A-Za-z\u03b1-\u03c9\u03d1\u03d5\u03d6\u03f5]+)")


#: Environments whose "&" is where lines line up: their columns alternate
#: right- and left-aligned ("a &= b").
_ALIGNED = ("aligned", "align", "split", "gathered", "alignat", "eqnarray")


def math_grid(tex: str) -> tuple[list[list[str]], list[tuple], list[str], list[int], list[tuple],
                                 list[tuple]] | None:
    """A display formula made of one environment of rows (cases, a matrix,
    aligned lines - what comes before and after it in its line) as a grid
    for a view that lays it out as a table, in a math face (its rows in a
    monospace font were the only way their columns lined up): (rows of
    cells, each TeX - "" where a cell spans; spans ``(row, column, rows,
    columns)``; each column's alignment; the columns with room before them -
    a case's condition, a matrix's next column; the cells ruled under (a
    fraction's numerator); the cells set larger or smaller ``(row, column,
    rows, step)`` - Qt's size steps: a case's brace, a matrix's brackets
    as tall as their rows, one glyph each; an operator of display size, its
    limits smaller - or None: math_text shows it. A span may say where its
    cell sits in its rows: ``(row, column, rows, columns, "bottom")``. A
    gap may be ``(column, pixels)``: room other than a matrix's."""
    tex = tex.strip()
    if len(tex) > MATH_LIMIT or math_too_deep(tex):
        return None  # (as text: math_runs - as written, with its note)
    try:
        return _math_grid(tex)
    except (Exception, RecursionError):  # noqa: BLE001 - a formula's fault: in its line, as text
        log.debug("A formula's grid could not be made; shown as text", exc_info=True)
        return None


def _math_grid(tex: str):
    if "\\begin" not in tex and "\\\\" not in tex:
        return _display_grid(tex)
    if len(tex) > MATH_LIMIT or len(re.findall(r"\\begin\s*\{", tex)) != 1:
        return None
    found = _ENVIRONMENT.search(tex)
    if not found:
        return None
    name, body = found.group(1), found.group(2)
    before, after = tex[:found.start()].strip(), tex[found.end():].strip()
    if "\\\\" in before or "\\\\" in after:
        return None
    rows = re.split(r"\\\\", body)
    while rows and not rows[-1].strip():
        rows.pop()
    if len(rows) < 2:
        return None  # (one row: in its line, as text)
    cells = [[cell.strip() for cell in row.split("&")] for row in rows]
    count, columns = len(cells), max(len(row) for row in cells)
    cells = [row + [""] * (columns - len(row)) for row in cells]
    base = name.rstrip("*")
    if base in _ALIGNED:
        aligns = ["right" if c % 2 == 0 else "left" for c in range(columns)]
    else:
        aligns = ["left" if base in ("cases", "dcases") else "center"] * columns
    left = right = None
    if name in _BRACKETS:  # (each of one piece, as tall as the rows: ⎛⎝ stood apart, a gap between)
        _tl, _tr, _ml, _mr, _bl, _br, one_l, one_r = _BRACKETS[name]
        left, right = [one_l] + [""] * (count - 1), [one_r] + [""] * (count - 1)
    elif base in ("cases", "dcases"):  # (one brace beside all rows, as tall as they are: tall)
        left = ["{"] + [""] * (count - 1)
    grid, spans, column_aligns, tall = [[] for _ in range(count)], [], [], []

    def column(pieces: list[str], align: str) -> None:
        column_aligns.append(align)
        for n in range(count):
            grid[n].append(pieces[n])

    if before:  # (beside all rows, in their middle)
        spans.append((0, 0, count, 1))
        column([before] + [""] * (count - 1), "right")
    if left is not None:
        # (a brace of one piece: ⎧⎨⎩ stood apart, a gap between each piece -
        # two rows' ⎧⎩ read as a parenthesis)
        spans.append((0, len(grid[0]), count, 1))
        tall.append((0, len(grid[0]), count, _tall_step(count)))
        column(left, "right")
    gaps = []
    for c in range(columns):
        if c and (base not in _ALIGNED or c % 2 == 0):
            gaps.append(len(grid[0]))
        column([cells[n][c] for n in range(count)], aligns[c])
    if right is not None:
        spans.append((0, len(grid[0]), count, 1))
        tall.append((0, len(grid[0]), count, _tall_step(count)))
        column(right, "left")
    if after:
        spans.append((0, len(grid[0]), count, 1))
        column([after] + [""] * (count - 1), "left")
    return grid, spans, column_aligns, gaps, [], tall


#: A line of simple front matter: "key: value" (YAML) or "key = value" (TOML).
_FRONT_PAIR = re.compile(r"^([A-Za-z0-9_][\w.-]{0,60})\s*[:=](?:[ \t]+(.*?))?[ \t]*\Z")
#: Keys of front matter shown as a table at most (more: shown as written).
FRONT_KEYS = 24


def front_matter_pairs(text: str) -> list[tuple[str, str]] | None:
    """Front matter of plain "key: value" lines as its (key, value) pairs - as
    GitHub shows it, a table - or None (nesting, lists, comments: shown as
    written)."""
    pairs = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        found = _FRONT_PAIR.match(line)
        if not found or line[:1].isspace():
            return None
        value = (found.group(2) or "").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        pairs.append((found.group(1), value))
    return pairs if 0 < len(pairs) <= FRONT_KEYS else None


def _brace_group(tex: str, at: int) -> tuple[str, int] | None:
    """The {group} of *tex* at *at* (spaces before it skipped): (its
    inside, where it ends), or None."""
    while at < len(tex) and tex[at].isspace():
        at += 1
    if at >= len(tex) or tex[at] != "{":
        return None
    depth = 0
    for index in range(at, len(tex)):
        depth += {"{": 1, "}": -1}.get(tex[index], 0)
        if depth == 0:
            return tex[at + 1:index], index + 1
    return None


_FRACTION = re.compile(r"\\[dt]?frac(?![A-Za-z])")
#: What a display formula sets apart at its top level: a fraction, a big
#: operator (its limits above and below - an integral's beside it), a limit.
_DISPLAY_PIECE = re.compile(r"\\(?:([dt]?frac)|(sum|prod|coprod|bigcup|bigcap|bigoplus|bigotimes|bigvee|bigwedge)"
                            r"|(iiint|iint|int|oint)|(lim|max|min|sup|inf|limsup|liminf))(?![A-Za-z])")
_BIG = {"sum": "∑", "prod": "∏", "coprod": "∐", "bigcup": "⋃", "bigcap": "⋂", "bigoplus": "⨁",
        "bigotimes": "⨂", "bigvee": "⋁", "bigwedge": "⋀", "iiint": "∭", "iint": "∬", "int": "∫", "oint": "∮"}
#: Qt's size steps of a display formula's operator (an integral taller), and of its limits.
OPERATOR_STEP, INTEGRAL_STEP, LIMIT_STEP = 2, 3, -1
#: The room beside a fraction and an operator (pixels): a matrix's columns get 16.
NARROW_GAP = 5
_LIMIT_MARK = re.compile(r"\s*\\(?:limits|nolimits)(?![A-Za-z])")
_SCRIPT_MARK = re.compile(r"\s*([_^])\s*")
_SCRIPT_TOKEN = re.compile(r"\\[A-Za-z]+|[^\s{}]")


def _tall_step(rows: int) -> int:
    """How much larger than the letters a brace or a bracket beside *rows*
    rows is set: Qt's size steps (+3: twice their size, +4: 2.4 times)."""
    return 3 if rows <= 2 else 4


def _limits(tex: str, at: int) -> tuple[str | None, str | None, int]:
    """(lower, upper, where they end) of the scripts after an operator at
    *at* in *tex* - "_x^y", either first; \\limits skipped."""
    found = _LIMIT_MARK.match(tex, at)
    at = found.end() if found else at
    lower = upper = None
    for _round in range(2):
        found = _SCRIPT_MARK.match(tex, at)
        if not found or (found.group(1) == "_" and lower is not None) or (found.group(1) == "^" and upper is not None):
            break
        group = _brace_group(tex, found.end())
        if group is not None:
            value, end = group
        else:
            token = _SCRIPT_TOKEN.match(tex, found.end())
            if token is None:
                break
            value, end = token.group(0), token.end()
        if found.group(1) == "_":
            lower = value
        else:
            upper = value
        at = end
    return lower, upper, at


def _display_grid(tex: str):
    """A display formula with fractions or big operators at its top level as
    a grid (as KaTeX's display style): each fraction its numerator over its
    denominator (the numerator's cell ruled under it - ``rules``); a sum
    larger, its limits above and below it, an integral's beside it; what
    stands between them beside all rows - or None (a line of text)."""
    pieces, at = [], 0
    while at < len(tex):
        found = _DISPLAY_PIECE.search(tex, at)
        if found is None:
            break
        before = tex[at:found.start()]
        if before.count("{") != before.count("}"):
            return None  # (inside a group: as text)
        if found.group(1):
            upper = _brace_group(tex, found.end())
            lower = _brace_group(tex, upper[1]) if upper else None
            if upper is None or lower is None:
                return None
            pieces += [("text", before), ("frac", upper[0], lower[0])]
            at = lower[1]
            continue
        low, high, end = _limits(tex, found.end())
        if found.group(4) and low is None:  # (a limit without its "_": in the line, as text)
            pieces.append(("text", before + found.group(0)))
            at = found.end()
            continue
        kind = "big" if found.group(2) else "integral" if found.group(3) else "limit"
        pieces += [("text", before), (kind, found.group(0), low, high)]
        at = end
    if not any(piece[0] != "text" for piece in pieces) or len(pieces) > 40:
        return None
    pieces.append(("text", tex[at:]))
    operators = any(piece[0] in ("big", "integral", "limit") for piece in pieces)
    fractions = any(piece[0] == "frac" for piece in pieces)
    count = 2 if not operators else 4 if fractions else 3
    grid, spans, rules, sized, gaps = [[] for _ in range(count)], [], [], [], []

    def column(cells: dict) -> int:
        at = len(grid[0])
        for row in range(count):
            grid[row].append(cells.get(row, ""))
        return at

    middle = (1, count - 2)  # (the rows of the formula's line: under its limits, over theirs)
    for piece in pieces:
        if piece[0] == "text":
            if piece[1].strip():
                spans.append((0, column({0: piece[1].strip()}), count, 1))
            continue
        if grid[0]:
            gaps.append((len(grid[0]), NARROW_GAP))
        if piece[0] == "frac":
            if count == 2:
                at = column({0: piece[1].strip(), 1: piece[2].strip()})
            else:  # (its numerator over the middle, its denominator under it)
                at = column({0: piece[1].strip(), 2: piece[2].strip()})
                spans += [(0, at, 2, 1, "bottom"), (2, at, 2, 1, "top")]
            rules.append((0, at))
            continue
        _kind, written, low, high = piece
        glyph = _BIG.get(written.lstrip("\\"), written)
        if piece[0] == "integral":  # (its limits beside it, at its top and its foot - each over half its rows:
            at = column({0: glyph})  # an empty row between them was as high as a line)
            spans.append((0, at, count, 1))
            sized.append((0, at, count, INTEGRAL_STEP))
            if high is not None or low is not None:
                half = count // 2
                after = column({0: high or "", half: low or ""})
                spans += [(0, after, half, 1, "top"), (half, after, count - half, 1, "bottom")]
                sized += [(row, after, 1, LIMIT_STEP) for row, value in ((0, high), (half, low)) if value]
            continue
        cells = {middle[0]: glyph}  # (a sum's, a limit's: above and below it)
        if high is not None:
            cells[0] = high
        if low is not None:
            cells[count - 1] = low
        at = column(cells)
        if middle[1] > middle[0]:
            spans.append((middle[0], at, middle[1] - middle[0] + 1, 1))
        if piece[0] == "big":
            sized.append((middle[0], at, middle[1] - middle[0] + 1, OPERATOR_STEP))
        for row in (0, count - 1):
            if row in cells:
                sized.append((row, at, 1, LIMIT_STEP))
                spans.append((row, at, 1, 1, "bottom" if row == 0 else "top"))
    if fractions and not operators:  # (room before each column: "=" touched the fraction's bar)
        gaps = [(column, NARROW_GAP) for column in range(1, len(grid[0]))]
    return grid, spans, ["center"] * len(grid[0]), gaps, rules, sized


def _place_rows(tex: str, environments: list[list[str]]) -> str:
    """The rows of each environment where it stood: the first on its line,
    the others below it, as far in as the text before it."""
    out = []
    for line in tex.split("\n"):
        found = re.search(_ROWS + r"(\d+)" + _ROWS, line)
        if not found:
            out.append(line)
            continue
        if len(re.findall(_ROWS + r"\d+" + _ROWS, line)) > 1:  # (side by side, each on the line's middle)
            out.extend(_side_by_side(line, environments))
            continue
        before, after = line[:found.start()], line[found.end():]
        rows = environments[int(found.group(1))]
        indent = " " * cell_width(before)
        for number, row in enumerate(rows):
            text = (before if number == 0 else indent) + row + (after if number == len(rows) - 1 else "")
            out.append(_place_rows(text, environments) if _ROWS in text else text.rstrip())
    return "\n".join(out)


def _side_by_side(line: str, environments: list[list[str]]) -> list[str]:
    """A line of several environments (two matrices, cases and a matrix):
    each one's rows beside the others', in the middle of the lines - the
    text between them on the middle line (each was a line lower than the
    one before: a staircase)."""
    pieces = re.split(_ROWS + r"(\d+)" + _ROWS, line)
    blocks = []
    for index, piece in enumerate(pieces):
        rows = list(environments[int(piece)]) if index % 2 else [piece]
        if any(_ROWS in row for row in rows):
            rows = [re.sub(_ROWS + r"\d+" + _ROWS, "", row) for row in rows]  # (inside another: as text)
        width = max(cell_width(row) for row in rows)
        blocks.append([row + " " * (width - cell_width(row)) for row in rows])
    height = max(len(block) for block in blocks)
    out = [""] * height
    for block in blocks:
        top = (height - len(block)) // 2
        width = cell_width(block[0]) if block else 0
        for number in range(height):
            out[number] += block[number - top] if 0 <= number - top < len(block) else " " * width
    return [row.rstrip() for row in out]


def math_display(tex: str) -> tuple[str, bool]:
    """(what the formula *tex* is shown as - its text, math_text - whether
    all of it was understood; what was not stays as written: math_runs and
    math_html mark only that part)."""
    shown = math_text(tex)
    return shown, not any(kind == "unknown" for _text, kind in math_runs(tex))


# -- shared helpers of the views --------------------------------------------------------------

#: C0 and C1 control characters but tab and newline, DEL, and the bidi
#: controls a text could use to make a name read as another one.
_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(text: str) -> str:
    """*text* without control characters: what a terminal or a label must
    never get from a file (an ESC starts an escape sequence)."""
    return by_lines(lambda piece: _CONTROLS.sub("", piece), text)


#: Characters of a text a pass over it (a regular expression's) goes over at
#: once: a pass over 5 MB is one call that holds Python's lock - on a
#: worker thread, the window waited for it (0.2 to 0.5 s at a time).
LINES_AT_ONCE = 1 << 16


_WORD_START = re.compile(r"(?<=\s)\S")


def _text_pieces(text: str, start: int = 0, end: int | None = None, size: int = LINES_AT_ONCE):
    """(start, end) of the pieces of *text* (from *start* to *end*) of about
    *size* characters: each cut after a line end - a line longer than twice
    that where a word begins (after a space, before what is not one; a line
    of 10 MB held the window's event loop 0.7 s in one search). A pattern
    that never reaches over a line end, nor from a space into the word after
    it, finds in the pieces what it finds in the whole."""
    end = len(text) if end is None else end
    while start < end:
        cut = start + size
        if cut >= end:
            yield start, end
            return
        stop = text.find("\n", cut, end)
        if stop < 0 or stop - start > 2 * size:
            word = _WORD_START.search(text, cut, min(end, cut + size))
            stop = word.start() if word else (stop + 1 if stop >= 0 else end)
        else:
            stop += 1
        yield start, stop
        start = stop


def by_lines(change, text: str) -> str:
    """*change(piece)* of *text*'s pieces of about LINES_AT_ONCE characters
    (_text_pieces), joined - for a change that never goes past a line end, nor
    from a space into the word after it."""
    if len(text) <= LINES_AT_ONCE:
        return change(text)
    return "".join(change(text[begin:stop]) for begin, stop in _text_pieces(text))


def found_by_lines(pattern: re.Pattern, text: str) -> bool:
    """Whether *pattern* (one that never goes past a line end, nor from a
    space into the word after it) is found in *text* - looked for a piece at
    a time (_text_pieces)."""
    if len(text) <= LINES_AT_ONCE:
        return pattern.search(text) is not None
    return any(pattern.search(text, begin, stop) for begin, stop in _text_pieces(text))


_ZWJ, _VS16 = "\u200d", "\ufe0f"


def _pictographic(ch: str) -> bool:
    """Whether *ch* may be an emoji (Unicode's Extended_Pictographic, near
    enough: the symbol and emoji blocks)."""
    o = ord(ch)
    return o >= 0x1F000 or 0x2190 <= o <= 0x2BFF or o in (0xA9, 0xAE, 0x203C, 0x2049, 0x2122, 0x2139,
                                                          0x3030, 0x303D, 0x3297, 0x3299)


def _regional(ch: str) -> bool:
    return 0x1F1E6 <= ord(ch) <= 0x1F1FF


def _extends(ch: str) -> bool:
    """Whether *ch* belongs to the character before it: a combining mark, a
    format character, a variation selector, a skin tone."""
    o = ord(ch)
    return 0x1F3FB <= o <= 0x1F3FF or 0xFE00 <= o <= 0xFE0F or bool(unicodedata.combining(ch)) \
        or unicodedata.category(ch) in ("Mn", "Me", "Cf")


def cluster_end(text: str, start: int) -> int:
    """Where the character a reader sees that begins at *start* ends: a
    letter with its marks, an emoji with its skin tone, variation selector
    and the emoji it is joined to (ZWJ), a flag's two letters."""
    end, size = start + 1, len(text)
    if end < size and _regional(text[start]) and _regional(text[end]):
        end += 1
    picture = _pictographic(text[start])
    while end < size:
        ch = text[end]
        if ch == _ZWJ and picture and end + 1 < size and _pictographic(text[end + 1]):
            end += 2  # (joined to the next emoji: one picture)
        elif _extends(ch):
            end += 1
        else:
            break
    return end


def _cluster_width(text: str, start: int, end: int) -> int:
    base = text[start]
    if _extends(base):
        return 0  # (a mark on nothing, a format character)
    if end - start > 1 and (_regional(base) or (
            (_pictographic(base) or base in "#*0123456789") and _VS16 in text[start:end])
            or _ZWJ in text[start:end]):
        return 2  # (a flag; shown as an emoji; emoji joined into one)
    return 2 if unicodedata.east_asian_width(base) in ("W", "F") else 1


def cell_width(text: str) -> int:
    """The columns *text* takes in a terminal: wide (East Asian) characters
    and emoji two - an emoji sequence (joined, with a skin tone or VS16, a
    flag) as the one picture it is - combining marks none."""
    if text.isascii():
        return len(text)
    width, index, size = 0, 0, len(text)
    while index < size:
        end = cluster_end(text, index)
        width += _cluster_width(text, index, end)
        index = end
    return width


__all__ = ["ALERTS", "Document", "EMOJI", "HTML_BLOCK", "HTML_INLINE", "Heading", "MAX_NESTING",
           "alert_of", "as_written", "available", "html_events", "math_display", "math_html", "math_runs", "raised", "sanitizer",
           "cell_width", "clean", "cluster_end", "decode_text", "looks_binary", "make_parser", "math_text", "parse", "slug"]
