"""A mail's HTML made safe to show: an allow-list of plain formatting tags,
no attributes but a link's address and a cell's span, no scripts, styles,
frames, forms, objects or images (an image becomes "[image: its alt text]"),
links only to http(s) and mailto - and every link shows where it really
goes beside its text ("Your bank [→ evil.example]"), which is the point of
looking at a suspicious mail. Nothing is fetched; the result is meant for
a viewer that loads no resource at all (ui/mail_project.py SafeBrowser).
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import SplitResult, urlsplit

ALLOWED = {"p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "a", "ul", "ol", "li", "table",
           "thead", "tbody", "tfoot", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
           "pre", "code", "hr", "small", "sub", "sup", "center", "font", "dl", "dt", "dd", "caption"}
DROP_WITH_CONTENT = {"script", "style", "head", "title", "iframe", "frame", "frameset", "object", "embed",
                     "applet", "noscript", "template", "svg", "math", "form", "select", "textarea", "button",
                     "video", "audio", "canvas", "link", "meta", "base"}
#: HTML's void elements (they never have an end tag): one of them must not
#: start a dropped region that only an end tag could close.
VOID = {"area", "base", "basefont", "bgsound", "br", "col", "command", "embed", "frame", "hr", "img", "input",
        "keygen", "link", "meta", "param", "source", "track", "wbr"}
#: The sanitised HTML is cut here - the escaped text counts, not the mail's
#: (``&#`` repeated grew four-fold on escaping: a 4 MB mail made 12.6 MB of
#: HTML, and the viewer's setHtml never came back).
MAX_OUTPUT = 2 * 1024 * 1024
#: What the formatted view (a QTextBrowser, which lays out the whole
#: document at once) is given of a message: its sanitised HTML up to this
#: many characters. A 4 MB plain-text mail of newlines kept the GUI thread
#: 24.6 s (509 MB), 6 MB of alternating Hebrew and Latin 20.7 s; the rest
#: is a click away in the plain view (:func:`message_view`).
MAX_SHOWN = 128 * 1024
#: The plain view (a QPlainTextEdit: it lays out only the lines on screen)
#: shows up to this many characters and lines of a message, every line
#: broken after :data:`PLAIN_LINE` characters - one long line is laid out
#: in quadratic time even there (40,000 mixed-direction characters: 3.7 s),
#: and each line costs memory and time to set (500,000 lines: 2.5 s).
MAX_PLAIN = 2 * 1024 * 1024
MAX_PLAIN_LINES = 100_000
PLAIN_LINE = 1000
#: Elements open at once; deeper ones are left out (keeps every end tag
#: cheap, and the viewer's layout shallow).
MAX_NESTING = 64
#: Tables open at once, and lists / quotes: Qt's layout of nested tables
#: grows exponentially with the depth - 21 nested tables in a 467-byte
#: mail kept the GUI thread busy for 25 s, 24 for minutes. A deeper one is
#: left out (its text stays, in the cell around it).
MAX_TABLE_DEPTH = 6
MAX_INDENT_DEPTH = 16
#: What the tables of one mail may cost the viewer's layout: each
#: character inside a table, and each cell (:data:`CELL_WORK`), counts
#: double for every table around it (Qt lays a nested table out again for
#: each one around it: 1 MB of text took 1 s in one table, 31 s in six).
#: Past it the tables end there and the rest is shown as text.
TABLE_WORK = 1_000_000
CELL_WORK = 64
#: The most rows or columns one cell may span; a larger span is cut to it.
#: Qt lays out the grid the spans make: ``colspan=99 rowspan=99`` cells
#: made a 4.7 KB mail's tables millions of grid cells (34 s of GUI
#: thread), and each cell of the grid counts (:class:`TableGrid`).
MAX_SPAN = 8
INDENT = {"ul", "ol", "dl", "blockquote"}
#: A word longer than this gets a break opportunity (a zero-width space)
#: every so many characters: Qt lays out one long word in quadratic time -
#: a 400,000-character word kept the GUI thread 10 s, 2 MB of "&#" (one
#: word once escaped) close to a minute.
MAX_WORD = 200
_SPACE = re.compile(r"(\s+)")
#: The parts of a table: without their table they are left out too.
TABLE_PARTS = {"thead", "tbody", "tfoot", "tr", "td", "th", "caption"}


def span(value) -> int:
    """The span a ``colspan`` / ``rowspan`` value asks for, cut to
    1..:data:`MAX_SPAN` (Qt reads a missing, zero or broken one as 1)."""
    value = (value or "").strip()
    if not value.isdigit() or not value.isascii():
        return 1
    return max(1, min(int(value[:4]), MAX_SPAN))


class TableGrid:
    """The cells Qt lays out for one table: its rows times its columns,
    the rows and columns the spans join included - also the empty cells
    that fill a short row up to the widest one (one row of 120 cells over
    1000 rows of one cell is a 120 x 1000 grid). An upper bound: a cell
    spanning rows keeps its columns in each row below it."""

    __slots__ = ("cols", "row", "rows", "spans", "width")

    def __init__(self) -> None:
        self.row = 0          # rows started
        self.rows = 0         # rows of the grid, spans included
        self.width = 0        # columns of the current row
        self.cols = 0         # columns of the grid
        self.spans: list[tuple[int, int]] = []   # (columns, rows still to cover) from rows above

    @property
    def size(self) -> int:
        return self.rows * self.cols

    def new_row(self) -> int:
        """Start a row; returns how many grid cells that added."""
        before = self.size
        self.row += 1
        self.spans = [(c, r - 1) for c, r in self.spans if r > 1]
        self.width = sum(c for c, _ in self.spans)
        self.rows = max(self.rows, self.row)
        self.cols = max(self.cols, self.width)
        return self.size - before

    def cell(self, colspan: int = 1, rowspan: int = 1) -> int:
        """Add a cell; returns how many grid cells that added."""
        added = self.new_row() if not self.row else 0    # a cell before any <tr>
        before = self.size
        self.width += colspan
        self.cols = max(self.cols, self.width)
        self.rows = max(self.rows, self.row - 1 + rowspan)
        if rowspan > 1:
            self.spans.append((colspan, rowspan))
        return added + self.size - before


def split_url(url: str) -> SplitResult | None:
    """``urlsplit(url)``, or None when it cannot be split: "https://[x"
    raises ValueError (an unclosed IPv6 bracket, a bad port), and one such
    link kept a whole mail out of the analysis and the safe view."""
    try:
        parts = urlsplit(url)
        parts.hostname, parts.port  # noqa: B018 - these raise ValueError too
    except ValueError:
        return None
    return parts


def breakable(text: str, run: int = 0) -> tuple[str, int]:
    """*text* with a zero-width space after every :data:`MAX_WORD`
    characters of a longer word (see there), and the length of the word it
    ends with; *run* is the length of the word before it (a word goes on
    across the pieces of text between tags: ``x<b>x</b>x``)."""
    if run + len(text) <= MAX_WORD and not _SPACE.search(text):
        return text, run + len(text)
    out = []
    for token in _SPACE.split(text):
        if not token:
            continue
        if token[0].isspace():
            out.append(token)
            run = 0
            continue
        if run + len(token) > MAX_WORD:
            cut = MAX_WORD - run
            pieces = [token[:cut]] + [token[i:i + MAX_WORD] for i in range(cut, len(token), MAX_WORD)]
            token = "\u200b".join(pieces)
            run = len(pieces[-1])
        else:
            run += len(token)
        out.append(token)
    return "".join(out), run


def hidden_chars(text: str) -> bool:
    """*text* holds format characters (Unicode Cf: bidi overrides and
    isolates, zero-width spaces and joiners), which show an address in
    another order or hide part of it."""
    return any(unicodedata.category(c) == "Cf" for c in text)


def strip_hidden(text: str) -> str:
    """*text* without its format characters (see :func:`hidden_chars`)."""
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


class _Sanitiser(HTMLParser):
    def __init__(self, limit: int = MAX_OUTPUT) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.size = 0
        self.limit = limit
        self.cut = False                    # text was left out at the limit
        self.skip = 0                       # inside a dropped element
        self.stack: list[str] = []
        self.link_target: list[str] = []
        self.open = {"table": 0, "indent": 0}     # open tables, open lists and quotes
        self.table_work = 0
        self.grids: list[TableGrid] = []           # one per open table, the innermost last
        self.cell_span = (1, 1)                    # (colspan, rowspan) of the cell starting
        self.flat = False                          # the tables ended: text only
        self.refused: dict[str, int] = {}          # elements left out, still open
        self.run = 0                               # length of the word shown last

    def _emit(self, text: str, *, closing: bool = False) -> None:
        # end tags of open elements always go out: the output stays balanced
        if closing:
            self.out.append(text)
            self.size += len(text)
            return
        room = self.limit - self.size
        if room <= 0:
            self.cut = True
            return
        if self.open["table"]:
            self._table_work(len(text))
        if len(text) > room:
            self.cut = True
            # Cut to what is left - the escaped text counts - and never in
            # the middle of a character reference or a tag.
            text = text[:room]
            for start, end in (("&", ";"), ("<", ">")):
                cut = text.rfind(start)
                if cut != -1 and end not in text[cut:]:
                    text = text[:cut]
        self.out.append(text)
        self.size += len(text)

    def _table_work(self, units: int) -> None:
        """Count *units* of work inside the open tables; past
        :data:`TABLE_WORK` every open table ends here."""
        self.table_work += units << (self.open["table"] - 1)
        if self.table_work > TABLE_WORK:
            self.flat = True
            while self.open["table"]:
                self._pop()

    def _refuse(self, tag: str) -> None:
        """Leave out the element *tag* (its text stays) - and its end tag."""
        self.refused[tag] = self.refused.get(tag, 0) + 1

    def _too_deep(self, tag: str) -> bool:
        if len(self.stack) >= MAX_NESTING:
            return True
        if tag == "table":
            return self.flat or self.open["table"] >= MAX_TABLE_DEPTH
        if tag in INDENT:
            return self.open["indent"] >= MAX_INDENT_DEPTH
        if tag in TABLE_PARTS:
            # the parts of a table left out, or of none at all
            if self.refused.get("table") or not self.open["table"]:
                return True
            if tag in ("td", "th", "tr"):
                # each cell of the grid counts, the ones a span makes too
                grid = self.grids[-1]
                cells = grid.new_row() if tag == "tr" else grid.cell(*self.cell_span)
                self._table_work(CELL_WORK * (1 + cells))
                return not self.open["table"]
        return False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT:
            if tag not in VOID:
                self.skip += 1       # only these count: their end tags count down
            return
        if self.skip:
            return
        if tag == "img":
            alt = next((v for k, v in attrs if k.lower() == "alt" and v), "")
            self._emit(html.escape(f"[image: {alt}]" if alt else "[image]"))
            return
        if tag not in ALLOWED:
            return
        if tag in ("td", "th"):
            spans = {k.lower(): span(v) for k, v in attrs if k.lower() in ("colspan", "rowspan")}
            self.cell_span = (spans.get("colspan", 1), spans.get("rowspan", 1))
        if tag not in VOID and self._too_deep(tag):
            self._refuse(tag)
            return
        kept = ""
        if tag == "a":
            raw = next((v for k, v in attrs if k.lower() == "href" and v), "").strip()
            # A bidi override in the address would show the target label
            # below in another order: removed, and the label says so.
            href = strip_hidden(raw)
            note = " (hidden characters removed)" if href != raw else ""
            parts = split_url(href)
            if parts is None:
                self.link_target.append(("", "malformed link - not followed"))
            elif parts.scheme.lower() in ("http", "https", "mailto"):
                kept = f' href="{html.escape(href, quote=True)}"'
                host = parts.hostname or (href[7:] if href.lower().startswith("mailto:") else "")
                self.link_target.append((href, (host or "not a web address") + note))
            else:
                self.link_target.append(("", "not a web address"))
        elif tag in ("td", "th"):
            for name, value in zip(("colspan", "rowspan"), self.cell_span):
                if value > 1:
                    kept += f' {name}="{value}"'
        self._emit(f"<{tag}{kept}>")
        if tag not in VOID:
            self.stack.append(tag)
            self._count(tag, 1)

    def _count(self, tag: str, step: int) -> None:
        if tag == "table":
            self.open["table"] += step
            if step > 0:
                self.grids.append(TableGrid())
            else:
                self.grids.pop()
        elif tag in INDENT:
            self.open["indent"] += step

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT or self.skip:
            return                   # <svg/> is empty: it starts no dropped region
        depth, refused = len(self.stack), self.refused.get(tag, 0)
        self.handle_starttag(tag, attrs)
        if tag not in VOID and len(self.stack) > depth:
            self._pop()
        elif self.refused.get(tag, 0) > refused:
            self.refused[tag] -= 1       # <table/> left out: no end tag follows

    def _pop(self) -> str:
        """Close the innermost open element."""
        open_tag = self.stack.pop()
        self._count(open_tag, -1)
        if open_tag == "a":
            _target, label = self.link_target.pop() if self.link_target else ("", "not a web address")
            self._emit(f"</a> <small>[&#8594; {html.escape(strip_hidden(label))}]</small>", closing=True)
        else:
            self._emit(f"</{open_tag}>", closing=True)
        return open_tag

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip:
            if tag in DROP_WITH_CONTENT and tag not in VOID:   # </embed> closes nothing
                self.skip -= 1
            return
        if self.refused.get(tag):
            # the end of an element left out (the innermost one of the name
            # is the one it closes): an element kept stays open
            self.refused[tag] -= 1
            return
        if tag in TABLE_PARTS and self.refused.get("table"):
            return                   # inside a table left out: its parts were too
        if tag not in self.stack:
            return
        while self.stack and self._pop() != tag:
            pass

    def handle_data(self, data):
        if not self.skip:
            data, self.run = breakable(data, self.run)
            self._emit(html.escape(data))

    def close(self):
        super().close()
        self.skip = 0                # a dropped element never closed ends with the text
        while self.stack:
            self._pop()


class _Links(HTMLParser):
    """Every <a href> with its text, as a browser reads them: an <a> ends at
    its end tag, at the next <a> or at the end of the text."""

    def __init__(self, limit: int, text_limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit, self.text_limit = limit, text_limit
        self.found: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._size = 0

    def _end(self) -> None:
        if self._href is not None and len(self.found) < self.limit:
            self.found.append((self._href, "".join(self._text)))
        self._href, self._text, self._size = None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        self._end()
        href = next((v for k, v in attrs if k.lower() == "href" and v is not None), None)
        self._href = href

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() == "a":
            self._end()

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self._end()

    def handle_data(self, data):
        if self._href is not None and self._size < self.text_limit:
            self._text.append(data[:self.text_limit - self._size])
            self._size += min(len(data), self.text_limit - self._size)

    def close(self):
        super().close()
        self._end()


def links(text: str, *, limit: int = 100_000, text_limit: int = 4096) -> list[tuple[str, str]]:
    """(href, text) of the first *limit* links of an HTML text, both
    unescaped. One pass of the parser: the time grows with the length and
    nothing else (core.mail_analyse used a regular expression that took
    minutes for a few hundred KB of unclosed <a>)."""
    p = _Links(limit, text_limit)
    _feed(p, text or "", lambda: len(p.found) >= limit)
    return p.found


_CHUNK = 64 * 1024


def _feed(parser: HTMLParser, text: str, done) -> bool:
    """*text* in pieces, until *done()* says the rest is not needed; True
    when some was left out so."""
    stopped = False
    for start in range(0, len(text), _CHUNK):
        if done():
            stopped = True
            break
        parser.feed(text[start:start + _CHUNK])
    parser.close()
    return stopped


def _sanitised(text: str, limit: int) -> tuple[str, bool]:
    """(*text* sanitised up to *limit* characters, whether some was left out)."""
    p = _Sanitiser(limit)
    text = text or ""
    if _feed(p, text, lambda: p.size >= limit):
        p.cut = True
    return "".join(p.out), p.cut


def sanitise(text: str, limit: int = MAX_OUTPUT) -> str:
    return _sanitised(text, limit)[0]


def message_html(msg) -> str:
    """The message as safe HTML for the formatted view: its HTML part
    sanitised, else its text - either up to :data:`MAX_SHOWN` characters."""
    return message_view(msg).html or _pre(msg.text or "")[0]


def _pre(text: str) -> tuple[str, bool]:
    shown = text[:MAX_SHOWN]
    return "<pre>" + html.escape(shown) + "</pre>", len(shown) < len(text)


class _Text(HTMLParser):
    """The text of an HTML part, a line per paragraph, cell or line break."""

    BLOCK = {"p", "br", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "table",
             "blockquote", "pre", "dt", "dd"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.size = 0
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in DROP_WITH_CONTENT and tag not in VOID:
            self.skip += 1
        elif tag in self.BLOCK:
            self._add("\n")
        elif tag in ("td", "th"):
            self._add("\t")

    def handle_startendtag(self, tag, attrs):
        if tag in self.BLOCK:
            self._add("\n")

    def handle_endtag(self, tag):
        if tag in DROP_WITH_CONTENT and tag not in VOID:
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self._add("\n")

    def handle_data(self, data):
        if not self.skip:
            self._add(data)

    def _add(self, text: str) -> None:
        self.out.append(text)
        self.size += len(text)


def html_text(text: str, limit: int = MAX_PLAIN) -> str:
    """The text of an HTML part (no tag, nothing dropped by the sanitiser),
    about *limit* characters of it at most."""
    p = _Text()
    _feed(p, text or "", lambda: p.size >= limit)
    return re.sub(r"\n{3,}", "\n\n", "".join(p.out)).strip("\n")


def plain_lines(text: str) -> tuple[str, bool]:
    """*text* for the plain view: every line broken after
    :data:`PLAIN_LINE` characters, at most :data:`MAX_PLAIN` characters
    and :data:`MAX_PLAIN_LINES` lines; and whether some was left out."""
    out: list[str] = []
    cut = False
    for line in text[:MAX_PLAIN].split("\n"):
        pieces = [line[i:i + PLAIN_LINE] for i in range(0, len(line), PLAIN_LINE)] or [""]
        if len(out) + len(pieces) > MAX_PLAIN_LINES:
            out.extend(pieces[:MAX_PLAIN_LINES - len(out)])
            cut = True
            break
        out.extend(pieces)
    cut = cut or len(text) > MAX_PLAIN
    return "\n".join(out), cut


@dataclass(frozen=True)
class MessageView:
    """A message as the viewer shows it.

    *html* - sanitised HTML for the formatted view (None for a plain-text
    mail: it goes to the plain view, which lays out only what is on
    screen); *cut* - the formatted view holds only the start of the
    message; *plain* - the plain view's text (the text part, else the HTML
    part's text); *plain_cut* - even that holds only the start."""

    html: str | None
    cut: bool
    plain: str
    plain_cut: bool


def message_view(msg) -> MessageView:
    """The message for the viewer: an HTML part sanitised for the
    formatted view up to :data:`MAX_SHOWN` characters, and its text for
    the plain view (:func:`plain_lines`)."""
    text = msg.text or ""
    if msg.html:
        shown, cut = _sanitised(msg.html, MAX_SHOWN)
        plain, plain_cut = plain_lines(text if text.strip() else html_text(msg.html))
        return MessageView(shown, cut, plain, plain_cut)
    plain, plain_cut = plain_lines(text)
    return MessageView(None, False, plain, plain_cut)
