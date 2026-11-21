"""The Markdown view: a file rendered as Markdown (CommonMark and GitHub's
tables, task lists, strikethrough and autolinks; footnotes made into links),
its headings in an outline beside it to jump to (the heading being read
marked in it as the text scrolls), fenced code highlighted, images beside
the file shown - fitted to the width, a click shows one at its own size
(:class:`ImageZoom`) - zoom, Back / Forward after a jump (Alt+Left /
Alt+Right, the mouse's back button). The theme follows the palette.

Ported from sandbox-ai's Files page (``sandbox_ai_app/markdown_view.py``,
MIT, the same author) to PyQt6 and axross' backends. Used by the Markdown
viewer window (:mod:`ui.markdown_viewer`) and the editor's live preview.

What is shown may have been written by anyone (a remote server, an agent,
a download), so it is untrusted:

- Qt renders it (``QTextDocument.setMarkdown``) **without HTML**: tags are
  shown as the text they are, nothing runs, no script, no style sheet, no
  frame;
- **nothing is loaded from the network**, ever: a remote image is a
  placeholder that names its URL; the browser's own loading is replaced
  (:meth:`MarkdownBrowser.loadResource` answers from what this module read,
  nothing else);
- an **image beside the file** is read through the file's backend, relative
  to the file's folder - in it or in a folder below it, never above it
  (``../``) nor, on this computer, through a symlink that leads elsewhere;
  never an absolute path, ``file:`` or any other scheme - in a thread,
  only a regular file, never a secret file
  (:func:`core.protected_places.read_refusal` on the local file system), at
  most :data:`IMAGE_LIMIT` bytes and :data:`IMAGE_PIXELS` pixels, at most
  :data:`IMAGES` of them and :data:`IMAGES_PIXELS` pixels together; Reload
  reads them again; an SVG image that names anything but a part of itself
  is not shown (Qt's SVG reader would read the files it names:
  :func:`svg_refers`);
- what Qt cannot lay out in time is shown as written, where it stands: the
  rows of a table past :data:`TABLE_CELLS` cells, the items of a list past
  :data:`LIST_ITEMS`, a line of :data:`LONG_RUN` characters without a space
  - and it says so (:func:`renderable`); a big page is laid out in parts, the
  window answers between them (:data:`PART_BLOCKS`);
- a link is never followed inside the view: ``#heading`` scrolls there,
  anything else goes to the window (:attr:`MarkdownView.link`), which
  decides.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import logging
import os
import posixpath
import re
import stat as _stat
import sys
import threading
import time
import unicodedata

from PyQt6 import sip
from PyQt6.QtCore import (
    QBuffer,
    QByteArray,
    QEvent,
    QIODevice,
    QMimeData,
    QObject,
    QPoint,
    QRect,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QColor,
    QFont,
    QImage,
    QImageReader,
    QKeySequence,
    QPainter,
    QPalette,
    QPixmap,
    QShortcut,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QTextDocumentFragment,
    QTextFormat,
    QTextListFormat,
)
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import svg_gate, svg_worker
from core.i18n import tr
from ui.markdown_html import _PICTURE_SIGNS, ANCHORS, CHIP, CODE_PART_LINES, CONTINUED, FOLD, picture_weight, \
    piece_floor
from ui.markdown_safe import _MARK, NOTES_MARKDOWN, _escape_html, _unmark

log = logging.getLogger(__name__)

SUFFIXES = (".md", ".markdown", ".mdown", ".mkd")
#: GitHub's dialect without raw HTML. Not ``GitHub | NoHTML``: on Python
#: 3.11 that union lost every bit (it was CommonMark *with* raw HTML) -
#: ui.update_ui builds it by value. Safety does not rest on the flags
#: alone: every ``<`` is escaped before parsing (_escape_html) and the mark
#: taken out after (_unmark), as for the release notes.
FEATURES = NOTES_MARKDOWN
#: Bytes of the Markdown text that are read (the rest is said to be cut).
TEXT_LIMIT = 8 << 20
IMAGE_LIMIT = 8 << 20  # bytes of one image
IMAGE_PIXELS = 40_000_000  # pixels of one image (a small file may say it is huge)
#: Pixels of all the images of one document together (until Reload): each
#: one is bounded, but a small PNG of 36 million pixels named 200 times
#: ("big.png?1", "./big.png", ...) was decoded 200 times - 28 GB.
IMAGES_PIXELS = 100_000_000
IMAGES = 200  # images of one document that are read
RENDER_DELAY = 300  # ms: the live preview follows the typing after this pause
#: A text longer than this is parsed on a worker thread (markdown-it is pure
#: Python: about a megabyte a second - a page of 60 KB held the window 0.15 s
#: on top of Qt's own work), the window shows "Rendering…" meanwhile. As
#: short as the one with formulas: some texts cost markdown-it far more than
#: their size ("#\n" 9,500 times, 19 KB: 0.23 s), and the editor's preview
#: parses at every pause in the typing (20,000 characters were parsed on the
#: GUI thread: 19 KB of "<!--" or "http:// " 0.8 to 0.9 s).
BACKGROUND_CHARS = 2_000
#: ... and a text with formulas longer than this.
MATH_BACKGROUND_CHARS = 2_000
#: ... and a text of more brackets than this, however short: markdown-it
#: reads brackets inside each other in time that grows with their square
#: ("[" 5,000 deep around "~x~": 0.3 s of the GUI thread's, 1.1 s held).
BRACKETS_BACKGROUND = 500
#: Seconds a message the view said before a page is made anew is said again after it (MarkdownView.say).
SAID_KEPT = 3.0
#: What Qt lays out in time (renderable): it lays out a table or a list in
#: one piece on the GUI thread, in time that grows with its cells or items
#: (a table of 90 rows x 1,000 columns: 10 s), and wraps a line without a
#: space in time that grows with its square (1 MB: over a minute). What goes
#: past one of these is shown as written (the editor shows it as it is).
#: Measured (2026-11, Qt 6.11, a 10 ms timer's longest gap while the page is
#: shown and scrolled to its end): a table of 3,000 cells about 0.2 s (Qt's
#: own parser's parts are joined as they come in: :data:`MD4C_TABLE_CELLS`
#: for about the same), a list of 3,000 items 0.19 s.
LIST_ITEMS = 3000
#: A long list is laid out in lists of this many items (each a part of the
#: page; the line between them as low as it gets): a part of 3,000 held the
#: window up to 1 s once the page had grown.
LIST_PART = 300
#: ... or of about so many lines (an item's code, its paragraphs count).
LIST_PART_LINES = 600
TABLE_CELLS = 900
MD4C_TABLE_CELLS = 300
#: Columns of a table above which a part holds fewer cells - in proportion.
WIDE_TABLE = 16
#: A page with more than this many blocks (paragraphs, items, cells) is laid
#: out in parts, one an event-loop turn (MarkdownView._show_page): Qt lays out
#: what it is given on the GUI thread, about 40 µs a block.
PART_BLOCKS = 200
#: A page is laid out at once (a part an event-loop turn) up to about this
#: many blocks; the rest as it is scrolled to (MarkdownView._laid): each part
#: put in took longer as the page grew - a list of 100,000 items held the
#: window 2.5 s at a time, 23 s before it could be read.
EAGER_BLOCKS = 4_000
#: ... or so many parts (each of a few blocks: a long paragraph's pieces - 100,000
#: images, each a frame of Qt's: each part took longer than the one before).
EAGER_PARTS = 60
#: The most pixels a block standing in for parts not laid out yet is high:
#: Qt lays out no block past 8,388,607 pixels (its fixed-point maximum) - a
#: page of 100,000 headings stood in for by 9 million showed nothing of its
#: end after Ctrl+End. (The scroll bar is less exact there: no matter.)
STAND_IN_PIXELS = 2_000_000.0
#: Milliseconds between two parts (the window's own events come between).
PART_PAUSE = 5
#: A place this many parts beyond what is laid out (a drop of the scroll bar,
#: find, an anchor, Ctrl+End): its part laid out first, the ones between
#: as they are scrolled to - laid out one after another, 95 % of a
#: 1 MB page took 6 s.
JUMP_PARTS = 2
LONG_RUN = 100_000  # characters without a space
LONG_WORD = re.compile(r"(?<!\S)\S{%d}" % LONG_RUN)  # (from where a run begins only: never quadratic)
#: A list item - or a footnote's definition: the notes are a list on the
#: page (markdown-it), numbered by Qt as any other (50,000 notes held up the
#: window for minutes).
LIST_ITEM = re.compile(r"^[ \t>]*(?:(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)|\[\^[^\]\s]+\]:)")
REMOTE = ("http", "https", "ftp", "ftps", "ws", "wss", "smb", "sftp", "ssh")
#: Characters of a name shown in a status line or placeholder.
SHOWN_CHARS = 300


def _t(text: str, **values) -> str:
    """*text* translated, then filled in with *values*."""
    out = tr(text)
    return out.format(**values) if values else out


def printable(value) -> str:
    """*value* as one line of text that shows what it is: control and format
    characters (line breaks, bidi overrides, zero-width ones) written as
    ``\\uXXXX``, at most :data:`SHOWN_CHARS` characters."""
    text = str(value)
    if len(text) > SHOWN_CHARS:
        text = text[:SHOWN_CHARS] + "…"
    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")
                   else c for c in text)


def is_markdown(name) -> bool:
    """Whether the file *name* is Markdown by its name (.md, .markdown,
    .mdown, .mkd; any case)."""
    return str(name).lower().endswith(SUFFIXES)


def slug(text: str) -> str:
    """The anchor GitHub gives a heading: lower case, punctuation dropped,
    spaces as dashes."""
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
NOTE_DEFINITION = re.compile(r"^ {0,3}\[\^([^\]\s]+)\]:\s?(.*)\Z")  # (a list item's: indented a little)
#: (no "[" in a label: from each "[^" of "[^[^[^…" the label was looked for to the line's end - 40 KB of them 3.9 s)
NOTE_REFERENCE = re.compile(r"\[\^([^\]\[\s]+)\](?!:)")


_BACKTICK_RUN = re.compile(r"`+")


def code_span_bounds(line: str) -> list[tuple[int, int]]:
    """Where *line*'s code spans are, as (start, end): a run of backticks (not escaped) to the next run
    of the same length, a run without one left as text (CommonMark). In one pass: the runs found once,
    by their length, each length's next run kept - a regex that tried each length from each backtick
    was cubic ("x " and 1,200 backticks held the window 11.7 s; on a worker thread too, re holding the
    GIL through one search)."""
    if "`" not in line:
        return []
    runs = [(run.start(), run.end()) for run in _BACKTICK_RUN.finditer(line)]
    by_length: dict[int, list[int]] = {}
    for number, (start, end) in enumerate(runs):
        by_length.setdefault(end - start, []).append(number)
    taken = dict.fromkeys(by_length, 0)
    spans, number, text_from = [], 0, 0
    while number < len(runs):
        start, end = runs[number]
        lead = start
        while lead > text_from and line[lead - 1] == "\\":
            lead -= 1
        if (start - lead) % 2:
            start += 1  # (its first backtick escaped: the run one shorter)
        closers = by_length.get(end - start)
        if closers is not None:
            at = taken[end - start]
            while at < len(closers) and closers[at] <= number:
                at += 1
            taken[end - start] = at
            if at < len(closers):
                closer = closers[at]
                spans.append((start, runs[closer][1]))
                text_from = runs[closer][1]
                number = closer + 1
                continue
        number += 1
    return spans
#: A note's block of the page (with_footnotes): its letters smaller, muted.
NOTE_BLOCK = "\ue098"


def with_footnotes(text: str) -> tuple[str, list[str]]:
    """*text* with its footnotes ("text[^b]", "[^b]: the note") as GitHub
    shows them, for Qt's own parser: numbered in the order they are referred
    to (in the text, and in a note where it stands), a reference a
    superscript link "[1]" to "#fn-1", the notes at the end, each "1." and a
    way back to each place it is referred to - a note no text refers to left
    out, its indented lines part of it; a reference to no note (none, or one
    "defined" in code only) left as written, as GitHub does - it was a
    number leading nowhere. Nothing in fenced code or a code span changes.
    Returns the notes' numbers too."""
    if "[^" not in text:
        return text, []  # (no note and no reference to one: nothing to do)
    rows = text.split("\n")
    notes: dict[str, str] = {}
    blocks_after: dict[str, list] = {}
    kinds = []  # (each row: ("fence"|"text", line) or ("note", label, its text))
    fence, index = None, 0
    while index < len(rows):
        line = rows[index]
        index += 1
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            kinds.append(("fence", line))
            continue
        if opened:
            fence = opened.group(1)
            kinds.append(("fence", line))
            continue
        definition = NOTE_DEFINITION.match(line)
        if definition:
            label, note = definition.groups()
            label = label.casefold()  # (GitHub matches a note's label case aside: [^A] is [^a]'s)
            more = []
            while index < len(rows) and (rows[index][:4] == "    " or rows[index][:1] == "\t"
                                         or (not rows[index].strip() and index + 1 < len(rows)
                                             and rows[index + 1][:4] == "    ")):
                more.append(rows[index][4:] if rows[index][:4] == "    " else rows[index].lstrip("\t"))
                index += 1
            if any(not row.strip() or FENCE.match(row) or TABLE_DELIMITER.match(row) or row.startswith(("    ", "<"))
                   or LIST_ITEM.match(row) for row in more):
                # (blocks of its own - a fenced block, a table: as they are, after its first line - joined
                # into it, 600 KB of code was one line of text)
                blocks_after[label] = more
            else:
                note += "".join(" " + row.strip() for row in more)  # (its indented lines: part of it)
            if label not in notes:
                notes[label] = note.strip()
                kinds.append(("note", label))
            continue
        kinds.append(("text", line))
    numbers: dict[str, str] = {}
    referred_to: dict[str, int] = {}

    def reference(match: re.Match) -> str:
        label = match.group(1).casefold()
        if label not in notes:
            return match.group(0)  # (no such note: as written)
        shown = numbers.setdefault(label, str(len(numbers) + 1))
        referred_to[label] = referred_to.get(label, 0) + 1
        return f"[{_open('sup')}\\[{shown}\\]{_close('sup')}](#fn-{shown})"

    def referred(line: str) -> str:
        out, at = [], 0
        for start, end in code_span_bounds(line):
            out.append(NOTE_REFERENCE.sub(reference, line[at:start]))
            out.append(line[start:end])
            at = end
        out.append(NOTE_REFERENCE.sub(reference, line[at:]))
        return "".join(out)

    lines, shown_notes = [], {}
    for kind in kinds:
        if kind[0] == "fence":
            lines.append(kind[1])
        elif kind[0] == "text":
            lines.append(referred(kind[1]))
        else:  # (a note's own references: numbered where it stands, as one parse of all of it numbers them)
            shown_notes[kind[1]] = referred(notes[kind[1]])
    used = sorted((label for label in notes if label in numbers), key=lambda label: int(numbers[label]))
    if used:
        last = next((line for line in reversed(lines) if line.strip()), "")
        # (a text ending in a rule: that one before its notes - two in a row were drawn)
        lines += [""] if re.fullmatch(r" {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*", last) else ["", "---", ""]
        for label in used:
            number = numbers[label]
            # (a way back to each place it is referred to: read_outline names them fnref-1, fnref-1-2, ...)
            back = " ".join(f"[↩](#fnref-{number}{'' if count == 1 else f'-{count}'})"
                            for count in range(1, referred_to.get(label, 1) + 1))
            lines += [f"{NOTE_BLOCK}{number}\\. {shown_notes.get(label, notes[label])} {back}", ""]
            if label in blocks_after:
                lines += [*blocks_after[label], ""]
    return "\n".join(lines), [numbers[label] for label in used]


#: A table's delimiter row ("|---|:-:|"): what makes the line above it a table.
TABLE_DELIMITER = re.compile(r"^ {0,3}\|?\s*:?-+:?\s*(?:\|\s*:?-+:?\s*)*\|?\s*$")
#: A footnote's definition (all of them are one list on the page).
NOTE_LINE = re.compile(r"^[ \t>]*\[\^[^\]\s]+\]:")
#: An image's data: address - no text Qt wraps, never "a long word".
DATA_IMAGE = re.compile(r"data:image/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]*")


def _as_written(lines: list[str]) -> list[str]:
    """*lines* as a fenced block that shows them as they are written - a line longer than LINE_CAP in lines
    of that many, as a code block's own (_capped_lines): a table of 200,000 columns shown as written was a
    code line of 800,000 characters, laid out in one turn of 4.6 s."""
    longest = max((len(run) for line in lines for run in re.findall(r"`{3,}", line)), default=2)
    fence = "`" * (longest + 1)
    shown = [line[at:at + LINE_CAP] for line in lines for at in range(0, max(1, len(line)), LINE_CAP)]
    return ["", fence + "text", *shown, fence, ""]


def _cells(row: str) -> int:
    """The cells of a table's row (its delimiter row: the columns)."""
    return max(1, row.strip().strip("|").count("|") + 1)


#: A link's reference definition ("[name]: https://…"): every part of a text
#: given to Qt's own parser in parts gets them all (they may be anywhere).
REFERENCE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*\S")
#: A line of "---" (or "+++"): no part may begin with one - Qt read a text
#: beginning so as front matter up to the next, a section or more gone.
FRONT_LINE = re.compile(r"^ {0,3}(?:-{3,}|\+{3,})[ \t]*\Z")
#: Lines of a part of a text Qt's own parser is given at once (markdown_parts).
PART_LINES = 90
#: ... or of about so many characters (long lines: one part of README.md was 45 KB, 0.27 s)
PART_CHARS = 4_500


def code_blocks(text: str) -> tuple[str, list[str]]:
    """(*text* with a line that is no code between two code blocks of the top
    level that follow each other - Qt's own parser joined them into one - and
    the code blocks of the text as they are written, in order: fenced ones,
    in a quote or a list too, and indented ones)."""
    from ui.markdown_safe import _CONTAINERS

    rows, out, blocks = text.split("\n"), [], []
    fence, inset, body, indented = None, 0, [], None
    last_code = in_list = False

    def end_indented() -> None:
        nonlocal indented, last_code
        while indented and not indented[-1].strip():
            indented.pop()  # (the empty lines after it are no part of it)
        blocks.append("\n".join(r[4:] if r.startswith("    ") else r[1:] for r in indented) + "\n")
        indented, last_code = None, True

    for number, line in enumerate(rows):
        if fence is not None:
            inner = line[inset:]
            closing = FENCE.match(inner)
            if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence) \
                    and not inner.strip().strip(fence[0]):
                blocks.append("".join(row + "\n" for row in body))
                fence, last_code = None, True
            else:
                body.append(inner)
            out.append(line)
            continue
        if indented is not None:
            if line.startswith(("    ", "\t")) or not line.strip():
                indented.append(line)
                out.append(line)
                continue
            end_indented()
        prefix = _CONTAINERS.match(line).end() if line.strip() else 0
        whitespace = not line[:prefix].strip()
        opened = None if whitespace and prefix >= 4 else FENCE.match(line[prefix:])
        top = whitespace and prefix < 4
        if opened:
            if last_code and top:
                out += ["\u200b", ""]  # (no code: the two blocks stay two - a line as low as it gets)
            fence, inset, body = opened.group(1), prefix, []
            out.append(line)
            continue
        if line.startswith(("    ", "\t")) and not in_list and (number == 0 or not rows[number - 1].strip()):
            if last_code:
                out += ["\u200b", ""]
            indented = [line]
            out.append(line)
            continue
        if line.strip():
            last_code = False
            if LIST_ITEM.match(line):
                in_list = True
            elif line[:1] not in " \t":
                in_list = False
        out.append(line)
    if indented is not None:
        end_indented()
    if fence is not None:
        blocks.append("".join(row + "\n" for row in body))
    return "\n".join(out), blocks




#: A heading "# …": a new block even right after a line of text (a part may begin there - 100,000
#: headings in a row were one part of Qt's own parser's page: 7 s).
_ATX_HEADING = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")


#: A thematic break ("---", "***", "___", spaced or not).
_THEMATIC = re.compile(r" {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*\Z")
#: A setext heading's line under its text ("===", "---"), at most three spaces in.
_UNDERLINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*\Z")


def block_ends(rows: list[str]) -> bytearray:
    """Which of *rows* (a text's lines for Qt's own parser) end a block of the
    page's top level so that a line of text right after them begins a new one,
    with no empty line between: an ATX heading, a setext heading's line under
    its text, a thematic break, a fenced code block's closing line, a link's
    reference definition (or a run of them) - not indented, never in front
    matter, a quote, a list, a table or raw HTML (1 for those, 0 else). A
    part of the page may begin after them (markdown_parts), a paragraph's
    pieces too (paragraph_pieces): 50,000 setext headings in a row, a long
    paragraph under a heading, a fence or a definition were one part, 1 to 4 s."""
    ended = bytearray(len(rows))
    at = 0
    if rows and FRONT_LINE.match(rows[0]):  # (front matter: nothing in it ends a block)
        at = next((k for k in range(1, len(rows)) if FRONT_LINE.match(rows[k])), len(rows)) + 1
    fence, top_fence, para = None, False, None  # para: None no paragraph open, True one of the top level, False else
    for number in range(at, len(rows)):
        line = rows[number]
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line.strip().strip(fence[0]):
                fence = None
                ended[number] = top_fence
            continue
        if not line.strip():
            para = None
            continue
        if opened:
            fence, top_fence, para = opened.group(1), line[:1] not in " \t", None
            continue
        flush = line[:1] not in " \t"
        if para is None:  # (a block begins here)
            if flush and (_ATX_HEADING.match(line) or _THEMATIC.match(line) or REFERENCE.match(line)):
                ended[number] = 1  # (a definition: a title may follow it - the caller's choice, see _titled)
                continue
            para = flush and line[:1] not in ">|<" and not LIST_ITEM.match(line)
            continue
        if flush and _ATX_HEADING.match(line):  # (a heading ends the paragraph before it)
            ended[number], para = 1, None
        elif para and flush and _UNDERLINE.match(line):
            ended[number], para = 1, None
        elif para and flush and _THEMATIC.match(line):
            ended[number], para = 1, None
        elif para and (not flush or line[:1] in ">|<" or LIST_ITEM.match(line)):
            para = False  # (a quote, a list begun in it: the lines after may be theirs)
    return ended


def _titled(line: str) -> bool:
    """Whether *line* may be a link reference definition's title, on the line after it."""
    return line.lstrip(" \t")[:1] in "\"'("


def markdown_parts(text: str, lines: int | None = None, first: int | None = None) -> list[str]:
    """*text* in parts of about *lines* lines for Qt's own parser, cut only
    where a new block of the page's top level begins - a heading, or a line
    after an empty one that is no list item, quote, table row, indented or
    fenced code (its first block a heading or a paragraph: see
    MarkdownView._append) - each with the link reference definitions of
    the text it uses (with every one, a text of 1000 links made each of its
    1000 parts 1000 lines longer: 8 s before the page showed anything)."""
    lines = PART_LINES if lines is None else lines
    first = lines if first is None else first
    rows = text.split("\n")
    if len(rows) <= first and CHUNK not in text:  # (a big table's parts: each a part of its own)
        return [text]
    cuts, fence, since, size, definitions = [0], None, 0, 0, []
    # (a long code block of the top level cut too, its fence closed before the cut and opened again
    # after it - Qt's own parser joins the code blocks as one: 30,000 lines in one part held the window
    # 30 s; where a part goes on with one: its line that opens it)
    reopened: dict[int, str] = {}
    opener, fenced, long = "", 0, False
    front_end = next((k for k in range(1, len(rows)) if FRONT_LINE.match(rows[k])), len(rows)) \
        if rows and FRONT_LINE.match(rows[0]) else 0  # (the front matter's closing line: no cut up to it)
    # (an emoji, a picture sign weighs picture_weight() letters in a part too, as in a paragraph's pieces:
    # 50,000 of them in pieces were 2,250 characters - 1,080 emoji - a part, 0.17 s an insert where a colour
    # emoji font's bitmaps cost FreeType a decoding each - Ubuntu's Noto Color Emoji, the CI runner's)
    extra = picture_weight() - 1 if _PICTURE_SIGNS.search(text) else 0
    ended = block_ends(rows)
    for number, line in enumerate(rows):
        size += len(line) + 1
        if extra and not line.isascii():
            size += extra * len(_PICTURE_SIGNS.findall(line))
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line.strip().strip(fence[0]):
                fence = None
                continue
            fenced += 1
            if long and (fenced >= CODE_PART_LINES or (size >= PART_CHARS and fenced > 1)):
                cuts.append(number)
                reopened[number] = opener
                since = size = fenced = 0
            continue
        if opened:
            # (a part may begin with a code block too: 50,000 short ones after one another were one part)
            if number and not rows[number - 1].strip() and line[:1] not in " \t" \
                    and (since >= lines or size >= PART_CHARS):
                cuts.append(number)
                since = size = 0
            fence, opener, fenced = opened.group(1), line, 0
            long = _code_lines(rows, number, fence) > BOX_BLOCKS  # (a shorter one: a box of its own, whole)
            continue
        if REFERENCE.match(line):
            definitions.append(line)
        since += 1
        table = line[:1] == "|" and number + 1 < len(rows) and TABLE_DELIMITER.match(rows[number + 1])
        if table and CHUNK in line[:3] and number:  # (a big table's later part: a part of its own)
            cuts.append(number)
            since = size = 0
            continue
        enough = since >= (first if len(cuts) == 1 else lines) or size >= PART_CHARS * (first / max(1, lines)
                                                                                    if len(cuts) == 1 else 1)
        # (a rule "---" after an empty line begins a block too - past the front matter: 100,000 rules, one part;
        # and a line after a block that ended without one - block_ends: after a heading of either kind, a fence,
        # a definition; never between definitions: 50,000 of them are laid out in 0.03 s, in parts in 15; a line
        # of "=" right after a heading's underline is no underline - "=\n" 300,000 times was one part, 12 s)
        after_end = ended[number - 1] and not (REFERENCE.match(rows[number - 1]) and _titled(line)) \
            if number else False
        if enough and number and (not rows[number - 1].strip() or _ATX_HEADING.match(line) or after_end) \
                and line.strip() and (line[:1] not in " \t>|" or table) and not LIST_ITEM.match(line) \
                and not REFERENCE.match(line) \
                and (not FRONT_LINE.match(line) or (number > front_end and _THEMATIC.match(line))) \
                and not (_UNDERLINE.match(line) and rows[number - 1].strip() and not ended[number - 1]):
            cuts.append(number)
            since = size = 0
    cuts.append(len(rows))
    parts = []
    for a, b in zip(cuts, cuts[1:]):
        if a and a < b and FRONT_LINE.match(rows[a]):  # (a part begun at a rule "---": Qt's own parser took it
            rows[a] = "***"  # for front matter, all up to the next "---" gone - the same rule, as "***")
        if a < b:
            head = [reopened[a]] if a in reopened else []
            tail = [FENCE.match(reopened[b]).group(1)] if b in reopened else []
            parts.append(_Continued("\n".join(head + rows[a:b] + tail)) if head else "\n".join(rows[a:b] + tail))
    if not definitions:
        return parts
    labelled: dict = {}
    for index, line in enumerate(definitions):
        label = line[line.index("[") + 1:]
        labelled.setdefault(_label(label[:label.index("]")]), index)  # (the first of a label is the one)
    out = []
    for part in parts:
        used = sorted({labelled[label] for label in map(_label, _BRACKETED.findall(part)) if label in labelled})
        out.append(part + ("\n\n" + "\n".join(definitions[index] for index in used) + "\n" if used else ""))
    return out


def _code_lines(rows: list[str], opened: int, fence: str) -> int:
    """Lines of the code block whose fence *fence* opens at *rows*[*opened*]
    (BOX_BLOCKS + 1 at most: counted only that far - and so many when it
    holds more than BOX_CHARS characters: long lines wrap, a box of them is
    laid out at once too)."""
    size = 0
    for number in range(opened + 1, min(len(rows), opened + BOX_BLOCKS + 2)):
        closing = FENCE.match(rows[number])
        if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence) \
                and not rows[number].strip().strip(fence[0]):
            return number - opened - 1
        size += len(rows[number])
        if size > BOX_CHARS:
            return BOX_BLOCKS + 1
    return min(len(rows) - opened - 1, BOX_BLOCKS + 1)


class _Continued(str):
    """A part of a text (markdown_parts) that goes on with the code block
    the part before it ends with."""


#: A text in brackets: a link's, a reference's label (markdown_parts).
_BRACKETED = re.compile(r"\[([^\[\]\n]{1,999})\]")


def _label(text: str) -> str:
    """A link reference's label as CommonMark matches it: case and runs of space aside."""
    return " ".join(text.split()).casefold()


#: Marks the header of a table's part after its first (renderable):
#: join_tables takes that header away and joins the parts. A private-use
#: character, taken out of the text first.
CHUNK = "\ue05d"
#: Cells of a table laid out at all (in parts); a table beyond is shown as written.
TABLE_CELLS_MAX = 300_000
#: Characters of a table's part (renderable; ui.markdown_html's _table_pieces - in a container: CONTAINED_CHARS):
#: a part of many long cells is cut sooner than its cells' count says.
TABLE_PART_CHARS = 30_000
#: Columns of a table laid out (wider: shown as written - a grid of 1,000
#: columns is read by no one, and each row of it is a part of its own).
TABLE_COLUMNS = 64


def _chunk_header(line: str) -> str:
    """A table's header *line* marked as the header of a later part."""
    stripped = line.lstrip()
    lead = line[:len(line) - len(stripped)]
    if stripped.startswith("|"):
        return f"{lead}|{CHUNK}{stripped[1:]}"
    return f"{lead}{CHUNK}{stripped}"


#: Levels of a list laid out as nested; deeper items are shown at this depth
#: (as in every view: core.markdown_doc.LIST_DEPTH - at 64 here, markdown-it
#: made a list 16 deep code).
LIST_DEPTH = 16
_DEEP = re.compile(r"^[ \t]{%d}" % (2 * LIST_DEPTH + 1), re.MULTILINE)


_NESTING_LINE = re.compile(r"^[ \t]{0,3}(?:>|[-+*][ \t]|\d{1,9}[.)][ \t])", re.MULTILINE)


def _one_line_nesting(text: str) -> tuple[str, bool]:
    """(*text* with no line opening more than LIST_DEPTH containers - list items, quotes - one in another on
    the line itself: the marks after those as text, a backslash before the first; whether a line was):
    "+ " 90,000 times is a list 90,000 deep, held the window 7.9 s ("1. " 60,000 times 4.3 s) - the depth
    _flatter counts is the indentation's only. A thematic break ("- - - …") and fenced code as they are."""
    from core.markdown_doc import _CONTAINER_PART

    if not _NESTING_LINE.search(text):
        return text, False
    rows, changed, fence = text.split("\n"), False, None
    for number, line in enumerate(rows):
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        if len(line) < 2 * LIST_DEPTH or line.lstrip(" \t")[:1] not in "->+*0123456789":
            continue
        pos, count = 0, 0
        while count <= LIST_DEPTH:
            found = _CONTAINER_PART.match(line, pos)
            if not found or found.end() == pos:
                break
            count += 1
            if count > LIST_DEPTH:
                break
            pos = found.end()
        if count > LIST_DEPTH and not _THEMATIC.match(line):
            rest = line[pos:]
            lead = len(rest) - len(rest.lstrip(" \t"))
            mark = rest[lead:]
            digits = len(mark) - len(mark.lstrip("0123456789"))
            # (the next mark as text: "\\+", "1\\.", "\\>")
            rows[number] = line[:pos] + rest[:lead] + mark[:digits] + "\\" + mark[digits:]
            changed = True
    return ("\n".join(rows), True) if changed else (text, False)


def _flatter(lines: list[str]) -> tuple[list[str], bool]:
    """(*lines* with no indentation deeper than LIST_DEPTH levels - code kept:
    core.markdown_doc.flatter -, whether a line was made flatter)."""
    from core import markdown_doc

    text, changed = markdown_doc.flatter("\n".join(lines), LIST_DEPTH)
    return (text.split("\n"), True) if changed else (lines, False)


#: Spaces or tabs in a row at most (more are cut): Qt's layout of a line of
#: more than 65,535 spaces before a word never ended - nor of 17,000 tabs.
#: Every space of Unicode counts (no-break ones, joiners and zero-width ones
#: too - 300,000 no-break spaces held the window 11 s), never a line's end.
SPACE_RUN = 1000
_SPACES = "\t\x0b\x0c\x1c-\x1f \x85\xa0\u1680\u180e\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff"
_SPACE_RUN = re.compile("[%s]{%d,}" % (_SPACES, SPACE_RUN + 1))


#: A heading's text, a table cell's, laid out at most (characters): Qt lays out a heading or a cell as one
#: piece, in one turn - one of 150,000 characters held the window 1.3 to 2.3 s, in any container.
LINE_CAP = 2000
_LONG_LINE = re.compile(r"[^\n]{%d}" % (LINE_CAP + 1))
#: What stands before a block in its containers: quote marks, list markers, indentation.
_CONTAINER_LEAD = re.compile(r"(?:[ \t]{0,3}>[ \t]?|[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]+|[ \t]+)*+")  # (possessive:
# its alternatives overlap - a pattern that backtracked into them took exponential time)
_ATX = re.compile(r"#{1,6}(?:[ \t]|$)")
_SETEXT_UNDER = re.compile(r"(?:=+|-+)[ \t]*\Z")
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def _letters(text: str) -> int:
    """*text*'s length, an emoji or a picture sign picture_weight() letters (as in a paragraph's pieces)."""
    if text.isascii():
        return len(text)
    return len(text) + (picture_weight() - 1) * len(_PICTURE_SIGNS.findall(text))


def _cut_text(text: str, cap: int) -> str:
    """*text* at most *cap* characters (_letters: a heading of 1,000 emoji was 0.4 s to lay out with a
    colour emoji font of bitmaps, a table cell of them 0.8 s) - at a space near the end when there is one -
    and "…"."""
    if _letters(text) <= cap:
        return text
    if not text.isascii():  # (where its letters reach *cap*)
        weight, total, at = picture_weight(), 0, 0
        for at, ch in enumerate(text):
            total += weight if _PICTURE_SIGNS.match(ch) else 1
            if total > cap:
                break
        cap = max(1, at)
    space = text.rfind(" ", cap - cap // 10, cap)
    return text[:space if space > 0 else cap].rstrip() + " …"


def _capped_lines(text: str) -> tuple[str, int]:
    """(*text* with each heading's and table cell's text past LINE_CAP characters cut - in any container
    of the page, never in code; a longer code line in lines of LINE_CAP -, how many were cut). Linear;
    nothing to do for most texts."""
    from core.markdown_doc import found_by_lines

    pictures = _PICTURE_SIGNS.search(text) is not None
    if not pictures and not found_by_lines(_LONG_LINE, text):
        return text, 0
    rows = text.split("\n")
    fence, table, cut, broken = None, False, 0, False
    for number, row in enumerate(rows):
        lead = _CONTAINER_LEAD.match(row).group(0)
        rest = row[len(lead):]
        opened = FENCE.match(rest)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            elif len(rest) > LINE_CAP:  # (a code line of 80,000 characters: one block, 0.6 to 0.7 s - in lines
                # of LINE_CAP characters, all of it kept)
                rows[number] = "\n".join(lead + rest[at:at + LINE_CAP] for at in range(0, len(rest), LINE_CAP))
                broken = True
            continue
        if opened:
            fence = opened.group(1)
            continue
        if not rest.strip():
            table = False
            continue
        if TABLE_DELIMITER.match(rest) and "|" in rest:
            table = True
            continue
        if not table and number + 1 < len(rows):  # (a table's header: the row above its delimiter)
            after = rows[number + 1]
            after = after[len(_CONTAINER_LEAD.match(after).group(0)):]
            if "|" in rest and "|" in after and TABLE_DELIMITER.match(after) and _letters(row) > LINE_CAP:
                rows[number] = lead + "|".join(_cut_text(cell, LINE_CAP) for cell in _UNESCAPED_PIPE.split(rest))
                cut += 1
                continue
        if len(row) <= LINE_CAP and (not pictures or _letters(row) <= LINE_CAP):
            continue
        if table and "|" in rest:
            rows[number] = lead + "|".join(_cut_text(cell, LINE_CAP) for cell in _UNESCAPED_PIPE.split(rest))
            cut += 1
        elif _ATX.match(rest):
            rows[number] = lead + _cut_text(rest, LINE_CAP)
            cut += 1
        elif number + 1 < len(rows) and _SETEXT_UNDER.match(rows[number + 1][len(_CONTAINER_LEAD.match(
                rows[number + 1]).group(0)):]) and rows[number + 1].strip():
            rows[number] = lead + _cut_text(rest, LINE_CAP)
            cut += 1
    return ("\n".join(rows), cut) if cut or broken else (text, 0)


def renderable(text: str, table_cells: int | None = None, keep_marks: bool = False) -> tuple[str, str]:
    """(*text* as it is rendered, why some of it is shown as written - or
    "") - see :data:`LIST_ITEMS`. Only what would hold up the window is
    shown as written (in a code block, where it stands): the rows of a table
    beyond :data:`TABLE_CELLS` cells, the items of a list beyond LIST_ITEMS
    (footnotes count as one list), a line of :data:`LONG_RUN` characters
    without a space (an image's ``data:`` address does not count). Code is
    never counted; a "|" counts only in a table (a delimiter row below its
    first line). A run of more than SPACE_RUN spaces or tabs is cut to
    that many. Linear in the length of *text*."""
    table_cells = TABLE_CELLS if table_cells is None else table_cells
    from core.markdown_doc import QUOTE_DEPTH, by_lines, found_by_lines, quote_flatter

    # (a pass a piece at a time: one over all of a long text held up the window - by_lines)
    text = by_lines(lambda piece: _SPACE_RUN.sub(lambda match: match.group(0)[:SPACE_RUN], piece),
                    text if keep_marks else text.replace(CHUNK, "").replace(JOINED, ""))
    early = {}
    text, flattened = quote_flatter(text)
    if flattened:
        early["quotes"] = _t("quotes nested more than {count} deep, shown flatter", count=QUOTE_DEPTH)
    text, flattened = _one_line_nesting(text)
    if flattened:
        early["deep"] = _t("lists nested more than {count} deep, shown flatter", count=LIST_DEPTH)
    from core.markdown_doc import LINE_FORMULAS

    if text.count("$") > 2 * LINE_FORMULAS and any(
            line.lstrip(" \t>").startswith(("#", "|")) and line.count("$") > 2 * LINE_FORMULAS
            for line in text.split("\n") if len(line) > 4 * LINE_FORMULAS):
        early["formulas"] = _t("formulas past the first {count} of a heading or a table's row, as their TeX",
                               count=LINE_FORMULAS)
    text, capped = _capped_lines(text)
    if capped:
        early["cut"] = _t("headings and table cells longer than {count} characters, cut (the editor shows them)",
                          count=LINE_CAP)
    deep = found_by_lines(_DEEP, text)
    tables = "|" in text and (text.count("|") >= table_cells or len(text) >= TABLE_PART_CHARS)
    if text.count("\n") < LIST_ITEMS and not deep and not tables \
            and not (len(text) >= LONG_RUN and found_by_lines(LONG_WORD, by_lines(lambda piece: DATA_IMAGE.sub(
                "", piece), text))):
        return text, _why(early)  # (most texts: nothing to count)
    lines, out, why = text.split("\n"), [], dict(early)
    fence, items, notes, index, chunked, list_from = None, 0, 0, 0, False, 0
    if deep:  # (nested thousands deep: shown flatter - 6 MB of spaces held the window)
        lines, flattened = _flatter(lines)
        if flattened:  # (only a code block's lines that deep: kept, nothing said - the notice was false)
            why["deep"] = _t("lists nested more than {count} deep, shown flatter", count=LIST_DEPTH)
            chunked = True
    while index < len(lines):
        line = lines[index]
        if len(line) >= LONG_RUN and LONG_WORD.search(DATA_IMAGE.sub("", line)):
            why["long"] = _t("a line of more than {count} characters without a space", count=LONG_RUN)
            out.append(_t("*(a line of {count} characters without a space – the editor shows it)*",
                          count=len(line)) if fence is None else line[:2000] + " …")
            index += 1
            continue
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            out.append(line)
            index += 1
            continue
        if opened:
            fence = opened.group(1)
            out.append(line)
            index += 1
            continue
        if NOTE_LINE.match(line):
            notes += 1
            if notes > LIST_ITEMS:
                why["notes"] = _t("more than {count} footnotes", count=LIST_ITEMS)
                end = index
                while end < len(lines) and (NOTE_LINE.match(lines[end]) or not lines[end].strip()
                                            or lines[end][:1] in " \t"):
                    end += 1
                out += _as_written(lines[index:end])
                index = end
                continue
        elif LIST_ITEM.match(line):
            items += 1
            top = line[:1] not in " \t"  # (an item of the top level: a nested one, 2 or 3 in, is no place to cut)
            if top and items > 1 and len(out) - list_from > LIST_PART_LINES:
                items = LIST_PART + 1  # (its items' lines - code in them - count too: 2,000 items of 40 lines)
            if items > LIST_PART and top:
                # A long list in parts: a line between them that is no text
                # (a new list begins; an ordered one goes on with its number),
                # each laid out on its own (a part of the page each).
                out += ["", "\u200b", ""]  # (zero-width: a no-break space was stripped, the line lost)
                items, chunked = 1, True
                list_from = len(out)
            elif items > 3 * LIST_ITEMS:  # (no item of the top level to cut at: the rest as written)
                why["list"] = _t("lists of more than {count} items", count=LIST_ITEMS)
                end = index
                while end < len(lines) and (LIST_ITEM.match(lines[end]) or not lines[end].strip()
                                            or lines[end][:1] in " \t"):
                    end += 1
                out += _as_written(lines[index:end])
                items = 0
                index = end
                continue
        elif line.strip() and line[:1] not in " \t" and not _MARKS_ONLY.fullmatch(line):
            items = 0  # (a line that is no item and not indented: the list has ended)
            list_from = len(out)
        if "|" in line and index + 1 < len(lines) and TABLE_DELIMITER.match(lines[index + 1]) \
                and "|" in lines[index + 1] + line:
            end = index + 2
            while end < len(lines) and lines[end].strip():
                end += 1
            columns = _cells(lines[index + 1])
            # (cells with formulas: a quarter as many a part - each laid out as a formula is, a part of
            # 1,500 held the window 1 s)
            mathy = any("$" in row for row in lines[index:min(end, index + 50)])
            # (and with footnotes: each reference a link and a superscript of its own - 300 rows of them a part,
            # 0.2 s to lay out)
            noted = any("[^" in row for row in lines[index:min(end, index + 50)])
            budget = table_cells // 4 if mathy or noted else table_cells
            if columns > WIDE_TABLE:  # (a wide table's cell costs more - each row laid out across all of them:
                budget = budget * WIDE_TABLE // columns  # 60 columns in parts of 900 cells, 0.3 s a part)
            rows = max(1, budget // columns - 1)  # (besides its header)
            # (and of at most TABLE_PART_CHARS characters: 300 rows of two cells of 1,800 characters were one
            # part - 0.9 to 1.3 s; cut by the cells only)
            sample = lines[index + 2:min(end, index + 52)]
            rows = min(rows, max(1, TABLE_PART_CHARS * max(1, len(sample)) // max(1, sum(map(len, sample)))))
            total = (end - index - 1) * columns
            if columns > TABLE_COLUMNS:  # (no one reads it as a grid: as written)
                why["columns"] = _t("tables of more than {count} columns", count=TABLE_COLUMNS)
                out += _as_written(lines[index:end])
            elif total > TABLE_CELLS_MAX:  # (beyond any measure: as written)
                why["table"] = _t("tables of more than {count} cells", count=TABLE_CELLS_MAX)
                out += _as_written(lines[index:end])
            elif end - index - 2 > rows:
                # In parts of at most table_cells cells, each laid out on its own
                # (a part of the page each: see MarkdownView), the header again
                # over each, marked: join_tables makes them one table again.
                chunked = True
                # (its first part a quarter as long: the page's first part is laid out with all that comes
                # with a new page - 20,000 rows, 300 of them in it, held the window 0.16 s)
                firsts = [index + 2] + list(range(index + 2 + max(1, rows // 4), end, rows))
                for at, first in enumerate(firsts):
                    if first > index + 2:
                        out += ["", _chunk_header(lines[index])]
                    else:
                        out.append(lines[index])
                    out.append(lines[index + 1])
                    out += lines[first:firsts[at + 1] if at + 1 < len(firsts) else end]
            else:
                out += lines[index:end]
            index = end
            continue
        out.append(line)
        index += 1
    if not why:
        return ("\n".join(out) if chunked else text), ""
    return "\n".join(out), _why(why)


#: What renderable shows flatter (its notice says so - not "as written").
_FLATTER = ("deep", "quotes")


#: A line of the passes' marks only (a hard break's of raw HTML's list): no line of text.
_MARKS_ONLY = re.compile("[\ue070-\ue09f]+[ \t]*")


def _why(why: dict) -> str:
    """The notice saying what renderable shows otherwise ("" for nothing):
    what is shown as written, what flatter - each said as what it is."""
    written = [text for key, text in why.items() if key not in _FLATTER]
    flatter = [text for key, text in why.items() if key in _FLATTER]
    said = []
    if written:
        said.append(_t("Shown as written, not laid out: {why} – more would hold up the window. "
                       "The editor shows them as they are.", why="; ".join(written)))
    if flatter:
        said.append(_t("Laid out flatter: {why}.", why="; ".join(flatter)))
    return " ".join(said)


_HTML_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>")
#: A tag as CommonMark reads one (its attributes' names and values as they may be written): another one -
#: "<a href="hi'>" - is text, as written.
_VALID_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*"
                        r"(?:\s*=\s*(?:[^\s\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*\s*/?>|</[A-Za-z][A-Za-z0-9-]*\s*>")
#: Raw HTML whose contents go with it.
_HTML_DROPPED = re.compile(r"<(script|style|template|iframe|object|embed|noscript|textarea|title|xmp|noembed|"
                           r"noframes|svg|math|select|head|frame|frameset|applet|audio|video|canvas)\b[^<>]*>",
                           re.IGNORECASE)
#: Raw HTML read as a whole: its contents become Markdown of their own.
_HTML_WHOLE = re.compile(r"<(table|pre|h[1-6]|summary)\b[^<>]*>", re.IGNORECASE)
_BLOCKS = frozenset("p div center details blockquote section article header footer nav aside figure "
                    "figcaption ul ol dl".split())
#: An alert's first line - of a quote of the top level only (GitHub nests none: in a list, in another
#: quote, it is a quote saying "[!NOTE]").
_ALERT_LINE = re.compile(r"^(>[ \t]?)\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*$",
                         re.IGNORECASE | re.MULTILINE)
#: Display math: "$$" on lines of their own around it - or on one line ("$$\frac{a}{b}$$": shown raw).
_BLOCK_MATH = re.compile(r"^\$\$[ \t]*\n(.*?)\n\$\$[ \t]*$|^ {0,3}\$\$[ \t]*(\S[^\n]*?)[ \t]*\$\$[ \t]*$",
                         re.MULTILINE | re.DOTALL)
_PREFIXED_MATH = re.compile(r"^((?:[ \t]*+>[ \t]?+)++|[ \t]{2,8})\$\$[ \t]*\n((?:\1[^\n]*\n)*?)\1\$\$[ \t]*$",
                            re.MULTILINE)
_INLINE_DOUBLE_MATH = re.compile(r"(?<![\\$])\$\$[ \t]*([^$\s][^$\n]{0,2000}?)[ \t]*\$\$(?!\$)")  # ("$$ E $$" too)
_INLINE_MATH = re.compile(r"(?<![\\$\w])\$(?![\s$])([^$\n]{1,2000}?)(?<![\s\\])\$(?![\d$])")
_REMOTE = r"(?:https?:|ftps?:|//)[^)\s]+"
#: (an image's alt, a link's text, holds no "[" in the patterns below: one with "[" ran on to the line's end
#: at every "![" of a run - "![" 49,500 times took the passes 90 s)
_LINKED_REMOTE_IMAGE = re.compile(r"\[!\[([^\[\]\n]*)\]\((" + _REMOTE + r")(?:\s+\"[^\"\n]*\")?\)\]\(([^)\s]+)\)")
_REMOTE_IMAGE = re.compile(r"!\[([^\[\]\n]*)\]\((" + _REMOTE + r")(?:\s+\"[^\"\n]*\")?\)")
_DESTINATION = re.compile(r"\]\([ \t]*[^()\s]*(?:\([^()\s]*\)[^()\s]*)*(?:\s+\"[^\"\n]*\")?[ \t]*\)")
#: A link's or an image's address in <…> (spaces, parentheses may be in it).
_ANGLE_DESTINATION = re.compile(r'\]\([ \t]*<([^<>\n]*)>((?:[ \t]+(?:"[^"\n]*"|\'[^\'\n]*\'|\([^()\n]*\)))?)[ \t]*\)')


def _unangled(match: re.Match) -> str:
    """"](<my file.md>)" as "](my%20file.md)": Qt's own parser read the
    "<…>" as a tag (the link dead, the image "%3Clogo.png%3E")."""
    from urllib.parse import quote

    return f"]({quote(match.group(1), safe=_URL_SAFE)}{match.group(2)})"


_URL_SAFE = ":/?#@!$&'*+,;=%~"
_AUTOLINK = re.compile(r"<[A-Za-z][A-Za-z0-9+.\-]{1,31}:[^<>\s]*>|<[\w.!#$%&'*+/=?^`{|}~\-]+@[\w.\-]+>")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]#|<>~])")
#: Marks the text passes leave for what Qt's own parser cannot be told in
#: Markdown (raw HTML's <b> where Markdown's ** would not count, <sub>, a
#: formula's colour): a start and an end character of Unicode's private
#: use area each, taken out of the text first; apply_marks turns them into
#: formats after the parser (they are text to it).
MARKS = {name: chr(0xE070 + 2 * n) for n, name in enumerate(
    ("bold", "italic", "strike", "underline", "code", "mark", "sub", "sup", "math", "rows", "over"))}
#: Spans a page's marks format at most (each a format change on the GUI
#: thread: a page of 300,000 formulas' scripts held it 1.5 s a piece) -
#: beyond, they stay plain.
MARK_SPANS = 10_000
_MARK_CHARS = re.compile("[%s]" % "".join(ch + chr(ord(ch) + 1) for ch in MARKS.values()))
_MARK_TAGS = {"b": "bold", "strong": "bold", "i": "italic", "em": "italic", "s": "strike", "strike": "strike",
              "del": "strike", "u": "underline", "ins": "underline", "code": "code", "kbd": "code",
              "mark": "mark", "sub": "sub", "sup": "sup"}
#: A block's alignment (raw HTML's align): a character at its start.
ALIGNS = {"center": "\ue090", "right": "\ue091", "justify": "\ue092"}
#: A line of its own between two quotes (Qt's own parser made one of them:
#: the same quote level, nothing between) - gone again in _style_md4c.
QUOTE_END = "\ue093"
#: A raw-HTML table's cell spanning rows or columns: "<mark>2:1<end>text" -
#: its rows and columns (_html_table; merged by _merge_spans).
SPAN_MARK, SPAN_END = "\ue094", "\ue095"
#: Marks a display formula Qt's own parser's page shows as markdown-it's HTML (_math_displays).
MATH_HTML = "\ue09b"
#: Marks an inline formula's TeX (base64, up to SPAN_END) before it: an anchor of its first letter.
MATH_INLINE = "\ue09c"
#: A formula's colour (_math_marked): COLOUR_ON, its hex digits, COLOUR_NAMED, what is in it, COLOUR_OFF.
COLOUR_ON, COLOUR_NAMED, COLOUR_OFF = "\ue09d", "\ue09e", "\ue09f"
#: An anchor's name (raw HTML's <a id>, <a name>): ANCHOR_MARK, the name in base64, SPAN_END.
ANCHOR_MARK = "\ue096"
#: A block indented as a definition under its term (_definitions; apply_marks).
INDENT = "\ue097"
#: A hard line break of prose ("\\" or two spaces at a line's end): Qt's own
#: parser made each line a paragraph of its own (_hard_breaks).
HARD = "\ue099"
#: (Qt's own parser) a raw-HTML table's first cell: its first row is no header (<td>, not <th>) -
#: _style_tables draws it as the others (Markdown's first row is always one).
NO_HEAD = "\ue09a"
#: a hard line break: a backslash or two spaces and more at a line's end (the
#: spaces from the first of their run - tried from each, a long run took time growing as its square)
_HARD_BREAK = re.compile(r"(?:\\|(?<! ) {2,})\n(?! {0,3}(?:=+|-+)[ \t]*(?:\n|\Z))(?=[ \t>]*[^\s>])")
_SPAN = re.compile("\ue094(\\d+):(\\d+)\ue095")
_QUOTES_APART = re.compile(r"(^ {0,3}>[^\n]*\n)(?:[ \t]*\n)+(?= {0,3}>)", re.MULTILINE)
_PRIVATE = re.compile("[\ue070-\ue09f]")
#: (a code piece) its last line in a quote; (the text after it) the gap before another quote
_QUOTED_LAST = re.compile(r"(?:^|\n) {0,3}>[^\n]*\n?\Z")
_QUOTE_AFTER_GAP = re.compile(r"\A(?:[ \t]*\n)+(?= {0,3}>)")
#: (anywhere) a quote after an empty line - perhaps one after another (two quotes: one box)
_QUOTE_AFTER_A_GAP = re.compile(r"\n[ \t]*\n {0,3}>")
#: An image's size and place (raw HTML's width, height, align) ride in its
#: address's fragment: "logo.png#axross:w=160:a=center" (the view reads the
#: file by its path; apply_marks sets them).
_IMAGE_SPEC = "#axross:"


def _open(kind: str) -> str:
    return MARKS[kind]


def _close(kind: str) -> str:
    return chr(ord(MARKS[kind]) + 1)


#: Wraps the number of a piece kept as written (a code span) while the
#: passes go over the text: a private-use character, taken out of it first.
_KEPT = "\ue05e"
_KEPT_SPAN = re.compile(_KEPT + r"(\d+)" + _KEPT)


#: Begins a long paragraph's later piece (paragraph_pieces): a private-use
#: character, taken out of the text first (renderable).
JOINED = "\ue05b"  # (not ui.markdown_safe._MARK, \ue05c: taken out by its escape)
#: Characters of a paragraph of the top level laid out at once by Qt's own
#: parser: a longer one is cut in pieces of about this many, each a
#: paragraph that begins with JOINED - one a part of the page (_style_md4c
#: takes the room between them away). (Qt lays out a line of many spans in
#: time that grows with their square: 6,000 formulas in one paragraph held
#: the window minutes, 5,000 images 1.6 s.)
PARAGRAPH_CHARS = 3000
#: ... or code spans (each one laid out on its own: "`a" 5,000 times, 0.7 s).
PARAGRAPH_CODE_SPANS = 400
_PIECE_STOPS = re.compile("[\\\\`\\[\\]()<>*_ \n%s%s\ue070-\ue08f]" % (MATH_INLINE, SPAN_END))


#: A big block inside a list item or a quote (Qt's own parser, container_pieces):
#: more lines than this or more characters - cut in pieces of so many.
CONTAINED_LINES = 200
CONTAINED_CHARS = 6000
_QUOTE_MARK = re.compile(r" {0,3}>[ \t]?")
_ITEM_MARK = re.compile(r"( {0,3})([-+*]|(\d{1,9})([.)]))( {1,4}(?! )|[ \t]*$)")


def _containers_of(line: str, stack: list, lazy: bool) -> tuple[list, int]:
    """(the containers *line* is in - quotes {"q"}, list items {"i": content
    width, "m": marker, "n": number} - and where its content begins), given
    those of the line before (*stack*); *lazy*: that line was a paragraph's
    (a line of text may go on with it without the marks)."""
    pos, kept = 0, []
    for container in stack:
        rest = line[pos:]
        if container["k"] == "q":
            found = _QUOTE_MARK.match(rest)
            if not found:
                break
            pos += found.end()
        elif rest.strip():
            if len(rest) - len(rest.lstrip(" ")) < container["w"]:
                break
            pos += container["w"]
        kept.append(container)
    if len(kept) < len(stack) and lazy and line.strip() and not _QUOTE_MARK.match(line[pos:]) \
            and not _ITEM_MARK.match(line[pos:]) and not FENCE.match(line[pos:]):
        return list(stack), pos  # (a paragraph's line going on, its marks left out)
    while True:  # (containers it begins)
        rest = line[pos:]
        found = _QUOTE_MARK.match(rest)
        if found:
            kept.append({"k": "q"})
            pos += found.end()
            continue
        found = _ITEM_MARK.match(rest)
        if found and rest.strip() and not TABLE_DELIMITER.match(rest) and not re.fullmatch(r" {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*", rest):
            width = len(found.group(0)) if found.group(5).strip(" \t") == "" and found.group(5) else len(found.group(0))
            if not rest[found.end():].strip():
                width = len(found.group(1)) + len(found.group(2)) + 1
            kept.append({"k": "i", "w": width, "m": found.group(2), "n": int(found.group(3)) if found.group(3) else None,
                         "d": found.group(4) or ""})
            pos += found.end()
            continue
        break
    return kept, pos


def _reopened(stack: list) -> tuple[str, str]:
    """(the line that begins *stack*'s containers again going on - an item
    begun with GOING_ON, its number the next one -, the prefix of the lines
    after it)."""
    from ui.markdown_html import GOING_ON

    first, rest = "", ""
    for container in stack:
        if container["k"] == "q":
            first += "> "
            rest += "> "
        else:
            marker = f"{container['n'] + 1}{container['d']}" if container["n"] is not None else container["m"]
            pad = max(1, container["w"] - len(marker))  # (its content where the item's was: "-   item")
            first += marker + " " * pad
            rest += " " * (len(marker) + pad)
    return first + GOING_ON, rest


def _prefix_of(stack: list) -> str:
    """The prefix of a line going on in *stack*'s containers as they were opened."""
    return "".join("> " if container["k"] == "q" else " " * container["w"] for container in stack)


def container_pieces(text: str) -> str:
    """*text* (for Qt's own parser, after its passes) with a big block inside
    a list item or a quote - a fenced or indented code block, a table, a
    paragraph of more than CONTAINED_LINES lines or CONTAINED_CHARS
    characters - in pieces, each in its containers again: a line between
    them that is no text ends them (a part of the page may begin there), the
    next begins them again going on (an item with a first block of no height:
    _going_on; a table's later piece's header marked: join_tables). Every
    block stays where it belongs (a 30,000-row table in a quote in a list
    item held the window 10 s)."""
    if len(text) < CONTAINED_CHARS:
        return text
    rows, out, stack, lazy, index, fence, since = _untabbed(text.split("\n")), [], [], False, 0, None, 0
    while index < len(rows):
        line = rows[index]
        if fence is not None:  # (a fenced block of the top level: as it is)
            closing = FENCE.match(line)
            if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence) \
                    and not line.strip().strip(fence[0]):
                fence = None
            out.append(line)
            index += 1
            continue
        before = stack
        stack, pos = _containers_of(line, stack, lazy)
        if stack and since > CONTAINED_LINES and line.strip() and not lazy:
            # (many small blocks in a container - 5,000 items of a list in a quote: cut between two of them
            # too, the containers going on begun again; a quote's line begins it again with its own marks)
            going = [container for container in stack if any(container is old for old in before)]
            out += ["", "\u200b", ""]
            if any(container["k"] == "i" for container in going):
                out += [_reopened(going)[0], _reopened(going)[1].rstrip()]  # (its own paragraph: the line after)
            since = 0
        if not stack:
            since = 0
        if not stack and line.startswith("    ") and line.strip() and not lazy:  # (indented code of the top level)
            end = index + 1
            while end < len(rows) and (rows[end].startswith("    ") or not rows[end].strip()):
                end += 1
            while end > index + 1 and not rows[end - 1].strip():
                end -= 1
            if end - index > CONTAINED_LINES or sum(len(row) for row in rows[index:end]) > CONTAINED_CHARS:
                for at in range(index, end, CONTAINED_LINES):
                    out += (["", "\u200b", ""] if at > index else []) + rows[at:min(end, at + CONTAINED_LINES)]
            else:
                out += rows[index:end]
            index, lazy = end, False
            continue
        if not stack:
            opened = FENCE.match(line)
            fence = opened.group(1) if opened else None
            out.append(line)
            lazy = bool(line.strip()) and not opened and not line.startswith(("    ", "\t"))
            index += 1
            continue
        end, kind = _contained_block(rows, index, stack, pos)
        size = sum(len(row) for row in rows[index:end])
        if end - index > CONTAINED_LINES or size > CONTAINED_CHARS:
            out += _contained_pieces(rows, index, end, stack, pos, kind)
            since = 0
        else:
            out += rows[index:end]
            since += end - index
        lazy = kind == "p"
        index = max(end, index + 1)
    return "\n".join(out)


_LEADING = re.compile(r"[ \t>]*(?:(?:[-+*]|\d{1,9}[.)])(?=[ \t]|$)[ \t>]*)*")


def _untabbed(rows: list) -> list:
    """*rows* with the tabs of their containers' marks and indent as spaces
    to the next column of four (as CommonMark counts them; container_pieces
    counts spaces: "-\titem" was no list item, its 30,000-line fence one
    piece): a line's tabs up to four columns past its last mark - a
    fenced block's lines of the top level as they are."""
    if not any("\t" in row for row in rows):
        return rows
    out, fence = [], None
    for row in rows:
        if fence is not None or "\t" not in row:
            opened = FENCE.match(row)
            if opened and (fence is None or (opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence)
                                             and not row.strip().strip(fence[0]))):
                fence = opened.group(1) if fence is None else None
            out.append(row)
            continue
        lead = _LEADING.match(row).group(0)
        marks = max(lead.rfind(mark) for mark in ">-+*.)") + 1  # (past the last mark: 0 for none)
        column, made = 0, []
        for at, char in enumerate(lead):
            if char == "\t" and column < _column(lead[:marks]) + 4:
                made.append(" " * (4 - column % 4))
                column += 4 - column % 4
            else:
                made.append(char)
                column = column + 4 - column % 4 if char == "\t" else column + 1
        out.append("".join(made) + row[len(lead):])
    return out


def _column(text: str) -> int:
    """The column *text* ends at (tabs to the next column of four)."""
    column = 0
    for char in text:
        column = column + 4 - column % 4 if char == "\t" else column + 1
    return column


def _same(kept: list, stack: list) -> bool:
    """*kept* the very containers of *stack* (a new list item is equal to the
    one before it, not the same: "1." after "1.")."""
    return len(kept) == len(stack) and all(a is b for a, b in zip(kept, stack, strict=True))


def _contained_block(rows: list, index: int, stack: list, pos: int) -> tuple[int, str]:
    """(where the block of *rows*[*index*] inside *stack* ends, its kind:
    "f" fenced code, "c" indented code, "t" table, "p" paragraph, "o" other)."""
    content = rows[index][pos:]
    depth = len(stack)

    def inside(row: str) -> tuple[bool, str]:
        kept, at = _containers_of(row, stack, False)
        return len(kept) == depth and _same(kept, stack), row[at:]

    opened = FENCE.match(content)
    if opened:
        end = index + 1
        while end < len(rows):
            ok, inner = inside(rows[end])
            if not ok and rows[end].strip():
                break
            end += 1
            closing = FENCE.match(inner)
            if closing and closing.group(1)[0] == opened.group(1)[0] and len(closing.group(1)) >= len(opened.group(1)) \
                    and not inner.strip().strip(opened.group(1)[0]):
                break
        return end, "f"
    if content.startswith("    ") and content.strip():
        end = index + 1
        while end < len(rows):
            ok, inner = inside(rows[end])
            if not ok or not (inner.startswith("    ") or not inner.strip()):
                break
            end += 1
        while end > index + 1 and not rows[end - 1][pos:].strip():
            end -= 1
        return end, "c"
    if "|" in content and index + 1 < len(rows):
        ok, after = inside(rows[index + 1])
        if ok and TABLE_DELIMITER.match(after) and "|" in after:
            end = index + 2
            while end < len(rows):
                ok, inner = inside(rows[end])
                if not ok or not inner.strip() or "|" not in inner:
                    break
                end += 1
            return end, "t"
    if not content.strip() or _ATX_HEADING.match(content):
        # (a heading is a block of its own, no paragraph a line may go on with: 50,000 headings in a quote
        # were never cut - one part, 4 s)
        return index + 1, "o"
    end = index + 1  # (a paragraph: up to an empty line, another block's line)
    while end < len(rows):
        kept, at = _containers_of(rows[end], stack, True)
        inner = rows[end][at:]
        if _same(kept, stack) and _SETEXT_UNDER.match(inner.lstrip(" ")) and len(inner) - len(inner.lstrip(" ")) < 4:
            return end + 1, "o"  # (a heading "text" over "===": ended by its line)
        if not inner.strip() or not _same(kept, stack) or FENCE.match(inner) or _ITEM_MARK.match(inner) \
                or _QUOTE_MARK.match(inner) or inner.lstrip().startswith("#"):
            break
        end += 1
    return end, "p"


_BLOCK_START = re.compile(r"[ \t]*(?:[-+*](?:[ \t]|\Z)|#{1,6}(?:[ \t]|\Z)|>|`{3}|~{3}|=+[ \t]*\Z|-+[ \t]*\Z"
                          r"|(\d{1,9})[.)](?:[ \t]|\Z)|[*_](?:[ \t]*[*_]){2,}[ \t]*\Z|\|)")


def _text_start(line: str) -> str:
    """*line* - a paragraph's line - with what would begin a block at its start (a list item's mark, a
    quote's, a heading's, a fence, an underline) as text: a backslash before it."""
    found = _BLOCK_START.match(line)
    if not found:
        return line
    lead = len(line) - len(line.lstrip(" \t"))
    at = found.end(1) if found.group(1) else lead
    return line[:at] + "\\" + line[at:]


def _contained_pieces(rows: list, index: int, end: int, stack: list, pos: int, kind: str) -> list:
    """The lines of the big block *rows*[*index*:*end*] (see container_pieces) in pieces."""
    first_line, prefix = _reopened(stack)
    if not any(container["k"] == "i" for container in stack):
        first_line = None  # (quotes only: begun again by their marks)
    contents = []
    for row in rows[index:end]:
        _kept, at = _containers_of(row, stack, kind == "p")
        contents.append(row[at:])
    opener, closer, header = None, None, []
    body = contents
    if kind == "f":
        opener = contents[0]
        fence = FENCE.match(opener).group(1)
        last = FENCE.match(contents[-1]) if len(contents) > 1 else None
        has_close = bool(last and last.group(1)[0] == fence[0] and not contents[-1].strip().strip(fence[0]))
        body = contents[1:-1] if has_close else contents[1:]
        closer = fence
    elif kind == "t":
        header, body = contents[:2], contents[2:]
    elif kind == "p" and (len(contents) == 1 or max(len(c) for c in contents) > CONTAINED_CHARS):
        joined = " ".join(c.strip() for c in contents)
        body = _pieces_of(joined).split("\n\n" + JOINED)
        # (a piece after the first begins a line of the paragraph: what would begin a block there - "+ ", "1. ",
        # "#", ">" - as text; "+ " 90,000 times in a list item were lists again, 1,500 deep a piece)
        body[1:] = [_text_start(piece) for piece in body[1:]]
    groups, group, size = [], [], 0
    per = CONTAINED_LINES
    if kind == "t":
        per = max(1, MD4C_TABLE_CELLS // max(1, _cells(header[1])))
    # (an emoji, a picture sign weighs picture_weight() letters, as in markdown_parts: a quote's paragraph of
    # 50,000 emoji was pieces of 3,000 of them - with a colour emoji font of bitmaps, 1 s a part)
    extra = picture_weight() - 1 if any(_PICTURE_SIGNS.search(line) for line in body) else 0
    for line in body:
        cost = len(line) + (extra * len(_PICTURE_SIGNS.findall(line)) if extra and not line.isascii() else 0)
        if group and (len(group) >= per or size + cost > CONTAINED_CHARS) and kind != "p" or \
                (kind == "p" and group and (size + cost > CONTAINED_CHARS)):
            groups.append(group)
            group, size = [], 0
        group.append(line)
        size += cost
    if group:
        groups.append(group)
    out = []
    for number, group in enumerate(groups):
        lines = list(group)
        if kind == "f":
            lines = [opener, *lines, closer]
        elif kind == "t":
            lines = [header[0] if number == 0 else _chunk_header(header[0]), header[1], *lines]
        if number == 0:
            original = rows[index][:len(rows[index]) - len(contents[0])]
            out.append(original + lines[0])
            kept = _prefix_of(stack)
            out += [kept + line if line.strip() else kept.rstrip() for line in lines[1:]]
        else:
            out += ["", "\u200b", ""] + ([first_line, prefix.rstrip()] if first_line else [])
            out += [prefix + line if line.strip() else prefix.rstrip() for line in lines]
    return out


def paragraph_pieces(text: str) -> str:
    """*text* (for Qt's own parser, after its passes) with each paragraph of
    the top level longer than PARAGRAPH_CHARS cut in pieces where nothing
    is open (a code span, a link, emphasis, a formula, a mark of
    fallback_text's, a tag): before a space or a line end."""
    weight = picture_weight()
    if len(text) * weight < PARAGRAPH_CHARS or (len(text) < PARAGRAPH_CHARS and not _PICTURE_SIGNS.search(text)):
        return text
    rows, out, fence, run = text.split("\n"), [], None, []
    ended = block_ends(rows)

    def flush() -> None:
        if run:
            joined = "\n".join(run)
            heavy = len(joined) + (weight - 1) * len(_PICTURE_SIGNS.findall(joined)) \
                if len(joined) * weight > PARAGRAPH_CHARS else len(joined)
            out.append(_pieces_of(_shorter_code_spans(joined)) if heavy > PARAGRAPH_CHARS else joined)
            run.clear()

    table = False  # (in a table: from a row over a delimiter row to an empty line)
    for number, line in enumerate(rows):
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line.strip().strip(fence[0]):
                fence = None
            out.append(line)
            continue
        after = rows[number + 1] if number + 1 < len(rows) else ""
        # (a table's row is a line over a delimiter row, and those after it - not any line with a "|" in it:
        # a paragraph of 2 MB with "`ls | wc`" in it was one piece, 1.2 s)
        table = bool(line.strip()) and (table or ("|" in line and bool(TABLE_DELIMITER.match(after))))
        prose = line.strip() and line[:1] not in " \t>#" and not LIST_ITEM.match(line) \
            and not REFERENCE.match(line) and not FRONT_LINE.match(line) \
            and not (TABLE_DELIMITER.match(line) and "|" not in line) and not _UNDERLINE.match(after) and not table
        # (a paragraph begins after an empty line, or after a block ended without one - block_ends: a heading,
        # a fence, a definition right above a long paragraph made it one piece, 1.1 to 1.4 s)
        if opened or not prose or (not run and number and rows[number - 1].strip()
                                   and not (ended[number - 1] and not (REFERENCE.match(rows[number - 1])
                                                                        and _titled(line)))):
            flush()
            if opened:
                fence = opened.group(1)
            # (a list item's, a quote's line: its long code spans shorter too)
            out.append(_shorter_code_spans(line) if not opened and len(line) > PARAGRAPH_CHARS else line)
            continue
        run.append(line)
    flush()
    return "\n".join(out)


_BACKTICKS = re.compile(r"`+")


def _shorter_code_spans(paragraph: str) -> str:
    """*paragraph* with each code span longer than PARAGRAPH_CHARS shortened to that, "…" after it: Qt
    lays a code span out as one piece, and no cut inside one keeps it a span (its own runs of backticks
    are next to every place) - one of 90,000 characters held the window 1 to 1.7 s (Qt's own parser;
    markdown-it's page keeps all of it, in spans one after another)."""
    if "`" not in paragraph:
        return paragraph
    out, at, opener = [], 0, None
    for run in _BACKTICKS.finditer(paragraph):
        if opener is None:
            if run.start() and paragraph[run.start() - 1] == "\\":
                continue
            opener = run
        elif len(run.group(0)) == len(opener.group(0)):
            if run.start() - opener.end() > PARAGRAPH_CHARS:
                inner = paragraph[opener.end():opener.end() + PARAGRAPH_CHARS].rstrip("`")
                out.append(paragraph[at:opener.end()] + inner + " …" + run.group(0))
                at = run.end()
            opener = None
    if not out:
        return paragraph
    return "".join(out) + paragraph[at:]


_EMPHASIS_RUN_AT = re.compile(r"\*+|_+")
#: The characters of a link's address its text's pieces may hold in all (_span_partners): each piece of a long
#: link's text is a link to the same address.
LINK_REPEAT = 60_000
#: An autolink longer than this many characters is shown as text (_long_autolinks): each piece of it would hold
#: all of it as its address again.
AUTOLINK_SHOWN = 4 * PARAGRAPH_CHARS


def _span_partners(paragraph: str) -> dict[int, tuple[int, str, str, str]]:
    """The spans of *paragraph* (Qt's own parser's) a cut may end and begin again (_pieces_of), by where
    each opens: ``{start: (end, kind, opener, closer)}`` - an inline link's text ("[", its "](address)"),
    a reference link's ("[", "][label]"), brackets that make no link ("", ""), emphasis ("*", "**", "_",
    ...) with its partner run, a mark of fallback_text's with its partner. In one pass, each kind kept on
    a stack of its own; an image's alt, what is in code or a formula never. *end*: where the span's
    closer begins."""
    partners: dict[int, tuple[int, str, str, str]] = {}
    hidden = bytearray(len(paragraph))  # (code spans and formulas: nothing in them opens or closes)
    for start, end in code_span_bounds(paragraph):
        hidden[start:end] = b"\x01" * (end - start)
    at = paragraph.find(MATH_INLINE)
    while at >= 0:
        end = paragraph.find(SPAN_END, at)
        end = len(paragraph) if end < 0 else end + 1
        hidden[at:end] = b"\x01" * (end - at)
        at = paragraph.find(MATH_INLINE, end)
    brackets, runs, marks = [], [], []
    closers = {chr(ord(mark) + 1): mark for mark in MARKS.values()}
    escaped = -1
    for match in _PIECE_STOPS.finditer(paragraph):
        ch, at = match.group(0), match.start()
        if hidden[at] or at == escaped:
            continue
        if ch == "\\":
            escaped = at + 1
        elif ch == "[":
            brackets.append(at)
        elif ch == "]" and brackets:
            begin = brackets.pop()
            if paragraph[begin - 1:begin] == "!" and (begin < 2 or paragraph[begin - 2] != "\\"):
                continue  # (an image: its alt never cut around - it would be two images)
            after = paragraph[at + 1:at + 2]
            if after == "(":
                destination = _DESTINATION.match(paragraph, at)  # (anchored: as far as its parentheses only)
                # (each piece of its text holds its address again: a long one only for a text of few pieces)
                if destination and len(destination.group(0)) * ((at - begin) // PARAGRAPH_CHARS + 1) <= LINK_REPEAT:
                    partners[begin] = (at, "link", "[", destination.group(0))
            elif after == "[":
                end = paragraph.find("]", at + 2, at + 2 + 1000)
                if end > 0 and "[" not in paragraph[at + 2:end]:
                    partners[begin] = (at, "link", "[", paragraph[at:end + 1])
            else:
                partners[begin] = (at, "text", "", "")  # (literal brackets: cut as text)
        elif ch in "*_":
            if paragraph[at - 1:at] == ch and at:
                continue  # (inside a run: its first character counts)
            run = _EMPHASIS_RUN_AT.match(paragraph, at).group(0)
            before = paragraph[at - 1:at] or " "
            after = paragraph[at + len(run):at + len(run) + 1] or " "
            closes = not before.isspace() and (ch == "*" or not after.isalnum())
            opens = not after.isspace() and (ch == "*" or not before.isalnum())
            if closes and runs and runs[-1][1] == run:
                begin, _run = runs.pop()
                partners[begin] = (at, "em", run, run)
            elif opens:
                runs.append((at, run))
                del runs[:-64]  # (only the latest: a closer looks at the last one)
        elif ch in closers:
            if marks and paragraph[marks[-1]] == closers[ch]:
                begin = marks.pop()
                partners[begin] = (at, "mark", paragraph[begin], ch)
        elif ch in MARKS.values():
            marks.append(at)
    return partners


def _long_autolinks(paragraph: str, limit: int) -> str:
    """*paragraph* with each autolink ("<https://…>") longer than *limit* written as an inline link, its
    address its text (as written: its Markdown escaped) - so that a cut inside it ends the link and begins
    it again (_pieces_of): one of 99,000 letters was one piece, 1.5 s."""
    if "<" not in paragraph:
        return paragraph

    def linked(match: re.Match) -> str:
        written = match.group(0)
        if len(written) <= limit:
            return written
        address = written[1:-1]
        if len(address) > AUTOLINK_SHOWN:  # (no address so long works anywhere: its letters as text)
            return _MD_SPECIAL.sub(r"\\\1", address)
        target = ("mailto:" + address) if "@" in address and ":" not in address else address
        target = target.replace("(", "%28").replace(")", "%29").replace("\\", "%5C")
        return "[" + _MD_SPECIAL.sub(r"\\\1", address) + "](" + target + ")"

    return _AUTOLINK.sub(linked, paragraph)


def _pieces_of(paragraph: str) -> str:
    """*paragraph* cut in pieces (see paragraph_pieces) - emoji and pictures counted as picture_weight()
    letters each (a colour bitmap each: 50,000 emoji held a CI runner's window 1.4 s). A cut inside a
    link's text, emphasis or a mark ends them in the piece before it and begins them again after it (the
    same address, the same emphasis): a word of 99,000 letters in a link or emphasis was one piece, 1.3 s."""
    pictures, weight = len(_PICTURE_SIGNS.findall(paragraph)), picture_weight()
    limit = PARAGRAPH_CHARS if not pictures else max(
        piece_floor(weight), int(PARAGRAPH_CHARS * len(paragraph) / (len(paragraph) + (weight - 1) * pictures)))
    from core.markdown_doc import cluster_end

    paragraph = _long_autolinks(paragraph, limit)
    partners = _span_partners(paragraph)
    marks = {MARKS[name]: name for name in MARKS}
    pieces, begun, depth, code, link, math, tag = [], 0, 0, 0, 0, False, False
    escaped, after, spans = -1, 0, 0  # (after: where the run of letters since the last stop begins)
    opened: list = []  # (the spans open here a cut may end and begin again: (end, kind, opener, closer))
    ends: dict = {}  # (where each of them ends)
    address_end = 0  # (the end of the address of the link last ended)
    prefix = ""  # (what the next piece begins with: the spans open at the cut, begun again)

    def cuttable() -> bool:
        return not (code or math or depth or link or tag)

    def cut(at: int, skip: int = 0) -> None:
        """A piece up to *at*, the spans open there ended in it; the next begins at *at* + *skip*."""
        nonlocal begun, prefix
        pieces.append(prefix + paragraph[begun:at] + "".join(span[3] for span in reversed(opened)))
        prefix = "".join(span[2] for span in opened)
        begun = at + skip

    def drop_open() -> None:
        """(open for too long, nothing to end it with: as text from here - a bracket never closed)"""
        nonlocal depth, link, tag
        depth = link = 0
        tag = False

    def letters(upto: int) -> None:
        """No space for twice as long, nothing open (or only what a cut ends and begins again): cut in the
        run of letters before *upto* (99,000 letters in one word, "`a" 5,000 times held the window 1.4 s
        and 0.7 s in Qt's layout)."""
        while upto - begun >= 2 * limit and cuttable():
            cut_at = max(after, begun + limit)
            if cut_at >= upto:
                return
            cut_at = cluster_end(paragraph, cut_at - 1) if cut_at > 0 else cut_at
            if cut_at >= upto:
                return
            cut(cut_at)

    for match in _PIECE_STOPS.finditer(paragraph):
        ch, at = match.group(0), match.start()
        if at > after:
            letters(at)
        after = at + 1
        if at - begun >= 2 * limit and not code and not math and at != escaped and at >= address_end:
            # (open for twice as long and no space: a bracket, a tag never closed - "[" 99,000 times, "<a"
            # 49,500 times were one piece, 1 to 4 s in Qt's layout; cut before this one all the same - the
            # spans a cut ends and begins again kept; never in a link's address it knows)
            if not cuttable():
                drop_open()
            cut(at)
            spans = 0
        if at == escaped:  # (the character after a backslash: as written)
            continue
        if at in ends:  # (a span's end: what closes it is the paragraph's own)
            span = ends.pop(at)
            opened.remove(span)
            if span[1] == "link" and span[3][:2] == "](":
                link += 1  # (its address: never cut in)
                address_end = at + len(span[3])
            continue
        if math:
            math = ch != SPAN_END
        elif code:
            # (a code span ends at a run of backticks as long as the one that opened it)
            if ch == "`" and (at == 0 or paragraph[at - 1] != "`"):
                end = at
                while end < len(paragraph) and paragraph[end] == "`":
                    end += 1
                if end - at == code:
                    code = 0
        elif ch == "\\":
            escaped = at + 1
        elif ch == "`":
            if at and paragraph[at - 1] == "`":
                continue
            spans += 1
            if (at - begun >= 2 * limit or spans > PARAGRAPH_CODE_SPANS) and cuttable():
                cut(at)  # (before a code span: nothing open, or only what a cut ends and begins again)
                spans = 1
            end = at
            while end < len(paragraph) and paragraph[end] == "`":
                end += 1
            code = end - at
        elif ch == MATH_INLINE:
            math = True
        elif at in partners and not link and not tag and partners[at][0] not in ends:
            span = partners[at]
            if span[1] == "em":
                # (before an emphasis begins, past PARAGRAPH_CODE_SPANS of them: "*a" 49,500 times was 1,000
                # italic letters a piece - 9,000 fragments a part, 0.14 s)
                spans += 1
                if spans > PARAGRAPH_CODE_SPANS and cuttable():
                    cut(at)
                    spans = 1
            opened.append(span)
            ends[span[0]] = span
        elif ch in marks:
            depth += 1  # (a mark without its partner: open, never ended by a cut)
        elif "\ue070" <= ch <= "\ue08f":
            depth = max(0, depth - 1)
        elif ch == "[":
            depth += 1  # (an image's alt; a bracket never closed)
        elif ch == "]":
            depth = max(0, depth - 1)
            if paragraph[at + 1:at + 2] == "(":
                link += 1
        elif ch == "(" and link:
            if paragraph[at - 1:at] != "]":
                link += 1
        elif ch == ")" and link:
            link -= 1
        elif ch == "<":
            tag = True
        elif ch == ">":
            tag = False
        elif ch in "*_":
            # (a run that is no emphasis's - a lone "*": text)
            if paragraph[at - 1:at] not in "*_":
                spans += 1
                if spans > PARAGRAPH_CODE_SPANS and cuttable():
                    cut(at)
                    spans = 1
        elif at - begun >= limit and paragraph[at - 1:at] not in ("\\", " "):
            if not cuttable():
                if at - begun < 2 * limit:
                    continue
                # (open for that long: never closed - a mark whose partner _fewer_marks took - so cut all
                # the same: a paragraph of 60,000 formulas was one piece)
                drop_open()
            cut(at, 1)
            spans = 0
    after = max(after, begun)
    letters(len(paragraph))
    pieces.append(prefix + paragraph[begun:])
    return ("\n\n" + JOINED).join(pieces)


_DETAILS_TAGS = re.compile(r"<(/?)(details|summary)\b([^<>]*)>", re.IGNORECASE)
_OPEN_ATTRIBUTE = re.compile(r"(?:^|\s)open(?:\s|=|/|$)", re.IGNORECASE)


def _fold_details(text: str, toggled=frozenset(), hidden: dict | None = None) -> str:
    """*text* (Qt's own parser's) with what each closed ``<details>`` holds after its summary left out, as
    GitHub shows it and markdown-it's page does (ui.markdown_html.fold_details): closed unless it says
    ``open`` or its number (1, 2 ... in the text's order) is in *toggled* - a click on its summary turns it.
    Its summary a link "▸ …" / "▾ …" that does ("Details" when it has none). Qt's own parser showed every
    one open. *hidden* gets what the closed ones hold ({"text": {number: text}, "anchors": {}}: find opens
    the one it finds in). Nothing in fenced code counts. Linear."""
    if "<details" not in text and "<DETAILS" not in text.upper():
        return text
    fenced = []  # (where fenced code is: [start, end) of each)
    at, fence, start = 0, None, 0
    for line in text.split("\n"):
        opened = FENCE.match(line.lstrip(" \t>-+*0123456789.)") if line[:1] in " \t>-+*0123456789" else line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fenced.append((start, at + len(line)))
                fence = None
        elif opened:
            fence, start = opened.group(1), at
        at += len(line) + 1
    if fence is not None:
        fenced.append((start, len(text)))
    edits, stack, number, hiding = [], [], 0, None  # (hiding: the entry whose contents go, or None)
    fences = iter(fenced)
    code = next(fences, None)
    for match in _DETAILS_TAGS.finditer(text):
        while code is not None and code[1] <= match.start():
            code = next(fences, None)
        if code is not None and code[0] <= match.start():
            continue  # (in fenced code: as written)
        closing, name = match.group(1), match.group(2).lower()
        if name == "details" and not closing:
            number += 1
            shown = bool(_OPEN_ATTRIBUTE.search(match.group(3))) != (number in toggled)
            stack.append({"number": number, "open": shown, "tag": match, "summary": None, "from": None})
            continue
        if not stack:
            continue
        entry = stack[-1]
        if name == "summary" and entry["summary"] is None and hiding is None:
            if not closing:
                entry["summary"] = match
            continue
        if name == "summary" and closing and isinstance(entry["summary"], re.Match) and hiding is None:
            begin = entry["summary"]
            inner = " ".join(text[begin.end():match.start()].split()) or tr("Details")
            edits.append((begin.start(), match.end(), _summary_line(entry, inner)))
            entry["summary"] = True
            if not entry["open"]:
                hiding, entry["from"] = entry, match.end()
            continue
        if name == "details" and closing:
            stack.pop()
            if hiding is None and entry["summary"] is not True:  # (none: "Details")
                edits.append((entry["tag"].end(), entry["tag"].end(), _summary_line(entry, tr("Details"))))
                if not entry["open"]:
                    hiding, entry["from"] = entry, entry["tag"].end()
            if hiding is entry:
                if hidden is not None:
                    hidden.setdefault("text", {})[entry["number"]] = " ".join(
                        _DETAILS_TAGS.sub(" ", text[entry["from"]:match.start()]).split())
                    hidden.setdefault("anchors", {})
                edits.append((entry["from"], match.start(), "\n\n"))
                hiding = None
    if hiding is not None:  # (never closed: to the end)
        edits.append((hiding["from"], len(text), "\n\n"))
    if not edits:
        return text
    out, at = [], 0
    for begin, end, replacement in sorted(edits, key=lambda edit: edit[0]):
        if begin < at:
            continue  # (inside what a closed one leaves out)
        out += [text[at:begin], replacement]
        at = end
    out.append(text[at:])
    return "".join(out)


def _summary_line(entry: dict, inner: str) -> str:
    """A <details>' summary as a line of its own: a link that opens or folds it, "▾" open, "▸" closed."""
    sign = "▾" if entry["open"] else "▸"
    inner = inner.replace("[", "\\[").replace("]", "\\]")
    return f"\n\n[{sign} {_open('bold')}{inner}{_close('bold')}](#{FOLD}{entry['number']})\n\n"


def fallback_text(text: str, toggled=frozenset(), hidden: dict | None = None) -> str:
    """*text* for Qt's own parser (md4c: the fallback without markdown-it-py)
    showing what markdown-it's page shows: raw HTML as the Markdown of its
    allowed subset (core.markdown_doc's sanitizer: emphasis, links, images,
    headings, a <details>' summary - closed ones folded: _fold_details -,
    tables; comments, scripts and any other tag gone), GitHub's alerts with
    their title, emoji short codes, math as text (core.markdown_doc.math_text),
    a remote image as a link "▣ alt" to it - never in code (fenced, indented,
    in backticks)."""
    from core.markdown_doc import by_lines

    text = _front_matter(by_lines(lambda piece: _PRIVATE.sub("", piece), text))
    text = _fold_details(text, toggled, hidden)
    if "|" in text or "#" in text or "-" in text or "=" in text:  # (blocks GFM reads otherwise than Qt's parser)
        text = "".join(segment if code else _tables_of_their_header(_headings_apart(segment))
                       for code, segment in _segments(text))
    if not any(mark in text for mark in ("<", "[!", ":", "$", "](", "^[", "math", "&")) \
            and not _SPACES_BETWEEN.search(text) \
            and not _HARD_BREAK.search(text) and not _QUOTE_AFTER_A_GAP.search(text):
        return text
    out, notes = [], []
    labels = defined_labels(text) if "![" in text else frozenset()
    for code, segment in _segments(text):
        if not code and out and _QUOTED_LAST.search(out[-1]):
            # (a quote whose code block ends it, a quote after it: apart -
            # _QUOTES_APART sees no quote's line before the gap there, and the
            # second came into the first one's box)
            segment = _QUOTE_AFTER_GAP.sub(f"\n{QUOTE_END}\n\n", segment, count=1)
        if code and _MATH_FENCE.match(segment):  # (GitHub's other way of writing a math block: as $$…$$ is)
            found = _MATH_FENCE.match(segment)
            segment, code = f"$$\n{found.group(2).rstrip()}\n$$\n", False
        out.append(segment if code else _outside_code(segment, notes, labels))
    if notes:  # (inline notes, ^[…]: notes of their own under the text, as markdown-it numbers them)
        out.append("\n\n" + "\n".join(f"[^{name}]: {body}" for name, body in notes) + "\n")
    return "".join(out)


#: A fenced block of the top level whose language is math ("```math").
_MATH_FENCE = re.compile(r"\A(`{3,}|~{3,})[ \t]*math[ \t]*\n(.*?)^\1[`~]*[ \t]*\n?\Z", re.DOTALL | re.MULTILINE)
#: Front matter (YAML between "---" lines, TOML between "+++") at a text's start.
_FRONT_MATTER = re.compile(r"\A(---|\+\+\+)[ \t]*\n(.*?)\n(?:\1|\.\.\.)[ \t]*(?:\n|\Z)", re.DOTALL)


def _front_matter(text: str) -> str:
    """Front matter as a code block of its language (Qt's own parser read
    its "---" as a rule and a heading: it was gone), as markdown-it's page
    shows it."""
    found = _FRONT_MATTER.match(text)
    if not found or "```" in found.group(2):
        return text
    from core import markdown_doc

    pairs = markdown_doc.front_matter_pairs(found.group(2))
    if pairs:  # (plain "key: value" lines: a table, as GitHub and markdown-it's page show them)
        def cell(value: str) -> str:
            return _md_escape(value) or " "

        return ("| " + " | ".join(cell(key) for key, _value in pairs) + " |\n|"
                + "|".join("---" for _pair in pairs) + "|\n| " + " | ".join(cell(value) for _key, value in pairs)
                + " |\n\n" + text[found.end():])
    lang = "yaml" if found.group(1) == "---" else "toml"
    return f"```{lang}\n{found.group(2)}\n```\n" + text[found.end():]


def _segments(text: str):
    """(is code, text) pieces of *text* in order: fenced and indented code
    blocks, and what lies between them (the line ends kept)."""
    from ui.markdown_safe import _CONTAINERS

    rows = text.splitlines(keepends=True)
    piece, code, fence, inset, in_list = [], False, None, 0, False
    for number, line in enumerate(rows):
        bare = line.rstrip("\r\n")
        if fence is not None:
            piece.append(line)
            closing = FENCE.match(bare[inset:])
            if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence) \
                    and not bare[inset:].strip().strip(fence[0]):
                yield True, "".join(piece)
                piece, fence = [], None
            continue
        prefix = _CONTAINERS.match(bare).end() if bare.strip() else 0
        whitespace = not bare[:prefix].strip()
        opened = None if whitespace and prefix >= 4 else FENCE.match(bare[prefix:])
        indented = bare.startswith(("    ", "\t")) and bare.strip() and not in_list \
            and (number == 0 or not rows[number - 1].strip() or code)
        if opened or indented:
            if piece and not code:
                yield False, "".join(piece)
                piece = []
            if opened:
                fence, inset = opened.group(1), prefix
            code = bool(indented)
            piece.append(line)
            continue
        if code and bare.strip():  # (an indented block ends)
            yield True, "".join(piece)
            piece, code = [], False
        if bare.strip():
            if LIST_ITEM.match(bare):
                in_list = True
            elif bare[:1] not in " \t":
                in_list = False
        piece.append(line)
    if piece:
        yield code or fence is not None, "".join(piece)


#: A definition list (markdown-it's deflist): a term, then lines ": …".
_DEFINITION = re.compile(r"^(?P<term>[^\s:>|#*+\-][^\n]*)\n(?P<defs>(?:: [^\n]*(?:\n|$))+)", re.MULTILINE)
#: An inline footnote: ^[its text].
_INLINE_NOTE = re.compile(r"\^\[([^\[\]\n]{1,1000})\]")


def _definitions(match: re.Match) -> str:
    """A term and its definitions for Qt's own parser (it knows no
    definition list: "Term : its definition" ran into one line) - the term
    bold, each definition a paragraph of its own, indented (INDENT)."""
    text = match.string
    if match.start() and text[max(0, match.start() - 2):match.start()] != "\n\n" and text[:match.start()].strip():
        return match.group(0)  # (a paragraph's last line, no term - not empty lines after a code block)
    definitions = [line[2:].strip() for line in match.group("defs").splitlines() if line.startswith(": ")]
    return f"**{match.group('term').strip()}**\n\n" + "\n\n".join(INDENT + line for line in definitions) + "\n"


_EMPHASIS_RUN = re.compile(r"(?<!\\)[*_]+")


#: Where _fewer_emphasis's paragraphs end: an empty line - or a line of a
#: table's row, a list's item, a heading (in a quote too): each its own
#: (a quoted table of 30,000 rows was one "paragraph": its emphasis past
#: row 300 shown as written).
_UNITS = re.compile(r"(\n[ \t>]*\n|\n(?=[ \t>]*(?:\||[-+*][ \t]|\d{1,9}[.)][ \t]|#)))")


def _fewer_emphasis(text: str) -> str:
    """A paragraph's emphasis marks past LINE_SPANS spans' escaped: shown as
    written, no span each (Qt laid a line of thousands out in time growing
    with their square: 9,900 italic words, 3.5 s)."""
    from core.markdown_doc import LINE_SPANS

    if text.count("*") + text.count("_") < 4 * LINE_SPANS:
        return text
    out = []
    for paragraph in _UNITS.split(text):
        runs = 0

        def escaped(match: re.Match) -> str:
            nonlocal runs
            runs += 1
            return match.group(0) if runs <= 2 * LINE_SPANS else "".join("\\" + ch for ch in match.group(0))

        if paragraph.count("*") + paragraph.count("_") <= 2 * LINE_SPANS:
            out.append(paragraph)
            continue
        at = 0  # (never in a formula: "x_{5992}" past the spans was copied "x\_{5992}")
        for formula in _MATH_SPAN.finditer(paragraph):
            out.append(_EMPHASIS_RUN.sub(escaped, paragraph[at:formula.start()]))
            out.append(formula.group(0))
            at = formula.end()
        out.append(_EMPHASIS_RUN.sub(escaped, paragraph[at:]))
    return "".join(out)


#: A formula of a paragraph ($…$, $$…$$) - left alone by _fewer_emphasis.
_MATH_SPAN = re.compile(r"\$\$[^$]{1,2000}?\$\$|(?<![\\$])\$(?![\s$])[^$\n]{1,2000}?(?<![\s\\])\$")


def _headings_apart(text: str) -> str:
    """*text* with an empty line after a heading in a list item or a quote that a line of the same item
    follows: Qt's own parser ran the two into one ("- Bar\\n  ---\\n  baz" showed "Barbaz": the spec's 278)."""
    if "#" not in text and "-" not in text and "=" not in text:
        return text
    rows = text.split("\n")
    out = []
    for number, line in enumerate(rows):
        out.append(line)
        if number + 1 >= len(rows) or not rows[number + 1].strip() or not line[:1] in " \t>-+*0123456789":
            continue
        lead = _CONTAINER_LEAD.match(line).group(0)
        rest = line[len(lead):]
        if not lead or not rest.strip():
            continue
        heading = _ATX_HEADING.match(rest) or (_UNDERLINE.match(rest) and number and rows[number - 1].strip()
                                               and _CONTAINER_LEAD.match(rows[number - 1]).end()
                                               < len(rows[number - 1]))
        after = rows[number + 1]
        if heading and not LIST_ITEM.match(after) and not _ATX_HEADING.match(after.lstrip(" \t>")):
            out.append(_CONTAINER_LEAD.match(after).group(0).rstrip())
    return "\n".join(out)


def _tables_of_their_header(text: str) -> str:
    """*text* with a "table" whose header has more or fewer cells than its delimiter row as text - GFM
    reads none there; Qt's own parser made a table of it and dropped what did not fit (the spec's 203)."""
    if "|" not in text or "-" not in text:
        return text
    rows = text.split("\n")
    for number in range(1, len(rows)):
        row = rows[number]
        if "|" in row and "-" in row and "|" in rows[number - 1] and TABLE_DELIMITER.match(row) \
                and _cells(rows[number - 1]) != _cells(row):
            lead = len(row) - len(row.lstrip(" "))
            rows[number] = row[:lead] + "\\" + row[lead:]
    return "\n".join(rows)


def _outside_code(text: str, notes: list | None = None, labels: set | frozenset = frozenset()) -> str:
    """The passes of fallback_text on text that holds no code block (its
    code spans kept as written); an inline note's text goes to *notes*;
    *labels*: the text's link reference definitions' (defined_labels)."""
    kept: list[str] = []

    def keep(span: str) -> str:
        kept.append(span)
        return f"{_KEPT}{len(kept) - 1}{_KEPT}"

    text = _code_spans(text.replace(_KEPT, ""), keep, formulas=True)
    if "]:" in text:  # (a link's reference definition: kept as Qt's own parser reads one - before the passes)
        text = _LINK_DEFINITION.sub(lambda m: keep(_link_definition(m)), text)
        # (and "[foo]: <bar>(baz)" is none - text right after its "<…>": its "[" as text, Qt's own parser took
        # it for one and showed nothing of it - the spec's 170)
        text = _NO_DEFINITION.sub(lambda m: m.group(1) + "\\[", text)
    text = _fewer_emphasis(text)
    if "](<" in text:  # (an address in <…>: written as one without - its "<" read as a tag, then escaped)
        text = _ANGLE_DESTINATION.sub(_unangled, text)
        # (one that is none - "<" never closed on its line, text after its ">": no link, CommonMark - Qt's own
        # parser made "[a](<b)c" the link "a", and "[link](<foo\nbar>)" too: the spec's 500 to 503)
        text = text.replace("](<", "]\\(<")
    # a remote image: "▣ alt" (in a link: that link's text) - never loaded
    text = _LINKED_REMOTE_IMAGE.sub(lambda m: f"[{CHIP} {m.group(1) or _name_of(m.group(2))}]({m.group(3)})", text)
    text = _REMOTE_IMAGE.sub(lambda m: f"{CHIP} {m.group(1) or _md_escape(_name_of(m.group(2)))}", text)
    # an image without alt text: its file's name (Qt's own parser showed none at all)
    text = re.sub(r"!\[\]\((<[^<>\n]*>|[^()\s]+)",
                  lambda m: f"![{_md_escape(_name_of(m.group(1).strip('<>')))}]({m.group(1)}", text)
    # a link's address and an autolink as written: no pass changes them
    # (a look-alike host of a link's address in punycode: followed as markdown-it's page follows it)
    text = _DESTINATION.sub(lambda m: keep(_ADDRESS.sub(lambda a: a.group(1) + _safe_host(a.group(2)), m.group(0),
                                                        count=1)), text)
    # (a look-alike host - "аррӏе.com" - in punycode, shown and followed: core.markdown_doc.safe_host_url)
    text = _AUTOLINK.sub(lambda m: keep("<" + _safe_shown(m.group(0)[1:-1]) + ">"), text)
    text = _bare_links(text, keep)
    if "](" in text:  # (a link hiding javascript: behind a tab: its text - core.markdown_doc)
        from core import markdown_doc

        text = markdown_doc._HIDDEN_BAD_LINK.sub(markdown_doc._hidden_bad, text)
    # (spaces between words: one, as markdown-it and a browser show them -
    # Qt's own parser kept every one; indentation and a line end's two stay)
    text = _SPACES_BETWEEN.sub(" ", text)
    if "&" in text:
        text = _ENTITY.sub(_entity, text)
    text = _html_to_markdown(text, keep)
    text = _ALERT_LINE.sub(_alert_title, text)
    if ": " in text:
        text = _DEFINITION.sub(_definitions, text)
    if notes is not None and "^[" in text:
        def note(match: re.Match) -> str:
            notes.append((f"axross-inline-{len(notes) + 1}", match.group(1)))
            return keep(f"[^{notes[-1][0]}]")

        text = _INLINE_NOTE.sub(note, text)
    text = _QUOTES_APART.sub(lambda m: f"{m.group(1)}\n{QUOTE_END}\n\n", text)
    text = _short_code().sub(_emoji_of, text)
    if "$$" in text:  # (in a quote, an alert, a list item: its lines' prefix taken off, put back)
        text = _PREFIXED_MATH.sub(lambda m: _prefixed_math(m, keep), text)
    text = _BLOCK_MATH.sub(lambda m: _math_block(m.group(1) if m.group(1) is not None else m.group(2), keep), text)
    if "$$" in text:  # ("$$…$$" in a paragraph: inline, as markdown-it shows it - it stayed as written)
        text = _INLINE_DOUBLE_MATH.sub(lambda m: _math_inline(m.group(1), keep), text)
    text = _INLINE_MATH.sub(_formulas_of_lines(text, keep), text)
    text = _HARD_BREAK.sub(HARD + "\n", text)  # (after the formulas: theirs are their rows)

    def restored(match: re.Match) -> str:  # (a span kept with a kept one in it - an autolink around a link's
        # address, "<http://e.com/?q=](uri)>": that one too - its mark showed in the page and in the link)
        span = kept[int(match.group(1))]
        return _KEPT_SPAN.sub(restored, span) if _KEPT in span else span

    text = _KEPT_SPAN.sub(restored, text)
    return _plain_alts(text, labels) if "![" in text else text


#: A character reference ("&ouml;", "&#0;", "&#x2603;") not escaped.
_ENTITY = re.compile(r"(?<!\\)&(?:#(\d{1,8})|#[xX]([0-9A-Fa-f]{1,8})|([A-Za-z][A-Za-z0-9]{1,31}));")


def _entity(match: re.Match) -> str:
    """A character reference as Qt's own parser should show it (CommonMark): a number that is no character
    - 0, a surrogate, past U+10FFFF - U+FFFD (Qt's showed U+0000), a name of HTML5's it does not know
    ("&Dcaron;", "&HilbertSpace;": shown as written) its character. One that stands for Markdown's own
    characters ("&ast;", "&lt;") is left to it."""
    import html.entities

    if match.group(3) is not None:
        char = html.entities.html5.get(match.group(3) + ";")
        if char is None or any(ch.isascii() and not ch.isalnum() for ch in char):
            return match.group(0)
        return char
    number = int(match.group(1)) if match.group(1) is not None else int(match.group(2), 16)
    if number == 0 or 0xD800 <= number <= 0xDFFF or number > 0x10FFFF:
        return "\ufffd"
    if number in (9, 10, 13):  # (a line end or a tab in the text: white space between its words - Qt's own
        return " "  # parser dropped them, "foo&#10;&#10;bar" was "foobar": the spec's 335)
    return match.group(0)


#: The label of a link's reference definition ("[label]: ..."), in a quote or a list too.
_DEFINED = re.compile(r"^[ \t>]*\[((?:[^\[\]\\\n]|\\.){1,999})\]:", re.MULTILINE)


def defined_labels(text: str) -> set[str]:
    """The labels (_label) of *text*'s link reference definitions."""
    return {_label(found.group(1)) for found in _DEFINED.finditer(text)} if "]:" in text else set()


def _plain_alts(text: str, labels: set | frozenset = frozenset()) -> str:
    """Every image's alt text plain (_plain_alt) - not in a code span. An
    image by reference with no label of its own ("![alt][]", "![alt]") gets
    its alt as its label, when *labels* (defined_labels) has it: the plain
    one matched no definition (the image was not shown), or the alt was
    laid out as it is - each piece of it a copy of the image."""
    spans: list[str] = []

    def keep(span: str) -> str:
        spans.append(span)
        return f"{_KEPT}{len(spans) - 1}{_KEPT}"

    def restored(span: str, inside: bool = False) -> str:
        return re.sub(_KEPT + r"(\d+)" + _KEPT,
                      lambda m: spans[int(m.group(1))].strip("`") if inside else spans[int(m.group(1))], span)

    text, out, at = _code_spans(text, keep), [], 0
    pairs = _bracket_pairs(text)
    while True:  # (each "![": its alt to the bracket that closes it - brackets in it, escaped ones)
        found = text.find("![", at)
        if found < 0:
            break
        end = pairs.get(found + 1)
        if end is not None and end - (found + 2) >= ALT_REACH:
            end = None
        after = text[end + 1:end + 2] if end is not None else ""
        collapsed = text[end + 1:end + 3] == "[]" if end is not None else False
        alt = text[found + 2:end] if end is not None else ""
        if end is not None and (collapsed or after != "(" and after != "[") and _label(restored(alt)) in labels:
            plain = _plain_alt(restored(alt, True))
            if plain != alt or collapsed:  # ("![alt][]", "![alt]": "![plain][alt]", its definition found)
                out += [text[at:found], "![", plain, "][", alt, "]"]
                at = end + (3 if collapsed else 1)
                continue
        if end is None or after not in ("(", "["):
            out.append(text[at:found + 2])
            at = found + 2
            continue
        out += [text[at:found], "![", _plain_alt(restored(alt, True)), "]"]
        at = end + 1
    out.append(text[at:])
    return restored("".join(out))


#: Characters an image's alt text reaches at most (_plain_alts): a bracket closing farther is none.
ALT_REACH = 2000
_BRACKET_STOPS = re.compile(r"\\.|[\[\]]|\n(?=\n)", re.DOTALL)


def _bracket_pairs(text: str) -> dict[int, int]:
    """{where a "[" of *text* is: where the "]" that closes it is} - nested ones, escaped ones, never over an
    empty line - in one pass (as _closing_bracket finds one: "![" 49,500 times, each looked for 2,000
    characters on, took 132 s)."""
    pairs, opened = {}, []
    for match in _BRACKET_STOPS.finditer(text):
        char = match.group(0)
        if char == "[":
            opened.append(match.start())
        elif char == "]":
            if opened:
                pairs[opened.pop()] = match.start()
        elif char == "\n":
            opened.clear()
    return pairs


def _plain_alt(alt: str) -> str:
    """An image's alt text as plain text for Qt's own parser: each piece of
    it its own copy of the picture - emphasis, a code span, an escape or an
    entity in it showed the picture three, five times ("my\\_pic\\_v2.png")."""
    import html as html_module

    plain = html_module.unescape(re.sub(r"\\(.)", r"\1", alt))
    plain = re.sub(r"[*`~\\&<>\[\]]", "", plain)  # (a bracket in it: the image's end, its pieces apart)
    plain = re.sub(r"(?<![^\W_])_|_(?![^\W_])", " ", plain)  # (a "_" not between letters: emphasis)
    return " ".join(plain.split())


_SPACES_BETWEEN = re.compile(r"(?<=[^\s|]) {2,}(?=[^\s|])")


_ADDRESS = re.compile(r"(\]\([ \t]*)([A-Za-z][A-Za-z0-9+.\-]*://[^()\s]+)")


def _safe_host(url: str) -> str:
    from core import markdown_doc

    return markdown_doc.safe_host_url(url)


def _safe_shown(address: str) -> str:
    """An autolink's address - an e-mail's too - its look-alike host in punycode (markdown_doc.safe_shown)."""
    from core import markdown_doc

    return markdown_doc.safe_shown(address)


def mail_address(url: QUrl) -> QUrl:
    """A mailto: link with its domain in punycode (as a status line and a
    question show it): "me@pаypal.com" read as the real one, percent-encoded
    "%D0%B0" was no help either."""
    if url.scheme().lower() != "mailto" or "@" not in url.path():
        return url
    local, _at, domain = url.path().rpartition("@")
    shown = QUrl(url)
    shown.setPath(local + "@" + (bytes(QUrl.toAce(domain)).decode("ascii", "replace") or domain))
    return shown


#: A raw HTML tag open before a place of its line (an attribute's value is there).
_IN_TAG = re.compile(r"<[A-Za-z][^<>]*\Z")


#: A link's reference definition on a line of its own ("[r]: <url> "title""
#: - in a quote or a list item too); not a footnote's.
_NO_DEFINITION = re.compile(r"^([ \t>]{0,8})\[(?=(?!\^)[^\]\n]{1,999}\]:[ \t]*<[^<>\n]*>[^\s])", re.MULTILINE)
_LINK_DEFINITION = re.compile(r"^([ \t>]*\[(?!\^)[^\]\n]+\]:[ \t]*)(?:<([^<>\n]*)>|([^\s<]\S*))"
                              r"((?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*)$", re.MULTILINE)


def _link_definition(match: re.Match) -> str:
    """A link's reference definition as Qt's own parser reads it: its
    address without "<…>" (spaces in it as %20; a look-alike host in
    punycode) - an autolink pass made "<https://…>" a link of its own, the
    reference's address "[https://…](https://…)"."""
    address = (match.group(2) if match.group(2) is not None else match.group(3)).replace(" ", "%20")
    return match.group(1) + (_safe_host(address) if "://" in address else address) + match.group(4)


def _bare_links(text: str, keep) -> str:
    """A bare http(s) address as an autolink ("<…>") - as GFM reads it
    (core.markdown_doc._bare_link: its trailing punctuation out): Qt's own
    parser lost "https://x.org/a_(b)" to the "_" it took for emphasis. Not in
    a link's text ("[" before it on its line, not closed)."""
    from core import markdown_doc

    # (its line up to each address, counted on from the address before - not its line again for each:
    # 100,000 addresses on one line took 129 s)
    state = {"at": 0, "open": 0, "angle": -1}  # (counted up to; "[" less "]" on its line; its last "<" or ">")

    def inside(string: str, start: int) -> bool:
        """Whether *start* is in a link's text ("[" before it on its line, not closed) or a raw HTML tag."""
        begin = state["at"]
        line_end = string.rfind("\n", begin, start)
        if line_end >= 0:
            state["open"], state["angle"], begin = 0, -1, line_end + 1
        state["open"] += string.count("[", begin, start) - string.count("]", begin, start)
        angle = max(string.rfind("<", begin, start), string.rfind(">", begin, start))
        if angle >= 0:
            state["angle"] = angle
        state["at"] = start
        angle = state["angle"]
        return state["open"] > 0 or (angle >= 0 and string[angle] == "<" and angle + 1 < start
                                     and string[angle + 1].isascii() and string[angle + 1].isalpha())

    def linked(match: re.Match) -> str:
        written = match.group(0)
        if "://" not in written or inside(match.string, match.start()):
            return written  # (in a link's text; in a raw HTML tag - its attribute: no link, the tag broken)
        bare = markdown_doc._bare_link(written)
        if bare is None:
            return written
        return keep(f"<{_safe_host(bare[0])}>") + written[len(bare[0]):]

    return markdown_doc._BARE_LINK.sub(linked, text) if "://" in text else text


def _short_code() -> re.Pattern:
    from core import markdown_doc

    return markdown_doc._SHORT_CODE


def _md_escape(text: str) -> str:
    """*text* with Markdown's own characters escaped (it is shown as it is)."""
    return _MD_SPECIAL.sub(r"\\\1", text)


def _emoji_of(match: re.Match) -> str:
    from core import markdown_doc

    return markdown_doc.emoji_for(match.group(1), match.group(0))


#: Signs that join or vary an emoji, drawn as part of it (no glyph a font must have).
_EMOJI_JOINERS = frozenset(chr(c) for c in (0x200D, 0xFE0F, 0xFE0E, *range(0x1F3FB, 0x1F400)))


def emoji_fonts() -> None:
    """Which short codes' emoji the installed fonts can draw (once, on the GUI
    thread): those of no font stay as written - without a colour emoji font
    every one was an empty box (_window_emoji, core.markdown_doc.EMOJI_DRAWN).
    A monochrome font that has them (DejaVu Sans, Symbola) draws them."""
    from core import markdown_doc

    if _EMOJI_DRAWN:
        return
    from PyQt6.QtGui import QFont, QFontDatabase, QFontInfo, QFontMetrics

    families = QFontDatabase.families()
    # (the emoji fonts first - one usually has all; the rest only for what they lack - each font's metrics
    # made when it is its turn: all of a few hundred families' at once took the first view a while)
    families = sorted(families, key=lambda family: "emoji" not in family.lower())
    missing = {}
    for code, emoji in markdown_doc.EMOJI.items():
        signs = [ord(ch) for ch in emoji if ch not in _EMOJI_JOINERS]
        missing[code] = signs
    # (a machine without a font that has them all: every one of hundreds of families was asked for every
    # emoji still missing, on the GUI thread - opening a Markdown file held the window for minutes. Each
    # family is asked only for what is still missing, and the search ends after EMOJI_SCAN_SECONDS: what
    # no font asked by then has stays as written)
    import time

    # (all of it under the deadline - the default font's pass too, a few short codes at a time: Qt's metrics
    # answer with its fallback fonts, an emoji no font has looked for in each of them - 2,000 families
    # without an emoji font held the first view 0.6 s)
    deadline = time.monotonic() + EMOJI_SCAN_SECONDS
    total = len(missing)
    every = dict(missing)
    drawn, best, most = set(), "", 0
    for family in [None, *families]:
        if time.monotonic() > deadline:
            break
        metric = QFontMetrics(QFont() if family is None else QFont(family))
        found = []
        for number, (code, signs) in enumerate(missing.items()):
            if not number % EMOJI_SCAN_STEP and number and time.monotonic() > deadline:
                break
            if all(metric.inFontUcs4(sign) for sign in signs):
                found.append(code)
        for code in found:
            del missing[code]
        drawn.update(found)
        if len(found) > most:
            # (the default font that draws the most - DejaVu Sans on a machine without a colour emoji
            # font - is the page's emoji family too, as it was before the search asked only for what
            # was still missing: by its resolved name)
            best = family if family is not None else QFontInfo(QFont()).family()
            most = len(found)
        if not missing:
            break
    _EMOJI_DRAWN.append(None if len(drawn) == total else frozenset(drawn))
    _EMOJI_FAMILY.append(_colour_emoji_family(families, every) or best)


#: (emoji_fonts) emoji fonts asked at most whether they draw the emoji themselves.
EMOJI_FAMILIES_ASKED = 4


def _colour_emoji_family(families: list, signs: dict) -> str:
    """An installed emoji font ("… Emoji" - Noto Color Emoji, Apple Color Emoji, Segoe UI Emoji) that draws
    at least half of the emoji *signs* ({short code: its code points}) itself, the one that draws most ("" for
    none). Asked of the font alone (QRawFont): QFontMetrics answered for the default font with Qt's fallback
    fonts too, so the default font - asked first - drew them all wherever the fallback reached the emoji font,
    and the page's emoji family was never the colour font (DejaVu Sans, a second font to look in for nothing)."""
    from PyQt6.QtGui import QFont, QRawFont

    best, most = "", len(signs) // 2
    for family in [family for family in families if "emoji" in family.lower()][:EMOJI_FAMILIES_ASKED]:
        raw = QRawFont.fromFont(QFont(family))
        if not raw.isValid():
            continue
        has = raw.supportsCharacter
        count = sum(1 for points in signs.values() if all(has(point) for point in points))
        if count > most:
            best, most = family, count
    return best


#: (emoji_fonts) how long the search for the installed fonts' emoji may hold the first view at most.
EMOJI_SCAN_SECONDS = 0.25
#: (emoji_fonts) the short codes asked of a font between two looks at the clock.
EMOJI_SCAN_STEP = 16


#: (emoji_fonts) the family that draws most of the emoji ("" none): the page's second font (MarkdownView) -
#: Qt looked for each emoji's font among all the system's (hundreds of families on a CI runner: 50,000
#: emoji held the window 2.6 s), now it is the one after the page's own.
_EMOJI_FAMILY: list = []


def with_emoji_family(font: QFont) -> QFont:
    """*font* with the family emoji_fonts found for emoji after its own (unchanged: none found)."""
    family = _EMOJI_FAMILY[0] if _EMOJI_FAMILY else ""
    if not family or family in font.families():
        return font
    font = QFont(font)
    font.setFamilies([*(font.families() or [font.family()]), family])
    return font


#: (emoji_fonts) the short codes the window's fonts draw - None: all.
_EMOJI_DRAWN: list = []


@contextlib.contextmanager
def _window_emoji():
    """A parse for the window: short codes of emoji no font of it has as written (emoji_fonts)."""
    from core import markdown_doc

    token = markdown_doc.EMOJI_DRAWN.set(_EMOJI_DRAWN[0] if _EMOJI_DRAWN else None)
    try:
        yield
    finally:
        markdown_doc.EMOJI_DRAWN.reset(token)


def _name_of(src: str) -> str:
    from urllib.parse import urlsplit

    return posixpath.basename(urlsplit(src).path) or tr("image")


def _code_spans(text: str, keep, formulas: bool = False) -> str:
    """*text* with each code span (a run of backticks to the next run of the
    same length) handed to *keep* - linear, as ui.markdown_safe's. *formulas*:
    a code span between two "$" - GitHub's $`x^2`$ - is a formula's TeX,
    left for the formulas' pass (only a code span's own backticks count:
    "`a$` then `$b`" stays two code spans)."""
    runs: dict[int, list[int]] = {}
    for m in re.finditer(r"`+", text):
        runs.setdefault(m.end() - m.start(), []).append(m.start())
    if not runs:
        return text
    taken = {length: 0 for length in runs}
    out, index = [], 0
    # (an autolink begun before a run of backticks holds it: "<http://foo.bar.`baz>`" is a link and a "`" -
    # the backtick in its address took the rest for code, its markup showed: the spec's 356)
    autolinks = iter([(found.start(), found.end()) for found in _AUTOLINK.finditer(text)] if "<" in text else [])
    autolink = next(autolinks, None)
    for m in re.finditer(r"`+", text):
        if m.start() < index:
            continue
        while autolink is not None and (autolink[1] <= m.start() or autolink[0] < index):
            autolink = next(autolinks, None)
        if autolink is not None and autolink[0] < m.start() < autolink[1]:
            continue
        length = m.end() - m.start()
        starts = runs[length]
        k = taken[length]
        while k < len(starts) and starts[k] <= m.start():
            k += 1
        taken[length] = k
        if k >= len(starts):
            continue
        end = starts[k] + length
        taken[length] = k + 1
        out.append(text[index:m.start()])
        if formulas and length == 1 and text[m.start() - 1:m.start()] == "$" and text[end:end + 1] == "$" \
                and text[m.start() - 2:m.start() - 1] != "\\" and end - m.start() > 2:
            out.append(text[m.start() + 1:end - 1])  # (the formula's TeX, its "$" around it)
        else:
            out.append(keep(text[m.start():end]))
        index = end
    out.append(text[index:])
    return "".join(out)


def _alert_title(match: re.Match) -> str:
    from ui.markdown_html import _title

    sign, title = _title(match.group(2).lower())
    return f"{match.group(1)}**{sign} {title}**\\"  # (a line of its own: a hard break)


def _math_escape(text: str) -> str:
    """A formula's text for Qt's own parser: every ASCII punctuation escaped
    (a row "-x" was a list item, "<" a "\\<"), its runs of spaces kept
    (no-break spaces: a matrix's columns line up), never in emphasis."""
    text = re.sub(r"([!-/:-@\[-`{-~])", r"\\\1", text)
    return re.sub(r" {2,}", lambda m: "\u00a0" * len(m.group(0)), text)


def _math_marked(tex: str, tight: bool = False) -> str:
    """A formula for Qt's own parser: its runs (core.markdown_doc.math_runs)
    escaped, with the marks apply_marks makes real sub- and superscript,
    bold, italic and code (what is not understood: that part only)."""
    from core import markdown_doc

    kinds = {"sub": "sub", "sup": "sup", "bold": "bold", "italic": "italic", "unknown": "code", "over": "over"}
    out = []
    runs = markdown_doc.math_runs(tex, small=False, tight=tight)  # (real sub- and superscripts)
    plain = sum(len(markdown_doc.VARIABLES.findall(text)) for text, _kind in runs) > markdown_doc.MATH_ITALICS
    for text, kind in runs:
        kind = kind.split(">")[-1]  # (a script of a script: raised or lowered as one - its "_b" was written)
        if kind.startswith("colour"):  # (\\textcolor, {\\color …}: its colour - it was none)
            out.append(COLOUR_ON + kind[8:] + COLOUR_NAMED if kind.startswith("colour:#") else COLOUR_OFF)
            continue
        text = markdown_doc.page_letters(text)  # (no letter a page's font has not: a box)
        if kind in ("", "over", "sub", "sup") and plain:  # (thousands of letters: no italic span each)
            shown = _math_escape(text.replace("\n", " "))
            out.append(shown if kind == "" else _open(kinds[kind]) + shown + _close(kinds[kind]))
            continue
        if kind in ("", "over", "sub", "sup"):  # (its letters - the variables - in italic, as KaTeX and
            italic = "".join(_open("italic") + _math_escape(piece) + _close("italic") if index % 2  # markdown-it's)
                             else _math_escape(piece)
                             for index, piece in enumerate(markdown_doc.VARIABLES.split(text.replace("\n", " "))))
            out.append(italic if kind == "" else _open(kinds[kind]) + italic + _close(kinds[kind]))
            continue
        shown = _math_escape(text.replace("\n", " "))
        out.append(_open(kinds[kind]) + shown + _close(kinds[kind]) if kind in kinds else shown)
    return "".join(out)


def _math_block(tex: str, keep, prefix: str = "") -> str:
    """A display formula for Qt's own parser - *prefix* before each of its
    lines: a quote's, an alert's "> ", a list item's indentation (it was
    left as written there)."""
    from core import markdown_doc
    from ui.markdown_html import display_items

    if len(tex) <= markdown_doc.MATH_LIMIT and display_items(tex):
        # (fractions, sums, matrices, cases: markdown-it's display - a row of items on one axis - put in its
        # place once the part is laid out: _math_displays; the formula in its mark, base64 as Markdown keeps it)
        written = base64.b64encode(tex.encode("utf-8")).decode("ascii")
        block = "\n\n" + MATH_HTML + written + SPAN_END + "\n\n"
    else:
        shown = markdown_doc.math_text(tex)
        lines = [line for line in shown.split("\n") if line]
        if len(lines) > 1:  # (rows: a monospace font, their columns in line)
            body = "\\\n".join(_math_escape(line) for line in lines)
            block = "\n\n" + ALIGNS["center"] + _open("rows") + body + _close("rows") + "\n\n"
        else:
            block = "\n\n" + ALIGNS["center"] + _open("math") + _math_marked(tex) + _close("math") + "\n\n"
    if prefix:
        block = "\n".join(prefix + line if line else prefix.rstrip() for line in block.split("\n"))
    return keep(block)


def _prefixed_math(match: re.Match, keep) -> str:
    prefix = match.group(1)
    tex = "\n".join(line[len(prefix):] for line in match.group(2).split("\n"))
    return _math_block(tex, keep, prefix)


def _formulas_of_lines(text: str, keep):
    """The replacement of each formula of *text* in a line: laid out as math -
    past core.markdown_doc.LINE_FORMULAS in a heading's or a table row's
    line, as its TeX (a heading of 8,000 held the window 4 s)."""
    import bisect

    from core.markdown_doc import LINE_FORMULAS

    starts = [0] + [match.end() for match in re.finditer("\n", text)] if "\n" in text else [0]
    seen: dict[int, int] = {}

    def formula(match: re.Match) -> str:
        line = bisect.bisect_right(starts, match.start()) - 1
        seen[line] = seen.get(line, 0) + 1
        if seen[line] > LINE_FORMULAS:
            head = text[starts[line]:starts[line] + 40].lstrip(" \t>")
            if head.startswith(("#", "|")) or "|" in text[starts[line]:match.start()][-200:]:
                return keep(_md_escape(match.group(0)))
        return _math_inline(match.group(1), keep)

    return formula


def _math_inline(tex: str, keep) -> str:
    # (its TeX in a mark before it - an anchor on its first letter once laid out: _inline_tex_marks)
    written = base64.b64encode(tex.encode("utf-8")).decode("ascii")
    return keep(MATH_INLINE + written + SPAN_END + _open("math") + _math_marked(tex) + _close("math"))


def _html_to_markdown(text: str, keep) -> str:
    """Raw HTML in *text* as the Markdown of its allowed subset (see
    fallback_text). Linear: each search goes on from where the last ended."""
    if "<" not in text:
        return text
    text = _drop_comments(text)
    out, index = [], 0
    dropped = _HTML_DROPPED.search(text)
    whole = _HTML_WHOLE.search(text)
    while True:
        # (each pattern searched again only once its match lies behind: a
        # search from every place again was quadratic - 20,000 <summary> 114 s)
        if dropped is not None and dropped.start() < index:
            dropped = _HTML_DROPPED.search(text, index)
        if whole is not None and whole.start() < index:
            whole = _HTML_WHOLE.search(text, index)
        found = min((m for m in (dropped, whole) if m), key=lambda m: m.start(), default=None)
        if found is None:
            out.append(_html_tags(text[index:], keep))
            break
        out.append(_html_tags(text[index:found.start()], keep))
        name = found.group(1).lower()
        close = re.compile(rf"</{name}\s*>", re.IGNORECASE).search(text, found.end())
        line_start = text.rfind("\n", 0, found.start()) + 1
        if close is not None and found is dropped and text[line_start:found.start()].strip():
            # (in a paragraph: closed in it, or not at all - the next paragraph is no part of it)
            gap = _BLANK_LINE.search(text, found.end())
            if gap is not None and gap.start() < close.start():
                close = None
        if close is None and found is dropped:
            # (prose that names it - "put it in a <script> tag": the tag as
            # text, as GitHub shows it; all that followed went with it)
            out.append(found.group(0))
            index = found.end()
            continue
        inner_end, after = (close.start(), close.end()) if close else (len(text), len(text))
        if found is whole:
            out.append(_html_whole(name, text[found.start():after], text[found.end():inner_end], keep))
        index = after
    return "".join(out)


_BLANK_LINE = re.compile(r"\n[ \t]*\n")


def _drop_comments(text: str) -> str:
    out, index = [], 0
    while True:
        start = text.find("<!--", index)
        if start < 0:
            out.append(text[index:])
            return "".join(out)
        end = text.find("-->", start + 4)
        out.append(text[index:start])
        if end < 0:
            return "".join(out)
        index = end + 3


def _html_tags(text: str, keep) -> str:
    """Each tag of *text* as its Markdown (the text between them as it is)."""
    from core import markdown_doc

    if "<" not in text:
        return text
    sanitizer = markdown_doc.sanitizer()
    out, links, scripts, index, opened = [], [], [], 0, []
    for m in _HTML_TAG.finditer(text):
        backslashes = m.start() - len(text[max(0, m.start() - 64):m.start()].rstrip("\\")) - max(0, m.start() - 64)
        if backslashes % 2 or not _VALID_TAG.fullmatch(m.group(0)):
            continue  # ("\<br/>", "<a href="hi'>": no tag, as written - the first was a line break, "\" before it)
        out.append(text[index:m.start()])
        index = m.end()
        for event in sanitizer.feed(m.group(0), markdown_doc.HTML_BLOCK) or [("end", "")]:
            out.append(_tag_markdown(event, links, scripts))
            if event[0] == "start" and event[1] == "a":
                opened.append(len(out) - 1 if out[-1].endswith("[") else None)
            elif event[0] == "end" and event[1] == "a" and opened:
                opened.pop()
    out.append(text[index:])
    for at in opened:  # (a link never closed - "<a href="x">" and no "</a>": no "[" of it left in the text)
        if at is not None:
            out[at] = out[at][:-1]
    return "".join(out)


def _tag_markdown(event, links: list, scripts: list) -> str:
    """The Markdown (and marks: MARKS) of one event of raw HTML's allowed
    subset. *links*: the addresses of the links open; *scripts*: the lists
    open (ul / ol, for their items)."""
    kind, tag = event[0], event[1] if len(event) > 1 else ""
    if kind == "text":
        return _md_escape(event[1])
    if kind == "start":
        attrs = event[2]
        if tag in _MARK_TAGS:
            return _open(_MARK_TAGS[tag])
        if tag == "br":
            return "  \n"
        if tag == "hr":
            return "\n\n---\n\n"
        if tag == "img":
            return _image_markdown(attrs, scripts)
        if tag == "a":
            links.append(attrs.get("href", ""))
            # (its name - <a id="v1.2.0"> - a mark the page keeps as the block's: read_outline, a link to it)
            named = ANCHOR_MARK + base64.b64encode(attrs["name"].encode("utf-8")).decode("ascii") + SPAN_END \
                if attrs.get("name") else ""
            return named + ("[" if attrs.get("href") else "")
        if tag in ("ul", "ol"):
            scripts.append(tag)
            return "\n\n"
        if tag == "li":
            depth = sum(1 for open_tag in scripts if open_tag in ("ul", "ol"))
            marker = "1. " if scripts and scripts[-1] == "ol" else "- "
            return "\n" + "   " * max(0, depth - 1) + marker
        if tag in _BLOCKS:
            align = attrs.get("align", "")
            scripts.append(f"align:{align}")
            return "\n\n" + ALIGNS.get(align, "")
        return ""
    if kind == "end":
        if tag in _MARK_TAGS:
            return _close(_MARK_TAGS[tag])
        if tag == "a" and links:
            href = links.pop()
            return f"]({href})" if href else ""
        if tag in ("ul", "ol") and tag in scripts:
            while scripts and scripts.pop() != tag:
                pass
            return "\n\n"
        if tag in _BLOCKS:
            for index in range(len(scripts) - 1, -1, -1):
                if scripts[index].startswith("align:"):
                    del scripts[index]
                    break
            return "\n\n"
        return ""
    return ""


def _image_markdown(attrs: dict, scripts: list) -> str:
    """A raw <img> as a Markdown image: its alt text (its file's name when
    it has none: Qt's own parser shows no image without), its asked size and
    its paragraph's alignment in its address's fragment (apply_marks)."""
    src = attrs.get("src", "")
    if not src:
        return ""
    alt = _md_escape(attrs.get("alt", "") or _name_of(src))
    if re.match(_REMOTE, src):  # (on the network: never loaded - a chip)
        return f"{CHIP} {alt}"
    align = next((entry[6:] for entry in reversed(scripts) if entry.startswith("align:")), "")
    spec = "".join(f":{key}={value}" for key, value in (("w", attrs.get("width", "")),
                                                          ("h", attrs.get("height", "")), ("a", align)) if value)
    if spec and not src.startswith("data:"):
        src = f"{src}{_IMAGE_SPEC}{spec[1:]}"
    return f"![{alt}]({src.replace(' ', '%20').replace('(', '%28').replace(')', '%29')})"


def _html_whole(name: str, written: str, inner: str, keep) -> str:
    """A <table>, <pre>, <h1>-<h6> or <summary> as Markdown of its own."""
    from html import unescape

    if name == "pre":
        body = unescape(re.sub(r"<[^<>]*>", "", inner)).strip("\n")
        longest = max((len(run) for run in re.findall(r"`{3,}", body)), default=2)
        fence = "`" * (longest + 1)
        return keep(f"\n\n{fence}\n{body}\n{fence}\n\n")
    if name == "table":
        return _html_table(written)
    line = " ".join(_html_tags(inner, keep).split())
    if name == "summary":
        return f"\n\n▾ {_open('bold')}{line}{_close('bold')}\n\n"
    align = re.search(r'\balign="?(center|right)', written[:200], re.IGNORECASE)
    return f"\n\n{'#' * int(name[1])} {ALIGNS[align.group(1).lower()] if align else ''}{line}\n\n"


def _html_table(written: str) -> str:
    """A raw-HTML table as a Markdown table (its cells' text, emphasis and
    images; the first row its header, aligned as its cells say)."""
    from core import markdown_doc

    rows, cell, align, aligns, links, opened, headed = [], None, "", [], [], [], False
    for event in markdown_doc.sanitizer().feed(written, markdown_doc.HTML_BLOCK):
        kind, tag = event[0], event[1]
        if kind == "start" and tag == "tr":
            rows.append([])
        elif kind == "start" and tag in ("th", "td"):
            headed = headed or (tag == "th" and len(rows) <= 1)
            cell, align, links, opened = [], event[2].get("align", ""), [], []
            span = (int(event[2].get("colspan", 1)), int(event[2].get("rowspan", 1)))
        elif kind == "end" and tag in ("th", "td") and cell is not None:
            if not rows:
                rows.append([])
            rows[-1].append((" ".join("".join(cell).split()).replace("|", "\\|"), *span))
            if len(rows) == 1:
                aligns.extend([align] * span[0])
            cell = None
        elif cell is not None:  # (a link of a cell: its address with it - "[link" lost it)
            cell.append(_tag_markdown(event, links, opened).replace("\n", " "))
    rows = [row for row in rows if row]
    if not rows:
        return "\n\n"
    # (spans: every cell under its own column, the spanning one marked -
    # _merge_spans merges its cells once Qt laid the table out)
    grid, spans = markdown_doc.span_grid(rows)
    rows = [["" if cell is None else cell for cell in row] for row in grid]
    for row, column, down, across in spans:
        rows[row][column] = f"{SPAN_MARK}{down}:{across}{SPAN_END}{rows[row][column]}"
    if not headed:  # (cells all: no header drawn bold on a tint - markdown-it's page shows none)
        rows[0][0] = NO_HEAD + rows[0][0]
    columns = max(len(row) for row in rows)
    rule = {"left": ":---", "center": ":---:", "right": "---:"}
    lines = ["| " + " | ".join(row + [""] * (columns - len(row))) + " |" for row in rows]
    delimiter = "|" + "|".join(rule.get(a, "---") for a in aligns + [""] * (columns - len(aligns))) + "|"
    return "\n\n" + "\n".join([lines[0], delimiter] + lines[1:]) + "\n\n"


# -- fenced code --



def _is_dark(palette: QPalette) -> bool:
    return palette.color(QPalette.ColorRole.Base).lightness() < 128


class CodeHighlighter(QSyntaxHighlighter):
    """Colours in fenced code blocks (any language: comments, strings,
    numbers, common keywords), in colours that suit the palette - made once
    a rendering (MarkdownView.render forgets them: a theme chosen since is
    taken then)."""

    formats: dict | None = None
    palette: QPalette | None = None

    def colours(self) -> dict:
        """{kind: QTextCharFormat} of GitHub's palette (ui.markdown_html),
        function names bold and comments italic as Pygments' github-dark.
        (Made anew for every line of code, they were most of the time a
        rendering took: a code block of 150,000 lines held the window 4 s.)"""
        if self.formats is None:
            from ui.markdown_html import GITHUB_DARK, GITHUB_LIGHT

            github = GITHUB_DARK if _is_dark(self.palette or QPalette()) else GITHUB_LIGHT
            self.formats = {}
            for kind, colour in github.items():
                fmt = QTextCharFormat()
                fmt.setForeground(QColor(colour))
                if kind == "function":
                    fmt.setFontWeight(QFont.Weight.Bold)
                elif kind == "comment":
                    fmt.setFontItalic(True)
                self.formats[kind] = fmt
        return self.formats

    def highlightBlock(self, text):  # noqa: N802 - Qt
        """A line of a fenced block in its language's colours (Pygments, as
        markdown-it's page) - none where its language is not known: a block
        without one, or "text", had "if", "in", "for" coloured as keywords."""
        block = self.currentBlock()
        if not block.blockFormat().hasProperty(QTextFormat.Property.BlockCodeFence) or not text:
            return
        language = block.blockFormat().stringProperty(QTextFormat.Property.BlockCodeLanguage)
        # (its colours as a worker had them lexed in a child - _lex_fences: lexed here, on the GUI
        # thread, a lexer's pattern stuck in backtracking froze the window)
        found = _LINE_KINDS.get(((language or "").strip().lower(), text))
        if not found:
            return
        formats = self.colours()
        for at, length, kind in found:
            self.setFormat(at, length, formats[kind])


@functools.lru_cache(maxsize=64)
def _lexer(lang: str):
    """Pygments' lexer of *lang*, or None (no language, plain text, none
    known, no Pygments)."""
    lang = (lang or "").strip().lower()
    if not lang or lang in ("text", "txt", "plain", "plaintext", "none", "nohighlight"):
        return None
    try:
        from pygments.lexers import get_lexer_by_name
        from pygments.util import ClassNotFound
    except ImportError:
        return None
    try:
        return get_lexer_by_name(lang, stripnl=False, ensurenl=False)
    except ClassNotFound:
        return None


#: (language, a line of a fenced block) -> its colours: (start, length, kind) - Qt's own parser's page
#: (_lex_fences fills it on a worker, highlightBlock reads it). At most LINE_KINDS lines.
_LINE_KINDS: dict = {}
LINE_KINDS = 50_000
_FENCE_BLOCK = re.compile(r"^(?P<lead>[ \t>]*?)(?P<fence>`{3,}|~{3,})[ \t]*(?P<lang>[\w+#.-]+)[^\n]*\n"
                          r"(?P<body>(?:.*\n)*?)(?P=lead)(?P=fence)[`~]*[ \t]*$", re.MULTILINE)


def _lex_fences(shown: str) -> None:
    """The colours of each line of *shown*'s fenced blocks of a language Pygments knows, for
    highlightBlock: each block lexed whole in a child process (core.markdown_doc.code_tokens - a block
    that takes too long stays plain)."""
    from core.markdown_doc import code_tokens

    if "``" not in shown and "~~" not in shown:
        return
    for match in _FENCE_BLOCK.finditer(shown):
        lang = match.group("lang").strip().lower()
        if _lexer(lang) is None:
            continue
        lead = match.group("lead")
        rows = [row[len(lead):] if row.startswith(lead) else row.lstrip(" \t>")
                for row in match.group("body").split("\n")[:-1]]
        if not rows or sum(map(len, rows)) > 200_000:
            continue
        tokens = code_tokens("\n".join(rows) + "\n", lang)
        if tokens is None:
            continue
        line, at, kinds = 0, 0, []
        for token, value in tokens:
            for number, part in enumerate(value.split("\n")):
                if number:
                    _LINE_KINDS[(lang, rows[line] if line < len(rows) else "")] = kinds
                    line, at, kinds = line + 1, 0, []
                kind = _token_kind(token) if part else None
                if kind is not None:
                    kinds.append((at, len(part), kind))
                at += len(part)
        if len(_LINE_KINDS) > LINE_KINDS:
            _LINE_KINDS.clear()


@functools.lru_cache(maxsize=512)
def _token_kind(token) -> str | None:
    """The GitHub palette's kind of a Pygments token type, or None (once a
    type: Pygments' "in" took 50 µs, half of laying out a part of code)."""
    from pygments.token import Comment, Generic, Keyword, Name, Number, Operator, String

    for types, kind in ((Keyword.Constant, "constant"), (Keyword, "keyword"), (Operator.Word, "keyword"),
                        (Name.Function, "function"), (Name.Decorator, "function"), (Name.Class, "class"),
                        (Name.Builtin, "constant"), (Name.Constant, "constant"), (Name.Attribute, "constant"),
                        (Name.Tag, "tag"), (String.Escape, "constant"), (String.Interpol, "constant"),
                        (String, "string"), (Number, "number"), (Comment, "comment"), (Operator, "constant"),
                        (Generic.Deleted, "deleted"), (Generic.Inserted, "tag")):
        if token in types:
            return kind
    return None


# -- images --

def elide_words(text: str, limit: int) -> str:
    """*text* at most *limit* characters: cut after a whole word, "…" after
    it."""
    if len(text) <= limit:
        return text
    cut = text[:max(1, limit - 1)]
    if " " in cut.strip():
        cut = cut[:cut.rstrip().rfind(" ")]
    return cut.rstrip() + "…"


def placeholder(text: str, palette: QPalette | None = None) -> QImage:
    """A box naming what is not shown (an image too big, not found, being
    read), as tall as a line of text and as wide as its words (at most 420
    pixels): it was 420 x 36 whatever it said, a row of them stacked."""
    palette = palette or QPalette()
    from PyQt6.QtGui import QFontMetrics
    from PyQt6.QtWidgets import QApplication

    text = f"{CHIP} {text}"  # (as the chip of an image not shown in the line - a framed grey box read as a button)
    metrics = QFontMetrics(QApplication.font())
    if metrics.horizontalAdvance(text) + 16 > 420:  # (cut at a word, "…" - "not beside th...le" was cut anywhere)
        count = len(text)
        while count > 8 and metrics.horizontalAdvance(elide_words(text, count)) + 16 > 420:
            count -= 4
        text = elide_words(text, count)
    width = max(40, min(420, metrics.horizontalAdvance(text) + 16))
    height = metrics.height() + 8
    image = QImage(width, height, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    base, ink = palette.color(QPalette.ColorRole.Base), palette.color(QPalette.ColorRole.Text)

    def mix(share: float) -> QColor:  # (of the text's colour on the page's)
        return QColor(*(round(a * (1 - share) + b * share) for a, b in
                        zip(base.getRgb()[:3], ink.getRgb()[:3], strict=True)))

    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(mix(0.06))
    painter.drawRoundedRect(0, 0, width, height, 4, 4)
    painter.setPen(mix(0.6))  # (muted, as the chip's)
    painter.setFont(QApplication.font())  # (the letters it was measured in)
    painter.drawText(QRect(8, 0, width - 16, height), Qt.AlignmentFlag.AlignVCenter, text)
    painter.end()
    return image


# What an SVG image may hold (svg_refers): Qt's SVG reader reads the files
# its <image> elements name, by their paths on this computer, so only an SVG
# that names nothing but parts of itself ("#id", url(#id)) is shown; one
# with an entity declared, an encoding in which ASCII's letters are other
# bytes, or a NUL (UTF-16: the names were not seen) is not either.
SVG_NAMES = re.compile(rb"""href\s*=\s*(["'])(.*?)\1""", re.IGNORECASE | re.DOTALL)
SVG_URLS = re.compile(rb"""url\s*\(\s*["']?\s*(?!#)""", re.IGNORECASE)
SVG_ENCODING = re.compile(rb"""<\?xml[^>]*?encoding\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
ASCII_ENCODINGS = {b"utf-8", b"utf8", b"us-ascii", b"ascii", b"iso-8859-1", b"latin1", b"latin-1"}
SVG_FORMATS = (b"svg", b"svgz")


def svg_refers(data: bytes) -> bool:
    """Whether the SVG *data* (bytes, not compressed) may name another file
    (see SVG_NAMES)."""
    if b"\0" in data or re.search(rb"<!ENTITY|@import", data, re.IGNORECASE) or SVG_URLS.search(data):
        return True
    declared = SVG_ENCODING.search(data[:1024])
    if declared and declared.group(1).strip().lower().replace(b"_", b"-") not in ASCII_ENCODINGS:
        return True
    return any(not value.startswith(b"#") for _quote, value in SVG_NAMES.findall(data))


def unpacked(data: bytes) -> bytes | None:
    """*data* as it is - or, compressed with gzip (an .svgz), unpacked: at
    most IMAGE_LIMIT bytes (None beyond, or when it does not unpack)."""
    if not data.startswith(b"\x1f\x8b"):
        return data
    import zlib

    unpacker = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        found = unpacker.decompress(data, IMAGE_LIMIT + 1)
    except zlib.error:
        return None
    return found if len(found) <= IMAGE_LIMIT and not unpacker.unconsumed_tail else None


def _reader_format(reader: QImageReader) -> bytes:
    return bytes(reader.format()).lower()


#: The formats decode() reads in this process, found by the content: the
#: pictures of a page. Anything else Qt could read is none - a PDF was drawn
#: by pdfium here, a "picture" of any name, also as a data: image.
RASTER_FORMATS = (b"png", b"jpeg", b"jpg", b"gif", b"bmp", b"webp", b"ico", b"cur", b"tiff", b"tif",
                  b"pbm", b"pgm", b"ppm", b"tga", b"wbmp")
#: Seconds the SVGs of one document may take to be drawn, together (each at
#: most core.svg_worker.RENDER_SECONDS): a page of slow ones is not drawn
#: for an hour.
SVG_SECONDS = 30.0


def looks_like_svg(data: bytes) -> bool:
    """Whether *data* (not compressed) is an XML document with an ``<svg``
    element - told without Qt: its image reader, asked only for the format
    or the size, loaded the SVG and walked its references (a 2.2 KB
    ``<use>`` fan-out held it 28 s)."""
    head = data[:65536].lstrip(b"\xef\xbb\xbf \t\r\n")
    return head[:1] == b"<" and b"<svg" in head.lower()


def _draw_svg(plain: bytes, budget: dict | None):
    """``(QImage, None)`` of the SVG *plain* (what it names checked) at its
    own size (at most IMAGE_PIXELS), or ``(None, why)``: through
    core.svg_gate (what its references draw) and core.svg_worker (drawn in
    a child process stopped after its time) - never in this process: the
    image reader drew ten levels of ten ``<use>`` (1.9 KB) for 7.6 s, a
    level more for minutes."""
    why = svg_gate.svg_expansion(plain, doctype=True)
    if why is not None:
        return None, tr("not drawn: {why}").format(why=why)
    seconds = svg_worker.RENDER_SECONDS
    if budget is not None:
        with budget["lock"]:
            seconds = min(seconds, budget.setdefault("svg", SVG_SECONDS))
            budget["svg"] -= seconds  # (taken now, the rest given back: the views draw at the same time)
    if seconds < 0.5:
        return None, tr("not drawn: the page's drawings took their time")
    started = time.monotonic()
    try:
        png = svg_worker.render_png(plain, -int(IMAGE_PIXELS ** 0.5), svg_gate.options_value(), seconds)
    except svg_worker.SvgTooSlow:
        return None, tr("not drawn: it takes too long")
    except svg_worker.SvgFailed as exc:
        return None, printable(exc)
    finally:
        if budget is not None:
            with budget["lock"]:
                budget["svg"] += max(0.0, seconds - (time.monotonic() - started))
    image = QImage.fromData(png, "PNG")
    if image.isNull():
        return None, tr("not an image")
    return image, None


def decode(data: bytes, budget: dict | None = None):
    """``(QImage, None)`` of *data*, or ``(None, why)``: never more than
    IMAGE_PIXELS pixels are decoded - nor more than ``budget["left"]`` (the
    pixels all the images of a document may still take: taken from it,
    under ``budget["lock"]``). Only RASTER_FORMATS are decoded here; an SVG
    that may name other files is not drawn (svg_refers), one that may is
    drawn in a child process (_draw_svg, within ``budget["svg"]`` seconds)."""
    plain = data
    if data.startswith(b"\x1f\x8b"):  # (an .svgz: read as the SVG it holds - what was looked at)
        plain = unpacked(data)
        if plain is None:
            return None, tr("too big")
        if not looks_like_svg(plain):
            return None, tr("not an image")
    svg = plain is not data or looks_like_svg(data)
    reader = None
    if not svg:
        buffer = QBuffer()
        buffer.setData(QByteArray(data))
        buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        reader = QImageReader(buffer)
        found_format = _reader_format(reader)
        if found_format in SVG_FORMATS:
            svg = True  # (Qt's reader took it for one: never asked for more)
        elif found_format not in RASTER_FORMATS:
            return None, tr("not an image")
        else:
            # (that format's decoder only: what the content was found to be)
            reader.setFormat(found_format)
            reader.setAutoDetectImageFormat(False)
    if svg and svg_refers(plain):
        return None, tr("refers to other files")
    if svg:
        pixels = 0  # (known once drawn: at most IMAGE_PIXELS, counted then)
    else:
        size = reader.size()
        pixels = size.width() * size.height() if size.isValid() else 0
    if pixels > IMAGE_PIXELS:
        return None, tr("too big")
    if budget is not None:
        with budget["lock"]:  # (taken before it is decoded: the views of one window read at the same time)
            if pixels > budget["left"]:
                return None, tr("too big")
            budget["left"] -= pixels
    if svg:
        image, why = _draw_svg(plain, budget)
        if image is None:
            return None, why
    else:
        image = reader.read()
    found = image.width() * image.height() if not image.isNull() else 0
    if budget is not None and found != pixels:  # (what it took: a size not told before, or no image)
        with budget["lock"]:
            if found - pixels > budget["left"]:
                budget["left"] += pixels
                return None, tr("too big")
            budget["left"] -= found - pixels
    if image.isNull():
        return None, tr("not an image")
    if found > IMAGE_PIXELS:
        return None, tr("too big")
    return image, None


class _Delivery(QObject):
    """Carries a worker's result to the GUI thread."""

    done = pyqtSignal(object, object)


#: Each worker's _Delivery (it lives in the GUI thread, made there) until a
#: turn after it delivered: held by the worker's thread it was freed when the
#: thread ended - on the worker thread, its queued signal on its way (the
#: reader's tests crashed now and then, SIGSEGV in a done() lambda).
_DELIVERIES: dict[int, QObject] = {}


#: Python's switch interval once a worker has run (seconds). The default
#: 5 ms is how long the GUI thread may wait for Python's lock at each of its
#: calls into Python while a worker computes: a turn of the event loop of
#: many such calls (typing in the editor, the preview parsed beside it) was
#: held 0.3 s, the GUI thread idle.
WORKER_SWITCH_SECONDS = 0.001


def in_background(fn, done, owner: QObject | None = None) -> threading.Thread:
    """``fn()`` on a worker thread (never on the GUI thread: a slow or hung
    server holds up no window); ``done(result, error)`` on the GUI thread -
    not at all once *owner* is deleted. (Python's lock is handed on more
    often from then on: WORKER_SWITCH_SECONDS.)"""
    if sys.getswitchinterval() > WORKER_SWITCH_SECONDS:
        sys.setswitchinterval(WORKER_SWITCH_SECONDS)
    delivery = _Delivery()
    key = id(delivery)
    _DELIVERIES[key] = delivery  # (freed on the GUI thread, a turn after it delivered - see _DELIVERIES)

    def deliver(result, error):
        QTimer.singleShot(0, lambda: _DELIVERIES.pop(key, None))
        if owner is not None and sip.isdeleted(owner):
            return
        done(result, error)

    delivery.done.connect(deliver, Qt.ConnectionType.QueuedConnection)

    def work():
        try:
            result, error = fn(), None
        except Exception as exc:  # noqa: BLE001 - handed to done()
            result, error = None, exc
        try:
            delivery.done.emit(result, error)
        except RuntimeError:  # pragma: no cover - the application is gone
            pass

    thread = threading.Thread(target=work, name="markdown-view", daemon=True)
    thread.start()
    return thread


class BinaryFile(ValueError):
    """A file that is no text (core.markdown_doc.looks_binary): said, not shown."""


def read_text(backend, path: str, limit: int | None = None) -> tuple[str, bool]:
    """The file's text (UTF-8, damaged bytes replaced; UTF-16 or -32 when its
    BOM says so, the BOM dropped: core.markdown_doc.decode_text) and whether
    it was cut at *limit* (default :data:`TEXT_LIMIT`) - BinaryFile for a
    file that is no text. Runs on a worker thread."""
    from core.markdown_doc import decode_text, looks_binary

    limit = TEXT_LIMIT if limit is None else limit
    with backend.open_read(path) as fh:
        data = fh.read(limit + 1)
    if looks_binary(data):
        raise BinaryFile(tr("not a text file (it holds binary data)"))
    return decode_text(data[:limit]), len(data) > limit


def _is_local(backend) -> bool:
    try:
        from core import previews as P

        return bool(P._is_local_backend(backend))
    except Exception:  # noqa: BLE001 - no previews module: judge by the class
        return type(backend).__name__ == "LocalFS"


#: The path functions of this computer's own paths: ntpath on Windows ("C:\\docs\\a.md", "C:/docs/a.md" from
#: a file dialog), posixpath elsewhere. (A test sets ntpath here to be Windows.)
LOCAL_PATHS = os.path


def path_functions(local: bool):
    """The path functions of a backend's paths: this computer's (LOCAL_PATHS) for a local one, posixpath
    for any other (SFTP, S3, ... are "/"-separated whatever the computer): the folder of "C:\\docs\\a.md"
    was "/" (posixpath), and every image beside a file on Windows "not beside the file"."""
    return LOCAL_PATHS if local else posixpath


def _inside(path: str, folder: str, paths=posixpath) -> bool:
    """Whether *path* is *folder* or lies below it (both normalised), as *paths* (path_functions) compares
    them: on Windows a drive's letter and the case aside, either separator."""
    if paths is posixpath:
        return path == folder or path.startswith(folder.rstrip("/") + "/")
    path, folder = paths.normcase(paths.normpath(path)), paths.normcase(paths.normpath(folder))
    try:
        return paths.commonpath([path, folder]) == folder
    except ValueError:  # (another drive; an absolute path and a relative one)
        return False


class ImageSource:
    """The images of the Markdown file *path* on *backend*: where a name
    points (:meth:`kind`: the file's folder or one below it - never above
    it, nor, on this computer, through a symlink to elsewhere) and reading
    them (:meth:`read`, in a thread)."""

    def __init__(self, backend, path: str):
        self.backend = backend
        self.local = _is_local(backend)
        self.paths = path_functions(self.local)
        self.folder = self.paths.dirname(path) or self.paths.sep
        self.budget, self.lock = None, threading.Lock()  # (the pixels its images may still take)

    def forget(self) -> None:
        """Reload: the images are read anew - the pixels of those read before
        count no more."""
        with self.lock:
            self.budget = None

    def kind(self, name: str) -> tuple[str, str | None]:
        """``("remote", url)`` | ``("data", None)`` | ``("local", path)`` |
        ``("outside", name)``."""
        url = QUrl(name)
        scheme = url.scheme().lower()
        if scheme in REMOTE or name.startswith("//"):
            return "remote", name
        if scheme == "data":
            return "data", None
        if scheme or name.startswith("/") or name.startswith("\\") or "\0" in name:
            return "outside", name  # file:, an absolute path, anything else: never read
        path = QUrl.fromPercentEncoding(url.path(QUrl.ComponentFormattingOption.FullyEncoded).encode())
        if not path or "\0" in path:
            return "outside", name
        paths = self.paths
        if paths.isabs(path) or paths.splitdrive(path)[0]:
            return "outside", name  # ("\\x.png", "C:x.png" on Windows: never read)
        joined = paths.normpath(paths.join(self.folder, path))
        if not paths.isabs(joined) or not _inside(joined, self.folder, paths):
            return "outside", name  # ("../x.png": the file's folder or one below it only)
        return "local", joined

    def read_later(self, names, done, owner=None):
        """:meth:`read` (*names*) in a thread; ``done(result, error)`` on the
        GUI thread."""
        names = list(names)
        return in_background(lambda: self.read(names), done, owner)

    def _read_file(self, path: str) -> bytes | str:
        """The bytes of the image at *path*, or why not."""
        if self.local:
            from core.protected_places import read_refusal

            real = self.paths.realpath
            if not _inside(real(path), real(self.folder), self.paths):
                return tr("not beside the file (a link to elsewhere)")
            if read_refusal(path):
                return tr("not shown (a secret file)")

            try:
                st = os.stat(path)
            except OSError:
                return tr("not found")
            if not _stat.S_ISREG(st.st_mode):  # a FIFO, a device: never opened
                return tr("not a file")
            if st.st_size > IMAGE_LIMIT:
                return tr("too big")
        with self.backend.open_read(path) as fh:
            data = fh.read(IMAGE_LIMIT + 1)
        if len(data) > IMAGE_LIMIT:
            return tr("too big")
        return data

    def read(self, names) -> dict:
        """``{name: QImage or why not}`` for the local and ``data:`` images
        *names* (runs in :meth:`read_later`'s thread)."""
        with self.lock:  # (a read begun before a Reload takes from what was left then)
            if self.budget is None:
                self.budget = {"left": IMAGES_PIXELS, "lock": threading.Lock()}
            budget, found = self.budget, {}
        for name in list(names)[:IMAGES]:
            kind, where = self.kind(name)
            try:
                if kind == "data":
                    head, _, body = name.partition(",")
                    if ";base64" not in head or len(body) > IMAGE_LIMIT * 4 // 3 + 4:
                        found[name] = tr("not shown")
                        continue
                    data = base64.b64decode(body, validate=False)
                elif kind == "local":
                    data = self._read_file(where)
                    if isinstance(data, str):
                        found[name] = data
                        continue
                else:
                    continue
                image, why = decode(data, budget)
                found[name] = image if image is not None else why
            except (OSError, ValueError) as exc:
                found[name] = printable(exc)
        return found


def _page(text: str, dark: bool, toggled=frozenset(), first_details: int = 0, notes=None):
    """(the HTML of *text* in parts, its headings) through markdown-it - pure
    Python, so it may run on a worker thread. *toggled*: the <details> a
    click opened or folded (ui.markdown_html.fold_details); *notes*: a long
    text's footnotes, numbered across its pieces (markdown_doc.parse)."""
    from core import markdown_doc
    from ui.markdown_html import to_html_parts

    with _window_emoji():
        doc = markdown_doc.parse(text, notes=notes)
    hidden: dict = {}
    try:
        return to_html_parts(doc, dark, PART_BLOCKS, toggled, hidden, first_details), doc.headings, hidden
    except (Exception, RecursionError) as exc:  # noqa: BLE001 - a fault of one block: the text as written,
        log.warning("A page could not be rendered; shown as written", exc_info=True)  # never a blank page
        doc, hidden = markdown_doc.as_written(doc.source or text, exc), {}
        return to_html_parts(doc, dark, PART_BLOCKS, toggled, hidden, first_details), doc.headings, hidden


#: Blocks of a part of the page printed or saved as PDF (print_parts): each a
#: document of its own, laid out and drawn in a turn of its own.
PRINT_BLOCKS = 400
#: Cells of a big table's part to print (renderable): each part is laid out four times for its pages - as
#: their size, its margins, its device need - a part of 300 rows of emoji held the window 0.2 s.
PRINT_TABLE_CELLS = TABLE_CELLS // 3


def print_parts(text: str, full: bool) -> tuple[str, list[str]]:
    """(the kind - "html" or "md4c" -, the parts) of *text* to print, in
    light colours - pure Python, for a worker thread. Each part is laid out
    and drawn on its own (ui.markdown_viewer's _PagePrinter): the whole page
    as one document was cut short past Qt's layout's reach (big.md: 613
    pages, the last ones missing) and held the window 6.6 s; a paragraph of
    3,000 formulas in one block took Qt 3 s - in pieces here."""
    from core import markdown_doc

    if full:
        from ui.markdown_html import to_html_parts

        shown = markdown_doc.clean(renderable(text, PRINT_TABLE_CELLS)[0])
        with _window_emoji():
            doc = markdown_doc.parse(shown)
        return "html", to_html_parts(doc, False, PRINT_BLOCKS)
    shown = markdown_doc.clean(renderable(text, min(MD4C_TABLE_CELLS, PRINT_TABLE_CELLS))[0])
    return "md4c", list(_md4c_page(shown)[0])


_IMG_SRC = re.compile(r'<img\b[^<>]*?\bsrc="([^"]*)"', re.IGNORECASE)
_DESTINATION_ADDRESS = re.compile(r'\]\([ \t]*(?:<([^<>\n]*)>|([^\s()]*(?:\([^()\s]*\)[^()\s]*)*))')


def image_names(kind: str, parts: list[str]) -> list[str]:
    """The names of the images the parts print_parts made (*kind* "html" or "md4c") show, in their order,
    each once - as the page asks for them (MarkdownView.image): what an export or a print reads before it
    lays the parts out (the page itself laid out whole first took 24 s to more than 10 minutes). Linear."""
    import html as _html

    names: dict[str, None] = {}
    for part in parts:
        if kind == "html":
            for found in _IMG_SRC.finditer(part):
                names[_html.unescape(found.group(1))] = None
            continue
        if "![" not in part:
            continue
        pairs, labels = _bracket_pairs(part), set()
        for begin, end in pairs.items():
            if not begin or part[begin - 1] != "!":
                continue
            if part[end + 1:end + 2] == "(":
                found = _DESTINATION_ADDRESS.match(part, end)
                name = (found.group(1) if found.group(1) is not None else found.group(2)) if found else ""
                if name:
                    names[name] = None
            elif part[end + 1:end + 2] == "[" and end + 1 in pairs:  # (by reference: "![alt][label]")
                labels.add(_label(part[end + 2:pairs[end + 1]] or part[begin + 1:end]))
            else:  # ("![label]")
                labels.add(_label(part[begin + 1:end]))
        if labels:
            for found in _IMAGE_DEFINITION.finditer(part):
                if _label(found.group(1)) in labels:
                    names[found.group(2) if found.group(2) is not None else found.group(3)] = None
    return list(names)


_IMAGE_DEFINITION = re.compile(r"^ {0,3}\[([^\]\n]{1,999})\]:[ \t]*(?:<([^<>\n]*)>|(\S+))", re.MULTILINE)


def _md4c_page(text: str, toggled=frozenset(), hidden: dict | None = None):
    """(the pieces of *text* for Qt's own parser - escaped - its footnotes,
    its code blocks as written, whether it has images): the text passes
    (fallback_text and the others) - pure Python, so it may run on a
    worker thread. (Runs of spaces cut again after the passes: raw HTML's
    tags dropped between spaces left them in a row - see SPACE_RUN.)
    *toggled*, *hidden*: the <details> a click turned, what closed ones
    hold (_fold_details)."""
    # (the notes first: a note's indented second line was taken for code -
    # and counted as a code block, Copy Code Block then copied the next one's)
    from core.markdown_doc import by_lines

    with _window_emoji():
        written = fallback_text(text, toggled, hidden)
    noted, notes = with_footnotes(_fewer_marks(by_lines(
        lambda piece: _SPACE_RUN.sub(lambda match: match.group(0)[:SPACE_RUN], piece), written)))
    shown, sources = code_blocks(noted)
    # (raw HTML's tables and lists are Markdown now: cut as a text's own - renderable - keeping the marks)
    shown = paragraph_pieces(container_pieces(renderable(shown, MD4C_TABLE_CELLS, keep_marks=True)[0]))
    _lex_fences(shown)  # (each fenced block's colours, lexed in a child - here, not on the GUI thread)
    pieces = markdown_parts(shown, first=PART_LINES // 4)  # (the first small: the page there at once)
    continued = {number for number, piece in enumerate(pieces) if isinstance(piece, _Continued)}
    return [_escape_html(piece) for piece in pieces], notes, sources, "![" in shown, continued


def _fewer_marks(text: str) -> str:
    """*text* with the marks of its first MARK_SPANS spans only (a mark
    whose partner went is left alone by apply_marks, and goes)."""
    seen = 0

    def kept(match: re.Match) -> str:
        nonlocal seen
        seen += 1
        return match.group(0) if seen <= 2 * MARK_SPANS else ""

    from core.markdown_doc import by_lines

    return by_lines(lambda piece: _MARK_CHARS.sub(kept, piece), text)


#: How far a list inside a list stands in (pixels): GitHub's 2em - Qt's 40 were wider.
LIST_INDENT = 30
#: Room above a heading an anchor or the outline jumped to (pixels).
ANCHOR_ROOM = 10
#: The least room between the text and the view's sides (pixels).
GUTTER = 16
#: Room above the page's first block (pixels).
TOP_ROOM = 16
#: The page's letters at least this many pixels high (as GitHub's 16): the
#: desktop's 12 read small beside its wide margins.
READING_PIXELS = 15


#: The outline's letters at least this many pixels high.
OUTLINE_PIXELS = 13


def reading_font(font: QFont, pixels: int = READING_PIXELS) -> QFont:
    """*font* at least *pixels* high - as a point size, which zoom steps
    (one of pixels it cannot)."""
    from PyQt6.QtGui import QFontInfo

    shown = QFontInfo(font).pixelSize()
    if 0 < shown < pixels and font.pointSizeF() > 0:
        font = QFont(font)
        font.setPointSizeF(font.pointSizeF() * pixels / shown)
    return font


class _LazyText(QMimeData):
    """Text made by *make()* the first time it is asked for."""

    def __init__(self, make):
        super().__init__()
        self._make, self._text = make, None

    def formats(self):
        return ["text/plain"]

    def hasFormat(self, kind: str) -> bool:  # noqa: N802 - Qt
        return kind == "text/plain"

    def retrieveData(self, kind: str, wanted):  # noqa: N802 - Qt
        if kind != "text/plain":
            return None
        if self._text is None:
            self._text = self._make()
        return self._text


class MarkdownBrowser(QTextBrowser):
    """A QTextBrowser that loads nothing itself: images come from the view's
    cache (read through the file's backend), every other resource is
    refused; links are never followed here (the view decides)."""

    def wheelEvent(self, event):  # noqa: N802 - Qt
        """Ctrl+wheel: the view's zoom (its level on the button, its bounds) - Qt's own zoomed the
        letters behind the view's back: the button stayed at 100 %."""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            self._wheel = getattr(self, "_wheel", 0) + delta
            steps = int(self._wheel / 120)
            if steps:
                self._wheel -= steps * 120
                self.view.zoom_by(steps)
            event.accept()
            return
        super().wheelEvent(event)

    def __init__(self, view: MarkdownView):
        super().__init__(view)
        self.view = view
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.setReadOnly(True)
        self.setAccessibleName(tr("The file rendered as Markdown"))
        self._sides = (0, 0)  # (the viewport's side margins: MarkdownView.fit_text)
        # (the text is laid out to a width of its own: a resize changes the
        # margins, not the width the page is laid out to - but in a view
        # narrower than the text - so Qt lays nothing out again for it)
        self.setLineWrapMode(QTextBrowser.LineWrapMode.FixedPixelWidth)
        self.setLineWrapColumnOrWidth(max(320, view.text_width() if hasattr(view, "browser") else 760))
        # (the margins beside the page in the page's colour)
        self.setBackgroundRole(QPalette.ColorRole.Base)
        self.setAutoFillBackground(True)
        # (read only: an undo stack of every page shown is memory for nothing)
        self.document().setUndoRedoEnabled(False)
        self.document().setIndentWidth(LIST_INDENT)
        # (a word longer than its line - a URL, inline code - breaks where it
        # must: it pushed tables and quotes past the view)
        from PyQt6.QtGui import QTextOption

        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt
        # (Ctrl+End on a page laid out in part: all of it first, then its end -
        # it stopped where the laying out had; and on a page laid out whole too, Ctrl+Home as well: Qt's
        # read-only browser does nothing with either - the key worked or not as far as the page had got)
        if event.key() in (Qt.Key.Key_End, Qt.Key.Key_Home) \
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier \
                and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            if event.key() == Qt.Key.Key_End:
                self.view.go_end()  # (its last part laid out first, its end shown)
            else:
                self.view.go_home()
            return
        if event.matches(QKeySequence.StandardKey.SelectAll) and self.view.more():
            self.select_all()
            return
        if event.matches(QKeySequence.StandardKey.Copy):
            self.view.copy_selection()  # (the parts not laid out yet too; a formula's TeX)
            return
        super().keyPressEvent(event)

    def createMimeDataFromSelection(self):  # noqa: N802 - Qt
        """What a drag or the selection clipboard holds: as Copy does (a formula's TeX) - of what is laid
        out (a drag cannot wait for the rest)."""
        cursor = self.textCursor()
        if not cursor.hasSelection():
            from PyQt6.QtCore import QMimeData

            data = QMimeData()
            data.setText("")
            return data
        # (its text made when it is asked for - a drop, a paste of the selection: made at once, a
        # selection of 60,000 formulas held the window 1.4 s each time it changed)
        low, high = QTextCursor(self.document()), QTextCursor(self.document())
        low.setPosition(_low(cursor))
        high.setPosition(_high(cursor))
        return _LazyText(lambda: _copy_text(self.document(), low.position(), high.position()).lstrip("\n"))

    def select_all(self) -> None:
        """All of the page selected - at once: a copy reads the parts not laid
        out yet from their text (copy_selection). It was laid out first: 9 s,
        58 s with Qt's own parser, and a Copy meanwhile copied nothing."""
        self.selectAll()

    def loadResource(self, kind, url):  # noqa: N802 - Qt
        if kind != QTextDocument.ResourceType.ImageResource.value:
            return QByteArray(b" ")  # (no style sheet, no frame, nothing else; empty would make Qt read it)
        return self.view.image(url.toString())

    def mouseMoveEvent(self, event):  # noqa: N802 - Qt
        super().mouseMoveEvent(event)
        point = event.position().toPoint()
        if not self.anchorAt(point):  # (a link says where it goes itself: hovered)
            self.view.hint(self.view.tooltip_at(self.cursorForPosition(point).position()))

    def margins(self) -> tuple[int, int, int, int]:
        return (self._sides[0], 0, self._sides[1], 0)

    def set_margins(self, left: int, right: int) -> None:
        self._sides = (left, right)
        self.setViewportMargins(left, 0, right, 0)

    def image_at(self, point: QPoint) -> str:
        """The name of the image at *point* (viewport coordinates), or ""."""
        cursor = self.cursorForPosition(point)
        for fmt in (cursor.charFormat(), self._format_after(cursor)):
            if fmt is not None and fmt.isImageFormat():
                name = fmt.toImageFormat().name()
                rect = self.cursorRect(cursor)
                if abs(rect.x() - point.x()) <= self.view.shown_width(name) + 4:
                    return name
        return ""

    @staticmethod
    def _format_after(cursor: QTextCursor):
        after = QTextCursor(cursor)
        if not after.movePosition(QTextCursor.MoveOperation.NextCharacter):
            return None
        return after.charFormat()

    def mousePressEvent(self, event):  # noqa: N802 - Qt
        self.pressed_at = event.position().toPoint()  # (the link clicked: its text, MarkdownView.clicked)
        if event.button() == Qt.MouseButton.BackButton:
            self.view.back()
            return
        if event.button() == Qt.MouseButton.ForwardButton:
            self.view.forward()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):  # noqa: N802 - Qt
        super().mouseReleaseEvent(event)
        point = event.position().toPoint()
        if event.button() == Qt.MouseButton.LeftButton and not self.anchorAt(point) \
                and not self.textCursor().hasSelection():
            name = self.image_at(point)
            if name:
                self.view.zoom_image(name)

    def resizeEvent(self, event):  # noqa: N802 - Qt
        super().resizeEvent(event)
        self.view.fit_later()

    def contextMenuEvent(self, event):  # noqa: N802 - Qt
        """The usual menu - and Copy Code Block on a code block."""
        menu = self.createStandardContextMenu(event.pos())
        for action in menu.actions():
            if action.objectName() == "select-all" and self.view.more():  # (all of it laid out first)
                action.triggered.disconnect()
                action.triggered.connect(self.select_all)
            if action.objectName() == "edit-copy":  # (the parts not laid out yet too; a formula's TeX)
                action.triggered.disconnect()
                action.triggered.connect(self.view.copy_selection)
        code = self.view.code_block_at(self.cursorForPosition(event.pos()).position())
        if code:
            from PyQt6.QtWidgets import QApplication

            action = menu.addAction(tr("Copy Code Block"))
            action.triggered.connect(lambda: QApplication.clipboard().setText(code))
        menu.exec(event.globalPos())
        menu.deleteLater()


def _plain_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setForegroundRole(QPalette.ColorRole.PlaceholderText)
    return label


_SCRIPT_CHECKED = []


def _check_script_letters() -> None:
    """Once: whether a maths font of the page (ui.markdown_html.MATH_FONTS)
    has the script letters - then a formula's \\mathcal{O} is 𝒪 on the page
    too (core.markdown_doc.keep_script_letters)."""
    if _SCRIPT_CHECKED:
        return
    _SCRIPT_CHECKED.append(True)
    from PyQt6.QtGui import QFontDatabase

    from core import markdown_doc
    from ui.markdown_html import MATH_FONTS

    installed = set(QFontDatabase.families())
    # (asked of the font alone: QFontMetrics answered with Qt's fallback fonts - each of 2,000 families looked in,
    # 0.15 to 0.28 s of the first view - and said yes for a maths font without them)
    if any(name in installed and _raw_has(name, 0x1D4AA) for name in MATH_FONTS):
        markdown_doc.keep_script_letters()


def _raw_has(family: str, point: int) -> bool:
    """Whether the font *family* itself (no fallback font) has the character *point*."""
    from PyQt6.QtGui import QRawFont

    raw = QRawFont.fromFont(QFont(family))
    return raw.isValid() and raw.supportsCharacter(point)


class MarkdownView(QWidget):
    """The rendering of a Markdown text: its outline (headings, a click jumps
    there) and the text. :attr:`link` (QUrl) for a link clicked that is not
    an anchor of this text (the window decides what it does). *source*: an
    :class:`ImageSource` or None (no images read)."""

    link = pyqtSignal(QUrl)
    #: The text's size changed: its zoom level in per cent (100: its own size).
    zoom_changed = pyqtSignal(int)
    #: A page rendered is readable (its first parts laid out, its place taken).
    shown = pyqtSignal()

    def __init__(self, source: ImageSource | None, outline: bool = True, parent=None):
        _check_script_letters()
        emoji_fonts()  # (a short code of an emoji no font has: as written, not an empty box)
        super().__init__(parent)
        self.source, self.markdown, self.anchors, self.zoom = source, "", {}, 0
        self.images, self.asked = {}, set()  # name: QImage (or a placeholder); names being read or read
        self.too_many = None  # the one picture of every image beyond 2 * IMAGES (image())
        self.generation = 0  # forget_images(): what a read begun before it brings is dropped
        #: markdown-it (core.markdown_doc) when installed: the full Markdown set;
        #: else Qt's own parser (md4c). A test may switch it off.
        from core import markdown_doc

        self.full = markdown_doc.available()
        self.names: set[str] = set()  # the page's anchors (footnotes, headings)
        self._page_generation = 0
        # (a page laid out in parts: _laid)
        self._page, self._rest, self._readable, self._whole, self._scheduled = None, None, False, False, False
        self._then, self._rendering, self._after, self._boxes, self._numbers = [], False, "", 0, {}
        self._stand_in = False  # (_stand_in_put: the parts not laid out yet's height at the end)
        self._gaps: list[dict] = []  # (parts skipped by a jump: _jump)
        self._want = None  # (the part to lay out first: a jump's)
        self._starts: dict[int, QTextCursor] = {}  # (each laid-out part's first place)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.outline = QListWidget()
        self.outline.setAccessibleName(tr("Outline"))
        # (its letters at least 13 pixels, its entries off the corner: small
        # and flush against the frame, it read as an afterthought)
        self.outline.setFont(reading_font(self.outline.font(), OUTLINE_PIXELS))
        self.outline.setStyleSheet("QListWidget { padding: 6px 6px; } QListWidget::item { padding: 2px 4px; }")
        self.outline.setToolTip(tr("The headings: a click shows that part"))
        # (a long heading is cut with "…" and named whole in its tooltip: it
        # made the outline scroll sideways)
        self.outline.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.outline.setWordWrap(False)
        # (each entry one line: the list lays out none to know its height - with
        # every heading of a long page listed, 20,000, a resize held the window)
        self.outline.setUniformItemSizes(True)
        self.outline.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.outline.itemActivated.connect(self.jump)
        self.outline.itemClicked.connect(self.jump)
        self.outline.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.outline.customContextMenuRequested.connect(self._outline_menu)
        #: the <details> a click opened or folded (by number: fold_details) -
        #: forgotten when another file is shown
        self.folds: set[int] = set()
        self.hidden: dict = {}  # (what folded <details> hold - fold_details: unfold_for)
        #: the file's name, for a link to one of its headings ("README.md#install")
        self.page_name = ""
        self.browser = MarkdownBrowser(self)
        self.browser.setFont(with_emoji_family(self.browser.font()))  # (emoji found at once: emoji_fonts)
        self.browser.setFont(reading_font(self.browser.font()))
        self.highlighter = CodeHighlighter(self.browser.document())
        self.browser.anchorClicked.connect(self.clicked)
        self.browser.highlighted.connect(self.hovered)
        # (a place held on the view's top while the page's layout changes -
        # a zoom, a width, a part shown at once: let go when the reader scrolls)
        self._held = None
        self.browser.verticalScrollBar().valueChanged.connect(self._moved)
        self.browser.verticalScrollBar().rangeChanged.connect(self._keep_held)
        self.browser.verticalScrollBar().rangeChanged.connect(self._scrolled)
        self.browser.verticalScrollBar().actionTriggered.connect(self._let_go)
        self.split.addWidget(self.outline)
        self.split.addWidget(self.browser)
        self.split.setStretchFactor(1, 1)
        self.split.setSizes([180, 600])
        self.outline.setVisible(outline)
        layout.addWidget(self.split, 1)
        self.notice = _plain_label()  # (renderable: why only a part is rendered)
        self.notice.hide()
        layout.addWidget(self.notice)
        self.status = _plain_label()
        self.status.setWordWrap(False)
        layout.addWidget(self.status)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(RENDER_DELAY)
        # (methods of the view, no lambdas, on its signals and timers: Qt drops
        # them with it - a lambda outlived it, a crash at a later test)
        self.timer.timeout.connect(self._render_again)
        #: images as they were read ({name: QImage}; images holds them as
        #: shown, fitted to the width) and the width they were fitted to
        self.originals: dict[str, QImage] = {}
        self.fitted_to = 0
        self.fit_timer = QTimer(self)
        self.fit_timer.setSingleShot(True)
        self.fit_timer.setInterval(150)
        self.fit_timer.timeout.connect(self.fit_images)
        self.read_timer = QTimer(self)
        self.read_timer.setSingleShot(True)
        self.read_timer.setInterval(0)
        self.read_timer.timeout.connect(self.read_missing)
        self.clear_pictures = False
        self._tables: tuple = (0, None)
        self.last_link_text = ""
        #: Qt's own parser: the code blocks of the text as written (code_block_at)
        self.code_sources: list[str] = []
        #: whether the page has images of a size raw HTML asked for (clamp_images)
        self.page_images = False  # (whether the page has images: clamp_images)
        #: where a jump (an anchor, the outline) was made from, and back -
        #: or the window's, when it keeps the places of several files
        #: (``navigator``: remember(), back(), forward())
        self.back_stack: list[int] = []
        self.forward_stack: list[int] = []
        self.navigator = None
        #: where the next page shown goes: ("anchor", name), ("scroll", y) or None (where it was)
        self.pending: tuple | None = None
        self.dark = _is_dark(self.palette())
        self.follow_timer = QTimer(self)  # (the outline marks the heading being read)
        self.follow_timer.setSingleShot(True)
        self.follow_timer.setInterval(80)
        self.follow_timer.timeout.connect(self.mark_heading)
        self.browser.verticalScrollBar().valueChanged.connect(self._follow_soon)
        self.browser.horizontalScrollBar().rangeChanged.connect(self._trim)
        for keys, slot in ((QKeySequence.StandardKey.Back, self.back),
                           (QKeySequence.StandardKey.Forward, self.forward)):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(slot)

    # -- the text --

    def show_later(self, text: str) -> None:
        """*text* rendered after a pause in the typing (the live preview)."""
        self.markdown = text
        self.timer.start()

    @property
    def page_name(self) -> str:
        return self._page_name

    @page_name.setter
    def page_name(self, name: str) -> None:
        if name != getattr(self, "_page_name", None):
            self.folds = set()  # (another file: its <details> as it has them)
        self._page_name = name

    def render(self, text: str, again=None) -> None:
        """*text* rendered (where it was scrolled to stays); its outline and
        anchors made anew. A long page is laid out a part an event-loop turn;
        past EAGER_BLOCKS blocks, the rest as it is scrolled to (or all of it:
        load_rest). *again*: (a zoom) the page made last laid out anew as it is -
        not parsed again - after *again()* changed what it is laid out with
        (the document emptied first: nothing of the old page laid out anew)."""
        self.timer.stop()
        self.markdown = text
        bar = self.browser.verticalScrollBar()
        where = bar.value()
        # (the place read: its part and how far into it - a page far on is
        # shown there again with that part laid out first)
        # (a page asked for again before it was shown: the place the first asking kept)
        kept = getattr(self, "_reading_next", None) if not getattr(self, "_readable", False) else None
        # (a place still being gone back to - its part not laid out yet - is the place: a second reload
        # meanwhile, a file saved twice, read the top of the page shown so far)
        kept = getattr(self, "_returning", None) or kept
        self._reading_next = (kept if getattr(self, "_returning", None) else self._reading() or kept) \
            if self.pending is None else None
        self._returning = None
        began = time.monotonic()
        # Line ends as CommonMark reads them (CR LF, CR, LF) before clean()
        # drops every CR: a file with CR alone (an old Mac's) was one line.
        raw = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
        full, cells = self.full, TABLE_CELLS if self.full else MD4C_TABLE_CELLS
        self.dark = dark = _is_dark(self.palette())
        toggled = frozenset(self.folds)
        self._page_generation += 1
        generation = self._page_generation
        self._page, self._rest, self._readable, self._whole, self._scheduled = None, None, False, False, False
        self._stand_in = False
        self._target = None
        self._more_text = None
        self._pieces = 1
        self._gaps, self._want, self._starts, self._on_laid = [], None, {}, []
        # (a copy under way when the page is made anew: said, not dropped silently - until the next page)
        self._cancelled = tr("Copy cancelled: the page was made anew.") if self._copying() else ""
        self.browser.document().setProperty(_WIDENED, False)  # (a new page: its own tables say)
        if self._cancelled:
            QTimer.singleShot(0, lambda: self.say(self._cancelled or ""))
        self._copy_job = None
        self._copy_waiting = False
        self._clamped_room, self._unclamped = None, 0
        made_key = (text, full, cells, dark, toggled)
        made_last = getattr(self, "_made", None)
        if again is not None:
            self.browser.document().clear()  # (its parts gone: none of them laid out anew at the new size)
            self.clear_pictures = False
            again()

        def prepare():  # (pure Python: on a worker thread for a long text)
            from core.markdown_doc import clean

            part, why = renderable(raw, cells)
            part = clean(part)  # (no control character of the file reaches the page: they showed as boxes)
            if not full:
                hidden: dict = {}
                made = _md4c_page(part, toggled, hidden)
                return why, (made, [part_headings("md4c", piece) for piece in made[0]], hidden)
            # (a long text parsed in parts, its first shown as soon as it is:
            # markdown-it took 7.8 s for 3.8 MB before the page showed anything)
            from core.markdown_term import labeled_inline_notes, notes_of, text_parts_at

            part = labeled_inline_notes(part)  # (a text with inline notes in parts too: one, 10 s)
            placed = text_parts_at(part)
            pieces = [piece for piece, _line in placed]
            # (its footnotes numbered across its pieces, listed in the last: a text with one was one
            # piece - 5 s before the page showed anything of 1 MB; each piece's places numbered on from
            # the line it begins at)
            notes = notes_of(part) if len(pieces) > 1 else None
            first = _page(pieces[0], dark, toggled, notes=(notes, len(pieces) == 1, placed[0][1]) if notes else None)
            return why, (first, pieces[1:], [part_headings("html", piece) for piece in first[0]],
                         (notes, [line for _piece, line in placed]))

        def done(result, error):
            if generation != self._page_generation:
                return  # (a newer page is on its way)
            if error is not None:
                self._idle()
                self.status.setText(_t("Cannot render: {error}", error=printable(error)))
                return
            self._made = (made_key, result)  # (a zoom lays it out again: relaid)
            why, page = _fresh(result)
            self.notice.setText(why)
            self.notice.setVisible(bool(why))
            if full:
                page, pieces, heads, (self._notes, self._piece_lines) = page
                self._more_text = (generation, list(pieces)) if pieces else None
                self._pieces = len(pieces) + 1  # (_show_page: the page's share parsed so far)
                self._show_page(generation, page, None, dark, where, began, heads)
                self._parse_next(generation, dark, toggled)
            else:
                page, heads, self.hidden = page
                self._show_pieces(generation, page, where, began, heads)

        if again is not None and made_last is not None and made_last[0] == made_key:
            done(made_last[1], None)  # (the page as it was made: laid out anew a part a turn)
            return
        # (a text with formulas: made on a worker from a smaller size on - their layout as tables is
        # Python's work; 2 KB of nested matrices held the window, 63 KB of 600 formulas half a second)
        # (and a text with fenced code, however short: its code is coloured by a child process the parse waits
        # for - up to CODE_LEX_SECONDS: a lexer stuck in backtracking held the window 1 s, its CPU idle - the
        # heartbeat's gap showed it, the turn did not)
        if len(raw) > BACKGROUND_CHARS or ("$" in raw and len(raw) > MATH_BACKGROUND_CHARS) \
                or raw.count("[") > BRACKETS_BACKGROUND or "```" in raw or "~~~" in raw:
            said, when = getattr(self, "_said_last", ("", 0.0))
            if said and self.status.text() == said and time.monotonic() - when < SAID_KEPT:
                self._after = said  # (said a moment ago - a link not followed -: said again once the page is made)
            self._busy(tr("Rendering…"), True)
            in_background(prepare, owner=self, done=done)
        else:
            done(prepare(), None)

    def _clear_pictures(self) -> None:
        """(the new page's first part about to be shown) the pictures the old
        page was given (addResource) dropped - they outlive setHtml. Not
        before: the page went blank for as long as the new one took (a
        reload of 1 MB: 2 to 8 s)."""
        if self.clear_pictures:
            self.clear_pictures = False
            self.browser.document().clear()

    def _pieces_notes(self, piece: int, count: int):
        """The footnotes the piece *piece* of *count* is parsed with (see _page), or None."""
        notes = getattr(self, "_notes", None)
        lines = getattr(self, "_piece_lines", None) or []
        return (notes, piece == count - 1, lines[piece] if piece < len(lines) else None) if notes else None

    # -- the status while a page is made --

    def _busy(self, text: str, first: bool = False) -> None:
        """*text* ("Rendering… N %") in the status line - *first*: a page begun, whatever it said; else not
        over what the window said meanwhile (_shown)."""
        self._rendering = True
        self._shown(text, first)  # (a copy under way says so: its "Copying… N %" stays)

    def _shown(self, text: str, first: bool = False) -> None:
        """The status says how much is laid out - unless a copy is under way (it says so); a copy the
        page's making anew cancelled said before it (while the new page is made too: "Rendering…"
        alone said nothing of it)."""
        if not self._copying():
            written = self.status.text()
            if not first and written and written != getattr(self, "_said", written):
                return  # (the window said something meanwhile - "Not opened (…)": it stays, not "Rendering… 49 %")
            cancelled = getattr(self, "_cancelled", "")
            self._said = f"{cancelled} {text}" if cancelled else text
            self.status.setText(self._said)

    def _copying(self) -> bool:
        return getattr(self, "_copy_job", None) is not None or bool(getattr(self, "_copy_waiting", False))

    def _idle(self) -> None:
        if getattr(self, "_rendering", False):
            self._rendering = False
            # (what the window wrote in the status line meanwhile - "Not opened (a folder without a README)" -
            # stays: a page made on a worker, a text with code too, ended by wiping it)
            written = self.status.text()
            if not written or written == getattr(self, "_said", written):
                self.status.setText(getattr(self, "_after", ""))
        self._after = ""

    def say(self, text: str) -> None:
        """*text* in the status line - once the page is made, if it is being
        made ("Rendering…" stays meanwhile: a long file showed nothing for
        seconds)."""
        if getattr(self, "_rendering", False):
            self._after = text
        else:
            self.status.setText(text)
            self._said_last = (text, time.monotonic())

    # -- a page in parts --

    def _show_pieces(self, generation, page, where, began, heads=None) -> None:
        """Qt's own parser's page (_md4c_page) shown: its first piece at
        once, the rest one an event-loop turn (_laid)."""
        pieces, notes, self.code_sources, self.page_images, continued = page
        self._clear_pictures()
        self.highlighter.formats = None  # (the palette of now)
        self.highlighter.palette = self.palette()
        self.browser.document().setMarkdown(pieces[0], FEATURES)
        _top_room(self.browser.document())
        _keep_reader(self.browser, 0, 0)  # (the reader's cursor at the start: find begins there, or where shown)
        self.fit_text()  # (as _show_page: while the page is small)
        apply_marks(self.browser.document(), 0, self.dark)
        _style_md4c(self.browser.document(), 0, self.dark, QUOTE_END in pieces[0])
        self._tables = (0, None)  # (tables seen, the table later parts join: join_tables)
        self._join(0)
        self._boxes = 0
        self._page = {"kind": "md4c", "generation": generation, "parts": pieces, "notes": set(notes),
                      "continued": continued,
                      "where": where, "began": began, "origin": [(0, number) for number in range(len(pieces))],
                      "heads": heads if heads is not None else [part_headings("md4c", piece) for piece in pieces]}
        self._starts = {0: QTextCursor(self.browser.document().begin())}
        self._begun()
        self._back_to_reading()
        self._laid(0, 1)

    def _show_page(self, generation, page, error, dark, where, began, heads=None) -> None:
        """A page :func:`_page` made, shown (unless a newer one is on its way):
        its first part at once, the rest one an event-loop turn (_laid)."""
        if generation != self._page_generation:
            return
        if error is not None:
            self._idle()
            self.status.setText(_t("Cannot render: {error}", error=printable(error)))
            return
        parts, headings, *rest = page
        self.hidden = rest[0] if rest else {}  # (what folded <details> hold: unfold_for)
        from ui.markdown_html import anchor_names, style_sheet

        self._clear_pictures()
        document = self.browser.document()
        document.setDefaultStyleSheet(style_sheet(dark))
        document.setHtml("<html><body>" + parts[0] + "</body></html>")
        _tex_names(document)
        _top_room(document)
        _keep_reader(self.browser, 0, 0)  # (the reader's cursor at the start: find begins there, or where shown)
        # (the margins while the page is small: set at its end they laid all
        # of it out again in one turn)
        self.fit_text()
        body = "".join(parts)
        self.page_images = "<img " in body
        self.names = anchor_names(body)  # (all of the page's - also of parts not laid out yet)
        waiting = getattr(self, "_more_text", None)
        texts = list(waiting[1]) if waiting else []
        # (each piece of a long text not parsed yet: one entry standing in for
        # its parts - a jump there has it parsed next, its parts in its place)
        self._page = {"kind": "html", "generation": generation, "notes": set(),
                      "parts": list(parts) + [_Unparsed(number + 1) for number in range(len(texts))],
                      "texts": [""] + texts, "where": where, "began": began,
                      "loading": bool(texts), "pieces": (1, getattr(self, "_pieces", 1)),
                      "titles": {heading.anchor: heading.text for heading in headings},
                      # (where each entry comes from: (its piece of the text, its part there) - a
                      # place kept across a reload, the parts' numbers moved as pieces came)
                      "origin": [(0, number) for number in range(len(parts))]
                      + [(number + 1, 0) for number in range(len(texts))],
                      "heads": (heads if heads is not None else [part_headings("html", part) for part in parts])
                      + [[] for _text in texts]}
        self._starts = {0: QTextCursor(document.begin())}
        self._begun()
        self._back_to_reading()
        self._laid(0, 1)

    def _parse_next(self, generation: int, dark: bool, toggled) -> None:
        """The next part of a long text parsed on a worker thread, its parts
        put after the page's (_page_more) - one after another."""
        page = self._page
        if page is None or page["generation"] != generation:
            return
        left = [part.piece for part in page["parts"] if isinstance(part, _Unparsed)]
        if not left:
            self._more_text = None
            page["loading"] = False
            if getattr(self, "_copy_waiting", False):  # (a copy waited for the text to be parsed)
                QTimer.singleShot(0, self.copy_selection)
            if self._rest is not None and self._rest >= len(page["parts"]):
                self._rest = None
                self._finish()
            return
        piece = page.get("wanted") if page.get("wanted") in left else left[0]  # (a jump's piece first)
        text = page["texts"][piece]
        page["loading"] = True
        page["parse"] = (dark, toggled, piece)  # (load_rest_now: what is being parsed)
        chain = page.setdefault("chain", 0)

        def done(result, error):
            if generation != self._page_generation or sip.isdeleted(self) or self._page.get("chain") != chain:
                return  # (a newer page; or load_rest_now parsed it meanwhile)
            self._page["parse"] = None
            if error is None:
                self._page_more(result, piece)
            self._parse_next(generation, dark, toggled)

        notes = self._pieces_notes(piece, len(page["texts"]))

        def parse():  # (its <details> numbered from a place of its own: the same whatever came first)
            made = _page(text, dark, toggled, piece * DETAILS_SPAN, notes)
            return made + ([part_headings("html", part) for part in made[0]],)

        in_background(parse, owner=self, done=done)

    def _page_more(self, page, piece: int | None = None) -> None:
        """A long text's later part parsed: its parts after the page's, its
        anchors, headings' names and folded details' contents with them; laid
        out as the others (_laid) - at once if the page waits for it."""
        from ui.markdown_html import anchor_names

        parts, headings, hidden, *more = page
        heads = more[0] if more else [part_headings("html", part) for part in parts]
        everything = self._page["parts"]
        at = next((n for n, part in enumerate(everything) if isinstance(part, _Unparsed) and part.piece == piece),
                  None) if piece is not None else None
        origin = self._page.setdefault("origin", [])
        listed = self._page.setdefault("heads", [[] for _part in everything])
        if at is None:
            at = len(everything)
            origin.extend((piece or 0, number) for number in range(len(parts)))
            everything.extend(parts)
            listed.extend(heads)
            self._outline_later(at, at + len(parts))
        else:
            self._spliced(at, len(parts))
            everything[at:at + 1] = parts
            origin[at:at + 1] = [(piece, number) for number in range(len(parts))]
            listed[at:at + 1] = heads
            self._outline_later(at, at + len(parts))
            written, made = self._page.setdefault("measured", [0, 0])
            written += len(self._page["texts"][piece])
            made += sum(len(part) for part in parts)
            self._page["measured"] = [written, made]
            self._page["ratio"] = made / max(1, written)
        parsed, total = self._page.get("pieces", (1, 1))
        self._page["pieces"] = (min(total, parsed + 1), total)
        self._page["titles"].update({heading.anchor: heading.text for heading in headings})
        body = "".join(parts)
        self.page_images = self.page_images or "<img " in body
        self.names |= anchor_names(body)
        for key in ("text", "anchors"):
            self.hidden.setdefault(key, {}).update(hidden.get(key) or {})
        if (self._want is not None or self._gaps and self._gap_in_view()[0] is not None) and not self._scheduled:
            self._schedule()  # (a jump - or a gap in view - waited for this piece)
        elif self._rest is not None and not self._scheduled:
            if self._whole or (self.browser.document().blockCount() <= EAGER_BLOCKS and self._rest <= EAGER_PARTS) \
                    or self._near_end():
                self._schedule()
            else:  # (paused: said so - "Rendering…" stayed until the page was scrolled)
                self._finish()
                self._shown(_t("Shown: {percent} of the page – the rest as you scroll on",
                                       percent=self._progress(self._rest)))

    def _laid(self, start: int, done: int) -> None:
        self._laid_part(start, done)
        self._run_laid()

    def _laid_part(self, start: int, done: int) -> None:
        """The first *done* parts of the page are in it, the last from
        *start* on: that part made whole (_settle); the next one at the next
        event-loop turn - unless the page is long (EAGER_BLOCKS) and its end
        is not near (nor all of it asked for: load_rest); then as it is
        scrolled to. Laying out more as the page grows took longer each
        time (a list of 100,000 items held the window 2.5 s at a time)."""
        page = self._page
        self._settle(start, done - 1)
        count = len(page["parts"])
        if done >= count:
            if page.get("loading"):
                self._rest = done  # (the text's next part is being parsed: laid out when it comes)
                self._finish()
                self._busy(tr("Rendering…"))
                return
            self._rest = None
            if self._gaps and (self._whole or self._want is not None or self._gap_in_view()[0] is not None):
                self._schedule()  # (a jump's gaps: filled in)
                return
            self._finish()
            return
        self._rest = done
        if not self._whole and (self.browser.document().blockCount() > EAGER_BLOCKS or done > EAGER_PARTS) \
                and not self._near_end() and not self._on_laid:  # (a part waited for: laid out on to it)
            self._finish()
            self._shown(_t("Shown: {percent} of the page – the rest as you scroll on",
                                   percent=self._progress(done)))
            return
        if not self._readable and self.browser.verticalScrollBar().maximum() >= page["where"]:
            self._finish()  # (where it was shown is laid out: shown there now, the rest comes)
        self._busy(_t("Rendering… {percent}", percent=self._progress(done)))
        # (the parts to come stood in for while they come too: the scroll bar
        # as long as all of the page - a drop at 95 % was at 95 % of what was
        # laid out so far, no jump)
        self._stand_in_put()
        if getattr(self, "_target", None) is not None:  # (the thumb where it was dropped meanwhile)
            self._hold_target()
        self._schedule()

    def _progress(self, done: int) -> str:
        """How much of the page is laid out with *done* parts in it - of the
        text parsed so far, times the share of the text that is (a long
        text's later parts are still being parsed: their parts are not
        counted yet)."""
        page = self._page
        sizes = [_size(page, number) for number in range(self._part_count())]
        laid = sum(size for number, size in enumerate(sizes[:done]) if not self._gap_of(number)) \
            if self._gaps else sum(sizes[:done])  # (a jump's gaps: not laid out)
        share = 100 * laid // max(1, sum(sizes))
        if self.more():  # (100 % only when all of it is: "100 % - the rest as you scroll on" was said)
            share = min(share, 99)
        page["shown"] = max(page.get("shown", 0), share)  # (never back: 25 % then 0 %)
        return _percent(page["shown"], 100)

    def _schedule(self) -> None:
        if not self._scheduled:
            self._scheduled = True
            # (a few ms, not 0: a zero timer ran the next part before the
            # window's own events - two parts in a row held it up twice as long)
            QTimer.singleShot(PART_PAUSE, self._next)

    def _next(self) -> None:
        """The page's next part laid out (_next_part) - and once all of it is,
        no "the rest as you scroll on" left in the status (a gap filled last,
        load_rest_now: "Shown: 100% … the rest as you scroll on" stayed)."""
        self._next_part()
        if not sip.isdeleted(self) and self._page is not None and not self.more():
            shown = tr("Shown: {percent} of the page – the rest as you scroll on").split("{")[0]
            if shown and shown in self.status.text():
                self.status.setText(getattr(self, "_cancelled", ""))

    def _next_part(self) -> None:
        """The page's next part laid out (see _laid): one a jump wants first,
        one of a gap in view, then the one after what is laid out."""
        if getattr(self, "_copy_job", None) is not None and not sip.isdeleted(self):
            # (a copy under way, a piece a turn: the page stays as it is meanwhile - a part laid out into a
            # gap between two of its pieces was lost to it)
            QTimer.singleShot(20, self._next)
            return
        self._scheduled = False
        page = self._page
        if page is None or page["generation"] != self._page_generation or sip.isdeleted(self):
            return  # (a newer page)
        if self._want is not None:
            want, self._want = self._want, None
            if self._jump(want):
                self._run_laid()
                self._after_jump()
                return
            # (near what is laid out: laid out with the next ones, as they come - _run_laid then)
        gap, number, dropped = self._gap_in_view()
        if gap is None and self._whole and self._gaps:
            gap, number = self._gaps[0], self._gaps[0]["lo"]
        if gap is not None and isinstance(page["parts"][number], _Unparsed):
            page["wanted"] = page["parts"][number].piece  # (not parsed yet: parsed next - _page_more goes on)
            return
        if gap is not None:
            if dropped:  # (the part where the thumb was dropped)
                self._want_at = self.browser.verticalScrollBar().value()
            self._lay_in_gap(gap, number)
            self._want_at = None
            self._after_jump()
            return
        self._lay_on()

    def _lay_on(self) -> None:
        """The part after what is laid out at the end, laid out (see _laid)."""
        page = self._page
        number = self._rest
        if number is None:
            return
        if number >= len(page["parts"]) or isinstance(page["parts"][number], _Unparsed):
            return  # (its part is still being parsed: _page_more goes on)
        self._rest = None
        self._stand_in_out()
        document = self.browser.document()
        start = document.characterCount() - 1
        after_gap = document.lastBlock().blockFormat().intProperty(_GAP) != 0
        text = page["parts"][number]
        if page["kind"] == "html":
            room = self.browser.lineWrapColumnOrWidth()

            def fill(copy) -> None:  # (bare: a space after its last line)
                copy.setHtml("<html><body>" + text + "</body></html>")
                # (its tables' cells made unbreakable in the part, before it goes into the page: there each
                # cell's change laid all of its table out again - 0.06 s a part of a long table's 300 rows)
                _unbroken_cells(copy, 0, room)

            begins = self._append(fill)
            if text.startswith(CONTINUED):  # (going on inside a box: the line between the boxes as low as it gets)
                _seam(document, begins)
        else:
            begins = self._append(lambda copy: copy.setMarkdown(text, FEATURES))
        if after_gap:  # (after a jump's gap: from past it - styled as prose, the gap lost its height)
            start += 1
        if page["kind"] != "html":
            apply_marks(document, start, self.dark)
            # (from the part's own first block: the one before it - a heading's rule - styled again as a
            # rule of its own, in parts only)
            _style_md4c(document, max(start, begins), self.dark, QUOTE_END in text)
            self._join(start)
        first = _first_block(document, start)
        while first.isValid() and first.blockFormat().intProperty(_GAP):
            first = first.next()
        self._starts[number] = QTextCursor(first)
        self._unclamped = min(getattr(self, "_unclamped", 0), start)
        self._laid(start, number + 1)

    def _gap_in_view(self):
        """(a gap, its part to lay out, whether the view's top is in it) for a
        gap the view shows or nearly does: the part beside what the view shows
        of the page - or (None, None, False)."""
        if not self._gaps:
            return None, None, False
        bar = self.browser.verticalScrollBar()
        layout = self.browser.document().documentLayout()
        top, bottom, room = bar.value(), bar.value() + bar.pageStep(), max(bar.pageStep(), 200)
        for gap in self._gaps:
            block = self._gap_block(gap)
            if block is None:
                continue
            rect = _stand_in_rect(layout, block)
            if rect.bottom() < top - room or rect.top() > bottom + room:
                continue
            if rect.bottom() <= top + 2:  # (above the view: its last part, against what is shown)
                return gap, gap["hi"] - 1, False
            if rect.top() >= top - 2:  # (below the view's top: its first)
                return gap, gap["lo"], False
            if top <= rect.bottom() <= bottom and rect.bottom() < self._content_end() - 2:
                # (its foot in view, a part laid out below it - Ctrl+End's: the part against that one first,
                # the view filled upward from what it shows - it stayed blank, the gap's middle laid out)
                return gap, gap["hi"] - 1, False
            # (the view's top in it - the scroll bar dropped there: the part of that place, begun there)
            share = (top - rect.top()) / max(1.0, rect.height())
            return gap, min(gap["hi"] - 1, gap["lo"] + int(share * (gap["hi"] - gap["lo"]))), True
        return None, None, False

    def _run_laid(self) -> None:
        """What waited for a part to be laid out (go_to_part), now that it is."""
        if not self._on_laid:
            return
        ready = [(number, then) for number, then in self._on_laid if self._is_laid(number)]
        if not ready:
            return
        self._on_laid = [entry for entry in self._on_laid if entry not in ready]
        for _number, then in ready:
            then()

    def _after_jump(self) -> None:
        """A jump's part laid out (or a gap's): more to lay out now, or not."""
        bar = self.browser.verticalScrollBar()
        if self._gaps and bar.value() >= bar.maximum() - bar.pageStep():
            # (the view at the page's end - Ctrl+End: the end laid out by Qt now - each part put in above it
            # began Qt's own layout anew there, never reaching the end: the view stayed blank for 11 s)
            document = self.browser.document()
            document.documentLayout().blockBoundingRect(document.lastBlock())
        gap, _number, _dropped = self._gap_in_view()
        waiting = self._want is not None and isinstance(self._page["parts"][self._want], _Unparsed)
        if waiting:  # (its piece being parsed: laid out when it comes - _page_more)
            self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest or self._part_count())))
        elif self._want is not None or gap is not None or self._whole and (self._gaps or self._rest is not None):
            self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest or self._part_count())))
            self._schedule()
        elif self._rest is not None and self._near_end():
            self._schedule()
        elif self._rest is not None and self._on_laid:  # (a part waited for, near: laid out on to it)
            self._schedule()
        else:
            self._finish()
            if self.more():
                self._shown(_t("Shown: {percent} of the page – the rest as you scroll on",
                                       percent=self._progress(self._rest or self._part_count())))

    def _near_end(self) -> bool:
        """Whether the view shows (nearly) the end of what is laid out, or
        is to show a place further on than that (a page shown anew)."""
        bar = self.browser.verticalScrollBar()
        room = 3 * max(bar.pageStep(), 200)
        if not self._readable:
            return bar.maximum() < (self._page or {}).get("where", 0) + room
        if getattr(self, "_target", None) is not None:  # (a place the scroll bar was dropped at)
            return self._content_end() < self._target + bar.pageStep() + room
        if self._stand_in:  # (the end of what is laid out: the stand-in's top)
            document = self.browser.document()
            end = document.documentLayout().blockBoundingRect(document.lastBlock()).top()
            return end - (bar.value() + bar.pageStep()) < room
        return bar.maximum() - bar.value() < room

    def _content_end(self) -> float:
        """Where what is laid out ends (the stand-in's top, if there is one)."""
        document, bar = self.browser.document(), self.browser.verticalScrollBar()
        if self._stand_in:
            return document.documentLayout().blockBoundingRect(document.lastBlock()).top()
        return bar.maximum() + bar.pageStep()

    def _hold(self, anchor=None, seconds: float = 3.0) -> None:
        """*anchor* (a block and how far above the view's top it begins -
        _view_anchor; else the view's own now) kept on the view's top for
        *seconds* while the page's layout changes - unless the reader
        scrolls meanwhile (a zoom laid the page out again in steps, the view
        drifted a paragraph or two each)."""
        self._held = (anchor or self._view_anchor(), time.monotonic() + seconds)
        self._keep_view(self._held[0])

    def _keep_held(self, *_args) -> None:
        held = self._held
        if held is None:
            return
        if time.monotonic() > held[1]:
            self._held = None
            return
        self._keep_view(held[0])

    def _let_go(self, *_args) -> None:
        """(the reader moved the scroll bar - a wheel, a key, the thumb) the place held, let go."""
        self._held = None

    def _moved(self, *args) -> None:
        if self._held is not None and not getattr(self, "_placing", False):
            self._held = None  # (moved by something else: find, a jump)
        self._scrolled(*args)

    def _scrolled(self, *_args) -> None:
        bar = self.browser.verticalScrollBar()
        if self._readable and not getattr(self, "_placing", False) and self._page is not None:
            far = self._dropped_far()
            if far is not None:  # (the scroll bar dropped far on: the part of that place first)
                self._want, self._target, self._want_at = far, None, bar.value()
                self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest or 0)))
                self._schedule()
                return
            if self._gap_in_view()[0] is not None:  # (a jump's gap scrolled to: its parts there)
                self._schedule()
        if self._stand_in and not getattr(self, "_placing", False):
            # (the scroll bar dropped beyond what is laid out: laid out up to
            # there, the thumb kept there - it snapped back)
            self._target = bar.value() if bar.value() + bar.pageStep() > self._content_end() else None
        if self._rest is not None and self._readable and self._near_end():
            self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest)))
            self._schedule()

    def go_to_part(self, number: int, then=None) -> None:
        """The page's part *number* laid out first (if it is not), then
        *then()* - find, an anchor, Ctrl+End, the place a page is shown again at."""
        if self._is_laid(number):
            if then is not None:
                then()
            return
        if then is not None:
            self._on_laid.append((number, then))
        self._want, self._target = number, None
        self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest or 0)))
        self._schedule()

    def part_at(self, position: int) -> int:
        """The number of the laid-out part the page's *position* is in."""
        found, at = 0, -1
        for number, cursor in self._starts.items():
            start = cursor.position()
            if at < start <= position:
                found, at = number, start
        return found

    def _plain(self, number: int) -> str:
        """The text of the page's part *number* without its marks (lower case): what find looks in."""
        return _plain_text(self._page, self._page["parts"][number])

    def find_match(self, needle: str, backward: bool = False, flags=None, again=None) -> bool | None:
        """The next match of *needle* after the reader's cursor (before it:
        *backward*) in the page's order, round past its end, selected and in
        view: True - False when there is none. On a page laid out in part a
        part not laid out yet that comes before the first match laid out is
        looked in first (its text, on a worker thread): the first that holds
        it laid out, then *again()* goes on from its start - None meanwhile
        (find looked only in what was laid out: after Ctrl+End, Home the
        last match came first, the one in a gap never; round past the end
        all of the page was laid out first, 7 to 68 s)."""
        browser, document = self.browser, self.browser.document()
        flags = flags if flags is not None else (QTextDocument.FindFlag.FindBackward if backward
                                                 else QTextDocument.FindFlag(0))
        cursor = browser.textCursor()
        since, self._found_part = getattr(self, "_found_part", None), None
        if since is not None and self._is_laid(since) and since in self._starts:
            cursor = self._part_edge(since, backward)  # (the part a seek laid out: looked in from its start)
        if not self._may_hold(needle):  # (nowhere in what is laid out: Qt's two searches through all of it
            hit, wrapped = QTextCursor(), True  # spared - 0.185 s a press of Enter on a page of 2.7 MB)
        else:
            hit = document.find(needle, cursor, flags)
            wrapped = hit.isNull()
            if wrapped:
                edge = QTextCursor(document)
                edge.movePosition(QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start)
                hit = document.find(needle, edge, flags)
        if self._page is not None and self.more():
            numbers = self._before_match(cursor.position(), None if hit.isNull() else hit.position(),
                                         wrapped, backward, needle)
            if numbers:
                self._seek_in(numbers, needle, again)
                return None
        if hit.isNull():
            return False
        browser.setTextCursor(hit)
        browser.ensureCursorVisible()
        return True

    def _may_hold(self, needle: str) -> bool:
        """Whether the page laid out may hold *needle* (its text, case aside, holds it: what Qt's find looks
        for is in it then) - the text kept while the document is the same (its revision)."""
        if not needle or any(ch in needle for ch in "\n\u2029\u2028\xa0\ufffc"):  # (toPlainText's own)
            return True
        document = self.browser.document()
        key = (id(document), document.revision(), document.characterCount())
        kept = getattr(self, "_plain_kept", None)
        if kept is None or kept[0] != key:
            kept = self._plain_kept = (key, document.toPlainText().casefold())
        return needle.casefold() in kept[1]

    def _part_edge(self, number: int, backward: bool) -> QTextCursor:
        """A cursor at the start of the laid-out part *number* (*backward*: at its end)."""
        document = self.browser.document()
        start = self._starts[number].position()
        cursor = QTextCursor(document)
        if not backward:
            cursor.setPosition(start)
            return cursor
        ends = [other.position() for other in self._starts.values() if other.position() > start]
        ends += [block.position() for block in (self._gap_block(gap) for gap in self._gaps)
                 if block is not None and block.position() > start]
        cursor.setPosition(min(ends) if ends else document.characterCount() - 1)
        return cursor

    def _before_match(self, here: int, match: int | None, wrapped: bool, backward: bool, needle: str) -> list:
        """The parts not laid out yet to look in, in order, before the match
        laid out at *match* (None: none) - found from the reader's place
        *here*, round past the page's end when *wrapped*. Not the ones looked
        in for *needle* already (in vain)."""
        count, at = self._part_count(), self.part_at(here)
        into = None if match is None else self.part_at(match)
        if not backward:
            if into is None:
                order = list(range(at + 1, count)) + list(range(0, at))
            elif not wrapped:
                order = list(range(at + 1, into))
            else:
                order = list(range(at + 1, count)) + list(range(0, into))
        elif into is None:
            order = list(range(at - 1, -1, -1)) + list(range(count - 1, at, -1))
        elif not wrapped:
            order = list(range(at - 1, into, -1))
        else:
            order = list(range(at - 1, -1, -1)) + list(range(count - 1, into, -1))
        looked = self._looked if getattr(self, "_looked", (None,))[0] == (needle.lower(), self._page_generation) \
            else None
        parts = self._page["parts"]
        return [number for number in order if not self._is_laid(number)
                and (looked is None or id(parts[number]) not in looked[1])]

    def _seek_in(self, numbers: list, needle: str, again) -> None:
        """The first of the parts *numbers* whose text holds *needle* -
        looked for on a worker thread - laid out, then *again()* (find goes
        on from its start); none: they are remembered as looked in, then
        *again()* (the match laid out is the next)."""
        page = self._page
        parts = [page["parts"][number] for number in numbers]
        wanted, generation = needle.lower(), self._page_generation
        self.say(tr("Searching the rest of the page…"))

        def look():  # (pure Python on strings: a worker thread - 4 MB looked through took the window's time)
            for index, number in enumerate(numbers):
                if wanted in _plain_text(page, parts[index]):
                    return index
            return None

        def found(index, error):
            if generation != self._page_generation or sip.isdeleted(self):
                return
            if error is not None or index is None:
                key = (wanted, generation)
                if getattr(self, "_looked", (None,))[0] != key:
                    self._looked = (key, {})
                self._looked[1].update((id(part), part) for part in parts)  # (kept: an id never reused)
                if self.status.text() == tr("Searching the rest of the page…"):
                    self.status.setText("")
                if again is not None:
                    again()
                return
            part = parts[index]
            number = next((n for n, p in enumerate(self._page["parts"]) if p is part), numbers[index])
            self._found_part = None

            def there():
                now = next((n for n, p in enumerate(self._page["parts"]) if p is part), None)
                self._found_part = now if now is not None else number
                if isinstance(part, _Unparsed):  # (a piece parsed since: its parts looked in anew)
                    self._found_part = None
                if again is not None:
                    again()

            self.go_to_part(number, there)

        in_background(look, found, owner=self)

    def seek(self, needle: str, backward: bool = False, then=None) -> bool:
        """The first part not laid out yet after the reader's place (before
        it: *backward*; round past the end) whose text holds *needle*,
        laid out first, then *then()*. False when no part is left to look in."""
        if self._page is None or not self.more():
            return False
        here = self.browser.textCursor().position()
        numbers = self._before_match(here, None, False, backward, needle)
        if not numbers:
            return False
        self._seek_in(numbers, needle, then)
        return True

    def _part_with_anchor(self, name: str) -> int | None:
        """The part not laid out yet that holds the heading or note *name*."""
        page = self._page
        if page is None:
            return None
        wanted = {name, slug(name)}
        for number in range(self._part_count()):
            if self._is_laid(number):
                continue
            part = page["parts"][number]
            if isinstance(part, _Unparsed):  # (a piece not parsed yet: its headings and raw anchors as written -
                written = page["texts"][part.piece]  # parsed first, then looked in again)
                if _written_anchors(written) & wanted:
                    return number
                note = re.fullmatch(r"fn(\d+)", name)  # (a note: the piece its definition is in - numbered
                notes = getattr(self, "_notes", None) or []  # across the text: _notes)
                if note and 0 < int(note.group(1)) <= len(notes) and f"[^{notes[int(note.group(1)) - 1][0]}]:" in written:
                    return number
                continue
            if page["kind"] == "html":
                if any(f'name="{each}"' in part or f'id="{each}"' in part for each in wanted):
                    return number
                continue
            source = _escape_html_undone(part)
            # (a note and the place it is referred to: with_footnotes' "1. " and "(#fn-1)" - a link to
            # one laid out all of the page first, 90 s)
            if name.startswith("fn-") and f"{NOTE_BLOCK}{name[3:]}. " in source:
                return number
            if name.startswith("fnref-") and f"(#fn-{name[6:]})" in source:
                return number
            for line in re.findall(r"(?m)^ {0,3}#{1,6}[ \t]+(.+?)[ \t#]*$", source):
                if slug(line) in wanted:
                    return number
        return None

    def _named_position(self, name: str) -> int | None:
        """(markdown-it's page) where the anchor *name* that is no heading's
        - a note's, the place one is referred to - is, in a part laid out."""
        page = self._page
        if page is None or page["kind"] != "html":
            return None
        document = self.browser.document()
        starts = sorted((cursor.position(), number) for number, cursor in self._starts.items())
        for index, (start, number) in enumerate(starts):
            if f'name="{name}"' not in page["parts"][number]:
                continue
            end = starts[index + 1][0] if index + 1 < len(starts) else document.characterCount()
            block = document.findBlock(start)
            while block.isValid() and block.position() < end:
                pieces = block.begin()
                while not pieces.atEnd():
                    if name in pieces.fragment().charFormat().anchorNames():
                        return pieces.fragment().position()
                    pieces += 1
                block = block.next()
        return None

    def _begun(self) -> None:
        """(a page's first part about to be laid out) the others not laid
        out yet: _rest None read as "all of it laid out" - the place read
        before was gone to at once, before its part was there (the page
        shown at its top after every reload)."""
        self._rest = 1 if self._part_count() > 1 else None

    def _number_of(self, origin) -> int | None:
        """The entry of the page's parts that is (or holds, not parsed yet) the part *origin* (piece, part)."""
        entries = self._page.get("origin") or []
        try:
            return entries.index(tuple(origin))
        except ValueError:
            piece = origin[0]
            return next((number for number, part in enumerate(self._page["parts"])
                         if isinstance(part, _Unparsed) and part.piece == piece), None)

    def _back_to_reading(self) -> None:
        """(a page shown again) the place read before, if far on: its part
        laid out first, the view there - not all of the page up to it."""
        reading, self._reading_next = getattr(self, "_reading_next", None), None
        if reading is None:
            return
        origin, offset = reading
        number = self._number_of(origin)
        if number is None or not number:
            return  # (in the first part: where it was, in pixels)
        self._page["where"] = 0  # (not the old place's pixels: the part's)
        self._readable = True
        self._returning = (origin, offset)
        self._back_to(origin, offset)

    def _back_to(self, origin, offset: float) -> None:
        """The view *offset* pixels into the part *origin*, laid out first (a
        piece not parsed yet: parsed first, then its part laid out)."""
        number = self._number_of(origin)
        if number is None:
            return
        if self._is_laid(number):
            self._returning = None
            into, pixels = offset
            if into is None or number not in self._starts:
                self._show_part(number, pixels)
                return
            # (the block that was on top, by its place in the part's text: a
            # table's room above it not there yet moved it by pixels)
            block = self.browser.document().findBlock(self._starts[number].position() + into)
            self._target = None
            self._hold((QTextCursor(block), pixels))
            return
        self.go_to_part(number, lambda: self._back_to(origin, offset))

    def go_home(self) -> None:
        """Ctrl+Home: the page's first part laid out first (a jump far into it left gaps), its top in view."""
        def top() -> None:
            self.browser.moveCursor(QTextCursor.MoveOperation.Start)
            self.browser.verticalScrollBar().setValue(0)

        if self._page is None or not self._part_count():
            top()
            return
        self.go_to_part(0, top)

    def go_end(self) -> None:
        """Ctrl+End: the page's last part laid out first, its end in view."""
        if self._page is None or not self.more():
            self.to_end()
            return
        self.go_to_part(self._part_count() - 1, self.to_end)

    def _reading(self):
        """Where the view is: (the part on its top - (its piece of the text,
        its part there) - how far into that part) - the place a page shown
        again goes back to (a reload deep in a long page laid out all of it
        up to there first: 18 s)."""
        if self._page is None or not self._starts or not self._readable:
            return None
        block = self.browser.cursorForPosition(QPoint(0, 0)).block()
        number = self.part_at(block.position())
        origin = (self._page.get("origin") or [])[number:number + 1]
        if not origin:
            return None
        layout = self.browser.document().documentLayout()
        value = self.browser.verticalScrollBar().value()
        fmt = block.blockFormat()
        if fmt.intProperty(_GAP) or fmt.boolProperty(_STAND_IN):  # (in a stand-in: pixels into the part)
            return origin[0], (None, value - layout.blockBoundingRect(self._starts[number].block()).top())
        # (the block on top - characters into its part - and pixels into that block)
        return origin[0], (block.position() - self._starts[number].position(),
                           value - layout.blockBoundingRect(block).top())

    def _dropped_far(self) -> int | None:
        """The part the view's top is at when it is far into the stand-in for
        the parts not laid out yet (more than a few screens past their start)
        - else None."""
        if not self._stand_in or self._rest is None:
            return None
        bar = self.browser.verticalScrollBar()
        document = self.browser.document()
        rect = _stand_in_rect(document.documentLayout(), document.lastBlock())
        if bar.value() < rect.top() + 2 * max(bar.pageStep(), 200):
            return None
        share = (bar.value() - rect.top()) / max(1.0, rect.height())
        count = self._part_count()
        number = min(count - 1, self._rest + int(share * (count - self._rest)))
        return number if number >= self._rest + JUMP_PARTS else None

    def folds_holding(self, needle: str) -> list[tuple[int, int, int]]:
        """(where its summary is, its number, how often *needle* is in it) of
        each folded <details> laid out that holds *needle*, in the page's
        order - find goes into them where they are (it found them only when
        nothing else on the page matched)."""
        texts = (getattr(self, "hidden", None) or {}).get("text") or {}
        lowered = needle.lower()
        counts = {number: text.lower().count(lowered) for number, text in texts.items() if lowered in text.lower()}
        if not counts:
            return []
        found, document = [], self.browser.document()
        cursor = document.find("\u25b8", 0)  # (a folded summary's "▸", its link "#axross-details-N")
        while not cursor.isNull():
            href = cursor.charFormat().anchorHref()
            if href.startswith("#" + FOLD) and href[len(FOLD) + 1:].isdigit():
                number = int(href[len(FOLD) + 1:])
                if number in counts:
                    found.append((cursor.selectionStart(), number, counts[number]))
            cursor = document.find("\u25b8", cursor)
        return found

    def summary_of(self, number: int) -> int | None:
        """Where the summary of the <details> *number* is (folded or open)."""
        document = self.browser.document()
        for mark in ("\u25be", "\u25b8"):
            cursor = document.find(mark, 0)
            while not cursor.isNull():
                if cursor.charFormat().anchorHref() == f"#{FOLD}{number}":
                    return cursor.selectionStart()
                cursor = document.find(mark, cursor)
        return None

    def unfold_for(self, needle: str = "", anchor: str = "", then=None, only: int | None = None) -> bool:
        """Open the folded <details> that hold *needle* (find) or the heading
        *anchor* (*only*: that one of them) - the page rendered anew, then
        *then()*; False when none does."""
        hidden = getattr(self, "hidden", None) or {}
        numbers = set()
        if needle:
            numbers = {n for n, text in (hidden.get("text") or {}).items() if needle.lower() in text.lower()}
        if anchor:
            owner = (hidden.get("anchors") or {}).get(anchor) or (hidden.get("anchors") or {}).get(slug(anchor))
            numbers |= {owner} if owner else set()
        if not numbers:
            return False
        if only is not None:
            numbers &= {only}
            if not numbers:
                return False
        self.folds ^= numbers  # (each is closed: turned, it opens)
        if then is not None:
            self._then.append(then)
        self.render(self.markdown)
        return True

    def copy_selection(self) -> None:
        """The selection copied - as the page shows it all laid out (a
        display formula: its TeX). The parts not laid out yet inside it (a
        gap's, the end's) are made as they would be laid out, in documents of
        their own, a few event-loop turns; a piece of the text not parsed yet
        is parsed first ("Copying… N %" meanwhile). The parts are taken when
        the copy begins: a piece parsed meanwhile moved their numbers - the
        copy lost its end, 1 in 3."""
        from PyQt6.QtWidgets import QApplication

        self._cancelled = ""  # (a copy cancelled before: said until this one)
        cursor = self.browser.textCursor()
        page = self._page
        end = self.browser.document().characterCount() - 1
        if getattr(self, "_copy_waiting", False) and getattr(self, "_copy_to_end", False) and cursor.hasSelection():
            # (it reached the page's end when it was asked for: it does still - parts came after it)
            cursor.setPosition(_low(cursor))
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
            self.browser.setTextCursor(cursor)
        holes = self._holes(cursor) if cursor.hasSelection() and page is not None else []
        if not holes:
            if not cursor.hasSelection():
                return
            ranges = _copy_ranges(self.browser.document(), _low(cursor), _high(cursor))
            if len(ranges) == 1:
                QApplication.clipboard().setText(  # (no empty line first: a table's, a quote's, a code
                    _copy_text(self.browser.document(), _low(cursor), _high(cursor)).lstrip("\n"))  # block's frame)
                return
            # (a long selection: a piece an event-loop turn - all of 60,000 formulas held the window 9 s)
            self._copy_job = {"pieces": ranges, "out": [], "generation": self._page_generation,
                              "count": len(ranges), "done": 0}
            self.say(_t("Copying… {percent}", percent=_percent(0, 1)))
            self._copy_more()
            return
        if any(isinstance(part, _Unparsed) for part in page["parts"]):  # (raw Markdown was copied for it)
            self._copy_to_end = _high(cursor) >= end or getattr(self, "_copy_to_end", False) \
                and getattr(self, "_copy_waiting", False)
            self._copy_waiting = True
            self.say(_t("Copying… {percent}", percent=_percent(0, 1)))
            return
        self._copy_waiting = False
        pieces, at = [], _low(cursor)
        document = self.browser.document()
        for position, numbers, after in holes:
            pieces.extend(_copy_ranges(document, at, position))
            pieces.extend(("part", page["parts"][number]) for number in numbers)
            at = after
        pieces.extend(_copy_ranges(document, at, _high(cursor)))
        self._copy_job = {"pieces": pieces, "out": [], "generation": self._page_generation,
                          "count": max(1, sum(isinstance(piece, tuple) for piece in pieces)), "done": 0}
        self.say(_t("Copying… {percent}", percent=_percent(0, 1)))
        self._copy_more()

    def _holes(self, cursor) -> list:
        """The stand-ins inside *cursor*'s selection - a gap's, the end's -
        as (where it begins, the parts it stands for, where it ends), in order."""
        low, high = _low(cursor), _high(cursor)
        holes = []
        for gap in self._gaps:
            block = self._gap_block(gap)
            if block is not None and low <= block.position() < high:
                holes.append((block.position(), list(range(gap["lo"], gap["hi"])),
                              block.position() + block.length()))
        document = self.browser.document()
        last = document.lastBlock()
        if self._rest is not None:  # (the parts after what is laid out: the end's stand-in, if it is)
            end = last.position() if last.blockFormat().boolProperty(_STAND_IN) else document.characterCount() - 1
            if high >= end:
                holes.append((end, list(range(self._rest, self._part_count())), document.characterCount() - 1))
        return sorted(holes, key=lambda hole: hole[0])

    def _copy_more(self) -> None:
        """(copy_selection) the next parts' text, COPY_TURN of it an event-loop
        turn; all of it there: on the clipboard."""
        job = getattr(self, "_copy_job", None)
        if job is None or sip.isdeleted(self) or job["generation"] != self._page_generation:
            return
        began = time.monotonic()
        pieces = job["pieces"]
        while pieces and time.monotonic() - began < COPY_TURN:
            piece = pieces.pop(0)
            if isinstance(piece, tuple) and piece[0] == "range":  # (of the page: its cursors kept their places)
                job["out"].append(_copy_text(self.browser.document(), piece[1].position(), piece[2].position()))
                job["done"] += 1
            elif isinstance(piece, tuple):
                part = self._part_document(None, piece[1], counted=False)
                text = _copy_text(part, 0, part.characterCount() - 1)
                part.deleteLater()
                job["out"].append(text.rstrip("\n") + "\n")
                job["done"] += 1
            else:
                job["out"].append(piece)
        if pieces:
            self.status.setText(_t("Copying… {percent}", percent=_percent(job["done"], job["count"])))
            QTimer.singleShot(0, self._copy_more)
            return
        self._copy_job = None
        from PyQt6.QtWidgets import QApplication

        QApplication.clipboard().setText("".join(job["out"]).lstrip("\n"))
        self.say(tr("Copied."))

    def more(self) -> bool:
        """Whether a part of the page is not laid out yet (see _laid)."""
        return self._rest is not None or self._scheduled or bool(self._gaps)

    def load_rest(self, then=None) -> None:
        """The rest of the page laid out, a part an event-loop turn - then
        *then()* (find, a jump, print)."""
        if then is not None:
            self._then.append(then)
        if self._rest is None and not self._scheduled and not self._gaps:
            self._run_then()
            return
        self._whole = True
        self._busy(_t("Rendering… {percent}", percent=self._progress(self._rest or 0)))
        self._schedule()

    def load_rest_now(self) -> None:
        """The rest of the page laid out at once (an export, a print asked
        for in code: it is waited for) - a long text's parts not parsed yet
        parsed here."""
        self._whole = True
        page = self._page
        if page is not None and page.get("loading"):
            page["chain"] = page.get("chain", 0) + 1  # (what the worker brings later is dropped)
            dark, toggled, _current = page.get("parse") or (self.dark, frozenset(self.folds), None)
            self._more_text = None
            for piece in [part.piece for part in page["parts"] if isinstance(part, _Unparsed)]:
                self._page_more(_page(page["texts"][piece], dark, toggled, piece * DETAILS_SPAN,
                                      self._pieces_notes(piece, len(page["texts"]))), piece)
            page["loading"], page["parse"] = False, None
        while self._rest is not None or self._scheduled or self._gaps:
            self._next()

    def _run_then(self) -> None:
        waiting, self._then = self._then, []
        for then in waiting:
            then()

    def _settle(self, start: int, number: int = 0) -> None:
        """A part just laid out (from *start* on) made whole: for Qt's own
        parser its marks out, its code wrapped, its boxes (_box_md4c); its
        headings in the outline."""
        document = self.browser.document()
        _list_items(document, start, self._page["kind"] == "html", self.dark)
        if self._page["kind"] == "md4c":
            _hard_breaks(document, start)
            _merge_spans(document, start)

            _math_displays(document, start, self.dark)
            _inline_tex_marks(document, start)
            _unmark(document, start)
            _wrap_code(document, start)
            continued = self._page.get("continued") or ()
            self._boxes += _box_md4c(document, self.dark, start, MD4C_BOXES - self._boxes,
                                     (number in continued, number + 1 in continued))
            _table_room(document, start)
        _going_on(document, start)
        _join_lists(document, start)
        if self._page["kind"] != "html" or not start:  # (markdown-it's later parts: theirs before - _lay_on)
            _unbroken_cells(document, start, self.browser.lineWrapColumnOrWidth())
        self.read_outline(self._page["notes"], start, number=number)
        if not start:  # (the page's first part: the others' headings stand in for theirs)
            self._outline_later(1, self._part_count())

    def _finish(self) -> None:
        """The page readable (its first parts, or all of it): margins, images,
        the place it is to be shown at - that once; when all of it is laid
        out, what waited for it."""
        page = self._page
        self.fit_text()
        self.clamp_images()
        if not self._readable:
            self._readable = True
            self._place(page["where"])
            # The live preview waits for a pause in the typing at least twice
            # as long as a rendering takes: a big text's rendering after every
            # pause of RENDER_DELAY left the typing stuck most of the time.
            self.timer.setInterval(max(RENDER_DELAY, int(2000 * (time.monotonic() - page["began"]))))
            self.shown.emit()
        self.read_missing()
        if self._rest is None and not self._gaps:
            self._stand_in_out()
            self._bar_kept(False)
            self._whole = False
            self._idle()
            self._run_then()
        else:
            if self._rest is not None:
                self._stand_in_put()
            self._hold_target()
            self._idle()

    def _hold_target(self) -> None:
        target = getattr(self, "_target", None)
        if target is None:
            return
        self._placing = True
        try:
            self.browser.verticalScrollBar().setValue(target)
        finally:
            self._placing = False

    def to_end(self) -> None:
        """The end of the page in view (Ctrl+End, once all of it is laid out)."""
        document = self.browser.document()
        document.documentLayout().blockBoundingRect(document.lastBlock())  # (laid out by Qt to there: shown)
        self.browser.moveCursor(QTextCursor.MoveOperation.End)
        bar = self.browser.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _stand_in_put(self) -> None:
        """An empty block as high as the parts not laid out yet are likely
        to be, at the page's end: the scroll bar as long as all of it (it was
        as long as what was laid out). Taken out before a part goes in."""
        page = self._page
        if self._stand_in or page is None or not self._rest:
            return
        from PyQt6.QtGui import QTextBlockFormat

        # (as high as the parts' text is long, at the pixels a character took so
        # far - an unparsed piece's by its text)
        height = self._per_char() * sum(_size(page, number) for number in range(self._rest, self._part_count()))
        if height < 1:
            return
        fmt = QTextBlockFormat()
        fmt.setLineHeight(min(height, STAND_IN_PIXELS), 2)  # (2: FixedHeight)
        fmt.setTopMargin(0)
        fmt.setBottomMargin(0)
        fmt.setProperty(_STAND_IN, True)
        cursor = QTextCursor(self.browser.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertBlock(fmt, QTextCharFormat())
        self._stand_in = True
        self._bar_kept(True)

    def _bar_kept(self, kept: bool) -> None:
        """The vertical scroll bar shown all along while parts are to come (*kept*), else as needed. While
        what is laid out was shorter than the view, each stand-in taken out hid the bar and each put in
        showed it: the view as wide again each time, and Qt laid all of the page out anew - twice a part,
        a turn as long as the page so far (a page of colour emoji, whose glyphs cost FreeType a bitmap
        decoded each: 0.19 s)."""
        policy = Qt.ScrollBarPolicy.ScrollBarAlwaysOn if kept else Qt.ScrollBarPolicy.ScrollBarAsNeeded
        if self.browser.verticalScrollBarPolicy() != policy:
            self.browser.setVerticalScrollBarPolicy(policy)

    def _stand_in_out(self) -> None:
        if not self._stand_in:
            return
        self._stand_in = False
        document = self.browser.document()
        last = document.lastBlock()
        if not last.blockFormat().boolProperty(_STAND_IN):
            return
        # (the block before it keeps its own format: joined, it took the
        # stand-in's - a blank band as high as the parts were, left mid-page)
        before = last.previous()
        kept = before.blockFormat() if before.isValid() else None
        cursor = QTextCursor(document)
        cursor.setPosition(max(0, last.position() - 1))
        cursor.setPosition(last.position() + last.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        if kept is not None and document.lastBlock().blockFormat().boolProperty(_STAND_IN):
            cursor.setBlockFormat(kept)

    # -- a jump: a part far on laid out first, the ones between as stand-ins (gaps) --

    def _part_count(self) -> int:
        return len(self._page["parts"]) if self._page else 0

    def _is_laid(self, number: int) -> bool:
        """Whether the page's part *number* is laid out."""
        end = self._rest if self._rest is not None else self._part_count()
        return number < end and not any(gap["lo"] <= number < gap["hi"] for gap in self._gaps)

    def _gap_of(self, number: int) -> dict | None:
        return next((gap for gap in self._gaps if gap["lo"] <= number < gap["hi"]), None)

    def _spliced(self, at: int, count: int) -> None:
        """The entry *at* of the page's parts (an unparsed piece) to become
        *count* parts: every number of a part after it moved on."""
        by = count - 1
        if not by:
            return
        for gap in self._gaps:
            if gap["lo"] > at:
                gap["lo"] += by
            if gap["hi"] > at:
                gap["hi"] += by
        self._starts = {(number + by if number > at else number): cursor for number, cursor in self._starts.items()}
        if self._rest is not None and self._rest > at:
            self._rest += by
        if self._want is not None and self._want > at:
            self._want += by
        self._on_laid = [(number + by if number > at else number, then) for number, then in self._on_laid]
        for span in (getattr(self, "_outline_queue", None) or [0, []])[1]:  # (the parts still to be listed)
            span[0] += by if span[0] > at else 0
            span[1] += by if span[1] > at else 0
        for row in range(self._outline_rows(at + 1)[0], self.outline.count()):  # (the outline's later entries)
            item = self.outline.item(row)
            item.setData(_PART_ROLE, int(item.data(_PART_ROLE)) + by)
        sizes = self._page.get("sizes")
        if sizes:
            self._page["sizes"] = {(number + by if number > at else number): size for number, size in sizes.items()
                                   if number != at}

    def _gap_block(self, gap: dict):
        """The block standing in for *gap* (found by its number if its place moved)."""
        if gap["at"] is None:  # (being made: no block yet)
            return None
        block = gap["at"].block()
        if block.isValid() and block.blockFormat().intProperty(_GAP) == gap["id"]:
            return block
        block = self.browser.document().begin()
        while block.isValid():
            if block.blockFormat().intProperty(_GAP) == gap["id"]:
                gap["at"] = QTextCursor(block)
                return block
            block = block.next()
        return None

    def _per_char(self) -> float:
        """Pixels a character of a part's text takes on the page, as laid out so far."""
        page, document = self._page, self.browser.document()
        sizes = page.setdefault("sizes", {})
        laid = height = 0.0
        for number, cursor in self._starts.items():
            if number not in sizes:
                sizes[number] = len(page["parts"][number] or "")
            laid += sizes[number]
        height = document.documentLayout().documentSize().height()
        for gap in self._gaps:
            block = self._gap_block(gap)
            if block is not None:
                height -= block.blockFormat().lineHeight()
        if self._stand_in:
            height -= document.lastBlock().blockFormat().lineHeight()
        return max(0.01, height / max(1.0, laid))

    def _gap_format(self, gap: dict):
        from PyQt6.QtGui import QTextBlockFormat

        chars = sum(_size(self._page, number) for number in range(gap["lo"], gap["hi"]))
        fmt = QTextBlockFormat()
        fmt.setLineHeight(max(1.0, min(chars * self._per_char(), STAND_IN_PIXELS)), 2)  # (2: FixedHeight)
        fmt.setTopMargin(0)
        fmt.setBottomMargin(0)
        fmt.setProperty(_GAP, gap["id"])
        return fmt

    def _new_gap(self, low: int, high: int) -> dict:
        self._gap_number = getattr(self, "_gap_number", 0) + 1
        gap = {"lo": low, "hi": high, "id": self._gap_number, "at": None}
        self._gaps.append(gap)
        self._gaps.sort(key=lambda found: found["lo"])
        return gap

    def _view_anchor(self):
        """The block on top of the view and how far above the view's top it begins."""
        block = self.browser.cursorForPosition(QPoint(0, 0)).block()
        top = self.browser.document().documentLayout().blockBoundingRect(block).top()
        return QTextCursor(block), self.browser.verticalScrollBar().value() - top

    def _keep_view(self, anchor) -> None:
        """The view where it was over *anchor*'s block (parts put in above it)."""
        cursor, offset = anchor
        top = self.browser.document().documentLayout().blockBoundingRect(cursor.block()).top()
        self._placing = True
        try:
            self.browser.verticalScrollBar().setValue(int(top + offset))
        finally:
            self._placing = False

    def _show_part(self, number: int, offset: float = 0.0) -> None:
        """The view on the part *number*'s first block (and *offset* pixels
        on) - held there while the page below it comes (the scroll bar
        not yet as long: the view stopped short of the place)."""
        cursor = self._starts.get(number)
        if cursor is None:
            return
        self._target = None
        self._hold((QTextCursor(cursor), offset))

    def _part_document(self, number: int | None, text: str | None = None, counted: bool = True,
                       kind: str | None = None, dark: bool | None = None, printed: bool = False):
        """The page's part *number* (or *text*, one of its parts) in a
        document of its own, made whole there (every pass that _settle runs
        on a part, bounded by the part) - what it shows. *counted*: its boxes
        count against the page's (not for a copy). *kind*, *dark*: a part
        of a page of its own ("html" or "md4c"; to print: light);
        *printed*: to print (no formula's TeX on its letters)."""

        page, document = self._page or {}, self.browser.document()
        kind = kind or page["kind"]
        dark = self.dark if dark is None else dark
        part = _PageCopy(self.browser)
        if dark == self.dark:
            part.setDefaultStyleSheet(document.defaultStyleSheet())
        else:
            from ui.markdown_html import style_sheet

            part.setDefaultStyleSheet(style_sheet(dark))
        part.setDefaultFont(document.defaultFont())
        text = page["parts"][number] if text is None else text
        if kind == "html":
            part.setHtml("<html><body>" + text + "</body></html>")
            if not printed:  # (to print not: Qt's printing crashed on a formula's anchor made its TeX name)
                _tex_names(part)  # (before it goes into the page: see _TEX)
        else:
            part.setMarkdown(text, FEATURES)
            apply_marks(part, 0, dark)
            _style_md4c(part, 0, dark, QUOTE_END in text)
        _list_items(part, 0, kind == "html", dark)
        if kind == "md4c":
            _hard_breaks(part, 0)
            _merge_spans(part, 0)
            _math_displays(part, 0, dark)
            _inline_tex_marks(part, 0)
            _unmark(part, 0)
            _wrap_code(part, 0)
            continued = page.get("continued") or ()
            boxes = _box_md4c(part, dark, 0, MD4C_BOXES - self._boxes,
                              (number in continued, number is not None and number + 1 in continued))
            self._boxes += boxes if counted else 0
            _table_room(part)
            if not counted:  # (a big table's later part: its header goes when it is joined - join_tables)
                from PyQt6.QtGui import QTextTable

                for frame in part.rootFrame().childFrames():
                    if isinstance(frame, QTextTable) and _first_cell(frame).startswith(CHUNK) and frame.rows() > 1:
                        frame.removeRows(0, 1)
        _going_on(part, 0)
        _join_lists(part, 0)
        _unbroken_cells(part, 0, self.browser.lineWrapColumnOrWidth())
        return part

    def _insert_before(self, block, part) -> tuple[int, int]:
        """*part* (a document) put in the page before *block* (a gap's), every
        format kept (a list's item its list, a heading its level, the gap's
        block its own): an empty block before and after it in *part* goes
        into the page's, those taken out again. Returns where it is: (start,
        end) in the page."""
        from PyQt6.QtGui import QTextBlockFormat

        head = QTextCursor(part)
        head.insertBlock(part.begin().blockFormat(), part.begin().charFormat())
        head.movePosition(QTextCursor.MoveOperation.Start)
        head.setBlockFormat(QTextBlockFormat())
        head.setBlockCharFormat(QTextCharFormat())
        head.movePosition(QTextCursor.MoveOperation.End)
        head.insertBlock(QTextBlockFormat(), QTextCharFormat())
        document = self.browser.document()
        at = block.position()
        cursor = QTextCursor(document)
        cursor.setPosition(at)
        cursor.insertBlock(block.blockFormat(), block.charFormat())  # (an empty block before it, as it)
        cursor.setPosition(at)
        cursor.setBlockFormat(QTextBlockFormat())
        cursor.setBlockCharFormat(QTextCharFormat())
        cursor.insertFragment(QTextDocumentFragment(part))
        tail = cursor.block()  # (the empty block after it: into the gap's)
        cursor.setPosition(tail.position())
        cursor.setPosition(tail.next().position(), QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        first = document.findBlock(at)
        if first.next().isValid() and QTextCursor(first.next()).currentTable() is None:
            cursor.setPosition(first.position())  # (the empty one before it: out - not before a table)
            cursor.setPosition(first.next().position(), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
        end = document.findBlock(at)
        while end.isValid() and end.blockFormat().intProperty(_GAP) == 0:
            end = end.next()
        return at, (end.position() if end.isValid() else document.characterCount() - 1)

    def _drop_gap(self, gap: dict) -> None:
        """*gap*'s block out of the page: all of its parts are laid out."""
        from PyQt6.QtGui import QTextBlockFormat

        self._gaps.remove(gap)
        block = self._gap_block(gap)
        if block is None:
            return
        cursor = QTextCursor(self.browser.document())
        after = block.next()
        if after.isValid() and QTextCursor(after).currentTable() is None:
            cursor.setPosition(block.position())
            cursor.setPosition(after.position(), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()  # (into the block after it: that one's format kept)
        else:  # (before a table, or the page's last: an empty line - a table needs one before it)
            cursor.setPosition(block.position())
            cursor.setBlockFormat(QTextBlockFormat())

    def _shift(self, at: int, by: int, height_at: float, grew: float) -> None:
        """Every place kept as a number moved on by *by* characters from *at*
        on (and by *grew* pixels from *height_at*): parts put in before them."""
        if by:
            for name, position in list(self.anchors.items()):
                if position >= at:
                    self.anchors[name] = position + by
            # (the outline's rows are in the page's order: those from *at* on found by halves - each row
            # looked at was 0.1 s a part put in with 150,000 headings)
            role, outline = Qt.ItemDataRole.UserRole, self.outline
            low, high = 0, outline.count()
            while low < high:
                middle = (low + high) // 2
                if int(outline.item(middle).data(role)) < at:
                    low = middle + 1
                else:
                    high = middle
            for row in range(low, outline.count()):
                item = outline.item(row)
                position = int(item.data(role))
                if position >= at:
                    item.setData(role, position + by)
        if grew:
            for stack in (self.back_stack, self.forward_stack):
                stack[:] = [where + int(grew) if where >= height_at else where for where in stack]

    def _lay_in_gap(self, gap: dict, number: int) -> int:
        """The part *number* of *gap* laid out in its place (the gap split
        around it: the parts before it a gap of their own); the view kept
        where it is, and the page's height as it was - the gap's height shared
        out, not estimated anew (what is below moved, the thumb with it).
        Returns where the part begins."""
        document = self.browser.document()
        layout = document.documentLayout()
        anchor = self._view_anchor()
        block = self._gap_block(gap)
        height_at = layout.blockBoundingRect(block).top()
        before_height, before_count = layout.documentSize().height(), document.characterCount()
        stood = block.blockFormat().lineHeight()
        page = self._page
        low, high = gap["lo"], gap["hi"]
        sizes = [_size(page, part) for part in range(low, high)]
        upper_height = 0.0
        if number > low:  # (the parts before it: a gap of their own, before it)
            wanted = getattr(self, "_want_at", None)
            upper_height = max(1.0, wanted - height_at) if wanted is not None \
                else stood * sum(sizes[:number - low]) / max(1, sum(sizes))  # (a drop: begun where dropped)
            upper = self._new_gap(low, number)
            at = block.position()
            cursor = QTextCursor(document)
            cursor.setPosition(at)
            cursor.insertBlock(block.blockFormat(), block.charFormat())  # (a copy of the gap's block before it)
            above = document.findBlock(at)
            fmt = above.blockFormat()
            fmt.setLineHeight(min(upper_height, STAND_IN_PIXELS), 2)
            fmt.setProperty(_GAP, upper["id"])
            cursor.setPosition(above.position())
            cursor.setBlockFormat(fmt)
            upper["at"] = QTextCursor(above)
            block = above.next()
            gap["at"] = QTextCursor(block)
        gap["lo"] = number + 1
        height = layout.documentSize().height()
        part = self._part_document(number)
        start, end = self._insert_before(block, part)
        part.deleteLater()
        self._starts[number] = QTextCursor(document.findBlock(start))
        self._unclamped = min(getattr(self, "_unclamped", 0), start)  # (its images: fitted to their room)
        took = layout.documentSize().height() - height  # (the part's own height)
        if gap["lo"] >= gap["hi"]:
            self._drop_gap(gap)
            if number > low and getattr(self, "_want_at", None) is None:
                # (its last part, from below: the gap above it what is left of the
                # height - an estimate moved what is below, the thumb with it)
                above = self._gap_block(upper)
                fmt = above.blockFormat()
                fmt.setLineHeight(max(1.0, stood - took), 2)
                cursor = QTextCursor(document)
                cursor.setPosition(above.position())
                cursor.setBlockFormat(fmt)
        else:  # (the rest of the gap: what is left of its height)
            fmt = self._gap_block(gap).blockFormat()
            fmt.setLineHeight(max(1.0, stood - upper_height - took), 2)
            cursor = QTextCursor(document)
            cursor.setPosition(self._gap_block(gap).position())
            cursor.setBlockFormat(fmt)
        grown = document.characterCount() - before_count
        self._shift(start, grown, height_at, layout.documentSize().height() - before_height)
        self._joined_around(start, end)
        self.read_outline(self._page["notes"], start, end, number)
        if getattr(self, "_want_at", None) is not None:
            # (the scroll bar put into the gap - a drop, a click in the trough after Ctrl+End: the part
            # of that place shown where it was put. Kept over the gap's block, the view went down by
            # the part's height - and by the next one's, ... back to the end)
            self._placing = True
            try:
                self.browser.verticalScrollBar().setValue(int(layout.blockBoundingRect(document.findBlock(start)).top()))
            finally:
                self._placing = False
        else:
            self._keep_view(anchor)
        return start

    def _joined_around(self, start: int, end: int) -> None:
        """A part put in between others: a list or a big table it goes on with
        (or the one after goes on with) joined across its edges."""
        document = self.browser.document()
        _join_lists(document, start, end)
        after = document.findBlock(end)
        if after.isValid() and after.blockFormat().intProperty(_GAP) == 0 and end < document.characterCount() - 1:
            _join_lists(document, end, min(document.characterCount() - 1, end + 1))
        if self._page["kind"] == "md4c":
            from PyQt6.QtGui import QTextTable

            frames = [frame for frame in document.rootFrame().childFrames() if isinstance(frame, QTextTable)]
            for index, table in enumerate(frames):
                if index and (start <= table.firstPosition() <= end + 2) and _first_cell(table).startswith(CHUNK):
                    previous = frames[index - 1]
                    between = document.findBlock(previous.lastPosition() + 1)
                    if between.next().isValid() and QTextCursor(between.next()).currentTable() == table \
                            and between.blockFormat().intProperty(_GAP) == 0:
                        join_tables(document, [table], previous)
            # (the room under the table before it, and under its last)
            before = document.findBlock(max(0, start - 1))
            _table_room(document, max(0, before.position() - 1), end + 2)

    def _jump(self, number: int) -> bool:
        """The part *number* laid out first (a place far on): the parts
        between it and what is laid out a gap, filled in as they are scrolled
        to. False when it is laid out already or near enough to come next."""
        page = self._page
        if page is None or not 0 <= number < self._part_count() or self._is_laid(number):
            return False
        if isinstance(page["parts"][number], _Unparsed):  # (not parsed yet: that piece next, then here)
            page["wanted"] = page["parts"][number].piece
            self._want = number
            return True
        # (what waits for the part shows its own place - an anchor's heading,
        # a match: the part's start shown after it scrolled away from there)
        waited = any(wanted == number for wanted, _then in self._on_laid)
        gap = self._gap_of(number)
        if gap is not None:
            start = self._lay_in_gap(gap, number)
        elif self._rest is not None and number >= self._rest:
            if number < self._rest + JUMP_PARTS:
                return False
            self._stand_in_out()
            document = self.browser.document()
            gap = self._new_gap(self._rest, number)
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.MoveOperation.End)
            fmt = self._gap_format(gap)
            at = getattr(self, "_want_at", None)
            if at is not None:  # (a drop: the part where the thumb was dropped - it went elsewhere)
                top = document.documentLayout().blockBoundingRect(document.lastBlock()).bottom()
                fmt.setLineHeight(max(1.0, min(at - top, STAND_IN_PIXELS)), 2)
            cursor.insertBlock(fmt, QTextCharFormat())
            gap["at"] = QTextCursor(document.lastBlock())
            self._rest = number
            self._lay_on()  # (the part after the gap, at the end as ever)
            start = self._starts[number].position() if number in self._starts else None
        else:
            return False
        if start is not None and not waited:
            self._show_part(number)
        self._want_at = None
        return True

    def _append(self, fill) -> int:
        """A part of the page, made by *fill(document)* in a document of its
        own (one that loads nothing itself: _PageCopy), put at the page's
        end. Its first block's format is set again: it went into the empty
        block that ends the page and took that one's - a heading there lost
        its level (and its place in the outline)."""
        document = self.browser.document()
        part = _PageCopy(self.browser)
        part.setDefaultStyleSheet(document.defaultStyleSheet())
        part.setDefaultFont(document.defaultFont())
        fill(part)
        _tex_names(part)  # (before it goes into the page: see _TEX)
        ruler = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
        first = part.begin()
        if not first.text() and first.next().isValid() and not first.next().text() and first.textList() is None \
                and first.next().blockFormat().hasProperty(ruler) and not first.blockFormat().hasProperty(ruler):
            # (a part begun at a rule: Qt's own parser put an empty block before it - one the whole page has
            # not; the rule's block first, as a part of markdown-it's begins)
            kept = first.next().blockFormat()
            head = QTextCursor(part)
            head.deleteChar()
            head.setBlockFormat(kept)
        bare = not part.begin().text()  # (an empty first block: the one before a table)
        ruled = part.begin().blockFormat().hasProperty(ruler)
        listed = part.begin().textList() is not None
        if listed:  # (its first block an item: one before it to go into the page's - set again, the item
            from PyQt6.QtGui import QTextBlockFormat  # lost its list)

            head = QTextCursor(part)
            head.insertBlock(part.begin().blockFormat(), part.begin().charFormat())  # (the item's on its text)
            head.movePosition(QTextCursor.MoveOperation.Start)
            head.setBlockFormat(QTextBlockFormat())  # (the empty one before it: in no list)
        reader = self.browser.textCursor()  # (the reader's: it rode to the end with every part - find began there)
        anchor, position = reader.anchor(), reader.position()
        cursor = QTextCursor(document)
        cursor.movePosition(QTextCursor.MoveOperation.End)
        last = document.lastBlock()
        rule = last.blockFormat().hasProperty(QTextFormat.Property.BlockTrailingHorizontalRulerWidth)
        into_last = last.length() == 1 and last.blockNumber() and bare and not last.blockFormat().intProperty(_GAP)
        before = last.previous()
        if into_last and ruled and before.isValid() and (
                before.blockFormat().nonBreakableLines() or QTextCursor(before).currentTable() is not None):
            into_last = False  # (a rule after code, a box - the list of notes' - has a line before it, a whole page's too)
        # (a part beginning with a table - a box: a code block, a quote - after a line of text: its
        # empty block into that line, the table right after it - as the whole page has it; an empty
        # line between them was the cut's)
        onto_last = bare and last.length() > 1 and not last.blockFormat().intProperty(_GAP) \
            and part.begin().next().isValid() and QTextCursor(part.begin().next()).currentTable() is not None
        if not into_last and not onto_last:
            # (a part beginning with a table begins with an empty block: after
            # a page ending in one - after a table - it goes into that one, two
            # empty lines between the tables were the cut's)
            cursor.insertBlock()
        start = cursor.position()
        cursor.insertFragment(QTextDocumentFragment(part))
        cursor.setPosition(start)
        if onto_last:
            start += 1  # (the part: from its table on)
        elif not (into_last and rule):  # (a rule the page ended with - a heading's - stays one)
            cursor.setBlockFormat(part.begin().blockFormat())
        if listed:  # (the block put before the item out again: the item, its list kept, in its place)
            item = document.findBlock(start).next()
            cursor.setPosition(start)
            cursor.setPosition(item.position(), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
        part.deleteLater()
        if (self.browser.textCursor().anchor(), self.browser.textCursor().position()) != (anchor, position):
            _keep_reader(self.browser, anchor, position)
        return start

    def _join(self, start: int) -> None:
        """The tables a part just put in (from *start* on) brought: a big
        table's later parts joined to its first (join_tables) - as they come,
        never all at once."""
        from PyQt6.QtGui import QTextTable

        _seen, head = self._tables
        tables = [frame for frame in _tables_from(self.browser.document(), start)
                  if isinstance(frame, QTextTable) and frame.firstPosition() >= start]
        self._tables = (0, join_tables(self.browser.document(), tables, head))

    def _outline_rows(self, number: int) -> tuple[int, int]:
        """The rows of the outline (from, to) of the part *number*'s headings (the entries go in the parts' order)."""
        count = self.outline.count()
        low, high = 0, count
        while low < high:
            middle = (low + high) // 2
            if int(self.outline.item(middle).data(_PART_ROLE) or 0) < number:
                low = middle + 1
            else:
                high = middle
        first, high = low, count
        while low < high:
            middle = (low + high) // 2
            if int(self.outline.item(middle).data(_PART_ROLE) or 0) <= number:
                low = middle + 1
            else:
                high = middle
        return first, low

    def _outline_later(self, low: int, high: int) -> None:
        """The headings of the parts *low* to *high* not laid out yet in the
        outline - each standing in for its heading (a click lays its part out
        first): read from the parts' text (part_headings), on a worker."""
        queue = getattr(self, "_outline_queue", None)
        if queue is None or queue[0] != self._page_generation:
            queue = self._outline_queue = [self._page_generation, []]
        queue[1].append([low, high])
        self._outline_on()

    def _outline_on(self) -> None:
        """(_outline_later) the next of the outline's entries standing in for
        headings made - OUTLINE_BATCH an event-loop turn at most (20,000 at
        once held the window 0.14 s)."""
        queue = getattr(self, "_outline_queue", None)
        if sip.isdeleted(self) or self._page is None or queue is None or queue[0] != self._page_generation:
            return
        heads = self._page.get("heads") or []
        titles = self._page.get("titles") or {}
        made = 0
        self.outline.setUpdatesEnabled(False)
        try:
            while queue[1] and made < OUTLINE_BATCH:
                span = queue[1][0]
                row = self._outline_rows(span[0])[0]
                while span[0] < min(span[1], len(heads)) and made < OUTLINE_BATCH:
                    number = span[0]
                    span[0] += 1
                    if self._is_laid(number):
                        continue
                    for level, text, anchor in heads[number] or ():
                        self.outline.insertItem(row, _outline_item(level, titles.get(anchor) or text, -1, anchor,
                                                                   number))
                        row += 1
                        made += 1
                if span[0] >= min(span[1], len(heads)):
                    queue[1].pop(0)
        finally:
            self.outline.setUpdatesEnabled(True)
        if queue[1]:
            QTimer.singleShot(0, self._outline_on)

    def read_outline(self, notes=(), start: int = 0, end: int | None = None, number: int | None = None) -> None:
        """The outline and anchors of the page's headings from *start* on
        (0: all of it, anew) - of its part *number*, in that part's place in
        the outline (the entries standing in for them made theirs): each
        heading's anchor the name its block carries (markdown-it's: as the
        parser named it - a heading folded away in a <details> is none, the
        ones after keep theirs), else its GitHub name; a footnote's anchor
        (Qt's own parser)."""
        document = self.browser.document()
        if start == 0:
            self.outline.clear()
            self.anchors = {}
            # (the number each name goes on from: counted up from 1 past every
            # heading of that name before, 20,000 headings of one name held up
            # the window for half a minute)
            self._numbers = {}
            self._referred = {}  # (a note's places referred to, by its link: fnref-1, fnref-1-2 ...)
            block = document.begin()
        else:
            block = document.findBlock(start)
            if block.position() < start:
                block = block.next()  # (laid out with the part before)
        numbers, notes = self._numbers, set(notes)
        # (a part put in between others - a jump's gap filled: its headings in
        # the outline where they are in the page, not after the ones below them;
        # in the place of the entries that stood in for them)
        part = number if number is not None else self.part_at(start) if start else 0
        row, high = (None, None) if not start else self._outline_rows(part)
        while block.isValid() and (end is None or block.position() < end):
            level = block.blockFormat().headingLevel()
            text = block.text()
            if level:
                name = _anchor_name(block)
                titles = (self._page or {}).get("titles") or {}
                shown = titles.get(name) or text.replace("\u2028", " ").replace("\ufffc", "").strip()
                if not name or name in self.anchors:
                    key = slug(shown)
                    number, name = numbers.get(key, 1), key
                    while name in self.anchors:  # (GitHub numbers headings of the same name)
                        name, number = f"{key}-{number}", number + 1
                    numbers[key] = number
                self.anchors[name] = block.position()
                if row is None:
                    self.outline.addItem(_outline_item(level, shown, block.position(), name, part))
                elif row < high:  # (the entry that stood in for it: made its own - a click on it waits for it)
                    _outline_item(level, shown, block.position(), name, part, self.outline.item(row))
                    row += 1
                else:
                    self.outline.insertItem(row, _outline_item(level, shown, block.position(), name, part))
                    row += 1
                    high += 1
            named = block.blockFormat().stringProperty(_NAMES)
            for name in named.split() if named else ():  # (Qt's own parser: raw HTML's <a id>)
                self.anchors.setdefault(name, block.position())
            if notes:  # (a note's block: "1. The note" - it was "[1] The note")
                name = block.blockFormat().stringProperty(_NOTE)
                if name in notes:
                    self.anchors.setdefault(f"fn-{name}", block.position())
            if notes and "[" in text:  # (where a note is referred to: its ↩ leads back there - each place)
                pieces = block.begin()
                while not pieces.atEnd():
                    href = pieces.fragment().charFormat().anchorHref()
                    if href.startswith("#fn-"):
                        seen = self.__dict__.setdefault("_referred", {}).setdefault(href, set())
                        place = pieces.fragment().position()
                        if place not in seen:
                            seen.add(place)
                            count = len(seen)
                            name = "fnref-" + href[4:] + ("" if count == 1 else f"-{count}")
                            self.anchors.setdefault(name, place)
                    pieces += 1
            block = block.next()
        while row is not None and row < high:  # (more stood in than there are: read otherwise from the text)
            self.outline.takeItem(row)
            high -= 1

    def tooltip_at(self, position: int) -> str:
        """The tooltip of the page at *position* (an image chip names its
        address there), or ""."""
        last = self.browser.document().characterCount() - 1
        cursor = QTextCursor(self.browser.document())
        for place in (position, position + 1):  # (the character before it, and the one after)
            cursor.setPosition(max(0, min(place, last)))
            tip = cursor.charFormat().toolTip()
            if tip:
                return tip
        return ""

    def hint(self, text: str) -> None:
        """*text* (an image chip's address) in the status line while the
        mouse is over it; what it put there goes when it leaves."""
        if text:
            self.status.setText(printable(text))
            self._hinted = True
        elif getattr(self, "_hinted", False):
            self.status.setText("")
            self._hinted = False

    def show_text(self, text: str, anchor: str = "", scroll: int | None = None) -> None:
        """*text* rendered and shown at the heading or note *anchor* - or at
        *scroll* (another file: 0) - once it is (a long text is rendered in
        the background)."""
        self.pending = ("anchor", anchor) if anchor else ("scroll", scroll) if scroll is not None else None
        self.render(text)

    def _place(self, where: int) -> None:
        """The page just shown scrolled to what :meth:`show_text` asked for,
        else to *where* it was."""
        pending, self.pending = self.pending, None
        if pending and pending[0] == "anchor" and self.go_to_anchor(pending[1], remember=False):
            return
        bar = self.browser.verticalScrollBar()
        bar.setValue(pending[1] if pending and pending[0] == "scroll" else where)

    def show_source_line(self, text: str, line: int, tries: int = 3) -> None:
        """The place of line *line* (0-based) of *text* - the Markdown shown - in view, a third down
        (the editor's preview follows the typing). The part it is in - by where the line stands in the
        text - laid out first (it is not, far down a long text: the preview stayed where it was), then
        the line's own words found there, the one nearest its place; none found (a blank line, marks
        only): its place in proportion."""
        page = self._page
        if page is None or not self._readable or not text:
            return
        rows = text.split("\n")
        line = max(0, min(line, len(rows) - 1))
        share = (sum(len(row) + 1 for row in rows[:line]) + len(rows[line]) / 2) / max(1, len(text))
        sizes = [_size(page, number) for number in range(self._part_count())]
        goal, at, number = share * max(1, sum(sizes)), 0, 0
        for number, size in enumerate(sizes):
            if at + size >= goal:
                break
            at += size
        within = (goal - at) / max(1, sizes[number]) if sizes else 0.0
        needle = _words_of_line(rows, line)
        if tries and (isinstance(page["parts"][number], _Unparsed) or not self._is_laid(number)):
            # (a piece not parsed yet: parsed, its parts numbered in - then asked again, the part known)
            generation = page["generation"]
            self.go_to_part(number, lambda: self._page is not None and self._page["generation"] == generation
                            and self.show_source_line(text, line, tries - 1))
            return
        self._show_line_in(number, needle, within)

    def _show_line_in(self, number: int, needle: str, within: float) -> None:
        """(show_source_line) *needle* - a line's words - found in the page near *within* of its laid-out
        part *number*, a third down the view."""
        document = self.browser.document()
        start = self._starts[number].position() if number in self._starts else 0
        later = [cursor.position() for other, cursor in self._starts.items() if other > number]
        end = min(later) if later else document.characterCount() - 1
        estimate = start + int(within * max(0, end - start))
        best = None
        if needle:
            low, high = max(0, start - 2000), end + 2000
            found, seen = document.find(needle, low), 0
            while not found.isNull() and found.selectionStart() <= high and seen < 200:
                if best is None or abs(found.selectionStart() - estimate) < abs(best - estimate):
                    best = found.selectionStart()
                found, seen = document.find(needle, found.selectionEnd()), seen + 1
        position = estimate if best is None else best
        block = document.findBlock(min(max(0, position), document.characterCount() - 1))
        top = document.documentLayout().blockBoundingRect(block).top()
        self.browser.verticalScrollBar().setValue(int(top - self.browser.viewport().height() / 3))

    def go_to_anchor(self, name: str, remember: bool = True) -> bool:
        """Scroll to the heading or note *name* of this text (its GitHub
        anchor); False when there is none."""
        position = self.anchors.get(name)
        if position is None:
            position = self.anchors.get(slug(name))
        if position is None and self.more() and name in self.names:
            position = self._named_position(name)  # (a note's, laid out)
        if position is not None:
            self.scroll_to(position, remember=remember)
            return True
        if not self.more() and self.unfold_for(anchor=name, then=lambda: self.go_to_anchor(name, remember)):
            return True  # (a heading in a folded <details>: it opened, as in a browser)
        if self.more() and (name in self.names or slug(name) in self.names or not self.full
                            or len(self.names) >= ANCHORS or (self._page or {}).get("loading")):
            # (a part of the page not laid out yet: the one it is in laid out
            # first, then there - not knowing which, all of it; a heading past
            # the page's ANCHORS named ones too: it has no name)
            def there():
                if not self.go_to_anchor(name, remember) and not self.more():
                    self.status.setText(_t("No heading {anchor} here.", anchor=printable("#" + name)))

            number = self._part_with_anchor(name)
            if number is not None:
                self.go_to_part(number, there)
            else:
                self.load_rest(lambda: self.go_to_anchor(name, remember) or self.status.setText(
                    _t("No heading {anchor} here.", anchor=printable("#" + name))))
            return True
        if name in self.names:  # (a footnote and its way back)
            if remember:
                self.remember()
            self.browser.scrollToAnchor(name)
            return True
        return False

    def text_width(self) -> int:
        """The widest the text is set: about 80 characters of prose (as a
        book's, GitHub's) - wider lines read badly (more room goes to the
        margins)."""
        # (of the letters before zoom: a zoom step is one relayout - its width
        # changed with it, two, 0.69 s on a page of formulas)
        if not hasattr(self, "_char_width"):
            self._char_width = self.browser.fontMetrics().averageCharWidth()
        return max(320, self._char_width * 80)

    def clamp_images(self) -> None:
        """Every image at most as wide as its place: the text's width, or in
        a table its share of it (the text's width over the table's columns -
        as GitHub; a screenshot in a cell took all of it and squeezed its
        neighbour to a letter a line) - in proportion. An image raw HTML
        asked to be wider than that likewise (``<img width="2000">``), and
        either is as wide as it is (or was asked) again when there is room.
        A walk over the page's pieces - only when the page has images."""
        if not self.page_images:
            return
        room = self.room()
        document = self.browser.document()
        changes, cursor = [], QTextCursor(document)
        # (each image's character found by Qt, not each piece of the page
        # walked in Python: 0.1 s a time on a long page, at every part - and
        # of the parts laid out since the last time only, unless the room changed)
        since = self._unclamped if getattr(self, "_clamped_room", None) == room else 0
        self._clamped_room, self._unclamped = room, document.characterCount()
        found, seen = document.find("\ufffc", since), 0
        while not found.isNull():
            seen += 1
            if seen > CLAMPED_AT_ONCE:  # (the rest in the next turn: 14,000 images were 0.3 s in one)
                self._unclamped = found.selectionStart()
                QTimer.singleShot(0, self.clamp_images)
                break
            piece = _Piece(found.selectionStart(), found.charFormat())
            found = document.find("\ufffc", piece.position() + 1)
            fmt = piece.charFormat()
            if fmt.isImageFormat():
                image = fmt.toImageFormat()
                if image.hasProperty(_ASKED_WIDTH):  # (what it was asked to be, before we changed it)
                    asked_w, asked_h = image.doubleProperty(_ASKED_WIDTH), image.doubleProperty(_ASKED_HEIGHT)
                else:
                    asked_w, asked_h = image.width(), image.height()
                natural = self.originals.get(image.name()) or self.images.get(image.name())
                if image.name() not in self.originals and natural is not None:
                    # (a placeholder - not found, being read: its own size, its words
                    # readable; "Image not sho…x" in the 64 pixels asked of the image)
                    want_w, want_h = natural.width(), natural.height()
                else:
                    want_w = asked_w or (natural.width() if natural is not None else 0)
                    want_h = asked_h or (want_w * natural.height() / max(1, natural.width())
                                         if natural is not None else 0)
                if want_w > 0:
                    cursor.setPosition(piece.position())
                    table = cursor.currentTable()
                    limit = room if table is None else max(48, room // table.columns() - 16)
                    width = min(want_w, limit)
                    if abs(width - (image.width() or want_w)) > 0.5 or (width < want_w and not image.width()):
                        changes.append((piece.position(), piece.length(), image, asked_w, asked_h,
                                        width, want_w, want_h))
        if not changes:
            return
        cursor.beginEditBlock()
        for position, length, image, asked_w, asked_h, width, want_w, want_h in changes:
            image.setProperty(_ASKED_WIDTH, float(asked_w))
            image.setProperty(_ASKED_HEIGHT, float(asked_h))
            image.setWidth(width)
            if want_h > 0:
                image.setHeight(want_h * width / want_w)
            cursor.setPosition(position)
            cursor.setPosition(position + length, QTextCursor.MoveMode.KeepAnchor)
            cursor.setCharFormat(image)
        cursor.endEditBlock()

    def fit_text(self, width: int | None = None) -> None:
        """The page's width and side margins (*width*: the view's, else as it
        is): the text at most :meth:`text_width`
        wide, in the middle of a wider view, and never closer than GUTTER
        to its edges. Margins of the view (viewport margins), not of the
        page: they outlive a new page, and changing them is a change of
        width Qt lays the page out for as it is shown (a margin of the page's
        root frame laid all of it out at once - 0.3 s for a big table)."""
        browser = self.browser
        left, _top, right, _bottom = browser.margins()
        room = width if width is not None else browser.viewport().width() + left + right
        wrap = max(160, min(self.text_width(), room - 2 * GUTTER))
        side = max(GUTTER, (room - wrap) // 2)
        # (what _trim took from the right margin for this width kept: set
        # even again, the table overflowed, was trimmed, set even - 65 <-> 64
        # pixels forever, the page laid out each time, a fifth of a CPU idle)
        trimmed = self._trimmed[1] if getattr(self, "_trimmed", None) and self._trimmed[0] == (room, wrap) else 0
        self._margins(side, room - wrap - side - trimmed)
        if browser.lineWrapColumnOrWidth() != wrap:  # (only then is the page laid out anew)
            # (the block on the view's top kept there: it drifted a paragraph or two)
            anchor = self._view_anchor() if self._page is not None and self._readable else None
            browser.setLineWrapColumnOrWidth(wrap)
            if anchor is not None:
                self._hold(anchor)

    def _trim(self, _low: int, high: int) -> None:
        """The page is wider than the view by *high* pixels: a table whose
        cells cannot be narrower goes past the text - what the right margin
        can take is taken from it (a wide window scrolled sideways by one
        pixel). Wider than that, all of it but GUTTER, and the view scrolls. (From the scroll bar, which
        follows the layout: asking the document its width lays out all of
        it at once.)"""
        left, _top, right, _bottom = self.browser.margins()
        widened = bool(self.browser.document().property(_WIDENED))  # (a table made wider than the text)
        if 0 < high and right > GUTTER and (widened or high <= right - 4):
            room = self.browser.viewport().width() + left + right
            wrap = self.browser.lineWrapColumnOrWidth()
            even = room - wrap - max(GUTTER, (room - wrap) // 2)
            # (wider than the margin: all of it but GUTTER - the rest scrolls; a wide table was cut at the
            # text's right edge, 420 pixels of a 1,700-pixel window left empty beside it)
            kept = max(GUTTER, right - high)
            self._trimmed = ((room, wrap), even - kept)  # (fit_text keeps it while the width is the same)
            self._margins(left, kept)

    def _margins(self, left: int, right: int) -> None:
        if self.browser.margins()[::2] != (left, right):
            self.browser.set_margins(left, right)

    def code_block_at(self, position: int) -> str:
        """The text of the code block at *position* in the page, or "" - as
        written in the file where Qt's own parser changed it (its tabs)."""
        document = self.browser.document()
        block = document.findBlock(position)
        if not _is_code(block):
            return ""
        anchor = block  # (a line of it: what the others are compared with - across a cut's blocks, the
        # piece beyond them: a part going on in a list item is indented as Qt places it)
        while block.previous().isValid():
            if _same_code(block.previous(), anchor):
                block = block.previous()
            elif _going_between(block.previous(), anchor):
                beyond = block.previous()
                while beyond.isValid() and _is_seam(beyond):
                    beyond = beyond.previous()
                if not beyond.isValid() or not _is_code(beyond):
                    break
                block = anchor = beyond
            else:
                break
        while not _is_code(block):  # (begun at a cut's block: from the first line)
            block = block.next()
        start, lines, anchor = block, [], block
        while block.isValid():
            if _same_code(block, anchor):
                lines.append(block.text())
            elif _going_between(block, anchor):
                beyond = block
                while beyond.isValid() and _is_seam(beyond):
                    beyond = beyond.next()
                if not beyond.isValid() or not _is_code(beyond):
                    break
                block = anchor = beyond
                continue
            else:
                break
            block = block.next()
        while lines and not lines[-1]:
            lines.pop()  # (the empty line Qt keeps after a <pre>)
        shown = "\n".join(lines).replace("\u2028", "\n") + "\n"
        if not self.full and self.code_sources:
            # (the how-manyth code block of the page: the file's one of that place -
            # those of the parts before its part counted in their text, a jump's
            # gaps not laid out)
            number, earlier = 0, document.begin()
            if self._gaps:
                part = self.part_at(start.position())
                counts = self._page.setdefault("code_counts", {})
                for earlier_part in range(part):
                    if earlier_part not in counts:
                        # (a part going on with the code block before it: that one not counted again)
                        counts[earlier_part] = sum(1 for code, _text in _segments(self._page["parts"][earlier_part])
                                                   if code) - (earlier_part in self._page.get("continued", ()))
                    number += counts[earlier_part]
                cursor = self._starts.get(part)
                earlier = cursor.block() if cursor is not None else document.begin()
            while earlier.isValid() and earlier != start:
                if _is_code(earlier) and not _same_code(earlier.previous(), earlier):
                    number += 1
                earlier = earlier.next()
            if number < len(self.code_sources):
                source = self.code_sources[number]
                if source.expandtabs(4) == shown.expandtabs(4) or source.replace("\t", "    ") == shown:
                    return source
        return shown

    def headings(self) -> list[str]:
        """The outline's entries (for tests and the window)."""
        return [self.outline.item(i).text().strip() for i in range(self.outline.count())]

    def scroll_to(self, position: int, remember: bool = True) -> None:
        """Show the block at *position* at the top; *remember*: Back
        returns to where the view was."""
        bar = self.browser.verticalScrollBar()
        if remember:
            self.remember()
        block = self.browser.document().findBlock(position)
        rect = self.browser.document().documentLayout().blockBoundingRect(block)
        top = max(0, int(rect.top()) - ANCHOR_ROOM)  # (a little room above it: flush at the view's edge before)
        bar.setValue(top)
        self.browser.setTextCursor(QTextCursor(block))
        bar.setValue(top)  # (setting the cursor may have scrolled it into view only)
        if bar.value() != top or self.more():  # (the page below it still to come: held there)
            self._hold((QTextCursor(block), -float(int(rect.top()) - top)))

    def remember(self) -> None:
        """Where the view is goes on the Back list (a jump is made)."""
        if self.navigator is not None:
            self.navigator.remember()
            return
        where = self.browser.verticalScrollBar().value()
        if not self.back_stack or self.back_stack[-1] != where:
            self.back_stack.append(where)
            del self.back_stack[:-100]
        self.forward_stack.clear()

    def back(self) -> bool:
        """Back to where the view was before the last jump (Alt+Left)."""
        if self.navigator is not None:
            return self.navigator.back()
        return self._go(self.back_stack, self.forward_stack)

    def forward(self) -> bool:
        """Forward again after Back (Alt+Right)."""
        if self.navigator is not None:
            return self.navigator.forward()
        return self._go(self.forward_stack, self.back_stack)

    def _go(self, source: list[int], other: list[int]) -> bool:
        if not source:
            return False
        bar = self.browser.verticalScrollBar()
        other.append(bar.value())
        bar.setValue(source.pop())
        return True

    def jump(self, item) -> None:
        """(an outline entry clicked) to its heading - its part laid out first if it is not."""
        position = int(item.data(Qt.ItemDataRole.UserRole))
        if position >= 0:
            self.scroll_to(position)
            return
        self.remember()
        number = int(item.data(_PART_ROLE) or 0)

        def there():
            if sip.isdeleted(item):
                return
            laid = int(item.data(Qt.ItemDataRole.UserRole))
            if laid >= 0:
                self.scroll_to(laid, remember=False)
            else:  # (it was read otherwise from its text: its part)
                self._show_part(int(item.data(_PART_ROLE) or 0))

        self.go_to_part(number, there)

    def heading_link(self, item) -> str:
        """The link to the heading of the outline entry *item*, as GitHub
        links it: ``README.md#install`` (``#install`` without a file name)."""
        anchor = str(item.data(_ANCHOR_ROLE) or "")
        return f"{self.page_name}#{anchor}" if anchor else ""

    def _outline_menu(self, point) -> None:
        item = self.outline.itemAt(point)
        link = self.heading_link(item) if item is not None else ""
        if not link:
            return
        from PyQt6.QtWidgets import QApplication, QMenu

        menu = QMenu(self.outline)
        menu.addAction(tr("Copy Link to Heading"), lambda: QApplication.clipboard().setText(link))
        menu.exec(self.outline.viewport().mapToGlobal(point))
        menu.deleteLater()

    def _render_again(self) -> None:
        """(the render timer) the text rendered anew - a theme chosen, a pause in the typing."""
        if not sip.isdeleted(self):
            self.render(self.markdown)

    def _follow_soon(self, _value: int = 0) -> None:
        """(the page scrolled) the outline marks the heading being read soon."""
        if not sip.isdeleted(self.follow_timer):
            self.follow_timer.start()

    def mark_heading(self) -> None:
        """The heading of the part on top of the view, marked in the outline
        (its signals off: marking it jumps nowhere)."""
        if not self.outline.count() or not self.outline.isVisible():
            return
        top = self.browser.cursorForPosition(QPoint(4, 4)).position()
        here = (self.part_at(top), top)
        current = -1
        low, high = 0, self.outline.count()  # (the entries go down the text - by part: a halving search)
        while low < high:
            middle = (low + high) // 2
            item = self.outline.item(middle)
            if (int(item.data(_PART_ROLE) or 0), int(item.data(Qt.ItemDataRole.UserRole))) <= here:
                current, low = middle, middle + 1
            else:
                high = middle
        if self.browser.verticalScrollBar().value() == 0:
            current = -1 if current < 0 else current
        if current == self.outline.currentRow():
            return
        self.outline.blockSignals(True)
        try:
            if current < 0:
                self.outline.setCurrentRow(-1)
                self.outline.clearSelection()
            else:
                self.outline.setCurrentRow(current)
                self.outline.scrollToItem(self.outline.item(current))
        finally:
            self.outline.blockSignals(False)

    def changeEvent(self, event):  # noqa: N802 - Qt
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and self.markdown \
                and _is_dark(self.palette()) != self.dark:
            # (a theme chosen since: the page's colours and the code's are made anew)
            self.dark = _is_dark(self.palette())
            self._repaint_placeholders()
            self.timer.start()

    # -- links --

    def hovered(self, url) -> None:
        # (a host as it is - punycode, percent-encoded: decoded, a look-alike
        # "pаypal.com" with a Cyrillic а read as the real one)
        text = (url.toString(QUrl.ComponentFormattingOption.FullyEncoded) if url.host() else url.toString()) \
            if isinstance(url, QUrl) else str(url or "")
        if isinstance(url, QUrl) and url.scheme().lower() == "mailto" and "@" in url.path():
            text = mail_address(url).toString()  # (its domain in punycode too: "me@pаypal.com" read as the real one)
        if text.startswith("#" + FOLD):
            self.status.setText(tr("A click shows or hides what it holds"))
            return
        self.status.setText(_t("Link: {target}", target=printable(text)) if text else "")

    def link_cursor(self, position: int) -> QTextCursor:
        cursor = QTextCursor(self.browser.document())
        cursor.setPosition(max(0, min(position, self.browser.document().characterCount() - 1)))
        return cursor

    def link_text_at(self, position: int, href: str) -> str:
        """The text of the link to *href* at *position* of the page (all of
        its pieces in its line), or ""."""
        block = self.browser.document().findBlock(position)
        parts, inside, found = [], False, False
        pieces = block.begin()
        while not pieces.atEnd():
            piece = pieces.fragment()
            fmt = piece.charFormat()
            ours = fmt.isAnchor() and fmt.anchorHref() == href
            if ours:
                parts.append(piece.text())
                inside = inside or piece.position() <= position <= piece.position() + piece.length()
            elif parts:
                if inside:
                    found = True
                    break
                parts = []
            pieces += 1
        return "".join(parts).replace("\ufffc", "").strip() if (found or inside) else ""

    def clicked(self, url: QUrl) -> None:
        """A link clicked: "#anchor" of this text scrolls there; anything
        else goes to the window (:attr:`link`) - its text in
        :attr:`last_link_text` (the question names it when it differs)."""
        pressed = getattr(self.browser, "pressed_at", None)
        position = (self.browser.cursorForPosition(pressed).position() if pressed is not None
                    else self.browser.textCursor().position())
        self.browser.pressed_at = None
        self.last_link_text = self.link_text_at(position, url.toString()) \
            or self.link_text_at(max(0, position - 1), url.toString())
        if not url.scheme() and not url.path() and url.hasFragment():
            fold = url.fragment().removeprefix(FOLD)
            if fold != url.fragment() and fold.isdigit():
                # (a folded <details>' summary: open or fold it, where the page is)
                self.folds ^= {int(fold)}
                self.render(self.markdown)
                return
            if not self.go_to_anchor(url.fragment()):
                self.status.setText(_t("No heading {anchor} here.",
                                       anchor=printable("#" + url.fragment())))
            elif self.status.text().startswith(_t("No heading {anchor} here.", anchor="").split(" ")[0]):
                self.status.setText("")  # (an earlier jump's error: this one went there)
            return
        self.link.emit(url)

    # -- images --

    def image(self, name: str) -> QImage:
        """What the browser shows for the image *name*: read already, a
        placeholder, or (read in a moment) one that says it is being read."""
        found = self.images.get(name)
        if found is not None:
            return found
        kind, where = self.source.kind(name) if self.source is not None else ("outside", name)
        if kind in ("local", "data") and (name in self.asked or len(self.asked) < IMAGES):
            self.asked.add(name)  # (read by read_missing)
            # (Qt lays out an image whose size is given without asking for it,
            # and asks when painting - after the rendering read what was asked)
            self.read_timer.start()
            return placeholder(_t("Reading {name}…", name=printable(name)), self.palette())
        if len(self.images) >= 2 * IMAGES:
            # (each name kept a picture of its own: a file naming 100,000
            # images took gigabytes; beyond these, one picture shared by all)
            if self.too_many is None:
                self.too_many = placeholder(_t("Not shown (more than {count} images)",
                                               count=2 * IMAGES), self.palette())
            return self.too_many
        if kind == "remote":
            found = self._placeholder(name, _t("Remote image, not loaded: {url}", url=printable(where)))
        elif kind == "outside":
            found = self._placeholder(name, _t("Not shown (not beside the file): {name}", name=printable(where)))
        else:
            found = self._placeholder(name, _t("Not shown (more than {count} images): {name}", count=IMAGES,
                                               name=printable(name)))
        self.images[name] = found
        return found

    def _placeholder(self, name: str, text: str) -> QImage:
        """A box saying why the image *name* is not shown, in the view's colours - its text kept: a theme
        chosen later paints it again (it kept the old theme's colours - _repaint_placeholders)."""
        if not hasattr(self, "_placeholder_texts"):
            self._placeholder_texts = {}
        self._placeholder_texts[name] = text
        return placeholder(text, self.palette())

    def _repaint_placeholders(self) -> None:
        """Each image box of the page painted again in the view's colours (a theme chosen since)."""
        self.too_many = None
        texts = getattr(self, "_placeholder_texts", {})
        document = self.browser.document()
        for name, text in texts.items():
            if name in self.images:
                self.images[name] = placeholder(text, self.palette())
                document.addResource(QTextDocument.ResourceType.ImageResource.value, QUrl(name), self.images[name])
        if texts:
            document.markContentsDirty(0, document.characterCount())

    def room(self) -> int:
        """The widest an image is shown: the text's width (the view's, at most
        :meth:`text_width`)."""
        return max(160, min(self.browser.viewport().width(), self.browser.lineWrapColumnOrWidth()) - 32)

    def _fitted(self, image: QImage) -> QImage:
        """*image* as shown: at most :meth:`room` wide."""
        room = self.room()
        self.fitted_to = room
        if image.width() > room:  # (wider than the view: shown at its width)
            return image.scaledToWidth(room, Qt.TransformationMode.SmoothTransformation)
        return image

    def shown_width(self, name: str) -> int:
        found = self.images.get(name)
        return found.width() if isinstance(found, QImage) else 0

    def fit_later(self) -> None:
        """The view's width changed: the text's margins and its images are
        fitted anew in a moment."""
        self.fit_timer.start()

    def fit_images(self) -> None:
        """Every image fitted to the view's width as it is now (shown wider
        than the view after it was made narrower, smaller than its own size
        after it was made wider). The page is laid out again, not parsed."""
        self.fit_text()
        self.clamp_images()
        room = self.room()
        if room == self.fitted_to or not self.originals:
            return
        changed = False
        document = self.browser.document()
        for name, original in self.originals.items():
            fitted = self._fitted(original)
            if self.images.get(name) is not fitted and (
                    fitted.width() != self.shown_width(name)):
                self.images[name] = fitted
                document.addResource(QTextDocument.ResourceType.ImageResource.value, QUrl(name), fitted)
                changed = True
        self.fitted_to = room
        if changed:
            document.markContentsDirty(0, document.characterCount())

    def zoom_image(self, name: str) -> ImageZoom | None:
        """The image *name* at its own size, in a window of its own (a
        click on it)."""
        original = self.originals.get(name)
        if original is None:
            return None
        zoom = ImageZoom(original, printable(name), self)
        zoom.show()
        return zoom

    def print_document(self) -> QTextDocument:
        """A copy of the page to print or to save as PDF: always in the light
        colours (paper is white), its images those the view read - it loads
        nothing itself either (:class:`_PageCopy`). Qt's own parser's page is
        laid out whole first (load_rest_now)."""
        if not self.full:
            self.load_rest_now()
        copy = _PageCopy(self.browser)
        if self.full and self.markdown:
            from core import markdown_doc
            from ui.markdown_html import style_sheet, to_html

            text = markdown_doc.clean(renderable(self.markdown.replace("\r\n", "\n").replace("\r", "\n"))[0])
            copy.setDefaultStyleSheet(style_sheet(False))
            copy.setHtml(to_html(markdown_doc.parse(text), dark=False))
        else:
            copy.setHtml(self.browser.document().toHtml())
        copy.setDefaultFont(self.browser.document().defaultFont())
        return copy

    def forget_images(self) -> None:
        """Read every image again at the next rendering (Reload: an image
        changed on disk kept its old picture)."""
        self.originals = {}
        self.images, self.asked, self.too_many = {}, set(), None
        self.generation += 1
        if self.source is not None:
            self.source.forget()
        self.clear_pictures = True  # (at the next rendering: see render)

    def read_missing(self) -> None:
        """Read (in a thread) the images asked for that are not read yet;
        render again once they are."""
        missing = [name for name in self.asked if name not in self.images]
        if not missing or self.source is None:
            return
        for name in missing:
            self.images[name] = placeholder(_t("Reading {name}…", name=printable(name)), self.palette())
        generation = self.generation
        self.source.read_later(missing, owner=self, done=lambda result, error: self.images_read(
            missing, result, error, generation))

    def images_read(self, names, result, error, generation=None) -> None:
        if generation is not None and generation != self.generation:
            return  # (read before a Reload: the next rendering reads them again)
        for name in names:
            found = (result or {}).get(name) if error is None else printable(error)
            if isinstance(found, QImage):
                self.originals[name] = found
                self.images[name] = self._fitted(found)
            else:
                self.images[name] = self._placeholder(name, _t("Image not shown: {name} ({why})",
                                                               name=printable(name),
                                                               why=printable(found or tr("not found"))))
        # In place on the page, laid out again - not rendered anew (a big page
        # is rendered in parts: it went short and long again for each image read).
        document = self.browser.document()
        for name in names:
            document.addResource(QTextDocument.ResourceType.ImageResource.value, QUrl(name), self.images[name])
        document.markContentsDirty(0, document.characterCount())
        self._clamped_room = None  # (their sizes known now: every image fitted again)
        self.clamp_images()

    # -- zoom --

    def zoom_by(self, steps: int) -> None:
        """*steps* larger (negative: smaller); 0: as it was - the block on
        the view's top kept there (it drifted a paragraph or two; with gaps
        the view swung on through the page, 165 parts laid out). A page of
        more than ZOOM_BLOCKS blocks laid out is laid out anew, a part a turn
        from the place read (render's *again*): Qt laid all of it out again
        in the turn that next needed a place past the view - a table of 20,000
        rows read to its end, 0.65 to 1.6 s at the next scroll or Find."""
        if self._page is not None and self._readable and self.markdown \
                and self.browser.document().blockCount() > ZOOM_BLOCKS and getattr(self, "_made", None):
            self.render(self.markdown, again=lambda: self._zoomed(steps))
            return
        anchor = self._view_anchor() if self._page is not None and self._readable else None
        size = self.browser.document().defaultFont().pointSizeF()
        self._zoomed(steps)
        if anchor is not None:
            ratio = self.browser.document().defaultFont().pointSizeF() / max(1.0, size)
            self._scale_stand_ins(ratio)
            self._hold((anchor[0], anchor[1] * ratio))

    def _scale_stand_ins(self, ratio: float) -> None:
        """Every gap's stand-in (and the end's) *ratio* times as high: the
        text it stands for grew (or shrank) with the letters."""
        if abs(ratio - 1) < 0.001:
            return
        document = self.browser.document()
        blocks = [self._gap_block(gap) for gap in self._gaps]
        if self._stand_in and document.lastBlock().blockFormat().boolProperty(_STAND_IN):
            blocks.append(document.lastBlock())
        cursor = QTextCursor(document)
        for block in blocks:
            if block is None:
                continue
            fmt = block.blockFormat()
            fmt.setLineHeight(max(1.0, min(fmt.lineHeight() * ratio, STAND_IN_PIXELS)), 2)
            cursor.setPosition(block.position())
            cursor.setBlockFormat(fmt)

    def _zoomed(self, steps: int) -> None:
        if self.zoom == 0:  # (its own size: what the level is counted from)
            self._own_font_points = self.browser.font().pointSizeF()
        if steps == 0:
            self._font_points(self._own_font_points)
            self.zoom = 0
            self.fit_text()
            self.zoom_changed.emit(100)
            return
        # (between ZOOM_RANGE of its own size, those reached exactly - a point a step: zoomed out it reached
        # 2 %, Qt warned of a font's size; then it stopped at 27 %, short of the bound)
        own = self._own_font_points or self.browser.font().pointSizeF()
        now = self.browser.font().pointSizeF()
        low, high = ZOOM_RANGE
        target = min(own * high, max(own * low, own + round(now + steps - own)))  # (on its own size's grid)
        if abs(target - now) < 0.001:
            return
        self._font_points(target)
        self.zoom = 0 if abs(target - own) < 0.001 else (round(target - own) or (1 if target > own else -1))
        self.fit_text()  # (the text's width follows its letters' size)
        self.zoom_changed.emit(self.zoom_percent())

    def _font_points(self, points: float) -> None:
        """The view's letters *points* large (as QTextEdit.zoomIn sets them: the widget's font)."""
        font = self.browser.font()
        font.setPointSizeF(points)
        self.browser.setFont(font)

    def zoom_percent(self) -> int:
        """The text's size in per cent of its own (100 when not zoomed)."""
        own = getattr(self, "_own_font_points", 0.0)
        if not self.zoom or own <= 0:
            return 100
        return max(1, round(100 * self.browser.font().pointSizeF() / own))


#: How small and how large the text may be zoomed, against its own size.
ZOOM_RANGE = (0.25, 4.0)
#: Blocks laid out past which a zoom lays the page out anew a part a turn (zoom_by).
ZOOM_BLOCKS = 3000


def _fresh(made):
    """*made* (a page render made: nested tuples and lists) with lists of its own - a page laid out again
    from it changes nothing of the one kept (MarkdownView._made)."""
    if type(made) is tuple:  # (exactly: a subclass - the notes' NoteLabels - kept as it is, its places with it)
        return tuple(_fresh(item) for item in made)
    if type(made) is list:
        return [_fresh(item) if type(item) in (tuple, list) else item for item in made]
    return made
#: Image characters clamp_images looks at in one event-loop turn (the rest in the next).
CLAMPED_AT_ONCE = 2000


#: Where clamp_images keeps the size an image was asked to have (0: its own).
_ASKED_WIDTH = QTextFormat.Property.UserProperty.value + 1
_ASKED_HEIGHT = QTextFormat.Property.UserProperty.value + 2
#: (Qt's own parser) the line of a code block's language over it (_label_code)
_CODE_LABEL = QTextFormat.Property.UserProperty.value + 3
#: the block standing in for the parts of a page not laid out yet (_stand_in_put)
_STAND_IN = QTextFormat.Property.UserProperty.value + 4
#: (Qt's own parser) a definition list's term (apply_marks)
_TERM = QTextFormat.Property.UserProperty.value + 5
#: the block standing in for parts a jump skipped (a gap: MarkdownView._jump) - its number
_GAP = QTextFormat.Property.UserProperty.value + 6
#: How far a footnote's lines stand in (pixels), and its number out to the left of them.
NOTE_INDENT, NOTE_NUMBER = 40, 19
#: The number of the footnote a block is (Qt's own parser's page): its anchor "fn-<number>".
_NOTE = QTextFormat.Property.UserProperty.value + 7
#: A formula's TeX ("axross-itex:…", "axross-tex:…" - ui.markdown_html's
#: TEX_INLINE, TEX_ANCHOR) on its first letter: a string, not an anchor's
#: name - Qt files every format with names under one key, each one more a
#: page's formats all compared again (8,000 formulas: 0.2 s more for each
#: part of the page put in, 22 s in all).
_TEX = QTextFormat.Property.UserProperty.value + 8
#: (Qt's own parser) the names of raw HTML's anchors in a block (<a id="here">), space between.
_NAMES = QTextFormat.Property.UserProperty.value + 9
#: A named letter's names as one string (_tex_names): its format hashed apart from every other one's.
_NAMED = QTextFormat.Property.UserProperty.value + 11
#: A block of no height a part going on inside an item begins with (_going_on): no text of the page.
_GOING = QTextFormat.Property.UserProperty.value + 10
#: The most pixels an image is zoomed to (ImageZoom): 8 times a photo of
#: 40 million pixels was a picture of gigabytes.
ZOOM_PIXELS = 64_000_000


#: Where an outline entry keeps its heading's anchor.
_ANCHOR_ROLE = Qt.ItemDataRole.UserRole.value + 1
#: Entries standing in for headings not laid out yet made an event-loop turn at most.
OUTLINE_BATCH = 2000
#: The part of the page an outline entry's heading is in (its position -1: not laid out yet).
_PART_ROLE = Qt.ItemDataRole.UserRole.value + 2


def _percent(done: int, count: int) -> str:
    """*done* of *count* as a percentage in the language of the window."""
    from core.i18n import format_percent

    return format_percent(100 * done // max(1, count))


def _anchor_name(block) -> str:
    """The anchor a heading's block carries (markdown-it's page: the name
    its parser gave it, on its first letter), or ""."""
    pieces = block.begin()
    if pieces.atEnd():
        return ""
    names = pieces.fragment().charFormat().anchorNames()
    return names[0] if names else ""


_LINE_MARKS = re.compile(r"^(?:[ \t]{0,3}>[ \t]?|[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]+(?:\[[ xX]\][ \t]+)?|[ \t]+)*+"
                         r"(?:#{1,6}[ \t]+)?")
_INLINE_MARKS = re.compile(r"!?\[([^\[\]]*)\]\([^()]*\)|[*_`~]+|<[^<>]*>|\\(?=\S)")


def _words_of_line(rows: list[str], line: int) -> str:
    """Words of the Markdown line *line* as the page shows them - its marks left out, the longest piece
    of a table row, at most 40 characters - or of the nearest line with some ("" none near)."""
    for distance in range(0, 6):
        for number in (line - distance, line + distance) if distance else (line,):
            if not 0 <= number < len(rows):
                continue
            row = _LINE_MARKS.sub("", rows[number], count=1)
            row = _INLINE_MARKS.sub(lambda match: match.group(1) or "", row)
            pieces = [piece.strip() for piece in row.split("|")] if "|" in row else [row.strip()]
            words = max(pieces, key=len)
            words = words[:40].rsplit(" ", 1)[0] if len(words) > 40 else words
            if sum(ch.isalnum() for ch in words) >= 4:
                return words
    return ""


_ATX_LINE = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
_SETEXT_LINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*\Z")


def _heading_lines(rows: list[str]) -> list[int]:
    """The lines (0-based) the headings of the Markdown *rows* begin at -
    ATX ("# ...") and setext ("Title" over "===") ones, none in code."""
    heads, fence, before = [], None, ""
    for number, row in enumerate(rows):
        opened = FENCE.match(row)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            before = ""
            continue
        if opened:
            fence, before = opened.group(1), ""
            continue
        if _ATX_LINE.match(row):
            heads.append(number)
            before = ""
            continue
        if before.strip() and _SETEXT_LINE.match(row) and not LIST_ITEM.match(before) \
                and before[:1] not in " \t>" and (number < 2 or not rows[number - 2].strip()
                                                   or _ATX_LINE.match(rows[number - 2])):
            heads.append(number - 1)
            before = ""
            continue
        before = row
    return heads


def _outline_item(level: int, text: str, position: int, anchor: str = "", part: int = 0,
                  item: QListWidgetItem | None = None) -> QListWidgetItem:
    """An entry of the outline: indented by its level, named whole in its
    tooltip (the outline cuts a long one), its heading's anchor and part
    kept (*position* -1: a part not laid out yet). *item*: an entry made so
    (one standing in for its heading) - made the heading's."""
    # (two spaces a level, four levels at most: a sixth-level heading stood
    # twenty spaces in, cut to "Heading…" in the outline's width)
    item = item if item is not None else QListWidgetItem()
    item.setText("  " * min(level - 1, 4) + text)
    item.setToolTip(text)
    item.setData(Qt.ItemDataRole.UserRole, position)
    item.setData(_ANCHOR_ROLE, anchor)
    item.setData(_PART_ROLE, part)
    return item


_HTML_HEADING = re.compile(r"<h([1-6])\b[^>]*>(.*?)</h\1>", re.DOTALL | re.IGNORECASE)
_ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*\Z")
_SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*\Z")
_LINK_TEXT = re.compile(r"!?\[([^\[\]]*)\]\([^()]*\)")
_HEAD_MARKS = re.compile(r"[`*]|(?<!\w)_|_(?!\w)|\ufffc")


def _shown_heading(text: str) -> str:
    return _HEAD_MARKS.sub("", _LINK_TEXT.sub(r"\1", _PRIVATE.sub("", text))).strip()


def part_headings(kind: str, part) -> list:
    """(level, text, anchor) of each heading of a part of the page - read
    from its HTML (markdown-it's) or its text (Qt's own parser's): the
    outline lists the headings of the parts not laid out yet too (it listed
    27 of 201 after a jump). Pure Python: on a worker thread."""
    import html as html_module

    if not isinstance(part, str):
        return []
    heads = []
    if kind == "html":
        for level, inner in _HTML_HEADING.findall(part):
            names = re.findall(r'<a name="([^"<>]*)">', inner)
            text = html_module.unescape(re.sub(r"<[^>]*>", "", inner)).replace("\ufffc", "").strip()
            heads.append((int(level), text, names[0] if names else slug(text)))
        return heads
    fence, previous = None, ""
    for line in _escape_html_undone(part).split("\n"):
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            previous = ""
            continue
        if opened:
            fence, previous = opened.group(1), ""
            continue
        found = _ATX.match(line)
        if found:
            text = _shown_heading(found.group(2) or "")
            heads.append((len(found.group(1)), text, slug(text)))
            previous = ""
            continue
        setext = _SETEXT.match(line)
        if setext and previous.strip() and not previous.startswith(("    ", "\t")) and not LIST_ITEM.match(previous) \
                and previous.lstrip()[:1] not in (">", "|"):
            text = _shown_heading(previous)
            heads.append((1 if setext.group(1)[0] == "=" else 2, text, slug(text)))
            previous = ""
            continue
        previous = line
    return heads


def _in_data_table(block) -> bool:
    """Whether *block* is in a table with lines (data - not a box, nor a
    formula's)."""
    table = QTextCursor(block).currentTable()
    return table is not None and table.format().border() > 0


def _tables_from(document: QTextDocument, start: int, end: int | None = None) -> list:
    """The tables of the page's top level from *start* (to *end*) - found
    block by block from there: every frame of the page each part was 33,000
    of a page of image chips, 0.07 s more each part (images.md: minutes)."""
    from PyQt6.QtGui import QTextTable

    root, found = document.rootFrame(), []
    block = document.findBlock(start)
    while block.isValid() and (end is None or block.position() < end):
        frame = QTextCursor(block).currentFrame()
        while frame is not None and frame.parentFrame() is not None and frame.parentFrame() != root:
            frame = frame.parentFrame()
        if frame is not None and frame != root and isinstance(frame, QTextTable):
            found.append(frame)
            block = document.findBlock(frame.lastPosition() + 1)
            continue
        block = block.next()
    return found


#: The widest a table is made whose words do not fit the text's width (_unbroken_cells).
WIDE_TABLE_PIXELS = 6000
#: A page's property: a table of it was made wider than the text (_unbroken_cells) - only then does the
#: view give it all of its right margin (_trim; any page wider by more than its margin - a display
#: formula's numbers - was laid out again for it).
_WIDENED = "axrossWidened"


#: Rows of a table _unbroken_cells looks at, its first (of its first part): what they need sets their
#: columns' widths, the rows after them have them too (each of a part's 300 rows of numbers made
#: unbreakable laid the part out again - 0.1 s a part of a long table).
UNBROKEN_ROWS = 100


def _unbroken_cells(document: QTextDocument, start: int, room: int, end: int | None = None) -> None:
    """A table's column of one-word cells only (a header, numbers, short
    codes - "Cent|er", "22.5|0" broken in a narrow window) never broken
    inside a word: its lines unbreakable - when such columns together take
    at most 60 % of the text's width *room* (more, and the columns of
    words were squeezed to a letter a line). The tables that begin from
    *start* on, their first UNBROKEN_ROWS rows."""
    from PyQt6.QtGui import QFontMetrics, QTextLength, QTextTable

    metrics = QFontMetrics(document.defaultFont())
    longest_word = metrics.horizontalAdvance("x" * 40)
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    for frame in _tables_from(document, start, end):
        if not isinstance(frame, QTextTable) or frame.firstPosition() < start or frame.format().border() == 0:
            continue  # (a big table's later part, joined to it: its first part's rows set the columns - a cell
            # of a laid-out table made unbreakable laid all of the table out again, 0.05 s a part)
        columns: dict[int, list] = {}
        for row in range(min(frame.rows(), UNBROKEN_ROWS)):
            for column in range(frame.columns()):
                cell = frame.cellAt(row, column)
                if cell.row() != row or cell.column() != column or cell.lastCursorPosition().position() < start:
                    continue
                blocks, block = [], cell.firstCursorPosition().block()
                while block.isValid() and block.position() <= cell.lastCursorPosition().position():
                    blocks.append(block)
                    block = block.next()
                columns.setdefault(column, []).append(blocks)
        single, width, least = [], 0, 0.0
        for column, cells in columns.items():
            texts = [b.text().strip() for blocks in cells for b in blocks]
            # (what the column needs at least: its longest word - code in a cell is wider: 1.15 -, at most 40
            # letters' worth: a longer one - an address - may break anywhere, as it did)
            widest = max((word for t in texts for word in t.split()), key=len, default="")  # (measured once:
            least += min(longest_word, metrics.horizontalAdvance(widest)) * 1.15 + 16  # each word was, a turn's time)
            if all(len(t) <= 40 and not any(ch.isspace() for ch in t) for t in texts):
                single.append(column)
                width += max((metrics.horizontalAdvance(t) for t in texts), default=0) * 1.15 + 16
        if least > room and frame.columns() > 1 and room / frame.columns() < metrics.horizontalAdvance("x" * 12):
            # (a column's share of the text's width under 12 letters: its words broken a few letters a line -
            # wider ones break a long word into readable lines, the page never scrolled for them)
            # (its words cannot fit the text's width: the table as wide as they need - past the text, the
            # view scrolls sideways as GitHub's does; each of 14 columns of identifiers was broken a few
            # letters a line, "val|ue_|0_0|_lo|ng_" in a column of 630 pixels, also in a window of 1,700)
            fmt = frame.format()
            fmt.setWidth(QTextLength(QTextLength.Type.FixedLength, min(least + 8, WIDE_TABLE_PIXELS)))
            fmt.setColumnWidthConstraints([])
            frame.setFormat(fmt)
            document.setProperty(_WIDENED, True)  # (the view's right margin then given to it: _trim)
            width = 0
        if not single or width > 0.6 * room:
            continue
        for column in single:
            for blocks in columns[column]:
                for block in blocks:
                    fmt = block.blockFormat()
                    if block.text().strip() and not fmt.nonBreakableLines():
                        fmt.setNonBreakableLines(True)
                        cursor.setPosition(block.position())
                        cursor.setBlockFormat(fmt)
    cursor.endEditBlock()


def _is_code(block) -> bool:
    """Whether the page's *block* is a line of a code block (markdown-it's
    <pre>, md4c's fence or indented code)."""
    fmt = block.blockFormat()
    return (fmt.nonBreakableLines() and not _in_data_table(block)) \
        or fmt.hasProperty(QTextFormat.Property.BlockCodeFence) \
        or fmt.hasProperty(QTextFormat.Property.BlockCodeLanguage) \
        or ("monospace" in (block.charFormat().fontFamilies() or ())  # (a <pre> that wraps: pre-wrap)
            and block.textList() is None)  # (a list item's: the room after its bullet - _list_items)


_MARK_OF = {ch: (name, True) for name, ch in MARKS.items()} | {chr(ord(ch) + 1): (name, False)
                                                                for name, ch in MARKS.items()}
_ALIGN_OF = {ch: name for name, ch in ALIGNS.items()}


def apply_marks(document: QTextDocument, start: int, dark: bool) -> None:
    """The marks the text passes left (MARKS, ALIGNS, an image's size in
    its address) made formats, from *start* on: bold, italic, struck,
    underlined, code, marked, sub- and superscript, a formula's colour and
    font, a block's alignment, an image's width, height and place. The marks
    go. Only blocks that hold one are looked at."""

    from ui.markdown_html import colours

    palette = colours(dark)
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    block = document.findBlock(start)
    while block.isValid():
        text = block.text()
        if _PRIVATE.search(text):
            _mark_block(document, cursor, block, text, palette)
        if _IMAGE_SPEC in text or "\ufffc" in text:
            _image_specs(cursor, block)
        block = block.next()
    cursor.endEditBlock()


def _mark_block(document, cursor, block, text: str, palette: dict) -> None:
    from PyQt6.QtGui import QBrush

    base, wide, opened, spans, align, marks = block.position(), 0, {}, [], None, []
    colour_at = named_at = None
    for index, ch in enumerate(text):
        position = base + index + wide
        if ord(ch) > 0xFFFF:
            wide += 1
        if named_at is not None:  # (an anchor's name: up to SPAN_END - the block's name)
            marks.append(position)
            if ch == SPAN_END:
                try:
                    name = base64.b64decode(text[named_at + 1:index]).decode("utf-8")
                except ValueError:
                    name = ""
                if name and not any(c.isspace() for c in name):
                    names = block.blockFormat().stringProperty(_NAMES).split()
                    fmt = block.blockFormat()
                    fmt.setProperty(_NAMES, " ".join([*names, name]))
                    cursor.setPosition(block.position())
                    cursor.setBlockFormat(fmt)
                named_at = None
            continue
        if ch == ANCHOR_MARK:
            named_at = index
            marks.append(position)
            continue
        if colour_at is not None:  # (a colour's hex digits: up to COLOUR_NAMED)
            marks.append(position)
            if ch == COLOUR_NAMED:
                opened.setdefault("colour", []).append((position + 1, text[colour_at + 1:index]))
                colour_at = None
            continue
        if ch == COLOUR_ON:
            colour_at = index
            marks.append(position)
        elif ch == COLOUR_OFF:
            marks.append(position)
            if opened.get("colour"):
                first, colour = opened["colour"].pop()
                spans.append(("colour:#" + colour, first, position))
        elif ch in _ALIGN_OF:
            align = _ALIGN_OF[ch]
            marks.append(position)
        elif ch == INDENT:
            align = align or "indent"
            marks.append(position)
        elif ch == NOTE_BLOCK:
            align = align or "note"
            marks.append(position)
        elif ch in _MARK_OF:
            name, starts = _MARK_OF[ch]
            marks.append(position)
            if starts:
                opened.setdefault(name, []).append(position + 1)
            elif opened.get(name):
                spans.append((name, opened[name].pop(), position))
    spans.sort(key=lambda span: span[0].startswith("colour:"))  # (a colour over the formula's own)
    for name, first, last in spans:
        if last <= first:
            continue
        fmt = QTextCharFormat()
        if name.startswith("colour:"):
            if re.fullmatch(r"colour:#[0-9a-f]{6}", name):
                fmt.setForeground(QBrush(QColor(name[7:])))
        elif name == "bold":
            fmt.setFontWeight(QFont.Weight.Bold)
        elif name == "italic":
            fmt.setFontItalic(True)
        elif name == "strike":
            fmt.setFontStrikeOut(True)
        elif name == "underline":
            fmt.setFontUnderline(True)
        elif name == "code":
            fmt.setFontFamilies(["monospace"])
            fmt.setFontFixedPitch(True)
            fmt.setBackground(QBrush(QColor(palette["code_bg"])))
            fmt.setForeground(QBrush(QColor(palette["code_fg"])))
        elif name == "mark":  # (a highlighter's: the text's colour on yellow)
            fmt.setBackground(QBrush(QColor(palette["highlight_bg"])))
            fmt.setForeground(QBrush(QColor(palette["text"])))
        elif name in ("sub", "sup"):
            fmt.setVerticalAlignment(QTextCharFormat.VerticalAlignment.AlignSubScript if name == "sub"
                                     else QTextCharFormat.VerticalAlignment.AlignSuperScript)
        elif name == "over":  # (a root's bar over what it holds)
            fmt.setFontOverline(True)
        elif name in ("math", "rows"):
            from ui.markdown_html import MATH_FONTS

            fmt.setForeground(QBrush(QColor(palette["math"])))
            fmt.setFontFamilies(["monospace"] if name == "rows" else list(MATH_FONTS))
        cursor.setPosition(first)
        cursor.setPosition(last, QTextCursor.MoveMode.KeepAnchor)
        cursor.mergeCharFormat(fmt)
    for position in reversed(marks):
        cursor.setPosition(position)
        cursor.setPosition(position + 1, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
    if align == "note":  # (a footnote: small, muted letters, as GitHub's)
        small = QTextCharFormat()
        small.setFontPointSize(max(6.0, document.defaultFont().pointSizeF() * 0.92))  # (13-14 pixels: readable)
        small.setForeground(QBrush(QColor(palette["muted"])))
        cursor.setPosition(block.position())
        cursor.setPosition(block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        cursor.mergeCharFormat(small)
        fmt = block.blockFormat()  # (its number kept: the note's anchor - read_outline)
        fmt.setProperty(_NOTE, block.text().partition(". ")[0])
        # (in from the side as markdown-it's list of notes, its number out to the left of its lines)
        fmt.setLeftMargin(fmt.leftMargin() + NOTE_INDENT)
        fmt.setTextIndent(-NOTE_NUMBER)
        cursor.setPosition(block.position())
        cursor.setBlockFormat(fmt)
    elif align == "indent":  # (a definition under its term)
        fmt = block.blockFormat()
        fmt.setLeftMargin(fmt.leftMargin() + 28)
        # (spaced as markdown-it's page spaces <dt> and <dd>: under its term
        # at once, a definition's room after it - the whole list was looser)
        fmt.setTopMargin(0)
        fmt.setBottomMargin(6)  # (and its lines' own 6: as a <dd>)
        cursor.setPosition(block.position())
        cursor.setBlockFormat(fmt)
        term = block.previous()
        if term.isValid() and term.blockFormat().leftMargin() < fmt.leftMargin() and term.text().strip():
            above = term.blockFormat()  # (its term: no room under it, a <dt>'s lines)
            above.setBottomMargin(0)
            above.setProperty(_TERM, True)  # (_style_md4c: its lines without the prose's room)
            if term.previous().isValid() and term.previous().blockFormat().leftMargin() >= fmt.leftMargin():
                above.setTopMargin(0)  # (a term after a definition: the definition's room is the room)
            cursor.setPosition(term.position())
            cursor.setBlockFormat(above)
    elif align:
        flag = {"center": Qt.AlignmentFlag.AlignHCenter, "right": Qt.AlignmentFlag.AlignRight,
                "justify": Qt.AlignmentFlag.AlignJustify}[align]
        fmt = block.blockFormat()
        fmt.setAlignment(flag)
        cursor.setPosition(block.position())
        cursor.setBlockFormat(fmt)


def _image_specs(cursor, block) -> None:
    """An image's size and place from its address's fragment (_IMAGE_SPEC)."""
    pieces = block.begin()
    while not pieces.atEnd():
        piece = pieces.fragment()
        fmt = piece.charFormat()
        if fmt.isImageFormat() and _IMAGE_SPEC in fmt.toImageFormat().name():
            image = fmt.toImageFormat()
            spec = dict(item.split("=", 1) for item in image.name().split(_IMAGE_SPEC, 1)[1].split(":")
                        if "=" in item)
            if spec.get("w", "").isdigit():
                image.setWidth(int(spec["w"]))
            if spec.get("h", "").isdigit():
                image.setHeight(int(spec["h"]))
            cursor.setPosition(piece.position())
            cursor.setPosition(piece.position() + piece.length(), QTextCursor.MoveMode.KeepAnchor)
            cursor.setCharFormat(image)
            if spec.get("a") in ("center", "right"):
                block_format = block.blockFormat()
                block_format.setAlignment(Qt.AlignmentFlag.AlignHCenter if spec["a"] == "center"
                                          else Qt.AlignmentFlag.AlignRight)
                cursor.setBlockFormat(block_format)
        pieces += 1


#: (Qt's own parser) a heading's room above and under it, by its level - as
#: markdown-it's page (ui.markdown_html.style_sheet)
_HEADING_MARGINS = {1: (24, 0), 2: (24, 0), 3: (22, 12), 4: (18, 8), 5: (16, 4), 6: (16, 4)}
#: (Qt's own parser) quotes, alerts and code blocks drawn as boxes at most -
#: each a table Qt lays out; the rest as they are
MD4C_BOXES = 200
#: (Qt's own parser) a quote or code block of more lines than this is not
#: boxed: moving it into its box is one step on the GUI thread (a file of
#: 50,000 lines shown as written held the window seconds)
BOX_BLOCKS = 500
#: ... nor of more characters (ui.markdown_html.BOXED_CHARS).
BOX_CHARS = 40_000


_BULLETS = (QTextListFormat.Style.ListDisc, QTextListFormat.Style.ListCircle, QTextListFormat.Style.ListSquare)


def _list_items(document: QTextDocument, start: int, tasks: bool, dark: bool | None = None) -> None:
    """A list's items from *start* on: the bullet a little apart from the
    text (Qt draws it a space of the block's letters before it: a space of
    a monospace face, as wide as GitHub's gap - it hugged the text); a task
    ("☐ " / "☑ " of markdown-it's page - *tasks* - Qt's own parser's box)
    its glyph, no bullet beside it - Qt's box of a task done is a cross, ☒,
    read as "rejected" (the terminal shows ☑). *dark*: the glyphs' colours
    of Qt's own parser's page (markdown-it's has them)."""
    from PyQt6.QtGui import QTextBlockFormat

    gap = QTextCharFormat()
    gap.setFontFamilies(["DejaVu Sans Mono", "monospace"])
    gap.setFontFixedPitch(True)
    from PyQt6.QtGui import QTextList

    cursor = QTextCursor(document)
    cursor.beginEditBlock()  # (one change of the page, not one an item: 0.4 s a part of 1,200)
    block = document.findBlock(start)
    lists: dict[int, tuple | None] = {}  # (a list's (style, depth) by its object: block.textList()

    def list_of(found) -> tuple | None:  # took 27 µs an item in a list of 60,000 - 3 s of a page's 11)
        index = found.blockFormat().objectIndex() if found.isValid() else -1
        if index < 0:
            return None
        if index not in lists:
            item = document.object(index)
            lists[index] = (item.format().style(), item.format().indent()) if isinstance(item, QTextList) else None
        return lists[index]

    while block.isValid():
        mine = list_of(block)
        style = mine[0] if mine else None
        if style is not None:
            cursor.setPosition(block.position())
            if style in _BULLETS:  # (a number keeps the text's letters)
                cursor.mergeBlockCharFormat(gap)
            own = block.blockFormat()
            said = own.intProperty(QTextFormat.Property.ListStyle)
            # (a task's 0 - no bullet, set below - kept: a second pass over the part (_settle after
            # _part_document) cleared it, a bullet stood beside the box again)
            if own.hasProperty(QTextFormat.Property.ListStyle) and said != style.value \
                    and not (said == 0 and block.text()[:1] in ("☐", "☑")):
                # (the style the item's own format says: Qt draws it, not its list's - the HTML's "li ul"
                # circle at every depth)
                own.clearProperty(QTextFormat.Property.ListStyle)
                cursor.setBlockFormat(own)
            below = list_of(block.next())
            if below and below[1] > mine[1] and block.blockFormat().bottomMargin():
                # (a list's last item with a list in it: the list's room after
                # it went before the inner list - "2. second", a gap, "• inner")
                fmt = block.blockFormat()
                fmt.setBottomMargin(0)
                cursor.setBlockFormat(fmt)
            text = block.text()
            marker = block.blockFormat().marker()
            if (tasks and text[:1] in ("☐", "☑")) or marker != QTextBlockFormat.MarkerType.NoMarker:
                fmt = block.blockFormat()
                fmt.setMarker(QTextBlockFormat.MarkerType.NoMarker)
                fmt.setProperty(QTextFormat.Property.ListStyle, 0)  # (no bullet: the glyph is its bullet)
                cursor.setBlockFormat(fmt)
                if marker != QTextBlockFormat.MarkerType.NoMarker:  # (Qt's own parser's: its glyph written)
                    from ui.markdown_html import colours

                    done = marker == QTextBlockFormat.MarkerType.Checked
                    palette = colours(bool(dark))
                    glyph = QTextCharFormat()
                    glyph.setForeground(QColor(palette["mark"] if done else palette["muted"]))
                    glyph.setFontWeight(QFont.Weight.Bold)
                    cursor.setPosition(block.position())
                    cursor.insertText("☑" if done else "☐", glyph)
                    cursor.insertText(" ", block.charFormat())
        block = block.next()
    cursor.endEditBlock()


def _join_lists(document: QTextDocument, start: int, end: int | None = None) -> None:
    """A long list cut into lists read as one on the page, from *start* on:
    each numbered on from the one before ("1." on every line began at 1
    again after 300 items), no line and no gap where it was cut - cut by
    renderable() (a zero-width line between them, each laid out on its own)
    or between two pieces of a long text parsed apart (the part at *start*
    beginning with the rest of a list)."""
    cursor = QTextCursor(document)
    first = _first_block(document, start)
    if start and first.isValid() and first.textList() is not None and first.previous().textList() is not None:
        _list_goes_on(cursor, first.previous(), first)
    block = document.findBlock(start)
    for _step in range(3):  # (the line may end the part before)
        if block.previous().isValid():
            block = block.previous()
    while block.isValid() and (end is None or block.position() <= end):
        if block.text() == "\u200b" and block.next().isValid() and block.next().textList() is not None \
                and block.previous().textList() is not None:
            before, after = block.previous(), block.next()
            cursor.setPosition(block.position())
            cursor.setPosition(after.position(), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()  # (the line out: its block now the next list's first item)
            block = _list_goes_on(cursor, before, before.next()) or before.next()
        block = block.next()


def _list_goes_on(cursor: QTextCursor, last, first):
    """The list *first* begins as the one *last* (an item, or in one) is in
    going on, if they are alike: numbered on, no room between them. Returns
    *first* - or None (not alike)."""
    later = first.textList()
    depth, back, earlier = later.format().indent(), last, None
    while back.isValid() and back.textList() is not None:  # (its last item may hold a list of its own)
        if back.textList().format().indent() == depth:
            earlier = back.textList()
            break
        back = back.previous()
    if earlier is None or earlier == later or earlier.format().style() != later.format().style():
        return None
    # (an item's room above and below as an item's in the middle of the list
    # has it - not as a list's first and last: room of the list's own)
    inner = [earlier.item(n) for n in range(1, earlier.count())] + [later.item(n) for n in range(1, later.count())]
    above = inner[0].blockFormat().topMargin() if inner else 3.0  # (3: an item's - li's, Qt's own parser's)
    middle = [earlier.item(n) for n in range(earlier.count() - 1)] + [later.item(n) for n in range(later.count() - 1)]
    if last.textList() == earlier:
        fmt = last.blockFormat()
        fmt.setBottomMargin(middle[-1].blockFormat().bottomMargin() if middle else 0)
        cursor.setPosition(last.position())
        cursor.setBlockFormat(fmt)
    # (numbered on from the earlier list's last: the lists stay two - an item
    # moved into the other one by one renumbered all of it each time, 5,000
    # items 80 s)
    shape = later.format()
    shape.setStart(earlier.format().start() + earlier.count())
    later.setFormat(shape)
    fmt = first.blockFormat()
    fmt.setTopMargin(above)
    cursor.setPosition(first.position())
    cursor.setBlockFormat(fmt)
    return first


def _hard_breaks(document: QTextDocument, start: int = 0) -> None:
    """(Qt's own parser) each HARD mark and the space Qt made of the line's
    end after it a line break in the paragraph - in one edit (one each: the
    part laid out again for each of thousands, 0.7 s a part)."""
    cursor = document.find(HARD, start)
    if cursor.isNull():
        return
    editing = QTextCursor(document)
    editing.beginEditBlock()
    while not cursor.isNull():
        at = cursor.selectionEnd()
        if document.characterAt(at) == " ":
            cursor.setPosition(at + 1, QTextCursor.MoveMode.KeepAnchor)
        cursor.insertText("\u2028")
        cursor = document.find(HARD, cursor.position())
    editing.endEditBlock()


def _merge_spans(document: QTextDocument, start: int = 0) -> None:
    """(Qt's own parser) each cell _html_table marked as spanning rows or
    columns merged with the ones it covers, its mark gone - from *start* on."""
    found = document.find(SPAN_MARK, start)
    while not found.isNull():
        table = found.currentTable()
        cursor = QTextCursor(found)
        cursor.setPosition(found.selectionStart())
        end = document.find(SPAN_END, cursor.position())
        mark = None if end.isNull() or end.selectionEnd() - cursor.position() > 12 else end
        if mark is not None:
            cursor.setPosition(mark.selectionEnd(), QTextCursor.MoveMode.KeepAnchor)
            numbers = _SPAN.fullmatch(cursor.selectedText())
            cursor.removeSelectedText()
            if table is not None and numbers:
                cell = table.cellAt(cursor.position())
                down = min(int(numbers.group(1)), table.rows() - cell.row())
                across = min(int(numbers.group(2)), table.columns() - cell.column())
                table.mergeCells(cell.row(), cell.column(), down, across)
        else:
            cursor.setPosition(found.selectionEnd(), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
        found = document.find(SPAN_MARK, cursor.position())


def _inline_tex_marks(document: QTextDocument, start: int = 0) -> None:
    """(Qt's own parser) each inline formula's mark of its TeX (_math_inline)
    from *start* on put on its first letter (_TEX: a copy holds "$TeX$").
    A block's marks from its end back, in one edit: each a change of its own,
    a paragraph of 1,000 formulas took a minute (each laid it out again)."""
    from ui.markdown_html import TEX_INLINE

    found = document.find(MATH_INLINE, start)
    if found.isNull():
        return
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    block = found.block()
    while block.isValid():
        text = block.text()
        if MATH_INLINE in text:
            marks, at = [], text.find(MATH_INLINE)
            while at >= 0:
                end = text.find(SPAN_END, at)
                marks.append((at, end))
                at = text.find(MATH_INLINE, at + 1 if end < 0 else end + 1)
            unit = _utf16(text)
            for at, end in reversed(marks):
                if block.position() + unit(at) < start:
                    break
                cursor.setPosition(block.position() + unit(at))
                cursor.setPosition(block.position() + unit(at + 1 if end < 0 else end + 1),
                                   QTextCursor.MoveMode.KeepAnchor)
                cursor.removeSelectedText()
                if end < 0 or end + 1 >= len(text):
                    continue
                # (the letter after it: by its length - moving by a character laid the block out, each time)
                cursor.setPosition(cursor.position() + (2 if ord(text[end + 1]) > 0xFFFF else 1),
                                   QTextCursor.MoveMode.KeepAnchor)
                fmt = QTextCharFormat()
                fmt.setProperty(_TEX, TEX_INLINE + text[at + 1:end])
                cursor.mergeCharFormat(fmt)
        block = block.next()
    cursor.endEditBlock()


_ASTRAL = re.compile("[\U00010000-\U0010FFFF]")


def _utf16(text: str):
    """index -> the place of *text*'s character at index in Qt's text
    (UTF-16: a character beyond the BMP - an emoji, a math letter - is two)."""
    if not _ASTRAL.search(text):
        return lambda index: index
    import bisect

    astral = [match.start() for match in _ASTRAL.finditer(text)]
    return lambda index: index + bisect.bisect_left(astral, index)


def _math_displays(document: QTextDocument, start: int = 0, dark: bool = False) -> None:
    """(Qt's own parser) each display formula _math_block marked, from
    *start* on, made markdown-it's: its HTML (ui.markdown_html.display_html)
    in the place of its mark's block."""
    from ui.markdown_html import colours, display_html

    found = document.find(MATH_HTML, start)
    while not found.isNull():
        block = found.block()
        text = block.text()
        at, end = text.find(MATH_HTML), text.find(SPAN_END)
        laid = None
        if 0 <= at < end:
            try:
                tex = base64.b64decode(text[at + 1:end]).decode("utf-8")
                laid = display_html(tex, colours(dark))
                if laid is None:  # (not laid out - too deep, a fault: in its line, as text - it was gone)
                    from core import markdown_doc

                    laid = f'<p align="center">{markdown_doc.math_html(tex)}</p>'
            except ValueError:
                laid = None
        kept = block.blockFormat()
        cursor = QTextCursor(block)
        cursor.setPosition(block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        if laid:
            cursor.insertHtml(laid.strip())
            cursor.setBlockFormat(kept)  # (the line after it as the mark's was - in parts and whole alike)
        else:
            cursor.removeSelectedText()
        found = document.find(MATH_HTML, cursor.position())


def _keep_reader(browser, anchor: int, position: int) -> None:
    """The reader's text cursor (*anchor*, *position*) put back - where the
    view is shown stays."""
    bar = browser.verticalScrollBar()
    where = bar.value()
    cursor = browser.textCursor()
    cursor.setPosition(anchor)
    cursor.setPosition(position, QTextCursor.MoveMode.KeepAnchor)
    browser.setTextCursor(cursor)
    bar.setValue(where)


def _top_room(document: QTextDocument) -> None:
    """Room above the page's first block (it touched the view's top) - set
    while the page is small: a frame's margins changed later laid all of it
    out again."""
    root = document.rootFrame()
    fmt = root.frameFormat()
    fmt.setTopMargin(TOP_ROOM)
    root.setFrameFormat(fmt)


def _seam(document: QTextDocument, begins: int) -> None:
    """The empty line before the part at *begins* (after the box the part
    before ended with) as low as it gets."""
    block = document.findBlock(begins)
    for candidate in (block, block.previous()):
        if candidate.isValid() and not candidate.text() and QTextCursor(candidate).currentTable() is None \
                and candidate.blockFormat().intProperty(_GAP) == 0:
            cursor = QTextCursor(document)
            _lowest(cursor, candidate)
            return


def _going_on(document: QTextDocument, start: int) -> None:
    """From *start* on: an item's (a note's) first block a part goes on with
    (ui.markdown_html.GOING_ON - the part was cut inside the item) made no
    item and of no height, its mark out."""
    from ui.markdown_html import GOING_ON

    found = document.find(GOING_ON, start)
    if found.isNull():
        return
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    while not found.isNull():
        block = found.block()
        if block.text() == GOING_ON:
            cursor.setPosition(block.position())
            cursor.setPosition(block.position() + 1, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            outer = block.previous()  # (Qt's own parser: "4. - " an empty item of the outer list before it)
            for going in ([outer] if outer.isValid() and not outer.text() and outer.textList() is not None else []) \
                    + [block]:
                _lowest(cursor, going)
                fmt = going.blockFormat()
                fmt.setProperty(_GOING, True)
                cursor.setPosition(going.position())
                cursor.setBlockFormat(fmt)
        found = document.find(GOING_ON, block.position() + block.length())
    cursor.endEditBlock()


def _lowest(cursor: QTextCursor, block) -> None:
    """*block* as low as a line gets (1 point, no margins)."""
    from PyQt6.QtGui import QTextBlockFormat

    small = QTextCharFormat()
    small.setFontPointSize(1)
    cursor.setPosition(block.position())
    cursor.setBlockFormat(QTextBlockFormat())
    cursor.setPosition(block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
    cursor.setBlockCharFormat(small)
    cursor.mergeCharFormat(small)


def _rule_format(palette: dict, top: int, bottom: int):
    """A block that is a light rule (as Qt's <hr>: its colour its background's)."""
    from PyQt6.QtGui import QBrush, QTextBlockFormat, QTextLength

    fmt = QTextBlockFormat()
    fmt.setProperty(QTextFormat.Property.BlockTrailingHorizontalRulerWidth,
                    QTextLength(QTextLength.Type.PercentageLength, 100))
    fmt.setBackground(QBrush(QColor(palette["rule"])))
    fmt.setTopMargin(top)
    fmt.setBottomMargin(bottom)
    return fmt


def _style_md4c(document: QTextDocument, start: int, dark: bool, quotes: bool = True) -> None:
    """Qt's own parser's blocks from *start* on in the colours and spacing of
    markdown-it's page (ui.markdown_html's palette and style sheet):
    headings in the text's colour with their room (a light rule under the
    first two levels), code blocks on their background, quotes muted (their
    links not), links in the link colour, rules light, lines of prose 6
    pixels apart. (Its page was black on white, tight - a piece at a time,
    as it comes in.) The boxes come at the end: _box_md4c. *quotes*: whether
    its text put a QUOTE_END in (else none is looked for)."""
    from PyQt6.QtGui import QBrush

    from ui.markdown_html import colours

    palette = colours(dark)
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    quote = QTextFormat.Property.BlockQuoteLevel
    ruler = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
    link = QBrush(QColor(palette["link"]))
    if quotes:
        _quotes_apart(document, cursor, start)
    block = document.findBlock(start)
    while block.isValid():
        fmt = block.blockFormat()
        level = fmt.headingLevel()
        colour = None
        cursor.setPosition(block.position())
        if level:
            colour = palette.get(f"h{level}")
            above, under = _HEADING_MARGINS.get(level, (16, 4))
            fmt.setTopMargin(above)
            fmt.setBottomMargin(under)
            cursor.setBlockFormat(fmt)
        elif fmt.hasProperty(ruler):
            cursor.setBlockFormat(_rule_format(palette, 14, 14))
        elif block.text() == "\u200b":  # (the line between a long list's parts: renderable)
            _lowest(cursor, block)
            block = block.next()
            continue
        elif block.text().startswith(JOINED):  # (a long paragraph's later piece: no room between them)
            cursor.setPosition(block.position() + 1, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            fmt.setTopMargin(0)
            before = block.previous()
            if before.isValid():
                above = QTextCursor(before)
                kept = before.blockFormat()
                kept.setBottomMargin(0)
                above.setBlockFormat(kept)
            fmt.setLineHeight(6, 4)
            cursor.setBlockFormat(fmt)
        elif fmt.hasProperty(QTextFormat.Property.BlockCodeFence) or fmt.nonBreakableLines():
            fmt.setBackground(QBrush(QColor(palette["pre_bg"])))
            cursor.setBlockFormat(fmt)
            block = block.next()  # (code holds no link, no code in a line: its pieces as they are)
            continue
        else:
            if fmt.intProperty(quote):
                colour = palette["quote_fg"]
            # (prose, items and cells alike: a cell's lines were closer than the text's;
            # a definition's term none - a <dt>'s)
            fmt.setLineHeight(0 if fmt.boolProperty(_TERM) else 6, 4)  # (4: LineDistanceHeight)
            items = block.textList()
            if items:  # (an item's lines closer than the items: as markdown-it's li - GitHub's 24 px)
                fmt.setLineHeight(4, 4)
                fmt.setTopMargin(3)
                fmt.setBottomMargin(0)
                before = block.previous().textList() if block.previous().isValid() else None
                if before is not None and before != items and items.item(0) == block \
                        and before.format().indent() >= items.format().indent():
                    fmt.setTopMargin(14)  # (a list after another, not in it: apart - they ran together)
                if items.item(0) == block and items.format().style() in _BULLETS:
                    # (its bullet by its depth, as GitHub's: Qt's by the character - "* a" a circle)
                    shape = items.format()
                    shape.setStyle(_BULLETS[min(len(_BULLETS), max(1, shape.indent())) - 1])
                    items.setFormat(shape)
            cursor.setBlockFormat(fmt)
        pieces = block.begin()
        while not pieces.atEnd():  # (each piece: a link in its colour - in a quote too)
            piece = pieces.fragment()
            pieces += 1
            anchor = piece.charFormat().isAnchor() and piece.charFormat().anchorHref()
            code = piece.charFormat().fontFixedPitch() and not fmt.hasProperty(QTextFormat.Property.BlockCodeFence)
            if anchor and not _safe_href(anchor):
                # (a link whose address is refused - javascript:, …: its text, no link)
                plain = piece.charFormat()
                plain.setAnchor(False)
                plain.setAnchorHref("")
                plain.setFontUnderline(False)
                plain.setForeground(QBrush(QColor(colour or palette["text"])))
                cursor.setPosition(piece.position())
                cursor.setPosition(piece.position() + piece.length(), QTextCursor.MoveMode.KeepAnchor)
                cursor.setCharFormat(plain)
                continue
            if not anchor and not colour and not code:
                continue
            char = QTextCharFormat()
            char.setForeground(link if anchor else QBrush(QColor(palette["code_fg"] if code else colour)))
            if anchor and anchor.startswith("#" + FOLD):  # (a <details>' summary: the text's colour, as
                char.setForeground(QBrush(QColor(colour or palette["text"])))  # markdown-it's page shows it)
                char.setFontUnderline(False)
            if code:  # (code in a line: on its light grey, as markdown-it's)
                char.setBackground(QBrush(QColor(palette["code_bg"])))
            cursor.setPosition(piece.position())
            cursor.setPosition(piece.position() + piece.length(), QTextCursor.MoveMode.KeepAnchor)
            cursor.mergeCharFormat(char)
        if level in (1, 2) and not block.next().blockFormat().hasProperty(ruler):
            cursor.setPosition(block.position() + block.length() - 1)
            cursor.insertBlock(_rule_format(palette, 0, 10), QTextCharFormat())
            block = block.next()  # (the rule)
        block = block.next()
    _style_tables(document, start, palette)
    cursor.endEditBlock()


def _safe_href(href: str) -> bool:
    """Whether a link of Qt's own parser's page may stay one (markdown-it's
    rule: no javascript:, vbscript:, file:, data:)."""
    import html as html_module

    from core import markdown_doc

    # (its entities read too, as markdown-it reads them: "&#106;avascript:" a
    # link to its own text - it is dropped there)
    return markdown_doc._link_ok(html_module.unescape(QUrl.fromPercentEncoding(href.encode())), None)


def _no_empty_first_line(table) -> None:
    """(Qt's own parser) the empty line Qt's Markdown reader puts into the
    first cell of a table right after a code block taken out: its header
    stood a line lower than the others'."""
    cell = table.cellAt(0, 0)
    first = cell.firstCursorPosition().block()
    after = first.next()
    if first.text() or not after.isValid() or after.position() > cell.lastCursorPosition().position():
        return
    fmt = after.blockFormat()
    cursor = QTextCursor(after)
    cursor.deletePreviousChar()
    cursor.setBlockFormat(fmt)


def _style_tables(document: QTextDocument, start: int, palette: dict) -> None:
    """(Qt's own parser) its tables from *start* on as markdown-it's page
    draws them: thin lines in the rule's colour, padded cells, the header on
    a tint, every second row on another (a formula's table aside)."""
    from PyQt6.QtGui import QBrush, QTextTable

    rule, head, zebra = QBrush(QColor(palette["rule"])), QBrush(QColor(palette["th_bg"])), \
        QBrush(QColor(palette["zebra"]))
    bold = QTextCharFormat()
    bold.setFontWeight(QFont.Weight.Bold)
    for frame in _tables_from(document, start):
        if not isinstance(frame, QTextTable) or frame.firstPosition() < start:
            continue
        _no_empty_first_line(frame)
        pipe = document.find("\\|", frame.firstPosition())
        while not pipe.isNull() and pipe.selectionEnd() <= frame.lastPosition():
            if pipe.charFormat().fontFixedPitch() or "monospace" in (pipe.charFormat().fontFamilies() or ()):
                pipe.setPosition(pipe.selectionStart())  # (code's "\|" in a cell: the pipe only, as GitHub)
                pipe.deleteChar()
            pipe = document.find("\\|", pipe.position() + 1)
        fmt = frame.format()
        fmt.setBorder(1)
        fmt.setBorderBrush(rule)
        fmt.setBorderStyle(fmt.BorderStyle.BorderStyle_Solid)
        fmt.setBorderCollapse(True)
        fmt.setCellPadding(6)
        fmt.setCellSpacing(0)
        fmt.setTopMargin(8)  # (two tables in a row, a table after raw HTML: apart)
        fmt.setBottomMargin(14)
        frame.setFormat(fmt)
        mark = document.find(NO_HEAD, frame.firstPosition())
        plain = not mark.isNull() and mark.selectionEnd() <= frame.lastPosition()
        if plain:  # (raw HTML's cells, no header: none drawn)
            mark.removeSelectedText()
            normal = QTextCharFormat()
            normal.setFontWeight(QFont.Weight.Normal)
            for column in range(frame.columns()):
                inside = frame.cellAt(0, column).firstCursorPosition()
                inside.setPosition(frame.cellAt(0, column).lastCursorPosition().position(),
                                   QTextCursor.MoveMode.KeepAnchor)
                inside.mergeCharFormat(normal)
            continue
        for row in range(frame.rows()):  # (rows as low as markdown-it's page's: 3 pixels above and below)
            for column in range(frame.columns()):
                cell = frame.cellAt(row, column)
                if cell.row() == row and cell.column() == column:
                    room = cell.format().toTableCellFormat()
                    room.setTopPadding(3)
                    room.setBottomPadding(3)
                    cell.setFormat(room)
        for row in range(frame.rows()):
            if row and row % 2:
                continue
            for column in range(frame.columns()):
                cell = frame.cellAt(row, column)
                if cell.row() != row or cell.column() != column:
                    continue
                cell_format = cell.format()
                cell_format.setBackground(head if row == 0 else zebra)
                cell.setFormat(cell_format)
                if row == 0:  # (the header bold - after a code block Qt's reader left it plain)
                    inside = cell.firstCursorPosition()
                    inside.setPosition(cell.lastCursorPosition().position(), QTextCursor.MoveMode.KeepAnchor)
                    inside.mergeCharFormat(bold)


def _box_md4c(document: QTextDocument, dark: bool, start: int = 0, most: int = MD4C_BOXES,
              bands: tuple[bool, bool] = (False, False)) -> int:
    """Qt's own parser's quotes, alerts and code blocks in boxes as
    markdown-it's page draws them (tables: Qt's rich text draws no border of
    one side): a quote beside a bar in the rule's colour, an alert on its
    background beside a bar and under a title in its colour, a code block
    padded on its grey with its language on it. And room under a table.
    From *start* on (a part of the page as it comes in), *most* boxes at
    most (MD4C_BOXES a page), none of more than BOX_BLOCKS lines - nor
    the code block the part begins or ends with where *bands* says it goes
    on in the part before or after it (a long one's band: markdown_parts).
    Returns how many it drew."""
    from ui.markdown_html import ALERT_TITLES, _title, colours

    palette = colours(dark)
    titles = {" ".join(_title(kind)): kind for kind in ALERT_TITLES}
    quote = QTextFormat.Property.BlockQuoteLevel
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    _label_code(document, start, palette)
    runs, block = [], _first_block(document, start)
    begins = block.position()
    while block.isValid() and len(runs) < most:
        cursor.setPosition(block.position())
        top = cursor.currentTable() is None and not block.textList() and not block.blockFormat().indent()
        if top and block.blockFormat().intProperty(quote) == 1:
            kind = titles.get(block.text().split("\u2028", 1)[0].strip())
            first = last = block
            count = 1
            while _in_quote(last.next()) and not titles.get(last.next().text().split("\u2028", 1)[0].strip()):
                last, count = last.next(), count + 1
            if count <= BOX_BLOCKS:
                runs.append(("alert" if kind else "quote", first, last, kind))
            block = last.next()
            continue
        if top and _is_code(block) and not block.blockFormat().intProperty(quote):
            first = last = block
            count = 1
            while _same_code(last.next(), first):
                last, count = last.next(), count + 1
            band = (bands[0] and first.position() <= begins) or (bands[1] and not _after_text(last))
            if count <= BOX_BLOCKS and not band:
                runs.append(("code", first, last, block.blockFormat().stringProperty(
                    QTextFormat.Property.BlockCodeLanguage)))
            block = last.next()
            continue
        block = block.next()
    for kind, first, last, info in reversed(runs):
        _box(document, palette, kind, first, last, info)
    cursor.endEditBlock()  # (the boxes made: seen by the pass after - inside one edit they were not)
    cursor.beginEditBlock()
    count, runs = len(runs), []
    block = _first_block(document, start)
    while block.isValid() and len(runs) < most:  # (a quote in a quote: a box in the box, its own bar)
        cursor.setPosition(block.position())
        table = cursor.currentTable()
        if table is not None and table.format().border() == 0 and block.blockFormat().intProperty(quote) == 2 \
                and not _is_code(block):
            first = last = block
            while last.next().isValid() and last.next().blockFormat().intProperty(quote) == 2 \
                    and QTextCursor(last.next()).currentTable() == table:
                last = last.next()
            runs.append(("quote", first, last, None))
            block = last.next()
            continue
        if table is not None and table.format().border() == 0 and table.columns() == 2 and _is_code(block) \
                and not _same_code(block.previous(), block):
            # (code in a quote or an alert: a box in the box - on a block's grey it
            # stood against the grey's edges, no room inside it)
            first = last = block
            while _same_code(last.next(), first) and QTextCursor(last.next()).currentTable() == table:
                last = last.next()
            label = block.previous() if block.previous().blockFormat().boolProperty(_CODE_LABEL) else None
            lang = block.blockFormat().stringProperty(QTextFormat.Property.BlockCodeLanguage)
            alert = table.cellAt(0, 1).format().background().style() != Qt.BrushStyle.NoBrush
            ends = not last.next().isValid() or QTextCursor(last.next()).currentTable() != table \
                or not last.next().text().strip() and QTextCursor(last.next().next()).currentTable() != table
            runs.append(("code", first, last, (lang, label, alert, ends)))
            block = last.next()
            continue
        block = block.next()
    for kind, first, last, info in reversed(runs):
        if kind == "code":
            lang, label, alert, ends = info
            if label is not None:  # (its language on the box, as a box's - not a line of its own)
                gone = QTextCursor(label)
                gone.setPosition(label.position() + label.length(), QTextCursor.MoveMode.KeepAnchor)
                gone.removeSelectedText()
            _box(document, {**palette, "pre_bg": palette["code_bg"]} if alert else palette, kind, first, last, lang,
                 0 if ends else 14)  # (the last thing in the box: no room under it inside the box)
        else:
            _box(document, palette, kind, first, last, info)
    cursor.endEditBlock()
    return count + len(runs)


def _first_block(document, start: int):
    """The first block of a part put in at *start* - not the page's last
    one before it (its code a run of its own: the end of a code block too
    long to box was boxed, as the next part came)."""
    block = document.findBlock(start)
    return block.next() if block.position() < start else block


def _quotes_apart(document, cursor, start: int) -> None:
    """The lines QUOTE_END put between two quotes (from *start* on) as low
    as they get, their mark gone."""
    from PyQt6.QtGui import QTextBlockFormat

    small = QTextCharFormat()
    small.setFontPointSize(1)
    found = document.find(QUOTE_END, start)
    while not found.isNull():
        block = found.block()
        found.removeSelectedText()
        if not block.text():
            cursor.setPosition(block.position())
            cursor.setBlockFormat(QTextBlockFormat())
            cursor.setBlockCharFormat(small)
        found = document.find(QUOTE_END, block.position())


def _after_text(block) -> bool:
    """Whether a block with text comes after *block* (the end of a part)."""
    block = block.next()
    while block.isValid():
        if block.text().strip():
            return True
        block = block.next()
    return False


def _label_code(document: QTextDocument, start: int, palette: dict) -> None:
    """(Qt's own parser) a code block in a list or a quote (no box of its
    own: _box_md4c boxes those of the top level) its language on a line
    over it, as the boxed ones - it had none."""
    from PyQt6.QtGui import QBrush, QTextBlockFormat

    from ui.markdown_html import _code_label

    quote = QTextFormat.Property.BlockQuoteLevel
    found, block = [], document.findBlock(start)
    while block.isValid():
        lang = block.blockFormat().stringProperty(QTextFormat.Property.BlockCodeLanguage)
        if lang and _is_code(block) and not _same_code(block.previous(), block) \
                and (block.textList() or block.blockFormat().indent() or block.blockFormat().intProperty(quote)) \
                and QTextCursor(block).currentTable() is None:
            found.append((block.position(), lang))
        block = block.next()
    cursor = QTextCursor(document)
    for position, lang in reversed(found):
        code = document.findBlock(position)
        code_format, code_chars = code.blockFormat(), code.charFormat()
        label_format = QTextBlockFormat()
        label_format.setLeftMargin(code_format.leftMargin())
        label_format.setIndent(code_format.indent())
        label_format.setProperty(quote, code_format.intProperty(quote))
        label_format.setTopMargin(4)
        label_format.setBackground(QBrush(QColor(palette["pre_bg"])))
        label_format.setProperty(_CODE_LABEL, True)
        cursor.setPosition(position)
        cursor.insertBlock(code_format, code_chars)  # (the code on: the line before it the label's)
        cursor.setPosition(position)
        cursor.setBlockFormat(label_format)
        cursor.setBlockCharFormat(QTextCharFormat())  # (the label's: no code's letters - Copy Code Block took it)
        small = QTextCharFormat()
        small.setForeground(QBrush(QColor(palette["muted"])))
        small.setFontPointSize(max(6.0, document.defaultFont().pointSizeF() * 0.8))
        cursor.insertText(_code_label(lang), small)


def _in_quote(block) -> bool:
    if not block.isValid() or not block.blockFormat().intProperty(QTextFormat.Property.BlockQuoteLevel):
        return False
    cursor = QTextCursor(block)
    return cursor.currentTable() is None


def _box(document, palette: dict, kind: str, first, last, info: str, below: int = 14) -> None:
    """The blocks *first* to *last* moved into a box (see _box_md4c)."""
    from PyQt6.QtGui import QBrush, QTextBlockFormat, QTextLength, QTextTableCellFormat, QTextTableFormat

    from ui.markdown_html import _code_label

    start, end = first.position(), last.position() + last.length() - 1
    formats = []
    block = first
    while True:
        formats.append(block.blockFormat())
        if block == last:
            break
        block = block.next()
    cursor = QTextCursor(document)
    cursor.setPosition(start)
    cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
    fragment = cursor.selection()
    cursor.removeSelectedText()
    gap = QTextBlockFormat()  # (the line Qt keeps before a table: as low as it gets)
    small = QTextCharFormat()
    small.setFontPointSize(1)
    cursor.setBlockFormat(gap)
    cursor.setBlockCharFormat(small)
    table_format = QTextTableFormat()
    table_format.setBorder(0)
    table_format.setCellSpacing(0)
    table_format.setCellPadding(0)
    table_format.setWidth(QTextLength(QTextLength.Type.PercentageLength, 100))
    table_format.setTopMargin(2 if kind == "code" else 6)
    table_format.setBottomMargin(below)
    columns = 1 if kind == "code" else 2
    if columns == 2:
        table_format.setColumnWidthConstraints([QTextLength(QTextLength.Type.FixedLength, 4),
                                                QTextLength(QTextLength.Type.VariableLength, 0)])
    background = {"code": palette["pre_bg"], "alert": palette["alert_bg"]}.get(kind)
    table = cursor.insertTable(1, columns, table_format)
    if columns == 2:
        bar = QTextTableCellFormat()
        bar.setBackground(QBrush(QColor(palette.get(info, palette["rule"]) if kind == "alert" else palette["rule"])))
        table.cellAt(0, 0).setFormat(bar)
    cell = table.cellAt(0, columns - 1)
    padding = QTextTableCellFormat()
    padding.setTopPadding(10 if kind == "code" else 6)
    padding.setBottomPadding(10 if kind == "code" else 6)
    padding.setLeftPadding(12)
    padding.setRightPadding(10)
    if background:  # (Qt paints a cell's background, not its table's)
        padding.setBackground(QBrush(QColor(background)))
    cell.setFormat(padding)
    inner = cell.firstCursorPosition()
    label = _code_label(info) if kind == "code" and info else ""
    if label:
        label_format = QTextCharFormat()
        label_format.setForeground(QBrush(QColor(palette["muted"])))
        label_format.setFontPointSize(max(6.0, document.defaultFont().pointSizeF() * 0.8))
        label_block = QTextBlockFormat()
        label_block.setBottomMargin(6)
        inner.setBlockFormat(label_block)
        inner.insertText(label, label_format)
        inner.insertBlock(QTextBlockFormat(), QTextCharFormat())
    inner.insertFragment(fragment)
    # (each block as it was, without the quote's indent: the box is it)
    first_position = cell.firstCursorPosition().position()
    last_position = cell.lastCursorPosition().position()
    block = document.findBlock(first_position)
    if label:
        block = block.next()
    for fmt in formats:
        if not block.isValid() or block.position() > last_position:
            break
        if kind != "code":
            fmt.setLeftMargin(max(0.0, fmt.leftMargin() - 40))
            fmt.setRightMargin(0)
        if fmt is formats[0]:
            fmt.setTopMargin(0)  # (the box's padding is the room above it)
        if fmt is formats[-1]:
            fmt.setBottomMargin(0)
        cursor.setPosition(block.position())
        cursor.setBlockFormat(fmt)
        block = block.next()
    if kind == "alert":  # (its title in its colour, its text not muted as a quote's)
        title = document.findBlock(first_position)
        end_of_title = title.position() + len(title.text().split("\u2028", 1)[0])
        block = title
        while block.isValid() and block.position() <= last_position:
            labelled = block.blockFormat().boolProperty(_CODE_LABEL)
            if labelled or _is_code(block):
                # (code in an alert on a grey of its own - on the alert's it
                # was no box - and its language muted as everywhere)
                tinted = block.blockFormat()
                tinted.setBackground(QBrush(QColor(palette["code_bg"])))
                cursor.setPosition(block.position())
                cursor.setBlockFormat(tinted)
                if labelled:
                    block = block.next()
                    continue
            pieces = block.begin()
            while not pieces.atEnd():
                piece = pieces.fragment()
                pieces += 1
                if piece.charFormat().isAnchor() or piece.charFormat().fontFixedPitch():
                    continue
                char = QTextCharFormat()
                char.setForeground(QBrush(QColor(palette.get(info, palette["link"]) if piece.position() < end_of_title
                                                 else palette["text"])))
                cursor.setPosition(piece.position())
                cursor.setPosition(min(piece.position() + piece.length(), max(end_of_title, piece.position() + 1))
                                   if piece.position() < end_of_title else piece.position() + piece.length(),
                                   QTextCursor.MoveMode.KeepAnchor)
                cursor.mergeCharFormat(char)
            block = block.next()


def _table_room(document, start: int = 0, end: int | None = None) -> None:
    """Room under each table that is no box (a big table's parts joined -
    join_tables - get it under the last) whose next block is in a part just
    laid out (from *start* to *end*: the table before it too). A part at a
    time: once over all of the page, a relayout each, it held the window
    37 s for 1000 tables."""
    from PyQt6.QtGui import QTextTable

    cursor = QTextCursor(document)
    end = document.characterCount() if end is None else end
    for frame in _tables_from(document, max(0, start - 2), end + 1):
        if not isinstance(frame, QTextTable) or frame.format().border() == 0:
            continue
        if frame.lastPosition() > end:
            break
        after = document.findBlock(frame.lastPosition() + 1).next()  # (past the block of its end)
        if not after.isValid() or after.position() < start or after.charFormat().fontPointSize() == 1:
            continue  # (the line before the next part of the same table)
        if after.blockFormat().intProperty(_GAP) or after.blockFormat().boolProperty(_STAND_IN):
            continue  # (what follows not laid out yet: when it is)
        fmt = after.blockFormat()
        if fmt.topMargin() < 14:
            fmt.setTopMargin(14)
            cursor.setPosition(after.position())
            cursor.setBlockFormat(fmt)


def join_tables(document: QTextDocument, tables: list, head=None):
    """(Qt's own parser) the parts of a big table renderable() cut made one
    table again: the header each later part carries (marked CHUNK) taken
    away, every part as wide as the page with the same column widths (in
    proportion to the first part's longest cells), the line between two
    parts as low as it gets. *tables*: those a part of the page just put in
    (each table's part is one: joined as it comes, never all at once);
    *head*: the first part the next later part belongs to. Returns the
    head for the next part. (markdown-it's are joined in their HTML:
    ui.markdown_html.)"""
    from PyQt6.QtGui import QTextLength

    cursor = QTextCursor(document)
    for table in tables:
        if not _first_cell(table).startswith(CHUNK) or head is None:
            head = table
            continue
        cursor.beginEditBlock()
        if table.rows() > 1:
            table.removeRows(0, 1)
        for frame in (head, table):
            fmt = frame.format()
            if not fmt.columnWidthConstraints():
                fmt.setColumnWidthConstraints(_column_widths(head))
                fmt.setWidth(QTextLength(QTextLength.Type.PercentageLength, 100))
                if frame is table:
                    fmt.setTopMargin(0)
                fmt.setBottomMargin(0)
                frame.setFormat(fmt)
        gap = document.findBlock(table.firstPosition() - 1)  # (the line between: as low as it gets)
        small = QTextCharFormat()
        small.setFontPointSize(1)
        block_format = gap.blockFormat()
        block_format.setTopMargin(0)
        block_format.setBottomMargin(0)
        cursor.setPosition(gap.position())
        cursor.setBlockFormat(block_format)
        cursor.setBlockCharFormat(small)
        cursor.endEditBlock()
    return head


def _first_cell(table) -> str:
    return table.cellAt(0, 0).firstCursorPosition().block().text()


def _column_widths(table) -> list:
    """Column widths in proportion to the longest text of each column of
    *table* (each at least 3, at most 40 characters' worth)."""
    from PyQt6.QtGui import QTextLength

    longest = [3] * table.columns()
    for row in range(min(table.rows(), 200)):
        for column in range(table.columns()):
            cell = table.cellAt(row, column)
            text = cell.firstCursorPosition().block().text() if cell.isValid() else ""
            longest[column] = min(40, max(longest[column], len(text.replace(CHUNK, ""))))
    longest = [n + 3 for n in longest]  # (the cell's padding)
    total = sum(longest)
    return [QTextLength(QTextLength.Type.PercentageLength, 100 * n / total) for n in longest]


def _wrap_code(document: QTextDocument, start: int = 0) -> None:
    """Qt's own parser's code blocks (from *start* on) wrapped in their box,
    as markdown-it's (pre-wrap): a long line scrolled the whole page
    sideways, past the box."""
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    block = document.findBlock(start)
    while block.isValid():
        if block.blockFormat().nonBreakableLines():
            fmt = block.blockFormat()
            fmt.setNonBreakableLines(False)
            cursor.setPosition(block.position())
            cursor.setBlockFormat(fmt)
        block = block.next()
    cursor.endEditBlock()


def _is_seam(block) -> bool:
    """Whether *block* is one of a cut's blocks of no height (_going_on, the zero-width line between parts)."""
    return block.isValid() and (block.blockFormat().boolProperty(_GOING) or block.text() == "\u200b"
                                or (not block.text() and block.charFormat().fontPointSize() == 1))


def _going_between(block, code) -> bool:
    """Whether *block* is one of a cut's blocks of no height (_going_on, the
    zero-width line between parts) between two pieces of the code block
    *code* is a line of."""
    def seam(candidate) -> bool:
        return candidate.isValid() and (candidate.blockFormat().boolProperty(_GOING) or candidate.text() == "\u200b"
                                        or (not candidate.text() and candidate.charFormat().fontPointSize() == 1))

    if not seam(block):
        return False
    after, before = block.next(), block.previous()
    for _step in range(3):
        if seam(after):
            after = after.next()
        if seam(before):
            before = before.previous()
    return _same_code(after, code) or _same_code(before, code)


def _same_code(block, other) -> bool:
    """Whether *block* is a line of the code block *other* is one of: code,
    at the same indent, margin and quote level (a list's code block and the
    quote's after it joined into one)."""
    if not block.isValid() or not _is_code(block):
        return False
    a, b = block.blockFormat(), other.blockFormat()
    quote = QTextFormat.Property.BlockQuoteLevel
    return a.indent() == b.indent() and a.leftMargin() == b.leftMargin() \
        and a.intProperty(quote) == b.intProperty(quote)


def _stand_in_rect(layout, block):
    """Where a block standing in for parts is, all of its height (Qt's
    bounding rectangle of a block of a fixed line height is one line high;
    the blocks after it begin below all of it)."""
    rect = layout.blockBoundingRect(block)
    rect.setHeight(max(rect.height(), block.blockFormat().lineHeight()))
    return rect


def _plain_text(page: dict, part) -> str:
    """The text of the page's *part* as find looks in it (lower case): its
    marks out - and, as written (Qt's own parser's, a piece not parsed yet),
    as it is and with its emphasis marks out too ("**a**b" shows "ab")."""
    import html as html_module

    if isinstance(part, _Unparsed):
        text = page["texts"][part.piece]
    elif page["kind"] == "html":
        return html_module.unescape(re.sub(r"<[^>]*>", "", part)).lower()
    else:
        text = _escape_html_undone(part)
    text = text.lower()
    return text + "\n" + _EMPHASIS.sub("", text)


_EMPHASIS = re.compile(r"[*_~`]+|" + "[" + "".join(MARKS.values()) + "".join(chr(ord(ch) + 1) for ch in MARKS.values())
                       + "]")


def _low(cursor: QTextCursor) -> int:
    """Where a selection begins as the reader made it (Qt's selectionStart() takes in all of a table it
    begins in: a selection begun in a quote held the formula before it)."""
    return min(cursor.anchor(), cursor.position())


def _high(cursor: QTextCursor) -> int:
    return max(cursor.anchor(), cursor.position())


#: Characters of the page a copy takes in one event-loop turn (copy_selection).
COPY_CHARS = 8_000
#: ... or blocks (each line of a code block one, each its frame).
COPY_BLOCKS = 600
#: Seconds of pieces a copy takes in one turn (_copy_more) - with the one begun last, under 0.1 s.
COPY_TURN = 0.025


def _copy_ranges(document: QTextDocument, low: int, high: int) -> list:
    """*low* to *high* of the page as ("range", start, end) pieces of about
    COPY_CHARS characters (cursors: they keep their places while parts come
    in), cut only where a block begins that _cuttable takes (never in a
    formula, never between a table's cells)."""
    root = document.rootFrame()
    out, start = [], low

    def next_cut(start: int):  # (COPY_CHARS on, or COPY_BLOCKS blocks on - the sooner: 50,000 short code
        # blocks, each a frame, were 2,000 a piece - 0.1 s)
        by_chars = document.findBlock(start + COPY_CHARS)
        by_blocks = document.findBlockByNumber(document.findBlock(start).blockNumber() + COPY_BLOCKS)
        if by_blocks.isValid() and (not by_chars.isValid() or by_blocks.position() < by_chars.position()):
            return by_blocks
        return by_chars

    first = document.findBlock(low)
    block = next_cut(low) if high - low > COPY_CHARS or (
        document.findBlock(high).blockNumber() - first.blockNumber() > COPY_BLOCKS) else None
    while block is not None and block.isValid() and block.position() < high:
        if (block.position() - start >= COPY_CHARS or block.blockNumber() - document.findBlock(start).blockNumber()
                >= COPY_BLOCKS) and _cuttable(block, root):
            out.append(block.position())
            start = block.position()
            block = next_cut(start)
            continue
        block = block.next()
    cuts = [low, *out, high]

    def place(position: int) -> QTextCursor:
        cursor = QTextCursor(document)
        cursor.setPosition(position)
        return cursor

    return [("range", place(a), place(b)) for a, b in zip(cuts, cuts[1:]) if a < b] or [("range", place(low),
                                                                                         place(high))]


def _cuttable(block, root) -> bool:
    """Whether a copy's piece may begin at *block* (_copy_ranges): at a block of the page's top level, or
    in a box of one row - a quote's, an alert's, a code block's - at a block that is not its cell's first
    (never in a formula, never between a table's cells: 20,000 code blocks in a quote had no place to cut,
    every block of it looked at - 0.09 s - and one piece of all of it)."""
    from PyQt6.QtGui import QTextTable

    cursor = QTextCursor(block)
    frame = cursor.currentFrame()
    while frame is not None and frame != root:
        if not isinstance(frame, QTextTable):
            return False
        if frame.rows() != 1 or _formula_tex(frame) is not None:
            return False
        if frame.cellAt(block.position()).firstCursorPosition().block() == block:
            return False
        frame = frame.parentFrame()
    return True


def _copy_text(document: QTextDocument, low: int, high: int) -> str:
    """What a copy holds of *document* from *low* to *high*: its text, a
    display formula's TeX in its place ("$$...$$" on a line of its own - as
    KaTeX's copy; its cells' pieces were scattered over lines), an inline
    one's "$...$". A formula is the table whose first cell holds its TeX's
    anchor - inside a quote, an alert, a list item too (a quote holding one
    was taken for it, its text lost)."""
    if high <= low:
        return ""
    formulas = _formulas_between(document, low, high)
    out, at = [], low
    for first, last, tex in sorted(formulas):
        before = _inline_tex(document, at, max(at, first - 1))
        out.append(before)
        if before and not before.endswith("\n"):
            out.append("\n")
        out.append(f"$${tex.strip()}$$\n")
        at = min(high, last + 1)
    # (the text after the last formula as after any other, its line break kept: a copy in pieces dropped it
    # after each piece's last formula - not as the copy at once did)
    out.append(_inline_tex(document, at, high))
    return "".join(out)


def _formulas_between(document: QTextDocument, low: int, high: int) -> list:
    """(first, last, TeX) of each display formula between *low* and *high* - inside a quote, an alert, a list
    item too. Found from the blocks there, each frame they are in looked at once - not from every frame's
    children: 50,000 code blocks were as many frames, a list of them made at each piece of a copy (0.13 s
    each, 0.42 s a turn), and so were 20,000 in one quote."""
    from PyQt6.QtGui import QTextTable

    root, found, seen = document.rootFrame(), [], set()
    block = document.findBlock(low)
    while block.isValid() and block.position() <= high:
        chain, frame = [], QTextCursor(block).currentFrame()
        while frame is not None and frame != root:
            chain.append(frame)
            frame = frame.parentFrame()
        after = None
        for frame in reversed(chain):  # (the outermost first: a formula's own cells are not looked at)
            first, last = frame.firstPosition(), frame.lastPosition()
            if (first, last) in seen:
                continue
            seen.add((first, last))
            tex = _formula_tex(frame) if isinstance(frame, QTextTable) else None
            if tex is not None:
                if first >= low:  # (begun before the selection: not selected - its text after it is)
                    found.append((first, last, tex))
                after = last
                break
        following = document.findBlock(after + 1) if after is not None else block.next()
        block = following if following.isValid() and following.position() > block.position() else block.next()
    return found


def _inline_tex(document: QTextDocument, low: int, high: int) -> str:
    """The text from *low* to *high*, an inline formula's "$TeX$" in its place.
    One pass over each block's fragments (a formula's end looked for from
    its own fragment on, each block's text read once: from the block's first
    fragment for each of 1,000 formulas, a copy took 7 s)."""
    from ui.markdown_html import TEX_INLINE

    if TEX_INLINE.rstrip(":") not in "".join(_anchors_between(document, low, high)):
        return _plain_between(document, low, high)
    out, at, texts = [], low, {}
    block = document.findBlock(low)
    while block.isValid() and block.position() <= high:
        fragments, pieces = [], block.begin()
        while not pieces.atEnd():
            fragments.append(pieces.fragment())
            pieces += 1
        index = 0
        while index < len(fragments):
            fragment = fragments[index]
            name = _tex_name(fragment.charFormat())
            start = fragment.position()
            index += 1
            if not name.startswith(TEX_INLINE) or not low <= start < high:
                continue
            tex = base64.b64decode(name[len(TEX_INLINE):]).decode("utf-8", "replace")
            # (its other fragments - italic letters, scripts - carry no anchor: up to the next plain one)
            end, family = start + fragment.length(), fragment.charFormat().fontFamilies()
            while index < len(fragments):
                other = fragments[index]
                fmt = other.charFormat()
                if other.position() != end or fmt.fontFamilies() != family or _tex_name(fmt).startswith(TEX_INLINE):
                    break
                end = other.position() + other.length()
                index += 1
            out.append(_plain_between(document, at, start, texts))
            out.append(f"${tex}$")
            at = min(high, end)
        block = block.next()
    out.append(_plain_between(document, at, high, texts))
    return "".join(out)


def _tex_names(document: QTextDocument, start: int = 0) -> None:
    """A formula's anchor of its TeX (ui.markdown_html's) from *start* on
    made its _TEX string - before the part goes into the page."""
    from ui.markdown_html import TEX_ANCHOR, TEX_INLINE

    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    block = document.findBlock(start)
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fragment = pieces.fragment()
            pieces += 1
            fmt = fragment.charFormat()
            if not fmt.isAnchor():
                continue
            names = fmt.anchorNames()
            tex = [name for name in names if name.startswith((TEX_INLINE, TEX_ANCHOR))]
            if not tex:
                if names and not fmt.hasProperty(_NAMED):
                    # (its names as a string too: Qt hashes a format's list of names by its type only - every
                    # heading's anchor fell into one bucket, compared with all of them at each part put in:
                    # 30,000 headings, each part slower than the last, 136 s)
                    fmt.setProperty(_NAMED, "\x1f".join(names))
                    cursor.setPosition(fragment.position())
                    cursor.setPosition(fragment.position() + fragment.length(), QTextCursor.MoveMode.KeepAnchor)
                    cursor.setCharFormat(fmt)
                continue
            fmt.setAnchorNames([name for name in names if name not in tex])
            if not fmt.anchorNames() and not fmt.anchorHref():
                fmt.setAnchor(False)
            fmt.setProperty(_TEX, tex[0])
            cursor.setPosition(fragment.position())
            cursor.setPosition(fragment.position() + fragment.length(), QTextCursor.MoveMode.KeepAnchor)
            cursor.setCharFormat(fmt)
        block = block.next()
    cursor.endEditBlock()


def _tex_name(fmt) -> str:
    """The TeX name a letter's format carries (_TEX - or an anchor's), or ""."""
    from ui.markdown_html import TEX_ANCHOR, TEX_INLINE

    name = fmt.stringProperty(_TEX)
    if name:
        return name
    return next((name for name in fmt.anchorNames() if name.startswith((TEX_INLINE, TEX_ANCHOR))), "") \
        if fmt.isAnchor() else ""


def _anchors_between(document: QTextDocument, low: int, high: int) -> list:
    names = []
    block = document.findBlock(low)
    while block.isValid() and block.position() <= high:
        pieces = block.begin()
        while not pieces.atEnd():
            fmt = pieces.fragment().charFormat()
            names += fmt.anchorNames() + ([fmt.stringProperty(_TEX)] if fmt.hasProperty(_TEX) else [])
            pieces += 1
        block = block.next()
    return names


def _plain_between(document: QTextDocument, low: int, high: int, texts: dict | None = None) -> str:
    """The text of *document* from *low* to *high*, a line a block - block by
    block: a selection that ends inside a table selects all of the table (a
    quote's text came twice). *texts*: the blocks' texts read so far (by
    position) - a block of many formulas read once, not once a formula."""
    if high <= low:
        return ""
    lines, previous = [], None
    block = document.findBlock(low)
    while block.isValid() and block.position() < high:
        start = block.position()
        if _is_seam(block) or (not block.text() and (_is_seam(block.next()) or _is_seam(block.previous()))):
            block = block.next()  # (a cut's block of no height - and the empty ones a table's pieces put
            continue  # around it: no line of the text)
        whole = texts.get(start) if texts is not None else None
        if whole is None:
            whole = block.text()
            if texts is not None:
                texts.clear()  # (one block at a time: the one the formulas are in)
                texts[start] = whole
        text = whole[max(0, low - start):max(0, high - start)]
        if start + len(whole) <= high and not _is_code(block):  # (its line's end: the spaces after it no text)
            text = text.rstrip(" ")
        prefix = _item_prefix(block) if low <= start else ""  # (an item's number or bullet: it was not copied)
        if lines:
            lines.append(_between(previous, block))
        lines.append(prefix + text.replace("\u2028", "\n").replace("\u00a0", " ").replace("\ufffc", ""))
        previous = block
        block = block.next()
    out = "".join(lines)
    ending = document.findBlock(high)
    if ending.position() == high and high > low:  # (up to a block's start: its line ended)
        out += _between(ending.previous(), ending) if lines else "\n"
    return out


def _between(before, block) -> str:
    """What a copy puts between *before* and the next *block*: a tab between
    two cells of a table's row ("h1\th2" - its cells came a line each), a
    space between two lines of a cell, else a line's end. A table of the
    page's - a Markdown table - is one with a border; the boxes of quotes,
    code and formulas are tables without."""
    table = QTextCursor(block).currentTable()
    if table is None or table.format().border() <= 0 or not before.isValid():
        return "\n"
    other = QTextCursor(before).currentTable()
    if other is None or other.firstPosition() != table.firstPosition():
        return "\n"
    here, there = table.cellAt(block.position()), table.cellAt(before.position())
    if here.row() != there.row():
        return "\n"
    return " " if here.column() == there.column() else "\t"

_COPIED_BULLETS = {QTextListFormat.Style.ListDisc: "•", QTextListFormat.Style.ListCircle: "◦",
                   QTextListFormat.Style.ListSquare: "▪"}


def _item_prefix(block) -> str:
    """A list item's number or bullet as a copy writes it - "1. ", "• " - two
    spaces a level in; a task's box is its bullet (its text holds it)."""
    items = block.textList()
    if items is None or _is_code(block):  # (Qt's own parser files an item's code lines in its list: no bullets)
        return ""
    style = items.format().style()
    indent = "  " * max(0, items.format().indent() - 1)
    own = block.blockFormat()
    if own.hasProperty(QTextFormat.Property.ListStyle) and own.intProperty(QTextFormat.Property.ListStyle) == 0:
        return indent  # (a task: "☐ " begins its text)
    if style in _COPIED_BULLETS:
        return indent + _COPIED_BULLETS[style] + " "
    shown = items.itemText(block).strip()
    return indent + (shown + " " if shown else "")


def _formula_tex(table) -> str | None:
    """The TeX of the display formula the table *table* is - its first cell holds its anchor - or None."""
    from ui.markdown_html import TEX_ANCHOR

    cell = table.cellAt(0, 0)
    if not cell.isValid():
        return None
    if table.rows() == 1 and table.columns() == 3 and not cell.firstCursorPosition().block().text():
        # (a formula with its number - "\\tag{B}": the formula in the middle cell, its number at the right
        # - one formula: its number was copied again after its TeX)
        from PyQt6.QtGui import QTextTable

        middle = table.cellAt(0, 1)
        inner = [frame for frame in table.childFrames() if isinstance(frame, QTextTable)
                 and middle.firstCursorPosition().position() <= frame.firstPosition()
                 <= middle.lastCursorPosition().position()]
        if inner:
            return _formula_tex(inner[0])
    block = cell.firstCursorPosition().block()
    pieces = block.begin()
    while not pieces.atEnd():
        name = _tex_name(pieces.fragment().charFormat())
        if name.startswith(TEX_ANCHOR):
            try:
                return base64.b64decode(name[len(TEX_ANCHOR):]).decode("utf-8")
            except ValueError:
                return None
        pieces += 1
    return None

def _written_anchors(text: str) -> set:
    """The anchors a piece of Markdown not parsed yet is likely to have: its
    headings' names (GitHub's), its raw HTML's names and ids, its notes'."""
    names = {slug(line) for line in re.findall(r"(?m)^ {0,3}#{1,6}[ \t]+(.+?)[ \t#]*$", text)}
    names |= set(re.findall(r'(?:name|id)="([^"<>]*)"', text))
    return names


def _escape_html_undone(text: str) -> str:
    """(Qt's own parser's part) its text as read: _escape_html's marks and
    every backslash escape out (find looks in it)."""
    return re.sub(r"\\(.)", r"\1", text.replace(_MARK + "\\", "").replace(_MARK, ""))


class _Unparsed:
    """(a long text's page) the parts of its piece *piece* - not parsed yet."""

    def __init__(self, piece: int) -> None:
        self.piece = piece

    def __len__(self) -> int:  # (its parts' length unknown: its text's, as markdown-it's HTML grows it)
        return 0


#: The <details> of a long text's piece are numbered from its number times this
#: (fold_details): the same whatever piece was parsed first.
DETAILS_SPAN = 100_000


def _size(page: dict, number: int) -> int:
    """How long the page's part *number* is (an unparsed piece: its text, as HTML)."""
    part = page["parts"][number]
    if isinstance(part, _Unparsed):  # (its text as long as HTML as the pieces parsed so far were)
        return int(len(page["texts"][part.piece]) * page.get("ratio", 2.5))
    return len(part)


class _Piece:
    """An image's character of the page (MarkdownView.clamp_images): where, its format."""

    def __init__(self, position: int, fmt) -> None:
        self._position, self._format = position, fmt

    def position(self) -> int:
        return self._position

    def length(self) -> int:
        return 1

    def charFormat(self):  # noqa: N802 - as QTextFragment's
        return self._format


class _PageCopy(QTextDocument):
    """A copy of the page (to print): its images come from the view, as the
    page's own do - QTextDocument would read a local file an image names."""

    def __init__(self, browser: MarkdownBrowser):
        super().__init__(browser)
        self.browser = browser
        self.setIndentWidth(browser.document().indentWidth())

    def loadResource(self, kind, url):  # noqa: N802 - Qt
        return self.browser.loadResource(kind, url)


class ImageZoom(QDialog):
    """An image of the page at its own size (scrolled when bigger than the
    window): + / - zoom, 0 back to its size, F fits it to the window."""

    def __init__(self, image: QImage, name: str, parent=None):
        super().__init__(parent)
        from ui.icon_provider import set_window_icon

        set_window_icon(self, "image")
        self.setWindowTitle(_t("Image: {name}", name=name))
        self.image, self.scale = image, 1.0
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.area = QScrollArea()
        self.area.setWidget(self.label)
        self.area.setWidgetResizable(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.area)
        from ui.close_corner import add_close_corner

        add_close_corner(self)  # (axross's title row and its [x], as every dialog of axross has)
        for keys, slot in (("+", lambda: self.zoom(1.25)), ("=", lambda: self.zoom(1.25)),
                           ("-", lambda: self.zoom(0.8)), ("0", lambda: self.zoom(0)),
                           ("F", self.fit), (QKeySequence.StandardKey.ZoomIn, lambda: self.zoom(1.25)),
                           (QKeySequence.StandardKey.ZoomOut, lambda: self.zoom(0.8))):
            QShortcut(QKeySequence(keys), self).activated.connect(slot)
        screen = self.screen().availableGeometry() if self.screen() else QRect(0, 0, 1280, 800)
        row = layout.itemAt(0).widget().sizeHint().height() if layout.count() > 1 and layout.itemAt(0).widget() \
            else 0  # (the title row's height too: the image was cut by it at its own size)
        self.resize(min(image.width() + 24, screen.width() * 9 // 10),
                    min(image.height() + 24 + row, screen.height() * 9 // 10))
        self.zoom(0)

    def zoom(self, factor: float) -> None:
        """*factor* larger (0: its own size); between 1/20 and 8 times, and
        never more than :data:`ZOOM_PIXELS` pixels."""
        largest = (ZOOM_PIXELS / max(1, self.image.width() * self.image.height())) ** 0.5
        self.scale = 1.0 if factor == 0 else max(0.05, min(8.0, largest, self.scale * factor))
        width = max(1, int(self.image.width() * self.scale))
        height = max(1, int(self.image.height() * self.scale))
        self.label.setPixmap(QPixmap.fromImage(self.image.scaled(
            width, height, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)))

    def fit(self) -> None:
        """As big as the window shows it whole."""
        room = self.area.viewport().size()
        self.scale = 1.0
        self.zoom(min(room.width() / max(1, self.image.width()), room.height() / max(1, self.image.height())))


__all__ = [
    "FEATURES", "IMAGES", "IMAGE_LIMIT", "ImageSource", "ImageZoom", "MarkdownBrowser", "MarkdownView",
    "ZOOM_PIXELS",
    "SUFFIXES", "decode", "in_background", "is_markdown", "printable", "read_text",
    "renderable", "slug", "svg_refers", "with_footnotes", "image_names", "code_span_bounds", "path_functions",
]
