"""Markdown that cannot carry HTML: the feature flags by value and the
escaping of every ``<`` (shared by the release notes, ui.update_ui, and the
Markdown viewer, ui.markdown_view).

Its own small module so a program exported without axross's updater
(axross-markdown) carries only this.
"""

from __future__ import annotations

import re

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QTextCursor, QTextDocument

from core.i18n import tr


def _markdown_features(*features: QTextDocument.MarkdownFeature) -> QTextDocument.MarkdownFeature:
    """The union of Qt Markdown *features*. Every member of MarkdownFeature
    has several bits, and Python 3.11's enum (3.11.2, Debian 12's, at least)
    derives a Flag's mask from its one-bit members only: ``|`` and the
    constructor dropped every bit - GitHub | NoHTML was CommonMark *with*
    raw HTML. Then the union is made by hand, which Qt reads by its value."""
    value = 0
    for feature in features:
        value |= feature.value
    return _markdown_feature(value)


def _feature_member(value: int) -> QTextDocument.MarkdownFeature:
    """``MarkdownFeature(value)`` (its own function so a test can make it
    behave like Python 3.12)."""
    return QTextDocument.MarkdownFeature(value)


def _markdown_feature(value: int) -> QTextDocument.MarkdownFeature:
    """The Qt Markdown feature set of the bits *value* (see above)."""
    try:
        union = _feature_member(value)
    except ValueError:
        # Python 3.12's enum refuses a value that is no member (3.11 gave a
        # member with fewer bits): the main window did not start at all.
        union = None
    if union is None or union.value != value:
        union = object.__new__(QTextDocument.MarkdownFeature)
        union._value_ = value
        union._name_ = None
    return union


#: Qt's GitHub Markdown, without raw HTML: an HTML span or block in the
#: notes is shown as the text it is (with HTML, Qt interprets it: a
#: <script> block swallowed the rest of the notes in a test). Safety does
#: not rest on these flags: :func:`_escape_html` takes every ``<`` out of
#: the notes first, so ``NOTES_MARKDOWN | X`` losing its bits on some
#: Python (see above) costs tables and strike-through, never raw HTML.
NOTES_MARKDOWN = _markdown_features(QTextDocument.MarkdownFeature.MarkdownDialectGitHub,
                                    QTextDocument.MarkdownFeature.MarkdownNoHTML)


#: Marks each backslash :func:`_escape_html` adds - a character of Unicode's
#: private use area, no Markdown syntax, taken out of the text first: so
#: :func:`_unmark` finds exactly those again. (It was WORD JOINER, which a
#: text may hold: the author's own ones went too.)
_MARK = "\ue05c"
#: A character beyond the BMP: two UTF-16 units (a QTextDocument position each).
_WIDE = re.compile("[\U00010000-\U0010ffff]")


#: A CommonMark autolink: ``<scheme:…>`` (a scheme of 2-32 characters, no
#: space, ``<`` or ``>`` in it) and ``<user@host>``.
_AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.\-]{1,31}:[^<>\x00-\x20]*)>"
                       r"|<([A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}"
                       r"[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*)>")
_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")


def _as_link(match: re.Match) -> str:
    """An autolink as an inline link: its text with every punctuation
    character escaped (no emphasis, no bracket comes out of it), its
    address with the characters that would end a destination encoded."""
    url, mail = match.group(1), match.group(2)
    shown = url or mail
    target = url if url else f"mailto:{mail}"
    text = "".join("\\" + c if c in _PUNCTUATION else c for c in shown)
    # (a backtick too: one in the address began a code span there - "<http://foo.bar.`baz>`" showed its
    # markup, the spec's 356; CommonMark's link has %60 in its address as well)
    target = target.replace("\\", "%5C").replace("(", "%28").replace(")", "%29").replace("`", "%60")
    return f"[{text}]({target})"


def _autolinks(text: str) -> str:
    """*text* with its autolinks (``<https://…>``) written as inline links,
    which survive :func:`_escape_html` (it takes every ``<``, autolinks
    too: Qt's parser showed them as text). Code - fenced (also in a quote
    or a list), indented, in backticks - is left as written, and so is a
    ``\\<`` escaped. Linear in the length of the text."""
    if "<" not in text:
        return text
    out: list[str] = []
    fence = ""
    for line in text.splitlines(keepends=True):
        body = _CONTAINERS.match(line)
        rest = line[body.end():] if body else line
        opener = _FENCE.match(rest)
        if fence:
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence) \
                    and not rest.strip().strip(fence[0]):
                fence = ""
            out.append(line)
            continue
        if opener:
            fence = opener.group(1)
            out.append(line)
            continue
        if line.startswith(("    ", "\t")) or "<" not in line:
            out.append(line)  # (indented code, or nothing to do)
            continue
        out.append(_autolinks_in_line(line))
    return "".join(out)


#: What a line of a quote or a list item starts with (``> ``, ``- ``, ``1. ``).
_CONTAINERS = re.compile(r"(?:[ \t]*(?:>|[-+*]|\d{1,9}[.)])(?=[ \t]|$))*[ \t]*")
_BACKTICKS = re.compile(r"`+")
#: Schemes markdown-it's validateLink refuses: such an autolink stays text.
_UNSAFE_SCHEMES = frozenset({"javascript", "vbscript", "file", "data"})


def _autolinks_in_line(line: str) -> str:
    """One line: autolinks outside code spans as inline links. A code span
    runs from a run of backticks to the next run of the same length (the
    runs found once, so a line full of unmatched ones stays linear)."""
    runs: dict[int, list[int]] = {}
    for m in _BACKTICKS.finditer(line):
        runs.setdefault(m.end() - m.start(), []).append(m.start())
    taken: dict[int, int] = {length: 0 for length in runs}
    out: list[str] = []
    i = 0
    backslashes = 0
    while i < len(line):
        ch = line[i]
        if ch == "`":
            m = _BACKTICKS.match(line, i)
            length = m.end() - m.start()
            starts = runs[length]
            # the next run of this length after this one closes the span
            k = taken[length]
            while k < len(starts) and starts[k] <= i:
                k += 1
            taken[length] = k
            end = starts[k] + length if k < len(starts) else m.end()
            if k < len(starts):
                taken[length] = k + 1
            out.append(line[i:end])
            i = end
            backslashes = 0
            continue
        if ch == "<" and backslashes % 2 == 0:
            match = _AUTOLINK.match(line, i)
            if match and match.group(1) and \
                    match.group(1).split(":", 1)[0].lower() in _UNSAFE_SCHEMES:
                match = None  # (as markdown-it's validateLink: left as text)
            if match:
                out.append(_as_link(match))
                i = match.end()
                backslashes = 0
                continue
        out.append(ch)
        backslashes = backslashes + 1 if ch == "\\" else 0
        i += 1
    return "".join(out)


def _escape_html(text: str) -> str:
    """*text* with every ``<`` as a Markdown backslash escape (its autolinks
    first written as inline links: :func:`_autolinks`).

    Raw HTML (inline or block) and autolinks all begin with ``<``; ``\\<``
    is a literal ``<`` in every dialect, with HTML enabled or not. A
    ``<`` already escaped (after an odd run of backslashes) stays as is;
    after an even run the added backslash escapes the ``<``, not one of
    them. In a code span or block a backslash is literal - there the
    added one is taken out again after rendering (:func:`_unmark`)."""
    text = _autolinks(text.replace(_MARK, ""))
    out: list[str] = []
    backslashes = 0
    for ch in text:
        if ch == "<" and backslashes % 2 == 0:
            out.append(_MARK + "\\")
        out.append(ch)
        backslashes = backslashes + 1 if ch == "\\" else 0
    return "".join(out)


def _unmark(document: QTextDocument, since: int = 0) -> None:
    """Remove what :func:`_escape_html` added from the rendered document
    (from position *since* on: a part of a page as it comes in): the mark,
    and the backslash after it where it stayed (code). Only characters go;
    the HTML question was settled by the parser."""
    # The marks are found in the blocks' texts from *since* on (the raw text of all of the page, read for each
    # part, was 0.013 s of each part's turn of a big table) and taken out from the last one back, so the
    # places before stay where they are: QTextDocument.find() from each mark again took 2.4 s for 20,000 "<"
    # (quadratic).
    marks = []  # (the mark's position in the document, whether "\\<" follows it)
    block = document.findBlock(since)
    while block.isValid():
        text = block.text()
        if _MARK in text:
            # (a position in the document counts UTF-16 units, a Python index characters: each character beyond
            # the BMP (an emoji) before a mark moves it one further - the wrong characters went, after an emoji)
            wide = [m.start() for m in _WIDE.finditer(text)] if not text.isascii() else []
            before, base = 0, block.position()
            for found in re.finditer(_MARK, text):
                start = found.start()
                while before < len(wide) and wide[before] < start:
                    before += 1
                if base + start + before >= since:
                    marks.append((base + start + before, text[start + 1:start + 3] == "\\<"))
        block = block.next()
    if not marks:
        return
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    for position, added in reversed(marks):
        cursor.setPosition(position)
        cursor.setPosition(position + (2 if added else 1), QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
    _unmark_targets(document, cursor, since)
    cursor.endEditBlock()


def _unmark_targets(document: QTextDocument, cursor: QTextCursor, since: int = 0) -> None:
    """The marks out of what is no text of the page: a link's target and an
    image's name ("[q](https://x.com/?a=<b>)" opened "?a=<mark><b>"). A walk
    over the page's pieces; only those holding a mark are changed."""
    changes = []
    block = document.findBlock(since)
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            piece = pieces.fragment()
            fmt = piece.charFormat()
            if fmt.isImageFormat() and _MARK in fmt.toImageFormat().name():
                image = fmt.toImageFormat()
                image.setName(image.name().replace(_MARK, ""))
                changes.append((piece.position(), piece.length(), image))
            elif fmt.isAnchor() and _MARK in fmt.anchorHref():
                fmt.setAnchorHref(fmt.anchorHref().replace(_MARK, ""))
                changes.append((piece.position(), piece.length(), fmt))
            pieces += 1
        block = block.next()
    for position, length, fmt in changes:
        cursor.setPosition(position)
        cursor.setPosition(position + length, QTextCursor.MoveMode.KeepAnchor)
        cursor.setCharFormat(fmt)


def _visible_controls(text: str) -> str:
    """*text* with every control and format character (bidi overrides and
    isolates, zero-width characters, line breaks …) written as ``\\uXXXX``:
    what the question shows is what the address is, in reading order."""
    import unicodedata

    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")
                   else c for c in text)


#: Characters of an address the question shows (a longer one is cut, its
#: length said), and of each of its lines (a long one made the box as wide
#: as the screen and more).
ADDRESS_SHOWN = 1000
LINE_SHOWN = 80


def _lines(text: str) -> str:
    """*text* in lines of at most LINE_SHOWN characters."""
    return "\n".join(text[i:i + LINE_SHOWN] for i in range(0, len(text), LINE_SHOWN)) or text


def open_link_question(href: str, text: str, where: str = "notes") -> str:
    """The body of the Open Link question: the address fully encoded (an
    IDN host as punycode, ``xn--…``, never its look-alike letters; bidi
    controls of the path percent-encoded; a long one cut, its length said,
    in lines), its host on a line of its own, and the link's text - with
    controls made visible - when it differs (*where* the link is: the
    release "notes" or a "document")."""
    url = QUrl(href)
    shown = bytes(url.toEncoded()).decode("ascii", "replace") if url.isValid() else href
    shown = _visible_controls(shown)
    if len(shown) > ADDRESS_SHOWN:
        shown = shown[:ADDRESS_SHOWN] + "… " + tr("({count} characters)").format(count=len(shown))
    question = (tr("Write to this address with your mail program?") if url.scheme().lower() == "mailto"
                else tr("Open this address in your web browser?"))
    body = question + "\n\n" + _lines(shown)
    host = url.host(QUrl.ComponentFormattingOption.FullyEncoded)
    if host:
        body += "\n\n" + tr("Host: {host}").format(host=_lines(_visible_controls(host)))
    text = (text or "").strip()
    if text and text != href and text != shown:
        reads = (tr("The link in the document reads: {text}") if where == "document"
                 else tr("The link in the notes reads: {text}"))
        body += "\n\n" + _lines(reads.format(text=_visible_controls(text[:300])))
    return body


def ask_open_link(parent, href: str, text: str, where: str = "notes") -> bool:
    """Ask before a link opens in the browser (the release notes', a
    Markdown document's): a link's text can name another address than it
    opens - the real one is shown (:func:`open_link_question`), and the text
    too when it differs."""
    from PyQt6.QtWidgets import QMessageBox

    body = open_link_question(href, text, where)
    box = QMessageBox(QMessageBox.Icon.Question, tr("Open Link"), body,
                      QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Cancel, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    return box.exec() == QMessageBox.StandardButton.Open
