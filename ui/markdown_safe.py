"""Markdown that cannot carry HTML: the feature flags by value and the
escaping of every ``<`` (shared by the release notes, ui.update_ui, and the
Markdown viewer, ui.markdown_view).

Its own small module so a program exported without axross's updater
(axross-markdown) carries only this.
"""

from __future__ import annotations

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


#: Marks each backslash :func:`_escape_html` adds (WORD JOINER: invisible,
#: no Markdown syntax), so :func:`_unmark` finds exactly those again.
_MARK = "\u2060"


def _escape_html(text: str) -> str:
    """*text* with every ``<`` as a Markdown backslash escape.

    Raw HTML (inline or block) and autolinks all begin with ``<``; ``\\<``
    is a literal ``<`` in every dialect, with HTML enabled or not. A
    ``<`` already escaped (after an odd run of backslashes) stays as is;
    after an even run the added backslash escapes the ``<``, not one of
    them. In a code span or block a backslash is literal - there the
    added one is taken out again after rendering (:func:`_unmark`)."""
    out: list[str] = []
    backslashes = 0
    for ch in text:
        if ch == "<" and backslashes % 2 == 0:
            out.append(_MARK + "\\")
        out.append(ch)
        backslashes = backslashes + 1 if ch == "\\" else 0
    return "".join(out)


def _unmark(document: QTextDocument) -> None:
    """Remove what :func:`_escape_html` added from the rendered document:
    the mark, and the backslash after it where it stayed (code). Only
    characters go; the HTML question was settled by the parser."""
    # The marks are found in the document's raw text (a position there is
    # a position in the document) and taken out from the last one back, so
    # the places before stay where they are: QTextDocument.find() from
    # each mark again took 2.4 s for 20,000 "<" (quadratic).
    raw = document.toRawText()
    cursor = QTextCursor(document)
    cursor.beginEditBlock()
    start = raw.rfind(_MARK)
    while start >= 0:
        added = raw[start + 1:start + 3] == "\\<"
        cursor.setPosition(start)
        cursor.setPosition(start + (2 if added else 1), QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        start = raw.rfind(_MARK, 0, start)
    cursor.endEditBlock()


def _visible_controls(text: str) -> str:
    """*text* with every control and format character (bidi overrides and
    isolates, zero-width characters, line breaks …) written as ``\\uXXXX``:
    what the question shows is what the address is, in reading order."""
    import unicodedata

    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")
                   else c for c in text)


def open_link_question(href: str, text: str) -> str:
    """The body of the Open Link question: the address fully encoded (an
    IDN host as punycode, ``xn--…``, never its look-alike letters; bidi
    controls of the path percent-encoded), its host on a line of its own,
    and the link's text - with controls made visible - when it differs."""
    url = QUrl(href)
    shown = bytes(url.toEncoded()).decode("ascii", "replace") if url.isValid() else href
    shown = _visible_controls(shown)
    body = tr("Open this address in your web browser?") + "\n\n" + shown
    host = url.host(QUrl.ComponentFormattingOption.FullyEncoded)
    if host:
        body += "\n\n" + tr("Host: {host}").format(host=_visible_controls(host))
    text = (text or "").strip()
    if text and text != href and text != shown:
        body += "\n\n" + tr("The link in the notes reads: {text}").format(
            text=_visible_controls(text[:300]))
    return body


def ask_open_link(parent, href: str, text: str) -> bool:
    """Ask before a link of the release notes opens in the browser: the
    notes come from the release page, and a link's text can name another
    address than it opens - the real one is shown (:func:`open_link_question`),
    and the text too when it differs."""
    from PyQt6.QtWidgets import QMessageBox

    body = open_link_question(href, text)
    box = QMessageBox(QMessageBox.Icon.Question, tr("Open Link"), body,
                      QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Cancel, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    return box.exec() == QMessageBox.StandardButton.Open
