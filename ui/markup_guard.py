"""No text shown by axross can make Qt read a file it names.

Qt renders a label, a tooltip or a message box as rich text when the text
looks like markup (``Qt.mightBeRichText``), and rich text loads the images
it names: ``<img src="/dev/zero">`` in a file name, a link target, an FTP
server's error or an LLM's answer made Qt read ``/dev/zero`` until the
process died (std::bad_alloc), and ``<img src=/proc/kcore>`` or a FIFO
froze it. Escaping each place that shows outside text
(:mod:`ui.plain_text`) closes one widget at a time; this module closes the
class for every widget, also the ones not written yet.

Two parts, installed once when the ``ui`` package is imported
(:func:`install`):

* **Labels, tooltips, message boxes.** Every Python call that hands Qt
  such a text - ``QLabel(text)`` / ``setText``, ``setToolTip`` of widgets,
  actions, tabs and item-view items, ``QToolTip.showText``, the
  ``QMessageBox`` constructor, setters and static functions - goes through
  :func:`defuse`: a text Qt would render as rich text *and* that asks for
  a resource (``<img``, a ``background`` attribute or property, CSS
  ``url(``) - or whose markup asks for an absurd size (a width, height,
  border, font or indent beyond :data:`MAX_LENGTH_PX` / :data:`MAX_FONT_PX`,
  tables or lists nested too deep: a layout bomb) - is shown as plain text
  instead. axross' own rich texts do neither, so they render as before; a
  hostile one reads as what it is. A label set to ``PlainText`` is left
  alone.
* **Progress and input dialogs.** Their label is a QLabel Qt makes in
  C++, so the QLabel wrappers never see its text: ``QProgressDialog(text,
  ...)``, ``setLabelText`` of QProgressDialog and QInputDialog and the
  static ``QInputDialog.getText()`` / ``getItem()`` / ``getInt()`` /
  ``getDouble()`` / ``getMultiLineText()`` show a label that reads as rich
  text as written (:func:`show_as_written`): axross' own labels there are
  plain text, so markup in one came from a name.
* **Links in message boxes.** A QMessageBox label opens links in the web
  browser on a click (``openExternalLinks``), and its texts carry names
  from outside: a remote file named ``x<br><b>verified</b> <a
  href=https://evil.example>report</a>`` turned the Checksum and Overwrite
  questions into a fake notice with a live link. A message box text that
  holds a link is shown as written (:func:`defuse_message`) - axross' own
  message boxes hold none - and the labels of a box made in Python do not
  open links.
* **Text views.** ``QTextEdit`` / ``QTextBrowser`` (the agent transcript,
  Markdown Preview, the scripting guide, the analysis dock) load images
  through :func:`_safe_load_resource`: Qt resources, ``data:`` URLs and
  regular local files up to :data:`MAX_IMAGE_BYTES` load as before; a
  device, a FIFO, a socket, a huge file or anything else gets an empty
  1x1 image - Qt then reads nothing itself.

Item data set by role (``setItemData`` / ``setData`` with ``ToolTipRole``)
is defused too. Item models that answer ``ToolTipRole`` in their own
``data()`` hand their text to Qt in C++, past these wrappers: they call
:func:`defuse` themselves (tests/test_markup_guard.py checks that each
does).
"""

from __future__ import annotations

import functools
import html
import logging
import os
import re
import stat
from html.parser import HTMLParser

log = logging.getLogger(__name__)

#: A local image larger than this is not loaded into rich text (a real
#: picture in a Markdown file is far smaller; /dev/zero has no end).
MAX_IMAGE_BYTES = 32 * 1024 * 1024

#: Tags that make Qt's rich text load a resource: an image, a style sheet
#: (``<link rel=stylesheet>``, a ``<style>`` block with its ``@import``
#: and ``url()``).
_RESOURCE_TAG = re.compile(r"<\s*(?:img|link|style)\b", re.IGNORECASE)
#: What makes a tag load one: a background (attribute or CSS property), a
#: CSS url() or @import.
_RESOURCE_IN_TAG = re.compile(r"@import\b|\bbackground(?:-image)?\s*[=:]|\burl\s*\(",
                              re.IGNORECASE)
_STYLE_ATTRIBUTE_NAME = re.compile(r"\bstyle\s*=", re.IGNORECASE)

_installed = False


def _tag_asks_for_resource(text: str) -> bool:
    """A start tag of *text* that asks for a resource - also once its
    character references are decoded (Qt decodes them in attribute names
    and values: ``b&#97;ckground=``, ``u&#114;l(``) - or whose style
    carries a CSS escape (``\\75rl(``). Outside a tag these words are text
    and load nothing (``url(`` in a chat topic shown with
    Qt.convertFromPlainText)."""
    for match in _TAG.finditer(text):
        raw = match.group(0)
        for tag in (raw, html.unescape(raw)):
            if _RESOURCE_IN_TAG.search(tag):
                return True
            if "\\" in tag and _STYLE_ATTRIBUTE_NAME.search(tag):
                return True
    return False


def asks_for_resource(text) -> bool:
    """True when *text* would be rendered as rich text and load something."""
    if not isinstance(text, str) or "<" not in text:
        return False
    if not _RESOURCE_TAG.search(text) and not _tag_asks_for_resource(text):
        return False
    from PyQt6.QtCore import Qt

    return bool(Qt.mightBeRichText(text))


# -- layout bombs ---------------------------------------------------------------------------
#
# Rich text that loads nothing can still make a widget's size hint absurd:
# ``<table width=40000>``, ``<p style="font-size:4000px">``,
# ``<table border=40000>`` (160000 x 160000), ``-qt-block-indent:1000`` or
# 300 nested lists lay a tooltip or a label out tens of thousands of pixels
# wide, and every nested ``<table>`` doubles the layout time (16 deep took
# 18 s). axross' own rich texts use a few pixels here and there; a text
# that asks for more than these limits is shown as plain text.

#: The largest length (px) a size attribute or style may ask for.
MAX_LENGTH_PX = 2000
#: The largest font size (px) a style may ask for.
MAX_FONT_PX = 200
#: The most rows or columns a span attribute may join: Qt lays out the
#: grid the spans make, and an 841-byte label of ``colspan=99 rowspan=99``
#: cells kept the GUI thread 31 s.
MAX_SPAN = 8
#: The largest ``size`` attribute (a font step is 1-7, a rule's thickness a few px).
MAX_SIZE = 100
#: How deep tables may nest, and lists / quotes (each indents 30-40 px).
MAX_TABLE_DEPTH = 6
MAX_INDENT_DEPTH = 24
#: The most table cells (5000 took 4 s to lay out, 50000 px wide) - the
#: cells of the grid Qt lays out: the ones spans join and the empty ones
#: that fill a short row up to the widest count, and a nested table's
#: count double for each table around it (core.mail_html.TableGrid).
MAX_CELLS = 1000

_NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?"
#: unit -> pixels (em/rem/ex at Qt's default 14 px font)
_PX = {"": 1.0, "px": 1.0, "pt": 4 / 3, "pc": 16.0, "in": 96.0, "cm": 96 / 2.54,
       "mm": 96 / 25.4, "q": 96 / 101.6, "em": 14.0, "rem": 14.0, "ex": 7.0}
_LENGTH = re.compile(rf"({_NUMBER})(px|pt|pc|in|cm|mm|q|rem|em|ex|%)?(?![a-z])",
                     re.IGNORECASE)
#: a start tag, a quoted value with a ">" in it included
_TAG = re.compile(r"<\s*[a-z](?:[^>\"']|\"[^\"]*\"?|'[^']*'?)*", re.IGNORECASE)
#: a size attribute: <table width=…>, <td colspan=…>, <hr size=…>, <font size=…>
_SIZE_ATTRIBUTE = re.compile(
    rf"\b(width|height|cellpadding|cellspacing|border|size|colspan|rowspan)\s*=\s*"
    rf"[\"']?\s*({_NUMBER})\s*(%?)", re.IGNORECASE)
#: a style attribute's value, and a <style> block
_STYLE_ATTRIBUTE = re.compile(r"\bstyle\s*=\s*(?:\"([^\"]*)\"?|'([^']*)'?|([^\s>]*))",
                              re.IGNORECASE)
_STYLE_BLOCK = re.compile(r"<\s*style\b[^>]*>(.*?)(?:<\s*/\s*style|\Z)",
                          re.IGNORECASE | re.DOTALL)
#: a CSS declaration
_DECLARATION = re.compile(r"(-?[a-z][a-z-]*)\s*:\s*([^;{}]*)", re.IGNORECASE)
#: properties whose unitless number Qt multiplies: -> pixels per unit
_UNITLESS = {"-qt-block-indent": 40.0, "-qt-list-indent": 40.0, "line-height": 14.0}
_NESTING = re.compile(r"<\s*(/?)\s*(table|blockquote|ul|ol|dl)\b", re.IGNORECASE)
#: a table, a row or a cell, start or end tag, with its attributes
_GRID_TAG = re.compile(r"<\s*(/?)\s*(table|tr|td|th)\b((?:[^>\"']|\"[^\"]*\"?|'[^']*'?)*)",
                       re.IGNORECASE)


def _number(text: str) -> float:
    try:
        value = abs(float(text))
    except (ValueError, OverflowError):
        return float("inf")
    return value if value == value else float("inf")  # NaN asks for too much


def _too_large_attribute(tag: str) -> bool:
    for match in _SIZE_ATTRIBUTE.finditer(tag):
        name, value = match.group(1).lower(), _number(match.group(2))
        # a span joins cells; a size is a font step (1-7) or a rule's thickness
        if name in ("colspan", "rowspan"):
            if value > MAX_SPAN:
                return True
            continue
        if match.group(3):  # a percentage of the room there is: no bomb
            continue
        if value > (MAX_SIZE if name == "size" else MAX_LENGTH_PX):
            return True
    return False


#: a CSS comment (an unclosed one runs to the end, as in Qt's CSS scanner)
_CSS_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.DOTALL)
#: a CSS escape: ``\66`` (hex, one optional white space after it) or ``\-``
_CSS_ESCAPE = re.compile(r"\\(?:([0-9a-f]{1,6})[ \t\r\n\f]?|(.))", re.IGNORECASE | re.DOTALL)


def _css_char(match) -> str:
    if match.group(1):
        code = int(match.group(1), 16)
        return chr(code) if 0 < code <= 0x10FFFF else "\ufffd"
    return match.group(2)


def _plain_css(css: str) -> str:
    """*css* as Qt's CSS scanner reads it: comments are white space
    (``font-size/**/:4000px`` is ``font-size :4000px`` - the property
    before the colon still counts) and escapes stand for their character."""
    if "/*" in css:
        css = _CSS_COMMENT.sub(" ", css)
    if "\\" in css:
        css = _CSS_ESCAPE.sub(_css_char, css)
    return css


def _too_large_style(css: str) -> bool:
    css = _plain_css(css)
    for match in _DECLARATION.finditer(css):
        prop = match.group(1).lower()
        font = prop in ("font", "font-size")
        limit = MAX_FONT_PX if font else MAX_LENGTH_PX
        for length in _LENGTH.finditer(match.group(2)):
            value, unit = _number(length.group(1)), (length.group(2) or "").lower()
            if unit == "%":
                # a percentage of the font for a font or a line; of the
                # room there is (no bomb) for anything else
                if (font or prop == "line-height") and value / 100 * _PX["em"] > limit:
                    return True
                continue
            if unit == "":
                if prop not in _UNITLESS:
                    continue  # a weight, a colour, an opacity
                value *= _UNITLESS[prop]
            else:
                value *= _PX[unit]
            if value > limit:
                return True
    return False


class _EndTagOffsets(HTMLParser):
    """Where an HTML parser reads an end tag in a text: a ``</table>``
    inside an attribute value (``<i title='</table>'>``) or an HTML comment
    is no tag - Qt lays the table around it out all the same. A
    ``</table>`` the parser reads as a tag closes one; any other one
    closes nothing (counted as open: stricter, never looser)."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=False)
        self.offsets: set[int] = set()
        self._line_starts = [0]
        self._line_starts.extend(m.end() for m in re.finditer("\n", text))
        try:
            self.feed(text)
            self.close()
        except Exception:  # noqa: BLE001 - a text it cannot read closes nothing more
            log.debug("markup guard: HTML parser gave up", exc_info=True)

    def handle_endtag(self, tag) -> None:
        line, column = self.getpos()
        self.offsets.add(self._line_starts[line - 1] + column)


@functools.lru_cache(maxsize=32)
def _end_tag_offsets(text: str) -> frozenset[int]:
    return frozenset(_EndTagOffsets(text).offsets)


def _closes(match, text: str) -> bool:
    """The end tag *match* found (``</table``, ``</ul``) is one an HTML
    parser reads as a tag too - not text in an attribute value or a
    comment."""
    return match.start() in _end_tag_offsets(text)


def _too_many_cells(text: str) -> bool:
    """The tables of *text* lay out more than :data:`MAX_CELLS` grid cells."""
    try:
        from core.mail_html import TableGrid
    except ImportError:
        # A tool exported on its own (export_standalone) carries no mail
        # module: count every cell at its largest span instead - stricter,
        # never looser.
        cells = 0
        for match in _GRID_TAG.finditer(text):
            if match.group(1) or match.group(2).lower() not in ("td", "th"):
                continue
            cells += MAX_SPAN * MAX_SPAN if re.search(r"(?:col|row)span", match.group(0),
                                                      re.IGNORECASE) else 1
        return cells > MAX_CELLS

    grids: list[TableGrid] = []
    cost = 0
    for match in _GRID_TAG.finditer(text):
        closing, tag = match.group(1), match.group(2).lower()
        if tag == "table":
            if closing:
                if grids and _closes(match, text):
                    grids.pop()
            else:
                grids.append(TableGrid())
            continue
        if closing:
            continue
        if not grids:
            cost += tag != "tr"          # a cell outside a table
        else:
            spans = {"colspan": 1, "rowspan": 1}
            if tag != "tr":
                attrs = match.group(3)
                for attr in _SIZE_ATTRIBUTE.finditer(html.unescape(attrs) if "&" in attrs else attrs):
                    name = attr.group(1).lower()
                    if name in spans:
                        spans[name] = max(1, int(min(_number(attr.group(2)), MAX_SPAN)))
            grid = grids[-1]
            cells = grid.new_row() if tag == "tr" else grid.cell(spans["colspan"], spans["rowspan"])
            cost += cells << min(len(grids) - 1, MAX_TABLE_DEPTH)
        if cost > MAX_CELLS:
            return True
    return False


def _too_deep(text: str) -> bool:
    if _too_many_cells(text):
        return True
    depth = {"table": 0, "indent": 0}
    for match in _NESTING.finditer(text):
        kind = "table" if match.group(2).lower() == "table" else "indent"
        if match.group(1):
            if _closes(match, text):
                depth[kind] = max(0, depth[kind] - 1)
            continue
        depth[kind] += 1
        if depth["table"] > MAX_TABLE_DEPTH or depth["indent"] > MAX_INDENT_DEPTH:
            return True
    return False


def _asks_too_much(markup: str) -> bool:
    """The sizes are read where Qt reads them - the attributes of a tag,
    its style, a <style> block - not from the text shown."""
    for tag in _TAG.finditer(markup):
        tag = tag.group(0)
        if '&' in tag:  # Qt reads width=&#52;0000 as 40000
            tag = html.unescape(tag)
        if _too_large_attribute(tag):
            return True
        for style in _STYLE_ATTRIBUTE.finditer(tag):
            if _too_large_style(next(g for g in style.groups() if g is not None)):
                return True
    if any(_too_large_style(block.group(1)) for block in _STYLE_BLOCK.finditer(markup)):
        return True
    return _too_deep(markup)


#: The largest size (px) rich text may lay out to: a few sizes under the
#: limits above still add up (200 letters at letter-spacing 1999px: 402172
#: px; six nested tables with cellpadding, cellspacing and border 1999:
#: 95960 px square, 636 MB once painted), so what passes the checks is
#: laid out once more off screen and measured (:func:`_renders_too_large`).
#: Only what the markup adds counts: a long text is as large as plain text.
MAX_RENDER_WIDTH_PX = 4000
MAX_RENDER_HEIGHT_PX = 5000


def _measure_document():
    """A QTextDocument that loads no resource (the text was checked for
    them before; this one reads nothing all the same)."""
    from PyQt6.QtGui import QImage, QTextDocument

    class _Measure(QTextDocument):
        def loadResource(self, kind, url):  # noqa: N802 - Qt's name
            empty = QImage(1, 1, QImage.Format.Format_ARGB32)
            empty.fill(0)
            return empty

    return _Measure()


def _sizes(document) -> tuple[float, float, float]:
    """(width on one line, width and height wrapped at MAX_RENDER_WIDTH_PX)."""
    document.setTextWidth(-1)
    natural = document.size().width()
    document.setTextWidth(MAX_RENDER_WIDTH_PX)
    wrapped = document.size()
    return natural, wrapped.width(), wrapped.height()


@functools.lru_cache(maxsize=256)
def _rendered_too_large(text: str) -> bool:
    rich = _measure_document()
    rich.setHtml(text)
    plain = _measure_document()
    plain.setPlainText(rich.toPlainText())
    limits = (MAX_RENDER_WIDTH_PX, MAX_RENDER_WIDTH_PX, MAX_RENDER_HEIGHT_PX)
    for got, as_text, limit in zip(_sizes(rich), _sizes(plain), limits):
        # larger than the limit and than the words take as plain text
        if got > max(limit, 2 * as_text + 1000):
            return True
    return False


def _renders_too_large(text: str) -> bool:
    """*text*, laid out as rich text, is wider than
    :data:`MAX_RENDER_WIDTH_PX` (on one line, as a label shows it, or
    wrapped at that width) or taller than :data:`MAX_RENDER_HEIGHT_PX` -
    and than its words take as plain text. Measured on the GUI thread
    only, where labels live (a QTextDocument needs the application's
    fonts); the checks before keep what is measured cheap to lay out
    (tables at most :data:`MAX_TABLE_DEPTH` deep, :data:`MAX_CELLS`
    cells) - and a widget showing it would lay it out anyway - and the
    answer is kept per text."""
    from PyQt6.QtCore import QThread
    from PyQt6.QtGui import QGuiApplication

    if not _MAY_ADD_SIZE.search(text) or _escaped_only(text):
        return False
    app = QGuiApplication.instance()
    if app is None or app.thread() is not QThread.currentThread():
        return False
    return _rendered_too_large(text)


#: Markup that can make text take more room than its words: a tag with an
#: attribute (a style, a size, a padding), a table, preformatted text.
#: ``<b>``, ``<i>``, ``<br>``, a list or a heading take about what the
#: words take; texts with only those are not measured.
_MAY_ADD_SIZE = re.compile(r"<\s*[a-z][^<>]*=|<\s*(?:table|pre)\b", re.IGNORECASE)


def _escaped_only(text: str) -> bool:
    """*text* is a text escaped to show as written (:func:`defuse`,
    :func:`ui.plain_text.as_written`): no markup but its head."""
    for head in (_DEFUSED_HEAD, _AS_WRITTEN_HEAD):
        if text.startswith(head) and text.endswith(_DEFUSED_TAIL) \
                and "<" not in text[len(head):-len(_DEFUSED_TAIL)]:
            return True
    return False


def bombs_layout(text) -> bool:
    """True when *text* would be rendered as rich text whose markup asks
    for an absurd size: a huge width, height, border, font or indent, or
    tables or lists nested too deep - or whose sizes, each small enough,
    add up to a layout wider or taller than :data:`MAX_RENDER_WIDTH_PX` /
    :data:`MAX_RENDER_HEIGHT_PX`."""
    if not isinstance(text, str) or "<" not in text:
        return False
    from PyQt6.QtCore import Qt

    if not Qt.mightBeRichText(text):
        return False
    return _asks_too_much(text) or _renders_too_large(text)


#: What a defused text starts and ends with (the class marks it as ours, so
#: a label switched to PlainText afterwards gets the original back).
_DEFUSED_HEAD = "<qt class='axross-defused' style='white-space:pre-wrap'>"
_DEFUSED_TAIL = "</qt>"


def defuse(text):
    """*text*, or - when Qt would render it as rich text that loads a
    resource or asks for an absurd size - the same text escaped, so it
    shows exactly as written."""
    if not (asks_for_resource(text) or bombs_layout(text)):
        return text
    return f"{_DEFUSED_HEAD}{html.escape(text)}{_DEFUSED_TAIL}"


#: A start tag of a link (``<a href=…>``, ``<A\nhref=…>``).
_LINK_TAG = re.compile(r"<\s*a(?=[\s>/])", re.IGNORECASE)


def holds_link(text) -> bool:
    """True when *text* would be rendered as rich text with a link in it."""
    if not isinstance(text, str) or "<" not in text or not _LINK_TAG.search(text):
        return False
    from PyQt6.QtCore import Qt

    return bool(Qt.mightBeRichText(text))


#: An HTML comment: as rich text it hides the rest of the text.
_COMMENT = "<!--"


def defuse_message(text):
    """:func:`defuse` for a message box text: a link (opened in the browser
    on a click) is shown as written too, and so is a text with an HTML
    comment in it - a file named ``report.pdf - <b>scan finished: no
    threats.</b><!--`` hid the error after it ("Could not open {name}:
    {error}") and put a verdict of its own there. axross' own message
    texts hold neither."""
    if holds_link(text) or (isinstance(text, str) and _COMMENT in text and _rich(text)):
        return f"{_DEFUSED_HEAD}{html.escape(text)}{_DEFUSED_TAIL}"
    return defuse(text)


def _rich(text: str) -> bool:
    from PyQt6.QtCore import Qt

    return bool(Qt.mightBeRichText(text))


#: The head of a text :func:`ui.plain_text.as_written` escaped.
_AS_WRITTEN_HEAD = "<qt style='white-space:pre-wrap'>"


def show_as_written(text):
    """*text* for the label of a progress or input dialog: shown exactly as
    written when Qt would render it as rich text. axross' own labels of
    these dialogs are plain text, so markup in one came from a name (an
    archive member, a remote file) - rendered, ``<img src=/dev/zero>``
    made Qt read the device until the process died. A text already
    escaped (:func:`defuse`, :func:`ui.plain_text.as_written`) is left as
    it is."""
    if not isinstance(text, str) or "<" not in text:
        return text
    if _escaped_only(text):
        return text
    from PyQt6.QtCore import Qt

    if not Qt.mightBeRichText(text):
        return text
    return f"{_DEFUSED_HEAD}{html.escape(text)}{_DEFUSED_TAIL}"


def original_of(text):
    """The text :func:`defuse` was given for *text*, or *text* itself."""
    if isinstance(text, str) and text.startswith(_DEFUSED_HEAD) and text.endswith(_DEFUSED_TAIL):
        return html.unescape(text[len(_DEFUSED_HEAD):-len(_DEFUSED_TAIL)])
    return text


def _wrap_set_text_format(cls, getters_setters) -> None:
    """``QLabel(text)`` then ``setTextFormat(PlainText)`` - a common order:
    the text was defused while the format was AutoText; switched to plain
    text it is shown as written again (plain text loads nothing)."""
    from PyQt6.QtCore import Qt

    original = cls.setTextFormat

    @functools.wraps(original)
    def wrapper(self, fmt):
        original(self, fmt)
        if fmt == Qt.TextFormat.PlainText:
            for get, put in getters_setters:
                current = getattr(self, get)()
                restored = original_of(current)
                if restored is not current:
                    getattr(self, put)(restored)

    cls.setTextFormat = wrapper


# -- the wrappers ---------------------------------------------------------------------------

def _wrap_text_at(cls, name: str, index: int, *, unless_plain: bool = False,
                  fn=None, after=None) -> None:
    """Wrap ``cls.name`` so its positional argument *index* is defused
    (by *fn*, default :func:`defuse`); *after(self)* runs after the call."""
    original = getattr(cls, name)
    fn = fn or defuse

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        # defuse() hands back anything but a str with a "<" as it is: the
        # rest is not looked at (setToolTip runs for every item of a list).
        if len(args) > index:
            value = args[index]
            if isinstance(value, str) and "<" in value \
                    and not (unless_plain and _is_plain(self)):
                args = list(args)
                args[index] = fn(value)
        result = original(self, *args, **kwargs)
        if after is not None:
            after(self)
        return result

    setattr(cls, name, wrapper)


def _wrap_static_text_at(cls, name: str, index: int, fn=None, keyword: str = "text") -> None:
    """Wrap the static ``cls.name`` so its positional argument *index* (or
    the one given as *keyword*) is defused by *fn*."""
    original = getattr(cls, name)
    fn = fn or defuse

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        if len(args) > index:
            args = list(args)
            args[index] = fn(args[index])
        if keyword in kwargs:
            kwargs[keyword] = fn(kwargs[keyword])
        return original(*args, **kwargs)

    setattr(cls, name, staticmethod(wrapper))


def _is_plain(widget) -> bool:
    from PyQt6.QtCore import Qt

    try:
        return widget.textFormat() == Qt.TextFormat.PlainText
    except AttributeError:
        pass
    except RuntimeError:
        return False
    # A dialog whose labels Qt made (QProgressDialog, QInputDialog): plain
    # once every one of them was switched to PlainText.
    from PyQt6.QtWidgets import QLabel

    try:
        labels = widget.findChildren(QLabel)
        return bool(labels) and all(label.textFormat() == Qt.TextFormat.PlainText
                                    for label in labels)
    except (AttributeError, RuntimeError):
        return False


def _wrap_label_init(cls) -> None:
    """``QProgressDialog(labelText, ...)``: the first argument, a str, is
    the label Qt makes in C++ (AutoText) - shown as written when it reads
    as rich text (:func:`show_as_written`)."""
    original = cls.__init__

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        if args and isinstance(args[0], str):
            args = (show_as_written(args[0]), *args[1:])
        original(self, *args, **kwargs)

    cls.__init__ = wrapper


def _wrap_role_data(cls, name: str, role_index: int, value_index: int) -> None:
    """Wrap ``cls.name`` (setData / setItemData) so a ToolTipRole value is
    defused: ``combo.setItemData(i, text, ToolTipRole)`` and friends -
    positional or by keyword (``setData(text, role=ToolTipRole)``).

    setData is virtual: once wrapped, sip routes Qt's own calls through
    here too (setText, setEditable, setFlags, setIcon all set data) -
    300,000 calls for a 50,000-member archive tree. So the common answer
    comes first and costs no more than a type test: only a str holding a
    "<" can be what defuse() changes (it hands every other value back
    as it is), and only then is the role compared."""
    from PyQt6.QtCore import Qt

    original = getattr(cls, name)
    tooltip = int(Qt.ItemDataRole.ToolTipRole)
    needed = max(role_index, value_index)

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        if kwargs:
            count = len(args)
            value = args[value_index] if value_index < count else kwargs.get("value")
            if isinstance(value, str) and "<" in value:
                role = args[role_index] if role_index < count else kwargs.get("role")
                if role == tooltip:
                    if value_index < count:
                        args = list(args)
                        args[value_index] = defuse(value)
                    else:
                        kwargs["value"] = defuse(value)
        elif len(args) > needed:
            value = args[value_index]
            if isinstance(value, str) and "<" in value and args[role_index] == tooltip:
                args = list(args)
                args[value_index] = defuse(value)
        return original(self, *args, **kwargs)

    setattr(cls, name, wrapper)


def _wrap_init_strings(cls, fn=None, after=None) -> None:
    """Defuse every str argument of ``cls(...)`` (QLabel(text, parent),
    QMessageBox(icon, title, text, ...)): the text format is AutoText then.
    *fn* defuses (default :func:`defuse`); *after(self)* runs at the end."""
    original = cls.__init__
    fn = fn or defuse

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        args = [fn(a) if isinstance(a, str) else a for a in args]
        if "text" in kwargs:
            kwargs["text"] = fn(kwargs["text"])
        original(self, *args, **kwargs)
        if after is not None:
            after(self)

    cls.__init__ = wrapper


def _no_external_links(box) -> None:
    """The labels of message box *box* do not open links in the browser
    (QMessageBox turns ``openExternalLinks`` on for them)."""
    from PyQt6.QtWidgets import QLabel

    try:
        for label in box.findChildren(QLabel):
            if label.openExternalLinks():
                label.setOpenExternalLinks(False)
    except RuntimeError:  # the C++ object is gone
        pass


def _local_path(url) -> str | None:
    """The local file *url* names, or None for anything else."""
    if url.isLocalFile():
        return url.toLocalFile()
    if url.scheme() == "" and url.path():
        return url.path()
    return None


def _loadable(path: str) -> bool:
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size <= MAX_IMAGE_BYTES


def _safe_load_resource(original):
    @functools.wraps(original)
    def load_resource(self, kind, url):
        from PyQt6.QtGui import QImage

        scheme = url.scheme().lower()
        if scheme in ("qrc", "data") or url.toString().startswith(":/"):
            return original(self, kind, url)
        path = _local_path(url)
        if path is not None:
            if not os.path.isabs(path):
                base = _base_folder(self)
                path = os.path.join(base, path) if base else None
            if path is not None and _loadable(path):
                return original(self, kind, url)
        log.debug("rich text resource refused: %s", url.toString()[:200])
        empty = QImage(1, 1, QImage.Format.Format_ARGB32)
        empty.fill(0)
        return empty

    return load_resource


def _base_folder(view) -> str | None:
    """The folder a relative image of *view* is read from (a QTextBrowser's
    source, else the document's base URL), or None."""
    for get in (getattr(view, "source", None),
                lambda: view.document().baseUrl()):
        if get is None:
            continue
        try:
            url = get()
        except (RuntimeError, TypeError):
            continue
        if url is not None and url.isLocalFile():
            local = url.toLocalFile()
            return local if os.path.isdir(local) else os.path.dirname(local)
    return None


def install() -> None:
    """Install the wrappers (once per process)."""
    global _installed
    if _installed:
        return
    _installed = True
    from PyQt6.QtGui import QAction, QStandardItem
    from PyQt6.QtWidgets import (
        QComboBox,
        QInputDialog,
        QLabel,
        QListWidgetItem,
        QMessageBox,
        QProgressDialog,
        QTabBar,
        QTableWidgetItem,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolTip,
        QTreeWidgetItem,
        QWidget,
    )

    _wrap_init_strings(QLabel)
    _wrap_text_at(QLabel, "setText", 0, unless_plain=True)
    _wrap_set_text_format(QLabel, (("text", "setText"),))
    _wrap_init_strings(QMessageBox, defuse_message, _no_external_links)
    for name in ("setText", "setInformativeText"):
        _wrap_text_at(QMessageBox, name, 0, unless_plain=True, fn=defuse_message,
                      after=_no_external_links)
    _wrap_set_text_format(QMessageBox, (("text", "setText"),
                                        ("informativeText", "setInformativeText")))
    for name in ("warning", "critical", "information", "question", "about"):
        _wrap_static_text_at(QMessageBox, name, 2, defuse_message)
    _wrap_static_text_at(QToolTip, "showText", 1)
    # Progress and input dialogs: their label is a QLabel Qt makes in C++
    # (AutoText), past the QLabel wrappers above - also the one of the
    # static QInputDialog.getText() and friends.
    _wrap_label_init(QProgressDialog)
    for cls in (QProgressDialog, QInputDialog):
        _wrap_text_at(cls, "setLabelText", 0, unless_plain=True, fn=show_as_written)
    for name in ("getText", "getMultiLineText", "getItem", "getInt", "getDouble"):
        # (PyQt takes the label positionally only; "text" is the answer.)
        _wrap_static_text_at(QInputDialog, name, 2, show_as_written, keyword="label")
    for cls in (QWidget, QAction, QListWidgetItem, QStandardItem):
        _wrap_text_at(cls, "setToolTip", 0)
    for cls in (QTreeWidgetItem,):
        _wrap_text_at(cls, "setToolTip", 1)
    _wrap_text_at(QTableWidgetItem, "setToolTip", 0)
    for cls in (QTabWidget, QTabBar):
        _wrap_text_at(cls, "setTabToolTip", 1)
    # item data set by role: (role index, value index) of each setter
    _wrap_role_data(QComboBox, "setItemData", 2, 1)       # (index, value, role)
    _wrap_role_data(QStandardItem, "setData", 1, 0)       # (value, role)
    _wrap_role_data(QListWidgetItem, "setData", 0, 1)     # (role, value)
    _wrap_role_data(QTableWidgetItem, "setData", 0, 1)    # (role, value)
    _wrap_role_data(QTreeWidgetItem, "setData", 1, 2)     # (column, role, value)
    for cls in (QTextEdit, QTextBrowser):
        cls.loadResource = _safe_load_resource(cls.loadResource)


__all__ = ["MAX_CELLS", "MAX_FONT_PX", "MAX_IMAGE_BYTES", "MAX_INDENT_DEPTH", "MAX_LENGTH_PX",
           "MAX_RENDER_HEIGHT_PX", "MAX_RENDER_WIDTH_PX", "MAX_SIZE", "MAX_SPAN",
           "MAX_TABLE_DEPTH", "asks_for_resource", "bombs_layout", "defuse", "defuse_message",
           "holds_link", "install", "original_of", "show_as_written"]
