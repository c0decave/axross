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
#: The most cells a span attribute may join (and the largest size attribute).
MAX_SPAN = 100
#: How deep tables may nest, and lists / quotes (each indents 30-40 px).
MAX_TABLE_DEPTH = 6
MAX_INDENT_DEPTH = 24
#: The most table cells (5000 took 4 s to lay out, 50000 px wide).
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
_CELL = re.compile(r"<\s*t[dh]\b", re.IGNORECASE)


def _number(text: str) -> float:
    try:
        value = abs(float(text))
    except (ValueError, OverflowError):
        return float("inf")
    return value if value == value else float("inf")  # NaN asks for too much


def _too_large_attribute(tag: str) -> bool:
    for match in _SIZE_ATTRIBUTE.finditer(tag):
        name, value = match.group(1).lower(), _number(match.group(2))
        if match.group(3):  # a percentage of the room there is: no bomb
            continue
        # a span joins cells; a size is a font step (1-7) or a rule's thickness
        if value > (MAX_SPAN if name in ("colspan", "rowspan", "size") else MAX_LENGTH_PX):
            return True
    return False


def _too_large_style(css: str) -> bool:
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


def _too_deep(text: str) -> bool:
    if len(_CELL.findall(text)) > MAX_CELLS:
        return True
    depth = {"table": 0, "indent": 0}
    for match in _NESTING.finditer(text):
        kind = "table" if match.group(2).lower() == "table" else "indent"
        depth[kind] = max(0, depth[kind] + (-1 if match.group(1) else 1))
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


def bombs_layout(text) -> bool:
    """True when *text* would be rendered as rich text whose markup asks
    for an absurd size: a huge width, height, border, font or indent, or
    tables or lists nested too deep."""
    if not isinstance(text, str) or "<" not in text or not _asks_too_much(text):
        return False
    from PyQt6.QtCore import Qt

    return bool(Qt.mightBeRichText(text))


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


def defuse_message(text):
    """:func:`defuse` for a message box text: a link (opened in the browser
    on a click) is shown as written too."""
    if holds_link(text):
        return f"{_DEFUSED_HEAD}{html.escape(text)}{_DEFUSED_TAIL}"
    return defuse(text)


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
    for head in (_DEFUSED_HEAD, _AS_WRITTEN_HEAD):
        if text.startswith(head) and text.endswith(_DEFUSED_TAIL) \
                and "<" not in text[len(head):-len(_DEFUSED_TAIL)]:
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


__all__ = ["MAX_CELLS", "MAX_FONT_PX","MAX_IMAGE_BYTES", "MAX_INDENT_DEPTH", "MAX_LENGTH_PX", "MAX_SPAN",
           "MAX_TABLE_DEPTH", "asks_for_resource", "bombs_layout", "defuse", "defuse_message",
           "holds_link", "install", "original_of", "show_as_written"]
