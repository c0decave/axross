"""The Markdown view: a file rendered as Markdown (CommonMark and GitHub's
tables, task lists, strikethrough and autolinks; footnotes made into links),
its headings in an outline beside it to jump to, fenced code highlighted,
images beside the file shown, zoom.

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
  to the file's folder (never an absolute path, ``file:`` or any other
  scheme), in a thread, only a regular file, never a secret file
  (:func:`core.protected_places.read_refusal` on the local file system), at
  most :data:`IMAGE_LIMIT` bytes and :data:`IMAGE_PIXELS` pixels, at most
  :data:`IMAGES` of them and :data:`IMAGES_PIXELS` pixels together; Reload
  reads them again; an SVG image that names anything but a part of itself
  is not shown (Qt's SVG reader would read the files it names:
  :func:`svg_refers`);
- what Qt cannot lay out in time is not rendered: the rendering ends before
  the line that goes past :data:`LIST_ITEMS` list items, :data:`TABLE_ROWS`
  table rows or :data:`LONG_RUN` characters without a space, and says so
  (:func:`renderable`);
- a link is never followed inside the view: ``#heading`` scrolls there,
  anything else goes to the window (:attr:`MarkdownView.link`), which
  decides.
"""

from __future__ import annotations

import base64
import logging
import posixpath
import re
import stat as _stat
import threading
import time
import unicodedata

from PyQt6 import sip
from PyQt6.QtCore import (
    QBuffer,
    QByteArray,
    QIODevice,
    QObject,
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
    QPainter,
    QPalette,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QTextFormat,
)
from PyQt6.QtWidgets import (
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.markdown_safe import NOTES_MARKDOWN, _escape_html, _unmark

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
#: Python: about a megabyte a second), the window shows "Rendering…" meanwhile.
BACKGROUND_CHARS = 200_000
#: What Qt lays out in time (renderable): it numbers each item of a list and
#: lays out each row of a table in time that grows with the list or table
#: (20,000 items: 16 s, 20,000 rows: 24 s), and wraps a line without a space
#: in time that grows with its square (1 MB: over a minute). The rendering
#: stops before the line that goes past one of these (the editor shows the
#: whole text).
LIST_ITEMS = 3000
TABLE_ROWS = 2000
LONG_RUN = 100_000  # characters without a space
LONG_WORD = re.compile(r"(?<!\S)\S{%d}" % LONG_RUN)  # (from where a run begins only: never quadratic)
LIST_ITEM = re.compile(r"^[ \t>]*(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)")
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
NOTE_DEFINITION = re.compile(r"^\[\^([^\]\s]+)\]:\s?(.*)\Z")
NOTE_REFERENCE = re.compile(r"\[\^([^\]\s]+)\](?!:)")


def with_footnotes(text: str) -> tuple[str, list[str]]:
    """*text* with its footnotes ("text[^1]", "[^1]: the note") as Qt shows
    them: a reference becomes a link "[1]" to "#fn-1", the notes go to the
    end, each a paragraph that begins with "[1]". Nothing inside fenced code
    changes."""
    lines, notes, fence = [], [], None
    for line in text.split("\n"):
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            lines.append(line)
            continue
        if opened:
            fence = opened.group(1)
            lines.append(line)
            continue
        definition = NOTE_DEFINITION.match(line)
        if definition:
            notes.append(definition.groups())
            continue
        lines.append(NOTE_REFERENCE.sub(lambda m: f"[\\[{m.group(1)}\\]](#fn-{m.group(1)})", line))
    if notes:
        lines += ["", "---", ""]
        for name, note in notes:
            lines += [f"\\[{name}\\] {note}", ""]
    return "\n".join(lines), [name for name, _ in notes]


def renderable(text: str) -> tuple[str, str]:
    """(the part of *text* rendered, why the rest is not - or "") - see
    :data:`LIST_ITEMS`: the lines before the one that goes past LIST_ITEMS
    list items or TABLE_ROWS lines of tables (outside fenced code), or holds
    LONG_RUN characters without a space."""
    if not LONG_WORD.search(text) and text.count("|") < TABLE_ROWS and text.count("\n") < LIST_ITEMS:
        return text, ""  # (most texts: nothing to count)
    items = rows = 0
    fence, lines = None, text.split("\n")
    for number, line in enumerate(lines):
        why = ""
        if len(line) >= LONG_RUN and LONG_WORD.search(line):
            why = _t("a line of more than {count} characters without a space", count=LONG_RUN)
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
        elif opened:
            fence = opened.group(1)
        elif LIST_ITEM.match(line):
            items += 1
            if items > LIST_ITEMS:
                why = _t("lists of more than {count} items", count=LIST_ITEMS)
        elif "|" in line:
            rows += 1
            if rows > TABLE_ROWS:
                why = _t("tables of more than {count} rows", count=TABLE_ROWS)
        if why:
            return "\n".join(lines[:number]), _t(
                "Only the first {count} of {total} lines are rendered: more would hold up "
                "the window ({why}). The editor shows them all.",
                count=number, total=len(lines), why=why)
    return text, ""


# -- fenced code --

KEYWORDS = set("""and as assert async await break case catch class const continue def default del delete do elif else
enum except export extends false final finally fn for foreach from func function go if impl import in interface is
lambda let loop match mod module mut namespace new nil none not null or package pass private protected pub public
raise return self static struct super switch this throw true try type typeof use var void while with yield then fi
done esac local echo""".split())
TOKENS = re.compile(r"""(?P<comment>\#.*$|//.*$|--\s.*$)|(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)"""
                    r"""|(?P<number>\b\d[\d_.xXa-fA-F]*\b)|(?P<word>\b[A-Za-z_]\w*\b)""")


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
        """{kind: QTextCharFormat}. (Made anew for every line of code, they
        were most of the time a rendering took: a code block of 150,000
        lines held up the window for 4 s.)"""
        if self.formats is None:
            dark = _is_dark(self.palette or QPalette())
            colours = {
                "comment": "#8a9099" if dark else "#6a737d",
                "string": "#98c379" if dark else "#22863a",
                "number": "#d19a66" if dark else "#b36200",
                "word": "#61afef" if dark else "#0550ae",
            }
            self.formats = {}
            for kind, colour in colours.items():
                fmt = QTextCharFormat()
                fmt.setForeground(QColor(colour))
                if kind == "word":
                    fmt.setFontWeight(QFont.Weight.Bold)
                self.formats[kind] = fmt
        return self.formats

    def highlightBlock(self, text):  # noqa: N802 - Qt
        block = self.currentBlock()
        if not block.blockFormat().hasProperty(QTextFormat.Property.BlockCodeFence):
            return
        formats = self.colours()
        for found in TOKENS.finditer(text):
            kind = found.lastgroup
            if kind == "word" and found.group() not in KEYWORDS:
                continue
            self.setFormat(found.start(), found.end() - found.start(), formats[kind])


# -- images --

def placeholder(text: str, palette: QPalette | None = None) -> QImage:
    """A box naming what is not shown (a remote image and its URL, an image
    too big or not found)."""
    palette = palette or QPalette()
    width, height = 420, 36
    image = QImage(width, height, QImage.Format.Format_ARGB32)
    image.fill(palette.color(QPalette.ColorRole.AlternateBase))
    painter = QPainter(image)
    painter.setPen(palette.color(QPalette.ColorRole.Mid))
    painter.drawRect(0, 0, width - 1, height - 1)
    painter.setPen(palette.color(QPalette.ColorRole.Text))
    metrics = painter.fontMetrics()
    painter.drawText(QRect(8, 0, width - 16, height), Qt.AlignmentFlag.AlignVCenter,
                     metrics.elidedText(text, Qt.TextElideMode.ElideMiddle, width - 16))
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


def decode(data: bytes, budget: dict | None = None):
    """``(QImage, None)`` of *data*, or ``(None, why)``: never more than
    IMAGE_PIXELS pixels are decoded - nor more than ``budget["left"]`` (the
    pixels all the images of a document may still take: taken from it,
    under ``budget["lock"]``). An SVG that may name other files is not
    decoded (svg_refers)."""
    buffer = QBuffer()
    buffer.setData(QByteArray(data))
    buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    reader = QImageReader(buffer)
    if _reader_format(reader) in SVG_FORMATS or data.startswith(b"\x1f\x8b"):
        plain = unpacked(data)
        if plain is None:
            return None, tr("too big")
        if svg_refers(plain):
            return None, tr("refers to other files")
        if plain is not data:  # (an .svgz: read as the SVG it holds - what was looked at)
            buffer.close()
            buffer.setData(QByteArray(plain))
            buffer.open(QIODevice.OpenModeFlag.ReadOnly)
            reader = QImageReader(buffer)
            if _reader_format(reader) not in SVG_FORMATS:
                return None, tr("not an image")
    size = reader.size()
    pixels = size.width() * size.height() if size.isValid() else 0
    if pixels > IMAGE_PIXELS:
        return None, tr("too big")
    if budget is not None:
        with budget["lock"]:  # (taken before it is decoded: the views of one window read at the same time)
            if pixels > budget["left"]:
                return None, tr("too big")
            budget["left"] -= pixels
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


def in_background(fn, done, owner: QObject | None = None) -> threading.Thread:
    """``fn()`` on a worker thread (never on the GUI thread: a slow or hung
    server holds up no window); ``done(result, error)`` on the GUI thread -
    not at all once *owner* is deleted."""
    delivery = _Delivery()

    def deliver(result, error):
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

    # The QObject lives in the GUI thread (made there); the closure keeps it
    # alive until the thread ends.
    thread = threading.Thread(target=work, name="markdown-view", daemon=True)
    thread._delivery = delivery  # type: ignore[attr-defined]
    thread.start()
    return thread


def read_text(backend, path: str, limit: int | None = None) -> tuple[str, bool]:
    """The file's text (UTF-8, damaged bytes replaced) and whether it was cut
    at *limit* (default :data:`TEXT_LIMIT`). Runs on a worker thread."""
    limit = TEXT_LIMIT if limit is None else limit
    with backend.open_read(path) as fh:
        data = fh.read(limit + 1)
    return data[:limit].decode("utf-8", "replace"), len(data) > limit


def _is_local(backend) -> bool:
    try:
        from core import previews as P

        return bool(P._is_local_backend(backend))
    except Exception:  # noqa: BLE001 - no previews module: judge by the class
        return type(backend).__name__ == "LocalFS"


class ImageSource:
    """The images of the Markdown file *path* on *backend*: where a name
    points (:meth:`kind`: relative to the file's folder only) and reading
    them (:meth:`read`, in a thread)."""

    def __init__(self, backend, path: str):
        self.backend = backend
        self.folder = posixpath.dirname(path) or "/"
        self.local = _is_local(backend)
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
        joined = posixpath.normpath(posixpath.join(self.folder, path))
        if not joined.startswith("/"):
            return "outside", name
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

            if read_refusal(path):
                return tr("not shown (a secret file)")
            import os

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


def _page(text: str, dark: bool):
    """(the HTML of *text*, its headings) through markdown-it - pure Python,
    so it may run on a worker thread."""
    from core import markdown_doc
    from ui.markdown_html import to_html

    doc = markdown_doc.parse(text)
    return to_html(doc, dark), doc.headings


class MarkdownBrowser(QTextBrowser):
    """A QTextBrowser that loads nothing itself: images come from the view's
    cache (read through the file's backend), every other resource is
    refused; links are never followed here (the view decides)."""

    def __init__(self, view: MarkdownView):
        super().__init__(view)
        self.view = view
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.setReadOnly(True)
        self.setAccessibleName(tr("The file rendered as Markdown"))

    def loadResource(self, kind, url):  # noqa: N802 - Qt
        if kind != QTextDocument.ResourceType.ImageResource.value:
            return QByteArray(b" ")  # (no style sheet, no frame, nothing else; empty would make Qt read it)
        return self.view.image(url.toString())


def _plain_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setForegroundRole(QPalette.ColorRole.PlaceholderText)
    return label


class MarkdownView(QWidget):
    """The rendering of a Markdown text: its outline (headings, a click jumps
    there) and the text. :attr:`link` (QUrl) for a link clicked that is not
    an anchor of this text (the window decides what it does). *source*: an
    :class:`ImageSource` or None (no images read)."""

    link = pyqtSignal(QUrl)

    def __init__(self, source: ImageSource | None, outline: bool = True, parent=None):
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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.outline = QListWidget()
        self.outline.setAccessibleName(tr("Outline"))
        self.outline.setToolTip(tr("The headings: a click shows that part"))
        self.outline.itemActivated.connect(self.jump)
        self.outline.itemClicked.connect(self.jump)
        self.browser = MarkdownBrowser(self)
        self.highlighter = CodeHighlighter(self.browser.document())
        self.browser.anchorClicked.connect(self.clicked)
        self.browser.highlighted.connect(self.hovered)
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
        self.timer.timeout.connect(lambda: self.render(self.markdown))

    # -- the text --

    def show_later(self, text: str) -> None:
        """*text* rendered after a pause in the typing (the live preview)."""
        self.markdown = text
        self.timer.start()

    def render(self, text: str) -> None:
        """*text* rendered (where it was scrolled to stays); its outline and
        anchors made anew."""
        self.timer.stop()
        self.markdown = text
        bar = self.browser.verticalScrollBar()
        where = bar.value()
        began = time.monotonic()
        part, why = renderable(text)
        self.notice.setText(why)
        self.notice.setVisible(bool(why))
        from core.markdown_doc import clean

        part = clean(part)  # (no control character of the file reaches the page: they showed as boxes)
        if self.full:
            self._page_generation += 1
            generation, dark = self._page_generation, _is_dark(self.palette())
            if len(part) > BACKGROUND_CHARS:
                self.status.setText(tr("Rendering…"))
                in_background(lambda: _page(part, dark), owner=self, done=lambda page, error: self._show_page(
                    generation, page, error, dark, where, began))
            else:
                self._show_page(generation, _page(part, dark), None, dark, where, began)
            return
        shown, notes = with_footnotes(part)
        self.highlighter.formats = None  # (the palette of now)
        self.highlighter.palette = self.palette()
        document = self.browser.document()
        document.setMarkdown(_escape_html(shown), FEATURES)
        _unmark(document)
        self.read_outline(notes)
        bar.setValue(where)
        # The live preview waits for a pause in the typing at least twice as
        # long as a rendering takes: a big text's rendering after every pause
        # of RENDER_DELAY left the typing stuck most of the time.
        self.timer.setInterval(max(RENDER_DELAY, int(2000 * (time.monotonic() - began))))
        self.read_missing()

    def _show_page(self, generation, page, error, dark, where, began) -> None:
        """A page :func:`_page` made, shown (unless a newer one is on its way)."""
        if generation != self._page_generation:
            return
        if error is not None:
            self.status.setText(_t("Cannot render: {error}", error=printable(error)))
            return
        if self.status.text() == tr("Rendering…"):
            self.status.setText("")
        body, headings = page
        from ui.markdown_html import anchor_names, style_sheet

        document = self.browser.document()
        document.setDefaultStyleSheet(style_sheet(dark))
        document.setHtml(body)
        self.names = anchor_names(body)
        self.outline.clear()
        self.anchors = {}
        block, found = document.begin(), []
        while block.isValid():
            if block.blockFormat().headingLevel():
                found.append(block.position())
            block = block.next()
        for heading, position in zip(headings, found):
            self.anchors[heading.anchor] = position
            item = QListWidgetItem("    " * (heading.level - 1) + heading.text)
            item.setData(Qt.ItemDataRole.UserRole, position)
            self.outline.addItem(item)
        self.browser.verticalScrollBar().setValue(where)
        self.timer.setInterval(max(RENDER_DELAY, int(2000 * (time.monotonic() - began))))
        self.read_missing()

    def read_outline(self, notes=()) -> None:
        self.outline.clear()
        self.anchors = {}
        # (the number each name goes on from: counted up from 1 past every
        # heading of that name before, 20,000 headings of one name held up the
        # window for half a minute)
        numbers, notes = {}, set(notes)
        block = self.browser.document().begin()
        while block.isValid():
            level = block.blockFormat().headingLevel()
            text = block.text()
            if level:
                key = slug(text)
                number, unique = numbers.get(key, 1), key
                while unique in self.anchors:  # (GitHub numbers headings of the same name)
                    unique, number = f"{key}-{number}", number + 1
                numbers[key] = number
                self.anchors[unique] = block.position()
                item = QListWidgetItem("    " * (level - 1) + text)
                item.setData(Qt.ItemDataRole.UserRole, block.position())
                self.outline.addItem(item)
            if notes and text.startswith("[") and "] " in text:
                name = text[1:text.index("] ")]
                if name in notes:
                    self.anchors.setdefault(f"fn-{name}", block.position())
            block = block.next()

    def headings(self) -> list[str]:
        """The outline's entries (for tests and the window)."""
        return [self.outline.item(i).text().strip() for i in range(self.outline.count())]

    def scroll_to(self, position: int) -> None:
        block = self.browser.document().findBlock(position)
        rect = self.browser.document().documentLayout().blockBoundingRect(block)
        self.browser.verticalScrollBar().setValue(int(rect.top()))
        self.browser.setTextCursor(QTextCursor(block))

    def jump(self, item) -> None:
        self.scroll_to(int(item.data(Qt.ItemDataRole.UserRole)))

    # -- links --

    def hovered(self, url) -> None:
        text = url.toString() if isinstance(url, QUrl) else str(url or "")
        self.status.setText(_t("Link: {target}", target=printable(text)) if text else "")

    def clicked(self, url: QUrl) -> None:
        """A link clicked: "#anchor" of this text scrolls there; anything
        else goes to the window (:attr:`link`)."""
        if not url.scheme() and not url.path() and url.hasFragment():
            position = self.anchors.get(url.fragment()) or self.anchors.get(slug(url.fragment()))
            if position is None and url.fragment() in self.names:
                self.browser.scrollToAnchor(url.fragment())  # a footnote and its way back
                return
            if position is None:
                self.status.setText(_t("No heading {anchor} here.",
                                       anchor=printable("#" + url.fragment())))
            else:
                self.scroll_to(position)
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
            return placeholder(_t("Reading {name}…", name=printable(name)), self.palette())
        if len(self.images) >= 2 * IMAGES:
            # (each name kept a picture of its own: a file naming 100,000
            # images took gigabytes; beyond these, one picture shared by all)
            if self.too_many is None:
                self.too_many = placeholder(_t("Not shown (more than {count} images)",
                                               count=2 * IMAGES), self.palette())
            return self.too_many
        if kind == "remote":
            found = placeholder(_t("Remote image, not loaded: {url}", url=printable(where)),
                                self.palette())
        elif kind == "outside":
            found = placeholder(_t("Not shown (not beside the file): {name}", name=printable(where)),
                                self.palette())
        else:
            found = placeholder(_t("Not shown (more than {count} images): {name}", count=IMAGES,
                                   name=printable(name)), self.palette())
        self.images[name] = found
        return found

    def forget_images(self) -> None:
        """Read every image again at the next rendering (Reload: an image
        changed on disk kept its old picture)."""
        self.images, self.asked, self.too_many = {}, set(), None
        self.generation += 1
        if self.source is not None:
            self.source.forget()

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
                room = max(160, self.browser.viewport().width() - 32)
                if found.width() > room:  # (wider than the view: shown at its width)
                    found = found.scaledToWidth(room, Qt.TransformationMode.SmoothTransformation)
                self.images[name] = found
            else:
                self.images[name] = placeholder(_t("Image not shown: {name} ({why})", name=printable(name),
                                                   why=printable(found or tr("not found"))),
                                                self.palette())
        self.render(self.markdown)

    # -- zoom --

    def zoom_by(self, steps: int) -> None:
        """*steps* larger (negative: smaller); 0: as it was."""
        if steps == 0:
            if self.zoom > 0:
                self.browser.zoomOut(self.zoom)
            elif self.zoom < 0:
                self.browser.zoomIn(-self.zoom)
            self.zoom = 0
            return
        if steps > 0:
            self.browser.zoomIn(steps)
        else:
            self.browser.zoomOut(-steps)
        self.zoom += steps


__all__ = [
    "FEATURES", "IMAGES", "IMAGE_LIMIT", "ImageSource", "MarkdownBrowser", "MarkdownView",
    "SUFFIXES", "decode", "in_background", "is_markdown", "printable", "read_text",
    "renderable", "slug", "svg_refers", "with_footnotes",
]
