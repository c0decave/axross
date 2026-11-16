"""Markdown for the terminal: a parsed document (core.markdown_doc) as text
with colours, for ``axross-mdcat`` / ``axross-markdown --term``.

Headings in colour with rules under the first two levels, bold, italics,
underline and strike-through, inline code on a background, fenced code
coloured by Pygments with its language named, block quotes with a bar,
nested lists with bullets, numbers and ☑ / ☐ task boxes, tables drawn with
box characters (aligned as written, wrapped to fit), definition lists,
footnotes, front matter, rules; links as terminal hyperlinks (OSC 8) with
their address beside the text; images drawn in the terminal - kitty's or
iTerm2's image protocol where the terminal speaks it, else coloured
half-blocks - or named with their path.

A file is untrusted, and a terminal runs what it is sent: every text from
the file passes :func:`core.markdown_doc.clean` (no ESC, no control
character reaches the terminal), a link's address is written into an OSC 8
sequence only when it is http(s), mailto or a file beside the document, and
images are read as the Qt viewer reads them (ui.markdown_view.ImageSource):
relative to the file only, regular files, never a secret file, bounded in
bytes and pixels; nothing is ever loaded from the network.
"""

from __future__ import annotations

import base64
import io
import os
import posixpath
import re
import stat as _stat
import sys
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from core import markdown_doc as MD

ESC = "\x1b"
#: The most bytes / pixels of one image read for the terminal (as the viewer).
IMAGE_LIMIT = 8 << 20
IMAGE_PIXELS = 40_000_000
#: The widest and tallest an image is drawn (columns; rows of text).
IMAGE_COLUMNS = 80
IMAGE_ROWS = 40

DARK = {
    "text": "#e6edf3", "muted": "#8b949e", "link": "#58a6ff",
    "h1": "#79c0ff", "h2": "#d2a8ff", "h3": "#7ee787", "h4": "#e3b341", "h5": "#ffa657", "h6": "#8b949e",
    "code_fg": "#ff7b72", "code_bg": "#2d333b", "pre_bg": "#161b22", "quote": "#8b949e",
    "rule": "#3d444d", "mark": "#3fb950", "open": "#8b949e", "image": "#d2a8ff", "border": "#545d68",
}
LIGHT = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    "h1": "#0550ae", "h2": "#8250df", "h3": "#1a7f37", "h4": "#9a6700", "h5": "#bc4c00", "h6": "#59636e",
    "code_fg": "#b31d28", "code_bg": "#eff1f3", "pre_bg": "#f6f8fa", "quote": "#59636e",
    "rule": "#d1d9e0", "mark": "#1a7f37", "open": "#59636e", "image": "#8250df", "border": "#afb8c1",
}
#: The 16-colour fallback of each role (SGR foreground numbers).
BASIC = {"text": 39, "muted": 90, "link": 94, "h1": 96, "h2": 95, "h3": 92, "h4": 93, "h5": 33,
         "h6": 90, "code_fg": 91, "quote": 90, "rule": 90, "mark": 92, "open": 90, "image": 95,
         "border": 90}

BULLETS = ("•", "◦", "▪", "‣")


# -- terminal capabilities ----------------------------------------------------------------------

def colour_depth(stream=None, environ=None) -> str:
    """"truecolor", "256", "16" or "none" for *stream* (NO_COLOR, FORCE_COLOR,
    TERM=dumb, COLORTERM)."""
    environ = os.environ if environ is None else environ
    stream = sys.stdout if stream is None else stream
    if environ.get("NO_COLOR"):
        return "none"
    forced = environ.get("FORCE_COLOR")
    if not forced and (not hasattr(stream, "isatty") or not stream.isatty()):
        return "none"
    term = environ.get("TERM", "")
    if term == "dumb" and not forced:
        return "none"
    if environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or "direct" in term:
        return "truecolor"
    if "256" in term or environ.get("TERM_PROGRAM") in ("iTerm.app", "WezTerm", "vscode", "Apple_Terminal"):
        return "256"
    return "16"


def image_protocol(environ=None) -> str:
    """"kitty", "iterm" or "blocks": how this terminal shows pictures."""
    environ = os.environ if environ is None else environ
    if environ.get("KITTY_WINDOW_ID") or "kitty" in environ.get("TERM", "") \
            or environ.get("TERM_PROGRAM") == "ghostty":
        return "kitty"
    if environ.get("TERM_PROGRAM") in ("iTerm.app", "WezTerm") or environ.get("LC_TERMINAL") == "iTerm2":
        return "iterm"
    return "blocks"


def dark_background(environ=None) -> bool:
    """Whether the terminal's background is dark (COLORFGBG; dark when not said)."""
    environ = os.environ if environ is None else environ
    value = environ.get("COLORFGBG", "")
    try:
        background = int(value.split(";")[-1])
    except ValueError:
        return True
    return background in (0, 1, 2, 3, 4, 5, 6, 8)


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    value = hex_colour.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _xterm256(r: int, g: int, b: int) -> int:
    """The nearest colour of xterm's 256 (the 6x6x6 cube or the grey ramp)."""
    def level(v):
        return 0 if v < 48 else 1 if v < 115 else (v - 35) // 40
    cube = 16 + 36 * level(r) + 6 * level(g) + level(b)
    steps = (0, 95, 135, 175, 215, 255)
    cr, cg, cb = steps[level(r)], steps[level(g)], steps[level(b)]
    grey = max(0, min(23, (sum((r, g, b)) // 3 - 3) // 10))
    gv = 8 + 10 * grey
    if (r - gv) ** 2 + (g - gv) ** 2 + (b - gv) ** 2 < (r - cr) ** 2 + (g - cg) ** 2 + (b - cb) ** 2:
        return 232 + grey
    return cube


# -- styled text --------------------------------------------------------------------------------

@dataclass(frozen=True)
class Style:
    fg: str = ""        # a role of the palette, or "#rrggbb"
    bg: str = ""
    bold: bool = False
    italic: bool = False
    underline: bool = False
    strike: bool = False
    dim: bool = False

    def but(self, **changes) -> Style:
        values = {**self.__dict__, **changes}
        return Style(**values)


PLAIN = Style()


@dataclass
class Painter:
    """Turns styles into SGR sequences for a colour depth and a palette."""

    depth: str = "truecolor"
    palette: dict = field(default_factory=lambda: DARK)
    hyperlinks: bool = True

    def _colour(self, value: str, background: bool) -> str:
        if not value:
            return ""
        hex_colour = value if value.startswith("#") else self.palette.get(value, "")
        if self.depth == "truecolor" and hex_colour:
            r, g, b = _rgb(hex_colour)
            return f"{48 if background else 38};2;{r};{g};{b}"
        if self.depth == "256" and hex_colour:
            return f"{48 if background else 38};5;{_xterm256(*_rgb(hex_colour))}"
        if self.depth == "16" and not background and value in BASIC:
            return str(BASIC[value])
        return ""

    def sgr(self, style: Style) -> str:
        if self.depth == "none":
            return ""
        codes = [c for c in (
            "1" if style.bold else "", "2" if style.dim else "", "3" if style.italic else "",
            "4" if style.underline else "", "9" if style.strike else "",
            self._colour(style.fg, False), self._colour(style.bg, True)) if c]
        return f"{ESC}[{';'.join(codes)}m" if codes else ""

    def reset(self) -> str:
        return "" if self.depth == "none" else f"{ESC}[0m"

    def paint(self, text: str, style: Style) -> str:
        start = self.sgr(style)
        return f"{start}{text}{self.reset()}" if start else text

    def link(self, text: str, url: str) -> str:
        """*text* as an OSC 8 hyperlink to *url* (when hyperlinks are on and
        *url* passes :func:`safe_url`)."""
        if not self.hyperlinks or self.depth == "none" or not safe_url(url):
            return text
        return f"{ESC}]8;;{url}{ESC}\\{text}{ESC}]8;;{ESC}\\"


def safe_url(url: str) -> bool:
    """Whether *url* may go into an escape sequence: http(s), mailto or file,
    no control character or space."""
    if not url or any(ord(c) < 0x21 or ord(c) == 0x7f or 0x80 <= ord(c) <= 0x9f for c in url):
        return False
    return urlsplit(url).scheme.lower() in ("http", "https", "mailto", "file")


@dataclass
class Span:
    text: str
    style: Style = PLAIN
    url: str = ""


def wrap(spans: list[Span], width: int) -> list[list[Span]]:
    """*spans* as lines of at most *width* columns (a word longer than a line
    is cut); "\\n" spans are hard breaks."""
    width = max(width, 8)
    lines: list[list[Span]] = [[]]
    used = 0
    tokens = _tokens(spans)
    for kind, piece in tokens:
        if kind == "break":
            lines.append([])
            used = 0
            continue
        if kind == "space":
            if used and used < width:
                lines[-1].append(Span(" ", piece.style, piece.url))
                used += 1
            continue
        size = MD.cell_width(piece.text)
        if used and used + size > width:
            while lines[-1] and lines[-1][-1].text == " ":
                lines[-1].pop()
            lines.append([])
            used = 0
        text = piece.text
        while MD.cell_width(text) > width:  # a word longer than a line
            cut = _cut(text, width - used)
            lines[-1].append(Span(cut, piece.style, piece.url))
            lines.append([])
            used = 0
            text = text[len(cut):]
        lines[-1].append(Span(text, piece.style, piece.url))
        used += MD.cell_width(text)
    while lines and not lines[-1]:
        lines.pop()
    for line in lines:
        while line and line[-1].text == " ":
            line.pop()
    return lines or [[]]


def _cut(text: str, width: int) -> str:
    out, used = [], 0
    for ch in text:
        size = MD.cell_width(ch)
        if used + size > max(width, 1):
            break
        out.append(ch)
        used += size
    return "".join(out) or text[:1]


def _tokens(spans: list[Span]):
    """("word" | "space" | "break", Span) in order."""
    for span in spans:
        if span.text == "\n":
            yield "break", span
            continue
        for part in re.split(r"( +)", span.text):
            if not part:
                continue
            if part.startswith(" "):
                yield "space", Span(" ", span.style, span.url)
            else:
                yield "word", Span(part, span.style, span.url)


def _glue_words(line: list[Span]) -> list[Span]:
    """Neighbouring spans of the same style and link joined (fewer escapes)."""
    out: list[Span] = []
    for span in line:
        if out and out[-1].style == span.style and out[-1].url == span.url:
            out[-1] = Span(out[-1].text + span.text, span.style, span.url)
        else:
            out.append(Span(span.text, span.style, span.url))
    return out


# -- images -------------------------------------------------------------------------------------

@dataclass
class Picture:
    """An image of the document: its name as written, alt text, and where it
    is (a local path below the document's folder, or why not)."""

    src: str
    alt: str
    path: str = ""
    why: str = ""


def locate(src: str, folder: str) -> tuple[str, str]:
    """(local path, "") for an image *src* beside a document in *folder*, or
    ("", why not) - as ui.markdown_view.ImageSource.kind: no scheme, no
    absolute path; remote images are never fetched."""
    parts = urlsplit(src)
    if parts.scheme.lower() in ("http", "https", "ftp", "ftps") or src.startswith("//"):
        return "", "remote, not loaded"
    if parts.scheme or src.startswith(("/", "\\")) or "\0" in src or not folder:
        return "", "not beside the file"
    path = unquote(parts.path)
    if not path:
        return "", "not beside the file"
    return os.path.normpath(os.path.join(folder, path)), ""


def read_picture(path: str):
    """A Pillow image of the local file *path* (RGBA), or a str why not:
    regular files only, never a secret one, bounded in bytes and pixels."""
    try:
        from PIL import Image
    except ImportError:
        return "Pillow is not installed"
    from core.protected_places import read_refusal

    if read_refusal(path):
        return "a secret file"
    try:
        st = os.stat(path)
    except OSError:
        return "not found"
    if not _stat.S_ISREG(st.st_mode):
        return "not a file"
    if st.st_size > IMAGE_LIMIT:
        return "too big"
    with open(path, "rb") as fh:
        data = fh.read(IMAGE_LIMIT + 1)
    if data.lstrip()[:5].lower() in (b"<?xml", b"<svg ") or path.lower().endswith((".svg", ".svgz")):
        return "SVG is not drawn in the terminal"
    Image.MAX_IMAGE_PIXELS = IMAGE_PIXELS
    try:
        image = Image.open(io.BytesIO(data))
        if image.width * image.height > IMAGE_PIXELS:
            return "too big"
        image.seek(0)
        return image.convert("RGBA")
    except Exception as exc:  # noqa: BLE001 - any decoder error: say it, draw nothing
        return f"not an image ({type(exc).__name__})"


def _fit(image, columns: int, rows: int, cell_aspect: float = 2.0):
    """*image* scaled to fit *columns* x *rows* character cells (a cell is
    about twice as tall as it is wide)."""
    width, height = image.size
    scale = min(columns / width, rows * cell_aspect / height, 1.0)
    return max(1, int(width * scale)), max(1, int(height * scale / cell_aspect))


def draw_blocks(image, painter: Painter, columns: int, rows: int) -> list[str]:
    """*image* as lines of upper half blocks: two pixels a cell (the
    foreground the upper, the background the lower)."""
    cols, cells = _fit(image, columns, rows)
    small = image.resize((cols, cells * 2))
    background = (0x16, 0x1b, 0x22) if painter.palette is DARK else (0xff, 0xff, 0xff)

    def over(pixel):
        r, g, b, a = pixel
        k = a / 255
        return tuple(int(c * k + bg * (1 - k)) for c, bg in zip((r, g, b), background))

    px = small.load()
    lines = []
    for y in range(0, cells * 2, 2):
        out = []
        for x in range(cols):
            top = "#%02x%02x%02x" % over(px[x, y])
            bottom = "#%02x%02x%02x" % over(px[x, y + 1])
            out.append(painter.paint("▀", Style(fg=top, bg=bottom)))
        lines.append("".join(out))
    return lines


def _png(image) -> bytes:
    out = io.BytesIO()
    image.save(out, format="PNG")  # re-encoded: no metadata of the file goes to the terminal
    return out.getvalue()


def draw_kitty(image, columns: int, rows: int) -> list[str]:
    """kitty's graphics protocol: the PNG in chunks of 4096, one escape each."""
    cols, cells = _fit(image, columns, rows)
    data = base64.b64encode(_png(image)).decode("ascii")
    chunks = [data[i:i + 4096] for i in range(0, len(data), 4096)] or [""]
    out = []
    for index, chunk in enumerate(chunks):
        more = 1 if index < len(chunks) - 1 else 0
        head = f"a=T,f=100,c={cols},r={cells},m={more}," if index == 0 else f"m={more},"
        out.append(f"{ESC}_G{head.rstrip(',')};{chunk}{ESC}\\")
    return ["".join(out)] + [""] * (cells - 1)


def draw_iterm(image, columns: int, rows: int) -> list[str]:
    """iTerm2's inline image (also WezTerm): one OSC 1337 with the PNG."""
    cols, cells = _fit(image, columns, rows)
    data = base64.b64encode(_png(image)).decode("ascii")
    return [f"{ESC}]1337;File=inline=1;width={cols};height={cells};preserveAspectRatio=1:{data}\a"] \
        + [""] * (cells - 1)


# -- the renderer -------------------------------------------------------------------------------

@dataclass
class Options:
    width: int = 80
    depth: str = "truecolor"
    dark: bool = True
    hyperlinks: bool = True
    images: str = "blocks"          # "kitty", "iterm", "blocks" or "none"
    folder: str = ""                # the document's folder (images, links)
    image_columns: int = IMAGE_COLUMNS
    image_rows: int = IMAGE_ROWS


class Renderer:
    """A parsed document as lines for the terminal (see the module docstring)."""

    def __init__(self, options: Options) -> None:
        self.o = options
        self.p = Painter(options.depth, DARK if options.dark else LIGHT, options.hyperlinks)
        self.lines: list[str] = []
        self.notes: dict[str, list[str]] = {}

    # -- inline --

    def inline(self, token, base: Style = PLAIN) -> tuple[list[Span], list[Picture]]:
        spans: list[Span] = []
        pictures: list[Picture] = []
        stack = [base]
        url_stack: list[str] = []
        links: list[tuple[int, str]] = []  # (where a link's text begins, its address)
        for child in token.children or ():
            style = stack[-1]
            url = url_stack[-1] if url_stack else ""
            kind = child.type
            if kind == "text":
                spans.append(Span(MD.clean(child.content), style, url))
            elif kind == "softbreak":
                spans.append(Span(" ", style, url))
            elif kind == "hardbreak":
                spans.append(Span("\n", style))
            elif kind == "code_inline":
                spans.append(Span(MD.clean(child.content), style.but(fg="code_fg", bg="code_bg"), url))
            elif kind in ("strong_open", "em_open", "s_open"):
                change = {"strong_open": {"bold": True}, "em_open": {"italic": True},
                          "s_open": {"strike": True, "fg": "muted"}}[kind]
                stack.append(style.but(**change))
            elif kind in ("strong_close", "em_close", "s_close"):
                if len(stack) > 1:
                    stack.pop()
            elif kind == "link_open":
                href = MD.clean(str(child.attrGet("href") or ""))
                url_stack.append(self._link_target(href))
                stack.append(style.but(fg="link", underline=True))
                links.append((len(spans), href))
            elif kind == "link_close":
                start, href = links.pop() if links else (len(spans), "")
                text = "".join(s.text for s in spans[start:])
                if len(stack) > 1:
                    stack.pop()
                if url_stack:
                    url_stack.pop()
                if href and text.strip() != href and not href.startswith("#"):
                    spans.append(Span(f" ‹{href}›", stack[-1].but(fg="muted", dim=True)))
            elif kind == "image":
                src = MD.clean(str(child.attrGet("src") or ""))
                alt = MD.clean(child.content or "")
                path, why = locate(src, self.o.folder)
                pictures.append(Picture(src, alt, path, why))
                label = f"🖼 {alt or posixpath.basename(src) or 'image'}"
                target = self._link_target(src) if path else ""
                spans.append(Span(label, style.but(fg="image", bold=True), target))
                if why:
                    spans.append(Span(f" ‹{src} – {why}›", style.but(fg="muted", dim=True)))
            elif kind == "footnote_ref":
                label = str((child.meta or {}).get("label", (child.meta or {}).get("id", "")))
                spans.append(Span(f"[{MD.clean(label)}]", style.but(fg="link")))
            elif kind == "html_inline":
                # html=False: only the task list's box makes one - the list
                # shows it in place of the bullet (Renderer.listing)
                continue
            else:
                spans.append(Span(MD.clean(child.content or ""), style, url))
        return [s for s in spans if s.text], pictures

    def _link_target(self, href: str) -> str:
        """The address a link opens in the terminal: http(s) / mailto as
        written; a relative one as a file:// URL beside the document."""
        parts = urlsplit(href)
        if parts.scheme.lower() in ("http", "https", "mailto"):
            return href
        if parts.scheme or not self.o.folder or href.startswith(("#", "/", "\\")):
            return ""
        path = os.path.normpath(os.path.join(self.o.folder, unquote(parts.path)))
        return "file://" + path.replace(" ", "%20")

    # -- output --

    def emit(self, line: str = "") -> None:
        self.lines.append(line)

    def blank(self) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")

    def paint_line(self, line: list[Span]) -> str:
        out = []
        for span in _glue_words(line):
            text = self.p.paint(span.text, span.style)
            out.append(self.p.link(text, span.url) if span.url else text)
        return "".join(out)

    def para(self, spans: list[Span], first: str, rest: str, width: int) -> None:
        """*spans* wrapped to *width* minus the prefix; *first* before the
        first line, *rest* before the others (both already painted)."""
        room = max(8, width - MD.cell_width(_strip_ansi(first)))
        for index, line in enumerate(wrap(spans, room)):
            self.emit((first if index == 0 else rest) + self.paint_line(line))

    def pictures(self, pictures: list[Picture], prefix: str, width: int) -> None:
        if self.o.images == "none":
            return
        for picture in pictures:
            if not picture.path:
                continue
            image = read_picture(picture.path)
            if isinstance(image, str):
                self.emit(prefix + self.p.paint(f"  ({picture.src}: {image})", Style(fg="muted", dim=True)))
                continue
            columns = max(4, min(self.o.image_columns, width - MD.cell_width(_strip_ansi(prefix))))
            if self.o.images == "kitty":
                drawn = draw_kitty(image, columns, self.o.image_rows)
            elif self.o.images == "iterm":
                drawn = draw_iterm(image, columns, self.o.image_rows)
            elif self.p.depth in ("truecolor", "256"):
                drawn = draw_blocks(image, self.p, columns, self.o.image_rows)
            else:
                continue
            for line in drawn:
                self.emit(prefix + line)

    # -- blocks --

    def render(self, doc: MD.Document) -> str:
        tokens = doc.tokens
        if doc.front_matter:
            self.front_matter(doc.front_matter)
        self.blocks(tokens, 0, len(tokens), "", "", self.o.width)
        while self.lines and self.lines[-1] == "":
            self.lines.pop()
        return "\n".join(self.lines) + "\n"

    def front_matter(self, text: str) -> None:
        style = Style(fg="muted", dim=True)
        self.emit(self.p.paint("┄┄┄ front matter ┄┄┄", style))
        for line in MD.clean(text).splitlines():
            self.emit(self.p.paint(line, style))
        self.emit(self.p.paint("┄" * 19, style))
        self.blank()

    def _close(self, tokens, start: int, end: int) -> int:
        """The index of the closing token of the block opened at *start*."""
        level = tokens[start].level
        close = tokens[start].type.replace("_open", "_close")
        for index in range(start + 1, end):
            if tokens[index].type == close and tokens[index].level == level:
                return index
        return end - 1

    def blocks(self, tokens, start: int, end: int, first: str, rest: str, width: int,
               tight: bool = False) -> None:
        """The blocks of tokens[start:end]; *first* is the prefix of the first
        line written (a list bullet), *rest* of every other."""
        index = start
        while index < end:
            token = tokens[index]
            kind = token.type
            prefix, first = first, rest
            if kind == "heading_open":
                self.heading(int(token.tag[1:]), tokens[index + 1], prefix, width)
                index += 3
            elif kind == "paragraph_open":
                spans, pictures = self.inline(tokens[index + 1])
                self.para(spans, prefix, rest, width)
                self.pictures(pictures, rest, width)
                if not tight:
                    self.blank()
                index += 3
            elif kind in ("fence", "code_block"):
                self.code(token, prefix, rest, width)
                index += 1
            elif kind == "hr":
                self.emit(prefix + self.p.paint("─" * max(4, width - MD.cell_width(_strip_ansi(prefix))),
                                                Style(fg="rule")))
                self.blank()
                index += 1
            elif kind == "blockquote_open":
                close = self._close(tokens, index, end)
                bar = self.p.paint("│ ", Style(fg="quote"))
                self.quote(tokens, index + 1, close, prefix + bar, rest + bar, width)
                self.blank()
                index = close + 1
            elif kind in ("bullet_list_open", "ordered_list_open"):
                close = self._close(tokens, index, end)
                self.listing(tokens, index, close, prefix, rest, width)
                self.blank()
                index = close + 1
            elif kind == "table_open":
                close = self._close(tokens, index, end)
                self.table(tokens, index, close, prefix, width)
                self.blank()
                index = close + 1
            elif kind == "dl_open":
                close = self._close(tokens, index, end)
                self.deflist(tokens, index + 1, close, prefix, rest, width)
                self.blank()
                index = close + 1
            elif kind == "footnote_block_open":
                close = self._close(tokens, index, end)
                self.footnotes(tokens, index + 1, close, width)
                index = close + 1
            elif kind == "html_block":  # (html=False: never made; kept as text should a plugin make one)
                self.para([Span(MD.clean(token.content))], prefix, rest, width)
                index += 1
            else:
                index += 1

    def quote(self, tokens, start, end, first, rest, width) -> None:
        """A block quote: its blocks, each line behind the bar, in its colour."""
        before = len(self.lines)
        self.blocks(tokens, start, end, first, rest, width)
        while len(self.lines) > before and self.lines[-1] == "":
            self.lines.pop()
        bar = rest.rstrip()
        for index in range(before, len(self.lines)):  # the bar goes on over its blank lines
            if self.lines[index] == "":
                self.lines[index] = bar

    def heading(self, level: int, inline, prefix: str, width: int) -> None:
        self.blank()
        role = f"h{level}"
        marks = {1: "█ ", 2: "▌ ", 3: "▸ "}.get(level, "· ")
        spans, pictures = self.inline(inline, Style(fg=role, bold=True, underline=level >= 4))
        lead = prefix + self.p.paint(marks, Style(fg=role, bold=True))
        self.para(spans, lead, prefix + "  ", width)
        if level <= 2:
            used = min(width, MD.cell_width("".join(s.text for s in spans)) + 2)
            self.emit(prefix + self.p.paint(("━" if level == 1 else "─") * max(used, 4), Style(fg=role)))
        self.pictures(pictures, prefix, width)
        self.blank()

    def code(self, token, first: str, rest: str, width: int) -> None:
        lang = (token.info or "").strip().split(maxsplit=1)[0] if token.info else ""
        text = MD.clean(token.content).rstrip("\n")
        gutter = self.p.paint("▏", Style(fg="border"))
        if lang:
            self.emit(first + self.p.paint(f" {lang} ", Style(fg="muted", bg="pre_bg", italic=True)))
            first = rest
        room = max(8, width - MD.cell_width(_strip_ansi(rest)) - 2)
        for index, line in enumerate(self._highlight(text, lang)):
            lead = first if index == 0 else rest
            plain = _strip_ansi(line)
            if MD.cell_width(plain) > room:  # cut, marked; the colours of a cut line are dropped
                line = self.p.paint(_cut(plain, room - 1), PLAIN) + self.p.paint("↩", Style(fg="muted"))
            self.emit(lead + gutter + " " + line)
        self.blank()

    def _highlight(self, text: str, lang: str) -> list[str]:
        """The lines of *text*, coloured by Pygments for *lang* (when it knows
        it and colours are on)."""
        if self.p.depth != "none" and lang and len(text) < 200_000:
            try:
                from pygments import highlight
                from pygments.formatters import (
                    Terminal256Formatter,
                    TerminalFormatter,
                    TerminalTrueColorFormatter,
                )
                from pygments.lexers import get_lexer_by_name
                from pygments.util import ClassNotFound

                lexer = get_lexer_by_name(lang.lower(), stripnl=False)
                style = "github-dark" if self.o.dark else "default"
                if self.p.depth == "truecolor":
                    formatter = TerminalTrueColorFormatter(style=style)
                elif self.p.depth == "256":
                    formatter = Terminal256Formatter(style=style)
                else:
                    formatter = TerminalFormatter(bg="dark" if self.o.dark else "light")
                return highlight(text, lexer, formatter).rstrip("\n").split("\n")
            except (ImportError, ClassNotFound):
                pass
            except Exception:  # noqa: BLE001 - a style missing in an old Pygments: plain
                pass
        return [self.p.paint(line, Style(fg="text")) for line in text.split("\n")]

    def listing(self, tokens, start: int, end: int, first: str, rest: str, width: int,
                depth: int = 0) -> None:
        ordered = tokens[start].type == "ordered_list_open"
        number = int(tokens[start].attrGet("start") or 1) if ordered else 0
        tight = bool((tokens[start].meta or {}).get("tight")) or all(
            t.hidden for t in tokens[start:end] if t.type == "paragraph_open")
        index = start + 1
        leading = first
        while index < end:
            if tokens[index].type != "list_item_open":
                index += 1
                continue
            close = self._close(tokens, index, end)
            task = self._task(tokens, index, close)
            if task is not None:
                mark = self.p.paint("☑" if task else "☐", Style(fg="mark" if task else "open", bold=True))
                bullet_width = 2
            elif ordered:
                label = f"{number}."
                mark = self.p.paint(label, Style(fg="muted", bold=True))
                bullet_width = len(label) + 1
                number += 1
            else:
                mark = self.p.paint(BULLETS[depth % len(BULLETS)], Style(fg="muted"))
                bullet_width = 2
            item_first = leading + mark + " "
            item_rest = rest + " " * bullet_width
            self._item(tokens, index + 1, close, item_first, item_rest, width, depth, tight)
            leading = rest
            index = close + 1

    def _task(self, tokens, start: int, end: int):
        """True / False for a task item (checked or not), None for another."""
        for index in range(start, min(end, start + 3)):
            if tokens[index].type == "inline":
                for child in tokens[index].children or ():
                    if child.type == "html_inline" and "checkbox" in child.content:
                        return "checked" in child.content
                return None
        return None

    def _item(self, tokens, start, end, first, rest, width, depth, tight) -> None:
        """A list item's blocks; a list inside it one level deeper."""
        index = start
        while index < end:
            kind = tokens[index].type
            if kind in ("bullet_list_open", "ordered_list_open"):
                close = self._close(tokens, index, end)
                self.listing(tokens, index, close, first, rest, width, depth + 1)
                first = rest
                index = close + 1
                continue
            close = self._close(tokens, index, end) if kind.endswith("_open") else index
            self.blocks(tokens, index, close + 1, first, rest, width, tight=tight)
            first = rest
            index = close + 1

    def deflist(self, tokens, start, end, first, rest, width) -> None:
        index = start
        while index < end:
            kind = tokens[index].type
            if kind == "dt_open":
                spans, _pictures = self.inline(tokens[index + 1], Style(bold=True))
                self.para(spans, first, rest, width)
                first = rest
                index += 3
            elif kind == "dd_open":
                close = self._close(tokens, index, end)
                mark = self.p.paint("  ⁝ ", Style(fg="muted"))
                self.blocks(tokens, index + 1, close, rest + mark, rest + "    ", width, tight=True)
                index = close + 1
            else:
                index += 1

    def footnotes(self, tokens, start, end, width) -> None:
        self.blank()
        self.emit(self.p.paint("─" * min(24, width), Style(fg="rule")))
        index = start
        while index < end:
            if tokens[index].type == "footnote_open":
                close = self._close(tokens, index, end)
                label = str((tokens[index].meta or {}).get("label", (tokens[index].meta or {}).get("id", "")))
                mark = self.p.paint(f"[{MD.clean(label)}] ", Style(fg="link"))
                body = [t for t in tokens[index + 1:close] if t.type != "footnote_anchor"]
                self.blocks(body, 0, len(body), mark, " " * (len(label) + 3), width, tight=True)
                index = close + 1
            else:
                index += 1

    def table(self, tokens, start, end, prefix, width) -> None:
        rows: list[list[tuple[list[Span], str]]] = []
        header_rows = 0
        aligns: list[str] = []
        in_head = False
        row: list = []
        for index in range(start, end):
            t = tokens[index]
            if t.type == "thead_open":
                in_head = True
            elif t.type == "thead_close":
                in_head = False
            elif t.type == "tr_open":
                row = []
            elif t.type == "tr_close":
                rows.append(row)
                if in_head:
                    header_rows += 1
            elif t.type in ("th_open", "td_open"):
                style = str(t.attrGet("style") or "")
                align = style.split(":", 1)[1] if style.startswith("text-align:") else "left"
                if in_head:
                    aligns.append(align)
                spans, _pictures = self.inline(tokens[index + 1], Style(bold=in_head, fg="h1" if in_head else ""))
                row.append((spans, align))
        if not rows:
            return
        columns = max(len(r) for r in rows)
        rows = [r + [([], "left")] * (columns - len(r)) for r in rows]
        natural = [max(MD.cell_width("".join(s.text for s in r[c][0])) for r in rows) for c in range(columns)]
        room = max(columns * 4, width - MD.cell_width(_strip_ansi(prefix)) - (3 * columns + 1))
        widths = [max(1, w) for w in natural]
        while sum(widths) > room:  # the widest column gives way first
            widest = widths.index(max(widths))
            if widths[widest] <= 4:
                break
            widths[widest] -= 1
        border = Style(fg="border")

        def rule(left, mid, right):
            return prefix + self.p.paint(left + mid.join("─" * (w + 2) for w in widths) + right, border)

        self.emit(rule("┌", "┬", "┐"))
        for number, cells in enumerate(rows):
            wrapped = [wrap(spans, widths[c]) for c, (spans, _a) in enumerate(cells)]
            height = max(len(w) for w in wrapped)
            for line_no in range(height):
                out = [self.p.paint("│", border)]
                for c, (_spans, align) in enumerate(cells):
                    line = wrapped[c][line_no] if line_no < len(wrapped[c]) else []
                    used = MD.cell_width("".join(s.text for s in line))
                    gap = widths[c] - used
                    left = gap // 2 if align == "center" else gap if align == "right" else 0
                    out.append(" " + " " * left + self.paint_line(line) + " " * (gap - left) + " ")
                    out.append(self.p.paint("│", border))
                self.emit(prefix + "".join(out))
            if number == header_rows - 1 and number < len(rows) - 1:
                self.emit(rule("╞", "╪", "╡").replace("─", "═"))
        self.emit(rule("└", "┴", "┘"))


_ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def render(text: str, options: Options | None = None) -> str:
    """*text* (Markdown) for the terminal."""
    options = options or Options()
    doc = MD.parse(text)
    return Renderer(options).render(doc)


__all__ = ["DARK", "LIGHT", "Options", "Painter", "Renderer", "colour_depth", "dark_background",
           "image_protocol", "locate", "read_picture", "render", "safe_url", "wrap"]
