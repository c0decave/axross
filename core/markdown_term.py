"""Markdown for the terminal: a parsed document (core.markdown_doc) as text
with colours, for ``axross-mdcat`` / ``axross-markdown --term``.

Headings in colour with rules under the first two levels, bold, italics,
underline and strike-through, inline code on a background, fenced code
coloured by Pygments with its language named, block quotes with a bar,
GitHub's alerts with a bar and a title in their colour, math as text
(core.markdown_doc.math_text),
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
from urllib.parse import quote, unquote, urlsplit

from core import markdown_doc as MD

ESC = "\x1b"
#: The most bytes / pixels of one image read for the terminal (as the viewer).
IMAGE_LIMIT = 8 << 20
IMAGE_PIXELS = 40_000_000
#: Images of one document that are drawn, and the pixels all of them may
#: take together (as the viewer: a small PNG of 36 million pixels named
#: 10,000 times was decoded 10,000 times; a page of 10,000 images wrote
#: 30 MB of half-blocks).
IMAGES = 200
IMAGES_PIXELS = 100_000_000
#: The widest and tallest an image is drawn (columns; rows of text).
IMAGE_COLUMNS = 80
IMAGE_ROWS = 40

DARK = {
    "text": "#e6edf3", "muted": "#8b949e", "link": "#58a6ff",
    "h1": "#79c0ff", "h2": "#d2a8ff", "h3": "#7ee787", "h4": "#e3b341", "h5": "#ffa657", "h6": "#8b949e",
    "code_fg": "#ff7b72", "code_bg": "#2d333b", "pre_bg": "#161b22", "quote": "#8b949e",
    "rule": "#3d444d", "mark": "#3fb950", "open": "#8b949e", "image": "#d2a8ff", "border": "#545d68",
    "math": "#ffa657", "note": "#4493f8", "tip": "#3fb950", "important": "#ab7df8", "warning": "#d29922",
    "caution": "#f85149",
}
LIGHT = {
    "text": "#1f2328", "muted": "#59636e", "link": "#0969da",
    "h1": "#0550ae", "h2": "#8250df", "h3": "#1a7f37", "h4": "#9a6700", "h5": "#bc4c00", "h6": "#59636e",
    "code_fg": "#b31d28", "code_bg": "#eff1f3", "pre_bg": "#f6f8fa", "quote": "#59636e",
    "rule": "#d1d9e0", "mark": "#1a7f37", "open": "#59636e", "image": "#8250df", "border": "#afb8c1",
    "math": "#953800", "note": "#0969da", "tip": "#1a7f37", "important": "#8250df", "warning": "#9a6700",
    "caution": "#d1242f",
}
#: The 16-colour fallback of each role (SGR foreground numbers).
BASIC = {"text": 39, "muted": 90, "link": 94, "h1": 96, "h2": 95, "h3": 92, "h4": 93, "h5": 33,
         "h6": 90, "code_fg": 91, "quote": 90, "rule": 90, "mark": 92, "open": 90, "image": 95,
         "border": 90, "math": 33, "note": 94, "tip": 92, "important": 95, "warning": 93, "caution": 91}

#: GitHub's alerts: the sign and title of each kind (as ui.markdown_html's).
ALERT_TITLES = {"note": ("ℹ", "Note"), "tip": ("✓", "Tip"), "important": ("❖", "Important"),
                "warning": ("⚠", "Warning"), "caution": ("✖", "Caution")}

BULLETS = ("•", "◦", "▪", "‣")
#: Fenced languages that are drawings (as ui.markdown_html.DIAGRAMS).
DIAGRAMS = ("mermaid", "geojson", "topojson", "stl", "plantuml")
#: Columns of a tab in a code block or front matter (as GitHub shows them).
TAB = 8


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
    is cut); "\\n" spans are hard breaks. A word is what stands between
    spaces, whatever its styles: "(`LC_ALL`)" and "**bold**," are broken
    nowhere (a change of style was a place to break: "locale (⏎LC_ALL")."""
    width = max(width, 1)  # (a table's column may be narrower than a paragraph: para keeps 8)
    lines: list[list[Span]] = [[]]
    used = 0

    def new_line() -> None:
        nonlocal used
        while lines[-1] and lines[-1][-1].text == " ":
            lines[-1].pop()
        lines.append([])
        used = 0

    for kind, piece in _tokens(spans):
        if kind == "break":
            lines.append([])
            used = 0
            continue
        if kind == "space":
            # (one space between words, as the viewer shows them: a tag
            # dropped between two spaces left both)
            if used and used < width and (lines[-1][-1].text != " " or piece.style.bg == "code_bg"):
                lines[-1].append(Span(" ", piece.style, piece.url))
                used += 1
            continue
        sizes = [MD.cell_width(part.text) for part in piece]
        size = sum(sizes)
        if used and used + size > width:
            new_line()
        if used + size <= width:
            lines[-1].extend(piece)
            used += size
            continue
        # A word longer than a line, cut from an index with its width kept
        # count of: measured and sliced anew for every line, a word of 1 MB
        # took minutes (each cut went over all of the rest).
        for part in piece:
            text, start = part.text, 0
            while start < len(text):
                if used >= width:
                    new_line()
                end = _cut_end(text, start, width - used)
                chunk = text[start:end]
                chunk_width = MD.cell_width(chunk)
                if used and used + chunk_width > width:  # (a wide character at a line's end)
                    new_line()
                    continue
                lines[-1].append(Span(chunk, part.style, part.url))
                used += chunk_width
                start = end
    while lines and not lines[-1]:
        lines.pop()
    for line in lines:
        while line and line[-1].text == " ":
            line.pop()
    return lines or [[]]


def _cut(text: str, width: int) -> str:
    """The start of *text* that fits *width* columns (one character at least)."""
    return text[:_cut_end(text, 0, width)]


def _cut_end(text: str, start: int, width: int) -> int:
    """Where the part of *text* from *start* that fits *width* columns ends
    (one character at least - as a reader sees one: an emoji sequence or a
    letter with its marks is never cut, core.markdown_doc.cluster_end)."""
    used, index = 0, start
    while index < len(text):
        end = MD.cluster_end(text, index)
        size = MD.cell_width(text[index:end])
        if used + size > max(width, 1):
            break
        used += size
        index = end
    return index if index > start else MD.cluster_end(text, start) if start < len(text) else start + 1


def _chop(text: str, width: int) -> list[str]:
    """*text* in pieces of at most *width* columns, nothing dropped, spaces
    kept (front matter: its indentation means something)."""
    pieces, start = [], 0
    while start < len(text):
        end = _cut_end(text, start, width)
        pieces.append(text[start:end])
        start = end
    return pieces or [""]


def _note_number(token) -> str:
    """The number a footnote (its reference or its note) is shown with: its
    place in the list of notes, as GitHub and the Qt viewer number them. (The
    label was shown: "[None]" and "[0]" for an inline note ``^[...]``, which
    has none, and a long label as it was written.)"""
    meta = token.meta or {}
    try:
        return str(int(meta.get("id", 0)) + 1)
    except (TypeError, ValueError):
        return "?"


def _math_spans(tex: str, style: Style, url: str = "") -> list:
    """An inline formula as spans: its text in the formula's colour, bold
    and italic as they are, what is not understood as code (that part only)."""
    looks = {"": {"fg": "math"}, "sub": {"fg": "math"}, "sup": {"fg": "math"},
             "bold": {"fg": "math", "bold": True}, "italic": {"fg": "math", "italic": True},
             "unknown": {"fg": "code_fg", "bg": "code_bg"}}
    spans = []
    for text, kind in MD.math_runs(tex):
        shown = MD._written_run(text, kind).replace("\n", " ")
        spans.append(Span(shown, style.but(**looks.get(kind, looks[""])), url))
    return spans


def _plain_text(text: str) -> str:
    """Text of the file for a line of the terminal: no control character
    (core.markdown_doc.clean), a tab as a space (a tab moves the cursor to the
    next stop of the terminal, as wide as no one counted)."""
    return MD.clean(text).replace("\t", " ")


def _tokens(spans: list[Span]):
    """("word", [Span, ...]) - the pieces of one word, in whatever styles -
    ("space", Span) and ("break", Span), in order."""
    word: list[Span] = []
    for span in spans:
        if span.text == "\n":
            if word:
                yield "word", word
                word = []
            yield "break", span
            continue
        for part in re.split(r"( +)", span.text):
            if not part:
                continue
            if part.startswith(" "):
                if word:
                    yield "word", word
                    word = []
                # (code keeps its spaces, each of them: "a  b" is not "a b")
                for _space in range(len(part) if span.style.bg == "code_bg" else 1):
                    yield "space", Span(" ", span.style, span.url)
            else:
                word.append(Span(part, span.style, span.url))
    if word:
        yield "word", word


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
    data: bytes | None = None  # (an image held in the document: data:image/…;base64,…)


#: The images a ``data:`` address may hold (as markdown-it's validateLink).
DATA_IMAGE = re.compile(r"data:image/(png|gif|jpeg|webp);base64,", re.IGNORECASE)


def data_image(src: str) -> tuple[bytes | None, str]:
    """(the bytes of the ``data:`` image *src*, "") or (None, why not): PNG,
    GIF, JPEG or WebP in base64, at most IMAGE_LIMIT bytes."""
    found = DATA_IMAGE.match(src)
    if not found:
        return None, "not an image this shows"
    payload = src[found.end():]
    if len(payload) > IMAGE_LIMIT * 4 // 3 + 4:
        return None, "too big"
    try:
        return base64.b64decode(re.sub(r"\s+", "", payload), validate=True), ""
    except ValueError:
        return None, "not an image"


def locate(src: str, folder: str) -> tuple[str, str]:
    """(local path, "") for an image *src* beside a document in *folder*, or
    ("", why not) - as ui.markdown_view.ImageSource.kind: no scheme, no
    absolute path, nothing above *folder* (its subfolders are beside it,
    "../" is not); remote images are never fetched."""
    parts = urlsplit(src)
    if parts.scheme.lower() in ("http", "https", "ftp", "ftps") or src.startswith("//"):
        return "", "remote, not loaded"
    if parts.scheme or src.startswith(("/", "\\")) or "\0" in src or not folder:
        return "", "not beside the file"
    path = unquote(parts.path)
    if not path or "\0" in path:
        return "", "not beside the file"
    full = os.path.normpath(os.path.join(folder, path))
    if not _inside(full, folder):  # ("../x.png": its folder or one below it only)
        return "", "not beside the file"
    return full, ""


#: Files a file:// link never names (programs a desktop would run).
_PROGRAMS = (".desktop", ".exe", ".bat", ".cmd", ".com", ".msi", ".ps1", ".sh", ".app", ".jar",
             ".appimage", ".run", ".command", ".vbs", ".scr", ".lnk")


def _inside(path: str, folder: str) -> bool:
    """Whether *path* is *folder* or lies below it (both normalised)."""
    folder = os.path.normpath(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def read_picture(path: str, pixels: int = IMAGE_PIXELS, folder: str = ""):
    """A Pillow image of the local file *path* (RGBA), or a str why not:
    regular files only, never a secret one, bounded in bytes and pixels (at
    most *pixels*: what the document's images may still take) - and, given
    the document's *folder*, only when what *path* resolves to (through
    symlinks) lies in it too."""
    from core.protected_places import read_refusal

    if folder and not _inside(os.path.realpath(path), os.path.realpath(folder)):
        return "not beside the file (a link to elsewhere)"
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
    if path.lower().endswith((".svg", ".svgz")):
        return "SVG is not drawn in the terminal"
    return decode_picture(data, pixels)


def decode_picture(data: bytes, pixels: int = IMAGE_PIXELS):
    """A Pillow image (RGBA) of the image *data*, or a str why not: at most
    IMAGE_LIMIT bytes and *pixels* pixels (IMAGE_PIXELS at most), no SVG."""
    try:
        from PIL import Image
    except ImportError:
        return "Pillow is not installed"
    if len(data) > IMAGE_LIMIT:
        return "too big"
    if data.lstrip()[:5].lower() in (b"<?xml", b"<svg "):
        return "SVG is not drawn in the terminal"
    Image.MAX_IMAGE_PIXELS = IMAGE_PIXELS
    try:
        image = Image.open(io.BytesIO(data))
        if image.width * image.height > min(IMAGE_PIXELS, pixels):
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


#: Pixels of one character cell an image is sent with (kitty, iTerm2): a
#: cell is about 10 x 20 pixels, twice that on a HiDPI screen.
CELL_PIXELS = (20, 40)


def _png(image, cols: int = 0, cells: int = 0) -> bytes:
    """*image* as PNG, re-encoded (no metadata of the file goes to the
    terminal) - at most as big as *cols* x *cells* cells show it: a photo of
    40 million pixels went to the terminal whole, 100 MB of base64 for a
    picture 80 columns wide."""
    if cols and cells:
        limit = (cols * CELL_PIXELS[0], cells * CELL_PIXELS[1])
        if image.width > limit[0] or image.height > limit[1]:
            image = image.copy()
            image.thumbnail(limit)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def draw_kitty(image, columns: int, rows: int) -> list[str]:
    """kitty's graphics protocol: the PNG in chunks of 4096, one escape each."""
    cols, cells = _fit(image, columns, rows)
    data = base64.b64encode(_png(image, cols, cells)).decode("ascii")
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
    data = base64.b64encode(_png(image, cols, cells)).decode("ascii")
    return [f"{ESC}]1337;File=inline=1;width={cols};height={cells};preserveAspectRatio=1:{data}\a"] \
        + [""] * (cells - 1)


# -- the renderer -------------------------------------------------------------------------------

#: Without colour (NO_COLOR, a pipe), emphasis is written with marks as in
#: Markdown: else it reads as the prose around it.
_PLAIN_MARKS = {"strong_open": "**", "em_open": "*", "s_open": "~~"}  # (bold italic "***x***", not "_**x**_")
#: The styles of raw HTML's tags (core.markdown_doc's allowed subset).
_HTML_STYLES = {
    "b": {"bold": True}, "strong": {"bold": True}, "i": {"italic": True}, "em": {"italic": True},
    "u": {"underline": True}, "ins": {"underline": True}, "s": {"strike": True, "fg": "muted"},
    "strike": {"strike": True, "fg": "muted"}, "del": {"strike": True, "fg": "muted"},
    "mark": {"fg": "h4", "bold": True}, "small": {"dim": True},
    "kbd": {"fg": "code_fg", "bg": "code_bg", "bold": True}, "code": {"fg": "code_fg", "bg": "code_bg"},
    "summary": {"bold": True}, **{f"h{n}": {"fg": f"h{n}", "bold": True} for n in range(1, 7)},
}
#: Tags of raw HTML that end a paragraph in the terminal.
_HTML_BLOCKS = frozenset("p div details summary h1 h2 h3 h4 h5 h6 blockquote pre hr ul ol li".split())


@dataclass
class _Inline:
    """What a line of text is made of while it is read: its spans and
    pictures, the styles, links and raw HTML tags open."""

    base: Style = PLAIN
    spans: list = field(default_factory=list)
    pictures: list = field(default_factory=list)
    stack: list = field(default_factory=list)
    url_stack: list = field(default_factory=list)
    links: list = field(default_factory=list)  # (where a link's text begins, its address)
    scripts: list = field(default_factory=list)  # ("sup" / "sub" open)
    html: list = field(default_factory=list)  # (a raw HTML tag open, what it changed)

    def __post_init__(self) -> None:
        self.stack = [self.base]

    @property
    def style(self) -> Style:
        return self.stack[-1]

    @property
    def url(self) -> str:
        return self.url_stack[-1] if self.url_stack else ""

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
        #: the images drawn (IMAGES at most), the pixels they may still take
        #: (IMAGES_PIXELS) and what each one drew ({(path, columns): lines or why})
        self.drawn, self.pixels_left = 0, IMAGES_PIXELS
        self.picture_cache: dict[tuple[str, int], list[str] | str] = {}

    # -- inline --

    def inline(self, token, base: Style = PLAIN) -> tuple[list[Span], list[Picture]]:
        at = _Inline(base)
        for child in token.children or ():
            style, url = at.style, at.url
            kind = child.type
            if kind == "text":
                text = _plain_text(child.content)
                if at.scripts:  # (inside <sup> / <sub>: small letters where Unicode has them)
                    text = MD.raised(text, at.scripts[-1], plain=True)
                at.spans.append(Span(text, style, url))
            elif kind == "softbreak":
                at.spans.append(Span(" ", style, url))
            elif kind == "hardbreak":
                at.spans.append(Span("\n", style))
            elif kind == "code_inline":
                code = _plain_text(child.content)
                if self.p.depth == "none":  # (no colour: code is told from prose by its marks)
                    # (a fence longer than any run of backticks in it: "`a ` b`" was ambiguous)
                    ticks = "`" * (max((len(run) for run in re.findall("`+", code)), default=0) + 1)
                    pad = " " if code.startswith("`") or code.endswith("`") or len(ticks) > 1 else ""
                    code = f"{ticks}{pad}{code}{pad}{ticks}"
                at.spans.append(Span(code, style.but(fg="code_fg", bg="code_bg"), url))
            elif kind in ("strong_open", "em_open", "s_open"):
                change = {"strong_open": {"bold": True}, "em_open": {"italic": True},
                          "s_open": {"strike": True, "fg": "muted"}}[kind]
                at.stack.append(style.but(**change))
                if self.p.depth == "none":
                    at.spans.append(Span(_PLAIN_MARKS[kind], style, url))
            elif kind in ("strong_close", "em_close", "s_close"):
                if len(at.stack) > 1:
                    at.stack.pop()
                if self.p.depth == "none":
                    at.spans.append(Span(_PLAIN_MARKS[kind.replace("_close", "_open")], at.style, url))
            elif kind == "link_open":
                self._open_link(at, MD.clean(str(child.attrGet("href") or "")))
            elif kind == "link_close":
                self._close_link(at)
            elif kind == "image":  # (its alt text as text: "*emph*", "`code`" were shown as written)
                alt = "".join(" " if part.type in ("softbreak", "hardbreak") else part.content
                              for part in (child.children or ()) if part.type in
                              ("text", "code_inline", "softbreak", "hardbreak")) if child.children else child.content
                self._image(at, MD.clean(str(child.attrGet("src") or "")), MD.clean(alt or ""))
            elif kind == "footnote_ref":
                at.spans.append(Span(f"[{_note_number(child)}]", style.but(fg="link")))
            elif kind in ("math_inline", "math_inline_double"):
                at.spans += _math_spans(_plain_text(child.content), style, url)
            elif kind == "safe_html_inline":
                for event in MD.html_events(child):
                    self._html_event(at, event)
            elif kind == "html_inline":
                # only the task list's box makes one (raw HTML is safe_html_inline):
                # the list shows it in place of the bullet (Renderer.listing)
                continue
            else:
                at.spans.append(Span(_plain_text(child.content or ""), style, url))
        return [s for s in at.spans if s.text], at.pictures

    def _open_link(self, at: _Inline, href: str) -> None:
        at.url_stack.append(self._link_target(href))
        at.stack.append(at.style.but(fg="link", underline=True))
        at.links.append((len(at.spans), href))

    def _close_link(self, at: _Inline) -> None:
        start, href = at.links.pop() if at.links else (len(at.spans), "")
        text = "".join(s.text for s in at.spans[start:])
        if len(at.stack) > 1:
            at.stack.pop()
        url = at.url_stack.pop() if at.url_stack else ""
        if href and text.strip() != href and not href.startswith("#") and href[:5].lower() != "data:":
            notes = getattr(self, "_cell_notes", None)
            if notes is not None:  # (in a table's cell: the address under the table, not in the cell -
                # it made the column as wide as it and was broken mid-word; a hyperlink needs none)
                if not (url and self.p.hyperlinks and self.p.depth != "none"):
                    notes.append(href)
                    at.spans.append(Span(f"[{len(notes)}]", at.style.but(fg="muted", dim=True)))
                return
            at.spans.append(Span(f" ‹{href}›", at.style.but(fg="muted", dim=True)))

    def _table_notes(self, prefix: str) -> None:
        """The addresses of a table's links (_close_link), under it."""
        notes, self._cell_notes = getattr(self, "_cell_notes", None) or [], None
        for number, href in enumerate(notes, 1):
            self.emit(prefix + self.p.paint(f"[{number}] {href}", Style(fg="muted", dim=True)))

    def _image(self, at: _Inline, src: str, alt: str) -> None:
        if src[:5].lower() == "data:":  # (held in the document: drawn, its payload never printed)
            data, why = data_image(src)
            at.pictures.append(Picture("data:", alt, "", why, data))
            at.spans.append(Span(f"🖼 {alt or 'image'}", at.style.but(fg="image", bold=True)))
            if why:
                at.spans.append(Span(f" ‹data: image – {why}›", at.style.but(fg="muted", dim=True)))
            return
        path, why = locate(src, self.o.folder)
        at.pictures.append(Picture(src, alt, path, why))
        label = f"🖼 {alt or posixpath.basename(urlsplit(src).path) or 'image'}"
        remote = why == "remote, not loaded"
        # A remote picture is named by its alt text and links to its address
        # (a badge row printed two addresses a badge); inside a link the
        # link's own address is the one that counts.
        target = self._link_target(src) if path else src if remote and safe_url(src) else ""
        at.spans.append(Span(label, at.style.but(fg="image", bold=True), at.url or target))
        if why and not remote:
            at.spans.append(Span(f" ‹{src} – {why}›", at.style.but(fg="muted", dim=True)))

    def _html_event(self, at: _Inline, event: tuple) -> None:
        """An event of raw HTML's allowed subset (core.markdown_doc) in a
        line of text: a style, a link, a picture, a line break."""
        kind, tag = event[0], event[1] if len(event) > 1 else ""
        if kind == "text":
            text = _plain_text(event[1])
            if at.scripts:
                text = MD.raised(text, at.scripts[-1], plain=True)
            at.spans.append(Span(text, at.style, at.url))
            return
        if kind == "start":
            attrs = event[2]
            if tag == "br":
                at.spans.append(Span("\n", at.style))
            elif tag == "img":
                self._image(at, attrs.get("src", ""), attrs.get("alt", ""))
            elif tag == "a":
                self._open_link(at, attrs.get("href", ""))
                at.html.append((tag, "link"))
            elif tag in ("sup", "sub"):
                at.scripts.append(tag)
                at.html.append((tag, "script"))
            elif tag in _HTML_STYLES:
                at.stack.append(at.style.but(**_HTML_STYLES[tag]))
                at.html.append((tag, "style"))
            elif tag not in ("hr",):
                at.html.append((tag, ""))
            return
        if not any(open_tag == tag for open_tag, _effect in at.html):
            return
        while at.html:  # (what opened inside it ends with it)
            open_tag, effect = at.html.pop()
            if effect == "link":
                self._close_link(at)
            elif effect == "script" and at.scripts:
                at.scripts.pop()
            elif effect == "style" and len(at.stack) > 1:
                at.stack.pop()
            if open_tag == tag:
                break

    def _link_target(self, href: str) -> str:
        """The address a link opens in the terminal: http(s) / mailto as
        written; a relative one as a file:// URL beside the document."""
        parts = urlsplit(href)
        if parts.scheme.lower() in ("http", "https", "mailto"):
            return href
        if parts.scheme or not self.o.folder or href.startswith(("#", "/", "\\")):
            return ""
        path = os.path.normpath(os.path.join(self.o.folder, unquote(parts.path)))
        # As the images: the document's folder or one below it (through
        # symlinks too), and never a program - the terminal opens what a
        # file:// link names with what the desktop runs it with.
        real = os.path.realpath(path)
        if not _inside(path, self.o.folder) or not _inside(real, os.path.realpath(self.o.folder)):
            return ""
        if os.path.isfile(real) and (os.access(real, os.X_OK) or real.lower().endswith(_PROGRAMS)):
            return ""
        # (percent-encoded as a URL must be: a "\\", a "~", a "#" were raw)
        return "file://" + quote(path, safe="/")

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
        # (the wider prefix: a table's record indents the lines after its first)
        room = max(8, width - max(MD.cell_width(_strip_ansi(first)), MD.cell_width(_strip_ansi(rest))))
        for index, line in enumerate(wrap(spans, room)):
            self.emit((first if index == 0 else rest) + self.paint_line(line))

    def pictures(self, pictures: list[Picture], prefix: str, width: int) -> None:
        if self.o.images == "none":
            return
        if self.o.images not in ("kitty", "iterm") and self.p.depth not in ("truecolor", "256"):
            return  # (half-blocks need more than 16 colours: nothing is read)
        columns = max(4, min(self.o.image_columns, width - MD.cell_width(_strip_ansi(prefix))))
        for picture in pictures:
            if not picture.path and picture.data is None:
                continue
            if self.drawn >= IMAGES:  # (each drawing counts: one image named 10,000 times wrote 30 MB)
                if self.drawn == IMAGES:
                    self.emit(prefix + self.p.paint(f"  (more than {IMAGES} images: the rest are not drawn)",
                                                    Style(fg="muted", dim=True)))
                    self.drawn += 1
                continue
            self.drawn += 1
            key = (picture.path or hash(picture.data), columns)
            drawn = self.picture_cache.get(key)
            if drawn is None:  # (decoded once however often it is named)
                drawn = self._draw(picture.path, columns, picture.data)
                self.picture_cache[key] = drawn
            if isinstance(drawn, str):  # (wrapped: a long name went past the width)
                self.para([Span(f"({picture.src}: {drawn})", Style(fg="muted", dim=True))],
                          prefix + "  ", prefix + "  ", width)
                continue
            for line in drawn:
                self.emit(prefix + line)

    def _draw(self, path: str, columns: int, data: bytes | None = None) -> list[str] | str:
        """The lines that draw the image at *path* - or of *data*, held in the
        document - (or why not), its pixels taken from what the document's
        images may still take."""
        image = decode_picture(data, self.pixels_left) if data is not None \
            else read_picture(path, self.pixels_left, self.o.folder)
        if isinstance(image, str):
            return image
        self.pixels_left -= image.width * image.height
        if self.o.images == "kitty":
            return draw_kitty(image, columns, self.o.image_rows)
        if self.o.images == "iterm":
            return draw_iterm(image, columns, self.o.image_rows)
        return draw_blocks(image, self.p, columns, self.o.image_rows)

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
        for line in MD.clean(text).expandtabs(TAB).splitlines():
            for piece in _chop(line, self.o.width):  # (a long YAML value went past the width)
                self.emit(self.p.paint(piece, style))
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
            elif kind in ("math_block", "math_block_label") or (
                    kind == "fence" and (token.info or "").strip().lower().split()[:1] == ["math"]):
                self.math(token, prefix, rest, width)
                index += 1
            elif kind in ("fence", "code_block"):
                self.code(token, prefix, rest, width)
                if tight and self.lines and self.lines[-1] == "":
                    self.lines.pop()  # (in a tight list's item: no line after it)
                index += 1
            elif kind == "hr":
                self.emit(prefix + self.p.paint("─" * max(4, width - MD.cell_width(_strip_ansi(prefix))),
                                                Style(fg="rule")))
                self.blank()
                index += 1
            elif kind == "blockquote_open":
                close = self._close(tokens, index, end)
                alert = MD.alert_of(token)
                bar = self.p.paint("┃ " if alert else "│ ", Style(fg=alert or "quote"))
                if MD.cell_width(_strip_ansi(rest)) + 2 + 8 > width:
                    bar = ""  # (no room for another bar and 8 columns of text: deeper quotes behind the last)
                if alert:  # (its title, then its blocks behind a bar in its colour)
                    sign, title = ALERT_TITLES[alert]
                    self.emit(prefix + bar + self.p.paint(f"{sign} {title}", Style(fg=alert, bold=True)))
                    prefix = rest
                self.quote(tokens, index + 1, close, prefix + bar, rest + bar, width)
                if not tight:  # (in a tight list's item: no line after it either)
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
            elif kind == "safe_html_block":
                self.html_block(token, prefix, rest, width)
                index += 1
            else:
                index += 1

    def html_block(self, token, first: str, rest: str, width: int) -> None:
        """A block of raw HTML's allowed subset: its text in paragraphs (one
        ends where a <p>, <div>, heading, <summary> ... does), its styles,
        links, line breaks and pictures; a <summary> marked ▾ (shown open), an <hr> a rule."""
        at = _Inline()
        pre = 0
        drawn = len(self.lines)

        centred: list[bool] = []  # (each open block: whether it says align="center")

        def flush(gap: bool = True) -> None:
            nonlocal first, drawn
            spans = [span for span in at.spans if span.text]
            if any(span.text.strip() for span in spans):
                while spans and spans[0].text in (" ", "\n"):
                    spans.pop(0)
                before = len(self.lines)
                self.para(spans, first, rest, width)
                if any(centred):  # (raw HTML's align="center": in the middle of the width, as on a page)
                    for index in range(before, len(self.lines)):
                        used = MD.cell_width(_strip_ansi(self.lines[index]))
                        self.lines[index] = " " * max(0, (width - used) // 2) + self.lines[index]
                first = rest
            self.pictures(at.pictures, rest, width)
            if len(self.lines) > drawn and gap:
                self.blank()
            drawn = len(self.lines)
            at.spans, at.pictures = [], []

        heading = 0
        table: list | None = None  # (a raw-HTML table's rows of (spans, alignment), while in one)
        cell: _Inline | None = None
        header_rows, align, head_row = 0, "left", False
        for event in MD.html_events(token):
            kind, tag = event[0], event[1]
            if tag == "table":
                if kind == "start" and table is None:
                    flush()
                    table, header_rows, self._cell_notes = [], 0, []
                elif kind == "end" and table is not None:
                    # (spans: every cell under its own column - a row under a
                    # cell of two rows slid one column to the left)
                    grid, spans = MD.span_grid(table)
                    table = [[([], "left") if cell is None else cell for cell in row] for row in grid]
                    self.draw_table(table, header_rows, first, width, spans)
                    self._table_notes(first)
                    self.blank()
                    first, table, cell, drawn = rest, None, None, len(self.lines)
                continue
            if table is not None:
                if tag == "tr" and kind == "start":
                    table.append([])
                    head_row = True
                elif tag in ("th", "td") and kind == "start":
                    if not table:
                        table.append([])
                    head_row = head_row and tag == "th"
                    align = event[2].get("align", "left")
                    span = (int(event[2].get("colspan", 1)), int(event[2].get("rowspan", 1)))
                    cell = _Inline(Style(bold=True, fg="h1") if tag == "th" else PLAIN)
                elif tag in ("th", "td") and kind == "end" and cell is not None:
                    spans = [span for span in cell.spans if span.text.strip() or span.text == " "]
                    while spans and spans[0].text == " ":
                        spans.pop(0)
                    table[-1].append(((spans, align if align in ("left", "center", "right") else "left"), *span))
                    cell = None
                elif tag == "tr" and kind == "end":
                    if head_row and table[-1] and len(table) == header_rows + 1:
                        header_rows += 1
                elif cell is not None:
                    if kind == "text":
                        self._html_event(cell, ("text", re.sub(r"\s+", " ", event[1])))
                    else:
                        self._html_event(cell, event)
                continue
            if tag in ("h1", "h2", "h3", "h4", "h5", "h6") and kind == "start":
                flush()
                heading = int(tag[1])
                at.stack.append(self.heading_style(heading))
                at.html.append((tag, "style"))
                continue
            if heading and kind == "end" and tag == f"h{heading}":
                self._html_event(at, event)
                spans = [span for span in at.spans if span.text]
                while spans and spans[0].text in (" ", "\n"):
                    spans.pop(0)
                self.heading_lines(heading, spans, at.pictures, first, width)
                first, heading, drawn = rest, 0, len(self.lines)
                at.spans, at.pictures = [], []
                continue
            if kind == "text":
                text = event[1] if pre else re.sub(r"\s+", " ", event[1])
                if pre:
                    for number, line in enumerate(text.split("\n")):
                        if number:
                            at.spans.append(Span("\n", at.style))
                        self._html_event(at, ("text", line))
                else:
                    self._html_event(at, ("text", text))
                continue
            if tag in _HTML_BLOCKS:
                flush(gap=tag not in ("li", "ul", "ol") or kind == "end" and tag != "li")
                if kind == "start" and tag not in ("hr", "br", "img"):
                    centred.append(event[2].get("align") == "center")
                elif kind == "end" and centred:
                    centred.pop()
            if kind == "start" and tag == "hr":
                self.emit(first + self.p.paint("─" * max(4, width - MD.cell_width(_strip_ansi(first))),
                                               Style(fg="rule")))
                first = rest
                continue
            if tag == "pre":
                pre += 1 if kind == "start" else -1 if pre else 0
            self._html_event(at, event)
            if kind == "start" and tag == "summary":  # (shown open)
                at.spans.append(Span("▾ ", at.style.but(fg="muted")))
            elif kind == "start" and tag == "li":  # (an item of a raw-HTML list)
                at.spans.append(Span("• ", at.style.but(fg="muted")))
        flush()
        self.blank()

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
        spans, pictures = self.inline(inline, self.heading_style(level))
        self.heading_lines(level, spans, pictures, prefix, width)

    @staticmethod
    def heading_style(level: int) -> Style:
        return Style(fg=f"h{level}", bold=True, underline=level >= 4)

    def heading_lines(self, level: int, spans, pictures, prefix: str, width: int) -> None:
        """A heading of *level* (Markdown's or raw HTML's): its mark, its
        text, a rule under the first two levels, its pictures."""
        self.blank()
        role = f"h{level}"
        marks = {1: "█ ", 2: "▌ ", 3: "▸ "}.get(level, "· ")
        lead = prefix + self.p.paint(marks, Style(fg=role, bold=True))
        self.para(spans, lead, prefix + "  ", width)
        if level <= 2:  # (the rule fits beside the prefix: in a quote it went past the width)
            used = min(width - MD.cell_width(_strip_ansi(prefix)),
                       MD.cell_width("".join(s.text for s in spans)) + 2)
            self.emit(prefix + self.p.paint(("━" if level == 1 else "─") * max(used, 4), Style(fg=role)))
        self.pictures(pictures, prefix, width)
        self.blank()

    def code(self, token, first: str, rest: str, width: int) -> None:
        # The info string is the file's too: an ESC in it went to the terminal.
        lang = _plain_text(token.info or "").strip().split(maxsplit=1)
        lang = lang[0] if lang else ""
        # Tabs expanded here (as GitHub, 8): the terminal's own stops, counted
        # from its first column, took a line past the width and the gutter.
        text = MD.clean(token.content).expandtabs(TAB).rstrip("\n")
        gutter = self.p.paint("▏", Style(fg="border"))
        room = max(8, width - MD.cell_width(_strip_ansi(rest)) - 2)
        if lang:
            if lang.lower() in DIAGRAMS:  # (drawn by GitHub; here its source, said so)
                lang = f"{lang} – diagram, shown as its source"
            label = _cut(lang, room) if MD.cell_width(lang) > room else lang
            self.emit(first + self.p.paint(f" {label} ", Style(fg="muted", bg="pre_bg", italic=True)))
            first = rest
        for index, line in enumerate(self._highlight(text, lang)):
            lead = first if index == 0 else rest
            plain = _strip_ansi(line)
            if MD.cell_width(plain) > room:
                # wrapped, each break marked (nothing of a line is lost); the
                # colours of a wrapped line are dropped
                pieces = _chop(plain, room - 1)
                for number, piece in enumerate(pieces):
                    mark = self.p.paint("↩", Style(fg="muted")) if number < len(pieces) - 1 else ""
                    self.emit((lead if number == 0 else rest) + gutter + " "
                              + self.p.paint(piece, PLAIN) + mark)
                continue
            self.emit(lead + gutter + " " + line)
        self.blank()

    def math(self, token, first: str, rest: str, width: int) -> None:
        """A math block: its text (core.markdown_doc.math_text) in the middle
        of the width (wrapped when longer); as written, as code, when it is
        not understood."""
        text, understood = MD.math_display(_plain_text(token.content))
        label = _plain_text(token.info or "") if token.type == "math_block_label" else ""
        room = max(8, width - MD.cell_width(_strip_ansi(rest)))
        style = Style(fg="math") if understood else Style(fg="code_fg")  # (a part not understood: as code)
        lines = text.split("\n") or [""]
        if label:
            lines[-1] += f"   ({label})"
        # (the block in the middle as a whole: its lines one under the other,
        # as a matrix's rows - each in the middle on its own went out of line)
        widest = max(MD.cell_width(line) for line in lines)
        gap = max(0, (room - widest) // 2)
        for number, line in enumerate(lines):
            for piece in _chop(line, room - gap if widest <= room else room):
                self.emit((first if number == 0 else rest) + " " * (gap if widest <= room else 0)
                          + self.p.paint(piece, style))
                first = rest
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
        given = tokens[start].attrGet("start")  # (a list from 0: "0." - "or 1" made it 1)
        number = (int(given) if given is not None and str(given) != "" else 1) if ordered else 0
        # (the list's own paragraphs only - a quote's in an item is never hidden:
        # a tight list with one was spaced out)
        level = tokens[start].level + 2
        tight = bool((tokens[start].meta or {}).get("tight")) or all(
            t.hidden for t in tokens[start:end] if t.type == "paragraph_open" and t.level == level)
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
            # (no deeper than half the width: a deep list pushed its text off the line)
            item_rest = rest + " " * bullet_width if MD.cell_width(_strip_ansi(rest)) < width // 2 else rest
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
        if not (start >= 2 and tokens[start - 2].type == "hr"):  # (a text ending in a rule: that one, not two)
            self.emit(self.p.paint("─" * min(24, width), Style(fg="rule")))
        index = start
        while index < end:
            if tokens[index].type == "footnote_open":
                close = self._close(tokens, index, end)
                number = _note_number(tokens[index])
                mark = self.p.paint(f"[{number}] ", Style(fg="link"))
                body = [t for t in tokens[index + 1:close] if t.type != "footnote_anchor"]
                self.blocks(body, 0, len(body), mark, " " * (len(number) + 3), width, tight=True)
                index = close + 1
            else:
                index += 1

    def table(self, tokens, start, end, prefix, width) -> None:
        self._cell_notes = []
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
        self.draw_table(rows, header_rows, prefix, width)
        self._table_notes(prefix)

    def draw_table(self, rows: list, header_rows: int, prefix: str, width: int, spans=()) -> None:
        """Rows of cells - (spans, alignment) - as a table drawn with box
        characters (a Markdown table's, a raw-HTML one's). *spans*: raw
        HTML's cells spanning columns (core.markdown_doc.span_grid) - each as
        wide as its columns and the lines between them, no line through it
        (its width was charged to its first column, lines drawn across it)."""
        if not rows:
            return
        columns = max(len(r) for r in rows)
        rows = [r + [([], "left")] * (columns - len(r)) for r in rows]
        across = {(row, column): count for row, column, _down, count in spans if count > 1}
        inside = {(row, column + n) for (row, column), count in across.items() for n in range(1, count)}

        def length(cell) -> int:
            return MD.cell_width("".join(s.text for s in cell[0]))

        natural = [max((length(r[c]) for n, r in enumerate(rows) if (n, c) not in across and (n, c) not in inside),
                       default=0) for c in range(columns)]
        for (row, column), count in across.items():  # (what a spanning cell needs beyond its columns: shared)
            extra = max(0, length(rows[row][column]) - sum(natural[column:column + count]) - 3 * (count - 1))
            for n in range(count):
                natural[column + n] += extra // count + (1 if n < extra % count else 0)
        widths = fit_columns(natural, width - MD.cell_width(_strip_ansi(prefix)) - (3 * columns + 1))
        if widths is None:
            self.records(rows, header_rows, prefix, width)
            return
        border = Style(fg="border")

        def ends(row: int | None) -> set[int]:
            """The columns a line ends after in *row* (None: every one)."""
            return {c for c in range(columns - 1) if row is None or (row, c + 1) not in inside}

        def rule(left, right, above, below, line="─", both="┼", up="┴", down="┬"):
            top, under = ends(above), ends(below)
            out = left
            for c, w in enumerate(widths):
                out += line * (w + 2)
                if c < columns - 1:
                    out += both if c in top and c in under else up if c in top else down if c in under else line
            return prefix + self.p.paint(out + right, border)

        self.emit(rule("┌", "┐", None, 0, both="┬", up="─"))
        for number, cells in enumerate(rows):
            pieces = []  # (start column, width, spans, alignment) of each cell drawn
            for c, (cell_spans, align) in enumerate(cells):
                if (number, c) in inside:
                    continue
                count = across.get((number, c), 1)
                pieces.append((sum(widths[c:c + count]) + 3 * (count - 1), cell_spans, align))
            wrapped = [wrap(cell_spans, w) for w, cell_spans, _a in pieces]
            height = max(len(w) for w in wrapped)
            for line_no in range(height):
                out = [self.p.paint("│", border)]
                for index, (w, _cell_spans, align) in enumerate(pieces):
                    line = wrapped[index][line_no] if line_no < len(wrapped[index]) else []
                    used = MD.cell_width("".join(s.text for s in line))
                    gap = w - used
                    left = gap // 2 if align == "center" else gap if align == "right" else 0
                    out.append(" " + " " * left + self.paint_line(line) + " " * (gap - left) + " ")
                    out.append(self.p.paint("│", border))
                self.emit(prefix + "".join(out))
            if number == header_rows - 1 and number < len(rows) - 1:
                self.emit(rule("╞", "╡", number, number + 1, line="═", both="╪", up="╧", down="╤"))
        self.emit(rule("└", "┘", len(rows) - 1, None, both="┴", down="─"))

    def records(self, rows, header_rows: int, prefix: str, width: int) -> None:
        """A table whose columns do not fit the width (each at least
        :data:`MIN_COLUMN`): a row after the other, each cell behind its
        column's heading. (Drawn wider, the terminal broke every line of it
        and its borders ran through the text.)"""
        heads = ["".join(s.text for s in cell[0]) for cell in rows[0]] if header_rows else []
        rule = prefix + self.p.paint("─" * max(4, min(24, width - MD.cell_width(_strip_ansi(prefix)))),
                                     Style(fg="border"))
        body = rows[header_rows:]
        if not body:  # (a table of headings only: the headings, not each behind itself)
            body, heads = rows[:header_rows], []
        for number, cells in enumerate(body):
            if number:
                self.emit(rule)
            for column, (spans, _align) in enumerate(cells):
                head = heads[column] if column < len(heads) else ""
                label = [Span(f"{head}: ", Style(fg="h1", bold=True))] if head.strip() else []
                self.para(label + spans, prefix, prefix + "  ", width)


#: The narrowest a table's column is made to fit the width (one narrower
#: by nature stays so); a table that does not fit with these is shown a row
#: after the other (Renderer.records).
MIN_COLUMN = 4


def fit_columns(natural: list[int], room: int) -> list[int] | None:
    """The widths of columns whose text takes *natural* columns, together at
    most *room*: the widest give way first, none below :data:`MIN_COLUMN`
    (but those narrower by nature) - None when even that is too wide. One
    cap for all, found by halving (a column a step, a table of thousands of
    columns took minutes)."""
    widths = [max(1, w) for w in natural]
    if sum(widths) <= room:
        return widths
    if sum(min(w, MIN_COLUMN) for w in widths) > room:
        return None
    low, high = MIN_COLUMN, max(widths)  # sum(min(w, low)) fits, sum(min(w, high)) does not
    while high - low > 1:
        middle = (low + high) // 2
        if sum(min(w, middle) for w in widths) <= room:
            low = middle
        else:
            high = middle
    widths = [min(w, low) for w in widths]
    left = room - sum(widths)
    for index, w in enumerate(natural):  # what is left goes to the first ones still cut
        if left <= 0:
            break
        if w > widths[index]:
            widths[index] += 1
            left -= 1
    return widths


_ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


#: List levels nested in the terminal; deeper items are shown at this depth
#: (as in every view: core.markdown_doc.LIST_DEPTH).
LIST_DEPTH = MD.LIST_DEPTH
#: A text longer than this is rendered in parts of about STREAM_LINES lines
#: (render_parts: markdown-it parses 100,000 list items in 7 s - the
#: terminal showed nothing meanwhile).
STREAM_CHARS = 500_000
STREAM_LINES = 2000
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_REFERENCE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*\S")
_TOP_ITEM = re.compile(r"^(?:[-+*]|\d{1,9}[.)])(?:[ \t]|$)")
#: A line of "---" (or "+++"): no part may begin with one - markdown-it read
#: a part beginning so as front matter, a section turned into a box.
#: An item of a top-level ordered list: its number.
_NUMBERED_ITEM = re.compile(r"^(\d{1,9})[.)](?:[ \t]|$)")
_FRONT_LINE = re.compile(r"^ {0,3}(?:-{3,}|\+{3,})[ \t]*\Z")


def text_parts(text: str, lines: int | None = None) -> list[str]:
    """*text* in parts of about *lines* lines (see _text_parts)."""
    return [part for part, _apart, _first in _text_parts(text, lines)]


def text_parts_at(text: str, lines: int | None = None) -> list[tuple[str, int | None]]:
    """(part, the line of *text* it begins at - None: the notes' part) of each part (see _text_parts)."""
    return [(part, first) for part, _apart, first in _text_parts(text, lines)]


def notes_of(text: str) -> list[str] | None:
    """The labels of *text*'s footnotes in the order they are numbered - a
    part of it is parsed with them (MD.parse's *notes*) - or None: none."""
    return (MD.note_labels(text) or None) if "[^" in text else None


def _text_parts(text: str, lines: int | None = None) -> list[tuple[str, bool, int | None]]:
    """*text* in parts of about *lines* lines that read as the whole does:
    cut only before a list item or a block of the top level (after an empty
    line), never in code; every link reference definition in each part.
    Footnotes: their definitions moved to the end (the last part shows them
    all; each part is parsed with them numbered across the text: notes_of)
    - a text with them was one part, 5 s before the page or the terminal
    showed anything of 1 MB. (An inline note, ^[...]: one part still.)"""
    lines = STREAM_LINES if lines is None else lines  # (read now: a test may make the parts small)
    if len(text) <= STREAM_CHARS:
        return [(text, False, 0)]
    plan = MD.note_plan(text) if "[^" in text else None
    if plan is None and "^[" in text:
        return [(text, False, 0)]  # (an inline note: numbered where it stands)
    notes, noted = "", frozenset()
    if plan is not None:  # (the notes' definitions: a part of their own, the last - never cut)
        text, notes, _labels, noted = plan
    rows = text.split("\n")
    cuts, fence, since, ordinal = [0], None, 0, None
    # (a footnote's definition no link's: all again in the last part - note_plan)
    definitions = [row for row in rows if _REFERENCE.match(row) and not row.lstrip().startswith("[^")]
    for number, row in enumerate(rows):
        opened = _FENCE.match(row)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        since += 1
        numbered = _NUMBERED_ITEM.match(row)
        if numbered:  # (a top-level ordered list's item: the number it is shown with)
            ordinal = int(numbered.group(1)) if ordinal is None else ordinal + 1
        elif row.strip() and row[:1] not in " \t":
            ordinal = None  # (the list has ended)
        if since >= lines and number and row[:1] not in " \t>|" and row.strip() and not _FRONT_LINE.match(row) \
                and (_TOP_ITEM.match(row) or not rows[number - 1].strip()) and number not in noted:
            cuts.append(number)
            since = 0
            if numbered and ordinal is not None:  # (a part beginning in a list: numbered on - "1997." then "1.")
                rows[number] = f"{ordinal}{row[numbered.end(1):]}"
    cuts.append(len(rows))
    tail = ("\n\n" + "\n".join(definitions) + "\n") if definitions else ""
    # (each with whether an empty line was before it: the blank line between
    # two blocks the parts are cut between - lost at every cut - or none,
    # between two items of a list)
    parts = [("\n".join(rows[a:b]) + tail, bool(a) and not rows[a - 1].strip(), a)
             for a, b in zip(cuts, cuts[1:]) if a < b]
    if notes:
        parts.append((notes + tail, True, None))
    return parts


def render_parts(text: str, options: Options | None = None):
    """*text* for the terminal in parts, as they are rendered (see
    text_parts): the first is there at once."""
    options = options or Options()
    text, flattened = MD.flatter(text, LIST_DEPTH)
    text, shallower = MD.quote_flatter(text)
    parts = _text_parts(text)
    labels = notes_of(text) if len(parts) > 1 else None
    for number, (part, apart, first) in enumerate(parts):
        shown = Renderer(options).render(MD.parse(part, notes=(labels, number == len(parts) - 1, first)
                                                  if labels else None))
        if shown.strip():  # (a part of nothing to show - definitions, a comment: no empty lines either)
            yield ("\n" + shown) if apart else shown
    if flattened or shallower:
        note = " ".join(([f"(lists nested more than {LIST_DEPTH} deep are shown flatter)"] if flattened else [])
                        + ([f"(quotes nested more than {MD.QUOTE_DEPTH} deep are shown flatter)"] if shallower
                           else []))
        painter = Painter(options.depth, DARK if options.dark else LIGHT)
        import textwrap

        yield "\n" + "\n".join(painter.paint(line, Style(fg="muted", italic=True))
                                for line in textwrap.wrap(note, max(20, options.width))) + "\n"


def render(text: str, options: Options | None = None) -> str:
    """*text* (Markdown) for the terminal. Lists nested deeper than
    LIST_DEPTH are shown flatter, said under the text (a list 3,000 deep was
    22 MB of indentation and wrapped lines, 7 s)."""
    return "".join(render_parts(text, options))


__all__ = ["ALERT_TITLES", "DARK", "LIGHT", "Options", "Painter", "Renderer", "colour_depth", "dark_background",
           "fit_columns", "image_protocol", "locate", "read_picture", "render", "render_parts", "safe_url", "wrap"]
