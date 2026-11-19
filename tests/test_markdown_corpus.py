"""The Markdown reader over real documents - the project's README, every
docs/*.md, the CHANGELOG, a few READMEs of installed packages and a text in
many parts made to hit the cuts - in both of Qt's paths (markdown-it's page
and Qt's own parser, md4c), each page laid out whole:

- its headings are the text's (text and count);
- it shows as many images as the text has (a picture or a chip each);
- no blank band taller than a few lines is left in it;
- every paragraph's first words are in it.

The golden images (test_markdown_golden.py) guard the look of one page;
these guard what a page in parts lost or repeated at its cuts (a section
read as front matter, a stand-in block left as a blank band, an image once
per piece of its alt text) - run them before every commit.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it", reason="markdown-it-py not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden" / "markdown"
#: A blank band taller than this many lines of text fails.
BAND_LINES = 4
_WORD = re.compile(r"[^\W_]{2,}|\d+")


def _documents() -> list[Path]:
    found = [ROOT / "README.md", ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").glob("*.md")),
             GOLDEN / "parts.md"]
    try:
        import mdit_py_plugins
        import markdown_it

        for package in (markdown_it, mdit_py_plugins):
            found += sorted(Path(package.__file__).parent.rglob("README.md"))[:3]
    except ImportError:  # pragma: no cover
        pass
    return [path for path in found if path.is_file()]


DOCUMENTS = _documents()


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.002)


def laid_out_whole(path: Path, full: bool):
    """A view of *path*, its page laid out to the end."""
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), str(path)), outline=False)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render(path.read_text(encoding="utf-8", errors="replace"))
    end = time.monotonic() + 60
    while time.monotonic() < end and view.status.text().startswith(MV.tr("Rendering…").rstrip("…")):
        pump(0.02)
    view.load_rest()
    while time.monotonic() < end and (view.more() or view.asked - set(view.images)):
        pump(0.02)
    pump(0.1)
    assert not view.more(), f"{path.name}: not laid out whole in time"
    return view


def _blocks(document):
    block = document.begin()
    while block.isValid():
        yield block
        block = block.next()


def _words(text: str) -> str:
    return " ".join(_WORD.findall(text.lower()))


def _source(path: Path):
    """(headings, images, first words of each paragraph) of *path*'s text, as
    markdown-it reads it (what a closed <details> hides left out)."""
    from core import markdown_doc as MD

    doc = MD.parse(path.read_text(encoding="utf-8", errors="replace"))
    headings, images, firsts, closed = [], 0, [], []  # (closed: each <details> open, whether it hides)

    def html(token) -> None:
        nonlocal images
        for event in MD.html_events(token):
            if event[0] == "start" and event[1] == "details":
                closed.append("open" not in event[2])
            elif event[0] == "end" and event[1] == "details" and closed:
                closed.pop()
            elif event[0] == "start" and event[1] == "img" and not any(closed):
                images += 1

    tokens = doc.tokens
    for index, token in enumerate(tokens):
        if token.type == "safe_html_block":
            html(token)
        if any(closed):
            continue
        if token.type == "heading_open":
            headings.append(_words(tokens[index + 1].content))
        if token.type == "inline":
            children = token.children or []
            for child in children:
                if child.type == "image":
                    images += 1
                elif child.type == "safe_html_inline":
                    html(child)
            if tokens[index - 1].type == "paragraph_open" and children and children[0].type == "text":
                words = _WORD.findall(children[0].content.lower())[:3]
                if len(words) >= 2:
                    firsts.append(" ".join(words))
    return headings, images, firsts


def _page(view):
    """(headings, images shown, the page's words, blank bands as (top, height))."""
    from PyQt6.QtGui import QTextFormat

    from ui.markdown_html import CHIP

    RULE = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
    document = view.browser.document()
    layout = document.documentLayout()
    headings, images, spans = [], 0, []
    for block in _blocks(document):
        if block.blockFormat().headingLevel():
            headings.append(_words(block.text()))
        it = block.begin()
        while not it.atEnd():
            piece = it.fragment()
            if piece.charFormat().isImageFormat():
                images += piece.length()
            it += 1
        images += block.text().count(CHIP)
        if block.text().strip() or block.blockFormat().hasProperty(RULE):  # (text, or a rule)
            rect = layout.blockBoundingRect(block)
            spans.append((rect.top(), rect.bottom()))
    bands, reach = [], 0.0
    line = view.browser.fontMetrics().lineSpacing()
    for top, bottom in sorted(spans):
        if top - reach > BAND_LINES * line + 60:
            bands.append((int(reach), int(top - reach)))
        reach = max(reach, bottom)
    end = document.size().height()
    if end - reach > BAND_LINES * line + 60:
        bands.append((int(reach), int(end - reach)))
    return headings, images, _words(document.toPlainText()), bands


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("path", DOCUMENTS, ids=[str(p.relative_to(p.parents[1])) for p in DOCUMENTS])
def test_happy_a_real_document_is_shown_whole(path, full):
    headings, images, firsts = _source(path)
    view = laid_out_whole(path, full)
    try:
        shown, shown_images, words, bands = _page(view)
        from ui.markdown_html import CHIP

        shown_images -= path.read_text(encoding="utf-8", errors="replace").count(CHIP)  # (written: no image)
        problems = []
        if shown != headings:
            missing = [h for h in headings if h not in shown]
            extra = [h for h in shown if h not in headings]
            problems.append(f"headings: {len(shown)} shown, {len(headings)} in the text; "
                            f"missing {missing[:5]}, not in the text {extra[:5]}")
        if shown_images != images:
            problems.append(f"images: {shown_images} shown, {images} in the text")
        if bands:
            problems.append(f"blank bands (top, height): {bands[:5]}")
        lost = [first for first in firsts if first not in words]
        if lost:
            problems.append(f"{len(lost)} of {len(firsts)} paragraphs not shown, e.g. {lost[:5]}")
        assert not problems, f"{path.name}: " + "; ".join(problems)
    finally:
        view.close()
        view.deleteLater()


# -- a page in parts is the page whole ---------------------------------------------------------------

def _signature(view) -> list[tuple]:
    """Each block of the page: its text, heading level, list (style, depth,
    number), indent, margins, background, cell, and its first letters' weight,
    slant, fixed pitch, image."""
    from PyQt6.QtGui import QTextCursor

    out = []
    for block in _blocks(view.browser.document()):
        fmt = block.blockFormat()
        it = block.begin()
        chars = it.fragment().charFormat() if not it.atEnd() else block.charFormat()
        items = block.textList()
        listed = (items.format().style(), items.format().indent(), items.itemText(block)) if items else None
        table = QTextCursor(block).currentTable()
        cell = None
        if table is not None:
            found = table.cellAt(QTextCursor(block))
            cell = (found.row(), found.column(), table.rows(), table.columns())
        out.append((block.text()[:70].rstrip(), fmt.headingLevel(), listed, fmt.indent(), round(fmt.leftMargin()),
                    round(fmt.topMargin()), round(fmt.bottomMargin()),
                    fmt.background().color().name() if fmt.background().style().value else None, cell,
                    chars.fontWeight(), chars.fontItalic(), chars.fontFixedPitch(),
                    chars.isImageFormat() and chars.toImageFormat().name()))
    while out and not out[-1][0] and out[-1][2] is None and out[-1][8] is None:
        out.pop()  # (empty lines the page ends with: nothing to see - a trailing space neither)
    return out


def _laid_out(path: Path, full: bool, monkeypatch, cut: int | None) -> list[tuple]:
    from core import markdown_term as T
    from ui import markdown_view as MV

    with monkeypatch.context() as patch:
        if cut is None:  # (whole: one part)
            for name, value in (("PART_LINES", 10**7), ("PART_CHARS", 10**9), ("PART_BLOCKS", 10**7),
                                ("EAGER_BLOCKS", 10**7)):
                patch.setattr(MV, name, value)
        else:  # (parts of a few lines each: every place a part may begin is one)
            for name, value in (("PART_LINES", cut), ("PART_CHARS", cut * 40), ("PART_BLOCKS", max(3, cut // 4))):
                patch.setattr(MV, name, value)
            patch.setattr(T, "STREAM_CHARS", 0)
            patch.setattr(T, "STREAM_LINES", cut)
        view = laid_out_whole(path, full)
        try:
            return _signature(view)
        finally:
            view.close()
            view.deleteLater()


IN_PARTS = [ROOT / "README.md", ROOT / "docs" / "PROXY_SUPPORT.md", GOLDEN / "parts.md", GOLDEN / "showcase.md"]


#: A long list numbered "1." on every line - cut by renderable() too - and a bulleted one.
LISTS = ("# Lists\n\n" + "".join(f"1. item number {n}\n" for n in range(1, 3101))
         + "\nBetween.\n\n" + "".join(f"- bullet {n}\n" for n in range(1, 120)))


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("path", [p for p in IN_PARTS if p.is_file()] + ["lists"],
                         ids=lambda p: getattr(p, "name", p))
def test_happy_a_page_in_parts_is_the_page_whole(path, full, monkeypatch, tmp_path):
    if path == "lists":
        path = tmp_path / "lists.md"
        path.write_text(LISTS, encoding="utf-8")
    whole = _laid_out(path, full, monkeypatch, None)
    parts = _laid_out(path, full, monkeypatch, 20)
    differ = [(n, a, b) for n, (a, b) in enumerate(zip(whole, parts, strict=False)) if a != b]
    assert len(whole) == len(parts) and not differ, \
        f"{path.name}: {len(whole)} blocks whole, {len(parts)} in parts; first differences: {differ[:3]}"


@pytest.mark.parametrize("path", [p for p in IN_PARTS if p.is_file()] + ["lists"],
                         ids=lambda p: getattr(p, "name", p))
def test_happy_the_terminal_in_parts_is_the_terminal_whole(path, monkeypatch):
    from core import markdown_doc as MD
    from core import markdown_term as T

    text = LISTS if path == "lists" else path.read_text(encoding="utf-8")
    options = T.Options(width=80, depth="none")
    flat, _deep = MD.flatter(text, T.LIST_DEPTH)
    whole = T.Renderer(options).render(MD.parse(flat))
    monkeypatch.setattr(T, "STREAM_CHARS", 0)
    monkeypatch.setattr(T, "STREAM_LINES", 20)
    parts = "".join(T.render_parts(text, options))
    if whole != parts:  # (a blank line lost at every cut, a list numbered from 1 again)
        import difflib

        differ = list(difflib.unified_diff(whole.splitlines(), parts.splitlines(), lineterm="", n=1))
        pytest.fail("in parts the terminal shows it otherwise:\n" + "\n".join(differ[:20]))
