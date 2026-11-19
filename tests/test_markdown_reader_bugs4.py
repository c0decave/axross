"""Bugs of the fourth review of the Markdown reader, each first a failing test
here - most in Qt's own parser's path (md4c, the fallback without
markdown-it-py), some in both, and the typography pass.
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

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def view_of(text: str, full: bool, path: str = "", width: int = 900):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), path) if path else None)
    view.full = view.full and full
    view.resize(width, 700)
    view.show()
    view.render(text)
    end = time.monotonic() + 10
    while time.monotonic() < end and (view.status.text() or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return view


def images_of(view):
    found = []
    block = view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fmt = pieces.fragment().charFormat()
            if fmt.isImageFormat():
                image = fmt.toImageFormat()
                found.append((image.name(), image.width(), block.blockFormat().alignment()))
            pieces += 1
        block = block.next()
    return found


def _png(path: Path, width: int = 256, height: int = 256) -> None:
    from PyQt6.QtGui import QColor, QImage

    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor("teal"))
    assert image.save(str(path), "PNG")


# -- R4-1 images with an empty alt, raw width and alignment, in Qt's own parser ----------------------

def test_sad_qts_own_parser_shows_images_without_alt_at_their_asked_size_and_place(tmp_path):
    from PyQt6.QtCore import Qt

    _png(tmp_path / "logo.png")
    text = ('A ![](logo.png) B\n\n<p align="center">\n  <img src="logo.png" width="160"/>\n</p>\n\n'
            '<img src="logo.png">\n')
    view = view_of(text, full=False, path=str(tmp_path / "doc.md"))
    try:
        found = images_of(view)
        # (the asked size rides in the address's fragment: the file read is its path)
        assert [name.split("#")[0] for name, _w, _a in found] == ["logo.png"] * 3, found
        assert found[1][1] == 160 and found[1][2] & Qt.AlignmentFlag.AlignHCenter
    finally:
        view.deleteLater()


# -- R4-2 display math with cases in Qt's own parser ---------------------------------------------------

def test_sad_qts_own_parser_shows_cases_as_rows_not_as_a_list():
    text = "$$\nf(x) = \\begin{cases} x^2 & x \\ge 0 \\\\ -x & x < 0 \\end{cases}\n$$\n"
    view = view_of(text, full=False)
    try:
        plain = view.browser.toPlainText()
        assert "\\<" not in plain and "*" not in plain
        assert "x < 0" in plain and "−x" in plain  # (a minus sign: bugs6)
        document = view.browser.document()
        assert document.find("-x").block().textList() is None  # (no bullet)
    finally:
        view.deleteLater()


# -- R4-3 raw HTML's formatting in Qt's own parser ------------------------------------------------------

def test_sad_qts_own_parser_formats_raw_html_where_markdown_would_not():
    from PyQt6.QtGui import QFont

    text = ("<b> spaced </b> end and a<b>(paren)</b>b\n\n<ul><li>one</li><li>two</li></ul>\n\n"
            "<table><tr><th>H</th></tr><tr><td><a href=\"https://example.com\">link</a> <i>it</i></td></tr></table>\n")
    view = view_of(text, full=False)
    try:
        plain = view.browser.toPlainText()
        assert "**" not in plain and "[link" not in plain and "*" not in plain
        document = view.browser.document()
        assert document.find("spaced").charFormat().fontWeight() == QFont.Weight.Bold
        assert document.find("(paren)").charFormat().fontWeight() == QFont.Weight.Bold
        assert document.find("one").block().textList() is not None
        assert document.find("two").block().textList() is not None
        link = document.find("link")
        assert link.charFormat().anchorHref() == "https://example.com"
        assert document.find("it").charFormat().fontItalic()
    finally:
        view.deleteLater()


# -- R4-7 a gutter at the sides --------------------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_a_narrow_view_keeps_the_text_off_its_edges(full):
    from ui import markdown_view as MV

    view = view_of("Text " * 200 + "\n", full=full, width=600)
    try:
        left, _top, right, _bottom = view.browser.margins()
        assert left >= MV.GUTTER and right >= MV.GUTTER - 4
        first = view.browser.cursorRect(view.browser.document().find("Text"))
        assert first.left() + left >= MV.GUTTER  # (it was 4 pixels)
    finally:
        view.deleteLater()


# -- R4-5 long and deep lists ----------------------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_a_long_list_is_laid_out_whole_in_parts(full):
    from ui import markdown_view as MV

    count = MV.LIST_ITEMS + 500
    part, why = MV.renderable("".join(f"{n + 1}. item {n}\n" for n in range(count)))
    assert not why and part.count("\n\u200b\n") == (count - 1) // MV.LIST_PART  # (parts, a line between them)
    view = view_of("# L\n\n" + "".join(f"{n + 1}. item {n}\n" for n in range(count)) + "\nAfter.\n", full=full)
    try:
        text = view.browser.toPlainText()
        assert "```" not in text and f"item {count - 1}" in text and not view.notice.isVisible()
        last = view.browser.document().find(f"item {count - 1}").block()
        assert last.textList() is not None
        assert last.textList().itemText(last) == f"{count}."  # (numbered on: its part starts there)
    finally:
        view.deleteLater()


def test_sad_a_list_nested_thousands_deep_is_shown_flatter():
    from ui import markdown_view as MV

    text = "".join("  " * level + "- item\n" for level in range(2500))
    part, why = MV.renderable(text)
    assert why and max(len(line) - len(line.lstrip()) for line in part.splitlines()) <= 2 * MV.LIST_DEPTH


# -- R4-8 colspan and rowspan ----------------------------------------------------------------------

def test_sad_raw_html_cells_keep_their_span():
    pytest.importorskip("markdown_it")
    from PyQt6.QtGui import QTextTable

    text = ('<table><tr><th>H1</th><th>H2</th></tr><tr><td colspan="2">spanning cell</td></tr>'
            '<tr><td rowspan="2">tall</td><td>a</td></tr><tr><td>b</td></tr>'
            '<tr><td colspan="999" onclick="x">huge</td></tr></table>\n')
    view = view_of(text, full=True)
    try:
        table = next(f for f in view.browser.document().rootFrame().childFrames() if isinstance(f, QTextTable))
        assert table.cellAt(1, 0).columnSpan() == 2 and table.cellAt(2, 0).rowSpan() == 2
        assert table.columns() == 2  # (a span beyond 100 is not kept)
    finally:
        view.deleteLater()


# -- R4-6 math ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("tex, shown", [
    (r"\sum_{i=1}^{\infty}\frac{1}{i^2}", "∑_(i=1)^∞ 1/i²"),        # (not "∞1")
    (r"\lim_{x\to 0} f", "lim_(x→0) f"),
    (r"\left\| \mathbf{v} \right\|", "‖v‖"),
    (r"a =b", "a = b"),
    (r"\mathcal{L} + \mathcal{A}", "ℒ + 𝒜"),
    (r"f(x) = \begin{cases} 1 & x \ge 0 \\ 0 & x < 0 \end{cases}", "f(x) = ⎧1  x ≥ 0\n       ⎩0  x < 0"),
    (r"a \xrightarrow{f} b", "a —f→ b"),
])
def test_sad_math_reads_right_and_spaced(tex, shown):
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD

    assert MD.math_text(tex) == shown


def test_sad_qt_shows_scripts_as_scripts_and_only_the_unknown_part_as_code():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import to_html

    html = MD.math_html(r"\int_0^\infty e^{-x} \mathbf{v} \overbrace{a+b}")
    assert "∫<sub>0</sub><sup>∞</sup>" in html and "<b>v</b>" in html
    page = to_html(MD.parse(r"$\frac{a}{b} \weird{x} + \alpha$" + "\n")).replace("<i>", "").replace("</i>", "")
    assert "a/b" in page  # (its letters in italic since the tenth round: bugs10) and "α" in page and r"<code>\weird{x}</code>" in page


# -- R4-10 smaller ones -----------------------------------------------------------------------------

def test_sad_a_punycode_host_is_shown_as_written_never_as_its_lookalike():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import to_html

    page = to_html(MD.parse("<https://xn--pypal-4ve.com/login> and [x](https://xn--pypal-4ve.com/)\n"))
    assert ">https://xn--pypal-4ve.com/login<" in page and "pаypal" not in page


def test_sad_the_terminal_keeps_the_spaces_of_code_spans():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    out = ANSI.sub("", T.render("Run `a  b   c` and  then.\n", T.Options(width=60, depth="none")))
    assert "`a  b   c`" in out and "and then." in out


FOLDED = "<details>\n<summary>More <b>here</b></summary>\n\nHidden **text**\n\n</details>\n\nAfter.\n"


def test_sad_details_are_folded_and_open_on_a_click_of_their_summary():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import to_html_parts

    closed = "".join(to_html_parts(MD.parse(FOLDED), blocks=0))
    assert 'href="#axross-details-1"' in closed and "▸" in closed and "here" in closed
    assert "Hidden" not in closed and "After." in closed
    shown = "".join(to_html_parts(MD.parse(FOLDED), blocks=0, toggled={1}))
    assert "Hidden" in shown and "▾" in shown and "After." in shown
    # (open as the file asks - a click folds it)
    asked = FOLDED.replace("<details>", "<details open>")
    assert "Hidden" in "".join(to_html_parts(MD.parse(asked), blocks=0))
    assert "Hidden" not in "".join(to_html_parts(MD.parse(asked), blocks=0, toggled={1}))


def test_sad_folded_details_without_summary_nested_or_in_a_list_keep_the_page_whole():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import to_html_parts

    bare = "".join(to_html_parts(MD.parse("<details>\n\nInside\n\n</details>\n\nAfter.\n"), blocks=0))
    assert "Details" in bare and "Inside" not in bare and "After." in bare
    nested = ("<details><summary>A</summary>\n\n<details><summary>B</summary>\n\nDeep\n\n</details>\n\n"
              "</details>\n\n<details><summary>C</summary>\n\nThird\n\n</details>\n")
    page = "".join(to_html_parts(MD.parse(nested), blocks=0, toggled={1}))
    assert "B" in page and "Deep" not in page and "#axross-details-3" in page and "Third" not in page
    listed = "- one\n- <details><summary>S</summary>\n\n  inner\n\n  - x\n\n  </details>\n- three\n\nAfter.\n"
    page = "".join(to_html_parts(MD.parse(listed), blocks=0))
    assert "inner" not in page and "three" in page and "After." in page
    assert page.count("<ul>") == page.count("</ul>")


def test_sad_the_viewer_folds_and_unfolds_details_where_it_is():
    pytest.importorskip("markdown_it")
    from PyQt6.QtCore import QUrl

    view = view_of(FOLDED, True)
    text = view.browser.toPlainText()
    assert "More here" in text and "Hidden" not in text and "After." in text
    view.clicked(QUrl("#axross-details-1"))
    pump(0.2)
    assert "Hidden text" in view.browser.toPlainText()
    view.clicked(QUrl("#axross-details-1"))
    pump(0.2)
    assert "Hidden" not in view.browser.toPlainText()


def test_sad_an_exported_page_keeps_details_as_the_file_has_them():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import export_html

    page = export_html(MD.parse(FOLDED.replace("<details>", "<details open>")))
    assert "<details open" in page and "Hidden" in page and "<summary>" in page


# -- typography (R4-4, R4-7 and the typography pass) --------------------------------------------

def _blocks(view) -> list:
    out, block = [], view.browser.document().begin()
    while block.isValid():
        out.append(block)
        block = block.next()
    return out


def _block(view, text: str):
    return next(b for b in _blocks(view) if text in b.text())


def _fragment(view, text: str):
    for block in _blocks(view):
        pieces = block.begin()
        while not pieces.atEnd():
            if text in pieces.fragment().text():
                return pieces.fragment()
            pieces += 1
    raise AssertionError(text)


def _baseline(block, line: int = 0) -> float:
    found = block.layout().lineAt(line)
    return block.layout().position().y() + found.y() + found.ascent()


def _palette(view) -> dict:
    from ui.markdown_html import colours

    return colours(view.dark)


PROSE = "The quick brown fox jumps over the lazy dog, and then it runs on. " * 12


@pytest.mark.parametrize("full", [False, True])
def test_typo_the_text_is_large_enough_and_about_eighty_characters_a_line(full):
    from PyQt6.QtGui import QFontInfo

    view = view_of(PROSE + "\n", full, width=1400)
    assert QFontInfo(view.browser.document().defaultFont()).pixelSize() >= 15
    line = _block(view, "quick").layout().lineAt(0)
    assert 70 <= line.textLength() <= 95, line.textLength()


@pytest.mark.parametrize("full", [False, True])
def test_typo_headings_are_neutral_ruled_spaced_and_sized(full):
    from PyQt6.QtGui import QTextFormat

    view = view_of("# One\n\nBody one.\n\n## Two\n\nBody two.\n\n### Three\n\nBody three.\n\n#### Four\n\nBody four.\n",
                   full)
    palette, blocks = _palette(view), _blocks(view)
    for name in ("One", "Two", "Three", "Four"):
        heading = _block(view, name)
        assert heading.blockFormat().headingLevel()
        assert heading.begin().fragment().charFormat().foreground().color().name() == palette["text"], name
        assert heading.blockFormat().topMargin() >= 12, name
    ruler = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
    rules = [n for n, b in enumerate(blocks) if b.blockFormat().hasProperty(ruler)]
    # (a light rule under h1 and h2, as GitHub's)
    assert [blocks[n - 1].text() for n in rules] == ["One", "Two"]
    assert all(blocks[n].blockFormat().background().color().name() == palette["rule"] for n in rules)
    three, body = _block(view, "Three"), _block(view, "Body three")
    assert three.layout().lineAt(0).ascent() >= 1.15 * body.layout().lineAt(0).ascent()
    assert _baseline(body) - _baseline(three) >= 1.6 * body.layout().lineAt(0).height()


@pytest.mark.parametrize("full", [False, True])
def test_typo_inline_code_is_neutral_on_light_grey(full):
    view = view_of("Run `make all` now.\n", full)
    palette = _palette(view)
    fmt = _fragment(view, "make all").charFormat()
    assert fmt.foreground().color().name() == palette["text"]
    assert fmt.background().color().name() == palette["code_bg"]
    from ui.markdown_html import colours

    for dark in (False, True):
        assert colours(dark)["code_fg"] == colours(dark)["text"]


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_list_items_lines_are_closer_than_its_items(full):
    view = view_of("- " + "many long words " * 30 + "\n- second\n- third\n", full, width=700)
    first, second = _block(view, "many long"), _block(view, "second")
    assert first.layout().lineCount() >= 2
    pitch = _baseline(first, 1) - _baseline(first, 0)
    step = _baseline(second) - _baseline(first, first.layout().lineCount() - 1)
    assert step >= pitch + 3, (pitch, step)


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_code_blocks_language_is_on_its_box(full):
    view = view_of("Before.\n\n```python\nx = 1\n```\n\nAfter.\n", full)
    cursor = view.link_cursor(_block(view, "python").position())
    code = view.link_cursor(_block(view, "x = 1").position())
    assert cursor.currentTable() is not None and cursor.currentTable() == code.currentTable()
    assert view.code_block_at(_block(view, "x = 1").position()) == "x = 1\n"


@pytest.mark.parametrize("full", [False, True])
def test_typo_rules_are_light_with_room_around_them(full):
    from PyQt6.QtGui import QTextFormat

    view = view_of("Above.\n\n---\n\nBelow.\n", full)
    ruler = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
    rule = next(b for b in _blocks(view) if b.blockFormat().hasProperty(ruler))
    assert rule.blockFormat().background().color().name() == _palette(view)["rule"]
    line = _block(view, "Below").layout().lineAt(0).height()
    assert _baseline(_block(view, "Below")) - _baseline(_block(view, "Above")) >= 3 * line


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_table_has_room_under_it(full):
    from PyQt6.QtGui import QTextTable

    view = view_of("| a | b |\n|---|---|\n| 1 | 2 |\n\nAfter.\n", full)
    cell = view.link_cursor(_block(view, "2").position())
    table = cell.currentTable()
    assert isinstance(table, QTextTable)
    # (in the view: the last cell's line, its padding and border, then the room to the next line)
    bottom = view.browser.cursorRect(cell).bottom() + table.format().cellPadding() + table.format().border()
    top = view.browser.cursorRect(view.link_cursor(_block(view, "After").position())).top()
    assert top - bottom >= 10, (top, bottom)


def test_sad_qts_own_parser_draws_alerts_and_quotes_as_boxes_with_a_bar():
    from PyQt6.QtGui import QTextTable

    view = view_of("> [!WARNING]\n> Careful [here](https://x.org/).\n\nBetween.\n\n> Quoted [link](https://y.org/).\n",
                   False)
    palette = _palette(view)
    tables = [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]
    assert len(tables) == 2
    bars = [table.cellAt(0, 0).format().background().color().name() for table in tables]
    assert bars == [palette["warning"], palette["rule"]]
    inside = tables[0].cellAt(0, 1).firstCursorPosition()
    inside.setPosition(tables[0].cellAt(0, 1).lastCursorPosition().position(), inside.MoveMode.KeepAnchor)
    assert "Careful" in inside.selectedText()
    assert _fragment(view, "Warning").charFormat().foreground().color().name() == palette["warning"]
    for text in ("here", "link"):
        assert _fragment(view, text).charFormat().foreground().color().name() == palette["link"], text


def test_sad_an_export_of_qts_own_page_keeps_its_line_height_for_a_browser():
    from ui.markdown_html import safe_page

    view = view_of("Some text.\n\nMore text.\n", False)
    page = safe_page(view.browser.document().toHtml())
    assert not re.search(r"line-height:\s*\d+(\.\d+)?\s*;", page) and "-qt-line-height-type" not in page


def test_typo_the_export_buttons_arrow_has_room_beside_its_text():
    from PyQt6.QtWidgets import QStyle

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    dialog = MarkdownViewerDialog(LocalFS(), "")
    button = dialog.export_button
    needed = button.fontMetrics().horizontalAdvance(button.text()) \
        + button.style().pixelMetric(QStyle.PixelMetric.PM_MenuButtonIndicator)
    assert button.sizeHint().width() >= needed + 8
    dialog.deleteLater()


def test_sad_qts_own_parser_keeps_two_quotes_apart():
    from PyQt6.QtGui import QTextTable

    view = view_of("> [!TIP]\n> First.\n\n> Second.\n\n> Third.\n", False)
    tables = [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]
    assert len(tables) == 3
    assert "\ue093" not in view.browser.toPlainText() and "Second" in view.browser.toPlainText()


def test_sad_qts_own_parser_boxes_no_huge_block_at_once():
    """Moving a block into its box is one step on the GUI thread: a code
    block of 50,000 lines (a file shown as written) held it seconds."""
    from PyQt6.QtGui import QTextTable

    from ui import markdown_view as MV

    view = view_of("```\n" + "".join(f"line {n}\n" for n in range(MV.BOX_BLOCKS + 10)) + "```\n\n```\nsmall\n```\n",
                   False)
    tables = [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]
    assert len(tables) == 1 and "small" in view.link_cursor(tables[0].firstPosition()).block().text()


_SPACES = """
import sys, time
sys.path.insert(0, {root!r})
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from ui import markdown_view as MV
view = MV.MarkdownView(None)
view.full = view.full and {full!r}
view.resize(900, 700)
view.show()
view.render(open({path!r}, encoding="utf-8").read())
end = time.monotonic() + 20
while time.monotonic() < end and view.status.text():
    app.processEvents()
app.processEvents()
print(len(view.browser.toPlainText()))
"""


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_run_of_spaces_past_65535_never_holds_the_window(full, tmp_path):
    """Qt's layout of a line holding more than 65,535 spaces (or tabs that
    wide) before a word never ended: the window hung (a file of nested
    raw <blockquote>s indented that far)."""
    import subprocess

    path = tmp_path / "spaces.md"
    path.write_text("Before.\n\n" + " " * 66000 + "deep\n\n```\n" + " " * 66000 + "x\n```\n\n"
                    + "\t" * 17000 + "tabs\n\n" + "<blockquote> " * 70000 + "deep\n", encoding="utf-8")
    root = str(Path(__file__).resolve().parent.parent)
    try:
        out = subprocess.run([sys.executable, "-c", _SPACES.format(root=root, path=str(path), full=full)],
                             capture_output=True, text=True, timeout=60,
                             env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    except subprocess.TimeoutExpired:
        pytest.fail("the view hung on a long run of spaces")
    assert out.returncode == 0, out.stderr[-2000:]


def test_sad_qts_own_parser_formats_a_bounded_number_of_spans():
    """Each span the text passes mark (raw HTML's <sub>, a formula) is one
    format change on the GUI thread: 300,000 of them (a page of formulas)
    held it 1.5 s a piece. Beyond MARK_SPANS a page's spans stay plain."""
    from PyQt6.QtGui import QTextCharFormat

    from ui import markdown_view as MV

    count = MV.MARK_SPANS + 500
    view = view_of("H<sub>2</sub>O " * count + "\n", False)
    text = view.browser.toPlainText()
    assert text.count("H2O") == count and not MV._PRIVATE.search(text)
    sub, block = 0, view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            sub += pieces.fragment().charFormat().verticalAlignment() == QTextCharFormat.VerticalAlignment.AlignSubScript
            pieces += 1
        block = block.next()
    assert 0 < sub <= MV.MARK_SPANS
