"""Bugs of the eighth review of the Markdown reader, each first a failing test
here - in both of Qt's paths (markdown-it's page and Qt's own parser, md4c)
and the terminal where they share the bug. (Whole real documents are checked
by tests/test_markdown_corpus.py, the look by tests/test_markdown_golden.py.)
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
ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def view_of(text: str, full: bool, path: str = "", width: int = 900, height: int = 700, whole: bool = True):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), path) if path else None)
    view.full = view.full and full
    view.resize(width, height)
    view.show()
    view.render(text)
    end = time.monotonic() + 30
    while time.monotonic() < end and (view.status.text().startswith(MV.tr("Rendering…"))
                                      or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    if whole:
        view.load_rest()
        while time.monotonic() < end and view.more():
            APP.processEvents()
            time.sleep(0.005)
    pump(0.1)
    return view


def sections(count: int, rule: bool = True) -> str:
    """A text of *count* sections, a rule after each - each place a part may
    begin is a "---" line."""
    return "# Text\n\nIntro.\n\n" + "".join(
        f"## Section {n}\nWords of section {n}.\n\n- one\n- two\n\n" + ("---\n\n" if rule else "")
        for n in range(count))


# -- 1. Qt's own parser: a part beginning with "---" was read as front matter -------------------------

def test_sad_no_part_for_qts_own_parser_begins_with_a_rule():
    from ui import markdown_view as MV

    parts = MV.markdown_parts(sections(80), first=20)
    assert len(parts) > 1
    assert not [part[:20] for part in parts[1:] if MV.FRONT_LINE.match(part.lstrip("\n").split("\n", 1)[0])]


def test_sad_qts_own_parser_shows_every_section_of_a_text_in_parts():
    view = view_of(sections(80), False)
    headings = [block for block in _blocks(view.browser.document()) if block.blockFormat().headingLevel()]
    assert len(headings) == 81, [b.text() for b in headings][:5]


# -- 2. markdown-it's page: the stand-in block left a blank band -----------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_page_laid_out_in_parts_keeps_no_stand_in(full):
    view = view_of(sections(60), full, whole=False)
    view.load_rest()
    end = time.monotonic() + 20
    while time.monotonic() < end and view.more():
        pump(0.02)
    tall = [(block.blockNumber(), block.blockFormat().lineHeight()) for block in _blocks(view.browser.document())
            if block.blockFormat().lineHeightType() == 2 and block.blockFormat().lineHeight() > 100]
    assert not tall  # (an empty block as high as the parts were, mid-page)


# -- 3. Qt's own parser: an image once per piece of its alt text -----------------------------------

@pytest.mark.parametrize("text", ["![](my_pic_v2.png)\n", '<img src="my_pic_v2.png">\n', "![a *b* c](my_pic_v2.png)\n",
                                  "![a `c` d](my_pic_v2.png)\n", "![a &amp; b](my_pic_v2.png)\n"])
def test_sad_qts_own_parser_shows_an_image_once(text, tmp_path):
    picture = tmp_path / "my_pic_v2.png"
    picture.write_bytes((ROOT / "tests" / "golden" / "markdown" / "pic.png").read_bytes())
    view = view_of(text, False, path=str(tmp_path / "doc.md"))
    assert view.browser.toPlainText().count("￼") == 1


# -- 6. the terminal (and markdown-it's long text in parts): a part read as front matter ------------

def test_sad_no_part_of_a_long_text_begins_with_a_rule(monkeypatch):
    from core import markdown_term as T

    monkeypatch.setattr(T, "STREAM_CHARS", 1000)
    monkeypatch.setattr(T, "STREAM_LINES", 50)
    text = sections(300)
    parts = T.text_parts(text, lines=50)
    assert len(parts) > 1
    assert not [part[:20] for part in parts[1:] if part.startswith("---")]
    shown = ANSI.sub("", "".join(T.render_parts(text, T.Options(width=80))))
    assert "front matter" not in shown.lower() and shown.count("Section 299") == 1


def _blocks(document):
    block = document.begin()
    while block.isValid():
        yield block
        block = block.next()


def test_sad_markdown_its_page_shows_an_image_block_on_its_own_line(tmp_path):
    # (a block of one <img> went up into the paragraph before it, at its line's end)
    (tmp_path / "a_b.png").write_bytes((ROOT / "tests" / "golden" / "markdown" / "pic.png").read_bytes())
    view = view_of('Paragraph before.\n\n<img src="a_b.png">\n\nAfter.\n', True, path=str(tmp_path / "doc.md"))
    document = view.browser.document()
    image = document.find("￼")
    assert not image.isNull() and image.block() != document.find("Paragraph before").block()


# -- 4. Qt's own parser: an address in <…> ----------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_an_address_in_angle_brackets_is_a_link_and_an_image(full, tmp_path):
    from PyQt6.QtCore import QUrl

    (tmp_path / "logo.png").write_bytes((ROOT / "tests" / "golden" / "markdown" / "pic.png").read_bytes())
    view = view_of("See [the file](<my file.md>) here.\n\n![logo](<logo.png>)\n", full, path=str(tmp_path / "doc.md"))
    document = view.browser.document()
    link = document.find("the file")
    assert link.charFormat().isAnchor()
    assert QUrl(link.charFormat().anchorHref()).path() == "my file.md"
    assert view.browser.toPlainText().count("￼") == 1 and "not shown" not in view.browser.toPlainText()


# -- 5. markdown-it and the terminal: a dropped tag's end looked for, quadratic ----------------------

def test_sad_a_paragraph_of_many_dropped_tags_takes_no_time():
    from core import markdown_doc as MD
    from core import markdown_term as T

    text = "<script> " * 12_000  # (one paragraph: 4,000 took 1 s, 30,000 more than 40 s)
    began = time.monotonic()
    MD.parse(text)
    T.render(text)
    assert time.monotonic() - began < 2.0
    assert "bold" in ANSI.sub("", T.render("A <script> word, then <b>bold</b>.\n", T.Options(width=80)))


# -- 7. Qt's own parser: parts by size as well as by lines --------------------------------------------

def test_sad_qts_own_parser_cuts_a_text_of_long_lines_into_small_parts():
    from ui import markdown_view as MV

    paragraph = "word " * 200  # (1,000 characters a line: 200 lines were one part of 70 KB)
    parts = MV.markdown_parts("\n\n".join(paragraph for _ in range(100)), first=MV.PART_LINES // 4)
    assert max(len(part) for part in parts) <= MV.PART_CHARS + 2 * len(paragraph)


# -- 8. Qt's own parser's lows ------------------------------------------------------------------------

def test_sad_qts_own_parser_makes_a_definition_after_a_labelled_code_block():
    view = view_of("Text.\n\n```sh\nx\n```\n\nTerm two\n: Its definition\n", False)
    text = view.browser.toPlainText()
    assert "Term two : Its" not in text and "Term two" in text and "Its definition" in text


def test_sad_qts_own_parser_sets_two_lists_apart_with_githubs_bullets():
    from PyQt6.QtGui import QTextListFormat

    view = view_of("- a\n- b\n\n1. one\n2. two\n\n* c\n* d\n", False)
    document = view.browser.document()
    one, c = document.find("one").block(), document.find("c").block()
    assert one.blockFormat().topMargin() >= 10 and c.blockFormat().topMargin() >= 10  # (they ran together)
    assert c.textList().format().style() == QTextListFormat.Style.ListDisc  # ("*": a circle)
    assert document.find("b").block().blockFormat().topMargin() < 10  # (items of one list: close)


@pytest.mark.parametrize("full", [True, False])
def test_sad_display_math_inside_a_paragraph_is_math(full):
    view = view_of("A paragraph with $$\\frac{a}{b}$$ in it.\n", full)
    text = view.browser.toPlainText()
    assert "$$" not in text and "frac" not in text and "paragraph with" in text


# -- 9. typography --------------------------------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_typo_a_list_in_a_lists_last_item_follows_at_the_items_rhythm(full):
    view = view_of("1. first\n2. second\n   - inner\n\n- [ ] outer task\n  - [x] inner task\n\nText.\n", full)
    document = view.browser.document()
    layout = document.documentLayout()

    def top(needle: str) -> float:
        return layout.blockBoundingRect(document.find(needle).block()).top()

    step = top("second") - top("first")
    assert abs((top("inner") - top("second")) - step) <= 3  # (the list's room after it came first: 7 px more)
    assert abs((top("inner task") - top("outer task")) - step) <= 3


def test_typo_two_cases_have_a_brace_with_its_middle():
    from core import markdown_doc as MD

    grid, spans, *_rest, tall = MD.math_grid(r"f(x) = \begin{cases} x^2 & x \ge 0 \\ -x & x < 0 \end{cases}")
    # (⎧⎩: a parenthesis - ⎧⎨⎩ with a row between since the eighth review, one
    # brace as tall as the rows since the tenth: bugs10; its size step with it
    # since the eleventh: bugs11)
    assert [row[1] for row in grid] == ["{", ""] and tall == [(0, 1, 2, 3)] and (0, 1, 2, 1) in spans


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_fraction_keeps_room_from_the_equals_sign(full):
    view = view_of("$$\nf(x) = \\frac{a+b}{2}\n$$\n", full)
    document = view.browser.document()
    equals, numerator = document.find("="), document.find("a+b")
    numerator.setPosition(numerator.selectionStart())
    room = view.browser.cursorRect(numerator).left() - view.browser.cursorRect(equals).right()
    # (some room - 16 px was too wide a gap beside a fraction: the tenth review; a few pixels since -
    # the bar beyond its numerator by 3 - the formula a row of items: bugs12)
    assert not equals.isNull() and 4 <= room <= 16, room


def test_typo_markdown_its_badge_chip_is_inline_text_in_its_links_colour():
    from ui.markdown_html import colours

    view = view_of("[![CI](https://x.org/b.svg)](https://ci) and ![badge](https://x.org/c.svg)\n", True)
    document = view.browser.document()
    linked, alone = document.find("CI").charFormat(), document.find("badge").charFormat()
    palette = colours(view.dark)  # (the theme the run is in)
    assert linked.background().style().name == "NoBrush" and alone.background().style().name == "NoBrush"
    assert linked.foreground().color().name() == palette["link"] and alone.foreground().color().name() == palette["muted"]


# -- 10. lows ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_link_hiding_javascript_behind_an_entity_is_no_link(full):
    view = view_of("[ent](&#106;avascript:alert(1)) here\n", full)
    found = view.browser.document().find("ent")
    assert not found.charFormat().isAnchor() and "ent here" in view.browser.toPlainText()


def test_sad_the_terminals_file_links_are_percent_encoded(tmp_path):
    from core import markdown_term as T

    folder = tmp_path / "a ~b#c"
    folder.mkdir()
    (folder / "x y.md").write_text("x")
    out = T.render("[s](<x y.md>)\n", T.Options(width=80, depth="truecolor", folder=str(folder), hyperlinks=True))
    links = [link for link in re.findall(r"\x1b\]8;;([^\x1b]*)\x1b\\", out) if link]
    assert links == ["file://" + str(folder).replace(" ", "%20").replace("#", "%23") + "/x%20y.md"]  # ("#" was raw)


def test_typo_an_image_not_shown_is_a_chip_not_a_button():
    from ui import markdown_view as MV

    image = MV.placeholder("Image not shown: x.png (not found)")
    assert image.pixelColor(0, 0).alpha() == 0  # (rounded - it was a framed box)
    middle = image.height() // 2
    assert image.pixelColor(1, middle) == image.pixelColor(3, middle)  # (no frame line at its edge)


@pytest.mark.parametrize("full", [True, False])
def test_typo_math_without_a_math_font_is_in_the_texts_face(full):
    from PyQt6.QtGui import QFontDatabase, QFontInfo

    if any(name in QFontDatabase.families() for name in ("STIX Two Math", "Latin Modern Math", "Cambria Math")):
        pytest.skip("a math font is installed: formulas are set in it")
    view = view_of("Text with $x^2 + y$ inline.\n", full)
    document = view.browser.document()
    math = document.find("y").charFormat().font()
    # (a serif face of the math faces' fall-back - DejaVu Serif last - since the thirteenth review, bugs14: the
    # sans text's own italic was the formulas' before)
    from ui.markdown_html import MATH_FONTS

    assert QFontInfo(math).family() in MATH_FONTS, QFontInfo(math).family()


@pytest.mark.parametrize("full", [True, False])
def test_typo_plain_front_matter_is_a_table_as_githubs(full):
    view = view_of("---\ntitle: Notes\ntags: [a, b]\n---\n\n# Body\n", full)
    document = view.browser.document()
    key, value = document.find("title"), document.find("Notes")
    assert key.currentTable() is not None and key.currentTable() == value.currentTable()
    assert key.charFormat().fontWeight() >= 600 and "yaml" not in view.browser.toPlainText()
    assert view.headings() == ["Body"]


def test_typo_dark_code_has_the_same_colours_in_both_paths():
    from PyQt6.QtGui import QColor, QPalette

    def dark() -> QPalette:
        palette = QPalette()
        for role, colour in ((QPalette.ColorRole.Window, "#1f1f1f"), (QPalette.ColorRole.Base, "#181818"),
                             (QPalette.ColorRole.Text, "#e6e6e6"), (QPalette.ColorRole.WindowText, "#e6e6e6")):
            palette.setColor(role, QColor(colour))
        return palette

    from core.local_fs import LocalFS  # noqa: F401 - (as view_of)
    from ui import markdown_view as MV

    words = ("def", "hello", "str", "None", "print", "len", '"hi"', "42", "return")
    seen = {}
    for full in (True, False):
        view = MV.MarkdownView(None)
        view.full = view.full and full
        view.setPalette(dark())
        view.resize(600, 300)
        view.show()
        view.render('```python\ndef hello(name: str) -> None:\n    print(len(name), "hi")\n    return 42\n```\n')
        pump(1.0)
        document = view.browser.document()
        colours = {}
        block = document.begin()
        while block.isValid():
            for word in words:
                at = block.text().find(word)
                if at < 0 or word in colours:
                    continue
                if full:
                    colours[word] = document.find(word).charFormat().foreground().color().name()
                else:  # (Qt's own parser's: a highlighter's formats)
                    for piece in block.layout().formats():
                        if piece.start <= at < piece.start + piece.length:
                            colours[word] = piece.format.foreground().color().name()
            block = block.next()
        seen[full] = colours
    assert seen[True] == seen[False]  # (str, print, len: plain on markdown-it's page, 42 as a string)
