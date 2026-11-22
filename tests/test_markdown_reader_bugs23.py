"""The twenty-third round of the Markdown reader (the twenty-second review):
a line of raw HTML a million characters long laid out in one piece (1.1 s in
the window, 18 s in a PDF); an export or a print the window was closed
during, stuck in its event loop until the program ended; Qt's own parser's
page - axross's own viewer's, without markdown-it-py - cut only after an empty
line (50,000 setext headings, headings in a quote, a long paragraph right
under a heading, a fence or a definition: 1 to 4 s), a line of no-break spaces
(11 s), runs of "<a" and "[" (1 to 4 s) and two passes before it of O(n^2)
(two minutes); marks and doubled images in its page; a false "lists nested
more than 16 deep" over deep code; the first parts of big tables past 0.1 s;
and the small things (Find's "++", a code block's label, the colour emoji
font as the page's emoji family). Each test failed before.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests.test_markdown_reader_bugs20 import _Turns  # noqa: E402
from tests.test_markdown_reader_bugs22 import (  # noqa: E402,F401 - _closed_after: the fixture, used by name
    PARSERS, _closed_after, _longest_turn, within_turn)
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _viewer(tmp_path, text: str, full: bool = True):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "page.md"
    page.write_text(text, encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.view.full = viewer.view.full and full
    viewer.resize(1000, 800)
    viewer.show()
    if not full:
        viewer.view.render(text)
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 120)
    until(lambda: not viewer.view._scheduled, 120)
    pump(0.2)
    return viewer


def _pdf_turn(tmp_path, text: str, full: bool = True) -> float:
    """The window's longest turn exporting *text*'s page as PDF."""
    viewer = _viewer(tmp_path, text, full)
    target = str(tmp_path / "page.pdf")
    turns = _Turns()
    made = viewer.export_pdf(target)
    pump(0.1)
    longest = turns.stop()
    assert made == target and os.path.getsize(target) > 0
    viewer.close()
    return longest


def _shown(text: str, full: bool = False) -> str:
    """*text*'s page as its plain text (Qt's own parser's by default)."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    until(lambda: not view._scheduled, 30)
    shown = view.browser.document().toPlainText()
    view.close()
    view.deleteLater()
    return shown


# -- F1: raw HTML with a long line ---------------------------------------------------------------------

HTML_LINES = {
    "a div of 2 MB": lambda: "<div>\n" + "word " * 400000 + "\n</div>\n",
    "a line after <br>": lambda: "<br>\n" + "**b** " * 300000 + "\n",
    "a <p> of 2 MB": lambda: "<p>" + "word " * 400000 + "</p>\n",
}


@pytest.mark.parametrize("name", sorted(HTML_LINES))
def test_sad_a_long_line_of_raw_html_holds_no_turn(name):
    """One text event of 2 MB was one piece of the block: 1.1 s in one turn (markdown-it's page)."""
    text = HTML_LINES[name]()
    within_turn(lambda: _longest_turn(text, True), text, name)


def test_sad_a_long_line_of_raw_html_is_cut_by_its_characters_all_of_it_kept():
    from core import markdown_doc as MD
    from ui import markdown_html as H

    tokens = H._html_pieces(MD.parse("<div>\n" + "word " * 40000 + "\n</div>\n\n<br>\n" + "x " * 30000 + "\n").tokens)
    pieces = [MD.html_events(token) for token in tokens if token.type == "safe_html_block"]
    assert len(pieces) > 20
    for events in pieces:  # (each piece at most a piece's text, its elements begun and ended in it)
        assert sum(len(event[1]) for event in events if event[0] == "text") <= 2 * H.PARAGRAPH_TEXT
        assert sum(1 for e in events if e[0] == "start" and e[1] == "div") \
            == sum(1 for e in events if e[0] == "end" and e[1] == "div")
    words = "".join(event[1] for events in pieces for event in events if event[0] == "text").split()
    assert words.count("word") == 40000 and words.count("x") == 30000


def test_sad_a_pdf_of_a_long_line_of_raw_html_holds_no_turn(tmp_path):
    """Each of its pages drew the whole block again: 18 s in one turn for 2 MB (pages x lines)."""
    text = HTML_LINES["a div of 2 MB"]()
    within_turn(lambda: _pdf_turn(tmp_path, text), text, "pdf")


# -- F2: the window closed during an export ------------------------------------------------------------

@pytest.mark.parametrize("kind", ["html", "pdf"])
def test_sad_closing_the_window_during_an_export_ends_the_export(tmp_path, kind, monkeypatch):
    """Escape, the close button, axross quitting - while the page was made on a worker: the export's event
    loop waited for a result the closed window never got, until the program ended (then RuntimeError)."""
    from PyQt6.QtCore import QTimer

    from ui import markdown_html as H
    from ui import markdown_view as MV

    from core.local_fs import LocalFS
    from ui.markdown_viewer import open_markdown_viewer

    page = tmp_path / "small.md"
    page.write_text("# Hi\n\ntext\n", encoding="utf-8")
    viewer = open_markdown_viewer(LocalFS(), str(page))  # (as axross opens one: deleted when closed)
    assert until(lambda: viewer.view._readable, TB.READY_SECONDS)
    pump(0.2)
    slow_html, slow_parts = H.export_html_pieces, MV.print_parts
    # (markdown-it's Export HTML makes its page a piece at a time: export_html_pieces - 0.16.12)
    monkeypatch.setattr(H, "export_html_pieces", lambda *a, **k: (time.sleep(1.5), slow_html(*a, **k))[1])
    monkeypatch.setattr(MV, "print_parts", lambda *a, **k: (time.sleep(1.5), slow_parts(*a, **k))[1])
    QTimer.singleShot(100, viewer.close)
    began = time.monotonic()
    target = str(tmp_path / f"page.{kind}")
    made = viewer.export_html(target) if kind == "html" else viewer.export_pdf(target)
    took = time.monotonic() - began
    assert made == "", (made, took)
    TB.budget(took < 1.2, (made, took))
    assert not os.path.exists(target)
    pump(2.0)  # (the worker's result, delivered to no one)


def test_sad_closing_the_window_while_its_pdf_s_pages_are_drawn_ends_the_export(tmp_path, monkeypatch):
    """Closed while the parts were laid out and drawn (a turn between two pages): no part or progress
    window of the closed one touched, the PDF cut short taken away."""
    from PyQt6.QtCore import QTimer

    from core.local_fs import LocalFS
    from ui import markdown_viewer as V
    from ui.markdown_viewer import open_markdown_viewer

    drawn, draw = [], V._PagePrinter._draw

    def drawing(self, *args, **kwargs):  # (the user closes the window as the third page is drawn)
        drawn.append(1)
        if len(drawn) == 3:
            QTimer.singleShot(0, viewer.close)
        return draw(self, *args, **kwargs)

    monkeypatch.setattr(V._PagePrinter, "_draw", drawing)

    page = tmp_path / "long.md"
    page.write_text("".join(f"## Section {n}\n\nThe words of section {n}.\n\n" for n in range(4000)),
                    encoding="utf-8")
    viewer = open_markdown_viewer(LocalFS(), str(page))
    assert until(lambda: viewer.view._readable, 60)
    pump(0.2)
    target = str(tmp_path / "long.pdf")
    made = viewer.export_pdf(target)
    assert made == "" and not os.path.exists(target) and 3 <= len(drawn) < 10, (made, len(drawn))
    pump(0.5)


# -- F3: Qt's own parser's parts -------------------------------------------------------------------------

MD4C_CASES = {
    "F3 50,000 setext headings": lambda: "H\n=\n" * 50000,
    "F3 50,000 headings in a quote": lambda: "> # h\n" * 50000,
    "F3 a long paragraph under a heading": lambda: "# Title\n" + "[a](https://e.com) " * 50000 + "\n",
    "F3 a long paragraph under a fence": lambda: "```\ncode\n```\n" + "[a](https://e.com) " * 50000 + "\n",
    "F3 a long paragraph under a definition": lambda: "[r]: https://e.com\n" + "[a][r] " * 50000 + "\n",
    "F3 50,000 definitions and their references": lambda: "".join(
        f"[r{i}]: https://e.com/{i}\n" for i in range(50000)) + "".join(f"[r{i}] " for i in range(50000)) + "\n",
    "F4 300,000 no-break spaces": lambda: "\u00a0" * 300000 + "\n",
    "F4 no-break and narrow spaces": lambda: "\u202f\u2007\u00a0" * 100000 + "x\n",
    "F5 <a 49,500 times": lambda: "<a" * 49500 + "\n",
    "F5 [a 49,500 times": lambda: "[a" * 49500 + "\n",
    "F5 [ 99,000 times": lambda: "[" * 99000 + "\n",
    "F5 < 99,000 times": lambda: "<" * 99000 + "\n",
    "F5 *a 49,500 times": lambda: "*a" * 49500 + "\n",
}


@pytest.mark.parametrize("name", sorted(MD4C_CASES))
def test_sad_qt_s_own_parser_holds_no_turn(name):
    """Before (Qt's own parser - axross's own viewer without markdown-it-py): 4.2 s, 4.1 s, 1.2 s, 1.4 s,
    1.1 s, 1.5 s; 11 s; 4.1 s, 1.05 s, 0.9 s, 7 s, 0.14 s."""
    text = MD4C_CASES[name]()
    within_turn(lambda: _longest_turn(text, False), text, name)


def test_sad_qt_s_own_parser_cuts_after_a_block_that_ends_without_an_empty_line():
    from ui import markdown_view as MV

    rows = ["H", "=", "# A", "text", "```", "code", "```", "more", "[s]: v", "", "[r]: u", "after", "> q", "lazy",
            "x", "==="]  # ("[s]: v" goes on with the paragraph; "x" "===" with the quote, lazily)
    ended = MV.block_ends(rows)
    assert [rows[k] for k in range(len(rows)) if ended[k]] == ["=", "# A", "```", "[r]: u"]
    parts = MV.markdown_parts("H\n=\n" * 5000)
    assert len(parts) > 20 and all(part.startswith("H\n=") for part in parts)
    assert sum(part.count("H\n=") for part in parts) == 5000
    # (a paragraph right under a heading cut in pieces, every word kept)
    text = MV.paragraph_pieces("# Title\n" + "word " * 20000 + "\n")
    assert text.count(MV.JOINED) > 3 and text.replace(MV.JOINED, " ").split().count("word") == 20000


def test_sad_qt_s_own_parser_shows_setext_headings_cut_in_parts_as_headings():
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render("".join(f"Heading {n}\n===\n" for n in range(3000)))
    assert until(lambda: view._readable, TB.READY_SECONDS)
    view.load_rest_now()
    until(lambda: not view.more() and not view._scheduled, 60)
    document = view.browser.document()
    levels, block = [], document.begin()
    while block.isValid():
        if block.text().startswith("Heading "):
            levels.append(block.blockFormat().headingLevel())
        block = block.next()
    assert len(levels) == 3000 and set(levels) == {1}, (len(levels), set(levels))
    view.close()


# -- F5: the passes before Qt's own parser ----------------------------------------------------------------

def test_sad_the_passes_before_qt_s_own_parser_are_linear():
    """"![" 49,500 times took the passes 132 s ("![" each looked for its "]" 2,000 characters on, then a
    pattern ran to the line's end at each one: 90 s), 100,000 addresses on a line 129 s (its line again for
    each)."""
    from ui import markdown_view as MV

    for text in ("![" * 49500 + "\n", "https://e.com/x " * 100000 + "\n", "[" * 99000 + "\n", "[a](" * 25000 + "\n"):
        began = time.monotonic()
        MV._md4c_page(text)
        took = time.monotonic() - began
        TB.budget(took < 8, (text[:10], took))


def test_happy_the_linear_passes_do_what_they_did():
    from ui import markdown_view as MV

    kept = []

    def keep(span):
        kept.append(span)
        return f"<{len(kept)}>"

    assert MV._bare_links("see https://e.com/a, [x https://e.com/b] <a href=https://e.com/c> https://e.com/d",
                          keep) == "see <1>, [x https://e.com/b] <a href=https://e.com/c> <2>"
    assert kept == ["<https://e.com/a>", "<https://e.com/d>"]
    assert MV._plain_alts("![a *b*](x.png) ![c [d] e](y.png) ![open") == "![a b](x.png) ![c d e](y.png) ![open"


# -- F6: Qt's own parser on the spec's examples ------------------------------------------------------------

@pytest.mark.parametrize("text, wanted", [
    ("[foo<http://example.com/?search=](uri)>\n", "[foohttp://example.com/?search=](uri)"),  # (534)
    ("next \\<br/> not a tag\n", "next <br/> not a tag"),  # (310)
    ("Foo\n<a href=\"bar\">\nbaz\n", "Foo baz"),  # (156)
    ("foo <a href=\"&ouml;\">\n", "foo"),  # (649)
    ("<a href=\"hi'> <a href=hi'>\n", "<a href=\"hi'> <a href=hi'>"),  # (639)
    ("&#35; &#1234; &#992; &#0;\n", "# \u04d2 \u03e0 \ufffd"),  # (322)
    ("&Dcaron; &HilbertSpace; &ngE; &amp; \\&ouml;\n", "\u010e \u210b \u2267\u0338 & &ouml;"),  # (321)
])
def test_sad_qt_s_own_parser_shows_the_spec_s_examples(text, wanted):
    """Private-use marks in the page and its link, an escaped tag a line break, a stray "[" of a link never
    closed, U+0000, entities Qt's parser knows not."""
    shown = " ".join(_shown(text).split())
    assert shown == wanted, (text, shown)
    assert not any("\ue000" <= ch <= "\uf8ff" for ch in shown)


@pytest.mark.parametrize("text", [
    "![foo *bar*]\n\n[foo *bar*]: train.jpg \"train & tracks\"\n",  # (581)
    "![*foo* bar]\n\n[*foo* bar]: /url \"title\"\n",  # (597)
    "![foo *bar*][]\n\n[foo *bar*]: train.jpg \"train & tracks\"\n",  # (584)
    "![*foo* bar][]\n\n[*foo* bar]: /url \"title\"\n",  # (593)
])
def test_sad_qt_s_own_parser_shows_an_image_by_reference_once(text):
    """An image by reference with emphasis in its alt: shown twice ("![foo *bar*]"), or not at all, as
    written ("![foo *bar*][]")."""
    shown = _shown(text).strip()
    assert shown == "\ufffc", (text, shown)


# -- F7: no notice over deep code -----------------------------------------------------------------------------

def test_sad_deep_code_says_nothing_of_lists_shown_flatter():
    """A ```json block nested 12 levels at 4 spaces (or a code line of 200,000 tabs): "Laid out flatter:
    lists nested more than 16 deep" over a page with no list, nothing flattened."""
    from ui import markdown_view as MV

    rows = ["```json"] + ["    " * n + '{"a":' for n in range(12)] + ["    " * 12 + "1"] \
        + ["    " * n + "}" for n in reversed(range(12))] + ["```"]
    for text in ("# Deep\n\n" + "\n".join(rows) + "\n", "```\n" + "\t" * 200000 + "x\n```\n"):
        shown, why = MV.renderable(text)
        assert why == "" and shown == MV._SPACE_RUN.sub(lambda m: m.group(0)[:MV.SPACE_RUN], text), why
    deep = "".join("  " * n + "- x\n" for n in range(40))
    assert "16 deep" in MV.renderable(deep)[1]  # (a list that deep: said, as before)


# -- F9: the first parts of big tables ----------------------------------------------------------------------

TABLES = {
    "20,000 rows": lambda: "| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 20000,
    "5,000 rows with notes": lambda: "| a |\n|---|\n" + "".join(f"| x[^{i}] |\n" for i in range(5000))
                                     + "\n" + "".join(f"[^{i}]: n\n" for i in range(5000)),
}


@PARSERS
@pytest.mark.parametrize("name", sorted(TABLES))
def test_sad_a_big_table_s_parts_hold_no_turn(name, full):
    """markdown-it's page: the first part 0.15 s (setHtml, then _settle), the footnoted 0.21 s; a later
    part's cells made unbreakable laid its whole table out again."""
    text = TABLES[name]()
    within_turn(lambda: _longest_turn(text, full), text, name)


@pytest.mark.parametrize("name", sorted(TABLES))
def test_sad_a_pdf_of_a_big_table_holds_no_turn(name, tmp_path):
    """0.20 s and 0.30 s a turn: a part of 300 rows laid out four times for its pages, then 16 pages drawn."""
    text = TABLES[name]()
    within_turn(lambda: _pdf_turn(tmp_path, text), text, name)


# -- the small things ----------------------------------------------------------------------------------------

def test_sad_find_says_more_may_come_with_one_plus(tmp_path, monkeypatch):
    """"1 of 2495++": counted for its time (here: past FIND_COUNT) and part of the page still to come, a "+"
    for each."""
    from ui import markdown_viewer as V

    monkeypatch.setattr(V, "FIND_COUNT", 50)
    text = "# Top\n\n" + "".join(f"## Sec {i}\n\nab ab ab ab ab x{i}\n\n" for i in range(4000))
    viewer = _viewer(tmp_path, text)
    assert viewer.view.more()
    viewer.find_field.setText("ab")
    pump(0.5)
    said = viewer.find_count.text()
    assert said.endswith("+") and not said.endswith("++"), said
    viewer.close()


@pytest.mark.parametrize("info, label", [("foo\\+bar", "foo+bar"), ("f&ouml;&ouml;", "f\u00f6\u00f6"),
                                         ("\\&ouml;", "&ouml;")])
def test_sad_a_code_block_s_label_is_its_info_unescaped(info, label):
    """CommonMark unescapes a fence's info string: "foo\\+bar" was shown as written (example 320, 330)."""
    shown = _shown(f"``` {info}\nfoo\n```\n", full=True).split()
    assert shown[0] == label, shown


class _WithFallbacks:
    """QFontMetrics as Qt's is: inFontUcs4 answers for the font and the fonts Qt falls back on - every
    font draws every emoji where the fallback reaches the colour emoji font."""

    def __init__(self, _font):
        pass

    def inFontUcs4(self, _sign):
        return True


class _Raw:
    """QRawFont: the font alone - only the colour emoji font has the emoji."""

    def __init__(self, family):
        self.family = family

    @classmethod
    def fromFont(cls, font):
        return cls(font.family())

    def isValid(self):
        return True

    def supportsCharacter(self, _sign):
        return self.family == "Noto Color Emoji"


def test_sad_the_colour_emoji_font_is_the_page_s_emoji_family_where_the_fallback_reaches_it(monkeypatch):
    """The default font, asked first, drew them all through Qt's fallback: the page's emoji family was
    "DejaVu Sans" with Noto Color Emoji installed (the tests' metrics drew only what a font had itself)."""
    from PyQt6 import QtGui

    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families",
                        staticmethod(lambda *a: ["DejaVu Sans", "Noto Color Emoji", "Zed Mono"]))
    monkeypatch.setattr(QtGui, "QFontMetrics", _WithFallbacks)
    monkeypatch.setattr(QtGui, "QRawFont", _Raw)
    MV.emoji_fonts()
    assert MV._EMOJI_DRAWN == [None]
    assert MV._EMOJI_FAMILY == ["Noto Color Emoji"]


def test_happy_an_installed_colour_emoji_font_is_the_page_s_emoji_family(monkeypatch):
    """With the machine's own fonts: an installed "... Emoji" font that has the emoji itself is the family
    (on a machine without one: none to find)."""
    from PyQt6.QtGui import QFont, QFontDatabase, QRawFont

    from core import markdown_doc
    from ui import markdown_view as MV

    emoji = [family for family in QFontDatabase.families() if "emoji" in family.lower()
             and QRawFont.fromFont(QFont(family)).supportsCharacter(0x1F600)]
    if not emoji:
        pytest.skip("no colour emoji font installed")
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    MV.emoji_fonts()
    assert MV._EMOJI_FAMILY[0] in emoji, (MV._EMOJI_FAMILY, emoji, len(markdown_doc.EMOJI))
