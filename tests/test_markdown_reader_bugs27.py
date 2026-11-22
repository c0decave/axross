"""The twenty-seventh round of the Markdown reader (the twenty-seventh review, axross-markdown 0.17.2 at 7/10):
Find selecting the wrong characters after an emoji (N1), a heading losing its size after its first inline
span in Qt's own parser (M2), "_em_" and "__strong__" underlined (M1), a link title in single quotes or
parentheses breaking the link (M3), Find backward never leaving a match at the page's first character (N5),
Export HTML closing a big <details> early (N3), the marks of Find not themed (Th1).

Each test here failed before.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests.test_markdown_reader_bugs22 import PARSERS  # noqa: E402
from tests.test_markdown_reader_bugs24 import _viewer  # noqa: E402

APP = QApplication.instance() or QApplication([])


# -- N1: Find after a character beyond the BMP ----------------------------------------------------------------

WIDE_PAGES = (
    "😀😀😀 alpha beta gamma\n\nSecond 🎉 paragraph with gamma here.\n",
    "𝐀𝐁𝐂 bold math then gamma\n",
    "𠀀𠀁 text gamma\n",
    "🎉" * 200 + " gamma\n\nline gamma\n",
    "```py\n# 😀 gamma\nx = 'gamma'\n```\n",
    "é́ combining then 👨‍👩‍👧 family then gamma and 🇩🇪 gamma\n",
    "| 😀 | gamma |\n|---|---|\n| 🎉🎉 x | gamma 𝐀 |\n\n- 🚀 item gamma\n",
)


@PARSERS
@pytest.mark.parametrize("text", WIDE_PAGES)
def test_sad_find_after_an_emoji_selects_and_marks_what_it_found(tmp_path, full, text):
    """Python's indices of the page's text (code points) were used as the document's positions (UTF-16
    units): each emoji before a match moved the selection and every mark one place - half a surrogate pair
    after 200 of them. Typed, Enter, Shift+Enter: "gamma" selected, every mark on a "gamma"."""
    viewer = _viewer(tmp_path, text, full)
    browser = viewer.view.browser
    viewer.find_field.setText("gamma")
    pump(0.2)
    seen = []
    for _press in range(4):
        assert browser.textCursor().selectedText().lower() == "gamma", (text, seen)
        seen.append(browser.textCursor().selectionStart())
        viewer.find_next()
        pump(0.05)
    viewer.find_next(backward=True)
    pump(0.05)
    assert browser.textCursor().selectedText().lower() == "gamma"
    marks = [mark.cursor.selectedText().lower() for mark in viewer._marks]
    assert marks and set(marks) == {"gamma"}, marks
    viewer.close()


def test_sad_the_page_s_text_and_qt_s_find_agree_beyond_the_bmp():
    """_find_laid and laid_matches against Qt's find, forward and backward, with emoji, a math letter, a CJK
    Extension-B character and combining marks before (and in) the needle - and after the page was laid out
    in parts (the text read again from where it changed)."""
    from PyQt6.QtGui import QTextCursor, QTextDocument

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(900, 700)
    view.show()
    view.render(("# 🚀 Project 😀\n\n𝐀𝐁 ab and 🎉ab🎉 and 𠀀b\n\né ab 👨‍👩‍👧 x\n\n"
                 "| 😀 a | b 🎉 |\n|---|---|\n| x ab | 𝐀b |\n\n") * 30)
    assert until(lambda: view._readable and not view._scheduled, 60)
    view.load_rest_now()
    assert until(lambda: not view.more() and not view._scheduled, 120)
    document = view.browser.document()
    for needle in ("ab", "b", "x", "🎉ab", "ab🎉", "𝐀b", "é", "😀 a", "nope"):
        for backward in (False, True):
            flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start)
            for _ in range(200):
                qt, ours = document.find(needle, cursor, flags), view._find_laid(needle, cursor, flags)
                assert (qt.isNull(), qt.selectionStart(), qt.selectionEnd()) == \
                    (ours.isNull(), ours.selectionStart(), ours.selectionEnd()), (needle, backward)
                if qt.isNull():
                    break
                cursor = qt
        places = view.laid_matches(needle)
        if places is None:
            continue
        found, cursor = [], document.find(needle, 0)
        while not cursor.isNull():
            found.append((cursor.selectionStart(), cursor.selectionEnd()))
            cursor = document.find(needle, cursor)
        assert list(places) == found, needle
    view.close()


# -- N5: Find backward from a match at the page's first character ---------------------------------------------

@PARSERS
def test_sad_find_backward_leaves_a_match_at_the_page_s_start(tmp_path, full):
    """With the match at position 0 selected, the bound of the backward search found it again: Shift+Enter
    four times gave [0, 0, 0, 0]. Now it goes round to the last match, then back."""
    viewer = _viewer(tmp_path, "gamma first\n\ngamma second\n\nthird gamma\n", full)
    browser = viewer.view.browser
    viewer.find_field.setText("gamma")
    pump(0.2)
    assert browser.textCursor().selectionStart() == 0
    seen = []
    for _press in range(4):
        viewer.find_next(backward=True)
        pump(0.05)
        assert browser.textCursor().selectedText().lower() == "gamma"
        seen.append(browser.textCursor().selectionStart())
    assert len(set(seen)) == 3 and seen[0] > seen[1] > seen[2] == 0, seen
    viewer.close()


@PARSERS
def test_sad_the_page_s_text_read_in_parts_keeps_its_emoji_in_place(full):
    """_laid_text reads a page laid out in parts again from the block that changed: it cut the text kept at
    that block's position (UTF-16) - one character later for each emoji before it. Read after each part:
    the text is Qt's toPlainText(), and its characters beyond the BMP where they are."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render("".join(f"## 🚀 H{i} 😀\n\n𝐀𝐁 ab and 🎉ab🎉 para {i}\n\n" for i in range(3000)))
    assert until(lambda: view._readable and not view._scheduled, 60)
    calls = []
    tail_read = MV._wide_in

    def counted(text, offset=0):
        calls.append(offset)
        return tail_read(text, offset)

    MV._wide_in = counted
    try:
        view.load_rest()
        for _turn in range(3000):
            if not view.more():
                break
            view._laid_text()
            pump(0.01)
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 120)
        plain, _folded = view._laid_text()
    finally:
        MV._wide_in = tail_read
    assert any(calls), "the text was never read from a part on"
    assert plain == view.browser.document().toPlainText()
    assert view._plain_kept[4] == MV._wide_in(plain)
    view.close()


# -- M2, M1, M3: Qt's own parser (axross's own viewer) against GFM's spec ------------------------------------

def _md4c_pieces(text: str) -> list:
    """[(the heading level of its block, its text, its char format, its block)] of every piece of *text*'s
    page in Qt's own parser."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and not view._scheduled, 60)
    pieces, block = [], view.browser.document().begin()
    while block.isValid():
        found = block.begin()
        while not found.atEnd():
            piece = found.fragment()
            pieces.append((block.blockFormat().headingLevel(), piece.text(), piece.charFormat(), block))
            found += 1
        block = block.next()
    _md4c_pieces.view = view  # (kept till the next: its blocks are read)
    return pieces


@pytest.mark.parametrize("text, heading", [
    ("# foo *bar* \\*baz\\*\n", "foo bar *baz*"),  # GFM 36
    ("Foo *bar*\n=========\n\nFoo *bar*\n---------\n", "Foo bar"),  # GFM 50
    ("Foo *bar\nbaz*\n====\n", "Foo bar\u2028baz"),  # GFM 51
    ("  Foo *bar\nbaz*\t\n====\n", "Foo bar\u2028baz"),  # GFM 52
    ("## Install `pkg` and [the *docs*](https://ok.example/) now\n\nbody\n", "Install pkg and the docs now"),
    ("### a **b** ~~c~~ `d`\n", "a b c d"),
])
def test_sad_a_heading_keeps_its_size_and_weight_after_an_inline_span(text, heading):
    """Qt's Markdown reader puts a heading's size and weight on its first piece only: "# foo *bar* baz" was
    "foo " 22.5 pt bold, "bar" and " baz" 11.25 pt. Every piece of a heading as its first - and laid out in
    one size, bold (its glyphs)."""
    from PyQt6.QtGui import QTextFormat

    pieces = [piece for piece in _md4c_pieces(text) if piece[0]]
    assert pieces
    assert pieces[0][3].text().startswith(heading.split("\u2028")[0])
    size = QTextFormat.Property.FontSizeAdjustment
    for level, shown, fmt, block in pieces:
        first = block.begin().fragment().charFormat()
        assert fmt.intProperty(size) == first.intProperty(size) > 0, (shown, level)
        assert fmt.fontWeight() >= 700, shown
        assert not fmt.hasProperty(QTextFormat.Property.FontPointSize), shown
    for block in {id(piece[3]): piece[3] for piece in pieces}.values():
        layout = block.layout()
        runs = [run for line in range(layout.lineCount()) for run in layout.lineAt(line).glyphRuns()]
        assert runs
        sizes = {round(run.rawFont().pixelSize()) for run in runs}
        weights = {run.rawFont().weight() >= 600 for run in runs}
        assert len(sizes) == 1 and weights == {True}, (block.text(), sizes, weights)
    _md4c_pieces.view.close()


@pytest.mark.parametrize("text, kind", [
    ("_foo bar_\n", "em"),  # GFM: "_" emphasis (Example 360)
    ("__foo bar__\n", "strong"),  # GFM: "__" strong emphasis (Example 384)
    ("*foo bar*\n", "em"),
    ("**foo bar**\n", "strong"),
    ("para _em_ and __strong__ and *star*\n", None),
    ("*(*foo*)*\n", "em"),
    ("__foo, __bar__, baz__\n", "strong"),
])
def test_sad_underscore_emphasis_is_emphasis_not_underline(text, kind):
    """The dialect Qt's own parser was given holds md4c's MD_FLAG_UNDERLINE: "_em_" was underlined, not
    italic, "__strong__" underlined and not bold. As GFM: italic and bold, nothing underlined."""
    pieces = _md4c_pieces(text)
    for _level, shown, fmt, _block in pieces:
        assert not fmt.fontUnderline(), shown
    marked = {shown.strip(): fmt for _level, shown, fmt, _block in pieces if fmt.fontItalic() or fmt.fontWeight() > 400}
    if kind is None:
        assert marked["em"].fontItalic() and marked["star"].fontItalic()
        assert marked["strong"].fontWeight() >= 700
    elif kind == "em":
        assert any(fmt.fontItalic() for fmt in marked.values()), pieces
    else:
        assert any(fmt.fontWeight() >= 700 for fmt in marked.values()), pieces
    _md4c_pieces.view.close()


@pytest.mark.parametrize("text, href", [
    ('[link](/url "title")\n', "/url"),  # GFM: the three kinds of a link's title
    ("[link](/url 'title')\n", "/url"),
    ("[link](/url (title))\n", "/url"),
    ('[link](/url "title \\"&quot;")\n', "/url"),  # GFM: an escaped quote in its title
    ("[t](https://ok.example/ 'x') [u](https://ok.example/ (y))\n", "https://ok.example/"),
    ("[link](</my uri> 'title')\n", "/my%20uri"),
])
def test_sad_a_link_s_title_in_single_quotes_or_parentheses_keeps_its_link(text, href):
    """A link's title in '…' or (…) was no title to the pass that keeps an address as written: the address
    was made a link of its own - the href "[https://ok.example/](https://ok.example/)", a relative file name
    to a click. As GFM: the address, the title no part of it."""
    pieces = _md4c_pieces(text)
    hrefs = [fmt.anchorHref() for _level, _shown, fmt, _block in pieces if fmt.isAnchor()]
    assert hrefs and all(found == href for found in hrefs), hrefs
    shown = "".join(piece[1] for piece in pieces)
    assert "title" not in shown and "(y)" not in shown and "'x'" not in shown, shown
    _md4c_pieces.view.close()


# -- N3: Export HTML of a <details> bigger than a piece -------------------------------------------------------

def _fold_text(sections: int = 400, closed: bool = True) -> str:
    return ("# Doc\n\n<details>\n<summary>Fold</summary>\n\n"
            + "".join(f"## T{i}\n\n" + ("word " * 50 + "\n\n") * 5 + f"t{i}.\n\n" for i in range(sections))
            + ("</details>\n\n" if closed else "") + "After the fold.\n")


@pytest.mark.parametrize("closed", [True, False])
def test_sad_export_html_keeps_a_big_details_open_to_its_end(closed):
    """The export parses a long text in pieces (parsed_pieces): each piece closed what its raw HTML left open,
    and the <details>' own end in a later piece was dropped - "</details>" at character 106,868 of 531,952,
    "t399." outside the fold. As one parse: the fold holds every section, its end after the last one."""
    import re

    from core import markdown_doc
    from ui import markdown_html as H
    from ui import markdown_view as MV

    text = _fold_text(closed=closed)
    pieces = MV.parsed_pieces(text)
    page = "".join(H.export_html_pieces(pieces, "x"))
    whole = H.export_html_pieces([markdown_doc.parse(text)], "x")
    whole = "".join(whole)
    tags = re.compile(r"</?(?:details|summary|div)\b[^>]*>")
    assert len(H.export_html_pieces(MV.parsed_pieces(text), "x")) > 3  # (in pieces)
    assert tags.findall(page) == tags.findall(whole)
    assert page.count("<details") == page.count("</details>") == 1
    end = page.find("</details>")
    assert page.find("t399.") < end
    if closed:
        assert end < page.find("After the fold.")


# -- Th1: Find's marks in the page's theme --------------------------------------------------------------------

@pytest.mark.parametrize("theme_id", ["solar-dark", "slate", "solar-light", "retro", "dark", "high-contrast-dark",
                                      "light", "sepia"])
def test_sad_find_s_marks_follow_the_theme_and_keep_its_contrast(tmp_path, theme_id):
    """Find's marks were one yellow on every light theme and one brown on every dark one, under the text's own
    colours: 2.8:1 in Solar Dark, Retro's code 1.84:1. Now the theme's highlight ground under its text colour -
    AA (AAA in a High Contrast theme) for every marked character, links and code too - and a switch of the
    theme marks the matches again in the new one."""
    from tests.test_markdown_themes import _switched
    from core import markdown_themes as MT
    from ui import markdown_theme_ui as TU

    hub = TU.hub()
    hub._applied = float("-inf")
    hub.choose(theme_id, keep=False)
    try:
        viewer = _viewer(tmp_path, "gamma [gamma link](https://ok.example/) `gamma code`\n\n> gamma quote\n", True)
        assert _switched(viewer.view, theme_id)
        viewer.find_field.setText("gamma")
        pump(0.2)
        theme = MT.THEMES[theme_id]
        least = 7.0 if theme.aaa else 4.5
        assert len(viewer._marks) == 4
        for mark in viewer._marks:
            ground = mark.format.background().color().name()
            text = mark.format.foreground().color().name()
            assert (ground, text) == (theme.page["highlight_bg"], theme.page["text"])
            assert MT.contrast(text, ground) >= least, (theme_id, MT.contrast(text, ground))
        other = "light" if theme.dark else "dark"
        hub._applied = float("-inf")
        hub.choose(other, keep=False)
        assert _switched(viewer.view, other)
        assert until(lambda: viewer._marks and viewer._marks[0].format.background().color().name()
                     == MT.THEMES[other].page["highlight_bg"], 120)
        viewer.close()
    finally:
        hub._applied = float("-inf")
        hub.choose("auto", keep=False)


# -- Th2: a theme switch on a page read to its end ------------------------------------------------------------

def _switch_after_reading_it_all(tmp_path, full: bool, theme_id: str):
    from tests.test_markdown_reader_bugs25 import _sections
    from tests.test_markdown_themes import _switched
    from ui import markdown_theme_ui as TU

    viewer = _viewer(tmp_path, _sections(10000), full)
    view = viewer.view
    view.load_rest_now()
    assert until(lambda: not view.more() and not view._scheduled, 600)
    pump(0.3)
    old = view.browser.document()
    hub = TU.hub()
    hub._applied = float("-inf")
    return viewer, old, lambda: (hub.choose(theme_id, keep=False), _switched(view, theme_id, 240))[1]


@PARSERS
def test_sad_a_theme_switch_on_a_page_read_to_its_end_shows_it_in_a_new_document(tmp_path, full):
    """setHtml (with the theme's style sheet) over all of a page laid out to its end: one turn of 0.16 to
    0.175 s. The new page now comes in a fresh document, the old one let go of a piece a turn - the new
    theme's colours, all of the text, Qt's own parser's code colouring on the new document."""
    from PyQt6 import sip

    from core import markdown_themes as MT
    from ui import markdown_theme_ui as TU

    try:
        viewer, old, switch = _switch_after_reading_it_all(tmp_path, full, "slate")
        view = viewer.view
        assert switch()
        assert view.browser.document() is not old
        assert until(lambda: sip.isdeleted(old) and not view._old_documents, 120)
        from tests.test_markdown_themes import _ground

        assert _ground(view) == MT.THEMES["slate"].page["page_bg"]
        assert view.highlighter.document() is view.browser.document()
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 600)
        assert "H9999" in view.browser.document().toPlainText()
        viewer.close()
    finally:
        TU.hub()._applied = float("-inf")
        TU.hub().choose("auto", keep=False)


def test_sad_a_theme_switch_on_a_page_read_to_its_end_holds_no_turn(tmp_path):
    """(the timing part of the test above) the switch's longest turn within the budget of a page's turn."""
    from tests.test_markdown_reader_bugs20 import _Turns
    from tests.test_markdown_reader_bugs22 import within_turn
    from tests.test_markdown_reader_bugs25 import _sections
    from ui import markdown_theme_ui as TU

    def measure() -> float:
        viewer, _old, switch = _switch_after_reading_it_all(tmp_path, True, "slate" if not seen else "dark")
        seen.append(1)
        turns = _Turns()
        switch()
        pump(0.3)
        longest = turns.stop()
        viewer.close()
        return longest

    seen: list = []
    try:
        within_turn(measure, _sections(10000), "Th2 theme switch")
    finally:
        TU.hub()._applied = float("-inf")
        TU.hub().choose("auto", keep=False)


# -- R6: a link to a missing anchor on 100,000 headings -------------------------------------------------------

@PARSERS
def test_sad_a_missing_anchor_reads_no_heading_on_the_gui_thread(full):
    """A missing anchor on 100,000 headings: a slug of every heading of every part not laid out on the GUI
    thread - a turn of 0.19 s (markdown-it's page), 0.1 to 0.35 s (Qt's own parser's). They are read on a
    worker now and kept with the page: "No heading" said, a few slugs at most on the GUI thread; a heading
    far on still gone to."""
    import threading

    from ui import markdown_view as MV

    text = "[none](#nope)\n\n" + "".join(f"## h{i}\n\npara {i} word word word\n\n" for i in range(100000))
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1100, 800)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and not view._scheduled, 240)
    real, on_gui = MV.slug, []

    def counted(*args, **kwargs):
        if threading.current_thread() is threading.main_thread():
            on_gui.append(1)
        return real(*args, **kwargs)

    MV.slug = counted
    try:
        for _again in range(2):
            on_gui.clear()
            view.go_to_anchor("nope-nothere")
            assert until(lambda: "No heading" in view.status.text(), 120), view.status.text()
            assert len(on_gui) < 100, len(on_gui)
            view.status.setText("")
        assert view.go_to_anchor("h99990")
        assert until(lambda: "h99990" in view.anchors, 600)
    finally:
        MV.slug = real
    view.close()


def test_sad_a_missing_anchor_holds_no_turn():
    """(the timing part of the test above) the longest turn of a missing anchor, both parsers."""
    from tests.test_markdown_reader_bugs20 import _Turns
    from tests.test_markdown_reader_bugs22 import within_turn
    from ui import markdown_view as MV

    text = "[none](#nope)\n\n" + "".join(f"## h{i}\n\npara {i} word word word\n\n" for i in range(100000))
    for full in (True, False):
        def measure() -> float:
            view = MV.MarkdownView(None)
            view.full = view.full and full
            view.resize(1100, 800)
            view.show()
            view.render(text)
            assert until(lambda: view._readable and not view._scheduled, 240)
            pump(0.5)
            turns = _Turns()
            view.go_to_anchor("nope-nothere")
            assert until(lambda: "No heading" in view.status.text(), 120)
            pump(0.2)
            longest = turns.stop()
            view.close()
            return longest

        within_turn(measure, text, ("R6", full))


# -- N4: GFM's 626 - the link of "www.…&hl;" ------------------------------------------------------------------

def test_sad_a_www_link_before_a_character_reference_has_its_own_address():
    """GFM's 626, "www.google.com/search?q=commonmark&hl;": the text was right, the href
    "[http://www.google.com/search?q=commonmark](http://www.google.com/search?q=commonmark)" (its "<…>" an autolink
    to a later pass) - a relative file name to a click. Now the address itself."""
    pieces = _md4c_pieces("www.google.com/search?q=commonmark&hl;\n")
    hrefs = [fmt.anchorHref() for _level, _shown, fmt, _block in pieces if fmt.isAnchor()]
    assert hrefs == ["http://www.google.com/search?q=commonmark"], hrefs
    assert "".join(piece[1] for piece in pieces) == "www.google.com/search?q=commonmark&hl;"
    _md4c_pieces.view.close()


# -- R2, F1: no pass over all of an 8 MB block in one call ----------------------------------------------------

class _Measured:
    """A compiled pattern whose search, sub and finditer note how much of a string each call reads."""

    def __init__(self, pattern, seen: list):
        self.pattern, self.seen = pattern, seen

    def _span(self, string, pos=0, endpos=None):
        self.seen.append((len(string) if endpos is None else min(endpos, len(string))) - pos)

    def search(self, string, *args):
        self._span(string, *args)
        return self.pattern.search(string, *args)

    def sub(self, repl, string, count=0):
        self.seen.append(len(string))
        return self.pattern.sub(repl, string, count)

    def __getattr__(self, name):
        return getattr(self.pattern, name)


BIG_BLOCK = "<div>\n" + "* " * 4000000


def test_sad_qt_s_own_parser_reads_an_8_mb_block_a_piece_a_call():
    """Opening "<div>" + 8 MB of "* " in Qt's own parser held Python's lock 0.27 to 0.34 s on its worker: a
    search for picture signs, for nesting, the autolinks and the emphasis runs each one call over all of the
    line. Each call now reads a piece of at most a few times LINES_AT_ONCE - and the page is the same."""
    from core.markdown_doc import LINES_AT_ONCE
    from ui import markdown_html as H
    from ui import markdown_view as MV

    before = MV.renderable(BIG_BLOCK[:200000], MV.MD4C_TABLE_CELLS)[0]
    seen: dict = {}
    names = ("_NESTING_LINE", "_AUTOLINK", "_EMPHASIS_RUN")
    real = {name: getattr(MV, name) for name in names}
    real_signs = H._PICTURE_SIGNS
    try:
        for name in names:
            setattr(MV, name, _Measured(real[name], seen.setdefault(name, [])))
        MV._PICTURE_SIGNS = _Measured(real_signs, seen.setdefault("_PICTURE_SIGNS", []))
        shown = MV.renderable(BIG_BLOCK, MV.MD4C_TABLE_CELLS)[0]
        MV._md4c_page(shown, frozenset(), {})
        small = MV.renderable(BIG_BLOCK[:200000], MV.MD4C_TABLE_CELLS)[0]
    finally:
        for name in names:
            setattr(MV, name, real[name])
        MV._PICTURE_SIGNS = real_signs
    assert small == before
    for name, spans in seen.items():
        assert spans, name
        assert max(spans) <= 3 * LINES_AT_ONCE, (name, max(spans))


def test_sad_find_reads_an_8_mb_part_a_piece_a_call():
    """Find looked through a part not laid out yet on a worker - an HTML block of 8 MB: its tags out, its
    references read, lower case, the emphasis marks out, each one call over all of it (0.25 to 0.45 s of
    Python's lock, the window frozen). Each step now a piece - the text found the same."""
    import html as html_module
    import re

    from ui import markdown_view as MV

    page = {"kind": "html", "texts": ["", BIG_BLOCK]}
    seen: list = []
    real = MV._TAG_RUN
    MV._TAG_RUN = _Measured(real, seen)
    try:
        part = "<p>" + "* " * 2000000 + "&amp; <b>Word</b></p>\n"
        plain = MV._plain_text(page, part)
    finally:
        MV._TAG_RUN = real
    assert seen and max(seen) <= 3 * MV.PLAIN_STEP
    assert plain == html_module.unescape(re.sub(r"<[^<>]*>", "", part)).lower()
    assert "& word" in plain
    steps = list(MV._html_steps("* " * 300000, "\\"))
    assert max(map(len, steps)) <= 2 * MV.PLAIN_STEP and "".join(steps) == "* " * 300000
    unparsed = MV._plain_text(page, MV._Unparsed(1))
    assert unparsed.startswith(BIG_BLOCK.lower()) and len(unparsed) == 2 * len(BIG_BLOCK) - BIG_BLOCK.count("*") + 1


# -- L2: Find's count after a reload that brings its matches back ---------------------------------------------

@PARSERS
def test_sad_find_marks_again_when_a_reload_brings_its_matches_back_far_on(tmp_path, full):
    """A page read in the middle, the file rewritten with the word Find looks for back in it: "no match" and no
    marks stayed - the new page was marked when its first part was shown, the part at the place read laid out
    only after. Marked again once the place read is back."""
    text = "".join(f"para {n} has a word here\n\n" for n in range(3000))
    viewer = _viewer(tmp_path, text, full)
    view = viewer.view
    viewer.find_field.setText("word")
    pump(0.2)
    viewer.find_next()
    assert until(lambda: viewer._marks, 60)
    page = tmp_path / "page.md"
    page.write_text(text.replace("word", "thing"), encoding="utf-8")
    viewer.reload()
    assert until(lambda: viewer.find_count.text() == "no match" and view._readable and not view._scheduled, 120)
    view.load_rest_now()
    assert until(lambda: not view.more() and not view._scheduled, 240)
    bar = view.browser.verticalScrollBar()
    bar.setValue(bar.maximum() // 2)
    pump(0.3)
    page.write_text(text, encoding="utf-8")
    viewer.reload()
    assert until(lambda: viewer._marks and viewer.find_count.text() not in ("", "no match"), 120), \
        viewer.find_count.text()
    viewer.close()
