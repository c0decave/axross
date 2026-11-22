"""The twelfth round of the Markdown reader (the eleventh review): Select
All and Copy of a long page at once, a long text with a footnote parsed in
parts, raw HTML's attributes no links, look-alike hosts, the golden guard
that sees a line move, math of several environments in a line - in both of
Qt's paths. Each test failed before.
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

from PyQt6.QtCore import Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import close, gap_text, opened, pump, settled, until  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


# -- 1, 6. Select All, Copy: all of the page, at once -----------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("jump", [False, True])
def test_sad_select_all_then_copy_copies_all_of_a_long_page_at_once(full, jump, tmp_path):
    from PyQt6.QtTest import QTest

    dialog = opened(full, tmp_path, gap_text(400))  # (default part sizes: about 170 KB)
    try:
        view = dialog.view
        if jump:
            view.clicked(QUrl("#chapter-300"))
            settled(view)
        assert view.more(), "all of it laid out already"
        browser = view.browser
        APP.clipboard().setText("OLD")
        browser.setFocus()
        began = time.monotonic()
        QTest.keyClick(browser, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        QTest.keyClick(browser, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)  # (at once: nothing selected yet)
        assert TB.until_within(until, lambda: APP.clipboard().text() != "OLD", 20), view.status.text()
        took = time.monotonic() - began
        copied = APP.clipboard().text()
        missing = [n for n in range(1, 401) if f"CHMARK{n:03d}" not in copied]
        assert not missing, missing[:10]
        assert copied.index("CHMARK001") < copied.index("CHMARK200") < copied.index("CHMARK400")
        assert "Last zebraquux two." in copied
        assert not re.search("[\ue000-\uf8ff]", copied), "a mark of the page's passes copied"
        TB.budget(took < 3.0, took)  # (laid out first: 9 s, 58 s for Qt's own parser - or nothing at all)
    finally:
        close(dialog)


# -- 2. a footnote: a long text still parsed in parts --------------------------------------------------

def noted_text() -> str:
    """A long text: notes referred to near its top, middle and end, defined
    in its middle (one of two lines) and at its end."""
    body = [f"## Section {n}\n\nParagraph {n} with some words to read about section {n}.\n\n" for n in range(3000)]
    body[2] += "A first note[^first] and an inline one^[inline later? no].\n\n"
    body[1500] += "[^first]: The first note,\n    on two lines.\n\nThe middle refers to a second[^second].\n\n"
    body[2990] += "The end refers to the first again[^first] and a third[^3].\n\n"
    return "".join(body).replace("^[inline later? no]", "") + "[^second]: The second note.\n\n[^3]: The third.\n"


@pytest.fixture
def small_pieces(monkeypatch):
    from core import markdown_term as T

    monkeypatch.setattr(T, "STREAM_CHARS", 20_000)
    monkeypatch.setattr(T, "STREAM_LINES", 300)


def test_sad_a_long_text_with_a_footnote_is_still_parsed_in_parts(small_pieces):
    from core import markdown_term as T

    text = noted_text()
    parts = T.text_parts(text)
    assert len(parts) > 3, len(parts)  # (one part: 5 s before markdown-it showed anything of gap.md)
    # (the notes' definitions all in the last part - where they are too, no block there, since bugs13)
    assert all(f"[^{label}]:" in parts[-1] for label in ("first", "second", "3"))


def test_sad_a_long_text_with_footnotes_in_parts_numbers_them_across_the_text(small_pieces):
    from core import markdown_term as T
    from ui.markdown_html import to_html_parts
    from core import markdown_doc as MD

    text = noted_text()
    parts, notes = T.text_parts(text), T.notes_of(text)
    assert [label for label, _count in notes] == ["first", "second", "3"]  # (how often each: bugs13)
    pages = []
    for number, part in enumerate(parts):
        doc = MD.parse(part, notes=(notes, number == len(parts) - 1))
        pages.append("".join(to_html_parts(doc, False, 200)))
    whole = "".join(pages)
    refs = re.findall(r'<a href="#fn(\d+)">\[(\d+)\]</a>', whole)
    assert [shown for _target, shown in refs] == ["1", "2", "1", "3"], refs
    assert all(target == shown for target, shown in refs)
    assert whole.count('class="footnotes"') == 1 and pages[-1].count('class="footnotes"') == 1
    tail = pages[-1][pages[-1].index('class="footnotes"'):]
    assert tail.index("The first note") < tail.index("The second note") < tail.index("The third")
    assert "on two lines" in tail


def test_sad_the_terminal_shows_a_long_text_with_footnotes_at_once(small_pieces):
    from core import markdown_term as T

    text = noted_text()
    began = time.monotonic()
    first = next(T.render_parts(text, T.Options(width=80)))
    TB.budget(time.monotonic() - began < 1.0, 'time.monotonic() - began < 1.0')  # (all of it first: 5.9 s for gap.md)
    assert "Section 0" in first and "Section 2999" not in first
    whole = re.sub(r"\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\", "", T.render(text, T.Options(width=80)))
    assert "The first note" in whole and "The third" in whole and "[^first]" not in whole


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_long_page_with_footnotes_shows_at_once_and_its_notes_work(full, small_pieces, tmp_path):
    dialog = opened(full, tmp_path, noted_text())
    try:
        view = dialog.view
        if full:
            assert view._page.get("loading") or len(view._page.get("texts") or []) > 1  # (in pieces)
        view.load_rest_now()
        text = view.browser.toPlainText()
        assert re.findall(r"\[(\d)\]", text)[:4] == ["1", "2", "1", "3"], re.findall(r"\[(\d)\]", text)[:6]
        assert text.index("The first note") < text.index("The second note") < text.index("The third")
        top = view.browser.document().find("A first note")
        links = []
        pieces = top.block().begin()
        while not pieces.atEnd():
            if pieces.fragment().charFormat().anchorHref():
                links.append(pieces.fragment().charFormat().anchorHref())
            pieces += 1
        assert links
        view.clicked(QUrl(links[0]))
        pump(0.3)
        note = view.browser.document().find("The first note").block()
        assert 0 <= view.browser.cursorRect(QTextCursor(note)).top() < view.browser.viewport().height()
    finally:
        close(dialog)


def test_sad_an_anchor_in_a_piece_not_parsed_yet_is_gone_to(small_pieces, tmp_path):
    """(markdown-it's page in pieces - now also a text with footnotes) a
    heading of a piece not parsed yet: that piece parsed first, then there."""
    dialog = opened(True, tmp_path, noted_text())
    try:
        view = dialog.view
        view.clicked(QUrl("#section-2900"))
        assert TB.until_within(until, lambda: (lambda block: block.isValid() and block.text() == "Section 2900"
                              and 0 <= view.browser.cursorRect(QTextCursor(block)).top() < 60)(
            view.browser.document().find("Section 2900").block()), 20), view.status.text()
    finally:
        close(dialog)


# -- 3, 4. display math: a row of items on one axis -------------------------------------------------------

TWO = r"\begin{pmatrix} 1 & 0 \\ 0 & 1 \end{pmatrix} \begin{pmatrix} x \\ y \end{pmatrix} = \begin{pmatrix} x \\ y \end{pmatrix}"
SYSTEM = r"\begin{cases} x + y = 1 \\ x - y = 0 \end{cases} \quad\Rightarrow\quad \begin{bmatrix} 1 & 1 \\ 1 & -1 \end{bmatrix}"


def test_sad_the_terminal_sets_several_matrices_of_a_line_side_by_side():
    from core import markdown_term as T

    out = re.sub(r"\x1b\[[0-9;]*m", "", T.render(f"$$\n{TWO}\n$$\n", T.Options(width=80)))
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2, out  # (a staircase: 4 lines, each matrix a line lower)
    assert "⎛1  0⎞ ⎛x⎞ = ⎛x⎞" in lines[0].replace("  =", " =") or ("⎛1" in lines[0] and "⎛x⎞" in lines[0]), out
    out = re.sub(r"\x1b\[[0-9;]*m", "", T.render(f"$$\n{SYSTEM}\n$$\n", T.Options(width=80)))
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2 and "⇒" in out, out
    assert lines[0].index("⎡") == lines[1].index("⎣"), out


def display_cells(view):
    """Every table cell's text of the page's formulas (nested ones too), in order."""
    from PyQt6.QtGui import QTextTable

    found = []
    document = view.browser.document()

    def walk(frame):
        for child in frame.childFrames():
            if isinstance(child, QTextTable):
                found.append(child)
            walk(child)

    walk(document.rootFrame())
    return found


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("tex", [TWO, SYSTEM])
def test_sad_several_environments_of_a_display_are_one_row(full, tex):
    from tests.test_markdown_reader_bugs11 import math_page

    view, _table = math_page(tex, full)
    document = view.browser.document()
    text = document.toPlainText()
    tops = []
    for needle in ("⇒",) if "⇒" in text else ("=",):  # (the line's own, not a case's)
        hit = document.find(needle)
        if not hit.isNull():
            tops.append(view.browser.cursorRect(hit).center().y())
    # (brackets in pieces, a piece a row, since the thirteenth review - bugs14: their middle on the axis)
    brackets = [(view.browser.cursorRect(document.find(top)).center().y()
                 + view.browser.cursorRect(document.find(foot)).center().y()) / 2
                for top, foot in (("⎛", "⎝"), ("⎧", "⎩")) if not document.find(top).isNull()]
    assert tops and brackets
    assert all(abs(top - bracket) <= 12 for top in tops for bracket in brackets), (tops, brackets)  # (one axis)
    fonts = {document.find(needle).charFormat().fontFixedPitch() for needle in ("=",)}
    assert fonts == {False}  # (not monospace)


def _y(view, needle, nth=0):
    document = view.browser.document()
    hit = document.find(needle)
    for _round in range(nth):
        hit = document.find(needle, hit)
    assert not hit.isNull(), needle
    return view.browser.cursorRect(hit)


def _size_step(view, needle) -> int:
    from PyQt6.QtGui import QTextFormat

    hit = view.browser.document().find(needle)
    assert not hit.isNull(), needle
    return int(hit.charFormat().property(QTextFormat.Property.FontSizeAdjustment) or 0)


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("tex", [r"\sum_{k=1}^{n} k = \frac{n(n+1)}{2}", r"\lim_{x \to 0} \frac{\sin x}{x} = 1"])
def test_typo_beside_a_sum_or_a_limit_all_sits_on_the_fraction_bar(full, tex):
    from tests.test_markdown_reader_bugs11 import math_page

    view, _table = math_page(tex, full)
    upper, lower = ("n(n+1)", "2") if "sum" in tex else ("sin", "x")
    bar = (_y(view, upper).bottom() + _y(view, lower, 1 if lower == "x" else 0).top()) / 2
    if lower == "x":  # (the denominator: the x after "sin x")
        bar = (_y(view, upper).bottom() + _y(view, "x", 2).top()) / 2
    equals = _y(view, "=", 1 if "sum" in tex else 0).center().y()  # (not the limit's, "k=1")
    assert abs(equals - bar) <= 7, (equals, bar)  # (on the denominator's line: 10-15 px below)


@pytest.mark.parametrize("full", [True, False])
def test_typo_left_and_right_stretch_sum_and_product_alike_tag_at_the_right(full):
    from tests.test_markdown_reader_bugs11 import math_page

    view, _table = math_page(r"\left( \frac{a}{b} \right)^2 = \prod_{i} x_i \le \sum_{i} x_i \tag{1}", full)
    assert _size_step(view, "(") >= 3  # (as tall as the fraction it holds)
    assert _size_step(view, "∏") == _size_step(view, "∑") > 0
    text = view.browser.toPlainText()
    assert "tag" not in text and "(1)" in text
    assert _y(view, "(1)").left() > view.browser.viewport().width() * 0.7  # (at the right)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_binomial_is_stacked_in_parentheses(full):
    from tests.test_markdown_reader_bugs11 import math_page

    view, _table = math_page(r"\binom{n}{k} = 1", full)
    text = view.browser.toPlainText()
    assert "C(" not in text
    assert _y(view, "n").bottom() <= _y(view, "k").top() + 2 and abs(_y(view, "n").left() - _y(view, "k").left()) < 6
    assert _size_step(view, "(") >= 3


@pytest.mark.parametrize("full", [True, False])
def test_typo_no_letter_a_pages_font_lacks(full):
    from tests.test_markdown_reader_bugs11 import math_page

    from PyQt6.QtGui import QFont, QFontDatabase, QFontMetrics

    from ui import markdown_view as MV
    from ui.markdown_html import MATH_FONTS

    view, _table = math_page(r"\mathcal{O}(n) + \underbrace{a+b}_{n} + \frac{1}{2}", full)
    text = view.browser.toPlainText()
    # (which of them this machine's fonts draw: DejaVu none - a box each -, a maths font 𝒪; the CI's
    # runner has such a font - the test assumed DejaVu's)
    families = QFontDatabase.families()
    drawn = {letter for letter in ("\U0001d4aa", "⏟", "⏞")
             if any(QFontMetrics(QFont(family)).inFontUcs4(ord(letter)) for family in families)}
    assert not (set(text) & {"\U0001d4aa", "⏟", "⏞"}) - drawn, (repr(text), drawn)
    # (a maths font that has it itself - not through Qt's fallback fonts: markdown_view._check_script_letters)
    maths = any(name in families and MV._raw_has(name, 0x1D4AA) for name in MATH_FONTS)
    assert ("\U0001d4aa" in text) == maths, (repr(text), maths)  # (𝒪 where a maths font of the page has it)
    assert "O" in text or "\U0001d4aa" in text


# -- 7. a raw HTML tag's address is no link -------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_hostile_an_address_in_a_tags_attribute_is_no_link(full):
    from tests.test_markdown_reader_bugs11 import math_page  # noqa: F401 - (the app, the helpers)
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(800, 400)
    view.show()
    view.render('<div title="see http://e.example/q">five</div>\n\n'
                '<div style="background-image:url(http://t.example/b)">six</div>\n\nand http://ok.example/ here\n')
    until(lambda: view._readable and not view.more(), 10)
    pump(0.2)
    text = view.browser.toPlainText()
    hrefs = []
    block = view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            if pieces.fragment().charFormat().anchorHref():
                hrefs.append(pieces.fragment().charFormat().anchorHref())
            pieces += 1
        block = block.next()
    assert "five" in text and "six" in text
    assert "title=" not in text and "url(" not in text and "e.example" not in text, repr(text)
    assert not [href for href in hrefs if "e.example" in href or "t.example" in href], hrefs
    assert any("ok.example" in href for href in hrefs), hrefs  # (a bare address in prose still is one)


# -- 10. a look-alike host: punycode -------------------------------------------------------------------

def _links_of(view) -> list[str]:
    hrefs, block = [], view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            if pieces.fragment().charFormat().anchorHref():
                hrefs.append(pieces.fragment().charFormat().anchorHref())
            pieces += 1
        block = block.next()
    return hrefs


@pytest.mark.parametrize("full", [True, False])
def test_hostile_a_look_alike_host_is_shown_and_followed_in_punycode(full):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(800, 400)
    view.show()
    view.render("Go to <http://аррӏе.com/login> or http://раураl.com/ now; "
                "but <https://münchen.de/> and <https://例え.jp/> are what they are.\n")
    until(lambda: view._readable and not view.more(), 10)
    pump(0.2)
    text, hrefs = view.browser.toPlainText(), _links_of(view)
    assert "аррӏе" not in text and "раураl" not in text, text  # (read "apple.com", "paypal.com")
    assert "xn--80ak6aa92e.com" in text, text
    assert not [href for href in hrefs if "аррӏе" in href or "раураl" in href], hrefs
    assert any("xn--80ak6aa92e" in href for href in hrefs), hrefs
    assert "münchen.de" in text and "例え.jp" in text  # (one script, none confusable with Latin: as written)


def test_hostile_the_terminal_and_the_page_agree_on_a_look_alike():
    from core import markdown_doc as MD

    assert MD.safe_host_url("http://аррӏе.com/login") == "http://xn--80ak6aa92e.com/login"
    assert MD.safe_host_url("https://münchen.de/") == "https://münchen.de/"
    assert MD.safe_host_url("http://gооgle.com") .startswith("http://xn--")  # (two Cyrillic о: mixed scripts)


# -- 9. a task done: ☑ (Qt's box was a cross, ☒: "rejected") --------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_typo_a_task_done_shows_a_check_not_a_cross(full):
    from PyQt6.QtGui import QTextBlockFormat

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(600, 300)
    view.show()
    view.render("- [x] done task\n- [ ] open task\n\n- plain\n- [x] mixed done\n")
    until(lambda: view._readable and not view.more(), 10)
    document = view.browser.document()
    for needle, glyph in (("done task", "☑"), ("open task", "☐"), ("mixed done", "☑")):
        block = document.find(needle).block()
        assert block.text().startswith(glyph), (needle, block.text())
        assert block.blockFormat().marker() == QTextBlockFormat.MarkerType.NoMarker  # (Qt's box: ☒)
    assert not document.find("plain").block().text().startswith(("☑", "☐"))


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_text_ending_in_a_rule_has_one_rule_before_its_notes(full):
    from PyQt6.QtGui import QTextFormat

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(600, 300)
    view.show()
    view.render("Text with a note[^1].\n\n---\n\n[^1]: The note.\n")
    until(lambda: view._readable and not view.more(), 10)
    rules, block = 0, view.browser.document().begin()
    while block.isValid():
        rules += block.blockFormat().hasProperty(QTextFormat.Property.BlockTrailingHorizontalRulerWidth)
        block = block.next()
    assert rules == 1, rules  # (the text's and the notes' own: two in a row)


@pytest.mark.parametrize("full", [True, False])
def test_typo_an_anchor_jump_leaves_a_little_room_above_its_heading(full, tmp_path):
    dialog = opened(full, tmp_path, gap_text(30))
    try:
        view = dialog.view
        view.clicked(QUrl("#chapter-20"))
        pump(0.3)
        block = view.browser.document().find("Chapter 20").block()
        top = view.browser.cursorRect(QTextCursor(block)).top()
        assert 6 <= top <= 20, top  # (flush at 0 before)
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_list_in_a_list_stands_in_as_githubs(full):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(600, 300)
    view.show()
    view.render("- outer\n  - inner\n    - innermost\n")
    until(lambda: view._readable and not view.more(), 10)
    left = []
    for word in ("outer", "inner", "innermost"):
        found = view.browser.document().find(word)
        found.setPosition(found.selectionStart())
        left.append(view.browser.cursorRect(found).left())
    steps = [left[1] - left[0], left[2] - left[1]]
    assert all(24 <= step <= 34 for step in steps), steps  # (Qt's 40 a level: wider than GitHub's 2em)
