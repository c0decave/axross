"""The tenth round of the Markdown reader: a place far on a long page laid
out first - a drop of the scroll bar, find, an anchor, Ctrl+End, the place a
page is shown again at - the parts between as they are scrolled to, every
place kept (outline, anchors, find, Back, the place read). In both of Qt's
paths (markdown-it's page and Qt's own parser, md4c). Each test failed
before.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.003)


def long_text(sections: int, last: str = "") -> str:
    """A long page: sections of a heading, a paragraph and a list."""
    out = ["# A long page\n\n"]
    for n in range(sections):
        out.append(f"## Section {n}\n\nParagraph {n} with some words that make a line or two of text "
                   f"to read, about section number {n} and nothing else.\n\n- item {n} a\n- item {n} b\n\n")
    out.append(f"## The end\n\nThe last words {last}.\n")
    return "".join(out)


def view_of(text: str, full: bool, width: int = 900, height: int = 700):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(width, height)
    view.show()
    view.render(text)
    end = time.monotonic() + 60
    while time.monotonic() < end and not view._readable:
        pump(0.01)
    pump(0.3)
    return view


def shown(view) -> str:
    """The text the view shows ("" when it shows stand-ins only): its blocks' first."""
    from ui import markdown_view as MV

    browser = view.browser
    block = browser.cursorForPosition(browser.viewport().rect().topLeft()).block()
    last = browser.cursorForPosition(browser.viewport().rect().bottomLeft()).block()
    while block.isValid():
        fmt = block.blockFormat()
        if block.text().strip() and not fmt.intProperty(MV._GAP) and not fmt.boolProperty(MV._STAND_IN):
            return block.text()
        if block == last:
            break
        block = block.next()
    return ""


def top_text(view) -> str:
    return view.browser.cursorForPosition(view.browser.viewport().rect().topLeft()).block().text()


# -- a drop far on, find of the last word: fast --------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_drop_at_95_percent_shows_its_place_at_once(full):
    view = view_of(long_text(5000), full)  # (about 1 MB)
    pump(1.0)
    bar = view.browser.verticalScrollBar()
    assert view.more()
    began, cpu = time.monotonic(), time.thread_time()
    target = int(bar.maximum() * 0.95)
    bar.setValue(target)
    while time.monotonic() - began < 30 and not shown(view).strip():
        pump(0.02)
    took, spent = time.monotonic() - began, time.thread_time() - cpu
    assert shown(view).strip(), "nothing shown where the thumb was dropped"
    # (all of the page up to there laid out first: 6 s; under a loaded machine's
    # time a generous bound, the window's own CPU the tight one)
    assert took < 3.0 and spent < 0.6, (took, spent)
    # (where it was dropped, not back at the top - the page's height made exact as it comes)
    assert abs(bar.value() - target) < view.browser.viewport().height(), (bar.value(), target)


@pytest.mark.parametrize("full", [True, False])
def test_sad_find_of_the_last_word_of_a_long_page_is_fast(full, tmp_path):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "long.md"
    path.write_text(long_text(5000, last="zebraquux"), encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.view.full = dialog.view.full and full
    if not full:
        dialog.view.render(path.read_text(encoding="utf-8"))
    dialog.resize(1000, 800)
    dialog.show()
    try:
        end = time.monotonic() + 60
        while time.monotonic() < end and not dialog.view._readable:
            pump(0.01)
        pump(1.0)
        began, cpu = time.monotonic(), time.thread_time()
        dialog.find_field.setFocus()
        dialog.find_field.setText("zebraquux")
        QTest.keyClick(dialog.find_field, Qt.Key.Key_Return)
        browser = dialog.view.browser
        while time.monotonic() - began < 30 and browser.textCursor().selectedText().lower() != "zebraquux":
            pump(0.02)
        took, spent = time.monotonic() - began, time.thread_time() - cpu
        assert browser.textCursor().selectedText().lower() == "zebraquux"
        assert took < 4.0 and spent < 1.0, (took, spent)  # (all of it laid out first: 10 s)
    finally:
        dialog.close()
        dialog.deleteLater()


# -- every place after a part laid out out of order ------------------------------------------------------

def jumped(full: bool, monkeypatch):
    """A long page with the scroll bar dropped far on (its part laid out
    first, a gap of parts before it) - and in pieces parsed apart."""
    from core import markdown_term as T
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 300)
    monkeypatch.setattr(T, "STREAM_CHARS", 20_000)
    monkeypatch.setattr(T, "STREAM_LINES", 300)
    view = view_of(long_text(800), full)
    bar = view.browser.verticalScrollBar()
    bar.setValue(int(bar.maximum() * 0.8))
    end = time.monotonic() + 30
    while time.monotonic() < end and not shown(view).strip():
        pump(0.02)
    pump(0.3)
    assert view._gaps, "no jump"  # (parts between not laid out)
    return view


@pytest.mark.parametrize("full", [True, False])
def test_sad_after_a_jump_an_outline_entry_leads_to_its_heading(full, monkeypatch):
    from PyQt6.QtCore import Qt

    view = jumped(full, monkeypatch)
    rows = [row for row in range(view.outline.count()) if "Section" in view.outline.item(row).text()]
    assert rows
    for row in (rows[0], rows[-1]):  # (one before the gap, one after it)
        item = view.outline.item(row)
        view.jump(item)
        pump(0.1)
        position = int(item.data(Qt.ItemDataRole.UserRole))
        block = view.browser.document().findBlock(position)
        assert block.text() == item.text().strip()  # (its place moved with the parts put in before it)
        from PyQt6.QtGui import QTextCursor

        rect = view.browser.cursorRect(QTextCursor(block))
        assert 0 <= rect.top() < view.browser.viewport().height(), (rect, top_text(view))  # (in view)


@pytest.mark.parametrize("full", [True, False])
def test_sad_after_a_jump_an_anchor_in_a_gap_lands_on_its_heading(full, monkeypatch):
    view = jumped(full, monkeypatch)
    gap = view._gaps[0]
    number = (gap["lo"] + gap["hi"]) // 2
    plain = view._plain(number)
    import re

    found = re.search(r"section (\d+)", plain)
    assert found
    name = f"section-{found.group(1)}"
    assert view.go_to_anchor(name)
    end = time.monotonic() + 20
    while time.monotonic() < end and top_text(view) != f"Section {found.group(1)}":
        pump(0.02)
    assert top_text(view) == f"Section {found.group(1)}"
    assert view.browser.document().findBlock(view.anchors[name]).text() == f"Section {found.group(1)}"


@pytest.mark.parametrize("full", [True, False])
def test_sad_after_a_jump_find_finds_a_word_in_a_gap(full, monkeypatch, tmp_path):
    view = jumped(full, monkeypatch)
    gap = view._gaps[0]
    import re

    word = re.search(r"section number (\d+)", view._plain((gap["lo"] + gap["hi"]) // 2)).group(0)
    from PyQt6.QtGui import QTextCursor

    view.browser.setTextCursor(QTextCursor(view.browser.document()))  # (from the page's start)
    found = view.browser.find(word)
    if not found:
        assert view.seek(word, False, lambda: None)
        end = time.monotonic() + 20
        while time.monotonic() < end and view.browser.document().find(word).isNull():
            pump(0.02)
    hit = view.browser.document().find(word)
    assert not hit.isNull() and hit.selectedText() == word


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_page_shown_again_after_a_jump_is_shown_at_the_same_place(full, monkeypatch):
    view = jumped(full, monkeypatch)
    before = top_text(view)
    assert before.strip()
    view.render(view.markdown)  # (a reload)
    end = time.monotonic() + 30
    while time.monotonic() < end and top_text(view) != before:
        pump(0.02)
    assert top_text(view) == before


@pytest.mark.parametrize("full", [True, False])
def test_sad_after_a_jump_all_of_the_page_comes_in_its_order(full, monkeypatch):
    from ui import markdown_view as MV

    view = jumped(full, monkeypatch)
    view.load_rest_now()  # (export, print, a copy of all of it)
    assert not view.more()
    text = view.browser.toPlainText()
    numbers = [int(line.split()[1]) for line in text.splitlines() if line.startswith("Section ")]
    assert numbers == list(range(800)), [n for a, n in zip(range(800), numbers, strict=False) if a != n][:5]
    tall = []
    block = view.browser.document().begin()
    while block.isValid():
        if block.blockFormat().intProperty(MV._GAP) or block.blockFormat().lineHeight() > 100:
            tall.append(block.blockNumber())
        block = block.next()
    assert not tall  # (no gap's stand-in left)


# -- math: italic variables, a brace of one piece, nothing half converted ------------------------------

FORMULAS = [r"x^2 + \sin y", r"f(x) = \begin{cases} x^2 & \text{if } x \ge 0 \\ -x & x < 0 \end{cases}",
            r"\frac{a+b}{\log n}", r"e^{\sin t}", r"\sqrt{x^2+y^2}", r"\mathbf{v} \cdot \text{max}(a, b)"]


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_formulas_letters_are_italic_its_words_are_not(full):
    view = view_of("Inline $x^2 + \\sin y$ and $\\text{area} = \\pi r^2$ here.\n", full)
    document = view.browser.document()

    def italic(needle: str, after: int = 0) -> bool:
        return document.find(needle, after).charFormat().fontItalic()

    assert italic("x") and italic("y", document.find("sin").selectionEnd()) \
        and italic("r", document.find("π").selectionEnd())  # (variables)
    assert not italic("sin") and not italic("area")  # (a function's name, \\text: upright, as KaTeX's)
    assert not italic("Inline") and not italic("here")


def test_typo_the_terminal_keeps_a_formulas_letters_plain():
    from core import markdown_doc as MD

    for tex in FORMULAS:
        shown = MD.math_text(tex)
        assert not any(ord(c) < 32 and c != "\n" for c in shown), (tex, shown)  # (no mark of ours left)
        assert "<i>" not in shown


def test_typo_no_mark_of_a_formula_reaches_a_page():
    import re

    from core import markdown_doc as MD

    for tex in FORMULAS:
        html = MD.math_html(tex)
        assert not re.search("[\x00-\x08\x0b-\x1f]", html), (tex, repr(html))


@pytest.mark.parametrize("full", [True, False])
def test_typo_cases_have_one_brace_as_tall_as_their_rows(full):
    from PyQt6.QtGui import QTextCursor

    view = view_of("$$\nf(x) = \\begin{cases} x^2 & x \\ge 0 \\\\ -x & x < 0 \\end{cases}\n$$\n\nAfter.\n", full)
    document = view.browser.document()
    # (in pieces since the thirteenth review - bugs14: one glyph was 1.3 rows tall whatever their count - its
    # top beside the first row, its foot beside the last, its middle between them)
    brace = document.find("⎨")
    first, second = view.browser.cursorRect(document.find("x ≥ 0")), view.browser.cursorRect(document.find("x < 0"))
    middle = view.browser.cursorRect(brace).center().y()
    assert first.center().y() < middle < second.center().y()
    top, foot = view.browser.cursorRect(document.find("⎧")), view.browser.cursorRect(document.find("⎩"))
    assert top.top() <= first.top() + 4 and foot.bottom() >= second.bottom() - 4, (top, first, foot, second)
    assert QTextCursor(brace).position() >= 0
