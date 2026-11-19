"""The fourteenth round of the Markdown reader (the thirteenth review): the
guards made independent - (G1) a page in parts is the page whole by every
block's full text, links and anchors; (G2) what Copy puts on the clipboard
is the text the Markdown source says, by an expected text written from the
source, not by the copy of a laid-out page; (G3) properly nested formulas
laid out in the real view within the window's budget - and the faults they
found. In both of Qt's paths and the terminal. Each test failed before.
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

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _closed_after():
    """Every window of a test closed after it: a page left open went on laying itself out in the next
    test's event loop - its pauses counted as that test's (the md4c italics stall, 0.5 s once a run)."""
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    pump(0.05)


# -- (G1) parts are the whole: full text, links, anchors -------------------------------------------------

#: The twelfth review's notes: one cited from another, an undefined one, one "defined" in a fence only.
NOTES = """# Notes

Alpha cites a long sentence here to push the reference far beyond seventy characters of text in the block[^b] and[^a].

[^a]: Note A cites another[^c].

Para two refers to b again[^b] and c[^c], and to an undefined one[^zz].

```
[^a]: not a definition, in a fence
```

Para three refers to [^x] defined in fence only.

[^b]: Note B
    with continuation line.

## Second

Text[^d].

[^c]: Note C.
[^d]: Note D with a link [x](https://example.com).
"""


def _laid(path, full, monkeypatch, cut):
    from tests import test_markdown_corpus as corpus

    real = corpus._signature
    monkeypatch.setattr(corpus, "_signature", lambda view: full_signature_of(view, real))
    try:
        return corpus._laid_out(path, full, monkeypatch, cut)
    finally:
        monkeypatch.setattr(corpus, "_signature", real)


def full_signature_of(view, short):
    blocks = short(view)
    out, block = [], view.browser.document().begin()
    for entry in blocks:
        while block.isValid() and block.text()[:70].rstrip() != entry[0]:
            block = block.next()
        hrefs, names = [], []
        if block.isValid():
            pieces = block.begin()
            while not pieces.atEnd():
                fmt = pieces.fragment().charFormat()
                if fmt.anchorHref():
                    hrefs.append(fmt.anchorHref())
                names += [name for name in fmt.anchorNames() if not name.startswith("axross-")]
                pieces += 1
            text = block.text().rstrip()
            block = block.next()
        else:
            text = entry[0]
        out.append((text,) + tuple(entry[1:]) + (tuple(hrefs), tuple(names)))
    return out


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("cut", [3, 5, 9])
@pytest.mark.parametrize("doc", ["notes", "noted"])
def test_guard_parts_are_the_whole_by_full_text_links_and_anchors(full, cut, doc, monkeypatch, tmp_path):
    from tests.test_markdown_reader_bugs13 import noted

    path = tmp_path / "doc.md"
    path.write_text(NOTES if doc == "notes" else noted(16), encoding="utf-8")
    whole = _laid(path, full, monkeypatch, None)
    parts = _laid(path, full, monkeypatch, cut)
    differ = [(n, a, b) for n, (a, b) in enumerate(zip(whole, parts, strict=False)) if a != b]
    assert len(whole) == len(parts) and not differ, \
        f"{len(whole)} blocks whole, {len(parts)} in parts; first differences: {differ[:2]}"


# -- (G2) Copy is the text the source says ---------------------------------------------------------------

#: Words a page draws that the text has not (a summary's arrow, an alert's sign, a note's way back,
#: a task's box, a note's number in Qt's own parser's list).
DRAWN = re.compile(r"^(?:[▾▸ℹ✓❖⚠✖↩︎☑☐]+|\d+\.)$")


def _tokens(text: str) -> list[str]:
    words = re.sub(r"[\u00a0\u2028\u2029\u200b\ufeff]", " ", text).replace("↩︎", " ").replace("↩", " ").split()
    return [word for word in words if not DRAWN.match(word)]


def quoted_source() -> tuple[str, list[str]]:
    """A page of formulas inside quotes, alerts, list items, tables, details -
    and the text a copy of all of it holds, written from the source: each
    construct's words, a display formula "$$TeX$$", an inline one "$TeX$"."""
    parts, expected = [], []

    def add(markdown: str, *words: str) -> None:
        parts.append(markdown)
        for piece in words:
            expected.extend(piece.split())

    add("Intro paragraph one.\n\n", "Intro paragraph one.")
    add("> $$\n> a = \\frac{1}{2}\n> $$\n>\n> Quote text after the formula, which must be copied.\n\n",
        "$$a = \\frac{1}{2}$$", "Quote text after the formula, which must be copied.")
    add("> [!NOTE]\n> Note body first.\n>\n> $$\n> \\sum_{k=1}^n k = \\frac{n(n+1)}{2}\n> $$\n\n",
        "Note", "Note body first.", "$$\\sum_{k=1}^n k = \\frac{n(n+1)}{2}$$")
    add("- item with formula:\n\n  $$\n  x = \\frac{-b}{2a}\n  $$\n\n  item tail text.\n\n",
        "• item with formula:", "$$x = \\frac{-b}{2a}$$", "item tail text.")  # (its bullet copied: bugs15 #10)
    add("| a | b |\n|---|---|\n| $\\frac{1}{2}$ | cell |\n\n", "a b", "$\\frac{1}{2}$ cell")
    add("Inline $E = mc^2$ and $x_1$ here.\n\n", "Inline $E = mc^2$ and $x_1$ here.")
    add("End paragraph.\n", "End paragraph.")
    return "".join(parts), expected


def _copy(view, start: str | None, end: str | None) -> str:
    browser = view.browser
    document = browser.document()
    cursor = QTextCursor(document)
    if start is None:
        cursor.select(QTextCursor.SelectionType.Document)
    else:
        first, last = document.find(start), document.find(end)
        assert not first.isNull() and not last.isNull(), (start, end)
        cursor.setPosition(first.selectionStart())
        cursor.setPosition(last.selectionEnd(), QTextCursor.MoveMode.KeepAnchor)
    browser.setTextCursor(cursor)
    APP.clipboard().setText("OLD")
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    QTest.keyClick(browser, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert until(lambda: APP.clipboard().text() != "OLD", 30), view.status.text()
    return APP.clipboard().text()


def _view(text: str, full: bool):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and not view.more(), 30)
    pump(0.2)
    return view


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_select_all_copies_the_text_the_source_says(full):
    text, expected = quoted_source()
    view = _view(text, full)
    copied = _tokens(_copy(view, None, None))
    assert copied == expected, f"\ncopied:   {copied}\nexpected: {expected}"


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_a_selection_begun_in_a_quote_copies_from_there(full):
    text, expected = quoted_source()
    view = _view(text, full)
    copied = _tokens(_copy(view, "Quote text after", "tail text."))
    begin = expected.index("Quote")
    finish = expected.index("text.", expected.index("tail"))
    assert copied == expected[begin:finish + 1], f"\ncopied:   {copied}\nexpected: {expected[begin:finish + 1]}"


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_a_copy_of_a_formula_begins_on_a_line_of_its_own(full):
    view = _view("Intro.\n\n$$\n\\frac{a}{b}\n$$\n\nAfter.\n", full)
    copied = _copy(view, None, None)
    assert re.search(r"Intro\.\s*\n\s*\$\$\\frac\{a\}\{b\}\$\$\s*\n\s*After\.", copied), repr(copied)


# -- (G3) properly nested formulas, laid out in the real view, within the budget ----------------------------

def nested(seed: int) -> list[str]:
    """Properly nested formulas: environments up to 8 deep, \\left \\right inside
    them, fractions in fractions, long ones."""
    import random

    rng = random.Random(seed)
    envs = ["pmatrix", "bmatrix", "matrix", "cases", "vmatrix"]

    def build(depth: int) -> str:
        if depth == 0:
            return rng.choice(["a", "x_1", r"\frac{a}{b}", r"\sqrt{x}", r"\alpha^2", "1"])
        kind = rng.choice(["env", "left", "frac", "env"])
        if kind == "env":
            name = rng.choice(envs)
            cells = " & ".join(build(depth - 1) for _ in range(2))
            return rf"\begin{{{name}}} {cells} \\ {build(depth - 1)} & {build(depth - 1)} \end{{{name}}}"
        if kind == "left":
            return rf"\left( {build(depth - 1)} \right)"
        return rf"\frac{{{build(depth - 1)}}}{{{build(depth - 1)}}}"

    out = [build(depth) for depth in (2, 3, 4, 5, 6) for _ in range(2)]
    out.append(r"\begin{pmatrix}" * 7 + r"a&b\\c&d" + r"\end{pmatrix}" * 7)  # (deep.md: 18 s)
    out.append(r"\begin{pmatrix}" * 8 + r"a&b\\c&d" + r"\end{pmatrix}" * 8)
    out.append((r"\begin{pmatrix}" + (r"\begin{pmatrix}a&b\\c&d\end{pmatrix}&") * 4 + r"x\end{pmatrix}") * 12)
    out.append(r"\begin{cases}" + (r"\frac{\frac{a}{b}}{\sum_{i=1}^n x_i} & x>0 \\") * 60 + r"\end{cases}")
    out.append(r"\left(\frac{" * 7 + "x" + r"}{y}\right)" * 7)
    return out


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_nested_formulas_never_hold_up_the_window(full):
    from ui import markdown_view as MV

    text = "".join(f"Formula {n}:\n\n$$\n{tex}\n$$\n\n" for n, tex in enumerate(nested(5)))
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    beats, last = [], [time.thread_time()]  # (the GUI thread's own time a turn: not the loaded machine's)

    def beat():
        now = time.thread_time()
        beats.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.timeout.connect(beat)
    timer.start(10)
    began = time.monotonic()
    view.render(text)
    view.load_rest()
    assert until(lambda: view._readable and not view.more(), 120)
    bar = view.browser.verticalScrollBar()
    for share in (0.25, 0.5, 0.75, 1.0):  # (laid out by Qt as it is shown: scrolled through)
        bar.setValue(int(bar.maximum() * share))
        pump(0.2)
    timer.stop()
    took = time.monotonic() - began
    assert max(beats) < 0.3, (round(took, 2), sorted(round(beat, 3) for beat in beats)[-5:])  # (deep.md: 18 s)
    assert "Formula 14" in view.browser.toPlainText()


# -- 4. footnotes as GitHub numbers them ----------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_footnotes_are_numbered_as_github_numbers_them(full):
    view = _view(NOTES, full)
    text = view.browser.toPlainText()
    # (a reference to no note - none, or one "defined" in a fence only - stays as written: [4] and [5]
    # led nowhere, the notes read 1, 2, 3, 6)
    assert "[^zz]" in text and "[^x]" in text, text
    refs = re.findall(r"\[(\d+)\]", text)
    assert sorted(set(refs), key=int) == ["1", "2", "3", "4"], refs
    assert "[^c]" not in text  # (a note's own reference: a number too)
    hrefs, block = [], view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fmt = pieces.fragment().charFormat()
            if fmt.anchorHref():
                hrefs.append(fmt.anchorHref())
            pieces += 1
        block = block.next()
    backs = [href for href in hrefs if "fnref" in href]
    # (one way back to each place a note is referred to: b twice, a once, c twice - in the text and in A -,
    # d once: 6)
    assert len(backs) == 6, backs
    for back in backs:  # (each leads somewhere)
        assert view.go_to_anchor(back[1:], remember=False), back


# -- 6. the terminal: a matrix in a matrix in its cell -----------------------------------------------------

TERMINAL_KNOWN = [
    (r"\begin{pmatrix} \begin{matrix} a & b \\ c & d \end{matrix} & e \\ f & g \end{pmatrix}",
     ["⎛a b; c d  e⎞", "⎝f         g⎠"]),
    (r"\begin{bmatrix} 1 & 2 \\ 3 & 4 \end{bmatrix}", ["⎡1  2⎤", "⎣3  4⎦"]),
    (r"\begin{array}{c|c} a & b \\ \hline c & d \end{array}", ["a  b", "c  d"]),
]


@pytest.mark.parametrize("tex, rows", TERMINAL_KNOWN, ids=["matrix-in-matrix", "bmatrix", "array"])
def test_guard_the_terminal_keeps_known_formulas_shape(tex, rows):
    from core import markdown_term as T

    out = re.sub(r"\x1b\[[0-9;]*m", "", T.render(f"$$\n{tex}\n$$\n", T.Options(width=60)))
    assert [line.strip() for line in out.splitlines() if line.strip()] == rows, out


# -- 8. math: \imath, colour, boxes, cancels, an array's rules, a root of a fraction -------------------------

def test_typo_an_accent_on_imath_is_one_letter_with_its_accent():
    from core import markdown_doc as MD

    for tex, shown in ((r"\hat{\imath}", "ı̂"), (r"\vec{\jmath}", "ȷ⃗")):
        assert MD.math_text(tex) == shown, MD.math_text(tex)
    assert "\\" not in MD.math_text(r"\hat{\unknowncmd}").replace("\\unknowncmd", "")  # (one unit, not each letter)


@pytest.mark.parametrize("tex", [r"\color{red}{x+1}", r"\textcolor{blue}{y}", r"{\color{#ff8800} z}",
                                 r"\boxed{E = mc^2}", r"\cancel{x}"])
def test_typo_colour_boxes_and_cancels_are_no_raw_code(tex):
    from core import markdown_doc as MD

    runs = MD.math_runs(tex, small=False)
    assert not [text for text, kind in runs if kind == "unknown"], runs
    page = MD.math_html(tex)
    assert "<code>" not in page and "\\" not in re.sub(r"<[^>]*>", "", page), page


def test_hostile_a_formulas_colour_is_a_named_or_hex_one_only():
    from core import markdown_doc as MD

    page = MD.math_html(r"\color{red; background:url(x)}{a} \textcolor{expression(alert)}{b} \color{red}{c}")
    assert "url(" not in page and "expression" not in page and "background" not in page, page
    assert 'color="#' in page or "color:" in page  # (red: a colour)


def test_typo_an_arrays_column_rule_and_last_hline_are_drawn():
    from ui.markdown_html import colours, display_html

    page = display_html(r"\begin{array}{c|c} a & b \\ \hline c & d \\ \hline \end{array}", colours(False))
    assert "border-left: 1px solid" in page  # (the "|" of c|c)
    assert "border-bottom: 1px solid" in page  # (the \hline after the last row)


def test_typo_a_root_of_a_fraction_is_laid_out_in_display():
    from ui.markdown_html import colours, display_html, display_items

    assert display_items(r"\sqrt[3]{\frac{a}{b}}"), "the root in its line, as text"
    page = display_html(r"\sqrt[3]{\frac{a}{b}} = c", colours(False))
    assert "border-top: 1px solid" in page and "border-bottom: 1px solid" in page  # (its bar; the fraction's)


# -- 9. no step over the budget: thousands of letters, of italic spans ----------------------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("text", ["$$\n" + "x+" * 9900 + "x\n$$\n", " ".join(["*a*"] * 9900) + "\n",
                                  "$" + "y+" * 5000 + "y$\n"], ids=["formula", "italics", "inline"])
def test_sad_thousands_of_spans_in_a_line_never_hold_up_the_window(full, text):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    beats, last = [], [time.thread_time()]  # (the GUI thread's own time a turn: not the loaded machine's)

    def beat():
        now = time.thread_time()
        beats.append(now - last[0])
        last[0] = now

    import gc

    gc.collect()  # (the tests before it left objects a collection would take its time for, then)
    timer = QTimer()
    timer.timeout.connect(beat)
    timer.start(10)
    view.render(text)
    assert until(lambda: view._readable, 60)
    view.load_rest()  # (all of it: past EAGER_PARTS the rest waits for the reader)
    assert until(lambda: not view.more(), 60)
    pump(0.5)
    timer.stop()
    # (2.2 to 3.5 s before: Qt lays a line of spans out in time growing with their square - the bound
    # leaves room for a busy machine)
    assert max(beats) < 0.5, sorted(round(beat, 3) for beat in beats)[-4:]


# -- 10. a drag or the selection clipboard: as Copy -------------------------------------------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_dragged_selection_holds_what_copy_holds(full):
    view = _view("Intro.\n\n$$\n\\frac{a}{b}\n$$\n\nInline $x^2$ after.\n", full)
    browser = view.browser
    cursor = QTextCursor(browser.document())
    cursor.select(QTextCursor.SelectionType.Document)
    browser.setTextCursor(cursor)
    dragged = browser.createMimeDataFromSelection().text()
    assert "$$\\frac{a}{b}$$" in dragged and "$x^2$" in dragged, repr(dragged)


# -- 5. brackets as tall as their rows ---------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_typo_brackets_are_as_tall_as_their_rows(full):
    view = _view("$$\n\\begin{pmatrix} a \\\\ b \\\\ c \\\\ d \\end{pmatrix} "
                 "\\begin{bmatrix} 1 & 2 \\\\ 3 & 4 \\\\ 5 & 6 \\\\ 7 & 8 \\end{bmatrix}\n$$\n", full)
    document = view.browser.document()
    text = document.toPlainText()
    assert "[" not in text and "]" not in text, repr(text)  # (a bracket of rules beside the rows)

    def middle(needle: str) -> int:
        found = document.find(needle)
        assert not found.isNull(), needle
        return view.browser.cursorRect(found).center().y()

    # (a piece a row, each beside its row: one "(" 1.3 rows tall whatever their count)
    assert abs(middle("⎛") - middle("a")) <= 6 and abs(middle("⎝") - middle("d")) <= 6, \
        (middle("⎛"), middle("a"), middle("⎝"), middle("d"))


# -- typography: a math face's fall-back, braces over and under -------------------------------------------

def test_typo_formulas_fall_back_to_a_serif_face_not_the_sans_text():
    from ui.markdown_html import MATH_FONTS

    assert MATH_FONTS[:3] == ("STIX Two Math", "Latin Modern Math", "Cambria Math")
    assert MATH_FONTS[-1] == "DejaVu Serif" and "STIX Two Text" in MATH_FONTS


def test_typo_an_underbrace_is_drawn_under_its_group_with_its_label():
    from ui.markdown_html import colours, display_html

    page = display_html(r"\underbrace{a+b}_{n} = \overbrace{c}^{m}", colours(False))
    assert "border-bottom: 1px solid" in page and "border-top: 1px solid" in page
    assert "(a+b)" not in re.sub(r"<[^>]*>", "", page)  # (a parenthesis: the brace none)
