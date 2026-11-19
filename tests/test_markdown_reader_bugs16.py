"""The sixteenth round of the Markdown reader (the fifteenth review): big
blocks inside a list item, a quote or an alert, Copy of many formulas, raw
HTML's anchors, formulas shown as written, runs of ">" and chips, a code
span in a formula - and the lows. Each test failed before, from the
reviewer's repros; time is the GUI thread's own (time.thread_time), not the
wall's (a loaded machine made wall-time tests flaky).
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

from PyQt6.QtCore import QTimer, QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _closed_after():
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    pump(0.05)


def _view(text: str, full: bool, size=(900, 700)):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(*size)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 120)
    pump(0.2)
    return view


class Turns:
    """The GUI thread's own time of each event-loop turn (a 5 ms timer's
    beats) while it runs - what holds the window up, whatever else the
    machine does."""

    def __init__(self):
        self.turns, self._last = [], time.thread_time()
        self.timer = QTimer()
        self.timer.timeout.connect(self._beat)
        self.timer.start(5)

    def _beat(self):
        now = time.thread_time()
        self.turns.append(now - self._last)
        self._last = now

    def worst(self) -> float:
        self.timer.stop()
        return round(max(self.turns, default=0.0), 3)


# -- (G5) a big block inside a container, a long copy, runs of ">", many chips: never a hold-up ----

def _quoted(lines: list[str]) -> str:
    return "".join("> " + line + "\n" for line in lines)


CONTAINED = {
    "quote_table": lambda: "# T\n\n" + _quoted(["| a | b | c |", "|---|---|---|"]
                                               + [f"| {n} | x{n} | **y** |" for n in range(3000)]),
    "quote_fence": lambda: "# T\n\n" + _quoted(["```"] + [f"log line {n} some text here" for n in range(20_000)]
                                               + ["```"]) + "\nAfter.\n",
    "list_fence": lambda: "# T\n\n- item\n\n  ```\n" + "".join(f"  log line {n} some text here\n"
                                                           for n in range(20_000)) + "  ```\n\n- next\n",
    "list_items_big": lambda: "".join("- item\n\n  ```\n" + "".join(f"  l{k}\n" for k in range(40)) + "  ```\n\n"
                                      for _ in range(500)),
    "list_math": lambda: "# T\n\n- " + "".join(f"term $x_{{{n}}}^2 + \\frac{{a}}{{b}}$ and $\\alpha_{n}$\n  "
                                              for n in range(3000)) + "\n",
    "quote_run": lambda: ">" * 20_000 + " deep\n",
    "images": lambda: " ".join(f"![i{n}](img{n}.png)" for n in range(20_000)) + "\n",
    "emoji": lambda: ":tada: " * 50_000 + "\n",
    "headings": lambda: "".join(f"# H{n}\n" for n in range(20_000)),
    "wide_table": lambda: "|" + "|".join(f"c{n}" for n in range(2000)) + "|\n|" + "---|" * 2000 + "\n"
                          + "".join("|" + "|".join(str(n) for n in range(2000)) + "|\n" for _ in range(100)),
    "notes": lambda: "".join(f"Text[^{n}].\n\n" for n in range(2000)) + "".join(f"[^{n}]: note {n}\n"
                                                                             for n in range(2000)),
}


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("bomb", sorted(CONTAINED))
def test_guard_a_big_block_in_a_container_never_holds_up_the_window(bomb, full):
    """The fifteenth review's container bombs (a 30,000-row table in a quote: 48 s; a fence in a list item:
    6.5 s; 20,000 formulas in one item: 29 s), a run of 20,000 ">" (3 s), a paragraph of image chips (each
    a frame of Qt's: every part walked all of them), 1.4 MB of emoji in one paragraph (1.7 s), 100,000
    headings in a row (Qt's own parser: one part, 7 s), a table of 2,000 columns as written (0.5 s), 3,000
    notes in one list (0.7 s): the GUI thread's own time in one turn stays under 0.25 s."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    turns = Turns()
    view.render(CONTAINED[bomb]())
    assert until(lambda: view._readable and view.markdown, 120)

    def laid() -> bool:
        return not view._scheduled and not view.status.text().startswith("Rendering")

    until(laid, 30)
    pump(0.3)
    view.go_end()
    pump(0.5)
    until(laid, 30)
    worst = turns.worst()
    assert worst < 0.25, (worst, sorted(turns.turns)[-4:])


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("bomb", ["list_math", "formulas"])
def test_guard_copy_of_many_formulas_takes_a_piece_a_turn(bomb, full):
    """lm_1000.md: Copy of 1,000 formulas took 7 s (each formula's end looked for from its block's first
    fragment, each block's text read again for each); 60,000 in one paragraph 9 s in one turn."""
    from PyQt6.QtWidgets import QApplication as App

    text = CONTAINED["list_math"]() if bomb == "list_math" else \
        " ".join(f"$x_{{{n}}}^2$" for n in range(6000)) + "\n"
    view = _view(text, full, (1000, 800))
    view.load_rest_now()
    until(lambda: not view.more(), 60)
    App.clipboard().setText("EMPTY")
    turns = Turns()
    view.browser.select_all()
    view.copy_selection()
    assert until(lambda: App.clipboard().text() != "EMPTY", 120)
    worst = turns.worst()
    copied = App.clipboard().text()
    assert ("$x_{2999}^2 + \\frac{a}{b}$" if bomb == "list_math" else "$x_{5999}^2$") in copied
    assert worst < 0.25, (worst, sorted(turns.turns)[-4:])


# -- 1. a block too big for its container: whole, in its place (laid out in parts inside it) -----------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_big_table_in_a_quote_is_a_table_in_its_quote(full):
    """(Seventeenth round: the table stays in its quote - the page is cut inside the quote - no notice.)"""
    from ui import markdown_view as MV

    text = "Intro.\n\n" + _quoted(["Quoted words.", "", "| a | b |", "|---|---|"]
                                  + [f"| r{n} | x{n} |" for n in range(800)]) + "\nAfter.\n"
    view = _view(text, full)
    view.load_rest_now()
    until(lambda: not view.more(), 60)
    shown = view.browser.toPlainText()
    assert "Quoted words." in shown and "r799" in shown and "After." in shown and ">" not in shown
    block = view.browser.document().find("r799").block()
    assert not MV._is_code(block)


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_long_fence_in_a_list_item_is_whole_in_its_item(full):
    from ui import markdown_view as MV

    text = "- step one:\n\n  ```\n" + "".join(f"  out {n}\n" for n in range(1500)) + "  ```\n\n- step two\n"
    view = _view(text, full)
    view.load_rest_now()
    until(lambda: not view.more(), 60)
    shown = view.browser.toPlainText()
    assert "step one" in shown and "out 1499" in shown and "step two" in shown
    position = view.browser.document().find("out 700").position()
    code = view.code_block_at(position)
    assert code.startswith("out 0\n") and code.rstrip("\n").endswith("out 1499"), code[:40]
    assert MV._is_code(view.browser.document().findBlock(position))


# -- 5. runs of ">", a table of 2,000 columns: flatter / banded -----------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_quotes_deeper_than_eight_are_shown_flatter(full):
    view = _view(">" * 3000 + " deep\n", full)
    assert "deep" in view.browser.toPlainText() and "flatter" in view.notice.text()


# -- 3. raw HTML's anchors: GitHub's characters, both parsers -----------------------------------------

ANCHORED = ("# T\n\n[go](#here) [v](#v1.2.0) [n](#2024) [c](#26.8.0)\n\n" + "filler\n\n" * 200
            + '<a id="here"></a>\n\nHere.\n\n' + "filler\n\n" * 100 + '<a id="v1.2.0"></a>\n\nVersion.\n\n'
            + "filler\n\n" * 100 + '<a name="2024"></a>\n\nYear.\n\n' + "filler\n\n" * 100
            + '<a id="26.8.0"></a>\n\n## 2026-08-26, Version 26.8.0\n\n' + "filler\n\n" * 100)


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("anchor, after", [("here", "Here."), ("v1.2.0", "Version."), ("2024", "Year."),
                                           ("26.8.0", "2026-08-26, Version 26.8.0")])
def test_sad_a_raw_html_anchor_with_digits_or_dots_is_found(full, anchor, after):
    """t/aid2.md, Node.js's CHANGELOG (#26.8.0): <a id="v1.2.0">, <a name="2024"> were dropped (a name
    began with a letter, held no dot); Qt's own parser kept no <a id> at all - even #here."""
    from PyQt6.QtCore import QPoint

    view = _view(ANCHORED, full)
    view.clicked(QUrl("#" + anchor))
    pump(0.5)
    until(lambda: not view._scheduled, 20)
    pump(0.3)
    block = view.browser.cursorForPosition(QPoint(5, 5)).block()
    shown = [block.text()]
    for _ in range(3):
        block = block.next()
        shown.append(block.text())
    assert after in shown, (view.status.text(), shown)


# -- 4. formulas: KaTeX's common signs, scripts of scripts, \cfrac and \overset stacked --------------

SIGNS = {r"a \ll b": "a ≪ b", r"x \gg 1": "x ≫ 1", r"a^\dagger": "a^†", r"\Pr(A)": "Pr(A)",
         r"f \colon A \longrightarrow B": "f : A ⟶ B", r"\therefore": "∴", r"p \vdash q": "p ⊢ q",
         r"\models": "⊨", r"a \prec b \succ c": "a ≺ b ≻ c", r"\odot": "⊙", r"\lvert x \rvert": "|x|",
         r"a \leqslant b": "a ⩽ b", r"a \lesssim b": "a ≲ b", r"\square": "□", r"\checkmark": "✓",
         r"\hookrightarrow": "↪", r"\limsup_{n} x_n": "limsupₙ xₙ", r"\liminf": "liminf"}


@pytest.mark.parametrize("tex, shown", sorted(SIGNS.items()))
def test_sad_katexs_common_signs_are_their_signs(tex, shown):
    """t/math2.md: about 90 common commands showed as written (\\ll, \\dagger, \\limsup, \\colon ...)."""
    from core import markdown_doc as MD

    assert MD.math_text(tex) == shown


@pytest.mark.parametrize("tex", [r"\sigma_{x_b}", r"a^{b_c}", r"\sum^{n_b}", r"\sum_{k=1}^{n_b}"])
def test_sad_a_script_of_a_script_is_raised_or_lowered_on_a_page(tex):
    """\\sigma_{x_b}: the inner script showed a literal "_b" on the page."""
    import re

    from core import markdown_doc as MD

    shown = MD.math_html(tex)
    assert "_" not in re.sub(r"<[^>]+>", "", shown) and "^" not in re.sub(r"<[^>]+>", "", shown), shown
    assert re.search(r"<su[bp]><su[bp]><i>[bc]</i></su[bp]></su[bp]>", shown), shown


def test_sad_cfrac_and_overset_are_stacked_in_a_display():
    """\\cfrac was never stacked; \\overset{!}{=} put the "!" beside the sign, not over it."""
    from ui import markdown_html as H

    assert H.display_items(r"x = \cfrac{1}{1+x}") == [("text", "x = "), ("frac", "1", "1+x")]
    assert H.display_items(r"a \overset{!}{=} b") == [("text", "a "), ("stack", "=", "!", None), ("text", " b")]
    assert H.display_items(r"\underset{x}{\min} f") == [("stack", "\\min", None, "x"), ("text", " f")]
    laid = H.display_html(r"a \overset{!}{=} b", H.colours(False))
    assert laid.index("!") < laid.index(">=<") if ">=<" in laid else laid.index("!") < laid.rindex("=")


# -- 6. $`…`$: GitHub's formula in a line -----------------------------------------------------------

BACKTICK_MATH = "A $`x^2`$ B\n\nC $`y`$ D $`z`$ E\n\nF `code` G $a$ H\n"


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_backtick_formula_is_a_formula_in_both_parsers(full):
    """t/btmath.md: Qt's own parser showed "A 0 B" (the code span's placeholder), markdown-it the
    backticks inside the formula."""
    shown = _view(BACKTICK_MATH, full).browser.toPlainText()
    assert "A x2 B" in shown and "C y D z E" in shown and "F code G a H" in shown and "`" not in shown, shown


def test_sad_a_backtick_formula_in_the_terminal():
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render(BACKTICK_MATH, MT.Options(depth="none")))
    assert "A x² B" in shown and "F `code` G a H" in shown and "$`" not in shown, shown


# -- 8. a new search after scrolling begins at what is shown ----------------------------------------

def test_sad_a_new_search_after_scrolling_starts_from_the_view():
    """findpos.py real/CHANGELOG.md: after scrolling down, a new search went back to the old match."""
    from PyQt6.QtTest import QTest

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    text = "".join(f"## Section {n}\n\n" + "filler line\n\n" * 20 + "needle here\n\n" for n in range(40))
    dialog = MarkdownViewerDialog(LocalFS(), "")
    dialog.resize(900, 700)
    dialog.show()
    dialog.view.render(text)
    assert until(lambda: dialog.view._readable, 30)
    pump(0.3)
    browser = dialog.view.browser
    for fraction, at_least in ((0.1, 3), (0.6, 23)):
        bar = browser.verticalScrollBar()
        bar.setValue(int(bar.maximum() * fraction))
        pump(0.4)
        top = browser.cursorForPosition(browser.viewport().rect().topLeft()).blockNumber()
        dialog.find_field.clear()
        dialog.find_field.setFocus()
        QTest.keyClicks(dialog.find_field, "needle")
        pump(0.5)
        assert browser.textCursor().blockNumber() >= top, (fraction, top, browser.textCursor().blockNumber())
        dialog.end_find()
        pump(0.2)


# -- 9. the terminal keeps a list's start 0 ---------------------------------------------------------

def test_sad_the_terminal_keeps_a_list_starting_at_zero():
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render("0. zero\n1. one\n", MT.Options(depth="none")))
    assert [line.strip() for line in shown.splitlines() if line.strip()] == ["0. zero", "1. one"], shown


# -- 10. the terminal keeps deep quotes within its width ---------------------------------------

def test_sad_the_terminal_keeps_deep_quotes_within_its_width():
    """t/q60.md at --width 40: 90 columns; deepquote.md (2 MB) wrote 184 MB."""
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render("> " * 60 + "deep\n", MT.Options(depth="none", width=40)))
    assert max(len(line) for line in shown.splitlines()) <= 40 and "quotes nested more than 8" in shown
    big = MT._strip_ansi(MT.render((">" * 1000 + " deep\n") * 500, MT.Options(depth="none", width=80)))
    assert len(big) < 100_000


# -- 11. a footnote's label: case aside, as GitHub -------------------------------------------------

NOTES = "Cited[^b], then[^a], case[^A], missing[^zz].\n\n[^a]: Note A.\n[^b]: Note B.\n"


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_footnote_label_matches_case_aside(full):
    """t/fn.md: [^A] stayed as written though [^a] is defined."""
    shown = _view(NOTES, full).browser.toPlainText()
    assert "case[2]" in shown and "missing[^zz]" in shown, shown


def test_sad_a_footnote_label_matches_case_aside_in_the_terminal():
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render(NOTES, MT.Options(depth="none")))
    assert "case[2]" in shown and "[2] Note A." in shown, shown
