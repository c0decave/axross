"""The twenty-second round of the Markdown reader (the twenty-first review):
"new freeze classes are still found by changing just one axis" - so the
budgets are of the layout's cost, not of a shape: every block weighs in a
part (a rule, a short code block, a box's frame), a part is cut past twice its
budget wherever a block begins (between two code blocks, inside any
container), a paragraph is cut in pieces inside a link or emphasis too (the
open spans ended and begun again), a table's part by its characters as well
as its cells, a code line and a formula past a size in lines. A seeded,
reproducible sample of a grid - container x inline kind x block repetition -
checks it, both parsers, Find, Copy, PDF and the editor's preview with it; the
whole grid is a slow test of its own (AXROSS_SLOW=1). And the small things.
Each test failed before, with the dependencies of the shipped lock.
"""

from __future__ import annotations

import gc
import os
import random
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
from tests.test_markdown_reader_bugs20 import _settle, _Turns  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])
#: What Qt took here to lay out the calibration page (machine_factor) - where the budgets were measured.
CALIBRATION_SECONDS = 0.014


def machine_factor() -> float:
    """How much slower than the machine the budgets were measured on this one lays out a page - 1 to 3: a CI
    runner took half as long again for the same turns, and its tests failed by that alone (the least of five
    layouts of the same page, Qt's own CPU)."""
    from PyQt6.QtGui import QTextDocument

    text = "\n\n".join(f"Paragraph {n} with *some* `code`, **strong** words and [a link](x)." for n in range(600))
    took = []
    for _ in range(5):
        document = QTextDocument()
        began = time.thread_time()
        document.setMarkdown(text)
        document.setTextWidth(800)
        document.documentLayout().documentSize()
        took.append(time.thread_time() - began)
    return min(3.0, max(1.0, min(took) / CALIBRATION_SECONDS))


#: The longest event-loop turn of the GUI thread allowed (its own CPU time): 0.1 s on the machine the budgets
#: were measured on, as much longer on a slower one (machine_factor).
TURN = 0.1 * machine_factor()
_PAINTED: list = []


def turn_for(text: str) -> float:
    """TURN - and for a page of emoji, on top of it what Qt itself takes to paint a view full of them once:
    with a colour emoji font of bitmaps (Ubuntu's Noto Color Emoji, the CI runner's) FreeType decodes each
    glyph's bitmap at each paint, 0.05 s a view whatever the page does (as test_markdown_reader_bugs21's
    test of emoji)."""
    from ui.markdown_html import _PICTURE_SIGNS

    if not _PICTURE_SIGNS.search(text):
        return TURN
    if not _PAINTED:
        from PyQt6.QtWidgets import QTextBrowser

        plain = QTextBrowser()
        plain.resize(1000, 800)
        plain.show()
        plain.setPlainText("\U0001F389 " * 3000)
        pump(0.3)
        began = time.thread_time()
        plain.viewport().repaint()
        _PAINTED.append(time.thread_time() - began)
        plain.close()
        plain.deleteLater()
    return TURN + min(_PAINTED[0], TURN)  # (at most twice TURN, whatever the font)


def within_turn(measure, text: str, label=None) -> float:
    """*measure()* - the longest turn of something done - under turn_for(*text*); when it is not, once more:
    the machine timed again (machine_factor now - a runner shared with another job, a second pytest beside
    it, ran 5 % slower for a while: 0.109 s against 0.104 failed a release) and the turn measured again, the
    better of the two against the budget of the machine as it is then. Never more than 0.1 s of the
    calibration machine's, as fast as it is. And the window's longest wall-clock gap meanwhile (the
    heartbeats the measure stopped - tests/markdown_heartbeat.py) under its budget, measured again likewise:
    a worker holding Python's lock froze the window 12.6 s while the turn read 0.08 s. Returns the turn
    that passed."""
    from tests import markdown_heartbeat as HB

    def measured() -> tuple[float, float]:
        mark = len(HB.STOPPED)
        HB.DEFERRED[0] += 1
        try:
            turn = measure()
        finally:
            HB.DEFERRED[0] -= 1
        return turn, HB.gaps_since(mark)

    longest, gap = measured()
    budget, gap_budget = turn_for(text), HB.gap_budget()
    if longest < budget and gap < gap_budget:
        return longest
    factor = machine_factor()
    again, gap_again = measured()
    budget = max(budget, budget - TURN + 0.1 * factor)
    best = min(longest, again)
    TB.budget(best < budget, (label, longest, again, budget))
    TB.budget(min(gap, gap_again) < max(gap_budget, HB.GAP * factor),
              (label, "the window did not answer for", gap, gap_again, gap_budget))
    return best


@pytest.fixture(autouse=True)
def _closed_after():
    # (what earlier tests left is kept out of the collector's way: in one process with all the tests - as the CI
    # runs them - a full collection of it took 0.03 to 0.06 s, in whichever turn it fell)
    gc.collect()
    gc.freeze()
    yield
    gc.unfreeze()
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    _settle()


def _longest_turn(text: str, full: bool) -> float:
    """The window's longest turn showing *text* and going to its end (Ctrl+End)."""
    from ui import markdown_view as MV

    _settle()
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    pump(0.05)
    turns = _Turns()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 240)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 240)
    view.go_end()
    until(lambda: not view._scheduled, 120)
    pump(0.1)
    longest = turns.stop()
    view.close()
    view.deleteLater()
    return longest


PARSERS = pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])


# -- the review's cases (F1-F4): no turn over 0.1 s --------------------------------------------------

REVIEW_CASES = {
    # F1: a paragraph cut only at its top level - inside emphasis or a link it was one piece
    "F1 images in emphasis": lambda: "*" + "![i](x.png) " * 8000 + "![i](x.png)*\n",
    "F1 images in a link": lambda: "[" + "![i](x.png) " * 8000 + "](https://e.com)\n",
    "F1 formulas in a link": lambda: "[" + "$a$ " * 30000 + "](url)\n",
    "F1 formulas in strong": lambda: "**" + "$a$ " * 30000 + "$a$**\n",
    "F1 code spans in emphasis": lambda: "_" + "`a` " * 30000 + "_\n",
    # F2: never cut between two code blocks, a rule weighed nothing
    "F2 50,000 code blocks": lambda: "```\na\n```\n\n" * 50000,
    "F2 20,000 yaml blocks": lambda: "```yaml\na: 1\n```\n\n" * 20000,
    "F2 20,000 ~~~ blocks": lambda: "~~~\na\n~~~\n\n" * 20000,
    "F2 code blocks in a quote": lambda: "> ```\n> a\n> ```\n>\n" * 20000,
    "F2 code blocks in a list": lambda: "- x\n\n  ```\n  a\n  ```\n\n" * 20000,
    "F2 code blocks in details": lambda: "<details open><summary>S</summary>\n\n" + "```\na\n```\n\n" * 20000
                                         + "</details>\n",
    "F2 100,000 rules": lambda: "---\n\n" * 100000,
    # F3: a table's part cut by its cells only
    "F3 300 rows of long cells": lambda: "| a | b |\n|---|---|\n" + f"| {'x' * 1800} | {'y' * 1800} |\n" * 300,
    "F3 1,000 rows of long cells": lambda: "| a | b |\n|---|---|\n" + f"| {'x' * 1800} | {'y' * 1800} |\n" * 1000,
    "F3 one column of 900": lambda: "| a |\n|---|\n" + f"| {'x' * 1800} |\n" * 900,
    # F4: one long formula set in one piece; a code line of 80,000 characters likewise (found with them)
    "F4 a formula of 80,000": lambda: "$" + "a+" * 40000 + "b$\n",
    "F4 a display formula of 80,000": lambda: "$$\n" + "a+" * 40000 + "b\n$$\n",
    "F4 a code line of 80,000": lambda: "```\n" + "a+" * 40000 + "b\n```\n",
}


@PARSERS
@pytest.mark.parametrize("name", sorted(REVIEW_CASES))
def test_sad_the_reviews_cases_hold_no_turn(name, full):
    """Before (markdown-it / Qt's own parser, here): F1 4.6-4.8 s and 1.1-1.3 s; F2 code blocks 2.5-9 s,
    rules 1.3 / 3.4 s; F3 1.3-2.0 / 0.7-0.85 s; F4 0.6-0.8 s, a code line 0.6 / 0.7 s."""
    text = REVIEW_CASES[name]()
    within_turn(lambda: _longest_turn(text, full), text, name)


def test_sad_a_long_formula_shows_its_tex_and_a_long_code_line_all_of_it():
    from core import markdown_doc as MD
    from ui import markdown_view as MV

    tokens = MD.parse("Text $" + "a+" * 3000 + "b$ and $x$.\n\n$$\n" + "c+" * 3000 + "d\n$$\n").tokens
    inline = [child.type for child in tokens[1].children]
    assert "math_inline" in inline and inline.count("math_inline") == 1  # (the long one as its TeX, text)
    assert "".join(child.content for child in tokens[1].children).startswith("Text $a+a+")
    fence = next(token for token in tokens if token.type == "fence")
    assert fence.info == "tex" and all(len(line) <= MD.FORMULA_LINE for line in fence.content.split("\n"))
    code = "```\n" + "z" * 9000 + "\n```\n"
    shown = MV.renderable(code)[0]
    assert shown.replace("\n", "").count("z") == 9000 and max(map(len, shown.split("\n"))) <= MV.LINE_CAP


def test_sad_a_paragraph_is_cut_inside_a_link_its_link_on_each_piece():
    from core import markdown_doc as MD
    from ui import markdown_html as H

    tokens = H._paragraph_pieces(MD.parse("[" + "word " * 5000 + "](https://e.com) **" + "bold " * 3000 + "**\n")
                                 .tokens)
    pieces = [t for t in tokens if t.type == "inline"]
    assert len(pieces) > 3
    for piece in pieces:  # (each piece's spans opened and closed in it)
        depth = 0
        for child in piece.children:
            depth += child.nesting
            assert depth >= 0
        assert depth == 0
    assert sum(1 for piece in pieces for c in piece.children if c.type == "link_open") > 1
    assert all(c.attrGet("href") == "https://e.com" for piece in pieces for c in piece.children
               if c.type == "link_open")


def test_sad_a_cut_between_two_code_blocks_keeps_the_line_between_them():
    """A part cut between two code blocks (past twice its weight) begins with the line between them: without
    it Qt joined the two into one box (Copy Code Block copied both)."""
    from core import markdown_doc as MD
    from ui import markdown_html as H
    from ui import markdown_view as MV

    parts = H.to_html_parts(MD.parse("```\na\n```\n\n" * 20000), blocks=MV.PART_BLOCKS)
    assert len(parts) > 10
    assert sum(part.count('class="code-gap"') for part in parts) == 20000 - 1
    assert all(part.startswith('<p class="code-gap">') for part in parts[1:])


def test_sad_a_code_block_weighs_its_box_and_parts_begin_at_one():
    """A code block's frame weighs BOX_WEIGHT blocks in a part (its box costs Qt as much as three of its
    lines: 50,000 one-line code blocks 0.04 s a part without it, 0.02 s with it); and a part of
    markdown_parts may begin with a code block (50,000 short ones after one another were one part)."""
    from core import markdown_doc as MD
    from ui import markdown_html as H
    from ui import markdown_view as MV

    assert H.BOX_WEIGHT >= 3
    parts = H.to_html_parts(MD.parse("```\na\n```\n\n" * 20000), blocks=MV.PART_BLOCKS)
    # (a code block 2 + BOX_WEIGHT blocks: a part of 200 blocks, cut past twice that, holds 80 of them - 200 without)
    assert max(part.count('class="code-gap"') for part in parts) <= MV.PART_BLOCKS // 2
    plain = MV.markdown_parts("```\na\n```\n\n" * 50000)
    assert len(plain) > 10 and all(part.startswith("```") for part in plain)
    assert sum(part.count("```\na\n```") for part in plain) == 50000


def test_sad_qt_s_own_parser_cut_at_a_rule_shows_the_page_as_one():
    """A part of Qt's own parser begun at a rule "---": Qt took it for front matter (all up to the next
    "---" gone), and put an empty block before the rule - the page as one document has neither."""
    from PyQt6.QtGui import QTextDocument, QTextFormat

    from ui import markdown_view as MV

    text = "intro\n\n" + "".join(f"---\n\npara {n}\n\n" for n in range(6000))
    assert len(MV.markdown_parts(text)) > 10

    def blocks(document) -> tuple[int, int, int]:
        ruler = QTextFormat.Property.BlockTrailingHorizontalRulerWidth
        rules = empty = paragraphs = 0
        block = document.begin()
        while block.isValid():
            if block.blockFormat().hasProperty(ruler):
                rules += 1
            elif not block.text():
                empty += 1
            elif block.text().startswith("para "):
                paragraphs += 1
            block = block.next()
        return rules, empty, paragraphs

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(1000, 800)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    view.load_rest_now()
    assert until(lambda: view._rest is None and not view._gaps and not view._scheduled, 120)
    pump(0.2)
    whole = QTextDocument()
    whole.setMarkdown(text)
    assert blocks(view.browser.document()) == blocks(whole) == (6000, 0, 6000)
    view.close()


def test_sad_a_table_in_a_quote_is_cut_by_its_characters_too():
    """300 rows of two cells of 1,800 characters in a quote: under TABLE_PIECE_CELLS cells, one table of
    over a million characters to lay out at once."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = "> | a | b |\n> |---|---|\n" + f"> | {'x' * 1800} | {'y' * 1800} |\n" * 300
    sizes, size = [], 0
    for token in H._table_pieces(MD.parse(text).tokens):
        if token.type == "table_open":
            size = 0
        elif token.type == "inline":
            size += len(token.content)
        elif token.type == "table_close":
            sizes.append(size)
    assert len(sizes) > 10 and max(sizes) <= H.TABLE_PIECE_CHARS and sum(sizes) == 300 * 3600 + 2


@PARSERS
@pytest.mark.parametrize("name", ["F2 50,000 code blocks", "F1 images in a link", "F3 1,000 rows of long cells"])
def test_sad_find_copy_and_pdf_of_a_review_case_hold_no_turn(name, full, tmp_path):
    """Find 0.75 s, PDF 5.7 s on the images in a link; a copy of 50,000 code blocks took 2,000 of them a
    turn (0.1 s): a copy's piece is COPY_CHARS characters or COPY_BLOCKS blocks."""
    _ops_turns(REVIEW_CASES[name](), full, tmp_path)


@PARSERS
@pytest.mark.parametrize("name", ["F2 50,000 code blocks", "F2 code blocks in a quote"])
def test_sad_find_and_copy_of_a_page_laid_out_to_its_end_hold_no_turn(name, full, tmp_path):
    """All of the page laid out (read to its end): a copy's every piece listed the root frame's 50,000
    frames (0.13 s each - 0.42 s a turn), the find's hit test for the view's top walked them (0.09 s)."""
    _ops_turns(REVIEW_CASES[name](), full, tmp_path, whole=True)


@PARSERS
def test_sad_a_copy_in_pieces_inside_quotes_is_the_copy_at_once(full):
    """A copy's pieces may begin inside a quote's or an alert's box now (_cuttable) - never in a formula,
    never between a table's cells: what they hold together is what one piece of all of it holds."""
    from ui import markdown_view as MV

    text = "> [!NOTE]\n" + "> text $x^2$ and\n>\n> $$\n> \\frac{a}{b}\n> $$\n>\n> ```\n> c\n> ```\n>\n" * 400 \
        + "| a | b |\n|---|---|\n" + "".join(f"| {'x' * 50} {n} | {'y' * 50} |\n" for n in range(500))
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    view.load_rest_now()
    assert until(lambda: not view.more() and not view._scheduled, 240)
    document = view.browser.document()
    end = document.characterCount() - 1
    ranges = MV._copy_ranges(document, 0, end)
    assert len(ranges) > 3
    whole = MV._copy_text(document, 0, end)
    assert "".join(MV._copy_text(document, piece[1].position(), piece[2].position()) for piece in ranges) == whole
    assert whole.count("\\frac{a}{b}") == 400
    view.close()


def _ops_turns(text: str, full: bool, tmp_path, whole: bool = False) -> None:
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "page.md"
    page.write_text(text, encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.view.full = viewer.view.full and full
    viewer.resize(1000, 800)
    viewer.show()
    viewer.view.render(text)
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 240)
    if whole:  # (all of the page laid out, as when read to its end: every match there)
        viewer.view.load_rest_now()
        until(lambda: not viewer.view.more() and not viewer.view._scheduled, 240)
    else:
        until(lambda: not viewer.view._scheduled, 120)
    pump(0.2)
    turns = _Turns()
    viewer.find_field.setText("a")
    pump(0.3)
    for _ in range(3):
        viewer.find_next()
        pump(0.2)
    until(lambda: not viewer.view._scheduled, 120)
    found = turns.stop()
    turns = _Turns()
    viewer.view.browser.selectAll()
    viewer.view.copy_selection()
    until(lambda: getattr(viewer.view, "_copy_job", None) is None, 240)
    pump(0.3)
    copied = turns.stop()
    if whole:
        TB.budget(max(found, copied) < turn_for(text), (found, copied))
        return
    turns = _Turns()
    target = str(tmp_path / "page.pdf")
    made = viewer.export_pdf(target)
    pump(0.2)
    printed = turns.stop()
    assert made == target and os.path.getsize(target) > 0
    TB.budget(max(found, copied, printed) < turn_for(text), (found, copied, printed))


# -- F2 and F5: the editor's preview ------------------------------------------------------------------

def _preview(text: str):
    from ui.editor_window import EditorWindow

    window = EditorWindow()
    window.resize(1200, 700)
    window.show()
    tab = window.new_tab()
    tab.editor.setPlainText(text)
    tab.set_preview(True)
    assert until(lambda: tab.preview._readable and tab.preview.markdown, 120)
    pump(0.3)
    return window, tab


def _place_at(tab, line: int, back: int) -> None:
    """The editor's cursor *back* characters before the end of its *line*."""
    from PyQt6.QtGui import QTextCursor

    cursor = tab.editor.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    cursor.movePosition(QTextCursor.MoveOperation.Down, n=line)
    cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock)
    cursor.movePosition(QTextCursor.MoveOperation.Left, n=back)
    tab.editor.setTextCursor(cursor)


def _type_at(tab, line: int, back: int, typed: str) -> None:
    _place_at(tab, line, back)
    tab.editor.insertPlainText(typed)


@pytest.mark.parametrize("where", ["a table, row 2,000 of 3,000", "a code block, line 1,500 of 6,000"])
def test_sad_the_preview_follows_the_typing_inside_a_long_block(where):
    """The preview shows the text as it was a moment ago, then the typed one: the first page shown -
    of the text before the typing - took the place to follow, the typed one's page never followed it
    (a long table: the preview stayed rows away)."""
    if where.startswith("a table"):
        text, line, back = "# T\n\n| a | b |\n|---|---|\n" + "".join(f"| row {n} | cell {n} |\n"
                                                                  for n in range(3000)), 4 + 2000, 2
    else:
        text, line, back = "# C\n\n```\n" + "".join(f"code line {n}\n" for n in range(6000)) + "```\n", 3 + 1500, 0
    window, tab = _preview(text)
    try:
        _type_at(tab, line, back, " TYPEDHERE")
        preview = tab.preview

        def shown() -> bool:
            found = preview.browser.document().find("TYPEDHERE")
            if found.isNull():
                return False
            top = preview.browser.document().documentLayout().blockBoundingRect(found.block()).top()
            bar = preview.browser.verticalScrollBar()
            return bar.value() <= top <= bar.value() + preview.browser.viewport().height()

        assert until(shown, 60)
    finally:
        tab.editor.document().setModified(False)
        window.close()


def test_sad_the_preview_of_3000_code_blocks_holds_no_turn_while_typing():
    """0.34 s a pause in the typing: 3,000 code blocks one part."""
    window, tab = _preview("# T\n\n" + "```\ncode\n```\n\n" * 3000)
    try:
        turns = _Turns()
        for n in range(3):
            _type_at(tab, 2 + 4 * 1000 * n, 0, " typed")
            until(lambda: "typed" in tab.preview.markdown, 10)
            pump(0.2)
            until(lambda: tab.preview._readable and not tab.preview.timer.isActive()
                  and not tab.preview._scheduled, 60)
        longest = turns.stop()
        TB.budget(longest < TURN, longest)
    finally:
        tab.editor.document().setModified(False)
        window.close()


# -- the grid: container x inline kind x block repetition ---------------------------------------------

INLINE = {
    "image": lambda: "![i](x.png) " * 8000,
    "maths": lambda: "$a$ " * 30000,
    "code span": lambda: "`a` " * 30000,
    "emoji": lambda: "\U0001F389 " * 50000,
    "link": lambda: "[a](https://e.com) " * 8000,
    "entity": lambda: "&amp; &copy; " * 30000,
    "raw html span": lambda: "<b>a</b> " * 20000,
    "footnote ref": lambda: "x[^1] " * 20000,
    "plain words": lambda: "word " * 150000,
}
BLOCKS = {
    "many fences": lambda: ["```", "a", "```", ""] * 20000,
    "many rules": lambda: ["---", ""] * 50000,
    "many tables": lambda: ["| a | b |", "|---|---|", "| 1 | 2 |", ""] * 10000,
    "many long cells": lambda: ["| a | b |", "|---|---|"] + [f"| {'x' * 1800} | {'y' * 1800} |"] * 300 + [""],
    "one long formula": lambda: ["$$", "a+" * 40000 + "b", "$$", ""],
}


def _prefixed(lines: list[str], first: str, rest: str) -> list[str]:
    return [(first if n == 0 else rest) + line if line or rest.strip() else rest.rstrip()
            for n, line in enumerate(lines)]


GRID_CONTAINERS = {
    "top": lambda run, blocks: [run, ""] + blocks,
    "quote": lambda run, blocks: _prefixed([run, ""] + blocks, "> ", "> "),
    "list item": lambda run, blocks: _prefixed([run, ""] + blocks, "- ", "  "),
    "alert": lambda run, blocks: ["> [!NOTE]"] + _prefixed([run, ""] + blocks, "> ", "> "),
    "footnote": lambda run, blocks: ["x[^n]", ""] + _prefixed([run, ""] + blocks, "[^n]: ", "    "),
    "details": lambda run, blocks: ["<details open><summary>S</summary>", "", run, ""] + blocks + ["</details>"],
    "table cell": lambda run, blocks: ["| h | g |", "|---|---|", f"| {run} | x |", ""] + blocks,
    "heading": lambda run, blocks: ["# " + run, ""] + blocks,
    "link text": lambda run, blocks: ["[" + run + "](https://e.com)", ""] + blocks,
    "emphasis": lambda run, blocks: ["*" + run + "*", ""] + blocks,
    "strike": lambda run, blocks: ["~~" + run + "~~", ""] + blocks,
}
GRID = [(c, i, b) for c in GRID_CONTAINERS for i in INLINE for b in BLOCKS]
#: The sample's seed: AXROSS_STRESS_SEED (another sample, reproducible by it), else a fixed one - every run
#: the same sample (the day's seed made a test pass one day and fail the next with no change; the whole grid
#: is test_slow_the_whole_grid_holds_no_turn's).
SEED = int(os.environ.get("AXROSS_STRESS_SEED") or 0)
#: The cells the preview's test takes whatever the seed: typing at the end of a line of 390,000 characters
#: (the link text of 30,000 entities) - Qt lays out a whole line again at each edit (typed_turn_for).
PREVIEW_CELLS = [("link text", "entity", "many rules")]
#: Documents of the grid a run opens (both parsers each).
SAMPLE = int(os.environ.get("AXROSS_STRESS_SAMPLE") or 6)


def grid_document(container: str, inline: str, blocks: str) -> str:
    """The grid's document: a paragraph of *inline* repeated, then *blocks* - both in *container*
    (a table's cell, a heading, a link's text, emphasis, a strike: the paragraph in it, the blocks after)."""
    lines = GRID_CONTAINERS[container](INLINE[inline]().strip(), BLOCKS[blocks]())
    return "\n".join(lines) + "\n" + ("\n[^1]: The note.\n" if inline == "footnote ref" else "")


def _sampled(count: int, always=()) -> list:
    sample = random.Random(SEED).sample(GRID, count)
    return sample + [cell for cell in always if cell not in sample]


#: What a bare QPlainTextEdit took here to take a typed word at the end of a line and paint it (by length).
_EDITED: dict = {}
#: A typed line at least this long gets Qt's own cost on top of its budget (typed_turn_for).
LONG_LINE = 100_000


def typed_turn_for(text: str, line: int) -> float:
    """turn_for(*text*) - and for typing at the end of a long *line* of it, on top of it what Qt itself takes
    for that in a bare QPlainTextEdit (no colours, no preview, no line numbers): Qt lays out and shapes the
    whole of a block again at each edit, then paints it - 0.10 s for a line of 390,000 characters here (the
    editor's own turn was 0.11 to 0.115 s), whatever the editor does. At most TURN more."""
    from PyQt6.QtGui import QTextCursor
    from PyQt6.QtWidgets import QPlainTextEdit

    row = text.split("\n", line + 1)[line]
    if len(row) < LONG_LINE:
        return turn_for(text)
    if len(row) not in _EDITED:
        editor = QPlainTextEdit()
        editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        editor.resize(600, 700)
        editor.show()
        editor.setPlainText(row)
        pump(0.3)
        took = []
        for _ in range(3):
            cursor = editor.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            editor.setTextCursor(cursor)
            began = time.thread_time()
            editor.insertPlainText(" typed")
            QApplication.processEvents()
            took.append(time.thread_time() - began)
            pump(0.1)
        editor.document().setModified(False)
        editor.close()
        editor.deleteLater()
        _EDITED[len(row)] = min(took)
    return turn_for(text) + min(_EDITED[len(row)], TURN)


@PARSERS
@pytest.mark.parametrize("cell", _sampled(SAMPLE), ids=lambda cell: "/".join(cell))
def test_sad_a_sample_of_the_grid_holds_no_turn(cell, full):
    """A seeded sample of the grid (the seed in the test's id's run: AXROSS_STRESS_SEED reruns it)."""
    text = grid_document(*cell)
    within_turn(lambda: _longest_turn(text, full), text, (SEED, cell))


@pytest.mark.parametrize("cell", _sampled(2, PREVIEW_CELLS), ids=lambda cell: "/".join(cell))
def test_sad_find_copy_pdf_and_the_preview_of_the_grid_hold_no_turn(cell, tmp_path):
    text = grid_document(*cell)
    _ops_turns(text, True, tmp_path)
    window, tab = _preview(text)
    try:
        # (the cursor where the typing goes first, as a user's is: the test's own move to a line's end, the
        # first one laid out there, was 0.03 s of the measured turn)
        _place_at(tab, 0, 0)
        pump(0.2)
        turns = _Turns()
        tab.editor.insertPlainText(" typed")
        until(lambda: "typed" in tab.preview.markdown, 10)
        pump(0.2)
        until(lambda: tab.preview._readable and not tab.preview.timer.isActive() and not tab.preview._scheduled, 120)
        longest = turns.stop()
        TB.budget(longest < typed_turn_for(text, 0), (SEED, cell, longest, typed_turn_for(text, 0)))
    finally:
        tab.editor.document().setModified(False)
        window.close()


@pytest.mark.skipif(not os.environ.get("AXROSS_SLOW"), reason="the whole grid: AXROSS_SLOW=1 (about an hour)")
@PARSERS
@pytest.mark.parametrize("cell", GRID, ids=lambda cell: "/".join(cell))
def test_slow_the_whole_grid_holds_no_turn(cell, full):
    text = grid_document(*cell)
    longest = _longest_turn(text, full)
    TB.budget(longest < turn_for(text), (cell, longest))


# -- the small things --------------------------------------------------------------------------------

def test_sad_a_missing_file_is_said_in_words(tmp_path):
    """"[Errno 2] No such file or directory: '/…/gone.md'" - the path twice, the system's words."""
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "gone.md"))
    viewer.show()
    assert TB.until_within(until, lambda: "gone.md" in viewer.view.browser.toPlainText(), 30)
    shown = viewer.view.browser.toPlainText()
    assert "it does not exist" in shown and "Errno" not in shown and str(tmp_path) not in shown, shown
    assert "Errno" not in viewer.view.status.text()


def test_sad_a_folder_given_opens_its_readme(tmp_path):
    from core import markdown_cli
    from ui import markdown_app

    (tmp_path / "README.md").write_text("# The folder's page\n", encoding="utf-8")
    app = markdown_app.MarkdownApp()
    viewer = app.open_paths([str(tmp_path)])[0]
    assert viewer.path == str(tmp_path / "README.md")
    assert TB.until_within(until, lambda: "The folder's page" in viewer.view.browser.toPlainText(), 30)
    text, why = markdown_cli._read(str(tmp_path))
    assert why == "" and "The folder's page" in text
    empty = tmp_path / "empty"
    empty.mkdir()
    assert markdown_cli._read(str(empty)) == ("", "a folder without a README")


def test_sad_a_cp1252_console_gets_ascii_boxes_not_question_marks():
    import codecs

    from core import markdown_cli

    markdown_cli._register_ascii()
    codecs.lookup_error(markdown_cli.ASCII_ERRORS)
    shown = "┌──┬──┐ │a │b │ └──┴──┘ ━━━ █▀▄ ✓ ☃".encode("cp1252", markdown_cli.ASCII_ERRORS).decode("cp1252")
    assert shown == "+--+--+ |a |b | +--+--+ --- ### v ?", shown


def test_sad_zoom_reaches_25_and_400_percent_exactly():
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.show()
    view.render("# Zoom\n\nText.\n")
    assert until(lambda: view._readable, TB.READY_SECONDS)
    for _ in range(80):
        view.zoom_by(-1)
    assert view.zoom_percent() == 25
    for _ in range(200):
        view.zoom_by(1)
    assert view.zoom_percent() == 400
    view.zoom_by(0)
    assert view.zoom_percent() == 100 and view.zoom == 0


def test_sad_a_run_of_three_tildes_in_a_line_stays_as_written():
    from core import markdown_doc as MD
    from ui import markdown_html as H

    page = H.to_html(MD.parse("a ~~~x~~~ b, ~~y~~ and ~z~\n"))
    assert "~~~x~~~" in page and "<s>y</s>" in page and "<s>z</s>" in page


@PARSERS
def test_sad_an_alert_in_a_list_or_a_quote_is_a_quote(full):
    """GitHub: alerts cannot be nested - in a list, in a quote, it is a quote saying "[!NOTE]"."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.show()
    view.render("- item\n\n  > [!NOTE]\n  > nested\n\n> > [!TIP]\n> > deeper\n\n> [!WARNING]\n> top\n")
    assert until(lambda: view._readable, TB.READY_SECONDS)
    shown = view.browser.toPlainText()
    assert "[!NOTE]" in shown and "[!TIP]" in shown and "[!WARNING]" not in shown, shown


# -- v0.16.7's CI: Ubuntu's colour emoji font, a bitmap one (67 µs an emoji at each layout and paint) ---------

def test_sad_qt_s_own_parser_weighs_an_emoji_in_a_part_too():
    """A part of Qt's own parser was 2,250 characters - 1,080 emoji, 0.17 s an insert with that font."""
    from ui import markdown_html as H
    from ui import markdown_view as MV

    for text in ("\U0001F389 " * 50_000 + "\n", ":tada: " * 50_000 + "\n",
                 # (in a quote, a list item: their pieces were of 6,000 characters - 3,000 emoji, 1 s a part)
                 "> " + "\U0001F389 " * 50_000 + "\n", "- " + "\U0001F389 " * 50_000 + "\n"):
        parts = MV._md4c_page(text)[0]
        assert max(part.count("\U0001F389") for part in parts) * H.PICTURE_WEIGHT <= 2 * MV.PART_CHARS, text[:3]


def test_sad_a_heading_or_a_cell_of_emoji_is_cut_by_their_weight():
    """A heading of 900 emoji (under LINE_CAP characters) was 0.4 s to lay out with a colour emoji font of
    bitmaps, a table cell of them 0.8 s: an emoji counts PICTURE_WEIGHT letters against LINE_CAP."""
    from ui import markdown_html as H
    from ui import markdown_view as MV

    limit = MV.LINE_CAP // H.PICTURE_WEIGHT + 1
    shown, why = MV.renderable("# " + "\U0001F389 " * 900 + "\n\ntext\n")
    assert 0 < shown.count("\U0001F389") <= limit and "…" in shown and str(MV.LINE_CAP) in why
    cell = MV.renderable("| h | g |\n|---|---|\n| " + "\U0001F389 " * 900 + " | x |\n")[0]
    assert 0 < cell.count("\U0001F389") <= limit and "| x |" in cell
    few = "# " + "\U0001F389 " * 10 + "\n"
    assert MV.renderable(few)[0] == few


def test_sad_the_scroll_bar_stays_while_parts_are_to_come():
    """Hidden when a stand-in was taken out, shown when it was put back - while the page was shorter than the
    view: the view as wide again each time, and Qt laid all of the page out anew, twice a part (0.19 s a
    turn with that font)."""
    from PyQt6.QtCore import Qt

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    seen = []
    view.browser.verticalScrollBar().rangeChanged.connect(
        lambda *_: seen.append((view._stand_in, view.browser.verticalScrollBar().isVisible())))
    view.render("word " * 40 + "\n\n" + "".join(f"Paragraph {n} " + "text " * 30 + "\n\n" for n in range(3000)))
    assert until(lambda: view._readable and view.markdown, 120)
    assert view._stand_in and view.browser.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOn
    assert all(visible for stand_in, visible in seen if stand_in), seen
    view.load_rest_now()
    assert until(lambda: view._rest is None and not view._gaps and not view._scheduled, 120)
    pump(0.2)
    assert view.browser.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded
    view.close()
