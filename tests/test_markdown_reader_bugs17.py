"""The seventeenth round of the Markdown reader (the sixteenth review): a big
block stays where it belongs - in a list item, a quote, an alert, a
definition, a note - and is laid out a part at a time (the part cut inside
its containers, the next begun in them going on), raw HTML's big blocks
too, a line of thousands of formulas in a heading or a cell; quotes after
a list's marker; code in a quote never changed; Qt's own parser's code
spans and "$$ … $$"; TeX's common forms. Times are the GUI thread's own
(time.thread_time). Each test failed before.
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

from PyQt6.QtCore import QPoint, QTimer  # noqa: E402
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


class Turns:
    """The GUI thread's own time of each event-loop turn while it runs."""

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


def _view(text: str, full: bool, size=(1000, 800)):
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


def _copied(view) -> list[str]:
    APP.clipboard().setText("EMPTY")
    view.browser.select_all()
    view.copy_selection()
    assert until(lambda: APP.clipboard().text() != "EMPTY", 120)
    return [line.rstrip() for line in APP.clipboard().text().splitlines() if line.strip()]


# -- (G6) every container x every big block x both parsers: never a hold-up, nothing lost ------------

def _in(container: str, lines: list[str]) -> str:
    """*lines* (a block) inside *container*, with text before and after it."""
    def prefixed(prefix: str, blank: str = "") -> str:
        return "".join((prefix + line if line else blank) + "\n" for line in lines)

    return {
        "top": "Intro.\n\n" + prefixed("") + "\nAfter the block.\n",
        "quote": "> Intro.\n>\n" + prefixed("> ", ">") + ">\n> After the block.\n",
        "item": "- intro\n\n" + prefixed("  ") + "\n  After the block.\n- next item\n",
        "tab_item": "-\tintro\n\n" + prefixed("\t") + "\n\tAfter the block.\n-\tnext item\n",
        "ordered": "1. one\n2. two\n\n" + prefixed("   ") + "\n   After the block.\n3. three\n",
        "quote_in_item": "- intro\n\n  > quoted\n  >\n" + prefixed("  > ", "  >") + "  >\n  > After the block.\n",
        "item_in_quote": "> - intro\n>\n" + prefixed(">   ", ">") + ">\n>   After the block.\n",
        "alert": "> [!NOTE]\n> Intro.\n>\n" + prefixed("> ", ">") + ">\n> After the block.\n",
        "definition": "Term\n:   Intro.\n\n" + prefixed("    ") + "\n    After the block.\n",
        "footnote": "Text[^n].\n\n[^n]: Intro.\n\n" + prefixed("    ") + "\n    After the block.\n",
    }[container]


BLOCKS = {
    "fence": lambda: ["```", *(f"line {n:05d} of the log" for n in range(6000)), "```"],
    "table": lambda: ["| a | b | c |", "|---|---|---|", *(f"| r{n} | v{n} | x |" for n in range(3000))],
    "formulas": lambda: [" ".join(f"w{n} $x_{{{n}}}^2$" for n in range(3000))],
    "html_table": lambda: ["<table>", *(f"<tr><td>r{n}</td><td>v{n}</td></tr>" for n in range(5000)), "</table>"],
    "html_list": lambda: ["<ul>", *(f"<li>item {n}</li>" for n in range(5000)), "</ul>"],
    "indented": lambda: [*(f"    code {n:05d}" for n in range(6000))],
}
LAST = {"fence": "line 05999", "table": "r2999", "formulas": "w2999", "html_table": "r4999",
        "html_list": "item 4999", "indented": "code 05999"}


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("kind", sorted(BLOCKS))
@pytest.mark.parametrize("container", ["top", "quote", "item", "tab_item", "ordered", "quote_in_item", "item_in_quote",
                                       "alert", "definition", "footnote"])
def test_guard_a_big_block_in_any_container_never_holds_up_the_window(container, kind, full):
    """The sixteenth review: a table in a quote in a list item (12.7 s), a fence under a definition
    (1.3 s), raw HTML's big tables and lists anywhere (6 s), a line of thousands of formulas in any
    container (36 s) - each shape escaped the text's splitting (a list item indented by tabs too). Now the page is cut inside its
    containers: the GUI thread's own time a turn stays under 0.25 s, every line of the block is there,
    and what follows the block stays where it belongs."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    turns = Turns()
    view.render(_in(container, BLOCKS[kind]()))
    assert until(lambda: view._readable and view.markdown, 120)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 60)
    view.go_end()
    pump(0.3)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 60)
    worst = turns.worst()
    assert worst < 0.25, (worst, sorted(turns.turns)[-4:])
    view.load_rest_now()
    until(lambda: not view.more(), 120)
    shown = view.browser.toPlainText()
    assert LAST[kind] in shown and "After the block." in shown
    assert "" not in shown  # (a going-on mark never shows)


# -- 4. a block cut in parts keeps its list item and the items after it as they are -------------------

ORDERED = ("1. one\n2. two\n   ```\n" + "".join(f"   line {n:04d} code\n" for n in range(3000))
           + "   ```\n   two continued\n3. three\n   - sub a\n     ```\n"
           + "".join(f"     sub {n:04d}\n" for n in range(1500)) + "     ```\n   - sub b\n4. four\n")


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_big_block_in_an_item_keeps_the_list_as_the_terminal_shows_it(full):
    """ordered.md, sub_fence.md: the block moved out of its item, items 3 and 4 ran into one paragraph,
    text became code, a sub-item went up a level. The block stays in its item now; the list's numbers,
    its sub-items and the item's text after the block are the terminal's."""
    from PyQt6.QtGui import QTextCursor

    view = _view(ORDERED, full)
    view.load_rest_now()
    until(lambda: not view.more(), 120)
    copied = [line for line in _copied(view) if "code" not in line and not line.lstrip().startswith("sub 0")
              and not line.lstrip().startswith("sub 1")]
    assert copied == ["1. one", "2. two", "two continued", "3. three", "  ◦ sub a", "  ◦ sub b", "4. four"], copied
    document = view.browser.document()
    continued = document.find("two continued").block()
    assert continued.textList() is None and continued.blockFormat().indent() + continued.blockFormat().leftMargin() > 0
    assert QTextCursor(document.find("line 2999").block()).block().text().startswith("line 2999")
    position = document.find("line 1500").position()
    code = view.code_block_at(position)
    assert code.startswith("line 0000 code\n") and code.rstrip("\n").endswith("line 2999 code"), code[-60:]


# -- 3. a line of thousands of formulas in a heading, a cell: the rest as TeX, said -----------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_formulas_past_a_headings_hundred_are_said_and_quick(full):
    """t/heading_math.md: 8,000 formulas in a heading held the window 3.3-11 s, said nothing."""
    turns = Turns()
    view = _view("# " + " ".join(f"w{n} $x_{{{n}}}^2$" for n in range(8000)) + "\n\nText.\n", full)
    assert turns.worst() < 0.6
    assert "TeX" in view.notice.text()
    assert "$x_{7999}^2$" in view.browser.toPlainText().replace("\\", "")


# -- 13. the notices say what they do --------------------------------------------------------------

def test_sad_a_flattened_quote_is_said_flatter_not_as_written():
    from ui import markdown_view as MV

    _text, why = MV.renderable("> " * 12 + "deep\n")
    assert why.startswith("Laid out flatter") and "as written" not in why


# -- 5, 6. quotes deeper than eight after a list's marker; code in a quote never changed -------------

def test_sad_a_deep_quote_after_a_lists_marker_is_shown_flatter_everywhere():
    """t/item_deepquote.md: "- " then 20,000 ">" escaped the limit (3.9 s; the terminal wrote 2.4 MB)."""
    from core import markdown_term as MT

    text = "- " + ">" * 20_000 + " deep\n"
    shown = MT._strip_ansi(MT.render(text, MT.Options(depth="none", width=80)))
    assert len(shown) < 2000 and "quotes nested more than 8" in shown
    for full in (True, False):
        turns = Turns()
        view = _view(text, full)
        assert turns.worst() < 0.25 and "deep" in view.browser.toPlainText()
        assert "flatter" in view.notice.text()


CODE_IN_QUOTE = ("> Example of a log:\n>\n> ```\n> >>>>>>>>>>>>>>>> BEGIN TRACE\n> <<<<<<<<<<<<<<<< END TRACE\n"
                 "> ```\n\n- in a list:\n\n  ```text\n  >>>>>>>>>>>>>>>>>>>> separator\n  ```\n")


def test_sad_quote_flatter_never_changes_code():
    """t/qflat_code.md: the ">" of a quote's code block were taken for quotes and cut."""
    from core import markdown_doc as MD

    assert MD.quote_flatter(CODE_IN_QUOTE) == (CODE_IN_QUOTE, False)
    deep = "> " * 10 + "```\n" + "> " * 10 + ">>>>>>>> code\n" + "> " * 10 + "```\n"
    flat, changed = MD.quote_flatter(deep)
    assert changed and ">>>>>>>> code" in flat and flat.count("\n") == 3


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_code_in_a_quote_shows_as_written(full):
    shown = _view(CODE_IN_QUOTE, full).browser.toPlainText()
    assert ">>>>>>>>>>>>>>>> BEGIN TRACE" in shown and ">>>>>>>>>>>>>>>>>>>> separator" in shown


# -- 7, 9. Qt's own parser: code spans kept apart; "$$ … $$" with spaces --------------------------

def test_sad_qts_own_parser_keeps_code_spans_beside_dollars_apart():
    """t/dollar_code.md: "`^v(\\d+)$` captures `$1`" became one code span (the $`…`$ formula's rewrite
    ran before the code spans were found)."""
    view = _view("The pattern `^v(\\d+)$` captures `$1` here.\n\nUse `a$` then `$b`.\n\nA $`x^2`$ B.\n", False)
    document = view.browser.document()
    codes, block = [], document.begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fragment = pieces.fragment()
            if fragment.charFormat().fontFixedPitch():
                codes.append(fragment.text())
            pieces += 1
        block = block.next()
    assert codes == ["^v(\\d+)$", "$1", "a$", "$b"], codes
    assert "A x2 B." in view.browser.toPlainText()


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_display_formula_with_spaces_inside_its_dollars(full):
    """t/dd_space.md: Qt's own parser left "$$ E = mc^2 $$" as written."""
    shown = _view("Energy: $$ E = mc^2 $$ done.\n\n$$ a+b $$\n", full).browser.toPlainText()
    assert "$" not in shown and "E = mc2" in shown.replace("\u2009", " ") and "a+b" in shown


# -- 8. TeX's common forms ------------------------------------------------------------------------

@pytest.mark.parametrize("tex, shown", [
    (r"\frac12", "1/2"), (r"\frac{1}2", "1/2"), (r"\dfrac12", "1/2"), (r"\frac{\frac12}{3}", "(1/2)/3"),
    (r"\sqrt5", "√5"), (r"\sqrt[3]8", "∛8"), (r"\bigcup_i A_i", "⋃ᵢ Aᵢ"), (r"\bigoplus", "⨁"),
    (r"\coprod", "∐"), (r"\lbrace x \rbrace", "{ x }"), (r"n \choose k", "C(n, k)"),
    (r"{n \choose k}", "C(n, k)"), (r"\operatorname*{argmax}_x f", "argmaxₓ f"), (r"\mathscr{L}", "ℒ"),
    (r"\ket{\psi}", "|ψ⟩"), (r"\bra{\phi}", "⟨ϕ|"), (r"n\log n", "n log n"), (r"2\sin x", "2 sin x"),
    (r"\vec v", "v⃗"), (r"\hat\theta", "θ̂"), (r"\overrightarrow{AB}", "A⃗B⃗"), (r"\binom12", "C(1, 2)"),
])
def test_sad_texs_common_forms_are_read(tex, shown):
    """vis/math2.md: \\frac12, \\sqrt5, \\bigcup, \\lbrace, \\choose, \\operatorname*, \\mathscr, \\ket ... showed
    as written; "n\\log n" read "nlog n"."""
    from core import markdown_doc as MD

    assert MD.math_text(tex) == shown


def test_sad_pmod_is_upright_and_a_display_stacks_frac12():
    import re

    from core import markdown_doc as MD
    from ui import markdown_html as H

    assert "<i>mod</i>" not in MD.math_html(r"a \pmod{p}")
    assert H.display_items(MD.math_normal(r"\frac12 + {n \choose k}")) == [
        ("frac", "1", "2"), ("text", " + "), ("binom", "n", "k")]
    laid = H.display_html(r"\frac12", H.colours(False))
    assert re.search(r"axross-tex:XGZyYWMxMg==", laid)  # (Copy: the TeX as written)


# -- 10, 12. a drag's text made when asked; a copy's status kept, a reload says it cancelled it -------

def test_sad_a_drag_makes_its_text_only_when_asked():
    """dragtime.py: createMimeDataFromSelection made the whole copy at once (1.4 s on manymath.md)."""
    text = " ".join(f"$x_{{{n}}}^2$" for n in range(6000)) + "\n"
    view = _view(text, True)
    view.load_rest_now()
    until(lambda: not view.more(), 120)
    view.browser.selectAll()
    began = time.thread_time()
    data = view.browser.createMimeDataFromSelection()
    assert time.thread_time() - began < 0.1
    assert "$x_{5999}^2$" in data.text()


def test_sad_a_reload_during_a_copy_says_the_copy_was_cancelled():
    view = _view(" ".join(f"$x_{{{n}}}^2$" for n in range(6000)) + "\n\n" + "para\n\n" * 3000, True)
    APP.clipboard().setText("SENTINEL")
    view.browser.select_all()
    view.copy_selection()
    pump(0.05)
    assert view.status.text().startswith("Copying")
    view.render(view.markdown)
    assert until(lambda: "cancelled" in view.status.text(), 30), view.status.text()


def test_sad_a_reload_during_a_copy_says_so_while_the_new_page_is_made():
    """manymath.md (one line of 60,000 formulas): a reload during its copy - the status read
    "Rendering…" with no word of the copy while the new page was made."""
    view = _view(" ".join(f"$x_{{{n}}}^2$" for n in range(60_000)), True)
    APP.clipboard().setText("SENTINEL")
    view.browser.select_all()
    view.copy_selection()
    pump(0.05)
    assert view.status.text().startswith("Copying")
    view.status.setText("")  # (as the viewer's reload does: "Reading…", then cleared)
    view.render(view.markdown)
    pump(0.3)
    assert "cancelled" in view.status.text(), view.status.text()
    assert APP.clipboard().text() == "SENTINEL"


# -- 11. Ctrl+End on a page of many small parts shows its end at once ------------------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_ctrl_end_shows_the_end_at_once(full):
    """headings.md (Qt's own parser): the view stayed blank 11 s after Ctrl+End - the parts' stand-in was
    taller than Qt lays out (8,388,607 pixels): nothing past it was laid out."""
    view = _view("".join(f"# H{n}\n" for n in range(100_000)), full)
    view.go_end()
    browser = view.browser

    def shown() -> str:
        return browser.cursorForPosition(QPoint(5, 5)).block().text()

    assert until(lambda: shown().startswith("H9999"), 5), shown()


# -- 14. the window keeps its least width ----------------------------------------------------------

def test_sad_the_viewer_keeps_its_least_width_once_shown(tmp_path):
    """minw.py: after it was shown the window went down to 120 pixels (ui.close_corner)."""
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MINIMUM_WIDTH, MarkdownViewerDialog

    page = tmp_path / "a.md"
    page.write_text("# A\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(page))
    dialog.show()
    pump(0.5)
    dialog.resize(200, 500)
    pump(0.3)
    assert dialog.minimumWidth() >= MINIMUM_WIDTH and dialog.width() >= MINIMUM_WIDTH


# -- 15. the terminal keeps quotes within a narrow width -------------------------------------------

@pytest.mark.parametrize("width", [20, 22, 30])
def test_sad_the_terminal_keeps_eight_deep_quotes_within_a_narrow_width(width):
    from core import markdown_doc as MD
    from core import markdown_term as MT

    text = "> " * 8 + "a quote that is long enough to wrap\n"
    shown = MT._strip_ansi(MT.render(text, MT.Options(depth="none", width=width)))
    assert max(MD.cell_width(line) for line in shown.splitlines()) <= width, shown


# -- 1 (after the end run): Qt's own parser - emphasis in a big table or list inside a quote ---------

@pytest.mark.parametrize("shape", ["table", "list"])
def test_sad_emphasis_in_a_big_table_in_a_quote_stays_emphasis(shape):
    """quote_table.md (Qt's own parser): past row 300 every "**y**" showed as written - the passes
    took the quoted table (no empty line in it) for one paragraph and escaped its emphasis past 300
    spans; a row, an item is a line of its own."""
    from ui import markdown_view as MV

    if shape == "table":
        text = "> | a | b |\n> |---|---|\n" + "".join(f"> | {n} | **y** |\n" for n in range(1200))
    else:
        text = "".join(f"> - item {n} **y**\n" for n in range(1200))
    view = _view(text + "\nafter\n", False)
    view.load_rest_now()
    assert until(lambda: not view.more(), 60)
    assert "**" not in view.browser.toPlainText()
    assert not MV._fewer_emphasis(text).count("\\*")


# -- 1 (after the end run): markdown-it - a big table in a quote in pieces of many rows, cut between rows

def test_sad_a_big_table_in_a_quote_is_cut_in_pieces_of_many_rows():
    """quote_table.md (markdown-it): every row of a big quoted table became a table of its own - its
    columns were counted over the whole table, not its first row - and a copy had an empty line
    between any two rows."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = "> | a | b |\n> |---|---|\n" + "".join(f"> | {n} | x{n} |\n" for n in range(1000))
    html = "".join(H.to_html_parts(MD.parse(text)))
    assert html.count("<table") < 10, html.count("<table")  # (pieces of 450 rows - and where a part ends)


def test_sad_a_part_never_ends_inside_a_tables_row():
    """quote_table.md (markdown-it): a part ended between two cells of a row of a quoted table - the
    next part's first row had four cells, a copy an empty line in every row after it."""
    import re

    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = "# T\n\n> | a | b | c |\n> |---|---|---|\n" + "".join(f"> | {n} | x{n} | **y** |\n" for n in range(3000))
    for part in H.to_html_parts(MD.parse(text)):
        for row in re.findall(r"<tr>((?:(?!<tr>|<table).)*?)</tr>", part, re.S):  # (the quote's box: a table too)
            assert len(re.findall(r"<t[dh][ >]", row)) == 3, row


def test_sad_a_list_of_thousands_of_notes_is_still_cut_between_its_notes():
    """footnotes.md (markdown-it): with parts cut only where the innermost container's level said so, the
    list of 3,000 notes (whose tokens' levels say nothing) was one part - 0.73 s in one turn."""
    from ui import markdown_view as MV

    text = "".join(f"Text[^{n}].\n\n" for n in range(3000)) + "".join(f"[^{n}]: note {n}\n\n" for n in range(3000))
    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    turns = Turns()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    view.go_end()
    pump(0.3)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 60)
    worst = turns.worst()
    assert worst < 0.25, (worst, sorted(turns.turns)[-4:])


def test_sad_a_long_note_in_pieces_has_one_way_back_and_is_cut_in_parts():
    """fndef_math.md (markdown-it): a note's last paragraph in pieces took the note's way back ("↩", the
    footnote_anchor before its end) for each piece's end - a way back after every piece, its own
    end left open: no part was cut inside the note again (3.6 s in one turn)."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = "Text[^1].\n\n[^1]: " + " ".join(f"word{n} $x_{{{n}}}^2$" for n in range(8000)) + "\n"
    tokens = H._paragraph_pieces(MD.parse(text).tokens)
    assert sum(t.type == "footnote_anchor" for t in tokens) == 1
    assert sum(t.nesting for t in tokens if t.type.startswith("paragraph")) == 0
    assert sum(t.type == "paragraph_open" for t in tokens) > 3


# -- the end run's export: "--html FILE | head" ----------------------------------------------------

def test_sad_html_export_into_a_pipe_closed_early_ends_quietly(tmp_path):
    """axross-markdown --html FILE | head: a BrokenPipeError traceback once head had its lines."""
    import subprocess

    page = tmp_path / "a.md"
    page.write_text("# A\n\n" + "para graph\n\n" * 20000, encoding="utf-8")
    run = subprocess.Popen([sys.executable, "-c", "import sys; from ui.markdown_app import export_html_main; "
                            "sys.exit(export_html_main([sys.argv[1]]))", str(page)],
                           cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run.stdout.read(100)
    run.stdout.close()
    error = run.stderr.read().decode()
    assert run.wait(60) in (0, 1) and "Traceback" not in error and "BrokenPipe" not in error, error


# -- the end run: a crash now and then while pages were made (in_background) ---------------------

def test_sad_a_workers_delivery_is_never_destroyed_on_the_worker_thread(monkeypatch):
    """Two full runs of the reader's tests crashed (SIGSEGV in a done() lambda): the QObject carrying a
    worker's result was held by the threading.Thread only - freed when the thread ended, on the worker
    thread, its queued signal still on its way to the GUI thread."""
    import gc
    import threading

    from PyQt6.QtCore import Qt
    from ui import markdown_view as MV

    threads, made = [], []
    original = MV._Delivery

    class Watched(original):
        def __init__(self):
            super().__init__()
            made.append(1)
            self.destroyed.connect(lambda *_: threads.append(threading.get_ident()),
                                   Qt.ConnectionType.DirectConnection)

    monkeypatch.setattr(MV, "_Delivery", Watched)
    got = []
    for _ in range(20):
        MV.in_background(lambda: time.sleep(0.05) or 1, lambda result, error: got.append(result))  # (no thread kept)
    deadline = time.monotonic() + 10
    while any(t.name == "markdown-view" for t in threading.enumerate()) and time.monotonic() < deadline:
        time.sleep(0.01)
    gc.collect()
    pump(0.3)
    gc.collect()
    pump(0.3)
    assert got == [1] * 20
    main = threading.main_thread().ident
    assert len(threads) == len(made) == 20 and all(ident == main for ident in threads), (threads, len(made))
    assert not MV._DELIVERIES
