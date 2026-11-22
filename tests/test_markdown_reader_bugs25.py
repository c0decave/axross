"""The twenty-fifth round of the Markdown reader (the twenty-fourth review, axross-markdown 0.16.10 at 7/10):
a heading pattern defined twice, the later one quadratic in runs of spaces (H1); fences never closed,
quadratic in Qt's own parser (H2); paragraphs never cut there when their lines begin with a space, a
tab, "#" or "+++" (H3); every part of an export alive to its end (M1); the emoji scan for every file
(M2); a table whose header has "\\|" shown as text (M3); a zoom's long turn (M4); workers that held
Python's lock (M5); and the small things (L1 to L3). With them what the sweep found
(tests/test_markdown_freeze_sweep.py): the space run pattern, a worker's garbage collections, Find's
marks painted wherever they are, an export's images laid out again for nothing, Qt's tables of
collapsed borders the slower the bigger, the outline's batches under a worker.

Each test here failed before.
"""

from __future__ import annotations

import ast
import gc
import ntpath
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests import markdown_heartbeat as HB  # noqa: E402
from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests.test_markdown_reader_bugs20 import _Turns  # noqa: E402
from tests.test_markdown_reader_bugs22 import (  # noqa: E402,F401 - _closed_after: the fixture, used by name
    PARSERS, _closed_after, _longest_turn, turn_for, within_turn)
from tests.test_markdown_reader_bugs24 import _opened, _shown_md4c, _viewer  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])

MODULES = ("core.markdown_cli", "core.markdown_doc", "core.markdown_term", "ui.markdown_app", "ui.markdown_html",
           "ui.markdown_safe", "ui.markdown_view", "ui.markdown_viewer")


def _quick(call, seconds: float) -> None:
    began = time.process_time()
    call()
    took = time.process_time() - began
    TB.budget(took < seconds * HB.machine_factor(), took)


# -- H1: one name, one pattern - and the outline's heading pattern linear -----------------------------------

def test_sad_no_name_of_the_reader_s_modules_is_defined_twice():
    """ui/markdown_view.py defined _ATX at line 767 (a heading's opening) and again at 6771 (the outline's
    heading pattern, quadratic): Python took the later one for _capped_lines too."""
    import importlib

    twice = []
    for name in MODULES:
        tree = ast.parse(Path(importlib.import_module(name).__file__).read_text(encoding="utf-8"))
        seen: dict = {}
        for node in tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                targets = [node.name]
            for target in targets:
                if target in seen:
                    twice.append((name, target, seen[target], node.lineno))
                seen[target] = node.lineno
    assert not twice, twice


def test_sad_a_heading_line_of_spaced_words_is_cut_at_once():
    """_capped_lines ran the outline's pattern on every line over LINE_CAP: "# " and words 999 spaces apart,
    400 KB, 3.8 s (2 MB: 18 s - one search, Python's lock held)."""
    from ui import markdown_view as MV

    for text in ("# " + ("a" + " " * 999) * 400, "# " + ("a" + "\t" * 999) * 400, "# a" + " " * 40000 + "b"):
        _quick(lambda: MV._capped_lines(text), 0.2)
        cut, count = MV._capped_lines(text)
        assert count == 1 and cut.startswith("# a") and len(cut) <= MV.LINE_CAP + 10, (count, len(cut))
    _quick(lambda: MV.part_headings("md4c", "# a" + " " * 40000 + "b\n"), 0.2)


def test_happy_the_outline_reads_a_heading_s_text_as_before():
    from ui import markdown_view as MV

    heads = MV.part_headings("md4c", "# One\n## Two ##\n### Three ###   \n#### a#\n# #\n#5 bolt\n####### x\n")
    assert [(level, text) for level, text, _anchor in heads] == [
        (1, "One"), (2, "Two"), (3, "Three"), (4, "a#"), (1, "")], heads


def test_sad_a_heading_of_spaced_words_freezes_no_window(tmp_path):
    """Before: 30 KB froze the window 0.30 s (tabs 0.37 s) though its turn read 0.04 s."""
    for text in ("# " + ("a" + " " * 999) * 30, "# " + ("a" + "\t" * 999) * 30):
        for full in (True, False):
            turn, gap = _opened(tmp_path, text, full)
            HB.assert_responsive(gap, ("H1", full))


# -- H2: fences never closed ------------------------------------------------------------------------------------

def test_sad_fences_never_closed_are_read_in_one_pass():
    """_FENCE_BLOCK looked for each opening line's end to the text's end: "```py" 4,000 times 1.5 s, 20,000
    times 24 to 32 s."""
    from ui import markdown_view as MV

    for text in ("```py\n" * 20000, "~~~x\n" * 30000, "````py\n```\n" * 20000, "> ```py\n" * 20000):
        _quick(lambda: MV._fenced_blocks(text), 0.3)
    assert MV._fenced_blocks("```py\n" * 3) == []


@pytest.mark.parametrize("text, wanted", [
    ("```py\nx = 1\n```\n", [("py", "", "x = 1\n")]),
    ("```py\na\n````\nb\n", [("py", "", "a\n")]),  # (a longer closing fence closes it)
    ("````py\na\n```\nb\n````\n", [("py", "", "a\n```\nb\n")]),  # (a shorter one does not)
    ("```py\n```js\nx\n```\n", [("py", "", "```js\nx\n")]),  # (an opening line inside is its text)
    ("> ```py\n> a\n> ```\n", [("py", "> ", "> a\n")]),  # (in a quote: its lead)
    ("```py\na\n~~~\n```\n", [("py", "", "a\n~~~\n")]),
    ("```py\n\n```\n```c\nint a;\n```\n", [("py", "", "\n"), ("c", "", "int a;\n")]),
    ("```py\nnever closed\n```js\nx\n```\n", [("py", "", "never closed\n```js\nx\n")]),
    ("```py\nnever closed\n~~~c\nx\n~~~\n", [("c", "", "x\n")]),
])
def test_happy_fenced_blocks_are_the_ones_the_pattern_found(text, wanted):
    from ui import markdown_view as MV

    assert MV._fenced_blocks(text) == wanted


def test_sad_fences_never_closed_freeze_no_window(tmp_path):
    """Before (Qt's own parser): "```py" 4,000 times, 24 KB, froze the window 1.6 s."""
    turn, gap = _opened(tmp_path, "```py\n" * 4000, False)
    HB.assert_responsive(gap, "H2")


# -- H3: every kind of paragraph cut ----------------------------------------------------------------------------

H3_CASES = {
    "after a space": " " + "word " * 40000,
    "after three spaces": "   " + "word " * 40000,
    "indented lines": "  word word word\n" * 12000,
    "a hashtag": "#tag " + "word " * 40000,
    "a shebang": "#!/bin/sh " + "a=b " * 50000,
    "seven #": "####### " + "word " * 40000,
    "a run of #": "#" * 99000,
    "# and a": ("#" + "a") * 49500,
    "lines of +++": "+++\n" * 50000,
}


@pytest.mark.parametrize("name", sorted(H3_CASES))
def test_sad_qt_s_own_parser_cuts_a_paragraph_whatever_its_lines_begin_with(name):
    """paragraph_pieces took a line with a space, a tab or "#" first, or "+++", for no paragraph's: never
    cut - 2 MB in one turn, 1.2 to 1.7 s."""
    from ui import markdown_view as MV

    shown = MV.paragraph_pieces(H3_CASES[name])
    assert shown.count(MV.JOINED) >= 5, name


def test_happy_what_is_no_paragraph_stays_whole():
    """An indented code block, a heading, a quote, a list item, a rule: never cut as a paragraph."""
    from ui import markdown_view as MV

    assert not MV._prose("    code", False) and MV._prose("    lazy", True)
    assert not MV._prose("# heading", False) and MV._prose("#tag", False) and MV._prose("####### x", False)
    assert not MV._prose("> quote", False) and not MV._prose("- item", False) and not MV._prose("---", False)
    assert MV._prose("+++", False) and MV._prose("  two spaces", False) and MV._prose("\tafter a tab", True)
    code = "    " + "code " * 4000
    assert MV.JOINED not in MV.paragraph_pieces(code)


@pytest.mark.parametrize("name", ["after a space", "a hashtag", "lines of +++"])
def test_sad_those_paragraphs_hold_no_turn(name):
    text = H3_CASES[name] * 5
    within_turn(lambda: _longest_turn(text, False), text, name)


# -- M1: an export's parts deleted as they are drawn -----------------------------------------------------------

def _sections(count: int) -> str:
    return "".join(f"## H{i}\n\nPara *{i}* with `code` and [link](#h{i}).\n\n- item\n- item\n\n> quote\n\n"
                   for i in range(count))


def _alive_parts(monkeypatch, viewer) -> list:
    """The part documents the view makes from now on, as made (sip.isdeleted tells which are gone)."""
    from ui import markdown_view as MV

    made = []
    part_document = viewer.view._part_document

    def recorded(*args, **kwargs):
        part = part_document(*args, **kwargs)
        made.append(part)
        return part

    monkeypatch.setattr(viewer.view, "_part_document", recorded)
    assert MV  # (the module the parts are its _PageCopy of)
    return made


def _alive(made: list) -> int:
    from PyQt6 import sip

    return sum(not sip.isdeleted(part) for part in made)


def _rss() -> int:
    with open("/proc/self/statm", encoding="ascii") as fh:
        return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


@PARSERS
def test_sad_export_pdf_keeps_one_part_document_alive_at_a_time(tmp_path, monkeypatch, full):
    """Every part's laid-out document was deleted later (deleteLater): 0.8 MB took 288 to 468 MiB at its
    peak, 4.3 MB 1 to 2 GB. Each is deleted once drawn: the peak bounded by a part."""
    if not os.path.exists("/proc/self/statm"):
        pytest.skip("no /proc")
    from ui import markdown_view as MV
    from ui import markdown_viewer as V

    viewer = _viewer(tmp_path, _sections(5000), full)
    made = _alive_parts(monkeypatch, viewer)
    alive, peak = [], [0]
    add = V._PagePrinter.add

    def counted(self, document):
        alive.append(_alive(made))
        peak[0] = max(peak[0], _rss())
        yield from add(self, document)

    monkeypatch.setattr(V._PagePrinter, "add", counted)
    gc.collect()
    before = _rss()
    assert viewer.export_pdf(str(tmp_path / "page.pdf"))
    assert len(alive) > 50 and max(alive) <= 2, (len(alive), max(alive))
    # (before: 5,000 sections +90 MiB (Qt's own parser), +174 MiB (markdown-it); now +3 and +72 - the rest is
    # the parsed page markdown-it's export holds)
    grown = (peak[0] - before) / 2 ** 20
    assert grown < (110 if full else 30), grown
    assert len(viewer.view.browser.findChildren(MV._PageCopy)) <= 1
    viewer.close()


def test_sad_export_html_of_qt_s_own_parser_keeps_no_part_document_either(tmp_path, monkeypatch):
    from ui import markdown_view as MV

    viewer = _viewer(tmp_path, _sections(1500), full=False)
    made = _alive_parts(monkeypatch, viewer)
    alive = []
    background = viewer._in_background  # (once the parts are made: made safe on a worker)
    monkeypatch.setattr(viewer, "_in_background", lambda *args: (alive.append(_alive(made)), background(*args))[1])
    assert viewer.export_html(str(tmp_path / "page.html"))
    assert len(made) > 20 and max(alive) <= 1, (len(made), alive)
    viewer.close()


# -- M2: the emoji scan only for a text with emoji ---------------------------------------------------------------

def test_sad_a_file_without_emoji_never_waits_for_the_emoji_scan(tmp_path, monkeypatch):
    """emoji_fonts ran for every window made (0.48 s of a three-line file's first view on a machine of 2,000
    fonts without an emoji font): now only for a text with an emoji or a short code - on the GUI thread
    still, asked by the worker that prepares a big one."""
    from ui import markdown_view as MV

    scans = []
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(MV, "emoji_fonts", lambda: (scans.append(threading.current_thread().name),
                                                    MV._EMOJI_DRAWN.append(None), MV._EMOJI_FAMILY.append("")))
    viewer = _viewer(tmp_path, "# Plain\n\nthree lines\n")
    assert scans == []
    viewer.close()
    assert not MV.wants_emoji("a: b, 10:30:45 :not_a_code: \u00e9\u00e8 \u2028")
    for text in ("hello :smile:", "a \U0001F600", "\u2764\ufe0f heart"):  # (0.16.12: "\u2764" alone is text - bugs26)
        assert MV.wants_emoji(text), text
    viewer = _viewer(tmp_path, "# Emoji\n\n" + "hello :smile: " * 400, name="emoji.md")  # (prepared on a worker)
    assert scans == ["MainThread"], scans
    viewer.close()


class _SlowMetrics:
    """QFontMetrics on a machine whose fallback fonts make each answer slow: 20 ms."""

    def __init__(self, _font):
        pass

    def inFontUcs4(self, _sign):  # noqa: N802 - Qt
        time.sleep(0.02)
        return False


def test_sad_the_emoji_scan_looks_at_the_clock_at_each_short_code(monkeypatch):
    """The deadline was looked at every 16 short codes (and after the families were listed): 0.31 s for a
    deadline of 0.25."""
    from PyQt6 import QtGui

    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui, "QFontMetrics", _SlowMetrics)
    began = time.monotonic()
    MV.emoji_fonts()
    TB.budget(time.monotonic() - began < MV.EMOJI_SCAN_SECONDS + 0.06, 'time.monotonic() - began < MV.EMOJI_SCAN_SECONDS + 0.06')
    assert MV._EMOJI_DRAWN == [frozenset()]


# -- M3: a table whose header holds an escaped bar ---------------------------------------------------------------

@pytest.mark.parametrize("text, cells", [
    ("| a\\|b | c |\n|---|---|\n| 1 | 2 |\n", 4),
    ("| f\\|oo  |\n| ------ |\n| b `\\|` az |\n| b **\\|** im |\n", 3),  # (GFM's example 200)
])
def test_sad_qt_s_own_parser_shows_a_header_with_an_escaped_bar_as_a_table(text, cells):
    """_cells counted an escaped "|" as a cell's end: the header had more cells than the delimiter row, the
    table was shown as text ("| a|b | c | |---|---|")."""
    from ui import markdown_view as MV

    assert MV._cells("| a\\|b | c |") == 2 and MV._cells("|a|b|") == 2 and MV._cells("a | b") == 2
    assert MV._cells("| a \\\\| b |") == 2 and MV._cells("| a \\| b |") == 1  # (an escaped backslash: the bar
    # ends a cell; an escaped bar does not)
    assert MV._cells("|---|---|") == 2 and MV._cells("| abc | def |") == 2
    view = _shown_table(text)
    assert view == cells, view


def _shown_table(text: str) -> int:
    from PyQt6.QtGui import QTextTable

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    until(lambda: not view._scheduled, 30)
    tables = [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]
    cells = sum(table.rows() * table.columns() for table in tables)
    view.close()
    return cells


# -- M4: a zoom on a page read to its end -------------------------------------------------------------------------

@PARSERS
def test_sad_a_zoom_on_a_page_of_100_000_headings_holds_no_turn(tmp_path, full):
    """The zoom's turn copied the page made whole (_fresh: 401,123 calls for 100,000 headings) - 0.16 to
    0.19 s. The copy is made on a worker."""
    text = "".join(f"{'#' * (i % 6 + 1)} h{i}\n" for i in range(100000))

    def measure() -> float:
        viewer = _viewer(tmp_path, text, full)
        view = viewer.view
        done = []
        view.load_rest(lambda: done.append(True))
        assert until(lambda: done, 300)
        pump(0.3)
        turns = _Turns()
        view.zoom_by(1)
        pump(0.1)
        until(lambda: view._readable and not view._scheduled, 120)
        pump(0.2)
        longest = turns.stop()
        assert view.zoom_percent() > 100
        viewer.close()
        return longest

    within_turn(measure, text, ("zoom", full))


# -- M5: workers that hold Python's lock -------------------------------------------------------------------------

def test_sad_a_page_is_made_safe_a_piece_at_a_time_as_it_was_whole():
    """safe_page's four passes ran over all of a page at once (47 MB of Qt's HTML: one search held Python's
    lock 0.33 s, 2.2 s under load). In pieces now - ended before a block's tag, never inside a tag."""
    from ui import markdown_html as H

    images = {"a.png": "data:image/png;base64,AAAA"}
    block = ('<p>Text <img src="a.png" alt="a"> and <img src="file:///etc/passwd" alt="x"> '
             '<a href="javascript:alert(1)">j</a> <a href="https://e.com">e</a> '
             '<a name="axross-itex:eA==">x</a><span style="line-height:7; -qt-line-height-type:fixed;">s</span>'
             '</p>\n')
    page = "<html><head></head><body>" + block * 3000 + "<pre>" + "code line\n" * 30000 + "</pre>\n" + block \
        + '<pre><img src="' + "x" * 300000 + '"></pre>' + "</body></html>"
    pieces = []
    whole = H.safe_page(page[:2 * H.BLOCKS_AT_ONCE - 1000], images)  # (a page that small: at once)
    assert H.by_blocks(lambda piece: pieces.append(len(piece)) or piece, page) == page
    assert len(pieces) > 4 and max(pieces) < 5 * H.BLOCKS_AT_ONCE + 300100
    made = H.safe_page(page, images)
    assert 'src="file:' not in made and 'href="javascript:' not in made and 'src="x' not in made
    assert made.count("data:image/png;base64,AAAA") == 3001 and "axross-itex" not in made
    assert "line-height:7px;" in made and whole.count("data:image/png") > 10


def test_sad_a_page_is_made_with_the_collector_held(monkeypatch):
    """A worker that made a big page (markdown-it's tokens: millions of objects) ran Python's full
    collections, 0.43 s each with Python's lock held - the window frozen 1.3 s while it was exported. A
    page's making holds the collector; a read on a worker (a slow server's) does not."""
    from ui import markdown_view as MV

    seen = []
    normal = gc.get_threshold()
    held = lambda: gc.get_threshold()[2] > 1_000_000  # noqa: E731 - (no full collection while it runs)
    real = MV.renderable
    monkeypatch.setattr(MV, "renderable", lambda *a, **k: (seen.append(held()), real(*a, **k))[1])
    view = MV.MarkdownView(None)
    view.render("# A page\n\n" + "word " * 2000)  # (made on a worker)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    view.close()
    MV.in_background(lambda: seen.append(("read", held())), lambda result, error: seen.append("done"))
    assert TB.until_within(until, lambda: "done" in seen, 10)
    assert seen[0] is True and ("read", False) in seen and gc.get_threshold() == normal, seen
    assert MV.held_while(held) is True and gc.get_threshold() == normal and gc.isenabled()


@PARSERS
def test_sad_export_html_of_a_big_page_keeps_the_window_answering(tmp_path, full):
    """Export HTML: 100,000 Python functions in one block (Qt's own parser: a gap of 0.33 s alone, 2.2 s
    under load), 10,000 sections (markdown-it: 0.27 s) - the page made safe in one pass, encoded and
    written on the GUI thread, the collector's full passes on the worker."""
    text = _sections(10000) if full else \
        "```python\n" + "".join(f"def f{n}(a):\n    return a + {n}\n" for n in range(100000)) + "```\n"
    viewer = _viewer(tmp_path, text, full)
    beat = HB.Heartbeat()
    target = str(tmp_path / "page.html")
    assert viewer.export_html(target) == target
    pump(0.1)
    _turn, gap = beat.stop()
    HB.assert_responsive(gap, ("export HTML", full))
    assert ("H9999" if full else "def f99999") in Path(target).read_text(encoding="utf-8")
    viewer.close()


# -- what the sweep found ---------------------------------------------------------------------------------------

def test_sad_the_space_run_pattern_looks_from_a_run_s_start_only():
    """_SPACE_RUN ("[spaces]{1001,}") was tried from each space of a run too short: 2 MB of words 999 spaces
    apart held Python's lock 1.1 s on the worker that prepares the page."""
    from ui import markdown_view as MV

    text = ("a" + " " * 999) * 200
    _quick(lambda: MV._SPACE_RUN.sub("", text), 0.05)
    assert MV._SPACE_RUN.sub(lambda m: m.group(0)[:3], "x" + " " * 1500 + "y" + "\u3000" * 1001 + "z") \
        == "x   y\u3000\u3000\u3000z"


def test_sad_find_sets_the_marks_near_the_view_only(tmp_path):
    """1,000 marks of matches were set on the page: Qt painted every one in every turn it painted - 0.13 s a
    turn on 20,000 lines of "!!! word". The ones near the view only, again as it scrolls."""
    from ui import markdown_viewer as V

    text = "!!! word\n" * 20000
    viewer = _viewer(tmp_path, text, full=False)
    viewer.find_field.setText("word")
    until(lambda: not viewer._find_timer.isActive(), 5)
    pump(0.1)
    shown = viewer.view.browser.extraSelections()
    assert 0 < len(shown) <= V.MARKS_SHOWN, len(shown)
    first = shown[0].cursor.selectionStart()
    bar = viewer.view.browser.verticalScrollBar()
    bar.setValue(bar.maximum() // 3)
    pump(0.1)
    again = viewer.view.browser.extraSelections()
    assert again and again[0].cursor.selectionStart() > first
    viewer.close()


def test_sad_an_export_lays_out_no_image_the_page_shows_already(tmp_path, monkeypatch):
    """_prepared handed the images it read to the page - one not found the page showed as not found
    already laid all of the page out again: 8,000 of it in a link, 0.054 s of the export's first turn
    (bugs22's F1 case: 0.104 s against 0.1)."""
    from ui import markdown_view as MV

    viewer = _viewer(tmp_path, "[" + "![i](x.png) " * 8000 + "](https://e.com)\n")
    pump(0.3)
    read = []
    monkeypatch.setattr(MV.MarkdownView, "images_read", lambda self, names, *a, **k: read.append(list(names)))
    assert viewer.export_pdf(str(tmp_path / "page.pdf"))
    assert read == [], read
    viewer.close()


def test_sad_a_big_table_s_parts_are_the_smaller_the_bigger_it_is():
    """Qt lays out a part of a table with collapsed borders the slower the more of the table is laid out
    before it: 300 rows a part took 0.026 s at the table's start, 0.088 s at its 20,000th row (load_rest's
    turn 0.115 s)."""
    from ui import markdown_view as MV

    small = MV.renderable("| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 1000)[0]
    big = MV.renderable("| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 20000)[0]
    rows_small, rows_big = 1000 / (small.count(MV.CHUNK) + 1), 20000 / (big.count(MV.CHUNK) + 1)
    assert rows_big < rows_small / 1.5 and rows_big < 200, (rows_small, rows_big)
    # (before: 67 parts of 300 rows, a small table's parts as big)


@PARSERS
def test_sad_reading_a_table_of_20_000_rows_to_its_end_holds_no_turn(full):
    """L3: load_rest on a table of 20,000 rows - a turn of 0.115 s (markdown-it), 0.104 s (Qt's own)."""
    from ui import markdown_view as MV

    text = "| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 20000

    def measure() -> float:
        view = MV.MarkdownView(None)
        view.full = view.full and full
        view.resize(1000, 800)
        view.show()
        view.render(text)
        assert until(lambda: view._readable and view.markdown, 120)
        until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 120)
        pump(0.2)
        turns = _Turns()
        done = []
        view.load_rest(lambda: done.append(True))
        assert until(lambda: done, 240)
        pump(0.2)
        longest = turns.stop()
        view.close()
        return longest

    within_turn(measure, text, ("load_rest", full))


@PARSERS
def test_sad_copying_30_000_formulas_holds_no_turn(full):
    """L3: select-all and Copy on 30,000 inline formulas: 0.154 s (Qt's own) and 0.167 s (markdown-it) - two
    pieces of 8,000 characters a turn, each block's text read again for each formula in it."""
    from ui import markdown_view as MV

    text = "$a^2$ " * 30000

    def measure() -> float:
        view = MV.MarkdownView(None)
        view.full = view.full and full
        view.resize(1000, 800)
        view.show()
        view.render(text)
        assert until(lambda: view._readable and view.markdown, 120)
        until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 120)
        pump(0.2)
        turns = _Turns()
        view.browser.selectAll()
        view.copy_selection()
        assert until(lambda: getattr(view, "_copy_job", None) is None, 240)
        pump(0.2)
        longest = turns.stop()
        assert APP.clipboard().text().count("$a^2$") >= 1000
        view.close()
        return longest

    within_turn(measure, text, ("copy", full))


def test_sad_the_outline_s_batches_end_in_time():
    """_outline_on made 2,000 entries a turn whatever they took: with a worker beside it (an export's parts
    made) it held the window 0.2 s. It stops after OUTLINE_SECONDS too."""
    from ui import markdown_view as MV

    assert MV.OUTLINE_SECONDS <= 0.05
    source = Path(MV.__file__).read_text(encoding="utf-8")
    body = source[source.index("    def _outline_on(self)"):source.index("    def read_outline(")]
    assert "OUTLINE_SECONDS" in body and "time.monotonic()" in body


# -- more of the sweep's: each shape it froze the window with ------------------------------------------------------

def test_sad_a_backtick_fence_with_a_backtick_after_it_is_no_fence_and_its_text_is_cut():
    """"```py" and "a`" 15,000 times: CommonMark reads no fence (a backtick in its info) but a paragraph
    of code spans - the passes took all of it for code, never cut, and an unclosed run of backticks for a
    code span to its end: 30 KB in one block, 1.4 s in one turn."""
    from ui import markdown_view as MV

    assert MV.FENCE.match("```py`a") is None and MV.FENCE.match("```py") and MV.FENCE.match("~~~py`a")
    text = "```py" + "a`" * 15000
    assert len(MV._md4c_page(text)[0]) > 1
    assert MV._pieces_of("```" + "a`" * 15000).count(MV.JOINED) > 3


def test_sad_a_word_without_spaces_is_laid_out_in_pieces_of_a_thousand():
    """A word longer than a line is laid out by Qt letter by letter, its block again at each change to it:
    3,000 to 12,000 letters a piece (in a list item, a quote) held a turn 0.11 to 0.14 s."""
    from ui import markdown_view as MV

    pieces = MV._pieces_of("a" * 30000).split("\n\n" + MV.JOINED)
    assert len(pieces) >= 25 and max(map(len, pieces)) <= 2 * MV.WORD_PIECE, (len(pieces), max(map(len, pieces)))
    parts = MV._page("+ " + "&" * 30000, False)[0]
    longest = max(len(paragraph) for part in parts for paragraph in part.split("<p")) / len("&amp;")
    assert longest < 2.5 * MV.WORD_PIECE, longest


def test_sad_a_long_code_span_without_a_space_is_in_pieces_of_a_thousand_too():
    """A code span of letters and no-break spaces (no place to break a line) was cut in spans of 6,000 one
    after another - one word to Qt, laid out letter by letter: 0.18 s a zoom's turn (markdown-it)."""
    import re as regex

    from ui import markdown_view as MV

    parts = MV._page("> - *[`" + "a\xa0" * 20000 + "`](u)*", False)[0]
    spans = [len(span) for part in parts for span in regex.findall(r"<code[^>]*>(.*?)</code>", part, regex.S)]
    paragraphs = [paragraph.count("a") for part in parts for paragraph in part.split("<p")]
    assert len(spans) > 30 and max(paragraphs) <= 2 * MV.WORD_PIECE, (len(spans), max(paragraphs))


def test_sad_a_list_of_a_few_hundred_items_is_cut_and_few_long_lines_too():
    """A list of 2,700 items was one part (renderable cut lists from 3,000 lines of text only: 0.18 s), and
    a text of 20 lines of 1,500 characters too (markdown_parts: one part when it has few lines)."""
    from ui import markdown_view as MV

    listed = MV.renderable("- item word\n" * 2700)[0]
    assert listed.count("\u200b") >= 5
    assert len(MV.markdown_parts("\n\n".join(["word " * 300] * 20), first=22)) > 1


def test_sad_unicode_s_separators_and_bidi_marks_are_no_lines_for_qt():
    """U+2028 and U+2029 are a line and a paragraph of their own to Qt (30,000 in a row: 0.75 s in one
    part); ALM, LRM, RLM a direction each (15,000 in a code line: 0.45 s)."""
    from core import markdown_doc as MD

    assert MD.clean("a\u2028b\u2029c") == "a b c"
    assert MD.clean("a\u200eb\u200fc\u061cd") == "abcd"


def test_sad_the_ogham_space_mark_and_code_weigh_by_their_letters():
    """The Ogham space mark - the one space a font draws, no font of most machines has it - laid out a
    code box of 30 KB in 0.3 s: a picture sign's weight; a code block's box and bands are weighed by their
    letters, and so is its part (markdown-it's page)."""
    from ui import markdown_html as H
    from ui import markdown_view as MV

    assert H._PICTURE_SIGNS.search("\u1680") and H._weighed("\u1680" * 10) == 10 * H.picture_weight()
    rows = ["```", *(("a\u1680" * 1000) for _ in range(15)), "```"]
    assert MV._code_lines(rows, 0, "```") > MV.BOX_BLOCKS
    from core import markdown_doc as MD

    fence = next(token for token in MD.parse("```\n" + "x" * 5000 + "\n```\n").tokens if token.type == "fence")
    assert H._weight(fence, 200) > 20  # (a line of 5,000 letters: more than a block)
    assert MV.PRINT_BLOCKS == MV.PART_BLOCKS  # (an export's parts as the page's: twice them were 0.1 s)


@pytest.mark.parametrize("sign", ["\u0600", "\u06dd", "\u070f", "\u08e2", "\u180e", "\ufff9", "\U000110bd",
                                  "\U000110cd", "\U00013430", "\U0001bca0", "\U0001d173"])
def test_sad_format_signs_qt_shapes_dearly_weigh_as_pictures(sign):
    """The sweep's: "a" and a prepended concatenation mark (Arabic's number sign, Kaithi's), the Mongolian
    vowel separator, a hieroglyphs' format control... 15,000 times in 30 KB - one piece of 3,000 of them
    took Qt 0.4 to 0.8 s to lay out. They weigh as an emoji does."""
    from ui import markdown_html as H

    assert H._PICTURE_SIGNS.search(sign)
    assert not H._PICTURE_SIGNS.search("a\u00e9\u4e2d\u200d")


def test_sad_a_run_of_format_signs_is_no_one_character_no_cut_goes_into():
    """The sweep's re-measure: "> " and U+1BCA0 (a shorthand format control) 30,000 times on one line - a
    format sign belonged to the character before it (cluster_end), so the run was one character of 30,000
    that no piece cut: one part, 0.4 s laid out at once. A character holds CLUSTER_MARKS at most."""
    from core import markdown_doc as MD
    from ui import markdown_view as MV

    assert MD.cluster_end("\U0001bca0" * 1000, 0) <= MD.CLUSTER_MARKS
    assert MD.cluster_end("e\u0301\u0302x", 0) == 3 and MD.cluster_end("\U0001F469\u200d\U0001F4BB!", 0) == 3
    for sign in ("\U0001bca0", "\u0600", "\U00013430"):
        for lead in ("> ", "", "- "):
            parts = MV._md4c_page(lead + sign * 29998)[0]
            assert len(parts) > 10 and max(map(len, parts)) < 2000, (sign, lead, len(parts))
    text = "> - *[`" + "\U00013430" * 29987 + "`](u)*"  # (the sweep's "nested" line)
    for full in (True, False):
        within_turn(lambda: _longest_turn(text, full), text, ("U+13430 nested", full))


def test_sad_find_while_the_rest_of_a_page_is_parsed_waits_little_for_python_s_lock(tmp_path):
    """The sweep's "=" 300,000 lines (150,000 headings, markdown-it): Find while a worker parsed the rest -
    a turn of 0.035 s, a gap of 0.15 to 0.2 s: the GUI thread waited for the lock 1 ms at each of its calls
    into Python. It is handed on every 0.3 ms now."""
    from tests import test_markdown_freeze_sweep as S
    from ui import markdown_view as MV

    assert MV.WORKER_SWITCH_SECONDS <= 0.0003
    measured = S.run_case("=\n" * 300000, True, tmp_path, ("open", "find"))["find"]
    TB.budget(max(measured["gap"], measured["hold"]) < HB.gap_budget(),
              ("Find's gap", measured, f"at most {HB.gap_budget():.3f} s"), error=HB.Frozen)


def test_sad_a_paragraph_of_kaithi_number_signs_holds_no_turn():
    text = "a " + "a\U000110bd" * 15000 + " b"
    within_turn(lambda: _longest_turn(text, True), text, "U+110BD")


def test_sad_a_container_s_paragraph_of_spans_is_in_smaller_parts():
    """"- " and "a*" 15,000 times: an item's paragraph of emphasis, its pieces grouped by their letters - 2,400
    spans a part, each change Qt made to it 0.1 s (a turn of 0.12 to 0.14 s). A span's marks weigh more."""
    from ui import markdown_view as MV

    for text in ("- " + "a*" * 15000, "> " + "a*" * 15000):
        parts = MV._md4c_page(text)[0]
        assert max(part.count("*") for part in parts) < 2000, (text[:2], max(part.count("*") for part in parts))


def test_sad_a_line_of_backticks_and_more_is_the_code_s_not_its_end():
    """"```" over a line of 30,000 backticks and an "x" (the preview after a key typed): the passes took the
    line for the block's end - CommonMark's end has nothing after its fence - and never cut it, 0.2 s."""
    from ui import markdown_view as MV

    assert not MV._closes(MV.FENCE.match("````x"), "```") and MV._closes(MV.FENCE.match("````  "), "```")
    assert not MV._closes(MV.FENCE.match("``"), "```") if MV.FENCE.match("``") else True
    cut, _ = MV._capped_lines("```\n" + "`" * 30000 + "x\n")
    assert max(map(len, cut.split("\n"))) <= MV.LINE_CAP


def test_sad_a_link_of_an_address_of_thirty_thousand_characters_is_text():
    """"[a](" and "a\\" 15,000 times ")": a link whose address no cut goes into - Qt's own parser took 0.4 s
    for it in one turn. An address over ADDRESS_CHARS: the link as written."""
    from ui import markdown_view as MV

    assert MV.fallback_text("[a](" + "a\\" * 15000 + ")").startswith("[a\\](")
    assert MV.fallback_text("[a](https://e.com/x)") == "[a](https://e.com/x)"


def test_sad_long_code_lines_are_cut_in_any_code_block():
    """A code line of 30 KB of ">" was quote marks to the line cutter, never cut (0.2 s); an indented code
    block's line was not cut at all, and the block never cut in parts (30 KB of "<": 0.2 s)."""
    from ui import markdown_view as MV

    fenced, _ = MV._capped_lines("```\n" + ">" * 30000 + "\n```\n")
    assert max(map(len, fenced.split("\n"))) <= MV.LINE_CAP
    indented, _ = MV._capped_lines("    " + "<" * 30000 + "\n")
    assert max(map(len, indented.split("\n"))) <= MV.LINE_CAP + 4
    shown, sources = MV.code_blocks("text\n\n" + "    code line\n" * 400 + "\nafter\n")
    assert "```" in shown and sources == ["code line\n" * 400]  # (fenced: markdown_parts cuts it in parts)
    assert len(MV._md4c_page("    " + "<" * 30000 + "\n")[0]) > 1


def test_sad_a_zoom_on_a_page_of_few_long_lines_lays_it_out_a_part_a_turn(monkeypatch):
    """A page of fewer than ZOOM_BLOCKS blocks was laid out again in the zoom's own turn however long its
    lines: 200 KB of Ogham space marks, 0.18 s. Past ZOOM_CHARS characters too, a part a turn."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render(("word " * 400 + "\n\n") * 60)
    assert until(lambda: view._readable, 60)
    until(lambda: not view._scheduled, 60)
    assert view.browser.document().blockCount() < MV.ZOOM_BLOCKS < view.browser.document().characterCount()
    again = []
    render = view.render
    monkeypatch.setattr(view, "render", lambda text, again_=None, **kw: (again.append(kw.get("again")),
                                                                       render(text, **kw))[1])
    view.zoom_by(1)
    assert again and again[0] is not None
    view.close()


def test_sad_a_line_of_many_tabs_has_spaces_for_them_but_its_indentation():
    """Qt lays a line of tabs out in time growing with their square: "[a](" and "a" with a tab 1,000,000
    times held the window 8.3 s, 200 KB of them 0.2 to 0.4 s (both parsers). Past TAB_LINE tabs a line's
    tabs are spaces - but its indentation, which says what the line is."""
    from ui import markdown_view as MV

    shown = MV.renderable("[a](" + "a\t" * 100000 + ")")[0]
    assert "\t" not in shown and shown.count(" ") >= 100000
    kept = MV.renderable("\t\tcode" + "\tx" * 100 + "\nshort\ta\tb\n")[0]
    assert kept.startswith("\t\tcode x") and "short\ta\tb" in kept


def test_sad_unicode_spaces_are_places_to_cut_a_paragraph():
    """"[a](" and "a" with a no-break space 15,000 times: one word to the cutter (only " " was a place),
    in a link's address never closed - one piece of 30 KB, 0.24 s."""
    from ui import markdown_view as MV

    assert MV._pieces_of("[a](" + "a\xa0" * 15000 + ")").count(MV.JOINED) >= 3


def test_sad_one_page_is_made_at_a_time_and_the_gui_thread_never_waits_for_it():
    """Two workers making pages at once (a long text's later pieces, an export's page) left the GUI thread
    a third of Python's lock: 0.16 to 0.24 s without an answer. One makes a page at a time; the GUI thread
    making a small one never waits for a worker's."""
    from ui import markdown_view as MV

    order = []

    def making(name, seconds):
        def work():
            order.append((name, "begun"))
            time.sleep(seconds)
            order.append((name, "ended"))
        return lambda: MV.held_while(work)

    first = threading.Thread(target=making("first", 0.3))
    first.start()
    until(lambda: order, 5)
    second = threading.Thread(target=making("second", 0.01))
    second.start()
    began = time.monotonic()
    MV.held_while(lambda: order.append(("gui", "made")))
    TB.budget(time.monotonic() - began < 0.1, 'time.monotonic() - began < 0.1')  # (the GUI thread: not waited)
    first.join()
    second.join()
    assert order.index(("second", "begun")) > order.index(("first", "ended")), order


def test_sad_a_long_paragraph_of_a_page_is_made_safe_in_pieces():
    """One paragraph of 2 MB of a page markdown-it exports has no block's tag to cut it at: made safe in one
    pass, 0.15 to 0.2 s with Python's lock. It is cut outside a tag now."""
    from ui import markdown_html as H

    page = "<p>" + "a" * 2_000_000 + '<img src="file:///x" alt="i">' + "b" * 1_000_000 + "</p>"
    pieces = []
    assert H.by_blocks(lambda piece: pieces.append(piece) or piece, page) == page
    assert len(pieces) > 10 and all(piece.count("<") == piece.count(">") for piece in pieces)
    assert 'src="file:' not in H.safe_page(page, {})


def test_sad_the_emoji_check_is_quick_on_a_big_text_of_other_letters():
    """wants_emoji's class held every emoji one by one - thousands beyond the BMP, which Python's engine
    tries in turn: 2 MB of letters and a six-per-em space took 5 s, Python's lock held."""
    from ui import markdown_view as MV

    text = ("a\u2006") * 1_000_000
    _quick(lambda: MV.wants_emoji(text), 0.3)
    assert not MV.wants_emoji(text) and MV.wants_emoji(text + "\U0001F600")


def test_sad_the_long_line_check_looks_from_a_line_s_start_only():
    """_LONG_LINE ("[^\\n]{2001}") was tried from each place of lines just short of it: a code line of 200,000
    characters cut in lines of 2,000 held Python's lock 0.1 s."""
    from core import markdown_doc as MD
    from ui import markdown_view as MV

    text = ("a" * 2000 + "\n") * 1000
    _quick(lambda: MD.found_by_lines(MV._LONG_LINE, text), 0.03)
    assert not MD.found_by_lines(MV._LONG_LINE, text) and MD.found_by_lines(MV._LONG_LINE, text + "b" * 2001)


_THRICE = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from tests.test_markdown_reader_bugs11 import pump, until
from ui import markdown_view as MV
text = "# \U0001F600\U0001F600\U0001F600 word\n" * 18000
view = MV.MarkdownView(None)
view.full = False
view.resize(600, 800)
view.show()
pump(0.05)
for typed in ("", "x", "y", "z"):
    view.timer.setInterval(5)
    view.show_later(text + typed)
    until(lambda: not view.timer.isActive(), 30)
    until(lambda: view._readable and view.markdown, 120)
    until(lambda: not view._scheduled, 120)
print("rendered", view.browser.document().blockCount())
"""


def test_sad_a_big_page_rendered_again_and_again_never_crashes_the_program(tmp_path):
    """The sweep's: 200 KB of emoji headings (Qt's own parser) rendered a third time in the preview - the
    program crashed (SIGSEGV in Qt's setMarkdown: the scroll bar's slots asked the layout where things
    were while Qt replaced the page). Run in a child: a crash fails the test, not the run."""
    import subprocess

    script = tmp_path / "thrice.py"
    script.write_text(_THRICE, encoding="utf-8")
    result = subprocess.run([sys.executable, str(script), str(ROOT)], capture_output=True, text=True, timeout=600,
                            env=dict(os.environ))
    assert result.returncode == 0 and "rendered" in result.stdout, (result.returncode, result.stderr[-2000:])


def test_sad_what_is_said_while_a_page_is_made_is_shown_once_it_is():
    """A link followed while the page was made (a folder without a README: "Reading…", then "Not opened
    (…)" said to be shown once the page was) lost its message when the page took longer than the link -
    the status line stuck at "Reading…" (the viewer's tests, on a busy machine)."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view._busy("Rendering…", True)
    view.status.setText("Reading…")  # (the window's own, a link being looked at)
    view.say("Not opened (a folder without a README): empty")
    view._idle()
    assert view.status.text() == "Not opened (a folder without a README): empty"
    view.close()


# -- L1: Qt's own parser and the spec ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, wanted", [
    ("-   \n  foo\n", "foo"),  # (257: an item's mark and spaces, its text below)
    ("- foo\n-   \n- bar\n", "foo bar"),  # (260)
    ("[Foo bar]:\n<my url>\n'title'\n\n[Foo bar]\n", "Foo bar"),  # (164: a definition over three lines)
    ("[link](<foo\\>)\n", "[link](<foo>)"),  # (502: "<foo\>" is no destination)
    ("&hl;\n", "&hl;"),  # (626)
    ("<div>\n*foo*\n</div>\n", "*foo*"),  # (an HTML block's Markdown as written)
    ("<div>\n*foo*\n\n*bar*\n", "*foo* bar"),  # (to an empty line)
    ("<?php\n\n  echo '>';\n\n?>\nokay\n", "okay"),  # (149)
    ("<!DOCTYPE html>\n", ""),  # (150)
    ("<![CDATA[\nfunction matchwo(a,b)\n{\n\n    return 1;\n}\n]]>\nokay\n", "okay"),  # (151)
    ("foo <!ELEMENT br EMPTY> bar\n", "foo bar"),  # (646)
    ("foo <![CDATA[>&<]]> bar\n", "foo bar"),  # (647)
    ("foo <?php echo $a; ?> bar\n", "foo bar"),
    ("```\n<?php\n```\n", "<?php"),  # (in code: as written)
    ('<a href="foo">\n*bar*\n</a>\n', "*bar*"),  # (141: a tag alone on its line, after an empty one)
    ("<del>\n\n*foo*\n\n</del>\n", "foo"),  # (144: Markdown after an empty line)
    ("x\n<span>\n*a*\n", "x a"),  # (in a paragraph: no HTML block)
])
def test_sad_qt_s_own_parser_shows_these_spec_examples_as_gfm_does(text, wanted):
    shown = " ".join(_shown_md4c(text).split())
    assert shown == wanted, (text, shown)


# -- L2: the same file written another way -------------------------------------------------------------------------

def test_sad_a_link_to_the_same_file_written_otherwise_jumps_on_windows(tmp_path, monkeypatch):
    """navigate compared the paths as strings: "C:/docs/a.md" from axross's pane and "C:\\docs\\a.md" from
    target_of - a link "a.md#install" read the file again and remembered a Back entry."""
    from ui import markdown_view as MV
    from ui import markdown_viewer as V

    viewer = _viewer(tmp_path, "# Top\n\ntext\n\n## Install\n\nhere\n")
    monkeypatch.setattr(MV, "LOCAL_PATHS", ntpath)
    shown = []
    monkeypatch.setattr(V.MarkdownViewerDialog, "_show", lambda self, *a, **k: shown.append(a))
    jumped = []
    monkeypatch.setattr(viewer.view, "go_to_anchor", lambda anchor: jumped.append(anchor) or True)
    viewer.path = "C:/docs/a.md"
    viewer.navigate("C:\\docs\\A.md", "install")
    assert shown == [] and jumped == ["install"]
    viewer.navigate("C:\\docs\\b.md", "")
    assert len(shown) == 1
    viewer.close()


def test_happy_the_heartbeat_s_budget_is_tight_and_measured_again(monkeypatch):
    """GAP was 0.5 s: review 24's 0.30 s heading line and 0.15 s paragraphs passed every stress test. A
    test whose window froze is run once more (the conftest's hook, Frozen) before it fails. (The heartbeat's
    own rules: no duration measured - its budgets strict here, under -m "not timing" too.)"""
    monkeypatch.setattr(TB, "SOFT", False)
    assert HB.GAP <= 0.15
    with pytest.raises(HB.Frozen):
        HB.assert_responsive(HB.gap_budget() + 0.01)
    assert issubclass(HB.Frozen, AssertionError)
    runs = []

    def flaky():
        runs.append(1)
        if len(runs) == 1:
            raise HB.Frozen("first")
        return "ok"

    try:
        flaky()
    except HB.Frozen as first:
        assert HB.measure_again(flaky, first) == "ok" and len(runs) == 2
    with pytest.raises(HB.Frozen, match="first - measured again"):
        HB.measure_again(lambda: (_ for _ in ()).throw(HB.Frozen("second")), HB.Frozen("first"))
    assert re  # (the module's own import)
