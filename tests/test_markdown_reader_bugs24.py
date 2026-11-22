"""The twenty-fourth round of the Markdown reader (the twenty-third review): a cubic regular expression
in Qt's own parser's footnote pass (a line of 1,200 backticks held axross's viewer 11.7 s - on a worker
too, Python's lock held: the window frozen while the per-turn CPU meter read 0.08 s); whole classes of
paragraphs Qt's own parser laid out in one turn (a "|" in it, a long word in a link or emphasis, list
marks nested on one line, lines of "="); Windows paths (no image beside a file ever shown, relative
links to the drive's root); a table shown as written in lines never cut; texts up to 20 KB parsed on the
GUI thread, and markdown-it-py's two quadratic rules; Qt's own parser's HTML export on the GUI thread;
the emoji scan's first family outside its deadline; a zoom that laid out a big table again in the next
turn; a footnote cited twice as broken HTML; an unpinned pytest in the release's build environment; and
the small things (the dialogs after the whole page, Ctrl+End / Ctrl+Home, the spec's examples, <details>).

A new kind of measure comes with it (tests/markdown_heartbeat.py): a heartbeat on the GUI thread whose
longest wall-clock gap is what the user sees - every stress test that measures turns measures it too.
Each test here failed before.
"""

from __future__ import annotations

import ntpath
import os
import re
import sys
import threading
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtCore import QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests import markdown_heartbeat as HB  # noqa: E402
from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests.test_markdown_reader_bugs20 import _Turns  # noqa: E402
from tests.test_markdown_reader_bugs22 import (  # noqa: E402,F401 - _closed_after: the fixture, used by name
    PARSERS, _closed_after, _longest_turn, within_turn)
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _viewer(tmp_path, text: str, full: bool = True, name: str = "page.md"):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / name
    page.write_text(text, encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.view.full = viewer.view.full and full
    viewer.resize(1100, 800)
    viewer.show()
    if not full:
        viewer.view.render(text)
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 120)
    until(lambda: not viewer.view._scheduled, 120)
    pump(0.2)
    return viewer


def _opened(tmp_path, text: str, full: bool) -> tuple[float, float]:
    """(the longest turn, the longest wall-clock gap) of the window while *text* is opened in it and laid
    out - the heartbeat started before the window is made (MarkdownViewerDialog, a real file)."""
    from core import markdown_doc
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "opened.md"
    page.write_text(text, encoding="utf-8")
    available = markdown_doc.available
    if not full:
        markdown_doc.available = lambda: False
    try:
        beat = HB.Heartbeat()
        viewer = MarkdownViewerDialog(LocalFS(), str(page))
        viewer.resize(1100, 800)
        viewer.show()
        assert until(lambda: viewer.view._readable and viewer.view.markdown, 240)
        until(lambda: not viewer.view._scheduled and not viewer.view.status.text().startswith("Rendering"), 240)
        pump(0.2)
        turn, gap = beat.stop()
        viewer.close()
        viewer.deleteLater()
        pump(0.05)
    finally:
        markdown_doc.available = available
    return turn, gap


# -- the heartbeat itself ----------------------------------------------------------------------------------

def test_sad_the_heartbeat_sees_a_worker_that_holds_pythons_lock_the_cpu_meter_does_not():
    """The new measure: a worker thread in one long search of a regular expression holds the GIL - the GUI
    thread spends no CPU time, so the per-turn CPU meter reads nearly nothing, but the window does not
    answer: the heartbeat's wall-clock gap says so."""
    pattern = re.compile(r"(`+)(?:(?!\1).)+?\1")  # (0.16.9's _CODE_SPAN: cubic in a run of backticks)
    beat = HB.Heartbeat()
    pump(0.05)
    worker = threading.Thread(target=lambda: list(pattern.finditer("x " + "`" * 500)))
    worker.start()
    while worker.is_alive():
        pump(0.01)
    turn, gap = beat.stop()
    TB.budget(turn < 0.1, turn)  # (the GUI thread itself did nothing)
    TB.budget(gap > 0.25, gap)  # (but the window was frozen)
    with pytest.raises(AssertionError):
        HB.assert_responsive(gap * HB.machine_factor() * 10)


def test_happy_every_stress_meter_measures_the_gap_too(monkeypatch):
    """_Turns (bugs20, and with it bugs21-24's measures and bugs22's within_turn) and bugs16/17/18's meters
    carry the heartbeat: a frozen window fails them whatever the CPU meter reads."""
    from tests.test_markdown_reader_bugs16 import Turns as Turns16
    from tests.test_markdown_reader_bugs17 import Turns as Turns17
    from tests.test_markdown_reader_bugs18 import _Turns as Turns18

    monkeypatch.setattr(TB, "SOFT", False)  # (the meters' own failure is what is asserted)
    for meter in (_Turns, Turns16, Turns17, Turns18):
        turns = meter()
        pump(0.02)
        frozen = threading.Thread(target=lambda: re.compile(r"(`+)(?:(?!\1).)+?\1").search("x " + "`" * 700))
        frozen.start()
        frozen.join()  # (the GUI thread waits: as a GIL held by a worker makes it)
        pump(0.02)
        with pytest.raises(AssertionError, match="did not answer"):
            turns.stop() if hasattr(turns, "stop") else turns.worst()


# -- N1: the cubic code span pattern ---------------------------------------------------------------------

def test_sad_code_spans_are_found_in_one_pass():
    """_CODE_SPAN tried every length of a run of backticks from each of them, each lazily: 800 backticks
    4.5 s, 1,600 54 s (with_footnotes ran it on every line). One pass now."""
    from ui import markdown_view as MV

    began = time.process_time()
    assert MV.code_span_bounds("x " + "`" * 200_000) == []
    noted, _numbers = MV.with_footnotes("x [^a] " + "`" * 2000 + "\n\n[^a]: the note\n")
    TB.budget(time.process_time() - began < 0.5, 'time.process_time() - began < 0.5')
    assert "[^a]" not in noted and "the note" in noted
    # (as CommonMark reads them: a run to the next run of its length, an escaped first backtick not one)
    line = "a `b` c ``d ` e`` f `g h \\`i` ``j"
    assert [line[s:e] for s, e in MV.code_span_bounds(line)] == ["`b`", "``d ` e``", "`g h \\`", ]
    noted, _ = MV.with_footnotes("`[^a]` and [^a]\n\n[^a]: n\n")
    assert noted.startswith("`[^a]` and [")  # (in a code span: as written; outside: the reference)
    assert MV.with_footnotes("no notes here\n") == ("no notes here\n", [])


def test_sad_a_line_of_backticks_freezes_no_window_on_its_own_or_in_a_big_file(tmp_path):
    """Before (Qt's own parser): "x " and 800 backticks a turn of 2.6 s (prepared on the GUI thread); in a
    file of 20,000 paragraphs the same pass on a worker, Python's lock held: the window frozen 4.5 s (1,200
    backticks: 12.6 s) while the per-turn CPU meter read 0.08 s."""
    small = "x " + "`" * 800
    big = "".join(f"Paragraph {i} with some words.\n\n" for i in range(20000)) + small
    for text in (small, big):
        turn, gap = _opened(tmp_path, text, False)
        TB.budget(turn < 0.5 and gap < HB.gap_budget(), (len(text), turn, gap))


# -- N2: Qt's own parser's paragraphs and parts ---------------------------------------------------------------

MD4C_CASES = {
    "a paragraph with a | in it": lambda: "Run `ls | wc` here. " + "word " * 100000,
    "pipes after a word": lambda: "x " + "|" * 99000,
    "a long word in a link": lambda: "[" + "a" * 99000 + "](https://e.com)",
    "a long autolink": lambda: "<https://e.com/" + "a" * 99000 + ">",
    "a long bare address": lambda: "https://e.com/" + "a" * 99000,
    "a long word in emphasis": lambda: "*" + "a" * 99000 + "*",
    "list marks nested on one line": lambda: "+ " * 30000,
    "ordered marks nested on one line": lambda: "1. " * 20000,
    "lines of =": lambda: "=\n" * 100000,
    "lines of ==": lambda: "==\n" * 60000,
    "quotes and lists on one line": lambda: "> - " * 2500 + "a",
    "a table's rows of pipes": lambda: "|a|b|\n|-|-|\n" + "".join("|" * (i % 500) + "\n" for i in range(5000)),
    "a header of 30,000 columns": lambda: "|" + "|".join(f"h{c}" for c in range(30000)) + "|\n|" + "-|" * 30000,
}


@pytest.mark.parametrize("name", sorted(MD4C_CASES))
def test_sad_qt_s_own_parser_cuts_these_paragraphs_and_parts(name):
    """Before: 0.3 to 18 s in one turn (a 2 MB paragraph with one "|" 1.2 s, a link's word of 99,000 letters
    1.3 s, "+ " 90,000 times 7.9 s, "=\\n" 300,000 times 12 to 18 s)."""
    text = MD4C_CASES[name]()
    within_turn(lambda: _longest_turn(text, False), text, name)


def test_sad_a_long_link_and_emphasis_are_ended_and_begun_again_around_each_cut():
    """Cut inside a link's text the pieces are links to the same address each, inside emphasis emphasis
    each - none shows markup ("[aaa" and "](https://e.com)" were two pieces of text)."""
    from ui import markdown_view as MV

    for text, opener, closer in (("[" + "a" * 20000 + "](https://e.com)", "[", "](https://e.com)"),
                                 ("*" + "a" * 20000 + "*", "*", "*"), ("**" + "b" * 20000 + "**", "**", "**"),
                                 ("[" + "word " * 5000 + "](u)", "[", "](u)")):
        pieces = MV._pieces_of(text).split("\n\n" + MV.JOINED)
        assert len(pieces) > 3, text[:10]
        for piece in pieces:
            assert piece.startswith(opener) and piece.endswith(closer), (text[:10], piece[:20], piece[-20:])
        letters = "".join(piece[len(opener):len(piece) - len(closer)] for piece in pieces)
        assert letters.replace(" ", "") == text[len(opener):len(text) - len(closer)].replace(" ", "")
    pieces = MV._pieces_of("<https://e.com/" + "a" * 9900 + ">").split("\n\n" + MV.JOINED)
    assert len(pieces) > 1 and all(p.startswith("[") and p.endswith("](https://e.com/" + "a" * 9900 + ")")
                                   for p in pieces)


def test_sad_marks_nested_on_one_line_are_shown_flatter_and_kept_as_text():
    from ui import markdown_view as MV

    text, flattened = MV._one_line_nesting("+ " * 40 + "end")
    assert flattened and text == "+ " * MV.LIST_DEPTH + "\\+ " + "+ " * (40 - MV.LIST_DEPTH - 1) + "end"
    assert MV._one_line_nesting("- " * 40) == ("- " * 40, False)  # (a thematic break)
    assert MV._one_line_nesting("```\n" + "+ " * 40 + "\n```\n")[1] is False  # (code)
    shown = _shown_md4c("+ " * 40 + "end\n")
    assert "end" in shown and "+ + +" in shown


def test_sad_a_page_of_lines_of_equals_is_cut_into_parts():
    from ui import markdown_view as MV

    assert len(MV.markdown_parts("=\n" * 3000)) > 10
    assert len(MV.markdown_parts("a\n=\n" * 1500)) > 10


# -- N3: Windows paths -------------------------------------------------------------------------------------

@pytest.fixture
def windows(monkeypatch):
    """This computer's paths as Windows' are (ntpath), its real places as written."""
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "LOCAL_PATHS", ntpath)
    monkeypatch.setattr(ntpath, "realpath", lambda path, **_kw: ntpath.normpath(path))
    return MV


@pytest.mark.parametrize("document", ["C:\\docs\\a.md", "C:/docs/a.md"])
def test_sad_an_image_beside_a_file_on_windows_is_local(windows, document):
    """Before: ImageSource(LocalFS(), "C:\\docs\\a.md").folder was "/" and "pic.png" "/pic.png" - never inside
    the folder's real place ("not beside the file"); with forward slashes every image was "outside"."""
    from core.local_fs import LocalFS

    source = windows.ImageSource(LocalFS(), document)
    assert source.folder.replace("/", "\\") == "C:\\docs"
    assert source.kind("pic.png") == ("local", "C:\\docs\\pic.png")
    assert source.kind("sub/p.png") == ("local", "C:\\docs\\sub\\p.png")
    for outside in ("../x.png", "..\\x.png", "/x.png", "\\x.png", "C:x.png", "D:/x.png", "\\\\host\\x.png",
                    "sub/../../x.png", "file:///C:/x.png"):
        assert source.kind(outside)[0] in ("outside", "remote"), outside
    assert source._read_file("C:\\docs\\pic.png") == windows.tr("not found")  # (beside it - only not there)
    assert source._read_file("C:\\other\\pic.png") == windows.tr("not beside the file (a link to elsewhere)")
    assert windows._inside("c:\\DOCS\\Pic.png", "C:\\docs", ntpath)  # (case aside, as Windows compares)
    assert not windows._inside("C:\\docs2\\p.png", "C:\\docs", ntpath)
    assert not windows._inside("D:\\docs\\p.png", "C:\\docs", ntpath)


@pytest.mark.parametrize("document", ["C:\\docs\\a.md", "C:/docs/a.md"])
def test_sad_a_relative_link_on_windows_opens_the_sibling(windows, document):
    """Before: "[b](b.md)" led to "/b.md" (the drive's root) after a question, and with forward slashes every
    relative link was asked about (_beside compared backslashed real places with "/")."""
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    window = types.SimpleNamespace(path=document, backend=LocalFS())
    window._paths = lambda: MarkdownViewerDialog._paths(window)
    window._name = lambda path=None: MarkdownViewerDialog._name(window, path)
    kind, path, fragment = MarkdownViewerDialog.target_of(window, QUrl("b.md#part"))
    assert (kind, path, fragment) == ("markdown", "C:\\docs\\b.md", "part")
    assert MarkdownViewerDialog.target_of(window, QUrl("sub/c.png"))[1] == "C:\\docs\\sub\\c.png"
    assert MarkdownViewerDialog._beside(window, "C:\\docs\\b.md")
    assert not MarkdownViewerDialog._beside(window, "C:\\b.md")
    assert MarkdownViewerDialog.target_of(window, QUrl("/etc/passwd"))[0] == "refused"
    assert window._name() == "a.md"


# -- N4: a table shown as written --------------------------------------------------------------------------

def test_sad_a_table_shown_as_written_has_its_lines_cut():
    """200,000 columns: one code line of 800,000 characters, laid out in one turn of 4.6 s (markdown-it's
    page). Its lines are cut as a code block's own (LINE_CAP), all of it kept."""
    from ui import markdown_view as MV

    text = "|" + " a |" * 60000 + "\n|" + "-|" * 60000 + "\n|" + " b |" * 60000
    shown, why = MV.renderable(text)
    assert why and max(map(len, shown.split("\n"))) <= MV.LINE_CAP
    body = shown.split("```text\n", 1)[1].rsplit("\n```", 1)[0]
    assert body.replace("\n", "") == text.replace("\n", "")  # (all of it, in order)
    within_turn(lambda: _longest_turn(text, True), text, "a table of 60,000 columns")


# -- N5: parsed on the GUI thread; markdown-it-py's quadratic rules -------------------------------------------

def test_sad_a_text_of_a_few_kilobytes_is_parsed_on_a_worker():
    """Up to 20,000 characters were parsed on the GUI thread - at every pause in the editor's typing: 19 KB
    of "#\\n" 0.23 s, of "<!--" or "http:// " (markdown-it-py 4.2) 0.8 to 0.9 s."""
    from ui import markdown_view as MV

    assert MV.BACKGROUND_CHARS <= 2_000
    text = "#\n" * 9500
    within_turn(lambda: _longest_turn(text, True), text, "19 KB of headings")


@pytest.mark.parametrize("text", ["x " + "<!--" * 12000, "x " + "<!-- " * 10000, "x " + "<?" * 20000,
                                  "x " + "<![CDATA[" * 5000, "x " + "<a" * 20000, "x " + "http:// " * 8000,
                                  "x " + "https://e.com " * 8000 + "<!-- a -->"])
def test_sad_markdown_it_s_inline_rules_are_linear(text):
    """markdown-it-py 4.2's html_inline looked for the end of an unclosed "<!--" (or "<?") from each one to
    the end of the text, its linkify for the scheme before each "://" in all the text before it: 96 KB of
    "<!--" 18 s, 200 KB of "http:// " 97 s before a page showed."""
    from core import markdown_doc as MD

    MD.parse("warm")
    began = time.process_time()
    doc = MD.parse(text)
    TB.budget(time.process_time() - began < 3.0, text[:12])
    assert doc.tokens


def test_happy_the_linear_inline_rules_read_what_they_read_before():
    from core import markdown_doc as MD
    from ui import markdown_html as H

    page = H.to_html(MD.parse("see <b>bold</b> and <!-- gone --> x <?pi?> <a href=\"https://e.com\">e</a>\n"))
    assert "<b>bold</b>" in page or "<strong>bold</strong>" in page
    assert "gone" not in page and 'href="https://e.com"' in page
    if MD._has_linkify():
        page = H.to_html(MD.parse("go to https://e.com/x, mailto:a@b.example and www.e.org now\n"))
        assert 'href="https://e.com/x"' in page and 'href="mailto:a@b.example"' in page
        assert "xhttp://e.com" in H.to_html(MD.parse("xhttp://e.com\n"))


# -- N6: Qt's own parser's HTML export --------------------------------------------------------------------

def test_sad_qt_s_own_parser_s_html_export_holds_no_turn(tmp_path):
    """Export HTML with Qt's own parser laid the whole page out, then toHtml and safe_page in one turn: a
    table of 20,000 rows 0.42 s, a code block of a million lines 4.4 s. Now a part a turn, made safe on a
    worker."""
    text = "| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 20000

    def measure() -> float:
        viewer = _viewer(tmp_path, text, full=False)
        target = str(tmp_path / "page.html")
        turns = _Turns()
        made = viewer.export_html(target)
        pump(0.1)
        longest = turns.stop()
        assert made == target
        page = Path(target).read_text(encoding="utf-8")
        assert page.count("<td") >= 3 * 20000 and "Content-Security-Policy" in page
        viewer.close()
        return longest

    within_turn(measure, text, "export HTML, Qt's own parser")


# -- N7: the emoji scan's deadline --------------------------------------------------------------------------

class _FallbackMetrics:
    """QFontMetrics as Qt's are on a machine of 2,000 fonts and no emoji font: inFontUcs4 looks for the
    character in every family (Qt's fallback) - a moment each, and no font has it."""

    def __init__(self, _font):
        pass

    def inFontUcs4(self, _sign):  # noqa: N802 - Qt
        time.sleep(0.0003)
        return False


def test_sad_the_emoji_scan_is_all_of_it_under_its_deadline(monkeypatch):
    """The first family asked (the default font, with Qt's fallback) was outside the deadline: 0.26 s of the
    first view on a machine of 2,000 fonts, 0.6 s with the maths font check."""
    from PyQt6 import QtGui

    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families", staticmethod(lambda *a: ["DejaVu Sans", "Other"]))
    monkeypatch.setattr(QtGui, "QFontMetrics", _FallbackMetrics)
    began = time.monotonic()
    MV.emoji_fonts()
    TB.budget(time.monotonic() - began < MV.EMOJI_SCAN_SECONDS + 0.1, 'time.monotonic() - began < MV.EMOJI_SCAN_SECONDS + 0.1')
    assert MV._EMOJI_DRAWN == [frozenset()]


def test_sad_the_maths_font_check_asks_the_font_alone(monkeypatch):
    """_check_script_letters asked QFontMetrics, which answers with Qt's fallback fonts (every family looked
    in: 0.15 to 0.28 s of the first view) - and said yes for a maths font without the letters."""
    from PyQt6 import QtGui

    from ui import markdown_html as H
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_SCRIPT_CHECKED", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families", staticmethod(lambda *a: list(H.MATH_FONTS)))

    class Slow(_FallbackMetrics):
        def inFontUcs4(self, _sign):  # noqa: N802 - Qt
            time.sleep(0.3)
            return True

    monkeypatch.setattr(QtGui, "QFontMetrics", Slow)
    kept = []
    from core import markdown_doc

    monkeypatch.setattr(markdown_doc, "keep_script_letters", lambda: kept.append(True))
    began = time.monotonic()
    MV._check_script_letters()
    TB.budget(time.monotonic() - began < 0.25, 'time.monotonic() - began < 0.25')
    from PyQt6.QtGui import QFont, QRawFont

    alone = any(QRawFont.fromFont(QFont(name)).supportsCharacter(0x1D4AA) for name in H.MATH_FONTS
                if name in QtGui.QFontDatabase.families())
    assert bool(kept) == alone


# -- N8: zoom on a page read to its end --------------------------------------------------------------------

@PARSERS
def test_sad_a_zoom_on_a_big_table_read_to_its_end_holds_no_later_turn(tmp_path, full):
    """Ctrl++ on a table of 20,000 rows read to its end: Qt laid all of it out again in the turn that next
    needed a place past the view - the scroll to the bottom 1.6 s (markdown-it) and 0.65 s (Qt's own), Find
    0.7 to 1.1 s. A zoom on a big page lays it out anew a part a turn, from the place read."""
    text = "| a | b | c |\n|---|---|---|\n" + "| 1 | 2 | 3 |\n" * 20000

    def measure() -> float:
        viewer = _viewer(tmp_path, text, full)
        view = viewer.view
        done = []
        view.load_rest(lambda: done.append(True))
        assert until(lambda: done, 240)
        pump(0.3)
        turns = _Turns()
        view.zoom_by(1)
        pump(0.2)
        until(lambda: not view._scheduled, 120)
        bar = view.browser.verticalScrollBar()
        bar.setValue(bar.maximum())
        pump(0.3)
        viewer.find_field.setText("zzz")
        pump(0.8)
        longest = turns.stop()
        assert view.zoom_percent() > 100
        viewer.close()
        return longest

    within_turn(measure, text, "zoom, scroll, find")


# -- N9: a footnote cited twice ------------------------------------------------------------------------------

def test_sad_a_footnote_cited_twice_is_well_formed_html():
    """Its first way back was wrapped in a paragraph of its own inside the note's: "<p>First note.<p
    class="footnote-back">…</p> <a …>↩︎</a></p>" - the ways back on lines of their own."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    for page in (H.to_html(MD.parse("a[^a] b[^a] c[^a]\n\n[^a]: First note.\n")),
                 H.export_html(MD.parse("a[^a] b[^a]\n\n[^a]: First note.\n"))):
        note = page[page.index('class="footnote-item"'):]
        note = note[:note.index("</li>")]
        assert 'class="footnote-back"' not in note, note
        assert re.search(r"<p>First note\.( <a [^<>]*>↩︎</a>){2,3}</p>", note), note
    page = H.to_html(MD.parse("a[^a] b[^a]\n\n[^a]: A note.\n\n    ```\n    code\n    ```\n"))
    note = page[page.index('class="footnote-item"'):]
    assert note.count('<p class="footnote-back">') == 1 and note.count("footnote-backref") == 2
    back = note[note.index('<p class="footnote-back">'):]
    assert back.index("</p>") > back.rindex("footnote-backref")  # (both ways back in the one paragraph)


# -- N11: Export PDF / HTML and Print ask first -------------------------------------------------------------

def test_sad_export_asks_for_the_file_before_the_page_is_laid_out_whole(tmp_path, monkeypatch):
    """ask_export_pdf / ask_export_html waited for the whole page to be laid out in the window (24 s to more
    than ten minutes) before the file dialog showed. They ask at once now; the images the page shows are
    read on a worker (one in a part never laid out too)."""
    from PyQt6.QtWidgets import QFileDialog

    from tests.test_markdown_reader_bugs3 import _png
    from ui import markdown_viewer as V

    _png(tmp_path / "far.png")
    text = "".join(f"Paragraph {n} of some words to fill the page.\n\n" for n in range(60000)) + "![far](far.png)\n"
    viewer = _viewer(tmp_path, text)
    assert viewer.view.more()  # (not laid out whole)
    asked = []

    def ask(*_args, **_kw):
        asked.append(viewer.view.more())
        return "", ""

    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(ask))
    for call in (viewer.ask_export_pdf, viewer.ask_export_html):
        began = time.monotonic()
        call()
        assert asked[-1] is True
        TB.budget(time.monotonic() - began < 2.0, 'time.monotonic() - began < 2.0')
    target = str(tmp_path / "page.html")
    assert viewer.export_html(target) == target
    assert '<img src="data:image/png;base64,' in Path(target).read_text(encoding="utf-8")
    del V


def test_sad_print_asks_once_and_first(tmp_path, monkeypatch):
    """Print made its dialog, then waited for the page laid out whole, then made a new one - the first left
    behind as the window's child."""
    from ui import markdown_viewer as V

    support = V._print_support()
    if support is None:
        pytest.skip("no Qt printing here")
    made = []

    class Dialog:
        def __init__(self, *_args):
            made.append(self)
            self.asked = False

        def exec(self):
            self.asked = True
            return 0  # (Cancel)

        def deleteLater(self):  # noqa: N802 - Qt
            pass

    monkeypatch.setattr(support, "QPrintDialog", Dialog)
    text = "".join(f"Paragraph {n} of some words to fill the page.\n\n" for n in range(60000))
    viewer = _viewer(tmp_path, text)
    began = time.monotonic()
    assert viewer.print_page() is False
    assert len(made) == 1 and made[0].asked and viewer.view.more()
    TB.budget(time.monotonic() - began < 2.0, 'time.monotonic() - began < 2.0')
    assert viewer.print_page() is False and len(made) == 2 and made[1].asked  # (asked again: one dialog each)


# -- N12: Ctrl+End and Ctrl+Home --------------------------------------------------------------------------

@PARSERS
def test_sad_ctrl_end_and_ctrl_home_go_there_on_a_page_laid_out_whole(full):
    """Qt's read-only browser does nothing with them: Ctrl+End went to the end only while parts were still to
    be laid out, Ctrl+Home never."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 600)
    view.show()
    view.render("".join(f"Paragraph {n} of some words.\n\n" for n in range(600)))
    assert until(lambda: view._readable and not view.more() and not view._scheduled, 60)
    pump(0.2)
    bar = view.browser.verticalScrollBar()
    assert bar.maximum() > 0 and bar.value() == 0
    QTest.keyClick(view.browser, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier)
    assert TB.until_within(until, lambda: bar.value() == bar.maximum(), 5)
    QTest.keyClick(view.browser, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier)
    assert TB.until_within(until, lambda: bar.value() == 0, 5)
    view.close()


# -- N13: Qt's own parser and the spec ------------------------------------------------------------------------

def _shown_md4c(text: str) -> str:
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    until(lambda: not view._scheduled, 30)
    shown = view.browser.document().toPlainText()
    view.close()
    view.deleteLater()
    return shown


@pytest.mark.parametrize("text, wanted", [
    ("[a](<b)c\n", "[a](<b)c"),  # (502: no link - "<" never closed)
    ("[a](<b)c\n[a](<b)c>\n", "[a](<b)c [a](<b)c>"),  # (503)
    ("Foo\\\n----\n", "Foo\\"),  # (60: a backslash at a heading's end is one)
    ("foo&#10;&#10;bar\n", "foo bar"),  # (335: line ends by reference, white space)
    ("| abc | def |\n| --- |\n| bar |\n", "| abc | def | | --- | | bar |"),  # (203: no table)
    ("- # Foo\n- Bar\n  ---\n  baz\n", "Foo Bar baz"),  # (278: a heading and a paragraph apart)
    ("`<http://foo.bar.`baz>`\n", "<http://foo.bar.baz>`"),  # (355: the code span first)
    ("<http://foo.bar.`baz>`\n", "http://foo.bar.`baz`"),  # (356: the autolink first)
])
def test_sad_qt_s_own_parser_shows_more_of_the_spec_s_examples(text, wanted):
    shown = " ".join(_shown_md4c(text).split())
    assert shown == wanted, (text, shown)


def test_sad_a_reference_definition_that_is_none_is_text():
    """170: "[foo]: <bar>(baz)" is no definition (text right after its "<…>") - Qt's own parser showed
    nothing of it; the raw HTML "<bar>" goes, as markdown-it's page drops it."""
    shown = " ".join(_shown_md4c("[foo]: <bar>(baz)\n\n[foo]\n").split())
    assert shown == "[foo]: (baz) [foo]", shown


def test_sad_details_are_folded_in_qt_s_own_parser_too():
    """<details> without "open" was shown open by Qt's own parser and folded by markdown-it's page; GitHub
    folds it. Folded in both now, a click on its summary opens it."""
    from ui import markdown_view as MV

    text = "<details>\n<summary>The summary</summary>\n\nHidden body\n\n</details>\n\nAfter\n"
    shown = _shown_md4c(text)
    assert "The summary" in shown and "Hidden body" not in shown and "After" in shown and "▸" in shown
    hidden: dict = {}
    folded = MV._fold_details(text, frozenset(), hidden)
    assert "Hidden body" not in folded and "Hidden body" in hidden["text"][1]
    assert f"#{MV.FOLD}1)" in folded
    opened = MV._fold_details(text, frozenset({1}))
    assert "Hidden body" in opened and "▾" in opened
    assert "Shown" in _shown_md4c("<details open>\n<summary>S</summary>\n\nShown\n\n</details>\n")
    view = MV.MarkdownView(None)
    view.full = False
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    pump(0.1)
    view.clicked(QUrl(f"#{MV.FOLD}1"))  # (its summary's link, as a click on it follows it)
    assert TB.until_within(until, lambda: "Hidden body" in view.browser.toPlainText(), 10)
    view.clicked(QUrl(f"#{MV.FOLD}1"))
    assert TB.until_within(until, lambda: "Hidden body" not in view.browser.toPlainText(), 10)
    view.close()


# -- every regular expression of the reader against adversarial runs ---------------------------------------

_AUDIT = r'''
import ast, importlib, json, os, re, sys, time
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
MODULES = sys.argv[2].split(",")
SEARCHING = {"sub", "subn", "search", "finditer", "findall", "split"}
CALLS = SEARCHING | {"compile", "match", "fullmatch"}
UNITS = ["`", "[", "]", "*", "_", "|", "\\", " ", "\t", "(", ")", "<", ">", "!", "#", "-", "=", "~", "$", ":",
         "&", "\"", "^", "{", "}", "\n", "\xa0", "a", "1", ".", "/", "@", "'", "+", "[a", "](", "<a", "<!--", "&#",
         "[^", "`a", "*a", "_a", "> ", "- ", "+ ", "1. ", "![", "| ", "a ", "\\`", "http://", "www.", "a.", "a@",
         "\\begin{", "\\frac{", "\\left(", "a^", "a_", "{a", "<a:", "", "", "a\n", " \n", "\\\n"]
sources = {name: open(importlib.import_module(name).__file__, encoding="utf-8").read() for name in MODULES}
trees = {}
for name, source in sources.items():
    trees[name] = tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent


def uses_of(target):
    """How the code uses the pattern named *target*: the methods called on it; "search" where it is handed on."""
    uses = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            named = (isinstance(node, ast.Name) and node.id == target) or \
                (isinstance(node, ast.Attribute) and node.attr == target)
            if not named or isinstance(getattr(node, "ctx", None), ast.Store):
                continue
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                if parent.attr in CALLS:
                    uses.add(parent.attr)
            elif isinstance(parent, ast.Compare):
                continue
            else:
                uses.add("search")  # (handed on: what is done with it unknown - searched, as the worst)
    return uses


patterns = []  # (where, compiled pattern, the methods it is used with)
for name in MODULES:
    module = importlib.import_module(name)
    source, tree = sources[name], trees[name]
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in CALLS
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.args):
            continue
        flags = None
        if node.func.attr == "compile" and len(node.args) > 1:
            flags = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "flags":
                flags = keyword.value
        try:
            pattern = eval("(" + ast.get_source_segment(source, node.args[0]) + ")", vars(module), {"re": re})
            flag = eval("(" + ast.get_source_segment(source, flags) + ")", vars(module), {"re": re}) if flags else 0
            compiled = re.compile(pattern, flag)
        except Exception:  # (made of a function's own values - an f-string, a local name: its call is checked by
            continue  # the pages' tests)
        uses = set()
        if node.func.attr != "compile":
            uses.add(node.func.attr)
        else:
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Attribute):  # (re.compile(...).match(...))
                uses.add(parent.attr)
            elif isinstance(parent, (ast.Assign, ast.AnnAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        uses |= uses_of(target.id)
            elif isinstance(parent, ast.Return):
                uses.add("search")
            if not uses:
                uses.add("search")
        patterns.append((f"{name}:{node.lineno}", compiled, sorted(uses)))


def timed(call, text):
    # (the collector held while it is timed: thousands of match objects made a full collection of the
    # audit's modules now and then - 0.05 s, a class of characters flagged as quadratic; review 25's R9)
    import gc

    best = 9.0
    for _ in range(2):
        gc.disable()
        try:
            began = time.perf_counter()
            call(text)
            best = min(best, time.perf_counter() - began)
        finally:
            gc.enable()
        if best > 0.5:
            break
    return best


flagged = []
for where, compiled, uses in patterns:
    is_bytes = isinstance(compiled.pattern, bytes)
    calls = []
    if set(uses) & SEARCHING:
        calls.append(("finditer", lambda text: list(compiled.finditer(text))))
    if "match" in uses:
        calls.append(("match", lambda text: compiled.match(text)))
    if "fullmatch" in uses:
        calls.append(("fullmatch", lambda text: compiled.fullmatch(text)))
    for unit in UNITS:
        for shape in ("{}", "x {}", "{}x"):
            small = shape.format(unit * (1500 // len(unit)))
            big = shape.format(unit * (6000 // len(unit)))
            if is_bytes:
                small, big = small.encode("utf-8"), big.encode("utf-8")
            for how, call in calls:
                a = timed(call, small)
                b = timed(call, big) if a < 0.3 else a * 16
                if b > 0.03 and b > 12 * max(a, 0.0005):
                    flagged.append((where, compiled.pattern if not is_bytes else repr(compiled.pattern), how,
                                    repr(shape.format(unit) + "..."), round(a, 4), round(b, 4)))
print(json.dumps({"patterns": len(patterns), "flagged": flagged}))
'''

_AUDITED = ("core.markdown_cli", "core.markdown_doc", "core.markdown_term", "ui.markdown_app", "ui.markdown_html",
            "ui.markdown_safe", "ui.markdown_view", "ui.markdown_viewer")


def test_sad_every_regular_expression_of_the_reader_is_linear_as_it_is_used(tmp_path):
    """Review 23 found a cubic pattern (N1); every pattern of core/markdown_*.py and ui/markdown_*.py - each
    re call's, compiled or not - is run here against runs of backticks, brackets, stars, underscores,
    pipes, backslashes, spaces and the rest, 1,500 and 6,000 characters of each (bare, after a word, before
    one), as it is used: searched (sub, finditer, ...) or matched at one place. Four times the text may
    take no more than about four times as long (twelve: a machine's noise). Before: the code span pattern
    (cubic), the footnote reference's ("[^" repeated: quadratic), the formula passes' (runs of spaces), the
    quotes before a "$$" block (exponential)."""
    import json
    import subprocess

    script = tmp_path / "audit.py"
    script.write_text(_AUDIT, encoding="utf-8")
    env = dict(os.environ)
    result = subprocess.run([sys.executable, str(script), str(ROOT), ",".join(_AUDITED)], capture_output=True,
                            text=True, timeout=900, env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr[-3000:]
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["patterns"] > 250, report["patterns"]  # (all of them looked at: none lost to a rename)
    assert not report["flagged"], "\n".join(map(str, report["flagged"]))


# -- N15: the small things ----------------------------------------------------------------------------------

def test_sad_the_terminal_view_names_the_program_that_was_run(tmp_path, capsys):
    """"axross-markdown --term missing.md" said "axross-mdcat: missing.md: …"."""
    from core import markdown_cli
    from ui import markdown_app

    assert markdown_app.main(["axross-markdown", "--term", str(tmp_path / "missing.md")]) != 0
    said = capsys.readouterr().err
    assert said.startswith("axross-markdown: ") and "axross-mdcat" not in said, said
    assert markdown_cli.main([str(tmp_path / "missing.md")]) != 0
    assert capsys.readouterr().err.startswith("axross-mdcat: ")


def test_sad_a_letter_with_ninety_nine_thousand_marks_holds_no_turn():
    """"a" and 99,000 combining marks: one cluster no cut can split - 0.14 s in one turn, both parsers. A
    letter keeps MARKS_ON_A_LETTER of them (Unicode's stream-safe text has 30 at most)."""
    from core import markdown_doc as MD

    assert MD.clean("a" + "́" * 99000) == "a" + "́" * MD.MARKS_ON_A_LETTER
    assert MD.clean("é ñ") == "é ñ"
    text = "a" + "́" * 99000
    for full in (True, False):
        within_turn(lambda: _longest_turn(text, full), text, ("marks", full))


def test_sad_find_without_a_match_on_a_big_page_is_quick(tmp_path):
    """Enter in Find, no match, on a page of 2.7 MB laid out whole: Qt's find looked through all of it
    twice, 0.185 s a press. The page's text is asked first."""
    text = "".join(f"## Function {n}\n\n```python\ndef function_{n}(a, b):\n    return a + b * {n}\n```\n\n"
                   for n in range(20000))
    viewer = _viewer(tmp_path, text)
    done = []
    viewer.view.load_rest(lambda: done.append(True))
    assert until(lambda: done, 240)
    pump(0.3)
    assert viewer.view.find_match("zebraquux") is False  # (the text kept once)
    began = time.thread_time()
    for _ in range(5):
        assert viewer.view.find_match("zebraquux") is False
    TB.budget((time.thread_time() - began) / 5 < 0.02, '(time.thread_time() - began) / 5 < 0.02')
    assert viewer.view.find_match("function_19999") is True
    viewer.close()
