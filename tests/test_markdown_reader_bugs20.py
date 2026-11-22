"""The twentieth round of the Markdown reader (the nineteenth review): the
exported tests run in the export; a long line of inline spans, a 10 MB line
with linkify, never hold the window; a display formula in a quote without its
"> "; many footnotes fast; the editor's preview follows the typing; PDF alert
boxes; the zoom button; axross-mdcat's --watch, pipes, full disks, image cap
and help. Each test failed before - with the dependencies of the shipped lock
(markdown-it-py 4.2, mdit-py-plugins 0.6.1, linkify-it-py).
"""

from __future__ import annotations

import os
import subprocess
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
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle() -> None:
    """What earlier tests left - views asked to be deleted, garbage - gone now: their teardown (a page
    of 25,000 spans) was counted in the next test's turns."""
    import gc

    from PyQt6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    gc.collect()
    pump(0.05)


@pytest.fixture(autouse=True)
def _closed_after():
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    _settle()


def _view(text: str, full: bool = True, size=(1000, 800)):
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


def _run(args: list[str], stdin: str | None = None, timeout: float = 120, env=None, **kw):
    return subprocess.run([sys.executable, *args], cwd=ROOT, input=stdin, capture_output=True, text=True,
                          timeout=timeout, env={**os.environ, **(env or {})}, **kw)


def _cli_module() -> str:
    from core import markdown_cli

    return markdown_cli.__name__


# -- H3. a display formula in a quote: without its "> " ---------------------------------------------

QUOTED_MATH = "Before.\n\n> $$\n> a = \\frac{1}{2}\n> $$\n\n> > $$\n> > b + c\n> > $$\n\nAfter.\n"


def test_sad_a_display_formula_in_a_quote_keeps_no_quote_marks_in_its_tex():
    """mdit-py-plugins 0.6.1 (the lock's) kept each line's "> " in the block: "> a = ½ >"."""
    from core import markdown_doc as MD

    blocks = [t.content for t in MD.parse(QUOTED_MATH).tokens if t.type == "math_block"]
    assert [b.strip() for b in blocks] == ["a = \\frac{1}{2}", "b + c"], blocks
    assert MD.parse("> $$ a\n> b $$\n").tokens[1].content.split("\n")[1] == "b "
    # (a formula outside a quote: as it is, its lines' own ">" too)
    assert [t.content for t in MD.parse("$$\na\n> b\n$$\n").tokens if t.type == "math_block"] == ["\na\n> b\n"]


def test_sad_mdcat_and_html_show_a_quoted_formula_without_its_marks():
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_html as H

    shown = T.render(QUOTED_MATH, T.Options(depth="none"))
    formula = [line for line in shown.splitlines() if "½" in line or "1/2" in line]
    assert formula and all(">" not in line for line in formula), shown
    assert ">" not in "".join(line for line in shown.splitlines() if "b + c" in line), shown
    page = H.export_html(MD.parse(QUOTED_MATH))
    assert "&gt;" not in page.split("<article", 1)[1], page.split("<article", 1)[1][:2000]


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_the_window_shows_and_copies_a_quoted_formula_without_its_marks(full):
    view = _view(QUOTED_MATH, full)
    shown = view.browser.toPlainText()
    assert ">" not in shown, shown
    view.browser.selectAll()
    view.copy_selection()
    pump(0.3)
    copied = APP.clipboard().text()
    assert "a = \\frac{1}{2}" in copied and "> a" not in copied and "> >" not in copied, copied


# -- H2b. linkify-it-py on a line of 10 MB: a piece at a time --------------------------------------

def test_sad_linkify_finds_every_link_of_a_long_line_in_pieces():
    """With linkify-it-py (the lock's), its rule pretested and matched all of a 10 MB line in one call
    each: the window froze 4-6 s while a worker parsed (tests/test_markdown_reader_bugs19.py's 10 MB test).
    Now a piece at a time - and every link found as before."""
    pytest.importorskip("linkify_it")
    from core import markdown_doc as MD

    links = ["https://e.com/a", "www.example.org/b", "user@example.net", "http://x.io/(c)"]
    text = "".join(("word " * 20_000) + link + " tail " for link in links * 3) + "\n"
    assert len(text) > 4 * MD.LINES_AT_ONCE
    doc = MD.parse(text)
    hrefs = [c.attrGet("href") for c in doc.tokens[1].children if c.type == "link_open"]
    assert len(hrefs) == 12 and hrefs[:4] == ["https://e.com/a", "http://www.example.org/b",
                                             "mailto:user@example.net", "http://x.io/(c)"], hrefs
    texts = [c for c in doc.tokens[1].children if c.type == "text" and c.level == 0]
    assert len(texts) == 13  # (the pieces joined again around the links: markdown-it's text_join)
    began = time.thread_time()
    MD.parse("word " * 2_000_000)
    TB.budget(time.thread_time() - began < 30, 'time.thread_time() - began < 30')


# -- H2a. a long line of inline spans, a long word, a wide table: laid out in pieces ---------------

class _Turns:
    """The most GUI-thread CPU time one event-loop turn took (a 5 ms timer's ticks) - not wall time:
    on a loaded machine that is what the window itself spends. And the longest wall-clock gap between two
    ticks (tests/markdown_heartbeat.py): a worker holding Python's lock freezes the window though the GUI
    thread spends nothing - over its budget stop() fails."""

    def __init__(self):
        from tests.markdown_heartbeat import Heartbeat

        self.beat = Heartbeat(5)
        self.longest = self.gap = 0.0

    def stop(self) -> float:
        from tests.markdown_heartbeat import assert_responsive

        self.longest, self.gap = self.beat.stop()
        assert_responsive(self.gap, "the heartbeat's longest gap")
        return self.longest


SPAN_LINES = {
    "code spans 9,950": "`a" * 9950,
    "code spans 49,500": "`a" * 49500,
    "a word of 99,000": "a" * 99000,
    "formulas 30,000": "$a$" * 30000,
    "table 60 x 150": "|" + "|".join(f"h{c}" for c in range(60)) + "|\n|" + "---|" * 60 + "\n"
                      + "".join("|" + "|".join(f"r{r}c{c}" for c in range(60)) + "|\n" for r in range(150)),
}


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("name", sorted(SPAN_LINES))
def test_sad_a_long_line_of_spans_never_holds_the_window(name, full):
    """One paragraph of 25,000 code spans and not one space was laid out by Qt in one setHtml: 17 s of
    the GUI thread ("`a" 49,500 times); 5,000 spans 0.6 s, 99,000 letters in one word 1.1 s, 30,000
    formulas 0.7 s, a table of 60 columns 0.3 s a part. Now in pieces, each an event-loop turn."""
    from ui import markdown_view as MV

    _settle()
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    pump(0.1)
    turns = _Turns()
    view.render(SPAN_LINES[name])
    assert until(lambda: view._readable and view.markdown, 240)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 240)
    pump(0.3)
    longest = turns.stop()
    TB.budget(longest < 0.25, (name, longest))
    shown = view.browser.toPlainText()
    assert ("h0" in shown and "r0c0" in shown) if name.startswith("table") else "aaaa" in shown or "a" in shown


def test_sad_the_pieces_of_a_paragraph_without_spaces_keep_its_text():
    """The pieces of such a paragraph hold all of its text, in order (markdown-it's page and Qt's own)."""
    from core import markdown_doc as MD
    from ui import markdown_html as H
    from ui import markdown_view as MV

    import html
    import re

    for text, letter, count in (("`a" * 9950, "a", 9950), ("a" * 99000, "a", 99000), ("x" * 7000 + "`c`d" * 900, "c", 900),
                                ("$a$" * 3000 + "b" * 20000, "b", 20000)):
        parts = H.to_html_parts(MD.parse(text))
        assert len(parts) > 2, text[:20]
        plain = html.unescape(re.sub(r"<[^<>]*>", "", "".join(parts)))
        assert plain.count(letter) == count, (text[:20], plain.count(letter))
        pieces = MV._pieces_of(text)
        assert pieces.replace("\n\n" + MV.JOINED, "") == text and pieces.count(MV.JOINED) >= 2, text[:20]
    assert MV._pieces_of("`a b`" * 3000).replace("\n\n" + MV.JOINED, "").count("`") == 6000  # (never in a span)
    joined = MV._pieces_of("`" + "a" * 20000 + "`")  # (a code span of 20,000 letters: never cut inside)
    assert MV.JOINED not in joined


# -- footnotes: a long text with inline notes in parts too -------------------------------------------

def _inline_notes(count: int, words: int = 60) -> str:
    return "".join(f"Para {n} " + "words " * 100 + "^[" + "explains this at length " * words + "]\n\n"
                   for n in range(count))


def test_sad_a_long_text_with_inline_notes_shows_its_first_part_at_once():
    """3.8 MB with 1,500 inline notes (^[...]) was one part: axross-mdcat wrote nothing until all of it was
    parsed (61 s on the reviewer's machine), the window showed nothing for 10.5 s."""
    from core import markdown_term as T

    text = _inline_notes(1500, 80)
    assert len(text) > 3_500_000
    began = time.thread_time()
    parts = T.render_parts(text, T.Options(width=100, depth="none"))
    first = next(parts)
    took = time.thread_time() - began
    assert "Para 0" in first and "Para 1499" not in first
    TB.budget(took < 2.0, took)
    rest = "".join(parts)
    assert "Para 1499" in rest and "[1500]" in rest


@pytest.mark.parametrize("sample", [
    "A^[one] b^[two [nested] three] c.\n\n| x | y^[in a cell] |\n|---|---|\n| 1 | 2 |\n\n# H ^[head]\n\n"
    "- item ^[- a dash first]\n- 2. ^[1. a number first]\n\n> quoted ^[> a mark]\n",
    "[x ^[in a link]](https://e.com) and ^[after]\n",
    "Code `^[no note]` and ^[a note] here.\n\n```\n^[in a fence]\n```\n\n    ^[indented]\n",
    "Label[^l] and inline^[i] and again[^l].\n\n[^l]: The label's.\n",
    "Escaped \\^[not a note] and ^[a \\] b] done.\n",
])
def test_sad_inline_notes_in_parts_show_as_the_whole_text_does(sample, monkeypatch):
    from core import markdown_term as T

    text = (sample + "\n" + "Filler paragraph.\n\n" * 40) * 3
    options = T.Options(width=70, depth="none", hyperlinks=False)
    whole = "".join(T.render_parts(text, options))
    monkeypatch.setattr(T, "STREAM_CHARS", 0)
    monkeypatch.setattr(T, "STREAM_ROWS", 0)
    monkeypatch.setattr(T, "STREAM_LINES", 30)
    parted = "".join(T.render_parts(text, options))
    assert parted == whole
    converted = T.labeled_inline_notes(text)
    if "in a link" in sample or "`^[" in sample:  # (where it is not sure: one part, as before)
        assert converted == text
    else:
        assert converted != text and "^[" not in converted.replace("\\^[", "") and len(T.text_parts(converted)) > 1


def test_sad_the_window_shows_a_long_text_with_inline_notes_in_parts():
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    began = time.monotonic()
    view.render(_inline_notes(1500, 80))
    assert until(lambda: view._readable and view.markdown, 120)
    assert view._page is not None and len(view._page["parts"]) > 1
    assert "Para 0" in view.browser.toPlainText() and "Para 1499" not in view.browser.toPlainText()
    TB.budget(time.monotonic() - began < 60, 'time.monotonic() - began < 60')


# -- axross-mdcat: --watch of a missing file, a closed pipe, a full disk, 6,000 images, --help -------

def test_sad_mdcat_watch_says_a_missing_file_and_waits_for_it(tmp_path):
    """--watch missing.md stayed silent for ever."""
    name = tmp_path / "later.md"
    run = subprocess.Popen([sys.executable, "-m", _cli_module(), "--watch", "--color", "never", str(name)],
                           cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import select

        ready, _w, _x = select.select([run.stderr], [], [], TB.READY_SECONDS)  # (it said nothing at all: no reading for ever)
        assert ready, "nothing said of the missing file"
        said = run.stderr.readline()
        assert "later.md" in said and "waiting for it" in said, said
        name.write_text("# Arrived\n", encoding="utf-8")
        out = ""
        began = time.monotonic()
        while "Arrived" not in out and time.monotonic() - began < TB.READY_SECONDS:
            out += run.stdout.readline()
        assert "Arrived" in out
    finally:
        run.kill()
        run.communicate(timeout=30)


def test_sad_mdcat_stops_when_its_pipe_closes(tmp_path):
    """axross-mdcat big.md | head -2 rendered all of the rest after head had gone (6.4 s of 2.7 MB)."""
    page = tmp_path / "big.md"
    page.write_text("".join(f"# Part {n}\n\n" + "para graph words here\n\n" * 400 for n in range(300)),
                    encoding="utf-8")
    run = subprocess.Popen([sys.executable, "-m", _cli_module(), "--no-pager", "--color", "always", str(page)],
                           cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run.stdout.readline()
    run.stdout.readline()
    run.stdout.close()
    began = time.monotonic()
    status = run.wait(120)
    error = run.stderr.read().decode()
    TB.budget(time.monotonic() - began < 2.0, 'time.monotonic() - began < 2.0')
    assert status == 0 and "Traceback" not in error and "BrokenPipe" not in error, error


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="no /dev/full")
@pytest.mark.parametrize("args", [["README.md"], ["--version"], ["--help"], ["--html", "README.md"]])
def test_sad_a_full_disk_is_said_not_a_traceback(args):
    from ui import markdown_app

    module = markdown_app.__name__ if args[0] == "--html" else _cli_module()
    with open("/dev/full", "w") as full:
        result = subprocess.run([sys.executable, "-m", module, "--no-pager", *args] if module == _cli_module()
                                else [sys.executable, "-m", module, *args], cwd=ROOT, stdout=full,
                                stderr=subprocess.PIPE, text=True, timeout=120,
                                env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 1 and "Traceback" not in result.stderr and "Exception ignored" not in result.stderr
    assert "cannot write the output: No space left on device" in result.stderr, result.stderr


def test_sad_mdcat_draws_200_images_of_a_text_not_200_a_part(tmp_path):
    """Each part of a long text had a cap of its own: 6,000 pictures were all drawn (193 MB of output)."""
    from PIL import Image

    from core import markdown_term as T

    Image.new("RGB", (40, 20), (200, 30, 30)).save(tmp_path / "p.png")
    text = "".join(f"Pic {n}\n\n![p{n}](p.png)\n\n" for n in range(6000))
    options = T.Options(width=80, depth="truecolor", images="blocks", folder=str(tmp_path), image_columns=20)
    shown = "".join(T.render_parts(text, options))
    assert shown.count("▀") + shown.count("▄") <= (T.IMAGES + 1) * 20 * 10
    assert shown.count(f"more than {T.IMAGES} images") == 1 and "Pic 5999" in shown


def test_sad_every_mdcat_option_has_its_help():
    from core import markdown_cli as C

    for action in C._parser()._actions:
        if action.option_strings and action.dest != "help":
            assert action.help, action.option_strings
    text = C._parser().format_help()
    for option in ("--color", "--theme", "--images", "--no-pager", "--version"):
        line = next(line for line in text.splitlines() if line.strip().startswith(option))
        assert len(line.split(option, 1)[1].strip()) > 3 or "  " in text.split(line, 1)[1][:200], option


# -- tests: the big-block guard closes its views ------------------------------------------------------

def test_sad_the_big_block_guard_closes_its_views():
    """tests/test_markdown_reader_bugs17.py's 120 cases left each view open: 1.47 GB by their end."""
    from tests import test_markdown_reader_bugs17 as B17
    from ui import markdown_view as MV

    def open_views() -> int:
        return sum(1 for widget in APP.topLevelWidgets() if isinstance(widget, MV.MarkdownView) and widget.isVisible())

    before = open_views()
    B17.test_guard_a_big_block_in_any_container_never_holds_up_the_window("top", "html_list", True)
    pump(0.1)
    assert open_views() == before


# -- the editor's preview follows the typing ---------------------------------------------------------

def test_sad_the_editor_preview_follows_the_line_typed_at():
    """Typed at line 170, the preview stayed at the top of the page."""
    from PyQt6.QtGui import QTextCursor

    from ui.editor_window import EditorWindow

    text = "".join(f"## Section {n}\n\n" + "".join(f"Line {n}.{k} words words words.\n\n" for k in range(5))
                   for n in range(20))
    window = EditorWindow()
    window.resize(1200, 700)
    window.show()
    tab = window.new_tab()
    try:
        tab.editor.setPlainText(text)
        tab.set_preview(True)
        preview = tab.preview
        assert until(lambda: preview._readable and "Section 19" in preview.browser.toPlainText(), 60)
        pump(0.3)
        assert preview.browser.verticalScrollBar().value() == 0
        cursor = tab.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.movePosition(QTextCursor.MoveOperation.Down, n=170)
        tab.editor.setTextCursor(cursor)
        tab.editor.insertPlainText("typed ")
        assert until(lambda: "typed" in preview.browser.toPlainText(), 60)
        assert TB.until_within(until, lambda: preview.browser.verticalScrollBar().value() > 0, 10)
        pump(0.3)
        bar, document = preview.browser.verticalScrollBar(), preview.browser.document()
        found = document.find("typed")
        rect = document.documentLayout().blockBoundingRect(found.block())
        assert bar.value() <= rect.top() <= bar.value() + preview.browser.viewport().height(), \
            (bar.value(), rect.top())
    finally:  # (closed without its question: a modal dialog no test leaves)
        tab.editor.document().setModified(False)
        window.close()


def test_sad_heading_lines_are_found_outside_code():
    from ui import markdown_view as MV

    rows = "# A\n\ntext\n\n```\n# not\n```\n\nTitle\n=====\n\n- item\n---\n\n## B\n".split("\n")
    assert MV._heading_lines(rows) == [0, 8, 14]


# -- PDF: a box going on to the next page stays between the margins ----------------------------------

def test_sad_pdf_an_alert_across_a_page_break_keeps_out_of_the_margins(tmp_path):
    """An alert crossing a page break had its ground drawn on through the bottom margin, under the
    page's number, and at the next page's top an empty grey piece of it."""
    QtPdf = pytest.importorskip("PyQt6.QtPdf")
    from PyQt6.QtCore import QSize

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    text = "".join(f"Paragraph {n} with some words to fill the page, words and words and words.\n\n" for n in range(22))
    text += "> [!NOTE]\n" + "".join(f"> Note line {n} of the alert, long enough to wrap a little.\n>\n"
                                    for n in range(12)) + "\nAfter.\n"
    page = tmp_path / "alert.md"
    page.write_text(text, encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.show()
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 60)
    target = str(tmp_path / "alert.pdf")
    assert viewer.export_pdf(target) == target
    document = QtPdf.QPdfDocument(None)
    document.load(target)
    assert document.pageCount() == 2
    tinted = []
    for number in range(2):
        size = document.pagePointSize(number).toSize()
        image = document.render(number, QSize(size.width(), size.height()))
        margin = round(2 / 2.54 * 72) - 2  # (2 cm, in points: the image's pixels)
        rows = range(image.height() - margin + 2, image.height()) if number == 0 else range(0, margin - 2)
        for y in rows:
            for x in range(0, image.width(), 3):
                colour = image.pixelColor(x, y)
                if colour.alpha() > 40 and min(colour.red(), colour.green(), colour.blue()) > 200 \
                        and colour.red() + colour.green() + colour.blue() < 3 * 252:
                    tinted.append((number, x, y))
    assert not tinted, tinted[:5]


# -- the zoom button says the zoom level --------------------------------------------------------------

def test_sad_the_zoom_button_shows_the_level_the_text_is_at(tmp_path):
    """"100%" stayed "100%" at any size: a label that looked like the level but was a reset button."""
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "a.md"
    page.write_text("# Zoom\n\nSome text.\n", encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.show()
    assert until(lambda: viewer.view._readable and viewer.view.markdown, TB.READY_SECONDS)
    assert viewer.zoom_reset.text() == "100%"
    viewer.view.zoom_by(2)
    larger = int(viewer.zoom_reset.text().rstrip("%"))
    assert larger > 100 and larger == viewer.view.zoom_percent()
    viewer.view.zoom_by(-4)
    assert int(viewer.zoom_reset.text().rstrip("%")) < 100
    viewer.zoom_reset.click()
    assert viewer.zoom_reset.text() == "100%" and viewer.view.zoom == 0
    assert "original size" in viewer.zoom_reset.toolTip()


# -- packaging: the program answers as each of its children --------------------------------------------

@pytest.mark.parametrize("worker, module", [("--lex-worker", "lex_worker"), ("--image-worker", "image_worker"),
                                            ("--svg-worker", "svg_worker")])
def test_sad_the_program_answers_as_each_child_it_starts(worker, module, monkeypatch):
    """A frozen build starts its children as itself (core.lex_worker: "--lex-worker"): axross-markdown
    answered only --svg-worker - the editor's highlighting child of a one-file build was the viewer again."""
    import importlib

    from ui import markdown_app

    child = importlib.import_module(markdown_app.__name__.rsplit(".ui.", 1)[0] + f".core.{module}"
                                    if ".ui." in markdown_app.__name__ else f"core.{module}")
    monkeypatch.setattr(child, "_child_main", lambda: 42)
    assert markdown_app.main(["axross-markdown", worker, "1", "2", "3", "4"]) == 42


# -- code blocks lexed in a child: a lexer stuck in backtracking never holds the reader ----------------

# A Python lexer whose first token runs a catastrophic match (~2.5 s) on a text with HOSTILE - in the
# lexing child and in this process (as tests/test_code_editor_lex_child.py's).
_HOSTILE = r'''
import re as _re
from pygments.lexers import python as _python
_real = _python.PythonLexer.get_tokens_unprocessed
def _slow(self, text, *args):
    if "HOSTILE" in text:
        _re.match(r"(a+)+$", "a" * 25 + "b")
    return _real(self, text, *args)
_python.PythonLexer.get_tokens_unprocessed = _slow
'''
HOSTILE_PAGE = "# Code\n\n```python\nHOSTILE = 1\ndef f(x):\n    return x\n```\n\nAfter.\n"


@pytest.fixture
def hostile_lexer(monkeypatch, tmp_path):
    from core import lex_worker as LW
    from core import markdown_doc as MD

    script = tmp_path / "hostile_lexer.py"
    script.write_text(_HOSTILE + LW._CHILD_SOURCE)
    real = LW.worker_argv
    monkeypatch.setattr(LW, "worker_argv", lambda *a, **kw: [sys.executable, "-I", str(script), *real(*a, **kw)[-4:]])
    from pygments.lexers import python as py

    monkeypatch.setattr(py.PythonLexer, "get_tokens_unprocessed", py.PythonLexer.get_tokens_unprocessed)
    exec(compile(_HOSTILE, "<hostile>", "exec"), {})
    monkeypatch.setattr(MD, "CODE_LEX_SECONDS", 1.0, raising=False)
    closed = getattr(MD, "close_code_pools", lambda: None)
    closed()
    yield
    closed()


def test_sad_a_lexer_stuck_in_backtracking_leaves_the_terminal_and_the_export_plain(hostile_lexer):
    """The reader lexed code in its own process: a lexer's regular expression stuck in backtracking held
    the thread (and Python's lock) as long as it ran. Now in a child, ended past CODE_LEX_SECONDS: plain."""
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_html as H

    began = time.thread_time()
    shown = T.render(HOSTILE_PAGE, T.Options(width=80, depth="truecolor"))
    page = H.export_html(MD.parse(HOSTILE_PAGE))
    TB.budget(time.thread_time() - began < 1.0, time.thread_time() - began)
    assert "HOSTILE = 1" in T._strip_ansi(shown) and "After." in shown
    assert "HOSTILE = 1" in page and "After." in page


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_lexer_stuck_in_backtracking_never_holds_the_window(hostile_lexer, full):
    from ui import markdown_view as MV

    _settle()
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    pump(0.1)
    turns = _Turns()
    view.render(HOSTILE_PAGE)
    assert until(lambda: view._readable and view.markdown, 60)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 60)
    pump(0.5)
    TB.budget(turns.stop() < 0.25, 'turns.stop() < 0.25')
    assert "HOSTILE = 1" in view.browser.toPlainText() and "After." in view.browser.toPlainText()


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_happy_code_is_still_coloured_lexed_in_a_child(full):
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_html as H

    text = "```python\ndef f(x):\n    return x  # note\n```\n"
    terminal = T.render(text, T.Options(depth="truecolor"))
    assert "\x1b[" in terminal.split("def")[0] and "def f(x)" in T._strip_ansi(terminal)
    body = H.export_html(MD.parse(text)).split("<article", 1)[1]
    assert "<span style" in body.split("f(x)")[0]
    view = _view(text, full)
    document = view.browser.document()
    keyword = document.find("def")
    if full:
        colour = keyword.charFormat().foreground().color().name()
        plain = document.find("(x)").charFormat().foreground().color().name()
        assert colour != plain
    else:
        layout = keyword.block().layout()
        assert any(f.start == 0 and f.length == 3 for f in layout.formats()), "no colour on the keyword"


def test_sad_mdcat_answers_as_its_lexing_child(monkeypatch):
    """A frozen axross-mdcat (axross-mdcat.exe) starts its lexing child as itself: "--lex-worker" was taken
    for a file's name."""
    from core import lex_worker as LW
    from core import markdown_cli as C

    monkeypatch.setattr(LW, "_child_main", lambda: 7)
    assert C.main(["--lex-worker", "/x", "1", "2", "3"]) == 7
