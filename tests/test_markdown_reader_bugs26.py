"""The twenty-sixth round of the Markdown reader (the twenty-fifth review, axross-markdown 0.16.11 at 7.5/10):
Export PDF and Print laying out an HTML block of 2 MB in one turn (R1); a block tag's long line escaped in
one call that held Python's lock (R2); a literal "<!--" in prose hiding the rest of the page in Qt's own
parser (R3); a copy after Ctrl+End stuck at "Copying… 0%" (R4); the export's memory, the emoji scan for a
"©", the zoom's clear() of a page read to its end (R5: M1, M2, M4); a link to a missing anchor laying out
all of a big page (R6); Find and zoom on a code block of 1,000,000 lines (R7); a resize, a theme switch
with many image boxes and highlighted code weighed by its lines only (R8); the 1,000 rows of long cells
that failed the suite in one process (R9); Find's marks after a reload (L2); GFM's 626, 645 and 146.

Each test here failed before. "Gap" is the heartbeat's (tests/markdown_heartbeat.py): the longest time the
window did not answer.
"""

from __future__ import annotations

import base64
import gc
import os
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

from tests import markdown_heartbeat as HB  # noqa: E402
from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests.test_markdown_reader_bugs20 import _Turns  # noqa: E402
from tests.test_markdown_reader_bugs22 import PARSERS, _closed_after, within_turn  # noqa: E402,F401
from tests.test_markdown_reader_bugs24 import _opened, _shown_md4c, _viewer  # noqa: E402
from tests.test_markdown_reader_bugs25 import _rss, _sections  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _quick(call, seconds: float) -> None:
    began = time.process_time()
    call()
    took = time.process_time() - began
    TB.budget(took < seconds * HB.machine_factor(), took)


def _exported(viewer, action: str, target: str, seconds: float = 3.0) -> float:
    """The window's longest gap while *action* ("pdf", "print", "html") of *viewer*'s page runs - cancelled
    after *seconds* (a big text's parts are alike: its making and its first parts measured)."""
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QProgressDialog

    def cancel() -> None:
        for dialog in viewer.findChildren(QProgressDialog):
            if not dialog.wasCanceled():
                dialog.cancel()

    stopper = QTimer()
    stopper.setSingleShot(True)
    stopper.timeout.connect(cancel)
    beat = HB.Heartbeat()
    stopper.start(int(seconds * 1000))
    if action == "pdf":
        viewer.export_pdf(target)
    elif action == "html":
        viewer.export_html(target)
    else:
        from PyQt6.QtPrintSupport import QPrinter

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(target)
        viewer._print_to(printer, "Printing…")
    stopper.stop()
    pump(0.1)
    return beat.stop()[1]


# -- R1: Export PDF and Print in parts as the window's ------------------------------------------------------

#: R1's texts: an HTML block of 2 MB, of many lines and of one.
HTML_BLOCKS = {
    "a <p> of 18,000 lines": lambda: "<p>\n" + ("plain words here and there " * 4 + "\n") * 18000,
    "a <div> of one line": lambda: "<div>\n" + "word *em* " * 200000,
}


@pytest.mark.parametrize("name", sorted(HTML_BLOCKS))
def test_sad_print_parts_parses_a_piece_at_a_time_its_parts_as_the_window_s(name, monkeypatch):
    """print_parts parsed all of the text at once: an HTML block of 2 MB was one token and one part of
    1,962,005 characters (the window: 298 parts of 218 KB at most) - and every token of a text was alive
    until the export ended (4 MB: 700 MiB more)."""
    from core import markdown_doc
    from ui import markdown_view as MV

    text = HTML_BLOCKS[name]()
    parsed = []
    real = markdown_doc.parse
    monkeypatch.setattr(markdown_doc, "parse", lambda piece, *a, **k: (parsed.append(len(piece)), real(piece, *a,
                                                                                                        **k))[1])
    kind, parts = MV.print_parts(text, True)
    assert kind == "html" and len(parsed) > 10 and max(parsed) < len(text) // 5, (len(parsed), max(parsed))
    assert len(parts) > 10 and max(map(len, parts)) < 300_000, (len(parts), max(map(len, parts)))


def test_sad_the_pieces_number_headings_and_notes_across_the_text():
    """Parsed in pieces, the headings' anchors and the notes are numbered as one parse numbers them."""
    from ui import markdown_view as MV

    text = "".join(f"## Intro\n\nPara {i}[^n{i}] " + "word " * 40 + "\n\n" for i in range(3000)) + "".join(
        f"[^n{i}]: note {i}\n" for i in range(3000))
    docs = list(MV.parsed_pieces(text))
    assert len(docs) > 3
    anchors = [heading.anchor for doc in docs for heading in doc.headings]
    assert anchors[:3] == ["intro", "intro-1", "intro-2"] and len(set(anchors)) == 3000 == len(anchors)
    _kind, parts = MV.print_parts(text, True)
    joined = "".join(parts)
    assert 'name="intro-2999"' in joined and "note 2999" in joined and "note 0" in joined


@pytest.mark.parametrize("action", ["pdf", "print"])
def test_sad_export_pdf_and_print_of_a_2_mb_html_block_keep_the_window_answering(action, tmp_path):
    """Before: Export PDF 0.698 s in one turn (gap 0.699 s), Print 0.717 s - markdown-it's page, the
    standalone's default."""
    text = HTML_BLOCKS["a <p> of 18,000 lines"]()
    viewer = _viewer(tmp_path, text, True)
    gap = _exported(viewer, action, str(tmp_path / f"page-{action}.pdf"))
    viewer.close()
    HB.assert_responsive(gap, ("R1", action))


def test_sad_export_html_parses_a_piece_at_a_time_and_writes_the_page_whole(tmp_path, monkeypatch):
    """M1: Export HTML parsed all of the text into one token tree (4 MB: 849 MiB at its peak). A piece at a
    time now - the page the same: every heading, its anchor numbered on, every note."""
    from core import markdown_doc

    text = "".join(f"## Intro\n\nPara {i}[^n{i}] ![p](pic.png)\n\n" for i in range(4000)) + "".join(
        f"[^n{i}]: note {i}\n" for i in range(4000))
    (tmp_path / "pic.png").write_bytes(base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="))
    viewer = _viewer(tmp_path, text, True)
    parsed = []
    real = markdown_doc.parse
    monkeypatch.setattr(markdown_doc, "parse", lambda piece, *a, **k: (parsed.append(len(piece)), real(piece, *a,
                                                                                                        **k))[1])
    target = str(tmp_path / "page.html")
    assert viewer.export_html(target) == target
    page = Path(target).read_text(encoding="utf-8")
    viewer.close()
    assert len(parsed) > 3 and max(parsed) < len(text) // 2, parsed
    assert page.startswith("<!DOCTYPE html>") and page.rstrip().endswith("</html>")
    assert page.count('id="intro') == 4000 and 'id="intro-3999"' in page and "note 3999" in page
    assert page.count("data:image/png;base64,") >= 4000 and page.count("<title>") == 1


def test_sad_an_export_of_markdown_it_s_page_holds_a_piece_s_tokens_at_a_time(tmp_path):
    """M1: markdown-it's exports held the token tree of all of the text (4.1 MB: Export PDF 819 MiB at its
    peak, +703 MiB; Export HTML 849 MiB). 20,000 sections' Export HTML here: +294 MiB before, +18 MiB now
    (Export PDF and Print parse as it does: parsed_pieces)."""
    if not os.path.exists("/proc/self/statm"):
        pytest.skip("no /proc")
    import threading

    viewer = _viewer(tmp_path, _sections(20000), True)
    peak, stop = [0], []

    def watch() -> None:
        while not stop:
            peak[0] = max(peak[0], _rss())
            time.sleep(0.02)

    gc.collect()
    before = _rss()
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    target = str(tmp_path / "page.html")
    try:
        assert viewer.export_html(target) == target
    finally:
        stop.append(True)
        watcher.join()
    viewer.close()
    grown = (peak[0] - before) / 2 ** 20
    assert grown < 100, grown
    assert "H19999" in Path(target).read_text(encoding="utf-8")


# -- R2: a block tag's long line ---------------------------------------------------------------------------

def test_sad_a_block_tag_s_long_line_is_escaped_in_pieces_as_at_once():
    """_html_blocks escaped a line under "<div>" in one call (_LITERAL_MARKS.sub): 2 MB of "* " held
    Python's lock 0.32 s. In pieces now, the same text."""
    from ui import markdown_view as MV

    for row in ("* " * 50000, "<b>*a*</b> `x` " * 4000 + "<" + "_" * 9000, "a<b" * 5000, "<" * 9000 + "*"):
        old = "".join(tag or MV._LITERAL_MARKS.sub(r"\\\1", words) for tag, words in MV._TAG_OR_TEXT.findall(row))
        assert MV._literal_row(row) == old
    calls = []
    real = MV._LITERAL_MARKS

    class Counted:
        def sub(self, repl, text):
            calls.append(len(text))
            return real.sub(repl, text)

    MV._LITERAL_MARKS = Counted()
    try:
        MV._html_blocks("<div>\n" + "* " * 200000 + "\n")
    finally:
        MV._LITERAL_MARKS = real
    assert calls and max(calls) <= MV.LITERAL_PIECE, max(calls)


def test_sad_an_ascii_text_is_searched_for_no_picture_sign(monkeypatch):
    """The picture signs' class (thousands of ranges, tried at each letter) was searched in all of a text of
    2 MB of ASCII in one call, three times (0.08 s each of Python's lock) - after R2's escape the longest
    calls left of a block tag's long line. ASCII has none."""
    from ui import markdown_view as MV

    searched = []
    real = MV._PICTURE_SIGNS

    class Counted:
        def __getattr__(self, name):
            def call(text, *args):
                searched.append((name, len(text)))
                return getattr(real, name)(text, *args)
            return call

    monkeypatch.setattr(MV, "_PICTURE_SIGNS", Counted())
    text = "<span>\n" + "* " * 100000
    MV.renderable(text)
    MV.paragraph_pieces("word " * 100000)
    assert not [call for call in searched if call[1] > 10_000], searched[:5]


@pytest.mark.parametrize("text", ["<div>\n" + "* " * 1000000, "<span>\n" + "* " * 1000000],
                         ids=["a div's", "a lone tag's"])
def test_sad_a_block_tag_s_line_of_2_mb_freezes_no_window(tmp_path, text):
    """Before (Qt's own parser): the window frozen 0.320 s (a <div>'s) and 0.313 s (a lone tag's) as it
    opened."""
    _turn, gap = _opened(tmp_path, text, False)
    HB.assert_responsive(gap, ("R2", text[:6]))


# -- R3: comments and processing instructions as GFM reads them --------------------------------------------

@pytest.mark.parametrize("text, wanted", [
    ("Type <!-- to begin a comment.\n\nNext paragraph.\n\n# Heading\n\nMore.\n",
     "Type <!-- to begin a comment. Next paragraph. Heading More."),
    ("Use `<!--` in code, then <!-- here\n\nLater text\n", "Use <!-- in code, then <!-- here Later text"),
    ("text <!-- a\n\nb --> end\n", "text <!-- a b --> end"),
    ("a <?x  b\n\nc ?> d\n", "a <?x b c ?> d"),
    ("> a <!-- b\n>\n> c --> d\n", "a <!-- b c --> d"),
    ("foo <!--> foo -->\n", "foo foo -->"),  # (the spec's 645: "<!-->" a comment whole)
    ("<!-- foo -->*bar*\n*baz*\n", "*bar* baz"),  # (146: the rest of the end's line the block's, as written)
    ("a <!-- x --> b <?p q ?> c\n", "a b c"),  # (closed in its paragraph: hidden, as before)
    ("<!-- open\n\nhidden\n\n# hidden too\n", ""),  # (at a block's start, never closed: to the end, as GFM)
    ("para\n<!-- c\nd -->\nafter\n", "para after"),
])
def test_sad_qt_s_own_parser_hides_a_comment_only_where_gfm_does(text, wanted):
    """_drop_comments hid all after a "<!--" never closed, wherever it was ("Type <!-- to begin a comment."
    showed "Type" alone, its heading gone too), and looked for a closer across paragraphs."""
    shown = " ".join(_shown_md4c(text).split())
    assert shown == wanted, (text, shown)


def test_sad_openers_never_closed_are_read_in_one_pass():
    """The search for a closer went to the text's end from each opener: "<?x" 50,000 times, 1.2 s of the
    pattern alone (quadratic)."""
    from ui import markdown_view as MV

    for text in ("a <?x " * 50000, "<?x\n" * 50000, "a <!-- b\n\n" * 30000, "x <![CDATA[ " * 40000):
        _quick(lambda: MV._drop_comments(text), 0.3)
    assert MV._drop_comments("a <?x b") == "a \\<?x b"


# -- R4: a copy after Ctrl+End ---------------------------------------------------------------------------

def test_sad_a_copy_asked_for_during_ctrl_end_is_made():
    """Ctrl+End, then select-all and Copy within 0.1 s: the jump's layout took the selection away, the
    copy that waited for the text to be parsed found none - "Copying… 0%" for good, the clipboard empty."""
    from ui import markdown_view as MV

    QApplication.clipboard().setText("")
    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    view.render(_sections(6000))
    assert until(lambda: view._readable and view.markdown, 120)
    assert until(lambda: view.status.text().startswith("Shown"), 120)
    assert view.more()
    view.go_end()
    pump(0.03)
    view.browser.selectAll()
    view.copy_selection()
    assert until(lambda: not view._copying(), 240), view.status.text()
    copied = QApplication.clipboard().text()
    view.close()
    assert "H0" in copied and "H5999" in copied, len(copied)
    assert "Copying" not in view.status.text()


def test_sad_a_waiting_copy_whose_selection_is_gone_says_so():
    """Nothing left to copy when the text is parsed: said - the status line kept "Copying… 0%"."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    view.render(_sections(6000))
    assert until(lambda: view._readable and view.markdown, 120)
    view._copy_waiting, view._copy_wanted = True, None
    view.copy_selection()
    assert not view._copying() and "Copying" not in view.status.text()
    view.close()


# -- R5: M2, the emoji scan for a "©" -------------------------------------------------------------------

def test_sad_a_copyright_sign_or_a_trade_mark_wants_no_emoji_scan():
    """_emoji_signs counted every character of a short code's emoji: "Copyright © 2026" made a three-line
    file wait 0.32 to 0.44 s for the scan on a machine of 2,000 fonts."""
    from ui import markdown_view as MV

    for text in ("Copyright © 2026 someone", "# Name™", "‼ ℹ ↔ ™ ® ©", "❤ heart"):
        assert not MV.wants_emoji(text), text
    for text in ("©️", "❤️", "✅ done", "⭐", "1️⃣", "\U0001F600", ":tada:"):
        assert MV.wants_emoji(text), text


# -- R5: M4, a zoom of a page read to its end ------------------------------------------------------------

def test_sad_a_zoom_on_10_000_sections_read_to_their_end_holds_no_turn(tmp_path):
    """The zoom's clear() of the page laid out whole: 0.16 to 0.195 s in one turn (markdown-it's page). A
    fresh document now, the old one let go of a piece a turn."""
    text = _sections(10000)

    def measure() -> float:
        viewer = _viewer(tmp_path, text, True)
        view = viewer.view
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 300)
        pump(0.3)
        old = view.browser.document()
        turns = _Turns()
        view.zoom_by(1)
        until(lambda: view._readable and not view._scheduled, 120)
        assert until(lambda: not view._old_documents, 60)
        pump(0.2)
        longest = turns.stop()
        from PyQt6 import sip

        assert sip.isdeleted(old) and view.zoom_percent() > 100
        assert view.browser.document().indentWidth() == old_indent[0]
        viewer.close()
        return longest

    old_indent = [__import__("ui.markdown_view", fromlist=["LIST_INDENT"]).LIST_INDENT]
    within_turn(measure, text, "M4 zoom")


# -- R6: a link to a missing anchor ------------------------------------------------------------------------

@PARSERS
def test_sad_a_missing_anchor_is_said_at_once(full):
    """A link to "#nope" on a page of 100,000 headings laid out all of it first (Qt's own parser: still at
    "Rendering… 84 %" after 120 s; markdown-it's 42 s) - its parts' headings say it is nowhere."""
    from ui import markdown_view as MV

    text = "[none](#nope)\n\n" + "".join(f"## h{i}\n\npara {i} word word word\n\n" for i in range(30000)) \
        + "Under\n=====\n\ntext\n"
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    until(lambda: not view._scheduled, 60)
    assert view.more()
    began = time.monotonic()
    view.go_to_anchor("nope")  # (the texts not parsed yet read on a worker: said when it is done)
    assert TB.until_within(until, lambda: "#nope" in view.status.text(), 10), view.status.text()
    TB.budget(time.monotonic() - began < 5 * HB.machine_factor(), 'time.monotonic() - began < 5 * HB.machine_factor()')
    assert view.more() and not view._whole  # (nothing laid out for it)
    for name in ("h29000", "under"):  # (a heading far on, an underlined one: found)
        view.go_to_anchor(name)
        assert until(lambda: name in view.anchors, 240), name
    view.close()
    # (a heading in a quote or an item - the outline reads the top level's only -: all of it laid out first)
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    view.render(text + "\n- > ## nested\n")
    assert until(lambda: view._readable and view.markdown, 120)
    until(lambda: not view._scheduled, 60)
    view.go_to_anchor("nested")
    assert until(lambda: "nested" in view.anchors, 240)
    view.close()


# -- R7: Find and zoom on a code block of 1,000,000 lines ---------------------------------------------------

@PARSERS
def test_sad_find_and_zoom_on_a_long_code_block_laid_out_hold_no_turn(tmp_path, full):
    """Qt's find read every block of the page when the needle was not there: 1,000,000 lines, Find 0.85 s
    a turn (Qt's own parser), 0.38 s (markdown-it); 200,000 lines 0.12 s. The zoom's clear() 0.29 to 0.35 s.
    The page's text is looked in now, the document swapped."""
    text = "```python\n" + "x = 1\n" * 200000 + "```\n"

    def measure() -> float:
        viewer = _viewer(tmp_path, text, full)
        view = viewer.view
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 600)
        pump(0.3)
        turns = _Turns()
        for typed in ("`", "``", "```", "```p", "```py", "```pyt"):
            viewer.find_field.setText(typed)
            pump(0.05)
        viewer.find_next()
        pump(0.05)
        viewer.find_next()
        pump(0.1)
        assert viewer.find_count.text() == "no match"
        viewer.find_field.setText("x = 1")
        pump(0.1)
        viewer.find_next()
        pump(0.1)
        assert viewer.view.browser.textCursor().selectedText().lower() == "x = 1"
        view.zoom_by(1)
        until(lambda: view._readable and not view._scheduled, 120)
        pump(0.2)
        longest = turns.stop()
        viewer.close()
        return longest

    within_turn(measure, text, ("R7", full))


def test_sad_find_in_the_page_s_text_finds_what_qt_s_find_finds():
    """The page's text a character a position (toPlainText's), in lower case - Qt's find for a needle case
    folding reads otherwise (a final sigma): the same matches - a table's cells, an image, a line break in a
    cell, forward and backward."""
    from PyQt6.QtGui import QTextCursor, QTextDocument

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(900, 700)
    view.show()
    view.render("# ΣΟΦΟΣ\n\nσοφος and Straße\n\n| a | b<br>c |\n|---|---|\n| x ![i](n.png) | ab |\n\n" * 30)
    assert until(lambda: view._readable and not view._scheduled, 60)
    document = view.browser.document()
    for needle in ("σοφος", "ΣΟΦΟΣ", "straße", "ab", "b", "x", "c", "nope"):
        for backward in (False, True):
            flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start)
            for _ in range(40):
                qt, ours = document.find(needle, cursor, flags), view._find_laid(needle, cursor, flags)
                assert (qt.isNull(), qt.selectionStart(), qt.selectionEnd()) == \
                    (ours.isNull(), ours.selectionStart(), ours.selectionEnd()), (needle, backward)
                if qt.isNull():
                    break
                cursor = qt
    places = [start for start, _end in view.laid_matches("ab")]
    found, cursor = [], document.find("ab", 0)
    while not cursor.isNull():
        found.append(cursor.selectionStart())
        cursor = document.find("ab", cursor)
    assert places == found and len(places) == 30
    view.close()


def test_sad_the_page_s_text_is_read_again_from_where_it_changed_only(monkeypatch):
    """_may_hold read all of the page (toPlainText) after each part a find laid out: 0.013 s of each turn of
    a table of 1,000 rows of long cells (R9's case, which failed the suite in one process)."""
    from PyQt6.QtGui import QTextCursor

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(900, 700)
    view.show()
    view.render("".join(f"Para {n} with words.\n\n" for n in range(3000)))
    assert until(lambda: view._readable and not view._scheduled, 60)
    document = view.browser.document()
    whole = view._laid_text()[0]
    assert whole == document.toPlainText()
    cursor = QTextCursor(document)
    cursor.movePosition(QTextCursor.MoveOperation.End)
    cursor.insertText("\nmore ΣΟΦΟΣ text")
    read = []
    real = MV.QTextDocument.toPlainText
    monkeypatch.setattr(MV.QTextDocument, "toPlainText", lambda self: (read.append(1), real(self))[1])
    plain, folded = view._laid_text()
    assert not read and plain == real(document) and folded.endswith("more σοφος text")
    view.close()


def test_sad_a_piece_that_begins_inside_a_big_table_cuts_it_at_each_later_part():
    """A long text's piece (markdown-it's page, a print) that began inside a big table made none of its table's
    later parts a part of its own - two to a part, 58 KB of long cells laid out in one turn (bugs22's 1,000
    rows of long cells: the window's Find 0.098 s, Export PDF 0.12 s a turn)."""
    from core import markdown_doc
    from core.markdown_term import text_parts_at
    from ui import markdown_view as MV

    text = "| a | b |\n|---|---|\n" + f"| {'x' * 1800} | {'y' * 1800} |\n" * 1000
    shown = markdown_doc.clean(MV.renderable(text, MV.TABLE_CELLS)[0])
    pieces = [piece for piece, _line in text_parts_at(shown)]
    assert len(pieces) > 3 and pieces[1].lstrip("|").startswith(MV.CHUNK)
    parts = MV._page(pieces[1], False)[0]
    assert len(parts) > 2 and max(map(len, parts)) < 40_000, sorted(map(len, parts))[-3:]
    _kind, printed = MV.print_parts(text, True)
    assert max(map(len, printed)) < 40_000, sorted(map(len, printed))[-3:]


# -- R8: a resize, a theme switch, highlighted code ----------------------------------------------------

def test_sad_a_resize_of_10_000_sections_read_to_their_end_holds_no_turn(tmp_path):
    """Qt laid all of the page out again at the new width in one turn: 0.19 s a step of a drag
    (markdown-it's page). A part a turn now, as a zoom."""
    text = _sections(10000)

    def measure() -> float:
        viewer = _viewer(tmp_path, text, True)
        view = viewer.view
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 300)
        pump(0.3)
        turns = _Turns()
        for width in (900, 1300, 700):
            viewer.resize(width, 800)
            pump(0.4)
            until(lambda: view._readable and not view._scheduled, 120)
        longest = turns.stop()
        assert view.browser.lineWrapColumnOrWidth() < 600
        viewer.close()
        return longest

    within_turn(measure, text, "R8 resize")


@PARSERS
def test_sad_a_theme_switch_paints_image_boxes_again_without_laying_out_the_page(tmp_path, full):
    """_repaint_placeholders laid all of the page out again for boxes of the sizes they had: 11,838 boxes,
    0.31 s of a theme switch's 0.62 s turn (markdown-it); 6,000 here, 0.21 s."""
    from PyQt6.QtGui import QColor, QPalette

    text = "".join(f"## H{i}\n\nPara *{i}* ![img{i}](x{i % 150}.png) with `code`.\n\n" for i in range(6000))

    def measure() -> float:
        viewer = _viewer(tmp_path, text, full)
        view = viewer.view
        view.load_rest_now()
        assert until(lambda: not view.more() and not view._scheduled, 300)
        pump(1.0)
        dark = QPalette()
        for role, colour in ((QPalette.ColorRole.Window, "#202020"), (QPalette.ColorRole.Base, "#101010"),
                             (QPalette.ColorRole.Text, "#eeeeee"), (QPalette.ColorRole.WindowText, "#eeeeee")):
            dark.setColor(role, QColor(colour))
        turns = _Turns()
        viewer.setPalette(dark)
        pump(0.1)
        until(lambda: view._readable and not view._scheduled, 120)
        pump(0.3)
        longest = turns.stop()
        assert view.dark
        viewer.close()
        return longest

    within_turn(measure, text, ("R8 theme", full))


def test_sad_highlighted_code_weighs_its_spans_too():
    """_weight counted a fence's lines and letters, not its colours: two blocks of 233 lines and 1,991 spans
    were a part with lists and tables around them, 0.3 s to lay out."""
    from core import markdown_doc
    from ui import markdown_html as H

    code = "".join(f"a{n}=b[c].d(e,f)+g*h-i/j;k\n" for n in range(60))
    plain, coloured = (markdown_doc.parse(f"```{lang}\n{code}```\n").tokens[0] for lang in ("", "python"))
    assert H._weight(coloured, 200) > H._weight(plain, 200) + 100
    huge = markdown_doc.parse("```python\n" + code * 2000 + "```\n").tokens[0]
    _quick(lambda: H._weight(huge, 200), 0.05)


# -- L2: Find's marks after the page is made anew ----------------------------------------------------------

def test_sad_find_s_count_and_marks_follow_a_reload(tmp_path):
    """The count said "1 of 959+" of a file that no longer had the word, and the old marks were set again at
    every scroll (empty)."""
    viewer = _viewer(tmp_path, "".join(f"para {n} has a word here\n\n" for n in range(3000)), False)
    viewer.find_field.setText("word")
    pump(0.5)
    viewer.find_next()
    pump(0.2)
    assert "+" in viewer.find_count.text() or "of" in viewer.find_count.text()
    viewer.view.render("".join(f"para {n} has nothing here\n\n" for n in range(3000)))
    assert until(lambda: viewer.view._readable and not viewer.view._scheduled, 60)
    pump(0.2)
    assert viewer.find_count.text() == "no match" and not viewer._marks
    viewer.view.browser.verticalScrollBar().setValue(500)
    pump(0.1)
    assert not viewer.view.browser.extraSelections()
    viewer.close()


# -- L1: the spec's 626 ----------------------------------------------------------------------------------

def test_sad_qt_s_own_parser_keeps_a_www_link_s_character_reference_as_text():
    """GFM's 626: "www.google.com/search?q=commonmark&hl;" - Qt's own parser's own link of it lost the ";".
    The link without "&hl;", the reference as text."""
    from ui import markdown_view as MV

    text = "www.google.com/search?q=commonmark&hl;\n"
    assert " ".join(_shown_md4c(text).split()) == "www.google.com/search?q=commonmark&hl;"
    shown = MV.fallback_text(text)
    # (its address without "<…>": an autolink to a later pass, the href "[http://…](http://…)" - review 27's N4)
    assert "(http://www.google.com/search?q=commonmark)&hl;" in shown, shown
