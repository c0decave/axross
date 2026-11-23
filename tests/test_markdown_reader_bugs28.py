"""The twenty-eighth round of the Markdown reader (what the twenty-seventh review left open, axross-markdown
0.17.3): the comment rules of Qt's own parser (N2), the editor's preview made anew by a move of the cursor.

Each test here failed before.
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
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _view(text: str, full: bool):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable, TB.READY_SECONDS)
    until(lambda: not view._scheduled, 30)
    return view


def _shown(text: str, full: bool) -> str:
    view = _view(text, full)
    shown = " ".join(view.browser.document().toPlainText().split())
    view.close()
    view.deleteLater()
    return shown


# -- N2: comments and raw HTML in Qt's own parser, as GFM reads them --------------------------------------------

COMMENT_PAGES = [
    # (an HTML block only up to three columns in after the containers' marks)
    ("para\n    <!-- x\n\nafter\n", "para <!-- x after"),
    (">     <!-- x\n\nafter\n", "<!-- x after"),
    # (an inline comment's paragraph ends at a line that interrupts one)
    ("text <!-- a\n# Heading\nb --> end\n", "text <!-- a Heading b --> end"),
    ("text <!-- a\nHeading\n---\nb --> end\n", "text <!-- a Heading b --> end"),
    ("text <!-- a\n***\nb --> end\n", "text <!-- a b --> end"),
    ("text <!-- a\n<div>\nb --> end\n", "text <!-- a b --> end"),
    ("- item <!-- a\n- item2 --> b\n", "item <!-- a item2 --> b"),
    ("> a <!-- b\n> > c --> d\n", "a <!-- b c --> d"),
    # (in a table's row: in its cell)
    ("| a | b |\n|---|---|\n| c <!-- x | d |\n| e --> | f |\n", "a b c <!-- x d e --> f"),
    # (never closed at the top level: to the text's end, code blocks too)
    ("<!-- never closed\n\ntext\n\n```\ncode\n```\n\nmore\n", ""),
    # (in an attribute's value: the tag's)
    ('<a href="x<!--y">l</a> z --> w\n', "l z --> w"),
    # (an HTML block's lines as written: no list, no quote, no list item after a comment or a script)
    ("<div>\n- a *b*\n> q _c_\n</div>\n", "- a *b* > q _c_"),
    ("<!-- x -->1. *bar*\n", "1. *bar*"),
    ("<script>x</script>1. *bar*\n", "1. *bar*"),
    # (in a container, the block ends with it, closed or not)
    ("> <!-- a\n\nafter\n", "after"),
    ("- <!-- a\n\nafter\n", "after"),
    ("1. <!-- a\n\nafter\n", "after"),
    ("- x\n  <!-- y\n\nafter\n", "x after"),
    ("> a\n> <!-- b\n\nafter\n", "a after"),
    ("> <!-- a\n> b -->\n> c\n\nafter\n", "c after"),
    # (a comment opened on the line a block's end is on hides that line's rest only)
    ("<!-- a --> <!-- b\n\nvisible\n", "visible"),
]


@pytest.mark.parametrize("text, wanted", COMMENT_PAGES)
def test_sad_qt_s_own_parser_reads_comments_as_gfm_does(text, wanted):
    """Before: "para\\n    <!-- x" hid "after"; "> <!-- a" all that followed the quote; "text <!-- a\\n#
    Heading\\nb --> end" the heading; a comment in a table's cell the next cells; a never closed one at the top
    level hid the text but its code blocks; "<!-- x -->1. *bar*" was a list item of "bar" in emphasis."""
    assert _shown(text, False) == wanted, (text, _shown(text, False))


@pytest.mark.parametrize("text", [text for text, _wanted in COMMENT_PAGES])
def test_happy_markdown_it_s_page_agrees_with_the_comment_cases(text):
    """The cases' expectations are what markdown-it's page (GFM) shows."""
    wanted = dict(COMMENT_PAGES)[text]
    assert _shown(text, True) == wanted, (text, _shown(text, True))


def test_sad_code_in_a_quote_keeps_its_indentation_in_qt_s_own_parser():
    """">     <!-- x": the run of spaces after the quote's mark was made one (as between words), the code
    became a paragraph and its comment hid what followed. Now a code block."""
    from PyQt6.QtGui import QTextFormat

    view = _view(">     <!-- x\n>     y = 1\n\nafter\n", False)
    document = view.browser.document()
    found = document.find("y = 1")
    assert not found.isNull()
    fmt = found.block().blockFormat()
    assert fmt.hasProperty(QTextFormat.Property.BlockCodeFence) or fmt.nonBreakableLines() \
        or found.charFormat().fontFixedPitch() or "monospace" in found.charFormat().fontFamilies()
    assert "<!-- x" in document.toPlainText()
    view.close()


def test_sad_the_comment_rules_stay_linear():
    """Each closer, paragraph end and container end looked for once: the shapes of the new rules (a quote
    of closed comments, of open ones, list items, cells, tags, a line of openers) at 50,000 and 100,000."""
    from ui import markdown_view as MV

    shapes = [lambda n: "> <!-- a -->\n" * n, lambda n: "> <!-- a\n" * n, lambda n: "- <!-- a\n" * n,
              lambda n: "text <!-- a\n" * n, lambda n: "| c <!-- x | d |\n" * n, lambda n: '<a href="x<!--y">' * n,
              lambda n: '<a href="' + "<!-- " * n, lambda n: "para\n" + "    <!-- x\n" * n,
              lambda n: "> > - <!-- a -->\n" * n]
    for shape in shapes:
        took = []
        for count in (50_000, 100_000):
            text = shape(count)
            began = time.thread_time()
            MV._drop_comments(text)
            took.append(time.thread_time() - began)
        # (linear: twice the text about twice the time - quadratic would be four times)
        TB.budget(took[1] < 3.2 * took[0] + 0.02, (shape(1), took))
        assert took[1] < 30, (shape(1), took)


# -- the editor's preview: a move of the cursor made it anew ---------------------------------------------------

def test_sad_moving_the_editor_s_cursor_never_makes_the_preview_anew():
    """The status bar's sync of View > Markdown Preview's check (setChecked) emitted toggled, which set the
    preview again: each move of the cursor in a tab whose check was out of step (the preview turned on by its
    tab, a tab chosen) made the preview of all of the text anew - 0.012 s of the typing's turn and a parse on
    a worker."""
    from PyQt6.QtGui import QTextCursor

    from ui.editor_window import EditorWindow

    window = EditorWindow()
    window.resize(1200, 700)
    window.show()
    tab = window.new_tab()
    tab.editor.setPlainText("# T\n\n" + "line\n" * 50)
    tab.set_preview(True)
    assert until(lambda: tab.preview._readable and tab.preview.markdown, TB.READY_SECONDS)
    pump(0.3)
    renders = []
    real = tab.preview.render
    tab.preview.render = lambda *a, **kw: (renders.append(a), real(*a, **kw))[1]
    try:
        cursor = tab.editor.textCursor()
        for _ in range(3):
            cursor.movePosition(QTextCursor.MoveOperation.Down)
            tab.editor.setTextCursor(cursor)
            pump(0.05)
        assert renders == []
        assert window.preview_action.isChecked() == tab.previewing
    finally:
        tab.editor.document().setModified(False)
        window.close()


# -- N5: a resize or a zoom of a long page shows its top before the place read ------------------------------

def _sections(count: int) -> str:
    return "".join(f"## H{i}\n\nPara *{i}* with `code` and [link](#h{i}).\n\n- item\n- item\n\n> quote\n\n"
                   for i in range(count))


def _heading_on_top(view) -> str:
    """The first heading ("H123") at or below the view's top."""
    from PyQt6.QtCore import QPoint

    block = view.browser.cursorForPosition(QPoint(0, 0)).block()
    for _ in range(12):
        text = block.text().strip()
        if text[:1] == "H" and text[1:].isdigit():
            return text
        block = block.next()
        if not block.isValid():
            break
    return "?"


class _Painted:
    """The heading on the view's top at each paint of its viewport (what the reader saw)."""

    def __init__(self, view):
        from PyQt6.QtCore import QEvent, QObject

        self.view, self.seen = view, []
        painted = self

        class Filter(QObject):
            def eventFilter(self, _watched, event):  # noqa: N802 - Qt
                if event.type() == QEvent.Type.Paint:
                    painted.seen.append(_heading_on_top(painted.view))
                return False

        self.filter = Filter()
        view.browser.viewport().installEventFilter(self.filter)

    def stop(self) -> list:
        self.view.browser.viewport().removeEventFilter(self.filter)
        return self.seen


@pytest.fixture(scope="module")
def _read_to_the_end(tmp_path_factory):
    """A viewer (markdown-it) of 4,000 sections read to their end, at H3000 - laid out once for the module."""
    from tests.test_markdown_reader_bugs24 import _viewer

    viewer = _viewer(tmp_path_factory.mktemp("n5"), _sections(4000), True)
    view = viewer.view
    view.load_rest()
    assert until(lambda: not view.more() and not view._scheduled and not view._gaps, TB.READY_SECONDS)
    yield viewer
    viewer.close()


def _at_h3000(viewer) -> None:
    """The page read to its end again (a resize or a zoom before made it anew), the view at H3000."""
    view = viewer.view
    assert until(lambda: view._readable and not view._scheduled, TB.READY_SECONDS)
    view.load_rest()
    assert until(lambda: not view.more() and not view._scheduled and not view._gaps, TB.READY_SECONDS)
    view.go_to_anchor("h3000")
    assert until(lambda: _heading_on_top(view) == "H3000" and not view._scheduled, 60)
    pump(0.3)


@pytest.mark.parametrize("action", ["resize", "zoom"])
def test_sad_a_resize_or_a_zoom_never_shows_the_page_s_top_before_the_place_read(_read_to_the_end, action):
    """Before (markdown-it, 10,000 sections read to their end, at H5000): a resize that changes the text's
    width showed an empty page, then H0 for about 0.65 s (13 samples of 0.05 s), then H5000 again; a zoom H0
    for 0.4 s. The page made anew waited for its later pieces to be parsed again; now they are kept, and the
    view's picture is held until the place read is shown again."""
    viewer = _read_to_the_end
    view = viewer.view
    _at_h3000(viewer)
    painted = _Painted(view)
    generation = view._page_generation
    try:
        if action == "resize":
            viewer.resize(700, 800)  # (the text's width changes: the page made anew)
        else:
            view.zoom_by(1)
        assert until(lambda: view._page_generation > generation, TB.READY_SECONDS)  # (the page made anew)
        assert until(lambda: view._readable and not view._scheduled and _heading_on_top(view) == "H3000"
                     and view.browser.viewport().updatesEnabled(), 60)
        pump(0.5)
    finally:
        seen = painted.stop()
    assert seen, "nothing painted"
    assert set(seen) == {"H3000"}, seen
    assert _heading_on_top(view) == "H3000"


def test_sad_a_resize_that_keeps_the_text_s_width_lays_nothing_out_again(_read_to_the_end):
    """QTextEdit's own resizeEvent laid all of a page with a table or a quote's box in it out again at every
    resize, though its width (the wrap's) stayed: 0.48 s of the GUI thread a step of a drag (10,000 sections
    read to their end). Now only the scroll bars follow - as Qt would set them."""
    from PyQt6.QtWidgets import QApplication

    viewer = _read_to_the_end
    view = viewer.view
    viewer.resize(1100, 800)
    _at_h3000(viewer)
    wrap = view.browser.lineWrapColumnOrWidth()
    took = []
    for width, height in ((1080, 800), (1060, 760), (1040, 820)):
        began = time.thread_time()
        viewer.resize(width, height)
        QApplication.processEvents()
        took.append(time.thread_time() - began)
        assert view.browser.lineWrapColumnOrWidth() == wrap
        browser = view.browser
        size = browser.document().documentLayout().documentSize().toSize()
        bar = browser.verticalScrollBar()
        assert bar.pageStep() == browser.viewport().height()
        assert bar.maximum() == max(0, size.height() - browser.viewport().height()), (bar.maximum(), size)
        pump(0.1)
    TB.budget(max(took) < 0.1, took)


# -- R7: a code block of a million lines after Ctrl+End and Ctrl+Home ------------------------------------------

def test_sad_laying_out_a_gap_asks_qt_s_hit_test_nothing_on_a_long_page():
    """Each part laid out into the gap Ctrl+End and Ctrl+Home left kept the view where it was by Qt's hit test
    at the view's top (cursorForPosition), which walks every block before it: at 300,000 lines of code 17 ms of
    each part's turn and growing with the page (review 26: turns of 0.1 to 3.6 s at 1,000,000 lines, 9 to 15
    minutes for all of it). Now found by halves: no hit test on a page of more than HALVED_BLOCKS blocks."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    from ui import markdown_view as MV

    view = _view("```python\n" + "x = 1\n" * 30_000 + "```\n", False)
    QTest.keyClick(view.browser, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier)
    pump(0.5)
    until(lambda: not view._scheduled, 60)
    QTest.keyClick(view.browser, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier)
    pump(0.5)
    until(lambda: not view._scheduled, 60)
    assert view._gaps
    view._whole = True  # (as load_rest: the gap's parts laid out a part a call)
    for _ in range(200):
        if view.browser.document().blockCount() > getattr(MV, "HALVED_BLOCKS", 5000) or not view._gaps:
            break
        view._next_part()
    assert view._gaps and view.browser.document().blockCount() > getattr(MV, "HALVED_BLOCKS", 5000)
    asked = []
    real = view.browser.cursorForPosition
    view.browser.cursorForPosition = lambda *a: (asked.append(a), real(*a))[1]
    try:
        for _ in range(40):
            view._next_part()
        assert asked == [], len(asked)
    finally:
        view.browser.cursorForPosition = real
        view.close()


def test_sad_the_block_on_the_view_s_top_found_by_halves_is_qt_s():
    """shown_at (by halves) finds the block Qt's hit test finds, at places all over a long page."""
    from PyQt6.QtCore import QPoint

    from ui import markdown_view as MV

    view = _view("".join(f"## H{i}\n\nwords {i} " + "and more " * (i % 7) + "\n\n> q\n\n" for i in range(3000)), False)
    view.load_rest_now()
    browser = view.browser
    assert browser.document().blockCount() > MV.HALVED_BLOCKS
    bar = browser.verticalScrollBar()
    for share in (0.0, 0.13, 0.5, 0.77, 1.0):
        bar.setValue(int(bar.maximum() * share))
        pump(0.05)
        for offset in (0, 4, 40):
            qt = browser.cursorForPosition(QPoint(0, offset)).block()
            halves = MV.shown_at(browser, offset)
            # (Qt's hit test gives the block whose line is there; by halves the first whose bottom reaches it -
            # the same block, or the box's cell at that height)
            assert abs(qt.blockNumber() - halves.blockNumber()) <= 1, (share, offset, qt.text(), halves.text())
    view.close()
