"""The eleventh round of the Markdown reader: every feature that keeps or
finds a place, end to end on a long page laid out in part with gaps (a
jump far on laid out first) - in both of Qt's paths (markdown-it's page and
Qt's own parser, md4c). Each test failed before (the guard round: a jump's
follow-on paths broke reload, folding, anchors, find, footnotes, Copy, the
outline and zoom, and no test saw it).
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

from PyQt6.QtCore import QPoint, Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])

CHAPTERS = 200


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.003)


def until(condition, seconds: float = 20.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        pump(0.02)
    return bool(condition())


def gap_text(chapters: int = CHAPTERS) -> str:
    """A long page of chapters: a heading, a paragraph, a folded <details>, a
    table, a list, a note; one match of "zebraquux" in its middle, one at
    its end; a note referred to at the top, defined at the end."""
    out = ["# Gap test\n\nTop: go to [C150](#chapter-150), a note[^far] and [C190](#chapter-190).\n\n"]
    for n in range(1, chapters + 1):
        out.append(f"## Chapter {n}\n\nBody of chapter {n} begins CHMARK{n:03d}, with words enough to make "
                   f"a line or two of text to read in chapter {n}.\n\n")
        out.append(f"<details>\n<summary>Folded {n}</summary>\n\nInside details {n}.\n\n</details>\n\n")
        out.append(f"| Col A {n} | Col B |\n|---|---|\n| a{n} | b |\n| c{n} | d |\n\n")
        out.append(f"- item {n} a\n- item {n} b\n\n")
        out.append(f"Second paragraph of chapter {n}, more words to make the part tall enough to scroll.\n\n")
        if n == chapters // 2:
            out.append("Middle zebraquux one.\n\n")
    out.append("Last zebraquux two.\n\n[^far]: The far note text.\n")
    return "".join(out)


@pytest.fixture
def small_parts(monkeypatch):
    """Parts and pieces small enough that a page of 200 chapters has many."""
    from core import markdown_term as T
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 300)
    monkeypatch.setattr(T, "STREAM_CHARS", 30_000)
    monkeypatch.setattr(T, "STREAM_LINES", 600)


def opened(full: bool, tmp_path, text: str | None = None):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "gap.md"
    path.write_text(text if text is not None else gap_text(), encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    if not full:
        dialog.view.full = False
        dialog.view.render(path.read_text(encoding="utf-8"))
    dialog.resize(1000, 800)
    dialog.show()
    assert until(lambda: dialog.view._readable and dialog.view.markdown, 60)
    settled(dialog.view)
    return dialog


def settled(view, seconds: float = 30.0) -> None:
    """Until the view lays out nothing more on its own for now."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pump(0.1)
        if not view._scheduled and not view.status.text().startswith("Rendering"):
            break
    pump(0.2)


def heading_block(view, text: str):
    block = view.browser.document().begin()
    while block.isValid():
        if block.blockFormat().headingLevel() and block.text() == text:
            return block
        block = block.next()
    return None


def y_of(view, block) -> int:
    """The top of *block* in the view (viewport pixels)."""
    return view.browser.cursorRect(QTextCursor(block)).top()


def top_block(view):
    """The first block with text on the view's top - and how far below the view's top it begins."""
    from ui import markdown_view as MV

    browser = view.browser
    block = browser.cursorForPosition(QPoint(5, 5)).block()
    while block.isValid() and (not block.text().strip() or block.blockFormat().intProperty(MV._GAP)
                               or block.blockFormat().boolProperty(MV._STAND_IN)):
        block = block.next()
    return block


def place(view) -> tuple[str, int]:
    block = top_block(view)
    return block.text()[:40], y_of(view, block)


def at_chapter(dialog, name: str = "chapter-150", below: int = 300) -> tuple[str, int]:
    """The page jumped to *name* (a link clicked), then scrolled *below* pixels on."""
    view = dialog.view
    view.clicked(QUrl("#" + name))
    shown = name.replace("-", " ").capitalize()
    assert until(lambda: heading_block(view, shown) is not None, TB.READY_SECONDS), "never laid out"
    settled(view)
    bar = view.browser.verticalScrollBar()
    bar.setValue(bar.value() + below)
    pump(0.3)
    settled(view)
    assert view._gaps, "no jump: no gap"
    return place(view)


def close(dialog) -> None:
    dialog.close()
    dialog.deleteLater()
    pump(0.05)


def same_place(before, after, slack: int = 30) -> bool:
    return before[0] == after[0] and abs(before[1] - after[1]) <= slack


# -- reload, live reload, folding: the place kept ------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_guard_a_reload_keeps_the_place_after_a_jump(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        before = at_chapter(dialog)
        dialog.reload()
        pump(0.5)
        settled(dialog.view)
        assert TB.until_within(until, lambda: same_place(before, place(dialog.view)), 20), (before, place(dialog.view))
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False])
def test_guard_a_reload_of_a_short_page_keeps_the_place(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path, gap_text(25))  # (a few parts: no jump, all laid out)
    try:
        view = dialog.view
        bar = view.browser.verticalScrollBar()
        bar.setValue(bar.maximum() // 2)
        pump(0.3)
        before = place(view)
        dialog.reload()
        pump(0.5)
        settled(view)
        assert TB.until_within(until, lambda: same_place(before, place(view)), 20), (before, place(view))
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False])
def test_guard_a_live_reload_keeps_the_place(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        before = at_chapter(dialog)
        path = Path(dialog.path)
        path.write_text(path.read_text(encoding="utf-8") + "\nAppended line.\n", encoding="utf-8")
        dialog._file_changed()  # (what the watcher calls)
        assert TB.until_within(until, lambda: "Appended line." in dialog.view.markdown, 20)
        pump(0.3)
        settled(dialog.view)
        assert TB.until_within(until, lambda: same_place(before, place(dialog.view)), 20), (before, place(dialog.view))
    finally:
        close(dialog)


def test_guard_folding_and_unfolding_details_keeps_the_place(tmp_path, small_parts):
    """(markdown-it's page: Qt's own parser shows a <details> open, no fold)"""
    from ui.markdown_html import FOLD

    dialog = opened(True, tmp_path)
    try:
        view = dialog.view
        at_chapter(dialog, below=0)
        block, href = top_block(view), ""
        for _round in range(200):  # (the first summary in view)
            pieces = block.begin()
            while not pieces.atEnd() and not href:
                link = pieces.fragment().charFormat().anchorHref()
                href = link if link.startswith("#" + FOLD) else ""
                pieces += 1
            if href:
                break
            block = block.next()
        assert href
        before = place(view)
        for _turn in range(2):  # (unfolded, folded again)
            view.clicked(QUrl(href))
            pump(0.5)
            settled(view)
            assert TB.until_within(until, lambda: same_place(before, place(view), 60), 20), (before, place(view))
    finally:
        close(dialog)


# -- an anchor, a footnote and its way back --------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_guard_an_anchor_jump_puts_its_heading_on_top(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        for name in ("chapter-150", "chapter-60"):  # (past what is laid out; in the gap before it)
            view.clicked(QUrl("#" + name))
            shown = name.replace("-", " ").capitalize()
            assert TB.until_within(until, lambda: heading_block(view, shown) is not None
                         and 0 <= y_of(view, heading_block(view, shown)) < 40, 30), \
                (name, heading_block(view, shown) and y_of(view, heading_block(view, shown)), place(view))
            settled(view)
            assert 0 <= y_of(view, heading_block(view, shown)) < 40, place(view)  # (it stays there)
    finally:
        close(dialog)


def note_links(block) -> list[str]:
    links, pieces = [], block.begin()
    while not pieces.atEnd():
        href = pieces.fragment().charFormat().anchorHref()
        if href and "chapter" not in href:
            links.append(href)
        pieces += 1
    return links


def in_view(view, block) -> bool:
    top = y_of(view, block)
    return 0 <= top < view.browser.viewport().height()


@pytest.mark.parametrize("full", [True, False])
def test_guard_a_footnote_link_and_its_way_back(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        document = view.browser.document()
        top = document.find("Top: go to")
        assert not top.isNull()
        links = note_links(top.block())
        assert links, "no note referred to"
        began = time.monotonic()
        view.clicked(QUrl(links[0]))

        def note():
            found = document.find("The far note text")
            return None if found.isNull() else found.block()

        assert TB.until_within(until, lambda: note() is not None and in_view(view, note()), 30), (view.status.text(), place(view))
        TB.budget(time.monotonic() - began < 8, 'time.monotonic() - began < 8')  # (all of the page laid out first: 7 to 90 s)
        assert view._gaps or view.more(), "all of the page laid out for a note"
        back = [link for link in note_links(note()) if link != links[0]]
        assert back, "no way back"
        view.clicked(QUrl(back[-1]))
        assert TB.until_within(until, lambda: in_view(view, document.find("Top: go to").block()), 20), place(view)
    finally:
        close(dialog)


# -- find --------------------------------------------------------------------------------------------------

def selected_line(view) -> str:
    return view.browser.textCursor().block().text()


def visible_selection(view) -> bool:
    rect = view.browser.cursorRect()
    return view.browser.textCursor().hasSelection() and 0 <= rect.top() < view.browser.viewport().height()


@pytest.mark.parametrize("full", [True, False])
def test_guard_find_in_order_across_gaps_and_round(full, tmp_path, small_parts):
    from PyQt6.QtTest import QTest

    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        browser = view.browser
        QTest.keyClick(browser, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier)
        assert TB.until_within(until, lambda: "zebraquux" in browser.toPlainText() and not view._scheduled, 30)
        settled(view)
        QTest.keyClick(browser, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier)
        pump(0.3)
        assert view._gaps, "no gap"
        dialog.find_field.setText("zebraquux")
        pump(0.2)
        settled(view)
        browser.setTextCursor(QTextCursor(browser.document()))  # (from the top)
        order = []
        for backward in (False, False, False, True):
            began = time.monotonic()
            dialog.find_next(backward)
            want = {0: "Middle", 1: "Last", 2: "Middle", 3: "Last"}[len(order)]
            assert TB.until_within(until, lambda w=want: selected_line(view).startswith(w) and visible_selection(view), 15), \
                (order, want, selected_line(view), browser.cursorRect(), view.status.text())
            order.append((selected_line(view)[:6], round(time.monotonic() - began, 2)))
            settled(view)
            assert visible_selection(view), (order, browser.cursorRect())
        TB.budget(all(took < 5 for _line, took in order), order)  # (round: all laid out first - 7 to 68 s)
        assert view._gaps, "find laid out all of the page"
    finally:
        close(dialog)


# -- Copy, the outline -------------------------------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_guard_a_copy_across_a_gap_holds_all_of_it(full, tmp_path, small_parts):
    from PyQt6.QtTest import QTest

    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        at_chapter(dialog, below=0)
        browser = view.browser
        cursor = QTextCursor(browser.document())
        cursor.setPosition(heading_block(view, "Chapter 150").position() + 5, QTextCursor.MoveMode.KeepAnchor)
        browser.setTextCursor(cursor)
        APP.clipboard().setText("")
        QTest.keyClick(browser, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        assert TB.until_within(until, lambda: "CHMARK149" in APP.clipboard().text(), 30), APP.clipboard().text()[-200:]
        copied = APP.clipboard().text()
        missing = [n for n in range(1, 150) if f"CHMARK{n:03d}" not in copied]
        assert not missing, missing[:10]
        assert "CHMARK151" not in copied
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False])
def test_guard_the_outline_lists_every_heading(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        at_chapter(dialog, below=0)
        listed = [view.outline.item(row).text().strip() for row in range(view.outline.count())]
        assert listed == ["Gap test"] + [f"Chapter {n}" for n in range(1, CHAPTERS + 1)], \
            (len(listed), listed[:3], listed[-3:])
        row = listed.index("Chapter 80")
        view.jump(view.outline.item(row))
        assert TB.until_within(until, lambda: heading_block(view, "Chapter 80") is not None
                     and 0 <= y_of(view, heading_block(view, "Chapter 80")) < 40, 30), place(view)
        assert view.outline.count() == CHAPTERS + 1
    finally:
        close(dialog)


# -- zoom, resize ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_guard_zoom_and_resize_keep_the_place(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        before = at_chapter(dialog)
        laid = sum(1 for number in range(view._part_count()) if view._is_laid(number))
        view.zoom_by(1)
        pump(0.5)
        settled(view)
        assert top_block(view).text()[:40] == before[0], (before, place(view))
        assert sum(1 for number in range(view._part_count()) if view._is_laid(number)) <= laid + 4  # (not scattered)
        view.zoom_by(-1)
        pump(0.5)
        settled(view)
        assert top_block(view).text()[:40] == before[0], (before, place(view))
        dialog.resize(700, 800)
        pump(0.6)
        settled(view)
        assert top_block(view).text()[:40] == before[0], (before, place(view))
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False])
def test_sad_an_outline_of_every_heading_is_made_a_batch_at_a_time(full, monkeypatch):
    """20,000 headings listed at once held the window 0.14 s, and the list
    laid all of them out to know their heights at each resize: entries of
    one height, made OUTLINE_BATCH an event-loop turn."""
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "BACKGROUND_CHARS", 10 ** 9)  # (shown in this turn: the outline as the first part left it)
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    text = "".join(f"## Heading {n}\n\nPara {n}.\n\n" for n in range(20000))
    view.render(text)
    assert view.outline.uniformItemSizes()
    if full:  # (markdown-it's later pieces are parsed on a worker: theirs come with them)
        assert view.outline.count() <= MV.OUTLINE_BATCH + 2000, view.outline.count()
    else:
        assert view.outline.count() <= MV.OUTLINE_BATCH + 200, view.outline.count()
    assert until(lambda: view.outline.count() == 20000, 60), view.outline.count()
    assert view.headings()[-1] == "Heading 19999"


# -- md4c: no pass over all of the page on the window's thread ---------------------------------------------

def test_sad_md4c_a_page_of_many_tables_is_made_whole_without_a_freeze(tmp_path, small_parts):
    from PyQt6.QtCore import QTimer

    words = "Text paragraph with some words in it to read. " * 3 + "\n\n"
    text = "".join(f"## T {n}\n\n| a {n} | b |\n|---|---|\n| c | d |\n\n" + words * 5 for n in range(1000))
    dialog = opened(False, tmp_path, text)
    try:
        view = dialog.view
        beats, last = [], [time.monotonic()]

        def beat():
            now = time.monotonic()
            beats.append(now - last[0])
            last[0] = now

        timer = QTimer()
        timer.timeout.connect(beat)
        timer.start(10)
        view.load_rest()  # (Select All, export, print, find's way round)
        assert until(lambda: not view.more(), 120)
        pump(0.3)
        timer.stop()
        # (each table's room made over all of the page once it was whole,
        # a relayout each: 2 s here, 37 s for gap.md's 1000 tables)
        TB.budget(max(beats) < 1.0, sorted(beats)[-5:])
        from PyQt6.QtGui import QTextTable

        document = view.browser.document()
        tables = [frame for frame in document.rootFrame().childFrames() if isinstance(frame, QTextTable)]
        assert len(tables) >= 1000
        for table in (tables[1], tables[500], tables[998]):  # (each still has its room below)
            after = document.findBlock(table.lastPosition() + 1).next()
            assert after.blockFormat().topMargin() >= 14, after.text()
    finally:
        close(dialog)


def test_sad_find_after_ctrl_end_then_home_takes_the_first_match_first(tmp_path, small_parts):
    """(markdown-it) the reviewer's case: the last match was found first, the one in the middle skipped."""
    dialog = opened(True, tmp_path)
    try:
        view = dialog.view
        view.go_end()
        settled(view)
        view.browser.verticalScrollBar().setValue(0)
        view.browser.setTextCursor(QTextCursor(view.browser.document()))
        dialog.find_field.setText("zebraquux")
        settled(view)
        view.browser.setTextCursor(QTextCursor(view.browser.document()))
        dialog.find_next()
        assert TB.until_within(until, lambda: view.browser.textCursor().hasSelection(), 15)
        assert re.match("Middle", selected_line(view)), selected_line(view)
    finally:
        close(dialog)


# -- a reload: the page there at once ----------------------------------------------------------------------

def test_sad_md4c_parts_carry_the_link_definitions_they_use_only():
    from ui import markdown_view as MV

    text = "".join(f"## C {n}\n\nA [link][ref{n}] here.\n\n" + "words\n\n" * 40 for n in range(300))
    text += "".join(f"[ref{n}]: https://example.com/{n}\n" for n in range(300))
    began = time.monotonic()
    parts = MV.markdown_parts(text)
    TB.budget(time.monotonic() - began < 2.0, 'time.monotonic() - began < 2.0')
    assert len(parts) > 100
    for part in parts[:-1]:  # (every one of the 300: 300 lines more each part, 8 s for gap.md before it showed)
        defined = re.findall(r"(?m)^\[(ref\d+)\]:", part)
        assert len(defined) <= 2, defined[:5]
    for n in (0, 150, 299):  # (each link still has its definition)
        part = next(part for part in parts if f"[link][ref{n}]" in part)
        assert f"[ref{n}]: https://example.com/{n}" in part
    # (one label defined again and again - gap.md's 1000 times: each part 1000 lines longer)
    text = "".join(f"## C {n}\n\nA [link][ref] here.\n\n" + "words\n\n" * 40 + "[ref]: https://example.com/\n\n"
                   for n in range(300))
    parts = MV.markdown_parts(text)
    assert max(len(re.findall(r"(?m)^\[ref\]:", part)) for part in parts) <= 3


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_reload_never_shows_a_blank_page(full, tmp_path, small_parts):
    dialog = opened(full, tmp_path)
    try:
        view = dialog.view
        assert view.browser.document().toPlainText().strip()
        dialog.reload()
        blank = False
        end = time.monotonic() + TB.READY_SECONDS
        while time.monotonic() < end:
            pump(0.005)
            blank = blank or not view.browser.document().toPlainText().strip()
            if view._readable and not view._scheduled:
                break
        assert not blank, "the page went blank while it was made anew"
    finally:
        close(dialog)


# -- math: display style ---------------------------------------------------------------------------------

def math_page(tex: str, full: bool):
    """A page of one display formula: (its view, its formula's table or None)."""
    from PyQt6.QtGui import QTextTable

    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(800, 600)
    view.show()
    view.render(f"Before.\n\n$$\n{tex}\n$$\n\nAfter.\n")
    until(lambda: view._readable and not view.more(), 10)
    pump(0.2)
    tables = [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]
    return view, (tables[0] if tables else None)


def cells_of(table) -> dict:
    """(row, column) -> (text, its first character's format) of each cell where it begins."""
    found = {}
    for row in range(table.rows()):
        for column in range(table.columns()):
            cell = table.cellAt(row, column)
            if (cell.row(), cell.column()) == (row, column):
                cursor = cell.firstCursorPosition()
                block = cursor.block()
                text = block.text().replace("\u200b", "")
                after = QTextCursor(cursor)
                after.movePosition(QTextCursor.MoveOperation.NextCharacter)
                found[row, column] = (text, after.charFormat(), cell)
    return found


def size_step(fmt) -> int:
    from PyQt6.QtGui import QTextFormat

    value = fmt.property(QTextFormat.Property.FontSizeAdjustment)
    return int(value or 0)


def _rect(view, needle, nth=0):
    document = view.browser.document()
    hit = document.find(needle)
    for _round in range(nth):
        hit = document.find(needle, hit)
    assert not hit.isNull(), needle
    return view.browser.cursorRect(hit), hit.charFormat()


# (the formula a row of items each in a table of its own since the twelfth round - bugs12: what is above,
# below, beside what is told by where it is shown)
@pytest.mark.parametrize("full", [True, False])
def test_typo_a_display_sum_is_large_its_limits_above_and_below(full):
    view, _table = math_page(r"\sum_{i=1}^{n} i = \frac{n(n+1)}{2}", full)
    sigma, sigma_format = _rect(view, "∑")
    upper, upper_format = _rect(view, "n")
    lower, _lower_format = _rect(view, "i=1")  # (tight, as a script: not "i = 1")
    assert upper.bottom() <= sigma.top() + 4 and lower.top() >= sigma.bottom() - 4, (upper, sigma, lower)
    assert abs(upper.center().x() - sigma.center().x()) <= 8 or upper.left() >= sigma.left() - 8
    assert size_step(sigma_format) > 0  # (display size)
    assert size_step(upper_format) < 0  # (its limits smaller)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_display_integral_is_large_its_limits_beside_it(full):
    view, _table = math_page(r"\int_0^1 x^2 \, dx", full)
    sign, sign_format = _rect(view, "∫")
    assert size_step(sign_format) >= 3
    upper, lower = _rect(view, "1")[0], _rect(view, "0")[0]
    assert upper.left() >= sign.left() and lower.left() >= sign.left() and upper.top() < lower.top()


def test_typo_a_script_of_a_script_is_raised_further():
    from core import markdown_doc as MD

    runs = MD.math_runs(r"e^{-x^2}", small=False)
    assert ("−x²", "sup") in runs, runs  # (the 2 as high as the -x before)
    assert MD.math_text(r"e^{-x^2}") in ("e^(−x²)", "e⁻ˣ²")  # (the terminal as before)


@pytest.mark.parametrize("full", [True, False])
def test_typo_quad_keeps_its_room(full):
    view, _table = math_page(r"a \quad b \qquad c", full)
    text = view.browser.toPlainText()
    assert "a\u2003b\u2003\u2003c" in text.replace(" ", ""), repr(text)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_matrix_has_brackets_of_one_piece_and_its_comma_in_the_middle(full):
    # (a piece of each bracket a row since the twelfth round - bugs14: one glyph was 1.3 rows tall whatever
    # their count - the pieces meeting, each beside its row)
    view, _table = math_page(r"A = \begin{pmatrix} a & b \\ c & d \end{pmatrix},", full)
    document = view.browser.document()

    def middle(needle: str) -> int:
        found = document.find(needle, document.find("A ="))
        assert not found.isNull(), needle
        found.setPosition(found.selectionStart())
        return view.browser.cursorRect(found).center().y()

    assert abs(middle("⎛") - middle("a")) <= 12 and abs(middle("⎝") - middle("c")) <= 12
    assert abs(middle("⎞") - middle("b")) <= 12 and abs(middle("⎠") - middle("d")) <= 12
    assert middle("⎛") < middle("⎝")
    assert middle("a") < middle(",") < middle("c")  # (in the middle of its rows)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_fraction_has_little_room_beside_it(full):
    view, table = math_page(r"\frac{a}{b} = \frac{c}{d}", full)
    cells = cells_of(table)
    for _text, _fmt, cell in cells.values():
        fmt = cell.format().toTableCellFormat()
        assert fmt.leftPadding() <= 6 and fmt.rightPadding() <= 6, (fmt.leftPadding(), fmt.rightPadding())


def test_typo_md4c_footnotes_stand_in_as_markdown_its():
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(500, 400)
    view.show()
    view.render("A note[^a].\n\n[^a]: The note text, long enough to wrap onto a second line of the page so we "
                "see its indent.\n")
    until(lambda: view._readable and not view.more(), 10)
    note = view.browser.document().find("The note text").block()
    fmt = note.blockFormat()
    assert fmt.leftMargin() >= 30 and fmt.textIndent() < 0, (fmt.leftMargin(), fmt.textIndent())
