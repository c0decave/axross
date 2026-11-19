"""Bugs of the sixth review of the Markdown reader, each first a failing test
here - in both of Qt's paths (markdown-it's page and Qt's own parser, md4c)
and the terminal where they share the bug.
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

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def view_of(text: str, full: bool, path: str = "", width: int = 900, height: int = 700):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), path) if path else None)
    view.full = view.full and full
    view.resize(width, height)
    view.show()
    view.render(text)
    end = time.monotonic() + 20
    while time.monotonic() < end and (view.status.text().startswith(MV.tr("Rendering…"))
                                      or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return view


def term(text: str, width: int = 80) -> str:
    from core import markdown_term as T

    return ANSI.sub("", T.render(text, T.Options(width=width, depth="none")))


# -- 1. task lists: a box before each task, painted ----------------------------------------------

TASKS = ("# V\n\n- [ ] write\n- [x] test\n\nNested:\n\n- [ ] parent\n  - [ ] inner\n  - [x] done inner\n\n"
         "Mixed:\n\n- plain\n- [ ] mixed task\n")


def _marker_painted(view, text: str) -> bool:
    """Whether something is drawn left of *text*'s first letter (its box)."""
    from PyQt6.QtGui import QColor

    browser = view.browser
    found = browser.document().find(text)
    rect = browser.cursorRect(view.link_cursor(found.selectionStart()))
    image = browser.viewport().grab().toImage()
    ground = QColor(image.pixel(max(0, rect.left() - 40), rect.top() + 2)).name()
    for x in range(max(0, rect.left() - 24), max(0, rect.left() - 2)):
        for y in range(rect.top() + 2, rect.bottom() - 1):
            if QColor(image.pixel(x, y)).name() != ground:
                return True
    return False


@pytest.mark.parametrize("full", [False, True])
def test_sad_every_task_shows_its_box_pure_nested_and_mixed(full):
    from PyQt6.QtGui import QTextBlockFormat

    view = view_of(TASKS, full)
    # (each its glyph - ☑, ☐ - Qt's box of a task done was a cross: test_markdown_reader_bugs12)
    checked, unchecked = "☑", "☐"
    for text, marker in (("write", unchecked), ("test", checked), ("parent", unchecked), ("inner", unchecked),
                         ("done inner", checked), ("mixed task", unchecked)):
        block = view.browser.document().find(text).block()
        assert block.text().startswith(marker), text
        assert block.blockFormat().marker() == QTextBlockFormat.MarkerType.NoMarker, text
        assert block.textList() is not None and block.textList().format().style() != 0, text
        assert _marker_painted(view, text), text


# -- 2. prose that names <script>, <style> …: nothing after it is lost -----------------------------

@pytest.mark.parametrize("tag", ["script", "style", "textarea", "title"])
@pytest.mark.parametrize("where", ["full", "md4c", "term"])
def test_sad_prose_naming_a_dropped_tag_keeps_the_rest(tag, where):
    if where != "md4c":
        pytest.importorskip("markdown_it")
    text = (f"# T\n\nPut the code in a <{tag}> tag in the head.\n\n## Next section\n\nImportant paragraph.\n\n"
            f"Closed: a <{tag}>hidden()</{tag}> b.\n\nNested: c <{tag}><{tag}>x</{tag}> d.\n")
    if where == "term":
        shown = term(text)
        headings = [line.strip("█ ").strip() for line in shown.split("\n") if "Next section" in line]
    else:
        view = view_of(text, where == "full")
        shown = view.browser.toPlainText()
        headings = view.headings()
    assert f"Put the code in a <{tag}> tag in the head." in shown
    assert "Next section" in "".join(headings) and "Important paragraph." in shown
    assert "Closed: a b." in " ".join(shown.split()) and "hidden()" not in shown
    assert "d." in shown


# -- 3. find on a page laid out in part, in folded details; anchors in them ----------------------

def _dialog(path, monkeypatch, eager: int | None = None, full: bool = True):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV
    from ui.markdown_viewer import MarkdownViewerDialog

    if eager is not None:
        monkeypatch.setattr(MV, "EAGER_BLOCKS", eager)
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.view.full = dialog.view.full and full  # (before the file is read and rendered)
    dialog.resize(1000, 700)
    dialog.show()
    end = time.monotonic() + 20
    while time.monotonic() < end and (not dialog.view.browser.toPlainText()
                                      or dialog.view.status.text().startswith(MV.tr("Rendering…"))):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return dialog


def _find(dialog, needle: str, seconds: float = 20) -> bool:
    dialog.find_field.setText(needle)
    found = dialog.find_next()
    end = time.monotonic() + seconds
    while time.monotonic() < end and dialog.view.browser.textCursor().selectedText() != needle:
        APP.processEvents()
        time.sleep(0.005)
    return dialog.view.browser.textCursor().selectedText() == needle or found


@pytest.mark.parametrize("full", [False, True])
def test_sad_find_reaches_what_is_not_laid_out_yet_and_counts_honestly(tmp_path, monkeypatch, full):
    if full:
        pytest.importorskip("markdown_it")
    path = tmp_path / "list.md"
    path.write_text("# L\n\n" + "".join(f"- item {n} end\n" for n in range(4000)), encoding="utf-8")
    dialog = _dialog(path, monkeypatch, eager=500, full=full)
    try:
        assert dialog.view.more()  # (laid out in part)
        dialog.view.browser.moveCursor(dialog.view.browser.textCursor().MoveOperation.Start)
        dialog.find_field.setText("item 1 ")
        dialog.find_next()
        assert "+" in dialog.find_count.text()  # (more may come: "1 of 1" was a lie)
        assert _find(dialog, "item 3999 end")
        assert dialog.view.browser.textCursor().selectedText() == "item 3999 end"
    finally:
        dialog.done(0)


DETAILS = ("# A\n\n[to inside](#inside) [to b](#b-after)\n\n<details>\n<summary>S</summary>\n\n## Inside\n\n"
           "secretword here\n\n</details>\n\n## B after\n\npara\n")


def test_sad_find_and_anchors_open_the_folded_details_they_are_in(tmp_path, monkeypatch):
    pytest.importorskip("markdown_it")
    from PyQt6.QtCore import QUrl

    path = tmp_path / "d.md"
    path.write_text(DETAILS, encoding="utf-8")
    dialog = _dialog(path, monkeypatch)
    view = dialog.view
    try:
        assert "secretword" not in view.browser.toPlainText()
        assert _find(dialog, "secretword")
        assert view.browser.textCursor().selectedText() == "secretword"
        dialog.find_field.clear()  # (else finding as typed opens it again)
        pump(0.5)
        view.folds.clear()
        view.render(view.markdown)
        pump(0.3)
        assert "Inside" not in view.headings()
        view.clicked(QUrl("#nowhere"))
        assert "No heading" in view.status.text()
        view.clicked(QUrl("#inside"))  # (as a browser: its details opened, then there)
        pump(0.5)
        assert "Inside" in view.headings() and "No heading" not in view.status.text()
        block = view.browser.document().findBlock(view.anchors["inside"])
        assert block.text() == "Inside"
    finally:
        dialog.done(0)


# -- 4. a long file on markdown-it's page: its start at once ----------------------------------------

def test_sad_markdown_its_page_shows_the_start_of_a_long_file_at_once():
    """markdown-it parsed all of a 3.8 MB file before the page showed
    anything (7.8 s blank): now the text is parsed in parts, the first shown
    as soon as it is."""
    pytest.importorskip("markdown_it")
    from ui import markdown_view as MV

    text = "# Long\n\n" + "".join(f"- item {n} with **bold** and `code`\n" for n in range(40_000)) + "\n## End\n"
    assert len(text) > 1_000_000
    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    began, cpu = time.monotonic(), time.process_time()
    view.render(text)
    while time.monotonic() - began < 30 and "item 0 with" not in view.browser.toPlainText():
        APP.processEvents()
        time.sleep(0.005)
    # (the process's own time - the parse on its worker too -, not the wall's: under load that was flaky)
    assert time.process_time() - cpu < 1.5, time.process_time() - cpu
    view.load_rest()
    end = time.monotonic() + 120
    while time.monotonic() < end and view.more():
        APP.processEvents()
        time.sleep(0.005)
    pump(0.3)
    assert not view.browser.document().find("item 39999 with").isNull()
    assert view.headings() == ["Long", "End"]


def test_sad_printing_a_long_file_while_it_is_parsed_lays_out_all_of_it():
    pytest.importorskip("markdown_it")
    from ui import markdown_view as MV

    text = "# Long\n\n" + "".join(f"- item {n}\n" for n in range(60_000))
    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    view.render(text)
    while "item 0" not in view.browser.toPlainText():
        APP.processEvents()
        time.sleep(0.005)
    view.load_rest_now()  # (while its later parts are still being parsed)
    assert not view.more() and not view.browser.document().find("item 59999").isNull()
    pump(2)  # (what the worker was parsing meanwhile is not put in twice)
    assert view.browser.toPlainText().count("item 59999") == 1


# -- 5. Qt's own parser's footnotes ----------------------------------------------------------------

NOTES = ("# N\n\nFirst[^b], second[^a], again[^b], inline^[x *em* y], code `[^a]`.\n\n```\n[^a] in code\n```\n\n"
         "[^a]: Note A.\n[^b]: Note B\n    continued.\n\n[^unused]: Unused.\n")


def test_sad_qts_own_parsers_footnotes_read_as_githubs():
    from PyQt6.QtGui import QFontInfo, QTextCharFormat

    view = view_of(NOTES, False)
    text = view.browser.toPlainText()
    assert "code [^a]." in text and "[^a] in code" in text  # (code as written)
    assert "Note B continued." in " ".join(text.split()) and "Unused" not in text
    document = view.browser.document()
    marker = document.find("1", document.find("First").selectionEnd())
    assert marker.charFormat().verticalAlignment() == QTextCharFormat.VerticalAlignment.AlignSuperScript
    body = QFontInfo(document.find("First").charFormat().font()).pixelSize()
    note = QFontInfo(view.link_cursor(document.find("Note A.").selectionStart() + 1).charFormat().font()).pixelSize()
    assert note < body


# -- 6. the terminal: a cell spanning columns is as wide as them, no line through it ------------------

def test_sad_the_terminal_draws_a_spanning_cell_across_its_columns():
    pytest.importorskip("markdown_it")
    table = ('<table><tr><th colspan="2">span two</th><th>c</th></tr><tr><td rowspan="2">rs</td><td>b</td>'
             '<td>c</td></tr><tr><td>b2</td><td>c2</td></tr><tr><td colspan="3">full width row spanning all '
             'three columns of the table</td></tr></table>\n')
    lines = term(table, 60).split("\n")
    row = {word: next(line for line in lines if word in line) for word in ("span two", "rs", "b2", "full width")}
    assert row["span two"].count("│") == 3 and row["full width"].count("│") == 2
    # (the spanning cell's width shared by its columns - "rs" had 48 of 60)
    bars = [n for n, ch in enumerate(row["rs"]) if ch == "│"]
    widths = [b - a for a, b in zip(bars, bars[1:])]
    assert len(widths) == 3 and max(widths) - min(widths) <= 3, row["rs"]
    assert row["b2"].index("b2") == row["rs"].index("b ")


# -- 7. a page laid out in part: the scroll bar as long as all of it, Ctrl+End to its end -------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_a_page_laid_out_in_part_has_its_whole_height_and_ctrl_end_reaches_the_end(full, monkeypatch):
    if full:
        pytest.importorskip("markdown_it")
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent

    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 1000)
    text = "# L\n\n" + "".join(f"- item {n}\n" for n in range(8000)) + "\nThe very end.\n"
    view = view_of(text, full)
    bar = view.browser.verticalScrollBar()
    assert view.more()
    estimate = bar.maximum()
    view.browser.setFocus()
    APP.sendEvent(view.browser, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier))
    end = time.monotonic() + 60
    while time.monotonic() < end and (view.browser.document().find("The very end.").isNull()
                                      or bar.value() < bar.maximum()):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.3)
    # (the end shown - its part laid out first since the tenth round, the
    # parts before it as they are scrolled to: not all of them first)
    assert bar.value() >= bar.maximum() - 2  # (the range made exact as the end came)
    rect = view.browser.cursorRect(view.link_cursor(view.browser.document().find("The very end.").selectionStart()))
    assert 0 <= rect.top() < view.browser.viewport().height()
    view.load_rest_now()
    whole = view.browser.document().documentLayout().documentSize().height()
    assert 0.6 * whole <= estimate <= 1.5 * whole, (estimate, whole)  # (the bar was as long as the page)


# -- 8. Qt's own parser: code coloured only where its language is known ------------------------------

def _colours_of(view, word: str) -> set:
    found = view.browser.document().find(word)
    block, position = found.block(), found.selectionStart() - found.block().position()
    return {r.format.foreground().color().name() for r in block.layout().formats()
            if r.start <= position < r.start + r.length}


def test_sad_qts_own_parser_colours_no_code_of_unknown_language():
    view = view_of("```\nfor x in list: if done then return null\n```\n\n    indented if in for\n\n"
                   "```text\nplain if in for\n```\n\n```python\ndef f(x):\n    return 'a'\n```\n", False)
    for word in ("for x", "indented if", "plain if"):
        assert not _colours_of(view, word), word
    from ui.markdown_html import GITHUB_DARK, GITHUB_LIGHT

    github = GITHUB_DARK if view.dark else GITHUB_LIGHT
    assert _colours_of(view, "return 'a'") == {github["keyword"]}
    assert _colours_of(view, "f(x)") == {github["function"]}  # (the full palette, as markdown-it's page)


# -- 9. axross-mdcat writes each part as it is rendered -------------------------------------------

def test_sad_mdcat_writes_its_first_part_before_the_last_is_rendered(tmp_path, monkeypatch):
    pytest.importorskip("markdown_it")
    import io

    from core import markdown_cli, markdown_term

    text = "# Long\n\n" + "".join(f"- item {n}\n" for n in range(60_000))
    path = tmp_path / "long.md"
    path.write_text(text, encoding="utf-8")
    written, real = [], markdown_term.render_parts

    class Out(io.StringIO):
        def write(self, data):
            written.append(("write", len(data)))
            return super().write(data)

        def isatty(self):
            return False

    def parts(*args, **kwargs):
        for part in real(*args, **kwargs):
            written.append(("part", len(part)))
            yield part

    monkeypatch.setattr(markdown_term, "render_parts", parts)
    monkeypatch.setattr("sys.stdout", Out())
    assert markdown_cli.main(["--no-pager", "--color", "never", str(path)]) == 0
    kinds = [kind for kind, _n in written]
    assert kinds.count("part") > 3 and kinds.index("write") < len(kinds) - 2  # (written as they come)


# -- 10. the lows -----------------------------------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_a_missing_images_placeholder_keeps_its_size_not_the_one_asked(full, tmp_path):
    (tmp_path / "doc.md").write_text("x", encoding="utf-8")
    view = view_of('Text <img src="gone.png" width="64"> after.\n', full, path=str(tmp_path / "doc.md"))
    pump(0.5)
    widths = []
    block = view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fmt = pieces.fragment().charFormat()
            if fmt.isImageFormat():
                widths.append(fmt.toImageFormat().width())
            pieces += 1
        block = block.next()
    assert widths and min(widths) >= 150, widths  # ("Image not sho…x" squeezed into 64 pixels)


def test_sad_math_writes_a_minus_sign_not_a_hyphen():
    from core import markdown_doc as MD

    for tex in ("-x", "a-b", "x^{-1}"):
        shown = MD.math_text(tex)
        assert "-" not in shown and ("−" in shown or "⁻" in shown), (tex, shown)
    assert "−" in term("Inline $a-b$.\n")


def test_sad_a_named_anchor_without_address_is_no_link():
    pytest.importorskip("markdown_it")
    view = view_of('Here <a name="spot">a place</a> and <a href="https://x.org">a link</a>.\n', True)
    from ui.markdown_html import colours

    palette = colours(view.dark)
    place = view.link_cursor(view.browser.document().find("a place").selectionStart() + 1).charFormat()
    link = view.link_cursor(view.browser.document().find("a link").selectionStart() + 1).charFormat()
    assert place.foreground().color().name() == palette["text"] and not place.anchorHref()
    assert link.foreground().color().name() == palette["link"]
    assert "spot" in view.names


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_mail_links_lookalike_domain_is_shown_in_punycode(full):
    from PyQt6.QtCore import QUrl

    view = view_of("Write to [me](mailto:me@pаypal.com).\n", full)
    href = view.link_cursor(view.browser.document().find("me").selectionStart() + 1).charFormat().anchorHref()
    view.hovered(QUrl(href))
    assert "xn--" in view.status.text() and "pаypal" not in view.status.text(), view.status.text()


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_link_hiding_javascript_behind_a_tab_shows_its_text(full):
    view = view_of('A <a href="jav&#x09;ascript:alert(8)">enttab</a> and [tab](java\tscript:alert(1)) end.\n', full)
    text = view.browser.toPlainText()
    assert "enttab" in text and "javascript" not in text.replace("\t", "") and "ascript" not in text
    for word in ("enttab",):
        assert not view.link_cursor(view.browser.document().find(word).selectionStart() + 1).charFormat().anchorHref()


def test_sad_the_window_may_be_narrow_its_toolbar_wrapping(tmp_path):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "doc.md"
    path.write_text("# One\n\ntext\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.resize(480, 600)
    dialog.show()
    pump(0.5)
    try:
        assert dialog.width() <= 500, dialog.width()  # (it could not be narrower than 742)
        for button in dialog.findChildren(type(dialog.export_button)):
            if button.isVisible():
                assert button.mapTo(dialog, button.rect().topRight()).x() <= dialog.width(), button.text()
        assert dialog.find_field.width() >= 150
    finally:
        dialog.done(0)


# -- typography of the sixth review ------------------------------------------------------------------

def _top(view, text: str) -> int:
    return view.browser.cursorRect(view.link_cursor(view.browser.document().find(text).selectionStart())).top()


def _bottom(view, text: str) -> int:
    return view.browser.cursorRect(view.link_cursor(view.browser.document().find(text).selectionStart())).bottom()


def test_typo_front_matter_on_markdown_its_page_is_a_labelled_box():
    pytest.importorskip("markdown_it")
    # (YAML that is more than "key: value" lines - plain ones are a table since the eighth review)
    view = view_of("---\ntitle: Notes\nnested:\n  a: 1\n---\n\n# Body\n", True)
    label, line = view.browser.document().find("yaml"), view.browser.document().find("title: Notes")
    assert not label.isNull() and label.currentTable() is not None and label.currentTable() == line.currentTable()


@pytest.mark.parametrize("full", [False, True])
def test_typo_the_page_does_not_touch_the_top_of_the_view(full):
    view = view_of("# First\n\ntext\n", full)
    assert _top(view, "First") >= 12


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_table_cells_lines_are_as_far_apart_as_the_texts(full):
    long = "word " * 60
    view = view_of(f"{long}\n\n| a | b |\n|---|---|\n| {long} | x |\n", full, width=700)
    document = view.browser.document()
    prose = document.find("word").block()
    cell = document.find("word", document.find("a").selectionEnd()).block()

    def pitch(block):
        layout = block.layout()
        return layout.lineAt(1).y() - layout.lineAt(0).y()

    assert abs(pitch(cell) - pitch(prose)) <= 2, (pitch(cell), pitch(prose))


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_tables_header_is_on_the_left_as_githubs(full):
    from PyQt6.QtCore import Qt

    view = view_of("| Header | B |\n|---|---|\n| a value that is long | b |\n\n"
                   '<table><tr><th colspan="2">Spanning</th></tr><tr><td>a long value</td><td>b</td></tr></table>\n',
                   full)
    for text in ("Header", "Spanning"):
        block = view.browser.document().find(text).block()
        assert not block.blockFormat().alignment() & Qt.AlignmentFlag.AlignHCenter, text


def test_typo_qts_own_parser_puts_room_between_tables_and_after_raw_html():
    view = view_of("| a |\n|---|\n| 1 |\n\n| b |\n|---|\n| 2 |\n\n<div>raw</div>\n\n| c |\n|---|\n| 3 |\n", False)
    assert _top(view, "b") - _bottom(view, "1") >= 20  # (the cells' padding and a gap)
    assert _top(view, "c") - _bottom(view, "raw") >= 14


def test_typo_markdown_its_page_puts_room_under_raw_html_and_a_nested_list():
    pytest.importorskip("markdown_it")
    view = view_of('<p>A raw paragraph</p> <span>loose</span> words\n\nA paragraph after.\n\n'
                   '<div align="center">centred div</div>\n\nAnother paragraph.\n\n- a\n  - b\n\nAfter the list.\n',
                   True)
    assert _top(view, "A paragraph after") - _bottom(view, "loose") >= 8
    assert _top(view, "Another paragraph") - _bottom(view, "centred div") >= 8
    assert _top(view, "After the list") - _bottom(view, "b") >= 8


@pytest.mark.parametrize("full", [False, True])
def test_typo_an_inline_sums_limits_are_real_scripts(full):
    from PyQt6.QtGui import QTextCharFormat

    view = view_of("Inline $\\sum_{k=1}^{n} k^2$ here.\n", full)
    text = view.browser.toPlainText()
    assert "ₖ" not in text and "k=1" in text  # (Unicode's tiny letters: unreadable)
    found = view.browser.document().find("k=1")
    fmt = view.link_cursor(found.selectionStart() + 1).charFormat()
    assert fmt.verticalAlignment() == QTextCharFormat.VerticalAlignment.AlignSubScript


@pytest.mark.parametrize("full", [False, True])
def test_happy_the_view_paints_its_margins_as_the_page_and_keeps_no_undo(full):
    """(a guard: a method put into the middle of MarkdownBrowser.__init__ took
    its last lines with it - the margins grey, an undo stack, long words
    pushing tables past the view)"""
    from PyQt6.QtGui import QColor, QPalette, QTextOption

    view = view_of("# T\n\ntext\n", full, width=1200)
    image = view.browser.grab().toImage()
    base = view.browser.palette().color(QPalette.ColorRole.Base).name()
    assert QColor(image.pixel(5, image.height() // 2)).name() == base
    assert not view.browser.document().isUndoRedoEnabled()
    assert view.browser.wordWrapMode() == QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere


def test_sad_a_paragraph_of_many_raw_tags_is_sanitized_in_linear_time():
    """(the look-ahead for a dropped tag's end joined all the paragraph's
    later raw HTML for each tag: 20,000 inline tags took 46 s)"""
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD

    text = "Start " + "<b>x</b> " * 30_000 + "<script> named, never closed.\n"
    began = time.process_time()
    MD.parse(text)
    assert time.process_time() - began < 5, time.process_time() - began
