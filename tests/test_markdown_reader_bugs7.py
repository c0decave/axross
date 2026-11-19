"""Bugs of the seventh review of the Markdown reader, each first a failing test
here - in both of Qt's paths (markdown-it's page and Qt's own parser, md4c)
and the terminal where they share the bug. (The look as a whole is guarded
by tests/test_markdown_golden.py.)
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
ROOT = Path(__file__).resolve().parent.parent


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
    end = time.monotonic() + 30
    while time.monotonic() < end and (view.status.text().startswith(MV.tr("Rendering…"))
                                      or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return view


def term(text: str, width: int = 80, depth: str = "none") -> str:
    from core import markdown_term as T

    out = T.render(text, T.Options(width=width, depth=depth))
    return ANSI.sub("", out) if depth != "none" else out


def dialog_of(path, full: bool = True, width: int = 1000, height: int = 700):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV
    from ui.markdown_viewer import MarkdownViewerDialog

    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.view.full = dialog.view.full and full
    dialog.resize(width, height)
    dialog.show()
    end = time.monotonic() + 30
    while time.monotonic() < end and (not dialog.view.browser.toPlainText()
                                      or dialog.view.status.text().startswith(MV.tr("Rendering…"))):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.3)
    return dialog


# -- 1. find starts where the reader is ----------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_the_text_cursor_stays_at_the_start_while_parts_come(full):
    view = view_of((ROOT / "README.md").read_text(encoding="utf-8"), full)
    assert view.browser.textCursor().position() == 0  # (it rode to the end with every part)


@pytest.mark.parametrize("full", [False, True])
def test_sad_find_starts_from_the_top_of_what_is_shown(full):
    dialog = dialog_of(ROOT / "README.md", full)
    view = dialog.view
    try:
        bar = view.browser.verticalScrollBar()
        bar.setValue(bar.maximum() // 2)
        pump(0.2)
        top = view.browser.cursorForPosition(view.browser.viewport().rect().topLeft()).position()
        before = bar.value()
        dialog.find_field.setText("the")
        dialog._find_as_typed()
        found = view.browser.textCursor()
        assert found.hasSelection() and found.selectionStart() >= top - 200, (found.selectionStart(), top)
        assert abs(bar.value() - before) < view.browser.viewport().height()  # (no jump to the top)
    finally:
        dialog.done(0)


# -- 2. prose naming <script>: the tags after it are still tags --------------------------------------

@pytest.mark.parametrize("tag", ["script", "style"])
@pytest.mark.parametrize("where", ["full", "md4c", "term"])
def test_sad_the_tags_after_prose_naming_a_dropped_tag_still_work(tag, where):
    if where != "md4c":
        pytest.importorskip("markdown_it")
    text = f"Use a <{tag}> tag. Press <kbd>Ctrl</kbd> and <b>bold</b> here.\n"
    if where == "term":
        shown = term(text)
        assert f"<{tag}>" in shown and "<kbd>" not in shown and "<b>" not in shown and "Ctrl" in shown
        return
    from PyQt6.QtGui import QFont

    view = view_of(text, where == "full")
    shown = view.browser.toPlainText()
    assert f"Use a <{tag}> tag." in shown and "<kbd>" not in shown and "<b>" not in shown
    bold = view.link_cursor(view.browser.document().find("bold").selectionStart() + 1).charFormat()
    assert bold.fontWeight() >= QFont.Weight.Bold


# -- 3. Qt's own parser: a table right after a code block --------------------------------------------

@pytest.mark.parametrize("gap", ["\n", ""])
def test_sad_qts_own_parser_keeps_a_tables_header_after_a_code_block(gap):
    from PyQt6.QtGui import QFont, QTextTable

    view = view_of(f"Usage:\n\n```\ntool -v\n```\n{gap}| Option | Meaning |\n|---|---|\n| -v | verbose |\n", False)
    table = next(f for f in view.browser.document().rootFrame().childFrames()
                 if isinstance(f, QTextTable) and f.format().border() > 0)
    cell = table.cellAt(0, 0)
    block = cell.firstCursorPosition().block()
    assert block.text() == "Option"  # (an empty line before it: the code's box left it there)
    assert view.link_cursor(block.position() + 1).charFormat().fontWeight() >= QFont.Weight.Bold


# -- 4. Qt's own parser: display math on one line ------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_display_math_on_one_line_is_math(full):
    view = view_of("A\n\n$$\\frac{a}{b}+x\\,y$$\n\nB\n", full)
    text = view.browser.toPlainText()
    assert "$$" not in text and "\\frac" not in text and "\\," not in text and "," not in text, text


# -- 5. a narrow window: the outline out of the way, no word broken in a cell -------------------------

TABLE = ("| Left | Center | Right |\n|:-----|:------:|------:|\n| a | b | 1.50 |\n"
         "| longer cell text that goes on | c | 22.50 |\n")


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_narrow_window_hides_the_outline_and_breaks_no_word_in_a_cell(full, tmp_path):
    path = tmp_path / "t.md"
    path.write_text("# T\n\n## Two\n\n" + TABLE, encoding="utf-8")
    dialog = dialog_of(path, full, width=440)
    view = dialog.view
    try:
        assert not view.outline.isVisible() and not dialog.outline_button.isChecked()
        document = view.browser.document()
        for word in ("Center", "22.50", "Right"):
            block = document.find(word).block()
            assert block.layout().lineCount() == 1, word  # ("Cent|er", "22.5|0")
        dialog.outline_button.setChecked(True)  # (back when asked - and it stays)
        dialog.resize(450, 700)
        pump(0.2)
        assert view.outline.isVisible()
        assert not view.code_block_at(document.find("Center").selectionStart())  # (a cell is no code)
    finally:
        dialog.done(0)


# -- 6. a page laid out in part: the scroll bar dropped far down stays there --------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_the_scroll_bar_dropped_beyond_what_is_laid_out_stays_and_brings_it(full, monkeypatch):
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 1000)
    view = view_of("# L\n\n" + "".join(f"- item {n}\n" for n in range(8000)), full)
    bar = view.browser.verticalScrollBar()
    assert view.more()
    target = int(bar.maximum() * 0.6)
    bar.setValue(target)  # (the thumb dropped at 60 %)
    end = time.monotonic() + 30
    while time.monotonic() < end and view.status.text().startswith(MV.tr("Rendering…")):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.3)
    assert abs(bar.value() - target) < view.browser.viewport().height(), (bar.value(), target)
    shown = view.browser.cursorForPosition(view.browser.viewport().rect().center()).block().text()
    assert shown.startswith("item"), shown  # (laid out there - not the stand-in's blank)


# -- 7. a link's address with spaces around it ------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_spaces_around_a_links_address_keep_the_link(full):
    view = view_of("See [t]( https://y.example ) and [u](  https://z.example/a  \"title\" ).\n", full)
    hrefs = {view.link_cursor(view.browser.document().find(word).selectionStart() + 1).charFormat().anchorHref()
             for word in ("t", "u")}
    assert hrefs == {"https://y.example", "https://z.example/a"}, hrefs
    assert "](" not in view.browser.toPlainText()


# -- 9. Qt's own parser: breaks, code in lists and alerts, \| in a cell, definitions, quotes in quotes ---

def test_sad_qts_own_parser_keeps_a_hard_break_in_its_paragraph():
    view = view_of("Line one\\\nline two  \nline three\n\nNext.\n", False)
    block = view.browser.document().find("Line one").block()
    assert "line two" in block.text() and "line three" in block.text()  # (a paragraph each: their gaps)


@pytest.mark.parametrize("text", ["- item\n\n  ```python\n  x = 1\n  ```\n",
                                  "> [!NOTE]\n> ```python\n> x = 1\n> ```\n"])
def test_sad_qts_own_parser_labels_code_in_a_list_or_an_alert(text):
    view = view_of(text, False)
    label = view.browser.document().find("python")
    assert not label.isNull() and "x = 1" not in label.block().text()


def test_sad_qts_own_parser_shows_an_escaped_pipe_in_a_cells_code():
    view = view_of("| a | b |\n|---|---|\n| `a\\|b` | x |\n", False)
    text = view.browser.toPlainText()
    assert "a|b" in text and "a\\|b" not in text


def test_sad_qts_own_parser_makes_a_definition_after_a_code_block():
    view = view_of("```\ncode\n```\nTerm\n: Its definition.\n", False)
    text = view.browser.toPlainText()
    assert ": Its" not in text and view.browser.document().find("Its definition").block().blockFormat().leftMargin() >= 20


def test_sad_qts_own_parser_draws_a_bar_for_a_quote_in_a_quote():
    from PyQt6.QtGui import QTextTable

    view = view_of("> outer\n>\n> > inner\n", False)
    inner = view.browser.document().find("inner")
    table = inner.currentTable()
    assert table is not None and table.format().border() == 0
    outer = view.browser.document().find("outer").currentTable()
    assert outer is not None and table != outer  # (a box of its own in the outer one)
    assert table.cellAt(0, 0).format().background().style() != 0
    assert isinstance(table.parentFrame(), QTextTable) or table.parentFrame() != view.browser.document().rootFrame()


# -- 10. the lows ----------------------------------------------------------------------------------

def test_sad_a_paused_page_says_so_and_its_progress_never_goes_back(monkeypatch):
    pytest.importorskip("markdown_it")
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 2000)
    text = "# M\n\n" + "".join(f"Formula $x_{{{n}}}^2 + y$ here {n}.\n\n" for n in range(30_000))
    view = MV.MarkdownView(None)
    view.resize(1000, 700)
    view.show()
    seen, end = [], time.monotonic() + 60
    view.render(text)
    while time.monotonic() < end:
        APP.processEvents()
        status = view.status.text()
        if not seen or seen[-1] != status:
            seen.append(status)
        if view._page and not view._page.get("loading") and not status.startswith(MV.tr("Rendering…")):
            break
        time.sleep(0.003)
    pump(1.0)
    assert not view.status.text().startswith(MV.tr("Rendering…")), seen[-5:]  # (it said so until scrolled)
    numbers = [int(m.group(1)) for s in seen for m in [re.search(r"(\d+)\s*%", s)] if m]
    assert numbers == sorted(numbers), numbers  # (25 % then 0 %)


def test_sad_a_placeholder_is_cut_at_a_word_with_an_ellipsis():
    from ui import markdown_view as MV

    shown = MV.elide_words("Image not shown: a-picture-with-a-long-name.png (not beside the file)", 30)
    assert shown.endswith("…") and "..." not in shown and len(shown) <= 30
    assert shown[:-1].rstrip() == shown[:-1] and " " in shown  # (a word whole, then …)


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_badge_chip_needs_no_emoji_font(full):
    view = view_of("A ![build](https://img.shields.io/badge/x-y-green) badge.\n", full)
    text = view.browser.toPlainText()
    assert "build" in text and "🖼" not in text


def test_sad_markdown_its_dark_code_colours_builtins_as_qts_own_parser():
    from ui.markdown_html import _highlight

    page = _highlight("print(str(1))\n", "python", True)
    assert page.count("color") >= 3 and "print" in page
    word = page.split("print")[0]
    assert "color" in word.rsplit("<span", 1)[-1]  # (print in a colour - it was the text's)


# -- typography of the seventh review -----------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_typo_display_math_is_the_bodys_size_and_stacks_a_fraction(full):
    from PyQt6.QtGui import QFontInfo

    view = view_of("Body text.\n\n$$\\frac{a+1}{b} + \\sqrt{x}$$\n\nMore.\n", full)
    document = view.browser.document()
    body = QFontInfo(document.find("Body").charFormat().font()).pixelSize()
    numerator, denominator = document.find("a+1"), document.find("b", document.find("a+1").selectionEnd())
    table = numerator.currentTable()
    assert table is not None and denominator.currentTable() == table  # (stacked: a table of its own)
    rows = {table.cellAt(numerator.selectionStart()).row(), table.cellAt(denominator.selectionStart()).row()}
    assert len(rows) == 2
    size = QFontInfo(view.link_cursor(numerator.selectionStart() + 1).charFormat().font()).pixelSize()
    assert abs(size - body) <= 2, (size, body)
    x = view.link_cursor(document.find("x", document.find("√").selectionEnd()).selectionStart() + 1)
    assert x.charFormat().fontOverline()  # (the root's bar over what it holds)


@pytest.mark.parametrize("full", [False, True])
def test_typo_footnotes_are_readable_and_lead_back(full):
    from PyQt6.QtGui import QFontInfo

    view = view_of("Text with a note[^1].\n\n[^1]: The note itself.\n", full)
    document = view.browser.document()
    note = view.link_cursor(document.find("The note itself").selectionStart() + 1).charFormat()
    assert QFontInfo(note.font()).pixelSize() >= 13
    back = document.find("↩")
    assert not back.isNull() and view.link_cursor(back.selectionStart() + 1).charFormat().anchorHref()


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_lists_rhythm_is_githubs(full):
    view = view_of("- one\n- two\n- three\n", full)
    document = view.browser.document()

    def baseline(word):
        block = document.find(word).block()
        line = block.layout().lineAt(0)
        return block.layout().position().y() + line.y() + line.ascent()

    step = baseline("two") - baseline("one")
    assert 21 <= step <= 27, step  # (30 pixels an item)


def _room_below(view, needle: str) -> float:
    """From the bottom of *needle*'s last line to the bottom of the alert
    it ends (the alert's table, without its own margin)."""
    document = view.browser.document()
    alert = document.find("Note").currentTable()
    bottom = view.browser.cursorRect(document.find(needle)).bottom()  # (the page not scrolled: as the document's)
    return (document.documentLayout().frameBoundingRect(alert).bottom() - alert.format().bottomMargin()) - bottom


@pytest.mark.parametrize("full", [False, True])
def test_typo_code_in_an_alert_leaves_no_empty_line_after_it(full):
    code = _room_below(view_of("> [!NOTE]\n> Text.\n>\n> ```\n> codeline\n> ```\n\nAfter.\n", full), "codeline")
    text = _room_below(view_of("> [!NOTE]\n> Text.\n\nAfter.\n", full), "Text.")
    assert code <= text + 8, (code, text)  # (the code box's bottom margin: 14 pixels more)


@pytest.mark.parametrize("full", [False, True])
def test_typo_code_in_an_alert_is_on_a_grey_of_its_own(full):
    view = view_of("> [!NOTE]\n> Text.\n>\n> ```python\n> codeline = 1\n> ```\n\nAfter.\n", full)
    pump(0.2)
    image = view.browser.viewport().grab().toImage()

    def ground(needle: str):
        rect = view.browser.cursorRect(view.browser.document().find(needle))
        return image.pixelColor(rect.x() + 300, rect.center().y()).name()

    assert ground("codeline") != ground("Text.")  # (the alert's grey: the box was not to be seen)
    label = view.browser.document().find("python")
    from ui.markdown_html import colours

    assert label.charFormat().foreground().color().name() == colours(view.dark)["muted"] or full  # (not the alert's)


def test_typo_the_dark_find_fields_placeholder_is_readable(tmp_path):
    from PyQt6.QtGui import QColor, QPalette

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "d.md"
    path.write_text("# D\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dark = QPalette()
    for role, colour in ((QPalette.ColorRole.Base, "#181818"), (QPalette.ColorRole.Text, "#e6e6e6"),
                         (QPalette.ColorRole.Window, "#1f1f1f"), (QPalette.ColorRole.WindowText, "#e6e6e6")):
        dark.setColor(role, QColor(colour))
    dialog.setPalette(dark)
    pump(0.2)
    try:
        palette = dialog.find_field.palette()
        hint = palette.color(QPalette.ColorRole.PlaceholderText).lightness()
        base = palette.color(QPalette.ColorRole.Base).lightness()
        assert hint - base >= 90, (hint, base)
    finally:
        dialog.done(0)


def test_typo_the_terminal_without_colour_writes_marks_plainly():
    pytest.importorskip("markdown_it")
    out = term("A ***both*** and `` a ` b `` and *it*.\n\n<p align=\"center\">Centred</p>\n", width=40)
    assert "***both***" in out and "_**" not in out
    assert "`` a ` b ``" in out
    line = next(line for line in out.split("\n") if "Centred" in line)
    assert line.index("Centred") >= (40 - len("Centred")) // 2 - 1, line


@pytest.mark.parametrize("text, first, second", [
    ("> Quote one.\n\n> Quote two.\n", "Quote one", "Quote two"),
    ("> Three\n>\n> ```\n> code\n> ```\n\n> Four.\n", "Three", "Four."),
    ("> [!WARNING]\n> Warned.\n>\n> ```sh\n> rm -rf build\n> ```\n\n> A quote.\n", "Warned", "A quote."),
])
def test_sad_qts_own_parser_boxes_two_quotes_one_after_another_apart(text, first, second):
    # (two quotes in one box: without a mark of Qt's text passes none was
    # set apart, and after a code block ending a quote none was either)
    document = view_of(text + "\nAfter.\n", False).browser.document()
    one, two = document.find(first).currentTable(), document.find(second).currentTable()
    assert one is not None and two is not None and one != two


def test_sad_a_scroll_after_the_views_timer_is_gone_does_not_crash():
    # (a lambda on the scroll bar outlived the view's timer: a later test's
    # event loop scrolled it - a crash of the whole run, not of one test)
    import subprocess

    script = f"""
import sys; sys.path.insert(0, {str(ROOT)!r})
from PyQt6 import sip
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from ui import markdown_view as MV
view = MV.MarkdownView(None); view.resize(400, 300); view.show()
view.render("".join(f"line {{i}}\\\\n\\\\n" for i in range(300)))
for _ in range(200):
    app.processEvents()
sip.delete(view.follow_timer)
view.browser.verticalScrollBar().setValue(100)
app.processEvents()
print("alive")
"""
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert done.returncode == 0 and "alive" in done.stdout, done.stderr[-2000:]



def test_sad_a_long_run_of_spaces_takes_qts_own_parser_no_time():
    # (a hard break's spaces were tried from each of a run's: 1.9 MB of nested
    # quotes as HTML took 26 s before Qt's own parser saw them)
    from ui import markdown_view as MV

    began = time.monotonic()
    shown = MV.fallback_text("para\n" + " " * 40_000 + "indented on\n\nx  \ny\n")  # (indentation: kept)
    assert time.monotonic() - began < 1.0
    assert MV.HARD in shown  # (still a hard break at a line's end)
