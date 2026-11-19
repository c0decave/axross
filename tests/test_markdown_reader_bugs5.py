"""Bugs of the fifth review of the Markdown reader, each first a failing test
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
ROOT = str(Path(__file__).resolve().parent.parent)
GUI_BLOCK = 0.4


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def view_of(text: str, full: bool, path: str = "", width: int = 900):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), path) if path else None)
    view.full = view.full and full
    view.resize(width, 700)
    view.show()
    view.render(text)
    end = time.monotonic() + 20
    while time.monotonic() < end and (view.status.text() or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return view


def _subprocess(script: str, timeout: int = 240) -> str:
    import subprocess

    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=timeout,
                         env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert out.returncode == 0, out.stderr[-3000:]
    return out.stdout


# -- 1. a list of tens of thousands of items -----------------------------------------------------

_BIG_LIST = """
import sys, time
sys.path.insert(0, {root!r})
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from ui import markdown_view as MV
items = {items!r}
text = "# Big\\n\\n" + "".join(f"- item {{n}} with **bold** and `code`\\n" for n in range(items)) + "\\nThe end.\\n"
view = MV.MarkdownView(None)
view.full = view.full and {full!r}
view.resize(1000, 800)
view.show()
app.processEvents()
gaps, last = [], [time.thread_time()]
def beat():  # (the GUI thread's own time a turn: a loaded machine's waits are no hold-up of ours)
    now = time.thread_time()
    gaps.append(now - last[0])
    last[0] = now
timer = QTimer()
timer.timeout.connect(beat)
timer.start(10)
def settle(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.003)
began = time.monotonic()
last[0] = time.thread_time()
view.render(text)
while time.monotonic() - began < 120 and (time.monotonic() - began < 1 or view.status.text() == MV.tr("Rendering…")
                                          or view.status.text().startswith(MV.tr("Rendering…"))):
    app.processEvents()
    time.sleep(0.003)
shown = view.browser.document().blockCount()
bar = view.browser.verticalScrollBar()
for _ in range(6):   # (to the end, again and again: more of it is laid out)
    bar.setValue(bar.maximum())
    settle(0.4)
scrolled = view.browser.document().blockCount()
view.load_rest()
end = time.monotonic() + 120
while time.monotonic() < end and view.more():
    app.processEvents()
    time.sleep(0.003)
settle(0.3)
found = not view.browser.document().find("item " + str(items - 1) + " with").isNull()
print(round(max(gaps), 3), shown, scrolled, view.browser.document().blockCount(), found)
"""


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_list_of_40000_items_never_holds_the_window_and_opens_at_once(full):
    """A list of 100,000 items held the window up to 2.5 s at a time, longer
    as the page grew, 23 s in all before it could be read: now its first
    parts are laid out, the rest as it is scrolled to (or all of it when
    asked: find, print), never longer than GUI_BLOCK at a time."""
    if full:
        pytest.importorskip("markdown_it")
    out = _subprocess(_BIG_LIST.format(root=ROOT, items=40_000, full=full)).split()
    block, shown, scrolled, total, found = float(out[0]), int(out[1]), int(out[2]), int(out[3]), out[4]
    assert block < GUI_BLOCK, block
    assert shown < 20_000 < total and shown < scrolled  # (opened with a part of it; scrolling lays out more)
    assert total >= 40_000 and found == "True"


# -- 6. a long file: "Rendering…" while it is prepared --------------------------------------------

def test_sad_the_viewer_says_it_is_rendering_a_long_file(tmp_path):
    pytest.importorskip("markdown_it")
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "long.md"
    path.write_text("# Long\n\n" + "A sentence of prose, long enough. " * 20_000 + "\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.show()
    seen, end = set(), time.monotonic() + 30
    while time.monotonic() < end:
        APP.processEvents()
        seen.add(dialog.view.status.text())
        if "Long" in dialog.view.browser.toPlainText() and dialog.view.status.text() == "":
            break
    dialog.done(0)
    assert any(text.startswith("Rendering") for text in seen), seen


# -- 5. headings after a folded <details> --------------------------------------------------------

OUTLINE = ("# A\n\n<details>\n<summary>S</summary>\n\n## Inside\n\ntext\n\n</details>\n\n"
           "## B after\n\npara\n\n### C after\n\n## D\n")


def _block_at(view, position: int) -> str:
    return view.browser.document().findBlock(position).text()


def test_sad_the_outline_and_anchors_after_a_folded_details_go_to_their_heading():
    pytest.importorskip("markdown_it")
    from PyQt6.QtCore import QUrl

    view = view_of(OUTLINE, True)
    assert view.headings() == ["A", "B after", "C after", "D"]
    for name, text in (("b-after", "B after"), ("c-after", "C after"), ("d", "D")):
        assert _block_at(view, view.anchors[name]) == text, name
    view.clicked(QUrl("#axross-details-1"))  # (unfolded: its heading in the outline too, the rest still right)
    pump(0.2)
    assert view.headings() == ["A", "Inside", "B after", "C after", "D"]
    for name, text in (("inside", "Inside"), ("b-after", "B after"), ("d", "D")):
        assert _block_at(view, view.anchors[name]) == text, name


# -- 2. the status line names a hovered link as it is -------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_a_hovered_links_address_is_shown_encoded_never_as_its_lookalike(full):
    from PyQt6.QtCore import QUrl

    view = view_of("[pay](https://xn--pypal-4ve.com/login) [raw](https://pаypal.com/x)\n", full)
    for text, shown in (("pay", "xn--pypal-4ve.com"), ("raw", "xn--pypal-4ve.com")):
        href = view.browser.document().find(text).charFormat().anchorHref()
        view.hovered(QUrl(href))
        assert shown in view.status.text() and "pаypal" not in view.status.text(), view.status.text()


# -- 3. row and column spans in Qt's own parser and the terminal ----------------------------------

SPANS = ("<table><tr><th>A</th><th>B</th><th>C</th></tr>"
         "<tr><td rowspan=\"2\">Tall</td><td>b1</td><td>c1</td></tr>"
         "<tr><td>b2</td><td>c2</td></tr>"
         "<tr><td colspan=\"2\">Wide</td><td>c3</td></tr></table>\n")


def test_sad_qts_own_parser_keeps_spanned_cells_under_their_column():
    from PyQt6.QtGui import QTextTable

    view = view_of(SPANS, False)
    table = next(f for f in view.browser.document().rootFrame().childFrames() if isinstance(f, QTextTable))

    def text(row, column):
        cell = table.cellAt(row, column)
        cursor = cell.firstCursorPosition()
        cursor.setPosition(cell.lastCursorPosition().position(), cursor.MoveMode.KeepAnchor)
        return cursor.selectedText().strip()

    assert table.columns() == 3 and [text(0, c) for c in range(3)] == ["A", "B", "C"]
    assert [text(2, 1), text(2, 2)] == ["b2", "c2"] and text(3, 2) == "c3"
    assert table.cellAt(1, 0).rowSpan() == 2 and table.cellAt(3, 0).columnSpan() == 2
    assert not re.search("[\ue094\ue095]", view.browser.toPlainText())


def test_sad_the_terminal_keeps_spanned_cells_under_their_column():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    lines = ANSI.sub("", T.render(SPANS, T.Options(width=60, depth="none"))).split("\n")
    row = {word: next(line for line in lines if word in line) for word in ("b1", "b2", "c1", "c2", "c3")}
    assert row["b2"].index("b2") == row["b1"].index("b1") and row["c2"].index("c2") == row["c1"].index("c1")
    assert row["c3"].index("c3") == row["c1"].index("c1")


# -- 4. cases and matrices: one centred block in a math face --------------------------------------

CASES = "Before.\n\n$$\n|x| = \\begin{cases} x & x \\ge 0 \\\\ -x & x < 0 \\end{cases}\n$$\n\nAfter $E = mc^2$.\n"


def _palette(view) -> dict:
    from ui.markdown_html import colours

    return colours(view.dark)


@pytest.mark.parametrize("full", [False, True])
def test_sad_cases_are_one_centred_block_in_a_math_face_in_the_texts_colour(full):
    from PyQt6.QtCore import Qt

    view = view_of(CASES, full)
    document = view.browser.document()
    first, second = document.find("x ≥ 0"), document.find("x < 0")
    table = first.currentTable()
    assert table is not None and second.currentTable() == table  # (both rows in one block)
    outer = table
    while outer.parentFrame() is not None and outer.parentFrame() != document.rootFrame():
        outer = outer.parentFrame()  # (the formula's row: the cases a table in a cell of it - bugs12)
    assert outer.format().alignment() & Qt.AlignmentFlag.AlignHCenter
    # (beside all rows - the brace one piece as tall as them since the tenth review: no row between)
    brace = view.browser.cursorRect(document.find("⎨")).center().y()  # (in pieces: bugs14)
    assert view.browser.cursorRect(first).center().y() < brace < view.browser.cursorRect(second).center().y()
    text = _palette(view)["text"]
    for found in (first, second, document.find("|x|"), document.find("mc")):
        fmt = found.charFormat()
        assert not fmt.fontFixedPitch() and "monospace" not in (fmt.fontFamilies() or []), found.selectedText()
        assert fmt.foreground().color().name() == text, found.selectedText()


# -- 7. bare addresses are links (GFM's extended autolinks) ---------------------------------------

BARE = ("Visit https://example.com/a_(b)). Or www.commonmark.org/help, then write to foo@bar.example.com. "
        "Not in `https://code.example.com` nor (www.x.org).\n")


def test_sad_bare_addresses_are_links_on_markdown_its_page_without_linkify():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import to_html

    page = to_html(MD.parse(BARE))
    assert '<a href="https://example.com/a_(b)">https://example.com/a_(b)</a>).' in page
    assert '<a href="http://www.commonmark.org/help">www.commonmark.org/help</a>,' in page
    assert '<a href="mailto:foo@bar.example.com">foo@bar.example.com</a>.' in page
    assert 'href="https://code.example.com"' not in page and '<a href="http://www.x.org">www.x.org</a>)' in page


def test_sad_bare_addresses_are_links_in_the_terminal_and_in_qts_own_parser():
    pytest.importorskip("markdown_it")
    from urllib.parse import unquote

    from core import markdown_term as T

    out = T.render(BARE, T.Options(width=200, depth="truecolor"))
    assert "\x1b]8;;https://example.com/a_(b)\x1b\\" in out and "\x1b]8;;http://www.commonmark.org/help\x1b\\" in out
    view = view_of(BARE, False)
    hrefs = set()
    block = view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            hrefs.add(unquote(pieces.fragment().charFormat().anchorHref()))  # (Qt writes "(" as %28)
            pieces += 1
        block = block.next()
    assert {"https://example.com/a_(b)", "http://www.commonmark.org/help", "mailto:foo@bar.example.com"} <= hrefs


# -- 9. spaces: kept in code, one in prose --------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_code_keeps_its_spaces_and_prose_shows_one(full):
    view = view_of("Run `spaced   code` now  and   then.\n", full)
    assert view.browser.toPlainText().strip() == "Run spaced   code now and then."


# -- 10. the terminal: deep lists, long lists, links to places above --------------------------------

def test_sad_the_terminal_shows_a_list_nested_thousands_deep_flatter_and_says_so():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    text = "".join("  " * level + "- x\n" for level in range(1500))
    out = ANSI.sub("", T.render(text, T.Options(width=80, depth="none")))
    lines = out.split("\n")
    assert len(out) < 200_000 and "↩" not in out  # (22 MB of indentation and wrapped lines)
    assert max(len(line) - len(line.lstrip()) for line in lines) <= 40
    assert any("flatter" in line for line in lines[-3:])


def test_sad_the_terminal_shows_the_start_of_a_long_list_at_once(tmp_path, capsys):
    """markdown-it parses a text of 100,000 items in 7 s: the terminal waited
    for all of it (11 s). Now it renders a long text in parts, the first
    out at once."""
    pytest.importorskip("markdown_it")
    from core import markdown_term as T
    from core.markdown_cli import main

    text = "# Long\n\n" + "".join(f"{n + 1}. item {n} with **bold**\n" for n in range(60_000))
    began = time.monotonic()
    parts = T.render_parts(text, T.Options(width=80, depth="none"))
    first = next(parts)
    assert time.monotonic() - began < 1.5 and "item 0 with" in first
    rest = "".join(parts)
    assert "item 59999 with" in rest and "60000. item 59999" in ANSI.sub("", rest)  # (numbered on)
    path = tmp_path / "long.md"
    path.write_text(text, encoding="utf-8")
    assert main(["--no-pager", "--color", "never", str(path)]) == 0
    out = capsys.readouterr().out
    assert out.count(" with ") == 60_000


def test_sad_a_link_above_the_documents_folder_asks_first_and_a_secret_never_opens(tmp_path, monkeypatch):
    from PyQt6.QtCore import QUrl

    from core import protected_places
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "page.md").write_text("[up](../../../../etc/passwd) [sib](other.md) [key](keys.md)\n", encoding="utf-8")
    (docs / "other.md").write_text("# Other\n", encoding="utf-8")
    (docs / "keys.md").write_text("# Keys\n", encoding="utf-8")
    (tmp_path / "parent.md").write_text("# Parent\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(docs / "page.md"))
    asked, opened = [], []
    monkeypatch.setattr(dialog, "ask_outside", lambda path, text="": asked.append(path) or False)
    monkeypatch.setattr(dialog, "open_file", lambda path: opened.append(path))
    try:
        dialog.follow(QUrl("../../../../etc/passwd"))
        dialog.follow(QUrl("../parent.md"))
        assert len(asked) == 2 and asked[0].endswith("/etc/passwd") and asked[1] == str(tmp_path / "parent.md")
        assert not opened
        assert dialog.path == str(docs / "page.md") and "Not opened" in dialog.view.status.text()
        real = protected_places.read_refusal
        monkeypatch.setattr(protected_places, "read_refusal",
                            lambda path, *a, **k: "secret" if path.endswith("keys.md") else real(path, *a, **k))
        dialog.follow(QUrl("keys.md"))
        assert dialog.path == str(docs / "page.md") and "secret" in dialog.view.status.text()
        dialog.follow(QUrl("other.md"))
        assert dialog.path == str(docs / "other.md") and len(asked) == 2
    finally:
        dialog.done(0)


def test_happy_the_terminal_links_no_file_above_the_documents_folder(tmp_path):
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    out = T.render("[up](../../../../etc/passwd) [f](file:///etc/shadow) [s](sib.md)\n",
                   T.Options(width=80, depth="256", folder=str(tmp_path)))
    links = re.findall("\x1b\\]8;;([^\x1b]+)\x1b", out)
    assert links == [f"file://{tmp_path}/sib.md"]


# -- 8. Qt's own parser: tables, code blocks one after another, front matter ----------------------

def test_sad_qts_own_parser_draws_tables_as_markdown_its_page():
    from PyQt6.QtGui import QTextTable

    view = view_of("| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n| 5 | 6 |\n", False)
    palette = _palette(view)
    table = next(f for f in view.browser.document().rootFrame().childFrames() if isinstance(f, QTextTable))
    fmt = table.format()
    assert fmt.borderBrush().color().name() == palette["rule"] and fmt.cellPadding() >= 4
    assert table.cellAt(0, 0).format().background().color().name() == palette["th_bg"]
    shades = [table.cellAt(row, 0).format().background().color().name() for row in (1, 2)]
    assert palette["zebra"] in shades  # (every second row on a tint)


@pytest.mark.parametrize("full", [False, True])
def test_sad_two_code_blocks_one_after_another_stand_close(full):
    view = view_of("```\nfirst\n```\n\n```\nsecond\n```\n", full)
    first = view.browser.cursorRect(view.link_cursor(view.browser.document().find("first").position()))
    second = view.browser.cursorRect(view.link_cursor(view.browser.document().find("second").position()))
    assert second.top() - first.bottom() <= 50, second.top() - first.bottom()


def test_sad_qts_own_parser_shows_front_matter():
    # (plain "key: value" lines: a table since the eighth review, as GitHub shows them)
    view = view_of("---\ntitle: Notes\ntags: [a, b]\n---\n\n# Body\n", False)
    text = view.browser.toPlainText()
    assert "title" in text and "Notes" in text and "[a, b]" in text and view.headings() == ["Body"]
    view = view_of("---\ntitle: Notes\nnested:\n  a: 1\n---\n\n# Body\n", False)
    assert "title: Notes" in view.browser.toPlainText() and view.headings() == ["Body"]


# -- typography of the fifth review ------------------------------------------------------------------

def _gap_under(view, above: str, below: str) -> int:
    document = view.browser.document()
    top = view.browser.cursorRect(view.link_cursor(document.find(below).selectionStart())).top()
    bottom = view.browser.cursorRect(view.link_cursor(document.find(above).selectionStart())).bottom()
    return top - bottom


@pytest.mark.parametrize("full", [False, True])
def test_typo_math_and_quotes_keep_their_room_under_a_heading(full):
    view = view_of("### Three\n\n$$\nf(x) = \\begin{cases} 1 & x \\\\ 0 & y \\end{cases}\n$$\n\n"
                   "###### Six\n\n> Quoted text.\n", full)
    assert _gap_under(view, "Three", "f(x)") >= 12
    assert _gap_under(view, "Six", "Quoted") >= 12


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_bullet_stands_apart_from_its_text(full):
    from PyQt6.QtGui import QFontMetricsF

    view = view_of("- one item\n- two\n", full)
    block = view.browser.document().find("one item").block()
    assert block.textList() is not None
    # (Qt draws a bullet a space of its block's letters before the text)
    assert QFontMetricsF(block.charFormat().font()).horizontalAdvance(" ") >= 8


@pytest.mark.parametrize("full", [False, True])
def test_typo_a_mixed_lists_tasks_show_their_box_not_a_bullet_too(full):
    from PyQt6.QtGui import QTextBlockFormat, QTextFormat

    view = view_of("- plain\n- [ ] open task\n- [x] done task\n", full)
    # (the glyph is the bullet, no box of Qt's - its cross read "rejected": test_markdown_reader_bugs12)
    for text, glyph in (("open task", "☐"), ("done task", "☑")):
        block = view.browser.document().find(text).block()
        assert block.blockFormat().marker() == QTextBlockFormat.MarkerType.NoMarker, text
        assert block.text().startswith(glyph) and block.blockFormat().intProperty(QTextFormat.Property.ListStyle) == 0
    assert view.browser.document().find("plain").block().blockFormat().marker() \
        == QTextBlockFormat.MarkerType.NoMarker


GITHUB = {False: {"keyword": "#cf222e", "string": "#0a3069", "comment": "#6e7781"},
          True: {"keyword": "#ff7b72", "string": "#a5d6ff", "comment": "#8b949e"}}


@pytest.mark.parametrize("full", [False, True])
def test_typo_code_wears_githubs_colours(full):
    view = view_of('```python\ndef f():\n    return "text"  # note\n```\n', full)
    colours = GITHUB[view.dark]
    document = view.browser.document()
    for word, kind in (("return", "keyword"), ('"text"', "string"), ("# note", "comment")):
        found = document.find(word)
        block, position = found.block(), found.selectionStart() - found.block().position()
        shown = None
        for format_range in block.layout().formats():  # (a highlighter's colours)
            if format_range.start <= position < format_range.start + format_range.length:
                shown = format_range.format.foreground().color().name()
        if shown is None:
            shown = view.link_cursor(found.selectionStart() + 1).charFormat().foreground().color().name()
        assert shown == colours[kind], (word, shown)


@pytest.mark.parametrize("full", [False, True])
def test_typo_mark_is_a_highlight_on_the_texts_colour(full):
    view = view_of("A <mark>marked</mark> word.\n", full)
    palette = _palette(view)
    fmt = view.link_cursor(view.browser.document().find("marked").selectionStart() + 1).charFormat()
    assert fmt.background().color().name() == palette["highlight_bg"]
    assert fmt.foreground().color().name() == palette["text"]


@pytest.mark.parametrize("full", [False, True])
def test_typo_an_unsafe_link_shows_its_text_and_is_no_link(full):
    view = view_of("An unsafe [js](javascript:alert(1)) link.\n", full)
    text = view.browser.toPlainText()
    assert "An unsafe js link." in text and "javascript" not in text
    found = view.browser.document().find("js")
    assert not view.link_cursor(found.selectionStart() + 1).charFormat().isAnchor()


def test_typo_raw_html_blocks_stand_apart():
    pytest.importorskip("markdown_it")
    view = view_of('<form><button>Go</button></form>\n\n<p style="color: red">hidden text</p>\n', True)
    assert _gap_under(view, "Go", "hidden") >= 8


def test_typo_qts_own_parser_shows_a_definition_under_its_term():
    view = view_of("Term\n: Its definition.\n\nAfter.\n", False)
    document = view.browser.document()
    term, definition = document.find("Term").block(), document.find("Its definition").block()
    assert term != definition and definition.blockFormat().leftMargin() >= 20
    assert ": Its" not in view.browser.toPlainText()


def test_typo_qts_own_parser_shows_inline_footnotes_as_notes():
    view = view_of("A note^[An inline footnote.] and another[^b].\n\n[^b]: The other.\n", False)
    text = view.browser.toPlainText()
    assert "^[" not in text and "An inline footnote." in text and "The other." in text
    assert text.index("An inline footnote.") > text.index("and another")  # (with the notes, under the text)
    # (numbered in the order they are referred to, as GitHub and markdown-it number them)
    assert "note[1]" in text and "another[2]" in text and "axross" not in text and "[b]" not in text


def test_typo_the_outline_reads_well_and_the_toolbar_folds_at_a_narrow_window(tmp_path):
    from PyQt6.QtGui import QFontInfo

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "doc.md"
    path.write_text("# One\n\n## Two\n\ntext\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.resize(560, 600)
    dialog.show()
    pump(0.5)
    try:
        outline = dialog.view.outline
        assert QFontInfo(outline.font()).pixelSize() >= 13
        corner = outline.viewport().mapTo(outline, outline.visualItemRect(outline.item(0)).topLeft())
        assert corner.x() >= 6 and corner.y() >= 6  # (padded, not against the corner)
        assert dialog.find_field.width() >= 150  # ("Fi…" at 560 pixels)
        for button in dialog.findChildren(type(dialog.export_button)):
            if button.isVisible():
                assert button.geometry().right() <= dialog.width(), button.text()
    finally:
        dialog.done(0)
