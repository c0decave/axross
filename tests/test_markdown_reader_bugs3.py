"""Bugs of the third review of the Markdown reader, each first a failing test
here. Many are in Qt's own parser's path (md4c): the fallback when
markdown-it-py is not installed - optional in axross - brought to the same
standard by text passes before it and fixes after it.
"""

from __future__ import annotations

import base64
import io
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


def view_of(text: str, full: bool, path: str = "", width: int = 900):
    """A MarkdownView of *text* (markdown-it or Qt's own parser), rendered."""
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    source = MV.ImageSource(LocalFS(), path) if path else None
    view = MV.MarkdownView(source)
    view.full = view.full and full
    view.resize(width, 700)
    view.show()
    view.render(text)
    end = time.monotonic() + 10
    while time.monotonic() < end and (view.status.text() or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    pump(0.2)
    return view


def anchors_and_images(view) -> tuple[list[str], list[str]]:
    hrefs, names = [], []
    block = view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fmt = pieces.fragment().charFormat()
            if fmt.isImageFormat():
                names.append(fmt.toImageFormat().name())
            elif fmt.isAnchor() and fmt.anchorHref():
                hrefs.append(fmt.anchorHref())
            pieces += 1
        block = block.next()
    return hrefs, names


def _png(path: Path, width: int = 40, height: int = 30) -> None:
    from PyQt6.QtGui import QColor, QImage

    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor("red"))
    assert image.save(str(path), "PNG")


# -- #3 the escape marks never reach a link or an image ------------------------------------------

def test_sad_qts_own_parser_leaves_no_mark_in_a_link_or_an_image_name():
    text = ("[q](https://x.com/?a=<b>&c) <https://x.com/a<b> [rel](other.md#sec<x>) "
            "![i](pic<1>.png) word\u2060joiner\n")
    view = view_of(text, full=False)
    try:
        hrefs, names = anchors_and_images(view)
        assert all("\u2060" not in href and "" not in href for href in hrefs), hrefs
        assert "https://x.com/?a=%3Cb%3E&c" in hrefs or "https://x.com/?a=<b>&c" in hrefs
        assert names and all("\u2060" not in n and "" not in n for n in names), names
        assert "word\u2060joiner" in view.browser.toPlainText()  # (the author's own joiner stays)
    finally:
        view.deleteLater()


def test_sad_the_release_notes_links_carry_no_mark_either():
    ReleaseNotesView = pytest.importorskip("ui.update_ui").ReleaseNotesView  # (axross's own: not in an export)

    view = ReleaseNotesView()
    try:
        view.set_notes("[q](https://x.com/?a=<b>) and a\u2060b\n")
        hrefs = []
        block = view.document().begin()
        while block.isValid():
            pieces = block.begin()
            while not pieces.atEnd():
                fmt = pieces.fragment().charFormat()
                if fmt.isAnchor():
                    hrefs.append(fmt.anchorHref())
                pieces += 1
            block = block.next()
        assert hrefs and all("\u2060" not in h for h in hrefs)
        assert "a\u2060b" in view.toPlainText()
    finally:
        view.deleteLater()


# -- #4 Copy Code Block in Qt's own parser -------------------------------------------------------

@pytest.mark.parametrize("full", [False, True])
def test_sad_copy_code_block_copies_one_code_block_with_its_tabs(full):
    text = ("```\nfirst()\n\n\tindented_with_tab()\n```\n```\nsecond()\n```\n\n    indented code\n\n"
            "Text\n\n```diff\n- removed\n+ added\n```\n\n- item\n\n  ```sh\n  echo nested\n  ```\n\n"
            "> ```py\n> quoted = True\n> ```\n")
    view = view_of(text, full=full)
    try:
        document = view.browser.document()
        assert view.code_block_at(document.find("echo nested").position()) == "echo nested\n"
        assert view.code_block_at(document.find("quoted").position()) == "quoted = True\n"
        assert view.code_block_at(document.find("first()").position()) == "first()\n\n\tindented_with_tab()\n"
        assert view.code_block_at(document.find("second()").position()) == "second()\n"
        assert view.code_block_at(document.find("indented code").position()) == "indented code\n"
        assert view.code_block_at(document.find("+ added").position()) == "- removed\n+ added\n"
    finally:
        view.deleteLater()


# -- #5 Export HTML of Qt's own parser -----------------------------------------------------------

def test_sad_qts_own_parser_exports_only_checked_images_and_safe_links(tmp_path):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    _png(tmp_path / "pic.png")
    (tmp_path / "doc.md").write_text(
        "# Doc\n\n![p](pic.png) ![t](https://tracker.example/t.png) ![a](/etc/passwd) ![o](../outside.png)\n\n"
        "[js](javascript:alert(1)) [web](https://ok.example) [mail](mailto:a@b.example) [here](#doc) "
        "[f](file:///etc/passwd)\n")
    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "doc.md"))
    viewer.view.full = False
    viewer.show()  # (images are asked for as the page is laid out)
    viewer.reload()
    try:
        end = time.monotonic() + 10
        while time.monotonic() < end and "pic.png" not in viewer.view.originals:
            APP.processEvents()
            time.sleep(0.01)
        out = tmp_path / "out.html"
        assert viewer.export_html(str(out)) == str(out)
        page = out.read_text()
        assert page.count("<img") == 1 and '<img src="data:image/png;base64,' in page
        targets = re.findall(r'\b(?:src|href)="([^"]*)"', page)
        for bad in ("tracker.example", "/etc/passwd", "../outside", "javascript", "file:"):
            assert not any(bad in target for target in targets), bad
        assert 'href="https://ok.example"' in page and 'href="mailto:a@b.example"' in page
    finally:
        viewer.deleteLater()


# -- #1 an image in a table cell ------------------------------------------------------------------

def _image_widths(view) -> list[tuple[str, float, int]]:
    """(name, width shown, columns of its table or 0) of every image."""
    from PyQt6.QtGui import QTextCursor

    found = []
    document = view.browser.document()
    block = document.begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            piece = pieces.fragment()
            fmt = piece.charFormat()
            if fmt.isImageFormat():
                cursor = QTextCursor(document)
                cursor.setPosition(piece.position())
                table = cursor.currentTable()
                width = fmt.toImageFormat().width() or view.images[fmt.toImageFormat().name()].width()
                found.append((fmt.toImageFormat().name(), width, table.columns() if table else 0))
            pieces += 1
        block = block.next()
    return found


@pytest.mark.parametrize("full", [False, True])
def test_sad_an_image_in_a_table_cell_takes_its_share_of_the_width(tmp_path, full):
    _png(tmp_path / "shot.png", 1600, 900)
    _png(tmp_path / "a.png", 1200, 700)
    _png(tmp_path / "b.png", 1200, 700)
    text = ("| Screenshot | Description |\n|---|---|\n| ![s](shot.png) | The main window |\n\n"
            "| | |\n|---|---|\n| ![a](a.png) | ![b](b.png) |\n\n![wide](shot.png)\n")
    view = view_of(text, full=full, path=str(tmp_path / "doc.md"))
    try:
        room = view.room()
        widths = _image_widths(view)
        assert len(widths) == 4
        for name, width, columns in widths:
            assert width <= (room / columns if columns else room) + 1, (name, width, columns, room)
        assert view.browser.horizontalScrollBar().maximum() == 0
    finally:
        view.deleteLater()


# -- #8 long code lines ----------------------------------------------------------------------------

LONG = ("# Code\n\n```bash\ncurl -fsSL https://example.com/releases/latest/download/install.sh | bash"
        "   # one long comment that goes on and on and on and on and on\n```\n\n"
        "> Quote with `a_very_long_inline_code_span_that_cannot_break_at_all_because_it_has_no_spaces_xx`\n\n"
        "| key | value |\n|---|---|\n| a | https://example.com/a/very/long/url/without/spaces/that/forces"
        "/the/table/wider/than/the/page/yes/really/it/does |\n\n    indented " + "x" * 30 + " y" * 60 + "\n")


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_long_code_line_wraps_in_its_box_and_never_scrolls_the_page(full):
    view = view_of(LONG, full=full, width=520)
    try:
        assert view.browser.horizontalScrollBar().maximum() == 0
        document = view.browser.document()
        block = document.find("curl -fsSL").block()
        assert block.layout().lineCount() > 1  # (wrapped in its box)
        assert view.code_block_at(block.position()).startswith("curl -fsSL https://example.com/releases/latest")
        assert "\n" not in view.code_block_at(block.position()).rstrip("\n")  # (one line, as written)
    finally:
        view.deleteLater()


# -- #6 a big table is laid out whole -------------------------------------------------------------

def big_table(rows: int, columns: int = 8) -> str:
    head = "| " + " | ".join(f"h{c}" for c in range(columns)) + " |\n|" + "---|" * columns + "\n"
    return "# Data\n\n" + head + "".join("| " + " | ".join(f"r{r}c{c}" for c in range(columns)) + " |\n"
                                         for r in range(rows)) + "\nAfter.\n"


def _tables(view):
    from PyQt6.QtGui import QTextTable

    return [frame for frame in view.browser.document().rootFrame().childFrames() if isinstance(frame, QTextTable)]


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_big_table_is_laid_out_whole_as_one_table(full):
    """500 rows x 8: from row 374 (Qt's own parser: 187) it was source text."""
    view = view_of(big_table(500), full=full)
    try:
        text = view.browser.toPlainText()
        assert "r499c7" in text and "```" not in text and "|" not in text and not view.notice.isVisible()
        tables = _tables(view)
        assert sum(table.rows() for table in tables) == 501  # (the header once)
        assert text.count("h0") == 1
        widths = {tuple(c.rawValue() for c in t.format().columnWidthConstraints()) for t in tables}
        assert len(tables) == 1 or len(widths) == 1  # (its parts in line)
    finally:
        view.deleteLater()




# -- #7 raw-HTML headings -------------------------------------------------------------------------

HTML_HEADINGS = ('<h1 align="center">Project <img src="logo.png" alt="logo"></h1>\n\nIntro.\n\n'
                 "## Install\n\n<h2>Usage</h2>\n\n<h3>Usage</h3>\n\ntext\n")


def test_sad_raw_html_headings_are_headings_with_anchors():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD

    doc = MD.parse(HTML_HEADINGS)
    assert [(h.level, h.text, h.anchor) for h in doc.headings] == [
        (1, "Project", "project"), (2, "Install", "install"), (2, "Usage", "usage"), (3, "Usage", "usage-1")]


@pytest.mark.parametrize("full", [True])
def test_sad_raw_html_headings_are_in_the_outline_and_scroll_there(full):
    pytest.importorskip("markdown_it")
    from PyQt6.QtCore import QUrl

    view = view_of(HTML_HEADINGS + "\n" + "filler\n\n" * 200, full=full)
    try:
        assert view.headings() == ["Project", "Install", "Usage", "Usage"]
        view.clicked(QUrl("#usage-1"))
        assert view.browser.verticalScrollBar().value() > 0 and "No heading" not in view.status.text()
        block = view.browser.document().find("Project").block()
        assert block.blockFormat().headingLevel() == 1
    finally:
        view.deleteLater()


def test_sad_raw_html_headings_are_headings_in_the_terminal():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    out = ANSI.sub("", T.render(HTML_HEADINGS, T.Options(width=60, depth="truecolor", images="none")))
    lines = out.splitlines()
    assert lines[0].startswith("█ Project") and lines[1].startswith("━")
    assert "▌ Usage" in lines and "▸ Usage" in lines


# -- #10a <sub> / <sup> in the terminal, #10b raw-HTML tables ---------------------------------------

def test_sad_a_sub_that_unicode_cannot_lower_is_its_text_in_the_terminal():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    out = ANSI.sub("", T.render("Built <sub>with care</sub>, H<sub>2</sub>O, x<sup>n</sup>, "
                                "<sup>[note]</sup>\n", T.Options(width=80, depth="truecolor")))
    assert "Built with care, H₂O, xⁿ, [note]" in out and "_(" not in out and "^(" not in out


HTML_TABLE = ("<table>\n  <tr><th>Feature</th><th align=\"right\">Status</th></tr>\n"
              "  <tr><td>Fast</td><td>✅ <b>yes</b></td></tr>\n  <tr><td>Safe</td><td>❌</td></tr>\n</table>\n")


def test_sad_a_raw_html_table_is_a_table_in_the_terminal():
    pytest.importorskip("markdown_it")
    from core import markdown_term as T

    out = ANSI.sub("", T.render(HTML_TABLE, T.Options(width=60, depth="truecolor")))
    assert "┌" in out and "│ Feature │" in out and "│ Fast    │" in out and "╞" in out and "└" in out


@pytest.mark.parametrize("full", [False, True])
def test_sad_a_raw_html_table_is_a_table_in_the_viewer(full):
    if full:
        pytest.importorskip("markdown_it")
    from PyQt6.QtGui import QTextTable

    view = view_of(HTML_TABLE, full=full)
    try:
        tables = [f for f in view.browser.document().rootFrame().childFrames() if isinstance(f, QTextTable)]
        assert len(tables) == 1 and tables[0].rows() == 3 and tables[0].columns() == 2
        assert "<" not in view.browser.toPlainText()
    finally:
        view.deleteLater()


# -- #2 Qt's own parser gets the same Markdown ------------------------------------------------------

FALLBACK = """<p align="center"><img src="logo.png" alt="Logo" width="200"><br><b>tagline</b></p>

<!-- a comment -->

<details>
<summary>More <kbd>Ctrl</kbd>+<kbd>C</kbd></summary>

Inside **md**.

</details>

<h2 align="center">Centered</h2>

H<sub>2</sub>O and x<sup>2</sup>, <a href="https://ok.example">ok</a> <a href="javascript:x()">js</a>
<script>alert(1)</script> <span>plain</span>

> [!NOTE]
> Useful.

Done :tada: and $E = mc^2$, prices $5 and $10, `$x$ <b>` stays.

$$
\\frac{a}{b}
$$

[![Build](https://ci.example/badge.svg)](https://ci.example/r) ![Logo](https://img.example/l.png)

```
<b>code</b> :tada: $x$
```
"""


def test_happy_qts_own_parser_shows_raw_html_alerts_emoji_and_math_as_markdown_it_does(monkeypatch):
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [None])  # (a font with the emoji: whatever this machine has)
    view = view_of(FALLBACK, full=False)
    try:
        text = view.browser.toPlainText()
        for written in ("<p", "<img", "<b>", "<kbd>", "<details>", "<summary>", "<sub>", "<script", "alert(1)",
                        "comment", "[!NOTE]", ":tada:", "$E", "\\frac", "<span>", "badge.svg", "img.example"):
            assert written not in text.split("<b>code</b>")[0].replace("$x$ <b>", ""), written
        # (a <details> without "open" folded, as markdown-it's page shows it - and GitHub: review 23)
        assert "Inside md." not in text
        for shown in ("tagline", "▸ More Ctrl+C", "H2O and x2", "ok", "ℹ Note", "Useful.",
                      "Done 🎉", "E = mc2", "prices $5 and $10", "$x$ <b>", "a\nb", "▣ Build", "▣ Logo", "plain"):
            assert shown in text, shown
        assert "<b>code</b> :tada: $x$" in text  # (code as written)
        assert "Centered" in view.headings()
        from PyQt6.QtGui import QTextCharFormat  # (sub- and superscript as Qt's own, not Unicode's)

        two = view.browser.document().find("H2O")
        two.setPosition(two.selectionStart() + 2)
        assert two.charFormat().verticalAlignment() == QTextCharFormat.VerticalAlignment.AlignSubScript
        hrefs, names = anchors_and_images(view)
        assert "https://ok.example" in hrefs and not any("javascript" in h for h in hrefs)
        assert "https://ci.example/r" in hrefs and [n.split("#")[0] for n in names] == ["logo.png"]
    finally:
        view.deleteLater()


# -- #9 math ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("tex, shown", [
    (r"10\%", "10%"),
    (r"\mathbf{x}^\top W", "x^⊤ W"),
    (r"\| x \|_2", "‖x‖₂"),
    (r"\lVert x \rVert", "‖x‖"),
    (r"\int_0^\infty", "∫_0^∞"),          # (one style for both: ∞ has no small form)
    (r"\sum_{i=1}^{n}", "∑ᵢ₌₁ⁿ"),          # (both small: both raised and lowered)
    (r"\sum\limits_{k} a_k", "∑ₖ aₖ"),
    (r"\begin{pmatrix} 1 & 2 \\ 3 & 4 \end{pmatrix}", "⎛1  2⎞\n⎝3  4⎠"),
    (r"\begin{bmatrix} a \\ b \\ c \end{bmatrix}", "⎡a⎤\n⎢b⎥\n⎣c⎦"),
    (r"f(x) = \begin{cases} 1 & x \ge 0 \\ 0 & \text{otherwise} \end{cases}",
     "f(x) = ⎧1  x ≥ 0\n       ⎩0  otherwise"),
])
def test_sad_math_is_shown_whole_and_in_one_style(tex, shown):
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD

    assert MD.math_text(tex) == shown


def test_sad_math_that_is_not_understood_is_shown_as_written_as_code():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui.markdown_html import to_html

    assert MD.math_display(r"\frac{a}{b} \weird{x}") == (r"a/b \weird{x}", False)
    assert MD.math_display(r"\frac{a}{b}") == ("a/b", True)
    page = to_html(MD.parse(r"$\frac{a}{b} \weird{x}$" + "\n"))
    assert r"a/b <code>\weird{x}</code>" in page.replace("<i>", "").replace("</i>", "")  # (letters in italic since the tenth round: bugs10)
    out = ANSI.sub("", T.render(r"$\frac{a}{b} \weird{x}$" + "\n", T.Options(width=60)))
    assert r"a/b \weird{x}" in out


def test_sad_a_matrix_block_stays_in_line_in_the_middle():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui.markdown_html import to_html

    text = "$$\nA = \\begin{pmatrix} 1 & 2 \\\\ 3 & 4 \\end{pmatrix}\n$$\n"
    lines = [line for line in ANSI.sub("", T.render(text, T.Options(width=60))).splitlines() if line.strip()]
    assert lines[0].index("⎛") == lines[1].index("⎝") and lines[0].startswith(" " * 10)
    page = to_html(MD.parse(text))
    # (a table of its cells in the math face - test_markdown_reader_bugs5: no monospace rows; in the
    # middle of the page, a row of items since the twelfth round: bugs12)
    assert '<table align="center"' in page and "math-rows" not in page
    # (its parentheses of one piece, as tall as its rows, since the eleventh round: bugs11 - ⎛⎝ stood apart)
    # (a piece of each a row since the thirteenth review: bugs14 - one glyph was 1.3 rows whatever their count)
    assert "⎛" in page and "⎝" in page and "⎞" in page and "⎠" in page


# -- #10c the link's text in the question, #10d a very long address ----------------------------------

def test_sad_the_question_names_the_links_text_when_it_differs(tmp_path, monkeypatch):
    from PyQt6.QtCore import QUrl

    from core.local_fs import LocalFS
    from ui import markdown_safe
    from ui.markdown_viewer import MarkdownViewerDialog

    (tmp_path / "doc.md").write_text("See [https://github.com/axross](https://evil.example/x) now.\n")
    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "doc.md"))
    viewer.show()
    try:
        end = time.monotonic() + 5
        while time.monotonic() < end and not viewer.loaded_once:
            APP.processEvents()
        pump(0.2)
        asked = []
        monkeypatch.setattr(markdown_safe, "ask_open_link",
                            lambda parent, href, text, **kw: asked.append((href, text, kw)) or False)
        monkeypatch.setattr("core.security_mode.current_policy",
                            lambda: type("P", (), {"allow_external_viewer": True})())
        position = viewer.view.browser.document().find("github.com/axross").position() - 3
        viewer.view.browser.setTextCursor(viewer.view.link_cursor(position))
        viewer.view.clicked(QUrl("https://evil.example/x"))
        assert asked and asked[0][1] == "https://github.com/axross"
        body = markdown_safe.open_link_question("https://evil.example/x", "https://github.com/axross",
                                                where="document")
        assert "The link in the document reads: https://github.com/axross" in body and "notes" not in body
    finally:
        viewer.deleteLater()


def test_sad_a_very_long_address_makes_no_huge_question():
    from ui import markdown_safe

    href = "https://example.com/" + "a" * 3000
    body = markdown_safe.open_link_question(href, "")
    assert max(len(line) for line in body.splitlines()) <= 100
    assert len(body) < 1600 and "3020" in body  # (cut, and how long it is said)


# -- the visual pass ----------------------------------------------------------------------------------

def test_happy_the_page_reads_as_github_shows_it():
    """Prose lines 7 px apart, code in a padded box (no empty line at
    its bottom), tables with one light rule and tinted alternate rows,
    quotes with a bar - in the light and the dark theme."""
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui.markdown_html import DARK, LIGHT, style_sheet, to_html

    text = "Prose.\n\n```py\nx = 1\n```\n\n| a |\n|---|\n| 1 |\n| 2 |\n\n> quoted\n"
    for dark, palette in ((False, LIGHT), (True, DARK)):
        page, sheet = to_html(MD.parse(text), dark), style_sheet(dark)
        assert "line-height: 6px; -qt-line-height-type: line-distance" in re.search(r"\np \{[^}]*\}", sheet).group(0)
        assert f'cellpadding="10" border="0" bgcolor="{palette["pre_bg"]}"' in page and "x = 1\n</code>" not in page
        assert f"border-collapse: collapse; border-color: {palette['rule']}" in page
        assert f'<tr bgcolor="{palette["zebra"]}">' in page
        assert f'<td width="4" bgcolor="{palette["rule"]}" style="padding: 0px">' in page


def test_sad_a_logo_leaves_no_gap_under_it():
    """A proportional line height made the line holding a 160-pixel logo
    240 pixels tall: a gap of 80 pixels under it (README.md's top)."""
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QColor, QImage, QTextDocument
    from PyQt6.QtWidgets import QTextBrowser

    from ui.markdown_html import style_sheet

    image = QImage(256, 256, QImage.Format.Format_RGB32)
    image.fill(QColor("red"))
    browser = QTextBrowser()
    browser.resize(800, 600)
    document = browser.document()
    document.addResource(QTextDocument.ResourceType.ImageResource.value, QUrl("x.png"), image)
    document.setDefaultStyleSheet(style_sheet(False))
    document.setHtml('<p align="center"><img src="x.png" width="160" /></p><h1>Title</h1>')
    browser.show()
    pump(0.1)
    layout = document.documentLayout()
    logo, title = document.begin(), document.begin().next()
    assert layout.blockBoundingRect(title).top() - layout.blockBoundingRect(logo).bottom() < 50
    browser.deleteLater()


def test_happy_qts_own_parser_wears_the_same_colours_and_spacing():
    from PyQt6.QtGui import QTextFormat

    from ui.markdown_html import colours

    view = view_of("# Title\n\nProse that\nwraps.\n\n> [!NOTE]\n> Noted.\n\n```py\nx = 1\n```\n\n> quoted\n", full=False)
    try:
        LIGHT = colours(view.dark)  # noqa: N806 - (the theme the view is in: an earlier test may leave a dark one)
        document = view.browser.document()
        title = document.find("Title").block()
        assert title.charFormat().foreground().color().name() == LIGHT["h1"] or \
            document.find("Title").charFormat().foreground().color().name() == LIGHT["h1"]
        code = document.find("x = 1").block()
        assert code.blockFormat().background().color().name() == LIGHT["pre_bg"]
        prose = document.find("Prose").block()
        assert prose.blockFormat().lineHeightType() == 4  # (QTextBlockFormat.LineDistanceHeight)
        note = document.find("Note").block()
        assert "Noted." not in note.text().split("\u2028")[0]  # (the alert's title a line of its own)
        quoted = document.find("quoted")
        assert quoted.charFormat().foreground().color().name() == LIGHT["quote_fg"]
        assert code.blockFormat().hasProperty(QTextFormat.Property.BlockCodeFence)
    finally:
        view.deleteLater()
