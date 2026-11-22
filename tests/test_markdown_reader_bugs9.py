"""Bugs of the ninth review of the Markdown reader, each first a failing test
here - in both of Qt's paths (markdown-it's page and Qt's own parser, md4c)
and the terminal where they share the bug. (Real documents whole and in
parts: tests/test_markdown_corpus.py; the look: tests/test_markdown_golden.py.)
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
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])
ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def view_of(text: str, full: bool, path: str = "", width: int = 900, height: int = 700, whole: bool = True):
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), path) if path else None)
    view.full = view.full and full
    view.resize(width, height)
    view.show()
    view.render(text)
    end = time.monotonic() + 60
    while time.monotonic() < end and (view.status.text().startswith(MV.tr("Rendering…"))
                                      or view.asked - set(view.images)):
        APP.processEvents()
        time.sleep(0.005)
    if whole:
        view.load_rest()
        while time.monotonic() < end and view.more():
            APP.processEvents()
            time.sleep(0.005)
    pump(0.1)
    return view


# -- 1. an endless laying out while idle: a table a pixel too wide -----------------------------------

def dialog_of(path: Path, full: bool, width: int = 1000, height: int = 800):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    dialog = MarkdownViewerDialog(LocalFS(), str(path))
    dialog.view.full = dialog.view.full and full
    if not full:
        dialog.view.render(dialog.view.markdown or path.read_text(encoding="utf-8"))
    dialog.resize(width, height)
    dialog.show()
    pump(3.0)  # (read, laid out, its images and margins settled)
    return dialog


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("name, width", [("README.md", 800), ("README.md", 1000), ("README.md", 1400),
                                         ("docs/PROXY_SUPPORT.md", 1000)])
def test_sad_an_idle_page_is_not_laid_out_again_and_again(name, full, width, monkeypatch):
    from ui import markdown_view as MV

    path = ROOT / name
    if not path.is_file():
        pytest.skip(f"{name} not here")
    calls = []
    original = MV.MarkdownView.fit_images
    monkeypatch.setattr(MV.MarkdownView, "fit_images", lambda self: (calls.append(1), original(self))[1])
    dialog = dialog_of(path, full, width)  # (its timer tied to the counting one)
    try:
        calls.clear()
        began, end = time.process_time(), time.monotonic() + 2.0
        while time.monotonic() < end:  # (idle: the events as they come, little polling of its own)
            APP.processEvents()
            time.sleep(0.05)
        spent = time.process_time() - began
        # (a table a pixel too wide: the right margin flipped 65 <-> 64 forever,
        # the page laid out again each time - 19 % of a CPU, idle)
        assert len(calls) == 0, f"{len(calls)} fittings while idle"
        TB.budget(spent < 0.3, f"{spent:.2f} s of CPU in 2 s idle")
    finally:
        dialog.close()
        dialog.deleteLater()


# -- 2. a long ordered list numbered "1." on every line began at 1 again ------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_long_list_numbered_one_on_every_line_is_numbered_on(full):
    text = "# List\n\n" + "".join(f"1. item number {n}\n" for n in range(1, 3101))  # (3,000 lines and more: cut)
    view = view_of(text, full)
    document = view.browser.document()
    layout = document.documentLayout()
    wrong, tops = [], []
    block = document.begin()
    while block.isValid():
        if block.textList() is not None:
            if block.textList().itemText(block) != block.text().split()[-1] + ".":
                wrong.append((block.text(), block.textList().itemText(block)))
            tops.append(layout.blockBoundingRect(block).top())
        block = block.next()
    assert len(tops) == 3100 and not wrong, wrong[:3]  # (item 301 was "1.")
    steps = [b - a for a, b in zip(tops, tops[1:], strict=False)]
    assert max(steps) - min(steps) <= 2, (min(steps), max(steps))  # (a gap of 45 px every 300 items)
    assert "\u200b" not in view.browser.toPlainText()  # (the line where it was cut)


def test_sad_the_terminal_numbers_a_list_on_across_its_parts(monkeypatch):
    from core import markdown_term as T

    monkeypatch.setattr(T, "STREAM_CHARS", 0)
    text = "# List\n\n" + "".join(f"1. item {n}\n" for n in range(1, 61))
    parts = T.text_parts(text, 20)  # (as render_parts cuts a text over 500 KB)
    assert len(parts) > 1
    out = ANSI.sub("", "".join(T.Renderer(T.Options(width=60, depth="none")).render(T.MD.parse(part))
                               for part in parts))
    shown = re.findall(r"^\s*(\d+)\. item (\d+)", out, re.MULTILINE)
    assert len(shown) == 60 and all(a == b for a, b in shown), [s for s in shown if s[0] != s[1]][:3]  # ("1997." "1.")


# -- 3. Qt's own parser: an image once per piece of its alt text (brackets, escapes) ---------------

@pytest.mark.parametrize("text", ["![*e* [b]](logo.png)\n", '![a *e* and `c` and [b]](logo.png "T")\n',
                                  "![a\\]b](logo.png)\n", "[![a *b* [c]](logo.png)](x.md)\n"])
def test_sad_qts_own_parser_shows_an_image_with_brackets_in_its_alt_once(text, tmp_path):
    (tmp_path / "logo.png").write_bytes((ROOT / "tests" / "golden" / "markdown" / "pic.png").read_bytes())
    view = view_of(text, False, path=str(tmp_path / "doc.md"))
    shown = view.browser.toPlainText()
    assert shown.count("￼") == 1 and "logo.png" not in shown, repr(shown)  # (2, 5 images; "a]b" as text)


# -- 4. the root of a sum: its bar over the first letter only ------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_the_root_of_a_sum_with_scripts_is_not_the_root_of_its_first_letter(full):
    view = view_of("$$\n\\sqrt{x^2+y^2} = r\n$$\n\nAnd $\\sqrt{a+b}$ inline.\n", full)
    document = view.browser.document()
    shown = view.browser.toPlainText()
    assert "√(x" in shown, repr(shown)  # (√x̄²+y²: read as √(x²) + y²)
    assert not document.find("x").charFormat().fontOverline()
    plain = document.find("a+b")
    assert not plain.isNull() and plain.charFormat().fontOverline()  # (no scripts in it: its bar over all of it)


# -- 6. Qt's own parser: a raw-HTML table of <td> cells drew its first row as a header ---------------

@pytest.mark.parametrize("full", [True, False])
def test_sad_a_raw_html_tables_first_row_of_cells_is_no_header(full):
    view = view_of("<table><tr><td>first cell</td><td>b</td></tr><tr><td>c</td><td>d</td></tr></table>\n\n"
                   "<table><tr><th>head cell</th></tr><tr><td>e</td></tr></table>\n", full)
    document = view.browser.document()
    cell = document.find("first cell")
    table = cell.currentTable()
    assert table is not None and cell.charFormat().fontWeight() < 600  # (bold, on the header's tint)
    background = table.cellAt(0, 0).format().background()
    assert background.style().name == "NoBrush" or background.color() == table.cellAt(1, 0).format().background().color()
    assert document.find("head cell").charFormat().fontWeight() >= 600  # (a <th>: a header still)
    assert "\ue09a" not in view.browser.toPlainText()  # (its mark gone)


# -- 7. markdown-it's page: raw HTML's <pre> unpadded, the next paragraph against it -------------------

def test_typo_raw_htmls_pre_is_a_padded_box_with_room_after_it():
    def gap_after(text: str, needle: str):
        view = view_of(text + "\n\nThe next paragraph.\n", True)
        document = view.browser.document()
        table = document.find(needle).currentTable()
        assert table is not None and table.format().cellPadding() >= 8  # (no room inside it)
        layout = document.documentLayout()
        return layout.blockBoundingRect(document.find("The next paragraph").block()).top() \
            - layout.frameBoundingRect(table).top()

    # (as a fenced code block's box: the next paragraph was against it)
    assert gap_after("<pre>\nraw preformatted\n</pre>", "raw preformatted") == gap_after("```\nraw fenced\n```",
                                                                                          "raw fenced")


# -- 9. the terminal's tables: link addresses in cells, columns as wide as them; alt text's marks ------

TABLE = ("| Project | License |\n|---|---|\n"
         "| [adb_shell](https://github.com/JeffLIrion/adb_shell) | [MIT](https://opensource.org/licenses/MIT) |\n")


def test_sad_the_terminal_puts_a_cells_link_address_under_the_table():
    from core import markdown_term as T

    out = T.render(TABLE, T.Options(width=60, depth="none"))
    cells = [line for line in out.splitlines() if line.startswith("│")]
    assert not any("http" in line for line in cells), out  # (printed in the cell, broken mid-word)
    assert "[1] https://github.com/JeffLIrion/adb_shell" in out and "[2] https://opensource.org/licenses/MIT" in out
    license_column = cells[0].split("│")[2]
    assert len(license_column) <= len(" MIT[2] ") + 4, out  # (as wide as the address made it: 19 for "MIT")


def test_sad_the_terminals_hyperlinked_cell_shows_its_text_only():
    from core import markdown_term as T

    out = T.render(TABLE, T.Options(width=60, depth="truecolor", hyperlinks=True))
    shown = ANSI.sub("", out)
    assert "https://" not in shown and "adb_shell" in shown
    assert "\x1b]8;;https://github.com/JeffLIrion/adb_shell\x1b\\" in out  # (the address in the hyperlink)


def test_sad_the_terminal_shows_an_images_alt_text_without_its_marks():
    from core import markdown_term as T

    out = T.render("![a *emph* and `code` and **bold**](https://x.org/p.png)\n", T.Options(width=80, depth="none"))
    assert "a emph and code and bold" in out and "*" not in out and "`" not in out


# -- 10. the paths disagreed --------------------------------------------------------------------------

@pytest.mark.parametrize("full", [True, False])
def test_typo_bullets_by_depth_as_githubs_in_both_paths(full):
    from PyQt6.QtGui import QTextFormat, QTextListFormat

    view = view_of("- a\n  - b\n    - c\n", full)
    document = view.browser.document()
    styles = {QTextListFormat.Style.ListDisc: "disc", QTextListFormat.Style.ListCircle: "circle",
              QTextListFormat.Style.ListSquare: "square"}
    drawn = []
    for word in "abc":
        block = document.find(word).block()
        own = block.blockFormat()
        # (Qt draws the style an item's own format says: the HTML's "li ul" gave a circle at every depth)
        style = QTextListFormat.Style(own.intProperty(QTextFormat.Property.ListStyle)) \
            if own.hasProperty(QTextFormat.Property.ListStyle) else block.textList().format().style()
        drawn.append(styles.get(style))
    assert drawn == ["disc", "circle", "square"]


def test_typo_qts_own_parser_numbers_footnotes_as_markdown_it_and_github():
    view = view_of("A note[^n].\n\n[^n]: The note.\n", False)
    shown = view.browser.toPlainText()
    assert "1. The note" in shown and "[1] The note" not in shown  # ("[1]": Qt's own parser's alone)


def test_typo_a_definition_list_is_spaced_alike_in_both_paths():
    text = "Term one\n: First definition\n: Second definition\n\nTerm two\n: Third definition\n\nAfter.\n"
    steps = {}
    for full in (True, False):
        document = view_of(text, full).browser.document()
        layout = document.documentLayout()
        tops = [layout.blockBoundingRect(document.find(word).block()).top()
                for word in ("Term one", "First definition", "Second definition", "Term two", "Third definition")]
        steps[full] = [b - a for a, b in zip(tops, tops[1:], strict=False)]
    assert all(abs(a - b) <= 2 for a, b in zip(steps[True], steps[False], strict=True)), steps  # (24, 36: looser)


def test_typo_qts_own_parsers_code_in_an_alert_is_padded():
    view = view_of("> [!NOTE]\n> Text.\n>\n> ```python\n> padded_code = 1\n> ```\n\nAfter.\n", False)
    document = view.browser.document()
    code, title = document.find("padded_code"), document.find("Note")
    box = code.currentTable()
    assert box is not None and box != title.currentTable()  # (a box of its own in the alert's)
    cell = box.cellAt(code).format().toTableCellFormat()
    assert min(cell.topPadding(), cell.leftPadding()) >= 8  # (on a block's grey: against its edges)
    assert document.find("python").currentTable() == box  # (its language on it)


@pytest.mark.parametrize("full", [True, False])
def test_typo_a_tables_rows_are_as_low_as_githubs(full):
    view = view_of("| A | B |\n|---|---|\n| row one | x |\n| row two | y |\n\n```\nboxed code\n```\n", full)
    document = view.browser.document()
    layout = document.documentLayout()
    step = layout.blockBoundingRect(document.find("row two").block()).top() \
        - layout.blockBoundingRect(document.find("row one").block()).top()
    line = view.browser.fontMetrics().lineSpacing()
    assert step <= line + 14, (step, line)  # (37 pixels at 12-pixel letters: GitHub's 37 are at 16)
    code = document.find("boxed code")
    box = code.currentTable()
    padding = max(box.format().cellPadding(), box.cellAt(code).format().toTableCellFormat().topPadding())
    assert padding >= 8  # (a code box keeps its room)
