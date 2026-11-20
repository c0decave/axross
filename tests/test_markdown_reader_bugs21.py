"""The twenty-first round of the Markdown reader (the twentieth review): each
stall fixed for its whole class - a stress test puts the hostile shape into
every container (top level, a table's cell, a heading, a list, a quote, an
alert, a footnote, a definition, a <details>) - YAML coloured again, the
editor's preview in long texts, display math in an alert, the release's
children checked, and the small things. Each test failed before, with the
dependencies of the shipped lock.
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
from tests.test_markdown_reader_bugs20 import _settle, _Turns  # noqa: E402

APP = QApplication.instance() or QApplication([])


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


# -- M1. every common language coloured (a token type its style leaves out: its parent's) ----------

SAMPLES = {
    "yaml": "name: build\non:\n  push:\n    branches: [main]\nretries: 3\n",
    "python": "def f(x):\n    return x + 1  # one\n",
    "json": '{"a": [1, 2.5, true, null], "b": "text"}\n',
    "toml": '[tool.x]\nname = "y"\ncount = 3\n',
    "bash": 'for f in *.md; do echo "$f"; done\n',
    "javascript": "const a = 1;\nfunction g() { return a; }\n",
    "typescript": "let n: number = 4;\n",
    "html": '<a href="x">t</a>\n',
    "css": "body { color: #fff; }\n",
    "c": "int main(void) { return 0; }\n",
    "cpp": "#include <vector>\nint x = 1;\n",
    "java": "public class A { int x = 1; }\n",
    "go": "package main\nfunc main() { x := 1 }\n",
    "rust": "fn main() { let x: u8 = 3; }\n",
    "sql": "SELECT a FROM t WHERE b = 1;\n",
    "ruby": "def f; puts 'x'; end\n",
    "php": "<?php echo $x; ?>\n",
    "diff": "--- a\n+++ b\n-old\n+new\n",
    "ini": "[s]\nkey = value\n",
    "dockerfile": "FROM python:3.12\nRUN pip install x\n",
    "makefile": "all:\n\techo hi\n",
    "xml": '<a b="c">d</a>\n',
}


@pytest.mark.parametrize("lang", sorted(SAMPLES))
def test_sad_every_common_language_is_coloured_in_the_reader(lang):
    """A YAML block was never coloured - window, --html, axross-mdcat: the lexing child's style lookup
    raised KeyError for Token.Literal.Scalar.Plain (a type the style leaves out), the block fell back
    to plain."""
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_html as H

    code = SAMPLES[lang]
    tokens = MD.code_tokens(code, lang)
    assert tokens is not None, lang
    html = H._highlight(code, lang, False)
    assert html and 'style="color: #' in html, (lang, html)
    terminal = T.render(f"```{lang}\n{code}```\n", T.Options(depth="truecolor"))
    assert "\x1b[38;2;" in terminal, lang


def _colour_at(view, word: str) -> str:
    """The colour *word* is drawn in: the highlighter's (Qt's own parser) or its text's own."""
    found = view.browser.document().find(word)
    assert not found.isNull(), word
    block, at = found.block(), found.selectionStart() - found.block().position()
    for piece in block.layout().formats():
        if piece.start <= at < piece.start + piece.length:
            return piece.format.foreground().color().name()
    return found.charFormat().foreground().color().name()


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_yaml_block_is_coloured_in_the_window(full):
    view = _view("```yaml\n" + SAMPLES["yaml"] + "```\n", full)
    assert _colour_at(view, "retries") != _colour_at(view, "build")  # (a key coloured, a plain scalar not)


@pytest.mark.parametrize("lang", ["yaml", "python", "toml", "json"])
def test_sad_the_editor_colours_every_common_language(lang):
    """axross's editor (ui.code_editor) had the same lookup: a YAML file was never coloured."""
    from pygments.lexers import get_lexer_by_name
    from pygments.styles import get_style_by_name
    from pygments.token import Token

    from core.lex_worker import style_of
    from ui import code_editor as CE

    assert style_of(get_style_by_name("default"), Token.Literal.Scalar.Plain) is not None
    editor = CE.CodeEditor()
    try:
        editor.set_language(get_lexer_by_name(lang).name)
        editor.setPlainText(SAMPLES[lang] * 3)
        assert until(lambda: any(block.layout().formats() for block in _blocks(editor.document())), 30), lang
    finally:
        editor.deleteLater()


def _blocks(document):
    block = document.begin()
    while block.isValid():
        yield block
        block = block.next()


# -- M2. the editor's preview follows the typing in a long text and in one without headings --------

def _typed_into_preview(text: str, line: int):
    from PyQt6.QtGui import QTextCursor

    from ui.editor_window import EditorWindow

    window = EditorWindow()
    window.resize(1200, 700)
    window.show()
    tab = window.new_tab()
    try:
        tab.editor.setPlainText(text)
        tab.set_preview(True)
        preview = tab.preview
        assert until(lambda: preview._readable and preview.markdown, 120)
        pump(0.3)
        cursor = tab.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.movePosition(QTextCursor.MoveOperation.Down, n=line)
        cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock)
        tab.editor.setTextCursor(cursor)
        tab.editor.insertPlainText(" TYPEDHERE")
        assert until(lambda: "TYPEDHERE" in preview.markdown and preview._readable, 120)

        def shown() -> bool:
            found = preview.browser.document().find("TYPEDHERE")
            if found.isNull():
                return False
            top = preview.browser.document().documentLayout().blockBoundingRect(found.block()).top()
            bar = preview.browser.verticalScrollBar()
            return bar.value() <= top <= bar.value() + preview.browser.viewport().height()

        assert until(shown, 120)
    finally:
        tab.editor.document().setModified(False)
        window.close()


def test_sad_the_preview_follows_the_typing_far_down_a_long_text():
    """3,000 sections, 36,000 lines, typed at line 24,000: the part there was not laid out - the preview
    stayed where it was."""
    text = "".join(f"## Section {n}\n\n" + "".join(f"Line {n}.{k} words words.\n\n" for k in range(5))
                   for n in range(3000))
    assert text.count("\n") >= 36_000
    _typed_into_preview(text, 24_000)


def test_sad_the_preview_follows_the_typing_in_a_text_without_headings():
    """240 lines, no heading, typed at line 160: the place was a proportion of the page, out of view."""
    text = "".join(f"Paragraph {n} with words.\n\n" if n % 7 else f"```\ncode {n}\nmore\nlines\n```\n\n"
                   for n in range(120))
    _typed_into_preview(text, 160)


# -- H1. every hostile shape in every container: no event-loop turn over 0.25 s ---------------------

HOSTILE_SHAPES = {
    "one code span of 90,000": lambda: "`a`" * 30000,
    "one word of 99,000": lambda: "a" * 99000,
    "150,000 words": lambda: "word " * 150000,
    "12,000 formulas": lambda: "$a$ " * 12000,
    "8,000 links": lambda: "[a](https://e.com) " * 8000,
}
CONTAINERS = {
    "top level": lambda s: s + "\n",
    "table cell": lambda s: "| h | g |\n|---|---|\n| " + s + " | x |\n",
    "heading": lambda s: "# " + s + "\n",
    "list": lambda s: "- " + s + "\n",
    "quote": lambda s: "> " + s + "\n",
    "alert": lambda s: "> [!NOTE]\n> " + s + "\n",
    "footnote": lambda s: "x[^1]\n\n[^1]: " + s + "\n",
    "definition": lambda s: "Term\n:   " + s + "\n",
    "details": lambda s: "<details open><summary>S</summary>\n\n" + s + "\n\n</details>\n",
}


def _longest_turn(text: str, full: bool) -> float:
    from ui import markdown_view as MV

    _settle()
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    pump(0.05)
    turns = _Turns()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 240)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 240)
    view.go_end()
    until(lambda: not view._scheduled, 120)
    pump(0.1)
    longest = turns.stop()
    view.close()
    view.deleteLater()
    return longest


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("place", sorted(CONTAINERS))
@pytest.mark.parametrize("shape", sorted(HOSTILE_SHAPES))
def test_sad_no_hostile_shape_in_any_container_holds_the_window(shape, place, full):
    """Each round fixed the shape named: a long line was cut at the top level only - in a table's cell
    (2.3 s), a heading (1.6 s), one code span of 90,000 characters anywhere (0.8 to 1.8 s) Qt laid it out
    in one turn. Every shape, every container, both parsers: no turn of the GUI thread over 0.25 s."""
    longest = _longest_turn(CONTAINERS[place](HOSTILE_SHAPES[shape]()), full)
    assert longest < 0.25, (shape, place, longest)


def test_sad_a_heading_or_cell_past_the_cap_is_cut_and_said():
    from ui import markdown_view as MV

    text = "# " + "word " * 1000 + "\n\n| a |\n|---|\n| " + "x" * 5000 + " |\n\n```\n# " + "c" * 5000 + "\n```\n"
    shown, why = MV.renderable(text)
    rows = shown.split("\n")
    assert len(rows[0]) <= MV.LINE_CAP + 10 and rows[0].endswith("…")
    assert len(rows[4]) <= MV.LINE_CAP + 20 and "…" in rows[4]
    assert "c" * 5000 in shown  # (code as it is)
    assert str(MV.LINE_CAP) in why
    quoted = MV.renderable("> | a |\n> |---|\n> | " + "y" * 5000 + " |\n")[0]
    assert "y" * 5000 not in quoted and "…" in quoted


# -- H2. one footnote cited 100,000 times -------------------------------------------------------------

def test_sad_a_note_cited_100000_times_shows_its_first_ways_back_and_a_count():
    """Its ways back were one paragraph of 100,000 links laid out at once: Ctrl+End 4.2 s of the
    window's own CPU in one turn."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = "x[^a] " * 100_000 + "\n\n[^a]: The note.\n"
    tokens = MD.parse(text).tokens
    anchors = [t for t in tokens if t.type == "footnote_anchor"]
    assert len(anchors) == MD.BACKREFS and anchors[-1].meta["more"] == 100_000 - MD.BACKREFS
    page = "".join(H.to_html_parts(MD.parse(text)))
    assert "and 99,980 more" in page
    longest = _longest_turn(text, True)
    assert longest < 0.25, longest


# -- H3. many headings: each part as quick as the first ------------------------------------------------

def test_sad_a_page_of_many_headings_is_laid_out_in_linear_time(monkeypatch):
    """Each heading's anchor name went into its letters' format, which Qt hashes by the list's type only:
    each part put in compared its formats with every named one before - 30,000 headings, 136 s."""
    from ui import markdown_view as MV

    costs = []
    real = MV.MarkdownView._append

    def timed(self, fill):
        began = time.thread_time()
        try:
            return real(self, fill)
        finally:
            costs.append(time.thread_time() - began)

    monkeypatch.setattr(MV.MarkdownView, "_append", timed)
    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    view.render("".join(f"# Heading {n}\n\n" for n in range(6000)))
    assert until(lambda: view._readable and view.markdown, 120)
    view.load_rest_now()
    until(lambda: not view.more(), 120)
    assert len(costs) > 20
    first, last = sorted(costs[2:7])[2], sorted(costs[-5:])[2]
    assert last < 3 * first + 0.01, (first, last)
    assert view.go_to_anchor("heading-1999", remember=False)


# -- M3. display math on its own lines in a paragraph (an alert's first, after text) ------------------

ALERT_MATH = "> [!NOTE]\n> $$\n> d = \\frac15\n> $$\n\nText first.\n$$\ne = \\frac17\n$$\nafter.\n"


def test_sad_display_math_in_an_alert_or_after_text_is_a_display_formula():
    """GitHub shows $$...$$ on its own lines as display math: after an alert's marker, after a line of
    text, the window, --html and axross-mdcat set it in the line."""
    from core import markdown_doc as MD
    from core import markdown_term as T

    blocks = [t.content.strip() for t in MD.parse(ALERT_MATH).tokens if t.type == "math_block"]
    assert blocks == ["d = \\frac15", "e = \\frac17"]
    assert [t.type for t in MD.parse("Inline $$a$$ stays.\n").tokens[1].children] == ["text", "math_inline_double",
                                                                                    "text"]
    shown = T.render(ALERT_MATH, T.Options(width=60, depth="none"))
    centred = [line for line in shown.splitlines() if "1/5" in line or "1/7" in line]
    assert len(centred) == 2 and all(line.index("1/") > 20 for line in centred), shown
    assert "Text first." in shown and "after." in shown


# -- L1. a lazy line in a quoted formula ---------------------------------------------------------------

def test_sad_a_lazy_line_in_a_quoted_formula_keeps_the_others_marks_off():
    from core import markdown_doc as MD
    from core import markdown_term as T

    text = "> $$\nf = \\frac17\n> $$\n"
    assert [t.content for t in MD.parse(text).tokens if t.type == "math_block"] == ["\nf = \\frac17\n"]
    assert ">" not in T.render(text, T.Options(depth="none")).replace("│", "")


# -- L2. zoom: Ctrl+wheel, Ctrl+=, bounds ----------------------------------------------------------------

def test_sad_ctrl_wheel_and_ctrl_equals_zoom_through_the_view_within_bounds(tmp_path):
    from PyQt6.QtCore import QPoint, QPointF, Qt
    from PyQt6.QtGui import QKeySequence, QShortcut, QWheelEvent

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "a.md"
    page.write_text("# Zoom\n\nText.\n", encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    viewer.show()
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 30)
    browser = viewer.view.browser
    wheel = QWheelEvent(QPointF(10, 10), QPointF(10, 10), QPoint(0, 0), QPoint(0, 120), Qt.MouseButton.NoButton,
                        Qt.KeyboardModifier.ControlModifier, Qt.ScrollPhase.NoScrollPhase, False)
    browser.wheelEvent(wheel)
    assert viewer.view.zoom == 1 and viewer.zoom_reset.text() != "100%"
    bound = {s.key() for s in viewer.findChildren(QShortcut)}
    assert QKeySequence("Ctrl+=") in bound or QKeySequence("Ctrl+=") in QKeySequence.keyBindings(
        QKeySequence.StandardKey.ZoomIn)
    for _ in range(60):
        viewer.view.zoom_by(-1)
    assert viewer.view.zoom_percent() >= 25
    for _ in range(200):
        viewer.view.zoom_by(1)
    assert viewer.view.zoom_percent() <= 400


# -- L3. the image boxes follow a theme chosen later ---------------------------------------------------

def test_sad_an_image_box_is_painted_again_in_a_new_theme(tmp_path):
    from PyQt6.QtGui import QColor, QPalette

    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), str(tmp_path / "a.md")))
    view.resize(900, 600)
    view.show()
    view.render("![local](missing.png) ![remote](https://img.example/x.png)\n")
    assert until(lambda: "missing.png" in view.images and not view.images["missing.png"].isNull()
                 and view._readable, 30)
    pump(1.0)
    light = view.images["missing.png"].pixelColor(2, 6).lightness()
    palette = QPalette(APP.palette())
    for role in (QPalette.ColorRole.Base, QPalette.ColorRole.Window):
        palette.setColor(role, QColor("#111111"))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText):
        palette.setColor(role, QColor("#eeeeee"))
    view.setPalette(palette)
    pump(1.0)
    assert light > 150 and view.images["missing.png"].pixelColor(2, 6).lightness() < 80


# -- L5. a file that cannot be read: the reason in the page ---------------------------------------------

def test_sad_a_missing_file_says_why_in_the_page(tmp_path):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "gone.md"))
    viewer.show()
    assert until(lambda: "gone.md" in viewer.view.browser.toPlainText(), 30)
    assert "cannot be read" in viewer.view.browser.toPlainText()


# -- L7. long texts of one kind: the first part soon -----------------------------------------------------

@pytest.mark.parametrize("name, text", [
    ("20,000 small tables", "".join(f"| a | b |\n|---|---|\n| {n} | x |\n\n" for n in range(20000))),
    ("150,000 lines of code spans", "".join(f"`a{n}` `b` `c`\n" for n in range(150000))),
    ("a line of 700 KB", "[a][b] " * 100000 + "\n"),
])
def test_sad_a_long_text_of_one_kind_shows_its_first_part_soon(name, text):
    """20,000 small tables, 150,000 lines of short code spans, a line of unresolved references were one
    part each: 3 to 7 s here (12 to 59 s on the reviewer's machine) before the first of it showed."""
    from core import markdown_term as T

    parts = T.text_parts(text)
    assert len(parts) > 3 and len(parts[0]) <= 2 * T.STREAM_PART_CHARS, (name, len(parts), len(parts[0]))
    assert "\n".join(parts).split() == text.split()  # (every word, in order)


# -- the release (v0.16.4): axross-mdcat.exe on a console or pipe of cp1252 -----------------------------

def test_sad_mdcat_writes_any_character_whatever_the_outputs_encoding(tmp_path):
    """Windows' axross-mdcat.exe ended in UnicodeEncodeError ('charmap' codec, "█"): its output into a pipe
    was the ANSI code page. A pipe or a file gets UTF-8; a console that cannot show a character gets it
    replaced - never an error."""
    import subprocess

    from PyQt6.QtGui import QColor, QImage

    from core import markdown_cli

    picture = QImage(20, 10, QImage.Format.Format_RGB32)
    picture.fill(QColor("#3b5bdb"))
    picture.save(str(tmp_path / "p.png"), "PNG")
    page = tmp_path / "a.md"
    page.write_text("# Title █\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n![p](p.png)\n", encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", markdown_cli.__name__, "--no-pager", "--color", "truecolor",
                             "--images", "blocks", str(page)], cwd=ROOT, capture_output=True, timeout=120,
                            env={**os.environ, "PYTHONIOENCODING": "cp1252"})
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    shown = result.stdout.decode("utf-8")
    assert "Title █" in shown and "┌" in shown and ("▀" in shown or "▄" in shown)



# -- the release (v0.16.4): emoji and images on a CI runner's fonts -----------------------------------

def test_sad_a_paragraph_of_emoji_is_laid_out_in_smaller_pieces():
    """50,000 colour emoji in a paragraph held a CI runner's window 2.6 s (markdown-it) and 1.4 s (Qt's own
    parser): 3,000 of them a piece. An emoji (a sign past U+1F000) counts as PICTURE_WEIGHT letters."""
    from core import markdown_doc as MD
    from ui import markdown_html as H
    from ui import markdown_view as MV

    text = "🎉 " * 20_000
    pieces = H._paragraph_pieces(MD.parse(text).tokens)
    sizes = [sum(len(c.content) for c in t.children) for t in pieces if t.type == "inline"]
    weight = H.picture_weight()
    assert len(sizes) > 1 and max(sizes) * weight <= 3 * H.PARAGRAPH_TEXT + 2 * H.piece_floor(weight), max(sizes)
    md4c = [piece for piece in MV._pieces_of(text).split("\n\n" + MV.JOINED)]
    assert len(md4c) > 1 and max(map(len, md4c)) * weight <= 3 * MV.PARAGRAPH_CHARS + 2 * H.piece_floor(weight)
    plain = "word " * 20_000  # (letters: as many as before)
    assert max(sum(len(c.content) for c in t.children) for t in H._paragraph_pieces(MD.parse(plain).tokens)
               if t.type == "inline") >= H.PARAGRAPH_TEXT


def test_sad_the_page_font_names_the_emoji_font_after_its_own(monkeypatch):
    """Qt looked for each emoji's font among all of the system's (hundreds of families on a CI runner);
    the family emoji_fonts found draws them now, second in the page's font."""
    from PyQt6.QtGui import QFont

    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "_EMOJI_FAMILY", ["Some Emoji"])
    font = MV.with_emoji_family(QFont("DejaVu Sans"))
    assert font.families()[-1] == "Some Emoji" and font.families()[0] == "DejaVu Sans"
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [""])
    assert MV.with_emoji_family(QFont("DejaVu Sans")).families() in ([], ["DejaVu Sans"])


def test_sad_clamping_images_looks_at_a_bounded_number_a_turn():
    """20,000 image chips with Qt's own parser: clamp_images found all 14,000 laid out in one turn (0.21 s
    here, 0.32 s on a CI runner). One call looks at CLAMPED_AT_ONCE, the next turns at the rest."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.resize(1000, 800)
    view.show()
    view.render(" ".join(f"![i{n}](img{n}.png)" for n in range(6000)) + "\n")
    assert until(lambda: view._readable and view.markdown, 120)
    view.load_rest_now()
    until(lambda: not view.more(), 120)
    pump(0.5)
    document = view.browser.document()
    assert document.toPlainText().count("\ufffc") > MV.CLAMPED_AT_ONCE
    view._clamped_room = None
    view.clamp_images()
    assert view._unclamped < document.characterCount() - 1  # (stopped: the rest in the next turn)
    assert until(lambda: view._unclamped >= document.characterCount() - 1, 30)


_EMOJI_TURNS = r"""import os, sys, time
sys.path.insert(0, sys.argv[1])
os.environ["QT_QPA_PLATFORM"] = "offscreen"
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from tests.test_markdown_reader_bugs11 import pump, until
from tests.test_markdown_reader_bugs16 import Turns
from ui import markdown_html as H
from ui import markdown_view as MV
for full in (True, False):
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    turns = Turns()
    view.render("\U0001F389 " * 50_000 + "\n")
    assert until(lambda: view._readable and view.markdown, 120)
    laid = lambda: not view._scheduled and not view.status.text().startswith("Rendering")
    until(laid, 60)
    pump(0.3)
    view.go_end()
    pump(0.5)
    until(laid, 60)
    print("parser", full, "weight", H.picture_weight(), "worst", turns.worst(), "family", MV._EMOJI_FAMILY[0])
    view.close()
"""


#: Where a colour emoji font may be (the test of the many fonts adds one; AXROSS_EMOJI_FONT names one).
_COLOUR_EMOJI_FONTS = ("/usr/share/fonts/**/*olor*moji*.ttf", "/usr/local/share/fonts/**/*olor*moji*.ttf",
                       os.path.expanduser("~/.local/share/fonts/**/*olor*moji*.ttf"))


def _fonts_conf(tmp_path, fonts: str) -> str | None:
    """A fontconfig file of the fonts *fonts* names: "dejavu" (DejaVu alone), "system" (the machine's own,
    all of them), "system+emoji" (those and a colour emoji font) - None: not on this machine."""
    import glob

    if fonts == "system":
        return os.environ.get("FONTCONFIG_FILE", "")
    if fonts == "dejavu":
        found = sorted(glob.glob("/usr/share/fonts/**/DejaVuSans.ttf", recursive=True))
        dirs, include = [os.path.dirname(f) for f in found[:1]], ""
    else:
        found = [os.environ["AXROSS_EMOJI_FONT"]] if os.environ.get("AXROSS_EMOJI_FONT") else \
            sorted(f for pattern in _COLOUR_EMOJI_FONTS for f in glob.glob(pattern, recursive=True))
        base = os.environ.get("FONTCONFIG_FILE") or "/etc/fonts/fonts.conf"
        dirs, include = [os.path.dirname(f) for f in found[:1]], f'  <include ignore_missing="yes">{base}</include>\n'
    if not dirs:
        return None
    conf = tmp_path / f"{fonts}.conf"
    conf.write_text('<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "fonts.dtd">\n<fontconfig>\n' + include
                    + "".join(f"  <dir>{d}</dir>\n" for d in dirs)
                    + f"  <cachedir>{tmp_path / ('cache-' + fonts)}</cachedir>\n</fontconfig>\n", encoding="utf-8")
    return str(conf)


@pytest.mark.parametrize("fonts", ["dejavu", "system", "system+emoji"])
def test_sad_a_paragraph_of_emoji_holds_no_turn_whatever_the_fonts(tmp_path, fonts):
    """v0.16.5's and v0.16.6's CI: 50,000 emoji in a paragraph held the runner's window 0.42 s a turn
    (markdown-it) and 0.68 s (Qt's own parser) - with its colour emoji font among hundreds of others, an
    emoji cost ten times what it costs here. An emoji weighs PICTURE_WEIGHT (128) letters in a paragraph's
    pieces, whatever the fonts: with DejaVu alone, the machine's own fonts, and those with a colour emoji
    font, the window's own CPU in a turn stays under 0.1 s, both parsers."""
    import subprocess

    from ui import markdown_html as H

    conf = _fonts_conf(tmp_path, fonts)
    if conf is None:
        pytest.skip(f"no fonts for {fonts!r} here")
    script = tmp_path / "emoji_turns.py"
    script.write_text(_EMOJI_TURNS, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "FONTCONFIG_FILE"}
    if conf:
        env["FONTCONFIG_FILE"] = conf
    result = subprocess.run([sys.executable, str(script), str(ROOT)], capture_output=True, text=True, timeout=400,
                            env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr[-3000:]
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith("parser")]
    assert len(rows) == 2, result.stdout
    for row in rows:
        assert int(row[3]) == H.PICTURE_WEIGHT == 128 and float(row[5]) < 0.1, (fonts, row)
