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
    assert len(sizes) > 1 and max(sizes) * H.PICTURE_WEIGHT <= 3 * H.PARAGRAPH_TEXT, max(sizes)
    md4c = [piece for piece in MV._pieces_of(text).split("\n\n" + MV.JOINED)]
    assert len(md4c) > 1 and max(map(len, md4c)) * H.PICTURE_WEIGHT <= 3 * MV.PARAGRAPH_CHARS
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
