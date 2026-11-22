"""The full Markdown set (core.markdown_doc, markdown-it-py) in the Qt viewer
(ui.markdown_html, ui.markdown_view) and in the terminal (core.markdown_term,
core.markdown_cli / axross-mdcat).

Asked for: "einen perfekten Markdown Reader" - a Qt and a CLI variant, with
colours, the complete Markdown set, images and links. A file is untrusted:
raw HTML only as an allowed subset (tests/test_markdown_raw_html.py), no
escape sequence of its own reaches a terminal, links into
OSC 8 only when safe, images only beside the file and never from the network.
"""

from __future__ import annotations

import io
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("markdown_it", reason="markdown-it-py not installed")
pytest.importorskip("mdit_py_plugins", reason="mdit-py-plugins not installed")

from core import markdown_doc as MD  # noqa: E402
from core import markdown_term as T  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

FULL = """---
title: Demo
---
# Head *one*

Text **bold** *it* ~~gone~~ `code` [web](https://example.org) <https://auto.example>
[bad](javascript:alert(1)) <b>raw</b> note[^a].

## Head *one*

| L | C | R |
|:--|:-:|--:|
| 1 | 2 | 3 |

- [x] done
- [ ] open

1. one
2. two
   - inner

> quote
> > deeper

Term
: Meaning

```python
def f():  # c
    return 1
```

---

![pic](pic.png) ![far](https://example.org/x.png)

[^a]: The note.
"""

ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def plain(text: str) -> str:
    return ANSI.sub("", text)


@pytest.fixture
def folder(tmp_path):
    from PIL import Image

    Image.new("RGB", (40, 20), (255, 0, 0)).save(tmp_path / "pic.png")
    (tmp_path / "doc.md").write_text(FULL)
    return tmp_path


# -- the parser ---------------------------------------------------------------------------------

def test_happy_the_parser_finds_headings_with_unique_anchors_front_matter_and_notes():
    doc = MD.parse(FULL)
    assert [(h.level, h.text, h.anchor) for h in doc.headings] == [
        (1, "Head one", "head-one"), (2, "Head one", "head-one-1")]
    assert doc.front_matter.strip() == "title: Demo"
    assert doc.notes == ["a"]


def test_sad_raw_html_is_its_allowed_subset_and_a_javascript_link_is_no_link():
    from ui.markdown_html import to_html

    page = to_html(MD.parse(FULL))
    assert "<b>raw</b>" in page  # (an allowed tag: tests/test_markdown_raw_html.py)
    assert "javascript:" not in page.replace("[bad](javascript:alert(1))", "")
    assert 'href="javascript' not in page


def test_happy_the_qt_page_has_anchors_alignment_tasks_colours_and_front_matter():
    from ui.markdown_html import anchor_names, style_sheet, to_html

    page = to_html(MD.parse(FULL), dark=False)
    assert {"head-one", "head-one-1", "fn1", "fnref1"} <= anchor_names(page)
    assert '<th align="left">' in page and '<th align="center">' in page and '<th align="right">' in page
    assert 'border="1"' in page and 'class="data"' in page  # (a data table: its rows' padding - bugs9)
    assert "☑" in page and "☐" in page and 'class="task-list"' in page and 'list-style-type: none' not in page
    # (a box labelled with its language, as Qt's own parser's - test_markdown_reader_bugs6)
    # (plain "key: value" front matter: a table, as GitHub shows it - eighth review; it was a YAML box)
    assert "<th" in page and ">title</th>" in page and ">Demo</td>" in page
    assert "<dl>" in page and "<dt>" in page
    assert re.search(r'<span style="[^"]*color: #', page)  # Pygments' colours, inline
    assert "#0969da" in style_sheet(False) and "#4493f8" in style_sheet(True)


def test_edge_a_mixed_list_keeps_its_bullets():
    from ui.markdown_html import to_html

    page = to_html(MD.parse("- [x] task\n\n- plain\n"))
    assert "list-style-type: none" not in page


def test_edge_clean_drops_escape_and_bidi_controls():
    assert MD.clean("a\x1b[31mb\x07c\u202ed\te\nf") == "a[31mbcd\te\nf"
    assert MD.cell_width("漢字a") == 5 and MD.cell_width("é") == 1


# -- the Qt view --------------------------------------------------------------------------------

_APP: list = []  # the application lives as long as the module: one dropped took every widget with it


def _app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    return _APP[0]


def _wait(app, predicate, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_happy_the_view_renders_the_full_set_and_footnote_links_scroll(folder):
    app = _app()
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), str(folder / "doc.md")))
    view.resize(700, 500)
    view.show()
    assert view.full
    view.render(FULL)
    assert _wait(app, lambda: view._readable)  # (a text with code: made on a worker)
    assert view.headings() == ["Head one", "Head one"]
    assert {"head-one", "head-one-1"} <= set(view.anchors) and "fn1" in view.names
    text = view.browser.toPlainText()
    assert " raw note" in text and "Meaning" in text
    # (a task's glyph, ☑, its bullet - Qt's box of a task done was a cross: test_markdown_reader_bugs12)
    from PyQt6.QtGui import QTextBlockFormat

    done = view.browser.document().find("done").block()
    assert done.text().startswith("☑ done") and done.blockFormat().marker() == QTextBlockFormat.MarkerType.NoMarker
    reached = []
    view.link.connect(reached.append)
    from PyQt6.QtCore import QUrl

    view.clicked(QUrl("#fn1"))  # the footnote: scrolled to, not handed to the window
    assert reached == []
    assert _wait(app, lambda: view.images.get("pic.png") is not None
                 and view.images["pic.png"].width() == 40)
    view.close()


def test_happy_a_long_text_is_parsed_off_the_gui_thread(monkeypatch):
    app = _app()
    from ui import markdown_view as MV

    threads = []
    real = MV._page

    def page(text, dark, *more, **named):  # (named: a long text's notes - test_markdown_reader_bugs12)
        threads.append(threading.current_thread())
        return real(text, dark, *more, **named)

    monkeypatch.setattr(MV, "BACKGROUND_CHARS", 10)
    monkeypatch.setattr(MV, "_page", page)
    view = MV.MarkdownView(None)
    view.render("# Long\n\n" + "word " * 50)
    assert view.status.text() == "Rendering…"
    assert _wait(app, lambda: view.headings() == ["Long"])
    assert threads and threads[0] is not threading.main_thread()
    assert view.status.text() == ""


def test_edge_without_markdown_it_the_view_falls_back_to_qts_parser():
    _app()
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.render("# A\n\n| x |\n|---|\n| 1 |\n\n<b>raw</b>\n")
    # (raw HTML as the Markdown of its allowed subset: ui.markdown_view.fallback_text)
    assert view.headings() == ["A"] and "raw" in view.browser.toPlainText() and "<b>" not in view.browser.toPlainText()


def test_sad_control_characters_never_reach_the_page():
    _app()
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.render("# T\n\nEvil \x1b]0;x\x07 end\n")
    assert "\x1b" not in view.browser.toPlainText() and "\x07" not in view.browser.toPlainText()


# -- the terminal -------------------------------------------------------------------------------

def _term(text=FULL, **options):
    base = {"width": 70, "depth": "truecolor", "images": "none", "folder": ""}
    base.update(options)
    return T.render(text, T.Options(**base))


def test_happy_the_terminal_shows_the_full_set():
    out = plain(_term())
    assert "█ Head one" in out and "▌ Head one" in out
    assert "━━━" in out and "───" in out
    assert "☑ done" in out and "☐ open" in out and "☑ ☑" not in out
    assert "1. one" in out and "   ◦ inner" in out  # (one level deeper: the second bullet)
    assert "│ quote" in out and "│ │ deeper" in out
    assert "Term" in out and "⁝ Meaning" in out
    assert "┌" in out and "╞" in out and "└" in out
    assert "‹https://example.org›" in out
    assert "note[1]" in out and "[1] The note." in out  # (numbered as GitHub numbers them)
    assert "front matter" in out and "title: Demo" in out
    assert " raw note" in out and "<b>" not in out


def test_happy_tables_are_aligned_and_fit_the_width():
    text = "| Left | Mid | Right |\n|:--|:-:|--:|\n| a | b | c |\n| " + "long " * 30 + "| x | 9 |\n"
    out = plain(_term(text, width=50, depth="none"))
    lines = [line for line in out.splitlines() if line.startswith("│")]
    assert all(MD.cell_width(line) <= 50 for line in out.splitlines())
    row = next(line for line in lines if " a " in line)
    cells = row.split("│")[1:-1]
    assert cells[0].startswith(" a") and cells[2].rstrip().endswith("c") and cells[2].endswith("c ")
    assert cells[1].strip() == "b" and abs(cells[1].index("b") - (len(cells[1]) - 1) / 2) <= 1


def test_happy_lines_wrap_to_the_width_and_wide_characters_count_twice():
    out = plain(_term("漢字 " * 40 + "\n\n" + "word " * 60, width=30, depth="none"))
    assert all(MD.cell_width(line) <= 30 for line in out.splitlines())


def test_sad_nothing_in_a_file_sends_the_terminal_an_escape_of_its_own():
    evil = ("# T\x1b]0;title\x07\n\ntext \x1b[2J \x9b31m `\x1b[5m` [x](https://e.org/\x1b]8;;evil\x1b\\)\n\n"
            "```sh\necho \x1b[31mred\n```\n")
    out = _term(evil)
    allowed = ANSI.sub("", out)
    assert "\x1b" not in allowed and "\x07" not in allowed and "\x9b" not in allowed


def test_sad_osc8_carries_only_safe_addresses(folder):
    out = _term("[a](https://ok.example) [b](mailto:x@example.org) [c](other.md) [d](javascript:x)"
                " [e](ftp://x.example)", folder=str(folder))
    urls = re.findall(r"\x1b\]8;;([^\x1b]+)\x1b\\", out)
    assert "https://ok.example" in urls and "mailto:x@example.org" in urls
    assert ("file://" + str(folder / "other.md")) in urls
    assert not any(u.startswith(("javascript", "ftp")) for u in urls)
    assert not T.safe_url("https://x\x1b") and not T.safe_url("javascript:x") and not T.safe_url("")


def test_happy_colours_follow_the_depth():
    assert "\x1b" not in _term("**b** `c`", depth="none")
    assert "38;2;" in _term("# h", depth="truecolor")
    assert "38;5;" in _term("# h", depth="256") and "38;2;" not in _term("# h", depth="256")
    assert re.search(r"\x1b\[[0-9;]*9[0-9]m|\x1b\[[0-9;]*3[0-9]m", _term("# h", depth="16"))


def test_happy_capabilities_from_the_environment():
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert T.colour_depth(Tty(), {"NO_COLOR": "1", "COLORTERM": "truecolor"}) == "none"
    assert T.colour_depth(io.StringIO(), {"COLORTERM": "truecolor"}) == "none"  # not a terminal
    assert T.colour_depth(io.StringIO(), {"FORCE_COLOR": "1", "COLORTERM": "truecolor"}) == "truecolor"
    assert T.colour_depth(Tty(), {"TERM": "xterm-256color"}) == "256"
    assert T.colour_depth(Tty(), {"TERM": "dumb"}) == "none"
    assert T.image_protocol({"KITTY_WINDOW_ID": "1"}) == "kitty"
    assert T.image_protocol({"TERM_PROGRAM": "iTerm.app"}) == "iterm"
    assert T.image_protocol({"TERM": "xterm"}) == "blocks"
    assert T.dark_background({"COLORFGBG": "0;15"}) is False and T.dark_background({}) is True


def test_happy_images_are_drawn_beside_the_file_only(folder):
    blocks = _term("![p](pic.png)", folder=str(folder), images="blocks", image_columns=10, image_rows=4)
    assert blocks.count("▀") >= 10
    kitty = _term("![p](pic.png)", folder=str(folder), images="kitty", image_columns=10, image_rows=4)
    assert "\x1b_Ga=T,f=100" in kitty
    iterm = _term("![p](pic.png)", folder=str(folder), images="iterm", image_columns=10, image_rows=4)
    assert "\x1b]1337;File=inline=1" in iterm
    for src, why in (("https://example.org/x.png", "remote, not loaded"), ("/etc/passwd", "not beside the file"),
                     ("file:///etc/passwd", "not beside the file")):
        assert T.locate(src, str(folder)) == ("", why)


def test_sad_secret_fifo_and_huge_images_are_not_read(folder, monkeypatch):
    from core import protected_places

    os.mkfifo(folder / "pipe.png")
    assert T.read_picture(str(folder / "pipe.png")) == "not a file"
    (folder / "big.png").write_bytes(b"\x89PNG" + b"\0" * (T.IMAGE_LIMIT + 1))
    assert T.read_picture(str(folder / "big.png")) == "too big"
    (folder / "x.svg").write_text("<svg/>")
    assert "SVG" in T.read_picture(str(folder / "x.svg"))
    monkeypatch.setattr(protected_places, "read_refusal", lambda path, **kw: "secret")
    assert T.read_picture(str(folder / "pic.png")) == "a secret file"


# -- the command --------------------------------------------------------------------------------

def test_happy_mdcat_shows_files_toc_and_stdin(folder, capsys, monkeypatch):
    from core import markdown_cli as C

    assert C.main(["--no-pager", "--color", "never", str(folder / "doc.md")]) == 0
    out = capsys.readouterr().out
    assert "█ Head *one*" in out and "\x1b" not in out  # (no colour: emphasis is marked)
    assert C.main(["--toc", "--color", "never", str(folder / "doc.md")]) == 0
    toc = capsys.readouterr().out.splitlines()
    assert toc == ["Head one  #head-one", "  Head one  #head-one-1"]
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"# From stdin\n")))
    assert C.main(["--color", "never", "-"]) == 0
    assert "From stdin" in capsys.readouterr().out


def test_sad_mdcat_says_why_a_file_is_not_shown(folder, capsys, monkeypatch):
    from core import markdown_cli as C
    from core import protected_places

    os.mkfifo(folder / "pipe.md")
    assert C.main(["--color", "never", str(folder / "missing.md"), str(folder / "pipe.md")]) == 1
    err = capsys.readouterr().err
    assert "missing.md" in err and "not a regular file" in err
    # The document the user named is shown as the viewer shows it: the
    # agent's read policy (which sniffs contents) decides nothing about it.
    monkeypatch.setattr(protected_places, "read_refusal", lambda path, **kw: "secret")
    assert C.main(["--color", "never", "--images", "none", str(folder / "doc.md")]) == 0
    assert "secret" not in capsys.readouterr().err


def test_edge_mdcat_imports_no_qt():
    import subprocess

    code = ("import sys; sys.argv=['x','--toc','--color','never','-']; import core.markdown_cli as C; "
            "C.main(['--toc','--color','never',%r]); "
            "print('QT' if any(m.startswith('PyQt6') for m in sys.modules) else 'NOQT')"
            % str(Path(__file__).resolve().parents[1] / "README.md"))
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                            cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 0, result.stderr[-1000:]
    assert result.stdout.strip().endswith("NOQT")


def test_happy_markdown_app_term_hands_over_to_mdcat(folder, capsys):
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import markdown_app as A

    assert A.main(["axross-markdown", "--term", "--toc", "--color", "never", str(folder / "doc.md")]) == 0
    assert "Head one  #head-one" in capsys.readouterr().out


# -- found by the verification of the reader (real documents, a terminal emulator, hostile files) --

def _lines_fit(out: str, width: int) -> bool:
    return all(MD.cell_width(line) <= width for line in plain(out).splitlines())


def test_sad_a_code_blocks_info_string_sends_the_terminal_no_escape():
    # The language after ``` is the file's too: it went to the terminal as written.
    evil = "```py\x1b]0;pwned\x07\x1b[31m\x9b31m more\nx = 1\n```\n"
    for depth in ("none", "truecolor"):
        rest = ANSI.sub("", _term(evil, depth=depth))
        assert "\x1b" not in rest and "\x07" not in rest and "\x9b" not in rest


def test_edge_tabs_in_code_and_text_stay_within_the_width():
    text = "```go\nfunc a() {\n\tif x {\n\t\treturn 1234567890123456789012345\n\t}\n}\n```\n\na\tb\tc\n"
    for depth in ("none", "truecolor"):
        out = plain(_term(text, width=40, depth=depth))
        assert "\t" not in out
        assert _lines_fit(out, 40)
    assert "▏         if x {" in plain(_term(text, width=40, depth="none"))  # (8 columns, as GitHub)


def test_edge_a_tables_narrow_columns_keep_its_borders_in_line():
    # Columns made narrower than 8 were filled 8 wide: the borders went askew.
    text = ("| a | b | c | d | e |\n|---|---|---|---|---|\n| supercalifragilistic | another-long-word | x | "
            "yet-another-long-one | z |\n")
    out = plain(_term(text, width=40, depth="none"))
    rows = [line for line in out.splitlines() if line]
    assert len({MD.cell_width(line) for line in rows}) == 1 and _lines_fit(out, 40)
    bars = {tuple(i for i, ch in enumerate(line) if ch in "│┼┬┴╪") for line in rows[1:-1] if "═" not in line}
    assert len(bars) == 1


def test_edge_a_table_too_wide_for_the_terminal_is_shown_a_row_after_the_other():
    head = "|" + "|".join(f"col{i}" for i in range(20)) + "|\n|" + "---|" * 20 + "\n"
    out = plain(_term(head + "|" + "|".join(f"v{i}" for i in range(20)) + "|\n", width=40, depth="none"))
    assert _lines_fit(out, 40) and "col0: v0" in out and "col19: v19" in out and "┌" not in out
    long = plain(_term(head + "|" + "|".join("many words in this cell " * 3 for i in range(20)) + "|\n",
                       width=40, depth="none"))
    assert _lines_fit(long, 40) and "\n  words in this cell" in long  # (a cell's next lines indented)
    only_heads = plain(_term(head, width=40, depth="none"))
    assert "col0" in only_heads and "col0: col0" not in only_heads


def test_edge_the_columns_of_a_huge_table_are_fitted_in_time():
    assert T.fit_columns([30, 5, 50, 2], 40) == [17, 5, 16, 2]
    assert T.fit_columns([3, 3], 10) == [3, 3] and T.fit_columns([10] * 10, 30) is None
    started = time.monotonic()
    widths = T.fit_columns([100_000] * 30, 4000)
    assert sum(widths) == 4000
    TB.budget(time.monotonic() - started < 1, 'time.monotonic() - started < 1')  # (a column a step: minutes)


def test_edge_a_word_of_a_megabyte_is_cut_in_linear_time():
    started = time.monotonic()
    out = _term("x" * (1 << 20), width=80, depth="none")
    TB.budget(time.monotonic() - started < 20, 'time.monotonic() - started < 20')  # (each cut went over all of the rest: over 3 minutes)
    assert out.count("\n") == (1 << 20) // 80 + 1 and _lines_fit(out, 80)
    assert T.wrap([T.Span("漢字漢字")], 3) == [[T.Span("漢")], [T.Span("字")], [T.Span("漢")], [T.Span("字")]]


def test_edge_headings_in_quotes_and_long_front_matter_fit_the_width():
    out = _term("> # A very long heading inside a block quote that wraps\n", width=40, depth="none")
    assert _lines_fit(out, 40) and "━━━" in out
    value = "word " * 40
    out = plain(_term(f"---\ndescription: {value}\n  nested: x\n---\n\ntext\n", width=40, depth="none"))
    assert _lines_fit(out, 40)
    assert "".join(line for line in out.splitlines()[1:-3]).startswith(f"description: {value}".rstrip()[:30])
    assert "  nested: x" in out  # (the indentation of YAML kept)


def test_happy_toml_front_matter_is_front_matter():
    doc = MD.parse('+++\ntitle = "Demo"\n[params]\nx = 1\n+++\n# Head\n')
    assert doc.front_matter == 'title = "Demo"\n[params]\nx = 1'
    assert [h.text for h in doc.headings] == ["Head"]
    out = plain(_term('+++\ntitle = "Demo"\n+++\n\ntext\n', depth="none"))
    assert "front matter" in out and 'title = "Demo"' in out and "+++" not in out
    for text in ("+++\nnot closed\n", "text\n+++\na = 1\n+++\n"):  # (not front matter: text)
        assert MD.parse(text).front_matter == ""


def test_sad_images_are_bounded_in_number_and_pixels_together(folder, monkeypatch):
    from PIL import Image

    calls = []
    real = T.read_picture
    monkeypatch.setattr(T, "read_picture", lambda path, pixels=T.IMAGE_PIXELS, folder="": calls.append(path)
                        or real(path, pixels, folder))
    out = _term("![p](pic.png)\n\n" * 50, folder=str(folder), images="blocks", image_columns=10, image_rows=4)
    assert len(calls) == 1  # (decoded once however often it is named)
    monkeypatch.setattr(T, "IMAGES", 5)
    out = plain(_term("![p](pic.png)\n\n" * 50, folder=str(folder), images="blocks", image_columns=10,
                      image_rows=4))
    assert out.count("▀" * 10) == 5 * 2 and out.count("more than 5 images") == 1
    Image.new("RGB", (100, 100)).save(folder / "big.png")
    Image.new("RGB", (100, 100)).save(folder / "big2.png")
    monkeypatch.setattr(T, "IMAGES_PIXELS", 15_000)  # (the first takes 10,000: the other does not fit)
    out = plain(_term("![a](big.png)\n\n![b](pic.png)\n\n![c](big2.png)", folder=str(folder),
                      images="blocks", image_columns=10, image_rows=4))
    assert "(big2.png: too big)" in out and out.count("▀" * 8) == 4 + 2
    assert T.read_picture(str(folder / "big.png"), 9_999) == "too big"


def test_edge_a_picture_goes_to_the_terminal_at_the_size_it_is_shown(folder):
    import base64

    from PIL import Image

    Image.linear_gradient("L").resize((3000, 2000)).convert("RGB").save(folder / "photo.png")
    out = _term("![p](photo.png)", folder=str(folder), images="kitty", image_columns=20, image_rows=10)
    data = "".join(re.findall(r"\x1b_G[^;]*;([A-Za-z0-9+/=]*)\x1b\\", out))
    picture = Image.open(io.BytesIO(base64.b64decode(data)))
    assert picture.width <= 20 * T.CELL_PIXELS[0] and picture.height <= 10 * T.CELL_PIXELS[1]


def test_happy_footnotes_are_numbered_as_github_numbers_them():
    from ui.markdown_html import to_html

    text = "Inline^[an inline note] and ref[^long-label] and again[^long-label].\n\n[^long-label]: Labelled.\n"
    out = plain(_term(text, depth="none"))
    assert "Inline[1] and ref[2] and again[2]." in out  # (were "[0]" and "[long-label]")
    assert "[1] an inline note" in out and "[2] Labelled." in out and "None" not in out
    page = to_html(MD.parse(text))
    assert "[2:1]" not in page and page.count(">[2]<") == 2


def test_edge_named_anchors_on_a_page_are_bounded_and_headings_still_found():
    app = _app()
    from PyQt6.QtCore import QUrl

    from ui import markdown_html as H
    from ui import markdown_view as MV

    text = "".join(f"# h{i}\n\n" for i in range(H.ANCHORS + 500))
    page = H.to_html(MD.parse(text))
    assert len(H.anchor_names(page)) == H.ANCHORS and ' id="' not in page
    view = MV.MarkdownView(None)
    view.resize(600, 400)
    view.show()
    view.render(text)
    # (a big page: laid out in parts - the heading clicked perhaps in one not laid out yet)
    assert _wait(app, lambda: not view.status.text().startswith(MV.tr("Rendering…")))
    bar = view.browser.verticalScrollBar()
    view.clicked(QUrl(f"#h{H.ANCHORS + 499}"))  # (past the named anchors: found by its place)
    assert _wait(app, lambda: bar.value() > 0, timeout=15) and "No heading" not in view.status.text()
    heading = view.browser.document().find(f"h{H.ANCHORS + 499}")
    assert view.browser.viewport().rect().contains(view.browser.cursorRect(heading).center())
    view.close()


def test_edge_footnote_definitions_count_as_list_items_for_qt():
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import markdown_view as MV

    notes = "".join(f"[^{i}]: note {i}\n" for i in range(MV.LIST_ITEMS + 10))
    part, why = MV.renderable("text[^1]\n\n" + notes)
    laid_out, as_written = part.split("```text", 1)
    assert why and laid_out.count("\n[^") == MV.LIST_ITEMS and as_written.count("\n[^") == 10


def test_sad_mdcat_refuses_a_negative_width_and_keeps_a_minimum(folder, capsys):
    from core import markdown_cli as C

    with pytest.raises(SystemExit) as exit_:
        C.main(["--width", "-5", str(folder / "doc.md")])
    assert exit_.value.code == 2 and "not a number of columns" in capsys.readouterr().err
    assert C.main(["--no-pager", "--color", "never", "--width", "3", str(folder / "doc.md")]) == 0
    out = capsys.readouterr().out
    assert "█ Head *one*" in out and _lines_fit(out, C.MIN_WIDTH)


def test_edge_a_file_with_old_mac_line_ends_is_not_one_line():
    _app()
    from ui import markdown_view as MV

    for end in ("\r\n", "\r"):
        text = end.join(["# One", "", "para", "", "## Two", "", "- a", "- b", ""])
        for full in (True, False):
            view = MV.MarkdownView(None)
            view.full = full
            view.render(text)
            assert view.headings() == ["One", "Two"], (repr(end), full)
        assert plain(_term(text, depth="none")).count("•") == 2


DEEP = ("# Top\n\n" + "> " * 40 + "deep quote\n\n- a\n"
        + "".join("  " * i + f"- level {i}\n" for i in range(1, 40))
        + "lazy line\n\n# After\n\nlast words\n")


def test_edge_what_is_nested_too_deeply_is_shown_as_written_not_dropped():
    # markdown-it skips what lies past its nesting limit - the rest of that
    # list or quote, and with it later headings - without a word
    assert [h.text for h in MD.parse(DEEP).headings] == ["Top", "After"]
    out = plain(_term(DEEP, depth="none", width=200))
    for words in ("deep quote", "level 39", "lazy line", "last words"):
        assert words in out, words
    assert "█ After" in out
    from ui import markdown_html as H

    html = H.to_html(MD.parse(DEEP))
    for words in ("deep quote", "level 39", "lazy line", "last words"):
        assert words in html, words


def test_edge_a_long_code_line_wraps_in_the_terminal_and_loses_nothing():
    line = " ".join(f"w{i:02}" for i in range(40))
    out = plain(_term("```\n" + line + "\n```\n", depth="none", width=30))
    rows = [r for r in out.splitlines() if r.startswith("▏")]
    assert len(rows) > 1 and all(r.endswith("↩") for r in rows[:-1])
    assert "".join(r[2:].rstrip("↩") for r in rows) == line
    assert all(len(r) <= 30 for r in out.splitlines())


def test_edge_autolinks_are_links_in_qts_own_parser_too():
    # (without markdown-it, Qt's md4c parses: every "<" is escaped first, so
    # no raw HTML - and autolinks came out as text with "<" and ">")
    from ui.markdown_safe import _autolinks, _escape_html

    assert _autolinks("see <https://a.example/x_y*z(1)> or <me@example.org>") == (
        r"see [https\:\/\/a\.example\/x\_y\*z\(1\)](https://a.example/x_y*z%281%29)"
        r" or [me\@example\.org](mailto:me@example.org)")
    kept = ["`<https://code.example>`", "``a ` <https://code.example> ``",
            r"\<https://escaped.example>", "    <https://indented.example>",
            "```\n<https://fence.example>\n```", "> ```\n> <https://quoted.example>\n> ```",
            "- ```\n  <https://listed.example>\n  ```", "<javascript:alert(1)>",
            "<b>raw</b>"]
    for text in kept:
        assert _autolinks(text) == text, text
    assert "\\<b>" in _escape_html("<b>raw</b> <https://a.example>").replace("\u2060", "")
    _app()
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False
    view.render("Go to <https://a.example/page> now.\n\n`<https://code.example>`\n")
    text = view.browser.toPlainText()
    assert "https://a.example/page" in text and "<https://a.example" not in text
    assert "<https://code.example>" in text and "\u2060" not in text
    anchors = []
    block = view.browser.document().begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            fmt = it.fragment().charFormat()
            if fmt.isAnchor():
                anchors.append(fmt.anchorHref())
            it += 1
        block = block.next()
    assert "https://a.example/page" in anchors


def test_sad_autolinks_of_hostile_lines_stay_linear():
    from ui.markdown_safe import _escape_html

    start = time.monotonic()
    _escape_html("`" * 200_000 + "<a:b>" * 100_000)
    _escape_html("<" * 1_000_000)
    _escape_html("\\" * 500_000 + "<x:y>")
    TB.budget(time.monotonic() - start < 5, 'time.monotonic() - start < 5')
