"""The full Markdown set (core.markdown_doc, markdown-it-py) in the Qt viewer
(ui.markdown_html, ui.markdown_view) and in the terminal (core.markdown_term,
core.markdown_cli / axross-mdcat).

Asked for: "einen perfekten Markdown Reader" - a Qt and a CLI variant, with
colours, the complete Markdown set, images and links. A file is untrusted:
no raw HTML, no escape sequence of its own reaches a terminal, links into
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


def test_sad_raw_html_stays_text_and_a_javascript_link_is_no_link():
    from ui.markdown_html import to_html

    page = to_html(MD.parse(FULL))
    assert "&lt;b&gt;raw&lt;/b&gt;" in page and "<b>raw" not in page
    assert "javascript:" not in page.replace("[bad](javascript:alert(1))", "")
    assert 'href="javascript' not in page


def test_happy_the_qt_page_has_anchors_alignment_tasks_colours_and_front_matter():
    from ui.markdown_html import anchor_names, style_sheet, to_html

    page = to_html(MD.parse(FULL), dark=False)
    assert {"head-one", "head-one-1", "fn1", "fnref1"} <= anchor_names(page)
    assert '<th align="left">' in page and '<th align="center">' in page and '<th align="right">' in page
    assert '<table border="1"' in page
    assert "☑" in page and "☐" in page and 'list-style-type: none' in page
    assert '<pre class="front-matter">' in page
    assert "<dl>" in page and "<dt>" in page
    assert re.search(r'<span style="[^"]*color: #', page)  # Pygments' colours, inline
    assert "#0550ae" in style_sheet(False) and "#79c0ff" in style_sheet(True)


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
    assert view.headings() == ["Head one", "Head one"]
    assert {"head-one", "head-one-1"} <= set(view.anchors) and "fn1" in view.names
    text = view.browser.toPlainText()
    assert "<b>raw</b>" in text and "☑ done" in text and "Meaning" in text
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

    def page(text, dark):
        threads.append(threading.current_thread())
        return real(text, dark)

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
    assert view.headings() == ["A"] and "<b>raw</b>" in view.browser.toPlainText()


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
    assert "[a]" in out and "The note." in out
    assert "front matter" in out and "title: Demo" in out
    assert "<b>raw</b>" in out


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
    assert "█ Head one" in out and "\x1b" not in out
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
    monkeypatch.setattr(protected_places, "read_refusal", lambda path, **kw: "secret")
    assert C.main(["--color", "never", str(folder / "doc.md")]) == 1
    assert "secret" in capsys.readouterr().err


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
