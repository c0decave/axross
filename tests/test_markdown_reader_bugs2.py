"""Bugs a second reviewer found in the Markdown reader, each first a failing
test here (the first one, _unmark after an emoji: tests/test_markdown_fallback.py):

* a wide table froze the window (90 rows x 1,000 columns: 10 s) - the limit
  counted rows, not cells; big pages are now rendered in bounded parts;
* renderable() cut ordinary documents: every line with a "|" counted as a
  table row (prose and code too), and a long line hid all after it;
* data: images - the terminal printed their base64, Qt cut the page there;
* badges and remote images, Export HTML's images, Copy Code Block, tight
  lists with a quote, math that changed meaning, and smaller things.
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

pytest.importorskip("markdown_it", reason="markdown-it-py not installed")
pytest.importorskip("mdit_py_plugins", reason="mdit-py-plugins not installed")

from core import markdown_doc as MD  # noqa: E402
from core import markdown_term as T  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def plain(text: str) -> str:
    return ANSI.sub("", text)


def term(text: str, width: int = 70, **options) -> str:
    return T.render(text, T.Options(width=width, **options))


_APP: list = []  # (the application lives as long as the module)


def _qt():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    return _APP[0]


def _png_bytes(width: int = 12, height: int = 8) -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (width, height), (200, 30, 30)).save(out, format="PNG")
    return out.getvalue()


def wide_table(rows: int, columns: int) -> str:
    head = "|" + "|".join(f"c{n}" for n in range(columns)) + "|\n|" + "---|" * columns + "\n"
    return head + "".join("|" + "|".join(f"r{r}" for _ in range(columns)) + "|\n" for r in range(rows))


_MEASURE = """
import sys, time
sys.path.insert(0, {root!r})
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
app = QApplication([])
from ui import markdown_view as MV
text = open({path!r}, encoding="utf-8").read()
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
last[0] = time.thread_time()
view.render(text)
def settle(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.003)
settle(3.0)
bar = view.browser.verticalScrollBar()
bar.setValue(bar.maximum())
settle(0.5)
view.resize(700, 800)   # (a resize, and a rendering anew - a reload - held it up too)
settle(1.0)
view.render(text)
settle(3.0)
print(max(gaps), view.browser.document().blockCount())
"""


def _gui_block(text: str, tmp_path, full: bool = True) -> tuple[float, int]:
    """The longest the GUI thread was held up (a 10 ms timer's longest gap)
    while *text* was rendered, scrolled to its end, the view resized and the
    text rendered anew, and the page's blocks
    - in a process of its own (the views of other tests answer timers too)."""
    import subprocess

    path = tmp_path / "page.md"
    path.write_text(text, encoding="utf-8")
    root = str(Path(__file__).resolve().parent.parent)
    best = None
    for _attempt in range(3):  # (the best of three: a busy machine holds any thread up now and then)
        out = subprocess.run([sys.executable, "-c", _MEASURE.format(root=root, path=str(path), full=full)],
                             capture_output=True, text=True, timeout=120,
                             env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
        assert out.returncode == 0, out.stderr[-2000:]
        block, blocks = out.stdout.split()
        best = (float(block), int(blocks)) if best is None or float(block) < best[0] else best
        if best[0] < GUI_BLOCK / 2:
            break
    return best


# -- 2. wide tables, big pages ------------------------------------------------------------------

#: The longest the GUI thread may be held up by rendering (a part of a page
#: is laid out by Qt on it; measured about 0.15 s here - the bound leaves room
#: for a busy machine).
GUI_BLOCK = 0.4


@pytest.mark.parametrize("text", [
    wide_table(90, 1000),                     # 10 s before
    wide_table(4000, 3),
    wide_table(500, 8),                       # (laid out whole, in parts: tests/test_markdown_reader_bugs3.py)
    "> " * 10000 + "deep\n",                   # (quotes as tables: 30 nested hung Qt's table layout)
    "<table><tr><td>" * 40 + "deep\n",          # (raw HTML tables inside each other)
    "".join("  " * level + "- item\n" for level in range(2500)),  # (a list 2,500 deep: 6 MB, 4.7 s before)
    "".join(f"## T{n}\n\n| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n\n" for n in range(1500)),
    "".join("".join(f"- item {j}\n" for j in range(100)) + "\npara\n\n" for _ in range(100)),
])
def test_sad_rendering_never_holds_up_the_window(text, tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    block, blocks = _gui_block(text, tmp_path)
    assert block < GUI_BLOCK, f"the GUI thread was held up {block:.2f} s"
    assert blocks >= 1  # (laid out at all)


@pytest.mark.parametrize("text", [
    "".join(f"## T{n}\n\n| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n\n" for n in range(1500)),
    "".join(f"Paragraph {n} with some words in it.\n\n" for n in range(20000)),
    wide_table(500, 8),
])
def test_sad_qts_own_parser_never_holds_up_the_window_either(text, tmp_path):
    """Without markdown-it-py (optional in axross) Qt's own parser is given
    a big text in parts too (0.5 s held before)."""
    pytest.importorskip("PyQt6.QtWidgets")
    block, blocks = _gui_block(text, tmp_path, full=False)
    assert block < GUI_BLOCK, f"the GUI thread was held up {block:.2f} s"
    # (laid out at all: shown anew where it was read - at its end - that
    # part is laid out first, not all of it before; it was more than 1000
    # blocks when the reload went back to the top)
    assert blocks > 20


@pytest.mark.parametrize("full", [False, True])
def test_happy_a_page_in_parts_shows_what_it_shows_at_once(monkeypatch, full):
    """A big page is laid out in parts (Qt's own parser and markdown-it's
    HTML alike); each part's first block went into the page's last one and
    took its format: a heading there lost its level and its place in the
    outline."""
    app = _qt()
    from ui import markdown_view as MV

    section = ("# Part {n}\n\nSee [the site][ref] and a note[^n{n}].\n\n- a\n- b\n\n  more of b\n\n"
               "1. one\n\n2. two\n\n```\n# not a heading\n\ntext\n```\n\n> quote\n>\n> on\n\n"
               "| x | y |\n|---|---|\n| 1 | 2 |\n\n[^n{n}]: note {n}\n\nThe end of {n}.\n\n")
    text = "".join(section.format(n=n) for n in range(400)) + "[ref]: https://example.org\n"

    def shown(parts: bool):
        monkeypatch.setattr(MV, "PART_LINES", 300 if parts else 10 ** 9)
        monkeypatch.setattr(MV, "PART_BLOCKS", 200 if parts else 0)
        monkeypatch.setattr(MV, "BACKGROUND_CHARS", 10 ** 9)
        view = MV.MarkdownView(None)
        view.full = view.full and full
        view.render(text)
        end = time.monotonic() + TB.READY_SECONDS
        while view.status.text().startswith(MV.tr("Rendering…")) and time.monotonic() < end:
            app.processEvents()
        view.load_rest()  # (a long page is laid out as it is read: all of it, to compare)
        while view.more() and time.monotonic() < end + TB.READY_SECONDS:
            app.processEvents()
        levels, block = [], view.browser.document().begin()
        while block.isValid():
            levels.append(block.blockFormat().headingLevel())
            block = block.next()
        result = (view.browser.toPlainText(), view.headings(), sorted(view.anchors), levels)
        view.deleteLater()
        return result

    if not full:
        assert len(MV.markdown_parts(text, 300)) > 5
    at_once, in_parts = shown(False), shown(True)
    assert len(at_once[1]) == 400 and in_parts[1] == at_once[1]
    assert in_parts[3] == at_once[3] and in_parts[2] == at_once[2]
    assert in_parts[0].replace("\n", "").rstrip() == at_once[0].replace("\n", "").rstrip()


def test_happy_a_table_too_big_is_laid_out_in_parts_or_too_wide_shown_as_written():
    """A long table is laid out whole, in parts (tests/test_markdown_reader_bugs3.py);
    one of more than TABLE_COLUMNS columns - no one reads 1,000 as a grid - as written."""
    from ui import markdown_view as MV

    text = "# Before\n\n" + wide_table(90, 1000) + "\n# After\n"
    part, why = MV.renderable(text)
    assert why and "columns" in why and "# After" in part and "# Before" in part
    assert part.count("|c0|") == 1 and "```" in part and "|r89|" in part
    part, why = MV.renderable(wide_table(2000, 4))
    assert not why and part.count(MV.CHUNK) >= 2  # (laid out in parts, none as written)


# -- 3. what renderable() counts ----------------------------------------------------------------

def test_sad_pipes_in_prose_and_code_are_no_table_rows():
    from ui import markdown_view as MV

    recipe = ("## Recipe\n\nFind with `ls | grep x` and `wc -l`.\n\n    cat log | sort | uniq -c\n\n"
              "```sh\na | b | c\n```\n\n| opt | meaning |\n|---|---|\n| -n | numeric |\n\n")
    text = recipe * 1500
    assert MV.renderable(text) == (text, "")


def test_sad_a_long_line_is_replaced_not_the_rest_of_the_page():
    from ui import markdown_view as MV

    text = "# A\n\nbefore\n\n" + "x" * (MV.LONG_RUN + 5) + "\n\n# B\n\nafter\n"
    part, why = MV.renderable(text)
    assert why and "# B" in part and "after" in part and "x" * MV.LONG_RUN not in part
    image = "![p](data:image/png;base64," + "A" * (MV.LONG_RUN + 5) + ")"
    assert MV.renderable(f"# A\n\n{image}\n\n# B\n") == (f"# A\n\n{image}\n\n# B\n", "")


def test_sad_a_long_list_keeps_all_its_items_and_the_page_after_it():
    from ui import markdown_view as MV

    text = "".join(f"- {n}\n" for n in range(MV.LIST_ITEMS + 50)) + "\n# After\n\ntext\n"
    part, why = MV.renderable(text)
    assert not why and "# After" in part and "```" not in part  # (in parts: tests/test_markdown_reader_bugs4.py)
    assert part.count("\n- ") == MV.LIST_ITEMS + 49 and f"- {MV.LIST_ITEMS + 49}" in part


# -- 4. data: images ----------------------------------------------------------------------------

def test_sad_a_data_image_is_drawn_in_the_terminal_never_printed():
    payload = base64.b64encode(_png_bytes()).decode("ascii")
    text = f"# N\n\n![plot](data:image/png;base64,{payload})\n\nafter\n"
    out = plain(term(text, images="blocks", depth="truecolor", folder="/tmp"))
    assert payload[:40] not in out and "base64" not in out
    assert "🖼 plot" in out and "▀" in out and "after" in out
    big = base64.b64encode(b"x" * (T.IMAGE_LIMIT + 10)).decode("ascii")
    out = plain(term(f"![b](data:image/png;base64,{big})\n", images="blocks", depth="truecolor"))
    assert big[:40] not in out and len(out) < 500
    out = plain(term(f'<img src="data:image/svg+xml;base64,PHN2Zz4=" alt="s"> [l](data:image/png;base64,{payload})\n',
                     images="blocks", depth="truecolor"))
    assert "PHN2Zz4" not in out and payload[:40] not in out  # (an SVG: no image; a link: no address beside it)


def test_sad_a_data_image_is_shown_in_qt_and_the_page_goes_on():
    _qt()
    from PyQt6.QtGui import QImage

    from ui import markdown_view as MV

    from core.local_fs import LocalFS

    payload = base64.b64encode(_png_bytes(300, 200)).decode("ascii")
    payload += "A" * 0  # (a real plot is longer than a line Qt wraps in time: see the next test)
    text = f"# N\n\n![plot](data:image/png;base64,{payload})\n\n# After\n"
    view = MV.MarkdownView(MV.ImageSource(LocalFS(), "/tmp/doc.md"))
    view.resize(900, 600)
    view.show()
    try:
        view.render(text)
        name = f"data:image/png;base64,{payload}"
        end = time.monotonic() + TB.READY_SECONDS
        while time.monotonic() < end and not isinstance(view.originals.get(name), QImage):
            _qt().processEvents()
            time.sleep(0.01)
        assert isinstance(view.originals.get(name), QImage) and view.originals[name].width() == 300
        assert view.headings() == ["N", "After"] and not view.notice.isVisible()
    finally:
        view.deleteLater()


# -- 5. badges and remote images ----------------------------------------------------------------

BADGES = ("[![Build](https://ci.example/badge.svg)](https://ci.example/o/r) "
          "[![PyPI](https://img.example/pypi.svg)](https://pypi.example/p/foo) "
          "![Logo](https://img.example/logo.png)\n\n"
          '<p align="center"><img src="https://img.example/l.png" alt="Banner" width="200"></p>\n')


def test_sad_a_badge_row_is_a_row_of_small_chips_named_by_their_alt_text_in_qt():
    _qt()
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(__import__("core.local_fs", fromlist=["LocalFS"]).LocalFS(),
                                          "/tmp/doc.md"))
    view.resize(900, 600)
    try:
        view.render(BADGES)
        text = view.browser.toPlainText()
        assert "▣ Build" in text and "▣ PyPI" in text and "▣ Logo" in text and "▣ Banner" in text
        assert text.splitlines()[0].count("▣") == 3  # (one row, not stacked boxes)
        assert "https://" not in text  # (the address: in the tooltip and the status line)
        assert not any(isinstance(image, object) and getattr(image, "width", lambda: 0)() == 420
                       for image in view.images.values())
        position = view.browser.document().find("Build").position()
        assert view.tooltip_at(position).endswith("https://ci.example/badge.svg")
    finally:
        view.deleteLater()


def test_sad_a_badge_row_prints_one_address_per_badge_at_most_in_the_terminal():
    out = plain(term(BADGES, width=200, depth="truecolor", folder="/tmp"))
    assert out.count("https://ci.example") == 1 and "badge.svg" not in out
    assert "🖼 Build" in out and "🖼 Logo" in out and "img.example" not in out
    raw = term(BADGES, width=200, depth="truecolor", folder="/tmp")
    assert "\x1b]8;;https://img.example/logo.png\x1b\\" in raw  # (the picture's address: its link)


def test_edge_a_placeholder_is_sized_from_the_font_not_420_pixels():
    _qt()
    from ui import markdown_view as MV

    small = MV.placeholder("Reading x.png…")
    assert small.width() < 420 and small.height() < 36 + 1


# -- 6. export ----------------------------------------------------------------------------------

def test_sad_export_html_shows_only_images_the_viewer_read_and_loads_nothing():
    _qt()
    from ui.markdown_html import EXPORT_POLICY, export_html

    text = "![ok](ok.png) ![refused](link.png) ![svg](ext.svg) <img src=\"sub/x.png\">\n"
    page = export_html(MD.parse(text), images={"ok.png": "data:image/png;base64,iVBORw0KGgo="})
    body = page.split("<body>", 1)[1]
    assert body.count("<img") == 1 and '<img src="data:image/png;base64,iVBORw0KGgo="' in body
    assert "▣ refused" in body and "▣ svg" in body and 'src="sub/x.png"' not in body
    assert "img-src data:;" in EXPORT_POLICY.replace("img-src data: ", "img-src data:;") \
        and "file:" not in EXPORT_POLICY and "'self'" not in EXPORT_POLICY


# -- 7. Copy Code Block -------------------------------------------------------------------------

def test_sad_copy_code_block_copies_one_block_not_its_neighbours():
    _qt()
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    try:
        view.render("```\nfirst()\n\n\tindented_with_tab()\n```\n```\nsecond()\n```\n\n    indented code\n\n"
                    "Text\n\n```diff\n- removed\n+ added\n```\n")
        from PyQt6.QtWidgets import QApplication

        end = time.monotonic() + TB.READY_SECONDS
        while time.monotonic() < end and not view._readable:  # (a text with code: made on a worker)
            QApplication.processEvents()
            time.sleep(0.01)
        document = view.browser.document()
        assert view.code_block_at(document.find("first()").position()) == "first()\n\n\tindented_with_tab()\n"
        assert view.code_block_at(document.find("second()").position()) == "second()\n"
        assert view.code_block_at(document.find("indented code").position()) == "indented code\n"
        assert view.code_block_at(document.find("+ added").position()) == "- removed\n+ added\n"
    finally:
        view.deleteLater()


# -- 8. tight lists -----------------------------------------------------------------------------

def test_sad_a_tight_list_with_a_quote_in_an_item_stays_tight():
    out = plain(term("- one\n- two\n  > quoted\n- three\n- four\n"))
    assert "• one\n• two\n  │ quoted\n• three\n• four" in out


# -- 9. math that keeps its meaning -------------------------------------------------------------

@pytest.mark.parametrize("tex, shown", [
    (r"x = \frac{-b \pm \sqrt{b^2-4ac}}{2a}", "x = (−b ± √(b²−4ac))/(2a)"),  # (a minus sign: bugs6)
    (r"\frac{1}{10}", "1/10"),
    (r"\hat{x} + \bar{y} + \vec{v} + \tilde{n}", "x̂ + ȳ + v⃗ + ñ"),
    (r"\binom{n}{k}", "C(n, k)"),
    (r"a \bmod b", "a mod b"),
    (r"a \equiv b \pmod{n}", "a ≡ b (mod n)"),
    (r"\sum_{n=0}^\infty a_n", "∑_(n=0)^∞ aₙ"),
    (r"\left( \frac{a}{b} \right)", "(a/b)"),
    (r"\left[ x \right]", "[x]"),
])
def test_sad_math_as_text_keeps_its_meaning(tex, shown):
    assert MD.math_text(tex) == shown


# -- 10. polish ---------------------------------------------------------------------------------

def test_happy_single_tildes_strike_as_on_github():
    doc = MD.parse("~one~ and ~~two~~ but a~b and ~ c ~\n")
    kinds = [c.type for c in doc.tokens[1].children]
    assert kinds.count("s_open") == 2 and "a~b" in "".join(c.content for c in doc.tokens[1].children)
    assert "~ c ~" in "".join(c.content for c in doc.tokens[1].children)


@pytest.mark.parametrize("code, emoji", [
    ("ambulance", "🚑"), ("robot", "🤖"), ("bookmark", "🔖"), ("construction_worker", "👷"),
    ("lipstick", "💄"), ("poop", "💩"), ("twisted_rightwards_arrows", "🔀"), ("alien", "👽"),
    ("card_file_box", "🗃️"), ("test_tube", "🧪"), ("adhesive_bandage", "🩹"), ("goal_net", "🥅"),
])
def test_happy_gitmoji_codes_are_known(code, emoji):
    assert MD.EMOJI[code] == emoji


def test_happy_without_colour_code_and_emphasis_are_marked():
    out = term("Use `ls` for *this*, **that** and ~~not~~ this.\n", depth="none")
    assert "`ls`" in out and "*this*" in out and "**that**" in out and "~~not~~" in out
    coloured = plain(term("Use `ls` for *this*.\n", depth="truecolor"))
    assert "`" not in coloured and "*this*" not in coloured


def test_sad_terminal_file_links_stay_in_the_documents_folder_and_never_run(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "other.md").write_text("x")
    tool = tmp_path / "docs" / "tool.sh"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    (tmp_path / "secret.txt").write_text("s")
    out = term("[o](other.md) [up](../secret.txt) [run](tool.sh)\n", folder=str(tmp_path / "docs"),
               depth="truecolor")
    links = re.findall(r"\x1b\]8;;([^\x1b]*)\x1b\\", out)
    assert [link for link in links if link] == ["file://" + str(tmp_path / "docs" / "other.md")]


def test_happy_watch_shows_a_long_file_from_its_top(tmp_path, capsys, monkeypatch):
    from core import markdown_cli as C

    doc = tmp_path / "long.md"
    doc.write_text("# Top\n\n" + "".join(f"line {n}\n\n" for n in range(200)))

    class Tty(io.StringIO):
        def isatty(self):
            return True

    out = Tty()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr("shutil.get_terminal_size", lambda fallback=None: os.terminal_size((80, 24)))
    args = C._parser().parse_args(["--watch", "--color", "never", str(doc)])
    assert C._watch(args, 60, "none", True, "none", False, poll=0, rounds=1) == 0
    shown = out.getvalue().replace("\x1b[H\x1b[2J", "")
    assert shown.startswith("█ Top") and shown.count("\n") <= 24 and "line 199" not in shown
    assert "more lines" in shown and "\x1b" not in shown


def test_happy_a_mailto_link_is_asked_about_then_opens_the_mail_program(tmp_path, monkeypatch):
    _qt()
    from PyQt6.QtCore import QUrl

    from core.local_fs import LocalFS
    from ui import markdown_safe
    from ui.markdown_viewer import MarkdownViewerDialog

    (tmp_path / "doc.md").write_text("[mail](mailto:team@example.org)\n")
    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "doc.md"))
    try:
        asked, opened = [], []
        monkeypatch.setattr(markdown_safe, "ask_open_link", lambda parent, href, text, **kw: asked.append(href) or True)
        monkeypatch.setattr("core.desktop_open.open_url", lambda url: opened.append(url.toString()))
        monkeypatch.setattr("core.security_mode.current_policy",
                            lambda: type("P", (), {"allow_external_viewer": True})())
        viewer.follow(QUrl("mailto:team@example.org"))
        assert asked == ["mailto:team@example.org"] and opened == ["mailto:team@example.org"]
        assert markdown_safe.open_link_question("mailto:team@example.org", "").startswith(
            "Write to this address with your mail program?")
    finally:
        viewer.deleteLater()


def test_happy_details_are_a_clear_open_summary_with_their_contents_under_it():
    text = "<details>\n<summary>Click me</summary>\n\nHidden *content*.\n\n</details>\n"
    _qt()
    from ui.markdown_html import style_sheet, to_html_parts

    # (folded at first, as GitHub shows it: a click on the summary opens it - test_markdown_reader_bugs4)
    page = "".join(to_html_parts(MD.parse(text), blocks=0, toggled={1}))
    assert '<a class="fold" href="#axross-details-1"><b>▾ Click me</b></a></p>' in page
    assert '<div class="details">' in page and "Hidden" in page
    assert ".details { margin-left" in style_sheet(False)
    assert "▾ Click me" in plain(term(text))


def test_happy_axross_markdown_html_puts_a_data_image_in_and_no_other(tmp_path, capsys):
    _qt()
    from ui.markdown_app import main

    payload = base64.b64encode(_png_bytes()).decode("ascii")
    (tmp_path / "doc.md").write_text(f"![d](data:image/png;base64,{payload}) ![r](https://x.example/a.png)\n")
    assert main(["axross-markdown", "--html", str(tmp_path / "doc.md")]) == 0
    page = capsys.readouterr().out
    body = page.split("<body>", 1)[1]
    assert body.count("<img") == 1 and "▣ r" in body and "img-src data:;" in page


def test_sad_a_wide_window_never_scrolls_sideways_by_a_pixel():
    """README.md's tables, whose cells cannot be narrower, went one pixel
    past the text: a scroll bar for one pixel at every width."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    if not readme.is_file():
        pytest.skip("no README.md here")
    _qt()
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    view = MV.MarkdownView(MV.ImageSource(LocalFS(), str(readme)))
    view.show()
    try:
        for width in (1000, 1250):
            view.resize(width, 700)
            view.render(MV.read_text(LocalFS(), str(readme))[0])
            end = time.monotonic() + TB.READY_SECONDS  # (the page made - a wait for it, not 0.8 s of pumps)
            while time.monotonic() < end and not (view._readable and not view._scheduled):
                _qt().processEvents()
                time.sleep(0.01)
            settled = time.monotonic() + 0.3
            while time.monotonic() < settled:
                _qt().processEvents()
                time.sleep(0.01)
            assert view.browser.horizontalScrollBar().maximum() == 0, width
    finally:
        view.deleteLater()
