"""The fifteenth round of the Markdown reader (the fourteenth review): a
formula that blanked the page, a folder's README opened unchecked, huge
single blocks laid out at once, reference links of Qt's own parser, deep
lists, the command line - and the lows. Each test failed before, from the
reviewer's repros.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _closed_after():
    """Every window of a test closed after it: a page left open went on laying itself out in the next
    test's event loop - its pauses counted as that test's (the md4c italics stall, 0.5 s once a run)."""
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    pump(0.05)


def _view(text: str, full: bool):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    view.render(text)
    assert until(lambda: view._readable and not view.more(), 60)
    pump(0.2)
    return view


# -- 1. a formula never blanks the page --------------------------------------------------------------

ENVIRONMENTS = ["matrix", "pmatrix", "bmatrix", "Bmatrix", "vmatrix", "Vmatrix", "smallmatrix", "cases", "dcases",
                "rcases", "aligned", "align", "align*", "gathered", "array", "split", "alignat", "subarray"]


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_every_environment_shows_and_the_page_stays(full):
    body = "".join(f"Before {name}.\n\n$$\\begin{{{name}}}{{cc}} 1 & 2 \\\\ 3 & 4 \\end{{{name}}}$$\n\n"
                   for name in ENVIRONMENTS) + "The end.\n"
    view = _view(body, full)
    text = view.browser.toPlainText()
    assert "The end." in text and all(f"Before {name}." in text for name in ENVIRONMENTS), text[:300]


def test_sad_a_formula_that_cannot_be_laid_out_shows_as_its_tex(monkeypatch):
    from ui import markdown_html as H

    def broken(*_args, **_kwargs):
        raise KeyError("}")

    monkeypatch.setattr(H, "_row_html", broken)
    page = H.display_html(r"\frac{a}{b} = 1", H.colours(False))
    assert page is None  # (in its line, as text - never an error)


def test_sad_qts_own_parser_shows_a_formula_it_cannot_lay_out_as_text(monkeypatch):
    from ui import markdown_html as H

    monkeypatch.setattr(H, "_row_html", lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("}")))
    view = _view("Before.\n\n$$\n\\frac{a}{b} = 1\n$$\n\nAfter.\n", False)
    text = view.browser.toPlainText()
    assert "Before." in text and "After." in text and "= 1" in text, repr(text)  # (it was gone)


# -- 2. a folder's README is checked as any link ---------------------------------------------------------

def test_hostile_a_folders_readme_is_checked_as_a_link(tmp_path):
    from PyQt6.QtCore import QUrl

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
    (outside / "private.md").write_text("# Private\n\nNot beside the document.\n", encoding="utf-8")
    doc = tmp_path / "doc"
    for name, target in (("sub", outside / "private.md"), ("sub2", outside / ".env")):
        (doc / name).mkdir(parents=True)
        (doc / name / "README.md").symlink_to(target)
    (doc / "index.md").write_text("# Doc\n\n[sub](sub) [sub2](sub2)\n", encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(doc / "index.md"))
    dialog.show()
    asked = []
    dialog.ask_outside = lambda path, text="": asked.append(path) or False
    try:
        assert until(lambda: "Doc" in dialog.view.browser.toPlainText(), 20)
        dialog.follow(QUrl("sub2"))
        pump(1.0)
        assert dialog.path == str(doc / "index.md") and "hunter2" not in dialog.view.browser.toPlainText()
        assert "secret" in dialog.view.status.text().lower() and not asked  # (never asked: never opened)
        dialog.follow(QUrl("sub"))
        pump(1.0)
        assert dialog.path == str(doc / "index.md") and asked == [str(doc / "sub" / "README.md")]
    finally:
        dialog.close()
        dialog.deleteLater()


# -- 3. the exported viewer: no import it needs left out -------------------------------------------------

def _exporter():
    sys.path.insert(0, str(ROOT / "scripts"))
    import export_standalone

    return export_standalone


def test_packaging_a_handler_that_raises_again_guards_no_import():
    import ast

    exporter = _exporter()
    again = ast.parse("try:\n    from core.x import y\nexcept BaseException:\n    clean()\n    raise\n")
    assert not exporter._catches_import_error(again.body[0].handlers[0])  # (the editor's Save failed so)
    other = ast.parse("try:\n    from core.x import y\nexcept ImportError as exc:\n    raise OSError('no') from exc\n")
    assert exporter._catches_import_error(other.body[0].handlers[0])  # (an error of its own: a guard)


def test_packaging_the_markdown_export_leaves_no_gap_and_has_its_own_version(tmp_path):
    exporter = _exporter()
    out = exporter.export("markdown", tmp_path / "markdown")  # (an unguarded import of a module left out: fails)
    project = (tmp_path / "markdown" / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "(?!' + re.escape(exporter._version()) + r'")', project, re.MULTILINE), project
    readme = (tmp_path / "markdown" / "README.md").read_text(encoding="utf-8")
    assert "raw HTML is shown as text" not in readme
    assert out


# -- (G4) one huge block never holds up the window -------------------------------------------------

BOMBS = {
    "fence": lambda: "# Log\n\n```\n" + "".join(f"2026-01-01 INFO request {n} served\n" for n in range(20_000)) + "```\n",
    "fence_unclosed": lambda: "```\n" + "line\n" * 60_000,
    "longtable": lambda: "| a | b |\n|---|---|\n" + "".join(f"| {n} | {n} |\n" for n in range(155_000)),
    "quotes": lambda: "".join(f"> quote {n}\n> more\n\n" for n in range(8_000)),
    "alerts": lambda: "".join(f"> [!NOTE]\n> n {n}\n\n" for n in range(8_000)),
    "displays": lambda: "".join(f"$$\\sum_{{i=0}}^{{{n}}} \\frac{{1}}{{i}}$$\n\n" for n in range(3_000)),
    "formulas": lambda: " ".join(f"${{x_{{{n}}}}}^2$" for n in range(6_000)) + "\n",
    "images": lambda: " ".join(f"![i{n}](img{n}.png)" for n in range(3_000)) + "\n",
    "math_cells": lambda: "| a | b |\n|---|---|\n" + "".join(f"| $\\frac{{{n}}}{{2}}$ | $\\sqrt{{{n}}}$ |\n"
                                                         for n in range(5_000)),
}


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("bomb", sorted(BOMBS))
def test_guard_one_huge_block_never_holds_up_the_window(bomb, full):
    """The fourteenth review's bombs: a fence of 30,000 lines, a table shown as written, 8,000 quotes,
    alerts or display formulas, 6,000 formulas or 5,000 images in one paragraph, a table of formulas -
    each was laid out in one turn of the event loop (5 to 30 s). The GUI thread's own time in one turn
    stays under 0.3 s (its wall time counts the machine's other work too: not asserted - flaky under load)."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(1000, 800)
    view.show()
    turns, last = [], [time.monotonic(), time.thread_time()]

    def beat():
        now = [time.monotonic(), time.thread_time()]
        turns.append((round(now[1] - last[1], 3), round(now[0] - last[0], 3)))
        last[:] = now

    timer = QTimer()
    timer.timeout.connect(beat)
    timer.start(5)
    view.render(BOMBS[bomb]())
    assert until(lambda: view._readable and view.markdown, 120)
    def laid() -> bool:  # (as far as it goes at once)
        return not view._scheduled and not view.status.text().startswith("Rendering")

    until(laid, 30)
    pump(0.3)
    view.go_end()
    pump(0.5)
    until(laid, 30)
    timer.stop()
    worst = sorted(turns, reverse=True)[:3]
    assert worst[0][0] < 0.3, worst


# -- 5. reference links in Qt's own parser ------------------------------------------------------------

REFERENCES = ('[ref][r] and [ref2][r2] and [r3] and [Spaced]\n\n[r]: https://example.com/x\n'
              '[r2]: https://example.com/a_b_c "Title"\n[r3]: <https://example.com/angle>\n'
              '[spaced]: <https://example.com/a b>\n')


def _hrefs(view) -> list[tuple[str, str]]:
    document, out = view.browser.document(), []
    block = document.begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            fragment = pieces.fragment()
            if fragment.charFormat().isAnchor() and fragment.charFormat().anchorHref():
                out.append((fragment.text(), fragment.charFormat().anchorHref()))
            pieces += 1
        block = block.next()
    return out


@pytest.mark.parametrize("full", [True, False])
def test_sad_reference_links_go_where_their_definition_says(full):
    """sec/refs.md: Qt's own parser's [ref][r] linked to "[https://…](https://…)" - its definition's
    address written "<…>" by a pass, then made a link of its own."""
    view = _view(REFERENCES, full)
    assert _hrefs(view) == [("ref", "https://example.com/x"), ("ref2", "https://example.com/a_b_c"),
                            ("r3", "https://example.com/angle"), ("Spaced", "https://example.com/a%20b")]
    assert view.browser.toPlainText().strip() == "ref and ref2 and r3 and Spaced"


# -- 6. deep lists: one limit in every view -----------------------------------------------------------

def _deep_list(levels: int) -> str:
    return "".join("  " * level + f"- item {level}\n" for level in range(levels))


@pytest.mark.parametrize("levels", [14, 15, 16, 17, 40])
def test_sad_a_deep_list_is_a_list_at_every_depth_in_the_terminal(levels):
    """docs/deeplist.md: markdown-it nested 15 levels (MAX_NESTING 30), the terminal flattened at 16 - an
    item 16 deep and every one after it was code, "- item" as written."""
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render(_deep_list(levels), MT.Options(depth="none", width=200)))
    lines = [line for line in shown.splitlines() if "item" in line]
    assert len(lines) == levels and not any("- item" in line for line in lines), shown
    assert ("flatter" in shown) == (levels > 17)


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("levels", [14, 15, 16, 17, 40])
def test_sad_a_deep_list_is_a_list_at_every_depth_in_the_viewer(levels, full):
    view = _view(_deep_list(levels), full)
    document = view.browser.document()
    items, block = [], document.begin()
    while block.isValid():
        if "item" in block.text():
            items.append((block.text(), block.textList() is not None))
        block = block.next()
    assert len(items) == levels and all(listed and not text.startswith("-") for text, listed in items), items
    deepest = max(document.findBlock(0).blockFormat().indent(), *(
        document.findBlockByNumber(n).textList().format().indent() for n in range(document.blockCount())
        if document.findBlockByNumber(n).textList() is not None))
    assert deepest == min(levels, 17)
    assert ("flatter" in view.notice.text()) == (levels > 17)


# -- 7. the command line ------------------------------------------------------------------------------

def _app(*args: str, stdin: str = "") -> tuple[int, str, str, bool]:
    """axross-markdown ARGS in a child: (exit code, stdout, stderr, whether Qt was imported)."""
    code = ("import sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from ui.markdown_app import main\n"
            "try:\n"
            f"    rc = main(['axross-markdown', *{list(args)!r}])\n"
            "except SystemExit as stop:\n"
            "    rc = stop.code\n"
            "sys.stdout.flush()\n"
            "print('QT-IMPORTED' if any(m.startswith('PyQt6') for m in sys.modules) else 'NO-QT', file=sys.stderr)\n"
            "sys.exit(rc)\n")
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", AXROSS_SMOKE_MS="1")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120, env=env,
                         input=stdin, cwd=str(ROOT))
    return out.returncode, out.stdout, out.stderr, "QT-IMPORTED" in out.stderr


def test_sad_help_and_version_say_so_without_qt():
    """--help and --version opened an empty viewer (Qt started); an unknown option was ignored."""
    rc, out, _err, qt = _app("--help")
    assert rc == 0 and "usage: axross-markdown" in out and "--term" in out and "--html" in out and not qt
    rc, out, _err, qt = _app("--version")
    assert rc == 0 and re.match(r"axross-markdown \d+\.\d+\.\d+", out) and not qt


def test_sad_an_unknown_option_is_an_error_not_a_file():
    rc, _out, err, qt = _app("--bogus", "README.md")
    assert rc == 2 and "unrecognized arguments: --bogus" in err and not qt


def test_sad_the_terminal_and_the_page_start_no_qt(tmp_path):
    """--term and --html imported Qt (ui/__init__ installed its guards at once): on a machine
    without Qt's libraries they failed."""
    page = tmp_path / "a.md"
    page.write_text("# Title\n\nSome *text*.\n", encoding="utf-8")
    rc, out, _err, qt = _app("--term", "--color", "never", "--no-pager", str(page))
    assert rc == 0 and "Title" in out and not qt
    rc, out, _err, qt = _app("--html", str(page))
    assert rc == 0 and "<h1" in out and "Title" in out and not qt
    rc, out, _err, qt = _app("--html", "-", stdin="# From stdin\n")
    assert rc == 0 and "From stdin" in out and not qt
    rc, _out, err, qt = _app("--html", str(page), str(page))
    assert rc == 2 and "one file" in err and not qt


def test_happy_the_guards_are_installed_once_qt_is_imported():
    """ui's installs (the exit handler, the rich-text guard) run as soon as Qt's modules come - in
    either order of the imports."""
    for first, then in (("import ui", "from PyQt6.QtWidgets import QLabel"),
                        ("from PyQt6.QtGui import QImage", "import ui"),
                        ("import ui", "from PyQt6.QtCore import QTimer\nfrom PyQt6.QtGui import QImage")):
        code = (f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n{first}\n{then}\n"
                "from ui import markup_guard\nimport core.qt_exit\n"
                "print(markup_guard._installed, core.qt_exit._installed)\n")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
        assert out.stdout.split() == ["True", "True"], (first, then, out.stderr[-500:])


# -- 8. formulas: what showed as written, a number gone, a brace's label read as a power --------------

@pytest.mark.parametrize("tex, shown", [
    (r"\overset{!}{=}", "= ^!"), (r"\underset{x}{\min}", "minₓ"), (r"\stackrel{def}{=}", "= ᵈᵉᶠ"),
    (r"a \not\in B", "a ∉ B"), (r"a \not= b", "a ≠ b"), (r"\phantom{x}a", "a"), (r"a \nmid b", "a ∤ b"),
    (r"\overbrace{a+b}^{2}", "(a+b)⏞[2]"), (r"\underbrace{x+y}_{2}", "(x+y)⏟[2]"),
    (r"\overbrace{a+b+c}^{\text{three}}", "(a+b+c)⏞[three]"),
    (r"\cfrac{1}{1+\cfrac{1}{1+x}}", "1/(1+1/(1+x))"),
    (r"\sum_{\substack{0<i<m \\ 0<j<n}} P(i,j)", "∑_(0<i<m, 0<j<n) P(i,j)"),
    (r"\begin{align} a &= 1 \tag{A} \\ b &= 2 \end{align}", "a = 1 \u2003(A)\nb = 2"),
    (r"x = 1 \tag{B}", "x = 1 \u2003(B)"), (r"E = mc^2 \label{eq:1}", "E = mc²"),
])
def test_sad_formulas_read_as_they_are_meant_in_text(tex, shown):
    """docs/math.md, math2.md, tag.md: these showed as written (\\cfrac, \\substack, \\overset, \\not, ...),
    \\tag raw in the terminal, \\overbrace{a+b}^{2} read "(a+b)²"."""
    from core import markdown_doc as MD

    assert MD.math_text(tex) == shown


def test_sad_a_rows_number_shows_beside_it_in_a_display():
    """tag.md: \\tag{A} in an align's row vanished in the viewer."""
    from ui import markdown_html as H

    laid = H.display_html(r"\begin{align} a &= 1 \tag{A} \\ b &= 2 \notag \end{align}", H.colours(False))
    assert re.sub(r"<[^>]+>", " ", laid).split()[1:] == ["a", "=", "1", "(A)", "b", "=", "2"]


def _foregrounds(view) -> dict[str, str]:
    """The text of each fragment of the page whose colour is not the text's own: {text: colour}."""
    document, out = view.browser.document(), {}

    def walk(frame_or_block):
        block = frame_or_block
        while block.isValid():
            pieces = block.begin()
            while not pieces.atEnd():
                fragment = pieces.fragment()
                brush = fragment.charFormat().foreground()
                if brush.style().value:
                    out[fragment.text()] = brush.color().name()
                pieces += 1
            block = block.next()

    walk(document.begin())
    return out


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_math_fence_and_a_formulas_colour_in_both_parsers(full):
    """Qt's own parser showed a ```math block as code, \\textcolor and {\\color …} not coloured."""
    view = _view("Before $\\textcolor{blue}{q} + {\\color{green} g}$ after.\n\n```math\n\\frac{1}{2}\n```\n", full)
    from core import markdown_doc as MD

    colours = _foregrounds(view)
    assert colours.get("q") == MD._COLOURS["blue"] and colours.get("g") == MD._COLOURS["green"], colours
    from ui import markdown_view as MV

    block = view.browser.document().begin()
    while block.isValid():
        assert not MV._is_code(block), block.text()
        block = block.next()


# -- 9. Qt's own parser's task list: no bullet beside its box ---------------------------------------

def _bulleted_tasks(view) -> list[str]:
    from PyQt6.QtGui import QTextFormat

    block, out = view.browser.document().begin(), []
    while block.isValid():
        if block.textList() and block.text()[:1] in "☐☑" \
                and not block.blockFormat().hasProperty(QTextFormat.Property.ListStyle):
            out.append(block.text())
        block = block.next()
    return out


def test_sad_a_task_keeps_no_bullet_when_its_part_is_made_whole_again():
    """docs/gfm.md (chk_bullet.py): a second pass of _list_items over a part cleared the task's
    "no bullet" (ListStyle 0) - a bullet stood beside the box."""
    from ui import markdown_view as MV

    view = _view("# Tasks\n\n- [ ] open\n- [x] done\n  - [ ] inner\n\nText.\n", False)
    assert not _bulleted_tasks(view)
    MV._list_items(view.browser.document(), 0, False, False)
    assert not _bulleted_tasks(view)


# -- 10. Copy: an item's number and bullet, a formula's number once ---------------------------------

COPIED = "# T\n\n1. first\n2. second\n   - inner\n- bullet\n- [ ] task\n\n$$x = 1 \\tag{B}$$\n\nAfter.\n"


@pytest.mark.parametrize("full", [True, False])
def test_sad_a_copy_holds_items_numbers_and_a_formulas_number_once(full):
    """copytest.py: list numbers and bullets were not copied; "\\tag{B}"'s "(B)" came again after the
    formula's TeX."""
    view = _view(COPIED, full)
    APP.clipboard().setText("EMPTY")
    view.browser.select_all()
    view.copy_selection()
    assert until(lambda: APP.clipboard().text() != "EMPTY", 30)
    copied = [line.rstrip() for line in APP.clipboard().text().splitlines() if line.strip()]
    assert copied == ["T", "1. first", "2. second", "  ◦ inner", "• bullet", "☐ task", "$$x = 1 \\tag{B}$$",
                      "After."], copied


# -- 11. a look-alike host in an autolink's text, an e-mail's, the mail question ---------------------

LOOK_ALIKES = "A www.pаypal.com and <me@pаypal.com> and me@pаypal.com, www.münchen.de.\n"


@pytest.mark.parametrize("full", [True, False])
def test_hostile_an_autolinks_text_shows_a_look_alike_host_in_punycode(full):
    """www.pаypal.com (a Cyrillic а) and e-mail autolinks showed the look-alike host as it is."""
    shown = _hrefs(_view(LOOK_ALIKES, full))
    assert shown and all("а" not in text for text, _href in shown), shown
    assert ("me@xn--pypal-4ve.com", "mailto:me@xn--pypal-4ve.com") in shown
    if full:
        assert ("www.xn--pypal-4ve.com", "http://www.xn--pypal-4ve.com") in shown
        assert ("www.münchen.de", "http://www.xn--mnchen-3ya.de") in shown  # (no look-alike: as it is)


def test_hostile_the_mail_question_names_the_domain_in_punycode():
    """The question before a mailto: link said "me@p%D0%B0ypal.com"."""
    from PyQt6.QtCore import QUrl

    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(LocalFS(), "")
    kind, where, _fragment = viewer.target_of(QUrl("mailto:me@pаypal.com"))
    assert (kind, where) == ("web", "mailto:me@xn--pypal-4ve.com")


def test_hostile_the_terminal_shows_a_look_alike_autolink_in_punycode():
    from core import markdown_term as MT

    shown = MT._strip_ansi(MT.render(LOOK_ALIKES, MT.Options(depth="none", hyperlinks=False)))
    assert "www.xn--pypal-4ve.com" in shown and "me@xn--pypal-4ve.com" in shown and "pаypal" not in shown


# -- 13. the terminal: two environments on lines of their own side by side --------------------------

def test_sad_the_terminal_sets_two_environments_on_two_lines_side_by_side():
    """A line end between two environments of one formula stacked them (a TeX line end is a space)."""
    from core import markdown_term as MT

    text = "$$\\begin{pmatrix} a \\\\ b \\end{pmatrix}\n\\begin{pmatrix} c \\\\ d \\end{pmatrix}$$\n"
    rows = [line.strip() for line in MT._strip_ansi(MT.render(text, MT.Options(depth="none"))).splitlines()
            if line.strip()]
    assert rows == ["⎛a⎞ ⎛c⎞", "⎝b⎠ ⎝d⎠"], rows
