"""The nineteenth round of the Markdown reader (the eighteenth review): a
formula of groups nested a thousand deep shown as written with a note, never
a blank page or a traceback; the terminal's long links in linear time; the
window's event loop never held by a worker; long task lists, short codes,
bare links, definitions and tables fast; the standalone app's light and dark
themes; HTML export's relative links; and the small things. Each test failed
before.
"""

from __future__ import annotations

import os
import subprocess
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

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _closed_after():
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    pump(0.05)


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


def _module(module) -> str:
    """The name *module* runs by with -m (axross's - or an export's, its imports renamed)."""
    return module.__name__


def _run(args: list[str], stdin: str | None = None, timeout: float = 120, env=None):
    return subprocess.run([sys.executable, *args], cwd=ROOT, input=stdin, capture_output=True, text=True,
                          timeout=timeout, env={**os.environ, **(env or {})})


# -- H1. a formula nested a thousand deep: as written, with a note ----------------------------------

DEEP_ROOTS = "# T\n\nIntro.\n\n$" + "\\sqrt{" * 1000 + "x" + "}" * 1000 + "$\n\nAfter.\n"

_NESTED = {
    "sqrt": lambda n: "\\sqrt{" * n + "x" + "}" * n,
    "frac": lambda n: "\\frac{" * n + "x" + "}{y}" * n,
    "power": lambda n: "x^{" * n + "y" + "}" * n,
    "overset": lambda n: "\\overset{a}{" * n + "x" + "}" * n,
    "text": lambda n: "\\text{" * n + "x" + "}" * n,
    "matrix": lambda n: "\\begin{matrix}" * n + "x" + "\\end{matrix}" * n,
    "left": lambda n: "\\left(" * n + "x" + "\\right)" * n,
    "frac-bare": lambda n: "\\frac1" * n + "2",
}


@pytest.mark.parametrize("depth", [1000, 3000, 10_000])
@pytest.mark.parametrize("kind", sorted(_NESTED))
def test_sad_a_formula_nested_thousands_deep_is_shown_without_an_error(kind, depth):
    """\\sqrt{ 1,000 deep went past Python's recursion limit (_braced read each group again for each one
    around it): a blank page, a traceback. Every nesting command, 1,000 to 10,000 deep: each step of the
    math - text, HTML, display, grid, the window's display layout - fast and without an error."""
    from core import markdown_doc as MD
    from ui import markdown_html as H

    tex = _NESTED[kind](depth)
    for step in (MD.math_text, MD.math_html, MD.math_display, MD.math_grid, H.display_items,
                 lambda t: H.display_html(t, H.LIGHT)):
        began = time.monotonic()
        step(tex)
        assert time.monotonic() - began < 2.0, (kind, depth, step)


def test_sad_braced_is_linear_and_capped():
    from core import markdown_doc as MD

    assert MD._braced("\\frac12 + \\sqrt[3]{\\frac ab} + \\vec v") == "\\frac{1}{2} + \\sqrt[3]{\\frac{a}{b}} + \\vec{v}"
    assert MD._braced("\\frac{\\frac12}3") == "\\frac{\\frac{1}{2}}{3}"
    deep = "\\sqrt{" * MD.MATH_DEPTH + "x" + "}" * MD.MATH_DEPTH
    assert MD._braced(deep) == deep
    with pytest.raises(MD.MathTooDeep):
        MD._braced("\\sqrt{" + deep + "}")
    began = time.monotonic()  # (before: each group read again for each one around it)
    MD._braced(("\\frac{a}{\\sqrt{b}} + " * 4000))
    assert time.monotonic() - began < 1.0


def test_sad_a_formula_deeper_than_the_cap_is_shown_as_written_with_a_note():
    from core import markdown_doc as MD

    tex = "\\sqrt{" * 1000 + "x" + "}" * 1000
    runs = MD.math_runs(tex)
    assert runs[0] == (tex, "unknown")
    assert "shown as written" in runs[-1][0] and str(MD.MATH_DEPTH) in runs[-1][0]
    assert MD.math_text(tex).startswith(tex)
    assert MD.math_text("\\sqrt{" * 3 + "x" + "}" * 3) == "√(√(√x))"  # (a formula within the cap: read)


def test_sad_any_fault_of_the_math_steps_shows_the_formula_as_written(monkeypatch):
    from core import markdown_doc as MD

    def broken(*_args):
        raise RuntimeError("a pass's fault")

    monkeypatch.setattr(MD, "_math", broken)
    monkeypatch.setattr(MD, "_display_grid", broken)
    runs = MD.math_runs("x^2")
    assert runs[0] == ("x^2", "unknown") and "shown as written" in runs[-1][0]
    assert MD.math_grid("\\frac{a}{b}") is None


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_the_deep_formula_page_keeps_its_outline_and_its_text(full):
    view = _view(DEEP_ROOTS, full)
    assert not view.status.text().startswith("Cannot render"), view.status.text()
    shown = view.browser.toPlainText()
    assert "Intro." in shown and "After." in shown and "\\sqrt{\\sqrt{" in shown
    if full:  # (Qt's own parser leaves a formula that long as written, its $ signs too)
        assert "shown as written" in shown and view.headings() == ["T"]


def test_sad_mdcat_and_html_export_show_the_deep_formula(tmp_path):
    source = tmp_path / "s.md"
    source.write_text(DEEP_ROOTS, encoding="utf-8")
    from core import markdown_cli
    from ui import markdown_app

    shown = _run(["-m", _module(markdown_cli), str(source)])
    assert shown.returncode == 0, shown.stderr[-2000:]
    assert "After." in shown.stdout and "shown as" in shown.stdout and "Traceback" not in shown.stderr
    page = _run(["-m", _module(markdown_app), "--html", str(source)])
    assert page.returncode == 0, page.stderr[-2000:]
    assert "After." in page.stdout and "shown as written" in page.stdout


def test_sad_a_render_fault_shows_the_page_as_written_in_every_view(monkeypatch, tmp_path):
    """A rule of the renderer that fails (as the deep formula's did): the page as written with a notice -
    in the window, the terminal and the exported page - not "Cannot render" and a blank page."""
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_html as H

    def broken(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    text = "# T\n\nIntro.\n\n$x$\n\nAfter.\n"
    monkeypatch.setattr(MD, "math_html", broken)
    monkeypatch.setattr(T, "_math_spans", broken)
    page = H.export_html(MD.parse(text))
    assert "After." in page and "as written" in page
    shown = T.render(text)
    assert "After." in shown and "as written" in shown
    view = _view(text, True)
    assert not view.status.text().startswith("Cannot render")
    assert "After." in view.browser.toPlainText()


# -- H2. a long link in the terminal: linear --------------------------------------------------------

def test_sad_mdcat_shows_a_link_of_a_megabyte_in_seconds():
    """safe_url went over all of the URL for each wrapped piece - and each piece carried all of it in its
    OSC 8 sequence: 100 KB took 52 s, 1 MB an hour. A link is checked once; one past HYPERLINK_CHARS is
    its text, not a hyperlink (terminals drop longer ones)."""
    from core import markdown_term as T

    url = "https://e.com/" + "a" * 1_000_000
    began = time.thread_time()  # (its own CPU time: by the clock a loaded machine took 3 s)
    shown = T.render(url + "\n", T.Options(width=80, depth="truecolor", hyperlinks=True))
    assert time.thread_time() - began < 2.0, time.thread_time() - began
    assert len(shown) < 3 * len(url) and shown.count("a") >= 1_000_000
    short = T.render("[e](https://e.com/x)\n", T.Options(hyperlinks=True))
    assert "\x1b]8;;https://e.com/x\x1b\\" in short  # (a link of a usual length: still a hyperlink)
    assert not T.safe_url("https://e.com/" + "a" * T.HYPERLINK_CHARS)
    assert not T.safe_url("https://e.com/a b") and not T.safe_url("javascript:alert(1)")


# -- M1, M2. the event loop never held by a worker, nor by a short text's parse --------------------

class _Gaps:
    """The longest pause of the event loop (a 5 ms timer's ticks) while it runs."""

    def __init__(self):
        from PyQt6.QtCore import QTimer

        self.last, self.longest = time.monotonic(), 0.0
        self.timer = QTimer()
        self.timer.setInterval(5)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def _tick(self):
        now = time.monotonic()
        self.longest = max(self.longest, now - self.last)
        self.last = now

    def stop(self) -> float:
        self.timer.stop()
        return self.longest


def _render_gaps(text: str) -> tuple[object, float]:
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    pump(0.2)
    gaps = _Gaps()
    pump(0.05)
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 180)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), 180)
    pump(0.5)
    return view, gaps.stop()


def test_sad_a_line_of_10_mb_never_holds_the_event_loop():
    """"word " 2,000,000 times: the worker's searches over all of the line (a bare link's, renderable's)
    held Python's lock - the GUI thread idle, its event loop held 1.7 s. Now a piece at a time."""
    view, longest = _render_gaps("word " * 2_000_000)
    assert "word word" in view.browser.document().begin().text()
    assert longest < 0.25, longest


def test_sad_a_short_text_of_brackets_inside_each_other_is_parsed_off_the_gui_thread():
    """"[" 5,000 deep around "~x~": 10 KB, parsed on the GUI thread - markdown-it reads nested brackets in
    time that grows with their square: the window held 1.1 s."""
    view, longest = _render_gaps("[" * 8000 + "~x~" + "]" * 8000)
    assert "x" in view.browser.toPlainText()
    assert longest < 0.25, longest


def test_sad_the_pieces_of_a_long_line_are_cut_where_a_word_begins():
    from core import markdown_doc as MD

    text = ("word " * 100_000) + "a" * 300_000 + " tail\n" + "short line\n" * 30_000
    cuts = list(MD._text_pieces(text))
    assert cuts[0][0] == 0 and cuts[-1][1] == len(text)
    assert all(a[1] == b[0] for a, b in zip(cuts, cuts[1:]))
    assert all(text[stop - 1] in " \n" and not text[stop].isspace() or text[stop - 1] == "\n"
               for _start, stop in cuts[:-1])
    assert max(stop - start for start, stop in cuts) <= 400_000  # (a run of 300,000 letters is never cut)
    assert MD.by_lines(lambda piece: piece.upper(), text) == text.upper()
    import re

    assert MD.found_by_lines(re.compile(r"(?<!\S)a{300000}"), text)
    assert not MD.found_by_lines(re.compile(r"(?<!\S)a{300001}"), text)
    assert MD.found_by_lines(re.compile(r"tail$", re.MULTILINE), text)


def test_sad_markdown_its_normalize_is_done_without_a_pass_over_the_text():
    import random

    from markdown_it.rules_core.normalize import normalize

    from core import markdown_doc as MD

    class State:
        def __init__(self, src):
            self.src = src

    rng = random.Random(3)
    for _ in range(500):
        src = "".join(rng.choice(["a", "\r", "\n", "\r\n", "\0", " ", "é"]) for _ in range(rng.randint(0, 20)))
        ours, theirs = State(src), State(src)
        MD._normalize(ours)
        normalize(theirs)
        assert ours.src == theirs.src, repr(src)
    assert "normalize" in [rule.name for rule in MD.make_parser().core.ruler.__rules__]


def test_sad_the_gui_thread_waits_for_pythons_lock_a_millisecond_at_most_once_a_worker_ran():
    from ui import markdown_view as MV

    before = sys.getswitchinterval()
    try:
        sys.setswitchinterval(0.005)
        done = []
        MV.in_background(lambda: 1, lambda result, error: done.append(result))
        assert until(lambda: done, 10)
        assert sys.getswitchinterval() <= MV.WORKER_SWITCH_SECONDS <= 0.001
    finally:
        sys.setswitchinterval(before)


# -- M3. long task lists, short codes, bare links, definitions, formulas, tables: fast ----------------

def test_sad_task_lists_find_their_list_in_one_pass():
    """mdit-py-plugins' task lists looked for each item's list back from the item, token by token: 50,000
    tasks in one part were minutes; in parts of 2,000, 2.3 s of a parse's 12."""
    from markdown_it import MarkdownIt
    from mdit_py_plugins.tasklists import tasklists_plugin

    from core import markdown_doc as MD

    md = MD.make_parser()
    began = time.monotonic()
    doc = MD.parse("- [ ] t\n" * 20_000, parser=md)
    assert time.monotonic() - began < 6.0
    assert sum(1 for t in doc.tokens if t.type == "list_item_open" and t.attrGet("class") == "task-list-item") \
        == 20_000
    theirs = MD.make_parser()  # (the plugin's own rule: the same page)
    plain = MarkdownIt("commonmark").use(tasklists_plugin)
    theirs.core.ruler.at("github-tasklists", next(r.fn for r in plain.core.ruler.__rules__
                                                  if r.name == "github-tasklists"))
    text = ("- [ ] a\n- [x] b\n  - [X] c\n  - d\n* [ ]\n  e\n1. [ ] f\n\n> - [ ] g\n\n- [x]h\n- [ ]  i\n"
            "  1. [ ] j\n     - [x] k\n")
    ours = md.renderer.render(MD.parse(text, parser=md).tokens, md.options, {})
    assert ours == theirs.renderer.render(MD.parse(text, parser=theirs).tokens, theirs.options, {})
    assert 'class="contains-task-list"' in ours and "checked" in ours


@pytest.mark.parametrize("name, text", [
    ("short codes", ":smile:\n" * 100_000),
    ("bare links", "".join(f"https://example.com/{n}\n" for n in range(50_000))),
    ("definitions", "".join(f"[r{n}]: https://example.com/{n}\n" for n in range(50_000)) + "\n[r7] and [R49999]\n"),
    ("tasks", "- [ ] t\n" * 50_000),
    ("display formulas", "".join("$$\n" + " + ".join("\\frac{a}{b}" for _ in range(200)) + "\n$$\n\n"
                                 for _ in range(200))),
])
def test_sad_a_long_text_of_one_kind_is_cut_in_parts_its_first_small(name, text):
    """100,000 short codes a line, 50,000 bare links, 50,000 definitions: one paragraph or one run of
    definitions was one part (15 to 19 s before the window showed any); 50,000 tasks in 400 KB, under
    STREAM_CHARS, one part; 200 display formulas of 200 fractions - 560 KB in 800 lines - one part. Every
    part had all 50,000 definitions after it."""
    from core import markdown_term as T

    parts = T.text_parts(text)
    assert len(parts) > 3, name
    assert len(parts[0]) <= T.STREAM_PART_CHARS + 20_000, (name, len(parts[0]))
    assert all(len(part) <= 2 * T.STREAM_PART_CHARS for part in parts), name


def test_sad_a_part_has_the_definitions_it_refers_to_only():
    from core import markdown_term as T

    text = ("".join(f"See [r{n}].\n\n" for n in range(3000)) + "Ref [Two  Words] and ![i][R5].\n\n"
            + "".join(f"[r{n}]: https://example.com/{n}\n" for n in range(3000)) + "[two words]: https://w.org\n")
    parts = T.text_parts(text, 500)
    assert "[r0]: https://example.com/0" in parts[0] and "[r2999]:" not in parts[0]
    assert len(parts[0]) < 30_000
    page = "".join(T.render_parts(text, T.Options(width=80, depth="none", hyperlinks=False)))
    assert "[r0]" not in page and "r2999" in page and "[Two  Words]" not in page


@pytest.mark.parametrize("name", ["definitions", "short codes"])
def test_sad_the_window_shows_the_first_part_of_a_long_text_of_one_kind_in_time(name):
    text = {"definitions": "".join(f"[r{n}]: https://example.com/{n}\n" for n in range(50_000)) + "\nEnd [r1].\n",
            "short codes": ":smile:\n" * 100_000}[name]
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.resize(1000, 800)
    view.show()
    began = time.monotonic()
    view.render(text)
    assert until(lambda: view._readable and view.markdown, 120)
    assert time.monotonic() - began < 1.5, time.monotonic() - began


def test_sad_mdcat_draws_a_table_of_100000_rows_as_it_goes_with_little_memory():
    """A table of 100,000 rows was one part: nothing for 46 s, 795 MB held. Now in parts of
    TABLE_PART_ROWS rows, drawn as one table (its columns from all of its rows)."""
    from core import markdown_term as T

    text = "| a | b | c |\n|---|---|---|\n" + "".join(f"| r{n} | {n * 7} | *text* {n} |\n" for n in range(100_000))
    options = T.Options(width=100, depth="none")
    began = time.monotonic()
    parts = T.render_parts(text, options)
    first = next(parts)
    assert time.monotonic() - began < 2.0
    assert first.startswith("┌") and "r0 " in first and "└" not in first
    rest = "".join(parts)
    assert rest.rstrip().endswith("┘") and rest.count("┌") == 0 and rest.count("╞") == 0
    lines = (first + rest).splitlines()
    assert len(lines) == 100_000 + 4 and len({len(line) for line in lines}) == 1  # (one table, one width)


@pytest.mark.parametrize("rows", [7, 30])
def test_sad_a_table_drawn_in_parts_is_the_table_drawn_whole(rows, monkeypatch):
    from core import markdown_term as T

    text = ("Before.\n\n| a | long heading | c |\n|:--|:--:|--:|\n"
            + "".join(f"| r{n} | x{n * n} | {'y' * (n % 9)} |\n" for n in range(rows)) + "\nAfter.\n")
    marked = text.replace("| x", "| [x").replace(" | y", "](https://e.com) | `y").replace("y |", "y` |")
    options = T.Options(width=60, depth="none")
    whole, whole_marked = T.render(text, options), T.render(marked, options)
    monkeypatch.setattr(T, "TABLE_PART_ROWS", 3)
    monkeypatch.setattr(T, "STREAM_CHARS", 0)
    monkeypatch.setattr(T, "STREAM_LINES", 5)
    assert T.render(text, options) == whole
    in_parts = T.render(marked, options)  # (links, code: its columns as wide as they need at least)
    assert len(in_parts.splitlines()) == len(whole_marked.splitlines())
    assert len({len(line) for line in in_parts.splitlines() if line and line[0] in "┌│└╞"}) == 1


def test_sad_mdcat_shows_a_table_of_more_than_64_columns_as_written():
    from core import markdown_term as T

    text = "|" + "|".join(f"c{n}" for n in range(80)) + "|\n|" + "---|" * 80 + "\n|" + "x|" * 80 + "\n"
    shown = T.render(text, T.Options(width=80, depth="none"))
    assert "|c0|c1|" in shown and "┌" not in shown and "more than 64 columns" in shown


def test_sad_mdcat_shows_a_line_of_10_mb_in_seconds_with_little_memory():
    """A paragraph of one line of 10 MB: all of its 2,000,000 words' spans held before its first line was
    written - 566 MB, 21.5 s. Its lines now go out as they are full, a line of plain text laid out at once."""
    import tracemalloc

    from core import markdown_term as T

    began = time.thread_time()  # (its own CPU time: on a loaded machine the wall time is twice that)
    shown = T.render("word " * 2_000_000, T.Options(width=100, depth="truecolor"))
    assert time.thread_time() - began < 4.0, time.thread_time() - began
    assert shown.count("\n") == 100_000 and shown.count("word") == 2_000_000
    tracemalloc.start()  # (2 MB of it: 115 MB held before)
    T.render("word " * 400_000, T.Options(width=100, depth="truecolor"))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 40_000_000, peak


def test_sad_a_run_of_plain_text_is_wrapped_as_word_by_word(monkeypatch):
    import random

    from core import markdown_term as T

    rng = random.Random(11)
    words = ["a", "bb", "a b c", "x" * 40, "  ", " ", "é", "日本", "\n", "`c  d`", "**b**", "[l](https://e.com)"]
    texts = ["".join(rng.choice(words) for _ in range(rng.randint(1, 60))) for _ in range(400)]
    options = [T.Options(width=w, depth="none") for w in (1, 7, 20, 33)]
    before = [T.render(text, o) for text in texts for o in options]
    monkeypatch.setattr(T, "RUN_CHARS", 3)
    assert [T.render(text, o) for text in texts for o in options] == before


# -- M4. the standalone app follows the desktop's light or dark scheme; View > Theme ---------------

@pytest.fixture
def _look(monkeypatch, tmp_path):
    """The application's look as it was after the test; a fresh home of the test's own."""
    from core import i18n

    style, palette, sheet = APP.style().name(), APP.palette(), APP.styleSheet()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(i18n, "SETTINGS_FILE", tmp_path / "axross" / "session.json")
    yield tmp_path
    APP.setStyle(style)
    APP.setPalette(palette)
    APP.setStyleSheet(sheet)
    APP.setProperty("axross_theme", None)


def _lightness() -> int:
    from PyQt6.QtGui import QPalette

    return APP.palette().color(QPalette.ColorRole.Window).lightness()


@pytest.mark.parametrize("scheme, light", [(None, True), ("light", True), ("dark", False)])
def test_sad_a_fresh_home_gets_the_desktops_scheme_light_when_unknown(scheme, light, _look, monkeypatch):
    """ui/standalone_app.py took prefs.theme or "classic": a fresh home was always dark."""
    from ui import standalone_app as SA
    from ui import themes

    monkeypatch.setattr(themes, "system_scheme", lambda: scheme)
    assert SA.apply_theme(APP, name="axross-markdown") == "modern"
    assert (_lightness() > 128) == light, _lightness()


def test_sad_view_theme_is_chosen_applied_and_kept_in_the_programs_own_settings(_look, monkeypatch):
    import json

    from ui import standalone_app as SA
    from ui import themes
    from ui.markdown_app import NAME, MarkdownApp

    monkeypatch.setattr(themes, "system_scheme", lambda: None)
    SA.apply_theme(APP, name=NAME)
    viewer = MarkdownApp().open_paths([""])[0]
    assert viewer.view_button is not None and viewer.view_button.text() == "&View"
    menu = viewer.view_button.menu()
    theme_menu = next(action.menu() for action in menu.actions() if action.menu() is not None)
    theme_menu.aboutToShow.emit()
    actions = {action.data(): action for action in theme_menu.actions()}
    assert set(actions) == {theme_id for theme_id, _label in themes.THEME_CHOICES}
    assert actions["modern"].isChecked()
    actions["modern-dark"].trigger()
    assert _lightness() < 100
    stored = json.loads(SA.settings_file(NAME).read_text(encoding="utf-8"))
    assert stored["theme"] == "modern-dark" and str(SA.settings_file(NAME)).startswith(str(_look))
    SA.apply_theme(APP, "modern", NAME)
    assert _lightness() > 128
    assert SA.apply_theme(APP, name=NAME) == "modern-dark"  # (a new start: the theme kept)
    theme_menu.aboutToShow.emit()
    assert next(a for a in theme_menu.actions() if a.data() == "modern-dark").isChecked()


def test_sad_modern_follows_the_desktop_when_it_turns_dark(_look, monkeypatch):
    from PyQt6.QtCore import Qt

    from ui import standalone_app as SA
    from ui import themes

    scheme = ["light"]
    monkeypatch.setattr(themes, "system_scheme", lambda: scheme[0])
    SA.apply_theme(APP, name="axross-markdown-test")
    SA.follow_system_scheme(APP, "axross-markdown-test")
    assert _lightness() > 128
    scheme[0] = "dark"
    try:
        APP.styleHints().colorSchemeChanged.emit(Qt.ColorScheme.Dark)
    except (AttributeError, TypeError):
        pytest.skip("Qt before 6.5: no colorSchemeChanged")
    assert _lightness() < 100


# -- the small things ------------------------------------------------------------------------------

def test_sad_html_export_keeps_relative_links_and_no_tex_marks():
    from core import markdown_doc as MD
    from ui import markdown_html as H

    text = ("# T\n\n[sib](other.md) [p](foo(and(bar))) [d](./x/y.md#z) [a](#t) [w](https://e.com) "
            "[j](javascript:alert(1)) [f](file:///etc/passwd) [h](//evil.example/x) [r](/etc/passwd)\n\n"
            "$$\n\\frac{a}{b}\n$$\n")
    page = H.export_html(MD.parse(text), title="t")
    for kept in ('href="other.md"', 'href="foo(and(bar))"', 'href="./x/y.md#z"', 'href="#t"', 'href="https://e.com"'):
        assert kept in page, kept
    for dropped in ("javascript", "file:", "evil.example", '"/etc/passwd"'):
        assert dropped not in page, dropped
    assert "axross-tex" not in page and "axross-itex" not in page
    qt_page = '<p><a name="axross-itex:eA==">x</a> <a href="notes.md">n</a> <a href="file:///x">f</a></p>'
    safe = H.safe_page(qt_page)
    assert "axross-itex" not in safe and 'href="notes.md"' in safe and "file:" not in safe


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_notes_way_back_after_its_code_block_is_in_the_note(full):
    """A note ending in a code block: its ↩ was a line of its own at the left, under the note's number."""
    from PyQt6.QtGui import QTextCursor

    text = "Text[^1].\n\n[^1]: Note.\n\n    ```\n    code\n    ```\n"
    view = _view(text, full)
    document = view.browser.document()
    found = document.find("↩")
    assert not found.isNull()
    note = document.find("Note.")

    def left(cursor) -> int:
        place = QTextCursor(cursor)
        place.setPosition(cursor.selectionStart())
        return view.browser.cursorRect(place).left()

    assert left(found) >= left(note) - 4, (left(found), left(note))  # (in the note: under its text, or after it)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_an_image_of_a_refused_address_is_a_box_not_its_bang(full):
    from core import markdown_term as T

    text = "A ![f](file:///etc/x.png) B ![g](data:text/html,x) C [j](javascript:x) D\n"
    shown = _view(text, full).browser.toPlainText()
    assert "!f" not in shown and "!g" not in shown and "j D" in shown
    terminal = T.render(text, T.Options(depth="none"))
    assert "!f" not in terminal and "🖼 f" in terminal and "🖼 g" in terminal


def test_sad_a_binary_file_is_said_to_be_one_not_shown_as_garbage(tmp_path):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    picture = tmp_path / "picture.md"
    picture.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)) * 20)
    viewer = MarkdownViewerDialog(LocalFS(), str(picture))
    viewer.show()
    assert until(lambda: viewer.view._readable and viewer.view.markdown, 30)
    shown = viewer.view.browser.toPlainText()
    assert "not a text file" in shown and "picture.md" in shown and "IHDR" not in shown
    from core import markdown_cli

    result = _run(["-m", _module(markdown_cli), str(picture)])
    assert result.returncode == 1 and "not a text file" in result.stderr and "IHDR" not in result.stdout
    from core import markdown_doc as MD

    assert not MD.looks_binary("# Héllo\n\tcolour \x1b[1m\n".encode("utf-8"))
    assert not MD.looks_binary("text".encode("utf-16"))  # (UTF-16 with its byte order mark: text)
    assert MD.looks_binary(b"\x7fELF\x02\x01\x01\x00")


@pytest.mark.parametrize("text", ["> quote\n\ntext\n", "| a | b |\n|---|---|\n| 1 | 2 |\n", "```\ncode\n```\n"])
def test_sad_a_copy_begins_with_its_text_not_an_empty_line(text):
    view = _view(text, True)
    view.browser.selectAll()
    view.copy_selection()
    pump(0.2)
    copied = APP.clipboard().text()
    assert copied and not copied.startswith("\n"), repr(copied)
    assert not view.browser.createMimeDataFromSelection().text().startswith("\n")


def test_sad_the_language_is_said_at_debug_not_at_every_start(caplog):
    import logging

    from core import i18n

    with caplog.at_level(logging.INFO, logger="core.i18n"):
        i18n.install("en")
    assert not [record for record in caplog.records if "translated strings" in record.getMessage()]


def test_sad_the_editor_window_names_the_program_it_is_part_of():
    from ui.editor_window import EditorWindow

    before = APP.applicationName()
    try:
        APP.setApplicationName("axross-markdown")
        assert EditorWindow().windowTitle().endswith("— axross-markdown")
        APP.setApplicationName("Axross")
        assert EditorWindow().windowTitle().endswith("— axross")
    finally:
        APP.setApplicationName(before)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_short_code_of_an_emoji_no_font_has_stays_as_written(full, monkeypatch):
    """Without a colour emoji font every short code was an empty box."""
    from core import markdown_doc as MD
    from ui import markdown_view as MV

    MV.emoji_fonts()
    assert MV._EMOJI_DRAWN  # (worked out once)
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [frozenset({"smile"})])
    shown = _view("Done :tada: and :smile:\n", full).browser.toPlainText()
    assert ":tada:" in shown and "😄" in shown
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [None])
    assert "🎉" in _view("Done :tada:\n", full).browser.toPlainText()
    assert MD.parse("Done :tada:\n").tokens[1].children[0].content == "Done 🎉"  # (the terminal, a browser)


# -- packaging: a one-file build draws its SVGs ------------------------------------------------------

def test_sad_an_svg_is_drawn_with_a_process_between_the_program_and_its_child():
    """A one-file build's --svg-worker child runs under the build's own bootloader, not under the
    program: the child's check of its parent refused it (exit 1) - no SVG of a frozen Linux build was
    drawn. A grandparent that is the program is the program."""
    if not sys.platform.startswith("linux"):
        pytest.skip("the parent check is Linux's")
    from core import svg_worker

    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><rect width="40" height="20"/></svg>'
    command = svg_worker.worker_argv(64)  # (python -I -c SOURCE pid cpu space edge options)
    result = subprocess.run(["/bin/sh", "-c", '"$@"; exit $?', "sh", *command], input=svg, capture_output=True,
                            timeout=60, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0 and result.stdout[:8] == b"\x89PNG\r\n\x1a\n", result.returncode
    stranger = command[:-5] + ["1"] + command[-4:]  # (a child whose program is gone: still refused)
    result = subprocess.run(["/bin/sh", "-c", '"$@"; exit $?', "sh", *stranger], input=svg, capture_output=True,
                            timeout=60, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 1


def test_sad_the_release_smoke_test_draws_an_svg_through_the_frozen_svg_worker():
    if not (ROOT / "scripts" / "standalone_repo").is_dir():
        pytest.skip("axross's templates of the exported tools: not in an export")
    workflow = (ROOT / "scripts" / "standalone_repo" / "axross-markdown" / ".github" / "workflows"
                / "release.yml").read_text(encoding="utf-8")
    smoke = workflow.split("- name: Smoke tests", 1)[1].split("\n    - name:", 1)[0]
    assert 'AXROSS_BUNDLE_SMOKE=1 "$bin" --script packaging/svg_check.py' in smoke and "svg drawn" in smoke
    check = ROOT / "scripts" / "standalone_repo" / "axross-markdown" / "packaging" / "svg_check.py"
    result = _run([str(check)], env={"PYTHONPATH": str(ROOT), "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0 and "svg drawn" in result.stdout, result.stderr[-2000:]
