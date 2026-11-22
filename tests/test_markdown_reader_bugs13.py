"""The thirteenth round of the Markdown reader (the twelfth review): a
stabilisation round - guards that catch whole classes of faults for good,
then the faults they found. (G1) a page in parts with footnotes is the
page whole; (G2) what Copy puts on the clipboard is what the page shows;
(G3) no formula holds up the window, and known formulas keep their shape.
In both of Qt's paths and the terminal. Each test failed before.
"""

from __future__ import annotations

import os
import random
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_markdown_reader_bugs11 import close, opened, pump, settled, until  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


# -- (G1) parts with footnotes are the whole -------------------------------------------------------------

def noted(sections: int = 40) -> str:
    """Footnotes every way a text has them: defined right before a heading,
    a fence, a list item; longer than a part; referred to out of order and
    again; named in code (a span, an indented block) - no reference; defined
    inside a quote."""
    out = ["# Notes everywhere\n\n"]
    for n in range(sections):
        out.append(f"## Section {n}\n\nText of section {n} refers to a later note[^a{n + 1}] "
                   f"and its own[^a{n}], again[^a{n}], and an earlier one[^a{max(0, n - 3)}].\n\n")
        out.append(f"Code names `[^a{n}]` in a span.\n\n    indented code [^a{n}] {n}\n\n")
        if n % 7 == 3:
            out.append(f"A quoted note[^q{n}].\n\n> [^q{n}]: Quoted note {n}.\n\n")
        if n % 9 == 4:
            out.append(f"- an item refers[^l{n}]\n\n  [^l{n}]: A note in a list item {n}.\n\n")
        kind = n % 4
        if kind == 0:  # (right before the next heading - no blank line)
            out.append(f"[^a{n}]: Note {n}, before a heading.\n")
        elif kind == 1:  # (right before a fence)
            out.append(f"[^a{n}]: Note {n}, before a fence.\n```\nfenced {n}\n```\n\n")
        elif kind == 2:  # (right before a list item)
            out.append(f"[^a{n}]: Note {n}, before a list.\n- item {n} a\n- item {n} b\n\n")
        else:  # (longer than a part: paragraphs of its own)
            body = "".join(f"    Paragraph {k} of note {n}, indented: still the note.\n\n" for k in range(30))
            out.append(f"[^a{n}]: Note {n} begins, long.\n\n{body}")
    out.append(f"[^a{sections}]: The last note.\n")
    return "".join(out)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("cut", [20, 9])
def test_guard_a_page_in_parts_with_footnotes_is_the_page_whole(full, cut, monkeypatch, tmp_path):
    from tests.test_markdown_corpus import _laid_out

    path = tmp_path / "noted.md"
    path.write_text(noted(), encoding="utf-8")
    whole = _laid_out(path, full, monkeypatch, None)
    parts = _laid_out(path, full, monkeypatch, cut)
    differ = [(n, a, b) for n, (a, b) in enumerate(zip(whole, parts, strict=False)) if a != b]
    assert len(whole) == len(parts) and not differ, \
        f"{len(whole)} blocks whole, {len(parts)} in parts; first differences: {differ[:3]}"
    headings = [entry[0] for entry in parts if entry[1] == 2]
    assert headings == [f"Section {n}" for n in range(40)], headings[:5]  # (in their place, in order)


def test_guard_the_terminal_in_parts_with_footnotes_is_the_terminal_whole(monkeypatch):
    from core import markdown_doc as MD
    from core import markdown_term as T

    text = noted()
    options = T.Options(width=80, depth="none")
    whole = T.Renderer(options).render(MD.parse(text))
    for cut in (20, 7, 60):
        monkeypatch.setattr(T, "STREAM_CHARS", 0)
        monkeypatch.setattr(T, "STREAM_LINES", cut)
        parts = "".join(T.render_parts(text, options))
        if whole != parts:
            import difflib

            differ = list(difflib.unified_diff(whole.splitlines(), parts.splitlines(), lineterm="", n=1))
            pytest.fail(f"in parts of {cut} lines the terminal shows it otherwise:\n" + "\n".join(differ[:24]))


# -- (G2) Copy is what the page shows ----------------------------------------------------------------------

def rich(sections: int = 120) -> str:
    """A long page of everything a copy holds: math, tables, tasks, alerts,
    details, footnotes."""
    out = ["# Everything\n\n"]
    for n in range(sections):
        out.append(f"## Section {n}\n\nText {n} with **bold**, `code` and a note[^n{n}].\n\n")
        out.append(f"$$\n\\frac{{a_{n}}}{{b}} = \\begin{{pmatrix}} 1 & {n} \\\\ 0 & 1 \\end{{pmatrix}}\n$$\n\n")
        out.append(f"| col {n} | b |\n|---|---|\n| x{n} | y |\n\n- [x] done {n}\n- [ ] open {n}\n\n")
        out.append(f"> [!TIP]\n> Tip {n}.\n\n<details>\n<summary>More {n}</summary>\n\nInside {n}.\n\n</details>\n\n")
        out.append(f"[^n{n}]: Note number {n}.\n\n")
    return "".join(out)


def _normal(text: str) -> str:
    return re.sub(r"[\s\u00a0\u2028\u2029\u200b\ufeff]+", " ", text).strip()


def _copied(view, start: str | None, end: str | None) -> str:
    """What Copy puts on the clipboard for the selection from the word *start* to *end* (None: all)."""
    browser = view.browser
    document = browser.document()
    cursor = QTextCursor(document)
    if start is None:
        cursor.select(QTextCursor.SelectionType.Document)
    else:
        first, last = document.find(start), document.find(end)
        assert not first.isNull() and not last.isNull(), (start, end)
        cursor.setPosition(first.selectionStart())
        cursor.setPosition(last.selectionEnd(), QTextCursor.MoveMode.KeepAnchor)
    browser.setTextCursor(cursor)
    APP.clipboard().setText("OLD")
    view.copy_selection()
    assert until(lambda: APP.clipboard().text() != "OLD", 60), view.status.text()
    return APP.clipboard().text()


@pytest.fixture
def pieces(monkeypatch):
    """Parts and pieces small: a page of 120 sections in many, parsed one after another."""
    from core import markdown_term as T
    from ui import markdown_view as MV

    monkeypatch.setattr(MV, "EAGER_BLOCKS", 300)
    monkeypatch.setattr(T, "STREAM_CHARS", 15_000)
    monkeypatch.setattr(T, "STREAM_LINES", 150)


def _reference(full: bool, tmp_path, start, end) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    dialog = opened(full, tmp_path, rich())
    try:
        dialog.view.load_rest_now()
        pump(0.2)
        return _copied(dialog.view, start, end)
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
@pytest.mark.parametrize("when", ["parsing", "jumped", "settled"])
@pytest.mark.parametrize("run", [1, 2, 3])
def test_guard_select_all_copies_what_the_page_shows(full, when, run, pieces, tmp_path, monkeypatch):
    reference = _normal(_reference(full, tmp_path / "whole", None, None))
    assert "Section 119" in reference and "Note number 119" in reference
    (tmp_path / "page").mkdir()
    if when != "settled":  # (the pieces after the first parsed slowly: a copy while they come, spliced in)
        from ui import markdown_view as MV

        real = MV._page

        def slow(text, dark, toggled=frozenset(), first_details=0, notes=None):
            if first_details:
                time.sleep(0.15)
            return real(text, dark, toggled, first_details, notes)

        monkeypatch.setattr(MV, "_page", slow)
    dialog = opened(full, tmp_path / "page", rich())
    try:
        view = dialog.view
        if when == "jumped":
            view.clicked(QUrl("#section-90"))
            pump(0.2)  # (pieces still being parsed and spliced in)
        elif when == "settled":
            settled(view)
        copied = _normal(_copied(view, None, None))
        if copied != reference:
            at = next((n for n, (a, b) in enumerate(zip(copied, reference, strict=False)) if a != b),
                      min(len(copied), len(reference)))
            pytest.fail(f"{len(copied)} copied, {len(reference)} shown; first difference at {at}:\n"
                        f"copied: {copied[max(0, at - 80):at + 120]!r}\nshown:  {reference[max(0, at - 80):at + 120]!r}")
    finally:
        close(dialog)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_a_selection_across_gaps_copies_what_the_page_shows(full, pieces, tmp_path):
    reference = _normal(_reference(full, tmp_path / "whole", "Text 3 ", "Text 100 "))
    (tmp_path / "page").mkdir()
    dialog = opened(full, tmp_path / "page", rich())
    try:
        view = dialog.view
        view.clicked(QUrl("#section-100"))
        assert TB.until_within(until, lambda: not view.browser.document().find("Text 100 ").isNull(), 30)
        settled(view)
        assert view._gaps, "no gap"
        copied = _normal(_copied(view, "Text 3 ", "Text 100 "))
        assert copied == reference, (len(copied), len(reference), copied[:200], reference[:200])
    finally:
        close(dialog)


# -- (G3) no formula holds up the window; known ones keep their shape -------------------------------------

def _fuzz(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    atoms = ["x", "y_1", "a^2", r"\alpha", r"\frac{a}{b}", r"\sqrt{x}", "1", "+", "=", r"\sum_{k=1}^{n}",
             r"\int_0^1", r"\binom{n}{k}", r"\lim_{x\to 0}", "{", "}", r"\left(", r"\right)", r"\\", "&",
             r"\begin{pmatrix}", r"\end{pmatrix}", r"\begin{cases}", r"\end{cases}", r"\middle|", r"\hline",
             r"\tag{1}", r"\mathcal{O}", r"\underbrace{a}_{b}", "^", "_"]
    out = []
    for _round in range(count):
        out.append(" ".join(rng.choice(atoms) for _ in range(rng.randint(1, 60))))
    deep = r"\left( " * 600 + "x" + r" \right)" * 600  # (the twelfth review's: 19 s, 32 s)
    out += [deep, deep[:7000], "{" * 3000 + "x" + "}" * 3000, r"\frac{" * 300 + "x" + "}{y}" * 300,
            " ".join([r"\begin{pmatrix} a & b \\ c & d \end{pmatrix}"] * 150),
            r"\left( " * 400 + "x", "x" + r" \right)" * 400, (r"\sum_{i=1}^{n} " * 400) + "x"]
    return out


def test_guard_no_formula_takes_long_to_lay_out():
    from ui.markdown_html import colours, display_html

    palette = colours(False)
    slow = []
    for tex in _fuzz(13, 400):
        began = time.thread_time()
        display_html(tex, palette)
        took = time.thread_time() - began
        if took > 0.05:
            slow.append((round(took, 3), tex[:60]))
    TB.budget(not slow, slow[:5])  # (each formula's layout timed: a budget)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_guard_a_page_of_hostile_formulas_never_holds_up_the_window(full):
    from ui import markdown_view as MV

    formulas = _fuzz(7, 30)
    text = "".join(f"Formula {n}:\n\n$$\n{tex}\n$$\n\n" for n, tex in enumerate(formulas))
    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(900, 700)
    view.show()
    from tests.markdown_heartbeat import Heartbeat, assert_responsive


    heartbeat = Heartbeat(10)  # (the GUI thread's own time a turn - not the loaded machine's - and the gaps)
    began = time.monotonic()
    view.render(text)
    view.load_rest()
    assert until(lambda: view._readable and not view.more(), 120)
    _turn, gap = heartbeat.stop()
    beats = heartbeat.turns
    assert_responsive(gap, "the heartbeat's longest gap")
    TB.budget(time.monotonic() - began < 60, 'time.monotonic() - began < 60')
    TB.budget(max(beats) < 0.5, sorted(beats)[-5:])  # (one formula: 19 s, 32 s)
    assert "Formula 37" in view.browser.toPlainText()


#: Known formulas and the rows and cells their grids show (rows of a matrix's own table, its cells' text).
KNOWN = [
    (r"\begin{pmatrix} \begin{matrix} a & b \\ c & d \end{matrix} & e \\ f & g \end{pmatrix}",
     [["a b c d", "e"], ["f", "g"]]),
    (r"\begin{array}{c|c} a & b \\ \hline c & d \end{array}", [["a", "b"], ["c", "d"]]),
    (r"\begin{aligned} a &= b \\[4pt] c &= d \end{aligned}", [["a", "= b"], ["c", "= d"]]),
    (r"\begin{pmatrix} x_{1} & \frac{a}{b} \\ \{y\} & z \end{pmatrix}", [["x 1", "a b"], ["{ y }", "z"]]),
]


@pytest.mark.parametrize("tex, rows", KNOWN, ids=["matrix-in-matrix", "array-hline", "aligned-dim", "braces"])
def test_guard_known_formulas_keep_their_shape(tex, rows):
    from ui.markdown_html import _env_rows

    shown = [[re.sub(r"<[^>]*>|&#8203;", " ", cell).replace("&nbsp;", " ") for cell in row]
             for row in _env_rows(tex)]
    shown = [[re.sub(r"\s+", " ", cell).strip() for cell in row] for row in shown]
    assert shown == rows, shown
    from ui.markdown_html import colours, display_html

    page = display_html(tex, colours(False))
    assert "\\hline" not in page and "[4pt]" not in page and "\\middle" not in page
    if "hline" in tex:  # (a rule)
        assert "border-top: 1px solid" in page
    shown = display_html(r"\left( \frac{a}{b} \middle| c \right)", colours(False))
    assert "\\middle" not in shown and "|" in shown


# -- 10. look-alike hosts of Latin letters; a link's own address; one rule in the terminal -------------

def test_hostile_a_latin_look_alike_host_is_punycode():
    from core import markdown_doc as MD

    for url in ("http://ɡoogle.com/", "https://ʟogin.com/", "http://exampıe.com/"):
        assert "xn--" in MD.safe_host_url(url), url  # (U+0261, U+029F, a dotless ı: read as ASCII)
    assert MD.safe_host_url("https://münchen.de/") == "https://münchen.de/"


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_hostile_a_links_own_look_alike_address_goes_in_punycode(full):
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = view.full and full
    view.resize(600, 300)
    view.show()
    view.render("A [link](https://аррӏе.com/login) here.\n")
    until(lambda: view._readable and not view.more(), 10)
    hrefs, block = [], view.browser.document().begin()
    while block.isValid():
        pieces = block.begin()
        while not pieces.atEnd():
            if pieces.fragment().charFormat().anchorHref():
                hrefs.append(pieces.fragment().charFormat().anchorHref())
            pieces += 1
        block = block.next()
    assert hrefs and all("аррӏе" not in href for href in hrefs), hrefs
    assert any("xn--80ak6aa92e" in href for href in hrefs), hrefs


def test_typo_the_terminal_draws_one_rule_before_the_notes_of_a_text_ending_in_one():
    from core import markdown_term as T

    out = re.sub(r"\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\", "", T.render("Text[^1].\n\n---\n\n[^1]: The note.\n"))
    rules = [line for line in out.splitlines() if line.strip() and set(line.strip()) == {"─"}]
    assert len(rules) == 1, out
