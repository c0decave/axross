"""The eighteenth round of the Markdown reader (the seventeenth review): a
parse that fails or runs past its time shows the text as written, never a
blank page or a hang; a scroll-bar step after Ctrl+End stays where it was
put; Export and Print of a big page whole and off the GUI thread; Find in
a folded <details>; wide tables; the terminal's mixed task lists; a
table's copy by rows; the status at 100 %. Each test failed before.
"""

from __future__ import annotations

import os
import random
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


def _view(text: str, full: bool, size=(1000, 800)):
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


# -- 1. a parse that fails or takes too long: the text as written, said ---------------------------

def test_sad_a_rule_that_raises_shows_the_text_as_written_with_a_notice(monkeypatch):
    """[~x~] raised in markdown-it 4.3: the page stayed blank. Any rule's error now gives the text as
    written, a notice above it."""
    from core import markdown_doc as MD

    md = MD.make_parser()

    def broken(state, silent):
        if state.src[state.pos] == "~":
            raise RuntimeError("inline rule didn't increment state.pos")
        return False

    md.inline.ruler.before("single_tilde", "broken", broken)
    doc = MD.parse("# Title\n\nSee [~approx~ value] here.\n", parser=md)
    assert doc.failed
    shown = [token.content for token in doc.tokens if token.type == "fence"]
    assert shown and "See [~approx~ value] here." in shown[0]
    from ui.markdown_html import to_html

    page = to_html(doc)
    assert "approx" in page and "as written" in page


def test_sad_a_rule_that_never_moves_on_cannot_hang_the_parse():
    """[~x~] hung for ever in markdown-it 4.2 (the released binaries): a rule that says yes in a link's
    label without moving on. The parse moves on itself."""
    from core import markdown_doc as MD

    md = MD.make_parser()

    def stuck(state, silent):
        return silent and state.src[state.pos] == "~"  # (yes, but state.pos not moved)

    md.inline.ruler.at("single_tilde", stuck)  # (as the rule was before the silent-mode fix)
    began = time.monotonic()
    doc = MD.parse("See [~approx~ value] here.\n", parser=md)
    assert time.monotonic() - began < 5
    assert "approx" in "".join(token.content for token in doc.tokens)


def test_sad_a_parse_past_its_time_shows_the_text_as_written(monkeypatch):
    from core import markdown_doc as MD

    monkeypatch.setattr(MD, "PARSE_SECONDS", 0.2)
    monkeypatch.setattr(MD, "PARSE_SECONDS_PER_CHAR", 0.0)
    md = MD.make_parser()

    def slow(state, silent):
        time.sleep(0.001)
        return False

    md.inline.ruler.before("strikethrough", "slow", slow)
    began = time.monotonic()
    doc = MD.parse("word " * 3000 + "\n\n" + "[a] " * 3000 + "\n", parser=md)
    assert time.monotonic() - began < 10
    assert doc.failed and "word word" in doc.tokens[-1].content


_PIECES = ["~", "~~", "[", "]", "(", ")", "$", "$$", "`", "``", "\\", "*", "_", "x", "a b", " ", "\n", "!", "<", ">",
           "|", "-", "1.", "#", ":", "^", "[^1]", "&"]


def test_guard_random_short_markdown_never_raises_or_hangs():
    """The review's fuzz found [~x~]: random short texts of ~ [ ] ( ) $ ` \\ and their neighbours -
    parsed, exported as HTML, drawn in the terminal and made for Qt's own parser - each fast and
    without an error, the text never lost."""
    from core import markdown_doc as MD
    from core import markdown_term as T
    from ui import markdown_view as MV
    from ui.markdown_html import export_html

    rng = random.Random(17)
    md = MD.make_parser()
    slowest = 0.0
    for _ in range(1500):
        text = "".join(rng.choice(_PIECES) for _ in range(rng.randint(1, 30)))
        began = time.monotonic()
        doc = MD.parse(text, parser=md)
        assert not doc.failed, repr(text)
        export_html(doc)
        T.render(text, T.Options(width=40))
        MV._md4c_page(MV.renderable(text)[0])
        slowest = max(slowest, time.monotonic() - began)
    assert slowest < 2.0, slowest


# -- 2. a scroll-bar move after Ctrl+End stays where it was put ------------------------------------

def _settled(view, seconds: float = 60.0) -> None:
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), seconds)
    pump(0.5)


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_scroll_bar_move_after_ctrl_end_stays_where_it_was_put(full):
    """big.md: Ctrl+End, then the bar set to the middle (a click in the trough, a step's drag) - the
    view snapped back to the end (456,671 -> 704,897 -> 913,342): the part laid out where it was put
    moved the view by its own height, then the next, ... The view stays in the middle."""
    from PyQt6.QtCore import QPoint

    text = "".join(f"## Section {n}\n\nSome words of section {n}, to fill a line or two of the page.\n\n"
                   for n in range(30_000))
    view = _view(text, full)
    view.go_end()
    _settled(view)
    bar = view.browser.verticalScrollBar()

    def shown() -> int:
        for y in range(5, 400, 10):
            line = view.browser.cursorForPosition(QPoint(5, y)).block().text()
            if "ection" in line:
                return int("".join(ch for ch in line.split("ection")[-1] if ch.isdigit()) or -1)
        return -1

    assert shown() > 29_000
    bar.setValue(bar.maximum() // 2)
    _settled(view)
    pump(1.0)
    _settled(view)
    assert abs(bar.value() / bar.maximum() - 0.5) < 0.1, (bar.value(), bar.maximum())
    assert 5_000 < shown() < 25_000, shown()  # (the parts' heights estimated: about the middle)


# -- 3, 4. Export and Print: the whole page, a part a turn, Cancel ---------------------------------

class _Turns:
    """The GUI thread's own time of each event-loop turn while it runs."""

    def __init__(self):
        from PyQt6.QtCore import QTimer

        self.turns, self._last = [], time.thread_time()
        self.timer = QTimer()
        self.timer.timeout.connect(self._beat)
        self.timer.start(5)

    def _beat(self):
        now = time.thread_time()
        self.turns.append(now - self._last)
        self._last = now

    def worst(self) -> float:
        self.timer.stop()
        return round(max(self.turns, default=0.0), 3)


def _viewer(tmp_path, text: str, full: bool = True):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "page.md"
    page.write_text(text, encoding="utf-8")
    dialog = MarkdownViewerDialog(LocalFS(), str(page))
    if not full:
        dialog.view.full = False
        dialog.view.render(text)
    dialog.resize(1000, 800)
    dialog.show()
    assert until(lambda: dialog.view._readable and dialog.view.markdown, 120)
    return dialog


def _pdf_text(path) -> list[str]:
    QtPdf = pytest.importorskip("PyQt6.QtPdf")
    document = QtPdf.QPdfDocument(None)
    document.load(str(path))
    return [document.getAllText(page).text() for page in range(document.pageCount())]


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_pdf_of_a_big_page_is_whole(full, tmp_path, monkeypatch):
    """big.md (613 pages): the PDF lost its last pages without a word - the page as one document went
    past Qt's layout's reach (8,388,607 of the device's units; here at 9,600 dots an inch to come there
    at about 75 pages, not 600)."""
    from PyQt6 import QtGui

    class Fine(QtGui.QPdfWriter):
        def __init__(self, *args):
            super().__init__(*args)
            self.setResolution(9600)

    monkeypatch.setattr(QtGui, "QPdfWriter", Fine)
    text = "".join(f"## Section {n}\n\nThe words of section {n}.\n\n" for n in range(3000)) + "ZZUNIQUEEND\n"
    dialog = _viewer(tmp_path, text, full)
    target = tmp_path / "page.pdf"
    assert dialog.export_pdf(str(target)) == str(target)
    pages = _pdf_text(target)
    assert len(pages) > 100 and "ZZUNIQUEEND" in pages[-1], (len(pages), pages[-1][-200:])
    assert "Section 1500" in "".join(pages)


@pytest.mark.parametrize("kind", ["pdf", "html"])
def test_sad_export_holds_up_the_window_no_longer(kind, tmp_path):
    """A paragraph of 3,000 formulas: its PDF held the window 10.9 s (Qt laid the paragraph out in time
    growing with its square), big.md's HTML 3.2 s, manymath.md's PDF did not finish in 13 minutes. The
    page is made on a worker thread and laid out a part a turn (the paragraph in pieces)."""
    text = "# Formulas\n\n" + " ".join(f"word{n} $x_{{{n}}}^2$" for n in range(3000)) + "\n\n" + \
        "".join(f"Paragraph {n} of some length to fill the page.\n\n" for n in range(4000 if kind == "pdf" else 30_000))
    dialog = _viewer(tmp_path, text)
    target = tmp_path / f"page.{kind}"
    turns = _Turns()
    began = time.monotonic()
    made = dialog.export_pdf(str(target)) if kind == "pdf" else dialog.export_html(str(target))
    took = time.monotonic() - began
    pump(0.05)  # (the turn the export ran in, if it ran in one, measured)
    worst = turns.worst()
    assert made == str(target) and target.stat().st_size > 1000
    assert worst < 0.5, (worst, took)
    assert took < 60, took


def test_sad_an_export_can_be_cancelled(tmp_path):
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QProgressDialog

    text = "".join(f"Paragraph {n} of some length to fill the page.\n\n" for n in range(40_000))
    dialog = _viewer(tmp_path, text)
    target = tmp_path / "page.pdf"

    def cancel():
        shown = [child for child in dialog.findChildren(QProgressDialog) if child.maximum() > 0]
        if shown:  # (the parts being laid out: Cancel)
            shown[0].cancel()
        else:
            QTimer.singleShot(20, cancel)

    QTimer.singleShot(20, cancel)
    assert dialog.export_pdf(str(target)) == ""
    assert not target.exists() and "cancelled" in dialog.view.status.text()


# -- 5. Find goes into a folded <details> in the page's order --------------------------------------

_FOLDED = ("# Find test\n\nalpha one\n\n<details><summary>Folded</summary>\n\nalpha hidden inside details\n\n"
           "</details>\n\n| alpha | in table |\n|---|---|\n| x | alpha cell |\n\nFinal alpha.\n")


@pytest.mark.parametrize("backward", [False, True], ids=["forward", "backward"])
def test_sad_find_goes_into_a_folded_details_in_the_pages_order(backward, tmp_path):
    """t/find.md: the match in a folded <details> was skipped whenever the page had another one ("of 9",
    the tenth in the fold) - found only when nothing else matched. It comes in its place now, the fold
    opened, and counts."""
    dialog = _viewer(tmp_path, _FOLDED)
    until(lambda: not dialog.view._scheduled, 30)
    dialog.find_field.setText("alpha")
    pump(0.5)
    seen = []
    for _ in range(5):
        dialog.find_next(backward=backward)
        pump(0.4)
        until(lambda: not dialog.view._scheduled and not dialog.view.status.text().startswith("Rendering"), 20)
        pump(0.2)
        seen.append((dialog.view.browser.textCursor().block().text().strip(), dialog.find_count.text()))
    blocks = [block for block, _count in seen]
    assert "alpha hidden inside details" in blocks, seen
    assert all(count.endswith("of 5") for _block, count in seen), seen
    order = ["alpha one", "alpha hidden inside details", "alpha", "alpha cell", "Final alpha."]
    if backward:
        assert blocks.index("alpha hidden inside details") == blocks.index("alpha one") - 1, seen
    else:
        assert blocks.index("alpha hidden inside details") == blocks.index("alpha") - 1, seen
    assert set(blocks) == set(order), seen


# -- 7. the terminal: an ordered list with task items counts on ------------------------------------

def test_sad_the_terminal_numbers_an_ordered_list_with_task_items():
    """t/olist.md: "1. [ ] a / 2. [x] b / 3. c" printed "☐ a / ☑ b / 1. c" - the tasks lost their numbers
    and the count began again."""
    from core import markdown_term as T

    shown = T._strip_ansi(T.render("1. [ ] a\n2. [x] b\n3. c\n4. d\n", T.Options(depth="none", width=40)))
    lines = [line.strip() for line in shown.splitlines() if line.strip()]
    assert lines == ["1. ☐ a", "2. ☑ b", "3. c", "4. d"], lines


# -- 9. the status at the end: never "100 % - the rest as you scroll on" ---------------------------

def test_sad_the_status_never_says_all_shown_and_more_to_come():
    """t/longlist.md: Ctrl+End, then scrolled up until all of it was laid out - "Shown: 100% of the page
    - the rest as you scroll on". 100 % is never said while parts are not laid out, and nothing of the
    rest once all is."""
    text = "# List\n\n" + "".join(f"1. item number {n} with some words\n" for n in range(40_000))
    view = _view(text, True)
    view.go_end()
    _settled(view, 30)
    bar = view.browser.verticalScrollBar()
    said = set()
    for _round in range(3000):
        if not view.more():
            break
        bar.setValue(max(0, bar.value() - 3 * bar.pageStep()))
        pump(0.03)
        said.add(view.status.text())
        if bar.value() == 0:
            view.load_rest_now()
    _settled(view, 30)
    said.add(view.status.text())
    assert not view.more()
    assert not any("100" in line and "scroll on" in line for line in said), [line for line in said if "100" in line]
    assert "scroll on" not in view.status.text(), view.status.text()


# -- 8. a table's copy by rows; no spaces after a list item's text ---------------------------------

def _copied(view) -> str:
    APP.clipboard().setText("EMPTY")
    view.browser.select_all()
    view.copy_selection()
    assert until(lambda: APP.clipboard().text() != "EMPTY", 60)
    return APP.clipboard().text()


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_tables_copy_is_a_row_a_line_its_cells_apart_by_tabs(full):
    """t/copy1.md: a table copied a cell a line ("h1", "h2", "x", "$y^2$"); a list item's line ended in a
    space ("3. c ")."""
    text = "1. a\n2. c\n   - nested *em*\n\n| h1 | h2 |\n|----|---:|\n| x  | $y^2$ |\n| more | cells |\n\n> quote\n"
    copied = _copied(_view(text, full))
    lines = copied.splitlines()
    assert "h1\th2" in lines and "x\t$y^2$" in lines and "more\tcells" in lines, lines
    assert not any(line.endswith(" ") for line in lines), [line for line in lines if line.endswith(" ")]
    assert "quote" in lines


# -- 6. a wide table: as wide as its words need, past the text, scrolled sideways ------------------

@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_a_wide_tables_words_are_never_broken_and_it_uses_the_window(full):
    """t/wide.md at 1,700 pixels: 14 columns of identifiers squeezed into the text's 630 pixels, broken a
    few letters a line ("val|ue_|0_0|_lo"), 420 pixels of the window empty beside them."""
    from ui import markdown_view as MV

    header = "| " + " | ".join(f"Column{n}" for n in range(14)) + " |\n|" + "---|" * 14 + "\n"
    rows = "".join("| " + " | ".join(f"`value_{r}_{c}_long_identifier`" for c in range(14)) + " |\n"
                   for r in range(4))
    view = _view("# Wide\n\n" + header + rows + "\nAfter the table.\n", full, size=(1700, 700))
    pump(0.5)
    document = view.browser.document()
    block, broken = document.begin(), []
    while block.isValid():
        if "_long_identifier" in block.text() and block.layout().lineCount() > 1:
            broken.append(block.text())
        block = block.next()
    assert not broken, broken[:3]
    assert view.browser.margins()[2] <= MV.GUTTER + 2, view.browser.margins()
    assert view.browser.horizontalScrollBar().maximum() > 0


# -- 10. a system library Qt needs missing: said, no traceback --------------------------------------

def test_sad_a_missing_system_library_is_named_with_its_package(monkeypatch, capsys):
    """The Linux binary on a host without libEGL.so.1 ended in PyInstaller's raw traceback."""
    from ui import markdown_app as A

    def missing(*_args, **_kwargs):
        raise ImportError("libEGL.so.1: cannot open shared object file: No such file or directory")

    monkeypatch.setattr(A, "run", missing)
    assert A.main(["axross-markdown", "page.md"]) == 1
    said = capsys.readouterr().err
    assert "libEGL.so.1" in said and "libegl1" in said and "Traceback" not in said, said
    assert "--term" in said  # (what works without it)


# -- 11. nits: \pmod's one-sign argument, a Latin-1 file ---------------------------------------------

def test_sad_pmod_without_braces_is_read():
    from core import markdown_doc as MD

    assert "(mod p)" in MD.math_text("x \\pmod p")


def test_sad_a_latin1_file_reads_as_latin1_a_utf8_file_as_utf8():
    """A Latin-1 (or Windows-1252) file showed U+FFFD for every accented letter; one damaged byte in a
    UTF-8 file, or one cut at the read limit, keeps the rest UTF-8."""
    from core import markdown_doc as MD

    assert MD.decode_text("Größe, café, “quoted”\n".encode("cp1252")) == "Größe, café, “quoted”\n"
    assert MD.decode_text("Größe à la carte\n".encode("latin-1")) == "Größe à la carte\n"
    utf8 = "Größe café ".encode() * 20
    assert MD.decode_text(utf8 + b"\xff" + utf8).count("\ufffd") == 1
    assert MD.decode_text(utf8 + "é".encode()[:1]) == "Größe café " * 20  # (cut inside its last letter)
