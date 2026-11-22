"""Review 24's systematic part: no freeze of the Markdown window survives a sweep of hostile texts.

Review 24 found the window frozen by a heading line of spaces (H1: a pattern quadratic in a run of them),
by fences never closed (H2: a pattern quadratic in their number) and by paragraphs never cut (H3) - each
a shape the stress tests before had not tried. Here the shapes are generated, not picked:

- **units:** every ASCII punctuation character and every Unicode space and format class (Zs, Zl, Zp, the
  C0 / C1 spaces, each block of Cf), as runs - at 200 KB and 2 MB a character of each class (class_units);
- **shapes:** at a line's start, after each block marker (``#``, ``>``, ``-``, ``+``, ``1.``, ``|``, a
  fence, an indent), inside emphasis, a link's text and address, a code span, and nested;
- **repetition:** one run on one line, runs of one or of 999 between letters on one line, and a short
  run on each of many lines;
- **sizes:** 2 KB, 30 KB, 200 KB and 2 MB;
- **both parsers** (markdown-it's page and Qt's own), each text through what the window does with it:
  open (and Ctrl+End, Ctrl+Home), the editor's preview (three pauses in the typing), Export PDF and
  Export HTML, Find (typed, then Enter twice) and a zoom followed by a scroll to the end.

Two things are measured for each: the GUI thread's longest heartbeat gap (tests/markdown_heartbeat.py:
what the user sees - the GUI thread's own wait for a CPU another job on the machine had left out) and the
longest time a worker held Python's lock as the GUI thread waited for it (HB.Heartbeat.blocked: asleep, not
on a CPU nor waiting for one). Over GAP (0.15 s on the machine the budgets were measured on), the case is
measured again and fails if it still is.

The run here takes a deterministic, representative subset (SUBSET: a fixed sample of the space plus the
review's own shapes) - quick enough for CI. ``AXROSS_FREEZE_SWEEP=full`` runs all of the space
(``AXROSS_FREEZE_SWEEP_SHARD=i/n`` a share of it; ``AXROSS_FREEZE_SWEEP_REPORT`` names a file for each
case's numbers, JSON lines); it takes hours.
"""

from __future__ import annotations

import functools
import gc
import json
import os
import random
import string
import sys
import threading
import time
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication, QProgressDialog  # noqa: E402

from tests import markdown_heartbeat as HB  # noqa: E402
from tests.test_markdown_reader_bugs11 import pump, until  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])

# -- the space -----------------------------------------------------------------------------------------------

#: The C0 and C1 controls Python and Unicode read as spaces (no category Zs of their own).
CONTROL_SPACES = "\t\x0b\x0c\x1c\x1d\x1e\x1f\x85"


@functools.lru_cache(maxsize=None)
def _category(name: str) -> tuple[str, ...]:
    return tuple(chr(point) for point in range(0x110000) if unicodedata.category(chr(point)) == name)


@functools.lru_cache(maxsize=1)
def format_classes() -> tuple[str, ...]:
    """One character of each block of Cf (format) characters: the first of each run of them - the Arabic
    number signs, the soft hyphen, the zero-width and direction marks, the bidi embeddings and isolates,
    the invisible operators, the byte order mark, the interlinear annotations, the tags..."""
    firsts, last = [], -2
    for ch in _category("Cf"):
        if ord(ch) != last + 1:
            firsts.append(ch)
        last = ord(ch)
    return tuple(firsts)


@functools.lru_cache(maxsize=1)
def units() -> tuple[str, ...]:
    """Every unit a run is made of: the ASCII punctuation, the spaces of each class (Zs, Zl, Zp, the
    control spaces) and a character of each block of format ones (Cf)."""
    spaces = [*_category("Zs"), *_category("Zl"), *_category("Zp"), *CONTROL_SPACES]
    return tuple(dict.fromkeys([*string.punctuation, *spaces, *format_classes()]))


#: Where a run stands: (before it, after it, what the text begins with).
SHAPES = {
    "line start": ("", "", ""),
    "between words": ("a ", " b", ""),
    "heading": ("# ", "", ""),
    "quote": ("> ", "", ""),
    "dash item": ("- ", "", ""),
    "plus item": ("+ ", "", ""),
    "ordered item": ("1. ", "", ""),
    "pipe": ("| ", " |", ""),
    "table cell": ("| ", " | b |", "| h | i |\n|---|---|\n"),
    "fence with a language": ("```py", "", ""),
    "code block": ("", "", "```\n"),
    "indent": ("    ", "", ""),
    "emphasis": ("*", "*", ""),
    "strong": ("**", "**", ""),
    "underscores": ("_", "_", ""),
    "link text": ("[", "](u)", ""),
    "link address": ("[a](", ")", ""),
    "code span": ("`", "`", ""),
    "nested": ("> - *[`", "`](u)*", ""),
    "after a block tag": ("", "", "<div>\n"),  # (an HTML block's lines: their Markdown escaped - review 25's R2)
    "after a lone tag": ("", "", "<span>\n"),
}
#: How a run is repeated: one run on one line; runs of one or of 999 between letters, on one line; a run of
#: three on each of many lines (each with a word).
MODES = ("one run", "runs of one", "runs of 999", "lines")
SIZES = (2_000, 30_000, 200_000, 2_000_000)
PARSERS = ("markdown-it", "md4c")
ACTIONS = ("open", "preview", "pdf", "html", "find", "zoom")


def document(unit: str, shape: str, mode: str, size: int) -> str:
    """The text of one case: *size* characters (about) of *unit* in *shape*, repeated as *mode* says."""
    before, after, head = SHAPES[shape]
    room = max(1, size - len(head) - len(before) - len(after))
    if mode == "one run":
        body = before + unit * (room // len(unit)) + after
    elif mode == "runs of one":
        body = before + ("a" + unit) * (room // (1 + len(unit))) + after
    elif mode == "runs of 999":
        body = before + ("a" + unit * 999) * max(1, room // (1 + 999 * len(unit))) + after
    else:
        line = before + unit * 3 + " word" + after + "\n"
        body = line * max(1, (size - len(head)) // len(line))
    return head + body


#: (space) from this size on the units are a class's each (class_units): the big texts take seconds each.
BIG = 200_000


@functools.lru_cache(maxsize=1)
def class_units() -> tuple[str, ...]:
    """The units of the big texts: every ASCII punctuation character, and a character of each Unicode
    space and format class - the no-break space (Zs), the Ogham space mark (Zs, the one a font draws), the
    line and paragraph separators (Zl, Zp), a tab (the control spaces), the zero-width space and the
    right-to-left mark's block (Cf)."""
    return tuple([*string.punctuation, "\xa0", "\u1680", "\u2028", "\u2029", "\t", "\u200b", "\u202a"])


def space(units_of=None, sizes=SIZES):
    """Every case of the space: (unit, shape, mode, size, parser) - every unit at the small sizes, a class's
    each at BIG and above."""
    for size in sizes:
        for unit in (units_of or (units() if size < BIG else class_units())):
            for shape in SHAPES:
                for mode in MODES:
                    for parser in PARSERS:
                        yield unit, shape, mode, size, parser


#: The review's own texts (H1-H3, M3-M5): the shapes that froze 0.16.10.
REVIEW = {
    "H1 a heading of spaced words": "# " + ("a" + " " * 999) * 30,
    "H1 a heading of tabbed words": "# " + ("a" + "\t" * 999) * 30,
    "H1 a heading of 400 KB": "# " + ("a" + " " * 999) * 400,
    "H2 fences never closed": "```py\n" * 4000,
    "H2 tilde fences never closed": "~~~x\n" * 30000,
    "H2 fences of 120 KB": "```py\n" * 20000,
    "H3 a paragraph after a space": " " + "word " * 400000,
    "H3 indented lines": "  word word word\n" * 120000,
    "H3 a hashtag paragraph": "#tag " + "word " * 400000,
    "H3 a shebang paragraph": "#!/bin/sh " + "a=b " * 400000,
    "H3 a run of #": "#" * 99000,
    "H3 # and a": ("#" + "a") * 49500,
    "H3 lines of +++": "+++\n" * 200000,
    "M5 a table of long cells": "| a | b |\n|---|---|\n" + ("| " + "w " * 900 + " | x |\n") * 300,
    "M5 lines of =": "=\n" * 300000,
    # (review 25: a block tag's long line - Qt's own parser's -, an HTML block of 2 MB - markdown-it's export)
    "R2 a block tag's line of 2 MB": "<div>\n" + "* " * 1000000,
    "R1 an HTML block of 2 MB": "<p>\n" + ("plain words here and there " * 4 + "\n") * 18000,
}


#: (subset) the shapes taken at each size: all of them at the small ones, a few drawn at the big ones.
SUBSET_SHAPES = {2_000: len(SHAPES), 30_000: len(SHAPES), 200_000: 6, 2_000_000: 3}


def subset() -> list[tuple]:
    """The run here: a fixed sample of the space (every shape at the small sizes, a few at the big ones,
    the units, modes and parsers drawn with the same seed every run - every mode and both parsers in it)
    and the review's texts, each in one of the parsers in turn - quick enough for CI."""
    chosen, draw = [], random.Random(24)
    order = list(units())
    draw.shuffle(order)
    picks = iter(order * 4)
    modes = iter(MODES * 40)
    for size in SIZES:
        shapes = list(SHAPES)
        draw.shuffle(shapes)
        for number, shape in enumerate(shapes[:SUBSET_SHAPES[size]]):
            chosen.append((next(picks), shape, next(modes), size, PARSERS[number % 2]))
    for number, name in enumerate(REVIEW):
        chosen.append((name, None, None, len(REVIEW[name]), PARSERS[number % 2]))
    return chosen


# -- what the window does with a text ---------------------------------------------------------------------------

def _settled() -> None:
    from PyQt6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    gc.collect()
    pump(0.02)


class _Measure:
    """The heartbeat from now to stop(): the GUI thread's longest gap and turn, and the longest time it was
    blocked - asleep on Python's lock a worker held (HB.Heartbeat.blocked)."""

    def __init__(self):
        self.beat = HB.Heartbeat()

    def stop(self) -> dict:
        turn, gap = self.beat.stop()
        return {"gap": round(gap, 4), "turn": round(turn, 4), "hold": round(max(0.0, self.beat.blocked), 4)}


def _readable(view, seconds: float = 300) -> None:
    until(lambda: view._readable and view.markdown, seconds)
    until(lambda: not view._scheduled and not view.status.text().startswith("Rendering"), seconds)


#: How long an export of a big text runs before it is cancelled (seconds; its making and first parts
#: measured - every part is like the others in a text of one shape repeated).
EXPORT_SECONDS = 2.5


def _cancel_exports(owner) -> None:
    for dialog in owner.findChildren(QProgressDialog):
        if not dialog.wasCanceled():
            dialog.cancel()


def run_case(text: str, full: bool, folder: Path, actions=ACTIONS) -> dict:
    """{action: {"gap", "turn", "hold"}} - *text* opened in the window (a real file) and the *actions* done."""
    from PyQt6.QtCore import QTimer

    from core import markdown_doc
    from core.local_fs import LocalFS
    from ui import markdown_view as MV
    from ui.markdown_viewer import MarkdownViewerDialog

    page = folder / "sweep.md"
    page.write_text(text, encoding="utf-8")
    available = markdown_doc.available
    if not full:
        markdown_doc.available = lambda: False
    out = {}
    viewer = preview = None
    try:
        _settled()
        measure = _Measure()
        viewer = MarkdownViewerDialog(LocalFS(), str(page))
        viewer.resize(1100, 800)
        viewer.show()
        _readable(viewer.view)
        viewer.view.go_end()  # (Ctrl+End, Ctrl+Home)
        until(lambda: not viewer.view._scheduled, 300)
        viewer.view.go_home()
        pump(0.02)
        out["open"] = measure.stop()
        if "find" in actions:  # (typed - found as typed -, then Enter twice; and a word not there)
            viewer._find_timer.setInterval(5)  # (the pause after typing: no matter here)
            measure = _Measure()
            viewer.find_field.setText(text.strip()[:6] or "zzz")
            until(lambda: not viewer._find_timer.isActive(), 10)
            pump(0.02)
            viewer.find_next()
            pump(0.02)
            viewer.find_next()
            viewer.find_field.setText("zebraquux")
            until(lambda: not viewer._find_timer.isActive(), 10)
            viewer.find_next()
            pump(0.02)
            out["find"] = measure.stop()
            viewer.find_field.setText("")
            until(lambda: not viewer._find_timer.isActive(), 10)
        if "zoom" in actions:  # (larger, then a scroll to the end)
            measure = _Measure()
            viewer.view.zoom_by(1)
            pump(0.02)
            until(lambda: viewer.view._readable and not viewer.view._scheduled, 300)
            bar = viewer.view.browser.verticalScrollBar()
            bar.setValue(bar.maximum())
            pump(0.05)
            until(lambda: not viewer.view._scheduled, 300)
            out["zoom"] = measure.stop()
        for action, export in (("pdf", viewer.export_pdf), ("html", viewer.export_html)):
            if action not in actions:  # (a big text's export cancelled after EXPORT_SECONDS: its parts are alike)
                continue
            measure = _Measure()
            stopper = QTimer()
            stopper.setSingleShot(True)
            stopper.timeout.connect(lambda: _cancel_exports(viewer))
            stopper.start(int(EXPORT_SECONDS * 1000))
            export(str(folder / f"sweep.{action}"))
            stopper.stop()
            out[action] = measure.stop()
            until(lambda: not any(thread.name == "markdown-view" for thread in threading.enumerate()), 60)
        viewer.close()
        viewer.deleteLater()
        viewer = None
        if "preview" in actions:  # (the editor's preview: the text typed, rendered at each pause)
            _settled()
            preview = MV.MarkdownView(None)
            preview.full = preview.full and full
            preview.resize(600, 800)
            preview.show()
            pump(0.02)
            measure = _Measure()
            for typed in ("", "x", "y")[:PREVIEW_PAUSES if len(text) < 1_000_000 else 1]:
                preview.timer.setInterval(5)
                preview.show_later(text + typed)
                until(lambda: not preview.timer.isActive(), 30)
                _readable(preview)
            pump(0.02)
            out["preview"] = measure.stop()
    finally:
        markdown_doc.available = available
        for widget in (viewer, preview):
            if widget is not None:
                widget.close()
                widget.deleteLater()
        _settled()
    return out


#: The pauses in the typing of the preview (one for a text of a megabyte or more: each is the same text again).
PREVIEW_PAUSES = 3


def worst(measured: dict) -> tuple[float, str]:
    """(the longest gap or hold of a case, where)."""
    return max(((max(numbers["gap"], numbers["hold"]), action) for action, numbers in measured.items()),
               default=(0.0, ""))


def _case_text(case) -> str:
    unit, shape, mode, size, _parser = case
    return REVIEW[unit] if shape is None else document(unit, shape, mode, size)


def _case_name(case) -> str:
    unit, shape, mode, size, parser = case
    if shape is None:
        return f"{unit} - {parser}"
    return f"U+{ord(unit):04X} {shape}, {mode}, {size:,} - {parser}"


def judged(case, folder: Path, actions=ACTIONS) -> dict:
    """The case run - and when its worst is over the budget, once more (alone in a turn of its own, the
    machine timed anew): the better of the two for each action."""
    text, full = _case_text(case), case[4] == "markdown-it"
    first = run_case(text, full, folder, actions)
    if worst(first)[0] < HB.gap_budget():
        return first
    HB._FACTOR.clear()
    again = run_case(text, full, folder, actions)
    return {action: min(first[action], again.get(action, first[action]), key=lambda n: max(n["gap"], n["hold"]))
            for action in first}


# -- the tests ----------------------------------------------------------------------------------------------------

def test_happy_the_space_holds_every_unit_shape_mode_size_and_parser():
    """The generator itself: every ASCII punctuation character, a space of each class and a format character
    of each block; each case's text about its size."""
    every = units()
    assert set(string.punctuation) <= set(every)
    assert {"\xa0", "\u3000", "\u2000", "\u2028", "\u2029", "\t", "\u200b", "\u202a", "\u2066", "\ufeff"} <= set(every)
    assert all(unicodedata.category(ch) in ("Zs", "Zl", "Zp", "Cf", "Cc") or ch in string.punctuation
               for ch in every)
    for case in [("*", "emphasis", "one run", 30_000, "md4c"), ("　", "heading", "lines", 2_000, "md4c"),
                 ("`", "nested", "runs of 999", 200_000, "markdown-it")]:
        text = _case_text(case)
        assert 0.5 * case[3] <= len(text) <= 1.1 * case[3] + 3000, (case, len(text))
    cases = subset()
    assert {case[1] for case in cases if case[1]} == set(SHAPES)
    assert {case[2] for case in cases if case[2]} == set(MODES)
    assert {case[3] for case in cases if case[1]} == set(SIZES)
    assert {case[4] for case in cases} == set(PARSERS)
    assert set(REVIEW) <= {case[0] for case in cases}
    assert len(set(cases)) == len(cases) == len(list(_cases(False)))
    every = list(space())
    small, big = sum(size < BIG for size in SIZES), sum(size >= BIG for size in SIZES)
    assert len(every) == (len(units()) * small + len(class_units()) * big) * len(SHAPES) * len(MODES) * len(PARSERS)
    assert set(class_units()) <= set(units())


def test_sad_the_heartbeat_sees_a_worker_holding_the_lock_not_the_gui_s_own_work():
    """HB.Heartbeat.blocked: a worker in one long search of a regular expression is a hold (the GUI thread
    asleep on the lock); the GUI thread's own long turn is not (the heartbeat's turn shows that)."""
    import re

    beat = HB.Heartbeat()
    worker = threading.Thread(target=lambda: re.search(r"(a+)+b", "a" * 23))
    worker.start()
    while worker.is_alive():
        pump(0.01)
    beat.stop()
    TB.budget(beat.blocked > 0.1, beat.blocked)
    beat = HB.Heartbeat()
    pump(0.02)
    began = time.thread_time()
    while time.thread_time() - began < 0.3:  # (the GUI thread's own turn)
        sum(range(1000))
    pump(0.02)
    beat.stop()
    TB.budget(beat.blocked < 0.1 and beat.turn > 0.25, (beat.blocked, beat.turn))


def _cases(full_sweep: bool) -> list:
    if not full_sweep:
        return subset()
    cases = list(space())
    cases += [(name, None, None, len(REVIEW[name]), parser) for name in REVIEW for parser in PARSERS]
    shard = os.environ.get("AXROSS_FREEZE_SWEEP_SHARD", "")
    if shard:
        index, count = (int(part) for part in shard.split("/"))
        cases = cases[index::count]
    return cases


FULL = os.environ.get("AXROSS_FREEZE_SWEEP", "") == "full"


@pytest.mark.parametrize("case", _cases(FULL), ids=_case_name)
def test_sad_no_text_of_the_sweep_freezes_the_window(case, tmp_path):
    """Before (0.16.10): a heading of spaced words 0.3 to 18 s (H1), fences never closed 1.6 to 64 s (H2),
    paragraphs after a space, of "#" or of "+++" 0.12 to 1.7 s (H3), Export HTML with Qt's own parser up
    to 2.2 s under load (M5). Now no gap and no hold of Python's lock over GAP (0.15 s here)."""
    measured = judged(case, tmp_path)
    report = os.environ.get("AXROSS_FREEZE_SWEEP_REPORT")
    if report:
        with open(report, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"case": _case_name(case), "measured": measured}) + "\n")
    longest, where = worst(measured)
    budget = HB.gap_budget()
    TB.budget(longest < budget, (_case_name(case), where, measured[where], f"at most {budget:.3f} s"))
