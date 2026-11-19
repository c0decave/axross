"""Console: a pasted block of several statements runs; .save never replaces
a script whose name differs only in case.

Review 2026-11-19 (round 1):

* Pasting ``a = 1`` / ``b = 2`` / ``print(a + b)`` and pressing Enter gave
  "SyntaxError: multiple statements found while compiling a single
  statement" and ran nothing: the whole input went to ``runsource``, which
  compiles ONE interactive statement. docs/USAGE.md promises multi-line
  input, and SCRIPTING.md's examples are meant to be pasted. A complete
  input of several statements now runs one statement after the other,
  each as at the prompt (an expression shows its value); the first error
  stops the rest, as a script would.
* ``.save Backup`` with ``backup.py`` saved passed the "never replaced"
  check (it compared names case-sensitively); on macOS and Windows the
  save then replaced backup.py. The Scripts dock compares casefolded
  names; the console does now too.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import QMimeData  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import scripting  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def console(tmp_path, monkeypatch):
    from ui import repl_widget

    monkeypatch.setattr(repl_widget, "HISTORY_PATH", tmp_path / "cfg" / "repl_history")
    w = repl_widget.ReplWidget(startup_path=tmp_path / "no-startup.py")
    w.show()
    yield w
    w.deleteLater()
    APP.processEvents()


def paste_and_enter(w, text: str) -> str:
    before = len(w.toPlainText())
    mime = QMimeData()
    mime.setText(text)
    w.insertFromMimeData(mime)
    w._submit_current()
    APP.processEvents()
    return w.toPlainText()[before:]


def test_happy_a_pasted_list_of_statements_runs(console):
    out = paste_and_enter(console, "a = 1\nb = 2\nprint(a + b)")
    assert "SyntaxError" not in out
    assert console._globals["a"] == 1 and console._globals["b"] == 2
    assert "3" in out


def test_happy_a_pasted_block_and_a_statement_after_it_run(console):
    out = paste_and_enter(console, "total = 0\nfor i in range(4):\n    total += i\nprint('sum', total)")
    assert "sum 6" in out
    assert console._buffer == []  # a fresh prompt, no open block


def test_happy_expressions_in_a_paste_show_their_value(console):
    out = paste_and_enter(console, "x = 20\nx + 22")
    assert "42" in out


def test_sad_the_first_error_stops_the_rest_of_the_paste(console):
    out = paste_and_enter(console, "first = 1\nraise ValueError('stop here')\nsecond = 2")
    assert "ValueError: stop here" in out
    assert console._globals.get("first") == 1
    assert "second" not in console._globals


def test_edge_an_open_block_still_waits_for_more(console):
    paste_and_enter(console, "def f():")
    assert console._buffer  # the ... prompt
    console._replace_input("    return 5")
    console._submit_current()
    console._replace_input("")
    console._submit_current()
    assert console._globals["f"]() == 5


def test_sad_save_refuses_a_name_that_differs_only_in_case(console, monkeypatch):
    saved: list = []
    monkeypatch.setattr(scripting, "list_scripts", lambda: ["backup"])
    monkeypatch.setattr(scripting, "save_script", lambda *a, **k: saved.append(a))
    console._session_source.append("x = 1")
    console._replace_input(".save Backup")
    console._submit_current()
    assert saved == []
    assert "save refused" in console.toPlainText()
