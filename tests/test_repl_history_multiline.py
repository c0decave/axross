"""Console history: a pasted entry of several lines comes back whole.

Review 2026-11-20 (console round 2): ``_append_history`` wrote an entry of
several lines (a pasted block, a ``for`` with its body) as one line, the
line breaks turned into blanks. After a restart Up gave ``a = 1 b = 2``,
a SyntaxError, or a loop body glued to its header; and the compaction
every 200 entries wrote the same entry as several lines - each line its
own entry. Such an entry is stored as one JSON-quoted line now (marked,
so a plain line typed before is still read as it is) and comes back as
it was typed; single-line entries are stored as before.
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

APP = QApplication.instance() or QApplication([])

BLOCK = "a = 1\nb = 2\nprint(a + b)"


@pytest.fixture
def history(tmp_path, monkeypatch):
    from ui import repl_widget

    path = tmp_path / "cfg" / "repl_history"
    monkeypatch.setattr(repl_widget, "HISTORY_PATH", path)
    made = []

    def console():
        w = repl_widget.ReplWidget(startup_path=tmp_path / "no-startup.py")
        made.append(w)
        return w

    yield console, path
    for w in made:
        w.deleteLater()
    APP.processEvents()


def _paste_and_enter(w, text: str) -> None:
    mime = QMimeData()
    mime.setText(text)
    w.insertFromMimeData(mime)
    w._submit_current()


def test_sad_a_pasted_block_comes_back_whole_after_a_restart(history):
    console, _path = history
    first = console()
    _paste_and_enter(first, BLOCK)
    first._replace_input("x = 5")
    first._submit_current()
    second = console()
    assert second._history[-2:] == [BLOCK, "x = 5"]


def test_sad_the_compaction_keeps_a_block_one_entry(history, monkeypatch):
    from ui import repl_widget

    monkeypatch.setattr(repl_widget, "COMPACT_EVERY_N", 2)
    console, _path = history
    first = console()
    _paste_and_enter(first, BLOCK)
    first._replace_input("y = 1")
    first._submit_current()  # the second append compacts
    assert console()._history[-2:] == [BLOCK, "y = 1"]


def test_edge_a_line_separator_inside_an_entry_does_not_split_it(history):
    console, _path = history
    first = console()
    entry = 's = "a b\x0cc"'
    first._history.append(entry)
    first._append_history(entry)
    assert console()._history[-1] == entry


def test_happy_plain_lines_of_an_older_file_are_read_as_they_are(history):
    console, path = history
    path.parent.mkdir(parents=True)
    path.write_text('print("a\\nb")\n#axross-note\nz = 3\n', encoding="utf-8")
    assert console()._history == ['print("a\\nb")', "#axross-note", "z = 3"]


def test_edge_a_damaged_marked_line_is_kept_as_text(history):
    console, path = history
    path.parent.mkdir(parents=True)
    from ui import repl_widget

    bad = repl_widget.HISTORY_BLOCK_MARK + '"unterminated'
    path.write_text(bad + "\n", encoding="utf-8")
    assert console()._history == [bad]
