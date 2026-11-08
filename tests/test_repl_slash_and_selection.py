"""The Console (ui.repl_widget): slash commands, .save, a script's
``__main__`` block, and edits over a selection.

What was wrong (review round 2):

* ``.load foo.py`` raised ValueError out of the key handler (only
  OSError was caught; bad bytes raised UnicodeDecodeError): the buffer
  was never cleared and no prompt came back - the console was wedged.
* ``.save`` dropped every submitted line that started with ".", also a
  continuation line of an open statement (a method chain's
  ``.upper())``); only a slash command at a fresh prompt is no Python.
* ``axross.run_script``, ``.run`` and Run in Console ran a script with
  ``__name__`` "__axross_script__" / "__axross_repl__": an
  ``if __name__ == "__main__":`` block did nothing, while --script, Run,
  the scheduler and script_run ran it.
* Ctrl+A (or a mouse selection from the scrollback) followed by typing,
  Backspace, Delete, Cut or Paste replaced the scrollback and the prompt:
  the edit guard looked at the cursor only, not at the selection's start.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QMimeData, Qt  # noqa: E402
from PyQt6.QtGui import QKeyEvent, QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import scripting  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def repl(monkeypatch):
    from ui import repl_widget

    tmp = Path(tempfile.mkdtemp(prefix="axross-repl-"))
    monkeypatch.setattr(repl_widget, "HISTORY_PATH", tmp / "history")
    widget = repl_widget.ReplWidget(startup_path=tmp / "no-startup.py")
    yield widget
    widget.deleteLater()
    APP.processEvents()


@pytest.fixture()
def saved():
    made: list[str] = []

    def _save(source: str) -> str:
        name = f"r_{uuid.uuid4().hex[:8]}"
        scripting.save_script(name, source)
        made.append(name)
        return name

    yield _save
    for name in made:
        scripting.delete_script(name)


def _type(w, line: str) -> None:
    w._replace_input(line)
    w._submit_current()


def _key(w, key, text: str = "", mods=Qt.KeyboardModifier.NoModifier) -> None:
    w.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, key, mods, text))


GUARDED = 'RAN = False\nif __name__ == "__main__":\n    RAN = True\n    FILE = __file__\n'


# -- .load -----------------------------------------------------------------------------------


def test_sad_load_with_a_py_suffix_shows_the_script_and_keeps_the_prompt(repl, saved):
    name = saved("value = 1\n")
    _type(repl, f".load {name}.py")
    assert repl._buffer == []
    assert f"--- {name} ---\nvalue = 1" in repl.toPlainText()
    assert repl.toPlainText().endswith(">>> ")
    _type(repl, "x = 41 + 1")
    assert repl._console.locals["x"] == 42


def test_sad_load_of_a_script_that_is_no_utf8_reports_and_keeps_the_prompt(repl, saved):
    name = saved("pass\n")
    Path(scripting.script_dir(), f"{name}.py").write_bytes(b"\xff\xfe\x00broken")
    _type(repl, f".load {name}")
    assert "load failed" in repl.toPlainText() and repl._buffer == []
    _type(repl, ".load bad/name")                                # ValueError: a refused name
    assert repl.toPlainText().count("load failed") == 2 and repl._buffer == []
    _type(repl, "y = 7")
    assert repl._console.locals["y"] == 7


# -- .save ------------------------------------------------------------------------------------


def test_sad_save_keeps_continuation_lines_that_start_with_a_dot(repl):
    name = f"chain_{uuid.uuid4().hex[:8]}"
    _type(repl, "s = ('a b'")
    _type(repl, "     .upper())")
    _type(repl, "")
    _type(repl, ".help")                                         # a slash command: not saved
    assert repl._console.locals["s"] == "A B"
    _type(repl, f".save {name}")
    try:
        src = scripting.load_script(name)
    finally:
        scripting.delete_script(name)
    assert src == "s = ('a b'\n     .upper())\n"


# -- a script's __main__ block ------------------------------------------------------------------


def test_sad_run_script_runs_the_main_block_with_the_scripts_path(saved):
    name = saved(GUARDED)
    ns = scripting.run_script(name)
    assert ns["RAN"] is True and ns["__name__"] == "__main__"
    assert ns["FILE"] == os.path.join(scripting.script_dir(), f"{name}.py")
    assert os.path.isfile(ns["FILE"])


def test_sad_dot_run_and_run_in_console_run_the_main_block(repl, saved):
    name = saved(GUARDED)
    _type(repl, f".run {name}")
    path = os.path.join(scripting.script_dir(), f"{name}.py")
    assert repl._console.locals["RAN"] is True and repl._console.locals["FILE"] == path
    assert "__file__" not in repl._console.locals              # the prompt has none afterwards
    repl._console.locals["RAN"] = False
    assert repl.run_saved_script(name) is True
    assert repl._console.locals["RAN"] is True


# -- edits over a selection -----------------------------------------------------------------


def _prepared(repl) -> str:
    _type(repl, "x = 5")
    repl._replace_input("abc")
    return repl.toPlainText()[: repl._input_start]


def _select_from(repl, anchor: int) -> None:
    c = repl.textCursor()
    c.setPosition(anchor)
    c.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
    repl.setTextCursor(c)


def test_sad_select_all_then_typing_keeps_the_scrollback_and_the_prompt(repl):
    scrollback = _prepared(repl)
    repl.selectAll()
    _key(repl, Qt.Key.Key_C, "", Qt.KeyboardModifier.ControlModifier)   # Copy keeps the selection
    assert repl.textCursor().selectionStart() == 0
    assert QApplication.clipboard().text().startswith("Axross embedded REPL")
    _key(repl, Qt.Key.Key_Z, "z")
    assert repl.toPlainText() == scrollback + "z"
    assert repl._current_input() == "z"
    _type(repl, "z = 9")
    assert repl._console.locals["z"] == 9


@pytest.mark.parametrize("key", [Qt.Key.Key_Backspace, Qt.Key.Key_Delete])
def test_sad_deleting_a_selection_from_the_scrollback_deletes_only_the_input(repl, key):
    scrollback = _prepared(repl)
    _select_from(repl, 5)
    _key(repl, key)
    assert repl.toPlainText() == scrollback
    assert repl._current_input() == ""


def test_sad_cut_and_paste_over_a_scrollback_selection_touch_only_the_input(repl):
    scrollback = _prepared(repl)
    _select_from(repl, 5)
    _key(repl, Qt.Key.Key_X, "", Qt.KeyboardModifier.ControlModifier)   # Cut
    assert repl.toPlainText() == scrollback
    assert QApplication.clipboard().text() == "abc"
    repl._replace_input("abc")
    _select_from(repl, 5)
    mime = QMimeData()
    mime.setText("q = 3")
    repl.insertFromMimeData(mime)                                        # menu Paste, middle click, drop
    assert repl.toPlainText() == scrollback + "q = 3"
    repl._submit_current()
    assert repl._console.locals["q"] == 3
