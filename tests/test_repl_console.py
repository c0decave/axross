"""The Python console (View > Panels > Console) end to end: typed into
the real widget with QTest - statements, blocks, errors, history, Tab
completion and the slash commands that save, load, run and delete scripts.

ui/repl_widget.py was at 59 % of its branches (docs/TEST_COVERAGE_MATRIX.md
of 2026-10-26); the slash commands were tested on a bare object with
save_script mocked, history and the keys not at all.

Bugs found while writing it:

* ``.save <name>`` replaced a saved script of that name without a word - a
  script written in the Scripts dock was gone after a ``.save`` of a few
  console lines. It now refuses and says how to replace it (``.delete``
  first).
* Tab with several matches printed them and the typed text again - as
  output: Enter then submitted nothing of it ("axross.list_" Tab, then
  "scripts()" Enter ran ``scripts()``, a NameError). The text is input
  again.
* ``.delete`` of a script that does not exist said "deleted".
* ``.help`` said ``.load`` pastes into the prompt and ``.open`` opens a
  file manager; both print (as docs/SCRIPTING.md says), and so does the
  help now (docs/USAGE.md too).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import scripting  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def history(tmp_path, monkeypatch):
    from ui import repl_widget

    path = tmp_path / "cfg" / "repl_history"
    monkeypatch.setattr(repl_widget, "HISTORY_PATH", path)
    return path


@pytest.fixture
def console(history, tmp_path):
    from ui import repl_widget

    w = repl_widget.ReplWidget(startup_path=tmp_path / "no-startup.py")
    w.show()
    w.setFocus()
    yield w
    w.deleteLater()
    APP.processEvents()


@pytest.fixture
def name():
    made = f"t_{uuid.uuid4().hex[:8]}"
    yield made
    try:
        scripting.delete_script(made)
    except (OSError, ValueError):
        pass


def enter(w, line: str) -> str:
    """Type *line*, press Enter; the console text that came after it."""
    before = len(w.toPlainText())
    QTest.keyClicks(w, line)
    QTest.keyClick(w, Qt.Key.Key_Return)
    APP.processEvents()
    return w.toPlainText()[before:]


def current(w) -> str:
    return w._current_input()


# ------------------------------------------------------------------ happy
def test_happy_e2e_statements_share_one_namespace(console):
    enter(console, "x = 6 * 7")
    assert "42" in enter(console, "print(x)")
    assert "84" in enter(console, "x * 2")


def test_happy_a_block_runs_after_its_empty_line(console):
    assert "..." in enter(console, "def twice(v):")
    enter(console, "    return v * 2")
    enter(console, "")
    assert "10" in enter(console, "twice(5)")


def test_happy_up_and_down_walk_the_history(console, history):
    enter(console, "a = 1")
    enter(console, "b = 2")
    QTest.keyClick(console, Qt.Key.Key_Up)
    assert current(console) == "b = 2"
    QTest.keyClick(console, Qt.Key.Key_Up)
    QTest.keyClick(console, Qt.Key.Key_Up)  # stays at the oldest
    assert current(console) == "a = 1"
    QTest.keyClick(console, Qt.Key.Key_Down)
    assert current(console) == "b = 2"
    QTest.keyClick(console, Qt.Key.Key_Down)
    assert current(console) == ""
    assert history.read_text().splitlines()[-2:] == ["a = 1", "b = 2"]
    assert (history.stat().st_mode & 0o777) == 0o600


def test_happy_tab_completes_a_unique_name_and_lists_several(console):
    QTest.keyClicks(console, "axross.list_scr")
    QTest.keyClick(console, Qt.Key.Key_Tab)
    assert current(console) == "axross.list_scripts"
    console._replace_input("")
    QTest.keyClicks(console, "axross.list_")
    QTest.keyClick(console, Qt.Key.Key_Tab)
    text = console.toPlainText()
    assert "axross.list_scripts" in text and "axross.list_trails" in text
    assert current(console) == "axross.list_"
    out = enter(console, "scripts()")  # goes on from what was typed
    assert "NameError" not in out and "[" in out


def test_happy_e2e_save_scripts_load_run_delete(console, name):
    enter(console, "greeting = 'hi from the console'")
    enter(console, "print(greeting)")
    out = enter(console, f".save {name}")
    assert "saved" in out
    assert scripting.load_script(name) == "greeting = 'hi from the console'\nprint(greeting)\n"
    assert name in enter(console, ".scripts")
    assert "print(greeting)" in enter(console, f".load {name}")
    enter(console, "greeting = 'changed'")
    assert "hi from the console" in enter(console, f".run {name}")
    assert f"deleted {name}" in enter(console, f".delete {name}")
    assert name not in scripting.list_scripts()


def test_happy_help_says_what_each_command_does(console):
    out = enter(console, ".help")
    assert ".load <name>                show a saved script" in out
    assert ".open                       print the script folder" in out


# -------------------------------------------------------------------- sad
def test_sad_an_error_shows_the_traceback_and_the_console_goes_on(console):
    out = enter(console, "1 / 0")
    assert "ZeroDivisionError" in out
    assert "3" in enter(console, "1 + 2")


def test_sad_save_never_replaces_an_existing_script(console, name):
    scripting.save_script(name, "important = True\n")
    enter(console, "scratch = 1")
    out = enter(console, f".save {name}")
    assert "exists" in out and f".delete {name}" in out
    assert scripting.load_script(name) == "important = True\n"


def test_sad_save_before_any_python_saves_nothing(console, name):
    assert "nothing to save" in enter(console, f".save {name}")
    assert name not in scripting.list_scripts()


@pytest.mark.parametrize("bad", ["../escape", "with/slash", ".hidden"])
def test_sad_an_unsafe_script_name_is_refused(console, bad):
    enter(console, "v = 1")
    assert "save failed" in enter(console, f".save {bad}")


@pytest.mark.parametrize("command", [".load", ".run", ".delete"])
def test_sad_a_missing_script_is_reported(console, command):
    out = enter(console, f"{command} t_does_not_exist")
    assert "failed" in out or "not found" in out.lower() or "no such" in out.lower()


@pytest.mark.parametrize("command", [".save", ".load", ".run", ".delete"])
def test_sad_a_command_without_its_name_shows_the_usage(console, command):
    assert f"usage: {command} <name>" in enter(console, command)


def test_sad_backspace_never_eats_the_prompt(console):
    prompt_text = console.toPlainText()
    for _ in range(5):
        QTest.keyClick(console, Qt.Key.Key_Backspace)
    assert console.toPlainText() == prompt_text


@pytest.mark.parametrize("command", [".save", ".delete"])
def test_sad_an_unreadable_script_folder_is_a_message_not_a_crash(
    console, name, monkeypatch, command
):
    def refuse():
        raise PermissionError(13, "Permission denied", "scripts")

    monkeypatch.setattr(scripting, "list_scripts", refuse)
    enter(console, "v = 1")
    out = enter(console, f"{command} {name}")
    assert "failed" in out and "Permission denied" in out
    assert "3" in enter(console, "1 + 2")


# ------------------------------------------------------------------- edge
def test_edge_typing_before_the_prompt_lands_at_the_end(console):
    enter(console, "z = 5")
    cursor = console.textCursor()
    cursor.setPosition(0)
    console.setTextCursor(cursor)
    QTest.keyClicks(console, "z")
    assert current(console) == "z"


def test_edge_home_goes_to_the_start_of_the_input(console):
    QTest.keyClicks(console, "value")
    QTest.keyClick(console, Qt.Key.Key_Home)
    assert console.textCursor().position() == console._input_start


def test_edge_ctrl_d_clears_an_open_block_and_never_closes(console):
    enter(console, "for i in range(3):")
    QTest.keyClick(console, Qt.Key.Key_D, Qt.KeyboardModifier.ControlModifier)
    assert console._buffer == []
    QTest.keyClick(console, Qt.Key.Key_D, Qt.KeyboardModifier.ControlModifier)
    assert "close the Console dock to exit" in console.toPlainText()


def test_edge_a_float_literal_starting_with_a_dot_is_python(console):
    assert "0.5" in enter(console, ".5")


def test_edge_the_history_file_is_compacted_to_its_limit(console, history, monkeypatch):
    from ui import repl_widget

    monkeypatch.setattr(repl_widget, "HISTORY_LIMIT", 3)
    monkeypatch.setattr(repl_widget, "COMPACT_EVERY_N", 4)
    for i in range(4):
        enter(console, f"n{i} = {i}")
    assert history.read_text().splitlines() == ["n1 = 1", "n2 = 2", "n3 = 3"]


def test_edge_a_history_from_the_last_start_is_recalled(history, tmp_path):
    from ui import repl_widget

    history.parent.mkdir(parents=True)
    history.write_text("old = 1\n\nolder = 2\n")
    w = repl_widget.ReplWidget(startup_path=tmp_path / "none.py")
    try:
        w.show()
        QTest.keyClick(w, Qt.Key.Key_Up)
        assert current(w) == "older = 2"
    finally:
        w.deleteLater()
