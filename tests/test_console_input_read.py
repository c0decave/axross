"""The Console reads the typed line from where it starts - not by copying
the whole buffer - and reads it whole after an emoji in the output.

Found 2026-10-25 while measuring the Console (scripts/ui_bench.py): every
Enter copied the whole buffer (up to 4 MiB) into a Python string four to
five times - ReplWidget._current_input sliced toPlainText(), and
_maybe_trim_buffer measured toPlainText() after every append. And the
slice was wrong: ``_input_start`` is a cursor position, counted in UTF-16
units, while the Python string counts code points - after "😀" in the
output, "x = 40 + 2" was read as " = 40 + 2" (IndentationError).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def repl(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from ui.repl_widget import ReplWidget

    widget = ReplWidget(startup_path=tmp_path / "no-startup.py")
    widget.resize(700, 400)
    widget.show()
    APP.processEvents()
    yield widget
    widget.close()
    widget.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _type(repl, text: str) -> None:
    """Type *text* and press Enter. QTest types characters of the Basic
    Multilingual Plane only: anything else goes in as an input method
    would put it (insertPlainText)."""
    if all(ord(ch) < 0x10000 for ch in text):
        QTest.keyClicks(repl, text)
    else:
        repl.insertPlainText(text)
    QTest.keyClick(repl, Qt.Key.Key_Return)


def _count_full_copies(monkeypatch, repl) -> list:
    calls = []
    real = repl.toPlainText
    monkeypatch.setattr(repl, "toPlainText", lambda: (calls.append(1), real())[1])
    return calls


# -- happy ---------------------------------------------------------------------


def test_happy_after_an_emoji_the_typed_line_is_read_whole(repl) -> None:
    _type(repl, 'print("\U0001F600 and \U0001F680")')
    _type(repl, "x = 40 + 2")
    assert repl._globals.get("x") == 42
    assert "IndentationError" not in repl.toPlainText()


def test_happy_enter_reads_no_copy_of_the_whole_buffer(repl, monkeypatch) -> None:
    repl._append("".join(f"line {i} of earlier output\n" for i in range(20000)))
    repl._write_prompt(">>> ")
    calls = _count_full_copies(monkeypatch, repl)
    _type(repl, "y = 6 * 7")
    assert repl._globals.get("y") == 42
    assert calls == []


# -- sad -----------------------------------------------------------------------


def test_sad_a_block_over_several_lines_runs_as_before(repl) -> None:
    _type(repl, 'print("\U0001F600")')
    _type(repl, "total = 0")
    _type(repl, "for i in range(4):")
    _type(repl, "    total += i")
    QTest.keyClick(repl, Qt.Key.Key_Return)
    assert repl._globals.get("total") == 6


def test_sad_a_non_breaking_space_reads_as_a_space_as_before(repl) -> None:
    repl._replace_input("z = 5")
    assert repl._current_input() == "z = 5"
    QTest.keyClick(repl, Qt.Key.Key_Return)
    assert repl._globals.get("z") == 5


# -- edge ----------------------------------------------------------------------


def test_edge_the_buffer_past_the_cap_keeps_its_tail_as_before(repl, monkeypatch) -> None:
    from ui import repl_widget as RW

    monkeypatch.setattr(RW, "CONSOLE_BUFFER_CAP_CHARS", 5000)
    monkeypatch.setattr(RW, "CONSOLE_BUFFER_TAIL_CHARS", 1000)
    repl._append("a" * 6000 + "END\n")
    text = repl.toPlainText()
    assert len(text) == 1000 and text.endswith("END\n")
    _type(repl, "w = 1")
    assert repl._globals.get("w") == 1


def test_edge_emoji_count_once_toward_the_cap_as_before(repl, monkeypatch) -> None:
    """The cap counts characters (code points): 3000 emoji are 6000 UTF-16
    units but 3000 characters - under a cap of 4000 nothing is cut."""
    from ui import repl_widget as RW

    before = len(repl.toPlainText())
    monkeypatch.setattr(RW, "CONSOLE_BUFFER_CAP_CHARS", before + 3001)
    repl._append("\U0001F600" * 3000)
    assert len(repl.toPlainText()) == before + 3000  # not trimmed
    repl._append("\U0001F600" * 2)
    assert len(repl.toPlainText()) <= RW.CONSOLE_BUFFER_TAIL_CHARS  # now it is


def test_edge_tab_completion_after_an_emoji_completes_the_typed_name(repl) -> None:
    _type(repl, 'print("\U0001F600")')
    _type(repl, "completion_target_value = 1")
    QTest.keyClicks(repl, "completion_tar")
    QTest.keyClick(repl, Qt.Key.Key_Tab)
    assert repl._current_input() == "completion_target_value"


# -- e2e -----------------------------------------------------------------------


def test_e2e_the_console_dock_of_the_window_runs_a_line_after_emoji_output(tmp_path,
                                                                           monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        dock = win._console_dock
        dock.show()
        dock.raise_()
        APP.processEvents()
        repl = dock.repl
        repl.setFocus()
        _type(repl, 'print("files: \U0001F4C1 \U0001F4C2")')
        _type(repl, "answer = sum([20, 22])")
        _type(repl, "print(answer)")
        assert repl._globals.get("answer") == 42
        assert repl.toPlainText().rstrip().endswith("42\n>>>")
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
