"""Run in Console: the Scripts dock hands a saved script to the REPL.

ReplWidget.run_saved_script behaves like typing ``.run <name>``: the
script runs in the live namespace, its output lands in the console, and
paranoid mode refuses it — as it already refuses startup.py and
axross.run_script, and now ``.run`` too.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import scripting, security_mode  # noqa: E402

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


def test_happy_a_saved_script_runs_in_the_live_namespace(repl, saved) -> None:
    name = saved("answer = 6 * 7\nprint('from script', answer)\n")
    assert repl.run_saved_script(name) is True
    assert repl._globals["answer"] == 42
    text = repl.toPlainText()
    assert f".run {name}" in text
    assert "from script 42" in text
    assert text.endswith(">>> ")


def test_sad_paranoid_mode_refuses_run_and_the_slash_command(repl, saved, tmp_path) -> None:
    marker = tmp_path / "ran"
    name = saved(f"open({str(marker)!r}, 'w').write('x')\n")
    with mock.patch.object(security_mode, "current_policy", return_value=security_mode.PARANOID):
        assert repl.run_saved_script(name) is False
        repl._replace_input(f".run {name}")
        repl._submit_current()
    assert not marker.exists()
    assert "paranoid" in repl.toPlainText()


def test_sad_a_missing_script_is_reported(repl) -> None:
    assert repl.run_saved_script(f"gone_{uuid.uuid4().hex[:6]}") is False
    assert "run failed" in repl.toPlainText()


def test_edge_a_half_typed_line_is_kept(repl, saved) -> None:
    name = saved("x_from_script = 1\n")
    repl._replace_input("print('unfinished")
    assert repl.run_saved_script(name) is True
    assert repl._current_input() == "print('unfinished"
    assert repl._globals["x_from_script"] == 1


def test_edge_an_open_block_is_not_interrupted(repl, saved) -> None:
    name = saved("y_from_script = 1\n")
    repl._replace_input("for i in range(2):")
    repl._submit_current()  # the prompt is now a continuation line
    assert repl.run_saved_script(name) is False
    assert "y_from_script" not in repl._globals
    assert "finish" in repl.toPlainText()


def test_edge_an_invalid_name_is_reported_not_raised(repl) -> None:
    repl._replace_input(".run ../etc/passwd")
    repl._submit_current()  # raised ValueError out of the key handler before
    assert "run failed" in repl.toPlainText()
    assert repl.toPlainText().endswith(">>> ")


def test_sad_a_script_error_is_shown_with_its_file_and_line(repl, saved) -> None:
    name = saved("ok = 1\nraise ValueError('bad value')\n")
    assert repl.run_saved_script(name) is True
    text = repl.toPlainText()
    assert f'{name}.py", line 2' in text
    assert "ValueError: bad value" in text
    assert repl._globals["ok"] == 1


def test_edge_a_syntax_error_in_a_script_is_shown_not_raised(repl, saved) -> None:
    name = saved("x = 1\ndef broken(:\n")
    repl.run_saved_script(name)
    assert "SyntaxError" in repl.toPlainText()
    assert "x" not in repl._globals  # nothing of a broken script runs


def test_edge_a_startup_script_of_several_statements_runs_whole(monkeypatch, tmp_path) -> None:
    from ui import repl_widget

    monkeypatch.setattr(repl_widget, "HISTORY_PATH", tmp_path / "history")
    startup = tmp_path / "startup.py"
    startup.write_text("first = 1\nsecond = first + 1\n")
    os.chmod(startup, 0o600)
    widget = repl_widget.ReplWidget(startup_path=startup)
    try:
        assert widget._globals.get("second") == 2
    finally:
        widget.deleteLater()
