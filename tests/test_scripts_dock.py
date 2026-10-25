"""ui.scripts_dock: start, manage and edit saved scripts in the GUI.

Every run is a child process (core.script_runner); each test that starts
one stops the dock in its teardown, and the tests that check an ended run
assert the process is gone.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import script_runner as SR  # noqa: E402
from core import scripting, security_mode  # noqa: E402
from ui import scripts_dock as SD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return predicate()


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class Prompts:
    """Scripted answers for the dock's dialogs, and a record of what it said."""

    def __init__(self) -> None:
        self.names: list[str | None] = []
        self.unsaved: list[str] = []
        self.confirms: list[bool] = []
        self.warnings: list[str] = []
        self.confirm_texts: list[str] = []

    def install(self, dock) -> None:
        dock._ask_name = lambda *a, **k: self.names.pop(0) if self.names else None
        dock._ask_unsaved = lambda *a, **k: self.unsaved.pop(0) if self.unsaved else "cancel"

        def confirm(_title, text):
            self.confirm_texts.append(text)
            return self.confirms.pop(0) if self.confirms else False

        dock._confirm = confirm
        dock._warn = lambda _title, text: self.warnings.append(text)


@pytest.fixture()
def names():
    """Unique script names; every one is deleted afterwards."""
    made: list[str] = []

    def _new(prefix: str = "t") -> str:
        name = f"{prefix}_{uuid.uuid4().hex[:8]}"
        made.append(name)
        return name

    yield _new
    for name in made:
        scripting.delete_script(name)


@pytest.fixture()
def jobs():
    return {}


@pytest.fixture()
def dock(jobs):
    d = SD.ScriptsDock(scheduled_jobs=lambda: jobs)
    d.prompts = Prompts()
    d.prompts.install(d)
    d.resize(900, 600)
    d.show()
    APP.processEvents()
    yield d
    d.shutdown()
    d.close()
    d.deleteLater()
    APP.processEvents()


def _item_texts(dock) -> list[str]:
    return [dock.list.item(i).text() for i in range(dock.list.count())]


def _user_item(dock, name):
    for i in range(dock.list.count()):
        item = dock.list.item(i)
        if item.data(SD.ENTRY_ROLE) == ("user", name):
            return item
    return None


def _run_and_wait(dock, timeout: float = 30.0):
    dock.run()
    assert _wait(lambda: not dock.is_running(), timeout), "run did not finish"
    return dock.status_text()


# ---------------------------------------------------------------------------
# Listing and opening
# ---------------------------------------------------------------------------


def test_happy_saved_scripts_and_bundled_examples_are_listed(dock, names) -> None:
    name = names()
    scripting.save_script(name, "print(1)\n")
    dock.refresh()
    texts = _item_texts(dock)
    assert name in texts
    assert any("Examples" in t for t in texts)
    assert "du" in texts  # a bundled example


def test_happy_an_example_opens_read_only_runs_and_can_only_be_copied(dock) -> None:
    assert dock.open_example("du")
    assert dock.editor.isReadOnly()
    assert "def du(" in dock.editor.toPlainText()
    for action in (dock.save_action, dock.rename_action, dock.delete_action):
        assert not action.isEnabled()
    # Run asks for the example's call first (tests/test_scripts_examples_usable.py)
    assert dock.run_action.isEnabled() and dock.console_action.isEnabled()
    assert dock.copy_example_action.isEnabled()


def test_happy_copy_an_example_into_my_scripts(dock, names) -> None:
    target = names("copy")
    dock.open_example("du")
    dock.prompts.names = [target]
    dock.copy_example()
    assert "def du(" in scripting.load_script(target)
    assert dock.current() == ("user", target)
    assert not dock.editor.isReadOnly()


# ---------------------------------------------------------------------------
# New / save / dirty marker / unsaved-changes guard
# ---------------------------------------------------------------------------


def test_happy_new_script_is_saved_opened_and_listed(dock, names) -> None:
    name = names()
    dock.prompts.names = [name]
    dock.new_script()
    assert name in scripting.list_scripts()
    assert dock.current() == ("user", name)
    assert "axross" in dock.editor.toPlainText()
    assert _user_item(dock, name) is not None


def test_happy_edit_marks_dirty_and_ctrl_s_saves(dock, names) -> None:
    name = names()
    scripting.save_script(name, "x = 1\n")
    dock.refresh()
    dock.open_script(name)
    dock.editor.moveCursor(dock.editor.textCursor().MoveOperation.End)
    QTest.keyClicks(dock.editor, "y = 2")
    assert dock.is_dirty()
    assert _user_item(dock, name).text().endswith("*")
    assert "*" in dock.header_text()
    dock.activateWindow()
    dock.editor.setFocus()
    APP.processEvents()
    QTest.keyClick(dock.editor, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)
    assert scripting.load_script(name) == "x = 1\ny = 2"
    assert not dock.is_dirty()
    assert not _user_item(dock, name).text().endswith("*")


def test_sad_invalid_names_are_refused_with_the_validator_reason(dock) -> None:
    before = scripting.list_scripts()
    for bad in ("../evil", "a b", "x" * 81):
        dock.prompts.names = [bad, None]
        dock.new_script()
    assert scripting.list_scripts() == before
    assert len(dock.prompts.warnings) == 3
    assert "must match" in dock.prompts.warnings[0]
    assert "too long" in dock.prompts.warnings[2]


def test_sad_unsaved_changes_cancel_keeps_the_script_open(dock, names) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    scripting.save_script(b, "b = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.editor.setPlainText("a = 2\n")
    dock.prompts.unsaved = ["cancel"]
    assert dock.open_script(b) is False
    assert dock.current() == ("user", a)
    assert dock.editor.toPlainText() == "a = 2\n"
    assert dock.list.currentItem().data(SD.ENTRY_ROLE) == ("user", a)


def test_edge_unsaved_changes_discard_and_save(dock, names) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    scripting.save_script(b, "b = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.editor.setPlainText("a = 2\n")
    dock.prompts.unsaved = ["discard"]
    assert dock.open_script(b)
    assert scripting.load_script(a) == "a = 1\n"
    dock.editor.setPlainText("b = 2\n")
    dock.prompts.unsaved = ["save"]
    assert dock.open_script(a)
    assert scripting.load_script(b) == "b = 2\n"


def test_edge_clicking_another_script_in_the_list_runs_the_guard(dock, names) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    scripting.save_script(b, "b = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.editor.setPlainText("changed\n")
    dock.prompts.unsaved = ["cancel"]
    dock.list.setCurrentItem(_user_item(dock, b))
    APP.processEvents()
    assert dock.current() == ("user", a)
    assert dock.list.currentItem().data(SD.ENTRY_ROLE) == ("user", a)


# ---------------------------------------------------------------------------
# Save as / rename / delete
# ---------------------------------------------------------------------------


def test_happy_save_as_copies_the_editor_text_under_a_new_name(dock, names) -> None:
    a, copy = names("a"), names("copy")
    scripting.save_script(a, "a = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.editor.setPlainText("a = 2\n")
    dock.prompts.names = [copy]
    dock.save_as()
    assert scripting.load_script(copy) == "a = 2\n"
    assert scripting.load_script(a) == "a = 1\n"
    assert dock.current() == ("user", copy)
    assert not dock.is_dirty()


def test_happy_rename_moves_the_file_and_keeps_the_edits(dock, names) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.editor.setPlainText("edited\n")
    dock.prompts.names = [b]
    dock.rename()
    assert a not in scripting.list_scripts()
    assert scripting.load_script(b) == "a = 1\n"  # the file moved, the edit did not get saved
    assert dock.current() == ("user", b)
    assert dock.editor.toPlainText() == "edited\n"
    assert dock.is_dirty()


def test_sad_rename_onto_an_existing_script_is_refused(dock, names) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    scripting.save_script(b, "b = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.prompts.names = [b, None]
    dock.rename()
    assert scripting.load_script(a) == "a = 1\n"
    assert scripting.load_script(b) == "b = 1\n"
    assert dock.current() == ("user", a)
    assert any("already exists" in w for w in dock.prompts.warnings)


def test_edge_delete_asks_first(dock, names) -> None:
    a = names("a")
    scripting.save_script(a, "a = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.prompts.confirms = [False]
    dock.delete()
    assert a in scripting.list_scripts()
    dock.prompts.confirms = [True]
    dock.delete()
    assert a not in scripting.list_scripts()
    assert dock.current() is None
    assert dock.editor.toPlainText() == ""
    assert _user_item(dock, a) is None


def test_edge_scripts_used_by_the_scheduler_are_marked_and_warned_about(dock, names, jobs) -> None:
    a, b = names("a"), names("b")
    scripting.save_script(a, "a = 1\n")
    jobs[a] = ["nightly mirror"]
    dock.refresh()
    item = _user_item(dock, a)
    assert "scheduled" in item.text()
    assert "nightly mirror" in item.toolTip()
    dock.open_script(a)
    dock.prompts.names = [b]
    dock.prompts.confirms = [False]  # do not rename after the warning
    dock.rename()
    assert "nightly mirror" in dock.prompts.confirm_texts[-1]
    assert a in scripting.list_scripts()
    dock.prompts.confirms = [False]
    dock.delete()
    assert "nightly mirror" in dock.prompts.confirm_texts[-1]
    assert a in scripting.list_scripts()


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def test_happy_run_streams_output_and_reports_exit_and_duration(dock, names) -> None:
    name = names()
    scripting.save_script(
        name, "import sys\nprint('out line')\nprint('err line', file=sys.stderr)\n"
    )
    dock.refresh()
    dock.open_script(name)
    status = _run_and_wait(dock)
    text = dock.output.toPlainText()
    assert "out line" in text and "err line" in text
    assert "exit status 0" in status
    assert " s" in status  # the duration
    assert dock.run_action.isEnabled() and not dock.stop_action.isEnabled()


def test_happy_output_arrives_while_the_script_still_runs(dock, names) -> None:
    name = names()
    scripting.save_script(name, "import time\nprint('early')\ntime.sleep(30)\n")
    dock.refresh()
    dock.open_script(name)
    dock.run()
    assert _wait(lambda: "early" in dock.output.toPlainText(), 20)
    assert dock.is_running()
    dock.stop()
    assert _wait(lambda: not dock.is_running(), 20)


def test_sad_a_non_zero_exit_is_reported(dock, names) -> None:
    name = names()
    scripting.save_script(name, "import sys\nsys.exit(3)\n")
    dock.refresh()
    dock.open_script(name)
    assert "exit status 3" in _run_and_wait(dock)


def test_sad_a_traceback_line_jumps_to_the_script_line(dock, names) -> None:
    name = names()
    scripting.save_script(name, "x = 1\ny = 2\nraise RuntimeError('boom')\n")
    dock.refresh()
    dock.open_script(name)
    assert "exit status 1" in _run_and_wait(dock)
    doc = dock.output.document()
    block = next(
        doc.findBlockByNumber(i)
        for i in range(doc.blockCount())
        if f'{name}.py", line 3' in doc.findBlockByNumber(i).text()
    )
    dock.editor.go_to_line(1)
    cursor = dock.output.textCursor()
    cursor.setPosition(block.position() + 4)
    rect = dock.output.cursorRect(cursor)
    QTest.mouseClick(dock.output.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    APP.processEvents()
    assert dock.editor.textCursor().blockNumber() == 2


def test_sad_a_syntax_error_is_shown_with_its_line(dock, names) -> None:
    name = names()
    scripting.save_script(name, "ok = 1\ndef broken(:\n")
    dock.refresh()
    dock.open_script(name)
    _run_and_wait(dock)
    assert "SyntaxError" in dock.output.toPlainText()
    assert dock.jump_to_traceback_line(f'  File "{dock.last_run_path()}", line 2')
    assert dock.editor.textCursor().blockNumber() == 1


def test_edge_stop_ends_an_endless_loop(dock, names) -> None:
    name = names()
    scripting.save_script(
        name, "import time\nprint('looping', flush=True)\nwhile True:\n    time.sleep(0.05)\n"
    )
    dock.refresh()
    dock.open_script(name)
    dock.run()
    assert _wait(lambda: "looping" in dock.output.toPlainText(), 20)
    pid = dock.running_pid()
    assert _alive(pid)
    dock.stop()
    assert _wait(lambda: not dock.is_running(), 20)
    assert "stopped" in dock.status_text()
    assert not _alive(pid)


def test_edge_stop_kills_a_script_that_ignores_terminate(dock, names) -> None:
    name = names()
    scripting.save_script(
        name,
        "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('stubborn', flush=True)\nwhile True:\n    time.sleep(0.05)\n",
    )
    dock.refresh()
    dock.open_script(name)
    with mock.patch.object(SR, "STOP_GRACE_SECONDS", 0.3):
        dock.run()
        assert _wait(lambda: "stubborn" in dock.output.toPlainText(), 20)
        pid = dock.running_pid()
        dock.stop()
        assert _wait(lambda: not dock.is_running(), 20)
    assert "stopped" in dock.status_text()
    assert not _alive(pid)


def test_edge_huge_output_stays_bounded(names) -> None:
    with mock.patch.object(SR, "MAX_OUTPUT_LINES", 500):
        d = SD.ScriptsDock(scheduled_jobs=lambda: {})
    Prompts().install(d)
    try:
        name = names()
        scripting.save_script(
            name, "import sys\nfor i in range(60000):\n    print('line', i)\nprint('x' * 50000)\n"
        )
        d.refresh()
        d.open_script(name)
        assert "exit status 0" in _run_and_wait(d, 60)
        doc = d.output.document()
        assert doc.blockCount() <= 501
        text = d.output.toPlainText()
        assert "line 59999" in text
        assert SR.LINE_CUT_MARKER in text  # the 50 000-char line was cut
        assert len(text) < 500 * (SR.MAX_LINE_CHARS + 50)
    finally:
        d.shutdown()
        d.deleteLater()


def test_edge_a_script_deleted_while_running_finishes_and_can_be_stopped(dock, names) -> None:
    name = names()
    scripting.save_script(name, "import time\nprint('alive', flush=True)\ntime.sleep(30)\n")
    dock.refresh()
    dock.open_script(name)
    dock.run()
    assert _wait(lambda: "alive" in dock.output.toPlainText(), 20)
    pid = dock.running_pid()
    dock.prompts.confirms = [True]
    dock.delete()
    assert name not in scripting.list_scripts()
    assert dock.is_running()
    assert dock.stop_action.isEnabled()
    dock.stop()
    assert _wait(lambda: not dock.is_running(), 20)
    assert not _alive(pid)


def test_sad_paranoid_mode_disables_run_and_says_why(dock, names) -> None:
    name = names()
    scripting.save_script(name, "print(1)\n")
    dock.refresh()
    dock.open_script(name)
    with mock.patch.object(security_mode, "current_policy", return_value=security_mode.PARANOID):
        dock.refresh_policy()
        assert not dock.run_action.isEnabled()
        assert "paranoid" in dock.run_action.toolTip().lower()
        assert not dock.console_action.isEnabled()
        dock.run()  # called directly anyway: still refused
        APP.processEvents()
        assert not dock.is_running()
        assert dock.running_pid() is None
    dock.refresh_policy()
    assert dock.run_action.isEnabled()


def test_edge_run_saves_unsaved_edits_first(dock, names) -> None:
    name = names()
    scripting.save_script(name, "print('old')\n")
    dock.refresh()
    dock.open_script(name)
    dock.editor.setPlainText("print('new')\n")
    _run_and_wait(dock)
    assert scripting.load_script(name) == "print('new')\n"
    assert "new" in dock.output.toPlainText()
    assert "old" not in dock.output.toPlainText()
    assert not dock.is_dirty()


def test_edge_shutdown_stops_a_running_script(dock, names) -> None:
    name = names()
    scripting.save_script(name, "import time\nprint('up', flush=True)\ntime.sleep(60)\n")
    dock.refresh()
    dock.open_script(name)
    dock.run()
    assert _wait(lambda: "up" in dock.output.toPlainText(), 20)
    pid = dock.running_pid()
    started = time.monotonic()
    dock.shutdown()
    assert time.monotonic() - started < SR.STOP_GRACE_SECONDS + 3
    assert not dock.is_running()
    assert not _alive(pid)


def test_happy_run_in_console_saves_and_hands_over_the_name(dock, names) -> None:
    name = names()
    scripting.save_script(name, "a = 1\n")
    dock.refresh()
    dock.open_script(name)
    dock.editor.setPlainText("a = 2\n")
    got: list[str] = []
    dock.run_in_console_requested.connect(got.append)
    dock.run_in_console()
    assert got == [name]
    assert scripting.load_script(name) == "a = 2\n"


_PRODUCTION_WRITE = (
    "import types\n"
    "from core import safety_tarpit\n"
    "profile = types.SimpleNamespace(production=True, name='prod', host='h', protocol='sftp')\n"
    "with safety_tarpit.production_gate(profile, 'remove /x', countdown_s=0.1):\n"
    "    print('write ran')\n"
)


def test_happy_a_production_write_counts_down_in_the_dock_and_runs(dock, names) -> None:
    # The dock shows the countdown live and Stop ends the run during it, so
    # a human watches it even though the child has no terminal.
    name = names()
    scripting.save_script(name, _PRODUCTION_WRITE)
    dock.refresh()
    dock.open_script(name)
    with mock.patch.dict(os.environ):
        os.environ.pop("AXROSS_TARPIT_DISABLE", None)
        status = _run_and_wait(dock)
    text = dock.output.toPlainText()
    assert "production tarpit" in text
    assert "write ran" in text, text
    assert "exit status 0" in status
