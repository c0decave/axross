"""The Scripts panel in the real MainWindow, offscreen, end to end.

Open the panel from View > Panels, create a script, type into it, save
with Ctrl+S, run it with Ctrl+Return and see its output, run a looping
script and stop it, delete it. Plus the window-level wiring: closing the
window ends a running script, Help > Scripting Guide, the paranoid
toggle, Run in Console and the scheduler marker.
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

from core import scripting, security_mode  # noqa: E402

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


def _alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.fixture()
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1200, 800)
    win.show()
    APP.processEvents()
    yield win
    dock = win._scripts_dock
    dock.shutdown()
    dock._set_dirty(False)  # never let a test's leftover edit block the close
    win.close()
    win.deleteLater()
    APP.processEvents()


@pytest.fixture()
def name():
    made = f"e2e_{uuid.uuid4().hex[:8]}"
    yield made
    scripting.delete_script(made)


def _panels_action(win, title: str):
    return next(a for a in win._dock_view_menu.actions() if a.text().replace("&", "") == title)


def _key(widget, key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    widget.window().activateWindow()
    widget.setFocus()
    APP.processEvents()
    QTest.keyClick(widget, key, mods)
    APP.processEvents()


def test_happy_create_edit_save_run_stop_delete(window, name) -> None:
    dock = window._scripts_dock
    action = _panels_action(window, "Scripts")
    if not dock.isVisible():
        action.trigger()
    dock.raise_()
    assert _wait(lambda: dock.isVisible(), 5)
    assert action.isChecked()

    # New
    with mock.patch.object(dock, "_ask_name", return_value=name):
        dock.new_action.trigger()
    assert name in scripting.list_scripts()
    assert dock.current() == ("user", name)

    # Edit + Ctrl+S
    dock.editor.selectAll()
    _key(dock.editor, Qt.Key.Key_Delete)
    QTest.keyClicks(dock.editor, "print('hello from e2e')")
    assert dock.is_dirty()
    _key(dock.editor, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)
    assert scripting.load_script(name) == "print('hello from e2e')"
    assert not dock.is_dirty()

    # Ctrl+Return runs it in its own process
    _key(dock.editor, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
    assert dock.is_running() or "exit status" in dock.status_text()
    assert _wait(lambda: not dock.is_running(), 30)
    assert "hello from e2e" in dock.output.toPlainText()
    assert "exit status 0" in dock.status_text()
    assert scripting.load_script(name) == "print('hello from e2e')"  # Ctrl+Return added no line

    # A looping script, stopped
    dock.editor.setPlainText(
        "import time\nprint('looping', flush=True)\nwhile True:\n    time.sleep(0.05)\n"
    )
    dock.run_action.trigger()
    assert _wait(lambda: "looping" in dock.output.toPlainText(), 30)
    pid = dock.running_pid()
    assert _alive(pid)
    dock.stop_action.trigger()
    assert _wait(lambda: not dock.is_running(), 20)
    assert "stopped" in dock.status_text()
    assert not _alive(pid)

    # Delete
    with mock.patch.object(dock, "_confirm", return_value=True):
        dock.delete_action.trigger()
    assert name not in scripting.list_scripts()
    assert dock.current() is None


def test_edge_closing_the_window_stops_a_running_script(name) -> None:
    from ui.main_window import MainWindow

    win = MainWindow()
    win.show()
    APP.processEvents()
    dock = win._scripts_dock
    scripting.save_script(name, "import time\nprint('up', flush=True)\ntime.sleep(60)\n")
    dock.refresh()
    dock.open_script(name)
    dock.run()
    assert _wait(lambda: "up" in dock.output.toPlainText(), 30)
    pid = dock.running_pid()
    assert _alive(pid)
    win.close()
    APP.processEvents()
    assert not _alive(pid)
    win.deleteLater()
    APP.processEvents()


def test_sad_unsaved_edits_can_keep_the_window_open(window, name) -> None:
    dock = window._scripts_dock
    scripting.save_script(name, "a = 1\n")
    dock.refresh()
    dock.open_script(name)
    dock.editor.setPlainText("a = 2\n")
    with mock.patch.object(dock, "_ask_unsaved", return_value="cancel"):
        assert window.close() is False
    assert window.isVisible()
    with mock.patch.object(dock, "_ask_unsaved", return_value="save"):
        assert window.close() is True
    assert scripting.load_script(name) == "a = 2\n"


def test_happy_help_menu_opens_the_scripting_guide_once(window) -> None:
    from ui.scripting_guide import ScriptingGuideDialog

    help_menu = next(
        a.menu() for a in window.menuBar().actions() if a.text().replace("&", "") == "Help"
    )
    guide_action = next(
        a for a in help_menu.actions() if a.text().replace("&", "") == "Scripting Guide"
    )
    guide_action.trigger()
    APP.processEvents()
    dialogs = [d for d in window.findChildren(ScriptingGuideDialog) if d.isVisible()]
    assert len(dialogs) == 1
    assert dialogs[0].guide.toPlainText()
    guide_action.trigger()  # a second click raises the same window
    APP.processEvents()
    assert [d for d in window.findChildren(ScriptingGuideDialog) if d.isVisible()] == dialogs
    dialogs[0].close()


def test_sad_the_paranoid_toggle_disables_run_at_once(window, name) -> None:
    dock = window._scripts_dock
    scripting.save_script(name, "print(1)\n")
    dock.refresh()
    dock.open_script(name)
    assert dock.run_action.isEnabled()
    try:
        with mock.patch("ui.main_window.QMessageBox.information"):
            window.set_paranoid_mode(True)
        assert not dock.run_action.isEnabled()
        assert "paranoid" in dock.run_action.toolTip()
    finally:
        with mock.patch("ui.main_window.QMessageBox.information"):
            window.set_paranoid_mode(False)
    assert security_mode.current_policy().allow_scripts
    assert dock.run_action.isEnabled()


def test_happy_run_in_console_runs_in_the_live_namespace(window, name) -> None:
    dock = window._scripts_dock
    var = f"from_{name}"
    scripting.save_script(name, f"{var} = 41\n{var} += 1\nprint('console run', {var})\n")
    dock.refresh()
    dock.open_script(name)
    dock.console_action.trigger()
    APP.processEvents()
    repl = window._console_dock.repl
    assert repl._globals[var] == 42
    assert "console run 42" in repl.toPlainText()
    assert window._console_dock.isVisible()


def test_edge_scripts_used_by_a_scheduled_job_are_marked(window, name) -> None:
    from core.scheduler import Job

    store = window._job_store()
    store.save(
        [Job(job_id="j1", name="hourly report", kind="script", target=name, interval_s=3600)]
    )
    try:
        scripting.save_script(name, "print(1)\n")
        window._scripts_dock.refresh()
        item = next(
            window._scripts_dock.list.item(i)
            for i in range(window._scripts_dock.list.count())
            if window._scripts_dock.list.item(i).data(Qt.ItemDataRole.UserRole + 1)
            == ("user", name)
        )
        assert "[scheduled]" in item.text()
        assert "hourly report" in item.toolTip()
    finally:
        store.save([])
