"""A mail dock's panel and settings (ui/mail_docks.py), from the
feature/icon/menu audit (2026-11-08):

* unticking "Run on its timer" in the settings changed nothing until the
  next start: the timer ran on and the dock was not paused;
* Pause was never saved: the next start ran the dock again;
* a run could not be stopped, and the panel's log showed only the agent's
  final answer - not one of its tool calls (the runner's ``on_event`` was
  never passed);
* the drafts of a POP3 mailbox went to a folder nothing opened;
* F1 did nothing in the dock's settings and the Mail Docks manager, which
  had no Edit… button, and a dock without a mailbox was saved.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QKeySequence, QShortcut  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QListWidget,
    QMessageBox,
    QPushButton,
    QWidget,
)

from core import mail_dock as MD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _spin(until, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return False


class Runner:
    """A runner that reports one tool call and, with *hold*, waits for its
    cancel - as core.mail_dock_runner.MailDockRunner does."""

    hold = False

    def __init__(self, dock, *, ask_send, on_log, on_event=None):
        self.dock, self.on_log, self.on_event = dock, on_log, on_event
        self.cancel = threading.Event()
        self.state_dir = None
        self.stopped = False

    def run_once(self):
        if self.on_event is not None:
            self.on_event({"type": "tool_call", "name": "mail_list_new", "args": {"limit": 5}})
            self.on_event({"type": "tool_result", "name": "mail_send", "outcome": "refused",
                           "reason": "the send policy is never"})
            self.on_event({"type": "usage", "prompt": 10})
        if self.hold:
            self.stopped = self.cancel.wait(5)
        return "done"

    def close(self):
        self.cancel.set()


def _panel(**changes):
    from ui.mail_docks import MailDockPanel

    dock = MD.MailDockConfig(name="work", mailbox_profile="imap-work", **changes)
    return MailDockPanel(dock, runner_factory=Runner)


def test_happy_unticking_run_on_its_timer_pauses_the_dock_at_once():
    panel = _panel()
    assert not panel.paused and panel.timer.isActive()
    panel.apply(dataclasses.replace(panel.dock, enabled=False))
    assert panel.paused and panel.pause_button.isChecked()
    assert not panel.timer.isActive() and "paused" in panel.status.text()
    panel.apply(dataclasses.replace(panel.dock, enabled=True))
    assert not panel.paused and not panel.pause_button.isChecked() and panel.timer.isActive()
    panel.shutdown()


def test_happy_pause_is_saved_and_comes_back_paused(tmp_path):
    from PyQt6.QtWidgets import QMainWindow

    from ui.mail_docks import MailDocks

    store = MD.MailDockStore(tmp_path / "docks.json")
    dock = MD.MailDockConfig(name="A", mailbox_profile="imap-work")
    store.save([dock])
    window = QMainWindow()
    docks = MailDocks(window, store=store, runner_factory=Runner)
    docks.start()
    _ext, panel = docks.panels[dock.dock_id]
    panel.pause_button.setChecked(True)
    assert store.load()[0].enabled is False
    docks.shutdown()
    again = MailDocks(window, store=store, runner_factory=Runner)
    again.start()
    assert again.panels[dock.dock_id][1].paused
    again.panels[dock.dock_id][1].pause_button.setChecked(False)
    assert store.load()[0].enabled is True
    again.shutdown()
    window.close()


def test_happy_stop_cancels_the_run_and_tool_calls_show_in_the_log():
    panel = _panel()
    panel.runner.hold = True
    assert not panel.stop_button.isEnabled()
    panel.run_now()
    assert panel.stop_button.isEnabled()
    assert _spin(lambda: "send policy" in panel.log_view.toPlainText())  # the last of the events
    log = panel.log_view.toPlainText()
    assert '{"limit": 5}' in log and "refused" in log and "send policy" in log
    panel.stop_button.click()
    assert _spin(lambda: not panel._running)
    assert panel.runner.stopped and not panel.stop_button.isEnabled()
    assert "prompt" not in panel.log_view.toPlainText()  # usage counts are no log line
    panel.shutdown()


def test_sad_stop_declines_a_mail_that_waits_for_its_answer():
    panel = _panel()
    from ui.mail_docks import _Approval

    approval = _Approval("To: bob@example.net")
    panel._running = True
    panel._show_approval(approval)
    panel.stop()
    assert approval.event.is_set() and approval.answer is False
    assert panel.approvals.count() == 0 and not panel.send_button.isVisibleTo(panel)
    panel._running = False
    panel.shutdown()


def test_happy_open_drafts_folder_shows_the_pop3_drafts_in_a_pane(tmp_path):
    from ui.mail_docks import MailDockPanel

    class Window(QWidget):
        opened: list = []

        def open_local_folder(self, path):
            self.opened.append(path)

    dock = MD.MailDockConfig(name="pop", mailbox_profile="pop-home")
    holder = Window()
    panel = MailDockPanel(dock, runner_factory=Runner, parent=holder)
    panel.runner.state_dir = tmp_path / dock.dock_id
    panel.drafts_button.click()
    drafts = tmp_path / dock.dock_id / "drafts"
    assert holder.opened == [str(drafts)] and drafts.is_dir()
    panel.shutdown()
    holder.deleteLater()


def test_sad_a_dock_without_a_mailbox_is_refused():
    from ui.mail_docks import MailDockDialog

    with pytest.raises(ValueError, match="mailbox"):
        MD.MailDockConfig(name="x").validate()
    dlg = MailDockDialog(MD.MailDockConfig(name="x"), mailboxes=[], llms=[], sandboxes=[], docks=[])
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert warn.called and dlg.result_dock is None
    assert "Connection Manager" in warn.call_args.args[2]
    dlg.deleteLater()


def _f1(widget) -> bool:
    return any(s.key() == QKeySequence("F1") for s in widget.findChildren(QShortcut))


def test_happy_f1_and_edit_in_the_dock_settings_and_the_manager(tmp_path):
    from PyQt6.QtWidgets import QMainWindow

    from ui.handbook import help_topic_of
    from ui.mail_docks import MailDockDialog, MailDocks

    dlg = MailDockDialog(MD.MailDockConfig(name="x", mailbox_profile="imap"), mailboxes=["imap"],
                         llms=[], sandboxes=[], docks=[])
    assert _f1(dlg) and help_topic_of(dlg) == "mail"
    dlg.deleteLater()

    store = MD.MailDockStore(tmp_path / "docks.json")
    dock = MD.MailDockConfig(name="A", mailbox_profile="imap-work")
    store.save([dock])
    window = QMainWindow()
    docks = MailDocks(window, store=store, runner_factory=Runner)
    docks.start()
    seen = []

    def run(dialog):
        seen.append((_f1(dialog), help_topic_of(dialog)))
        dialog.findChild(QListWidget).setCurrentRow(0)
        edit = next(b for b in dialog.findChildren(QPushButton) if b.text() == "Edit…")
        with mock.patch.object(docks, "edit_panel") as edit_panel:
            edit.click()
        seen.append(edit_panel.call_args.args[0] is docks.panels[dock.dock_id][1])
        return 0

    with mock.patch.object(QDialog, "exec", run):
        docks.manage()
    assert seen == [(True, "mail"), True]
    docks.shutdown()
    window.close()


def test_edge_event_lines_are_short_and_only_what_the_agent_did():
    from ui.mail_docks import EVENT_ARGS_CHARS, event_text

    long = event_text({"type": "tool_call", "name": "mail_read", "args": {"id": "x" * 500}})
    assert long.startswith("Tool: mail_read") and len(long) < EVENT_ARGS_CHARS + 40
    assert event_text({"type": "tool_result", "name": "mail_read", "outcome": "ok"}) is None
    assert event_text({"type": "assistant", "text": "the answer"}) is None  # the runner logs it
    assert event_text({"type": "notice", "text": "MCP server not available"}) == "MCP server not available"
    assert "unreachable" in event_text({"type": "connection", "state": "failed", "detail": "unreachable"})
