"""ui/mail_docks.py and ui/mail_project.py offscreen: a dock's panel shows
a mail that waits for Send / Don't Send and the runner gets the answer;
settings round-trip through the dialog; the Tools menu opens both; a mail
project lists by score, shows the report, and opens a read-only Agent tab."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

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


class FakeRunner:
    def __init__(self, dock, *, ask_send, on_log):
        self.dock, self.ask_send, self.on_log = dock, ask_send, on_log
        self.answers = []
        self.closed = False

    def run_once(self):
        self.on_log("looking")
        self.answers.append(self.ask_send(None, "To: bob@example.net\nSubject: Re: Lunch?"))
        return "done"

    def close(self):
        self.closed = True


def test_happy_a_waiting_mail_is_sent_only_after_the_click():
    from ui.mail_docks import MailDockPanel

    panel = MailDockPanel(MD.MailDockConfig(name="work", mailbox_profile="imap"), runner_factory=FakeRunner)
    panel.run_now()
    assert _spin(lambda: panel.approvals.count() == 1)
    assert panel.send_button.isVisibleTo(panel) and "Re: Lunch?" in panel.approvals.item(0).text()
    assert panel.runner.answers == []          # still waiting
    panel.send_button.click()
    assert _spin(lambda: panel.runner.answers == [True] and not panel._running)
    assert panel.approvals.count() == 0 and not panel.send_button.isVisibleTo(panel)
    panel.run_now()
    assert _spin(lambda: panel.approvals.count() == 1)
    panel.decline_button.click()
    assert _spin(lambda: panel.runner.answers == [True, False])
    assert "looking" in panel.log_view.toPlainText()
    panel.shutdown()
    assert panel.runner.closed


def test_happy_pause_skips_the_timer_run_and_shutdown_releases_a_waiting_run():
    from ui.mail_docks import MailDockPanel

    panel = MailDockPanel(MD.MailDockConfig(name="w", enabled=False), runner_factory=FakeRunner)
    assert panel.paused and "paused" in panel.status.text()
    panel._tick()
    assert not panel._running
    panel.pause_button.setChecked(False)
    panel._tick()
    assert _spin(lambda: panel.approvals.count() == 1)
    panel.shutdown()                            # the waiting run is released (as a no)
    assert _spin(lambda: panel.runner.answers == [False])


def test_happy_the_settings_dialog_round_trips_and_checks():
    from ui.mail_docks import MailDockDialog

    dock = MD.MailDockConfig(name="work", mailbox_profile="imap-work", send_policy="allowed",
                             send_allow=["@example.org"], smtp_host="smtp.example.org",
                             from_address="me@example.org", report_to=["Security"], interval_minutes=7)
    dlg = MailDockDialog(dock, mailboxes=["imap-work", "pop-home"], llms=["local"], sandboxes=["High"],
                         docks=["Security"])
    got = dlg.config()
    for field in ("name", "mailbox_profile", "send_policy", "send_allow", "smtp_host", "from_address",
                  "report_to", "interval_minutes", "dock_id"):
        assert getattr(got, field) == getattr(dock, field), field
    dlg.smtp_host.setText("")
    from unittest import mock

    from PyQt6.QtWidgets import QMessageBox
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert warn.called and dlg.result_dock is None   # sending without SMTP is refused


def test_happy_a_mail_project_lists_by_score_and_opens_a_read_only_agent_tab(tmp_path):
    from test_mail_message_analyse import CLEAN, PHISH

    from ui.mail_project import ANALYST_PROMPT, MailProjectDialog

    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "a.eml").write_bytes(CLEAN)
    (tmp_path / "in" / "b.eml").write_bytes(PHISH)

    class Tab:
        class session:
            files_read_only = False

        def refresh_choices(self):
            pass

    class Dock:
        def __init__(self):
            self.opened = []

        def new_tab(self, folder, task):
            self.opened.append((folder, task))
            self.tab = Tab()
            return self.tab

        def show(self):
            pass

        def raise_(self):
            pass

    agent = Dock()
    dlg = MailProjectDialog(folder=str(tmp_path / "proj"), agent_dock=agent)
    dlg.project.import_paths([str(tmp_path / "in")])
    dlg.refresh()
    assert dlg.table.rowCount() == 2 and dlg.table.item(0, 5).text() == "Your account"
    dlg.table.selectRow(0)
    APP.processEvents()
    text = dlg.detail.toPlainText()
    assert "[HIGH] auth: SPF fail" in text and "invoice.pdf.exe" in text
    dlg.ask_agent()
    assert agent.opened == [(str(tmp_path / "proj"), ANALYST_PROMPT)]
    assert agent.tab.session.files_read_only is True
    dlg.search.setText("Lunch")
    assert dlg.table.rowCount() == 1
    dlg.done(0)


def test_happy_mail_docks_open_from_the_settings_file_and_can_be_removed(tmp_path):
    from PyQt6.QtWidgets import QMainWindow

    from ui.mail_docks import MailDocks

    store = MD.MailDockStore(tmp_path / "docks.json")
    a, b = MD.MailDockConfig(name="A"), MD.MailDockConfig(name="B")
    store.save([a, b])
    window = QMainWindow()
    docks = MailDocks(window, store=store, runner_factory=FakeRunner)
    docks.start()
    assert set(docks.panels) == {a.dock_id, b.dock_id}
    ext, _panel = docks.panels[a.dock_id]
    assert ext.windowTitle() == "Mail: A"
    docks.remove(a.dock_id)
    assert [d.name for d in store.load()] == ["B"] and a.dock_id not in docks.panels
    docks.shutdown()
    window.close()
