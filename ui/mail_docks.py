"""Mail docks in the window (Tools > Mail Docks…): one panel per dock -
what it watches, when it runs next, its log, Run Now / Pause / Settings,
and the mails it wants to send waiting for Send or Don't Send (send policy
"ask", or a recipient outside "allowed"). core.mail_dock has the rules,
core.mail_dock_runner does a run on a thread of its own.
"""

from __future__ import annotations

import dataclasses
import logging
import threading
import time

from PyQt6.QtCore import QObject, Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import mail_dock as MD
from core.i18n import tr
from core.mail_dock_runner import MailDockRunner
from core.thread_relay import GuiCall
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: A mail waiting for the user's yes is declined after this long.
APPROVAL_TIMEOUT_S = 30 * 60


class _Approval:
    def __init__(self, summary: str):
        self.summary = summary
        self.event = threading.Event()
        self.answer = False


class MailDockPanel(QWidget):
    """The content of one mail dock's panel."""

    def __init__(self, dock: MD.MailDockConfig, *, runner_factory=MailDockRunner, edit=None, parent=None):
        super().__init__(parent)
        self.dock = dock
        self._edit = edit
        self._pending: list[_Approval] = []
        self._post_log = GuiCall(self._log)
        self._post_approval = GuiCall(self._show_approval)
        self._post_done = GuiCall(self._done)
        self.runner = runner_factory(dock, ask_send=self._ask_send, on_log=self._post_log)
        self._running = False
        self.paused = not dock.enabled
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.run_button = QPushButton(tr("Run Now"))
        self.run_button.clicked.connect(self.run_now)
        self.pause_button = QPushButton(tr("Pause"))
        self.pause_button.setCheckable(True)
        self.pause_button.setChecked(self.paused)
        self.pause_button.toggled.connect(self._toggle_pause)
        settings = QPushButton(tr("Settings…"))
        settings.clicked.connect(lambda: self._edit and self._edit(self))
        for b in (self.run_button, self.pause_button, settings):
            row.addWidget(b)
        row.addStretch(1)
        layout.addLayout(row)
        self.approvals = QListWidget()
        self.approvals.setVisible(False)
        layout.addWidget(self.approvals)
        approve_row = QHBoxLayout()
        self.send_button = QPushButton(tr("Send"))
        self.decline_button = QPushButton(tr("Don't Send"))
        self.send_button.clicked.connect(lambda: self._answer(True))
        self.decline_button.clicked.connect(lambda: self._answer(False))
        for b in (self.send_button, self.decline_button):
            b.setVisible(False)
            approve_row.addWidget(b)
        approve_row.addStretch(1)
        layout.addLayout(approve_row)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view, 1)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self._next = 0.0
        self.apply(dock)

    # -- settings and timer -----------------------------------------------------------------

    def apply(self, dock: MD.MailDockConfig) -> None:
        self.dock = self.runner.dock = dock
        self.timer.start(int(dock.interval_minutes) * 60 * 1000)
        self._next = time.time() + dock.interval_minutes * 60
        self._status()

    def _status(self) -> None:
        d = self.dock
        policy = {"never": tr("never sends"), "ask": tr("sends after your yes"),
                  "allowed": tr("answers the sender without asking")}[d.send_policy]
        when = tr("paused") if self.paused else (tr("running…") if self._running else
                                                tr("next run {t}").format(t=time.strftime("%H:%M", time.localtime(self._next))))
        self.status.setText(tr("{box} / {folder} - every {n} min - {policy} - {when}").format(
            box=d.mailbox_profile or tr("(no mailbox)"), folder=d.folder, n=d.interval_minutes,
            policy=policy, when=when))

    def _toggle_pause(self, paused: bool) -> None:
        self.paused = paused
        self._status()

    def _tick(self) -> None:
        self._next = time.time() + self.dock.interval_minutes * 60
        if not self.paused:
            self.run_now()
        else:
            self._status()

    def run_now(self) -> None:
        if self._running:
            return
        self._running = True
        self.run_button.setEnabled(False)
        self._status()
        threading.Thread(target=self._work, name=f"mail-dock-{self.dock.name}", daemon=True).start()

    def _work(self) -> None:
        try:
            self.runner.run_once()
            error = ""
        except Exception as exc:  # noqa: BLE001 - shown in the dock, the timer goes on
            log.warning("mail dock %s: %s", self.dock.name, exc)
            error = f"{type(exc).__name__}: {exc}"
        self._post_done(error)

    def _done(self, error: str) -> None:
        self._running = False
        self.run_button.setEnabled(True)
        if error:
            self._log(tr("The run failed: {error}").format(error=error))
        self._status()

    def _log(self, text: str) -> None:
        self.log_view.appendPlainText(f"{time.strftime('%H:%M')}  {text}")

    # -- approvals ---------------------------------------------------------------------------

    def _ask_send(self, outgoing, summary: str) -> bool:
        """On the runner's thread: show the mail, wait for Send / Don't Send."""
        approval = _Approval(summary)
        self._post_approval(approval)
        if not approval.event.wait(APPROVAL_TIMEOUT_S):
            self._post_log(tr("Nobody answered within 30 minutes: not sent."))
            return False
        return approval.answer

    def _show_approval(self, approval: _Approval) -> None:
        self._pending.append(approval)
        item = QListWidgetItem(approval.summary)
        item.setData(Qt.ItemDataRole.UserRole, id(approval))
        self.approvals.addItem(item)
        self.approvals.setCurrentItem(item)
        for w in (self.approvals, self.send_button, self.decline_button):
            w.setVisible(True)
        self._log(tr("A mail waits for your answer."))

    def _answer(self, yes: bool) -> None:
        item = self.approvals.currentItem()
        if item is None:
            return
        key = item.data(Qt.ItemDataRole.UserRole)
        approval = next((a for a in self._pending if id(a) == key), None)
        self.approvals.takeItem(self.approvals.row(item))
        if approval is not None:
            self._pending.remove(approval)
            approval.answer = yes
            approval.event.set()
        if not self._pending:
            for w in (self.approvals, self.send_button, self.decline_button):
                w.setVisible(False)

    def shutdown(self) -> None:
        self.timer.stop()
        for approval in self._pending:
            approval.event.set()
        self.runner.close()


class MailDockDialog(QDialog):
    """The settings of one mail dock."""

    def __init__(self, dock: MD.MailDockConfig, *, mailboxes: list[str], llms: list[str], sandboxes: list[str],
                 docks: list[str], parent=None):
        super().__init__(parent)
        set_window_icon(self, "mail")
        self.setWindowTitle(tr("Mail Dock"))
        self._dock = dock
        form = QFormLayout(self)
        self.name = QLineEdit(dock.name)
        self.mailbox = QComboBox()
        self.mailbox.addItems(mailboxes)
        self.mailbox.setCurrentText(dock.mailbox_profile)
        self.folder = QLineEdit(dock.folder)
        self.interval = QSpinBox()
        self.interval.setRange(1, 1440)
        self.interval.setValue(int(dock.interval_minutes))
        self.interval.setSuffix(tr(" min"))
        self.instructions = QPlainTextEdit(dock.instructions)
        self.instructions.setMinimumHeight(110)
        self.llm = QComboBox()
        self.llm.addItem(tr("(the active LLM profile)"), "")
        for name in llms:
            self.llm.addItem(name, name)
        self.llm.setCurrentIndex(max(0, self.llm.findData(dock.llm_profile)))
        self.sandbox = QComboBox()
        self.sandbox.addItem(tr("(no sandbox)"), "")
        for name in sandboxes:
            self.sandbox.addItem(name, name)
        self.sandbox.setCurrentIndex(max(0, self.sandbox.findData(dock.sandbox)))
        self.policy = QComboBox()
        for key, label in (("never", tr("Never send - drafts only")),
                           ("ask", tr("Ask me before each mail")),
                           ("allowed", tr("Answer the sender without asking (others: ask)"))):
            self.policy.addItem(label, key)
        self.policy.setCurrentIndex(max(0, self.policy.findData(dock.send_policy)))
        self.allow = QLineEdit(", ".join(dock.send_allow))
        self.allow.setPlaceholderText(tr("also without asking: boss@example.org, @example.org"))
        self.smtp_host = QLineEdit(dock.smtp_host)
        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(int(dock.smtp_port))
        self.smtp_security = QComboBox()
        for key, label in (("starttls", "STARTTLS"), ("ssl", "TLS (SMTPS)"), ("plain", tr("none (this machine only)"))):
            self.smtp_security.addItem(label, key)
        self.smtp_security.setCurrentIndex(max(0, self.smtp_security.findData(dock.smtp_security)))
        self.smtp_user = QLineEdit(dock.smtp_username)
        self.smtp_password = QLineEdit()
        self.smtp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.smtp_password.setPlaceholderText(tr("unchanged") if MD.smtp_password(dock) else "")
        self.from_address = QLineEdit(dock.from_address)
        self.report_to = QLineEdit(", ".join(dock.report_to))
        self.report_to.setPlaceholderText(", ".join(docks) or tr("names of other mail docks"))
        self.dns_checks = QCheckBox(tr("Check SPF / DKIM / DMARC in DNS (shows the DNS servers which domains you look at)"))
        self.dns_checks.setChecked(dock.dns_checks)
        self.enabled = QCheckBox(tr("Run on its timer"))
        self.enabled.setChecked(dock.enabled)
        for label, w in ((tr("Name:"), self.name), (tr("Mailbox:"), self.mailbox), (tr("Folder:"), self.folder),
                         (tr("Every:"), self.interval), (tr("Instructions:"), self.instructions),
                         (tr("LLM:"), self.llm), (tr("Sandbox:"), self.sandbox), (tr("Sending:"), self.policy),
                         (tr("Allowed recipients:"), self.allow), (tr("SMTP server:"), self.smtp_host),
                         (tr("SMTP port:"), self.smtp_port), (tr("SMTP security:"), self.smtp_security),
                         (tr("SMTP user:"), self.smtp_user), (tr("SMTP password:"), self.smtp_password),
                         (tr("From:"), self.from_address), (tr("Reports to:"), self.report_to),
                         ("", self.dns_checks), ("", self.enabled)):
            form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        add_close_corner(self)
        self.result_dock: MD.MailDockConfig | None = None

    def config(self) -> MD.MailDockConfig:
        def names(text):
            return [p.strip() for p in text.split(",") if p.strip()]
        return dataclasses.replace(
            self._dock, name=self.name.text().strip(), mailbox_profile=self.mailbox.currentText(),
            folder=self.folder.text().strip() or "INBOX", interval_minutes=self.interval.value(),
            instructions=self.instructions.toPlainText().strip(), llm_profile=self.llm.currentData() or "",
            sandbox=self.sandbox.currentData() or "", send_policy=self.policy.currentData(),
            send_allow=names(self.allow.text()), smtp_host=self.smtp_host.text().strip(),
            smtp_port=self.smtp_port.value(), smtp_security=self.smtp_security.currentData(),
            smtp_username=self.smtp_user.text().strip(), from_address=self.from_address.text().strip(),
            report_to=names(self.report_to.text()), dns_checks=self.dns_checks.isChecked(),
            enabled=self.enabled.isChecked())

    def _accept(self) -> None:
        dock = self.config()
        try:
            dock.validate()
        except ValueError as exc:
            QMessageBox.warning(self, tr("Mail Dock"), str(exc))
            return
        if self.smtp_password.text():
            MD.store_smtp_password(dock, self.smtp_password.text())
        self.result_dock = dock
        self.accept()


class MailDocks(QObject):
    """The mail docks of a main window: made at start, kept in sync with
    the settings file, one ExtensionDock each."""

    EXT_ID = "core:mail-docks"

    def __init__(self, window, *, store: MD.MailDockStore | None = None, runner_factory=MailDockRunner):
        super().__init__(window)
        self.window = window
        self.store = store or MD.MailDockStore()
        self.runner_factory = runner_factory
        self.panels: dict[str, tuple] = {}     # dock_id -> (ExtensionDock, MailDockPanel)

    def start(self) -> None:
        for dock in self.store.load():
            self._open(dock)

    def _choices(self) -> dict:
        try:
            from core.profiles import ProfileManager

            pm = ProfileManager()
            mailboxes = [n for n in pm.list_names() if (pm.get(n) and pm.get(n).protocol in ("imap", "pop3", "exchange"))]
        except Exception:  # noqa: BLE001
            mailboxes = []
        try:
            from core import llm_profiles as LP

            llms = [p.name for p in LP.LLMSettings.load().profiles]
        except Exception:  # noqa: BLE001
            llms = []
        try:
            from core import agent_settings as AGS

            sandboxes = [p.name for p in AGS.AgentSettings.load().sandboxes]
        except Exception:  # noqa: BLE001
            sandboxes = []
        return {"mailboxes": mailboxes, "llms": llms, "sandboxes": sandboxes,
                "docks": [d.name for d in self.store.load()]}

    def _open(self, dock: MD.MailDockConfig):
        from ui.dock_titlebar import DockTitleBar
        from ui.extension_panels import ExtensionDock

        if dock.dock_id in self.panels:
            ext, panel = self.panels[dock.dock_id]
            ext.show()
            ext.raise_()
            return panel
        ext = ExtensionDock(tr("Mail: {name}").format(name=dock.name), self.window, self.EXT_ID)
        ext.setObjectName(f"mail-dock-{dock.dock_id}")
        # The built-in panels' title bar, with the dock's own icon.
        ext.setTitleBarWidget(DockTitleBar(ext.windowTitle(), "mail", ext,
                                           reopen_hint="Tools → Mail Docks…"))
        panel = MailDockPanel(dock, runner_factory=self.runner_factory, edit=self.edit_panel)
        ext.setWidget(panel)
        add = getattr(self.window, "addDockWidget", None)
        if callable(add):
            add(Qt.DockWidgetArea.RightDockWidgetArea, ext)
        self.panels[dock.dock_id] = (ext, panel)
        return panel

    def add(self) -> MD.MailDockConfig | None:
        dock = MD.MailDockConfig(name=tr("Mail {n}").format(n=len(self.panels) + 1))
        dialog = MailDockDialog(dock, parent=self.window, **self._choices())
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.result_dock is None:
            return None
        docks = self.store.load() + [dialog.result_dock]
        self.store.save(docks)
        self._open(dialog.result_dock)
        return dialog.result_dock

    def edit_panel(self, panel: MailDockPanel) -> None:
        dialog = MailDockDialog(panel.dock, parent=self.window, **self._choices())
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.result_dock is None:
            return
        docks = [dialog.result_dock if d.dock_id == panel.dock.dock_id else d for d in self.store.load()]
        self.store.save(docks)
        panel.apply(dialog.result_dock)
        ext, _ = self.panels[panel.dock.dock_id]
        ext.setWindowTitle(tr("Mail: {name}").format(name=dialog.result_dock.name))
        bar = ext.titleBarWidget()
        if hasattr(bar, "set_title"):
            bar.set_title(ext.windowTitle())

    def remove(self, dock_id: str) -> None:
        self.store.save([d for d in self.store.load() if d.dock_id != dock_id])
        ext, panel = self.panels.pop(dock_id, (None, None))
        if panel is not None:
            panel.shutdown()
            ext.close()
            ext.deleteLater()

    def manage(self) -> None:
        """Tools > Mail Docks…: the list, with Add / Show / Remove."""
        dialog = QDialog(self.window)
        dialog.setWindowTitle(tr("Mail Docks"))
        set_window_icon(dialog, "mail")
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(tr("Each mail dock is an agent that watches one mailbox and follows its "
                                   "instructions: read, analyse, draft, send as its policy allows, "
                                   "report to other docks.")))
        listing = QListWidget()
        layout.addWidget(listing)

        def fill():
            listing.clear()
            for d in self.store.load():
                item = QListWidgetItem(f"{d.name} - {d.mailbox_profile}/{d.folder} ({d.send_policy})")
                item.setData(Qt.ItemDataRole.UserRole, d.dock_id)
                listing.addItem(item)
        fill()
        row = QHBoxLayout()
        for label, action in ((tr("Add…"), lambda: (self.add(), fill())),
                              (tr("Show"), lambda: listing.currentItem() and self._open(next(
                                  d for d in self.store.load()
                                  if d.dock_id == listing.currentItem().data(Qt.ItemDataRole.UserRole)))),
                              (tr("Remove"), lambda: listing.currentItem() and (
                                  self.remove(listing.currentItem().data(Qt.ItemDataRole.UserRole)), fill()))):
            b = QPushButton(label)
            b.clicked.connect(action)
            row.addWidget(b)
        row.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(dialog.accept)
        row.addWidget(close)
        layout.addLayout(row)
        add_close_corner(dialog)
        dialog.resize(560, 320)
        dialog.exec()

    def shutdown(self) -> None:
        for _ext, panel in self.panels.values():
            panel.shutdown()
