"""Mail docks in the window (Tools > Mail Docks…): one panel per dock -
what it watches, when it runs next, its log (with the agent's tool calls),
Run Now / Stop / Pause / Settings / Open Drafts Folder, and the mails it
wants to send waiting for Send or Don't Send (send policy "ask", or a
recipient outside "allowed"). core.mail_dock has the rules,
core.mail_dock_runner does a run on a thread of its own.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
import time

from PyQt6.QtCore import QObject, QSignalBlocker, Qt, QTimer
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
from ui.handbook import install_help_key
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: A mail waiting for the user's yes is declined after this long.
APPROVAL_TIMEOUT_S = 30 * 60
#: A tool call's arguments in the dock's log are cut after this many characters.
EVENT_ARGS_CHARS = 160


def event_text(event: dict) -> str | None:
    """One line of the dock's log for an agent event (core.agent on_event):
    the tool calls and their outcome, notices and a failed connection - what
    the dock's agent did, not only its final answer. None for the rest
    (usage counts, the streamed answer: the runner logs the answer)."""
    kind = event.get("type")
    if kind == "tool_call":
        try:
            args = json.dumps(event.get("args") or {}, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            args = ""
        if len(args) > EVENT_ARGS_CHARS:
            args = args[:EVENT_ARGS_CHARS] + "…"
        return tr("Tool: {name} {args}").format(name=event.get("name", "?"), args=args).rstrip()
    if kind == "tool_result" and event.get("outcome") not in (None, "ok"):
        reason = event.get("reason") or event.get("detail") or ""
        return tr("Tool {name}: {outcome} {reason}").format(
            name=event.get("name", "?"), outcome=event.get("outcome"), reason=reason).rstrip()
    if kind == "notice" and event.get("text"):
        return str(event["text"])
    if kind == "connection" and event.get("state") == "failed":
        return tr("The LLM could not be reached: {detail}").format(detail=event.get("detail", ""))
    return None


class _Approval:
    def __init__(self, summary: str):
        self.summary = summary
        self.event = threading.Event()
        self.answer = False


class MailDockPanel(QWidget):
    """The content of one mail dock's panel.

    *save* stores the dock's settings when Pause changes them (the dock's
    ``enabled``): a pause that was not saved came back unpaused at the next
    start, while the same switch in the settings dialog stayed."""

    def __init__(self, dock: MD.MailDockConfig, *, runner_factory=MailDockRunner, edit=None, save=None,
                 parent=None):
        super().__init__(parent)
        self.dock = dock
        self._edit = edit
        self._save = save
        self._pending: list[_Approval] = []
        self._post_log = GuiCall(self._log)
        self._post_event = GuiCall(self._event)
        self._post_approval = GuiCall(self._show_approval)
        self._post_done = GuiCall(self._done)
        self.runner = runner_factory(dock, ask_send=self._ask_send, on_log=self._post_log,
                                     on_event=self._post_event)
        self._running = False
        self.paused = not dock.enabled
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.run_button = QPushButton(tr("Run Now"))
        self.run_button.clicked.connect(self.run_now)
        self.stop_button = QPushButton(tr("Stop"))
        self.stop_button.setToolTip(tr("Stop the run in progress; a mail waiting for your answer is not sent"))
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop)
        self.pause_button = QPushButton(tr("Pause"))
        self.pause_button.setCheckable(True)
        self.pause_button.setChecked(self.paused)
        self.pause_button.toggled.connect(self._toggle_pause)
        settings = QPushButton(tr("Settings…"))
        settings.clicked.connect(lambda: self._edit and self._edit(self))
        self.drafts_button = QPushButton(tr("Open Drafts Folder"))
        self.drafts_button.setToolTip(
            tr("The drafts of a POP3 mailbox (an IMAP mailbox keeps them in its Drafts folder)"))
        self.drafts_button.clicked.connect(self.open_drafts_folder)
        for b in (self.run_button, self.stop_button, self.pause_button, settings, self.drafts_button):
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
        """New settings: the interval, and "Run on its timer" as the pause -
        before, unticking it changed nothing until the next start."""
        self.dock = self.runner.dock = dock
        self.paused = not dock.enabled
        with QSignalBlocker(self.pause_button):
            self.pause_button.setChecked(self.paused)
        self._restart_timer()

    def _restart_timer(self) -> None:
        """The timer runs only while the dock is not paused."""
        if self.paused:
            self.timer.stop()
        else:
            self.timer.start(int(self.dock.interval_minutes) * 60 * 1000)
            self._next = time.time() + self.dock.interval_minutes * 60
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
        self.dock = self.runner.dock = dataclasses.replace(self.dock, enabled=not paused)
        if self._save is not None:
            try:
                self._save(self.dock)
            except OSError as exc:
                self._log(tr("Could not save the setting: {error}").format(error=exc))
        self._restart_timer()

    def stop(self) -> None:
        """Stop the run in progress (the runner's cancel; the agent stops at
        its next step). A mail waiting for Send / Don't Send is not sent."""
        if not self._running:
            return
        cancel = getattr(self.runner, "cancel", None)
        if cancel is not None:
            cancel.set()
        self._decline_waiting()
        self.stop_button.setEnabled(False)
        self._log(tr("Stopping…"))

    def drafts_folder(self):
        """Where the dock's agent puts its drafts for a POP3 mailbox
        (core.mail_dock.MailTools.draft)."""
        from pathlib import Path

        state = getattr(self.runner, "state_dir", None)
        return Path(state if state is not None else MD.STATE_DIR / self.dock.dock_id) / "drafts"

    def open_drafts_folder(self) -> None:
        """The drafts folder in a pane of the window (made when missing)."""
        folder = self.drafts_folder()
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._log(tr("Could not create {folder}: {error}").format(folder=folder, error=exc))
            return
        window = self.parentWidget()
        while window is not None and not callable(getattr(window, "open_local_folder", None)):
            window = window.parentWidget()  # the main window, also from a floating dock
        opener = getattr(window, "open_local_folder", None)
        if callable(opener):
            opener(str(folder))
        else:
            from PyQt6.QtCore import QUrl

            from core.desktop_open import open_url

            open_url(QUrl.fromLocalFile(str(folder)))

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
        self.stop_button.setEnabled(True)
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
        self.stop_button.setEnabled(False)
        if error:
            self._log(tr("The run failed: {error}").format(error=error))
        self._status()

    def _log(self, text: str) -> None:
        self.log_view.appendPlainText(f"{time.strftime('%H:%M')}  {text}")

    def _event(self, event: dict) -> None:
        text = event_text(event) if isinstance(event, dict) else None
        if text:
            self._log(text)

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

    def _decline_waiting(self) -> None:
        """Every mail waiting for an answer: not sent."""
        for approval in self._pending:
            approval.answer = False
            approval.event.set()
        self._pending.clear()
        self.approvals.clear()
        for w in (self.approvals, self.send_button, self.decline_button):
            w.setVisible(False)

    def shutdown(self) -> None:
        self.timer.stop()
        for approval in self._pending:
            approval.event.set()
        self.runner.close()


#: Item data role marking a combo entry for a saved name that is gone.
_MISSING_ROLE = Qt.ItemDataRole.UserRole + 1


def _select_saved(combo: QComboBox, name: str) -> None:
    """Select the entry for the saved *name*; a name the list no longer
    has is added as "<name> (missing)" and selected, never replaced by the
    first entry."""
    index = combo.findData(name)
    if index < 0 and name:
        combo.addItem(tr("{name} (missing)").format(name=name), name)
        index = combo.count() - 1
        combo.setItemData(index, True, _MISSING_ROLE)
    combo.setCurrentIndex(max(0, index))


class MailDockDialog(QDialog):
    """The settings of one mail dock."""

    def __init__(self, dock: MD.MailDockConfig, *, mailboxes: list[str], llms: list[str], sandboxes: list[str],
                 docks: list[str], parent=None):
        super().__init__(parent)
        set_window_icon(self, "mail")
        install_help_key(self, "mail")
        self.setWindowTitle(tr("Mail Dock"))
        self._dock = dock
        form = QFormLayout(self)
        self.name = QLineEdit(dock.name)
        self.mailbox = QComboBox()
        for name in mailboxes:
            self.mailbox.addItem(name, name)
        _select_saved(self.mailbox, dock.mailbox_profile)
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
        _select_saved(self.llm, dock.llm_profile)
        self.sandbox = QComboBox()
        self.sandbox.addItem(tr("(no sandbox)"), "")
        for name in sandboxes:
            self.sandbox.addItem(name, name)
        _select_saved(self.sandbox, dock.sandbox)
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
            self._dock, name=self.name.text().strip(), mailbox_profile=self.mailbox.currentData() or "",
            folder=self.folder.text().strip() or "INBOX", interval_minutes=self.interval.value(),
            instructions=self.instructions.toPlainText().strip(), llm_profile=self.llm.currentData() or "",
            sandbox=self.sandbox.currentData() or "", send_policy=self.policy.currentData(),
            send_allow=names(self.allow.text()), smtp_host=self.smtp_host.text().strip(),
            smtp_port=self.smtp_port.value(), smtp_security=self.smtp_security.currentData(),
            smtp_username=self.smtp_user.text().strip(), from_address=self.from_address.text().strip(),
            report_to=names(self.report_to.text()), dns_checks=self.dns_checks.isChecked(),
            enabled=self.enabled.isChecked())

    def missing_choices(self) -> list[str]:
        """The saved mailbox / LLM / sandbox names this dialog shows as
        "(missing)": renamed or deleted since the dock was set up."""
        return [f"{label} {combo.currentData()}"
                for label, combo in ((tr("Mailbox:"), self.mailbox), (tr("LLM:"), self.llm),
                                     (tr("Sandbox:"), self.sandbox))
                if combo.currentData(_MISSING_ROLE)]

    def _accept(self) -> None:
        missing = self.missing_choices()
        if missing:
            # Before, OK put the first entry in place of a name that is gone:
            # a renamed sandbox profile became "(no sandbox)" without a word.
            QMessageBox.warning(self, tr("Mail Dock"), tr(
                "This dock names a mailbox, LLM or sandbox profile that no longer exists:\n\n"
                "{names}\n\nChoose one from the list (or \"{none}\" on purpose) before "
                "saving.").format(names="\n".join(missing), none=tr("(no sandbox)")))
            return
        dock = self.config()
        if not dock.mailbox_profile.strip():
            # Before, a dock without a mailbox was saved and failed at every run.
            QMessageBox.warning(self, tr("Mail Dock"), tr(
                "A mail dock watches a mailbox: choose one. Without one in the list, first save "
                "an IMAP, POP3 or Exchange connection in the Connection Manager."))
            return
        try:
            dock.validate()
        except ValueError as exc:
            # validate() speaks English (core); its sentences are in the catalogue.
            QMessageBox.warning(self, tr("Mail Dock"), tr(str(exc)))
            return
        if self.smtp_password.text() and not MD.store_smtp_password(dock, self.smtp_password.text()):
            # Before, the password was dropped without a word when no
            # keyring was usable, and every send failed at its login.
            from core import credentials

            QMessageBox.warning(self, tr("Mail Dock"), tr(
                "The SMTP password was not saved: no usable keyring.\n\n{why}\n\nThe other "
                "settings are saved; enter the password again once the keyring works.").format(
                    why=credentials.keyring_status_message()))
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
        panel = MailDockPanel(dock, runner_factory=self.runner_factory, edit=self.edit_panel,
                              save=self._save_dock)
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

    def _save_dock(self, dock: MD.MailDockConfig) -> None:
        """*dock*'s settings into the store, in its place among the others."""
        self.store.save([dock if d.dock_id == dock.dock_id else d for d in self.store.load()])

    def edit(self, dock_id: str) -> None:
        """The settings of the dock *dock_id* (the manager's Edit…)."""
        dock = next((d for d in self.store.load() if d.dock_id == dock_id), None)
        if dock is None:
            return
        self.edit_panel(self._open(dock))

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
        install_help_key(dialog, "mail")
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
        def selected() -> str | None:
            item = listing.currentItem()
            return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

        for label, action in ((tr("Add…"), lambda: (self.add(), fill())),
                              (tr("Edit…"), lambda: selected() and (self.edit(selected()), fill())),
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
