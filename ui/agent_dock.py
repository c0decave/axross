"""Agent dock: a local LLM works with axross through the MCP tools.

The conversation runs on a background thread (core.agent.Agent). The
user chooses what the model may use: the read-only file tools always,
capability groups by tick, changes and remote commands only when their
box is ticked - and even then every such call waits for a Yes in a
dialog that shows the tool and its arguments (secrets masked). Closing
the dock or Stop answers No to a waiting question and ends the run
between two steps.

What the model and the tools return is shown as plain text: it comes
from files and servers and can be hostile.
"""

from __future__ import annotations

import html
import json
import logging
import os
import threading
from typing import Callable

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import agent as A
from core import llm_profiles as LP
from core.i18n import tr

log = logging.getLogger(__name__)

#: Groups a user may offer; exec has its own box, scripts are never offered.
OFFERED_GROUPS = ("metadata", "filetype", "archive", "duplicates", "index", "packer", "crypto",
                  "transfer", "remote")
#: Ticked in a fresh dock: read-only use of these is harmless.
DEFAULT_GROUPS = ("metadata", "filetype", "archive")


def _ask_call(parent, name: str, args: dict) -> bool:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Question)
    box.setWindowTitle(tr("Allow this action?"))
    box.setTextFormat(Qt.TextFormat.PlainText)  # the arguments come from the model
    box.setText(tr("The model wants to run {tool}.").format(tool=name))
    box.setDetailedText(json.dumps(args, indent=2, ensure_ascii=False))
    box.setInformativeText(json.dumps(args, ensure_ascii=False)[:600])
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    try:
        return box.exec() == QMessageBox.StandardButton.Yes
    finally:
        box.deleteLater()


def _ask_remote(parent, profile: LP.LLMProfile, host: str) -> bool:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(tr("Send file content to a remote LLM?"))
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setText(
        tr("The profile {name} talks to {host}. What the tools read is sent there.").format(
            name=profile.name, host=host
        )
    )
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    try:
        return box.exec() == QMessageBox.StandardButton.Yes
    finally:
        box.deleteLater()


class _Bridge(QObject):
    """Carries the worker thread's events to the GUI thread."""

    event = pyqtSignal(object)
    finished = pyqtSignal(object, str)
    confirm = pyqtSignal(str, object, object)


class AgentDock(QDockWidget):
    settings_requested = pyqtSignal()

    def __init__(
        self,
        parent=None,
        *,
        settings_loader: Callable[[], LP.LLMSettings] | None = None,
        settings_saver: Callable[[LP.LLMSettings], None] | None = None,
        key_lookup: Callable[[str], str] | None = None,
        confirm_remote: Callable[[LP.LLMProfile, str], bool] | None = None,
        confirm_call: Callable[[str, dict], bool] | None = None,
        root_provider: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(tr("Agent"), parent)
        self.setObjectName("axAgentDock")
        self._load_settings = settings_loader or LP.LLMSettings.load
        self._save_settings = settings_saver or (lambda s: s.save())
        self._key_lookup = key_lookup or LP.get_api_key
        self._confirm_remote = confirm_remote or (lambda p, h: _ask_remote(self, p, h))
        self._confirm_call = confirm_call or (lambda n, a: _ask_call(self, n, a))
        self._root_provider = root_provider or (lambda: os.path.expanduser("~"))
        self._profile: LP.LLMProfile | None = None
        self._agent: A.Agent | None = None
        self._agent_key: tuple | None = None
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        #: The confirmation the worker waits for: {"done": Event, "yes": bool}.
        self._pending: dict | None = None
        self._bridge = _Bridge()
        self._bridge.event.connect(self._on_event)
        self._bridge.finished.connect(self._on_finished)
        self._bridge.confirm.connect(self._on_confirm)

        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(6, 6, 6, 6)
        head = QHBoxLayout()
        self.profile_label = QLabel()
        self.profile_label.setTextFormat(Qt.TextFormat.PlainText)
        self.settings_button = QPushButton(tr("LLM…"))
        self.settings_button.setToolTip(tr("LLM profiles"))
        self.settings_button.clicked.connect(self.settings_requested.emit)
        head.addWidget(self.profile_label, 1)
        head.addWidget(self.settings_button)
        layout.addLayout(head)

        root_row = QHBoxLayout()
        root_row.addWidget(QLabel(tr("Folder:")))
        self.root_edit = QLineEdit(self._root_provider())
        self.root_edit.setToolTip(tr("Local files are reachable only inside this folder"))
        root_row.addWidget(self.root_edit, 1)
        layout.addLayout(root_row)

        self.groups = QListWidget()
        self.groups.setMaximumHeight(110)
        for group in OFFERED_GROUPS:
            item = QListWidgetItem(group)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if group in DEFAULT_GROUPS else Qt.CheckState.Unchecked)
            self.groups.addItem(item)
        layout.addWidget(self.groups)
        self.allow_write = QCheckBox(tr("Allow changes to files (asks every time)"))
        self.allow_exec = QCheckBox(tr("Allow remote commands (asks every time)"))
        from core.security_mode import current_policy

        if not current_policy().allow_remote_exec:
            self.allow_exec.setEnabled(False)
            self.allow_exec.setToolTip(tr("The security mode blocks remote commands"))
        layout.addWidget(self.allow_write)
        layout.addWidget(self.allow_exec)

        self.transcript = QTextBrowser()
        self.transcript.setOpenLinks(False)
        self.transcript.setOpenExternalLinks(False)
        layout.addWidget(self.transcript, 1)
        self.input = QPlainTextEdit()
        self.input.setPlaceholderText(tr("What should the agent do?"))
        self.input.setMaximumHeight(90)
        layout.addWidget(self.input)
        buttons = QHBoxLayout()
        self.new_button = QPushButton(tr("New conversation"))
        self.new_button.clicked.connect(self.new_conversation)
        self.stop_button = QPushButton(tr("Stop"))
        self.stop_button.clicked.connect(self.stop)
        self.send_button = QPushButton(tr("Send"))
        self.send_button.clicked.connect(self.send)
        buttons.addWidget(self.new_button)
        buttons.addStretch(1)
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.send_button)
        layout.addLayout(buttons)
        self.setWidget(body)
        self.refresh_profiles()
        self._update_buttons()

    # -- state ---------------------------------------------------------------
    def refresh_profiles(self) -> None:
        try:
            self._profile = self._load_settings().active_profile()
        except Exception:  # a broken settings file must not break the dock
            log.exception("LLM settings could not be read")
            self._profile = None
        self.profile_label.setText(
            tr("Model: {name}").format(name=self._profile.name) if self._profile
            else tr("No LLM profile is active: set one up with LLM…")
        )
        self._update_buttons()

    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _update_buttons(self) -> None:
        busy = self.busy()
        self.send_button.setEnabled(not busy and self._profile is not None)
        self.stop_button.setEnabled(busy)
        self.new_button.setEnabled(not busy)

    def selected_groups(self) -> frozenset:
        return frozenset(
            self.groups.item(i).text()
            for i in range(self.groups.count())
            if self.groups.item(i).checkState() == Qt.CheckState.Checked
        )

    def _config(self) -> A.AgentConfig:
        groups = set(self.selected_groups())
        allow_exec = self.allow_exec.isEnabled() and self.allow_exec.isChecked()
        if allow_exec:
            groups |= {"exec", "remote"}
        try:
            key = self._key_lookup(self._profile.name) or ""
        except Exception:
            log.exception("API key lookup failed for %s", self._profile.name)
            key = ""
        return A.AgentConfig(
            profile=self._profile,
            api_key=key,
            root=os.path.abspath(os.path.expanduser(self.root_edit.text().strip() or "~")),
            groups=frozenset(groups),
            allow_write=self.allow_write.isChecked(),
            allow_exec=allow_exec,
        )

    def _append(self, who: str, text: str, *, muted: bool = False) -> None:
        color = "#888" if muted else "inherit"
        self.transcript.append(
            f'<p style="color:{color}"><b>{html.escape(who)}</b> '
            f"{html.escape(text).replace(chr(10), '<br>')}</p>"
        )

    # -- actions -------------------------------------------------------------
    def new_conversation(self) -> None:
        if self.busy():
            return
        self._agent = None
        self._agent_key = None
        self.transcript.clear()

    def send(self) -> None:
        task = self.input.toPlainText().strip()
        if not task or self.busy():
            return
        self.refresh_profiles()
        profile = self._profile
        if profile is None:
            self._append(tr("axross:"), tr("No LLM profile is active."), muted=True)
            return
        if profile.needs_consent():
            host = profile.host() or profile.resolved_endpoint()
            if not self._confirm_remote(profile, host):
                return
            profile.consent()  # for this conversation; the profile dialog stores it for good
        config = self._config()
        key = (profile.name, profile.consent_key(), config.root, config.groups,
               config.allow_write, config.allow_exec)
        if self._agent is None or key != self._agent_key:
            if self._agent is not None:
                self._append(tr("axross:"), tr("New settings: a new conversation starts."), muted=True)
            self._cancel = threading.Event()
            self._agent = A.Agent(config, confirm=self._wait_for_answer,
                                  on_event=self._bridge.event.emit, cancel=self._cancel)
            self._agent_key = key
        self._cancel.clear()
        self.input.clear()
        self._append(tr("You:"), task)
        agent = self._agent

        def work() -> None:
            try:
                result = agent.run(task)
                self._bridge.finished.emit(result, "")
            except A.AgentError as exc:
                self._bridge.finished.emit(None, str(exc))
            except Exception as exc:  # noqa: BLE001 - the dock must survive anything
                log.exception("agent run failed")
                self._bridge.finished.emit(None, f"{type(exc).__name__}: {exc}")

        self._thread = threading.Thread(target=work, name="axross-agent", daemon=True)
        self._thread.start()
        self._update_buttons()

    def stop(self) -> None:
        self._cancel.set()
        self._answer(False)

    def shutdown(self) -> None:
        self.stop()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # -- confirmation across threads --------------------------------------------
    def _wait_for_answer(self, name: str, args: dict) -> bool:
        """Called on the worker thread: ask on the GUI thread, wait for it."""
        pending = {"done": threading.Event(), "yes": False}
        self._bridge.confirm.emit(name, args, pending)
        while not pending["done"].wait(0.1):
            if self._cancel.is_set():
                return False
        return bool(pending["yes"]) and not self._cancel.is_set()

    def _on_confirm(self, name: str, args: object, pending: object) -> None:
        self._pending = pending
        if self._cancel.is_set():
            self._answer(False)
            return
        tool = self._agent._tools.get(name) if self._agent is not None else None
        shown = A._shown(args, tool.schema if tool is not None else {})
        try:
            yes = bool(self._confirm_call(name, shown))
        except Exception:  # noqa: BLE001 - a broken dialog is a No
            log.exception("confirmation dialog failed")
            yes = False
        self._answer(yes)

    def _answer(self, yes: bool) -> None:
        pending, self._pending = self._pending, None
        if pending is not None:
            pending["yes"] = yes
            pending["done"].set()

    # -- events ---------------------------------------------------------------
    def _on_event(self, event: dict) -> None:
        kind = event.get("type")
        if kind == "assistant":
            self._append(tr("Agent:"), str(event.get("text", "")))
        elif kind == "tool_call":
            args = json.dumps(event.get("args", {}), ensure_ascii=False)
            self._append("→", f"{event.get('name')} {args[:300]}", muted=True)
        elif kind == "tool_result":
            self._append("←", f"{event.get('name')}: {event.get('outcome')}", muted=True)

    def _on_finished(self, result, error: str) -> None:
        self._thread = None
        if error:
            self._append(tr("axross:"), error, muted=True)
        elif result is not None:
            # The answer itself arrived as an "assistant" event.
            if result.stopped == "max_steps":
                self._append(tr("axross:"), tr("Stopped after the step limit."), muted=True)
            elif result.stopped == "cancelled":
                self._append(tr("axross:"), tr("Stopped."), muted=True)
        self._update_buttons()
