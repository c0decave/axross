"""Agent dock: a local LLM works with axross through the MCP tools.

Every tab is a session of its own (core.agent_session): its conversation,
LLM profile, protection mode, sandbox, folder and tools. Tabs are kept in
one JSON file each and come back at the next start when "Keep tabs" is on
(Tools > Agent Settings…).

Protection modes:

* **Ask** - every change and every remote command waits for Yes.
* **Plan** - the agent may only read; it answers with a plan, and
  "Run this plan" carries it out in Ask mode.
* **Auto** - changes run without asking, remote commands still ask.
* **Bypass** - nothing asks. Only when Agent Settings allow it, never in
  the paranoid security mode, and the tab says so in red.

A task runs on a background thread (core.agent.Agent, or
core.agent_sandbox.SandboxedAgent when the tab has a sandbox). Closing a
tab or Stop answers No to a waiting question and ends the run between two
steps. What the model and the tools return is shown as plain text: it
comes from files and servers and can be hostile.
"""

from __future__ import annotations

import html
import json
import logging
import os
import threading
import time
from typing import Callable

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDockWidget,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import agent as A
from core import agent_access as X
from core import agent_settings as AGS
from core import llm_profiles as LP
from core.agent_session import AgentSession, SessionStore
from core.mcp_client import McpClientPool
from core.i18n import tr

log = logging.getLogger(__name__)

#: Groups a tab may offer; exec has its own box, scripts are never offered.
OFFERED_GROUPS = ("metadata", "filetype", "archive", "duplicates", "index", "packer", "crypto",
                  "transfer", "remote")
#: The Tools-list lines of further MCP servers: "mcp:<name>".
MCP_PREFIX = "mcp:"
#: The Tools-list lines of extensions with agent tools: "ext:<extension id>".
EXT_PREFIX = "ext:"
#: Ticked in a fresh tab: read-only use of these is harmless.
DEFAULT_GROUPS = AGS.DEFAULT_GROUPS
#: Tools that run something on a remote host: Auto still asks for them.
EXEC_TOOLS = frozenset({"remote_exec", "remote_script"})
MODE_NAMES = {"ask": "Ask", "plan": "Plan", "auto": "Auto", "bypass": "Bypass"}
PLAN_PROMPT = (
    "\nPlan mode: you cannot change anything now. Investigate with the read tools, then answer "
    "with a numbered plan of the exact changes and commands you would make, and wait."
)
RUN_PLAN_TASK = "Carry out the plan above, step by step. Report what you changed."
#: Most tasks kept for the Up key.
HISTORY_LIMIT = 50


def _ask_user(parent, question: str) -> str | None:
    from PyQt6.QtWidgets import QInputDialog

    text, ok = QInputDialog.getMultiLineText(parent, tr("The agent asks"), question)
    return text if ok else None


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


def bypass_allowed(settings: AGS.AgentSettings) -> bool:
    from core.security_mode import is_paranoid

    return settings.allow_bypass and not is_paranoid()


class _Bridge(QObject):
    """Carries the worker thread's events to the GUI thread."""

    event = pyqtSignal(object)
    finished = pyqtSignal(object, str)
    confirm = pyqtSignal(str, object, object)
    ask = pyqtSignal(str, object)


class _TaskInput(QPlainTextEdit):
    """Ctrl+Enter sends, Up in an empty field brings the last task back,
    files dropped here are attached instead of typed."""

    submit = pyqtSignal()
    recall = pyqtSignal(int)
    dropped = pyqtSignal(object)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        key = event.key()
        mods = event.modifiers()
        if (
            key in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and mods & Qt.KeyboardModifier.ControlModifier
        ):
            self.submit.emit()
            return
        if key in (Qt.Key.Key_Up, Qt.Key.Key_Down) and not mods and (
            not self.toPlainText() or getattr(self, "_recalling", False)
        ):
            self.recall.emit(-1 if key == Qt.Key.Key_Up else 1)
            return
        self._recalling = False
        super().keyPressEvent(event)

    def canInsertFromMimeData(self, source) -> bool:  # noqa: N802 - Qt override
        return _dropped_paths(source) is not None or super().canInsertFromMimeData(source)

    def insertFromMimeData(self, source) -> None:  # noqa: N802 - Qt override
        found = _dropped_paths(source)
        if found is not None:
            self.dropped.emit(found)
            return
        super().insertFromMimeData(source)


def _dropped_paths(mime):
    """``{"paths": [...], "source_pane_id": str|None}`` for a pane drag or
    local files dropped from elsewhere; None for anything else."""
    if mime is None:
        return None
    from ui.file_pane import decode_transfer_payload

    payload = decode_transfer_payload(mime)
    if payload is not None:
        return {"paths": list(payload["paths"]), "source_pane_id": payload.get("source_pane_id"),
                "dirs": list(payload.get("dirs") or [])}
    if mime.hasUrls():
        paths = [u.toLocalFile() for u in mime.urls() if u.isLocalFile()]
        if paths:
            return {
                "paths": paths,
                "source_pane_id": None,
                "dirs": [p for p in paths if os.path.isdir(p)],
            }
    return None


class AgentTab(QWidget):
    """One session: its conversation, settings and controls."""

    changed = pyqtSignal()
    busy_changed = pyqtSignal(bool)
    title_changed = pyqtSignal(str)

    def __init__(self, dock: AgentDock, session: AgentSession) -> None:
        super().__init__()
        self.dock = dock
        self.session = session
        self._agent = None
        self._agent_key: tuple | None = None
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        #: The questions waiting for the user: each its own slot (a dialog's
        #: nested event loop can bring a second one while the first is open).
        self._pending: list[dict] = []
        self._root_typed = bool(session.folder)
        self._history: list[str] = [
            e["text"] for e in session.transcript if e.get("who") == tr("You:")
        ]
        self._recall_index = len(self._history)
        self._attachments: list[dict] = []
        self._started = 0.0
        self._tool_calls = 0
        self._steps = 0
        self._plan_ready = False
        #: ``on_done(answer, error)`` of the running task (an extension's run_agent).
        self._done: list = []
        self._bridge = _Bridge()
        self._bridge.event.connect(self._on_event)
        self._bridge.finished.connect(self._on_finished)
        self._bridge.confirm.connect(self._on_confirm)
        self._bridge.ask.connect(self._on_ask)
        self._clock = QTimer(self)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._update_status)
        self._build()
        self._load_session()

    # -- widgets -----------------------------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        head = QHBoxLayout()
        self.model_combo = QComboBox()
        self.model_combo.setToolTip(tr("LLM profile of this tab"))
        self.mode_combo = QComboBox()
        self.mode_combo.setToolTip(tr("Protection mode: what runs without asking"))
        self.sandbox_combo = QComboBox()
        self.sandbox_combo.setToolTip(tr("Sandbox the agent of this tab runs in"))
        self.access_button = QPushButton(tr("Access…"))
        self.access_button.clicked.connect(self.edit_access)
        self.settings_button = QPushButton(tr("LLM…"))
        self.settings_button.setToolTip(tr("LLM profiles"))
        self.settings_button.clicked.connect(self.dock.settings_requested.emit)
        head.addWidget(self.model_combo, 2)
        head.addWidget(self.mode_combo, 1)
        head.addWidget(self.sandbox_combo, 1)
        head.addWidget(self.access_button)
        head.addWidget(self.settings_button)
        layout.addLayout(head)
        self.profile_label = QLabel()
        self.profile_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.profile_label)
        self.bypass_label = QLabel(tr("Bypass: changes and commands run without asking."))
        self.bypass_label.setStyleSheet("color: #c0392b; font-weight: bold;")
        self.bypass_label.hide()
        layout.addWidget(self.bypass_label)

        root_row = QHBoxLayout()
        root_row.addWidget(QLabel(tr("Folder:")))
        self.root_edit = QLineEdit()
        self.root_edit.setToolTip(tr("Local files are reachable only inside this folder"))
        self.root_edit.textEdited.connect(self._on_root_edited)
        root_row.addWidget(self.root_edit, 1)
        self.tools_button = QToolButton()
        self.tools_button.setText(tr("Tools ▸"))
        self.tools_button.setCheckable(True)
        self.tools_button.toggled.connect(self._toggle_tools)
        root_row.addWidget(self.tools_button)
        layout.addLayout(root_row)

        self.tools_box = QWidget()
        tools = QVBoxLayout(self.tools_box)
        tools.setContentsMargins(0, 0, 0, 0)
        self.groups = QListWidget()
        self.groups.setMaximumHeight(110)
        for group in OFFERED_GROUPS:
            item = QListWidgetItem(group)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            self.groups.addItem(item)
        self.groups.itemChanged.connect(lambda _item: self._store())
        tools.addWidget(self.groups)
        self.allow_write = QCheckBox(tr("Allow changes to files"))
        self.allow_exec = QCheckBox(tr("Allow remote commands"))
        self.allow_write.toggled.connect(lambda _on: self._store())
        self.allow_exec.toggled.connect(lambda _on: self._store())
        tools.addWidget(self.allow_write)
        tools.addWidget(self.allow_exec)
        self.tools_box.setVisible(False)
        layout.addWidget(self.tools_box)

        self.transcript = QTextBrowser()
        self.transcript.setOpenLinks(False)
        self.transcript.setOpenExternalLinks(False)
        layout.addWidget(self.transcript, 1)
        self.status_label = QLabel()
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)

        self.chips_box = QWidget()
        self.chips = QHBoxLayout(self.chips_box)
        self.chips.setContentsMargins(0, 0, 0, 0)
        self.chips.addStretch(1)
        self.chips_box.hide()
        layout.addWidget(self.chips_box)

        self.plan_label = QLabel()
        self.plan_label.setTextFormat(Qt.TextFormat.PlainText)
        self.plan_label.setWordWrap(True)
        self.plan_label.setToolTip(tr("The agent's plan (update_plan)"))
        self.plan_label.hide()
        layout.addWidget(self.plan_label)

        self.input = _TaskInput()
        self.input.setPlaceholderText(tr("What should the agent do? (Ctrl+Enter sends)"))
        self.input.setMaximumHeight(90)
        self.input.submit.connect(self.send)
        self.input.recall.connect(self._recall)
        self.input.dropped.connect(self._on_dropped)
        layout.addWidget(self.input)

        buttons = QHBoxLayout()
        self.attach_button = QToolButton()
        self.attach_button.setText("+")
        self.attach_button.setToolTip(tr("Attach files or folders"))
        self.attach_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.attach_menu = QMenu(self.attach_button)
        self.attach_menu.aboutToShow.connect(self._fill_attach_menu)
        self.attach_button.setMenu(self.attach_menu)
        self.topics_button = QToolButton()
        self.topics_button.setText(tr("Topics ▸"))
        self.topics_button.setToolTip(
            tr("Prepared tasks: inventory, installs, logs, disk usage, ...")
        )
        self.topics_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.topics_menu = QMenu(self.topics_button)
        self.topics_menu.aboutToShow.connect(self._fill_topics_menu)
        self.topics_button.setMenu(self.topics_menu)
        self.new_button = QPushButton(tr("New conversation"))
        self.new_button.clicked.connect(self.new_conversation)
        self.plan_button = QPushButton(tr("Run this plan"))
        self.plan_button.clicked.connect(self.run_plan)
        self.plan_button.hide()
        self.stop_button = QPushButton(tr("Stop"))
        self.stop_button.clicked.connect(self.stop)
        self.send_button = QPushButton(tr("Send"))
        self.send_button.clicked.connect(self.send)
        buttons.addWidget(self.attach_button)
        buttons.addWidget(self.topics_button)
        buttons.addWidget(self.new_button)
        buttons.addStretch(1)
        buttons.addWidget(self.plan_button)
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.send_button)
        layout.addLayout(buttons)

        self.model_combo.currentIndexChanged.connect(lambda _i: self._store())
        self.mode_combo.currentIndexChanged.connect(lambda _i: self._store())
        self.sandbox_combo.currentIndexChanged.connect(lambda _i: self._store())
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self, activated=self._escape,
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.setAcceptDrops(True)

    def _toggle_tools(self, shown: bool) -> None:
        self.tools_box.setVisible(shown)
        self.tools_button.setText(tr("Tools ▾") if shown else tr("Tools ▸"))

    # -- session <-> widgets -------------------------------------------------------------

    def _load_session(self) -> None:
        s = self.session
        self._loading = True
        try:
            self.refresh_choices()
            if not s.folder:
                s.folder = self.dock.root_provider()
            self.root_edit.setText(s.folder)
            groups = set(s.groups) if s.groups else set(self.dock.agent_settings.groups)
            for i in range(self.groups.count()):
                item = self.groups.item(i)
                item.setCheckState(
                    Qt.CheckState.Checked if item.text() in groups else Qt.CheckState.Unchecked
                )
            self.allow_write.setChecked(s.allow_write)
            self.allow_exec.setChecked(s.allow_exec)
            for entry in s.transcript:
                self._show(entry["who"], entry["text"], entry.get("muted", False))
        finally:
            self._loading = False
        self._store(save=False)
        self._update_buttons()

    def refresh_choices(self) -> None:
        """Fill the model, mode and sandbox lists from the settings now."""
        settings = self.dock.agent_settings
        s = self.session
        was = getattr(self, "_loading", False)
        self._loading = True
        try:
            self.model_combo.clear()
            self.model_combo.addItem(tr("Default model"), "")
            for profile in self.dock.llm_settings().profiles:
                self.model_combo.addItem(profile.name, profile.name)
            self.model_combo.setCurrentIndex(max(0, self.model_combo.findData(s.profile)))
            self.mode_combo.clear()
            modes = list(settings.modes())
            if not bypass_allowed(settings) and "bypass" in modes:
                modes.remove("bypass")
            for mode in modes:
                self.mode_combo.addItem(tr(MODE_NAMES[mode]), mode)
            if s.mode not in modes:
                s.mode = "ask"
            self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(s.mode)))
            self.sandbox_combo.clear()
            self.sandbox_combo.addItem(tr("No sandbox"), "")
            for profile in settings.sandboxes:
                self.sandbox_combo.addItem(f"{profile.name} ({profile.level})", profile.name)
            if s.sandbox and settings.sandbox_profile(s.sandbox) is None:
                # Renamed or deleted: kept and refused, never quietly "no sandbox".
                self.sandbox_combo.addItem(tr("{name} (missing)").format(name=s.sandbox), s.sandbox)
            self.sandbox_combo.setCurrentIndex(max(0, self.sandbox_combo.findData(s.sandbox)))
            self._fill_servers(settings)
            functions = self.functions()
            for i in range(self.groups.count()):
                item = self.groups.item(i)
                if item.text() == "remote":
                    item.setHidden("saved_profiles" not in functions)
            self.allow_exec.setEnabled("remote_commands" in functions and self._exec_policy())
            self.allow_exec.setToolTip(
                ""
                if self.allow_exec.isEnabled()
                else tr(
                    "Remote commands are off in this tab's Access, Agent Settings "
                    "or the security mode"
                )
            )
        finally:
            self._loading = was
        self._update_profile_label()
        self._update_mode_look()
        self._update_access_tip()

    def _fill_servers(self, settings) -> None:
        """One "mcp:<name>" line per enabled MCP server and one "ext:<id>"
        line per extension with agent tools, ticked as the session says."""
        for i in reversed(range(self.groups.count())):
            if self.groups.item(i).text().startswith((MCP_PREFIX, EXT_PREFIX)):
                self.groups.takeItem(i)
        chosen = set(self.session.groups)
        lines = [(MCP_PREFIX + s.name, " ".join(s.command) if s.transport == "stdio" else s.url)
                 for s in settings.mcp_servers if s.enabled]
        lines += [(EXT_PREFIX + ext_id, tr("Tools of the extension {name}").format(name=name))
                  for ext_id, name in self.dock.extension_owners()]
        for text, tip in lines:
            item = QListWidgetItem(text)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if text in chosen else Qt.CheckState.Unchecked)
            item.setToolTip(tip)
            self.groups.addItem(item)

    @staticmethod
    def _exec_policy() -> bool:
        from core.security_mode import current_policy

        return bool(current_policy().allow_remote_exec)

    def _store(self, *, save: bool = True) -> None:
        if getattr(self, "_loading", False):
            return
        s = self.session
        s.profile = self.model_combo.currentData() or ""
        s.mode = self.mode_combo.currentData() or "ask"
        s.sandbox = self.sandbox_combo.currentData() or ""
        s.folder = self.root_edit.text().strip()
        s.groups = sorted(self.selected_groups())
        s.allow_write = self.allow_write.isChecked()
        s.allow_exec = self.allow_exec.isChecked()
        self._update_profile_label()
        self._update_mode_look()
        if save:
            self.changed.emit()

    def _update_profile_label(self) -> None:
        profile = self.profile()
        self.profile_label.setText(
            tr("Model: {name}").format(name=profile.name) if profile
            else tr("No LLM profile is active: set one up with LLM…")
        )
        self._update_buttons()

    def _update_mode_look(self) -> None:
        mode = self.session.mode
        self.bypass_label.setVisible(mode == "bypass")
        sandbox = self.sandbox_profile()
        from core.agent_sandbox import writes_allowed

        can_write = mode != "plan" and writes_allowed(sandbox)
        self.allow_write.setEnabled(can_write)
        self.allow_write.setToolTip(
            ""
            if can_write
            else (
                tr("Plan mode only reads")
                if mode == "plan"
                else tr("This sandbox mounts nothing writable")
            )
        )

    # -- state ---------------------------------------------------------------------------

    def profile(self) -> LP.LLMProfile | None:
        try:
            llm = self.dock.llm_settings()
        except Exception:  # a broken settings file must not break the tab
            log.exception("LLM settings could not be read")
            return None
        name = self.session.profile or self.dock.agent_settings.profile
        return (llm.profile(name) if name else None) or llm.active_profile()

    def sandbox_profile(self):
        return (
            self.dock.agent_settings.sandbox_profile(self.session.sandbox)
            if self.session.sandbox
            else None
        )

    def session_access(self) -> X.SessionAccess:
        """The tab's access: its own, or - a session from before - what
        Agent Settings > Access says now."""
        return self.session.access or X.SessionAccess.from_settings(self.dock.agent_settings.access)

    def functions(self) -> frozenset:
        """The axross functions this tab may use now."""
        return X.allowed_functions(self.dock.agent_settings.access, self.session_access())

    def edit_access(self) -> None:
        from PyQt6.QtWidgets import QDialog

        from ui.agent_access_dialog import SessionAccessDialog

        dialog = SessionAccessDialog(
            self,
            self.session.title,
            self.session_access(),
            list(self.session.extra_folders),
            ceiling=self.dock.agent_settings.access,
            sandbox=self.sandbox_profile(),
        )
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            self.session.access = dialog.editor.access()
            self.session.extra_folders = dialog.editor.folders()
        finally:
            dialog.deleteLater()
        self.refresh_choices()
        self._update_access_tip()
        self.changed.emit()

    def _update_access_tip(self) -> None:
        from ui.agent_access_dialog import summary

        self.access_button.setToolTip(tr("What this tab may reach: ") + summary(
            self.session_access(), self.session.extra_folders))

    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _update_buttons(self) -> None:
        busy = self.busy()
        self.send_button.setEnabled(not busy and self.profile() is not None)
        self.stop_button.setEnabled(busy)
        self.new_button.setEnabled(not busy)
        self.plan_button.setVisible(self._plan_ready and not busy)

    def selected_groups(self) -> frozenset:
        return frozenset(
            self.groups.item(i).text()
            for i in range(self.groups.count())
            if self.groups.item(i).checkState() == Qt.CheckState.Checked
            and not self.groups.item(i).isHidden()
        )

    def _on_root_edited(self, text: str) -> None:
        self._root_typed = bool(text)
        self._store()

    def follow_folder(self) -> None:
        if self._root_typed:
            return
        try:
            folder = self.dock.root_provider()
        except Exception:  # noqa: BLE001 - a gone pane must not break the tab
            log.exception("agent folder could not be read")
            return
        if folder and folder != self.root_edit.text():
            self.root_edit.setText(folder)
            self._store()

    def _config(self, profile: LP.LLMProfile, *, mode: str) -> A.AgentConfig:
        settings = self.dock.agent_settings
        chosen = set(self.selected_groups())
        servers = sorted(g[len(MCP_PREFIX):] for g in chosen if g.startswith(MCP_PREFIX))
        extensions = sorted(g[len(EXT_PREFIX):] for g in chosen if g.startswith(EXT_PREFIX))
        groups = {g for g in chosen if not g.startswith((MCP_PREFIX, EXT_PREFIX))}
        allow_exec = (self.allow_exec.isEnabled() and self.allow_exec.isChecked()
                      and mode != "plan")
        if allow_exec:
            groups.add("exec")
        functions = self.functions()
        access = self.session_access()
        if "saved_profiles" not in functions:
            groups.discard("remote")
        if "mcp_servers" not in functions:
            servers = []
        if "extensions" not in functions:
            extensions = []
        allow_write = (
            self.allow_write.isEnabled() and self.allow_write.isChecked() and mode != "plan"
        )
        try:
            key = self.dock.key_lookup(profile.name) or ""
        except Exception:
            log.exception("API key lookup failed for %s", profile.name)
            key = ""
        prompt = A.SYSTEM_PROMPT + (PLAN_PROMPT if mode == "plan" else "")
        return A.AgentConfig(
            profile=profile, api_key=key,
            root=os.path.abspath(os.path.expanduser(self.root_edit.text().strip() or "~")),
            groups=frozenset(groups), allow_write=allow_write, allow_exec=allow_exec,
            max_steps=settings.max_steps, max_tool_chars=settings.max_tool_chars,
            system_prompt=prompt, extra_roots=tuple(self.session.extra_folders),
            remote_backends=self._remote_backends() if "remote_files" in functions else (),
            external_tools=lambda: self._external_tools(servers, extensions, plan=mode == "plan"),
            functions=functions, firewall=X.firewall(access),
        )

    def _external_tools(self, servers, extensions, *, plan: bool = False) -> tuple:
        tools, errors = (
            self.dock.external_tools(servers, extensions) if servers or extensions else ([], [])
        )
        if plan:  # Plan only reads: nothing that may change something is offered
            tools = [t for t in tools if not t.write]
        return [*self._conversation_tools(), *tools], errors

    def _conversation_tools(self) -> list:
        """ask_user and update_plan: the tab answers them itself."""
        return [
            A.FunctionTool(
                name="ask_user",
                description="Ask the user a question and wait for the answer - when the task is "
                "unclear or a choice is the user's. Returns the answer text.",
                schema={
                    "type": "object",
                    "properties": {"question": {"type": "string", "maxLength": 2000}},
                    "required": ["question"],
                },
                handler=self._ask_user_tool,
                group="conversation",
                outside=False,
            ),
            A.FunctionTool(
                name="update_plan",
                description="Show the user your plan as a checklist; call it again as steps get "
                "done. steps: [{text, done}].",
                schema={
                    "type": "object",
                    "properties": {
                        "steps": {
                            "type": "array",
                            "maxItems": 30,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "text": {"type": "string"},
                                    "done": {"type": "boolean"},
                                },
                            },
                        }
                    },
                    "required": ["steps"],
                },
                handler=self._update_plan_tool,
                group="conversation",
                outside=False,
            ),
        ]

    def _ask_user_tool(self, args: dict) -> str:
        """On the agent's thread: ask on the GUI thread and wait."""
        question = str(args.get("question") or "")[:2000]
        pending = {"done": threading.Event(), "answer": None}
        self._bridge.ask.emit(question, pending)
        while not pending["done"].wait(0.1):
            if self._cancel.is_set():
                return "the user stopped the task"
        answer = pending["answer"]
        return answer if isinstance(answer, str) and answer.strip() else "the user did not answer"

    def _update_plan_tool(self, args: dict) -> str:
        steps = [s for s in args.get("steps") or [] if isinstance(s, dict)][:30]
        lines = [
            f"{'☑' if s.get('done') is True else '☐'} {str(s.get('text') or '')[:200]}"
            for s in steps
        ]
        self._bridge.event.emit({"type": "plan", "steps": lines})
        return "the plan is shown to the user"

    def _on_ask(self, question: str, pending: object) -> None:
        self._append(tr("Agent asks:"), question)
        try:
            answer = None if self._cancel.is_set() else self.dock.ask_user(question)
        except Exception:  # noqa: BLE001 - a broken dialog is no answer
            log.exception("the question dialog failed")
            answer = None
        if isinstance(answer, str) and answer.strip():
            self._append(tr("You:"), answer)
        pending["answer"] = answer
        pending["done"].set()

    def _remote_backends(self) -> tuple:
        try:
            return tuple(self.dock.remote_backends())
        except Exception:  # noqa: BLE001 - a gone pane must not stop the task
            log.exception("the panes' connections could not be read")
            return ()

    # -- the transcript --------------------------------------------------------------------

    def _show(self, who: str, text: str, muted: bool = False) -> None:
        # No colour on normal lines: the theme's text colour applies. Qt's
        # rich text has no "inherit" - it paints that as black.
        style = ' style="color:#888"' if muted else ""
        self.transcript.append(
            f"<p{style}><b>{html.escape(who)}</b> "
            f"{html.escape(text).replace(chr(10), '<br>')}</p>"
        )

    def _append(self, who: str, text: str, *, muted: bool = False) -> None:
        self._show(who, text, muted)
        self.session.transcript.append({"who": who, "text": text, "muted": muted})

    # -- attachments ------------------------------------------------------------------------

    def _fill_attach_menu(self) -> None:
        menu = self.attach_menu
        menu.clear()
        for label, kind in ((tr("Selected files of the active pane"), "selection"),
                            (tr("Folder of the active pane"), "folder")):
            action = menu.addAction(label)
            action.triggered.connect(lambda _c=False, k=kind: self.attach_from_pane(k))
        menu.addAction(tr("Files…")).triggered.connect(self._attach_files_dialog)
        menu.addAction(tr("Path from the clipboard")).triggered.connect(self._attach_clipboard)
        if self._attachments:
            menu.addSeparator()
            menu.addAction(tr("Remove all attachments")).triggered.connect(self.clear_attachments)

    def attach_from_pane(self, kind: str) -> None:
        found = self.dock.pane_items(kind)
        if found:
            self.attach(found["paths"], found.get("backend"), found.get("local", True))

    # -- topics -------------------------------------------------------------------------------

    def _fill_topics_menu(self) -> None:
        menu = self.topics_menu
        menu.clear()
        source = None
        for topic in self.dock.topics():
            if source is not None and topic.source != source:
                menu.addSeparator()
            source = topic.source
            action = menu.addAction(topic.title)
            action.setToolTip(topic.description)
            action.setStatusTip(topic.description)
            action.triggered.connect(lambda _c=False, t=topic: self.use_topic(t))

    def use_topic(self, topic) -> None:
        """Type the topic's task into the task field; the user sends it."""
        backend = next((a["backend"] for a in self._attachments if not a["local"]), "") or ""
        self.input.setPlainText(topic.render(self.root_edit.text().strip(), backend))
        if topic.mode and self.mode_combo.findData(topic.mode) >= 0:
            self.mode_combo.setCurrentIndex(self.mode_combo.findData(topic.mode))
        missing = []
        if "exec" in topic.needs and not (
            self.allow_exec.isEnabled() and self.allow_exec.isChecked()
        ):
            missing.append(
                tr("remote commands (Tools ▸ Allow remote commands; Agent Settings > Access)")
            )
        if "remote" in topic.needs and "remote_files" not in self.functions():
            missing.append(tr("remote files (Access…; Agent Settings > Access)"))
        if "write" in topic.needs and not (
            self.allow_write.isEnabled() and self.allow_write.isChecked()
        ):
            missing.append(tr("changes to files (Tools ▸ Allow changes to files)"))
        if missing:
            self._show(
                tr("axross:"),
                tr("This topic needs: {what}.").format(what="; ".join(missing)),
                muted=True,
            )
        self.input.setFocus()

    def _attach_files_dialog(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        paths, _ = QFileDialog.getOpenFileNames(self, tr("Attach files"), self.root_edit.text())
        if paths:
            self.attach(paths, None, True)

    def _attach_clipboard(self) -> None:
        from PyQt6.QtWidgets import QApplication

        text = QApplication.clipboard().text().strip()
        paths = [line.strip() for line in text.splitlines() if line.strip().startswith("/")]
        if paths:
            self.attach(paths, None, True)

    def _on_dropped(self, found: dict) -> None:
        backend, local = self.dock.pane_backend(found.get("source_pane_id"))
        self.attach(found["paths"], backend, local)

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        if _dropped_paths(event.mimeData()) is not None:
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.dragEnterEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        found = _dropped_paths(event.mimeData())
        if found is None:
            event.ignore()
            return
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        self._on_dropped(found)

    def attach(self, paths, backend: str | None, local: bool) -> None:
        """Attach *paths* (of *backend*; a local one when *local*). A local
        path outside the tab's folders adds its folder read-only."""
        for path in paths:
            if any(a["path"] == path and a["backend"] == backend for a in self._attachments):
                continue
            self._attachments.append({"path": path, "backend": backend, "local": local})
            if local:
                self._reach_local(path)
        if (
            any(not a["local"] for a in self._attachments)
            and "remote_files" not in self.functions()
        ):
            self._show(
                tr("axross:"),
                tr(
                    "Remote files are off in this tab's Access or Agent Settings > Access: "
                    "the agent cannot open files of a connection."
                ),
                muted=True,
            )
        self._render_chips()

    def _reach_local(self, path: str) -> None:
        folders = [self.root_edit.text().strip()] + [p for p, _ in self.session.extra_folders]
        real = os.path.realpath(path)
        for folder in folders:
            if folder and (real == os.path.realpath(folder)
                           or real.startswith(os.path.realpath(folder).rstrip("/") + "/")):
                return
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        self.session.extra_folders.append((os.path.normpath(folder), False))
        self._append(
            tr("axross:"),
            tr("{folder} is now readable for this tab.").format(folder=folder),
            muted=True,
        )
        self.changed.emit()

    def _render_chips(self) -> None:
        while self.chips.count() > 1:
            item = self.chips.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        for index, att in enumerate(self._attachments):
            name = os.path.basename(att["path"].rstrip("/")) or att["path"]
            label = name if att["local"] else f"{name} ({att['backend']})"
            chip = QPushButton(f"{label} ✕")
            chip.setToolTip(att["path"])
            chip.setFlat(True)
            chip.clicked.connect(lambda _c=False, i=index: self.remove_attachment(i))
            self.chips.insertWidget(self.chips.count() - 1, chip)
        self.chips_box.setVisible(bool(self._attachments))

    def remove_attachment(self, index: int) -> None:
        if 0 <= index < len(self._attachments):
            self._attachments.pop(index)
            self._render_chips()

    def clear_attachments(self) -> None:
        self._attachments.clear()
        self._render_chips()

    def _context_text(self) -> str:
        if not self._attachments:
            return ""
        lines = [tr("Files the user points to:")]
        for att in self._attachments:
            where = "" if att["local"] else f' (backend "{att["backend"]}")'
            lines.append(f"- {att['path']}{where}")
        return "\n".join(lines) + "\n\n"

    # -- actions ----------------------------------------------------------------------------

    def _recall(self, step: int) -> None:
        if not self._history:
            return
        self._recall_index = max(0, min(len(self._history), self._recall_index + step))
        text = self._history[self._recall_index] if self._recall_index < len(self._history) else ""
        self.input.setPlainText(text)
        self.input._recalling = True
        cursor = self.input.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.input.setTextCursor(cursor)

    def _escape(self) -> None:
        if self.busy():
            self.stop()

    def new_conversation(self) -> None:
        if self.busy():
            return
        self._agent = None
        self._agent_key = None
        self._close_agent()
        self.transcript.clear()
        self.session.transcript.clear()
        self.session.messages.clear()
        self._plan_ready = False
        self._update_buttons()
        self.changed.emit()

    def run_plan(self) -> None:
        if self.busy() or not self._plan_ready:
            return
        self._plan_ready = False
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData("ask")))
        self._send(RUN_PLAN_TASK)

    def send(self) -> None:
        task = self.input.toPlainText().strip()
        if not task or self.busy():
            return
        self._send(task)

    def _send(self, task: str) -> None:
        profile = self.profile()
        if profile is None:
            self._append(tr("axross:"), tr("No LLM profile is active."), muted=True)
            return
        if profile.needs_consent():
            host = profile.host() or profile.resolved_endpoint()
            if not self.dock.confirm_remote(profile, host):
                return
            profile.consent()  # for this conversation; the profile dialog stores it for good
        mode = self.session.mode
        sandbox = self.sandbox_profile()
        if self.session.sandbox and sandbox is None:
            self._append(
                tr("axross:"),
                tr(
                    "The sandbox profile {name} no longer exists (renamed or deleted in "
                    "Agent Settings): choose a sandbox for this tab."
                ).format(name=self.session.sandbox),
                muted=True,
            )
            return
        config = self._config(profile, mode=mode)
        key = (
            profile.name,
            profile.consent_key(),
            config.root,
            config.groups,
            config.allow_write,
            config.allow_exec,
            config.system_prompt,
            tuple(config.extra_roots),
            self.session.sandbox,
            tuple((bid, id(backend)) for bid, backend, _p in config.remote_backends),
            self.dock.external_signature(self.selected_groups()),
            self._exec_policy(),
            config.functions,
            self.session_access().network,
        )
        if self._agent is None or key != self._agent_key:
            history = list(self.session.messages)
            if self._agent is not None:
                self._append(
                    tr("axross:"),
                    tr("New settings: the conversation continues with them."),
                    muted=True,
                )
            self._close_agent()
            self._cancel = threading.Event()
            if sandbox is not None:
                from core.agent_sandbox import SandboxedAgent

                name = self.session.sandbox
                self._agent = SandboxedAgent(
                    config,
                    lambda: X.session_profile(
                        self.dock.agent_settings.sandbox_profile(name), self.session_access()
                    ),
                    confirm=self._wait_for_answer,
                    on_event=self._bridge.event.emit,
                    cancel=self._cancel,
                    history=history,
                )
            else:
                self._agent = A.Agent(config, confirm=self._wait_for_answer,
                                      on_event=self._bridge.event.emit, cancel=self._cancel)
                if history:
                    history[0:1] = [{"role": "system", "content": config.system_prompt}] \
                        if history and history[0].get("role") == "system" else history[0:1]
                    if history[0].get("role") != "system":
                        history.insert(0, {"role": "system", "content": config.system_prompt})
                    self._agent.messages = history
            self._agent_key = key
        self._cancel.clear()
        self.input.clear()
        context = self._context_text()
        self.clear_attachments()
        self._append(tr("You:"), task)
        if self.session.title == "New task" and task != RUN_PLAN_TASK:
            self.session.title = task.splitlines()[0][:40]
            self.title_changed.emit(self.session.title)
        self._history = (self._history + [task])[-HISTORY_LIMIT:]
        self._recall_index = len(self._history)
        self._plan_ready = False
        agent = self._agent
        self._started = time.monotonic()
        self._tool_calls = 0
        self._steps = 0
        self._mode_of_run = mode
        self.dock.emit_event(self, {"type": "run_started", "mode": mode,
                                    "sandbox": self.session.sandbox or None})

        def work() -> None:
            try:
                result = agent.run(context + task)
                self._bridge.finished.emit(result, "")
            except A.AgentError as exc:
                self._bridge.finished.emit(None, str(exc))
            except Exception as exc:  # noqa: BLE001 - the dock must survive anything
                log.exception("agent run failed")
                self._bridge.finished.emit(None, f"{type(exc).__name__}: {exc}")

        self._thread = threading.Thread(target=work, name="axross-agent", daemon=True)
        self._thread.start()
        self._clock.start()
        self._update_status()
        self._update_buttons()
        self.busy_changed.emit(True)
        self.changed.emit()

    def stop(self) -> None:
        self._cancel.set()
        self._answer(False)

    def _close_agent(self) -> None:
        agent, self._agent = self._agent, None
        close = getattr(agent, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                log.exception("closing the agent failed")

    def shutdown(self) -> None:
        self.stop()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._close_agent()

    # -- confirmation across threads -----------------------------------------------------------

    def _needs_user(self, name: str) -> bool:
        mode = getattr(self, "_mode_of_run", self.session.mode)
        if mode == "bypass" and bypass_allowed(self.dock.agent_settings):
            return False
        if mode == "auto":
            return name in EXEC_TOOLS or self.dock.always_ask(name)
        return True

    def _wait_for_answer(self, name: str, args: dict) -> bool:
        """Called on the worker thread: ask on the GUI thread, wait for it."""
        if not self._needs_user(name):
            self._bridge.event.emit({"type": "auto_approved", "name": name})
            return not self._cancel.is_set()
        pending = {"done": threading.Event(), "yes": False}
        self._bridge.confirm.emit(name, args, pending)
        while not pending["done"].wait(0.1):
            if self._cancel.is_set():
                return False
        return bool(pending["yes"]) and not self._cancel.is_set()

    def _on_confirm(self, name: str, args: object, pending: object) -> None:
        self._pending.append(pending)
        if self._cancel.is_set():
            self._answer_one(pending, False)
            return
        tools = getattr(self._agent, "_tools", {}) if self._agent is not None else {}
        tool = tools.get(name)
        shown = A._shown(args, tool.schema if tool is not None else {})
        try:
            yes = bool(self.dock.confirm_call(name, shown))
        except Exception:  # noqa: BLE001 - a broken dialog is a No
            log.exception("confirmation dialog failed")
            yes = False
        self.dock.emit_event(self, {"type": "confirmation", "name": name, "yes": yes})
        self._answer_one(pending, yes)

    def _answer_one(self, pending: dict, yes: bool) -> None:
        if pending in self._pending:
            self._pending.remove(pending)
        pending["yes"] = yes
        pending["done"].set()

    def _answer(self, yes: bool) -> None:
        """Answer every open question (Stop: all of them No)."""
        for pending in list(self._pending):
            self._answer_one(pending, yes)

    # -- events -----------------------------------------------------------------------------------

    def _on_event(self, event: dict) -> None:
        kind = event.get("type")
        if kind == "assistant":
            self._steps += 1
            self._append(tr("Agent:"), str(event.get("text", "")))
        elif kind == "tool_call":
            self._tool_calls += 1
            args = json.dumps(event.get("args", {}), ensure_ascii=False)
            self._append("→", f"{event.get('name')} {args[:300]}", muted=True)
        elif kind == "tool_result":
            self._append("←", f"{event.get('name')}: {event.get('outcome')}", muted=True)
        elif kind == "plan":
            text = "\n".join(str(line) for line in event.get("steps") or [])
            self.plan_label.setText(text)
            self.plan_label.setVisible(bool(text))
        elif kind == "notice":
            self._append(tr("axross:"), str(event.get("text", "")), muted=True)
        elif kind == "auto_approved":
            self._append("✓", tr("{tool} ran without asking ({mode})").format(
                tool=event.get("name"), mode=MODE_NAMES.get(self._mode_of_run, "")), muted=True)
        self._update_status()
        self.dock.emit_event(self, dict(event))

    def _update_status(self) -> None:
        if not self._started:
            self.status_label.clear()
            return
        seconds = int(time.monotonic() - self._started)
        clock = f"{seconds // 60:02d}:{seconds % 60:02d}"
        what = tr("Running") if self.busy() else tr("Done")
        self.status_label.setText(
            tr("{what} · {clock} · {calls} tool calls · {steps} answers").format(
                what=what, clock=clock, calls=self._tool_calls, steps=self._steps
            )
        )

    def _on_finished(self, result, error: str) -> None:
        self._thread = None
        self._clock.stop()
        if error:
            self._append(tr("axross:"), error, muted=True)
        elif result is not None:
            # The answer itself arrived as an "assistant" event.
            if result.stopped == "max_steps":
                self._append(tr("axross:"), tr("Stopped after the step limit."), muted=True)
            elif result.stopped == "cancelled":
                self._append(tr("axross:"), tr("Stopped."), muted=True)
            elif self._mode_of_run == "plan" and result.answer:
                self._plan_ready = True
        agent = self._agent
        if agent is not None:
            self.session.messages = list(getattr(agent, "messages", []) or [])
        done, self._done = self._done, []
        for callback in done:
            try:
                callback(getattr(result, "answer", "") if result is not None else "", error or "")
            except Exception:  # noqa: BLE001 - a caller's callback must not break the tab
                log.exception("an agent task's callback failed")
        self._update_status()
        self._update_buttons()
        self.busy_changed.emit(False)
        self.dock.emit_event(
            self,
            {
                "type": "run_finished",
                "error": error or None,
                "stopped": getattr(result, "stopped", None) if result is not None else None,
                "seconds": round(time.monotonic() - self._started, 1) if self._started else 0,
                "tool_calls": self._tool_calls,
                "outcomes": [c.get("outcome") for c in getattr(result, "calls", [])]
                if result is not None
                else [],
            },
        )
        self.changed.emit()


class AgentDock(QDockWidget):
    """The Agent panel: a tab per session, kept across starts."""

    settings_requested = pyqtSignal()
    #: ``(tab session id, event dict)`` for every agent event of every tab:
    #: tool calls, answers, confirmations, run started/finished. Extensions
    #: read it (ui.extension_host: api.on_agent_event).
    agent_event = pyqtSignal(str, object)

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
        agent_settings_loader: Callable[[], AGS.AgentSettings] | None = None,
        session_store: SessionStore | None = None,
        pane_items: Callable[[str], dict | None] | None = None,
        pane_backend: Callable[[str | None], tuple] | None = None,
        remote_backends: Callable[[], list] | None = None,
        mcp_pool: McpClientPool | None = None,
        extensions: Callable[[], object] | None = None,
    ) -> None:
        super().__init__(tr("Agent"), parent)
        self.setObjectName("axAgentDock")
        self.llm_settings = settings_loader or LP.LLMSettings.load
        self._save_llm_settings = settings_saver or (lambda s: s.save())
        self.key_lookup = key_lookup or LP.get_api_key
        self.confirm_remote = confirm_remote or (lambda p, h: _ask_remote(self, p, h))
        self.confirm_call = confirm_call or (lambda n, a: _ask_call(self, n, a))
        #: ``ask_user(question) -> answer or None`` for the agent's questions.
        self.ask_user = lambda question: _ask_user(self, question)
        self.root_provider = root_provider or (lambda: os.path.expanduser("~"))
        self._load_agent_settings = agent_settings_loader or AGS.AgentSettings.load
        self.agent_settings = self._load_agent_settings()
        self.store = session_store if session_store is not None else SessionStore()
        self.pane_items = pane_items or (lambda kind: None)
        self.pane_backend = pane_backend or (lambda pane_id: (None, True))
        #: The remote connections of the panes: ``(id, backend, profile)``.
        self.remote_backends = remote_backends or (lambda: [])
        #: The connected MCP servers, shared by every tab.
        self.mcp_pool = mcp_pool if mcp_pool is not None else McpClientPool()
        #: The extension host (ui.extension_host), or None.
        self._extensions = extensions or (lambda: None)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(
            lambda _i: self.current_tab() and self.current_tab().follow_folder()
        )
        self.tabs.tabBarDoubleClicked.connect(self.rename_tab)
        new_tab = QToolButton()
        new_tab.setText("+")
        new_tab.setToolTip(tr("New tab (Ctrl+T)"))
        new_tab.clicked.connect(lambda: self.new_tab())
        self.tabs.setCornerWidget(new_tab, Qt.Corner.TopRightCorner)
        self.setWidget(self.tabs)
        QShortcut(QKeySequence("Ctrl+T"), self.tabs, activated=lambda: self.new_tab(),
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)

        restored = self.store.all() if self.agent_settings.keep_sessions else []
        for session in restored:
            self._add_tab(session)
        if not restored:
            self.new_tab(save=False)

    # -- tabs ---------------------------------------------------------------------------------

    def _add_tab(self, session: AgentSession) -> AgentTab:
        tab = AgentTab(self, session)
        tab.changed.connect(lambda t=tab: self._save(t))
        tab.title_changed.connect(lambda title, t=tab: self._retitle(t, title))
        index = self.tabs.addTab(tab, session.title)
        self.tabs.setCurrentIndex(index)
        return tab

    def sessions(self) -> list:
        """The open tabs' sessions (Agent Settings > Sessions edits them)."""
        return [tab.session for tab in self.all_tabs()]

    def store_session(self, session: AgentSession) -> None:
        """A session changed outside its tab (Agent Settings > Sessions):
        the tab shows it, and it is saved like any change of the tab."""
        for tab in self.all_tabs():
            if tab.session is session:
                tab.refresh_choices()
                self._save(tab)
                return
        self.store.save(session)

    def new_tab(
        self, *, save: bool = True, task: str | None = None, folder: str | None = None
    ) -> AgentTab:
        s = self.agent_settings
        session = AgentSession(
            profile=s.profile,
            mode=s.mode if s.mode != "bypass" or bypass_allowed(s) else "ask",
            sandbox=s.sandbox,
            groups=list(s.groups),
            folder=folder or "",
            access=X.SessionAccess.from_settings(s.access),
        )
        tab = self._add_tab(session)
        if save:
            self._save(tab)
        if task:
            tab.input.setPlainText(task)
        tab.input.setFocus()
        return tab

    def current_tab(self) -> AgentTab | None:
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, AgentTab) else None

    def all_tabs(self) -> list[AgentTab]:
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def _retitle(self, tab: AgentTab, title: str) -> None:
        index = self.tabs.indexOf(tab)
        if index >= 0:
            self.tabs.setTabText(index, title)
            self.tabs.setTabToolTip(index, title)

    def rename_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        if not isinstance(tab, AgentTab):
            return
        title, ok = QInputDialog.getText(self, tr("Rename tab"), tr("Name"), text=tab.session.title)
        if ok and title.strip():
            tab.session.title = title.strip()[:80]
            self._retitle(tab, tab.session.title)
            self._save(tab)

    def close_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        if not isinstance(tab, AgentTab):
            return
        if tab.busy() or tab.session.transcript:
            answer = QMessageBox.question(
                self, tr("Close tab"),
                tr("Close {title}? Its conversation is deleted.").format(title=tab.session.title),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        tab.shutdown()
        self.tabs.removeTab(index)
        self.store.delete(tab.session.id)
        tab.deleteLater()
        if self.tabs.count() == 0:
            self.new_tab()

    def _save(self, tab: AgentTab) -> None:
        if not self.agent_settings.keep_sessions:
            return
        try:
            self.store.save(tab.session)
        except OSError as exc:
            log.warning("agent session could not be saved: %s", exc)

    def reload_settings(self) -> None:
        """Agent Settings were saved: every tab offers what they say now."""
        self.agent_settings = self._load_agent_settings()
        self.mcp_pool.keep_only([s for s in self.agent_settings.mcp_servers if s.enabled])
        for tab in self.all_tabs():
            tab.refresh_choices()

    def _servers(self, names) -> list:
        return [s for s in self.agent_settings.mcp_servers if s.enabled and s.name in names]

    def mcp_tools(self, names) -> tuple:
        """The tools of the enabled servers *names*, and one error line per
        server that failed (core.mcp_client.McpClientPool.tools)."""
        return self.mcp_pool.tools(self._servers(names), wrap_for=self._mcp_wrap)

    def external_signature(self, groups) -> tuple:
        """What the chosen servers and extensions are now: a change starts
        a new agent."""
        names = {g[len(MCP_PREFIX):] for g in groups if g.startswith(MCP_PREFIX)}
        ext_ids = sorted(g[len(EXT_PREFIX):] for g in groups if g.startswith(EXT_PREFIX))
        return (tuple((s.name, s.signature()) for s in self._servers(names)),
                tuple((t.name, id(t)) for t in self.extension_tools(ext_ids)))

    def external_tools(self, servers, extensions) -> tuple:
        """The tools of the MCP servers and extensions a tab chose, and the
        servers that failed."""
        tools, errors = self.mcp_tools(servers) if servers else ([], [])
        return [*tools, *self.extension_tools(extensions)], errors

    def extension_tools(self, ext_ids) -> list:
        host = self._extensions()
        return list(host.agent_tools(ext_ids)) if host is not None else []

    def extension_owners(self) -> list:
        host = self._extensions()
        return list(host.agent_tool_owners()) if host is not None else []

    def always_ask(self, name: str) -> bool:
        if self.mcp_pool.always_ask(name):
            return True
        host = self._extensions()
        return host is not None and any(
            t.name == name and t.always_ask
            for t in host.agent_tools([i for i, _n in host.agent_tool_owners()])
        )

    def topics(self) -> list:
        from core.agent_topics import BUILTIN_TOPICS

        host = self._extensions()
        return [*BUILTIN_TOPICS, *(host.agent_topics() if host is not None else [])]

    def refresh_extensions(self) -> None:
        for tab in self.all_tabs():
            tab.refresh_choices()

    def start_task(self, task: str, *, folder: str | None = None, mode: str | None = None,
                   groups=(), on_done=None) -> AgentTab:
        """A new tab that runs *task* at once (an extension's run_agent)."""
        tab = self.new_tab(folder=folder)
        tab.session.groups = sorted(
            set(tab.session.groups or self.agent_settings.groups) | set(groups)
        )
        tab.refresh_choices()
        if mode and tab.mode_combo.findData(mode) >= 0:
            tab.mode_combo.setCurrentIndex(tab.mode_combo.findData(mode))
        if on_done is not None:
            tab._done.append(on_done)
        self.show()
        tab._send(task)
        return tab

    def _mcp_wrap(self, server):
        """A stdio server's argv in its sandbox profile, if it names one."""
        return self.agent_settings.mcp_wrap(server)

    def emit_event(self, tab: AgentTab, event: dict) -> None:
        self.agent_event.emit(tab.session.id, event)

    # -- the current tab (the main window and older callers) ------------------------------------

    def refresh_profiles(self) -> None:
        for tab in self.all_tabs():
            tab.refresh_choices()

    def follow_folder(self) -> None:
        tab = self.current_tab()
        if tab is not None:
            tab.follow_folder()

    def busy(self) -> bool:
        return any(tab.busy() for tab in self.all_tabs())

    def send(self) -> None:
        self.current_tab().send()

    def stop(self) -> None:
        for tab in self.all_tabs():
            tab.stop()

    def new_conversation(self) -> None:
        self.current_tab().new_conversation()

    def selected_groups(self) -> frozenset:
        return self.current_tab().selected_groups()

    def shutdown(self) -> None:
        for tab in self.all_tabs():
            tab.shutdown()
        self.mcp_pool.close_all()

    def __getattr__(self, name):
        # The widgets of the current tab: dock.input, dock.transcript, ...
        if name in (
            "input",
            "transcript",
            "send_button",
            "stop_button",
            "new_button",
            "allow_write",
            "allow_exec",
            "groups",
            "root_edit",
            "profile_label",
            "mode_combo",
            "model_combo",
            "sandbox_combo",
            "status_label",
            "plan_button",
        ):
            tab = self.current_tab()
            if tab is not None:
                return getattr(tab, name)
        raise AttributeError(name)
