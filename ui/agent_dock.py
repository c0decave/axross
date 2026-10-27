"""Agent dock: a local LLM works with axross through the MCP tools.

Every tab is a session of its own (core.agent_session): its conversation,
LLM profile, protection mode, sandbox, folder and tools. Tabs are kept in
one JSON file each and come back at the next start when "Keep tabs" is on
(Tools > Agent Settings…).

A tab can be detached into a panel of its own (tab menu > Detach as Panel,
or dragged out of the tab bar) and attached back, or sent straight onto a
workspace (tab menu > Send to Workspace > a workspace or New Workspace, a
panel laid out there in one step); Tools > New Agent Window
opens a new conversation as such a panel (ui.agent_panels). A detached
conversation stays a tab of this dock in all but the place it is shown:
voice, settings, the link lamp and agent events cover it as well.

Protection modes:

* **Ask** - every change and every remote command waits for Yes.
* **Plan** - the agent may only read; it answers with a plan, and
  "Run this plan" carries it out in Ask mode.
* **Auto** - changes run without asking, remote commands still ask.
* **Bypass** - nothing asks. Only when Agent Settings allow it, never in
  the paranoid security mode, and the tab says so in red.

A task runs on a background thread (core.agent.Agent, or
core.agent_sandbox.SandboxedAgent when the tab has a sandbox). Closing a
tab or Stop answers No to a waiting question and ends the run at once,
also while the model is still answering (core.agent.post_chat cuts the
request). What the model and the tools return is shown as plain text: it
comes from files and servers and can be hostile.
"""

from __future__ import annotations

import dataclasses
import html
import json
import logging
import os
import re
import threading
import time
from typing import Callable

from PyQt6.QtCore import QObject, QStringListModel, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QCompleter,
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
from core import agent_profiles as AP
from core import agent_link as AL
from core import agent_settings as AGS
from core import llm_profiles as LP
from core import voice_text as VT
from core.agent_session import DETACHED_PLACES, AgentSession, SessionStore
from core.mcp_client import McpClientPool
from core.i18n import tr
from ui.agent_panels import AgentPanel, DetachTabBar, alive, weak_call
from ui.dock_frame import framed

log = logging.getLogger(__name__)

#: Groups a tab may offer; exec has its own box, scripts are never offered.
OFFERED_GROUPS = ("metadata", "filetype", "archive", "duplicates", "index", "packer", "crypto",
                  "transfer", "remote")
#: A task that starts like a work prompt's command: "/name", then the rest.
_SLASH = re.compile(r"/([A-Za-z0-9-]*)(?:\s+(.*))?\Z", re.DOTALL)
#: The Tools-list lines of further MCP servers: "mcp:<name>" (agent profiles
#: write them into a session's groups too).
MCP_PREFIX = AP.MCP_PREFIX
#: The Tools-list lines of extensions with agent tools: "ext:<extension id>".
EXT_PREFIX = "ext:"
#: The Tools-list lines of MCP servers found on this machine (core.mcp_detect)
#: that are not in the settings yet: a tick adds one and uses it here.
DETECTED_PREFIX = "detected:"
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
#: Added to the system prompt while answers are read aloud.
VOICE_PROMPT = (
    "\nYour final answer is also read aloud: write plain sentences, keep it short, put code in "
    "code blocks. In a German answer put English technical terms in curly braces, e.g. "
    "{Pull Request}, so they are spoken in English."
)
MIC_TIPS = {
    "push_to_talk": "Hold to talk to the agent (or hold {key})",
    "toggle": "Click to talk, click again or pause to end ({key})",
    "conversation": "Click to start a spoken conversation, click again to end it ({key})",
}
VOICE_STATES = {"listening": "Listening…", "transcribing": "Recognising…",
                "speaking": "Speaking…"}
#: Most tasks kept for the Up key.
HISTORY_LIMIT = 50
#: The links of the transcript's Thinking blocks: "axross-thinking:<line>".
THINKING_SCHEME = "axross-thinking"
#: Longest first line a closed Thinking block shows.
SUMMARY_CHARS = 100


def reasoning_summary(text: str, limit: int = SUMMARY_CHARS) -> str:
    """The one line a closed Thinking block shows: its first line with
    text, cut at *limit* characters; "…" says that more follows."""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    if not lines:
        return ""
    first = lines[0]
    if len(first) > limit:
        return first[: limit - 1].rstrip() + "…"
    return first + (" …" if len(lines) > 1 else "")


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


def _ask_voice_remote(parent, profile: LP.LLMProfile, host: str) -> bool:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(tr("Send your voice to a remote server?"))
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setText(
        tr("The profile {name} recognises speech on {host}. Your recording is sent there.").format(
            name=profile.name, host=host
        )
    )
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    try:
        return box.exec() == QMessageBox.StandardButton.Yes
    finally:
        box.deleteLater()


def _default_voice(dock):
    from ui.voice import VoiceController

    return VoiceController(dock, profile_provider=dock.voice_profile,
                           confirm_remote=lambda p, h: _ask_voice_remote(dock, p, h))


def bypass_allowed(settings: AGS.AgentSettings) -> bool:
    from core.security_mode import is_paranoid

    return settings.allow_bypass and not is_paranoid()


class _LinkBridge(QObject):
    """Carries a connection check's result to the GUI thread:
    ``(tab, token, reachable, detail)``."""

    checked = pyqtSignal(object, int, bool, str)
    #: core.mcp_detect.DetectResult of a scan.
    detected = pyqtSignal(object)
    #: (on_done, detected server, config or None, error): a contained install ended.
    installed = pyqtSignal(object, object, object, str)


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
    #: A key that types something: new input, any speech stops.
    typed = pyqtSignal()

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        key = event.key()
        mods = event.modifiers()
        completer = getattr(self, "completer", None)
        if (
            completer is not None
            and completer.popup().isVisible()
            and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Escape, Qt.Key.Key_Tab,
                        Qt.Key.Key_Backtab)
        ):
            event.ignore()  # the completer's popup takes these
            return
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
        if event.text() and event.text().isprintable():
            self.typed.emit()
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
        #: A spoken conversation: each answer is spoken, then the microphone opens again.
        self._conversation = False
        self._hotkey_down = False
        self._refusals_said: set[str] = set()
        #: What the transcript shows, in order: ``{who, text, muted, kind}``
        #: (also lines that are not kept, the voice's notes).
        self._entries: list[dict] = []
        #: The Thinking blocks that are open (indexes into _entries).
        self._open: set[int] = set()
        #: Whether this tab's LLM is reachable: the dock's lamp.
        self.link = AL.LinkTracker()
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
        # In the head, not under Tools ▸: whether the agent may change files
        # at all must be visible at a glance (core.agent.read_only).
        self.read_only_check = QCheckBox(tr("Files read-only"))
        self.read_only_check.toggled.connect(lambda _on: self._store())
        self.settings_button = QPushButton(tr("LLM…"))
        self.settings_button.setToolTip(tr("LLM profiles"))
        self.settings_button.clicked.connect(self.dock.settings_requested.emit)
        head.addWidget(self.model_combo, 2)
        head.addWidget(self.mode_combo, 1)
        head.addWidget(self.sandbox_combo, 1)
        head.addWidget(self.read_only_check)
        head.addWidget(self.access_button)
        head.addWidget(self.settings_button)
        layout.addLayout(head)
        self.profile_label = QLabel()
        self.profile_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.profile_label)
        # What applying the tab's agent profile cut or missed (core.agent_profiles),
        # with Install from Catalog… links; hidden while there is nothing to say.
        self.profile_notes = QLabel()
        self.profile_notes.setTextFormat(Qt.TextFormat.RichText)
        self.profile_notes.setWordWrap(True)
        self.profile_notes.setStyleSheet("color: #b9770e;")
        self.profile_notes.linkActivated.connect(self.profile_notes_link)
        self.profile_notes.hide()
        layout.addWidget(self.profile_notes)
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
        self.groups.itemChanged.connect(self._on_group_changed)
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
        self.transcript.anchorClicked.connect(self._on_anchor)
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
        # "/" at the start of the task offers the work prompts' commands.
        self.slash_model = QStringListModel(self)
        self.slash_completer = QCompleter(self.slash_model, self)
        self.slash_completer.setWidget(self.input)
        self.slash_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.slash_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.slash_completer.activated[str].connect(self._slash_chosen)
        self.input.completer = self.slash_completer
        self.input.textChanged.connect(self._update_slash_popup)

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
            tr("Prepared tasks: inventory, installs, logs, disk usage, ... - and your own "
               "(+ New Topic…)")
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
        from ui.icon_provider import icon

        self.mic_button = QToolButton()
        self.mic_button.setIcon(icon("mic"))
        self.mic_button.pressed.connect(self._mic_pressed)
        self.mic_button.released.connect(self._mic_released)
        self.mic_button.clicked.connect(self._mic_clicked)
        self.speaker_button = QToolButton()
        self.speaker_button.setIcon(icon("speaker"))
        self.speaker_button.setCheckable(True)
        self.speaker_button.setToolTip(tr("Read the agent's answers aloud"))
        self.speaker_button.toggled.connect(self._on_speaker)
        self.voice_label = QLabel()
        self.voice_label.setStyleSheet("color: #888;")
        self.input.typed.connect(self._on_typed)
        buttons.addWidget(self.attach_button)
        buttons.addWidget(self.topics_button)
        buttons.addWidget(self.new_button)
        buttons.addStretch(1)
        buttons.addWidget(self.voice_label)
        buttons.addWidget(self.mic_button)
        buttons.addWidget(self.speaker_button)
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
        from ui.voice_lens import LensOverlay

        self.lens = LensOverlay(self.transcript)
        self.update_voice_look()

    # -- voice ----------------------------------------------------------------------------

    @property
    def voice(self):
        return self.dock.voice

    def update_voice_look(self) -> None:
        """The microphone and speaker as the voice settings and state say."""
        from core.security_mode import is_paranoid

        settings = self.voice.settings
        mode = settings.input_mode
        listening = self.voice.listening() and self.dock.voice_tab is self
        self.mic_button.setCheckable(mode != "push_to_talk")
        self.mic_button.blockSignals(True)
        self.mic_button.setChecked(mode != "push_to_talk" and (
            self._conversation if mode == "conversation" else listening))
        self.mic_button.blockSignals(False)
        paranoid = is_paranoid()
        self.mic_button.setEnabled(not paranoid)
        self.mic_button.setToolTip(
            tr("The microphone is off in the paranoid security mode") if paranoid
            else tr(MIC_TIPS[mode]).format(key=settings.hotkey))
        self.speaker_button.blockSignals(True)
        self.speaker_button.setChecked(settings.output_enabled)
        self.speaker_button.blockSignals(False)
        state = self.voice.state if self.dock.voice_tab in (self, None) else "idle"
        self.voice_label.setText(tr(VOICE_STATES[state]) if state in VOICE_STATES else "")
        self._update_buttons()

    def _start_listening(self) -> bool:
        self.dock.voice_tab = self
        started = self.voice.start_listening(
            auto_stop=self.voice.settings.input_mode != "push_to_talk")
        self.update_voice_look()
        return started

    def _mic_pressed(self) -> None:
        if self.voice.settings.input_mode == "push_to_talk":
            self._start_listening()

    def _mic_released(self) -> None:
        if self.voice.settings.input_mode == "push_to_talk" and self.dock.voice_tab is self:
            self.voice.stop_listening()

    def _mic_clicked(self) -> None:
        mode = self.voice.settings.input_mode
        if mode == "toggle":
            if self.voice.listening():
                self.voice.stop_listening()
            else:
                self._start_listening()
        elif mode == "conversation":
            if self._conversation:
                self.end_conversation()
            else:
                self._conversation = True
                if not self._start_listening():
                    self._conversation = False
        self.update_voice_look()

    def end_conversation(self) -> None:
        self._conversation = False
        if self.dock.voice_tab is self:
            self.voice.cancel_listening()
            self.voice.stop_speaking()
        self.update_voice_look()

    def _hotkey(self) -> QKeySequence:
        return QKeySequence(self.voice.settings.hotkey)

    def _is_hotkey(self, event) -> bool:
        portable = QKeySequence.SequenceFormat.PortableText
        return QKeySequence(event.keyCombination()).toString(portable) == \
            self.voice.settings.hotkey

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._is_hotkey(event):
            event.accept()
            if not event.isAutoRepeat() and not self._hotkey_down:
                self._hotkey_down = True
                if self.voice.settings.input_mode == "push_to_talk":
                    self._start_listening()
                else:
                    self._mic_clicked()
            return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event) -> None:  # noqa: N802 - Qt override
        hotkey = self._hotkey()
        if self._hotkey_down and hotkey.count() and event.key() == hotkey[0].key():
            event.accept()
            if not event.isAutoRepeat():
                self._hotkey_down = False
                self._mic_released()
            return
        super().keyReleaseEvent(event)

    def on_voice_text(self, text: str) -> None:
        """Recognised speech: into the task field, or sent (the setting, and
        always in a conversation). Never an answer to a confirmation."""
        if self._conversation or self.voice.settings.after_recognition == "send":
            if not self.busy():
                self.input.setPlainText(text)
                self.send()
                return
        current = self.input.toPlainText().rstrip()
        self.input.setPlainText(f"{current} {text}" if current else text)
        cursor = self.input.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.input.setTextCursor(cursor)
        self.input.setFocus()

    def on_speaking_finished(self) -> None:
        if self._conversation and not self.busy() and not self.voice.listening():
            QTimer.singleShot(0, self._listen_again)

    def _listen_again(self) -> None:
        if self._conversation and not self.busy() and not self.voice.listening():
            if not self._start_listening():
                self._conversation = False
                self.update_voice_look()

    def _on_speaker(self, on: bool) -> None:
        self.voice.set_output_enabled(on)
        self.dock.update_voice_look()

    def _on_typed(self) -> None:
        if self.voice.speaking():
            self.voice.stop_speaking()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        if not self.lens.isHidden():
            self.lens.cover()

    def _toggle_tools(self, shown: bool) -> None:
        self.tools_box.setVisible(shown)
        self.tools_button.setText(tr("Tools ▾") if shown else tr("Tools ▸"))

    # -- session <-> widgets -------------------------------------------------------------

    def _load_session(self) -> None:
        s = self.session
        self._loading = True
        try:
            if not s.folder:
                s.folder = self.dock.root_provider()
            self.root_edit.setText(s.folder)
            self._load_settings()
            self._entries = [{"who": e["who"], "text": e["text"], "muted": e.get("muted", False),
                              "kind": e.get("kind", "")} for e in s.transcript]
            self._render_all()
            # The latest lines in view, as appending them showed them.
            self.transcript.moveCursor(QTextCursor.MoveOperation.End)
        finally:
            self._loading = False
        self._store(save=False)
        self._update_buttons()

    def _load_settings(self) -> None:
        """The session's model, mode, sandbox, tools and switches into the
        widgets (its conversation and folder are not touched)."""
        s = self.session
        was = getattr(self, "_loading", False)
        self._loading = True
        try:
            self.refresh_choices()
            # A tab set up from an agent profile takes its groups as they are,
            # also none; otherwise none means the General page's.
            groups = (set(s.groups) if s.groups or s.agent_profile
                      else set(self.dock.agent_settings.groups))
            for i in range(self.groups.count()):
                item = self.groups.item(i)
                if item.text().startswith(DETECTED_PREFIX):
                    continue
                item.setCheckState(
                    Qt.CheckState.Checked if item.text() in groups else Qt.CheckState.Unchecked
                )
            self.allow_write.setChecked(s.allow_write)
            self.allow_exec.setChecked(s.allow_exec)
            self.read_only_check.setChecked(s.files_read_only or self._read_only_forced())
        finally:
            self._loading = was

    def apply_resolution(self, profile: AP.AgentProfile, res: AP.Resolution) -> None:
        """Set the tab up as *res* (core.agent_profiles.resolve of *profile*)
        says, show what was cut or is missing, and save it."""
        res.apply_to(self.session, profile.name)
        self._load_settings()
        self._store(save=False)
        self._update_access_tip()
        self.show_profile_report(res)
        self.changed.emit()

    def show_profile_report(self, res: AP.Resolution | None) -> None:
        """The notes and missing servers of the profile applied last, with
        Install from Catalog… links (None: nothing to show)."""
        import html

        self._profile_report = res
        if res is None or not (res.notes or res.missing):
            self.profile_notes.clear()
            self.profile_notes.hide()
            return
        lines = [html.escape(n) for n in res.notes]
        if res.notes:
            # The notes are what Agent Settings said then: after changing them,
            # applying again takes what they allow now.
            lines.append('<a href="apply:again">' + html.escape(tr("Apply Profile again"))
                         + "</a>")
        for missing in res.missing:
            target = html.escape(f"{missing.kind}:{missing.name}", quote=True)
            line = html.escape(AP.missing_text(missing))
            if missing.why == "not installed":
                line += f' <a href="{target}">' + html.escape(tr("Install from Catalog…")) + "</a>"
            lines.append(line)
        self.profile_notes.setText("<br>".join(lines))
        self.profile_notes.show()

    def profile_link_targets(self) -> list[str]:
        """The Install from Catalog… links the notes show now."""
        res = getattr(self, "_profile_report", None)
        return [f"{m.kind}:{m.name}" for m in (res.missing if res else ())
                if m.why == "not installed"]

    def profile_notes_link(self, target: str):
        """An Install from Catalog… link: the catalog, on the category (or
        searching the server's name). Returns the dialog."""
        kind, _sep, name = str(target).partition(":")
        if kind == "category":
            return self.dock.install_from_catalog(self, category=name)
        if kind == "server":
            return self.dock.install_from_catalog(self, query=name)
        if kind == "apply" and self.session.agent_profile:
            self.dock.apply_profile(self, self.session.agent_profile)
        return None

    def prompts(self):
        """The prompt profile of this tab (core.agent_prompts)."""
        return self.dock.agent_settings.prompts_for(self.session.prompt_profile)

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
        finally:
            self._loading = was
        self._update_profile_label()
        self._update_mode_look()
        self._update_access_tip()

    def _fill_servers(self, settings) -> None:
        """One "mcp:<name>" line per enabled MCP server and one "ext:<id>"
        line per extension with agent tools, ticked as the session says."""
        for i in reversed(range(self.groups.count())):
            if self.groups.item(i).text().startswith((MCP_PREFIX, EXT_PREFIX, DETECTED_PREFIX)):
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
        from ui.agent_settings_dialog import free_name
        from ui.mcp_catalog_dialog import plain_tooltip

        names = {s.name for s in settings.mcp_servers}
        for detected in self.dock.detected_servers():
            # The name it gets when it is added (core.mcp_detect names may repeat).
            name = free_name(detected.name, names)
            names.add(name)
            item = QListWidgetItem(DETECTED_PREFIX + name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, detected.key)
            item.setToolTip(plain_tooltip(
                detected.describe() + "\n\n" + tr(
                    "Tick to add it to Agent Settings, switched on, and use it in this tab"
                    "{sandbox}.").format(sandbox=tr(" (in its sandbox profile)")
                                         if self.session.sandbox else "")))
            self.groups.addItem(item)

    def _on_group_changed(self, item) -> None:
        if item.text().startswith(DETECTED_PREFIX):
            if item.checkState() == Qt.CheckState.Checked and not getattr(self, "_loading", False):
                key = item.data(Qt.ItemDataRole.UserRole)
                # Not inside itemChanged: using it rebuilds this very list.
                use = weak_call(self, "_use_detected")
                QTimer.singleShot(0, lambda: use(key))
            return
        self._store()

    def _use_detected(self, key: str) -> None:
        """Add the detected server *key* (switched on; a program in this
        tab's sandbox profile, one that downloads code installed into a
        container first) and tick it here; untick it when it was not added."""
        started = self.dock.add_detected(key, sandbox=self.session.sandbox or "", parent=self,
                                         on_done=weak_call(self, "_detected_added"))
        if not started:
            self.refresh_choices()

    def _detected_added(self, config) -> None:
        if config is None:
            self.refresh_choices()
            return
        self.session.groups = sorted(set(self.session.groups) | {MCP_PREFIX + config.name})
        self.changed.emit()
        self.dock.reload_settings()

    def _read_only_forced(self) -> bool:
        """Agent Settings > Access makes files read-only in every tab."""
        return bool(getattr(self.dock.agent_settings.access, "files_read_only", False))

    def files_read_only(self) -> bool:
        return self._read_only_forced() or self.session.files_read_only

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
        if self.read_only_check.isEnabled():
            # Forced by Agent Settings, the box shows the ceiling, not the
            # tab's own choice: that one is kept for when it is lifted.
            s.files_read_only = self.read_only_check.isChecked()
        self._update_profile_label()
        self._update_mode_look()
        self.dock.check_link(self, when="changed")
        if save:
            self.changed.emit()

    def _update_profile_label(self) -> None:
        profile = self.profile()
        parts = [
            tr("Model: {name}").format(name=profile.name) if profile
            else tr("No LLM profile is active: set one up with LLM…")
        ]
        if self.session.agent_profile:
            parts.append(tr("Profile: {name}").format(name=self.session.agent_profile))
        if self.session.prompt_profile:
            parts.append(tr("Prompt: {name}").format(name=self.session.prompt_profile))
        self.profile_label.setText(" · ".join(parts))
        self._update_buttons()

    def _update_mode_look(self) -> None:
        mode = self.session.mode
        self.bypass_label.setVisible(mode == "bypass")
        sandbox = self.sandbox_profile()
        from core.agent_sandbox import writes_allowed

        forced = self._read_only_forced()
        read_only = self.files_read_only()
        self.read_only_check.blockSignals(True)
        self.read_only_check.setChecked(read_only)
        self.read_only_check.blockSignals(False)
        self.read_only_check.setEnabled(not forced)
        self.read_only_check.setToolTip(
            tr("Agent Settings > Access makes files read-only in every tab")
            if forced
            else tr(
                "The agent reads files but changes none: no writing, deleting or moving, "
                "no remote commands, no writing tools of MCP servers or extensions - except "
                "a container server axross installed with no network and only read-only "
                "folders (its calls still ask as its Asks says)"
            )
        )
        can_write = mode != "plan" and writes_allowed(sandbox) and not read_only
        self.allow_write.setEnabled(can_write)
        self.allow_write.setToolTip(
            ""
            if can_write
            else (
                tr("Files read-only is on")
                if read_only
                else tr("Plan mode only reads")
                if mode == "plan"
                else tr("This sandbox mounts nothing writable")
            )
        )
        can_exec = (
            not read_only
            and "remote_commands" in self.functions()
            and self._exec_policy()
        )
        self.allow_exec.setEnabled(can_exec)
        self.allow_exec.setToolTip(
            ""
            if can_exec
            else tr("Files read-only is on: a command could change files")
            if read_only
            else tr(
                "Remote commands are off in this tab's Access, Agent Settings "
                "or the security mode"
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
        voice = getattr(self.dock, "voice", None)
        usable = {
            self.send_button: not busy and self.profile() is not None,
            self.stop_button: busy or bool(voice is not None and voice.speaking()),
            self.new_button: not busy,
            self.plan_button: self._plan_ready and not busy,
        }
        # A clicked button keeps the keyboard focus. Disabled or hidden, Qt
        # hands it to the next widget (the tab bar, the microphone) and the
        # next task typed is lost: the task field takes it instead.
        focus = self.window().focusWidget()
        if focus in usable and not usable[focus]:
            self.input.setFocus()
        self.send_button.setEnabled(usable[self.send_button])
        self.stop_button.setEnabled(usable[self.stop_button])
        self.new_button.setEnabled(usable[self.new_button])
        self.plan_button.setVisible(usable[self.plan_button])

    def selected_groups(self) -> frozenset:
        return frozenset(
            self.groups.item(i).text()
            for i in range(self.groups.count())
            if self.groups.item(i).checkState() == Qt.CheckState.Checked
            and not self.groups.item(i).isHidden()
            and not self.groups.item(i).text().startswith(DETECTED_PREFIX)
        )

    def _on_root_edited(self, text: str) -> None:
        self._root_typed = bool(text)
        self._store()

    def set_folder(self, folder: str) -> None:
        """Work in *folder* from now on, as if it had been typed: the tab no
        longer follows the active pane."""
        self.root_edit.setText(folder)
        self._on_root_edited(folder)

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
        # The tab's prompt profile (its agent profile's, else Agent Settings >
        # Prompts'); Default is A.SYSTEM_PROMPT.
        prompt = self.prompts().system_prompt + (
            PLAN_PROMPT if mode == "plan" else "") + (
            VOICE_PROMPT if self.voice.settings.output_enabled else "")
        return A.AgentConfig(
            profile=profile, api_key=key,
            root=os.path.abspath(os.path.expanduser(self.root_edit.text().strip() or "~")),
            groups=frozenset(groups), allow_write=allow_write, allow_exec=allow_exec,
            files_read_only=self.files_read_only(),
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

    def _show(self, who: str, text: str, muted: bool = False, *, kind: str = "") -> None:
        self._entries.append({"who": who, "text": text, "muted": muted, "kind": kind})
        self.transcript.append(self._entry_html(len(self._entries) - 1))

    def _entry_html(self, index: int) -> str:
        entry = self._entries[index]
        # A paragraph separator would start a block of its own inside this
        # line: the transcript keeps one block per line (toggle_reasoning).
        text = entry["text"].replace("\u2029", "\n")
        if entry["kind"] == "reasoning":
            # The model's thinking: grey and italic, closed to one line; the
            # label opens and closes it. The text is escaped like any line,
            # so the model cannot add a link of its own.
            opened = index in self._open
            label = (f'<a href="{THINKING_SCHEME}:{index}" style="color:#888; '
                     f'text-decoration:none"><b>{"▾" if opened else "▸"} '
                     f'{html.escape(tr("Thinking"))}</b></a>')
            body = (html.escape(text).replace(chr(10), "<br>") if opened
                    else html.escape(reasoning_summary(text)))
            return f'<p style="color:#888"><i>{label}{"<br>" if opened else " "}{body}</i></p>'
        # No colour on normal lines: the theme's text colour applies. Qt's
        # rich text has no "inherit" - it paints that as black.
        style = ' style="color:#888"' if entry["muted"] else ""
        return (f"<p{style}><b>{html.escape(entry['who'])}</b> "
                f"{html.escape(text).replace(chr(10), '<br>')}</p>")

    def _append(self, who: str, text: str, *, muted: bool = False, kind: str = "") -> None:
        self._show(who, text, muted, kind=kind)
        entry = {"who": who, "text": text, "muted": muted}
        if kind:
            entry["kind"] = kind
        self.session.transcript.append(entry)

    def _on_anchor(self, url: QUrl) -> None:
        if url.scheme() != THINKING_SCHEME:
            return  # the transcript has no other links; nothing is opened
        try:
            index = int(url.path())
        except ValueError:
            return
        self.toggle_reasoning(index)

    def toggle_reasoning(self, index: int) -> None:
        """Open a closed Thinking block, close an open one. The transcript
        is drawn again; the view stays where it was (at the end, if it was
        there)."""
        if not 0 <= index < len(self._entries) or self._entries[index]["kind"] != "reasoning":
            return
        self._open ^= {index}
        bar = self.transcript.verticalScrollBar()
        at_end, value = bar.value() >= bar.maximum(), bar.value()
        document = self.transcript.document()
        if document.blockCount() == len(self._entries):
            # One block per line: only this one is drawn again, not the
            # whole transcript (130 ms for 850 lines).
            cursor = QTextCursor(document.findBlockByNumber(index))
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            cursor.insertHtml(self._entry_html(index))
        if document.blockCount() != len(self._entries):
            self._render_all()  # out of step: drawn again whole
        bar.setValue(bar.maximum() if at_end else min(value, bar.maximum()))

    def _render_all(self) -> None:
        """Draw the whole transcript at once: one setHtml gives the same
        document as appending line by line, which took twice as long in a
        hidden tab and almost five times as long in a shown one."""
        self.transcript.setHtml("".join(self._entry_html(i) for i in range(len(self._entries))))

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
        from core.agent_topics import command_of

        menu = self.topics_menu
        menu.clear()
        menu.setToolTipsVisible(True)
        source = None
        for topic in self.dock.topics():
            if source is not None and topic.source != source:
                menu.addSeparator()
            source = topic.source
            action = menu.addAction(f"{topic.title}\t/{command_of(topic)}")
            action.setToolTip(topic.description)
            action.setStatusTip(topic.description)
            action.triggered.connect(lambda _c=False, t=topic: self.use_topic(t))
        # Own topics: written here, stored in work_prompts.json (core.agent_topics).
        menu.addSeparator()
        menu.addAction(tr("+ New Topic…"), self.new_topic)
        menu.addAction(tr("Save This Task as Topic…"), self.save_task_as_prompt)
        menu.addAction(tr("Edit or Delete My Topics…"), self.manage_prompts)

    # -- work prompts: "/" commands ---------------------------------------------------------

    def _slash_token(self) -> tuple[str, str] | None:
        """("/command", rest) when the task starts like a slash command:
        "/" then letters, digits or "-" up to the first space or line end.
        A path ("/etc/ssh/…") is no command."""
        match = _SLASH.match(self.input.toPlainText())
        if match is None:
            return None
        return "/" + match.group(1), (match.group(2) or "").strip()

    def slash_matches(self) -> list[str]:
        """The commands that start with what was typed after "/"."""
        from core.agent_topics import command_of

        token = self._slash_token()
        if token is None:
            return []
        prefix = token[0][1:].lower()
        return sorted(f"/{command_of(t)}" for t in self.dock.topics()
                      if command_of(t).startswith(prefix))

    def _update_slash_popup(self) -> None:
        token = self._slash_token()
        matches = self.slash_matches() if token is not None and not token[1] else []
        popup = self.slash_completer.popup()
        if not matches or matches == [token[0]]:
            popup.hide()
            return
        self.slash_model.setStringList(matches)
        self.slash_completer.setCompletionPrefix(token[0])
        rect = self.input.cursorRect()
        rect.setWidth(max(240, popup.sizeHintForColumn(0) + 24))
        self.slash_completer.complete(rect)
        # Return takes the first match, as in a command palette.
        popup.setCurrentIndex(self.slash_completer.completionModel().index(0, 0))

    def _slash_chosen(self, command: str) -> None:
        token = self._slash_token()
        self.apply_slash(command, token[1] if token else "")

    def apply_slash(self, command: str, extra: str = "") -> bool:
        """Fill the task field from the topic of *command*, with *extra*
        (what was typed after the command) below it. False: no such topic."""
        from core.agent_topics import find_topic

        topic = find_topic(self.dock.topics(), command)
        if topic is None:
            return False
        self.slash_completer.popup().hide()
        self.use_topic(topic)
        if extra:
            self.input.setPlainText(self.input.toPlainText().rstrip() + "\n\n" + extra)
        return True

    def manage_prompts(self):
        from ui.work_prompts_dialog import WorkPromptsDialog

        dlg = WorkPromptsDialog(self)
        dlg.exec()
        return dlg

    def new_topic(self):
        """Topics ▸ + New Topic…: an empty form for an own topic."""
        from ui.work_prompts_dialog import WorkPromptsDialog

        dlg = WorkPromptsDialog(self, new=True)
        dlg.exec()
        return dlg

    def save_task_as_prompt(self):
        from ui.work_prompts_dialog import WorkPromptsDialog

        dlg = WorkPromptsDialog(self, task=self.input.toPlainText().strip())
        dlg.exec()
        return dlg

    def use_topic(self, topic) -> None:
        """Type the topic's task into the task field; the user sends it."""
        backend = next((a["backend"] for a in self._attachments if not a["local"]), "") or ""
        self.input.setPlainText(topic.render(self.root_edit.text().strip(), backend))
        if topic.groups:
            wanted = set(topic.groups)
            for i in range(self.groups.count()):
                item = self.groups.item(i)
                if item.text() in wanted:
                    item.setCheckState(Qt.CheckState.Checked)
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
        if self.busy() or self.voice.speaking() or self._conversation:
            self.stop()

    def new_conversation(self) -> None:
        if self.busy():
            return
        # Closed, not just dropped: the connections it opened would stay open.
        self._close_agent()
        self._agent_key = None
        self.transcript.clear()
        self._entries.clear()
        self._open.clear()
        self.session.transcript.clear()
        self.session.messages.clear()
        self._plan_ready = False
        self.plan_label.clear()
        self.plan_label.hide()
        self._started = 0.0
        self._update_status()
        self._update_buttons()
        # The click left the keyboard focus on this button: the next task
        # is typed into the field, as in a new tab (AgentDock.new_tab).
        self.input.setFocus()
        self.changed.emit()

    def run_plan(self) -> None:
        if self.busy() or not self._plan_ready:
            return
        self._plan_ready = False
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData("ask")))
        self._send(RUN_PLAN_TASK)

    def send(self) -> None:
        task = self.input.toPlainText().strip()
        if VT.is_pod_bay_request(task):
            self.input.clear()
            self.dock.voice_tab = self
            self.voice.play_line()
            return
        if not task or self.busy():
            return
        self.voice.stop_speaking()
        token = self._slash_token()
        if token is not None:
            # A work prompt's command fills the field; the user reads it and
            # sends again. An unknown bare command is said, not sent; text
            # after an unknown "/word" is an ordinary task ("/tmp is full").
            if self.apply_slash(token[0], token[1]):
                return
            if not token[1]:
                self._append(
                    tr("axross:"),
                    tr("No topic {command}. Type / to see the commands, or Topics ▸ "
                       "+ New Topic… to write one.").format(command=token[0]),
                    muted=True,
                )
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
            config.files_read_only,
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
                    # The agent's own system message names the folder of now.
                    self._agent.messages = A.with_system_message(history,
                                                                 self._agent.messages[0])
            self._agent_key = key
        self._cancel.clear()
        self._refusals_said = set()
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
        # The tab's prompt profile's user prompt wraps what was typed; the
        # transcript keeps the typed task. "Run the plan" is axross's own.
        sent = task
        if task != RUN_PLAN_TASK:
            from core.agent_prompts import render_task

            sent = render_task(self.prompts().user_prompt, task)
        self._started = time.monotonic()
        self._tool_calls = 0
        self._steps = 0
        self._mode_of_run = mode
        self.dock.emit_event(self, {"type": "run_started", "mode": mode,
                                    "sandbox": self.session.sandbox or None})

        def work() -> None:
            try:
                result = agent.run(context + sent)
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
        voice = getattr(self.dock, "voice", None)
        if voice is not None and self.dock.voice_tab in (self, None):
            self._conversation = False
            voice.cancel_listening()
            voice.stop_speaking()
            self.update_voice_look()

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
            # A reasoning model sends "\n\n" before its answer (LM Studio,
            # Qwen): shown, that is empty lines under "Agent:". The history
            # sent back to the model keeps what the model wrote.
            text = str(event.get("text", "")).strip()
            # Terms marked for the voice ({Pull Request}) are shown plain.
            self._append(tr("Agent:"), VT.strip_term_braces(text)
                         if self.voice.settings.output_enabled else text)
        elif kind == "reasoning":
            # Not an answer: not counted, not spoken (only result.answer is).
            self._append(tr("Thinking:"), str(event.get("text", "")), muted=True,
                         kind="reasoning")
        elif kind == "connection":
            if self.link.on_event(event):
                self.dock.show_link()
        elif kind == "tool_call":
            self._tool_calls += 1
            args = json.dumps(event.get("args", {}), ensure_ascii=False)
            self._append("→", f"{event.get('name')} {args[:300]}", muted=True)
        elif kind == "tool_result":
            detail = event.get("detail")
            line = f"{event.get('name')}: {event.get('outcome')}"
            self._append("←", f"{line} - {detail}" if isinstance(detail, str) and detail else line,
                         muted=True)
            reason = event.get("reason")
            if reason in A.REFUSAL_REASONS and reason not in self._refusals_said:
                self._refusals_said.add(reason)
                self.voice.say_refusal(reason)
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
        spoken = False
        if result is not None and result.stopped == "answered" and result.answer:
            self.dock.voice_tab = self
            spoken = self.voice.speak_answer(result.answer)
        if self._conversation and not spoken:
            QTimer.singleShot(0, self._listen_again)
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
    #: "+" ▸ Edit Agent Profiles…: Agent Settings on its Profiles page.
    profiles_requested = pyqtSignal()
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
        voice_factory: Callable[[AgentDock], object] | None = None,
        agent_settings_saver: Callable[[AGS.AgentSettings], None] | None = None,
        mcp_detector: Callable[..., object] | None = None,
        mcp_opener=None,
    ) -> None:
        super().__init__(tr("Agent"), parent)
        self.setObjectName("axAgentDock")
        #: The tab the voice listens and speaks for.
        self.voice_tab: AgentTab | None = None
        #: The conversation the keyboard focus was in last (a tab here or a
        #: detached panel): the voice's target while no tab listens.
        self.focus_tab: AgentTab | None = None
        #: The detached conversations (ui.agent_panels.AgentPanel).
        self._panels: list[AgentPanel] = []
        #: The window that lays the panels out (the main window:
        #: add_agent_panel / remove_agent_panel); None: they float.
        self.panel_host = None
        #: Between restore_detached and settle_detached: the places of the
        #: restored panels are not written (the layout restore moves them).
        self._settling = False
        self._closing = False
        self.voice = (voice_factory or _default_voice)(self)
        self.llm_settings = settings_loader or LP.LLMSettings.load
        self._save_llm_settings = settings_saver or (lambda s: s.save())
        self.key_lookup = key_lookup or LP.get_api_key
        self.confirm_remote = confirm_remote or (lambda p, h: _ask_remote(self, p, h))
        self.confirm_call = confirm_call or (lambda n, a: _ask_call(self, n, a))
        #: ``ask_user(question) -> answer or None`` for the agent's questions.
        self.ask_user = lambda question: _ask_user(self, question)
        self.root_provider = root_provider or (lambda: os.path.expanduser("~"))
        self._load_agent_settings = agent_settings_loader or AGS.AgentSettings.load
        self._save_agent_settings = agent_settings_saver or (lambda s: s.save())
        self.agent_settings = self._load_agent_settings()
        #: Finds the MCP servers on this machine (core.mcp_detect); what it
        #: found last.
        self._mcp_detector = mcp_detector
        #: urllib's opener for the package registries of a contained install (tests).
        self._mcp_opener = mcp_opener
        self._detected: list = []
        self._detect_started = False
        #: What applying an agent profile to a new session said, until its tab shows it.
        self._pending_reports: dict = {}
        self.store = session_store if session_store is not None else SessionStore()
        self.pane_items = pane_items or (lambda kind: None)
        self.pane_backend = pane_backend or (lambda pane_id: (None, True))
        #: The remote connections of the panes: ``(id, backend, profile)``.
        self.remote_backends = remote_backends or (lambda: [])
        #: The connected MCP servers, shared by every tab.
        self.mcp_pool = mcp_pool if mcp_pool is not None else McpClientPool()
        #: The extension host (ui.extension_host), or None.
        self._extensions = extensions or (lambda: None)
        from ui.agent_link_lamp import LinkLamp

        #: Whether the current tab's LLM is reachable (core.agent_link); the
        #: main window puts it in the title bar (show_lamp_in).
        self.lamp = LinkLamp(self)
        self.lamp.hide()  # until a title bar shows it, never over the tabs
        self.lamp.clicked.connect(lambda: self.check_link(when="always"))
        self._link_bridge = _LinkBridge(self)
        self._link_bridge.checked.connect(self._on_link_checked)
        self._link_bridge.detected.connect(self._on_detected)
        self._link_bridge.installed.connect(self._on_installed)

        self.tabs = QTabWidget()
        bar = DetachTabBar()
        self.tabs.setTabBar(bar)
        bar.detach_requested.connect(lambda index: self.detach_tab(self.tabs.widget(index)))
        bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bar.customContextMenuRequested.connect(self._show_tab_menu)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(
            lambda _i: self.current_tab() and self.current_tab().follow_folder()
        )
        self.tabs.currentChanged.connect(lambda _i: self.check_link(when="stale"))
        self.tabs.currentChanged.connect(lambda _i: self._follow_current())
        self.visibilityChanged.connect(lambda shown: shown and self.check_link(when="stale"))
        self.visibilityChanged.connect(lambda shown: shown and self._detect_once())
        self.tabs.tabBarDoubleClicked.connect(self.rename_tab)
        corner = QWidget()
        corner_row = QHBoxLayout(corner)
        corner_row.setContentsMargins(0, 0, 0, 0)
        corner_row.setSpacing(0)
        new_tab = QToolButton()
        new_tab.setText("+")
        new_tab.setToolTip(tr("New tab (Ctrl+T); the arrow: agent profiles"))
        new_tab.clicked.connect(lambda: self.new_tab())
        # The arrow: New Tab from Profile ▸, Apply Profile…, Edit Agent Profiles….
        new_tab.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.profiles_menu = QMenu(new_tab)
        self.profiles_menu.aboutToShow.connect(self._fill_profiles_menu)
        new_tab.setMenu(self.profiles_menu)
        self.new_tab_button = new_tab
        corner_row.addWidget(new_tab)
        self.new_window_button = QToolButton()
        self.new_window_button.setText("⧉")  # ⧉: a window of its own
        self.new_window_button.setToolTip(
            tr("New Agent Window: a conversation in a panel of its own"))
        self.new_window_button.setAccessibleName(tr("New Agent Window"))
        self.new_window_button.clicked.connect(lambda: self.new_window())
        corner_row.addWidget(self.new_window_button)
        self.tabs.setCornerWidget(corner, Qt.Corner.TopRightCorner)
        # In a scroll area: the dock's smallest size is not its tabs' (ui.dock_frame).
        self.setWidget(framed(self.tabs, self))
        QShortcut(QKeySequence("Ctrl+T"), self.tabs, activated=lambda: self.new_tab(),
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)

        self.voice.transcribed.connect(self._on_voice_text)
        self.voice.notice.connect(self._on_voice_notice)
        self.voice.state_changed.connect(lambda _s: self.update_voice_look())
        self.voice.speaking_finished.connect(self._on_speaking_finished)
        self.voice.level.connect(self._on_voice_level)
        self.voice.line_started.connect(self._on_line_started)
        self.voice.line_finished.connect(self._on_line_finished)
        from ui.voice_settings_page import register_settings_page

        register_settings_page()

        from PyQt6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is not None:
            app.focusChanged.connect(weak_call(self, "_on_focus_changed"))

        restored = self.store.all() if self.agent_settings.keep_sessions else []
        for session in restored:
            self._add_tab(session)
        #: The tab the dock opened by itself, until someone uses it: Start
        #: Agent takes it over instead of leaving it empty beside a new one.
        self._placeholder: AgentTab | None = None
        if not restored:
            self._placeholder = self.new_tab(save=False)

    # -- tabs ---------------------------------------------------------------------------------

    def _make_tab(self, session: AgentSession) -> AgentTab:
        tab = AgentTab(self, session)
        tab.show_profile_report(self._pending_reports.pop(session.id, None))
        tab.changed.connect(lambda t=tab: self._save(t))
        tab.title_changed.connect(lambda title, t=tab: self._retitle(t, title))
        return tab

    def _add_tab(self, session: AgentSession) -> AgentTab:
        tab = self._make_tab(session)
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

    def _new_session(self, folder: str | None, profile: str | None = None) -> AgentSession:
        """A new tab's session: as Agent Settings say, set up from the agent
        profile *profile* (None: the default profile of new tabs, if any)."""
        s = self.agent_settings
        session = AgentSession(
            profile=s.profile,
            mode=s.mode if s.mode != "bypass" or bypass_allowed(s) else "ask",
            sandbox=s.sandbox,
            groups=list(s.groups),
            folder=folder or "",
            access=X.SessionAccess.from_settings(s.access),
        )
        chosen = AP.find_profile(s, s.agent_profile if profile is None else profile)
        if chosen is not None:
            res = self.resolve_profile(chosen)
            res.apply_to(session, chosen.name)
            self._pending_reports[session.id] = res
        return session

    # -- agent profiles (core.agent_profiles) ---------------------------------------------

    def profiles(self) -> list:
        """The presets, then the user's agent profiles."""
        return AP.all_profiles(self.agent_settings)

    def tab_modes(self) -> tuple:
        """The modes a tab may choose now."""
        s = self.agent_settings
        return tuple(m for m in s.modes() if m != "bypass" or bypass_allowed(s))

    def resolve_profile(self, profile) -> AP.Resolution:
        """What *profile* gives a tab under Agent Settings now (never wider
        than its Access page)."""
        try:
            names = [p.name for p in self.llm_settings().profiles]
        except Exception:  # noqa: BLE001 - a broken LLM file: names are not checked
            log.exception("LLM settings could not be read")
            names = None
        return AP.resolve(profile, self.agent_settings, llm_names=names, modes=self.tab_modes())

    def new_tab_from_profile(self, name: str, *, folder: str | None = None) -> AgentTab | None:
        """A new tab set up from the agent profile *name* (None: no such one)."""
        if AP.find_profile(self.agent_settings, name) is None:
            return None
        tab = self._add_tab(self._new_session(folder, profile=name))
        self._save(tab)
        tab.input.setFocus()
        return tab

    def apply_profile(self, tab: AgentTab, name: str) -> bool:
        """Set *tab* up from the agent profile *name*. Refused while a task
        runs in it (the running task keeps the settings it started with;
        changing them under it would only mislead)."""
        profile = AP.find_profile(self.agent_settings, name)
        if profile is None or tab is None:
            return False
        if tab.busy():
            QMessageBox.information(
                self, tr("Apply Profile"),
                tr("A task is running in {title}: stop it first, then apply the profile.").format(
                    title=tab.session.title))
            return False
        tab.apply_resolution(profile, self.resolve_profile(profile))
        return True

    def pick_profile(self, tab: AgentTab | None = None):
        """Apply Profile…: the dialog for *tab* (default: the current one),
        opened window-modal; OK applies. Returns the dialog."""
        from ui.agent_profile_dialog import ProfilePickerDialog

        tab = tab or self.current_tab()
        if tab is None:
            return None
        dialog = ProfilePickerDialog(self, tab.session.title, self.profiles(),
                                     self.resolve_profile,
                                     conversation=bool(tab.session.transcript))
        if tab.session.agent_profile:
            dialog.select(tab.session.agent_profile)

        def accepted() -> None:
            chosen = dialog.chosen()
            if chosen is not None and alive(tab):
                self.apply_profile(tab, chosen.name)

        dialog.accepted.connect(accepted)
        dialog.finished.connect(lambda _r: dialog.deleteLater())
        dialog.open()
        return dialog

    def _fill_profiles_menu(self) -> None:
        menu = self.profiles_menu
        menu.clear()
        new_menu = menu.addMenu(tr("New Tab from Profile"))
        new_menu.aboutToShow.connect(lambda m=new_menu: self.fill_new_from_profile_menu(m))
        self.fill_new_from_profile_menu(new_menu)
        apply = menu.addAction(tr("Apply Profile…"))
        apply.setEnabled(self.current_tab() is not None)
        apply.triggered.connect(lambda _checked=False: self.pick_profile())
        menu.addSeparator()
        menu.addAction(tr("Edit Agent Profiles…")).triggered.connect(
            lambda _checked=False: self.profiles_requested.emit())

    def fill_new_from_profile_menu(self, menu: QMenu, folder_provider=None) -> None:
        """One entry per profile, presets first ("(preset)"), then the
        user's; a click opens a new tab from it (in *folder_provider()*)."""
        from ui.agent_profile_dialog import profile_label

        menu.clear()
        presets_done = False
        for profile in self.profiles():
            if not profile.preset and not presets_done:
                menu.addSeparator()
                presets_done = True
            # "&" in a name is no mnemonic ("Network & Web Recon").
            action = menu.addAction(profile_label(profile).replace("&", "&&"))
            action.setToolTip(profile.description)
            action.triggered.connect(
                lambda _checked=False, n=profile.name: self.new_tab_from_profile(
                    n, folder=folder_provider() if folder_provider else None))

    def install_from_catalog(self, tab: AgentTab | None = None, *, category: str = "",
                             query: str = ""):
        """Add from Catalog on *category* (or searching *query*); what it
        installs is added to Agent Settings and ticked in *tab* when its
        profile wants it. Returns the dialog (window-modal, not blocking)."""
        from ui.mcp_catalog_dialog import McpCatalogDialog

        dialog = McpCatalogDialog(self, sources=self.agent_settings.mcp_sources,
                                  taken={s.name for s in self.agent_settings.mcp_servers},
                                  opener=self._mcp_opener, category=category, query=query)
        dialog.installed.connect(
            lambda config, secrets, token: self._catalog_installed(tab, config, secrets, token))
        dialog.finished.connect(lambda _r: dialog.deleteLater())
        dialog.open()
        return dialog

    def _catalog_installed(self, tab, config, secrets, token: str) -> None:
        stored = self.store_server(config, secrets or {}, token, parent=self)
        if stored is None:
            return
        self.reload_settings()
        if tab is None or not alive(tab):
            return
        profile = AP.find_profile(self.agent_settings, tab.session.agent_profile)
        if profile is None:
            return
        res = self.resolve_profile(profile)
        if MCP_PREFIX + stored.name in res.groups:
            tab.session.groups = sorted(set(tab.session.groups) | {MCP_PREFIX + stored.name})
            tab._load_settings()
            tab.changed.emit()
        tab.show_profile_report(res)

    def new_tab(
        self, *, save: bool = True, task: str | None = None, folder: str | None = None
    ) -> AgentTab:
        tab = self._add_tab(self._new_session(folder))
        if save:
            self._save(tab)
        if task:
            tab.input.setPlainText(task)
        tab.input.setFocus()
        return tab

    def current_tab(self) -> AgentTab | None:
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, AgentTab) else None

    def docked_tabs(self) -> list[AgentTab]:
        """The conversations shown as tabs of this dock."""
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def all_tabs(self) -> list[AgentTab]:
        """Every conversation: the tabs, then the detached panels'."""
        return [*self.docked_tabs(), *(panel.tab for panel in self.panels())]

    def _retitle(self, tab: AgentTab, title: str) -> None:
        index = self.tabs.indexOf(tab)
        if index >= 0:
            self.tabs.setTabText(index, title)
            self.tabs.setTabToolTip(index, title)
        panel = self.panel_of(tab)
        if panel is not None:
            panel.set_title(title)

    def rename_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        if not isinstance(tab, AgentTab):
            return
        title, ok = QInputDialog.getText(self, tr("Rename tab"), tr("Name"), text=tab.session.title)
        if ok and title.strip():
            tab.session.title = title.strip()[:80]
            self._retitle(tab, tab.session.title)
            self._save(tab)

    def _may_close(self, tab: AgentTab, heading: str) -> bool:
        """Closing *tab* deletes its conversation: asked first when there is
        one (or a task runs), as a closed tab always did."""
        if not (tab.busy() or tab.session.transcript):
            return True
        answer = QMessageBox.question(
            self, heading,
            tr("Close {title}? Its conversation is deleted.").format(title=tab.session.title),
        )
        return answer == QMessageBox.StandardButton.Yes

    def close_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        if not isinstance(tab, AgentTab):
            return
        if not self._may_close(tab, tr("Close tab")):
            return
        tab.shutdown()
        self.tabs.removeTab(index)
        self.store.delete(tab.session.id)
        tab.deleteLater()
        if self.tabs.count() == 0:
            self._placeholder = self.new_tab()

    def start_tab(self, folder: str) -> AgentTab:
        """A tab working in *folder* (Start Agent, New Agent Tab Here): the
        dock's own first tab while nobody used it, else a new one."""
        tab, self._placeholder = self._placeholder, None
        untouched = (tab is not None and self.tabs.indexOf(tab) >= 0 and not tab.busy()
                     and not tab.session.transcript and not tab.input.toPlainText().strip())
        if not untouched:
            return self.new_tab(folder=folder)
        tab.set_folder(folder)
        self.tabs.setCurrentWidget(tab)
        self._save(tab)
        tab.input.setFocus()
        return tab

    def _save(self, tab: AgentTab) -> None:
        if not self.agent_settings.keep_sessions:
            return
        try:
            self.store.save(tab.session)
        except OSError as exc:
            log.warning("agent session could not be saved: %s", exc)

    # -- detached conversations (ui.agent_panels) ----------------------------------------------

    def panels(self) -> list[AgentPanel]:
        """The detached conversations' panels, in the order they were made."""
        self._panels = [p for p in self._panels if alive(p)]
        return list(self._panels)

    def panel_of(self, tab) -> AgentPanel | None:
        """The panel *tab* is detached into, or None (a tab of the dock)."""
        return next((p for p in self.panels() if p.tab is tab), None)

    def tab_menu(self, index: int) -> QMenu:
        """The right-click menu of the tab at *index* (a new one each time)."""
        menu = QMenu(self)
        tab = self.tabs.widget(index)
        if not isinstance(tab, AgentTab):
            return menu
        menu.addAction(tr("Detach as Panel")).triggered.connect(
            lambda _checked=False, t=tab: self.detach_tab(t))
        fill = getattr(self.panel_host, "fill_workspace_targets", None)
        if fill is not None:
            # Send to Workspace ▸: detached and laid out there in one step.
            send = menu.addMenu(tr("Send to Workspace"))
            fill(send, lambda ws, t=tab: self.send_tab_to_workspace(t, ws))
        menu.addAction(tr("Rename…")).triggered.connect(
            lambda _checked=False, t=tab: self.rename_tab(self.tabs.indexOf(t)))
        menu.addAction(tr("Apply Profile…")).triggered.connect(
            lambda _checked=False, t=tab: self.pick_profile(t))
        menu.addSeparator()
        menu.addAction(tr("Close")).triggered.connect(
            lambda _checked=False, t=tab: self.close_tab(self.tabs.indexOf(t)))
        return menu

    def _show_tab_menu(self, pos) -> None:
        bar = self.tabs.tabBar()
        index = bar.tabAt(pos)
        if index < 0:
            return
        menu = self.tab_menu(index)
        menu.exec(bar.mapToGlobal(pos))
        menu.deleteLater()

    def detach_tab(self, tab) -> AgentPanel | None:
        """Take the tab *tab* out of the dock into a panel of its own, on
        All Workspaces. The same tab moves - its session, a running task,
        an open question - nothing restarts. None for anything that is no
        tab of this dock."""
        if not isinstance(tab, AgentTab) or tab.dock is not self or self.tabs.indexOf(tab) < 0:
            return None
        panel = self._detach(tab)
        tab.session.detached = "all"
        self._save(tab)
        log.info("Agent conversation %s detached", tab.session.id)
        return panel

    def send_tab_to_workspace(self, tab, ws) -> AgentPanel | None:
        """Send to Workspace on a tab: detach *tab* into a panel and lay it
        out on workspace *ws* of the window - with *ws* None on a new
        workspace of its own, where the conversation is the only pane. The
        panel, or None when the window has no workspaces, *ws* is not one
        of them, no workspace can be added, or *tab* is no tab of this
        dock: the tab then stays where it is."""
        host = self.panel_host
        if host is None or not hasattr(host, "move_extension_panel"):
            return None
        if not isinstance(tab, AgentTab) or tab.dock is not self or self.tabs.indexOf(tab) < 0:
            return None
        if ws is None and not host.can_add_workspace():
            return None
        if ws is not None and ws not in host.workspaces():
            return None
        panel = self.detach_tab(tab)
        if panel is None:
            return None
        if ws is None:
            moved = host.move_extension_panel_to_new_workspace(panel) is not None
        else:
            moved = host.move_extension_panel(panel, ws)
        if not moved:
            # Checked above, so not expected: the conversation goes back
            # rather than staying on All Workspaces unasked.
            log.warning("Agent conversation %s: no place on a workspace, back as a tab",
                        tab.session.id)
            self.attach_panel(panel)
            return None
        tab.input.setFocus()
        return panel

    def _detach(self, tab: AgentTab) -> AgentPanel:
        if self._placeholder is tab:
            self._placeholder = None
        self.tabs.removeTab(self.tabs.indexOf(tab))
        panel = self._make_panel(tab)
        if self.tabs.count() == 0:
            # Never an empty dock: a fresh tab, as after closing the last one.
            self._placeholder = self.new_tab(save=False)
        return panel

    def _make_panel(self, tab: AgentTab) -> AgentPanel:
        host = self.panel_host
        panel = AgentPanel(tab, host if host is not None else self)
        self._panels.append(panel)
        panel.close_requested.connect(weak_call(self, "_on_panel_close"))
        panel.place_changed.connect(weak_call(self, "_on_panel_place"))
        panel.park_requested.connect(
            lambda p, attach=weak_call(self, "attach_panel"): attach(p, show=False))
        panel.titleBarWidget().attach_requested.connect(
            lambda p=panel, check=weak_call(self, "attach_panel"): check(p))
        check = weak_call(self, "check_link")
        panel.lamp.clicked.connect(lambda _checked=False, t=tab: check(t, when="always"))
        panel.visibilityChanged.connect(
            lambda shown, t=tab: shown and check(t, when="stale"))
        if host is not None:
            host.add_agent_panel(panel)
        else:
            panel.setFloating(True)
            panel.show()
        self.show_link()
        return panel

    def new_window(self, folder: str | None = None) -> AgentPanel:
        """New Agent Window: a new conversation directly in a panel of its
        own (for *folder*, else the active pane's folder)."""
        tab = self._make_tab(self._new_session(folder))
        tab.session.detached = "all"
        panel = self._make_panel(tab)
        self._save(tab)
        tab.input.setFocus()
        return panel

    def attach_panel(self, panel, *, show: bool = True) -> AgentTab | None:
        """Put a detached conversation back as a tab of the dock (the dock
        comes to the front when *show*); its panel goes. The untouched tab
        the dock opened by itself goes as well. None for anything that is
        no panel of this dock."""
        if not isinstance(panel, AgentPanel) or panel not in self.panels():
            return None
        tab = panel.tab
        self._panels.remove(panel)
        index = self.tabs.addTab(tab, tab.session.title)
        self.tabs.setTabToolTip(index, tab.session.title)
        self.tabs.setCurrentIndex(index)
        tab.show()
        tab.session.detached = ""
        self._save(tab)
        self._remove_panel(panel)
        placeholder, self._placeholder = self._placeholder, None
        if placeholder is not None and placeholder is not tab and self._untouched(placeholder):
            placeholder.shutdown()
            self.tabs.removeTab(self.tabs.indexOf(placeholder))
            self.store.delete(placeholder.session.id)
            placeholder.deleteLater()
        if show:
            self.show()
            self.raise_()
            tab.input.setFocus()
        self.show_link()
        log.info("Agent conversation %s attached", tab.session.id)
        return tab

    def _untouched(self, tab: AgentTab) -> bool:
        return (alive(tab) and self.tabs.indexOf(tab) >= 0 and not tab.busy()
                and not tab.session.transcript and not tab.input.toPlainText().strip())

    def _remove_panel(self, panel: AgentPanel) -> None:
        panel.closing = True
        host = self.panel_host
        if host is not None:
            host.remove_agent_panel(panel)
        panel.hide()
        panel.deleteLater()

    def _on_panel_close(self, panel) -> None:
        """[x] on a detached conversation: closed as its tab would be -
        asked first when there is a conversation, then it is deleted."""
        if panel not in self.panels():
            return
        tab = panel.tab
        if not self._may_close(tab, tr("Close conversation")):
            return
        self._panels.remove(panel)
        tab.shutdown()
        self.store.delete(tab.session.id)
        # Out of the window once its close event is over.
        QTimer.singleShot(0, lambda p=panel: alive(p) and self._remove_panel(p))
        self.show_link()

    def _on_panel_place(self, panel) -> None:
        """A panel moved: its session keeps whether it is on a workspace."""
        if self._settling or self._closing or panel not in self.panels():
            return
        place = "workspace" if panel.in_layout() else "all"
        if panel.tab.session.detached != place:
            panel.tab.session.detached = place
            self._save(panel.tab)

    def restore_detached(self) -> None:
        """At the start, once the window can hold panels: the kept
        conversations that were detached become panels again (on All
        Workspaces; the layout restore puts the others on their
        workspace, settle_detached the rest back into tabs)."""
        self._settling = True
        for tab in self.docked_tabs():
            if tab.session.detached in DETACHED_PLACES:
                self._detach(tab)

    def settle_detached(self) -> None:
        """After the layout restore (or none): a conversation that was on a
        workspace the restored layout does not hold comes back as a tab.
        Once; later moves write their places again."""
        if not self._settling:
            return
        self._settling = False
        for panel in self.panels():
            if panel.tab.session.detached == "workspace" and not panel.in_layout():
                log.info("Agent conversation %s: its workspace is gone, back as a tab",
                         panel.tab.session.id)
                self.attach_panel(panel, show=False)
            else:
                self._on_panel_place(panel)

    def _on_focus_changed(self, _old, new) -> None:
        """The keyboard focus moved: into a conversation of this dock (a tab
        or a detached panel), the voice follows it. Within one window only:
        a dialog over the dock (a confirmation) is no conversation."""
        widget = new
        while alive(widget):
            if isinstance(widget, AgentTab):
                if widget.dock is self:
                    self.focus_tab = widget
                return
            if widget is self:
                self.focus_tab = self.current_tab()  # the tab bar, the corner buttons
                return
            if widget.isWindow():
                return
            widget = widget.parentWidget()

    def _follow_current(self) -> None:
        """Another tab came to the front: the voice follows it, unless the
        focus is in a detached conversation."""
        focus = self.focus_tab
        if not alive(focus) or self.tabs.indexOf(focus) >= 0 or self.panel_of(focus) is None:
            self.focus_tab = self.current_tab()

    # -- voice ---------------------------------------------------------------------------------

    def _voice_target(self) -> AgentTab | None:
        """The tab the voice listens for, else the conversation the focus
        was in last (a tab or a detached panel), else the current tab."""
        tabs = self.all_tabs()
        for tab in (self.voice_tab, self.focus_tab):
            if tab is not None and any(t is tab for t in tabs):
                return tab
        return self.current_tab()

    def voice_profile(self) -> tuple:
        """(LLM profile, API key) of the tab the voice works for: its
        speech recognition settings."""
        tab = self._voice_target()
        profile = tab.profile() if tab is not None else None
        if profile is None:
            return None, ""
        try:
            key = self.key_lookup(profile.name) or ""
        except Exception:  # noqa: BLE001 - no keyring: recognition without a key
            log.exception("API key lookup failed for %s", profile.name)
            key = ""
        return profile, key

    def update_voice_look(self) -> None:
        for tab in self.all_tabs():
            tab.update_voice_look()

    def reload_voice(self) -> None:
        """The Voice settings were saved: speak and listen as they say now."""
        self.voice.reload()
        self.update_voice_look()

    def _on_voice_text(self, text: str) -> None:
        tab = self._voice_target()
        if tab is not None:
            tab.on_voice_text(text)

    def _on_voice_notice(self, text: str) -> None:
        tab = self._voice_target()
        if tab is not None:
            tab._show(tr("axross:"), text, muted=True)

    def _on_speaking_finished(self) -> None:
        tab = self._voice_target()
        self.update_voice_look()
        if tab is not None:
            tab.on_speaking_finished()

    def _on_voice_level(self, value: float) -> None:
        tab = self._voice_target()
        if tab is not None and not tab.lens.isHidden():
            tab.lens.set_level(value)

    def _on_line_started(self) -> None:
        tab = self._voice_target()
        if tab is not None:
            tab.lens.start(self.voice.line_text())

    def _on_line_finished(self) -> None:
        for tab in self.all_tabs():
            tab.lens.finish()

    def reload_settings(self) -> None:
        """Agent Settings were saved: every tab offers what they say now."""
        self.agent_settings = self._load_agent_settings()
        self.voice.reload()
        self.update_voice_look()
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
        from core.agent_topics import BUILTIN_TOPICS, load_user_topics

        host = self._extensions()
        return [*BUILTIN_TOPICS, *(host.agent_topics() if host is not None else []),
                *load_user_topics()]

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

    # -- MCP servers found on this machine ------------------------------------------------------

    def _detect_once(self) -> None:
        if not self._detect_started:
            self.detect_servers()

    def detect_servers(self) -> None:
        """Look for MCP servers on this machine in the background
        (core.mcp_detect: other clients' files, the tabs' folders, podman
        images axross installed); the tabs' Tools lists follow."""
        self._detect_started = True
        detector = self._mcp_detector
        if detector is None:
            from ui.agent_settings_dialog import default_detector as detector
        configured = list(self.agent_settings.mcp_servers)
        folders = [t.root_edit.text().strip() for t in self.all_tabs()
                   if t.root_edit.text().strip()]
        bridge = self._link_bridge

        def work() -> None:
            try:
                result = detector(configured=configured,
                                  folders=[os.path.expanduser(f) for f in folders])
            except Exception:  # noqa: BLE001 - a scan must end, whatever it meets
                log.exception("detecting MCP servers failed")
                return
            try:
                bridge.detected.emit(result)
            except RuntimeError:
                pass  # the dock is gone

        threading.Thread(target=work, name="axross-mcp-detect", daemon=True).start()

    def _on_detected(self, result) -> None:
        self._detected = list(result.servers)
        for tab in self.all_tabs():
            tab.refresh_choices()

    def detected_servers(self) -> list:
        """The usable servers found on this machine that the settings do not
        have yet."""
        from core.mcp_detect import configured_as

        return [d for d in self._detected
                if d.usable and configured_as(d, self.agent_settings.mcp_servers) is None]

    def add_detected(self, key: str, *, sandbox: str = "", parent=None, on_done=None) -> bool:
        """Add the detected server *key* to the settings, switched on, and save
        them (its secret values to the keyring, after asking): a program runs
        in *sandbox*; one that downloads code is installed into a container
        first, in the background. *on_done* hears the new config (None: not
        added). False when nothing was started."""
        from ui.agent_settings_dialog import (
            confirm_detected_install,
            confirm_detected_secrets,
            free_name,
        )

        detected = next((d for d in self.detected_servers() if d.key == key), None)
        if detected is None:
            return False
        parent = parent or self
        on_done = on_done or (lambda _config: None)
        name = free_name(detected.name, {s.name for s in self.agent_settings.mcp_servers})
        if detected.needs_install:
            if not confirm_detected_install(parent, detected):
                return False
            self._install_detected(detected, name, on_done)
            return True
        if not confirm_detected_secrets(parent, detected):
            return False
        config = self._store_detected(detected, detected.config(name=name, sandbox=sandbox),
                                      parent)
        on_done(config)
        return config is not None

    def _install_detected(self, detected, name: str, on_done) -> None:
        taken = {s.name for s in self.agent_settings.mcp_servers}
        opener, bridge = self._mcp_opener, self._link_bridge
        tab = self.current_tab()
        if tab is not None:
            tab._show(tr("axross:"), tr("Installing {name} in a container ({spec})…").format(
                name=name, spec=detected.plan.spec), muted=True)

        def work() -> None:
            from core import mcp_install as I

            try:
                config, error = detected.install(name=name, podman=I.Podman(), opener=opener,
                                                 taken=taken), ""
            except I.InstallError as exc:
                config, error = None, str(exc)
            except Exception as exc:  # noqa: BLE001 - reported, never a crash
                log.exception("installing the detected %s failed", name)
                config, error = None, type(exc).__name__
            try:
                bridge.installed.emit(on_done, detected, config, error)
            except RuntimeError:
                pass  # the dock is gone

        threading.Thread(target=work, name="axross-mcp-contain", daemon=True).start()

    def _on_installed(self, on_done, detected, config, error: str) -> None:
        if config is not None:
            config = self._store_detected(detected, config, self)
        else:
            QMessageBox.warning(self, tr("Detected MCP server"),
                                tr("It was not installed: {why}").format(why=error))
        on_done(config)

    def _store_detected(self, detected, config, parent):
        """Keep *config* (and *detected*'s secrets in the keyring); the
        config, or None when that failed."""
        return self.store_server(config, detected.secrets, detected.token, parent=parent,
                                 heading=tr("Detected MCP server"))

    def store_server(self, config, secrets: dict, token: str, *, parent=None,
                     heading: str | None = None):
        """Add *config* to Agent Settings and save them, its *secrets* and
        *token* to the keyring first; the config, or None when a server of
        that name exists or storing failed (said in a message)."""
        from core import mcp_client as MC

        heading = heading or tr("MCP server")
        parent = parent or self
        settings = self.agent_settings
        if config.name in {s.name for s in settings.mcp_servers}:
            return None
        try:
            for var, value in secrets.items():
                if var in config.secret_env:
                    MC.set_secret(config.name, var, value)
            if token:
                MC.set_token(config.name, token)
        except Exception as exc:  # noqa: BLE001 - no keyring: say so, add nothing
            QMessageBox.warning(parent, heading, tr(
                "The secrets of {name} could not be stored in the keyring - it is not "
                "added:").format(name=config.name) + f"\n{type(exc).__name__}")
            return None
        settings.mcp_servers.append(config)
        try:
            self._save_agent_settings(settings)
        except OSError as exc:
            settings.mcp_servers.remove(config)
            QMessageBox.warning(parent, heading,
                                tr("The settings could not be saved:") + f"\n{exc}")
            return None
        return config

    def emit_event(self, tab: AgentTab, event: dict) -> None:
        self.agent_event.emit(tab.session.id, event)

    # -- the connection lamp ------------------------------------------------------------------

    def show_lamp_in(self, title_bar) -> None:
        """Put the lamp into *title_bar* (ui.dock_titlebar.DockTitleBar)."""
        title_bar.add_indicator(self.lamp)
        self.show_link()

    def check_link(self, tab: AgentTab | None = None, *, when: str = "stale") -> None:
        """Follow *tab*'s profile (default: the current tab) and check its
        endpoint off the GUI thread - *when* "changed": only for another
        profile than before, "stale": also when it is not known to be
        reachable, "always": in any case (a click on the lamp). Nothing is
        asked while the dock is hidden or a request is on its way."""
        tab = tab or self.current_tab()
        if tab is None:
            return
        panel = self.panel_of(tab)
        shown = panel.isVisible() if panel is not None else self.isVisible()
        profile = tab.profile()
        if profile is None:
            tab.link.no_profile()
            self.show_link()
            return
        changed = tab.link.reset(profile)
        wanted = {"changed": changed, "stale": changed or tab.link.needs_check(),
                  "always": True}.get(when, False)
        if wanted and shown and tab.link.state != AL.TRYING:
            self._start_check(tab, profile)
        self.show_link()

    def _start_check(self, tab: AgentTab, profile: LP.LLMProfile) -> None:
        token = tab.link.begin_check()
        profile = dataclasses.replace(profile)  # the thread's own copy
        lookup, bridge = self.key_lookup, self._link_bridge

        def work() -> None:
            try:
                key = lookup(profile.name) or ""
            except Exception:  # noqa: BLE001 - no keyring: ask without a key
                key = ""
            try:
                ok, detail = AL.probe(profile, key)
            except Exception as exc:  # noqa: BLE001 - a check must end, whatever happens
                log.exception("the LLM connection check failed")
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            try:
                bridge.checked.emit(tab, token, ok, detail)
            except RuntimeError:
                pass  # the dock is gone

        threading.Thread(target=work, name="axross-llm-check", daemon=True).start()

    def _on_link_checked(self, tab, token: int, ok: bool, detail: str) -> None:
        if tab in self.all_tabs() and tab.link.end_check(token, ok, detail):
            self.show_link()

    def show_link(self) -> None:
        """The lamp shows the current tab's state, each detached panel's
        lamp its own conversation's."""
        tab = self.current_tab()
        if tab is not None:
            self.lamp.set_state(tab.link.state, tab.link.tooltip())
        for panel in self.panels():
            panel.lamp.set_state(panel.tab.link.state, panel.tab.link.tooltip())

    # -- the current tab (the main window and older callers) ------------------------------------

    def refresh_profiles(self) -> None:
        for tab in self.all_tabs():
            tab.refresh_choices()
        # The profiles may name another endpoint now, or a server came up.
        self.check_link(when="stale")

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
        self._closing = True  # the window goes: no panel place is written now
        for tab in self.all_tabs():
            tab.shutdown()
        self.voice.shutdown()
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
