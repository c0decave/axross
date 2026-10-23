"""The agent's settings: how the agent works, what it may reach, and the
sandboxes it runs in (core.agent_settings). :class:`AgentSettingsPage` is
the Agent page of Edit > Settings… (Tools > Agent Settings… opens it);
:class:`AgentSettingsDialog` is the same form as a dialog of its own.

Six pages:

* **General** - the LLM profile and protection mode of new tabs, whether
  bypass may be chosen at all, step and output limits, whether tabs are
  kept, the tool groups new tabs offer.
* **Prompts** - the prompt profiles (core.agent_prompts): a system prompt
  and a user prompt (a template for the typed task) each, the built-in
  Default read-only, and the profile new requests use.
* **Access** - the ceiling of every tab (core.agent_access): the master
  switch for axross functions (tools axross runs outside the agent's
  sandbox) and each function - remote files, saved connections, remote
  commands, MCP servers, extensions.
* **Sandboxes** - the sandbox profiles (engine, level, allowed hosts,
  extra folders, image) and the one new tabs use.
* **MCP Servers** - further MCP servers whose tools a tab may offer
  (core.mcp_client): a program (stdio) or an http endpoint, when a call
  asks, a timeout, and for a program the sandbox profile it runs in. An
  http server's token goes to the keyring.
* **Sessions** - every tab's own access: its axross functions, network
  and folders, within the ceiling.

Save writes the file; the open Agent tabs read it before their next task.
"""

from __future__ import annotations

import shlex
import threading

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
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
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import agent_prompts as AP
from core import agent_settings as S
from core import llm_profiles as LP
from core import mcp_client as MC
from core.agent_net import parse_host
from core.agent_sandbox import ENGINES, LEVELS, RULES, SandboxProfile, available
from core.i18n import tr
from ui.close_corner import add_close_corner

MODE_LABELS = {
    "ask": "Ask - every change asks first",
    "plan": "Plan - read and plan only, run the plan after your OK",
    "auto": "Auto - changes in the folder run, remote commands ask",
    "bypass": "Bypass - nothing asks (dangerous)",
}
LEVEL_LABELS = {
    "lax": "Lax - the host's network, folders as configured",
    "normal": "Normal - allowed hosts only, folders as configured",
    "high": "High - allowed hosts only, extra folders read-only, tighter limits",
    "paranoid": "Paranoid - only the LLM, nothing writable, tightest limits",
}
ENGINE_LABELS = {
    "auto": "Automatic",
    "bubblewrap": "bubblewrap",
    "podman": "podman",
    "docker": "docker",
}
CONFIRM_LABELS = {
    "always": "Every call asks (also in Auto)",
    "writes": "Tools the server marks read-only run without asking",
}


#: The tabs of the agent's settings, in order: (id, title).
AGENT_TABS: tuple[tuple[str, str], ...] = (
    ("general", "General"),
    ("prompts", "Prompts"),
    ("access", "Access"),
    ("sandboxes", "Sandboxes"),
    ("mcp", "MCP Servers"),
    ("sessions", "Sessions"),
)


class _AgentSettingsForm:
    """The tabs of the agent's settings (AGENT_TABS); :class:`AgentSettingsPage`
    (Edit > Settings… > Agent) and :class:`AgentSettingsDialog` share it.
    The class it is mixed into is the widget and has the signals ``saved``
    and ``_tested``."""

    def _build_form(
        self,
        settings_path=None,
        llm_settings: LP.LLMSettings | None = None,
        sessions=None,
        store_session=None,
    ) -> QTabWidget:
        """Build the tabs; returns the tab widget for the widget to place."""
        self._path = settings_path
        self.settings = S.AgentSettings.load(settings_path)
        self._llm = llm_settings if llm_settings is not None else LP.LLMSettings.load()
        self._current: SandboxProfile | None = None
        self._loading = False
        self._server: MC.McpServerConfig | None = None
        #: Tokens typed here, per server name: written to the keyring on save
        #: ("" deletes).
        self._tokens: dict[str, str] = {}
        self._tested.connect(self._show_test)
        #: The tabs' sessions: the open tabs' (the dock's) or the saved ones.
        self._sessions_source = sessions
        self._store_session = store_session
        #: Edits on the Sessions page, per session id: (access, folders),
        #: applied on Save.
        self._session_edits: dict[str, tuple] = {}
        self._session_row = -1
        #: The built-in prompt profile (row 0 of the Prompts list) and the
        #: user's profile shown in the form (None: the built-in one).
        self._prompt_default = AP.default_profile()
        self._prompt_current: AP.PromptProfile | None = None

        self.tabs = QTabWidget()
        builders = {
            "general": self._general_page,
            "prompts": self._prompts_page,
            "access": self._access_page,
            "sandboxes": self._sandbox_page,
            "mcp": self._mcp_page,
            "sessions": self._sessions_page,
        }
        for tab_id, title in AGENT_TABS:
            self.tabs.addTab(builders[tab_id](), tr(title))
        self._load_general()
        return self.tabs

    def show_tab(self, tab_id: str) -> None:
        """Bring the tab *tab_id* (an id of AGENT_TABS) to the front."""
        ids = [t for t, _title in AGENT_TABS]
        if tab_id in ids:
            self.tabs.setCurrentIndex(ids.index(tab_id))

    def refresh_llm_choices(self, names) -> None:
        """Offer the LLM profiles *names* as the profile of new tabs - the
        LLM Profiles page may have added or renamed some before they were
        saved. The choice made stays when its profile is still there."""
        chosen = self.profile_combo.currentData()
        self.profile_combo.blockSignals(True)
        try:
            self.profile_combo.clear()
            self.profile_combo.addItem(tr("The active LLM profile"), "")
            for name in names:
                self.profile_combo.addItem(name, name)
            self.profile_combo.setCurrentIndex(max(0, self.profile_combo.findData(chosen)))
        finally:
            self.profile_combo.blockSignals(False)

    # -- General ---------------------------------------------------------------------

    def _general_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        self.profile_combo = QComboBox()
        self.profile_combo.addItem(tr("The active LLM profile"), "")
        for p in self._llm.profiles:
            self.profile_combo.addItem(p.name, p.name)
        form.addRow(tr("LLM profile of new tabs"), self.profile_combo)
        self.mode_combo = QComboBox()
        form.addRow(tr("Protection mode of new tabs"), self.mode_combo)
        self.bypass_check = QCheckBox(
            tr("Bypass may be chosen (the agent changes and runs commands without asking)")
        )
        self.bypass_check.toggled.connect(self._fill_modes)
        form.addRow("", self.bypass_check)
        self.steps_spin = QSpinBox()
        self.steps_spin.setRange(1, S.MAX_STEPS_LIMIT)
        form.addRow(tr("Model requests per task"), self.steps_spin)
        self.chars_spin = QSpinBox()
        self.chars_spin.setRange(200, S.MAX_TOOL_CHARS_LIMIT)
        self.chars_spin.setSingleStep(1000)
        self.chars_spin.setSuffix(tr(" characters"))
        form.addRow(tr("Tool result kept for the model"), self.chars_spin)
        self.keep_check = QCheckBox(tr("Keep tabs and their conversations (one JSON file per tab)"))
        form.addRow("", self.keep_check)
        self.groups_list = QListWidget()
        self.groups_list.setMaximumHeight(140)
        for group in S.OFFERED_GROUPS:
            item = QListWidgetItem(group)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            self.groups_list.addItem(item)
        form.addRow(tr("Tool groups of new tabs"), self.groups_list)
        return page

    def _fill_modes(self, *_args) -> None:
        current = self.mode_combo.currentData() or self.settings.mode
        self.mode_combo.clear()
        for mode in S.MODES:
            if mode == "bypass" and not self.bypass_check.isChecked():
                continue
            self.mode_combo.addItem(tr(MODE_LABELS[mode]), mode)
        index = self.mode_combo.findData(current)
        self.mode_combo.setCurrentIndex(max(0, index))

    def _load_general(self) -> None:
        s = self.settings
        self.profile_combo.setCurrentIndex(max(0, self.profile_combo.findData(s.profile)))
        self.bypass_check.setChecked(s.allow_bypass)
        self._fill_modes()
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(s.mode)))
        self.steps_spin.setValue(s.max_steps)
        self.chars_spin.setValue(s.max_tool_chars)
        self.keep_check.setChecked(s.keep_sessions)
        for i in range(self.groups_list.count()):
            item = self.groups_list.item(i)
            item.setCheckState(
                Qt.CheckState.Checked if item.text() in s.groups else Qt.CheckState.Unchecked
            )
        self.axross_check.setChecked(s.access.axross_functions)
        self.files_read_only_check.setChecked(s.access.files_read_only)
        for name, box in self._function_checks().items():
            box.setChecked(getattr(s.access, name))
        self._update_access_page()

    # -- Prompts ---------------------------------------------------------------------

    def _prompts_page(self) -> QWidget:
        page = QWidget()
        top = QHBoxLayout(page)
        left = QVBoxLayout()
        self.prompt_list = QListWidget()
        self.prompt_list.currentRowChanged.connect(self._show_prompt_profile)
        left.addWidget(self.prompt_list, 1)
        row = QHBoxLayout()
        self.prompt_new_button = QPushButton(tr("New"))
        self.prompt_new_button.clicked.connect(self.add_prompt_profile)
        self.prompt_duplicate_button = QPushButton(tr("Duplicate"))
        self.prompt_duplicate_button.clicked.connect(self.duplicate_prompt_profile)
        self.prompt_delete_button = QPushButton(tr("Delete"))
        self.prompt_delete_button.clicked.connect(self.delete_prompt_profile)
        for button in (self.prompt_new_button, self.prompt_duplicate_button,
                       self.prompt_delete_button):
            row.addWidget(button)
        left.addLayout(row)
        left.addWidget(QLabel(tr("Prompt profile of new requests")))
        self.prompt_active_combo = QComboBox()
        self.prompt_active_combo.currentIndexChanged.connect(self._mark_active_prompt)
        left.addWidget(self.prompt_active_combo)
        top.addLayout(left, 1)

        form_widget = QWidget()
        form = QFormLayout(form_widget)
        self.prompt_name_edit = QLineEdit()
        self.prompt_name_edit.setMaxLength(AP.MAX_NAME)
        form.addRow(tr("Name"), self.prompt_name_edit)
        self.prompt_system_edit = QPlainTextEdit()
        self.prompt_system_edit.setPlaceholderText(tr("The rules the model gets before the task"))
        form.addRow(tr("System prompt"), self.prompt_system_edit)
        self.prompt_user_edit = QPlainTextEdit()
        self.prompt_user_edit.setMaximumHeight(110)
        self.prompt_user_edit.setPlaceholderText(
            tr("Empty: the task is sent as typed. {task} becomes the typed task, e.g. "
               "\"Answer in German: {task}\"; text without {task} goes in front of the task."))
        form.addRow(tr("User prompt"), self.prompt_user_edit)
        note = QLabel(tr(
            "Each tab adds the folder it works in, the Plan mode and the read-aloud rules to the "
            "system prompt. Default is axross's own prompt and cannot be changed: Duplicate it "
            "to change a copy. A change applies to the next request."))
        note.setWordWrap(True)
        form.addRow("", note)
        top.addWidget(form_widget, 2)

        self.prompt_name_edit.textChanged.connect(self._store_prompt_profile)
        self.prompt_system_edit.textChanged.connect(self._store_prompt_profile)
        self.prompt_user_edit.textChanged.connect(self._store_prompt_profile)
        self._rebuild_prompt_list(active=self.settings.prompt_profile)
        self.prompt_list.setCurrentRow(0)
        return page

    def _prompt_rows(self) -> list[AP.PromptProfile]:
        """The Prompts list in order: the built-in Default, then the user's."""
        return [self._prompt_default, *self.settings.prompt_profiles]

    def _prompt_label(self, profile: AP.PromptProfile) -> str:
        name = (tr("{name} (built-in)").format(name=profile.name) if profile.builtin
                else profile.name or tr("(unnamed)"))
        rows = self._prompt_rows()
        index = next((i for i, p in enumerate(rows) if p is profile), -1)
        return name + ("  ✓" if index == self.prompt_active_combo.currentIndex() else "")

    def _rebuild_prompt_list(self, *, active: str | None = None,
                             active_index: int | None = None) -> None:
        """Fill the list and the "new requests" combo (one entry per list
        row, in the same order). The combo keeps *active_index*, else the
        profile named *active*, else its current row."""
        rows = self._prompt_rows()
        if active_index is None:
            if active is not None:
                active_index = next((i for i, p in enumerate(rows)
                                     if not p.builtin and p.name == active), 0)
            else:
                active_index = self.prompt_active_combo.currentIndex()
        self.prompt_active_combo.blockSignals(True)
        try:
            self.prompt_active_combo.clear()
            for profile in rows:
                self.prompt_active_combo.addItem(
                    profile.name if not profile.builtin
                    else tr("{name} (built-in)").format(name=profile.name),
                    "" if profile.builtin else profile.name)
            self.prompt_active_combo.setCurrentIndex(
                active_index if 0 <= active_index < len(rows) else 0)
        finally:
            self.prompt_active_combo.blockSignals(False)
        row = self.prompt_list.currentRow()
        self.prompt_list.blockSignals(True)
        try:
            self.prompt_list.clear()
            for profile in rows:
                self.prompt_list.addItem(self._prompt_label(profile))
            if 0 <= row < len(rows):
                self.prompt_list.setCurrentRow(row)
        finally:
            self.prompt_list.blockSignals(False)

    def _mark_active_prompt(self, *_args) -> None:
        for i, profile in enumerate(self._prompt_rows()):
            item = self.prompt_list.item(i)
            if item is not None:
                item.setText(self._prompt_label(profile))

    def _show_prompt_profile(self, row: int) -> None:
        rows = self._prompt_rows()
        if not 0 <= row < len(rows):
            return
        profile = rows[row]
        self._loading = True
        try:
            self._prompt_current = None if profile.builtin else profile
            self.prompt_name_edit.setText(profile.name)
            self.prompt_system_edit.setPlainText(profile.system_prompt)
            self.prompt_user_edit.setPlainText(profile.user_prompt)
            for edit in (self.prompt_name_edit, self.prompt_system_edit, self.prompt_user_edit):
                edit.setReadOnly(profile.builtin)
            self.prompt_delete_button.setEnabled(not profile.builtin)
        finally:
            self._loading = False

    def _store_prompt_profile(self, *_args) -> None:
        if self._loading or self._prompt_current is None:
            return
        p = self._prompt_current
        p.name = self.prompt_name_edit.text().strip()
        p.system_prompt = self.prompt_system_edit.toPlainText()
        p.user_prompt = self.prompt_user_edit.toPlainText()
        index = 1 + next(i for i, q in enumerate(self.settings.prompt_profiles) if q is p)
        item = self.prompt_list.item(index)
        if item is not None:
            item.setText(self._prompt_label(p))
        # The combo follows a rename: its entry for this row gets the new name.
        self.prompt_active_combo.setItemText(index, p.name)
        self.prompt_active_combo.setItemData(index, p.name)

    def _unique_prompt_name(self, base: str) -> str:
        names = {p.name for p in self._prompt_rows()}
        name, n = base, 1
        while name in names:
            n += 1
            name = f"{base} {n}"
        return name

    def _append_prompt_profile(self, profile: AP.PromptProfile) -> None:
        self.settings.prompt_profiles.append(profile)
        self._rebuild_prompt_list()
        self.prompt_list.setCurrentRow(len(self.settings.prompt_profiles))
        self.prompt_name_edit.setFocus()

    def add_prompt_profile(self) -> None:
        """A new profile, starting from axross's own system prompt."""
        self._append_prompt_profile(AP.PromptProfile(
            self._unique_prompt_name(tr("Prompt profile")), self._prompt_default.system_prompt))

    def duplicate_prompt_profile(self) -> None:
        rows = self._prompt_rows()
        row = self.prompt_list.currentRow()
        if not 0 <= row < len(rows):
            return
        self._store_prompt_profile()
        source = rows[row]
        self._append_prompt_profile(AP.PromptProfile(
            self._unique_prompt_name(f"{source.name} {tr('copy')}"),
            source.system_prompt, source.user_prompt))

    def delete_prompt_profile(self) -> None:
        row = self.prompt_list.currentRow()
        if not 1 <= row <= len(self.settings.prompt_profiles):
            return  # the built-in Default stays
        active = self.prompt_active_combo.currentIndex()
        self.settings.prompt_profiles.pop(row - 1)
        self._prompt_current = None
        if active == row:
            active = 0
        elif active > row:
            active -= 1
        self._rebuild_prompt_list(active_index=active)
        self.prompt_list.setCurrentRow(min(row, len(self.settings.prompt_profiles)))
        self._show_prompt_profile(self.prompt_list.currentRow())

    # -- Access ----------------------------------------------------------------------

    def _access_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        # Independent of the master switch below: it limits every tab.
        self.files_read_only_check = QCheckBox(tr("Files read-only in every tab"))
        self.files_read_only_check.setToolTip(tr(
            "Agents read files but change none: no writing, deleting or moving, no remote "
            "commands, no writing tools of MCP servers or extensions. Enforced whatever a tab "
            "chooses."))
        layout.addWidget(self.files_read_only_check)
        self.axross_check = QCheckBox(tr("Let agents use axross functions"))
        self.axross_check.setToolTip(tr(
            "Tools axross runs itself, outside the agent's sandbox and with axross's rights. "
            "Off: no tab reaches any of them, whatever it chose."))
        self.axross_check.toggled.connect(self._update_access_page)
        layout.addWidget(self.axross_check)
        self.remote_files_check = QCheckBox(tr("Files of the remote connections open in the panes"))
        self.saved_profiles_check = QCheckBox(tr("Saved connections the agent opens itself"))
        self.remote_commands_check = QCheckBox(tr("Commands on remote hosts (SSH, WinRM, ...)"))
        self.mcp_servers_check = QCheckBox(tr("Tools of further MCP servers"))
        self.extensions_check = QCheckBox(tr("Tools of axross extensions"))
        for box in self._function_checks().values():
            box.setContentsMargins(18, 0, 0, 0)
            box.toggled.connect(self._update_access_page)
            layout.addWidget(box)
        note = QLabel(
            tr(
                "This is the ceiling of every tab: a tab chooses within it (its Access… button, "
                "or the Sessions page), and a new tab starts with the master switch as set here. "
                "axross functions are a way out of a sandbox: remote work runs in axross, outside "
                "it, with the confirmations of the tab's protection mode. A tab's network "
                "(Access…) limits the connections too. Production connections refuse every change."
            )
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)
        return page

    def _function_checks(self) -> dict:
        return {
            "remote_files": self.remote_files_check,
            "saved_profiles": self.saved_profiles_check,
            "remote_commands": self.remote_commands_check,
            "mcp_servers": self.mcp_servers_check,
            "extensions": self.extensions_check,
        }

    def _update_access_page(self, *_args) -> None:
        for box in self._function_checks().values():
            box.setEnabled(self.axross_check.isChecked())
        if getattr(self, "session_editor", None) is not None and self._session_row >= 0:
            self._show_session(self._session_row)  # the new ceiling

    def _ceiling(self) -> S.Access:
        """Access as the page shows it now (the Sessions page's ceiling)."""
        access = S.Access(
            axross_functions=self.axross_check.isChecked(),
            files_read_only=self.files_read_only_check.isChecked(),
        )
        for name, box in self._function_checks().items():
            setattr(access, name, box.isChecked())
        return access

    # -- Sessions --------------------------------------------------------------------------

    def _sessions(self) -> list:
        if self._sessions_source is not None:
            return list(self._sessions_source())
        from core.agent_session import SessionStore

        return SessionStore().all()

    def _sessions_page(self) -> QWidget:
        from ui.agent_access_dialog import AccessEditor

        page = QWidget()
        top = QHBoxLayout(page)
        left = QVBoxLayout()
        self.session_list = QListWidget()
        left.addWidget(self.session_list, 1)
        note = QLabel(tr("Each tab's own access, within the ceiling of the Access page."))
        note.setWordWrap(True)
        left.addWidget(note)
        top.addLayout(left, 1)
        self.session_editor = AccessEditor()
        self.session_editor.setEnabled(False)
        self.session_editor.changed.connect(self._keep_session_edit)
        top.addWidget(self.session_editor, 2)
        self._session_objects = self._sessions()
        for session in self._session_objects:
            self.session_list.addItem(session.title)
        self.session_list.currentRowChanged.connect(self._show_session)
        return page

    def _show_session(self, row: int) -> None:
        from core import agent_access as X

        self._session_row = row
        if not 0 <= row < len(self._session_objects):
            self.session_editor.setEnabled(False)
            return
        session = self._session_objects[row]
        access, folders = self._session_edits.get(session.id) or (
            session.access or X.SessionAccess.from_settings(self.settings.access),
            list(session.extra_folders),
        )
        self.session_editor.setEnabled(True)
        sandbox = self.settings.sandbox_profile(session.sandbox) if session.sandbox else None
        self.session_editor.load(access, folders, ceiling=self._ceiling(), sandbox=sandbox)

    def _keep_session_edit(self) -> None:
        if 0 <= self._session_row < len(self._session_objects):
            session = self._session_objects[self._session_row]
            self._session_edits[session.id] = (
                self.session_editor.access(),
                self.session_editor.folders(),
            )

    def _save_sessions(self) -> None:
        from core.agent_session import SessionStore

        store = self._store_session or SessionStore().save
        for session in self._session_objects:
            edit = self._session_edits.pop(session.id, None)
            if edit is None:
                continue
            session.access, session.extra_folders = edit[0], list(edit[1])
            try:
                store(session)
            except OSError as exc:
                QMessageBox.warning(
                    self,
                    tr("Agent Settings"),
                    tr("The tab {title} could not be saved:").format(title=session.title)
                    + f"\n{exc}",
                )

    # -- Sandboxes ----------------------------------------------------------------------

    def _sandbox_page(self) -> QWidget:
        page = QWidget()
        top = QHBoxLayout(page)
        left = QVBoxLayout()
        self.sandbox_list = QListWidget()
        self.sandbox_list.currentRowChanged.connect(self._show_sandbox)
        left.addWidget(self.sandbox_list, 1)
        row = QHBoxLayout()
        for label, slot in (
            (tr("Add"), self.add_sandbox),
            (tr("Duplicate"), self.duplicate_sandbox),
            (tr("Delete"), self.delete_sandbox),
        ):
            button = QPushButton(label)
            button.clicked.connect(slot)
            row.addWidget(button)
        left.addLayout(row)
        self.default_sandbox_combo = QComboBox()
        left.addWidget(QLabel(tr("Sandbox of new tabs")))
        left.addWidget(self.default_sandbox_combo)
        top.addLayout(left, 1)

        self.sandbox_form = QWidget()
        form = QFormLayout(self.sandbox_form)
        self.name_edit = QLineEdit()
        form.addRow(tr("Name"), self.name_edit)
        self.engine_combo = QComboBox()
        for engine in ENGINES:
            ok = engine == "auto" or available(engine)
            self.engine_combo.addItem(
                ENGINE_LABELS[engine] + ("" if ok else tr(" (not installed)")), engine
            )
        form.addRow(tr("Engine"), self.engine_combo)
        self.level_combo = QComboBox()
        for level in LEVELS:
            self.level_combo.addItem(tr(LEVEL_LABELS[level]), level)
        form.addRow(tr("Level"), self.level_combo)
        self.hosts_list = QListWidget()
        self.hosts_list.setMaximumHeight(110)
        hosts_row = QHBoxLayout()
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("db.example:5432")
        self.host_add = QPushButton(tr("Add host"))
        self.host_add.clicked.connect(self.add_host)
        self.host_remove = QPushButton(tr("Remove"))
        self.host_remove.clicked.connect(self.remove_host)
        hosts_row.addWidget(self.host_edit, 1)
        hosts_row.addWidget(self.host_add)
        hosts_row.addWidget(self.host_remove)
        self.hosts_note = QLabel()
        self.hosts_note.setWordWrap(True)
        hosts_box = QVBoxLayout()
        hosts_box.addWidget(self.hosts_list)
        hosts_box.addLayout(hosts_row)
        hosts_box.addWidget(self.hosts_note)
        form.addRow(tr("Allowed hosts"), hosts_box)
        self.mounts_table = QTableWidget(0, 2)
        self.mounts_table.setHorizontalHeaderLabels([tr("Folder"), tr("Access")])
        self.mounts_table.horizontalHeader().setStretchLastSection(False)
        self.mounts_table.setColumnWidth(0, 330)
        self.mounts_table.setMaximumHeight(130)
        mounts_row = QHBoxLayout()
        mount_add = QPushButton(tr("Add folder…"))
        mount_add.clicked.connect(self.add_mount)
        mount_remove = QPushButton(tr("Remove"))
        mount_remove.clicked.connect(self.remove_mount)
        mounts_row.addWidget(mount_add)
        mounts_row.addWidget(mount_remove)
        mounts_row.addStretch(1)
        self.mounts_note = QLabel()
        self.mounts_note.setWordWrap(True)
        mounts_box = QVBoxLayout()
        mounts_box.addWidget(self.mounts_table)
        mounts_box.addLayout(mounts_row)
        mounts_box.addWidget(self.mounts_note)
        form.addRow(tr("Extra folders"), mounts_box)
        self.image_edit = QLineEdit()
        form.addRow(tr("Container image"), self.image_edit)
        image_note = QLabel(
            tr(
                "podman and docker need the image: scripts/axross-podman.sh agent-image "
                "(or build Dockerfile.agent with docker)."
            )
        )
        image_note.setWordWrap(True)
        form.addRow("", image_note)
        top.addWidget(self.sandbox_form, 2)

        self.name_edit.textChanged.connect(self._store_sandbox)
        self.engine_combo.currentIndexChanged.connect(self._store_sandbox)
        self.level_combo.currentIndexChanged.connect(self._store_sandbox)
        self.image_edit.textChanged.connect(self._store_sandbox)
        self._rebuild_sandbox_list()
        self.sandbox_list.setCurrentRow(0 if self.settings.sandboxes else -1)
        self._show_sandbox(self.sandbox_list.currentRow())
        return page

    def _rebuild_sandbox_list(self) -> None:
        row = self.sandbox_list.currentRow()
        self.sandbox_list.blockSignals(True)
        self.sandbox_list.clear()
        for profile in self.settings.sandboxes:
            self.sandbox_list.addItem(f"{profile.name}  ({profile.level})")
        self.sandbox_list.blockSignals(False)
        if 0 <= row < self.sandbox_list.count():
            self.sandbox_list.setCurrentRow(row)
        chosen = (
            self.default_sandbox_combo.currentData()
            if self.default_sandbox_combo.count()
            else self.settings.sandbox
        )
        self.default_sandbox_combo.clear()
        self.default_sandbox_combo.addItem(tr("No sandbox"), "")
        for profile in self.settings.sandboxes:
            self.default_sandbox_combo.addItem(profile.name, profile.name)
        self.default_sandbox_combo.setCurrentIndex(
            max(0, self.default_sandbox_combo.findData(chosen))
        )

    def _show_sandbox(self, row: int) -> None:
        self._loading = True
        try:
            if not 0 <= row < len(self.settings.sandboxes):
                self._current = None
                self.sandbox_form.setEnabled(False)
                return
            profile = self._current = self.settings.sandboxes[row]
            self.sandbox_form.setEnabled(True)
            self.name_edit.setText(profile.name)
            self.engine_combo.setCurrentIndex(max(0, self.engine_combo.findData(profile.engine)))
            self.level_combo.setCurrentIndex(max(0, self.level_combo.findData(profile.level)))
            self.image_edit.setText(profile.image)
            self.hosts_list.clear()
            self.hosts_list.addItems(list(profile.hosts))
            self.mounts_table.setRowCount(0)
            for path, writable in profile.mounts:
                self._add_mount_row(path, writable)
        finally:
            self._loading = False
        self._update_level_notes()

    def _add_mount_row(self, path: str, writable: bool) -> None:
        row = self.mounts_table.rowCount()
        self.mounts_table.insertRow(row)
        item = QTableWidgetItem(path)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.mounts_table.setItem(row, 0, item)
        mode = QComboBox()
        mode.addItem(tr("read-only"), False)
        mode.addItem(tr("read-write"), True)
        mode.setCurrentIndex(1 if writable else 0)
        mode.currentIndexChanged.connect(self._store_sandbox)
        self.mounts_table.setCellWidget(row, 1, mode)

    def _update_level_notes(self) -> None:
        level = self.level_combo.currentData() or "normal"
        rules = RULES[level]
        allowlist = rules.network == "allowlist"
        for widget in (self.hosts_list, self.host_edit, self.host_add, self.host_remove):
            widget.setEnabled(allowlist)
        self.hosts_note.setText(
            "" if allowlist else tr("Lax uses the host's network; paranoid reaches only the LLM. "
                                    "The list counts on normal and high.")
        )
        self.mounts_note.setText(
            "" if rules.extra_writable else tr("On this level every extra folder is read-only.")
        )

    def _store_sandbox(self, *_args) -> None:
        if self._loading or self._current is None:
            return
        p = self._current
        p.name = self.name_edit.text().strip()
        p.engine = self.engine_combo.currentData() or "auto"
        p.level = self.level_combo.currentData() or "normal"
        p.image = self.image_edit.text().strip()
        p.hosts = tuple(self.hosts_list.item(i).text() for i in range(self.hosts_list.count()))
        mounts = []
        for row in range(self.mounts_table.rowCount()):
            mode = self.mounts_table.cellWidget(row, 1)
            mounts.append((self.mounts_table.item(row, 0).text(), bool(mode.currentData())))
        p.mounts = tuple(mounts)
        item = self.sandbox_list.item(self.sandbox_list.currentRow())
        if item is not None:
            item.setText(f"{p.name or tr('(unnamed)')}  ({p.level})")
        self._update_level_notes()

    def add_sandbox(self) -> None:
        names = {p.name for p in self.settings.sandboxes}
        name, n = tr("Sandbox"), 1
        while name in names:
            n += 1
            name = f"{tr('Sandbox')} {n}"
        self.settings.sandboxes.append(SandboxProfile(name=name))
        self._rebuild_sandbox_list()
        self.sandbox_list.setCurrentRow(len(self.settings.sandboxes) - 1)

    def duplicate_sandbox(self) -> None:
        if self._current is None:
            return
        data = self._current.to_dict()
        data["name"] = f"{self._current.name} {tr('copy')}"
        copy = SandboxProfile.from_dict(data)
        if copy is not None:
            self.settings.sandboxes.append(copy)
            self._rebuild_sandbox_list()
            self.sandbox_list.setCurrentRow(len(self.settings.sandboxes) - 1)

    def delete_sandbox(self) -> None:
        row = self.sandbox_list.currentRow()
        if not 0 <= row < len(self.settings.sandboxes):
            return
        self.settings.sandboxes.pop(row)
        self._current = None
        self._rebuild_sandbox_list()
        self.sandbox_list.setCurrentRow(min(row, len(self.settings.sandboxes) - 1))
        self._show_sandbox(self.sandbox_list.currentRow())

    def add_host(self) -> None:
        text = self.host_edit.text().strip()
        try:
            host, port = parse_host(text)
        except ValueError as exc:
            QMessageBox.warning(self, tr("Allowed hosts"), str(exc))
            return
        entry = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        existing = {self.hosts_list.item(i).text() for i in range(self.hosts_list.count())}
        if entry not in existing:
            self.hosts_list.addItem(entry)
        self.host_edit.clear()
        self._store_sandbox()

    def remove_host(self) -> None:
        row = self.hosts_list.currentRow()
        if row >= 0:
            self.hosts_list.takeItem(row)
            self._store_sandbox()

    def add_mount(self, path: str | None = None) -> None:
        if not isinstance(path, str):
            path = QFileDialog.getExistingDirectory(self, tr("Extra folder for the sandbox"))
        if not path:
            return
        existing = {
            self.mounts_table.item(r, 0).text() for r in range(self.mounts_table.rowCount())
        }
        if path not in existing:
            self._add_mount_row(path, False)
            self._store_sandbox()

    def remove_mount(self) -> None:
        row = self.mounts_table.currentRow()
        if row >= 0:
            self.mounts_table.removeRow(row)
            self._store_sandbox()

    # -- MCP servers ------------------------------------------------------------------------

    def _mcp_page(self) -> QWidget:
        page = QWidget()
        top = QHBoxLayout(page)
        left = QVBoxLayout()
        self.server_list = QListWidget()
        self.server_list.currentRowChanged.connect(self._show_server)
        left.addWidget(self.server_list, 1)
        row = QHBoxLayout()
        for label, slot in ((tr("Add"), self.add_server), (tr("Delete"), self.delete_server),
                            (tr("Test"), self.test_server)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            row.addWidget(button)
        left.addLayout(row)
        top.addLayout(left, 1)

        self.server_form = QWidget()
        form = QFormLayout(self.server_form)
        self.server_name_edit = QLineEdit()
        form.addRow(tr("Name"), self.server_name_edit)
        self.server_enabled_check = QCheckBox(tr("Tabs may offer this server's tools"))
        form.addRow("", self.server_enabled_check)
        self.server_transport_combo = QComboBox()
        self.server_transport_combo.addItem(tr("Program (stdio)"), "stdio")
        self.server_transport_combo.addItem(tr("HTTP endpoint"), "http")
        form.addRow(tr("Connection"), self.server_transport_combo)
        self.server_command_edit = QLineEdit()
        self.server_command_edit.setPlaceholderText("uvx mcp-server-git --repository /srv/repo")
        form.addRow(tr("Program"), self.server_command_edit)
        self.server_env_edit = QLineEdit()
        self.server_env_edit.setPlaceholderText("LANG=C.UTF-8 LOG_LEVEL=warning")
        form.addRow(tr("Environment"), self.server_env_edit)
        self.server_sandbox_combo = QComboBox()
        form.addRow(tr("Runs in sandbox"), self.server_sandbox_combo)
        self.server_url_edit = QLineEdit()
        self.server_url_edit.setPlaceholderText("http://127.0.0.1:7331/messages")
        form.addRow(tr("URL"), self.server_url_edit)
        self.server_bearer_check = QCheckBox(tr("Send a token (Authorization: Bearer)"))
        form.addRow("", self.server_bearer_check)
        self.server_token_edit = QLineEdit()
        self.server_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.server_token_edit.setPlaceholderText(tr("unchanged - stored in the keyring"))
        form.addRow(tr("Token"), self.server_token_edit)
        self.server_confirm_combo = QComboBox()
        for key, label in CONFIRM_LABELS.items():
            self.server_confirm_combo.addItem(tr(label), key)
        form.addRow(tr("Asks"), self.server_confirm_combo)
        self.server_timeout_spin = QDoubleSpinBox()
        self.server_timeout_spin.setRange(1, 3600)
        self.server_timeout_spin.setSuffix(" s")
        form.addRow(tr("Timeout"), self.server_timeout_spin)
        self.server_test_label = QLabel()
        self.server_test_label.setWordWrap(True)
        form.addRow("", self.server_test_label)
        note = QLabel(
            tr(
                "A server runs with axross, never inside a tab's sandbox: a sandboxed tab reaches "
                "it through axross, paranoid not at all, and an http server only when its host is "
                "an allowed host of the tab's sandbox. A program runs with your rights unless it "
                "runs in a sandbox profile here."
            )
        )
        note.setWordWrap(True)
        form.addRow("", note)
        top.addWidget(self.server_form, 2)

        for edit in (self.server_name_edit, self.server_command_edit, self.server_env_edit,
                     self.server_url_edit):
            edit.textChanged.connect(self._store_server)
        for combo in (
            self.server_transport_combo,
            self.server_confirm_combo,
            self.server_sandbox_combo,
        ):
            combo.currentIndexChanged.connect(self._store_server)
        self.server_enabled_check.toggled.connect(self._store_server)
        self.server_bearer_check.toggled.connect(self._store_server)
        self.server_timeout_spin.valueChanged.connect(self._store_server)
        self.server_token_edit.textChanged.connect(self._store_token)
        self._rebuild_server_list()
        self.server_list.setCurrentRow(0 if self.settings.mcp_servers else -1)
        self._show_server(self.server_list.currentRow())
        return page

    def _rebuild_server_list(self) -> None:
        row = self.server_list.currentRow()
        self.server_list.blockSignals(True)
        self.server_list.clear()
        for server in self.settings.mcp_servers:
            self.server_list.addItem(self._server_label(server))
        self.server_list.blockSignals(False)
        if 0 <= row < self.server_list.count():
            self.server_list.setCurrentRow(row)

    @staticmethod
    def _server_label(server: MC.McpServerConfig) -> str:
        state = "" if server.enabled else ", off"
        return f"{server.name or tr('(unnamed)')}  ({server.transport}{state})"

    def _show_server(self, row: int) -> None:
        self._loading = True
        try:
            self.server_test_label.clear()
            self.server_test_label.setToolTip("")
            if not 0 <= row < len(self.settings.mcp_servers):
                self._server = None
                self.server_form.setEnabled(False)
                return
            server = self._server = self.settings.mcp_servers[row]
            self.server_form.setEnabled(True)
            self.server_name_edit.setText(server.name)
            self.server_enabled_check.setChecked(server.enabled)
            self.server_transport_combo.setCurrentIndex(
                max(0, self.server_transport_combo.findData(server.transport)))
            self.server_command_edit.setText(shlex.join(server.command))
            self.server_env_edit.setText(
                " ".join(shlex.quote(f"{k}={v}") for k, v in server.env.items())
            )
            self.server_sandbox_combo.clear()
            self.server_sandbox_combo.addItem(tr("No sandbox"), "")
            for profile in self.settings.sandboxes:
                self.server_sandbox_combo.addItem(profile.name, profile.name)
            if server.sandbox and self.server_sandbox_combo.findData(server.sandbox) < 0:
                # Kept, never quietly "no sandbox": Save refuses it until changed.
                self.server_sandbox_combo.addItem(
                    tr("{name} (missing)").format(name=server.sandbox), server.sandbox
                )
            self.server_sandbox_combo.setCurrentIndex(
                max(0, self.server_sandbox_combo.findData(server.sandbox))
            )
            self.server_url_edit.setText(server.url)
            self.server_bearer_check.setChecked(server.bearer)
            self.server_token_edit.setText(self._tokens.get(server.name, ""))
            self.server_confirm_combo.setCurrentIndex(
                max(0, self.server_confirm_combo.findData(server.confirm))
            )
            self.server_timeout_spin.setValue(server.timeout)
        finally:
            self._loading = False
        self._update_server_fields()

    def _update_server_fields(self) -> None:
        stdio = self.server_transport_combo.currentData() == "stdio"
        for widget in (self.server_command_edit, self.server_env_edit, self.server_sandbox_combo):
            widget.setEnabled(stdio)
        for widget in (self.server_url_edit, self.server_bearer_check):
            widget.setEnabled(not stdio)
        self.server_token_edit.setEnabled(not stdio and self.server_bearer_check.isChecked())

    @staticmethod
    def _split(text: str) -> list[str]:
        try:
            return shlex.split(text)
        except ValueError:  # an open quote while typing
            return text.split()

    def _store_server(self, *_args) -> None:
        if self._loading or self._server is None:
            return
        server = self._server
        old_name = server.name
        server.name = self.server_name_edit.text().strip()
        if old_name != server.name:
            # The token lives under the name: it moves along, nothing stays behind.
            token = self._tokens.pop(old_name, None)
            if token is None and server.bearer:
                token = MC.get_token(old_name)
            if token:
                self._tokens[server.name] = token
            held = any(
                other is not server and other.name == old_name
                for other in self.settings.mcp_servers
            )
            if (server.bearer or token) and not held:  # another server's name keeps its token
                self._tokens[old_name] = ""
        server.enabled = self.server_enabled_check.isChecked()
        server.transport = self.server_transport_combo.currentData() or "stdio"
        server.command = tuple(self._split(self.server_command_edit.text()))
        server.env = dict(
            e.split("=", 1) for e in self._split(self.server_env_edit.text()) if "=" in e
        )
        server.sandbox = self.server_sandbox_combo.currentData() or ""
        server.url = self.server_url_edit.text().strip()
        server.bearer = self.server_bearer_check.isChecked()
        server.confirm = self.server_confirm_combo.currentData() or "always"
        server.timeout = float(self.server_timeout_spin.value())
        item = self.server_list.item(self.server_list.currentRow())
        if item is not None:
            item.setText(self._server_label(server))
        self._update_server_fields()

    def _store_token(self, text: str) -> None:
        if not self._loading and self._server is not None:
            self._tokens[self._server.name] = text

    def add_server(self) -> None:
        names = {s.name for s in self.settings.mcp_servers}
        name, n = "server", 1
        while name in names:
            n += 1
            name = f"server{n}"
        self.settings.mcp_servers.append(MC.McpServerConfig(name=name))
        self._rebuild_server_list()
        self.server_list.setCurrentRow(len(self.settings.mcp_servers) - 1)

    def delete_server(self) -> None:
        row = self.server_list.currentRow()
        if not 0 <= row < len(self.settings.mcp_servers):
            return
        gone = self.settings.mcp_servers.pop(row)
        if gone.bearer or gone.name in self._tokens:
            self._tokens[gone.name] = ""  # the keyring entry goes too
        self._server = None
        self._rebuild_server_list()
        self.server_list.setCurrentRow(min(row, len(self.settings.mcp_servers) - 1))
        self._show_server(self.server_list.currentRow())

    def test_server(self) -> None:
        """Connect the shown server in the background and list its tools."""
        self._store_server()
        if self._server is None:
            return
        server = MC.McpServerConfig.from_dict(self._server.to_dict()) or self._server
        problems = server.problems()
        if problems:
            self.server_test_label.setText(
                tr("Test failed: needs {what}").format(what=", ".join(problems))
            )
            return
        token = self._tokens.get(server.name) or (
            MC.get_token(server.name) if server.bearer else ""
        )
        self.server_test_label.setText(tr("Connecting…"))

        settings = self.settings

        def run() -> None:
            try:
                # The same sandbox the tabs start it in - a test is a real start.
                client = MC.McpClient(server, token=token, wrap=settings.mcp_wrap(server))
                try:
                    names = [t.remote_name for t in client.tools()]
                finally:
                    client.close()
                self._tested.emit(
                    server.name, tr("{n} tools").format(n=len(names)), ", ".join(names)
                )
            except MC.McpClientError as exc:
                self._tested.emit(server.name, tr("Test failed: {why}").format(why=exc), "")

        threading.Thread(target=run, name="mcp-server-test", daemon=True).start()

    def _show_test(self, name: str, text: str, tools: str) -> None:
        if self._server is not None and self._server.name == name:
            self.server_test_label.setText(text)
            self.server_test_label.setToolTip(tools)

    # -- save ----------------------------------------------------------------------------

    def problems(self) -> list[str]:
        out = []
        self._store_prompt_profile()
        prompt_names = [p.name for p in self.settings.prompt_profiles]
        for p in self.settings.prompt_profiles:
            out.extend(p.problems())
            if p.name and prompt_names.count(p.name) > 1:
                out.append(tr("Two prompt profiles are named {name}.").format(name=p.name))
        names = [p.name for p in self.settings.sandboxes]
        for p in self.settings.sandboxes:
            if not p.name:
                out.append(tr("A sandbox has no name."))
            elif names.count(p.name) > 1:
                out.append(tr("Two sandboxes are named {name}.").format(name=p.name))
        servers = [s.name for s in self.settings.mcp_servers]
        for server in self.settings.mcp_servers:
            for what in server.problems():
                what = "a URL" if what.startswith("an http") else what
                out.append(
                    tr("The MCP server {name} needs {what}.").format(
                        name=server.name or "?", what=what
                    )
                )
            if servers.count(server.name) > 1:
                out.append(tr("Two MCP servers are named {name}.").format(name=server.name))
        sandboxes = {p.name for p in self.settings.sandboxes}
        for server in self.settings.mcp_servers:
            if server.sandbox and server.sandbox not in sandboxes:
                out.append(
                    tr("The MCP server {name} runs in the missing sandbox {sandbox}.").format(
                        name=server.name, sandbox=server.sandbox
                    )
                )
        return list(dict.fromkeys(out))

    def _general_values(self) -> dict:
        """The General / Access / default-sandbox choices as the tabs show them."""
        return {
            "profile": self.profile_combo.currentData() or "",
            "allow_bypass": self.bypass_check.isChecked(),
            "mode": self.mode_combo.currentData() or "ask",
            "max_steps": self.steps_spin.value(),
            "max_tool_chars": self.chars_spin.value(),
            "keep_sessions": self.keep_check.isChecked(),
            "groups": tuple(
                self.groups_list.item(i).text() for i in range(self.groups_list.count())
                if self.groups_list.item(i).checkState() == Qt.CheckState.Checked
            ),
            "access": self._ceiling(),
            "sandbox": self.default_sandbox_combo.currentData() or "",
            "prompt_profile": self.prompt_active_combo.currentData() or "",
        }

    def save(self) -> bool:
        self._store_sandbox()
        self._store_server()
        problems = self.problems()
        if problems:
            QMessageBox.warning(self, tr("Agent Settings"), "\n".join(problems))
            return False
        s = self.settings
        for name, value in self._general_values().items():
            setattr(s, name, value)
        try:
            s.save(self._path)
        except OSError as exc:
            QMessageBox.warning(
                self, tr("Agent Settings"), tr("The settings could not be saved:") + f"\n{exc}"
            )
            return False
        for name, token in self._tokens.items():
            try:
                MC.set_token(name, token)
            except Exception as exc:  # noqa: BLE001 - no keyring: say so, the rest is saved
                QMessageBox.warning(
                    self,
                    tr("Agent Settings"),
                    tr("The token of {name} could not be stored in the keyring:").format(name=name)
                    + f"\n{exc}",
                )
        self._tokens.clear()
        self._save_sessions()
        self.saved.emit()
        return True



class AgentSettingsPage(_AgentSettingsForm, QWidget):
    """Edit > Settings… > Agent (Tools > Agent Settings… opens it)."""

    #: Emitted after a successful save.
    saved = pyqtSignal()
    #: (server name, result line, tool names): a Test finished.
    _tested = pyqtSignal(str, str, str)

    def __init__(
        self,
        parent=None,
        *,
        settings_path=None,
        llm_settings: LP.LLMSettings | None = None,
        sessions=None,
        store_session=None,
    ) -> None:
        QWidget.__init__(self, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(
            self._build_form(settings_path, llm_settings, sessions, store_session), 1
        )
        self._baseline = self._snapshot()

    def _snapshot(self):
        return (
            repr(self._general_values()),
            repr([p.to_dict() for p in self.settings.sandboxes]),
            repr([server.to_dict() for server in self.settings.mcp_servers]),
            repr([p.to_dict() for p in self.settings.prompt_profiles]),
            tuple(sorted(self._tokens.items())),
            repr(sorted(self._session_edits.items())),
        )

    def is_dirty(self) -> bool:
        return self._snapshot() != self._baseline

    def save(self) -> bool:
        if not super().save():
            return False
        self._baseline = self._snapshot()
        return True


class AgentSettingsDialog(_AgentSettingsForm, QDialog):
    """The agent's settings as a dialog of their own (Save / Cancel)."""

    #: Emitted after a successful save.
    saved = pyqtSignal()
    #: (server name, result line, tool names): a Test finished.
    _tested = pyqtSignal(str, str, str)

    def __init__(
        self,
        parent=None,
        *,
        settings_path=None,
        llm_settings: LP.LLMSettings | None = None,
        sessions=None,
        store_session=None,
    ) -> None:
        QDialog.__init__(self, parent)
        self.setWindowTitle(tr("Agent Settings"))
        self.resize(820, 560)
        tabs = self._build_form(settings_path, llm_settings, sessions, store_session)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(tabs, 1)
        layout.addWidget(buttons)
        add_close_corner(self)

    def _save_and_close(self) -> None:
        if self.save():
            self.accept()
