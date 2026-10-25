"""The agent's settings: how the agent works, what it may reach, and the
sandboxes it runs in (core.agent_settings). :class:`AgentSettingsPage` is
the Agent page of Edit > Settings… (Tools > Agent Settings… opens it);
:class:`AgentSettingsDialog` is the same form as a dialog of its own.

Eight pages:

* **General** - the LLM profile and protection mode of new tabs, whether
  bypass may be chosen at all, step and output limits, whether tabs are
  kept, the tool groups new tabs offer.
* **Profiles** - agent profiles (core.agent_profiles): named bundles of a
  tab's settings - LLM and prompt profile, mode, sandbox, tool groups,
  axross functions, files read-only, MCP servers by category or name. The
  presets are read-only (Copy makes an editable one); a preview shows what
  a tab gets within the Access page, and Install from Catalog… opens the
  catalog on a category the profile misses. One may be the profile of new
  tabs.
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
  http server's token and a server's secret environment values go to the
  keyring. *Add from Catalog…* (ui.mcp_catalog_dialog) searches the MCP
  sources and installs a server into rootless podman (core.mcp_install);
  *Uninstall* removes such a server and, on Save, its image; *Check for
  Update* looks up its package upstream. *Detected on this machine*
  (core.mcp_detect) lists the servers of other clients (Claude Desktop,
  Claude Code, VS Code, Cursor) and podman images
  axross installed:
  a tick adds one switched on (secret values to the keyring on Save), an
  untick removes it again.
* **MCP Sources** - where Add from Catalog searches (core.mcp_catalog):
  the built-in catalog, the c0decave MCP Hub, Docker Hub's mcp namespace,
  the MCP Registry, Discover (curated lists, core.mcp_discover), and
  catalog files or https URLs of the user's, each checked on demand.
* **Sessions** - every tab's own access: its axross functions, network
  and folders, within the ceiling.

Save writes the file; the open Agent tabs read it before their next task.
"""

from __future__ import annotations

import dataclasses
import logging
import queue
import shlex
import threading

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
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
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import agent_profiles as AGP
from core import agent_prompts as AP
from core import agent_settings as S
from core import llm_profiles as LP
from core import mcp_catalog as M
from core import mcp_client as MC
from core.agent_net import parse_host
from core.agent_sandbox import ENGINES, LEVELS, RULES, SandboxProfile, available
from core.i18n import tr
from ui.close_corner import add_close_corner

#: Why the function boxes of the Access page cannot be ticked.
SWITCH_ON_FIRST = 'Switch on "Let agents use axross functions" first to choose these.'

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
log = logging.getLogger(__name__)

CONFIRM_LABELS = {
    "always": "Every call asks (also in Auto)",
    "writes": "Tools the server marks read-only run without asking",
}


#: The tabs of the agent's settings, in order: (id, title).
AGENT_TABS: tuple[tuple[str, str], ...] = (
    ("general", "General"),
    ("profiles", "Profiles"),
    ("prompts", "Prompts"),
    ("access", "Access"),
    ("sandboxes", "Sandboxes"),
    ("mcp", "MCP Servers"),
    ("mcp_sources", "MCP Sources"),
    ("sessions", "Sessions"),
)


def default_detector(**kwargs):
    """MCP servers on this machine: the other clients' files and podman
    images axross installed (core.mcp_detect)."""
    from core.mcp_detect import detect
    from core.mcp_install import Podman

    return detect(podman=Podman(), **kwargs)


def free_name(name: str, taken) -> str:
    """*name*, or with a number when *taken* has it (at most 32 characters)."""
    candidate, n = name, 1
    while candidate in taken:
        n += 1
        suffix = str(n)
        candidate = f"{name[:32 - len(suffix)]}{suffix}"
    return candidate


def confirm_detected_install(parent, detected) -> bool:
    """Ask before a detected server that downloads code is installed into a
    container (it is never run on this machine)."""
    names = sorted(detected.secrets)
    text = tr("{name} downloads {spec} when it starts ({runner}). axross never runs that on this "
              "machine: it installs it into a container instead (rootless podman, no "
              "network).").format(name=detected.name, spec=detected.plan.spec,
                                  runner=detected.plan.runner)
    if names:
        text += " " + tr("Its values that look like secrets ({names}) go to the keyring, not to "
                         "agent.json.").format(names=", ".join(names))
    answer = QMessageBox.question(parent, tr("Detected MCP server"),
                                  text + "\n\n" + tr("Install it now?"))
    return answer == QMessageBox.StandardButton.Yes


def confirm_detected_secrets(parent, detected) -> bool:
    """Ask before a detected server with secret values is switched on - they
    go to the keyring (the question names them, never their values)."""
    names = sorted(detected.secrets) + (["the token"] if detected.token else [])
    if not names:
        return True
    answer = QMessageBox.question(
        parent, tr("Detected MCP server"),
        tr("{name} has values that look like secrets: {names}. Switching it on stores them in "
           "the keyring, not in agent.json. Switch it on?").format(
            name=detected.name, names=", ".join(names)))
    return answer == QMessageBox.StandardButton.Yes


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
        mcp_detector=None,
        mcp_opener=None,
    ) -> QTabWidget:
        """Build the tabs; returns the tab widget for the widget to place.
        *mcp_detector* (``**kw -> core.mcp_detect.DetectResult``) finds the
        MCP servers on this machine (default: core.mcp_detect.detect);
        *mcp_opener* is urllib's for the package registries (tests)."""
        self._path = settings_path
        self._mcp_detector = mcp_detector or default_detector
        self._mcp_opener = mcp_opener
        #: What the last scan found (core.mcp_detect.DetectedServer).
        self._detected: list = []
        self.settings = S.AgentSettings.load(settings_path)
        self._llm = llm_settings if llm_settings is not None else LP.LLMSettings.load()
        self._current: SandboxProfile | None = None
        self._loading = False
        self._server: MC.McpServerConfig | None = None
        #: Tokens typed here, per server name: written to the keyring on save
        #: ("" deletes).
        self._tokens: dict[str, str] = {}
        #: Secret environment values typed here: (server, variable) -> value,
        #: written to the keyring on save ("" deletes).
        self._secrets: dict[tuple[str, str], str] = {}
        #: Container servers uninstalled here: their images go on save.
        self._uninstalls: list[MC.McpServerConfig] = []
        self._catalog_dialog = None
        self._tested.connect(self._show_test)
        # Update and source checks report through a queue that a timer of
        # the page empties: a worker never touches a widget that may be gone.
        self._inbox: queue.SimpleQueue = queue.SimpleQueue()
        self._inbox_timer = QTimer(self)
        self._inbox_timer.setInterval(50)
        self._inbox_timer.timeout.connect(self._drain_inbox)
        self._inbox_timer.start()
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
        #: The presets (row 0.. of the Profiles list, never stored) and the
        #: user's agent profile shown in the form (None: a preset or none).
        self._agent_presets = AGP.presets()
        self._agent_profile_current: AGP.AgentProfile | None = None

        self.tabs = QTabWidget()
        builders = {
            "general": self._general_page,
            "profiles": self._agent_profiles_page,
            "prompts": self._prompts_page,
            "access": self._access_page,
            "sandboxes": self._sandbox_page,
            "mcp": self._mcp_page,
            "mcp_sources": self._mcp_sources_page,
            "sessions": self._sessions_page,
        }
        for tab_id, title in AGENT_TABS:
            self.tabs.addTab(builders[tab_id](), tr(title))
        self._detect_started = False
        # The machine is scanned when the MCP Servers tab is first shown,
        # not for every settings window that never shows it.
        self.tabs.currentChanged.connect(self._maybe_detect)
        # Servers, sandboxes and prompt profiles may have changed on their pages.
        self.tabs.currentChanged.connect(self._refresh_agent_profile_page)
        self._load_general()
        self._rebuild_agent_profile_list(select=self.settings.agent_profile or None)
        self.files_read_only_check.toggled.connect(self._update_agent_profile_preview)
        self.bypass_check.toggled.connect(self._refresh_agent_profile_modes)
        return self.tabs

    def _refresh_agent_profile_modes(self, *_args) -> None:
        """Bypass may (no longer) be chosen: the profile's mode list follows."""
        self._show_agent_profile(self.agent_profile_list.currentRow())

    def _maybe_detect(self, _index=None) -> None:
        if not self._detect_started and self.tabs.currentWidget() is self._mcp_page_widget:
            self.detect_servers()

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

    # -- Profiles (agent profiles) ------------------------------------------------------

    def _agent_profiles_page(self) -> QWidget:
        from ui.agent_access_dialog import AccessEditor

        page = QWidget()
        top = QHBoxLayout(page)
        left = QVBoxLayout()
        self.agent_profile_list = QListWidget()
        self.agent_profile_list.currentRowChanged.connect(self._show_agent_profile)
        left.addWidget(self.agent_profile_list, 1)
        row = QHBoxLayout()
        self.agent_profile_new_button = QPushButton(tr("New"))
        self.agent_profile_new_button.clicked.connect(lambda _c=False: self.add_agent_profile())
        self.agent_profile_copy_button = QPushButton(tr("Copy"))
        self.agent_profile_copy_button.setToolTip(tr("An editable copy of this profile"))
        self.agent_profile_copy_button.clicked.connect(
            lambda _c=False: self.copy_agent_profile())
        self.agent_profile_delete_button = QPushButton(tr("Delete"))
        self.agent_profile_delete_button.clicked.connect(
            lambda _c=False: self.delete_agent_profile())
        for button in (self.agent_profile_new_button, self.agent_profile_copy_button,
                       self.agent_profile_delete_button):
            row.addWidget(button)
        left.addLayout(row)
        left.addWidget(QLabel(tr("Agent profile of new tabs")))
        self.agent_profile_default_combo = QComboBox()
        left.addWidget(self.agent_profile_default_combo)
        top.addLayout(left, 1)

        right = QVBoxLayout()
        self.agent_profile_form = QWidget()
        form = QFormLayout(self.agent_profile_form)
        self.agent_profile_name_edit = QLineEdit()
        self.agent_profile_name_edit.setMaxLength(AGP.MAX_NAME)
        form.addRow(tr("Name"), self.agent_profile_name_edit)
        self.agent_profile_description_edit = QLineEdit()
        self.agent_profile_description_edit.setMaxLength(AGP.MAX_DESCRIPTION)
        form.addRow(tr("Description"), self.agent_profile_description_edit)
        self.agent_profile_llm_combo = QComboBox()
        form.addRow(tr("LLM profile"), self.agent_profile_llm_combo)
        self.agent_profile_prompt_combo = QComboBox()
        form.addRow(tr("Prompt profile"), self.agent_profile_prompt_combo)
        self.agent_profile_mode_combo = QComboBox()
        form.addRow(tr("Protection mode"), self.agent_profile_mode_combo)
        self.agent_profile_sandbox_combo = QComboBox()
        form.addRow(tr("Sandbox"), self.agent_profile_sandbox_combo)
        self.agent_profile_groups = QListWidget()
        self.agent_profile_groups.setMaximumHeight(110)
        for group in S.OFFERED_GROUPS:
            item = QListWidgetItem(group)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.agent_profile_groups.addItem(item)
        form.addRow(tr("Tool groups"), self.agent_profile_groups)
        self.agent_profile_read_only_check = QCheckBox(tr("Files read-only"))
        self.agent_profile_write_check = QCheckBox(tr("Allow changes to files"))
        self.agent_profile_exec_check = QCheckBox(tr("Allow remote commands"))
        for box in (self.agent_profile_read_only_check, self.agent_profile_write_check,
                    self.agent_profile_exec_check):
            form.addRow("", box)
            box.toggled.connect(self._store_agent_profile)
        self.agent_profile_access = AccessEditor(folders=False)
        self.agent_profile_access.changed.connect(self._store_agent_profile)
        form.addRow(self.agent_profile_access)
        self.agent_profile_categories = QListWidget()
        self.agent_profile_categories.setMaximumHeight(150)
        self.agent_profile_categories.setToolTip(tr(
            "MCP servers installed from a catalog entry of a ticked category (or given that "
            "category in MCP Servers)"))
        form.addRow(tr("MCP server categories"), self.agent_profile_categories)
        self.agent_profile_servers = QListWidget()
        self.agent_profile_servers.setMaximumHeight(110)
        self.agent_profile_servers.setToolTip(tr(
            "MCP servers by name (or by the catalog entry they were installed from)"))
        form.addRow(tr("MCP servers"), self.agent_profile_servers)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.agent_profile_form)
        right.addWidget(scroll, 3)
        right.addWidget(QLabel(tr("A tab gets (within the Access page):")))
        self.agent_profile_preview = QPlainTextEdit()
        self.agent_profile_preview.setReadOnly(True)
        self.agent_profile_preview.setMaximumHeight(150)
        right.addWidget(self.agent_profile_preview, 1)
        missing_row = QHBoxLayout()
        self.agent_profile_missing = QListWidget()
        self.agent_profile_missing.setMaximumHeight(70)
        missing_row.addWidget(self.agent_profile_missing, 1)
        self.agent_profile_install_button = QPushButton(tr("Install from Catalog…"))
        self.agent_profile_install_button.setToolTip(tr(
            "Open Add from Catalog on the chosen missing category (or searching the server)"))
        self.agent_profile_install_button.clicked.connect(lambda _c=False: self.install_missing())
        missing_row.addWidget(self.agent_profile_install_button, 0, Qt.AlignmentFlag.AlignTop)
        right.addLayout(missing_row)
        top.addLayout(right, 2)

        for edit in (self.agent_profile_name_edit, self.agent_profile_description_edit):
            edit.textChanged.connect(self._store_agent_profile)
        for combo in (self.agent_profile_llm_combo, self.agent_profile_prompt_combo,
                      self.agent_profile_mode_combo):
            combo.currentIndexChanged.connect(self._store_agent_profile)
        self.agent_profile_sandbox_combo.currentIndexChanged.connect(self._agent_sandbox_changed)
        for widget in (self.agent_profile_groups, self.agent_profile_categories,
                       self.agent_profile_servers):
            widget.itemChanged.connect(self._store_agent_profile)
        self.agent_profiles_page = page
        return page

    def _agent_profile_rows(self) -> list[AGP.AgentProfile]:
        """The Profiles list in order: the presets, then the user's."""
        return [*self._agent_presets, *self.settings.agent_profiles]

    def _rebuild_agent_profile_list(self, *, select: str | None = None,
                                    default: str | None = None) -> None:
        """Fill the list and the "new tabs" combo; select the profile named
        *select* (else the current row); the combo keeps *default* (else
        what it has)."""
        from ui.agent_profile_dialog import profile_label

        rows = self._agent_profile_rows()
        row = self.agent_profile_list.currentRow()
        if select is not None:
            row = next((i for i, p in enumerate(rows) if p.name == select), row)
        default = self.agent_profile_default_combo.currentData() if default is None else default
        if default is None:
            default = self.settings.agent_profile
        self.agent_profile_list.blockSignals(True)
        self.agent_profile_default_combo.blockSignals(True)
        try:
            self.agent_profile_list.clear()
            self.agent_profile_default_combo.clear()
            self.agent_profile_default_combo.addItem(tr("None - as the General page says"), "")
            for profile in rows:
                item = QListWidgetItem(profile_label(profile))
                item.setData(Qt.ItemDataRole.UserRole, profile.name)
                item.setToolTip(profile.description)
                self.agent_profile_list.addItem(item)
                self.agent_profile_default_combo.addItem(profile_label(profile), profile.name)
            self.agent_profile_default_combo.setCurrentIndex(
                max(0, self.agent_profile_default_combo.findData(default)))
        finally:
            self.agent_profile_list.blockSignals(False)
            self.agent_profile_default_combo.blockSignals(False)
        self.agent_profile_list.setCurrentRow(row if 0 <= row < len(rows) else 0)
        self._show_agent_profile(self.agent_profile_list.currentRow())

    def _refresh_agent_profile_page(self, _index=None) -> None:
        if self.tabs.currentWidget() is getattr(self, "agent_profiles_page", None):
            self._show_agent_profile(self.agent_profile_list.currentRow())

    def _fill_combo(self, combo: QComboBox, entries, current: str) -> None:
        """*entries* ``(label, data)``; *current* is chosen, added as
        "(missing)" when it is none of them."""
        combo.clear()
        for label, data in entries:
            combo.addItem(label, data)
        if current and combo.findData(current) < 0:
            combo.addItem(tr("{name} (missing)").format(name=current), current)
        combo.setCurrentIndex(max(0, combo.findData(current)))

    def _fill_checks(self, widget: QListWidget, names, ticked) -> None:
        ticked_keys = {t.strip().casefold() for t in ticked}
        widget.clear()
        shown = []
        for name in [*names, *ticked]:
            if name.strip().casefold() in (n.casefold() for n in shown):
                continue
            shown.append(name.strip())
            item = QListWidgetItem(name.strip())
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if name.strip().casefold() in ticked_keys
                               else Qt.CheckState.Unchecked)
            widget.addItem(item)

    @staticmethod
    def _ticked(widget: QListWidget) -> tuple[str, ...]:
        return tuple(widget.item(i).text() for i in range(widget.count())
                     if widget.item(i).checkState() == Qt.CheckState.Checked)

    def _show_agent_profile(self, row: int) -> None:
        rows = self._agent_profile_rows()
        if not 0 <= row < len(rows):
            self._agent_profile_current = None
            self.agent_profile_form.setEnabled(False)
            self.agent_profile_copy_button.setEnabled(False)
            self.agent_profile_delete_button.setEnabled(False)
            self._update_agent_profile_preview()
            return
        profile = rows[row]
        self._loading = True
        try:
            self._agent_profile_current = None if profile.preset else profile
            self.agent_profile_name_edit.setText(profile.name)
            self.agent_profile_description_edit.setText(profile.description)
            # The beginning, not the end setText leaves the cursor at.
            self.agent_profile_name_edit.setCursorPosition(0)
            self.agent_profile_description_edit.setCursorPosition(0)
            self._fill_combo(self.agent_profile_llm_combo,
                             [(tr("Default model"), "")]
                             + [(p.name, p.name) for p in self._llm.profiles],
                             profile.llm_profile)
            self._fill_combo(self.agent_profile_prompt_combo,
                             [(tr("As Agent Settings > Prompts"), ""),
                              (tr("{name} (built-in)").format(name=AP.DEFAULT_NAME),
                               AP.DEFAULT_NAME)]
                             + [(p.name, p.name) for p in self.settings.prompt_profiles],
                             profile.prompt_profile)
            modes = [m for m in S.MODES if m != "bypass" or self.bypass_check.isChecked()
                     or profile.mode == "bypass"]
            self._fill_combo(self.agent_profile_mode_combo,
                             [(tr(MODE_LABELS[m]), m) for m in modes], profile.mode)
            self._fill_combo(self.agent_profile_sandbox_combo,
                             [(tr("No sandbox"), "")]
                             + [(p.name, p.name) for p in self.settings.sandboxes],
                             profile.sandbox)
            for i in range(self.agent_profile_groups.count()):
                item = self.agent_profile_groups.item(i)
                item.setCheckState(Qt.CheckState.Checked if item.text() in profile.groups
                                   else Qt.CheckState.Unchecked)
            self.agent_profile_read_only_check.setChecked(profile.files_read_only)
            self.agent_profile_write_check.setChecked(profile.allow_write)
            self.agent_profile_exec_check.setChecked(profile.allow_exec)
            self._load_agent_access(profile)
            self._fill_checks(self.agent_profile_categories,
                              AGP.known_categories(self.settings.mcp_servers),
                              profile.mcp_categories)
            self._fill_checks(self.agent_profile_servers,
                              [s.name for s in self.settings.mcp_servers], profile.mcp_servers)
            self.agent_profile_form.setEnabled(not profile.preset)
            self.agent_profile_copy_button.setEnabled(True)
            self.agent_profile_delete_button.setEnabled(not profile.preset)
        finally:
            self._loading = False
        self._update_agent_profile_preview()

    def _load_agent_access(self, profile: AGP.AgentProfile) -> None:
        from core.agent_access import SessionAccess

        sandbox = self.settings.sandbox_profile(profile.sandbox) if profile.sandbox else None
        # No ceiling here: a profile may name any function; the Access page
        # cuts it when the profile is applied (the preview says so).
        self.agent_profile_access.load(
            SessionAccess(axross=profile.axross, functions=profile.functions,
                          network=profile.network, hosts=profile.hosts),
            [], ceiling=None, sandbox=sandbox)

    def _agent_sandbox_changed(self, *_args) -> None:
        self._store_agent_profile()
        p = self._agent_profile_current
        if p is not None and not self._loading:
            self._loading = True
            try:
                self._load_agent_access(p)  # the network choices of the new level
            finally:
                self._loading = False
            self._store_agent_profile()

    def _store_agent_profile(self, *_args) -> None:
        if self._loading or self._agent_profile_current is None:
            return
        p = self._agent_profile_current
        old_name = p.name
        p.name = self.agent_profile_name_edit.text().strip()
        p.description = self.agent_profile_description_edit.text().strip()
        p.llm_profile = self.agent_profile_llm_combo.currentData() or ""
        p.prompt_profile = self.agent_profile_prompt_combo.currentData() or ""
        p.mode = self.agent_profile_mode_combo.currentData() or "ask"
        p.sandbox = self.agent_profile_sandbox_combo.currentData() or ""
        ticked = self._ticked(self.agent_profile_groups)
        p.groups = tuple(g for g in S.OFFERED_GROUPS if g in ticked)
        p.files_read_only = self.agent_profile_read_only_check.isChecked()
        p.allow_write = self.agent_profile_write_check.isChecked()
        p.allow_exec = self.agent_profile_exec_check.isChecked()
        access = self.agent_profile_access.access()
        p.axross, p.functions = access.axross, access.functions
        p.network, p.hosts = access.network, access.hosts
        p.mcp_categories = self._ticked(self.agent_profile_categories)
        p.mcp_servers = self._ticked(self.agent_profile_servers)
        if old_name != p.name:
            from ui.agent_profile_dialog import profile_label

            index = len(self._agent_presets) + next(
                i for i, q in enumerate(self.settings.agent_profiles) if q is p)
            item = self.agent_profile_list.item(index)
            if item is not None:
                item.setText(profile_label(p))
                item.setData(Qt.ItemDataRole.UserRole, p.name)
            # The "new tabs" entry of this row follows the rename.
            self.agent_profile_default_combo.setItemText(index + 1, profile_label(p))
            self.agent_profile_default_combo.setItemData(index + 1, p.name)
        self._update_agent_profile_preview()

    def _profile_settings_view(self) -> S.AgentSettings:
        """The settings as the pages show them now (the Access page's
        ceiling, whether bypass may be chosen)."""
        return dataclasses.replace(self.settings, access=self._ceiling(),
                                   allow_bypass=self.bypass_check.isChecked())

    def _shown_agent_profile(self) -> AGP.AgentProfile | None:
        rows = self._agent_profile_rows()
        row = self.agent_profile_list.currentRow()
        return rows[row] if 0 <= row < len(rows) else None

    def _update_agent_profile_preview(self, *_args) -> None:
        profile = self._shown_agent_profile()
        self.agent_profile_missing.clear()
        if profile is None or not hasattr(self, "axross_check"):
            self.agent_profile_preview.clear()
            self.agent_profile_install_button.setEnabled(False)
            return
        res = AGP.resolve(profile, self._profile_settings_view(),
                          llm_names=[p.name for p in self._llm.profiles])
        self.agent_profile_preview.setPlainText("\n".join(AGP.summary_lines(profile, res)))
        for missing in res.missing:
            item = QListWidgetItem(AGP.missing_text(missing))
            item.setData(Qt.ItemDataRole.UserRole, (missing.kind, missing.name))
            self.agent_profile_missing.addItem(item)
        if self.agent_profile_missing.count():
            self.agent_profile_missing.setCurrentRow(0)
        self.agent_profile_install_button.setEnabled(bool(res.missing))

    def _unique_agent_profile_name(self, base: str) -> str:
        names = {p.name.casefold() for p in self._agent_profile_rows()}
        name, n = base, 1
        while name.casefold() in names:
            n += 1
            name = f"{base} {n}"
        return name

    def _append_agent_profile(self, profile: AGP.AgentProfile) -> None:
        self._store_agent_profile()
        self.settings.agent_profiles.append(profile)
        self._rebuild_agent_profile_list(select=profile.name)
        self.agent_profile_name_edit.setFocus()

    def add_agent_profile(self) -> None:
        """A new profile: as a new tab starts (the General page's groups)."""
        self._append_agent_profile(AGP.AgentProfile(
            name=self._unique_agent_profile_name(tr("Agent profile")),
            groups=tuple(g for g in S.OFFERED_GROUPS if g in self._general_values()["groups"])))

    def copy_agent_profile(self) -> None:
        source = self._shown_agent_profile()
        if source is None:
            return
        self._store_agent_profile()
        self._append_agent_profile(source.copy(AGP.free_profile_name(
            source.name, [p.name for p in self.settings.agent_profiles])))

    def delete_agent_profile(self) -> None:
        profile = self._shown_agent_profile()
        if profile is None or profile.preset:
            return  # the presets stay
        row = self.agent_profile_list.currentRow()
        default = self.agent_profile_default_combo.currentData()
        self.settings.agent_profiles = [p for p in self.settings.agent_profiles
                                        if p is not profile]
        self._agent_profile_current = None
        self._rebuild_agent_profile_list(default="" if default == profile.name else default)
        self.agent_profile_list.setCurrentRow(min(row, len(self._agent_profile_rows()) - 1))

    def install_missing(self):
        """Install from Catalog… for the chosen missing entry: the catalog
        on its category, or searching the server's name. Returns the dialog."""
        item = self.agent_profile_missing.currentItem() or self.agent_profile_missing.item(0)
        if item is None:
            return None
        kind, name = item.data(Qt.ItemDataRole.UserRole)
        if kind == "category":
            return self.add_from_catalog(category=name)
        return self.add_from_catalog(query=name)

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
            "chooses. Only an MCP server that cannot change files keeps its tools: a container "
            "installed by axross with no network and only read-only folders (its calls still "
            "ask as its Asks says)."))
        layout.addWidget(self.files_read_only_check)
        self.axross_check = QCheckBox(tr("Let agents use axross functions"))
        self.axross_check.setToolTip(tr(
            "Tools axross runs itself, outside the agent's sandbox and with axross's rights. "
            "Off: no tab reaches any of them, whatever it chose."))
        self.axross_check.toggled.connect(self._update_access_page)
        layout.addWidget(self.axross_check)
        # Without it the locked boxes below look broken.
        self.axross_off_hint = QLabel(tr(SWITCH_ON_FIRST))
        self.axross_off_hint.setWordWrap(True)
        self.axross_off_hint.setContentsMargins(18, 0, 0, 0)
        self.axross_off_hint.setEnabled(False)
        layout.addWidget(self.axross_off_hint)
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
                "(Access…) limits the connections too. Production connections refuse every change. "
                "Files read-only drops every MCP tool that may write, except those of a container "
                "server axross installed with no network and only read-only folders."
            )
        )
        note.setWordWrap(True)
        self.access_note = note
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
        master = self.axross_check.isChecked()
        self.axross_off_hint.setHidden(master)
        for box in self._function_checks().values():
            box.setEnabled(master)
            box.setToolTip("" if master else tr(SWITCH_ON_FIRST))
        if getattr(self, "session_editor", None) is not None and self._session_row >= 0:
            self._show_session(self._session_row)  # the new ceiling
        if getattr(self, "agent_profile_preview", None) is not None:
            self._update_agent_profile_preview()

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
        for label, slot, attr in ((tr("Add"), self.add_server, "server_add_button"),
                                  (tr("Delete"), self.delete_server, "server_delete_button"),
                                  (tr("Test"), self.test_server, "server_test_button")):
            button = QPushButton(label)
            button.clicked.connect(slot)
            setattr(self, attr, button)
            row.addWidget(button)
        left.addLayout(row)
        self.catalog_button = QPushButton(tr("Add from Catalog…"))
        self.catalog_button.setToolTip(tr(
            "Search the MCP sources (Docker Hub's mcp namespace, the MCP Registry, the "
            "built-in catalog, your catalogs) and install a server into rootless podman"))
        self.catalog_button.clicked.connect(lambda _c=False: self.add_from_catalog())
        left.addWidget(self.catalog_button)
        row = QHBoxLayout()
        self.uninstall_button = QPushButton(tr("Uninstall"))
        self.uninstall_button.setToolTip(tr(
            "Remove this server; on Save its image is removed from podman too"))
        self.uninstall_button.clicked.connect(lambda _c=False: self.uninstall_server())
        self.update_button = QPushButton(tr("Check for Update"))
        self.update_button.clicked.connect(lambda _c=False: self.check_update())
        row.addWidget(self.uninstall_button)
        row.addWidget(self.update_button)
        left.addLayout(row)
        detected_row = QHBoxLayout()
        detected_row.addWidget(QLabel(tr("Detected on this machine:")), 1)
        self.detected_rescan_button = QPushButton(tr("Rescan"))
        self.detected_rescan_button.setToolTip(tr(
            "Look again for MCP servers of Claude Desktop, Claude Code, VS Code, Cursor "
            "and podman images axross installed"))
        self.detected_rescan_button.clicked.connect(lambda _c=False: self.detect_servers())
        detected_row.addWidget(self.detected_rescan_button)
        left.addLayout(detected_row)
        self.detected_list = QListWidget()
        self.detected_list.setToolTip(tr("Tick a server to add it switched on"))
        self.detected_list.itemChanged.connect(self._on_detected_changed)
        self.detected_list.currentItemChanged.connect(self._show_detected)
        left.addWidget(self.detected_list, 1)
        self.detected_details = QPlainTextEdit()
        self.detected_details.setReadOnly(True)
        self.detected_details.setMaximumHeight(120)
        self.detected_details.setPlaceholderText(tr("Choose a detected server to see it."))
        left.addWidget(self.detected_details)
        top.addLayout(left, 1)

        self.server_form = QWidget()
        form = QFormLayout(self.server_form)
        self.server_name_edit = QLineEdit()
        form.addRow(tr("Name"), self.server_name_edit)
        self.server_enabled_check = QCheckBox(tr("Tabs may offer this server's tools"))
        form.addRow("", self.server_enabled_check)
        self.server_category_combo = QComboBox()
        self.server_category_combo.setEditable(True)
        self.server_category_combo.setToolTip(tr(
            "The catalog category it was installed from, or one of your own: agent profiles "
            "choose servers by it"))
        form.addRow(tr("Category"), self.server_category_combo)
        self.server_transport_combo = QComboBox()
        self.server_transport_combo.addItem(tr("Program (stdio)"), "stdio")
        self.server_transport_combo.addItem(tr("HTTP endpoint"), "http")
        form.addRow(tr("Connection"), self.server_transport_combo)
        self.server_command_edit = QLineEdit()
        self.server_command_edit.setPlaceholderText(
            "/usr/local/bin/mcp-server-git --repository /srv/repo")
        form.addRow(tr("Program"), self.server_command_edit)
        self.server_runner_label = QLabel()
        self.server_runner_label.setWordWrap(True)
        self.server_runner_label.setTextFormat(Qt.TextFormat.PlainText)
        self.server_contain_button = QPushButton(tr("Install in a Container"))
        self.server_contain_button.setToolTip(tr(
            "A command that downloads code (npx, uvx, docker run …) never runs on this machine: "
            "install its package or image into rootless podman instead (no network)"))
        self.server_contain_button.clicked.connect(lambda _c=False: self.install_in_container())
        self.server_runner_label.hide()
        self.server_contain_button.hide()
        runner_row = QVBoxLayout()
        runner_row.addWidget(self.server_runner_label)
        runner_row.addWidget(self.server_contain_button, 0, Qt.AlignmentFlag.AlignLeft)
        form.addRow("", runner_row)
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
        self.server_secret_env_edit = QLineEdit()
        self.server_secret_env_edit.setPlaceholderText("API_KEY OTHER_TOKEN")
        self.server_secret_env_edit.setToolTip(tr(
            "Environment variables whose values are kept in the keyring, not in the file"))
        secret_row = QHBoxLayout()
        secret_row.addWidget(self.server_secret_env_edit, 1)
        self.server_secret_button = QPushButton(tr("Set Secret…"))
        self.server_secret_button.clicked.connect(lambda _c=False: self.ask_secret())
        secret_row.addWidget(self.server_secret_button)
        form.addRow(tr("Secret environment"), secret_row)
        self.server_egress_edit = QLineEdit()
        self.server_egress_edit.setPlaceholderText("api.example.com:443")
        self.server_egress_edit.setToolTip(tr(
            "The hosts a container on the allowlist network may reach (host:port)"))
        form.addRow(tr("Allowed hosts"), self.server_egress_edit)
        self.server_package_label = QLabel()
        self.server_package_label.setWordWrap(True)
        self.server_package_label.setTextFormat(Qt.TextFormat.PlainText)
        self.server_package_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(tr("Installed from"), self.server_package_label)
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
                     self.server_url_edit, self.server_secret_env_edit, self.server_egress_edit):
            edit.textChanged.connect(self._store_server)
        for combo in (
            self.server_transport_combo,
            self.server_confirm_combo,
            self.server_sandbox_combo,
        ):
            combo.currentIndexChanged.connect(self._store_server)
        self.server_enabled_check.toggled.connect(self._store_server)
        self.server_category_combo.editTextChanged.connect(self._store_server)
        self.server_bearer_check.toggled.connect(self._store_server)
        self.server_timeout_spin.valueChanged.connect(self._store_server)
        self.server_token_edit.textChanged.connect(self._store_token)
        self._rebuild_server_list()
        self.server_list.setCurrentRow(0 if self.settings.mcp_servers else -1)
        self._show_server(self.server_list.currentRow())
        self._mcp_page_widget = page
        return page

    # -- detected on this machine ---------------------------------------------------------

    def _install_detected(self, detected) -> None:
        """Install a detected server that downloads code into a container
        (in the background); it is added switched on when that is done."""
        name = free_name(detected.name, {s.name for s in self.settings.mcp_servers})
        taken = {s.name for s in self.settings.mcp_servers}
        opener, inbox = self._mcp_opener, self._inbox
        self.server_test_label.setText(tr("Installing {name} in a container…").format(name=name))

        def run() -> None:
            from core import mcp_install as I

            try:
                config = detected.install(
                    name=name, podman=I.Podman(), opener=opener, taken=taken,
                    on_line=lambda line: inbox.put(("_show_install_line", line)))
            except I.InstallError as exc:
                inbox.put(("_detected_installed", detected, None, str(exc)))
                return
            except Exception as exc:  # noqa: BLE001 - shown, never a crash of the page
                log.exception("installing the detected %s failed", name)
                inbox.put(("_detected_installed", detected, None, type(exc).__name__))
                return
            inbox.put(("_detected_installed", detected, config, ""))

        threading.Thread(target=run, name="mcp-detected-install", daemon=True).start()

    def _detected_installed(self, detected, config, error: str) -> None:
        if config is None or config.name in {s.name for s in self.settings.mcp_servers}:
            self.server_test_label.setText(tr("Install failed: {why}").format(
                why=error or tr("the name is taken now")))
            self._fill_detected()
            return
        self._store_server()
        self.settings.mcp_servers.append(config)
        for var in config.secret_env:
            if detected.secrets.get(var):
                self._secrets[(config.name, var)] = detected.secrets[var]
        self._rebuild_server_list()
        self.server_list.setCurrentRow(len(self.settings.mcp_servers) - 1)
        self.server_test_label.setText(tr(
            "Installed in a container and switched on - Save keeps it"))
        self._fill_detected()

    def detect_servers(self) -> None:
        """Look for MCP servers on this machine (in the background)."""
        self._detect_started = True
        detector = self._mcp_detector
        configured = list(self.settings.mcp_servers)
        inbox = self._inbox

        def run() -> None:
            try:
                result = detector(configured=configured)
            except Exception:  # noqa: BLE001 - a scan must end, whatever it meets
                log.exception("detecting MCP servers failed")
                return
            inbox.put(("_take_detected", result))

        threading.Thread(target=run, name="mcp-detect", daemon=True).start()

    def _take_detected(self, result) -> None:
        self._detected = list(result.servers)
        self._fill_detected()

    def _configured_as(self, detected) -> MC.McpServerConfig | None:
        from core.mcp_detect import configured_as

        return configured_as(detected, self.settings.mcp_servers)

    def _fill_detected(self) -> None:
        from ui.mcp_catalog_dialog import plain_tooltip

        current = self.detected_list.currentItem()
        chosen = current.data(Qt.ItemDataRole.UserRole) if current is not None else None
        self.detected_list.blockSignals(True)
        try:
            self.detected_list.clear()
            for detected in self._detected:
                text = f"{detected.name}  ({', '.join(detected.clients)})"
                if not detected.usable:
                    text += tr(" - cannot be used")
                item = QListWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, detected.key)
                item.setToolTip(plain_tooltip(detected.describe()))
                if detected.usable:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Checked if self._configured_as(detected)
                                       else Qt.CheckState.Unchecked)
                else:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                self.detected_list.addItem(item)
                if detected.key == chosen:
                    self.detected_list.setCurrentItem(item)
        finally:
            self.detected_list.blockSignals(False)
        self._show_detected(self.detected_list.currentItem())

    def _detected_of(self, item):
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return next((d for d in self._detected if d.key == key), None)

    def _show_detected(self, item, _previous=None) -> None:
        detected = self._detected_of(item)
        self.detected_details.setPlainText(detected.describe() if detected is not None else "")

    def _on_detected_changed(self, item) -> None:
        detected = self._detected_of(item)
        if detected is None:
            return
        if item.checkState() == Qt.CheckState.Checked:
            if self._configured_as(detected) is None and not self.add_detected(detected):
                self.detected_list.blockSignals(True)
                item.setCheckState(Qt.CheckState.Unchecked)
                self.detected_list.blockSignals(False)
            return
        server = self._configured_as(detected)
        if server is None:
            return
        if server.package.get("source") != "detected":
            # Set up by hand (or installed from a catalog): not removed by an untick.
            self.detected_list.blockSignals(True)
            item.setCheckState(Qt.CheckState.Checked)
            self.detected_list.blockSignals(False)
            self.server_test_label.setText(tr(
                "{name} was not added from this list - delete it in the list above").format(
                name=server.name))
            return
        self._store_server()
        self.server_list.setCurrentRow(self.settings.mcp_servers.index(server))
        self.delete_server()

    def add_detected(self, detected) -> bool:
        """Add *detected* switched on (its secrets to the keyring on Save);
        False when it cannot be used or the user says no."""
        if not detected.usable:
            return False
        if detected.needs_install:
            if not confirm_detected_install(self, detected):
                return False
            self._install_detected(detected)
            return True
        if not confirm_detected_secrets(self, detected):
            return False
        self._store_server()
        names = {s.name for s in self.settings.mcp_servers}
        config = detected.config(name=free_name(detected.name, names),
                                 sandbox=self.default_sandbox_combo.currentData() or "")
        self.settings.mcp_servers.append(config)
        for var, value in detected.secrets.items():
            self._secrets[(config.name, var)] = value
        if detected.token:
            self._tokens[config.name] = detected.token
        self._rebuild_server_list()
        self.server_list.setCurrentRow(len(self.settings.mcp_servers) - 1)
        self.server_test_label.setText(tr("Detected server added and switched on - Save keeps it"))
        return True

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
        label = f"{server.name or tr('(unnamed)')}  ({server.transport}{state})"
        if server.transport == "stdio" and server.command and not server.container:
            from core.mcp_runner import downloading_runner

            if downloading_runner(server.command) is not None:
                label += tr(" - downloads code: install it in a container")
            elif not server.sandbox:
                label += tr(" - runs on this machine, not in a container")
        return label

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
            self.server_category_combo.clear()
            self.server_category_combo.addItems(
                ["", *AGP.known_categories(self.settings.mcp_servers)])
            self.server_category_combo.setEditText(server.category)
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
            self.server_secret_env_edit.setText(" ".join(server.secret_env))
            self.server_egress_edit.setText(" ".join(server.egress))
            self.server_package_label.setText(_package_text(server))
        finally:
            self._loading = False
        self._update_server_fields()

    def _update_server_fields(self) -> None:
        stdio = self.server_transport_combo.currentData() == "stdio"
        container = self._server is not None and self._server.container
        for widget in (self.server_command_edit, self.server_env_edit, self.server_sandbox_combo,
                       self.server_secret_env_edit, self.server_secret_button):
            widget.setEnabled(stdio)
        # A container is its own sandbox; its network is set at install.
        self.server_sandbox_combo.setEnabled(stdio and not container)
        self.server_sandbox_combo.setToolTip(
            tr("A container server runs in podman - it is its own sandbox") if container else "")
        allowlist = container and any(MC.TOKEN_EGRESS in a for a in self._server.command)
        self.server_egress_edit.setEnabled(bool(allowlist))
        self.uninstall_button.setEnabled(container)
        self.update_button.setEnabled(container and bool(self._server.package.get("kind")))
        for widget in (self.server_url_edit, self.server_bearer_check):
            widget.setEnabled(not stdio)
        self.server_token_edit.setEnabled(not stdio and self.server_bearer_check.isChecked())
        self._update_runner()

    def _runner_plan(self):
        """The shown server's command as a downloading runner (or None)."""
        from core.mcp_runner import downloading_runner

        server = self._server
        if server is None or server.container or server.transport != "stdio":
            return None
        return downloading_runner(server.command)

    def _update_runner(self) -> None:
        plan = self._runner_plan()
        self.server_runner_label.setVisible(plan is not None)
        self.server_contain_button.setVisible(plan is not None)
        self.server_contain_button.setEnabled(bool(plan and plan.convertible)
                                              and not getattr(self, "_containing", False))
        if plan is None:
            self.server_runner_label.clear()
        elif plan.convertible:
            text = tr("{runner} downloads {spec} when it starts: such a command is never run on "
                      "this machine and is not saved as a program here. Install in a Container "
                      "builds it in rootless podman (no network).").format(
                runner=plan.runner, spec=plan.spec)
            if plan.dropped:
                text += " " + tr("Not taken over from its line: {flags}").format(
                    flags=", ".join(plan.dropped))
            self.server_runner_label.setText(text)
        else:
            self.server_runner_label.setText(tr(
                "{runner} downloads code when it starts and cannot be put into a container: "
                "{why}. It is not saved.").format(runner=plan.runner, why=plan.why_not))

    def install_in_container(self) -> None:
        """Install the shown server's downloading command the contained way
        (core.mcp_install.install_plan) in the background; the server is
        replaced by the container server when it is done."""
        self._store_server()
        plan = self._runner_plan()
        server = self._server
        if plan is None or not plan.convertible or server is None or getattr(
                self, "_containing", False):
            return
        name = server.name
        env = dict(server.env)
        secrets = {var: self._secrets.get((name, var)) or MC.get_secret(name, var)
                   for var in server.secret_env}
        secrets = {k: v for k, v in secrets.items() if v}
        missing = tuple(v for v in server.secret_env if v not in secrets)
        taken = {s.name for s in self.settings.mcp_servers if s is not server}
        opener, inbox = self._mcp_opener, self._inbox
        self._containing = True
        self.server_contain_button.setEnabled(False)
        self.server_test_label.setText(tr("Installing {spec} in a container…").format(
            spec=plan.spec))

        def run() -> None:
            from core import mcp_install as I

            try:
                config = I.install_plan(
                    plan, name=name, env=env, secrets=secrets, missing=missing,
                    podman=I.Podman(), opener=opener, taken=taken, source="manual",
                    on_line=lambda line: inbox.put(("_show_install_line", line)))
            except I.InstallError as exc:
                inbox.put(("_contained", server, None, str(exc)))
                return
            except Exception as exc:  # noqa: BLE001 - shown, never a crash of the page
                log.exception("installing %s in a container failed", name)
                inbox.put(("_contained", server, None, type(exc).__name__))
                return
            inbox.put(("_contained", server, config, ""))

        threading.Thread(target=run, name="mcp-contain", daemon=True).start()

    def _show_install_line(self, line: str) -> None:
        self.server_test_label.setText(M.clean_text(line, 300))

    def _contained(self, server, config, error: str) -> None:
        if config is None:
            self._containing = False
            self.server_test_label.setText(tr("Install failed: {why}").format(why=error))
            self._update_runner()
            return
        self._containing = False
        row = next((i for i, s in enumerate(self.settings.mcp_servers) if s is server), -1)
        if row < 0:
            self.server_test_label.setText(tr(
                "Installed, but its server was deleted meanwhile - not added"))
            return
        self.settings.mcp_servers[row] = config
        self._server = None
        self._rebuild_server_list()
        self.server_list.setCurrentRow(row)
        self._show_server(row)
        self.server_test_label.setText(tr(
            "Installed in a container and switched on - Save keeps it"))

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
            for var in server.secret_env:
                value = self._secrets.pop((old_name, var), None)
                if value is None:
                    value = MC.get_secret(old_name, var)
                if value:
                    self._secrets[(server.name, var)] = value
                if not held:
                    self._secrets[(old_name, var)] = ""
        server.enabled = self.server_enabled_check.isChecked()
        server.category = self.server_category_combo.currentText().strip()
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
        server.secret_env = tuple(dict.fromkeys(self.server_secret_env_edit.text().split()))
        if server.container:
            server.egress = tuple(dict.fromkeys(self.server_egress_edit.text().split()))
            if server.sandbox:
                server.sandbox = ""
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
        for var in gone.secret_env:
            self._secrets[(gone.name, var)] = ""
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
        secrets = self._secret_values(server)
        self.server_test_label.setText(tr("Connecting…"))

        settings = self.settings

        def run() -> None:
            try:
                # The same sandbox the tabs start it in - a test is a real start.
                extra = {"secrets": secrets} if server.secret_env else {}
                client = MC.McpClient(server, token=token, wrap=settings.mcp_wrap(server),
                                      **extra)
                try:
                    names = [t.remote_name for t in client.tools()]
                finally:
                    client.close()
                self._tested.emit(
                    server.name, tr("{n} tools").format(n=len(names)), ", ".join(names)
                )
            except MC.McpClientError as exc:
                self._tested.emit(server.name, tr("Test failed: {why}").format(why=exc), "")
            except Exception as exc:  # noqa: BLE001 - said, never a test stuck on "Connecting…"
                self._tested.emit(server.name, tr("Test failed: {why}").format(why=exc), "")

        threading.Thread(target=run, name="mcp-server-test", daemon=True).start()

    def _show_test(self, name: str, text: str, tools: str) -> None:
        if self._server is not None and self._server.name == name:
            self.server_test_label.setText(text)
            self.server_test_label.setToolTip(tools)

    def _secret_values(self, server: MC.McpServerConfig) -> dict:
        """The secrets of *server*: typed here (not yet saved) or the keyring's."""
        out = {}
        for var in server.secret_env:
            value = self._secrets.get((server.name, var))
            if value is None:
                value = MC.get_secret(server.name, var)
            if value:
                out[var] = value
        return out

    def set_secret_value(self, var: str, value: str) -> bool:
        """Keep *value* for the shown server's secret variable *var* (written
        to the keyring on save); False when *var* is not one of its secrets."""
        if self._server is None or var not in self._server.secret_env:
            return False
        self._secrets[(self._server.name, var)] = value
        return True

    def ask_secret(self) -> None:
        from PyQt6.QtWidgets import QInputDialog

        self._store_server()
        if self._server is None or not self._server.secret_env:
            QMessageBox.information(self, tr("Agent Settings"), tr(
                "Name the variable under Secret environment first."))
            return
        var, ok = QInputDialog.getItem(self, tr("Set Secret"), tr("Variable"),
                                       list(self._server.secret_env), 0, False)
        if not ok or not var:
            return
        value, ok = QInputDialog.getText(self, tr("Set Secret"),
                                         tr("Value of {var} (kept in the keyring)").format(
                                             var=var), QLineEdit.EchoMode.Password)
        if ok:
            self.set_secret_value(var, value)

    # -- catalog, uninstall, update ----------------------------------------------------

    def add_from_catalog(self, *, podman=None, opener=None, category: str = "",
                         query: str = ""):
        """Open Add from Catalog (window-modal, not blocking), on *category*
        or searching *query* when given; servers it installs are added here.
        Returns the dialog."""
        from ui.mcp_catalog_dialog import McpCatalogDialog

        self._store_server()
        dlg = McpCatalogDialog(self, sources=self.settings.mcp_sources,
                               taken={s.name for s in self.settings.mcp_servers},
                               podman=podman, opener=opener or self._mcp_opener,
                               category=category, query=query)
        dlg.installed.connect(self._take_installed)
        self._catalog_dialog = dlg
        dlg.open()
        return dlg

    def _take_installed(self, config, secrets, token: str) -> None:
        if config.name in {s.name for s in self.settings.mcp_servers}:
            return
        self.settings.mcp_servers.append(config)
        for var, value in (secrets or {}).items():
            if var in config.secret_env:
                self._secrets[(config.name, var)] = value
        if token:
            self._tokens[config.name] = token
        self._rebuild_server_list()
        self.server_list.setCurrentRow(len(self.settings.mcp_servers) - 1)
        self.server_test_label.setText(
            tr("Installed and switched on - Save keeps it") if config.enabled
            else tr("Installed, switched off: its test failed"))

    def uninstall_server(self, *, confirm: bool = True) -> bool:
        """Remove the shown container server; its image is removed on save."""
        self._store_server()
        server = self._server
        if server is None or not server.container:
            return False
        if confirm:
            answer = QMessageBox.question(
                self, tr("Uninstall"),
                tr("Remove {name}? On Save its image ({image}) is removed from podman as well, "
                   "unless another server uses it.").format(
                    name=server.name, image=server.package.get("image", "?")[:12]))
            if answer != QMessageBox.StandardButton.Yes:
                return False
        self._uninstalls.append(server)
        self.delete_server()
        return True

    def check_update(self, *, opener=None) -> None:
        """Look the shown server's package up upstream (in the background)."""
        self._store_server()
        server = self._server
        if server is None or not server.container:
            return
        self.server_test_label.setText(tr("Looking for an update…"))
        name = server.name
        inbox = self._inbox

        def run() -> None:
            from core.mcp_install import check_update

            info = check_update(server, opener=opener)
            if info.error:
                text = tr("Update check failed: {why}").format(why=info.error)
            elif info.newer:
                text = tr("An update exists: {latest} (installed: {current}). Install it again "
                          "from the catalog to use it.").format(latest=info.latest,
                                                               current=info.current)
            else:
                text = tr("Up to date ({current})").format(current=info.current)
            inbox.put(("_show_update", name, text))

        threading.Thread(target=run, name="mcp-update-check", daemon=True).start()

    def _drain_inbox(self) -> None:
        while True:
            try:
                handler, *args = self._inbox.get_nowait()
            except queue.Empty:
                return
            getattr(self, handler)(*args)

    def _show_update(self, name: str, text: str) -> None:
        if self._server is not None and self._server.name == name:
            self.server_test_label.setText(text)

    # -- MCP sources --------------------------------------------------------------------------

    def _mcp_sources_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        note = QLabel(tr(
            "Where Add from Catalog searches. What a source says is checked and shown as text; "
            "nothing from it runs on this machine - servers run in rootless podman."))
        note.setWordWrap(True)
        layout.addWidget(note)
        self.source_builtin_check = QCheckBox(tr("Built-in catalog (official images, pinned)"))
        self.source_hub_check = QCheckBox(
            tr("c0decave MCP Hub (ghcr.io/c0decave images, pinned by digest)"))
        self.source_dockerhub_check = QCheckBox(tr("Docker Hub - Docker's mcp namespace"))
        self.source_registry_check = QCheckBox(
            tr("MCP Registry (registry.modelcontextprotocol.io)"))
        self.source_discover_check = QCheckBox(tr(
            "Discover - curated awesome-lists to browse (install only where the MCP Registry "
            "or Docker Hub names the repository)"))
        for box in (self.source_builtin_check, self.source_hub_check,
                    self.source_dockerhub_check, self.source_registry_check,
                    self.source_discover_check):
            box.toggled.connect(self._store_sources)
            layout.addWidget(box)
        layout.addWidget(QLabel(tr("Your catalogs (a JSON file or an https:// URL):")))
        self.source_list = QListWidget()
        self.source_list.currentRowChanged.connect(lambda _r: self.source_check_label.clear())
        layout.addWidget(self.source_list, 1)
        row = QHBoxLayout()
        self.source_add_file_button = QPushButton(tr("Add File…"))
        self.source_add_file_button.clicked.connect(lambda _c=False: self.add_source_file())
        self.source_add_url_button = QPushButton(tr("Add URL…"))
        self.source_add_url_button.clicked.connect(lambda _c=False: self.add_source_url())
        self.source_remove_button = QPushButton(tr("Remove"))
        self.source_remove_button.clicked.connect(lambda _c=False: self.remove_source())
        self.source_check_button = QPushButton(tr("Check"))
        self.source_check_button.setToolTip(tr("Read the catalog now and say what it holds"))
        self.source_check_button.clicked.connect(lambda _c=False: self.check_source())
        for button in (self.source_add_file_button, self.source_add_url_button,
                       self.source_remove_button, self.source_check_button):
            row.addWidget(button)
        row.addStretch(1)
        layout.addLayout(row)
        self.source_check_label = QLabel()
        self.source_check_label.setWordWrap(True)
        self.source_check_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.source_check_label)
        schema = QLabel(tr(
            "A catalog has the schema \"axross-mcp-catalog\", version 1 - see docs/USAGE.md. "
            "Its images must be pinned by digest."))
        schema.setWordWrap(True)
        schema.setProperty("role", "muted")
        layout.addWidget(schema)
        self._load_sources()
        return page

    def _load_sources(self) -> None:
        sources = self.settings.mcp_sources
        self._loading = True
        try:
            self.source_builtin_check.setChecked(sources.builtin)
            self.source_hub_check.setChecked(sources.c0decave)
            self.source_dockerhub_check.setChecked(sources.dockerhub)
            self.source_registry_check.setChecked(sources.mcpregistry)
            self.source_discover_check.setChecked(sources.discover)
            self.source_list.clear()
            for location in sources.extra:
                self.source_list.addItem(location)
        finally:
            self._loading = False

    def _store_sources(self, *_args) -> None:
        if self._loading:
            return
        from dataclasses import replace

        self.settings.mcp_sources = replace(
            self.settings.mcp_sources,
            builtin=self.source_builtin_check.isChecked(),
            c0decave=self.source_hub_check.isChecked(),
            dockerhub=self.source_dockerhub_check.isChecked(),
            mcpregistry=self.source_registry_check.isChecked(),
            discover=self.source_discover_check.isChecked(),
            extra=tuple(self.source_list.item(i).text() for i in range(self.source_list.count())),
        )

    def add_source(self, location: str) -> bool:
        """Add a catalog location; False (and why, below the list) if refused."""
        location = (location or "").strip()
        problems = M.CatalogSources.problems_of(location)
        if not problems and location in self.settings.mcp_sources.extra:
            problems = [tr("it is in the list already")]
        if not problems and len(self.settings.mcp_sources.extra) >= M.MAX_EXTRA_SOURCES:
            problems = [tr("at most {n} catalogs").format(n=M.MAX_EXTRA_SOURCES)]
        if problems:
            self.source_check_label.setText(
                tr("Not added: {why}").format(why="; ".join(problems)))
            return False
        self.source_list.addItem(location)
        self.source_list.setCurrentRow(self.source_list.count() - 1)
        self._store_sources()
        self.source_check_label.setText(tr("Added - Check reads it now."))
        return True

    def add_source_file(self, path: str | None = None) -> bool:
        if not isinstance(path, str):
            path, _filter = QFileDialog.getOpenFileName(
                self, tr("MCP catalog file"), "", tr("JSON (*.json);;All files (*)"))
        return bool(path) and self.add_source(path)

    def add_source_url(self, url: str | None = None) -> bool:
        if not isinstance(url, str):
            from PyQt6.QtWidgets import QInputDialog

            url, ok = QInputDialog.getText(self, tr("MCP catalog URL"),
                                           tr("https:// address of a catalog (JSON)"))
            if not ok:
                return False
        return self.add_source(url)

    def remove_source(self) -> None:
        row = self.source_list.currentRow()
        if row >= 0:
            self.source_list.takeItem(row)
            self._store_sources()

    def check_source(self, *, opener=None) -> None:
        """Read the selected catalog (in the background) and say what it holds."""
        item = self.source_list.currentItem()
        if item is None:
            return
        location = item.text()
        self.source_check_label.setText(tr("Reading {where}…").format(where=location))
        source = M.CatalogSources(builtin=False, dockerhub=False, mcpregistry=False,
                                  c0decave=False, discover=False,
                                  extra=(location,)).sources(opener=opener)[0]
        inbox = self._inbox

        def run() -> None:
            result = source.search("")
            if result.error:
                text = tr("Refused: {why}").format(why=result.error)
            else:
                text = tr("{n} servers").format(n=len(result.entries))
                if result.warnings:
                    text += tr(", {n} entries skipped: {first}").format(
                        n=len(result.warnings), first="; ".join(result.warnings[:3]))
            inbox.put(("_show_source_check", location, text))

        threading.Thread(target=run, name="mcp-source-check", daemon=True).start()

    def _show_source_check(self, location: str, text: str) -> None:
        item = self.source_list.currentItem()
        if item is not None and item.text() == location:
            self.source_check_label.setText(text)

    # -- save ----------------------------------------------------------------------------

    def problems(self) -> list[str]:
        out = []
        self._store_prompt_profile()
        self._store_agent_profile()
        profile_names = [p.name.casefold() for p in self.settings.agent_profiles]
        for p in self.settings.agent_profiles:
            out.extend(p.problems())
            if p.name and profile_names.count(p.name.casefold()) > 1:
                out.append(tr("Two agent profiles are named {name}.").format(name=p.name))
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
            if server.category and MC.clean_category(server.category) != server.category:
                out.append(tr("The MCP server {name}: the category must be one line of plain "
                              "text of at most {n} characters.").format(
                                  name=server.name, n=MC.MAX_CATEGORY))
        for server in self.settings.mcp_servers:
            for host in server.egress:
                try:
                    parse_host(host)
                except ValueError as exc:
                    out.append(tr("The MCP server {name}: allowed host {why}").format(
                        name=server.name, why=exc))
            if server.container and any(MC.TOKEN_EGRESS in a for a in server.command) \
                    and not server.egress:
                out.append(tr("The MCP server {name} needs an allowed host (its network is "
                              "an allowlist).").format(name=server.name))
            for var in server.secret_env:
                if not MC._ENV_NAME.match(var):
                    out.append(tr("The MCP server {name}: {var} is not a variable name.").format(
                        name=server.name, var=var))
        sandboxes = {p.name for p in self.settings.sandboxes}
        for server in self.settings.mcp_servers:
            if server.sandbox and server.sandbox not in sandboxes:
                out.append(
                    tr("The MCP server {name} runs in the missing sandbox {sandbox}.").format(
                        name=server.name, sandbox=server.sandbox
                    )
                )
        return list(dict.fromkeys(out))

    def _remove_uninstalled_images(self) -> None:
        """The images of the servers uninstalled here (now saved), by ID."""
        from core.mcp_install import uninstall

        done, kept = [], []
        for server in self._uninstalls:
            ok, message = uninstall(server, others=self.settings.mcp_servers)
            (done if ok else kept).append(f"{server.name}: {message}" if message else server.name)
        self._uninstalls = []
        self.uninstall_messages = done + kept
        if kept:
            QMessageBox.warning(self, tr("Agent Settings"),
                                tr("Not every image was removed:") + "\n" + "\n".join(kept))

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
            "agent_profile": self.agent_profile_default_combo.currentData() or "",
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
        for (name, var), value in self._secrets.items():
            try:
                MC.set_secret(name, var, value)
            except Exception as exc:  # noqa: BLE001 - no keyring: say so, the rest is saved
                QMessageBox.warning(
                    self, tr("Agent Settings"),
                    tr("The secret {var} of {name} could not be stored in the keyring:").format(
                        var=var, name=name) + f"\n{exc}")
        self._secrets.clear()
        self._remove_uninstalled_images()
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
        mcp_detector=None,
        mcp_opener=None,
    ) -> None:
        QWidget.__init__(self, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(
            self._build_form(settings_path, llm_settings, sessions, store_session,
                             mcp_detector, mcp_opener), 1
        )
        self._baseline = self._snapshot()

    def _snapshot(self):
        return (
            repr(self._general_values()),
            repr([p.to_dict() for p in self.settings.sandboxes]),
            repr([server.to_dict() for server in self.settings.mcp_servers]),
            repr([p.to_dict() for p in self.settings.prompt_profiles]),
            repr([p.to_dict() for p in self.settings.agent_profiles]),
            tuple(sorted(self._tokens.items())),
            tuple(sorted(self._secrets.items())),
            tuple(s.name for s in self._uninstalls),
            repr(self.settings.mcp_sources.to_dict()),
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
        mcp_detector=None,
        mcp_opener=None,
    ) -> None:
        QDialog.__init__(self, parent)
        self.setWindowTitle(tr("Agent Settings"))
        self.resize(820, 560)
        tabs = self._build_form(settings_path, llm_settings, sessions, store_session,
                                mcp_detector, mcp_opener)
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


def _package_text(server: MC.McpServerConfig) -> str:
    """One line about where a container server came from."""
    pkg = server.package
    if not server.container or not pkg:
        return tr("- (configured by hand)")
    what = pkg.get("identifier", "")
    if pkg.get("kind") in ("npm", "pypi"):
        what = f"{pkg.get('kind')} {what} {pkg.get('version', '')}"
    elif pkg.get("digest"):
        what = f"{what}@{pkg['digest'][:19]}…"
    return tr("{what} - from {source}, image {image}, network {network}, {when}").format(
        what=what, source=pkg.get("source", "?"), image=pkg.get("image", "?")[:12],
        network=pkg.get("network", "?"), when=pkg.get("installed", ""))
