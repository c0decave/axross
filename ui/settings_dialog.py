"""Edit > Settings… (Ctrl+,): every setting of axross in one window.

A category list on the left, the category's page on the right, a filter
over the names of the settings above the list. The categories, in order:

==========  ===============================================  ==============================
Category    Settings                                         Store
==========  ===============================================  ==============================
General     language, restore the layout on start, when a    session.json (window), settings.json
            pane becomes the active one
Appearance  theme, compact mode, monochrome icons, font      session.json (window)
            size (zoom), highlight hidden files and their
            colour
Files       show hidden files, open size limit, RAM          session.json, settings.json,
            workspaces and temporary files in RAM            ramfs.json
Network     the default proxy (ui.network_proxy_dialog)      proxy.json + keyring
LLM         the LLM profiles (ui.llm_settings_dialog)        llm.json + keyring
Agent       the agent's settings, five sub-pages             agent/settings.json + keyring
            (ui.agent_settings_dialog)
Voice       registered by the voice feature (register_page)  its own
Audio       audio backend, output and input device and       audio.json
            volume, a test of each (ui.audio_settings_page)
Metadata    how Remove Metadata writes, asking first         settings.json
Search      hosts searched at once by Find on Network        settings.json
            Hosts, where the indexes are (information)
Security    paranoid security mode, remember the sudo        settings.json
            password
Extensions  which extensions are switched on                 extensions.json
==========  ===============================================  ==============================

**OK, Apply, Cancel - one rule for every page.** Only pages whose values
were changed are written. OK and Apply first check every changed page; if
one has a problem nothing at all is saved, that page is shown and the
problem is named above it. Then the changed pages are saved in the order of
the list and take effect at once (the language at the next start; temporary
files in RAM at the next start). Should a page fail to save (a disk error),
the dialog stays open on that page; the pages before it are saved. Cancel,
Esc and the [x] discard every change not yet applied.

**A page** is a QWidget with three methods - the protocol the Voice page
(or any page registered with :func:`register_page`) implements as well:

* ``is_dirty() -> bool`` - a value differs from what is stored;
* ``problems() -> list[str]`` - why it cannot be saved (optional, [] = none);
* ``save() -> bool`` - store and apply; False when it could not (the page
  has said why), or raise OSError / ValueError with the reason.

``shutdown()`` (optional) runs when the dialog closes.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractButton,
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui import themes, window_prefs
from ui.close_corner import add_close_corner

log = logging.getLogger(__name__)

MIB = 1024 * 1024

#: Category ids in the order of the list. "voice" is the slot of the voice
#: feature's page: it appears once a page is registered under that id.
CATEGORY_ORDER: tuple[str, ...] = (
    "general",
    "appearance",
    "files",
    "network",
    "llm",
    "agent",
    "voice",
    "audio",
    "metadata",
    "search",
    "security",
    "extensions",
)


@dataclass
class _Registered:
    title: str
    factory: Callable
    keywords: tuple[str, ...] = ()
    #: (sub id, title) - entries below the category in the list.
    sub_pages: tuple[tuple[str, str], ...] = field(default_factory=tuple)


_REGISTERED: dict[str, _Registered] = {}


def register_page(
    page_id: str,
    title: str,
    factory: Callable,
    *,
    keywords: tuple[str, ...] = (),
    sub_pages: tuple[tuple[str, str], ...] = (),
) -> None:
    """Add a page to the Settings dialog. *factory(parent, window)* builds
    the page widget (see the module docstring for its methods). An id of
    :data:`CATEGORY_ORDER` ("voice") takes that place; any other id comes
    after the built-in pages. Registering an id again replaces the page."""
    if page_id in _BUILTIN:
        raise ValueError(f"{page_id!r} is a built-in settings page")
    _REGISTERED[page_id] = _Registered(title, factory, tuple(keywords), tuple(sub_pages))


def unregister_page(page_id: str) -> None:
    _REGISTERED.pop(page_id, None)


# ---------------------------------------------------------------------------
# Pages of their own
# ---------------------------------------------------------------------------


def _note(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "muted")
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class _FormPage(QWidget):
    """A page of plain values: ``_values()`` reads the widgets, ``_store``
    writes the changed ones. Dirty is "differs from what was loaded"."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)

    def _finish(self) -> None:
        self.layout_.addStretch(1)
        self._baseline = self._values()

    def _values(self) -> dict:
        raise NotImplementedError

    def _store(self, changed: dict) -> None:
        raise NotImplementedError

    def changed_values(self) -> dict:
        now = self._values()
        return {k: v for k, v in now.items() if self._baseline.get(k) != v}

    def is_dirty(self) -> bool:
        return bool(self.changed_values())

    def problems(self) -> list[str]:
        return []

    def save(self) -> bool:
        changed = self.changed_values()
        if changed:
            self._store(changed)
        self._baseline = self._values()
        return True


class GeneralPage(_FormPage):
    """Language, restore the layout on start, pane activation."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        from core import i18n
        from core import pane_activation as PA

        form = QFormLayout()
        self.language_combo = QComboBox()
        self.language_combo.addItem(tr("Automatic (system locale)"), "")
        for code, name in i18n.SUPPORTED.items():
            self.language_combo.addItem(name, code)
        stored = i18n.stored_language() or ""
        self.language_combo.setCurrentIndex(max(0, self.language_combo.findData(stored)))
        form.addRow(tr("Language"), self.language_combo)
        form.addRow("", _note(tr("The language changes when axross restarts.")))

        self.restore_check = QCheckBox(tr("Restore the layout of the last session on start"))
        self.restore_check.setToolTip(
            tr("Open the panes, terminals and docks of the last session on start. "
               "Remote panes come back disconnected, with a Reconnect button.")
        )
        self.restore_check.setChecked(window.current_window_prefs().restore_layout_on_start)
        form.addRow(tr("Start"), self.restore_check)

        self.activation_combo = QComboBox()
        self.activation_combo.addItem(tr("On Click"), PA.CLICK)
        for seconds in PA.HOVER_SECONDS:
            self.activation_combo.addItem(
                tr("After {n} s in the Pane").format(n=seconds), seconds
            )
        current = PA.activation()
        self.activation_combo.setCurrentIndex(
            next(i for i in range(self.activation_combo.count())
                 if self.activation_combo.itemData(i) == current)
        )
        form.addRow(tr("Activate a pane"), self.activation_combo)
        self.layout_.addLayout(form)
        self._finish()

    def _values(self) -> dict:
        return {
            "language": self.language_combo.currentData(),
            "restore": self.restore_check.isChecked(),
            "activation": self.activation_combo.currentData(),
        }

    def _store(self, changed: dict) -> None:
        from core import i18n
        from core import pane_activation as PA

        if "language" in changed:
            i18n.store_language(changed["language"])
        if "restore" in changed:
            self._window.set_restore_on_start(changed["restore"])
        if "activation" in changed:
            PA.set_activation(changed["activation"])


class AppearancePage(_FormPage):
    """Theme, compact mode, monochrome icons, font size, hidden files' look."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        prefs = window.current_window_prefs()
        form = QFormLayout()
        self.theme_combo = QComboBox()
        for theme_id, label in themes.THEME_CHOICES:
            self.theme_combo.addItem(tr(label), theme_id)
        current = "classic" if prefs.theme == "dark" else prefs.theme
        self.theme_combo.setCurrentIndex(max(0, self.theme_combo.findData(current)))
        form.addRow(tr("Theme"), self.theme_combo)
        self.compact_check = QCheckBox(tr("Compact mode (smaller rows and margins)"))
        self.compact_check.setChecked(prefs.compact)
        form.addRow("", self.compact_check)
        self.monochrome_check = QCheckBox(tr("Monochrome icons"))
        self.monochrome_check.setChecked(prefs.monochrome_icons)
        form.addRow("", self.monochrome_check)

        self.font_spin = QSpinBox()
        # The minimum stands for "the desktop's size".
        self.font_spin.setRange(window_prefs.MIN_FONT_SIZE - 1, window_prefs.MAX_FONT_SIZE)
        self.font_spin.setSpecialValueText(tr("Desktop default"))
        self.font_spin.setSuffix(tr(" pt"))
        self.font_spin.setValue(prefs.font_size or self.font_spin.minimum())
        form.addRow(tr("Font size (zoom)"), self.font_spin)
        form.addRow("", _note(tr("View > Zoom In / Out / Reset (Ctrl+= / Ctrl+- / Ctrl+0) "
                                 "change it too.")))

        hidden = QGroupBox(tr("Hidden files"))
        hidden_form = QFormLayout(hidden)
        self.highlight_check = QCheckBox(tr("Highlight hidden files (italics, muted colour)"))
        self.highlight_check.setChecked(prefs.highlight_hidden)
        hidden_form.addRow("", self.highlight_check)
        self.theme_colour_radio = QRadioButton(tr("Theme colour"))
        self.own_colour_radio = QRadioButton(tr("Own colour"))
        self.colour_button = QPushButton(tr("Choose Colour…"))
        self.colour_button.clicked.connect(self.choose_colour)
        self.colour_label = QLabel()
        row = QHBoxLayout()
        row.addWidget(self.theme_colour_radio)
        row.addWidget(self.own_colour_radio)
        row.addWidget(self.colour_label)
        row.addWidget(self.colour_button)
        row.addStretch(1)
        hidden_form.addRow(tr("Hidden files colour"), row)
        self._colour: str | None = prefs.hidden_color
        self.theme_colour_radio.setChecked(self._colour is None)
        self.own_colour_radio.setChecked(self._colour is not None)
        self.own_colour_radio.setEnabled(self._colour is not None)
        self.theme_colour_radio.toggled.connect(self._show_colour)
        self._show_colour()
        self.layout_.addLayout(form)
        self.layout_.addWidget(hidden)
        self._finish()

    def _show_colour(self, *_args) -> None:
        colour = self.colour()
        self.colour_label.setText(colour or "")
        self.colour_label.setStyleSheet(f"color: {colour};" if colour else "")

    def colour(self) -> str | None:
        """The hidden-files colour as chosen here (None: the theme's)."""
        return self._colour if self.own_colour_radio.isChecked() else None

    def choose_colour(self) -> None:
        """A colour that is hard to read on the current theme (below WCAG AA
        on either row background) is used only after a question, default No."""
        start = QColor(self._colour) if self._colour else QColor("#888888")
        chosen = QColorDialog.getColor(start, self, tr("Hidden Files Colour"))
        if not chosen.isValid():
            return
        colour = chosen.name()
        ratio = self._window.hidden_colour_contrast(colour)
        if ratio < themes.MIN_TEXT_CONTRAST:
            answer = QMessageBox.question(
                self,
                tr("Hidden Files Colour"),
                tr("{colour} is hard to read on the current theme (contrast {ratio:.1f}:1, "
                   "readable text needs {need}:1). Use it anyway?").format(
                    colour=colour, ratio=ratio, need=themes.MIN_TEXT_CONTRAST),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._colour = colour
        self.own_colour_radio.setEnabled(True)
        self.own_colour_radio.setChecked(True)
        self._show_colour()

    def font_size(self) -> int | None:
        value = self.font_spin.value()
        return None if value == self.font_spin.minimum() else value

    def _values(self) -> dict:
        return {
            "theme": self.theme_combo.currentData(),
            "compact": self.compact_check.isChecked(),
            "monochrome": self.monochrome_check.isChecked(),
            "font_size": self.font_size(),
            "highlight": self.highlight_check.isChecked(),
            "colour": self.colour(),
        }

    def _store(self, changed: dict) -> None:
        win = self._window
        if "theme" in changed:
            # Compact first, unstored: the theme pass applies both at once.
            if "compact" in changed:
                win._compact_mode = changed["compact"]
            win.set_theme(changed["theme"])
            if "compact" in changed:
                win.store_window_prefs(**{window_prefs.COMPACT_KEY: changed["compact"]})
        elif "compact" in changed:
            win.set_compact_mode(changed["compact"])
        if "monochrome" in changed:
            win.set_monochrome_icons(changed["monochrome"])
        if "font_size" in changed:
            win.set_font_size(changed["font_size"])
        if "highlight" in changed:
            win.set_highlight_hidden(changed["highlight"])
        if "colour" in changed:
            win.set_hidden_color(changed["colour"])


class FilesPage(_FormPage):
    """Show hidden files, the open size limit, RAM workspaces."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        from core import open_limits as OL
        from core import ramfs_settings as RS

        form = QFormLayout()
        self.show_hidden_check = QCheckBox(tr("Show hidden files (Ctrl+H)"))
        self.show_hidden_check.setChecked(window.current_window_prefs().show_hidden)
        form.addRow(tr("Panes"), self.show_hidden_check)
        self.open_limit_spin = QSpinBox()
        self.open_limit_spin.setRange(OL.MIN_MAX_OPEN_MB, OL.MAX_MAX_OPEN_MB)
        self.open_limit_spin.setSuffix(" MB")
        self.open_limit_spin.setValue(OL.max_open_mb())
        form.addRow(tr("Open Size Limit"), self.open_limit_spin)
        form.addRow("", _note(tr("The largest file the text and hex viewers, the media "
                                 "viewer and the metadata tools read.")))
        self.layout_.addLayout(form)

        ram = QGroupBox(tr("RAM workspace"))
        ram_form = QFormLayout(ram)
        settings = RS.RamFsSettings.load()
        self.ramfs_check = QCheckBox(tr("RAM workspaces can be opened"))
        self.ramfs_check.setChecked(settings.ramfs_enabled)
        ram_form.addRow("", self.ramfs_check)
        self.ramfs_max_spin = QSpinBox()
        self.ramfs_max_spin.setRange(1, RS.MAX_BYTES // MIB)
        self.ramfs_max_spin.setSuffix(" MiB")
        self.ramfs_max_spin.setValue(max(1, settings.ramfs_max_bytes // MIB))
        ram_form.addRow(tr("Size limit of a RAM workspace"), self.ramfs_max_spin)
        self.ramfs_reserve_spin = QSpinBox()
        self.ramfs_reserve_spin.setRange(0, RS.MAX_BYTES // MIB)
        self.ramfs_reserve_spin.setSuffix(" MiB")
        self.ramfs_reserve_spin.setValue(settings.ramfs_system_reserve_bytes // MIB)
        ram_form.addRow(tr("Memory kept free for the system"), self.ramfs_reserve_spin)
        self.tmpfs_check = QCheckBox(tr("Temporary files in RAM (tmpfs) instead of on disk"))
        self.tmpfs_check.setChecked(settings.tmpfs_enabled)
        ram_form.addRow("", self.tmpfs_check)
        ram_form.addRow("", _note(tr(
            "Download and upload buffers, archive extraction and FUSE write buffers then "
            "never touch a disk, but take RAM. Applies from the next start; a TMPDIR set "
            "in the environment always wins.")))
        self.layout_.addWidget(ram)
        self._finish()

    def _values(self) -> dict:
        return {
            "show_hidden": self.show_hidden_check.isChecked(),
            "open_limit": self.open_limit_spin.value(),
            "ramfs_enabled": self.ramfs_check.isChecked(),
            "ramfs_max_mib": self.ramfs_max_spin.value(),
            "ramfs_reserve_mib": self.ramfs_reserve_spin.value(),
            "tmpfs_enabled": self.tmpfs_check.isChecked(),
        }

    def _store(self, changed: dict) -> None:
        from core import open_limits as OL
        from core import ramfs_settings as RS

        if "show_hidden" in changed:
            self._window.set_show_hidden(changed["show_hidden"])
        if "open_limit" in changed:
            OL.set_max_open_mb(changed["open_limit"])
        ram_keys = {"ramfs_enabled", "ramfs_max_mib", "ramfs_reserve_mib", "tmpfs_enabled"}
        if ram_keys & changed.keys():
            # Read again: only what changed here replaces what is stored.
            settings = RS.RamFsSettings.load()
            if "ramfs_enabled" in changed:
                settings.ramfs_enabled = changed["ramfs_enabled"]
            if "ramfs_max_mib" in changed:
                settings.ramfs_max_bytes = changed["ramfs_max_mib"] * MIB
            if "ramfs_reserve_mib" in changed:
                settings.ramfs_system_reserve_bytes = changed["ramfs_reserve_mib"] * MIB
            if "tmpfs_enabled" in changed:
                settings.tmpfs_enabled = changed["tmpfs_enabled"]
            settings.save()
            RS.reload_settings()  # a new RAM workspace uses the new values


class SearchPage(_FormPage):
    """Find on Network Hosts' parallelism; where the indexes live."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        from core import cas
        from core import metadata_index as MI
        from core import remote_sweep as RW

        form = QFormLayout()
        self.parallel_spin = QSpinBox()
        self.parallel_spin.setRange(1, RW.MAX_PARALLEL)
        self.parallel_spin.setValue(RW.parallel_hosts())
        form.addRow(tr("Hosts searched at once (Find on Network Hosts)"), self.parallel_spin)
        self.layout_.addLayout(form)
        where = QGroupBox(tr("Index locations"))
        where_form = QFormLayout(where)
        self.metadata_index_label = _note(str(MI.default_db_path()))
        where_form.addRow(tr("Offline index (Find in Index)"), self.metadata_index_label)
        self.cas_index_label = _note(str(cas.default_db_path()))
        where_form.addRow(tr("Duplicate index"), self.cas_index_label)
        where_form.addRow("", _note(tr(
            "Set by AXROSS_METADATA_DB and AXROSS_CAS_DB in the environment, else "
            "$XDG_DATA_HOME/axross (default ~/.local/share/axross; an index already "
            "there stays in use). Edit > Index Active Folder… fills the offline index.")))
        self.layout_.addWidget(where)
        self._finish()

    def _values(self) -> dict:
        return {"parallel": self.parallel_spin.value()}

    def _store(self, changed: dict) -> None:
        from core import remote_sweep as RW

        RW.set_parallel_hosts(changed["parallel"])


class SecurityPage(_FormPage):
    """Paranoid security mode and the sudo password."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        from core import security_mode as SM
        from core import sudo_password as SP

        self.paranoid_check = QCheckBox(tr("Paranoid security mode"))
        self.paranoid_check.setChecked(SM.is_paranoid())
        self.layout_.addWidget(self.paranoid_check)
        self.layout_.addWidget(_note(tr(
            "Blocks scripts and extensions, external viewers and automatic previews, legacy "
            "protocols (FTP, Telnet, TFTP, ...), remote commands, Find on Network Hosts and "
            "private proxy overrides. Kept for the next start.")))
        if (os.environ.get(SM.ENV) or "").strip():
            self.layout_.addWidget(_note(tr(
                "AXROSS_SECURITY_MODE is set in the environment: it decides the mode at "
                "every start; this switch changes it until axross exits.")))
        self.remember_check = QCheckBox(tr("Remember the sudo password while axross runs"))
        self.remember_check.setToolTip(
            tr("Keep the sudo password in memory while axross runs, so mounting a disk "
               "image asks once. Never stored on disk; off in Paranoid Security Mode.")
        )
        #: The stored choice; the box shows it only outside paranoid mode.
        self._remember = SP.remember_setting()
        self.layout_.addWidget(self.remember_check)
        self.layout_.addWidget(_note(tr(
            "Never written to disk. Paranoid security mode never remembers it.")))
        self.paranoid_check.toggled.connect(self._sync_remember)
        self.remember_check.toggled.connect(self._keep_remember)
        self._sync_remember()
        self._finish()

    def _sync_remember(self, *_args) -> None:
        paranoid = self.paranoid_check.isChecked()
        self.remember_check.blockSignals(True)
        self.remember_check.setChecked(not paranoid and self._remember)
        self.remember_check.blockSignals(False)
        self.remember_check.setEnabled(not paranoid)

    def _keep_remember(self, on: bool) -> None:
        if self.remember_check.isEnabled():
            self._remember = on

    def _values(self) -> dict:
        return {"paranoid": self.paranoid_check.isChecked(), "remember": self._remember}

    def _store(self, changed: dict) -> None:
        from core import sudo_password as SP

        if "remember" in changed:
            SP.set_remember(changed["remember"])
        if "paranoid" in changed:
            self._window.set_paranoid_mode(changed["paranoid"])


# ---------------------------------------------------------------------------
# The built-in pages
# ---------------------------------------------------------------------------


def _network_page(parent, window):
    from ui.network_proxy_dialog import NetworkProxyPage

    return NetworkProxyPage(window._profile_manager, parent)


def _llm_page(parent, window):
    from ui.llm_settings_dialog import LLMProfilesPage

    return LLMProfilesPage(parent)


def _agent_page(parent, window):
    from ui.agent_settings_dialog import AgentSettingsPage

    dock = getattr(window, "_agent_dock", None)
    live = dock is not None and hasattr(dock, "sessions")
    page = AgentSettingsPage(
        parent,
        sessions=dock.sessions if live else None,
        store_session=dock.store_session if live else None,
    )
    page.saved.connect(window.refresh_agent_settings)
    return page


def _audio_page(parent, window):
    from ui.audio_settings_page import AudioPage

    return AudioPage(parent)


def _audio_keywords() -> tuple[str, ...]:
    from ui.audio_settings_page import KEYWORDS

    return KEYWORDS


def _metadata_page(parent, window):
    from ui.metadata_dialog import MetadataSettingsPage

    return MetadataSettingsPage(parent)


def _extensions_page(parent, window):
    from ui.extensions_dialog import ExtensionsPage

    return ExtensionsPage(window.extension_host, parent)


def _agent_sub_pages() -> tuple[tuple[str, str], ...]:
    from ui.agent_settings_dialog import AGENT_TABS

    return AGENT_TABS


#: id -> (title, factory(parent, window), keywords, sub pages()).
_BUILTIN: dict[str, tuple[str, Callable, tuple[str, ...], Callable | None]] = {
    "general": ("General", lambda p, w: GeneralPage(w, p),
                ("language", "restore", "layout", "start", "activate", "hover", "click"), None),
    "appearance": ("Appearance", lambda p, w: AppearancePage(w, p),
                   ("theme", "compact", "monochrome", "icons", "font", "zoom", "hidden", "colour",
                    "color", "dark", "light"), None),
    "files": ("Files & Panes", lambda p, w: FilesPage(w, p),
              ("hidden", "open size limit", "ram", "tmpfs", "memory", "workspace"), None),
    "network": ("Network & Proxy", _network_page,
                ("proxy", "socks", "http", "pac", "bypass", "network"), None),
    "llm": ("LLM Profiles", _llm_page, ("llm", "model", "endpoint", "api key", "ollama"), None),
    "agent": ("Agent", _agent_page,
              ("agent", "sandbox", "mcp", "access", "sessions", "bypass", "prompt",
               "system prompt", "user prompt"), _agent_sub_pages),
    "audio": ("Audio", _audio_page, _audio_keywords(), None),
    "metadata": ("Metadata", _metadata_page, ("metadata", "exif", "remove", "clean"), None),
    "search": ("Search", lambda p, w: SearchPage(w, p),
               ("search", "network hosts", "smb", "parallel", "index"), None),
    "security": ("Security", lambda p, w: SecurityPage(w, p),
                 ("paranoid", "security", "sudo", "password"), None),
    "extensions": ("Extensions", _extensions_page, ("extensions", "plugins"), None),
}

#: Called after a page saved: id -> window method name.
_AFTER_SAVE = {
    "network": "refresh_proxy_indicators",
    "llm": "refresh_llm_profiles",
}


# ---------------------------------------------------------------------------
# The dialog
# ---------------------------------------------------------------------------

_ID_ROLE = Qt.ItemDataRole.UserRole
_SUB_ROLE = Qt.ItemDataRole.UserRole + 1


def _searchable_texts(widget: QWidget) -> list[str]:
    """Every setting name a page shows: labels, check boxes, radio buttons,
    group titles, tab titles and combo box entries."""
    texts = []
    for child in widget.findChildren(QLabel):
        texts.append(child.text())
    for child in widget.findChildren(QAbstractButton):
        texts.append(child.text())
        texts.append(child.toolTip())
    for child in widget.findChildren(QGroupBox):
        texts.append(child.title())
    for child in widget.findChildren(QTabWidget):
        texts.extend(child.tabText(i) for i in range(child.count()))
    for child in widget.findChildren(QComboBox):
        texts.extend(child.itemText(i) for i in range(child.count()))
    return [t.replace("&", "").lower() for t in texts if t]


class SettingsDialog(QDialog):
    """Edit > Settings…: the categories, their pages, OK / Apply / Cancel."""

    def __init__(self, parent: QWidget | None = None, *, window) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Settings"))
        self.resize(980, 660)
        self._window = window
        self._pages: dict[str, QWidget] = {}
        self._titles: dict[str, str] = {}
        self._terms: dict[str, list[str]] = {}
        self._items: dict[str, QTreeWidgetItem] = {}
        self._scrolls: dict[str, QScrollArea] = {}

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(tr("Find a setting"))
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(True)
        self.no_match_label = QLabel(tr("No setting matches."))
        self.no_match_label.setProperty("role", "muted")
        self.no_match_label.hide()
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(self.filter_edit)
        left_layout.addWidget(self.tree, 1)
        left_layout.addWidget(self.no_match_label)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-weight: bold; font-size: 14pt;")
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setObjectName("axSettingsError")
        self.error_label.setStyleSheet("color: #c0392b; font-weight: bold;")
        self.error_label.setTextFormat(Qt.TextFormat.PlainText)
        self.error_label.hide()
        self.stack = QStackedWidget()
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self.title_label)
        right_layout.addWidget(self.error_label)
        right_layout.addWidget(self.stack, 1)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([220, 760])

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Apply
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply)

        layout = QVBoxLayout(self)
        layout.addWidget(splitter, 1)
        layout.addWidget(self.buttons)

        self._build_pages()
        self.tree.currentItemChanged.connect(self._on_item_changed)
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        add_close_corner(self)

    # -- pages -------------------------------------------------------------
    def _categories(self) -> list[tuple[str, str, Callable, tuple, tuple]]:
        """(id, title, factory, keywords, sub pages) in list order."""
        out = []
        for page_id in CATEGORY_ORDER:
            if page_id in _BUILTIN:
                title, factory, keywords, subs = _BUILTIN[page_id]
                out.append((page_id, tr(title), factory, keywords, subs() if subs else ()))
            elif page_id in _REGISTERED:
                reg = _REGISTERED[page_id]
                out.append((page_id, reg.title, reg.factory, reg.keywords, reg.sub_pages))
        for page_id, reg in _REGISTERED.items():
            if page_id not in CATEGORY_ORDER:
                out.append((page_id, reg.title, reg.factory, reg.keywords, reg.sub_pages))
        return out

    def _build_pages(self) -> None:
        for page_id, title, factory, keywords, subs in self._categories():
            try:
                page = factory(None, self._window)
            except Exception:  # noqa: BLE001 - one broken page must not cost the others
                log.exception("Settings page %s could not be built", page_id)
                page = QLabel(tr("This page could not be opened; see the log."))
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            scroll.setWidget(page)
            self.stack.addWidget(scroll)
            self._pages[page_id] = page
            self._scrolls[page_id] = scroll
            self._titles[page_id] = title
            self._terms[page_id] = (
                [title.lower()] + [k.lower() for k in keywords] + _searchable_texts(page)
            )
            item = QTreeWidgetItem([title])
            item.setData(0, _ID_ROLE, page_id)
            self.tree.addTopLevelItem(item)
            self._items[page_id] = item
            for sub_id, sub_title in subs:
                child = QTreeWidgetItem([tr(sub_title)])
                child.setData(0, _ID_ROLE, page_id)
                child.setData(0, _SUB_ROLE, sub_id)
                item.addChild(child)
            if subs and isinstance(getattr(page, "tabs", None), QTabWidget):
                page.tabs.currentChanged.connect(
                    lambda index, pid=page_id: self._follow_tab(pid, index)
                )
        self.tree.expandAll()
        security = self._pages.get("security")
        if isinstance(security, SecurityPage) and "extensions" in self._pages:
            security.paranoid_check.toggled.connect(self._preview_paranoid)

    def page(self, page_id: str) -> QWidget:
        return self._pages[page_id]

    def page_ids(self) -> list[str]:
        return list(self._pages)

    def current_page_id(self) -> str:
        item = self.tree.currentItem()
        return item.data(0, _ID_ROLE) if item is not None else ""

    def show_page(self, page_id: str, sub: str | None = None) -> None:
        """Select the category *page_id* (and its sub-page *sub*)."""
        item = self._items.get(page_id)
        if item is None:
            raise KeyError(f"no settings page {page_id!r}")
        if sub is not None:
            for i in range(item.childCount()):
                if item.child(i).data(0, _SUB_ROLE) == sub:
                    item = item.child(i)
                    break
        self.tree.setCurrentItem(item)

    def show_page_titled(self, title: str) -> bool:
        """Select the first category whose list title is *title* (in English
        or in the interface language). False, and the selection unchanged,
        when no category has that title."""
        if not title:
            return False
        wanted = {title, tr(title)}
        for page_id, page_title in self._titles.items():
            if page_title in wanted:
                self.show_page(page_id)
                return True
        return False

    def _on_item_changed(self, item, _previous=None) -> None:
        if item is None:
            return
        page_id = item.data(0, _ID_ROLE)
        page = self._pages[page_id]
        self.stack.setCurrentWidget(self._scrolls[page_id])
        self.title_label.setText(self._titles[page_id])
        sub = item.data(0, _SUB_ROLE)
        if sub and hasattr(page, "show_tab"):
            page.show_tab(sub)
        if page_id == "agent":
            self._offer_llm_profiles()

    def _follow_tab(self, page_id: str, index: int) -> None:
        """The agent page's own tabs keep the list's selection in step."""
        parent = self._items[page_id]
        if 0 <= index < parent.childCount() and self.current_page_id() == page_id:
            self.tree.blockSignals(True)
            self.tree.setCurrentItem(parent.child(index))
            self.tree.blockSignals(False)

    def _offer_llm_profiles(self) -> None:
        """Profiles added or renamed on the LLM page, not yet saved, can be
        chosen for new agent tabs already."""
        llm, agent = self._pages.get("llm"), self._pages.get("agent")
        if hasattr(llm, "profile_names") and hasattr(agent, "refresh_llm_choices"):
            agent.refresh_llm_choices(llm.profile_names())

    def _preview_paranoid(self, on: bool) -> None:
        """The Extensions page says what the Security page's switch will do."""
        page = self._pages["extensions"]
        blocked = getattr(page, "_blocked", None)
        if blocked is not None:
            from core.extensions import extensions_allowed

            blocked.setVisible(on or not extensions_allowed())

    # -- filter ------------------------------------------------------------
    def apply_filter(self, text: str) -> None:
        """Show only the categories with a setting whose name contains
        *text* (case-insensitive); the first of them is selected when the
        selected one is hidden."""
        needle = text.strip().lower()
        first = None
        for page_id, item in self._items.items():
            match = not needle or any(needle in term for term in self._terms[page_id])
            item.setHidden(not match)
            if match and first is None:
                first = item
        self.no_match_label.setVisible(first is None)
        current = self.tree.currentItem()
        top = (current.parent() or current) if current is not None else None
        if first is not None and (top is None or top.isHidden()):
            self.tree.setCurrentItem(first)

    def visible_page_ids(self) -> list[str]:
        return [pid for pid, item in self._items.items() if not item.isHidden()]

    # -- OK / Apply / Cancel --------------------------------------------------
    def dirty_page_ids(self) -> list[str]:
        return [pid for pid, page in self._pages.items() if _page_dirty(page)]

    def apply(self) -> bool:
        """Check, then save every changed page (the rule in the module
        docstring). True when everything changed is saved."""
        self.error_label.hide()
        dirty = self.dirty_page_ids()
        for page_id in dirty:
            problems = _page_problems(self._pages[page_id])
            if problems:
                self._show_error(page_id, problems)
                return False
        for page_id in dirty:
            page = self._pages[page_id]
            try:
                ok = _page_save(page)
            except (OSError, ValueError) as exc:
                log.warning("Settings page %s not saved: %s", page_id, exc)
                self._show_error(page_id, [str(exc)])
                return False
            if not ok:
                self.show_page(page_id)
                return False
            after = _AFTER_SAVE.get(page_id)
            if after and hasattr(self._window, after):
                getattr(self._window, after)()
        return True

    def _show_error(self, page_id: str, problems: list[str]) -> None:
        self.show_page(page_id)
        self.error_label.setText(
            tr("Not saved - {page}:").format(page=self._titles[page_id]) + "\n"
            + "\n".join(problems)
        )
        self.error_label.show()

    def error_text(self) -> str:
        return self.error_label.text() if not self.error_label.isHidden() else ""

    def accept(self) -> None:
        if self.apply():
            super().accept()

    def done(self, result: int) -> None:  # noqa: D102 - Qt override
        for page in self._pages.values():
            shutdown = getattr(page, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except Exception:  # noqa: BLE001 - closing must not fail
                    log.warning("Settings page shutdown failed", exc_info=True)
        super().done(result)


def _page_dirty(page) -> bool:
    check = getattr(page, "is_dirty", None)
    if not callable(check):
        return False  # a page without the protocol stores nothing here
    return bool(check())


def _page_problems(page) -> list[str]:
    check = getattr(page, "problems", None)
    return list(check()) if callable(check) else []


def _page_save(page) -> bool:
    save = getattr(page, "save", None)
    if not callable(save):
        return True
    result = save()
    return True if result is None else bool(result)


__all__ = [
    "CATEGORY_ORDER",
    "AppearancePage",
    "FilesPage",
    "GeneralPage",
    "SearchPage",
    "SecurityPage",
    "SettingsDialog",
    "register_page",
    "unregister_page",
]
