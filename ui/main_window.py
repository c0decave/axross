from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QByteArray, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QKeySequence, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QTabBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from core.bookmarks import Bookmark, BookmarkManager
from core.connection_manager import ConnectionManager
from core import i18n
from core.i18n import tr
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile, ProfileManager
from core.transfer_manager import TransferManager
from core.transfer_worker import TransferDirection
from ui import themes
from ui.bookmark_edit_dialog import BookmarkEditDialog
from ui.close_corner import add_close_corner
from ui.disconnected_pane import KIND_PANE, KIND_TERMINAL, DisconnectedPanePlaceholder
from ui.file_pane import FilePaneWidget
from ui.layout_utils import (
    equal_split_sizes,
    sanitize_splitter_sizes,
    splitter_axis_for_zone,
)
from ui.log_dock import LogDock
from ui.terminal_pane import TerminalPaneWidget
from ui.terminal_widget import TerminalDock
from ui.themes import (  # noqa: F401  (theme constants stay importable from here)
    AMBER_THEME,
    COMPACT_CSS,
    DARK_THEME,
    HACKER_THEME,
)
from ui.transfer_dock import TransferDock

if TYPE_CHECKING:
    from core.ssh_client import UnknownHostKeyError

log = logging.getLogger(__name__)


def _is_ssh_session(backend) -> bool:
    """``isinstance(backend, SSHSession)`` without importing paramiko at
    start-up (~0.13 s): until core.ssh_client is loaded no SSH session can
    exist."""
    mod = sys.modules.get("core.ssh_client")
    return mod is not None and isinstance(backend, mod.SSHSession)


RECONNECT_INTERVAL_MS = 30_000  # 30 seconds
MAX_UI_STATE_BYTES = 1024 * 1024
MAX_PROFILE_IMPORT_BYTES = 8 * 1024 * 1024


def _read_json_file(path: Path | str, *, max_bytes: int = MAX_UI_STATE_BYTES):
    """Parsed JSON of ``path``. Raises OSError (unreadable, too large) or
    ValueError (not UTF-8: UnicodeDecodeError, not JSON: JSONDecodeError);
    callers catch both."""
    target = Path(path)
    if target.stat().st_size > max_bytes:
        raise OSError(f"{target} exceeds {max_bytes} bytes")
    return json.loads(target.read_bytes().decode("utf-8"))


#: Real layouts are a few splitters deep; the rebuild recurses per level.
MAX_SESSION_DEPTH = 32
#: Splitters plus panes. Real layouts hold a dozen; every terminal entry
#: starts a shell, so a hostile file must not ask for thousands.
MAX_SESSION_NODES = 128
MAX_RESTORED_WINDOW_PX = 100_000
#: Base64 of QMainWindow.saveGeometry / saveState: a few hundred bytes.
MAX_SAVED_WINDOW_STATE_CHARS = 64 * 1024
#: window key of the File > "Restore Layout on Start" switch (default on).
RESTORE_ON_START_KEY = "restore_layout_on_start"
_SESSION_NODE_TYPES = ("splitter", "pane", "terminal")


def _session_problem(data) -> str:
    """Why a saved session cannot be restored, or "" when it can.

    Checks the whole shape ``_restore_session`` relies on, so a bad file is
    refused before the open panes are closed instead of half-way through.
    """
    if not isinstance(data, dict):
        return "The file does not hold a JSON object."
    if not isinstance(data.get("window", {}), dict):
        return "The window settings are not an object."
    stack = [(data.get("splitter", {}), 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_SESSION_NODES:
            return f"The layout holds more than {MAX_SESSION_NODES} entries."
        if not isinstance(node, dict):
            return "A layout entry is not an object."
        if depth > MAX_SESSION_DEPTH:
            return f"The layout is nested deeper than {MAX_SESSION_DEPTH} levels."
        kind = node.get("type", "splitter")
        if kind not in _SESSION_NODE_TYPES:
            return f"A layout entry has an unknown type: {str(kind)[:40]!r}."
        if kind in ("pane", "terminal"):
            if not isinstance(node.get("path", "/"), str):
                return "A pane path is not text."
            if not isinstance(node.get("cwd", ""), (str, type(None))):
                return "A terminal folder is not text."
            if not isinstance(node.get("profile", ""), (str, type(None))):
                return "A pane profile name is not text."
            continue
        children = node.get("children", [])
        if not isinstance(children, list):
            return "A splitter's children are not a list."
        stack.extend((child, depth + 1) for child in children)
    return ""


def _decode_window_state(value) -> bytes | None:
    """The bytes of a saved window geometry / dock state, or None when the
    entry is missing, too large or not base64."""
    if not isinstance(value, str) or not value or len(value) > MAX_SAVED_WINDOW_STATE_CHARS:
        return None
    import base64
    import binascii

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error):
        return None


def _defer_while_alive(widgets, fn) -> None:
    """Run *fn* on the next event-loop pass unless one of *widgets* was
    deleted meanwhile. PyQt6's singleShot has no context-object form, and a
    closure on a deleted splitter raised RuntimeError from inside Qt, which
    aborts the process (seen when a window was deleted right after a split)."""
    from PyQt6 import sip

    def run() -> None:
        if any(sip.isdeleted(w) for w in widgets):
            return
        fn()

    QTimer.singleShot(0, run)


def _write_private_text(path: Path | str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        log.debug("Could not set permissions on %s", target.parent, exc_info=True)
    fd, temp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
        os.replace(temp_name, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


class MainWindow(QMainWindow):
    """Main application window with file panes."""

    #: (job_id, ok, detail) — emitted from a scheduler worker thread so
    #: the store write and the status bar happen on the GUI thread.
    _scheduler_done = pyqtSignal(str, bool, str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Axross")
        self.resize(1200, 700)

        self._panes: list[FilePaneWidget] = []
        self._terminal_panes: list[TerminalPaneWidget] = []
        # Remote panes of a restored layout, waiting for Reconnect.
        self._pane_placeholders: list[DisconnectedPanePlaceholder] = []
        self._pane_profiles: dict[FilePaneWidget, ConnectionProfile] = {}
        self._pane_passwords: dict[FilePaneWidget, str] = {}
        self._pane_key_passphrases: dict[FilePaneWidget, str] = {}
        self._active_pane: FilePaneWidget | None = None
        self._target_pane: FilePaneWidget | None = None
        self._profile_manager = ProfileManager()
        self._connection_manager = ConnectionManager()
        self._connection_manager.set_profile_resolver(self._profile_manager.get)
        self._transfer_manager = TransferManager(self)
        self._bookmark_manager = BookmarkManager()
        # In-flight async connect handles; we pin them here so Qt
        # doesn't tear the worker threads down mid-run. Older tasks
        # drain off this list once their threads have actually exited.
        self._connect_tasks: list = []
        # Open Compare windows with the two panes each was built on.
        self._compare_dialogs: list = []

        self._current_theme = themes.DEFAULT_THEME
        self._compact_mode = False
        self._recent_profiles: list[str] = (
            self._load_recents()
        )  # Last connected profile names (max 8)

        # Lazily-created, reused single archive-preview dock (Task A4).
        # Content is transient per archive; the dock itself is created
        # on first preview and re-targeted thereafter.
        self._archive_dock = None
        # Temp dirs created for single-member previews; cleaned on close.
        self._archive_member_tempdirs: list[str] = []
        # The most-recent single-member temp dir. Since the member viewer
        # opens one file at a time, the previous one is reaped on the NEXT
        # open (never immediately, in case a viewer still holds the file).
        self._archive_last_member_tempdir: str | None = None

        self._setup_menubar()
        self._setup_toolbar()
        self._setup_menu_mirrors()
        self._setup_central()
        self._setup_transfer_dock()
        self._setup_terminal_dock()
        self._setup_log_dock()
        self._setup_console_dock()
        self._setup_scripts_dock()
        self._setup_bookmark_sidebar()
        self._setup_analysis_dock()
        self._setup_status_bar()
        # Arm the recurring-job tick. Failure here must never stop the
        # window from opening — a broken schedule file should cost the
        # user their schedule, not their file manager.
        try:
            self._start_scheduler()
        except Exception as exc:  # noqa: BLE001
            log.warning("scheduler: not started: %s", exc)
        self._apply_theme(self._current_theme)
        # "Modern (follow system)" must follow the desktop live.
        try:
            from PyQt6.QtGui import QGuiApplication

            hints = QGuiApplication.styleHints()
            if hints is not None:
                hints.colorSchemeChanged.connect(self._on_system_scheme_changed)
        except (AttributeError, ImportError):  # Qt < 6.5: no signal
            pass
        # Persistent visual settings (theme, monochrome icons, the
        # "Restore Layout on Start" switch) from session.json. The pane
        # layout itself is rebuilt by restore_layout_on_start, which
        # main.py calls after construction - and which never connects.
        self._load_persistent_visual_settings()

        # Show hidden files by default
        self._hidden_action.setChecked(True)

        # Auto-reconnect timer
        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setInterval(RECONNECT_INTERVAL_MS)
        self._reconnect_timer.timeout.connect(self._check_connections)
        self._reconnect_timer.start()

        # Track which panes received transfers for auto-refresh
        self._transfer_target_panes: set[FilePaneWidget] = set()
        # Destination checks of F5 / F6 / drops still running (ScanJob).
        self._conflict_checks: set = set()
        self._transfer_manager.job_finished.connect(self._on_transfer_finished)
        self._transfer_manager.all_finished.connect(self._on_all_transfers_finished)

        # Extensions: only the switched-on ones are loaded, and none in the
        # paranoid security mode (core.extensions).
        from ui.extension_host import ExtensionHost

        self.extension_host = ExtensionHost(self, self.extensions_menu)
        self.extension_host.load_enabled()

        # Debounce timer for post-transfer refresh
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(500)
        self._refresh_timer.timeout.connect(self._do_debounced_refresh)

    def _setup_menubar(self) -> None:
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu(tr("&File"))

        quick_connect_action = file_menu.addAction(tr("&Quick Connect..."))
        quick_connect_action.setShortcut(QKeySequence("Ctrl+N"))
        quick_connect_action.triggered.connect(self._show_quick_connect)

        connect_action = file_menu.addAction(tr("Connection &Manager..."))
        connect_action.setShortcut(QKeySequence("Ctrl+Shift+N"))
        connect_action.triggered.connect(self._on_connect)

        ssh_menu = file_menu.addMenu(tr("Import SSH &Config"))
        ssh_default_action = ssh_menu.addAction(tr("From ~/.ssh/config"))
        ssh_default_action.triggered.connect(self._import_ssh_config)
        ssh_file_action = ssh_menu.addAction(tr("From File..."))
        ssh_file_action.triggered.connect(self._import_ssh_config_file)
        ssh_paste_action = ssh_menu.addAction(tr("Paste Config Text..."))
        ssh_paste_action.triggered.connect(self._import_ssh_config_paste)

        import_profiles_action = file_menu.addAction(tr("Import &Profiles (JSON)..."))
        import_profiles_action.triggered.connect(self._import_profiles_json)

        export_profiles_action = file_menu.addAction(tr("&Export Profiles (JSON)..."))
        export_profiles_action.triggered.connect(self._export_profiles_json)

        view_profiles_action = file_menu.addAction(tr("&View All Profiles..."))
        view_profiles_action.triggered.connect(self._view_all_profiles)

        file_menu.addSeparator()

        restore_action = file_menu.addAction(tr("&Restore Last Session"))
        restore_action.setShortcut(QKeySequence("Ctrl+Shift+R"))
        restore_action.triggered.connect(self._restore_session)

        # On by default; persisted in session.json window.restore_layout_on_start.
        # ``triggered`` (the user's click), not ``toggled``: loading the
        # stored value must not write the file back.
        self._restore_on_start_action = file_menu.addAction(tr("Restore &Layout on Start"))
        self._restore_on_start_action.setCheckable(True)
        self._restore_on_start_action.setChecked(True)
        self._restore_on_start_action.setToolTip(
            "Open the panes, terminals and docks of the last session on start. "
            "Remote panes come back disconnected, with a Reconnect button."
        )
        self._restore_on_start_action.triggered.connect(self._set_restore_on_start)

        file_menu.addSeparator()

        recheck_keyring_action = file_menu.addAction(tr("Re-&detect System Keyring"))
        recheck_keyring_action.setToolTip(
            "Force a fresh check for SecretService / KWallet / "
            "KeePassXC. Useful after starting a keyring daemon while "
            "axross is already running."
        )
        recheck_keyring_action.triggered.connect(self._recheck_keyring)

        file_menu.addSeparator()

        quit_action = file_menu.addAction(tr("&Quit"))
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)

        # Edit menu. Order matters: File, Edit, View, ... is what every
        # desktop toolkit has done for thirty years, and a menu bar that
        # opens with Edit reads as broken before a single item is read.
        edit_menu = menubar.addMenu(tr("&Edit"))
        undo_action = edit_menu.addAction(tr("&Undo Last Operation"))
        undo_action.setShortcut(QKeySequence("Ctrl+Z"))
        undo_action.setToolTip(tr("Reverse the most recent move or trash"))
        undo_action.triggered.connect(self._undo_last_operation)

        # View menu
        view_menu = menubar.addMenu(tr("&View"))

        self._hidden_action = view_menu.addAction(tr("Show &Hidden Files"))
        self._hidden_action.setCheckable(True)
        self._hidden_action.setShortcut(QKeySequence("Ctrl+H"))
        self._hidden_action.toggled.connect(self._toggle_hidden)

        # Per pane: the active pane switches, the check mark follows it.
        self.thumbnail_view_action = view_menu.addAction(tr("&Thumbnail View"))
        self.thumbnail_view_action.setCheckable(True)
        self.thumbnail_view_action.setShortcut(QKeySequence("Ctrl+Shift+G"))
        self.thumbnail_view_action.setToolTip(
            tr("Show the active pane's folder as thumbnails (images, PDFs, videos)")
        )
        self.thumbnail_view_action.triggered.connect(self._toggle_thumbnail_view)

        view_menu.addSeparator()

        add_local_action = view_menu.addAction(tr("Add &Local Pane"))
        add_local_action.triggered.connect(self._add_local_pane)

        # Layout-preset submenu + cycle hotkey. The submenu lists each
        # preset; the hotkey rotates through them in PRESET_ORDER.
        layout_menu = view_menu.addMenu(tr("&Layout Preset"))
        from ui.layout_presets import PRESET_ORDER

        for preset_name in PRESET_ORDER:
            act = layout_menu.addAction(preset_name)
            act.triggered.connect(lambda _checked, n=preset_name: self.apply_layout_preset(n))
        layout_menu.addSeparator()
        cycle_fwd = layout_menu.addAction(tr("Cycle Next"))
        cycle_fwd.setShortcut("Ctrl+Alt+L")
        cycle_fwd.triggered.connect(lambda: self.cycle_layout_preset(forward=True))
        cycle_back = layout_menu.addAction(tr("Cycle Previous"))
        cycle_back.setShortcut("Ctrl+Alt+Shift+L")
        cycle_back.triggered.connect(lambda: self.cycle_layout_preset(forward=False))

        self._build_pane_activation_menu(view_menu.addMenu(tr("Activate &Pane")))

        view_menu.addSeparator()

        # Theme submenu
        theme_menu = view_menu.addMenu(tr("&Theme"))
        for theme_name, theme_label in themes.THEME_CHOICES:
            if theme_name == "classic":
                theme_menu.addSeparator()
            action = theme_menu.addAction(tr(theme_label))
            action.triggered.connect(lambda checked, t=theme_name: self._apply_theme(t))

        self._compact_action = view_menu.addAction(tr("&Compact Mode"))
        self._compact_action.setCheckable(True)
        self._compact_action.setChecked(False)
        self._compact_action.toggled.connect(self._toggle_compact_mode)

        # Monochrome icon toggle. Default: colourful (False). Persisted
        # in session.json; see _save_session / _restore_session.
        self._monochrome_action = view_menu.addAction(tr("&Monochrome Icons"))
        self._monochrome_action.setCheckable(True)
        self._monochrome_action.setChecked(False)
        self._monochrome_action.toggled.connect(self._toggle_monochrome_icons)

        open_limit_action = view_menu.addAction(tr("Open &Size Limit…"))
        open_limit_action.setToolTip("Largest file the text / hex viewers will open")
        open_limit_action.triggered.connect(self._choose_open_limit)

        view_menu.addSeparator()

        zoom_in_action = view_menu.addAction(tr("Zoom &In"))
        zoom_in_action.setShortcut(QKeySequence("Ctrl+="))
        zoom_in_action.triggered.connect(lambda: self._change_font_size(1))

        zoom_out_action = view_menu.addAction(tr("Zoom &Out"))
        zoom_out_action.setShortcut(QKeySequence("Ctrl+-"))
        zoom_out_action.triggered.connect(lambda: self._change_font_size(-1))

        zoom_reset_action = view_menu.addAction(tr("Zoom &Reset"))
        zoom_reset_action.setShortcut(QKeySequence("Ctrl+0"))
        zoom_reset_action.triggered.connect(lambda: self._set_font_size(10))

        view_menu.addSeparator()

        self._dock_view_menu = view_menu.addMenu(tr("&Panels"))

        view_menu.addSeparator()

        find_action = view_menu.addAction(tr("&Find in Index…"))
        self._find_index_action = find_action
        find_action.setShortcut(QKeySequence("Ctrl+Shift+F"))
        find_action.triggered.connect(self._open_metadata_search)

        self._view_media_action = view_menu.addAction(tr("View &Media…"))
        self._view_media_action.setToolTip(
            "Images, PDFs and videos of the active pane's folder as overview or slideshow"
        )
        self._view_media_action.triggered.connect(lambda: self._view_media(selected_only=False))

        self._view_selected_media_action = view_menu.addAction(tr("View Selec&ted Media…"))
        self._view_selected_media_action.setToolTip(
            "Images, PDFs and videos among the active pane's selection"
        )
        self._view_selected_media_action.triggered.connect(
            lambda: self._view_media(selected_only=True)
        )

        cas_action = view_menu.addAction(tr("&Duplicate Finder…"))
        cas_action.setShortcut(QKeySequence("Ctrl+Shift+D"))
        cas_action.triggered.connect(self._open_cas_duplicates)

        cas_history_action = view_menu.addAction(tr("Duplicate Index && &History…"))
        cas_history_action.setToolTip("Every scan of the duplicate index; remove or clear it")
        cas_history_action.triggered.connect(self._open_cas_history)

        disk_action = view_menu.addAction(tr("Dis&k Usage…"))
        self._disk_usage_action = disk_action
        disk_action.setToolTip("Capacity of every open connection")
        disk_action.triggered.connect(self._open_disk_usage)

        compare_action = view_menu.addAction(tr("Co&mpare Panes…"))
        self._compare_action = compare_action
        compare_action.setToolTip("Diff the active pane's tree against the target pane's")
        compare_action.triggered.connect(self._open_compare_panes)

        sched_action = view_menu.addAction(tr("Scheduled &Jobs…"))
        sched_action.setToolTip("Run scripts on a recurring schedule")
        sched_action.triggered.connect(self._open_scheduler)

        view_menu.addSeparator()

        # Bookmarks submenu
        lang_menu = view_menu.addMenu(tr("&Language"))
        self._build_language_menu(lang_menu)

        self._bookmarks_menu = view_menu.addMenu(tr("&Bookmarks"))
        self._rebuild_bookmarks_menu()

        # Pane menu
        pane_menu = menubar.addMenu(tr("&Pane"))

        split_h_action = pane_menu.addAction(tr("Split &Horizontal"))
        split_h_action.setShortcut(QKeySequence("Ctrl+Shift+H"))
        split_h_action.triggered.connect(lambda: self._split_pane(Qt.Orientation.Horizontal))

        split_v_action = pane_menu.addAction(tr("Split &Vertical"))
        split_v_action.setShortcut(QKeySequence("Ctrl+Shift+V"))
        split_v_action.triggered.connect(lambda: self._split_pane(Qt.Orientation.Vertical))

        close_pane_action = pane_menu.addAction(tr("&Close Pane"))
        close_pane_action.setShortcut(QKeySequence("Ctrl+W"))
        close_pane_action.triggered.connect(self._close_active_pane)

        pane_menu.addSeparator()

        toggle_orient_action = pane_menu.addAction(tr("Toggle &Layout (H/V)"))
        toggle_orient_action.setShortcut(QKeySequence("Ctrl+Shift+L"))
        toggle_orient_action.triggered.connect(self._toggle_splitter_orientation)
        self._toggle_orient_action = toggle_orient_action  # the toolbar shows it too

        equalize_action = pane_menu.addAction(tr("&Equalize Pane Sizes"))
        equalize_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        equalize_action.triggered.connect(self._equalize_pane_sizes)
        self._equalize_action = equalize_action

        pane_menu.addSeparator()

        move_left_action = pane_menu.addAction(tr("Move Pane &Left"))
        move_left_action.setShortcut(QKeySequence("Ctrl+Shift+Left"))
        move_left_action.triggered.connect(lambda: self._move_pane(-1))

        move_right_action = pane_menu.addAction(tr("Move Pane &Right"))
        move_right_action.setShortcut(QKeySequence("Ctrl+Shift+Right"))
        move_right_action.triggered.connect(lambda: self._move_pane(1))

        extract_action = pane_menu.addAction(tr("E&xtract Pane to Root"))
        extract_action.setShortcut(QKeySequence("Ctrl+Shift+X"))
        extract_action.triggered.connect(self._extract_pane_from_split)
        self._extract_pane_action = extract_action

        pane_menu.addSeparator()

        next_pane_action = pane_menu.addAction(tr("&Next Pane\tTab"))
        next_pane_action.triggered.connect(self._cycle_next_pane)

        prev_pane_action = pane_menu.addAction(tr("&Previous Pane\tShift+Tab"))
        prev_pane_action.triggered.connect(self._cycle_prev_pane)

        # Tools menu
        tools_menu = menubar.addMenu(tr("&Tools"))
        diag_action = tools_menu.addAction(tr("Run Active Pane &Diagnostics…"))
        diag_action.triggered.connect(self._run_active_pane_diagnostics)
        recovery_action = tools_menu.addAction(tr("&Recovery Scan…"))
        recovery_action.triggered.connect(self._run_recovery_scan)
        network_action = tools_menu.addAction(tr("&Network && Proxy…"))
        network_action.triggered.connect(self._show_network_proxy)
        llm_action = tools_menu.addAction(tr("&LLM Profiles…"))
        llm_action.triggered.connect(self._show_llm_profiles)
        metadata_settings_action = tools_menu.addAction(tr("&Metadata Settings…"))
        metadata_settings_action.setToolTip(
            "How Remove Metadata writes (in place or a cleaned copy) and whether it asks first"
        )
        metadata_settings_action.triggered.connect(self._show_metadata_settings)
        tools_menu.addSeparator()
        self._paranoid_action = tools_menu.addAction(tr("&Paranoid Security Mode"))
        self._paranoid_action.setCheckable(True)
        from core.security_mode import is_paranoid

        self._paranoid_action.setChecked(is_paranoid())
        self._paranoid_action.triggered.connect(self._toggle_paranoid_mode)

        # Extensions menu: three fixed entries; loaded extensions add theirs
        # below (ui.extension_host).
        self.extensions_menu = menubar.addMenu(tr("E&xtensions"))
        manage_ext_action = self.extensions_menu.addAction(tr("&Manage Extensions…"))
        self._manage_ext_action = manage_ext_action
        manage_ext_action.triggered.connect(self._show_extensions_dialog)
        folder_ext_action = self.extensions_menu.addAction(tr("&Open Extensions Folder"))
        folder_ext_action.triggered.connect(self._open_extensions_folder)
        reload_ext_action = self.extensions_menu.addAction(tr("&Reload Extensions"))
        reload_ext_action.triggered.connect(lambda _checked=False: self.extension_host.reload())

        # Help menu
        help_menu = menubar.addMenu(tr("&Help"))
        shortcuts_action = help_menu.addAction(tr("&Keyboard Shortcuts"))
        shortcuts_action.setShortcut(QKeySequence("F1"))
        shortcuts_action.triggered.connect(self._show_shortcuts)
        guide_action = help_menu.addAction(tr("&Scripting Guide"))
        guide_action.triggered.connect(self._show_scripting_guide)
        about_action = help_menu.addAction(tr("&About axross"))
        about_action.triggered.connect(self._show_about)

    def _setup_toolbar(self) -> None:
        toolbar = self.addToolBar("Main")
        toolbar.setObjectName("axMainToolbar")  # saveState / restoreState key
        toolbar.setMovable(False)

        quick_btn = toolbar.addAction(tr("Quick Connect"))
        quick_btn.setToolTip("Quick connect to recent profiles (Ctrl+N)")
        quick_btn.triggered.connect(self._show_quick_connect)

        manager_btn = toolbar.addAction(tr("Connection Manager"))
        manager_btn.setToolTip("Open connection manager (Ctrl+Shift+N)")
        manager_btn.triggered.connect(self._on_connect)

        shell_btn = toolbar.addAction(tr("Shell"))
        shell_btn.setToolTip("Open inline terminal pane (Ctrl+Shift+T)")
        shell_btn.setShortcut(QKeySequence("Ctrl+Shift+T"))
        shell_btn.triggered.connect(self._open_shell_pane)

        # Same toggle as View > Panels > Bookmark Sidebar. No shortcut of
        # its own: F12 belongs to the dock's toggleViewAction and a second
        # owner would make the key ambiguous.
        self._bookmarks_btn = toolbar.addAction(tr("Bookmarks"))
        self._bookmarks_btn.setToolTip("Show / hide the bookmark sidebar (F12)")
        self._bookmarks_btn.setCheckable(True)
        self._bookmarks_btn.triggered.connect(self._toggle_bookmark_sidebar)

        toolbar.addSeparator()

        split_h_btn = toolbar.addAction(tr("Split Horizontal"))
        split_h_btn.setToolTip("Split pane horizontally (Ctrl+Shift+H)")
        split_h_btn.triggered.connect(lambda: self._split_pane(Qt.Orientation.Horizontal))

        split_v_btn = toolbar.addAction(tr("Split Vertical"))
        split_v_btn.setToolTip("Split pane vertically (Ctrl+Shift+V)")
        split_v_btn.triggered.connect(lambda: self._split_pane(Qt.Orientation.Vertical))

        close_btn = toolbar.addAction(tr("Close Pane"))
        close_btn.setToolTip("Close active pane (Ctrl+W)")
        close_btn.triggered.connect(self._close_active_pane)

        # The Pane menu's own actions: one QAction per command, so a
        # shortcut has one owner and both places stay the same.
        toggle_btn = self._toggle_orient_action
        toolbar.addAction(toggle_btn)
        toggle_btn.setToolTip("Toggle layout horizontal/vertical (Ctrl+Shift+L)")

        eq_btn = self._equalize_action
        toolbar.addAction(eq_btn)
        eq_btn.setToolTip("Equalize pane sizes (Ctrl+Shift+E)")

        extract_btn = self._extract_pane_action
        toolbar.addAction(extract_btn)
        extract_btn.setToolTip("Extract pane from nested split (Ctrl+Shift+X)")

        toolbar.addSeparator()

        copy_btn = toolbar.addAction(tr("Copy to Target"))
        copy_btn.setToolTip("Copy selected files to target pane (F5)")
        copy_btn.setShortcut(QKeySequence("F5"))
        copy_btn.triggered.connect(self._transfer_to_target)

        move_btn = toolbar.addAction(tr("Move to Target"))
        move_btn.setToolTip("Move selected files to target pane (F6)")
        move_btn.setShortcut(QKeySequence("F6"))
        move_btn.triggered.connect(self._move_files)

        refresh_btn = toolbar.addAction(tr("Refresh"))
        # Refresh moved off F2 because the file pane uses F2 for
        # rename (Windows / GNOME Files / KDE Dolphin convention).
        # Ctrl+R is the standard refresh shortcut across most
        # desktop file managers + browsers. The toolbar-button
        # click and the V+iew menu's refresh entry still work for
        # mouse users.
        refresh_btn.setToolTip("Refresh active pane (Ctrl+R)")
        refresh_btn.setShortcut(QKeySequence("Ctrl+R"))
        refresh_btn.triggered.connect(self._refresh_active)

        # The shortcut belongs to View > Duplicate Finder; one owner per key.
        dupes_btn = toolbar.addAction(tr("Duplicate Finder"))
        dupes_btn.setToolTip("Duplicate Finder (Ctrl+Shift+D)")
        dupes_btn.triggered.connect(self._open_cas_duplicates)

        # Icon-only toolbar: drop the inline [Shortcut] text labels,
        # swap in SVG icons. Tooltips still carry the shortcut hint.
        from PyQt6.QtCore import QSize as _QSize

        from ui.icon_provider import icon as _ico

        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        toolbar.setIconSize(_QSize(22, 22))
        for act, icon_name in (
            (quick_btn, "quick-connect"),
            (manager_btn, "connection-manager"),
            (shell_btn, "shell"),
            (self._bookmarks_btn, "bookmark"),
            (split_h_btn, "split-h"),
            (split_v_btn, "split-v"),
            (close_btn, "close-pane"),
            (toggle_btn, "toggle-layout"),
            (eq_btn, "equalize"),
            (extract_btn, "extract-pane"),
            (copy_btn, "copy-right"),
            (move_btn, "move-right"),
            (refresh_btn, "refresh"),
            (dupes_btn, "duplicates"),
        ):
            # Remembered on the action so a theme / monochrome switch can
            # re-icon the bar without matching on translated labels.
            act.setProperty("axIcon", icon_name)
            act.setIcon(_ico(icon_name))
        self._add_feature_buttons(toolbar)
        self._shell_action = shell_btn
        self._copy_target_action = copy_btn
        self._move_target_action = move_btn
        self._refresh_action = refresh_btn

    def _add_feature_buttons(self, toolbar: QToolBar) -> None:
        """Buttons for the newer features, after the existing ones. Where
        a menu entry exists the button IS that QAction (one shortcut
        owner, one check state)."""
        from PyQt6.QtGui import QAction

        from ui.icon_provider import icon as _ico

        self._pack_action = QAction(tr("Pack…"), self)
        self._pack_action.triggered.connect(self._pack_from_toolbar)
        self._metadata_action = QAction(tr("Show Metadata…"), self)
        self._metadata_action.triggered.connect(self._metadata_from_toolbar)
        toolbar.addSeparator()
        for action, icon_name, tip in (
            (self.thumbnail_view_action, "thumbnails", "Thumbnail view for the active pane (Ctrl+Shift+G)"),
            (self._view_media_action, "media-view", "View the images, PDFs and videos of this folder"),
            (self._find_index_action, "find-index", "Find in the offline index (Ctrl+Shift+F)"),
            (self._compare_action, "compare", "Compare the two panes"),
            (self._disk_usage_action, "disk-usage", "Disk usage of this folder"),
            (self._metadata_action, "metadata", "Show the metadata of the selection or this folder"),
            (self._pack_action, "pack", "Pack the selection into an archive"),
            (self._manage_ext_action, "extensions", "Manage extensions"),
        ):
            toolbar.addAction(action)
            action.setToolTip(tip)
            action.setProperty("axIcon", icon_name)
            action.setIcon(_ico(icon_name))

    def _pack_from_toolbar(self, _checked: bool = False) -> None:
        pane = self._active_pane
        if pane is None:
            self.statusBar().showMessage(tr("No file pane is active."), 5000)
            return
        if not pane.selected_items():
            self.statusBar().showMessage(tr("Select the files or folders to pack first."), 5000)
            return
        pane.pack_selection(None)

    def _metadata_from_toolbar(self, _checked: bool = False) -> None:
        pane = self._active_pane
        if pane is None:
            self.statusBar().showMessage(tr("No file pane is active."), 5000)
            return
        pane.open_metadata("show")

    def _setup_menu_mirrors(self) -> None:
        """Put what only the toolbar and the right-click menu offered into
        the menu bar too - the same QAction objects, so each shortcut keeps
        one owner (two actions on one key make Qt fire neither)."""
        menubar = self.menuBar()
        view_menu = next(a.menu() for a in menubar.actions() if a.text() == tr("&View"))
        edit_action = next(a for a in menubar.actions() if a.text() == tr("&Edit"))
        first_view_entry = view_menu.actions()[0]
        view_menu.insertAction(first_view_entry, self._shell_action)
        view_menu.insertAction(first_view_entry, self._bookmarks_btn)
        view_menu.insertSeparator(first_view_entry)

        self.actions_menu = QMenu(tr("&Actions"), self)
        after_edit = menubar.actions()[menubar.actions().index(edit_action) + 1]
        menubar.insertMenu(after_edit, self.actions_menu)
        self._actions_source: QMenu | None = None
        self.actions_menu.aboutToShow.connect(self._fill_actions_menu)
        self._fill_actions_menu()

    def _fill_actions_menu(self) -> None:
        """The active pane's right-click menu, rebuilt each time the menu
        opens (it depends on the selection), below the transfer entries."""
        menu = self.actions_menu
        menu.clear()
        fixed = (
            self._copy_target_action,
            self._move_target_action,
            self._refresh_action,
            self._pack_action,
            self._metadata_action,
        )
        for action in fixed:
            menu.addAction(action)
        menu.addSeparator()
        old = self._actions_source
        if old is not None:
            old.deleteLater()
        self._actions_source = None
        pane = getattr(self, "_active_pane", None)
        if pane is None:
            note = menu.addAction(tr("No file pane is active"))
            note.setEnabled(False)
            return
        try:
            source = pane._build_context_menu()
        except Exception:  # noqa: BLE001 - the menu bar must open regardless
            log.warning("Building the Actions menu failed", exc_info=True)
            return
        source.setParent(self, source.windowFlags())
        self._actions_source = source  # owns the actions while they are shown
        above = {tr("Refresh"), tr("Show Metadata…")}  # the window-wide ones are above
        for action in source.actions():
            if action.text() in above:
                continue
            menu.addAction(action)

    def _toggle_bookmark_sidebar(self, checked: bool) -> None:
        sidebar = getattr(self, "_bookmark_sidebar", None)
        if sidebar is not None:
            sidebar.setVisible(checked)

    def _install_dock_titlebar(self, dock, title: str, icon_name: str) -> None:
        """Swap out Qt's default QDockWidget title bar for our custom
        :class:`DockTitleBar`. The default renders close/float
        buttons as 6-px glyphs on some desktop themes which users
        legitimately can't see. The custom bar always shows them at
        a consistent size using our SVG icon set."""
        from ui.dock_titlebar import DockTitleBar

        dock.setTitleBarWidget(DockTitleBar(title, icon_name, dock))

    def _setup_bookmark_sidebar(self) -> None:
        """Build + install the left-side bookmark panel. Rebuilds
        itself on add / edit / delete; navigation requests flow
        through the existing ``_navigate_bookmark`` router so
        bookmark clicks behave exactly like menu clicks."""
        from ui.bookmark_sidebar import BookmarkSidebar

        self._bookmark_sidebar = BookmarkSidebar(
            self._bookmark_manager,
            self,
        )
        self._install_dock_titlebar(
            self._bookmark_sidebar,
            "Bookmarks",
            "bookmark",
        )
        self._bookmark_sidebar.navigate_requested.connect(
            self._navigate_bookmark,
        )
        # Edits made in the sidebar (reorder, groups, colours) refresh the menu.
        self._bookmark_sidebar.changed.connect(self._populate_bookmarks_menu)
        # Pane drags dropped on the sidebar: new bookmarks, or a transfer
        # into the bookmarked folder.
        self._bookmark_sidebar.bookmark_drop_requested.connect(self._on_bookmark_drop)
        self._bookmark_sidebar.transfer_drop_requested.connect(self._on_bookmark_transfer_drop)
        # Keep the toolbar button's checked state in step with the dock,
        # however it was toggled (F12, menu, the dock's own X).
        self._bookmark_sidebar.visibilityChanged.connect(self._bookmarks_btn.setChecked)
        self.addDockWidget(
            Qt.DockWidgetArea.LeftDockWidgetArea,
            self._bookmark_sidebar,
        )
        # The sidebar arrives AFTER _setup_log_dock first populated
        # the Panels menu — re-populate so the sidebar's toggle
        # entry (with its F12 shortcut) shows up alongside the
        # Transfer / Terminal / Log dock toggles.
        self._populate_dock_view_menu()

    def _setup_transfer_dock(self) -> None:
        self._transfer_dock = TransferDock(self._transfer_manager, self)
        # saveState / restoreState find a dock by its object name.
        self._transfer_dock.setObjectName("axTransferDock")
        self._install_dock_titlebar(
            self._transfer_dock,
            "Transfers",
            "download",
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._transfer_dock)

    def _setup_terminal_dock(self) -> None:
        self._terminal_dock = TerminalDock(self)
        self._terminal_dock.setObjectName("axTerminalDock")
        self._install_dock_titlebar(
            self._terminal_dock,
            "Terminal",
            "terminal",
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._terminal_dock)
        self.tabifyDockWidget(self._transfer_dock, self._terminal_dock)
        self._transfer_dock.raise_()  # Show transfer dock by default

    def _setup_log_dock(self) -> None:
        self._log_dock = LogDock(self)
        self._log_dock.setObjectName("axLogDock")
        self._install_dock_titlebar(
            self._log_dock,
            "Log",
            "inbox",
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._log_dock)
        self.tabifyDockWidget(self._terminal_dock, self._log_dock)
        self._transfer_dock.raise_()  # Keep transfer dock visible by default

    def _setup_console_dock(self) -> None:
        from ui.repl_widget import ConsoleDock

        self._console_dock = ConsoleDock(self)
        self._console_dock.setObjectName("axConsoleDock")
        self._install_dock_titlebar(
            self._console_dock,
            "Console",
            "code",
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._console_dock)
        self.tabifyDockWidget(self._log_dock, self._console_dock)
        self._transfer_dock.raise_()
        self._populate_dock_view_menu()
        self._wire_dock_activity_indicators()

    def _setup_scripts_dock(self) -> None:
        """Saved scripts: edit, run in a child process, manage. Tabbed
        next to the Console, which runs a script in the live namespace."""
        from ui.scripts_dock import ScriptsDock

        self._scripts_dock = ScriptsDock(self, scheduled_jobs=self._scheduled_script_jobs)
        self._install_dock_titlebar(self._scripts_dock, tr("Scripts"), "edit")
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._scripts_dock)
        self.tabifyDockWidget(self._console_dock, self._scripts_dock)
        self._transfer_dock.raise_()
        self._scripts_dock.run_in_console_requested.connect(self._run_script_in_console)
        self._watch_dock_activity(self._scripts_dock)
        self._populate_dock_view_menu()

    def _scheduled_script_jobs(self) -> dict[str, list[str]]:
        """Script name -> names of the scheduled jobs that run it."""
        by_script: dict[str, list[str]] = {}
        for job in self._job_store().load():
            if job.kind == "script":
                by_script.setdefault(job.target, []).append(job.name)
        return by_script

    def _run_script_in_console(self, name: str) -> None:
        """Scripts dock > Run in Console: the REPL runs it in its live namespace."""
        self._console_dock.show()
        self._console_dock.raise_()
        self._console_dock.repl.run_saved_script(name)

    def _show_scripting_guide(self) -> None:
        """Help > Scripting Guide: one non-modal window, raised when open."""
        from ui.scripting_guide import ScriptingGuideDialog

        dialog = getattr(self, "_scripting_guide", None)
        if dialog is None:
            dialog = ScriptingGuideDialog(self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda *_: setattr(self, "_scripting_guide", None))
            self._scripting_guide = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    # ------------------------------------------------------------------
    # Analysis dock: sift's explanation of the selected file
    def _setup_analysis_dock(self) -> None:
        from ui.analysis_dock import AnalysisDock

        self._analysis_dock = AnalysisDock(self)
        self._install_dock_titlebar(self._analysis_dock, "Analysis", "bot")
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._analysis_dock)
        self._analysis_dock.hide()
        # Debounced: arrowing through a listing analyses where it stops.
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setSingleShot(True)
        self._analysis_timer.setInterval(200)
        self._analysis_timer.timeout.connect(self._analyse_selection)
        self._analysis_dock.visibilityChanged.connect(self._on_analysis_visibility)
        self._analysis_dock.settings_requested.connect(self._show_llm_profiles)
        self._populate_dock_view_menu()

    def _show_llm_profiles(self) -> None:
        from ui.llm_settings_dialog import LLMSettingsDialog

        dialog = LLMSettingsDialog(self)
        try:
            dialog.exec()
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed
        dock = getattr(self, "_analysis_dock", None)
        if dock is not None:
            dock.refresh_profiles()

    def _on_analysis_visibility(self, visible: bool) -> None:
        if visible:
            self._analysis_dock.refresh_profiles()
            self._schedule_analysis()
        else:
            self._analysis_timer.stop()

    def _on_pane_selection_changed(self, pane: FilePaneWidget) -> None:
        if pane is self._active_pane:
            self._schedule_analysis()

    def _schedule_analysis(self) -> None:
        dock = getattr(self, "_analysis_dock", None)
        if dock is None or not dock.isVisible():
            return  # nothing is analysed while nobody looks
        self._analysis_timer.start()

    def _analyse_selection(self) -> None:
        dock = getattr(self, "_analysis_dock", None)
        pane = self._active_pane
        if dock is None or pane is None or not dock.isVisible():
            return
        items = pane.selected_file_items()
        paths = pane.selected_items()
        if not items:
            dock.show_message(tr("Select a file to see what it is."))
            return
        if len(items) != len(paths):
            dock.show_message(tr("Select a single file to see its analysis."))
            return
        if len(items) > 1:
            targets = [
                self._analysis_target(pane, i, p)
                for i, p in zip(items, paths)
                if not i.is_dir and not i.is_link
            ]
            if targets:
                dock.offer_batch(targets, tr("{n} files selected").format(n=len(targets)))
            else:
                dock.show_message(tr("Select a single file to see its analysis."))
            return
        item = items[0]
        if item.is_dir:
            dock.offer_folder(pane.backend, paths[0], item.name)
            return
        dock.analyse(self._analysis_target(pane, item, paths[0]))

    @staticmethod
    def _analysis_target(pane: FilePaneWidget, item, path: str):
        from core.file_analysis import Target

        try:
            mtime = item.modified.timestamp() if item.modified else 0.0
        except (OverflowError, OSError, ValueError):
            mtime = 0.0
        return Target(
            backend=pane.backend, path=path, name=item.name, size=int(item.size or 0), mtime=mtime
        )

    # ------------------------------------------------------------------
    # Archive preview dock (Task A4)
    # ------------------------------------------------------------------
    def open_archive_pane(self, path: str) -> None:
        """Show *path* in the non-modal archive preview dock.

        Creates a SINGLE right-area QDockWidget on first use and reuses
        it for every subsequent archive — the listing is transient per
        archive, so we just swap the dock's widget and retarget the
        title rather than spawning a new dock each time. The dock is
        closable / floatable (default ``QDockWidget`` features) and
        registered in the Panels menu alongside the other docks so its
        view/restore toggle stays consistent.

        The hosted :class:`~ui.archive_pane.ArchivePaneWidget` emits
        extraction signals; we wire them to the same QProgressDialog +
        daemon-thread extraction flow as the file pane's right-click
        "Extract…". The widget never extracts on its own.
        """
        from PyQt6.QtWidgets import QDockWidget

        from ui.archive_pane import ArchivePaneWidget

        basename = os.path.basename(path)
        # ``on_open_member`` is left None; the open_member signal is
        # wired below so the slot is the MainWindow's extractor rather
        # than a pane-internal callback.
        pane = ArchivePaneWidget(path, on_open_member=None)
        pane.extract_all.connect(lambda p=path: self._archive_extract_all(p))
        pane.extract_selected.connect(
            lambda members, p=path: self._archive_extract_selected(p, members)
        )
        pane.extract_to.connect(lambda p=path: self._archive_extract_to(p))
        pane.open_member.connect(lambda member, p=path: self._archive_open_member(p, member))

        if self._archive_dock is None:
            dock = QDockWidget(self)
            dock.setObjectName("axArchiveDock")  # saveState names every dock
            dock.setAllowedAreas(
                Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.LeftDockWidgetArea
            )
            self._archive_dock = dock
            self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
            self._register_archive_dock_view_action()
        else:
            dock = self._archive_dock
            old = dock.widget()
            if old is not None:
                old.deleteLater()

        dock.setWindowTitle(f"Archive: {basename}")
        dock.setWidget(pane)
        # ``_install_dock_titlebar`` constructs a fresh DockTitleBar each
        # call, so this installs a new title bar carrying the new title.
        self._install_dock_titlebar(dock, f"Archive: {basename}", "inbox")
        dock.show()
        dock.raise_()
        if pane.load_error is not None:
            log.info("Archive preview opened with load error for %s: %s", path, pane.load_error)

    def _register_archive_dock_view_action(self) -> None:
        """Add the archive dock's toggle to the Panels menu once.

        Idempotent: safe to call again after a menu rebuild
        (:meth:`_populate_dock_view_menu` clears the menu and re-adds the
        static toggles, then calls back here). The dock's
        ``toggleViewAction()`` is a stable, reused QAction, so we skip the
        addAction if it's already present to avoid a duplicate entry."""
        menu = getattr(self, "_dock_view_menu", None)
        if menu is None or self._archive_dock is None:
            return
        action = self._archive_dock.toggleViewAction()
        action.setText("&Archive Preview")
        if action not in menu.actions():
            menu.addAction(action)

    # -- extraction-with-progress (shared with file_pane's pattern) -----
    def _run_archive_extraction(
        self,
        archive_path: str,
        target_dir: str,
        members: list[str] | None,
        *,
        title: str,
    ) -> None:
        """Drive a daemon-thread extraction behind a QProgressDialog.

        Mirrors :meth:`ui.file_pane.FilePaneWidget._extract_archive`:
        the worker runs the (cancellable, self-cleaning) ``core.archive``
        extractor while the GUI thread pumps events and watches the
        Cancel button. ``members is None`` → ``extract`` (whole archive);
        otherwise ``extract_members`` (partial). On success refreshes any
        local file pane whose directory is the extraction parent; on
        failure shows a non-crashing QMessageBox.
        """
        import threading

        from PyQt6.QtWidgets import QProgressDialog

        from core import archive as ARCH

        arc_name = os.path.basename(archive_path)
        progress = QProgressDialog(
            f"Extracting {arc_name} → {os.path.basename(target_dir)}…",
            "Cancel",
            0,
            0,
            self,
        )
        progress.setWindowTitle(title)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(250)
        progress.setValue(0)

        done_event = threading.Event()
        state: dict = {"ok": False, "count": 0, "error": None}

        def _progress_cb(done: int, total: int, name: str) -> None:
            if progress.wasCanceled():
                raise ARCH.ExtractCancelled("user cancelled via progress dialog")

        def _worker() -> None:
            try:
                if members is None:
                    state["count"] = ARCH.extract(
                        archive_path, target_dir, progress=_progress_cb
                    )
                else:
                    state["count"] = ARCH.extract_members(
                        archive_path, target_dir, members, progress=_progress_cb
                    )
                state["ok"] = True
            except ARCH.ExtractCancelled:
                state["error"] = "cancelled"
            except ARCH.RarUnavailable as exc:
                state["error"] = f"RAR support unavailable: {exc}"
            except ARCH.UnsafeArchive as exc:
                state["error"] = f"refused as unsafe: {exc}"
            except NotImplementedError:
                # Surfaced specially by the caller for partial 7z/RAR;
                # re-flagged here so the message is precise.
                state["error"] = "notimplemented"
            except Exception as exc:  # noqa: BLE001
                state["error"] = f"extraction failed: {exc}"
            finally:
                done_event.set()

        t = threading.Thread(target=_worker, daemon=True, name=f"extract:{arc_name}")
        t.start()
        while not done_event.is_set():
            QApplication.processEvents()
            done_event.wait(0.05)
        QApplication.processEvents()
        progress.close()

        if state["ok"]:
            log.info(
                "Extracted %s → %s (%d files)", archive_path, target_dir, state["count"]
            )
            self._refresh_panes_for_dir(os.path.dirname(target_dir))
            QMessageBox.information(
                self,
                title,
                f"Extracted {state['count']} files to\n{target_dir}",
            )
            return
        if state["error"] == "cancelled":
            log.info("Extraction cancelled: %s", archive_path)
            return
        if state["error"] == "notimplemented":
            QMessageBox.information(
                self,
                title,
                "Partial extraction is not supported for this format (7z/RAR) — "
                "please use 'Extract All'.",
            )
            return
        QMessageBox.warning(
            self,
            title,
            f"Could not extract {arc_name}:\n{state['error']}",
        )

    def _refresh_panes_for_dir(self, directory: str) -> None:
        """Refresh any visible local file pane currently showing
        *directory* so a fresh extraction appears without a manual
        reload. Best-effort — pane refresh failures never propagate."""
        from core import previews as PV

        try:
            target = os.path.realpath(directory)
        except OSError:
            target = directory
        for pane in self._panes:
            try:
                if not PV._is_local_backend(pane.backend):
                    continue
                if os.path.realpath(pane.current_path) == target:
                    pane.refresh_after_change()
            except Exception as exc:  # noqa: BLE001 — never block on a pane
                log.debug("Post-extract pane refresh skipped: %s", exc)

    def _archive_extract_all(self, archive_path: str) -> None:
        from core import archive as ARCH

        parent = os.path.dirname(archive_path)
        base = ARCH.strip_archive_extension(os.path.basename(archive_path))
        try:
            target = ARCH.auto_suffix_dir(parent, base)
        except OSError as exc:
            QMessageBox.warning(self, "Extract Archive", f"Cannot pick a target folder:\n{exc}")
            return
        self._run_archive_extraction(archive_path, target, None, title="Extract Archive")

    def _archive_extract_selected(self, archive_path: str, members: list[str]) -> None:
        from core import archive as ARCH

        if not members:
            QMessageBox.information(
                self,
                "Extract Selection",
                "Nothing selected — please select files or folders in the tree.",
            )
            return
        parent = os.path.dirname(archive_path)
        base = ARCH.strip_archive_extension(os.path.basename(archive_path))
        try:
            target = ARCH.auto_suffix_dir(parent, base)
        except OSError as exc:
            QMessageBox.warning(self, "Extract Selection", f"Cannot pick a target folder:\n{exc}")
            return
        self._run_archive_extraction(
            archive_path, target, members, title="Extract Selection"
        )

    def _archive_extract_to(self, archive_path: str) -> None:
        from PyQt6.QtWidgets import QFileDialog

        from core import archive as ARCH

        parent = QFileDialog.getExistingDirectory(self, "Extract into folder")
        if not parent:
            return
        base = ARCH.strip_archive_extension(os.path.basename(archive_path))
        try:
            target = ARCH.auto_suffix_dir(parent, base)
        except OSError as exc:
            QMessageBox.warning(self, "Extract Archive", f"Cannot pick a target folder:\n{exc}")
            return
        self._run_archive_extraction(archive_path, target, None, title="Extract Archive")

    def _extract_single_member(self, archive_path: str, member_name: str) -> str | None:
        """Extract ONE member to a fresh ``mkdtemp`` dir and return the
        absolute path of the extracted file, or ``None`` (after showing
        a non-crashing message) when it can't be produced.

        Factored out of :meth:`_archive_open_member` so the extraction
        half is unit-testable without spinning up a modal viewer.
        7z/RAR single-member extraction is unsupported
        (``NotImplementedError`` from ``extract_members``) → info
        message.

        Temp-dir lifecycle: the member viewer opens one file at a time,
        so the PREVIOUS single-member temp dir is reaped here, on the
        next open — never immediately after the prior viewer returns, in
        case that viewer still holds the file open. Each dir is also
        tracked in ``_archive_member_tempdirs`` as a close-time safety
        net (deduped so ``closeEvent`` doesn't double-remove)."""
        import shutil
        import tempfile as _tempfile

        self._reap_last_member_tempdir()
        base = _tempfile.mkdtemp(prefix="axross-archive-")
        extracted = self._extract_member_into(base, archive_path, member_name)
        if extracted is None:
            # Only a successful open is tracked for later removal; a failed
            # one must not leave its temp dir behind.
            shutil.rmtree(base, ignore_errors=True)
        return extracted

    def _extract_member_into(self, base: str, archive_path: str, member_name: str) -> str | None:
        """The extraction half of :meth:`_extract_single_member`, into *base*."""
        from core import archive as ARCH

        # extract_members requires a non-existing target dir, so place
        # the extraction in a child of the mkdtemp dir.
        target = os.path.join(base, "member")
        try:
            ARCH.extract_members(archive_path, target, [member_name])
        except NotImplementedError:
            QMessageBox.information(
                self,
                "Open Member",
                "Single-file preview is not supported for this format (7z/RAR) — "
                "please use 'Extract All'.",
            )
            return None
        except (ARCH.RarUnavailable, ARCH.UnsafeArchive) as exc:
            QMessageBox.warning(self, "Open Member", f"Could not open member:\n{exc}")
            return None
        except Exception as exc:  # noqa: BLE001 — never crash on a bad member
            QMessageBox.warning(self, "Open Member", f"Could not open member:\n{exc}")
            log.warning("Open archive member failed for %r: %s", member_name, exc)
            return None

        # The member name may include a directory prefix; resolve the
        # actual extracted file path under the target dir.
        extracted = os.path.join(target, member_name.replace("\\", "/"))
        if not os.path.isfile(extracted):
            # Fall back to the first regular file found under target.
            extracted = None
            for dirpath, _dirs, files in os.walk(target):
                if files:
                    extracted = os.path.join(dirpath, files[0])
                    break
        if extracted is None or not os.path.isfile(extracted):
            QMessageBox.warning(self, "Open Member", "Extracted member not found on disk.")
            return None
        # Track for the close-time safety net (deduped) and mark as the
        # current member temp dir so the NEXT open reaps it.
        if base not in self._archive_member_tempdirs:
            self._archive_member_tempdirs.append(base)
        self._archive_last_member_tempdir = base
        return extracted

    def _archive_open_member(self, archive_path: str, member_name: str) -> None:
        """Extract ONE member to a temp dir and open it in a read-only
        viewer (image / hex / text dispatch shared with the file pane).
        Extraction + failure handling live in
        :meth:`_extract_single_member`; this wraps it with the modal
        viewer open."""
        from ui.file_pane import open_local_file_in_viewer

        extracted = self._extract_single_member(archive_path, member_name)
        if extracted is None:
            return
        open_local_file_in_viewer(self, extracted, read_only=True)

    def _reap_last_member_tempdir(self) -> None:
        """Remove the previous single-member preview temp dir, if any.

        Called at the START of the next single-member open so we never
        pull the file out from under a viewer that's still holding the
        prior member. The dir is also dropped from the close-time
        tracking list so ``closeEvent`` doesn't try to remove it twice."""
        import shutil

        prev = self._archive_last_member_tempdir
        if prev is None:
            return
        self._archive_last_member_tempdir = None
        shutil.rmtree(prev, ignore_errors=True)
        try:
            self._archive_member_tempdirs.remove(prev)
        except ValueError:
            pass

    def _cleanup_archive_tempdirs(self) -> None:
        """Remove every temp dir created for single-member previews."""
        import shutil

        for d in self._archive_member_tempdirs:
            shutil.rmtree(d, ignore_errors=True)
        self._archive_member_tempdirs.clear()
        self._archive_last_member_tempdir = None

    # ------------------------------------------------------------------
    # Tab-activity indicator: colour the tab label of any tabified dock
    # whose ``activity`` signal fired while it wasn't the raised tab.
    # Clears the moment the user raises that dock.
    # ------------------------------------------------------------------
    _ACTIVITY_COLOR = QColor("#e5a45a")  # amber accent — matches dark theme

    def _wire_dock_activity_indicators(self) -> None:
        self._dock_has_activity: dict[QWidget, bool] = {
            self._transfer_dock: False,
            self._terminal_dock: False,
            self._log_dock: False,
            self._console_dock: False,
        }
        for dock in list(self._dock_has_activity):
            self._watch_dock_activity(dock)

    def _watch_dock_activity(self, dock) -> None:
        """Colour ``dock``'s tab when its ``activity`` fires out of sight."""
        self._dock_has_activity[dock] = False
        dock.activity.connect(  # type: ignore[attr-defined]
            lambda d=dock: self._flag_dock_activity(d),
        )
        dock.visibilityChanged.connect(
            lambda visible, d=dock: self._on_dock_visibility_changed(
                d,
                visible,
            ),
        )

    def _flag_dock_activity(self, dock) -> None:
        # Skip the flag when the dock is already what the user is
        # looking at — no point colouring the tab that's already raised.
        if self._is_dock_currently_visible(dock):
            return
        # Already flagged: the tab is coloured. Every log record lands
        # here, and a burst re-walked every tab bar once per record.
        if self._dock_has_activity.get(dock):
            return
        self._dock_has_activity[dock] = True
        self._apply_tab_colors()

    def _on_dock_visibility_changed(self, dock, visible: bool) -> None:
        # Qt fires visibilityChanged(True) when the user raises a
        # tabified dock. At that moment the user has "seen" any
        # queued activity, so clear the flag.
        if visible and self._dock_has_activity.get(dock):
            self._dock_has_activity[dock] = False
            self._apply_tab_colors()

    def _is_dock_currently_visible(self, dock) -> bool:
        """True when *dock* is the raised tab of its tabified group
        (or not tabified at all). Qt's ``isVisible()`` returns True
        for ALL tabified docks even when they're hidden behind
        another tab, so it's not a reliable signal on its own —
        ``visibleRegion().isEmpty()`` catches the obscured case."""
        if not dock.isVisible():
            return False
        return not dock.visibleRegion().isEmpty()

    def _apply_tab_colors(self) -> None:
        """Walk every QTabBar under the main window; for each tab
        whose text matches one of our flagged docks' titles, set the
        tab text colour to the activity accent (or reset to default
        when the flag has been cleared)."""
        # Default tab text color — Qt's palette, not our amber.
        default = self.palette().color(self.foregroundRole())
        flagged_titles = {
            dock.windowTitle() for dock, flagged in self._dock_has_activity.items() if flagged
        }
        for tabbar in self.findChildren(QTabBar):
            for i in range(tabbar.count()):
                title = tabbar.tabText(i)
                if title in flagged_titles:
                    tabbar.setTabTextColor(i, self._ACTIVITY_COLOR)
                else:
                    # Only reset if it was one of OUR tabs; leave
                    # other tab bars' colours alone.
                    if title in {dock.windowTitle() for dock in self._dock_has_activity}:
                        tabbar.setTabTextColor(i, default)

    def _populate_dock_view_menu(self) -> None:
        if not hasattr(self, "_dock_view_menu"):
            return
        self._dock_view_menu.clear()
        self._dock_view_menu.addAction(self._transfer_dock.toggleViewAction())
        self._dock_view_menu.addAction(self._terminal_dock.toggleViewAction())
        self._dock_view_menu.addAction(self._log_dock.toggleViewAction())
        self._dock_view_menu.addAction(self._console_dock.toggleViewAction())
        scripts = getattr(self, "_scripts_dock", None)
        if scripts is not None:
            self._dock_view_menu.addAction(scripts.toggleViewAction())
        # Bookmark sidebar toggle + F12 hotkey. Uses the dock's
        # built-in toggleViewAction so show / hide / close all stay
        # in sync — closing the panel via its X button flips the
        # menu checkmark, toggling the menu flips the visibility,
        # and F12 routes through the same action.
        sidebar = getattr(self, "_bookmark_sidebar", None)
        if sidebar is not None:
            bm_toggle = sidebar.toggleViewAction()
            bm_toggle.setText("&Bookmark Sidebar")
            bm_toggle.setShortcut(QKeySequence("F12"))
            self._dock_view_menu.addAction(bm_toggle)
        # The archive dock is created lazily (on first preview), so its
        # toggle isn't part of the static rebuild above. Re-add it after
        # any rebuild so the toggle survives. ``clear()`` only detaches
        # actions from the menu (it doesn't delete the dock's reused
        # toggleViewAction), and the register helper is idempotent.
        analysis = getattr(self, "_analysis_dock", None)
        if analysis is not None:
            analysis_toggle = analysis.toggleViewAction()
            analysis_toggle.setText("&Analysis")
            analysis_toggle.setShortcut(QKeySequence("Ctrl+Shift+I"))
            self._dock_view_menu.addAction(analysis_toggle)
        if getattr(self, "_archive_dock", None) is not None:
            self._register_archive_dock_view_action()

    def _setup_central(self) -> None:
        self._root_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(self._root_splitter)
        self._add_pane_to_splitter(self._root_splitter, LocalFS())

    def _add_pane_to_splitter(
        self,
        splitter: QSplitter,
        backend,
        profile=None,
        password="",
        key_passphrase="",
    ) -> FilePaneWidget:
        pane = FilePaneWidget(backend, async_initial_load=True)
        pane.pane_focused.connect(lambda p=pane: self._set_active_pane(p))
        pane.view_mode_changed.connect(lambda _mode, p=pane: self._sync_view_mode_action(p))
        pane.selection_changed.connect(lambda p=pane: self._extension_event("selection_changed", p))
        pane.path_changed.connect(lambda _path, p=pane: self._extension_event("path_changed", p))
        pane.transfer_requested.connect(lambda paths, p=pane: self._transfer_from_pane(p, paths))
        pane.move_requested.connect(lambda paths, p=pane: self._move_from_pane(p, paths))
        pane.drop_transfer_requested.connect(self._on_drop_transfer)
        pane.bookmark_requested.connect(self._on_bookmark_request)
        pane.close_requested.connect(lambda p=pane: self._close_pane(p))
        pane.set_as_target_requested.connect(lambda p=pane: self._set_target_pane(p))
        pane.pane_drop_requested.connect(self._on_pane_drop)
        pane.open_bookmarks_requested.connect(self._show_bookmarks_popup)
        pane.open_duplicates_requested.connect(self._open_cas_duplicates)
        pane.open_terminal_requested.connect(
            lambda directory, p=pane: self._open_terminal_here(p, directory)
        )
        pane.cycle_pane_requested.connect(
            lambda forward: self._cycle_next_pane() if forward else self._cycle_prev_pane()
        )
        pane.selection_changed.connect(lambda p=pane: self._on_pane_selection_changed(p))
        splitter.addWidget(pane)
        self._panes.append(pane)
        if profile is not None:
            self._pane_profiles[pane] = profile
            self._refresh_proxy_indicator(pane)
            self._pane_passwords[pane] = password
            self._pane_key_passphrases[pane] = key_passphrase

        if self._active_pane is None:
            self._set_active_pane(pane)
        elif self._target_pane is None and pane is not self._active_pane:
            self._target_pane = pane
            self._refresh_pane_styles()

        return pane

    def _set_active_pane(self, pane: FilePaneWidget) -> None:
        if pane not in self._panes:
            return
        changed = pane is not self._active_pane
        if self._active_pane and self._active_pane != pane:
            self._target_pane = self._active_pane
        self._active_pane = pane
        if self._target_pane is pane:
            self._target_pane = next((p for p in self._panes if p is not pane), None)
        self._refresh_pane_styles()
        self._sync_view_mode_action()
        if changed:
            self._extension_event("pane_activated", pane)
        log.debug("Active pane: %s at %s", pane.backend.name, pane.current_path)
        if changed:  # a click into the active pane must not restart its analysis
            self._schedule_analysis()

    def _toggle_thumbnail_view(self, _checked: bool = False) -> None:
        pane = self._active_pane
        if pane is None:
            self.thumbnail_view_action.setChecked(False)
            return
        pane.toggle_view_mode()
        self._sync_view_mode_action(pane)

    def _sync_view_mode_action(self, pane=None) -> None:
        action = getattr(self, "thumbnail_view_action", None)
        if action is None or (pane is not None and pane is not self._active_pane):
            return
        active = self._active_pane
        action.setChecked(active is not None and active.view_mode == "thumbnails")

    def _extension_event(self, event: str, pane) -> None:
        """Forward a pane event to the extensions - for the active pane only."""
        host = getattr(self, "extension_host", None)
        if host is not None and pane is self._active_pane:
            host.emit(event, pane)

    def _show_extensions_dialog(self, _checked: bool = False) -> None:
        from ui.extensions_dialog import ExtensionsDialog

        dialog = ExtensionsDialog(self.extension_host, parent=self)
        try:
            dialog.exec()
        finally:
            dialog.deleteLater()

    def _open_extensions_folder(self, _checked: bool = False) -> None:
        from ui.extensions_dialog import open_extensions_folder

        open_extensions_folder()

    def _set_target_pane(self, pane: FilePaneWidget) -> None:
        """Explicitly set a pane as the transfer target."""
        if pane not in self._panes or pane is self._active_pane:
            return
        self._target_pane = pane
        self._refresh_pane_styles()
        log.info("Target pane set to: %s at %s", pane.backend.name, pane.current_path)

    def _cycle_next_pane(self) -> None:
        """Cycle focus to the next file pane (Tab)."""
        if not self._panes:
            return
        if self._active_pane in self._panes:
            idx = (self._panes.index(self._active_pane) + 1) % len(self._panes)
        else:
            idx = 0
        self._set_active_pane(self._panes[idx])
        self._panes[idx]._table.setFocus()

    def _cycle_prev_pane(self) -> None:
        """Cycle focus to the previous file pane (Shift+Tab)."""
        if not self._panes:
            return
        if self._active_pane in self._panes:
            idx = (self._panes.index(self._active_pane) - 1) % len(self._panes)
        else:
            idx = 0
        self._set_active_pane(self._panes[idx])
        self._panes[idx]._table.setFocus()

    def _refresh_pane_styles(self) -> None:
        theme = themes.pane_family(
            themes.resolve(
                getattr(self, "_current_theme", themes.DEFAULT_THEME),
                themes.system_scheme(),
            )
        )
        for pane in self._panes:
            if pane is self._active_pane:
                pane.set_pane_role("source", theme)
            elif pane is self._target_pane:
                pane.set_pane_role("target", theme)
            else:
                pane.set_pane_role("", theme)
            pane.update_header_color(theme)

    def _add_local_pane(self) -> None:
        self._add_pane_to_splitter(self._root_splitter, LocalFS())

    def _open_shell_pane(self) -> None:
        """Open an inline terminal pane next to the matching host's file pane."""
        # Build list of available shell targets:
        # (display_label, transport, profile_or_None, host_file_pane_or_None)
        choices: list[
            tuple[str, object | None, ConnectionProfile | None, FilePaneWidget | None]
        ] = []
        choices.append(("Local Shell", None, None, None))

        seen: set[str] = set()
        for pane in self._panes:
            backend = pane.backend
            if _is_ssh_session(backend) and backend.transport and backend.connected:
                label = backend.name
                if label not in seen:
                    seen.add(label)
                    profile = self._pane_profiles.get(pane)
                    choices.append((f"SSH: {label}", backend.transport, profile, pane))

        if len(choices) == 1:
            # Only local shell available — open directly
            self._embed_terminal_pane(None, "Local Shell", None, self._active_pane)
            return

        # Let user pick
        names = [c[0] for c in choices]
        from PyQt6.QtWidgets import QInputDialog

        choice, ok = QInputDialog.getItem(self, "Open Shell", "Select host:", names, editable=False)
        if not ok:
            return

        for name, transport, profile, host_pane in choices:
            if name == choice:
                self._embed_terminal_pane(
                    transport,
                    name,
                    profile,
                    host_pane or self._active_pane,
                )
                return

    def _embed_terminal_pane(
        self,
        transport: object | None,
        label: str,
        profile: ConnectionProfile | None,
        beside_pane: FilePaneWidget | None,
    ) -> None:
        """Create a TerminalPaneWidget and split it beside the given file pane.

        The pane takes its own reference on the profile's session and
        gives back exactly that in TerminalPaneWidget.shutdown."""
        term_pane = TerminalPaneWidget(
            transport=transport,
            label=label,
            profile=profile,
            connection_manager=self._connection_manager,
        )
        term_pane.close_requested.connect(lambda tp=term_pane: self._close_terminal_pane(tp))
        self._terminal_panes.append(term_pane)

        # Find the splitter containing the target pane and add terminal beside it
        target = beside_pane or self._active_pane
        if target is None:
            # Fallback: add to root splitter
            self._root_splitter.addWidget(term_pane)
            term_pane.show()
            return

        parent_splitter = target.parent()
        if not isinstance(parent_splitter, QSplitter):
            self._root_splitter.addWidget(term_pane)
            term_pane.show()
            return

        idx = parent_splitter.indexOf(target)
        new_splitter = QSplitter(Qt.Orientation.Horizontal)
        parent_splitter.replaceWidget(idx, new_splitter)
        new_splitter.addWidget(target)
        new_splitter.addWidget(term_pane)
        new_splitter.show()
        target.show()
        term_pane.show()

        def _apply_equal_split() -> None:
            new_splitter.setSizes(
                equal_split_sizes(
                    self._splitter_extent(new_splitter, Qt.Orientation.Horizontal),
                    2,
                    fallback_extent=self._splitter_extent(
                        parent_splitter, Qt.Orientation.Horizontal
                    ),
                )
            )

        _defer_while_alive((new_splitter, parent_splitter), _apply_equal_split)
        log.info("Opened terminal pane: %s", label)

    def _close_terminal_pane(self, term_pane: TerminalPaneWidget) -> None:
        """Close an inline terminal pane and clean up splitter."""
        if term_pane not in self._terminal_panes:
            return

        term_pane.shutdown()
        self._terminal_panes.remove(term_pane)
        self._remove_from_splitter(term_pane)
        log.info("Closed terminal pane: %s", term_pane.session_label)

    def _remove_from_splitter(self, widget: QWidget) -> None:
        """Take *widget* out of its splitter and delete it; a nested
        splitter left with one child is replaced by that child."""
        parent = widget.parent()
        widget.setParent(None)
        widget.deleteLater()

        # Clean up single-child splitter
        if isinstance(parent, QSplitter) and parent.count() == 1 and parent != self._root_splitter:
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                idx = grandparent.indexOf(parent)
                remaining = parent.widget(0)
                grandparent.replaceWidget(idx, remaining)
                remaining.show()
                parent.deleteLater()

    # --- Disconnected placeholders of a restored layout ---

    def _make_placeholder(
        self, splitter: QSplitter, kind: str, profile_name: str, path: str = ""
    ) -> DisconnectedPanePlaceholder:
        """A remote pane of a restored layout, in its place, not connected."""
        known = self._profile_manager.get(profile_name) is not None
        placeholder = DisconnectedPanePlaceholder(kind, profile_name, path, profile_known=known)
        placeholder.reconnect_requested.connect(
            lambda ph=placeholder: self._reconnect_placeholder(ph)
        )
        placeholder.close_requested.connect(lambda ph=placeholder: self._close_placeholder(ph))
        splitter.addWidget(placeholder)
        self._pane_placeholders.append(placeholder)
        return placeholder

    def _close_placeholder(self, placeholder: DisconnectedPanePlaceholder) -> None:
        if placeholder not in self._pane_placeholders:
            return
        self._pane_placeholders.remove(placeholder)
        self._remove_from_splitter(placeholder)

    def _reconnect_placeholder(self, placeholder: DisconnectedPanePlaceholder) -> None:
        """Reconnect: connect the profile exactly as opening it does - Quick
        Connect for a file pane, the profile terminal for a terminal - and
        put the result where the placeholder is."""
        if placeholder not in self._pane_placeholders:
            return
        name = placeholder.profile_name
        profile = self._profile_manager.get(name)
        if profile is None:
            message = f"The profile '{name}' no longer exists."
            placeholder.set_note(message)
            self.statusBar().showMessage(message, 5000)
            return
        if placeholder.kind == KIND_TERMINAL:
            self._swap_placeholder(placeholder, self._preset_make_terminal_pane(name))
            return
        self._quick_connect_profile(
            profile,
            post_connect=lambda pane, ph=placeholder: self._land_reconnected_pane(ph, pane),
        )

    def _land_reconnected_pane(
        self, placeholder: DisconnectedPanePlaceholder, pane: FilePaneWidget
    ) -> None:
        """post_connect of a Reconnect: the new pane takes the placeholder's
        place and opens the saved folder. A placeholder closed meanwhile
        leaves the pane where Quick Connect put it."""
        if placeholder not in self._pane_placeholders:
            return
        self._swap_placeholder(placeholder, pane)
        if placeholder.path:
            pane.navigate_async(placeholder.path)

    def _swap_placeholder(self, placeholder: DisconnectedPanePlaceholder, widget: QWidget) -> None:
        self._pane_placeholders.remove(placeholder)
        splitter = placeholder.parent()
        if widget.parent() is not None:
            widget.setParent(None)  # Quick Connect put it into the root splitter
        if isinstance(splitter, QSplitter):
            # The new widget inherits the slot's geometry and visibility;
            # the placeholder leaves the splitter.
            splitter.replaceWidget(splitter.indexOf(placeholder), widget)
        else:
            self._root_splitter.addWidget(widget)
        widget.show()
        placeholder.deleteLater()

    @staticmethod
    def _splitter_extent(widget: QWidget, orientation: Qt.Orientation) -> int:
        if orientation == Qt.Orientation.Horizontal:
            return widget.width()
        return widget.height()

    def _split_pane(self, orientation: Qt.Orientation) -> None:
        if not self._active_pane:
            return

        pane = self._active_pane
        parent_splitter = pane.parent()

        if not isinstance(parent_splitter, QSplitter):
            return

        idx = parent_splitter.indexOf(pane)
        new_splitter = QSplitter(orientation)

        parent_splitter.replaceWidget(idx, new_splitter)
        new_splitter.addWidget(pane)
        new_pane = self._add_pane_to_splitter(new_splitter, LocalFS())
        new_splitter.show()
        pane.show()
        new_pane.show()

        def _apply_equal_split() -> None:
            new_splitter.setSizes(
                equal_split_sizes(
                    self._splitter_extent(new_splitter, orientation),
                    2,
                    fallback_extent=self._splitter_extent(parent_splitter, orientation),
                )
            )

        _defer_while_alive((new_splitter, parent_splitter), _apply_equal_split)

    def _close_active_pane(self) -> None:
        if self._active_pane:
            self._close_pane(self._active_pane)

    # ------------------------------------------------------------------
    # Layout presets — see ui/layout_presets.py
    # ------------------------------------------------------------------

    def _preset_make_file_pane(self) -> "FilePaneWidget":
        """Factory hook for layout_presets.apply_preset — returns a
        fresh FilePaneWidget on LocalFS, fully wired into the active-
        pane / drop-target machinery just like a manual split would."""
        pane = FilePaneWidget(LocalFS(), async_initial_load=True)
        pane.pane_focused.connect(lambda p=pane: self._set_active_pane(p))
        pane.view_mode_changed.connect(lambda _mode, p=pane: self._sync_view_mode_action(p))
        pane.selection_changed.connect(lambda p=pane: self._extension_event("selection_changed", p))
        pane.path_changed.connect(lambda _path, p=pane: self._extension_event("path_changed", p))
        pane.transfer_requested.connect(lambda paths, p=pane: self._transfer_from_pane(p, paths))
        pane.move_requested.connect(lambda paths, p=pane: self._move_from_pane(p, paths))
        pane.drop_transfer_requested.connect(self._on_drop_transfer)
        pane.bookmark_requested.connect(self._on_bookmark_request)
        pane.close_requested.connect(lambda p=pane: self._close_pane(p))
        pane.set_as_target_requested.connect(lambda p=pane: self._set_target_pane(p))
        pane.pane_drop_requested.connect(self._on_pane_drop)
        pane.open_bookmarks_requested.connect(self._show_bookmarks_popup)
        pane.open_duplicates_requested.connect(self._open_cas_duplicates)
        pane.open_terminal_requested.connect(
            lambda directory, p=pane: self._open_terminal_here(p, directory)
        )
        pane.cycle_pane_requested.connect(
            lambda forward: self._cycle_next_pane() if forward else self._cycle_prev_pane()
        )
        pane.selection_changed.connect(lambda p=pane: self._on_pane_selection_changed(p))
        self._panes.append(pane)
        return pane

    def _preset_make_terminal_pane(
        self, profile_name: str, cwd: str | None = None
    ) -> "TerminalPaneWidget":
        """Factory hook for layout_presets and the session restore — returns
        a TerminalPaneWidget. ``profile_name`` is "local" for a local shell
        (started in *cwd* when given) or a saved connection profile name
        for an SSH/Telnet session, which connects as the pane starts."""
        if profile_name == "local":
            term = TerminalPaneWidget(label="Local Shell", cwd=cwd)
        else:
            profile = self._profile_manager.get(profile_name)
            term = TerminalPaneWidget(
                label=profile_name if profile else "Local Shell",
                profile=profile,
                connection_manager=self._connection_manager,
            )
        # As _embed_terminal_pane does: without it the pane's close button
        # did nothing and its shell ran until the window closed.
        term.close_requested.connect(lambda tp=term: self._close_terminal_pane(tp))
        self._terminal_panes.append(term)
        return term

    def _preset_tear_down_existing(self) -> None:
        """Close every file + terminal pane before applying a new
        preset so we don't leak backend sessions / SSH transports.

        Each pane gives back what it holds, as _close_pane and
        _close_terminal_pane do: a saved connection's reference and its
        terminal-dock entry, and a terminal's shell. ``close()`` alone
        stopped neither - TerminalPaneWidget has no closeEvent."""
        for pane in list(self._panes):
            profile = self._pane_profiles.pop(pane, None)
            try:
                if _is_ssh_session(pane.backend):
                    self._terminal_dock.remove_ssh_session(pane.backend.name)
                if profile is not None:
                    self._connection_manager.release(profile)
            except Exception:  # noqa: BLE001 — a dead session must not block the switch
                log.debug("Preset teardown: releasing %s failed", pane, exc_info=True)
            self._close_compare_windows_for(pane)
            try:
                pane.close()
            except Exception:  # noqa: BLE001
                pass
        for term in list(self._terminal_panes):
            try:
                term.shutdown()
                term.close()
            except Exception:  # noqa: BLE001
                pass
        for placeholder in list(self._pane_placeholders):
            placeholder.close()  # holds nothing; setCentralWidget deletes it
        self._panes.clear()
        self._terminal_panes.clear()
        self._pane_placeholders.clear()
        self._pane_profiles.clear()
        self._pane_passwords.clear()
        self._pane_key_passphrases.clear()
        self._active_pane = None
        self._target_pane = None

    def _refresh_after_preset(self) -> None:
        """Settle internal state after a fresh preset takes effect:
        pick the first file pane (if any) as active, refresh styles."""
        if self._panes:
            self._set_active_pane(self._panes[0])
        if len(self._panes) >= 2:
            self._target_pane = self._panes[1]
        self._refresh_pane_styles()

    def _build_pane_activation_menu(self, menu) -> None:
        """On Click, or after resting the mouse 1, 2 or 3 s in a pane."""
        from PyQt6.QtGui import QActionGroup

        from core import pane_activation as PA

        group = QActionGroup(menu)
        group.setExclusive(True)
        current = PA.activation()
        choices = [(PA.CLICK, tr("On Click"))] + [
            (n, tr("After {n} s in the Pane").format(n=n)) for n in PA.HOVER_SECONDS
        ]
        self._pane_activation_actions = {}
        for value, label in choices:
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(value == current)
            group.addAction(action)
            action.triggered.connect(lambda _checked=False, v=value: self._set_pane_activation(v))
            self._pane_activation_actions[value] = action

    def _set_pane_activation(self, value) -> None:
        from core import pane_activation as PA

        try:
            PA.set_activation(value)
        except (OSError, ValueError) as exc:
            log.warning("Could not store the pane activation: %s", exc)

    def apply_layout_preset(self, name: str) -> None:
        """Public entry point — set the central layout from a named
        preset (see :mod:`ui.layout_presets`)."""
        from ui.layout_presets import apply_preset

        apply_preset(self, name)

    def cycle_layout_preset(self, *, forward: bool = True) -> None:
        """Rotate through the built-in preset list. Wired to
        ``Ctrl+Alt+L`` (forward) and ``Ctrl+Alt+Shift+L`` (back)."""
        from ui.layout_presets import cycle_preset

        new_name = cycle_preset(self, forward=forward)
        # Lightweight statusbar hint so the user sees what they cycled to.
        try:
            self.statusBar().showMessage(f"Layout: {new_name}", 2000)
        except Exception:  # noqa: BLE001
            pass

    def _close_pane(self, pane: FilePaneWidget) -> None:
        if pane not in self._panes or len(self._panes) <= 1:
            return

        profile = self._pane_profiles.pop(pane, None)
        self._pane_passwords.pop(pane, None)
        self._pane_key_passphrases.pop(pane, None)

        # Remove SSH terminal option only when no other pane uses the same session label.
        if _is_ssh_session(pane.backend):
            still_used = any(
                other is not pane
                and _is_ssh_session(other.backend)
                and other.backend.name == pane.backend.name
                for other in self._panes
            )
            if not still_used:
                self._terminal_dock.remove_ssh_session(pane.backend.name)

        if profile is not None:
            self._connection_manager.release(profile)
        self._panes.remove(pane)
        self._close_compare_windows_for(pane)
        if pane is self._target_pane:
            self._target_pane = None
        if pane is self._active_pane:
            self._active_pane = None

        parent = pane.parent()
        pane.setParent(None)
        pane.deleteLater()

        # Clean up empty splitters
        if isinstance(parent, QSplitter) and parent.count() == 1 and parent != self._root_splitter:
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                idx = grandparent.indexOf(parent)
                remaining = parent.widget(0)
                grandparent.replaceWidget(idx, remaining)
                remaining.show()
                parent.deleteLater()
        elif (
            isinstance(parent, QSplitter) and parent.count() == 0 and parent != self._root_splitter
        ):
            parent.deleteLater()

        if self._panes:
            self._set_active_pane(self._panes[0])
            if self._target_pane is None and len(self._panes) > 1:
                self._target_pane = next(
                    (other for other in self._panes if other is not self._active_pane),
                    None,
                )
                self._refresh_pane_styles()
        else:
            self._active_pane = None
            self._target_pane = None
            self._refresh_pane_styles()

    def _toggle_splitter_orientation(self) -> None:
        """Toggle the orientation of the splitter containing the active pane."""
        if not self._active_pane:
            return
        parent = self._active_pane.parent()
        if not isinstance(parent, QSplitter):
            return
        if parent.orientation() == Qt.Orientation.Horizontal:
            parent.setOrientation(Qt.Orientation.Vertical)
        else:
            parent.setOrientation(Qt.Orientation.Horizontal)

    def _equalize_pane_sizes(self) -> None:
        """Set all panes in the active pane's splitter to equal size."""
        if not self._active_pane:
            return
        parent = self._active_pane.parent()
        if not isinstance(parent, QSplitter):
            return
        count = parent.count()
        if count < 2:
            return
        parent.setSizes(
            equal_split_sizes(
                self._splitter_extent(parent, parent.orientation()),
                count,
            )
        )

    def _move_pane(self, direction: int) -> None:
        """Move the active pane left/up (-1) or right/down (+1) within its splitter."""
        if not self._active_pane:
            return
        parent = self._active_pane.parent()
        if not isinstance(parent, QSplitter):
            return
        idx = parent.indexOf(self._active_pane)
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= parent.count():
            return
        # QSplitter.insertWidget moves an existing widget
        parent.insertWidget(new_idx, self._active_pane)

    def _on_pane_drop(self, source_pane_id: str, target_pane: FilePaneWidget, zone: str) -> None:
        """Handle a pane being dropped onto another pane to create a nested split."""
        source_pane = next((p for p in self._panes if str(id(p)) == source_pane_id), None)
        if source_pane is None or source_pane is target_pane:
            return

        target_parent = target_pane.parent()
        if not isinstance(target_parent, QSplitter):
            return

        axis = splitter_axis_for_zone(zone)
        if axis is None:
            log.warning("Ignoring pane drop with unknown zone %r", zone)
            return
        orientation = Qt.Orientation.Horizontal if axis == "horizontal" else Qt.Orientation.Vertical

        # Remove source pane from its current splitter
        source_parent = source_pane.parent()
        source_pane.setParent(None)

        # Replace target pane with a new nested splitter
        target_idx = target_parent.indexOf(target_pane)
        new_splitter = QSplitter(orientation)
        target_parent.replaceWidget(target_idx, new_splitter)

        # Add panes in correct order
        # Note: replaceWidget() and setParent(None) hide widgets in Qt,
        # so we must explicitly show() them after re-adding.
        if zone in ("left", "top"):
            new_splitter.addWidget(source_pane)
            new_splitter.addWidget(target_pane)
        else:
            new_splitter.addWidget(target_pane)
            new_splitter.addWidget(source_pane)
        new_splitter.show()
        source_pane.show()
        target_pane.show()

        # Equal split — defer setSizes until after Qt processes the layout,
        # because new_splitter has 0 size at this point.
        def _apply_equal_split() -> None:
            new_splitter.setSizes(
                equal_split_sizes(
                    self._splitter_extent(new_splitter, orientation),
                    2,
                    fallback_extent=self._splitter_extent(target_parent, orientation),
                )
            )

        _defer_while_alive((new_splitter, target_parent), _apply_equal_split)

        # Clean up empty parent splitters left behind
        if isinstance(source_parent, QSplitter) and source_parent != self._root_splitter:
            if source_parent.count() == 1:
                grandparent = source_parent.parent()
                if isinstance(grandparent, QSplitter):
                    gp_idx = grandparent.indexOf(source_parent)
                    remaining = source_parent.widget(0)
                    grandparent.replaceWidget(gp_idx, remaining)
                    remaining.show()  # replaceWidget hides the old widget
                    source_parent.deleteLater()
            elif source_parent.count() == 0:
                source_parent.deleteLater()

        log.info(
            "Pane rearranged: %s dropped %s of %s",
            source_pane.backend.name,
            zone,
            target_pane.backend.name,
        )

    def _extract_pane_from_split(self) -> None:
        """Pull the active pane out of a nested splitter back to the root level."""
        if not self._active_pane:
            return
        parent = self._active_pane.parent()
        if not isinstance(parent, QSplitter) or parent is self._root_splitter:
            return  # Already at root level

        pane = self._active_pane

        # Remove pane from nested splitter
        pane.setParent(None)

        # Clean up the now-possibly-single-child nested splitter
        if parent.count() == 1:
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                gp_idx = grandparent.indexOf(parent)
                remaining = parent.widget(0)
                grandparent.replaceWidget(gp_idx, remaining)
                remaining.show()  # replaceWidget hides the old widget
                parent.deleteLater()
        elif parent.count() == 0:
            gp = parent.parent()
            if isinstance(gp, QSplitter):
                parent.deleteLater()

        # Add pane to root splitter
        self._root_splitter.addWidget(pane)
        pane.show()
        count = self._root_splitter.count()
        self._root_splitter.setSizes(
            equal_split_sizes(
                self._splitter_extent(self._root_splitter, self._root_splitter.orientation()),
                count,
            )
        )
        log.info("Pane extracted to root: %s", pane.backend.name)

    def _toggle_hidden(self, show: bool) -> None:
        for pane in self._panes:
            pane.set_show_hidden(show)
            pane.refresh_after_change()

    # ------------------------------------------------------------------
    # Scheduled jobs
    # ------------------------------------------------------------------

    def _job_store(self):
        """The on-disk schedule, alongside the operation journal."""
        from pathlib import Path

        from core.operation_journal import JOURNAL_PATH
        from core.scheduler import JobStore

        return JobStore(Path(JOURNAL_PATH).parent / "jobs.json")

    def _build_language_menu(self, menu) -> None:
        """One entry per shipped language, plus automatic detection.

        A restart is required and the entry says so: retranslating a
        live window means rebuilding every menu, dock title and open
        dialog, and a half-retranslated interface is worse than an
        honest prompt.
        """
        from core.i18n import SUPPORTED, active, store_language

        current = active().language
        auto = menu.addAction(tr("Automatic (system locale)"))
        auto.setCheckable(True)
        auto.triggered.connect(lambda: self._set_language(None))
        menu.addSeparator()
        for code, name in SUPPORTED.items():
            action = menu.addAction(name)
            action.setCheckable(True)
            action.setChecked(code == current)
            action.triggered.connect(lambda _checked=False, c=code: self._set_language(c))
        self._language_store = store_language

    def _set_language(self, code: str | None) -> None:
        from core.i18n import SUPPORTED, store_language

        try:
            store_language(code or "")
        except OSError as exc:
            QMessageBox.warning(
                self, tr("Language"), tr("Could not save the language setting:") + f"\n{exc}"
            )
            return
        label = SUPPORTED.get(code or "", tr("Automatic (system locale)"))
        QMessageBox.information(
            self,
            tr("Language"),
            tr("The language changes when axross restarts.") + f"\n\n{label}",
        )

    def _open_scheduler(self) -> None:
        from ui.scheduler_dialog import SchedulerDialog

        dlg = SchedulerDialog(self._job_store(), parent=self)
        dlg.exec()
        # Pick up edits without waiting for the next tick.
        self._scheduler_jobs = self._job_store().load()
        if getattr(self, "_scripts_dock", None) is not None:
            self._scripts_dock.refresh()  # the [scheduled] markers

    def _start_scheduler(self) -> None:
        """Arm the tick that runs due jobs.

        60 s is deliberately coarse: the shortest offered interval is
        five minutes, so a finer tick would only wake the process more
        often to decide there is nothing to do.
        """
        from PyQt6.QtCore import QTimer

        self._scheduler_jobs = self._job_store().load()
        self._scheduler_done.connect(self._on_scheduled_job_finished)
        self._scheduler_timer = QTimer(self)
        self._scheduler_timer.setInterval(60_000)
        self._scheduler_timer.timeout.connect(self._scheduler_tick)
        self._scheduler_timer.start()

    def _scheduler_tick(self) -> None:
        from dataclasses import replace
        from datetime import datetime

        from core.scheduler import due_jobs

        jobs = getattr(self, "_scheduler_jobs", None)
        if not jobs:
            return
        now = datetime.now()
        for job in due_jobs(jobs, now=now):
            # Mark it in flight BEFORE starting: due_jobs excludes
            # running jobs, and without this a slow job would be
            # started again on the next tick.
            self._scheduler_jobs = [
                replace(j, running=True) if j.job_id == job.job_id else j
                for j in self._scheduler_jobs
            ]
            self._run_scheduled_job(job)

    @staticmethod
    def _scheduled_runner(job):
        """What a job actually does. Runs on a worker thread."""
        if job.kind == "script":
            from core import scripting

            scripting.run_script(job.target)
            return f"ran {job.target}"
        raise ValueError(f"unknown job kind {job.kind!r}")

    def _run_scheduled_job(self, job) -> None:
        """Start one job on a worker thread.

        Off the GUI thread on purpose: the first wiring called
        run_script straight from the timer slot, so a nightly mirror
        over SFTP froze the window for as long as it took — the one
        thing a background schedule must never do.

        The outcome comes back through a queued signal so the store is
        written and the status bar touched on the GUI thread only.
        """
        from PyQt6.QtCore import QThread

        from core.scheduler import run_job

        done = self._scheduler_done
        runner = self._scheduled_runner

        def _report(j, ok, detail):
            try:
                done.emit(j.job_id, ok, detail)
            except RuntimeError:  # the window is gone; nobody to tell
                log.info("scheduler: job %s ended after the window closed", j.name)

        class _JobThread(QThread):
            # The work goes into run(): a plain function connected to
            # ``started`` was queued back to the GUI thread (its
            # receiver lives there), so the job ran on the GUI thread
            # after all and the window froze for as long as it took.
            def run(self) -> None:
                run_job(job, runner=runner, on_finished=_report)

        # No parent: a QThread parented to the window died with it while
        # the job still ran, which Qt answers with an abort. closeEvent
        # hands a running one over instead. Keep a reference meanwhile.
        thread = _JobThread()
        self._scheduler_threads = getattr(self, "_scheduler_threads", [])
        self._scheduler_threads.append(thread)
        thread.finished.connect(
            lambda t=thread: self._scheduler_threads.remove(t)
            if t in self._scheduler_threads
            else None
        )
        thread.start()

    def _on_scheduled_job_finished(self, job_id: str, ok: bool, detail: str) -> None:
        """Record a finished run. Always on the GUI thread."""
        from datetime import datetime

        from core.scheduler import record_result

        job = next((j for j in self._scheduler_jobs if j.job_id == job_id), None)
        if job is None:
            return
        updated = record_result(job, ok=ok, at=datetime.now(), detail=detail)
        self._scheduler_jobs = [
            updated if j.job_id == job_id else j for j in self._scheduler_jobs
        ]
        try:
            self._job_store().save(self._scheduler_jobs)
        except OSError as exc:
            log.warning("scheduler: could not persist job state: %s", exc)
        if not ok:
            self.statusBar().showMessage(f"Scheduled job {job.name!r} failed: {detail}", 8000)

    def _backends_by_label(self) -> dict:
        """Every open backend, keyed by the label the journal records."""
        out: dict = {}
        for pane in self._panes:
            backend = getattr(pane, "backend", None)
            if backend is None:
                continue
            out.setdefault(getattr(backend, "name", type(backend).__name__), (backend, pane))
        return out

    def _undo_last_operation(self) -> None:
        """Reverse the newest operation that can actually be reversed.

        The journal spans every connection the app has ever had, so the
        candidate has to be one whose backend is open right now — see
        core.undo.pick_undoable. Non-reversible entries are reported
        with their reason rather than skipped in silence: a user who
        presses undo and gets no response assumes it worked.
        """
        from core.operation_journal import read_recent
        from core.undo import apply_undo, pick_undoable, undoable

        try:
            events = read_recent(limit=200)
        except Exception as exc:  # noqa: BLE001 — a broken journal must not block the app
            log.warning("undo: could not read the journal: %s", exc)
            QMessageBox.warning(self, "Undo", f"Could not read the operation journal:\n{exc}")
            return

        plans = undoable(events)
        by_label = self._backends_by_label()
        plan = pick_undoable(plans, set(by_label))
        if plan is None:
            newest = plans[0] if plans else None
            if newest is not None and not newest.reversible:
                QMessageBox.information(
                    self,
                    "Nothing to undo",
                    f"The most recent operation ({newest.operation}) cannot be "
                    f"reversed:\n\n{newest.reason}",
                )
            else:
                QMessageBox.information(
                    self,
                    "Nothing to undo",
                    "No recent operation on a currently open connection can be reversed.",
                )
            return

        refusal = self._undo_refusal(plan, by_label)
        if refusal:
            QMessageBox.information(self, "Cannot undo", refusal)
            return

        if QMessageBox.question(
            self,
            "Undo",
            f"Undo the last {plan.operation}?\n\n{plan.reason}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return

        # Looked up again: while the question was open a reconnect may have
        # replaced a connection, or a pane may have been closed.
        by_label = self._backends_by_label()
        refusal = self._undo_refusal(plan, by_label)
        if refusal:
            QMessageBox.information(self, "Cannot undo", refusal)
            return
        backend, pane = by_label[plan.backend] if plan.backend else next(iter(by_label.values()))
        try:
            apply_undo(
                plan,
                backend,
                source_backend=self._undo_source_backend(plan, by_label),
                transfer=self._undo_transfer,
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Undo failed", str(exc))
            return
        try:
            from core.undo import record_undone

            # The next Ctrl+Z reaches the operation before this one.
            record_undone(plan)
        except Exception as exc:  # noqa: BLE001 - the undo itself succeeded
            log.warning("undo: could not record the undo in the journal: %s", exc)
        if pane is not None:
            pane.refresh_after_change()
        self.statusBar().showMessage(f"Undone: {plan.reason}", 5000)

    @staticmethod
    def _undo_refusal(plan, by_label: dict) -> str:
        """Why *plan* cannot be carried out on the open connections, or "".

        Each connection is looked up by the label the journal recorded;
        none is ever guessed. A move between two local panes has "Local"
        on both ends, so "any other open connection" picked a remote host
        as the source and sent the file there.
        """
        if not by_label:
            return "No connection is open."
        if not plan.backend:
            if len(by_label) > 1:
                return (
                    "The journal entry does not say which connection it belongs to, "
                    "and more than one is open. Close the others and try again."
                )
        elif plan.backend not in by_label:
            return f"The connection {plan.backend} is no longer open."
        if plan.action == "transfer_back":
            if not plan.source_backend:
                return (
                    "This move was recorded before the journal named the connection "
                    "the data came from, so sending it back would mean guessing the host."
                )
            if plan.source_backend not in by_label:
                return (
                    f"The data came from {plan.source_backend}, which is not open. "
                    "Connect to it and try again."
                )
        return ""

    def _undo_source_backend(self, plan, by_label: dict):
        """The connection a transfer-engine move took the data from.

        Returns ``None`` when it is not open (or not recorded), which makes
        apply_undo refuse instead of pushing data to whichever host
        happened to be at hand.
        """
        if plan.action != "transfer_back" or not plan.source_backend:
            return None
        entry = by_label.get(plan.source_backend)
        return entry[0] if entry else None

    def _undo_transfer(self, *, src_backend, src_path, dst_backend, dst_path) -> str:
        """Move data back to *dst_path* through the normal transfer engine.

        The target folder is the one the data came from - not the folder a
        pane on that connection happens to show now, where a file of the
        same name would be overwritten.
        """
        src_name = src_path.rsplit(src_backend.separator(), 1)[-1]
        dst_name = dst_path.rsplit(dst_backend.separator(), 1)[-1]
        if src_name != dst_name:
            raise OSError(
                f"{src_path} no longer has the name it was moved under ({dst_name}); "
                "undo cannot put it back."
            )
        if dst_backend.exists(dst_path):
            raise OSError(
                f"{dst_path} exists again — undo would overwrite it. Move or rename it first."
            )
        self._transfer_manager.transfer_files(
            source_backend=src_backend,
            dest_backend=dst_backend,
            source_paths=[src_path],
            dest_dir=dst_backend.parent(dst_path),
            direction=self._transfer_direction(src_backend, dst_backend),
            move=True,
        )
        labels = {getattr(src_backend, "name", None), getattr(dst_backend, "name", None)}
        for pane in self._panes:
            if getattr(pane.backend, "name", None) in labels:
                self._transfer_target_panes.add(pane)
        return dst_path

    def _open_compare_panes(self) -> None:
        """Diff the active pane's tree against the target pane's.

        Uses the existing active/target pair rather than asking for two
        paths — it is the same pairing the transfer actions already use,
        so "left" and "right" are whatever the user is looking at.
        """
        from ui.compare_dialog import CompareDialog

        left, right = self._active_pane, self._target_pane
        if left is None or right is None or left is right:
            QMessageBox.information(
                self,
                "Compare Panes",
                "Comparing needs two panes: an active one and a target. "
                "Split the view (Ctrl+Shift+H) and mark the second pane as "
                "target from its header.",
            )
            return

        dlg = CompareDialog(left, right, parent=self)
        self._compare_dialogs.append((dlg, left, right))
        dlg.finished.connect(lambda _code, d=dlg: self._forget_compare_dialog(d))
        dlg.reveal_requested.connect(
            lambda side, path, left=left, right=right: self._reveal_compared(
                left if side == "left" else right, path
            )
        )
        dlg.copy_requested.connect(
            lambda direction, paths, left=left, right=right: self._copy_compared(
                left, right, direction, paths
            )
        )
        dlg.delete_requested.connect(
            lambda side, paths, left=left, right=right: self._delete_compared(
                left if side == "left" else right, paths
            )
        )
        dlg.sync_requested.connect(
            lambda items, left=left, right=right: self._apply_sync(left, right, items)
        )
        # Modeless on purpose: "reveal in pane" navigates the window
        # behind this one, which a modal exec() would hide until the
        # user closed the very dialog they were navigating from.
        dlg.show()

    def _close_compare_windows_for(self, pane) -> None:
        """Close every Compare window built on *pane*.

        The window is modeless and its rows name that pane's folder and
        connection; once the pane is closed they belong to nothing, and an
        action there would run on a released connection and refresh a
        deleted widget.
        """
        for dlg, left, right in list(self._compare_dialogs):
            if pane is left or pane is right:
                self._compare_dialogs.remove((dlg, left, right))
                try:
                    dlg.close()
                except RuntimeError:  # already deleted
                    pass

    def _forget_compare_dialog(self, dlg) -> None:
        self._compare_dialogs = [e for e in self._compare_dialogs if e[0] is not dlg]
        # A child of the window: without this every closed Compare window
        # stays alive until the app exits.
        dlg.deleteLater()

    def _compared_panes_open(self, *panes) -> bool:
        """True when every pane of a comparison is still open; else says so."""
        if all(pane in self._panes for pane in panes):
            return True
        QMessageBox.information(
            self,
            "Compare Panes",
            "A pane of this comparison has been closed; compare again.",
        )
        return False

    def _reveal_compared(self, pane, full_path: str) -> None:
        """Navigate ``pane`` to the directory holding ``full_path``."""
        if not self._compared_panes_open(pane):
            return
        parent = full_path.rsplit("/", 1)[0] or "/"
        try:
            pane.navigate_async(parent)
        except OSError as exc:
            log.debug("compare: could not reveal %s: %s", full_path, exc)

    def _apply_sync(self, left, right, items: list) -> None:
        """Carry out a confirmed sync plan.

        Directories are created first — the plan is already ordered
        shallowest-first, so copying into a freshly made directory
        works. Copies go through the normal transfer engine in two
        batches, one per direction, so the transfer dock shows them as
        ordinary transfers.
        """
        if not items or not self._compared_panes_open(left, right):
            return
        made, errors = 0, []
        for item in items:
            if item.get("kind") != "mkdir":
                continue
            target = right if item["direction"] == "to_right" else left
            backend = getattr(target, "backend", None)
            if backend is None:
                continue
            try:
                backend.mkdir(item["dest"])
                made += 1
            except OSError as exc:
                # An existing directory is the normal case on a re-run.
                log.debug("sync: mkdir %s: %s", item["dest"], exc)

        for direction, (source, target) in (
            ("to_right", (left, right)),
            ("to_left", (right, left)),
        ):
            pairs = [
                (i["source"], i["dest"])
                for i in items
                if i["direction"] == direction and i.get("kind") == "copy"
            ]
            if pairs:
                self._transfer_compared(source, target, pairs)

        if errors:
            QMessageBox.warning(
                self, "Sync", f"{len(errors)} step(s) failed:\n" + "\n".join(errors[:10])
            )
        self.statusBar().showMessage(
            f"Sync started: {made} directory/directories created, "
            f"{sum(1 for i in items if i.get('kind') == 'copy')} file(s) queued",
            5000,
        )

    def _copy_compared(self, left, right, direction: str, pairs: list) -> None:
        """Route a comparison copy through the normal transfer engine."""
        if not pairs or not self._compared_panes_open(left, right):
            return
        source, target = (left, right) if direction == "to_right" else (right, left)
        self._transfer_compared(source, target, pairs)

    def _transfer_compared(self, source, target, pairs) -> None:
        """Queue ``(source, dest)`` pairs so each lands at its own path.

        ``_start_transfer_between`` on its own queues into the target
        pane's CURRENT folder: a file from ``sub/`` landed beside the
        compared root's files (or wherever the pane had browsed to) and
        replaced a namesake there. Grouped by destination folder, the
        name is the source's, which a comparison row shares on both sides.
        """
        backend = target.backend
        by_dir: dict[str, list[str]] = {}
        for src, dst in pairs:
            by_dir.setdefault(backend.parent(dst), []).append(src)
        for dest_dir, paths in by_dir.items():
            self._start_transfer_between(source, target, paths, move=False, dest_dir=dest_dir)

    def _delete_compared(self, pane, paths: list) -> None:
        """Delete paths the compare window asked for.

        The dialog has already confirmed and has already refused
        anything that exists on both sides, so this only carries it out
        and reports what failed.
        """
        backend = getattr(pane, "backend", None)
        if backend is None or not paths or not self._compared_panes_open(pane):
            return
        removed, errors = 0, []
        for path in paths:
            try:
                backend.remove(path)
            except OSError as exc:
                errors.append(f"{path}: {exc}")
                continue
            removed += 1
        if errors:
            QMessageBox.warning(
                self,
                "Some deletions failed",
                f"{removed} removed, {len(errors)} failed:\n" + "\n".join(errors[:10]),
            )
        pane.refresh_after_change()

    def _open_disk_usage(self) -> None:
        """Capacity table over every open connection. The probing and
        its timeouts already live in core.dashboard; this is the view."""
        from ui.disk_usage_dialog import DiskUsageDialog, collect_backends

        dlg = DiskUsageDialog(collect_backends(self._panes), parent=self)
        try:
            dlg.exec()
        finally:
            dlg.deleteLater()  # a child of the window: gone once closed

    def _view_media(self, selected_only: bool = False) -> None:
        """View -> View Media…: the media viewer on the active pane."""
        pane = self._active_pane
        if pane is None:
            return
        pane.view_media(selected_only=selected_only)

    def _open_terminal_here(self, pane, directory: str) -> None:
        """A pane's Open Terminal Here: a local shell in *directory*, or a
        shell on the pane's SSH transport that cds into it. The dock comes
        to the front either way; it reports its own failures."""
        from core import terminal_here as TH

        dock = self._terminal_dock
        backend = pane.backend
        kind = TH.shell_kind(backend)
        if kind == TH.LOCAL:
            dock.open_local_shell_at(directory)
        elif kind == TH.SSH:
            dock.open_ssh_shell_at(backend.name, TH.ssh_transport(backend), directory)
        else:
            QMessageBox.information(self, tr("Open Terminal Here"), TH.no_shell_reason(backend))
            return
        # The dock focuses its terminal when a session starts; a refusal
        # (folder gone) is in its status line, so it is shown either way.
        dock.show()
        dock.raise_()

    def _open_cas_duplicates(self, *_args, scan_id: int | None = None) -> None:
        """Open the CAS duplicate-finder. The active pane is wired in
        so the rebuild button has a backend + path to walk; *scan_id*
        opens it on one recorded scan's duplicates."""
        from ui.cas_dialog import CasDuplicatesDialog
        from ui.disk_usage_dialog import collect_backends

        # Every open pane's backend, so a copy on another host can be
        # re-verified as the survivor before a duplicate is trashed.
        dlg = CasDuplicatesDialog(
            active_pane=self._active_pane,
            parent=self,
            backends=collect_backends(self._panes),
            scan_id=scan_id,
        )
        dlg.open_requested.connect(self._on_cas_open)
        dlg.open()

    def _open_cas_history(self) -> None:
        """View > Duplicate Index & History: the index on its own."""
        from ui.cas_history_dialog import CasHistoryDialog
        from ui.disk_usage_dialog import collect_backends

        dlg = CasHistoryDialog(parent=self, backends=collect_backends(self._panes))
        dlg.show_duplicates_requested.connect(lambda sid: self._open_cas_duplicates(scan_id=sid))
        dlg.finished.connect(dlg.deleteLater)
        dlg.show()

    def _on_cas_open(self, backend_id: str, path: str) -> None:
        """Same routing as the metadata search: navigate the active
        pane to the file's directory when the backend matches."""
        from ui.cas_dialog import _backend_id_for

        pane = self._active_pane
        if pane is None:
            return
        if _backend_id_for(pane.backend) != backend_id:
            QMessageBox.information(
                self,
                "CAS",
                f"That file lives on backend [{backend_id}] but the "
                f"active pane is on [{_backend_id_for(pane.backend)}]. "
                "Open the matching session first.",
            )
            return
        try:
            pane.navigate_async(pane.backend.parent(path))
        except OSError as exc:
            QMessageBox.warning(
                self,
                "CAS",
                f"Could not navigate to {path}:\n{exc}",
            )

    def _open_metadata_search(self) -> None:
        """Pop a Find-in-Index dialog. The active pane is wired in so
        the indexer + the optional 'only this backend' scope work
        without the user re-stating the obvious."""
        from ui.metadata_search_dialog import MetadataSearchDialog

        dlg = MetadataSearchDialog(active_pane=self._active_pane, parent=self)
        dlg.open_requested.connect(self._on_metadata_search_open)
        dlg.open()

    def _on_metadata_search_open(self, backend_id: str, path: str, is_dir: bool) -> None:
        """User double-clicked a search result. Navigate the active
        pane to the path's parent (or the path itself if it's a dir)
        when it lives on the active pane's backend; otherwise just
        beep — the index is multi-backend but pane targeting requires
        the right session, which we don't auto-spawn."""
        from ui.metadata_search_dialog import _backend_id_for

        pane = self._active_pane
        if pane is None:
            return
        if _backend_id_for(pane.backend) != backend_id:
            QMessageBox.information(
                self,
                "Find in Index",
                f"That entry lives on backend [{backend_id}] but the "
                f"active pane is on [{_backend_id_for(pane.backend)}]. "
                "Open the matching session first.",
            )
            return
        target = path if is_dir else pane.backend.parent(path)
        try:
            pane.navigate_async(target)
        except OSError as exc:
            QMessageBox.warning(
                self,
                "Find in Index",
                f"Could not navigate to {target}:\n{exc}",
            )

    def _refresh_active(self) -> None:
        if self._active_pane:
            self._active_pane.refresh_async()

    @staticmethod
    def _profile_label(profile: ConnectionProfile) -> str:
        """Return a human-readable label for a connection profile."""
        proto = profile.protocol
        if proto == "s3":
            return f"{profile.name} [S3: {profile.s3_bucket}]"
        if proto == "webdav":
            url = profile.webdav_url[:40] if profile.webdav_url else ""
            return f"{profile.name} [WebDAV: {url}]"
        if proto == "smb":
            return f"{profile.name} [SMB: \\\\{profile.host}\\{profile.smb_share}]"
        if proto == "rsync":
            return f"{profile.name} [Rsync: {profile.host}/{profile.rsync_module}]"
        if proto == "nfs":
            return f"{profile.name} [NFS: {profile.host}:{profile.nfs_export}]"
        if proto == "azure_blob":
            return f"{profile.name} [Azure Blob: {profile.azure_container}]"
        if proto == "azure_files":
            return f"{profile.name} [Azure Files: {profile.azure_share}]"
        if proto == "onedrive":
            return f"{profile.name} [OneDrive]"
        if proto == "sharepoint":
            url = (profile.sharepoint_site_url or "")[:30]
            return f"{profile.name} [SharePoint: {url}]"
        if proto == "gdrive":
            return f"{profile.name} [Google Drive]"
        if proto == "dropbox":
            return f"{profile.name} [Dropbox]"
        if proto == "iscsi":
            return f"{profile.name} [iSCSI: {profile.host}]"
        if proto == "imap":
            return f"{profile.name} [IMAP: {profile.username}@{profile.host}]"
        proto_tag = profile.protocol.upper()
        return f"{profile.name} [{proto_tag}: {profile.username}@{profile.host}:{profile.port}]"

    def _show_quick_connect(self) -> None:
        """Show a popup menu with recent profiles and all saved profiles for quick connect."""
        menu = self._build_quick_connect_menu()

        # Show at a reasonable position
        toolbar = self.findChild(QToolBar)
        if toolbar:
            pos = toolbar.mapToGlobal(toolbar.rect().bottomLeft())
        else:
            pos = self.mapToGlobal(self.rect().topLeft())
        try:
            menu.exec(pos)
        finally:
            menu.deleteLater()

    def _build_quick_connect_menu(self):
        """The Quick Connect list: recent profiles, then all of them. A right
        click on a profile offers Connect, Connect in Background and Edit
        Config (see :mod:`ui.quick_connect_menu`)."""
        from ui.quick_connect_menu import QuickConnectMenu

        menu = QuickConnectMenu(
            "Quick Connect",
            self,
            on_connect=lambda p: self._quick_connect_profile(p),
            on_background=lambda p: self._quick_connect_profile(p, activate=False),
            on_edit=lambda p: self._on_connect(profile=p),
        )

        # Recent profiles (with number shortcuts 1-8)
        if self._recent_profiles:
            menu.addSection("Recent")
            for i, name in enumerate(self._recent_profiles[:8]):
                profile = self._profile_manager.get(name)
                if not profile:
                    continue
                menu.add_profile(f"&{i + 1}  {self._profile_label(profile)}", profile)

        # All saved profiles
        all_names = self._profile_manager.list_names()
        if all_names:
            menu.addSection("All Profiles")
            for name in all_names:
                profile = self._profile_manager.get(name)
                if not profile:
                    continue
                menu.add_profile(self._profile_label(profile), profile)

        if menu.isEmpty():
            action = menu.addAction(tr("No profiles — open Connection Manager"))
            action.triggered.connect(self._on_connect)

        menu.addSeparator()
        manager_action = menu.addAction(tr("Connection Manager... [Ctrl+Shift+N]"))
        manager_action.triggered.connect(lambda _checked=False: self._on_connect())
        return menu

    def _run_connect_async(
        self,
        profile: "ConnectionProfile",
        password: str,
        key_passphrase: str,
        on_success,
        on_failure,
    ) -> None:
        """Start a background connect so the GUI stays responsive.

        ``on_success(session)`` and ``on_failure(exc)`` run on the GUI
        thread via queued signals. The returned task is appended to
        ``self._connect_tasks``; we sweep out already-finished entries
        each call so rapid reconnects don't pile up, but we do NOT
        tear down a still-running predecessor (that would block the
        GUI on ``thread.wait``).
        """
        from core.connect_worker import run_connect

        # Drop tasks whose thread has already exited. A still-running
        # task stays in the list until its own ``finished`` fires.
        self._connect_tasks = [
            t for t in self._connect_tasks if t.thread is not None and t.thread.isRunning()
        ]
        if hasattr(self, "statusBar") and self.statusBar():
            self.statusBar().showMessage(
                f"Connecting to {profile.name}…",
                0,
            )

        def _wrap_success(session):
            try:
                if hasattr(self, "statusBar") and self.statusBar():
                    self.statusBar().clearMessage()
                on_success(session)
            except Exception as exc:  # noqa: BLE001
                log.error("post-connect handler failed: %s", exc, exc_info=True)

        def _wrap_failure(exc):
            try:
                if hasattr(self, "statusBar") and self.statusBar():
                    self.statusBar().clearMessage()
                on_failure(exc)
            except Exception as handler_exc:  # noqa: BLE001
                log.error(
                    "connect failure handler raised: %s (original failure was: %s)",
                    handler_exc,
                    exc,
                    exc_info=True,
                )

        task = run_connect(
            self._connection_manager,
            profile,
            password=password,
            key_passphrase=key_passphrase,
            host_key_prompt=self._confirm_unknown_host,
            on_success=_wrap_success,
            on_failure=_wrap_failure,
        )
        self._connect_tasks.append(task)

    def _quick_connect_profile(
        self,
        profile: ConnectionProfile,
        *,
        post_connect=None,
        activate: bool = True,
    ) -> None:
        """Connect to a profile, prompting for password if needed.

        ``activate=False`` (Quick Connect's "Connect in Background") adds
        the new pane without making it the active one.

        ``post_connect`` is an optional callable ``(pane) -> None``
        run after the new pane lands. Used by ``_navigate_bookmark``
        to navigate to the bookmark's path once the connection
        succeeds — routing bookmark opens through this method means
        bookmarks inherit the same password-prompt + save-to-keyring
        flow Quick Connect uses instead of silently failing when
        ``store_password`` is False.
        """
        password = ""
        key_passphrase = ""
        stored: str | None = None

        proto = getattr(profile, "protocol", "sftp")
        needs_password = False
        prompt_label = ""

        if proto in ("sftp", "scp"):
            if profile.auth_type == "password":
                needs_password = True
                prompt_label = f"Password for {profile.username}@{profile.host}:"
            elif profile.auth_type == "key" and profile.key_file:
                # Try without passphrase first; if key is encrypted, ask
                pass
        elif proto == "s3":
            # Only prompt for secret key if access key is set (not anonymous)
            if profile.username:
                needs_password = True
                prompt_label = f"Secret Key for S3 bucket '{profile.s3_bucket}':"
        elif proto == "webdav":
            url = (profile.webdav_url or "")[:50]
            needs_password = True
            prompt_label = f"Password for WebDAV {url}:"
        elif proto in ("ftp", "ftps"):
            needs_password = True
            prompt_label = f"Password for {proto.upper()} {profile.username}@{profile.host}:"
        elif proto == "smb":
            needs_password = True
            prompt_label = f"Password for SMB \\\\{profile.host}\\{profile.smb_share}:"
        elif proto == "rsync" and not profile.rsync_ssh:
            needs_password = True
            prompt_label = f"Password for rsync {profile.host}/{profile.rsync_module}:"
        elif proto in ("azure_blob", "azure_files"):
            needs_password = True
            prompt_label = f"Account Key for Azure {profile.azure_account_name}:"
        elif proto == "iscsi":
            needs_password = True
            prompt_label = f"CHAP password for iSCSI {profile.host}:"
        elif proto == "imap":
            needs_password = True
            prompt_label = f"Password for IMAP {profile.username}@{profile.host}:"
        # OAuth protocols (onedrive, sharepoint, gdrive, dropbox) don't need password prompts
        # NFS doesn't need password

        if needs_password:
            # Try stored credential first
            from core.credentials import get_password as _get_stored_pw

            stored = _get_stored_pw(profile.name)
            if stored:
                password = stored
            else:
                from PyQt6.QtWidgets import QInputDialog

                title = "Secret Key" if proto == "s3" else "Password"
                pw, ok = QInputDialog.getText(
                    self,
                    title,
                    prompt_label,
                    QLineEdit.EchoMode.Password,
                )
                if not ok:
                    return
                password = pw

        def _on_success(session):
            pane = self._add_pane_to_splitter(
                self._root_splitter,
                session,
                profile=profile,
                password=password,
                key_passphrase=key_passphrase,
            )
            if activate:
                self._set_active_pane(pane)

            if (
                hasattr(session, "transport")
                and session.transport
                and session.transport.is_active()
            ):
                self._terminal_dock.add_ssh_session(session.name, session.transport)

            # Post-connect hook (used by bookmark navigation to
            # land the new pane on the bookmarked path).
            if post_connect is not None:
                try:
                    post_connect(pane)
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "post_connect hook failed: %s",
                        exc,
                    )

            # Offer to save password if it was manually entered
            if password and not stored and not profile.store_password:
                from core.credentials import (
                    is_keyring_available,
                    keyring_status_message,
                )
                from core.credentials import (
                    store_password as _store_pw,
                )

                if not is_keyring_available():
                    # Don't even ask — the OS can't persist it. Show
                    # one warning so the user knows why "Save password"
                    # isn't on offer.
                    QMessageBox.warning(
                        self,
                        "Password not saved",
                        keyring_status_message(),
                    )
                else:
                    reply = QMessageBox.question(
                        self,
                        "Save Password",
                        f"Save password for '{profile.name}' in the system keyring?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        if _store_pw(profile.name, password):
                            profile.store_password = True
                            self._profile_manager.add(profile)
                            log.info("Password saved to keyring for %s", profile.name)
                        else:
                            QMessageBox.warning(
                                self,
                                "Password not saved",
                                keyring_status_message()
                                or "Could not persist password — see axross.log.",
                            )

            self._add_to_recent(profile.name)
            log.info("Quick connected to %s", session.name)

        def _on_failure(exc):
            QMessageBox.critical(self, "Connection Failed", str(exc))
            log.error("Quick connect failed: %s", exc)

        self._run_connect_async(
            profile,
            password,
            key_passphrase,
            _on_success,
            _on_failure,
        )

    _RECENTS_FILE = Path.home() / ".config" / "axross" / "recents.json"
    # The viewers and the language setting read and write the same file.
    _SESSION_FILE = i18n.SETTINGS_FILE

    def _add_to_recent(self, name: str) -> None:
        """Add a profile name to the recent list (max 8, deduplicated) and persist."""
        if name in self._recent_profiles:
            self._recent_profiles.remove(name)
        self._recent_profiles.insert(0, name)
        self._recent_profiles = self._recent_profiles[:8]
        self._save_recents()

    def _save_recents(self) -> None:
        try:
            _write_private_text(
                self._RECENTS_FILE,
                json.dumps(self._recent_profiles),
            )
        except OSError as e:
            log.debug("Could not save recents: %s", e)

    @staticmethod
    def _load_recents() -> list[str]:
        try:
            data = _read_json_file(MainWindow._RECENTS_FILE)
            if isinstance(data, list):
                return [s for s in data if isinstance(s, str)][:8]
        except (OSError, ValueError):
            pass
        return []

    # --- Session save / restore ---

    def _load_persistent_visual_settings(self) -> None:
        """Read the subset of session.json that represents user
        preferences: theme, monochrome icons and the "Restore Layout on
        Start" switch. The layout itself is restore_layout_on_start's job.

        Guarantee kept from before the layout came back on start: a fresh
        start never connects to anything. Remote panes of the restored
        layout are placeholders until the user clicks Reconnect.
        """
        try:
            if not self._SESSION_FILE.exists():
                return
            data = _read_json_file(self._SESSION_FILE)
        except (OSError, ValueError) as exc:
            log.debug(
                "Persistent visual settings: could not read %s: %s",
                self._SESSION_FILE,
                exc,
            )
            return
        win = data.get("window") if isinstance(data, dict) else None
        if not isinstance(win, dict):
            return
        if win.get("ui_theme"):
            self._apply_theme(win["ui_theme"])
        # Only a stored False switches it off; anything else is the default.
        if win.get(RESTORE_ON_START_KEY) is False and hasattr(self, "_restore_on_start_action"):
            self._restore_on_start_action.setChecked(False)
        mono = bool(win.get("monochrome_icons", False))
        if mono and hasattr(self, "_monochrome_action"):
            # setChecked fires the toggle handler → icons
            # re-rasterise, dock titles rebuild.
            self._monochrome_action.setChecked(True)

    def _save_session(self) -> None:
        """Save current pane layout and connections for later restore."""
        from ui.icon_provider import is_monochrome as _is_mono

        # session.json is shared: core.i18n.store_language keeps the
        # language the user picked in window.language. Keep what this
        # window does not write itself instead of dropping it.
        try:
            previous = _read_json_file(self._SESSION_FILE)
        except (OSError, ValueError):
            previous = None
        session = previous if isinstance(previous, dict) else {}
        window = session.get("window")
        if not isinstance(window, dict):
            window = {}
        window.update(
            {
                "width": self.width(),
                "height": self.height(),
                "ui_theme": self._current_theme,
                "compact": self._compact_mode,
                "monochrome_icons": _is_mono(),
                RESTORE_ON_START_KEY: self._restore_on_start_action.isChecked(),
                # Base64 of Qt's own formats: window geometry and the dock
                # layout (which docks are open, where, and how large).
                "geometry": bytes(self.saveGeometry().toBase64()).decode("ascii"),
                "dock_state": bytes(self.saveState().toBase64()).decode("ascii"),
            }
        )
        session["splitter"] = self._serialize_splitter(self._root_splitter)
        session["window"] = window
        try:
            _write_private_text(
                self._SESSION_FILE,
                json.dumps(session, indent=2),
            )
            log.info("Session saved (%d panes)", len(self._panes))
        except OSError as e:
            log.warning("Could not save session: %s", e)

    def _serialize_splitter(self, splitter: QSplitter) -> dict:
        """Recursively serialize a splitter tree to JSON-friendly dict.

        File panes, terminal panes and disconnected placeholders are
        written; anything else is left out together with its size, so the
        sizes still match the children on restore."""
        children = []
        sizes = []
        all_sizes = splitter.sizes()
        for i in range(splitter.count()):
            child = splitter.widget(i)
            if isinstance(child, QSplitter):
                entry = self._serialize_splitter(child)
            elif isinstance(child, FilePaneWidget):
                entry = self._serialize_pane(child)
            elif isinstance(child, TerminalPaneWidget):
                entry = self._serialize_terminal(child)
            elif isinstance(child, DisconnectedPanePlaceholder):
                entry = child.serialize()
            else:
                entry = None
            if entry is None:
                continue
            children.append(entry)
            sizes.append(all_sizes[i] if i < len(all_sizes) else 0)
        return {
            "type": "splitter",
            "orientation": "horizontal"
            if splitter.orientation() == Qt.Orientation.Horizontal
            else "vertical",
            "sizes": sizes,
            "children": children,
        }

    @staticmethod
    def _serialize_terminal(term: TerminalPaneWidget) -> dict | None:
        """A local shell with its folder, or the profile of a remote one. A
        shell on a transport without a profile cannot be opened again and
        is left out."""
        if term.is_local:
            entry: dict = {"type": "terminal", "local": True}
            cwd = term.working_directory()
            if cwd:
                entry["cwd"] = cwd
            return entry
        if term.profile is not None:
            return {"type": "terminal", "profile": term.profile.name}
        return None

    def _serialize_pane(self, pane: FilePaneWidget) -> dict:
        """Serialize a single pane's state."""
        profile = self._pane_profiles.get(pane)
        is_active = pane is self._active_pane
        is_target = pane is self._target_pane
        entry: dict = {
            "type": "pane",
            "path": pane.current_path,
            "active": is_active,
            "target": is_target,
        }
        if profile:
            entry["profile"] = profile.name
        else:
            entry["local"] = True
        return entry

    def _restore_session(self) -> None:
        """File > Restore Last Session: rebuild the saved layout now. Asked
        for by the user, so remote file panes connect (prompting for what
        they need) and problems are reported in a dialog."""
        try:
            data = _read_json_file(self._SESSION_FILE)
        except (OSError, ValueError) as e:
            QMessageBox.information(
                self,
                "Restore Session",
                f"No saved session found.\n{e}",
            )
            return

        # Checked in full before anything is torn down: a tree that fails
        # half-way through the rebuild leaves the window without its panes.
        problem = _session_problem(data)
        if problem:
            QMessageBox.information(
                self,
                "Restore Session",
                f"The saved session cannot be restored.\n{problem}",
            )
            return

        if not data.get("splitter", {}).get("children"):
            QMessageBox.information(
                self,
                "Restore Session",
                "Saved session is empty.",
            )
            return
        self._apply_session(data, connect_remote=True)

    def restore_layout_on_start(self) -> bool:
        """Rebuild the last session's layout as the application starts
        (main.py calls it before the window is shown). True when a layout
        was restored.

        Never connects and never asks: remote file panes and profile
        terminals come back as DisconnectedPanePlaceholder with a
        Reconnect button; local panes and local shells come back as they
        were. Switched off (File > Restore Layout on Start), or with a
        missing, unreadable or invalid session.json, the default layout
        stays and the reason goes to the log only."""
        if not self._restore_on_start_action.isChecked():
            log.info("Layout restore on start is switched off")
            return False
        try:
            data = _read_json_file(self._SESSION_FILE)
        except FileNotFoundError:
            return False
        except (OSError, ValueError) as exc:
            log.warning("Layout not restored: cannot read %s: %s", self._SESSION_FILE, exc)
            return False
        problem = _session_problem(data)
        if problem:
            log.warning("Layout not restored from %s: %s", self._SESSION_FILE, problem)
            return False
        if not data.get("splitter", {}).get("children"):
            return False
        try:
            self._apply_session(data, connect_remote=False)
        except Exception:  # noqa: BLE001 - a bad layout must not stop the start
            log.exception("Layout restore failed; starting with the default layout")
            self._reset_to_default_layout()
            return False
        return True

    def _reset_to_default_layout(self) -> None:
        """One local pane in a fresh root splitter, whatever was there."""
        self._preset_tear_down_existing()
        self._setup_central()
        self._refresh_after_preset()

    def _set_restore_on_start(self, checked: bool) -> None:
        """File > Restore Layout on Start: stored at once, not only on close."""
        try:
            previous = _read_json_file(self._SESSION_FILE)
        except (OSError, ValueError):
            previous = None
        session = previous if isinstance(previous, dict) else {}
        window = session.get("window")
        if not isinstance(window, dict):
            window = {}
        window[RESTORE_ON_START_KEY] = bool(checked)
        session["window"] = window
        try:
            _write_private_text(self._SESSION_FILE, json.dumps(session, indent=2))
        except OSError as exc:
            log.warning("Could not store the layout restore switch: %s", exc)

    def _tear_down_for_restore(self) -> None:
        """Close every pane, terminal and placeholder before a rebuild."""
        # Terminal panes first: clearing the splitters below would delete a
        # nested one with its splitter while it stayed listed and its shell
        # ran on, and closeEvent then failed on the dead widget.
        for term in list(self._terminal_panes):
            self._close_terminal_pane(term)
        for placeholder in list(self._pane_placeholders):
            self._close_placeholder(placeholder)

        # Close all existing panes
        for pane in list(self._panes):
            if len(self._panes) > 1:
                self._close_pane(pane)

        # Remove the last remaining pane manually (including SSH terminal cleanup)
        if self._panes:
            last = self._panes[0]
            profile = self._pane_profiles.pop(last, None)
            self._pane_passwords.pop(last, None)
            self._pane_key_passphrases.pop(last, None)
            if _is_ssh_session(last.backend):
                self._terminal_dock.remove_ssh_session(last.backend.name)
            if profile:
                self._connection_manager.release(profile)
            self._panes.remove(last)
            last.setParent(None)
            last.deleteLater()
            self._active_pane = None
            self._target_pane = None

        # Clear root splitter
        while self._root_splitter.count() > 0:
            w = self._root_splitter.widget(0)
            w.setParent(None)

    def _apply_session(self, data: dict, *, connect_remote: bool) -> None:
        """Replace the layout and window state with a validated session
        (see _session_problem). *connect_remote* False: remote panes become
        placeholders instead of connecting."""
        splitter_data = data.get("splitter", {})

        # Pause reconnect timer to avoid race conditions during restore
        self._reconnect_timer.stop()
        try:
            self._tear_down_for_restore()
            # Rebuild from saved layout
            active_pane, target_pane = self._restore_splitter(
                self._root_splitter, splitter_data, connect_remote=connect_remote
            )
        finally:
            # Always restart reconnect timer
            self._reconnect_timer.start()

        win = data.get("window", {})
        # Window geometry and dock layout in Qt's own format; restoreGeometry
        # and restoreState refuse data they cannot parse. Without them
        # (sessions of 0.10.10 and older) the saved size is used.
        geometry = _decode_window_state(win.get("geometry"))
        if geometry is None or not self.restoreGeometry(QByteArray(geometry)):
            width, height = win.get("width"), win.get("height")
            if (
                isinstance(width, int)
                and isinstance(height, int)
                and not isinstance(width, bool)
                and not isinstance(height, bool)
                and 0 < width <= MAX_RESTORED_WINDOW_PX
                and 0 < height <= MAX_RESTORED_WINDOW_PX
            ):
                self.resize(width, height)
        dock_state = _decode_window_state(win.get("dock_state"))
        if dock_state is not None and not self.restoreState(QByteArray(dock_state)):
            log.info("Session restore: the saved dock layout was not usable")
        self._compact_action.setChecked(bool(win.get("compact", False)))
        # ``theme`` is the pre-modern key and is deliberately ignored:
        # the modern theme became the default for everyone, and the old
        # key could not tell a deliberate choice from the old default.
        if win.get("ui_theme"):
            self._apply_theme(win["ui_theme"])
        # Restore monochrome-icons setting. Guarded: the action only
        # exists after _setup_menubar ran, which always precedes
        # _restore_session. The toggle path handles the icon cache
        # reset + UI rebuild for us.
        if hasattr(self, "_monochrome_action"):
            self._monochrome_action.setChecked(
                bool(win.get("monochrome_icons", False)),
            )

        # Set active/target
        if active_pane and active_pane in self._panes:
            self._active_pane = active_pane
        elif self._panes:
            self._active_pane = self._panes[0]

        if target_pane and target_pane in self._panes and target_pane is not self._active_pane:
            self._target_pane = target_pane
        elif len(self._panes) > 1:
            self._target_pane = next(p for p in self._panes if p is not self._active_pane)

        # Force all panes visible (Qt may hide widgets during reparenting)
        for pane in self._panes:
            pane.show()
        self._root_splitter.show()

        self._refresh_pane_styles()
        log.info(
            "Session restored (%d panes, %d terminals, %d disconnected)",
            len(self._panes),
            len(self._terminal_panes),
            len(self._pane_placeholders),
        )

    def _restore_splitter(
        self, splitter: QSplitter, data: dict, *, connect_remote: bool = True
    ) -> tuple[FilePaneWidget | None, FilePaneWidget | None]:
        """Recursively restore a splitter tree from serialized data.

        Returns (active_pane, target_pane) if found in this subtree.
        """
        active_pane = None
        target_pane = None

        orientation = data.get("orientation", "horizontal")
        if orientation == "vertical":
            splitter.setOrientation(Qt.Orientation.Vertical)
        else:
            splitter.setOrientation(Qt.Orientation.Horizontal)

        for child in data.get("children", []):
            kind = child.get("type", "splitter")
            if kind == "splitter":
                child_splitter = QSplitter()
                splitter.addWidget(child_splitter)
                a, t = self._restore_splitter(
                    child_splitter, child, connect_remote=connect_remote
                )
                if child_splitter.count() == 0:
                    # Nothing restorable inside: no empty splitter on screen.
                    child_splitter.setParent(None)
                    child_splitter.deleteLater()
                    continue
                if a:
                    active_pane = a
                if t:
                    target_pane = t
            elif kind == "pane":
                pane = self._restore_pane(splitter, child, connect_remote=connect_remote)
                if pane:
                    if child.get("active"):
                        active_pane = pane
                    if child.get("target"):
                        target_pane = pane
            elif kind == "terminal":
                self._restore_terminal(splitter, child, connect_remote=connect_remote)

        # Restore splitter sizes, ensuring no pane gets 0 pixels
        sizes = sanitize_splitter_sizes(data.get("sizes"), splitter.count())
        if sizes:
            splitter.setSizes(sizes)

        # Ensure all children are visible
        for i in range(splitter.count()):
            w = splitter.widget(i)
            if w and not w.isVisible():
                w.show()

        return active_pane, target_pane

    @staticmethod
    def _existing_local_folder(path) -> str:
        """*path* when it is a local folder, else the home folder: a folder
        removed since the session was saved is no error worth a dialog."""
        if isinstance(path, str) and path and os.path.isdir(path):
            return path
        return str(Path.home())

    def _restore_terminal(self, splitter: QSplitter, data: dict, *, connect_remote: bool) -> None:
        """A local shell (fresh, in its saved folder or home), or a profile
        terminal: a placeholder unless *connect_remote*."""
        profile_name = data.get("profile")
        if data.get("local") or not profile_name:
            cwd = self._existing_local_folder(data.get("cwd"))
            splitter.addWidget(self._preset_make_terminal_pane("local", cwd=cwd))
            return
        if not connect_remote:
            self._make_placeholder(splitter, KIND_TERMINAL, profile_name)
            return
        splitter.addWidget(self._preset_make_terminal_pane(profile_name))

    def _restore_pane(
        self, splitter: QSplitter, data: dict, *, connect_remote: bool = True
    ) -> FilePaneWidget | None:
        """Restore a single pane from serialized data. A remote pane connects
        only with *connect_remote*; else it becomes a placeholder (None)."""
        path = data.get("path", "/")
        profile_name = data.get("profile")

        if data.get("local") or not profile_name:
            # Local pane
            path = self._existing_local_folder(path)
            pane = self._add_pane_to_splitter(splitter, LocalFS())
            try:
                pane.navigate_async(path)
            except Exception:
                log.warning(
                    "Session restore: failed to navigate local pane to %s", path, exc_info=True
                )
            return pane

        if not connect_remote:
            self._make_placeholder(splitter, KIND_PANE, profile_name, path)
            return None

        # Remote pane — try to reconnect
        profile = self._profile_manager.get(profile_name)
        if not profile:
            log.warning("Session restore: profile %r not found, using local pane", profile_name)
            pane = self._add_pane_to_splitter(splitter, LocalFS())
            return pane

        # Get stored password from keyring (non-blocking)
        password = ""
        key_passphrase = ""
        if profile.store_password:
            from core.credentials import get_password

            password = get_password(profile.name) or ""

        auth = getattr(profile, "auth_type", "password")

        # Determine what kind of credential prompt (if any) is needed
        # No prompt: NFS, SSH agent, OAuth protocols, or password already retrieved
        no_prompt_protocols = ("nfs", "onedrive", "sharepoint", "gdrive", "dropbox")
        needs_no_prompt = (
            profile.protocol in no_prompt_protocols
            or auth == "agent"
            or password  # already have it from keyring
        )

        if not needs_no_prompt:
            from PyQt6.QtWidgets import QInputDialog, QLineEdit

            if auth == "key":
                # SSH key auth — may need key passphrase
                label = (
                    f"Session restore: Key passphrase for "
                    f"'{profile.name}'\n"
                    f"{profile.username}@{profile.host}:{profile.port}\n"
                    f"Key: {profile.key_file}\n"
                    f"(leave empty if key has no passphrase)"
                )
                key_passphrase, ok = QInputDialog.getText(
                    self,
                    "Session Restore — Key Passphrase",
                    label,
                    QLineEdit.EchoMode.Password,
                )
                if not ok:
                    log.info(
                        "Session restore: user cancelled passphrase for %s, using local pane",
                        profile_name,
                    )
                    pane = self._add_pane_to_splitter(splitter, LocalFS())
                    return pane
            else:
                # Password-based auth (SSH password, FTP, Telnet, SMB, etc.)
                label = (
                    f"Session restore: Password for "
                    f"'{profile.name}'\n"
                    f"{profile.username}@{profile.host}:{profile.port}"
                )
                password, ok = QInputDialog.getText(
                    self,
                    "Session Restore — Password Required",
                    label,
                    QLineEdit.EchoMode.Password,
                )
                if not ok:
                    log.info(
                        "Session restore: user cancelled password for %s, using local pane",
                        profile_name,
                    )
                    pane = self._add_pane_to_splitter(splitter, LocalFS())
                    return pane

        try:
            session = self._connection_manager.connect(
                profile,
                password=password,
                key_passphrase=key_passphrase,
                on_unknown_host=self._confirm_unknown_host,
            )
            pane = self._add_pane_to_splitter(
                splitter,
                session,
                profile=profile,
                password=password,
                key_passphrase=key_passphrase,
            )
            # Register SSH terminal
            if (
                hasattr(session, "transport")
                and session.transport
                and session.transport.is_active()
            ):
                self._terminal_dock.add_ssh_session(session.name, session.transport)
            self._add_to_recent(profile.name)
            try:
                pane.navigate_async(path)
            except Exception:
                log.warning(
                    "Session restore: failed to navigate to %s on %s",
                    path,
                    profile.name,
                    exc_info=True,
                )
            log.info("Session restore: reconnected to %s", profile.name)
            return pane
        except Exception as e:
            log.warning("Session restore: could not connect to %s: %s", profile_name, e)
            # Fall back to local pane
            pane = self._add_pane_to_splitter(splitter, LocalFS())
            return pane

    def _show_network_proxy(self) -> None:
        from ui.network_proxy_dialog import NetworkProxyDialog

        dialog = NetworkProxyDialog(self._profile_manager, parent=self)
        try:
            accepted = dialog.exec()
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed
        if accepted:
            for pane in list(self._panes):
                self._refresh_proxy_indicator(pane)

    def _refresh_proxy_indicator(self, pane) -> None:
        """Show (or clear) the pane's proxy route; never contains a secret."""
        profile = self._pane_profiles.get(pane)
        if profile is None:
            pane.set_proxy_info("", "")
            return
        from core import proxy_settings

        try:
            res = proxy_settings.resolve_for_profile(profile)
        except Exception as exc:  # noqa: BLE001 - e.g. an unreachable PAC file
            pane.set_proxy_info("Proxy: ?", f"Proxy could not be resolved: {exc}")
            return
        if res.config is None:
            pane.set_proxy_info("", res.description)
        else:
            cfg = res.config
            label = f"via {cfg.proxy_type.upper()} {cfg.host}:{cfg.port}"
            pane.set_proxy_info(label, res.description)

    def _on_connect(self, _checked: bool = False, *, profile=None) -> None:
        """The connection dialog; with *profile* it opens with that profile
        loaded (Quick Connect's "Edit Config…")."""
        from ui.connection_dialog import ConnectionDialog

        dialog = ConnectionDialog(self._profile_manager, parent=self, profile=profile)
        try:
            if dialog.exec() != ConnectionDialog.DialogCode.Accepted or not dialog.result_profile:
                return
            profile = dialog.result_profile
            password = dialog.result_password
            key_passphrase = dialog.result_key_passphrase
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed

        def _on_success(session):
            pane = self._add_pane_to_splitter(
                self._root_splitter,
                session,
                profile=profile,
                password=password,
                key_passphrase=key_passphrase,
            )
            self._set_active_pane(pane)

            if (
                hasattr(session, "transport")
                and session.transport
                and session.transport.is_active()
            ):
                self._terminal_dock.add_ssh_session(session.name, session.transport)

            if password and not profile.store_password:
                reply = QMessageBox.question(
                    self,
                    "Save Password",
                    f"Save password for '{profile.name}' in the system keyring?\n"
                    "This allows automatic reconnection.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    from core.credentials import store_password as _store_pw

                    if _store_pw(profile.name, password):
                        profile.store_password = True
                        self._profile_manager.add(profile)
                        log.info("Password saved to keyring for %s", profile.name)
                    else:
                        QMessageBox.warning(
                            self,
                            "Keyring Error",
                            "Could not save password to system keyring.",
                        )

            if not self._profile_manager.get(profile.name):
                self._profile_manager.add(profile)
            self._add_to_recent(profile.name)
            log.info("Connected to %s", session.name)

        def _on_failure(exc):
            QMessageBox.critical(self, "Connection Failed", str(exc))
            log.error("Connection failed: %s", exc)

        self._run_connect_async(
            profile,
            password,
            key_passphrase,
            _on_success,
            _on_failure,
        )

    def _import_ssh_hosts(self, hosts: list, source: str) -> None:
        """Import parsed SSH host configs into connection profiles."""
        if not hosts:
            QMessageBox.information(self, "SSH Config", f"No hosts found in {source}")
            return

        imported = 0
        for host in hosts:
            if self._profile_manager.get(host.alias):
                continue

            hostname = host.hostname or host.alias
            auth_type = "key" if host.identity_file else "password"

            profile = ConnectionProfile(
                name=host.alias,
                host=hostname,
                port=host.port,
                username=host.user or "",
                auth_type=auth_type,
                key_file=host.identity_file,
                proxy_command=host.proxy_command,
                address_family=host.address_family,
            )
            try:
                self._profile_manager.add(profile)
            except ValueError as exc:  # a name that would share a keyring entry
                log.warning("Not importing SSH host %r: %s", host.alias, exc)
                continue
            imported += 1

        log.info("Imported %d profiles from %s", imported, source)
        QMessageBox.information(
            self,
            "SSH Config Import",
            f"Imported {imported} new profile(s) from {source}\n"
            f"({len(hosts) - imported} already existed)",
        )

    def _import_ssh_config(self) -> None:
        """Import hosts from ~/.ssh/config."""
        from core.ssh_config import parse_ssh_config

        self._import_ssh_hosts(parse_ssh_config(), "~/.ssh/config")

    def _import_ssh_config_file(self) -> None:
        """Import hosts from a user-selected SSH config file."""
        from pathlib import Path

        from PyQt6.QtWidgets import QFileDialog

        from core.ssh_config import parse_ssh_config

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import SSH Config",
            str(Path.home() / ".ssh"),
            "Config Files (config *.conf *.cfg);;All Files (*)",
        )
        if not path:
            return
        self._import_ssh_hosts(parse_ssh_config(Path(path)), path)

    def _import_ssh_config_paste(self) -> None:
        """Import hosts from pasted SSH config text."""
        import tempfile
        from pathlib import Path

        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

        from core.ssh_config import parse_ssh_config

        dlg = QDialog(self)
        dlg.setWindowTitle("Paste SSH Config")
        dlg.resize(520, 380)
        layout = QVBoxLayout(dlg)

        text_edit = QPlainTextEdit()
        text_edit.setPlaceholderText(
            "Paste SSH config here, e.g.:\n\n"
            "Host myserver\n"
            "    Hostname 192.168.1.10\n"
            "    User admin\n"
            "    Port 22\n"
            "    IdentityFile ~/.ssh/id_rsa\n"
            "    ProxyCommand ssh -W %h:%p jumphost"
        )
        layout.addWidget(text_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        config_text = text_edit.toPlainText().strip()
        if not config_text:
            return

        # Write to temp file and parse (reuses existing parser)
        with tempfile.NamedTemporaryFile("w", suffix=".sshconfig", delete=False) as tmp:
            tmp.write(config_text)
            tmp_path = Path(tmp.name)
        try:
            hosts = parse_ssh_config(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self._import_ssh_hosts(hosts, "pasted config")

    def _import_profiles_json(self) -> None:
        """Import connection profiles from a JSON file."""
        from PyQt6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getOpenFileName(
            self, "Import Profiles", "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return

        try:
            data = _read_json_file(path, max_bytes=MAX_PROFILE_IMPORT_BYTES)
        except (ValueError, OSError) as e:
            QMessageBox.warning(self, "Import Error", f"Cannot read file:\n{e}")
            return

        if not isinstance(data, dict):
            QMessageBox.warning(
                self, "Import Error", "Expected a JSON object with profile names as keys."
            )
            return

        imported = 0
        skipped = 0
        failed: list[tuple[str, str]] = []
        warnings: list[tuple[str, str]] = []

        for name, profile_data in data.items():
            if not isinstance(profile_data, dict):
                continue
            # Extract inline password before building profile (not stored in JSON)
            inline_pw = profile_data.pop("_password", None)
            try:
                profile = ConnectionProfile.from_dict(profile_data)
            except Exception as e:
                # Parse error — that's a *failure*, not "already
                # existed". Surface it so users can fix the JSON.
                failed.append((name, f"parse error: {e}"))
                log.warning("Profile %s parse failed: %s", name, e)
                continue

            if self._profile_manager.get(profile.name):
                skipped += 1
                continue

            # ``add()`` can raise RuntimeError if the keyring refuses a
            # sensitive field (headless system, locked keyring, DBus
            # session missing). Catch so one bad profile doesn't abort
            # the whole import.
            try:
                self._profile_manager.add(profile)
            except RuntimeError as add_exc:
                failed.append((profile.name, str(add_exc)))
                log.warning("Profile %s import failed: %s", profile.name, add_exc)
                continue
            except Exception as add_exc:  # noqa: BLE001
                failed.append((profile.name, f"{type(add_exc).__name__}: {add_exc}"))
                log.exception(
                    "Profile %s import failed with %s", profile.name, type(add_exc).__name__
                )
                continue

            if inline_pw and profile.store_password:
                try:
                    profile.set_password(inline_pw)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        (
                            profile.name,
                            f"password not stored in keyring: {exc}",
                        )
                    )
                    log.warning("Could not store password for %s: %s", profile.name, exc)
            imported += 1

        log.info(
            "Imported %d profiles from %s (%d skipped, %d failed, %d warn)",
            imported,
            path,
            skipped,
            len(failed),
            len(warnings),
        )
        msg_lines = [
            f"Imported {imported} profile(s) from:\n{path}",
            f"({skipped} skipped / already existed)",
        ]
        LIMIT = 8
        if failed:
            shown = failed[:LIMIT]
            joined = "\n".join(f"  - {n}: {err}" for n, err in shown)
            more = len(failed) - len(shown)
            suffix = f"\n  ...and {more} more" if more > 0 else ""
            msg_lines.append(f"\n{len(failed)} failed (keyring unavailable?):\n{joined}{suffix}")
        if warnings:
            shown = warnings[:LIMIT]
            joined = "\n".join(f"  - {n}: {w}" for n, w in shown)
            more = len(warnings) - len(shown)
            suffix = f"\n  ...and {more} more" if more > 0 else ""
            msg_lines.append(f"\n{len(warnings)} warning(s):\n{joined}{suffix}")
        QMessageBox.information(
            self,
            "Profile Import",
            "\n".join(msg_lines),
        )

    def _export_profiles_json(self) -> None:
        """Export all connection profiles to a JSON file."""
        from PyQt6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Profiles", "profiles.json", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return

        profiles = self._profile_manager.all_profiles()
        data = {p.name: p.to_dict() for p in profiles}

        try:
            _write_private_text(
                path,
                json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            )
        except OSError as e:
            QMessageBox.warning(self, "Export Error", f"Cannot write file:\n{e}")
            return

        QMessageBox.information(
            self, "Profile Export", f"Exported {len(data)} profile(s) to:\n{path}"
        )

    def _view_all_profiles(self) -> None:
        """Show all saved profiles in a read-only text dialog."""
        import json

        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

        profiles = self._profile_manager.all_profiles()
        if not profiles:
            QMessageBox.information(self, "Profiles", "No saved profiles.")
            return

        data = {p.name: p.to_dict() for p in profiles}
        text = json.dumps(data, indent=2, ensure_ascii=False)

        dlg = QDialog(self)
        dlg.setWindowTitle(f"All Profiles ({len(profiles)})")
        dlg.resize(600, 480)
        layout = QVBoxLayout(dlg)
        add_close_corner(dlg)

        editor = QPlainTextEdit()
        editor.setPlainText(text)
        editor.setReadOnly(True)
        layout.addWidget(editor)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)

        dlg.exec()

    def _show_text_dialog(self, title: str, text: str) -> None:
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(720, 520)
        layout = QVBoxLayout(dlg)
        add_close_corner(dlg)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(text)
        layout.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        dlg.exec()

    def _run_active_pane_diagnostics(self) -> None:
        if self._active_pane is None:
            QMessageBox.information(self, "Diagnostics", "No active pane.")
            return
        from core.security_mode import is_paranoid

        write_test = False
        if not is_paranoid():
            write_test = (
                QMessageBox.question(
                    self,
                    "Diagnostics",
                    "Run a write/rename/delete probe in the active pane's current directory?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            )
        from core.diagnostics import diagnose_backend

        report = diagnose_backend(
            self._active_pane.backend,
            root=self._active_pane.current_path,
            write_test=write_test,
        )
        self._show_text_dialog("Diagnostics", report.to_text())

    def _run_recovery_scan(self) -> None:
        if self._active_pane is None:
            QMessageBox.information(self, "Recovery", "No active pane.")
            return
        from core.recovery import format_findings, scan_backend_recovery

        findings = scan_backend_recovery(
            self._active_pane.backend,
            self._active_pane.current_path,
        )
        self._show_text_dialog("Recovery Scan", format_findings(findings))

    def _toggle_paranoid_mode(self, checked: bool) -> None:
        from core.security_mode import set_policy

        policy = set_policy("paranoid" if checked else "normal")
        log.warning("Security mode changed to %s", policy.name)
        if getattr(self, "_scripts_dock", None) is not None:
            self._scripts_dock.refresh_policy()
        host = getattr(self, "extension_host", None)
        if host is not None:
            host.reload()  # paranoid unloads them all, normal loads the switched-on ones
        QMessageBox.information(
            self,
            "Security Mode",
            f"Security mode is now: {policy.name}",
        )

    # --- Transfer ---

    def _transfer_to_target(self) -> None:
        if self._active_pane is None:
            return
        self._start_transfer(self._active_pane, self._active_pane.selected_items())

    def _transfer_from_pane(self, pane: FilePaneWidget, paths: list[str]) -> None:
        self._set_active_pane(pane)
        self._start_transfer(pane, paths)

    def _move_from_pane(self, pane: FilePaneWidget, paths: list[str]) -> None:
        self._set_active_pane(pane)
        if not self._target_pane:
            QMessageBox.information(
                self,
                "Move",
                "Select files in one pane and activate a second pane as the target first.",
            )
            return
        if paths:
            self._request_transfer(pane, self._target_pane, paths, move=True)

    def _on_drop_transfer(
        self,
        paths: list[str],
        target_pane: FilePaneWidget,
        source_pane_id: str,
        is_move: bool = False,
        dest_dir: str = "",
    ) -> None:
        """Handle drag & drop transfer using the explicit source pane id.

        *dest_dir* is the folder the drop was released on ("" = the target
        pane's current folder). Inside one pane only a drop on a folder
        means anything."""
        source_pane = self._pane_by_id(source_pane_id)
        if source_pane is None:
            log.warning("Could not resolve source pane for drop transfer")
            return
        if source_pane is target_pane and not dest_dir:
            return

        self._request_transfer(
            source_pane, target_pane, paths, move=is_move, dest_dir=dest_dir or None
        )

    def _start_transfer(self, source: FilePaneWidget, selected: list[str]) -> None:
        if not self._target_pane:
            QMessageBox.information(
                self,
                "Transfer",
                "Select files in one pane and activate a second pane as the target first.",
            )
            return
        if not selected:
            return
        self._request_transfer(source, self._target_pane, selected)

    def _move_files(self) -> None:
        """Move selected files from active pane to target pane (F6)."""
        if not self._active_pane or not self._target_pane:
            return
        selected = self._active_pane.selected_items()
        if not selected:
            return
        self._request_transfer(self._active_pane, self._target_pane, selected, move=True)

    @staticmethod
    def _transfer_direction(source_backend, target_backend) -> TransferDirection:
        source_is_remote = not isinstance(source_backend, LocalFS)
        target_is_remote = not isinstance(target_backend, LocalFS)
        if source_is_remote and target_is_remote:
            return TransferDirection.RELAY
        if source_is_remote:
            return TransferDirection.DOWNLOAD
        if target_is_remote:
            return TransferDirection.UPLOAD
        return TransferDirection.DOWNLOAD  # local to local

    def _request_transfer(
        self,
        source: FilePaneWidget,
        target: FilePaneWidget,
        selected: list[str],
        move: bool = False,
        *,
        dest_dir: str | None = None,
    ) -> None:
        """F5 / F6 / drag & drop: check the destination, ask, then queue.

        The destination is listed on a background thread (a slow remote
        must not freeze the window); every name the transfer would replace
        is put to the user before a single job is queued. The jobs then
        refuse to replace anything the answers did not allow, so a file
        that appears in the meantime is not overwritten silently.
        """
        if not selected:
            return
        from core import transfer_conflicts as TC
        from ui.scan_job import ScanJob

        paths = list(selected)
        if dest_dir is None:
            dest_dir = target.current_path
        source_backend, dest_backend = source.backend, target.backend
        check = ScanJob(self)
        self._conflict_checks.add(check)

        def work(cancel, _progress):
            return TC.scan_conflicts(
                source_backend, dest_backend, paths, dest_dir, cancel=cancel
            )

        def finished(kind: str, value, cancelled: bool) -> None:
            self._conflict_checks.discard(check)
            check.deleteLater()
            self.statusBar().clearMessage()
            title = tr("Move") if move else tr("Copy")
            if cancelled:
                return
            if kind == "error":
                QMessageBox.warning(
                    self,
                    title,
                    tr("Could not check {dest} for existing names, so nothing was "
                       "queued:\n{error}").format(dest=dest_dir, error=value),
                )
                return
            if (
                source not in self._panes
                or target not in self._panes
                or source.backend is not source_backend
                or target.backend is not dest_backend
            ):
                log.info("Transfer dropped: a pane closed or changed connection meanwhile")
                return
            plan = self._resolve_transfer_conflicts(dest_backend, value)
            if plan is None:
                log.info("Transfer cancelled at the conflict prompt")
                return
            self._start_transfer_between(
                source, target, paths, move=move, dest_dir=dest_dir, conflict_plan=plan
            )

        check.finished.connect(finished)
        self.statusBar().showMessage(tr("Checking the destination for existing names…"))
        check.start(work)

    def _resolve_transfer_conflicts(self, dest_backend, scan):
        """Ask about each conflict of *scan*; a ConflictPlan, or None on Cancel."""
        from core import transfer_conflicts as TC

        overwriting = (TC.ConflictAction.OVERWRITE, TC.ConflictAction.OVERWRITE_IF_NEWER)
        plan = TC.ConflictPlan(dest_backend, scan)
        for_all = None
        total = len(scan.conflicts)
        for index, conflict in enumerate(scan.conflicts):
            action = for_all
            if action in overwriting and conflict.type_mismatch:
                action = None  # a folder against a file is never overwritten by "all"
            if action is None:
                answer = self._ask_transfer_conflict(conflict, total - index - 1)
                if answer is None:
                    return None
                action, apply_all = answer
                if apply_all:
                    for_all = action
            plan.decide(conflict, action)
        return plan

    def _ask_transfer_conflict(self, conflict, remaining: int):
        """The prompt for one name: ``(action, apply_to_all)`` or ``None``."""
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(conflict, remaining, self)
        try:
            dialog.exec()
            return dialog.result_choice()
        finally:
            dialog.deleteLater()

    def _start_transfer_between(
        self,
        source: FilePaneWidget,
        target: FilePaneWidget,
        selected: list[str],
        move: bool = False,
        *,
        dest_dir: str | None = None,
        conflict_plan=None,
    ) -> None:
        """Queue the transfer now. Without *conflict_plan* existing files
        are replaced: callers that confirmed that themselves (compare /
        sync) use this directly; the user commands go through
        ``_request_transfer``."""
        direction = self._transfer_direction(source.backend, target.backend)

        # Track target pane (and source for move) for auto-refresh on completion
        self._transfer_target_panes.add(target)
        if move:
            self._transfer_target_panes.add(source)
        # The summary comes from the jobs just created. A separate preview
        # walk (stat + exists per entry, on the GUI thread) only fed this
        # log line; every job is in the operation journal as well.
        jobs = self._transfer_manager.transfer_files(
            source_backend=source.backend,
            dest_backend=target.backend,
            source_paths=selected,
            dest_dir=target.current_path if dest_dir is None else dest_dir,
            direction=direction,
            move=move,
            conflict_plan=conflict_plan,
        )
        log.info(
            "Transfer enqueued: %s: %d file(s), %d byte(s)",
            "move" if move else "copy",
            len(jobs),
            sum(j.total_bytes for j in jobs),
        )

        action = "Move" if move else "Copy"
        relay = " (relay via localhost)" if direction == TransferDirection.RELAY else ""
        log.info(
            "%s %d items from %s to %s%s",
            action,
            len(selected),
            source.backend.name,
            target.backend.name,
            relay,
        )

    def _on_transfer_finished(self, job_id: str) -> None:
        """Single transfer finished — debounce refresh of target panes."""
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _do_debounced_refresh(self) -> None:
        """Perform a single debounced refresh of all target panes."""
        for pane in list(self._transfer_target_panes):
            if pane in self._panes:
                pane.refresh_after_change(quiet=True)

    def _on_all_transfers_finished(self) -> None:
        """All transfers complete — final refresh and clear tracking."""
        for pane in list(self._transfer_target_panes):
            if pane in self._panes:
                pane.refresh_after_change(quiet=True)
        self._transfer_target_panes.clear()

    # --- Auto-reconnect ---

    def _check_connections(self) -> None:
        """Periodically check SSH connections and attempt reconnect."""
        for pane in list(self._panes):
            if pane not in self._pane_profiles:
                continue

            backend = pane.backend
            if not _is_ssh_session(backend):
                continue

            if backend.connected:
                continue

            profile = self._pane_profiles[pane]
            password = self._pane_passwords.get(pane, "")
            key_passphrase = self._pane_key_passphrases.get(pane, "")
            log.info("Auto-reconnecting to %s...", profile.host)

            try:
                # Re-use connection manager which handles session key matching
                previous_path = pane.current_path
                session = self._connection_manager.connect(
                    profile,
                    password=password,
                    key_passphrase=key_passphrase,
                )
                # One load, straight to where the pane was.
                pane.set_backend(session, previous_path)
                if (
                    hasattr(session, "transport")
                    and session.transport
                    and session.transport.is_active()
                ):
                    self._terminal_dock.add_ssh_session(session.name, session.transport)
                log.info("Auto-reconnected to %s", session.name)
            except Exception as e:
                log.debug("Auto-reconnect to %s failed: %s", profile.host, e)

    # --- Bookmarks ---

    def _bookmark_draft(
        self, path: str, backend_name: str, pane: FilePaneWidget | None
    ) -> Bookmark:
        """A new bookmark for *path* shown in *pane*: its backend and, for a
        profile-backed connection, the profile ``_navigate_bookmark``
        reconnects through later."""
        profile = self._pane_profiles.get(pane) if pane is not None else None
        return Bookmark(
            name=path.rsplit("/", 1)[-1] or path,
            path=path,
            backend_name=backend_name,
            profile_name=profile.name if profile is not None else "",
        )

    def _on_bookmark_request(
        self, path: str, backend_name: str, pane: FilePaneWidget | None = None
    ) -> None:
        if pane is None:
            # From a pane's own bookmark button the pane is the sender.
            sender = self.sender()
            pane = sender if isinstance(sender, FilePaneWidget) else None
        draft = self._bookmark_draft(path, backend_name, pane)
        dialog = BookmarkEditDialog(
            draft,
            parent=self,
            groups=self._bookmark_manager.groups(),
            current_group=None,
            new=True,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        bookmark = dialog.result_bookmark()
        if not bookmark.name:
            return
        self._bookmark_manager.add(bookmark, group=dialog.result_group())
        self._rebuild_bookmarks_menu()

    def _show_bookmarks_popup(self) -> None:
        """Show the bookmarks menu as a popup at the current cursor position."""
        self._bookmarks_menu.popup(self.cursor().pos())

    def _rebuild_bookmarks_menu(self) -> None:
        self._populate_bookmarks_menu()
        # Also refresh the sidebar panel so it reflects the same
        # add / edit / delete that just hit the menu.
        sidebar = getattr(self, "_bookmark_sidebar", None)
        if sidebar is not None:
            sidebar.rebuild()

    def _populate_bookmarks_menu(self) -> None:
        self._bookmarks_menu.clear()

        add_action = self._bookmarks_menu.addAction(tr("Add Current Directory"))
        # F8 / Ctrl+Shift+B = add bookmark, window-wide. F2 rename, F3 view,
        # F4 edit, F5 copy, F6 move, F7 mkdir, F9 rename-alias, F10 context
        # menu, F12 bookmark-sidebar toggle; Del deletes.
        add_action.setShortcuts([QKeySequence("F8"), QKeySequence("Ctrl+Shift+B")])
        add_action.triggered.connect(self._bookmark_active_dir)

        manage_action = self._bookmarks_menu.addAction(tr("Manage Bookmarks..."))
        manage_action.triggered.connect(self._manage_bookmarks)

        nodes = self._bookmark_manager.tree()
        if nodes:
            self._bookmarks_menu.addSeparator()
            self._add_bookmark_nodes(self._bookmarks_menu, nodes)

    def _add_bookmark_nodes(self, menu: QMenu, nodes: list) -> None:
        """Fill *menu* with the bookmark tree; groups become submenus,
        which Qt opens on hover."""
        from core.bookmarks import BookmarkGroup
        from ui.icon_provider import icon as _bm_icon

        # QAction text is rendered via Qt's AutoText, which flips to
        # Rich-Text the moment it sees ``<tag>`` markup. A hostile name
        # like ``<u>fake</u>`` would then render with an underline —
        # visual spoofing. Strip ``<`` / ``>`` entirely so no HTML tag can
        # form, and double ``&`` so Qt's mnemonic parser treats it as a
        # literal character instead of an underscore-next-letter trigger.
        def _safe(text: str) -> str:
            return text.replace("<", "").replace(">", "").replace("&", "&&")

        for node in nodes:
            if isinstance(node, BookmarkGroup):
                group_icon = _bm_icon(node.icon_name or "folder", 32, node.color)
                sub = menu.addMenu(group_icon, _safe(node.name))
                if node.children:
                    self._add_bookmark_nodes(sub, node.children)
                else:
                    sub.addAction(tr("(empty)")).setEnabled(False)
                continue
            action = menu.addAction(
                _bm_icon(node.icon_name or "bookmark", 32, node.color),
                f"{_safe(node.name)}  [{_safe(node.backend_name)}]",
            )
            action.triggered.connect(lambda checked, b=node: self._navigate_bookmark(b))

    def _bookmark_active_dir(self) -> None:
        if self._active_pane:
            # Pass the pane: from the menu / F8 the sender is the QAction,
            # and a remote bookmark would lose its connection profile.
            self._on_bookmark_request(
                self._active_pane.current_path,
                self._active_pane.backend.name,
                self._active_pane,
            )

    def _pane_by_id(self, pane_id: str) -> FilePaneWidget | None:
        """The open pane a drag payload's ``source_pane_id`` names."""
        return next((p for p in self._panes if str(id(p)) == pane_id), None)

    def _drop_status(self, text: str, timeout_ms: int = 6000) -> None:
        self.statusBar().showMessage(text, timeout_ms)

    def _on_bookmark_drop(self, paths: list, source_pane_id: str, group, index: int | None) -> None:
        """Folders dragged from a pane onto the bookmark sidebar: bookmark
        each at the drop position, without a dialog (Edit… changes name,
        icon and group later). A remote folder keeps the pane's backend and
        connection profile, like "Add Current Directory" does."""
        source = self._pane_by_id(source_pane_id)
        if source is None:
            self._drop_status(tr("The dragged items come from a pane that is no longer open."))
            return
        if group is not None:
            try:
                self._bookmark_manager.parent_of(group)
            except KeyError:  # the group was deleted meanwhile
                group, index = None, None
        backend_name = source.backend.name
        added = skipped = 0
        for path in paths:
            if not isinstance(path, str) or not path:
                continue
            draft = self._bookmark_draft(path, backend_name, source)
            at = None if index is None else index + added
            if self._bookmark_manager.add(draft, group=group, index=at):
                added += 1
            else:
                skipped += 1
        self._rebuild_bookmarks_menu()
        if added and skipped:
            text = tr("Bookmarked {added} folder(s); {skipped} already bookmarked.")
        elif added:
            text = tr("Bookmarked {added} folder(s).")
        else:
            text = tr("Nothing added: {skipped} folder(s) already bookmarked.")
        self._drop_status(text.format(added=added, skipped=skipped))

    @staticmethod
    def _pane_serves_bookmark(pane: FilePaneWidget, bookmark: Bookmark) -> bool:
        """Whether *pane* shows the filesystem *bookmark* points into. Only
        names and types are compared - no backend call."""
        if bookmark.backend_name == "Local":
            return isinstance(pane.backend, LocalFS)
        return not isinstance(pane.backend, LocalFS) and pane.backend.name == bookmark.backend_name

    def _pane_for_bookmark(
        self, bookmark: Bookmark, prefer: FilePaneWidget | None
    ) -> FilePaneWidget | None:
        """An open pane on the bookmark's filesystem, *prefer* first (a
        transfer inside one filesystem then stays a rename)."""
        for pane in (prefer, self._active_pane, self._target_pane, *self._panes):
            if (
                pane is not None
                and pane in self._panes
                and self._pane_serves_bookmark(pane, bookmark)
            ):
                return pane
        return None

    @staticmethod
    def _bookmark_drop_refusal(
        source: FilePaneWidget, paths: list[str], bookmark: Bookmark
    ) -> str | None:
        """Why dropping *paths* onto *bookmark* would do nothing (or harm),
        or ``None``. Pure path arithmetic with the source backend's own
        ``parent()``; only applies when both sit on the same filesystem."""
        if not MainWindow._pane_serves_bookmark(source, bookmark):
            return None
        # A hand-edited bookmark may end in "/"; parent() never does.
        folder = bookmark.path.rstrip("/") or bookmark.path
        if any(source.is_within(folder, path) for path in paths):
            return tr("Cannot move or copy a folder into itself.")
        if all(source.backend.parent(path) == folder for path in paths):
            return tr("The dropped items are already in {folder}.").format(folder=folder)
        return None

    def _on_bookmark_transfer_drop(
        self, paths: list, source_pane_id: str, bookmark, is_move: bool
    ) -> None:
        """Items dragged from a pane onto a bookmark: move them (Ctrl: copy)
        into the bookmarked folder through ``_request_transfer``.

        Nothing here touches a filesystem or the network. Whether the folder
        is there at all (a dead mount, a deleted folder, a file now) and
        whether a remote answers is found out by the destination check that
        ``_request_transfer`` runs on a background thread; a failure is
        reported and nothing is queued. A remote bookmark without an open
        pane connects through its profile first - the same asynchronous
        connect a bookmark click uses - and transfers once the pane is up."""
        source = self._pane_by_id(source_pane_id)
        if source is None:
            self._drop_status(tr("The dragged items come from a pane that is no longer open."))
            return
        if not isinstance(bookmark, Bookmark) or not any(
            b is bookmark for b in self._bookmark_manager.all()
        ):
            self._drop_status(tr("That bookmark no longer exists."))
            return
        paths = [p for p in paths if isinstance(p, str) and p]
        if not paths:
            return
        refusal = self._bookmark_drop_refusal(source, paths, bookmark)
        if refusal:
            self._drop_status(refusal)
            return
        target = self._pane_for_bookmark(bookmark, source)
        if target is None and bookmark.backend_name == "Local":
            # Same as a click on a local bookmark without a local pane.
            target = self._add_pane_to_splitter(self._root_splitter, LocalFS())
        if target is not None:
            self._request_transfer(source, target, paths, move=is_move, dest_dir=bookmark.path)
            return
        self._connect_then_transfer(source, paths, bookmark, is_move)

    def _connect_then_transfer(
        self, source: FilePaneWidget, paths: list[str], bookmark: Bookmark, is_move: bool
    ) -> None:
        """Open the bookmark's connection (asynchronously, with the usual
        password prompt) and transfer once its pane is there."""
        from html import escape

        name = escape(bookmark.name)
        if not bookmark.profile_name:
            QMessageBox.warning(
                self,
                tr("Bookmark"),
                tr(
                    "Bookmark '{name}' has no connection profile, so its connection "
                    "cannot be opened. Connect to {backend} first and drop again; "
                    "nothing was transferred."
                ).format(name=name, backend=escape(bookmark.backend_name)),
            )
            return
        profile = self._profile_manager.get(bookmark.profile_name)
        if profile is None:
            QMessageBox.warning(
                self,
                tr("Bookmark"),
                tr(
                    "Profile '{profile}' for bookmark '{name}' was not found; "
                    "nothing was transferred."
                ).format(profile=escape(bookmark.profile_name), name=name),
            )
            return
        source_backend = source.backend

        def transfer_when_connected(pane: FilePaneWidget) -> None:
            if source not in self._panes or source.backend is not source_backend:
                self._drop_status(tr("The dragged items come from a pane that is no longer open."))
                return
            if pane.backend.name != bookmark.backend_name:
                self._drop_status(
                    tr(
                        "The connection for '{name}' opened {actual}, not {expected}; "
                        "nothing was transferred."
                    ).format(
                        name=bookmark.name,
                        actual=pane.backend.name,
                        expected=bookmark.backend_name,
                    ),
                    10000,
                )
                return
            self._request_transfer(source, pane, paths, move=is_move, dest_dir=bookmark.path)

        self._quick_connect_profile(profile, post_connect=transfer_when_connected)

    def _navigate_bookmark(self, bookmark: Bookmark) -> None:
        if not self._active_pane:
            return

        # For local bookmarks, just navigate
        if bookmark.backend_name == "Local":
            if isinstance(self._active_pane.backend, LocalFS):
                self._active_pane.navigate_async(bookmark.path)
            else:
                # Create a local pane for it
                pane = self._add_pane_to_splitter(self._root_splitter, LocalFS())
                pane.navigate_async(bookmark.path)
        else:
            if self._active_pane.backend.name == bookmark.backend_name:
                self._active_pane.navigate_async(bookmark.path)
                return

            # profile_name missing — typically an older bookmark
            # saved before we tracked profiles, OR one created via
            # "Add Current Directory" on a pane whose connection
            # wasn't profile-backed. Tell the user instead of
            # silently no-oping.
            if not bookmark.profile_name:
                QMessageBox.warning(
                    self,
                    "Bookmark",
                    f"Bookmark '{bookmark.name}' has no associated "
                    f"connection profile. The profile reference was "
                    f"lost or never set — re-bookmark this location "
                    f"from the matching remote pane after connecting.",
                )
                return

            profile = self._profile_manager.get(bookmark.profile_name)
            if profile is None:
                QMessageBox.warning(
                    self,
                    "Bookmark",
                    f"Profile '{bookmark.profile_name}' for this bookmark was not found.",
                )
                return

            # Route through _quick_connect_profile so bookmarks
            # inherit the full password-prompt + save-to-keyring
            # flow, protocol-specific credential lookups, and the
            # async connect that keeps the UI responsive. The
            # post_connect hook navigates the freshly-created pane
            # to the bookmarked path after the session opens.
            self._quick_connect_profile(
                profile,
                post_connect=lambda pane: pane.navigate_async(bookmark.path),
            )

    def _manage_bookmarks(self) -> None:
        bookmarks = self._bookmark_manager.all()
        if not bookmarks:
            QMessageBox.information(self, "Bookmarks", "No bookmarks saved yet.")
            return

        names = [f"{b.name} -> {b.path} [{b.backend_name}]" for b in bookmarks]
        from PyQt6.QtWidgets import QDialog, QListWidget

        dialog = QDialog(self)
        dialog.setWindowTitle("Manage Bookmarks")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout(dialog)
        add_close_corner(dialog)

        lst = QListWidget()
        lst.addItems(names)
        layout.addWidget(lst)

        from PyQt6.QtWidgets import QHBoxLayout, QPushButton

        btn_layout = QHBoxLayout()
        btn_del = QPushButton("Delete Selected")
        btn_close = QPushButton("Close")
        btn_layout.addWidget(btn_del)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

        def _delete():
            row = lst.currentRow()
            if row >= 0:
                self._bookmark_manager.remove(row)
                lst.takeItem(row)
                self._rebuild_bookmarks_menu()

        btn_del.clicked.connect(_delete)
        btn_close.clicked.connect(dialog.accept)
        dialog.exec()

    # --- Host key ---

    def _confirm_unknown_host(self, error: UnknownHostKeyError) -> bool:
        reply = QMessageBox.question(
            self,
            "Trust Host Key?",
            (
                f"The host {error.host} is not present in known_hosts.\n\n"
                f"Key type: {error.key_type}\n"
                f"SHA256:{error.fingerprint_sha256}\n\n"
                "Trust this host key and continue?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    # --- Keyring tools ---

    def _recheck_keyring(self) -> None:
        """Force a fresh keyring backend probe.

        Surfaces a result dialog either way: if the user just started
        a daemon (gnome-keyring / KeePassXC / kwalletd) they get an
        immediate "now usable" confirmation; if nothing changed they
        get the actionable install hint.
        """
        from core.credentials import (
            keyring_status_message,
            recheck_keyring,
        )

        usable = recheck_keyring()
        if usable:
            QMessageBox.information(
                self,
                "Keyring",
                "System keyring is now reachable. Saved passwords should persist again.",
            )
        else:
            QMessageBox.warning(
                self,
                "Keyring",
                keyring_status_message(),
            )

    # --- About ---

    def _show_shortcuts(self) -> None:
        """Show the keyboard shortcut reference (F1)."""
        from ui.shortcuts_dialog import ShortcutsDialog

        dialog = ShortcutsDialog(self)
        try:
            dialog.exec()
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed

    def _setup_status_bar(self) -> None:
        """The running version, bottom right; a permanent widget, so a
        temporary status message never covers it."""
        from axross._version import __version__

        self._version_label = QLabel(f"axross {__version__}")
        self._version_label.setProperty("role", "muted")
        self._version_label.setToolTip(tr("Version of this axross"))
        self.statusBar().addPermanentWidget(self._version_label)

    def _show_about(self) -> None:
        from axross._version import __version__

        about_text = f"""<h2>axross {__version__}</h2>
<p>Multi-protocol file manager with a pane-based UI, a scripting surface
and an MCP server.</p>

<h3>Protocols</h3>
<table>
<tr><td><b>SFTP / SCP</b></td><td>SSH (password, key, agent)</td></tr>
<tr><td><b>FTP / FTPS</b></td><td>Active/passive, explicit TLS</td></tr>
<tr><td><b>SMB / CIFS</b></td><td>Windows/Samba shares</td></tr>
<tr><td><b>WebDAV</b></td><td>Nextcloud, ownCloud, Apache</td></tr>
<tr><td><b>S3</b></td><td>AWS, MinIO, R2 (anonymous too)</td></tr>
<tr><td><b>Rsync</b></td><td>Daemon and SSH transport</td></tr>
<tr><td><b>NFS</b></td><td>v3 / v4</td></tr>
<tr><td><b>IMAP / POP3</b></td><td>Mail as a file system</td></tr>
<tr><td><b>Azure Blob / Files</b></td><td>Microsoft cloud storage</td></tr>
<tr><td><b>OneDrive / SharePoint</b></td><td>Microsoft 365</td></tr>
<tr><td><b>Google Drive, Dropbox</b></td><td>Cloud storage</td></tr>
<tr><td><b>iSCSI</b></td><td>Block storage mount</td></tr>
</table>
<p>…and more: see File &gt; Connection Manager for the full list.</p>

<h3>Features</h3>
<ul>
<li>Any number of panes, split horizontally or vertically</li>
<li>Drag &amp; drop between all panes and protocols; remote-to-remote relay</li>
<li>Transfer queue with progress, resume and retry; asks before overwriting</li>
<li>Live filter, text and hex editor, batch rename, bookmarks</li>
<li>Proxies (SOCKS, HTTP, HTTPS, PAC) per profile or globally</li>
<li>Analysis dock, media viewer, Scripts panel with a Python editor</li>
<li>Themes: Modern (light/dark), Classic, Light, Hacker, Amber</li>
</ul>

<h3>Docks</h3>
<ul>
<li><b>Transfers</b> — queue, progress, retry/cancel</li>
<li><b>Terminal</b> — shell on connected hosts</li>
<li><b>Log</b> — live log of all operations</li>
<li><b>Console / Scripts</b> — Python REPL and saved scripts</li>
<li><b>Analysis</b> — what the selected file is</li>
</ul>

<p><small>axross {__version__} — Python + PyQt6 | github.com/c0decave/axross</small></p>
<p><small>F1 = keyboard shortcuts · Help &gt; Scripting Guide</small></p>
"""
        QMessageBox.about(self, f"About axross {__version__}", about_text)

    # --- Font / Zoom ---

    def _change_font_size(self, delta: int) -> None:
        """Increase or decrease application font size by delta points."""
        app = QApplication.instance()
        if not app:
            return
        font = app.font()
        new_size = max(6, min(24, font.pointSize() + delta))
        self._set_font_size(new_size)

    def _set_font_size(self, size: int) -> None:
        """Set the application font to a specific point size."""
        app = QApplication.instance()
        if not app:
            return
        font = app.font()
        font.setPointSize(size)
        with themes.collection_paused():
            app.setFont(font)
            # Update all existing widgets
            for widget in app.allWidgets():
                widget.setFont(font)
                widget.update()
        log.info("Font size set to %dpt", size)

    # --- Themes ---

    def _apply_theme(self, theme: str) -> None:
        theme = themes.normalize(theme)
        self._current_theme = theme
        app = QApplication.instance()
        if app is None:
            return

        scheme = themes.system_scheme()
        resolved = themes.resolve(theme, scheme)
        tokens = themes.palette_tokens_for(resolved)
        if not hasattr(self, "_base_style_name"):
            # Remember what the desktop gave us so classic can restore it.
            self._base_style_name = app.style().objectName()
            self._base_palette = app.palette()
        css = themes.stylesheet_for(theme, scheme, compact=self._compact_mode)
        with themes.collection_paused():
            if tokens is not None:
                # Fusion honours the palette and the stylesheet uniformly;
                # native styles (Breeze, Windows11, ...) draw some controls
                # themselves and ignore parts of both.
                app.setStyle("Fusion")
                app.setPalette(themes.qpalette_for(tokens))
            else:
                if self._base_style_name:
                    app.setStyle(self._base_style_name)
                app.setPalette(self._base_palette)
            app.setStyleSheet(css)

        # Re-apply pane border styles on top of the theme
        self._refresh_pane_styles()
        self._refresh_icons()
        log.info("Theme changed to: %s", theme)

    def _on_system_scheme_changed(self, *_args) -> None:
        if self._current_theme == "modern":
            self._apply_theme("modern")

    def _show_metadata_settings(self) -> None:
        from ui.metadata_dialog import MetadataSettingsDialog

        MetadataSettingsDialog(self).exec()

    def _choose_open_limit(self) -> None:
        from core import open_limits as _ol

        value, ok = QInputDialog.getInt(
            self,
            "Open Size Limit",
            "Largest file the text / hex viewers open (MB):",
            _ol.max_open_mb(),
            _ol.MIN_MAX_OPEN_MB,
            _ol.MAX_MAX_OPEN_MB,
        )
        if ok:
            _ol.set_max_open_mb(value)

    def _toggle_compact_mode(self, checked: bool) -> None:
        self._compact_mode = checked
        self._apply_theme(self._current_theme)
        log.info("Compact mode: %s", "on" if checked else "off")

    def _toggle_monochrome_icons(self, checked: bool) -> None:
        """Flip the icon provider between colourful (default) and
        monochrome (every icon rendered with ``currentColor`` so it
        inherits the theme's foreground). Every cached QIcon is
        dropped; surfaces that bound icons at construction time get
        rebuilt."""
        from ui.icon_provider import set_monochrome as _set_mono

        _set_mono(checked)
        self._refresh_icons()
        log.info("Monochrome icons: %s", "on" if checked else "off")

    def _icon_tint(self) -> str | None:
        """Colour for every icon under the current theme: the Hacker /
        Amber accent, or in monochrome mode the palette's text colour
        (``currentColor`` would rasterise black), else ``None`` for the
        regular per-icon palette."""
        from ui.icon_provider import is_monochrome as _is_mono

        resolved = themes.resolve(self._current_theme, themes.system_scheme())
        tint = themes.icon_tint_for(resolved)
        if tint is None and _is_mono():
            app = QApplication.instance()
            if app is not None:
                tint = app.palette().color(QPalette.ColorRole.WindowText).name()
        return tint

    def _refresh_icons(self) -> None:
        """Re-rasterise every icon surface after a theme or monochrome
        change: toolbar, dock title bars, bookmark sidebar + menu and
        the file lists (their rows ask the provider on each paint)."""
        from ui.icon_provider import set_tint as _set_tint

        _set_tint(self._icon_tint())
        self._rebuild_toolbar_icons()
        self._rebuild_dock_titlebars()
        if hasattr(self, "_bookmark_sidebar"):
            self._bookmark_sidebar.rebuild()
        if hasattr(self, "_bookmarks_menu"):
            self._rebuild_bookmarks_menu()
        for pane in self._panes:
            pane._table.viewport().update()

    def _rebuild_toolbar_icons(self) -> None:
        """Re-apply icons to the Main toolbar's actions (those carrying
        an ``axIcon`` property, set in ``_setup_toolbar``)."""
        from ui.icon_provider import icon as _ico

        for tb in self.findChildren(QToolBar):
            for action in tb.actions():
                icon_name = action.property("axIcon")
                if icon_name:
                    action.setIcon(_ico(str(icon_name)))

    def _rebuild_dock_titlebars(self) -> None:
        """Re-install the dock title bars so their icons re-rasterise
        from the now-monochrome (or colourful-again) provider."""
        dock_specs = [
            (getattr(self, "_transfer_dock", None), "Transfers", "download"),
            (getattr(self, "_terminal_dock", None), "Terminal", "terminal"),
            (getattr(self, "_log_dock", None), "Log", "inbox"),
            (getattr(self, "_scripts_dock", None), tr("Scripts"), "edit"),
            (getattr(self, "_bookmark_sidebar", None), "Bookmarks", "bookmark"),
        ]
        for dock, title, icon_name in dock_specs:
            if dock is not None:
                self._install_dock_titlebar(dock, title, icon_name)

    def _abandon_background_threads(self) -> None:
        """Hand over connect attempts and scheduled jobs still running.

        Neither can be interrupted, and waiting would hang the close for
        as long as an unanswering server takes. Destroying their QThread
        with them still running aborts the app instead ("QThread:
        Destroyed while thread '' is still running"), so each is cut
        from the window and left to finish on its own.
        """
        from core.thread_lifetime import detach_running_thread

        for task in self._connect_tasks:
            try:
                task.abandon()
            except Exception:  # noqa: BLE001 — the rest of the cleanup must run
                log.warning("Abandoning a connect attempt failed on close", exc_info=True)
        self._connect_tasks.clear()
        for thread in list(getattr(self, "_scheduler_threads", ())):
            detach_running_thread(thread)
        self._scheduler_threads = []

    def closeEvent(self, event) -> None:
        scripts = getattr(self, "_scripts_dock", None)
        if scripts is not None and not scripts.maybe_close():
            event.ignore()  # unsaved script edits, and the user chose Cancel
            return
        log.info("Application closing, cleaning up...")
        if scripts is not None:
            try:
                scripts.shutdown()  # a running script ends with the window
            except Exception:  # noqa: BLE001 — the rest of the cleanup must run
                log.warning("Scripts dock shutdown failed on close", exc_info=True)
        self._save_session()
        self._reconnect_timer.stop()
        self._abandon_background_threads()
        host = getattr(self, "extension_host", None)
        if host is not None:
            host.unload_all()  # their deactivate() runs while the window is whole
        for check in list(self._conflict_checks):
            check.abandon()
        self._conflict_checks.clear()
        for tp in self._terminal_panes:
            # One broken pane must not skip the cleanup below (transfer
            # threads, connections, temp dirs).
            try:
                tp.shutdown()
            except Exception:  # noqa: BLE001
                log.warning("Terminal pane shutdown failed on close", exc_info=True)
        self._terminal_panes.clear()
        self._log_dock.shutdown()
        self._terminal_dock.shutdown()
        if getattr(self, "_analysis_dock", None) is not None:
            self._analysis_dock.shutdown()
        self._transfer_manager.shutdown()
        self._connection_manager.disconnect_all()
        self._cleanup_archive_tempdirs()
        log.info("Cleanup complete")
        super().closeEvent(event)
