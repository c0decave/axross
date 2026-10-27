from __future__ import annotations

import json
import logging
import os
import posixpath
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QByteArray, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QKeySequence, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabBar,
    QToolBar,
    QWidget,
)

from core import i18n, posix_compat
from core.bookmarks import KIND_TERMINAL as BOOKMARK_TERMINAL
from core.bookmarks import LOCAL_SHELL, Bookmark, BookmarkManager
from core.connection_manager import ConnectionManager
from core.i18n import tr
from core.local_fs import LocalFS
from core.profiles import (
    SIMPLE_PASSWORD_PROTOCOLS,
    ConnectionProfile,
    ProfileManager,
    password_needed,
)
from core.transfer_manager import TransferManager
from core.transfer_worker import TransferDirection
from ui import themes, window_prefs
from ui.analysis_dock import DOCK_TITLE as ANALYSIS_DOCK_TITLE
from ui.bookmark_edit_dialog import BookmarkEditDialog
from ui.close_corner import add_close_corner
from ui.disconnected_pane import KIND_PANE, KIND_TERMINAL, DisconnectedPanePlaceholder
from ui.dock_fit import SESSION_KEY as DOCK_FIT_SESSION_KEY
from ui.dock_fit import DockFit
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
from ui.toolbar_order import TOOL_ID_PROPERTY
from ui.transfer_dock import TransferDock

# The window keys of session.json the preferences use; ui.window_prefs reads
# them all, Edit > Settings… changes them.
from ui.window_prefs import (
    FONT_SIZE_KEY,
    HIDDEN_COLOR_KEY,
    HIGHLIGHT_HIDDEN_KEY,
    RESTORE_ON_START_KEY,
    SHOW_HIDDEN_KEY,
)
from ui.extension_panels import PANEL_NODE, ExtensionDock, ExtensionPanelsMixin
from ui.extension_panels import panel_node_problem as _panel_node_problem
from ui.workspaces import Workspace, WorkspaceMixin
from ui.workspaces import session_problem as _workspaces_problem

if TYPE_CHECKING:
    from core.ssh_client import UnknownHostKeyError

log = logging.getLogger(__name__)


def _under_any(path: str, roots: set[str]) -> bool:
    """*path* is in *roots* or lies below one of them, with ``/`` or ``\\``
    as the separator (a root of ``/`` is kept as ``""``)."""
    if path in roots:
        return True
    return any(path[:i] in roots for i, ch in enumerate(path) if ch in "/\\")


def _is_ssh_session(backend) -> bool:
    """``isinstance(backend, SSHSession)`` without importing paramiko at
    start-up (~0.13 s): until core.ssh_client is loaded no SSH session can
    exist."""
    mod = sys.modules.get("core.ssh_client")
    return mod is not None and isinstance(backend, mod.SSHSession)


def _terminal_name(session, profile) -> str:
    """The terminal dock's name for an SSH *session* opened through *profile*.

    ``session.name`` is only ``user@host``: two profiles to one user@host
    (another port, two jump hosts to one inner address) shared one dock
    entry, and connecting the second restarted the first one's running
    shell on the other machine. The profile name and a non-default port
    tell them apart."""
    target = session.name
    if profile is None:
        return target
    port = getattr(profile, "port", None)
    if port and int(port) != 22:
        target = f"{target}:{port}"
    name = getattr(profile, "name", "")
    return f"{name} ({target})" if name else target


def _needs_key_passphrase(exc: BaseException) -> bool:
    """True when a connect failed for want of (the right) SSH key
    passphrase. Without importing paramiko at start-up: no SSH connect
    can have failed before it is loaded."""
    mod = sys.modules.get("paramiko")
    return mod is not None and isinstance(exc, mod.PasswordRequiredException)


# How often Quick Connect asks for a key passphrase before it gives up.
KEY_PASSPHRASE_TRIES = 3

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
_SESSION_NODE_TYPES = ("splitter", "pane", "terminal", PANEL_NODE)


def _session_problem(data) -> str:
    """Why a saved session cannot be restored, or "" when it can.

    Checks the whole shape ``_restore_session`` relies on, so a bad file is
    refused before the open panes are closed instead of half-way through.
    """
    if not isinstance(data, dict):
        return "The file does not hold a JSON object."
    if not isinstance(data.get("window", {}), dict):
        return "The window settings are not an object."
    problem, trees = _workspaces_problem(data.get("workspaces"))
    if problem:
        return problem
    stack = [(data.get("splitter", {}), 1)] + [(tree, 1) for tree in trees]
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
        if kind == PANEL_NODE:
            problem = _panel_node_problem(node)
            if problem:
                return problem
            continue
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


def _session_workspaces(data: dict) -> list[dict]:
    """The workspaces of a checked session: its ``workspaces`` entry, or
    one workspace from the ``splitter`` of a session written before them."""
    entries = data.get("workspaces")
    if isinstance(entries, list) and entries:
        return entries
    return [{"name": "Workspace 1", "splitter": data.get("splitter", {}), "current": True}]


def _session_has_panes(data: dict) -> bool:
    return any(
        isinstance(entry.get("splitter"), dict) and entry["splitter"].get("children")
        for entry in _session_workspaces(data)
    )


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


def _write_private_text(path: Path | str, text: str, *, private_dir: bool = True) -> None:
    """Write *text* to *path* atomically as a 0600 file.

    *private_dir* (axross' own config folder) also creates the folder and
    makes it 0700. A folder the user picked (an export) is left exactly
    as it is: its mode is not ours to change."""
    target = Path(path)
    if private_dir:
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
            posix_compat.fchmod_private(fd, 0o600)
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


_PROMPT_PROTOCOL_NAMES = {
    "telnet": "Telnet",
    "cisco-telnet": "Cisco Telnet",
    "pop3": "POP3",
    "nntp": "NNTP",
    "winrm": "WinRM",
}


def _simple_password_prompt(profile: ConnectionProfile) -> tuple[bool, str]:
    """Whether Quick Connect asks *profile* for its secret, and the label.

    For a protocol in SIMPLE_PASSWORD_PROTOCOLS - the ones whose dialog
    has the password field; whether to ask is core.profiles.password_needed,
    the decision the MCP server shares.
    """
    if not password_needed(profile):
        return False, ""
    proto = profile.protocol
    if proto == "s3":
        return True, f"Secret Key for S3 bucket '{profile.s3_bucket}':"
    if proto == "webdav":
        return True, f"Password for WebDAV {(profile.webdav_url or '')[:50]}:"
    if proto in ("ftp", "ftps"):
        return True, f"Password for {proto.upper()} {profile.username}@{profile.host}:"
    if proto == "smb":
        return True, f"Password for SMB \\\\{profile.host}\\{profile.smb_share}:"
    if proto == "dfsn":
        return True, f"Password for DFS \\\\{profile.host}\\{profile.smb_share}:"
    if proto == "rsync":
        return True, f"Password for rsync {profile.host}/{profile.rsync_module}:"
    if proto in ("azure_blob", "azure_files"):
        return True, f"Account Key for Azure {profile.azure_account_name}:"
    if proto == "iscsi":
        return True, f"CHAP password for iSCSI {profile.host}:"
    if proto == "imap":
        return True, f"Password for IMAP {profile.username}@{profile.host}:"
    name = _PROMPT_PROTOCOL_NAMES.get(proto, proto.upper())
    return True, f"Password for {name} {profile.username}@{profile.host}:"


#: The application font size the desktop gave the first window, in points
#: (View > Zoom Reset returns to it).
_DESKTOP_FONT_PT: int | None = None
#: Qt's own default when the desktop font is sized in pixels.
_FALLBACK_FONT_PT = 10


def _desktop_font_size() -> int:
    global _DESKTOP_FONT_PT
    if _DESKTOP_FONT_PT is None:
        app = QApplication.instance()
        size = app.font().pointSize() if app is not None else -1
        _DESKTOP_FONT_PT = size if size > 0 else _FALLBACK_FONT_PT
    return _DESKTOP_FONT_PT


class MainWindow(ExtensionPanelsMixin, WorkspaceMixin, QMainWindow):
    """Main application window with file panes."""

    #: (job_id, ok, detail) — emitted from a scheduler worker thread so
    #: the store write and the status bar happen on the GUI thread.
    _scheduler_done = pyqtSignal(str, bool, str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Axross")
        self.resize(1200, 700)
        _desktop_font_size()  # before a stored zoom changes the font

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
        # Pane -> its auto-reconnect still in flight (skipped meanwhile).
        self._reconnecting: dict = {}
        # Open Compare windows with the two panes each was built on.
        self._compare_dialogs: list = []
        # Open Find Files windows and the Find in Index window (Edit >
        # Index Active Folder... drives it).
        self._find_dialogs: list = []
        self._index_dialog = None

        self._current_theme = themes.DEFAULT_THEME
        self._compact_mode = False
        # Window preferences (ui.window_prefs) - set from session.json by
        # _load_persistent_visual_settings, changed in Edit > Settings…
        self._restore_on_start = True
        self._highlight_hidden = True
        self._hidden_color: str | None = None
        # Icon colours (ui.window_prefs.ICON_COLOUR_MODES) and the colour of "one".
        self._icon_colours = "theme"
        self._icon_colour: str | None = None
        self._font_size: int | None = None
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
        # The archive views of the dock, outermost first: the archive opened
        # from a pane, then each archive opened inside the one before.
        # ``path`` is what is listed, ``origin`` the archive on disk whose
        # folder receives extractions, ``tempdir`` where a nested archive
        # was extracted to (removed when its view goes).
        self._archive_views: list[dict] = []

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
        self._setup_agent_dock()
        # A sign-in that shows a code in the browser asks for it here (Dropbox).
        from ui import auth_prompt as _auth_prompt

        _auth_prompt.install()
        self._setup_status_bar()
        # The right column reaches the bottom edge; docks of a column that
        # do not fit its height are tabbed together (ui.dock_fit).
        self._apply_dock_corners()
        self._dock_fit = DockFit(self)
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

        # Auto-reconnect timer
        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setInterval(RECONNECT_INTERVAL_MS)
        self._reconnect_timer.timeout.connect(self._check_connections)
        self._reconnect_timer.start()

        # Track which panes received transfers for auto-refresh
        self._transfer_target_panes: set[FilePaneWidget] = set()
        # Destination checks of F5 / F6 / drops still running (ScanJob).
        self._conflict_checks: set = set()
        # Checked transfers waiting for their conflict prompt while another
        # one is open (see _next_conflict_prompt), and whether one is.
        self._conflict_waiting: list = []
        self._conflict_prompting = False
        self._transfer_manager.job_finished.connect(self._on_transfer_finished)
        self._transfer_manager.all_finished.connect(self._on_all_transfers_finished)
        # Undos carried out by the transfer engine, recorded as undone only
        # once every job of them finished (see _await_undo_jobs).
        self._undo_waits: list[dict] = []
        # Tags follow moved files (core.tags): job id -> (source backend,
        # dest backend, dest profile, source path, dest path), and the moved
        # folders that wait for all their jobs.
        self._tag_moves: dict[str, tuple[str, str, str, str, str]] = {}
        self._tag_folder_moves: list[dict] = []
        # Ended jobs whose tags follow in one batch with one write of
        # tags.json (job id, ended well); see _queue_tag_job.
        self._tag_job_queue: list[tuple[str, bool | None]] = []
        self._tag_last_flush = 0.0
        self._transfer_manager.job_finished.connect(self._tags_on_move_finished)
        self._transfer_manager.job_error.connect(self._tags_on_move_error)
        self._transfer_manager.job_finished.connect(self._on_undo_job_finished)
        self._transfer_manager.job_error.connect(self._on_undo_job_error)
        # Connections of closed panes kept open for their transfers:
        # (profile, backend), released once no job uses the backend.
        self._deferred_releases: list[tuple] = []
        self._transfer_manager.job_finished.connect(self._release_idle_connections)
        self._transfer_manager.job_error.connect(self._release_idle_connections)
        self._transfer_manager.walk_finished.connect(self._release_idle_connections)

        # Extensions: only the switched-on ones are loaded, and none in the
        # paranoid security mode (core.extensions).
        from ui.extension_host import ExtensionHost

        self.extension_host = ExtensionHost(self, self.extensions_menu)
        # The agent through extensions: their tools and topics in the Agent
        # tabs, every agent event to them (ui.extension_host).
        self._agent_dock.agent_event.connect(self.extension_host.emit_agent_event)
        self.extension_host.agent_tools_changed.connect(self._agent_dock.refresh_extensions)
        self.extension_host.load_enabled()
        # The tool buttons need the docks and the extension host.
        self._add_tool_buttons(self._tools_toolbar)
        self._setup_toolbar_reorder()
        self._fit_toolbars()

        # Debounce timer for post-transfer refresh
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(500)
        self._refresh_timer.timeout.connect(self._do_debounced_refresh)

    def _setup_menubar(self) -> None:
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu(tr("&File"))

        quick_connect_action = file_menu.addAction(tr("Quic&k Connect..."))
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
        edit_menu.addSeparator()
        # Alt+F7 is the commander file managers' Find; Ctrl+F stays the
        # pane filter and Ctrl+Shift+F Find in Index.
        self._find_files_action = edit_menu.addAction(tr("&Find Files…"))
        self._find_files_action.setShortcuts([QKeySequence("Alt+F7"), QKeySequence("Ctrl+Alt+F")])
        self._find_files_action.setToolTip(
            tr("Search folders on any open connection by name, type, content and inside archives")
        )
        self._find_files_action.triggered.connect(lambda _checked=False: self._open_find_files())
        self._index_folder_action = edit_menu.addAction(tr("&Index Active Folder…"))
        self._index_folder_action.setToolTip(
            tr("Record names, sizes and dates below the active pane's folder in the offline "
               "index, for Find in Index and Find Files")
        )
        self._index_folder_action.triggered.connect(
            lambda _checked=False: self._index_active_folder()
        )
        edit_menu.addSeparator()
        # Every preference in one window (ui.settings_dialog). The menu
        # role puts it into the application menu on macOS.
        self._settings_action = edit_menu.addAction(tr("&Settings…"))
        self._settings_action.setShortcut(QKeySequence("Ctrl+,"))
        self._settings_action.setMenuRole(QAction.MenuRole.PreferencesRole)
        self._settings_action.setToolTip(tr("Every setting of axross, sorted by category"))
        self._settings_action.triggered.connect(lambda _checked=False: self.open_settings())

        # View menu
        view_menu = menubar.addMenu(tr("&View"))

        # One switch for the whole window; every file pane follows it
        # (_new_file_pane, _toggle_hidden). On by default; a stored
        # window.show_hidden of False switches it off at the start.
        self._hidden_action = view_menu.addAction(tr("Show &Hidden Files"))
        self._hidden_action.setCheckable(True)
        self._hidden_action.setChecked(True)
        self._hidden_action.setShortcut(QKeySequence("Ctrl+H"))
        self._hidden_action.toggled.connect(self._toggle_hidden)
        # Stored at once (window.show_hidden); ``triggered`` is the user's
        # press - loading the stored value must not write the file back.
        self._hidden_action.triggered.connect(self._store_show_hidden)

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
        layout_menu = view_menu.addMenu(tr("La&yout Preset"))
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

        view_menu.addSeparator()

        # Theme submenu: a quick switch; Edit > Settings > Appearance has
        # the same choice next to the other looks. The check mark follows
        # the theme in use (_apply_theme).
        from PyQt6.QtGui import QActionGroup

        theme_menu = view_menu.addMenu(tr("Th&eme"))
        theme_group = QActionGroup(theme_menu)
        theme_group.setExclusive(True)
        self._theme_actions: dict[str, QAction] = {}
        for theme_name, theme_label in themes.THEME_CHOICES:
            if theme_name == "classic":
                theme_menu.addSeparator()
            action = theme_menu.addAction(tr(theme_label))
            action.setCheckable(True)
            theme_group.addAction(action)
            action.triggered.connect(
                lambda _checked, t=theme_name: self._quietly(self.set_theme, t)
            )
            self._theme_actions[theme_name] = action

        view_menu.addSeparator()

        # The zoom is stored (window.font_size) and comes back on start;
        # Reset returns to the desktop's font size.
        zoom_in_action = view_menu.addAction(tr("Zoom &In"))
        zoom_in_action.setShortcut(QKeySequence("Ctrl+="))
        zoom_in_action.triggered.connect(lambda: self._change_font_size(1))

        zoom_out_action = view_menu.addAction(tr("Zoom &Out"))
        zoom_out_action.setShortcut(QKeySequence("Ctrl+-"))
        zoom_out_action.triggered.connect(lambda: self._change_font_size(-1))

        zoom_reset_action = view_menu.addAction(tr("Zoom &Reset"))
        zoom_reset_action.setShortcut(QKeySequence("Ctrl+0"))
        zoom_reset_action.triggered.connect(lambda: self._quietly(self.set_font_size, None))

        view_menu.addSeparator()

        self._dock_view_menu = view_menu.addMenu(tr("P&anels"))

        view_menu.addSeparator()

        tagged_action = view_menu.addAction(tr("Tagged &Files…"))
        self._tagged_action = tagged_action  # the toolbar shows it too
        tagged_action.setToolTip("Every tag and the files that carry it")
        tagged_action.triggered.connect(self._show_tagged_files)
        find_action = view_menu.addAction(tr("Find in Inde&x…"))
        self._find_index_action = find_action
        find_action.setShortcut(QKeySequence("Ctrl+Shift+F"))
        find_action.triggered.connect(self._open_metadata_search)

        self._view_media_action = view_menu.addAction(tr("&View Media…"))
        self._view_media_action.setToolTip(
            "Images, PDFs and videos of the active pane's folder as overview or slideshow"
        )
        self._view_media_action.triggered.connect(lambda: self._view_media(selected_only=False))

        self._view_selected_media_action = view_menu.addAction(tr("Vie&w Selected Media…"))
        self._view_selected_media_action.setToolTip(
            "Images, PDFs and videos among the active pane's selection"
        )
        self._view_selected_media_action.triggered.connect(
            lambda: self._view_media(selected_only=True)
        )

        cas_action = view_menu.addAction(tr("&Duplicate Finder…"))
        cas_action.setShortcut(QKeySequence("Ctrl+Shift+D"))
        cas_action.triggered.connect(self._open_cas_duplicates)

        cas_history_action = view_menu.addAction(tr("Duplicate Index && History…"))
        cas_history_action.setToolTip("Every scan of the duplicate index; remove or clear it")
        cas_history_action.triggered.connect(self._open_cas_history)

        disk_action = view_menu.addAction(tr("Dis&k Usage…"))
        self._disk_usage_action = disk_action
        disk_action.setToolTip("Capacity of every open connection")
        disk_action.triggered.connect(self._open_disk_usage)

        compare_action = view_menu.addAction(tr("Compare Pa&nes…"))
        self._compare_action = compare_action
        compare_action.setToolTip("Diff the active pane's tree against the target pane's")
        compare_action.triggered.connect(self._open_compare_panes)

        sched_action = view_menu.addAction(tr("Scheduled &Jobs…"))
        sched_action.setToolTip("Run scripts on a recurring schedule")
        sched_action.triggered.connect(self._open_scheduler)

        view_menu.addSeparator()

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

        toggle_orient_action = pane_menu.addAction(tr("T&oggle Layout (H/V)"))
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

        self._build_workspace_menu(menubar)

        # Tools menu
        tools_menu = menubar.addMenu(tr("&Tools"))
        self._network_search_action = tools_menu.addAction(tr("&Find on Network Hosts (SMB)…"))
        self._network_search_action.setToolTip(
            "Your files on many SMB hosts at once - host list, addresses or CIDR, one login, read only"
        )
        self._network_search_action.triggered.connect(self._show_network_search)
        diag_action = tools_menu.addAction(tr("Run Active Pane &Diagnostics…"))
        diag_action.triggered.connect(self._run_active_pane_diagnostics)
        recovery_action = tools_menu.addAction(tr("&Recovery Scan…"))
        recovery_action.triggered.connect(self._run_recovery_scan)
        editor_action = tools_menu.addAction(tr("Text &Editor"))
        editor_action.setToolTip(
            tr("The editor window: new files, local files and every file opened for editing")
        )
        editor_action.triggered.connect(lambda _checked=False: self.show_editor())
        # These four open Edit > Settings… on their page.
        network_action = tools_menu.addAction(tr("&Network && Proxy…"))
        network_action.triggered.connect(lambda _checked=False: self._show_network_proxy())
        llm_action = tools_menu.addAction(tr("&LLM Profiles…"))
        llm_action.triggered.connect(lambda _checked=False: self._show_llm_profiles())
        # sift's Analysis dock on the active pane's selection (else its folder).
        from ui.icon_provider import icon as _menu_icon

        sift_action = tools_menu.addAction(tr("Analyse with &sift"))
        sift_action.setToolTip(
            tr("Explain the selected file in the Analysis dock (sift); with nothing "
               "selected, offer the folder shown")
        )
        sift_action.setProperty("axIcon", "analysis")
        sift_action.setIcon(_menu_icon("analysis"))  # again on a theme change
        sift_action.triggered.connect(lambda _checked=False: self.analyse_active_with_sift())
        self._analyse_sift_action = sift_action
        start_agent_action = tools_menu.addAction(tr("Start &Agent"))
        start_agent_action.setToolTip(
            tr("Open the Agent with a new conversation for the active pane's folder")
        )
        start_agent_action.triggered.connect(lambda _checked=False: self._new_agent_tab())
        self._new_agent_window_action = tools_menu.addAction(tr("New Agent W&indow"))
        self._new_agent_window_action.setToolTip(
            tr("A new Agent conversation in a panel of its own, for the active pane's folder")
        )
        self._new_agent_window_action.triggered.connect(
            lambda _checked=False: self._new_agent_window()
        )
        # One entry per agent profile (core.agent_profiles), presets first.
        self._agent_profile_menu = tools_menu.addMenu(tr("New Agent Tab from &Profile"))
        self._agent_profile_menu.setToolTip(
            tr("A new Agent tab set up from an agent profile, for the active pane's folder"))
        self._agent_profile_menu.aboutToShow.connect(self._fill_agent_profile_menu)
        agent_settings_action = tools_menu.addAction(tr("A&gent Settings…"))
        agent_settings_action.triggered.connect(lambda _checked=False: self._show_agent_settings())
        # Settings > Agent > MCP Servers: configure servers, Add from Catalog…
        mcp_action = tools_menu.addAction(tr("M&CP Servers…"))
        mcp_action.setToolTip(
            tr("Configure the agent's MCP servers, or add one from a catalog (runs in podman)")
        )
        mcp_action.triggered.connect(lambda _checked=False: self._show_mcp_servers())
        # Opens Settings on the page titled "Audio" (playback, voice); the
        # toolbar shows it beside the Media Player.
        self._av_settings_action = tools_menu.addAction(tr("Audio && &Video Settings…"))
        self._av_settings_action.triggered.connect(
            lambda _checked=False: self.open_audio_video_settings()
        )
        metadata_settings_action = tools_menu.addAction(tr("&Metadata Settings…"))
        metadata_settings_action.setToolTip(
            "How Remove Metadata writes (in place or a cleaned copy) and whether it asks first"
        )
        metadata_settings_action.triggered.connect(
            lambda _checked=False: self._show_metadata_settings()
        )

        # Extensions menu: three fixed entries; loaded extensions add theirs
        # below (ui.extension_host). Manage opens Settings > Extensions.
        self.extensions_menu = menubar.addMenu(tr("E&xtensions"))
        manage_ext_action = self.extensions_menu.addAction(tr("&Manage Extensions…"))
        self._manage_ext_action = manage_ext_action
        manage_ext_action.triggered.connect(lambda _checked=False: self._show_extensions_dialog())
        folder_ext_action = self.extensions_menu.addAction(tr("&Open Extensions Folder"))
        folder_ext_action.triggered.connect(self._open_extensions_folder)
        reload_ext_action = self.extensions_menu.addAction(tr("&Reload Extensions"))
        self._reload_ext_action = reload_ext_action  # the extension tools go below it
        reload_ext_action.triggered.connect(lambda _checked=False: self.extension_host.reload())

        # Help menu
        help_menu = menubar.addMenu(tr("&Help"))
        shortcuts_action = help_menu.addAction(tr("&Keyboard Shortcuts"))
        shortcuts_action.setShortcut(QKeySequence("F1"))
        shortcuts_action.triggered.connect(self._show_shortcuts)
        features_action = help_menu.addAction(tr("Features…"))
        self._features_action = features_action  # the toolbar shows it too
        features_action.setToolTip("Optional features: installed, missing, and how to get them")
        features_action.triggered.connect(self._show_features)
        guide_action = help_menu.addAction(tr("&Scripting Guide"))
        guide_action.triggered.connect(self._show_scripting_guide)
        third_party_action = help_menu.addAction(tr("&Third-Party Software…"))
        third_party_action.setToolTip("The projects axross uses and ships, with their licences")
        third_party_action.triggered.connect(self._show_third_party)
        help_menu.addSeparator()
        # Shown only while a newer version is there (ui.update_ui).
        self._update_menu_action = help_menu.addAction(tr("Update to…"))
        self._update_menu_action.setVisible(False)
        self._update_menu_action.triggered.connect(lambda _checked=False: self.show_update_dialog())
        check_updates_action = help_menu.addAction(tr("Check for &Updates…"))
        check_updates_action.setToolTip("Ask GitHub for a newer axross release")
        check_updates_action.triggered.connect(lambda _checked=False: self.check_for_updates())
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
            # re-icon the bar without matching on translated labels; the
            # stable id keeps the button's place in a stored order
            # (ui.toolbar_order).
            act.setProperty("axIcon", icon_name)
            act.setProperty(TOOL_ID_PROPERTY, icon_name)
            act.setIcon(_ico(icon_name))
        self._add_feature_buttons(toolbar)
        self._main_toolbar = toolbar
        # The tools (Agent ... Features) are a bar of their own: it moves to
        # a second row when both do not fit side by side (_fit_toolbars) -
        # in one row the tools fell off the edge of a narrow window.
        tools = self.addToolBar("Tools")
        tools.setObjectName("axToolsToolbar")  # saveState / restoreState key
        tools.setMovable(False)
        self._tools_toolbar = tools
        self._shell_action = shell_btn
        self._copy_target_action = copy_btn
        self._move_target_action = move_btn
        self._refresh_action = refresh_btn
        self._dupes_action = dupes_btn

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
            (
                self.thumbnail_view_action,
                "thumbnails",
                "Thumbnail view for the active pane (Ctrl+Shift+G)",
            ),
            (
                self._view_media_action,
                "media-view",
                "View the images, PDFs and videos of this folder",
            ),
            (self._find_index_action, "find-index", "Find in the offline index (Ctrl+Shift+F)"),
            (self._compare_action, "compare", "Compare the two panes"),
            (self._disk_usage_action, "disk-usage", "Disk usage of this folder"),
            (
                self._metadata_action,
                "metadata",
                "Show the metadata of the selection or this folder",
            ),
            (self._pack_action, "pack", "Pack the selection into an archive"),
            (self._manage_ext_action, "extensions", "Manage extensions"),
        ):
            toolbar.addAction(action)
            action.setToolTip(tip)
            action.setProperty("axIcon", icon_name)
            action.setProperty(TOOL_ID_PROPERTY, icon_name)
            action.setIcon(_ico(icon_name))

    #: The extension tools with a toolbar button: (icon, extension id, title).
    TOOLBAR_EXTENSIONS = (
        ("media-player", "bundled:media_player", "Media Player"),
        ("treemap", "bundled:folder_treemap", "Folder Treemap"),
        ("drives", "bundled:drives_overview", "Drives Overview"),
    )

    def _add_tool_buttons(self, toolbar: QToolBar) -> None:
        """The tools, after the feature buttons: the docks' own toggles and
        the menus' own actions (one shortcut owner, one check state), and a
        button per extension tool that offers to switch it on."""
        from PyQt6.QtGui import QAction

        from ui.icon_provider import icon as _ico

        self._trash_action = QAction(tr("Show Trash…"), self)
        self._trash_action.triggered.connect(self._trash_from_toolbar)
        buttons = [
            (self._agent_dock.toggleViewAction(), "agent", "Agent: tasks for the LLM agent"),
            (self._analysis_dock.toggleViewAction(), "analysis",
             tr("{title}: what the selected file is (Ctrl+Shift+I)").format(
                 title=tr(ANALYSIS_DOCK_TITLE))),
            (self._terminal_dock.toggleViewAction(), "terminal", "Terminal panel"),
            (self._find_files_action, "find-files", "Find Files (Alt+F7)"),
            (self._scripts_dock.toggleViewAction(), "scripts",
             "Scripts: the saved scripts and the script editor"),
            (self._console_dock.toggleViewAction(), "console",
             "Console: the Python scripting engine (the axross.* API)"),
            (self._tagged_action, "tag", "Tagged files"),
            (self._trash_action, "trash", "The trash of the active pane"),
        ]
        self._extension_buttons: dict[str, QAction] = {}
        for icon_name, ext_id, title in self.TOOLBAR_EXTENSIONS:
            action = QAction(tr(title), self)
            action.triggered.connect(
                lambda _checked=False, e=ext_id, t=title: self._toggle_extension_tool(e, t))
            self._extension_buttons[ext_id] = action
            buttons.append((action, icon_name, f"{title} (extension)"))
            if icon_name == "media-player":
                # The equalizer: what plays and how (Settings > Audio).
                buttons.append((self._av_settings_action, "audio-settings",
                                "Audio & Video Settings: playback and voice"))
        buttons += [
            (self._settings_action, "settings", "Settings (Ctrl+,)"),
            (self._features_action, "features", "Features: what is installed, what is missing"),
        ]
        if toolbar.actions():
            toolbar.addSeparator()
        for action, icon_name, tip in buttons:
            toolbar.addAction(action)
            action.setToolTip(tip)
            action.setProperty("axIcon", icon_name)
            action.setProperty(TOOL_ID_PROPERTY, icon_name)
            action.setIcon(_ico(icon_name))
        # The right-click menu's own "Show Trash…" entry (its icon too).
        self._trash_action.setProperty("axCommand", "trash-browser")
        # Every button is in the menus as well: Trash beside Tagged Files,
        # the extension tools below the Extensions menu's fixed entries.
        view_menu = self._tagged_action.associatedObjects()[0]
        entries = view_menu.actions()
        after = entries.index(self._tagged_action) + 1
        view_menu.insertAction(entries[after] if after < len(entries) else None,
                               self._trash_action)
        entries = self.extensions_menu.actions()
        after = entries.index(self._reload_ext_action) + 1
        before = entries[after] if after < len(entries) else None
        if before is None:
            self.extensions_menu.addSeparator()
        else:
            self.extensions_menu.insertSeparator(before)
        for action in self._extension_buttons.values():
            self.extensions_menu.insertAction(before, action)

    def _trash_from_toolbar(self, _checked: bool = False) -> None:
        pane = self._active_pane
        if pane is None:
            self.statusBar().showMessage(tr("No file pane is active."), 5000)
            return
        pane._show_trash_browser()

    def _toggle_extension_tool(self, ext_id: str, title: str) -> None:
        """An extension tool's button: show or hide its panel; switched off,
        ask first to switch it on (Extensions > Manage Extensions… does the
        same), then show the panel."""
        host = self.extension_host
        if ext_id not in host.loaded_ids():
            answer = QMessageBox.question(
                self,
                tr("Switch on {title}?").format(title=tr(title)),
                tr("{title} is an extension and switched off. Switch it on now? "
                   "(Extensions > Manage Extensions… switches it off again.)").format(
                       title=tr(title)),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            host.set_enabled(ext_id, True)
            if ext_id not in host.loaded_ids():
                why = host.error(ext_id) or tr("see the log")
                self.statusBar().showMessage(
                    tr("{title} could not be switched on: {why}").format(title=tr(title), why=why),
                    8000)
                return
            for dock in host.docks(ext_id):
                dock.show()
                dock.raise_()
                self.reveal_extension_panel(dock)
            return
        docks = host.docks(ext_id)
        if not docks:
            self.statusBar().showMessage(tr("{title} has no panel.").format(title=tr(title)), 5000)
            return
        # A panel on a workspace not on screen counts as hidden: the button
        # brings that workspace to the front (reveal_extension_panel).
        show = not any(d.isVisible() for d in docks)
        for dock in docks:
            if not show and isinstance(dock, ExtensionDock) and dock.pane_mode:
                dock.close()  # out of its workspace, as its [x] and the menu entry do
                continue
            dock.setVisible(show)
            if show:
                dock.raise_()
                self.reveal_extension_panel(dock)

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

        # The command each toolbar button shares with a right-click entry
        # (file_pane.CONTEXT_COMMANDS): the entry takes the button's icon, and
        # tests/test_pane_context_menu_layout.py holds the two together.
        for action, command in (
            (self._refresh_action, "refresh"),
            (self._copy_target_action, "copy-to-target"),
            (self._move_target_action, "move-to-target"),
            (self._dupes_action, "duplicates"),
            (self.thumbnail_view_action, "view-mode"),
            (self._view_media_action, "media-view"),
            (self._metadata_action, "metadata"),
            (self._pack_action, "pack"),
        ):
            action.setProperty("axCommand", command)

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
        # The window-wide Refresh and Show Metadata are above; matched by
        # command, the labels carry mnemonics and translations.
        above = {self._refresh_action.property("axCommand"),
                 self._metadata_action.property("axCommand")}
        for action in source.actions():
            if action.property("axCommand") in above:
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

        old = dock.titleBarWidget()
        dock.setTitleBarWidget(DockTitleBar(title, icon_name, dock))
        if old is not None:
            # QDockWidget hides a replaced title bar but keeps it as a child:
            # every theme switch left six behind, each repolished ever after.
            old.deleteLater()

    def _setup_bookmark_sidebar(self) -> None:
        """Build + install the left-side bookmark panel. Rebuilds
        itself on add / edit / delete; navigation requests flow
        through the existing ``_navigate_bookmark`` router so
        bookmark clicks behave exactly like menu clicks."""
        from ui.bookmark_sidebar import BookmarkSidebar

        self._bookmark_sidebar = BookmarkSidebar(
            self._bookmark_manager,
            self,
            terminal_profiles=self._terminal_profile_names,
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

    def _apply_dock_corners(self) -> None:
        """The right column takes the bottom-right corner: it reaches the
        window's bottom edge, and the bottom area (Transfers, Terminal,
        ...) is as wide as the panes and the left column. The bottom-left
        corner stays with the bottom area: the left column holds the
        Bookmarks alone (a list that scrolls), so it has no docks to stack,
        while the bottom area's tables and terminal lines are better off
        wide - between both columns it would be squeezed from two sides.
        restoreState sets the corners a saved state carries, so this runs
        again after it."""
        self.setCorner(Qt.Corner.BottomRightCorner, Qt.DockWidgetArea.RightDockWidgetArea)
        self.setCorner(Qt.Corner.BottomLeftCorner, Qt.DockWidgetArea.BottomDockWidgetArea)

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
        self._scripts_dock.run_example_in_console_requested.connect(self._run_example_in_console)
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

    def _run_example_in_console(self, name: str, call: str) -> None:
        """Scripts dock > Run in Console on a bundled example, with its call."""
        self._console_dock.show()
        self._console_dock.raise_()
        self._console_dock.repl.run_example(name, call)

    def _show_features(self, key: str = "") -> None:
        """Help > Features…: one non-modal window, raised when open;
        *key* selects one feature (core.features)."""
        from ui.features_dialog import FeaturesDialog

        dialog = getattr(self, "_features_dialog", None)
        if dialog is None:
            dialog = FeaturesDialog(self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda *_: setattr(self, "_features_dialog", None))
            self._features_dialog = dialog
        if isinstance(key, str) and key:
            dialog.select(key)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _editor(self):
        """This window's editor window (one per main window, made on first
        use). It shows itself whenever a tab is added - also one whose file
        was read in the background."""
        from ui.editor_window import EditorWindow

        editor = getattr(self, "_editor_window", None)
        if editor is None:
            editor = EditorWindow(self)
            editor.setWindowFlag(Qt.WindowType.Window, True)
            editor.saved.connect(self._editor_saved)
            editor.opened.connect(lambda _tab: self._show_editor_window())
            self._editor_window = editor
        return editor

    def open_in_editor(self, backend, path: str, *, read_only: bool = False):
        """*path* as a tab of this window's editor. A file not open yet is
        read off the GUI thread: None now, and the editor shows with the new
        tab once it is read. Returns the tab when it was open already."""
        editor = self._editor()
        tab = editor.open_file(backend, path, read_only=read_only, background=True)
        if tab is not None:
            self._show_editor_window()
        return tab

    def show_editor(self) -> None:
        """Tools > Text Editor: the editor window raised; without a tab it
        starts with an untitled one (File > New there)."""
        editor = self._editor()
        if editor.tabs.count() == 0:
            editor.new_tab()
        self._show_editor_window()

    def _show_editor_window(self) -> None:
        editor = self._editor_window
        editor.show()
        editor.raise_()
        editor.activateWindow()

    def _editor_saved(self, backend, path: str) -> None:
        """A save in the editor: the panes that show the file's folder on
        the same backend list it again (size, modified)."""
        folder = posixpath.dirname(path.replace("\\", "/")).rstrip("/") or "/"
        for pane in self._panes:
            current = pane.current_path.replace("\\", "/").rstrip("/") or "/"
            if pane.backend is backend and current == folder:
                pane.refresh_after_change()

    def open_terminal_command(self, argv: list[str], *, cwd: str | None = None,
                              label: str = "") -> TerminalPaneWidget:
        """A local terminal pane in the current workspace, in *cwd*, running
        *argv* (an interactive tool started by an extension)."""
        term = self._preset_make_terminal_pane("local", cwd=cwd)
        self._root_splitter.addWidget(term)
        term.show()
        if label:
            term.setToolTip(label)
        if not term.run_command(argv):
            self.statusBar().showMessage(f"Could not start {argv[0] if argv else '?'}", 5000)
        return term

    def open_local_folder(self, path: str) -> None:
        """A new local pane on *path* in the current workspace (a mounted
        disk image, for one)."""
        pane = self._add_pane_to_splitter(self._root_splitter, LocalFS())
        pane.navigate_async(path)
        self._set_active_pane(pane)

    def _show_tagged_files(self) -> None:
        """View > Tagged Files…: one non-modal window, raised when open."""
        from ui.tag_ui import TaggedFilesDialog

        dialog = getattr(self, "_tagged_files_dialog", None)
        if dialog is None:
            dialog = TaggedFilesDialog(self, go_to=self._go_to_tagged_file)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda *_: setattr(self, "_tagged_files_dialog", None))
            self._tagged_files_dialog = dialog
        else:
            dialog.reload()
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _go_to_tagged_file(self, entry) -> None:
        """The folder of a tagged file, reached like a bookmark (the same
        backend, or its connection profile)."""
        import posixpath as _pp

        folder = _pp.dirname(entry.path.replace("\\", "/")) or "/"
        if "\\" in entry.path and "/" not in entry.path:
            folder = entry.path.rsplit("\\", 1)[0] or entry.path
        self._navigate_bookmark(Bookmark(name=_pp.basename(folder) or folder, path=folder,
                                         backend_name=entry.backend_name,
                                         profile_name=entry.profile_name))

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

    def _show_third_party(self) -> None:
        """Help > Third-Party Software…: one non-modal window, raised when open."""
        from ui.third_party_dialog import ThirdPartyDialog

        dialog = getattr(self, "_third_party_dialog", None)
        if dialog is None:
            dialog = ThirdPartyDialog(self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda *_: setattr(self, "_third_party_dialog", None))
            self._third_party_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    # ------------------------------------------------------------------
    # Analysis dock: sift's explanation of the selected file
    def _setup_analysis_dock(self) -> None:
        from ui.analysis_dock import AnalysisDock

        self._analysis_dock = AnalysisDock(self)
        # sift's own sieve and name: the robot is the Agent's.
        self._install_dock_titlebar(self._analysis_dock, tr(ANALYSIS_DOCK_TITLE), "analysis")
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._analysis_dock)
        self._analysis_dock.hide()
        # Debounced: arrowing through a listing analyses where it stops.
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setSingleShot(True)
        self._analysis_timer.setInterval(200)
        self._analysis_timer.timeout.connect(self._analyse_selection)
        self._analysis_dock.visibilityChanged.connect(self._on_analysis_visibility)
        self._analysis_dock.settings_requested.connect(self._show_llm_profiles)
        self._analysis_dock.features_requested.connect(self._show_features)
        self._populate_dock_view_menu()

    def _setup_agent_dock(self) -> None:
        from ui.agent_dock import AgentDock

        self._agent_dock = AgentDock(
            self,
            root_provider=self._agent_root,
            pane_items=self._agent_pane_items,
            pane_backend=self._agent_pane_backend,
            remote_backends=self._agent_remote_backends,
            extensions=lambda: getattr(self, "extension_host", None),
        )
        self._install_dock_titlebar(self._agent_dock, "Agent", "bot")
        # Green, orange or red: whether the LLM is reachable, in the top row.
        self._agent_dock.show_lamp_in(self._agent_dock.titleBarWidget())
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._agent_dock)
        self._agent_dock.hide()
        # Detached conversations are panels of this window (ui.agent_panels):
        # the kept ones come back now, before a session layout is restored.
        self._agent_dock.panel_host = self
        self._agent_dock.restore_detached()
        # restore_layout_on_start settles them (main.py calls it before the
        # event loop runs); without one, the first event-loop pass does.
        QTimer.singleShot(0, self._settle_agent_panels)
        self._agent_dock.settings_requested.connect(self._show_llm_profiles)
        self._agent_dock.profiles_requested.connect(
            lambda: self.open_settings("agent", "profiles"))
        self._agent_dock.visibilityChanged.connect(self._on_agent_visibility)
        self._focus_agent_action = QAction(tr("Ask the Agent"), self)
        self._focus_agent_action.setShortcut(QKeySequence("Ctrl+Shift+A"))
        self._focus_agent_action.triggered.connect(self._focus_agent)
        self.addAction(self._focus_agent_action)
        self._populate_dock_view_menu()

    def _on_agent_visibility(self, visible: bool) -> None:
        if visible:
            self._agent_dock.refresh_profiles()
            self._agent_dock.follow_folder()

    def _agent_follow_pane(self, pane: FilePaneWidget) -> None:
        """The active pane changed or moved: the Agent dock follows it."""
        dock = getattr(self, "_agent_dock", None)
        if dock is not None and pane is self._active_pane and dock.isVisible():
            dock.follow_folder()

    def _agent_pane_items(self, kind: str) -> dict | None:
        """For the Agent's + menu: the active pane's selection or folder."""
        from core.local_fs import LocalFS

        pane = getattr(self, "_active_pane", None)
        if pane is None:
            return None
        paths = pane.selected_items() if kind == "selection" else [pane.current_path]
        paths = [p for p in paths if p]
        if not paths:
            return None
        local = isinstance(pane.backend, LocalFS)
        return {
            "paths": paths,
            "backend": None if local else self._agent_backend_id(pane),
            "local": local,
        }

    def _agent_pane_backend(self, pane_id) -> tuple:
        """(the agent's backend id or None, local?) of the pane a drag came from."""
        from core.local_fs import LocalFS

        for pane in self._panes:
            if str(id(pane)) == pane_id:
                local = isinstance(pane.backend, LocalFS)
                return (None if local else self._agent_backend_id(pane)), local
        return None, True

    def _agent_remote_backends(self) -> list:
        """The remote connections of the panes as the agent sees them:
        ``(pane:<profile or backend name>, backend, profile or None)``, one
        per connection object (two panes on one connection share it)."""
        from core.local_fs import LocalFS

        out: list = []
        taken: set = set()
        for pane in self._panes:
            backend = getattr(pane, "backend", None)
            if (
                backend is None
                or isinstance(backend, LocalFS)
                or any(b is backend for _i, b, _p in out)
            ):
                continue
            profile = self._pane_profiles.get(pane) if hasattr(self, "_pane_profiles") else None
            name = profile.name if profile is not None else ""
            base = f"pane:{name or getattr(backend, 'name', '') or 'remote'}"
            bid, n = base, 1
            while bid in taken:
                n += 1
                bid = f"{base}#{n}"
            taken.add(bid)
            out.append((bid, backend, profile))
        return out

    def _agent_backend_id(self, pane) -> str | None:
        for bid, backend, _profile in self._agent_remote_backends():
            if backend is pane.backend:
                return bid
        return None

    def _send_to_agent(self, pane, paths: list) -> None:
        from core.local_fs import LocalFS

        dock = getattr(self, "_agent_dock", None)
        if dock is None:
            return
        self._focus_agent()
        local = isinstance(pane.backend, LocalFS)
        dock.current_tab().attach(paths, None if local else self._agent_backend_id(pane), local)

    def _new_agent_tab(self, folder: str | None = None):
        """Start Agent / New Agent Tab Here: the Agent dock in front with a
        new tab for *folder* (default: the active pane's local folder, else
        home - the agent's folder is a local one). Returns the tab."""
        dock = getattr(self, "_agent_dock", None)
        if dock is None:
            return None
        dock.show()
        dock.raise_()
        return dock.start_tab(folder or self._agent_root())  # focuses its input

    def _fill_agent_profile_menu(self) -> None:
        """Tools > New Agent Tab from Profile: the dock's profiles; a click
        opens a tab for the active pane's folder, the dock in front."""
        dock = getattr(self, "_agent_dock", None)
        menu = self._agent_profile_menu
        if dock is None:
            menu.clear()
            menu.addAction(tr("The Agent is not available")).setEnabled(False)
            return

        def folder() -> str:
            dock.show()
            dock.raise_()
            return self._agent_root()

        dock.fill_new_from_profile_menu(menu, folder_provider=folder)

    def _new_agent_window(self, folder: str | None = None):
        """Tools > New Agent Window: a new conversation in a panel of its
        own, for *folder* (default as Start Agent). Returns the panel."""
        dock = getattr(self, "_agent_dock", None)
        if dock is None:
            return None
        return dock.new_window(folder or self._agent_root())

    # -- detached Agent conversations: panels of this window (ui.agent_panels) --

    def add_agent_panel(self, panel) -> None:
        """A detached conversation goes on All Workspaces (the dock area);
        from there it moves like an extension panel."""
        panel.pane_drop_requested.connect(self._on_pane_drop)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, panel)
        panel.show()
        panel.raise_()

    def remove_agent_panel(self, panel) -> None:
        """A detached conversation was attached back or closed: out of its
        workspace (which goes when nothing else is in it) or the dock area."""
        self._panel_homes.pop(panel.objectName(), None)
        if self._in_layout(panel):
            self._take_out_of_layout(panel)
            self._prune_empty_workspaces()
        else:
            self.removeDockWidget(panel)

    def _own_panels(self) -> list:
        dock = getattr(self, "_agent_dock", None)
        return dock.panels() if dock is not None else []

    def _settle_agent_panels(self) -> None:
        from PyQt6 import sip

        dock = getattr(self, "_agent_dock", None)
        if dock is not None and not sip.isdeleted(dock):
            dock.settle_detached()

    def _focus_agent(self) -> None:
        dock = getattr(self, "_agent_dock", None)
        if dock is None:
            return
        dock.show()
        dock.raise_()
        tab = dock.current_tab()
        if tab is not None:
            tab.input.setFocus()

    def _agent_root(self) -> str:
        """The agent's folder: the active pane's, when it shows local files."""
        from core.local_fs import LocalFS

        pane = getattr(self, "_active_pane", None)
        if pane is not None and isinstance(pane.backend, LocalFS) and pane.current_path:
            return pane.current_path
        return os.path.expanduser("~")

    # --- Edit > Settings… (ui.settings_dialog) ---

    def open_settings(
        self, page: str | None = None, sub: str | None = None, *, title: str | None = None
    ) -> int:
        """Open the Settings dialog, on *page* (a category id of
        ui.settings_dialog, *sub* one of its sub-pages) when given, or on the
        page titled *title* (the dialog's first page when none has it).
        Returns the dialog's result. The dialog is a child of the window
        only while it is open."""
        from ui.settings_dialog import SettingsDialog

        dialog = SettingsDialog(self, window=self)
        if page is not None:
            dialog.show_page(page, sub)
        elif title is not None and not dialog.show_page_titled(title):
            log.info("Settings: no page titled %r, opening the first page", title)
        try:
            return dialog.exec()
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed

    def refresh_llm_profiles(self) -> None:
        """The Analysis and Agent docks re-read the LLM profiles."""
        for dock in (getattr(self, "_analysis_dock", None), getattr(self, "_agent_dock", None)):
            if dock is not None:
                dock.refresh_profiles()

    def refresh_analysis_settings(self) -> None:
        """The Analysis dock takes the saved Analysis (sift) settings in."""
        dock = getattr(self, "_analysis_dock", None)
        if dock is not None:
            dock.reload_settings()

    def clear_analysis_session(self) -> None:
        """Clear Cache: the Analysis dock forgets this session's results too."""
        dock = getattr(self, "_analysis_dock", None)
        if dock is not None:
            dock.clear_session_cache()

    def refresh_agent_settings(self) -> None:
        """The open Agent tabs re-read the agent's settings."""
        dock = getattr(self, "_agent_dock", None)
        if dock is not None and hasattr(dock, "reload_settings"):
            dock.reload_settings()

    def refresh_proxy_indicators(self) -> None:
        for pane in list(self._panes):
            self._refresh_proxy_indicator(pane)

    def _show_llm_profiles(self) -> None:
        self.open_settings("llm")
        # Also after Cancel: an Apply before it saved the profiles.
        self.refresh_llm_profiles()

    def _show_agent_settings(self) -> None:
        self.open_settings("agent")

    def _show_mcp_servers(self) -> None:
        """Tools > MCP Servers…: Settings on Agent > MCP Servers."""
        self.open_settings("agent", "mcp")

    #: The Settings page of playback and voice ("Audio & Video Settings").
    AUDIO_SETTINGS_TITLE = "Audio"

    def open_audio_video_settings(self) -> int:
        """Tools > Audio & Video Settings… and its toolbar button: Settings
        on the page titled "Audio"."""
        return self.open_settings(title=self.AUDIO_SETTINGS_TITLE)

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
        self._analyse_pane_selection(dock, pane)

    def _analyse_pane_selection(
        self, dock, pane: FilePaneWidget, explicit: bool = False
    ) -> None:
        """*explicit*: a request (Tools > Analyse with sift), which runs even
        while automatic analysis is off; else a selection, which then does not."""
        if not dock.ensure_available():
            return  # the dock says where sift comes from
        items = pane.selected_file_items()
        paths = pane.selected_items()
        if not items:
            # Analyse Folder with sift on empty space: the folder shown stays
            # on offer while nothing is selected (a reload re-sends this).
            if dock.offers_folder(pane.backend, pane.current_path):
                return
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
        dock.analyse(self._analysis_target(pane, item, paths[0]), explicit=explicit)

    def _show_analysis_dock(self):
        """Show and raise the Analysis dock for an explicit request (a menu
        entry); the dock, or None when sift is missing - the dock then says
        where sift comes from."""
        dock = self._analysis_dock
        dock.show()
        dock.raise_()
        # The caller's request is the answer: the automatic run the dock's
        # visibility just scheduled would only repeat it, or replace a folder
        # offer with "select a file".
        self._analysis_timer.stop()
        return dock if dock.ensure_available() else None

    def analyse_with_sift(self, pane: FilePaneWidget, entries: list) -> None:
        """Analyse with sift: [(path, FileItem), ...] of *pane* in the Analysis
        dock - one file explained, several offered as a batch for the LLM."""
        dock = self._show_analysis_dock()
        if dock is None:
            return
        if len(entries) == 1 and not entries[0][1].is_dir:
            path, item = entries[0]
            dock.analyse(self._analysis_target(pane, item, path), explicit=True)
            return
        targets = [self._analysis_target(pane, item, path) for path, item in entries
                   if not item.is_dir and not item.is_link]
        if targets:
            dock.offer_batch(targets, tr("{n} files selected").format(n=len(targets)))
        else:
            dock.show_message(tr("Select a single file to see its analysis."))

    def analyse_folder_with_sift(self, pane: FilePaneWidget, folder: str) -> None:
        """Analyse Folder with sift: the files of *folder* on offer in the
        Analysis dock, as a batch for the LLM."""
        dock = self._show_analysis_dock()
        if dock is None:
            return
        if not folder:
            dock.show_message(tr("Select a file to see what it is."))
            return
        name = folder.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1] or folder
        dock.offer_folder(pane.backend, folder, name)

    def analyse_active_with_sift(self) -> None:
        """Tools > Analyse with sift: the active pane's selection, or the
        folder it shows when nothing is selected."""
        pane = self._active_pane
        if pane is None:
            dock = self._show_analysis_dock()
            if dock is not None:
                dock.show_message(tr("No file pane is active."))
            return
        if not pane.selected_file_items():
            self.analyse_folder_with_sift(pane, pane.current_path)
            return
        dock = self._show_analysis_dock()
        if dock is not None:
            self._analyse_pane_selection(dock, pane, explicit=True)

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
        self._drop_archive_views(0)
        self._archive_views.append({"path": path, "chain": (), "origin": path, "tempdir": None})
        self._show_archive_view()

    def _show_archive_view(self) -> None:
        """Put the innermost archive view of :attr:`_archive_views` into
        the dock."""
        from PyQt6.QtWidgets import QDockWidget

        from ui.archive_pane import ArchivePaneWidget

        view = self._archive_views[-1]
        path, chain = view["path"], view["chain"]
        # Extractions land next to the archive on disk, also from inside
        # a nested one (whose own file sits in a temp folder).
        parent = os.path.dirname(view["origin"])
        # ``on_open_member`` is left None; the open_member signal is
        # wired below so the slot is the MainWindow's extractor rather
        # than a pane-internal callback.
        pane = ArchivePaneWidget(path, on_open_member=None, chain=chain)
        basename = pane.display_name()
        pane.extract_all.connect(lambda p=path, d=parent: self._archive_extract_all(p, d))
        pane.extract_selected.connect(
            lambda members, p=path, d=parent: self._archive_extract_selected(p, members, d)
        )
        pane.extract_to.connect(lambda p=path: self._archive_extract_to(p))
        pane.extract_selected_to.connect(
            lambda members, p=path: self._archive_extract_selected_to(p, members)
        )
        pane.open_member.connect(lambda member, p=path: self._archive_open_member(p, member))
        pane.back_requested.connect(self._archive_back)

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

    def _archive_open_nested(self, archive_path: str, member: str) -> None:
        """Open *member* of the shown archive - itself an archive - as the
        next view: extracted (core.archive.extract_nested_archive, depth
        and size bounded, every extraction guard) into a temp folder that
        lives as long as the view."""
        import shutil
        import tempfile as _tempfile

        from core import archive as ARCH

        if not self._archive_views or self._archive_views[-1]["path"] != archive_path:
            return  # a signal of a view that is gone
        view = self._archive_views[-1]
        workdir = _tempfile.mkdtemp(prefix="axross-archive-nested-")
        try:
            nested = self._extract_off_the_gui_thread(
                f"Opening {os.path.basename(member)}…",
                lambda progress: ARCH.extract_nested_archive(
                    archive_path,
                    member,
                    workdir,
                    depth=len(view["chain"]) + 1,
                    progress=progress,
                ),
            )
        except ARCH.ExtractCancelled:
            shutil.rmtree(workdir, ignore_errors=True)
            return
        except NotImplementedError:
            shutil.rmtree(workdir, ignore_errors=True)
            QMessageBox.information(
                self,
                "Open Archive",
                "Opening an archive inside a 7z or RAR archive is not supported — "
                "extract it first.",
            )
            return
        except (ARCH.UnsafeArchive, ARCH.RarUnavailable, KeyError, OSError) as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            QMessageBox.warning(self, "Open Archive", f"Could not open {member}:\n{exc}")
            log.warning("Nested archive %r of %s not opened: %s", member, archive_path, exc)
            return
        if not self._archive_views or self._archive_views[-1] is not view:
            # The window stayed live during the extraction: another archive,
            # or Back replaced this view meanwhile.
            shutil.rmtree(workdir, ignore_errors=True)
            return
        chain = (*view["chain"], os.path.basename(archive_path))
        self._archive_views.append(
            {"path": nested, "chain": chain, "origin": view["origin"], "tempdir": workdir}
        )
        self._show_archive_view()

    def _extract_off_the_gui_thread(self, text: str, work):
        """Run ``work(progress)`` on a worker thread while the window stays
        live, with a Cancel dialog after 250 ms; return its result or raise
        its exception (core.archive.ExtractCancelled after Cancel)."""
        import threading

        from PyQt6.QtWidgets import QProgressDialog

        from core import archive as ARCH

        dialog = QProgressDialog(text, "Cancel", 0, 0, self)
        dialog.setWindowTitle("Open Archive")
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(250)
        cancel = threading.Event()
        dialog.canceled.connect(cancel.set)  # read by the worker, never the widget
        done = threading.Event()
        state: dict = {}

        def progress(_done: int, _total: int, _name: str) -> None:
            if cancel.is_set():
                raise ARCH.ExtractCancelled("cancelled")

        def run() -> None:
            try:
                state["value"] = work(progress)
            except BaseException as exc:  # noqa: BLE001 - handed to the GUI thread
                state["error"] = exc
            finally:
                done.set()

        threading.Thread(target=run, daemon=True, name="archive-nested").start()
        while not done.is_set():
            QApplication.processEvents()
            done.wait(0.05)
        dialog.close()
        dialog.deleteLater()
        if "error" in state:
            raise state["error"]
        return state["value"]

    def _archive_back(self) -> None:
        """Back from a nested archive to the one it was opened from."""
        if len(self._archive_views) < 2:
            return
        self._drop_archive_views(len(self._archive_views) - 1)
        self._show_archive_view()

    def _drop_archive_views(self, keep: int) -> None:
        """Forget every archive view past the first *keep* and remove the
        temp folders of the nested ones."""
        import shutil

        for view in self._archive_views[keep:]:
            if view["tempdir"]:
                shutil.rmtree(view["tempdir"], ignore_errors=True)
        del self._archive_views[keep:]

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

    def _archive_extract_all(self, archive_path: str, parent: str | None = None) -> None:
        from core import archive as ARCH

        parent = parent or os.path.dirname(archive_path)
        base = ARCH.strip_archive_extension(os.path.basename(archive_path))
        try:
            target = ARCH.auto_suffix_dir(parent, base)
        except OSError as exc:
            QMessageBox.warning(self, "Extract Archive", f"Cannot pick a target folder:\n{exc}")
            return
        self._run_archive_extraction(archive_path, target, None, title="Extract Archive")

    def _archive_extract_selected(
        self, archive_path: str, members: list[str], parent: str | None = None
    ) -> None:
        from core import archive as ARCH

        if not members:
            QMessageBox.information(
                self,
                "Extract Selection",
                "Nothing selected — please select files or folders in the tree.",
            )
            return
        parent = parent or os.path.dirname(archive_path)
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

    def _archive_extract_selected_to(self, archive_path: str, members: list[str]) -> None:
        """Extract the selected members into a folder the user picks."""
        from PyQt6.QtWidgets import QFileDialog

        if not members:
            self._archive_extract_selected(archive_path, members)  # says "nothing selected"
            return
        parent = QFileDialog.getExistingDirectory(self, "Extract selection into folder")
        if parent:
            self._archive_extract_selected(archive_path, members, parent)

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
        viewer open. A member that is itself an archive opens as the next
        archive view instead (:meth:`_archive_open_nested`)."""
        from core import archive as ARCH
        from ui.file_pane import open_local_file_in_viewer

        if ARCH.is_supported_archive(member_name):
            self._archive_open_nested(archive_path, member_name)
            return
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
        for view in self._archive_views:
            if view["tempdir"]:
                shutil.rmtree(view["tempdir"], ignore_errors=True)
                view["tempdir"] = None

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
            analysis_toggle.setText(tr("&Analysis (sift)"))
            analysis_toggle.setShortcut(QKeySequence("Ctrl+Shift+I"))
            self._dock_view_menu.addAction(analysis_toggle)
        agent = getattr(self, "_agent_dock", None)
        if agent is not None:
            agent_toggle = agent.toggleViewAction()
            agent_toggle.setText("A&gent")
            self._dock_view_menu.addAction(agent_toggle)
            focus = getattr(self, "_focus_agent_action", None)
            if focus is not None:
                self._dock_view_menu.addAction(focus)
        if getattr(self, "_archive_dock", None) is not None:
            self._register_archive_dock_view_action()

    def _setup_central(self) -> None:
        self._setup_workspaces()
        self._add_pane_to_splitter(self._root_splitter, LocalFS())

    def _new_file_pane(self, backend) -> FilePaneWidget:
        """A file pane wired to the window - the one place every file pane
        is made (splits, connections, restored layouts, layout presets).
        It starts with the window's View settings, Show Hidden Files
        among them: a pane made with the model default showed no hidden
        files while the menu said it did."""
        pane = FilePaneWidget(backend, async_initial_load=True)
        pane.set_show_hidden(self._hidden_action.isChecked())
        pane.set_hidden_style(self._highlight_hidden, self._hidden_color)
        pane.pane_focused.connect(lambda p=pane: self._set_active_pane(p))
        pane.view_mode_changed.connect(lambda _mode, p=pane: self._sync_view_mode_action(p))
        pane.selection_changed.connect(lambda p=pane: self._extension_event("selection_changed", p))
        pane.path_changed.connect(lambda _path, p=pane: self._extension_event("path_changed", p))
        pane.path_changed.connect(lambda _path, p=pane: self._agent_follow_pane(p))
        pane.transfer_requested.connect(lambda paths, p=pane: self._transfer_from_pane(p, paths))
        pane.move_requested.connect(lambda paths, p=pane: self._move_from_pane(p, paths))
        pane.paste_requested.connect(lambda p=pane: self._paste_cut_into(p))
        pane.drop_transfer_requested.connect(self._on_drop_transfer)
        pane.bookmark_requested.connect(self._on_bookmark_request)
        pane.close_requested.connect(lambda p=pane: self._close_pane(p))
        pane.set_as_target_requested.connect(lambda p=pane: self._set_target_pane(p))
        pane.pane_drop_requested.connect(self._on_pane_drop)
        pane.open_bookmarks_requested.connect(self._show_bookmarks_popup)
        pane.open_duplicates_requested.connect(self._open_cas_duplicates)
        pane.find_files_requested.connect(
            lambda folder, p=pane: self._open_find_files(pane=p, folder=folder)
        )
        pane.open_terminal_requested.connect(
            lambda directory, p=pane: self._open_terminal_here(p, directory)
        )
        pane.send_to_agent_requested.connect(lambda paths, p=pane: self._send_to_agent(p, paths))
        pane.new_agent_tab_requested.connect(lambda folder: self._new_agent_tab(folder or None))
        pane.analyse_requested.connect(lambda entries, p=pane: self.analyse_with_sift(p, entries))
        pane.analyse_folder_requested.connect(
            lambda folder, p=pane: self.analyse_folder_with_sift(p, folder)
        )
        pane.cycle_pane_requested.connect(
            lambda forward: self._cycle_next_pane() if forward else self._cycle_prev_pane()
        )
        pane.selection_changed.connect(lambda p=pane: self._on_pane_selection_changed(p))
        return pane

    def _add_pane_to_splitter(
        self,
        splitter: QSplitter,
        backend,
        profile=None,
        password="",
        key_passphrase="",
    ) -> FilePaneWidget:
        pane = self._new_file_pane(backend)
        splitter.addWidget(pane)
        self._panes.append(pane)
        if profile is not None:
            self._pane_profiles[pane] = profile
            pane.profile_name = profile.name
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
        self._note_active_workspace(pane)
        if self._target_pane is pane:
            self._target_pane = next((p for p in self._panes if p is not pane), None)
        self._refresh_pane_styles()
        self._sync_view_mode_action()
        if changed:
            self._extension_event("pane_activated", pane)
            self._agent_follow_pane(pane)
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
        self.open_settings("extensions")

    def _open_extensions_folder(self, _checked: bool = False) -> None:
        """Extensions > Open Extensions Folder: the folder in the active
        pane when it is local, else in a new local pane - created first when
        missing. Before, it went to the desktop's opener only, which the
        frozen binary could not start, and nothing at all happened."""
        from core import extensions as EX
        from ui.extensions_dialog import ensure_extensions_folder

        try:
            folder = str(ensure_extensions_folder())
        except OSError as exc:
            log.warning("Cannot create the extensions folder: %s", exc)
            self.statusBar().showMessage(
                tr("Could not create {folder}: {error}").format(
                    folder=EX.extensions_dir(), error=exc.strerror or exc
                ),
                8000,
            )
            return
        pane = self._active_pane
        if pane is not None and isinstance(pane.backend, LocalFS):
            pane.navigate_async(folder)
        else:
            self.open_local_folder(folder)
        self.statusBar().showMessage(tr("Extensions folder: {folder}").format(folder=folder), 8000)

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
                profile = self._pane_profiles.get(pane)
                label = _terminal_name(backend, profile)
                if label not in seen:
                    seen.add(label)
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
        self._wire_terminal_pane(term_pane)
        self._place_terminal_pane(term_pane, beside_pane)
        log.info("Opened terminal pane: %s", label)

    def _place_terminal_pane(
        self, term_pane: TerminalPaneWidget, beside_pane: FilePaneWidget | None
    ) -> None:
        """Put *term_pane* beside *beside_pane* (default: the active
        pane), or add it to the root splitter when there is none - or when
        that pane is in another workspace than the one on screen: in a
        workspace without file panes the active pane is elsewhere, and the
        new shell landed in a workspace nobody was looking at."""
        # Find the splitter containing the target pane and add terminal beside it
        target = beside_pane or self._active_pane
        if target is not None and self.workspace_of(target) is not self._current_ws:
            target = None
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
        if (
            isinstance(parent, QSplitter)
            and parent.count() == 1
            and not self._is_workspace_root(parent)
        ):
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                idx = grandparent.indexOf(parent)
                remaining = parent.widget(0)
                grandparent.replaceWidget(idx, remaining)
                remaining.show()
                parent.deleteLater()
        self._prune_empty_workspaces()

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
        pane = self._new_file_pane(LocalFS())
        self._panes.append(pane)
        return pane

    def _preset_make_terminal_pane(
        self, profile_name: str, cwd: str | None = None
    ) -> "TerminalPaneWidget":
        """Factory hook for layout_presets and the session restore — returns
        a TerminalPaneWidget. ``profile_name`` is "local" for a local shell
        or a saved connection profile name for an SSH session, which
        connects as the pane starts; either starts in *cwd* when given (a
        remote shell is sent a ``cd`` there)."""
        if profile_name == "local":
            term = TerminalPaneWidget(label="Local Shell", cwd=cwd)
        else:
            profile = self._profile_manager.get(profile_name)
            term = TerminalPaneWidget(
                label=profile_name if profile else "Local Shell",
                profile=profile,
                connection_manager=self._connection_manager,
                cwd=cwd if profile else None,
            )
        self._wire_terminal_pane(term)
        return term

    def _wire_terminal_pane(self, term: TerminalPaneWidget) -> None:
        """Connect *term* to the window and list it - the one place for
        every terminal pane (embedded, restored, preset, bookmark). A pane
        made without it had a close button that did nothing, a shell that
        ran until the window closed, and took no dragged pane."""
        term.close_requested.connect(lambda tp=term: self._close_terminal_pane(tp))
        term.bookmark_requested.connect(lambda tp=term: self._bookmark_terminal(tp))
        term.pane_drop_requested.connect(self._on_pane_drop)
        self._terminal_panes.append(term)

    def _preset_tear_down_existing(self) -> None:
        """Close the current workspace's panes before a new preset takes
        its place, so we don't leak backend sessions / SSH transports. The
        other workspaces keep theirs."""
        self._tear_down_panes(*self._widgets_of(self._current_ws))

    def _tear_down_panes(self, panes, terminals, placeholders) -> None:
        """Close the given file panes, terminal panes and placeholders.

        Each pane gives back what it holds, as _close_pane and
        _close_terminal_pane do: a saved connection's reference and its
        terminal-dock entry, and a terminal's shell. ``close()`` alone
        stopped neither - TerminalPaneWidget has no closeEvent. The widgets
        go with the root splitter that held them."""
        for pane in list(panes):
            profile = self._pane_profiles.pop(pane, None)
            try:
                if _is_ssh_session(pane.backend):
                    name = _terminal_name(pane.backend, profile)
                    still_used = any(
                        other not in panes
                        and _is_ssh_session(other.backend)
                        and _terminal_name(other.backend, self._pane_profiles.get(other)) == name
                        for other in self._panes
                    )
                    if not still_used:
                        self._terminal_dock.remove_ssh_session(name)
                if profile is not None:
                    self._release_pane_connection(profile, pane.backend)
            except Exception:  # noqa: BLE001 — a dead session must not block the switch
                log.debug("Pane teardown: releasing %s failed", pane, exc_info=True)
            self._close_compare_windows_for(pane)
            try:
                pane.close()
            except Exception:  # noqa: BLE001
                pass
            if pane in self._panes:
                self._panes.remove(pane)
            self._pane_passwords.pop(pane, None)
            self._pane_key_passphrases.pop(pane, None)
            if pane is self._active_pane:
                self._active_pane = None
            if pane is self._target_pane:
                self._target_pane = None
        for term in list(terminals):
            try:
                term.shutdown()
                term.close()
            except Exception:  # noqa: BLE001
                pass
            if term in self._terminal_panes:
                self._terminal_panes.remove(term)
        for placeholder in list(placeholders):
            placeholder.close()  # holds nothing; its root splitter deletes it
            if placeholder in self._pane_placeholders:
                self._pane_placeholders.remove(placeholder)

    def _refresh_after_preset(self) -> None:
        """Settle internal state after a fresh preset takes effect:
        pick the first file pane (if any) as active, refresh styles."""
        mine = self._widgets_of(self._current_ws)[0]
        if mine:
            self._set_active_pane(mine[0])
        if len(mine) >= 2:
            self._target_pane = mine[1]
        self._settle_source_and_target()

    def apply_layout_preset(self, name: str) -> None:
        """Public entry point — set the central layout from a named
        preset (see :mod:`ui.layout_presets`)."""
        from ui.layout_presets import apply_preset

        apply_preset(self, name)

    def _layout_switch_confirmed(self) -> bool:
        """A layout switch rebuilds every pane: ask first when that closes
        a running shell or a remote connection. The key chord is easy to
        hit by accident, and the switch used to kill them unasked."""
        panes, terminals, _holders = self._widgets_of(self._current_ws)
        shells = sum(1 for term in terminals if getattr(term, "is_running", False))
        remotes = sum(1 for pane in panes if pane in self._pane_profiles)
        if not shells and not remotes:
            return True
        lost = []
        if shells:
            lost.append(f"{shells} shell{'s' if shells != 1 else ''}")
        if remotes:
            lost.append(f"{remotes} connection{'s' if remotes != 1 else ''}")
        reply = QMessageBox.question(
            self,
            tr("Switch Layout"),
            f"Switching the layout closes {' and '.join(lost)}. Switch anyway?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def cycle_layout_preset(self, *, forward: bool = True) -> None:
        """Rotate through the built-in preset list. Wired to
        ``Ctrl+Alt+L`` (forward) and ``Ctrl+Alt+Shift+L`` (back)."""
        from ui.layout_presets import cycle_preset

        if not self._layout_switch_confirmed():
            return
        new_name = cycle_preset(self, forward=forward)
        # Lightweight statusbar hint so the user sees what they cycled to.
        try:
            self.statusBar().showMessage(f"Layout: {new_name}", 2000)
        except Exception:  # noqa: BLE001
            pass

    def _release_pane_connection(self, profile, backend) -> None:
        """Give back a closing pane's reference on its connection - once
        no transfer uses it any more. Released at once, a session whose
        last reference that was got disconnected under its running and
        queued transfers, and every one of them failed."""
        if not self._transfer_manager.busy(backend):
            self._connection_manager.release(profile)
            return
        self._deferred_releases.append((profile, backend))
        log.info("%s stays connected until its transfers finish", profile.name)
        self.statusBar().showMessage(
            f"{profile.name}: the connection stays open until its transfers finish", 8000
        )

    def _release_idle_connections(self, *_args) -> None:
        """A transfer ended: release the kept connections it was the last
        user of."""
        for entry in list(self._deferred_releases):
            profile, backend = entry
            if self._transfer_manager.busy(backend):
                continue
            self._deferred_releases.remove(entry)
            try:
                self._connection_manager.release(profile)
            except Exception:  # noqa: BLE001 - a dead session must not stop the others
                log.debug("Releasing %s after its transfers failed", profile.name, exc_info=True)

    def _close_pane(self, pane: FilePaneWidget) -> None:
        if pane not in self._panes or len(self._panes) <= 1:
            return

        profile = self._pane_profiles.pop(pane, None)
        self._pane_passwords.pop(pane, None)
        self._pane_key_passphrases.pop(pane, None)

        # Remove SSH terminal option only when no other pane uses the same session label.
        if _is_ssh_session(pane.backend):
            name = _terminal_name(pane.backend, profile)
            still_used = any(
                other is not pane
                and _is_ssh_session(other.backend)
                and _terminal_name(other.backend, self._pane_profiles.get(other)) == name
                for other in self._panes
            )
            if not still_used:
                self._terminal_dock.remove_ssh_session(name)

        if profile is not None:
            self._release_pane_connection(profile, pane.backend)
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
        if (
            isinstance(parent, QSplitter)
            and parent.count() == 1
            and not self._is_workspace_root(parent)
        ):
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                idx = grandparent.indexOf(parent)
                remaining = parent.widget(0)
                grandparent.replaceWidget(idx, remaining)
                remaining.show()
                parent.deleteLater()
        elif (
            isinstance(parent, QSplitter)
            and parent.count() == 0
            and not self._is_workspace_root(parent)
        ):
            parent.deleteLater()
        # The last pane of a workspace closes the workspace (never the last).
        self._prune_empty_workspaces()

        if self._panes:
            # Only a closed source needs a new one: re-activating the first
            # pane whatever was closed turned the source into the target
            # and F5 / F6 ran the other way round.
            if self._active_pane is None:
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
        """Make every pane of the current workspace (the tab on screen, or
        the detached window worked in) the same size - its file panes,
        terminals and extension panels. Splitting nests splitters of the
        same orientation, so evening out only the active pane's own
        splitter left e.g. 324 | 324 | 651 as it was. The active file
        pane's layout was evened out before, which in a workspace of
        terminals or extension panels only is another workspace, not the
        one on screen."""
        from PyQt6 import sip

        ws = getattr(self, "_current_ws", None)
        if ws is not None and not sip.isdeleted(ws.root):
            self._equalize_splitter(ws.root)
            return
        if not self._active_pane:
            return
        root = self._active_pane.parent()
        if not isinstance(root, QSplitter):
            return
        while isinstance(root.parent(), QSplitter):
            root = root.parent()
        self._equalize_splitter(root)

    @classmethod
    def _pane_count_along(cls, widget, orientation) -> int:
        """How many panes *widget* puts side by side along *orientation*."""
        if isinstance(widget, QSplitter) and widget.orientation() == orientation:
            return sum(
                cls._pane_count_along(widget.widget(i), orientation)
                for i in range(widget.count())
                if not widget.widget(i).isHidden()
            ) or 1
        return 1

    def _equalize_splitter(self, splitter: QSplitter) -> None:
        """Size *splitter*'s children by the panes each holds along its
        axis, then do the same inside each child splitter."""
        orientation = splitter.orientation()
        children = [splitter.widget(i) for i in range(splitter.count())]
        weights = [0 if c.isHidden() else self._pane_count_along(c, orientation)
                   for c in children]
        if splitter.count() > 1 and sum(weights):
            unit = equal_split_sizes(self._splitter_extent(splitter, orientation), sum(weights))[0]
            splitter.setSizes([unit * w for w in weights])
        for child in children:
            if isinstance(child, QSplitter):
                self._equalize_splitter(child)

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

    @staticmethod
    def _pane_name(pane) -> str:
        """A file pane's backend name, a terminal pane's label or an
        extension panel's title, for the log."""
        if isinstance(pane, TerminalPaneWidget):
            return pane.session_label
        if isinstance(pane, ExtensionDock):
            return pane.windowTitle()
        return pane.backend.name

    def _on_pane_drop(self, source_pane_id: str, target_pane, zone: str) -> None:
        """A pane - file or terminal - was dropped onto another one, in
        this workspace or another: split the target and put the dragged
        pane on the *zone* side. An unknown id, a target that is no pane
        of this window, or a pane dropped on itself changes nothing."""
        movable = [*self._panes, *self._terminal_panes, *self._layout_panels()]
        source_pane = next((p for p in movable if str(id(p)) == source_pane_id), None)
        if source_pane is None or not any(p is target_pane for p in movable):
            return
        if source_pane is target_pane or source_pane.isAncestorOf(target_pane):
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
        if isinstance(source_parent, QSplitter) and not self._is_workspace_root(source_parent):
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
        # Dragged out of another workspace: that one may be empty now.
        self._prune_empty_workspaces()

        log.info(
            "Pane rearranged: %s dropped %s of %s",
            self._pane_name(source_pane),
            zone,
            self._pane_name(target_pane),
        )

    def _extract_pane_from_split(self) -> None:
        """Pull the active pane out of a nested splitter back to the root level."""
        if not self._active_pane:
            return
        parent = self._active_pane.parent()
        if not isinstance(parent, QSplitter) or self._is_workspace_root(parent):
            return  # Already at root level

        pane = self._active_pane
        workspace = self.workspace_of(pane)
        root = workspace.root if workspace is not None else self._root_splitter

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

        # Add pane to the root splitter of its workspace
        root.addWidget(pane)
        pane.show()
        count = root.count()
        root.setSizes(
            equal_split_sizes(
                self._splitter_extent(root, root.orientation()),
                count,
            )
        )
        log.info("Pane extracted to root: %s", pane.backend.name)

    def _toggle_hidden(self, show: bool) -> None:
        for pane in self._panes:
            pane.set_show_hidden(show)
            pane.refresh_after_change()

    def set_show_hidden(self, show: bool, *, store: bool = True) -> None:
        """Show Hidden Files for every pane (the Ctrl+H switch follows)."""
        self._hidden_action.setChecked(bool(show))
        if store:
            self.store_window_prefs(**{SHOW_HIDDEN_KEY: bool(show)})

    def _store_show_hidden(self, checked: bool) -> None:
        self._quietly(self.store_window_prefs, **{SHOW_HIDDEN_KEY: bool(checked)})

    @staticmethod
    def _quietly(setter, *args, **kwargs) -> None:
        """Run a preference *setter* from a menu or key: the change applies
        even when it cannot be stored (store_window_prefs logged why)."""
        try:
            setter(*args, **kwargs)
        except OSError:
            pass

    def set_highlight_hidden(self, on: bool, *, store: bool = True) -> None:
        """Hidden entries in italics and a muted (or the chosen) colour."""
        self._highlight_hidden = bool(on)
        for pane in self._panes:
            pane.set_hidden_style(self._highlight_hidden, self._hidden_color)
        if store:
            self.store_window_prefs(**{HIGHLIGHT_HIDDEN_KEY: self._highlight_hidden})

    def set_hidden_color(self, colour: str | None, *, store: bool = True) -> None:
        """The colour of hidden entries in every pane; ``None`` is the
        theme's muted colour. Anything but ``#rrggbb`` counts as ``None``."""
        colour = colour.lower() if themes.is_hex_colour(colour) else None
        self._hidden_color = colour
        for pane in self._panes:
            pane.set_hidden_style(self._highlight_hidden, colour)
        if store:
            self.store_window_prefs(**{HIDDEN_COLOR_KEY: colour})

    @staticmethod
    def hidden_colour_contrast(colour: str) -> float:
        """The worse WCAG contrast of *colour* against the two row
        backgrounds of the current theme (Settings > Appearance asks before
        it uses a colour below themes.MIN_TEXT_CONTRAST)."""
        palette = QApplication.palette()
        return min(
            themes.contrast_ratio(colour, palette.color(QPalette.ColorRole.Base).name()),
            themes.contrast_ratio(colour, palette.color(QPalette.ColorRole.AlternateBase).name()),
        )

    # ------------------------------------------------------------------
    # Scheduled jobs
    # ------------------------------------------------------------------

    def _job_store(self):
        """The on-disk schedule, alongside the operation journal."""
        from pathlib import Path

        from core.operation_journal import JOURNAL_PATH
        from core.scheduler import JobStore

        return JobStore(Path(JOURNAL_PATH).parent / "jobs.json")

    def _open_scheduler(self) -> None:
        from ui.scheduler_dialog import SchedulerDialog

        dlg = SchedulerDialog(self._job_store(), parent=self)
        dlg.exec()
        # Pick up edits without waiting for the next tick.
        self._scheduler_jobs = self._with_running_flags(self._job_store().load())
        if getattr(self, "_scripts_dock", None) is not None:
            self._scripts_dock.refresh()  # the [scheduled] markers

    def _with_running_flags(self, jobs: list, *, finished: str = "") -> list:
        """*jobs* as loaded from the store, with the in-process ``running``
        flag carried over from the current list. The store never holds it:
        a reload that dropped it let the next tick start a job that was
        still in flight a second time. *finished* names the job whose run
        just ended."""
        from dataclasses import replace

        running = {
            j.job_id
            for j in getattr(self, "_scheduler_jobs", None) or ()
            if j.running and j.job_id != finished
        }
        return [replace(j, running=True) if j.job_id in running else j for j in jobs]

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
    def _scheduled_runner(job, cancel_event=None):
        """What a job actually does. Runs on a worker thread; a script
        runs in a child process (core.scheduler.run_script_job), which
        *cancel_event* stops."""
        from core.scheduler import run_script_job

        return run_script_job(job, cancel_event=cancel_event)

    def _run_scheduled_job(self, job) -> None:
        """Start one job on a worker thread.

        Off the GUI thread on purpose: the first wiring called
        run_script straight from the timer slot, so a nightly mirror
        over SFTP froze the window for as long as it took — the one
        thing a background schedule must never do.

        The outcome comes back through a queued signal so the store is
        written and the status bar touched on the GUI thread only.
        """
        import functools
        import threading

        from PyQt6.QtCore import QThread

        from core.scheduler import run_job

        done = self._scheduler_done
        cancel = getattr(self, "_scheduler_cancel", None)
        if cancel is None:
            # Set on close: a scheduled script's child process ends with the app.
            cancel = self._scheduler_cancel = threading.Event()
        runner = functools.partial(self._scheduled_runner, cancel_event=cancel)

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
        at = datetime.now()

        def _record(jobs: list) -> list:
            # The result goes onto the job as the store holds it now: the
            # Scheduler dialog may have changed or removed it meanwhile,
            # and a job removed there stays removed.
            return [
                record_result(j, ok=ok, at=at, detail=detail) if j.job_id == job_id else j
                for j in jobs
            ]

        try:
            jobs = self._job_store().update(_record)
        except OSError as exc:
            log.warning("scheduler: could not persist job state: %s", exc)
            jobs = _record(self._scheduler_jobs)
        self._scheduler_jobs = self._with_running_flags(jobs, finished=job_id)
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
        from core.undo import apply_undo, gone_reason, pick_undoable, undoable

        try:
            events = read_recent(limit=200)
        except Exception as exc:  # noqa: BLE001 — a broken journal must not block the app
            log.warning("undo: could not read the journal: %s", exc)
            QMessageBox.warning(self, "Undo", f"Could not read the operation journal:\n{exc}")
            return

        plans = undoable(events)
        by_label = self._backends_by_label()

        def _gone(candidate) -> bool:
            # An entry restored or deleted in the Trash window is not in
            # the journal; offering it again would block every older one.
            entry = by_label.get(candidate.backend) if candidate.backend else None
            if entry is None and not candidate.backend and len(by_label) == 1:
                entry = next(iter(by_label.values()))
            return entry is not None and bool(gone_reason(candidate, entry[0]))

        plan = pick_undoable(plans, set(by_label), gone=_gone)
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
        queued: list = []

        def transfer(**kwargs):
            return self._undo_transfer(queued=queued, **kwargs)

        try:
            apply_undo(
                plan,
                backend,
                source_backend=self._undo_source_backend(plan, by_label),
                transfer=transfer,
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Undo failed", str(exc))
            return
        if plan.action == "transfer_back":
            # Only queued so far: recording it now would drop the entry
            # from the undo history even when the transfer back fails.
            self._await_undo_jobs(plan, queued, pane)
            return
        self._finish_undo(plan, pane)

    def _finish_undo(self, plan, pane, jobs=()) -> None:
        try:
            from core.undo import record_undone

            # The next Ctrl+Z reaches the operation before this one - not
            # the move back the jobs of this undo journaled.
            record_undone(plan, by=[getattr(j, "operation_id", "") for j in jobs])
        except Exception as exc:  # noqa: BLE001 - the undo itself succeeded
            log.warning("undo: could not record the undo in the journal: %s", exc)
        if pane is not None and pane in self._panes:
            pane.refresh_after_change()
        self.statusBar().showMessage(f"Undone: {plan.reason}", 5000)

    def _await_undo_jobs(self, plan, jobs: list, pane) -> None:
        """Record *plan* as undone when every job of it has finished."""
        from core.transfer_worker import TransferStatus

        refused = [j for j in jobs if j.status is TransferStatus.ERROR]
        if not jobs or refused:
            why = refused[0].error_message if refused else "nothing was queued"
            QMessageBox.warning(self, "Undo failed", f"{plan.reason} failed:\n{why}")
            return
        self._undo_waits.append(
            {"plan": plan, "pending": {j.job_id for j in jobs}, "pane": pane, "jobs": jobs}
        )
        self.statusBar().showMessage(f"Undoing: {plan.reason}", 5000)

    def _on_undo_job_finished(self, job_id: str) -> None:
        for wait in list(self._undo_waits):
            if job_id not in wait["pending"]:
                continue
            wait["pending"].discard(job_id)
            if not wait["pending"]:
                self._undo_waits.remove(wait)
                self._finish_undo(wait["plan"], wait["pane"], wait.get("jobs", ()))

    def _on_undo_job_error(self, job_id: str, error: str) -> None:
        for wait in list(self._undo_waits):
            if job_id not in wait["pending"]:
                continue
            self._undo_waits.remove(wait)
            plan = wait["plan"]
            QMessageBox.warning(
                self,
                "Undo failed",
                f"{plan.reason} failed:\n{error}\n\n"
                "The operation stays in the undo history.",
            )

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

    def _undo_transfer(
        self, *, src_backend, src_path, dst_backend, dst_path, queued: list | None = None
    ) -> str:
        """Move data back to *dst_path* through the normal transfer engine.

        The target folder is the one the data came from - not the folder a
        pane on that connection happens to show now, where a file of the
        same name would be overwritten. The jobs are appended to *queued*:
        the undo is done when they are, not when they are queued.
        """
        from core.path_policy import safe_join, transfer_leaf
        from core.transfer_conflicts import IF_EXISTS_FAIL, ConflictPlan

        src_name = src_path.rsplit(src_backend.separator(), 1)[-1]
        dst_name = dst_path.rsplit(dst_backend.separator(), 1)[-1]
        if dst_backend.exists(dst_path):
            raise OSError(
                f"{dst_path} exists again — undo would overwrite it. Move or rename it first."
            )
        direction = self._transfer_direction(src_backend, dst_backend)
        if src_name == dst_name:
            jobs = self._transfer_manager.transfer_files(
                source_backend=src_backend,
                dest_backend=dst_backend,
                source_paths=[src_path],
                dest_dir=dst_backend.parent(dst_path),
                direction=direction,
                move=True,
                # The check above looked once; a file that appears before the
                # job runs is not replaced either.
                conflict_plan=ConflictPlan.never_replace(dst_backend),
            )
        else:
            # The move stored the file under another name ("Rename" at the
            # conflict prompt), which transfer_files cannot give back: it
            # names the result after the source. The journal holds one entry
            # per file, so this is one file job, refusing an existing name.
            try:
                leaf = transfer_leaf(src_backend, dst_backend, dst_name)
                target = safe_join(dst_backend, dst_backend.parent(dst_path), leaf)
            except ValueError as exc:
                raise OSError(f"undo cannot put {src_path} back as {dst_path}: {exc}") from exc
            jobs = [
                self._transfer_manager.transfer_file(
                    src_backend, dst_backend, src_path, target, direction,
                    move=True, if_exists=IF_EXISTS_FAIL,
                )
            ]
        if queued is not None:
            queued.extend(jobs)
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
            # Only an action that says it overwrites may replace a file:
            # a "missing" one that exists by the time it runs fails instead.
            for overwrites in (False, True):
                pairs = [
                    (i["source"], i["dest"])
                    for i in items
                    if i["direction"] == direction
                    and i.get("kind") == "copy"
                    and bool(i.get("overwrites")) is overwrites
                ]
                if pairs:
                    self._transfer_compared(source, target, pairs, overwrites=overwrites)

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
        # The window copies one-sided rows only: the destination was
        # free when compared, and a file there now is not to be replaced.
        self._transfer_compared(source, target, pairs, overwrites=False)

    def _transfer_compared(self, source, target, pairs, *, overwrites: bool) -> None:
        """Queue ``(source, dest)`` pairs so each lands at its own path.

        ``_start_transfer_between`` on its own queues into the target
        pane's CURRENT folder: a file from ``sub/`` landed beside the
        compared root's files (or wherever the pane had browsed to) and
        replaced a namesake there. Grouped by destination folder, the
        name is the source's, which a comparison row shares on both sides.

        Without ``overwrites`` every job refuses to replace an existing
        destination; the transfer engine's default is to replace it.
        """
        from core.transfer_conflicts import ConflictPlan

        backend = target.backend
        conflict_plan = None if overwrites else ConflictPlan.never_replace(backend)
        by_dir: dict[str, list[str]] = {}
        for src, dst in pairs:
            by_dir.setdefault(backend.parent(dst), []).append(src)
        for dest_dir, paths in by_dir.items():
            self._start_transfer_between(
                source,
                target,
                paths,
                move=False,
                dest_dir=dest_dir,
                conflict_plan=conflict_plan,
            )

    def _delete_compared(self, pane, paths: list) -> None:
        """Delete paths the compare window asked for.

        The dialog has already confirmed and has already refused
        anything that exists on both sides. The pane holding the paths
        carries it out in the background, like its own Delete: progress
        and Cancel in its status line, errors per entry, reload at the end.
        """
        backend = getattr(pane, "backend", None)
        if backend is None or not paths or not self._compared_panes_open(pane):
            return
        pane.remove_paths(list(paths))

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
            name = _terminal_name(backend, self._pane_profiles.get(pane))
            dock.open_ssh_shell_at(name, TH.ssh_transport(backend), directory)
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
        self._index_dialog = dlg
        dlg.finished.connect(lambda _code, d=dlg: self._forget_index_dialog(d))
        dlg.open()

    def _forget_index_dialog(self, dlg) -> None:
        if self._index_dialog is dlg:
            self._index_dialog = None
        dlg.deleteLater()

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

    # ------------------------------------------------------------------
    # Find Files, Smart Folders, the offline index
    # ------------------------------------------------------------------
    def _find_scope_choices(self, pane=None, folder: str | None = None) -> list:
        """One folder per open pane: *folder* of *pane* (default: the active
        pane's folder) ticked, the other panes' folders offered unticked."""
        from core.cas import backend_id_for
        from ui.find_files_dialog import ScopeChoice

        pane = pane if pane is not None else self._active_pane
        choices = []
        seen = set()
        ordered = [p for p in (pane, *self._panes) if p is not None]
        for candidate in ordered:
            if candidate not in self._panes and candidate is not pane:
                continue
            path = folder if candidate is pane and folder else candidate.current_path
            # The backend's identity, not the object: every local pane has a
            # LocalFS of its own, and one folder was offered once per pane.
            key = (backend_id_for(candidate.backend), path)
            if not path or key in seen:
                continue
            seen.add(key)
            choices.append(
                ScopeChoice(
                    candidate.backend,
                    path,
                    checked=candidate is pane,
                    profile_name=self._pane_profile_name(candidate),
                )
            )
        return choices

    def _pane_profile_name(self, pane) -> str:
        profile = self._pane_profiles.get(pane)
        return profile.name if profile is not None else ""

    def _open_find_files(self, pane=None, folder: str | None = None, *,
                         saved: dict | None = None, choices: list | None = None) -> None:
        """Open a Find Files window (modeless: activating a result
        navigates the window behind it)."""
        from ui.find_files_dialog import FindFilesDialog

        if choices is None:
            choices = self._find_scope_choices(pane, folder)
        dlg = FindFilesDialog(choices, self, saved=saved, autostart=saved is not None)
        dlg.reveal_requested.connect(self._reveal_found)
        dlg.open_archive_requested.connect(self._open_found_archive)
        dlg.index_open_requested.connect(self._on_metadata_search_open)
        dlg.send_to_agent_requested.connect(self._send_found_to_agent)
        dlg.save_smart_folder_requested.connect(self._save_smart_folder)
        self._find_dialogs.append(dlg)
        dlg.finished.connect(lambda _code, d=dlg: self._forget_find_dialog(d))
        dlg.show()
        dlg.raise_()

    def _forget_find_dialog(self, dlg) -> None:
        self._find_dialogs = [d for d in self._find_dialogs if d is not dlg]
        dlg.deleteLater()

    def _pane_for_backend(self, backend):
        """An open pane on *backend* (the active one first); for a local
        backend any local pane, else a new local pane."""
        for pane in (self._active_pane, *self._panes):
            if pane is not None and pane in self._panes and pane.backend is backend:
                return pane
        if isinstance(backend, LocalFS):
            for pane in (self._active_pane, *self._panes):
                if pane is not None and pane in self._panes and isinstance(pane.backend, LocalFS):
                    return pane
            return self._add_pane_to_splitter(self._root_splitter, LocalFS())
        return None

    def _reveal_found(self, backend, path: str) -> None:
        pane = self._pane_for_backend(backend)
        if pane is None:
            self.statusBar().showMessage(
                tr("The connection of {path} is no longer open.").format(path=path), 8000
            )
            return
        self._set_active_pane(pane)
        pane.reveal_path(path)

    def _open_found_archive(self, backend, archive_path: str, member: str) -> None:
        """An archive member: the archive view for a local archive (and the
        archive selected in a pane); a remote archive is revealed."""
        self._reveal_found(backend, archive_path)
        if isinstance(backend, LocalFS):
            self.open_archive_pane(archive_path)
        else:
            self.statusBar().showMessage(
                tr("{member} is inside {archive}; copy the archive to a local pane to open it.")
                .format(member=member, archive=archive_path),
                10000,
            )

    def _send_found_to_agent(self, backend, paths: list) -> None:
        if isinstance(backend, LocalFS):
            dock = getattr(self, "_agent_dock", None)
            if dock is None:
                return
            self._focus_agent()
            dock.current_tab().attach(paths, None, True)
            return
        pane = self._pane_for_backend(backend)
        if pane is None:
            self.statusBar().showMessage(tr("That connection is no longer open."), 8000)
            return
        self._send_to_agent(pane, paths)

    def _save_smart_folder(self, name: str, data: dict) -> None:
        from core.bookmarks import new_smart_folder

        self._bookmark_manager.add(new_smart_folder(name, data))
        self._rebuild_bookmarks_menu()
        self.statusBar().showMessage(
            tr("Smart Folder '{name}' is in the bookmarks.").format(name=name), 6000
        )

    def _run_smart_folder(self, bookmark: Bookmark) -> None:
        """A Smart Folder was clicked: open Find Files with its search and
        run it on the folders whose connection is open."""
        from core.file_search import saved_search_from_dict
        from ui.find_files_dialog import ScopeChoice

        try:
            _query, scopes, _options = saved_search_from_dict(bookmark.search)
        except ValueError as exc:
            # Fixed first line, the name as typed below it: a message box
            # guesses rich text from the first line (escaped, "Bob's" read
            # "Bob&#x27;s" there).
            QMessageBox.warning(
                self,
                tr("Smart Folder"),
                tr("This Smart Folder cannot run.\n\nSmart Folder: {name}\nReason: {error}").format(
                    name=bookmark.name, error=exc
                ),
            )
            return
        choices = []
        for scope in scopes:
            if scope["backend_name"] == "Local":
                choices.append(ScopeChoice(LocalFS(), scope["path"]))
                continue
            pane = next(
                (p for p in self._panes
                 if not isinstance(p.backend, LocalFS) and p.backend.name == scope["backend_name"]),
                None,
            )
            choices.append(
                ScopeChoice(
                    pane.backend if pane is not None else None,
                    scope["path"],
                    profile_name=scope["profile_name"],
                    available=pane is not None,
                    backend_name=scope["backend_name"],
                )
            )
        self._open_find_files(saved=bookmark.search, choices=choices)

    def _index_active_folder(self) -> None:
        """Edit > Index Active Folder…: the Find in Index window, which shows
        where the index is stored, asks and indexes the active pane's
        folder with its status line."""
        self._open_metadata_search()
        if self._index_dialog is not None:
            self._index_dialog.start_index_active()

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
            on_delete=self._delete_connection_config,
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

    def _delete_connection_config(self, profile) -> None:
        """Quick Connect's "Delete Connection Config…": after a question,
        the profile goes - with its keyring password, as the connection
        dialog's Delete button does (ProfileManager.remove) - and out of
        the recent list. Open panes on it keep their connection."""
        name = profile.name
        if self._profile_manager.get(name) is None:
            self.statusBar().showMessage(
                tr("The connection config '{name}' was already deleted.").format(name=name), 6000
            )
            return
        reply = QMessageBox.question(
            self,
            tr("Delete Connection Config"),
            # The name never stands in the first line: Qt reads a first line
            # with markup as rich text, and a profile name is user text.
            tr("Delete this connection config?\n\n{name}\n\nIts stored password is removed "
               "from the keyring as well. Open panes keep their connection.").format(name=name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self._profile_manager.remove(name)
        except Exception as exc:  # noqa: BLE001 - shown, as the dialog's Delete does
            log.error("Failed to delete profile %s: %s", name, exc)
            QMessageBox.warning(
                self,
                tr("Delete Connection Config"),
                tr("Failed to delete profile:\n{error}").format(error=exc),
            )
            return
        if name in self._recent_profiles:
            self._recent_profiles = [n for n in self._recent_profiles if n != name]
            self._save_recents()
        log.info("Deleted profile: %s", name)
        self.statusBar().showMessage(
            tr("Deleted the connection config '{name}'.").format(name=name), 6000
        )

    def _proxy_command_confirmed(self, profile) -> bool:
        """An imported profile's ProxyCommand is shown once and runs only
        when the user says Yes; the answer is saved with the profile."""
        command = getattr(profile, "proxy_command", "")
        if not command or getattr(profile, "proxy_command_confirmed", True):
            return True
        reply = QMessageBox.question(
            self,
            tr("Run ProxyCommand?"),
            f"The profile '{profile.name}' was imported and connects through this "
            f"command, which runs on this computer:\n\n{command}\n\n"
            "Run it now and from now on?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            log.info("ProxyCommand of %s not confirmed; not connecting", profile.name)
            return False
        profile.proxy_command_confirmed = True
        try:
            self._profile_manager.add(profile)
        except Exception:  # noqa: BLE001 - confirmed for this run at least
            log.warning("Could not save the confirmation for %s", profile.name, exc_info=True)
        return True

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

        if not self._proxy_command_confirmed(profile):
            return
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
            # A key-auth profile connects without a passphrase first; an
            # encrypted key fails with PasswordRequiredException, and
            # _on_failure asks for it and tries again.
        elif proto in SIMPLE_PASSWORD_PROTOCOLS:
            needs_password, prompt_label = _simple_password_prompt(profile)
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
                self._terminal_dock.add_ssh_session(
                    _terminal_name(session, profile), session.transport
                )

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

        passphrase_tries = 0

        def _on_failure(exc):
            nonlocal key_passphrase, passphrase_tries
            if _needs_key_passphrase(exc) and passphrase_tries < KEY_PASSPHRASE_TRIES:
                from PyQt6.QtWidgets import QInputDialog

                passphrase_tries += 1
                prompt = f"Passphrase for the key {profile.key_file}:"
                if key_passphrase:
                    prompt = f"Wrong passphrase. {prompt}"
                entered, ok = QInputDialog.getText(
                    self, "Key Passphrase", prompt, QLineEdit.EchoMode.Password
                )
                if not ok:
                    log.info("Quick connect to %s: passphrase prompt cancelled", profile.name)
                    return
                key_passphrase = entered
                self._run_connect_async(profile, password, key_passphrase, _on_success, _on_failure)
                return
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
        preferences (ui.window_prefs: theme, compact mode, monochrome
        icons, zoom, Show / Highlight Hidden Files, the hidden-files colour
        and the "Restore layout on start" switch). The layout itself is
        restore_layout_on_start's job.

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
        prefs = window_prefs.parse(win)
        self._restore_on_start = prefs.restore_layout_on_start
        self._apply_window_prefs(prefs)

    def _apply_window_prefs(self, prefs: window_prefs.WindowPrefs) -> None:
        """Bring the window to *prefs* (a start, a layout restore). Stores
        nothing: the values came from the file."""
        # One theme pass for theme and compact, none when both are as they
        # are; set_monochrome_icons re-icons by itself.
        theme = prefs.theme or self._current_theme
        if theme != self._current_theme or prefs.compact != self._compact_mode:
            self._compact_mode = prefs.compact
            self._apply_theme(theme)
        self.set_icon_colours(prefs.icon_colours, prefs.icon_colour, store=False)
        self.set_monochrome_icons(prefs.monochrome_icons, store=False)
        self.set_show_hidden(prefs.show_hidden, store=False)
        self._hidden_color = prefs.hidden_color
        self.set_highlight_hidden(prefs.highlight_hidden, store=False)
        if prefs.font_size is not None:
            self.set_font_size(prefs.font_size, store=False)

    # --- Window preferences: set now, stored at once ---

    def store_window_prefs(self, **values) -> None:
        """Merge *values* into session.json's ``window`` object now, not
        only on close (Edit > Settings…, Ctrl+H, the Theme menu, zoom).
        Every other key of the file is kept."""
        try:
            previous = _read_json_file(self._SESSION_FILE)
        except (OSError, ValueError):
            previous = None
        session = previous if isinstance(previous, dict) else {}
        window = session.get("window")
        if not isinstance(window, dict):
            window = {}
        window.update(values)
        session["window"] = window
        try:
            _write_private_text(self._SESSION_FILE, json.dumps(session, indent=2))
        except OSError as exc:
            log.warning("Could not store the window settings %s: %s", sorted(values), exc)
            raise

    def current_window_prefs(self) -> window_prefs.WindowPrefs:
        """The preferences as the window has them now."""
        from ui.icon_provider import is_monochrome

        return window_prefs.WindowPrefs(
            theme=self._current_theme,
            compact=self._compact_mode,
            monochrome_icons=is_monochrome(),
            show_hidden=self._hidden_action.isChecked(),
            highlight_hidden=self._highlight_hidden,
            hidden_color=self._hidden_color,
            restore_layout_on_start=self._restore_on_start,
            font_size=self._font_size,
            icon_colours=self._icon_colours,
            icon_colour=self._icon_colour,
        )

    def set_theme(self, theme: str, *, store: bool = True) -> None:
        """Switch the theme (View > Theme, Settings > Appearance)."""
        self._apply_theme(theme)
        if store:
            self.store_window_prefs(**{window_prefs.THEME_KEY: self._current_theme})

    def set_compact_mode(self, on: bool, *, store: bool = True) -> None:
        self._toggle_compact_mode(bool(on))
        if store:
            self.store_window_prefs(**{window_prefs.COMPACT_KEY: self._compact_mode})

    def set_monochrome_icons(self, on: bool, *, store: bool = True) -> None:
        from ui.icon_provider import is_monochrome

        if bool(on) != is_monochrome():
            self._toggle_monochrome_icons(bool(on))
        if store:
            self.store_window_prefs(**{window_prefs.MONOCHROME_KEY: bool(on)})

    def set_icon_colours(self, mode: str, colour: str | None = None, *,
                         store: bool = True) -> None:
        """How icons are coloured (ui.window_prefs.ICON_COLOUR_MODES); *colour*
        is the ``#rrggbb`` of "one". A mode that is not one of them, or "one"
        without a valid colour, raises ValueError and changes nothing."""
        if mode not in window_prefs.ICON_COLOUR_MODES:
            raise ValueError(f"unknown icon colour mode: {mode!r}")
        if mode == "one" and not themes.is_hex_colour(colour):
            raise ValueError(f"not a #rrggbb colour: {colour!r}")
        colour = colour.lower() if mode == "one" else None
        if (mode, colour) != (self._icon_colours, self._icon_colour):
            self._icon_colours, self._icon_colour = mode, colour
            self._refresh_icons()
            log.info("Icon colours: %s", colour or mode)
        if store:
            self.store_window_prefs(**{window_prefs.ICON_COLOURS_KEY: mode,
                                       window_prefs.ICON_COLOUR_KEY: colour})

    def set_restore_on_start(self, on: bool, *, store: bool = True) -> None:
        self._restore_on_start = bool(on)
        if store:
            self.store_window_prefs(**{RESTORE_ON_START_KEY: self._restore_on_start})

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
                SHOW_HIDDEN_KEY: self._hidden_action.isChecked(),
                HIGHLIGHT_HIDDEN_KEY: self._highlight_hidden,
                HIDDEN_COLOR_KEY: self._hidden_color,
                RESTORE_ON_START_KEY: self._restore_on_start,
                FONT_SIZE_KEY: self._font_size,
                # Base64 of Qt's own formats: window geometry and the dock
                # layout (which docks are open, where, and how large).
                "geometry": bytes(self.saveGeometry().toBase64()).decode("ascii"),
                "dock_state": bytes(self.saveState().toBase64()).decode("ascii"),
                # The tabs axross made itself, which come apart with room.
                DOCK_FIT_SESSION_KEY: self._dock_fit.session_state(),
            }
        )
        workspaces = self._serialize_workspaces()
        session["workspaces"] = workspaces
        # An axross from before workspaces reads this one: the first.
        session["splitter"] = workspaces[0]["splitter"]
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
        items = []
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
            elif isinstance(child, ExtensionDock):
                entry = self._serialize_extension_panel(child)
            else:
                entry = None
            if entry is None:
                continue
            items.append((i, child, entry, all_sizes[i] if i < len(all_sizes) else 0))
        # The places of switched-off extensions' panels go in between.
        placed = self._place_kept_homes(splitter, items)
        children = [entry for entry, _size in placed]
        sizes = [size for _entry, size in placed]
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
        shell on a transport without a saved profile (one a host terminal
        bookmark opened included) cannot be opened again and is left out."""
        if term.is_local:
            entry: dict = {"type": "terminal", "local": True}
            cwd = term.working_directory()
            if cwd:
                entry["cwd"] = cwd
            return entry
        from core.bookmarks import is_host_profile

        if term.profile is not None and not is_host_profile(term.profile):
            return {"type": "terminal", "profile": term.profile.name}
        # A host terminal bookmark's shell has no saved profile either.
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

        if not _session_has_panes(data):
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
        were. Switched off (Edit > Settings > General), or with a
        missing, unreadable or invalid session.json, the default layout
        stays and the reason goes to the log only."""
        try:
            return self._restore_layout_on_start()
        finally:
            # Detached Agent conversations whose workspace did not come back
            # become tabs again (ui.agent_dock.AgentDock.settle_detached).
            self._settle_agent_panels()

    def _restore_layout_on_start(self) -> bool:
        if not self._restore_on_start:
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
        if not _session_has_panes(data):
            return False
        try:
            self._apply_session(data, connect_remote=False)
        except Exception:  # noqa: BLE001 - a bad layout must not stop the start
            log.exception("Layout restore failed; starting with the default layout")
            self._reset_to_default_layout()
            return False
        return True

    def _reset_to_default_layout(self) -> None:
        """One local pane in one fresh workspace, whatever was there."""
        self._tear_down_panes(
            list(self._panes), list(self._terminal_panes), list(self._pane_placeholders)
        )
        self._setup_central()
        self._refresh_after_preset()

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
                self._terminal_dock.remove_ssh_session(_terminal_name(last.backend, profile))
            if profile:
                self._release_pane_connection(profile, last.backend)
            self._panes.remove(last)
            last.setParent(None)
            last.deleteLater()
            self._active_pane = None
            self._target_pane = None

        # One empty workspace is left for the rebuild.
        self._setup_workspaces()

    def _apply_session(self, data: dict, *, connect_remote: bool) -> None:
        """Replace the layout and window state with a validated session
        (see _session_problem). *connect_remote* False: remote panes become
        placeholders instead of connecting."""
        # Pause reconnect timer to avoid race conditions during restore
        self._reconnect_timer.stop()
        try:
            self._tear_down_for_restore()
            # Rebuild from saved layout
            active_pane, target_pane, current_ws = self._restore_workspaces(
                _session_workspaces(data), connect_remote=connect_remote
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
        # A dock state carries the corners; one of an older axross gave the
        # bottom area both bottom corners.
        self._apply_dock_corners()
        self._dock_fit.load_session_state(win.get(DOCK_FIT_SESSION_KEY))
        # A saved layout carries its toolbar rows; they follow this width.
        self._fit_toolbars()
        # The same reading as at the start (ui.window_prefs). A missing
        # theme keeps the one in use; ``theme`` is the pre-modern key and is
        # deliberately ignored: the modern theme became the default for
        # everyone, and the old key could not tell a deliberate choice from
        # the old default.
        self._apply_window_prefs(window_prefs.parse(win))

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
        if current_ws is not None and current_ws.window is None:
            # The saved current workspace, shown - also one that holds only
            # terminals, whose active file pane lives in another workspace
            # (following the active pane made that other one current).
            self.switch_workspace(current_ws)
        elif self._active_pane is not None:
            self._note_active_workspace(self._active_pane)

        self._refresh_pane_styles()
        log.info(
            "Session restored (%d panes, %d terminals, %d disconnected)",
            len(self._panes),
            len(self._terminal_panes),
            len(self._pane_placeholders),
        )

    def _restore_workspaces(
        self, entries: list[dict], *, connect_remote: bool
    ) -> tuple[FilePaneWidget | None, FilePaneWidget | None, Workspace | None]:
        """Rebuild every saved workspace into the one empty workspace
        _tear_down_for_restore left (and new ones); detach those that were
        detached. Returns the saved (active_pane, target_pane) and the saved
        current workspace (None when it did not come back)."""
        active_pane = target_pane = None
        current = None
        detach = []
        for index, entry in enumerate(entries):
            if index == 0:
                ws = self._current_ws
                if not self.rename_workspace(ws, entry.get("name")):
                    log.info("Session restore: the first workspace keeps its default name")
            else:
                ws = self.new_workspace(entry.get("name"), with_pane=False, activate=False)
                if ws is None:
                    continue
            a, t = self._restore_splitter(
                ws.root, entry.get("splitter", {}), connect_remote=connect_remote
            )
            active_pane = a or active_pane
            target_pane = t or target_pane
            if entry.get("current"):
                current = ws
            if entry.get("detached"):
                detach.append((ws, _decode_window_state(entry.get("geometry"))))
        self._prune_empty_workspaces()
        if current in self._workspaces and current.window is None:
            self.switch_workspace(current)
        for ws, geometry in detach:
            if ws in self._workspaces:
                self.detach_workspace(ws, geometry=geometry, activate=False)
        if current in self._workspaces:
            self._current_ws = current
        else:
            current = None
        return active_pane, target_pane, current

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

        saved_sizes = data.get("sizes")
        # Indexes of entries that added no widget (a switched-off
        # extension's panel): their sizes go, so the rest still match.
        skipped: set[int] = set()
        for position, child in enumerate(data.get("children", [])):
            kind = child.get("type", "splitter")
            if kind == PANEL_NODE:
                size = (saved_sizes[position] if isinstance(saved_sizes, list)
                        and position < len(saved_sizes) else None)
                if not self._restore_extension_panel(splitter, child, size):
                    skipped.add(position)
                continue
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
                    skipped.add(position)
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

        self._settle_restored_homes(splitter)
        if skipped and isinstance(saved_sizes, list):
            saved_sizes = [s for i, s in enumerate(saved_sizes) if i not in skipped]
        # Restore splitter sizes, ensuring no pane gets 0 pixels
        sizes = sanitize_splitter_sizes(saved_sizes, splitter.count())
        if sizes:
            splitter.setSizes(sizes)

        # Ensure all children are visible
        for i in range(splitter.count()):
            w = splitter.widget(i)
            if w and not w.isVisible():
                w.show()

        return active_pane, target_pane

    @staticmethod
    def _local_folder_or_home(path) -> str:
        """*path* when it names an absolute local folder, else the home
        folder - without asking the filesystem. This runs in the GUI thread,
        also before the window is shown, and a folder on a dead hard network
        mount (NFS, sshfs) never answers: one ``isdir`` there kept the
        window from ever appearing. Whoever uses the folder checks it where
        waiting is harmless: a pane lists it in the background and shows
        home when it is gone (navigate_async's *fallback*), a shell enters
        it itself and starts at home when it cannot (LocalTerminalSession)."""
        if isinstance(path, str) and path and os.path.isabs(path):
            return path
        return str(Path.home())

    def _restore_terminal(self, splitter: QSplitter, data: dict, *, connect_remote: bool) -> None:
        """A local shell (fresh, in its saved folder or home), or a profile
        terminal: a placeholder unless *connect_remote*."""
        profile_name = data.get("profile")
        if data.get("local") or not profile_name:
            cwd = self._local_folder_or_home(data.get("cwd"))
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
            # Local pane: the folder is listed in the background; a folder
            # removed since the session was saved shows home - no error
            # worth a dialog, and no filesystem call in the GUI thread.
            path = self._local_folder_or_home(path)
            pane = self._add_pane_to_splitter(splitter, LocalFS())
            try:
                pane.navigate_async(path, fallback=pane.backend.home())
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
                self._terminal_dock.add_ssh_session(
                    _terminal_name(session, profile), session.transport
                )
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
        self.open_settings("network")

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
                self._terminal_dock.add_ssh_session(
                    _terminal_name(session, profile), session.transport
                )

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
        add_close_corner(dlg)

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
            # A ProxyCommand from a file is someone else's shell command:
            # it runs only after the user saw and confirmed it on Connect.
            # The file's own "confirmed" field cannot vouch for it.
            profile.proxy_command_confirmed = not profile.proxy_command

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
                private_dir=False,  # the user's folder keeps its mode
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

        profiles = self._profile_manager.all_profiles()
        if not profiles:
            QMessageBox.information(self, "Profiles", "No saved profiles.")
            return

        data = {p.name: p.to_dict() for p in profiles}
        text = json.dumps(data, indent=2, ensure_ascii=False)
        self._show_text_dialog(f"All Profiles ({len(profiles)})", text, size=(600, 480))

    def _show_text_dialog(self, title: str, text: str, *, size: tuple[int, int] = (720, 520)):
        """*text* read-only in a window of its own (non-modal, like every
        viewer: ui.viewer_window.show_independent). Returns the window."""
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

        from ui import viewer_window as VW

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(*size)
        layout = QVBoxLayout(dlg)
        add_close_corner(dlg)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(text)
        layout.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        return VW.show_independent(dlg)

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

    def set_paranoid_mode(self, on: bool, *, announce: bool = False) -> None:
        """Switch the security mode (Settings > Security). The choice is
        stored and comes back on the next start (core.security_mode
        .apply_stored_mode) unless AXROSS_SECURITY_MODE says otherwise.
        *announce* shows the new mode in a message box."""
        from core import security_mode as SM
        from core import sudo_password as SP

        policy = SM.set_policy("paranoid" if on else "normal")
        not_stored: OSError | None = None
        try:
            SM.store_mode(policy.name)
        except OSError as exc:
            log.warning("Could not store the security mode: %s", exc)
            not_stored = exc  # raised once the mode is in force
        if policy.name == "paranoid":
            SP.forget()
        log.warning("Security mode changed to %s", policy.name)
        if getattr(self, "_scripts_dock", None) is not None:
            self._scripts_dock.refresh_policy()
        host = getattr(self, "extension_host", None)
        if host is not None:
            host.reload()  # paranoid unloads them all, normal loads the switched-on ones
        if announce:
            QMessageBox.information(
                self,
                "Security Mode",
                f"Security mode is now: {policy.name}",
            )
        if not_stored is not None:
            raise not_stored

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

    def _paste_cut_into(self, target: FilePaneWidget) -> None:
        """Paste (Ctrl+V / right-click in *target*): move the pending Cut
        (ui.cut_clipboard) into *target*'s current folder.

        The move is the one F6 and drag & drop use (``_request_transfer``):
        names already in the folder are asked about, and the transfer queue
        removes each source only after its own copy completed and was
        checked, so a failed, cancelled or partial transfer leaves it in
        place. Entries pasted into the folder they came from are left alone
        (no copy, no delete); a folder pasted into itself refuses the paste;
        a production source asks first. The cut is cleared once its move is
        queued; until then (a refusal, a Cancel at the conflict prompt) it
        stays pending and nothing is removed."""
        from core.cut_paste import plan_paste
        from ui.cut_clipboard import cut_clipboard

        board = cut_clipboard()
        cut = board.pending
        if cut is None:
            return
        self._set_active_pane(target)
        source = cut.source
        if source not in self._panes or source.backend is not cut.backend:
            # Closing or reconnecting the pane drops its cut; this is the guard.
            board.clear(cut)
            self.statusBar().showMessage(
                tr("Nothing pasted: the pane the entries were cut in closed or changed "
                   "connection"), 8000)
            return
        dest_dir = target.current_path
        plan = plan_paste(cut.backend, cut.paths, target.backend, dest_dir)
        if plan.refusal:
            QMessageBox.warning(self, tr("Paste"), tr("Nothing was moved: {reason}").format(
                reason=plan.refusal))
            return
        if not plan.paths:
            self.statusBar().showMessage(
                tr("Nothing to move: the cut entries already are in {folder}").format(
                    folder=dest_dir), 8000)
            return
        if not source._production_ok(f"move {len(plan.paths)} item(s) away"):
            return
        self._request_transfer(
            source, target, list(plan.paths), move=True, dest_dir=dest_dir,
            on_queued=lambda: board.clear(cut),
        )

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
        on_queued=None,
    ) -> None:
        """F5 / F6 / drag & drop / Paste: check the destination, ask, then queue.

        The destination is listed on a background thread (a slow remote
        must not freeze the window); every name the transfer would replace
        is put to the user before a single job is queued. The jobs then
        refuse to replace anything the answers did not allow, so a file
        that appears in the meantime is not overwritten silently. Cancel
        All while the check runs queues nothing. *on_queued* is called once
        the jobs are being queued (not after a refusal, error or Cancel).
        """
        if not selected:
            return
        from core import transfer_conflicts as TC
        from ui.scan_job import ScanJob

        paths = list(selected)
        if dest_dir is None:
            dest_dir = target.current_path
        source_backend, dest_backend = source.backend, target.backend
        cancel_epoch = self._transfer_manager.cancel_epoch
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
            if cancelled:
                return
            self._conflict_waiting.append(lambda: decide(kind, value))
            self._next_conflict_prompt()

        def decide(kind: str, value) -> None:
            title = tr("Move") if move else tr("Copy")
            if self._transfer_manager.cancel_epoch != cancel_epoch:
                log.info("Transfer dropped: Cancel All was pressed while the destination "
                         "was checked")
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
            if on_queued is not None:
                on_queued()

        check.finished.connect(finished)
        self.statusBar().showMessage(tr("Checking the destination for existing names…"))
        check.start(work)

    def _next_conflict_prompt(self) -> None:
        """Ask about the checked transfers in the order their checks
        finished, one at a time. A prompt (QDialog.exec, a message box)
        runs the event loop; a second check finishing meanwhile opened its
        own prompt on top of the first. Now it waits for the open one."""
        if self._conflict_prompting:
            return
        self._conflict_prompting = True
        try:
            while self._conflict_waiting:
                step = self._conflict_waiting.pop(0)
                try:
                    step()
                except Exception:  # noqa: BLE001 - the next transfer is still asked
                    log.exception("Transfer conflict prompt failed")
        finally:
            self._conflict_prompting = False

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
        are replaced: callers that decided that themselves (the compare
        window, through ``_transfer_compared``) use this directly; the
        user commands go through ``_request_transfer``."""
        direction = self._transfer_direction(source.backend, target.backend)

        # Track target pane (and source for move) for auto-refresh on completion
        self._transfer_target_panes.add(target)
        if move:
            self._transfer_target_panes.add(source)
        # The summary comes from the jobs the walk creates. A separate
        # preview walk only fed this log line; every job is in the
        # operation journal as well. The walk itself (a round trip per
        # remote folder) runs off the GUI thread; the jobs are queued here
        # when it is done, in the same order.
        def _walked(jobs) -> None:
            if move:
                self._track_tag_moves(source, target, selected,
                                      target.current_path if dest_dir is None else dest_dir, jobs,
                                      conflict_plan)
            log.info(
                "Transfer enqueued: %s: %d file(s), %d byte(s)",
                "move" if move else "copy",
                len(jobs),
                sum(j.total_bytes for j in jobs),
            )

        self._transfer_manager.transfer_files_in_background(
            source_backend=source.backend,
            dest_backend=target.backend,
            source_paths=selected,
            dest_dir=target.current_path if dest_dir is None else dest_dir,
            direction=direction,
            move=move,
            conflict_plan=conflict_plan,
            on_done=_walked,
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

    # -- tags follow moves -------------------------------------------------------

    def _track_tag_moves(self, source, target, selected, dest_dir: str, jobs,
                         conflict_plan=None) -> None:
        """Remember the jobs of a move whose files or folders carry tags.

        A folder's own tags (and those of the folders inside it) follow
        once all its jobs ended well - not when the conflict answers kept
        something of it at the source (the source folder stays then), and
        to the name a Rename answer gave it."""
        from core import tags as TG
        from core.path_policy import safe_join

        store = TG.store()
        src, dst = source.backend.name, target.backend.name
        profile = getattr(target, "profile_name", "") or ""
        index = store.tagged_index(src)  # one pass over the tags, not one per entry
        tagged = [p for p in selected if index.has_tags_under(p)]
        if not tagged:
            return
        # A job is tracked when its source is a tagged entry or lies below
        # one: its own path or one of its parents (split at / and \) is in
        # the set - instead of comparing every job with every tagged entry.
        roots = {p for p in tagged} | {p.rstrip("/\\") for p in tagged}
        for job in jobs:
            if _under_any(job.source_path, roots):
                self._tag_moves[job.job_id] = (src, dst, profile, job.source_path, job.dest_path)
        sep = source.backend.separator() or "/"
        for path in tagged:
            prefix = path.rstrip(sep) + sep
            pending = {j.job_id for j in jobs if j.source_path.startswith(prefix)}
            if not pending:
                continue  # a file (its own job) or an empty folder
            name = path.rstrip(sep).rsplit(sep, 1)[-1]
            try:
                new = safe_join(target.backend, dest_dir, name)
            except ValueError:
                continue  # transfer_files queued nothing under it either
            if conflict_plan is not None:
                resolved = conflict_plan.resolve(new)
                if resolved is None or conflict_plan.keeps_inside(new):
                    continue
                new = resolved[0]
            self._tag_folder_moves.append({
                "src": src, "dst": dst, "profile": profile, "old": path,
                "new": new, "pending": pending, "failed": False,
            })

    def _tags_on_move_finished(self, job_id: str) -> None:
        self._queue_tag_job(job_id, None)

    def _tags_on_move_error(self, job_id: str, _error: str = "") -> None:
        self._queue_tag_job(job_id, False)

    #: The least time between two writes of tags.json while a move ends job
    #: after job. Applied on the next event-loop turn alone, 300 moved files
    #: wrote it 38 to 98 times once the panes refreshed during the move
    #: (watchdog): each turn carried only a few ended jobs.
    TAG_FLUSH_GAP_MS = 250

    def _queue_tag_job(self, job_id: str, ok: bool | None) -> None:
        """Every ended job wrote tags.json once (1000 moved files: 1.5 s of
        GUI time); they are applied together: on the next event-loop turn,
        or :data:`TAG_FLUSH_GAP_MS` after the last batch if that was later."""
        if job_id not in self._tag_moves and not any(
                job_id in folder["pending"] for folder in self._tag_folder_moves):
            return  # no tag follows this job
        if not self._tag_job_queue:
            since = (time.monotonic() - self._tag_last_flush) * 1000
            QTimer.singleShot(max(0, int(self.TAG_FLUSH_GAP_MS - since)), self._flush_tag_jobs)
        self._tag_job_queue.append((job_id, ok))

    def _flush_tag_jobs(self) -> None:
        from core import tags as TG

        queue, self._tag_job_queue = self._tag_job_queue, []
        self._tag_last_flush = time.monotonic()
        if not queue:
            return  # already applied (the window closed in between)
        store = TG.store()
        try:
            with store.batch():
                for job_id, ok in queue:
                    if ok is None:
                        self._tags_job_finished(job_id)
                    else:
                        self._tag_moves.pop(job_id, None)
                        self._tags_folder_progress(job_id, False)
        except OSError as exc:  # tags.json not writable: the moves themselves stand
            log.warning("Tags could not follow the moved files: %s", exc)

    def _tags_job_finished(self, job_id: str) -> None:
        from core import tags as TG
        from core.transfer_worker import TransferStatus

        entry = self._tag_moves.pop(job_id, None)
        job = self._transfer_manager.get_job(job_id) if entry is not None else None
        ok = job is not None and job.status == TransferStatus.DONE and not job.skipped
        if entry is not None and ok:
            src, dst, profile, old, new = entry
            try:
                TG.store().move_path(src, old, new, dest_backend=dst, dest_profile=profile)
            except OSError as exc:  # tags.json not writable: the move itself stands
                log.warning("Tags could not follow %s -> %s: %s", old, new, exc)
        self._tags_folder_progress(job_id, ok or entry is None)

    def _tags_folder_progress(self, job_id: str, ok: bool) -> None:
        """A moved folder's own tags follow once every job below it ended
        well; one failed job leaves them (the source folder is still there)."""
        from core import tags as TG

        for folder in list(self._tag_folder_moves):
            if job_id not in folder["pending"]:
                continue
            folder["pending"].discard(job_id)
            folder["failed"] = folder["failed"] or not ok
            if folder["pending"]:
                continue
            self._tag_folder_moves.remove(folder)
            if not folder["failed"]:
                try:
                    TG.store().move_path(folder["src"], folder["old"], folder["new"],
                                         dest_backend=folder["dst"],
                                         dest_profile=folder["profile"])
                except OSError as exc:
                    log.warning("Tags could not follow %s: %s", folder["old"], exc)

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
        """Periodically check SSH connections and attempt reconnect.

        The connect runs on a worker thread: on the GUI thread a host that
        accepts TCP but never answers froze the window for the whole
        handshake timeout, every interval, per dropped pane. A pane whose
        reconnect is still in flight is skipped."""
        for pane in list(self._panes):
            if pane not in self._pane_profiles or pane in self._reconnecting:
                continue

            backend = pane.backend
            if not _is_ssh_session(backend):
                continue

            if backend.connected:
                continue

            self._start_auto_reconnect(pane, self._pane_profiles[pane], backend)

    def _start_auto_reconnect(self, pane, profile, dropped) -> None:
        from core.connect_worker import run_connect

        log.info("Auto-reconnecting to %s...", profile.host)
        previous_path = pane.current_path

        def _on_success(session) -> None:
            self._reconnecting.pop(pane, None)
            if (
                pane not in self._panes
                or self._pane_profiles.get(pane) is not profile
                or pane.backend is not dropped
            ):
                # The pane closed or moved on meanwhile: nobody uses it.
                self._connection_manager.release(profile)
                return
            # One load, straight to where the pane was.
            pane.set_backend(session, previous_path)
            # The reference the pane held on the dropped session.
            self._connection_manager.release(profile)
            transport = getattr(session, "transport", None)
            if transport and transport.is_active():
                self._terminal_dock.add_ssh_session(
                    _terminal_name(session, profile), session.transport
                )
            log.info("Auto-reconnected to %s", session.name)

        def _on_failure(exc) -> None:
            self._reconnecting.pop(pane, None)
            log.debug("Auto-reconnect to %s failed: %s", profile.host, exc)

        # Unknown host keys are not asked about: a background reconnect
        # refuses them, as it did on the GUI thread.
        task = run_connect(
            self._connection_manager,
            profile,
            password=self._pane_passwords.get(pane, ""),
            key_passphrase=self._pane_key_passphrases.get(pane, ""),
            on_success=_on_success,
            on_failure=_on_failure,
        )
        self._reconnecting[pane] = task
        # Pinned there too, so closing the window abandons it.
        self._connect_tasks = [
            t for t in self._connect_tasks if t.thread is not None and t.thread.isRunning()
        ]
        self._connect_tasks.append(task)

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
        existing = self._bookmark_manager.find(path, backend_name)
        if existing is not None:
            # A second "New Bookmark" for the same folder could only be
            # dropped by the manager's duplicate rule; edit the one there is.
            self.statusBar().showMessage(
                tr("{path} is already bookmarked as '{name}'.").format(
                    path=path, name=existing.name
                ),
                6000,
            )
            self._bookmark_sidebar.edit_node(existing)
            return
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
        if not self._bookmark_manager.add(bookmark, group=dialog.result_group()):
            # The dialog's path field pointed the draft at a folder that is
            # bookmarked already.
            taken = self._bookmark_manager.find(bookmark.path, bookmark.backend_name)
            self.statusBar().showMessage(
                tr("Not added: {path} is already bookmarked as '{name}'.").format(
                    path=bookmark.path, name=taken.name if taken is not None else ""
                ),
                6000,
            )
            return
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
            where = node.backend_name
            if node.is_terminal:
                host = node.backend_name if node.is_host_terminal else node.profile_name
                if host == LOCAL_SHELL and not node.is_host_terminal:
                    host = tr("Local Shell")
                where = tr("Terminal: {host}").format(host=host)
            action = menu.addAction(
                _bm_icon(node.icon_name or "bookmark", 32, node.color),
                f"{_safe(node.name)}  [{_safe(where)}]",
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
        if getattr(bookmark, "is_terminal", False):
            # The sidebar refuses this drop already; a terminal is no folder.
            self._drop_status(tr("A terminal bookmark is no folder: nothing was moved."))
            return
        source = self._pane_by_id(source_pane_id)
        if source is None:
            self._drop_status(tr("The dragged items come from a pane that is no longer open."))
            return
        if not isinstance(bookmark, Bookmark) or not any(
            b is bookmark for b in self._bookmark_manager.all()
        ):
            self._drop_status(tr("That bookmark no longer exists."))
            return
        if bookmark.is_smart_folder:
            self._drop_status(tr("A Smart Folder is a saved search, not a folder."))
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
        # Fixed first lines, names as typed below them: a message box guesses
        # rich text from the first line (escaped, "Bob's" read "Bob&#x27;s").
        name = bookmark.name
        if not bookmark.profile_name:
            QMessageBox.warning(
                self,
                tr("Bookmark"),
                tr(
                    "This bookmark has no connection profile, so its connection cannot be "
                    "opened. Connect first and drop again; nothing was transferred.\n\n"
                    "Bookmark: {name}\nConnection: {backend}"
                ).format(name=name, backend=bookmark.backend_name),
            )
            return
        profile = self._profile_manager.get(bookmark.profile_name)
        if profile is None:
            QMessageBox.warning(
                self,
                tr("Bookmark"),
                tr(
                    "The connection profile of this bookmark was not found; nothing was "
                    "transferred.\n\nBookmark: {name}\nProfile: {profile}"
                ).format(profile=bookmark.profile_name, name=name),
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

    def _terminal_profile_names(self) -> list[str]:
        """The saved profiles a terminal can be opened on (SSH ones). A
        profile named like the local shell (LOCAL_SHELL) is left out: its
        bookmark would open a shell on this machine, not on its host."""
        from core.terminal_here import profile_has_shell

        return [
            name
            for name in self._profile_manager.list_names()
            if name != LOCAL_SHELL and profile_has_shell(self._profile_manager.get(name))
        ]

    def _open_terminal_bookmark(self, bookmark: Bookmark) -> TerminalPaneWidget | None:
        """A terminal bookmark: a terminal pane on its connection, in its
        folder, beside the active pane. Refused with a message - and nothing
        opened - when the profile is gone, has no shell, or a local folder
        does not exist. A bookmark on a bare host connects in the background
        (:meth:`_open_host_terminal_bookmark`) and returns ``None`` here."""
        from core.terminal_here import profile_has_shell

        title = tr("Terminal Bookmark")
        name = bookmark.profile_name or LOCAL_SHELL
        folder = bookmark.path or None
        if folder is not None and any(ord(c) < 0x20 or ord(c) == 0x7F for c in folder):
            # A shell would act on them (core.terminal_here.remote_cd_command
            # refuses them too); said here instead of a silent home folder.
            QMessageBox.warning(
                self, title,
                tr("The folder of this terminal bookmark contains control characters; "
                   "edit the bookmark.\n\nBookmark: {bookmark}").format(bookmark=bookmark.name),
            )
            return None
        if bookmark.is_host_terminal:
            self._open_host_terminal_bookmark(bookmark, folder)
            return None
        if name == LOCAL_SHELL:
            # A folder typed as ~/... is in the home folder (a remote shell
            # expands the tilde itself: core.terminal_here.remote_cd_command).
            folder = os.path.expanduser(folder) if folder is not None else None
            if folder is not None and not os.path.isdir(folder):
                QMessageBox.warning(
                    self,
                    title,
                    tr("The folder of this terminal bookmark does not exist.\n\n"
                       "Bookmark: {bookmark}\nFolder: {folder}").format(
                        folder=folder, bookmark=bookmark.name),
                )
                return None
        else:
            profile = self._profile_manager.get(name)
            if profile is None:
                QMessageBox.warning(
                    self,
                    title,
                    tr("The connection profile of this terminal bookmark no longer exists."
                       "\n\nBookmark: {bookmark}\nProfile: {profile}").format(
                        profile=name, bookmark=bookmark.name
                    ),
                )
                return None
            if not profile_has_shell(profile):
                QMessageBox.warning(
                    self,
                    title,
                    tr("This connection profile has no shell: terminals open on SSH "
                       "(SFTP/SCP) profiles.\n\nProfile: {profile} ({protocol})").format(
                        profile=name, protocol=profile.protocol.upper()
                    ),
                )
                return None
        term = self._preset_make_terminal_pane(name, cwd=folder)
        self._place_terminal_pane(term, self._active_pane)
        log.info("Opened terminal bookmark %r (%s)", bookmark.name, name)
        return term

    def _open_host_terminal_bookmark(self, bookmark: Bookmark, folder: str | None) -> None:
        """A terminal bookmark on a bare host: connect the way Quick Connect
        does - in the background, the known_hosts question for an unknown
        host key (``_confirm_unknown_host``, never a silent accept), the
        password asked when neither a key file nor an ssh-agent is there, the
        key's passphrase asked when the key
        is encrypted, the password again when the server refuses the key -
        then a terminal pane that changes into *folder*. Nothing typed here is
        stored."""
        from core.bookmarks import host_bookmark_problem, host_bookmark_profile

        problem = host_bookmark_problem(bookmark)
        if problem:
            QMessageBox.warning(
                self,
                tr("Terminal Bookmark"),
                tr("This terminal bookmark cannot connect; edit the bookmark.\n\n"
                   "Bookmark: {bookmark}\n{problem}").format(
                    bookmark=bookmark.name, problem=problem),
            )
            return
        self._connect_host_terminal(host_bookmark_profile(bookmark), folder)

    def _ask_host_secret(self, title: str, prompt: str) -> str | None:
        """A password or passphrase, typed hidden; ``None`` when cancelled."""
        from PyQt6.QtWidgets import QInputDialog

        text, ok = QInputDialog.getText(self, title, prompt, QLineEdit.EchoMode.Password)
        return text if ok else None

    def _connect_host_terminal(self, profile: ConnectionProfile, folder: str | None) -> None:
        """Connect *profile* (built by core.bookmarks.host_bookmark_profile)
        and open a terminal pane on it in *folder*; see
        :meth:`_open_host_terminal_bookmark`."""
        import dataclasses

        import paramiko

        from core.bookmarks import as_host_profile

        state = {"profile": profile, "password": "", "passphrase": "", "tries": 0}

        def ask_password() -> bool:
            p = state["profile"]
            text = self._ask_host_secret(tr("Password"), f"Password for {p.username}@{p.host}:")
            if text is None:
                log.info("Host terminal %s: password prompt cancelled", p.name)
                return False
            state["password"] = text
            return True

        def on_success(session) -> None:
            p = state["profile"]
            if not getattr(session, "transport", None):
                self._connection_manager.release(p)
                QMessageBox.critical(self, "Connection Failed",
                                     f"{p.name}: the connection has no shell.")
                return
            term = TerminalPaneWidget(label=p.name, profile=p,
                                      connection_manager=self._connection_manager, cwd=folder)
            if term.holds_session or not term.is_running:
                # The pane took its own reference on the live session - or its
                # shell did not start and nothing uses the session: give back
                # the one this connect took, so closing the pane ends it.
                self._connection_manager.release(p)
            else:  # a shell on the transport without a reference: keep ours
                log.warning("Host terminal %s holds no reference; the connection "
                            "stays open until the window closes", p.name)
            self._wire_terminal_pane(term)
            self._place_terminal_pane(term, self._active_pane)
            log.info("Opened a host terminal on %s", p.name)

        def on_failure(exc) -> None:
            p = state["profile"]
            if _needs_key_passphrase(exc) and state["tries"] < KEY_PASSPHRASE_TRIES:
                state["tries"] += 1
                prompt = f"Passphrase for the key {p.key_file}:"
                if state["passphrase"]:
                    prompt = f"Wrong passphrase. {prompt}"
                text = self._ask_host_secret(tr("Key Passphrase"), prompt)
                if text is None:
                    return
                state["passphrase"] = text
                self._run_connect_async(p, state["password"], text, on_success, on_failure)
                return
            if p.auth_type in ("agent", "key") and isinstance(
                exc, paramiko.AuthenticationException
            ) and not _needs_key_passphrase(exc):
                # The agent's keys or the key file were refused: ask the
                # password, as ssh does.
                retry = as_host_profile(dataclasses.replace(p, auth_type="password"))
                state["profile"] = retry
                if ask_password():
                    self._run_connect_async(retry, state["password"], "", on_success, on_failure)
                return
            QMessageBox.critical(self, "Connection Failed", str(exc))
            log.error("Host terminal connect to %s failed: %s", p.name, exc)

        if profile.auth_type == "password" and not ask_password():
            return
        self._run_connect_async(profile, state["password"], "", on_success, on_failure)

    def _bookmark_terminal(self, term: TerminalPaneWidget) -> None:
        """Bookmark this Terminal: a terminal bookmark for the pane's
        connection (its profile, or a local shell) and current folder."""
        from core.bookmarks import is_host_profile

        if term.profile is not None and is_host_profile(term.profile):
            # A shell a host terminal bookmark opened: bookmark the host again.
            p = term.profile
            draft = Bookmark(
                name="", path=term.start_directory or "", kind=BOOKMARK_TERMINAL,
                host=p.host, port=p.port, username=p.username, key_file=p.key_file,
                icon_name="terminal",
            )
            self._bookmark_sidebar.new_terminal_bookmark(draft)
            return
        if term.is_local:
            profile_name = LOCAL_SHELL
            folder = term.working_directory() or ""
        elif term.profile is not None and term.profile.name == LOCAL_SHELL:
            QMessageBox.information(
                self,
                tr("Bookmark this Terminal"),
                tr("The connection profile is named '{name}', the name a terminal bookmark "
                   "keeps for a local shell: its bookmark would open a shell on this "
                   "machine. Rename the profile first.").format(name=LOCAL_SHELL),
            )
            return
        elif term.profile is not None:
            profile_name = term.profile.name
            folder = term.start_directory or ""
        else:
            QMessageBox.information(
                self,
                tr("Bookmark this Terminal"),
                tr("This terminal runs on a connection without a saved profile. Save the "
                   "connection as a profile first; a terminal bookmark names a profile and "
                   "never stores credentials."),
            )
            return
        if profile_name == LOCAL_SHELL:
            name = os.path.basename(folder.rstrip("/")) or folder or tr("Local Shell")
        else:
            name = f"{profile_name}: {folder}" if folder else profile_name
        draft = Bookmark(
            name=name,
            path=folder,
            backend_name="Local" if profile_name == LOCAL_SHELL else profile_name,
            profile_name=profile_name,
            icon_name="terminal",
            kind=BOOKMARK_TERMINAL,
        )
        self._bookmark_sidebar.new_terminal_bookmark(draft)

    def _navigate_bookmark(self, bookmark: Bookmark) -> None:
        if bookmark.is_smart_folder:
            self._run_smart_folder(bookmark)
            return
        if bookmark.is_terminal:
            self._open_terminal_bookmark(bookmark)
            return
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
        """Bookmarks > Manage Bookmarks...: the bookmark tree with the
        sidebar's actions (ui.bookmark_manager_dialog). Each change is
        stored at once and rebuilds the sidebar and this menu - one store."""
        from ui.bookmark_manager_dialog import BookmarkManagerDialog

        dialog = BookmarkManagerDialog(
            self._bookmark_manager, self, terminal_profiles=self._terminal_profile_names
        )
        dialog.changed.connect(self._rebuild_bookmarks_menu)
        try:
            dialog.exec()
        finally:
            dialog.deleteLater()  # a child of the window: gone once closed

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
        temporary status message never covers it. Once a newer version is
        found it says so ("axross 0.14.60 · Update available: 0.14.61"),
        and a click opens the update window (ui.update_ui)."""
        from ui.update_ui import UpdateController

        self._update_controller = UpdateController(self)
        self._update_dialog = None
        self._version_button = QPushButton()
        self._version_button.setObjectName("axVersion")
        self._version_button.setFlat(True)
        self._version_button.clicked.connect(lambda _checked=False: self._version_clicked())
        self.statusBar().addPermanentWidget(self._version_button)
        self._show_version_notice("")
        self._update_controller.changed.connect(self._refresh_update_notice)

    def _show_version_notice(self, notice: str) -> None:
        """The version bottom right, plain or with the update notice."""
        from axross._version import __version__

        shown = f"axross {__version__}"
        button = self._version_button
        button.setProperty("notice", bool(notice))
        button.setProperty("role", "" if notice else "muted")
        if notice:
            button.setText(f"{shown} · {notice}".replace("&", "&&"))
            button.setToolTip(tr("{notice} - click for the update window").format(notice=notice))
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            button.setText(shown)
            button.setToolTip(tr("Version of this axross"))
            button.unsetCursor()
        button.style().unpolish(button)
        button.style().polish(button)

    def _version_clicked(self) -> None:
        if self._version_button.property("notice"):
            self.show_update_dialog()

    # --- self-update (ui.update_ui, core.self_update) ---
    def update_controller(self):
        return self._update_controller

    def start_update_check(self) -> bool:
        """The check at start (main.py, once the window is shown)."""
        return self._update_controller.start_check()

    def check_for_updates(self) -> None:
        """Help > Check for Updates…: check now and show the answer."""
        self._update_controller.check_now()
        self.show_update_dialog()

    def show_update_dialog(self) -> None:
        """One non-modal update window, raised when open."""
        from ui.update_ui import UpdateDialog

        dialog = self._update_dialog
        if dialog is None:
            dialog = UpdateDialog(self._update_controller, self, self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.destroyed.connect(lambda *_: setattr(self, "_update_dialog", None))
            self._update_dialog = dialog
        dialog.refresh()
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _refresh_update_notice(self) -> None:
        controller = self._update_controller
        visible = controller.notice_visible()
        text = controller.notice_text() if visible else ""
        self._show_version_notice(controller.status_text() if visible else "")
        self._update_menu_action.setText(text.replace("&", "&&"))
        self._update_menu_action.setVisible(visible)

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
<li><b>Analysis (sift)</b> — what the selected file is; right-click › Analyse with sift</li>
</ul>

<p><small>axross {__version__} — Python + PyQt6 | github.com/c0decave/axross</small></p>
<p><small>F1 = keyboard shortcuts · Help &gt; Scripting Guide</small></p>
<p><small>Thanks to the projects behind axross: Help &gt; Third-Party Software…</small></p>
"""
        QMessageBox.about(self, f"About axross {__version__}", about_text)

    # --- Font / Zoom ---

    def _change_font_size(self, delta: int) -> None:
        """View > Zoom In / Out: the application font *delta* points larger,
        within the zoom range, stored at once."""
        app = QApplication.instance()
        if not app:
            return
        size = app.font().pointSize()
        if size <= 0:  # a pixel-sized font: start from the desktop's size
            size = _desktop_font_size()
        self._quietly(
            self.set_font_size,
            max(window_prefs.MIN_FONT_SIZE, min(window_prefs.MAX_FONT_SIZE, size + delta)),
        )

    def set_font_size(self, size: int | None, *, store: bool = True) -> None:
        """The application font size in points; ``None`` is the desktop's
        size (View > Zoom Reset). Settings > Appearance and the zoom keys
        store it in window.font_size."""
        if size is not None and not window_prefs.valid_font_size(size):
            raise ValueError(
                f"font size must be {window_prefs.MIN_FONT_SIZE}-{window_prefs.MAX_FONT_SIZE}"
                f" points, not {size!r}"
            )
        self._font_size = size
        self._set_font_size(_desktop_font_size() if size is None else size)
        if store:
            self.store_window_prefs(**{FONT_SIZE_KEY: size})

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
        # View > Theme marks the theme in use; "dark" is the old id of Classic.
        action = getattr(self, "_theme_actions", {}).get("classic" if theme == "dark" else theme)
        if action is not None:
            action.setChecked(True)
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

    # ------------------------------------------------------------------
    # Find on Network Hosts (core.remote_sweep)
    # ------------------------------------------------------------------

    def _show_network_search(self) -> None:
        from ui.network_search_dialog import NetworkSearchDialog

        dlg = getattr(self, "_network_search_dialog", None)
        if dlg is None:
            dlg = NetworkSearchDialog(
                self, open_hit=self._open_sweep_hit, analyse_hit=self._analyse_sweep_hit
            )
            self._network_search_dialog = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _sweep_backend(self, hit, login, on_ready) -> None:
        """An SMB session for the share of *hit*, made off the GUI thread
        (a connect can take seconds), handed to *on_ready* on the GUI
        thread. One session per host, share and login is kept for reuse."""
        import threading

        from PyQt6.QtCore import QObject, pyqtSignal

        key = (hit.host, hit.share, login.username, login.domain, login.port)
        cache = self.__dict__.setdefault("_sweep_sessions", {})
        if key in cache:
            on_ready(cache[key])
            return

        class _Ready(QObject):
            done = pyqtSignal(object, str)

        bridge = _Ready(self)
        self.__dict__.setdefault("_sweep_bridges", set()).add(bridge)

        def finish(session, error: str) -> None:
            self._sweep_bridges.discard(bridge)
            bridge.deleteLater()
            if session is None:
                QMessageBox.warning(self, tr("Find on Network Hosts"), error)
                return
            cache[key] = session
            on_ready(session)

        bridge.done.connect(finish)
        user = f"{login.domain}\\{login.username}" if login.domain else login.username

        def work() -> None:
            from core.smb_client import SmbSession

            try:
                session = SmbSession(hit.host, hit.share, user, login.password, port=login.port)
            except Exception as exc:  # noqa: BLE001 - shown in a message box
                text = str(exc) or type(exc).__name__
                if login.password:
                    text = text.replace(login.password, "***")
                bridge.done.emit(None, f"{hit.host}\\{hit.share}: {text}")
                return
            bridge.done.emit(session, "")

        threading.Thread(target=work, name="axross-sweep-connect", daemon=True).start()

    def _open_sweep_hit(self, hit, login) -> None:
        """A new pane on the hit's share, in the hit's folder."""
        import posixpath

        def ready(session) -> None:
            pane = self._add_pane_to_splitter(self._root_splitter, session)
            pane.navigate_async(posixpath.dirname(hit.path) or "/")

        self._sweep_backend(hit, login, ready)

    def _analyse_sweep_hit(self, hit, login) -> None:
        """The hit in the Analysis dock (sift), read through a bounded
        temporary copy like any remote file."""
        import posixpath

        from core.file_analysis import Target

        def ready(session) -> None:
            dock = self._analysis_dock
            dock.show()
            dock.raise_()
            dock.analyse(Target(backend=session, path=hit.path, name=posixpath.basename(hit.path),
                                size=hit.size, mtime=hit.mtime), explicit=True)

        self._sweep_backend(hit, login, ready)

    def _show_metadata_settings(self) -> None:
        self.open_settings("metadata")

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
        """Colour for every icon under the current theme and the icon colour
        choice: the Hacker / Amber accent ("theme"), the chosen colour
        ("one"), none ("coloured": each icon its own colour); in monochrome
        mode the theme's accent or else the palette's text colour
        (``currentColor`` would rasterise black)."""
        from ui.icon_provider import is_monochrome as _is_mono

        resolved = themes.resolve(self._current_theme, themes.system_scheme())
        mode = self._icon_colours
        if mode == "one" and not _is_mono():
            return self._icon_colour
        tint = themes.icon_tint_for(resolved) if mode == "theme" or _is_mono() else None
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
        """Re-apply icons to the toolbars' actions (those carrying
        an ``axIcon`` property, set in ``_setup_toolbar``)."""
        from ui.icon_provider import icon as _ico

        for tb in self.findChildren(QToolBar):
            for action in tb.actions():
                icon_name = action.property("axIcon")
                if icon_name:
                    action.setIcon(_ico(str(icon_name)))
        sift = getattr(self, "_analyse_sift_action", None)  # Tools menu only
        if sift is not None:
            sift.setIcon(_ico("analysis"))
        # The tint follows the theme's background and the icons' colours.
        self._apply_toolbar_tint()
        self._fit_toolbars()

    #: The overflow button's least width: Qt's own was a 12 px strip.
    TOOLBAR_EXTENSION_WIDTH = 22

    def _fit_toolbars(self) -> None:
        """Main and Tools in one row when both fit, else Tools in a second
        row; the overflow button (still needed when one bar alone is wider
        than the window) gets a visible arrow."""
        main = getattr(self, "_main_toolbar", None)
        tools = getattr(self, "_tools_toolbar", None)
        if main is None or tools is None:
            return
        margins = self.contentsMargins()
        room = self.width() - margins.left() - margins.right()
        wrap = main.sizeHint().width() + tools.sizeHint().width() > room
        if wrap != self.toolBarBreak(tools):
            if wrap:
                self.insertToolBarBreak(tools)
            else:
                self.removeToolBarBreak(tools)
        from PyQt6.QtWidgets import QToolButton

        from ui.icon_provider import icon as _ico

        for bar in (main, tools):
            ext = bar.findChild(QToolButton, "qt_toolbar_ext_button")
            if ext is not None:
                ext.setIcon(_ico("chevrons-right"))
                ext.setMinimumWidth(self.TOOLBAR_EXTENSION_WIDTH)

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().resizeEvent(event)
        self._fit_toolbars()

    # --- Toolbar order: drag and drop, kept in session.json (ui.toolbar_order) ---

    def _order_bars(self) -> list[QToolBar]:
        return [bar for bar in (getattr(self, "_main_toolbar", None),
                                getattr(self, "_tools_toolbar", None)) if bar is not None]

    def _setup_toolbar_reorder(self) -> None:
        """Remember each bar's default order, read the toolbar style, let
        the buttons be dragged and lay the bars out (grouped by category or
        in the stored plain order, ui.toolbar_categories)."""
        from ui import toolbar_categories, toolbar_order

        self._default_toolbar_orders = {
            bar.objectName(): toolbar_order.bar_order(bar) for bar in self._order_bars()
        }
        self._toolbar_style = toolbar_categories.parse_style(self._session_window())
        self._toolbar_reorder: dict[str, toolbar_order.ToolbarReorder] = {}
        for bar in self._order_bars():
            reorder = toolbar_order.ToolbarReorder(bar)
            reorder.reordered.connect(self._on_toolbar_reordered)
            self._toolbar_reorder[bar.objectName()] = reorder
        self._layout_toolbars()

    def _session_window(self) -> dict:
        """session.json's ``window`` object ({} when there is none)."""
        try:
            data = _read_json_file(self._SESSION_FILE)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.debug("Toolbar: could not read %s: %s", self._SESSION_FILE, exc)
            return {}
        window = data.get("window") if isinstance(data, dict) else None
        return window if isinstance(window, dict) else {}

    def _stored_toolbar_orders(self) -> dict[str, list[str]]:
        from ui import toolbar_order

        return toolbar_order.parse(self._session_window().get(toolbar_order.ORDER_KEY))

    def _stored_group_orders(self) -> dict[str, list[str]]:
        from ui import toolbar_categories

        return toolbar_categories.parse_group_order(
            self._session_window().get(toolbar_categories.GROUP_ORDER_KEY))

    def _default_group_orders(self) -> dict[str, list[str]]:
        from ui import toolbar_categories as TC

        return TC.group_orders(TC.grouped_layout(self._default_toolbar_orders, {}))

    def _layout_toolbars(self, stored: dict | None = None) -> None:
        """Lay the bars out for the current style: grouped by category with
        the stored order per category, or the plain bars with their stored
        order. *stored* replaces what session.json holds for the mode."""
        from ui import toolbar_categories as TC
        from ui import toolbar_order as TO

        grouping = self._toolbar_style.grouping
        defaults = self._default_toolbar_orders
        if grouping:
            layout = TC.grouped_layout(
                defaults, self._stored_group_orders() if stored is None else stored)
        else:
            orders = self._stored_toolbar_orders() if stored is None else stored
            layout = {name: TO.merge(orders.get(name), order) for name, order in defaults.items()}
        reorders = getattr(self, "_toolbar_reorder", {})
        # Off the buttons while the bars rebuild them (a moved action gets a
        # new button); back on the new ones afterwards.
        for reorder in reorders.values():
            reorder.disarm()
        TO.apply_layout(self._order_bars(), layout)
        for reorder in reorders.values():
            reorder.set_bounded(grouping)
            reorder.arm()
        self._apply_toolbar_tint()
        self._fit_toolbars()

    def _on_toolbar_reordered(self, _bar=None) -> None:
        self._store_toolbar_order()
        self._apply_toolbar_tint()  # the moved button is a new one
        self._fit_toolbars()

    def _store_toolbar_order(self) -> None:
        """Store the order that differs from the default: per bar (grouping
        off) or per category (grouping on). What is left as it was follows
        the default of a later version."""
        from ui import toolbar_categories as TC
        from ui import toolbar_order as TO

        current = {bar.objectName(): TO.bar_order(bar) for bar in self._order_bars()}
        if self._toolbar_style.grouping:
            default = self._default_group_orders()
            key = TC.GROUP_ORDER_KEY
            orders = {c: o for c, o in TC.group_orders(current).items() if o != default.get(c)}
        else:
            key = TO.ORDER_KEY
            orders = {name: o for name, o in current.items()
                      if o != self._default_toolbar_orders.get(name)}
        try:
            self.store_window_prefs(**{key: orders})
        except OSError:
            self.statusBar().showMessage(tr("Could not store the toolbar order"), 5000)

    def reset_toolbar_order(self) -> None:
        """The toolbar's right-click menu: the default order (inside the
        groups while grouping is on), and no stored order for the mode."""
        from ui import toolbar_categories as TC
        from ui import toolbar_order as TO

        key = TC.GROUP_ORDER_KEY if self._toolbar_style.grouping else TO.ORDER_KEY
        try:
            self.store_window_prefs(**{key: {}})
        except OSError:
            self.statusBar().showMessage(tr("Could not store the toolbar order"), 5000)
        self._layout_toolbars(stored={})

    # --- Toolbar categories and colours (ui.toolbar_categories) ---

    def toolbar_style(self):
        """The toolbar style in use (a ui.toolbar_categories.ToolbarStyle)."""
        from ui import toolbar_categories

        return getattr(self, "_toolbar_style", None) or toolbar_categories.ToolbarStyle()

    def set_toolbar_style(self, style, *, store: bool = True) -> None:
        """Group the buttons by category or not, colour them or not, the
        colours (Settings > Toolbar): applied now, stored at once."""
        from ui import toolbar_categories

        previous = self.toolbar_style()
        self._toolbar_style = style
        if hasattr(self, "_toolbar_reorder"):
            if previous.grouping != style.grouping:
                self._layout_toolbars()
            else:
                self._apply_toolbar_tint()
        if store:
            self.store_window_prefs(**toolbar_categories.style_values(style))

    def toolbar_background(self) -> str:
        """The bars' background colour in the current theme."""
        resolved = themes.resolve(self._current_theme, themes.system_scheme())
        colour = themes.toolbar_background(resolved)
        if colour is None:
            app = QApplication.instance()
            palette = app.palette() if app is not None else self.palette()
            colour = palette.color(QPalette.ColorRole.Window).name()
        return colour

    def _toolbar_text_colour(self) -> str:
        resolved = themes.resolve(self._current_theme, themes.system_scheme())
        tokens = themes.palette_tokens_for(resolved)
        if tokens is not None:
            return tokens["text"]
        app = QApplication.instance()
        palette = app.palette() if app is not None else self.palette()
        return palette.color(QPalette.ColorRole.WindowText).name()

    def toolbar_button_colours(self) -> dict:
        """Category id -> the colours of its buttons (ButtonColours) for
        the current theme, icons and style."""
        from ui import toolbar_categories as TC
        from ui import toolbar_order as TO
        from ui.icon_provider import stroke_colour

        icons: dict[str, list[str]] = {c: [] for c in TC.CATEGORY_IDS}
        for bar in self._order_bars():
            for action in bar.actions():
                tool = TO.tool_id(action)
                if tool and not action.isSeparator():
                    icon_name = str(action.property("axIcon") or tool)
                    icons[TC.category_of(tool)].append(stroke_colour(icon_name))
        background, text = self.toolbar_background(), self._toolbar_text_colour()
        style = self.toolbar_style()
        return {c: TC.button_colours(style.colour(c), background, text, icons[c])
                for c in TC.CATEGORY_IDS}

    def _apply_toolbar_tint(self) -> None:
        """Mark each button with its category and give the bars the style
        sheet of the category colours (none while colours are off). A
        property and a style sheet: no Python object on the buttons."""
        if not hasattr(self, "_toolbar_reorder"):
            return  # the bars are still being built
        from ui import toolbar_categories as TC
        from ui import toolbar_order as TO

        style = self.toolbar_style()
        css = TC.stylesheet(self.toolbar_button_colours(), compact=self._compact_mode) \
            if style.tint else ""
        for bar in self._order_bars():
            changed = []
            for action in bar.actions():
                tool = TO.tool_id(action)
                button = bar.widgetForAction(action)
                if not tool or action.isSeparator() or button is None:
                    continue
                category = TC.category_of(tool)
                if button.property(TC.CATEGORY_PROPERTY) != category:
                    button.setProperty(TC.CATEGORY_PROPERTY, category)
                    changed.append(button)
            if bar.styleSheet() != css:
                with themes.collection_paused():
                    bar.setStyleSheet(css)  # repolishes every button
            elif css:
                for button in changed:  # the selector reads the new property
                    button.style().unpolish(button)
                    button.style().polish(button)
                    button.update()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt
        super().showEvent(event)
        for reorder in getattr(self, "_toolbar_reorder", {}).values():
            reorder.arm()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt
        # Before the window can be destroyed (a close hides it first): the
        # toolbar's Python event filter must be off the buttons by then.
        for reorder in getattr(self, "_toolbar_reorder", {}).values():
            reorder.disarm()
        super().hideEvent(event)

    def createPopupMenu(self):  # noqa: N802 - Qt
        """Qt's right-click menu of the toolbars and docks, plus "Reset
        Toolbar Order"."""
        menu = super().createPopupMenu() or QMenu(self)
        if getattr(self, "_toolbar_reorder", None):
            if menu.actions():
                menu.addSeparator()
            reset = menu.addAction(tr("Reset Toolbar Order"))
            reset.setToolTip(tr("Put the toolbar buttons back in their default order"))
            reset.triggered.connect(lambda _checked=False: self.reset_toolbar_order())
        return menu

    def _rebuild_dock_titlebars(self) -> None:
        """Re-install the dock title bars so their icons re-rasterise
        from the now-monochrome (or colourful-again) provider."""
        dock_specs = [
            (getattr(self, "_transfer_dock", None), "Transfers", "download"),
            (getattr(self, "_terminal_dock", None), "Terminal", "terminal"),
            (getattr(self, "_log_dock", None), "Log", "inbox"),
            (getattr(self, "_scripts_dock", None), tr("Scripts"), "edit"),
            (getattr(self, "_bookmark_sidebar", None), "Bookmarks", "bookmark"),
            (getattr(self, "_analysis_dock", None), tr(ANALYSIS_DOCK_TITLE), "analysis"),
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

        controller = getattr(self, "_update_controller", None)
        if controller is not None:
            controller.shutdown()  # a running download stops and removes its file
        for task in self._connect_tasks:
            try:
                task.abandon()
            except Exception:  # noqa: BLE001 — the rest of the cleanup must run
                log.warning("Abandoning a connect attempt failed on close", exc_info=True)
        self._connect_tasks.clear()
        # A Find Files search walks on a plain thread: closing its window
        # tells it to stop instead of leaving it to finish the whole tree.
        for dlg in list(self._find_dialogs):
            try:
                dlg.close()
            except RuntimeError:  # already deleted
                pass
        cancel = getattr(self, "_scheduler_cancel", None)
        if cancel is not None:
            cancel.set()
        for thread in list(getattr(self, "_scheduler_threads", ())):
            detach_running_thread(thread)
        self._scheduler_threads = []

    def closeEvent(self, event) -> None:
        scripts = getattr(self, "_scripts_dock", None)
        if scripts is not None and not scripts.maybe_close():
            event.ignore()  # unsaved script edits, and the user chose Cancel
            return
        # The editor asks for its unsaved tabs now, while the connections
        # they save through are still open; Cancel keeps everything. Left to
        # Qt's quit, it asked after the teardown below: a Save went to a
        # disconnected backend, a Cancel kept it next to a dead main window.
        from PyQt6 import sip

        editor = getattr(self, "_editor_window", None)
        if editor is not None and not sip.isdeleted(editor) and not editor.close():
            event.ignore()
            return
        # The viewer and editor windows of their own (hex, text, properties,
        # ...) ask for their unsaved changes the same way; destroyed with
        # this window instead, a hex edit was gone without a question.
        from ui import viewer_window as VW

        if not VW.close_independent_windows(self):
            event.ignore()
            return
        log.info("Application closing, cleaning up...")
        if self._tag_job_queue:
            self._flush_tag_jobs()  # ended moves whose tags wait for the gap
        if scripts is not None:
            try:
                scripts.shutdown()  # a running script ends with the window
            except Exception:  # noqa: BLE001 — the rest of the cleanup must run
                log.warning("Scripts dock shutdown failed on close", exc_info=True)
        self._save_session()
        self._close_detached_windows()
        self._reconnect_timer.stop()
        self._abandon_background_threads()
        host = getattr(self, "extension_host", None)
        if host is not None:
            host.unload_all()  # their deactivate() runs while the window is whole
        for check in list(self._conflict_checks):
            check.abandon()
        self._conflict_checks.clear()
        self._conflict_waiting.clear()
        for tp in self._terminal_panes:
            # One broken pane must not skip the cleanup below (transfer
            # threads, connections, temp dirs).
            try:
                tp.shutdown()
            except Exception:  # noqa: BLE001
                log.warning("Terminal pane shutdown failed on close", exc_info=True)
        self._terminal_panes.clear()
        # File panes: their FUSE mounts go before the sessions they serve
        # (disconnect_all below) - left mounted, the kernel kept a mount
        # whose serving thread was gone. Their watchers stop as well.
        for pane in list(self._panes):
            try:
                pane.shutdown()
            except Exception:  # noqa: BLE001 — the rest of the cleanup must run
                log.warning("File pane shutdown failed on close", exc_info=True)
        self._log_dock.shutdown()
        self._terminal_dock.shutdown()
        if getattr(self, "_analysis_dock", None) is not None:
            self._analysis_dock.shutdown()
        if getattr(self, "_agent_dock", None) is not None:
            self._agent_dock.shutdown()
        self._transfer_manager.shutdown()
        self._connection_manager.disconnect_all()
        self._cleanup_archive_tempdirs()
        log.info("Cleanup complete")
        super().closeEvent(event)
