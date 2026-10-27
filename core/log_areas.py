"""Logging areas: which part of axross a logger name belongs to.

One table, the single source of truth for Settings > Logging (a level per
area) and the Log dock's area filter. An area lists the logger names that
belong to it - the module names of axross, ``logging.getLogger(__name__)``,
and the top-level names of third-party libraries. A child logger belongs to
its parent's area (``core.mcp_server.audit`` -> MCP server, ``paramiko.transport``
-> paramiko). ``patterns`` catch names made at run time: an extension runs as
``axross_extension_<source>_<module>`` (ui.extension_host), and modules of a
family still being written (``core.bluetooth*``) need no edit here.

Lookup order: the exact name, a pattern, then the nearest listed parent. The
last step lets a module nobody listed yet log under its package's area at run
time; tests/test_log_areas.py fails for it all the same, because every module
must be listed by name (:func:`explicit_areas`).

Area ids are dotted: ``protocols.smb`` is a sub-area of ``protocols``. A
sub-area without a level of its own takes its parent's (core.log_config).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Area:
    id: str
    #: English label; the UI passes it through tr().
    label: str
    #: Logger names of this area; their child loggers belong to it too.
    loggers: tuple[str, ...] = ()
    #: fnmatch patterns for logger names made at run time.
    patterns: tuple[str, ...] = ()
    #: The level an area has until the user picks one: "inherit" or a level name.
    default: str = "inherit"

    @property
    def parent(self) -> str | None:
        head, dot, _tail = self.id.rpartition(".")
        return head if dot else None


def _core(*names: str) -> tuple[str, ...]:
    return tuple(f"core.{n}" for n in names)


def _ui(*names: str) -> tuple[str, ...]:
    return tuple(f"ui.{n}" for n in names)


def _models(*names: str) -> tuple[str, ...]:
    return tuple(f"models.{n}" for n in names)


#: Parents come before their children - the Settings page builds its tree in
#: this order.
AREAS: tuple[Area, ...] = (
    Area("app", "Application", (
        "axross", "axross.cli", "axross.__main__", "axross._version", "core",
        *_core("features", "startup_guard", "qt_exit", "thread_lifetime", "i18n",
               "posix_compat", "frozen_archive", "process_launcher", "subprocess_env",
               "desktop_open", "pane_activation", "open_limits", "third_party",
               "structured_log", "log_areas", "log_config"),
    )),
    Area("protocols", "Protocols"),
    Area("protocols.connections", "Connections & Proxy", (
        *_core("backend", "backend_registry", "capability_contracts", "connection_manager",
               "connect_worker", "conn_health", "dashboard", "diagnostics", "profiles",
               "net_helpers", "auth_prompt", "proxy", "proxy_http", "pac", "proxy_settings",
               "tls_context", "tls_env", "client_identity", "remote_name", "storage_identity",
               "session_lock", "server_ops", "version_stubs", "adaptive_io", "read_spool",
               "path_policy", "answer_fields", "exec_util", "reverse_serve"),
        *_ui("auth_prompt", "connection_dialog", "quick_connect_menu", "disconnected_pane",
             "network_proxy_dialog"),
    )),
    Area("protocols.ssh", "SFTP / SSH / SCP / rsync",
         _core("ssh_client", "sftp_io", "scp_client", "rsync_client", "ssh_config")),
    Area("protocols.smb", "SMB / DFS", _core("smb_client", "smb_shares", "dfsn_client")),
    Area("protocols.ftp", "FTP / TFTP", _core("ftp_client", "tftp_client")),
    Area("protocols.webdav", "WebDAV", _core("webdav_client")),
    Area("protocols.cloud", "Cloud Storage (S3, Azure, Google Drive, Dropbox, OneDrive)",
         _core("s3_client", "azure_client", "gdrive_client", "dropbox_client",
               "onedrive_client", "oauth_help")),
    Area("protocols.nfs", "NFS / iSCSI", _core("nfs_client", "iscsi_client")),
    Area("protocols.mail", "Mail / News (IMAP, POP3, NNTP, Exchange)",
         _core("imap_client", "pop3_client", "nntp_client", "nntp_lib", "exchange_client")),
    Area("protocols.windows", "WinRM / WMI", _core("winrm_client", "wmi_client")),
    Area("protocols.database", "Databases / LDAP",
         _core("sqlite_fs_client", "postgres_fs_client", "mongo_fs_client", "redis_fs_client",
               "db_fs_base", "ldap_fs_client")),
    Area("protocols.vcs", "Git / SVN", _core("git_fs_client", "git_fs_writer_helper",
                                            "svn_fs_client")),
    Area("protocols.devices", "Devices (ADB, MTP, Bluetooth)", _core("adb_client", "mtp_client"),
         patterns=("core.bluetooth*",)),
    Area("protocols.legacy", "Legacy (Telnet, rsh, Gopher, SLP, PJL, SNMP)",
         _core("telnet_client", "telnet_cisco", "rsh_client", "gopher_client", "slp_client",
               "slp_lib", "pjl_client", "snmp_helpers")),
    Area("files", "Local Files & File Operations", (
        *_core("local_fs", "ram_fs", "ramfs_settings", "tmpfs_detect", "archive", "packer",
               "atomic_io", "atomic_recovery", "trash", "disk_image", "loop_mount",
               "fuse_mount", "private_mount_dir", "elevated_io", "encrypted_overlay",
               "snapshot_browser", "xlink", "cut_paste", "undo", "append_helpers",
               "removal_cancel", "watch", "tree_size", "tree_compare", "fs_summary",
               "multi_view", "text_document", "recovery", "destructive_preview", "trail"),
        *_ui("archive_pane", "batch_rename_dialog", "permissions_dialog", "pack_dialog",
             "dir_size_dialog", "disk_usage_dialog", "disk_image_dialog", "trash_browser",
             "create_xlink_dialog", "cut_clipboard", "elevated_viewer",
             "snapshot_browser_dialog", "compare_dialog"),
        *_models("trash_entry", "watch_tick_state", "xlink"),
    )),
    Area("transfers", "Transfers", (
        *_core("transfer_manager", "transfer_pool", "transfer_worker", "transfer_conflicts",
               "copy_resume", "sync", "scheduler", "operation_journal"),
        *_ui("transfer_dock", "transfer_conflict_dialog", "scheduler_dialog"),
        *_models("transfer_model"),
    )),
    Area("search", "Indexing / Search", (
        *_core("file_search", "metadata_index", "cas", "search_federation", "remote_sweep",
               "tags", "file_categories", "inspect"),
        *_ui("find_files_dialog", "metadata_search_dialog", "network_search_dialog",
             "cas_dialog", "cas_history_dialog", "checksum_dialog", "tag_ui"),
    )),
    Area("analysis", "Analysis (sift) / Metadata", (
        "sift",
        *_core("file_analysis", "analysis_worker", "analysis_settings", "file_type",
               "metadata_formats", "metadata_tools"),
        *_ui("analysis_dock", "analysis_settings_page", "file_type_dialog", "metadata_dialog"),
    )),
    Area("agent", "Agent / LLM", (
        *_core("agent", "agent_access", "agent_link", "agent_net", "agent_profiles",
               "agent_prompts", "agent_sandbox", "agent_session", "agent_settings",
               "agent_topics", "agent_worker", "llm_profiles"),
        *_ui("agent_access_dialog", "agent_dock", "agent_link_lamp", "agent_panels",
             "agent_profile_dialog", "agent_settings_dialog", "llm_settings_dialog",
             "work_prompts_dialog"),
    )),
    Area("mcp", "MCP"),
    Area("mcp.client", "MCP Client (servers the agent uses)", (
        *_core("mcp_client", "mcp_catalog", "mcp_detect", "mcp_discover", "mcp_install",
               "mcp_runner", "mcp_egress"),
        *_ui("mcp_catalog_dialog"),
    )),
    Area("mcp.server", "MCP Server (axross as a server)",
         _core("mcp_server", "mcp_http", "mcp_groups")),
    Area("scripting", "Scripting", (
        *_core("scripting", "script_runner", "ui_helpers", "llm_guide"),
        *_ui("repl_widget", "script_editor", "scripting_guide", "scripts_dock"),
    )),
    Area("media", "Media / Audio / Voice", (
        *_core("audio_route", "audio_settings", "multimedia_env", "multimedia_probe",
               "media_collect", "media_load", "previews", "voice_audio", "voice_models",
               "voice_settings", "voice_stt", "voice_text", "voice_worker"),
        *_ui("audio_settings_page", "voice", "voice_lens", "voice_settings_page",
             "media_viewer", "image_viewer"),
    )),
    Area("update", "Update", (*_core("self_update"), *_ui("update_ui"))),
    Area("security", "Security / Credentials", (
        *_core("credentials", "secure_storage", "security_mode", "sudo_password", "redaction",
               "cred_attack", "safety_tarpit"),
        *_ui("production_gate"),
    )),
    Area("terminal", "Terminal / Remote Commands", (
        *_core("terminal_here", "vt_screen"),
        *_ui("terminal_pane", "terminal_widget"),
        *_models("exec_result", "interactive_shell"),
    )),
    Area("extensions", "Extensions", (
        "axross.ext", "resources.extensions",
        *_core("extensions"),
        *_ui("extension_host", "extension_panels", "extensions_dialog"),
    ), patterns=("resources.extensions.*", "axross_extension_*")),
    Area("ui", "User Interface", (
        "ui", "models",
        *_core("bookmarks", "visit_history"),
        *_ui("bookmark_edit_dialog", "bookmark_manager_dialog", "bookmark_sidebar",
             "close_corner", "code_editor", "column_fit", "column_prefs", "dock_fit",
             "dock_frame", "dock_titlebar", "editor_window", "features_dialog", "file_pane",
             "format_utils", "hex_editor", "icon_provider", "layout_presets", "layout_utils",
             "log_dock", "logging_settings_page", "main_window", "pane_drag",
             "properties_dialog", "scan_job", "settings_dialog", "shortcuts_dialog", "text_editor",
             "themes", "third_party_dialog", "thread_lifetime", "thumbnail_view",
             "toolbar_categories", "toolbar_order", "viewer_file_actions", "viewer_window",
             "window_move", "window_prefs", "workspaces"),
        *_models("file_item", "file_table_model", "file_version"),
    )),
    Area("third_party", "Third-Party Libraries", default="WARNING"),
    Area("third_party.ssh", "paramiko (SSH)", ("paramiko",)),
    Area("third_party.smb", "smbprotocol / impacket (SMB)",
         ("smbprotocol", "smbclient", "spnego", "impacket")),
    Area("third_party.http", "HTTP (urllib3, requests, httpx)",
         ("urllib3", "requests", "httpx", "httpcore", "httplib2", "socks", "charset_normalizer")),
    Area("third_party.cloud", "Cloud SDKs (boto3, Azure, Google, MSAL, Dropbox)",
         ("boto3", "botocore", "s3transfer", "azure", "msal", "google", "googleapiclient",
          "google_auth_oauthlib", "google_auth_httplib2", "oauthlib", "requests_oauthlib",
          "dropbox")),
    Area("third_party.other", "Other Libraries (Pillow, asyncio, keyring, ...)",
         ("PIL", "asyncio", "concurrent", "keyring", "watchdog", "dulwich", "py7zr", "rarfile",
          "tftpy", "psycopg", "redis", "pymongo", "ldap3", "pysnmp", "dns", "puremagic",
          "chardet", "pypdf", "numpy", "exchangelib", "winrm", "pypsrp", "adb_shell", "fuse",
          "manuf", "ipwhois", "ntplib", "onnxruntime", "faster_whisper", "ctranslate2", "piper",
          "huggingface_hub", "filelock", "markdown_it")),
)

AREAS_BY_ID: dict[str, Area] = {a.id: a for a in AREAS}
AREA_IDS: tuple[str, ...] = tuple(a.id for a in AREAS)

_EXACT: dict[str, str] = {name: a.id for a in AREAS for name in a.loggers}
_PATTERNS: tuple[tuple[str, str], ...] = tuple((p, a.id) for a in AREAS for p in a.patterns)


def explicit_areas(name: str) -> list[str]:
    """The areas that list *name* itself or match it by a pattern - without
    the parent fallback. Exactly one for every module of axross (the test)."""
    hits = []
    if name in _EXACT:
        hits.append(_EXACT[name])
    for pattern, area_id in _PATTERNS:
        if fnmatch.fnmatchcase(name, pattern) and area_id not in hits:
            hits.append(area_id)
    return hits


@lru_cache(maxsize=4096)
def area_of(name: str) -> str | None:
    """The area of the logger *name*, or None for a name outside axross and
    the libraries it lists (a test, ``py.warnings``)."""
    if not name:
        return None
    if name in _EXACT:
        return _EXACT[name]
    for pattern, area_id in _PATTERNS:
        if fnmatch.fnmatchcase(name, pattern):
            return area_id
    head = name
    while "." in head:
        head = head.rpartition(".")[0]
        if head in _EXACT:
            return _EXACT[head]
    return None


def ancestors(area_id: str) -> list[str]:
    """*area_id* and its parents, nearest first. KeyError for an unknown id."""
    out = []
    current: str | None = area_id
    while current is not None:
        out.append(AREAS_BY_ID[current].id)
        current = AREAS_BY_ID[current].parent
    return out


def children(area_id: str) -> list[str]:
    """The direct sub-areas of *area_id*."""
    return [a.id for a in AREAS if a.parent == area_id]


def logger_names(area_id: str) -> tuple[str, ...]:
    return AREAS_BY_ID[area_id].loggers


def is_third_party(area_id: str) -> bool:
    return area_id == "third_party" or area_id.startswith("third_party.")


__all__ = ["AREAS", "AREAS_BY_ID", "AREA_IDS", "Area", "ancestors", "area_of", "children",
           "explicit_areas", "is_third_party", "logger_names"]
