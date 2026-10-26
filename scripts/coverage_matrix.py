"""Generate docs/TEST_COVERAGE_MATRIX.md: one row per main feature of axross.

Usage::

    python scripts/coverage_matrix.py --data COMBINED_COVERAGE_FILE \\
        --command "the command that produced it" [--date YYYY-MM-DD] \\
        [--rc RC_TXT] [--out docs/TEST_COVERAGE_MATRIX.md]
    python scripts/coverage_matrix.py --check

The coverage data comes from a per-file branch-coverage run over every
``tests/test_*.py`` (``cov_scope.sh``: one ``.coverage.<file>`` per test file,
then ``coverage combine``). For every feature of ``FEATURES`` the matrix shows

* line and branch coverage of its main modules (summed over the modules);
* the test files that import one of those modules (``grep``, not a guess);
* how many test functions in those files are happy / sad / edge tests - read
  from the project's naming convention (``test_happy_*``, ``test_sad_*``,
  ``test_edge_*``), with a keyword fallback for older names;
* the end-to-end tests: hand-picked node ids in ``FEATURES``, each with its
  kind (see ``E2E_KINDS``). ``--check`` fails when a node id no longer exists
  or a module is neither mapped to a feature nor named in ``INFRASTRUCTURE``,
  so the table cannot silently go stale.
"""

from __future__ import annotations

import argparse
import ast
import datetime as _dt
import glob
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: What an end-to-end test drives.
E2E_KINDS = {
    "ui": "the real window or widget offscreen (QTest keys/clicks or the slot a menu "
    "entry calls) on a real backend (LocalFS, RamFS)",
    "backend": "the real backend on a real local resource (a folder, an SQLite file, a git "
    "repository, a FUSE mount, a real HTTP request against the served endpoint)",
    "fake-server": "the backend's own wire code over a real socket against a protocol "
    "server scripted in the test",
    "process": "a real axross child process (CLI, MCP server, watchdog)",
    "lab": "a container of the podman lab (tests/docker); skipped when the lab is not "
    "reachable, so not part of a host coverage run",
}


@dataclass(frozen=True)
class Feature:
    group: str
    key: str
    name: str
    modules: tuple[str, ...]
    e2e: tuple[tuple[str, str], ...] = ()


def _f(group, key, name, modules, e2e=()):
    return Feature(group, key, name, tuple(modules), tuple(e2e))


FEATURES: tuple[Feature, ...] = (
    # ---------------------------------------------------------------- backends
    _f(
        "Connections & backends",
        "connections",
        "Connection Manager, Quick Connect, profiles, SSH config import, keyring",
        [
            "core/profiles.py",
            "core/connection_manager.py",
            "core/connect_worker.py",
            "core/credentials.py",
            "core/ssh_config.py",
            "core/secure_storage.py",
            "core/oauth_help.py",
            "core/auth_prompt.py",
            "core/conn_health.py",
            "core/client_identity.py",
            "core/sudo_password.py",
            "ui/connection_dialog.py",
            "ui/quick_connect_menu.py",
            "ui/auth_prompt.py",
        ],
        [
            (
                "tests/test_delete_connection_config.py::test_happy_e2e_quick_connect_delete_removes_profile_recent_and_password",
                "ui",
            ),
            (
                "tests/test_connection_dialog_async_labels.py::test_e2e_connect_to_server_of_the_window_opens_and_labels",
                "ui",
            ),
            (
                "tests/test_connection_dialog_protocol_matrix.py::"
                "test_happy_e2e_an_mtp_connection_is_saved_through_the_window",
                "ui",
            ),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-layer",
        "Backend layer: registry, capability contracts, path policy",
        [
            "core/backend.py",
            "core/backend_registry.py",
            "core/capability_contracts.py",
            "core/version_stubs.py",
            "core/remote_name.py",
            "core/path_policy.py",
        ],
        [
            (
                "tests/test_ramfs_tftp_profiles.py::test_happy_two_ram_workspaces_are_two_sessions",
                "backend",
            )
        ],
    ),
    _f(
        "Connections & backends",
        "backend-local",
        "Local file system (incl. polkit-elevated reads)",
        ["core/local_fs.py", "core/elevated_io.py", "ui/elevated_viewer.py"],
        [
            (
                "tests/test_drag_drop_move_copy.py::BetweenPanesTest::test_happy_a_plain_drop_moves",
                "ui",
            )
        ],
    ),
    _f(
        "Connections & backends",
        "backend-ssh",
        "SFTP / SCP",
        ["core/ssh_client.py", "core/sftp_io.py", "core/scp_client.py"],
        [
            (
                "tests/test_scp_large_upload.py::ScpLargeUploadTest::test_happy_small_binary_upload",
                "fake-server",
            ),
            ("tests/test_protocols.py::test_ssh_atomic_write", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-ftp",
        "FTP / FTPS",
        ["core/ftp_client.py"],
        [
            (
                "tests/test_ftp_parallel_connections.py::test_happy_uploads_and_downloads_together_are_byte_exact",
                "fake-server",
            ),
            ("tests/test_protocols.py::test_ftp_write_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-smb",
        "SMB / DFS-N",
        ["core/smb_client.py", "core/dfsn_client.py", "core/smb_shares.py"],
        [("tests/test_protocols.py::test_smb_write_cycle", "lab")],
    ),
    _f(
        "Connections & backends",
        "backend-webdav",
        "WebDAV",
        ["core/webdav_client.py"],
        [
            (
                "tests/test_webdav_thread_sessions.py::test_happy_threads_put_and_get_byte_exact_on_one_session",
                "fake-server",
            ),
            ("tests/test_protocols.py::test_webdav_write_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-s3",
        "S3-compatible",
        ["core/s3_client.py"],
        [
            ("tests/test_fuzz_s3.py::test_happy_listing", "fake-server"),
            ("tests/test_protocols.py::test_s3_write_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-rsync",
        "Rsync",
        ["core/rsync_client.py"],
        [
            (
                "tests/test_rsync_remove_folder.py::test_happy_a_tree_is_removed_with_its_folder",
                "fake-server",
            ),
            ("tests/test_protocols.py::test_rsync_write_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-nfs-iscsi",
        "NFS / iSCSI (mount wrappers)",
        ["core/nfs_client.py", "core/iscsi_client.py", "core/private_mount_dir.py"],
        [
            ("tests/test_protocols.py::TestNfs::test_nfs_write_read_cycle", "lab"),
            ("tests/test_protocols.py::TestIscsi::test_iscsi_write_read_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-azure",
        "Azure Blob / Azure Files",
        ["core/azure_client.py"],
        [
            (
                "tests/test_azure_files_rename_target.py::AzureFilesRenameTargetTest::test_happy_file_rename_in_the_share_root",
                "fake-server",
            ),
            ("tests/test_protocols.py::TestAzureBlob::test_azure_blob_write_read_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-cloud",
        "OneDrive / SharePoint / Google Drive / Dropbox",
        ["core/onedrive_client.py", "core/gdrive_client.py", "core/dropbox_client.py"],
        [
            (
                "tests/test_onedrive_path_encoding.py::OneDrivePathEncodingTest::test_happy_plain_names_are_unchanged",
                "fake-server",
            )
        ],
    ),
    _f(
        "Connections & backends",
        "backend-mail",
        "IMAP / POP3 / Exchange (EWS)",
        ["core/imap_client.py", "core/pop3_client.py", "core/exchange_client.py"],
        [
            (
                "tests/test_pop3_stat.py::Pop3StatTest::test_happy_stat_reports_the_message_size",
                "fake-server",
            ),
            (
                "tests/test_imap_connection_state.py::ImapConnectionStateTest::test_happy_select_once_per_connection",
                "fake-server",
            ),
            ("tests/test_protocols.py::TestImap::test_imap_write_read_cycle", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-news",
        "NNTP / Gopher",
        ["core/nntp_client.py", "core/nntp_lib.py", "core/gopher_client.py"],
        [
            (
                "tests/test_nntp_binary_articles.py::NntpBinaryArticleTest::test_happy_ascii_article_with_dot_stuffing",
                "fake-server",
            ),
            (
                "tests/test_gopher_recursive_fetch.py::RecursiveFetchNamingTest::test_happy_info_lines_are_not_fetched_as_files",
                "fake-server",
            ),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-db",
        "SQLite / PostgreSQL / Redis / MongoDB / LDAP as FS",
        [
            "core/db_fs_base.py",
            "core/sqlite_fs_client.py",
            "core/postgres_fs_client.py",
            "core/redis_fs_client.py",
            "core/mongo_fs_client.py",
            "core/ldap_fs_client.py",
        ],
        [
            ("tests/test_sqlite_fs_memory.py::test_memory_backend_is_functional", "backend"),
            ("tests/test_protocols.py::test_ldap_list_dir_navigates_tree", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-vcs",
        "Git / SVN as FS",
        ["core/git_fs_client.py", "core/git_fs_writer_helper.py", "core/svn_fs_client.py"],
        [
            ("tests/test_protocols.py::test_git_log_returns_history_newest_first", "backend"),
            ("tests/test_protocols.py::test_svn_lists_and_reads_with_matching_sizes", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-legacy",
        "Telnet / Cisco IOS / rsh / TFTP",
        [
            "core/telnet_client.py",
            "core/telnet_cisco.py",
            "core/rsh_client.py",
            "core/tftp_client.py",
        ],
        [
            (
                "tests/test_telnet_raw_transfer_is_byte_exact.py::test_happy_upload_stores_the_bytes_unchanged",
                "fake-server",
            ),
            (
                "tests/test_tftp_size_probe.py::SizeProbeTest::test_happy_tsize_server_answers_without_data_blocks",
                "fake-server",
            ),
            ("tests/test_protocols.py::TestTelnet::test_telnet_write_read", "lab"),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-printer",
        "PJL printer FS / SLP discovery",
        ["core/pjl_client.py", "core/slp_client.py", "core/slp_lib.py"],
        [
            (
                "tests/test_pjl_exists_only_not_found_is_false.py::test_happy_present_and_absent",
                "fake-server",
            ),
            (
                "tests/test_slp_multicast_overflow.py::test_happy_a_unicast_host_is_asked_and_answers",
                "fake-server",
            ),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-windows",
        "WinRM / WMI",
        ["core/winrm_client.py", "core/wmi_client.py"],
        [
            (
                "tests/test_winrm_proxy_session.py::test_happy_proxy_profile_constructs_and_its_session_uses_the_proxy",
                "fake-server",
            )
        ],
    ),
    _f(
        "Connections & backends",
        "backend-mobile",
        "ADB / MTP",
        ["core/adb_client.py", "core/mtp_client.py"],
        [
            ("tests/test_mtp_confined.py::test_happy_the_device_is_read_and_written", "backend"),
            (
                "tests/test_remove_matrix.py::"
                "test_happy_e2e_a_symlink_to_a_folder_is_deleted_as_the_pane_deletes_it",
                "backend",
            ),
        ],
    ),
    _f(
        "Connections & backends",
        "backend-ramfs",
        "RamFS volatile workspace",
        ["core/ram_fs.py", "core/ramfs_settings.py", "core/tmpfs_detect.py"],
        [
            (
                "tests/test_pane_cut_paste.py::test_happy_e2e_cut_and_paste_across_backends_into_ramfs",
                "ui",
            )
        ],
    ),
    # ---------------------------------------------------------- panes, layout
    _f(
        "Panes & layout",
        "file-pane",
        "Multi-pane file panes (listing, navigation, path bar, drag & drop)",
        [
            "ui/file_pane.py",
            "ui/main_window.py",
            "ui/column_fit.py",
            "ui/column_prefs.py",
            "ui/pane_drag.py",
            "core/pane_activation.py",
            "ui/disconnected_pane.py",
        ],
        [
            ("tests/test_drag_drop_move_copy.py::BetweenPanesTest::test_happy_ctrl_copies", "ui"),
            (
                "tests/test_pane_filter_escape.py::test_happy_e2e_esc_in_the_filter_line_clears_it_and_returns_to_the_list",
                "ui",
            ),
        ],
    ),
    _f(
        "Panes & layout",
        "layouts",
        "Layout presets, workspaces, session restore",
        [
            "ui/layout_presets.py",
            "ui/workspaces.py",
            "ui/window_prefs.py",
            "ui/window_move.py",
            "ui/dock_titlebar.py",
        ],
        [
            (
                "tests/test_workspaces.py::test_e2e_main_window_shortcuts_work_in_a_detached_window",
                "ui",
            ),
            (
                "tests/test_layout_preset_root_splitter.py::test_happy_every_preset_leaves_a_live_root_splitter",
                "ui",
            ),
        ],
    ),
    _f(
        "Panes & layout",
        "thumbnails",
        "Thumbnail view and previews",
        ["ui/thumbnail_view.py", "core/previews.py"],
        [("tests/test_thumbnail_view.py::test_happy_double_click_on_a_folder_tile_opens_it", "ui")],
    ),
    # ------------------------------------------------- transfers, file ops
    _f(
        "Transfers & file operations",
        "transfers",
        "Transfer queue: copy / move between any two backends, conflicts",
        [
            "core/transfer_manager.py",
            "core/transfer_worker.py",
            "core/transfer_pool.py",
            "core/transfer_conflicts.py",
            "core/adaptive_io.py",
            "core/read_spool.py",
            "core/server_ops.py",
            "ui/transfer_dock.py",
            "ui/transfer_conflict_dialog.py",
        ],
        [
            (
                "tests/test_transfer_parallel.py::test_e2e_the_dock_shows_several_running_jobs_with_their_progress_and_speed",
                "ui",
            ),
            ("tests/test_protocols.py::test_ftp_to_smb", "lab"),
        ],
    ),
    _f(
        "Transfers & file operations",
        "resumable-copy",
        "Resumable cross-backend copy",
        ["core/copy_resume.py"],
        [
            (
                "tests/test_copy_resume_commit.py::CommitTest::test_happy_a_committed_copy_is_complete",
                "backend",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "cut-paste",
        "Cut and Paste",
        ["core/cut_paste.py", "ui/cut_clipboard.py"],
        [
            (
                "tests/test_pane_cut_paste.py::test_happy_e2e_cut_then_ctrl_v_in_the_other_pane_moves",
                "ui",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "delete-trash-undo",
        "Delete preview, trash, undo, cancel inside a folder",
        [
            "core/trash.py",
            "ui/trash_browser.py",
            "core/destructive_preview.py",
            "core/undo.py",
            "core/removal_cancel.py",
        ],
        [
            (
                "tests/test_delete_cancel_inside_folder.py::PaneCancelInsideFolderTest::test_e2e_cancel_inside_one_big_folder_reports_the_partial_delete",
                "ui",
            ),
            (
                "tests/test_trash_browser_async.py::TrashListingAsyncTest::test_e2e_open_from_the_pane_menu_with_a_slow_listing",
                "ui",
            ),
        ],
    ),
    _f(
        "Transfers & file operations",
        "journal-recovery",
        "Atomic writes, operation journal, recovery scan, diagnostics",
        [
            "core/atomic_io.py",
            "core/atomic_recovery.py",
            "core/operation_journal.py",
            "core/recovery.py",
            "core/diagnostics.py",
        ],
        [
            (
                "tests/test_journal_keeps_real_paths.py::test_happy_undo_restores_a_trashed_file_under_its_real_name",
                "backend",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "batch-rename",
        "Batch rename",
        ["ui/batch_rename_dialog.py"],
        [
            (
                "tests/test_rename_case_only_and_feedback.py::test_happy_batch_case_only_rename_on_a_case_insensitive_backend",
                "ui",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "properties",
        "Properties, permissions, folder size, checksums",
        [
            "ui/properties_dialog.py",
            "ui/permissions_dialog.py",
            "core/fs_summary.py",
            "core/tree_size.py",
            "ui/dir_size_dialog.py",
            "ui/checksum_dialog.py",
        ],
        [
            (
                "tests/test_dir_size_results.py::test_happy_e2e_the_pane_shows_and_sorts_by_the_computed_size",
                "ui",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "xlink",
        "Cross-protocol links (xlink)",
        ["core/xlink.py", "ui/create_xlink_dialog.py"],
        [
            (
                "tests/test_xlink_create_e2e.py::"
                "test_happy_e2e_create_xlink_from_the_menu_writes_the_link_and_lists_it",
                "ui",
            ),
        ],
    ),
    _f(
        "Transfers & file operations",
        "compare-sync",
        "Compare panes / sync plan",
        ["core/tree_compare.py", "core/sync.py", "ui/compare_dialog.py"],
        [
            (
                "tests/test_compare_delete_async.py::CompareDeleteAsyncTest::test_e2e_delete_from_the_compare_window",
                "ui",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "duplicates",
        "Duplicate Finder (CAS)",
        ["core/cas.py", "ui/cas_dialog.py", "ui/cas_history_dialog.py"],
        [
            (
                "tests/test_cas_finder_e2e.py::EndToEndTest::test_happy_hotkey_rebuild_mark_all_trash_restore",
                "ui",
            )
        ],
    ),
    _f(
        "Transfers & file operations",
        "disk-usage",
        "Disk usage, Treemap, Drives Overview",
        [
            "ui/disk_usage_dialog.py",
            "resources/extensions/folder_treemap.py",
            "resources/extensions/drives_overview.py",
        ],
        [
            (
                "tests/test_folder_treemap_layout.py::test_e2e_the_panel_draws_hovers_and_opens_a_folder_of_a_big_listing",
                "ui",
            ),
            (
                "tests/test_drives_overview.py::test_e2e_extension_loads_in_the_window_and_fills_its_panel",
                "ui",
            ),
        ],
    ),
    _f(
        "Transfers & file operations",
        "scheduler",
        "Scheduled jobs",
        ["core/scheduler.py", "ui/scheduler_dialog.py"],
        [
            (
                "tests/test_scripts_dock_e2e.py::test_edge_scripts_used_by_a_scheduled_job_are_marked",
                "ui",
            ),
            (
                "tests/test_scheduler_script_child.py::test_edge_the_script_runs_in_another_process",
                "process",
            ),
        ],
    ),
    # ------------------------------------------------------ search, organise
    _f(
        "Search & organise",
        "find-files",
        "Find Files and Smart Folders",
        [
            "core/file_search.py",
            "core/file_categories.py",
            "ui/find_files_dialog.py",
            "ui/scan_job.py",
        ],
        [
            (
                "tests/test_find_files_dialog.py::test_e2e_find_double_click_navigates_the_pane_and_selects_the_file",
                "ui",
            ),
            (
                "tests/test_find_files_dialog.py::test_e2e_smart_folder_round_trip_through_the_sidebar",
                "ui",
            ),
            (
                "tests/test_file_search_live.py::test_live_smb_by_type_content_and_inside_an_archive",
                "lab",
            ),
        ],
    ),
    _f(
        "Search & organise",
        "offline-index",
        "Offline metadata index (Find in Index)",
        ["core/metadata_index.py", "ui/metadata_search_dialog.py"],
        [
            ("tests/test_find_files_dialog.py::test_e2e_index_active_folder_from_the_menu", "ui"),
            (
                "tests/test_index_data_home.py::test_happy_e2e_a_fresh_process_indexes_into_xdg_data_home",
                "process",
            ),
        ],
    ),
    _f(
        "Search & organise",
        "network-search",
        "Find on network hosts (SMB sweep)",
        ["core/remote_sweep.py", "ui/network_search_dialog.py"],
        [("tests/test_network_search_dialog.py::test_live_e2e_open_a_hit_in_a_new_pane", "lab")],
    ),
    _f(
        "Search & organise",
        "tags",
        "Coloured tags",
        ["core/tags.py", "ui/tag_ui.py"],
        [
            ("tests/test_tags.py::test_e2e_tags_follow_an_f6_move", "ui"),
            ("tests/test_tags_non_utf8_names.py::test_e2e_tag_from_the_pane_context_menu", "ui"),
        ],
    ),
    _f(
        "Search & organise",
        "bookmarks",
        "Bookmarks, groups, terminal bookmarks, manager",
        [
            "core/bookmarks.py",
            "ui/bookmark_sidebar.py",
            "ui/bookmark_manager_dialog.py",
            "ui/bookmark_edit_dialog.py",
        ],
        [
            (
                "tests/test_bookmark_manager_dialog.py::test_happy_e2e_a_change_in_the_manager_shows_in_the_sidebar_and_menu_at_once",
                "ui",
            )
        ],
    ),
    _f(
        "Search & organise",
        "trail",
        "Trail / snapshot timeline / version browser",
        ["core/trail.py", "core/snapshot_browser.py", "ui/snapshot_browser_dialog.py"],
        [
            ("tests/test_multi_system.py::TrailTests::test_diff_detects_modified_file", "backend"),
            (
                "tests/test_trail.py::test_happy_e2e_a_background_trail_on_ramfs_records_a_change",
                "backend",
            ),
            (
                "tests/test_snapshot_job.py::SnapshotJobTest::test_restore_completes_and_replaces_the_file",
                "ui",
            ),
        ],
    ),
    # ---------------------------------------------------------- files, formats
    _f(
        "Files & formats",
        "archive-browse",
        "Archives as folders (browse, nested, extract)",
        ["core/archive.py", "ui/archive_pane.py"],
        [
            (
                "tests/test_archive_nested_ui.py::test_happy_e2e_double_click_opens_a_zip_in_a_tar_and_back_returns",
                "ui",
            )
        ],
    ),
    _f(
        "Files & formats",
        "pack",
        "Pack into an archive",
        ["core/packer.py", "ui/pack_dialog.py"],
        [("tests/test_pack_ui.py::test_happy_one_click_zip_lands_in_the_folder", "ui")],
    ),
    _f(
        "Files & formats",
        "metadata",
        "Metadata view / strip / export",
        ["core/metadata_tools.py", "core/metadata_formats.py", "ui/metadata_dialog.py"],
        [("tests/test_metadata_ui.py::test_e2e_folder_show_recursive_export_remove_undo", "ui")],
    ),
    _f(
        "Files & formats",
        "encryption",
        "Encryption overlay (.axenc)",
        ["core/encrypted_overlay.py"],
        [
            (
                "tests/test_encrypt_keeps_existing_ciphertext.py::EncryptExistingCiphertextTest::test_happy_a_first_encryption_asks_nothing",
                "ui",
            )
        ],
    ),
    _f(
        "Files & formats",
        "file-type",
        "File type by content",
        ["core/file_type.py", "ui/file_type_dialog.py"],
        [
            (
                "tests/test_identify_folder.py::test_happy_e2e_right_click_on_empty_space_identifies_the_folder",
                "ui",
            )
        ],
    ),
    _f(
        "Files & formats",
        "disk-images",
        "Disk images, loop mount, Forensic Tools",
        [
            "core/disk_image.py",
            "core/loop_mount.py",
            "ui/disk_image_dialog.py",
            "resources/extensions/forensic_tools.py",
        ],
        [
            ("tests/test_disk_image.py::test_e2e_agrees_with_sfdisk_and_mkfs", "backend"),
            (
                "tests/test_forensic_tools_extension.py::test_e2e_browse_opens_the_file_list_and_extracts",
                "ui",
            ),
        ],
    ),
    # ------------------------------------------------------- viewers, editors
    _f(
        "Viewers & editors",
        "text-editor",
        "Tabbed text editor",
        [
            "ui/text_editor.py",
            "ui/code_editor.py",
            "ui/editor_window.py",
            "core/text_document.py",
            "core/open_limits.py",
            "ui/viewer_file_actions.py",
        ],
        [
            (
                "tests/test_code_editor.py::test_e2e_edit_from_the_pane_opens_a_tab_and_refreshes_after_save",
                "ui",
            ),
            (
                "tests/test_editor_file_actions.py::test_e2e_shortcuts_drive_new_type_save_as_and_open",
                "ui",
            ),
        ],
    ),
    _f(
        "Viewers & editors",
        "hex-editor",
        "Hex editor",
        ["ui/hex_editor.py"],
        [
            (
                "tests/test_hex_paint_static_text.py::test_e2e_the_hex_dialog_scrolls_and_edits_and_looks_as_before",
                "ui",
            ),
            (
                "tests/test_hex_editor_matrix.py::"
                "test_happy_e2e_type_hex_and_ascii_then_save_writes_the_file",
                "ui",
            ),
        ],
    ),
    _f(
        "Viewers & editors",
        "media-viewer",
        "Image / PDF / video viewer",
        [
            "ui/image_viewer.py",
            "ui/media_viewer.py",
            "ui/viewer_window.py",
            "core/media_collect.py",
            "core/media_load.py",
        ],
        [
            (
                "tests/test_media_viewer_e2e.py::test_e2e_view_media_recursive_overview_viewer_slideshow_escape",
                "ui",
            )
        ],
    ),
    _f(
        "Viewers & editors",
        "media-player",
        "Media Player extension",
        [
            "resources/extensions/media_player.py",
            "core/multimedia_env.py",
            "core/multimedia_probe.py",
        ],
        [
            (
                "tests/test_media_player_controls.py::test_e2e_panel_seeks_a_real_track_with_the_slider",
                "ui",
            )
        ],
    ),
    # ----------------------------------------------------- mount, serve, shell
    _f(
        "Mount, serve, shell",
        "fuse-mount",
        "FUSE mount of any backend",
        ["core/fuse_mount.py"],
        [
            (
                "tests/test_quit_unmounts_fuse.py::RealMountTest::test_happy_a_real_mount_is_gone_after_quit",
                "ui",
            ),
            ("tests/test_fuse_end_to_end.py::test_happy_write_and_read_back", "backend"),
        ],
    ),
    _f(
        "Mount, serve, shell",
        "reverse-serve",
        "Reverse serve over S3 / WebDAV",
        ["core/reverse_serve.py"],
        [
            (
                "tests/test_reverse_dav_overwrite_header.py::DavOverwriteHeaderTest::test_happy_move_to_a_free_name_with_overwrite_f",
                "backend",
            ),
            ("tests/test_reverse_serve_matrix.py::test_happy_mkcol_copy_move_delete", "backend"),
            ("tests/test_reverse_serve_matrix.py::test_happy_s3_put_get_list_delete", "backend"),
        ],
    ),
    _f(
        "Mount, serve, shell",
        "terminal",
        "Terminals and remote shells",
        [
            "ui/terminal_widget.py",
            "ui/terminal_pane.py",
            "core/vt_screen.py",
            "core/terminal_here.py",
            "core/exec_util.py",
        ],
        [
            (
                "tests/test_terminal_keys_reach_the_shell.py::test_happy_ctrl_letters_reach_the_shell_not_the_window",
                "ui",
            )
        ],
    ),
    # ------------------------------------------------- scripting, automation
    _f(
        "Scripting & automation",
        "scripting",
        "Scripting API, REPL, Scripts dock",
        [
            "core/scripting.py",
            "core/script_runner.py",
            "core/ui_helpers.py",
            "core/llm_guide.py",
            "ui/repl_widget.py",
            "ui/scripts_dock.py",
            "ui/script_editor.py",
            "ui/scripting_guide.py",
        ],
        [
            ("tests/test_scripts_dock_e2e.py::test_happy_create_edit_save_run_stop_delete", "ui"),
            (
                "tests/test_scripts_dock_e2e.py::test_happy_run_in_console_runs_in_the_live_namespace",
                "ui",
            ),
            ("tests/test_repl_console.py::test_happy_e2e_save_scripts_load_run_delete", "ui"),
        ],
    ),
    _f(
        "Scripting & automation",
        "bundled-scripts",
        "Bundled example scripts",
        ["resources/scripts/*.py"],
        [
            ("tests/test_scripting_examples.py::test_local_scripting_examples_run", "backend"),
            (
                "tests/test_scripting_examples.py::test_docker_scripting_examples_run_against_lab",
                "lab",
            ),
        ],
    ),
    _f(
        "Scripting & automation",
        "multi-system",
        "Multi-system verbs (inspect, federated search, dashboard, where-was-I, watch)",
        [
            "core/inspect.py",
            "core/multi_view.py",
            "core/search_federation.py",
            "core/dashboard.py",
            "core/visit_history.py",
            "core/net_helpers.py",
            "core/snmp_helpers.py",
            "core/watch.py",
        ],
        [
            ("tests/test_multi_system.py::MultiViewTests::test_compare_file_diverges", "backend"),
            (
                "tests/test_multi_system.py::SearchFederationTests::test_generic_walker_name_glob",
                "backend",
            ),
            (
                "tests/test_federated_search_backends.py::"
                "test_happy_e2e_imap_hits_are_message_files_not_numbers",
                "fake-server",
            ),
        ],
    ),
    _f(
        "Scripting & automation",
        "cred-attack",
        "Authorised credential testing",
        ["core/cred_attack.py"],
        [
            (
                "tests/test_cred_attack_live.py::test_bruteforce_finds_valid_credential_against_docker_lab",
                "lab",
            )
        ],
    ),
    _f(
        "Scripting & automation",
        "headless-cli",
        "Headless CLI (--script, start-up watchdog)",
        ["main.py", "core/startup_guard.py"],
        [
            (
                "tests/test_main_script_exit.py::ScriptExitTest::test_happy_an_exit_status_is_the_process_status",
                "process",
            ),
            (
                "tests/test_startup_watchdog_e2e.py::test_sad_e2e_a_hung_extension_is_reported_then_skipped_on_the_next_start",
                "process",
            ),
        ],
    ),
    # ------------------------------------------------------------- MCP, agent
    _f(
        "MCP & agent",
        "mcp-server",
        "MCP server (stdio / HTTP, capability groups)",
        ["core/mcp_server.py", "core/mcp_http.py", "core/mcp_groups.py"],
        [
            ("tests/test_mcp_groups_e2e.py::test_happy_stdio_server_serves_every_group", "process"),
            ("tests/test_mcp_groups_e2e.py::test_happy_http_server_serves_every_group", "process"),
        ],
    ),
    _f(
        "MCP & agent",
        "mcp-client-hub",
        "MCP client, catalog, hub, contained install",
        [
            "core/mcp_client.py",
            "core/mcp_catalog.py",
            "core/mcp_install.py",
            "core/mcp_detect.py",
            "core/mcp_discover.py",
            "core/mcp_runner.py",
            "core/mcp_egress.py",
            "ui/mcp_catalog_dialog.py",
        ],
        [
            (
                "tests/test_mcp_catalog_dialog.py::test_happy_e2e_a_third_party_server_says_axross_does_not_maintain_it",
                "ui",
            )
        ],
    ),
    _f(
        "MCP & agent",
        "agent",
        "Agent dock, sessions, topics, prompts",
        [
            "core/agent.py",
            "core/agent_session.py",
            "core/agent_topics.py",
            "core/agent_prompts.py",
            "core/agent_link.py",
            "core/agent_worker.py",
            "ui/agent_dock.py",
            "ui/agent_panels.py",
            "ui/agent_link_lamp.py",
            "ui/work_prompts_dialog.py",
        ],
        [
            (
                "tests/test_agent_tabs.py::test_happy_tabs_are_sessions_that_come_back_after_a_restart",
                "ui",
            ),
            (
                "tests/test_agent_detach.py::test_e2e_the_tab_menu_detaches_and_the_title_bar_attaches",
                "ui",
            ),
        ],
    ),
    _f(
        "MCP & agent",
        "agent-sandbox",
        "Agent sandbox and per-tab access",
        [
            "core/agent_sandbox.py",
            "core/agent_access.py",
            "core/agent_net.py",
            "ui/agent_access_dialog.py",
        ],
        [
            (
                "tests/test_agent_sandbox.py::test_edge_inside_bubblewrap_there_is_no_network_no_home_and_paranoid_is_read_only",
                "process",
            )
        ],
    ),
    _f(
        "MCP & agent",
        "agent-settings",
        "Agent settings and agent profiles",
        [
            "core/agent_settings.py",
            "core/agent_profiles.py",
            "ui/agent_settings_dialog.py",
            "ui/agent_profile_dialog.py",
        ],
        [("tests/test_agent_settings_dialog.py::test_edge_the_tools_menu_opens_it", "ui")],
    ),
    _f(
        "MCP & agent",
        "sift-analysis",
        "Analysis dock (sift) and LLM profiles",
        [
            "ui/analysis_dock.py",
            "core/analysis_worker.py",
            "core/file_analysis.py",
            "core/analysis_settings.py",
            "ui/analysis_settings_page.py",
            "core/llm_profiles.py",
            "ui/llm_settings_dialog.py",
        ],
        [
            (
                "tests/test_sift_identity.py::test_happy_e2e_real_sift_explains_the_file_from_the_right_click",
                "ui",
            )
        ],
    ),
    _f(
        "MCP & agent",
        "voice",
        "Voice: push-to-talk, speech output, audio settings",
        [
            "core/voice_audio.py",
            "core/voice_models.py",
            "core/voice_settings.py",
            "core/voice_stt.py",
            "core/voice_text.py",
            "core/voice_worker.py",
            "core/audio_route.py",
            "core/audio_settings.py",
            "ui/voice.py",
            "ui/voice_lens.py",
            "ui/voice_settings_page.py",
            "ui/audio_settings_page.py",
        ],
        [
            (
                "tests/test_agent_dock_voice.py::test_happy_push_to_talk_puts_the_text_into_the_task_field",
                "ui",
            ),
            (
                "tests/test_agent_dock_voice.py::test_happy_the_answer_is_read_aloud_and_shown_without_braces",
                "ui",
            ),
        ],
    ),
    # ------------------------------------------------------------------ system
    _f(
        "System",
        "extensions",
        "Extensions host, manager and small bundled extensions",
        [
            "core/extensions.py",
            "ui/extension_host.py",
            "ui/extension_panels.py",
            "ui/extensions_dialog.py",
            "resources/extensions/agent_stats.py",
            "resources/extensions/backup_repos.py",
            "resources/extensions/checksum_manifest.py",
            "resources/extensions/entropy_heatmap.py",
            "resources/extensions/image_batch.py",
            "resources/extensions/markdown_preview.py",
            "resources/extensions/virtualbox.py",
        ],
        [
            (
                "tests/test_extension_host.py::test_e2e_a_single_folder_action_shows_for_one_selected_folder_only",
                "ui",
            ),
            (
                "tests/test_backup_repos_extension.py::test_e2e_the_repository_dialog_opens_with_the_chains",
                "ui",
            ),
        ],
    ),
    _f(
        "System",
        "self-update",
        "Self-update",
        ["core/self_update.py", "ui/update_ui.py", "core/frozen_archive.py"],
        [("tests/test_self_update_ui.py::test_happy_e2e_notice_download_install_restart", "ui")],
    ),
    _f(
        "System",
        "proxy",
        "Proxy, PAC, TLS verification",
        [
            "core/proxy.py",
            "core/proxy_http.py",
            "core/pac.py",
            "core/proxy_settings.py",
            "ui/network_proxy_dialog.py",
            "core/tls_context.py",
            "core/tls_env.py",
        ],
        [
            (
                "tests/test_proxy_tunnel.py::LocalTunnelTest::test_bytes_flow_through_the_proxy_to_the_requested_target",
                "fake-server",
            )
        ],
    ),
    _f(
        "System",
        "security",
        "Security modes, production tarpit, redacted logs, log dock",
        [
            "core/security_mode.py",
            "core/safety_tarpit.py",
            "ui/production_gate.py",
            "core/redaction.py",
            "core/structured_log.py",
            "ui/log_dock.py",
        ],
        [
            (
                "tests/test_pane_production_gate.py::test_sad_a_cancelled_countdown_keeps_the_file_on_delete",
                "ui",
            ),
            (
                "tests/test_log_dock_batching.py::test_e2e_the_main_windows_log_dock_takes_a_burst_in_few_edits",
                "ui",
            ),
        ],
    ),
    _f(
        "System",
        "settings-appearance",
        "Settings dialog, themes, toolbar, icon colours, language, shortcuts",
        [
            "ui/settings_dialog.py",
            "ui/themes.py",
            "ui/icon_provider.py",
            "ui/toolbar_order.py",
            "ui/toolbar_categories.py",
            "core/i18n.py",
            "ui/shortcuts_dialog.py",
        ],
        [
            (
                "tests/test_settings_dialog.py::test_e2e_menu_navigate_change_ok_with_mouse_clicks",
                "ui",
            )
        ],
    ),
    _f(
        "System",
        "help",
        "Features and Third-Party Software",
        [
            "core/features.py",
            "ui/features_dialog.py",
            "core/third_party.py",
            "ui/third_party_dialog.py",
        ],
        [
            ("tests/test_features_overview.py::test_e2e_help_menu_opens_features", "ui"),
            (
                "tests/test_third_party_dialog.py::test_happy_e2e_from_the_help_menu_filter_and_click_a_link",
                "ui",
            ),
        ],
    ),
)

#: Modules that are no feature of their own, with the reason.
INFRASTRUCTURE: dict[str, str] = {
    "core/__init__.py": "package marker",
    "ui/__init__.py": "package marker",
    "resources/extensions/__init__.py": "package marker",
    "core/answer_fields.py": "typed reads of server JSON, used by the cloud backends",
    "core/append_helpers.py": "read-modify-write append shared by backends",
    "core/desktop_open.py": "hands files and links to the desktop",
    "core/posix_compat.py": "POSIX-only os calls made safe on other platforms",
    "core/process_launcher.py": "starts long-lived children from a long-lived thread",
    "core/qt_exit.py": "deletes Python-owned Qt objects before PyQt's exit clean-up",
    "core/session_lock.py": "one lock per protocol handle",
    "core/storage_identity.py": "which storage a path lives on (used by transfers, trash)",
    "core/subprocess_env.py": "the environment handed to child processes",
    "core/thread_lifetime.py": "lets a worker thread outlive its starter",
    "ui/thread_lifetime.py": "lets a worker QThread outlive its starter",
    "ui/close_corner.py": "the close corner every dialog gets",
    "ui/format_utils.py": "size and date formatting",
    "ui/layout_utils.py": "splitter helpers",
}

#: Where the measured modules live (the ``--cov`` roots of cov_scope.sh).
MODULE_GLOBS = ("core/*.py", "ui/*.py", "resources/extensions/*.py", "main.py")

SAD_WORDS = re.compile(
    r"(error|invalid|fail|refus|reject|missing|broken|unreadable|denied|corrupt|malformed|"
    r"hostile|wrong|not_found|raises|cannot|timeout|unknown|garbage|abort|blocked|forbid)",
    re.I,
)
EDGE_WORDS = re.compile(
    r"(empty|large|huge|unicode|zero|boundary|limit|max|nested|symlink|concurrent|cancel|race|"
    r"exactly|one_byte|utf|special|overflow|deep|many|duplicate|hidden|trailing)",
    re.I,
)


def classify(name: str) -> str:
    """happy, sad or edge for a test function name: the project's prefix
    convention first (``test_happy_`` / ``test_sad_`` / ``test_edge_``, also
    with ``e2e`` or ``live`` in between), keywords for older names."""
    words = name.lower().split("_")
    for kind in ("sad", "edge", "happy"):
        if kind in words[:4]:
            return kind
    if SAD_WORDS.search(name):
        return "sad"
    if EDGE_WORDS.search(name):
        return "edge"
    return "happy"


def expand(modules, root: Path = ROOT) -> list[str]:
    out: list[str] = []
    for m in modules:
        hits = sorted(str(Path(p).relative_to(root)) for p in glob.glob(str(root / m)))
        out.extend(h for h in hits if not h.endswith("__init__.py") or h == m)
    return out


def all_modules(root: Path = ROOT) -> list[str]:
    return expand(MODULE_GLOBS, root)


_DOTTED = re.compile(r"\b(core|ui)\.([A-Za-z_]\w*)")
_FROM_IMPORT = re.compile(r"\bfrom (core|ui) import (\([^)]*\)|[^\n]+)")


def import_patterns(module: str) -> list[re.Pattern]:
    """How a test file names a module it uses."""
    if module == "main.py":
        return [
            re.compile(r"^\s*(import main\b|from main import)", re.M),
            re.compile(r"[\"'/]main\.py\b"),
        ]
    stem = Path(module).stem
    if module.startswith("resources/scripts/"):
        return [re.compile(rf"\b{stem}\.py\b"), re.compile(r"resources[/.]scripts\b")]
    if module.startswith("resources/extensions/"):
        return [re.compile(rf"extensions[./]{stem}\b"), re.compile(rf"\b{stem}\.py\b")]
    pkg = module.split("/")[0]
    return [
        re.compile(rf"\b{pkg}\.{stem}\b"),
        re.compile(rf"from {pkg} import [^\n(]*\b{stem}\b"),
        re.compile(rf"from {pkg} import \([^)]*\b{stem}\b"),  # a parenthesized import
    ]


def nodes_of(path: Path) -> list[str]:
    """Node ids (``Class::name`` or ``name``) of the test functions in a file."""
    return list(node_sources(path))


def node_sources(path: Path) -> dict[str, str]:
    """Node id -> the source a test runs from: the function, and for a
    method also its class's set-up methods."""
    text = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(text)
    lines = text.splitlines()

    def seg(node) -> str:
        return "\n".join(lines[node.lineno - 1 : node.end_lineno])

    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            out[node.name] = seg(node)
        elif isinstance(node, ast.ClassDef):
            setup = "\n".join(
                seg(m)
                for m in node.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                and m.name in ("setUp", "setUpClass", "asyncSetUp", "setup_method")
            )
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith(
                    "test_"
                ):
                    out[f"{node.name}::{m.name}"] = (seg(m)) + setup
    return out


def module_symbols(module: str, root: Path = ROOT) -> set[str]:
    """Names a test that exercises *module* mentions: its stem and its public
    top-level classes and functions of at least six characters."""
    path = root / module
    names = {path.stem} if path.stem != "main" else {"main.py"}
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return names
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_") and len(node.name) >= 6:
                names.add(node.name)
    return names


#: A test file that imports more core/ui modules than this is a catch-all
#: (the hardening regression file imports 147): only its tests that
#: name one of the feature's modules or symbols count for the feature.
CATCH_ALL_IMPORTS = 20


class SuiteIndex:
    def __init__(self, root: Path = ROOT) -> None:
        self.root = root
        self.files = sorted(str(p.relative_to(root)) for p in (root / "tests").glob("test_*.py"))
        self.text = {
            f: (root / f).read_text(encoding="utf-8", errors="replace") for f in self.files
        }
        self._nodes: dict[str, dict[str, str]] = {}
        self._used: dict[str, set[str]] = {}

    def nodes(self, f: str) -> list[str]:
        return list(self.sources(f))

    def sources(self, f: str) -> dict[str, str]:
        if f not in self._nodes:
            self._nodes[f] = node_sources(self.root / f)
        return self._nodes[f]

    def used_packages_modules(self, f: str) -> set[str]:
        """``core/x.py`` / ``ui/x.py`` for every core or ui module a test
        file names (``core.x``, ``from core import x`` - also in parentheses)."""
        if f not in self._used:
            text = self.text[f]
            used = {f"{pkg}/{mod}.py" for pkg, mod in _DOTTED.findall(text)}
            for pkg, names in _FROM_IMPORT.findall(text):
                for name in re.split(r"[\s,()]+", names):
                    name = name.split(" as ")[0].strip()
                    if name.isidentifier():
                        used.add(f"{pkg}/{name}.py")
            self._used[f] = used
        return self._used[f]

    def importers(self, modules) -> list[str]:
        pkg_mods = {m for m in modules if m.split("/")[0] in ("core", "ui")}
        pats = {p.pattern for m in modules if m not in pkg_mods for p in import_patterns(m)}
        other = re.compile("|".join(f"(?:{p})" for p in sorted(pats)), re.M) if pats else None
        return [
            f
            for f in self.files
            if pkg_mods & self.used_packages_modules(f) or (other and other.search(self.text[f]))
        ]

    def node_exists(self, nodeid: str) -> bool:
        f, _, rest = nodeid.partition("::")
        if f not in self.text:
            return False
        # a parametrized id names its function without the [...] part
        return rest.split("[")[0] in self.nodes(f)


def check(root: Path = ROOT) -> list[str]:
    """Every problem that makes the table stale; empty when it is current."""
    problems: list[str] = []
    tree = SuiteIndex(root)
    keys = [f.key for f in FEATURES]
    for k in sorted({k for k in keys if keys.count(k) > 1}):
        problems.append(f"feature key {k} is used twice")
    mapped: dict[str, str] = {}
    for feat in FEATURES:
        for m in feat.modules:
            if not expand([m], root):
                problems.append(f"{feat.key}: module {m} does not exist")
        for m in expand(feat.modules, root):
            if m in mapped:
                problems.append(f"{m} is in {mapped[m]} and {feat.key}")
            mapped[m] = feat.key
        for nodeid, kind in feat.e2e:
            if kind not in E2E_KINDS:
                problems.append(f"{feat.key}: {nodeid} has an unknown kind {kind}")
            if not tree.node_exists(nodeid):
                problems.append(f"{feat.key}: e2e test {nodeid} does not exist")
    for m in all_modules(root):
        if m not in mapped and m not in INFRASTRUCTURE:
            problems.append(f"{m} belongs to no feature and is not named in INFRASTRUCTURE")
    for m in INFRASTRUCTURE:
        if not (root / m).exists():
            problems.append(f"INFRASTRUCTURE names {m}, which does not exist")
        if m in mapped:
            problems.append(f"{m} is in INFRASTRUCTURE and in {mapped[m]}")
    return problems


# ------------------------------------------------------------------ coverage
def load_summary(data_file: Path, root: Path = ROOT) -> dict[str, dict]:
    """Per-module summary (statements, branches, covered) of a coverage data
    file, keyed by the module's path relative to the tree."""
    import coverage

    cwd = os.getcwd()
    os.chdir(root)
    try:
        cov = coverage.Coverage(
            data_file=str(data_file),
            branch=True,
            source=["core", "ui", "resources", "main"],
            config_file=False,
        )
        cov.load()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cov.json"
            cov.json_report(outfile=str(out), ignore_errors=True)
            report = json.loads(out.read_text())
    finally:
        os.chdir(cwd)
    summary: dict[str, dict] = {}
    for name, data in report["files"].items():
        rel = _tree_relative(name, root)
        if rel is not None:
            summary[rel] = data["summary"]
    # A module no test imported is not in the data at all: count it as
    # nothing covered, with its statements and branches from its source.
    wanted = set(all_modules(root)) | {m for f in FEATURES for m in expand(f.modules, root)}
    for module in sorted(wanted - set(summary)):
        summary[module] = _unexecuted_summary(cov, root / module)
    return summary


def _unexecuted_summary(cov, path: Path) -> dict:
    from coverage.python import PythonFileReporter

    reporter = PythonFileReporter(str(path), cov)
    statements = reporter.lines()
    branches = sum(n for n in reporter.exit_counts().values() if n > 1)
    return {
        "num_statements": len(statements),
        "covered_lines": 0,
        "missing_lines": len(statements),
        "num_branches": branches,
        "covered_branches": 0,
        "percent_covered": 0.0,
    }


def _tree_relative(name: str, root: Path) -> str | None:
    """*name* (as the coverage report gives it) relative to the tree, or
    None for a file outside the measured roots. Compared by real path, so a
    tree reached through a symlink still matches."""
    real = os.path.realpath(name if os.path.isabs(name) else os.path.join(root, name))
    for top in ("core", "ui", "resources", "scripts"):
        base = os.path.realpath(root / top) + os.sep
        if real.startswith(base):
            return f"{top}/{real[len(base) :]}".replace(os.sep, "/")
    if real == os.path.realpath(root / "main.py"):
        return "main.py"
    return None


@dataclass
class Numbers:
    statements: int = 0
    covered_lines: int = 0
    branches: int = 0
    covered_branches: int = 0

    def add(self, s: dict | None) -> None:
        if not s:
            return
        self.statements += s.get("num_statements", 0)
        self.covered_lines += s.get("covered_lines", 0)
        self.branches += s.get("num_branches", 0)
        self.covered_branches += s.get("covered_branches", 0)

    @property
    def line_pct(self) -> float:
        return 100.0 * self.covered_lines / self.statements if self.statements else 100.0

    @property
    def branch_pct(self) -> float:
        return 100.0 * self.covered_branches / self.branches if self.branches else 100.0

    @property
    def missing_branches(self) -> int:
        return self.branches - self.covered_branches


def _pct(v: float) -> str:
    return f"{v:.1f} %"


def feature_counts(
    tree: SuiteIndex, files: list[str], mods: list[str], root: Path = ROOT
) -> dict[str, int]:
    """happy / sad / edge test functions for a feature (see CATCH_ALL_IMPORTS)."""
    symbols = set().union(*(module_symbols(m, root) for m in mods)) if mods else set()
    named = (
        re.compile("|".join(rf"\b{re.escape(n)}\b" for n in sorted(symbols))) if symbols else None
    )
    counts = {"happy": 0, "sad": 0, "edge": 0}
    for f in files:
        catch_all = len(tree.used_packages_modules(f)) > CATCH_ALL_IMPORTS
        for nodeid, src in tree.sources(f).items():
            if catch_all and not (named and named.search(src)):
                continue
            counts[classify(nodeid.split("::")[-1])] += 1
    return counts


def build_rows(summary: dict[str, dict], tree: SuiteIndex, root: Path = ROOT) -> list[dict]:
    rows = []
    for feat in FEATURES:
        mods = expand(feat.modules, root)
        num = Numbers()
        for m in mods:
            num.add(summary.get(m))
        files = tree.importers(mods)
        counts = feature_counts(tree, files, mods, root)
        rows.append(
            {"feature": feat, "modules": mods, "num": num, "files": files, "counts": counts}
        )
    return rows


def render(
    rows: list[dict],
    summary: dict[str, dict],
    *,
    date: str,
    command: str,
    failed: list[str],
    notes: list[str] = (),
    root: Path = ROOT,
) -> str:
    total = Numbers()
    for m in all_modules(root):
        total.add(summary.get(m))
    with_e2e = [r for r in rows if r["feature"].e2e]
    host_e2e = [r for r in rows if any(k != "lab" for _, k in r["feature"].e2e)]
    all_three = [r for r in rows if all(r["counts"][k] for k in ("happy", "sad", "edge"))]
    out: list[str] = []
    w = out.append
    w("# Test Coverage Matrix")
    w("")
    w(f"Measured on {date}. Generated by `scripts/coverage_matrix.py` - do not edit by hand;")
    w("refresh it with the commands under *How to refresh*.")
    w("")
    w("## Summary")
    w("")
    w(f"- Main features: **{len(rows)}** (in {len({r['feature'].group for r in rows})} groups)")
    w(
        f"- Features with at least one end-to-end test: **{len(with_e2e)}**; "
        f"with one that runs on the host (not only in the lab): **{len(host_e2e)}**"
    )
    w(f"- Features whose tests include happy, sad and edge cases: **{len(all_three)}**")
    w(
        f"- Measured code (`core/`, `ui/`, `resources/extensions/`, `main.py`): "
        f"{total.statements} statements, line coverage **{_pct(total.line_pct)}**, "
        f"{total.branches} branches, branch coverage **{_pct(total.branch_pct)}**"
    )
    w("")
    w("Command that produced the coverage data:")
    w("")
    w("```")
    w(command)
    w("```")
    w("")
    if failed:
        w("Test files that failed in that run (their coverage still counts up to the failure):")
        w("")
        for f in failed:
            w(f"- `{f}`")
        w("")
    for note in notes:
        w(note)
        w("")
    w(
        "What the numbers do not include: tests that need the podman lab "
        "(`tests/docker`), live LLM servers or extra hardware skip themselves in a host run, "
        "so the backend families are measured by their host tests only (scripted servers, "
        "mocks). The e2e column still names a lab test where one exists (kind `lab`). Code "
        "that runs in a child process (the agent worker in its sandbox, a script run by the "
        "Scripts dock or the scheduler) is not measured, and `models/` and `security/` are "
        "outside the measured roots."
    )
    w("")
    w("## Features")
    w("")
    w(
        "Lines / branches: coverage of the feature's main modules together. Tests: test files "
        "that import one of them, and their test functions as happy / sad / edge (naming "
        "convention). E2E: hand-picked end-to-end tests, by kind:"
    )
    w("")
    for kind, text in E2E_KINDS.items():
        w(f"- `{kind}`: {text}")
    w("")
    group = None
    for r in rows:
        feat = r["feature"]
        if feat.group != group:
            group = feat.group
            w(f"### {group}")
            w("")
            w("| Feature | Modules | Lines | Branches | Test files | happy / sad / edge | E2E |")
            w("|---|---:|---:|---:|---:|---|---|")
        c = r["counts"]
        kinds = sorted({k for _, k in feat.e2e})
        e2e = ", ".join(f"`{k}`" for k in kinds) if kinds else "**none**"
        w(
            f"| {feat.name} (`{feat.key}`) | {len(r['modules'])} | {_pct(r['num'].line_pct)} | "
            f"{_pct(r['num'].branch_pct)} | {len(r['files'])} | "
            f"{c['happy']} / {c['sad']} / {c['edge']} | {e2e} |"
        )
        nxt = rows.index(r) + 1
        if nxt == len(rows) or rows[nxt]["feature"].group != group:
            w("")
    w("## End-to-end tests per feature")
    w("")
    for r in rows:
        feat = r["feature"]
        if not feat.e2e:
            w(f"- `{feat.key}`: **none**")
            continue
        w(f"- `{feat.key}`:")
        for nodeid, kind in feat.e2e:
            w(f"  - `{nodeid}` ({kind})")
    w("")
    w("## Gaps: main modules under 60 % branch coverage")
    w("")
    w("Sorted by uncovered branches - the order in which closing them helps most.")
    w("")
    w("| Module | Feature | Statements | Lines | Branches | Uncovered branches |")
    w("|---|---|---:|---:|---:|---:|")
    gaps = []
    for r in rows:
        for m in r["modules"]:
            n = Numbers()
            n.add(summary.get(m))
            if n.branches and n.branch_pct < 60.0:
                gaps.append((n.missing_branches, m, r["feature"].key, n))
    for _, m, key, n in sorted(gaps, reverse=True):
        w(
            f"| `{m}` | `{key}` | {n.statements} | {_pct(n.line_pct)} | "
            f"{_pct(n.branch_pct)} | {n.missing_branches} |"
        )
    w("")
    w("## Every module")
    w("")
    w("| Module | Feature | Statements | Lines | Branches |")
    w("|---|---|---:|---:|---:|")
    for r in rows:
        for m in r["modules"]:
            n = Numbers()
            n.add(summary.get(m))
            w(
                f"| `{m}` | `{r['feature'].key}` | {n.statements} | "
                f"{_pct(n.line_pct)} | {_pct(n.branch_pct)} |"
            )
    for m, why in INFRASTRUCTURE.items():
        n = Numbers()
        n.add(summary.get(m))
        w(
            f"| `{m}` | infrastructure: {why} | {n.statements} | "
            f"{_pct(n.line_pct)} | {_pct(n.branch_pct)} |"
        )
    w("")
    w("## How to refresh")
    w("")
    w("1. Run every test file with branch coverage, one data file per test file:")
    w(
        "   `cov_scope.sh <tree> <outdir> <list of tests/test_*.py>` (it writes "
        "`<outdir>/cov/.coverage.<file>` and `<outdir>/rc.txt`)."
    )
    w("2. `coverage combine --keep --data-file=<outdir>/combined <outdir>/cov/.coverage.*`")
    w(
        "3. `python scripts/coverage_matrix.py --data <outdir>/combined --rc <outdir>/rc.txt "
        '--command "..." --out docs/TEST_COVERAGE_MATRIX.md`'
    )
    w(
        "4. `python scripts/coverage_matrix.py --check` (also run by "
        "`tests/test_coverage_matrix_script.py`) fails when a feature names a module or an e2e "
        "test that no longer exists, or a new module belongs to no feature."
    )
    w("")
    return "\n".join(out)


def failed_files(rc_txt: Path) -> list[str]:
    out = []
    for line in rc_txt.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[0] != "0":
            out.append(parts[2])
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", type=Path, help="combined coverage data file")
    ap.add_argument("--command", default="(not given)", help="command that produced the data")
    ap.add_argument("--date", default=_dt.date.today().isoformat())
    ap.add_argument("--rc", type=Path, help="rc.txt of the run: failed test files are listed")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "TEST_COVERAGE_MATRIX.md")
    ap.add_argument("--note", action="append", default=[], help="a paragraph about the run")
    ap.add_argument("--check", action="store_true", help="only check the feature map")
    args = ap.parse_args(argv)
    problems = check()
    if problems:
        for p in problems:
            print(f"coverage_matrix: {p}", file=sys.stderr)
        return 1
    if args.check:
        print(f"coverage_matrix: {len(FEATURES)} features, map is current")
        return 0
    if not args.data:
        ap.error("--data is required unless --check is given")
    if not args.data.exists():
        print(f"coverage_matrix: no coverage data at {args.data}", file=sys.stderr)
        return 2
    summary = load_summary(args.data)
    rows = build_rows(summary, SuiteIndex())
    failed = failed_files(args.rc) if args.rc else []
    args.out.write_text(
        render(rows, summary, date=args.date, command=args.command, failed=failed, notes=args.note),
        encoding="utf-8",
    )
    print(f"coverage_matrix: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
