"""The MCP tools' public names: verb first, then the resource.

tools/list shows these names; tools/call accepts them and, as hidden
aliases, the names the tools had up to 0.15.182, which stay their
internal names (_Tool.name: the hint, timeout and schema tables, the agent's
confirmation rules and the tests key on them). Former tools that were
merged into another one (MERGED) still answer to their names, with their
arguments translated. Audit lines carry the public name. No imports:
core.mcp_server, core.mcp_groups and core.agent load this at import time.

Verbs: list (several entries), get (one entry's details), read, write,
search, walk, compute, create, delete, move, copy, set, run, scan, trash,
export, strip, extract, encrypt, decrypt, build, identify, open, close,
render, restore; for devices (the adb group) start, stop, install,
uninstall, grant, revoke, reboot, take, compose, send. The resource is the thing the verb acts on, singular for one
(read_file), plural for a listing (list_scripts): file (one file),
directory (one folder), tree (a folder and everything below it), path
(a file or a folder).
"""

from __future__ import annotations

#: internal (former) name -> public name.
PUBLIC_NAMES: dict[str, str] = {
    # core file tools
    "list_dir": "list_directory",
    "stat": "get_path_info",
    "read_file": "read_file",
    "checksum": "compute_file_checksum",
    "search": "search_index",
    "walk": "walk_tree",
    "recursive_checksum": "compute_tree_checksums",
    "preview": "render_preview",
    "grep": "search_content",
    "list_versions": "list_file_versions",
    "open_version_read": "read_file_version",
    "restore_version": "restore_file_version",
    "list_backends": "list_backends",
    # write tools
    "write_file": "write_file",
    "mkdir": "create_directory",
    "remove": "delete_path",
    "rename": "move_path",
    "copy": "copy_file",
    "bulk_copy": "copy_tree",
    "symlink": "create_link",
    "chmod": "set_permissions",
    # saved scripts
    "script_list": "list_scripts",
    "script_api_schema": "get_script_api",
    "script_read": "read_script",
    "script_write": "write_script",
    "script_delete": "delete_script",
    "script_run": "run_script",
    # groups
    "metadata_read": "read_metadata",
    "metadata_export": "export_metadata",
    "metadata_remove": "strip_metadata",
    "duplicates_scan": "scan_duplicates",
    "duplicates_scans": "list_duplicate_scans",
    "duplicates_groups": "list_duplicate_groups",
    "duplicates_dedupe": "trash_duplicates",
    "trash_list": "list_trash",
    "trash_restore": "restore_from_trash",
    "pack_formats": "list_archive_formats",
    "pack": "create_archive",
    "archive_list": "list_archive_members",
    "archive_extract": "extract_archive",
    "encrypt": "encrypt_file",
    "decrypt": "decrypt_file",
    "index_build": "build_index",
    "file_type": "identify_file_type",
    "file_type_scan": "scan_file_types",
    "transfer_copy": "copy_path_to_backend",
    "transfer_move": "move_file_to_backend",
    "remote_profiles": "list_remote_profiles",
    "remote_open": "open_remote_profile",
    "remote_close": "close_remote_profile",
    "remote_exec": "run_backend_command",
    "agent_run": "run_llm_agent",
    "llm_profiles": "list_llm_profiles",
    "extensions_list": "list_extensions",
    # adb (0.15.184): named verb_resource from the start, no former names
    **{name: name for name in (
        "get_device_info", "list_device_properties", "get_battery_status", "list_apps",
        "get_app_info", "list_running_apps", "get_logcat", "take_screenshot", "list_sms",
        "start_app", "stop_app", "install_app", "uninstall_app", "export_app",
        "grant_permission", "revoke_permission", "reboot_device", "write_sms", "compose_sms",
        "send_at_command")},
}
#: A former tool merged into another one (0.15.183, 0.15.184): its name -> (the
#: internal name of the tool that does its job now, arguments to set,
#: arguments renamed {old: new}).
MERGED: dict[str, tuple[str, dict, dict]] = {
    "metadata_export_file": ("metadata_export", {}, {}),
    "exec_backends": ("list_backends", {"can_run_commands": True}, {}),
    "extensions_info": ("extensions_list", {}, {"ext_id": "name"}),
    # 0.15.184: one link tool, one remote command tool
    "create_symlink": ("symlink", {"kind": "symbolic"}, {}),
    "hardlink": ("symlink", {"kind": "hard"}, {}),
    "create_hardlink": ("symlink", {"kind": "hard"}, {}),
    "remote_script": ("remote_exec", {}, {}),
    "run_backend_script": ("remote_exec", {}, {}),
}
#: Former --mcp-tools group names -> the group that holds their tools now
#: (also in run_llm_agent's groups argument).
GROUP_ALIASES: dict[str, str] = {"packer": "archive"}
#: Parameters renamed in 0.15.183, so one name means one thing across the
#: tools (max_<what> caps a result, timeout is seconds, pattern is what a
#: search looks for, path is what a tool works on, max_depth always counts
#: levels from 1): internal tool name -> {former argument: argument}. A
#: call with the former key works; the schema shows the new one only.
ARG_ALIASES: dict[str, dict[str, str]] = {
    "search": {"needle": "pattern", "limit": "max_results"},
    "script_run": {"timeout_s": "timeout"},
    "file_type_scan": {"max_depth": "subfolder_levels"},
    "transfer_copy": {"max_depth": "subfolder_levels"},
    "pack": {"folder": "path", "folder_b64": "path_b64"},
    # 0.15.184: profile meant a connection profile everywhere else
    "agent_run": {"profile": "llm_profile"},
}
#: public name -> internal name (also every internal name to itself).
INTERNAL_NAMES: dict[str, str] = {
    **{old: old for old in PUBLIC_NAMES}, **{new: old for old, new in PUBLIC_NAMES.items()},
    **{old: new for old, (new, _set, _renamed) in MERGED.items()}}
#: The verbs a public name may start with.
VERBS = frozenset({
    "list", "get", "read", "write", "search", "walk", "compute", "render", "create",
    "delete", "move", "copy", "set", "run", "scan", "trash", "export", "strip", "extract",
    "encrypt", "decrypt", "build", "identify", "open", "close", "restore",
    "compose", "start", "stop", "install", "uninstall", "grant", "revoke", "reboot", "take", "send",
})


def public(name: str) -> str:
    """The public name of the tool *name* (internal or public)."""
    return PUBLIC_NAMES.get(INTERNAL_NAMES.get(name, name), name)


def internal(name: str) -> str:
    """The internal name a tools/call *name* (public or former) means."""
    return INTERNAL_NAMES.get(name, name)


def rename_args(name: str, args):
    """*args* of a call of the tool *name* (internal or public) with every
    former argument key renamed (a new dict; a key given under both names
    keeps the new one, and the former one is dropped)."""
    renamed = ARG_ALIASES.get(internal(name))
    if not renamed or not isinstance(args, dict) or not set(renamed) & set(args):
        return args
    out = {key: value for key, value in args.items() if key not in renamed}
    for old, new in renamed.items():
        if old in args and new not in out:
            out[new] = args[old]
    return out


def resolve(name, args):
    """``(internal name, arguments)`` of a tools/call of *name* with *args*:
    a merged former tool's arguments translated for the tool that took it
    over (a new dict; *args* itself is never changed)."""
    if not isinstance(name, str):
        return name, args
    merged = MERGED.get(name)
    if merged is None:
        meant = internal(name)
        groups = args.get("groups") if isinstance(args, dict) else None
        if (meant == "agent_run" and isinstance(groups, list)
                and all(isinstance(g, str) for g in groups)
                and any(g in GROUP_ALIASES for g in groups)):
            renamed = [GROUP_ALIASES.get(g, g) for g in groups]
            args = {**args, "groups": list(dict.fromkeys(renamed))}
        return meant, rename_args(meant, args)
    target, preset, renamed = merged
    if not isinstance(args, dict):
        return target, args
    moved = {renamed.get(key, key): value for key, value in args.items()}
    return target, rename_args(target, {**moved, **preset})
