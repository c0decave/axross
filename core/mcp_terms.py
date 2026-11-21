"""The words the MCP tool definitions share (core.mcp_server, core.mcp_groups).

The shared rules - paths, the backend argument, the ``*_b64`` twins, secret
files, the write guards, the paranoid mode, the two max_depth counts - are
stated once, in the server's initialize instructions (RULES). A tool names
the rule that applies to it with a short tag (SECRET_TAG, WRITE_TAG ...),
always in these words, and never repeats the definition:
tests/test_mcp_tool_quality.py holds the descriptions to that. Tools are
named by their public names (core.mcp_names, which imports nothing); both
tool modules load this one at import time.
"""

from __future__ import annotations

from core import mcp_names as _N

SECRET_TAG = "Refuses secret files."
WRITE_TAG = "Write guards apply."
PARANOID_TAG = "off in paranoid mode"
CLASS_TEXT = "class (the backend's implementation, e.g. 'SSHSession')"

#: The definitions, once (SERVER_INSTRUCTIONS).
SECRET_RULE = (
    "Secret files (SSH and GnuPG private keys, axross's tokens; on remote hosts also .env "
    "and credentials files) are refused unless the server runs with "
    "--mcp-allow-secret-reads."
)
WRITE_RULE = (
    "Write guards: writes stay inside a writable MCP root and outside protected places "
    "(shell and session start files, autostart, user services, SSH and GnuPG folders, "
    "axross settings); production-flagged profiles are read-only."
)
PARANOID_RULE = (
    "Paranoid mode (AXROSS_SECURITY_MODE=paranoid or the app setting) turns off scripts, "
    "extensions, remote commands, ffmpeg/ffprobe and legacy protocols."
)
PATH_RULE = (
    "Paths are absolute or relative to the MCP root; local paths stay inside the root, a "
    "remote backend takes that host's paths. Tools take backend only when there is more "
    "than one; its ids come from list_backends, served then ('profile:<name>' after "
    "open_remote_profile); omitted, the default backend. A <name>_b64 "
    "argument carries the raw bytes of a non-UTF-8 name in base64, as listings return it "
    "(name_b64), and replaces <name>; the server, not the schema, requires one of the two "
    "(clients refuse a top-level oneOf)."
)
DEPTH_RULE = (
    "max_depth counts levels from 1 in every tool (1 = path's own entries); subfolder_levels "
    "counts subfolders from 0 (0 = path's own files)."
)
IDEMPOTENT_RULE = (
    "idempotentHint true: a repeat changes nothing more; where a repeat fails, the "
    "description names the error."
)
NAME_RULE = (
    "Names are verb_resource; the resource says what a tool takes or makes: file, "
    "directory (one folder), tree (a folder and all below it), path (a file or a folder). "
    "Former names (up to 0.15.182) still work."
)
PARAM_RULE = (
    "One parameter name, one meaning: path is what a tool works on, max_<what> caps a "
    "result, offset pages, timeout is seconds, pattern is what a search looks for. Former "
    "names (needle, limit, timeout_s, folder, a 0-based max_depth) still work."
)
FLAG_RULE = (
    "Tools and arguments that change files (export_metadata's out) need --mcp-write; the "
    "script tools --mcp-allow-scripts, the remote command tools --mcp-allow-exec - neither "
    "in paranoid mode, the script tools only over stdio; each optional group its "
    "--mcp-tools name; a read-only tool that points at a write tool says '(needs "
    "--mcp-write)'. "
    + _N.public("remove") + " deletes for good; only " + _N.public("duplicates_dedupe")
    + " moves files to axross's restorable trash."
)
LIMIT_RULE = (
    "truncated: a limit (max_*, max_depth or subfolder_levels leaving a folder unentered) "
    "cut the result; the tree tools have no cursor (narrow path or raise the limit), "
    "search_index and list_duplicate_groups page with offset. Tree walks also carry complete, false when anything was cut or left unread. A "
    "folder or file they could not read is in unreadable ({path, error} in walk_tree and "
    "search_content; paths in scan_file_types (folders, secret files), folder paths in "
    "scan_duplicates and build_index), or an error "
    "entry (compute_tree_checksums, copy_tree, copy_path_to_backend)."
)
TIME_RULE = (
    "A call past its time limit fails with a timeout error (JSON-RPC -32002) and returns "
    "nothing; work it started may still finish. run_script, run_backend_command and "
    "run_backend_script stop at their own timeout argument instead. Long tools send "
    "progress notifications and stop on notifications/cancelled."
)
ERROR_RULE = (
    "Errors: a tool that fails answers isError true, the message as text ('tool <name> "
    "failed: ...') and _meta.type the error's kind (FileNotFoundError, PermissionError ...), "
    "without structuredContent; an unknown tool is a JSON-RPC error, and so are refused "
    "arguments before protocol 2025-11-25."
)
#: What each group gives agent_run's model: its tools that need no
#: --mcp-write (tests/test_mcp_tool_quality.py holds it to the real groups).
AGENT_CORE_TOOLS = ("list_dir", "stat", "read_file", "checksum", "search", "walk",
                    "recursive_checksum", "preview", "grep", "list_versions",
                    "open_version_read")
AGENT_GROUP_TOOLS = {
    "metadata": ("metadata_read", "metadata_export"),
    "duplicates": ("duplicates_scan", "duplicates_scans", "duplicates_groups"),
    "archive": ("pack_formats", "archive_list"),
    "index": ("index_build",),
    "filetype": ("file_type", "file_type_scan"),
    "remote": ("remote_profiles", "remote_open", "remote_close"),
    "extensions": ("extensions_list",),
}
AGENT_RULE = (
    "run_llm_agent's model gets the core file tools ("
    + ", ".join(_N.public(n) for n in AGENT_CORE_TOOLS) + ") and, per group asked for: "
    + "; ".join(f"{g} {', '.join(_N.public(n) for n in names)}"
                for g, names in AGENT_GROUP_TOOLS.items())
    + "; remote adds list_backends."
)
#: The instructions' sections, each a heading and its rules (one line each).
SECTIONS = (
    ("Names and parameters", (NAME_RULE, PARAM_RULE, DEPTH_RULE)),
    ("Paths and backends", (PATH_RULE,)),
    ("Flags and safety", (FLAG_RULE, SECRET_RULE, WRITE_RULE, PARANOID_RULE)),
    ("Results and errors", (LIMIT_RULE, TIME_RULE, ERROR_RULE, IDEMPOTENT_RULE)),
    ("run_llm_agent", (AGENT_RULE,)),
)
RULES = tuple(rule for _heading, rules in SECTIONS for rule in rules)

#: A repeat with no further effect (MCP idempotentHint), in one wording.
IDEMPOTENT = "Idempotent: a repeat changes nothing more"


def levels_text(start: str = "path") -> str:
    """max_depth of walk, grep, recursive_checksum and bulk_copy."""
    return f"Levels to visit, counted from 1: 1 = {start}'s own entries."


def descend_text(start: str = "path") -> str:
    """max_depth of file_type_scan and transfer_copy."""
    return (f"Subfolder levels, counted from 0: 0 = {start}'s own files, 1 = also its "
            "subfolders'.")
