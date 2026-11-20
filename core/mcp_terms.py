"""The words the MCP tool definitions share (core.mcp_server, core.mcp_groups).

The shared rules - paths, the backend argument, the ``*_b64`` twins, secret
files, the write guards, the paranoid mode, the two max_depth counts - are
stated once, in the server's initialize instructions (RULES). A tool names
the rule that applies to it with a short tag (SECRET_TAG, WRITE_TAG ...),
always in these words, and never repeats the definition:
tests/test_mcp_tool_quality.py holds the descriptions to that. No imports:
both tool modules load this one at import time.
"""

from __future__ import annotations

SECRET_TAG = "Refuses secret files."
WRITE_TAG = "Write guards apply."
PARANOID_TAG = "off in paranoid mode"
CLASS_TEXT = "class (the backend's implementation, e.g. 'SSHSession')"

#: The definitions, once (SERVER_INSTRUCTIONS).
SECRET_RULE = (
    "Secret files (SSH and GnuPG private keys, axross's tokens; on remote hosts also .env "
    "and credentials files) are refused, unless the server was started with "
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
    "remote_open); omitted, the default backend. A <name>_b64 "
    "argument carries the raw bytes of a non-UTF-8 name in base64, as listings return it "
    "(name_b64), and replaces <name>."
)
DEPTH_RULE = (
    "max_depth: walk, grep, recursive_checksum and bulk_copy count levels from 1 (1 = "
    "path's own entries); file_type_scan and transfer_copy count subfolder levels from 0 "
    "(0 = path's own files)."
)
IDEMPOTENT_RULE = (
    "An idempotent tool changes nothing more when repeated; the description names the "
    "error a repeat may give."
)
FLAG_RULE = (
    "Tools that write files need --mcp-write (they say so); the script tools "
    "--mcp-allow-scripts, the remote command tools --mcp-allow-exec; each optional group "
    "its --mcp-tools name. remove deletes for good; only duplicates_dedupe moves files "
    "to axross's restorable trash."
)
LIMIT_RULE = (
    "truncated: a limit (max_*, or max_depth leaving a folder unentered) cut the result; "
    "tree walks also carry complete, false when anything was cut or left unread, and "
    "unreadable ({path, error} in walk and grep, folder paths elsewhere). A call "
    "past its time limit fails with a timeout error and returns nothing; work it started "
    "may still finish."
)
RULES = (PATH_RULE, FLAG_RULE, SECRET_RULE, WRITE_RULE, PARANOID_RULE, DEPTH_RULE,
         LIMIT_RULE, IDEMPOTENT_RULE)

#: A repeat with no further effect (MCP idempotentHint), in one wording.
IDEMPOTENT = "Idempotent: a repeat changes nothing more"


def levels_text(start: str = "path") -> str:
    """max_depth of walk, grep, recursive_checksum and bulk_copy."""
    return f"Levels to visit, counted from 1: 1 = {start}'s own entries."


def descend_text(start: str = "path") -> str:
    """max_depth of file_type_scan and transfer_copy."""
    return (f"Counted from 0 (walk-style tools count from 1): 0 = {start}'s own files, "
            "1 = also its subfolders'.")
