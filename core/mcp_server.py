"""Phase 6b — Minimal MCP server exposing axross backends to LLMs.

The MCP (Model Context Protocol) is a JSON-RPC 2.0 dialect for an
LLM client to discover and call tools on a server. This module
implements a stdio-framed MCP server: requests come in on stdin
(line-delimited JSON), responses go out on stdout. Logging goes to
stderr only (anything on stdout would corrupt the protocol stream).

Read-only by default
--------------------
``--mcp-write`` (or ``AXROSS_MCP_WRITE=1``) toggles a small set of
mutating tools. Off by default because an LLM with shell-equivalent
access to a remote SFTP / S3 / Dropbox session is a bigger blast
radius than most users intend.

Backends
--------
The server is started with a default backend and may be given
additional named backends (``ServerConfig.backends``) that tools can
route to per-call via an optional ``backend`` argument; when omitted
the default is used. The ``list_backends`` tool enumerates them and
only exists when such a registry is configured. ``main.py`` never
passes ``backends=``: the CLI server (``--mcp-server``, stdio or
``--mcp-http``) serves ``default_backend()`` — LocalFS — and gets a
registry only through the ``remote`` capability group, whose
``remote_open`` adds saved profiles at run time (per session; see
core.mcp_groups). The default backend is then ``local``.

Capability groups
-----------------
``--mcp-tools GROUP[,GROUP...]`` (``tool_groups`` on ServerConfig /
HTTPServerConfig / _build_tools) adds the tools of core.mcp_groups:
metadata, duplicates, packer, archive, crypto, index, filetype,
transfer, remote, extensions. Their mutating tools follow
``allow_write`` like the write tools; their local paths go through the
same root confinement (``_scope_path`` / ``_write_path`` /
``_refuse_root``, backend-aware: a profile opened by ``remote_open`` is
not local disk, so the root does not apply to it). ``axross
--mcp-list-tools`` prints the manifest of whatever a flag set serves
(docs/mcp-tools.json for everything).

Activation
----------
``main.py`` only enters this module when ``AXROSS_MCP=1`` is set
**or** the ``--mcp-server`` CLI flag is passed. Otherwise the GUI
boots normally and this module is never imported.

Tool surface (read-only)
------------------------
* ``list_dir(path)``  → listing entries
* ``stat(path)``      → mode/size/mtime
* ``read_file(path, max_bytes=…)`` → bounded read
* ``checksum(path, algorithm=…)`` → native backend fingerprint, with
  a streaming hashlib fallback that emits progress notifications
  when the backend has no cheap native hash
* ``search(needle, ext=…, min_size=…, max_size=…)`` → metadata index
* ``walk(path, max_depth=…, max_entries=…)`` → bounded recursive
  listing with progress notifications
* ``recursive_checksum(path, algorithm=…, max_files=…, max_depth=…,
  max_file_bytes=…)`` → hash every file under path; one progress
  notification per hashed file
* ``grep(pattern, path=…, max_depth=…, max_matches=…)`` → bounded
  server-side regex search with progress notifications
* ``preview(path, edge=…)`` → thumbnail as an MCP image block
* ``list_versions(path)`` / ``open_version_read(path, version_id, …)``

Adds when write is enabled (``--mcp-write``), nine tools:

* ``write_file(path, content_b64)``
* ``mkdir(path)``
* ``remove(path, recursive=False)``
* ``rename(src, dst)`` / ``copy(src, dst)``
* ``bulk_copy(src, dst, max_files=…, max_depth=…, overwrite=…)`` →
  tree copy, one progress notification per copied file
* ``symlink(target, link_path)`` / ``hardlink(target, link_path)``
* ``chmod(path, mode)``

Adds when scripts are enabled (``--mcp-allow-scripts``, stdio only):
``script_list``, ``script_api_schema``, ``script_read``, ``script_write``, ``script_delete``,
``script_run``. These work on the user's script directory; script_run
runs the script as the user in a child process (stdin empty, its own
process group, ``timeout_s`` wall-clock limit, bounded output) and
answers with exit status, output and any uncaught exception. They are
not confined to the MCP root.

Write tools and ``script_write`` / ``script_delete`` / ``script_run``
leave attempt / ok / refused lines on the ``core.mcp_server.audit``
logger (names, paths and sizes only, never payloads).

Long-running operations (MCP progress notifications)
----------------------------------------------------
Clients may supply ``params._meta.progressToken`` on ``tools/call``
to opt into streaming progress. Handlers that can report partial
work — ``walk`` (entries visited), ``grep`` (files scanned),
``checksum`` (bytes hashed in the streaming fallback),
``recursive_checksum`` (files hashed) and ``bulk_copy`` (files
copied) — call ``ctx.progress(done, total, msg)`` inside the loop,
which writes a ``notifications/progress`` frame to the same stdout
stream the final response goes to. Several threads write that stream
(the request loop, ``tasks/start`` workers, the log forwarder), so
``serve()`` routes every write through one :class:`_SerializedWriter`
lock: frames from different threads may arrive in any order, but
never interleave inside one line.

Cancellation on stdio
---------------------
The stdio loop is single-threaded: while a synchronous ``tools/call``
runs, the loop sits in the worker join and reads no further input,
so a ``notifications/cancelled`` for that call is only read after it
finished. On stdio a synchronous call is therefore stopped only by
its wall-clock timeout. Use ``tasks/start`` + ``tasks/cancel`` for
work that must be cancellable.

Task namespace (fire-and-forget long-running calls)
---------------------------------------------------
For operations that outlive a reasonable request/response window,
a client can issue:

* ``tasks/start(name, arguments)``       → {task_id, status}
* ``tasks/status(task_id)``              → {status, last_progress,
                                            result?, error?}
* ``tasks/cancel(task_id)``              → {ok}
* ``tasks/list()``                       → [{task_id, status, tool, ...}]

The task runs on a background thread with its own cancel event.
``ctx.progress`` calls update the task record AND are still
forwarded to the session's stdout sink (so subscribed SSE
clients see them live). Completed results are capped at
``MAX_TASK_RESULT_BYTES`` and retained for
``TASK_RETENTION_SECONDS`` or until the per-scope cap kicks in.
Session-scoped on HTTP (client A can't observe or cancel client
B's tasks); server-scoped on stdio.
"""

from __future__ import annotations

import base64
import contextvars
import errno
import fnmatch
import io
import json
import logging
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import IO, Any, Callable, Optional

from core.redaction import redact_text
from core.script_runner import OUTPUT_DRAIN_SECONDS, STOP_GRACE_SECONDS

try:  # pragma: no cover — optional dep
    import jsonschema

    _JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    jsonschema = None  # type: ignore[assignment]
    _JSONSCHEMA_AVAILABLE = False

log = logging.getLogger(__name__)

#: Validators of the tools' input schemas, by schema text. jsonschema.validate
#: checks the SCHEMA against its metaschema before the arguments - 4 ms of
#: $ref resolution per tools/call; a kept validator was checked once.
_SCHEMA_VALIDATORS: dict[str, Any] = {}
_SCHEMA_VALIDATORS_MAX = 1024
_SCHEMA_VALIDATORS_LOCK = threading.Lock()


def _validate_arguments(args, schema: dict) -> None:
    """``jsonschema.validate(args, schema)``: raises the same
    ValidationError (best_match of the same validator class) or, for a
    schema that is itself invalid, the same SchemaError - with the
    metaschema check made once per schema text instead of per call."""
    try:
        key = json.dumps(schema)
    except (TypeError, ValueError):  # not JSON: no key to keep it under
        jsonschema.validate(args, schema)
        return
    validator = _SCHEMA_VALIDATORS.get(key)
    if validator is None:
        import copy

        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)  # SchemaError: nothing is kept
        # A copy: a later edit of the tool's dict must not change what this
        # validator (shared by every schema with this text) checks.
        validator = cls(copy.deepcopy(schema))
        with _SCHEMA_VALIDATORS_LOCK:
            if len(_SCHEMA_VALIDATORS) >= _SCHEMA_VALIDATORS_MAX:
                _SCHEMA_VALIDATORS.clear()
            _SCHEMA_VALIDATORS[key] = validator
    error = jsonschema.exceptions.best_match(validator.iter_errors(args))
    if error is not None:
        raise error


def _argument_refusal(args, schema: dict) -> tuple[str, list] | None:
    """``(message, path)`` of the arguments' first schema violation, else
    None. Without jsonschema the handlers check their own arguments, but
    not the ones they do not know: a strict schema's
    (``additionalProperties: false``) unknown arguments are refused here,
    as jsonschema refuses them - a misspelt option was ignored silently."""
    if _JSONSCHEMA_AVAILABLE:
        try:
            _validate_arguments(args, schema)
        except jsonschema.ValidationError as exc:
            return exc.message, list(exc.absolute_path)
        return None
    if isinstance(args, dict) and isinstance(schema, dict):
        missing = [key for key in schema.get("required") or () if key not in args]
        if missing:
            return f"{missing[0]!r} is a required property", []
    if isinstance(args, dict) and isinstance(schema, dict) \
            and schema.get("additionalProperties") is False:
        unknown = [key for key in args if key not in (schema.get("properties") or {})]
        if unknown:
            names = ", ".join(repr(key) for key in unknown)
            verb = "was" if len(unknown) == 1 else "were"
            return f"Additional properties are not allowed ({names} {verb} unexpected)", []
    return None

# Separate logger for write-tool audit trail. Operators typically
# route this to a different sink (append-only file, SIEM) than the
# general-purpose log. Every successful OR refused write lands
# here with the tool name, paths, and outcome — never the payload
# bytes themselves.
audit_log = logging.getLogger("core.mcp_server.audit")


# The MCP revisions this server speaks, newest first. initialize echoes
# the client's version when it is one of them and answers the newest
# otherwise (the client then decides whether it can live with that).
# 2025-03-26 is left out on purpose: it is the one revision that demands
# JSON-RPC batches, which 2025-06-18 removed again; a client asking for it
# is offered the newest. What each revision changes here:
#   2025-06-18: tool ``title``, ``outputSchema`` and ``structuredContent``,
#               ``serverInfo.title``, the MCP-Protocol-Version header on
#               HTTP (core.mcp_http), no batches;
#   2025-11-25: arguments a tool refuses come back as a tool error
#               (isError) the model can read and correct, not as a
#               JSON-RPC error; ``serverInfo.description`` / ``websiteUrl``.
# Tool annotations (readOnlyHint, destructiveHint, idempotentHint,
# openWorldHint) go out from 2025-03-26 on, so with both newer revisions.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
#: The revision a session that never sent initialize is answered in (a
#: direct caller of _handle_request, a test): the oldest, as before.
LEGACY_PROTOCOL_VERSION = "2024-11-05"
#: Every released revision up to the newest supported one, oldest first:
#: what "at least revision X" is measured against.
_KNOWN_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
SERVER_NAME = "axross-mcp"
#: serverInfo's display name (2025-06-18) and its description and website
#: (2025-11-25).
SERVER_TITLE = "axross"
SERVER_DESCRIPTION = (
    "axross's file tools over MCP: list, read, search, hash and (opt-in) write files "
    "on the local disk and on remote connections (SFTP, SMB, WebDAV, S3 and more)"
)
SERVER_WEBSITE = "https://github.com/c0decave/axross-headless-mcp"
#: InitializeResult.instructions (2025-03-26 on): what a client may put
#: ahead of the tool list. Facts about the tools only, no requests to the
#: model - a client shows it as the server's own text.
from core import mcp_names as _mcp_names  # noqa: E402
from core import mcp_terms as _mcp_terms  # noqa: E402

SERVER_INSTRUCTIONS = (
    "axross file tools for the local disk and remote storage.\n"
    "Start: list_directory lists one folder, walk_tree a tree, get_path_info one entry; "
    "read_file reads in pages (offset, next_offset). search_content searches contents "
    "live; search_index queries the offline index that build_index fills.\n"
    + "".join(f"\n{heading}:\n" + "".join(f"- {rule}\n" for rule in rules)
              for heading, rules in _mcp_terms.SECTIONS)
).rstrip("\n")
#: serverInfo's icons (2025-11-25): the headless server's logo, as in
#: server.json for the registry. An HTTPS URL a client fetches itself; no
#: image travels in the protocol.
SERVER_ICONS = (
    {"src": "https://raw.githubusercontent.com/c0decave/axross-headless-mcp/main/"
            "docs/assets/logo.png",
     "mimeType": "image/png", "sizes": ["400x400"]},
)
# The package version, so serverInfo and /health name the axross that runs.
from axross._version import __version__ as SERVER_VERSION  # noqa: E402

# JSON-RPC 2.0 standard error codes. We use these instead of a
# generic -32000 so MCP clients can distinguish "you sent bad args"
# from "my handler crashed".
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

MAX_READ_BYTES = 4 * 1024 * 1024  # 4 MiB cap on a single read_file
#: Most entries of a folder moved to another folder whose symlinks are
#: checked (rename, transfer_move): a relative link points elsewhere from
#: its new place. A bigger folder is refused.
MOVED_LINK_CHECK_LIMIT = 100_000
_READ_CHUNK_BYTES = 1024 * 1024
# Default wall-clock ceilings per tool category. Values are generous
# enough for real backend latency (an SFTP list_dir on a spinning
# disk can take several seconds) but tight enough that a wedged
# backend call gives up in-session instead of holding the tool thread
# indefinitely.
DEFAULT_TIMEOUT_QUICK = 15.0  # stat, read_file, list_dir, search
DEFAULT_TIMEOUT_WALK = 60.0  # walk, grep
DEFAULT_TIMEOUT_WRITE = 30.0  # write tools
DEFAULT_TIMEOUT_PREVIEW = 30.0  # preview renders a thumbnail
# ``checksum`` may fall back to streaming-hash the whole file when the
# backend has no native fingerprint. Five minutes accommodates a
# gigabyte-class file over a slow link while still bounding a wedged
# backend. Tools that poll ctx.check_cancel() can still be stopped by
# the client at any point before this deadline.
DEFAULT_TIMEOUT_STREAM_HASH = 300.0
#: Bytes past its reported size a remote file's hash stream may bring.
STREAM_HASH_SLACK_BYTES = 16 << 20
# Whole-tree jobs of the capability groups (duplicate scan, index build,
# pack, extract, transfer): half an hour bounds a wedged backend while a
# real job on a large tree still finishes. They poll ctx.check_cancel(),
# so tasks/cancel stops them much sooner.
DEFAULT_TIMEOUT_LONG = 1800.0
# script_run's own wall-clock limit (its ``timeout_s`` argument): the
# default and the most a caller may ask for. The child is terminated at
# the limit and killed STOP_GRACE_SECONDS later; tasks/start runs a
# script in the background of the stdio loop.
DEFAULT_SCRIPT_TIMEOUT_S = 60.0
MAX_SCRIPT_TIMEOUT_S = 600.0
# The tool deadline of script_run, derived so it never fires before the
# script's own limit, the kill grace and the output drain have run out:
# the run then always ends with a structured reply, not ERR_TIMEOUT.
DEFAULT_TIMEOUT_SCRIPT = MAX_SCRIPT_TIMEOUT_S + STOP_GRACE_SECONDS + OUTPUT_DRAIN_SECONDS + 5.0
# Named timeout classes. Every tool has one (see _TIMEOUT_CLASS_BY_TOOL);
# the class is what the --mcp-list-tools manifest reports.
TIMEOUT_CLASSES: dict[str, float] = {
    "quick": DEFAULT_TIMEOUT_QUICK,
    "walk": DEFAULT_TIMEOUT_WALK,
    "write": DEFAULT_TIMEOUT_WRITE,
    "preview": DEFAULT_TIMEOUT_PREVIEW,
    "stream": DEFAULT_TIMEOUT_STREAM_HASH,
    "long": DEFAULT_TIMEOUT_LONG,
    "script": DEFAULT_TIMEOUT_SCRIPT,
}

# JSON-RPC application error code for rate-limit rejection. The
# -32000 range is "server-defined"; nothing in the MCP spec claims
# a canonical value so we carve out one here.
ERR_RATE_LIMITED = -32001
# JSON-RPC application error code for tool wall-clock timeout. Also
# in the server-defined -32000 range.
ERR_TIMEOUT = -32002

# Rate limit defaults. Token bucket: burst == max instantaneous
# tools/call queued; refill_per_sec == steady-state rate.
DEFAULT_RATE_BURST = 30
DEFAULT_RATE_REFILL_PER_SEC = 1.0  # 60/min
# URI scheme for backend-rooted resources exposed via ``resources/list``
# and ``resources/read``. Referenced as ``axross:///<path>`` in every
# URI the server emits.
RESOURCE_SCHEME = "axross"
# Cap on the number of entries ``resources/list`` returns at the
# root. An LLM that pulled 20k resource descriptors would waste the
# context window; the URI template advertised via
# ``resources/templates/list`` covers arbitrary paths anyway, so the
# flat list is just a discovery aid, not an enumeration.
MAX_RESOURCES_LISTED = 100


def _utf8_tail(data: bytes) -> int:
    """How many bytes at the end of *data* are an unfinished UTF-8 character."""
    for back in range(1, min(4, len(data)) + 1):
        byte = data[-back]
        if byte < 0x80:
            return 0
        if byte >= 0xC0:  # a lead byte: how long its character is
            need = 2 if byte < 0xE0 else 3 if byte < 0xF0 else 4
            return back if back < need else 0
    return 0


#: Tool arguments that name a file: each also has a ``<name>_b64`` twin
#: (base64 of the name's raw bytes) for a name that is not UTF-8.
PATH_ARGUMENTS = ("path", "src", "dst", "dest_dir", "folder", "link_path", "out", "target")
#: ... and lists of names.
PATH_LIST_ARGUMENTS = ("names",)
#: Result fields that name a file: a name that is not UTF-8 gets a
#: ``<field>_b64`` twin there (error texts are only made readable).
_TWIN_KEYS = frozenset(PATH_ARGUMENTS) | {"name", "output", "file", "dest", "link_target"}


def _raw_bytes(text: str) -> bytes | None:
    """The bytes a surrogate-escaped name stands for (os.fsdecode made it),
    or None when *text* holds other lone surrogates."""
    try:
        return text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return None


def _wire_text(text: str) -> str:
    """*text* as it can go over the wire: a lone surrogate - a byte of a
    file name that is not UTF-8 (``os.fsdecode``) - becomes U+FFFD. JSON
    may escape such a surrogate, but a client's UTF-8 decoder refuses it:
    the official SDK dropped the whole response and waited forever."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        pass
    raw = _raw_bytes(text)
    if raw is not None:
        return raw.decode("utf-8", "replace")
    return "".join("\ufffd" if "\ud800" <= ch <= "\udfff" else ch for ch in text)


def _wire_safe(value):
    """*value* (a tool result, an error) with every string fit for the wire
    (:func:`_wire_text`). A dict value that changed gets a sibling
    ``<key>_b64`` - base64 of its raw bytes - so the file can still be
    named: every tool takes ``path_b64`` (and the other ``*_b64`` twins of
    :data:`PATH_ARGUMENTS`) instead of ``path``."""
    if isinstance(value, str):
        return _wire_text(value)
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            name = _wire_text(key) if isinstance(key, str) else key
            if isinstance(item, str):
                clean = _wire_text(item)
                out[name] = clean
                if clean is not item and isinstance(name, str) and (
                        name in _TWIN_KEYS or name.endswith("path")):
                    raw = _raw_bytes(item)
                    twin = f"{name}_b64"
                    if raw is not None and twin not in value:
                        out[twin] = base64.b64encode(raw).decode("ascii")
            else:
                out[name] = _wire_safe(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_wire_safe(item) for item in value]
    return value


def _dumps_wire(message) -> str:
    """One JSON-RPC frame as a line of JSON, without lone surrogates."""
    line = json.dumps(message, default=str)
    if "\\ud" in line or "\\uD" in line:
        line = json.dumps(_wire_safe(message), default=str)
    return line


def _decode_path_args(args: dict) -> dict:
    """``path_b64`` (and the other twins) into ``path``: the raw bytes of
    a name that is not UTF-8, as :func:`_wire_safe` handed them out. A
    twin wins over the plain argument; malformed base64 is refused."""
    if not isinstance(args, dict) or not any(
            isinstance(key, str) and key.endswith("_b64") for key in args):
        return args
    import os as _os

    out = dict(args)
    for name in PATH_ARGUMENTS:
        twin = out.pop(f"{name}_b64", None)
        if twin is None:
            continue
        out[name] = _os.fsdecode(_strict_b64(twin, f"{name}_b64"))
    for name in PATH_LIST_ARGUMENTS:
        twins = out.pop(f"{name}_b64", None)
        if twins is None:
            continue
        if not isinstance(twins, list):
            raise ValueError(f"{name}_b64 must be a list of base64 strings")
        if name in out and isinstance(out[name], list) and len(out[name]) != len(twins):
            # Both given and of different lengths: one name would be lost.
            raise ValueError(f"{name}_b64 has {len(twins)} entries but {name} has "
                             f"{len(out[name])}; give one of them, or both alike")
        out[name] = [_os.fsdecode(_strict_b64(t, f"{name}_b64")) for t in twins]
    return out


def _strict_b64(value, what: str) -> bytes:
    """Standard base64, canonical only: ``YWJj=`` (excess padding) and the
    like are refused, not read as "abc"."""
    import binascii

    if not isinstance(value, str):
        raise ValueError(f"{what} must be a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{what} is not base64: {exc}") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{what} is not canonical base64 (padding or trailing bits)")
    return raw


def _call_schema(tool) -> dict:
    """The schema a call's (decoded) arguments are checked against: the
    published one plus what it leaves to the server (twin_required,
    legacy_minimum)."""
    schema = tool.schema
    twins = getattr(tool, "twin_required", ())
    legacy = getattr(tool, "legacy_minimum", {})
    if not twins and not legacy:
        return schema
    schema = dict(schema)
    if twins:
        schema["required"] = [*schema.get("required", []),
                              *(n for n in twins if n not in schema.get("required", []))]
    if legacy:
        props = dict(schema.get("properties", {}))
        for name, minimum in legacy.items():
            if name in props:
                props[name] = {**props[name], "minimum": minimum}
        schema["properties"] = props
    return schema


#: Tools whose ``backend`` argument is required when they have one: the
#: default backend (the local disk) cannot run what they run.
_BACKEND_REQUIRED = frozenset({"remote_exec", "remote_script"})

#: Tools whose list argument ``names`` holds identifiers, not file names.
_NO_NAME_TWINS = frozenset({"script_api_schema"})


def _add_path_twins(tools: list) -> None:
    """Give every path argument its ``*_b64`` twin in the tool's schema. A
    required argument with a twin leaves ``required`` (either one will do:
    the server checks that one of them came, see _call_schema)."""
    for tool in tools:
        props = tool.schema.get("properties")
        if not isinstance(props, dict):
            continue
        twinned = []
        for name in PATH_ARGUMENTS:
            spec = props.get(name)
            if isinstance(spec, dict) and spec.get("type") == "string":
                twinned.append(name)
                props.setdefault(f"{name}_b64", {
                    "type": "string",
                    "contentEncoding": "base64",
                    "description": f"{name} as base64 of its raw bytes, for non-UTF-8 names; "
                                   f"replaces {name}.",
                })
        for name in PATH_LIST_ARGUMENTS:
            spec = props.get(name)
            if (isinstance(spec, dict) and spec.get("type") == "array"
                    and tool.name not in _NO_NAME_TWINS):
                twinned.append(name)
                props.setdefault(f"{name}_b64", {
                    "type": "array", "items": {"type": "string", "contentEncoding": "base64"},
                    "description": f"{name} as base64 of each name's raw bytes, for non-UTF-8 "
                                   f"names; replaces {name}.",
                })
        required = tool.schema.get("required") or []
        moved = tuple(name for name in twinned if name in required)
        if moved:
            tool.twin_required = moved
            tool.schema["required"] = [n for n in required if n not in moved]
            if not tool.schema["required"]:
                del tool.schema["required"]
            for name in moved:
                # A copy: groups share one property dict between tools.
                spec = props[name] = dict(props[name])
                note = f"Required unless {name}_b64 is given."
                if note not in spec.get("description", ""):
                    spec["description"] = f"{spec.get('description', '').rstrip()} {note}"


#: Shared wording of the tool definitions (tools/list): core.mcp_terms.
from core.mcp_terms import CLASS_TEXT as _CLASS_TEXT  # noqa: E402
from core.mcp_terms import IDEMPOTENT as _IDEMPOTENT  # noqa: E402
from core.mcp_terms import SECRET_TAG as _SECRET_TAG  # noqa: E402
from core.mcp_terms import WRITE_TAG as _WRITE_TAG  # noqa: E402
from core.mcp_terms import levels_text as _levels_text  # noqa: E402

_DEPTH_TEXT = _levels_text()
#: The tools whose max_depth counts levels from 1 (_levels_text). An older
#: caller's 0 still works there (it acts like 1); the schema says 1.
_LEVEL_DEPTH_TOOLS = frozenset({"walk", "grep", "recursive_checksum", "bulk_copy"})


def _local_path_spec(what: str) -> dict:
    """A path argument of a tool that works on the local disk only."""
    return {
        "type": "string",
        "minLength": 1,
        "description": f"{what} on the local disk (absolute, or relative to the MCP root).",
    }


def _path_spec(what: str) -> dict:
    """A path argument's schema: *what* it names, then its format."""
    return {
        "type": "string",
        "minLength": 1,
        "description": f"{what} (absolute, or relative to the MCP root).",
    }


def _script_name_spec(what: str) -> dict:
    """A saved script's name (core.scripting._validate_script_name)."""
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 80,
        "pattern": "^[A-Za-z0-9_-]+$",
        "description": f"{what}: letters, digits, '_' and '-', at most 80 characters, "
                       "without '.py', e.g. 'disk_report'.",
    }


def _secret_scan_limit() -> int:
    from core import protected_places

    return protected_places.SECRET_CONTENT_SCAN


def _utf8_unit(data: bytes, i: int) -> int:
    """Length of the UTF-8 unit at *data[i]*: a whole character, or 1 for a
    byte that starts none (an invalid byte, a lone continuation byte, a
    lead byte whose continuation is wrong). 0: a character cut by the end
    of *data*."""
    b = data[i]
    if b < 0x80:
        return 1
    if 0xC2 <= b <= 0xDF:
        need = 2
    elif 0xE0 <= b <= 0xEF:
        need = 3
    elif 0xF0 <= b <= 0xF4:
        need = 4
    else:
        return 1  # 80-C1, F5-FF: no character starts here
    for k in range(1, need):
        if i + k >= len(data):
            return 0
        if not 0x80 <= data[i + k] <= 0xBF:
            return 1  # the lead byte alone is the bad unit
    return need


def _text_window(ahead: bytes, cap: int, more: bool) -> bytes:
    """The bytes a text read hands out from *ahead* (the file from the read
    position on, a few bytes past *cap*): whole units up to *cap* bytes,
    at least one unit (max_bytes smaller than one character), and never a
    character cut in two - an invalid byte is a unit of its own, so
    ``ff fe 中`` read a byte at a time gives ff, fe, then 中 (it lost 中)."""
    out = 0
    while out < len(ahead):
        unit = _utf8_unit(ahead, out)
        if unit == 0:
            if out == 0 and not more:
                unit = len(ahead)  # the file ends inside it: what is there
            else:
                break
        if out and out + unit > cap:
            break
        out += unit
        if out >= cap:
            break
    return ahead[:out]


def _skip_stream(fh, count: int) -> None:
    """Move *count* bytes into a backend stream: a seek where the stream has
    one, else read and drop (chunk by chunk, never more than one chunk held)."""
    seek = getattr(fh, "seek", None)
    seekable = getattr(fh, "seekable", None)
    try:
        if callable(seek) and (not callable(seekable) or seekable()):
            seek(count, 1)
            return
    except (OSError, ValueError, AttributeError):
        pass
    left = count
    while left > 0:
        chunk = fh.read(min(_READ_CHUNK_BYTES, left))
        if not chunk:
            return
        left -= len(chunk)


def _read_capped_stream(fh, cap: int) -> tuple[bytes, bool]:
    """Read at most ``cap`` bytes plus one sentinel byte from a backend
    stream. Returns ``(data_at_cap, truncated)``.

    Some test doubles and odd protocol wrappers ignore the requested
    ``read(n)`` size. Reading in small chunks and slicing each response
    keeps the caller from accumulating more than ``cap + 1`` bytes.
    """
    if cap < 0:
        raise ValueError("cap must be >= 0")
    chunks: list[bytes] = []
    remaining = cap + 1
    while remaining > 0:
        chunk = fh.read(min(_READ_CHUNK_BYTES, remaining))
        if chunk == b"" or chunk == "":
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        elif isinstance(chunk, bytearray):
            chunk = bytes(chunk)
        elif not isinstance(chunk, bytes):
            raise RuntimeError("backend.open_read yielded non-bytes; cannot encode as MCP content")
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    truncated = len(data) > cap
    if truncated:
        data = data[:cap]
    return data, truncated


# Per-file scan cap for the grep tool. Server-side regex over remote
# files costs network bandwidth; we refuse anything larger than this
# per match candidate.
MAX_GREP_FILE_BYTES = 4 * 1024 * 1024
# Hard ceiling on grep results to keep responses bounded.
MAX_GREP_MATCHES = 500
# Maximum grep pattern length. A legitimate regex is rarely longer
# than a few hundred chars; longer patterns are usually a DoS
# vector (pathological catastrophic-backtracking shapes tend to be
# verbose). Applies before re.compile.
MAX_GREP_PATTERN_LENGTH = 512
# Cheap heuristic for "nested unbounded quantifier" — the canonical
# ReDoS shape ``(a+)+``, ``(.*)*``, ``([abc]+)*``, etc. Captures
# most real-world attacks without false-positiving on patterns like
# ``[a-z]+`` or ``.*hello.*``. Compiled at import time.
import re as _re_preflight  # noqa: E402 — intentionally near the inline doc-block above

_REDOS_NESTED_QUANTIFIER = _re_preflight.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")
del _re_preflight
# Seconds the grep tool's pattern may run on one file (in its child
# process, core.regex_worker) before the call is refused as a ReDoS.
GREP_REGEX_SECONDS_PER_FILE = 5.0
# Emit a progress notification every N entries during walk(). 50 is a
# compromise: often enough to keep a slow client informed, rare enough
# that the notification overhead stays below 2% of the per-entry cost
# on a fast local backend.
WALK_PROGRESS_EVERY = 50
# Chunk size for the streaming-hash fallback in the ``checksum`` tool.
# Matches the file-pane's _stream_sha256 so the two code paths hash at
# the same granularity, and keeps Python's hashlib in its sweet spot
# (any bigger and GIL hold-time per update starts starving the cancel
# check).
STREAM_HASH_CHUNK = 1 << 20  # 1 MiB
# Emit a progress notification every N chunks during streaming-hash.
# Four chunks = 4 MiB of file — small enough that a client watching a
# multi-GB blob gets live feedback, large enough that a 2-MiB file
# completes before the first progress frame (which is what the MCP
# spec recommends — "optional on small operations").
STREAM_HASH_PROGRESS_EVERY = 4
# Default per-file size ceiling for ``recursive_checksum``. Above this
# the file is recorded as ``skipped: "too-large"`` instead of
# streamed. 1 GiB is generous for documents / media but refuses to
# quietly pull a multi-GB VM image through a WAN backend. Callers
# that really want to hash those can bump ``max_file_bytes`` per-call.
RECURSIVE_CHECKSUM_MAX_FILE_BYTES = 1 << 30  # 1 GiB


def _list_or_note(backend, folder: str, root: str, unreadable: list[dict]):
    """``backend.list_dir(folder)`` for a tree walk, or None when it failed:
    the failure is noted in *unreadable* as ``{path, error}``. The walk's
    own *root* raises instead - an unreadable root gave an empty answer
    that looked like an empty tree (walk), no match (grep) or nothing to
    hash (recursive_checksum)."""
    try:
        return backend.list_dir(folder)
    except OSError as exc:
        if folder == root:
            raise
        unreadable.append({"path": folder, "error": redact_text(str(exc))})
        return None


def _all_hashed(entries: list[dict], truncated: bool) -> bool:
    """Whether a recursive_checksum left nothing out: no cut, and every
    record a checksum (not an error, a too-large skip or a folder it could
    not list)."""
    return not truncated and all("checksum" in e for e in entries)


def _bulk_copy_complete(entries: list[dict], truncated: bool) -> bool:
    """Whether a bulk_copy left nothing out: the walk ran to the end and
    every record is a copy or a requested "exists" skip."""
    if truncated:
        return False
    return all(
        e.get("action") == "copied"
        or (e.get("action") == "skipped" and e.get("reason") == "exists")
        for e in entries
    )


# Default per-file size ceiling for ``bulk_copy``. Looser than
# ``recursive_checksum`` because copy is the user's explicit intent
# to move the bytes — a user who wants to hash 50 GiB usually means
# "spot-check a tree" and a 1 GiB cap saves them from themselves, but
# a user who wants to copy 50 GiB usually means "move that VM image
# over". 10 GiB keeps the safety rail at "huge object that probably
# shouldn't silently stream over a WAN backend" without refusing
# realistic payloads. Caller overrides per-call.
BULK_COPY_MAX_FILE_BYTES = 10 * (1 << 30)  # 10 GiB

# Upper caps of the counts a caller may ask for: what a tree tool keeps in
# memory and sends back is bounded, whatever max_entries / max_files says
# (10**9 kept a whole disk's listing in the server). The defaults stay far
# below; a call above a cap is refused, not cut silently.
MAX_WALK_ENTRIES = 100_000
MAX_RECURSIVE_CHECKSUM_FILES = 50_000
MAX_BULK_COPY_FILES = 100_000
MAX_TREE_DEPTH = 64
# search: at most this many results (default DEFAULT_SEARCH_LIMIT), and at
# most MAX_SEARCH_SCAN rows of the index read for them.
DEFAULT_SEARCH_LIMIT = 1000
MAX_SEARCH_RESULTS = 10_000
MAX_SEARCH_SCAN = 200_000
# Allowed algorithm names for ``checksum``. Deliberately restricted to
# the four hashlib.new-safe algorithms that a client can reproduce
# locally — any request for a backend-specific hash (S3 ETag, Dropbox
# content-hash, quickxor) is refused rather than silently stream-
# hashing with sha256, which would give the caller the wrong answer.
_HASHLIB_ALGOS = frozenset({"sha256", "sha1", "md5", "sha512"})


# ---------------------------------------------------------------------------
# Tool catalogue
# ---------------------------------------------------------------------------


class CancelledError(Exception):
    """Raised by ``ToolContext.check_cancel()`` when the client has
    sent ``notifications/cancelled`` for the in-flight request."""


class _CancelRegistry:
    """Thread-safe map of ``request_id → threading.Event`` used to
    deliver ``notifications/cancelled`` from the dispatcher to the
    in-flight tool handler.

    Stdio transport is single-threaded: the registry is overkill but
    harmless. HTTP transport (ThreadingHTTPServer) runs each request
    on its own thread, which is why the registry exists — a cancel
    notification for request #42 has to find the handler-thread's
    event no matter what thread the notification arrives on."""

    def __init__(self) -> None:
        self._events: dict[Any, threading.Event] = {}
        # Ids a notifications/cancelled reached while they ran: their
        # response is not sent (MCP: a cancelled request gets none).
        self._cancelled: set = set()
        self._lock = threading.Lock()

    def register(self, request_id) -> threading.Event:
        """The cancel event of *request_id* - the one already registered
        when the stdio loop did that before handing the call to a worker
        (so a cancel that comes first is not lost)."""
        with self._lock:
            event = self._events.get(request_id)
            if event is None:
                event = self._events[request_id] = threading.Event()
        return event

    def pop_cancelled(self, request_id) -> bool:
        """True (once) when *request_id* was cancelled while it ran."""
        with self._lock:
            if request_id in self._cancelled:
                self._cancelled.discard(request_id)
                return True
            return False

    def unregister(self, request_id) -> None:
        with self._lock:
            self._events.pop(request_id, None)

    def pending(self) -> int:
        """Requests registered and not yet unregistered: calls running now."""
        with self._lock:
            return len(self._events)

    def cancel_all(self) -> None:
        """Flip every in-flight request's cancel event (the session ended)."""
        with self._lock:
            events = list(self._events.values())
        for event in events:
            event.set()

    def cancel(self, request_id) -> bool:
        """Mark request *request_id* as cancelled. Returns True when
        we actually knew about that id, False otherwise — the
        difference is useful to log the "client cancelled a request
        we'd already finished" pattern."""
        with self._lock:
            event = self._events.get(request_id)
            if event is not None:
                self._cancelled.add(request_id)
        if event is None:
            return False
        event.set()
        return True


# Hard cap on a serialised task result stored in the registry. A
# tool that returns a 500-entry recursive_checksum result might
# still fit; a gigabyte blob wouldn't — that would turn
# tasks/status into a memory-exhaustion vector. Tasks above the
# cap finish in status="error".
MAX_TASK_RESULT_BYTES = 16 * 1024 * 1024

# Same cap for direct tools/call responses. Individual tools still
# apply their own domain-specific limits first; this is the final
# circuit breaker before a result is JSON-wrapped into the MCP text
# content block.
MAX_TOOL_RESULT_BYTES = 16 * 1024 * 1024

# Saved-script stdout/stderr cap. Scripts are opt-in and powerful, but
# an LLM-triggered ``while True: print(...)`` should stop quickly
# instead of pinning memory in the MCP process.
MAX_SCRIPT_OUTPUT_CHARS = 1 * 1024 * 1024

# script_run's ``args`` (the script's sys.argv[1:]): how many, how long each.
MAX_SCRIPT_ARGS = 64
MAX_SCRIPT_ARG_CHARS = 4096

# Stdio transport line cap. HTTP has MAX_REQUEST_BYTES; stdio needs the
# same shape of guard because ``readline()`` without a size can allocate
# until a malicious client finally sends a newline.
MAX_STDIN_LINE_CHARS = 16 * 1024 * 1024

# Default maximum number of tasks kept in the registry PER SESSION
# (or globally on stdio). Finished tasks beyond the cap are evicted
# oldest-first so tasks/start always succeeds even when a client
# forgets to call tasks/status on older tasks.
MAX_TASKS_PER_SCOPE = 100

#: axross's own background-task methods; on the wire ``axross/tasks/...``
#: (sessions before MCP 2025-11-25 may also use the bare names).
LEGACY_TASK_METHODS = ("tasks/start", "tasks/status", "tasks/cancel", "tasks/list")

# Tasks of one scope that may run at the same time. Each running task
# owns a worker thread and never gets evicted, so without this cap a
# tasks/start loop spawns threads without bound.
MAX_RUNNING_TASKS_PER_SCOPE = 8
# ... and of the whole server: on HTTP every session is a scope of its
# own, and a client opening sessions got 8 more workers with each.
MAX_RUNNING_TASKS_TOTAL = 16
# Bytes of finished task results the registry keeps, all scopes together.
# Over it, the oldest finished tasks go first (their status then answers
# "unknown task_id").
MAX_TASK_RESULTS_TOTAL_BYTES = 64 * 1024 * 1024
# How long a cancelled or timed-out task's worker gets to stop before the
# task ends anyway ("abandoned"): its slot is free again, the thread - a
# backend call that cannot be interrupted - runs out on its own.
TASK_STOP_GRACE_SECONDS = 10.0


#: Workers of calls that did not stop (a hard-stopped tools/call, an
#: abandoned task) that may still run on one backend before new calls on
#: that backend are refused: their slots were freed, but the threads - and
#: what they hold - are not. Calls on other backends go on.
MAX_ABANDONED_WORKERS = 8

#: Argument names that address a backend (core.mcp_groups' transfer tools
#: name two).
_BACKEND_ARGS = ("backend", "src_backend", "dst_backend")

#: Tools never refused for abandoned workers: the way out of a stuck
#: connection (remote_close tears it down, which ends its waiting calls)
#: and what only reads the server's own state.
_ALWAYS_ALLOWED_TOOLS = frozenset({"remote_close", "remote_profiles", "list_backends"})


def _backends_of(args) -> frozenset:
    """The remote backends a call's arguments address, or ``{"local"}``."""
    named = set()
    if isinstance(args, dict):
        for key in _BACKEND_ARGS:
            value = args.get(key)
            if isinstance(value, str) and value.strip() not in ("", "local"):
                named.add(value.strip())
    return frozenset(named or {"local"})


class _AbandonedWorkers:
    """Threads left to end on their own, counted per backend while they
    live (a stalled profile holds its own calls, not the server's)."""

    def __init__(self) -> None:
        self._threads: list[tuple[threading.Thread, frozenset]] = []
        self._lock = threading.Lock()

    def add(self, thread: threading.Thread | None, args=None) -> None:
        if thread is None:
            return
        with self._lock:
            if all(t is not thread for t, _b in self._threads):
                self._threads.append((thread, _backends_of(args)))

    def _prune_locked(self) -> None:
        self._threads = [(t, b) for t, b in self._threads if t.is_alive()]

    def alive(self, backend: str | None = None) -> int:
        with self._lock:
            self._prune_locked()
            if backend is None:
                return len(self._threads)
            return sum(1 for _t, b in self._threads if backend in b)

    def refusal(self, name: str | None = None, args=None) -> str | None:
        """Why a call of *name* with *args* is refused now, or None."""
        if name in _ALWAYS_ALLOWED_TOOLS:
            return None
        for backend in sorted(_backends_of(args)):
            count = self.alive(backend)
            if count >= MAX_ABANDONED_WORKERS:
                way_out = ("close_remote_profile it (that ends them) and "
                           "open_remote_profile it again"
                           if backend != "local" else "wait until some of them end")
                return (f"{count} earlier calls on {backend} did not stop and still run "
                        f"in the background (cap {MAX_ABANDONED_WORKERS}); new work on "
                        f"{backend} is refused - a backend that does not answer holds "
                        f"them: {way_out}")
        return None


_ABANDONED = _AbandonedWorkers()


def _cancel_hooks(event):
    """The call's cancel as core.transfer_hooks' current one: a backend's
    long listing, a server-side command, a spooled upload stop on it."""
    from core import transfer_hooks

    return transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event=event))


class TaskLimitError(RuntimeError):
    """The scope (or the server) already runs as many tasks as it may."""


# How long a finished task is retained in the registry before it
# becomes eligible for eviction. One hour is long enough for a
# distracted client to come back and poll the result, short
# enough that finished results don't pin memory indefinitely.
TASK_RETENTION_SECONDS = 3600


@dataclass
class _Task:
    """One server-side long-running task. Created by
    ``axross/tasks/start``, polled by ``axross/tasks/status``, cancelled
    by ``axross/tasks/cancel``. The worker thread lives in ``thread``;
    the terminal state is set once, through :meth:`finish` - by the
    worker, or by the stop grace when the worker does not stop.
    """

    task_id: str
    scope: str  # session_id for HTTP, "" for stdio
    tool_name: str
    arguments: dict
    status: str  # "running" | "done" | "error" | "cancelled"
    started_at: float  # wall-clock seconds since epoch
    finished_at: float | None = None
    last_progress: dict | None = None
    result: Any = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = field(default=None, repr=False)
    # Set by the deadline timer before it flips cancel_event, so the
    # runner can tell a timeout from a tasks/cancel.
    timed_out: threading.Event = field(default_factory=threading.Event)
    # Size of the serialised result (what the registry's byte cap counts).
    result_bytes: int = 0
    # True when the task ended without its worker (the stop grace ran out).
    abandoned: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def finish(self, status: str, *, result: Any = None, error: str | None = None,
               result_bytes: int = 0, abandoned: bool = False) -> bool:
        """Move a running task to its terminal *status*; False when it
        had one already (the worker came back after it was abandoned)."""
        with self._lock:
            if self.status != "running":
                return False
            self.result, self.error, self.result_bytes = result, error, result_bytes
            self.abandoned = abandoned
            self.finished_at = time.time()
            self.status = status
            return True


class _TaskRegistry:
    """Per-server store of long-running :class:`_Task` records.

    Tasks are scoped via the ``scope`` key — session_id on HTTP,
    empty string on stdio. ``start`` / ``get`` / ``cancel`` /
    ``list_scope`` filter by scope so client A can't observe or
    kill client B's tasks on a shared HTTP server.

    Limits: at most ``max_running_per_scope`` running tasks per scope and
    ``max_running_total`` in the server. Eviction, of every scope on every
    call: finished tasks retire after ``retention_seconds``, beyond
    ``max_per_scope`` records of a scope (oldest finished first) and
    beyond ``max_result_bytes`` of kept results in all. ``drop_scope``
    (an HTTP session that ends) cancels the scope's tasks and forgets
    them. A cancelled or timed-out task whose worker does not stop within
    ``stop_grace`` seconds ends anyway (``abandoned``), freeing its slot.

    Thread-safety: all mutations go through ``_lock``.
    """

    def __init__(
        self,
        *,
        max_per_scope: int = MAX_TASKS_PER_SCOPE,
        retention_seconds: float = TASK_RETENTION_SECONDS,
        max_running_per_scope: int | None = None,
        max_running_total: int | None = None,
        max_result_bytes: int | None = None,
        stop_grace: float | None = None,
    ) -> None:
        self._tasks: dict[str, _Task] = {}
        self._lock = threading.Lock()
        self._max_per_scope = max_per_scope
        self._retention_seconds = retention_seconds
        self._max_running_per_scope = max_running_per_scope
        self._max_running_total = max_running_total
        self._max_result_bytes = max_result_bytes
        self._stop_grace = stop_grace

    def _caps(self) -> tuple[int, int, int, float]:
        # Read late: tests and operators patch the module constants.
        return (
            MAX_RUNNING_TASKS_PER_SCOPE if self._max_running_per_scope is None
            else self._max_running_per_scope,
            MAX_RUNNING_TASKS_TOTAL if self._max_running_total is None
            else self._max_running_total,
            MAX_TASK_RESULTS_TOTAL_BYTES if self._max_result_bytes is None
            else self._max_result_bytes,
            TASK_STOP_GRACE_SECONDS if self._stop_grace is None else self._stop_grace,
        )

    def start(self, scope: str, tool_name: str, arguments: dict) -> _Task:
        import secrets as _secrets

        task_id = _secrets.token_hex(8)
        task = _Task(
            task_id=task_id,
            scope=scope,
            tool_name=tool_name,
            arguments=arguments,
            status="running",
            started_at=time.time(),
        )
        cap, total_cap, _bytes, _grace = self._caps()
        with self._lock:
            self._evict_locked()
            running = [t for t in self._tasks.values() if t.status == "running"]
            mine = sum(1 for t in running if t.scope == scope)
            if mine >= cap:
                raise TaskLimitError(f"{mine} tasks already running in this session (cap {cap})")
            if len(running) >= total_cap:
                raise TaskLimitError(
                    f"{len(running)} tasks already running in this server (cap {total_cap})")
            self._tasks[task_id] = task
        return task

    def get(self, task_id: str, scope: str) -> _Task | None:
        """Return the task if it exists AND belongs to *scope*.
        Scope mismatch returns None — looks the same as "not
        found" to the caller, which is the point: never leak the
        existence of another client's tasks."""
        with self._lock:
            self._evict_locked()
            task = self._tasks.get(task_id)
            if task is None or task.scope != scope:
                return None
            return task

    def cancel(self, task_id: str, scope: str) -> bool:
        task = self.get(task_id, scope)
        if task is None:
            return False
        self._stop(task, "cancelled", "cancelled by axross/tasks/cancel")
        return True

    def _stop(self, task: _Task, status: str, error: str) -> None:
        """Ask *task* to stop; end it without its worker after the grace."""
        task.cancel_event.set()
        if task.status != "running":
            return
        grace = self._caps()[3]

        def _abandon() -> None:
            worker = task.thread
            if worker is not None and worker.is_alive():
                _ABANDONED.add(worker, task.arguments)
                if task.finish(status, error=f"{error}; the tool did not stop within "
                               f"{grace:g}s and was left to end in the background",
                               abandoned=True):
                    log.warning("task %s (%s) abandoned: its worker did not stop",
                                task.task_id, task.tool_name)

        timer = threading.Timer(grace, _abandon)
        timer.daemon = True
        timer.start()

    def stop_for_timeout(self, task: _Task, error: str) -> None:
        task.timed_out.set()
        self._stop(task, "error", error)

    def drop_scope(self, scope: str) -> int:
        """Cancel and forget every task of *scope* (its session ended).
        Returns how many were still running."""
        with self._lock:
            mine = [t for t in self._tasks.values() if t.scope == scope]
            for t in mine:
                self._tasks.pop(t.task_id, None)
        running = 0
        for t in mine:
            if t.status == "running":
                running += 1
                t.cancel_event.set()
                t.finish("cancelled", error="the session ended")
        return running

    def list_scope(self, scope: str) -> list[_Task]:
        with self._lock:
            self._evict_locked()
            return [t for t in self._tasks.values() if t.scope == scope]

    def list_all(self) -> list[_Task]:
        with self._lock:
            return list(self._tasks.values())

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == "running")

    def _evict_locked(self) -> None:
        """Drop finished tasks of every scope that aged out, that push a
        scope over its record cap, or the server over its result bytes.
        Caller holds ``_lock``. Running tasks are never evicted."""
        now = time.time()
        for t in list(self._tasks.values()):
            if t.status != "running" and t.finished_at is not None \
                    and now - t.finished_at > self._retention_seconds:
                self._tasks.pop(t.task_id, None)
        by_scope: dict[str, list[_Task]] = {}
        for t in self._tasks.values():
            by_scope.setdefault(t.scope, []).append(t)
        for scope_tasks in by_scope.values():
            overflow = len(scope_tasks) - self._max_per_scope
            if overflow > 0:
                finished = sorted((t for t in scope_tasks if t.status != "running"),
                                  key=lambda t: t.finished_at or t.started_at)
                for t in finished[:overflow]:
                    self._tasks.pop(t.task_id, None)
        # Over the byte cap the scope that keeps the most gives up its
        # oldest result first: one session's many results no longer erase
        # another's unread one.
        limit = self._caps()[2]
        kept_by_scope: dict[str, int] = {}
        for t in self._tasks.values():
            kept_by_scope[t.scope] = kept_by_scope.get(t.scope, 0) + t.result_bytes
        kept = sum(kept_by_scope.values())
        while kept > limit:
            finished = [t for t in self._tasks.values() if t.status != "running"]
            if not finished:
                break
            def age(t):
                return t.finished_at or t.started_at

            oldest = {}
            for t in finished:
                if t.scope not in oldest or age(t) < age(oldest[t.scope]):
                    oldest[t.scope] = t
            # The heaviest scope; of equally heavy ones, the oldest result.
            victim = max(oldest.values(), key=lambda t: (kept_by_scope[t.scope], -age(t)))
            heaviest = victim.scope
            kept -= victim.result_bytes
            kept_by_scope[heaviest] -= victim.result_bytes
            self._tasks.pop(victim.task_id, None)

    def note_finished(self) -> None:
        """A task ended: apply the byte cap now, not at the next call."""
        with self._lock:
            self._evict_locked()


class _RateLimiter:
    """Token-bucket limiter for ``tools/call``.

    Carved out of the dispatcher so servers that want custom quotas
    (a paid-tier gateway, a multi-tenant host) can swap in a
    different implementation without forking the whole module.

    The bucket starts full; ``try_acquire()`` consumes one token and
    returns whether it succeeded. Refill happens lazily on each
    call — no background timer to leak.
    """

    def __init__(
        self, burst: int = DEFAULT_RATE_BURST, refill_per_sec: float = DEFAULT_RATE_REFILL_PER_SEC
    ):
        if burst <= 0:
            raise ValueError("burst must be positive")
        if refill_per_sec < 0:
            raise ValueError("refill_per_sec must be >= 0")
        self._burst = burst
        self._refill = refill_per_sec
        self._tokens = float(burst)
        self._last = _monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = _monotonic()
            elapsed = max(0.0, now - self._last)
            self._tokens = min(float(self._burst), self._tokens + elapsed * self._refill)
            self._last = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    def refund(self, cost: float = 1.0) -> None:
        """Give back what a try_acquire took (a second limiter refused)."""
        with self._lock:
            self._tokens = min(float(self._burst), self._tokens + cost)

    @property
    def tokens(self) -> float:
        """Current (approximate) token count. Useful for metrics/
        debug — not atomic with a subsequent try_acquire."""
        return self._tokens


def _monotonic() -> float:
    """Module-private monotonic clock. Wrapping ``time.monotonic`` in
    a helper keeps tests able to patch a single symbol when they
    need to fake time."""
    import time

    return time.monotonic()


@dataclass
class _ToolContext:
    """Per-call context passed to every tool handler.

    ``progress_token`` is the MCP client's opaque value for correlating
    progress notifications with the originating request; ``stdout`` is
    the stream the dispatcher is writing responses to. ``progress()``
    is a no-op when either is absent — tests drive handlers directly
    without a stdout and callers that didn't request progress don't
    supply a token.

    ``cancel_event`` is the ``threading.Event`` the registry set()s
    when a ``notifications/cancelled`` arrived for our request id.
    Long-running handlers should call ``check_cancel()`` periodically
    so the client-side cancel translates to a real stop."""

    progress_token: Any = None
    stdout: Optional[IO] = None
    cancel_event: Optional[threading.Event] = None

    def progress(self, progress: float, total: float | None = None, message: str = "") -> None:
        if self.progress_token is None or self.stdout is None:
            return
        params = {"progressToken": self.progress_token, "progress": progress}
        if total is not None:  # optional: left out when not known, never null
            params["total"] = total
        params["message"] = message
        notif = {"jsonrpc": "2.0", "method": "notifications/progress", "params": params}
        self.stdout.write(_dumps_wire(notif) + "\n")
        try:
            self.stdout.flush()
        except Exception:  # noqa: BLE001 — StringIO.flush is a no-op; real pipes may EPIPE
            pass

    def check_cancel(self) -> None:
        """Raise :class:`CancelledError` when the client has cancelled
        this request. Long loops should call this between iterations
        so the cancel lands within one loop tick of arrival."""
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise CancelledError("request cancelled by client")

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()


class _SerializedWriter:
    """Serialise writes to one stream shared by several threads.

    On stdio three writers share ``sys.stdout``: the request loop
    (responses), ``tasks/start`` worker threads and timed-out tool
    workers (``notifications/progress``) and the log forwarder
    (``notifications/message``). ``io.TextIOWrapper`` is documented as
    not thread-safe, so without one shared lock two frames can
    interleave inside a single JSON-RPC line. Every frame is written
    with a single ``write()`` call, so a lock per call keeps each line
    whole. Re-entrant so a stream that logs from inside ``write`` cannot
    deadlock its own thread.
    """

    def __init__(self, stream: IO) -> None:
        self._stream = stream
        self._lock = threading.RLock()

    def write(self, text: str) -> int:
        with self._lock:
            return self._stream.write(text)

    def flush(self) -> None:
        with self._lock:
            self._stream.flush()


def _run_task(task: _Task, tool: "_Tool", stdout: IO | None,
              registry: "_TaskRegistry | None" = None) -> None:
    """Background worker body for an ``axross/tasks/start`` invocation.

    Runs ``tool.handler`` with a ``_ToolContext`` wired so that:

    * ``ctx.progress(...)`` updates ``task.last_progress`` AND
      still writes the frame to the client's ``stdout`` (SSE sink
      on HTTP, stdout on stdio) so clients that stayed subscribed
      continue to see live progress.
    * ``ctx.cancel_event`` is the task's own cancel event, so a
      cancel flips it and the next ``ctx.check_cancel()`` raises.
    * The task_id doubles as the progressToken.

    The terminal state goes through ``task.finish`` so a worker that comes
    back after the registry abandoned it (cancel or timeout, then the stop
    grace) changes nothing. The deadline is the tool's own timeout, then
    the registry's stop grace ends the task with or without its worker.
    """
    import json as _json

    def _on_progress(progress: float, total: float | None = None, message: str = "") -> None:
        task.last_progress = {
            "progress": float(progress),
            "total": float(total) if total is not None else None,
            "message": message,
        }

    ctx = _ToolContext(
        progress_token=task.task_id,
        stdout=stdout,
        cancel_event=task.cancel_event,
    )
    _orig_progress = ctx.progress

    def _progress(progress, total=None, message=""):
        _on_progress(progress, total, message)
        _orig_progress(progress, total, message)

    ctx.progress = _progress  # type: ignore[method-assign]

    timeout_text = f"tool {tool.name!r} exceeded its {tool.timeout_seconds}s timeout"
    timer = None
    if tool.timeout_seconds:

        def _on_deadline() -> None:
            if registry is not None:
                registry.stop_for_timeout(task, timeout_text)
            else:
                task.timed_out.set()
                task.cancel_event.set()

        timer = threading.Timer(tool.timeout_seconds, _on_deadline)
        timer.daemon = True
        timer.start()

    try:
        with _cancel_hooks(task.cancel_event):
            result = tool.handler(task.arguments, ctx)
        if isinstance(result, _PreviewResult):
            # An image block cannot be a task's JSON result: its fields can.
            result = {"mimeType": result.mime, "data": result.data_b64,
                      "width": result.width, "height": result.height}
        result = _wire_safe(result)
        try:
            encoded = _json.dumps(result)
        except (TypeError, ValueError) as exc:
            task.finish("error", error=f"tool result not JSON-serialisable: {exc}")
            return
        if len(encoded) > MAX_TASK_RESULT_BYTES:
            task.finish("error", error=(
                f"tool result ({len(encoded)} bytes) exceeds "
                f"{MAX_TASK_RESULT_BYTES}-byte cap — fetch via "
                f"paginated / narrower tool args"))
            return
        if task.cancel_event.is_set() and not task.timed_out.is_set():
            # Finished although cancelled: a cancel is a cancel.
            task.finish("cancelled", error="cancelled by axross/tasks/cancel")
            return
        task.finish("done", result=result, result_bytes=len(encoded))
    except CancelledError:
        if task.timed_out.is_set():
            task.finish("error", error=timeout_text)
        else:
            task.finish("cancelled", error="cancelled by axross/tasks/cancel")
    except Exception as exc:  # noqa: BLE001 — surface on task record
        task.finish("error", error=redact_text(_wire_text(str(exc))))
    finally:
        if timer is not None:
            timer.cancel()
        if registry is not None:
            registry.note_finished()


@dataclass
class _PreviewResult:
    """Marker return type from the ``preview`` handler. The dispatcher
    recognises it and emits an MCP ``image`` content block instead of
    the default ``text`` wrapper."""

    data_b64: str
    mime: str
    width: int = 0
    height: int = 0


class _ListResult(list):
    """A tool result that is a JSON array on the wire (its text content, as
    it always was) with *extra* fields for structuredContent, which must be
    an object: ``{<structured_key>: [...], **extra}`` (_Tool.structured_key)."""

    def __init__(self, items, **extra) -> None:
        super().__init__(items)
        self.extra = extra


@dataclass
class _Tool:
    name: str
    description: str
    schema: dict
    handler: Callable[[dict, _ToolContext], Any]
    write: bool = False  # mutating; gated behind --mcp-write (scripts: --mcp-allow-scripts)
    # Wall-clock ceiling for one invocation. A background timer flips
    # the ctx.cancel_event when the deadline passes; handlers that call
    # ctx.check_cancel() then raise CancelledError and the dispatcher
    # answers ERR_TIMEOUT (-32002). Tools that don't periodically
    # check cancel won't be force-killed — the timer just nudges them;
    # but every tool added after Commit 3 does check, so timeouts land
    # within one loop tick.
    timeout_seconds: float | None = None
    # Key of TIMEOUT_CLASSES; None takes the class from
    # _TIMEOUT_CLASS_BY_TOOL (default "quick").
    timeout_class: str | None = None
    # "core" (file tools), "write" (--mcp-write), "scripts"
    # (--mcp-allow-scripts) or a capability group of core.mcp_groups.
    group: str = "core"
    # False for tools that name their backends themselves (transfer) or
    # touch none (profiles, extensions): the multi-backend wiring then
    # leaves their schema without the generic ``backend`` argument.
    accepts_backend: bool = True
    # tools/list's display name (2025-06-18) and annotations (2025-03-26:
    # title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint).
    # None: taken from _TOOL_HINTS when the catalogue is built.
    title: str | None = None
    annotations: dict | None = None
    # JSON Schema of the object the tool returns (2025-06-18 outputSchema;
    # the result also goes out as structuredContent). Only for tools whose
    # result always has this shape - tests/test_mcp_protocol_revisions.py
    # checks real results against it. None: from _OUTPUT_SCHEMAS.
    output_schema: dict | None = None
    # Arguments the published inputSchema leaves out of ``required`` because
    # a ``<name>_b64`` twin may stand in for them (a top-level anyOf is
    # refused by some clients, the Anthropic API among them): the call is
    # still checked against them, after the twin was decoded into <name>.
    twin_required: tuple = ()
    # {argument: minimum} the server still accepts below the published
    # minimum, for callers that sent it before the schema said otherwise.
    legacy_minimum: dict = field(default_factory=dict)
    # A tool whose result is a JSON array: structuredContent (2025-06-18)
    # must be an object, so it carries the array under this key while the
    # text content stays the array clients have always read.
    structured_key: str | None = None
    # A tool served without --mcp-write that writes only through these
    # arguments, which exist only with it (export_metadata's out): its
    # manifest flags are its group's alone.
    write_args: tuple = ()


def _script_run_args(raw) -> list[str]:
    """script_run's ``args``: a list of at most MAX_SCRIPT_ARGS strings of
    at most MAX_SCRIPT_ARG_CHARS each, without NUL (argv cannot carry it).
    Checked here as well as by the schema: jsonschema is optional."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("run_script args must be a list of strings")
    if len(raw) > MAX_SCRIPT_ARGS:
        raise ValueError(f"run_script takes at most {MAX_SCRIPT_ARGS} args")
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("run_script args must be strings")
        if len(item) > MAX_SCRIPT_ARG_CHARS:
            raise ValueError(f"a run_script arg is longer than {MAX_SCRIPT_ARG_CHARS} characters")
        if "\x00" in item:
            raise ValueError("a run_script arg contains a NUL character")
    return list(raw)


def _script_run_timeout(raw) -> float:
    """script_run's ``timeout_s``: a finite number in (0, MAX_SCRIPT_TIMEOUT_S];
    DEFAULT_SCRIPT_TIMEOUT_S when absent."""
    import math

    if raw is None:
        return DEFAULT_SCRIPT_TIMEOUT_S
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError("run_script timeout must be a number of seconds")
    if not math.isfinite(raw) or not 0 < raw <= MAX_SCRIPT_TIMEOUT_S:
        raise ValueError(f"run_script timeout must be in (0, {MAX_SCRIPT_TIMEOUT_S:g}]")
    return float(raw)


def _backend_id_for(backend) -> str:
    """Stable id matching the convention used by the UI dialogs."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


def _streams_its_checksum(backend) -> bool:
    """True for a backend whose checksum() reads the whole file itself
    (the local file systems): no cheaper than streaming it here, and not
    cancellable."""
    try:
        from core.local_fs import LocalFS
    except ImportError:  # pragma: no cover
        return False
    return isinstance(backend, LocalFS)


#: Folders of kernel pseudo files: a "regular" file there (/proc/kmsg) has
#: size 0 and blocks a reader for good.
_PSEUDO_FILE_ROOTS = ("/proc/", "/sys/", "/dev/")


def _refuse_remote_special(backend, path: str) -> bool:
    """For an SFTP backend: OSError unless *path* - its link followed, as
    the server's hash command or a read would - is a regular file outside
    the kernel's pseudo file systems (``sha256sum`` of a link to /dev/zero
    ran on the server for good, of /proc/kmsg it held the channel 300 s).
    Returns whether the server's own hash command may run: not for a file
    of size 0 (a pseudo file says 0; an empty file is hashed here at once).
    Other backends have no devices to reach: True."""
    import posixpath
    import stat as _stat

    if _streams_its_checksum(backend):
        return True
    sftp = getattr(backend, "sftp", None)
    stat_of = getattr(sftp, "stat", None)
    if not callable(stat_of):
        return True
    normalize = getattr(sftp, "normalize", None)
    if callable(normalize):
        try:
            real = normalize(path)
        except Exception:  # noqa: BLE001 - the hash itself says what is wrong
            real = None
        if isinstance(real, str):
            real = posixpath.normpath(real) + "/"
            if any(real.startswith(prefix) for prefix in _PSEUDO_FILE_ROOTS):
                raise OSError(errno.EINVAL, f"checksum: {path} lies in a kernel pseudo file "
                              f"system ({real.rstrip('/')}); not hashed", path)
    try:
        st = stat_of(path)
    except Exception:  # noqa: BLE001 - the hash itself says what is wrong
        return True
    mode = getattr(st, "st_mode", None)
    if not isinstance(mode, int):
        return True  # no mode (a stand-in, a server that sends none): not known
    if not _stat.S_ISREG(mode):
        raise OSError(errno.EINVAL, f"checksum: {path} is not a regular file (a device, FIFO "
                      "or socket, perhaps behind a symlink); not hashed", path)
    size = getattr(st, "st_size", None)
    return not (isinstance(size, int) and size == 0)


def _hash_one_path(
    backend,
    path: str,
    algo: str,
    ctx: "_ToolContext",
    *,
    total_bytes: int | None = None,
    emit_byte_progress: bool = True,
) -> dict:
    """Compute a hashlib hash of one file via the backend.

    Shared by the single-file ``checksum`` tool and the per-file loop
    inside ``recursive_checksum``. The logic is:

    1. Ask ``backend.checksum(path, algorithm=algo)`` for a native
       fingerprint. Trust it only when either the returned string
       has no ``":"`` (raw hex from a backend that honours the
       algorithm kwarg — SSH, WebDAV) OR the prefix matches the
       requested algo (``md5:<hex>`` when md5 asked). Backends that
       ignore the algorithm kwarg (S3 always returns ``md5:..``,
       Dropbox returns ``dropbox:..``) fall through.
    2. Streaming fallback: read the file through ``open_read`` in
       STREAM_HASH_CHUNK byte chunks into ``hashlib.new(algo)``.
       ``ctx.check_cancel()`` runs before every chunk so a client
       cancel lands within one chunk; ``ctx.progress`` emits every
       STREAM_HASH_PROGRESS_EVERY chunks when ``emit_byte_progress``
       is True.

    Callers that already know the file's size pass it via
    ``total_bytes`` to skip a duplicate stat round-trip (list_dir
    hands the size out; recursive walks reuse it). When None, we
    stat lazily and fall back to "total unknown" if that fails.

    The byte-level progress is suppressed inside ``recursive_checksum``
    so the per-file progress (files_done/files_total) stays
    monotonic from the client's perspective. Mixing both scales
    under the same progressToken would make the number regress on
    each new file — MCP clients treat that as a bug.
    """
    import hashlib as _hashlib

    command_ok = _refuse_remote_special(backend, path)
    # A local file system's "native" checksum streams the whole file in one
    # call that no cancel reaches (a 40 GiB file ran on after tasks/cancel
    # and after the tool's timeout): hash it here, chunk by chunk.
    native = "" if _streams_its_checksum(backend) or not command_ok else (
        backend.checksum(path, algorithm=algo) or "")
    trusted_native = ""
    if ":" in native:
        prefix, _, tail = native.partition(":")
        if prefix == algo and tail:
            trusted_native = tail
    elif native:
        trusted_native = native
    if trusted_native:
        return {"value": trusted_native, "source": "native"}
    size_for_total = total_bytes
    size_known = size_for_total is not None
    if size_for_total is None:
        try:
            size_for_total = int(getattr(backend.stat(path), "size", 0) or 0)
            size_known = True
        except OSError:
            size_for_total = 0
    hasher = _hashlib.new(algo)
    bytes_done = 0
    chunks_since_progress = 0
    # A remote's file is hashed up to the size it gave and some slack: one
    # that sends without end (a link to /dev/zero, a lying server) stops.
    limit = (None if _streams_its_checksum(backend) or not size_known
             else size_for_total + STREAM_HASH_SLACK_BYTES)
    with backend.open_read(path) as fh:
        while True:
            ctx.check_cancel()
            chunk = fh.read(STREAM_HASH_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            bytes_done += len(chunk)
            if limit is not None and bytes_done > limit:
                raise OSError(errno.EFBIG,
                              f"checksum: {path} sent more than {limit} bytes for a file "
                              f"of {size_for_total}; not hashed", path)
            chunks_since_progress += 1
            if emit_byte_progress and chunks_since_progress >= STREAM_HASH_PROGRESS_EVERY:
                chunks_since_progress = 0
                ctx.progress(
                    progress=float(bytes_done),
                    total=(float(size_for_total) if size_for_total else None),
                    message=f"hashing {path} — {bytes_done} bytes",
                )
    return {"value": hasher.hexdigest(), "source": "stream"}


def _enforce_root(path: str, root: str, *, real_root: str | None = None) -> str:
    """Normalise *path* and refuse it when it escapes *root*.

    The MCP server is configured with one backend rooted at a
    directory the user explicitly opted into (default: $HOME for
    LocalFS). Without this check, an LLM client could ask to
    ``write_file("/etc/passwd")`` and the backend would happily
    obey because the path is absolute and the backend doesn't
    enforce its own root.

    Two-pass check:

    1. ``abspath`` normalises ``..`` / ``.`` segments so a payload
       like ``/root/../etc/passwd`` collapses to ``/etc/passwd``
       and fails the prefix match below.
    2. ``realpath`` walks the filesystem, resolving every symlink
       component, and we re-check the prefix on the resolved form.
       Without this second pass, a symlink ``/root/escape → /``
       (placed under the root either legitimately or by the LLM
       using the ``symlink`` write tool itself) would let
       ``write_file("/root/escape/etc/cron.d/evil")`` slip through:
       abspath sees ``/root/escape/etc/cron.d/evil`` which starts
       with the root prefix, but the backend writes to
       ``/etc/cron.d/evil``.

    Non-existent paths are tolerated: ``realpath`` of a
    not-yet-created file returns its would-be absolute path with
    symlink-resolved parents. The write then happens at that
    resolved location, which is still prefix-checked.

    *real_root* is ``realpath(abspath(root))`` when the caller already
    resolved it - once per tool call for a tool that checks many paths
    (:func:`_root_resolver`); the result is then exactly the same as
    without it. The path's own realpath is always taken here. Never
    resolve a root once for longer than one call: a root re-pointed
    while the server runs must be seen by the next call.

    Returns the cleaned absolute path on success. Raises
    :class:`PermissionError` when either pass finds an escape; the
    dispatcher answers it as a tool result with ``isError`` and
    ``_meta.type`` = ``"PermissionError"`` (only ValueError / TypeError
    map to the JSON-RPC error -32602).
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    # ``os.path`` resolution rather than ``backend.normalize`` —
    # backend implementations vary and we want a stable attacker-
    # resistant shape no matter which backend got wired in.
    import os.path as op

    abs_root = op.abspath(root or "/")
    abs_path = op.abspath(op.join(abs_root, path) if not op.isabs(path) else path)

    def _inside(candidate: str) -> bool:
        # Trailing separator guard: prevents ``/etcother`` from
        # sliding through a naïve prefix check on ``/etc``.
        if abs_root == "/":
            return True
        root_prefix = abs_root.rstrip("/") + "/"
        return candidate == abs_root or candidate.startswith(root_prefix)

    if not _inside(abs_path):
        raise PermissionError(f"path {path!r} escapes the configured MCP root {abs_root!r}")
    # Second pass: resolve symlinks. realpath of a non-existent
    # leaf is the abspath with symlink-resolved parents (strict=
    # False is the default in Python 3.10+), which is exactly the
    # semantic we want — the write will land there.
    real_path = op.realpath(abs_path)
    # The root itself has to be realpath'd too: an operator who set
    # ``--mcp-root`` to a path whose parents contain a symlink
    # should still get a consistent comparison.
    if real_root is None:
        real_root = op.realpath(abs_root)
    # Rebuild the "inside" check against the realpath form.
    if real_root == "/":
        return real_path
    real_prefix = real_root.rstrip("/") + "/"
    if real_path == real_root or real_path.startswith(real_prefix):
        expected_real_path = op.join(real_root, op.relpath(abs_path, abs_root))
        if op.normpath(real_path) == op.normpath(expected_real_path):
            return abs_path
        return real_path
    raise PermissionError(
        f"path {path!r} resolves to {real_path!r} via symlink, "
        f"which escapes the configured MCP root {real_root!r}"
    )


def _root_resolver():
    """An ``enforce(path, root)`` like :func:`_enforce_root` that resolves
    each root once, at its first use, and reuses it for the rest of this
    resolver's life. Make one per tool call - never keep one across calls,
    so a root re-pointed between calls is resolved again."""
    import os.path as op

    resolved: dict[str, str] = {}

    def enforce(path: str, root: str) -> str:
        real_root = resolved.get(root)
        if real_root is None:
            real_root = resolved[root] = op.realpath(op.abspath(root or "/"))
        return _enforce_root(path, root, real_root=real_root)

    return enforce


def _enforce_root_entry(path: str, root: str) -> str:
    """Like :func:`_enforce_root`, for an operation on the entry itself.

    remove / rename / move act on the directory entry *path* names. When
    that entry is a symlink, resolving it (as :func:`_enforce_root` does)
    hands the link's TARGET to the backend: ``remove(link, recursive)``
    deleted the folder the link points to. Here only the parent is
    resolved and confined; the final name is joined back unresolved.

    The whole-path check still runs first as a second gate, so a link
    that points out of the root stays refused exactly as before.
    """
    import os.path as op

    resolved = _enforce_root(path, root)
    abs_root = op.abspath(root or "/")
    abs_path = op.abspath(op.join(abs_root, path) if not op.isabs(path) else path)
    name = op.basename(abs_path)
    if abs_path == abs_root or not name:
        # The root itself (or "/"): there is no parent inside the root;
        # the caller's root refusal decides.
        return resolved
    parent = _enforce_root(op.dirname(abs_path), root)
    return op.join(parent, name)


def _refuse_protected(path: str, *, entry: bool = False, granted=()) -> str:
    """*path* unless it is (or lies in) a protected place of the home
    folder (core.protected_places); PermissionError otherwise. *entry*:
    the path's entry is created, removed or moved, so a folder holding a
    protected place is refused too (deleting ~/.config takes ~/.config/autostart).
    *granted*: the writable roots - one inside a hidden folder of the home
    or a settings folder lifts default-deny below it."""
    from core import protected_places

    reason = protected_places.refusal(path, entry=entry, granted=granted)
    if reason is not None:
        raise PermissionError(reason)
    return path


#: The mode bits MCP chmod sets (core.mcp_server): read and execute for
#: everyone, write for the owner only - no setuid, setgid or sticky bit.
_CHMOD_ALLOWED_BITS = 0o755
#: The mode strings chmod parses: octal, with an optional 0 / 0o prefix. The
#: handler then refuses every bit outside _CHMOD_ALLOWED_BITS with a reason
#: (a tighter pattern answered only "does not match").
_CHMOD_PATTERN = "^(0[oO]?)?[0-7]{1,4}$"


def _refuse_configured_root(path: str, root: str, operation: str) -> None:
    """Refuse write operations that target the MCP root object itself."""
    import os.path as op

    safe_root = op.realpath(op.abspath(root or "/"))
    safe_path = op.realpath(path)
    if op.normcase(safe_path) == op.normcase(safe_root):
        raise PermissionError(
            f"{operation} refuses to modify the configured MCP root itself: {safe_root!r}"
        )


def _confine_local(backend, backends: dict | None, roots: tuple, *,
                   allow_secret_reads: bool = False):
    """*backend* and the *backends* registry with every plain LocalFS
    replaced by a :class:`core.confined_fs.ConfinedLocalFS` beneath *roots*.
    A read through a symlink that is a path's last component is refused for
    the secret files unless *allow_secret_reads*."""
    from core import confined_fs

    def follow_check(path: str) -> None:
        if allow_secret_reads:
            return
        from core import protected_places

        reason = protected_places.read_refusal(path, granted=roots)
        if reason is not None:
            raise PermissionError(reason)

    def scanning(handle, path):
        from core.protected_places import SecretScanningReader

        return SecretScanningReader(handle, path)

    def confine(candidate):
        if confined_fs.confinable(candidate):
            # Every local read is scanned for a key in the whole stream, not
            # only in the first MiB read_refusal looks at: what a tool
            # copies, packs, encrypts or sends to a remote is read here.
            return confined_fs.ConfinedLocalFS(
                roots, follow_check=follow_check,
                read_wrap=None if allow_secret_reads else scanning)
        return candidate

    confined = confine(backend)
    if backends:
        backends = {
            bid: (confined if b is backend else confine(b)) for bid, b in backends.items()
        }
    return confined, backends


#: Held by every mutating file tool while it runs (core.mcp_server
#: _serialize_mutations): two calls of one client - the HTTP transport and
#: tasks/start run them in threads - cannot interleave a rename + symlink
#: with another call's check and write. Defence in depth beside
#: core.confined_fs, and the only guard where there is no dir_fd (Windows).
#: One key per backend a call changes ("local" for this machine): a
#: transfer whose remote CLOSE hangs for 30 minutes held one lock for the
#: whole process, and every local write timed out meanwhile.
#
#: Mutating tools that do not touch this machine's files themselves, or run
#: for minutes: commands on remote hosts, the user's own LLM, scripts.
_UNSERIALIZED_GROUPS = frozenset({"exec", "agent"})
_UNSERIALIZED_TOOLS = frozenset({"script_run"})
#: Tools that change their source too (moved away).
_MOVING_TOOLS = frozenset({"transfer_move"})
#: The lock key of this machine's disk.
LOCAL_LOCK_KEY = "local"


class _MutationTable:
    """Which backends write calls hold, and who waits for them.

    A call takes every key it needs at once or none (it never holds one
    while waiting for another: a move from a remote whose upload hung held
    the local disk meanwhile), and waiting is first come, first served: a
    call goes ahead only when no call that came earlier and could go now
    needs one of its keys (try-lock polling let a 30 ms write wait 20 s
    behind busy writers). A key is held by one thread at a time, again by the same
    thread (a tool inside a tool); a key nobody holds is not kept (no lock
    objects to drop while a waiter still has one: two writes ran on one
    backend at once past 64 backends)."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._held: dict[str, list] = {}  # key -> [owner thread id, depth]
        self._queue: list = []  # [ticket, keys, thread id] in arrival order
        self._tickets = 0

    def _free_for(self, keys, me) -> bool:
        return all(key not in self._held or self._held[key][0] == me for key in keys)

    def acquire(self, keys, ctx) -> None:
        me = threading.get_ident()
        keys = list(keys)
        with self._cond:
            self._tickets += 1
            entry = [self._tickets, set(keys), me]
            self._queue.append(entry)
            try:
                while True:
                    # An earlier call that could go now (every key it needs
                    # is free) comes first for the keys it shares with this
                    # one; one still waiting for a held key reserves nothing
                    # (it would hold the rest while it waits).
                    earlier = self._queue[: self._queue.index(entry)]
                    blocked = any(other[2] != me and other[1] & entry[1]
                                  and self._free_for(other[1], other[2]) for other in earlier)
                    if not blocked and self._free_for(keys, me):
                        for key in keys:
                            row = self._held.setdefault(key, [me, 0])
                            row[1] += 1
                        return
                    if ctx is not None and ctx.is_cancelled:
                        raise CancelledError("cancelled while waiting for another write to "
                                             "finish")
                    self._cond.wait(0.2)
            finally:
                self._queue.remove(entry)
                self._cond.notify_all()

    def release(self, keys) -> None:
        with self._cond:
            for key in keys:
                row = self._held.get(key)
                if row is None:
                    continue
                row[1] -= 1
                if row[1] <= 0:
                    del self._held[key]
            self._cond.notify_all()


_MUTATIONS = _MutationTable()


def _lock_key_for(backend) -> str:
    """One key per backend object; this machine's disk (the server's own
    backend, a confined one, any LocalFS) is :data:`LOCAL_LOCK_KEY`."""
    from core.local_fs import LocalFS

    if backend is None or isinstance(backend, LocalFS):
        return LOCAL_LOCK_KEY
    return f"backend:{id(backend)}"


def _changed_backends(name: str, args, resolve=None) -> list[str]:
    """The lock keys of the backends a write call of *name* changes, sorted.
    *resolve(kind, value)* turns a ``backend`` / ``src_backend`` /
    ``dst_backend`` argument into its backend object (the call's own
    lookup); one that does not resolve fails the call anyway - it takes
    the local lock meanwhile, never one of its own."""
    def key(kind: str, value) -> str:
        if resolve is None:
            return LOCAL_LOCK_KEY
        try:
            return _lock_key_for(resolve(kind, value))
        except Exception:  # noqa: BLE001 - the call reports it
            return LOCAL_LOCK_KEY

    if not isinstance(args, dict):
        return [LOCAL_LOCK_KEY]
    if "dst_backend" in args or "src_backend" in args or name.startswith("transfer_"):
        keys = {key("dst_backend", args.get("dst_backend"))}
        if name in _MOVING_TOOLS:
            keys.add(key("src_backend", args.get("src_backend")))
    else:
        keys = {key("backend", args.get("backend"))}
    return sorted(keys)


def _serialized(handler, name: str = "", resolve=None):
    def run(args, ctx):
        keys = _changed_backends(name, args, resolve)
        _MUTATIONS.acquire(keys, ctx)
        try:
            return handler(args, ctx)
        finally:
            _MUTATIONS.release(keys)

    run.__wrapped__ = handler
    return run


def _serialize_mutations(tools: list, resolve=None) -> None:
    """Run every mutating file tool under the locks of the backends it
    changes (:class:`_MutationTable`, keys by :func:`_lock_key_for` of
    what *resolve* makes of its backend arguments)."""
    for tool in tools:
        if (
            tool.write
            and tool.group not in _UNSERIALIZED_GROUPS
            and tool.name not in _UNSERIALIZED_TOOLS
            and not getattr(tool.handler, "__wrapped__", None)
        ):
            tool.handler = _serialized(tool.handler, tool.name, resolve)


def _exec_allowed_by_policy() -> bool:
    """The security mode's word on remote command execution (paranoid: no)."""
    from core.security_mode import current_policy

    return bool(current_policy().allow_remote_exec)


def _build_tools(
    backend,
    *,
    allow_write: bool,
    backend_id: str | None = None,
    root: str | None = None,
    backends: dict | None = None,
    allow_scripts: bool = False,
    tool_groups: frozenset[str] | None = None,
    allow_exec: bool = False,
    extra_roots: tuple = (),
    remote_registry=None,
    allow_secret_reads: bool = False,
) -> list[_Tool]:
    """Build the catalogue. Write tools are added only when allowed.

    *allow_secret_reads* (``--mcp-allow-secret-reads``): tools may hand out
    the contents of secret files (core.protected_places.read_refusal:
    axross's OAuth and MCP tokens, chat and Bluetooth keys, SSH and GnuPG
    private keys). Off, every tool that returns or copies contents refuses
    them, whatever the root; their names are still listed.

    *remote_registry* is a :class:`core.mcp_groups.RemoteRegistry` the
    caller owns - with connections it lent (``attach``) and its gate -
    instead of the one the ``remote`` group makes for itself. The caller
    closes it.

    *extra_roots* are further ``(folder, writable)`` pairs beside *root*
    (the agent's extra folders): tools read in every one and write only in
    *root* and the writable ones. A relative path belongs to *root*.

    *tool_groups* names the optional capability groups
    (:data:`core.mcp_groups.GROUPS`) to add on top of the file tools;
    empty or None keeps the plain file-tool surface. A group's mutating
    tools follow *allow_write* like the write tools do.

    *backend_id* is the metadata-index key the search tool is allowed
    to filter against. Defaults to the configured backend's own id —
    never None at runtime, so an LLM client can't enumerate paths
    that live on a backend we don't expose.

    *root* scopes backend tools: every path that can touch backend
    data is resolved against it and rejected if it escapes. ``None``
    preserves the legacy unrestricted helper behaviour used by some
    direct unit tests; GUI/CLI entry points pass a concrete root for
    untrusted-LLM scenarios.

    *backends* is an optional registry of ``{id: backend}`` that lets
    each tools/call carry a ``"backend": "<id>"`` argument to pick a
    target other than the default. The ``backend`` positional arg
    remains the fallback used when the call omits ``backend``. This
    keeps single-backend deployments unchanged (no schema churn) and
    only adds the backend-selection field when a registry is wired."""
    from core import mcp_groups as _groups

    groups = _groups.check_groups(tool_groups or ())
    server_backend_id = backend_id or _backend_id_for(backend)
    read_root = root
    write_root = root or "/"
    extras = tuple((str(path), bool(writable)) for path, writable in (extra_roots or ()))
    if extras and root is None:
        raise ValueError("extra_roots need a root")
    read_roots = (root, *(path for path, _ in extras)) if root is not None else ()
    write_roots = (write_root, *(path for path, writable in extras if writable))
    if read_roots:
        # The checks below look at a path as a string; the local file
        # system then opens it beneath its root's descriptor without
        # following a symlink (core.confined_fs), so a folder of the path
        # swapped for a link between the check and the use is refused,
        # not followed out of the root or into a protected place.
        backend, backends = _confine_local(backend, backends, read_roots,
                                           allow_secret_reads=allow_secret_reads)

    def _confined(path: str, roots: tuple, enforce=None) -> str:
        """*enforce* (default _enforce_root) against the first root that
        holds *path*; a relative path is only ever the main root's."""
        import os.path as op

        enforce = enforce or _enforce_root
        if len(roots) == 1 or not isinstance(path, str) or not op.isabs(path):
            return enforce(path, roots[0])
        first: PermissionError | None = None
        for candidate in roots:
            try:
                return enforce(path, candidate)
            except PermissionError as exc:
                first = first or exc
        raise first

    # Per-call backend selector. When a registry is configured, tool
    # callers can pass ``{"backend": "<id>"}`` to route the invocation
    # to a non-default backend. Missing / None / absent-from-registry
    # falls back to the outer ``backend`` (the default) or raises
    # ValueError if the caller named an unknown id.
    _default_backend = backend

    # The ``remote`` group opens saved profiles at run time. They live in
    # a per-session registry beside the static ``backends`` one, and the
    # static registry gains the default backend as "local" so every
    # backend has an id.
    # The exec group's commands run on remote backends that list_backends
    # names (can_run_commands): it needs the registry as the remote group does.
    exec_served = "exec" in groups and bool(allow_exec) and _exec_allowed_by_policy()
    if remote_registry is None and ("remote" in groups or exec_served):
        remote_registry = _groups.RemoteRegistry()
    if remote_registry is not None:
        backends = dict(backends or {})
        if not any(b is backend for b in backends.values()):
            backends["local" if "local" not in backends else "default"] = backend

    def _is_remote(active_backend) -> bool:
        return remote_registry is not None and remote_registry.holds(active_backend)

    def _resolve_backend(args):
        bid = args.get("backend") if isinstance(args, dict) else None
        if not bid:
            return _default_backend
        if remote_registry is not None:
            opened = remote_registry.get(bid)
            if opened is not None:
                return opened
        if not backends:
            # Single-backend deployment; the arg is ignored silently
            # rather than erroring — gentler on clients that always
            # pass a backend field by habit.
            return _default_backend
        b = backends.get(bid)
        if b is None:
            raise ValueError(f"unknown backend {bid!r}; call 'list_backends' to see available ids")
        return b

    def _backend_by_id(bid):
        """Strict lookup for tools that name two backends (transfer):
        an unknown id is an error even without a registry."""
        if bid is None or bid == "":
            return _default_backend
        if not isinstance(bid, str):
            raise ValueError("a backend id must be a string")
        if remote_registry is not None and remote_registry.get(bid) is not None:
            return remote_registry.get(bid)
        if backends and bid in backends:
            return backends[bid]
        if bid == "local":
            return _default_backend
        raise ValueError(f"unknown backend {bid!r}; call 'list_backends' to see available ids")

    def _call_scope(active_backend=None):
        """:func:`_scope_path` for the many paths of ONE tool call (grep,
        the index search, recursive_checksum): each root is resolved once
        for the call, every path still on its own. A new one per call."""
        if active_backend is not None and _is_remote(active_backend):
            return _groups.check_remote_path
        if read_root is None:
            return lambda path: path
        enforce = _root_resolver()
        return lambda path: _confined(path, read_roots, enforce)

    def _scope_path(path: str, active_backend=None) -> str:
        """Apply the configured MCP root to a tool path.

        ``resources/read`` already enforces the root through
        _ResourceCatalog. The tool catalogue needs the same guard
        because clients can call read_file/checksum/grep directly
        without going through resource URIs. A backend opened through
        the ``remote`` group is not local disk: --mcp-root does not
        apply, its paths are only checked for shape.
        """
        if active_backend is not None and _is_remote(active_backend):
            return _groups.check_remote_path(path)
        if read_root is None:
            return path
        return _confined(path, read_roots)

    def _refuse_read_only(path: str) -> str:
        """A path whose nearest folder is a read-only extra one is not
        written, even when a writable folder around it holds it too."""
        import os.path as op

        if not extras:
            return path
        here = {op.abspath(path), op.realpath(path)}
        best: tuple[int, bool] | None = None
        for folder, writable in ((write_root, True), *extras):
            for base in {op.abspath(folder), op.realpath(folder)}:
                base = base.rstrip(op.sep) or op.sep
                if any(h == base or h.startswith(base + op.sep) for h in here):
                    depth = base.count(op.sep)
                    if best is None or depth > best[0] or (depth == best[0] and not writable):
                        best = (depth, writable)
        if best is not None and not best[1]:
            raise PermissionError(f"{path} is in a read-only folder")
        return path

    def _refuse_read_only_below(path: str) -> str:
        """An entry removed or moved with its subtree may not hold a
        read-only extra folder: deleting or moving ``main/sub`` would take
        ``main/sub/keep`` along."""
        import os.path as op

        if not extras:
            return path
        entry = op.abspath(path).rstrip(op.sep) or op.sep
        # The entry itself is acted on (a symlink is not followed); the
        # folders on the way to it may be links.
        here = {entry, op.join(op.realpath(op.dirname(entry)), op.basename(entry))}
        for folder, writable in extras:
            if writable:
                continue
            for base in {op.abspath(folder), op.realpath(folder)}:
                if any(base.startswith(h.rstrip(op.sep) + op.sep) for h in here):
                    raise PermissionError(f"{path} holds a read-only folder")
        return path

    def _typed(path: str) -> str:
        """*path* as the client typed it, made absolute (a relative path is
        the main root's): the protected places and secrets are checked on
        this name too, not only on where its symlinks lead."""
        import os.path as op

        return op.abspath(path if op.isabs(path) else op.join(root or "/", path))

    def _write_path(path: str, active_backend) -> str:
        """Confine a path a mutating tool writes, moves or deletes. On a
        remote backend of a production-flagged profile every mutation
        is refused (the GUI's countdown cannot be shown over MCP)."""
        if _is_remote(active_backend):
            remote_registry.refuse_production(active_backend)
            return _groups.check_remote_path(path, mutating=True)
        confined = _refuse_read_only(_confined(path, write_roots))
        if _typed(path) != confined:
            _refuse_protected(_typed(path), granted=write_roots)
        return _refuse_protected(confined, granted=write_roots)

    def _entry_path(path: str, active_backend) -> str:
        """Confine a path whose directory entry itself is removed or
        moved: a symlink there is acted on, never its target."""
        if _is_remote(active_backend):
            remote_registry.refuse_production(active_backend)
            return _groups.check_remote_path(path, mutating=True)
        confined = _refuse_read_only_below(
            _refuse_read_only(_confined(path, write_roots, _enforce_root_entry)))
        if _typed(path) != confined:
            _refuse_protected(_typed(path), entry=True, granted=write_roots)
        return _refuse_protected(confined, entry=True, granted=write_roots)

    def _entry_checker(active_backend):
        """``check(path) -> path``: :func:`_entry_path` (and the secret
        check) for the many new entries of ONE tool call - an archive's
        members - with the protected places resolved once."""
        if _is_remote(active_backend):
            return lambda path: _entry_path(path, active_backend)
        from core import protected_places

        places = protected_places.write_checker(granted=write_roots, members=True)
        secret = _secret_check(active_backend)

        def check(path: str) -> str:
            confined = _refuse_read_only_below(
                _refuse_read_only(_confined(path, write_roots, _enforce_root_entry)))
            for name in dict.fromkeys((_typed(path), confined)):
                reason = places(name, entry=True)
                if reason is not None:
                    raise PermissionError(reason)
            if _typed(path) != confined:
                secret(_typed(path), entry=True)
            return secret(confined, entry=True)

        return check

    def _refuse_served_secret(active_backend, path: str, offset: int, length: int) -> None:
        """A read that reaches past the first bytes read_refusal looked at
        (protected_places.SECRET_CONTENT_SCAN): look at what it serves -
        and a key's length around it, for a window that starts or ends
        inside a key - before handing it out."""
        if allow_secret_reads:
            return
        from core import protected_places

        margin = 16 * 1024
        start = max(0, offset - margin)
        with active_backend.open_read(path) as fh:
            _skip_stream(fh, start)
            window, _ = _read_capped_stream(fh, (offset - start) + length + margin)
        inside = protected_places.secret_in_content(window)
        if not inside:
            # The window may lie in the middle of a key block longer than
            # the margin: walk back over its base64 lines to a BEGIN line.
            try:
                with active_backend.open_read(path) as fh:
                    inside = protected_places.inside_key_block(fh, offset)
            except PermissionError:
                inside = True  # the scanning reader met the key on the way
            except (OSError, ValueError, io.UnsupportedOperation):
                inside = False
        if inside:
            raise PermissionError(
                f"{path}: refused - this part of the file holds a private key "
                "(--mcp-allow-secret-reads hands secrets out)")

    def _secret_check(active_backend):
        """``refuse(path, entry=False) -> path`` for the paths of ONE tool
        call: PermissionError when *path*'s contents are a secret
        (core.protected_places: axross's tokens and keys, SSH and GnuPG
        private keys) and *allow_secret_reads* is off. *entry*: the path is
        copied or moved whole, so a folder holding a secret is refused too.
        Names stay listable."""
        if allow_secret_reads:
            return lambda path, *, entry=False: path
        from core import protected_places

        if _is_remote(active_backend):
            # A remote's secrets by their names: ~/.ssh's private keys,
            # .env, credentials files... (the local rules need this
            # machine's home folder and the file's content).
            def refuse_remote(path: str, *, entry: bool = False) -> str:
                reason = protected_places.remote_secret_refusal(path, entry=entry)
                if reason is not None:
                    raise PermissionError(reason)
                return path

            return refuse_remote
        check = protected_places.secret_checker(granted=read_roots)

        def refuse(path: str, *, entry: bool = False) -> str:
            reason = check(path, entry=entry)
            if reason is not None:
                raise PermissionError(reason)
            return path

        return refuse

    def _refuse_special_remote(active_backend, path: str, tool: str) -> None:
        """A remote's server-side copy (``cp -p``) follows a symlink and
        reads a device without end (/zero -> /dev/zero ran until the disk
        was full): its source must be a regular file or a folder."""
        if not _is_remote(active_backend):
            return
        why = _groups._special_source(active_backend, path, None)
        if why is not None:
            raise ValueError(f"{tool} copies regular files and folders; {path} is a {why}")

    def _refuse_secret(path: str, active_backend, *, entry: bool = False) -> str:
        """:func:`_secret_check` for one path."""
        return _secret_check(active_backend)(path, entry=entry)

    def _read_path(path: str, active_backend=None) -> str:
        """:func:`_scope_path` for a path whose contents a tool hands out:
        refused when the name typed, a symlink on the way or where it leads
        is a secret (or in a default-deny place of the read side)."""
        scoped = _scope_path(path, active_backend)
        if (not _is_remote(active_backend) and isinstance(path, str)
                and _typed(path) != scoped):
            _refuse_secret(_typed(path), active_backend)
        return _refuse_secret(scoped, active_backend)

    def _refuse_root(path: str, active_backend, operation: str) -> None:
        """Refuse a mutation of the configured root object itself."""
        if _is_remote(active_backend):
            return
        for configured in (write_root, *(p for p, _ in extras)):
            _refuse_configured_root(path, configured, operation)

    def _refuse_moved_links(src: str, dst: str, active_backend) -> None:
        """PermissionError when moving *src* to *dst* re-points a relative
        symlink - the entry itself or one in a moved folder - outside a
        writable root or at a protected place: a link refused when made at
        ``a/l`` (``../../.ssh``) was made at ``a/b/l`` and renamed up. Each
        link whose target changes is checked as if made at its new place;
        absolute links (and moves within one folder) point where they did."""
        import os
        import os.path as op

        if _is_remote(active_backend):
            return

        def check(link: str, new_link: str, real_src: str | None) -> None:
            target = os.readlink(link)
            if op.isabs(target):
                return
            before = op.realpath(op.join(op.dirname(link), target))
            if real_src is not None and (before == real_src
                                         or before.startswith(real_src.rstrip(os.sep) + os.sep)):
                after = op.join(dst, op.relpath(before, real_src))  # inside the moved folder
            else:
                after = op.realpath(op.join(op.dirname(new_link), target))
            if after == before:
                return
            try:
                _refuse_protected(_write_path(after, active_backend), entry=True,
                                  granted=write_roots)
            except PermissionError as exc:
                raise PermissionError(
                    f"{link}: moved to {new_link}, the symlink would point to {after}: {exc}"
                ) from exc

        if op.islink(src):
            check(src, dst, None)
            return
        if not op.isdir(src):
            return
        if op.realpath(op.dirname(src)) == op.realpath(op.dirname(dst)):
            return  # renamed in its folder: every ".." leads where it did
        real_src = op.realpath(src)
        count = 0
        for folder, dirs, files in os.walk(src):
            for name in dirs + files:
                count += 1
                if count > MOVED_LINK_CHECK_LIMIT:
                    raise PermissionError(
                        f"{src} holds more than {MOVED_LINK_CHECK_LIMIT} entries: their links "
                        "cannot all be checked - move it in smaller parts")
                path = op.join(folder, name)
                if op.islink(path):
                    check(path, op.join(dst, op.relpath(path, src)), real_src)

    def _safe_child_path(active_backend, parent: str, name: str) -> str | None:
        from core.path_policy import safe_join

        try:
            return safe_join(active_backend, parent, name)
        except ValueError as exc:
            log.warning("MCP: skipping unsafe backend entry %r: %s", name, exc)
            return None

    def _list_dir(args, ctx):
        backend = _resolve_backend(args)
        path = _scope_path(args.get("path") or "/", backend)
        entries = backend.list_dir(path)
        return [
            {
                "name": getattr(it, "name", ""),
                "is_dir": bool(getattr(it, "is_dir", False)),
                "is_link": bool(getattr(it, "is_link", False)),
                "size": int(getattr(it, "size", 0) or 0),
                "modified": (
                    getattr(it, "modified", None).isoformat()
                    if getattr(it, "modified", None)
                    else None
                ),
            }
            for it in entries
            if getattr(it, "name", "") and getattr(it, "name", "") not in (".", "..")
        ]

    def _stat(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("stat requires a path")
        typed = path
        path = _scope_path(path, backend)
        item = backend.stat(path)
        bits = getattr(item, "permissions", 0)
        if _is_remote(backend) or read_root is None:
            is_link = bool(getattr(item, "is_link", False))
        else:
            import os.path as op

            # The path as typed (inside the root - _scope_path checked it):
            # the fields describe where it leads, is_link whether it leads on.
            is_link = op.islink(_typed(typed))
        return {
            "name": getattr(item, "name", ""),
            "is_dir": bool(getattr(item, "is_dir", False)),
            "is_link": is_link,
            "size": int(getattr(item, "size", 0) or 0),
            "modified": (
                getattr(item, "modified", None).isoformat()
                if getattr(item, "modified", None)
                else None
            ),
            # What chmod would replace: octal, or null where the backend has
            # no POSIX bits (it reports 0 then).
            "mode": f"{int(bits) & 0o7777:04o}" if isinstance(bits, int) and bits else None,
        }

    def _window_args(args, tool):
        """encoding, cap and offset of a read_file / open_version_read call."""
        encoding = args.get("encoding") or "base64"
        if encoding not in ("base64", "text"):
            raise ValueError(f"{tool}: encoding must be 'base64' or 'text'")
        cap = int(args.get("max_bytes") or MAX_READ_BYTES)
        cap = max(0, min(cap, MAX_READ_BYTES))
        offset = args.get("offset") or 0
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError(f"{tool}: offset must be a whole number >= 0")
        return encoding, cap, offset

    def _read_window(opened, encoding, cap, offset):
        """``(offset, data, truncated)``: the bytes a read hands out from the
        open stream *opened*, from *offset* on (text: whole characters)."""
        with opened as fh:
            if offset:
                _skip_stream(fh, offset)
            if encoding == "text":
                # Three bytes of look-ahead: a character the cap cuts is
                # finished when it is the only one (max_bytes smaller than
                # one character returned "" with next_offset == offset, and
                # a client paging on that looped forever) and left for the
                # next read otherwise.
                ahead, more = _read_capped_stream(fh, cap + 3)
            else:
                data, truncated = _read_capped_stream(fh, cap)
        if encoding == "text":
            lead = 0
            if offset:
                # Started inside a UTF-8 character: begin at the next one.
                while lead < min(3, len(ahead)) and 0x80 <= ahead[lead] <= 0xBF:
                    lead += 1
            offset += lead
            data = _text_window(ahead[lead:], cap, more)
            truncated = more or lead + len(data) < len(ahead)
        return offset, data, truncated

    def _window_result(data, encoding, offset, truncated):
        extra = {"offset": offset, "next_offset": offset + len(data)} if offset or truncated else {}
        if encoding == "text":
            import codecs

            # A cut inside a multi-byte character is the cap, not a bad
            # byte: final=False keeps that tail out of the text.
            # _text_window never cuts a character: what is left undecodable
            # is a bad byte, shown as U+FFFD.
            text = codecs.getincrementaldecoder("utf-8")("replace").decode(data, final=True)
            strict = codecs.getincrementaldecoder("utf-8")("strict")
            try:
                strict.decode(data, final=True)
                replaced = False
            except UnicodeDecodeError:
                replaced = True
            return {"text": text, "size": len(data), "truncated": truncated, "replaced": replaced,
                    **extra}
        return {
            "content_b64": base64.b64encode(data).decode("ascii"),
            "size": len(data),
            "truncated": truncated,
            **extra,
        }

    def _refuse_key_in(data, path) -> None:
        if not allow_secret_reads:
            from core import protected_places

            if protected_places.secret_in_content(data):
                raise PermissionError(f"{path}: refused - this part of the file holds a "
                                      "private key (--mcp-allow-secret-reads hands secrets out)")

    def _read_file(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("read_file requires a path")
        path = _read_path(path, backend)
        encoding, cap, offset = _window_args(args, "read_file")
        offset, data, truncated = _read_window(backend.open_read(path), encoding, cap, offset)
        # A remote file is not scanned at open (review B): every window is.
        if offset + len(data) > _secret_scan_limit() or _is_remote(backend):
            _refuse_served_secret(backend, path, offset, len(data))
        if _is_remote(backend):
            # A remote file is not scanned at open: what is served is.
            _refuse_key_in(data, path)
        return _window_result(data, encoding, offset, truncated)

    def _checksum(args, ctx):
        """Return a content hash of ``path``. See :func:`_hash_one_path`
        for the native-vs-streaming decision and the cancel / progress
        contract."""
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("checksum requires a path")
        path = _read_path(path, backend)
        algo = (args.get("algorithm") or "sha256").lower()
        if algo not in _HASHLIB_ALGOS:
            raise ValueError(
                f"checksum algorithm must be one of {sorted(_HASHLIB_ALGOS)}; got {algo!r}",
            )
        result = _hash_one_path(backend, path, algo, ctx)
        return {
            "value": result["value"],
            "algorithm": algo,
            "source": result["source"],
        }

    def _search(args, ctx):
        from core import metadata_index as MX

        # Scope to either the caller-requested backend (if it exists
        # in the registry) or the server's default. Never permit an
        # empty / None backend_id — that would search ACROSS every
        # backend the metadata_index ever saw, including ones this
        # server isn't supposed to expose.
        resolved = _resolve_backend(args)
        scope_id = (
            _backend_id_for(resolved) if resolved is not _default_backend else server_backend_id
        )
        kwargs = {
            "needle": args.get("pattern"),
            "ext": args.get("ext"),
            "min_size": int(args.get("min_size") or 0),
            "backend_id": scope_id,
        }
        if args.get("max_size"):
            kwargs["max_size"] = int(args["max_size"])
        raw_limit = args.get("max_results")
        limit = DEFAULT_SEARCH_LIMIT if raw_limit is None else int(raw_limit)
        if not 0 < limit <= MAX_SEARCH_RESULTS:
            raise ValueError(f"search_index: max_results must be 1 … {MAX_SEARCH_RESULTS}")
        offset = args.get("offset") or 0
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset:
            raise ValueError("search_index: offset must be a whole number >= 0")
        ctx.check_cancel()
        # The index is read up to MAX_SEARCH_SCAN rows (the root is applied
        # to them below), and a cancel interrupts the query.
        try:
            entries = MX.search_all(**kwargs, limit=MAX_SEARCH_SCAN,
                                    cancel=lambda: ctx.is_cancelled)
        except sqlite3.OperationalError:
            ctx.check_cancel()
            raise
        ctx.check_cancel()
        scope = _call_scope(resolved)

        def _in_root(entry_path: str) -> bool:
            # The index is shared by every session of every backend id;
            # only rows under the configured MCP root may leave.
            try:
                scope(entry_path)
            except (PermissionError, ValueError):
                return False
            return True

        folder = args.get("path")
        if folder:
            folder = scope(folder).rstrip("/") or "/"
            inside = folder + "/" if folder != "/" else "/"
            entries = [e for e in entries if e.path == folder or e.path.startswith(inside)]
        scanned_all = len(entries) < MAX_SEARCH_SCAN
        entries = [e for e in entries if _in_root(e.path)]
        more = len(entries) > offset + limit or not scanned_all
        entries = entries[offset:offset + limit]
        if entries:
            indexed = True
        else:
            # Nothing matched - or nothing was ever indexed for this backend.
            indexed = bool(MX.search_all(backend_id=scope_id, limit=1))
        # One object, the same as text and as structuredContent: a client
        # that reads only the text sees indexed and truncated too.
        return {
            "entries": [
                {
                    "backend_id": e.backend_id,
                    "path": e.path,
                    "name": e.name,
                    "size": e.size,
                    "is_dir": e.is_dir,
                    "modified": e.modified.isoformat() if e.modified else None,
                }
                for e in entries
            ],
            "indexed": indexed,
            "truncated": more,
        }

    def _walk(args, ctx):
        """Breadth-first traversal of a directory tree with caps on
        depth and entry count. Emits progress every WALK_PROGRESS_EVERY
        entries so a slow backend (SFTP over WAN, S3 with many
        per-prefix round-trips) doesn't leave the client waiting in
        silence.

        Calls ``ctx.check_cancel()`` at the top of each outer-queue
        iteration AND at every progress tick, so a
        ``notifications/cancelled`` from the client lands within one
        list_dir round-trip of arrival."""
        backend = _resolve_backend(args)
        path = _scope_path(args.get("path") or "/", backend)
        # An explicit 0 is a depth (it acts like 1), not "use the default".
        max_depth = 4 if args.get("max_depth") is None else int(args["max_depth"])
        max_entries = int(args.get("max_entries") or 1000)
        if max_depth < 0 or max_entries <= 0:
            raise ValueError("walk: max_depth must be ≥0 and max_entries > 0")
        if max_depth > MAX_TREE_DEPTH or max_entries > MAX_WALK_ENTRIES:
            raise ValueError(f"walk: max_depth must be ≤ {MAX_TREE_DEPTH} and max_entries "
                             f"≤ {MAX_WALK_ENTRIES}")
        entries: list[dict] = []
        unreadable: list[dict] = []
        depth_cut = False  # a folder at max_depth was listed but not entered
        queue: list[tuple[str, int]] = [(path, 0)]
        while queue and len(entries) < max_entries:
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            children = _list_or_note(backend, cur, path, unreadable)
            if children is None:
                continue
            for child in children:
                if len(entries) >= max_entries:
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = _safe_child_path(backend, cur, name)
                if full is None:
                    continue
                is_dir = bool(getattr(child, "is_dir", False))
                entries.append(
                    {
                        "path": full,
                        "name": name,
                        "is_dir": is_dir,
                        "is_link": bool(getattr(child, "is_link", False)),
                        "size": int(getattr(child, "size", 0) or 0),
                        "modified": (getattr(child, "modified", None).isoformat()
                                     if getattr(child, "modified", None) else None),
                    }
                )
                if is_dir and depth + 1 < max_depth:
                    queue.append((full, depth + 1))
                elif is_dir:
                    depth_cut = True
                if len(entries) % WALK_PROGRESS_EVERY == 0:
                    ctx.check_cancel()
                    ctx.progress(
                        progress=float(len(entries)),
                        total=None,  # max_entries is a cap, not the count
                        message=f"walked {len(entries)} entries @ {cur}",
                    )
        # truncated: a limit cut the tree - max_entries, or max_depth (a
        # folder there was not entered); complete: nothing cut or left out.
        truncated = (len(entries) >= max_entries and bool(queue)) or depth_cut
        return {
            "entries": entries,
            "truncated": truncated,
            "unreadable": unreadable,
            "complete": not truncated and not unreadable,
        }

    def _recursive_checksum(args, ctx):
        """Hash every file under ``path`` breadth-first up to
        ``max_files`` and ``max_depth``.

        Each record is one of three shapes:

        * hashed     — ``{path, size, algorithm, checksum, source}``
        * skipped    — ``{path, size, algorithm, skipped: "too-large"}``
        * errored    — ``{path, size, algorithm, error: "<msg>"}``

        Progress is emitted once per file (files done, total unknown).
        The single-file byte-level progress inside
        :func:`_hash_one_path` is suppressed here so the value the
        client sees stays monotonic — mixing files and bytes under
        the same progressToken would make the counter regress.

        A cancel lands within one chunk of the currently-hashing
        file OR at the next directory boundary, whichever comes first.

        Design note: unlike ``walk``, the tree can be accepted as
        either a directory (BFS expansion) or a single file (hashed
        once and returned in a 1-element list). The single-file form
        lets a client batch-hash a specific list of paths by issuing
        one call per path without switching between ``checksum`` and
        ``recursive_checksum`` based on prior knowledge.
        """
        backend = _resolve_backend(args)
        scope = _call_scope(backend)
        refuse_secret = _secret_check(backend)
        path = scope(args.get("path") or "/")
        algo = (args.get("algorithm") or "sha256").lower()
        if algo not in _HASHLIB_ALGOS:
            raise ValueError(
                f"compute_tree_checksums algorithm must be one of "
                f"{sorted(_HASHLIB_ALGOS)}; got {algo!r}",
            )
        # ``or DEFAULT`` would coerce an explicit ``0`` to the default
        # and paper over a caller bug; use explicit ``is None`` checks
        # so invalid zeros surface in the validation block below.
        raw_max_files = args.get("max_files")
        max_files = 500 if raw_max_files is None else int(raw_max_files)
        raw_max_depth = args.get("max_depth")
        max_depth = 10 if raw_max_depth is None else int(raw_max_depth)
        raw_max_file_bytes = args.get("max_file_bytes")
        max_file_bytes = (
            RECURSIVE_CHECKSUM_MAX_FILE_BYTES
            if raw_max_file_bytes is None
            else int(raw_max_file_bytes)
        )
        if max_files <= 0:
            raise ValueError("compute_tree_checksums: max_files must be > 0")
        if max_depth < 0:
            raise ValueError("compute_tree_checksums: max_depth must be ≥ 0")
        if max_files > MAX_RECURSIVE_CHECKSUM_FILES or max_depth > MAX_TREE_DEPTH:
            raise ValueError(f"compute_tree_checksums: max_files must be ≤ {MAX_RECURSIVE_CHECKSUM_FILES} "
                             f"and max_depth ≤ {MAX_TREE_DEPTH}")
        if max_file_bytes <= 0:
            raise ValueError(
                "compute_tree_checksums: max_file_bytes must be > 0",
            )

        entries: list[dict] = []
        truncated = False

        def _hash_file(full_path: str, size: int) -> None:
            """Hash one file, append a record, emit progress. Keeps
            the inner loop concise whether we took the tree branch or
            the single-file branch."""
            if size > max_file_bytes:
                entries.append(
                    {
                        "path": full_path,
                        "size": size,
                        "algorithm": algo,
                        "skipped": "too-large",
                    }
                )
                return
            ctx.check_cancel()
            try:
                safe_full_path = refuse_secret(scope(full_path))
                result = _hash_one_path(
                    backend,
                    safe_full_path,
                    algo,
                    ctx,
                    total_bytes=size,
                    emit_byte_progress=False,
                )
            except CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — record & continue
                entries.append(
                    {
                        "path": full_path,
                        "size": size,
                        "algorithm": algo,
                        "error": redact_text(str(exc)),
                    }
                )
                return
            entries.append(
                {
                    "path": full_path,
                    "size": size,
                    "algorithm": algo,
                    "checksum": result["value"],
                    "source": result["source"],
                }
            )
            hashed = sum(1 for e in entries if "checksum" in e)
            # The tree is walked while it is hashed: how many files there
            # are is not known yet (max_files is a cap, not the count).
            ctx.progress(
                progress=float(hashed),
                total=None,
                message=f"{hashed} hashed — {full_path}",
            )

        # Classify the root: file vs directory. The ``walk`` tool
        # always starts with a directory; we don't require that.
        try:
            root_stat = backend.stat(path)
        except OSError as exc:
            raise OSError(
                f"compute_tree_checksums({path}): stat failed: {exc}",
            ) from exc
        if not getattr(root_stat, "is_dir", False):
            _hash_file(path, int(getattr(root_stat, "size", 0) or 0))
            return {
                "entries": entries,
                "truncated": False,
                "complete": _all_hashed(entries, False),
            }

        # BFS over the tree.
        unreadable: list[dict] = []
        queue: list[tuple[str, int]] = [(path, 0)]
        while queue:
            hashed = sum(1 for e in entries if "checksum" in e)
            if hashed >= max_files:
                truncated = True
                break
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            children = _list_or_note(backend, cur, path, unreadable)
            if children is None:
                continue
            for child in children:
                hashed = sum(1 for e in entries if "checksum" in e)
                if hashed >= max_files:
                    truncated = True
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = _safe_child_path(backend, cur, name)
                if full is None:
                    continue
                is_dir = bool(getattr(child, "is_dir", False))
                if is_dir:
                    if depth + 1 < max_depth:
                        queue.append((full, depth + 1))
                    else:
                        truncated = True  # max_depth: this folder is not entered
                    continue
                size = int(getattr(child, "size", 0) or 0)
                _hash_file(full, size)
        # The files below a folder it could not list are missing: say so.
        entries.extend(
            {"path": u["path"], "folder": True, "algorithm": algo, "error": u["error"]}
            for u in unreadable
        )
        return {
            "entries": entries,
            "truncated": truncated,
            "complete": _all_hashed(entries, truncated),
        }

    tools = [
        _Tool(
            name="list_dir",
            description=(
                "List the entries of one folder, one level deep.\n"
                "Use when: you need what is inside a folder.\n"
                "Instead: walk_tree for a subtree or a capped listing; get_path_info for one "
                "path; search_index for indexed names.\n"
                "Behavior: read-only. Every entry, hidden ones too, in the backend's order; "
                "a symlink is listed itself (is_link true, is_dir false). No entry cap, but "
                "a result over 16 MiB fails. A missing path or a file fails.\n"
                "Returns: a JSON array of {name, is_dir, is_link, size, modified (ISO 8601 "
                "or null)}; structuredContent wraps it as {entries}."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": _path_spec("The folder to list"),
                },
                "required": ["path"],
            },
            handler=_list_dir,
        ),
        _Tool(
            name="stat",
            description=(
                "Get the type, size, modification time and mode of one file or folder.\n"
                "Use when: checking that a path exists or what it is, or reading a mode.\n"
                "Instead: list_directory for a folder's entries; read_file for the "
                "contents.\n"
                "Behavior: read-only. Follows a symlink: the fields, name included, are the "
                "target's; is_link says the path itself is a link (local disk; remote "
                "backends report false). Nothing at path, or a dangling link, fails "
                "(list_directory on the parent shows the link).\n"
                "Returns: {name, is_dir, is_link, size, modified (ISO 8601 or null), mode "
                "(octal such as '0644', null without POSIX bits)}."
            ),
            schema={
                "type": "object",
                "properties": {"path": _path_spec("The file or folder to describe")},
                "required": ["path"],
            },
            handler=_stat,
        ),
        _Tool(
            name="read_file",
            description=(
                "Read one file's contents as base64 bytes or UTF-8 text, at most 4 MiB per "
                "call.\n"
                "Use when: you need a file's contents; page through a larger one with "
                "offset.\n"
                "Instead: search_content to find lines across files; read_file_version for "
                "an older version; render_preview for an image.\n"
                f"Behavior: read-only. {_SECRET_TAG} A folder or missing file fails; text "
                "never cuts a character in two.\n"
                "Returns: {content_b64 or text, size (bytes in this page; get_path_info "
                "gives the file's), truncated, replaced (text: bad bytes became U+FFFD)}. "
                "When truncated, or when offset was given, also offset and next_offset. An "
                "offset past the end returns empty content with truncated false."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": _path_spec("The file to read"),
                    "max_bytes": {"type": "integer", "minimum": 0, "maximum": MAX_READ_BYTES,
                                  "default": MAX_READ_BYTES,
                                  "description": "Most bytes to return; 0 or omitted means "
                                                 f"the ceiling, {MAX_READ_BYTES} (4 MiB)."},
                    "offset": {"type": "integer", "minimum": 0, "default": 0,
                               "description": "Byte offset to start at; pass the previous "
                                              "call's next_offset to continue."},
                    "encoding": {
                        "type": "string",
                        "enum": ["base64", "text"],
                        "default": "base64",
                        "description": "base64 (default): the exact bytes, safe for any "
                                       "file. text: decoded as UTF-8 - pass it for text "
                                       "files.",
                    },
                },
                "required": ["path"],
            },
            handler=_read_file,
        ),
        _Tool(
            name="checksum",
            description=(
                "Compute one file's hash (md5, sha1, sha256 or sha512).\n"
                "Use when: comparing a file with a copy or a published digest without "
                "transferring it.\n"
                "Instead: compute_tree_checksums for a folder (or a file, as a list); "
                "scan_duplicates to find identical files.\n"
                "Behavior: read-only. Uses the backend's own hash in that algorithm when it "
                "has one (e.g. sha256sum over SSH), else streams the file. "
                f"{_SECRET_TAG} A folder or missing path fails.\n"
                "Returns: {value (hex digest), algorithm, source (native|stream)}."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": _path_spec("The file to hash"),
                    "algorithm": {
                        "type": "string",
                        "enum": sorted(_HASHLIB_ALGOS),
                        "default": "sha256",
                        "description": "The hash algorithm.",
                    },
                },
                "required": ["path"],
            },
            handler=_checksum,
        ),
        _Tool(
            name="search",
            description=(
                "Find files and folders by name, extension and size in the offline metadata "
                "index.\n"
                "Use when: looking up names fast across folders indexed before.\n"
                "Instead: walk_tree for the live tree (slower, never stale); search_content "
                "for contents.\n"
                "Requires: an index from build_index or the axross app.\n"
                "Behavior: read-only; results can be stale. Searches only the rows of "
                "backend (the default backend if omitted). The given filters must all "
                "match; none gives every indexed entry. Pages with offset and max_results.\n"
                "Returns: {entries: [{backend_id, path, name, size, is_dir, modified}], "
                "indexed (false: no index yet - no entries may mean that), truncated (more "
                "after this page)}."
            ),
            schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string",
                                "description": "A substring of the file name (not a regex), "
                                               "matched ignoring case and Unicode "
                                               "normalisation, e.g. 'report' finds "
                                               "'Q3_Report.pdf'."},
                    "ext": {"type": "string",
                            "description": "File extension, matched whole in any case; a "
                                           "leading dot is ignored, e.g. 'pdf'."},
                    "min_size": {"type": "integer", "minimum": 0, "default": 0,
                                 "description": "Smallest size in bytes, inclusive."},
                    "max_size": {"type": "integer", "minimum": 0,
                                 "description": "Largest size in bytes, inclusive; omit for "
                                                "no upper bound. Below min_size nothing "
                                                "matches."},
                    "max_results": {"type": "integer", "minimum": 1,
                                    "maximum": MAX_SEARCH_RESULTS,
                                    "default": DEFAULT_SEARCH_LIMIT,
                                    "description": "Most results to return."},
                    "offset": {"type": "integer", "minimum": 0, "default": 0,
                               "description": "Matches to skip, for the next page: the "
                                              "previous offset + max_results."},
                    "path": _path_spec("Only entries anywhere below this folder"),
                },
            },
            handler=_search,
        ),
        _Tool(
            name="walk",
            description=(
                "List the live folder tree under path, breadth-first, to max_depth "
                "levels.\n"
                "Use when: you need every file and folder below a path.\n"
                "Instead: list_directory for one level; search_index for the faster, maybe "
                "stale index; search_content for contents.\n"
                "Behavior: read-only. Symlinked folders are listed, not entered. Hitting "
                "max_entries, or a folder at max_depth left unentered, sets truncated (no "
                "cursor: rerun on a subfolder); an unlistable subfolder goes to "
                "unreadable.\n"
                "Returns: {entries: [{path, name, is_dir, is_link, size, modified}], "
                "truncated, unreadable: [{path, error}], complete (false when anything was "
                "cut or unread)}."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": _path_spec("The folder to walk"),
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": MAX_TREE_DEPTH,
                                  "default": 4, "description": _DEPTH_TEXT},
                    "max_entries": {"type": "integer", "minimum": 1, "maximum": MAX_WALK_ENTRIES,
                                    "default": 1000,
                                    "description": "Most entries to return (files and "
                                                   "folders together)."},
                },
                "required": ["path"],
            },
            handler=_walk,
        ),
        _Tool(
            name="recursive_checksum",
            description=(
                "Hash every file under a folder (or one file) and list each digest.\n"
                "Use when: verifying or comparing a whole tree.\n"
                "Instead: compute_file_checksum for one file; scan_duplicates to group identical "
                "files.\n"
                "Behavior: read-only, breadth-first. Symlinked files are hashed, symlinked "
                "folders get an error entry. Secret files are refused with an error entry. "
                "Files above max_file_bytes are skipped; max_files or a folder at max_depth "
                "sets truncated (no cursor: rerun on a subfolder).\n"
                "Returns: {entries, truncated, complete}; each entry is {path, size, "
                "algorithm} plus one of: checksum and source (hashed), skipped 'too-large', "
                "or error (with folder true when a folder could not be listed)."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": _path_spec("The folder (or one file) to hash"),
                    "algorithm": {
                        "type": "string",
                        "enum": sorted(_HASHLIB_ALGOS),
                        "default": "sha256",
                        "description": "The hash algorithm.",
                    },
                    "max_files": {"type": "integer", "minimum": 1,
                                  "maximum": MAX_RECURSIVE_CHECKSUM_FILES, "default": 500,
                                  "description": "Most files to hash; truncated=true when "
                                                 "there were more."},
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": MAX_TREE_DEPTH,
                                  "default": 10, "description": _DEPTH_TEXT},
                    "max_file_bytes": {"type": "integer", "minimum": 1,
                                       "default": RECURSIVE_CHECKSUM_MAX_FILE_BYTES,
                                       "description": "Files larger than this many bytes are "
                                                      "skipped (default 1 GiB)."},
                },
                "required": ["path"],
            },
            handler=_recursive_checksum,
        ),
    ]

    # Read-only version-history tools. Not gated behind --mcp-write
    # because they don't mutate anything — a list_versions call on
    # a read-only S3 pane is as safe as list_dir.

    def _list_versions(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("list_file_versions requires a path")
        path = _scope_path(path, backend)
        versions = backend.list_versions(path)
        return [
            {
                "version_id": getattr(v, "version_id", ""),
                "size": int(getattr(v, "size", 0) or 0),
                "modified": (
                    getattr(v, "modified", None).isoformat()
                    if getattr(v, "modified", None)
                    else None
                ),
                "is_current": bool(getattr(v, "is_current", False)),
                "label": getattr(v, "label", "") or "",
            }
            for v in versions
        ]

    def _open_version_read(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        version_id = args.get("version_id")
        if not path or not version_id:
            raise ValueError(
                "read_file_version requires path + version_id",
            )
        path = _read_path(path, backend)
        encoding, cap, offset = _window_args(args, "open_version_read")
        # Paged like read_file: an old version is a stream from its start,
        # so an offset reads (and drops) the bytes before it.
        offset, data, truncated = _read_window(
            backend.open_version_read(path, version_id), encoding, cap, offset)
        _refuse_key_in(data, path)  # the version is not the file the name check saw
        return _window_result(data, encoding, offset, truncated)

    def _grep(args, ctx):
        """Regex search inside file contents under a root path.

        Recurses up to ``max_depth`` levels, scans each file up to
        ``MAX_GREP_FILE_BYTES`` (anything larger is skipped so we
        don't stream 10 GiB logs by accident), and returns up to
        ``MAX_GREP_MATCHES`` hits as {path, line_no, line_text}.

        Cooperates with cancellation: the outer walk checks
        ``ctx.check_cancel()`` at every directory boundary AND every
        progress tick so client-side cancels land within one
        list_dir round-trip.

        NB: we apply regex line-by-line on UTF-8-decoded bytes with
        ``errors='replace'`` — so a regex like ``[^\\x00]*`` won't
        trip over null bytes; binaries tend to produce gibberish
        lines but the server doesn't crash.
        """
        import re

        backend = _resolve_backend(args)
        pattern = args.get("pattern")
        if not pattern:
            raise ValueError("grep requires a pattern")
        # ReDoS preflight. Python's stdlib ``re`` has no per-call
        # timeout; a catastrophic pattern like ``(a+)+b`` against a
        # line of many ``a``s burns CPU for seconds inside a single
        # regex.search. The outer tool timeout (60s) eventually
        # hard-stops the worker, but 60s of CPU per request × N
        # parallel HTTP clients is a real DoS vector.
        #
        # Two cheap guards:
        #  1. Length cap — a legitimate grep regex is rarely longer
        #     than a few hundred chars; refuse anything larger.
        #  2. Heuristic detection of nested unbounded quantifiers
        #     — the classic ReDoS shape. Doesn't catch every
        #     pathological case (e.g. alternation-based backtracking
        #     ``(a|a)+``) but covers the common ones with zero
        #     false positives on real-world patterns.
        if len(pattern) > MAX_GREP_PATTERN_LENGTH:
            raise ValueError(
                f"grep: pattern too long ({len(pattern)} > {MAX_GREP_PATTERN_LENGTH} chars)",
            )
        if _REDOS_NESTED_QUANTIFIER.search(pattern):
            raise ValueError(
                "grep: pattern contains a nested unbounded quantifier "
                "(ReDoS risk). Rewrite without '(…+)+' / '(…*)*' shapes."
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"grep: bad regex {pattern!r}: {exc}") from exc
        scope = _call_scope(backend)
        refuse_secret = _secret_check(backend)
        # No path: the MCP root (a remote backend's "/"), as the schema says;
        # "/" itself is outside any root but "/".
        default_start = "/" if _is_remote(backend) else (read_root or "/")
        start = scope(args.get("path") or default_start)
        max_depth = 2 if args.get("max_depth") is None else int(args["max_depth"])
        max_matches = int(args.get("max_matches") or 100)
        max_matches = min(max_matches, MAX_GREP_MATCHES)
        if max_depth < 0 or max_matches <= 0:
            raise ValueError(
                "grep: max_depth must be ≥0 and max_matches > 0",
            )
        if max_depth > MAX_TREE_DEPTH:
            raise ValueError(f"grep: max_depth must be ≤ {MAX_TREE_DEPTH}")
        include = args.get("include") or None
        if include is not None and not isinstance(include, str):
            raise ValueError("grep: include must be a glob string such as '*.py'")
        matches: list[dict] = []
        unreadable: list[dict] = []
        queue: list[tuple[str, int]] = [(start, 0)]
        # The shape check above misses most catastrophic patterns
        # ((?:(a)+)+$, (a|a)+$, (a+){2,}$ ran 10-20 s on 27 characters, and
        # re cannot be interrupted): the lines are matched in a child
        # process that is killed once one file takes longer than
        # GREP_REGEX_SECONDS_PER_FILE, or when the call is cancelled.
        from core import regex_worker

        matchers: list = []  # started at the first file: an empty walk starts no child
        depth_cut: list = []  # a folder at max_depth was not entered

        def _matching_lines(text: str, limit: int) -> list[int]:
            if not matchers:
                matchers.append(regex_worker.RegexMatcher(
                    pattern,
                    seconds_per_text=GREP_REGEX_SECONDS_PER_FILE,
                    is_cancelled=lambda: ctx.is_cancelled,
                ))
            return matchers[0].matching_lines(text, limit)

        try:
            files_scanned = _grep_walk(
                backend, _matching_lines, scope, refuse_secret, start, max_depth, max_matches,
                matches, unreadable, queue, ctx, include, depth_cut,
            )
        except regex_worker.RegexTimeout as exc:
            raise ValueError(
                f"grep: the pattern ran longer than {GREP_REGEX_SECONDS_PER_FILE:g} s on one "
                "file and was stopped; it backtracks catastrophically (ReDoS). "
                "Rewrite it without nested or overlapping repetition."
            ) from exc
        except regex_worker.RegexCancelled as exc:
            raise CancelledError("grep cancelled") from exc
        finally:
            for matcher in matchers:
                matcher.close()
        truncated = len(matches) >= max_matches or bool(depth_cut)
        return {
            "matches": matches,
            "files_scanned": files_scanned,
            "truncated": truncated,
            "unreadable": unreadable,
            "complete": not truncated and not unreadable,
        }

    def _grep_walk(backend, matching_lines, scope, refuse_secret, start, max_depth,
                   max_matches, matches, unreadable, queue, ctx, include=None,
                   depth_cut=None) -> int:
        """grep's walk: fills *matches* / *unreadable*, returns the number
        of files scanned. *matching_lines(text, limit)* runs the pattern."""
        files_scanned = 0
        while queue and len(matches) < max_matches:
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            children = _list_or_note(backend, cur, start, unreadable)
            if children is None:
                continue
            for child in children:
                if len(matches) >= max_matches:
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = _safe_child_path(backend, cur, name)
                if full is None:
                    continue
                is_dir = bool(getattr(child, "is_dir", False))
                if is_dir:
                    if depth + 1 < max_depth:
                        queue.append((full, depth + 1))
                    elif depth_cut is not None:
                        depth_cut.append(full)
                    continue
                if include is not None and not fnmatch.fnmatchcase(name, include):
                    continue
                size = int(getattr(child, "size", 0) or 0)
                if size > MAX_GREP_FILE_BYTES:
                    continue
                try:
                    # PermissionError is an OSError: a secret is "unreadable".
                    safe_full = refuse_secret(scope(full))
                    with backend.open_read(safe_full) as fh:
                        raw = fh.read(MAX_GREP_FILE_BYTES + 1)
                    if (not allow_secret_reads and isinstance(raw, bytes)
                            and (_is_remote(backend) or len(raw) > _secret_scan_limit())):
                        from core import protected_places

                        # read_refusal looked at the first MiB only; at a
                        # remote's file nothing did (review B).
                        if protected_places.secret_in_content(raw):
                            raise PermissionError(f"{full}: holds a private key (refused)")
                except OSError as exc:
                    # "No match" in a file it could not read is no answer.
                    unreadable.append({"path": full, "error": redact_text(str(exc))})
                    continue
                files_scanned += 1
                if files_scanned % WALK_PROGRESS_EVERY == 0:
                    ctx.check_cancel()
                    ctx.progress(
                        progress=float(files_scanned),
                        total=None,
                        message=f"grepped {files_scanned} files @ {cur}",
                    )
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", errors="replace")
                text = raw.decode("utf-8", errors="replace")
                hits = matching_lines(text, max_matches - len(matches))
                if not hits:
                    continue
                lines = text.splitlines()
                for lineno in hits:
                    matches.append(
                        {
                            "path": full,
                            "line_no": lineno,
                            # Trim long lines so one pathological
                            # minified .js file doesn't blow up the
                            # response payload.
                            "line": lines[lineno - 1][:500],
                        }
                    )
                    if len(matches) >= max_matches:
                        break
        return files_scanned

    def _preview(args, ctx):
        """Generate a thumbnail of *path* via ``core.previews`` and
        return it as an MCP image content block (base64 PNG +
        mimeType) — much more native for MCP clients than the
        fire-and-hope base64-in-text shape.

        Only works for backends the previews module considers
        "local" (LocalFS + subclasses); raises PreviewNotAvailable
        otherwise."""
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("preview requires a path")
        path = _read_path(path, backend)
        edge = int(args.get("edge") or 256)
        if not 16 <= edge <= 2048:
            raise ValueError("preview: edge must be 16 … 2048 pixels")
        from core import previews as P

        # PreviewNotAvailable / PreviewTooLarge / PreviewDecodeFailed
        # (PreviewError) are the tool's failure, not bad arguments: they
        # come back as a tool error (isError), as any failed call does.
        if getattr(backend, "confined_beneath", False):
            # The decoder opens files by name: it gets the file the confined
            # backend opened (a folder swapped for a symlink meanwhile led it
            # outside the root otherwise). No cache: the name is per call.
            from core.confined_fs import pinned_path

            with pinned_path(backend, path) as pinned:
                result = P.thumbnail(backend, pinned, edge=edge, use_cache=False)
        else:
            result = P.thumbnail(backend, path, edge=edge, use_cache=True)
        # Return MCP image content directly — the dispatcher's
        # default wrapper turns results into {"type":"text"} blocks;
        # the preview handler signals otherwise by returning a
        # _ContentBlock wrapper that the dispatcher respects.
        return _PreviewResult(
            data_b64=base64.b64encode(result.data).decode("ascii"),
            mime=result.mime,
            width=result.width,
            height=result.height,
        )

    tools.extend(
        [
            _Tool(
                name="preview",
                description=(
                    "Render a PNG thumbnail of an image file on the local disk.\n"
                    "Use when: you need to see an image (PNG, JPEG, GIF, BMP, WebP, TIFF ...).\n"
                    "Instead: read_file for the raw bytes; read_metadata for EXIF. A remote "
                    "image: copy_path_to_backend (needs --mcp-tools transfer and --mcp-write) "
                    "first.\n"
                    "Behavior: read-only, local disk only. Files over 50 MiB, images over "
                    "20000 px, SVG, other types and undecodable files fail.\n"
                    "Returns: an MCP image content block (image/png) with _meta {width, height} "
                    "of the thumbnail."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "path": _local_path_spec("The image file"),
                        "edge": {"type": "integer", "minimum": 16, "maximum": 2048,
                                 "default": 256,
                                 "description": "Longest side of the thumbnail in pixels, "
                                                "16-2048."},
                    },
                    "required": ["path"],
                },
                handler=_preview,
                # The local disk only: a backend argument could only fail.
                accepts_backend=False,
            ),
            _Tool(
                name="grep",
                description=(
                    "Search file contents under a folder for lines matching a regular "
                    "expression.\n"
                    "Use when: finding which files contain a word or pattern, with line "
                    "numbers.\n"
                    "Instead: search_index or walk_tree to match names; read_file for a whole "
                    "file.\n"
                    "Behavior: read-only, breadth-first; include narrows by file name. Files "
                    "are read as UTF-8, binary ones too (bad bytes: U+FFFD); over 4 MiB they "
                    "are skipped; lines are cut at 500 characters. Patterns with nested "
                    "quantifiers or slower than 5 s on a file are refused (ReDoS). Secret files "
                    "go to unreadable.\n"
                    "Returns: {matches: [{path, line_no, line}], files_scanned, truncated "
                    "(max_matches, or a folder at max_depth not searched), unreadable, "
                    "complete}. An empty result with complete=false does not mean the "
                    "pattern is absent; when truncated, narrow path or include."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "minLength": 1,
                                    "maxLength": MAX_GREP_PATTERN_LENGTH,
                                    "description": "A Python regular expression, matched "
                                                   "against each line, e.g. 'import|require' or "
                                                   "'(?i)password'."},
                        "path": {**_path_spec("The folder to search"),
                                 "description": "The folder to search (absolute, or relative "
                                                "to the MCP root); default the MCP root, '/' "
                                                "on a remote backend."},
                        "include": {"type": "string", "minLength": 1,
                                    "description": "Only files whose name matches this glob, "
                                                   "case-sensitive, e.g. '*.py' or "
                                                   "'*.[ch]'."},
                        "max_depth": {"type": "integer", "minimum": 1,
                                      "maximum": MAX_TREE_DEPTH, "default": 2,
                                      "description": _DEPTH_TEXT},
                        "max_matches": {"type": "integer", "minimum": 1,
                                        "maximum": MAX_GREP_MATCHES, "default": 100,
                                        "description": "Most matching lines to return."},
                    },
                    "required": ["pattern"],
                },
                handler=_grep,
            ),
            _Tool(
                name="list_versions",
                description=(
                    "List the stored older versions of one file.\n"
                    "Use when: you need an earlier state on a versioning backend (S3, Dropbox, "
                    "Drive, Azure, WebDAV, Git).\n"
                    "Instead: read_file_version to read one; read_file for the current one.\n"
                    "Behavior: read-only. Unsorted (the backend's order). Backends without "
                    "versions, the local disk too, give [] (read_file_version fails there).\n"
                    "Returns: a JSON array of {version_id, size, modified (ISO 8601 or null), "
                    "is_current, label (may be empty)}; structuredContent: {versions}."
                ),
                schema={
                    "type": "object",
                    "properties": {"path": _path_spec("The file whose versions to list")},
                    "required": ["path"],
                },
                handler=_list_versions,
            ),
            _Tool(
                name="open_version_read",
                description=(
                    "Read one older version of a file (from list_file_versions), paged like "
                    "read_file.\n"
                    "Use when: inspecting or recovering an older version.\n"
                    "Instead: read_file for the current version.\n"
                    "Behavior: read-only. offset, encoding and max_bytes (at most 4 MiB) work as "
                    "in read_file; each page reads the version from its start, so later pages "
                    "cost more. Refuses secret files, also by their content. Backends without "
                    "versions fail.\n"
                    "Returns: as read_file: {content_b64 or text, size, truncated, replaced, "
                    "offset, next_offset}."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "path": _path_spec("The file to read"),
                        "version_id": {"type": "string", "minLength": 1,
                                       "description": "The version_id of one entry from "
                                                      "list_file_versions for this path."},
                        "max_bytes": {"type": "integer", "minimum": 0,
                                      "maximum": MAX_READ_BYTES, "default": MAX_READ_BYTES,
                                      "description": "Most bytes to return; 0 or omitted "
                                                     f"means the ceiling, {MAX_READ_BYTES} "
                                                     "(4 MiB)."},
                        "offset": {"type": "integer", "minimum": 0, "default": 0,
                                   "description": "Byte offset to start at; pass the "
                                                  "previous call's next_offset."},
                        "encoding": {"type": "string", "enum": ["base64", "text"],
                                     "default": "base64",
                                     "description": "base64 (default): the exact bytes. "
                                                    "text: decoded as UTF-8, as read_file."},
                    },
                    "required": ["path", "version_id"],
                },
                handler=_open_version_read,
            ),
        ]
    )

    def _audit(tool_name: str, outcome: str, **fields) -> None:
        """Emit a single audit line. Paths, names and outcomes are safe
        to log; payloads are never logged (write_file and script_write
        go through this helper with ``size=<bytes>``, never the bytes or
        the script source themselves). Shared by the write tools and the
        script tools, so it lives outside both opt-in blocks.
        """
        parts = [f"tool={_mcp_names.public(tool_name)}", f"outcome={outcome}"]
        for k, v in fields.items():
            parts.append(f"{k}={v!r}")
        audit_log.info(" ".join(parts))

    if allow_write:

        def _write_file(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            content_b64 = args.get("content_b64")
            content = args.get("content")
            if not path or (content_b64 is None) == (content is None):
                raise ValueError(
                    "write_file requires path and exactly one of content (text) or content_b64"
                )
            # Audit "attempt" BEFORE the backend call. A subsequent
            # process death between the write and the "ok" entry
            # still leaves a trace in the audit log — operators see
            # an "attempt" without matching "ok" and know the
            # outcome is unknown.
            _audit("write_file", "attempt", path=path)
            try:
                safe = _write_path(path, backend)
                _refuse_root(safe, backend, "write_file")
                if content is not None:
                    if not isinstance(content, str):
                        raise ValueError("write_file: content must be a string")
                    data = content.encode("utf-8")
                else:
                    data = _strict_b64(content_b64, "content_b64")
                new_file = not _is_remote(backend) and not backend.exists(safe)
                confined_write = getattr(backend, "confined_atomic_write", None)
                if confined_write is not None:
                    # Temp file + rename relative to the folder's descriptor.
                    confined_write(safe, data)
                else:
                    from core.atomic_io import atomic_write

                    atomic_write(backend, safe, data)
                if new_file:
                    # A file the server creates is the user's alone (mode
                    # 0600), as the group tools' files; an existing file
                    # keeps its mode.
                    try:
                        backend.chmod(safe, 0o600)
                    except (OSError, NotImplementedError):
                        pass
            except BaseException as exc:
                _audit("write_file", "refused", path=path, error=type(exc).__name__)
                raise
            _audit("write_file", "ok", path=safe, size=len(data))
            return {"size": len(data)}

        def _mkdir(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            if not path:
                raise ValueError("mkdir requires a path")
            _audit("mkdir", "attempt", path=path)
            try:
                safe = _write_path(path, backend)
                _refuse_root(safe, backend, "mkdir")
                backend.mkdir(safe)
            except BaseException as exc:
                _audit("mkdir", "refused", path=path, error=type(exc).__name__)
                raise
            _audit("mkdir", "ok", path=safe)
            return {"ok": True}

        def _remove(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            if not path:
                raise ValueError("remove requires a path")
            recursive = bool(args.get("recursive", False))
            _audit("remove", "attempt", path=path, recursive=recursive)
            try:
                safe = _entry_path(path, backend)
                _refuse_root(safe, backend, "remove")
                backend.remove(safe, recursive=recursive)
            except BaseException as exc:
                _audit(
                    "remove", "refused", path=path, recursive=recursive, error=type(exc).__name__
                )
                raise
            _audit("remove", "ok", path=safe, recursive=recursive)
            return {"ok": True}

        def _rename(args, ctx):
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("rename requires src + dst")
            _audit("rename", "attempt", src=src, dst=dst)
            try:
                # Moved to a name of no secret place, a secret would be read.
                safe_src = _refuse_secret(_entry_path(src, backend), backend, entry=True)
                _refuse_root(safe_src, backend, "rename source")
                safe_dst = _entry_path(dst, backend)
                _refuse_root(safe_dst, backend, "rename destination")
                if backend.exists(safe_dst):
                    raise OSError(f"rename target already exists: {safe_dst}")
                _refuse_moved_links(safe_src, safe_dst, backend)
                from core.server_ops import server_side_move

                server_side_move(backend, safe_src, safe_dst)
            except BaseException as exc:
                _audit("rename", "refused", src=src, dst=dst, error=type(exc).__name__)
                raise
            _audit("rename", "ok", src=safe_src, dst=safe_dst)
            return {"ok": True}

        def _copy(args, ctx):
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("copy requires src + dst")
            _audit("copy", "attempt", src=src, dst=dst)
            try:
                safe_src = _refuse_secret(_write_path(src, backend), backend, entry=True)
                _refuse_special_remote(backend, safe_src, "copy")
                safe_dst = _write_path(dst, backend)
                _refuse_root(safe_dst, backend, "copy destination")
                if backend.exists(safe_dst):
                    raise OSError(f"copy target already exists: {safe_dst}")
                from core.server_ops import server_side_copy

                server_side_copy(backend, safe_src, safe_dst, overwrite=False)
            except BaseException as exc:
                _audit("copy", "refused", src=src, dst=dst, error=type(exc).__name__)
                raise
            _audit("copy", "ok", src=safe_src, dst=safe_dst)
            return {"ok": True}

        def _ensure_dir(backend, path: str) -> None:
            """Create ``path`` if missing, including any intermediate
            parents. Idempotent — a concurrent writer that creates the
            dir between our exists() and mkdir() does not raise."""
            if backend.exists(path) and backend.is_dir(path):
                return
            parent = backend.parent(path)
            # Terminate when parent == path (root of the backend).
            if parent and parent != path:
                _ensure_dir(backend, parent)
            try:
                backend.mkdir(path)
            except OSError:
                # Re-check after the failure — concurrent creator is
                # fine; anything else propagates.
                if not (backend.exists(path) and backend.is_dir(path)):
                    raise

        def _bulk_copy(args, ctx):
            """Copy a file or directory tree under ``src`` into ``dst``.

            Per-file copy via ``core.server_ops.server_side_copy`` —
            native backend copy when available, stream fallback
            otherwise — same semantics as the single-file ``copy``
            tool, repeated across every file the BFS visits under src.
            Each record is one
            of:

            * ``{src, dst, size, action: "copied"}``
            * ``{src, dst, size, action: "skipped",
                reason: "too-large" | "exists"}``
            * ``{src, dst, size, action: "error", error: "<msg>"}``
            * ``{src, dst, size: 0, action: "error", error, folder: true}``
              for a folder that could not be listed
            * ``{src, dst, size: 0, action: "skipped", reason: "max-depth"}``
              for a folder below ``max_depth`` (also sets ``truncated``)
            * ``{src, dst, size, action: "skipped", reason: "unsafe-name"}``

            ``complete`` is true only when the whole tree was walked and
            every file was copied or skipped as already existing. A walk
            that left something out used to answer ``truncated: false``
            with no record of it.

            Progress is emitted once per copied file
            (``files_copied/max_files``). Cancel is checked before
            every file and before every directory descent.

            Single-backend only in V1: src and dst both resolve
            through the same ``_resolve_backend(args)`` path. Cross-
            backend copy would need streaming open_read → open_write
            and is intentionally out of scope — that's what the
            full transfer_manager is for.

            When src is a file, dst is treated as the target file
            path. When src is a directory, dst is the target directory
            and the src tree lands under it; missing intermediate
            directories are created automatically.

            Per-file audit: every refusal OR skip emits its own audit
            line; successful copies are summarised in the final
            ``bulk_copy ok`` record to avoid flooding the audit stream
            when tens of thousands of small files move at once.
            """
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("copy_tree requires src + dst")
            # ``or DEFAULT`` silently coerces 0 → default and hides
            # invalid input; explicit None check surfaces it.
            raw_max_files = args.get("max_files")
            max_files = 1000 if raw_max_files is None else int(raw_max_files)
            raw_max_depth = args.get("max_depth")
            max_depth = 10 if raw_max_depth is None else int(raw_max_depth)
            raw_max_file_bytes = args.get("max_file_bytes")
            max_file_bytes = (
                BULK_COPY_MAX_FILE_BYTES if raw_max_file_bytes is None else int(raw_max_file_bytes)
            )
            overwrite = bool(args.get("overwrite", False))
            if max_files <= 0:
                raise ValueError("copy_tree: max_files must be > 0")
            if max_depth < 0:
                raise ValueError("copy_tree: max_depth must be ≥ 0")
            if max_files > MAX_BULK_COPY_FILES or max_depth > MAX_TREE_DEPTH:
                raise ValueError(f"copy_tree: max_files must be ≤ {MAX_BULK_COPY_FILES} and "
                                 f"max_depth ≤ {MAX_TREE_DEPTH}")
            if max_file_bytes <= 0:
                raise ValueError(
                    "copy_tree: max_file_bytes must be > 0",
                )

            _audit("bulk_copy", "attempt", src=src, dst=dst, overwrite=overwrite)
            try:
                safe_src = _refuse_secret(_write_path(src, backend), backend, entry=True)
                safe_dst = _write_path(dst, backend)
                if overwrite:
                    _refuse_root(safe_dst, backend, "copy_tree destination")
            except BaseException as exc:
                _audit("bulk_copy", "refused", src=src, dst=dst, error=type(exc).__name__)
                raise

            entries: list[dict] = []
            truncated = False
            refuse_secret = _secret_check(backend)

            def _copy_one(src_file: str, dst_file: str, size: int) -> None:
                try:
                    safe_src_file = refuse_secret(_write_path(src_file, backend))
                    safe_dst_file = _write_path(dst_file, backend)
                except PermissionError as exc:
                    _audit(
                        "bulk_copy.file",
                        "error",
                        src=src_file,
                        dst=dst_file,
                        error=type(exc).__name__,
                    )
                    entries.append(
                        {
                            "src": src_file,
                            "dst": dst_file,
                            "size": size,
                            "action": "error",
                            "error": redact_text(str(exc)),
                        }
                    )
                    return
                if size > max_file_bytes:
                    _audit(
                        "bulk_copy.file", "skipped", src=src_file, dst=dst_file, reason="too-large"
                    )
                    entries.append(
                        {
                            "src": src_file,
                            "dst": dst_file,
                            "size": size,
                            "action": "skipped",
                            "reason": "too-large",
                        }
                    )
                    return
                if not overwrite and backend.exists(safe_dst_file):
                    _audit("bulk_copy.file", "skipped", src=src_file, dst=dst_file, reason="exists")
                    entries.append(
                        {
                            "src": src_file,
                            "dst": dst_file,
                            "size": size,
                            "action": "skipped",
                            "reason": "exists",
                        }
                    )
                    return
                ctx.check_cancel()
                try:
                    _refuse_special_remote(backend, safe_src_file, "bulk_copy")
                    _ensure_dir(backend, backend.parent(safe_dst_file))
                    from core.server_ops import server_side_copy

                    server_side_copy(
                        backend,
                        safe_src_file,
                        safe_dst_file,
                        overwrite=overwrite,
                    )
                except CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — record + go on
                    _audit(
                        "bulk_copy.file",
                        "error",
                        src=src_file,
                        dst=dst_file,
                        error=type(exc).__name__,
                    )
                    entries.append(
                        {
                            "src": src_file,
                            "dst": dst_file,
                            "size": size,
                            "action": "error",
                            "error": redact_text(str(exc)),
                        }
                    )
                    return
                entries.append(
                    {
                        "src": src_file,
                        "dst": dst_file,
                        "size": size,
                        "action": "copied",
                    }
                )
                copied_count = sum(1 for e in entries if e.get("action") == "copied")
                ctx.progress(
                    progress=float(copied_count),
                    total=None,  # max_files is a cap, not the count
                    message=f"copied {copied_count} — {src_file}",
                )

            # File vs directory at the root.
            try:
                root_stat = backend.stat(safe_src)
            except OSError as exc:
                _audit("bulk_copy", "refused", src=src, dst=dst, error=type(exc).__name__)
                raise
            if not getattr(root_stat, "is_dir", False):
                _copy_one(
                    safe_src,
                    safe_dst,
                    int(getattr(root_stat, "size", 0) or 0),
                )
                copied = sum(1 for e in entries if e.get("action") == "copied")
                _audit("bulk_copy", "ok", src=src, dst=dst, files_copied=copied)
                return {
                    "entries": entries,
                    "truncated": False,
                    "complete": _bulk_copy_complete(entries, False),
                }

            # Directory: BFS walk of src, mirror under dst.
            _ensure_dir(backend, safe_dst)
            queue: list[tuple[str, str, int]] = [(safe_src, safe_dst, 0)]
            while queue:
                copied = sum(1 for e in entries if e.get("action") == "copied")
                if copied >= max_files:
                    truncated = True
                    break
                ctx.check_cancel()
                cur_src, cur_dst, depth = queue.pop(0)
                try:
                    children = backend.list_dir(cur_src)
                except OSError as exc:
                    _audit(
                        "bulk_copy.folder", "error", src=cur_src, error=type(exc).__name__
                    )
                    entries.append(
                        {
                            "src": cur_src,
                            "dst": cur_dst,
                            "size": 0,
                            "action": "error",
                            "error": redact_text(str(exc)),
                            "folder": True,
                        }
                    )
                    continue
                for child in children:
                    copied = sum(1 for e in entries if e.get("action") == "copied")
                    if copied >= max_files:
                        truncated = True
                        break
                    name = getattr(child, "name", "")
                    if not name or name in (".", ".."):
                        continue
                    full_src = _safe_child_path(backend, cur_src, name)
                    full_dst = _safe_child_path(backend, cur_dst, name)
                    if full_src is None or full_dst is None:
                        entries.append(
                            {
                                "src": cur_src,
                                "dst": cur_dst,
                                "size": int(getattr(child, "size", 0) or 0),
                                "action": "skipped",
                                "reason": "unsafe-name",
                                "name": redact_text(repr(name)),
                            }
                        )
                        continue
                    is_dir = bool(getattr(child, "is_dir", False))
                    if is_dir:
                        if depth + 1 < max_depth:
                            queue.append((full_src, full_dst, depth + 1))
                        else:
                            truncated = True
                            entries.append(
                                {
                                    "src": full_src,
                                    "dst": full_dst,
                                    "size": 0,
                                    "action": "skipped",
                                    "reason": "max-depth",
                                }
                            )
                        continue
                    _copy_one(
                        full_src,
                        full_dst,
                        int(getattr(child, "size", 0) or 0),
                    )

            copied_total = sum(1 for e in entries if e.get("action") == "copied")
            _audit(
                "bulk_copy", "ok", src=src, dst=dst, files_copied=copied_total, truncated=truncated
            )
            return {
                "entries": entries,
                "truncated": truncated,
                "complete": _bulk_copy_complete(entries, truncated),
            }

        def _require_links(backend, kind: str) -> None:
            # FTP, SMB, S3, WebDAV, rsync ... have no links: say so instead
            # of letting "object has no attribute 'symlink'" through.
            if not callable(getattr(backend, kind, None)) or not getattr(
                backend, f"supports_{kind}s", True
            ):
                what = "symbolic" if kind == "symlink" else "hard"
                raise OSError(f"{type(backend).__name__} has no {what} links")

        def _refuse_link_target(target, safe_link: str, active_backend) -> str:
            """PermissionError unless *target* (relative to the link's
            folder) resolves inside a writable root, outside its read-only
            folders and outside the protected places - nor to a folder that
            holds one (the home folder, ~/.config). Returns the target the
            link is made with: as typed, or - when it has a ``..`` - the
            checked place itself (absolute, every link resolved). ``b/..``
            with ``b`` a link leads wherever ``b``'s parent is once ``b`` is
            re-pointed, and ``../../x`` wherever its folder is moved to: what
            was checked would not stay what the link leads to. A target
            without ``..`` stays in the root whatever is re-pointed in it
            (every link made here leads into it)."""
            import os.path as op

            if _is_remote(active_backend):
                return target
            if not isinstance(target, str) or "\x00" in target:
                raise ValueError("symlink target must be a string without NUL")
            where = target if op.isabs(target) else op.join(op.dirname(safe_link), target)
            try:
                # realpath walks the links in it the way the kernel will.
                resolved = _write_path(op.realpath(where), active_backend)
                _refuse_protected(resolved, entry=True, granted=write_roots)
            except PermissionError as exc:
                raise PermissionError(f"symlink target {target!r} is refused: {exc}") from exc
            if ".." in target.replace("\\", "/").split("/"):
                return resolved
            return target

        def _symlink(args, ctx):
            backend = _resolve_backend(args)
            target = args.get("target")
            link_path = args.get("link_path")
            if not target or not link_path:
                raise ValueError("symlink requires target + link_path")
            _require_links(backend, "symlink")
            # The link itself must live under the root, and so must what
            # it points to: a link to ~/.config/autostart or to the home
            # folder, renamed over a folder another call had just checked,
            # led that call's write there (core.confined_fs refuses that
            # now as well). The target may be dangling.
            _audit("symlink", "attempt", target=target, link_path=link_path)
            try:
                # An entry: a link at a missing ~/.config would lead every
                # later write around ~/.config/autostart.
                safe_link = _entry_path(link_path, backend)
                _refuse_root(safe_link, backend, "symlink link_path")
                made = _refuse_link_target(target, safe_link, backend)
                backend.symlink(made, safe_link)
            except BaseException as exc:
                _audit(
                    "symlink",
                    "refused",
                    target=target,
                    link_path=link_path,
                    error=type(exc).__name__,
                )
                raise
            _audit("symlink", "ok", target=made, link_path=safe_link)
            return {"ok": True} if made == target else {"ok": True, "target": made}

        def _hardlink(args, ctx):
            backend = _resolve_backend(args)
            target = args.get("target")
            link_path = args.get("link_path")
            if not target or not link_path:
                raise ValueError("hardlink requires target + link_path")
            _require_links(backend, "hardlink")
            # Unlike symlinks, hardlinks have no path indirection to
            # resolve later. Allowing an outside-root target would
            # create an inside-root alias to data the MCP server was
            # not meant to expose, so cap both ends.
            _audit("hardlink", "attempt", target=target, link_path=link_path)
            try:
                # A second name of a secret file is the secret.
                safe_target = _refuse_secret(_write_path(target, backend), backend)
                safe_link = _write_path(link_path, backend)
                _refuse_root(safe_link, backend, "hardlink link_path")
                backend.hardlink(safe_target, safe_link)
            except BaseException as exc:
                _audit(
                    "hardlink",
                    "refused",
                    target=target,
                    link_path=link_path,
                    error=type(exc).__name__,
                )
                raise
            _audit("hardlink", "ok", target=target, link_path=safe_link)
            return {"ok": True}

        def _chmod(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            mode = args.get("mode")
            if not path or mode is None:
                raise ValueError("chmod requires path + mode (octal)")
            # Accept both integer (0o644) and string ("0o644" / "644")
            # — LLMs tend to format octal inconsistently.
            if isinstance(mode, str):
                try:
                    mode_int = int(mode, 8)
                except ValueError as exc:
                    raise ValueError(
                        f"chmod: mode {mode!r} is not octal",
                    ) from exc
            else:
                mode_int = int(mode)
            if not 0 <= mode_int <= 0o7777:
                raise ValueError(
                    f"chmod: mode {mode_int:o} out of range (0..07777)",
                )
            if mode_int & ~_CHMOD_ALLOWED_BITS:
                # setuid / setgid run a file with its owner's rights, a
                # world- or group-writable file or folder lets others change
                # it, the sticky bit belongs to shared folders: none is a mode
                # an agent needs, and each hands others the user's account.
                raise PermissionError(
                    f"chmod: mode {mode_int:o} refused: the agent does not set the "
                    "setuid, setgid or sticky bit or make a file group- or world-writable "
                    f"(allowed: the bits of {_CHMOD_ALLOWED_BITS:o})"
                )
            _audit("chmod", "attempt", path=path, mode=oct(mode_int))
            try:
                safe = _write_path(path, backend)
                _refuse_root(safe, backend, "chmod")
                if not _is_remote(backend):
                    import os
                    import stat

                    # A mode belongs to the inode: through a second name
                    # (a hard link to ~/.bashrc in the root) chmod would
                    # change the protected file's mode, not a copy's.
                    try:
                        st = os.stat(safe, follow_symlinks=False)
                    except OSError:
                        st = None
                    if st is not None and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                        raise PermissionError(
                            f"chmod: {safe} has {st.st_nlink} names (hard links): the agent "
                            "does not change the mode of a file that has other names - one of "
                            "them may be a protected file"
                        )
                if mode_int & 0o022 and not _is_remote(backend):
                    # Writable by others, a folder that holds protected places
                    # (~, ~/.config, ~/.local) lets another local user swap
                    # ~/.config/autostart for their own: an operation on the
                    # entry, not on its contents.
                    try:
                        _refuse_protected(safe, entry=True, granted=write_roots)
                    except PermissionError as exc:
                        raise PermissionError(
                            f"chmod {mode_int:o}: group or others could write {safe}: {exc}"
                        ) from exc
                backend.chmod(safe, mode_int)
            except BaseException as exc:
                _audit("chmod", "refused", path=path, mode=oct(mode_int), error=type(exc).__name__)
                raise
            _audit("chmod", "ok", path=safe, mode=oct(mode_int))
            return {"ok": True}

        _first_write_tool = len(tools)
        tools.extend(
            [
                _Tool(
                    name="write_file",
                    description=(
                        "Create a file or replace its whole contents with text or bytes.\n"
                        "Use when: saving content to one file; to edit, read_file, change, write "
                        "back. It always replaces: when the file must not exist yet, check with "
                        "get_path_info first.\n"
                        "Instead: copy_file to duplicate a file; create_directory for folders.\n"
                        f"Behavior: destructive - replaces the file. Atomic on the "
                        "local disk (temp file, rename): a replaced file keeps its mode, a new one "
                        "gets 0600. The parent must exist; a symlink at path is followed, a folder "
                        "fails. The 16 MiB limit is the whole request, so content_b64 carries about "
                        f"12 MiB.\n"
                        "Returns: {size: bytes written}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "path": _path_spec("The file to create or replace"),
                            "content": {
                                "type": "string",
                                "description": "The new content as text, stored UTF-8 "
                                               "encoded. Required unless content_b64 is "
                                               "given; not both.",
                            },
                            "content_b64": {
                                "type": "string",
                                "contentEncoding": "base64",
                                "description": "content as base64 of the raw bytes, for "
                                               "binary files; give this or content.",
                            },
                        },
                        "required": ["path"],
                    },
                    handler=_write_file,
                    write=True,
                ),
                _Tool(
                    name="mkdir",
                    description=(
                        "Create a folder, with missing parents on the local disk.\n"
                        "Use when: a folder must exist before writing into it.\n"
                        "Instead: copy_tree and copy_path_to_backend make their destinations.\n"
                        f"Behavior: only adds. A repeat succeeds locally. Remote backends "
                        "create no parents, and an existing folder fails there with 'exists'. A file "
                        f"at path fails.\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {"path": _path_spec("The folder to create")},
                        "required": ["path"],
                    },
                    handler=_mkdir,
                    write=True,
                ),
                _Tool(
                    name="remove",
                    description=(
                        "Permanently delete a file, symbolic link or folder.\n"
                        "Use when: something must go for good.\n"
                        "Instead: move_path to move it aside.\n"
                        f"Behavior: destructive, irreversible (no trash). A repeat fails "
                        "with 'No such file'. A non-empty folder needs recursive=true; a failure "
                        "half-way leaves the rest. A symlink is removed, not its target. "
                        f"\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "path": _path_spec("The file, link or folder to delete"),
                            "recursive": {"type": "boolean", "default": False,
                                          "description": "true: also delete everything inside "
                                                         "a folder. false: a non-empty folder "
                                                         "fails."},
                        },
                        "required": ["path"],
                    },
                    handler=_remove,
                    write=True,
                ),
                _Tool(
                    name="rename",
                    description=(
                        "Move or rename a file or folder within one backend.\n"
                        "Use when: renaming, or moving on the same backend - folders too.\n"
                        "Instead: copy_file to keep the original; move_file_to_backend to another "
                        "backend.\n"
                        f"Behavior: destructive for the old path. A repeat fails with "
                        "'target already exists'. Native rename (atomic locally); a backend without "
                        "one copies, then deletes the source, and takes the copy back if that "
                        "delete fails. dst's parent must exist; an existing dst is never replaced. "
                        f"A symlink moves itself; secret files cannot be moved.\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "src": _path_spec("The file or folder to move"),
                            "dst": _path_spec("Its new path, including the new name; must "
                                              "not exist yet"),
                        },
                        "required": ["src", "dst"],
                    },
                    handler=_rename,
                    write=True,
                ),
                _Tool(
                    name="copy",
                    description=(
                        "Copy one file to a new path on the same backend.\n"
                        "Use when: duplicating a single file.\n"
                        "Instead: copy_tree for a folder tree; copy_path_to_backend across backends "
                        "or for files that take over 30 s (it resumes).\n"
                        f"Behavior: only adds. A repeat fails with 'already exists'. "
                        "Native copy (S3, WebDAV, cp over SSH) where possible; locally mode and "
                        "mtime are kept. dst's parent must exist; a folder as src fails. "
                        f"{_SECRET_TAG}\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "src": _path_spec("The file to copy"),
                            "dst": _path_spec("The new file's path, including its name; must "
                                              "not exist yet"),
                        },
                        "required": ["src", "dst"],
                    },
                    handler=_copy,
                    write=True,
                ),
                _Tool(
                    name="bulk_copy",
                    description=(
                        "Copy a folder tree (or one file) to another path on the same backend.\n"
                        "Use when: duplicating or merging a folder on one backend.\n"
                        "Instead: copy_file for a single file; copy_path_to_backend across "
                        "backends, or for files or trees that take over 5 min (resumable=true).\n"
                        "Behavior: breadth-first; src's entries land in dst, folders are created. "
                        "Existing files are skipped unless overwrite=true (destructive). "
                        f"A repeat with overwrite=true rewrites the same files. Locally mode and "
                        "mtime are kept. Symlinked files are copied as plain files; symlinked "
                        "folders and secret files give error entries. A rerun finishes a "
                        "truncated or timed-out copy (copied files are skipped).\n"
                        "Returns: {entries, truncated, complete}; entry fields and reasons explained "
                        "in outputSchema."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "src": _path_spec("The file or folder to copy"),
                            "dst": {**_path_spec("dst"), "description":
                                    "The copy (absolute, or relative to the MCP root): for a "
                                    "file the new file, for a folder the folder that becomes "
                                    "the copy, made if missing."},
                            "max_files": {"type": "integer", "minimum": 1,
                                          "maximum": MAX_BULK_COPY_FILES, "default": 1000,
                                          "description": "Most files to copy; truncated=true "
                                                         "when there were more."},
                            "max_depth": {"type": "integer", "minimum": 1,
                                          "maximum": MAX_TREE_DEPTH, "default": 10,
                                          "description": _levels_text("src") + " Deeper "
                                                         "folders get a 'max-depth' record."},
                            "max_file_bytes": {"type": "integer", "minimum": 1,
                                               "default": BULK_COPY_MAX_FILE_BYTES,
                                               "description": "Files larger than this many "
                                                              "bytes are skipped (default 10 "
                                                              "GiB)."},
                            "overwrite": {"type": "boolean", "default": False,
                                          "description": "true: replace files that exist at "
                                                         "the destination. false: skip them "
                                                         "(reason 'exists')."},
                        },
                        "required": ["src", "dst"],
                    },
                    handler=_bulk_copy,
                    write=True,
                ),
                _Tool(
                    name="symlink",
                    description=(
                        "Create a symbolic link at link_path pointing to target.\n"
                        "Use when: a second path should lead to a file or folder.\n"
                        "Instead: create_hardlink for a second name of one file; copy_file for a "
                        "copy.\n"
                        f"Behavior: only adds. A repeat fails with 'File exists'. Locally "
                        "the target must also stay inside the root; it may dangle. Local disk, SFTP "
                        f"and NFS only.\n"
                        "Returns: {ok: true}, plus target when the one stored differs."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "minLength": 1,
                                       "description": "What the link points to: absolute, or "
                                                      "relative to the link's folder, e.g. "
                                                      "'../shared/data.csv'. SFTP and NFS "
                                                      "store it as given."},
                            "link_path": _path_spec("The new link's own path; must not exist "
                                                    "yet"),
                        },
                        "required": ["target", "link_path"],
                    },
                    handler=_symlink,
                    write=True,
                ),
                _Tool(
                    name="hardlink",
                    description=(
                        "Create a hard link: a second name for an existing file.\n"
                        "Use when: one file must appear under two paths.\n"
                        "Instead: create_symlink for folders or across file systems; copy_file for "
                        "a copy.\n"
                        f"Behavior: only adds. A repeat fails with 'File exists'. One file "
                        f"system; local disk, SFTP and NFS only. {_SECRET_TAG}\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "target": _path_spec("The existing file to link to; unlike "
                                                 "symlink's target it is resolved like any "
                                                 "path"),
                            "link_path": _path_spec("The new name; must not exist yet"),
                        },
                        "required": ["target", "link_path"],
                    },
                    handler=_hardlink,
                    write=True,
                ),
                _Tool(
                    name="chmod",
                    description=(
                        "Set the POSIX permission bits of a file or folder.\n"
                        "Use when: making a script executable or a file private ('755', '600'); "
                        "get_path_info shows the mode.\n"
                        "Instead: none for owner or group; run_backend_command (chmod) on a "
                        "remote host for bits this tool refuses.\n"
                        "Behavior: destructive - replaces the mode of path only, not recursive "
                        "(a tree: one call per entry). Follows a symlink. Files with several "
                        "hard links are refused. Backends without POSIX modes fail ('... does "
                        "not support Unix permissions').\n"
                        "Returns: {ok: true}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "path": _path_spec("The file or folder"),
                            "mode": {
                                "description": "The new mode in octal: a string such as "
                                               "'644', '0644' or '0o755', or the integer "
                                               "value (420 = 0o644). Refused, with the "
                                               "reason: any bit outside 0755 - setuid, "
                                               "setgid, sticky, group or world write "
                                               "(e.g. '777', '4755', '664').",
                                "oneOf": [
                                    {"type": "integer", "minimum": 0,
                                     "maximum": _CHMOD_ALLOWED_BITS},
                                    {"type": "string", "pattern": _CHMOD_PATTERN},
                                ],
                            },
                        },
                        "required": ["path", "mode"],
                    },
                    handler=_chmod,
                    write=True,
                ),
            ]
        )
        for _tool in tools[_first_write_tool:]:
            _tool.group = "write"

    # ----------------------------------------------------------------
    # Scripting tools (opt-in via allow_scripts).
    #
    # script_list / script_read leak only metadata + bytes the user
    # already wrote; script_write / script_run / script_delete
    # mutate state. ALL are gated behind ``allow_scripts`` because
    # script_run hands the LLM arbitrary Python as the user (in a
    # child process, core.script_runner.run_bounded) — strictly more
    # powerful than the per-file write_file tool. Operators who want neither leave the flag off.
    # ----------------------------------------------------------------
    if allow_scripts:
        from core import scripting as _scripting

        def _script_list(args, ctx):
            return {"scripts": _scripting.list_scripts()}

        def _script_api_schema(args, ctx):
            # Read-only: built with inspect and ast from the scripting module
            # the server already imported; no user code runs.
            return _scripting.api_schema(names=args.get("names"))

        def _script_read(args, ctx):
            name = args.get("name")
            if not name:
                raise ValueError("read_script requires a name")
            return {"name": name, "source": _scripting.load_script(name)}

        def _script_write(args, ctx):
            name = args.get("name")
            source = args.get("source", "")
            if not name:
                raise ValueError("write_script requires a name")
            # Same attempt / ok / refused trail as the write tools: the
            # name and the size only, never the source text.
            _audit("script_write", "attempt", name=name)
            try:
                path = _scripting.save_script(name, source)
            except BaseException as exc:
                _audit("script_write", "refused", name=name, error=type(exc).__name__)
                raise
            size = len(source.encode("utf-8")) if isinstance(source, str) else 0
            _audit("script_write", "ok", name=name, size=size)
            return {"name": name, "path": path, "size": size}

        def _script_delete(args, ctx):
            name = args.get("name")
            if not name:
                raise ValueError("delete_script requires a name")
            _audit("script_delete", "attempt", name=name)
            try:
                existed = name in _scripting.list_scripts()
                _scripting.delete_script(name)
            except BaseException as exc:
                _audit("script_delete", "refused", name=name, error=type(exc).__name__)
                raise
            _audit("script_delete", "ok", name=name)
            # deleted: false - there was no such script (still no error).
            return {"name": name, "deleted": existed}

        def _script_run(args, ctx):
            """Run a saved script in a child process (core.script_runner)
            and answer with a structured outcome. Never in the server
            process: there a looping script held the server, nothing could
            stop it, and input() read the stdio JSON-RPC stream."""
            from core import script_runner as _runner
            from core.security_mode import current_policy, require
            from core.ui_helpers import ENV_NONINTERACTIVE

            name = args.get("name")
            if not name:
                raise ValueError("run_script requires a name")
            script_args = _script_run_args(args.get("args"))
            timeout_s = _script_run_timeout(args.get("timeout"))
            # Audit the name and the outcome only — the arguments and the
            # captured stdout/stderr are payload and stay out of the trail.
            _audit("script_run", "attempt", name=name)
            try:
                require("saved script execution", current_policy().allow_scripts)
                _scripting.load_script(name)  # refuses bad names, missing files
                run = _runner.run_bounded(
                    name,
                    args=script_args,
                    timeout_s=timeout_s,
                    max_output_chars=MAX_SCRIPT_OUTPUT_CHARS,
                    cancel_event=ctx.cancel_event,
                    env_overrides={ENV_NONINTERACTIVE: "1"},
                )
                if run.cancelled:
                    raise CancelledError("request cancelled by client")
                if run.output_exceeded:
                    raise RuntimeError(
                        f"script output exceeded {MAX_SCRIPT_OUTPUT_CHARS} characters "
                        f"on {run.output_exceeded}; the script was stopped"
                    )
            except BaseException as exc:
                _audit("script_run", "refused", name=name, error=type(exc).__name__)
                raise
            outcome: dict = {"exit": run.exit}
            if run.timed_out:
                outcome["timed_out"] = True
            if run.error_type:
                outcome["error"] = run.error_type
            _audit("script_run", "ok", name=name, **outcome)
            reply = {
                "name": name,
                "exit": run.exit,
                "timed_out": run.timed_out,
                "duration_ms": run.duration_ms,
                "stdout": run.stdout,
                "stderr": run.stderr,
                "namespace_keys": run.namespace_keys,
            }
            if run.error_type:
                reply.update(
                    error_type=run.error_type, error=run.error or "", traceback=run.traceback or ""
                )
            return reply

        _first_script_tool = len(tools)
        tools.extend(
            [
                _Tool(
                    name="script_list",
                    description=(
                        "List the names of the saved Python scripts.\n"
                        "Use when: looking for a script to read, run or delete.\n"
                        "Instead: read_script for a source; get_script_api for the API.\n"
                        "Behavior: read-only; the server's script folder, not the MCP root.\n"
                        "Returns: {scripts: [name, ...]}, sorted, without '.py'."
                    ),
                    schema={"type": "object", "properties": {}},
                    handler=_script_list,
                ),
                _Tool(
                    name="script_api_schema",
                    description=(
                        "Describe the axross Python API that scripts can call, as JSON from the "
                        "live code.\n"
                        "Use when: writing a script: names=[] gives the index (about 30 KB), then "
                        "the names you need.\n"
                        "Instead: read_script to see an existing script.\n"
                        "Behavior: read-only; runs no code. An unknown name fails.\n"
                        "Returns: {schema_version, module, legend, rules, errors, groups (names by "
                        "topic), functions, classes, backend_protocol, types}; the index has "
                        "functions and classes empty, names fills them for those names."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "names": {
                                "type": "array",
                                "items": {"type": "string", "minLength": 1},
                                "description": "Function, class or type names (from the "
                                               "index's groups), e.g. ['open_url', "
                                               "'FileItem']; each comes with the types it "
                                               "uses. [] gives the index alone (start "
                                               "there); omit names only for the whole API, "
                                               "some 200 KB.",
                            },
                        },
                    },
                    handler=_script_api_schema,
                ),
                _Tool(
                    name="script_read",
                    description=(
                        "Read the Python source of one saved script.\n"
                        "Use when: checking a script before run_script or write_script.\n"
                        "Instead: list_scripts for names; read_file for files under the MCP root.\n"
                        "Behavior: read-only. A missing script, a bad name or a symlinked file "
                        "fails.\n"
                        "Returns: {name, source}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {"name": _script_name_spec("The script's name, from "
                                                                 "list_scripts")},
                        "required": ["name"],
                    },
                    handler=_script_read,
                ),
                _Tool(
                    name="script_write",
                    description=(
                        "Save Python source as a named script, replacing one of that name.\n"
                        "Use when: creating or changing a script for run_script.\n"
                        "Instead: write_file for files under the MCP root.\n"
                        f"Behavior: destructive for a script of that name. Atomic, "
                        "mode 0600, in the script folder. Over 1 MiB of UTF-8 fails. Runs "
                        "nothing.\n"
                        "Returns: {name, path, size (bytes)}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "name": _script_name_spec("The script's name"),
                            "source": {"type": "string",
                                       "description": "The complete Python source; it runs "
                                                      "with the module axross already "
                                                      "imported."},
                        },
                        "required": ["name", "source"],
                    },
                    handler=_script_write,
                    write=True,
                ),
                _Tool(
                    name="script_delete",
                    description=(
                        "Delete one saved script permanently.\n"
                        "Use when: a script is no longer needed.\n"
                        "Instead: write_script to replace its source.\n"
                        f"Behavior: destructive, no trash. A repeat succeeds with "
                        "deleted false. A bad name fails.\n"
                        "Returns: {name, deleted (false: there was no such script)}."
                    ),
                    schema={
                        "type": "object",
                        "properties": {"name": _script_name_spec("The script's name, from "
                                                                 "list_scripts")},
                        "required": ["name"],
                    },
                    handler=_script_delete,
                    write=True,
                ),
                _Tool(
                    name="script_run",
                    description=(
                        "Run a saved Python script in a child process with the axross API "
                        "imported.\n"
                        "Use when: a job needs logic the file tools lack; write it with "
                        "write_script after get_script_api.\n"
                        "Instead: run_backend_command on a remote host.\n"
                        "Behavior: destructive - runs with the server user's full rights, outside "
                        "the MCP root. stdin is empty: API prompts "
                        "raise NonInteractiveError unless passed assume_yes=True. Over 1 MiB of "
                        "output fails the call (its effects stay). Time limit: timeout, then the "
                        "run is killed and returns timed_out true with the output so far.\n"
                        "Returns: {name, exit (negative: killed by that signal), timed_out, "
                        "duration_ms, stdout, stderr, namespace_keys (globals left)}, plus "
                        "{error_type, error, traceback} after an exception."
                    ),
                    schema={
                        "type": "object",
                        "properties": {
                            "name": _script_name_spec("The script's name, from list_scripts"),
                            "args": {
                                "type": "array",
                                "items": {"type": "string", "maxLength": MAX_SCRIPT_ARG_CHARS},
                                "maxItems": MAX_SCRIPT_ARGS,
                                "default": [],
                                "description": "Command-line arguments, the script's "
                                               "sys.argv[1:], e.g. ['--dry-run', 'docs']; no "
                                               "NUL characters.",
                            },
                            "timeout": {
                                "type": "number",
                                "exclusiveMinimum": 0,
                                "maximum": MAX_SCRIPT_TIMEOUT_S,
                                "default": DEFAULT_SCRIPT_TIMEOUT_S,
                                "description": "Wall-clock limit for the run in seconds.",
                            },
                        },
                        "required": ["name"],
                    },
                    handler=_script_run,
                    write=True,
                ),
            ]
        )

        for _tool in tools[_first_script_tool:]:
            _tool.group = "scripts"
            # They work on the script directory and never read ``backend``.
            _tool.accepts_backend = False

    # Capability groups (--mcp-tools). Built last among the tool sets so
    # they reuse the confinement and audit helpers above.
    if groups:
        tools.extend(
            _groups.build_group_tools(
                groups,
                _groups.GroupEnv(
                    default_backend=_default_backend,
                    resolve_backend=_resolve_backend,
                    # The groups read contents (metadata, file types,
                    # hashes, archives, packing, encryption, transfers):
                    # a secret is out of their reach like out of the root.
                    scope_path=_read_path,
                    write_path=_write_path,
                    entry_path=lambda p, b: _refuse_secret(_entry_path(p, b), b, entry=True),
                    entry_checker=_entry_checker,
                    refuse_root=_refuse_root,
                    refuse_moved_links=_refuse_moved_links,
                    index_backend_id=lambda b: (
                        server_backend_id if b is _default_backend else _backend_id_for(b)
                    ),
                    audit=_audit,
                    root=root,
                    read_roots=tuple(read_roots),
                    allow_write=allow_write,
                    backend_by_id=_backend_by_id,
                    remote=remote_registry,
                    allow_exec=bool(allow_exec) and _exec_allowed_by_policy(),
                    all_backends=lambda: {
                        **(backends or {"default": _default_backend}),
                        **(
                            {bid: o.backend for bid, o in remote_registry.entries()}
                            if remote_registry is not None
                            else {}
                        ),
                    },
                    groups=frozenset(groups),
                ),
            )
        )

    # Multi-backend wiring: if the caller configured a registry,
    # advertise it via a list_backends tool AND decorate every tool's
    # input schema with an optional ``backend`` field. Single-backend
    # deployments skip both — keeping the schema footprint unchanged.
    if backends:
        # Find the registry id that corresponds to the default
        # backend — identity (``is``) rather than equality so a
        # custom __eq__ doesn't fool the lookup. Only the FIRST
        # match gets is_default=True, so an operator accidentally
        # registering the same instance under two ids doesn't end
        # up with two defaults.
        _default_id: str | None = None
        for _bid, _b in backends.items():
            if _b is _default_backend:
                _default_id = _bid
                break

        def _commands(entry: dict, b) -> dict:
            # What run_backend_command runs there (the exec group only).
            if exec_served:
                entry["commands"] = _groups._exec_kind(b)
            return entry

        def _list_backends(args, ctx):
            out = []
            for bid, b in backends.items():
                out.append(_commands(
                    {
                        "id": bid,
                        "class": getattr(b, "display_class", None) or type(b).__name__,
                        "name": getattr(b, "name", "") or "",
                        "is_default": bid == _default_id,
                        "remote": False,
                    }, b)
                )
            if remote_registry is not None:
                # Profiles opened with remote_open in this session.
                for bid, opened in remote_registry.entries():
                    out.append(_commands(
                        {
                            "id": bid,
                            "class": type(opened.backend).__name__,
                            "name": getattr(opened.backend, "name", "") or "",
                            "is_default": False,
                            "remote": True,
                            "profile": opened.profile.name,
                            "protocol": opened.profile.protocol,
                            "production": bool(getattr(opened.profile, "production", False)),
                            # Lent by an axross pane: remote_close refuses it.
                            "lent": not getattr(opened, "owned", True),
                        }, opened.backend)
                    )
            if exec_served and args.get("can_run_commands") is True:
                out = [entry for entry in out if entry.get("commands")]
            return out

        tools.append(
            _Tool(
                name="list_backends",
                description=(
                    "List the backend ids this session can address, the default marked"
                    + ("; also which can run commands" if exec_served else "") + ".\n"
                    "Use when: choosing another tool's backend argument, e.g. after "
                    "open_remote_profile"
                    + (", or run_backend_command's" if exec_served else "") + ".\n"
                    "Instead: list_remote_profiles for saved connections not yet open.\n"
                    "Behavior: read-only; connects nothing. Served whenever tools take a "
                    "backend argument.\n"
                    f"Returns: a JSON array of {{id, {_CLASS_TEXT}, name, is_default, remote"
                    + (", commands" if exec_served else "") + "} (structuredContent: "
                    "{backends}). Opened profiles add {profile, protocol, production, lent (an "
                    "axross pane's connection)}."
                    + (" commands is posix-shell, powershell (WinRM), ios-show (Cisco IOS, show "
                       "commands only) or null (runs none)." if exec_served else "")
                ),
                schema={"type": "object", "properties": {
                    "can_run_commands": {
                        "type": "boolean",
                        "default": False,
                        "description": "true: only the backends run_backend_command and "
                        "run_backend_script can use (commands not null).",
                    }} if exec_served else {}},
                handler=_list_backends,
                group="remote" if remote_registry is not None else "core",
                accepts_backend=False,
            )
        )
        for tool in tools:
            if tool.name == "list_backends" or not tool.accepts_backend:
                continue
            props = tool.schema.setdefault("properties", {})
            props.setdefault(
                "backend",
                {
                    "type": "string",
                    "description": "Backend id from list_backends; omit for the default.",
                },
            )
            if tool.name in _BACKEND_REQUIRED:
                # The default backend runs no commands: say which one.
                props["backend"] = {
                    "type": "string",
                    "minLength": 1,
                    "description": "Backend id from list_backends (can_run_commands=true), e.g. "
                    "'profile:web1'.",
                }
                tool.schema["required"] = [*tool.schema.get("required", []), "backend"]
    for tool in tools:
        # Every handler takes only the arguments its schema names; the
        # dispatcher refuses the others (_argument_refusal), so say so.
        tool.schema.setdefault("additionalProperties", False)
        if tool.name in _LEVEL_DEPTH_TOOLS:
            tool.legacy_minimum = {"max_depth": 0}
    # Apply default wall-clock timeouts based on tool category. Set
    # here rather than at each _Tool() site so the table is easy to
    # reason about and tune in one place.
    _apply_default_timeouts(tools)
    _describe_requirements(tools)
    _describe_time_limits(tools)
    _tidy_descriptions(tools)
    _apply_tool_hints(tools)
    # A tool that takes a backend reaches what that backend reaches: with
    # remote connections in reach (the remote group, or a registry that holds
    # a remote backend), SFTP, S3, Drive... are an open world.
    reaches_remote = remote_registry is not None or any(
        not _groups._is_local(b) for b in (backends or {}).values())
    if reaches_remote:
        for tool in tools:
            props = tool.schema.get("properties", {})
            if tool.annotations and ({"backend", "src_backend", "dst_backend"} & set(props)):
                tool.annotations["openWorldHint"] = True
    _add_path_twins(tools)
    from core.previews import preview_available

    if not preview_available():
        # Neither Qt's image classes nor Pillow: preview could only fail.
        tools = [t for t in tools if t.name != "preview"]
    def _lock_resolve(kind, value):
        if kind == "backend":
            return _resolve_backend({"backend": value})
        return _backend_by_id(value)

    _serialize_mutations(tools, _lock_resolve)
    for tool in tools:
        if tool.name in _mcp_names.ARG_ALIASES:
            tool.handler = _taking_former_args(tool.handler, tool.name)
    return tools


def _taking_former_args(handler, name: str):
    """*handler* that also takes the former argument names of the tool
    *name* (core.mcp_names.ARG_ALIASES) - a direct call too, not only one
    through tools/call, which renames them before the schema check."""

    def run(args, ctx):
        return handler(_mcp_names.rename_args(name, args), ctx)

    run.__wrapped__ = getattr(handler, "__wrapped__", handler)
    return run


# Tool -> (title, readOnlyHint, destructiveHint, idempotentHint,
# openWorldHint): the annotations tools/list sends (MCP 2025-03-26 on).
# Hints, not guarantees - but true ones:
#   readOnly     the tool changes nothing: no file, no index, no remote
#                host (opening a connection for this session is not a
#                change of the environment), and hands no file contents to
#                a service outside (agent_run's LLM);
#   destructive  it can overwrite, remove or change what exists (False:
#                it only adds - a new file under a free name, an index
#                row); meaningful only when not read-only;
#   idempotent   MCP's meaning: the same call again has no additional
#                effect - also when it fails the second time (remove,
#                copy, rename); False where it writes 'x (2)', runs a
#                command or asks a model again. Every description says
#                which ("Idempotent:" / "Not idempotent:");
#   openWorld    it reaches beyond the configured backends: arbitrary
#                hosts, a command's or a script's effects, an LLM service.
# A tool missing here gets no annotations (the spec's defaults apply:
# not read-only, destructive, not idempotent, open world);
# tests/test_mcp_protocol_revisions.py demands an entry for every tool.
_TOOL_HINTS: dict[str, tuple[str, bool, bool, bool, bool]] = {
    # core: read-only file tools
    "list_dir": ("List directory", True, False, True, False),
    "stat": ("Get path info", True, False, True, False),
    "read_file": ("Read file", True, False, True, False),
    "checksum": ("Compute file checksum", True, False, True, False),
    "search": ("Search the file index", True, False, True, False),
    "walk": ("Walk folder tree", True, False, True, False),
    "recursive_checksum": ("Checksum folder tree", True, False, True, False),
    "preview": ("Preview image", True, False, True, False),
    "grep": ("Search file contents", True, False, True, False),
    "list_versions": ("List file versions", True, False, True, False),
    "open_version_read": ("Read older file version", True, False, True, False),
    "list_backends": ("List backends", True, False, True, False),
    # write (--mcp-write)
    "write_file": ("Write file", False, True, True, False),
    "mkdir": ("Create folder", False, False, True, False),
    "remove": ("Delete file or folder", False, True, True, False),
    "rename": ("Move or rename", False, True, True, False),
    "copy": ("Copy file", False, False, True, False),
    "bulk_copy": ("Copy folder tree", False, True, True, False),
    "symlink": ("Create symbolic link", False, False, True, False),
    "hardlink": ("Create hard link", False, False, True, False),
    "chmod": ("Change permissions", False, True, True, False),
    # scripts (--mcp-allow-scripts)
    "script_list": ("List scripts", True, False, True, False),
    "script_api_schema": ("Scripting API reference", True, False, True, False),
    "script_read": ("Read script", True, False, True, False),
    "script_write": ("Save script", False, True, True, False),
    "script_delete": ("Delete script", False, True, True, False),
    "script_run": ("Run script", False, True, False, True),
    # groups
    "metadata_read": ("Read file metadata", True, False, True, False),
    "metadata_export": ("Export file metadata", True, False, True, False),
    "metadata_remove": ("Strip metadata into copies", False, False, False, False),
    "duplicates_scan": ("Scan for duplicates", False, False, False, False),
    "duplicates_scans": ("List duplicate scans", True, False, True, False),
    "duplicates_groups": ("List duplicate groups", True, False, True, False),
    "duplicates_dedupe": ("Move duplicates to trash", False, True, True, False),
    "pack_formats": ("List archive formats", True, False, True, False),
    "pack": ("Create archive", False, False, False, False),
    "archive_list": ("List archive members", True, False, True, False),
    "archive_extract": ("Extract archive", False, False, False, False),
    "encrypt": ("Encrypt file", False, False, False, False),
    "decrypt": ("Decrypt file", False, False, False, False),
    "index_build": ("Build file index", False, False, True, False),
    "file_type": ("Identify file type", True, False, True, False),
    "file_type_scan": ("Identify file types in a folder", True, False, True, False),
    "transfer_copy": ("Copy path to backend", False, True, True, False),
    "transfer_move": ("Move file to backend", False, True, True, False),
    "remote_profiles": ("List connection profiles", True, False, True, False),
    "remote_open": ("Open remote profile", False, False, True, True),
    "remote_close": ("Close remote profile", False, False, True, True),
    "remote_exec": ("Run backend command", False, True, False, True),
    "remote_script": ("Run backend script", False, True, False, True),
    "agent_run": ("Ask the user's LLM", False, False, False, True),
    "extensions_list": ("List extensions", True, False, True, False),
}

_BOOLEAN = {"type": "boolean"}
# outputSchema per tool (MCP 2025-06-18): only tools whose every result
# has this shape; the result then also goes out as structuredContent.
#: Tools whose result is a JSON array: structuredContent carries it under
#: this key (_Tool.structured_key), the text stays the array.
_STRUCTURED_KEYS = {"list_dir": "entries", "list_versions": "versions",
                    "list_backends": "backends"}
_OUTPUT_SCHEMAS: dict[str, dict] = {
    "stat": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "is_dir": _BOOLEAN,
            "size": {"type": "integer", "minimum": 0},
            "modified": {"type": ["string", "null"], "description": "ISO 8601, or null"},
            "is_link": _BOOLEAN,
            "mode": {"type": ["string", "null"],
                     "description": "permission bits in octal, e.g. '0644'; null: none"},
        },
        "required": ["name", "is_dir", "is_link", "size", "modified", "mode"],
    },
    "read_file": {
        "type": "object",
        "properties": {
            "content_b64": {"type": "string", "description": "the bytes (encoding=base64)"},
            "text": {"type": "string", "description": "the text (encoding=text)"},
            "size": {"type": "integer", "minimum": 0, "description": "bytes read"},
            "truncated": {"type": "boolean"},
            "replaced": {"type": "boolean", "description": "text: undecodable bytes replaced"},
            "offset": {"type": "integer", "minimum": 0},
            "next_offset": {"type": "integer", "minimum": 0},
        },
        "required": ["size", "truncated"],
    },
    "checksum": {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "algorithm": {"type": "string"},
            "source": {"type": "string", "enum": ["native", "stream"]},
        },
        "required": ["value", "algorithm", "source"],
    },
    "walk": {
        "type": "object",
        "properties": {
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "is_dir": _BOOLEAN,
                        "is_link": _BOOLEAN,
                        "size": {"type": "integer", "minimum": 0},
                        "modified": {"type": ["string", "null"],
                                     "description": "ISO 8601, or null"},
                    },
                    "required": ["path", "name", "is_dir", "is_link", "size", "modified"],
                },
            },
            "truncated": {"type": "boolean"},
            "unreadable": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}, "error": {"type": "string"}},
                    "required": ["path", "error"],
                },
            },
            "complete": {"type": "boolean"},
        },
        "required": ["entries", "truncated", "unreadable", "complete"],
    },
}


def _object(properties: dict, *required: str) -> dict:
    return {"type": "object", "properties": properties, "required": list(required)}


_INT0 = {"type": "integer", "minimum": 0}
_STR = {"type": "string"}
_OK = _object({"ok": {"type": "boolean", "const": True}}, "ok")
_EXEC_RESULT = _object(
    {"returncode": {"type": "integer"}, "stdout": _STR, "stderr": _STR,
     "truncated_stdout": _BOOLEAN, "truncated_stderr": _BOOLEAN},
    "returncode", "stdout", "stderr", "truncated_stdout", "truncated_stderr")
_UNREADABLE = {"type": "array", "items": _object({"path": _STR, "error": _STR}, "path", "error")}
_STRINGS = {"type": "array", "items": _STR}
_ISO = {"type": ["string", "null"], "description": "ISO 8601, or null"}
_REPORT = _object({
    "path": _STR, "name": _STR, "kind": {"type": ["string", "null"]},
    "size": {"type": ["integer", "null"]}, "error": _STR, "truncated": _BOOLEAN,
    "removable_count": _INT0,
    "fields": {"type": "array", "items": _object({
        "group": _STR, "name": _STR, "value": {}, "removable": _BOOLEAN},
        "group", "name", "value", "removable")}},
    "path", "name", "kind", "error", "fields")
_TYPE_RECORD = _object({
    "path": {"type": "string", "description": "the file as asked for"},
    "name": {"type": "string", "description": "its file name"},
    "kind": {"type": "string",
             "enum": ["file", "directory", "special", "error", "timeout", "cancelled"],
             "description": "special: a FIFO, device or socket (not read); error, timeout, "
                            "cancelled: not read, error says why and the type fields are "
                            "empty"},
    "description": {"type": "string", "description": "the content type in words, e.g. "
                                                     "'PNG image'; '' when unknown"},
    "mime": {"type": "string", "description": "the content's MIME type; '' when unknown"},
    "extension": {"type": "string", "description": "the name's extension, e.g. '.png'; '' "
                                                   "for none"},
    "extension_mime": {"type": "string", "description": "the MIME type the extension "
                                                        "claims; '' when it is unknown"},
    "verdict": {"type": "string", "enum": ["match", "mismatch", "unknown"],
                "description": "content against extension; unknown: no extension claim, or "
                               "the content cannot tell"},
    "mismatch": {"type": "boolean", "description": "verdict == 'mismatch'"},
    "size": {"type": ["integer", "null"], "description": "bytes; null when not known"},
    "encoding": {"type": "string", "description": "text only: 'ASCII', 'UTF-8', a BOM's "
                                                  "name or a guess; '' for binary"},
    "line_endings": {"type": "string", "description": "text only: 'LF', 'CRLF', 'CR', "
                                                      "'mixed (...)' or 'none'"},
    "engine": {"type": "string", "description": "what decided: 'Qt', 'puremagic', "
                                                "'signature table', 'text heuristic', "
                                                "'disk image' or 'size'"},
    "file_command": {"type": "string", "description": "file(1)'s description, local only; "
                                                      "'' when unavailable"},
    "bytes_read": {"type": ["integer", "null"], "description": "bytes of content read (at "
                                                               "most max_bytes)"},
    "error": {"type": "string", "description": "why the type fields are empty; '' when read"}},
    "path", "name", "kind", "verdict", "mismatch")
_EXTENSION = _object({
    "id": _STR, "name": _STR, "version": _STR, "description": _STR, "author": _STR,
    "source": _STR,
    "enabled": {"type": "boolean", "description": "switched on in Manage Extensions"},
    "loadable": {"type": "boolean", "description": "its manifest and code can load"},
    "error": _STR,
    "active": {"type": "boolean", "description": "loaded by the app now"}},
    "id", "name", "enabled", "loadable", "active")
# More tools whose every result has one shape (tests/test_mcp_tool_quality.py
# checks real results against each).
_OUTPUT_SCHEMAS.update({
    "recursive_checksum": _object({
        "entries": {"type": "array", "items": _object({
            "path": _STR, "size": _INT0, "algorithm": _STR,
            "checksum": {"type": "string", "description": "hex digest; absent when not hashed"},
            "source": {"type": "string", "enum": ["native", "stream"],
                       "description": "native: the backend's own hash; stream: read here"},
            "skipped": {"type": "string", "enum": ["too-large"],
                        "description": "above max_file_bytes, not hashed"},
            "error": {"type": "string", "description": "why this file or folder was not hashed"},
            "folder": {"type": "boolean",
                       "description": "true: a folder that could not be listed, or a "
                                      "symlinked folder; the files below it are missing"}},
            "path", "algorithm")},
        "truncated": _BOOLEAN, "complete": _BOOLEAN}, "entries", "truncated", "complete"),
    "grep": _object({
        "matches": {"type": "array", "items": _object({
            "path": _STR, "line_no": {"type": "integer", "minimum": 1}, "line": _STR},
            "path", "line_no", "line")},
        "files_scanned": _INT0, "truncated": _BOOLEAN, "unreadable": _UNREADABLE,
        "complete": _BOOLEAN}, "matches", "files_scanned", "truncated", "unreadable", "complete"),
    "open_version_read": None,  # read_file's (set below)
    "write_file": _object({"size": _INT0}, "size"),
    "mkdir": _OK, "remove": _OK, "rename": _OK, "copy": _OK, "hardlink": _OK, "chmod": _OK,
    "symlink": _object({"ok": {"type": "boolean", "const": True},
                        "target": {"type": "string",
                                   "description": "the target stored, when not the one given"}},
                       "ok"),
    "bulk_copy": _object({
        "entries": {"type": "array", "items": _object({
            "src": _STR, "dst": _STR, "size": _INT0,
            "action": {"type": "string", "enum": ["copied", "skipped", "error"]},
            "reason": {"type": "string",
                       "enum": ["exists", "too-large", "unsafe-name", "max-depth"],
                       "description": "exists: dst has it (overwrite=false); too-large: over "
                                      "max_file_bytes; unsafe-name: a name with a path "
                                      "separator or control character, not copied; "
                                      "max-depth: a folder below max_depth"},
            "error": {"type": "string", "description": "why it failed (secret files too)"},
            "folder": {"type": "boolean", "description": "true: a folder that could not be "
                                                         "listed; its files are missing"},
            "name": {"type": "string", "description": "the unsafe name, quoted"}},
            "src", "dst", "size", "action")},
        "truncated": _BOOLEAN, "complete": _BOOLEAN}, "entries", "truncated", "complete"),
    "script_list": _object({"scripts": {"type": "array", "items": _STR}}, "scripts"),
    "script_read": _object({"name": _STR, "source": _STR}, "name", "source"),
    "script_write": _object({"name": _STR, "path": _STR, "size": _INT0}, "name", "path", "size"),
    "script_delete": _object({"name": _STR, "deleted": {
        "type": "boolean", "description": "false: there was no such script"}},
        "name", "deleted"),
    "script_run": _object({
        "name": _STR, "exit": {"type": "integer"}, "timed_out": _BOOLEAN,
        "duration_ms": _INT0, "stdout": _STR, "stderr": _STR,
        "namespace_keys": {"type": "array", "items": _STR},
        "error_type": _STR, "error": _STR, "traceback": _STR},
        "name", "exit", "timed_out", "duration_ms", "stdout", "stderr", "namespace_keys"),
    "remote_open": _object({
        "backend": _STR, "profile": _STR, "protocol": _STR, "class": _STR,
        "production": _BOOLEAN, "writable": _BOOLEAN, "reused": _BOOLEAN},
        "backend", "profile", "protocol", "class", "production", "writable", "reused"),
    "remote_close": _object({"backend": _STR, "closed": {"type": "boolean", "const": True}},
                            "backend", "closed"),
    "remote_exec": _EXEC_RESULT,
    "remote_script": _EXEC_RESULT,
    "transfer_copy": _object({
        "src": _STR, "dst": _STR, "copied": _INT0, "truncated": _BOOLEAN, "complete": _BOOLEAN,
        "entries": {"type": "array", "items": _object({
            "src": _STR, "dst": _STR, "size": _INT0,
            "action": {"type": "string", "enum": ["copied", "skipped", "error"]},
            "reason": {"type": "string", "enum": [
                "exists", "too-large", "symlink", "special-file", "protected", "unsafe-name",
                "outside-root", "max-depth", "size-mismatch"],
                "description": "exists: at the destination (overwrite=false); too-large: over "
                               "max_file_bytes; symlink: a symlinked folder, or any link on "
                               "a remote (local links to files are copied); special-file: a "
                               "device, "
                               "FIFO or socket; protected: the destination is a protected "
                               "place; unsafe-name: a name the destination refuses; "
                               "outside-root: outside the MCP root, or a secret file; "
                               "max-depth: a folder below subfolder_levels; size-mismatch: "
                               "the source sent another size (the copy was removed)"},
            "bytes": {"type": "integer", "minimum": 0,
                      "description": "bytes written for this entry"},
            "resumed_segments": {"type": "integer", "minimum": 0,
                                 "description": "resumable=true: 4 MiB segments an earlier "
                                                "run had copied already"},
            "error": {"type": "string", "description": "why the entry failed or was left out"},
            "folder": {"type": "boolean", "description": "true: a folder that could not be "
                                                         "listed"},
            "name": {"type": "string", "description": "unsafe-name: the refused name, quoted"}},
            "src", "dst", "size", "action")}},
        "src", "dst", "copied", "truncated", "complete", "entries"),
    "decrypt": _object({"path": _STR, "size": _INT0}, "path", "size"),
    "transfer_move": _object({"src": _STR, "dst": _STR, "bytes": _INT0}, "src", "dst", "bytes"),
    "metadata_read": _object({"path": _STR, "is_dir": _BOOLEAN, "truncated": _BOOLEAN,
                              "files": {"type": "array", "items": _REPORT}},
                             "path", "is_dir", "truncated", "files"),
    "metadata_export": _object({"path": _STR, "format": {"type": "string",
                                                         "enum": ["json", "csv"]},
                                "files": _INT0, "truncated": _BOOLEAN,
                                "text": {"type": "string", "description": "the export; "
                                         "absent with out"},
                                "out": {"type": "string", "description": "with out: the "
                                        "file written (a taken name gets a counter)"},
                                "size": {"type": "integer", "minimum": 0,
                                         "description": "with out: bytes written"}},
                               "path", "format", "files", "truncated"),
    "metadata_remove": _object({
        "path": _STR, "mode": {"type": "string", "const": "copy"}, "truncated": _BOOLEAN,
        "results": {"type": "array", "items": _object({
            "path": _STR,
            "status": {"type": "string",
                       "enum": ["cleaned", "unchanged", "unsupported", "skipped", "error"]},
            "output": _STR, "removed": _INT0, "sha256": _STR, "error": _STR, "note": _STR},
            "path", "status")}},
        "path", "mode", "truncated", "results"),
    "archive_list": _object({
        "path": _STR, "total": _INT0, "truncated": _BOOLEAN,
        "entries": {"type": "array", "items": _object({
            "name": _STR, "size": _INT0, "compressed": _INT0,
            "mtime": {"type": ["number", "null"], "description": "Unix seconds"},
            "modified": {"type": ["string", "null"], "description": "mtime as ISO 8601"},
            "is_dir": _BOOLEAN}, "name", "size", "compressed", "mtime", "modified", "is_dir")}},
        "path", "total", "truncated", "entries"),
    "archive_extract": _object({"path": _STR, "files": _INT0, "skipped_links": _STRINGS,
                                "note": _STR}, "path", "files"),
    "pack": _object({"path": _STR, "format": _STR, "files": _INT0, "folders": _INT0,
                     "bytes_in": _INT0, "bytes_out": _INT0, "skipped": _STRINGS,
                     "encrypted": _BOOLEAN},
                    "path", "format", "files", "folders", "bytes_in", "bytes_out", "skipped",
                    "encrypted"),
    "pack_formats": _object({"formats": {"type": "array", "items": _object({
        "format": _STR, "label": _STR, "suffix": _STR, "single": _BOOLEAN,
        "encrypts": _BOOLEAN, "available": _BOOLEAN, "reason": _STR},
        "format", "label", "suffix", "single", "encrypts", "available", "reason")},
        "levels": _STRINGS}, "formats", "levels"),
    "duplicates_scan": _object({
        "scan_id": {"type": ["integer", "null"]}, "root": _STR, "backend_id": _STR,
        "algorithm": _STR, "files_indexed": _INT0,
        "status": {"type": "string", "enum": ["complete", "cancelled", "failed"]},
        "truncated": _BOOLEAN, "complete": _BOOLEAN, "unreadable": _STRINGS},
        "scan_id", "root", "backend_id", "algorithm", "files_indexed", "status", "truncated",
        "complete"),
    "duplicates_scans": _object({"scans": {"type": "array", "items": _object({
        "scan_id": {"type": "integer"}, "root": _STR, "backend_id": _STR, "algorithm": _STR,
        "started_at": _ISO, "finished_at": _ISO, "files_indexed": _INT0,
        "files_in_index": _INT0, "duplicate_groups": _INT0,
        "status": {"type": "string", "enum": ["complete", "cancelled", "failed", "running"]},
        "error": _STR}, "scan_id", "root", "backend_id", "algorithm", "status")},
        "truncated": _BOOLEAN}, "scans", "truncated"),
    "duplicates_groups": _object({"path": _STR, "truncated": _BOOLEAN,
                                  "groups": {"type": "array", "items": _object({
                                      "algorithm": _STR, "value": _STR, "size": _INT0,
                                      "copies": {"type": "array", "items": _object({
                                          "path": _STR, "size": _INT0,
                                          "mtime": {"type": ["number", "null"],
                                                    "description": "Unix seconds"},
                                          "modified": {"type": ["string", "null"],
                                                       "description": "mtime as ISO 8601"},
                                          "scan_id": {"type": ["integer", "null"]},
                                          "keep": _BOOLEAN},
                                          "path", "size", "mtime", "scan_id", "keep")}},
                                      "algorithm", "value", "size", "copies")}},
                                 "path", "truncated", "groups"),
    "duplicates_dedupe": _object({
        "path": _STR, "dry_run": _BOOLEAN, "groups": _INT0, "undated_groups": _INT0,
        "keep": _STRINGS, "trash": _STRINGS, "removed": _STRINGS,
        "refused": {"type": "array", "items": _object({"path": _STR, "reason": _STR},
                                                      "path", "reason")},
        "failed": {"type": "array", "items": _object({"path": _STR, "reason": _STR},
                                                     "path", "reason")},
        "trash_root": {"type": ["string", "null"]}},
        "path", "dry_run", "groups", "undated_groups", "keep", "trash", "removed", "refused",
        "failed", "trash_root"),
    "index_build": _object({"path": _STR, "backend_id": _STR, "recursive": _BOOLEAN,
                            "indexed": _INT0, "pruned": _INT0, "truncated": _BOOLEAN,
                            "complete": _BOOLEAN, "unreadable": _STRINGS},
                           "path", "backend_id", "recursive", "indexed", "pruned", "truncated",
                           "complete"),
    "file_type": _TYPE_RECORD,
    "file_type_scan": _object({"path": _STR, "files_scanned": _INT0, "truncated": _BOOLEAN,
                               "complete": _BOOLEAN, "unreadable": _STRINGS,
                               "entries": {"type": "array", "items": _TYPE_RECORD}},
                              "path", "files_scanned", "truncated", "complete", "entries"),
    "remote_profiles": _object({"profiles": {"type": "array", "items": _object({
        "name": _STR, "protocol": _STR, "host": {"type": ["string", "null"]},
        "port": {"type": ["integer", "null"]}, "username": {"type": ["string", "null"]},
        "auth_type": {"type": ["string", "null"]},
        "store_password": {"type": ["boolean", "null"]}, "production": _BOOLEAN,
        "open_as": {"type": ["string", "null"]}, "openable": _BOOLEAN, "reason": _STR},
        "name", "protocol", "production", "open_as", "openable", "reason")}}, "profiles"),
    "extensions_list": _object({
        "allowed": {"type": "boolean",
                    "description": "extensions may load (false in paranoid mode)"},
        "runnable_over_mcp": {"type": "boolean", "description": "always false"},
                                "why_not_runnable": _STR,
                                "extensions": {"type": "array", "items": _EXTENSION}},
                               "allowed", "runnable_over_mcp", "why_not_runnable",
                               "extensions"),
    "script_api_schema": _object({
        "schema_version": {"type": "integer"}, "module": _STR,
        "legend": {"type": "object", "description": "what each field means",
                   "additionalProperties": {}},
        "rules": {"type": "array", "items": {"type": "object"}},
        "errors": {"type": "array", "items": {"type": "object"}},
        "groups": {"type": "array", "items": _object({
            "name": _STR, "functions": _STRINGS, "classes": _STRINGS}, "name")},
        "functions": {"type": "array", "description": "[] for the index (names=[])",
                      "items": _object({"name": _STR, "signature": _STR}, "name")},
        "classes": {"type": "array", "description": "[] for the index",
                    "items": _object({"name": _STR}, "name")},
        "backend_protocol": {"type": "array", "items": {"type": "object"}},
        "types": {"type": "array", "items": _object({"name": _STR}, "name")}},
        "schema_version", "module", "groups", "functions", "classes", "types"),
    "agent_run": _object({
        "answer": _STR,
        "stopped": {"type": "string", "enum": ["answered", "max_steps", "cancelled"]},
        "calls": {"type": "array", "items": _object({
            "name": _STR,
            "outcome": {"type": "string",
                        "enum": ["ok", "error", "declined", "unavailable"]}}, "name")},
        "profile": _STR, "model": _STR}, "answer", "stopped", "calls", "profile", "model"),
    "list_dir": _object({"entries": {"type": "array", "items": _object({
        "name": _STR, "is_dir": _BOOLEAN, "is_link": _BOOLEAN, "size": _INT0, "modified": _ISO},
        "name", "is_dir", "is_link", "size", "modified")}}, "entries"),
    "search": _object({"entries": {"type": "array", "items": _object({
        "backend_id": _STR, "path": _STR, "name": _STR, "size": _INT0, "is_dir": _BOOLEAN,
        "modified": _ISO}, "backend_id", "path", "name", "size", "is_dir", "modified")},
        "indexed": {"type": "boolean",
                    "description": "false: this backend has no index rows at all"},
        "truncated": {"type": "boolean",
                      "description": "true: more matches after this page (offset + "
                                     "max_results)"}},
        "entries", "indexed", "truncated"),
    "list_versions": _object({"versions": {"type": "array", "items": _object({
        "version_id": _STR, "size": _INT0, "modified": _ISO, "is_current": _BOOLEAN,
        "label": _STR}, "version_id", "size", "modified", "is_current", "label")}},
        "versions"),
    "list_backends": _object({"backends": {"type": "array", "items": _object({
        "id": _STR, "class": _STR, "name": _STR, "is_default": _BOOLEAN, "remote": _BOOLEAN,
        "profile": _STR, "protocol": _STR, "production": _BOOLEAN,
        "lent": {"type": "boolean", "description": "a connection of an axross pane; "
                                                   "close_remote_profile refuses it"},
        "commands": {"type": ["string", "null"],
                     "enum": ["posix-shell", "powershell", "ios-show", None],
                     "description": "with the exec group: what run_backend_command runs "
                                    "there (ios-show: Cisco IOS show commands only); null: "
                                    "none"}},
        "id", "class", "name", "is_default", "remote")}}, "backends"),
    "encrypt": _object({"path": _STR, "size": _INT0, "plaintext_size": _INT0},
                       "path", "size", "plaintext_size"),
})
_OUTPUT_SCHEMAS["open_version_read"] = _OUTPUT_SCHEMAS["read_file"]


def _apply_tool_hints(tools: list[_Tool]) -> None:
    for tool in tools:
        hint = _TOOL_HINTS.get(tool.name)
        if hint is not None:
            title, read_only, destructive, idempotent, open_world = hint
            if tool.title is None:
                tool.title = title
            if tool.annotations is None:
                tool.annotations = {
                    "title": tool.title,
                    "readOnlyHint": read_only,
                    "destructiveHint": destructive,
                    "idempotentHint": idempotent,
                    "openWorldHint": open_world,
                }
        tool.structured_key = tool.structured_key or _STRUCTURED_KEYS.get(tool.name)
        if tool.output_schema is None and tool.name in _OUTPUT_SCHEMAS:
            import copy

            tool.output_schema = copy.deepcopy(_OUTPUT_SCHEMAS[tool.name])


# Tool → timeout class (a key of TIMEOUT_CLASSES). Anything missing lands
# on "quick"; group tools name their class on the _Tool itself. Callers
# can override on a specific tool by assigning after build.
_TIMEOUT_CLASS_BY_TOOL = {
    # Quick: one backend op, bounded output.
    "list_dir": "quick",
    "stat": "quick",
    "read_file": "quick",
    "search": "quick",
    "list_versions": "quick",
    "open_version_read": "quick",
    # checksum may stream-hash a whole file when the backend has no
    # native fingerprint.
    "checksum": "stream",
    # Traversal: may hit many files over slow backends.
    "walk": "walk",
    "grep": "walk",
    # recursive_checksum can be long: 500 files × streaming sha256 of
    # up-to-1 GiB each is many minutes even on a fast local backend.
    # The cancel path inside _hash_one_path means clients can always
    # stop sooner; this is just the deadline before the timer fires.
    "recursive_checksum": "stream",
    # Preview runs an image decoder + resizer — give it breathing room.
    "preview": "preview",
    # Writes: one round-trip per call, but a slow backend (SMB over a
    # flaky link) can take a while to acknowledge.
    "write_file": "write",
    "mkdir": "write",
    "remove": "write",
    "rename": "write",
    "copy": "write",
    # bulk_copy walks a tree and issues backend.copy per file. 1000
    # files × 30 s each is a lot — but the cancel path inside the
    # per-file loop means the client can always stop sooner. The
    # streaming-hash ceiling doubles as "long write" ceiling here.
    "bulk_copy": "stream",
    # script_run stops its child at its own timeout_s; the tool deadline
    # only backs that up (DEFAULT_TIMEOUT_SCRIPT).
    "script_run": "script",
    "symlink": "write",
    "hardlink": "write",
    "chmod": "write",
}
# Seconds per tool, derived from the class table (kept for callers that
# read the per-tool ceiling directly).
_TIMEOUT_BY_TOOL = {
    name: TIMEOUT_CLASSES[cls] for name, cls in _TIMEOUT_CLASS_BY_TOOL.items()
}


def _apply_default_timeouts(tools: list[_Tool]) -> None:
    for tool in tools:
        if tool.timeout_class is None:
            tool.timeout_class = _TIMEOUT_CLASS_BY_TOOL.get(tool.name, "quick")
        if tool.timeout_seconds is None:
            tool.timeout_seconds = TIMEOUT_CLASSES[tool.timeout_class]


def _duration_text(seconds: float) -> str:
    if seconds >= 120 and seconds % 60 == 0:
        return f"{int(seconds // 60)} min"
    return f"{seconds:g} s"


def _describe_requirements(tools: list[_Tool]) -> None:
    """Open each gated tool's ``Requires:`` line with the server flags it is
    served under (core.mcp_groups._required_flags, as the manifest lists
    them): a condition of the server, said once and alike everywhere."""
    from core import mcp_groups as _groups

    for tool in tools:
        if tool.group == "core" or tool.name == "list_backends":
            continue  # list_backends is there whenever a tool takes backend
        # --mcp-write (and --mcp-root) is the instructions' write rule, said once there.
        flags = [f for f in _groups._required_flags(tool)
                 if not f.startswith(("--mcp-root", "--mcp-write"))]
        if not flags:
            continue
        clause = " and ".join(flags)
        if tool.group == "scripts":
            clause += " (stdio only)"
        if tool.group in ("scripts", "exec"):
            clause += "; not in paranoid mode"
        lines = tool.description.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("Requires:"):
                rest = line[len("Requires:"):].strip()
                lines[i] = f"Requires: {clause}; {rest}"
                break
        else:
            at = next(i for i, line in enumerate(lines) if line.startswith("Behavior:"))
            lines.insert(at, f"Requires: {clause}.")
        tool.description = "\n".join(lines)


def _tidy_descriptions(tools: list[_Tool]) -> None:
    """No trailing or doubled blanks where a description's parts meet."""
    import re

    for tool in tools:
        lines = (re.sub(r" {2,}", " ", line).rstrip() for line in tool.description.split("\n"))
        tool.description = "\n".join(lines)


def _describe_time_limits(tools: list[_Tool]) -> None:
    """End each description's ``Behavior:`` line with the tool's deadline
    (timeout_seconds), so a client knows when a call is given up. Tools
    with a time limit argument of their own (script_run's timeout_s,
    remote_exec's timeout) describe that one instead."""
    for tool in tools:
        props = (tool.schema or {}).get("properties", {})
        if not tool.timeout_seconds or {"timeout", "timeout_s"} & set(props):
            continue
        lines = tool.description.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("Behavior:") and "Time limit:" not in line:
                lines[i] = f"{line} Time limit: {_duration_text(tool.timeout_seconds)}."
                break
        tool.description = "\n".join(lines)


# ---------------------------------------------------------------------------
# Resources (resources/list, resources/read, resources/templates/list)
# ---------------------------------------------------------------------------

# Conservative text-ish mime prefixes — anything not matching is
# returned as a base64 ``blob`` field per MCP spec. The goal isn't to
# be an authoritative mime detector; it's to avoid sending binary
# bytes to clients as text and getting UnicodeDecodeErrors on their
# end.
_TEXT_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
    "application/javascript",
)


def _parse_resource_uri(uri: str) -> str:
    """Parse ``axross://<path>`` and return the raw absolute path.

    Rejects any other scheme with a ValueError so the dispatcher can
    map it to -32602 rather than leaking an internal traceback.

    URL-encoded bytes are decoded: a malicious ``axross:///%2e%2e%2f``
    becomes ``/../`` which ``_enforce_root``'s abspath-then-realpath
    pass will either collapse (if staying inside the root) or
    reject (if escaping). Without this decode, the backend might
    interpret ``%2e`` inconsistently between protocols — a foot-gun
    once a backend that does decode (e.g. future URL-aware one)
    enters the picture.
    """
    import urllib.parse

    if not isinstance(uri, str):
        raise ValueError("uri must be a string")
    prefix = f"{RESOURCE_SCHEME}://"
    if not uri.startswith(prefix):
        raise ValueError(f"unsupported resource scheme: {uri!r} — expected {prefix}<path>")
    raw = uri[len(prefix) :]
    # Strip query + fragment — they aren't meaningful for a file
    # URI and would otherwise be passed to the backend, which
    # might interpret them or fail with a confusing error.
    for sep in ("?", "#"):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    path = urllib.parse.unquote(raw)
    # Allow both ``axross:///abs/path`` (empty authority, common in
    # URI literature) and ``axross://abs/path``. The path component
    # starts after the first slash of an empty authority or is the
    # whole remainder. Normalise to a leading-slash absolute path.
    if not path.startswith("/"):
        path = "/" + path
    return path


def _guess_mime(path: str) -> str:
    """Best-effort mime guess for a path. Falls back to
    ``application/octet-stream`` so binary-safe callers get the blob
    encoding."""
    import mimetypes

    guess, _ = mimetypes.guess_type(path)
    return guess or "application/octet-stream"


@dataclass
class _ResourceCatalog:
    """Bundle the backend + root so ``_handle_request`` can serve
    ``resources/*`` without re-deriving them on every call.

    Kept separate from the tools catalogue because the MCP spec
    models resources and tools as two different capabilities. A
    server may expose one without the other; tests drive them
    independently."""

    backend: Any
    root: str  # absolute, enforced on every read
    #: --mcp-allow-secret-reads: secret files (core.protected_places) may be read.
    allow_secret_reads: bool = False

    def list_root(self) -> list[dict]:
        """Return up to MAX_RESOURCES_LISTED entries directly under
        the root, each as an MCP resource descriptor. Directories
        are included so an LLM can walk via the URI template."""
        try:
            entries = self.backend.list_dir(self.root)
        except Exception as exc:  # noqa: BLE001 — surface to client
            raise RuntimeError(f"list_root failed: {exc}") from exc
        out: list[dict] = []
        for it in entries:
            name = getattr(it, "name", "") or ""
            if not name or name in (".", ".."):
                continue
            is_dir = bool(getattr(it, "is_dir", False))
            from core.path_policy import safe_join

            try:
                child_path = safe_join(self.backend, self.root, name)
            except ValueError as exc:
                log.warning(
                    "MCP resources/list: skipping unsafe backend entry %r: %s",
                    name,
                    exc,
                )
                continue
            # Slash-terminate dir URIs so clients can tell them apart
            # without an extra stat round-trip.
            child = child_path.rstrip("/") + ("/" if is_dir else "")
            mime = "inode/directory" if is_dir else _guess_mime(name)
            out.append(
                {
                    "uri": f"{RESOURCE_SCHEME}://{child}",
                    "name": name,
                    "description": "directory"
                    if is_dir
                    else f"file, {getattr(it, 'size', 0)} bytes",
                    "mimeType": mime,
                }
            )
            if len(out) >= MAX_RESOURCES_LISTED:
                break
        return out

    def list_templates(self) -> list[dict]:
        """One template covering any absolute path under the
        configured root. MCP clients substitute ``{path}`` with
        paths they discovered through tools or previous reads."""
        return [
            {
                "uriTemplate": f"{RESOURCE_SCHEME}://{{+path}}",
                "name": "backend-file",
                "description": (
                    f"Any file reachable through the configured backend, "
                    f"rooted at {self.root}. Reads are capped at "
                    f"{MAX_READ_BYTES} bytes."
                ),
            }
        ]

    def read(self, uri: str) -> dict:
        """Resolve *uri*, enforce the root, return an MCP
        ``resources/read`` contents entry."""
        raw_path = _parse_resource_uri(uri)
        # Strip trailing slash the caller used as a "is-directory"
        # marker — the backend won't accept it.
        clean = raw_path.rstrip("/") or "/"
        resolved = _enforce_root(clean, self.root)
        if not self.allow_secret_reads:
            import os.path as op

            from core import protected_places

            check = protected_places.secret_checker(granted=(self.root,))
            typed = op.abspath(clean if op.isabs(clean) else op.join(self.root, clean))
            for name in dict.fromkeys((typed, resolved)):
                reason = check(name)
                if reason is not None:
                    raise PermissionError(reason)
        with self.backend.open_read(resolved) as fh:
            data, _ = _read_capped_stream(fh, MAX_READ_BYTES)
        # Silently truncate at cap — the MCP spec has no partial-read
        # marker on resources/read so we'd have to lie either way.
        # 4 MiB is plenty for any text file an LLM should be reading
        # inline; binary blobs that size are a misuse of the resource
        # channel anyway.
        data = bytes(data)
        mime = _guess_mime(resolved)
        text_like = any(mime.startswith(p) for p in _TEXT_MIME_PREFIXES)
        entry: dict[str, Any] = {"uri": uri, "mimeType": mime}
        if text_like:
            try:
                entry["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                # Mime said text but the bytes aren't UTF-8 (a
                # Latin-1 .txt, a binary file with a .log
                # extension). Fall back to blob so the client gets
                # the raw bytes instead of a partial mojibake
                # string.
                entry["blob"] = base64.b64encode(data).decode("ascii")
                entry["mimeType"] = "application/octet-stream"
        else:
            entry["blob"] = base64.b64encode(data).decode("ascii")
        return entry


def _build_resources(backend, *, root: str | None = None,
                     allow_secret_reads: bool = False) -> _ResourceCatalog:
    """Construct the resources catalogue. Separated from
    :func:`_build_tools` so tests can drive one without the other
    and the HTTP transport can share them trivially."""
    if root is not None:
        # Opened beneath the root without following a swapped-in symlink.
        backend, _ = _confine_local(backend, None, (root,),
                                    allow_secret_reads=allow_secret_reads)
    return _ResourceCatalog(backend=backend, root=root or "/",
                            allow_secret_reads=allow_secret_reads)


# ---------------------------------------------------------------------------
# notifications/message — server→client log forwarding (MCP logging cap.)
# ---------------------------------------------------------------------------

# Python logging level → MCP/syslog-style level string. MCP spec lists
# "debug", "info", "notice", "warning", "error", "critical", "alert",
# "emergency"; Python's stdlib doesn't have notice/alert/emergency, so
# we stick to the six that round-trip cleanly.
_PY_LEVEL_TO_MCP = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
    logging.WARNING: "warning",
    logging.ERROR: "error",
    logging.CRITICAL: "critical",
}
_MCP_LEVEL_TO_PY = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "notice": logging.INFO,  # closest python has
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "alert": logging.CRITICAL,
    "emergency": logging.CRITICAL,
}


# ContextVar holding the current session id (HTTP) or None (stdio /
# no-session). The dispatcher sets it at entry to ``_handle_request``
# so the log forwarder can pick the right per-session sink on emit.
# A ContextVar survives across threads only when the parent context
# is copied (which is what stdlib's ThreadingMixIn does via
# ``contextvars.copy_context().run``), but we only rely on it being
# set *within* the same thread that runs the handler — every log
# record emitted during that handler sees it.
_current_session_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "mcp_current_session_id", default=None
)


class _LogForwarder(logging.Handler):
    """Forward selected log records to an MCP client as
    ``notifications/message`` JSON-RPC notifications.

    Routing model
    -------------
    There is exactly **one** forwarder per server — attached to the
    ``core.mcp_server`` logger tree once at startup, removed at
    shutdown. Per-client routing is done inside ``emit()`` via a
    session-id → sink table. The HTTP transport registers a sink
    when a session is created and unregisters it on drop / idle
    eviction; stdio never registers anything and uses the
    ``default_sink`` (its stdout).

    Why a single shared instance instead of one handler per
    session? Because Python logging is additive: every attached
    handler receives every record. The previous "one
    ``_LogForwarder`` per session" scheme meant Session A's SSE
    stream received every log frame emitted during Session B's
    tool calls — a silent information-disclosure bug. With demux
    here, a record fires once, picks its sink via the current
    session contextvar, and writes only there.

    Thread-safety
    -------------
    Logging writes can fire from any thread (a tool worker, a
    ``tasks/start`` worker, the HTTP ThreadingMixIn). A per-instance
    lock serialises this forwarder's own writes. On stdio the default
    sink is the :class:`_SerializedWriter` that ``serve()`` also uses
    for responses and progress, so all writers share one lock there.
    """

    def __init__(self, default_sink: IO | None = None, min_level: int = logging.WARNING) -> None:
        super().__init__()
        self._default_sink = default_sink
        # session_id → sink. HTTP transport populates this.
        self._routes: dict[str, IO] = {}
        # session_id -> its own logging/setLevel (HTTP).
        self._levels: dict[str, int] = {}
        self._lock = threading.Lock()
        self._min_level = min_level

    # Backwards compat for existing callers / tests that pass a
    # positional sink.
    @property
    def _stdout(self) -> IO | None:
        return self._default_sink

    def set_default_sink(self, sink: IO | None) -> None:
        self._default_sink = sink

    def register_session(self, session_id: str, sink: IO) -> None:
        """Route log records emitted while
        ``_current_session_id.get() == session_id`` to *sink*."""
        with self._lock:
            self._routes[session_id] = sink

    def unregister_session(self, session_id: str) -> None:
        """Stop routing to *session_id*. Records emitted under that
        session after unregister fall through to the default sink
        (usually None on HTTP, so they're silently discarded — the
        session is gone, there's nobody to read them)."""
        with self._lock:
            self._routes.pop(session_id, None)
            self._levels.pop(session_id, None)

    def set_min_level(self, level: int, session_id: str | None = None) -> None:
        """Update the minimum level to forward - of one session (HTTP:
        one client's logging/setLevel is not every client's), or the
        default (stdio, and sessions that never set one)."""
        if session_id is None:
            self._min_level = level
        else:
            with self._lock:
                self._levels[session_id] = level

    def level_for(self, session_id: str | None) -> int:
        if session_id is None:
            return self._min_level
        with self._lock:
            return self._levels.get(session_id, self._min_level)

    @property
    def min_level(self) -> int:
        return self._min_level

    def _pick_sink(self) -> IO | None:
        sid = _current_session_id.get()
        with self._lock:
            if sid is not None:
                route = self._routes.get(sid)
                if route is not None:
                    return route
                # A record emitted during a session whose sink has
                # already been unregistered (rare — the session was
                # just dropped on another thread). Silently discard:
                # there's nobody reading anyway.
                return None
            return self._default_sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < self.level_for(_current_session_id.get()):
                return
            sink = self._pick_sink()
            if sink is None:
                return
            level_str = _PY_LEVEL_TO_MCP.get(record.levelno, "info")
            try:
                message = record.getMessage()
            except Exception:  # noqa: BLE001 — broken %-args shouldn't kill logging
                message = record.msg
            frame = {
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": level_str,
                    "logger": record.name,
                    "data": message,
                },
            }
            try:
                line = _dumps_wire(frame) + "\n"
            except Exception:  # noqa: BLE001
                return
            # Lock per write so two records don't interleave bytes
            # into the same JSON-RPC line. Other writers on the same
            # sink are covered by the sink itself: the HTTP _QueueSink
            # handles each write() atomically under the session lock,
            # and the stdio sink is serve()'s _SerializedWriter.
            with self._lock:
                try:
                    sink.write(line)
                    sink.flush()
                except Exception:  # noqa: BLE001 — EPIPE on client exit
                    pass
        except Exception:  # noqa: BLE001 — the logging system must never raise
            self.handleError(record)


# Loggers attached to the forwarder. Intentionally narrow: we want the
# client to see MCP server activity and audit events, not every
# unrelated chat from deeper ``core.*`` modules (SFTP reconnects,
# metadata index chatter) which would drown the useful signal.
# The audit logger is a child of core.mcp_server: its records reach the
# forwarder through the parent (attached to both, every audit line went
# out twice).
_FORWARDED_LOGGER_NAMES = ("core.mcp_server",)


def _attach_log_forwarder(forwarder: _LogForwarder) -> None:
    for name in _FORWARDED_LOGGER_NAMES:
        logging.getLogger(name).addHandler(forwarder)


def _detach_log_forwarder(forwarder: _LogForwarder) -> None:
    for name in _FORWARDED_LOGGER_NAMES:
        logging.getLogger(name).removeHandler(forwarder)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------


def _ok(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code: int, message: str, data=None):
    # Messages embed backend exception text, which can carry a URL with
    # userinfo, a ``password=`` pair or an auth header.
    err: dict[str, Any] = {"code": code, "message": _wire_text(redact_text(message))}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _is_request_id(value) -> bool:
    """A JSON-RPC id this server accepts: a string or an integer (bool
    is an int subclass in Python, but ``true`` is not an id)."""
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _negotiate_protocol_version(requested) -> str:
    """Pick the version string we'll echo back in the initialize
    response. Rule: if the client asked for one of our supported
    versions, echo it; otherwise answer with our newest. Per MCP
    spec the client is allowed to close the connection when it can't
    live with the server's chosen version — we don't pretend to
    support a wire format we don't understand."""
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return PROTOCOL_VERSIONS_NEWEST


PROTOCOL_VERSIONS_NEWEST = SUPPORTED_PROTOCOL_VERSIONS[0]


def protocol_at_least(version: str | None, minimum: str) -> bool:
    """Whether *version* is a known MCP revision no older than *minimum*.
    An unknown or missing version is not (it is answered as the oldest)."""
    if version not in _KNOWN_PROTOCOL_VERSIONS:
        return False
    return _KNOWN_PROTOCOL_VERSIONS.index(version) >= _KNOWN_PROTOCOL_VERSIONS.index(minimum)


@dataclass
class ProtocolState:
    """The revision one session agreed on in initialize (stdio: the whole
    connection; HTTP: one Mcp-Session-Id). None until then: the session is
    answered as LEGACY_PROTOCOL_VERSION."""

    version: str | None = None

    @property
    def effective(self) -> str:
        return self.version or LEGACY_PROTOCOL_VERSION


def _server_info(version: str) -> dict:
    info: dict[str, Any] = {"name": SERVER_NAME, "version": SERVER_VERSION}
    if protocol_at_least(version, "2025-06-18"):
        info["title"] = SERVER_TITLE
    if protocol_at_least(version, "2025-11-25"):
        info["description"] = SERVER_DESCRIPTION
        info["websiteUrl"] = SERVER_WEBSITE
        info["icons"] = [dict(icon, sizes=list(icon["sizes"])) for icon in SERVER_ICONS]
    return info


def _tool_listing(tool: _Tool, version: str) -> dict:
    """One tools/list entry in the shape of *version*: annotations from
    2025-03-26 on, title and outputSchema from 2025-06-18 on."""
    entry: dict[str, Any] = {
        "name": _mcp_names.public(tool.name),  # the former name stays a hidden alias
        "description": tool.description,
        "inputSchema": tool.schema,
    }
    if protocol_at_least(version, "2025-06-18"):
        if tool.title:
            entry["title"] = tool.title
        if tool.output_schema is not None:
            entry["outputSchema"] = tool.output_schema
    if protocol_at_least(version, "2025-03-26") and tool.annotations:
        entry["annotations"] = dict(tool.annotations)
    return entry


def _is_tool_failure(exc: BaseException) -> bool:
    """A ValueError that is the tool's failure, not the caller's bad
    arguments: an archive refused as unsafe, an image with no preview."""
    names = {cls.__name__ for cls in type(exc).__mro__}
    return bool(names & {"UnsafeArchive", "PreviewError", "ArchiveError"})


def _tool_error_result(message: str, exc_type: str) -> dict:
    """A tools/call result that reports a failure to the model (isError)."""
    return {
        "content": [{"type": "text", "text": _wire_text(redact_text(message))}],
        "isError": True,
        "_meta": {"type": exc_type},
    }


def _handle_request(
    req: dict,
    tools: list[_Tool],
    stdout: IO | None = None,
    cancels: _CancelRegistry | None = None,
    resources: _ResourceCatalog | None = None,
    log_forwarder: _LogForwarder | None = None,
    rate_limiter: _RateLimiter | None = None,
    session_id: str | None = None,
    tasks: _TaskRegistry | None = None,
    protocol: ProtocolState | None = None,
) -> dict | None:
    """Dispatch one request. Returns the response dict, or None if the
    request was a notification (no id) and no response is expected.

    ``stdout`` is the stream progress notifications should be written
    to during a tool call. Tests drive handlers without a stdout; the
    resulting context silently swallows ``ctx.progress()`` calls.

    ``cancels`` is the per-server registry of in-flight cancel events.
    The dispatcher registers the current request's id before calling
    the handler and unregisters in a finally — so an arriving
    ``notifications/cancelled`` can flip the event while the handler
    is still running.

    ``tasks`` is the per-server long-running-task registry. When
    non-None the dispatcher honours the ``tasks/*`` namespace
    (start, status, cancel, list) so clients can fire-and-forget
    a tool call and poll for results. None disables the namespace
    and the server returns -32601 for those methods.

    ``protocol`` is the session's :class:`ProtocolState`: initialize
    records the agreed revision in it, every later request is answered
    in that revision's shape. None (direct callers, tests) answers in
    the revision of the initialize in the same call, else the oldest.
    """
    # Bind the current session id on the contextvar so the
    # log forwarder can demux records to the right per-session sink.
    # Reset in a finally to keep the contextvar clean across request
    # boundaries — otherwise a record emitted later from a different
    # code path would inherit this session id.
    token = _current_session_id.set(session_id)
    try:
        return _dispatch(
            req, tools, stdout, cancels, resources, log_forwarder, rate_limiter, tasks, session_id,
            protocol,
        )
    finally:
        _current_session_id.reset(token)


def _dispatch(
    req: dict,
    tools: list[_Tool],
    stdout: IO | None,
    cancels: _CancelRegistry | None,
    resources: _ResourceCatalog | None,
    log_forwarder: _LogForwarder | None,
    rate_limiter: _RateLimiter | None,
    tasks: _TaskRegistry | None = None,
    session_id: str | None = None,
    protocol: ProtocolState | None = None,
) -> dict | None:
    req_id = req.get("id")
    version = protocol.effective if protocol is not None else LEGACY_PROTOCOL_VERSION
    method = req.get("method")
    params = req.get("params") or {}
    # JSON-RPC 2.0 and MCP: a request has an "id" (a string or an integer,
    # never null in MCP), a notification has none and is never answered -
    # whatever it names: a tools/call without an id runs nothing.
    is_request = "id" in req
    if "method" not in req and ("result" in req or "error" in req):
        return None  # a response from the client: this server asks nothing
    if is_request and not _is_request_id(req_id):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": ERR_INVALID_REQUEST,
                      "message": "id must be a string or integer (MCP: never null)"},
        }
    if req.get("jsonrpc") != "2.0":
        if not is_request:
            return None
        return _err(req_id, ERR_INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"')
    if not isinstance(method, str) or not method:
        if not is_request:
            return None
        return _err(req_id, ERR_INVALID_REQUEST, "Invalid Request: missing method")
    if not is_request:
        if not isinstance(params, dict):
            return None  # a malformed notification gets no reply
        if method == "notifications/cancelled":
            # Deliver the cancel to the in-flight handler for that request
            # id. Unknown / finished ids are tolerated (a race between
            # cancel and completion is normal); a requestId that cannot be
            # an id names no request.
            target = params.get("requestId")
            if cancels is not None and _is_request_id(target):
                cancels.cancel(target)
        # notifications/initialized and every other notification: nothing
        # to do and nothing to answer.
        return None
    if not isinstance(params, dict):
        return _err(req_id, ERR_INVALID_PARAMS, "params must be an object")
    if (protocol is not None and protocol.version is None
            and method not in ("initialize", "ping")):
        # MCP lifecycle: initialize first. Direct callers without a
        # session (protocol None) are not held to it.
        return _err(req_id, ERR_INVALID_REQUEST,
                    f"{method!r} before initialize: send initialize first")
    if method == "initialize":
        # Echo the client's requested protocolVersion if we recognise
        # it; fall back to our newest. Let the client decide whether
        # to hang up on a mismatch.
        if protocol is not None and protocol.version is not None:
            # One initialize per session: a second one switched the
            # revision under the calls already made in it.
            return _err(req_id, ERR_INVALID_REQUEST,
                        f"this session is initialized already (revision {protocol.version}); "
                        "start a new session to initialize again")
        agreed = _negotiate_protocol_version(params.get("protocolVersion"))
        if protocol is not None:
            protocol.version = agreed
        caps: dict[str, Any] = {"tools": {}}
        if resources is not None:
            # listChanged/subscribe both False — V1 doesn't emit
            # notifications/resources/updated. Clients that want live
            # updates can poll resources/list.
            caps["resources"] = {"listChanged": False, "subscribe": False}
        if log_forwarder is not None:
            # Empty object advertises the logging capability; per MCP
            # spec there are no sub-flags here yet.
            caps["logging"] = {}
        return _ok(
            req_id,
            {
                "protocolVersion": agreed,
                "serverInfo": _server_info(agreed),
                "capabilities": caps,
                **({"instructions": SERVER_INSTRUCTIONS}
                   if protocol_at_least(agreed, "2025-03-26") else {}),
            },
        )
    if method == "ping":
        # MCP standard liveness check. Empty params in, empty result
        # out. Exists so clients can probe the connection without the
        # cost of a tools/list round-trip.
        return _ok(req_id, {})
    if method == "tools/list":
        return _ok(req_id, {"tools": [_tool_listing(t, version) for t in tools]})
    if method == "logging/setLevel":
        if log_forwarder is None:
            return _err(
                req_id, ERR_METHOD_NOT_FOUND, "logging capability not enabled on this server"
            )
        level_str = params.get("level")
        if not isinstance(level_str, str):
            return _err(req_id, ERR_INVALID_PARAMS, "logging/setLevel requires a string level")
        py_level = _MCP_LEVEL_TO_PY.get(level_str.lower())
        if py_level is None:
            return _err(req_id, ERR_INVALID_PARAMS, f"unknown log level: {level_str!r}")
        # Per session: one HTTP client's setLevel is not every client's.
        log_forwarder.set_min_level(py_level, session_id=session_id)
        # Empty result object per MCP convention — the client polls
        # its own log sink to see the new stream, no confirmation
        # payload is needed.
        return _ok(req_id, {})
    if method == "resources/list":
        if resources is None:
            return _err(
                req_id, ERR_METHOD_NOT_FOUND, "resources capability not enabled on this server"
            )
        try:
            listing = resources.list_root()
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            return _err(
                req_id,
                ERR_INTERNAL,
                f"resources/list failed: {exc}",
                data={"type": type(exc).__name__},
            )
        return _ok(req_id, {"resources": listing})
    if method == "resources/templates/list":
        if resources is None:
            return _err(
                req_id, ERR_METHOD_NOT_FOUND, "resources capability not enabled on this server"
            )
        return _ok(req_id, {"resourceTemplates": resources.list_templates()})
    if method == "resources/read":
        if resources is None:
            return _err(
                req_id, ERR_METHOD_NOT_FOUND, "resources capability not enabled on this server"
            )
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri:
            return _err(req_id, ERR_INVALID_PARAMS, "resources/read requires a non-empty uri")
        try:
            entry = resources.read(uri)
        except ValueError as exc:
            return _err(
                req_id,
                ERR_INVALID_PARAMS,
                f"resources/read rejected uri: {exc}",
                data={"type": "ValueError"},
            )
        except PermissionError as exc:
            return _err(
                req_id,
                ERR_INVALID_PARAMS,
                f"resources/read refused uri: {exc}",
                data={"type": "PermissionError"},
            )
        except Exception as exc:  # noqa: BLE001
            return _err(
                req_id,
                ERR_INTERNAL,
                f"resources/read failed: {exc}",
                data={"type": type(exc).__name__},
            )
        return _ok(req_id, {"contents": [entry]})
    # axross's background tasks are axross/tasks/*: MCP 2025-11-25 has a
    # tasks/* of its own (taskId, other states), which this server does
    # not offer. Sessions of older revisions keep the old names.
    task_method = None
    if method.startswith("axross/tasks/"):
        task_method = method[len("axross/"):]
    elif method in LEGACY_TASK_METHODS and not protocol_at_least(version, "2025-11-25"):
        task_method = method
    if task_method in LEGACY_TASK_METHODS:
        if tasks is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND, "tasks namespace not enabled on this server")
        scope = session_id or ""
        if task_method == "tasks/start":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(name, str) or not name:
                return _err(req_id, ERR_INVALID_PARAMS, "tasks/start requires a non-empty 'name'")
            if not isinstance(args, dict):
                return _err(req_id, ERR_INVALID_PARAMS, "tasks/start 'arguments' must be an object")
            # A public name, or the former one (a hidden alias): the same tool.
            wanted, args = _mcp_names.resolve(name, args)
            tool = next((t for t in tools if t.name == wanted), None)
            if tool is None:
                return _err(req_id, ERR_INVALID_PARAMS, f"Unknown tool: {name!r}")
            try:
                args = _decode_path_args(args)
            except ValueError as exc:
                return _err(req_id, ERR_INVALID_PARAMS, str(exc))
            # Validate against the tool's schema — same guard as
            # synchronous tools/call. A malformed task that would
            # immediately fail in the worker is rejected upfront.
            refusal = _argument_refusal(args, _call_schema(tool))
            if refusal is not None:
                return _err(
                    req_id,
                    ERR_INVALID_PARAMS,
                    f"tool {name!r} arguments failed schema: {refusal[0]}",
                    data={"type": "ValidationError", "path": refusal[1]},
                )
            busy = _ABANDONED.refusal(wanted, args)
            if busy is not None:
                return _err(req_id, ERR_RATE_LIMITED, busy, data={"type": "AbandonedWorkers"})
            # A task is a tools/call that returns early: the same rate
            # limit applies, and the running ones are capped per session.
            if rate_limiter is not None and not rate_limiter.try_acquire():
                return _err(
                    req_id,
                    ERR_RATE_LIMITED,
                    "tasks/start rate limit exceeded — retry shortly",
                    data={"type": "RateLimitError"},
                )
            try:
                task = tasks.start(scope, name, args)
            except TaskLimitError as exc:
                return _err(
                    req_id,
                    ERR_RATE_LIMITED,
                    f"tasks/start refused: {exc}; wait for one to finish",
                    data={"type": "TaskLimitError"},
                )
            # Spawn worker with a copy_context so contextvar-based
            # session routing in the log forwarder still works.
            ctx_snapshot = contextvars.copy_context()

            def _worker():
                ctx_snapshot.run(_run_task, task, tool, stdout, tasks)

            worker_thread = threading.Thread(
                target=_worker,
                daemon=True,
                name=f"mcp-task-{task.task_id}",
            )
            task.thread = worker_thread
            worker_thread.start()
            return _ok(
                req_id,
                {
                    "task_id": task.task_id,
                    "status": task.status,
                    "tool": task.tool_name,
                    "started_at": task.started_at,
                },
            )
        if task_method == "tasks/status":
            task_id = params.get("task_id")
            if not isinstance(task_id, str) or not task_id:
                return _err(
                    req_id, ERR_INVALID_PARAMS, "tasks/status requires a non-empty 'task_id'"
                )
            task = tasks.get(task_id, scope)
            if task is None:
                return _err(req_id, ERR_INVALID_PARAMS, f"unknown task_id {task_id!r}")
            out = {
                "task_id": task.task_id,
                "status": task.status,
                "tool": task.tool_name,
                "started_at": task.started_at,
                "finished_at": task.finished_at,
                "last_progress": task.last_progress,
            }
            # Include result / error only for terminal states so the
            # happy-path response stays small while running.
            if task.status == "done":
                out["result"] = task.result
            elif task.status == "error":
                out["error"] = task.error
            elif task.status == "cancelled":
                out["error"] = task.error or "cancelled"
            if task.abandoned:
                out["abandoned"] = True
            return _ok(req_id, out)
        if task_method == "tasks/cancel":
            task_id = params.get("task_id")
            if not isinstance(task_id, str) or not task_id:
                return _err(
                    req_id, ERR_INVALID_PARAMS, "tasks/cancel requires a non-empty 'task_id'"
                )
            task = tasks.get(task_id, scope)
            if task is None:
                return _err(req_id, ERR_INVALID_PARAMS, f"unknown task_id {task_id!r}")
            ok = tasks.cancel(task_id, scope)
            # ok: the stop was asked for; status: what the task is now
            # ("running" until its tool stops - at the latest after
            # TASK_STOP_GRACE_SECONDS, then "cancelled", abandoned).
            return _ok(req_id, {"ok": ok, "task_id": task_id, "status": task.status})
        if task_method == "tasks/list":
            # Short summary per task — no result / error, no last_progress.
            # Clients call tasks/status for details on a specific id.
            scope_tasks = tasks.list_scope(scope)
            return _ok(
                req_id,
                {
                    "tasks": [
                        {
                            "task_id": t.task_id,
                            "status": t.status,
                            "tool": t.tool_name,
                            "started_at": t.started_at,
                            "finished_at": t.finished_at,
                        }
                        for t in scope_tasks
                    ],
                },
            )
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        meta = params.get("_meta") or {}
        if not isinstance(meta, dict):
            return _err(req_id, ERR_INVALID_PARAMS, "_meta must be an object")
        # A public name, or the former one (a hidden alias; a merged tool's
        # arguments translated), before any gating: the same tool, schema,
        # audit and permissions either way.
        wanted, args = _mcp_names.resolve(name, args)
        busy = _ABANDONED.refusal(wanted, args)
        if busy is not None:
            return _err(req_id, ERR_RATE_LIMITED, busy, data={"type": "AbandonedWorkers"})
        # Rate-limit BEFORE we touch the cancel registry or allocate a
        # context — the cheap rejection path should stay cheap. A
        # tools/list probe isn't rate-limited because it doesn't
        # traverse the backend; only tools/call does work.
        if rate_limiter is not None and not rate_limiter.try_acquire():
            return _err(
                req_id,
                ERR_RATE_LIMITED,
                "tools/call rate limit exceeded — retry shortly",
                data={"type": "RateLimitError"},
            )
        # Register a cancel event for this request id BEFORE calling
        # the handler, so a notifications/cancelled that arrives on
        # another thread can flip the event while we're mid-handler.
        cancel_event = None
        if cancels is not None and req_id is not None:
            cancel_event = cancels.register(req_id)
        ctx = _ToolContext(
            progress_token=meta.get("progressToken"),
            stdout=stdout,
            cancel_event=cancel_event,
        )
        tool = next((t for t in tools if t.name == wanted), None)
        if tool is None:
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
            # MCP: an unknown tool is invalid params (-32602).
            return _err(req_id, ERR_INVALID_PARAMS, f"Unknown tool: {name!r}")
        try:
            args = _decode_path_args(args)
        except ValueError as exc:
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
            if protocol_at_least(version, "2025-11-25"):
                return _ok(req_id, _tool_error_result(f"tool {name!r}: {exc}", "ValueError"))
            return _err(req_id, ERR_INVALID_PARAMS, f"tool {name!r} rejected args: {exc}")
        # Validate the supplied arguments against the tool's declared
        # inputSchema before we call the handler. jsonschema is an
        # optional dep — when absent we fall back to the handler's
        # own ValueError-raising checks (and refuse unknown arguments).
        refusal = _argument_refusal(args, _call_schema(tool))
        if refusal is not None:
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
            if protocol_at_least(version, "2025-11-25"):
                # 2025-11-25: arguments the tool refuses are a tool error
                # the model sees and can correct, not a protocol error.
                return _ok(req_id, _tool_error_result(
                    f"tool {name!r} arguments failed schema: {refusal[0]}"
                    + (f" (at {'/'.join(map(str, refusal[1]))})" if refusal[1] else ""),
                    "ValidationError"))
            return _err(
                req_id,
                ERR_INVALID_PARAMS,
                f"tool {name!r} arguments failed schema: {refusal[0]}",
                data={"type": "ValidationError", "path": refusal[1]},
            )
        # Wall-clock timeout enforcement. Two parallel mechanisms:
        #
        # 1. A threading.Timer flips ``cancel_event`` at the deadline.
        #    Handlers that poll ``ctx.check_cancel()`` (walk, grep)
        #    then exit cleanly on the next tick.
        #
        # 2. The handler runs on a dedicated worker thread joined
        #    with the timeout. If the handler is wedged inside a
        #    single blocking IO call (backend.read_file on a huge
        #    blob, backend.checksum stream-hashing a slow SFTP
        #    transfer), the cooperative cancel event is useless.
        #    The join-with-timeout still returns control to the
        #    dispatcher so the *client* is unblocked and receives
        #    ERR_TIMEOUT — even though the background thread may
        #    keep running and eventually complete its side effect.
        #    That's the honest trade-off: we cannot safely interrupt
        #    an arbitrary blocking IO call mid-flight.
        timer = None
        timed_out = threading.Event()
        if tool.timeout_seconds and cancel_event is not None:

            def _on_deadline():
                timed_out.set()
                cancel_event.set()

            timer = threading.Timer(tool.timeout_seconds, _on_deadline)
            timer.daemon = True
            timer.start()

        result_box: list = [None]
        error_box: list[BaseException | None] = [None]
        # Propagate our contextvars context so the worker's log
        # records still demux to the right session sink. A raw
        # Thread loses the contextvars binding set by the outer
        # _handle_request — copy_context().run fixes that.
        ctx_snapshot = contextvars.copy_context()

        def _runner():
            try:
                with _cancel_hooks(cancel_event):
                    result_box[0] = tool.handler(args, ctx)
            except BaseException as exc:  # noqa: BLE001 — surface via error_box
                error_box[0] = exc

        worker = threading.Thread(
            target=lambda: ctx_snapshot.run(_runner),
            name=f"mcp-tool-{name}",
            daemon=True,
        )
        try:
            worker.start()
            # Give the worker slightly longer than the timer, so the
            # timer fires first and the cancel_event is set before
            # we decide "it really is hung". 200 ms grace covers the
            # timer's own scheduling latency.
            wait_for = tool.timeout_seconds + 0.2 if tool.timeout_seconds else None
            worker.join(timeout=wait_for)
            if worker.is_alive():
                # Hard stop: the handler ignored (or didn't poll)
                # the cooperative cancel. Return timeout; leave the
                # worker running as a zombie — it holds backend
                # state we can't safely pull out from under it - and
                # count it: new work is refused while too many run on.
                timed_out.set()
                _ABANDONED.add(worker, args)
                return _err(
                    req_id,
                    ERR_TIMEOUT,
                    f"tool {name!r} exceeded its "
                    f"{tool.timeout_seconds}s timeout "
                    f"(worker still running in background)",
                    data={"type": "TimeoutError", "hard_stop": True},
                )
            if error_box[0] is not None:
                exc = error_box[0]
                if isinstance(exc, CancelledError):
                    if timed_out.is_set():
                        return _err(
                            req_id,
                            ERR_TIMEOUT,
                            f"tool {name!r} exceeded its {tool.timeout_seconds}s timeout",
                            data={"type": "TimeoutError"},
                        )
                    return _err(
                        req_id,
                        ERR_INTERNAL,
                        f"tool {name!r} cancelled by client",
                        data={"type": "CancelledError"},
                    )
                if isinstance(exc, (ValueError, TypeError)) and not _is_tool_failure(exc):
                    # TypeError from handler arg-coercion (``int(None)``,
                    # ``int([...])``) maps to -32602 alongside ValueError
                    # so clients can tell their payload was bad, not
                    # the server - from 2025-11-25 on a tool error the
                    # model can read instead.
                    if protocol_at_least(version, "2025-11-25"):
                        return _ok(req_id, _tool_error_result(
                            f"tool {name!r} rejected args: {exc}", type(exc).__name__))
                    return _err(
                        req_id,
                        ERR_INVALID_PARAMS,
                        f"tool {name!r} rejected args: {exc}",
                        data={"type": type(exc).__name__},
                    )
                # The tool ran and failed (a missing file, a refused path, a
                # server that said no): MCP wants that in the RESULT, flagged
                # isError, so the model sees it and can react - a JSON-RPC
                # error is for the protocol (unknown tool, bad arguments).
                # Redacted like _err: backend text can carry credentials.
                return _ok(req_id, _tool_error_result(f"tool {name!r} failed: {exc}",
                                                      type(exc).__name__))
            result = result_box[0]
        finally:
            if timer is not None:
                timer.cancel()
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
        # Image content (preview tool): emit MCP ``image`` block.
        if isinstance(result, _PreviewResult):
            return _ok(
                req_id,
                {
                    "content": [
                        {
                            "type": "image",
                            "data": result.data_b64,
                            "mimeType": result.mime,
                        }
                    ],
                    "isError": False,
                    "_meta": {
                        "width": result.width,
                        "height": result.height,
                    },
                },
            )
        extra = _wire_safe(getattr(result, "extra", {}))  # _ListResult's structured fields
        result = _wire_safe(result)
        try:
            encoded_result = json.dumps(result, default=str)
        except (TypeError, ValueError) as exc:
            return _err(
                req_id,
                ERR_INTERNAL,
                f"tool {name!r} returned non-serialisable result: {exc}",
                data={"type": type(exc).__name__},
            )
        if len(encoded_result) > MAX_TOOL_RESULT_BYTES:
            return _err(
                req_id,
                ERR_INTERNAL,
                f"tool {name!r} result exceeds {MAX_TOOL_RESULT_BYTES}-byte cap",
                data={
                    "type": "ResultTooLarge",
                    "bytes": len(encoded_result),
                    "max_bytes": MAX_TOOL_RESULT_BYTES,
                },
            )
        reply: dict[str, Any] = {
            "content": [{"type": "text", "text": encoded_result}],
            "isError": False,
        }
        if isinstance(result, dict) and protocol_at_least(version, "2025-06-18"):
            # The same object as the text, parsed back: what json.dumps made
            # of a value that is not JSON (default=str) is in both alike.
            reply["structuredContent"] = json.loads(encoded_result)
        elif (isinstance(result, list) and tool.structured_key
                and protocol_at_least(version, "2025-06-18")):
            # The text stays the array; the object wraps it (MCP: the text
            # SHOULD be the serialised object - an array client keeps working).
            reply["structuredContent"] = {tool.structured_key: json.loads(encoded_result),
                                          **extra}
        return _ok(req_id, reply)
    if method is None:
        return _err(req_id, ERR_INVALID_REQUEST, "Invalid Request: missing method")
    if req_id is None:
        # Notification we don't recognise — silent per JSON-RPC.
        return None
    return _err(req_id, ERR_METHOD_NOT_FOUND, f"Method not found: {method!r}")


# ---------------------------------------------------------------------------
# Server entry
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    backend: object
    allow_write: bool = False
    backend_id: str | None = None  # explicit override; default = derived
    # Backend-tool root cap. Defaults to unrestricted for direct
    # library callers; main.py supplies --mcp-root, or backend.home()
    # when none is given, so a casual MCP client cannot read or write
    # outside the exposed tree.
    root: str | None = None
    # Optional multi-backend registry: ``{id: backend_instance}``.
    # When set, the tools/call surface gains a list_backends tool
    # and every other tool accepts an optional ``backend`` arg that
    # routes the call to the named backend. The ``backend`` field on
    # this config is still the default (used when a tool call omits
    # ``backend``). Single-backend deployments leave this None.
    backends: dict | None = None
    # Scripting tools (script_list / api_schema / read / write / run / delete) are
    # gated behind their own opt-in. Read-only would still leak any
    # secrets the user has pasted into local scripts; write+run hands
    # the LLM arbitrary Python as the user (in a child process). Default
    # OFF so a casual LLM connection can't reach the script surface.
    allow_scripts: bool = False
    # Optional capability groups (``--mcp-tools``); see core.mcp_groups.
    # Empty keeps the plain file-tool surface.
    tool_groups: frozenset[str] = frozenset()
    # Remote command execution (the exec group); its own opt-in, like scripts.
    allow_exec: bool = False
    # --mcp-allow-secret-reads: tools may read axross's tokens and keys and
    # the SSH / GnuPG private keys (core.protected_places.read_refusal).
    allow_secret_reads: bool = False
    stdin: IO = field(default_factory=lambda: sys.stdin)
    stdout: IO = field(default_factory=lambda: sys.stdout)
    # Rate limit: token-bucket guarding tools/call only. Default on
    # so a runaway agent can't flood a backend, but tests and tight
    # local deployments can disable.
    rate_limit_enabled: bool = True
    rate_burst: int = DEFAULT_RATE_BURST
    rate_refill_per_sec: float = DEFAULT_RATE_REFILL_PER_SEC


def serve(config: ServerConfig) -> int:
    """Run the stdio JSON-RPC loop. Returns the exit code (0 on EOF,
    non-zero on protocol failure that we couldn't recover from)."""
    tools = _build_tools(
        config.backend,
        allow_write=config.allow_write,
        backend_id=config.backend_id,
        root=config.root,
        backends=config.backends,
        allow_scripts=config.allow_scripts,
        tool_groups=config.tool_groups,
        allow_exec=config.allow_exec,
        allow_secret_reads=config.allow_secret_reads,
    )
    resources = _build_resources(config.backend, root=config.root,
                                 allow_secret_reads=config.allow_secret_reads)
    cancels = _CancelRegistry()
    tasks = _TaskRegistry()
    # One session per stdio connection: the revision initialize agreed on.
    protocol = ProtocolState()
    rate_limiter = (
        _RateLimiter(
            burst=config.rate_burst,
            refill_per_sec=config.rate_refill_per_sec,
        )
        if config.rate_limit_enabled
        else None
    )
    # Forward server logs to the client as notifications/message.
    # Install AFTER the first info log so that "serve starting" lands
    # in stderr (where operators look) rather than being the very
    # first JSON-RPC notification on a channel that the client hasn't
    # yet acked initialize on.
    log.info(
        "MCP serve starting: %d tool(s), write=%s",
        len(tools),
        config.allow_write,
    )
    # One lock for every writer on stdout: this loop, task / timed-out
    # tool worker threads (progress) and the log forwarder (messages).
    out = _SerializedWriter(config.stdout)
    log_forwarder = _LogForwarder(out)
    _attach_log_forwarder(log_forwarder)
    # Lines are read as bytes and decoded one at a time where the
    # stream has a byte layer (sys.stdin): a text stream raises
    # UnicodeDecodeError from readline() for a client byte that is not
    # UTF-8 and drops the rest of the chunk it was decoding, the
    # following requests included.
    binary = getattr(config.stdin, "buffer", None)
    readline = binary.readline if binary is not None else config.stdin.readline
    newline = b"\n" if binary is not None else "\n"

    def _dispatch_aside(req):
        return _handle_request(req, tools, stdout=out, cancels=cancels, resources=resources,
                               log_forwarder=log_forwarder, rate_limiter=rate_limiter,
                               tasks=tasks, protocol=protocol)

    calls = _StdioCalls(_dispatch_aside, cancels, out, config.stdout)
    guard = sigterm_as_interrupt() if config.stdin is sys.stdin else None
    if guard is not None:
        guard.__enter__()
    try:
        while True:
            line = readline(MAX_STDIN_LINE_CHARS + 1)
            if not line:
                log.info("MCP serve: stdin closed, exiting")
                calls.stop()
                _stop_tasks(tasks)
                return 0
            if len(line) > MAX_STDIN_LINE_CHARS and not line.endswith(newline):
                # Drain the rest of this overlong frame so the next
                # iteration starts at a fresh JSON-RPC line instead of
                # parsing arbitrary chunks of the rejected payload.
                while True:
                    chunk = readline(MAX_STDIN_LINE_CHARS + 1)
                    if not chunk or chunk.endswith(newline):
                        break
                response = _err(
                    None,
                    ERR_INVALID_REQUEST,
                    f"Request line exceeds {MAX_STDIN_LINE_CHARS} chars",
                )
                if not _write_frame(out, response, config.stdout):
                    calls.stop()
                    _stop_tasks(tasks)
                    return 0
                continue
            line = line.strip()
            if not line:
                continue
            try:
                # ValueError covers JSONDecodeError, a line that is not
                # UTF-8 and an integer above the digit limit;
                # RecursionError is nesting deeper than the C stack.
                req = json.loads(line)
            except (ValueError, RecursionError) as exc:
                response = _err(None, ERR_PARSE, f"Parse error: {exc}")
            else:
                if isinstance(req, list):
                    # No revision this server speaks has batches (2025-06-18
                    # removed them; 2025-03-26, which had them, is not offered).
                    response = _err(None, ERR_INVALID_REQUEST,
                                    "Invalid Request: JSON-RPC batches are not supported")
                elif not isinstance(req, dict):
                    response = _err(None, ERR_INVALID_REQUEST, "Invalid Request: not an object")
                elif _runs_aside(req, protocol):
                    # A tool call runs on a worker: this loop keeps reading,
                    # answers ping, delivers notifications/cancelled to it,
                    # and notices the client going away.
                    response = calls.start(req)
                    if response is None:
                        continue
                else:
                    response = _handle_request(
                        req,
                        tools,
                        stdout=out,
                        cancels=cancels,
                        resources=resources,
                        log_forwarder=log_forwarder,
                        rate_limiter=rate_limiter,
                        tasks=tasks,
                        protocol=protocol,
                    )
            if response is not None and not _write_frame(out, response, config.stdout):
                calls.stop()
                _stop_tasks(tasks)
                return 0
    except KeyboardInterrupt:
        # Ctrl+C, or SIGTERM (sigterm_as_interrupt): the tasks are stopped
        # and clean up (a pack's staging folder) before the exit.
        log.info("MCP serve: interrupted, exiting")
        calls.stop()
        _stop_tasks(tasks)
        return 0
    finally:
        if guard is not None:
            guard.__exit__(None, None, None)
        _detach_log_forwarder(log_forwarder)


#: How long the stdio server waits, when its client went away, for running
#: tasks to stop and clean up (a pack's temporary archive, a partial copy).
SHUTDOWN_TASK_WAIT_SECONDS = 5.0
#: Methods the stdio loop runs on a worker thread instead of in the loop.
STDIO_ASIDE_METHODS = frozenset({"tools/call", "resources/read"})
#: Calls of one stdio client that may run at once.
MAX_STDIO_CALLS = 16


def _runs_aside(req: dict, protocol: ProtocolState) -> bool:
    return (req.get("method") in STDIO_ASIDE_METHODS and "id" in req
            and _is_request_id(req.get("id")) and req.get("jsonrpc") == "2.0"
            and protocol.version is not None)


class _StdioCalls:
    """The stdio server's tool calls in flight, each on a worker thread.

    The loop stays free: ping is answered while a 70 s pack runs, a
    notifications/cancelled reaches the call (its response is then not
    sent, as MCP has it), and the client closing stdin stops everything
    instead of waiting for the slowest call."""

    def __init__(self, dispatch, cancels: _CancelRegistry, out, stream) -> None:
        self._dispatch = dispatch
        self._cancels = cancels
        self._out = out
        self._stream = stream
        self._lock = threading.Lock()
        self._running: dict[Any, threading.Thread] = {}
        self._closed = False

    def start(self, req: dict) -> dict | None:
        """Start *req* on a worker; an error response when it cannot run."""
        req_id = req["id"]
        with self._lock:
            if req_id in self._running:
                return _err(req_id, ERR_INVALID_REQUEST,
                            f"request id {req_id!r} is already in use by a running call")
            if len(self._running) >= MAX_STDIO_CALLS:
                return _err(req_id, ERR_RATE_LIMITED,
                            f"{MAX_STDIO_CALLS} calls are already running; retry when one "
                            "has finished", data={"type": "RateLimitError"})
            # Registered before the worker runs: a cancel that comes
            # right after the call is not lost.
            self._cancels.register(req_id)
            ctx = contextvars.copy_context()
            worker = threading.Thread(target=lambda: ctx.run(self._run, req), daemon=True,
                                      name=f"mcp-stdio-{req.get('method')}-{req_id}")
            self._running[req_id] = worker
        worker.start()
        return None

    def _run(self, req: dict) -> None:
        req_id = req["id"]
        try:
            response = self._dispatch(req)
        except Exception:  # noqa: BLE001 - a crashed call still answers
            log.exception("stdio call %r failed", req_id)
            response = _err(req_id, ERR_INTERNAL, "internal error")
        finally:
            with self._lock:
                self._running.pop(req_id, None)
            self._cancels.unregister(req_id)
        if self._cancels.pop_cancelled(req_id):
            log.info("stdio call %r was cancelled: no response", req_id)
            return
        if response is not None and not self._closed:
            _write_frame(self._out, response, self._stream)

    def stop(self) -> None:
        """stdin ended: the calls in flight get SHUTDOWN_TASK_WAIT_SECONDS
        to finish and answer (a client that pipes its requests and then
        closes stdin still reads them), then what still runs is cancelled
        and the server exits without waiting for it."""
        with self._lock:
            workers = list(self._running.values())
        deadline = time.monotonic() + SHUTDOWN_TASK_WAIT_SECONDS
        for worker in workers:
            worker.join(max(0.0, deadline - time.monotonic()))
        self._closed = True
        self._cancels.cancel_all()
        for worker in workers:
            worker.join(0.5)


class sigterm_as_interrupt:
    """While serving in the main thread: SIGTERM raises KeyboardInterrupt,
    so the server's clean-up runs (stop the tasks, a pack's staging
    folder, the HTTP token file) instead of the process just ending. The
    previous handler comes back afterwards."""

    def __enter__(self):
        import signal

        self._old = None
        if threading.current_thread() is threading.main_thread():
            def _interrupt(_signum, _frame):
                raise KeyboardInterrupt

            try:
                self._old = signal.signal(signal.SIGTERM, _interrupt)
            except (ValueError, OSError):
                self._old = None
        return self

    def __exit__(self, *exc):
        import signal

        if self._old is not None:
            try:
                signal.signal(signal.SIGTERM, self._old)
            except (ValueError, OSError):
                pass
        return False


def _stop_tasks(tasks: _TaskRegistry) -> None:
    """Cancel every task and give the workers a moment to clean up."""
    workers = [t.thread for t in tasks.list_scope("") if t.status == "running"]
    tasks.drop_scope("")
    deadline = time.monotonic() + SHUTDOWN_TASK_WAIT_SECONDS
    for worker in workers:
        if worker is not None:
            worker.join(max(0.0, deadline - time.monotonic()))


def _write_frame(out, message, stream) -> bool:
    """Write one frame; False when the client is gone (a broken pipe). The
    stream is then pointed at /dev/null so the interpreter's exit flush
    does not fail too (that printed a traceback and exited with 120)."""
    try:
        out.write(_dumps_wire(message) + "\n")
        out.flush()
        return True
    except (BrokenPipeError, ConnectionResetError, ValueError):
        log.info("MCP serve: the client closed its end, exiting")
        try:
            import os as _os

            fd = stream.fileno()
            devnull = _os.open(_os.devnull, _os.O_WRONLY)
            _os.dup2(devnull, fd)
            _os.close(devnull)
        except (AttributeError, OSError, ValueError):
            pass
        return False


def default_backend():
    """Return the default backend used when no explicit one is given:
    LocalFS rooted at the user's home dir."""
    from core.local_fs import LocalFS

    return LocalFS()


__all__ = [
    "CancelledError",
    "DEFAULT_RATE_BURST",
    "DEFAULT_RATE_REFILL_PER_SEC",
    "ERR_INTERNAL",
    "ERR_INVALID_PARAMS",
    "ERR_INVALID_REQUEST",
    "ERR_METHOD_NOT_FOUND",
    "ERR_PARSE",
    "ERR_RATE_LIMITED",
    "ERR_TIMEOUT",
    "MAX_READ_BYTES",
    "MAX_RESOURCES_LISTED",
    "LEGACY_PROTOCOL_VERSION",
    "PROTOCOL_VERSION",
    "ProtocolState",
    "RESOURCE_SCHEME",
    "SERVER_NAME",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ServerConfig",
    "protocol_at_least",
    "default_backend",
    "serve",
]
