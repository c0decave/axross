"""Optional MCP capability groups (``--mcp-tools GROUP[,GROUP...]``).

The MCP server (:mod:`core.mcp_server`) always serves the file tools. Every
other axross feature an LLM may drive is a *capability group* the operator
switches on at start:

``--mcp-tools metadata,packer`` or ``AXROSS_MCP_TOOLS=metadata,packer``;
``all`` means every group. No flag keeps the plain file tools exactly as
before.

Safety layering, on top of every guard of the base server:

* A group's mutating tools are registered only with ``--mcp-write`` (which
  itself needs ``--mcp-root``); its read-only tools work without it.
* Local paths go through the same root confinement as the file tools, and
  everything written (archives, extracted folders, decrypted files, metadata
  exports, cleaned copies) lands under the root under a fresh name - nothing
  is overwritten.
* Mutating tools leave attempt / ok / refused lines on the
  ``core.mcp_server.audit`` logger (paths, names, sizes - never payloads,
  passphrases or passwords).
* Long operations report MCP progress, poll cancellation and run under
  ``tasks/start``.

The builders below get a :class:`GroupEnv` from
:func:`core.mcp_server._build_tools` - the same backend resolution, root
confinement and audit helpers the file tools use - and return
:class:`core.mcp_server._Tool` records.
"""

from __future__ import annotations

import logging
import os
import posixpath
import threading
import weakref
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger(__name__)

#: Every capability group, in documentation order. ``all`` is not a group
#: but the name for all of them.
GROUPS: tuple[str, ...] = (
    "metadata",
    "duplicates",
    "packer",
    "archive",
    "crypto",
    "index",
    "filetype",
    "transfer",
    "remote",
    "exec",
    "agent",
    "extensions",
)
ALL = "all"
#: Environment variable equivalent of ``--mcp-tools``; merged with the flag.
ENV_VAR = "AXROSS_MCP_TOOLS"

#: One line per group for ``--help``, the manifest and the docs.
GROUP_DESCRIPTIONS: dict[str, str] = {
    "metadata": "Show and export file metadata (EXIF/XMP/IPTC, Office, PDF, media tags); "
    "remove it (mutating, writes a cleaned copy).",
    "duplicates": "Duplicate Finder: scan a folder into the duplicate index, list scans and "
    "duplicate groups; dedupe to the axross trash (mutating, dry run by default).",
    "packer": "List archive formats; pack files and folders into zip / tar.* / 7z / single-file "
    "compression, 7z optionally AES-256 encrypted (mutating).",
    "archive": "List an archive's members; extract it into a fresh folder (mutating).",
    "crypto": "Encrypt a file into the axross .axenc format and decrypt it again (mutating).",
    "index": "Build or refresh the offline metadata index that the search tool reads.",
    "filetype": "Identify files by content (magic bytes), flag extension mismatches.",
    "transfer": "Copy or move files and folders between backends, optionally resumable "
    "(mutating).",
    "remote": "List saved connection profiles (no secrets), open one as an extra backend "
    "that every tool can address with its backend argument, close it again.",
    "agent": "Hand a task to the user's own LLM (the active profile of the axross GUI): it "
    "works with the read-only tools inside the MCP root and answers; it can change nothing.",
    "exec": "Run commands and scripts on remote hosts over SSH, SCP, Telnet, rsh, ADB, "
    "WinRM (PowerShell) and Cisco (show commands only); only with --mcp-allow-exec "
    "(mutating), refused in the paranoid security mode and on production profiles.",
    "extensions": "List installed extensions and whether they are enabled (read-only: "
    "extensions are GUI plugins).",
}


class GroupError(ValueError):
    """An ``--mcp-tools`` / ``AXROSS_MCP_TOOLS`` value names no known group."""


def _valid_names() -> str:
    return ", ".join((ALL, *GROUPS))


def _split(values: Iterable[str]) -> list[str]:
    names: list[str] = []
    for value in values:
        for part in str(value).split(","):
            name = part.strip().lower()
            if name:
                names.append(name)
    return names


def _resolve(names: list[str]) -> frozenset[str]:
    unknown = [n for n in names if n != ALL and n not in GROUPS]
    if unknown:
        listed = ", ".join(repr(n) for n in unknown)
        raise GroupError(f"unknown MCP tool group {listed}; valid groups: {_valid_names()}")
    if ALL in names:
        return frozenset(GROUPS)
    return frozenset(names)


def parse_groups(values: Iterable[str] | None) -> frozenset[str]:
    """Groups named by the ``--mcp-tools`` values (each may be comma-separated).

    ``None`` or no values means no group. A flag that was given but names
    nothing (``--mcp-tools ","``) is an error, like an unknown group.
    """
    values = list(values or [])
    if not values:
        return frozenset()
    names = _split(values)
    if not names:
        raise GroupError(f"--mcp-tools needs at least one group; valid groups: {_valid_names()}")
    return _resolve(names)


def groups_from(values: Iterable[str] | None, *, env_value: str | None) -> frozenset[str]:
    """The flag's groups merged with ``AXROSS_MCP_TOOLS``. An unset or blank
    environment value adds nothing."""
    groups = parse_groups(values)
    if env_value and env_value.strip():
        groups = groups | _resolve(_split([env_value]))
    return groups


def check_groups(groups: Iterable[str]) -> frozenset[str]:
    """Validate an already-split collection of group names (library callers)."""
    return _resolve([str(g).strip().lower() for g in groups])


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


@dataclass
class GroupEnv:
    """What a group builder gets from :func:`core.mcp_server._build_tools`."""

    default_backend: Any
    #: ``resolve_backend(args)`` - the backend a call addresses.
    resolve_backend: Callable[[dict], Any]
    #: ``scope_path(path, backend)`` - read confinement (the root, locally).
    scope_path: Callable[[str, Any], str]
    #: ``write_path(path, backend)`` - confinement of what a tool writes.
    write_path: Callable[[str, Any], str]
    #: ``entry_path(path, backend)`` - confinement of an entry that is itself
    #: removed or moved (a symlink there is acted on, not its target).
    entry_path: Callable[[str, Any], str]
    #: ``refuse_root(path, backend, operation)`` - no mutation of the root itself.
    refuse_root: Callable[[str, Any, str], None]
    #: The metadata-index id the search tool reads for a backend.
    index_backend_id: Callable[[Any], str]
    #: ``audit(tool, outcome, **fields)`` on core.mcp_server.audit.
    audit: Callable[..., None]
    root: str | None
    allow_write: bool
    #: ``backend_by_id(id)`` - strict lookup ("local" is the default backend).
    backend_by_id: Callable[[Any], Any] | None = None
    #: The ``remote`` group's registry of opened profiles (None without it).
    remote: RemoteRegistry | None = None
    #: ``--mcp-allow-exec`` (and the security mode allows it).
    allow_exec: bool = False
    #: ``all_backends()`` - every addressable backend by id.
    all_backends: Callable[[], dict] | None = None
    #: The groups this server offers (``--mcp-tools``).
    groups: frozenset = frozenset()


def _tool(
    name,
    description,
    properties,
    handler,
    *,
    group,
    required=(),
    write=False,
    timeout_class="quick",
    accepts_backend=True,
):
    """A _Tool with a strict object schema (unknown arguments are refused)."""
    from core.mcp_server import _Tool

    schema: dict = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return _Tool(
        name=name,
        description=description,
        schema=schema,
        handler=handler,
        write=write,
        timeout_class=timeout_class,
        group=group,
        accepts_backend=accepts_backend,
    )


def _path_prop(text: str) -> dict:
    return {"type": "string", "minLength": 1, "description": text}


def _int_prop(text: str, *, minimum: int, maximum: int, default: int) -> dict:
    return {
        "type": "integer",
        "minimum": minimum,
        "maximum": maximum,
        "default": default,
        "description": text,
    }


def _bool_prop(text: str, *, default: bool) -> dict:
    return {"type": "boolean", "default": default, "description": text}


def _str_arg(args: dict, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    if "\x00" in value:
        raise ValueError(f"{key} contains a NUL byte")
    return value


def _int_arg(args: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    value = args.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}, got {value}")
    return value


def _bool_arg(args: dict, key: str, default: bool) -> bool:
    value = args.get(key, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def _cancel_event(ctx) -> threading.Event:
    """The call's cancel event (a fresh one for direct handler calls)."""
    return ctx.cancel_event if ctx.cancel_event is not None else threading.Event()


def _is_dir(backend, path: str) -> bool:
    try:
        return bool(backend.is_dir(path))
    except OSError:
        return False


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _confined(env: GroupEnv, backend, path: str) -> str | None:
    """*path* after read confinement, or None when it leaves the root (a
    walk then skips it instead of failing the whole call)."""
    try:
        return env.scope_path(path, backend)
    except (PermissionError, ValueError):
        return None


def _split_name(name: str) -> tuple[str, str]:
    """``report.json`` -> (``report``, ``.json``); a dot file has no suffix."""
    stem, ext = posixpath.splitext(name)
    if not stem:
        return name, ""
    return stem, ext


def _free_name(stem: str, ext: str, n: int) -> str:
    """The packer's naming: ``stem.ext``, then ``stem (2).ext``, …"""
    return f"{stem}{ext}" if n == 1 else f"{stem} ({n}){ext}"


def _place_new(env: GroupEnv, backend, path: str, data: bytes, *, ext: str | None = None) -> str:
    """Write *data* to *path*, or to ``stem (2).ext``, ``stem (3).ext`` …
    when the name is taken - never over an existing file. Every candidate
    is confined like *path*. *ext* overrides the suffix split (``.axenc``
    for ``a.txt.axenc``). A local file is created with O_EXCL and mode
    0600; a remote one after an existence check. Returns the path used."""
    folder = backend.parent(path)
    name = posixpath.basename(path.replace("\\", "/").rstrip("/"))
    if ext is not None and name.endswith(ext) and len(name) > len(ext):
        stem = name[: -len(ext)]
    else:
        stem, ext = _split_name(name)
    for n in range(1, 10_000):
        candidate = env.write_path(backend.join(folder, _free_name(stem, ext, n)), backend)
        if _is_local(backend):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return candidate
        if backend.exists(candidate):
            continue
        from core.atomic_io import atomic_write

        atomic_write(backend, candidate, data)
        return candidate
    raise OSError(f"no free name for {path}")


def _audited(
    env: GroupEnv,
    tool: str,
    fields: dict,
    work: Callable[[], Any],
    ok_fields: Callable[[Any], dict],
):
    """Run *work* between an attempt line and an ok / refused audit line."""
    env.audit(tool, "attempt", **fields)
    try:
        result = work()
    except BaseException as exc:
        env.audit(tool, "refused", **fields, error=type(exc).__name__)
        raise
    env.audit(tool, "ok", **ok_fields(result))
    return result


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------

_MAX_METADATA_FILES = 2000


def _metadata_targets(
    env: GroupEnv, backend, folder: str, recursive: bool, max_files: int, cancel
) -> tuple[list[str], bool]:
    """Supported files under *folder* (confined), and whether the cap cut."""
    from core import metadata_tools as MT

    scan = MT.collect_targets(
        backend, folder, recursive=recursive, max_items=max_files + 1, cancel=cancel
    )
    paths = [p for p in (_confined(env, backend, i.path) for i in scan.items) if p]
    truncated = bool(scan.truncated) or len(paths) > max_files
    return paths[:max_files], truncated


def _build_metadata(env: GroupEnv) -> list:
    from core import metadata_tools as MT

    def _scope_args(args):
        backend = env.resolve_backend(args)
        path = env.scope_path(_str_arg(args, "path"), backend)
        recursive = _bool_arg(args, "recursive", False)
        max_files = _int_arg(args, "max_files", 200, 1, _MAX_METADATA_FILES)
        return backend, path, recursive, max_files

    def _reports(backend, path, recursive, max_files, ctx):
        if not _is_dir(backend, path):
            return [MT.read_metadata(backend, path, cancel=ctx.cancel_event)], False, False
        cancel = _cancel_event(ctx)
        targets, truncated = _metadata_targets(env, backend, path, recursive, max_files, cancel)
        reports = []
        for n, target in enumerate(targets, start=1):
            ctx.check_cancel()
            reports.append(MT.read_metadata(backend, target, cancel=cancel))
            ctx.progress(float(n), float(len(targets)), f"metadata {n}/{len(targets)}")
        ctx.check_cancel()
        return reports, truncated, True

    def _read(args, ctx):
        backend, path, recursive, max_files = _scope_args(args)
        reports, truncated, is_dir = _reports(backend, path, recursive, max_files, ctx)
        return {
            "path": path,
            "is_dir": is_dir,
            "files": [r.to_dict() for r in reports],
            "truncated": truncated,
        }

    def _export_text(args, ctx):
        backend, path, recursive, max_files = _scope_args(args)
        fmt = args.get("format", "json") or "json"
        if fmt not in MT.EXPORT_FORMATS:
            raise ValueError(f"format must be one of {list(MT.EXPORT_FORMATS)}")
        reports, truncated, _ = _reports(backend, path, recursive, max_files, ctx)
        return path, fmt, MT.export_reports(reports, fmt), len(reports), truncated

    def _export(args, ctx):
        path, fmt, text, count, truncated = _export_text(args, ctx)
        return {"path": path, "format": fmt, "files": count, "truncated": truncated, "text": text}

    def _export_file(args, ctx):
        out = _str_arg(args, "out")
        source = args.get("path")

        def work():
            backend = env.resolve_backend(args)
            target = env.write_path(out, backend)
            _path, fmt, text, count, truncated = _export_text(args, ctx)
            data = text.encode("utf-8")
            written = _place_new(env, backend, target, data)
            return {
                "path": written,
                "format": fmt,
                "files": count,
                "truncated": truncated,
                "size": len(data),
            }

        return _audited(
            env,
            "metadata_export_file",
            {"path": source, "out": out},
            work,
            lambda r: {"path": source, "out": r["path"], "size": r["size"]},
        )

    def _remove(args, ctx):
        source = args.get("path")

        def work():
            backend, path, recursive, max_files = _scope_args(args)
            env.write_path(path, backend)
            cancel = _cancel_event(ctx)
            if _is_dir(backend, path):
                targets, truncated = _metadata_targets(
                    env, backend, path, recursive, max_files, cancel
                )
            else:
                if not backend.exists(path):
                    raise FileNotFoundError(f"no such file: {path}")
                targets, truncated = [path], False
            batch = MT.remove_many(
                backend,
                targets,
                mode=MT.MODE_COPY,
                cancel=cancel,
                progress=lambda done, total, p: ctx.progress(float(done), float(total), p),
                source=path,
            )
            ctx.check_cancel()
            return {
                "path": path,
                "mode": MT.MODE_COPY,
                "results": [r.to_dict() for r in batch.results],
                "truncated": truncated,
            }

        def ok(result):
            cleaned = sum(1 for r in result["results"] if r["status"] == MT.CLEANED)
            return {"path": source, "files": len(result["results"]), "cleaned": cleaned}

        return _audited(env, "metadata_remove", {"path": source}, work, ok)

    common = {
        "path": _path_prop("A file, or a folder whose supported files are used."),
        "recursive": _bool_prop("For a folder: descend into subfolders.", default=False),
        "max_files": _int_prop(
            "For a folder: at most this many files (truncated=true when cut).",
            minimum=1,
            maximum=_MAX_METADATA_FILES,
            default=200,
        ),
    }
    fmt = {
        "type": "string",
        "enum": list(MT.EXPORT_FORMATS),
        "default": "json",
        "description": 'json: {"files": [...]}; csv: one row per field, formula-safe.',
    }
    kinds = (
        "images (JPEG/PNG/WebP/GIF/TIFF), Office (docx/xlsx/pptx/odt/ods/odp), PDF, "
        "audio/video (ffprobe)"
    )
    return [
        _tool(
            "metadata_read",
            "Read the metadata of a file or of every supported file in a folder: "
            f"{kinds}. Returns {{path, is_dir, truncated, files: [{{path, name, kind, size, "
            "error, truncated, removable_count, fields: [{group, name, value, removable}]}]}}. "
            "An unsupported or unreadable file is a report with error set, not a failure. "
            "Values are length-bounded. Local paths are confined to the MCP root.",
            common,
            _read,
            group="metadata",
            required=("path",),
            timeout_class="stream",
        ),
        _tool(
            "metadata_export",
            "The metadata_read data of a file or folder as one text in JSON or CSV. Returns "
            "{path, format, files, truncated, text}.",
            {**common, "format": fmt},
            _export,
            group="metadata",
            required=("path",),
            timeout_class="stream",
        ),
        _tool(
            "metadata_export_file",
            "Write the metadata_export text of path into the new file out (under the MCP "
            "root, mode 0600). An existing file is never overwritten: 'meta.json' becomes "
            "'meta (2).json'. Returns {path (the file written), format, files, truncated, "
            "size}.",
            {**common, "format": fmt, "out": _path_prop("File to create.")},
            _export_file,
            group="metadata",
            required=("path", "out"),
            write=True,
            timeout_class="stream",
        ),
        _tool(
            "metadata_remove",
            "Remove the metadata of a file, or of every supported file in a folder, by "
            "writing a cleaned copy next to each ('photo.jpg' -> 'photo.clean.jpg', then "
            "'photo.clean (1).jpg'); the original is never modified and nothing is "
            "overwritten. Images keep orientation and colour profile, pixels are not "
            "re-encoded. PDF removal needs pypdf, audio/video needs ffmpeg (both blocked in "
            "the paranoid security mode). Returns {path, mode: 'copy', truncated, results: "
            "[{path, status (cleaned|unchanged|unsupported|error), output, removed, error, "
            "note, sha256}]}.",
            common,
            _remove,
            group="metadata",
            required=("path",),
            write=True,
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# filetype
# ---------------------------------------------------------------------------

_MAX_TYPE_BYTES = 1024 * 1024
_MAX_TYPE_SCAN_FILES = 5000


def _type_info(info) -> dict:
    out = asdict(info)
    out["mismatch"] = info.mismatch
    return out


def _walk_files(env: GroupEnv, backend, start: str, max_depth: int, ctx):
    """Breadth-first ``(path, item)`` of the files under *start*: symlinks
    and entries that leave the root are skipped, cancel is polled per
    folder."""
    from core.path_policy import safe_join

    queue: list[tuple[str, int]] = [(start, 0)]
    while queue:
        ctx.check_cancel()
        folder, depth = queue.pop(0)
        try:
            children = sorted(backend.list_dir(folder), key=lambda c: getattr(c, "name", ""))
        except OSError:
            continue
        for child in children:
            name = getattr(child, "name", "")
            if not name or name in (".", "..") or getattr(child, "is_link", False):
                continue
            try:
                full = safe_join(backend, folder, name)
            except ValueError:
                continue
            if _confined(env, backend, full) is None:
                continue
            if getattr(child, "is_dir", False):
                if depth < max_depth:
                    queue.append((full, depth + 1))
                continue
            yield full, child


def _build_filetype(env: GroupEnv) -> list:
    from core import file_type as FT

    def _limits(args):
        return (
            _int_arg(args, "max_bytes", FT.DEFAULT_MAX_BYTES, 1, _MAX_TYPE_BYTES),
            _bool_arg(args, "use_file_command", True),
        )

    def _one(args, ctx):
        backend = env.resolve_backend(args)
        path = env.scope_path(_str_arg(args, "path"), backend)
        max_bytes, use_file = _limits(args)
        info = FT.identify(
            backend,
            path,
            max_bytes=max_bytes,
            cancel=ctx.cancel_event,
            use_file_command=use_file,
        )
        return _type_info(info)

    def _scan(args, ctx):
        backend = env.resolve_backend(args)
        start = env.scope_path(_str_arg(args, "path"), backend)
        max_bytes, use_file = _limits(args)
        max_depth = _int_arg(args, "max_depth", 2, 0, 50)
        max_files = _int_arg(args, "max_files", 500, 1, _MAX_TYPE_SCAN_FILES)
        only_mismatch = _bool_arg(args, "mismatches_only", False)
        entries: list[dict] = []
        scanned = 0
        truncated = False
        for full, _item in _walk_files(env, backend, start, max_depth, ctx):
            if scanned >= max_files:
                truncated = True
                break
            ctx.check_cancel()
            info = FT.identify(
                backend,
                full,
                max_bytes=max_bytes,
                cancel=ctx.cancel_event,
                use_file_command=use_file,
            )
            scanned += 1
            ctx.progress(float(scanned), float(max_files), f"identified {full}")
            if only_mismatch and not info.mismatch:
                continue
            entries.append(_type_info(info))
        return {
            "path": start,
            "entries": entries,
            "files_scanned": scanned,
            "truncated": truncated,
        }

    limits = {
        "max_bytes": _int_prop(
            "Read at most this many bytes per file.",
            minimum=1,
            maximum=_MAX_TYPE_BYTES,
            default=FT.DEFAULT_MAX_BYTES,
        ),
        "use_file_command": _bool_prop(
            "Also ask file(1) for its description (local files only).", default=True
        ),
    }
    record = (
        "{path, name, kind (file|directory|special|error|timeout|cancelled), description, "
        "mime (from the content), extension, extension_mime (what the name claims), verdict "
        "(match|mismatch|unknown), mismatch (bool), size, encoding, line_endings, engine, "
        "file_command, bytes_read, error}"
    )
    return [
        _tool(
            "file_type",
            "Identify one file by its content (magic bytes), not its name, and say whether "
            f"the extension matches. Returns {record}. Never fails for an unreadable file: "
            "kind is then error or timeout with error set.",
            {"path": _path_prop("File to identify."), **limits},
            _one,
            group="filetype",
            required=("path",),
            timeout_class="quick",
        ),
        _tool(
            "file_type_scan",
            "Identify every file under a folder (breadth-first, symlinks skipped). Returns "
            f"{{path, files_scanned, truncated, entries: [{record}]}}; with mismatches_only "
            "only files whose content contradicts their extension are listed. One progress "
            "notification per file; honours cancellation.",
            {
                "path": _path_prop("Folder to scan."),
                "max_depth": _int_prop(
                    "Subfolder levels to descend (0: the folder itself only).",
                    minimum=0,
                    maximum=50,
                    default=2,
                ),
                "max_files": _int_prop(
                    "Stop after this many files (truncated=true).",
                    minimum=1,
                    maximum=_MAX_TYPE_SCAN_FILES,
                    default=500,
                ),
                "mismatches_only": _bool_prop(
                    "List only files whose content does not match the extension.",
                    default=False,
                ),
                **limits,
            },
            _scan,
            group="filetype",
            required=("path",),
            timeout_class="stream",
        ),
    ]


# ---------------------------------------------------------------------------
# duplicates
# ---------------------------------------------------------------------------

_HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
_MAX_GROUPS = 1000
_MAX_LISTED = 1000


def _cancelled():
    from core.mcp_server import CancelledError

    return CancelledError("request cancelled by client")


def _folder_arg(env: GroupEnv, backend, args: dict) -> str:
    """The ``path`` argument as a confined folder; the MCP root when it is
    omitted on the local backend."""
    raw = args.get("path")
    if raw is None:
        if backend is not env.default_backend or not env.root:
            raise ValueError("path is required for this backend")
        raw = env.root
    folder = env.scope_path(_str_arg({"path": raw}, "path"), backend)
    if not _is_dir(backend, folder):
        raise ValueError(f"path must be a folder: {folder}")
    return folder


def _iso(when) -> str | None:
    return when.isoformat() if when is not None else None


def _build_duplicates(env: GroupEnv) -> list:
    from core import cas
    from core.redaction import redact_text

    def _algorithm(args, default):
        algo = args.get("algorithm", default)
        if algo is None:
            return None
        if algo not in _HASH_ALGORITHMS:
            raise ValueError(f"algorithm must be one of {list(_HASH_ALGORITHMS)}")
        return algo

    def _scan(args, ctx):
        backend = env.resolve_backend(args)
        folder = _folder_arg(env, backend, args)
        algo = _algorithm(args, "sha256")
        rehash = _bool_arg(args, "rehash", False)
        bid = cas.backend_id_for(backend)
        count = cas.rebuild(
            backend,
            folder,
            backend_id=bid,
            algorithm=algo,
            rehash=rehash,
            cancel=lambda: ctx.is_cancelled,
            progress=lambda scanned, indexed, p: ctx.progress(
                float(scanned), None, f"{indexed} indexed - {p}"
            ),
        )
        if ctx.is_cancelled:
            raise _cancelled()
        record = next(
            (
                s
                for s in cas.list_scans(None)
                if s.backend_id == bid and s.root == folder and s.algorithm == algo
            ),
            None,
        )
        return {
            "scan_id": record.scan_id if record else None,
            "root": folder,
            "backend_id": bid,
            "algorithm": algo,
            "files_indexed": count,
            "status": record.status if record else cas.SCAN_COMPLETE,
        }

    def _scans(args, ctx):
        backend = env.resolve_backend(args)
        bid = cas.backend_id_for(backend)
        out = []
        for s in cas.list_scans(None):
            if s.scan_id == cas.EARLIER_SCANS or s.backend_id != bid:
                continue
            if _confined(env, backend, s.root) is None:
                continue
            out.append(
                {
                    "scan_id": s.scan_id,
                    "root": s.root,
                    "backend_id": s.backend_id,
                    "algorithm": s.algorithm,
                    "started_at": _iso(s.started_at),
                    "finished_at": _iso(s.finished_at),
                    "files_indexed": s.files_indexed,
                    "files_in_index": s.files_in_index,
                    "duplicate_groups": s.duplicate_groups,
                    "status": s.status,
                    "error": redact_text(s.error or ""),
                }
            )
        return {"scans": out[:_MAX_LISTED], "truncated": len(out) > _MAX_LISTED}

    def _groups(args, backend):
        """Duplicate groups inside the confined folder: every copy of a group
        lies inside it (rows elsewhere in the shared index never count)."""
        folder = _folder_arg(env, backend, args)
        algo = _algorithm(args, None)
        scan_id = args.get("scan_id")
        if scan_id is not None:
            scan_id = _int_arg(args, "scan_id", 0, 0, 2**31 - 1)
        bid = cas.backend_id_for(backend)
        raw = cas.duplicates(None, algo, scan_id=scan_id, folder=folder, backend_id=bid)
        groups = []
        for group in raw:
            kept = [e for e in group if _confined(env, backend, e.path) is not None]
            if len(kept) >= 2:
                groups.append(cas.order_by_survivor(kept))
        return folder, bid, groups

    def _list_groups(args, ctx):
        backend = env.resolve_backend(args)
        max_groups = _int_arg(args, "max_groups", 100, 1, _MAX_GROUPS)
        folder, _bid, groups = _groups(args, backend)
        out = []
        for group in groups[:max_groups]:
            head = group[0]
            out.append(
                {
                    "algorithm": head.algorithm,
                    "value": head.value,
                    "size": head.size,
                    "copies": [
                        {
                            "path": e.path,
                            "size": e.size,
                            "mtime": e.mtime,
                            "scan_id": e.scan_id,
                            "keep": n == 0,
                        }
                        for n, e in enumerate(group)
                    ],
                }
            )
        return {"path": folder, "groups": out, "truncated": len(groups) > max_groups}

    def _dedupe(args, ctx):
        dry_run = _bool_arg(args, "dry_run", True)
        source = args.get("path")

        def work():
            backend = env.resolve_backend(args)
            folder, bid, groups = _groups(args, backend)
            env.write_path(folder, backend)
            trash_root = None
            if backend is env.default_backend and env.root:
                trash_root = env.write_path(os.path.join(env.root, ".axross-trash"), backend)
            result = cas.dedupe(
                groups,
                {bid: backend},
                dry_run=dry_run,
                trash_root=trash_root,
                cancel=lambda: ctx.is_cancelled,
                progress=lambda handled, removed, p: ctx.progress(
                    float(handled), None, f"{removed} moved to the trash - {p}"
                ),
            )
            if ctx.is_cancelled:
                raise _cancelled()

            def paths(entries):
                return [e.path for e in entries][:_MAX_LISTED]

            def reasons(pairs):
                return [{"path": e.path, "reason": redact_text(str(r))} for e, r in pairs][
                    :_MAX_LISTED
                ]

            return {
                "path": folder,
                "dry_run": result.dry_run,
                "groups": result.groups,
                "undated_groups": result.undated_groups,
                "keep": paths(result.keep),
                "trash": paths(result.trash),
                "removed": paths(result.removed),
                "refused": reasons(result.refused),
                "failed": reasons(result.failed),
                "trash_root": trash_root,
            }

        def ok(r):
            return {
                "path": source,
                "dry_run": r["dry_run"],
                "removed": len(r["removed"]),
                "refused": len(r["refused"]),
                "failed": len(r["failed"]),
            }

        return _audited(
            env, "duplicates_dedupe", {"path": source, "dry_run": dry_run}, work, ok
        )

    folder = _path_prop("Folder; default: the MCP root (local backend).")
    algo_any = {
        "type": "string",
        "enum": list(_HASH_ALGORITHMS),
        "description": "Only groups hashed with this algorithm; omit for all.",
    }
    scope = {
        "path": folder,
        "algorithm": algo_any,
        "scan_id": {
            "type": "integer",
            "minimum": 0,
            "maximum": 2**31 - 1,
            "description": "Only groups with at least one copy from this scan "
            "(duplicates_scans); 0 = rows from before scans were recorded.",
        },
    }
    copy_shape = "{path, size, mtime, scan_id, keep}"
    return [
        _tool(
            "duplicates_scan",
            "Hash every file under a folder into the Duplicate Finder's index (the same "
            "index the GUI uses), skipping symlinks and the axross trash; files whose size and "
            "mtime did not change are not hashed again unless rehash. Returns {scan_id, root, "
            "backend_id, algorithm, files_indexed, status}. One progress notification per "
            "file; cancellable (rows indexed so far are kept). Run it before duplicates_groups.",
            {
                "path": folder,
                "algorithm": {
                    "type": "string",
                    "enum": list(_HASH_ALGORITHMS),
                    "default": "sha256",
                    "description": "Hash algorithm.",
                },
                "rehash": _bool_prop("Hash every file even when unchanged.", default=False),
            },
            _scan,
            group="duplicates",
            timeout_class="long",
        ),
        _tool(
            "duplicates_scans",
            "The scan history of the addressed backend, newest first, limited to scans of "
            "folders inside the MCP root: {scans: [{scan_id, root, backend_id, algorithm, "
            "started_at, finished_at, files_indexed, files_in_index, duplicate_groups, status "
            "(complete|cancelled|failed|running), error}], truncated}.",
            {},
            _scans,
            group="duplicates",
        ),
        _tool(
            "duplicates_groups",
            "Groups of identical files from the index, every copy inside path. Each group is "
            f"{{algorithm, value (hash), size, copies: [{copy_shape}]}} in survivor order: the "
            "first copy (keep=true) is the oldest by mtime (ties: shorter, then "
            "alphabetically first path) and is what duplicates_dedupe keeps. The index is a "
            "record of the last scan; nothing is read from the files. Returns {path, groups, "
            "truncated}.",
            {
                **scope,
                "max_groups": _int_prop(
                    "Return at most this many groups.", minimum=1, maximum=_MAX_GROUPS,
                    default=100,
                ),
            },
            _list_groups,
            group="duplicates",
        ),
        _tool(
            "duplicates_dedupe",
            "Keep the first copy of every duplicate group inside path and move the others to "
            "the axross trash (restorable; for the local backend the trash is "
            "<MCP root>/.axross-trash). A dry run unless dry_run=false: the dry run only "
            "returns the plan. A real run re-checks every copy on disk first: a copy that "
            "changed since the scan, or a group without another verified copy, is reported "
            "in refused and left alone. Returns {path, dry_run, groups, undated_groups, keep, "
            "trash, removed, refused: [{path, reason}], failed: [{path, reason}], trash_root}.",
            {
                **scope,
                "dry_run": _bool_prop(
                    "true: only plan; false: move the planned copies to the trash.",
                    default=True,
                ),
            },
            _dedupe,
            group="duplicates",
            write=True,
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# index
# ---------------------------------------------------------------------------


def _build_index(env: GroupEnv) -> list:
    from core import metadata_index as MX

    def _build(args, ctx):
        backend = env.resolve_backend(args)
        folder = _folder_arg(env, backend, args)
        recursive = _bool_arg(args, "recursive", True)
        prune = _bool_arg(args, "prune", False)
        bid = env.index_backend_id(backend)
        indexed = MX.index_dir(
            backend,
            folder,
            backend_id=bid,
            recursive=recursive,
            cancel=lambda: ctx.is_cancelled,
            progress=lambda scanned, done, p: ctx.progress(float(done), None, f"indexed {p}"),
        )
        if ctx.is_cancelled:
            raise _cancelled()
        pruned = MX.prune_missing(backend, folder, backend_id=bid) if prune else 0
        return {
            "path": folder,
            "backend_id": bid,
            "recursive": recursive,
            "indexed": indexed,
            "pruned": pruned,
        }

    return [
        _tool(
            "index_build",
            "Walk a folder and record every entry (name, size, type, mtime) in the offline "
            "metadata index that the search tool reads - the same index as the GUI's "
            "metadata search. Additive; prune=true also drops index rows under the folder "
            "whose file no longer exists. Returns {path, backend_id, recursive, indexed, "
            "pruned}. One progress notification per entry; cancellable (what was indexed is "
            "kept).",
            {
                "path": _path_prop("Folder; default: the MCP root (local backend)."),
                "recursive": _bool_prop("Descend into subfolders.", default=True),
                "prune": _bool_prop(
                    "Also drop rows of files under the folder that are gone.", default=False
                ),
            },
            _build,
            group="index",
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# packer
# ---------------------------------------------------------------------------

_MAX_PACK_NAMES = 10_000


def _build_packer(env: GroupEnv) -> list:
    from core import packer as P

    def _formats(args, ctx):
        out = []
        for fmt in P.FORMATS.values():
            available, reason = fmt.available()
            out.append(
                {
                    "format": fmt.fmt_id,
                    "label": fmt.label,
                    "suffix": fmt.suffix,
                    "single": fmt.single,
                    "encrypts": fmt.encrypts,
                    "available": available,
                    "reason": reason,
                }
            )
        return {"formats": out, "levels": list(P.LEVELS)}

    def _pack(args, ctx):
        fmt = args.get("format", "zip") or "zip"
        names = args.get("names")
        fields = {
            "folder": args.get("folder"),
            "archive_name": args.get("archive_name"),
            "format": fmt,
            "names": len(names) if isinstance(names, list) else None,
        }

        def work():
            from core.mcp_server import CancelledError

            backend = env.resolve_backend(args)
            folder = env.write_path(_str_arg(args, "folder"), backend)
            if not _is_dir(backend, folder):
                raise ValueError(f"folder must be a folder: {folder}")
            if not isinstance(names, list) or not names or not all(
                isinstance(n, str) and n for n in names
            ):
                raise ValueError("names must be a non-empty list of entry names")
            if len(set(names)) != len(names):
                # core.packer would pack a repeated name twice.
                raise ValueError("names must not repeat an entry")
            archive_name = _str_arg(args, "archive_name")
            try:
                options = P.PackOptions(
                    fmt=fmt,
                    level=args.get("level", "normal") or "normal",
                    password=args.get("password") or "",
                    encrypt_names=_bool_arg(args, "encrypt_names", True),
                )
                result = P.pack(
                    backend,
                    folder,
                    list(names),
                    archive_name,
                    options,
                    progress=lambda done, total, name: ctx.progress(
                        float(done), float(total), f"packed {name}"
                    ),
                    cancel=_cancel_event(ctx),
                )
            except P.PackCancelled as exc:
                raise CancelledError("request cancelled by client") from exc
            except P.PackError as exc:
                raise ValueError(str(exc)) from exc
            # Built from the confined folder; re-checked so a surprise in the
            # naming can never leave the root unnoticed.
            env.write_path(result.path, backend)
            return {
                "path": result.path,
                "format": fmt,
                "files": result.files,
                "folders": result.folders,
                "bytes_in": result.bytes_in,
                "bytes_out": result.bytes_out,
                "skipped": result.skipped,
                "encrypted": bool(options.password),
            }

        return _audited(
            env,
            "pack",
            fields,
            work,
            lambda r: {"path": r["path"], "files": r["files"], "size": r["bytes_out"]},
        )

    return [
        _tool(
            "pack_formats",
            "The archive formats pack can write and whether each is usable here: "
            "{formats: [{format, label, suffix, single (exactly one file in), encrypts "
            "(takes a password), available, reason}], levels}.",
            {},
            _formats,
            group="packer",
            accepts_backend=False,
        ),
        _tool(
            "pack",
            "Pack entries of folder into a new archive folder/archive_name + suffix. Folders "
            "are packed recursively; symbolic links are skipped and listed in skipped, never "
            "followed. The archive is written to a temporary file first and an existing "
            "archive is never overwritten: 'bundle.zip' becomes 'bundle (2).zip'. Only 7z "
            "takes a password (AES-256; encrypt_names also hides the file list); ZIP and tar "
            "refuse one. Single-file formats (gz, bz2, xz, zst) take exactly one file. "
            "Returns {path, format, files, folders, bytes_in, bytes_out, skipped, encrypted}. "
            "One progress notification per file; cancellable (nothing is left behind).",
            {
                "folder": _path_prop("Folder holding the entries; the archive is created here."),
                "names": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "minItems": 1,
                    "maxItems": _MAX_PACK_NAMES,
                    "uniqueItems": True,
                    "description": "Names of files or folders directly inside folder (no "
                    "path separators, no repeats).",
                },
                "archive_name": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Archive file name without directory; the format's suffix "
                    "is added when missing.",
                },
                "format": {
                    "type": "string",
                    "enum": list(P.FORMATS),
                    "default": "zip",
                    "description": "Archive format (see pack_formats).",
                },
                "level": {
                    "type": "string",
                    "enum": list(P.LEVELS),
                    "default": "normal",
                    "description": "Compression level.",
                },
                "password": {
                    "type": "string",
                    "minLength": 1,
                    "writeOnly": True,
                    "description": "7z only: encrypt with AES-256. Never logged or returned.",
                },
                "encrypt_names": _bool_prop(
                    "7z with password: also encrypt the file list.", default=True
                ),
            },
            _pack,
            group="packer",
            required=("folder", "names", "archive_name"),
            write=True,
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# archive
# ---------------------------------------------------------------------------

_MAX_ARCHIVE_ENTRIES = 10_000


def _local_archive(env: GroupEnv, args: dict) -> tuple[Any, str]:
    backend = env.resolve_backend(args)
    if not _is_local(backend):
        raise ValueError(
            "archive tools read archives on the local backend only; copy the archive "
            "under the MCP root first (transfer_copy)"
        )
    path = env.scope_path(_str_arg(args, "path"), backend)
    if not os.path.isfile(path):
        raise ValueError(f"not a regular file: {path}")
    return backend, path


def _build_archive(env: GroupEnv) -> list:
    from core import archive as A

    def _list(args, ctx):
        _backend, path = _local_archive(env, args)
        max_entries = _int_arg(args, "max_entries", 1000, 1, _MAX_ARCHIVE_ENTRIES)
        entries = A.list_archive(path)
        return {
            "path": path,
            "total": len(entries),
            "truncated": len(entries) > max_entries,
            "entries": [
                {
                    "name": e.name,
                    "size": e.size,
                    "compressed": e.compressed,
                    "mtime": e.mtime,
                    "is_dir": e.is_dir,
                }
                for e in entries[:max_entries]
            ],
        }

    def _extract(args, ctx):
        fields = {"path": args.get("path"), "dest_dir": args.get("dest_dir")}

        def work():
            from core.mcp_server import CancelledError

            backend, path = _local_archive(env, args)
            dest = args.get("dest_dir")
            dest = env.write_path(
                _str_arg(args, "dest_dir") if dest is not None else os.path.dirname(path),
                backend,
            )
            if not os.path.isdir(dest):
                raise ValueError(f"dest_dir must be an existing folder: {dest}")
            base = A.strip_archive_extension(path) or "extracted"
            target = env.write_path(A.auto_suffix_dir(dest, base), backend)
            if ctx.is_cancelled:
                raise CancelledError("request cancelled by client")

            def progress(done, total, name):
                if ctx.is_cancelled:
                    raise A.ExtractCancelled("cancelled")
                ctx.progress(float(done), float(total), f"extracted {name}")

            try:
                files = A.extract(path, target, progress=progress)
            except A.ExtractCancelled as exc:
                raise CancelledError("request cancelled by client") from exc
            return {"path": target, "files": files}

        return _audited(
            env,
            "archive_extract",
            fields,
            work,
            lambda r: {"path": fields["path"], "target": r["path"], "files": r["files"]},
        )

    path = _path_prop("Archive file (zip family, tar.*, 7z, rar, gz/bz2/xz/zst) on the local "
                      "backend.")
    return [
        _tool(
            "archive_list",
            "List an archive's members without extracting anything: {path, total, truncated, "
            "entries: [{name, size (uncompressed), compressed, mtime, is_dir}]}. Local "
            "backend only.",
            {
                "path": path,
                "max_entries": _int_prop(
                    "Return at most this many entries.",
                    minimum=1,
                    maximum=_MAX_ARCHIVE_ENTRIES,
                    default=1000,
                ),
            },
            _list,
            group="archive",
            required=("path",),
            timeout_class="walk",
        ),
        _tool(
            "archive_extract",
            "Extract an archive into a new folder named after it inside dest_dir (default: "
            "the archive's folder): 'x.zip' -> 'x', then 'x-1', … - an existing folder is "
            "never written into. Zip-slip, absolute paths, links, more than 10,000 entries, "
            "more than 1 GiB or a compression ratio above 100 are refused and nothing is "
            "left behind. Returns {path (the new folder), files}. Progress per file; "
            "cancellable (the partial folder is removed). Local backend only.",
            {
                "path": path,
                "dest_dir": _path_prop("Existing folder under the MCP root to extract into."),
            },
            _extract,
            group="archive",
            required=("path",),
            write=True,
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------


def _build_crypto(env: GroupEnv) -> list:
    from core import encrypted_overlay as E

    def _source(args):
        backend = env.resolve_backend(args)
        path = env.scope_path(_str_arg(args, "path"), backend)
        if _is_dir(backend, path):
            raise ValueError(f"path must be a file: {path}")
        return backend, path

    def _encrypt(args, ctx):
        def work():
            from core.mcp_server import _read_capped_stream

            backend, path = _source(args)
            passphrase = _str_arg(args, "passphrase")
            cap = E.MAX_ENCRYPTED_SIZE
            with backend.open_read(path) as fh:
                data, too_big = _read_capped_stream(fh, cap)
            if too_big:
                raise ValueError(f"file larger than {cap} bytes, the most one .axenc file holds")
            blob = E.encrypt_bytes(data, passphrase)
            target = path if path.endswith(E.ENC_SUFFIX) else path + E.ENC_SUFFIX
            written = _place_new(env, backend, target, blob, ext=E.ENC_SUFFIX)
            return {"path": written, "size": len(blob), "plaintext_size": len(data)}

        return _audited(
            env,
            "encrypt",
            {"path": args.get("path")},
            work,
            lambda r: {"path": args.get("path"), "out": r["path"], "size": r["size"]},
        )

    def _decrypt(args, ctx):
        def work():
            backend, path = _source(args)
            plaintext = E.read_encrypted(backend, path, _str_arg(args, "passphrase"))
            if path.endswith(E.ENC_SUFFIX) and len(path) > len(E.ENC_SUFFIX):
                target = path[: -len(E.ENC_SUFFIX)]
            else:
                target = path + ".decrypted"
            written = _place_new(env, backend, target, plaintext)
            return {"path": written, "size": len(plaintext)}

        return _audited(
            env,
            "decrypt",
            {"path": args.get("path")},
            work,
            lambda r: {"path": args.get("path"), "out": r["path"], "size": r["size"]},
        )

    passphrase = {
        "type": "string",
        "minLength": 1,
        "writeOnly": True,
        "description": "Passphrase (PBKDF2-SHA256, 200,000 iterations, AES-256-GCM). Never "
        "logged or returned.",
    }
    return [
        _tool(
            "encrypt",
            "Encrypt a file (at most 1 GiB) into the axross encrypted-overlay format next to "
            "it: 'a.txt' -> 'a.txt.axenc', then 'a.txt (2).axenc' - nothing is overwritten. "
            "The plaintext stays in place, as in the GUI. Returns {path (the .axenc file), "
            "size, plaintext_size}.",
            {"path": _path_prop("File to encrypt."), "passphrase": passphrase},
            _encrypt,
            group="crypto",
            required=("path", "passphrase"),
            write=True,
            timeout_class="stream",
        ),
        _tool(
            "decrypt",
            "Decrypt an .axenc file into a new file next to it: 'a.txt.axenc' -> 'a.txt', or "
            "'a (2).txt' when that exists (a name without .axenc gets '.decrypted'); mode "
            "0600, nothing is overwritten. A wrong passphrase or a tampered file fails with "
            "nothing written. Returns {path (the plaintext file), size}.",
            {"path": _path_prop("The .axenc file."), "passphrase": passphrase},
            _decrypt,
            group="crypto",
            required=("path", "passphrase"),
            write=True,
            timeout_class="stream",
        ),
    ]


# ---------------------------------------------------------------------------
# remote
# ---------------------------------------------------------------------------

#: Profiles one MCP session (one HTTP session, or the stdio server) may have
#: open at the same time; each holds a live connection.
MAX_REMOTE_BACKENDS = 8

#: Protocols whose first sign-in is an interactive browser flow: Dropbox
#: reads the code with input() (core/dropbox_client.py), Google Drive runs
#: a local OAuth server (core/gdrive_client.py), OneDrive / SharePoint call
#: acquire_token_interactive (core/onedrive_client.py). On stdio, input()
#: would even read the JSON-RPC stream.
INTERACTIVE_PROTOCOLS = frozenset({"dropbox", "gdrive", "onedrive", "sharepoint"})


def password_prompt_needed(profile) -> bool:
    """Whether the GUI asks for a password before connecting this profile.

    The decision Quick Connect makes (core.profiles.password_needed); over
    MCP that password can only come from the keyring.
    """
    from core.profiles import password_needed

    return password_needed(profile)


def openable(profile) -> tuple[bool, str]:
    """``(can remote_open try it, why not)`` - decided without touching the
    keyring or the network."""
    proto = getattr(profile, "protocol", "")
    if proto in INTERACTIVE_PROTOCOLS:
        return False, (
            f"{proto} needs an interactive browser sign-in, which the MCP server cannot show"
        )
    from core.security_mode import LEGACY_PROTOCOLS, current_policy

    policy = current_policy()
    if not policy.allow_legacy_protocols and proto in LEGACY_PROTOCOLS:
        return False, f"the '{policy.name}' security mode blocks the legacy protocol {proto}"
    if password_prompt_needed(profile) and not getattr(profile, "store_password", False):
        return False, (
            "needs a password that is not stored in the keyring; store it once from the "
            "axross GUI (connection dialog: Store password)"
        )
    return True, ""


def check_remote_path(path) -> str:
    """Shape check for a path on a remote backend: --mcp-root does not apply
    there (the profile defines what is reachable)."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    return path


@dataclass
class OpenedBackend:
    backend: Any
    profile: Any
    #: False for a connection lent by the GUI (attach): never released here.
    owned: bool = True


class RemoteRegistry:
    """Saved profiles opened over MCP, per session.

    The scope is the HTTP session id (``core.mcp_server._current_session_id``)
    or ``""`` on stdio, so one HTTP client never sees or closes another's
    connections. Connections go through one ConnectionManager - the GUI's
    connect path, with its keyring, proxy and security-mode handling.

    :meth:`attach` lends a connection the GUI already holds (a pane's) to
    every scope; it stays the GUI's and is never released here. *gate*,
    when given, is asked with the profile before every use and every
    open - it raises PermissionError to refuse (the agent sandbox's
    allowed hosts, which may change at run time).
    """

    #: Every live registry, so tests and shutdown can close what is open.
    _live: weakref.WeakSet = weakref.WeakSet()

    def __init__(self, gate: Callable[[Any], None] | None = None) -> None:
        self._lock = threading.Lock()
        self._scopes: dict[str, dict[str, OpenedBackend]] = {}
        self._attached: dict[str, OpenedBackend] = {}
        self._gate = gate
        self._manager = None
        RemoteRegistry._live.add(self)

    @staticmethod
    def _scope() -> str:
        from core.mcp_server import _current_session_id

        return _current_session_id.get() or ""

    def _connections(self):
        if self._manager is None:
            from core.backend_registry import all_backends, init_registry
            from core.connection_manager import ConnectionManager
            from core.profiles import ProfileManager

            if not all_backends():
                init_registry()
            self._manager = ConnectionManager()
            self._manager.set_profile_resolver(lambda name: ProfileManager().get(name))
        return self._manager

    def attach(self, bid: str, backend, profile) -> None:
        """Lend *backend* (with its *profile*, or None) under *bid*."""
        with self._lock:
            if bid in self._attached or any(bid in scope for scope in self._scopes.values()):
                raise ValueError(f"the backend id {bid!r} is taken")
            self._attached[bid] = OpenedBackend(backend=backend, profile=profile, owned=False)

    def get(self, bid: str):
        with self._lock:
            opened = self._scopes.get(self._scope(), {}).get(bid) or self._attached.get(bid)
        if opened is None:
            return None
        if self._gate is not None:
            self._gate(opened.profile)
        return opened.backend

    def entries(self) -> list[tuple[str, OpenedBackend]]:
        with self._lock:
            return sorted({**self._attached, **self._scopes.get(self._scope(), {})}.items())

    def holds(self, backend) -> bool:
        return self._find(backend) is not None

    def _find(self, backend) -> OpenedBackend | None:
        if backend is None:
            return None
        with self._lock:
            for scope in (self._attached, *self._scopes.values()):
                for opened in scope.values():
                    if opened.backend is backend:
                        return opened
        return None

    def refuse_production(self, backend) -> None:
        opened = self._find(backend)
        if opened is not None and getattr(opened.profile, "production", False):
            raise PermissionError(
                f"profile {opened.profile.name!r} is flagged production: the MCP server "
                "refuses every mutation on it (the GUI's production countdown cannot be "
                "shown over MCP)"
            )

    def open(self, name: str) -> tuple[str, OpenedBackend, bool]:
        from core.local_fs import LocalFS
        from core.profiles import ProfileManager
        from core.redaction import redact_text
        from core.security_mode import require_protocol_allowed

        bid = f"profile:{name}"
        scope = self._scope()
        with self._lock:
            mine = self._scopes.get(scope, {})
            if bid in mine:
                return bid, mine[bid], True
            if len(mine) >= MAX_REMOTE_BACKENDS:
                raise ValueError(
                    f"at most {MAX_REMOTE_BACKENDS} profiles may be open at once; "
                    "call remote_close first"
                )
        profile = ProfileManager().get(name)
        if profile is None:
            raise ValueError(f"no saved profile named {name!r}; call remote_profiles")
        if self._gate is not None:
            self._gate(profile)
        require_protocol_allowed(profile.protocol)
        ok, reason = openable(profile)
        if not ok:
            raise PermissionError(f"profile {name!r} cannot be opened over MCP: {reason}")
        password = (profile.get_password() or "") if profile.store_password else ""
        if password_prompt_needed(profile) and not password:
            raise PermissionError(
                f"profile {name!r} needs a password that is not stored in the keyring; "
                "store it once from the axross GUI (connection dialog: Store password) - "
                "the MCP server never prompts"
            )
        manager = self._connections()
        unknown_host, mismatch = _host_key_errors()
        try:
            backend = manager.connect(profile, password=password, on_unknown_host=None)
        except unknown_host as exc:
            raise PermissionError(
                f"the host key of {exc.host} ({exc.key_type} SHA256:{exc.fingerprint_sha256}) "
                "is not trusted yet; connect once in the axross GUI and accept it - the MCP "
                "server never prompts"
            ) from None
        except mismatch as exc:
            raise PermissionError(
                f"refused: the host key of {name!r} does not match known_hosts "
                f"({redact_text(str(exc))})"
            ) from None
        except Exception as exc:  # noqa: BLE001 - any backend failure becomes one clear error
            raise OSError(
                f"cannot open profile {name!r}: {type(exc).__name__}: {redact_text(str(exc))}"
            ) from None
        if isinstance(backend, LocalFS):
            manager.release(profile)
            raise PermissionError(
                f"profile {name!r} opens the local file system, which would bypass --mcp-root; "
                "refused"
            )
        opened = OpenedBackend(backend=backend, profile=profile)
        with self._lock:
            mine = self._scopes.setdefault(scope, {})
            if bid in mine:  # a concurrent open of the same profile won
                manager.release(profile)
                return bid, mine[bid], True
            mine[bid] = opened
        return bid, opened, False

    def close(self, bid: str) -> bool:
        with self._lock:
            if bid in self._attached:
                raise ValueError(f"{bid!r} is the connection of an axross pane; it stays open")
            opened = self._scopes.get(self._scope(), {}).pop(bid, None)
        if opened is None:
            return False
        self._connections().release(opened.profile)
        return True

    def _release(self, opened_backends) -> None:
        for opened in opened_backends:
            if not opened.owned:
                continue
            try:
                self._connections().release(opened.profile)
            except Exception as exc:  # noqa: BLE001 - closing is best effort
                log.debug("remote close failed: %s", exc)

    def close_all(self) -> None:
        with self._lock:
            everything = [o for scope in self._scopes.values() for o in scope.values()]
            self._scopes.clear()
            self._attached.clear()  # the GUI's: dropped, never released
        self._release(everything)

    def _close_scope(self, scope: str) -> int:
        with self._lock:
            mine = self._scopes.pop(scope, {})
        self._release(mine.values())
        return len(mine)

    @staticmethod
    def close_session(session_id: str) -> int:
        """Release what an ended HTTP session left open, in every registry
        of this process (core.mcp_http calls this on drop and on idle
        eviction). Returns the number of connections released."""
        return sum(r._close_scope(session_id) for r in list(RemoteRegistry._live))


def _host_key_errors() -> tuple[type, type]:
    """The SSH host-key exception types, or never-raised stand-ins when
    paramiko is not installed (no SSH backend can connect then)."""
    try:
        from core.ssh_client import HostKeyMismatchError, UnknownHostKeyError
    except ImportError:

        class _Never(Exception):
            pass

        return _Never, _Never
    return UnknownHostKeyError, HostKeyMismatchError


_PROFILE_FIELDS = ("name", "protocol", "host", "port", "username", "auth_type", "store_password")


def _build_remote(env: GroupEnv) -> list:
    registry = env.remote

    def _profiles(args, ctx):
        from core.profiles import ProfileManager

        opened = dict(registry.entries())
        out = []
        for profile in sorted(ProfileManager().all_profiles(), key=lambda p: p.name):
            ok, reason = openable(profile)
            row = {field: getattr(profile, field, None) for field in _PROFILE_FIELDS}
            bid = f"profile:{profile.name}"
            row.update(
                production=bool(getattr(profile, "production", False)),
                open_as=bid if bid in opened else None,
                openable=ok,
                reason=reason,
            )
            out.append(row)
        return {"profiles": out}

    def _open(args, ctx):
        bid, opened, reused = registry.open(_str_arg(args, "profile"))
        production = bool(getattr(opened.profile, "production", False))
        return {
            "backend": bid,
            "profile": opened.profile.name,
            "protocol": opened.profile.protocol,
            "class": type(opened.backend).__name__,
            "production": production,
            "writable": env.allow_write and not production,
            "reused": reused,
        }

    def _close(args, ctx):
        bid = _str_arg(args, "backend")
        if not registry.close(bid):
            raise ValueError(f"no open backend {bid!r} in this session; see list_backends")
        return {"backend": bid, "closed": True}

    return [
        _tool(
            "remote_profiles",
            "The saved connection profiles, without any secret: {profiles: [{name, protocol, "
            "host, port, username, auth_type, store_password, production, open_as (backend "
            "id when opened in this session, else null), openable, reason (why remote_open "
            "would refuse, else empty)}]}.",
            {},
            _profiles,
            group="remote",
            accepts_backend=False,
        ),
        _tool(
            "remote_open",
            "Connect a saved profile and register it as backend 'profile:<name>' for this "
            "session; every other tool then reaches it with backend='profile:<name>'. "
            "Credentials come from the keyring when the profile stores them; a profile that "
            "would need a prompt (password not stored, SSH host key not yet trusted, browser "
            "sign-in) fails with an error instead. --mcp-root does not apply to remote paths. "
            "Writing needs --mcp-write, and a production-flagged profile stays read-only. "
            "Returns {backend, profile, protocol, class, production, writable, reused}.",
            {"profile": {"type": "string", "minLength": 1, "description": "Profile name."}},
            _open,
            group="remote",
            required=("profile",),
            timeout_class="walk",
            accepts_backend=False,
        ),
        _tool(
            "remote_close",
            "Disconnect a profile opened with remote_open in this session. Returns {backend, "
            "closed}.",
            {"backend": {"type": "string", "minLength": 1, "description": "'profile:<name>'."}},
            _close,
            group="remote",
            required=("backend",),
            accepts_backend=False,
        ),
    ]


# ---------------------------------------------------------------------------
# transfer
# ---------------------------------------------------------------------------

_MAX_TRANSFER_FILES = 10_000
_DEFAULT_MAX_FILE_BYTES = 10 * (1 << 30)


class _CancelAwareHandle:
    """A read handle that polls the call's cancellation before every read."""

    def __init__(self, handle, ctx) -> None:
        self._handle = handle
        self._ctx = ctx

    def read(self, *args):
        self._ctx.check_cancel()
        return self._handle.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self) -> None:
        self._handle.close()

    def __getattr__(self, name):
        return getattr(self._handle, name)


class _CancelAwareSource:
    """The source backend of a resumable copy, with cancel-polling reads, so
    tasks/cancel stops it within one segment (the manifest keeps the done
    segments for the next run)."""

    def __init__(self, backend, ctx) -> None:
        self._backend = backend
        self._ctx = ctx

    def open_read(self, *args, **kwargs):
        return _CancelAwareHandle(self._backend.open_read(*args, **kwargs), self._ctx)

    def __getattr__(self, name):
        attr = getattr(self._backend, name)
        if name == "open_read_range":
            return lambda *a, **k: _CancelAwareHandle(attr(*a, **k), self._ctx)
        return attr


def _ensure_dir(backend, path: str) -> None:
    """Create *path* and missing parents (idempotent)."""
    if backend.exists(path) and backend.is_dir(path):
        return
    parent = backend.parent(path)
    if parent and parent != path:
        _ensure_dir(backend, parent)
    try:
        backend.mkdir(path)
    except OSError:
        if not (backend.exists(path) and backend.is_dir(path)):
            raise


def _build_transfer(env: GroupEnv) -> list:
    from core.redaction import redact_text

    def _ends(args, *, mutate_source: bool):
        src_backend = env.backend_by_id(args.get("src_backend"))
        dst_backend = env.backend_by_id(args.get("dst_backend"))
        raw_src = _str_arg(args, "src")
        if mutate_source:
            src = env.entry_path(raw_src, src_backend)
            env.refuse_root(src, src_backend, "transfer source")
        else:
            src = env.scope_path(raw_src, src_backend)
        dst = env.write_path(_str_arg(args, "dst"), dst_backend)
        env.refuse_root(dst, dst_backend, "transfer destination")
        if src_backend is dst_backend and src == dst:
            raise ValueError("src and dst are the same path")
        return src_backend, src, dst_backend, dst

    def _copy(args, ctx):
        fields = {
            "src_backend": args.get("src_backend") or "local",
            "src": args.get("src"),
            "dst_backend": args.get("dst_backend") or "local",
            "dst": args.get("dst"),
        }

        def work():
            from core import copy_resume as CR
            from core import scripting as S
            from core.mcp_server import CancelledError
            from core.path_policy import safe_join

            sb, src, db, dst = _ends(args, mutate_source=False)
            overwrite = _bool_arg(args, "overwrite", False)
            resumable = _bool_arg(args, "resumable", False)
            max_files = _int_arg(args, "max_files", 1000, 1, _MAX_TRANSFER_FILES)
            max_depth = _int_arg(args, "max_depth", 10, 0, 50)
            max_file_bytes = _int_arg(
                args, "max_file_bytes", _DEFAULT_MAX_FILE_BYTES, 1, 1 << 50
            )
            entries: list[dict] = []

            def record(s, d, size, action, **extra):
                entries.append({"src": s, "dst": d, "size": size, "action": action, **extra})

            def one(s: str, d: str, size: int) -> None:
                d = env.write_path(d, db)
                if size > max_file_bytes:
                    record(s, d, size, "skipped", reason="too-large")
                    return
                if not resumable and not overwrite and db.exists(d):
                    record(s, d, size, "skipped", reason="exists")
                    return
                ctx.check_cancel()
                try:
                    _ensure_dir(db, db.parent(d))
                    if resumable:
                        report = CR.resumable_copy(
                            _CancelAwareSource(sb, ctx),
                            s,
                            db,
                            d,
                            overwrite=overwrite,
                            progress=lambda done, total: ctx.progress(
                                float(done), float(total), f"copied {done} bytes of {s}"
                            ),
                        )
                        if not report.completed:
                            raise OSError("the resumable copy did not complete")
                        record(
                            s,
                            d,
                            size,
                            "copied",
                            bytes=report.bytes_transferred,
                            resumed_segments=report.segments_skipped,
                        )
                    else:
                        moved = S.copy(sb, s, db, d, overwrite=overwrite)
                        record(s, d, size, "copied", bytes=int(moved or 0))
                except CancelledError:
                    raise
                except FileExistsError:
                    record(s, d, size, "skipped", reason="exists")
                except Exception as exc:  # noqa: BLE001 - one file must not end a tree copy
                    record(s, d, size, "error", error=redact_text(f"{type(exc).__name__}: {exc}"))

            def copied() -> int:
                return sum(1 for e in entries if e["action"] == "copied")

            # Every part of the tree left out gets a record and makes the
            # copy incomplete: dropped silently, a partial copy looked whole
            # to an agent that deletes the source next (bulk_copy, 0.12.10).
            truncated = False
            top = sb.stat(src)
            if not getattr(top, "is_dir", False):
                one(src, dst, int(getattr(top, "size", 0) or 0))
            else:
                queue: list[tuple[str, str, int]] = [(src, dst, 0)]
                while queue and not truncated:
                    ctx.check_cancel()
                    cur_src, cur_dst, depth = queue.pop(0)
                    try:
                        children = sorted(sb.list_dir(cur_src), key=lambda c: c.name)
                    except OSError as exc:
                        record(cur_src, cur_dst, 0, "error", folder=True,
                               error=redact_text(f"{type(exc).__name__}: {exc}"))
                        continue
                    for child in children:
                        name = getattr(child, "name", "")
                        if not name or name in (".", ".."):
                            continue
                        size = int(getattr(child, "size", 0) or 0)
                        try:
                            child_src = safe_join(sb, cur_src, name)
                            child_dst = safe_join(db, cur_dst, name)
                        except ValueError:
                            record(cur_src, cur_dst, size, "skipped", reason="unsafe-name",
                                   name=redact_text(repr(name)))
                            continue
                        if getattr(child, "is_link", False):
                            record(child_src, child_dst, size, "skipped", reason="symlink")
                            continue
                        if _confined(env, sb, child_src) is None:
                            record(child_src, child_dst, size, "skipped", reason="outside-root")
                            continue
                        if getattr(child, "is_dir", False):
                            if depth < max_depth:
                                queue.append((child_src, child_dst, depth + 1))
                            else:
                                truncated = True
                                record(child_src, child_dst, 0, "skipped", reason="max-depth")
                            continue
                        if copied() >= max_files:
                            truncated = True
                            break
                        one(child_src, child_dst, size)
                        ctx.progress(float(copied()), float(max_files), f"copied {child_src}")
            from core.mcp_server import _bulk_copy_complete

            return {
                "src": src,
                "dst": dst,
                "copied": copied(),
                "truncated": truncated,
                "complete": _bulk_copy_complete(entries, truncated),
                "entries": entries,
            }

        def ok(r):
            skipped = sum(1 for e in r["entries"] if e["action"] == "skipped")
            errors = sum(1 for e in r["entries"] if e["action"] == "error")
            return {**fields, "copied": r["copied"], "skipped": skipped, "errors": errors}

        return _audited(env, "transfer_copy", fields, work, ok)

    def _move(args, ctx):
        fields = {
            "src_backend": args.get("src_backend") or "local",
            "src": args.get("src"),
            "dst_backend": args.get("dst_backend") or "local",
            "dst": args.get("dst"),
        }

        def work():
            from core import scripting as S

            sb, src, db, dst = _ends(args, mutate_source=True)
            if _is_dir(sb, src):
                raise ValueError("transfer_move moves one file; copy a folder with transfer_copy")
            if db.exists(dst):
                raise FileExistsError(f"destination exists: {dst}")
            ctx.check_cancel()
            _ensure_dir(db, db.parent(dst))
            moved = S.move(sb, src, db, dst, overwrite=False)
            if not moved:
                moved = int(getattr(db.stat(dst), "size", 0) or 0)
            return {"src": src, "dst": dst, "bytes": int(moved)}

        return _audited(
            env, "transfer_move", fields, work, lambda r: {**fields, "bytes": r["bytes"]}
        )

    ends = {
        "src_backend": {
            "type": "string",
            "minLength": 1,
            "default": "local",
            "description": "Backend id of the source (list_backends); 'local' is the local "
            "file system under the MCP root.",
        },
        "src": _path_prop("Source path on src_backend."),
        "dst_backend": {
            "type": "string",
            "minLength": 1,
            "default": "local",
            "description": "Backend id of the destination.",
        },
        "dst": _path_prop("Destination path on dst_backend (the file, or the folder that "
                          "becomes the copy of a source folder)."),
    }
    return [
        _tool(
            "transfer_copy",
            "Copy a file or a folder tree from one backend to another (or within one). "
            "Local paths are confined to the MCP root, remote ones are not. Existing "
            "destination files are skipped unless overwrite; symlinks are skipped; missing "
            "destination folders are created. resumable=true copies each file in 4 MiB "
            "segments with a local manifest: a cancelled or failed run continues where it "
            "stopped when called again with the same arguments. Returns {src, dst, copied, "
            "truncated, complete, entries: [{src, dst, size, action (copied|skipped|error), "
            "reason, bytes, resumed_segments, error, folder}]}. Every part left out has a "
            "record: reason exists, too-large, symlink, unsafe-name, outside-root or "
            "max-depth (also sets truncated); a folder that could not be listed is an error "
            "with folder=true. complete is true only when every file was copied or already "
            "existed. Progress per file; cancellable.",
            {
                **ends,
                "overwrite": _bool_prop("Replace existing destination files.", default=False),
                "resumable": _bool_prop(
                    "Segmented copy that can continue after an interruption.", default=False
                ),
                "max_files": _int_prop(
                    "Copy at most this many files (truncated=true).",
                    minimum=1,
                    maximum=_MAX_TRANSFER_FILES,
                    default=1000,
                ),
                "max_depth": _int_prop(
                    "Subfolder levels to descend.", minimum=0, maximum=50, default=10
                ),
                "max_file_bytes": _int_prop(
                    "Skip files above this size (reason too-large).",
                    minimum=1,
                    maximum=1 << 50,
                    default=_DEFAULT_MAX_FILE_BYTES,
                ),
            },
            _copy,
            group="transfer",
            required=("src", "dst"),
            write=True,
            timeout_class="long",
            accepts_backend=False,
        ),
        _tool(
            "transfer_move",
            "Move one file to another backend (copy, then delete the source; the copy is "
            "removed again if the source cannot be deleted) or within one backend (rename). "
            "An existing destination is refused. Returns {src, dst, bytes}.",
            ends,
            _move,
            group="transfer",
            required=("src", "dst"),
            write=True,
            timeout_class="long",
            accepts_backend=False,
        ),
    ]


# ---------------------------------------------------------------------------
# extensions
# ---------------------------------------------------------------------------

#: Why the MCP server lists extensions but never runs one.
EXTENSIONS_NOT_RUNNABLE = (
    "extensions are GUI plugins: activate(api) receives the Qt ExtensionAPI "
    "(ui/extension_host.py) and can only add menu actions, context actions and docks; "
    "there is no headless action to call, and loading one runs its code with the "
    "user's rights - so the MCP server only reports them"
)


def _build_extensions(env: GroupEnv) -> list:
    from core import extensions as EX

    def _rows() -> tuple[bool, list[dict]]:
        allowed = EX.extensions_allowed()
        enabled = EX.enabled_ids()
        rows = []
        for info in EX.discover():
            on = info.ext_id in enabled
            rows.append(
                {
                    "id": info.ext_id,
                    "name": info.name,
                    "version": info.version,
                    "description": info.description,
                    "author": info.author,
                    "source": info.source,
                    "enabled": on,
                    "loadable": not info.error,
                    "error": info.error,
                    # What the GUI loads at start: switched on, valid, and
                    # not blocked by the security mode.
                    "active": allowed and on and not info.error,
                }
            )
        return allowed, rows

    def _list(args, ctx):
        allowed, rows = _rows()
        return {
            "allowed": allowed,
            "runnable_over_mcp": False,
            "why_not_runnable": EXTENSIONS_NOT_RUNNABLE,
            "extensions": rows,
        }

    def _info(args, ctx):
        ext_id = _str_arg(args, "ext_id")
        _allowed, rows = _rows()
        for row in rows:
            if row["id"] == ext_id:
                return {
                    **row,
                    "runnable_over_mcp": False,
                    "why_not_runnable": EXTENSIONS_NOT_RUNNABLE,
                }
        raise ValueError(f"no extension {ext_id!r}; see extensions_list")

    row = (
        "{id ('user:<name>' or 'bundled:<name>'), name, version, description, author, source, "
        "enabled (switched on in Extensions > Manage Extensions), loadable, error, active "
        "(loaded by the GUI: enabled, loadable and allowed)}"
    )
    return [
        _tool(
            "extensions_list",
            "The installed extensions (user and bundled) and their state, read without "
            f"importing any of them: {{allowed (false in the paranoid security mode), "
            f"runnable_over_mcp (always false), why_not_runnable, extensions: [{row}]}}. "
            "Extensions are GUI plugins with no headless actions, so none can be run here.",
            {},
            _list,
            group="extensions",
            accepts_backend=False,
        ),
        _tool(
            "extensions_info",
            f"One extension by id: {row} plus runnable_over_mcp and why_not_runnable.",
            {
                "ext_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Extension id from extensions_list.",
                }
            },
            _info,
            group="extensions",
            required=("ext_id",),
            accepts_backend=False,
        ),
    ]


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------

#: How a script reaches each POSIX interpreter: on stdin, arguments after it.
_POSIX_INTERPRETERS = {
    "sh": "sh -s --",
    "bash": "bash -s --",
    "python3": "python3 -",
    "perl": "perl -",
}
_MAX_EXEC_OUTPUT = 16 * 1024 * 1024


def _exec_kind(backend) -> str | None:
    """posix-shell, powershell (WinRM), ios-show (Cisco) or None."""
    if not callable(getattr(backend, "exec", None)):
        return None
    name = type(backend).__name__
    if name == "WinRMSession":
        return "powershell"
    if name == "CiscoTelnetSession":
        return "ios-show"
    return "posix-shell"


def _exec_result(result) -> dict:
    return {
        "returncode": int(result.returncode),
        "stdout": result.stdout.decode("utf-8", "replace"),
        "stderr": result.stderr.decode("utf-8", "replace"),
        "truncated_stdout": bool(result.truncated_stdout),
        "truncated_stderr": bool(result.truncated_stderr),
    }


def _build_exec(env: GroupEnv) -> list:
    import hashlib
    import shlex

    def target(args):
        backend = env.resolve_backend(args)
        kind = _exec_kind(backend)
        if kind is None:
            raise ValueError(
                f"backend {args.get('backend') or 'default'!r} ({type(backend).__name__}) has no "
                "remote shell; call exec_backends for the ones that do"
            )
        if env.remote is not None:
            env.remote.refuse_production(backend)
        return backend, kind

    def common(args):
        timeout = _int_arg(args, "timeout", 60, 1, 3600)
        cap = _int_arg(args, "max_output", 1024 * 1024, 1, _MAX_EXEC_OUTPUT)
        variables = args.get("env") or {}
        if not isinstance(variables, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in variables.items()
        ):
            raise ValueError("env must be an object of string values")
        return timeout, cap, variables or None

    def run(tool, args, backend, kind, command, stdin, timeout, cap, variables):
        from core.security_mode import current_policy

        # Checked at the call too: the mode can change after the tools were built.
        if not current_policy().allow_remote_exec:
            raise PermissionError("the security mode does not allow remote commands")
        sent = command
        if kind == "posix-shell" and variables:
            # Exported in the command line: SSH's env requests are dropped
            # by sshd unless AcceptEnv names the variable.
            from core.exec_util import sh_env_prefix

            try:
                sent = sh_env_prefix(variables, tool) + command
            except OSError as exc:
                raise ValueError(str(exc)) from None
            variables = None
        fields = {
            "backend": args.get("backend") or "default",
            "class": type(backend).__name__,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest()[:16],
            "command_len": len(command),
            "stdin_len": len(stdin) if stdin is not None else 0,
        }
        return _audited(
            env,
            tool,
            fields,
            lambda: backend.exec(
                sent,
                timeout=timeout,
                stdin=stdin,
                stdout_cap=cap,
                stderr_cap=min(cap, 1024 * 1024),
                env=variables,
            ),
            lambda r: {**fields, "returncode": r.returncode},
        )

    def _remote_exec(args, ctx):
        backend, kind = target(args)
        command = _str_arg(args, "command")
        stdin = args.get("stdin")
        if stdin is not None and not isinstance(stdin, str):
            raise ValueError("stdin must be a string")
        timeout, cap, variables = common(args)
        data = stdin.encode("utf-8") if stdin is not None else None
        return _exec_result(
            run("remote_exec", args, backend, kind, command, data, timeout, cap, variables)
        )

    def _remote_script(args, ctx):
        backend, kind = target(args)
        script = _str_arg(args, "script")
        interpreter = args.get("interpreter") or ("powershell" if kind == "powershell" else "sh")
        extra = args.get("args") or []
        if not isinstance(extra, list) or not all(isinstance(a, str) for a in extra):
            raise ValueError("args must be a list of strings")
        timeout, cap, variables = common(args)
        if kind == "ios-show":
            raise ValueError("a Cisco device runs single show commands only; use remote_exec")
        if kind == "powershell":
            if interpreter != "powershell":
                raise ValueError(
                    "a WinRM host runs PowerShell scripts only (interpreter=powershell)"
                )
            if extra:
                raise ValueError(
                    "PowerShell scripts take no args here; put the values into the script"
                )
            return _exec_result(
                run("remote_script", args, backend, kind, script, None, timeout, cap, variables)
            )
        if interpreter not in _POSIX_INTERPRETERS:
            raise ValueError(
                f"interpreter must be one of {sorted(_POSIX_INTERPRETERS)} on a POSIX shell"
            )
        command = " ".join([_POSIX_INTERPRETERS[interpreter], *map(shlex.quote, extra)])
        return _exec_result(
            run(
                "remote_script",
                args,
                backend,
                kind,
                command,
                script.encode("utf-8"),
                timeout,
                cap,
                variables,
            )
        )

    def _exec_backends(args, ctx):
        found = []
        for bid, backend in sorted((env.all_backends() if env.all_backends else {}).items()):
            kind = _exec_kind(backend)
            if kind is not None:
                found.append({"backend": bid, "class": type(backend).__name__, "kind": kind})
        return {"backends": found}

    env_prop = {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "description": "Environment variables for the command (names [A-Za-z_][A-Za-z0-9_]*).",
    }
    timeout_prop = _int_prop(
        "Seconds before the command is given up.", minimum=1, maximum=3600, default=60
    )
    cap_prop = _int_prop(
        "Bytes of stdout kept (stderr: at most 1 MiB); truncated_* tells when output was cut.",
        minimum=1,
        maximum=_MAX_EXEC_OUTPUT,
        default=1024 * 1024,
    )
    return [
        _tool(
            "remote_exec",
            "Run one command on a remote host (backend = an id from exec_backends) and return "
            "{returncode, stdout, stderr, truncated_stdout, truncated_stderr}. A non-zero exit is "
            "a result, not an error. Telnet and ADB deliver stderr inside stdout. Cisco: show "
            "commands only. WinRM: PowerShell.",
            {
                "command": {"type": "string", "minLength": 1, "description": "The command line."},
                "stdin": {
                    "type": "string",
                    "description": "Text fed to the command's stdin (not on WinRM/Cisco).",
                },
                "env": env_prop,
                "timeout": timeout_prop,
                "max_output": cap_prop,
            },
            _remote_exec,
            group="exec",
            required=("command",),
            write=True,
            timeout_class="long",
        ),
        _tool(
            "remote_script",
            "Run a script on a remote host: POSIX hosts get it on stdin of sh, bash, python3 or "
            "perl with args after it; WinRM hosts run it as PowerShell. "
            "Same result as remote_exec.",
            {
                "script": {"type": "string", "minLength": 1, "description": "The script text."},
                "interpreter": {
                    "type": "string",
                    "enum": sorted([*_POSIX_INTERPRETERS, "powershell"]),
                    "description": "sh by default; powershell on WinRM.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Script arguments.",
                },
                "env": env_prop,
                "timeout": timeout_prop,
                "max_output": cap_prop,
            },
            _remote_script,
            group="exec",
            required=("script",),
            write=True,
            timeout_class="long",
        ),
        _tool(
            "exec_backends",
            "List the backends that can run commands: {backend, class, kind} with kind "
            "posix-shell, powershell or ios-show. Open more with remote_open.",
            {},
            _exec_backends,
            group="exec",
            accepts_backend=False,
        ),
    ]


# ---------------------------------------------------------------------------
# agent
# ---------------------------------------------------------------------------

#: Groups agent_run may offer its model: those with read-only tools. The
#: inner agent never gets a write, exec, script or agent tool.
AGENT_GROUPS = ("metadata", "duplicates", "packer", "archive", "index", "filetype", "remote",
                "extensions")
#: Groups that reach beyond the MCP root (saved connections with their
#: stored credentials, the extensions' code): agent_run passes them on only
#: when the server itself offers them.
AGENT_GROUPS_SERVER_ONLY = frozenset({"remote", "extensions"})


def _build_agent(env: GroupEnv) -> list:
    def _agent_run(args, ctx):
        import os

        from core import agent as A
        from core import llm_profiles as LP

        task = _str_arg(args, "task")
        name = args.get("profile")
        settings = LP.LLMSettings.load()
        profile = settings.profile(name) if name else settings.active_profile()
        if profile is None:
            raise ValueError(
                f"no LLM profile named {name!r}" if name else
                "no LLM profile is active: set one up in the axross GUI (Agent dock: LLM…)"
            )
        groups = args.get("groups") or []
        if not isinstance(groups, list) or not all(g in AGENT_GROUPS for g in groups):
            raise ValueError(f"groups must be a list of {', '.join(AGENT_GROUPS)}")
        beyond = sorted(set(groups) & AGENT_GROUPS_SERVER_ONLY - env.groups)
        if beyond:
            raise PermissionError(
                f"the group(s) {', '.join(beyond)} reach beyond the MCP root: "
                "this server offers them only when started with them (--mcp-tools)"
            )
        max_steps = _int_arg(args, "max_steps", 10, 1, 30)
        if profile.needs_consent():
            raise PermissionError(
                f"the LLM profile {profile.name!r} sends to {profile.host() or 'an unknown host'}, "
                "which has no consent: confirm it once in the axross GUI"
            )
        config = A.AgentConfig(
            profile=profile,
            root=env.root or os.path.expanduser("~"),
            api_key=LP.get_api_key(profile.name),
            groups=frozenset(groups),
            allow_write=False,
            allow_exec=False,
            max_steps=max_steps,
        )
        agent = A.Agent(config, cancel=ctx.cancel_event)
        try:
            result = agent.run(task)
        except A.AgentError as exc:
            raise OSError(str(exc)) from None
        return {"answer": result.answer, "stopped": result.stopped, "calls": result.calls,
                "profile": profile.name, "model": profile.model}

    return [
        _tool(
            "agent_run",
            "Hand a task to the user's own LLM (the active LLM profile of the axross GUI, or "
            "'profile'). It works with axross' read-only tools inside the MCP root - plus the "
            "read-only tools of 'groups' - and returns {answer, stopped, calls, profile, model}. "
            "It cannot change files or run commands. Use it to keep file content on the user's "
            "machine, e.g. to summarise documents with a local model.",
            {
                "task": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 20000,
                    "description": "What the local model should do, in plain language.",
                },
                "profile": {
                    "type": "string",
                    "description": "An LLM profile name; default: the active one.",
                },
                "groups": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(AGENT_GROUPS)},
                    "description": "Extra tool groups the model may use (read-only tools only).",
                },
                "max_steps": _int_prop(
                    "Most model requests for this task.", minimum=1, maximum=30, default=10
                ),
            },
            _agent_run,
            group="agent",
            required=("task",),
            accepts_backend=False,
            timeout_class="long",
        ),
    ]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

_BUILDERS: dict[str, Callable[[GroupEnv], list]] = {
    "metadata": _build_metadata,
    "duplicates": _build_duplicates,
    "packer": _build_packer,
    "archive": _build_archive,
    "crypto": _build_crypto,
    "index": _build_index,
    "filetype": _build_filetype,
    "transfer": _build_transfer,
    "remote": _build_remote,
    "exec": _build_exec,
    "agent": _build_agent,
    "extensions": _build_extensions,
}


def build_group_tools(groups: Iterable[str], env: GroupEnv) -> list:
    """The tools of *groups*, in :data:`GROUPS` order. Mutating tools are
    left out unless ``env.allow_write``."""
    wanted = check_groups(groups)
    tools: list = []
    for group in GROUPS:
        if group not in wanted:
            continue
        if group == "exec" and not env.allow_exec:
            continue  # off unless --mcp-allow-exec, also under "all"
        builder = _BUILDERS.get(group)
        if builder is None:
            raise GroupError(f"MCP tool group {group!r} has no tools in this build")
        # exec's tools are mutating but gated by their own flag, not --mcp-write
        tools.extend(
            t for t in builder(env) if env.allow_write or not t.write or t.group == "exec"
        )
    return tools


# ---------------------------------------------------------------------------
# Machine-readable manifest (--mcp-list-tools, docs/mcp-tools.json)
# ---------------------------------------------------------------------------

#: The tool sets that exist without --mcp-tools.
BASE_GROUP_DESCRIPTIONS: dict[str, str] = {
    "core": "File tools of the configured backend; always on, read-only.",
    "write": "Write tools; only with --mcp-write, which needs --mcp-root.",
    "scripts": "Saved-script tools; only with --mcp-allow-scripts, stdio only, not confined "
    "to the MCP root; refused in the paranoid security mode.",
}
_WRITE_FLAGS = ["--mcp-write", "--mcp-root DIR"]


def _required_flags(tool) -> list[str]:
    if tool.group == "core":
        return []
    if tool.group == "write":
        return list(_WRITE_FLAGS)
    if tool.group == "scripts":
        return ["--mcp-allow-scripts"]
    if tool.group == "exec":
        return ["--mcp-tools exec", "--mcp-allow-exec"]
    flags = [f"--mcp-tools {tool.group}"]
    if tool.write:
        flags += _WRITE_FLAGS
    return flags


def tool_manifest(
    tools,
    *,
    groups: Iterable[str],
    allow_write: bool,
    allow_scripts: bool,
    allow_exec: bool = False,
) -> dict:
    """The manifest of *tools* (as built by ``_build_tools`` for these flags):
    everything a client needs to call each tool, and nothing about the
    host (no root, no version)."""
    from core.mcp_server import PROTOCOL_VERSION, SERVER_NAME, TIMEOUT_CLASSES

    descriptions = {**BASE_GROUP_DESCRIPTIONS, **GROUP_DESCRIPTIONS}
    order = ["core", "write", "scripts", *GROUPS]
    present = [g for g in order if any(t.group == g for t in tools)]
    return {
        "server": SERVER_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "generated_for": {
            "mcp_tools": sorted(check_groups(groups)),
            "mcp_write": bool(allow_write),
            "mcp_allow_scripts": bool(allow_scripts),
            "mcp_allow_exec": bool(allow_exec),
        },
        "timeout_classes": dict(TIMEOUT_CLASSES),
        "groups": {
            g: {
                "description": descriptions[g],
                "tools": [t.name for t in tools if t.group == g],
            }
            for g in present
        },
        "tools": [
            {
                "name": t.name,
                "group": t.group,
                "mutating": bool(t.write),
                "required_flags": _required_flags(t),
                "transports": ["stdio"] if t.group == "scripts" else ["stdio", "http"],
                "timeout_class": t.timeout_class,
                "timeout_seconds": t.timeout_seconds,
                "description": t.description,
                "input_schema": t.schema,
            }
            for t in tools
        ],
    }


def manifest_json(manifest: dict) -> str:
    """The canonical text form: sorted keys, two-space indent, UTF-8."""
    import json

    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


__all__ = [
    "ALL",
    "BASE_GROUP_DESCRIPTIONS",
    "ENV_VAR",
    "GROUPS",
    "GROUP_DESCRIPTIONS",
    "GroupEnv",
    "GroupError",
    "build_group_tools",
    "check_groups",
    "groups_from",
    "manifest_json",
    "parse_groups",
    "tool_manifest",
]
