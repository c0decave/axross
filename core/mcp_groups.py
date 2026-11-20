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

import io
import logging
import os
import posixpath
import re
import sys
import threading
import weakref
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from core import mcp_terms as T
from core.server_ops import ShortCopy

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
    #: ``refuse_moved_links(src, dst, backend)`` - a move that re-points a
    #: relative symlink out of the root or at a protected place is refused.
    refuse_moved_links: Callable[[str, str, Any], None] | None = None
    #: ``entry_checker(backend)`` -> ``check(path)``: :attr:`entry_path` for
    #: the many new entries of ONE call (an archive's members), with the
    #: protected places resolved once. None: entry_path per path.
    entry_checker: Callable[[Any], Callable[[str], str]] | None = None
    #: The folders the tools read (the root and the extra ones): granted for
    #: the read side's default-deny (core.protected_places.secret_checker).
    read_roots: tuple = ()


def _entry_checker(env: GroupEnv, backend) -> Callable[[str], str]:
    """``check(path)`` confining each new entry of one tool call."""
    if env.entry_checker is not None:
        return env.entry_checker(backend)
    return lambda path: env.entry_path(path, backend)


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


def _secret_refuser(env: GroupEnv, backend) -> Callable[[str], bool]:
    """``refuse(path)``: true for an entry below a confined folder that the
    tools must not read - a secret (core.protected_places: an SSH key, a
    token) unless the operator allowed secret reads. The secret places are
    resolved once per call; only a path among them goes through the full
    read confinement (:func:`_confined`), which decides."""
    if not _is_local(backend):
        return lambda path: False  # no secret places on a remote backend
    from core import protected_places

    check = protected_places.secret_checker(granted=env.read_roots)
    return lambda path: check(path) is not None and _confined(env, backend, path) is None


class _ConfinedListing:
    """*backend* with ``list_dir`` leaving out every secret entry
    (:func:`_secret_refuser`): for a walk in another module (core.cas)
    whose files are read."""

    def __init__(self, env: GroupEnv, backend) -> None:
        self._backend = backend
        self._refuse = _secret_refuser(env, backend)
        #: Folders whose listing failed (the walk goes on without them).
        self.failed: list[str] = []

    def __getattr__(self, name):
        return getattr(self._backend, name)

    def list_dir(self, path: str):
        try:
            listed = self._backend.list_dir(path)
        except OSError:
            self.failed.append(path)
            raise
        return [
            child
            for child in listed
            if getattr(child, "name", "") in ("", ".", "..")
            or not self._refuse(self._backend.join(path, child.name))
        ]


def _removable(path: str, backend, env: GroupEnv, *, entry: bool = True) -> bool:
    """Whether a tool walking a folder may change *path* in it: confined for
    writing (*entry*: removed or moved as an entry) - a read-only extra
    folder below the folder the call names stays untouched."""
    try:
        (env.entry_path if entry else env.write_path)(path, backend)
    except (PermissionError, ValueError):
        return False
    return True


def _split_name(name: str) -> tuple[str, str]:
    """``report.json`` -> (``report``, ``.json``); a dot file has no suffix."""
    stem, ext = posixpath.splitext(name)
    if not stem:
        return name, ""
    return stem, ext


def _free_name(stem: str, ext: str, n: int) -> str:
    """The packer's naming: ``stem.ext``, then ``stem (2).ext``, …"""
    return f"{stem}{ext}" if n == 1 else f"{stem} ({n}){ext}"


def _write_into(fh, data) -> None:
    """*data* (bytes, or a callable that writes into the handle) into *fh*."""
    if callable(data):
        data(fh)
    else:
        fh.write(data)


def _place_new(env: GroupEnv, backend, path: str, data, *, ext: str | None = None) -> str:
    """Write *data* to *path*, or to ``stem (2).ext``, ``stem (3).ext`` …
    when the name is taken - never over an existing file. Every candidate
    is confined like *path*. *ext* overrides the suffix split (``.axenc``
    for ``a.txt.axenc``). *data* is bytes or a callable ``write(fh)`` that
    streams into the new file. Returns the path used.

    The content is written under a temporary name beside the target
    (``.<name>.axross-part-<pid>-<random>``, mode 0600, recorded by
    core.partials) and renamed to the free name only when it is complete -
    without replacing anything. A process killed mid-write (a decrypt cut
    at 0.9 s) left a truncated file under the final name, indistinguishable
    from a whole one; now it leaves a temporary file, removed when it fails
    and swept at the next start when the process was killed."""
    from core import partials

    folder = backend.parent(path)
    name = posixpath.basename(path.replace("\\", "/").rstrip("/"))
    if ext is not None and name.endswith(ext) and len(name) > len(ext):
        stem = name[: -len(ext)]
    else:
        stem, ext = _split_name(name)
    import secrets

    tmp = env.entry_path(backend.join(
        folder, f".{name[:80]}.axross-part-{os.getpid()}-{secrets.token_hex(4)}"), backend)
    local = _is_local(backend)
    record = partials.track(tmp) if local else None
    try:
        if hasattr(backend, "create_new"):
            # core.confined_fs: created beneath the root's descriptor - a
            # folder of the path swapped for a symlink meanwhile is refused.
            with backend.create_new(tmp, 0o600) as fh:
                _write_into(fh, data)
        elif local:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(tmp, flags, 0o600), "wb") as fh:
                _write_into(fh, data)
        else:
            with backend.open_write(tmp) as fh:
                _write_into(fh, data)
        for n in range(1, 10_000):
            # A new entry: checked as one (a missing folder that would hold
            # a protected place is refused, not only the places themselves).
            candidate = env.entry_path(backend.join(folder, _free_name(stem, ext, n)), backend)
            try:
                if hasattr(backend, "rename_no_replace"):
                    backend.rename_no_replace(tmp, candidate)
                elif local:
                    os.link(tmp, candidate)  # fails when the name is taken
                    os.unlink(tmp)
                else:
                    if backend.exists(candidate):
                        continue
                    backend.rename(tmp, candidate)
            except FileExistsError:
                continue
            partials.done(record)
            return candidate
        raise OSError(f"no free name for {path}")
    except BaseException:
        _remove_quietly(backend, tmp)
        partials.done(record)
        raise


def _remove_quietly(backend, path: str) -> None:
    try:
        backend.remove(path)
    except Exception as exc:  # noqa: BLE001 - clean-up is best effort
        log.debug("could not remove the partial %s: %s", path, exc)


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
    # A folder that could not be listed (a remote over its listing cap)
    # makes the result incomplete, not empty.
    truncated = bool(scan.truncated) or bool(scan.unreadable) or len(paths) > max_files
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
                # The cleaned copy is written next to each file: none in a
                # read-only folder below *path*.
                skipped = [t for t in targets if not _removable(t, backend, env, entry=False)]
                targets = [t for t in targets if t not in skipped]
            else:
                if not backend.exists(path):
                    raise FileNotFoundError(f"no such file: {path}")
                targets, truncated, skipped = [path], False, []
            batch = MT.remove_many(
                backend,
                targets,
                mode=MT.MODE_COPY,
                cancel=cancel,
                progress=lambda done, total, p: ctx.progress(float(done), float(total), p),
                source=path,
            )
            ctx.check_cancel()
            # Over MCP every result is a copy: the per-result mode and the
            # in-place trash_id would always be "copy" and "".
            results = [{k: v for k, v in r.to_dict().items() if k not in ("mode", "trash_id")}
                       for r in batch.results]
            results += [{"path": s, "status": "skipped", "output": "", "removed": 0,
                         "error": "", "sha256": "", "note": "in a read-only folder"}
                        for s in skipped]
            return {
                "path": path,
                "mode": MT.MODE_COPY,
                "results": results,
                "truncated": truncated,
            }

        def ok(result):
            cleaned = sum(1 for r in result["results"] if r["status"] == MT.CLEANED)
            return {"path": source, "files": len(result["results"]), "cleaned": cleaned}

        return _audited(env, "metadata_remove", {"path": source}, work, ok)

    common = {
        "path": _path_prop(
            "A file, or a folder whose supported files are read (absolute, or relative to "
            "the MCP root)."
        ),
        "recursive": _bool_prop(
            "For a folder: also take the files in its subfolders (false: the folder's own "
            "files only). Ignored for a file.",
            default=False,
        ),
        "max_files": _int_prop(
            "For a folder: take at most this many files; more sets truncated=true. Ignored for "
            "a file.",
            minimum=1,
            maximum=_MAX_METADATA_FILES,
            default=200,
        ),
    }
    fmt = {
        "type": "string",
        "enum": list(MT.EXPORT_FORMATS),
        "default": "json",
        "description": "Text format. json: {\"files\": [<metadata_read file report>, ...]}; "
        "csv: header path,kind,group,field,value,removable,error and one row per field, cells "
        "that would start a spreadsheet formula prefixed with '.",
    }
    return [
        _tool(
            "metadata_read",
            "Read the embedded metadata (EXIF, XMP, document properties, tags) of a file or "
            "of every supported file in a folder.\n"
            "Use when: checking what a photo, document or media file reveals before "
            "sharing it.\n"
            "Instead: metadata_export for one JSON/CSV text; metadata_remove (needs "
            "--mcp-write) for cleaned copies.\n"
            "Behavior: read-only. Images, Office, PDF, audio/video (ffprobe, "
            f"{T.PARANOID_TAG}). A file it cannot read is a report with error set. "
            f"{T.SECRET_TAG} Values are cut at 512 characters. Cancellable.\n"
            "Returns: {path, is_dir, truncated, files: [{path, kind, error ('' when read), "
            "fields: [{group, name, value, removable}], ...}]}.",
            common,
            _read,
            group="metadata",
            required=("path",),
            timeout_class="stream",
        ),
        _tool(
            "metadata_export",
            "Export the metadata_read data of a file or folder as one JSON or CSV text.\n"
            "Use when: you need the metadata as a document to quote or diff.\n"
            "Instead: metadata_read for structured fields; metadata_export_file (needs "
            "--mcp-write) for a file, better for big folders.\n"
            "Behavior: read-only; reads as metadata_read does. A result over 16 MiB "
            "fails.\n"
            "Returns: {path, format, files (number of file reports), truncated, text}.",
            {**common, "format": fmt},
            _export,
            group="metadata",
            required=("path",),
            timeout_class="stream",
        ),
        _tool(
            "metadata_export_file",
            "Save the metadata_export text of path as a new file at out, on the same "
            "backend.\n"
            "Use when: the export should stay on disk next to the data.\n"
            "Instead: metadata_export for the text in the response.\n"
            "Behavior: only adds; a taken name gets a counter ('meta (2).json'). Not "
            "idempotent: each call adds a file. Written via a temporary name; new local "
            f"files are mode 0600. {T.WRITE_TAG}\n"
            "Returns: {path (the file written, not the source), format, files, truncated, "
            "size (bytes)}.",
            {
                **common,
                "format": fmt,
                "out": _path_prop(
                    "The new file on path's backend (absolute, or relative to the MCP root); its "
                    "folder must exist. A taken name gets a counter."
                ),
            },
            _export_file,
            group="metadata",
            required=("path", "out"),
            write=True,
            timeout_class="stream",
        ),
        _tool(
            "metadata_remove",
            "Strip the metadata of a file, or of each supported file in a folder, into "
            "cleaned copies next to the originals.\n"
            "Use when: sharing a file without its camera, GPS or author data; look with "
            "metadata_read first.\n"
            "Instead: metadata_export_file to keep the metadata as a record.\n"
            f"Requires: PDF needs pypdf; audio/video ffmpeg, {T.PARANOID_TAG}.\n"
            "Behavior: only adds; originals stay ('photo.jpg' -> 'photo.clean.jpg', taken: "
            "'photo.clean (1).jpg'); no in-place mode. Not idempotent: a repeat writes "
            "another copy. A missing file fails. "
            f"{T.SECRET_TAG} {T.WRITE_TAG} Progress; cancellable.\n"
            "Returns: {path, truncated, results: [{path, status, output (the copy), removed "
            "(fields), sha256, error}]}; status: cleaned, unchanged, unsupported, skipped "
            "(read-only folder) or error.",
            {**common, "path": _path_prop(
                "A file, or a folder whose supported files are cleaned (absolute, or relative "
                "to the MCP root).")},
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


def _unreadable(paths) -> dict:
    """The ``unreadable`` field of a walk's result: the folders it could
    not list (a few), when there were any."""
    paths = list(paths)
    return {"unreadable": paths[:_MAX_UNREADABLE]} if paths else {}


_MAX_UNREADABLE = 20


def _walk_files(env: GroupEnv, backend, start: str, max_depth: int, ctx,
                failed: list | None = None, cut: list | None = None):
    """Breadth-first ``(path, item)`` of the files under *start*: symlinks
    and entries that leave the root are skipped, cancel is polled per
    folder; folders that could not be listed go to *failed*."""
    from core.path_policy import safe_join

    queue: list[tuple[str, int]] = [(start, 0)]
    while queue:
        ctx.check_cancel()
        folder, depth = queue.pop(0)
        try:
            children = sorted(backend.list_dir(folder), key=lambda c: getattr(c, "name", ""))
        except OSError:
            if failed is not None:
                failed.append(folder)
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
                elif cut is not None:
                    cut.append(full)  # max_depth: listed, not entered
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
        failed: list[str] = []
        cut: list[str] = []
        for full, _item in _walk_files(env, backend, start, max_depth, ctx, failed, cut):
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
            ctx.progress(float(scanned), None, f"identified {full}")
            if only_mismatch and not info.mismatch:
                continue
            entries.append(_type_info(info))
        return {
            "path": start,
            "entries": entries,
            "files_scanned": scanned,
            # As walk: truncated - max_files or max_depth cut it; complete -
            # nothing cut and no folder left unread.
            "truncated": truncated or bool(cut),
            "complete": not (truncated or cut or failed),
            **_unreadable(failed),
        }

    limits = {
        "max_bytes": _int_prop(
            "Bytes read from the start of each file for the content check (64 KiB default, "
            "at most 1 MiB).",
            minimum=1,
            maximum=_MAX_TYPE_BYTES,
            default=FT.DEFAULT_MAX_BYTES,
        ),
        "use_file_command": _bool_prop(
            "Also run the file(1) command for its description (file_command); local regular "
            "files only, ignored on remote backends.",
            default=True,
        ),
    }
    return [
        _tool(
            "file_type",
            "Identify one file's real type from its content (magic bytes) and check the "
            "extension against it.\n"
            "Use when: an extension may lie, or encoding and line endings matter.\n"
            "Instead: file_type_scan for a folder; stat for size and date.\n"
            "Behavior: read-only; reads at most max_bytes. An unreadable or missing file "
            "is a result (kind error); reading gives up after 15 s per file (kind "
            f"timeout). {T.SECRET_TAG}\n"
            "Returns: {path, name, kind, verdict (match|mismatch|unknown), mime, "
            "extension, ...}; every field in outputSchema.",
            {
                "path": _path_prop(
                    "The file to identify (absolute, or relative to the MCP root)."
                ),
                **limits,
                "max_bytes": {**limits["max_bytes"], "description": "Bytes read from the "
                              "start of the file for the content check (64 KiB default, at "
                              "most 1 MiB)."},
            },
            _one,
            group="filetype",
            required=("path",),
            timeout_class="walk",  # above its 15 s per-file limit: that is a result
        ),
        _tool(
            "file_type_scan",
            "Identify the content type of every file under a folder and flag misleading "
            "extensions.\n"
            "Use when: auditing a folder for disguised files (mismatches_only=true).\n"
            "Instead: file_type for one file; walk for names only.\n"
            "Behavior: read-only, breadth-first, name order; symlinks are skipped. "
            "max_files or a folder at max_depth sets truncated; an unlistable folder "
            "goes to unreadable. "
            f"{T.SECRET_TAG} Progress; cancellable.\n"
            "Returns: {path, files_scanned, truncated, complete, unreadable (folder paths), "
            "entries: "
            "[file_type records]}; mismatches_only lists verdict=mismatch only.",
            {
                "path": _path_prop(
                    "The folder to scan (absolute, or relative to the MCP root)."
                ),
                "max_depth": _int_prop(
                    T.descend_text(),
                    minimum=0,
                    maximum=50,
                    default=2,
                ),
                "max_files": _int_prop(
                    "Stop after identifying this many files; more sets truncated=true.",
                    minimum=1,
                    maximum=_MAX_TYPE_SCAN_FILES,
                    default=500,
                ),
                "mismatches_only": _bool_prop(
                    "List only files whose content contradicts their extension.",
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


def _iso_seconds(seconds) -> str | None:
    """Unix seconds as the ISO 8601 the file tools give (modified)."""
    from datetime import datetime

    if seconds is None:
        return None
    try:
        return datetime.fromtimestamp(float(seconds)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


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
        cap = _WalkCap(env, backend, args)

        def progress(scanned, indexed, p):
            cap.count(scanned)
            ctx.progress(float(scanned), None, f"{indexed} indexed - {p}")

        listing = _ConfinedListing(env, backend)
        count = cas.rebuild(
            # Hashing reads every file: a secret is not read (nor indexed).
            listing,
            folder,
            backend_id=bid,
            algorithm=algo,
            rehash=rehash,
            cancel=lambda: ctx.is_cancelled or cap.reached,
            progress=progress,
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
            "truncated": cap.reached,
            "complete": not cap.reached and not listing.failed,
            **_unreadable(listing.failed),
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
        offset = _int_arg(args, "offset", 0, 0, 2**31 - 1)
        folder, _bid, groups = _groups(args, backend)
        out = []
        for group in groups[offset:offset + max_groups]:
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
                            "modified": _iso_seconds(e.mtime),
                            "scan_id": e.scan_id,
                            "keep": n == 0,
                        }
                        for n, e in enumerate(group)
                    ],
                }
            )
        return {"path": folder, "groups": out,
                "truncated": len(groups) > offset + max_groups}

    def _dedupe(args, ctx):
        dry_run = _bool_arg(args, "dry_run", True)
        source = args.get("path")

        def work():
            backend = env.resolve_backend(args)
            folder, bid, groups = _groups(args, backend)
            env.write_path(folder, backend)
            # A copy in a read-only folder inside *folder* is neither moved
            # to the trash nor counted on to stay.
            groups = [g for g in ([e for e in group if _removable(e.path, backend, env)]
                                  for group in groups) if len(g) > 1]
            trash_root = None
            if backend is env.default_backend and env.root:
                # axross's own trash: no tool writes there (core.protected_places),
                # core.trash does - into the root's, which must be the root's own
                # folder (not a link leading elsewhere).
                from core.trash import TRASH_DIRNAME

                trash_root = os.path.join(env.write_path(env.root, backend), TRASH_DIRNAME)
                if os.path.islink(trash_root) or (os.path.lexists(trash_root)
                                                  and not os.path.isdir(trash_root)):
                    raise PermissionError(f"{trash_root} is not a folder of the root")
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

    folder = _path_prop(
        "The folder (absolute, or relative to the MCP root). Default on the local "
        "backend: the MCP root; other backends need it."
    )
    algo_any = {
        "type": "string",
        "enum": list(_HASH_ALGORITHMS),
        "description": "Only groups hashed with this algorithm; omit for every algorithm.",
    }
    scope = {
        "path": folder,
        "algorithm": algo_any,
        "scan_id": {
            "type": "integer",
            "minimum": 0,
            "maximum": 2**31 - 1,
            "description": "Only groups with at least one copy from this scan (a scan_id from "
            "duplicates_scans); 0 = rows from before scans were recorded. Omit for all scans.",
        },
    }
    copy_shape = "{path, size, mtime (Unix seconds), modified (ISO 8601), scan_id, keep}"
    return [
        _tool(
            "duplicates_scan",
            "Run a duplicate scan: hash every file under a folder into the Duplicate "
            "Finder's index.\n"
            "Use when: before duplicates_groups or duplicates_dedupe, or after "
            "changes.\n"
            "Instead: duplicates_scans for past scans; checksum for one file.\n"
            "Behavior: writes index rows, never files. path must be a folder. Not "
            "idempotent: each run adds a scan record (the rows stay the same). Symlinks, "
            "the axross trash and secret files are skipped. "
            "Unchanged files are not hashed again unless rehash. The local disk hashes by "
            "reading; remote backends use their own checksum, so ETag-only ones (plain "
            "S3, WebDAV) index nothing. A capped or "
            "cancelled scan keeps its rows. Progress.\n"
            "Returns: {scan_id (null: no scan record was written), root, backend_id, "
            "algorithm, files_indexed, status, truncated (max_files), complete, "
            "unreadable (folder paths)}.",
            {
                "path": folder,
                "algorithm": {
                    "type": "string",
                    "enum": list(_HASH_ALGORITHMS),
                    "default": "sha256",
                    "description": "Hash algorithm for the index rows.",
                },
                "rehash": _bool_prop(
                    "Hash every file again, even when size and mtime are unchanged.",
                    default=False,
                ),
                "max_files": _WalkCap.prop(),
            },
            _scan,
            group="duplicates",
            timeout_class="long",
        ),
        _tool(
            "duplicates_scans",
            "List past duplicate scans (scan history), newest first.\n"
            "Use when: choosing a scan_id, or checking that a scan finished.\n"
            "Instead: duplicates_scan to run one; duplicates_groups for the duplicates.\n"
            "Behavior: read-only; this backend's scans (local: inside the MCP root), the "
            "newest 1000 only.\n"
            "Returns: {scans: [{scan_id, root, backend_id, algorithm, started_at, "
            "finished_at (ISO 8601, null while running), files_indexed, files_in_index, "
            "duplicate_groups, status, error}], truncated}.",
            {},
            _scans,
            group="duplicates",
        ),
        _tool(
            "duplicates_groups",
            "List groups of identical files from the duplicate index, every copy inside "
            "path.\n"
            "Use when: reviewing duplicates after duplicates_scan.\n"
            "Instead: duplicates_dedupe (needs --mcp-write) with dry_run for the trash "
            "plan.\n"
            "Behavior: read-only; the index as of the last scan, no file is read. Groups "
            "come by hash; empty files never group. The first copy (keep=true) is the "
            "oldest, the one duplicates_dedupe keeps. Pages with offset and "
            "max_groups.\n"
            f"Returns: {{path, truncated, groups: [{{algorithm, value, size, copies: "
            f"[{copy_shape}]}}]}}.",
            {
                **scope,
                "max_groups": _int_prop(
                    "Return at most this many groups; more sets truncated=true.",
                    minimum=1,
                    maximum=_MAX_GROUPS,
                    default=100,
                ),
                "offset": _int_prop(
                    "Groups to skip, for the next page: the previous offset + max_groups.",
                    minimum=0,
                    maximum=2**31 - 1,
                    default=0,
                ),
            },
            _list_groups,
            group="duplicates",
        ),
        _tool(
            "duplicates_dedupe",
            "Keep the first copy of each duplicate group inside path and move the others "
            "to the axross trash.\n"
            "Use when: after duplicates_groups; run dry_run=true first.\n"
            "Instead: duplicates_groups to look; remove to delete for good.\n"
            "Behavior: destructive but restorable; dry_run=true (default) only plans. "
            f"{T.IDEMPOTENT}: trashed copies leave the index, so a repeat plans none. "
            "Each copy is re-checked first; changed ones go to refused. "
            "The trash is .axross-trash in the MCP root (remote: the home folder); "
            "restore in the axross app.\n"
            "Returns: {path, dry_run, groups, undated_groups (survivor chosen by path), "
            "keep, trash (planned moves), removed (moves done; [] on dry_run), refused, "
            "failed, trash_root}.",
            {
                **scope,
                "dry_run": _bool_prop(
                    "true: only return the plan; false: move the planned copies to the trash.",
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
        cap = _WalkCap(env, backend, args)

        def progress(scanned, done, p):
            cap.count(scanned)
            ctx.progress(float(done), None, f"indexed {p}")

        walk = {"skipped": [], "complete": True, "seen": set()}
        indexed = MX.index_dir(
            backend,
            folder,
            backend_id=bid,
            recursive=recursive,
            cancel=lambda: ctx.is_cancelled or cap.reached,
            progress=progress,
            _walk=walk,
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
            # A folder that could not be listed (a remote over its listing
            # cap) is no empty folder.
            "truncated": cap.reached or not walk["complete"],
            "complete": not cap.reached and walk["complete"] and not walk["skipped"],
            **_unreadable(walk["skipped"]),
        }

    return [
        _tool(
            "index_build",
            "Record every entry under a folder (name, size, type, mtime) in the offline "
            "index that search reads.\n"
            "Use when: before search, or to refresh it.\n"
            "Instead: search to query; walk for the live state.\n"
            "Behavior: writes index rows, never files; reads listings only. "
            f"{T.IDEMPOTENT}. prune=true drops rows of files now gone. Linked folders are "
            "not followed; folders deeper than 50 levels go to unreadable. A cancelled "
            "run keeps its rows. Progress.\n"
            "Returns: {path, backend_id, recursive, indexed, pruned, truncated (max_files), "
            "complete, unreadable (folder paths)}.",
            {
                "path": _path_prop(
                    "The folder to index (absolute, or relative to the MCP root). Default on the "
                    "local backend: the MCP root; other backends need it."
                ),
                "recursive": _bool_prop(
                    "Also index the subfolders (false: the folder's own entries only).",
                    default=True,
                ),
                "prune": _bool_prop(
                    "Afterwards drop index rows below the folder whose file is gone.",
                    default=False,
                ),
                "max_files": _WalkCap.prop(),
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
                    # Every name and everything below one: a secret (an SSH
                    # key, a token) is left out and listed in skipped, as
                    # transfer_copy does - packed, read_file on the archive
                    # would hand it out.
                    refuse=_secret_refuser(env, backend),
                    # Each name the archive may get, before it is made there.
                    check_target=lambda p: env.entry_path(p, backend),
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
            "List the archive formats pack can write and whether each works here.\n"
            "Use when: before pack, to pick an available format.\n"
            "Instead: archive_list to read an archive; pack (needs --mcp-write) to create "
            "one.\n"
            "Behavior: read-only, no arguments; availability depends on installed "
            "packages (zstd, py7zr).\n"
            "Returns: {formats: [{format, label, suffix, single (one file in), encrypts "
            "(takes a password), available, reason}], levels (what pack's level takes)}.",
            {},
            _formats,
            group="packer",
            accepts_backend=False,
        ),
        _tool(
            "pack",
            "Pack entries of one folder into a new archive in that folder.\n"
            "Use when: bundling or compressing files, optionally with a 7z password.\n"
            "Instead: pack_formats for formats; archive_extract to unpack; encrypt for one "
            "file.\n"
            "Behavior: any backend (bytes pass through this machine). Only adds: a taken "
            "name gets a counter ('bundle (2).zip'). Not idempotent: each call adds an "
            "archive. A failure "
            "leaves nothing. Symlinks and secret files go to skipped. "
            f"{T.WRITE_TAG} Progress.\n"
            "Returns: {path, format, files, folders, bytes_in, bytes_out, skipped, "
            "encrypted}.",
            {
                "folder": _path_prop(
                    "The folder holding the entries (absolute, or relative to the MCP root); the "
                    "archive is created in it."
                ),
                "names": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "minItems": 1,
                    "maxItems": _MAX_PACK_NAMES,
                    "uniqueItems": True,
                    "description": "Names of files or folders directly inside folder, e.g. "
                    "['report.pdf', 'images']; no path separators, no repeats.",
                },
                "archive_name": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Archive file name without a folder, e.g. 'bundle'; the "
                    "format's suffix (.zip, .tar.gz, ...) is added when missing.",
                },
                "format": {
                    "type": "string",
                    "enum": list(P.FORMATS),
                    "default": "zip",
                    "description": "Archive format; pack_formats tells which are available "
                    "here. gz, zst, xz and bz2 compress exactly one file.",
                },
                "level": {
                    "type": "string",
                    "enum": list(P.LEVELS),
                    "default": "normal",
                    "description": "Compression level: fast (larger, quicker), normal or "
                    "best (smallest, slowest).",
                },
                "password": {
                    "type": "string",
                    "minLength": 1,
                    "writeOnly": True,
                    "description": "7z only: encrypt the archive with AES-256 using this "
                    "password; any other format fails with one. Never logged or returned.",
                },
                "encrypt_names": _bool_prop(
                    "7z with a password: also encrypt the file list, so names are hidden "
                    "without the password. Ignored otherwise.",
                    default=True,
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


def pinned_local_file(backend, path: str):
    """core.confined_fs.pinned_path (kept here for the group code)."""
    from core.confined_fs import pinned_path

    return pinned_path(backend, path)


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
        backend, path = _local_archive(env, args)
        max_entries = _int_arg(args, "max_entries", 1000, 1, _MAX_ARCHIVE_ENTRIES)
        try:
            # Read through the file the confined backend opened, not by
            # name (a folder swapped for a symlink meanwhile).
            with pinned_local_file(backend, path) as pinned:
                entries = A.list_archive(pinned, cancel=lambda: ctx.is_cancelled,
                                         password=args.get("password") or None)
        except A.ExtractCancelled as exc:
            raise _cancelled() from exc
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
                    "modified": _iso_seconds(e.mtime),
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
            # The new folder is an entry (a missing folder that holds a
            # protected place - ~/.local/share/systemd - is refused), and so
            # is every member below it, before it is made (core.archive
            # check_member): a member can land in a protected place.
            target = env.entry_path(A.auto_suffix_dir(dest, base), backend)
            if ctx.is_cancelled:
                raise CancelledError("request cancelled by client")

            def progress(done, total, name):
                if ctx.is_cancelled:
                    raise A.ExtractCancelled("cancelled")
                if total:  # 0: core.archive is still reading the headers
                    ctx.progress(float(done), float(total), f"extracted {name}")

            try:
                # Beneath the confined backend's descriptors (core.archive._Sink):
                # a folder swapped for a symlink while it extracts is refused.
                with pinned_local_file(backend, path) as pinned:
                    files = A.extract(pinned, target, progress=progress,
                                      parent_dir=getattr(backend, "parent_dir", None),
                                      check_member=_entry_checker(env, backend),
                                      password=args.get("password") or None)
            except A.ExtractCancelled as exc:
                raise CancelledError("request cancelled by client") from exc
            out = {"path": target, "files": int(files)}
            skipped = list(getattr(files, "skipped_links", None) or ())
            if skipped:
                # Links are never extracted; the caller must not take the
                # folder for the whole archive.
                out["skipped_links"] = skipped[:_MAX_ARCHIVE_ENTRIES]
                out["note"] = (
                    f"{len(skipped)} symbolic link{'s were' if len(skipped) != 1 else ' was'} "
                    f"not extracted: {', '.join(skipped[:10])}{', …' if len(skipped) > 10 else ''}"
                )
            return out

        return _audited(
            env,
            "archive_extract",
            fields,
            work,
            lambda r: {"path": fields["path"], "target": r["path"], "files": r["files"],
                       "skipped_links": len(r.get("skipped_links", ()))},
        )

    path = _path_prop(
        "The archive on the local disk (absolute, or relative to the MCP root): zip "
        "family, tar.*, 7z, rar, gz, bz2, xz or zst."
    )
    password = {
        "type": "string",
        "minLength": 1,
        "writeOnly": True,
        "description": "The password of an encrypted 7z or ZIP (e.g. one pack made with a "
        "password). Without it such an archive fails with 'the archive is encrypted with a "
        "password'; a wrong one fails too. Never logged or returned.",
    }
    return [
        _tool(
            "archive_list",
            "List the members of an archive on the local disk without extracting.\n"
            "Use when: checking contents or unpacked size before archive_extract.\n"
            "Instead: archive_extract (needs --mcp-write) to unpack it. A remote archive: "
            "transfer_copy (needs --mcp-write) to the local disk first.\n"
            "Behavior: read-only, local disk only. Unknown or damaged files fail; an "
            "encrypted 7z or ZIP needs password; 7z needs py7zr, rar rarfile. "
            f"{T.SECRET_TAG} Cancellable.\n"
            "Returns: {path, total, truncated, entries: [{name, size, compressed, mtime "
            "(Unix seconds), modified (ISO 8601), is_dir}]}.",
            {
                "path": path,
                "max_entries": _int_prop(
                    "Return at most this many members; total still counts all, truncated "
                    "tells when some were left out.",
                    minimum=1,
                    maximum=_MAX_ARCHIVE_ENTRIES,
                    default=1000,
                ),
                "password": password,
            },
            _list,
            group="archive",
            required=("path",),
            timeout_class="walk",
            accepts_backend=False,
        ),
        _tool(
            "archive_extract",
            "Extract an archive on the local disk into a new folder named after it.\n"
            "Use when: unpacking; look with archive_list first.\n"
            "Instead: archive_list to look; decrypt for .axenc files. A remote archive: "
            "transfer_copy to the local disk first.\n"
            "Behavior: only adds - 'x.zip' -> folder 'x', then 'x-1' (folders count with "
            "'-n'). Not idempotent: a repeat "
            "makes 'x-1'. An encrypted archive needs password. Zip-slip, over 10,000 "
            "members or 1 GiB unpacked, or zip bombs are refused, leaving nothing. "
            f"Links are never extracted. Local disk only. {T.WRITE_TAG}\n"
            "Returns: {path (the new folder), files}, plus skipped_links and note (how "
            "many links were left out) when there were links.",
            {
                "path": path,
                "dest_dir": _path_prop(
                    "An existing local folder that receives the new folder (absolute, or relative "
                    "to the MCP root). Default: the archive's folder."
                ),
                "password": password,
            },
            _extract,
            group="archive",
            required=("path",),
            write=True,
            timeout_class="long",
            accepts_backend=False,
        ),
    ]


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------


#: Single-shot (AXXE1) decryptions held in memory at once: each holds the
#: whole file (up to 1 GiB) and its plaintext.
_SINGLE_SHOT_SLOTS = threading.BoundedSemaphore(2)


class _CountingWriter:
    """Counts the bytes written through it."""

    def __init__(self, out) -> None:
        self._out = out
        self.count = 0

    def write(self, data) -> int:
        self._out.write(data)
        self.count += len(data)
        return len(data)


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
            backend, path = _source(args)
            passphrase = _str_arg(args, "passphrase")
            cap = E.MAX_ENCRYPTED_SIZE
            if not passphrase:
                raise ValueError("passphrase must be non-empty")
            # Streamed in the chunked format (AXXE2: every chunk
            # authenticated with its index, the last one marked, so a
            # reordered or cut file fails): a few MiB of memory whatever
            # the file's size, not the whole file several times.
            budget = _Budget(cap)
            sizes = {}

            def write(out) -> None:
                counted = _CountingWriter(out)
                with backend.open_read(path) as fh:
                    try:
                        E.encrypt_stream(_CancelAwareHandle(fh, ctx, budget), counted,
                                         passphrase)
                    except SourceTooLarge:
                        raise ValueError(f"file larger than {cap} bytes, the most one .axenc "
                                         "file holds") from None
                sizes["out"] = counted.count

            target = path if path.endswith(E.ENC_SUFFIX) else path + E.ENC_SUFFIX
            written = _place_new(env, backend, target, write, ext=E.ENC_SUFFIX)
            return {"path": written, "size": sizes.get("out", 0), "plaintext_size": budget.used}

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
            passphrase = _str_arg(args, "passphrase")
            if path.endswith(E.ENC_SUFFIX) and len(path) > len(E.ENC_SUFFIX):
                target = path[: -len(E.ENC_SUFFIX)]
            else:
                target = path + ".decrypted"
            with backend.open_read(path) as fh:
                head = fh.read(len(E.MAGIC_V2))
            if E.is_streaming_blob(head or b""):
                # The chunked format: decrypted chunk by chunk into the new
                # file; a chunk that fails, or a missing last chunk, removes
                # it again.
                sizes = {}

                def write(out) -> None:
                    counted = _CountingWriter(out)
                    with backend.open_read(path) as fh:
                        E.decrypt_stream(_CancelAwareHandle(fh, ctx), counted, passphrase)
                    sizes["out"] = counted.count

                written = _place_new(env, backend, target, write)
                return {"path": written, "size": sizes.get("out", 0)}
            # The single-shot format (AXXE1, files encrypted before): streamed
            # too (its GCM tag is read first, checked at the end; a failure
            # removes the new file). A source that cannot seek is held in
            # memory instead - at most _SINGLE_SHOT_SLOTS of them at a time.
            size = int(getattr(backend.stat(path), "size", 0) or 0)
            if size > E.MAX_ENCRYPTED_SIZE:
                raise ValueError(f"encrypted file larger than {E.MAX_ENCRYPTED_SIZE} bytes")
            sizes = {}

            def write_v1(out) -> None:
                with backend.open_read(path) as fh:
                    if not callable(getattr(fh, "seek", None)) or (
                            callable(getattr(fh, "seekable", None)) and not fh.seekable()):
                        raise io.UnsupportedOperation("not seekable")
                    sizes["out"] = E.decrypt_v1_stream(_CancelAwareHandle(fh, ctx), size,
                                                       out, passphrase)

            try:
                written = _place_new(env, backend, target, write_v1)
                return {"path": written, "size": sizes.get("out", 0)}
            except io.UnsupportedOperation:
                pass
            with _SINGLE_SHOT_SLOTS:
                plaintext = E.read_encrypted(backend, path, passphrase)
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
        "description": "The passphrase; the key is derived with PBKDF2-SHA256 (200,000 "
        "iterations) for AES-256-GCM. Never logged or returned.",
    }
    return [
        _tool(
            "encrypt",
            "Encrypt one file into a new .axenc file next to it (axross's format).\n"
            "Use when: one file must be kept or shared under a passphrase; decrypt "
            "reverses it.\n"
            "Instead: pack as 7z with a password for several files.\n"
            "Behavior: only adds; the plaintext stays ('a.txt' -> 'a.txt.axenc', taken: "
            "'a.txt (2).axenc'). Not "
            "idempotent: each call adds a file. At most 1 GiB; new local files are mode "
            f"0600. {T.SECRET_TAG} {T.WRITE_TAG} Cancellable.\n"
            "Returns: {path, size, plaintext_size}.",
            {
                "path": _path_prop(
                    "The file to encrypt, not a folder (absolute, or relative to the MCP root)."
                ),
                "passphrase": passphrase,
            },
            _encrypt,
            group="crypto",
            required=("path", "passphrase"),
            write=True,
            timeout_class="stream",
        ),
        _tool(
            "decrypt",
            "Decrypt an .axenc file into a new plaintext file next to it.\n"
            "Use when: restoring a file encrypted with axross.\n"
            "Instead: archive_extract for encrypted 7z or ZIP archives.\n"
            "Behavior: only adds ('a.txt.axenc' -> 'a.txt', taken: 'a (2).txt'; a name "
            "without .axenc gets '.decrypted'). Not "
            "idempotent: each call adds a file. A wrong passphrase or tampered file fails, "
            f"leaving nothing. At most 1 GiB; new local files are mode 0600. "
            f"{T.WRITE_TAG} Cancellable.\n"
            "Returns: {path, size}.",
            {
                "path": _path_prop(
                    "The .axenc file to decrypt (absolute, or relative to the MCP root)."
                ),
                "passphrase": passphrase,
            },
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


#: A ``..`` component, with either separator, or after a drive (``C:..``).
_PARENT_COMPONENT = re.compile(r"(?:^|[/\\:])\.\.(?:[/\\]|$)")


def check_remote_path(path, *, mutating: bool = False) -> str:
    """Shape check for a path on a remote backend: --mcp-root does not apply
    there (the profile defines what is reachable). A path a tool writes,
    moves or deletes (*mutating*) may hold no ``..`` component, split on
    ``/`` or ``\\``: where it lands depends on who resolves it (smbclient
    and Remove-Item apply Windows rules, ``/x\\..`` is the share root
    there). The backends refuse it too; this is the second line."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    if mutating and _PARENT_COMPONENT.search(path):
        raise ValueError(f"refusing a remote path with '..' in it: {path!r}")
    return path


@dataclass
class OpenedBackend:
    backend: Any
    profile: Any
    #: False for a connection lent by the GUI (attach): never released here.
    owned: bool = True
    #: The ConnectionManager it came from (released there).
    manager: Any = None


#: Seconds an SFTP request of a profile opened over MCP may wait for its
#: answer: a server that stops answering mid-read held a worker thread
#: (and its partial file) for good. A healthy server answers each
#: request long before this.
REMOTE_IO_TIMEOUT_SECONDS = 60.0


def remote_io_timeout() -> float:
    """The SFTP request deadline: AXROSS_MCP_REMOTE_TIMEOUT (seconds, 5 to
    3600) or REMOTE_IO_TIMEOUT_SECONDS. A CLOSE, REMOVE or rename waits
    longer anyway (core.ssh_client._SLOW_BY_NATURE)."""
    raw = os.environ.get("AXROSS_MCP_REMOTE_TIMEOUT", "").strip()
    try:
        value = float(raw) if raw else REMOTE_IO_TIMEOUT_SECONDS
    except ValueError:
        log.warning("AXROSS_MCP_REMOTE_TIMEOUT=%r is no number of seconds; using %g", raw,
                    REMOTE_IO_TIMEOUT_SECONDS)
        return REMOTE_IO_TIMEOUT_SECONDS
    if not 5 <= value <= 3600:
        log.warning("AXROSS_MCP_REMOTE_TIMEOUT=%g is outside 5..3600; using %g", value,
                    REMOTE_IO_TIMEOUT_SECONDS)
        return REMOTE_IO_TIMEOUT_SECONDS
    return value


def _bound_remote_io(backend) -> None:
    """Bound every SFTP request of *backend*: REMOTE_IO_TIMEOUT_SECONDS
    without an answer ends it (an OSError), keepalives or not, on every
    thread's channel (core.ssh_client.SSHSession.bound_requests). Other
    clients: their channel's read time-out."""
    bound = getattr(backend, "bound_requests", None)
    if callable(bound):
        bound(remote_io_timeout())
        return
    sftp = getattr(backend, "sftp", None)
    try:
        channel = sftp.get_channel() if sftp is not None else None
        if channel is not None:
            channel.settimeout(remote_io_timeout())
    except Exception as exc:  # noqa: BLE001 - a stand-in client: nothing to bound
        log.debug("no SFTP channel timeout for %s: %s", type(backend).__name__, exc)


def _unknown_host_advice(profile, exc) -> str:
    """How to trust a host key without the GUI: commands that work as given
    - the bare host name for ``-p`` (the known_hosts form ``[host]:port``
    is what ssh-keyscan writes, not what it takes) and ssh-keyscan's key
    type names (rsa, ed25519, ecdsa)."""
    import shlex

    host = str(getattr(profile, "host", "") or exc.host)
    port = int(getattr(profile, "port", 22) or 22)
    raw_type = str(getattr(exc, "key_type", "") or "")
    kind = ("rsa" if "rsa" in raw_type else "ed25519" if "ed25519" in raw_type
            else "ecdsa" if "ecdsa" in raw_type else "")
    scan = f"ssh-keyscan -p {port}{f' -t {kind}' if kind else ''} {shlex.quote(host)}"
    # Every command in backticks runs as given when pasted (a remark in
    # the middle of one was a shell syntax error).
    return (f"the host key of {exc.host} ({raw_type} SHA256:{exc.fingerprint_sha256}) is not "
            "trusted yet - the MCP server never prompts. Check that fingerprint with the "
            f"server's admin. To trust it: run `{scan} > /tmp/hostkey`, check that "
            "`ssh-keygen -lf /tmp/hostkey` shows the same SHA256, then run "
            "`mkdir -p ~/.ssh && cat /tmp/hostkey >> ~/.ssh/known_hosts`. Or connect once "
            f"with `ssh -p {port} {shlex.quote(host)}` and accept it there, or once in the "
            "axross GUI")


def _tear_down(backend, bid: str) -> None:
    """Close *backend*'s connection, whoever still holds it."""
    for name in ("close", "disconnect"):
        method = getattr(backend, name, None)
        if callable(method):
            try:
                method()
                log.info("remote_close: %s torn down (calls on it had not stopped)", bid)
                return
            except Exception as exc:  # noqa: BLE001 - best effort
                log.debug("remote_close: %s of %s failed: %s", name, bid, exc)


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
        # Production profiles connect through a pool of their own: the
        # shared pool hands two profiles of one server the same session,
        # and a write through the production one looked like a write
        # through the other (round 1 of the MCP review).
        self._production_manager = None
        RemoteRegistry._live.add(self)

    @staticmethod
    def _scope() -> str:
        from core.mcp_server import _current_session_id

        return _current_session_id.get() or ""

    def _connections(self, production: bool = False):
        attr = "_production_manager" if production else "_manager"
        if getattr(self, attr) is None:
            from core.backend_registry import all_backends, init_registry
            from core.connection_manager import ConnectionManager
            from core.profiles import ProfileManager

            if not all_backends():
                init_registry()
            manager = ConnectionManager()
            manager.set_profile_resolver(lambda name: ProfileManager().get(name))
            setattr(self, attr, manager)
        return getattr(self, attr)

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

    def _all_for(self, backend) -> list[OpenedBackend]:
        if backend is None:
            return []
        with self._lock:
            return [o for scope in (self._attached, *self._scopes.values())
                    for o in scope.values() if o.backend is backend]

    def refuse_production(self, backend) -> None:
        # Every profile that reaches this connection counts, not the first
        # one found: one production profile among them refuses.
        for opened in self._all_for(backend):
            if getattr(opened.profile, "production", False):
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
        production = bool(getattr(profile, "production", False))
        manager = self._connections(production=production)
        unknown_host, mismatch = _host_key_errors()
        try:
            backend = manager.connect(profile, password=password, on_unknown_host=None)
        except unknown_host as exc:
            raise PermissionError(_unknown_host_advice(profile, exc)) from None
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
        _bound_remote_io(backend)
        opened = OpenedBackend(backend=backend, profile=profile, manager=manager)
        shared = [o for o in self._all_for(backend)
                  if bool(getattr(o.profile, "production", False)) != production]
        if shared:
            # Belt and braces: a session must never be both a production
            # profile's and an ordinary one's.
            manager.release(profile)
            raise PermissionError(
                f"profile {name!r} would share its connection with "
                f"{shared[0].profile.name!r}, which differs in the production flag; refused")
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
        (opened.manager or self._connections()).release(opened.profile)
        from core.mcp_server import _ABANDONED

        if _ABANDONED.alive(bid):
            # Calls on it did not stop (a server that stalls a request but
            # answers keepalives): only closing the connection ends their
            # waits - and frees the profile for a new remote_open.
            _tear_down(opened.backend, bid)
        return True

    def _release(self, opened_backends) -> None:
        for opened in opened_backends:
            if not opened.owned:
                continue
            try:
                (opened.manager or self._connections()).release(opened.profile)
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
            "List the saved connection profiles (SFTP, SMB, WebDAV, S3 ...) and whether "
            "remote_open can open each.\n"
            "Use when: finding the name to pass to remote_open.\n"
            "Instead: list_backends for what is open now.\n"
            "Behavior: read-only; no network, no keyring, never a secret.\n"
            "Returns: {profiles: [{name, protocol, host, port, username, auth_type, "
            "store_password (a password is kept), production, open_as (its backend id "
            "when open), openable, reason}]}, by name.",
            {},
            _profiles,
            group="remote",
            accepts_backend=False,
        ),
        _tool(
            "remote_open",
            "Connect a saved profile as backend 'profile:<name>' for this session.\n"
            "Use when: files on a remote server or cloud store are needed.\n"
            "Instead: remote_profiles to list profiles; remote_close when done.\n"
            "Requires: a profile that needs no prompt (password in the keyring, host key "
            "trusted).\n"
            "Behavior: changes no files; opens a network connection and holds one of 8 "
            "session slots (a ninth fails: 'call remote_close first'). "
            f"{T.IDEMPOTENT}; it returns the open one (reused=true). "
            "Remote paths are outside --mcp-root; production profiles are read-only.\n"
            f"Returns: {{backend, profile, protocol, {T.CLASS_TEXT}, production, writable, "
            "reused}.",
            {
                "profile": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The saved profile's name, exactly as remote_profiles "
                    "lists it, e.g. 'nas'.",
                }
            },
            _open,
            group="remote",
            required=("profile",),
            timeout_class="walk",
            accepts_backend=False,
        ),
        _tool(
            "remote_close",
            "Disconnect a profile that remote_open opened in this session.\n"
            "Use when: done with a remote backend, or to free a slot.\n"
            "Instead: list_backends to see what is open.\n"
            "Behavior: changes no files; the id stops working and calls stuck on it end. "
            f"{T.IDEMPOTENT}; it fails with 'no open backend'. A connection lent by an "
            "axross pane is refused.\n"
            "Returns: {backend, closed: true}.",
            {
                "backend": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The backend id remote_open returned, e.g. 'profile:nas'.",
                }
            },
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


class SourceTooLarge(OSError):
    """A source sent more bytes than the call's byte cap (a server can say
    a file has 5 bytes and send gigabytes)."""


class _Budget:
    """Bytes one call may still read from its sources, shared by them."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.used = 0

    def take(self, count: int) -> None:
        self.used += count
        if self.limit is not None and self.used > self.limit:
            raise SourceTooLarge(f"the source sent more than {self.limit} bytes "
                                 "(the call's max_file_bytes); stopped")


class _CancelAwareHandle:
    """A read handle that polls the call's cancellation before every read
    and counts what it reads against the call's byte budget."""

    def __init__(self, handle, ctx, budget: "_Budget | None" = None) -> None:
        self._handle = handle
        self._ctx = ctx
        self._budget = budget

    def read(self, *args):
        self._ctx.check_cancel()
        data = self._handle.read(*args)
        if self._budget is not None and data:
            self._budget.take(len(data))
        return data

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

    def __init__(self, backend, ctx, budget: "_Budget | None" = None) -> None:
        self._backend = backend
        self._ctx = ctx
        self._budget = budget

    def open_read(self, *args, **kwargs):
        return _CancelAwareHandle(self._backend.open_read(*args, **kwargs), self._ctx,
                                  self._budget)

    def __getattr__(self, name):
        attr = getattr(self._backend, name)
        if name == "open_read_range":
            return lambda *a, **k: _CancelAwareHandle(attr(*a, **k), self._ctx, self._budget)
        return attr


def _source_mode(backend, path: str) -> int | None:
    """The st_mode of *path* itself (not following a link) where the
    backend can tell: SFTP's lstat, the local file system's. None
    elsewhere (the byte budget still bounds what is read)."""
    import stat as _stat  # noqa: F401 - for callers' S_IS* checks

    sftp = getattr(backend, "sftp", None)
    try:
        if sftp is not None:
            return int(sftp.lstat(path).st_mode)
        if _is_local(backend):
            return os.lstat(path).st_mode
    except (OSError, AttributeError, TypeError, ValueError):
        return None
    except Exception:  # noqa: BLE001 - a backend's own error: not known
        return None
    return None


def _special_source(backend, path: str, item=None) -> str | None:
    """Why *path* is no regular file to copy, or None. On a remote: a
    symlink (the server follows it when reading: /zero -> /dev/zero), a
    device, a FIFO, a socket. On the local disk a link is followed - the
    root check already refused one that leaves the root - and what it
    reaches must be a regular file."""
    import stat as _stat

    if _is_local(backend):
        try:
            mode = os.stat(path).st_mode
        except OSError:
            return None
        return None if _stat.S_ISREG(mode) or _stat.S_ISDIR(mode) else "special-file"
    if item is not None and getattr(item, "is_link", False):
        return "symlink"
    mode = _source_mode(backend, path)
    if mode is None:
        return None
    if _stat.S_ISLNK(mode):
        return "symlink"
    if _stat.S_ISDIR(mode) or _stat.S_ISREG(mode):
        return None
    return "special-file"


#: Characters a name taken from another machine may not bring into a local
#: name (a newline split a file's line in every listing and log).
def _unsafe_name(name: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in name)


class _WalkCap:
    """The entries a whole-tree walk (index_build, duplicates_scan) may
    visit: ``max_files``, by default 100,000 on a remote (a server that
    lists without end) and 1,000,000 locally. Reached, the walk stops and
    the result says ``truncated``."""

    REMOTE_DEFAULT = 100_000
    LOCAL_DEFAULT = 1_000_000

    def __init__(self, env, backend, args) -> None:
        remote = env.remote is not None and env.remote.holds(backend)
        default = self.REMOTE_DEFAULT if remote else self.LOCAL_DEFAULT
        self.limit = _int_arg(args, "max_files", default, 1, self.LOCAL_DEFAULT)
        self.reached = False

    def count(self, scanned) -> None:
        if int(scanned) >= self.limit:
            self.reached = True

    @staticmethod
    def prop() -> dict:
        prop = _int_prop("Visit at most this many entries; reaching it stops the walk and "
                         "sets truncated=true. Default 1,000,000 on the local backend, "
                         "100,000 on a remote one.", minimum=1, maximum=1_000_000,
                         default=1_000_000)
        prop.pop("default")  # it depends on the backend
        return prop


def _whole_or_raise(size: int, sent, backend, path: str) -> int:
    """The bytes a copy wrote to *path* on *backend* (*sent* when the copy
    counted them, else the destination's size); :class:`ShortCopy` when
    that is not the source's reported *size*."""
    got = int(sent) if sent else int(getattr(backend.stat(path), "size", 0) or 0)
    if got != int(size):
        raise ShortCopy(f"the source reported {int(size)} bytes and sent {got}; "
                        "not a complete copy")
    return got


def _sends_more_than(backend, path: str, size: int) -> bool:
    """Whether *path* has a byte past *size* (a server that reported 5
    bytes and holds 30 MiB). Seeks there; a stream that cannot seek is not
    asked (False)."""
    try:
        with backend.open_read(path) as fh:
            if not callable(getattr(fh, "seek", None)):
                return False
            fh.seek(size)
            return bool(fh.read(1))
    except (OSError, ValueError, io.UnsupportedOperation):
        return False


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

            def one(s: str, d: str, size: int, item=None) -> None:
                try:
                    d = env.write_path(d, db)
                except PermissionError as exc:
                    # A protected place (a .git hook, a shell start file):
                    # this file is left out, the rest of the tree goes on
                    # and the report says what landed and what did not.
                    record(s, d, size, "skipped", reason="protected",
                           error=redact_text(str(exc)))
                    return
                except ValueError as exc:
                    # A name the destination refuses (C:.. from a hostile
                    # listing): this entry is left out, not the whole copy.
                    record(s, d, size, "skipped", reason="unsafe-name",
                           error=redact_text(str(exc)))
                    return
                if size > max_file_bytes:
                    record(s, d, size, "skipped", reason="too-large")
                    return
                why = _special_source(sb, s, item)
                if why is not None:
                    # A symlink is followed by the server when read (/zero
                    # -> /dev/zero filled the disk), a device or FIFO never
                    # ends: only regular files are copied.
                    record(s, d, size, "skipped", reason=why)
                    return
                if not resumable and not overwrite and db.exists(d):
                    record(s, d, size, "skipped", reason="exists")
                    return
                if _is_local(sb):
                    # A local link is followed: its target's size is what
                    # the copy must bring (a listing gave the link's own).
                    try:
                        size = os.stat(s).st_size
                    except OSError:
                        pass
                ctx.check_cancel()
                # What the source really sends counts, not what it said its
                # size was; the cap and a cancel stop the copy mid-file and
                # the partial destination is removed.
                budget = _Budget(max_file_bytes)
                try:
                    _ensure_dir(db, db.parent(d))
                    if resumable:
                        report = CR.resumable_copy(
                            _CancelAwareSource(sb, ctx, budget),
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
                        if _sends_more_than(sb, s, size) or int(
                                getattr(db.stat(d), "size", 0) or 0) != size:
                            # It copied the size the source gave; the source
                            # holds more. Not a complete copy: no file.
                            _remove_quietly(db, d)
                            record(s, d, size, "error", reason="size-mismatch",
                                   error="the source sends more bytes than the size it "
                                         "reports; the copy was removed")
                            return
                        record(
                            s,
                            d,
                            size,
                            "copied",
                            bytes=report.bytes_transferred,
                            resumed_segments=report.segments_skipped,
                        )
                    elif sb is db:
                        # One backend: its own copy (the bytes never pass
                        # through here); the source is a regular file.
                        moved = S.copy(sb, s, db, d, overwrite=overwrite)
                        _whole_or_raise(size, None, db, d)
                        record(s, d, size, "copied", bytes=size)
                    else:
                        from core.server_ops import stream_copy_between_backends

                        if not overwrite and db.exists(d):
                            raise FileExistsError(d)
                        with S._mutation_gate(db, f"copy {s!r} to {d!r}"):
                            moved = stream_copy_between_backends(
                                _CancelAwareSource(sb, ctx, budget), s, db, d,
                                expected_size=size)
                        _whole_or_raise(size, moved, db, d)
                        record(s, d, size, "copied", bytes=size)
                    if _is_local(db):
                        # Files the groups create are the user's alone.
                        try:
                            os.chmod(d, 0o600)
                        except OSError:
                            pass
                except CancelledError:
                    raise
                except ShortCopy as exc:
                    # Another byte count than the source reported: the copy
                    # is removed, the entry says why (never complete).
                    _remove_quietly(db, d)
                    record(s, d, size, "error", reason="size-mismatch",
                           error=redact_text(str(exc)))
                except SourceTooLarge:
                    record(s, d, size, "skipped", reason="too-large", bytes=budget.used)
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
                one(src, dst, int(getattr(top, "size", 0) or 0), top)
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
                            if _unsafe_name(name):
                                raise ValueError("control character in the name")
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
                        one(child_src, child_dst, size, child)
                        ctx.progress(float(copied()), None, f"copied {child_src}")
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
            if sb is db and env.refuse_moved_links is not None:
                env.refuse_moved_links(src, dst, sb)  # a link is moved as the link
            ctx.check_cancel()
            _ensure_dir(db, db.parent(dst))
            if sb is db:
                moved = S.move(sb, src, db, dst, overwrite=False)  # a rename
            else:
                item = sb.stat(src)
                why = _special_source(sb, src, item)
                if why is not None:
                    raise ValueError(f"transfer_move moves regular files; {src} is a {why}")
                from core.server_ops import stream_copy_between_backends

                # The bytes the source sends count, cancellable, with the
                # size it gave plus slack as the cap.
                # The size the source says: a local link is followed (its
                # target is what is read), a remote link was refused above.
                said = int(getattr(item, "size", 0) or 0)
                if _is_local(sb):
                    try:
                        said = os.stat(src).st_size
                    except OSError:
                        pass
                budget = _Budget(said + (16 << 20))
                with S._mutation_gate(db, f"move {src!r} to {dst!r}"), \
                        S._mutation_gate(sb, f"remove {src!r} after moving it"):
                    moved = stream_copy_between_backends(
                        _CancelAwareSource(sb, ctx, budget), src, db, dst,
                        expected_size=said)
                    try:
                        # Only a whole copy lets the source go: a server that
                        # said 1 MiB and sent 10 bytes kept nothing else.
                        moved = _whole_or_raise(said, moved, db, dst)
                    except Exception:
                        _remove_quietly(db, dst)
                        raise
                    try:
                        sb.remove(src)
                    except Exception:
                        try:
                            db.remove(dst)  # the source stays: so does nothing else
                        except Exception as undo_exc:  # noqa: BLE001
                            log.warning("transfer_move: undo of %s failed: %s", dst, undo_exc)
                        raise
                if _is_local(db):
                    try:
                        os.chmod(dst, 0o600)
                    except OSError:
                        pass
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
            "description": "Backend id of the source, from list_backends, e.g. 'profile:nas'; "
            "omit for the default backend.",
        },
        "src": _path_prop(
            "Source path on src_backend (absolute, or relative to the MCP root)."
        ),
        "dst_backend": {
            "type": "string",
            "minLength": 1,
            "description": "Backend id of the destination, from list_backends; omit for the "
            "default backend.",
        },
        "dst": _path_prop(
            "Destination on dst_backend (absolute, or relative to the MCP root): the file, or "
            "for a source folder the folder that becomes its copy. Parents are created."
        ),
    }
    return [
        _tool(
            "transfer_copy",
            "Copy a file or folder tree from one backend to another, or within one.\n"
            "Use when: data must cross backends, or a big copy should be resumable.\n"
            "Instead: copy or bulk_copy within one backend; transfer_move to move one "
            "file.\n"
            "Behavior: never changes the source. Existing files are skipped unless "
            f"overwrite=true (destructive). {T.IDEMPOTENT}. Regular files only; whatever "
            "is left out gets a reason. resumable=true and the same arguments continue an "
            "interrupted run; without it a partial file starts over. Mode and mtime are "
            "not kept (new local files 0600). "
            f"{T.SECRET_TAG} {T.WRITE_TAG} Progress; cancellable.\n"
            "Returns: {src, dst, copied, truncated, complete, entries}; reasons in "
            "outputSchema.",
            {
                **ends,
                "overwrite": _bool_prop(
                    "Replace destination files that exist (false: skip them, reason exists).",
                    default=False,
                ),
                "resumable": _bool_prop(
                    "Copy in 4 MiB segments that a repeated call can resume after an "
                    "interruption.",
                    default=False,
                ),
                "max_files": _int_prop(
                    "Copy at most this many files; more sets truncated=true.",
                    minimum=1,
                    maximum=_MAX_TRANSFER_FILES,
                    default=1000,
                ),
                "max_depth": _int_prop(
                    T.descend_text("src"),
                    minimum=0,
                    maximum=50,
                    default=10,
                ),
                "max_file_bytes": _int_prop(
                    "Skip files larger than this many bytes (reason too-large), also when a "
                    "source sends more than it reported. Default 10 GiB.",
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
            "Move one file to another backend: copy, check the byte count, delete the "
            "source.\n"
            "Use when: a file must leave one backend for another.\n"
            "Instead: rename within one backend (folders too); for a folder across "
            "backends transfer_copy, then remove.\n"
            "Behavior: destructive for the source, deleted only after a complete copy. "
            f"{T.IDEMPOTENT}; it fails with 'destination exists'. An existing destination or a "
            f"folder fails. {T.SECRET_TAG} {T.WRITE_TAG}\n"
            "Returns: {src, dst, bytes}.",
            {
                **ends,
                "src": _path_prop(
                    "The source file on src_backend, not a folder (absolute, or relative to "
                    "the MCP root)."
                ),
                "dst": _path_prop(
                    "The destination file on dst_backend (absolute, or relative to the MCP "
                    "root); it must not exist. Parents are created."
                ),
            },
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
            "List the installed axross extensions (app plugins) and their state.\n"
            "Use when: asking which extensions exist, are on, or fail to load.\n"
            "Instead: extensions_info for one by id.\n"
            "Behavior: read-only; imports nothing. Extensions add app menus only, so "
            f"none runs over MCP; they are {T.PARANOID_TAG}.\n"
            f"Returns: {{allowed, why_not_runnable, extensions: [{row}]}}.",
            {},
            _list,
            group="extensions",
            accepts_backend=False,
        ),
        _tool(
            "extensions_info",
            "Show one installed axross extension by id.\n"
            "Use when: you have an id from extensions_list and need its state or error.\n"
            "Instead: extensions_list to find ids.\n"
            "Behavior: read-only; imports nothing. An unknown id fails.\n"
            "Returns: one extensions_list entry plus why_not_runnable.",
            {
                "ext_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The extension id from extensions_list, e.g. "
                    "'bundled:arcade' or 'user:my_tool'.",
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
#: remote_exec / remote_script ``timeout``: a minute below the tools' own deadline
#: (core.mcp_server's "long" class, 30 min), so a command that runs out is
#: answered as such, not cut off by the deadline first.
_MAX_EXEC_TIMEOUT = 1740


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
        timeout = args.get("timeout", 60)
        if timeout is None:
            timeout = 60
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or not 1 <= timeout <= _MAX_EXEC_TIMEOUT:
            raise ValueError(f"timeout must be a number of seconds, 1 to {_MAX_EXEC_TIMEOUT}")
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

    def env_prop(what):
        return {
            "type": "object",
            "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
            "additionalProperties": {"type": "string"},
            "description": f"Environment variables for the {what} as {{NAME: value}}, e.g. "
            "{\"LANG\": \"C\"}. On POSIX shells they are exported in the command line, so "
            "other users of the host may see the values: pass no secrets this way.",
        }

    def timeout_prop(what):
        return {
            "type": "number",
            "minimum": 1,
            "maximum": _MAX_EXEC_TIMEOUT,
            "default": 60,
            "description": f"Seconds the {what} may run (at most {_MAX_EXEC_TIMEOUT}, below "
            "the call's 30 min); longer fails with a timeout error and returns no output.",
        }
    cap_prop = _int_prop(
        "Most bytes of stdout kept; stderr keeps min(max_output, 1 MiB). truncated_stdout "
        "/ truncated_stderr tell when output was cut.",
        minimum=1,
        maximum=_MAX_EXEC_OUTPUT,
        default=1024 * 1024,
    )
    result = "{returncode, stdout, stderr, truncated_stdout, truncated_stderr} (text, UTF-8 " \
        "with undecodable bytes replaced)"
    gate = f"Requires: a backend from exec_backends; {T.PARANOID_TAG}.\n"
    return [
        _tool(
            "remote_exec",
            "Run one command line on a remote host (SSH, Telnet, ADB, WinRM, Cisco).\n"
            "Use when: a shell command is needed there (ps, df, a Cisco show).\n"
            "Instead: remote_script for scripts; the file tools for files.\n"
            f"{gate}"
            "Behavior: destructive - runs with the profile user's rights. Not idempotent: "
            "it runs again. Refused on production profiles. A non-zero exit is a result; "
            "past timeout the call fails and no output returns. "
            "Telnet and ADB mix stderr into stdout; Cisco runs show only; WinRM "
            "PowerShell.\n"
            f"Returns: {result}.",
            {
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The command line, run by the remote's shell, e.g. "
                    "'df -h /'.",
                },
                "stdin": {
                    "type": "string",
                    "description": "Text fed to the command's stdin (UTF-8); not supported on "
                    "WinRM or Cisco. Default: none.",
                },
                "env": env_prop("command"),
                "timeout": timeout_prop("command"),
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
            "Run a multi-line script on a remote host: sh, bash, python3 or perl on "
            "POSIX, PowerShell on WinRM.\n"
            "Use when: the job needs loops or a scripting language there.\n"
            "Instead: remote_exec for one command; script_run on this machine.\n"
            f"{gate}"
            "Behavior: destructive - runs with the profile user's rights. Not idempotent: "
            "it runs again. The script goes to the interpreter's stdin, so it cannot "
            "read stdin itself. Refused on production profiles and Cisco. Past timeout "
            "the call fails and no output returns.\n"
            f"Returns: {result}.",
            {
                "script": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The script text, e.g. 'for f in /var/log/*.log; do wc -l "
                    "\"$f\"; done'.",
                },
                "interpreter": {
                    "type": "string",
                    "enum": sorted([*_POSIX_INTERPRETERS, "powershell"]),
                    "description": "What runs the script. Default: sh on POSIX hosts, "
                    "powershell on WinRM (the only choice there).",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Arguments passed to the script ($1... / sys.argv[1:]) as raw "
                    "strings; the server shell-quotes each one. POSIX hosts only. Default: none.",
                },
                "env": env_prop("script"),
                "timeout": timeout_prop("script"),
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
            "List the open backends that can run commands.\n"
            "Use when: choosing remote_exec's or remote_script's backend.\n"
            "Instead: list_backends for all; remote_open to open more.\n"
            "Behavior: read-only; runs and opens nothing.\n"
            f"Returns: {{backends: [{{backend, {T.CLASS_TEXT}, kind: posix-shell, powershell "
            "(WinRM) or ios-show (Cisco IOS, show commands only)}]}.",
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
#: What each group gives agent_run's model: its tools that need no
#: --mcp-write (tests/test_mcp_tool_quality.py holds it to the real groups).
AGENT_GROUP_TOOLS = {
    "metadata": ("metadata_read", "metadata_export"),
    "duplicates": ("duplicates_scan", "duplicates_scans", "duplicates_groups"),
    "packer": ("pack_formats",),
    "archive": ("archive_list",),
    "index": ("index_build",),
    "filetype": ("file_type", "file_type_scan"),
    "remote": ("remote_profiles", "remote_open", "remote_close", "list_backends"),
    "extensions": ("extensions_list", "extensions_info"),
}


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
            known = ", ".join(repr(p.name) for p in settings.profiles) or "none"
            raise ValueError(
                f"no LLM profile named {name!r}; the profiles: {known}" if name else
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
            "Hand a task to the user's own LLM profile, which works with axross tools "
            "that write no files and answers in text.\n"
            "Use when: file contents should stay with the user's model, e.g. a local "
            "one.\n"
            "Instead: read_file or grep directly - faster, when the contents may reach "
            "you.\n"
            "Requires: an LLM profile set up in the axross app (an unknown name's error "
            "lists them).\n"
            "Behavior: does not write files itself; sends file contents to the "
            "configured LLM, so it is not read-only. Its model gets the groups' tools that "
            "need no --mcp-write, inside the MCP root. Not idempotent: it asks again. "
            "Stops after max_steps; cancellable.\n"
            "Returns: {answer, stopped (answered|max_steps|cancelled), calls, profile, "
            "model}.",
            {
                "task": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 20000,
                    "description": "What the model should do, in plain language, e.g. "
                    "'Summarise the PDFs in reports/2024 in five bullet points'.",
                },
                "profile": {
                    "type": "string",
                    "description": "Name of an LLM profile set up in the axross app. No tool "
                    "lists them: omit it for the active profile, the usual choice. An unknown "
                    "name fails.",
                },
                "groups": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(AGENT_GROUPS)},
                    "description": "Extra groups for the model, each with its tools that need "
                    "no --mcp-write: " + "; ".join(
                        f"{g} ({', '.join(AGENT_GROUP_TOOLS[g])})" for g in AGENT_GROUPS)
                    + ". remote and extensions fail unless this server runs with them. "
                    "Default: none (the core file tools only).",
                },
                "max_steps": _int_prop(
                    "Most model requests for this task; reaching it ends with "
                    "stopped=max_steps.",
                    minimum=1,
                    maximum=30,
                    default=10,
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
        try:
            built = builder(env)
        except ImportError as exc:
            # A package the group needs is missing (crypto without
            # cryptography): the group is left out with one clear line,
            # the server and every other group still start.
            missing = getattr(exc, "name", None) or str(exc)
            if group not in _MISSING_GROUPS:
                _MISSING_GROUPS[group] = str(missing)
                message = (f"MCP tool group {group!r} left out: it needs the Python package "
                           f"{missing!r} (pip install {missing})")
                log.warning("%s", message)
                print(f"axross MCP: {message}", file=sys.stderr)
            continue
        # exec's tools are mutating but gated by their own flag, not --mcp-write
        tools.extend(
            t for t in built if env.allow_write or not t.write or t.group == "exec"
        )
    return tools


#: Groups asked for but left out, with the package each one lacked.
_MISSING_GROUPS: dict[str, str] = {}


def missing_groups() -> dict[str, str]:
    return dict(_MISSING_GROUPS)


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
    from core.mcp_server import (
        PROTOCOL_VERSION,
        SERVER_NAME,
        SUPPORTED_PROTOCOL_VERSIONS,
        TIMEOUT_CLASSES,
    )

    descriptions = {**BASE_GROUP_DESCRIPTIONS, **GROUP_DESCRIPTIONS}
    order = ["core", "write", "scripts", *GROUPS]
    present = [g for g in order if any(t.group == g for t in tools)]
    return {
        "server": SERVER_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
        "generated_for": {
            "mcp_tools": sorted(check_groups(groups)),
            "mcp_write": bool(allow_write),
            "mcp_allow_scripts": bool(allow_scripts),
            "mcp_allow_exec": bool(allow_exec),
        },
        "timeout_classes": dict(TIMEOUT_CLASSES),
        # The rules every tool shares (the initialize instructions carry them;
        # a description names one with a short tag only).
        "rules": list(T.RULES),
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
                "title": t.title,
                "group": t.group,
                "mutating": bool(t.write),
                "required_flags": _required_flags(t),
                "transports": ["stdio"] if t.group == "scripts" else ["stdio", "http"],
                "timeout_class": t.timeout_class,
                "timeout_seconds": t.timeout_seconds,
                "description": t.description,
                "annotations": t.annotations,
                "input_schema": t.schema,
                **({"output_schema": t.output_schema} if t.output_schema is not None else {}),
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
