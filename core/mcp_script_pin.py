"""The files a host-run MCP server runs, pinned by their SHA-256.

A stdio server that runs on this machine as it is (no sandbox profile, no
container: a pure launcher such as ``python3 ~/projects/my-mcp/server.py``,
or a server marked trusted) runs its script with the user's rights at each
start. An agent allowed to change files under the MCP root could rewrite
that script - or put a ``json.py`` beside it, which Python imports before
its own (the script's folder comes first on the import path) - and axross
would run it at the server's next start, outside the agent's sandbox.

So the user's confirmation of a server covers its files: when a host-run
server is saved in Agent Settings (or confirmed again there), :func:`compute`
walks the whole folder of its file (the script, else the program) and
records the SHA-256 of every file in it - every sub-folder, ``__pycache__``,
``node_modules`` and data files included (a server may load code from any
of them: ``import pkg.util``, ``require('./lib.js')``, a ``.pyc``). The walk
is bounded (:data:`MAX_FILES` entries, :data:`MAX_BYTES` bytes hashed,
:data:`MAX_DEPTH` levels); one that does not see all of the folder is
incomplete, and a server whose files cannot all be pinned does not start
(put it in a folder of its own). At start :func:`start_problem` compares; a
changed, new or missing file stops the start until the user looks and
confirms the files again (Agent Settings → MCP Servers → Confirm files).

Beside it :func:`write_guard` makes these folders protected places for the
agent's and the MCP server's writes (core.protected_places): nothing below
the folder of an enabled host-run server is written, created, moved or
removed (and folders on symlinks the walk followed count as well) - for
a Node server neither anything in a ``node_modules`` folder above it,
where Node looks a module up that its own folder lacks.
core.mcp_client starts a Python server with a private
``PYTHONPYCACHEPREFIX`` (a protected place), so it never loads byte code
from its folder.

A script of the system (owned by root, no one else may write it, e.g. a
packaged ``/usr/lib/…/server.py``) and ``python -m <package>`` (an installed
package: ``~/.local/lib`` is a protected place) are not pinned.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat

#: At most this many entries (files and folders) of a server's folder are
#: walked; a folder with more is not pinned completely: the server does not start.
MAX_FILES = 10000
#: Kept for settings of older versions (their pins held module names only).
MAX_NAMES = MAX_FILES
#: At most this many bytes are hashed in all (more: incomplete).
MAX_BYTES = 256 * 1024 * 1024
#: At most this many folder levels below the server's folder (more: incomplete).
MAX_DEPTH = 32
#: A pin read from the settings file holds at most this many files.
_PIN_FILES = 4 * 10000
_CHUNK = 1024 * 1024
#: Where the system's packages put files (run as root, only these count as
#: the system's: root's other files are the user's own).
_SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/nix/store/",
                    "/snap/", "/System/", "/Library/")


def host_run(config) -> bool:
    """*config* (core.mcp_client.McpServerConfig) runs on this machine as it
    is: a stdio program with no container and no sandbox profile."""
    return (getattr(config, "transport", "") == "stdio" and bool(getattr(config, "command", ()))
            and not getattr(config, "container", False) and not getattr(config, "sandbox", ""))


def _system_file(path: str) -> bool:
    from core.mcp_runner import _system_owned
    from core.posix_compat import effective_uid

    uid = effective_uid()
    if uid is None:
        return False  # no owners to read (Windows): pinned
    real = os.path.realpath(path)
    if uid == 0 and not real.startswith(_SYSTEM_PREFIXES):
        return False  # run as root, root's files are the user's own
    return _system_owned(real)


def target(command) -> tuple[str, bool] | None:
    """(the file the server line *command* runs, whether Python runs it),
    or None for nothing to pin: the script of a pure launcher
    (core.mcp_runner.launcher_script), else a program given by its
    absolute path (a trusted server); never a file of the system, nor
    axross's own (its ``main.py``: whoever changes that folder changes the
    axross that runs this check)."""
    from core.mcp_runner import _PYTHONS, _absolute, _program, launcher_script

    words = [str(w) for w in (command or ())]
    if not words:
        return None
    script = launcher_script(words)
    if script:
        path, python = script, bool(_PYTHONS.fullmatch(_program(words)))
    elif script is None and _absolute(words[0]):
        path, python = words[0], False
    else:
        return None
    if not os.path.isfile(path) or _system_file(path) or _own_file(path):
        return None
    return os.path.abspath(path), python


def _own_file(path: str) -> bool:
    """*path* is a file of the axross that runs (its source folder)."""
    own = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    return os.path.dirname(os.path.realpath(path)) == own


_DIGESTS: dict = {}


def _digest(path: str, budget: list[int]) -> str:
    """``sha256:<hex>`` of the regular file *path* (opened without
    following a final symlink's FIFO or device: no wait), ``size:<n>:<ns>``
    beyond the byte budget, ``missing`` / ``not-a-file``. A file whose
    identity, size and change times are as at its last hash is not read
    again (the change time cannot be set back by its owner)."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        st = os.stat(path)
    except OSError:
        return "missing"
    if not stat.S_ISREG(st.st_mode):
        return "not-a-file"  # never opened: a FIFO, a device
    try:
        fd = os.open(path, flags)
    except OSError:
        return "missing"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "not-a-file"
        ident = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if st.st_size > budget[0]:
            return f"size:{st.st_size}:{st.st_mtime_ns}"
        held = _DIGESTS.get(ident)
        if held is not None:
            budget[0] -= st.st_size
            return held
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            h.update(chunk)
            budget[0] -= len(chunk)
        value = "sha256:" + h.hexdigest()
        if len(_DIGESTS) > 4 * MAX_FILES:
            _DIGESTS.clear()
        _DIGESTS[ident] = value
        return value
    finally:
        os.close(fd)


def _link(path: str) -> str:
    """``link:<sha256 of the symlink's text>`` (bounded: a pin value)."""
    try:
        text = os.readlink(path)
    except OSError:
        text = ""
    return "link:" + hashlib.sha256(os.fsencode(text)).hexdigest()[:32]


def walk(folder: str, budget: list[int]) -> tuple[dict, list[str], bool]:
    """(path -> pin value of every file below *folder*, the real folders
    walked, whether that is all of it). Symlinked folders are followed
    (each real folder once: no loops); a folder that cannot be listed, too
    many entries (:data:`MAX_FILES`), levels (:data:`MAX_DEPTH`) or bytes
    (*budget*) make it incomplete."""
    files: dict[str, str] = {}
    roots: list[str] = [os.path.realpath(folder)]
    seen: set[tuple[int, int]] = set()
    complete = True
    count = 0
    stack = [(folder, 0)]
    while stack:
        here, depth = stack.pop()
        try:
            st = os.stat(here)
        except OSError:
            complete = False
            continue
        if (st.st_dev, st.st_ino) in seen:
            continue
        seen.add((st.st_dev, st.st_ino))
        entries = []
        try:
            with os.scandir(here) as listing:
                for entry in listing:
                    if count + len(entries) >= MAX_FILES:
                        complete = False
                        break
                    entries.append(entry)
        except OSError:
            complete = False
            continue
        count += len(entries)
        for entry in sorted(entries, key=lambda e: e.name):
            path = entry.path
            try:
                is_link = entry.is_symlink()
                is_dir = entry.is_dir(follow_symlinks=True)
            except OSError:
                is_link, is_dir = False, False
            if is_dir:
                if is_link:
                    files[path] = _link(path)
                    real = os.path.realpath(path)
                    if real not in roots:
                        roots.append(real)
                if depth + 1 > MAX_DEPTH:
                    complete = False
                    continue
                stack.append((path, depth + 1))
                continue
            value = _digest(path, budget)
            if value.startswith("size:"):
                complete = False
            if is_link:
                value = _link(path) + ";" + value
            files[path] = value
    return files, roots, complete


def compute(command) -> dict:
    """The pin of the server line *command* now ({} = nothing to pin): its
    file and every file of the (real) folder it lies in."""
    found = target(command)
    if found is None:
        return {}
    script, python = found
    budget = [MAX_BYTES]
    files = {script: _digest(script, budget)}
    complete = not files[script].startswith("size:")
    walked, roots, whole = walk(os.path.dirname(os.path.realpath(script)), budget)
    for path, value in walked.items():
        files.setdefault(path, value)
    return {"command": [str(w) for w in command], "files": files, "python": python,
            "complete": complete and whole, "roots": roots}


def clean(raw) -> dict:
    """A pin read from the settings file, checked ({} when invalid)."""
    if not isinstance(raw, dict):
        return {}
    command, files = raw.get("command"), raw.get("files")
    if not (isinstance(command, list) and all(isinstance(w, str) for w in command)
            and isinstance(files, dict) and len(files) <= _PIN_FILES
            and all(isinstance(k, str) and isinstance(v, str) and len(v) < 200
                    for k, v in files.items())):
        return {}
    roots = raw.get("roots")
    roots = [r for r in roots if isinstance(r, str) and os.path.isabs(r)][:_PIN_FILES] \
        if isinstance(roots, list) else []
    return {"command": list(command), "files": dict(files),
            "python": raw.get("python") is True, "complete": raw.get("complete") is not False,
            "roots": roots}


def needs_pin(config) -> bool:
    """*config* runs a file of the user's on this machine: it is pinned."""
    return host_run(config) and target(config.command) is not None


def current(config) -> bool:
    """*config*'s pin is for its server line as it is now (else the user
    changed the line, and saving it pins it anew)."""
    pin = getattr(config, "pin", None) or {}
    return bool(pin) and pin.get("command") == [str(w) for w in config.command]


def changed(config, now: dict | None = None) -> list[str]:
    """The pinned files of *config* that differ now - changed, new or gone
    (paths). *now*: its :func:`compute` already made."""
    pin = getattr(config, "pin", None) or {}
    if now is None:
        now = compute(config.command)
    old_files, new_files = pin.get("files", {}), now.get("files", {})
    out = [p for p in sorted(set(old_files) | set(new_files))
           if old_files.get(p) != new_files.get(p)]
    return out


def start_check(config) -> tuple[str, list[str]]:
    """Why the host-run server *config* may not start now, and the files
    (paths) it is about: ("", []) = it may. Its files were never confirmed,
    or changed since - the user decides (core.mcp_client.McpFilesChanged:
    axross asks; Agent Settings → MCP Servers → Confirm files). Its folder
    holds more than the walk can pin: ("why", []) - it does not start."""
    if not needs_pin(config):
        return "", []
    from core.i18n import tr
    from core.mcp_catalog import clean_text

    script = target(config.command)[0]
    if not current(config):
        return tr("the files it runs on this machine ({file}) were not confirmed yet – if "
                  "they are yours, confirm them when axross asks or with Confirm files in "
                  "Agent Settings → MCP Servers").format(file=clean_text(script, 120)), [script]
    now = compute(config.command)
    if not now.get("complete", False):
        return tr("the folder of the files it runs on this machine ({folder}) holds more than "
                  "axross can check at each start (more than {count} entries, {size} MB or "
                  "{depth} levels, or a folder it cannot read) – it runs every file there, "
                  "so put the server in a folder of its own").format(
            folder=clean_text(os.path.dirname(os.path.realpath(script)), 120),
            count=MAX_FILES, size=MAX_BYTES // (1024 * 1024), depth=MAX_DEPTH), []
    diff = changed(config, now)
    if not diff and not config.pin.get("complete", True):
        diff = [script]  # confirmed when it could not all be pinned: confirmed again
    if not diff:
        return "", []
    shown = ", ".join(clean_text(p, 120) for p in diff[:3]) + (" …" if len(diff) > 3 else "")
    return tr("the files it runs on this machine changed since you confirmed them ({files}) – "
              "if you changed them yourself, confirm them when axross asks or with Confirm "
              "files in Agent Settings → MCP Servers").format(files=shown), diff


def start_problem(config) -> str:
    """:func:`start_check`'s reason alone."""
    return start_check(config)[0]


def pinned(config):
    """*config* with the files it runs pinned as they are now - the caller
    confirms them (a server made in code, not in Agent Settings); returned
    for chaining."""
    config.pin = compute(config.command) if needs_pin(config) else {}
    return config


def confirm(settings, name: str) -> bool:
    """Pin the files of the server *name* of *settings* (core.agent_settings
    .AgentSettings) as they are now - the user said so; False when there
    is no such server to pin."""
    for server in settings.mcp_servers:
        if server.name == name and needs_pin(server):
            server.pin = compute(server.command)
            return True
    return False


# -- protected places -----------------------------------------------------------------------


_GUARD_CACHE: dict = {}


def _settings_files(environ) -> list[str]:
    from core.protected_places import homes

    out = []
    for home in homes(environ):
        path = os.path.join(home, ".config", "axross", "agent", "settings.json")
        if path not in out:
            out.append(path)
    return out


def _protected_of(path: str) -> list[tuple[str, bool, list[str], list[str]]]:
    """(server name, enabled, pinned files, folders) of each host-run server
    in the settings file *path* - cached by its identity. The folders are
    the walked ones of its pin (a pin that could not hold all of them:
    none, its files alone), else the folder of its file."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    ident = (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns)
    held = _GUARD_CACHE.get(path)
    if held is not None and held[0] == ident:
        return held[1]
    try:
        if st.st_size > 16 * 1024 * 1024:
            raise ValueError("too large")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        servers = data.get("mcp_servers") if isinstance(data, dict) else None
    except (OSError, ValueError, RecursionError):
        servers = None
    from types import SimpleNamespace

    result = []
    for raw in servers if isinstance(servers, list) else ():
        if not isinstance(raw, dict):
            continue
        command = raw.get("command")
        if not (isinstance(command, list) and all(isinstance(w, str) for w in command)):
            continue
        config = SimpleNamespace(transport=raw.get("transport", "stdio"), command=tuple(command),
                                 container=raw.get("container") is True,
                                 sandbox=raw.get("sandbox") if isinstance(raw.get("sandbox"),
                                                                          str) else "")
        if not host_run(config):
            continue
        pin = clean(raw.get("pin"))
        files = list(pin.get("files", {}))
        try:
            found = target(command)
        except Exception:  # noqa: BLE001 - a guard never fails a check
            found = None
        folders: list[str] = []
        if pin and not pin.get("complete"):
            pass  # it does not start (core.mcp_client): its files alone
        elif pin.get("roots"):
            folders = list(pin["roots"])
        elif found is not None:
            folders = [os.path.dirname(os.path.realpath(found[0]))]
        elif files:
            folders = [os.path.dirname(os.path.realpath(files[0]))]
        if found is not None:
            files.append(found[0])
        if folders and _node(command, found):
            folders += _node_modules_above(folders)
        if folders:
            # A file below a protected folder needs no entry of its own (a
            # walked tree holds thousands: each would be resolved per check).
            inside = tuple(os.path.join(f, "") for f in folders)
            files = [f for f in files if not f.startswith(inside)]
        name = raw.get("name") if isinstance(raw.get("name"), str) else ""
        result.append((name, raw.get("enabled") is not False, sorted(set(files)),
                       sorted(set(folders))))
    _GUARD_CACHE[path] = (ident, result)
    return result


#: The suffixes of the scripts Node runs.
_NODE_SUFFIXES = (".js", ".mjs", ".cjs")


def _node(command, found) -> bool:
    """The server line *command* (its pinned file *found*) runs a Node script."""
    from core.mcp_runner import _NODES, _program

    words = [str(w) for w in command or ()]
    return bool(words) and (_program(words) in _NODES or (
        found is not None and found[0].lower().endswith(_NODE_SUFFIXES)))


def _node_modules_above(folders: list[str]) -> list[str]:
    """``node_modules`` of every folder above *folders* (as written and
    resolved): Node looks a ``require('x')`` up there when the server's
    own folder has no ``x`` - a monorepo keeps all its packages there."""
    out: list[str] = []
    for folder in folders:
        for start in dict.fromkeys((os.path.abspath(folder), os.path.realpath(folder))):
            here = os.path.dirname(start)
            while True:
                candidate = os.path.join(here, "node_modules")
                if candidate not in out:
                    out.append(candidate)
                parent = os.path.dirname(here)
                if parent == here:
                    break
                here = parent
    return out


def _places(environ, *, enabled_only: bool):
    """[(server name, file keys, folder keys)] of the host-run servers of
    the saved settings (as written and resolved)."""
    from core.protected_places import _key

    out = []
    for settings in _settings_files(environ):
        for name, enabled, pinned_files, dirs in _protected_of(settings):
            if enabled_only and not enabled:
                continue
            files: set[tuple[str, ...]] = set()
            folders: set[tuple[str, ...]] = set()
            for p in pinned_files:
                files |= {_key(p), _key(os.path.realpath(p))}
            for d in dirs:
                folders |= {_key(d), _key(os.path.realpath(d))}
            if files or folders:
                out.append((name, files, list(folders)))
    return out


def guarded_paths(environ=os.environ) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of what :func:`write_guard` keeps from the
    agent: the folders of the enabled host-run servers (with a Node
    server's ``node_modules`` above it) and their pinned files outside
    them, as written and resolved - core.agent_sandbox mounts them
    read-only. A file only where it exists."""
    out: dict[str, bool] = {}
    for settings in _settings_files(environ):
        for _name, enabled, pinned_files, dirs in _protected_of(settings):
            if not enabled:
                continue
            for folder in dirs:
                for path in (os.path.abspath(folder), os.path.realpath(folder)):
                    out.setdefault(path, True)
            for file in pinned_files:
                for path in (os.path.abspath(file), os.path.realpath(file)):
                    if os.path.lexists(path):
                        out.setdefault(path, False)
    return list(out.items())


def _owner_in(places, path: str, entry: bool) -> str | None:
    from core.protected_places import _key

    ck = _key(path)
    for name, files, folders in places:
        if ck in files or any(ck[:len(f)] == f for f in folders) \
                or (entry and any(len(ck) <= len(f) and f[:len(ck)] == ck for f in folders)):
            return name
    return None


def owner(path: str, environ=os.environ) -> str | None:
    """The name of the host-run MCP server of the saved settings (enabled
    or not) that runs *path* - a file in its folder, as written or resolved
    - or None."""
    places = _places(environ, enabled_only=False)
    if not places:
        return None
    for candidate in dict.fromkeys((os.path.abspath(path), os.path.realpath(path))):
        found = _owner_in(places, candidate, False)
        if found is not None:
            return found
    return None


def owner_note(name: str) -> str:
    """What changing a file of the host-run MCP server *name* means."""
    from core.i18n import tr
    from core.mcp_catalog import clean_text

    return tr("This file belongs to the MCP server {name}, which runs on this machine with "
              "your rights: what is written here runs at the server's next start.").format(
        name=clean_text(name, 80) or "?")


def write_guard(environ=os.environ):
    """A check for core.protected_places: path, entry -> a refusal or None.
    Refused: anything below the folder of an enabled host-run server (the
    folders its pin walked; as written or resolved) and its pinned files,
    and, as an entry (moved, removed), a folder that holds one."""
    places = _places(environ, enabled_only=True)
    if not places:
        return lambda path, entry=False: None

    def check(path: str, entry: bool = False) -> str | None:
        name = _owner_in(places, path, entry)
        if name is None:
            return None
        from core.mcp_catalog import clean_text

        return (f"{path}: this file belongs to the MCP server {clean_text(name, 80)!r}, which "
                "runs on this machine (Agent Settings → MCP Servers): the agent does not "
                "change the files an MCP server runs - axross would run them with your rights "
                "at the server's next start")

    return check
