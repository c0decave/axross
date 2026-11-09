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
records the SHA-256 of its script and - for a Python script - the names and
hashes of the module files in the script's folder (``*.py``, ``*.pyc``,
extension modules, packages; bounded: :data:`MAX_NAMES` names,
:data:`MAX_FILES` files and :data:`MAX_BYTES` bytes hashed, the rest by size
and change time). At start :func:`start_problem` compares; a changed, new or
missing file stops the start until the user looks and confirms the files
again (Agent Settings → MCP Servers → Confirm files).

Beside it :func:`write_guard` makes these files protected places for the
agent's and the MCP server's writes (core.protected_places): the pinned
files of every enabled host-run server of the saved settings, and any new
module file in a pinned Python script's folder.

A script of the system (owned by root, no one else may write it, e.g. a
packaged ``/usr/lib/…/server.py``) and ``python -m <package>`` (an installed
package: ``~/.local/lib`` is a protected place) are not pinned.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat

#: At most this many names of a Python script's folder are listed.
MAX_NAMES = 4096
#: At most this many of its module files are hashed (the rest: size and time).
MAX_FILES = 256
#: At most this many bytes are hashed in all.
MAX_BYTES = 64 * 1024 * 1024
_CHUNK = 1024 * 1024
#: Where the system's packages put files (run as root, only these count as
#: the system's: root's other files are the user's own).
_SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/nix/store/",
                    "/snap/", "/System/", "/Library/")


def _suffixes() -> tuple[str, ...]:
    import importlib.machinery as machinery

    return tuple(sorted(set(machinery.all_suffixes()) | {".py", ".pyc", ".pyw", ".pyd", ".so"},
                        key=len, reverse=True))


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
    absolute path (a trusted server); never a file of the system."""
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
    if not os.path.isfile(path) or _system_file(path):
        return None
    return os.path.abspath(path), python


def _digest(path: str, budget: list[int]) -> str:
    """``sha256:<hex>`` of the regular file *path* (opened without
    following a final symlink's FIFO or device: no wait), ``size:<n>:<ns>``
    beyond the byte budget, ``missing`` / ``not-a-file``."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return "missing"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "not-a-file"
        if st.st_size > budget[0]:
            return f"size:{st.st_size}:{st.st_mtime_ns}"
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            h.update(chunk)
            budget[0] -= len(chunk)
        return "sha256:" + h.hexdigest()
    finally:
        os.close(fd)


def _module_entries(folder: str) -> tuple[list[str], bool]:
    """The module files of *folder* (sorted paths, a package by its
    ``__init__``), and whether that is all of them."""
    suffixes = _suffixes()
    out: list[str] = []
    complete = True
    try:
        with os.scandir(folder) as entries:
            names = []
            for entry in entries:
                if len(names) >= MAX_NAMES:
                    complete = False
                    break
                names.append(entry)
    except OSError:
        return [], True
    for entry in sorted(names, key=lambda e: e.name):
        try:
            is_dir = entry.is_dir(follow_symlinks=True)
        except OSError:
            is_dir = False
        if is_dir:
            try:
                inits = sorted(n for n in os.listdir(entry.path)
                               if n.startswith("__init__.") and n.endswith(suffixes))
            except OSError:
                continue
            out.extend(os.path.join(entry.path, n) for n in inits[:4])
        elif entry.name.endswith(suffixes):
            out.append(entry.path)
    return out, complete


def compute(command) -> dict:
    """The pin of the server line *command* now ({} = nothing to pin)."""
    found = target(command)
    if found is None:
        return {}
    script, python = found
    budget = [MAX_BYTES]
    files = {script: _digest(script, budget)}
    complete = True
    if python:
        entries, complete = _module_entries(os.path.dirname(script))
        for i, path in enumerate(entries):
            if path in files:
                continue
            if i >= MAX_FILES:
                try:
                    st = os.stat(path)
                    files[path] = f"size:{st.st_size}:{st.st_mtime_ns}"
                except OSError:
                    files[path] = "missing"
                complete = False
                continue
            files[path] = _digest(path, budget)
    return {"command": [str(w) for w in command], "files": files, "python": python,
            "complete": complete}


def clean(raw) -> dict:
    """A pin read from the settings file, checked ({} when invalid)."""
    if not isinstance(raw, dict):
        return {}
    command, files = raw.get("command"), raw.get("files")
    if not (isinstance(command, list) and all(isinstance(w, str) for w in command)
            and isinstance(files, dict) and len(files) <= MAX_NAMES + 1
            and all(isinstance(k, str) and isinstance(v, str) and len(v) < 200
                    for k, v in files.items())):
        return {}
    return {"command": list(command), "files": dict(files),
            "python": raw.get("python") is True, "complete": raw.get("complete") is not False}


def needs_pin(config) -> bool:
    """*config* runs a file of the user's on this machine: it is pinned."""
    return host_run(config) and target(config.command) is not None


def current(config) -> bool:
    """*config*'s pin is for its server line as it is now (else the user
    changed the line, and saving it pins it anew)."""
    pin = getattr(config, "pin", None) or {}
    return bool(pin) and pin.get("command") == [str(w) for w in config.command]


def changed(config) -> list[str]:
    """The pinned files of *config* that differ now - changed, new or gone
    (paths)."""
    pin = getattr(config, "pin", None) or {}
    now = compute(config.command)
    old_files, new_files = pin.get("files", {}), now.get("files", {})
    out = [p for p in sorted(set(old_files) | set(new_files))
           if old_files.get(p) != new_files.get(p)]
    return out


def start_check(config) -> tuple[str, list[str]]:
    """Why the host-run server *config* may not start now, and the files
    (paths) it is about: ("", []) = it may. Its files were never confirmed,
    or changed since - the user decides (core.mcp_client.McpFilesChanged:
    axross asks; Agent Settings → MCP Servers → Confirm files)."""
    if not needs_pin(config):
        return "", []
    from core.i18n import tr
    from core.mcp_catalog import clean_text

    if not current(config):
        script = target(config.command)[0]
        return tr("the files it runs on this machine ({file}) were not confirmed yet – if "
                  "they are yours, confirm them when axross asks or with Confirm files in "
                  "Agent Settings → MCP Servers").format(file=clean_text(script, 120)), [script]
    diff = changed(config)
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


def _protected_of(path: str) -> tuple[list[str], list[str]]:
    """(pinned files, folders of pinned Python scripts) of the enabled
    host-run servers in the settings file *path* - cached by its identity."""
    try:
        st = os.stat(path)
    except OSError:
        return [], []
    ident = (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns)
    held = _GUARD_CACHE.get(path)
    if held is not None and held[0] == ident:
        return held[1]
    files: list[str] = []
    folders: list[str] = []
    try:
        if st.st_size > 16 * 1024 * 1024:
            raise ValueError("too large")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        servers = data.get("mcp_servers") if isinstance(data, dict) else None
    except (OSError, ValueError, RecursionError):
        servers = None
    from types import SimpleNamespace

    for raw in servers if isinstance(servers, list) else ():
        if not isinstance(raw, dict) or raw.get("enabled") is False:
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
        files.extend(pin.get("files", {}))
        try:
            found = target(command)
        except Exception:  # noqa: BLE001 - a guard never fails a check
            found = None
        if found is not None:
            files.append(found[0])
            if found[1]:
                folders.append(os.path.dirname(found[0]))
        elif pin.get("python") and pin.get("files"):
            folders.append(os.path.dirname(next(iter(pin["files"]))))
    result = (sorted(set(files)), sorted(set(folders)))
    _GUARD_CACHE[path] = (ident, result)
    return result


def write_guard(environ=os.environ):
    """A check for core.protected_places: path, entry -> a refusal or None.
    Refused: a pinned file of an enabled host-run server (as written or
    resolved), a new module file in its Python script's folder, and, as an
    entry (moved, removed), that folder."""
    from core.protected_places import _key

    files: set[tuple[str, ...]] = set()
    folders: list[tuple[str, ...]] = []
    for settings in _settings_files(environ):
        pinned, dirs = _protected_of(settings)
        for p in pinned:
            files |= {_key(p), _key(os.path.realpath(p))}
        for d in dirs:
            folders.extend({_key(d), _key(os.path.realpath(d))})
    if not files and not folders:
        return lambda path, entry=False: None
    suffixes = _suffixes()

    def check(path: str, entry: bool = False) -> str | None:
        ck = _key(path)
        name = os.path.basename(path).lower()
        module = name.endswith(suffixes)
        hit = ck in files or (module and ck[:-1] in folders) \
            or (module and name.startswith("__init__.") and ck[:-2] in folders) \
            or (entry and any(len(ck) <= len(f) and f[:len(ck)] == ck for f in folders))
        if not hit:
            return None
        return (f"{path}: the agent does not change the files an MCP server runs on this "
                "machine (Agent Settings → MCP Servers): axross would run them with your "
                "rights at the server's next start")

    return check
