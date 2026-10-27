"""Extensions: Python plugins that add menu entries, context actions and
panels to axross.

Where they live
---------------
* ``~/.config/axross/extensions/<name>.py`` or ``.../<name>/__init__.py``
  - the user's own (``user:<name>``).
* ``resources/extensions/`` inside axross - the bundled examples
  (``bundled:<name>``).

What one looks like
-------------------
::

    EXTENSION = {
        "name": "Hello",
        "version": "1.0",
        "description": "Says hello.",
        "author": "you",
    }

    def activate(api):          # required
        api.add_menu_action("Say Hello", lambda: api.notify("Hello"))

    def deactivate(api):        # optional; what api registered goes anyway
        ...

``api`` is :class:`ui.extension_host.ExtensionAPI`; its ``axross``
attribute is the whole scripting API.

Trust
-----
An extension runs inside axross with the user's rights, like a script.
So nothing of it runs before the user switched it on (Extensions >
Manage Extensions…): finding one parses its source with :mod:`ast` and
reads the ``EXTENSION`` literal, it never imports the file. Every
extension starts switched off, the bundled examples included, and the
paranoid security mode (which blocks scripts) blocks all of them.

Startup guard
-------------
Before the host runs an extension's code it writes a marker (extension,
pid, time) to a private state folder and removes it when ``activate``
returned or raised (:func:`begin_activation` / :func:`end_activation`). A
marker whose process is gone - it hung and was killed, or crashed, inside
that code - or one that has been activating for longer than the startup
watchdog's bound, is found by the next start
(:func:`collect_stale_activations`): that extension is *suspended*, i.e.
stays switched on but is not loaded at the start until the user tries it
again (``suspended`` in extensions.json). ``--safe-mode``
(:func:`set_safe_mode`) loads no extension at the start at all.

This module is Qt-free: discovery, the on/off state and the startup guard.
Loading and the API live in :mod:`ui.extension_host`.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from core.startup_guard import WATCHDOG_SECONDS

log = logging.getLogger(__name__)

#: An activation running longer than this counts as hung: the startup
#: watchdog reports a window missing after the same time.
HUNG_ACTIVATION_SECONDS = WATCHDOG_SECONDS
#: An activation taking longer than this is logged as a warning. Measured:
#: the slowest bundled extension (Media Player, it builds a QAudioDecoder)
#: takes about 0.24 s, all others under 0.02 s.
SLOW_ACTIVATE_SECONDS = 1.0
_MARKER_NAME = re.compile(r"^(\d{1,10})\.json$")
#: --safe-mode of this process (main.py sets it).
_SAFE_MODE = False
#: (ext_id, name, monotonic start) of the activation running right now.
_CURRENT: tuple[str, str, float] | None = None

#: A source file larger than this is not even parsed.
MAX_SOURCE_BYTES = 512 * 1024
#: Manifest text fields are cut to this length.
MAX_FIELD_CHARS = 300
_FIELDS = ("name", "version", "description", "author")


@dataclass(frozen=True)
class ExtensionInfo:
    ext_id: str  # "user:<name>" or "bundled:<name>"
    source: str  # "user" or "bundled"
    module_name: str
    path: str  # the file holding EXTENSION / activate()
    name: str = ""
    version: str = ""
    description: str = ""
    author: str = ""
    error: str = ""  # why it cannot be loaded; "" when it can


def extensions_dir() -> Path:
    """The user's extension folder (it may not exist yet)."""
    return Path.home() / ".config" / "axross" / "extensions"


def bundled_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "resources" / "extensions"


def settings_file() -> Path:
    return Path.home() / ".config" / "axross" / "extensions.json"


def extensions_allowed() -> bool:
    """Extensions are code: the security mode that blocks scripts blocks
    them too."""
    from core.security_mode import current_policy

    return bool(current_policy().allow_scripts)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _candidates(folder: Path) -> list[tuple[str, Path]]:
    """``(module name, file)`` pairs in *folder*: ``name.py`` files and
    ``name/__init__.py`` packages. Hidden and private names, caches and
    symlinks are skipped: a link could point the loader anywhere."""
    out: list[tuple[str, Path]] = []
    try:
        entries = sorted(folder.iterdir())
    except OSError:
        return out
    for entry in entries:
        name = entry.name
        if name.startswith((".", "_")) or entry.is_symlink():
            continue
        if entry.is_file() and name.endswith(".py"):
            stem = name[:-3]
            if stem.isidentifier():
                out.append((stem, entry))
        elif entry.is_dir() and name.isidentifier():
            init = entry / "__init__.py"
            if init.is_file() and not init.is_symlink():
                out.append((name, init))
    return out


#: _manifest results by path, with the file state they were read from.
_MANIFESTS: dict[str, tuple[tuple, tuple[dict, str]]] = {}


def clear_manifest_cache() -> None:
    _MANIFESTS.clear()


def _manifest(path: Path) -> tuple[dict, str]:
    """The EXTENSION literal of *path* and an error text ("" when fine).
    Parsed once per file state (size, change and modification time, inode):
    Settings asks again each time it opens, the file rarely changes."""
    try:
        st = path.stat()
    except OSError as exc:
        return {}, f"cannot read: {exc.strerror or exc}"
    state = (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, st.st_dev)
    cached = _MANIFESTS.get(str(path))
    if cached is not None and cached[0] == state:
        fields, error = cached[1]
        return dict(fields), error
    result = _read_manifest(path, st.st_size)
    if not result[1].startswith("cannot read"):  # a passing read error is tried again
        _MANIFESTS[str(path)] = (state, (dict(result[0]), result[1]))
    return result


def _read_manifest(path: Path, size: int) -> tuple[dict, str]:
    if size > MAX_SOURCE_BYTES:
        return {}, f"too large ({size} bytes, at most {MAX_SOURCE_BYTES})"
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return {}, f"syntax error in line {exc.lineno}: {exc.msg}"
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {}, f"cannot read: {exc}"
    manifest = None
    has_activate = False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "EXTENSION" for t in node.targets
        ):
            try:
                manifest = ast.literal_eval(node.value)
            except ValueError:
                return {}, "EXTENSION must be a plain literal dict"
        elif isinstance(node, ast.FunctionDef) and node.name == "activate":
            has_activate = True
    if not isinstance(manifest, dict):
        return {}, "no EXTENSION manifest (a dict with at least a name)"
    if not isinstance(manifest.get("name"), str) or not manifest["name"].strip():
        return {}, "the EXTENSION manifest needs a name"
    if not has_activate:
        return {}, "no activate() function"
    fields = {
        key: str(manifest.get(key, "") or "")[:MAX_FIELD_CHARS].strip() for key in _FIELDS
    }
    return fields, ""


def discover(*, include_bundled: bool = True, ids: set[str] | None = None) -> list[ExtensionInfo]:
    """Every extension found, user ones first; never runs their code.
    *ids*: only these (the others are not even parsed)."""
    sources = [("user", extensions_dir())]
    if include_bundled:
        sources.append(("bundled", bundled_dir()))
    found: list[ExtensionInfo] = []
    for source, folder in sources:
        for module_name, path in _candidates(folder):
            if ids is not None and f"{source}:{module_name}" not in ids:
                continue
            fields, error = _manifest(path)
            found.append(
                ExtensionInfo(
                    ext_id=f"{source}:{module_name}",
                    source=source,
                    module_name=module_name,
                    path=str(path),
                    name=fields.get("name") or module_name,
                    version=fields.get("version", ""),
                    description=fields.get("description", ""),
                    author=fields.get("author", ""),
                    error=error,
                )
            )
    return found


# ---------------------------------------------------------------------------
# On / off
# ---------------------------------------------------------------------------


def _read_settings() -> tuple[dict, bool]:
    """The settings and whether the file was readable (missing counts as
    readable: there is nothing to lose)."""
    path = settings_file()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, True
    except (OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError: a file that is not UTF-8 - read_text() raises
        # it, and the main window reads this while it is built.
        log.warning("Cannot read %s: %s", path, exc)
        return {}, False
    try:
        data = json.loads(text)
    except ValueError:
        log.warning("%s is not valid JSON; no extension is switched on", path)
        return {}, False
    if not isinstance(data, dict):
        return {}, False
    return data, True


def _id_list(key: str) -> set[str]:
    """The extension ids stored under *key*; a missing or malformed entry
    is an empty set."""
    data, _ok = _read_settings()
    ids = data.get(key)
    if not isinstance(ids, list):
        return set()
    return {i for i in ids if isinstance(i, str)}


def _set_member(key: str, ext_id: str, on: bool, *, also_off: tuple[str, ...] = ()) -> None:
    """Add *ext_id* to (or remove it from) the list under *key* - and
    remove it from the lists under *also_off* in the same write - keeping
    every other key of the settings file."""
    from core.secure_storage import keep_unreadable_copy, write_secret_file

    data, readable = _read_settings()
    if not readable and not keep_unreadable_copy(settings_file()):
        raise OSError(f"{settings_file()} is unreadable and could not be kept aside")
    data = dict(data) if readable else {}
    for name in (key, *also_off):
        old = data.get(name)
        ids = {i for i in old if isinstance(i, str)} if isinstance(old, list) else set()
        if name != key and name not in data:
            continue  # nothing to remove from a list that is not there
        if on and name == key:
            ids.add(ext_id)
        else:
            ids.discard(ext_id)
        data[name] = sorted(ids)
    os.makedirs(settings_file().parent, mode=0o700, exist_ok=True)
    write_secret_file(str(settings_file()), json.dumps(data, indent=2) + "\n")


def enabled_ids() -> set[str]:
    return _id_list("enabled")


def set_enabled(ext_id: str, on: bool) -> None:
    """Switch *ext_id* on or off. Either way it is no longer suspended:
    switching it on again is the user's new try, and one switched off has
    nothing to be suspended from."""
    _set_member("enabled", ext_id, on, also_off=("suspended",))


def paused_ids() -> set[str]:
    """Extensions the user paused: loaded, but no pane events reach them
    (``ui.extension_host.ExtensionHost.set_paused``)."""
    return _id_list("paused")


def set_paused(ext_id: str, on: bool) -> None:
    _set_member("paused", ext_id, on)


# ---------------------------------------------------------------------------
# Startup guard
# ---------------------------------------------------------------------------


def suspended_ids() -> set[str]:
    """Switched-on extensions an earlier start stopped in (hung or crashed
    while their code ran): not loaded at the start until tried again."""
    return _id_list("suspended")


def set_suspended(ext_id: str, on: bool) -> None:
    _set_member("suspended", ext_id, on)


def safe_mode() -> bool:
    """``--safe-mode``: this process loads no extension at the start."""
    return _SAFE_MODE


def set_safe_mode(on: bool) -> None:
    global _SAFE_MODE
    _SAFE_MODE = bool(on)


def activation_dir() -> Path:
    """The private folder of the activation markers (beside the log)."""
    return Path.home() / ".local" / "state" / "axross" / "extension-activation"


def begin_activation(info: ExtensionInfo) -> Path | None:
    """Write the marker for *info*'s code about to run in this process;
    its path, or None when it cannot be written - the load goes on
    without the guard, a start never fails over its marker."""
    global _CURRENT
    from core.secure_storage import write_secret_file

    folder = activation_dir()
    marker = folder / f"{os.getpid()}.json"
    data = {
        "pid": os.getpid(),
        "ext_id": info.ext_id,
        "name": info.name,
        "started": time.time(),
        "proc_start": _process_start(os.getpid()),
    }
    try:
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        write_secret_file(str(marker), json.dumps(data) + "\n")
    except OSError as exc:
        log.warning("Extension %s runs without its startup marker: %s", info.ext_id, exc)
        marker = None
    _CURRENT = (info.ext_id, info.name, time.monotonic())
    return marker


def end_activation(marker: Path | None) -> None:
    """The code of the extension *marker* names has returned (or raised)."""
    global _CURRENT
    _CURRENT = None
    if marker is None:
        return
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("Cannot remove the extension marker %s: %s", marker, exc)


def current_activation() -> tuple[str, str, float] | None:
    """``(ext_id, name, seconds running)`` of the extension code running in
    this process right now, None when none is (the startup watchdog names
    it in its message)."""
    current = _CURRENT
    if current is None:
        return None
    ext_id, name, since = current
    return ext_id, name, time.monotonic() - since


def _process_start(pid: int) -> int | None:
    """The kernel's start time of *pid* (Linux, clock ticks after boot):
    tells a process from a later one that got the same pid."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
        return int(text.rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None


def _process_alive(pid: int, proc_start) -> bool:
    """Whether the process that wrote a marker still runs."""
    if pid == os.getpid():
        return False  # a marker of an earlier process that had this pid
    if os.name == "nt":
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # PermissionError: another user's process has that pid now - the
        # marker's writer (always this user) is gone.
        return False
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.exists():
        try:
            state = stat_path.read_text(encoding="ascii", errors="replace").rsplit(")", 1)[1]
            if state.split()[0] == "Z":
                return False  # ended, not yet reaped
        except (OSError, IndexError):
            pass
        now = _process_start(pid)
        if isinstance(proc_start, int) and now is not None and now != proc_start:
            return False  # the pid was reused
    return True


def _windows_process_alive(pid: int) -> bool:
    # os.kill(pid, 0) on Windows sends CTRL_C_EVENT; ask the kernel instead.
    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def collect_stale_activations() -> list[dict]:
    """The markers an earlier process left: each as ``{"ext_id", "name",
    "pid", "started", "reason"}`` with *reason* ``"ended"`` (its process
    is gone; the marker is removed) or ``"hung"`` (it still runs but has
    been activating for longer than :data:`HUNG_ACTIVATION_SECONDS`; the
    marker stays for its owner to remove). Markers of processes that are
    activating right now are left alone, unreadable ones removed."""
    folder = activation_dir()
    try:
        entries = sorted(folder.iterdir())
    except OSError:
        return []
    found = []
    for path in entries:
        match = _MARKER_NAME.match(path.name)
        if match is None or path.is_symlink():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            pid = data["pid"]
            ext_id = data["ext_id"]
            started = float(data.get("started", 0))
            if not (isinstance(pid, int) and isinstance(ext_id, str) and ext_id):
                raise ValueError("bad marker")
        except (OSError, ValueError, KeyError, TypeError):
            _remove(path)
            continue
        name = data.get("name") if isinstance(data.get("name"), str) else ext_id
        entry = {"ext_id": ext_id, "name": name, "pid": pid, "started": started}
        if not _process_alive(pid, data.get("proc_start")):
            found.append({**entry, "reason": "ended"})
            _remove(path)
        elif time.time() - started > HUNG_ACTIVATION_SECONDS:
            found.append({**entry, "reason": "hung"})
    return found


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


__all__ = [
    "ExtensionInfo",
    "HUNG_ACTIVATION_SECONDS",
    "MAX_SOURCE_BYTES",
    "SLOW_ACTIVATE_SECONDS",
    "activation_dir",
    "begin_activation",
    "bundled_dir",
    "collect_stale_activations",
    "current_activation",
    "discover",
    "enabled_ids",
    "end_activation",
    "extensions_allowed",
    "extensions_dir",
    "paused_ids",
    "safe_mode",
    "set_enabled",
    "set_paused",
    "set_safe_mode",
    "set_suspended",
    "settings_file",
    "suspended_ids",
]
