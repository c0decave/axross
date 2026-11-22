"""axross-markdown's own settings file, without Qt: ~/.config/axross-markdown/settings.json
(``$XDG_CONFIG_HOME`` when set; ``$AXROSS_MARKDOWN_SETTINGS`` names another file - a test's, a portable
setup's) - the window's and the terminal's theme (core.markdown_themes) and the updates' mode
(core.markdown_update). ui.standalone_app keeps the window theme of axross's in the same file.

The file is written only when the user chooses something (a menu, ``--update-mode``): what the program
notes by itself - when it last asked for updates, the newer version it found - is its state, in
:func:`state_path` (``$XDG_STATE_HOME``), never here.

The file is hand-editable: every value is checked where it is read. A file that is no JSON object (a
typo: a trailing comma) is read for what can still be read (salvaged: each top-level key whose value parses),
never taken for empty - and the next write keeps that file aside first (``settings.json.broken``, never one
kept before) and writes what was salvaged with the new choice, so a typo loses no setting: before 0.17.3 it
lost all of them at the next choice, ``"update_mode": "off"`` with them - and the program asked GitHub again.
Writes keep every other key, are private (0600) and atomic (a temporary file, fsync, rename), one at a time
across threads and processes (a file lock beside it), and go through a symlink to its target (a dotfiles
manager's link stays a link).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path

log = logging.getLogger(__name__)

NAME = "axross-markdown"
#: Names the settings file instead of ~/.config/axross-markdown/settings.json (the state goes beside it).
ENV = "AXROSS_MARKDOWN_SETTINGS"
#: The most of the file that is read (a hand-edited file is no reason to read gigabytes).
MAX_BYTES = 1 << 20
_LOCK = threading.Lock()


def settings_path(name: str = NAME) -> Path:
    override = os.environ.get(ENV, "").strip()
    if override and name == NAME:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / name / "settings.json"


def state_path(name: str = NAME) -> Path:
    """What the program notes by itself (the update checks): ~/.local/state/axross-markdown/state.json
    (``$XDG_STATE_HOME``) - beside ``$AXROSS_MARKDOWN_SETTINGS``'s file when that is set."""
    override = os.environ.get(ENV, "").strip()
    if override and name == NAME:
        settings = Path(override).expanduser()
        return settings.with_name(settings.stem + ".state.json")
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / name / "state.json"


def window_state_path(name: str = NAME) -> Path:
    """Where the window's size and place are kept: ~/.local/state/axross-markdown/window.json - the program's
    own (it wrote them into axross's ~/.config/axross/session.json)."""
    state = state_path(name)
    return state.with_name(state.stem + ".window.json") if state.name != "state.json" \
        else state.with_name("window.json")


#: (_salvaged) a top-level "key": value of a JSON object, its value a string, a number, true, false or null.
_PAIR = re.compile(r'"((?:[^"\\\n]|\\.){1,200})"\s*:\s*("(?:[^"\\\n]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?'
                   r'|true|false|null)\s*(?=[,}\n"]|$)')
#: (_salvaged) commas before a closing brace or bracket (outside strings: the text has none then).
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _salvaged(text: str) -> dict:
    """What can still be read of a settings file that is no JSON object: the object without its trailing commas,
    else each "key": value pair whose value is a plain JSON value - the update mode "off" kept whatever else is
    lost (never asked again for updates the user turned off)."""
    try:
        value = json.loads(_TRAILING_COMMA.sub(r"\1", text))
        if isinstance(value, dict):
            return value
    except (ValueError, RecursionError):
        pass
    found: dict = {}
    for match in _PAIR.finditer(text):
        try:
            found.setdefault(json.loads(f'"{match.group(1)}"'), json.loads(match.group(2)))
        except (ValueError, RecursionError):
            continue
    if "update_mode" not in found and re.search(r'update_mode"?\s*[:=]\s*"?off', text):
        found["update_mode"] = "off"
    return found


def _load(path: Path) -> tuple[dict, bytes | None]:
    """(the settings of *path*, the file's bytes when it is there but no JSON object - None: it is one, or there
    is none)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return {}, None
    except OSError:
        return {}, None
    if len(data) > MAX_BYTES:
        return _salvaged(data[:MAX_BYTES].decode("utf-8", "replace")), data
    try:
        value = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):  # (nested past the limit: salvaged too)
        return _salvaged(data.decode("utf-8", "replace")), data
    if isinstance(value, dict):
        return value, None
    return {}, data


def read_settings(path: Path | None = None) -> dict:
    """The settings as a dict - {} when there are none; what can still be read of a file that is no JSON object
    (_salvaged)."""
    return _load(settings_path() if path is None else Path(path))[0]


def read_setting(key: str, default=None, path: Path | None = None):
    return read_settings(path).get(key, default)


def write_setting(key: str, value, path: Path | None = None) -> None:
    """*key* = *value* (None: the key removed), the rest kept."""
    write_settings({key: value}, path)


def write_settings(values: dict, path: Path | None = None) -> None:
    """Every key of *values* set (a None removes it), the rest kept - written privately and atomically, to a
    symlink's target. A file that is no JSON object is kept aside first (_kept_aside) and what can still be read
    of it kept (_salvaged)."""
    from core.secure_storage import locked_store_update

    path = settings_path() if path is None else Path(path)
    target = Path(os.path.realpath(path))  # (a symlink - a dotfiles manager's - written through, kept a link)
    with _LOCK, locked_store_update(target):
        data, broken = _load(target)
        if broken is not None:
            _kept_aside(target, broken)
        for key, value in values.items():
            if value is None:
                data.pop(key, None)
            else:
                data[key] = value
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise


def _kept_aside(path: Path, data: bytes) -> Path:
    """A copy of the file *path* that is no JSON object (*data*: its bytes), beside it - settings.json.broken,
    else .broken-2, -3 …: never one kept before overwritten. Said in the log."""
    for number in range(1, 1000):
        aside = path.with_name(path.name + (".broken" if number == 1 else f".broken-{number}"))
        try:
            fd = os.open(aside, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                if aside.read_bytes() == data:
                    break  # (this one kept already)
            except OSError:
                pass
            continue
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        break
    log.warning("%s could not be read as JSON (a typo?): it is kept as %s, and what could still be read of "
                "it is written back with the new choice", path, aside)
    return aside


__all__ = ["ENV", "NAME", "read_setting", "read_settings", "settings_path", "state_path", "window_state_path",
           "write_setting", "write_settings"]
