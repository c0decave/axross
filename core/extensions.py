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

This module is Qt-free: discovery and the on/off state. Loading and the
API live in :mod:`ui.extension_host`.
"""

from __future__ import annotations

import ast
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

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


def _manifest(path: Path) -> tuple[dict, str]:
    """The EXTENSION literal of *path* and an error text ("" when fine)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {}, f"cannot read: {exc.strerror or exc}"
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


def discover(*, include_bundled: bool = True) -> list[ExtensionInfo]:
    """Every extension found, user ones first; never runs their code."""
    sources = [("user", extensions_dir())]
    if include_bundled:
        sources.append(("bundled", bundled_dir()))
    found: list[ExtensionInfo] = []
    for source, folder in sources:
        for module_name, path in _candidates(folder):
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
    except OSError as exc:
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


def enabled_ids() -> set[str]:
    data, _ok = _read_settings()
    ids = data.get("enabled")
    if not isinstance(ids, list):
        return set()
    return {i for i in ids if isinstance(i, str)}


def set_enabled(ext_id: str, on: bool) -> None:
    from core.secure_storage import keep_unreadable_copy, write_secret_file

    data, readable = _read_settings()
    if not readable and not keep_unreadable_copy(settings_file()):
        raise OSError(f"{settings_file()} is unreadable and could not be kept aside")
    ids = enabled_ids() if readable else set()
    if on:
        ids.add(ext_id)
    else:
        ids.discard(ext_id)
    data = dict(data) if readable else {}
    data["enabled"] = sorted(ids)
    os.makedirs(settings_file().parent, mode=0o700, exist_ok=True)
    write_secret_file(str(settings_file()), json.dumps(data, indent=2) + "\n")


__all__ = [
    "ExtensionInfo",
    "MAX_SOURCE_BYTES",
    "bundled_dir",
    "discover",
    "enabled_ids",
    "extensions_allowed",
    "extensions_dir",
    "set_enabled",
    "settings_file",
]
