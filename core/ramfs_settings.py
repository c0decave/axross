"""Process-wide RamFS / tmpfs feature settings.

These are *application-level* preferences (not per-connection
profile fields) — same shape as theme / column-prefs config. They
control:

* ``ramfs_enabled`` — can the user open RAM-pane workspaces and
  use auto-decrypt-to-RAM. Default ON.
* ``ramfs_max_bytes`` — per-RamFsSession byte cap. Default 256 MiB.
* ``ramfs_system_reserve_bytes`` — refuse RamFS writes when the
  OS has less than this free. Default 256 MiB.
* ``tmpfs_enabled`` — should atomic_io / archive / fuse_mount
  prefer detected tmpfs over /tmp. Default ON.

Settings live in ``~/.config/axross/ramfs.json`` (single small
file rather than a giant ``settings.json``) so a future general
app-settings store can absorb it cleanly. The loader is robust to
the file being missing, malformed, or having unknown keys.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)


CONFIG_DIR = Path.home() / ".config" / "axross"
SETTINGS_FILE = CONFIG_DIR / "ramfs.json"


@dataclass
class RamFsSettings:
    """Process-wide RamFS / tmpfs settings."""

    ramfs_enabled: bool = True
    ramfs_max_bytes: int = 256 * 1024 * 1024
    ramfs_system_reserve_bytes: int = 256 * 1024 * 1024
    tmpfs_enabled: bool = True

    @classmethod
    def load(cls) -> RamFsSettings:
        """Load from disk, falling back to defaults on any error.
        Unknown keys in the file are ignored so older axross versions
        cope with newer-version configs gracefully."""
        if not SETTINGS_FILE.exists():
            return cls()
        try:
            raw = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning(
                "RamFsSettings: cannot parse %s (%s) — using defaults",
                SETTINGS_FILE, exc,
            )
            return cls()
        if not isinstance(raw, dict):
            return cls()

        kw: dict = {}
        for fld in (
            "ramfs_enabled", "tmpfs_enabled",
        ):
            if isinstance(raw.get(fld), bool):
                kw[fld] = raw[fld]
        for fld in (
            "ramfs_max_bytes", "ramfs_system_reserve_bytes",
        ):
            v = raw.get(fld)
            if isinstance(v, int) and 0 <= v <= 64 * 1024 * 1024 * 1024:
                kw[fld] = v
        return cls(**kw)

    def save(self) -> None:
        """Write settings atomically with 0o600 perms."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(CONFIG_DIR, 0o700)
        except OSError:
            pass
        tmp = SETTINGS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(SETTINGS_FILE)


_CACHED: RamFsSettings | None = None


def get_settings() -> RamFsSettings:
    """Return the cached process-wide settings, loading on first call.
    Re-loadable via :func:`reload_settings`."""
    global _CACHED
    if _CACHED is None:
        _CACHED = RamFsSettings.load()
    return _CACHED


def reload_settings() -> RamFsSettings:
    """Force a re-read from disk — used after the user edits the file
    or by tests that change the file under the runtime."""
    global _CACHED
    _CACHED = RamFsSettings.load()
    return _CACHED
