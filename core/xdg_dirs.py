"""The XDG base directories, as the spec reads them: a variable that is
unset, empty or holds a relative path is ignored and the default under the
home is used. A relative ``XDG_DATA_HOME`` taken as it is would put
axross's data - the packs it puts on sys.path, a downloaded update, a
token - under whatever the current directory is."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

#: variable -> its default below the home (XDG Base Directory spec).
DEFAULTS = {
    "XDG_CONFIG_HOME": (".config",),
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_STATE_HOME": (".local", "state"),
    "XDG_CACHE_HOME": (".cache",),
}


def env_dir(var: str, environ: Mapping[str, str] | None = None) -> str | None:
    """``$var`` when it is an absolute path, else None (relative: ignored)."""
    value = (os.environ if environ is None else environ).get(var, "") or ""
    value = value.strip()
    return value if value and os.path.isabs(value) else None


def base_dir(var: str, environ: Mapping[str, str] | None = None) -> Path:
    """The XDG base directory *var* (one of :data:`DEFAULTS`): ``$var`` when
    absolute, else its default under the home."""
    value = env_dir(var, environ)
    if value is not None:
        return Path(value)
    return Path(os.path.expanduser("~")).joinpath(*DEFAULTS[var])


__all__ = ["DEFAULTS", "base_dir", "env_dir"]
