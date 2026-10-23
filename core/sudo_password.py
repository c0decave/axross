"""The sudo password, remembered while axross runs.

The operator asked to remember it by default, allow switching that off, so a
mount does not ask again and again. ``remember_sudo_password`` in
settings.json (a bool, default true) is the switch.

* Memory only: never written anywhere, gone when axross exits.
* Switching remembering off, or paranoid mode, forgets it at once; paranoid
  mode never remembers.
* polkit (pkexec, udisksctl) asks through its own agent - axross never sees
  that password and cannot remember it; core.loop_mount therefore prefers
  sudo while remembering is on.
"""

from __future__ import annotations

import threading

from core import open_limits as OL
from core.security_mode import is_paranoid

SETTING = "remember_sudo_password"
DEFAULT = True

_LOCK = threading.Lock()
_SECRET: str | None = None


def _stored() -> bool:
    value = OL.read_setting(SETTING, DEFAULT)
    return value if isinstance(value, bool) else DEFAULT


def remember_setting() -> bool:
    """The stored choice, whatever the security mode says."""
    return _stored()


def remember_enabled() -> bool:
    """Whether a sudo password is kept now: the setting, and not paranoid."""
    if is_paranoid():
        forget()
        return False
    return _stored()


def set_remember(enabled: bool) -> None:
    if not isinstance(enabled, bool):
        raise TypeError(f"remember_sudo_password must be true or false, not {enabled!r}")
    OL.write_setting(SETTING, enabled)
    if not enabled:
        forget()


def remember(secret: str) -> None:
    """Keep *secret* for the next sudo call, if remembering is on."""
    global _SECRET
    if secret and remember_enabled():
        with _LOCK:
            _SECRET = secret


def remembered() -> str | None:
    """The kept password, or None."""
    if not remember_enabled():
        return None
    with _LOCK:
        return _SECRET


def forget() -> None:
    global _SECRET
    with _LOCK:
        _SECRET = None


__all__ = [
    "DEFAULT",
    "SETTING",
    "forget",
    "remember",
    "remember_enabled",
    "remember_setting",
    "remembered",
    "set_remember",
]
