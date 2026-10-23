"""Runtime security modes."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SecurityPolicy:
    name: str
    allow_external_viewer: bool = True
    allow_auto_preview: bool = True
    allow_scripts: bool = True
    allow_private_proxy: bool = True
    allow_legacy_protocols: bool = True
    allow_remote_exec: bool = True
    #: One login against many SMB hosts (core.remote_sweep).
    allow_network_sweep: bool = True


NORMAL = SecurityPolicy("normal")
PARANOID = SecurityPolicy(
    "paranoid",
    allow_external_viewer=False,
    allow_auto_preview=False,
    allow_scripts=False,
    allow_private_proxy=False,
    allow_legacy_protocols=False,
    allow_remote_exec=False,
    allow_network_sweep=False,
)

LEGACY_PROTOCOLS = frozenset(
    {
        "cisco-telnet",
        "ftp",
        "gopher",
        "nntp",
        "pop3",
        "rsh",
        "telnet",
        "tftp",
    }
)

_CURRENT: SecurityPolicy | None = None
#: The environment variable that sets the mode at start (and always wins).
ENV = "AXROSS_SECURITY_MODE"


def policy_from_name(name: str | None) -> SecurityPolicy:
    """Map a mode name to its policy. Unset or empty means normal; a name
    that is neither ``normal`` nor ``paranoid`` (``AXROSS_SECURITY_MODE=
    paranoia``) fails closed to paranoid instead of silently dropping
    every restriction the user asked for."""
    text = (name or "").strip().lower()
    if text in ("", "normal"):
        return NORMAL
    if text != "paranoid":
        log.warning("Unknown security mode %r; using 'paranoid'", name)
    return PARANOID


def current_policy() -> SecurityPolicy:
    global _CURRENT
    if _CURRENT is None:
        _CURRENT = policy_from_name(os.environ.get(ENV))
    return _CURRENT


def set_policy(name: str) -> SecurityPolicy:
    global _CURRENT
    _CURRENT = policy_from_name(name)
    return _CURRENT


def is_paranoid() -> bool:
    return current_policy().name == "paranoid"


#: settings.json key of the mode the user chose in the window
#: (Edit > Settings > Security): ``"normal"`` or ``"paranoid"``.
SETTING = "security_mode"


def stored_mode() -> str | None:
    """The mode stored by the window, or None when none is stored.

    Fails closed like :func:`policy_from_name`: anything but ``"normal"``,
    ``"paranoid"`` or an empty name (a hand-edited ``"paranoia"``, ``true``,
    ``1``) reads as paranoid - a broken file must not drop every
    restriction the user chose."""
    from core import open_limits as OL

    value = OL.read_setting(SETTING)
    if value is None:
        return None
    if not isinstance(value, str):
        log.warning("Stored security mode %r is not a name; using 'paranoid'", value)
        return PARANOID.name
    return policy_from_name(value).name


def store_mode(name: str) -> None:
    """Remember *name* (``normal`` / ``paranoid``) for the next start."""
    from core import open_limits as OL

    OL.write_setting(SETTING, policy_from_name(name).name)


def apply_stored_mode() -> SecurityPolicy:
    """At the start of the window (main.py): the stored mode becomes the
    current one - unless ``AXROSS_SECURITY_MODE`` is set, which always
    wins, or nothing is stored. Returns the policy in force."""
    if (os.environ.get(ENV) or "").strip():
        return current_policy()
    stored = stored_mode()
    if stored is None:
        return current_policy()
    return set_policy(stored)


def require(feature: str, allowed: bool) -> None:
    if not allowed:
        raise PermissionError(f"Security mode '{current_policy().name}' blocks {feature}")


def require_protocol_allowed(protocol: str) -> None:
    proto = (protocol or "").strip().lower()
    policy = current_policy()
    if not policy.allow_legacy_protocols and proto in LEGACY_PROTOCOLS:
        raise OSError(f"Security mode '{policy.name}' blocks legacy protocol {proto!r}")


__all__ = [
    "ENV",
    "LEGACY_PROTOCOLS",
    "NORMAL",
    "PARANOID",
    "SETTING",
    "SecurityPolicy",
    "apply_stored_mode",
    "current_policy",
    "is_paranoid",
    "policy_from_name",
    "require",
    "require_protocol_allowed",
    "set_policy",
    "store_mode",
    "stored_mode",
]
