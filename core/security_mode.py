"""Runtime security modes."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityPolicy:
    name: str
    allow_external_viewer: bool = True
    allow_auto_preview: bool = True
    allow_scripts: bool = True
    allow_private_proxy: bool = True
    allow_legacy_protocols: bool = True


NORMAL = SecurityPolicy("normal")
PARANOID = SecurityPolicy(
    "paranoid",
    allow_external_viewer=False,
    allow_auto_preview=False,
    allow_scripts=False,
    allow_private_proxy=False,
    allow_legacy_protocols=False,
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


def policy_from_name(name: str | None) -> SecurityPolicy:
    return PARANOID if (name or "").strip().lower() == "paranoid" else NORMAL


def current_policy() -> SecurityPolicy:
    global _CURRENT
    if _CURRENT is None:
        _CURRENT = policy_from_name(os.environ.get("AXROSS_SECURITY_MODE"))
    return _CURRENT


def set_policy(name: str) -> SecurityPolicy:
    global _CURRENT
    _CURRENT = policy_from_name(name)
    return _CURRENT


def is_paranoid() -> bool:
    return current_policy().name == "paranoid"


def require(feature: str, allowed: bool) -> None:
    if not allowed:
        raise PermissionError(f"Security mode '{current_policy().name}' blocks {feature}")


def require_protocol_allowed(protocol: str) -> None:
    proto = (protocol or "").strip().lower()
    policy = current_policy()
    if not policy.allow_legacy_protocols and proto in LEGACY_PROTOCOLS:
        raise OSError(f"Security mode '{policy.name}' blocks legacy protocol {proto!r}")


__all__ = [
    "LEGACY_PROTOCOLS",
    "NORMAL",
    "PARANOID",
    "SecurityPolicy",
    "current_policy",
    "is_paranoid",
    "policy_from_name",
    "require",
    "require_protocol_allowed",
    "set_policy",
]
