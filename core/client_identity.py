"""Uniform client-identity strings for network-facing Axross backends.

The goal is to prevent every backend from shipping its own SDK-default
identifier that — together — forms an "Axross-ran-here" fingerprint.
Defaults below are picked to **blend in** with common traffic, not to
be maximally stealthy: blending beats randomising because a constantly-
changing UA or banner is itself a marker.

If you override these, prefer currently-common strings over unusual
ones. The identity-hygiene rule is documented in ``docs/OPSEC.md``.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# HTTP User-Agent. Firefox ESR 128 runs on Linux for a long maintenance
# window (Jun 2024 → mid 2025+) so it remains a plausible string for a
# while. Matches Mozilla-UA-format so Accept-Language / Accept-Encoding
# defaults from ``requests`` look internally consistent.
HTTP_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

# SSH local-version string. Broadcast in plaintext before KEX, logged
# by every server as ``client_version``. OpenSSH 9.6p1 shipped Dec
# 2023 in Debian 12 backports / Ubuntu 24.04 / Fedora 40 and is still
# heavily represented in 2026 traffic — distinctive-looking version
# strings (``paramiko_X.Y.Z``, ``libssh2_X.Y.Z``) identify the exact
# implementation.
#
# Do NOT pick a patch level with a known CVE — that invites targeted
# probes from automated attackers.
SSH_LOCAL_VERSION = "SSH-2.0-OpenSSH_9.6p1 Debian-4"

# SMB workstation/client name. Real Windows clients auto-generate
# ``DESKTOP-XXXXXXX`` (7 random alphanumerics). Using a single fixed
# string across all users is a weaker disguise (every Axross install
# looks identical), but the alternative — generating a per-install
# random string and persisting it — creates a stable correlatable
# identity in its own right. ``WORKSTATION`` is the smbprotocol /
# Samba-era fallback and looks like a valid NetBIOS name.
#
# A follow-up could generate ``DESKTOP-<hex>`` on first use and
# persist it to the config dir, trading uniformity-fingerprint for
# convincingness. See OPSEC.md.
SMB_CLIENT_NAME = "WORKSTATION"

# Telnet NAWS default. 80×24 is the VT100 classical geometry and the
# single most common value on the wire — a fixed default blends
# better than randomisation would, because real terminals rarely
# resize mid-session. Overridable per profile.
TELNET_NAWS_WIDTH = 80
TELNET_NAWS_HEIGHT = 24


def apply_paramiko_banner_override() -> None:
    """Patch paramiko's Transport class-level ``_CLIENT_ID`` so every
    Transport instance — including those created internally by
    ``paramiko.SSHClient`` — advertises ``SSH_LOCAL_VERSION`` instead
    of ``paramiko_X.Y.Z``.

    Call once at startup. Idempotent. Safe to invoke before or after
    any imports of ``core.ssh_client`` / ``core.scp_client`` because
    the class attribute is consulted inside ``Transport.__init__`` at
    instantiation time, not at import time.
    """
    try:
        import paramiko  # noqa: PLC0415 — deferred import so modules that
        # don't need SSH aren't forced to pull paramiko.
    except ImportError:
        return

    desired = SSH_LOCAL_VERSION.removeprefix("SSH-2.0-")
    try:
        paramiko.Transport._CLIENT_ID = desired  # type: ignore[attr-defined]
    except AttributeError:
        # Older paramiko layouts: best-effort fall-through. Individual
        # backends still set ``transport.local_version`` per-instance.
        log.debug("paramiko.Transport._CLIENT_ID attribute missing")
