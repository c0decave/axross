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
HTTP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

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


#: The module whose import defines paramiko.Transport.
_TRANSPORT_MODULE = "paramiko.transport"


class _BannerLoader:
    """Runs the real loader, then gives the new module's Transport the
    banner. A wrapper, never a change to the real loader: a frozen build's
    importer is one object that loads every module."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def create_module(self, spec):
        create = getattr(self._inner, "create_module", None)
        return create(spec) if create is not None else None  # None: the default module

    def exec_module(self, module) -> None:
        self._inner.exec_module(module)
        # Not through ``import paramiko``: the package is still running its
        # own import of this module and has no Transport name yet.
        module.Transport._CLIENT_ID = SSH_LOCAL_VERSION.removeprefix("SSH-2.0-")

    def __getattr__(self, name):  # get_code, get_source, is_package ...
        return getattr(self._inner, name)


class _BannerOnImport:
    """A ``sys.meta_path`` finder for paramiko.transport only: it asks the
    finders after it for the module and hands back their spec with the
    loader wrapped in :class:`_BannerLoader` - so Transport has the banner
    before any code can make one."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _TRANSPORT_MODULE:
            return None
        import sys  # noqa: PLC0415

        for finder in sys.meta_path:
            find = getattr(finder, "find_spec", None)
            if finder is self or find is None:
                continue
            spec = find(fullname, path, target)
            if spec is None:
                continue
            if spec.loader is not None and hasattr(spec.loader, "exec_module"):
                spec.loader = _BannerLoader(spec.loader)
            return spec
        return None


def banner_override_on_import() -> None:
    """The banner of :func:`apply_paramiko_banner_override` without
    importing paramiko now: applied at once when paramiko.transport is
    loaded already, else the moment something imports it. For the GUI
    start, which needs no SSH until a connection is opened (paramiko with
    invoke and yaml costs ~0.14 s). Idempotent."""
    import sys  # noqa: PLC0415

    if _TRANSPORT_MODULE in sys.modules:
        apply_paramiko_banner_override()
        return
    if not any(isinstance(finder, _BannerOnImport) for finder in sys.meta_path):
        sys.meta_path.insert(0, _BannerOnImport())
