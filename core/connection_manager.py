"""Connection manager — manages backend sessions with reference counting."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from core.backend_registry import load_backend_class
from core.profiles import ConnectionProfile, password_needed

if TYPE_CHECKING:
    from core.backend import FileBackend
    from core.ssh_client import UnknownHostKeyError

log = logging.getLogger(__name__)

# SSH / SCP sessions pull in paramiko (~0.13 s, a third of the GUI start)
# but a fresh window shows a local pane. They are imported on first use;
# the names stay module attributes so callers and tests that patch
# ``core.connection_manager.SSHSession`` keep working.
_LAZY_SESSIONS = {
    "SSHSession": ("core.ssh_client", "SSHSession"),
    "SCPSession": ("core.scp_client", "SCPSession"),
    "UnknownHostKeyError": ("core.ssh_client", "UnknownHostKeyError"),
}


def __getattr__(name: str):
    target = _LAZY_SESSIONS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(target[0]), target[1])
    globals()[name] = value
    return value


def _profile_token_files(stem: str, profile_name: str) -> dict[str, str]:
    """``token_file`` / ``legacy_token_file`` for an OAuth cloud profile.

    Every profile gets a token file of its own; one file shared by all
    profiles of a protocol opened the first profile's account for the
    second. The name keeps a readable part of the profile name and a
    hash of the whole name, so names that differ only in characters a
    file name cannot carry still get distinct files.
    """
    base = os.path.expanduser("~/.config/axross")
    readable = re.sub(r"[^A-Za-z0-9_-]", "_", profile_name)[:40] or "profile"
    digest = hashlib.sha256(profile_name.encode("utf-8")).hexdigest()[:12]
    return {
        "token_file": os.path.join(base, f"{stem}.{readable}-{digest}.json"),
        "legacy_token_file": os.path.join(base, f"{stem}.json"),
    }


def _session_class(name: str):
    """The class bound to *name* here — a test's patch if one is active."""
    return globals()[name] if name in globals() else __getattr__(name)


# Which protocols actually consume the ``ProxyConfig`` on the profile.
# Cloud HTTP backends use requests.Session.proxies / boto3 Config /
# azure RequestsTransport / httplib2 ProxyInfo. SMB, DFS-N and ADB
# use the scoped socket.create_connection patch from core.proxy. Rsync
# wires the proxy into RSYNC_CONNECT_PROG (daemon mode) or ProxyCommand
# (SSH mode). See docs/PROXY_SUPPORT.md.
_PROTOCOLS_HONOURING_PROFILE_PROXY = frozenset(
    {
        "sftp",
        "scp",
        "webdav",
        "s3",
        "telnet",
        "cisco-telnet",
        "ftp",
        "ftps",
        "smb",
        "dfsn",
        "imap",
        "nntp",
        "pop3",
        "rsync",
        "adb",
        "gopher",
        "pjl",
        "azure_blob",
        "azure_files",
        "onedrive",
        "sharepoint",
        "gdrive",
        "dropbox",
        "winrm",
        "svn",
        "tftp",
        # kernel-mounted: reached through a loopback tunnel (NFSv4 only; the
        # backend itself refuses NFSv3 behind a proxy)
        "nfs",
        "iscsi",
    }
)

# Registry-only backends (reachable from scripts / the REPL through
# ``proxy_*`` keyword arguments, not through saved profiles) that route
# their traffic through the proxy they are given.
_PROTOCOLS_HONOURING_KWARG_PROXY = frozenset(
    {"postgres", "redis", "mongodb", "ldap", "git", "slp"}
)

_PROTOCOLS_PARTIAL_PROFILE_PROXY = {
    # exchange honours it but only with autodiscover=False — the
    # backend itself raises a clear error in the autodiscover-on case
    # when constructed directly.
    "exchange": (
        "Exchange supports proxies only when autodiscover=False and an explicit "
        "server is supplied; saved profiles do not expose those fields yet."
    ),
}

# Backends that cannot be proxied AND would put traffic on the network:
# connecting would silently go around the configured proxy, so they fail
# closed (``ProxyUnsupportedError``). Removing the proxy from the profile
# is the explicit opt-out.
_PROTOCOLS_PROXY_REFUSED = {
    "rsh": (
        "rsh needs a reverse stderr connection and a privileged source port; "
        "no forward proxy can provide that."
    ),
    "wmi": (
        "WMI/DCOM negotiates dynamic RPC ports after the endpoint mapper; "
        "a single proxied connection is not enough."
    ),
}

# Backends without any network transport: a proxy is meaningless, so it is
# only reported (nothing can leak).
_PROTOCOLS_NO_NETWORK = {
    "mtp": "MTP is USB/FUSE based here, not a TCP transport.",
    "ramfs": "RamFS is in-process memory and has no network path.",
    "sqlite": "SQLite is a local file backend and has no network path.",
}

# Union kept for the classification test and docs.
_PROTOCOLS_NOT_PROXIABLE = {**_PROTOCOLS_PROXY_REFUSED, **_PROTOCOLS_NO_NETWORK}


def proxy_unavailable_reason(protocol: str) -> str | None:
    """Why a proxy cannot apply to *protocol*, or ``None`` when it can.

    The connection dialog uses this to disable the proxy group instead of
    letting the user configure a setting that would be refused."""
    return _PROTOCOLS_NOT_PROXIABLE.get(protocol)


def _health_key(session_key: tuple[str, ...]) -> str:
    """Stable-ish process-local key for health/visit hooks.

    The session key already contains only routing/auth discriminators
    (secret fields are hashed upstream). Keep the exported health key
    compact so dashboard output does not become a tuple dump.
    """
    raw = "\x1f".join(str(part) for part in session_key)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]


def _profile_label(profile: "ConnectionProfile") -> str:
    user = f"{profile.username}@" if profile.username else ""
    port = f":{profile.port}" if profile.port else ""
    target = f"{profile.protocol}://{user}{profile.host}{port}"
    return f"{profile.name} ({target})" if profile.name else target


def effective_profile(profile: "ConnectionProfile") -> "ConnectionProfile":
    """The profile with its proxy resolved for this connection.

    ``custom`` profiles are returned untouched. ``default`` / ``none``
    profiles come back as a copy whose ``proxy_*`` fields hold the proxy
    chosen by :mod:`core.proxy_settings` (the global default, a PAC
    answer, the bypass list), so every backend, the session key and
    ``_proxy_kwargs`` keep reading plain profile fields.
    """
    mode = getattr(profile, "proxy_mode", "custom") or "custom"
    if mode == "custom":
        return _with_expanded_key_file(profile)
    import dataclasses

    from core import proxy_settings

    res = proxy_settings.resolve_for_profile(profile)
    cfg = res.config
    resolved = dataclasses.replace(
        profile,
        proxy_mode="custom",
        proxy_type=cfg.proxy_type if cfg else "none",
        proxy_host=cfg.host if cfg else "",
        proxy_port=cfg.port if cfg else 0,
        proxy_username=cfg.username if cfg else "",
        store_proxy_password=False,
        # A ProxyCommand belongs to a custom proxy. Left in place it would
        # route SSH through a jump host while the profile claims the
        # default proxy, or "none" (direct).
        proxy_command="",
    )
    resolved._proxy_password_override = cfg.password if cfg else ""
    return _with_expanded_key_file(resolved)


def _with_expanded_key_file(profile: "ConnectionProfile") -> "ConnectionProfile":
    """*profile*, or a copy whose ``key_file`` has its leading ``~``
    expanded: the SSH / SCP clients open the path as given, and a key
    typed as ``~/.ssh/id_x`` (which the connection dialog accepts) was
    a FileNotFoundError. The caller's profile is never changed."""
    key_file = getattr(profile, "key_file", "") or ""
    if not key_file.startswith("~"):
        return profile
    import copy

    expanded = copy.copy(profile)  # keeps _proxy_password_override and the like
    expanded.key_file = os.path.expanduser(key_file)
    return expanded


def _proxy_kind(profile: "ConnectionProfile") -> str:
    return (profile.proxy_type or "none").lower()


def _proxy_kwargs(profile: "ConnectionProfile") -> dict:
    """Build the proxy_* kwargs dict that every backend session ctor
    accepts. Keeps the per-protocol blocks below short and consistent.
    Returns ``{}`` when no proxy is configured.
    """
    kind = _proxy_kind(profile)
    if kind == "none":
        return {}
    if not profile.proxy_host:
        raise ValueError(
            f"Profile {profile.name!r} sets proxy_type={kind!r} but no "
            "proxy_host; refusing direct traffic."
        )
    from core.proxy import _validate_proxy_port

    proxy_port = _validate_proxy_port(profile.proxy_port)
    return {
        "proxy_type": profile.proxy_type,
        "proxy_host": profile.proxy_host,
        "proxy_port": proxy_port,
        "proxy_username": profile.proxy_username,
        "proxy_password": profile.get_proxy_password() or "",
    }


def _validate_proxy_request(profile: "ConnectionProfile") -> None:
    """Fail closed when a profile says "use a proxy" but does not
    provide the proxy endpoint.
    """
    kind = _proxy_kind(profile)
    if kind != "none" and not profile.proxy_host:
        raise ValueError(
            f"Profile {profile.name!r} sets proxy_type={kind!r} but no "
            "proxy_host; refusing direct traffic."
        )
    if kind != "none":
        from core.proxy import _validate_proxy_port

        _validate_proxy_port(profile.proxy_port)


def _warn_unsupported_proxy(profile: "ConnectionProfile") -> None:
    """Guard the profile's proxy config before the backend is built.

    Raises ``ProxyUnsupportedError`` for network backends that cannot
    honour a proxy (never a silent direct connection), warns for backends
    where a proxy is merely meaningless (no network at all), and logs the
    partial-support cases. Called from ``_create_session``."""
    if _proxy_kind(profile) == "none":
        return
    proto = profile.protocol
    if proto == "adb" and getattr(profile, "adb_mode", "tcp") == "usb":
        log.warning(
            "Profile %r configures a %s proxy, but ADB USB mode has no "
            "TCP transport. Remove the proxy or switch the profile to "
            "ADB TCP mode. See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
        )
        return
    if proto in _PROTOCOLS_HONOURING_PROFILE_PROXY or proto in _PROTOCOLS_HONOURING_KWARG_PROXY:
        return
    if proto == "s3":
        return  # every proxy kind: HTTP-only botocore is fronted by the shim
    if proto in _PROTOCOLS_PARTIAL_PROFILE_PROXY:
        log.warning(
            "Profile %r configures a %s proxy, but %s proxy support is "
            "limited: %s See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
            proto,
            _PROTOCOLS_PARTIAL_PROFILE_PROXY[proto],
        )
        return
    if proto in _PROTOCOLS_PROXY_REFUSED:
        from core.proxy import refuse_unsupported_proxy

        refuse_unsupported_proxy(
            proto, profile.proxy_type, profile.proxy_host, _PROTOCOLS_PROXY_REFUSED[proto]
        )
    if proto in _PROTOCOLS_NO_NETWORK:
        log.warning(
            "Profile %r configures a %s proxy, but %s has no network transport, "
            "so the setting has no effect. %s See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
            proto,
            _PROTOCOLS_NO_NETWORK[proto],
        )


class ConnectionManager:
    """Manages backend sessions keyed by endpoint and network settings.

    Multiple panes connecting to the same endpoint may reuse one session
    if the effective network route is the same.
    """

    def __init__(self):
        self._sessions: dict[tuple[str, ...], object] = {}
        self._ref_counts: dict[tuple[str, ...], int] = {}
        # connect() runs on worker QThreads while release() runs on the
        # GUI thread; this guards the two dicts above.
        self._lock = threading.Lock()
        # One (profile, session key) entry per reference handed out by
        # connect() / acquire(). release() gives back the key the
        # reference was taken under: recomputing it would go through
        # the PAC again, whose answer may have changed meanwhile (a new
        # PAC file after the cache TTL, a time-based rule) or which may
        # no longer be readable.
        # Each entry also names the session the reference was taken on:
        # a stale session that a new connect() replaces lives under the
        # same key, and its holders must give back THEIR reference, not
        # one of the new session's.
        self._held: list[tuple[ConnectionProfile, tuple[str, ...], object]] = []
        # Replaced (stale) sessions still referenced by an old holder:
        # id(session) -> [session, references]. Closed at the last release.
        self._retired: dict[int, list] = {}
        self._profile_resolver: Callable[[str], ConnectionProfile | None] | None = None

    def set_profile_resolver(self, resolver: Callable[[str], ConnectionProfile | None]) -> None:
        """Set a callback to resolve profile names (for ProxyCommand alias expansion)."""
        self._profile_resolver = resolver

    def _session_key(self, profile: ConnectionProfile) -> tuple[str, ...]:
        profile = effective_profile(profile)
        return (
            profile.protocol,
            profile.username,
            profile.host,
            str(profile.port),
            profile.auth_type,
            profile.key_file,
            profile.proxy_type,
            profile.proxy_host,
            str(profile.proxy_port),
            profile.proxy_username,
            profile.proxy_command,
            profile.address_family,
            # Protocol-specific discriminators
            str(profile.ftp_passive),
            str(profile.ftps_verify_tls),
            profile.smb_share,
            profile.smb_client_name,
            profile.s3_bucket,
            profile.s3_region,
            profile.s3_endpoint,
            profile.webdav_url,
            profile.rsync_module,
            str(profile.rsync_ssh),
            profile.rsync_ssh_key,
            str(profile.rsync_preserve_metadata),
            profile.nfs_export,
            str(profile.nfs_version),
            profile.azure_container,
            profile.azure_share,
            profile.azure_account_name,
            str(hash(profile.azure_connection_string)),
            str(hash(profile.azure_sas_token)),
            profile.onedrive_client_id,
            profile.onedrive_tenant_id,
            profile.gdrive_client_id,
            profile.dropbox_app_key,
            profile.sharepoint_site_url,
            profile.iscsi_target_iqn,
            profile.iscsi_mount_point,
            str(profile.imap_ssl),
            str(profile.pop3_ssl),
            profile.tftp_filelist,
            str(profile.tftp_filelist_enabled),
            str(profile.tftp_max_size_bytes),
            profile.adb_mode,
            profile.adb_usb_serial,
            profile.mtp_device_id,
            profile.mtp_mounter,
            str(profile.ssh_keepalive_interval),
            str(profile.telnet_naws_width),
            str(profile.telnet_naws_height),
            str(hash(profile.gdrive_client_secret)),
            str(hash(profile.dropbox_app_secret)),
            # A RAM workspace has no server to tell two of them apart: the
            # profile name is its identity. Two network profiles to one
            # server keep sharing a session.
            profile.name if profile.protocol == "ramfs" else "",
        )

    def connect(
        self,
        profile: ConnectionProfile,
        password: str = "",
        key_passphrase: str = "",
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
    ) -> FileBackend:
        """Connect to a host or reuse an existing connection.

        Routes to the appropriate backend based on profile.protocol.
        """
        # Resolve default / PAC / bypass once; everything below, including
        # the backends, sees a plain profile.
        resolved = effective_profile(profile)
        key = self._session_key(resolved)

        # Reuse existing active session
        reused = self._reuse_locked(key, profile)
        if reused is not None:
            self._decorate_session(reused, profile, key)
            self._record_visit(profile)
            return reused

        # No password passed in (a script's axross.open, a terminal
        # reconnect): use the one the profile stores, for every protocol
        # that takes one - not only SSH/SCP, whose clients also look it up.
        if not password and profile.store_password and password_needed(profile):
            password = profile.get_password() or ""

        # Create new session based on protocol. Not under the lock: it is
        # network I/O (and may wait for a host-key prompt).
        session = self._create_session(resolved, password, key_passphrase, on_unknown_host)

        # Another thread may have connected the same key meanwhile (two
        # panes opening one profile). Keep the registered session so both
        # panes share one reference count; close the duplicate. Its
        # liveness is asked outside the lock: for several backends that
        # is network I/O.
        duplicate = None
        stale = None
        while True:
            with self._lock:
                existing = self._sessions.get(key)
            alive = existing is not None and self._is_connected(existing)
            with self._lock:
                if self._sessions.get(key) is not existing:
                    continue  # changed while we probed: look again
                if alive:
                    self._ref_counts[key] = self._ref_counts.get(key, 0) + 1
                    duplicate, session = session, existing
                else:
                    stale = self._retire_locked(key)
                    self._sessions[key] = session
                    self._ref_counts[key] = 1
                self._held.append((profile, key, session))
            break
        self._close_unheld(stale)
        if duplicate is not None:
            log.info("Concurrent connect for %s; closing the duplicate session", key[:4])
            try:
                self._disconnect_session(duplicate)
            except Exception as exc:  # noqa: BLE001
                log.debug("ConnectionManager: closing duplicate failed: %s", exc)
            self._decorate_session(session, profile, key)
            self._record_visit(profile)
            return session
        self._decorate_session(session, profile, key)
        self._enroll_health(session, profile, key)
        self._record_visit(profile)
        log.info(
            "New %s session established for %s@%s", profile.protocol, profile.username, profile.host
        )
        return session

    def _reuse_locked(
        self, key: tuple[str, ...], profile: ConnectionProfile | None = None
    ) -> object | None:
        """Take a reference on the live session for *key*, or drop a stale
        one and return None.

        Whether the session is alive is asked without the lock held: for
        SMB, WebDAV, NFS, Telnet and FTP that is a round trip to the
        server, and a server that stopped answering would otherwise make
        every other connect / release - the GUI thread's too - wait for
        its timeout."""
        while True:
            with self._lock:
                session = self._sessions.get(key)
            if session is None:
                return None
            alive = self._is_connected(session)
            with self._lock:
                if self._sessions.get(key) is not session:
                    continue  # replaced or released while we probed
                if alive:
                    self._ref_counts[key] = self._ref_counts.get(key, 0) + 1
                    if profile is not None:
                        self._held.append((profile, key, session))
                    log.info(
                        "Reusing existing session for %s (refs: %d)",
                        key[:4],
                        self._ref_counts[key],
                    )
                    return session
                log.info("Stale session for %s, reconnecting", key[:4])
                stale = self._retire_locked(key)
            break
        self._unenroll_health(key)
        self._close_unheld(stale)
        return None

    def _retire_locked(self, key: tuple[str, ...]) -> object | None:
        """Take the stale session under *key* out of service (lock held).

        Holders that still reference it keep counting on it, apart from
        the session that replaces it; the last of them closes it. Returns
        the session when nobody holds it, for the caller to close."""
        session = self._sessions.pop(key, None)
        refs = self._ref_counts.pop(key, 0)
        if session is None:
            return None
        if refs > 0:
            self._retired[id(session)] = [session, refs]
            return None
        return session

    def _close_unheld(self, session: object | None) -> None:
        if session is None:
            return
        try:
            self._disconnect_session(session)
        except Exception as exc:  # noqa: BLE001 - it is dead already
            log.debug("ConnectionManager: closing a stale session failed: %s", exc)

    @staticmethod
    def _decorate_session(
        session: object, profile: ConnectionProfile, key: tuple[str, ...]
    ) -> None:
        """Attach lightweight metadata used by scripting safety gates.

        Backends are intentionally duck-typed; if a very small object
        refuses dynamic attributes we log and continue. Safety helpers
        still no-op rather than breaking the connection.
        """
        try:
            setattr(session, "_axross_profile", profile)
            setattr(session, "_axross_profile_key", _health_key(key))
            setattr(session, "_axross_session_label", _profile_label(profile))
        except Exception as exc:  # noqa: BLE001
            log.debug("ConnectionManager: cannot decorate session: %s", exc)

    @staticmethod
    def _record_visit(profile: ConnectionProfile) -> None:
        try:
            from core.visit_history import record_visit

            record_visit(
                profile.protocol,
                profile.host,
                profile.username,
                path="",
                verb="connect",
                desc=_profile_label(profile),
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("ConnectionManager: visit_history hook failed: %s", exc)

    @staticmethod
    def _enroll_health(session: object, profile: ConnectionProfile, key: tuple[str, ...]) -> None:
        try:
            from core.conn_health import get_manager

            get_manager().enroll(
                _health_key(key),
                session,
                protocol=profile.protocol,
                label=_profile_label(profile),
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("ConnectionManager: conn_health enroll failed: %s", exc)

    @staticmethod
    def _unenroll_health(key: tuple[str, ...]) -> None:
        try:
            from core.conn_health import get_manager

            get_manager().unenroll(_health_key(key))
        except Exception as exc:  # noqa: BLE001
            log.debug("ConnectionManager: conn_health unenroll failed: %s", exc)

    def _create_session(
        self,
        profile: ConnectionProfile,
        password: str,
        key_passphrase: str,
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None,
    ) -> FileBackend:
        """Create and connect a new backend session based on protocol."""
        # A half-configured proxy must never silently become a direct
        # connection, especially for SFTP/SCP which consume the profile
        # directly instead of the proxy_kw dict below.
        _validate_proxy_request(profile)
        # Flag backends that would silently drop a user-configured proxy.
        _warn_unsupported_proxy(profile)
        if profile.proxy_command and not profile.proxy_command_confirmed:
            # An imported profile's shell command: the UI asks first.
            raise PermissionError(
                f"profile {profile.name!r} came in through an import and its "
                f"ProxyCommand ({profile.proxy_command!r}) has not been confirmed; "
                "confirm it in axross before it can run"
            )
        proto = profile.protocol
        from core.security_mode import require_protocol_allowed

        require_protocol_allowed(proto)

        if proto == "sftp":
            session = _session_class("SSHSession")(profile)
            session.connect(
                password=password,
                key_passphrase=key_passphrase,
                on_unknown_host=on_unknown_host,
                resolve_profile=self._profile_resolver,
            )
            return session

        if proto == "scp":
            session = _session_class("SCPSession")(profile)
            session.connect(
                password=password,
                key_passphrase=key_passphrase,
                on_unknown_host=on_unknown_host,
                resolve_profile=self._profile_resolver,
            )
            return session

        proxy_kw = _proxy_kwargs(profile)

        if proto in ("ftp", "ftps"):
            cls = load_backend_class(proto)
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                tls=(proto == "ftps"),
                passive=profile.ftp_passive,
                verify_tls=profile.ftps_verify_tls,
                **proxy_kw,
            )

        if proto == "smb":
            cls = load_backend_class("smb")
            return cls(
                host=profile.host,
                share=profile.smb_share,
                username=profile.username,
                password=password,
                port=profile.port,
                client_name=profile.smb_client_name,
                **proxy_kw,
            )

        if proto == "dfsn":
            cls = load_backend_class("dfsn")
            return cls(
                host=profile.host,
                namespace=profile.smb_share,
                username=profile.username,
                password=password,
                port=profile.port or 445,
                **proxy_kw,
            )

        if proto == "webdav":
            cls = load_backend_class("webdav")
            return cls(
                url=profile.webdav_url,
                username=profile.username,
                password=password,
                # Webdavclient3 exposes its requests.Session — we can
                # push a proxy onto it. Covers SOCKS4/5 + HTTP CONNECT.
                **proxy_kw,
            )

        if proto == "s3":
            cls = load_backend_class("s3")
            return cls(
                bucket=profile.s3_bucket,
                region=profile.s3_region,
                access_key=profile.username,
                secret_key=password,
                endpoint=profile.s3_endpoint or None,
                **proxy_kw,
            )

        if proto == "rsync":
            cls = load_backend_class("rsync")
            return cls(
                host=profile.host,
                port=profile.port,
                module=profile.rsync_module,
                username=profile.username,
                password=password,
                ssh_mode=profile.rsync_ssh,
                ssh_key=profile.rsync_ssh_key,
                preserve_metadata=profile.rsync_preserve_metadata,
                **proxy_kw,
            )

        if proto == "nfs":
            cls = load_backend_class("nfs")
            return cls(
                host=profile.host,
                export_path=profile.nfs_export,
                port=profile.port,
                version=profile.nfs_version,
                **proxy_kw,
            )

        if proto == "azure_blob":
            cls = load_backend_class("azure_blob")
            return cls(
                connection_string=profile.azure_connection_string,
                account_name=profile.azure_account_name or profile.username,
                account_key=password,
                container=profile.azure_container,
                sas_token=profile.azure_sas_token,
                **proxy_kw,
            )

        if proto == "azure_files":
            cls = load_backend_class("azure_files")
            return cls(
                connection_string=profile.azure_connection_string,
                account_name=profile.azure_account_name or profile.username,
                account_key=password,
                share_name=profile.azure_share,
                sas_token=profile.azure_sas_token,
                **proxy_kw,
            )

        if proto in ("onedrive", "sharepoint"):
            cls = load_backend_class("onedrive")
            return cls(
                client_id=profile.onedrive_client_id,
                tenant_id=profile.onedrive_tenant_id,
                drive_type="sharepoint" if proto == "sharepoint" else "personal",
                site_url=profile.sharepoint_site_url,
                **_profile_token_files("onedrive_token", profile.name),
                **proxy_kw,
            )

        if proto == "gdrive":
            cls = load_backend_class("gdrive")
            return cls(
                client_id=profile.gdrive_client_id,
                client_secret=password or profile.gdrive_client_secret,
                **_profile_token_files("gdrive_token", profile.name),
                **proxy_kw,
            )

        if proto == "dropbox":
            cls = load_backend_class("dropbox")
            return cls(
                app_key=profile.dropbox_app_key,
                app_secret=password or profile.dropbox_app_secret,
                **_profile_token_files("dropbox_token", profile.name),
                **proxy_kw,
            )

        if proto == "iscsi":
            cls = load_backend_class("iscsi")
            session = cls(
                target_ip=profile.host,
                target_iqn=profile.iscsi_target_iqn,
                port=profile.port,
                username=profile.username,
                password=password,
                mount_point=profile.iscsi_mount_point,
                **proxy_kw,
            )
            if not session.connected:
                session.connect()
            return session

        if proto == "imap":
            cls = load_backend_class("imap")
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                use_ssl=profile.imap_ssl,
                **proxy_kw,
            )

        if proto == "pop3":
            cls = load_backend_class("pop3")
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                use_ssl=profile.pop3_ssl,
                **proxy_kw,
            )

        if proto == "nntp":
            cls = load_backend_class("nntp")
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                use_tls=profile.nntp_ssl,
                **proxy_kw,
            )

        if proto == "tftp":
            cls = load_backend_class("tftp")
            # The profile stores filelist as a comma-separated string
            # (JSON-friendly, single-field UI). Split here.
            raw_list = (profile.tftp_filelist or "").strip()
            filelist = [x.strip() for x in raw_list.split(",") if x.strip()]
            return cls(
                host=profile.host,
                port=profile.port or 69,
                filelist=filelist,
                filelist_enabled=profile.tftp_filelist_enabled,
                max_size_bytes=profile.tftp_max_size_bytes,
                **proxy_kw,
            )

        if proto == "ramfs":
            cls = load_backend_class("ramfs")
            from core.ramfs_settings import get_settings

            settings = get_settings()
            if not settings.ramfs_enabled:
                raise OSError(
                    "RamFS is disabled in settings (ramfs.json). "
                    "Set ramfs_enabled=true to use a RAM workspace.",
                )
            # The profile's `name` doubles as the workspace label so
            # the user sees "RAM:my-staging" rather than a generic tag.
            return cls(
                label=profile.name or "ramfs",
                max_bytes=settings.ramfs_max_bytes,
                system_reserve_bytes=settings.ramfs_system_reserve_bytes,
            )

        if proto == "svn":
            cls = load_backend_class("svn")
            return cls(
                url=profile.host,
                username=profile.username,
                password=password,
                **proxy_kw,
            )

        if proto == "telnet":
            cls = load_backend_class("telnet")
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                naws_width=profile.telnet_naws_width,
                naws_height=profile.telnet_naws_height,
                **proxy_kw,
            )

        if proto == "cisco-telnet":
            cls = load_backend_class("cisco-telnet")
            return cls(
                host=profile.host,
                port=profile.port or 23,
                username=profile.username,
                password=password,
                **proxy_kw,
            )

        if proto == "adb":
            cls = load_backend_class("adb")
            if profile.adb_mode == "usb":
                # USB transport doesn't use TCP — proxy can't apply.
                if proxy_kw:
                    log.warning(
                        "Profile %r configures a proxy for ADB USB mode; "
                        "the ADB backend will reject this unsupported "
                        "combination.",
                        profile.name,
                    )
                return cls(
                    usb=True,
                    usb_serial=profile.adb_usb_serial,
                    **proxy_kw,
                )
            return cls(
                host=profile.host,
                port=profile.port or 5555,
                **proxy_kw,
            )

        if proto == "mtp":
            from core.mtp_client import MtpDevice

            cls = load_backend_class("mtp")
            device = MtpDevice(
                device_id=profile.mtp_device_id or "1",
                vendor="",
                product=profile.host or "device",
                mounter=profile.mtp_mounter,
            )
            return cls(
                device,
                mounter=profile.mtp_mounter or None,
            )

        if proto == "gopher":
            cls = load_backend_class("gopher")
            return cls(
                host=profile.host,
                port=profile.port or 70,
                username=profile.username,
                password=password,
                **proxy_kw,
            )

        if proto == "pjl":
            cls = load_backend_class("pjl")
            return cls(
                host=profile.host,
                port=profile.port or 9100,
                username=profile.username,
                password=password,
                **proxy_kw,
            )

        if proto == "winrm":
            cls = load_backend_class("winrm")
            return cls(
                host=profile.host,
                port=profile.port or 5986,
                username=profile.username,
                password=password,
                **proxy_kw,
            )

        raise ValueError(f"Unsupported protocol: {proto}")

    @staticmethod
    def _is_connected(session: object) -> bool:
        """Check if a session is still connected."""
        if hasattr(session, "connected"):
            return session.connected
        # Non-SSH backends: assume connected if the object exists
        return True

    def _held_key_locked(
        self, profile: ConnectionProfile, *, take: bool
    ) -> tuple[str, ...] | None:
        """Session key of a reference *profile* holds; *take* removes it."""
        entry = self._held_entry_locked(profile, take=take)
        return entry[0] if entry is not None else None

    def _held_entry_locked(
        self, profile: ConnectionProfile, *, take: bool
    ) -> tuple[tuple[str, ...], object] | None:
        """(key, session) of a reference *profile* holds: the same object
        first, then an equal copy; *take* removes it.

        release() names only the profile, and two panes on one profile
        pass the same object. A reference on a replaced (retired)
        session is given back before one on the live session: whichever
        holder is closing, the live session then outlasts every pane
        that still uses it. Otherwise the newest reference."""
        for same in (lambda held: held is profile, lambda held: held == profile):
            chosen = None
            for idx in range(len(self._held) - 1, -1, -1):
                held_profile, key, session = self._held[idx]
                if not same(held_profile):
                    continue
                if chosen is None:
                    chosen = idx
                if not take:
                    break
                if self._sessions.get(key) is not session:
                    chosen = idx
                    break
            if chosen is not None:
                _held_profile, key, session = self._held[chosen]
                if take:
                    del self._held[chosen]
                return key, session
        return None

    def acquire(self, profile: ConnectionProfile) -> bool:
        """Take one more reference on the live session *profile* holds
        (a terminal pane beside a file pane). False when there is none;
        then nothing is taken and the caller connects on its own."""
        with self._lock:
            key = self._held_key_locked(profile, take=False)
            if key is None or key not in self._sessions:
                return False
            self._ref_counts[key] = self._ref_counts.get(key, 0) + 1
            self._held.append((profile, key, self._sessions[key]))
            return True

    def release(self, profile: ConnectionProfile) -> None:
        """Release a reference to a session. Disconnects when no more references."""
        with self._lock:
            entry = self._held_entry_locked(profile, take=True)
            retired = None
            if entry is not None:
                key, held_session = entry
                if self._sessions.get(key) is not held_session:
                    retired = self._release_retired_locked(held_session)
                    if retired is None:
                        return
            key = entry[0] if entry is not None else None
        if retired is not None:
            # The last holder of a replaced session: close it. The key's
            # health enrolment belongs to the session that replaced it.
            self._close_unheld(retired)
            log.info("Disconnected replaced session %s (no more references)", key[:4])
            return
        if key is None:
            # A reference not taken through connect() / acquire().
            try:
                key = self._session_key(profile)
            except ConnectionError as exc:  # PAC unreadable: nothing to match
                log.debug("release: no session key for %s: %s", profile.name, exc)
                return
        with self._lock:
            if key not in self._ref_counts:
                return

            self._ref_counts[key] -= 1
            log.debug("Released session %s (refs: %d)", key[:4], self._ref_counts[key])

            if self._ref_counts[key] > 0:
                return
            session = self._sessions.pop(key, None)
            self._ref_counts.pop(key, None)
        self._unenroll_health(key)
        if session:
            self._disconnect_session(session)
            log.info("Disconnected session %s (no more references)", key[:4])

    def _release_retired_locked(self, session: object) -> object | None:
        """Give back one reference on a replaced session (lock held);
        returns it once the last one is gone, for the caller to close."""
        record = self._retired.get(id(session))
        if record is None or record[0] is not session:
            return None
        record[1] -= 1
        if record[1] > 0:
            return None
        del self._retired[id(session)]
        return session

    def disconnect_all(self) -> None:
        """Disconnect all sessions."""
        with self._lock:
            sessions = list(self._sessions.items())
            retired = [record[0] for record in self._retired.values()]
            self._sessions.clear()
            self._ref_counts.clear()
            self._held.clear()
            self._retired.clear()
        for session in retired:
            self._close_unheld(session)
        for key, session in sessions:
            try:
                self._unenroll_health(key)
                self._disconnect_session(session)
            except Exception as e:
                log.error("Error disconnecting %s: %s", key[:4], e)
        log.info("All sessions disconnected")

    @staticmethod
    def _disconnect_session(session: object) -> None:
        """Disconnect a session, handling different backend types."""
        if hasattr(session, "disconnect"):
            session.disconnect()
        elif hasattr(session, "close"):
            session.close()

    def get_session(self, profile: ConnectionProfile) -> object | None:
        """Get an existing session without connecting."""
        with self._lock:
            key = self._held_key_locked(profile, take=False)
        if key is None:
            key = self._session_key(profile)
        with self._lock:
            session = self._sessions.get(key)
        if session and self._is_connected(session):
            return session
        return None

    def active_sessions(self) -> list:
        """Return all active sessions."""
        with self._lock:
            sessions = list(self._sessions.values())
        return [s for s in sessions if self._is_connected(s)]
