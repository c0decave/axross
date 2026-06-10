"""Connection manager — manages backend sessions with reference counting."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

from core.backend_registry import load_backend_class
from core.profiles import ConnectionProfile
from core.scp_client import SCPSession
from core.ssh_client import SSHSession, UnknownHostKeyError

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)


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
    }
)

_PROTOCOLS_PARTIAL_PROFILE_PROXY = {
    "s3": "S3 supports HTTP CONNECT proxies only; botocore rejects SOCKS proxy URLs.",
    # exchange honours it but only with autodiscover=False — the
    # backend itself raises a clear error in the autodiscover-on case
    # when constructed directly.
    "exchange": (
        "Exchange supports proxies only when autodiscover=False and an explicit "
        "server is supplied; saved profiles do not expose those fields yet."
    ),
}

# Backends that genuinely cannot be proxied — kernel-level mounts
# plus TFTP (UDP; common SOCKS proxies don't support UDP-ASSOCIATE
# and HTTP CONNECT is TCP-only) plus RamFS (in-process, no network
# at all).
_PROTOCOLS_NOT_PROXIABLE = {
    "nfs": "NFS is mounted by the kernel; user-space SOCKS/HTTP proxies cannot see it.",
    "iscsi": "iSCSI is handled by the kernel initiator; proxy at the OS/network layer instead.",
    "mtp": "MTP is USB/FUSE based here, not a TCP transport.",
    "tftp": "TFTP is UDP; HTTP CONNECT is TCP-only and SOCKS UDP-ASSOCIATE is not implemented.",
    "ramfs": "RamFS is in-process memory and has no network path.",
    "sqlite": "SQLite is a local file backend and has no network path.",
    "postgres": "PostgreSQL proxy tunnelling is not implemented for psycopg connections.",
    "redis": "Redis proxy tunnelling is not implemented for redis-py connections.",
    "mongodb": "MongoDB proxy tunnelling is not implemented for pymongo connections.",
    "git": "Git transport proxying is not uniform across dulwich HTTP/SSH transports.",
    "svn": "SVN uses the system svn binary; SOCKS/HTTP CONNECT is not wired in.",
    "slp": "SLP defaults to UDP and is not proxied by axross.",
    "rsh": "rsh uses the system rsh binary and cannot be tunnelled by axross.",
    "wmi": "WMI/DCOM uses RPC/DCOM with dynamic transport details; proxying is not implemented.",
    "ldap": "LDAP proxy tunnelling is not implemented for ldap3 connections.",
}


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
    """Emit a WARNING when the profile's proxy config will not take
    effect for the chosen protocol. Called from ``_create_session``
    before we instantiate the backend."""
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
    if proto in _PROTOCOLS_HONOURING_PROFILE_PROXY:
        return
    if proto == "s3":
        if _proxy_kind(profile) == "http":
            return
        log.warning(
            "Profile %r configures a %s proxy, but S3 proxy support is "
            "limited: %s See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
            _PROTOCOLS_PARTIAL_PROFILE_PROXY["s3"],
        )
        return
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
    if proto in _PROTOCOLS_NOT_PROXIABLE:
        log.warning(
            "Profile %r configures a %s proxy, but %s does not support "
            "SOCKS/HTTP proxy tunnelling in axross. %s The setting is "
            "ignored. See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
            proto,
            _PROTOCOLS_NOT_PROXIABLE[proto],
        )
    else:
        log.warning(
            "Profile %r configures a %s proxy, but the %s backend "
            "has no proxy plumbing yet. See docs/PROXY_SUPPORT.md.",
            profile.name,
            profile.proxy_type,
            proto,
        )


class ConnectionManager:
    """Manages backend sessions keyed by endpoint and network settings.

    Multiple panes connecting to the same endpoint may reuse one session
    if the effective network route is the same.
    """

    def __init__(self):
        self._sessions: dict[tuple[str, ...], object] = {}
        self._ref_counts: dict[tuple[str, ...], int] = {}
        self._profile_resolver: Callable[[str], ConnectionProfile | None] | None = None

    def set_profile_resolver(self, resolver: Callable[[str], ConnectionProfile | None]) -> None:
        """Set a callback to resolve profile names (for ProxyCommand alias expansion)."""
        self._profile_resolver = resolver

    def _session_key(self, profile: ConnectionProfile) -> tuple[str, ...]:
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
        key = self._session_key(profile)

        # Reuse existing active session
        if key in self._sessions:
            session = self._sessions[key]
            if self._is_connected(session):
                self._ref_counts[key] = self._ref_counts.get(key, 0) + 1
                log.info(
                    "Reusing existing session for %s (refs: %d)", key[:4], self._ref_counts[key]
                )
                self._decorate_session(session, profile, key)
                self._record_visit(profile)
                return session
            else:
                log.info("Stale session for %s, reconnecting", key[:4])
                self._unenroll_health(key)
                del self._sessions[key]
                self._ref_counts.pop(key, None)

        # Create new session based on protocol
        session = self._create_session(profile, password, key_passphrase, on_unknown_host)

        self._sessions[key] = session
        self._ref_counts[key] = 1
        self._decorate_session(session, profile, key)
        self._enroll_health(session, profile, key)
        self._record_visit(profile)
        log.info(
            "New %s session established for %s@%s", profile.protocol, profile.username, profile.host
        )
        return session

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
        proto = profile.protocol
        from core.security_mode import require_protocol_allowed

        require_protocol_allowed(proto)

        if proto == "sftp":
            session = SSHSession(profile)
            session.connect(
                password=password,
                key_passphrase=key_passphrase,
                on_unknown_host=on_unknown_host,
                resolve_profile=self._profile_resolver,
            )
            return session

        if proto == "scp":
            session = SCPSession(profile)
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
                **proxy_kw,
            )

        if proto == "gdrive":
            cls = load_backend_class("gdrive")
            return cls(
                client_id=profile.gdrive_client_id,
                client_secret=password or profile.gdrive_client_secret,
                **proxy_kw,
            )

        if proto == "dropbox":
            cls = load_backend_class("dropbox")
            return cls(
                app_key=profile.dropbox_app_key,
                app_secret=password or profile.dropbox_app_secret,
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

    def release(self, profile: ConnectionProfile) -> None:
        """Release a reference to a session. Disconnects when no more references."""
        key = self._session_key(profile)
        if key not in self._ref_counts:
            return

        self._ref_counts[key] -= 1
        log.debug("Released session %s (refs: %d)", key[:4], self._ref_counts[key])

        if self._ref_counts[key] <= 0:
            session = self._sessions.pop(key, None)
            self._ref_counts.pop(key, None)
            self._unenroll_health(key)
            if session:
                self._disconnect_session(session)
                log.info("Disconnected session %s (no more references)", key[:4])

    def disconnect_all(self) -> None:
        """Disconnect all sessions."""
        for key, session in list(self._sessions.items()):
            try:
                self._unenroll_health(key)
                self._disconnect_session(session)
            except Exception as e:
                log.error("Error disconnecting %s: %s", key[:4], e)
        self._sessions.clear()
        self._ref_counts.clear()
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
        key = self._session_key(profile)
        session = self._sessions.get(key)
        if session and self._is_connected(session):
            return session
        return None

    def active_sessions(self) -> list:
        """Return all active sessions."""
        return [s for s in self._sessions.values() if self._is_connected(s)]
