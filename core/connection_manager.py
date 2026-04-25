"""Connection manager — manages backend sessions with reference counting."""
from __future__ import annotations

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
# Everything else either ignores it entirely or inherits from OS env
# vars — see docs/PROXY_SUPPORT.md. We warn once per connect when a
# user sets a proxy on an unsupported backend so the setting isn't
# silently swallowed.
_PROTOCOLS_HONOURING_PROFILE_PROXY = frozenset({
    "sftp", "scp",
    "webdav",   # uses requests.Session proxy
    "telnet",   # we own the socket; swapped in with create_proxy_socket
})

# Cloud backends that at least inherit HTTPS_PROXY / HTTP_PROXY from
# the process environment.
_PROTOCOLS_INHERITING_ENV_PROXY = frozenset({
    "s3", "azure_blob", "azure_files",
    "onedrive", "sharepoint", "gdrive", "dropbox",
})


def _warn_unsupported_proxy(profile: "ConnectionProfile") -> None:
    """Emit a WARNING when the profile's proxy config will not take
    effect for the chosen protocol. Called from ``_create_session``
    before we instantiate the backend."""
    if profile.proxy_type in (None, "", "none"):
        return
    proto = profile.protocol
    if proto in _PROTOCOLS_HONOURING_PROFILE_PROXY:
        return
    if proto in _PROTOCOLS_INHERITING_ENV_PROXY:
        log.warning(
            "Profile %r uses %s but %s only honours HTTPS_PROXY / "
            "HTTP_PROXY from the process environment, NOT the "
            "per-profile proxy fields. See docs/PROXY_SUPPORT.md.",
            profile.name, profile.proxy_type, proto,
        )
    else:
        log.warning(
            "Profile %r configures a %s proxy, but the %s backend "
            "has no proxy plumbing — the setting is ignored. See "
            "docs/PROXY_SUPPORT.md.",
            profile.name, profile.proxy_type, proto,
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
            profile.proxy_type,
            profile.proxy_host,
            str(profile.proxy_port),
            profile.proxy_username,
            profile.proxy_command,
            profile.address_family,
            # Protocol-specific discriminators
            profile.smb_share,
            profile.s3_bucket,
            profile.webdav_url,
            profile.rsync_module,
            str(profile.rsync_ssh),
            profile.rsync_ssh_key,
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
                log.info("Reusing existing session for %s (refs: %d)", key[:4], self._ref_counts[key])
                return session
            else:
                log.info("Stale session for %s, reconnecting", key[:4])
                del self._sessions[key]
                self._ref_counts.pop(key, None)

        # Create new session based on protocol
        session = self._create_session(profile, password, key_passphrase, on_unknown_host)

        self._sessions[key] = session
        self._ref_counts[key] = 1
        log.info("New %s session established for %s@%s", profile.protocol, profile.username, profile.host)
        return session

    def _create_session(
        self,
        profile: ConnectionProfile,
        password: str,
        key_passphrase: str,
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None,
    ) -> FileBackend:
        """Create and connect a new backend session based on protocol."""
        # Flag backends that would silently drop a user-configured proxy.
        _warn_unsupported_proxy(profile)
        proto = profile.protocol

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
            )

        if proto == "webdav":
            cls = load_backend_class("webdav")
            return cls(
                url=profile.webdav_url,
                username=profile.username,
                password=password,
                # Webdavclient3 exposes its requests.Session — we can
                # push a proxy onto it. Covers SOCKS4/5 + HTTP CONNECT.
                proxy_type=profile.proxy_type,
                proxy_host=profile.proxy_host,
                proxy_port=profile.proxy_port,
                proxy_username=profile.proxy_username,
                proxy_password=profile.get_proxy_password() or "",
            )

        if proto == "s3":
            cls = load_backend_class("s3")
            return cls(
                bucket=profile.s3_bucket,
                region=profile.s3_region,
                access_key=profile.username,
                secret_key=password,
                endpoint=profile.s3_endpoint or None,
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
            )

        if proto == "azure_files":
            cls = load_backend_class("azure_files")
            return cls(
                connection_string=profile.azure_connection_string,
                account_name=profile.azure_account_name or profile.username,
                account_key=password,
                share_name=profile.azure_share,
                sas_token=profile.azure_sas_token,
            )

        if proto in ("onedrive", "sharepoint"):
            cls = load_backend_class("onedrive")
            return cls(
                client_id=profile.onedrive_client_id,
                tenant_id=profile.onedrive_tenant_id,
                drive_type="sharepoint" if proto == "sharepoint" else "personal",
                site_url=profile.sharepoint_site_url,
            )

        if proto == "gdrive":
            cls = load_backend_class("gdrive")
            return cls(
                client_id=profile.gdrive_client_id,
                client_secret=password or profile.gdrive_client_secret,
            )

        if proto == "dropbox":
            cls = load_backend_class("dropbox")
            return cls(
                app_key=profile.dropbox_app_key,
                app_secret=password or profile.dropbox_app_secret,
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
            )

        if proto == "telnet":
            cls = load_backend_class("telnet")
            return cls(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                # Telnet is plain TCP — tunnel it through the proxy if
                # one is configured.
                proxy_type=profile.proxy_type,
                proxy_host=profile.proxy_host,
                proxy_port=profile.proxy_port,
                proxy_username=profile.proxy_username,
                proxy_password=profile.get_proxy_password() or "",
                naws_width=profile.telnet_naws_width,
                naws_height=profile.telnet_naws_height,
            )

        if proto == "adb":
            cls = load_backend_class("adb")
            if profile.adb_mode == "usb":
                return cls(
                    usb=True,
                    usb_serial=profile.adb_usb_serial,
                )
            return cls(
                host=profile.host,
                port=profile.port or 5555,
            )

        if proto == "mtp":
            from core.mtp_client import MtpDevice
            cls = load_backend_class("mtp")
            device = MtpDevice(
                device_id=profile.mtp_device_id or "1",
                vendor="", product=profile.host or "device",
                mounter=profile.mtp_mounter,
            )
            return cls(
                device,
                mounter=profile.mtp_mounter or None,
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
            if session:
                self._disconnect_session(session)
                log.info("Disconnected session %s (no more references)", key[:4])

    def disconnect_all(self) -> None:
        """Disconnect all sessions."""
        for key, session in list(self._sessions.items()):
            try:
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
