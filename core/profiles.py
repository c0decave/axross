"""Connection profile management — JSON storage under XDG config."""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from core.credentials import (
    delete_secret,
    delete_proxy_password,
    delete_password,
    get_secret,
    get_password,
    store_secret,
    get_proxy_password,
    store_password,
    store_proxy_password,
)

log = logging.getLogger(__name__)


import re as _re

# Allowlisted character set for USB serials. Real-world Android
# vendors use either uppercase alphanumerics (e.g. ``ABCD1234EF``)
# or 16-byte hex strings. Underscore + dash are tolerated because
# some emulators use them. ANYTHING outside the set — including
# CR/LF, ANSI escapes, null bytes — is stripped at load time.
_USB_SERIAL_SAFE_RE = _re.compile(r"[^A-Za-z0-9_\-]")

# MTP device_id allowlist (mirrors the stricter one in
# core.mtp_client — we sanitise at load time as defence-in-depth).
_MTP_DEVICE_ID_SAFE_RE = _re.compile(r"[^0-9:.\-]")

# Known MTP mounter binaries; anything else collapses to "" so the
# backend's auto-pick kicks in.
_MTP_KNOWN_MOUNTERS = frozenset({"jmtpfs", "simple-mtpfs", "go-mtpfs"})


def _sanitize_usb_serial(value: str) -> str:
    return _USB_SERIAL_SAFE_RE.sub("", value or "")


def _sanitize_mtp_device_id(value: str) -> str:
    cleaned = _MTP_DEVICE_ID_SAFE_RE.sub("", value or "")
    # Never let the sanitiser produce an empty string — the backend
    # needs SOMETHING to pass to jmtpfs. "1" is the safest default
    # (first device on every supported mounter).
    return cleaned or "1"


def _sanitize_mtp_mounter(value: str) -> str:
    return value if value in _MTP_KNOWN_MOUNTERS else ""


CONFIG_DIR = Path.home() / ".config" / "axross"
PROFILES_FILE = CONFIG_DIR / "profiles.json"


VALID_PROTOCOLS = {
    "sftp", "scp", "ftp", "ftps", "smb", "webdav", "s3",
    "rsync", "nfs", "azure_blob", "azure_files",
    "onedrive", "sharepoint", "gdrive", "dropbox", "iscsi", "imap",
    "pop3",
    "tftp",
    "ramfs",
    "telnet", "adb", "mtp",
}

SENSITIVE_PROFILE_FIELDS = (
    "azure_connection_string",
    "azure_sas_token",
    "gdrive_client_secret",
    "dropbox_app_secret",
)


@dataclass
class ConnectionProfile:
    """A saved connection profile (multi-protocol)."""

    name: str = ""
    protocol: str = "sftp"  # "sftp", "ftp", "ftps", "smb", "webdav", "s3"
    host: str = ""
    port: int = 22
    username: str = ""
    auth_type: str = "password"  # "password", "key", "agent"
    key_file: str = ""
    store_password: bool = False

    # Proxy settings
    proxy_type: str = "none"  # "none", "socks4", "socks5", "http"
    proxy_host: str = ""
    proxy_port: int = 0
    proxy_username: str = ""
    store_proxy_password: bool = False

    # SSH ProxyCommand (alternative to SOCKS/HTTP proxy)
    proxy_command: str = ""  # e.g. "ssh -W %h:%p jumphost"

    # Address family preference
    address_family: str = "auto"  # "auto", "ipv4", "ipv6"

    # --- Protocol-specific fields ---
    # FTP/FTPS
    ftp_passive: bool = True
    # FTPS-only: whether to verify the server's TLS certificate chain
    # and hostname. Default is True (secure); users connecting to
    # internal / lab servers with self-signed certs can flip this to
    # False per-profile.
    ftps_verify_tls: bool = True

    # SMB
    smb_share: str = ""

    # WebDAV
    webdav_url: str = ""  # Full URL (e.g. https://cloud.example.com/remote.php/dav)

    # S3-compatible
    s3_bucket: str = ""
    s3_region: str = ""
    s3_endpoint: str = ""  # Custom endpoint for MinIO, Ceph, Wasabi, R2

    # Rsync
    rsync_module: str = ""  # rsyncd module name
    rsync_ssh: bool = False  # True = rsync over SSH, False = native rsync protocol
    rsync_ssh_key: str = ""

    # NFS
    nfs_export: str = ""  # e.g. /srv/nfs/share
    nfs_version: int = 3  # NFS version (3 or 4)

    # Azure Blob
    azure_container: str = ""
    azure_connection_string: str = ""
    azure_account_name: str = ""
    azure_sas_token: str = ""

    # Azure Files
    azure_share: str = ""

    # OneDrive / SharePoint
    onedrive_client_id: str = ""
    onedrive_tenant_id: str = "common"
    sharepoint_site_url: str = ""

    # Google Drive
    gdrive_client_id: str = ""
    gdrive_client_secret: str = ""

    # Dropbox
    dropbox_app_key: str = ""
    dropbox_app_secret: str = ""

    # iSCSI
    iscsi_target_iqn: str = ""
    iscsi_mount_point: str = ""

    # IMAP
    imap_ssl: bool = True

    # POP3 (read-only)
    pop3_ssl: bool = True

    # TFTP (UDP — no proxy support; opt-in file-list since TFTP
    # has no native LIST). ``tftp_filelist`` is a comma-separated
    # list of filenames in profiles.json, deserialised to a Python
    # list. ``tftp_max_size_bytes`` caps each transfer.
    tftp_filelist: str = ""
    tftp_filelist_enabled: bool = False
    tftp_max_size_bytes: int = 16 * 1024 * 1024

    # ADB (Android Debug Bridge)
    adb_mode: str = "tcp"          # "tcp" or "usb"
    adb_usb_serial: str = ""       # USB serial filter (optional)

    # MTP (Android via FUSE mount)
    mtp_device_id: str = "1"       # jmtpfs 1-based index / simple-mtpfs id
    mtp_mounter: str = ""          # "" = auto-pick first available

    # --- OpSec / client-identity overrides (see docs/OPSEC.md) ---
    #
    # SSH keepalive in seconds. 0 = disabled (default — blends with
    # OpenSSH's own default). Values > 0 enable per-session keepalive
    # at that interval. Fingerprinting observers can spot a fixed
    # 30-s cadence, so this is off unless the user opts in for a
    # specific NAT-bound profile.
    ssh_keepalive_interval: int = 0

    # SMB NTLM WorkstationName override. Empty string → fall back to
    # the module-level default (``core.client_identity.SMB_CLIENT_NAME``,
    # currently "WORKSTATION"). Set per-profile to mimic a specific
    # Windows machine name your environment expects, or leave alone
    # for the uniform-across-installs default.
    smb_client_name: str = ""

    # Telnet NAWS geometry override. 0 → module default (80×24). Set
    # per-profile if the server expects a specific geometry.
    telnet_naws_width: int = 0
    telnet_naws_height: int = 0

    # rsync: default is to strip local uid/gid/perms/mtime on upload
    # so the receiver can't correlate the file back to the client's
    # UID scheme. Set True on a per-profile basis when doing a true
    # archive/backup flow where metadata preservation matters.
    rsync_preserve_metadata: bool = False

    # Shell-history suppression: when True (the safe default), the
    # SSH/Telnet terminal flow silently disables HISTFILE / HISTSIZE /
    # zsh-savehist on the remote shell so red-team / forensic engagements
    # don't leak through ``~/.bash_history``. Users running their own
    # boxes can flip this off per-profile to keep normal history.
    suppress_shell_history: bool = True

    # Terminal theme name (matches keys in ``ui.terminal_widget.TERMINAL_THEMES``).
    # Empty string keeps the dock default. Valid: Dark / Solarized-Dark
    # / Solarized-Light / Hacker / Amber / Light.
    terminal_theme: str = ""

    def get_password(self) -> str | None:
        """Retrieve password from keyring."""
        if self.store_password:
            return get_password(self.name)
        return None

    def set_password(self, password: str) -> None:
        """Store password in keyring."""
        if self.store_password:
            store_password(self.name, password)

    def get_proxy_password(self) -> str | None:
        """Retrieve proxy password from keyring."""
        if self.store_proxy_password:
            return get_proxy_password(self.name)
        return None

    def set_proxy_password(self, password: str) -> None:
        """Store proxy password in keyring."""
        if self.store_proxy_password:
            store_proxy_password(self.name, password)

    def to_dict(self) -> dict:
        """Serialize to dict — only includes relevant fields per protocol."""
        d: dict = {
            "name": self.name,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth_type": self.auth_type,
            "store_password": self.store_password,
        }

        # Key-based auth
        if self.key_file:
            d["key_file"] = self.key_file

        # Proxy (only if configured)
        if self.proxy_type != "none":
            d["proxy_type"] = self.proxy_type
            d["proxy_host"] = self.proxy_host
            d["proxy_port"] = self.proxy_port
            if self.proxy_username:
                d["proxy_username"] = self.proxy_username
            d["store_proxy_password"] = self.store_proxy_password

        # SSH ProxyCommand (only if set)
        if self.proxy_command:
            d["proxy_command"] = self.proxy_command

        # Address family (only if not default)
        if self.address_family != "auto":
            d["address_family"] = self.address_family

        # Protocol-specific fields
        proto = self.protocol

        if proto in ("ftp", "ftps"):
            d["ftp_passive"] = self.ftp_passive
            if proto == "ftps" and not self.ftps_verify_tls:
                d["ftps_verify_tls"] = False

        elif proto == "smb":
            d["smb_share"] = self.smb_share

        elif proto == "webdav":
            d["webdav_url"] = self.webdav_url

        elif proto == "s3":
            d["s3_bucket"] = self.s3_bucket
            if self.s3_region:
                d["s3_region"] = self.s3_region
            if self.s3_endpoint:
                d["s3_endpoint"] = self.s3_endpoint

        elif proto == "rsync":
            d["rsync_module"] = self.rsync_module
            d["rsync_ssh"] = self.rsync_ssh
            if self.rsync_ssh_key:
                d["rsync_ssh_key"] = self.rsync_ssh_key

        elif proto == "nfs":
            d["nfs_export"] = self.nfs_export
            d["nfs_version"] = self.nfs_version

        elif proto == "azure_blob":
            d["azure_container"] = self.azure_container
            if self.azure_account_name:
                d["azure_account_name"] = self.azure_account_name
            # Secrets not persisted in JSON

        elif proto == "azure_files":
            d["azure_share"] = self.azure_share
            if self.azure_account_name:
                d["azure_account_name"] = self.azure_account_name

        elif proto in ("onedrive", "sharepoint"):
            if self.onedrive_client_id:
                d["onedrive_client_id"] = self.onedrive_client_id
            if self.onedrive_tenant_id != "common":
                d["onedrive_tenant_id"] = self.onedrive_tenant_id
            if proto == "sharepoint" and self.sharepoint_site_url:
                d["sharepoint_site_url"] = self.sharepoint_site_url

        elif proto == "gdrive":
            if self.gdrive_client_id:
                d["gdrive_client_id"] = self.gdrive_client_id
            # client_secret not persisted

        elif proto == "dropbox":
            if self.dropbox_app_key:
                d["dropbox_app_key"] = self.dropbox_app_key
            # app_secret not persisted

        elif proto == "iscsi":
            d["iscsi_target_iqn"] = self.iscsi_target_iqn
            if self.iscsi_mount_point:
                d["iscsi_mount_point"] = self.iscsi_mount_point

        elif proto == "imap":
            d["imap_ssl"] = self.imap_ssl

        elif proto == "pop3":
            d["pop3_ssl"] = self.pop3_ssl

        elif proto == "tftp":
            if self.tftp_filelist:
                d["tftp_filelist"] = self.tftp_filelist
            if self.tftp_filelist_enabled:
                d["tftp_filelist_enabled"] = True
            if self.tftp_max_size_bytes != 16 * 1024 * 1024:
                d["tftp_max_size_bytes"] = self.tftp_max_size_bytes

        elif proto == "adb":
            d["adb_mode"] = self.adb_mode
            if self.adb_usb_serial:
                d["adb_usb_serial"] = self.adb_usb_serial

        elif proto == "mtp":
            if self.mtp_device_id:
                d["mtp_device_id"] = self.mtp_device_id
            if self.mtp_mounter:
                d["mtp_mounter"] = self.mtp_mounter

        # OpSec overrides — only persist when the user changed them
        # away from the safe default so the JSON stays readable.
        if self.ssh_keepalive_interval > 0:
            d["ssh_keepalive_interval"] = self.ssh_keepalive_interval
        if self.smb_client_name:
            d["smb_client_name"] = self.smb_client_name
        if self.telnet_naws_width > 0:
            d["telnet_naws_width"] = self.telnet_naws_width
        if self.telnet_naws_height > 0:
            d["telnet_naws_height"] = self.telnet_naws_height
        if self.rsync_preserve_metadata:
            d["rsync_preserve_metadata"] = True
        # Persist the suppression flag whenever the user OPTED OUT of
        # the safe default — keeps profile JSON minimal in the common
        # case (default True is implicit).
        if not self.suppress_shell_history:
            d["suppress_shell_history"] = False
        if self.terminal_theme:
            d["terminal_theme"] = self.terminal_theme

        return d

    @classmethod
    def from_dict(cls, d: dict) -> ConnectionProfile:
        if not isinstance(d, dict):
            raise TypeError("Profile data must be a JSON object")

        def _string(key: str, default: str = "") -> str:
            value = d.get(key, default)
            return value if isinstance(value, str) else default

        def _boolean(key: str, default: bool = False) -> bool:
            value = d.get(key, default)
            return value if isinstance(value, bool) else default

        def _int_in_range(key: str, default: int, minimum: int, maximum: int) -> int:
            value = d.get(key, default)
            if not isinstance(value, int):
                return default
            if minimum <= value <= maximum:
                return value
            return default

        auth_type = _string("auth_type", "password")
        if auth_type not in {"password", "key", "agent"}:
            auth_type = "password"

        proxy_type = _string("proxy_type", "none")
        if proxy_type not in {"none", "socks4", "socks5", "http"}:
            proxy_type = "none"

        address_family = _string("address_family", "auto")
        if address_family not in {"auto", "ipv4", "ipv6"}:
            address_family = "auto"

        protocol = _string("protocol", "sftp")
        if protocol not in VALID_PROTOCOLS:
            protocol = "sftp"

        return cls(
            name=_string("name"),
            protocol=protocol,
            host=_string("host"),
            port=_int_in_range("port", 22, 1, 65535),
            username=_string("username"),
            auth_type=auth_type,
            key_file=_string("key_file"),
            store_password=_boolean("store_password"),
            proxy_type=proxy_type,
            proxy_host=_string("proxy_host"),
            proxy_port=_int_in_range("proxy_port", 0, 0, 65535),
            proxy_username=_string("proxy_username"),
            store_proxy_password=_boolean("store_proxy_password"),
            proxy_command=_string("proxy_command"),
            address_family=address_family,
            # Protocol-specific
            ftp_passive=_boolean("ftp_passive", True),
            ftps_verify_tls=_boolean("ftps_verify_tls", True),
            smb_share=_string("smb_share"),
            webdav_url=_string("webdav_url"),
            s3_bucket=_string("s3_bucket"),
            s3_region=_string("s3_region"),
            s3_endpoint=_string("s3_endpoint"),
            # Rsync
            rsync_module=_string("rsync_module"),
            rsync_ssh=_boolean("rsync_ssh"),
            rsync_ssh_key=_string("rsync_ssh_key"),
            # NFS
            nfs_export=_string("nfs_export"),
            nfs_version=_int_in_range("nfs_version", 3, 2, 4),
            # Azure
            azure_container=_string("azure_container"),
            azure_connection_string=_string("azure_connection_string"),
            azure_account_name=_string("azure_account_name"),
            azure_sas_token=_string("azure_sas_token"),
            azure_share=_string("azure_share"),
            # OneDrive / SharePoint
            onedrive_client_id=_string("onedrive_client_id"),
            onedrive_tenant_id=_string("onedrive_tenant_id", "common"),
            sharepoint_site_url=_string("sharepoint_site_url"),
            # Google Drive
            gdrive_client_id=_string("gdrive_client_id"),
            gdrive_client_secret=_string("gdrive_client_secret"),
            # Dropbox
            dropbox_app_key=_string("dropbox_app_key"),
            dropbox_app_secret=_string("dropbox_app_secret"),
            # iSCSI
            iscsi_target_iqn=_string("iscsi_target_iqn"),
            iscsi_mount_point=_string("iscsi_mount_point"),
            # IMAP
            imap_ssl=_boolean("imap_ssl", True),
            # POP3 (read-only)
            pop3_ssl=_boolean("pop3_ssl", True),
            # TFTP
            tftp_filelist=_string("tftp_filelist"),
            tftp_filelist_enabled=_boolean("tftp_filelist_enabled"),
            tftp_max_size_bytes=_int_in_range(
                "tftp_max_size_bytes",
                16 * 1024 * 1024,
                1024,                # at least 1 KiB
                512 * 1024 * 1024,   # at most 512 MiB
            ),
            # ADB — "tcp" or "usb"; fall back to tcp on junk input.
            adb_mode=_string("adb_mode", "tcp") if _string(
                "adb_mode", "tcp",
            ) in ("tcp", "usb") else "tcp",
            # USB serial is user-visible in logs + UI labels. An
            # adversary with write access to profiles.json (cloud-
            # sync compromise, shared laptop) could otherwise plant
            # CR/LF + ANSI escapes in the serial string to forge
            # log lines or spoof error dialogs. Filter to the
            # character set real USB serials actually use.
            adb_usb_serial=_sanitize_usb_serial(
                _string("adb_usb_serial"),
            ),
            # MTP device_id: the mtp_client wrapper re-validates
            # against a strict allowlist before use, but we also
            # canonicalise here so an invalid value doesn't survive
            # a save/load round-trip.
            mtp_device_id=_sanitize_mtp_device_id(
                _string("mtp_device_id", "1"),
            ),
            # mtp_mounter is an allowlist of known binary names.
            mtp_mounter=_sanitize_mtp_mounter(
                _string("mtp_mounter"),
            ),
            # --- OpSec overrides ---
            ssh_keepalive_interval=_int_in_range(
                "ssh_keepalive_interval", 0, 0, 3600,
            ),
            smb_client_name=_string("smb_client_name"),
            telnet_naws_width=_int_in_range(
                "telnet_naws_width", 0, 0, 500,
            ),
            telnet_naws_height=_int_in_range(
                "telnet_naws_height", 0, 0, 500,
            ),
            rsync_preserve_metadata=_boolean("rsync_preserve_metadata"),
            # The safe default is True; only honour an explicit False.
            suppress_shell_history=_boolean(
                "suppress_shell_history", default=True,
            ),
            terminal_theme=_string("terminal_theme"),
        )


class ProfileManager:
    """Manages saved connection profiles."""

    def __init__(self):
        self._profiles: dict[str, ConnectionProfile] = {}
        self.load()

    def load(self) -> None:
        if not PROFILES_FILE.exists():
            return
        try:
            data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
            self._profiles = {
                name: self._restore_sensitive_fields(ConnectionProfile.from_dict(profile))
                for name, profile in data.items()
            }
            log.info("Loaded %d profiles from %s", len(self._profiles), PROFILES_FILE)
        except (json.JSONDecodeError, OSError) as e:
            log.error("Failed to load profiles: %s", e)

    def save(self) -> None:
        target_dir = PROFILES_FILE.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target_dir, 0o700)
        except OSError:
            log.debug("Could not set permissions on %s", target_dir, exc_info=True)
        data = {name: profile.to_dict() for name, profile in self._profiles.items()}
        payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        try:
            # Use mkstemp so the file is 0o600 from birth — NamedTemporary-
            # File inherits the umask and could leave the JSON world-
            # readable for the millisecond between write and the follow-
            # up os.chmod. Profiles contain host + username; not secrets
            # but not broadcast-worthy either.
            fd, temp_name = tempfile.mkstemp(
                dir=target_dir, prefix=".profiles.", suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    fd = -1  # ownership transferred
                    tmp.write(payload)
                os.replace(temp_name, PROFILES_FILE)
                os.chmod(PROFILES_FILE, 0o600)
                log.info(
                    "Saved %d profiles to %s",
                    len(self._profiles), PROFILES_FILE,
                )
            except BaseException:
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise
        except OSError as e:
            log.error("Failed to save profiles: %s", e)

    def get(self, name: str) -> ConnectionProfile | None:
        return self._profiles.get(name)

    def list_names(self) -> list[str]:
        return sorted(self._profiles.keys())

    def add(self, profile: ConnectionProfile) -> None:
        failed_secret_fields = self._sync_sensitive_fields(profile)
        if failed_secret_fields:
            failed = ", ".join(sorted(failed_secret_fields))
            raise RuntimeError(
                f"Could not store secret fields in keyring: {failed}"
            )
        self._profiles[profile.name] = profile
        if not profile.store_password:
            delete_password(profile.name)
        if not profile.store_proxy_password:
            delete_proxy_password(profile.name)
        self.save()

    def remove(self, name: str) -> None:
        if name in self._profiles:
            delete_password(name)
            delete_proxy_password(name)
            self._delete_sensitive_fields(name)
            del self._profiles[name]
            self.save()

    def all_profiles(self) -> list[ConnectionProfile]:
        return list(self._profiles.values())

    @staticmethod
    def _restore_sensitive_fields(profile: ConnectionProfile) -> ConnectionProfile:
        for field_name in SENSITIVE_PROFILE_FIELDS:
            value = get_secret(profile.name, field_name)
            if value is not None:
                setattr(profile, field_name, value)
        return profile

    @staticmethod
    def _sync_sensitive_fields(profile: ConnectionProfile) -> list[str]:
        failed_fields: list[str] = []
        for field_name in SENSITIVE_PROFILE_FIELDS:
            value = getattr(profile, field_name, "")
            if value:
                if not store_secret(profile.name, field_name, value):
                    failed_fields.append(field_name)
            else:
                delete_secret(profile.name, field_name)
        return failed_fields

    @staticmethod
    def _delete_sensitive_fields(profile_name: str) -> None:
        for field_name in SENSITIVE_PROFILE_FIELDS:
            delete_secret(profile_name, field_name)
