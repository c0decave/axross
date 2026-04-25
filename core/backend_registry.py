"""Backend registry — capability model and factory for file backends."""
from __future__ import annotations

import importlib
import logging
import shutil
from dataclasses import dataclass, field
from enum import Enum, auto

log = logging.getLogger(__name__)


class CredentialKind(Enum):
    """How a backend authenticates."""
    NONE = auto()          # No credentials needed (e.g. local FS)
    PASSWORD = auto()      # Username + password
    SSH = auto()           # SSH auth (password, key, agent)
    API_KEY = auto()       # Access key + secret key (S3)
    OAUTH = auto()         # OAuth2 browser flow (Google Drive, OneDrive)


@dataclass(frozen=True)
class BackendCapabilities:
    """Declares what a backend can and cannot do.

    The registry consults this so the transfer engine and UI avoid
    asking a backend for operations it cannot fulfill. New fields
    default to ``False`` so unknown backends fall back to "unsupported"
    — that's the safe choice.
    """
    can_chmod: bool = False
    can_symlink: bool = False
    can_rename: bool = True
    can_recursive_delete: bool = True
    can_stream_read: bool = True
    can_stream_write: bool = True
    can_seek: bool = True
    has_posix_paths: bool = True
    case_sensitive: bool = True
    has_disk_usage: bool = False
    # -- Added in the feature-coverage round ---------------------------
    # True when the backend can return a checksum (sha256/md5/etag) for
    # an existing object WITHOUT pulling the whole content down.
    can_checksum_without_read: bool = False
    # True when the backend supports a native server-side copy so a
    # copy between two paths on the same server does not round-trip
    # via the client (S3 CopyObject, WebDAV COPY, SFTP/Telnet cp, etc.).
    can_server_side_copy: bool = False
    # True when server-side rename covers arbitrary cross-directory
    # moves (not just same-dir rename).
    can_server_side_move: bool = True
    # True when the backend can return a last-access time (atime) in
    # addition to mtime.
    has_atime: bool = False
    # True when the backend natively supports a version history per
    # object (S3 versioning, WebDAV DAV:version-tree, Dropbox,
    # Google Drive).
    has_version_history: bool = False
    # True when the backend can fire change notifications for a
    # watched path (inotify/kqueue for local, server-sent events for
    # WebDAV, SNS/Lambda for S3, Drive activity for Google Drive).
    has_watch: bool = False
    # True when the backend supports sparse files (holes).
    has_sparse_files: bool = False
    # True when the backend's paths are on the machine that axross
    # is running on — ``os.stat``, ``QImageReader``, ``xdg-open`` work.
    # Remote backends MUST leave this False; the preview/open helpers
    # refuse to touch them otherwise (to avoid accidentally shelling
    # out on attacker-supplied paths from an S3 bucket, say).
    is_local: bool = False


# Pre-built capability sets for common backend types
POSIX_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=True, has_disk_usage=True,
    has_atime=True, has_sparse_files=True, has_watch=True,
    can_server_side_copy=True,
)
FTP_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=False, can_seek=False,
    can_stream_write=False, has_disk_usage=False,
)
SMB_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False,
    has_posix_paths=False, case_sensitive=False, has_disk_usage=True,
)
WEBDAV_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False, can_seek=False,
    can_stream_write=False, has_disk_usage=False,
    # WebDAV has native COPY / MOVE methods that run server-side
    can_server_side_copy=True,
    # DAV:getetag — strong etag functions as a content checksum
    can_checksum_without_read=True,
    # Some WebDAV servers support DAV:version-tree (RFC 3253).
    # We don't assume it universally; per-server probe still needed.
)
S3_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False, can_rename=False,
    can_seek=False, can_stream_write=False, has_disk_usage=False,
    # S3 CopyObject / versioning / ETag
    can_server_side_copy=True,
    can_checksum_without_read=True,
    has_version_history=True,
)
RSYNC_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=True, can_rename=False,
    can_seek=False, can_stream_write=False, has_disk_usage=False,
)
NFS_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=True, has_disk_usage=True,
    has_atime=True, has_sparse_files=True,
    can_server_side_copy=True,  # local mount → os.link / shutil copy
)
AZURE_BLOB_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False, can_rename=False,
    can_seek=False, can_stream_write=False, has_disk_usage=False,
    can_server_side_copy=True,  # Azure's Copy Blob operation
    can_checksum_without_read=True,  # Content-MD5
    has_version_history=True,
)
AZURE_FILES_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False,
    has_posix_paths=False, case_sensitive=False,
    can_server_side_copy=True,
)
CLOUD_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False,
    can_seek=False, can_stream_write=False, has_disk_usage=True,
    has_version_history=True,  # OneDrive/Dropbox/GDrive all keep history
    can_checksum_without_read=True,
)
ISCSI_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=True, has_disk_usage=True,
    has_atime=True, has_sparse_files=True,
    can_server_side_copy=True,
)
IMAP_CAPS = BackendCapabilities(
    can_chmod=False, can_symlink=False, can_rename=False,
    can_seek=False, can_stream_write=False, has_disk_usage=True,
    case_sensitive=True,
)
TELNET_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=True, can_rename=True,
    can_recursive_delete=True, can_stream_read=True,
    can_stream_write=False, can_seek=False,
    has_posix_paths=True, case_sensitive=True, has_disk_usage=True,
    has_atime=True,
    can_server_side_copy=True,  # shell cp
    can_checksum_without_read=True,  # sha256sum on remote shell
)
SCP_CAPS = BackendCapabilities(
    can_chmod=True, can_symlink=True, can_rename=True,
    can_recursive_delete=True, can_stream_read=True,
    can_stream_write=False, can_seek=False,
    has_posix_paths=True, case_sensitive=True, has_disk_usage=True,
    has_atime=True, has_sparse_files=True,
    can_server_side_copy=True,  # remote shell cp
    can_checksum_without_read=True,  # remote sha256sum
)
WINRM_CAPS = BackendCapabilities(
    can_chmod=False,           # NTFS ACLs don't map to POSIX bits
    can_symlink=False,         # reparse points need elevated PS
    can_rename=True,           # Move-Item handles cross-dir
    can_recursive_delete=True,
    can_stream_read=True, can_stream_write=False,  # base64-buffered
    can_seek=False,
    has_posix_paths=False, case_sensitive=False,
    has_disk_usage=True,
    can_server_side_copy=True,        # Copy-Item runs remote
    can_checksum_without_read=True,   # Get-FileHash native SHA256
)
WMI_CAPS = BackendCapabilities(
    # Metadata-only by design — every mutation / IO entry point raises.
    can_chmod=False, can_symlink=False,
    can_rename=False, can_recursive_delete=False,
    can_stream_read=False, can_stream_write=False, can_seek=False,
    has_posix_paths=False, case_sensitive=False,
    has_disk_usage=True,                 # Win32_LogicalDisk is cheap
    can_server_side_copy=False,
    can_checksum_without_read=False,
)
EXCHANGE_CAPS = BackendCapabilities(
    # Read-mostly: messages + attachments readable; deletes work; rest
    # raises. Same general shape as IMAP.
    can_chmod=False, can_symlink=False,
    can_rename=False, can_recursive_delete=False,
    can_stream_read=True, can_stream_write=False, can_seek=False,
    has_posix_paths=True, case_sensitive=True,
    has_disk_usage=False,
)
ADB_CAPS = BackendCapabilities(
    # Android shell via ADB — chmod exists (toybox), symlinks don't
    # (no ln on most images). Streams go through push/pull tempfiles
    # so can_seek is False and can_stream_write is False. Checksum
    # works via sha256sum on the remote shell.
    can_chmod=True, can_symlink=False,
    can_rename=True, can_recursive_delete=True,
    can_stream_read=True, can_stream_write=False, can_seek=False,
    has_posix_paths=True, case_sensitive=True,
    has_disk_usage=False,
    can_server_side_copy=True,  # cp on the shell
    can_checksum_without_read=True,
)
MTP_CAPS = BackendCapabilities(
    # MTP-over-FUSE looks like a POSIX filesystem through the kernel,
    # but the protocol underneath is NOT POSIX — random IO, chmod,
    # and symlinks usually don't round-trip. Keep conservative.
    can_chmod=False, can_symlink=False,
    can_rename=True, can_recursive_delete=True,
    can_stream_read=True, can_stream_write=True, can_seek=False,
    has_posix_paths=True, case_sensitive=True,
    has_disk_usage=True,  # FUSE statfs reports device storage
    is_local=True,  # we mount it locally; previews / xdg-open work
)


@dataclass(frozen=True)
class BackendInfo:
    """Describes a registered backend type."""
    protocol_id: str
    display_name: str
    module: str              # e.g. "core.ftp_client"
    class_name: str          # e.g. "FtpSession"
    default_port: int = 0
    required_extra: str | None = None  # pip extra name, e.g. "smb"
    available: bool = True
    capabilities: BackendCapabilities = field(default_factory=BackendCapabilities)
    credential_kind: CredentialKind = CredentialKind.PASSWORD


# Global registry
_registry: dict[str, BackendInfo] = {}


def register(info: BackendInfo) -> None:
    """Register a backend info entry."""
    _registry[info.protocol_id] = info


def get(protocol_id: str) -> BackendInfo | None:
    """Look up a registered backend by protocol ID."""
    return _registry.get(protocol_id)


def all_backends() -> list[BackendInfo]:
    """Return all registered backends, sorted by display name."""
    return sorted(_registry.values(), key=lambda b: b.display_name)


def available_backends() -> list[BackendInfo]:
    """Return only backends whose dependencies are installed."""
    return [b for b in all_backends() if b.available]


def load_backend_class(protocol_id: str):
    """Import and return the backend class for the given protocol."""
    info = _registry.get(protocol_id)
    if info is None:
        raise ValueError(f"Unknown protocol: {protocol_id}")
    if not info.available:
        extra = info.required_extra or protocol_id
        raise ImportError(
            f"Backend '{info.display_name}' is not available. "
            f"Install it with: pip install axross[{extra}]"
        )
    mod = importlib.import_module(info.module)
    return getattr(mod, info.class_name)


def _check_available(import_probe: str) -> bool:
    """Check if a Python package is importable."""
    try:
        __import__(import_probe)
        return True
    except ImportError:
        return False


def _check_command_available(*commands: str) -> bool:
    """Check if all required system commands are present on PATH."""
    return all(shutil.which(command) is not None for command in commands)


def _check_any_command_available(*commands: str) -> bool:
    """Check if at least one of the given system commands is present on PATH."""
    return any(shutil.which(command) is not None for command in commands)


def init_registry() -> None:
    """Populate the global registry with all known backends."""
    _registry.clear()

    # --- Always available (stdlib or core dependency) ---
    register(BackendInfo(
        protocol_id="sftp",
        display_name="SFTP",
        module="core.ssh_client",
        class_name="SSHSession",
        default_port=22,
        capabilities=POSIX_CAPS,
        credential_kind=CredentialKind.SSH,
    ))
    register(BackendInfo(
        protocol_id="ftp",
        display_name="FTP",
        module="core.ftp_client",
        class_name="FtpSession",
        default_port=21,
        capabilities=FTP_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))
    register(BackendInfo(
        protocol_id="ftps",
        display_name="FTPS",
        module="core.ftp_client",
        class_name="FtpSession",
        default_port=990,
        capabilities=FTP_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- Optional backends ---
    register(BackendInfo(
        protocol_id="smb",
        display_name="SMB / CIFS",
        module="core.smb_client",
        class_name="SmbSession",
        default_port=445,
        required_extra="smb",
        available=_check_available("smbprotocol"),
        capabilities=SMB_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))
    register(BackendInfo(
        protocol_id="webdav",
        display_name="WebDAV",
        module="core.webdav_client",
        class_name="WebDavSession",
        default_port=443,
        required_extra="webdav",
        available=_check_available("webdav3"),
        capabilities=WEBDAV_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))
    register(BackendInfo(
        protocol_id="s3",
        display_name="S3-kompatibel",
        module="core.s3_client",
        class_name="S3Session",
        default_port=443,
        required_extra="s3",
        available=_check_available("boto3"),
        capabilities=S3_CAPS,
        credential_kind=CredentialKind.API_KEY,
    ))

    # --- Rsync (always available — uses system rsync binary) ---
    register(BackendInfo(
        protocol_id="rsync",
        display_name="Rsync",
        module="core.rsync_client",
        class_name="RsyncSession",
        default_port=873,
        available=_check_command_available("rsync"),
        capabilities=RSYNC_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- NFS (uses system mount.nfs — no pip dependency) ---
    register(BackendInfo(
        protocol_id="nfs",
        display_name="NFS",
        module="core.nfs_client",
        class_name="NfsSession",
        default_port=2049,
        available=_check_command_available("mount", "umount") and _check_any_command_available(
            "mount.nfs", "mount.nfs4", "mount"
        ),
        capabilities=NFS_CAPS,
        credential_kind=CredentialKind.NONE,
    ))

    # --- Azure Blob Storage (optional: azure-storage-blob) ---
    register(BackendInfo(
        protocol_id="azure_blob",
        display_name="Azure Blob",
        module="core.azure_client",
        class_name="AzureBlobSession",
        default_port=443,
        required_extra="azure",
        available=_check_available("azure.storage.blob"),
        capabilities=AZURE_BLOB_CAPS,
        credential_kind=CredentialKind.API_KEY,
    ))

    # --- Azure Files (optional: azure-storage-file-share) ---
    register(BackendInfo(
        protocol_id="azure_files",
        display_name="Azure Files",
        module="core.azure_client",
        class_name="AzureFilesSession",
        default_port=443,
        required_extra="azure",
        available=_check_available("azure.storage.fileshare"),
        capabilities=AZURE_FILES_CAPS,
        credential_kind=CredentialKind.API_KEY,
    ))

    # --- OneDrive (optional: msal) ---
    register(BackendInfo(
        protocol_id="onedrive",
        display_name="OneDrive",
        module="core.onedrive_client",
        class_name="OneDriveSession",
        default_port=443,
        required_extra="onedrive",
        available=_check_available("msal"),
        capabilities=CLOUD_CAPS,
        credential_kind=CredentialKind.OAUTH,
    ))

    # --- SharePoint (optional: msal) ---
    register(BackendInfo(
        protocol_id="sharepoint",
        display_name="SharePoint",
        module="core.onedrive_client",
        class_name="OneDriveSession",
        default_port=443,
        required_extra="onedrive",
        available=_check_available("msal"),
        capabilities=CLOUD_CAPS,
        credential_kind=CredentialKind.OAUTH,
    ))

    # --- Google Drive (optional: google-api-python-client) ---
    register(BackendInfo(
        protocol_id="gdrive",
        display_name="Google Drive",
        module="core.gdrive_client",
        class_name="GDriveSession",
        default_port=443,
        required_extra="gdrive",
        available=_check_available("googleapiclient"),
        capabilities=CLOUD_CAPS,
        credential_kind=CredentialKind.OAUTH,
    ))

    # --- Dropbox (optional: dropbox) ---
    register(BackendInfo(
        protocol_id="dropbox",
        display_name="Dropbox",
        module="core.dropbox_client",
        class_name="DropboxSession",
        default_port=443,
        required_extra="dropbox",
        available=_check_available("dropbox"),
        capabilities=CLOUD_CAPS,
        credential_kind=CredentialKind.OAUTH,
    ))

    # --- iSCSI (always available — uses system iscsiadm) ---
    register(BackendInfo(
        protocol_id="iscsi",
        display_name="iSCSI",
        module="core.iscsi_client",
        class_name="IscsiSession",
        default_port=3260,
        available=_check_command_available("iscsiadm", "mount", "umount", "blkid"),
        capabilities=ISCSI_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- IMAP (always available — stdlib imaplib) ---
    register(BackendInfo(
        protocol_id="imap",
        display_name="IMAP (Mail)",
        module="core.imap_client",
        class_name="ImapSession",
        default_port=993,
        capabilities=IMAP_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- Telnet (always available — stdlib sockets) ---
    register(BackendInfo(
        protocol_id="telnet",
        display_name="Telnet (Shell)",
        module="core.telnet_client",
        class_name="TelnetSession",
        default_port=23,
        capabilities=TELNET_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- SCP (always available — uses paramiko, same as SFTP) ---
    register(BackendInfo(
        protocol_id="scp",
        display_name="SCP (Shell over SSH)",
        module="core.scp_client",
        class_name="SCPSession",
        default_port=22,
        capabilities=SCP_CAPS,
        credential_kind=CredentialKind.SSH,
    ))

    # --- WinRM (PowerShell-Remoting, optional: pywinrm) ---
    register(BackendInfo(
        protocol_id="winrm",
        display_name="WinRM (PowerShell-Remoting)",
        module="core.winrm_client",
        class_name="WinRMSession",
        default_port=5986,
        required_extra="winrm",
        available=_check_available("winrm"),
        capabilities=WINRM_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- WMI / DCOM (metadata-only enumeration; impacket) ---
    register(BackendInfo(
        protocol_id="wmi",
        display_name="WMI / DCOM (Read-only)",
        module="core.wmi_client",
        class_name="WMISession",
        default_port=135,
        required_extra="wmi",
        available=_check_available("impacket"),
        capabilities=WMI_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- Exchange / EWS (optional: exchangelib) ---
    register(BackendInfo(
        protocol_id="exchange",
        display_name="Exchange (EWS)",
        module="core.exchange_client",
        class_name="ExchangeSession",
        default_port=443,
        required_extra="exchange",
        available=_check_available("exchangelib"),
        capabilities=EXCHANGE_CAPS,
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- DFS-N (Distributed File System Namespaces, uses smbprotocol) ---
    register(BackendInfo(
        protocol_id="dfsn",
        display_name="DFS-N (Distributed Namespace)",
        module="core.dfsn_client",
        class_name="DFSNamespaceSession",
        default_port=445,
        required_extra="smb",        # piggy-backs on the SMB extra
        available=_check_available("smbprotocol"),
        capabilities=SMB_CAPS,        # behaves like SMB on the wire
        credential_kind=CredentialKind.PASSWORD,
    ))

    # --- ADB (Android Debug Bridge, optional: adb-shell) ---
    register(BackendInfo(
        protocol_id="adb",
        display_name="ADB (Android)",
        module="core.adb_client",
        class_name="AdbSession",
        default_port=5555,
        required_extra="adb",
        available=_check_available("adb_shell"),
        capabilities=ADB_CAPS,
        credential_kind=CredentialKind.NONE,  # RSA keypair, no pw
    ))

    # --- MTP (Media Transfer Protocol — Android via FUSE mount) ---
    register(BackendInfo(
        protocol_id="mtp",
        display_name="MTP (Android Phone)",
        module="core.mtp_client",
        class_name="MtpSession",
        default_port=0,       # bus-level, no TCP port
        # Available iff at least one MTP-FUSE mounter is on PATH.
        # The core/mtp_client.py default list drives this — keep in
        # sync if new mounters are added there.
        available=_check_any_command_available(
            "jmtpfs", "simple-mtpfs", "go-mtpfs",
        ),
        capabilities=MTP_CAPS,
        credential_kind=CredentialKind.NONE,
    ))

    installed = [b.protocol_id for b in _registry.values() if b.available]
    log.info("Backend registry initialized: %s", ", ".join(installed))
