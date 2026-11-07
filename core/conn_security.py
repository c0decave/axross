"""How a connection is protected - one answer for every file connection and
every chat account or conversation, so the interface can always show it
(ui/security_badge.py: an icon of its own per level, a tooltip saying
exactly what).

The levels, from weakest to strongest:

* ``cleartext`` - anyone on the network path can read (and change) it;
* ``signed`` - protected against changes, not against reading (SMB signing);
* ``tls-weak`` - TLS, but the certificate is not checked or only part of
  the connection is protected (FTPS with a cleartext data channel);
* ``tls`` - TLS with a checked (or pinned) certificate;
* ``encrypted`` - encrypted by the protocol itself (SSH, SMB3 encryption);
* ``e2e-failed`` / ``e2e-unverified`` / ``e2e`` - end-to-end encryption of
  a chat (could not decrypt / not every key verified / verified);

plus ``local`` (nothing crosses a network) and ``unknown``.

Where the backend knows the real state of its connection it says so with a
``security_info()`` method (negotiated TLS version and cipher, the SSH
cipher, the SMB dialect and whether the session is encrypted); otherwise the
state follows from the profile's settings, and the text says "configured"
rather than "negotiated". Reading the state never touches the network: the
values are those the handshake already left on the connection objects.
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

LEVEL_LOCAL = "local"
LEVEL_UNKNOWN = "unknown"
LEVEL_CLEARTEXT = "cleartext"
LEVEL_SIGNED = "signed"
LEVEL_TLS_WEAK = "tls-weak"
LEVEL_TLS = "tls"
LEVEL_ENCRYPTED = "encrypted"
LEVEL_E2E_FAILED = "e2e-failed"
LEVEL_E2E_UNVERIFIED = "e2e-unverified"
LEVEL_E2E = "e2e"

#: Weakest first; :func:`weakest` uses the order. ``local`` counts as
#: strong (nothing to intercept); ``unknown`` as weak (nothing to rely on).
ORDER = (LEVEL_CLEARTEXT, LEVEL_UNKNOWN, LEVEL_E2E_FAILED, LEVEL_SIGNED, LEVEL_TLS_WEAK, LEVEL_TLS,
         LEVEL_E2E_UNVERIFIED, LEVEL_ENCRYPTED, LEVEL_E2E, LEVEL_LOCAL)

#: One short title per level (the first line of a tooltip, a legend).
TITLES = {
    LEVEL_LOCAL: "Local - no network",
    LEVEL_UNKNOWN: "Protection unknown",
    LEVEL_CLEARTEXT: "Cleartext - anyone on the network can read it",
    LEVEL_SIGNED: "Signed, not encrypted - readable on the network",
    LEVEL_TLS_WEAK: "TLS with a weakness",
    LEVEL_TLS: "TLS encrypted",
    LEVEL_ENCRYPTED: "Encrypted",
    LEVEL_E2E_FAILED: "End-to-end encrypted - could not be decrypted",
    LEVEL_E2E_UNVERIFIED: "End-to-end encrypted - not every key verified",
    LEVEL_E2E: "End-to-end encrypted, keys verified",
}

_CLEAR = "cleartext - anyone on the network can read it"


@dataclass(frozen=True)
class SecurityInfo:
    """*summary* is one line saying exactly what ("TLS 1.3, certificate
    verified"); *negotiated* is True when it was read from the live
    connection, False when it follows from the settings."""
    level: str
    summary: str
    negotiated: bool = False
    details: tuple[str, ...] = ()

    @property
    def title(self) -> str:
        return TITLES.get(self.level, TITLES[LEVEL_UNKNOWN])


LOCAL = SecurityInfo(LEVEL_LOCAL, "Local files - nothing goes over a network", True)
UNKNOWN = SecurityInfo(LEVEL_UNKNOWN, "How this connection is protected is not known")


def rank(level: str) -> int:
    try:
        return ORDER.index(level)
    except ValueError:
        return ORDER.index(LEVEL_UNKNOWN)


def weakest(infos) -> SecurityInfo | None:
    """The weakest of *infos* (a tab with several connections shows it)."""
    infos = [i for i in infos if i is not None]
    return min(infos, key=lambda i: rank(i.level)) if infos else None


# --- helpers for the backends ----------------------------------------------------------------

def tls_version_text(version: str | None) -> str:
    """"TLS 1.3" of "TLSv1.3"."""
    if not version:
        return "TLS"
    return version.replace("TLSv", "TLS ").replace("SSLv", "SSL ")


def tls_socket(sock, *, verified: bool, what: str = "", extra: tuple[str, ...] = ()) -> SecurityInfo | None:
    """The info of a live TLS socket (an ``ssl.SSLSocket`` or asyncio's
    SSL object); None when *sock* is not TLS. *verified*: the certificate
    was checked against the trusted CAs (or a pin)."""
    if not isinstance(sock, (ssl.SSLSocket, ssl.SSLObject)):
        return None
    try:
        version = sock.version()
        cipher = sock.cipher()
    except (OSError, ValueError, AttributeError):
        version, cipher = None, None
    text = tls_version_text(version)
    if what:
        text = f"{what}: {text}"
    details = list(extra)
    if cipher:
        details.insert(0, f"Cipher: {cipher[0]}")
    old = version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    if verified and not old:
        return SecurityInfo(LEVEL_TLS, f"{text}, certificate verified", True, tuple(details))
    reason = "certificate NOT verified" if not verified else "outdated TLS version"
    return SecurityInfo(LEVEL_TLS_WEAK, f"{text}, {reason}", True, tuple(details))


def ssh_transport(transport, what: str = "SSH") -> SecurityInfo | None:
    """The info of a connected paramiko Transport (None when it is not)."""
    if transport is None:
        return None
    try:
        if not transport.is_active():
            return None
        cipher = getattr(transport, "remote_cipher", "") or ""
        mac = getattr(transport, "remote_mac", "") or ""
        kex = getattr(getattr(transport, "kex_engine", None), "name", "") or ""
        key = transport.get_remote_server_key()
        key_type = key.get_name() if key is not None else ""
        version = getattr(transport, "remote_version", "") or ""
    except Exception:  # noqa: BLE001 - a half-closed transport: say what is known
        log.debug("SSH transport state not readable", exc_info=True)
        return SecurityInfo(LEVEL_ENCRYPTED, f"{what}, encrypted", False)
    summary = f"{what}, encrypted" + (f" ({cipher})" if cipher else "") + ", host key checked"
    details = tuple(d for d in (
        f"Key exchange: {kex}" if kex else "",
        f"MAC: {mac}" if mac and "gcm" not in cipher and "poly1305" not in cipher else "",
        f"Host key: {key_type}" if key_type else "",
        f"Server: {version}" if version else "",
    ) if d)
    return SecurityInfo(LEVEL_ENCRYPTED, summary, True, details)


SMB_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
SMB_CIPHERS = {0x0001: "AES-128-CCM", 0x0002: "AES-128-GCM", 0x0003: "AES-256-CCM", 0x0004: "AES-256-GCM"}


def smb_session(session, share: str = "") -> SecurityInfo | None:
    """The info of an smbprotocol Session: its dialect, whether it (or the
    tree of *share*) is encrypted, else whether it is signed."""
    if session is None:
        return None
    try:
        connection = session.connection
        dialect = SMB_DIALECTS.get(getattr(connection, "dialect", None) or 0, "")
        encrypted = bool(getattr(session, "encrypt_data", False))
        if not encrypted and share:
            for tree in list(getattr(session, "tree_connect_table", {}).values()):
                name = str(getattr(tree, "share_name", "")).rstrip("\\").rsplit("\\", 1)[-1]
                if name.lower() == share.lower() and getattr(tree, "encrypt_data", False):
                    encrypted = True
        signed = bool(getattr(session, "signing_required", False) or getattr(connection, "require_signing", False))
        cipher = SMB_CIPHERS.get(getattr(connection, "cipher_id", None) or 0, "")
    except Exception:  # noqa: BLE001 - not set up: the caller falls back to the settings
        log.debug("SMB session state not readable", exc_info=True)
        return None
    name = f"SMB {dialect}" if dialect else "SMB"
    if encrypted:
        return SecurityInfo(LEVEL_ENCRYPTED, f"{name} with encryption" + (f" ({cipher})" if cipher else ""), True)
    if signed:
        return SecurityInfo(LEVEL_SIGNED, f"{name} signing only, not encrypted - "
                            "the files can be read on the network", True)
    return SecurityInfo(LEVEL_CLEARTEXT, f"{name} neither signed nor encrypted - {_CLEAR}", True)


def url_info(url: str, *, what: str = "", verified: bool = True) -> SecurityInfo:
    """The configured protection of an http(s) address."""
    try:
        scheme = urlsplit(url or "").scheme.lower()
    except ValueError:
        scheme = ""
    prefix = f"{what}: " if what else ""
    if scheme == "https":
        if verified:
            return SecurityInfo(LEVEL_TLS, f"{prefix}HTTPS (TLS), certificate verified")
        return SecurityInfo(LEVEL_TLS_WEAK, f"{prefix}HTTPS (TLS), certificate NOT verified")
    if scheme == "http":
        return SecurityInfo(LEVEL_CLEARTEXT, f"{prefix}http:// - {_CLEAR}")
    return SecurityInfo(LEVEL_UNKNOWN, f"{prefix}{url or 'no address'}")


# --- from a profile ---------------------------------------------------------------------------------

def _cloud(what: str) -> SecurityInfo:
    return SecurityInfo(LEVEL_TLS, f"{what} over HTTPS (TLS), certificate verified")


def from_profile(profile) -> SecurityInfo:
    """The protection a connection profile (core.profiles.ConnectionProfile)
    asks for - "configured", before or without a live connection."""
    proto = str(getattr(profile, "protocol", "") or "").lower()
    get = lambda name, default=None: getattr(profile, name, default)  # noqa: E731
    if proto in ("sftp", "scp"):
        return SecurityInfo(LEVEL_ENCRYPTED, f"{proto.upper()} over SSH, encrypted, host key checked")
    if proto == "rsync":
        if get("rsync_ssh"):
            return SecurityInfo(LEVEL_ENCRYPTED, "rsync over SSH, encrypted")
        return SecurityInfo(LEVEL_CLEARTEXT, f"rsync daemon (rsync://) - {_CLEAR}")
    if proto == "ftp":
        return SecurityInfo(LEVEL_CLEARTEXT, f"FTP - {_CLEAR}, the password too")
    if proto == "ftps":
        if get("ftps_verify_tls", True):
            return SecurityInfo(LEVEL_TLS, "FTPS (explicit TLS), certificate verified")
        return SecurityInfo(LEVEL_TLS_WEAK, "FTPS (explicit TLS), certificate NOT verified")
    if proto in ("smb", "dfsn"):
        return SecurityInfo(LEVEL_SIGNED, "SMB, signing required; encrypted only when the server "
                            "asks for it (SMB3)")
    if proto == "webdav":
        return url_info(str(get("webdav_url", "") or ""), what="WebDAV")
    if proto == "s3":
        endpoint = str(get("s3_endpoint", "") or "")
        if not endpoint:
            return _cloud("Amazon S3")
        if "://" not in endpoint:
            endpoint = "https://" + endpoint
        return url_info(endpoint, what="S3")
    if proto in ("azure_blob", "azure_files"):
        conn = str(get("azure_connection_string", "") or "").replace(" ", "").lower()
        if "defaultendpointsprotocol=http;" in conn + ";" and "defaultendpointsprotocol=https" not in conn:
            return SecurityInfo(LEVEL_CLEARTEXT, f"Azure over http:// - {_CLEAR}")
        return _cloud("Azure")
    if proto in ("onedrive", "sharepoint"):
        return _cloud("Microsoft Graph")
    if proto == "gdrive":
        return _cloud("Google Drive")
    if proto == "dropbox":
        return _cloud("Dropbox")
    if proto == "nfs":
        return SecurityInfo(LEVEL_CLEARTEXT, f"NFS with AUTH_SYS - {_CLEAR}; the server trusts the "
                            "user id the client claims (no Kerberos krb5p)")
    if proto == "iscsi":
        return SecurityInfo(LEVEL_CLEARTEXT, f"iSCSI - {_CLEAR} (CHAP protects only the login)")
    for name, flag, title in (("imap", "imap_ssl", "IMAP"), ("pop3", "pop3_ssl", "POP3"),
                              ("nntp", "nntp_ssl", "NNTP")):
        if proto == name:
            if get(flag, True):
                return SecurityInfo(LEVEL_TLS, f"{title} over TLS, certificate verified")
            return SecurityInfo(LEVEL_CLEARTEXT, f"{title} without TLS - {_CLEAR}, the password too")
    if proto == "winrm":
        return SecurityInfo(LEVEL_TLS, "WinRM over HTTPS (TLS)")
    if proto == "svn":
        host = str(get("host", "") or "")
        scheme = urlsplit(host).scheme.lower() if "://" in host else ""
        if scheme == "svn+ssh":
            return SecurityInfo(LEVEL_ENCRYPTED, "Subversion over SSH, encrypted")
        if scheme == "svn":
            return SecurityInfo(LEVEL_CLEARTEXT, f"Subversion (svn://) - {_CLEAR}")
        return url_info(host, what="Subversion")
    if proto == "adb":
        if str(get("adb_mode", "tcp")) == "usb":
            return SecurityInfo(LEVEL_LOCAL, "ADB over USB - a cable, no network")
        return SecurityInfo(LEVEL_CLEARTEXT, f"ADB over TCP - {_CLEAR} (the RSA key only authenticates)")
    if proto == "mtp":
        return SecurityInfo(LEVEL_LOCAL, "MTP device on USB - no network")
    if proto == "ramfs":
        return SecurityInfo(LEVEL_LOCAL, "In memory - no network")
    if proto in ("telnet", "cisco-telnet"):
        return SecurityInfo(LEVEL_CLEARTEXT, f"Telnet - {_CLEAR}, the password too")
    if proto == "tftp":
        return SecurityInfo(LEVEL_CLEARTEXT, f"TFTP - {_CLEAR}, no login at all")
    if proto == "gopher":
        return SecurityInfo(LEVEL_CLEARTEXT, f"Gopher - {_CLEAR}")
    if proto == "pjl":
        return SecurityInfo(LEVEL_CLEARTEXT, f"PJL printer port - {_CLEAR}")
    return SecurityInfo(LEVEL_UNKNOWN, f"{proto or 'This connection'}: how it is protected is not known")


# --- of a live backend --------------------------------------------------------------------------------

def of_backend(backend) -> SecurityInfo:
    """What protects *backend* now: its own ``security_info()`` (negotiated)
    when it has one and knows, else its profile's settings (configured),
    else local for the local file system, else unknown."""
    if backend is None:
        return UNKNOWN
    method = getattr(backend, "security_info", None)
    if callable(method):
        try:
            info = method()
        except Exception:  # noqa: BLE001 - a badge must never break the pane
            log.debug("security_info() of %s failed", type(backend).__name__, exc_info=True)
            info = None
        if isinstance(info, SecurityInfo):
            return info
    profile = getattr(backend, "_axross_profile", None)
    if profile is not None:
        return from_profile(profile)
    from core.local_fs import LocalFS

    if isinstance(backend, LocalFS):
        return LOCAL
    return UNKNOWN


# --- chat --------------------------------------------------------------------------------------------

#: core.chat's encryption values -> levels.
CHAT_LEVELS = {
    "none": LEVEL_CLEARTEXT,
    "tls": LEVEL_TLS,
    "e2e-untrusted": LEVEL_E2E_UNVERIFIED,
    "e2e": LEVEL_E2E,
    "e2e-failed": LEVEL_E2E_FAILED,
}


def from_chat(encryption: str, summary: str, *, negotiated: bool = False,
              details: tuple[str, ...] = ()) -> SecurityInfo:
    return SecurityInfo(CHAT_LEVELS.get(encryption, LEVEL_UNKNOWN), summary, negotiated, details)
