"""SMB/CIFS backend implementing the FileBackend protocol.

Requires: pip install axross[smb]  (smbprotocol>=1.13)
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib
import errno
import logging
import os
import posixpath
import socket
import stat as stat_module
import struct
import sys
import threading
from datetime import datetime, timedelta, timezone
from typing import IO

from core import removal_cancel
from core.backend import SessionLifecycle
from core.client_identity import SMB_CLIENT_NAME
from core.path_policy import (
    MAX_RECURSIVE_DELETE_DEPTH,
    check_tree_depth,
    refuse_folder_path,
    safe_join,
)
from models.file_item import FileItem

log = logging.getLogger(__name__)


def _import_smbclient_package():
    """Import the pysmbclient package, avoiding CLI-script shadowing.

    Some optional tools, notably impacket, install ``/usr/local/bin/smbclient.py``.
    When Axross is launched via a console-script entry point such as ``pytest``,
    that directory can sit at ``sys.path[0]`` and shadow the real ``smbclient``
    package from ``site-packages``.
    """
    module = importlib.import_module("smbclient")
    if hasattr(module, "__path__") or "smbclient.path" in sys.modules:
        importlib.import_module("smbclient.path")
        return module

    origin = os.path.abspath(getattr(module, "__file__", "") or "")
    shadow_dir = os.path.dirname(origin)
    original_path = list(sys.path)
    sys.modules.pop("smbclient", None)
    try:
        sys.path[:] = [
            entry for entry in original_path if os.path.abspath(entry or os.getcwd()) != shadow_dir
        ]
        module = importlib.import_module("smbclient")
        importlib.import_module("smbclient.path")
        log.warning(
            "Ignored shadowing smbclient module at %s; using package from %s",
            origin,
            getattr(module, "__file__", "<unknown>"),
        )
        return module
    finally:
        sys.path[:] = original_path


try:
    smbclient = _import_smbclient_package()
    from smbprotocol.exceptions import SMBException, SMBOSError

    _SMB_IMPORT_ERROR: ImportError | None = None
except ImportError as exc:  # pragma: no cover
    smbclient = None  # type: ignore[assignment]
    SMBOSError = OSError  # type: ignore[assignment,misc]
    SMBException = OSError  # type: ignore[assignment,misc]
    _SMB_IMPORT_ERROR = exc

# A link smbclient cannot follow (to another server or a local drive).
# Looked up on its own: test doubles of smbprotocol.exceptions lack it.
_LINK_REDIRECTION: tuple[type[BaseException], ...] = ()
try:
    from smbprotocol.exceptions import SMBLinkRedirectionError as _Redirection

    if isinstance(_Redirection, type) and issubclass(_Redirection, BaseException):
        _LINK_REDIRECTION = (_Redirection,)
except ImportError:  # pragma: no cover - smbprotocol absent
    pass

# Every way an smbclient call fails: OSError / SMBOSError for an error
# status; SMBException (not an OSError) for a message whose signature
# does not verify or a closed connection; and whatever parsing a server
# message raised in smbprotocol's message worker, which stores the
# exception and re-raises it in the caller (smbprotocol/connection.py
# _process_message_thread, _check_worker_running) - KeyError for an
# unknown message id, struct.error / ValueError / IndexError for a short
# or malformed message.
_SMB_FAILURES: tuple[type[BaseException], ...] = (
    OSError,
    SMBOSError,
    SMBException,
    KeyError,
    IndexError,
    ValueError,
    struct.error,
)




# NT statuses smbprotocol's SMBOSError gives errno 0 ("Unknown NtStatus")
# that have a POSIX meaning ([MS-ERREF] 2.3.1).
_NT_ERRNO = {
    0xC0000022: errno.EACCES,  # STATUS_ACCESS_DENIED
    0xC0000121: errno.EACCES,  # STATUS_CANNOT_DELETE
    0xC0000056: errno.EACCES,  # STATUS_DELETE_PENDING
    0xC0000043: errno.EBUSY,  # STATUS_SHARING_VIOLATION (also EPERM in smbprotocol)
    0xC000007F: errno.ENOSPC,  # STATUS_DISK_FULL
    0xC0000033: errno.EINVAL,  # STATUS_OBJECT_NAME_INVALID
    0xC0000034: errno.ENOENT,  # STATUS_OBJECT_NAME_NOT_FOUND
    0xC000003A: errno.ENOENT,  # STATUS_OBJECT_PATH_NOT_FOUND
    0xC0000035: errno.EEXIST,  # STATUS_OBJECT_NAME_COLLISION
    0xC00000BA: errno.EISDIR,  # STATUS_FILE_IS_A_DIRECTORY
    0xC0000103: errno.ENOTDIR,  # STATUS_NOT_A_DIRECTORY
    0xC0000101: errno.ENOTEMPTY,  # STATUS_DIRECTORY_NOT_EMPTY
}


def _smb_error(exc: BaseException, what: str, path: str) -> OSError:
    """*exc* as the OSError the backend contract names: smbprotocol's
    SMBOSError carries the errno of its NT status, but is no
    FileNotFoundError / FileExistsError / ...; ``OSError(errno, ...)``
    is. A plain ``OSError(str)`` lost the cause, so a caller could not
    tell "not there" (create it) from "denied" or a dropped connection.
    A failure without a POSIX meaning stays a plain OSError; a timeout
    or connection error keeps its class."""
    code = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
    status = getattr(exc, "ntstatus", None)
    if not code and isinstance(status, int):
        code = _NT_ERRNO.get(status)
    if isinstance(status, int):
        detail = f"{getattr(exc, 'strerror', None) or exc} [NtStatus 0x{status:08x}]"
    else:
        detail = str(exc) or type(exc).__name__
    if isinstance(code, int) and code in errno.errorcode:
        return OSError(code, f"{what}: {detail}", path)
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return type(exc)(f"{what}: {detail}")
    return OSError(f"{what}: {detail}")


def _is_not_found(exc: BaseException) -> bool:
    """True for an SMB answer that nothing is at the path: ENOENT
    (STATUS_OBJECT_NAME_NOT_FOUND / _PATH_NOT_FOUND / STATUS_NOT_FOUND)
    or ENOTDIR (STATUS_NOT_A_DIRECTORY: a file where the path needs a
    folder). STATUS_ACCESS_DENIED and the rest map to errno 0."""
    return isinstance(exc, OSError) and exc.errno in (errno.ENOENT, errno.ENOTDIR)


# acl_get: the parts of a security descriptor asked for ([MS-DTYP]
# 2.4.7 SECURITY_INFORMATION; smbprotocol spells OWNER "SECURTIY").
_SD_OWNER, _SD_GROUP, _SD_DACL = 0x1, 0x2, 0x4
_SD_MAX_BYTES = 64 * 1024
# dfs_referrals: the statuses of a path that is no DFS path
# (STATUS_NOT_FOUND, STATUS_FS_DRIVER_REQUIRED, STATUS_OBJECT_PATH_NOT_FOUND,
# STATUS_OBJECT_NAME_NOT_FOUND, STATUS_DFS_UNAVAILABLE).
_NOT_DFS = frozenset({0xC0000225, 0xC000019C, 0xC000003A, 0xC0000034, 0xC000026D})

_ACE_TYPES = {0x00: "allow", 0x01: "deny", 0x02: "audit", 0x03: "alarm", 0x05: "allow_object",
              0x06: "deny_object", 0x07: "audit_object", 0x09: "allow_callback",
              0x0A: "deny_callback", 0x11: "mandatory_label"}
_ACE_FLAGS = ((0x01, "OBJECT_INHERIT"), (0x02, "CONTAINER_INHERIT"), (0x04, "NO_PROPAGATE_INHERIT"),
              (0x08, "INHERIT_ONLY"), (0x10, "INHERITED"), (0x40, "SUCCESSFUL_ACCESS"),
              (0x80, "FAILED_ACCESS"))
# [MS-DTYP] 2.4.3 ACCESS_MASK, file rights of [MS-SMB2] 2.2.13.1.1.
_FULL_CONTROL = 0x001F01FF
_RIGHTS = (
    (0x00000001, "READ_DATA"),
    (0x00000002, "WRITE_DATA"),
    (0x00000004, "APPEND_DATA"),
    (0x00000008, "READ_EA"),
    (0x00000010, "WRITE_EA"),
    (0x00000020, "EXECUTE"),
    (0x00000040, "DELETE_CHILD"),
    (0x00000080, "READ_ATTRIBUTES"),
    (0x00000100, "WRITE_ATTRIBUTES"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x02000000, "MAXIMUM_ALLOWED"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
)
_SD_CONTROL = (
    (0x0001, "OWNER_DEFAULTED"),
    (0x0002, "GROUP_DEFAULTED"),
    (0x0004, "DACL_PRESENT"),
    (0x0008, "DACL_DEFAULTED"),
    (0x0010, "SACL_PRESENT"),
    (0x0020, "SACL_DEFAULTED"),
    (0x0400, "DACL_AUTO_INHERITED"),
    (0x0800, "SACL_AUTO_INHERITED"),
    (0x1000, "DACL_PROTECTED"),
    (0x2000, "SACL_PROTECTED"),
    (0x8000, "SELF_RELATIVE"),
)
_WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
}


def _names(value: int, table) -> list[str]:
    return [name for bit, name in table if value & bit]


def _describe_security(raw: bytes, path: str) -> dict:
    """acl_get's dict of a self-relative security descriptor."""
    from smbprotocol.security_descriptor import SMB2CreateSDBuffer

    try:
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)
        control = int(sd["control"].get_value())
        owner, group = sd.get_owner(), sd.get_group()
        dacl = sd.get_dacl()
        aces = []
        for ace in (dacl["aces"].get_value() if dacl is not None else []):
            mask = int(ace["mask"].get_value())
            flags = int(ace["ace_flags"].get_value())
            sid = str(ace["sid"].get_value())
            kind = int(ace["ace_type"].get_value())
            aces.append(
                {
                    "type": _ACE_TYPES.get(kind, f"type_{kind:#x}"),
                    "sid": sid,
                    "name": _WELL_KNOWN_SIDS.get(sid, ""),
                    "mask": mask,
                    "rights": ["FULL_CONTROL"]
                    if mask & _FULL_CONTROL == _FULL_CONTROL and not mask & ~_FULL_CONTROL
                    else _names(mask, _RIGHTS),
                    "flags": flags,
                    "flag_names": _names(flags, _ACE_FLAGS),
                }
            )
    except (ValueError, KeyError, IndexError, TypeError, struct.error, AttributeError) as exc:
        raise OSError(
            f"SMB acl_get {path}: the server's security descriptor cannot be read ({exc})"
        ) from exc
    if dacl is None:
        note = "no DACL: everyone has full access"
    elif not aces:
        note = "an empty DACL: no access for anyone but the owner's right to change it"
    else:
        note = ""
    return {
        "owner": str(owner) if owner is not None else "",
        "group": str(group) if group is not None else "",
        "control": control,
        "control_flags": _names(control, _SD_CONTROL),
        "dacl": aces if dacl is not None else None,
        "note": note,
    }


# Per-host lock registry so concurrent SmbSession constructors don't
# race on smbclient's process-wide session pool.
_SESSION_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()

# Serialises the ``socket.gethostname`` patch used by
# ``_patched_gethostname``. Without this, two threads constructing
# SmbSession(host=A) and SmbSession(host=B) in parallel would both
# swap the module-global ``socket.gethostname`` around the same
# register_session call and thread B's choice could leak into thread
# A's NTLM negotiation. The per-host lock above only serialises the
# smbclient pool, not this process-global patch.
_GETHOSTNAME_PATCH_LOCK = threading.Lock()


def _session_lock(host: str) -> threading.Lock:
    with _LOCKS_LOCK:
        lock = _SESSION_LOCKS.get(host)
        if lock is None:
            lock = threading.Lock()
            _SESSION_LOCKS[host] = lock
    return lock


@contextlib.contextmanager
def _patched_gethostname(name: str):
    """Temporarily override ``socket.gethostname()`` with *name*.

    smbprotocol reaches through spnego to build the NTLM
    ``WorkstationName`` field, and spnego pulls the workstation
    identifier from ``socket.gethostname()``. There is no SDK-level
    knob to override that; patching the function for the duration of
    the ``register_session`` call is the least-invasive way to stop
    the local hostname from landing in remote Event Log entries.
    See docs/OPSEC.md #3.

    The patch is process-global, so ``_GETHOSTNAME_PATCH_LOCK``
    serialises patched regions across threads — otherwise two
    SmbSession init paths on different hosts could interleave and
    one thread's replacement hostname could leak into the other
    thread's NTLM handshake.
    """
    if not name:
        # No override requested — run untouched.
        yield
        return
    with _GETHOSTNAME_PATCH_LOCK:
        original = socket.gethostname
        socket.gethostname = lambda: name  # type: ignore[assignment]
        try:
            yield
        finally:
            socket.gethostname = original  # type: ignore[assignment]


_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FILE_ATTRIBUTE_READONLY = 0x01  # smbprotocol FileAttributes, MS-FSCC 2.6
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_HIDDEN = 0x02
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_SMB_PORT = 445


def _host_key(name: str) -> str:
    """*name* as one spelling: lowercase, without the trailing dot of an
    absolute name or the brackets of an IPv6 literal."""
    return str(name).strip().strip("[]").rstrip(".").lower()


def _is_address(name: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(name.partition("%")[0])
    except ValueError:
        return False
    return True


def _addresses(name: str) -> frozenset[str]:
    """The addresses *name* resolves to; empty when it does not."""
    try:
        return frozenset(info[4][0] for info in socket.getaddrinfo(name, None))
    except (OSError, UnicodeError):
        return frozenset()


def _alive(connection) -> bool:
    transport = getattr(connection, "transport", None)
    return bool(getattr(transport, "connected", False))


class _ReferralPortCache(dict):
    """A session's smbclient connection pool (``connection_cache``) that
    keeps a non-default port to the server the user named.

    smbclient opens every connection on the ``port`` of the call - also
    the one to the server a DFS referral sends it to. So a namespace
    server on, say, 4445 sent every referral to the target's port 4445,
    where nothing listens. smbclient looks a connection up here by
    ``"server:port"`` before it dials (``_pool.register_session``): for
    any server but the original one, a lookup on the session's port gets
    that server's connection on 445 instead.

    "The original one" is the same server, not the same string: a
    referral that names the namespace server by its FQDN where the user
    typed the short name (or its address, or the other way round) must
    keep the session's port. Names are compared by their addresses; with
    a proxy (*resolve* False: a lookup here would leak the name to the
    local resolver) or when one does not resolve, a short name matches
    the first label of a full one.
    """

    def __init__(self, host: str, port: int, *, resolve: bool = True, dial=None) -> None:
        super().__init__()
        self._origin = host.lower()
        self._origin_key = _host_key(host)
        self._port = int(port)
        self._resolve = resolve
        self._same: dict[str, bool] = {}
        # dial(server, port, connection) -> a connected Connection with
        # this session's authenticated Session in its session_table.
        # With one, every connection this pool hands smbclient is alive
        # and logged in, so smbclient's register_session never dials or
        # authenticates by itself - it would do that with username=None
        # (implicit Kerberos as whoever holds the local ticket), straight
        # past the proxy and with the real hostname in NTLM.
        self._dial = dial
        self._dial_lock = threading.Lock()
        self._closed = False

    def _is_origin(self, server: str) -> bool:
        key = _host_key(server)
        if key == self._origin_key:
            return True
        if key not in self._same:
            self._same[key] = self._same_server(self._origin_key, key)
        return self._same[key]

    def _same_server(self, a: str, b: str) -> bool:
        if self._resolve:
            mine, theirs = _addresses(a), _addresses(b)
            if mine and theirs:
                return bool(mine & theirs)
        if _is_address(a) or _is_address(b) or ("." in a) == ("." in b):
            return False
        short, full = (a, b) if "." not in a else (b, a)
        return full.split(".", 1)[0] == short

    def get(self, key, default=None):
        server, _, port = str(key).rpartition(":")
        remapped = False
        if self._port != _SMB_PORT and port == str(self._port) and not self._is_origin(server):
            hit = super().get(key)
            if hit is not None and _alive(hit):
                return hit
            key, port, remapped = f"{server}:{_SMB_PORT}", str(_SMB_PORT), True
        hit = super().get(key, default)
        if self._closed:
            # After close() nothing dials again; a dead connection left
            # here would make smbclient dial a fresh one by itself.
            if hit is not None and _alive(hit):
                return hit
            self._drop(key)
            raise ConnectionError(errno.ENOTCONN, "SMB session closed")
        if self._dial is None:
            if not remapped or (hit is not None and _alive(hit)):
                return hit
            from smbclient._pool import ClientConfig
            from smbprotocol.connection import Connection

            connection = Connection(ClientConfig().client_guid, server, _SMB_PORT)
            connection.connect(timeout=60)
            self[key] = connection
            return connection
        if hit is not None and _alive(hit) and hit.session_table:
            return hit
        with self._dial_lock:
            hit = super().get(key)
            if hit is not None and _alive(hit) and hit.session_table:
                return hit
            if hit is not None and not _alive(hit):
                self._drop(key)
                hit = None
            log.info("SMB: (re)connecting to %s:%s", server, port)
            connection = self._dial(server, int(port), hit)
            self[key] = connection
            return connection

    def _drop(self, key: str) -> None:
        connection = self.pop(key, None)
        if connection is None:
            return
        try:
            connection.disconnect()
        except Exception as exc:  # noqa: BLE001 - it is gone either way
            log.debug("SMB: closing the dead connection %s failed: %s", key, exc)

    def shut(self) -> None:
        """No more dials: from now on a lookup of a dead or missing
        connection raises ConnectionError."""
        self._closed = True

    def close_all(self) -> None:
        """shut() and disconnect every connection of this pool."""
        self._closed = True
        for key in list(self):
            self._drop(key)


class SmbSession(SessionLifecycle):
    """SMB/CIFS backend implementing the FileBackend protocol.

    Uses smbclient (high-level wrapper over smbprotocol).
    Paths are stored internally as UNC: \\\\server\\share\\path
    but the UI sees forward-slash paths relative to the share root.
    """

    _port: int = 445

    @property
    def _kw(self) -> dict:
        """Connection arguments for every smbclient call. smbclient keys its
        pool by "host:port" and defaults every call to port 445, so a call
        without them dials 445 - not the port this session registered."""
        kw = {"port": self._port}
        connections = getattr(self, "_connections", None)
        if connections is not None:
            # This session's own pool: smbclient's default one is keyed
            # by host:port for the whole process, so a second pane on
            # another share of the same server shared - and on connect
            # or close tore down - this pane's connection, and a call
            # without credentials ran as whoever logged in last.
            kw["connection_cache"] = connections
        username = getattr(self, "_username", "")
        if username:
            # Should smbclient ever create a session itself, it uses
            # these credentials - not username=None (implicit Kerberos
            # as the local ticket holder) - and its lookup only matches
            # a session of this user.
            kw["username"] = username
            kw["password"] = getattr(self, "_password", "")
        return kw

    def _dial(self, server: str, port: int, connection=None):
        """Connect (unless *connection* is still up) and log in to
        *server*:*port* the way __init__ did: through the profile's
        proxy, with the masked workstation name in NTLM and with this
        session's credentials. The pool (_ReferralPortCache) calls it for
        the first connection, after a connection dropped and for the
        server a DFS referral names."""
        import smbclient._pool as pool
        from core.proxy import patched_create_connection

        with (
            _patched_gethostname(self._client_name),
            patched_create_connection(self._proxy),
        ):
            fresh = connection is None
            if fresh:
                connection = pool.Connection(
                    pool.ClientConfig().client_guid, server, port, require_signing=True
                )
                connection.connect(timeout=60)
            try:
                session = pool.Session(
                    connection,
                    username=self._username,
                    password=self._password,
                    require_encryption=False,
                    auth_protocol="negotiate",
                )
                session.connect()
            except BaseException:
                if fresh:
                    try:
                        connection.disconnect()
                    except Exception as exc:  # noqa: BLE001 - failing anyway
                        log.debug("SMB: closing after a failed login: %s", exc)
                raise
        if _host_key(server) == _host_key(self._host) and int(port) == int(self._port):
            self._smb_session = session
        return connection

    def __init__(
        self,
        host: str,
        share: str,
        username: str = "",
        password: str = "",
        port: int = 445,
        client_name: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if smbclient is None:
            detail = f": {_SMB_IMPORT_ERROR}" if _SMB_IMPORT_ERROR else ""
            raise ImportError(
                f"SMB support requires smbprotocol. Install with: pip install axross[smb]{detail}"
            )

        self._host = host
        self._share = share
        self._username = username
        self._password = password
        self._port = port
        self._prefix = f"\\\\{host}\\{share}"
        from core.proxy import ProxyConfig

        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )

        # smbclient keeps a process-wide session registry. Two threads
        # constructing SmbSession(host=X, ...) concurrently can race on
        # the delete+register pair: thread A deletes, thread B deletes
        # (no-op), A registers, B registers, A listdirs — sometimes the
        # session that A registered is the one B's listdir sees. The
        # per-host lock below makes init atomic per-host: each thread
        # owns the registry entry for host during delete→register→probe.
        self._client_name = client_name or SMB_CLIENT_NAME

        # Every connection of this session is dialled by self._dial (the
        # pool calls it): inside two scoped patches that nest cleanly -
        # 1) socket.gethostname returns our chosen WORKSTATION name
        #    (OpSec finding #3 - keeps the real hostname out of NTLM)
        # 2) socket.create_connection routes through the SOCKS / HTTP
        #    proxy when the profile has one set, otherwise no-op -
        # and logged in with this session's credentials. That covers the
        # first connection, every redial after the connection dropped and
        # the server a DFS referral names; smbclient never dials alone.
        self._connections: dict = _ReferralPortCache(
            host, port, resolve=self._proxy.proxy_type == "none", dial=self._dial
        )
        with _session_lock(host):
            # kept for security_info(): dialect, signing, encryption
            try:
                self._smb_session = smbclient.register_session(
                    host,
                    username=username,
                    password=password,
                    port=port,
                    connection_cache=self._connections,
                )
            except BaseException:
                self._close_connections()
                raise
            # Verify credentials eagerly by doing a cheap listdir
            # on the share root so a wrong-password / wrong-share
            # misconfiguration surfaces at connection time instead
            # of halfway into a transfer.
            try:
                smbclient.listdir(self._prefix, **self._kw)
            except Exception as exc:
                self._close_connections()
                raise OSError(f"SMB connect failed for {self._prefix}: {exc}") from exc

        log.info("SMB connected: %s@%s\\%s:%d", username, host, share, port)

    @property
    def name(self) -> str:
        return f"\\\\{self._host}\\{self._share} (SMB)"

    def security_info(self):
        """The negotiated SMB protection (dialect; encrypted, signed or
        neither) for the security badge; None before a session exists."""
        from core.conn_security import smb_session

        return smb_session(getattr(self, "_smb_session", None), self._share)

    @property
    def connected(self) -> bool:
        try:
            smbclient.listdir(self._prefix, **self._kw)
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("SMB liveness check of %s failed: %s", self._prefix, exc)
            return False

    def close(self) -> None:
        """Tear down this session's entry in smbclient's global registry.

        Without this, subsequent SmbSession()s for the same host silently
        reuse our credentials (or vice versa), which causes test-order
        bugs and means disconnected UI sessions leak kernel resources.
        """
        self._close_connections()

    def _close_connections(self) -> None:
        connections = getattr(self, "_connections", None)
        if isinstance(connections, _ReferralPortCache):
            # First: no redial while (or after) closing.
            connections.shut()
        kw = {"port": self._port}
        if connections is not None:
            kw["connection_cache"] = connections
        try:
            smbclient.delete_session(self._host, **kw)
        except Exception as exc:
            log.debug("smbclient.delete_session(%s) raised: %s", self._host, exc)
        if isinstance(connections, _ReferralPortCache):
            connections.close_all()

    def disconnect(self) -> None:
        self.close()

    def _unc(self, path: str) -> str:
        """Convert a UI path (forward slashes) to UNC path."""
        # Strip leading / and convert to backslashes
        clean = path.lstrip("/").replace("/", "\\")
        if clean:
            return f"{self._prefix}\\{clean}"
        return self._prefix

    def _to_ui_path(self, unc: str) -> str:
        """Convert UNC path back to UI path (forward slashes)."""
        if unc.startswith(self._prefix):
            rel = unc[len(self._prefix) :]
        else:
            rel = unc
        return "/" + rel.replace("\\", "/").lstrip("/")

    def list_dir(self, path: str) -> list[FileItem]:
        unc = self._unc(path)
        items: list[FileItem] = []
        try:
            for entry in smbclient.scandir(unc, **self._kw):
                if entry.name in (".", ".."):
                    continue
                # The directory query already carries attributes, size and
                # times; entry.stat() costs one extra SMB call per entry.
                # Symlinks still need it: their target decides type and size.
                is_link = entry.is_symlink()
                item = None if is_link else self._dir_info_to_item(entry)
                if item is not None:
                    items.append(item)
                    continue
                try:
                    # Not entry.stat(): SMBDirEntry passes no port on.
                    st = smbclient.stat(entry.path, **self._kw)
                    item = self._stat_to_item(entry.name, st)
                except _SMB_FAILURES as e:
                    log.warning("Cannot stat %s: %s", entry.name, e)
                    item = FileItem(name=entry.name)
                # Marked as a link: a recursive delete removes the link
                # itself instead of descending into its target. An entry
                # that only fell back to stat() (an unusable FILETIME) is
                # not a link.
                items.append(dataclasses.replace(item, is_link=True) if is_link else item)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot list {path}", path) from e
        return items

    def stat(self, path: str) -> FileItem:
        unc = self._unc(path)
        try:
            st = smbclient.stat(unc, **self._kw)
            name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or path
            item = self._stat_to_item(name, st)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot stat {path}", path) from e
        # smbclient normalizes the trailing backslash away: "g/" answered
        # with the file g. A path ending in "/" names a folder (stat(2)).
        if path.endswith("/") and path.strip("/") and not item.is_dir:
            raise NotADirectoryError(errno.ENOTDIR, f"Cannot stat {path}: not a folder", path)
        return item

    def is_dir(self, path: str) -> bool:
        """False only for "not found" (smbclient answers ENOENT with
        False itself) or a file on the way; access denied, a dropped
        connection or a garbled message is an OSError - remove() and the
        transfer layer pick their action from this answer."""
        try:
            return smbclient.path.isdir(self._unc(path), **self._kw)
        except _LINK_REDIRECTION:
            # A link to another server: no folder of this share (and
            # remove() deletes the link itself).
            return False
        except _SMB_FAILURES as e:
            if _is_not_found(e):
                return False
            raise _smb_error(e, f"Cannot check {path}", path) from e

    def exists(self, path: str) -> bool:
        """Whether the entry itself is there - lstat, as on every other
        backend: smbclient.path.exists follows a link, so a dangling one
        or one to another server answered False and an overwrite=False
        copy wrote over it. False only for "not found"; any other failure
        is an OSError - server_side_copy(overwrite=False) takes False as
        its go-ahead."""
        try:
            return smbclient.path.lexists(self._unc(path), **self._kw)
        except _SMB_FAILURES as e:
            if _is_not_found(e):
                return False
            raise _smb_error(e, f"Cannot check {path}", path) from e

    def mkdir(self, path: str) -> None:
        try:
            smbclient.mkdir(self._unc(path), **self._kw)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot create directory {path}", path) from e

    def remove(self, path: str, recursive: bool = False) -> None:
        unc = self._unc(path)
        try:
            if self.is_dir(path):
                if recursive and not self._is_reparse_point(unc):
                    self._rmdir_recursive(path)
                else:
                    # A link to a directory goes as the link: smbclient
                    # deletes with FILE_OPEN_REPARSE_POINT, never the target.
                    smbclient.rmdir(unc, **self._kw)
            else:
                smbclient.remove(unc, **self._kw)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot remove {path}", path) from e

    def _is_reparse_point(self, unc: str) -> bool:
        """A symlink, junction or mount point (the entry itself, not its
        target): a recursive delete must not descend into it."""
        if smbclient.path.islink(unc, **self._kw):
            return True
        attrs = getattr(smbclient.lstat(unc, **self._kw), "st_file_attributes", 0)
        return isinstance(attrs, int) and bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)

    _MAX_TREE_DEPTH = MAX_RECURSIVE_DELETE_DEPTH

    def _rmdir_recursive(self, path: str, depth: int = 0) -> None:
        check_tree_depth(path, depth, self._MAX_TREE_DEPTH)
        children = []
        for item in self.list_dir(path):
            try:
                child = safe_join(self, path, item.name)
            except ValueError as exc:
                raise OSError(
                    f"Cannot recursively remove {path}: unsafe child name {item.name!r}: {exc}"
                ) from exc
            children.append((item, child))
        for item, child in children:
            removal_cancel.checkpoint(child)  # the pane's Cancel stops here
            if item.is_link:
                # Never descend through a link: its target may lie outside
                # the tree being deleted. Only the link itself goes.
                if item.is_dir:
                    smbclient.rmdir(self._unc(child), **self._kw)
                else:
                    smbclient.remove(self._unc(child), **self._kw)
            elif item.is_dir:
                self._rmdir_recursive(child, depth + 1)
            else:
                smbclient.remove(self._unc(child), **self._kw)
            removal_cancel.removed(child)
        smbclient.rmdir(self._unc(path), **self._kw)

    def rename(self, src: str, dst: str) -> None:
        # smbclient drops the trailing backslash: a file renamed to "x/"
        # became a FILE x. A folder may be named so.
        refuse_folder_path(dst, "rename to",
                           source_is_file=lambda: self._exists_quietly(src) and not self.is_dir(src))
        try:
            smbclient.rename(self._unc(src), self._unc(dst), **self._kw)
        except _SMB_FAILURES as e:
            # Samba refuses a rename onto an existing name with
            # STATUS_ACCESS_DENIED, not OBJECT_NAME_COLLISION: name the
            # cause, so an overwrite can swap through a backup instead.
            if self._exists_quietly(dst):
                raise FileExistsError(
                    errno.EEXIST, f"Cannot rename {src} -> {dst}: target exists ({e})", dst
                ) from e
            raise _smb_error(e, f"Cannot rename {src} -> {dst}", src) from e

    def rename_no_replace(self, src: str, dst: str) -> None:
        """``rename`` already refuses an existing *dst* (smbclient.rename
        does not replace; ``replace`` would): named, so a move within the
        share knows it (core.transfer_worker)."""
        self.rename(src, dst)

    def set_modified(self, path: str, mtime: float) -> None:
        """Set *path*'s modification time (epoch seconds; SMB keeps 100 ns),
        so a copy keeps its source's time. The access time stays."""
        unc = self._unc(path)
        try:
            atime = smbclient.stat(unc, **self._kw).st_atime
            smbclient.utime(unc, times=(atime, mtime), **self._kw)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot set the modification time of {path}", path) from e

    def _exists_quietly(self, path: str) -> bool:
        try:
            return bool(smbclient.path.exists(self._unc(path), **self._kw))
        except Exception as exc:  # noqa: BLE001 - "not there" is the caller's safe answer
            log.debug("SMB exists(%s) failed, taken as missing: %s", path, exc)
            return False

    def open_read(self, path: str) -> IO[bytes]:
        if path.endswith("/") and path.strip("/"):
            # smbclient would open the FILE "x" for "x/"; a folder is
            # refused by the server (EISDIR) either way.
            if not self.is_dir(path):
                if not self._exists_quietly(path):
                    raise FileNotFoundError(errno.ENOENT, f"Cannot read {path}: not found", path)
                raise NotADirectoryError(errno.ENOTDIR, f"Cannot read {path}: not a folder", path)
        try:
            return smbclient.open_file(self._unc(path), mode="rb", **self._kw)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot read {path}", path) from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # smbclient drops the trailing backslash: "t/" was written as a FILE t.
        refuse_folder_path(path)
        mode = "ab" if append else "wb"
        try:
            return smbclient.open_file(self._unc(path), mode=mode, **self._kw)
        except _SMB_FAILURES as e:
            raise _smb_error(e, f"Cannot write {path}", path) from e

    def normalize(self, path: str) -> str:
        # Use forward slashes for UI
        normalized = posixpath.normpath(path.replace("\\", "/"))
        return normalized if normalized != "." else "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("SMB does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("SMB does not support symlinks")

    # ------------------------------------------------------------------
    # SMB-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    @staticmethod
    def shares_list(
        host: str, *, username: str = "", password: str = "", timeout: float = 10.0,
        domain: str = "", port: int = 445,
    ) -> list[dict]:
        """Enumerate shares published by ``host``. Static method so a
        script can browse before mounting a specific share.

        Implementation: NetShareEnum over the SRVSVC pipe through impacket
        (:func:`core.smb_shares.list_shares`) - no ``smbclient`` binary, so
        the password never reaches a child process.

        Returns one dict per share ``{name, type, comment, special}`` where
        ``type`` is ``Disk``, ``Printer``, ``Device`` or ``IPC`` and
        ``special`` marks the hidden admin shares (``C$``, ``IPC$``).

        Raises ``ValueError`` for a bad host, ``PermissionError`` for a
        refused logon, ``OSError`` when the host cannot be reached or
        impacket is missing.
        """
        from core.smb_shares import list_shares

        if "\r" in host or "\n" in host:
            raise ValueError("SMB shares_list host must not contain CR/LF")
        return list_shares(host, username=username, password=password, domain=domain,
                           port=port, timeout=timeout)

    def _query_security(self, unc: str) -> bytes:
        """The raw security descriptor of *unc* (owner, group, DACL):
        an SMB2 QUERY_INFO of type SECURITY on a READ_CONTROL handle."""
        from smbclient._io import SMBFileTransaction, SMBRawIO
        from smbprotocol.file_info import InfoType
        from smbprotocol.open import (
            FilePipePrinterAccessMask,
            SMB2QueryInfoRequest,
            SMB2QueryInfoResponse,
        )

        raw = SMBRawIO(unc, mode="rb", share_access="rwd",
                       desired_access=FilePipePrinterAccessMask.READ_CONTROL, **self._kw)
        with SMBFileTransaction(raw) as transaction:
            request = SMB2QueryInfoRequest()
            request["info_type"] = InfoType.SMB2_0_INFO_SECURITY
            request["output_buffer_length"] = _SD_MAX_BYTES
            request["additional_information"] = _SD_OWNER | _SD_GROUP | _SD_DACL
            request["file_id"] = raw.fd.file_id

            def receive(sent):
                response = raw.fd.connection.receive(sent)
                answer = SMB2QueryInfoResponse()
                answer.unpack(response["data"].get_value())
                return answer["buffer"].get_value()

            transaction += (request, receive)
        return transaction.results[0]

    def acl_get(self, path: str) -> dict:
        """The security descriptor of *path*: ``{owner, group, control,
        control_flags, dacl, note}``. ``dacl`` is a list of ACEs
        ``{type, sid, name, mask, rights, flags, flag_names}`` (``name``
        for well-known SIDs), or None when the object has no DACL
        (everyone has full access); an empty list denies everyone."""
        unc = self._unc(path)
        try:
            raw = self._query_security(unc)
        except _SMB_FAILURES as exc:
            errno_value = getattr(exc, "errno", None)
            if isinstance(errno_value, int) and errno_value:
                raise OSError(errno_value, f"SMB acl_get {path}: {exc}") from exc
            raise OSError(f"SMB acl_get {path}: {exc}") from exc
        return _describe_security(raw, path)

    def _dfs_lookup(self, unc: str) -> list[tuple[str, str, bool, int]] | None:
        """The DFS referral entries for *unc* as ``(dfs path, target,
        root, ttl)``, the server's preferred target first; None when the
        server has no DFS namespace there."""
        from smbclient._pool import dfs_request, get_smb_tree
        from smbprotocol.dfs import DFSServerTypes
        from smbprotocol.exceptions import SMBResponseException

        tree, _path = get_smb_tree(f"\\\\{self._host}\\IPC$", **self._kw)
        try:
            response = dfs_request(tree, unc)
        except SMBResponseException as exc:
            if exc.status in _NOT_DFS:
                return None
            raise
        out = []
        for entry in response["referral_entries"].get_value() or ():
            ttl = entry["time_to_live"].get_value() if "time_to_live" in entry.fields else 0
            out.append(
                (
                    str(entry.dfs_path) if hasattr(entry, "dfs_path") else unc.lstrip("\\"),
                    str(entry.network_address),
                    entry["server_type"].has_flag(DFSServerTypes.ROOT_TARGETS),
                    int(ttl or 0),
                )
            )
        return out or None

    def dfs_referrals(self, path: str = "/") -> list[dict]:
        """Where the DFS path *path* leads: one ``{dfs_path, target, root,
        link, ttl}`` per target, the server's preferred one first; [] when
        it is no DFS path (FSCTL_DFS_GET_REFERRALS on IPC$)."""
        unc = self._unc(path)
        try:
            entries = self._dfs_lookup(unc)
        except _SMB_FAILURES as exc:
            raise OSError(f"SMB dfs_referrals {path}: {exc}") from exc
        return [{"dfs_path": dfs_path, "target": target, "root": root, "link": not root, "ttl": ttl}
                for dfs_path, target, root, ttl in entries or ()]

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """SMB has no client-exposed server-side copy. Raise for fallback."""
        raise OSError("SMB has no server-side copy primitive in this backend")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """SMB has no native checksum operation. Returning "" lets
        callers decide to stream-hash via open_read if they need one."""
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Try smbclient.shutil.disk_usage (available in smbprotocol >= 1.10)
        try:
            import smbclient.shutil as smb_shutil

            usage = smb_shutil.disk_usage(self._unc(path), **self._kw)
            return (usage.total, usage.used, usage.free)
        except (AttributeError, ImportError):
            log.debug("smbclient.shutil.disk_usage not available")
        except (OSError, SMBOSError, Exception) as e:
            log.debug("SMB disk_usage failed: %s", e)
        return (0, 0, 0)

    @staticmethod
    def _modified(us: int) -> datetime:
        """Local naive mtime from whole microseconds since the epoch.

        Listing and stat both go through here with the microseconds floored,
        as smbprotocol floors FILETIME for directory entries; rounding a
        float in one path and flooring in the other made them disagree by
        a microsecond.

        A FILETIME at the edge of datetime's range (a server may report
        9999-12-31 23:59:59 UTC) is out of range as local time east of
        UTC (year 10000); such a time reads as the epoch, like a missing
        one."""
        if not us:
            return datetime.fromtimestamp(0)
        try:
            return datetime.fromtimestamp(us / 1_000_000)
        except (ValueError, OverflowError, OSError):
            return datetime.fromtimestamp(0)

    @classmethod
    def _dir_info_to_item(cls, entry) -> FileItem | None:
        """FileItem from the directory query of a non-symlink entry — the
        same fields smbclient's stat() would compute (st_mode from the
        attributes, end_of_file, last_write_time). None when unusable."""
        info = entry.smb_info
        written = info.last_write_time
        if getattr(written, "tzinfo", None) is None:
            return None  # datetime.max placeholder for an out-of-range FILETIME
        attrs = int(info.file_attributes)
        is_dir = bool(attrs & _FILE_ATTRIBUTE_DIRECTORY)
        mode = 0o444 if attrs & _FILE_ATTRIBUTE_READONLY else 0o666
        if is_dir:
            mode |= 0o111
        us = (written - _EPOCH_UTC) // timedelta(microseconds=1)
        return FileItem(
            name=entry.name,
            size=int(info.end_of_file) if not is_dir else 0,
            modified=cls._modified(us),
            permissions=mode & 0o777,
            is_dir=is_dir,
            attr_hidden=bool(attrs & _FILE_ATTRIBUTE_HIDDEN),
            # A folder that is a reparse point - an NTFS junction or mount
            # point, not only a symlink - counts as a link: a recursive
            # delete removes it and never empties its target.
            is_link=is_dir and bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT),
        )

    @classmethod
    def _stat_to_item(cls, name: str, st) -> FileItem:
        is_dir = stat_module.S_ISDIR(st.st_mode)
        modified = cls._modified(st.st_mtime_ns // 1000)
        attrs = getattr(st, "st_file_attributes", 0)
        return FileItem(
            name=name,
            size=st.st_size if not is_dir else 0,
            modified=modified,
            permissions=st.st_mode & 0o777,
            is_dir=is_dir,
            attr_hidden=isinstance(attrs, int) and bool(attrs & _FILE_ATTRIBUTE_HIDDEN),
        )
