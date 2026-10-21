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

from core.backend import SessionLifecycle
from core.client_identity import SMB_CLIENT_NAME
from core.path_policy import MAX_RECURSIVE_DELETE_DEPTH, check_tree_depth, safe_join
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

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
_FILE_ATTRIBUTE_HIDDEN = 0x02
_FILE_ATTRIBUTE_DIRECTORY = 0x10


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
        return {"port": self._port}

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
        effective_client_name = client_name or SMB_CLIENT_NAME
        from core.proxy import patched_create_connection

        with _session_lock(host):
            try:
                smbclient.delete_session(host, port=port)
            except Exception:
                pass

            # Two scoped patches that nest cleanly:
            # 1) socket.gethostname returns our chosen WORKSTATION name
            #    (OpSec finding #3 — keeps the real hostname out of NTLM)
            # 2) socket.create_connection routes through the SOCKS / HTTP
            #    proxy when the profile has one set, otherwise no-op.
            #
            # Both patches MUST cover the eager probe listdir below as
            # well — register_session is lazy, the actual TCP socket
            # opens on first IO. Once it's open, the smbclient pool
            # reuses the same socket for every subsequent op so the
            # proxy stays in effect without re-patching.
            with (
                _patched_gethostname(effective_client_name),
                patched_create_connection(self._proxy),
            ):
                smbclient.register_session(
                    host,
                    username=username,
                    password=password,
                    port=port,
                )
                # Verify credentials eagerly by doing a cheap listdir
                # on the share root so a wrong-password / wrong-share
                # misconfiguration surfaces at connection time instead
                # of halfway into a transfer.
                try:
                    smbclient.listdir(self._prefix, **self._kw)
                except Exception as exc:
                    try:
                        smbclient.delete_session(host, port=port)
                    except Exception:
                        pass
                    raise OSError(f"SMB connect failed for {self._prefix}: {exc}") from exc

        log.info("SMB connected: %s@%s\\%s:%d", username, host, share, port)

    @property
    def name(self) -> str:
        return f"\\\\{self._host}\\{self._share} (SMB)"

    @property
    def connected(self) -> bool:
        try:
            smbclient.listdir(self._prefix, **self._kw)
            return True
        except Exception:
            return False

    def close(self) -> None:
        """Tear down this session's entry in smbclient's global registry.

        Without this, subsequent SmbSession()s for the same host silently
        reuse our credentials (or vice versa), which causes test-order
        bugs and means disconnected UI sessions leak kernel resources.
        """
        try:
            smbclient.delete_session(self._host, **self._kw)
        except Exception as exc:
            log.debug("smbclient.delete_session(%s) raised: %s", self._host, exc)

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
            raise OSError(f"Cannot list {path}: {e}") from e
        return items

    def stat(self, path: str) -> FileItem:
        unc = self._unc(path)
        try:
            st = smbclient.stat(unc, **self._kw)
            name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or path
            return self._stat_to_item(name, st)
        except _SMB_FAILURES as e:
            raise OSError(f"Cannot stat {path}: {e}") from e

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
            raise OSError(f"Cannot check {path}: {e}") from e

    def exists(self, path: str) -> bool:
        """False only for "not found"; any other failure is an OSError -
        server_side_copy(overwrite=False) takes False as its go-ahead."""
        try:
            return smbclient.path.exists(self._unc(path), **self._kw)
        except _SMB_FAILURES as e:
            if _is_not_found(e):
                return False
            raise OSError(f"Cannot check {path}: {e}") from e

    def mkdir(self, path: str) -> None:
        try:
            smbclient.mkdir(self._unc(path), **self._kw)
        except _SMB_FAILURES as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        unc = self._unc(path)
        try:
            if self.is_dir(path):
                if recursive and not smbclient.path.islink(unc, **self._kw):
                    self._rmdir_recursive(path)
                else:
                    # A link to a directory goes as the link: smbclient
                    # deletes with FILE_OPEN_REPARSE_POINT, never the target.
                    smbclient.rmdir(unc, **self._kw)
            else:
                smbclient.remove(unc, **self._kw)
        except _SMB_FAILURES as e:
            raise OSError(f"Cannot remove {path}: {e}") from e

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
        smbclient.rmdir(self._unc(path), **self._kw)

    def rename(self, src: str, dst: str) -> None:
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
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def _exists_quietly(self, path: str) -> bool:
        try:
            return bool(smbclient.path.exists(self._unc(path), **self._kw))
        except Exception:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        try:
            return smbclient.open_file(self._unc(path), mode="rb", **self._kw)
        except _SMB_FAILURES as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        mode = "ab" if append else "wb"
        try:
            return smbclient.open_file(self._unc(path), mode=mode, **self._kw)
        except _SMB_FAILURES as e:
            raise OSError(f"Cannot write {path}: {e}") from e

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
        host: str, *, username: str = "", password: str = "", timeout: float = 10.0
    ) -> list[dict]:
        """Enumerate shares published by ``host``. Static method so a
        script can browse before mounting a specific share.

        Implementation: shells out to the system ``smbclient -L``
        (samba-client package). Pure-Python NetShareEnum via DCE-RPC
        over IPC$ would be possible with smbprotocol but adds ~400 LOC;
        every Linux distro that ships SMB tools also ships ``smbclient``,
        so the shellout is a fair trade.

        Returns one dict per share ``{name, type, comment}`` where
        ``type`` is ``Disk``, ``Printer``, ``IPC``, or whatever the
        server reports.

        Raises ``OSError`` when ``smbclient`` is missing.
        """
        import shutil as _shutil
        import subprocess as _sp

        if "\r" in host or "\n" in host:
            raise ValueError("SMB shares_list host must not contain CR/LF")
        binary = _shutil.which("smbclient")
        if not binary:
            raise OSError(
                "shares_list requires the system 'smbclient' binary (install samba-client / samba)"
            )
        from core.subprocess_env import clean_child_env

        cmd = [binary, "-L", f"//{host}", "-g"]
        env = clean_child_env()
        env.pop("PASSWD", None)
        if username:
            # Never "-U user%password": argv is world readable in /proc
            # and ps, and smbclient scrubs it only after startup. smbclient
            # reads the PASSWD environment variable instead (smbclient(1)),
            # which only this user can see. It splits "-U" at "%" itself,
            # so a "%" in the name would turn the rest into a password.
            if "%" in username:
                raise ValueError("SMB shares_list username must not contain '%'")
            cmd += ["-U", username]
            env["PASSWD"] = password
        else:
            cmd += ["-N"]  # no auth
        try:
            proc = _sp.run(cmd, capture_output=True, text=True, timeout=float(timeout), env=env)
        except _sp.TimeoutExpired as exc:
            raise OSError(f"smbclient -L {host} timed out") from exc
        if proc.returncode != 0:
            stderr = (proc.stderr or proc.stdout).strip() or "smbclient -L returned non-zero"
            raise OSError(f"smbclient -L {host}: {stderr}")
        # ``-g`` (grepable) emits ``Type|Name|Comment`` lines; rows
        # without ``Disk|`` / ``Printer|`` / ``IPC|`` prefix are skipped.
        out: list[dict] = []
        for line in split_lf_only_stream(proc.stdout):
            parts = line.split("|", 2)
            if len(parts) < 2:
                continue
            kind = parts[0].strip()
            if kind not in ("Disk", "Printer", "IPC"):
                continue
            out.append(
                {
                    "name": parts[1].strip(),
                    "type": kind,
                    "comment": parts[2].strip() if len(parts) > 2 else "",
                }
            )
        return out

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
