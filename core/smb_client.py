"""SMB/CIFS backend implementing the FileBackend protocol.

Requires: pip install axross[smb]  (smbprotocol>=1.13)
"""
from __future__ import annotations

import contextlib
import io
import logging
import posixpath
import socket
import stat as stat_module
import threading
from datetime import datetime
from typing import IO

from core.client_identity import SMB_CLIENT_NAME
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import smbclient
    import smbclient.path
    from smbprotocol.exceptions import SMBOSError
except ImportError:  # pragma: no cover
    smbclient = None  # type: ignore[assignment]
    SMBOSError = OSError  # type: ignore[assignment,misc]


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


class SmbSession:
    """SMB/CIFS backend implementing the FileBackend protocol.

    Uses smbclient (high-level wrapper over smbprotocol).
    Paths are stored internally as UNC: \\\\server\\share\\path
    but the UI sees forward-slash paths relative to the share root.
    """

    def __init__(
        self,
        host: str,
        share: str,
        username: str = "",
        password: str = "",
        port: int = 445,
        client_name: str = "",
    ):
        if smbclient is None:
            raise ImportError(
                "SMB support requires smbprotocol. "
                "Install with: pip install axross[smb]"
            )

        self._host = host
        self._share = share
        self._username = username
        self._password = password
        self._port = port
        self._prefix = f"\\\\{host}\\{share}"

        # smbclient keeps a process-wide session registry. Two threads
        # constructing SmbSession(host=X, ...) concurrently can race on
        # the delete+register pair: thread A deletes, thread B deletes
        # (no-op), A registers, B registers, A listdirs — sometimes the
        # session that A registered is the one B's listdir sees. The
        # per-host lock below makes init atomic per-host: each thread
        # owns the registry entry for host during delete→register→probe.
        effective_client_name = client_name or SMB_CLIENT_NAME
        with _session_lock(host):
            try:
                smbclient.delete_session(host)
            except Exception:
                pass

            with _patched_gethostname(effective_client_name):
                smbclient.register_session(
                    host,
                    username=username,
                    password=password,
                    port=port,
                )
            # register_session is lazy — it does not actually
            # authenticate until the first I/O. Verify credentials
            # eagerly by doing a cheap listdir on the share root, so a
            # wrong-password / wrong-share misconfiguration surfaces at
            # connection time instead of halfway into a transfer.
            try:
                smbclient.listdir(self._prefix)
            except Exception as exc:
                try:
                    smbclient.delete_session(host)
                except Exception:
                    pass
                raise OSError(
                    f"SMB connect failed for {self._prefix}: {exc}"
                ) from exc

        log.info("SMB connected: %s@%s\\%s:%d", username, host, share, port)

    @property
    def name(self) -> str:
        return f"\\\\{self._host}\\{self._share} (SMB)"

    @property
    def connected(self) -> bool:
        try:
            smbclient.listdir(self._prefix)
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
            smbclient.delete_session(self._host)
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
            rel = unc[len(self._prefix):]
        else:
            rel = unc
        return "/" + rel.replace("\\", "/").lstrip("/")

    def list_dir(self, path: str) -> list[FileItem]:
        unc = self._unc(path)
        items: list[FileItem] = []
        try:
            for entry in smbclient.scandir(unc):
                if entry.name in (".", ".."):
                    continue
                try:
                    st = entry.stat()
                    items.append(self._stat_to_item(entry.name, st))
                except (OSError, SMBOSError) as e:
                    log.warning("Cannot stat %s: %s", entry.name, e)
                    items.append(FileItem(name=entry.name))
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        return items

    def stat(self, path: str) -> FileItem:
        unc = self._unc(path)
        try:
            st = smbclient.stat(unc)
            name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or path
            return self._stat_to_item(name, st)
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot stat {path}: {e}") from e

    def is_dir(self, path: str) -> bool:
        try:
            return smbclient.path.isdir(self._unc(path))
        except (OSError, SMBOSError):
            return False

    def exists(self, path: str) -> bool:
        try:
            return smbclient.path.exists(self._unc(path))
        except (OSError, SMBOSError):
            return False

    def mkdir(self, path: str) -> None:
        try:
            smbclient.mkdir(self._unc(path))
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        unc = self._unc(path)
        try:
            if self.is_dir(path):
                if recursive:
                    self._rmdir_recursive(path)
                else:
                    smbclient.rmdir(unc)
            else:
                smbclient.remove(unc)
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot remove {path}: {e}") from e

    def _rmdir_recursive(self, path: str) -> None:
        for item in self.list_dir(path):
            child = self.join(path, item.name)
            if item.is_dir:
                self._rmdir_recursive(child)
            else:
                smbclient.remove(self._unc(child))
        smbclient.rmdir(self._unc(path))

    def rename(self, src: str, dst: str) -> None:
        try:
            smbclient.rename(self._unc(src), self._unc(dst))
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def open_read(self, path: str) -> IO[bytes]:
        try:
            return smbclient.open_file(self._unc(path), mode="rb")
        except (OSError, SMBOSError) as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        mode = "ab" if append else "wb"
        try:
            return smbclient.open_file(self._unc(path), mode=mode)
        except (OSError, SMBOSError) as e:
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

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

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
            usage = smb_shutil.disk_usage(self._unc(path))
            return (usage.total, usage.used, usage.free)
        except (AttributeError, ImportError):
            log.debug("smbclient.shutil.disk_usage not available")
        except (OSError, SMBOSError, Exception) as e:
            log.debug("SMB disk_usage failed: %s", e)
        return (0, 0, 0)

    @staticmethod
    def _stat_to_item(name: str, st) -> FileItem:
        is_dir = stat_module.S_ISDIR(st.st_mode)
        modified = datetime.fromtimestamp(st.st_mtime) if st.st_mtime else datetime.fromtimestamp(0)
        return FileItem(
            name=name,
            size=st.st_size if not is_dir else 0,
            modified=modified,
            permissions=st.st_mode & 0o777,
            is_dir=is_dir,
        )
