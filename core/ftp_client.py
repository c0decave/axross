"""FTP/FTPS backend implementing the FileBackend protocol."""
from __future__ import annotations

import io
import logging
import os
import posixpath
import tempfile
from datetime import datetime
from ftplib import FTP, FTP_TLS, error_perm
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


class _SpooledWriter:
    """Write to a temp file, then upload on close."""

    def __init__(self, ftp: FTP, remote_path: str, append: bool = False):
        self._ftp = ftp
        self._remote_path = remote_path
        self._append = append
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        self._buf.seek(0)
        cmd = "APPE" if self._append else "STOR"
        self._ftp.storbinary(f"{cmd} {self._remote_path}", self._buf)
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FtpSession:
    """FTP/FTPS backend implementing the FileBackend protocol.

    Uses ftplib (stdlib). Supports both plain FTP and explicit FTPS.
    """

    def __init__(
        self,
        host: str,
        port: int = 21,
        username: str = "",
        password: str = "",
        tls: bool = False,
        passive: bool = True,
        verify_tls: bool = True,
    ):
        """Create an FTP / FTPS session.

        ``verify_tls`` (default ``True``): when ``tls=True``, require
        the server's certificate to chain to a trusted CA AND have a
        subject that matches the connected host. Set to ``False`` to
        accept self-signed / hostname-mismatched certs — useful for
        internal lab servers, never for production.

        Background: Python's ``ftplib.FTP_TLS()`` with no ``context=``
        argument uses ``ssl._create_stdlib_context()`` which defaults
        to ``CERT_NONE`` + ``check_hostname=False``, i.e. NO
        verification at all. That is indistinguishable from a MITM
        attacker. We default to a verifying context and only fall back
        when the caller explicitly opts in.
        """
        self._host = host
        self._port = port
        self._username = username or "anonymous"
        self._password = password
        self._tls = tls
        self._passive = passive
        self._verify_tls = verify_tls
        self._ftp: FTP | None = None
        self._has_mlsd = False

        self._connect()

    def _connect(self) -> None:
        """Establish FTP connection."""
        if self._tls:
            import ssl
            if self._verify_tls:
                context = ssl.create_default_context()
            else:
                # Explicit opt-out: used for self-signed / lab servers.
                log.warning(
                    "FTPS connection to %s:%d with TLS verification DISABLED "
                    "— subject to MITM attacks",
                    self._host, self._port,
                )
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            ftp = FTP_TLS(context=context)
        else:
            ftp = FTP()

        ftp.connect(self._host, self._port, timeout=15)
        ftp.login(self._username, self._password)

        if self._tls and isinstance(ftp, FTP_TLS):
            ftp.prot_p()  # Protect data channel

        ftp.set_pasv(self._passive)

        # Try UTF-8
        try:
            ftp.sendcmd("OPTS UTF8 ON")
            ftp.encoding = "utf-8"
        except error_perm:
            ftp.encoding = "latin-1"

        # Harden the response reader against encoding mismatches: even
        # when the server accepts OPTS UTF8 ON it may still echo paths
        # back in latin-1 (vsftpd/pure-ftpd both do this for non-ASCII
        # names on certain builds). A raw UnicodeDecodeError inside
        # ftplib.getline() aborts the control session; switching the
        # decoder to errors='replace' keeps the channel alive while
        # logging what happened.
        try:
            raw = ftp.sock.makefile(
                "r", encoding=ftp.encoding, errors="replace",
            )
            ftp.file = raw
        except Exception as exc:
            log.debug("Could not harden FTP response decoder: %s", exc)

        # Probe MLSD support
        try:
            list(ftp.mlsd("/", facts=["type"]))
            self._has_mlsd = True
        except Exception:
            self._has_mlsd = False

        self._ftp = ftp
        log.info(
            "FTP%s connected: %s@%s:%d (MLSD=%s)",
            "S" if self._tls else "",
            self._username, self._host, self._port,
            self._has_mlsd,
        )

    @property
    def connected(self) -> bool:
        if self._ftp is None:
            return False
        try:
            self._ftp.voidcmd("NOOP")
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        if self._ftp:
            try:
                self._ftp.quit()
            except Exception:
                try:
                    self._ftp.close()
                except Exception:
                    pass
            self._ftp = None

    def close(self) -> None:
        self.disconnect()

    @property
    def name(self) -> str:
        proto = "FTPS" if self._tls else "FTP"
        return f"{self._username}@{self._host} ({proto})"

    def _ensure_connected(self) -> FTP:
        if self._ftp is None or not self.connected:
            self._connect()
        assert self._ftp is not None
        return self._ftp

    def list_dir(self, path: str) -> list[FileItem]:
        ftp = self._ensure_connected()
        items: list[FileItem] = []

        if self._has_mlsd:
            try:
                for name, facts in ftp.mlsd(path, facts=["type", "size", "modify", "perm"]):
                    if name in (".", ".."):
                        continue
                    items.append(self._mlsd_to_item(name, facts))
                return items
            except error_perm:
                pass

        # Fallback: NLST + individual stat
        try:
            names = ftp.nlst(path)
        except error_perm as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        for full_path in names:
            entry_name = posixpath.basename(full_path) or full_path
            if entry_name in (".", ".."):
                continue
            try:
                item = self.stat(posixpath.join(path, entry_name) if not full_path.startswith("/") else full_path)
                items.append(FileItem(
                    name=entry_name,
                    size=item.size,
                    modified=item.modified,
                    is_dir=item.is_dir,
                ))
            except OSError:
                items.append(FileItem(name=entry_name))

        return items

    def stat(self, path: str) -> FileItem:
        ftp = self._ensure_connected()
        name = posixpath.basename(path) or path
        size = 0
        modified = datetime.fromtimestamp(0)
        is_dir = False

        # Try MLST first
        if self._has_mlsd:
            try:
                resp = ftp.sendcmd(f"MLST {path}")
                for line in resp.splitlines():
                    line = line.strip()
                    if "=" in line:
                        facts_str, _, entry_name = line.rpartition(" ")
                        facts = self._parse_mlsd_facts(facts_str)
                        return self._mlsd_to_item(name, facts)
            except error_perm:
                pass

        # Fallback: SIZE + MDTM + CWD probe
        try:
            size = ftp.size(path) or 0
        except Exception:
            pass

        try:
            mdtm_resp = ftp.sendcmd(f"MDTM {path}")
            # Response: "213 YYYYMMDDHHMMSS"
            ts = mdtm_resp.split(None, 1)[-1]
            modified = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
        except Exception:
            pass

        # Check if directory
        try:
            old_cwd = ftp.pwd()
            ftp.cwd(path)
            ftp.cwd(old_cwd)
            is_dir = True
        except error_perm:
            is_dir = False

        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir)

    def is_dir(self, path: str) -> bool:
        ftp = self._ensure_connected()
        try:
            old_cwd = ftp.pwd()
            ftp.cwd(path)
            ftp.cwd(old_cwd)
            return True
        except error_perm:
            return False
        except UnicodeDecodeError:
            # Some FTP servers echo the path back in the error response
            # using a different encoding than the one we negotiated
            # (vsftpd/pure-ftpd with non-ASCII names and failed OPTS UTF8).
            # Python's ftplib then throws while decoding the server
            # response. Treat as "not a directory" so callers (remove,
            # list) can proceed rather than propagating the decode
            # failure.
            log.warning(
                "FTP server returned a response we could not decode while "
                "probing is_dir(%r); assuming not a directory", path,
            )
            return False

    def exists(self, path: str) -> bool:
        ftp = self._ensure_connected()
        try:
            ftp.size(path)
            return True
        except error_perm:
            pass
        try:
            old_cwd = ftp.pwd()
            ftp.cwd(path)
            ftp.cwd(old_cwd)
            return True
        except error_perm:
            return False
        except UnicodeDecodeError:
            # See is_dir() for the pure-ftpd/vsftpd encoding mismatch.
            return False

    def mkdir(self, path: str) -> None:
        ftp = self._ensure_connected()
        try:
            ftp.mkd(path)
        except error_perm as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        ftp = self._ensure_connected()
        if self.is_dir(path):
            if recursive:
                self._rmdir_recursive(path)
            else:
                try:
                    ftp.rmd(path)
                except error_perm as e:
                    raise OSError(f"Cannot remove directory {path}: {e}") from e
        else:
            try:
                ftp.delete(path)
            except error_perm as e:
                raise OSError(f"Cannot delete {path}: {e}") from e

    def _rmdir_recursive(self, path: str) -> None:
        ftp = self._ensure_connected()
        for item in self.list_dir(path):
            child = posixpath.join(path, item.name)
            if item.is_dir:
                self._rmdir_recursive(child)
            else:
                ftp.delete(child)
        ftp.rmd(path)

    def rename(self, src: str, dst: str) -> None:
        ftp = self._ensure_connected()
        try:
            ftp.rename(src, dst)
        except error_perm as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def open_read(self, path: str) -> IO[bytes]:
        ftp = self._ensure_connected()
        buf = io.BytesIO()
        try:
            ftp.retrbinary(f"RETR {path}", buf.write)
        except error_perm as e:
            raise OSError(f"Cannot read {path}: {e}") from e
        buf.seek(0)
        return buf

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        ftp = self._ensure_connected()
        return _SpooledWriter(ftp, path, append=append)

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    def home(self) -> str:
        ftp = self._ensure_connected()
        return ftp.pwd()

    def chmod(self, path: str, mode: int) -> None:
        ftp = self._ensure_connected()
        octal = format(mode, 'o')
        try:
            ftp.sendcmd(f"SITE CHMOD {octal} {path}")
        except error_perm as e:
            log.warning("SITE CHMOD failed for %s (server may not support it): %s", path, e)
            raise OSError(f"chmod not supported by this FTP server: {e}") from e
        except Exception as e:
            log.warning("Unexpected error during SITE CHMOD for %s: %s", path, e)
            raise OSError(f"chmod failed: {e}") from e

    def readlink(self, path: str) -> str:
        raise OSError("FTP does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """FTP has no native server-side copy. Raises so server_ops
        falls back to stream copy."""
        raise OSError("FTP has no server-side copy primitive")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """FTP has no native checksum command. Some servers advertise
        ``HASH`` (RFC draft) or ``XMD5`` / ``XSHA256`` extensions; we
        try them on a best-effort basis and return "" otherwise.
        Callers should fall back to client-side streaming."""
        ftp = self._ensure_connected()
        cmd_map = {
            "sha256": ("HASH SHA-256", "XSHA256"),
            "sha1": ("HASH SHA-1", "XSHA1"),
            "md5": ("HASH MD5", "XMD5"),
        }
        for cmd_text in cmd_map.get(algorithm, ()):
            cmd, _, _ = cmd_text.partition(" ")
            try:
                resp = ftp.sendcmd(f"{cmd_text} {path}")
            except error_perm:
                continue
            except Exception:
                continue
            # Typical response: "213 0-12345 abc123deadbeef..."
            parts = resp.split()
            if parts:
                candidate = parts[-1].strip().lower()
                if all(c in "0123456789abcdef" for c in candidate) and len(candidate) >= 32:
                    return f"{algorithm}:{candidate}"
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        log.debug("disk_usage not available for FTP (no standard command); returning zeros")
        return (0, 0, 0)

    # --- MLSD helpers ---

    @staticmethod
    def _parse_mlsd_facts(facts_str: str) -> dict[str, str]:
        facts: dict[str, str] = {}
        for part in facts_str.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, val = part.partition("=")
                facts[key.lower()] = val
        return facts

    @staticmethod
    def _mlsd_to_item(name: str, facts: dict[str, str]) -> FileItem:
        entry_type = facts.get("type", "file").lower()
        is_dir = entry_type in ("dir", "cdir", "pdir")
        is_link = entry_type == "os.unix=symlink"

        size = 0
        if "size" in facts:
            try:
                size = int(facts["size"])
            except ValueError:
                pass

        modified = datetime.fromtimestamp(0)
        if "modify" in facts:
            try:
                ts = facts["modify"][:14]
                modified = datetime.strptime(ts, "%Y%m%d%H%M%S")
            except (ValueError, IndexError):
                pass

        return FileItem(
            name=name,
            size=size,
            modified=modified,
            is_dir=is_dir,
            is_link=is_link,
        )
