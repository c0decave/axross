"""NFS without the kernel: axross's own NFSv3 client (core.nfs3_rpc) as a
FileBackend, for profiles that choose what the client sends about itself.

AUTH_SYS carries a machine name, a UID, a GID and up to 16 more GIDs - the
server believes them; with the kernel mount (core/nfs_client.py) they are
always the host's name and the reading process's IDs. Here every one is the
profile's (Connect to Server, a saved profile, axross.open_url). It needs no
root and no mount point, and the portmapper, mountd and nfsd connections all
go through the profile's proxy when it has one.

Paths are the export's: "/" is its root. ".." never reaches the server; a
symbolic link is followed only inside the export (an absolute target counts
from the export's root), at most 16 deep.
"""

from __future__ import annotations

import errno
import io
import logging
import posixpath
import stat as stat_module
import threading
from datetime import datetime
from typing import IO

from core import nfs3_rpc as R
from core.backend import SessionLifecycle
from models.file_item import FileItem

log = logging.getLogger(__name__)

_MAX_LINK_DEPTH = 16
_TYPE_BITS = {R.NF3REG: stat_module.S_IFREG, R.NF3DIR: stat_module.S_IFDIR, R.NF3LNK: stat_module.S_IFLNK,
              R.NF3BLK: stat_module.S_IFBLK, R.NF3CHR: stat_module.S_IFCHR,
              R.NF3SOCK: stat_module.S_IFSOCK, R.NF3FIFO: stat_module.S_IFIFO}


def _split(path: str) -> list[str]:
    """'/a/./b//c/' -> ['a', 'b', 'c']; '..' is refused, never sent."""
    parts = []
    for part in (path or "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise PermissionError(errno.EACCES, f"{path!r} leaves the export")
            parts.pop()
            continue
        if "\0" in part:
            raise ValueError("a path must not contain NUL")
        parts.append(part)
    return parts


def _dt(ts: float) -> datetime:
    try:
        return datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return datetime.fromtimestamp(0)


class NfsUserSession(SessionLifecycle):
    """NFSv3 over axross's own RPC client, AUTH_SYS as the profile says."""

    def __init__(
        self,
        host: str,
        export_path: str,
        port: int = 2049,
        *,
        machine_name: str = "",
        uid: int = 65534,
        gid: int = 65534,
        gids: tuple[int, ...] | list[int] | str = (),
        mount_port: int = 0,
        version: int = 3,
        client_id: str = "",
        privileged_port: bool = False,
        timeout: float = 30.0,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        **_ignored,
    ):
        from core.nfs_client import _validate_mount_source
        from core.proxy import proxy_config_from_kwargs

        _validate_mount_source(host, export_path)
        if isinstance(gids, str):
            gids = R.parse_gids(gids)
        self.auth = R.AuthSys(machine_name=machine_name, uid=int(uid), gid=int(gid), gids=tuple(gids))
        self._host, self._export = host, export_path.rstrip("/") or "/"
        self._port = int(port or 2049)
        self._proxy = proxy_config_from_kwargs({
            "proxy_type": proxy_type, "proxy_host": proxy_host, "proxy_port": proxy_port,
            "proxy_username": proxy_username, "proxy_password": proxy_password,
        })
        self._privileged = bool(privileged_port)
        self._timeout = float(timeout)
        self._mount_port = int(mount_port or 0)
        if str(version) not in ("3", "4", "4.0", "4.1"):
            raise ValueError(f"NFS version {version}: axross's own client speaks 3, 4.0 and 4.1")
        self._minor = 1 if str(version) == "4.1" else 0
        self._version = 3 if str(version) == "3" else 4
        self._client_id = client_id
        self._mount_rpc: R.RpcConnection | None = None
        self._nfs: R.Nfs3 | None = None
        self._root = b""
        self._info = R.FsInfo()
        self._handles: dict[tuple[str, ...], bytes] = {}
        self._lock = threading.RLock()
        self._connect()

    # --- connection ------------------------------------------------------------------

    def _connector(self, port: int):
        return R.connector(self._host, port, proxy=self._proxy, timeout=self._timeout,
                           privileged=self._privileged)

    def _connect(self) -> None:
        if self._version == 4:
            # one connection to 2049: no portmapper, no mountd
            from core.nfs4_rpc import NFS4_PROG, NFS4_VERS, Nfs4

            rpc = R.RpcConnection(self._connector(self._port), NFS4_PROG, NFS4_VERS, self.auth, self._timeout)
            nfs = Nfs4(rpc, client_id=self._client_id, machine_name=self.auth.machine_name, minor=self._minor)
            try:
                self._root = nfs.root(self._export)
            except BaseException:
                rpc.close()
                raise
            self._nfs = nfs
            self._info = nfs.fsinfo(self._root)
            self._handles = {(): self._root}
            log.info("NFSv4 %s:%s by axross's own client as %s (uid %d, gid %d, client id %r)",
                     self._host, self._export, self.auth.machine_name or "(no machine name)",
                     self.auth.uid, self.auth.gid, nfs.client_id.decode("utf-8", "replace"))
            return
        mport = self._mount_port or R.getport(self._connector(111), R.MOUNT_PROG, R.MOUNT_VERS, self._timeout)
        self._mount_rpc = R.RpcConnection(self._connector(mport), R.MOUNT_PROG, R.MOUNT_VERS, self.auth, self._timeout)
        try:
            self._root = R.mount(self._mount_rpc, self._export)
            rpc = R.RpcConnection(self._connector(self._port), R.NFS_PROG, R.NFS_VERS, self.auth, self._timeout)
            self._nfs = R.Nfs3(rpc)
            self._info = self._nfs.fsinfo(self._root)
        except BaseException:
            self.disconnect()
            raise
        self._handles = {(): self._root}
        log.info("NFS %s:%s mounted by axross's own client as %s (uid %d, gid %d, gids %s)",
                 self._host, self._export, self.auth.machine_name or "(no machine name)",
                 self.auth.uid, self.auth.gid, list(self.auth.gids))

    @property
    def name(self) -> str:
        version = "4.1" if self._minor else str(self._version)
        return f"{self._host}:{self._export} (NFSv{version}, own client)"

    @property
    def connected(self) -> bool:
        return self._nfs is not None

    def close(self) -> None:
        self.disconnect()

    def disconnect(self) -> None:
        if self._mount_rpc is not None:
            if self._root:
                try:
                    R.unmount(self._mount_rpc, self._export)
                except OSError as exc:
                    log.debug("UMNT %s: %s", self._export, exc)
            self._mount_rpc.close()
            self._mount_rpc = None
        if self._nfs is not None:
            close = getattr(self._nfs, "close", None)
            if callable(close):
                close()
            self._nfs.rpc.close()
            self._nfs = None

    def _client(self) -> R.Nfs3:
        if self._nfs is None:
            raise OSError(errno.ENOTCONN, "the NFS session is closed")
        return self._nfs

    # --- path resolution ---------------------------------------------------------------

    def _walk(self, parts: list[str], *, follow_last: bool, depth: int = 0) -> tuple[bytes, R.Fattr | None, list[str]]:
        """The handle of *parts*, following links in the middle (and at the
        end with *follow_last*) inside the export. Returns the handle, its
        attributes when known and the resolved path."""
        nfs = self._client()
        fh, attr, done = self._root, None, []
        pending = list(parts)
        while pending:
            name = pending.pop(0)
            key = tuple(done + [name])
            cached = self._handles.get(key)
            if cached is not None:
                child, cattr = cached, None
            else:
                child, cattr = nfs.lookup(fh, name)
            if cattr is None:
                cattr = nfs.getattr(child)
            if cattr.is_link and (pending or follow_last):
                if depth >= _MAX_LINK_DEPTH:
                    raise OSError(errno.ELOOP, f"too many symbolic links in {'/'.join(parts)!r}")
                target = nfs.readlink(child)
                base = [] if target.startswith("/") else done
                resolved = _split("/" + "/".join(base + [target]))
                return self._walk(resolved + pending, follow_last=follow_last, depth=depth + 1)
            if len(self._handles) < 10_000:
                self._handles[key] = child
            fh, attr, done = child, cattr, list(key)
        return fh, attr, done

    def _resolve(self, path: str, *, follow: bool = True) -> tuple[bytes, R.Fattr]:
        with self._lock:
            parts = _split(path)
            try:
                fh, attr, _ = self._walk(parts, follow_last=follow)
            except R.NfsError as exc:
                if exc.status == 70:   # stale handle: the cache is old
                    self._handles = {(): self._root}
                    fh, attr, _ = self._walk(parts, follow_last=follow)
                else:
                    raise
            return fh, attr if attr is not None else self._client().getattr(fh)

    def _parent(self, path: str) -> tuple[bytes, str, tuple[str, ...]]:
        parts = _split(path)
        if not parts:
            raise PermissionError(errno.EACCES, "the export's root has no parent here")
        with self._lock:
            fh, _attr, done = self._walk(parts[:-1], follow_last=True)
        return fh, parts[-1], tuple(done + [parts[-1]])

    def _forget(self, key: tuple[str, ...]) -> None:
        with self._lock:
            for k in [k for k in self._handles if k[:len(key)] == key]:
                del self._handles[k]

    # --- FileBackend ---------------------------------------------------------------------

    def _item(self, name: str, attr: R.Fattr | None, link_target: str = "") -> FileItem:
        if attr is None:
            return FileItem(name=name, stat_error="the server sent no attributes")
        return FileItem(
            name=name, size=attr.size, modified=_dt(attr.mtime), accessed=_dt(attr.atime),
            is_dir=attr.is_dir, is_link=attr.is_link, link_target=link_target,
            permissions=attr.mode, owner=str(attr.uid), group=str(attr.gid),
        )

    def list_dir(self, path: str) -> list[FileItem]:
        fh, attr = self._resolve(path)
        if not attr.is_dir:
            raise NotADirectoryError(errno.ENOTDIR, f"Cannot list {path}: not a folder")
        entries = self._client().readdirplus(fh, self._info.dtpref, max(self._info.dtpref * 8, 32768))
        items = []
        base = tuple(_split(path))
        for e in entries:
            attr = e.attr
            if attr is None and e.fh is not None:
                try:
                    attr = self._client().getattr(e.fh)
                except OSError as exc:
                    items.append(FileItem(name=e.name, stat_error=str(exc)))
                    continue
            if e.fh is not None and len(self._handles) < 10_000:
                self._handles[base + (e.name,)] = e.fh
            items.append(self._item(e.name, attr))
        return sorted(items, key=lambda i: (not i.is_dir, i.name.lower()))

    def stat(self, path: str) -> FileItem:
        fh, attr = self._resolve(path, follow=False)
        target = self._client().readlink(fh) if attr.is_link else ""
        return self._item(posixpath.basename(path.rstrip("/")) or "/", attr, target)

    def lstat_mode(self, path: str) -> int:
        _fh, attr = self._resolve(path, follow=False)
        return _TYPE_BITS.get(attr.type, 0) | attr.mode

    def is_dir(self, path: str) -> bool:
        try:
            return self._resolve(path)[1].is_dir
        except FileNotFoundError:
            return False
        except PermissionError:
            return False
        except R.NfsError as exc:
            if exc.status in (2, 20):
                return False
            raise

    def exists(self, path: str) -> bool:
        """False only when nothing is there; any other failure is an OSError."""
        try:
            self._resolve(path, follow=False)
            return True
        except R.NfsError as exc:
            if exc.status == 2:
                return False
            raise

    def mkdir(self, path: str) -> None:
        parts = _split(path)
        for i in range(1, len(parts) + 1):
            sub = "/" + "/".join(parts[:i])
            dir_fh, name, key = self._parent(sub)
            try:
                fh, _ = self._client().mkdir(dir_fh, name)
                if fh:
                    self._handles[key] = fh
            except R.NfsError as exc:
                if exc.status != 17 or not self.is_dir(sub):
                    raise

    def remove(self, path: str, recursive: bool = False) -> None:
        dir_fh, name, key = self._parent(path)
        _fh, attr = self._resolve(path, follow=False)
        if attr.is_dir:
            if recursive:
                for item in self.list_dir(path):
                    self.remove(posixpath.join("/" + "/".join(key), item.name), recursive=True)
            self._client().remove(dir_fh, name, directory=True)
        else:
            self._client().remove(dir_fh, name)
        self._forget(key)

    def rename(self, src: str, dst: str) -> None:
        sdir, sname, skey = self._parent(src)
        ddir, dname, dkey = self._parent(dst)
        try:
            self._client().rename(sdir, sname, ddir, dname)
        finally:
            # Both names change: the source is gone, and the destination
            # names the moved entry now. A handle cached for the entry
            # the rename replaced (and for everything below it, when
            # that was a folder) would read and write the old inode - one
            # that lives on under another hard link or while still open.
            self._forget(skey)
            self._forget(dkey)

    def open_read(self, path: str) -> IO[bytes]:
        fh, attr = self._resolve(path)
        if attr.is_dir:
            raise IsADirectoryError(errno.EISDIR, f"{path} is a folder")
        return io.BufferedReader(_NfsReader(self._client(), fh, self._info.rtmax), self._info.rtmax)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        dir_fh, name, key = self._parent(path)
        nfs = self._client()
        offset = 0
        try:
            fh, attr = self._resolve(path)
            if attr.is_dir:
                raise IsADirectoryError(errno.EISDIR, f"{path} is a folder")
            if append:
                offset = attr.size
            else:
                nfs.setattr(fh, size=0)
        except R.NfsError as exc:
            if exc.status != 2:
                raise
            fh, _ = nfs.create(dir_fh, name)
            if fh is None:
                fh, _ = nfs.lookup(dir_fh, name)
            self._handles[key] = fh
        return io.BufferedWriter(_NfsWriter(nfs, fh, offset, self._info.wtmax), self._info.wtmax)

    def normalize(self, path: str) -> str:
        return "/" + "/".join(_split(path))

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts) if parts else "/"

    def parent(self, path: str) -> str:
        parts = _split(path)
        return "/" + "/".join(parts[:-1])

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        fh, _ = self._resolve(path)
        self._client().setattr(fh, mode=mode & 0o7777)

    def readlink(self, path: str) -> str:
        fh, attr = self._resolve(path, follow=False)
        if not attr.is_link:
            raise OSError(errno.EINVAL, f"{path} is no symbolic link")
        return self._client().readlink(fh)

    def symlink(self, target: str, link_path: str) -> None:
        dir_fh, name, _ = self._parent(link_path)
        self._client().symlink(dir_fh, name, target)

    def hardlink(self, target: str, link_path: str) -> None:
        fh, _ = self._resolve(target, follow=False)
        dir_fh, name, _ = self._parent(link_path)
        self._client().link(fh, dir_fh, name)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        fh, _ = self._resolve(path)
        total, free, avail = self._client().fsstat(fh)
        return (total, total - free, avail)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        import hashlib

        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported algorithm: {algorithm}") from exc
        with self.open_read(path) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    @staticmethod
    def exports_list(host: str, *, timeout: float = 5.0, machine_name: str = "", uid: int = 65534,
                     gid: int = 65534, mount_port: int = 0, proxy=None) -> list[dict]:
        """The server's exports through MOUNT v3 EXPORT, with the given
        sender information (no showmount needed)."""
        auth = R.AuthSys(machine_name=machine_name, uid=uid, gid=gid)
        port = mount_port or R.getport(R.connector(host, 111, proxy=proxy, timeout=timeout),
                                       R.MOUNT_PROG, R.MOUNT_VERS, timeout)
        rpc = R.RpcConnection(R.connector(host, port, proxy=proxy, timeout=timeout),
                              R.MOUNT_PROG, R.MOUNT_VERS, auth, timeout)
        try:
            return R.exports(rpc)
        finally:
            rpc.close()


class _NfsReader(io.RawIOBase):
    def __init__(self, nfs: R.Nfs3, fh: bytes, chunk: int):
        self._nfs, self._fh, self._chunk, self._pos, self._eof = nfs, fh, chunk, 0, False

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        else:
            self._pos = self._nfs.getattr(self._fh).size + offset
        self._eof = False
        return self._pos

    def tell(self) -> int:
        return self._pos

    def readinto(self, buf) -> int:
        if self._eof or len(buf) == 0:
            return 0
        data, eof = self._nfs.read(self._fh, self._pos, min(len(buf), self._chunk))
        n = len(data)
        buf[:n] = data
        self._pos += n
        self._eof = eof or n == 0
        return n


class _NfsWriter(io.RawIOBase):
    def __init__(self, nfs: R.Nfs3, fh: bytes, offset: int, chunk: int):
        self._nfs, self._fh, self._pos, self._chunk = nfs, fh, offset, chunk

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def write(self, data) -> int:
        view = memoryview(data).cast("B")
        done = 0
        while done < len(view):
            piece = bytes(view[done:done + self._chunk])
            n = self._nfs.write(self._fh, self._pos, piece)
            if n <= 0:
                raise OSError(errno.EIO, "the NFS server wrote nothing")
            self._pos += n
            done += n
        return done
