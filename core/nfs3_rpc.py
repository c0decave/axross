"""NFSv3 spoken by axross itself: XDR, ONC RPC over TCP with AUTH_SYS,
the portmapper, MOUNT v3 and the NFSv3 procedures a file browser needs.

Why a client of our own next to the kernel mount (core/nfs_client.py): what
the client sends about itself is then the profile's choice. AUTH_SYS
(RFC 5531) carries a machine name, a UID, a GID and up to 16 more GIDs; the
kernel always sends the host's name and the reading process's IDs. It also
needs no root and no mount, and every connection can go through a proxy.

Standard library only. Everything a server sends is bounded before it is
believed: record fragments, the whole reply, strings, opaques, arrays and
linked lists (core.nfs3_rpc.MAX_*), so a hostile server cannot make it
allocate without limit or loop forever.
"""

from __future__ import annotations

import errno
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

# --- limits -------------------------------------------------------------------------

#: One RPC reply, all fragments together (a READ of 1 MiB plus headers).
MAX_REPLY = 4 * 1024 * 1024 + 64 * 1024
#: Largest READ / WRITE asked for (servers answer with less if they like).
MAX_IO = 1024 * 1024
#: A file handle (RFC 1813: NFS3_FHSIZE).
FHSIZE = 64
#: Entries of a linked list (READDIRPLUS, EXPORT) believed per reply.
MAX_LIST = 100_000
#: AUTH_SYS: machine name at most 255 bytes, at most 16 extra GIDs.
MAX_MACHINE_NAME = 255
MAX_GIDS = 16

# --- programs, procedures -----------------------------------------------------------

PMAP_PROG, PMAP_VERS, PMAP_GETPORT = 100000, 2, 3
MOUNT_PROG, MOUNT_VERS = 100005, 3
MOUNTPROC_MNT, MOUNTPROC_UMNT, MOUNTPROC_EXPORT = 1, 3, 5
NFS_PROG, NFS_VERS = 100003, 3
(NFSPROC_GETATTR, NFSPROC_SETATTR, NFSPROC_LOOKUP, NFSPROC_ACCESS, NFSPROC_READLINK,
 NFSPROC_READ, NFSPROC_WRITE, NFSPROC_CREATE, NFSPROC_MKDIR, NFSPROC_SYMLINK) = range(1, 11)
NFSPROC_REMOVE, NFSPROC_RMDIR, NFSPROC_RENAME, NFSPROC_LINK = 12, 13, 14, 15
NFSPROC_READDIRPLUS, NFSPROC_FSSTAT, NFSPROC_FSINFO, NFSPROC_COMMIT = 17, 18, 19, 21

AUTH_NONE, AUTH_SYS = 0, 1
IPPROTO_TCP = 6

NF3REG, NF3DIR, NF3BLK, NF3CHR, NF3LNK, NF3SOCK, NF3FIFO = range(1, 8)
UNSTABLE, DATA_SYNC, FILE_SYNC = 0, 1, 2

#: nfsstat3 values that are no errno (RFC 1813 2.6).
_NFS_ONLY_ERRORS = {
    10001: "bad file handle", 10002: "update synchronization mismatch",
    10003: "READDIR cookie is stale", 10004: "operation not supported",
    10005: "buffer or request too small", 10006: "server fault",
    10007: "object type not supported", 10008: "the server is busy, try again later",
}
_NFS_ERRNO = {1: errno.EPERM, 2: errno.ENOENT, 5: errno.EIO, 6: errno.ENXIO, 13: errno.EACCES,
              17: errno.EEXIST, 18: errno.EXDEV, 19: errno.ENODEV, 20: errno.ENOTDIR,
              21: errno.EISDIR, 22: errno.EINVAL, 27: errno.EFBIG, 28: errno.ENOSPC,
              30: errno.EROFS, 31: errno.EMLINK, 63: errno.ENAMETOOLONG, 66: errno.ENOTEMPTY,
              69: errno.EDQUOT, 70: errno.ESTALE, 71: errno.EREMOTE}
_MOUNT_ERRORS = {1: "not owner", 2: "no such export", 5: "I/O error", 13: "permission denied - "
                 "the export does not allow this client, or wants a privileged source port",
                 20: "not a directory", 22: "invalid argument", 63: "name too long",
                 10004: "operation not supported", 10006: "server fault"}


class RpcError(OSError):
    """The RPC layer failed: the server refused the call or answered garbage."""


class NfsError(OSError):
    """An NFS procedure answered with an error status (errno set where one fits)."""

    def __init__(self, status: int, what: str):
        self.status = status
        code = _NFS_ERRNO.get(status)
        text = _NFS_ONLY_ERRORS.get(status) or (os.strerror(code) if code else f"NFS error {status}")
        super().__init__(code or errno.EIO, f"{what}: {text}")


_SUBCLASS: dict[int, type] = {}


def make_nfs_error(status: int, what: str) -> NfsError:
    """An NfsError that is also the builtin OSError subclass of its errno
    (FileNotFoundError, FileExistsError, PermissionError ...), as the
    kernel mount's errors are."""
    code = _NFS_ERRNO.get(status)
    base = {errno.ENOENT: FileNotFoundError, errno.EEXIST: FileExistsError,
            errno.EACCES: PermissionError, errno.EPERM: PermissionError,
            errno.ENOTDIR: NotADirectoryError, errno.EISDIR: IsADirectoryError}.get(code)
    if base is None:
        return NfsError(status, what)
    cls = _SUBCLASS.get(code)
    if cls is None:
        cls = _SUBCLASS[code] = type(f"Nfs{base.__name__}", (NfsError, base), {})
    return cls(status, what)


# --- XDR -------------------------------------------------------------------------------

class Packer:
    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def uint(self, v: int) -> Packer:
        self._parts.append(struct.pack(">I", v & 0xFFFFFFFF))
        return self

    def hyper(self, v: int) -> Packer:
        self._parts.append(struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF))
        return self

    def boolean(self, v: bool) -> Packer:
        return self.uint(1 if v else 0)

    def fixed(self, data: bytes) -> Packer:
        self._parts.append(data + b"\0" * (-len(data) % 4))
        return self

    def opaque(self, data: bytes) -> Packer:
        self.uint(len(data))
        return self.fixed(data)

    def string(self, text: str | bytes) -> Packer:
        return self.opaque(text.encode("utf-8", "surrogateescape") if isinstance(text, str) else text)

    def bytes(self) -> bytes:
        return b"".join(self._parts)


class Unpacker:
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data, self.pos = data, offset

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise RpcError(errno.EPROTO, "the server's answer ends too early")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def int(self) -> int:
        return struct.unpack(">i", self._take(4))[0]

    def hyper(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def boolean(self) -> bool:
        v = self.uint()
        if v > 1:
            raise RpcError(errno.EPROTO, f"the server sent {v} as a boolean")
        return v == 1

    def fixed(self, n: int) -> bytes:
        out = self._take(n)
        self._take(-n % 4)
        return out

    def opaque(self, limit: int) -> bytes:
        n = self.uint()
        if n > limit:
            raise RpcError(errno.EPROTO, f"the server sent {n} bytes where at most {limit} fit")
        return self.fixed(n)

    def string(self, limit: int = 4096) -> str:
        return self.opaque(limit).decode("utf-8", "surrogateescape")

    def done(self) -> bool:
        return self.pos >= len(self.data)


# --- AUTH_SYS ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthSys:
    """What the client says about itself in every call (RFC 5531 AUTH_SYS).
    Freely chosen: the server believes it, that is the flavour's nature."""

    machine_name: str = ""
    uid: int = 65534
    gid: int = 65534
    gids: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        name = self.machine_name.encode("utf-8")
        if len(name) > MAX_MACHINE_NAME:
            raise ValueError(f"the machine name is longer than {MAX_MACHINE_NAME} bytes")
        if any(c < 0x20 or c == 0x7F for c in name):
            raise ValueError("the machine name must not contain control characters")
        for label, v in (("UID", self.uid), ("GID", self.gid), *(("GID", g) for g in self.gids)):
            if not isinstance(v, int) or not 0 <= v <= 0xFFFFFFFF:
                raise ValueError(f"{label} {v!r} is not a number from 0 to 4294967295")
        if len(self.gids) > MAX_GIDS:
            raise ValueError(f"AUTH_SYS carries at most {MAX_GIDS} extra GIDs, not {len(self.gids)}")

    def body(self) -> bytes:
        p = Packer().uint(int(time.time()) & 0xFFFFFFFF).string(self.machine_name)
        p.uint(self.uid).uint(self.gid).uint(len(self.gids))
        for g in self.gids:
            p.uint(g)
        return p.bytes()


def parse_gids(text: str) -> tuple[int, ...]:
    """'100, 27 1000' -> (100, 27, 1000); empty -> ()."""
    parts = [p for p in text.replace(",", " ").split() if p]
    try:
        gids = tuple(int(p) for p in parts)
    except ValueError as exc:
        raise ValueError(f"extra GIDs {text!r}: numbers separated by commas or spaces") from exc
    AuthSys(gids=gids)  # range and count
    return gids


# --- RPC over TCP ----------------------------------------------------------------------

class RpcConnection:
    """One TCP connection to one RPC program, calls one at a time.

    *connect* returns a connected socket (direct, through a proxy, or from
    a reserved port); it is called again after the connection broke."""

    def __init__(self, connect, prog: int, vers: int, auth: AuthSys | None, timeout: float = 30.0):
        self._connect, self.prog, self.vers, self.auth = connect, prog, vers, auth
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._xid = int.from_bytes(os.urandom(4), "big")

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _drop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def call(self, proc: int, args: bytes = b"", *, retry: bool = True) -> Unpacker:
        """Send one call and return the reply's results. A broken
        connection is opened again once (NFSv3 procedures are meant to be
        retried; a non-idempotent one may then answer EEXIST/ENOENT)."""
        with self._lock:
            for attempt in (0, 1):
                try:
                    if self._sock is None:
                        self._sock = self._connect()
                        self._sock.settimeout(self.timeout)
                    return self._call(proc, args)
                except (ConnectionError, socket.timeout, BrokenPipeError) as exc:
                    self._drop()
                    if attempt or not retry:
                        raise RpcError(errno.ECONNRESET, f"RPC {self.prog}/{proc}: {exc}") from exc
                except RpcError:
                    self._drop()   # out of step with the server: a fresh connection next time
                    raise
            raise AssertionError("unreachable")

    def _call(self, proc: int, args: bytes) -> Unpacker:
        self._xid = (self._xid + 1) & 0xFFFFFFFF
        xid = self._xid
        p = Packer().uint(xid).uint(0).uint(2).uint(self.prog).uint(self.vers).uint(proc)
        if self.auth is None:
            p.uint(AUTH_NONE).opaque(b"")
        else:
            p.uint(AUTH_SYS).opaque(self.auth.body())
        p.uint(AUTH_NONE).opaque(b"")
        message = p.bytes() + args
        self._sock.sendall(struct.pack(">I", 0x80000000 | len(message)) + message)
        while True:
            reply = self._read_record()
            u = Unpacker(reply)
            if u.uint() != xid:
                continue    # an answer to an earlier, abandoned call
            if u.uint() != 1:
                raise RpcError(errno.EPROTO, "the server sent a call, not a reply")
            return self._accepted(u)

    def _read_record(self) -> bytes:
        parts, total = [], 0
        while True:
            header = self._recv_exact(4)
            (word,) = struct.unpack(">I", header)
            length = word & 0x7FFFFFFF
            total += length
            if total > MAX_REPLY:
                raise RpcError(errno.EMSGSIZE, f"the server's reply is larger than {MAX_REPLY} bytes")
            parts.append(self._recv_exact(length))
            if word & 0x80000000:
                return b"".join(parts)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(min(n - len(buf), 1 << 20))
            if not chunk:
                raise ConnectionError("the server closed the connection")
            buf += chunk
        return bytes(buf)

    @staticmethod
    def _accepted(u: Unpacker) -> Unpacker:
        if u.uint() != 0:  # MSG_DENIED
            reject = u.uint()
            if reject == 0:
                lo, hi = u.uint(), u.uint()
                raise RpcError(errno.EPROTONOSUPPORT, f"RPC version mismatch (server: {lo}-{hi})")
            stat = u.uint()
            text = {1: "bad credentials (seal broken)", 2: "the server rejected the credentials - "
                    "AUTH_SYS refused, or a privileged source port wanted",
                    3: "bad verifier", 5: "credentials too weak", 13: "AUTH_SYS refused (wrong flavour)"}
            raise RpcError(errno.EACCES, text.get(stat, f"authentication error {stat}"))
        u.uint()
        u.opaque(400)  # verifier
        stat = u.uint()
        if stat == 0:
            return u
        if stat == 2:
            lo, hi = u.uint(), u.uint()
            raise RpcError(errno.EPROTONOSUPPORT, f"the server offers versions {lo}-{hi} of this program")
        text = {1: "program not available", 3: "procedure not available", 4: "the server could not "
                "decode the arguments", 5: "system error on the server"}
        raise RpcError(errno.EPROTO, text.get(stat, f"RPC accept status {stat}"))


def connector(host: str, port: int, *, proxy=None, timeout: float = 10.0, privileged: bool = False):
    """A function that opens a TCP connection to host:port - through
    *proxy* (core.proxy.ProxyConfig) when given, else directly, from a
    reserved port (< 1024) when *privileged* (servers exporting with
    "secure" want one; only root may bind it)."""
    def connect() -> socket.socket:
        if proxy is not None:
            from core.proxy import create_proxy_socket

            return create_proxy_socket(proxy, host, port, timeout=timeout)
        if not privileged:
            from core.proxy import create_direct_socket

            return create_direct_socket(host, port, timeout=timeout)
        last: Exception | None = None
        for af, st, proto, _c, addr in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            for local in range(1023, 599, -1):
                s = socket.socket(af, st, proto)
                try:
                    s.bind(("::" if af == socket.AF_INET6 else "0.0.0.0", local))
                except PermissionError as exc:
                    s.close()
                    raise PermissionError(
                        errno.EACCES, "a privileged source port (< 1024) needs root; or export "
                        "with 'insecure' on the server") from exc
                except OSError as exc:
                    s.close()
                    last = exc
                    continue
                try:
                    s.settimeout(timeout)
                    s.connect(addr)
                    return s
                except OSError as exc:
                    s.close()
                    last = exc
                    break
        raise ConnectionError(f"Cannot connect to {host}:{port}: {last}")
    return connect


def getport(connect, prog: int, vers: int, timeout: float = 10.0) -> int:
    """Ask the portmapper (port 111) where *prog* / *vers* listens on TCP."""
    rpc = RpcConnection(connect, PMAP_PROG, PMAP_VERS, None, timeout)
    try:
        port = rpc.call(PMAP_GETPORT, Packer().uint(prog).uint(vers).uint(IPPROTO_TCP).uint(0).bytes()).uint()
    finally:
        rpc.close()
    if not 0 < port < 65536:
        raise RpcError(errno.EPROTONOSUPPORT, f"program {prog} version {vers} is not registered on TCP")
    return port


# --- attributes -------------------------------------------------------------------------

@dataclass
class Fattr:
    type: int
    mode: int
    nlink: int
    uid: int
    gid: int
    size: int
    used: int
    fileid: int
    atime: float
    mtime: float
    ctime: float

    @property
    def is_dir(self) -> bool:
        return self.type == NF3DIR

    @property
    def is_link(self) -> bool:
        return self.type == NF3LNK


def _time(u: Unpacker) -> float:
    sec, nsec = u.uint(), u.uint()
    return sec + min(nsec, 999_999_999) / 1e9


def read_fattr(u: Unpacker) -> Fattr:
    ftype, mode, nlink, uid, gid = u.uint(), u.uint(), u.uint(), u.uint(), u.uint()
    size, used = u.hyper(), u.hyper()
    u.uint(), u.uint()            # rdev
    u.hyper()                     # fsid
    fileid = u.hyper()
    return Fattr(ftype, mode & 0o7777, nlink, uid, gid, size, used, fileid, _time(u), _time(u), _time(u))


def read_post_op_attr(u: Unpacker) -> Fattr | None:
    return read_fattr(u) if u.boolean() else None


def skip_wcc(u: Unpacker) -> Fattr | None:
    if u.boolean():               # pre_op_attr: size, mtime, ctime
        u.hyper(), u.uint(), u.uint(), u.uint(), u.uint()
    return read_post_op_attr(u)


def read_post_op_fh(u: Unpacker) -> bytes | None:
    return u.opaque(FHSIZE) if u.boolean() else None


def sattr(mode: int | None = None, size: int | None = None, uid: int | None = None,
          gid: int | None = None, mtime: float | None = None) -> bytes:
    p = Packer()
    for v in (mode, uid, gid):
        p.boolean(v is not None)
        if v is not None:
            p.uint(v)
    p.boolean(size is not None)
    if size is not None:
        p.hyper(size)
    p.uint(0)                     # atime: don't change
    if mtime is None:
        p.uint(0)
    else:
        p.uint(2).uint(int(mtime)).uint(int((mtime % 1) * 1e9))
    return p.bytes()


@dataclass
class DirEntry:
    name: str
    fileid: int
    attr: Fattr | None
    fh: bytes | None


@dataclass
class FsInfo:
    rtmax: int = 32768
    wtmax: int = 32768
    dtpref: int = 8192
    extra: dict = field(default_factory=dict)


# --- MOUNT v3 and NFSv3 -------------------------------------------------------------------

def _check(u: Unpacker, what: str) -> None:
    status = u.uint()
    if status != 0:
        raise make_nfs_error(status, what)


class Nfs3:
    """The NFSv3 procedures on one connection (handles in, results out)."""

    def __init__(self, rpc: RpcConnection) -> None:
        self.rpc = rpc

    def getattr(self, fh: bytes) -> Fattr:
        u = self.rpc.call(NFSPROC_GETATTR, Packer().opaque(fh).bytes())
        _check(u, "GETATTR")
        return read_fattr(u)

    def setattr(self, fh: bytes, **attrs) -> None:
        u = self.rpc.call(NFSPROC_SETATTR, Packer().opaque(fh).bytes() + sattr(**attrs) + Packer().boolean(False).bytes())
        _check(u, "SETATTR")

    def lookup(self, dir_fh: bytes, name: str) -> tuple[bytes, Fattr | None]:
        u = self.rpc.call(NFSPROC_LOOKUP, Packer().opaque(dir_fh).string(name).bytes())
        status = u.uint()
        if status != 0:
            raise make_nfs_error(status, f"LOOKUP {name!r}")
        fh = u.opaque(FHSIZE)
        return fh, read_post_op_attr(u)

    def readlink(self, fh: bytes) -> str:
        u = self.rpc.call(NFSPROC_READLINK, Packer().opaque(fh).bytes())
        status = u.uint()
        read_post_op_attr(u)
        if status != 0:
            raise make_nfs_error(status, "READLINK")
        return u.string(4096)

    def read(self, fh: bytes, offset: int, count: int) -> tuple[bytes, bool]:
        u = self.rpc.call(NFSPROC_READ, Packer().opaque(fh).hyper(offset).uint(count).bytes())
        status = u.uint()
        read_post_op_attr(u)
        if status != 0:
            raise make_nfs_error(status, "READ")
        u.uint()
        eof = u.boolean()
        return u.opaque(count), eof   # never more than asked for

    def write(self, fh: bytes, offset: int, data: bytes, stable: int = FILE_SYNC) -> int:
        u = self.rpc.call(NFSPROC_WRITE, Packer().opaque(fh).hyper(offset).uint(len(data)).uint(stable).opaque(data).bytes())
        status = u.uint()
        skip_wcc(u)
        if status != 0:
            raise make_nfs_error(status, "WRITE")
        return u.uint()

    def _made(self, u: Unpacker, what: str) -> tuple[bytes | None, Fattr | None]:
        status = u.uint()
        if status != 0:
            skip_wcc(u)
            raise make_nfs_error(status, what)
        fh = read_post_op_fh(u)
        attr = read_post_op_attr(u)
        skip_wcc(u)
        return fh, attr

    def create(self, dir_fh: bytes, name: str, mode: int = 0o644, exclusive: bool = False) -> tuple[bytes | None, Fattr | None]:
        p = Packer().opaque(dir_fh).string(name).uint(1 if exclusive else 0)
        u = self.rpc.call(NFSPROC_CREATE, p.bytes() + sattr(mode=mode, size=0 if not exclusive else None))
        return self._made(u, f"CREATE {name!r}")

    def mkdir(self, dir_fh: bytes, name: str, mode: int = 0o755) -> tuple[bytes | None, Fattr | None]:
        u = self.rpc.call(NFSPROC_MKDIR, Packer().opaque(dir_fh).string(name).bytes() + sattr(mode=mode))
        return self._made(u, f"MKDIR {name!r}")

    def symlink(self, dir_fh: bytes, name: str, target: str) -> None:
        u = self.rpc.call(NFSPROC_SYMLINK, Packer().opaque(dir_fh).string(name).bytes() + sattr(mode=0o777) + Packer().string(target).bytes())
        self._made(u, f"SYMLINK {name!r}")

    def link(self, fh: bytes, dir_fh: bytes, name: str) -> None:
        u = self.rpc.call(NFSPROC_LINK, Packer().opaque(fh).opaque(dir_fh).string(name).bytes())
        _check(u, f"LINK {name!r}")

    def remove(self, dir_fh: bytes, name: str, *, directory: bool = False) -> None:
        u = self.rpc.call(NFSPROC_RMDIR if directory else NFSPROC_REMOVE, Packer().opaque(dir_fh).string(name).bytes())
        _check(u, f"{'RMDIR' if directory else 'REMOVE'} {name!r}")

    def rename(self, from_dir: bytes, from_name: str, to_dir: bytes, to_name: str) -> None:
        u = self.rpc.call(NFSPROC_RENAME, Packer().opaque(from_dir).string(from_name).opaque(to_dir).string(to_name).bytes())
        _check(u, f"RENAME {from_name!r}")

    def readdirplus(self, dir_fh: bytes, dircount: int = 8192, maxcount: int = 65536) -> list[DirEntry]:
        out: list[DirEntry] = []
        cookie, verf = 0, b"\0" * 8
        for _round in range(MAX_LIST):
            u = self.rpc.call(NFSPROC_READDIRPLUS, Packer().opaque(dir_fh).hyper(cookie).fixed(verf).uint(dircount).uint(maxcount).bytes())
            status = u.uint()
            read_post_op_attr(u)
            if status != 0:
                raise make_nfs_error(status, "READDIRPLUS")
            verf = u.fixed(8)
            got = 0
            while u.boolean():
                fileid = u.hyper()
                name = u.string(4096)
                cookie = u.hyper()
                attr = read_post_op_attr(u)
                fh = read_post_op_fh(u)
                got += 1
                if name not in (".", ".."):
                    out.append(DirEntry(name, fileid, attr, fh))
                if len(out) > MAX_LIST:
                    raise RpcError(errno.EMSGSIZE, f"more than {MAX_LIST} entries in one folder")
            if u.boolean():
                return out
            if got == 0:
                raise RpcError(errno.EPROTO, "READDIRPLUS made no progress")
        raise RpcError(errno.EMSGSIZE, "READDIRPLUS did not end")

    def fsstat(self, fh: bytes) -> tuple[int, int, int]:
        u = self.rpc.call(NFSPROC_FSSTAT, Packer().opaque(fh).bytes())
        status = u.uint()
        read_post_op_attr(u)
        if status != 0:
            raise make_nfs_error(status, "FSSTAT")
        tbytes, fbytes, abytes = u.hyper(), u.hyper(), u.hyper()
        return tbytes, fbytes, abytes

    def fsinfo(self, fh: bytes) -> FsInfo:
        u = self.rpc.call(NFSPROC_FSINFO, Packer().opaque(fh).bytes())
        status = u.uint()
        read_post_op_attr(u)
        if status != 0:
            raise make_nfs_error(status, "FSINFO")
        rtmax, _rtpref, _rtmult, wtmax, _wtpref, _wtmult, dtpref = (u.uint() for _ in range(7))
        return FsInfo(rtmax=max(512, min(rtmax or 32768, MAX_IO)), wtmax=max(512, min(wtmax or 32768, MAX_IO)),
                      dtpref=max(512, min(dtpref or 8192, 65536)))


def mount(rpc: RpcConnection, export: str) -> bytes:
    """MOUNT v3 MNT: the export's root handle."""
    u = rpc.call(MOUNTPROC_MNT, Packer().string(export).bytes())
    status = u.uint()
    if status != 0:
        raise OSError(_NFS_ERRNO.get(status, errno.EIO),
                      f"MOUNT {export}: {_MOUNT_ERRORS.get(status, f'error {status}')}")
    fh = u.opaque(FHSIZE)
    n = u.uint()
    if n > 64:
        raise RpcError(errno.EPROTO, "too many auth flavours")
    flavours = [u.uint() for _ in range(n)]
    if flavours and AUTH_SYS not in flavours and AUTH_NONE not in flavours:
        raise OSError(errno.EACCES, f"MOUNT {export}: the export wants another security flavour "
                      f"({flavours}; Kerberos is not spoken here)")
    return fh


def unmount(rpc: RpcConnection, export: str) -> None:
    rpc.call(MOUNTPROC_UMNT, Packer().string(export).bytes(), retry=False)


def exports(rpc: RpcConnection) -> list[dict]:
    """MOUNT v3 EXPORT: [{"path", "clients"}]."""
    u = rpc.call(MOUNTPROC_EXPORT)
    out = []
    while u.boolean():
        path = u.string(1024)
        groups = []
        while u.boolean():
            groups.append(u.string(255))
            if len(groups) > 1024:
                raise RpcError(errno.EMSGSIZE, "too many client groups")
        out.append({"path": path, "clients": groups or ["*"]})
        if len(out) > MAX_LIST:
            raise RpcError(errno.EMSGSIZE, "too many exports")
    return out
