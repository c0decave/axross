"""A small NFSv3 server for the tests of axross's own NFS client.

Portmapper, MOUNT v3 and NFSv3 on one TCP port of 127.0.0.1, the export
backed by a folder. Every call's AUTH_SYS credentials are recorded
(``server.creds``), and ``allowed_uids`` refuses calls from other UIDs with
NFS3ERR_ACCES - the way a server's permission check depends on what the
client says about itself. Written from RFC 1813 / RFC 5531, independent of
core.nfs3_rpc (its own XDR code), so a shared misreading cannot hide.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import threading

OK, NOENT, IO, ACCES, EXIST, NOTDIR, ISDIR, INVAL, NOTEMPTY, STALE = 0, 2, 5, 13, 17, 20, 21, 22, 66, 70


class _In:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def u32(self) -> int:
        v = struct.unpack_from(">I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from(">Q", self.d, self.p)[0]
        self.p += 8
        return v

    def raw(self, n: int) -> bytes:
        v = self.d[self.p:self.p + n]
        self.p += n + (-n % 4)
        return v

    def var(self) -> bytes:
        return self.raw(self.u32())

    def text(self) -> str:
        return self.var().decode("utf-8", "surrogateescape")


def u32(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def var(b: bytes) -> bytes:
    return u32(len(b)) + b + b"\0" * (-len(b) % 4)


def text(s: str) -> bytes:
    return var(s.encode("utf-8", "surrogateescape"))


class FakeNfsd:
    def __init__(self, root: str, export: str = "/export", allowed_uids: set[int] | None = None,
                 dir_page: int = 3):
        self.root, self.export = os.path.realpath(root), export
        self.allowed_uids = allowed_uids
        self.dir_page = dir_page            # entries per READDIRPLUS reply: forces cookies
        self.creds: list[tuple[str, int, int, tuple[int, ...]]] = []
        self.calls: list[tuple[int, int]] = []
        self.lookups: list[str] = []
        self._ids: dict[bytes, str] = {}
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._stop = True
        self._sock.close()

    # --- handles -------------------------------------------------------------

    def fh(self, path: str) -> bytes:
        key = os.urandom(0) + struct.pack(">Q", os.lstat(path).st_ino) + b"axross-fake"
        self._ids[key] = path
        return key

    def path(self, fh: bytes) -> str | None:
        p = self._ids.get(fh)
        return p if p is not None and os.path.lexists(p) else None

    def _inside(self, path: str) -> bool:
        real = os.path.realpath(os.path.dirname(path))
        return real == self.root or real.startswith(self.root + os.sep)

    # --- attributes ----------------------------------------------------------

    @staticmethod
    def fattr(path: str) -> bytes:
        st = os.lstat(path)
        kind = {stat.S_IFREG: 1, stat.S_IFDIR: 2, stat.S_IFLNK: 5}.get(stat.S_IFMT(st.st_mode), 1)
        out = u32(kind) + u32(st.st_mode & 0o7777) + u32(st.st_nlink) + u32(st.st_uid) + u32(st.st_gid)
        out += u64(st.st_size) + u64(st.st_blocks * 512) + u32(0) + u32(0) + u64(1) + u64(st.st_ino)
        for t in (st.st_atime_ns, st.st_mtime_ns, st.st_ctime_ns):
            out += u32(t // 10**9) + u32(t % 10**9)
        return out

    def post(self, path: str | None) -> bytes:
        return u32(1) + self.fattr(path) if path and os.path.lexists(path) else u32(0)

    def wcc(self, path: str | None) -> bytes:
        return u32(0) + self.post(path)

    # --- the wire ------------------------------------------------------------

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(conn,), daemon=True).start()

    def _conn(self, conn: socket.socket) -> None:
        with conn:
            buf = b""
            while True:
                try:
                    while len(buf) < 4:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        buf += chunk
                    n = struct.unpack(">I", buf[:4])[0] & 0x7FFFFFFF
                    while len(buf) < 4 + n:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        buf += chunk
                    msg, buf = buf[4:4 + n], buf[4 + n:]
                    reply = self._dispatch(msg)
                    conn.sendall(u32(0x80000000 | len(reply)) + reply)
                except OSError:
                    return

    def _dispatch(self, msg: bytes) -> bytes:
        r = _In(msg)
        xid = r.u32()
        r.u32(), r.u32()                       # CALL, rpcvers
        prog, vers, proc = r.u32(), r.u32(), r.u32()
        flavor, body = r.u32(), r.var()
        r.u32(), r.var()                       # verifier
        head = u32(xid) + u32(1) + u32(0) + u32(0) + var(b"")
        if flavor == 1:
            a = _In(body)
            a.u32()
            machine = a.text()
            uid, gid = a.u32(), a.u32()
            gids = tuple(a.u32() for _ in range(a.u32()))
            self.creds.append((machine, uid, gid, gids))
        else:
            uid = None
        self.calls.append((prog, proc))
        if prog == 100000:
            p, v = r.u32(), r.u32()
            port = self.port if (p, v) in ((100005, 3), (100003, 3)) else 0
            return head + u32(0) + u32(port)
        if prog == 100005:
            return head + u32(0) + self._mount(proc, r)
        if prog == 100003 and vers == 3:
            if self.allowed_uids is not None and uid not in self.allowed_uids:
                return head + u32(0) + u32(ACCES) + u32(0) + u32(0) + u32(0)
            try:
                return head + u32(0) + self._nfs(proc, r)
            except OSError:
                return head + u32(0) + u32(IO) + u32(0) + u32(0)
        return head + u32(1)                   # PROG_UNAVAIL

    def _mount(self, proc: int, r: _In) -> bytes:
        if proc == 1:
            if r.text() != self.export:
                return u32(NOENT)
            return u32(OK) + var(self.fh(self.root)) + u32(1) + u32(1)
        if proc == 3:
            return b""
        if proc == 5:
            return u32(1) + text(self.export) + u32(1) + text("127.0.0.1") + u32(0) + u32(0)
        return u32(INVAL)

    def _child(self, r: _In) -> tuple[str | None, str]:
        d = self.path(r.var())
        name = r.text()
        if d is None:
            return None, name
        return os.path.join(d, name), name

    def _nfs(self, proc: int, r: _In) -> bytes:
        if proc == 1:   # GETATTR
            p = self.path(r.var())
            return u32(OK) + self.fattr(p) if p else u32(STALE)
        if proc == 2:   # SETATTR
            p = self.path(r.var())
            if not p:
                return u32(STALE) + self.wcc(None)
            if r.u32():
                os.chmod(p, r.u32())
            for _ in range(2):                 # uid, gid
                if r.u32():
                    r.u32()
            if r.u32():
                os.truncate(p, r.u64())
            return u32(OK) + self.wcc(p)
        if proc == 3:   # LOOKUP
            child, name = self._child(r)
            self.lookups.append(name)
            if child is None:
                return u32(STALE) + u32(0)
            if name in ("..", ".") or not self._inside(child) or not os.path.lexists(child):
                return u32(NOENT) + self.post(os.path.dirname(child))
            return u32(OK) + var(self.fh(child)) + self.post(child) + self.post(os.path.dirname(child))
        if proc == 5:   # READLINK
            p = self.path(r.var())
            return u32(OK) + self.post(p) + text(os.readlink(p)) if p else u32(STALE) + u32(0)
        if proc == 6:   # READ
            p, off, count = self.path(r.var()), r.u64(), r.u32()
            if not p:
                return u32(STALE) + u32(0)
            with open(p, "rb") as f:
                f.seek(off)
                data = f.read(min(count, 4096))  # less than asked: the client must loop
            eof = off + len(data) >= os.path.getsize(p)
            return u32(OK) + self.post(p) + u32(len(data)) + u32(1 if eof else 0) + var(data)
        if proc == 7:   # WRITE
            p, off, _count, _stable, data = self.path(r.var()), r.u64(), r.u32(), r.u32(), r.var()
            if not p:
                return u32(STALE) + self.wcc(None)
            data = data[:3000]                   # a short write: the client must loop
            with open(p, "r+b") as f:
                f.seek(off)
                f.write(data)
            return u32(OK) + self.wcc(p) + u32(len(data)) + u32(2) + b"verf0000"
        if proc in (8, 9, 10):   # CREATE, MKDIR, SYMLINK
            child, _name = self._child(r)
            if child is None or not self._inside(child):
                return u32(STALE) + self.wcc(None)
            if os.path.lexists(child) and proc != 8:
                return u32(EXIST) + self.wcc(os.path.dirname(child))
            if proc == 8:
                mode = r.u32()
                if mode == 1 and os.path.lexists(child):
                    return u32(EXIST) + self.wcc(os.path.dirname(child))
                with open(child, "wb"):
                    pass
            elif proc == 9:
                os.mkdir(child)
            else:
                for _ in range(3):
                    if r.u32():
                        r.u32()
                if r.u32():
                    r.u64()
                r.u32(), r.u32()
                os.symlink(r.text(), child)
            return u32(OK) + u32(1) + var(self.fh(child)) + self.post(child) + self.wcc(os.path.dirname(child))
        if proc in (12, 13):   # REMOVE, RMDIR
            child, _name = self._child(r)
            if child is None or not os.path.lexists(child):
                return u32(NOENT) + self.wcc(None)
            try:
                os.rmdir(child) if proc == 13 else (os.remove(child) if not os.path.isdir(child) or os.path.islink(child) else (_ for _ in ()).throw(IsADirectoryError()))
            except IsADirectoryError:
                return u32(ISDIR) + self.wcc(os.path.dirname(child))
            except OSError as exc:
                return u32(NOTEMPTY if exc.errno == 39 else IO) + self.wcc(os.path.dirname(child))
            return u32(OK) + self.wcc(os.path.dirname(child))
        if proc == 14:   # RENAME
            src, _ = self._child(r)
            dst, _ = self._child(r)
            if src is None or dst is None or not os.path.lexists(src):
                return u32(NOENT) + self.wcc(None) + self.wcc(None)
            os.replace(src, dst)
            return u32(OK) + self.wcc(None) + self.wcc(None)
        if proc == 15:   # LINK
            p = self.path(r.var())
            dst, _ = self._child(r)
            os.link(p, dst)
            return u32(OK) + self.post(p) + self.wcc(None)
        if proc == 17:   # READDIRPLUS
            p, cookie = self.path(r.var()), r.u64()
            r.raw(8), r.u32(), r.u32()
            if not p:
                return u32(STALE) + u32(0)
            names = sorted(os.listdir(p))
            page = names[cookie:cookie + self.dir_page]
            out = u32(OK) + self.post(p) + b"cookieve"
            for i, name in enumerate(page):
                full = os.path.join(p, name)
                out += u32(1) + u64(os.lstat(full).st_ino) + text(name) + u64(cookie + i + 1)
                out += self.post(full) + u32(1) + var(self.fh(full))
            out += u32(0) + u32(1 if cookie + len(page) >= len(names) else 0)
            return out
        if proc == 18:   # FSSTAT
            p = self.path(r.var())
            sv = os.statvfs(p)
            return (u32(OK) + self.post(p) + u64(sv.f_blocks * sv.f_frsize) + u64(sv.f_bfree * sv.f_frsize)
                    + u64(sv.f_bavail * sv.f_frsize) + u64(0) * 3 + u32(0))
        if proc == 19:   # FSINFO
            p = self.path(r.var())
            return (u32(OK) + self.post(p) + u32(8192) * 3 + u32(8192) * 3 + u32(4096)
                    + u64(2**40) + u32(0) + u32(1) + u32(0x1B))
        return u32(10004) + u32(0)


# --- NFSv4.0 -------------------------------------------------------------------------------

def _bitmap_in(r: _In) -> list[int]:
    words = [r.u32() for _ in range(r.u32())]
    return [i * 32 + b for i, w in enumerate(words) for b in range(32) if w & (1 << b)]


def _bitmap_out(attrs) -> bytes:
    n = max(attrs) // 32 + 1 if attrs else 0
    words = [0] * n
    for a in attrs:
        words[a // 32] |= 1 << (a % 32)
    return u32(n) + b"".join(u32(w) for w in words)


class FakeNfs4d(FakeNfsd):
    """NFSv4.0 COMPOUND on one port; the pseudo-root is *root*'s parent so
    the export is a path below it. ``client_ids`` records SETCLIENTID."""

    SUPPORTED = (1, 4, 19, 20, 33, 35, 36, 37, 42, 43, 44, 45, 47, 52, 53)

    def __init__(self, root: str, **kw):
        super().__init__(root, **kw)
        self.pseudo = os.path.dirname(self.root)
        self.client_ids: list[bytes] = []
        self._next_client = 1
        self.opens = 0
        self.minors: list[int] = []
        self.sessions: list[bytes] = []
        self.destroyed: list[bytes] = []

    def _inside(self, path: str) -> bool:
        real = os.path.realpath(os.path.dirname(path))
        return real == self.pseudo or real.startswith(self.pseudo + os.sep)

    def _attrs(self, path: str, wanted) -> bytes:
        st = os.lstat(path)
        kind = {stat.S_IFREG: 1, stat.S_IFDIR: 2, stat.S_IFLNK: 5}.get(stat.S_IFMT(st.st_mode), 1)
        out, have = b"", []
        sv = os.statvfs(path) if not os.path.islink(path) else None
        for a in sorted(wanted):
            if a not in self.SUPPORTED:
                continue
            have.append(a)
            if a == 1:
                out += u32(kind)
            elif a == 4:
                out += u64(st.st_size)
            elif a == 19:
                out += var(self.fh(path))
            elif a == 20:
                out += u64(st.st_ino)
            elif a == 33:
                out += u32(st.st_mode & 0o7777)
            elif a == 35:
                out += u32(st.st_nlink)
            elif a == 36:
                out += text(str(st.st_uid))
            elif a == 37:
                out += text(str(st.st_gid))
            elif a in (42, 43, 44):
                v = {42: sv.f_bavail, 43: sv.f_bfree, 44: sv.f_blocks}[a] * sv.f_frsize if sv else 0
                out += u64(v)
            elif a == 45:
                out += u64(st.st_blocks * 512)
            else:
                t = {47: st.st_atime_ns, 52: st.st_ctime_ns, 53: st.st_mtime_ns}[a]
                out += u64(t // 10**9) + u32(t % 10**9)
        return _bitmap_out(have) + var(out)

    def _dispatch(self, msg: bytes) -> bytes:
        r = _In(msg)
        xid = r.u32()
        r.u32(), r.u32()
        prog, vers, proc = r.u32(), r.u32(), r.u32()
        flavor, body = r.u32(), r.var()
        r.u32(), r.var()
        head = u32(xid) + u32(1) + u32(0) + u32(0) + var(b"")
        uid = None
        if flavor == 1:
            a = _In(body)
            a.u32()
            machine = a.text()
            uid, gid = a.u32(), a.u32()
            self.creds.append((machine, uid, gid, tuple(a.u32() for _ in range(a.u32()))))
        if prog != 100003 or vers != 4 or proc not in (0, 1):
            return head + u32(1)
        if proc == 0:
            return head + u32(0)
        tag = r.text()
        minor = r.u32()
        self.minors.append(minor)
        n = r.u32()
        cur = saved = None
        results, status = b"", 0
        done = 0
        for index in range(n):
            op = r.u32()
            self.calls.append((100003, op))
            st, res = OK, b""
            try:
                if minor == 1 and index == 0 and op not in (42, 43, 53, 44):
                    st = 10071                         # NFS4ERR_OP_NOT_IN_SESSION
                elif op == 42:                         # EXCHANGE_ID
                    r.raw(8)
                    self.client_ids.append(r.var())
                    r.u32()                            # flags
                    r.u32()                            # SP4_NONE
                    for _ in range(r.u32()):
                        r.text(), r.text(), r.u64(), r.u32()
                    res = (u64(self._next_client) + u32(1) + u32(0x10000) + u32(0) + u64(7) + var(b"fake")
                           + var(b"scope") + u32(0))
                    self._next_client += 1
                elif op == 43:                         # CREATE_SESSION
                    r.u64(), r.u32(), r.u32()
                    for _ in range(2):
                        for _ in range(6):
                            r.u32()
                        for _ in range(r.u32()):
                            r.u32()
                    r.u32()
                    for _ in range(r.u32()):
                        r.u32()
                    sid = os.urandom(16)
                    self.sessions.append(sid)
                    attrs = u32(0) + u32(1 << 20) * 2 + u32(4096) + u32(16) + u32(1) + u32(0)
                    res = sid + u32(1) + u32(0) + attrs + attrs
                elif op == 53:                         # SEQUENCE
                    sid = r.raw(16)
                    seq, slot, _high, _cache = r.u32(), r.u32(), r.u32(), r.u32()
                    if sid not in self.sessions:
                        st = 10052                     # NFS4ERR_BADSESSION
                    else:
                        res = sid + u32(seq) + u32(slot) + u32(0) + u32(0) + u32(0)
                elif op == 44:                         # DESTROY_SESSION
                    self.destroyed.append(r.raw(16))
                elif op == 58:                         # RECLAIM_COMPLETE
                    r.u32()
                elif self.allowed_uids is not None and uid not in self.allowed_uids and op not in (35, 36, 30):
                    st = ACCES
                elif op == 24:                         # PUTROOTFH
                    cur = self.pseudo
                    self._ids[self.fh(cur)] = cur
                elif op == 22:                         # PUTFH
                    cur = self.path(r.var())
                    st = OK if cur else STALE
                elif op == 32:                         # SAVEFH
                    saved = cur
                elif op == 15:                         # LOOKUP
                    name = r.text()
                    self.lookups.append(name)
                    child = os.path.join(cur, name)
                    if name in (".", "..") or not self._inside(child) or not os.path.lexists(child):
                        st = NOENT
                    else:
                        cur = child
                elif op == 10:                         # GETFH
                    res = var(self.fh(cur))
                elif op == 9:                          # GETATTR
                    res = self._attrs(cur, _bitmap_in(r))
                elif op == 27:                         # READLINK
                    res = text(os.readlink(cur))
                elif op == 25:                         # READ
                    r.raw(16)
                    off, count = r.u64(), r.u32()
                    with open(cur, "rb") as f:
                        f.seek(off)
                        data = f.read(min(count, 4096))
                    res = u32(1 if off + len(data) >= os.path.getsize(cur) else 0) + var(data)
                elif op == 38:                         # WRITE
                    r.raw(16)
                    off, _stable, data = r.u64(), r.u32(), r.var()
                    data = data[:3000]
                    with open(cur, "r+b") as f:
                        f.seek(off)
                        f.write(data)
                    res = u32(len(data)) + u32(2) + b"wverf000"
                elif op == 34:                         # SETATTR
                    r.raw(16)
                    wanted = _bitmap_in(r)
                    vals = _In(r.var())
                    for a in wanted:
                        if a == 4:
                            os.truncate(cur, vals.u64())
                        elif a == 33:
                            os.chmod(cur, vals.u32())
                    res = _bitmap_out(wanted)
                elif op == 6:                          # CREATE (dir / link)
                    kind = r.u32()
                    target = r.text() if kind == 5 else None
                    name = r.text()
                    _bitmap_in(r)
                    r.var()
                    child = os.path.join(cur, name)
                    if os.path.lexists(child):
                        st = EXIST
                    else:
                        os.mkdir(child) if kind == 2 else os.symlink(target, child)
                        cur = child
                        res = u32(1) + u64(0) + u64(1) + _bitmap_out([])
                elif op == 28:                         # REMOVE
                    child = os.path.join(cur, r.text())
                    if not os.path.lexists(child):
                        st = NOENT
                    else:
                        try:
                            os.rmdir(child) if os.path.isdir(child) and not os.path.islink(child) else os.remove(child)
                            res = u32(1) + u64(0) + u64(1)
                        except OSError:
                            st = NOTEMPTY
                elif op == 29:                         # RENAME (saved = source dir)
                    old, new = r.text(), r.text()
                    os.replace(os.path.join(saved, old), os.path.join(cur, new))
                    res = (u32(1) + u64(0) + u64(1)) * 2
                elif op == 11:                         # LINK
                    name = r.text()
                    os.link(saved, os.path.join(cur, name))
                    res = u32(1) + u64(0) + u64(1)
                elif op == 26:                         # READDIR
                    cookie = r.u64()
                    r.raw(8), r.u32(), r.u32()
                    wanted = _bitmap_in(r)
                    names = sorted(os.listdir(cur))
                    page = names[cookie:cookie + self.dir_page]
                    res = b"verf4000"
                    for i, name in enumerate(page):
                        res += u32(1) + u64(cookie + i + 1) + text(name) + self._attrs(os.path.join(cur, name), wanted)
                    res += u32(0) + u32(1 if cookie + len(page) >= len(names) else 0)
                elif op == 35:                         # SETCLIENTID
                    r.raw(8)
                    self.client_ids.append(r.var())
                    r.u32(), r.text(), r.text(), r.u32()
                    res = u64(self._next_client) + b"confirm0"
                    self._next_client += 1
                elif op in (36, 30):                   # SETCLIENTID_CONFIRM, RENEW
                    r.u64()
                    if op == 36:
                        r.raw(8)
                elif op == 18:                         # OPEN
                    r.u32(), r.u32(), r.u32()
                    r.u64(), r.var()                   # owner
                    if r.u32() == 1:                   # OPEN4_CREATE
                        r.u32()
                        _bitmap_in(r)
                        r.var()
                    r.u32()                            # CLAIM_NULL
                    name = r.text()
                    child = os.path.join(cur, name)
                    if not os.path.lexists(child):
                        with open(child, "wb"):
                            pass
                    cur = child
                    self.opens += 1
                    res = b"S" * 16 + u32(1) + u64(0) + u64(1) + u32(2) + _bitmap_out([]) + u32(0)
                elif op == 20:                         # OPEN_CONFIRM
                    r.raw(16)
                    r.u32()
                    res = b"C" * 16
                elif op == 4:                          # CLOSE
                    r.u32()
                    r.raw(16)
                    res = b"X" * 16
                else:
                    st = 10004
            except OSError:
                st = IO
            results += u32(op) + u32(st) + (res if st == OK else b"")
            done += 1
            if st != OK:
                status = st
                break
        return head + u32(0) + u32(status) + text(tag) + u32(done) + results
