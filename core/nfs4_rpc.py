"""NFSv4.0 (RFC 7530) for axross's own NFS client: COMPOUND procedures on
one TCP connection to port 2049 (no portmapper, no mountd), with the same
AUTH_SYS sender information as NFSv3 (core.nfs3_rpc) and a chosen client
id string (SETCLIENTID: what the server knows this client as).

:class:`Nfs4` offers the method set of core.nfs3_rpc.Nfs3 (getattr,
lookup, readdirplus, read, write, create, mkdir, symlink, link, remove,
rename, setattr, readlink, fsstat, fsinfo), so core.nfs_user_client uses
either. Files are created with OPEN (and closed again at once); READ and
WRITE of existing files use the anonymous stateid; the client id is
registered when a file is first created and renewed when it expired.
Everything a server sends is bounded as in core.nfs3_rpc.
"""

from __future__ import annotations

import errno
import os
import threading
import time

from core import nfs3_rpc as R

NFS4_PROG, NFS4_VERS, PROC_COMPOUND = 100003, 4, 1
(OP_CLOSE, OP_COMMIT, OP_CREATE, OP_GETATTR, OP_GETFH, OP_LINK, OP_LOOKUP, OP_OPEN, OP_OPEN_CONFIRM,
 OP_PUTFH, OP_PUTROOTFH, OP_READ, OP_READDIR, OP_READLINK, OP_REMOVE, OP_RENAME, OP_RENEW, OP_SAVEFH,
 OP_SETATTR, OP_SETCLIENTID, OP_SETCLIENTID_CONFIRM, OP_WRITE) = (
    4, 5, 6, 9, 10, 11, 15, 18, 20, 22, 24, 25, 26, 27, 28, 29, 30, 32, 34, 35, 36, 38)
NF4REG, NF4DIR, NF4LNK = 1, 2, 5
# attribute numbers (RFC 7530 5.8)
A_TYPE, A_SIZE, A_FILEHANDLE, A_FILEID = 1, 4, 19, 20
A_SPACE_AVAIL, A_SPACE_FREE, A_SPACE_TOTAL = 42, 43, 44
A_MODE, A_NUMLINKS, A_OWNER, A_OWNER_GROUP, A_SPACE_USED = 33, 35, 36, 37, 45
A_TIME_ACCESS, A_TIME_METADATA, A_TIME_MODIFY = 47, 52, 53
STAT_ATTRS = (A_TYPE, A_SIZE, A_FILEID, A_MODE, A_NUMLINKS, A_OWNER, A_OWNER_GROUP, A_SPACE_USED,
              A_TIME_ACCESS, A_TIME_METADATA, A_TIME_MODIFY)
ANON_STATEID = b"\0" * 16
NFS4ERR_EXPIRED, NFS4ERR_STALE_CLIENTID, NFS4ERR_LEASE_MOVED = 10011, 10022, 10031
NFS4ERR_NOFILEHANDLE, NFS4ERR_DENIED = 10020, 10010
# NFSv4.1 (RFC 8881): sessions
OP_EXCHANGE_ID, OP_CREATE_SESSION, OP_DESTROY_SESSION, OP_SEQUENCE = 42, 43, 44, 53
OP_DESTROY_CLIENTID, OP_RECLAIM_COMPLETE = 57, 58
EXCHGID4_FLAG_USE_NON_PNFS = 0x00010000
NFS4ERR_BADSESSION, NFS4ERR_DEADSESSION, NFS4ERR_SEQ_MISORDERED = 10052, 10078, 10063
#: A SEQUENCE refused with one of these: the session (or the client id) is
#: gone, or the slot's sequence id is out of step - a new session mends it.
SESSION_LOST = (NFS4ERR_BADSESSION, NFS4ERR_DEADSESSION, NFS4ERR_STALE_CLIENTID, NFS4ERR_SEQ_MISORDERED)

_V4_ERRORS = {10001: "bad file handle", 10004: "operation not supported", 10006: "server fault",
              10008: "the server is busy, try again later", 10011: "the client's lease expired",
              10013: "the server is in its grace period, try again", 10016: "wrong security flavour "
              "for this export (AUTH_SYS not accepted)", 10020: "no current file handle",
              10022: "stale client id", 10026: "the operation needs an OPEN the server does not know",
              10044: "operation not supported on this kind of file", 10025: "bad stateid",
              10052: "the server does not know the session", 10078: "the server ended the session",
              10063: "the session's sequence is out of step"}


class _SequenceRefused(Exception):
    """The server refused a compound's SEQUENCE: nothing of it was done,
    and the slot's sequence id did not advance."""

    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


def _error(status: int, what: str) -> OSError:
    if status in _V4_ERRORS and status not in (10001, 10004, 10006, 10008):
        return OSError(errno.EIO, f"{what}: {_V4_ERRORS[status]}")
    return R.make_nfs_error(status, what)


def bitmap(attrs) -> list[int]:
    words = [0] * (max(attrs) // 32 + 1 if attrs else 0)
    for a in attrs:
        words[a // 32] |= 1 << (a % 32)
    return words


def pack_bitmap(p: R.Packer, words: list[int]) -> R.Packer:
    p.uint(len(words))
    for w in words:
        p.uint(w)
    return p


def read_bitmap(u: R.Unpacker) -> list[int]:
    n = u.uint()
    if n > 8:
        raise R.RpcError(errno.EPROTO, "an attribute bitmap of more than 8 words")
    return [u.uint() for _ in range(n)]


def attrs_in(words: list[int]) -> list[int]:
    return [i * 32 + b for i, w in enumerate(words) for b in range(32) if w & (1 << b)]


def _time4(u: R.Unpacker) -> float:
    sec = u.hyper()
    if sec >= 1 << 63:
        sec -= 1 << 64
    return sec + min(u.uint(), 999_999_999) / 1e9


_SKIP = {A_SPACE_AVAIL: 8, A_SPACE_FREE: 8, A_SPACE_TOTAL: 8}


def read_fattr4(u: R.Unpacker) -> dict:
    """bitmap + attrlist -> {attribute number: value} for the ones known here."""
    words = read_bitmap(u)
    data = R.Unpacker(u.opaque(64 * 1024))
    out: dict = {}
    for a in attrs_in(words):
        if a in (A_TYPE, A_MODE, A_NUMLINKS):
            out[a] = data.uint()
        elif a in (A_SIZE, A_FILEID, A_SPACE_USED, A_SPACE_AVAIL, A_SPACE_FREE, A_SPACE_TOTAL):
            out[a] = data.hyper()
        elif a in (A_OWNER, A_OWNER_GROUP):
            out[a] = data.string(1024)
        elif a in (A_TIME_ACCESS, A_TIME_METADATA, A_TIME_MODIFY):
            out[a] = _time4(data)
        elif a == A_FILEHANDLE:
            out[a] = data.opaque(128)
        else:
            break   # an attribute not asked for: the rest cannot be told apart
    return out


def _id_of(owner: str) -> int:
    """'1000' or '1000@domain' -> 1000; a name -> 65534 (not mapped here)."""
    head = owner.split("@", 1)[0]
    return int(head) if head.isdigit() else 65534


def to_fattr(a: dict) -> R.Fattr:
    t = a.get(A_TYPE, NF4REG)
    kind = {NF4REG: R.NF3REG, NF4DIR: R.NF3DIR, NF4LNK: R.NF3LNK}.get(t, R.NF3REG)
    return R.Fattr(kind, a.get(A_MODE, 0) & 0o7777, a.get(A_NUMLINKS, 1), _id_of(a.get(A_OWNER, "")),
                   _id_of(a.get(A_OWNER_GROUP, "")), a.get(A_SIZE, 0), a.get(A_SPACE_USED, 0),
                   a.get(A_FILEID, 0), a.get(A_TIME_ACCESS, 0.0), a.get(A_TIME_MODIFY, 0.0),
                   a.get(A_TIME_METADATA, 0.0))


def _setattrs(mode: int | None = None, size: int | None = None) -> bytes:
    attrs, body = [], R.Packer()
    if size is not None:
        attrs.append(A_SIZE)
        body.hyper(size)
    if mode is not None:
        attrs.append(A_MODE)
        body.uint(mode & 0o7777)
    p = pack_bitmap(R.Packer(), bitmap(attrs))
    return p.opaque(body.bytes()).bytes()


def _skip_cinfo(u: R.Unpacker) -> None:
    u.boolean()
    u.hyper()
    u.hyper()


class Nfs4:
    """NFSv4.0 / 4.1 compounds with the method set of core.nfs3_rpc.Nfs3.

    *minor* 1: the client id is registered by EXCHANGE_ID, a session is made
    (CREATE_SESSION, RECLAIM_COMPLETE) at the first call, and every compound
    starts with SEQUENCE on slot 0; OPEN needs no confirmation. The one slot
    is used by one call at a time (``_slot_lock``: a listing and a transfer
    on two threads otherwise send the same sequence id, or one out of
    order); its sequence id advances only when the server took the
    SEQUENCE. A session the server lost (BADSESSION, DEADSESSION,
    STALE_CLIENTID: a reboot, an expired lease) or a sequence out of step
    (SEQ_MISORDERED, after a reply that never came) is made again and the
    call sent once more - a refused SEQUENCE means nothing of it was done."""

    def __init__(self, rpc: R.RpcConnection, *, client_id: str = "", machine_name: str = "", minor: int = 0):
        if minor not in (0, 1):
            raise ValueError(f"NFSv4.{minor}: axross's own client speaks 4.0 and 4.1")
        self.minor = minor
        self._session: bytes | None = None
        self._slot_seq = 0
        self.rpc = rpc
        self.client_id = (client_id or f"axross:{machine_name or 'client'}").encode("utf-8")[:1024]
        self._clientid: int | None = None
        self._verifier = os.urandom(8)
        self._lock = threading.Lock()       # the client id and making a session
        self._slot_lock = threading.Lock()  # slot 0: its sequence id and the call that uses it
        self._last_renew = 0.0

    # --- compounds ----------------------------------------------------------------------

    def compound(self, ops: list[tuple[int, bytes]], what: str, *, _recover: bool = True
                 ) -> list[tuple[int, R.Unpacker]]:
        """Send *ops*; [(opcode, unpacker positioned after that op's status)].
        The first failing op raises."""
        sequenced = self.minor == 1 and ops and ops[0][0] not in (OP_EXCHANGE_ID, OP_CREATE_SESSION)
        if not sequenced:
            return self._send(ops, what, False)
        for attempt in (0, 1):
            self._ensure_session()
            with self._slot_lock:
                session = self._session
                if session is None:              # closed, or lost on another thread just now
                    refused = _SequenceRefused(NFS4ERR_BADSESSION)
                else:
                    seq = (self._slot_seq + 1) & 0xFFFFFFFF
                    args = R.Packer().fixed(session).uint(seq).uint(0).uint(0).boolean(False).bytes()
                    try:
                        results = self._send([(OP_SEQUENCE, args)] + list(ops), what, True)
                    except _SequenceRefused as exc:
                        refused = exc            # not taken: the sequence id stays where it was
                    except BaseException:
                        # taken (a later op failed) or no answer at all: count it as used - the
                        # same id sent again would be answered from the reply cache
                        self._advance(session, seq)
                        raise
                    else:
                        self._advance(session, seq)
                        return results[1:]
            if _recover and attempt == 0 and refused.status in SESSION_LOST:
                self._drop_session(session, refused.status)
                continue
            raise _error(refused.status, what)
        raise AssertionError("unreachable")

    def _advance(self, session: bytes, seq: int) -> None:
        """Under _slot_lock: *seq* was used on *session*."""
        if self._session is session:
            self._slot_seq = seq

    def _drop_session(self, session: bytes | None, status: int) -> None:
        """Forget *session* (unless another thread made a new one already)."""
        with self._lock, self._slot_lock:
            if self._session is session:
                self._session = None
                if status == NFS4ERR_STALE_CLIENTID:
                    self._clientid = None

    def _send(self, ops: list[tuple[int, bytes]], what: str, sequenced: bool) -> list[tuple[int, R.Unpacker]]:
        p = R.Packer().string("axross").uint(self.minor).uint(len(ops))
        body = p.bytes() + b"".join(R.Packer().uint(op).bytes() + args for op, args in ops)
        u = self.rpc.call(PROC_COMPOUND, body)
        status = u.uint()
        u.string(1024)                     # tag
        n = u.uint()
        if n > len(ops):
            raise R.RpcError(errno.EPROTO, "more results than operations")
        if sequenced and n == 0 and status != 0:
            raise _SequenceRefused(status)     # refused before SEQUENCE was looked at
        results = []
        for i in range(n):
            op = u.uint()
            if op != ops[i][0]:
                raise R.RpcError(errno.EPROTO, f"result for operation {op}, expected {ops[i][0]}")
            op_status = u.uint()
            if op_status != 0:
                if sequenced and i == 0:
                    raise _SequenceRefused(op_status)
                raise _error(op_status, what)
            results.append((op, u))
            self._consume(op, u, results)
        if status != 0:
            raise _error(status, what)
        return results

    def _consume(self, op: int, u: R.Unpacker, results: list) -> None:
        """Read past an op's result body, keeping what is needed."""
        if op == OP_GETFH:
            results[-1] = (op, u.opaque(R.FHSIZE * 2))
        elif op == OP_GETATTR:
            results[-1] = (op, read_fattr4(u))
        elif op == OP_READLINK:
            results[-1] = (op, u.string(4096))
        elif op == OP_READ:
            eof = u.boolean()
            results[-1] = (op, (u.opaque(R.MAX_IO + 4096), eof))
        elif op == OP_WRITE:
            count = u.uint()
            u.uint()
            u.fixed(8)
            results[-1] = (op, count)
        elif op in (OP_CREATE,):
            _skip_cinfo(u)
            read_bitmap(u)
        elif op in (OP_REMOVE, OP_LINK):
            _skip_cinfo(u)
        elif op == OP_RENAME:
            _skip_cinfo(u)
            _skip_cinfo(u)
        elif op == OP_SETATTR:
            read_bitmap(u)
        elif op == OP_SETCLIENTID:
            results[-1] = (op, (u.hyper(), u.fixed(8)))
        elif op == OP_OPEN:
            stateid = u.fixed(16)
            _skip_cinfo(u)
            rflags = u.uint()
            read_bitmap(u)
            delegation = u.uint()
            if delegation in (1, 2):
                u.fixed(16)
                u.boolean()
                if delegation == 2:
                    limit = u.uint()
                    if limit == 1:
                        u.hyper()
                    else:
                        u.uint()
                        u.uint()
                u.uint(), u.uint(), u.uint()
                u.string(1024)
            results[-1] = (op, (stateid, rflags))
        elif op in (OP_OPEN_CONFIRM, OP_CLOSE):
            results[-1] = (op, u.fixed(16))
        elif op == OP_SEQUENCE:
            u.fixed(16)
            for _ in range(5):
                u.uint()
        elif op == OP_EXCHANGE_ID:
            clientid, sequence = u.hyper(), u.uint()
            u.uint()                                   # flags
            if u.uint() != 0:                          # state protection: only SP4_NONE is asked
                raise R.RpcError(errno.EPROTO, "EXCHANGE_ID: state protection not asked for")
            u.hyper()
            u.opaque(1024)                             # server owner
            u.opaque(1024)                             # server scope
            for _ in range(min(u.uint(), 1)):          # server implementation id
                u.string(1024), u.string(1024), u.hyper(), u.uint()
            results[-1] = (op, (clientid, sequence))
        elif op == OP_CREATE_SESSION:
            session = u.fixed(16)
            u.uint(), u.uint()
            for _ in range(2):                         # fore and back channel attributes
                for _ in range(6):
                    u.uint()
                for _ in range(min(u.uint(), 1)):
                    u.uint()
            results[-1] = (op, session)
        elif op == OP_READDIR:
            verf = u.fixed(8)
            entries = []
            while u.boolean():
                cookie = u.hyper()
                name = u.string(4096)
                attrs = read_fattr4(u)
                entries.append((cookie, name, attrs))
                if len(entries) > R.MAX_LIST:
                    raise R.RpcError(errno.EMSGSIZE, "too many directory entries")
            results[-1] = (op, (verf, entries, u.boolean()))
        # PUTFH, PUTROOTFH, LOOKUP, SAVEFH, RENEW, SETCLIENTID_CONFIRM, COMMIT: nothing more

    @staticmethod
    def _putfh(fh: bytes) -> tuple[int, bytes]:
        return OP_PUTFH, R.Packer().opaque(fh).bytes()

    @staticmethod
    def _getattr(attrs=STAT_ATTRS) -> tuple[int, bytes]:
        return OP_GETATTR, pack_bitmap(R.Packer(), bitmap(attrs)).bytes()

    # --- the export's root ----------------------------------------------------------------------

    def root(self, export: str) -> bytes:
        ops = [(OP_PUTROOTFH, b"")]
        for part in [p for p in export.split("/") if p]:
            ops.append((OP_LOOKUP, R.Packer().string(part).bytes()))
        ops.append((OP_GETFH, b""))
        return self.compound(ops, f"the export {export}")[-1][1]

    # --- the Nfs3 method set -----------------------------------------------------------------

    def getattr(self, fh: bytes) -> R.Fattr:
        return to_fattr(self.compound([self._putfh(fh), self._getattr()], "GETATTR")[-1][1])

    def lookup(self, dir_fh: bytes, name: str) -> tuple[bytes, R.Fattr | None]:
        res = self.compound([self._putfh(dir_fh), (OP_LOOKUP, R.Packer().string(name).bytes()),
                             (OP_GETFH, b""), self._getattr()], f"LOOKUP {name!r}")
        return res[2][1], to_fattr(res[3][1])

    def readlink(self, fh: bytes) -> str:
        return self.compound([self._putfh(fh), (OP_READLINK, b"")], "READLINK")[-1][1]

    def read(self, fh: bytes, offset: int, count: int) -> tuple[bytes, bool]:
        args = R.Packer().fixed(ANON_STATEID).hyper(offset).uint(count).bytes()
        data, eof = self.compound([self._putfh(fh), (OP_READ, args)], "READ")[-1][1]
        if len(data) > count:
            raise R.RpcError(errno.EPROTO, "READ answered more than was asked")
        return data, eof

    def write(self, fh: bytes, offset: int, data: bytes, stable: int = R.FILE_SYNC) -> int:
        args = R.Packer().fixed(ANON_STATEID).hyper(offset).uint(stable).opaque(data).bytes()
        return self.compound([self._putfh(fh), (OP_WRITE, args)], "WRITE")[-1][1]

    def setattr(self, fh: bytes, *, mode: int | None = None, size: int | None = None, **_other) -> None:
        args = R.Packer().fixed(ANON_STATEID).bytes() + _setattrs(mode=mode, size=size)
        self.compound([self._putfh(fh), (OP_SETATTR, args)], "SETATTR")

    def _made(self, dir_fh: bytes, name: str, create_args: bytes, what: str):
        res = self.compound([self._putfh(dir_fh), (OP_CREATE, create_args), (OP_GETFH, b""),
                             self._getattr()], what)
        return res[2][1], to_fattr(res[3][1])

    def mkdir(self, dir_fh: bytes, name: str, mode: int = 0o755):
        args = R.Packer().uint(NF4DIR).string(name).bytes() + _setattrs(mode=mode)
        return self._made(dir_fh, name, args, f"MKDIR {name!r}")

    def symlink(self, dir_fh: bytes, name: str, target: str) -> None:
        args = R.Packer().uint(NF4LNK).string(target).string(name).bytes() + _setattrs()
        self._made(dir_fh, name, args, f"SYMLINK {name!r}")

    def link(self, fh: bytes, dir_fh: bytes, name: str) -> None:
        self.compound([self._putfh(fh), (OP_SAVEFH, b""), self._putfh(dir_fh),
                       (OP_LINK, R.Packer().string(name).bytes())], f"LINK {name!r}")

    def remove(self, dir_fh: bytes, name: str, *, directory: bool = False) -> None:
        self.compound([self._putfh(dir_fh), (OP_REMOVE, R.Packer().string(name).bytes())],
                      f"{'RMDIR' if directory else 'REMOVE'} {name!r}")

    def rename(self, from_dir: bytes, from_name: str, to_dir: bytes, to_name: str) -> None:
        self.compound([self._putfh(from_dir), (OP_SAVEFH, b""), self._putfh(to_dir),
                       (OP_RENAME, R.Packer().string(from_name).string(to_name).bytes())],
                      f"RENAME {from_name!r}")

    def readdirplus(self, dir_fh: bytes, dircount: int = 8192, maxcount: int = 65536) -> list[R.DirEntry]:
        out: list[R.DirEntry] = []
        cookie, verf = 0, b"\0" * 8
        want = pack_bitmap(R.Packer(), bitmap(STAT_ATTRS + (A_FILEHANDLE,))).bytes()
        for _round in range(R.MAX_LIST):
            args = R.Packer().hyper(cookie).fixed(verf).uint(dircount).uint(maxcount).bytes() + want
            verf, entries, eof = self.compound([self._putfh(dir_fh), (OP_READDIR, args)], "READDIR")[-1][1]
            for cookie, name, attrs in entries:
                if name not in (".", ".."):
                    out.append(R.DirEntry(name, attrs.get(A_FILEID, 0), to_fattr(attrs),
                                          attrs.get(A_FILEHANDLE)))
            if eof:
                return out
            if not entries:
                raise R.RpcError(errno.EPROTO, "READDIR made no progress")
        raise R.RpcError(errno.EMSGSIZE, "READDIR did not end")

    def fsstat(self, fh: bytes) -> tuple[int, int, int]:
        a = self.compound([self._putfh(fh), self._getattr((A_SPACE_AVAIL, A_SPACE_FREE, A_SPACE_TOTAL))],
                          "space")[-1][1]
        return a.get(A_SPACE_TOTAL, 0), a.get(A_SPACE_FREE, 0), a.get(A_SPACE_AVAIL, 0)

    def fsinfo(self, fh: bytes) -> R.FsInfo:
        return R.FsInfo(rtmax=256 * 1024, wtmax=256 * 1024, dtpref=16384)

    # --- creating files: the client id and OPEN ----------------------------------------------------

    def _ensure_session(self) -> None:
        if self._session is not None:
            return
        with self._lock:
            if self._session is not None:
                return
            args = (R.Packer().fixed(self._verifier).opaque(self.client_id).uint(EXCHGID4_FLAG_USE_NON_PNFS)
                    .uint(0).uint(0).bytes())          # SP4_NONE, no implementation id
            clientid, sequence = self.compound([(OP_EXCHANGE_ID, args)], "EXCHANGE_ID")[-1][1]
            attrs = R.Packer()
            for size in (0, 1 << 20, 1 << 20, 4096, 16, 1):   # pad, request, response, cached, ops, requests
                attrs.uint(size)
            attrs.uint(0)                               # no RDMA
            channel = attrs.bytes()
            args = (R.Packer().hyper(clientid).uint(sequence).uint(0).bytes() + channel + channel
                    + R.Packer().uint(0x40000000).uint(1).uint(0).bytes())   # callback: AUTH_NONE
            session = self.compound([(OP_CREATE_SESSION, args)], "CREATE_SESSION")[-1][1]
            with self._slot_lock:                       # a new session: its slot starts again at 1
                self._session, self._slot_seq = session, 0
            self._clientid = clientid
        try:
            self.compound([(OP_RECLAIM_COMPLETE, R.Packer().boolean(False).bytes())], "RECLAIM_COMPLETE",
                          _recover=False)
        except OSError:
            pass                                        # a server without state to reclaim may say so

    def close(self) -> None:
        """Ends the 4.1 session (best effort)."""
        if self.minor == 1 and self._session is not None:
            try:
                self.compound([(OP_DESTROY_SESSION, R.Packer().fixed(self._session).bytes())], "DESTROY_SESSION",
                              _recover=False)
            except OSError:
                pass
            with self._slot_lock:
                self._session = None

    def _register(self) -> int:
        if self.minor == 1:
            self._ensure_session()
            return self._clientid
        with self._lock:
            if self._clientid is not None and time.monotonic() - self._last_renew < 60:
                return self._clientid
            if self._clientid is not None:
                try:
                    self.compound([(OP_RENEW, R.Packer().hyper(self._clientid).bytes())], "RENEW")
                    self._last_renew = time.monotonic()
                    return self._clientid
                except OSError:
                    self._clientid = None
            callback = R.Packer().uint(0x40000000).string("tcp").string("0.0.0.0.0.0").uint(1).bytes()
            args = R.Packer().fixed(self._verifier).opaque(self.client_id).bytes() + callback
            clientid, confirm = self.compound([(OP_SETCLIENTID, args)], "SETCLIENTID")[-1][1]
            self.compound([(OP_SETCLIENTID_CONFIRM, R.Packer().hyper(clientid).fixed(confirm).bytes())],
                          "SETCLIENTID_CONFIRM")
            self._clientid, self._last_renew = clientid, time.monotonic()
            return clientid

    def create(self, dir_fh: bytes, name: str, mode: int = 0o644, exclusive: bool = False):
        for attempt in (0, 1):
            clientid = self._register()
            owner = R.Packer().hyper(clientid).opaque(os.urandom(12)).bytes()
            how = R.Packer().uint(1).uint(1 if exclusive else 0).bytes() + _setattrs(mode=mode, size=0)
            args = (R.Packer().uint(0).uint(3).uint(0).bytes() + owner + how
                    + R.Packer().uint(0).string(name).bytes())
            try:
                res = self.compound([self._putfh(dir_fh), (OP_OPEN, args), (OP_GETFH, b""),
                                     self._getattr()], f"OPEN {name!r}")
            except OSError as exc:
                if attempt == 0 and ("lease" in str(exc) or "stale client" in str(exc)):
                    self._clientid = None
                    continue
                raise
            (stateid, rflags), fh, attrs = res[1][1], res[2][1], res[3][1]
            seqid = 0 if self.minor == 1 else 1           # 4.1: seqids are not used
            if rflags & 2 and self.minor == 0:   # OPEN4_RESULT_CONFIRM
                stateid = self.compound([self._putfh(fh), (OP_OPEN_CONFIRM,
                                         R.Packer().fixed(stateid).uint(seqid).bytes())], "OPEN_CONFIRM")[-1][1]
                seqid += 1
            self.compound([self._putfh(fh), (OP_CLOSE, R.Packer().uint(seqid).fixed(stateid).bytes())], "CLOSE")
            return fh, to_fattr(attrs)
        raise OSError(errno.EIO, f"OPEN {name!r}: the client id could not be registered")
