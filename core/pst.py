"""Outlook data files (.pst, .ost) read without Outlook or a library: the
node database (MS-PST NDB: header, node and block B-trees, data trees,
subnodes), the lists-tables-properties layer (heap-on-node, BTH, property
and table contexts) and the messaging layer (folders, messages, their
recipients and attachments).

Unicode files (wVer 23: 512-byte pages; wVer 36: Outlook 2013's 4 KB pages
with zlib-compressed blocks); "compressible" encoded blocks are decoded
(the cyclic encoding and ANSI files are refused with the reason). Read by
offset - a PST may be gigabytes - and bounded: every chain, tree depth,
count and size is checked before it is believed.

:meth:`PstFile.messages` yields each message as an RFC 5322 .eml rebuilt
from its properties: the transport headers when the message came over SMTP
(Received, Authentication-Results, DKIM-Signature ... as received), the
text and HTML bodies and the attachments.
"""

from __future__ import annotations

import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MAX_DEPTH = 16
MAX_BLOCK = 1024 * 1024
MAX_NODE = 128 * 1024 * 1024

NID_TYPE_NORMAL_FOLDER, NID_TYPE_NORMAL_MESSAGE, NID_TYPE_ATTACHMENT = 0x02, 0x04, 0x05
NID_ATTACHMENT_TABLE, NID_RECIPIENT_TABLE = 0x671, 0x692
NID_ROOT_FOLDER = 0x122

PT_I2, PT_I4, PT_R4, PT_R8, PT_BOOL, PT_I8, PT_SYSTIME = 0x2, 0x3, 0x4, 0x5, 0xB, 0x14, 0x40
PT_STRING8, PT_UNICODE, PT_BINARY, PT_GUID = 0x1E, 0x1F, 0x102, 0x48


class PstError(ValueError):
    """Not an Outlook data file, an unsupported one, or a broken one."""


_DECODE = bytes([
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
    0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
    0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
    0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
    0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
    0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
    0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
    0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
    0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
    0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
    0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
    0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
    0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
    0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
    0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
    0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec,
])


@dataclass
class Node:
    nid: int
    data: int
    sub: int
    parent: int


@dataclass
class PstMessage:
    folder: str
    nid: int
    props: dict
    recipients: list = field(default_factory=list)
    attachments: list = field(default_factory=list)

    @property
    def subject(self) -> str:
        s = self.props.get(0x0037, "")
        return s[2:] if isinstance(s, str) and s[:1] == "\x01" else s   # a subject prefix marker


class PstFile:
    def __init__(self, path: str | os.PathLike):
        self._f = open(path, "rb")
        self.size = os.fstat(self._f.fileno()).st_size
        head = self._read(0, 564)
        if head[:4] != b"!BDN":
            raise PstError("not an Outlook data file")
        self.version = struct.unpack_from("<H", head, 10)[0]
        if self.version in (14, 15):
            raise PstError("an ANSI .pst (Outlook 97-2002): not read here - save it as a Unicode .pst")
        if self.version not in (23, 36):
            raise PstError(f"unknown .pst version {self.version}")
        self.crypt = head[513]
        if self.crypt not in (0, 1):
            raise PstError("the .pst uses the cyclic encoding: not read here")
        self.page = 4096 if self.version == 36 else 512
        _nbt_bid, nbt_ib, _bbt_bid, bbt_ib = struct.unpack_from("<QQQQ", head, 216)
        self.blocks: dict[int, tuple[int, int, int]] = {}
        self.nodes: dict[int, Node] = {}
        # every B-tree page once: no more page reads than pages in the file
        self._visited: set[int] = set()
        self._page_budget = self.size // self.page + 1
        self._walk(bbt_ib, 0x80, 0)
        self._walk(nbt_ib, 0x81, 0)
        del self._visited

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- NDB -------------------------------------------------------------------------------

    def _read(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0 or offset + n > self.size:
            raise PstError(f"a read outside the file ({offset}+{n} of {self.size})")
        self._f.seek(offset)
        return self._f.read(n)

    def _walk(self, ib: int, ptype: int, depth: int, level: int | None = None) -> None:
        """One B-tree page and, below it, its children - each page read at
        most once, at most as many pages as the file can hold, each child one
        level lower than its parent: a crafted tree of pages pointing at each
        other is refused, not walked for ever."""
        if depth > MAX_DEPTH:
            raise PstError("corrupt .pst: a B-tree deeper than 16 levels")
        if ib in self._visited:
            raise PstError(f"corrupt .pst: the B-tree page at {ib} is reached twice")
        self._visited.add(ib)
        if len(self._visited) > self._page_budget:
            raise PstError(f"corrupt .pst: more B-tree pages than the file can hold ({self._page_budget})")
        page = self._read(ib, self.page)
        if self.page == 512:
            c_ent, _max, cb_ent, page_level = struct.unpack_from("<BBBB", page, 488)
            trailer = 496
        else:
            c_ent, _max, cb_ent, page_level = struct.unpack_from("<HHBB", page, 4056)
            trailer = 4072
        if page[trailer] != ptype:
            raise PstError(f"corrupt .pst: page at {ib} is no B-tree page of the expected kind")
        if level is not None and page_level != level:
            raise PstError(f"corrupt .pst: the B-tree page at {ib} is on level {page_level}, not on "
                           f"level {level} below its parent")
        if cb_ent * c_ent > trailer or cb_ent < 24:
            raise PstError(f"corrupt .pst: page at {ib}: {c_ent} entries of {cb_ent} bytes do not fit")
        for i in range(c_ent):
            e = page[i * cb_ent:(i + 1) * cb_ent]
            if page_level > 0:
                _key, _bid, child = struct.unpack_from("<QQQ", e)
                self._walk(child, ptype, depth + 1, page_level - 1)
            elif ptype == 0x80:
                bid, bib = struct.unpack_from("<QQ", e)
                cb = struct.unpack_from("<H", e, 16)[0]
                inflated = struct.unpack_from("<H", e, 18)[0] if self.version == 36 else cb
                self.blocks[bid & ~1] = (bib, cb, inflated)
            else:
                nid, data, sub, parent = struct.unpack_from("<QQQI", e)
                self.nodes[nid & 0xFFFFFFFF] = Node(nid & 0xFFFFFFFF, data, sub, parent)
            if len(self.blocks) + len(self.nodes) > 50_000_000:
                raise PstError("too many entries")

    def block(self, bid: int) -> bytes:
        entry = self.blocks.get(bid & ~1)
        if entry is None:
            raise PstError(f"block {bid:#x} is not in the block tree")
        ib, cb, inflated = entry
        if cb > MAX_BLOCK:
            raise PstError(f"block {bid:#x} claims {cb} bytes")
        data = self._read(ib, cb)
        internal = bool(bid & 2)
        if self.version == 36 and inflated != cb and not internal:
            data = zlib.decompressobj().decompress(data, MAX_BLOCK)
        if self.crypt == 1 and not internal:
            data = data.translate(_DECODE)
        return data

    def data_tree(self, bid: int, depth: int = 0, total: list | None = None) -> list[bytes]:
        """The blocks of a node's data (an XBLOCK / XXBLOCK tree, or one block)."""
        total = total if total is not None else [0]
        if depth > 3:
            raise PstError("a data tree deeper than XXBLOCK")
        raw = self.block(bid)
        if not bid & 2:
            total[0] += len(raw)
            if total[0] > MAX_NODE:
                raise PstError(f"a node larger than {MAX_NODE} bytes")
            return [raw]
        btype, level, count = struct.unpack_from("<BBH", raw)
        if btype != 1 or count * 8 + 8 > len(raw):
            raise PstError(f"block {bid:#x} is no XBLOCK")
        out = []
        for i in range(count):
            child = struct.unpack_from("<Q", raw, 8 + 8 * i)[0]
            out += self.data_tree(child, depth + 1, total) if level > 1 else [self._external(child, total)]
        return out

    def _external(self, bid: int, total: list) -> bytes:
        data = self.block(bid)
        total[0] += len(data)
        if total[0] > MAX_NODE:
            raise PstError(f"a node larger than {MAX_NODE} bytes")
        return data

    def subnodes(self, bid: int, depth: int = 0) -> dict[int, tuple[int, int]]:
        """nid -> (data bid, sub bid) of a node's subnode tree."""
        if not bid:
            return {}
        if depth > 3:
            raise PstError("a subnode tree too deep")
        raw = self.block(bid)
        btype, level, count = struct.unpack_from("<BBH", raw)
        if btype != 2:
            raise PstError(f"block {bid:#x} is no subnode block")
        out = {}
        if level == 0:
            for i in range(count):
                nid, data, sub = struct.unpack_from("<QQQ", raw, 8 + 24 * i)
                out[nid & 0xFFFFFFFF] = (data, sub)
        else:
            for i in range(count):
                _nid, child = struct.unpack_from("<QQ", raw, 8 + 16 * i)
                out.update(self.subnodes(child, depth + 1))
        return out

    # --- LTP: heap-on-node, BTH, PC, TC --------------------------------------------------

    def heap(self, data_bid: int, sub_bid: int = 0) -> "_Heap":
        return _Heap(self, self.data_tree(data_bid), self.subnodes(sub_bid))

    def properties(self, data_bid: int, sub_bid: int = 0) -> dict:
        h = self.heap(data_bid, sub_bid)
        if h.client_sig != 0xBC:
            raise PstError("not a property context")
        out = {}
        for key, value in h.bth(h.user_root):
            prop_id = struct.unpack("<H", key)[0]
            ptype, hnid = struct.unpack("<HI", value)
            out[prop_id] = h.value(ptype, hnid, raw=value[2:])
        return out

    def table(self, data_bid: int, sub_bid: int = 0) -> list[dict]:
        h = self.heap(data_bid, sub_bid)
        if h.client_sig != 0x7C:
            raise PstError("not a table context")
        info = h.alloc(h.user_root)
        _btype, cols = info[0], info[1]
        ib4, ib2, ib1, ib_bm = struct.unpack_from("<HHHH", info, 2)
        _row_index, hnid_rows = struct.unpack_from("<II", info, 10)
        descs = []
        for i in range(cols):
            tag, ib, cb, ibit = struct.unpack_from("<IHBB", info, 22 + 8 * i)
            descs.append((tag, ib, cb, ibit))
        row_size = ib_bm
        if not row_size or not hnid_rows:
            return []
        blocks = h.hnid_blocks(hnid_rows)
        rows = []
        for blk in blocks:
            per = len(blk) // row_size if len(blocks) == 1 else 8176 // row_size
            for r in range(min(per, len(blk) // row_size)):
                raw = blk[r * row_size:(r + 1) * row_size]
                row = {}
                for tag, ib, cb, ibit in descs:
                    if not raw[ib1 + ibit // 8] & (1 << (7 - ibit % 8)):
                        continue                       # the cell has no value
                    ptype, pid = tag & 0xFFFF, tag >> 16
                    cell = raw[ib:ib + cb]
                    if cb == 4 and ptype not in (PT_I4, PT_R4, PT_BOOL, PT_I2):
                        row[pid] = h.value(ptype, struct.unpack("<I", cell)[0], raw=b"")
                    else:
                        row[pid] = _fixed(ptype, cell)
                rows.append(row)
                if len(rows) > 1_000_000:
                    raise PstError("a table of more than a million rows")
        return rows

    # --- messaging --------------------------------------------------------------------------

    def folders(self) -> dict[int, str]:
        """folder nid -> its path ("Inbox/Projects")."""
        names, parents = {}, {}
        for nid, node in self.nodes.items():
            if nid & 0x1F == NID_TYPE_NORMAL_FOLDER:
                try:
                    props = self.properties(node.data, node.sub)
                except (PstError, struct.error):
                    continue
                names[nid] = str(props.get(0x3001, "") or f"folder-{nid:#x}")
                parents[nid] = node.parent
        paths = {}
        for nid in names:
            parts, cur, seen = [], nid, set()
            while cur in names and cur not in seen and cur != NID_ROOT_FOLDER:
                seen.add(cur)
                parts.append(names[cur])
                cur = parents[cur]
            paths[nid] = "/".join(reversed(parts)) or names[nid]
        return paths

    def messages(self):
        """Every message: PstMessage with its properties, recipients and attachments."""
        folders = self.folders()
        for nid in sorted(self.nodes):
            if nid & 0x1F != NID_TYPE_NORMAL_MESSAGE:
                continue
            node = self.nodes[nid]
            try:
                yield self.message(nid, folders.get(node.parent, ""))
            except (PstError, struct.error, zlib.error) as exc:
                yield PstMessage(folders.get(node.parent, ""), nid, {"error": str(exc)})

    def message(self, nid: int, folder: str = "") -> PstMessage:
        node = self.nodes[nid]
        props = self.properties(node.data, node.sub)
        sub = self.subnodes(node.sub)
        msg = PstMessage(folder, nid, props)
        if NID_RECIPIENT_TABLE in sub:
            d, s = sub[NID_RECIPIENT_TABLE]
            msg.recipients = self.table(d, s)
        if NID_ATTACHMENT_TABLE in sub:
            d, s = sub[NID_ATTACHMENT_TABLE]
            for row in self.table(d, s):
                anid = row.get(0x67F2)                 # PidTagLtpRowId: the attachment's subnode
                if anid in sub:
                    ad, asub = sub[anid]
                    try:
                        msg.attachments.append(self.properties(ad, asub))
                    except PstError as exc:
                        msg.attachments.append({"error": str(exc)})
        return msg


def _fixed(ptype: int, raw: bytes):
    if ptype == PT_I2:
        return struct.unpack("<h", raw[:2])[0]
    if ptype in (PT_I4,):
        return struct.unpack("<i", raw[:4])[0]
    if ptype == PT_BOOL:
        return bool(raw[0]) if raw else False
    if ptype == PT_R4:
        return struct.unpack("<f", raw[:4])[0]
    if ptype in (PT_I8, PT_SYSTIME, PT_R8) and len(raw) >= 8:
        v = struct.unpack("<q", raw[:8])[0]
        if ptype == PT_SYSTIME:
            return filetime(v)
        return struct.unpack("<d", raw[:8])[0] if ptype == PT_R8 else v
    return raw


def filetime(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


class _Heap:
    """A heap-on-node over a node's data blocks (and its subnodes for HNIDs)."""

    def __init__(self, pst: PstFile, blocks: list[bytes], subnodes: dict):
        if not blocks or len(blocks[0]) < 12:
            raise PstError("an empty heap")
        self.pst, self.blocks, self.sub = pst, blocks, subnodes
        _ib, sig, self.client_sig, self.user_root = struct.unpack_from("<HBBI", blocks[0])
        if sig != 0xEC:
            raise PstError("not a heap-on-node")

    def alloc(self, hid: int) -> bytes:
        if hid & 0x1F:
            raise PstError(f"{hid:#x} is no heap id")
        index, block = (hid >> 5) & 0x7FF, hid >> 16
        if block >= len(self.blocks) or index == 0:
            raise PstError(f"heap id {hid:#x} outside the heap")
        raw = self.blocks[block]
        ib_map = struct.unpack_from("<H", raw)[0]
        if ib_map + 4 > len(raw):
            raise PstError("a broken heap page map")
        count = struct.unpack_from("<H", raw, ib_map)[0]
        if index > count:
            raise PstError(f"heap id {hid:#x}: only {count} allocations")
        start, end = struct.unpack_from("<HH", raw, ib_map + 4 + 2 * (index - 1))
        if not start <= end <= len(raw):
            raise PstError("a broken heap allocation")
        return raw[start:end]

    def hnid_blocks(self, hnid: int) -> list[bytes]:
        if hnid & 0x1F == 0:
            return [self.alloc(hnid)]
        if hnid not in self.sub:
            raise PstError(f"subnode {hnid:#x} is missing")
        data, _sub = self.sub[hnid]
        return self.pst.data_tree(data)

    def hnid(self, hnid: int) -> bytes:
        return b"".join(self.hnid_blocks(hnid)) if hnid else b""

    def value(self, ptype: int, hnid: int, raw: bytes):
        if ptype in (PT_I2, PT_I4, PT_R4, PT_BOOL):
            return _fixed(ptype, struct.pack("<I", hnid))
        data = self.hnid(hnid)
        if ptype == PT_UNICODE:
            return data.decode("utf-16-le", "replace")
        if ptype == PT_STRING8:
            return data.decode("cp1252", "replace")
        if ptype in (PT_I8, PT_SYSTIME, PT_R8):
            return _fixed(ptype, data)
        return data

    def bth(self, hid: int):
        """(key, value) records of a BTH."""
        head = self.alloc(hid)
        btype, cb_key, cb_ent, levels, root = struct.unpack_from("<BBBBI", head)
        if btype != 0xB5:
            raise PstError("not a BTH")
        if not root:
            return
        yield from self._bth_level(root, cb_key, cb_ent, levels, 0)

    def _bth_level(self, hid, cb_key, cb_ent, level, depth):
        if depth > MAX_DEPTH:
            raise PstError("a BTH too deep")
        raw = self.alloc(hid)
        size = cb_key + (4 if level else cb_ent)
        for i in range(len(raw) // size):
            rec = raw[i * size:(i + 1) * size]
            if level:
                yield from self._bth_level(struct.unpack_from("<I", rec, cb_key)[0], cb_key, cb_ent,
                                           level - 1, depth + 1)
            else:
                yield rec[:cb_key], rec[cb_key:]


# --- as .eml ------------------------------------------------------------------------------

def _set_boundaries(out, seed: str) -> None:
    """Give every multipart of *out* a boundary derived from *seed* (the PST
    path, folder and node id): the email package draws random ones, so the
    same message rebuilt twice gave other bytes and another SHA-256 - a
    mail project's duplicate check never matched on a second import."""
    import hashlib

    digest = hashlib.sha256(seed.encode("utf-8", "surrogateescape")).hexdigest()[:32]
    leaves = [part.as_string() for part in out.walk() if not part.is_multipart()]
    for n, part in enumerate(p for p in out.walk() if p.is_multipart()):
        boundary = f"=_axross_{digest}_{n}"
        while any(boundary in leaf for leaf in leaves):     # never a line of the content
            boundary += "x"
        part.set_boundary(boundary)


def to_eml(msg: PstMessage, source: str = "") -> bytes:
    """An RFC 5322 message rebuilt from a PST message's properties - the
    same bytes each time for the same *source* (the PST's path) and
    message."""
    from email import message_from_string, policy
    from email.message import EmailMessage
    from email.utils import format_datetime

    p = msg.props
    out = EmailMessage()
    transport = p.get(0x007D)
    kept = set()
    if isinstance(transport, str) and transport.strip():
        parsed = message_from_string(transport.strip() + "\n\n", policy=policy.compat32)
        for key, value in parsed.items():
            if key.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                continue
            out[key] = re.sub(r"\r?\n[ \t]*", " ", value).strip()   # unfolded: one line each
            kept.add(key.lower())
    if "subject" not in kept:
        out["Subject"] = msg.subject.replace("\n", " ")
    if "from" not in kept:
        name = p.get(0x0C1A) or p.get(0x0042) or ""
        addr = p.get(0x5D01) or p.get(0x0C1F) or p.get(0x0065) or ""
        out["From"] = f"{name} <{addr}>" if name and addr and "@" in addr else (addr or name or "unknown")
    if "to" not in kept and msg.recipients:
        to = [r for r in msg.recipients if r.get(0x0C15, 1) == 1]
        cc = [r for r in msg.recipients if r.get(0x0C15) == 2]

        def fmt(rs):
            return ", ".join(f"{r.get(0x3001, '')} <{r.get(0x39FE) or r.get(0x3003, '')}>" for r in rs)
        if to:
            out["To"] = fmt(to)
        if cc:
            out["Cc"] = fmt(cc)
    if "date" not in kept:
        when = p.get(0x0039) or p.get(0x0E06)
        if isinstance(when, datetime):
            out["Date"] = format_datetime(when)
    if "message-id" not in kept and isinstance(p.get(0x1035), str):
        out["Message-ID"] = p[0x1035]
    out["X-Axross-Source"] = f"pst folder {msg.folder!r}, node {msg.nid:#x}"
    text = p.get(0x1000) if isinstance(p.get(0x1000), str) else ""
    html = p.get(0x1013)
    if isinstance(html, bytes):
        from core.mail_message import decode_html_body

        html = decode_html_body(html, p.get(0x3FDE), p.get(0x3FFD))   # PR_INTERNET_CPID, PR_MESSAGE_CODEPAGE
    elif not isinstance(html, str):
        html = ""
    out.set_content(text or ("" if html else "(no text)"))
    if html:
        out.add_alternative(html, subtype="html")
    for a in msg.attachments:
        data = a.get(0x3701)
        if not isinstance(data, bytes):
            continue
        name = a.get(0x3707) or a.get(0x3704) or "attachment"
        mime = a.get(0x370E) or "application/octet-stream"
        maintype, _, subtype = str(mime).partition("/")
        out.add_attachment(data, maintype=maintype or "application", subtype=subtype or "octet-stream",
                           filename=str(name))
    _set_boundaries(out, f"{source}\0{msg.folder}\0{msg.nid}")
    return out.as_bytes()
