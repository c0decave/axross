"""A reader for Microsoft's Compound File Binary format (MS-CFB, "OLE2"):
the container of Outlook .msg files (and old Office documents).

Standard library only, read-only, bounded: the file size, every sector
chain (a loop or a chain longer than the file is refused), the number of
directory entries and each stream's size are checked before anything is
allocated, so a hostile file can neither loop nor exhaust memory.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
#: Largest compound file read (a .msg with attachments).
MAX_FILE = 256 * 1024 * 1024
MAX_ENTRIES = 100_000

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
STORAGE, STREAM, ROOT = 1, 2, 5


class CfbError(ValueError):
    """Not a compound file, or a broken one."""


@dataclass
class Entry:
    name: str
    kind: int
    start: int
    size: int
    left: int
    right: int
    child: int
    children: dict[str, "Entry"] = field(default_factory=dict)


class CompoundFile:
    def __init__(self, data: bytes):
        if len(data) > MAX_FILE:
            raise CfbError(f"larger than {MAX_FILE} bytes")
        if len(data) < 512 or data[:8] != MAGIC:
            raise CfbError("not a compound file")
        self.data = data
        (major,) = struct.unpack_from("<H", data, 0x1A)
        shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
        if (major, shift) not in ((3, 9), (4, 12)) or mini_shift != 6:
            raise CfbError(f"unsupported version {major} / sector shift {shift}")
        self.sector = 1 << shift
        self.mini_sector = 1 << mini_shift
        n_fat, first_dir = struct.unpack_from("<II", data, 0x2C)
        self.cutoff, first_minifat, n_minifat, first_difat, n_difat = struct.unpack_from("<IIIII", data, 0x38)
        # the header takes the first sector (512 bytes, or 4096 in version 4)
        self.n_sectors = max(0, (len(data) - 1) // self.sector)
        if n_fat > self.n_sectors or n_minifat > self.n_sectors or n_difat > self.n_sectors:
            raise CfbError("sector counts larger than the file")
        fat_sectors = list(struct.unpack_from("<109I", data, 0x4C))
        sec, seen = first_difat, set()
        per = self.sector // 4 - 1
        for _ in range(n_difat):
            if sec in (ENDOFCHAIN, FREESECT) or sec in seen:
                break
            seen.add(sec)
            block = self._sector(sec)
            fat_sectors += list(struct.unpack_from(f"<{per}I", block))
            (sec,) = struct.unpack_from("<I", block, per * 4)
        fat_sectors = [s for s in fat_sectors[:n_fat] if s not in (FREESECT, ENDOFCHAIN)]
        self.fat: list[int] = []
        for s in fat_sectors:
            self.fat += struct.unpack(f"<{self.sector // 4}I", self._sector(s))
        minifat_raw = self._chain_bytes(first_minifat, limit=n_minifat * self.sector) if n_minifat else b""
        self.minifat = list(struct.unpack(f"<{len(minifat_raw) // 4}I", minifat_raw[:len(minifat_raw) // 4 * 4]))
        dir_raw = self._chain_bytes(first_dir, limit=MAX_ENTRIES * 128)
        self.entries: list[Entry] = []
        for off in range(0, len(dir_raw) - 127, 128):
            raw = dir_raw[off:off + 128]
            (name_len,) = struct.unpack_from("<H", raw, 0x40)
            name = raw[:max(0, min(name_len, 64) - 2)].decode("utf-16-le", "replace")
            kind = raw[0x42]
            left, right, child = struct.unpack_from("<III", raw, 0x44)
            start, size = struct.unpack_from("<IQ", raw, 0x74)
            if major == 3:
                size &= 0xFFFFFFFF
            self.entries.append(Entry(name, kind, start, size, left, right, child))
        if not self.entries or self.entries[0].kind != ROOT:
            raise CfbError("no root entry")
        root = self.entries[0]
        self.ministream = self._chain_bytes(root.start, limit=root.size) if root.size else b""
        self._link(root, set())
        self.root = root

    # --- sectors ---------------------------------------------------------------

    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.sector
        if n >= FATSECT or off + self.sector > len(self.data) + self.sector:
            raise CfbError(f"sector {n} outside the file")
        block = self.data[off:off + self.sector]
        return block + b"\0" * (self.sector - len(block))

    def _chain(self, start: int, table: list[int], limit_items: int) -> list[int]:
        out, seen, n = [], set(), start
        while n not in (ENDOFCHAIN, FREESECT):
            if n in seen or n >= len(table) and table is not self.fat or len(out) > limit_items:
                raise CfbError("a broken or looping sector chain")
            seen.add(n)
            out.append(n)
            if n >= len(table):
                raise CfbError("a sector chain leaves the allocation table")
            n = table[n]
        return out

    def _chain_bytes(self, start: int, limit: int) -> bytes:
        if start in (ENDOFCHAIN, FREESECT):
            return b""
        sectors = self._chain(start, self.fat, limit // self.sector + 2)
        return b"".join(self._sector(s) for s in sectors)[:limit] if limit else b""

    def _link(self, storage: Entry, seen: set[int]) -> None:
        stack = [storage.child]
        while stack:
            i = stack.pop()
            if i == NOSTREAM:
                continue
            if i in seen or i >= len(self.entries):
                raise CfbError("a broken directory tree")
            seen.add(i)
            e = self.entries[i]
            storage.children[e.name] = e
            stack += [e.left, e.right]
            if e.kind == STORAGE:
                self._link(e, seen)

    # --- reading ---------------------------------------------------------------

    def read(self, entry: Entry, limit: int = MAX_FILE) -> bytes:
        if entry.kind != STREAM:
            raise CfbError(f"{entry.name!r} is not a stream")
        size = min(entry.size, limit)
        if entry.size > len(self.data) * 2 + 4096:
            raise CfbError(f"{entry.name!r} claims more bytes than the file has")
        if entry.size < self.cutoff:
            sectors = self._chain(entry.start, self.minifat, size // self.mini_sector + 2)
            out = b"".join(self.ministream[s * 64:(s + 1) * 64] for s in sectors)
            return out[:size]
        return self._chain_bytes(entry.start, size)

    def stream(self, path: str, limit: int = MAX_FILE) -> bytes | None:
        node = self.root
        for part in path.split("/"):
            node = node.children.get(part)
            if node is None:
                return None
        return self.read(node, limit) if node.kind == STREAM else None
