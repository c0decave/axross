"""Writes MS-CFB (version 3, 512-byte sectors) compound files for tests:
a tree of storages and streams, small streams in the mini stream, the rest
in regular sectors. Written from the specification, independent of
core.cfb, so the reader is checked against another implementation.
"""

from __future__ import annotations

import struct

END, FREE, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
CUTOFF = 4096


def build(tree: dict) -> bytes:
    """*tree*: name -> bytes (a stream) or dict (a storage)."""
    entries = [{"name": "Root Entry", "kind": 5, "children": [], "data": b""}]

    def add(node: dict, parent: int) -> None:
        for name, value in node.items():
            idx = len(entries)
            if isinstance(value, dict):
                entries.append({"name": name, "kind": 1, "children": [], "data": b""})
                entries[parent]["children"].append(idx)
                add(value, idx)
            else:
                entries.append({"name": name, "kind": 2, "children": [], "data": value})
                entries[parent]["children"].append(idx)
    add(tree, 0)

    # mini stream and regular streams
    mini, minifat = bytearray(), []
    big_streams = []
    for e in entries[1:]:
        if e["kind"] != 2:
            continue
        if len(e["data"]) < CUTOFF:
            n = (len(e["data"]) + 63) // 64
            start = len(minifat)
            e["start"] = start if n else END
            for i in range(n):
                minifat.append(start + i + 1 if i < n - 1 else END)
            mini += e["data"] + b"\0" * (n * 64 - len(e["data"]))
        else:
            big_streams.append(e)

    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes) -> int:
        if not data:
            return END
        n = (len(data) + 511) // 512
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * 512:(i + 1) * 512].ljust(512, b"\0"))
            fat.append(start + i + 1 if i < n - 1 else END)
        return start

    for e in big_streams:
        e["start"] = place(e["data"])
    entries[0]["start"] = place(bytes(mini))
    entries[0]["size"] = len(mini)
    minifat_raw = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_raw += struct.pack("<I", FREE) * (-len(minifat) % 128)
    first_minifat = place(minifat_raw) if minifat else END

    # directory: each storage's children as a right-leaning chain (a valid tree)
    for e in entries:
        e["left"] = e["right"] = e["child"] = NOSTREAM
    for e in entries:
        kids = e["children"]
        if kids:
            e["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b
    raw_dir = bytearray()
    for e in entries:
        name = e["name"].encode("utf-16-le") + b"\0\0"
        rec = bytearray(128)
        rec[:len(name)] = name
        struct.pack_into("<HBB", rec, 0x40, len(name), e["kind"], 1)
        struct.pack_into("<III", rec, 0x44, e["left"], e["right"], e["child"])
        size = e.get("size", len(e["data"]))
        start = e.get("start", END) if e["kind"] != 1 else 0
        struct.pack_into("<IQ", rec, 0x74, start, size)
        raw_dir += rec
    raw_dir += b"\0" * (-len(raw_dir) % 512)
    first_dir = place(bytes(raw_dir))

    # FAT sectors themselves (their entries are FATSECT)
    n_fat = 1
    while (len(fat) + n_fat) > n_fat * 128:
        n_fat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * n_fat
    fat += [FREE] * (n_fat * 128 - len(fat))
    for i in range(n_fat):
        sectors.append(b"".join(struct.pack("<I", v) for v in fat[i * 128:(i + 1) * 128]))
    assert n_fat <= 109

    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, n_fat)
    struct.pack_into("<I", header, 0x30, first_dir)
    struct.pack_into("<I", header, 0x38, CUTOFF)
    struct.pack_into("<II", header, 0x3C, first_minifat, (len(minifat_raw) // 512) if minifat else 0)
    struct.pack_into("<II", header, 0x44, END, 0)
    difat = [fat_start + i for i in range(n_fat)] + [FREE] * (109 - n_fat)
    struct.pack_into("<109I", header, 0x4C, *difat)
    return bytes(header) + b"".join(sectors)


def unicode(text: str) -> bytes:
    return text.encode("utf-16-le")


def msg_file(subject: str, sender: str, sender_addr: str, body: str, headers: str = "",
             recipients: list[tuple[str, str, int]] = (), attachments: list[tuple[str, bytes]] = ()) -> bytes:
    """A minimal Outlook .msg with the properties core.mail_message reads."""
    tree = {
        "__substg1.0_0037001F": unicode(subject),
        "__substg1.0_0C1A001F": unicode(sender),
        "__substg1.0_5D01001F": unicode(sender_addr),
        "__substg1.0_1000001F": unicode(body),
        "__properties_version1.0": b"\0" * 32,
    }
    if headers:
        tree["__substg1.0_007D001F"] = unicode(headers)
    for i, (name, addr, rtype) in enumerate(recipients):
        props = b"\0" * 8 + struct.pack("<IIQ", (0x0C15 << 16) | 0x0003, 0, rtype)
        tree[f"__recip_version1.0_#{i:08X}"] = {
            "__substg1.0_3001001F": unicode(name), "__substg1.0_39FE001F": unicode(addr),
            "__properties_version1.0": props}
    for i, (name, data) in enumerate(attachments):
        tree[f"__attach_version1.0_#{i:08X}"] = {
            "__substg1.0_3707001F": unicode(name), "__substg1.0_37010102": data,
            "__properties_version1.0": b"\0" * 8}
    return build(tree)
