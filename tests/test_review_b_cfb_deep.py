"""Review B, item 15: a .msg whose storages nest a few thousand deep made
core.cfb's directory walk recurse until RecursionError (no CfbError: the
caller's handler of a damaged file did not see it). The walk is iterative
now, and a damaged tree still is a CfbError."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cfb  # noqa: E402
from tests import cfb_writer  # noqa: E402

FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _nested(n: int, *, loop: bool = False) -> bytes:
    """A compound file of *n* directory entries: the root, then storages
    each the only child of the one before (*loop*: the last one's child is
    the first storage again)."""
    dirs_sectors = (n + 3) // 4
    total = dirs_sectors + 8
    fat_sectors = (total + 127) // 128
    fat = [FATSECT] * fat_sectors
    first_dir = fat_sectors
    for i in range(dirs_sectors):
        fat.append(first_dir + i + 1 if i < dirs_sectors - 1 else ENDOFCHAIN)
    fat += [FREESECT] * (fat_sectors * 128 - len(fat))
    hdr = bytearray(512)
    hdr[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", hdr, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<II", hdr, 0x2C, fat_sectors, first_dir)
    struct.pack_into("<IIIII", hdr, 0x38, 4096, ENDOFCHAIN, 0, ENDOFCHAIN, 0)
    struct.pack_into("<109I", hdr, 0x4C, *(list(range(fat_sectors)) + [FREESECT] * (109 - fat_sectors)))
    body = b"".join(struct.pack("<128I", *fat[k * 128:(k + 1) * 128]) for k in range(fat_sectors))
    dirs = bytearray()
    for i in range(dirs_sectors * 4):
        e = bytearray(128)
        if i < n:
            name = ("Root Entry" if i == 0 else f"s{i}").encode("utf-16-le") + b"\0\0"
            e[:len(name)] = name
            struct.pack_into("<H", e, 0x40, len(name))
            e[0x42] = 5 if i == 0 else 1
            child = i + 1 if i < n - 1 else (1 if loop else NOSTREAM)
            struct.pack_into("<III", e, 0x44, NOSTREAM, NOSTREAM, child)
            struct.pack_into("<IQ", e, 0x74, ENDOFCHAIN, 0)
        dirs += e
    return bytes(hdr) + body + bytes(dirs)


def test_sad_storages_nested_thousands_deep_are_no_recursion_error():
    try:
        doc = cfb.CompoundFile(_nested(3000))
    except cfb.CfbError:
        return  # refused as damaged: fine
    deepest = doc.root
    depth = 0
    while deepest.children:
        deepest = next(iter(deepest.children.values()))
        depth += 1
    assert depth == 2999


def test_sad_a_loop_of_storages_is_a_broken_tree():
    with pytest.raises(cfb.CfbError):
        cfb.CompoundFile(_nested(50, loop=True))


def test_sad_parse_msg_reports_it_as_a_damaged_message():
    from core import mail_message

    try:
        mail_message.parse_msg(_nested(3000), "x.msg")
    except RecursionError:  # pragma: no cover - the bug
        pytest.fail("RecursionError out of parse_msg")
    except Exception:  # noqa: BLE001 - "not a message" is the right answer
        pass


def test_happy_a_normal_tree_still_reads():
    data = cfb_writer.build({"a": b"hello", "sub": {"b": b"x" * 5000, "c": {"d": b"deep"}}})
    doc = cfb.CompoundFile(data)
    sub = doc.root.children["sub"]
    assert doc.read(doc.root.children["a"]) == b"hello"
    assert doc.read(sub.children["b"]) == b"x" * 5000
    assert doc.read(sub.children["c"].children["d"]) == b"deep"
