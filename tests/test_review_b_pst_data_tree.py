"""Review B, item 9: a crafted .pst of 3-4 KB hung the import with memory
growing without end. Its node's data tree was XBLOCKs whose entries all
point at the next XBLOCK and at last at a zero-length block: count**4 block
reads, each zero-length leaf counted as 0 bytes against the node's limit.
Now every block a data or subnode tree reads counts, a node may refer to
a bounded number of blocks, and an internal block is read once per tree.
"""

from __future__ import annotations

import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import pst as P  # noqa: E402

LIMIT_S = 20.0


def _fanout(path: Path, count: int, *, flat: bool = False) -> Path:
    """The review's file: one folder node whose data is XBLOCK -> XBLOCK ->
    XBLOCK -> XBLOCK -> one zero-length block, every entry the same
    (*flat*: one XBLOCK whose entries all name the zero-length block)."""
    B0, B1, B2, C, Z = 0x6, 0xA, 0xE, 0x12, 0x4

    def blk(level, kid):
        return (struct.pack("<BBH", 1, level, count) + b"\0" * 4
                + struct.pack(f"<{count}Q", *([kid] * count)))

    blocks = {B0: blk(2, B1), B1: blk(2, B2), B2: blk(2, C), C: blk(1, Z), Z: b""}
    if flat:
        blocks = {B0: blk(1, Z), Z: b""}
    data = bytearray(2048)
    data[0:4] = b"!BDN"
    struct.pack_into("<H", data, 10, 23)
    data[513] = 0
    offs = {}
    for bid, raw in blocks.items():
        offs[bid] = len(data)
        data += raw
    page = bytearray(512)
    for i, bid in enumerate(blocks):
        struct.pack_into("<QQHH", page, i * 24, bid, offs[bid], len(blocks[bid]), 1)
    struct.pack_into("<BBBB", page, 488, len(blocks), 20, 24, 0)
    page[496] = 0x80
    data[1024:1536] = page
    page = bytearray(512)
    struct.pack_into("<QQQI", page, 0, 0x22, B0, 0, 0x122)
    struct.pack_into("<BBBB", page, 488, 1, 15, 32, 0)
    page[496] = 0x81
    data[1536:2048] = page
    struct.pack_into("<QQQQ", data, 216, 0, 1536, 0, 1024)
    path.write_bytes(bytes(data))
    return path


def _bounded(fn):
    out: list = []

    def run():
        try:
            out.append(fn())
        except Exception as exc:  # noqa: BLE001 - the test looks at it
            out.append(exc)
    t = threading.Thread(target=run, daemon=True)
    begun = time.monotonic()
    t.start()
    t.join(LIMIT_S)
    assert not t.is_alive(), f"still reading after {LIMIT_S} s"
    return out[0], time.monotonic() - begun


@pytest.mark.parametrize("count", [60, 120])
def test_sad_a_fan_out_of_xblocks_is_corrupt_not_endless(tmp_path, count):
    path = _fanout(tmp_path / "f.pst", count)
    assert path.stat().st_size < 8192
    pst = P.PstFile(path)
    result, took = _bounded(lambda: pst.data_tree(0x6))
    assert isinstance(result, P.PstError), result
    assert took < 5


def test_sad_the_folder_list_reports_it(tmp_path):
    pst = P.PstFile(_fanout(tmp_path / "f.pst", 60))
    _result, took = _bounded(pst.folders)
    assert took < 5


def test_sad_zero_length_blocks_count_against_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "MAX_NODE_BLOCKS", 50)
    pst = P.PstFile(_fanout(tmp_path / "f.pst", 100, flat=True))
    result, _took = _bounded(lambda: pst.data_tree(0x6))
    assert isinstance(result, P.PstError) and "blocks" in str(result)


def test_happy_a_flat_xblock_within_the_limit_is_read(tmp_path):
    pst = P.PstFile(_fanout(tmp_path / "f.pst", 100, flat=True))
    assert pst.data_tree(0x6) == [b""] * 100
