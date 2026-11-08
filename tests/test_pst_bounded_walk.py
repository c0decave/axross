"""core.pst refuses a crafted B-tree instead of walking it for ever.

What was wrong: ``PstFile._walk`` bounded only the depth (16) and the number
of stored entries, not the pages it visits, and never checked that a child
page is one level below its parent. A 9 KB .pst of 15 inner pages whose 20
entries all point at the next page means 20**15 page reads: the import of
such a file never ended (and could not be cancelled). Now every page is read
at most once, never more pages than the file can hold, each child exactly
one level lower - else a clear "corrupt .pst" error.
"""

from __future__ import annotations

import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import pst as P  # noqa: E402

LIMIT_S = 20.0


def crafted(path: Path, levels: int = 15, fanout: int = 20, *, level_of=lambda lv, levels: levels - lv,
            child_of=lambda lv, i: lv + 1) -> Path:
    """A Unicode .pst header and *levels* inner block-tree pages, each with
    *fanout* entries pointing at page child_of(level, entry), then an empty leaf."""
    head = bytearray(1024)
    head[:4] = b"!BDN"
    struct.pack_into("<H", head, 10, 23)
    struct.pack_into("<QQQQ", head, 216, 0, 1024, 0, 1024)
    pages = b""
    for lv in range(levels + 1):
        page = bytearray(512)
        if lv < levels:
            for i in range(fanout):
                struct.pack_into("<QQQ", page, i * 24, i, i, 1024 + 512 * child_of(lv, i))
            struct.pack_into("<BBBB", page, 488, fanout, 20, 24, level_of(lv, levels))
        else:
            struct.pack_into("<BBBB", page, 488, 0, 20, 24, 0)
        page[496] = 0x80
        pages += bytes(page)
    path.write_bytes(bytes(head) + pages)
    return path


def valid_tree(path: Path) -> Path:
    """A root on level 1 with three children, each its own empty leaf."""
    head = bytearray(1024)
    head[:4] = b"!BDN"
    struct.pack_into("<H", head, 10, 23)
    struct.pack_into("<QQQQ", head, 216, 0, 1024 + 512 * 4, 0, 1024)
    root = bytearray(512)
    for i in range(3):
        struct.pack_into("<QQQ", root, i * 24, i, i, 1024 + 512 * (i + 1))
    struct.pack_into("<BBBB", root, 488, 3, 20, 24, 1)
    root[496] = 0x80
    pages = bytes(root)
    for _ in range(3):
        leaf = bytearray(512)
        struct.pack_into("<BBBB", leaf, 488, 0, 20, 24, 0)
        leaf[496] = 0x80
        pages += bytes(leaf)
    nbt = bytearray(512)
    struct.pack_into("<BBBB", nbt, 488, 0, 20, 24, 0)
    nbt[496] = 0x81
    path.write_bytes(bytes(head) + pages + bytes(nbt))
    return path


def open_bounded(path: Path, monkeypatch):
    reads = [0]
    real = P.PstFile._read

    def counting(self, offset, n):
        reads[0] += 1
        return real(self, offset, n)
    monkeypatch.setattr(P.PstFile, "_read", counting)
    out: list = []

    def run():
        try:
            out.append(P.PstFile(path))
        except Exception as exc:  # noqa: BLE001 - the test looks at it
            out.append(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(LIMIT_S)
    assert not t.is_alive(), f"PstFile() still walking after {LIMIT_S} s ({reads[0]} page reads)"
    return out[0], reads[0]


def test_sad_a_fan_out_of_pages_pointing_at_one_page_is_corrupt(tmp_path, monkeypatch):
    # correct levels (15, 14, ... 0), but every entry of a page points at the same next page
    result, reads = open_bounded(crafted(tmp_path / "fan.pst"), monkeypatch)
    assert isinstance(result, P.PstError) and "corrupt" in str(result)
    assert "reached twice" in str(result)
    assert reads <= 20


def test_sad_children_on_the_same_level_as_their_parent_are_corrupt(tmp_path, monkeypatch):
    # distinct pages one level apart: opened, each page read once
    result, reads = open_bounded(valid_tree(tmp_path / "ok.pst"), monkeypatch)
    assert isinstance(result, P.PstFile), result
    assert reads == 1 + 5          # the header, then each page once
    result.close()
    # the review's file: every inner page says level 1
    path = crafted(tmp_path / "flat.pst", level_of=lambda lv, levels: 1)
    result, reads = open_bounded(path, monkeypatch)
    assert isinstance(result, P.PstError) and "corrupt" in str(result) and "level" in str(result)
    assert reads <= 20


def test_sad_a_page_pointing_at_itself_is_corrupt(tmp_path, monkeypatch):
    path = crafted(tmp_path / "self.pst", levels=1, fanout=3, level_of=lambda lv, levels: 1,
                   child_of=lambda lv, i: lv)
    result, _reads = open_bounded(path, monkeypatch)
    assert isinstance(result, P.PstError) and "corrupt" in str(result)


