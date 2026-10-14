"""RamFS keeps its used size as a running counter.

Measured before: every ``write()`` and every commit summed the size of
every entry in the tree, so writing n files cost O(n^2) — 1 000 files
0.06 s, 4 000 files 1.10 s. The counter must always equal that sum.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ram_fs import RamFsCapacityError, RamFsSession  # noqa: E402


def _summed(s: RamFsSession) -> int:
    return sum(len(e.data) for e in s._tree.values() if not e.is_dir)


class _CountingTree(dict):
    scans = 0

    def values(self):
        type(self).scans += 1
        return super().values()

    def items(self):
        type(self).scans += 1
        return super().items()


def _write(s: RamFsSession, path: str, data: bytes, append: bool = False) -> None:
    with s.open_write(path, append=append) as f:
        f.write(data)


class SizeCounterTest(unittest.TestCase):
    def test_happy_counter_equals_the_sum_after_every_operation(self) -> None:
        s = RamFsSession(max_bytes=10_000)
        steps = [
            lambda: s.mkdir("/a/b", parents=True),
            lambda: _write(s, "/a/x", b"1" * 100),
            lambda: _write(s, "/a/b/y", b"2" * 300),
            lambda: _write(s, "/a/x", b"3" * 40),  # overwrite smaller
            lambda: _write(s, "/a/x", b"4" * 500),  # overwrite larger
            lambda: _write(s, "/a/x", b"5" * 10, append=True),
            lambda: s.copy("/a/x", "/a/b/z"),
            lambda: s.rename("/a/b", "/c"),
            lambda: s.remove("/a/x"),
            lambda: s.remove("/c", recursive=True),
            lambda: _write(s, "/top", b""),
        ]
        for i, step in enumerate(steps):
            step()
            with self.subTest(step=i):
                self.assertEqual(s.size_bytes, _summed(s))
        s.disconnect()
        self.assertEqual(s.size_bytes, 0)

    def test_happy_a_write_does_not_scan_the_tree(self) -> None:
        s = RamFsSession()
        for i in range(50):
            _write(s, f"/f{i}", b"x" * 10)
        s._tree = _CountingTree(s._tree)
        _CountingTree.scans = 0
        _write(s, "/new", b"y" * 1000)
        self.assertEqual(_CountingTree.scans, 0)
        self.assertEqual(s.size_bytes, 50 * 10 + 1000)

    def test_sad_the_cap_is_still_enforced(self) -> None:
        s = RamFsSession(max_bytes=1000)
        _write(s, "/a", b"x" * 600)
        with self.assertRaises(RamFsCapacityError):
            _write(s, "/b", b"x" * 600)
        self.assertFalse(s.exists("/b"))
        self.assertEqual(s.size_bytes, 600)
        s.remove("/a")
        _write(s, "/b", b"x" * 600)  # room again after the remove
        self.assertEqual(s.size_bytes, 600)

    def test_sad_a_refused_commit_leaves_the_counter_alone(self) -> None:
        s = RamFsSession(max_bytes=10_000)
        s.mkdir("/d")
        w = s.open_write("/e/f")  # parent auto-created
        s.remove("/e", recursive=True)
        w.write(b"z" * 50)
        with self.assertRaises(OSError):
            w.close()  # parent vanished
        self.assertEqual(s.size_bytes, 0)

    def test_edge_overwrite_at_the_cap_and_a_discarded_writer(self) -> None:
        s = RamFsSession(max_bytes=100)
        _write(s, "/a", b"x" * 100)
        _write(s, "/a", b"y" * 100)  # same size: no growth
        with self.assertRaises(RuntimeError):
            with s.open_write("/a") as f:
                f.write(b"z" * 10)
                raise RuntimeError("abort")
        self.assertEqual(s.open_read("/a").read(), b"y" * 100)
        self.assertEqual(s.size_bytes, 100)


if __name__ == "__main__":
    unittest.main()
