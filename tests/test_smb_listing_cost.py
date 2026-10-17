"""SMB listings come from the directory query itself, not one stat per entry.

smbclient's ``SMBDirEntry.stat()`` "always requires an extra SMB call"
(its own docstring): listing 1 000 files cost 1 001 round trips. The
directory query already carries attributes, size and times; only symlinks
still need a stat (their target decides is_dir / size).

mtime: smbprotocol floors FILETIME to whole microseconds; stat() used to
round a float instead. Both paths now use the same integer-microsecond
rule, so a listing and a stat of the same file agree exactly.
"""

from __future__ import annotations

import datetime as dt
import stat as st_mod
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from smbprotocol.file_info import FileAttributes  # noqa: F401 - availability probe

    from core import smb_client as SC
except ImportError:  # pragma: no cover
    SC = None

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
DIR = 0x10
READONLY = 0x01


def _entry(name, *, attrs=0x20, size=10, mtime_us=1_700_000_000_123_457, symlink=False):
    info = SimpleNamespace(
        file_attributes=attrs,
        end_of_file=size,
        last_write_time=EPOCH + dt.timedelta(microseconds=mtime_us),
    )
    calls = []

    def stat(follow_symlinks=True):
        calls.append(name)
        mode = (st_mod.S_IFDIR | 0o111) if attrs & DIR else st_mod.S_IFREG
        mode |= 0o444 if attrs & READONLY else 0o666
        return SimpleNamespace(
            st_mode=mode, st_size=size, st_mtime_ns=mtime_us * 1000 + 700,
            st_mtime=(mtime_us * 1000 + 700) / 1e9,
        )

    return SimpleNamespace(
        name=name,
        path=f"\\\\srv\\share\\d\\{name}",
        smb_info=info,
        is_symlink=lambda: symlink,
        stat=stat,
        calls=calls,
    )


@unittest.skipIf(SC is None, "smbprotocol not installed")
class SmbListingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.session = object.__new__(SC.SmbSession)
        self.session._prefix = r"\\srv\share"

    def listing(self, entries):
        # A symlink is stat-ed through smbclient.stat(entry.path, port=...)
        # (SMBDirEntry.stat() would drop the port); route it to the entry.
        by_path = {e.path: e for e in entries}

        def smb_stat(path, **kw):
            return by_path[path].stat()

        with (
            mock.patch.object(SC.smbclient, "scandir", return_value=entries),
            mock.patch.object(SC.smbclient, "stat", side_effect=smb_stat),
        ):
            return self.session.list_dir("/d")

    def test_happy_no_stat_for_regular_entries(self) -> None:
        entries = [_entry(f"f{i}") for i in range(20)] + [_entry("sub", attrs=DIR, size=0)]
        items = self.listing(entries)
        self.assertEqual(len(items), 21)
        self.assertEqual(sum(len(e.calls) for e in entries), 0)

    def test_happy_items_equal_what_stat_gives(self) -> None:
        cases = [
            _entry("plain"),
            _entry("ro", attrs=READONLY | 0x20),
            _entry("dir", attrs=DIR, size=4096),
            _entry("rodir", attrs=DIR | READONLY, size=0),
            _entry("zero-time", mtime_us=0),
        ]
        listed = {i.name: i for i in self.listing(cases)}
        for e in cases:
            with self.subTest(e.name):
                via_stat = SC.SmbSession._stat_to_item(e.name, e.stat())
                self.assertEqual(listed[e.name], via_stat)

    def test_sad_a_symlink_is_still_stat_ed(self) -> None:
        link = _entry("lnk", symlink=True)
        items = self.listing([link, _entry("x")])
        self.assertEqual(link.calls, ["lnk"])
        self.assertEqual([i.name for i in items], ["lnk", "x"])

    def test_sad_a_failing_symlink_stat_keeps_the_bare_entry(self) -> None:
        link = _entry("lnk", symlink=True)

        def boom(follow_symlinks=True):
            raise OSError("dangling")

        link.stat = boom
        (item,) = self.listing([link])
        self.assertEqual(item.name, "lnk")
        self.assertFalse(item.is_dir)

    def test_edge_mtime_rounding_is_identical_in_both_paths(self) -> None:
        # 100-ns remainder 7 (>= 5): a float round-half-even would add a
        # microsecond; both paths must floor like smbprotocol.
        e = _entry("t", mtime_us=1_234_567_890_123_456)
        (listed,) = self.listing([e])
        self.assertEqual(listed.modified, SC.SmbSession._stat_to_item("t", e.stat()).modified)
        self.assertEqual(listed.modified.microsecond, 123456)

    def test_edge_dot_entries_are_skipped(self) -> None:
        items = self.listing([_entry("."), _entry(".."), _entry("a")])
        self.assertEqual([i.name for i in items], ["a"])


if __name__ == "__main__":
    unittest.main()
