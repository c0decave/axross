"""uid / gid -> name lookups are cached.

Measured on Arch with the stock ``group: files [SUCCESS=merge] systemd``:
``grp.getgrgid`` costs ~0.56 ms because glibc asks systemd-userdb even
after a hit in /etc/group, and LocalFS called it once per directory
entry — 3.0 of 5.8 s of a 5 000-file CAS rebuild, and every listing.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import local_fs  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class NameCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        local_fs.clear_name_cache()
        self.addCleanup(local_fs.clear_name_cache)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for i in range(30):
            (self.tmp / f"f{i}").write_bytes(b"x")

    def test_happy_a_listing_resolves_each_id_once(self) -> None:
        # The cache is process-wide: a background listing left running by
        # another test may fill it between setUp's clear and this listing,
        # and then this thread looks nothing up. Count only this thread's
        # lookups; 30 entries must cost at most one each.
        me = threading.get_ident()
        mine = {"gr": 0, "pw": 0}

        def counted(key, real):
            def call(ident):
                if threading.get_ident() == me:
                    mine[key] += 1
                return real(ident)

            return call

        real_gr, real_pw = local_fs.grp.getgrgid, local_fs.pwd.getpwuid
        with (
            mock.patch.object(local_fs.grp, "getgrgid", side_effect=counted("gr", real_gr)),
            mock.patch.object(local_fs.pwd, "getpwuid", side_effect=counted("pw", real_pw)),
        ):
            items = LocalFS().list_dir(str(self.tmp))
        self.assertEqual(len(items), 30)
        self.assertLessEqual(mine["gr"], 1)
        self.assertLessEqual(mine["pw"], 1)

    def test_happy_names_are_the_real_ones(self) -> None:
        import grp
        import pwd

        item = LocalFS().stat(str(self.tmp / "f0"))
        st = os.stat(self.tmp / "f0")
        self.assertEqual(item.owner, pwd.getpwuid(st.st_uid).pw_name)
        self.assertEqual(item.group, grp.getgrgid(st.st_gid).gr_name)

    def test_sad_an_unknown_id_falls_back_to_the_number_and_is_cached_too(self) -> None:
        with mock.patch.object(local_fs.grp, "getgrgid", side_effect=KeyError) as gr:
            self.assertEqual(local_fs.group_name(424242), "424242")
            self.assertEqual(local_fs.group_name(424242), "424242")
        self.assertEqual(gr.call_count, 1)
        with mock.patch.object(local_fs.pwd, "getpwuid", side_effect=KeyError):
            self.assertEqual(local_fs.owner_name(434343), "434343")

    def test_edge_entries_expire_so_a_renamed_group_shows_up(self) -> None:
        clock = [1000.0]
        with (
            mock.patch.object(local_fs.time, "monotonic", lambda: clock[0]),
            mock.patch.object(local_fs.grp, "getgrgid") as gr,
        ):
            gr.return_value.gr_name = "old"
            self.assertEqual(local_fs.group_name(5), "old")
            gr.return_value.gr_name = "new"
            clock[0] += local_fs.NAME_CACHE_TTL - 1
            self.assertEqual(local_fs.group_name(5), "old")
            clock[0] += 2
            self.assertEqual(local_fs.group_name(5), "new")

    def test_edge_the_cache_is_bounded(self) -> None:
        with mock.patch.object(local_fs.grp, "getgrgid", side_effect=KeyError):
            for gid in range(local_fs.NAME_CACHE_MAX + 50):
                local_fs.group_name(gid)
        self.assertLessEqual(len(local_fs._group_cache), local_fs.NAME_CACHE_MAX)

    def test_iscsi_listing_uses_the_same_cache(self) -> None:
        from core import iscsi_client

        self.assertIs(iscsi_client.group_name, local_fs.group_name)
        self.assertIs(iscsi_client.owner_name, local_fs.owner_name)


if __name__ == "__main__":
    unittest.main()
