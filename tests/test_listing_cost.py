"""LocalFS.list_dir and FileItem: less work per entry, the same entries.

Measured before (100,000 entries): list_dir 3.6 s against 1.5 s for the
bare scandir + lstat; ~370 bytes per FileItem. Now: the owner and group
names come from a dict of the listing (no lock, no clock per entry), the
hidden-flag test is skipped where the platform's stat has no such field,
the timestamps are converted inline; FileItem has slots and builds its
permission string from a table.
"""

from __future__ import annotations

import dataclasses
import os
import stat
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import local_fs  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402


def _same(a: FileItem, b: FileItem) -> bool:
    """Equal - but for a link's access time: reading the link (its target)
    is an access, so two listings see two times."""
    if a.is_link:
        a, b = dataclasses.replace(a, accessed=None), dataclasses.replace(b, accessed=None)
    return a == b


def _former_permissions(mode: int) -> str:
    """FileItem.permissions_str as it was: bit by bit."""
    bits = (stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR, stat.S_IRGRP, stat.S_IWGRP,
            stat.S_IXGRP, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH)
    return "".join(c if mode & b else "-" for c, b in zip("rwxrwxrwx", bits))


@pytest.fixture
def folder(tmp_path):
    for i in range(40):
        (tmp_path / f"f{i:02d}.txt").write_bytes(b"x" * i)
    (tmp_path / "sub").mkdir()
    (tmp_path / ".hidden").write_text("h")
    os.symlink(tmp_path / "f01.txt", tmp_path / "link")
    os.utime(tmp_path / "f02.txt", (1.0e9, 1.5e9))
    return tmp_path


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_listing_holds_exactly_what_one_stat_per_entry_gives(folder):
    fs = LocalFS()
    listed = {item.name: item for item in fs.list_dir(str(folder))}
    assert set(listed) == {p.name for p in folder.iterdir()}
    for name, item in listed.items():
        # outside a listing: the shared caches, local_time(), the full hidden test
        alone = fs._stat_to_item(name, os.lstat(folder / name), full_path=str(folder / name))
        assert _same(item, alone), name
    assert listed["link"].is_link and listed["link"].link_target.endswith("f01.txt")
    assert listed["f02.txt"].modified == datetime.fromtimestamp(1.5e9)
    assert listed["f02.txt"].accessed == datetime.fromtimestamp(1.0e9)


def test_happy_permission_strings_are_the_former_ones_for_every_mode():
    for mode in range(0o10000):
        assert FileItem("x", permissions=mode).permissions_str == _former_permissions(mode)
    assert FileItem("x", permissions=-1).permissions_str == _former_permissions(-1)


def test_happy_a_file_item_has_slots_and_stays_frozen():
    item = FileItem("a.txt", size=3)
    assert not hasattr(item, "__dict__")
    with pytest.raises(AttributeError):
        item.size = 4  # type: ignore[misc]
    utc = FileItem("b", modified=datetime(2024, 1, 1, 12, tzinfo=timezone.utc))
    assert utc.modified.tzinfo is None  # aware times still become local wall clock
    assert utc.modified == datetime(2024, 1, 1, 12, tzinfo=timezone.utc).astimezone().replace(
        tzinfo=None)


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_listing_inside_a_listing_keeps_the_outer_names(folder):
    fs = LocalFS()
    inner_seen = []
    real = LocalFS._stat_to_item

    def nested(self, name, st, full_path=""):
        if name == "f05.txt" and not inner_seen:
            inner_seen.append(self.list_dir(str(folder / "sub")))
        return real(self, name, st, full_path)

    with mock.patch.object(LocalFS, "_stat_to_item", nested):
        items = fs.list_dir(str(folder))
    assert inner_seen == [[]] and len(items) == 43
    assert getattr(local_fs._listing, "names", None) is None  # nothing left behind


def test_edge_listings_on_two_threads_keep_their_own_names(folder):
    results = {}

    def run(key):
        results[key] = LocalFS().list_dir(str(folder))

    threads = [threading.Thread(target=run, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    first = sorted(results[0], key=lambda i: i.name)
    for key in range(1, 4):
        again = sorted(results[key], key=lambda i: i.name)
        assert len(again) == len(first) and all(map(_same, again, first))


def test_edge_a_stat_like_object_still_gets_the_full_hidden_test():
    st = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=1, st_mtime=0, st_atime=0,
                         st_uid=0, st_gid=0, st_flags=stat.UF_HIDDEN)
    assert LocalFS()._stat_to_item("Library", st).attr_hidden


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_time_no_datetime_holds_falls_back_to_the_epoch(folder):
    fs = LocalFS()
    st = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=1, st_mtime=1e20,
                         st_atime=-1e20, st_uid=0, st_gid=0)
    item = fs._stat_to_item("far.txt", st)
    assert item.modified == datetime.fromtimestamp(0)
    assert item.accessed == datetime.fromtimestamp(0)


def test_sad_a_listing_that_fails_leaves_no_listing_state(tmp_path):
    with pytest.raises(OSError):
        LocalFS().list_dir(str(tmp_path / "gone"))
    assert getattr(local_fs._listing, "names", None) is None


# -- regression guard (counted) ---------------------------------------------------------------


def test_perf_happy_one_shared_cache_lookup_per_owner_per_listing(folder):
    calls = []
    real_owner, real_group = local_fs.owner_name, local_fs.group_name
    with mock.patch.object(local_fs, "owner_name", lambda u: calls.append(u) or real_owner(u)), \
            mock.patch.object(local_fs, "group_name", lambda g: calls.append(g) or real_group(g)):
        LocalFS().list_dir(str(folder))
    assert len(calls) <= 4  # one uid and one gid here (at most two of each)
