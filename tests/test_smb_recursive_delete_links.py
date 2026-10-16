"""SMB recursive delete removes links, never what they point at.

list_dir resolved a symlink / junction entry with smbclient.stat (which
follows it) and returned it as a plain directory, so _rmdir_recursive
descended into the link and deleted the TARGET's contents - possibly a
tree outside the one being deleted - before removing the link. A
remove(path, recursive=True) on a link to a directory did the same at the
top. And a server whose every directory holds another one (a junction
loop) drove the recursion into RecursionError. Found by
tests/test_fuzz_smb.py (the RecursionError; the link case by reading the
path it took).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from smb_fake_client import (  # noqa: E402
    DirEntry,
    FakeSmbClient,
    StatResult,
    make_session,
    smb_info,
)

from core import smb_client  # noqa: E402

DIR = 0x10
SUB = "\\\\h\\s\\sub"


@pytest.fixture
def smb(monkeypatch):
    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    return fake, make_session(fake)


def test_happy_tree_is_removed_depth_first(smb):
    fake, s = smb
    fake.listings = {
        SUB: [DirEntry("a.txt"), DirEntry("d", smb_info(attrs=DIR, size=0))],
        SUB + "\\d": [DirEntry("b.txt")],
    }
    s.remove("/sub", recursive=True)
    assert [c for c in fake.calls if c[0] != "scandir"] == [
        ("remove", SUB + "\\a.txt"),
        ("remove", SUB + "\\d\\b.txt"),
        ("rmdir", SUB + "\\d"),
        ("rmdir", SUB),
    ]


def test_sad_link_to_a_directory_is_removed_not_descended(smb):
    fake, s = smb
    fake.stat_value = StatResult(0o040755, 0, 1_704_164_645_000_000_000)  # the target: a dir
    fake.listings = {
        SUB: [DirEntry("link", symlink=True)],
        SUB + "\\link": [DirEntry("precious.txt")],  # what the link points at
    }
    s.remove("/sub", recursive=True)
    assert ("scandir", SUB + "\\link") not in fake.calls
    assert not any("precious" in unc for _op, unc in fake.calls)
    assert ("rmdir", SUB + "\\link") in fake.calls
    assert fake.calls[-1] == ("rmdir", SUB)


def test_edge_link_to_a_file_is_removed(smb):
    fake, s = smb
    fake.stat_value = StatResult(0o100644, 5, 1_704_164_645_000_000_000)
    fake.listings = {SUB: [DirEntry("flink", symlink=True)]}
    s.remove("/sub", recursive=True)
    assert ("remove", SUB + "\\flink") in fake.calls


def test_edge_top_level_link_goes_as_the_link(smb):
    fake, s = smb
    fake.links = {SUB}
    fake.listings = {SUB: [DirEntry("precious.txt")]}
    s.remove("/sub", recursive=True)
    assert fake.calls == [("rmdir", SUB)]


def test_edge_endless_tree_fails_instead_of_recursing_forever(smb):
    fake, s = smb
    fake.entries = [DirEntry("d", smb_info(attrs=DIR, size=0))]  # every directory holds "d"
    with pytest.raises(OSError, match="deeper than"):
        s.remove("/sub", recursive=True)


def test_happy_listing_marks_links(smb):
    fake, s = smb
    fake.entries = [DirEntry("link", symlink=True), DirEntry("a.txt")]
    items = {i.name: i for i in s.list_dir("/")}
    assert items["link"].is_link and not items["a.txt"].is_link


def test_sad_directory_with_an_out_of_range_time_is_not_a_link(smb):
    # A FILETIME past year 9999 arrives as a naive datetime.max
    # placeholder; the listing then falls back to stat(). That fallback
    # is no reason to call the entry a link: a recursive delete would
    # try a bare rmdir on a full directory instead of descending.
    from datetime import datetime

    fake, s = smb
    fake.stat_value = StatResult(0o040755, 0, 1_704_164_645_000_000_000)
    fake.entries = [DirEntry("old", smb_info(written=datetime.max, attrs=DIR, size=0))]
    (item,) = s.list_dir("/")
    assert item.is_dir and not item.is_link


def test_edge_a_link_whose_stat_fails_is_still_a_link(smb):
    fake, s = smb

    def dangling(unc, **_kw):
        raise OSError(f"{unc}: target not found")

    fake.stat = dangling
    fake.entries = [DirEntry("gone", symlink=True)]
    (item,) = s.list_dir("/")
    assert item.is_link
