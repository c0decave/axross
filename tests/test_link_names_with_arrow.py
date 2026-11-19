"""Symlinks whose name holds " -> " (review round 2).

``ls -l`` and ``rsync --list-only`` print a link as ``name -> target``
with nothing to tell where the name ends when the name itself holds
`` -> ``. SCP, Telnet without ``ls -b`` (BusyBox), RSH, ADB and rsync cut
at the first (or the last) arrow: the link ``a -> x`` was listed as
``a``, and a delete of the listed entry removed the OTHER file ``a``.
The link's size is the length of its target, which settles the cut; an
entry it cannot settle is listed under its whole text, a name that hits
no other file.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adb_client import AdbSession  # noqa: E402
from core.rsh_client import RshSession  # noqa: E402
from core.telnet_client import _parse_ls_la, split_link_field  # noqa: E402


@pytest.fixture
def arrow_tree(tmp_path):
    (tmp_path / "a").write_text("KEEP ME")
    os.symlink("b -> c", tmp_path / "a -> x")
    os.symlink("plain", tmp_path / "l")
    return tmp_path


def _gnu_ls(folder, *flags: str) -> str:
    env = {"LC_ALL": "C", "QUOTING_STYLE": "literal", "TZ": "UTC0", "PATH": os.environ["PATH"]}
    return subprocess.run(
        ["ls", "-la", *flags, f"{folder}/"], capture_output=True, text=True, env=env, check=True
    ).stdout


def _links(items) -> dict:
    return {i.name: i.link_target for i in items if i.is_link}


def test_sad_shared_parser_names_the_link_with_an_arrow(arrow_tree) -> None:
    """Telnet (BusyBox, no ls -b) and SCP: "a -> x" was listed as "a"."""
    assert _links(_parse_ls_la(_gnu_ls(arrow_tree))) == {"a -> x": "b -> c", "l": "plain"}


def test_sad_scp_listing_names_the_link_with_an_arrow(arrow_tree) -> None:
    from core.scp_client import SCPSession, _Capabilities as ScpCaps

    s = SCPSession.__new__(SCPSession)
    s._caps = ScpCaps()
    s._exec = lambda cmd, timeout=None, **_kw: _gnu_ls(arrow_tree)
    assert _links(s.list_dir(str(arrow_tree))) == {"a -> x": "b -> c", "l": "plain"}


def test_sad_rsh_listing_names_the_link_with_an_arrow(arrow_tree) -> None:
    s = RshSession.__new__(RshSession)
    out = _gnu_ls(arrow_tree).encode()
    with mock.patch.object(RshSession, "_run_remote", return_value=out):
        names = sorted(i.name for i in s.list_dir(str(arrow_tree)) if i.is_link)
    assert names == ["a -> x", "l"]


def test_sad_adb_listing_names_the_link_with_an_arrow(arrow_tree) -> None:
    s = AdbSession.__new__(AdbSession)
    out = _gnu_ls(arrow_tree, "--time-style=+%Y-%m-%d %H:%M")
    s._shell = lambda cmd: out
    assert _links(s.list_dir("/sdcard/x")) == {"a -> x": "b -> c", "l": "plain"}


def test_sad_rsync_listing_names_the_link_with_an_arrow(monkeypatch) -> None:
    from core import rsync_client as RC

    listing = (
        "drwxr-xr-x          4,096 2026/01/01 12:00:00 .\n"
        "-rw-r--r--              7 2026/01/01 12:00:00 x\n"
        "lrwxrwxrwx              1 2026/01/01 12:00:00 a -> b -> c\n"
        "lrwxrwxrwx              6 2026/01/01 12:00:00 d -> e -> f\n"
    )
    monkeypatch.setattr(
        RC.subprocess, "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=listing, stderr=""),
    )
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    s = RC.RsyncSession("h", module="m")
    assert _links(s.list_dir("/")) == {"a -> b": "c", "d": "e -> f"}


def test_edge_split_link_field() -> None:
    assert split_link_field("a -> b", None) == ("a", "b")
    assert split_link_field("a -> b -> c", 1) == ("a -> b", "c")
    assert split_link_field("a -> b -> c", 6) == ("a", "b -> c")
    # The size names no cut (a /proc link, a listing without sizes): the
    # whole text, which names no other file.
    assert split_link_field("a -> b -> c", 0) == ("a -> b -> c", "")
    assert split_link_field("a -> b -> c", None) == ("a -> b -> c", "")
    # A target of several bytes per character.
    assert split_link_field("a -> b -> é", 2) == ("a -> b", "é")


# --- rsync: a leading blank, an escaped line feed ------------------------------


def _rsync(monkeypatch, listing: str):
    from core import rsync_client as RC

    monkeypatch.setattr(
        RC.subprocess, "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=listing, stderr=""),
    )
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    return RC.RsyncSession("h", module="m")


def test_sad_rsync_listing_keeps_a_leading_blank(monkeypatch) -> None:
    """``\\s+`` before the name ate its leading blanks: " notes" was
    listed as "notes", another file."""
    s = _rsync(monkeypatch, "-rw-r--r--              1 2026/01/01 12:00:00  notes\n")
    assert [i.name for i in s.list_dir("/")] == [" notes"]


def test_sad_rsync_escaped_line_feed_is_no_entry_of_its_own(monkeypatch) -> None:
    """rsync prints a line feed in a name as \\#012; undone over the whole
    output it made a line of its own - here a fake entry "evil". A name
    with a "/" (a forged line holds one in its date) is no entry at all."""
    fake = "-rw-r--r--              1 2026/01/01 12:00:00 evil"
    s = _rsync(
        monkeypatch,
        "-rw-r--r--              1 2026/01/01 12:00:00 a\\#012" + fake + "\n"
        "-rw-r--r--              1 2026/01/01 12:00:00 b\\#012c\n",
    )
    assert [i.name for i in s.list_dir("/")] == ["b\nc"]
