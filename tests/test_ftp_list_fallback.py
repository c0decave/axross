"""A server without MLSD (vsftpd) still lists mode, owner, group and dates.

The fallback listing took the names from ``NLST`` and then asked each
entry on its own - ``SIZE``, ``MDTM``, ``PWD`` and two ``CWD`` - and read
``LIST`` only to tell which entries are links. Everything else that the
``ls -l`` line carries was dropped: every entry showed permissions
``----------``, no owner, and every directory the epoch as its date,
because ``MDTM`` is defined for files only.

Now a Unix-style ``LIST`` line fills the item, and only a regular file
still asks ``MDTM`` for its exact UTC time. A listing the parser cannot
read (DOS style) keeps the per-entry probe.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402
from tests.test_ftp_symlink_delete import _DirFtpServer  # noqa: E402

EPOCH = datetime.fromtimestamp(0)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "srv"
    (root / "site" / "img").mkdir(parents=True)
    (root / "site" / "index.html").write_text("<h1>hi</h1>\n")
    (root / "site" / "secret.txt").write_text("x")
    os.chmod(root / "site" / "secret.txt", 0o640)
    os.chmod(root / "site" / "img", 0o750)
    os.symlink("index.html", root / "site" / "home.html")
    (root / "plain" / "sub").mkdir(parents=True)
    (root / "plain" / "a.txt").write_text("a")
    (root / "plain" / "b.txt").write_text("b")
    (root / "dots" / ".cache").mkdir(parents=True)
    (root / "dots" / ".env").write_text("SECRET=1\n")
    os.chmod(root / "dots" / ".env", 0o600)
    (root / "dots" / "visible.txt").write_text("v")
    return root


@pytest.fixture
def server(tmp_path):
    made: list[tuple[_DirFtpServer, FC.FtpSession]] = []

    def make(
        list_style: str = "unix",
        mdtm: bool = True,
        dash_a: str = "parse",
        missing_listing: str = "error",
    ):
        root = _tree(tmp_path)
        srv = _DirFtpServer(
            root,
            mlsd="none",
            list_style=list_style,
            mdtm=mdtm,
            dash_a=dash_a,
            missing_listing=missing_listing,
        )
        s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
        made.append((srv, s))
        return root, srv, s

    yield make
    for srv, s in made:
        s.disconnect()
        srv.close()


def _listed(srv: _DirFtpServer, s: FC.FtpSession, path: str):
    before = len(srv.commands)
    items = {i.name: i for i in s.list_dir(path)}
    return items, [c.split(" ", 1)[0].upper() for c in srv.commands[before:]]


# --- happy ----------------------------------------------------------------


def test_happy_list_line_fills_mode_owner_and_group(server):
    _root, srv, s = server()
    items, _ = _listed(srv, s, "/site")
    assert items["secret.txt"].permissions == 0o640
    assert items["img"].permissions == 0o750
    assert items["img"].is_dir and not items["img"].is_link
    assert items["index.html"].permissions == 0o644
    assert (items["index.html"].owner, items["index.html"].group) == ("owner", "group")
    assert items["index.html"].size == len("<h1>hi</h1>\n")


def test_happy_a_directory_gets_its_list_date_and_a_file_its_mdtm(server):
    root, srv, s = server()
    items, _ = _listed(srv, s, "/site")
    real_dir = datetime.fromtimestamp((root / "site" / "img").stat().st_mtime)
    assert items["img"].modified != EPOCH
    # LIST has minutes and no zone; the server's clock may be any zone.
    assert abs(items["img"].modified - real_dir) < timedelta(hours=15)
    real_file = datetime.fromtimestamp(int((root / "site" / "index.html").stat().st_mtime))
    assert items["index.html"].modified == real_file  # MDTM: exact, UTC


def test_happy_a_listing_asks_mdtm_per_file_and_nothing_per_directory(server):
    _root, srv, s = server()
    items, verbs = _listed(srv, s, "/plain")
    assert "CWD" not in verbs and "SIZE" not in verbs and "PWD" not in verbs
    assert verbs.count("MDTM") == 2  # a.txt, b.txt; the directory asks nothing
    assert verbs.count("LIST") == 1 and verbs.count("NLST") == 1
    assert set(items) == {"a.txt", "b.txt", "sub"} and items["sub"].is_dir


def test_happy_dot_entries_get_their_list_line_too(server):
    """pure-ftpd (measured 2026-10-21) leaves dot entries out of a plain
    ``LIST``; NLST still named them, so each was probed on its own and
    showed no mode, owner or group. ``LIST -a`` carries them."""
    _root, srv, s = server()
    items, verbs = _listed(srv, s, "/dots")
    assert set(items) == {".env", ".cache", "visible.txt"}
    assert items[".env"].permissions == 0o600
    assert (items[".env"].owner, items[".env"].group) == ("owner", "group")
    assert items[".cache"].is_dir and not items[".cache"].is_link
    assert "CWD" not in verbs and "SIZE" not in verbs
    assert verbs.count("LIST") == 1
    assert any(c.startswith("LIST -a ") for c in srv.commands)


# --- sad ------------------------------------------------------------------


def test_sad_a_server_that_refuses_the_option_gets_a_plain_list(server):
    _root, srv, s = server(dash_a="literal")  # "LIST -a /x": 550, no such path
    items, verbs = _listed(srv, s, "/site")
    assert verbs.count("LIST") == 2
    assert items["secret.txt"].permissions == 0o640
    assert items["home.html"].is_link


def test_sad_without_mdtm_a_file_keeps_its_list_date(server):
    _root, srv, s = server(mdtm=False)
    items, _ = _listed(srv, s, "/site")
    assert items["index.html"].modified != EPOCH
    assert items["index.html"].permissions == 0o644


def test_sad_a_dos_listing_keeps_the_per_entry_probe(server):
    _root, srv, s = server(list_style="dos")
    items, verbs = _listed(srv, s, "/site")
    assert "CWD" in verbs  # the old probe decides what is a directory
    assert items["img"].is_dir
    assert items["index.html"].permissions == 0


def test_sad_a_link_stays_a_link_with_its_target_and_mode(server):
    _root, srv, s = server()
    items, _ = _listed(srv, s, "/site")
    link = items["home.html"]
    assert link.is_link and not link.is_dir
    assert link.link_target == "index.html"
    assert link.permissions == 0o777


# --- edge -----------------------------------------------------------------


NOW = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)


def _one(line: str):
    (entry,) = FC._parse_unix_list_details(["total 1", line], now=NOW)
    return entry


def test_edge_an_empty_answer_to_the_option_gets_a_plain_list(server):
    """A server that takes ``-a /x`` for a missing path and answers with an
    empty listing (as vsftpd-style servers do for a missing folder)."""
    _root, srv, s = server(dash_a="literal", missing_listing="empty")
    items, verbs = _listed(srv, s, "/plain")
    assert verbs.count("LIST") == 2
    assert set(items) == {"a.txt", "b.txt", "sub"} and items["sub"].is_dir
    assert "CWD" not in verbs


def test_edge_a_time_in_the_future_belongs_to_last_year():
    e = _one("drwxr-xr-x    2 a b 4096 Dec 24 18:30 xmas")
    assert e.modified == datetime(2025, 12, 24, 18, 30, tzinfo=timezone.utc)
    e = _one("drwxr-xr-x    2 a b 4096 Mar 10 11:00 today")
    assert e.modified == datetime(2026, 3, 10, 11, 0, tzinfo=timezone.utc)


def test_edge_a_year_column_and_a_missing_group_column():
    e = _one("-rw-r--r--    1 ftp       12 Jan  1  2024 old file.txt")
    assert e.modified == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert (e.owner, e.group, e.size, e.rest) == ("ftp", "", 12, "old file.txt")


def test_edge_setuid_setgid_and_sticky_bits():
    assert _one("-rwsr-sr-t    1 a b 1 Jan  1  2024 x").mode == 0o7755
    assert _one("-rwSr-Sr-T    1 a b 1 Jan  1  2024 x").mode == 0o7644
    assert _one("----------    1 a b 1 Jan  1  2024 x").mode == 0


def test_edge_an_unknown_month_gives_no_date_but_keeps_the_entry():
    e = _one("-rw-r--r--    1 a b 1 Foo  1  2024 x")
    assert e.modified is None and e.mode == 0o644


def test_edge_the_link_type_view_is_unchanged():
    lines = [
        "lrwxrwxrwx 1 o g 9 Oct 15 12:00 link -> ../t",
        "drwxr-xr-x 2 o g 4096 Jan  1  2025 a b",
    ]
    assert FC._parse_unix_list(lines) == [("l", "link -> ../t"), ("d", "a b")]
    assert FC._parse_unix_list_details(["10-15-26  12:00PM   <DIR>  x"]) is None
