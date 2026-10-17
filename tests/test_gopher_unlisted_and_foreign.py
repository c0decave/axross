"""Gopher: reading a path no menu lists, and recursive_fetch's foreign leaves.

Review of 2026-10-17:
- B26: open_read of a path the parent menu does not list falls back to
  fetching it verbatim; the server's "doesn't exist" error menu (type 3
  plus info lines) came back as the file's bytes, while stat said ENOENT.
- B25: recursive_fetch fetched a leaf that lives on ANOTHER server from
  THIS server with the foreign selector and returned that answer as the
  entry's content; open_read refuses the same entry.
"""

from __future__ import annotations

import pytest

from core import gopher_client as G

ROOT = (b"0Readme\t/readme\th\t70\r\n"
        b"0Remote file\t/secret.txt\tother.example\t70\r\n"
        b"1Away\t/away\tother.example\t70\r\n.\r\n")
ERR = (b"3 '/nope.txt' doesn't exist!\t\terror.host\t1\r\n"
       b"i This resource cannot be located.\t\terror.host\t1\r\n.\r\n")


def _session(files):
    s = G.GopherSession.__new__(G.GopherSession)
    s._host, s._port, s._dir_cache = "h", 70, {}
    s._fetch_menu = lambda sel: G._parse_menu({"": ROOT}[sel])
    fetched = []

    def fetch_file(sel):
        fetched.append(sel)
        return files.get(sel, ERR)

    s._fetch_file = fetch_file
    return s, fetched


def test_happy_an_unlisted_path_the_server_has_is_read():
    s, _ = _session({"/hidden.txt": b"hidden but there"})
    assert s.open_read("/hidden.txt").read() == b"hidden but there"


def test_sad_an_unlisted_path_the_server_lacks_is_file_not_found():
    s, _ = _session({})
    with pytest.raises(FileNotFoundError, match="doesn't exist"):
        s.open_read("/nope.txt")


def test_edge_a_listed_file_that_looks_like_an_error_menu_is_still_its_content():
    s, _ = _session({"/readme": ERR})
    name = next(i.name for i in s.list_dir("/") if i.name.startswith("Readme"))
    assert s.open_read("/" + name).read() == ERR  # listed: its bytes are its content


def test_sad_recursive_fetch_never_asks_this_server_for_a_foreign_entry():
    s, fetched = _session({"/readme": b"local text"})
    out = s.recursive_fetch("/")
    assert all(not k.startswith(("/Remote", "/Away")) for k in out)
    assert "/secret.txt" not in fetched and "/away" not in fetched
    assert b"local text" in out.values()
