"""A Gopher menu entry on another server is shown as a link, never fetched.

gopher.floodgap.com's root lists "Super-Dimensional Fortress: SDF
Gopherspace" with selector "" on host sdf.org. axross ignored an entry's
host and port and asked the connected server for the selector - and an
empty selector fell back to the path itself - so the folder showed
Floodgap's "doesn't exist" page (before that fix: an empty folder).
Following such an entry automatically would let any menu steer axross to
any host and port (the classic gopher:// SSRF against 127.0.0.1:6379), so
it is listed as a link to its gopher:// URL and opening it says where it
points. A same-server entry with an empty selector is the server's root.
When no root entry names the host and port axross connected to (an IP,
an alias, a mapped port), the root's most frequent host and port is the
server's own name.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import gopher_client as G  # noqa: E402

ROOT = (
    b"1Docs\t/docs\th\t70\r\n"
    b"1Home again\t\th\t70\r\n"
    b"1Elsewhere\t\tother.example\t70\r\n"
    b"0Remote file\t/f.txt\tother.example\t70\r\n"
    b"1Other port\t/x\th\t7070\r\n"
    b".\r\n"
)
DOCS = b"0Guide\t/docs/guide\th\t70\r\n.\r\n"


def _session(host="h", menus=None):
    menus = menus or {"": ROOT, "/docs": DOCS}
    s = G.GopherSession.__new__(G.GopherSession)
    s._host, s._port, s._dir_cache = host, 70, {}
    s.fetched = []

    def fetch(selector):
        s.fetched.append(selector)
        return G._parse_menu(menus[selector])

    s._fetch_menu = fetch
    s._fetch_file = lambda selector: (_ for _ in ()).throw(AssertionError(f"fetched {selector!r}"))
    return s


# --- happy ----------------------------------------------------------------


def test_happy_entries_on_the_same_server_browse():
    s = _session()
    assert [i.name for i in s.list_dir("/Docs")] == ["Guide.txt"]


def test_happy_a_foreign_entry_is_a_link_to_its_url():
    items = {i.name: i for i in _session().list_dir("/")}
    assert items["Elsewhere"].is_link
    assert items["Elsewhere"].link_target == "gopher://other.example:70/1"
    assert items["Remote file.txt"].link_target == "gopher://other.example:70/0/f.txt"
    assert not items["Docs"].is_link
    assert _session().readlink("/Elsewhere") == "gopher://other.example:70/1"


# --- sad ------------------------------------------------------------------


def test_sad_a_foreign_folder_is_not_fetched_from_this_server():
    s = _session()
    with pytest.raises(OSError, match="other.example:70") as err:
        s.list_dir("/Elsewhere")
    assert not isinstance(err.value, FileNotFoundError)
    assert s.fetched == [""]  # only the root menu


def test_sad_a_foreign_file_is_not_read():
    with pytest.raises(OSError, match="other.example:70"):
        _session().open_read("/Remote file.txt")


# --- edge -----------------------------------------------------------------


def test_edge_same_host_other_port_is_foreign():
    with pytest.raises(OSError, match="h:7070"):
        _session().list_dir("/Other port")


def test_edge_an_empty_selector_on_this_server_is_its_root():
    s = _session()
    assert "Docs" in [i.name for i in s.list_dir("/Home again")]
    assert s.fetched.count("") == 2  # the root, asked for again


@pytest.mark.parametrize("host, port", [("192.0.2.7", 70), ("h", 7071)])
def test_edge_connected_by_ip_or_mapped_port_the_server_name_is_learned(host, port):
    s = _session(host=host)
    s._port = port
    items = {i.name: i for i in s.list_dir("/")}
    assert not items["Docs"].is_link and items["Elsewhere"].is_link
    assert [i.name for i in s.list_dir("/Docs")] == ["Guide.txt"]
