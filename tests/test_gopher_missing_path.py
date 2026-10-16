"""A Gopher path the server does not have is missing, not an empty folder.

gopher.floodgap.com answers an unknown selector with a menu of one error
line (type 3) and info lines:

    3 '/x' doesn't exist!\\t\\terror.host\\t1
    i This resource cannot be located.\\t\\terror.host\\t1

list_dir() dropped both kinds and showed an empty folder (and cached the
error page); stat() raised a plain OSError. Now a menu with an error line
and nothing to list is FileNotFoundError, and it is not cached.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import gopher_client as G  # noqa: E402

ROOT = b"1Docs\t/docs\th\t70\r\n0Readme\t/readme\th\t70\r\n.\r\n"
DOCS = b"iWelcome\t\terror.host\t1\r\n0Guide\t/docs/guide\th\t70\r\n.\r\n"
QUIET = b"iNothing here yet\t\terror.host\t1\r\n.\r\n"
MISSING = (
    b"3 '/nope' doesn't exist!\t\terror.host\t1\r\n"
    b"i This resource cannot be located.\t\terror.host\t1\r\n.\r\n"
)


@pytest.fixture
def session():
    menus = {"": ROOT, "/docs": DOCS, "/quiet": QUIET}
    s = G.GopherSession.__new__(G.GopherSession)
    s._host, s._port, s._dir_cache = "h", 70, {}
    s.fetched = []

    def fetch(selector):
        s.fetched.append(selector)
        return G._parse_menu(menus.get(selector, MISSING))

    s._fetch_menu = fetch
    return s


# --- happy ----------------------------------------------------------------


def test_happy_a_real_menu_lists_without_its_info_lines(session):
    assert [i.name for i in session.list_dir("/Docs")] == ["Guide.txt"]


def test_happy_a_menu_of_info_lines_only_is_an_empty_folder(session):
    assert session.list_dir("/quiet") == []


# --- sad ------------------------------------------------------------------


def test_sad_an_error_menu_is_a_missing_folder(session):
    with pytest.raises(FileNotFoundError, match="doesn't exist"):
        session.list_dir("/nope")


def test_sad_stat_of_a_missing_entry_is_file_not_found(session):
    with pytest.raises(FileNotFoundError):
        session.stat("/Docs/absent.txt")


# --- edge -----------------------------------------------------------------


def test_edge_the_error_page_is_not_cached(session):
    for _ in range(2):
        with pytest.raises(FileNotFoundError):
            session.list_dir("/nope")
    assert session.fetched.count("/nope") == 2
    assert "/nope" not in session._dir_cache
