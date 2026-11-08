"""Dropbox: a name's blanks are part of the API path.

``_api_path`` stripped the whole path: ``"/dir/foo "`` went to the API
as ``"/dir/foo"``, so reading or deleting the file "foo " read or deleted
its namesake "foo". Only "" and "/" are the root now, and only a
trailing "/" is dropped.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dropbox")

from core.dropbox_client import DropboxSession  # noqa: E402


def test_sad_api_path_keeps_leading_and_trailing_blanks() -> None:
    assert DropboxSession._api_path("/dir/foo ") == "/dir/foo "
    assert DropboxSession._api_path("/ notes") == "/ notes"
    assert DropboxSession._api_path(" ") == "/ "


def test_edge_api_path_root_and_trailing_slash() -> None:
    """The root and a trailing "/" map as before; blanks never do - a
    folder's entry named " " stays one."""
    assert DropboxSession._api_path("/dir/ ") == "/dir/ "
    assert DropboxSession._api_path("") == ""
    assert DropboxSession._api_path("/") == ""
    assert DropboxSession._api_path("dir/") == "/dir"
    assert DropboxSession._api_path("/dir/sub/") == "/dir/sub"
    assert DropboxSession._api_path("/dir/sub /") == "/dir/sub "


def test_sad_remove_of_name_with_trailing_blank_deletes_that_file() -> None:
    deleted: list[str] = []
    dbx = SimpleNamespace(
        files_get_metadata=lambda p: SimpleNamespace(),
        files_delete_v2=deleted.append,
    )
    s = DropboxSession.__new__(DropboxSession)
    s._ensure_connected = lambda: dbx
    s.remove("/dir/foo ")
    assert deleted == ["/dir/foo "]
