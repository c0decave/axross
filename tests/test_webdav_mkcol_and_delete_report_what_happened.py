"""WebDAV mkdir() and remove() no longer report changes that did not happen.

* MKCOL answers 405 when something already has the name. The client took
  every 405 for "the folder exists" and returned - also when the name was
  a FILE, so the caller went on to write into a folder that was never
  made. Now a PROPFIND tells the two apart: a folder stays the idempotent
  no-op, a file is FileExistsError. A 409 (no parent) is FileNotFoundError,
  or NotADirectoryError when the parent is a file.
* DELETE answering 404 counted as success, so removing a typo said
  "removed". It is FileNotFoundError now, as on LocalFS; stat(), list_dir()
  and open_read() of a missing path are FileNotFoundError too.

Runs against axross' own reverse WebDAV server on loopback.
"""

from __future__ import annotations

import pytest

pytest.importorskip("defusedxml", reason="WebDAV needs defusedxml")

from core.webdav_client import WebDavSession  # noqa: E402


@pytest.fixture
def dav(tmp_path):
    from core.local_fs import LocalFS
    from core.reverse_serve import serve_webdav

    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "file.txt").write_bytes(b"data")
    srv = serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(tmp_path), auth_token=None
    )
    try:
        yield WebDavSession(srv.base_url), tmp_path
    finally:
        srv.shutdown()


# -- happy -------------------------------------------------------------------


def test_happy_mkdir_of_an_existing_folder_is_still_a_no_op(dav):
    session, root = dav
    session.mkdir("/d")
    assert (root / "d" / "file.txt").read_bytes() == b"data"


def test_happy_remove_of_an_existing_file_removes_it(dav):
    session, root = dav
    session.remove("/d/file.txt")
    assert not (root / "d" / "file.txt").exists()


# -- sad ---------------------------------------------------------------------


def test_sad_mkdir_over_a_file_is_file_exists(dav):
    session, root = dav
    with pytest.raises(FileExistsError):
        session.mkdir("/d/file.txt")
    assert (root / "d" / "file.txt").read_bytes() == b"data"


def test_sad_mkdir_below_a_file_is_not_a_directory(dav):
    session, _ = dav
    with pytest.raises(NotADirectoryError):
        session.mkdir("/d/file.txt/sub")


def test_sad_mkdir_without_a_parent_is_not_found(dav):
    session, _ = dav
    with pytest.raises(FileNotFoundError):
        session.mkdir("/nodir/sub")


@pytest.mark.parametrize("recursive", [False, True])
def test_sad_remove_of_a_missing_path_is_not_found(dav, recursive):
    session, _ = dav
    with pytest.raises(FileNotFoundError):
        session.remove("/d/missing.txt", recursive=recursive)


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize(
    "op",
    [
        lambda s: s.stat("/d/missing.txt"),
        lambda s: s.list_dir("/nodir"),
        lambda s: s.open_read("/d/missing.txt"),
    ],
    ids=["stat", "list_dir", "open_read"],
)
def test_edge_reading_a_missing_path_is_not_found(dav, op):
    session, _ = dav
    with pytest.raises(FileNotFoundError):
        op(session)
