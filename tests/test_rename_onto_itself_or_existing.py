"""Git and Azure Blob: rename() onto itself, onto an existing file, and
to a key that ends in "/".

* Git renamed in two commits, "write dst" then "remove src":
  ``rename(src, src)`` removed the file, and a rename onto an existing
  file replaced it without a word. Both are refused now (as DbFsBackend
  does): ``OSError`` for the same path, ``FileExistsError`` for an
  existing destination.
* Azure Blob ``rename(x, x)`` copied the blob onto itself and then
  deleted the source - the only copy. It is a no-op now, as rename(2).
* Azure Blob: a file destination whose key ends in "/" became the
  folder marker ``"x/"`` - the data vanished from the listing (a folder
  was shown) and the next mkdir() replaced it with an empty marker.
  rename(), open_write() and copy() refuse such a destination, and
  stat() of ``"x/"`` reports a folder only when the prefix exists.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("dulwich")


@pytest.fixture
def git(tmp_path):
    from dulwich.repo import Repo

    from core.git_fs_client import GitFsSession

    Repo.init_bare(str(tmp_path / "repo"), mkdir=True)
    s = GitFsSession(path=str(tmp_path / "repo"), author_name="a", author_email="a@b")

    def write(path, data):
        f = s.open_write(path)
        f.write(data)
        f.close()

    write("/main/a.txt", b"AAA")
    s._refresh_branch_tips()
    write("/main/b.txt", b"BBB")
    return s


def _read(s, path):
    with s.open_read(path) as fh:
        return fh.read()


def test_sad_git_rename_onto_itself_keeps_the_file(git) -> None:
    with pytest.raises(OSError):
        git.rename("/main/a.txt", "/main/a.txt")
    assert _read(git, "/main/a.txt") == b"AAA"


def test_sad_git_rename_onto_an_existing_file_is_refused(git) -> None:
    with pytest.raises(FileExistsError):
        git.rename("/main/a.txt", "/main/b.txt")
    assert _read(git, "/main/a.txt") == b"AAA"
    assert _read(git, "/main/b.txt") == b"BBB"


def test_edge_git_rename_to_a_free_name_still_moves(git) -> None:
    """The guard must not stop a plain rename; and a rename onto a
    folder is no longer an IsADirectoryError from the write but the
    same FileExistsError."""
    git.rename("/main/a.txt", "/main/c.txt")
    assert _read(git, "/main/c.txt") == b"AAA"
    assert not git.exists("/main/a.txt")
    f = git.open_write("/main/d/x.txt")
    f.write(b"x")
    f.close()
    with pytest.raises(FileExistsError):
        git.rename("/main/c.txt", "/main/d")


# -- Azure Blob --------------------------------------------------------------


def _azure(names):
    import test_object_store_file_beside_a_same_named_folder as T

    return T.MAKERS["azure_blob"](names)


def test_sad_azure_rename_onto_itself_keeps_the_blob() -> None:
    sess, blobs = _azure(["a.txt"])
    sess.rename("/a.txt", "a.txt")
    sess.rename("/a.txt", "/a.txt")
    assert blobs == {"a.txt": b"data-a.txt"}


def test_edge_azure_rename_of_a_missing_blob_onto_itself_raises() -> None:
    sess, blobs = _azure(["b.txt"])
    with pytest.raises(FileNotFoundError):
        sess.rename("/a.txt", "/a.txt")
    assert blobs == {"b.txt": b"data-b.txt"}


def test_sad_azure_file_to_trailing_slash_destination_is_refused() -> None:
    from core.server_ops import server_side_move

    sess, blobs = _azure(["report.txt"])
    for call in (
        lambda: sess.rename("/report.txt", "/archive/"),
        lambda: sess.copy("/report.txt", "/archive/"),
        lambda: sess.open_write("/archive/"),
        lambda: server_side_move(sess, "/report.txt", "/archive/"),
    ):
        with pytest.raises(IsADirectoryError):
            call()
    assert blobs == {"report.txt": b"data-report.txt"}


def test_sad_azure_stat_of_a_trailing_slash_checks_the_prefix() -> None:
    """stat("/nothing/") answered "a folder" for any name."""
    sess, _blobs = _azure(["dir/x.txt"])
    with pytest.raises(FileNotFoundError):
        sess.stat("/nothing/")
    assert sess.stat("/dir/").is_dir
    assert sess.stat("/").is_dir
