"""Git-FS exists() and is_dir() say False only for "not found".

Both caught every OSError from stat() and answered False. stat() raises
OSError for a tree object the repository does not have (a partial or
damaged clone), for an object it cannot decode, and for an I/O error
reading the object store - none of which says the path is absent.
server_side_copy(overwrite=False) and the transfer worker's no-clobber
check take False as the go-ahead to write. A missing branch, a missing
folder on the way and a file where a folder should be raised a bare
OSError too; they are FileNotFoundError now, and only that means False.
"""

from __future__ import annotations

import errno
import time

import pytest

pytest.importorskip("dulwich")
from dulwich.objects import Blob, Commit, Tree  # noqa: E402
from dulwich.repo import Repo  # noqa: E402

from core.git_fs_client import GitFsSession  # noqa: E402

_REG = 0o100644
_DIR = 0o040000
_MISSING_TREE = b"1" * 40


def _commit(repo: Repo) -> None:
    store = repo.object_store
    a = Blob.from_string(b"keep")
    b = Blob.from_string(b"b")
    sub = Tree()
    sub.add(b"b.txt", _REG, b.id)
    root = Tree()
    root.add(b"a.txt", _REG, a.id)
    root.add(b"sub", _DIR, sub.id)
    # A folder whose tree object this clone does not have.
    root.add(b"gone", _DIR, _MISSING_TREE)
    for obj in (a, b, sub, root):
        store.add_object(obj)
    c = Commit()
    c.tree = root.id
    c.parents = []
    c.author = c.committer = b"t <t@example.invalid>"
    c.author_time = c.commit_time = int(time.time())
    c.author_timezone = c.commit_timezone = 0
    c.message = b"init"
    store.add_object(c)
    repo.refs[b"refs/heads/main"] = c.id


@pytest.fixture
def s(tmp_path):
    path = str(tmp_path / "r.git")
    _commit(Repo.init_bare(path, mkdir=True))
    return GitFsSession(path=path, author_name="t", author_email="t@example.invalid")


class _FailingRepo:
    """The repository, with every object read failing like a bad disk."""

    def __init__(self, repo):
        self._repo = repo

    def __getitem__(self, key):
        raise OSError(errno.EIO, "Input/output error")

    def __getattr__(self, name):
        return getattr(self._repo, name)


def test_happy_present_and_absent(s):
    assert s.exists("/main/a.txt") is True
    assert s.exists("/main/sub") is True
    assert s.is_dir("/main/sub") is True
    assert s.is_dir("/main/a.txt") is False
    assert s.exists("/main/missing") is False
    assert s.is_dir("/main/missing") is False
    assert s.exists("/main") is True


def test_sad_an_object_the_clone_lacks_is_an_oserror_not_absent(s):
    with pytest.raises(OSError) as err:
        s.exists("/main/gone/x.txt")
    assert not isinstance(err.value, FileNotFoundError)
    with pytest.raises(OSError):
        s.is_dir("/main/gone/x")


def test_sad_an_io_error_is_an_oserror_not_absent(s):
    s._repo = _FailingRepo(s._repo)
    with pytest.raises(OSError, match="Input/output"):
        s.exists("/main/a.txt")
    with pytest.raises(OSError, match="Input/output"):
        s.is_dir("/main/sub")


@pytest.mark.parametrize(
    "path",
    ["/nobranch", "/nobranch/a.txt", "/main/nodir/b.txt", "/main/a.txt/b"],
    ids=["branch", "under-missing-branch", "missing-folder", "file-on-the-way"],
)
def test_edge_every_kind_of_absence_is_file_not_found(s, path):
    with pytest.raises(FileNotFoundError):
        s.stat(path)
    assert s.exists(path) is False
    assert s.is_dir(path) is False
