"""Git backend reads on a corrupt object store: OSError, never a hang.

Two defects, both found by tests/test_fuzz_git.py:

* The translation of dulwich / zlib errors into OSError (_as_oserror)
  guarded only the commit path. A corrupt commit, tree or blob made
  list_dir / stat / open_read raise dulwich's ObjectFormatException or
  zlib.error to callers that handle OSError.
* A loose object whose zlib stream ends before the header's NUL hung
  every call that touched it: dulwich (1.2.6) reads the header in
  ShaFile._parse_legacy_object_header by reading more of the file until
  the header holds a NUL - after the whole file was already read, so the
  loop spins on empty reads forever.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")
from dulwich.repo import Repo  # noqa: E402
from fuzz_testkit import check_contract  # noqa: E402
from test_fuzz_git import pristine  # noqa: E402,F401 - fixture

from core.git_fs_client import GitFsSession  # noqa: E402


@pytest.fixture
def repo_copy(pristine):  # noqa: F811
    tmp = Path(tempfile.mkdtemp())
    copy = tmp / "repo"
    shutil.copytree(pristine, copy)
    try:
        yield copy
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _object_path(repo_dir: Path, sha: bytes) -> Path:
    hexsha = sha.decode()
    return repo_dir / ".git" / "objects" / hexsha[:2] / hexsha[2:]


def _blob_sha(repo_dir: Path, name: bytes) -> bytes:
    repo = Repo(str(repo_dir))
    try:
        tree = repo[repo[repo.refs[b"refs/heads/main"]].tree]
        return tree[name][1]
    finally:
        repo.close()


def _overwrite(path: Path, data: bytes) -> None:
    path.chmod(0o644)
    path.write_bytes(data)


def test_happy_intact_repository(repo_copy):
    s = GitFsSession(path=str(repo_copy), default_branch="main")
    assert s.open_read("/main/a.txt").read() == b"hello\n"


def test_sad_header_cut_short_is_an_oserror_not_a_hang(repo_copy):
    target = _object_path(repo_copy, _blob_sha(repo_copy, b"a.txt"))
    raw = target.read_bytes()
    _overwrite(target, raw[:6])  # the zlib stream ends inside "blob 6"
    s = GitFsSession(path=str(repo_copy), default_branch="main")
    result = check_contract(lambda: s.open_read("/main/a.txt"), (OSError,), timeout=15.0)
    assert isinstance(result, OSError) and "truncated" in str(result)


def test_sad_corrupt_tree_is_an_oserror(repo_copy):
    tree_sha = _blob_sha(repo_copy, b"sub")
    _overwrite(_object_path(repo_copy, tree_sha), zlib.compress(b"tree 7\x00garbage"))
    s = GitFsSession(path=str(repo_copy), default_branch="main")
    result = check_contract(lambda: s.list_dir("/main/sub"), (OSError,), timeout=15.0)
    assert isinstance(result, OSError)


def test_edge_body_cut_short_is_an_oserror(repo_copy):
    target = _object_path(repo_copy, _blob_sha(repo_copy, b"a.txt"))
    full = zlib.compress(b"blob 6\x00hello\n")
    _overwrite(target, full[: len(full) - 8])  # header intact, deflate data cut
    s = GitFsSession(path=str(repo_copy), default_branch="main")
    result = check_contract(lambda: s.open_read("/main/a.txt").read(), (OSError,), timeout=15.0)
    assert isinstance(result, OSError)
