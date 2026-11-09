"""A Git URL session stays in step with origin, and says when it is not.

Round 5 found (repro_git_url_session.py):

* after an upstream force-push the session kept showing the old content
  and refused every write ("behind or has diverged") for ever;
* a save was committed into the local cache only and never pushed -
  flush_push() was reachable from scripting alone;
* an unreachable origin opened the stale cache with connected=True and
  without a word, and writes went into it.

Now (see core/git_fs_client.py's module docstring): a branch with
nothing unpushed follows origin, also over a force-push and a deletion;
every write is pushed; a failed push keeps the commit and raises
GitPushFailed; offline the cache is read-only and the status note says
so. Driven against a bare origin through a file:// URL.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")
from dulwich.objects import Blob, Commit, Tree  # noqa: E402
from dulwich.repo import Repo  # noqa: E402

import core.git_fs_client as G  # noqa: E402

_ID = b"Up <up@example.org>"


def _commit(repo: Repo, branch: str, files: dict[str, bytes], parents: list[bytes]) -> bytes:
    """A commit of *files* (flat) on *branch* of the bare *repo*, its ref
    set to it whatever it was (a force-push when *parents* leave out the
    old tip)."""
    tree = Tree()
    for name, data in files.items():
        blob = Blob.from_string(data)
        repo.object_store.add_object(blob)
        tree.add(name.encode(), 0o100644, blob.id)
    repo.object_store.add_object(tree)
    commit = Commit()
    commit.tree = tree.id
    commit.parents = parents
    commit.author = commit.committer = _ID
    commit.author_time = commit.commit_time = int(time.time())
    commit.author_timezone = commit.commit_timezone = 0
    commit.message = b"upstream\n"
    repo.object_store.add_object(commit)
    repo.refs[f"refs/heads/{branch}".encode()] = commit.id
    return commit.id


@pytest.fixture
def origin(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    bare = tmp_path / "origin.git"
    bare.mkdir()
    repo = Repo.init_bare(str(bare))
    first = _commit(repo, "main", {"f.txt": b"v1\n"}, [])
    repo.refs.set_symbolic_ref(b"HEAD", b"refs/heads/main")
    yield repo, first
    repo.close()


def _session(repo: Repo, **kw) -> G.GitFsSession:
    return G.GitFsSession(
        url="file://" + repo.path, author_name="T", author_email="t@example.org", **kw
    )


def _write(s, path: str, data: bytes) -> None:
    with s.open_write(path) as fh:
        fh.write(data)


def _tree_names(repo: Repo, branch: str) -> set[str]:
    tip = repo.refs[f"refs/heads/{branch}".encode()]
    return {e.path.decode() for e in repo[repo[tip].tree].items()}


def test_happy_a_force_push_upstream_is_followed_when_nothing_is_unpushed(origin):
    repo, first = origin
    _session(repo).close()
    # Upstream amends v1: the new tip does not contain the old one.
    _commit(repo, "main", {"f.txt": b"v1-amended\n"}, [])
    s = _session(repo)
    try:
        assert s.open_read("/main/f.txt").read() == b"v1-amended\n"
        _write(s, "/main/new.txt", b"x")  # not "behind or diverged"
    finally:
        s.close()
    assert "new.txt" in _tree_names(repo, "main")


def test_happy_a_write_is_pushed_to_origin(origin):
    repo, _first = origin
    s = _session(repo)
    try:
        _write(s, "/main/saved.txt", b"important edit\n")
        assert s.unpushed_commits() == {}
        assert s.status_note() == ""
        s.rename("/main/saved.txt", "/main/moved.txt")
    finally:
        s.close()
    assert _tree_names(repo, "main") == {"f.txt", "moved.txt"}


def test_happy_auto_push_off_batches_until_flush_push(origin):
    repo, _first = origin
    s = _session(repo, auto_push=False)
    try:
        _write(s, "/main/a.txt", b"a")
        _write(s, "/main/b.txt", b"b")
        assert s.unpushed_commits() == {"main": 2}
        assert "main (2)" in s.status_note()
        assert _tree_names(repo, "main") == {"f.txt"}
        s.flush_push()
        assert s.unpushed_commits() == {}
        assert s.status_note() == ""
    finally:
        s.close()
    assert _tree_names(repo, "main") == {"f.txt", "a.txt", "b.txt"}


def test_sad_an_unreachable_origin_opens_the_cache_read_only_and_says_so(origin, caplog):
    repo, _first = origin
    _session(repo).close()
    gone = repo.path + ".gone"
    os.rename(repo.path, gone)
    try:
        with caplog.at_level("WARNING", logger="core.git_fs_client"):
            s = _session(repo)  # the cache of the first session, origin gone
        try:
            assert s.offline
            assert "offline" in s.status_note()
            assert any("unreachable" in r.getMessage() for r in caplog.records)
            assert s.open_read("/main/f.txt").read() == b"v1\n"  # reads still work
            with pytest.raises(OSError) as err:
                _write(s, "/main/x.txt", b"x")
            assert err.value.errno == __import__("errno").EROFS
            assert "read-only" in str(err.value)
        finally:
            s.close()
    finally:
        os.rename(gone, repo.path)


def test_sad_a_failed_push_keeps_the_commit_and_says_so(origin):
    repo, _first = origin
    s = _session(repo)
    path = repo.path
    try:
        os.rename(path, path + ".gone")
        try:
            with pytest.raises(G.GitPushFailed) as err:
                _write(s, "/main/a.txt", b"a")
            assert "not pushed" in str(err.value)
            assert s.open_read("/main/a.txt").read() == b"a"  # the commit is kept
            assert s.unpushed_commits() == {"main": 1}
            assert "main (1)" in s.status_note()
        finally:
            os.rename(path + ".gone", path)
        _write(s, "/main/b.txt", b"b")  # pushes both
        assert s.unpushed_commits() == {}
    finally:
        s.close()
    assert {"a.txt", "b.txt"} <= _tree_names(repo, "main")


def test_edge_unpushed_commits_survive_a_force_push(origin):
    """Round 6: the unpushed commit (another file than the force-push
    rewrote) is replayed onto the rewritten tip instead of leaving the
    branch read-only."""
    repo, _first = origin
    s = _session(repo, auto_push=False)
    _write(s, "/main/local.txt", b"not pushed\n")
    s.close()
    _commit(repo, "main", {"f.txt": b"rewritten\n"}, [])
    s2 = _session(repo, auto_push=False)
    try:
        assert s2.open_read("/main/local.txt").read() == b"not pushed\n"  # nothing lost
        assert s2.open_read("/main/f.txt").read() == b"rewritten\n"
        assert "main (1)" in s2.status_note()  # local.txt only
        _write(s2, "/main/more.txt", b"x")
        s2.flush_push()
    finally:
        s2.close()
    assert {"f.txt", "local.txt", "more.txt"} <= _tree_names(repo, "main")


def test_edge_unpushed_commits_of_a_force_pushed_file_go_to_a_side_branch(origin):
    repo, _first = origin
    s = _session(repo, auto_push=False)
    _write(s, "/main/f.txt", b"mine\n")
    local_tip = s._repo.refs[b"refs/heads/main"]
    s.close()
    _commit(repo, "main", {"f.txt": b"rewritten\n"}, [])
    s2 = _session(repo, auto_push=False)
    try:
        side = [b for b in s2.branch_list() if b.startswith("axross/unpushed-")]
        assert len(side) == 1
        assert s2._repo.refs[f"refs/heads/{side[0]}".encode()] == local_tip  # nothing lost
        assert s2.open_read("/main/f.txt").read() == b"rewritten\n"
        _write(s2, "/main/more.txt", b"x")  # main is writable again
    finally:
        s2.close()


def test_edge_a_deleted_upstream_branch_goes_when_nothing_is_unpushed(origin):
    repo, first = origin
    _commit(repo, "feature", {"g.txt": b"feature\n"}, [first])
    s = _session(repo)
    _write(s, "/feature/h.txt", b"h")  # makes a local refs/heads/feature, pushed
    s.close()
    del repo.refs[b"refs/heads/feature"]
    s2 = _session(repo)
    try:
        assert sorted(i.name for i in s2.list_dir("/")) == ["main"]
    finally:
        s2.close()


def test_sad_a_branch_checked_out_in_a_local_origin_is_not_written(tmp_path, monkeypatch):
    from dulwich import porcelain

    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    up = tmp_path / "work"
    up.mkdir()
    porcelain.init(str(up))
    (up / "f.txt").write_bytes(b"v1\n")
    porcelain.add(str(up), [str(up / "f.txt")])
    porcelain.commit(str(up), message=b"v1", author=_ID, committer=_ID)
    branch = porcelain.active_branch(str(up)).decode()
    before = Repo(str(up)).head()
    s = G.GitFsSession(url="file://" + str(up), author_name="T", author_email="t@example.org")
    try:
        with pytest.raises(OSError) as err:
            _write(s, f"/{branch}/new.txt", b"x")
        assert "checked out" in str(err.value)
        assert s.exists(f"/{branch}/new.txt") is False
    finally:
        s.close()
    assert Repo(str(up)).head() == before


def test_edge_typed_errors_of_the_read_surface(tmp_path):
    repo_dir = tmp_path / "repo.git"
    repo_dir.mkdir()
    Repo.init_bare(str(repo_dir))
    s = G.GitFsSession(path=str(repo_dir), author_name="T", author_email="t@x")
    try:
        _write(s, "/main/g", b"other")
        _write(s, "/main/d/f", b"hello")
        with pytest.raises(FileNotFoundError):
            s.open_read("/main/nope")
        with pytest.raises(FileNotFoundError):
            s.list_dir("/main/nope")
        with pytest.raises(FileNotFoundError):
            s.list_dir("/nobranch")
        with pytest.raises(IsADirectoryError):
            s.open_read("/main/d")
        with pytest.raises(NotADirectoryError):
            s.list_dir("/main/g")
        with pytest.raises(FileExistsError):
            s.mkdir("/main/g")
        with pytest.raises(FileExistsError):
            s.mkdir("/main")
        s.mkdir("/main/d")  # an existing folder: fine
        with pytest.raises(NotADirectoryError):
            s.stat("/main/g/")
        assert s.stat("/main/d/").is_dir
        with pytest.raises(OSError):
            _write(s, "/main/t/", b"data")
        with pytest.raises(OSError):
            s.rename("/main/g", "/main/x/")
        assert sorted(i.name for i in s.list_dir("/main")) == ["d", "g"]
    finally:
        s.close()
