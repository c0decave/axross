"""A Git URL session sees what was pushed upstream since the first clone.

GitFsSession reuses its cache clone and fetched with
``porcelain.fetch(remote_location=<URL>)``. Given a URL rather than the
remote's name dulwich updates no ref: the objects arrived, but
refs/heads/* and refs/remotes/origin/* stayed at clone time. Every later
session showed the clone-time files as current and committed on top of
them. The fetch now files the remote's branches under
refs/remotes/origin/*, fast-forwards local branches that have nothing of
their own, and keeps (and refuses to build on) a diverged one.

Driven against a real upstream repository through a file:// URL.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

porcelain = pytest.importorskip("dulwich.porcelain")
from dulwich.repo import Repo  # noqa: E402

import core.git_fs_client as G  # noqa: E402

_ID = b"A <a@example.org>"


def _commit(repo_dir: Path, name: str, data: bytes, message: bytes) -> bytes:
    (repo_dir / name).write_bytes(data)
    porcelain.add(str(repo_dir), [str(repo_dir / name)])
    return porcelain.commit(str(repo_dir), message=message, author=_ID, committer=_ID)


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    up = tmp_path / "upstream"
    up.mkdir()
    porcelain.init(str(up))
    _commit(up, "notes.txt", b"version 1\n", b"v1")
    return up


def _session(up: Path) -> G.GitFsSession:
    return G.GitFsSession(url="file://" + str(up), author_name="T", author_email="t@example.org")


def _branch(up: Path) -> str:
    return porcelain.active_branch(str(up)).decode()


def test_happy_a_new_session_sees_the_upstream_commit(upstream):
    branch = _branch(upstream)
    s = _session(upstream)
    assert s.open_read(f"/{branch}/notes.txt").read() == b"version 1\n"
    s.close()
    _commit(upstream, "notes.txt", b"version 2\n", b"v2")
    s2 = _session(upstream)
    try:
        assert s2.open_read(f"/{branch}/notes.txt").read() == b"version 2\n"
    finally:
        s2.close()


def test_sad_a_write_after_reconnect_builds_on_the_upstream_tip(upstream):
    branch = _branch(upstream)
    _session(upstream).close()
    upstream_tip = _commit(upstream, "other.txt", b"from upstream\n", b"upstream")
    s = _session(upstream)
    try:
        with s.open_write(f"/{branch}/mine.txt") as fh:
            fh.write(b"mine\n")
        tip = s._repo.refs[f"refs/heads/{branch}".encode()]
        assert s._repo[tip].parents == [upstream_tip]
        # Nothing of upstream's is dropped from the branch.
        assert s.open_read(f"/{branch}/other.txt").read() == b"from upstream\n"
    finally:
        s.close()


def test_edge_a_branch_pushed_upstream_appears_and_a_deleted_one_goes(upstream):
    s = _session(upstream)
    s.close()
    up = Repo(str(upstream))
    up.refs[b"refs/heads/feature"] = up.head()
    up.close()
    s2 = _session(upstream)
    try:
        assert "feature" in {i.name for i in s2.list_dir("/")}
    finally:
        s2.close()
    up = Repo(str(upstream))
    del up.refs[b"refs/heads/feature"]
    up.close()
    s3 = _session(upstream)
    try:
        assert b"refs/remotes/origin/feature" not in s3._repo.refs.allkeys()
    finally:
        s3.close()


def test_edge_local_commits_not_pushed_yet_are_kept(upstream):
    branch = _branch(upstream)
    s = _session(upstream)
    with s.open_write(f"/{branch}/local.txt") as fh:
        fh.write(b"not pushed\n")
    local_tip = s._repo.refs[f"refs/heads/{branch}".encode()]
    s.close()
    s2 = _session(upstream)  # upstream unchanged: local is ahead
    try:
        assert s2._repo.refs[f"refs/heads/{branch}".encode()] == local_tip
        assert s2.open_read(f"/{branch}/local.txt").read() == b"not pushed\n"
    finally:
        s2.close()


def test_sad_a_diverged_branch_is_kept_and_not_built_on(upstream):
    branch = _branch(upstream)
    s = _session(upstream)
    with s.open_write(f"/{branch}/local.txt") as fh:
        fh.write(b"not pushed\n")
    local_tip = s._repo.refs[f"refs/heads/{branch}".encode()]
    s.close()
    _commit(upstream, "notes.txt", b"version 2\n", b"v2")
    s2 = _session(upstream)
    try:
        assert s2._repo.refs[f"refs/heads/{branch}".encode()] == local_tip
        with pytest.raises(G.GitForceRefused):
            with s2.open_write(f"/{branch}/more.txt") as fh:
                fh.write(b"x")
    finally:
        s2.close()
