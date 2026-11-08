"""Git-FS never overwrites commits made after the session read the branch.

_commit_modification took the parent from the branch tips cached when
the session opened and set the ref with a plain assignment. A commit
pushed to the branch in between (another clone, a CI job, a second
axross) was dropped from the branch by the next save through axross:
the new commit's parent was the old tip, and the ref simply moved to it.
Now the ref is read again under the session lock: when it moved, the
write is refused with GitBranchMoved (ESTALE) and the cached tips are
refreshed; and the ref is set with a compare-and-swap
(``refs.set_if_equals`` / ``add_if_new``), so a commit landing while
axross commits is not overwritten either.
"""

from __future__ import annotations

import errno
import time

import pytest

pytest.importorskip("dulwich")
from dulwich.objects import Blob, Commit, Tree  # noqa: E402
from dulwich.repo import Repo  # noqa: E402

from core.git_fs_client import GitBranchMoved, GitFsSession  # noqa: E402


def _commit(repo: Repo, files: dict[str, bytes], parents: list[bytes], msg: bytes) -> bytes:
    tree = Tree()
    for name, data in files.items():
        blob = Blob.from_string(data)
        repo.object_store.add_object(blob)
        tree.add(name.encode(), 0o100644, blob.id)
    repo.object_store.add_object(tree)
    c = Commit()
    c.tree = tree.id
    c.parents = parents
    c.author = c.committer = b"t <t@example.invalid>"
    c.author_time = c.commit_time = int(time.time())
    c.author_timezone = c.commit_timezone = 0
    c.message = msg
    repo.object_store.add_object(c)
    return c.id


@pytest.fixture
def bare(tmp_path):
    repo = Repo.init_bare(str(tmp_path / "r.git"), mkdir=True)
    first = _commit(repo, {"a.txt": b"one\n"}, [], b"c1")
    repo.refs[b"refs/heads/main"] = first
    return repo, first


def _session(repo: Repo) -> GitFsSession:
    return GitFsSession(path=repo.path, author_name="ax", author_email="ax@example.invalid")


def test_sad_a_commit_pushed_after_open_is_kept(bare):
    repo, first = bare
    s = _session(repo)
    pushed = _commit(repo, {"a.txt": b"one\n", "b.txt": b"important\n"}, [first], b"external")
    repo.refs[b"refs/heads/main"] = pushed
    with pytest.raises(GitBranchMoved) as info:
        with s.open_write("/main/c.txt") as fh:
            fh.write(b"axross\n")
    assert info.value.errno == errno.ESTALE
    assert "moved" in str(info.value)
    assert Repo(repo.path).refs[b"refs/heads/main"] == pushed


def test_edge_after_the_refusal_the_write_builds_on_the_new_tip(bare):
    repo, first = bare
    s = _session(repo)
    pushed = _commit(repo, {"a.txt": b"one\n", "b.txt": b"important\n"}, [first], b"external")
    repo.refs[b"refs/heads/main"] = pushed
    with pytest.raises(GitBranchMoved):
        s.open_write("/main/c.txt").close()
    assert s.open_read("/main/b.txt").read() == b"important\n"  # the tips were refreshed
    with s.open_write("/main/c.txt") as fh:
        fh.write(b"axross\n")
    fresh = Repo(repo.path)
    tip = fresh[fresh.refs[b"refs/heads/main"]]
    assert tip.parents == [pushed]
    names = {e.path for e in fresh[tip.tree].items()}
    assert names == {b"a.txt", b"b.txt", b"c.txt"}


def test_sad_a_commit_landing_while_axross_commits_is_not_overwritten(bare, monkeypatch):
    """The compare-and-swap: the ref moves between the re-read and the set."""
    repo, first = bare
    s = _session(repo)
    racing = _commit(repo, {"a.txt": b"race\n"}, [first], b"racing")
    real = s._build_modified_tree

    def build_then_race(*a, **kw):
        tree = real(*a, **kw)
        s._repo.refs[b"refs/heads/main"] = racing
        return tree

    monkeypatch.setattr(s, "_build_modified_tree", build_then_race)
    with pytest.raises(GitBranchMoved):
        with s.open_write("/main/c.txt") as fh:
            fh.write(b"axross\n")
    assert Repo(repo.path).refs[b"refs/heads/main"] == racing


def test_happy_writes_in_a_row_each_build_on_the_last(bare):
    repo, first = bare
    s = _session(repo)
    for name in ("x.txt", "y.txt"):
        with s.open_write(f"/main/{name}") as fh:
            fh.write(b"1\n")
    s.rename("/main/x.txt", "/main/z.txt")  # two commits back to back
    fresh = Repo(repo.path)
    tip = fresh[fresh.refs[b"refs/heads/main"]]
    assert {e.path for e in fresh[tip.tree].items()} == {b"a.txt", b"y.txt", b"z.txt"}


def test_happy_a_new_branch_is_created(bare):
    repo, _first = bare
    s = _session(repo)
    with s.open_write("/topic/new.txt") as fh:
        fh.write(b"n\n")
    assert b"refs/heads/topic" in Repo(repo.path).refs.allkeys()
