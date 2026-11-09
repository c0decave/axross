"""Someone else pushes to the branch a Git URL session writes to.

Round 6 found (repro git/push_conflict.py): the save was committed on the
stale tip, the push was refused with dulwich's DivergedBranches - shown
as "Git push main: (b'8148...', b'0aaa...')" and "pushed with the next
write" - every later save piled another commit on the diverged branch,
and after a reconnect the branch was read-only until it was merged in a
git client in the hidden cache.

Now: a write asks origin first and builds on its tip when only other
files changed; a refused push fetches and replays the unpushed commits
onto origin's tip (other files) or keeps them on a side branch
``axross/unpushed-<time>`` (the same files) - with a sentence that says
so; a reopened cache is brought up to date the same way.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")
from dulwich.objects import Blob, Commit, Tree  # noqa: E402
from dulwich.repo import Repo  # noqa: E402

import core.git_fs_client as G  # noqa: E402

_ID = b"Colleague <c@example.org>"


def _push_as_colleague(repo: Repo, files: dict[str, bytes], branch: str = "main") -> bytes:
    """A commit on top of *branch* of the bare *repo* that sets *files*
    (flat names), as a colleague's push would."""
    ref = f"refs/heads/{branch}".encode()
    parent = repo.refs[ref]
    tree = Tree()
    for entry in repo[repo[parent].tree].items():
        tree.add(entry.path, entry.mode, entry.sha)
    for name, data in files.items():
        blob = Blob.from_string(data)
        repo.object_store.add_object(blob)
        tree[name.encode()] = (0o100644, blob.id)
    repo.object_store.add_object(tree)
    commit = Commit()
    commit.tree = tree.id
    commit.parents = [parent]
    commit.author = commit.committer = _ID
    commit.author_time = commit.commit_time = int(time.time())
    commit.author_timezone = commit.commit_timezone = 0
    commit.message = b"colleague\n"
    repo.object_store.add_object(commit)
    repo.refs[ref] = commit.id
    return commit.id


@pytest.fixture
def origin(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    bare = tmp_path / "origin.git"
    bare.mkdir()
    repo = Repo.init_bare(str(bare))
    tree = Tree()
    blob = Blob.from_string(b"v1\n")
    repo.object_store.add_object(blob)
    tree.add(b"f.txt", 0o100644, blob.id)
    repo.object_store.add_object(tree)
    commit = Commit()
    commit.tree = tree.id
    commit.parents = []
    commit.author = commit.committer = _ID
    commit.author_time = commit.commit_time = int(time.time())
    commit.author_timezone = commit.commit_timezone = 0
    commit.message = b"v1\n"
    repo.object_store.add_object(commit)
    repo.refs[b"refs/heads/main"] = commit.id
    repo.refs.set_symbolic_ref(b"HEAD", b"refs/heads/main")
    yield repo
    repo.close()


def _session(repo: Repo, **kw) -> G.GitFsSession:
    return G.GitFsSession(
        url="file://" + repo.path, author_name="T", author_email="t@example.org", **kw
    )


def _write(s, path: str, data: bytes) -> None:
    with s.open_write(path) as fh:
        fh.write(data)


def _origin_file(repo: Repo, name: str, branch: str = "main") -> bytes | None:
    tree = repo[repo[repo.refs[f"refs/heads/{branch}".encode()]].tree]
    if name.encode() not in tree:
        return None
    return repo[tree[name.encode()][1]].data


def test_happy_a_colleagues_push_to_other_files_does_not_stop_the_save(origin):
    s = _session(origin)
    try:
        _write(s, "/main/mine1.txt", b"first\n")
        _push_as_colleague(origin, {"colleague.txt": b"c\n"})
        _write(s, "/main/mine2.txt", b"second\n")  # was GitPushFailed
        _write(s, "/main/mine3.txt", b"third\n")
        assert s.unpushed_commits() == {}
        names = sorted(i.name for i in s.list_dir("/main"))
        assert names == ["colleague.txt", "f.txt", "mine1.txt", "mine2.txt", "mine3.txt"]
    finally:
        s.close()
    assert _origin_file(origin, "colleague.txt") == b"c\n"
    assert _origin_file(origin, "mine3.txt") == b"third\n"


def test_sad_a_colleagues_change_of_the_same_file_is_not_overwritten(origin):
    s = _session(origin)
    try:
        assert s.open_read("/main/f.txt").read() == b"v1\n"
        _push_as_colleague(origin, {"f.txt": b"theirs\n"})
        with pytest.raises(G.GitBranchMoved) as err:
            _write(s, "/main/f.txt", b"mine\n")
        assert "(b'" not in str(err.value)
        assert s.unpushed_commits() == {}
        assert s.open_read("/main/f.txt").read() == b"theirs\n"  # now shown
        _write(s, "/main/f.txt", b"mine, after looking\n")  # a repeat works
    finally:
        s.close()
    assert _origin_file(origin, "f.txt") == b"mine, after looking\n"


def test_edge_a_refused_push_is_replayed_onto_their_tip(origin):
    """The push race: the colleague pushes between our commit and our
    push (here: auto_push=False and flush_push)."""
    s = _session(origin, auto_push=False)
    try:
        _write(s, "/main/mine.txt", b"mine\n")
        _push_as_colleague(origin, {"colleague.txt": b"c\n"})
        s.flush_push()  # was OSError "Git push main: (b'...', b'...')"
        assert s.unpushed_commits() == {}
        assert sorted(i.name for i in s.list_dir("/main")) == [
            "colleague.txt", "f.txt", "mine.txt"
        ]
    finally:
        s.close()
    assert _origin_file(origin, "mine.txt") == b"mine\n"
    assert _origin_file(origin, "colleague.txt") == b"c\n"


def test_edge_a_refused_push_of_the_same_file_goes_to_a_side_branch(origin):
    s = _session(origin, auto_push=False)
    try:
        _write(s, "/main/f.txt", b"mine\n")
        mine = s._repo.refs[b"refs/heads/main"]
        theirs = _push_as_colleague(origin, {"f.txt": b"theirs\n"})
        with pytest.raises(G.GitPushFailed) as err:
            s.flush_push()
        text = str(err.value)
        assert "(b'" not in text
        assert "someone else pushed to main" in text
        side = [b for b in s.branch_list() if b.startswith("axross/unpushed-")]
        assert len(side) == 1 and side[0] in text
        # Nothing lost: the side branch has our commit, main shows origin's.
        assert s._repo.refs[f"refs/heads/{side[0]}".encode()] == mine
        assert s._repo.refs[b"refs/heads/main"] == theirs
        assert s.open_read(f"/{side[0]}/f.txt").read() == b"mine\n"
        assert s.open_read("/main/f.txt").read() == b"theirs\n"
    finally:
        s.close()
    assert _origin_file(origin, "f.txt") == b"theirs\n"


def test_edge_no_commit_lands_while_a_refused_push_cannot_be_caught_up(origin, monkeypatch):
    s = _session(origin)
    try:
        _write(s, "/main/mine1.txt", b"1\n")
        _push_as_colleague(origin, {"colleague.txt": b"c\n"})
        # The colleague's push lands after the check before the commit,
        # and origin cannot be read after the refusal.
        monkeypatch.setattr(s, "_sync_before_commit", lambda branch, sub: None)
        monkeypatch.setattr(s, "_fetch_origin", lambda: (_ for _ in ()).throw(OSError("down")))
        with pytest.raises(G.GitPushFailed) as err:
            _write(s, "/main/mine2.txt", b"2\n")
        assert "no further commit on main" in str(err.value)
        monkeypatch.undo()
        monkeypatch.setattr(
            s, "_remote_branch_tip", lambda branch: (_ for _ in ()).throw(OSError("down"))
        )
        with pytest.raises(G.GitForceRefused):
            _write(s, "/main/mine3.txt", b"3\n")
        tip = s._repo[s._repo.refs[b"refs/heads/main"]]
        assert b"mine3.txt" not in s._repo[tip.tree]
        monkeypatch.undo()
        _write(s, "/main/mine3.txt", b"3\n")  # origin back: caught up, pushed
        assert s.unpushed_commits() == {}
    finally:
        s.close()
    for name in ("colleague.txt", "mine1.txt", "mine2.txt", "mine3.txt"):
        assert _origin_file(origin, name) is not None, name


def test_edge_a_reopened_diverged_cache_is_brought_up_to_date(origin):
    s = _session(origin, auto_push=False)
    _write(s, "/main/local.txt", b"not pushed\n")
    s.close()
    _push_as_colleague(origin, {"colleague.txt": b"c\n"})
    s2 = _session(origin)
    try:  # was read-only "until it is merged in a git client"
        assert s2.unpushed_commits() == {"main": 1}
        _write(s2, "/main/more.txt", b"more\n")
        assert s2.unpushed_commits() == {}
    finally:
        s2.close()
    for name in ("colleague.txt", "local.txt", "more.txt"):
        assert _origin_file(origin, name) is not None, name


def test_edge_dulwich_progress_does_not_reach_the_terminal(origin, capfd):
    s = _session(origin)
    try:
        _push_as_colleague(origin, {"colleague.txt": b"c\n"})
        _write(s, "/main/mine.txt", b"x")
    finally:
        s.close()
    s = _session(origin)  # a fetch
    s.close()
    captured = capfd.readouterr()
    assert "counting objects" not in captured.out + captured.err
    assert "writing pack data" not in captured.out + captured.err
