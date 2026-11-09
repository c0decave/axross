"""A Git rename is one commit; side branches reach origin; quick saves
ask origin once.

Round 7 found (repro git/repro_git_rename_race.py):

* rename() was two commits ("write dst", then "rm src"), each with its
  own sync with origin. Someone pushing a change of the source between
  them left the rename half done: the copy committed and not pushed, the
  original still there, GitBranchMoved - and a repeat failed with EEXIST.
  Now it is one commit that changes both paths (a folder: its whole tree
  entry moves), one sync, one push.
* the side branch ``axross/unpushed-<time>`` that keeps a change origin
  refused lived only in ~/.cache/axross/git. Now it is pushed to origin
  under the same name, and the message says where it is.
* every save asked origin (ls-remote) and then pushed. A save moments
  after a fetch or push (no failure seen) now skips the ls-remote; the
  push still refuses a non-fast-forward and the catch-up handles it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")

import core.git_fs_client as G  # noqa: E402
from test_git_push_conflict import (  # noqa: E402,F401 - the fixture
    _origin_file,
    _push_as_colleague,
    _session,
    _write,
    origin,
)


def _commits_on(repo, branch: str = "main") -> int:
    sha = repo.refs[f"refs/heads/{branch}".encode()]
    n = 0
    while True:
        n += 1
        parents = repo[sha].parents
        if not parents:
            return n
        sha = parents[0]


def _origin_paths(repo, branch: str = "main") -> list[str]:
    out = []

    def walk(tree_sha, prefix):
        for entry in repo[tree_sha].items():
            name = prefix + entry.path.decode()
            if entry.mode & 0o040000:
                walk(entry.sha, name + "/")
            else:
                out.append(name)

    walk(repo[repo.refs[f"refs/heads/{branch}".encode()]].tree, "")
    return sorted(out)


def test_happy_a_rename_is_one_commit_and_one_push(origin):
    s = _session(origin)
    before = _commits_on(origin)
    try:
        s.rename("/main/f.txt", "/main/g.txt")
        assert s.unpushed_commits() == {}
        assert sorted(i.name for i in s.list_dir("/main")) == ["g.txt"]
    finally:
        s.close()
    assert _commits_on(origin) == before + 1  # was 2 commits
    assert _origin_paths(origin) == ["g.txt"]
    assert _origin_file(origin, "g.txt") == b"v1\n"


def test_happy_a_folder_rename_moves_every_file_in_one_commit(origin):
    s = _session(origin, auto_push=False)
    try:
        _write(s, "/main/d/a.txt", b"a\n")
        _write(s, "/main/d/sub/b.txt", b"b\n")
        s.flush_push()
        before = _commits_on(origin)
        s._auto_push = True
        s.rename("/main/d", "/main/e")
        assert s.open_read("/main/e/sub/b.txt").read() == b"b\n"
        assert not s.exists("/main/d")
        with pytest.raises(OSError):
            s.rename("/main/e", "/main/e/inner")  # into itself
    finally:
        s.close()
    assert _commits_on(origin) == before + 1
    assert _origin_paths(origin) == ["e/a.txt", "e/sub/b.txt", "f.txt"]


def test_sad_a_push_between_the_halves_cannot_leave_it_half_done(origin, monkeypatch):
    """The colleague's change of the source lands once axross has a local
    commit of the rename (the old second sync); the rename is all or
    nothing, and a repeat works."""
    s = _session(origin)
    first = s._repo.refs[b"refs/heads/main"]
    real = s._remote_branch_tip
    pushed: list = []

    def remote_tip(branch):
        if not pushed and s._repo.refs[b"refs/heads/main"] != first:
            pushed.append(_push_as_colleague(origin, {"f.txt": b"colleague edited f\n"}))
        return real(branch)

    monkeypatch.setattr(s, "_remote_branch_tip", remote_tip)
    try:
        try:
            s.rename("/main/f.txt", "/main/g.txt")
        except G.GitBranchMoved:
            pass
        names = sorted(i.name for i in s.list_dir("/main"))
        assert names in (["f.txt"], ["g.txt"]), names  # was ['f.txt', 'g.txt']
        assert s.unpushed_commits() == {}  # was {'main': 1}
        if names == ["f.txt"]:
            s.rename("/main/f.txt", "/main/g.txt")  # was EEXIST
        assert sorted(i.name for i in s.list_dir("/main")) == ["g.txt"]
    finally:
        s.close()
    assert _origin_paths(origin) == ["g.txt"]


def test_sad_their_change_of_the_source_refuses_the_whole_rename(origin):
    s = _session(origin)
    try:
        assert s.exists("/main/f.txt")
        _push_as_colleague(origin, {"f.txt": b"theirs\n"})
        with pytest.raises(G.GitBranchMoved):
            s.rename("/main/f.txt", "/main/g.txt")
        assert sorted(i.name for i in s.list_dir("/main")) == ["f.txt"]
        assert s.unpushed_commits() == {}
    finally:
        s.close()
    assert _origin_paths(origin) == ["f.txt"]
    assert _origin_file(origin, "f.txt") == b"theirs\n"


def test_edge_the_side_branch_is_pushed_to_origin(origin):
    s = _session(origin, auto_push=False)
    try:
        _write(s, "/main/f.txt", b"mine\n")
        mine = s._repo.refs[b"refs/heads/main"]
        _push_as_colleague(origin, {"f.txt": b"theirs\n"})
        s._auto_push = True
        with pytest.raises(G.GitPushFailed) as err:
            s.flush_push()
        side = [b for b in s.branch_list() if b.startswith("axross/unpushed-")]
        assert len(side) == 1
        assert "on origin" in str(err.value)
    finally:
        s.close()
    # Was: only in ~/.cache/axross/git.
    assert origin.refs[f"refs/heads/{side[0]}".encode()] == mine
    assert _origin_file(origin, "f.txt", branch=side[0]) == b"mine\n"


def test_edge_a_side_branch_origin_refuses_is_named_as_local_only(origin, monkeypatch):
    s = _session(origin, auto_push=False)
    real_push = G.porcelain.push

    def push(repo, *a, refspecs=(), **kw):
        if any(b"axross/unpushed-" in r for r in refspecs):
            raise OSError("hook declined")
        return real_push(repo, *a, refspecs=refspecs, **kw)

    try:
        _write(s, "/main/f.txt", b"mine\n")
        _push_as_colleague(origin, {"f.txt": b"theirs\n"})
        s._auto_push = True
        monkeypatch.setattr(G.porcelain, "push", push)
        with pytest.raises(G.GitPushFailed) as err:
            s.flush_push()
        text = str(err.value)
        assert "only in the local cache" in text and s._workdir in text
        assert "hook declined" in text
    finally:
        s.close()
    assert not [r for r in origin.refs.keys() if b"unpushed" in r]


def test_edge_quick_saves_ask_origin_once(origin, monkeypatch):
    s = _session(origin)
    asked: list = []
    real = s._remote_branch_tip

    def remote_tip(branch):
        asked.append(branch)
        return real(branch)

    monkeypatch.setattr(s, "_remote_branch_tip", remote_tip)
    try:
        for i in range(5):
            _write(s, f"/main/n{i}.txt", b"%d\n" % i)
        assert len(asked) == 1  # was 5: an ls-remote before every push
        # Someone pushes inside the window: the push is refused and caught
        # up - nothing is lost.
        _push_as_colleague(origin, {"colleague.txt": b"c\n"})
        _write(s, "/main/n5.txt", b"5\n")
        assert s.unpushed_commits() == {}
        # After that refusal every save asks again.
        asked.clear()
        _write(s, "/main/n6.txt", b"6\n")
        assert asked == ["main"]
    finally:
        s.close()
    assert _origin_paths(origin) == sorted(
        ["colleague.txt", "f.txt"] + [f"n{i}.txt" for i in range(7)]
    )


def test_edge_an_old_fetch_is_asked_again(origin, monkeypatch):
    s = _session(origin)
    asked: list = []
    real = s._remote_branch_tip
    monkeypatch.setattr(s, "_remote_branch_tip", lambda b: asked.append(b) or real(b))
    try:
        _write(s, "/main/a.txt", b"a\n")
        s._pushed_at["main"] -= G.GitFsSession._FRESH_SECONDS + 1
        _write(s, "/main/b.txt", b"b\n")
        assert asked == ["main", "main"]
    finally:
        s.close()



def test_edge_a_side_branch_made_on_reopening_reaches_origin(origin):
    s = _session(origin, auto_push=False)
    _write(s, "/main/f.txt", b"mine, offline\n")
    mine = s._repo.refs[b"refs/heads/main"]
    s.close()
    _push_as_colleague(origin, {"f.txt": b"theirs\n"})
    s2 = _session(origin)  # the fetch moves the unpushed commit aside
    try:
        side = [b for b in s2.branch_list() if b.startswith("axross/unpushed-")]
        assert len(side) == 1
    finally:
        s2.close()
    assert origin.refs[f"refs/heads/{side[0]}".encode()] == mine
