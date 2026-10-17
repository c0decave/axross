"""Git-FS keeps a file's mode, and leaves a checked-out branch alone.

* A write of an existing file committed it with mode 100644: an
  executable (100755) lost its +x on every save. rename / copy did the
  same to the moved / copied file. The mode of the entry stays now.
* A commit on the branch a work tree has checked out (the local repo's
  own HEAD, or a linked worktree) moved the branch ref without touching
  index and files: ``git status`` showed the edit reverted, staged, and
  the user's next ``git commit`` undid it. Such a write is refused now,
  like git refuses a push to a checked-out branch
  (receive.denyCurrentBranch); other branches are written as before.
"""

from __future__ import annotations

import os
import time

import pytest

pytest.importorskip("dulwich")
from dulwich.objects import Blob, Commit, Tree  # noqa: E402
from dulwich.repo import Repo  # noqa: E402

from core.git_fs_client import GitFsSession  # noqa: E402

_EXEC = 0o100755
_REG = 0o100644


def _commit(repo: Repo, branch: bytes, files: dict[str, tuple[int, bytes]]) -> bytes:
    tree = Tree()
    for name, (mode, data) in files.items():
        blob = Blob.from_string(data)
        repo.object_store.add_object(blob)
        tree.add(name.encode(), mode, blob.id)
    repo.object_store.add_object(tree)
    c = Commit()
    c.tree = tree.id
    c.parents = []
    c.author = c.committer = b"t <t@example.invalid>"
    c.author_time = c.commit_time = int(time.time())
    c.author_timezone = c.commit_timezone = 0
    c.message = b"init"
    repo.object_store.add_object(c)
    repo.refs[b"refs/heads/" + branch] = c.id
    return c.id


def _modes(path: str, branch: bytes) -> dict[str, int]:
    repo = Repo(path)
    tree = repo[repo[repo.refs[b"refs/heads/" + branch]].tree]
    return {e.path.decode(): e.mode for e in tree.items()}


_FILES = {"build.sh": (_EXEC, b"#!/bin/sh\necho old\n"), "notes.txt": (_REG, b"n\n")}


def _session(path: str) -> GitFsSession:
    return GitFsSession(path=path, author_name="t", author_email="t@example.invalid")


@pytest.fixture
def bare(tmp_path):
    path = str(tmp_path / "r.git")
    repo = Repo.init_bare(path, mkdir=True)
    _commit(repo, b"main", _FILES)
    return path


# -- happy -------------------------------------------------------------------


def test_happy_write_keeps_the_executable_and_the_regular_mode(bare):
    s = _session(bare)
    with s.open_write("/main/build.sh") as fh:
        fh.write(b"#!/bin/sh\necho new\n")
    with s.open_write("/main/notes.txt") as fh:
        fh.write(b"m\n")
    with s.open_write("/main/new.txt") as fh:
        fh.write(b"x")
    assert _modes(bare, b"main") == {"build.sh": _EXEC, "notes.txt": _REG, "new.txt": _REG}


def test_happy_rename_and_copy_carry_the_mode(bare):
    s = _session(bare)
    s.copy("/main/build.sh", "/main/copy.sh")
    s.rename("/main/build.sh", "/main/run.sh")
    modes = _modes(bare, b"main")
    assert modes["copy.sh"] == _EXEC and modes["run.sh"] == _EXEC
    assert "build.sh" not in modes


def test_happy_chmod_still_sets_the_mode(bare):
    s = _session(bare)
    s.chmod("/main/build.sh", 0o644)
    s.chmod("/main/notes.txt", 0o755)
    assert _modes(bare, b"main") == {"build.sh": _REG, "notes.txt": _EXEC}


# -- sad ---------------------------------------------------------------------


def test_sad_write_to_the_checked_out_branch_is_refused(tmp_path):
    path = str(tmp_path / "work")
    os.makedirs(path)
    repo = Repo.init(path)
    head = repo.refs.read_ref(b"HEAD")  # b"ref: refs/heads/<default>"
    branch = head.split(b"refs/heads/", 1)[1]
    tip = _commit(repo, branch, _FILES)
    _commit(repo, b"other", _FILES)
    s = _session(path)
    with pytest.raises(OSError, match="checked out"):
        with s.open_write(f"/{branch.decode()}/notes.txt") as fh:
            fh.write(b"changed")
    with pytest.raises(OSError, match="checked out"):
        s.remove(f"/{branch.decode()}/notes.txt")
    assert Repo(path).refs[b"refs/heads/" + branch] == tip
    # A branch no work tree has checked out is written as before.
    with s.open_write("/other/notes.txt") as fh:
        fh.write(b"changed")
    assert Repo(path).refs[b"refs/heads/other"] != tip


# -- edge --------------------------------------------------------------------


def test_edge_branch_checked_out_in_a_linked_worktree_is_refused(bare):
    repo = Repo(bare)
    _commit(repo, b"feature", _FILES)
    wt = os.path.join(repo.controldir(), "worktrees", "wt1")
    os.makedirs(wt)
    with open(os.path.join(wt, "HEAD"), "wb") as fh:
        fh.write(b"ref: refs/heads/feature\n")
    s = _session(bare)
    with pytest.raises(OSError, match="checked out"):
        with s.open_write("/feature/notes.txt") as fh:
            fh.write(b"x")
    # The bare repo's own HEAD names a branch no work tree shows.
    with s.open_write("/main/notes.txt") as fh:
        fh.write(b"x")


def test_edge_detached_worktree_head_blocks_nothing(bare):
    repo = Repo(bare)
    wt = os.path.join(repo.controldir(), "worktrees", "wt1")
    os.makedirs(wt)
    with open(os.path.join(wt, "HEAD"), "wb") as fh:
        fh.write(repo.refs[b"refs/heads/main"] + b"\n")
    s = _session(bare)
    with s.open_write("/main/notes.txt") as fh:
        fh.write(b"x")
