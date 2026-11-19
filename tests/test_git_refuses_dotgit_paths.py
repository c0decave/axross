"""Git: no ``.git`` path component and no invalid branch name is committed.

Protocol review (round 1): writing ``/main/vendor/lib/.git/config`` or
``/main/.GIT/hooks/post-checkout`` (a project folder with its own .git
dragged into a Git pane) was committed and pushed; afterwards ``git
clone`` of the branch failed for everyone ("invalid path") and ``git
fsck`` warned hasDotgit. A branch named by the path's first part was
taken as it was: ``/-x/f`` made ``refs/heads/-x``, ``/a..b/f`` failed
with "repository object ... may be corrupt". Both are refused up front
now, as git's own verify_path and check-ref-format refuse them.
"""

from __future__ import annotations

import errno
import subprocess

import pytest

pytest.importorskip("dulwich")

from core.git_fs_client import GitFsSession  # noqa: E402


@pytest.fixture
def session(tmp_path):
    bare = tmp_path / "r.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
    seed = tmp_path / "seed"
    subprocess.run(["git", "clone", "-q", str(bare), str(seed)], check=True, capture_output=True)
    (seed / "README").write_text("x\n")
    git = ["git", "-C", str(seed), "-c", "user.name=t", "-c", "user.email=t@x"]
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "seed"], check=True)
    subprocess.run([*git, "push", "-q", "origin", "main"], check=True, capture_output=True)
    s = GitFsSession(path=str(bare), author_name="t", author_email="t@e")
    yield s
    s.close()


def _write(s, path, data=b"1"):
    with s.open_write(path) as f:
        f.write(data)


@pytest.mark.parametrize("path", [
    "/main/vendor/lib/.git/config",
    "/main/.GIT/hooks/post-checkout",
    "/main/a/.git",
    "/main/.git./x",
    "/main/GIT~1/x",
])
def test_sad_dotgit_component_is_refused(session, path):
    with pytest.raises(OSError) as info:
        _write(session, path)
    assert info.value.errno == errno.EINVAL
    assert ".git" in str(info.value)


def test_sad_rename_into_dotgit_is_refused(session):
    with pytest.raises(OSError) as info:
        session.rename("/main/README", "/main/sub/.git/README")
    assert info.value.errno == errno.EINVAL


@pytest.mark.parametrize("path", ["/-x/f", "/a..b/f", "/x.lock/f", "/a b/f"])
def test_sad_invalid_new_branch_name_is_refused(session, path):
    with pytest.raises(OSError) as info:
        _write(session, path)
    assert info.value.errno == errno.EINVAL
    assert "branch" in str(info.value).lower()


def test_happy_ordinary_names_still_commit(session):
    _write(session, "/main/docs/.gitignore", b"*.o\n")
    _write(session, "/main/my.git.notes", b"n\n")
    _write(session, "/feature-1/f", b"new branch\n")
    with session.open_read("/main/docs/.gitignore") as f:
        assert f.read() == b"*.o\n"
    session.remove("/main/my.git.notes")
