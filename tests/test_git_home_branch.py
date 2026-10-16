"""A Git pane opens on a branch the repository has.

URL write matrix against a local repository whose only branch is
"master": home() answered "/main" - the constructor's default_branch -
and every operation there failed with "No such branch: main". Nobody
passes default_branch (core/, ui/), so the backend now follows the
repository's HEAD branch unless one is named, then "main", then the
first branch there is.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")

from core.git_fs_client import GitFsSession  # noqa: E402


def _repo(tmp_path, *branches, head=None):
    repo = tmp_path / "repo"
    first = branches[0] if branches else "master"
    subprocess.run(["git", "init", "-q", "-b", first, str(repo)], check=True)
    if branches:
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-q", "--allow-empty", "-m", "i"],
            check=True,
        )
        for b in branches[1:]:
            subprocess.run(["git", "-C", str(repo), "branch", b], check=True)
    if head:
        subprocess.run(["git", "-C", str(repo), "symbolic-ref", "HEAD", f"refs/heads/{head}"], check=True)
    return str(repo)


# --- happy ----------------------------------------------------------------


def test_happy_a_master_only_repo_opens_on_master(tmp_path):
    s = GitFsSession(path=_repo(tmp_path, "master"))
    assert s.home() == "/master"
    assert s.list_dir(s.home()) == []


def test_happy_the_head_branch_wins_over_main(tmp_path):
    s = GitFsSession(path=_repo(tmp_path, "main", "develop", head="develop"))
    assert s.home() == "/develop"


# --- sad ------------------------------------------------------------------


def test_sad_a_named_branch_that_is_missing_is_not_used(tmp_path):
    s = GitFsSession(path=_repo(tmp_path, "master"), default_branch="release")
    assert s.home() == "/master"


# --- edge -----------------------------------------------------------------


def test_edge_a_named_branch_that_exists_is_used(tmp_path):
    s = GitFsSession(path=_repo(tmp_path, "main", "release"), default_branch="release")
    assert s.home() == "/release"


def test_edge_an_empty_repository_opens_at_the_root(tmp_path):
    s = GitFsSession(path=_repo(tmp_path))
    assert s.home() == "/"
