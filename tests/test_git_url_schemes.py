"""git+https:// and git+http:// reach the server over HTTP(S).

Probe through axross.open_url("git+https://github.com/c0decave/axross.git"):
dulwich.errors.HangupException. open_url maps every git+ scheme to the git
backend and hands the URL on as it is; dulwich reads "git+https://" as an
SSH URL with an empty host and the path "//github.com/..." (SSHGitClient),
so the clone ran ssh and the far end hung up. The backend now strips the
"git+" of git+http(s) before dulwich sees it; git+ssh, which dulwich knows,
and plain URLs are left alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")

from dulwich.client import get_transport_and_path  # noqa: E402

from core import git_fs_client as G  # noqa: E402


@pytest.fixture
def cloned(monkeypatch, tmp_path):
    """Run the constructor up to the clone and record the URL it used."""
    seen = []

    def fake_clone(url, target, **kwargs):
        seen.append(url)
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(G.porcelain, "clone", fake_clone)
    monkeypatch.setattr(G, "_cache_dir_for", lambda url: tmp_path / "cache")

    def run(url):
        with pytest.raises(RuntimeError, match="stop before the network"):
            G.GitFsSession(url=url)
        return seen[-1]

    return run


# --- happy ----------------------------------------------------------------


def test_happy_git_plus_https_clones_over_https(cloned):
    url = cloned("git+https://github.com/c0decave/axross.git")
    assert url == "https://github.com/c0decave/axross.git"
    client, _ = get_transport_and_path(url)
    assert "Http" in type(client).__name__


def test_happy_git_plus_http_clones_over_http(cloned):
    assert cloned("git+http://lab.example/repo.git") == "http://lab.example/repo.git"


# --- sad ------------------------------------------------------------------


def test_sad_the_raw_git_plus_https_url_is_ssh_to_dulwich():
    # The failure itself: what dulwich makes of the unmapped URL.
    client, path = get_transport_and_path("git+https://github.com/c0decave/axross.git")
    assert type(client).__name__ == "SSHGitClient" and path.startswith("//")


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "git+ssh://git@github.com/c0decave/axross.git",
        "https://github.com/c0decave/axross.git",
        "git://lab.example/repo.git",
    ],
)
def test_edge_other_schemes_are_left_alone(cloned, url):
    assert cloned(url) == url


def test_edge_the_scheme_prefix_is_matched_case_insensitively(cloned):
    assert cloned("GIT+HTTPS://lab.example/r.git") == "https://lab.example/r.git"
