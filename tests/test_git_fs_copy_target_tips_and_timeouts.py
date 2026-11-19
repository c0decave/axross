"""Git-as-FS: a copy onto a branch folder, the branch map during a
refresh, and remotes that never answer.

Before:

* ``copy("/main/a.txt", "/main")`` - a drop onto the branch folder -
  raised nothing and committed a tree entry WITHOUT A NAME: the pane
  showed a nameless file, ``git ls-tree main`` failed with "empty filename
  in tree entry", ``git fsck`` reported a bad tree, and in a URL session
  that commit was pushed to origin.
* ``_refresh_branch_tips`` emptied the branch map and filled it again
  while listings in other threads read it without the lock: they found
  "No such branch: main".
* dulwich's transports wait without a limit: a remote that accepted the
  connection and never answered held the session for ever (and a write
  holds the session lock meanwhile, so every pane on it).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("dulwich")

from core import git_fs_client as G  # noqa: E402

_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")


def _git(cwd, *args) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True, env=_ENV).stdout


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    (work / "a.txt").write_text("hello\n")
    _git(work, "add", "a.txt")
    _git(work, "commit", "-q", "-m", "init")
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
    return bare


@pytest.mark.parametrize("target", ["/main", "/main/", "/"])
def test_sad_a_copy_onto_the_branch_folder_is_refused_and_writes_nothing(repo, target):
    s = G.GitFsSession(path=str(repo), author_name="t", author_email="t@e")
    before = _git(repo, "rev-parse", "main")
    with pytest.raises(OSError):
        s.copy("/main/a.txt", target)
    assert _git(repo, "rev-parse", "main") == before
    _git(repo, "fsck", "--full")  # no bad tree
    assert [i.name for i in s.list_dir("/main")] == ["a.txt"]


def test_happy_a_copy_to_a_file_name_still_works(repo):
    s = G.GitFsSession(path=str(repo), author_name="t", author_email="t@e")
    s.copy("/main/a.txt", "/main/b.txt")
    assert sorted(_git(repo, "ls-tree", "--name-only", "main").split()) == ["a.txt", "b.txt"]


def test_edge_a_listing_during_a_refresh_still_sees_the_branches(repo):
    s = G.GitFsSession(path=str(repo), author_name="t", author_email="t@e")
    seen: list[set] = []
    real_get_refs = s._repo.get_refs

    def get_refs():
        # What a listing in another thread reads while the refresh runs.
        seen.append(set(s._branch_tips))
        return real_get_refs()

    s._repo.get_refs = get_refs
    s._refresh_branch_tips()
    assert seen == [{"main"}]
    assert set(s._branch_tips) == {"main"}


# ------------------------------------------------------------ time-outs


def test_happy_https_and_ssh_remotes_get_time_outs():
    http = G._with_network_timeouts("https://git.example/r.git", {})
    assert http["pool_manager"].connection_pool_kw["timeout"].read_timeout == G.GIT_READ_TIMEOUT
    ssh = G._with_network_timeouts("git@git.example:team/r.git", {})
    assert f"ConnectTimeout={G.GIT_CONNECT_TIMEOUT}" in ssh["ssh_command"]
    assert "ServerAliveInterval=" in ssh["ssh_command"]
    keep = G._with_network_timeouts("ssh://h/r", {"ssh_command": "ssh -o HostKeyAlias=h"})
    assert keep["ssh_command"].startswith("ssh -o HostKeyAlias=h ")
    assert G._with_network_timeouts("/srv/repo.git", {}) == {}


def test_happy_a_proxy_pool_gets_the_time_out_too():
    import urllib3

    pool = urllib3.PoolManager()
    G._with_network_timeouts("https://git.example/r.git", {"pool_manager": pool})
    assert pool.connection_pool_kw["timeout"].read_timeout == G.GIT_READ_TIMEOUT


def test_sad_an_http_remote_that_never_answers_fails_in_time(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    monkeypatch.setattr(G, "GIT_READ_TIMEOUT", 1)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    held: list = []
    threading.Thread(target=lambda: [held.append(srv.accept()) for _ in range(5)],
                     daemon=True).start()
    result: dict = {}

    def run():
        try:
            G.GitFsSession(url=f"http://127.0.0.1:{srv.getsockname()[1]}/r.git",
                           author_name="t", author_email="t@e")
            result["r"] = "opened"
        except BaseException as exc:  # noqa: BLE001
            result["r"] = exc

    thread = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(30)
    try:
        assert not thread.is_alive(), "still waiting for a remote that never answers"
        assert isinstance(result["r"], Exception)
        assert time.monotonic() - started < 30
    finally:
        srv.close()


def test_sad_a_git_daemon_that_never_answers_fails_in_time(tmp_path, monkeypatch):
    """git:// (dulwich's TCPGitClient) made its socket without a timeout:
    a daemon - or a proxy tunnel - that took the connection and never
    answered held the session for ever."""
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache")
    monkeypatch.setattr(G, "GIT_READ_TIMEOUT", 1)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    held: list = []
    threading.Thread(target=lambda: [held.append(srv.accept()) for _ in range(5)],
                     daemon=True).start()
    result: dict = {}

    def run():
        try:
            G.GitFsSession(url=f"git://127.0.0.1:{srv.getsockname()[1]}/r.git",
                           author_name="t", author_email="t@e")
            result["r"] = "opened"
        except BaseException as exc:  # noqa: BLE001
            result["r"] = exc

    thread = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(20)
    try:
        assert not thread.is_alive(), "still waiting for a git daemon that never answers"
        assert isinstance(result["r"], Exception)
        assert time.monotonic() - started < 20
    finally:
        srv.close()


def test_edge_the_git_daemon_socket_waits_to_connect_then_per_answer(monkeypatch):
    import dulwich.client as dulwich_client

    assert dulwich_client.socket.socket is G._GitDaemonSocket
    assert dulwich_client.socket.AF_UNSPEC == socket.AF_UNSPEC  # the rest is the module
    monkeypatch.setattr(G, "GIT_CONNECT_TIMEOUT", 3)
    monkeypatch.setattr(G, "GIT_READ_TIMEOUT", 7)
    srv = socket.create_server(("127.0.0.1", 0))
    s = G._GitDaemonSocket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(srv.getsockname())
        assert s.gettimeout() == 7
    finally:
        s.close()
        srv.close()
