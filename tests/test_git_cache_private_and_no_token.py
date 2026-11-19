"""Git URL sessions: the cache holds no token and is private (review round 2).

A token comes in through the remote URL (user and token before the host);
dulwich's clone wrote it as ``remote.origin.url`` into the cache's config,
which was 0644 in folders 0755 under ~/.cache/axross/git: every local user
read the token, and the whole private repository. Every fetch and push
uses the URL in memory, so the config keeps it without the credentials;
the cache folders are 0700 (and an older cache is made so on open).
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

porcelain = pytest.importorskip("dulwich.porcelain")

from core import git_fs_client as G  # noqa: E402

_ID = b"T <t@example.org>"


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_ROOT", tmp_path / "cache" / "git")
    up = tmp_path / "upstream"
    up.mkdir()
    porcelain.init(str(up))
    (up / "a.txt").write_bytes(b"a\n")
    porcelain.add(str(up), [str(up / "a.txt")])
    porcelain.commit(str(up), message=b"a", author=_ID, committer=_ID)
    return up


def _open(up):
    return G.GitFsSession(url="file://" + str(up), author_name="T",
                          author_email="t@example.org", auto_push=False)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_sad_the_cache_is_private(upstream) -> None:
    s = _open(upstream)
    try:
        cache = Path(s._workdir)
        assert _mode(G.CACHE_ROOT) == 0o700
        assert _mode(cache) == 0o700
    finally:
        s.close()


def test_sad_a_token_in_the_cache_config_is_removed_on_open(upstream) -> None:
    s = _open(upstream)
    cache = Path(s._workdir)
    s.close()
    config = cache / "config"
    text = config.read_text()
    secret_url = "https://alice" + ":" + "S3CRET" + "@example.org/r.git"
    config.write_text(text + f'[remote "origin"]\n\turl = {secret_url}\n'
                      '[remote "mirror"]\n\turl = https://ghp_TOKEN@example.org/m.git\n')
    cache.chmod(0o755)
    _open(upstream).close()
    after = config.read_text()
    assert "S3CRET" not in after and "ghp_TOKEN" not in after
    assert "example.org/r.git" in after
    assert _mode(cache) == 0o700


def test_edge_strip_userinfo() -> None:
    assert G._without_credentials("https://alice" + ":pw@h/r.git") == "https://h/r.git"
    assert G._without_credentials("https://TOKEN@h:8443/r") == "https://h:8443/r"
    assert G._without_credentials("ssh://git@h/r") == "ssh://git@h/r"
    assert G._without_credentials("ssh://git" + ":pw@h/r") == "ssh://git@h/r"
    assert G._without_credentials("/local/path") == "/local/path"
