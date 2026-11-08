"""DFS-N: the DFS switch and the referral lookup do something.

``_enable_dfs_locked`` passed ``client_dfs_enabled=True`` to
smbclient's ClientConfig - an option smbclient does not have; the real
knob is ``skip_dfs``. A ``skip_dfs=True`` set elsewhere stayed, and the
DFS-N backend resolved no referral. ``referral_for`` asked
``smbclient._pool.lookup_tree``, which does not exist: it answered None
for every path. The switch now sets ``skip_dfs=False`` and the lookup
reads smbclient's referral cache.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

smbclient = pytest.importorskip("smbclient")

from core.dfsn_client import DFSNamespaceSession, DfsReferral  # noqa: E402


@pytest.fixture
def config():
    cfg = smbclient.ClientConfig()
    before = cfg.skip_dfs
    yield cfg
    cfg.set(skip_dfs=before)


def test_sad_enable_dfs_turns_skip_dfs_off(config) -> None:
    config.set(skip_dfs=True)
    DFSNamespaceSession._enable_dfs_locked()
    assert smbclient.ClientConfig().skip_dfs is False


def test_sad_referral_for_reads_the_referral_cache(config, monkeypatch) -> None:
    asked: list[list[str]] = []
    entry = SimpleNamespace(target_hint=SimpleNamespace(target_path="\\\\fs01\\projects"))

    def lookup(components):
        asked.append(components)
        return entry if components[:3] == ["corp.local", "dfs", "projects"] else None

    monkeypatch.setattr(config, "lookup_referral", lookup)
    s = DFSNamespaceSession.__new__(DFSNamespaceSession)
    s._prefix = "\\\\corp.local\\dfs"
    assert s.referral_for("/projects") == DfsReferral(
        namespace_path="/projects", target_path="\\\\fs01\\projects", ttl_seconds=0
    )
    assert s.referral_for("/other") is None
    assert asked[0] == ["corp.local", "dfs", "projects"]
