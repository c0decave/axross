"""Round-8 security L5: private folders and the packs folder.

core.self_update.private_dir_problem walked the parents as written only
(``~/.cache`` a symlink into a world-writable folder passed) and accepted a
parent its group may write; core.packs.activate put the folders of
$XDG_DATA_HOME/axross/packs/<version> on sys.path with no check at all - a
folder others may write had its planted module imported.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="owners and modes are POSIX")


@pytest.fixture
def no_private_group(monkeypatch):
    monkeypatch.setattr(SU, "_private_group", lambda *a: False, raising=False)


def test_happy_a_fresh_private_folder_is_used(tmp_path):
    folder = tmp_path / "cache" / "axross" / "update"
    assert SU.private_dir_problem(folder) == ""
    assert (folder.stat().st_mode & 0o777) == 0o700


def test_sad_a_symlinked_parent_into_a_world_writable_folder_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # not sticky: anyone may rename c away
    real = shared / "c" / "axross" / "update"
    real.mkdir(parents=True)
    for p in (real, real.parent, real.parent.parent):
        p.chmod(0o700)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".cache").symlink_to(shared / "c")
    problem = SU.private_dir_problem(home / ".cache" / "axross" / "update", create=False)
    assert str(shared) in problem and "other users" in problem


def test_sad_a_parent_its_group_may_write_is_refused(tmp_path, no_private_group):
    folder = tmp_path / "cache" / "axross" / "update"
    folder.mkdir(parents=True)
    folder.chmod(0o700)
    folder.parent.chmod(0o775)
    problem = SU.private_dir_problem(folder, create=False)
    assert "can be changed by other users" in problem and "chmod go-w" in problem


def test_edge_the_users_own_group_and_a_sticky_parent_are_fine(tmp_path, monkeypatch):
    folder = tmp_path / "cache" / "axross" / "update"
    folder.mkdir(parents=True)
    folder.chmod(0o700)
    folder.parent.chmod(0o775)
    monkeypatch.setattr(SU, "_private_group", lambda *a: True, raising=False)
    assert SU.private_dir_problem(folder, create=False) == ""
    monkeypatch.setattr(SU, "_private_group", lambda *a: False, raising=False)
    folder.parent.chmod(0o1777)
    assert SU.private_dir_problem(folder, create=False) == ""


# -- packs ------------------------------------------------------------------------------------

VERSION = "9.9.9"
BLOB = "planted-1.0-py3-none-any.whl"


def _installed(root: Path, module: str) -> Path:
    folder = root / VERSION
    blob = folder / BLOB
    (blob / module).mkdir(parents=True)
    (blob / module / "__init__.py").write_text("RAN = True\n")
    sha = "0" * 64
    (blob / ".axross-sha256").write_text(sha + "\n")
    state = {"units": ["u"], "manifest": {"units": {"u": {"blobs": [BLOB]}},
                                          "blobs": {BLOB: {"sha256": sha, "size": 1}}}}
    (folder / "installed.json").write_text(json.dumps(state))
    for p in (root, folder, blob):
        p.chmod(0o755)
    return folder


def test_happy_a_private_packs_folder_is_activated(tmp_path, no_private_group):
    root = tmp_path / "packs"
    folder = _installed(root, "axross_r8_pack_ok")
    assert P.activate(VERSION, root=root, path=[]) == [str(folder / BLOB)]


@pytest.mark.parametrize("which", ["root", "version", "blob"])
def test_sad_a_packs_folder_others_may_write_puts_nothing_on_the_path(tmp_path, which,
                                                                      no_private_group):
    root = tmp_path / "packs"
    folder = _installed(root, "axross_r8_pack_planted")
    {"root": root, "version": folder, "blob": folder / BLOB}[which].chmod(0o777)
    path: list = []
    assert P.activate(VERSION, root=root, path=path) == [] and path == []


def test_sad_activate_now_refuses_a_folder_others_may_write(tmp_path, no_private_group):
    root = tmp_path / "packs"
    folder = _installed(root, "axross_r8_pack_now")
    folder.chmod(0o777)
    with pytest.raises(P.PackError, match="other users"):
        P.activate_now(VERSION, ["u"], root=root, path=[])


def test_edge_a_missing_version_folder_adds_nothing(tmp_path):
    assert P.activate(VERSION, root=tmp_path / "packs", path=[]) == []
