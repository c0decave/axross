"""MCP tools that act on a directory entry (remove, rename, transfer_move)
must act on a symlink itself, never on what it points to.

The root confinement resolves symlinks to keep a link from leading out
of the root. For an operation on the entry itself only the parent may be
resolved: resolving the final component handed the link's TARGET to the
backend, so ``remove(link, recursive=True)`` deleted the target folder
and ``rename(link, x)`` moved the target. The whole-path check stays as
a second gate, so a link that points out of the root is still refused.
"""

from __future__ import annotations

import json
import os

import pytest

from core import credentials
from core import profiles as P
from core.profiles import ConnectionProfile
from tests import mcp_group_testkit as T


@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)


@pytest.fixture(autouse=True)
def _fresh_connections():
    yield
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    (r / "data").mkdir(parents=True)
    (r / "data" / "keep.txt").write_text("precious")
    (r / "file.txt").write_text("file body")
    os.symlink("data", r / "dirlink")
    os.symlink("file.txt", r / "filelink")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("outside")
    return r


@pytest.fixture
def ram_profile(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    ram = ConnectionProfile(name="ram1", protocol="ramfs").to_dict()
    path.write_text(json.dumps({"ram1": ram}))


def _tools(root, groups=()):
    return T.build(root, set(groups), allow_write=True)


# -- happy -------------------------------------------------------------------


def test_happy_remove_recursive_on_a_dir_link_removes_only_the_link(root):
    T.call(_tools(root), "remove", {"path": str(root / "dirlink"), "recursive": True})
    assert not os.path.lexists(root / "dirlink")
    assert (root / "data" / "keep.txt").read_text() == "precious"


def test_happy_remove_on_a_file_link_removes_only_the_link(root):
    T.call(_tools(root), "remove", {"path": str(root / "filelink")})
    assert not os.path.lexists(root / "filelink")
    assert (root / "file.txt").read_text() == "file body"


def test_happy_rename_moves_the_link_not_its_target(root):
    T.call(_tools(root), "rename", {"src": str(root / "dirlink"), "dst": str(root / "moved")})
    assert os.path.islink(root / "moved")
    assert os.readlink(root / "moved") == "data"
    assert not os.path.lexists(root / "dirlink")
    assert (root / "data" / "keep.txt").read_text() == "precious"


def test_happy_transfer_move_on_the_same_backend_moves_the_link(root):
    tools = _tools(root, {"transfer"})
    T.call(tools, "transfer_move", {"src": str(root / "filelink"), "dst": str(root / "renamed")})
    assert os.path.islink(root / "renamed")
    assert not os.path.lexists(root / "filelink")
    assert (root / "file.txt").read_text() == "file body"


def test_happy_transfer_move_to_another_backend_keeps_the_target(root, ram_profile):
    tools = _tools(root, {"remote", "transfer"})
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    out = T.call(
        tools,
        "transfer_move",
        {"src": str(root / "filelink"), "dst_backend": bid, "dst": "/f.txt"},
    )
    assert out["bytes"] == len("file body")
    assert not os.path.lexists(root / "filelink")
    assert (root / "file.txt").read_text() == "file body"


# -- sad ---------------------------------------------------------------------


def test_sad_a_link_pointing_out_of_the_root_is_still_refused(root, tmp_path):
    os.symlink(str(tmp_path / "outside"), root / "escape")
    tools = _tools(root, {"transfer"})
    for name, args in (
        ("remove", {"path": str(root / "escape"), "recursive": True}),
        ("rename", {"src": str(root / "escape"), "dst": str(root / "e2")}),
    ):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, name, args)
        assert "escapes" in err.value.message
    assert (tmp_path / "outside" / "secret.txt").read_text() == "outside"
    assert os.path.islink(root / "escape")


def test_sad_a_symlinked_parent_out_of_the_root_is_refused(root, tmp_path):
    os.symlink(str(tmp_path / "outside"), root / "escape")
    tools = _tools(root, {"transfer"})
    target = str(root / "escape" / "secret.txt")
    for name, args in (
        ("remove", {"path": target}),
        ("rename", {"src": target, "dst": str(root / "stolen.txt")}),
        ("rename", {"src": str(root / "file.txt"), "dst": str(root / "escape" / "planted.txt")}),
        ("transfer_move", {"src": target, "dst": str(root / "stolen.txt")}),
    ):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, name, args)
        assert "escapes" in err.value.message
    assert (tmp_path / "outside" / "secret.txt").read_text() == "outside"
    assert not (tmp_path / "outside" / "planted.txt").exists()
    assert not (root / "stolen.txt").exists()


def test_sad_the_root_itself_is_still_refused(root):
    with pytest.raises(T.RpcError) as err:
        T.call(_tools(root), "remove", {"path": str(root), "recursive": True})
    assert "root" in err.value.message
    assert (root / "data" / "keep.txt").exists()


# -- edge --------------------------------------------------------------------


def test_edge_a_symlinked_parent_inside_the_root_is_still_followed(root):
    T.call(_tools(root), "remove", {"path": str(root / "dirlink" / "keep.txt")})
    assert not (root / "data" / "keep.txt").exists()
    assert os.path.islink(root / "dirlink")


def test_edge_a_dangling_link_inside_the_root_can_be_removed(root):
    os.symlink("not-there", root / "dangling")
    T.call(_tools(root), "remove", {"path": str(root / "dangling")})
    assert not os.path.lexists(root / "dangling")


def test_edge_a_relative_link_path_resolves_against_the_root(root):
    tools = _tools(root)
    T.call(tools, "rename", {"src": "dirlink", "dst": "moved"})
    assert os.path.islink(root / "moved")
    assert (root / "data" / "keep.txt").exists()


def test_edge_rename_onto_an_existing_link_is_refused(root):
    with pytest.raises(T.RpcError) as err:
        T.call(
            _tools(root), "rename", {"src": str(root / "file.txt"), "dst": str(root / "dirlink")}
        )
    assert "exists" in err.value.message
    assert os.path.islink(root / "dirlink")
    assert (root / "file.txt").exists()
