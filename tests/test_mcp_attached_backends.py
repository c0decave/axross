"""Connections the GUI already holds, lent to the MCP tools (the agent).

The agent sees the remote connections open in the panes as backends
``pane:<name>``: reachable with ``backend=`` like a profile opened with
remote_open, remote in every sense (paths only shape-checked, never
confined to the local root; a production profile refuses every
mutation). They stay the GUI's: remote_close refuses them and closing
the registry never releases them. A gate (the sandbox's allowed hosts)
decides on every call whether a connection may be used at all.
"""

from __future__ import annotations

import pytest

from core import mcp_groups as G
from core.profiles import ConnectionProfile
from core.ram_fs import RamFsSession
from tests import mcp_group_testkit as T


def _ram(name="pane-ram"):
    ram = RamFsSession(name)
    ram.mkdir("/data")
    with ram.open_write("/data/f.txt") as handle:
        handle.write(b"remote text")
    return ram


def _profile(name="box", host="files.example", port=22, production=False):
    return ConnectionProfile(
        name=name, protocol="sftp", host=host, port=port, production=production
    )


def _tools(tmp_path, registry, groups=(), **kw):
    return T.build(tmp_path, set(groups), remote_registry=registry, **kw)


# -- happy ---------------------------------------------------------------------


def test_happy_an_attached_connection_is_read_with_its_id(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    tools = _tools(tmp_path, registry)
    out = T.call(
        tools, "read_file", {"path": "/data/f.txt", "encoding": "text", "backend": "pane:box"}
    )
    assert "remote text" in str(out)


def test_happy_list_backends_names_the_attached_connection(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    rows = T.call(_tools(tmp_path, registry), "list_backends")
    pane = [r for r in rows if r["id"] == "pane:box"]
    assert pane and pane[0]["remote"] is True and pane[0]["profile"] == "box"
    assert any(r["id"] == "local" for r in rows)


def test_happy_writes_reach_an_attached_connection_outside_the_local_root(tmp_path):
    registry = G.RemoteRegistry()
    ram = _ram()
    registry.attach("pane:box", ram, _profile())
    tools = _tools(tmp_path, registry, allow_write=True)
    T.call(tools, "write_file", {"path": "/data/new.txt", "content": "x", "backend": "pane:box"})
    with ram.open_read("/data/new.txt") as handle:
        assert handle.read() == b"x"


# -- sad -----------------------------------------------------------------------


def test_sad_remote_close_refuses_a_connection_of_the_gui(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    tools = _tools(tmp_path, registry, groups=("remote",))
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "remote_close", {"backend": "pane:box"})
    assert "pane" in err.value.message
    assert registry.get("pane:box") is not None


def test_sad_closing_the_registry_never_releases_an_attached_connection(tmp_path, monkeypatch):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    released = []

    class _Manager:
        def release(self, profile):
            released.append(profile.name)

    monkeypatch.setattr(registry, "_connections", lambda: _Manager())
    registry.close_all()
    assert released == []


def test_sad_a_production_connection_refuses_writes(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:prod", _ram(), _profile(name="prod", production=True))
    tools = _tools(tmp_path, registry, allow_write=True)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "write_file", {"path": "/data/x.txt", "content": "x", "backend": "pane:prod"})
    assert "production" in err.value.message


def test_sad_the_gate_refuses_a_connection_on_every_call(tmp_path):
    allowed = {"files.example"}

    def gate(profile):
        if profile is None or profile.host not in allowed:
            raise PermissionError("not an allowed host of this sandbox")

    registry = G.RemoteRegistry(gate=gate)
    registry.attach("pane:box", _ram(), _profile())
    tools = _tools(tmp_path, registry)
    args = {"path": "/data/f.txt", "encoding": "text", "backend": "pane:box"}
    assert "remote text" in str(T.call(tools, "read_file", args))
    allowed.clear()  # the sandbox profile changed at run time
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "read_file", args)
    assert "allowed host" in err.value.message


def test_sad_the_gate_refuses_remote_open_before_connecting(tmp_path, monkeypatch):
    from core import profiles as P

    monkeypatch.setattr(
        P.ProfileManager, "get", lambda self, name: _profile(name=name, host="evil.example")
    )
    connected = []
    monkeypatch.setattr(G.RemoteRegistry, "_connections", lambda self: connected.append(1))

    def gate(profile):
        raise PermissionError(f"{profile.host} is not an allowed host")

    registry = G.RemoteRegistry(gate=gate)
    with pytest.raises(PermissionError, match="evil.example"):
        registry.open("box")
    assert connected == []


# -- edge ----------------------------------------------------------------------


def test_edge_an_attached_id_is_unique(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    with pytest.raises(ValueError):
        registry.attach("pane:box", _ram("other"), _profile())


def test_edge_attaching_only_needs_no_remote_group(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:box", _ram(), _profile())
    tools = _tools(tmp_path, registry)
    assert "remote_open" not in tools and "list_backends" in tools


def test_edge_an_attached_connection_without_a_profile_is_still_remote(tmp_path):
    registry = G.RemoteRegistry()
    registry.attach("pane:ram", _ram(), None)
    tools = _tools(tmp_path, registry, allow_write=True)
    T.call(tools, "write_file", {"path": "/data/y.txt", "content": "y", "backend": "pane:ram"})
    # The local root still confines the local backend.
    with pytest.raises(T.RpcError):
        T.call(tools, "read_file", {"path": "/etc/hostname", "encoding": "text"})
