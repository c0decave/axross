"""MCP capability group ``extensions``: extensions_list / extensions_info.

Extensions are GUI plugins: activate(api) receives a Qt ExtensionAPI
(ui/extension_host.py) that adds menu actions, context actions and docks.
There is no headless action to run, so the group only reports what is
installed and enabled - and never imports an extension's code.
"""

from __future__ import annotations

import pytest

from core import extensions as EX
from core import mcp_server as M
from core import security_mode
from tests import mcp_group_testkit as T

GOOD = '''
EXTENSION = {"name": "Good One", "version": "1.2", "description": "does things", "author": "me"}
open(MARKER, "w").write("imported")

def activate(api):
    pass
'''


@pytest.fixture
def ext_home(tmp_path, monkeypatch):
    folder = tmp_path / "extensions"
    folder.mkdir()
    marker = tmp_path / "imported.marker"
    (folder / "good.py").write_text(GOOD.replace("MARKER", repr(str(marker))))
    (folder / "broken.py").write_text("def activate(api): pass\n")  # no manifest
    settings = tmp_path / "extensions.json"
    settings.write_text('{"enabled": ["user:good"]}')
    monkeypatch.setattr(EX, "extensions_dir", lambda: folder)
    monkeypatch.setattr(EX, "settings_file", lambda: settings)
    return tmp_path, marker


def _ext(tmp_path, write=True):
    return T.build(tmp_path, {"extensions"}, allow_write=write)


def test_happy_list_reports_state_without_importing(ext_home):
    tmp_path, marker = ext_home
    out = T.call(_ext(tmp_path), "extensions_list", {})
    by_id = {e["id"]: e for e in out["extensions"]}
    good = by_id["user:good"]
    assert good["name"] == "Good One" and good["version"] == "1.2"
    assert good["enabled"] is True and good["loadable"] is True and good["source"] == "user"
    assert by_id["user:broken"]["loadable"] is False and by_id["user:broken"]["error"]
    assert out["allowed"] is True and out["runnable_over_mcp"] is False
    assert any(e["source"] == "bundled" for e in out["extensions"])
    assert not marker.exists()  # discovery parses, it never imports


def test_happy_info_explains_why_nothing_runs(ext_home):
    tmp_path, _ = ext_home
    info = T.call(_ext(tmp_path), "extensions_info", {"ext_id": "user:good"})
    assert info["id"] == "user:good" and info["enabled"] is True
    assert info["runnable_over_mcp"] is False and "GUI" in info["why_not_runnable"]


def test_sad_unknown_extension_and_bad_args(ext_home):
    tmp_path, _ = ext_home
    tools = _ext(tmp_path)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "extensions_info", {"ext_id": "user:nope"})
    assert "user:nope" in err.value.message
    for args in ({}, {"ext_id": ""}, {"ext_id": 3}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "extensions_info", args)
        assert err.value.code == M.ERR_INVALID_PARAMS
    with pytest.raises(T.RpcError):
        T.call(tools, "extensions_list", {"x": 1})


def test_edge_paranoid_mode_reports_extensions_blocked(ext_home):
    tmp_path, _ = ext_home
    security_mode.set_policy("paranoid")
    try:
        out = T.call(_ext(tmp_path), "extensions_list", {})
    finally:
        security_mode.set_policy("normal")
    assert out["allowed"] is False
    assert all(e["active"] is False for e in out["extensions"])


def test_edge_group_has_no_mutating_tool_and_no_backend_argument(ext_home):
    tmp_path, _ = ext_home
    tools = {n: t for n, t in _ext(tmp_path).items() if t.group == "extensions"}
    assert set(tools) == {"extensions_list", "extensions_info"}
    assert not any(t.write for t in tools.values())
    assert all(t.accepts_backend is False for t in tools.values())


def test_edge_unreadable_settings_mean_nothing_enabled(ext_home):
    tmp_path, _ = ext_home
    (tmp_path / "extensions.json").write_text("{not json")
    out = T.call(_ext(tmp_path), "extensions_list", {})
    assert not any(e["enabled"] for e in out["extensions"])
