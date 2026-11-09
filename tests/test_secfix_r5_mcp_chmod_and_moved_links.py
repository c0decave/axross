"""MCP chmod of folders that hold protected places, and relative symlinks
re-pointed by a move (review 5 of the security audit).

Before: chmod was checked like a write of the path's contents, so
``chmod 0777 ~/.config`` (or ``~/.local``) went through - another local
user could then swap ``~/.config/autostart`` for their own
(round-5 security review). A symlink's relative target was
checked only where the link was made: made at ``a/b/l`` (``../../.ssh``
-> inside the root) and renamed to ``a/l`` it pointed out of the root
(mcp/relative_link_move.py).
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402

#: (core.protected_places.HOST_PATH_ENV; spelled out so the fixtures run on
#: the code before the fix too.)
_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    real.mkdir()
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, _HOST_PATH_ENV,
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    return real


def _call(tools, name, args) -> str:
    resp = M._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
    if "error" in resp:
        return "error: " + resp["error"]["message"]
    return "ok" if not resp["result"].get("isError") else "error: " + json.dumps(resp["result"])


def _tools(root, groups=None):
    kw = {"tool_groups": frozenset(groups)} if groups else {}
    return M._build_tools(LocalFS(), allow_write=True, root=str(root), **kw)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.mark.parametrize("rel", [".config", ".local", ".local/share"])
def test_sad_a_folder_holding_protected_places_is_not_made_writable_by_others(home, rel):
    for d in (".config/autostart", ".local/share/applications", ".local/bin"):
        (home / d).mkdir(parents=True, exist_ok=True)
    os.chmod(home / rel, 0o755)
    out = _call(_tools(home), "chmod", {"path": str(home / rel), "mode": "0777"})
    # Round 6: no tool makes anything group- or world-writable.
    assert out.startswith("error") and "group- or world-writable" in out
    assert _mode(home / rel) == 0o755
    out = _call(_tools(home), "chmod", {"path": str(home / rel), "mode": "0775"})
    assert out.startswith("error")


def test_happy_tightening_such_a_folder_and_chmod_elsewhere_still_work(home):
    # ~/go holds ~/go/bin (on PATH): a folder holding a protected place that
    # default-deny (round 6: hidden entries of the home) leaves alone.
    (home / "go" / "bin").mkdir(parents=True)
    (home / "proj").mkdir()
    tools = _tools(home)
    assert _call(tools, "chmod", {"path": str(home / "go"), "mode": "0700"}) == "ok"
    assert _mode(home / "go") == 0o700
    assert _call(tools, "chmod", {"path": str(home / "proj"), "mode": "0755"}) == "ok"
    assert _mode(home / "proj") == 0o755


def test_edge_the_protected_place_itself_stays_refused_for_any_mode(home):
    (home / ".ssh").mkdir()
    assert _call(_tools(home), "chmod", {"path": str(home / ".ssh"), "mode": "0700"}) \
        .startswith("error")


@pytest.fixture
def proj(home) -> Path:
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("KEY")
    root = home / "proj"
    (root / "a" / "b").mkdir(parents=True)
    return root


def test_sad_a_link_renamed_upward_is_checked_at_its_new_place(proj):
    """The reviewer's mcp/relative_link_move.py."""
    tools = _tools(proj)
    assert _call(tools, "symlink", {"target": "../../.ssh", "link_path": str(proj / "a" / "l")}) \
        .startswith("error")
    assert _call(tools, "symlink",
                 {"target": "../../.ssh", "link_path": str(proj / "a" / "b" / "l")}) == "ok"
    out = _call(tools, "rename", {"src": str(proj / "a" / "b" / "l"), "dst": str(proj / "a" / "l")})
    assert out.startswith("error") and "symlink would point" in out
    assert not os.path.lexists(proj / "a" / "l")
    assert os.path.islink(proj / "a" / "b" / "l")


def test_sad_a_folder_moved_upward_rechecks_the_links_in_it(proj):
    (proj / "a" / "b" / "c").mkdir()
    tools = _tools(proj)
    assert _call(tools, "symlink", {"target": "../../../.ssh",
                                    "link_path": str(proj / "a" / "b" / "c" / "l")}) == "ok"
    out = _call(tools, "rename", {"src": str(proj / "a" / "b"), "dst": str(proj / "b")})
    assert out.startswith("error") and "symlink would point" in out
    assert (proj / "a" / "b" / "c").is_dir() and not (proj / "b").exists()


def test_happy_links_that_point_where_they_did_or_inside_the_folder_move_freely(proj):
    venv = proj / "a" / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib64").symlink_to("lib")  # inside the moved folder
    (venv / "python").symlink_to("/usr/bin/python3")  # absolute: unchanged by a move
    (venv / "up").symlink_to("../../../proj")  # leads to the root from a/venv and from x/venv
    tools = _tools(proj)
    (proj / "x").mkdir()
    assert _call(tools, "rename", {"src": str(venv), "dst": str(proj / "x" / "venv")}) == "ok"
    assert os.readlink(proj / "x" / "venv" / "lib64") == "lib"
    # Renamed in its own folder: every ".." leads where it did.
    assert _call(tools, "rename", {"src": str(proj / "x" / "venv"),
                                   "dst": str(proj / "x" / "venv2")}) == "ok"


def test_edge_a_link_that_stays_inside_the_root_is_moved(proj):
    (proj / "data").mkdir()
    tools = _tools(proj)
    assert _call(tools, "symlink", {"target": "../../data",
                                    "link_path": str(proj / "a" / "b" / "l")}) == "ok"
    (proj / "a" / "b" / "c").mkdir()
    out = _call(tools, "rename", {"src": str(proj / "a" / "b" / "l"),
                                  "dst": str(proj / "a" / "b" / "c" / "l")})
    assert out == "ok"  # now ../../data is a/data: still inside the root


def test_sad_transfer_move_of_a_link_is_checked_too(proj):
    tools = _tools(proj, {"transfer"})
    os.symlink("../../.ssh", proj / "a" / "b" / "l")
    out = _call(tools, "transfer_move", {"src": str(proj / "a" / "b" / "l"),
                                         "dst": str(proj / "a" / "l")})
    assert out.startswith("error")
    assert not os.path.lexists(proj / "a" / "l")
