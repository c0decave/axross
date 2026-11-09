"""Protected places on macOS and Windows, on PATH, in site-packages, and
where the user's XDG variables move them (review 5 of the security audit).

Before: core.protected_places listed Linux places only. With the home as
the MCP root, macOS launchd agents, the Windows Startup folder and
PowerShell profiles, ~/bin and ~/.cargo/bin, the pipx / uv tool venvs (a
.pth file there runs at every start of that Python), ~/.tmux.conf,
~/.config/mimeapps.list, ~/.emacs.d/init.el and openbox's autostart were
written (round-5 security review). An MCP server
started without the user's XDG variables (by a desktop client) did not
protect ``$XDG_CONFIG_HOME/axross`` (mcp/xdg_env_mismatch.py).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402

#: (core.protected_places.HOST_PATH_ENV; spelled out so the fixtures run on
#: the code before the fix too.)
_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    real.mkdir()
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, _HOST_PATH_ENV, "APPDATA", "LOCALAPPDATA",
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    getattr(P, "_PROFILE_CACHE", {}).clear()
    return real


def _tools(root):
    from core.local_fs import LocalFS

    return M._build_tools(LocalFS(), allow_write=True, root=str(root))


def _write(tools, path) -> bool:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    resp = M._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "write_file", "arguments": {"path": str(path), "content": "x"}}},
        tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
    return "error" not in resp and not resp.get("result", {}).get("isError")


@pytest.mark.parametrize("rel", [
    "Library/LaunchAgents/com.evil.plist",
    "Library/Application Support/axross/settings.json",
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.bat",
    "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    "Documents/WindowsPowerShell/profile.ps1",
    "AppData/Roaming/axross/x", "AppData/Local/axross/x",
    "bin/ls", ".cargo/bin/git", "go/bin/x",
    ".local/share/pipx/venvs/axross/lib/python3.12/site-packages/evil.pth",
    ".local/share/uv/tools/axross/lib/python3.12/site-packages/x.py",
    ".tmux.conf", ".config/mimeapps.list", ".emacs.d/init.el", ".config/openbox/autostart",
])
def test_sad_the_reviewers_gaps_are_refused_through_mcp(home, rel):
    assert not _write(_tools(home), home / rel)
    assert not (home / rel).exists()


def test_happy_ordinary_files_of_the_home_stay_writable(home):
    tools = _tools(home)
    assert _write(tools, home / "notes.txt")
    assert _write(tools, home / "proj" / "src" / "main.py")
    assert _write(tools, home / "Documents" / "letter.txt")


def test_sad_a_folder_on_path_in_the_home_is_protected(home, monkeypatch):
    monkeypatch.setenv("PATH", f"{home}/tools/bin{os.pathsep}/usr/bin")
    assert P.refusal(str(home / "tools" / "bin" / "ls"))
    assert P.refusal(str(home / "tools"), entry=True)  # replacing its holder
    assert P.refusal(str(home / "tools" / "README")) is None


def test_edge_the_home_itself_on_path_does_not_protect_the_whole_home(home, monkeypatch):
    monkeypatch.setenv("PATH", f"{home}{os.pathsep}/usr/bin")
    assert P.refusal(str(home / "notes.txt")) is None


def test_sad_the_host_path_reaches_the_worker_in_the_sandbox(home, monkeypatch):
    monkeypatch.setenv(P.HOST_PATH_ENV, f"{home}/opt/bin")
    assert P.refusal(str(home / "opt" / "bin" / "x"))


def test_sad_python_start_files_are_refused_anywhere(home):
    for rel in ("proj/.venv/lib/python3.12/site-packages/evil.pth", "x/sitecustomize.py",
                "usercustomize.py", "a/EVIL.PTH" if sys.platform in ("win32", "darwin") else "a/e.pth"):
        assert P.refusal(str(home / rel)), rel
    assert P.refusal(str(home / "proj" / "pth.txt")) is None


def test_sad_site_packages_of_sys_path_in_the_home_are_protected(home, monkeypatch):
    site = home / "venvs" / "app" / "lib" / "python3.12" / "site-packages"
    monkeypatch.setattr(sys, "path", [*sys.path, str(site)])
    assert P.refusal(str(site / "pkg" / "__init__.py"))


def test_sad_windows_appdata_is_protected_where_the_variable_moves_it(home, tmp_path,
                                                                      monkeypatch):
    roaming = tmp_path / "Roaming"
    monkeypatch.setenv("APPDATA", str(roaming))
    assert P.refusal(str(roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                         / "Startup" / "x.lnk"))
    assert P.refusal(str(roaming / "axross" / "settings.json"))


def test_edge_windows_spellings_of_the_startup_folder(home, monkeypatch):
    monkeypatch.setattr(P, "_case_insensitive", lambda: True)
    monkeypatch.setattr(P, "_windows_names", lambda: True)
    for rel in ("appdata/roaming/microsoft/windows/start menu/programs/startup./x.bat",
                "Documents/PowerShell /profile.ps1", "AppData/Local/axross:stream"):
        assert P.refusal(str(home / rel)), rel


def test_sad_xdg_folders_the_gui_ran_with_are_protected_without_the_variable(home):
    """The reviewer's mcp/xdg_env_mismatch.py: the GUI records them."""
    target = home / ".xdgconf" / "autostart" / "x.desktop"
    mcp_env = {"HOME": str(home)}
    assert P.refusal(str(target), environ=mcp_env) is None  # nothing known yet
    P.remember_xdg({"XDG_CONFIG_HOME": str(home / ".xdgconf")})
    assert (home / ".config" / "axross" / "xdg-locations.json").is_file()
    assert P.refusal(str(target), environ=mcp_env)
    assert P.refusal(str(home / ".xdgconf" / "axross" / "settings.json"), environ=mcp_env)
    # The record itself lies in a protected place wherever XDG points.
    assert P.refusal(str(home / ".config" / "axross" / "xdg-locations.json"), environ=mcp_env)


@pytest.mark.parametrize("line", ['export XDG_CONFIG_HOME="$HOME/.cfg"',
                                  "XDG_CONFIG_HOME=${HOME}/.cfg",
                                  "XDG_CONFIG_HOME DEFAULT=@{HOME}/.cfg"])
def test_sad_xdg_folders_set_in_the_profile_are_protected(home, line):
    profile = ".pam_environment" if "DEFAULT" in line else ".profile"
    (home / profile).write_text(f"# x\n{line}\n")
    assert P.refusal(str(home / ".cfg" / "autostart" / "x.desktop"), environ={"HOME": str(home)})


def test_edge_a_relative_or_unknown_xdg_value_in_the_profile_is_ignored(home):
    (home / ".profile").write_text("XDG_CONFIG_HOME=cfg\nXDG_DATA_HOME=$OTHER/x\n")
    assert P.refusal(str(home / "cfg" / "autostart" / "x"), environ={"HOME": str(home)}) is None
    P.remember_xdg({"XDG_CONFIG_HOME": "relative/cfg"})
    assert not (home / ".config" / "axross" / "xdg-locations.json").exists()


def test_edge_the_sandbox_lists_other_platforms_places_only_where_they_exist(home):
    if sys.platform in ("darwin", "win32"):
        pytest.skip("checks the places of another platform")
    agents = str(home / "Library" / "LaunchAgents")
    assert agents in [p for p, _f in P.protected_paths()]  # refused through MCP
    assert agents not in [p for p, _f in P.protected_paths(foreign_missing=False)]
    os.makedirs(agents)
    assert agents in [p for p, _f in P.protected_paths(foreign_missing=False)]
