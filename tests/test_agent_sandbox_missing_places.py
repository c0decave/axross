"""The agent sandbox keeps missing protected places from being created, and
the list covers more places that run code (review 2 of 0.15.176).

Before: core.agent_sandbox mounted only the protected places that existed.
In a usual home (``~/.bashrc`` and ``~/.config`` there; no
``~/.config/autostart``, ``~/.bash_profile``, ``~/.local/bin``) a
compromised worker, with the home mounted writable, created
``~/.config/autostart/x.desktop`` or ``~/.bash_profile`` and ran code on the
host at the next login. ``~/.claude/settings.json``, ``~/.claude.json``,
``~/.config/containers``, user systemd units and D-Bus services below
``~/.local/share``, ``~/.bashrc.d``, ``~/.zlogout``, oh-my-zsh, vim and
neovim, ``~/.npmrc`` and the i3 / sway / Hyprland settings were not
protected at all, and places moved by ``$XDG_CONFIG_HOME`` /
``$XDG_DATA_HOME`` were not either.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """A usual home: .bashrc, .profile and .config exist, the rest does not."""
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    (real / ".bashrc").write_text("# shell\n")
    (real / ".profile").write_text("# login\n")
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 *(host for _p, _v, host in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    return real


def _argv(engine: str, root: Path, writable: bool = True, extra=()) -> list[str]:
    profile = SB.SandboxProfile(name="t", engine=engine, level="normal", image="img:x")
    argv = SB.sandbox_command(profile, str(root), writable=writable, extra=extra)
    return argv[argv.index("bwrap"):] if engine == "bubblewrap" else argv


def _after(argv: list[str], flag: str) -> list[tuple[str, str]]:
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv[:-2]) if a == flag]


def test_sad_bwrap_mounts_a_missing_protected_folder_as_an_empty_read_only_one(home):
    """A missing ~/.config/autostart was writable through the home's mount."""
    argv = _argv("bubblewrap", home)
    place = str(home / ".config" / "autostart")
    assert place in [argv[j + 1] for j, a in enumerate(argv) if a == "--tmpfs"]
    k = argv.index(place)
    assert argv[k - 1] == "--tmpfs" and argv[k + 1:k + 3] == ["--remount-ro", place]
    assert argv.index("--bind-try") < k  # after the ~/.config it lies in
    assert argv[argv.index("--bind-try") + 1] == str(home / ".config")
    assert not os.path.exists(place)  # nothing is made by building the command


def test_sad_a_missing_protected_file_gets_no_placeholder_on_the_host(home):
    """A missing file is not mounted: the engine would create its mount
    point in the real home, and an empty ~/.bash_profile left by a crash
    hides ~/.profile from every later login (an empty ~/.vimrc switches off
    vim's defaults). The home is a read-only frame in the sandbox instead
    (core.agent_sandbox; tests/test_secfix_sandbox_missing_files.py)."""
    argv = _argv("bubblewrap", home)
    sources = {dest: src for src, dest in _after(argv, "--ro-bind")}
    for rel in (".bash_profile", ".claude.json", ".pip/pip.conf", ".vimrc"):
        assert str(home / rel) not in sources
        assert not (home / rel).exists()
        with pytest.raises(PermissionError):
            M._refuse_protected(str(home / rel))
    assert sources[str(home / ".bashrc")] == str(home / ".bashrc")  # existing: itself


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_sad_containers_mount_missing_places_read_only_too(home, engine):
    argv = _argv(engine, home)
    # The home holds missing protected files: a frame (core.agent_sandbox).
    assert f"--tmpfs={home}:rw,nosuid,nodev,noexec,mode=0555" in argv
    assert f"{home / '.config'}:{home / '.config'}:rw" in argv
    assert any(a.startswith(f"--tmpfs={home / '.config' / 'autostart'}:ro") for a in argv)
    assert any(a.startswith(f"--tmpfs={home / '.local' / 'bin'}:ro") for a in argv)
    assert not [v for v in argv if v.endswith(f":{home / '.bash_profile'}:ro")]
    assert f"{home / '.bashrc'}:{home / '.bashrc'}:ro" in argv


def test_edge_a_read_only_mount_takes_no_missing_places(home):
    """Inside a read-only folder nothing can be created - and bwrap could
    not make the mount point there."""
    assert [p for p, _rw in SB._agent_mounts(SB.SandboxProfile(name="t"), str(home), False)] \
        == [str(home)]
    mounts = dict(SB._agent_mounts(SB.SandboxProfile(name="t"), str(home), True,
                                   extra=((str(home / ".config"), False),)))
    assert mounts[str(home / ".config")] is False
    assert str(home / ".config" / "autostart") not in mounts
    assert mounts[str(home / ".local" / "bin")] is False  # still inside the writable home


def test_edge_a_place_behind_a_link_out_of_the_writable_folder_is_left_out(home, tmp_path):
    """~/.config pointing outside every writable mount: the agent cannot
    write there, and a mount point could not be made."""
    os.rmdir(home / ".config")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / ".config").symlink_to(elsewhere)
    mounts = dict(SB._agent_mounts(SB.SandboxProfile(name="t"), str(home), True))
    assert str(home / ".config" / "autostart") not in mounts
    assert mounts[str(home / ".local" / "bin")] is False  # the rest still is


@pytest.mark.parametrize("rel", [
    ".claude/settings.json", ".claude.json", ".config/containers/registries.conf",
    ".local/share/systemd/user/evil.service",
    ".local/share/dbus-1/services/org.freedesktop.Notifications.service",
    ".bashrc.d/evil.sh", ".zlogout", ".oh-my-zsh/custom/evil.zsh", ".vimrc",
    ".config/nvim/init.lua", ".npmrc", ".config/i3/config", ".config/sway/config",
    ".config/hypr/hyprland.conf",
    ".config/Claude/claude_desktop_config.json", ".cursor/mcp.json",
    ".config/Code/User/settings.json", ".config/autostart-scripts/x.sh",
    ".ipython/profile_default/startup/00.py", ".docker/config.json",
])
def test_sad_more_places_that_run_code_are_protected(home, rel):
    with pytest.raises(PermissionError):
        M._refuse_protected(str(home / rel))


def test_sad_places_moved_by_xdg_are_protected_in_both_locations(home, tmp_path, monkeypatch):
    config, data = tmp_path / "cfg", tmp_path / "data"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    for path in (config / "autostart" / "x.desktop", home / ".config" / "autostart" / "x.desktop",
                 data / "systemd" / "user" / "x.service", data / "applications" / "x.desktop",
                 config / "axross" / "agent" / "settings.json"):
        assert P.refusal(str(path)), path
    assert P.refusal(str(config / "notes.txt")) is None


def test_sad_inside_the_sandbox_the_hosts_xdg_places_stay_protected(home, tmp_path,
                                                                   monkeypatch):
    """The worker's environment is cleared: the host's XDG folders come in
    variables of their own, and the mounts cover them."""
    config = home / "cfg"
    config.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    argv = _argv("bubblewrap", home)
    host_var = dict((v, h) for _p, v, h in P.XDG_PLACES)["XDG_CONFIG_HOME"]
    assert (host_var, str(config)) in _after(argv, "--setenv")
    assert str(config / "autostart") in argv  # mounted read-only as well
    assert f"--env={host_var}={config}" in _argv("podman", home)
    # The worker: HOME is /tmp, the variable names the host's folder.
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "sandbox-tmp"))
    monkeypatch.setenv(host_var, str(config))
    with pytest.raises(PermissionError):
        M._refuse_protected(str(config / "systemd" / "user" / "x.service"))


def test_happy_mount_points_are_removed_when_the_last_sandbox_ends(home, monkeypatch):
    """bwrap and podman create the mount point of a missing place on the
    host; left there, an empty ~/.bash_profile hides ~/.profile from the
    next login shell. It goes when the last sandbox using it has ended -
    not before (that would drop the running sandbox's mount)."""
    monkeypatch.setattr(SB, "available", lambda engine: True)
    profile = SB.SandboxProfile(name="P", engine="bubblewrap", level="normal")
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio",
                                              endpoint="http://127.0.0.1:9/v1"),
                           root=str(home), allow_write=True)
    first, second = SB.SandboxedAgent(config, profile), SB.SandboxedAgent(config, profile)
    first._argv(profile)
    # What the engine does at start:
    (home / ".config" / "autostart").mkdir()
    (home / ".local" / "share" / "systemd" / "user").mkdir(parents=True)
    second._argv(profile)  # sees them made, not the user's
    assert str(home / ".config" / "autostart") in second._points
    first._release_points()
    assert (home / ".config" / "autostart").is_dir()
    (home / ".local" / "share" / "keep.txt").write_text("the user's\n")
    second._release_points()
    assert not (home / ".config" / "autostart").exists()
    assert not (home / ".local" / "share" / "systemd").exists()
    assert (home / ".local" / "share" / "keep.txt").exists()  # not empty: kept
    assert (home / ".config").is_dir() and (home / ".bashrc").exists()  # were there before
    assert not SB._POINTS_IN_USE


def test_edge_a_mount_point_someone_wrote_to_stays(home):
    points = SB._mount_points(SB._mount_plan(SB.SandboxProfile(name="t"), str(home), True))
    SB._hold_mount_points(points)
    (home / ".local" / "bin").mkdir(parents=True, exist_ok=True)
    (home / ".local" / "bin" / "tool").write_text("echo bye\n")
    SB._release_mount_points(points)
    assert (home / ".local" / "bin" / "tool").read_text() == "echo bye\n"
    assert not SB._POINTS_IN_USE
