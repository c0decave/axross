"""The agent sandbox: protected places reached through symlinks (GNU stow,
chezmoi) and secret files (review 5 of the security audit).

Before: ``~/.bashrc -> dotfiles/bash/.bashrc`` was mounted read-only at its
typed path only, while its real file stayed writable through the
read-write ``~/dotfiles`` (round-5 security review). With
the home as the agent's folder the SSH and GnuPG private keys, the ADB key
and axross's tokens and keys were readable in the sandbox - the worker's
own read refusal is no guard once it is compromised
(sandbox/secrets_visible.py).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import protected_places as P  # noqa: E402

#: (core.protected_places.HOST_PATH_ENV; spelled out so the fixtures run on
#: the code before the fix too.)
_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    (real / "proj").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, _HOST_PATH_ENV, "XDG_RUNTIME_DIR",
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    return real


def _plan(root, **kw) -> dict:
    return {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(root), True, **kw)}


def _deepest(plan: dict, path: str):
    holder = max((p for p in plan if SB._inside(path, p)), key=len)
    return holder, plan[holder]


def _stow(home: Path) -> Path:
    (home / "dotfiles" / "bash").mkdir(parents=True)
    (home / "dotfiles" / "autostart").mkdir()
    real = home / "dotfiles" / "bash" / ".bashrc"
    real.write_text("# real bashrc\n")
    (home / ".bashrc").symlink_to("dotfiles/bash/.bashrc")
    (home / ".config").mkdir()
    (home / ".config" / "autostart").symlink_to("../dotfiles/autostart")
    return real


def test_sad_a_stowed_bashrc_is_read_only_at_its_real_path_too(home):
    real = _stow(home)
    plan = _plan(home)
    assert plan[str(home / ".bashrc")] == (False, "bind")
    holder, (rw, kind) = _deepest(plan, str(real))
    assert holder == str(real) and rw is False and kind == "bind"
    assert _deepest(plan, str(home / "dotfiles" / "autostart" / "x.desktop"))[1][0] is False
    assert plan[str(home / "dotfiles")][0] is True  # the rest of the dotfiles stays writable


def test_happy_bwrap_mounts_the_real_file_after_the_writable_folder(home):
    real = str(_stow(home))
    argv = SB._bwrap_command(SB.SandboxProfile(name="t"), str(home), True, ["true"])
    i = argv.index(real)
    assert argv[i - 1:i + 2] == ["--ro-bind", real, real]
    assert argv.index(str(home / "dotfiles")) < i


def test_edge_a_link_out_of_every_writable_folder_adds_no_mount(home, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / ".bashrc").write_text("# x\n")
    (home / ".bashrc").symlink_to(outside / ".bashrc")
    assert str(outside / ".bashrc") not in _plan(home / "proj") | _plan(home)


def test_edge_a_hard_linked_protected_file_is_logged(home, caplog):
    (home / "dotfiles").mkdir()
    (home / "dotfiles" / "bashrc").write_text("# x\n")
    os.link(home / "dotfiles" / "bashrc", home / ".bashrc")
    with caplog.at_level(logging.WARNING, logger=SB.log.name):
        _plan(home)
    assert any("hard links" in r.getMessage() for r in caplog.records)


SECRETS = (".ssh/id_ed25519", ".android/adbkey", ".config/axross/extension-code.key",
           ".config/axross/gdrive_token.p-1.json", ".gnupg/private-keys-v1.d/AB.key",
           ".netrc", ".local/share/keyrings/login.keyring")


def _secrets(home: Path) -> None:
    for rel in SECRETS:
        (home / rel).parent.mkdir(parents=True, exist_ok=True)
        (home / rel).write_text("SECRET")
    (home / ".ssh" / "id_ed25519.pub").write_text("public")


def test_sad_secrets_are_covered_when_the_home_is_the_agents_folder(home):
    _secrets(home)
    plan = _plan(home)
    for rel in SECRETS:
        holder, (rw, kind) = _deepest(plan, str(home / rel))
        assert rw is False and kind in ("dir", "hide"), (rel, holder, kind)
    assert plan[str(home / ".ssh")] == (False, "dir")  # all of it: a key may have any name
    assert plan[str(home / ".android" / "adbkey")] == (False, "hide")
    assert plan[str(home / ".gnupg" / "private-keys-v1.d")] == (False, "dir")


def test_happy_bwrap_and_containers_cover_secret_files_with_empty_ones(home):
    _secrets(home)
    key = str(home / ".android" / "adbkey")
    argv = SB._bwrap_command(SB.SandboxProfile(name="t"), str(home), True, ["true"])
    i = argv.index(key)
    assert argv[i - 2:i + 1] == ["--ro-bind", os.devnull, key]
    ssh = str(home / ".ssh")
    j = max(k for k, a in enumerate(argv) if a == ssh and argv[k - 1] == "--tmpfs")
    assert argv[j + 1:j + 3] == ["--remount-ro", ssh]
    for engine in ("podman", "docker"):
        prof = SB.SandboxProfile(name="t", engine=engine, image="img:x")
        cargv = SB._container_command(prof, engine, str(home), True, ["true"])
        assert f"{os.devnull}:{key}:ro" in cargv
        assert any(a.startswith(f"--tmpfs={ssh}:ro") for a in cargv)


def test_happy_a_folder_without_secrets_is_left_as_it_was(home):
    _secrets(home)
    plan = _plan(home / "proj")
    assert all(kind not in ("hide",) for _rw, kind in plan.values())
    assert list(plan) == [str(home / "proj")]


def test_edge_a_mount_that_names_the_secret_gives_it_on_purpose(home):
    _secrets(home)
    plan = _plan(home / "proj", extra=((str(home / ".ssh"), False),))
    assert plan[str(home / ".ssh")] == (False, "bind")


def test_edge_secrets_in_a_read_only_mount_are_covered_too(home):
    _secrets(home)
    plan = {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(home), False)}
    assert plan[str(home / ".ssh")] == (False, "dir")
    assert plan[str(home / ".netrc")] == (False, "hide")


def test_edge_a_symlinked_ssh_folder_is_covered_at_its_real_path(home):
    (home / "dotfiles" / "ssh").mkdir(parents=True)
    (home / "dotfiles" / "ssh" / "id_rsa").write_text("KEY")
    (home / ".ssh").symlink_to("dotfiles/ssh")
    plan = _plan(home)
    assert plan[str(home / "dotfiles" / "ssh")] == (False, "dir")


def test_happy_the_hosts_path_folders_in_the_home_reach_the_worker(home, monkeypatch):
    monkeypatch.setenv("PATH", f"{home}/bin2{os.pathsep}/usr/bin")
    assert (P.HOST_PATH_ENV, str(home / "bin2")) in SB._host_xdg_env()
