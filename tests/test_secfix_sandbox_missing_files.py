"""Missing protected FILES cannot be created in the agent sandbox
(pre-release security review 4).

Before: core.agent_sandbox mounted a missing protected folder as an empty
read-only one, but skipped a missing protected file (``~/.bash_profile``,
``~/.zshenv``, ``~/.xsession``, ``~/.gitconfig``, ``~/.npmrc``,
``~/.claude.json``, ...): with the home folder writable, a compromised worker
created it and ran code on the host at the next login. A placeholder file on
the host is no fix (an empty ``~/.bash_profile`` left by a crash makes bash
skip ``~/.profile``). Now the folder such a file would be made in is a
read-only *frame* in the sandbox: a tmpfs of the sandbox's own that holds a
mount of each of its entries - the host's folder is never touched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import protected_places as P  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """A usual Debian home: .profile, .bashrc, .config and a project."""
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    (real / "proj").mkdir()
    (real / "notes.txt").write_text("mine\n")
    (real / ".bashrc").write_text("# shell\n")
    (real / ".profile").write_text("# login\n")
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 "XDG_CACHE_HOME", *(host for _p, _v, host in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    return real


def _plan(root: Path, writable: bool = True, extra=()) -> dict[str, tuple[bool, str]]:
    return {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(root), writable, extra)}


def _bwrap(root: Path) -> list[str]:
    argv = SB.sandbox_command(SB.SandboxProfile(name="t", engine="bubblewrap"), str(root),
                              writable=True)
    return argv[argv.index("bwrap"):]


def _missing_files(home: Path) -> list[str]:
    return [p for p, folder in P.protected_paths() if not folder and not os.path.lexists(p)]


def test_sad_no_missing_protected_file_stays_writable(home):
    """The reviewer's sandbox/missing_files.py: every missing protected
    file lies in a read-only mount of the plan - and nothing is made on the host."""
    plan = _plan(home)
    missing = _missing_files(home)
    assert str(home / ".bash_profile") in missing and str(home / ".zshenv") in missing
    for place in missing:
        holder = max((p for p in plan if SB._inside(place, p)), key=len)
        assert plan[holder][0] is False, (place, holder, plan[holder])
    assert plan[str(home)] == (False, "frame")
    points = SB._mount_points(SB._mount_plan(SB.SandboxProfile(name="t"), str(home), True))
    _bwrap(home)
    assert not set(missing) & set(points)  # no mount point is made for them
    assert all(not os.path.lexists(p) for p in missing)


def test_sad_bwrap_makes_the_home_a_read_only_frame(home):
    argv = _bwrap(home)
    h = str(home)
    triples = [argv[i:i + 3] for i in range(len(argv) - 2)]
    assert ["--bind", h, h] not in triples  # the host's home is not mounted itself
    tmpfs = [i for i, a in enumerate(argv[:-1]) if a == "--tmpfs" and argv[i + 1] == h][0] + 1
    # The host's entries, as writable as the home was; protected ones read-only.
    for name in ("proj", "notes.txt", ".config", ".profile"):
        path = str(home / name)
        i = argv.index(path)
        rw = name != ".profile"
        assert argv[i - 1:i + 2] == ["--bind-try" if rw else "--ro-bind", path, path], name
        assert i > tmpfs
    assert argv[argv.index(str(home / ".bashrc")) - 1] == "--ro-bind"
    # Read-only after every mount in it was made (bwrap makes their mount
    # points in the tmpfs, not on the host).
    remount = len(argv) - 1 - argv[::-1].index("--remount-ro")
    assert argv[remount:remount + 2] == ["--remount-ro", h]
    dests = [argv[i + 2] for i, a in enumerate(argv[:-2])
             if a in ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try", "--tmpfs")
             and SB._inside(argv[i + 2], h) and argv[i + 2] != h]
    assert dests and all(argv.index(d) < remount for d in dests)
    assert not any(str(home / ".bash_profile") in a for a in argv)


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_sad_containers_frame_the_home_too(home, engine):
    argv = SB.sandbox_command(SB.SandboxProfile(name="t", engine=engine, image="img:x"),
                              str(home), writable=True)
    assert f"{home}:{home}:rw" not in argv
    assert f"--tmpfs={home}:rw,nosuid,nodev,noexec,mode=0555" in argv
    assert f"{home / 'proj'}:{home / 'proj'}:rw" in argv
    assert f"{home / '.bashrc'}:{home / '.bashrc'}:ro" in argv
    frame = argv.index(f"--tmpfs={home}:rw,nosuid,nodev,noexec,mode=0555")
    assert frame < argv.index(f"{home / 'proj'}:{home / 'proj'}:rw")


def test_edge_a_symlink_in_the_frame_stays_a_link(home, tmp_path):
    """Bound, a link out of the home would mount its target writable."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "out").symlink_to(outside)
    plan = _plan(home)
    assert plan[str(home / "out")] == (True, "link")
    argv = _bwrap(home)
    i = argv.index(str(home / "out"))
    assert argv[i - 2:i + 1] == ["--symlink", str(outside), str(home / "out")]
    assert str(outside) not in [argv[j + 1] for j, a in enumerate(argv) if "bind" in a]
    podman = SB.sandbox_command(SB.SandboxProfile(name="t", engine="podman", image="i"),
                                str(home), writable=True)
    assert not any(str(home / "out") in a for a in podman)  # left out there


def test_edge_an_existing_pip_folder_is_a_frame_of_its_own(home):
    (home / ".pip").mkdir()
    (home / ".pip" / "keep.txt").write_text("x\n")
    plan = _plan(home)
    assert plan[str(home / ".pip")] == (False, "frame")
    assert plan[str(home / ".pip" / "pip.conf")] == (False, "absent")
    assert plan[str(home / ".pip" / "keep.txt")] == (True, "entry")


def test_edge_a_frame_reached_through_a_link_is_its_target(home):
    """~/.pip -> ~/dotfiles/pip: pip.conf would be made in the target."""
    (home / "dotfiles" / "pip").mkdir(parents=True)
    (home / ".pip").symlink_to(home / "dotfiles" / "pip")
    plan = _plan(home)
    assert plan[str(home / "dotfiles" / "pip")] == (False, "frame")
    assert plan[str(home / ".pip")][1] == "link"


def test_edge_folders_of_the_profile_keep_their_own_mount(home):
    """A read-only extra folder inside the framed home stays read-only."""
    plan = _plan(home, extra=((str(home / "proj"), False),))
    assert plan[str(home / "proj")] == (False, "bind")
    assert plan[str(home / "notes.txt")] == (True, "entry")
    assert plan[str(home)] == (False, "frame")
