"""The agent's protected home places hold in the sandbox, through symlinks,
and on Windows and macOS spellings (review 1 of 0.15.176).

Before: core.mcp_server took the home folder from ``expanduser("~")``,
which is ``/tmp`` inside the agent sandbox, while the real home is mounted
writable at its own path: ``~/.bashrc`` and the agent's own settings were
unguarded there. A symlink created at a missing ``~/.config`` led every
later write around ``~/.config/autostart``. ``.bash_aliases``,
``~/.local/bin``, user site-packages ``.pth`` files and ``~/.gitconfig``
were missing from the list, and the comparison was by string: Windows
separators and macOS case never matched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as AS  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    real.mkdir()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    return real


def test_sad_in_the_sandbox_the_host_home_stays_protected(home, tmp_path, monkeypatch):
    sandbox_home = tmp_path / "sandbox-tmp"
    sandbox_home.mkdir()
    monkeypatch.setenv("HOME", str(sandbox_home))  # the worker's HOME is /tmp
    monkeypatch.setenv(P.HOST_HOME_ENV, str(home))
    for rel in (".bashrc", ".config/axross/agent/settings.json"):
        with pytest.raises(PermissionError):
            M._refuse_protected(str(home / rel))
    assert M._refuse_protected(str(home / "notes.txt")) == str(home / "notes.txt")


def test_sad_a_symlink_at_a_missing_config_does_not_lead_around_autostart(home):
    stage = home / "stage"
    (stage / "autostart").mkdir(parents=True)
    with pytest.raises(PermissionError):
        M._refuse_protected(str(home / ".config"), entry=True)  # the link's entry
    (home / ".config").symlink_to(stage)  # made anyway (by hand, another program)
    with pytest.raises(PermissionError):
        M._refuse_protected(str(stage / "autostart" / "evil.desktop"))


@pytest.mark.parametrize("rel", [".bash_aliases", ".xsession", ".local/bin/ls",
                                 ".local/lib/python3.11/site-packages/evil.pth", ".gitconfig",
                                 ".config/git/config", ".config/pip/pip.conf",
                                 ".config/plasma-workspace/env/x.sh"])
def test_sad_more_places_that_run_code_are_protected(home, rel):
    with pytest.raises(PermissionError):
        M._refuse_protected(str(home / rel))


def test_edge_case_insensitive_systems_compare_without_case(home, monkeypatch):
    monkeypatch.setattr(P, "_case_insensitive", lambda: True)
    with pytest.raises(PermissionError):
        M._refuse_protected(str(home / ".SSH" / "authorized_keys"))
    monkeypatch.setattr(P, "_case_insensitive", lambda: False)
    assert P.refusal(str(home / ".SSH" / "authorized_keys")) is None


def test_edge_places_are_joined_per_component():
    """op.join(home, ".config/axross") mixed separators on Windows."""
    assert all("/" not in p[len("/h"):] or os.sep == "/" for p in P.places("/h"))
    assert os.path.join("/h", ".config", "axross") in P.places("/h")


def test_happy_the_sandbox_mounts_existing_protected_places_read_only(home):
    (home / ".bashrc").write_text("# shell\n")
    (home / ".ssh").mkdir()
    plan = {p: (rw, kind) for p, rw, kind in
            AS._mount_plan(AS.SandboxProfile(name="t"), str(home), True)}
    mounts = {p: rw for p, (rw, _kind) in plan.items()}
    assert mounts[str(home / ".bashrc")] is False
    assert mounts[str(home / ".ssh")] is False
    # A missing file gets no placeholder on the host (a crash leaving an
    # empty ~/.bash_profile hides ~/.profile): the home is a read-only frame
    # in the sandbox, so nothing can be made in it (core.agent_sandbox).
    assert plan[str(home)] == (False, "frame")
    assert plan[str(home / ".gitconfig")] == (False, "absent")
    assert not (home / ".gitconfig").exists()
    order = [p for p, _rw in AS._agent_mounts(AS.SandboxProfile(name="t"), str(home), True)]
    assert order.index(str(home)) < order.index(str(home / ".bashrc"))  # parents first


def test_edge_a_read_only_root_adds_no_mounts(home):
    (home / ".bashrc").write_text("# shell\n")
    mounts = dict(AS._agent_mounts(AS.SandboxProfile(name="t"), str(home), False))
    assert list(mounts) == [str(home)]


def test_sad_windows_trailing_dots_spaces_and_streams_name_the_same_file(home, monkeypatch):
    """Windows drops trailing dots and spaces when it opens a name, and
    ``name:stream`` writes the file's alternate stream: ``.claude.json.``,
    ``.claude \\settings.json`` and ``.bashrc:x`` got past the guard
    (review 3 of 0.15.176)."""
    monkeypatch.setattr(P, "_case_insensitive", lambda: True)
    monkeypatch.setattr(P, "_windows_names", lambda: True)
    for rel in (".claude.json.", ".claude.json ", ".claude /settings.json", ".bashrc:evil",
                ".SSH./authorized_keys"):
        assert P.refusal(str(home / rel)), rel
    assert P.refusal(str(home / "notes.txt.")) is None


def test_edge_posix_keeps_trailing_dots_as_part_of_the_name(home, monkeypatch):
    """On Linux ``.bashrc.`` is another file than ``.bashrc``."""
    monkeypatch.setattr(P, "_case_insensitive", lambda: False)
    monkeypatch.setattr(P, "_windows_names", lambda: False)
    assert P.refusal(str(home / ".bashrc.")) is None
    assert P.refusal(str(home / ".bashrc"))
