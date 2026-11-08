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
    mounts = dict(AS._agent_mounts(AS.SandboxProfile(name="t"), str(home), True))
    assert mounts[str(home)] is True
    assert mounts[str(home / ".bashrc")] is False
    assert mounts[str(home / ".ssh")] is False
    assert str(home / ".gitconfig") not in mounts  # missing: nothing to mount
    order = [p for p, _rw in AS._agent_mounts(AS.SandboxProfile(name="t"), str(home), True)]
    assert order.index(str(home)) < order.index(str(home / ".bashrc"))  # parents first


def test_edge_a_read_only_root_adds_no_mounts(home):
    (home / ".bashrc").write_text("# shell\n")
    mounts = dict(AS._agent_mounts(AS.SandboxProfile(name="t"), str(home), False))
    assert list(mounts) == [str(home)]
