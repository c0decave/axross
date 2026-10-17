"""axross itself in a container: when the agent's sandbox cannot start
there, the error says what the container needs - never a run without the
sandbox.

Measured 2026-10-17 in podman (keep-id, cap-drop=ALL, no-new-privileges):
bubblewrap failed with "Can't mount proc on /newroot/proc" (podman masks
/proc paths) and, on high/paranoid, "cannot open
/proc/sys/user/max_user_namespaces: Read-only file system"; with
``--security-opt unmask=/proc/*`` (scripts/axross-podman.sh --agent-sandbox)
every test of tests/test_agent_sandbox.py passed. podman inside podman
failed at newuidmap (the outer user namespace maps no further ids)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402

_DYING = "import sys; sys.stderr.write({msg!r} + '\\n'); sys.exit(1)"


def _agent(tmp_path, message):
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path))
    return SB.SandboxedAgent(
        config,
        SB.SandboxProfile(name="N", engine="bubblewrap", level="normal"),
        command=[sys.executable, "-c", _DYING.format(msg=message)],
    )


def _error(agent) -> str:
    with pytest.raises(A.AgentError) as caught:
        agent.run("hi")
    agent.close()
    return str(caught.value)


def test_happy_in_a_container_a_masked_proc_names_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: True)
    text = _error(
        _agent(tmp_path, "bwrap: Can't mount proc on /newroot/proc: Operation not permitted")
    )
    assert "Can't mount proc" in text
    assert "unmask=/proc/*" in text and "--agent-sandbox" in text


def test_happy_a_read_only_proc_sys_names_the_same_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: True)
    text = _error(_agent(tmp_path, "bwrap: cannot open /proc/sys/user/max_user_namespaces: "
                                   "Read-only file system"))
    assert "unmask=/proc/*" in text


def test_sad_outside_a_container_no_container_advice(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: False)
    text = _error(
        _agent(tmp_path, "bwrap: Can't mount proc on /newroot/proc: Operation not permitted")
    )
    assert "unmask" not in text and "Can't mount proc" in text


def test_sad_another_failure_gets_no_advice(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: True)
    text = _error(_agent(tmp_path, "worker: something else broke"))
    assert "unmask" not in text and "bubblewrap" not in text


def test_edge_podman_inside_a_container_points_to_bubblewrap(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: True)
    text = _error(
        _agent(tmp_path, 'Error: cannot set up namespace using "/usr/bin/newuidmap": exit status 1')
    )
    assert "bubblewrap" in text and "newuidmap" in text


def test_edge_in_container_reads_the_engines_marker_files(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "_CONTAINER_MARKERS", (str(tmp_path / ".containerenv"),))
    assert SB.in_container() is False
    (tmp_path / ".containerenv").write_text("")
    assert SB.in_container() is True


# podman without cgroup delegation (no systemd user session): measured
# 2026-10-17 with a scratch XDG_RUNTIME_DIR - runc refuses the level's limits.
_NO_CGROUPS = (
    "Error: runc: runc create failed: unable to start container process: unable to apply cgroup "
    "configuration: rootless needs no limits + no cgrouppath when no permission is granted for "
    "cgroups: mkdir /sys/fs/cgroup/user.slice/x: permission denied: OCI permission denied"
)


def test_happy_podman_without_cgroups_says_why_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "in_container", lambda: False)
    text = _error(_agent(tmp_path, _NO_CGROUPS))
    assert "systemd user session" in text and "bubblewrap" in text
