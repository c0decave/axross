"""rsync: argv, ports, time limits and messages (connection review 2026-11).

* A failed rsync was "rsync exited with code 5: @ERROR: auth failed on
  module x" - or ssh's "Host key verification failed." - wrapped in
  "Cannot connect to rsync server h: ...". Failures now map to what
  core.user_errors explains (refused, unknown host, time-out, permission)
  or to a sentence that says what to do (login, SSH host key, module).
* SSH mode with the daemon's port 873 still in the profile ran
  ``ssh -p 873``; a daemon profile with the profile default 22 (an
  imported profile) dialled the SSH server. Each mode now takes its own
  default for the other mode's port.
* rename() and remove() of a large folder had wall-clock limits of
  120 / 300 s: a copy that was still moving data failed half done. They
  use rsync's stall limit now, as open_read and uploads do. Connecting has
  its own limit (--contimeout / ssh ConnectTimeout).
* A host or user name starting with "-" became an rsync option (the
  ``user@host:path`` argument comes first); refused.
* SSH mode without --protect-args: an rsync before 3.2.4 (RHEL 8/9) let
  the remote shell split "a b" and expand "$x" in remote paths.
* address_family: -4 / -6 for the daemon socket, ssh -4 / -6 in SSH mode.

No rsync binary needed: subprocess.run is replaced by a recorder.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import rsync_client as RC  # noqa: E402
from core.user_errors import describe  # noqa: E402

LISTING = "drwxr-xr-x          4,096 2024/01/15 10:30:00 .\n"


class _Recorder:
    def __init__(self):
        self.calls: list[tuple[list[str], dict]] = []
        self.answers: list[tuple[int, str, str]] = []

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        rc, out, err = self.answers.pop(0) if self.answers else (0, LISTING, "")
        return subprocess.CompletedProcess(cmd, rc, out, err)


@pytest.fixture
def rec(monkeypatch):
    r = _Recorder()
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    monkeypatch.setattr(RC.subprocess, "run", r)
    return r


def _session(**kw):
    kw.setdefault("host", "srv.example")
    return RC.RsyncSession(**kw)


def _ssh_cmd(cmd: list[str]) -> str:
    return cmd[cmd.index("-e") + 1]


# --- ports -------------------------------------------------------------------


def test_happy_ssh_mode_with_the_daemon_port_uses_ssh_default(rec):
    _session(port=873, ssh_mode=True)
    ssh = _ssh_cmd(rec.calls[0][0])
    assert " -p " not in ssh


def test_happy_ssh_mode_with_a_real_port_passes_it(rec):
    _session(port=2222, ssh_mode=True)
    assert " -p 2222" in _ssh_cmd(rec.calls[0][0])


def test_sad_daemon_mode_with_the_ssh_default_port_dials_873(rec):
    _session(port=22, module="m")
    cmd = rec.calls[0][0]
    assert "--port" not in cmd
    assert cmd[-1] == "rsync://srv.example/m/"


def test_edge_daemon_mode_with_another_port(rec):
    _session(port=8873, module="m")
    cmd = rec.calls[0][0]
    assert cmd[cmd.index("--port") + 1] == "8873"


# --- argv safety ----------------------------------------------------------------


@pytest.mark.parametrize("field", ["host", "username"])
def test_sad_a_name_starting_with_a_dash_is_refused(rec, field):
    with pytest.raises(OSError):
        _session(ssh_mode=True, **{field: "-oProxyCommand=touch /tmp/x"})
    assert rec.calls == []


def test_happy_ssh_mode_protects_remote_paths(rec):
    s = _session(ssh_mode=True)
    s.list_dir("/a b/$(id)")
    cmd = rec.calls[-1][0]
    assert "--protect-args" in cmd
    assert cmd[-1] == "srv.example:/a b/$(id)/"


def test_edge_daemon_mode_keeps_its_arguments(rec):
    _session(module="m")
    assert "--protect-args" not in rec.calls[0][0]


def test_happy_the_password_travels_in_the_environment_only(rec):
    _session(module="m", username="u", password="s3cret")
    cmd, kw = rec.calls[0]
    assert all("s3cret" not in a for a in cmd)
    assert kw["env"]["RSYNC_PASSWORD"] == "s3cret"


# --- address family ---------------------------------------------------------------


@pytest.mark.parametrize("family, flag", [("ipv4", "-4"), ("ipv6", "-6")])
def test_happy_address_family_in_daemon_mode(rec, family, flag):
    _session(module="m", address_family=family)
    assert flag in rec.calls[0][0]


@pytest.mark.parametrize("family, flag", [("ipv4", "-4"), ("ipv6", "-6")])
def test_happy_address_family_in_ssh_mode(rec, family, flag):
    _session(ssh_mode=True, address_family=family)
    assert f"ssh {flag} " in _ssh_cmd(rec.calls[0][0])


def test_edge_auto_adds_nothing(rec):
    _session(module="m")
    assert "-4" not in rec.calls[0][0] and "-6" not in rec.calls[0][0]


# --- time limits ----------------------------------------------------------------------


def test_happy_connecting_has_its_own_limit(rec):
    _session(module="m")
    assert any(a.startswith("--contimeout=") for a in rec.calls[0][0])
    _session(ssh_mode=True)
    assert "ConnectTimeout=" in _ssh_cmd(rec.calls[-1][0])


def test_sad_rename_of_a_large_folder_has_no_wall_clock(rec, monkeypatch):
    s = _session(module="m")
    monkeypatch.setattr(s, "is_dir", lambda p: True)

    def stat(path):
        if path == "/new":
            raise FileNotFoundError(path)
        return RC.FileItem(name=path.strip("/"), is_dir=True)

    monkeypatch.setattr(s, "stat", stat)
    monkeypatch.setattr(s, "remove", lambda *a, **k: None)
    rec.calls.clear()
    s.rename("/old", "/new")
    copies = [(c, kw) for c, kw in rec.calls]
    assert len(copies) == 2
    for cmd, kw in copies:
        assert kw["timeout"] is None
        assert f"--timeout={RC.STALL_TIMEOUT}" in cmd


def test_sad_remove_of_a_large_folder_has_no_wall_clock(rec, monkeypatch):
    s = _session(module="m")
    monkeypatch.setattr(s, "list_dir", lambda p: [])
    rec.calls.clear()
    s._remove_entry("/big", True, True)
    assert rec.calls
    for cmd, kw in rec.calls:
        assert kw["timeout"] is None
        assert f"--timeout={RC.STALL_TIMEOUT}" in cmd


# --- messages -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rc, stderr, ssh, expect",
    [
        (5, "@ERROR: auth failed on module m\nrsync error: error starting client-server "
            "protocol (code 5) at main.c(1863) [Receiver=3.2.7]", False, "refused the rsync login"),
        (5, "@ERROR: Unknown module 'mm'\nrsync error: error starting client-server protocol "
            "(code 5)", False, "no module"),
        (10, "rsync: [Receiver] failed to connect to srv.example (10.0.0.1): Connection "
             "refused (111)\nrsync error: error in socket IO (code 10)", False,
         "refused the connection"),
        (10, "rsync: getaddrinfo: srv.example 873: Name or service not known\nrsync error: "
             "error in socket IO (code 10)", False, "could not be resolved"),
        (35, "rsync error: timeout waiting for daemon connection (code 35)", False,
         "did not answer in time"),
        (255, "ssh: connect to host srv.example port 22: Connection refused\r\nrsync: "
              "connection unexpectedly closed (0 bytes received so far) [Receiver]", True,
         "refused the connection"),
        (255, "Host key verification failed.\r\nrsync: connection unexpectedly closed", True,
         "host key"),
        (255, "u@srv.example: Permission denied (publickey,password).\r\nrsync: connection "
              "unexpectedly closed", True, "SSH key"),
        (255, "ssh: Could not resolve hostname srv.example: Name or service not known\r\n",
         True, "could not be resolved"),
    ],
)
def test_sad_a_failed_connect_says_what_to_do(rec, rc, stderr, ssh, expect):
    rec.answers.append((rc, "", stderr))
    with pytest.raises(OSError) as info:
        _session(module="m", ssh_mode=ssh)
    text = describe(info.value)
    assert expect in text, text


def test_sad_permission_denied_while_listing_is_a_permission_error(rec):
    s = _session(module="m")
    rec.answers.append((23, "", 'rsync: [sender] change_dir "/x" (in m) failed: Permission '
                                "denied (13)\nrsync error: some files/attrs were not "
                                "transferred (code 23)"))
    with pytest.raises(PermissionError):
        s.list_dir("/x")


def test_edge_not_there_stays_file_not_found(rec):
    s = _session(module="m")
    rec.answers.append((23, "", 'rsync: [sender] change_dir "/gone" (in m) failed: No such '
                                "file or directory (2)"))
    with pytest.raises(FileNotFoundError):
        s.list_dir("/gone")
