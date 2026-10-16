"""Every backend with a remote shell answers ``exec()`` the same way.

SSH and SCP had ``exec(cmd, *, timeout, stdin, stdout_cap, stderr_cap,
env) -> ExecResult``; Telnet, rsh, ADB, WinRM and Cisco each had their own
private runner (``_shell.execute``, ``_run_remote``, ``shell``, ``ps``,
``show``) with different return shapes - some raised on a non-zero exit,
some returned a plain string. The MCP ``exec`` group needs one surface,
so each of them now has the same ``exec()``:

* the remote exit status is ``returncode``, never an exception;
* ``stdin`` reaches the command (over a temporary file where the
  protocol has no stdin channel); WinRM and Cisco refuse it;
* ``env`` keys are validated like SSHSession.exec does (OSError);
* output is capped with the ``truncated_*`` flags set;
* Cisco runs ``show`` commands only - nothing that changes the device.
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.exec_result import ExecResult  # noqa: E402


# --- fakes -----------------------------------------------------------------


class _FakeShell:
    """Stands in for telnet's _ShellSession: records commands."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.sent = []

    def execute(self, cmd, timeout=None):
        self.sent.append((cmd, timeout))
        return self.answers.pop(0) if self.answers else ("", 0)


def _telnet(answers):
    from core.telnet_client import TelnetSession

    s = TelnetSession.__new__(TelnetSession)
    s._shell = _FakeShell(answers)
    s.uploads = {}
    s.removed = []

    class _W:
        def __init__(self, path):
            self.path, self.buf = path, b""

        def write(self, data):
            self.buf += data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            s.uploads[self.path] = self.buf

    s.open_write = lambda path, append=False: _W(path)
    s.remove = lambda path, recursive=False: s.removed.append(path)
    return s


def _rsh(monkeypatch, stdout: bytes, status: int, rc: int = 0, stderr: bytes = b""):
    import subprocess

    from core import rsh_client

    s = rsh_client.RshSession.__new__(rsh_client.RshSession)
    s._rsh, s._port, s._username, s._host, s._timeout = "rsh", 514, "u", "lab", 10.0
    seen = {}

    def run(argv, input=None, capture_output=True, timeout=None, check=False, env=None):
        seen.update(argv=argv, input=input, timeout=timeout)
        tag = re.search(r"__AXROSS_RSH_STATUS_[0-9a-f]+__", argv[-1]).group(0)
        body = stdout + b"\n" + tag.encode() + b" " + str(status).encode() + b"\n"
        return subprocess.CompletedProcess(argv, rc, stdout=body, stderr=stderr)

    monkeypatch.setattr(rsh_client.subprocess, "run", run)
    return s, seen


def _adb(outputs):
    from core.adb_client import AdbSession

    s = AdbSession.__new__(AdbSession)
    s.sent = []

    def shell(cmd):
        s.sent.append(cmd)
        out = outputs.pop(0) if outputs else ""
        if "__AXROSS_RC_" in cmd:
            tag = cmd.rsplit("echo ", 1)[1].split(" ", 1)[0]
            code = getattr(s, "next_rc", 0)
            return f"{out}{tag} {code}\n"
        return out

    s._shell = shell
    s.uploads = {}

    class _W:
        def __init__(self, path):
            self.path, self.buf = path, b""

        def write(self, data):
            self.buf += data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            s.uploads[self.path] = self.buf

    s.open_write = lambda path, append=False: _W(path)
    s.remove = lambda path, recursive=False: s.uploads.pop(path, None)
    return s


def _winrm(status=0, out=b"ok\r\n", err=b""):
    from core.winrm_client import WinRMSession

    s = WinRMSession.__new__(WinRMSession)
    s.scripts = []

    def run_ps(script):
        s.scripts.append(script)
        return types.SimpleNamespace(status_code=status, std_out=out, std_err=err)

    s._session = types.SimpleNamespace(run_ps=run_ps)
    return s


def _cisco(reply="Cisco IOS Software, Version 15.2\n"):
    from core.telnet_cisco import CiscoTelnetSession

    s = CiscoTelnetSession.__new__(CiscoTelnetSession)
    s.shown = []

    def show(command):
        s.shown.append(command)
        return reply

    s.show = show
    return s


# --- happy -----------------------------------------------------------------


def test_happy_telnet_exec_returns_output_and_status():
    s = _telnet([("Linux lab 6.1\n", 0)])
    r = s.exec("uname -a", timeout=12)
    assert isinstance(r, ExecResult) and r.returncode == 0 and r.stdout == b"Linux lab 6.1\n"
    assert s._shell.sent[0][1] == 12


def test_happy_rsh_exec_returns_output_and_status(monkeypatch):
    s, seen = _rsh(monkeypatch, b"hello\n", 0)
    r = s.exec("echo hello", timeout=7)
    assert r.returncode == 0 and r.stdout == b"hello\n" and seen["timeout"] == 7


def test_happy_adb_exec_reads_the_exit_status():
    s = _adb(["data\n"])
    s.next_rc = 0
    r = s.exec("ls /sdcard")
    assert r.returncode == 0 and r.stdout == b"data\n"


def test_happy_winrm_exec_runs_powershell():
    s = _winrm(out=b"ok\r\n")
    r = s.exec("Get-Date")
    assert r.returncode == 0 and r.stdout == b"ok\r\n" and s.scripts == ["Get-Date"]


def test_happy_cisco_exec_runs_a_show_command():
    s = _cisco()
    r = s.exec("show version")
    assert r.returncode == 0 and b"Cisco IOS" in r.stdout and s.shown == ["version"]


def test_happy_stdin_reaches_the_command_over_a_temporary_file():
    s = _telnet([("", 0)])
    s.exec("wc -c", stdin=b"12345")
    (path, data), = s.uploads.items()
    assert data == b"12345"
    assert f"< {path}" in s._shell.sent[0][0] and s.removed == [path]


def test_happy_rsh_stdin_goes_to_the_process(monkeypatch):
    s, seen = _rsh(monkeypatch, b"5\n", 0)
    s.exec("wc -c", stdin=b"12345")
    assert seen["input"] == b"12345"


# --- sad -------------------------------------------------------------------


@pytest.mark.parametrize("maker", ["telnet", "rsh", "adb", "winrm"])
def test_sad_a_nonzero_exit_is_a_returncode_not_an_exception(monkeypatch, maker):
    if maker == "telnet":
        s = _telnet([("no such file\n", 2)])
    elif maker == "rsh":
        s, _ = _rsh(monkeypatch, b"", 2)
    elif maker == "adb":
        s = _adb(["no such file\n"])
        s.next_rc = 2
    else:
        s = _winrm(status=2)
    r = s.exec("ls /nope")
    assert r.returncode == 2 and not r.ok
    with pytest.raises(OSError):
        r.check()


def test_sad_cisco_refuses_anything_but_show():
    s = _cisco()
    for cmd in ("configure terminal", "reload", "write memory", "show run\nreload"):
        with pytest.raises(OSError):
            s.exec(cmd)
    assert s.shown == []


@pytest.mark.parametrize(
    "cmd",
    [
        "show running-config | redirect flash:copy.cfg",
        "show running-config | red flash:copy.cfg",
        "show version | tee flash:v.txt",
        "show version | t flash:v.txt",
        "show version | append flash:v.txt",
        "show version | include IOS | tee flash:v.txt",
        "show version > flash:v.txt",
    ],
)
def test_sad_cisco_refuses_output_modifiers_that_write_files(cmd):
    # IOS output modifiers redirect / tee / append (abbreviated too)
    # write the output to the device's flash.
    s = _cisco()
    with pytest.raises(OSError, match="read-only"):
        s.exec(cmd)
    assert s.shown == []


def test_edge_cisco_keeps_the_filtering_modifiers():
    s = _cisco()
    for cmd in ("show running-config | include hostname", "show ip interface brief | i up",
                "show running-config | section interface", "show log | begin Oct", "show users | count"):
        assert s.exec(cmd).returncode == 0
    assert len(s.shown) == 5


@pytest.mark.parametrize("maker", ["winrm", "cisco"])
def test_sad_stdin_is_refused_where_the_protocol_cannot_carry_it(maker):
    s = _winrm() if maker == "winrm" else _cisco()
    with pytest.raises(OSError, match="stdin"):
        s.exec("show version" if maker == "cisco" else "Get-Date", stdin=b"x")


@pytest.mark.parametrize("maker", ["telnet", "rsh", "adb", "winrm"])
def test_sad_a_bad_env_key_is_refused(monkeypatch, maker):
    s = {"telnet": lambda: _telnet([]), "rsh": lambda: _rsh(monkeypatch, b"", 0)[0],
         "adb": lambda: _adb([]), "winrm": lambda: _winrm()}[maker]()
    with pytest.raises(OSError, match="env key"):
        s.exec("true", env={"A;rm -rf /": "x"})


# --- edge ------------------------------------------------------------------


def test_edge_env_values_are_quoted():
    s = _telnet([("", 0)])
    s.exec("echo $GREETING", env={"GREETING": "it's me; rm -rf /"})
    sent = s._shell.sent[0][0]
    assert "GREETING='it'\"'\"'s me; rm -rf /'" in sent


def test_edge_output_is_capped_with_the_flag(monkeypatch):
    s, _ = _rsh(monkeypatch, b"x" * 100, 0)
    r = s.exec("yes", stdout_cap=10)
    assert r.stdout == b"x" * 10 and r.truncated_stdout


def test_edge_winrm_env_becomes_powershell_variables():
    s = _winrm()
    s.exec("Write-Output $env:NAME", env={"NAME": "O'Brien"})
    assert s.scripts[0].startswith("$env:NAME = 'O''Brien'; ")


import subprocess as _subprocess  # noqa: E402

_RUN = _subprocess.run  # the rsh fake below replaces subprocess.run


def _real_sh(line: str, stdin: bytes | None = None) -> tuple[str, int]:
    proc = _RUN(["sh", "-c", line], input=stdin, capture_output=True, timeout=10)
    return (proc.stdout + proc.stderr).decode(), proc.returncode


def _persistent_sh(line: str, timeout=None) -> tuple[str, int]:
    """Telnet's login shell outlives the command: run *line* the way
    _ShellSession.execute does and see whether the shell is still there
    to report the status; if not, the real session times out."""
    out, _rc = _real_sh(f"{line}\necho __status_$?__")
    m = re.search(r"__status_(\d+)__", out)
    if m is None:
        raise TimeoutError(f"Command timed out: {line[:80]!r}")
    return out[: m.start()], int(m.group(1))


def _sh_backed(maker, monkeypatch):
    """A backend whose remote side is a real local sh running what the
    backend would send, so quoting and exit behaviour are measured."""
    if maker == "telnet":
        s = _telnet([])
        s._shell.execute = _persistent_sh
        return s
    if maker == "rsh":
        import subprocess

        from core import rsh_client

        s = rsh_client.RshSession.__new__(rsh_client.RshSession)
        s._rsh, s._port, s._username, s._host, s._timeout = "rsh", 514, "u", "lab", 10.0

        def run(argv, input=None, capture_output=True, timeout=None, check=False, env=None):
            out, _rc = _real_sh(argv[-1], input)  # rshd hands argv[-1] to the login shell
            return subprocess.CompletedProcess(argv, 0, stdout=out.encode(), stderr=b"")

        monkeypatch.setattr(rsh_client.subprocess, "run", run)
        return s
    s = _adb([])
    s._shell = lambda cmd: _real_sh(cmd)[0]
    return s


@pytest.mark.parametrize("maker", ["telnet", "rsh", "adb"])
def test_edge_exit_and_comments_stay_inside_the_command(monkeypatch, maker):
    # 'exit' must end the command, not the shell that reports its status
    # (on Telnet: the session's login shell); a trailing comment must not
    # swallow the wrapping.
    s = _sh_backed(maker, monkeypatch)
    r = s.exec("echo before; exit 3")
    assert r.returncode == 3 and r.stdout.strip() == b"before"
    r = s.exec("echo ok # a comment")
    assert r.returncode == 0 and r.stdout.strip() == b"ok"


def test_edge_telnet_env_does_not_leak_into_the_session():
    s = _telnet([("", 0)])
    s.exec("true", env={"LEAK": "1"})
    sent = s._shell.sent[0][0]
    out, _rc = _real_sh(sent + "\necho \"[${LEAK:-unset}]\"")
    assert "[unset]" in out


def test_edge_the_old_raising_runners_still_raise(monkeypatch):
    from core.rsh_client import RshError

    s, _ = _rsh(monkeypatch, b"", 3)
    with pytest.raises(RshError):
        s._run_remote("false")
