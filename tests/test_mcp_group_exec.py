"""MCP capability group ``exec``: commands and scripts on remote hosts.

remote_exec runs one command, remote_script one script (sent on stdin to
an interpreter), exec_backends lists the backends that can do either. Any
backend whose session has ``exec()`` serves: SSH, SCP, Telnet, rsh, ADB,
WinRM (PowerShell) and Cisco (show commands only).

Off by default, twice over: the tools exist only with ``--mcp-tools exec``
(or ``all``) AND ``--mcp-allow-exec``; the paranoid security mode refuses
the flag. A production-flagged profile never runs anything. The audit
log records each attempt with the command's length and hash - never the
command, its stdin or its output.
"""

from __future__ import annotations

import hashlib

import pytest

from core import security_mode
from core.backend import SessionLifecycle
from models.exec_result import ExecResult
from tests import mcp_group_testkit as T


class _Shell(SessionLifecycle):
    """A remote with a POSIX shell: records what it is asked to run."""

    def __init__(self, rc=0, out=b"ok\n", err=b""):
        self.calls = []
        self.rc, self.out, self.err = rc, out, err

    def exec(
        self, cmd, *, timeout=30.0, stdin=None, stdout_cap=1 << 20, stderr_cap=1 << 16, env=None
    ):
        self.calls.append(
            {"cmd": cmd, "timeout": timeout, "stdin": stdin, "env": env, "cap": stdout_cap}
        )
        out = self.out
        return ExecResult(
            self.rc, out[:stdout_cap], self.err, truncated_stdout=len(out) > stdout_cap
        )


class _WinRM(_Shell):
    pass


_WinRM.__name__ = "WinRMSession"


class _Cisco(_Shell):
    pass


_Cisco.__name__ = "CiscoTelnetSession"


def _tools(root, *, allow_exec=True, groups=("exec",), **backends):
    return T.build(root, groups, backends=backends or {"box": _Shell()}, allow_exec=allow_exec)


# --- happy ----------------------------------------------------------------


def test_happy_remote_exec_returns_status_and_output(tmp_path):
    box = _Shell(out=b"Linux lab\n")
    tools = _tools(tmp_path, box=box)
    r = T.call(tools, "remote_exec", {"backend": "box", "command": "uname -a", "timeout": 20})
    assert r == {"returncode": 0, "stdout": "Linux lab\n", "stderr": "",
                 "truncated_stdout": False, "truncated_stderr": False}
    assert box.calls[0]["cmd"] == "uname -a" and box.calls[0]["timeout"] == 20


def test_happy_remote_script_goes_on_stdin_to_the_interpreter(tmp_path):
    box = _Shell()
    tools = _tools(tmp_path, box=box)
    T.call(tools, "remote_script", {"backend": "box", "script": "echo $1\n", "interpreter": "bash",
                                    "args": ["it's"]})
    assert box.calls[0]["cmd"] == "bash -s -- 'it'\"'\"'s'"
    assert box.calls[0]["stdin"] == b"echo $1\n"


def test_happy_exec_backends_lists_what_can_run_commands(tmp_path):
    tools = _tools(tmp_path, box=_Shell(), win=_WinRM(), sw=_Cisco())
    listed = {b["backend"]: b["kind"] for b in T.call(tools, "exec_backends", {})["backends"]}
    assert listed == {"box": "posix-shell", "win": "powershell", "sw": "ios-show"}


def test_happy_powershell_scripts_run_on_winrm(tmp_path):
    win = _WinRM()
    tools = _tools(tmp_path, win=win)
    T.call(
        tools,
        "remote_script",
        {"backend": "win", "script": "Get-Date", "interpreter": "powershell"},
    )
    assert win.calls[0]["cmd"] == "Get-Date" and win.calls[0]["stdin"] is None


# --- sad ------------------------------------------------------------------


def test_sad_no_tools_without_the_exec_flag(tmp_path):
    tools = T.build(tmp_path, ("all",), backends={"box": _Shell()})
    assert not {"remote_exec", "remote_script", "exec_backends"} & set(tools)


def test_sad_a_backend_without_a_shell_is_refused(tmp_path):
    tools = _tools(tmp_path)
    with pytest.raises(T.RpcError) as info:
        T.call(tools, "remote_exec", {"command": "id"})  # default backend: local files
    assert "no remote shell" in str(info.value)


def test_sad_cisco_runs_no_scripts(tmp_path):
    tools = _tools(tmp_path, sw=_Cisco())
    with pytest.raises(T.RpcError):
        T.call(tools, "remote_script", {"backend": "sw", "script": "reload\n", "interpreter": "sh"})


def test_sad_the_interpreter_must_fit_the_backend(tmp_path):
    tools = _tools(tmp_path, box=_Shell(), win=_WinRM())
    for backend, interpreter in (("box", "powershell"), ("win", "bash")):
        with pytest.raises(T.RpcError):
            T.call(
                tools,
                "remote_script",
                {"backend": backend, "script": "x", "interpreter": interpreter},
            )


def test_sad_paranoid_mode_builds_no_exec_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    tools = _tools(tmp_path)
    assert "remote_exec" not in tools


def test_sad_a_production_profile_runs_nothing(tmp_path, monkeypatch, caplog):
    import json

    from core import credentials
    from core import mcp_groups
    from core import profiles as P
    from core.profiles import ConnectionProfile
    from core.ram_fs import RamFsSession

    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    path = tmp_path / "profiles.json"
    profile = ConnectionProfile(name="prod", protocol="ramfs", production=True).to_dict()
    path.write_text(json.dumps({"prod": profile}))
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    ran = []
    # Give the RAM backend a shell, so the production check is what refuses.
    monkeypatch.setattr(
        RamFsSession, "exec", lambda self, cmd, **kw: ran.append(cmd), raising=False
    )
    root = tmp_path / "root"
    root.mkdir()
    tools = T.build(root, ("remote", "exec"), allow_exec=True)
    T.capture_audit(caplog)
    try:
        bid = T.call(tools, "remote_open", {"profile": "prod"})["backend"]
        with pytest.raises(T.RpcError) as info:
            T.call(tools, "remote_exec", {"backend": bid, "command": "id"})
    finally:
        for registry in list(mcp_groups.RemoteRegistry._live):
            registry.close_all()
    assert "production" in str(info.value) and ran == []


def test_sad_a_non_zero_exit_is_a_result_not_an_error(tmp_path):
    tools = _tools(tmp_path, box=_Shell(rc=2, out=b"", err=b"ls: /nope: No such file\n"))
    r = T.call(tools, "remote_exec", {"backend": "box", "command": "ls /nope"})
    assert r["returncode"] == 2 and "No such file" in r["stderr"]


# --- edge -----------------------------------------------------------------


def test_edge_the_audit_log_never_holds_the_command(tmp_path, caplog):
    tools = _tools(tmp_path)
    secret = "mysql -p'hunter2' -e 'select 1'"
    T.capture_audit(caplog)
    T.call(tools, "remote_exec", {"backend": "box", "command": secret, "stdin": "payload"})
    lines = " ".join(T.audit_lines(caplog))
    assert "hunter2" not in lines and "payload" not in lines
    assert hashlib.sha256(secret.encode()).hexdigest()[:16] in lines


def test_edge_output_cap_and_undecodable_bytes(tmp_path):
    tools = _tools(tmp_path, box=_Shell(out=b"\xff\xfeabc" * 10))
    r = T.call(tools, "remote_exec", {"backend": "box", "command": "cat blob", "max_output": 8})
    assert r["truncated_stdout"] is True and len(r["stdout"]) <= 8 and "�" in r["stdout"]


def test_edge_env_is_inlined_for_posix_shells(tmp_path, caplog):
    # SSH sends env as protocol requests that sshd drops unless AcceptEnv
    # lists the name (measured against the lab's OpenSSH); exporting in
    # the command line reaches every POSIX shell.
    box = _Shell()
    tools = _tools(tmp_path, box=box)
    T.capture_audit(caplog)
    T.call(tools, "remote_exec", {"backend": "box", "command": "env", "env": {"V": "a'b; c"}})
    assert box.calls[0]["cmd"] == "export V='a'\"'\"'b; c'; env" and box.calls[0]["env"] is None
    lines = " ".join(T.audit_lines(caplog))
    assert hashlib.sha256(b"env").hexdigest()[:16] in lines and "a'b" not in lines


def test_edge_env_stays_a_mapping_for_powershell(tmp_path):
    win = _WinRM()
    tools = _tools(tmp_path, win=win)
    T.call(
        tools, "remote_exec", {"backend": "win", "command": "Get-Date", "env": {"LANG": "C.UTF-8"}}
    )
    assert win.calls[0]["cmd"] == "Get-Date" and win.calls[0]["env"] == {"LANG": "C.UTF-8"}


def test_sad_a_bad_env_name_is_refused_before_anything_runs(tmp_path):
    box = _Shell()
    tools = _tools(tmp_path, box=box)
    with pytest.raises(T.RpcError):
        T.call(tools, "remote_exec", {"backend": "box", "command": "env", "env": {"A;id": "x"}})
    assert box.calls == []


def test_edge_the_manifest_names_both_flags(tmp_path):
    tools = list(_tools(tmp_path).values())
    from core import mcp_groups

    manifest = mcp_groups.tool_manifest(
        tools, groups={"exec"}, allow_write=False, allow_scripts=False, allow_exec=True
    )
    entry = next(t for t in manifest["tools"] if t["name"] == "remote_exec")
    assert entry["mutating"] is True
    assert entry["required_flags"] == ["--mcp-tools exec", "--mcp-allow-exec"]




# --- the command line ------------------------------------------------------


def _cli(*argv, env=None):
    from tests.test_mcp_write_root import _main_in_process

    return _main_in_process(*argv, env=env)


def test_happy_the_flag_reaches_both_transports():
    code, err, serve, serve_http = _cli("--mcp-server", "--mcp-tools", "exec", "--mcp-allow-exec")
    assert code == 0, err
    assert serve.call_args.args[0].allow_exec is True
    code, err, serve, serve_http = _cli(
        "--mcp-server", "--mcp-tools", "exec", "--mcp-allow-exec", "--mcp-http", "127.0.0.1:7331"
    )
    assert code == 0, err
    assert serve_http.call_args.args[0].allow_exec is True


def test_sad_paranoid_mode_refuses_the_flag(monkeypatch):
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    code, err, serve, serve_http = _cli("--mcp-server", "--mcp-tools", "exec", "--mcp-allow-exec")
    assert code == 2 and "remote command execution" in err
    assert not serve.called and not serve_http.called


def test_edge_list_tools_shows_exec_only_with_the_flag(capsys):
    import json

    for flags, expected in (
        (("--mcp-tools", "all"), False),
        (("--mcp-tools", "all", "--mcp-allow-exec"), True),
    ):
        code, err, _s, _h = _cli("--mcp-server", "--mcp-list-tools", *flags)
        assert code == 0, err
        names = [t["name"] for t in json.loads(capsys.readouterr().out)["tools"]]
        assert ("remote_exec" in names) is expected


def test_sad_switching_to_paranoid_stops_tools_built_before(tmp_path, monkeypatch):
    """The security mode can change while an agent (or server) holds tools
    built earlier: a remote command checks it at the call, not only when the
    tools were built."""
    tools = _tools(tmp_path)
    assert "remote_exec" in tools
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    with pytest.raises(T.RpcError) as info:
        T.call(tools, "remote_exec", {"backend": "box", "command": "id"})
    assert "security mode" in str(info.value)
