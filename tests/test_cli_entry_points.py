"""The non-GUI starts of main.py: --script, the MCP server and what they
share (the log file, the stored security mode).

What was wrong (review round 2):

* ``AXROSS_MCP=1`` won over ``--script``: the MCP branch was taken first.
  A frozen build's script child is ``axross --script -`` and inherited
  the variable from the MCP client's environment, so every ``script_run``
  answered "exit 0" while the script never ran (it served MCP on stdin).
* The paranoid mode chosen in Settings applied to the window only;
  ``--script`` and ``--mcp-server --mcp-allow-scripts`` ran anyway,
  although SPEC.md, MCP.md and USAGE.md say paranoid blocks both.
* An unwritable log folder ended every mode with a PermissionError
  traceback (core.log_config._make_file_handler).
* ``--script`` handed the script axross's own sys.argv and refused
  arguments for the script; a missing script file was a traceback.
* ``--mcp-allow-exec`` without the exec group, and an ``--mcp-root``
  that does not exist, were accepted silently.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TIMEOUT = 120


def _env(home: Path, **extra: str) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("AXROSS_") and not k.startswith("XDG_")}
    env.update(HOME=str(home), PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
               QT_QPA_PLATFORM="offscreen")
    env.update(extra)
    return env


def _main(home: Path, *argv: str, stdin: str | None = None, **env) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *argv],
        cwd=str(ROOT), env=_env(home, **env), capture_output=True, text=True,
        timeout=TIMEOUT, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL,
    )


@pytest.fixture
def home(tmp_path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


def _script(tmp_path: Path, source: str, name: str = "job.py") -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def _paranoid(home: Path) -> None:
    folder = home / ".config" / "axross"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "settings.json").write_text(json.dumps({"security_mode": "paranoid"}))


# -- --script and AXROSS_MCP ---------------------------------------------------------------


def test_sad_axross_mcp_does_not_turn_a_script_run_into_an_mcp_server(home, tmp_path):
    script = _script(tmp_path, 'print("SCRIPT RAN")\nraise SystemExit(5)\n')
    proc = _main(home, "--script", str(script), AXROSS_MCP="1")
    assert proc.returncode == 5, proc.stderr[-2000:]
    assert proc.stdout.strip() == "SCRIPT RAN"
    assert "jsonrpc" not in proc.stdout


def test_sad_script_together_with_an_mcp_mode_is_refused(home, tmp_path):
    script = _script(tmp_path, 'print("SCRIPT RAN")\n')
    for flags in (("--mcp-server",), ("--mcp-list-tools",)):
        proc = _main(home, *flags, "--script", str(script))
        assert proc.returncode == 2, (flags, proc.stdout[-500:], proc.stderr[-2000:])
        assert "--script" in proc.stderr and "Traceback" not in proc.stderr
        assert proc.stdout == ""


def test_sad_the_script_child_environment_has_no_mcp_variables(monkeypatch):
    from core import script_runner

    for name in ("AXROSS_MCP", "AXROSS_MCP_WRITE", "AXROSS_MCP_TOOLS"):
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("AXROSS_TARPIT_DISABLE", "1")             # not ours to drop
    env = script_runner.child_env("normal")
    assert not [k for k in env if k.startswith("AXROSS_MCP")]
    assert env["AXROSS_TARPIT_DISABLE"] == "1"


def test_edge_a_frozen_script_child_runs_the_script_under_axross_mcp(tmp_path, monkeypatch):
    """The real chain of a frozen build: run_bounded starts
    ``<binary> --script -`` (here main.py behind a wrapper), the MCP
    client's AXROSS_MCP=1 in the environment."""
    from core import script_runner, scripting

    wrapper = tmp_path / "axross"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{ROOT / "main.py"}" "$@"\n')
    wrapper.chmod(0o755)
    name = f"probe_mcp_env_{os.getpid()}"
    scripting.save_script(name, 'print("SCRIPT RAN")\nraise SystemExit(7)\n')
    try:
        monkeypatch.setenv("AXROSS_MCP", "1")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(wrapper))
        run = script_runner.run_bounded(name, timeout_s=TIMEOUT, max_output_chars=100_000)
    finally:
        scripting.delete_script(name)
    assert run.exit == 7, (run.stdout[-500:], run.stderr[-2000:])
    assert "SCRIPT RAN" in run.stdout and "jsonrpc" not in run.stdout


# -- the stored security mode ----------------------------------------------------------------


def test_sad_paranoid_mode_from_settings_blocks_script_and_mcp_scripts(home, tmp_path):
    _paranoid(home)
    script = _script(tmp_path, 'print("SCRIPT RAN")\n')
    proc = _main(home, "--script", str(script))
    assert proc.returncode == 2 and "SCRIPT RAN" not in proc.stdout
    assert "paranoid" in proc.stderr
    proc = _main(home, "--mcp-server", "--mcp-allow-scripts")
    assert proc.returncode == 2 and "paranoid" in proc.stderr
    # AXROSS_SECURITY_MODE in the environment still wins.
    proc = _main(home, "--script", str(script), AXROSS_SECURITY_MODE="normal")
    assert proc.returncode == 0 and proc.stdout.strip() == "SCRIPT RAN", proc.stderr[-2000:]


# -- the log file ----------------------------------------------------------------------------


def test_sad_an_unwritable_log_folder_does_not_stop_a_start(home, tmp_path):
    state = home / ".local" / "state" / "axross"
    state.mkdir(parents=True)
    (state / "logs").write_text("a file where the log folder belongs\n")  # unwritable, also for root
    script = _script(tmp_path, 'print("SCRIPT RAN")\n')
    proc = _main(home, "--script", str(script))
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip() == "SCRIPT RAN"
    assert "Traceback" not in proc.stderr
    warnings = [line for line in proc.stderr.splitlines() if "log file" in line]
    assert len(warnings) == 1 and "[WARNING]" in warnings[0]
    assert "[INFO]" not in proc.stderr                         # the terminal stands in at WARNING
    proc = _main(home, "--mcp-list-tools")
    assert proc.returncode == 0 and json.loads(proc.stdout)["tools"], proc.stderr[-2000:]


def test_edge_configure_without_a_writable_log_file(tmp_path, capsys):
    from core import log_config as LC

    blocker = tmp_path / "logs"
    blocker.write_text("")
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        LC.configure(blocker / "axross.log", settings=LC.LogSettings())
        assert LC.file_handler() is None
        assert LC.terminal_handler() is not None
        logging.getLogger("core.smb_client").warning("disk full on share")
        logging.getLogger("core.smb_client").info("a detail")
        err = capsys.readouterr().err
        assert "cannot be written" in err and "disk full on share" in err
        assert "a detail" not in err
    finally:
        LC.teardown()
        for handler in list(root.handlers):
            if handler not in before:
                root.removeHandler(handler)


# -- --script's own command line --------------------------------------------------------------


def test_happy_script_arguments_reach_the_scripts_sys_argv(home, tmp_path):
    script = _script(tmp_path, "import json, sys\nprint(json.dumps(sys.argv))\n")
    proc = _main(home, "--script", str(script), "first", "--flag", "-x")
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert json.loads(proc.stdout) == [str(script), "first", "--flag", "-x"]
    proc = _main(home, "--script", "-", "a", stdin="import json, sys\nprint(json.dumps(sys.argv))\n")
    assert proc.returncode == 0 and json.loads(proc.stdout) == ["-", "a"], proc.stderr[-2000:]


def test_sad_a_missing_script_file_is_one_line_and_exit_2(home, tmp_path):
    missing = tmp_path / "nope.py"
    proc = _main(home, "--script", str(missing))
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    assert f"--script {missing}: No such file or directory" in proc.stderr


# -- MCP option checks ----------------------------------------------------------------------


def _in_process(*argv):
    from tests.test_mcp_write_root import _main_in_process

    return _main_in_process(*argv)


def test_sad_allow_exec_without_the_exec_group_is_refused():
    code, err, serve, serve_http = _in_process("--mcp-server", "--mcp-allow-exec")
    assert code == 2 and "--mcp-tools exec" in err
    assert not serve.called and not serve_http.called
    code, err, serve, _h = _in_process("--mcp-server", "--mcp-tools", "remote,exec",
                                       "--mcp-allow-exec")
    assert code == 0, err


def test_sad_an_mcp_root_that_does_not_exist_is_refused(tmp_path):
    code, err, serve, serve_http = _in_process("--mcp-server", "--mcp-root", str(tmp_path / "nope"))
    assert code == 2 and "no such directory" in err
    assert not serve.called and not serve_http.called
    code, err, serve, _h = _in_process("--mcp-server", "--mcp-root", str(tmp_path))
    assert code == 0 and serve.called, err
