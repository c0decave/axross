"""core.script_runner: a saved script in its own interpreter.

The Scripts dock runs a saved script as a child process so the window
never freezes and Stop can end it. These tests drive the child the way
the dock does (the same command, cwd and environment) but through
subprocess, so they need no event loop; the dock's own tests cover the
QProcess side.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import script_runner as SR  # noqa: E402
from core import scripting  # noqa: E402


@pytest.fixture()
def script():
    """Save a uniquely named script; remove it afterwards."""
    names: list[str] = []

    def _save(source: str, name: str | None = None) -> str:
        name = name or f"t_{uuid.uuid4().hex[:10]}"
        scripting.save_script(name, source)
        names.append(name)
        return name

    yield _save
    for name in names:
        scripting.delete_script(name)


def _run_child(name: str, *, policy: str = "normal", timeout: float = 60):
    cmd = SR.build_command(name)
    # As the dock does: whatever the command reads, then end of input.
    stdin = {"input": cmd.stdin_text} if cmd.stdin_text else {"stdin": subprocess.DEVNULL}
    return subprocess.run(
        cmd.argv,
        **stdin,
        cwd=cmd.cwd,
        env=SR.child_env(policy),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# execute_source (shared with ``main.py --script``)
# ---------------------------------------------------------------------------


def test_happy_execute_source_gives_the_script_the_axross_namespace(tmp_path) -> None:
    out = tmp_path / "out.txt"
    src = (
        f"open({str(out)!r}, 'w').write("
        "__name__ + ' ' + __file__ + ' ' + str(axross.localfs is not None))\n"
    )
    assert SR.execute_source(src, "/x/job.py") == 0
    assert out.read_text() == "__main__ /x/job.py True"


def test_sad_execute_source_maps_system_exit_like_the_interpreter(capsys) -> None:
    assert SR.execute_source("import sys\nsys.exit(4)\n", "j.py") == 4
    assert SR.execute_source("raise SystemExit\n", "j.py") == 0
    assert SR.execute_source("import sys\nsys.exit('bad input')\n", "j.py") == 1
    assert "bad input" in capsys.readouterr().err


def test_edge_execute_source_lets_other_exceptions_through() -> None:
    with pytest.raises(ZeroDivisionError):
        SR.execute_source("1/0\n", "j.py")


# ---------------------------------------------------------------------------
# The child process
# ---------------------------------------------------------------------------


def test_happy_the_child_runs_the_saved_script(script) -> None:
    name = script("import sys\nprint('hello', axross.__name__)\nprint('warn', file=sys.stderr)\n")
    proc = _run_child(name)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["hello core.scripting"]
    assert "warn" in proc.stderr


def test_happy_the_child_runs_in_the_script_directory_with_its_file_name(script) -> None:
    name = script("import os\nprint(os.getcwd())\nprint(__file__)\nprint(__name__)\n")
    proc = _run_child(name)
    assert proc.returncode == 0, proc.stderr
    cwd, file_, mod = proc.stdout.splitlines()
    assert os.path.realpath(cwd) == os.path.realpath(scripting.script_dir())
    assert file_ == os.path.join(scripting.script_dir(), f"{name}.py")
    assert mod == "__main__"


def test_sad_a_non_zero_exit_is_the_child_status(script) -> None:
    proc = _run_child(script("import sys\nsys.exit(3)\n"))
    assert proc.returncode == 3
    assert "Traceback" not in proc.stderr


def test_sad_a_syntax_error_names_the_script_line(script) -> None:
    name = script("x = 1\ndef broken(:\n")
    proc = _run_child(name)
    assert proc.returncode == 1
    path = os.path.join(scripting.script_dir(), f"{name}.py")
    assert f'File "{path}", line 2' in proc.stderr
    assert "SyntaxError" in proc.stderr


def test_sad_a_runtime_error_shows_the_script_not_the_runner(script) -> None:
    name = script("def f():\n    return 1 / 0\n\nf()\n")
    proc = _run_child(name)
    assert proc.returncode == 1
    path = os.path.join(scripting.script_dir(), f"{name}.py")
    assert f'File "{path}", line 2' in proc.stderr
    assert "ZeroDivisionError" in proc.stderr
    assert "script_runner" not in proc.stderr  # the runner's own frames are dropped


def test_sad_paranoid_mode_refuses_in_the_child_too(script, tmp_path) -> None:
    marker = tmp_path / "ran"
    name = script(f"open({str(marker)!r}, 'w').write('x')\n")
    proc = _run_child(name, policy="paranoid")
    assert proc.returncode == 2
    assert "paranoid" in proc.stderr
    assert not marker.exists()


def test_sad_a_missing_script_is_reported_not_raised() -> None:
    proc = _run_child(f"missing_{uuid.uuid4().hex[:8]}")
    assert proc.returncode == 2
    assert "cannot load script" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_sad_an_invalid_name_is_refused_before_any_command_is_built() -> None:
    for bad in ("../x", "a b", "", "x" * 81):
        with pytest.raises(ValueError):
            SR.build_command(bad)


def test_edge_a_module_planted_in_the_script_directory_is_not_imported(script, tmp_path) -> None:
    """cwd is the script directory; a script named json.py must not
    replace the stdlib for every other script (-I keeps cwd off sys.path)."""
    marker = tmp_path / "hijacked"
    planted = script(f"open({str(marker)!r}, 'w').write('x')\n", name="json")
    assert planted == "json"
    name = script("import json\nprint(json.dumps([1]))\n")
    proc = _run_child(name)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "[1]"
    assert not marker.exists()


def test_edge_stdin_is_closed_so_confirm_refuses_instead_of_answering(script) -> None:
    # Nobody can answer in the child: answering the default here used to
    # approve default_yes=True prompts on its own.
    name = script("print(axross.confirm('go?', default_yes=True))\n")
    proc = _run_child(name)
    assert proc.returncode == 1
    assert "NonInteractiveError" in proc.stderr and "assume_yes=True" in proc.stderr
    assert "True" not in proc.stdout


def test_happy_assume_yes_lets_a_child_script_through(script) -> None:
    name = script("print(axross.confirm('go?', assume_yes=True))\n")
    proc = _run_child(name)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "True"


def test_edge_the_child_environment_carries_the_live_policy() -> None:
    assert SR.child_env("paranoid")["AXROSS_SECURITY_MODE"] == "paranoid"
    assert SR.child_env("normal")["AXROSS_SECURITY_MODE"] == "normal"


def test_edge_a_frozen_build_runs_through_its_own_script_mode(script) -> None:
    name = script("print(1)\n")
    with mock.patch.object(sys, "frozen", True, create=True):
        cmd = SR.build_command(name)
    assert cmd.argv == [sys.executable, "--script", "-"]
    assert cmd.stdin_text is not None and repr(name) in cmd.stdin_text
    assert "child_main" in cmd.stdin_text


def test_edge_the_source_build_is_isolated_and_unbuffered(script) -> None:
    cmd = SR.build_command(script("print(1)\n"))
    assert cmd.argv[0] == sys.executable
    assert "-I" in cmd.argv and "-u" in cmd.argv
    assert cmd.stdin_text is None
    assert os.path.realpath(cmd.cwd) == os.path.realpath(scripting.script_dir())


def test_happy_the_child_sees_its_arguments_as_sys_argv(script) -> None:
    name = script("import sys, json\nprint(json.dumps(sys.argv))\n")
    cmd = SR.build_command(name, ["one", "two words"])
    proc = subprocess.run(
        cmd.argv, stdin=subprocess.DEVNULL, cwd=cmd.cwd, env=SR.child_env("normal"),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    path = os.path.join(scripting.script_dir(), f"{name}.py")
    assert json.loads(proc.stdout) == [path, "one", "two words"]


def test_edge_a_frozen_build_passes_the_arguments_in_its_bootstrap(script) -> None:
    name = script("print(1)\n")
    with mock.patch.object(sys, "frozen", True, create=True):
        cmd = SR.build_command(name, ["a'b", "c"])
    assert repr([name, "a'b", "c"]) in cmd.stdin_text


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[1, 2]", b'{"exit": "0"}', b'{"exit": true}', b"\xff\xfe",
     b"[" * 100_000],
)
def test_sad_a_malformed_outcome_record_is_ignored(raw) -> None:
    # The script owns the child and can write anything to the record pipe.
    assert SR._parse_record(raw).get("exit") is None


def test_edge_an_outcome_record_is_type_checked_and_bounded() -> None:
    raw = json.dumps({
        "exit": 3, "error_type": 7, "error": "x" * (SR.MAX_ERROR_CHARS + 10),
        "namespace_keys": ["ok", 5, "y" * (SR.MAX_NAMESPACE_KEY_CHARS + 1)],
    }).encode()
    record = SR._parse_record(raw)
    assert record["exit"] == 3 and "error_type" not in record
    assert len(record["error"]) == SR.MAX_ERROR_CHARS
    assert record["namespace_keys"] == ["ok"]


# ---------------------------------------------------------------------------
# OutputLimiter: what reaches the output pane
# ---------------------------------------------------------------------------


def test_happy_short_output_passes_through_unchanged() -> None:
    lim = SR.OutputLimiter(max_line_chars=50, max_lines=10)
    assert lim.feed(b"a\nb\n") == "a\nb\n"
    assert lim.feed(b"partial") == "partial"
    assert lim.feed(b" line\n") == " line\n"
    assert lim.total_bytes == len(b"a\nb\npartial line\n")


def test_sad_an_endless_line_is_cut_once_across_chunks() -> None:
    lim = SR.OutputLimiter(max_line_chars=10, max_lines=10)
    first = lim.feed(b"x" * 8)
    second = lim.feed(b"x" * 100)
    third = lim.feed(b"x" * 100 + b"\nnext\n")
    shown = first + second + third
    assert shown.split("\n")[0] == "x" * 10 + SR.LINE_CUT_MARKER
    assert shown.count(SR.LINE_CUT_MARKER) == 1
    assert shown.endswith("\nnext\n")


def test_edge_a_flood_keeps_only_the_newest_lines_of_a_chunk() -> None:
    lim = SR.OutputLimiter(max_line_chars=100, max_lines=5)
    data = "".join(f"line {i}\n" for i in range(1000)).encode()
    shown = lim.feed(data)
    lines = shown.splitlines()
    assert lines[-1] == "line 999"
    assert len(lines) <= 6  # five lines plus the "skipped" note
    assert "995 lines skipped" in shown


def test_edge_a_character_split_across_chunks_decodes_whole() -> None:
    lim = SR.OutputLimiter()
    raw = "grüße\n".encode()
    cut = raw.index(b"\xc3") + 1  # in the middle of the two-byte "ü"
    assert lim.feed(raw[:cut]) + lim.feed(raw[cut:]) == "grüße\n"


def test_edge_invalid_utf8_is_replaced_not_raised() -> None:
    lim = SR.OutputLimiter()
    assert lim.feed(b"\xff\xfe ok\n") + lim.flush() == "�� ok\n"


# ---------------------------------------------------------------------------
# Traceback lines -> script line numbers
# ---------------------------------------------------------------------------


def test_happy_a_traceback_line_of_the_script_gives_its_line_number() -> None:
    path = "/home/u/.config/axross/scripts/job.py"
    assert SR.script_line_in(f'  File "{path}", line 12, in main', path) == 12
    assert SR.script_line_in(f'File "{path}", line 3', path) == 3


def test_sad_other_files_and_plain_text_give_nothing() -> None:
    path = "/home/u/.config/axross/scripts/job.py"
    assert SR.script_line_in('  File "/usr/lib/python3/json/__init__.py", line 3', path) is None
    assert SR.script_line_in("ZeroDivisionError: division by zero", path) is None
    assert SR.script_line_in("", path) is None


def test_edge_a_similar_path_prefix_is_not_the_script() -> None:
    path = "/s/job.py"
    assert SR.script_line_in('  File "/s/job.py.bak", line 3', path) is None
    assert SR.script_line_in('  File "/s/job.py", line 0', path) is None


# ---------------------------------------------------------------------------
# Bundled examples (the Scripts dock's read-only section)
# ---------------------------------------------------------------------------


def test_happy_bundled_examples_are_listed_and_loadable() -> None:
    names = scripting._list_bundled_scripts()
    assert "du" in names and "mirror" in names
    assert not any(n.startswith("_") for n in names)
    assert "def du(" in scripting._load_bundled_script("du")


def test_sad_a_bundled_name_outside_the_allow_list_is_refused() -> None:
    for bad in ("../core/scripting", "du.py", ""):
        with pytest.raises(ValueError):
            scripting._load_bundled_script(bad)
    with pytest.raises(FileNotFoundError):
        scripting._load_bundled_script("no_such_example")


def test_edge_a_missing_bundle_directory_lists_nothing(tmp_path) -> None:
    with mock.patch.object(scripting, "_bundled_scripts_dir", return_value=str(tmp_path / "x")):
        assert scripting._list_bundled_scripts() == []
        assert "not present" in scripting._render_scripts_reference()
