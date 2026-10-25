"""The bundled examples are libraries: running one does nothing visible.

Reported: scripts "cannot be started" from the Scripts dock. With no saved
script of one's own, the dock lists only the bundled examples; Run is
greyed out for them with the tooltip of a normal script, and a copy made
with "Copy to My Scripts" ran with "exit status 0" and printed nothing -
every example only defines functions, its call lives in the docstring's
``Usage::`` block. Requested too: the examples can be run directly, in a
sensible way. Now Run (and Run in Console) on an example shows its Usage
block to adjust and runs the example with it; a copy carries the block as
a "Try it" section; a run that only defined functions says so.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import script_runner as SR  # noqa: E402
from core import scripting  # noqa: E402
from tests.test_scripts_dock import (  # noqa: E402,F401 - fixtures
    _run_and_wait,
    dock,
    jobs,
    names,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "resources" / "scripts"


# -- the Usage block ---------------------------------------------------------------------


def test_happy_the_usage_block_of_an_example_is_found():
    block = SR.usage_block(scripting._load_bundled_script("du"))
    assert block.splitlines()[0] == 'sizes = du(axross.localfs(), "/var/log")'
    assert "print(" in block and not block.startswith(" ")


def test_sad_a_source_without_a_usage_block_gives_nothing():
    assert SR.usage_block('"""Just a docstring."""\nx = 1\n') == ""
    assert SR.usage_block("x = 1\n") == ""
    assert SR.usage_block("def broken(:\n") == ""  # not Python: nothing, no exception


def test_edge_the_block_ends_at_the_first_unindented_line():
    source = '"""Doc.\n\nUsage::\n\n    a = 1\n\n    b = 2\n\nMore text.\n"""\n'
    assert SR.usage_block(source) == "a = 1\n\nb = 2"


def test_edge_every_bundled_example_carries_a_usage_block():
    missing = [p.stem for p in EXAMPLES.glob("*.py")
               if not p.stem.startswith("_") and not SR.usage_block(p.read_text("utf-8"))]
    assert missing == []


def test_edge_every_usage_block_is_valid_python():
    broken = {}
    for p in EXAMPLES.glob("*.py"):
        block = SR.usage_block(p.read_text("utf-8"))
        if block:
            try:
                ast.parse(block)
            except SyntaxError as exc:
                broken[p.stem] = str(exc)
    assert broken == {}


# -- a script that only defines functions ------------------------------------------------


def test_happy_a_library_script_is_recognised():
    source = scripting._load_bundled_script("du")
    assert SR.only_defines(source) == ["du"]


def test_sad_a_script_that_does_something_is_not_a_library():
    assert SR.only_defines("import os\nprint(os.getcwd())\n") == []
    assert SR.only_defines("def f():\n    pass\nf()\n") == []
    assert SR.only_defines("def f():\n    pass\nif __name__ == '__main__':\n    f()\n") == []
    assert SR.only_defines("def broken(:\n") == []


def test_edge_constants_imports_and_classes_still_count_as_defining_only():
    source = ('"""Doc."""\nfrom __future__ import annotations\nimport re\nLIMIT = 5\n'
              'class Box:\n    pass\ndef go():\n    pass\n')
    assert SR.only_defines(source) == ["Box", "go"]


# -- the dock ------------------------------------------------------------------------------


def test_happy_a_copied_example_carries_its_usage_as_try_it(dock, names):
    target = names("copy")
    dock.open_example("du")
    dock.prompts.names = [target]
    dock.copy_example()
    text = scripting.load_script(target)
    assert "def du(" in text
    tail = text[text.index(SR.TRY_IT_HEADER):]
    assert '# sizes = du(axross.localfs(), "/var/log")' in tail
    # still only defines functions: the Try it lines are comments
    assert SR.only_defines(text) == ["du"]


def test_happy_e2e_running_a_library_script_says_what_to_do(dock, names):
    target = names("lib")
    dock.open_example("du")
    dock.prompts.names = [target]
    dock.copy_example()
    status = _run_and_wait(dock)
    assert "exit status 0" in status
    assert "only defines" in status and "du" in status
    assert "Try it" in status


def test_happy_e2e_uncommenting_the_try_it_line_prints(dock, names, tmp_path):
    target = names("try")
    dock.open_example("du")
    dock.prompts.names = [target]
    dock.copy_example()
    (tmp_path / "a.bin").write_bytes(b"x" * 1234)
    text = scripting.load_script(target) + f"\nfor p, n in du(axross.localfs(), {str(tmp_path)!r}):\n    print(n, p)\n"
    dock.editor.setPlainText(text)
    status = _run_and_wait(dock)
    assert "exit status 0" in status
    assert "1234" in dock.output.toPlainText()
    assert "only defines" not in status


def test_happy_e2e_run_an_example_directly_with_its_adjusted_usage(dock, tmp_path):
    (tmp_path / "big.bin").write_bytes(b"x" * 4321)
    dock.open_example("du")
    assert dock.run_action.isEnabled() and dock.console_action.isEnabled()
    seen = {}

    def ask(name, usage):
        seen["name"], seen["usage"] = name, usage
        return f"for p, n in du(axross.localfs(), {str(tmp_path)!r}):\n    print(n, p)\n"

    dock._ask_example_call = ask
    status = _run_and_wait(dock)
    assert seen["name"] == "du" and seen["usage"].startswith("sizes = du(")
    assert "exit status 0" in status, status
    assert "4321" in dock.output.toPlainText()
    assert dock.current() == ("example", "du")  # nothing was saved or copied
    assert dock.editor.isReadOnly()


def test_sad_cancelling_the_example_call_runs_nothing(dock):
    dock.open_example("du")
    dock._ask_example_call = lambda name, usage: None
    dock.run()
    assert not dock.is_running()
    assert dock.output.toPlainText() == ""


def test_happy_e2e_an_example_run_can_be_stopped(dock):
    dock.open_example("du")
    dock._ask_example_call = lambda name, usage: (
        "import time\nprint('example looping', flush=True)\nwhile True:\n    time.sleep(0.05)\n")
    dock.run()
    from tests.test_scripts_dock import _wait
    assert _wait(lambda: "example looping" in dock.output.toPlainText(), 30)
    dock.stop()
    assert _wait(lambda: not dock.is_running(), 20)
    assert "stopped" in dock.status_text()


def test_edge_the_call_reaches_the_child_on_stdin_not_argv():
    command = SR.build_example_command("du", "print('secret-host')")
    assert not any("secret-host" in a for a in command.argv)
    assert "secret-host" in (command.stdin_text or "")


def test_sad_an_unknown_example_is_refused_before_anything_starts():
    with pytest.raises(ValueError):
        SR.build_example_command("../etc/passwd", "x = 1")
    with pytest.raises((ValueError, OSError)):
        SR.build_example_command("no_such_example_xyz", "x = 1")


def test_happy_run_in_console_runs_an_example_with_its_call(dock):
    asked = []
    dock.run_example_in_console_requested.connect(lambda name, call: asked.append((name, call)))
    dock.open_example("du")
    dock._ask_example_call = lambda name, usage: "print('console call')"
    dock.run_in_console()
    assert asked == [("du", "print('console call')")]


def test_edge_a_normal_script_keeps_the_normal_tooltip_and_status(dock, names):
    target = names("plain")
    dock.prompts.names = [target]
    dock.new_script()
    dock.editor.setPlainText("print('plain run')\n")
    assert "Copy to My Scripts" not in dock.run_action.toolTip()
    status = _run_and_wait(dock)
    assert "exit status 0" in status and "only defines" not in status


def test_happy_the_frozen_bootstrap_runs_the_example_with_its_call(monkeypatch, tmp_path):
    """A frozen build runs ``axross --script -``: the call travels inside the
    bootstrap on stdin. Run that bootstrap with this tree's Python."""
    import subprocess

    (tmp_path / "x.bin").write_bytes(b"z" * 99)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    command = SR.build_example_command(
        "du", f"print('frozen call', du(axross.localfs(), {str(tmp_path)!r})[0][1])")
    monkeypatch.delattr(sys, "frozen")
    assert command.argv[1:] == ["--script", "-"]
    assert not any("frozen call" in a for a in command.argv)
    root = str(Path(__file__).resolve().parent.parent)
    proc = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {root!r})\n"
                           + command.stdin_text], cwd=command.cwd, capture_output=True,
                          text=True, timeout=60, env=SR.child_env("normal"))
    assert proc.returncode == 0, proc.stderr
    assert "frozen call 99" in proc.stdout
