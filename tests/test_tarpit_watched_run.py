"""The production tarpit in a script run a human watches but cannot type into.

A Scripts dock run has no terminal on stdin, yet its output is shown live
and Stop ends it during the countdown: the countdown still protects, so it
runs. An MCP script_run child (AXROSS_NONINTERACTIVE) and an unwatched run
without a terminal (cron, a pipe) have nobody to stop it: the gate refuses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import script_runner as SR  # noqa: E402
from core import ui_helpers  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

_GATE = (
    "import sys, types\n"
    f"sys.path.insert(0, {str(REPO)!r})\n"
    "from core import safety_tarpit\n"
    "profile = types.SimpleNamespace(production=True, name='prod', host='h', protocol='sftp')\n"
    "try:\n"
    "    with safety_tarpit.production_gate(profile, 'remove /x', countdown_s=0.1):\n"
    "        print('RAN')\n"
    "except BaseException as exc:\n"
    "    print('REFUSED', type(exc).__name__)\n"
)


def _gate_in_child(env: dict) -> str:
    env = dict(env)
    env.pop("AXROSS_TARPIT_DISABLE", None)
    proc = subprocess.run(
        [sys.executable, "-c", _GATE],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return proc.stdout.strip()


def test_happy_a_watched_run_without_a_terminal_counts_down_and_runs() -> None:
    assert _gate_in_child(SR.child_env("normal", watched=True)) == "RAN"


def test_sad_an_unwatched_run_without_a_terminal_is_refused() -> None:
    assert _gate_in_child(SR.child_env("normal")) == "REFUSED NonInteractiveError"


def test_sad_a_machine_run_is_refused_even_when_marked_watched() -> None:
    env = SR.child_env("normal", watched=True)
    env[ui_helpers.ENV_NONINTERACTIVE] = "1"
    assert _gate_in_child(env) == "REFUSED NonInteractiveError"


def test_edge_watched_lets_a_countdown_run_but_answers_no_question(monkeypatch) -> None:
    monkeypatch.setenv(ui_helpers.ENV_WATCHED, "1")
    monkeypatch.delenv(ui_helpers.ENV_NONINTERACTIVE, raising=False)
    monkeypatch.setattr(ui_helpers, "_qt_is_running", lambda: False)
    monkeypatch.setattr(ui_helpers, "_stdin_is_terminal", lambda: False)
    assert ui_helpers.can_watch_countdown() is True
    assert ui_helpers.is_interactive() is False
    try:
        ui_helpers.confirm("delete?")
    except ui_helpers.NonInteractiveError:
        pass
    else:
        raise AssertionError("a watched run cannot answer a question")
    monkeypatch.setenv(ui_helpers.ENV_WATCHED, "no")
    assert ui_helpers.can_watch_countdown() is False


def test_edge_only_the_dock_marks_its_runs_watched() -> None:
    assert ui_helpers.ENV_WATCHED not in SR.child_env("normal")
    assert SR.child_env("normal", watched=True)[ui_helpers.ENV_WATCHED] == "1"
