"""A scheduled script runs in a child process; its exit never ends the app.

Before: the scheduler ran a script job in the GUI process, on a QThread,
through ``scripting.run_script``, and ``run_job`` caught ``Exception``
only. A script ending with ``sys.exit()`` (a common idiom) raised
SystemExit out of the worker thread and the application died with a
segfault; nothing was recorded and the job never ran again.

Now a script job runs the way the Scripts dock and the MCP ``script_run``
tool run one: in a child interpreter (core.script_runner.run_bounded).
Exit status 0 is a success, anything else a recorded failure, and
``run_job`` turns any BaseException a runner raises into a failure too.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scheduler, scripting  # noqa: E402
from core.scheduler import Job, run_job  # noqa: E402


def _job(target: str, kind: str = "script") -> Job:
    return Job(job_id="j1", name=target, kind=kind, target=target, interval_s=300)


def _run(job: Job, **kw) -> list[tuple]:
    outcome: list[tuple] = []
    run_job(
        job,
        runner=lambda j: scheduler.run_script_job(j, **kw),
        on_finished=lambda j, ok, detail: outcome.append((ok, detail)),
    )
    return outcome


@pytest.fixture
def script():
    names: list[str] = []

    def save(name: str, source: str) -> str:
        scripting.save_script(name, source)
        names.append(name)
        return name

    yield save
    for name in names:
        try:
            scripting.delete_script(name)
        except (OSError, ValueError):
            pass


def test_happy_a_script_ending_with_sys_exit_0_is_a_success(script):
    name = script("sched_exit_zero", "print('mirror done')\nimport sys\nsys.exit(0)\n")
    assert _run(_job(name)) == [(True, f"ran {name}")]


def test_happy_a_plain_script_is_a_success(script):
    name = script("sched_plain", "x = 1\n")
    assert _run(_job(name)) == [(True, f"ran {name}")]


def test_sad_sys_exit_with_a_status_is_a_failure(script):
    name = script("sched_exit_three", "import sys\nsys.exit(3)\n")
    [(ok, detail)] = _run(_job(name))
    assert ok is False
    assert "3" in detail


def test_sad_a_raising_script_reports_its_error(script):
    name = script("sched_raises", "raise RuntimeError('boom')\n")
    [(ok, detail)] = _run(_job(name))
    assert ok is False
    assert "RuntimeError" in detail and "boom" in detail


def test_sad_a_missing_script_is_a_failure_not_a_crash():
    [(ok, detail)] = _run(_job("sched_does_not_exist"))
    assert ok is False
    assert detail


def test_sad_an_unknown_job_kind_is_a_failure():
    [(ok, detail)] = _run(_job("x", kind="sync"))
    assert ok is False
    assert "unknown job kind" in detail


def test_edge_the_script_runs_in_another_process(script, tmp_path):
    marker = tmp_path / "pid"
    name = script(
        "sched_pid",
        f"import os\nopen({str(marker)!r}, 'w').write(str(os.getpid()))\n",
    )
    assert _run(_job(name))[0][0] is True
    assert int(marker.read_text()) != os.getpid()


def test_edge_a_cancel_stops_a_running_script(script):
    name = script("sched_sleeps", "import time\ntime.sleep(60)\n")
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    [(ok, detail)] = _run(_job(name), cancel_event=cancel)
    assert ok is False
    assert "cancel" in detail
    assert time.monotonic() - started < 30


def test_edge_a_timeout_ends_the_run_as_a_failure(script):
    name = script("sched_hangs", "import time\ntime.sleep(60)\n")
    [(ok, detail)] = _run(_job(name), timeout_s=0.5)
    assert ok is False
    assert "timed out" in detail


@pytest.mark.parametrize("exc", [SystemExit(2), KeyboardInterrupt()])
def test_edge_run_job_reports_a_base_exception_from_any_runner(exc):
    outcome: list[tuple] = []

    def runner(_job):
        raise exc

    run_job(_job("x"), runner=runner, on_finished=lambda j, ok, d: outcome.append((ok, d)))
    assert len(outcome) == 1
    assert outcome[0][0] is False
