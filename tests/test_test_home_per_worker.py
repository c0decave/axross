"""Each pytest-xdist worker runs its tests in a home of its own.

Found on 2026-11-02: tests/conftest.py made the run's private home once, in
the controller, and every worker inherited it - under ``pytest -n`` all
workers shared one home. tests/test_terminal_bookmarks.py and
tests/test_terminal_host_bookmarks.py each keep a main window for their
module and write bookmarks.json and the profiles; run at the same time on
two workers they saw each other's entries and failed, never alone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_happy_this_process_runs_in_the_home_made_for_it():
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    assert os.environ["AXROSS_TEST_HOME_WORKER"] == worker
    assert os.environ["HOME"] == os.environ["AXROSS_TEST_HOME"]
    assert Path(os.environ["HOME"]).name.startswith(f"axross-test-home-{worker or 'main'}-")


def test_happy_e2e_two_workers_get_two_homes(tmp_path):
    pytest.importorskip("xdist", reason="pytest-xdist not installed")
    out = tmp_path / "homes"
    out.mkdir()
    probe = (
        "import os, pathlib\n"
        "def test_home():\n"
        f"    pathlib.Path({str(out)!r}, os.environ.get('PYTEST_XDIST_WORKER', 'main'))"
        ".write_text(os.environ['HOME'])\n"
        "    import time; time.sleep(1.0)  # both workers busy at once\n"
    )
    tests = ROOT / "tests"
    files = [tests / f"_probe_home_{os.getpid()}_{n}.py" for n in (1, 2)]  # no test_*.py
    try:
        for f in files:
            f.write_text(probe)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("PYTEST_") and k != "AXROSS_TEST_HOME_WORKER"}
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-n", "2",
             "--dist", "loadfile", "-o", "python_files=_probe_home_*.py", *map(str, files)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
        )
    finally:
        for f in files:
            f.unlink(missing_ok=True)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    homes = {p.name: p.read_text() for p in out.iterdir()}
    assert sorted(homes) == ["gw0", "gw1"], homes
    assert homes["gw0"] != homes["gw1"]
    assert all(Path(h).name.startswith(f"axross-test-home-{w}-") for w, h in homes.items())
