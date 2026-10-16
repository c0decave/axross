"""A hard crash leaves the Python stack of every thread in crash.log.

A segfault in Qt ended axross with "Segmentation fault (core dumped)" and
nothing else: --debug only adds log lines, and the last one says nothing
about what crashed. faulthandler writes the Python traceback of all
threads at the moment of the fatal signal; main.enable_crash_traces points
it at <log dir>/crash.log, after a header naming version and platform.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")


def _crash(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    code = textwrap.dedent(
        f"""
        import resource, sys
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core file for a test crash
        sys.path.insert(0, {str(ROOT)!r})
        import main
        from pathlib import Path
        main.LOG_DIR = Path({str(tmp_path / "logs")!r})
        """
    ) + textwrap.dedent(body)
    env = {**os.environ, "HOME": str(tmp_path), "QT_QPA_PLATFORM": "offscreen"}
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env
    )


# --- happy ----------------------------------------------------------------


def test_happy_a_segfault_leaves_every_threads_stack(tmp_path):
    r = _crash(
        tmp_path,
        """
        import faulthandler, threading, time
        main.enable_crash_traces()
        def media_worker():
            time.sleep(30)
        threading.Thread(target=media_worker, name="media-task", daemon=True).start()
        time.sleep(0.2)
        def open_media_viewer():
            faulthandler._sigsegv()
        open_media_viewer()
        """,
    )
    assert r.returncode != 0
    log = (tmp_path / "logs" / "crash.log").read_text(encoding="utf-8")
    assert "Segmentation fault" in log
    assert "open_media_viewer" in log  # the crashing thread
    assert "media_worker" in log  # and the others
    assert "axross " in log and sys.platform in log  # the header


# --- sad ------------------------------------------------------------------


def test_sad_an_unwritable_log_dir_does_not_stop_the_start(tmp_path):
    (tmp_path / "logs").write_text("a file where the directory should be")
    r = _crash(
        tmp_path,
        """
        print("path:", main.enable_crash_traces())
        """,
    )
    assert r.returncode == 0, r.stderr
    assert "path: None" in r.stdout


# --- edge -----------------------------------------------------------------


def test_edge_two_crashes_append_and_the_file_is_private(tmp_path):
    body = """
        import faulthandler
        main.enable_crash_traces()
        faulthandler._sigsegv()
        """
    _crash(tmp_path, body)
    _crash(tmp_path, body)
    path = tmp_path / "logs" / "crash.log"
    assert path.read_text(encoding="utf-8").count("Segmentation fault") == 2
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
